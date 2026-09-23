# IndraMQTT licensing (B2-04)

How cluster licensing works: the request/install round trip, the four
visible states, and what to do when things go wrong. Read this before
generating a request, installing a licence, or recovering a cluster.

## The round trip

There is no call home and no activation server at any step. Both
directions are files a person can move, so an air-gapped site works the
same way as a connected one.

1. The installation generates a **licence request**: a small JSON file,
   like a certificate signing request, carrying the identity of the
   installation and what it is asking for. Generate it from the dashboard
   (`GET /api/v1/licence/request`) or on the node itself:
   `indramqtt --licence-request-out request.json`.
2. Send that file to sales (email, portal, support ticket).
3. Sales signs it with the hardware token and sends back a licence token
   (`INDRA-ENT-V2.<payload>.<signature>`).
4. Install the licence once, on any node: `POST /api/v1/licence/install
   {"token": "..."}` or `indramqtt --licence-install-file licence.token`.
   Every node in the cluster receives it through cluster metadata, and a
   node that joins later receives it as part of joining.

Because the request carries the installation identity, the licence is
**bound**: a licence issued to one cluster does not work anywhere else.
Installing a licence issued for another cluster is refused with an
identity-mismatch reason naming both identities.

## Identity is per cluster

One licence file covers a whole cluster; adding a node never needs
another round trip.

- The first node to start creates the cluster identity: a keypair plus a
  stable identity derived from its public key, persisted in the data
  directory (`cluster_identity.json`) and held in cluster metadata.
- A node joining an existing cluster adopts the cluster identity and
  discards any it generated while standing alone. A single node is a
  cluster of one, so nothing is special about the unclustered case.
- The trial start is recorded with the identity, so restarting does not
  restart the trial and adding a node does not either.

### Ordering: the bootstrap never deadlocks

Clustering is itself an entitlement, so an unlicensed cluster still forms
far enough to produce a request: unlicensed, a cluster forms and runs
with enterprise entitlements off. It is never impossible to reach the
state where a request can be generated.

### The node ceiling

The licence carries a maximum node count and the cluster enforces it at
join: a node beyond the ceiling is refused membership with a reason
naming the ceiling and the current count, raises the
`licence_node_ceiling` alarm, and logs it. It is refused from the
cluster, not stopped as a broker: it keeps serving MQTT standalone.

### Two previously separate nodes join

Two nodes that each ran alone have different identities. When they join,
the joining node adopts the cluster identity, and any licence it held is
no longer valid for it (it was bound to the old identity). The node logs
a line naming both identities rather than silently dropping the licence:

`cluster identity adoption: node identity '<old>' adopts cluster
identity '<new>'; any licence bound to '<old>' is no longer valid for
this node`

After adoption the node receives the cluster licence as part of joining,
so it is licensed the moment it is a member. If the two sides held
different licences, the surviving cluster licence wins; reinstall the
intended licence afterwards if that was not the one wanted.

## If the cluster data directory is lost

The identity lives in the data directory. If the whole cluster loses its
data directory, the identity is gone: the next start creates a fresh
identity, returns to trial, and needs a fresh licence request. Do not
discover this during a recovery:

- Back up the data directory (or at least `cluster_identity.json` and
  `licence.token`) with the same procedure as the rest of the state.
- After restoring from backup, confirm `GET /api/v1/licence/status`
  reports the expected identity and state before rejoining nodes.
- If no backup exists, generate a new request from the fresh identity
  and ask sales for a reissue; the old licence cannot be made to match
  the new identity.

Replacing a licence is atomic: a failed install never leaves a node with
nothing when it had a good licence.

## The four states

| state   | meaning                                                   | entitlements |
|---------|-----------------------------------------------------------|--------------|
| trial   | fresh installation, no licence, 90 days from first start  | on           |
| valid   | licensed, before the expiry date                          | on           |
| grace   | past expiry, inside the grace window (default 90 days)    | on           |
| lapsed  | trial or grace ran out                                    | off          |

MQTT connect, publish and subscribe keep working in every state; only
enterprise entitlements turn off when lapsed. A licence condition never
stops customer traffic.

- The grace length is carried in the licence (default 90 days), so a
  customer can be given longer without a new build.
- Installing a licence at any point moves the cluster to valid and the
  trial is forgotten; the licence expiry governs from then on.
- Approaching expiry warns through the log and the
  `licence_expiry_approaching` alarm (window configurable via
  `--licence-expiry-warn-days`, default 30). In grace the `licence_grace`
  alarm stays active for the whole period with days remaining on the
  status route. Lapsing logs the transition naming what stopped.
- `GET /api/v1/licence/status` reports identity, customer, expiry,
  entitlements, signing key id and days remaining.

### The clock must not go backwards

Grace is measured against the highest timestamp the node has ever seen,
recorded with the identity. Setting the clock back neither extends grace
nor makes a valid licence look expired.

## What the trial does not prevent

Every installation starts with 90 days of the full product: no licence,
no request, no contact. With no call home, a customer who deletes the
data directory gets a new identity and a new 90 days. That is the cost
of offline licensing and it is the right trade: the alternative punishes
every honest operator who rebuilds a node in order to inconvenience
someone who was never going to pay. There is no fingerprinting and no
hidden state outside the data directory. As the trial runs down, the
alarm and log message say how to generate a licence request, because at
that moment that is the only thing the operator needs to know.
