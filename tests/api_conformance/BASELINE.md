# API conformance baseline — 2026-09-19 (T-14)

First live run of `tests/api_conformance` against a real kernel. This is the
number to improve against. No broker code was changed for this baseline.

## How it was produced

- Spec: the reference specification.0 OpenAPI, fetched live from the reference container
  `test container` (`POST /api/v5/login` with the disposable test password
  documented in `team/parity/REFERENCE.md`, then `GET /api-docs/swagger.json`;
  296 paths). The spec file lives outside the repo and is passed by path only:
  run with `--spec <path-to-openapi.json>`.
- Kernel: release `indramqtt` built from this tree at `cdf7530`, plus the
  `beam/ebin` edge from the same tree, both built in `test container`.
- Stack: fresh remote host container `test container` (removed after the run) —
  kernel `--api-bind 0.0.0.0:28083 --brokerlink-bind 127.0.0.1:28883
  --allow-anonymous --data-dir /opt/indramqtt/data` (fresh data dir),
  edge `mqtt_port 11883 kernel_port 28883`.
  Reached from the run host as API `100.104.51.36:13484`, MQTT
  `100.104.51.36:13483`.
- Stack prep before the run: `POST /api/v5/users/admin/change_pwd`
  `{old_pwd: public, new_pwd: Adm1n-test-pass!}` (admin self-change; the
  checker refuses to run while `must_change_password` is true). The
  `POST /login` case in `cases/users.json` uses that stack password, which
  matches the value already used by the repo's own e2e tests.
- Command (from the repo root):
  `python -m tests.api_conformance --spec <openapi.json> --base
  http://100.104.51.36:13484/api/v5 --user admin --password Adm1n-test-pass!
  --allow-mutations --cases tests/api_conformance/cases --exclude-tags
  "Plugins,AI Completion,A2A Registry" --mqtt 100.104.51.36:13483
  --report tests/api_conformance/baseline-2026-09-19.json`
- Raw report: `tests/api_conformance/baseline-2026-09-19.json` (420 rows).

## Headline

Spec operations after tag exclusion: 420. Exercised: 141
(31 pass, 11 fail, 99 not-implemented). Skipped for want of a case: 279
(these are endpoints the kernel does not implement). No auth errors.

## Summary by tag

| tag | pass | fail | not-impl | skipped |
|---|---|---|---|---|
| API Keys | 0 | 0 | 2 | 4 |
| Actions | 0 | 2 | 2 | 9 |
| Alarms | 0 | 0 | 1 | 2 |
| Audit | 0 | 0 | 1 | 0 |
| Authentication | 4 | 0 | 3 | 12 |
| Authorization | 0 | 0 | 7 | 23 |
| Auto Subscribe | 0 | 0 | 1 | 1 |
| Banned | 0 | 0 | 1 | 3 |
| Clients | 6 | 2 | 1 | 5 |
| Cluster | 0 | 0 | 4 | 10 |
| CoAP Gateways | 0 | 0 | 0 | 1 |
| Configs | 0 | 0 | 10 | 11 |
| Connectors | 5 | 1 | 0 | 3 |
| Dashboard | 5 | 3 | 0 | 3 |
| Dashboard Single Sign-On | 0 | 0 | 4 | 9 |
| Data Backup | 0 | 0 | 1 | 5 |
| Durable storage | 0 | 0 | 2 | 7 |
| Error Codes | 0 | 0 | 1 | 1 |
| ExHook | 0 | 0 | 1 | 6 |
| Features | 0 | 0 | 1 | 0 |
| File Transfer | 0 | 0 | 3 | 2 |
| Gateway Authentication | 0 | 0 | 0 | 11 |
| Gateway Clients | 0 | 0 | 0 | 6 |
| Gateway Listeners | 0 | 0 | 0 | 14 |
| Gateways | 0 | 0 | 1 | 3 |
| License | 0 | 0 | 3 | 2 |
| Listeners | 0 | 0 | 2 | 8 |
| Load Rebalance | 0 | 0 | 3 | 4 |
| LwM2M Gateways | 0 | 0 | 0 | 4 |
| MQTT | 0 | 0 | 5 | 14 |
| Message Queue | 0 | 0 | 2 | 5 |
| Message Stream | 0 | 0 | 2 | 5 |
| Message Transformation | 0 | 0 | 1 | 9 |
| Metrics | 2 | 0 | 2 | 3 |
| Monitor | 0 | 0 | 9 | 2 |
| Multi-tenancy | 0 | 0 | 4 | 12 |
| Node Eviction | 0 | 0 | 1 | 0 |
| Nodes | 0 | 2 | 0 | 2 |
| Opentelemetry | 0 | 0 | 0 | 3 |
| Publish | 1 | 0 | 0 | 0 |
| Retainer | 0 | 0 | 2 | 4 |
| Rules | 7 | 0 | 2 | 3 |
| Schema Registry | 0 | 0 | 2 | 10 |
| Schema Validation | 0 | 0 | 1 | 8 |
| Slow Subscriptions | 0 | 0 | 2 | 2 |
| Sources | 0 | 0 | 3 | 10 |
| Status | 0 | 0 | 1 | 0 |
| Subscriptions | 0 | 1 | 0 | 0 |
| TLS Management | 0 | 0 | 1 | 7 |
| Telemetry | 0 | 0 | 2 | 1 |
| Topics | 1 | 0 | 0 | 0 |
| Trace | 0 | 0 | 2 | 8 |

## The 11 failures (all response-shape/status-code, no crash or hang)

- `GET /action_types` (200): our list has `kafka`, spec enum has
  `kafka_producer` (plus many bridge types). Vocabulary mismatch.
- `POST /actions_probe`, `POST /connectors_probe` (400): our error code is
  `CONNECTION_FAILED`, spec documents `TEST_FAILED`.
- `GET /clients/{clientid}/mqueue_messages` (200): our `meta` lacks the
  spec-required `start` property.
- `POST /clients/{clientid}/subscribe` (201): spec documents only 200/400-ish;
  201 is "not documented". Same class: `POST /users` returns 201 where the
  spec documents 200, and `POST /users/{username}/change_pwd` returns 200
  where the spec documents 204.
- `GET /nodes`, `GET /nodes/{node}` (200): `load1`/`load5`/`load15` are
  strings, spec wants numbers.
- `GET /schemas/{name}` (200): ours returns an object, spec wants a string.
- `GET /subscriptions` (200): ours returns `{data, meta}`, spec wants an
  array.

## What passed (31)

Login, dashboard users CRUD + self/other password change, authn
built-in-database users CRUD + list, client list/get/kick (single + bulk),
client subscriptions get/subscribe/unsubscribe, publish, topics list, rules
CRUD + metrics + metrics reset, connectors CRUD + list, stats, monitor_current,
user_scopes, nodes list is exercised but shape-fails (see above).

## Honest limits of this baseline

- 279 operations are still skipped for want of a case; they are endpoints the
  kernel does not implement, so a case would only record `not-implemented`.
  Cases were added for every spec operation the kernel does implement (29 new
  cases in 7 files; the 2 pre-existing case files cover the other 2), except
  `POST /logout`, which is deliberately uncased: our logout revokes the
  checker's bearer token, so exercising it would turn every later operation
  into an auth error.
- Rule cases chain on one shared fixture: `POST /rules` leaves `conf-rule-1`
  behind and the `{id}` cases resolve `$from:GET /rules#/data/0/id` (envelope
  path — `#/0/id` does not work because our list nests under `data`). Each
  `{id}` case setup creates its own rule first, so reruns keep working, but
  rules accumulate (~6 per run) on a disposable stack.
- Connector cases delete-then-create `conf-conn-1` in setup so reruns do not
  stack duplicates (see defect note below).
- The checker validates only status codes and JSON response schemas; it does
  not judge behaviour (e.g. whether a kick really disconnected a client).

## Defect note (not fixed — baseline task is read-only on broker code)

While iterating, connector setups posted the same name three times. The
in-memory store accepted the duplicates, but from then on every connector
mutation (POST a new connector, PUT, DELETE) returned 500
`cannot persist connectors: connectors.connectors[1].id "conf-conn-1" is
duplicated (field 'id')` — i.e. duplicate ids poison connector persistence
and fail closed on all later mutations. Repro on a fresh stack: create the
same connector name twice, then any connector mutation 500s. The committed
cases avoid tripping this (delete-before-create in setup); the second live
run above (31 pass) is unaffected by it.
