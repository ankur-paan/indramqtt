# indramqtt Helm chart (single node, minimal)

Minimal means one replica with no clustering. You install from this doc
without editing the chart's internals: adjust the named values only,
install, connect.

## Non-goals (by design, not omissions)

- Clustering (multi-node mesh, seed discovery, shared subscriptions
  across nodes).
- TLS termination at ingress (terminate TLS outside the chart or extend
  it; the chart serves plaintext MQTT inside the cluster).
- Production hardening beyond the documented values (resource limits,
  network policies, pod disruption budgets, backups).

## 1. Adjust named values only

| Value | Default | When to change it |
|---|---|---|
| `image.repository` / `image.tag` | `indramqtt/indramqtt:0.1.0` (workspace version, pinned, never `:latest`) | Track releases. |
| `service.type` | `ClusterIP` | `NodePort` or `LoadBalancer` to reach the broker from outside the cluster. |
| `service.mqttPort` / `wsPort` / `apiPort` | `1883` / `8083` / `18083`, the same ports as the compose example | Change once here: the Service, container ports and args (`--api-bind` for the API port, overriding the image default), probes and the rendered `indra.toml` binds all follow the same value. |
| `storage.size` | `10Gi` | Grow for retained history or an enabled stream journal. |
| `storage.storageClassName` | `""` (cluster default) | Name a class explicitly for production. |
| `config.nodeId` | `indra-node-1` | Unique id per installation. |
| `config.allowAnonymous` | `true` | Set `false` beyond evaluation, and create users first. |
| `config.logLevel` | `info` | Default level in the file; `extraEnv` below wins at runtime. |
| `extraEnv` | `INDRA_LOGGING__LEVEL=debug` | Canonical `INDRA_*` overrides winning over the ConfigMap file. Names must match `crates/broker-config/src/schema.rs`; an unknown name refuses startup (fail closed). |

## 2. Render and install

```bash
# Render against the documented values first; the render must succeed
# with no errors before installing.
helm template indra ./deploy/helm/indramqtt

# Install with defaults (same ports, volume and probes as the compose
# example), or override named values only:
helm install indra ./deploy/helm/indramqtt
helm install indra ./deploy/helm/indramqtt \
  --set image.tag=0.1.0 \
  --set storage.size=20Gi \
  --set config.allowAnonymous=false
```

## 3. Health endpoint

```bash
kubectl port-forward svc/indra-indramqtt 18083:18083 &
curl -sf http://localhost:18083/healthz   # must print OK
```

The settled probe for both liveness and readiness is the public
unauthenticated `/healthz` route answering `OK`. `/api/v1/health` does
not exist; a probe against it fails closed with a 404.

## 4. MQTT round trip (connect, publish, deliver)

```bash
kubectl port-forward svc/indra-indramqtt 1883:1883 &
mosquitto_sub -h localhost -p 1883 -t 'ops/check' -C 1 &
mosquitto_pub -h localhost -p 1883 -t 'ops/check' -m 'helm-ok'
wait
```

The subscriber must print `helm-ok`. The default install allows
anonymous clients (`config.allowAnonymous=true`), so no credentials are
needed for evaluation.

## 5. Prove the `INDRA_*` override wins over the file

The ConfigMap file sets log level `info`, while `extraEnv` sets
`INDRA_LOGGING__LEVEL=debug`. The environment wins per the M1-04
precedence. The winning layer is reported by the authenticated
`GET /api/v1/config/explain` endpoint (protected router behind
`require_api_auth`: an unauthenticated curl fails closed with 401
UNAUTHORIZED).

```bash
# Log in as the first-boot default admin, rotate the password (a
# must-change-password token answers nothing else), and keep the
# fully-privileged token.
kubectl port-forward svc/indra-indramqtt 18083:18083 &
TOKEN=$(curl -sf -X POST http://localhost:18083/api/v5/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"public"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
curl -sf -X PUT http://localhost:18083/api/v5/users/admin/change_pwd \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"old_pwd":"public","new_pwd":"<choose-a-password>"}'
TOKEN=$(curl -sf -X POST http://localhost:18083/api/v5/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<choose-a-password>"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')

# The explain endpoint names the winning layer for the setting.
curl -sf -H "Authorization: Bearer $TOKEN" \
  'http://localhost:18083/api/v1/config/explain?key=logging.level'
# -> {"key":"logging.level","value":"\"debug\"",
#     "layer":"environment variable INDRA_LOGGING__LEVEL", ...}
```

## 6. Uninstall

```bash
helm uninstall indra
# The PVC survives uninstall by default; remove it to delete broker state:
kubectl delete pvc indra-indramqtt-data
```
