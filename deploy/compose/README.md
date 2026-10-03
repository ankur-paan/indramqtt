# IndraMQTT compose example (single node)

One-node start from a clean tree. You copy nothing into the broker's
internals: adjust the named values below, then start and connect.

## 1. Adjust named values only

| Value | Where | Default | When to change it |
|---|---|---|---|
| `[node] id` | `deploy/compose/indra.toml` | `"indra-node-1"` | Give each node a unique id (matters once clustering is used). |
| `[auth] allow_anonymous` | `deploy/compose/indra.toml` | `true` | Set `false` for anything beyond evaluation, and create users first. |
| `[logging] level` | `deploy/compose/indra.toml`, but `INDRA_LOGGING__LEVEL` in `docker-compose.yml` wins | file `info`, running `debug` | Change the environment entry to set the running level without editing the file. |
| Listener binds | `deploy/compose/indra.toml` (`listeners.tcp/ws/api`) | `1883` / `8083` / `18083` on all interfaces | Change together with the matching `ports:` entry in `docker-compose.yml`. The kernel passes the MQTT and WebSocket binds to the edge at start, so this file is the one place a listener is set. |
| Image tag | `docker-compose.yml` (`image:`) | `indramqtt/indramqtt:0.1.0` (workspace version) | Track releases; never use `:latest` for a running deployment. |

Every other setting keeps its schema default (see
`crates/broker-config/src/schema.rs`); the full reference template is
`indramqtt.example.toml` at the repository root.

## 2. Start

```bash
docker compose up -d --build
docker compose ps
```

## 3. Health endpoint

```bash
curl -sf http://localhost:18083/healthz   # must print OK
docker inspect --format='{{.State.Health.Status}}' indramqtt-broker   # healthy
```

The settled probe is the public unauthenticated `/healthz` route
answering `OK`. `/api/v1/health` does not exist; a probe against it
fails closed with a 404.

## 4. MQTT round trip (connect, publish, deliver)

```bash
mosquitto_sub -h localhost -p 1883 -t 'ops/check' -C 1 &
mosquitto_pub -h localhost -p 1883 -t 'ops/check' -m 'compose-ok'
wait
```

The subscriber must print `compose-ok`. Any 3.1.1 client works; the
example allows anonymous clients (`[auth] allow_anonymous = true`), so
no credentials are needed for evaluation.

## 5. Prove the `INDRA_*` override wins over the file

The mounted file sets `[logging] level = "info"`, while
`docker-compose.yml` sets `INDRA_LOGGING__LEVEL=debug`. The environment
wins, so the broker logs at `debug`:

```bash
docker compose logs indramqtt | grep -c DEBUG   # more than 0
```

`RUST_LOG`, when set, overrides `logging.level`; it is a developer
filter (`RUST_LOG=broker_router=trace`) and the compose file leaves it
unset.

The authenticated `GET /api/v1/config/explain` endpoint names the layer
that set a value (an unauthenticated request gets 401):

```bash
# Log in as the first-boot default admin, rotate the password (a
# must-change-password token answers nothing else), and keep the
# fully-privileged token.
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

## 6. Persistence survives a restart

```bash
docker restart indramqtt-broker
sleep 8
curl -sf http://localhost:18083/healthz   # OK again, same volume
```

All mutable state lives on the `indramqtt_data` volume
(`/var/lib/indramqtt`); the config mount is read-only and never written
by the broker.

## 7. Clean up

```bash
docker compose down        # keeps the data volume
docker compose down -v     # also removes the data volume
```
