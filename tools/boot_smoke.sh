#!/usr/bin/env bash
# Boot test for a built broker.
#
# This script starts the kernel and the edge as an operator does: from an
# indra.toml file and INDRA_* variables. It then examines the behaviour
# through the sockets. It does not use internal functions.
#
# Usage:
#   tools/boot_smoke.sh <dir with indramqtt and indra> <edge ebin dir>
#
# Build the inputs first:
#   cargo build -p broker-node --bins
#   (cd beam && mkdir -p ebin && erlc -o ebin src/*.erl \
#      && cp src/indra_edge.app.src ebin/indra_edge.app)
#
# The script exits with 0 if all the checks are satisfactory. It prints
# one line for each check.
set -u

BIN_DIR=${1:?give the directory that contains indramqtt and indra}
EBIN=${2:?give the ebin directory of the edge}
# The script starts the edge from a different directory. Thus it needs
# absolute paths.
BIN_DIR=$(cd "$BIN_DIR" 2>/dev/null && pwd) || { echo "FAIL: $1 is not a directory"; exit 2; }
EBIN=$(cd "$EBIN" 2>/dev/null && pwd) || { echo "FAIL: $2 is not a directory"; exit 2; }
KERNEL=$BIN_DIR/indramqtt
CTL=$BIN_DIR/indra

for tool in "$KERNEL" "$CTL"; do
    [ -x "$tool" ] || { echo "FAIL: $tool is not an executable file"; exit 2; }
done
[ -f "$EBIN/indra_edge_sup.beam" ] || { echo "FAIL: $EBIN does not contain the edge"; exit 2; }
command -v erl >/dev/null || { echo "FAIL: erl is not in PATH"; exit 2; }
command -v python3 >/dev/null || { echo "FAIL: python3 is not in PATH"; exit 2; }

ROOT=$(mktemp -d)
KERNEL_PID=
EDGE_PID=
failures=0

cleanup() {
    [ -n "$EDGE_PID" ] && kill "$EDGE_PID" 2>/dev/null
    [ -n "$KERNEL_PID" ] && kill "$KERNEL_PID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$ROOT"
}
trap cleanup EXIT

pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }
check() { if [ "$2" = 0 ]; then pass "$1"; else fail "$1"; fi; }

# Get free ports. The checks use these ports and not the defaults. Thus
# a check is satisfactory only if the broker reads the port from the file.
read -r API_PORT LINK_PORT MQTT_PORT WS_PORT <<EOF
$(python3 - <<'PY'
import socket
socks = [socket.socket() for _ in range(4)]
for s in socks:
    s.bind(("127.0.0.1", 0))
print(" ".join(str(s.getsockname()[1]) for s in socks))
for s in socks:
    s.close()
PY
)
EOF

API_KEY_GOOD=boot-smoke-key-0001
# With SMOKE_NATIVE=1 the kernel owns the plaintext MQTT listener
# (listeners.tcp.native = true). Without it the edge owns the listener.
# The MQTT checks are the same for the two modes.
if [ "${SMOKE_NATIVE:-0}" = 1 ]; then NATIVE=true; else NATIVE=false; fi
mkdir -p "$ROOT/cfg" "$ROOT/data"
cat > "$ROOT/cfg/indra.toml" <<EOF
[node]
id = "boot-smoke"
data_dir = "$ROOT/data"
brokerlink_bind = "127.0.0.1:$LINK_PORT"

[listeners.tcp]
bind = "127.0.0.1:$MQTT_PORT"
native = $NATIVE

[listeners.ws]
bind = "127.0.0.1:$WS_PORT"
path = "/smoke"

[listeners.api]
bind = "127.0.0.1:$API_PORT"

[logging]
level = "warn"

# A client with a username goes into the tenant of that username.
[[tenants.rules]]
expression = "t-\${username}"
EOF

# --- 1. The kernel starts from the file and the credential variables ---
INDRA_API_KEYS=$API_KEY_GOOD INDRA_API_KEY=$API_KEY_GOOD \
    "$KERNEL" --config-dir "$ROOT/cfg" > "$ROOT/kernel.log" 2>&1 &
KERNEL_PID=$!

healthz=
for _ in $(seq 1 50); do
    healthz=$(python3 - "$API_PORT" <<'PY' 2>/dev/null
import sys, urllib.request
print(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/healthz", timeout=1).read().decode())
PY
)
    [ "$healthz" = OK ] && break
    kill -0 "$KERNEL_PID" 2>/dev/null || break
    sleep 0.2
done
kill -0 "$KERNEL_PID" 2>/dev/null
check "the kernel starts when INDRA_API_KEYS and INDRA_API_KEY are set" $?
[ "$healthz" = OK ]
check "listeners.api.bind from indra.toml is the bind in operation" $?
if grep -q ' INFO' "$ROOT/kernel.log"; then
    fail "logging.level from indra.toml is the level in operation"
else
    pass "logging.level from indra.toml is the level in operation"
fi

# --- 2. The operator CLI uses an API key ---
"$CTL" ctl --endpoint "http://127.0.0.1:$API_PORT" --api-key "$API_KEY_GOOD" status \
    > "$ROOT/ctl.log" 2>&1
check "indra ctl gets access with a key from INDRA_API_KEYS" $?
if "$CTL" ctl --endpoint "http://127.0.0.1:$API_PORT" --api-key wrong-key-wrong-key status \
    > /dev/null 2>&1; then
    fail "indra ctl gets no access with an incorrect key"
else
    pass "indra ctl gets no access with an incorrect key"
fi
"$CTL" ctl --endpoint "http://127.0.0.1:$API_PORT" --api-key "$API_KEY_GOOD" --json \
    config explain --key node.id 2>/dev/null | grep -q 'boot-smoke'
check "explain shows the value from indra.toml" $?

# --- 3. Each setting in the schema is permitted in indra.toml ---
python3 - "$ROOT" > "$ROOT/all.count" <<'PY'
import json, os, sys
root = sys.argv[1]
schema = json.load(open("schemas/config-schema.json"))
lines = []
def walk(prefix, node):
    scalars, tables = [], []
    for name, spec in sorted(node.get("properties", {}).items()):
        if spec.get("type") == "object":
            tables.append((name, spec))
        elif "default" in spec:
            scalars.append((name, spec["default"]))
    if prefix and scalars:
        lines.append(f"[{prefix}]")
        for name, default in scalars:
            lines.append(f"{name} = {json.dumps(default)}")
        lines.append("")
    for name, spec in tables:
        walk(f"{prefix}.{name}" if prefix else name, spec)
walk("", schema)
os.makedirs(f"{root}/all", exist_ok=True)
open(f"{root}/all/indra.toml", "w").write("\n".join(lines))
print(sum(1 for line in lines if " = " in line))
PY
"$KERNEL" --config-dir "$ROOT/all" --print-edge-args > "$ROOT/all.log" 2>&1
all_status=$?
[ "$all_status" = 0 ] || head -3 "$ROOT/all.log"
check "indra.toml accepts each setting in schemas/config-schema.json" "$all_status"

# --- 4. The edge gets its listeners from the resolved configuration ---
mapfile -t EDGE_ARGS < <("$KERNEL" --config-dir "$ROOT/cfg" --print-edge-args)
[ "${#EDGE_ARGS[@]}" -gt 0 ]
check "the kernel prints the edge arguments" $?
(cd "$ROOT" && exec erl -noshell -noinput -pa "$EBIN" "${EDGE_ARGS[@]}" \
    -eval '{ok, _} = application:ensure_all_started(indra_edge), timer:sleep(infinity).' \
    > "$ROOT/edge.log" 2>&1) &
EDGE_PID=$!

python3 - "$MQTT_PORT" "$WS_PORT" <<'PY'
import base64, os, socket, struct, sys, time
mqtt_port, ws_port = int(sys.argv[1]), int(sys.argv[2])

def wait_port(port):
    for _ in range(100):
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=2)
        except OSError:
            time.sleep(0.1)
    raise SystemExit(f"FAIL the edge does not listen on port {port} from indra.toml")

def packet(kind, body):
    return bytes([kind, len(body)]) + body

def field(data):
    return struct.pack(">H", len(data)) + data

def mqtt_connect(sock, client_id, username=None):
    if username is None:
        body = b"\x00\x04MQTT\x04\x02\x00\x3c" + field(client_id)
    else:
        # Connect flags: username, password and clean session.
        body = b"\x00\x04MQTT\x04\xc2\x00\x3c" + field(client_id) + field(username) + field(b"pw")
    sock.sendall(packet(0x10, body))
    return sock.recv(4) == b"\x20\x02\x00\x00"

def receive(sock, seconds):
    sock.settimeout(seconds)
    try:
        return sock.recv(200)
    except OSError:
        return b""

failures = 0
def report(name, good):
    global failures
    print(("ok   " if good else "FAIL ") + name)
    failures += 0 if good else 1

sub = wait_port(mqtt_port)
report("listeners.tcp.bind from indra.toml is the MQTT bind in operation", mqtt_connect(sub, b"smoke-sub"))
topic = b"smoke/check"
sub.sendall(packet(0x82, b"\x00\x01" + struct.pack(">H", len(topic)) + topic + b"\x00"))
suback = sub.recv(5)
pub = socket.create_connection(("127.0.0.1", mqtt_port), timeout=5)
mqtt_connect(pub, b"smoke-pub")
pub.sendall(packet(0x30, struct.pack(">H", len(topic)) + topic + b"smoke-ok"))
sub.settimeout(5)
try:
    delivered = sub.recv(100)
except OSError:
    delivered = b""
report("a publish goes to a subscriber through the edge and the kernel",
       suback[:1] == b"\x90" and delivered.endswith(b"smoke-ok"))

# MQTT 5 delivery. Each MQTT 5 PUBLISH has a property length, also when
# there are no properties. The check compares the full packet.
def mqtt5_client(client_id):
    sock = socket.create_connection(("127.0.0.1", mqtt_port), timeout=5)
    sock.sendall(packet(0x10, b"\x00\x04MQTT\x05\x02\x00\x3c\x00" + field(client_id)))
    ack = receive(sock, 5)
    return sock, len(ack) >= 4 and ack[0] == 0x20 and ack[3] == 0

def subscribe5(sock, topic):
    sock.sendall(packet(0x82, b"\x00\x02\x00" + field(topic) + b"\x00"))
    ack = receive(sock, 5)
    return len(ack) >= 6 and ack[0] == 0x90 and ack[4] == 0 and ack[5] == 0

v5_topic = b"smoke/v5"
v5_token = os.urandom(8).hex().encode()
v5_sub, v5_ok = mqtt5_client(b"smoke-v5-sub")
v5_ready = v5_ok and subscribe5(v5_sub, v5_topic)
# The publisher sets the retain flag, thus the broker keeps the message.
pub.sendall(packet(0x31, field(v5_topic) + v5_token))
report("an MQTT 5 subscriber gets a publish with an empty property section",
       v5_ready and receive(v5_sub, 5) == packet(0x30, field(v5_topic) + b"\x00" + v5_token))
v5_late, v5_late_ok = mqtt5_client(b"smoke-v5-late")
v5_late.sendall(packet(0x82, b"\x00\x02\x00" + field(v5_topic) + b"\x00"))
v5_replay = b""
for _ in range(2):
    v5_replay += receive(v5_late, 5)
    if v5_token in v5_replay:
        break
report("a new MQTT 5 subscription gets the retained message with the retain flag",
       v5_late_ok and v5_replay.endswith(packet(0x31, field(v5_topic) + b"\x00" + v5_token)))

# Tenants. The payload is random, thus the broker cannot know it.
def tenant_client(client_id, username):
    sock = socket.create_connection(("127.0.0.1", mqtt_port), timeout=5)
    return sock, mqtt_connect(sock, client_id, username)

def subscribe(sock, topic):
    sock.sendall(packet(0x82, b"\x00\x01" + field(topic) + b"\x00"))
    return sock.recv(5)[:1] == b"\x90"

# Fan-out. One publish to many subscribers must reach each of them.
# The count is larger than one write batch of the kernel for each link,
# thus a kernel that writes one batch and then waits fails this check.
import select
fan_topic = b"smoke/fan"
fan_token = os.urandom(6).hex().encode()
fan_socks = []
for index in range(400):
    fan_sock = socket.create_connection(("127.0.0.1", mqtt_port), timeout=5)
    if mqtt_connect(fan_sock, b"smoke-fan-%d" % index) and subscribe(fan_sock, fan_topic):
        fan_socks.append(fan_sock)
FAN_PUBLISHES = 4
for _ in range(FAN_PUBLISHES):
    pub.sendall(packet(0x30, field(fan_topic) + fan_token))
fan_seen = {s: b"" for s in fan_socks}
fan_deadline = time.time() + 10
def fan_complete():
    return all(data.count(fan_token) >= FAN_PUBLISHES for data in fan_seen.values())
while time.time() < fan_deadline and not fan_complete():
    readable, _, _ = select.select(fan_socks, [], [], 0.5)
    for s in readable:
        try:
            fan_seen[s] += s.recv(4096)
        except OSError:
            pass
fan_got = sum(data.count(fan_token) for data in fan_seen.values())
report("each of 400 subscribers gets each of 4 publishes (%d of %d deliveries)" % (fan_got, 400 * FAN_PUBLISHES),
       len(fan_socks) == 400 and fan_complete())
for s in fan_socks:
    s.close()

secret = base64.b16encode(os.urandom(8))
a_sub, a_ok = tenant_client(b"smoke-a-sub", b"alpha")
b_sub, b_ok = tenant_client(b"smoke-b-sub", b"beta")
a_pub, _ = tenant_client(b"smoke-a-pub", b"alpha")
topic = b"smoke/tenant"
ready = a_ok and b_ok and subscribe(a_sub, topic) and subscribe(b_sub, topic)
a_pub.sendall(packet(0x30, field(topic) + secret))
in_tenant = receive(a_sub, 5)
other_tenant = receive(b_sub, 2)
report("a subscriber gets the publish of a client in the same tenant",
       ready and in_tenant.endswith(secret))
report("a subscriber does not get the publish of a client in a different tenant",
       ready and secret not in other_tenant)

# Same client id in two tenants. Both connects succeed.
# Both sockets stay open. A takeover between tenants fails.
a_dup, a_dup_ok = tenant_client(b"smoke-dup", b"alpha")
b_dup, b_dup_ok = tenant_client(b"smoke-dup", b"beta")
b_pub, _ = tenant_client(b"smoke-b-pub", b"beta")
dup_topic = b"smoke/dup"
dup_ready = (a_dup_ok and b_dup_ok
             and subscribe(a_dup, dup_topic) and subscribe(b_dup, dup_topic))
a_pub.sendall(packet(0x30, field(dup_topic) + secret))
a_dup_got = receive(a_dup, 5)
b_dup_got = receive(b_dup, 2)
report("two clients with the same client id stay connected in two tenants",
       dup_ready and a_dup_got.endswith(secret) and secret not in b_dup_got)
b_pub.sendall(packet(0x30, field(dup_topic) + secret))
b_dup_got2 = receive(b_dup, 5)
a_dup_got2 = receive(a_dup, 2)
report("a takeover between tenants does not happen",
       dup_ready and b_dup_got2.endswith(secret) and secret not in a_dup_got2)

def upgrade(path):
    sock = wait_port(ws_port)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall((f"GET {path} HTTP/1.1\r\nHost: smoke\r\nUpgrade: websocket\r\n"
                  f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                  "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n").encode())
    return sock.recv(200).split(b"\r\n")[0]

report("listeners.ws.path from indra.toml is the WebSocket path in operation",
       b"101" in upgrade("/smoke") and b"404" in upgrade("/mqtt"))
sys.exit(1 if failures else 0)
PY
[ $? = 0 ] || failures=$((failures + 1))

if [ "$failures" = 0 ]; then
    echo "boot smoke: all checks are satisfactory"
    exit 0
fi
echo "boot smoke: $failures check(s) failed"
echo "--- kernel log"; tail -15 "$ROOT/kernel.log"
echo "--- edge log"; tail -15 "$ROOT/edge.log" 2>/dev/null
exit 1
