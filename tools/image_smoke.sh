#!/usr/bin/env bash
# Test for a container that runs the IndraMQTT image.
#
# Start the container first (for example with `docker compose up -d`).
# This script examines the container through its published ports.
#
# Usage:
#   tools/image_smoke.sh <container name> <MQTT host port> <WebSocket host port>
set -u

CONTAINER=${1:?give the container name}
MQTT_PORT=${2:?give the MQTT host port}
WS_PORT=${3:?give the WebSocket host port}
failures=0

check() { if [ "$2" = 0 ]; then echo "ok   $1"; else echo "FAIL $1"; failures=$((failures + 1)); fi; }

[ "$(docker exec "$CONTAINER" id -un)" != root ]
check "the broker does not run as root" $?

docker exec "$CONTAINER" sh -c 'ps -eo args | grep -q "[b]eam"'
check "the edge runs in the container" $?

# The compose file sets INDRA_LOGGING__LEVEL=debug. The file sets info.
[ "$(docker logs "$CONTAINER" 2>&1 | grep -c DEBUG)" -gt 0 ]
check "the INDRA_* variable overrides logging.level from the file" $?

python3 - "$MQTT_PORT" "$WS_PORT" <<'PY'
import base64, os, socket, struct, sys
mqtt_port, ws_port = int(sys.argv[1]), int(sys.argv[2])
failures = 0

def report(name, good):
    global failures
    print(("ok   " if good else "FAIL ") + name)
    failures += 0 if good else 1

def packet(kind, body):
    return bytes([kind, len(body)]) + body

def mqtt_connect(client_id):
    sock = socket.create_connection(("127.0.0.1", mqtt_port), timeout=5)
    header = b"\x00\x04MQTT\x04\x02\x00\x3c"
    sock.sendall(packet(0x10, header + struct.pack(">H", len(client_id)) + client_id))
    return sock, sock.recv(4) == b"\x20\x02\x00\x00"

try:
    sub, accepted = mqtt_connect(b"image-sub")
    topic = b"ops/check"
    sub.sendall(packet(0x82, b"\x00\x01" + struct.pack(">H", len(topic)) + topic + b"\x00"))
    suback = sub.recv(5)
    pub, _ = mqtt_connect(b"image-pub")
    pub.sendall(packet(0x30, struct.pack(">H", len(topic)) + topic + b"image-ok"))
    delivered = sub.recv(100)
    report("a publish goes to a subscriber through the published MQTT port",
           accepted and suback[:1] == b"\x90" and delivered.endswith(b"image-ok"))
except OSError as error:
    report(f"a publish goes to a subscriber through the published MQTT port ({error})", False)

try:
    sock = socket.create_connection(("127.0.0.1", ws_port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(("GET /mqtt HTTP/1.1\r\nHost: image\r\nUpgrade: websocket\r\n"
                  f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                  "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n").encode())
    report("the published WebSocket port accepts the upgrade on /mqtt",
           b"101" in sock.recv(200).split(b"\r\n")[0])
except OSError as error:
    report(f"the published WebSocket port accepts the upgrade on /mqtt ({error})", False)
sys.exit(1 if failures else 0)
PY
[ $? = 0 ] || failures=$((failures + 1))

if [ "$failures" = 0 ]; then
    echo "image smoke: all checks are satisfactory"
    exit 0
fi
echo "image smoke: $failures check(s) failed"
exit 1
