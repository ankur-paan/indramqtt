#!/usr/bin/env python3
"""IndraMQTT benchmark_suite load generator (v5).

Extends the vendored ``team/perf/tools/mqtt_load.py`` (kept byte-identical
under ``vendor/``) with:

* ``--qos 0|1``: QoS 1 publishes (pipelined, packet ids cycle 1..65535) and
  QoS 1 subscriptions (requested QoS 1, PUBACK sent for each delivery).
  Framing, stamping and pacing reuse the vendored helpers unchanged; the
  differences from the vendored tool are: paired mode subscribes each
  subscriber only to its own topic (true 1:1, the vendored tool subscribes
  everyone to everything), client ids take a ``--tag`` prefix, and the
  guards below.
* Robustness guards: short/corrupt PUBLISH bodies are counted in
  ``framing_skips`` instead of crashing the subscriber (the vendored tool
  dies with ``struct.error`` on a truncated packet under backlog pressure),
  and deliveries whose stamp decodes to an impossible latency (negative,
  or older than the run itself — corrupt stamp bytes on the wire) are counted in
  ``latency_invalid_count`` and excluded from the latency percentiles.

Latency is measured the same way as the vendored tool: the publisher stamps
``time.time_ns()`` into the first 8 payload bytes, so end-to-end latency
uses a single clock (no cross-host sync error).

Topology mirrors the vendored tool:

* paired mode (default): N publishers + N subscribers 1:1, publisher ``i``
  publishes to ``bench/pair/<i>``, subscriber ``i`` subscribes to it.
  Fan-out factor 1.
* shared mode (``--shared K``): K shared topics ``bench/fan/<i>``;
  publishers spread round-robin across them, every subscriber subscribes to
  all of them. Fan-out factor = number of subscribers.

Report JSON (stdout, optionally ``--out``) contains sent/received counts,
true delivery %, in/out rates, latency percentiles (avg/p50/p90/p99/max),
handshake round-trip samples, QoS 1 PUBACK counts and framing skip counts.
"""

import argparse
import asyncio
import json
import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))
import mqtt_load as base  # noqa: E402  (vendored, byte-identical framing helpers)

PAYLOAD_SIZE = 128
QOS = 0
TAG = "bench"


def encode_publish_qos1(topic: bytes, packet_id: int, payload: bytes) -> bytes:
    body = struct.pack("!H", len(topic)) + topic + struct.pack("!H", packet_id) + payload
    return b"\x32" + base.encode_remaining(len(body)) + body


def encode_puback(packet_id: int) -> bytes:
    return b"\x40\x02" + struct.pack("!H", packet_id)


def encode_subscribe_qos(pid: int, topics: list, qos: int) -> bytes:
    body = struct.pack("!H", pid)
    for topic in topics:
        body += struct.pack("!H", len(topic)) + topic + bytes([qos])
    return b"\x82" + base.encode_remaining(len(body)) + body


def parse_publish(body: bytes):
    """Return (payload, qos_flag, packet_id) or None when truncated."""
    if len(body) < 2:
        return None
    tlen = struct.unpack("!H", body[:2])[0]
    rest = body[2 + tlen:]
    return rest


async def publisher(host, port, idx, rate_per_pub, duration, stats, stop, topics):
    reader, writer = await asyncio.open_connection(host, port)
    t = time.monotonic()
    writer.write(base.encode_connect(f"{TAG}-pub-{idx}".encode()))
    await writer.drain()
    ptype, body = await base.read_packet(reader)
    assert ptype == 0x20 and body[1] == 0, f"pub {idx} CONNACK failed: {body.hex()}"
    stats.conn_rt.append((time.monotonic() - t) * 1000.0)
    topic = topics[idx % len(topics)]
    interval = 1.0 / rate_per_pub
    deadline = time.monotonic()
    end = deadline + duration
    seq = 0
    pid = (idx % 65535) + 1
    pub_errors = 0
    ack_task = None
    if QOS == 1:
        async def count_acks():
            try:
                while True:
                    atype, _ = await base.read_packet(reader)
                    if atype == 0x40:
                        stats.acks += 1
            except (asyncio.IncompleteReadError, ConnectionResetError):
                pass
        ack_task = asyncio.create_task(count_acks())
    while time.monotonic() < end and not stop.is_set():
        send_ns = time.time_ns()
        payload = base.make_payload(send_ns, seq, idx, PAYLOAD_SIZE)
        try:
            if QOS == 1:
                writer.write(encode_publish_qos1(topic, pid, payload))
                pid = pid + 1 if pid < 65535 else 1
            else:
                writer.write(base.encode_publish(topic, payload))
            if seq % 200 == 0:
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError,
                ConnectionAbortedError, OSError):
            # The broker or the local stack dropped this connection under
            # load (RST / abort). Count it and stop this publisher; the
            # achieved rate is reported honestly instead of crashing the run.
            pub_errors += 1
            break
        seq += 1
        stats.sent += 1
        stats.per_sec_sent[stats.sec()] = stats.per_sec_sent.get(stats.sec(), 0) + 1
        deadline += interval
        now = time.monotonic()
        if deadline > now:
            try:
                await asyncio.wait_for(stop.wait(), timeout=deadline - now)
            except asyncio.TimeoutError:
                pass
        else:
            if deadline < now - 0.5:
                deadline = now
            await asyncio.sleep(0)
    if ack_task is not None:
        await asyncio.sleep(1.0)  # let trailing PUBACKs arrive
        ack_task.cancel()
    try:
        writer.write(b"\xe0\x00")
        writer.close()
    except Exception:
        pass
    stats.pub_errors = getattr(stats, "pub_errors", 0) + pub_errors


async def subscriber(host, port, idx, stats, stop, drain_extra, topics):
    reader, writer = await asyncio.open_connection(host, port)
    t = time.monotonic()
    writer.write(base.encode_connect(f"{TAG}-sub-{idx}".encode()))
    await writer.drain()
    ptype, body = await base.read_packet(reader)
    assert ptype == 0x20 and body[1] == 0, f"sub {idx} CONNACK failed: {body.hex()}"
    stats.conn_rt.append((time.monotonic() - t) * 1000.0)
    t = time.monotonic()
    writer.write(encode_subscribe_qos(1, topics, QOS))
    await writer.drain()
    while True:
        ptype, body = await base.read_packet(reader)
        if ptype == 0x90:
            stats.sub_rt.append((time.monotonic() - t) * 1000.0)
            break

    def handle(ptype, body):
        if ptype & 0xF0 != 0x30:
            return None
        qos_flag = (ptype & 0x06) >> 1
        payload = parse_publish(body)
        if payload is None:
            stats.framing_skips += 1
            return None
        if qos_flag == 1:
            if len(payload) < 2 + base.HEADER.size:
                stats.framing_skips += 1
                return None
            pid = struct.unpack("!H", payload[:2])[0]
            payload = payload[2:]
            return ("ack", pid, payload)
        if len(payload) < base.HEADER.size:
            stats.framing_skips += 1
            return None
        return ("noack", 0, payload)

    def record(payload):
        send_ns, _, _ = base.HEADER.unpack(payload[: base.HEADER.size])
        t = (time.time_ns() - send_ns) / 1e6
        if t < 0 or t > (time.time() - stats.t0) * 1000.0 + 5000.0:
            # Impossible on a single clock inside one run (negative, or
            # older than the run itself): the stamp bytes are corrupt
            # (wire corruption under backlog pressure). Count, don't hide.
            stats.lat_invalid += 1
            return
        stats.lat.append(t)
        stats.received += 1
        stats.per_sec_recv[stats.sec()] = stats.per_sec_recv.get(stats.sec(), 0) + 1

    try:
        while not stop.is_set():
            try:
                ptype, body = await asyncio.wait_for(base.read_packet(reader), timeout=5.0)
            except asyncio.TimeoutError:
                continue
            r = handle(ptype, body)
            if r is None:
                continue
            kind, pid, payload = r
            if kind == "ack":
                try:
                    writer.write(encode_puback(pid))
                except (ConnectionResetError, BrokenPipeError):
                    break
            record(payload)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        stats.sub_disconnects = getattr(stats, "sub_disconnects", 0) + 1
    end = time.monotonic() + drain_extra
    try:
        while time.monotonic() < end:
            ptype, body = await asyncio.wait_for(
                base.read_packet(reader), timeout=max(0.1, end - time.monotonic()))
            r = handle(ptype, body)
            if r is None:
                continue
            kind, pid, payload = r
            if kind == "ack":
                try:
                    writer.write(encode_puback(pid))
                except (ConnectionResetError, BrokenPipeError):
                    break
            record(payload)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    try:
        writer.write(b"\xe0\x00")
        writer.close()
    except Exception:
        pass


async def amain(args):
    global PAYLOAD_SIZE, QOS, TAG
    PAYLOAD_SIZE = args.payload
    QOS = args.qos
    TAG = args.tag
    stats = base.Stats()
    stats.t0 = time.time()
    stats.acks = 0
    stats.framing_skips = 0
    stats.lat_invalid = 0
    stop = asyncio.Event()

    if args.shared > 0:
        topics = [f"bench/fan/{i}".encode() for i in range(args.shared)]
        fanout = args.subs
        sub_topics = [topics for _ in range(args.subs)]
    else:
        assert args.subs == args.pubs, "paired mode needs pubs == subs"
        topics = [f"bench/pair/{i}".encode() for i in range(args.pubs)]
        fanout = 1
        # True 1:1 pairing: subscriber i subscribes ONLY to its own topic,
        # so each message is delivered exactly once when healthy.
        sub_topics = [[topics[i]] for i in range(args.subs)]
    stats.fanout = fanout

    subs = [asyncio.create_task(subscriber(args.host, args.port, i, stats, stop, args.drain, sub_topics[i]))
            for i in range(args.subs)]
    await asyncio.sleep(2.0)
    rate_per_pub = args.rate / args.pubs
    pubs = [asyncio.create_task(
        publisher(args.host, args.port, i, rate_per_pub, args.duration, stats, stop, topics))
        for i in range(args.pubs)]
    # return_exceptions: one dead connection must not cancel the other 499
    # publishers; partial achievement is reported, not hidden.
    pub_results = await asyncio.gather(*pubs, return_exceptions=True)
    stats.pub_exceptions = sum(1 for r in pub_results if isinstance(r, BaseException))
    stop.set()
    sub_results = await asyncio.gather(*subs, return_exceptions=True)
    stats.sub_exceptions = sum(1 for r in sub_results if isinstance(r, BaseException))

    lat = stats.lat
    report = {
        "tool": "benchmark_suite/mqtt_bench.py (asyncio raw MQTT 3.1.1, QoS %d)" % QOS,
        "qos": QOS,
        "target_rate": args.rate,
        "duration": args.duration,
        "drain": args.drain,
        "pubs": args.pubs,
        "subs": args.subs,
        "payload_bytes": args.payload,
        "shared_topics": args.shared,
        "sent": stats.sent,
        "received": stats.received,
        "pub_errors": getattr(stats, "pub_errors", 0),
        "sub_disconnects": getattr(stats, "sub_disconnects", 0),
        "pub_exceptions": getattr(stats, "pub_exceptions", 0),
        "sub_exceptions": getattr(stats, "sub_exceptions", 0),
        "pubacks_received": getattr(stats, "acks", 0),
        "framing_skips": getattr(stats, "framing_skips", 0),
        "latency_invalid_count": getattr(stats, "lat_invalid", 0),
        "fanout": getattr(stats, "fanout", 1),
        "delivered_pct": (100.0 * stats.received / (stats.sent * getattr(stats, "fanout", 1))
                          if stats.sent else 0.0),
        "in_rate": stats.sent / args.duration,
        "out_rate": stats.received / args.duration,
        "latency_ms": {
            "count": len(lat),
            "avg": sum(lat) / len(lat) if lat else None,
            "p50": base.pct(lat, 50),
            "p90": base.pct(lat, 90),
            "p99": base.pct(lat, 99),
            "max": max(lat) if lat else None,
        },
        "handshake_ms": {
            "conn_avg": sum(stats.conn_rt) / len(stats.conn_rt) if stats.conn_rt else None,
            "conn_p99": base.pct(stats.conn_rt, 99),
            "sub_avg": sum(stats.sub_rt) / len(stats.sub_rt) if stats.sub_rt else None,
            "sub_p99": base.pct(stats.sub_rt, 99),
        },
        "per_sec_sent": stats.per_sec_sent,
        "per_sec_recv": stats.per_sec_recv,
        "wall_elapsed": time.time() - stats.t0,
    }
    print(json.dumps(report, indent=1))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(report, f, indent=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11883)
    ap.add_argument("--pubs", type=int, default=100)
    ap.add_argument("--subs", type=int, default=100)
    ap.add_argument("--rate", type=float, default=5000)
    ap.add_argument("--duration", type=float, default=20)
    ap.add_argument("--payload", type=int, default=128)
    ap.add_argument("--drain", type=float, default=10)
    ap.add_argument("--qos", type=int, default=0, choices=[0, 1])
    ap.add_argument("--tag", default="bench",
                    help="client-id prefix; use a unique tag per scenario so "
                         "stale sessions cannot leak subscriptions across runs")
    ap.add_argument("--shared", type=int, default=0)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    asyncio.run(amain(args))


if __name__ == "__main__":
    main()
