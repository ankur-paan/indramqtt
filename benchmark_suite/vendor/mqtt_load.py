#!/usr/bin/env python3
"""PERF-01 asyncio raw MQTT 3.1.1 load generator (QoS 0, paired topics).

Topology: N publishers + N subscribers, paired 1:1. Publisher ``i``
publishes to ``perf/pair/<i>``; subscriber ``i`` subscribes to the same
topic. Every message carries its send timestamp (``time.time_ns``) in the
first 8 payload bytes, so end-to-end latency is measured with a single
clock (no cross-host sync error).

Payload size is exactly ``--payload`` bytes (default 128).

Usage (from WSL)::

    python3 mqtt_load.py --host 127.0.0.1 --port 11883 \\
        --pubs 100 --subs 100 --rate 5000 --duration 20 \\
        --out /tmp/perf_5k.json

Report JSON contains in/out rates, delivered %, latency percentiles,
per-second buckets, and handshake (CONNECT/CONNACK, SUBSCRIBE/SUBACK)
round-trip samples.
"""

import argparse
import asyncio
import json
import struct
import time

HEADER = struct.Struct("!Q I H")  # send_ns, seq, pub_idx


def encode_remaining(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


async def read_packet(reader: asyncio.StreamReader):
    hdr = await reader.readexactly(1)
    ptype = hdr[0]
    mult = 1
    length = 0
    while True:
        b = (await reader.readexactly(1))[0]
        length += (b & 0x7F) * mult
        mult *= 128
        if not b & 0x80:
            break
    body = await reader.readexactly(length) if length else b""
    return ptype, body


def encode_connect(client_id: bytes, keepalive: int = 60) -> bytes:
    vh = b"\x00\x04MQTT\x04\x02" + struct.pack("!H", keepalive)
    pl = struct.pack("!H", len(client_id)) + client_id
    return b"\x10" + encode_remaining(len(vh) + len(pl)) + vh + pl


def encode_subscribe(pid: int, topic: bytes) -> bytes:
    body = struct.pack("!H", pid) + struct.pack("!H", len(topic)) + topic + b"\x00"
    return b"\x82" + encode_remaining(len(body)) + body


def encode_publish(topic: bytes, payload: bytes) -> bytes:
    body = struct.pack("!H", len(topic)) + topic + payload
    return b"\x30" + encode_remaining(len(body)) + body


def make_payload(send_ns: int, seq: int, pub_idx: int, size: int) -> bytes:
    pad = size - HEADER.size
    return HEADER.pack(send_ns, seq, pub_idx) + b"\x55" * pad


class Stats:
    def __init__(self):
        self.sent = 0
        self.received = 0
        self.lat = []          # ms
        self.conn_rt = []      # ms (CONNECT -> CONNACK)
        self.sub_rt = []       # ms (SUBSCRIBE -> SUBACK)
        self.per_sec_sent = {}
        self.per_sec_recv = {}
        self.t0 = None

    def sec(self):
        return int(time.time() - self.t0)


async def publisher(host, port, idx, rate_per_pub, duration, stats, stop, topics):
    reader, writer = await asyncio.open_connection(host, port)
    t = time.monotonic()
    writer.write(encode_connect(f"perf-pub-{idx}".encode()))
    await writer.drain()
    ptype, body = await read_packet(reader)
    assert ptype == 0x20 and body[1] == 0, f"pub {idx} CONNACK failed: {body.hex()}"
    stats.conn_rt.append((time.monotonic() - t) * 1000.0)
    topic = topics[idx % len(topics)]
    interval = 1.0 / rate_per_pub
    deadline = time.monotonic()
    end = deadline + duration
    seq = 0
    payload_size = PAYLOAD_SIZE
    pub_errors = 0
    while time.monotonic() < end and not stop.is_set():
        send_ns = time.time_ns()
        try:
            writer.write(encode_publish(topic, make_payload(send_ns, seq, idx, payload_size)))
            if seq % 200 == 0:
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
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
            # behind schedule: yield so the loop can flush the socket
            if deadline < now - 0.5:
                deadline = now
            await asyncio.sleep(0)
    try:
        writer.write(b"\xe0\x00")
        writer.close()
    except Exception:
        pass
    stats.pub_errors = getattr(stats, "pub_errors", 0) + pub_errors


async def subscriber(host, port, idx, stats, stop, drain_extra, topics):
    reader, writer = await asyncio.open_connection(host, port)
    t = time.monotonic()
    writer.write(encode_connect(f"perf-sub-{idx}".encode()))
    await writer.drain()
    ptype, body = await read_packet(reader)
    assert ptype == 0x20 and body[1] == 0, f"sub {idx} CONNACK failed: {body.hex()}"
    stats.conn_rt.append((time.monotonic() - t) * 1000.0)
    t = time.monotonic()
    # One SUBSCRIBE carrying every topic (also exercises multi-filter decode
    # on both sides: beam decode_subscribe + kernel decode_subscribe_meta).
    sub_body = struct.pack("!H", 1)
    for topic in topics:
        sub_body += struct.pack("!H", len(topic)) + topic + b"\x00"
    writer.write(b"\x82" + encode_remaining(len(sub_body)) + sub_body)
    await writer.drain()
    while True:
        ptype, body = await read_packet(reader)
        if ptype == 0x90:
            stats.sub_rt.append((time.monotonic() - t) * 1000.0)
            break
    try:
        # NOTE: the 5 s timeout only re-checks `stop` so the task ends
        # promptly after publishers finish; it is NOT a give-up (timeouts
        # loop back), so a quiet broker shows up as a gap, never an exit.
        while not stop.is_set():
            try:
                ptype, body = await asyncio.wait_for(read_packet(reader), timeout=5.0)
            except asyncio.TimeoutError:
                continue
            if ptype & 0xF0 == 0x30:
                tlen = struct.unpack("!H", body[:2])[0]
                payload = body[2 + tlen:]
                if len(payload) >= HEADER.size:
                    send_ns, _, _ = HEADER.unpack(payload[: HEADER.size])
                    stats.lat.append((time.time_ns() - send_ns) / 1e6)
                    stats.received += 1
                    stats.per_sec_recv[stats.sec()] = stats.per_sec_recv.get(stats.sec(), 0) + 1
    except (asyncio.IncompleteReadError, ConnectionResetError):
        stats.sub_disconnects = getattr(stats, "sub_disconnects", 0) + 1
    # drain late messages after publishers stop; the subscriber NEVER gives
    # up while publishers are active (no read timeout there), so a quiet
    # broker shows up as a gap, not as an early exit.
    end = time.monotonic() + drain_extra
    try:
        while time.monotonic() < end:
            ptype, body = await asyncio.wait_for(
                read_packet(reader), timeout=max(0.1, end - time.monotonic()))
            if ptype & 0xF0 == 0x30:
                tlen = struct.unpack("!H", body[:2])[0]
                payload = body[2 + tlen:]
                if len(payload) >= HEADER.size:
                    send_ns, _, _ = HEADER.unpack(payload[: HEADER.size])
                    stats.lat.append((time.time_ns() - send_ns) / 1e6)
                    stats.received += 1
                    stats.per_sec_recv[stats.sec()] = stats.per_sec_recv.get(stats.sec(), 0) + 1
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    try:
        writer.write(b"\xe0\x00")
        writer.close()
    except Exception:
        pass


def pct(data, p):
    if not data:
        return None
    s = sorted(data)
    k = min(len(s) - 1, int(p / 100.0 * len(s)))
    return s[k]


async def main():
    global PAYLOAD_SIZE
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11883)
    ap.add_argument("--pubs", type=int, default=100)
    ap.add_argument("--subs", type=int, default=100)
    ap.add_argument("--rate", type=float, default=5000,
                    help="aggregate target msg/s across all publishers")
    ap.add_argument("--duration", type=float, default=20)
    ap.add_argument("--payload", type=int, default=128)
    ap.add_argument("--drain", type=float, default=3,
                    help="extra seconds to wait for late messages")
    ap.add_argument("--shared", type=int, default=0,
                    help="fan-out mode: N shared topics (perf/fan/<i>); all "
                         "subs subscribe to all of them, pubs spread across "
                         "them. 0 = paired 1:1 mode (perf/pair/<i>).")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    PAYLOAD_SIZE = args.payload

    stats = Stats()
    stats.t0 = time.time()
    stop = asyncio.Event()

    if args.shared > 0:
        topics = [f"perf/fan/{i}".encode() for i in range(args.shared)]
        fanout = args.subs  # every message is delivered to every subscriber
    else:
        assert args.subs == args.pubs, "paired mode needs pubs == subs"
        topics = [f"perf/pair/{i}".encode() for i in range(args.pubs)]
        fanout = 1
    stats.fanout = fanout

    subs = [asyncio.create_task(subscriber(args.host, args.port, i, stats, stop, args.drain, topics))
            for i in range(args.subs)]
    await asyncio.sleep(2.0)  # let all subscriptions install before publishing
    rate_per_pub = args.rate / args.pubs
    pubs = [asyncio.create_task(
        publisher(args.host, args.port, i, rate_per_pub, args.duration, stats, stop, topics))
        for i in range(args.pubs)]
    await asyncio.gather(*pubs)
    stop.set()
    await asyncio.gather(*subs)

    elapsed = time.time() - stats.t0
    lat = stats.lat
    report = {
        "tool": "team/perf/tools/mqtt_load.py (asyncio raw MQTT 3.1.1, QoS 0, paired 1:1)",
        "target_rate": args.rate,
        "duration": args.duration,
        "pubs": args.pubs,
        "subs": args.subs,
        "payload_bytes": args.payload,
        "sent": stats.sent,
        "received": stats.received,
        "pub_errors": getattr(stats, "pub_errors", 0),
        "sub_disconnects": getattr(stats, "sub_disconnects", 0),
        "fanout": getattr(stats, "fanout", 1),
        "delivered_pct": (100.0 * stats.received / (stats.sent * getattr(stats, "fanout", 1))
                          if stats.sent else 0.0),
        "in_rate": stats.sent / args.duration,
        "out_rate": stats.received / args.duration,
        "latency_ms": {
            "count": len(lat),
            "avg": sum(lat) / len(lat) if lat else None,
            "p50": pct(lat, 50),
            "p90": pct(lat, 90),
            "p99": pct(lat, 99),
            "max": max(lat) if lat else None,
        },
        "handshake_ms": {
            "conn_avg": sum(stats.conn_rt) / len(stats.conn_rt) if stats.conn_rt else None,
            "conn_p99": pct(stats.conn_rt, 99),
            "sub_avg": sum(stats.sub_rt) / len(stats.sub_rt) if stats.sub_rt else None,
            "sub_p99": pct(stats.sub_rt, 99),
        },
        "per_sec_sent": stats.per_sec_sent,
        "per_sec_recv": stats.per_sec_recv,
        "wall_elapsed": elapsed,
    }
    print(json.dumps(report, indent=1))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(report, f, indent=1)


if __name__ == "__main__":
    asyncio.run(main())
