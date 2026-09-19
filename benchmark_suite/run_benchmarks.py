#!/usr/bin/env python3
"""IndraMQTT benchmark_suite runner (v5).

Runs every scenario in ``scenarios.json`` end to end against a running
stack and writes the results JSON. Each scenario spawns ``mqtt_bench.py``
as a subprocess with the scenario's parameters, while broker resource
usage (RSS + CPU for the ``indramqtt`` kernel process and the ``beam.smp``
edge process) is sampled inside the stack container through ``exec_helper.sh
exec`` (``/proc`` scan loop, no extra tooling needed in the container).

Usage (from the repo root)::

    python benchmark_suite/run_benchmarks.py \
      --host 100.104.51.36 --port 13483 \
      --exec-helper ../team-workspace/team/exec_helper.sh \
      --target-name broker-bench \
      --out benchmark_suite/benchmark_results_v5.json

Resource sampling is best-effort: when ``--target-name`` is omitted
(or sampling fails), the ``*_cpu``/``*_rss_mb`` fields are ``null`` and
the run is still valid for throughput/latency/delivery comparisons.

Result rows keep every field name ``benchmark_results_v4.json`` used
(``scenario, qos, pub_clients, sub_clients, payload_bytes, interval_ms,
duration_sec, in_rate, out_rate, total_tps, delivery_pct, rust_*,
beam_*, combined_*, cores_utilized, combined_ram_mb,
tps_per_core_*``) and add real latency fields (``avg_latency_ms``,
``p50_latency_ms``, ``p99_latency_ms``, ``max_latency_ms``) plus
diagnostics (``sent``, ``received``, ``fanout``, ``pub_errors``,
``sub_disconnects``, ``pubacks_received``, ``framing_skips``,
``latency_invalid_count``, ``target_rate``, ``handshake_ms``). ``delivery_pct`` is the TRUE delivery
ratio ``100 * received / (sent * fanout)``; v4's fan-out/fan-in rows
reported ``out/in`` ignoring fanout, so compare with care (see README).
"""

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))

SCAN_SH = r"""
SAMPLES=%d
INTERVAL=%d
for i in $(seq 1 $SAMPLES); do
  echo "SAMPLE $i"
  head -1 /proc/stat
  for d in /proc/[0-9]*; do
    if [ -r "$d/stat" ] && [ -r "$d/statm" ]; then
      comm=$(cut -d' ' -f2 "$d/stat" | tr -d '()')
      if [ "$comm" = "indramqtt" ] || [ "$comm" = "beam.smp" ]; then
        set -- $(cut -d' ' -f14,15,24 "$d/stat")
        rss_pages=$(cut -d' ' -f2 "$d/statm")
        echo "PROC $comm $1 $2 $rss_pages"
      fi
    fi
  done
  sleep $INTERVAL
done
"""


def parse_samples(out, ncpu=1):
    """Fold raw scan output into per-group {rss_kb_peak, cpu_pct_avg, cpu_pct_peak}.

    CPU is percent of ONE core (100 = one core saturated): the /proc/stat
    total advances ncpu jiffies per wall jiffy, so scale by ncpu.
    """
    HZ = 100.0
    PAGE_KB = 4.0
    samples = []
    cur = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SAMPLE"):
            if cur is not None:
                samples.append(cur)
            cur = {"cpu_total": None, "procs": {}}
        elif line.startswith("cpu ") and cur is not None:
            parts = line.split()[1:]
            cur["cpu_total"] = sum(float(x) for x in parts)
        elif line.startswith("PROC") and cur is not None:
            _, comm, utime, stime, rss_pages = line.split()
            g = cur["procs"].setdefault(comm, {"t": 0.0, "rss": 0.0})
            g["t"] += float(utime) + float(stime)
            g["rss"] += float(rss_pages) * PAGE_KB
    if cur is not None:
        samples.append(cur)
    agg = {}
    for comm in ("indramqtt", "beam.smp"):
        rss_peak = 0.0
        avg_cpus, peak_cpus = [], []
        for a, b in zip(samples, samples[1:]):
            if a["cpu_total"] is None or b["cpu_total"] is None:
                continue
            dt_cpu = b["cpu_total"] - a["cpu_total"]
            if dt_cpu <= 0:
                continue
            dt = dt_cpu / HZ
            for s in (a, b):
                rss_peak = max(rss_peak, s["procs"].get(comm, {}).get("rss", 0.0))
            dproc = b["procs"].get(comm, {}).get("t", 0.0) - a["procs"].get(comm, {}).get("t", 0.0)
            cpu = 100.0 * ncpu * (dproc / HZ) / dt if dt > 0 else 0.0
            avg_cpus.append(cpu)
            peak_cpus.append(cpu)
        if samples:
            rss_peak = max(rss_peak, samples[-1]["procs"].get(comm, {}).get("rss", 0.0))
        agg[comm] = {
            "rss_kb_peak": rss_peak,
            "cpu_avg": sum(avg_cpus) / len(avg_cpus) if avg_cpus else None,
            "cpu_peak": max(peak_cpus) if peak_cpus else None,
        }
    return agg


def helper_cmd(exec_helper):
    return ["bash", exec_helper]


def sample_resources(exec_helper, container, duration_sec, interval=2, ncpu=1):
    """Run the /proc scan loop in the container; returns parsed aggregates."""
    n = max(2, int(duration_sec / interval) + 1)
    cmd = helper_cmd(exec_helper) + ["exec", container, "sh", "-c", SCAN_SH % (n, interval)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=duration_sec + 60)
        return parse_samples(p.stdout, ncpu)
    except Exception as e:
        print(f"resource sampling failed: {e}", flush=True)
        return {}
    except Exception as e:
        print(f"resource sampling failed: {e}", flush=True)
        return {}


def container_info(exec_helper, container):
    info = {}
    cmds = {
        "cpu_model": "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'",
        "cpus": "nproc",
        "mem_limit": "cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo unknown",
        "os": "grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"'",
        "otp": "erl -eval 'io:format(\"~s\", [erlang:system_info(otp_release)]), halt().' -noshell 2>/dev/null || echo unknown",
    }
    for key, sh in cmds.items():
        try:
            p = subprocess.run(helper_cmd(exec_helper) + ["exec", container, "sh", "-c", sh],
                               capture_output=True, text=True, timeout=60)
            info[key] = p.stdout.strip().splitlines()[0] if p.stdout.strip() else "unknown"
        except Exception:
            info[key] = "unknown"
    return info


def tcp_rtt_ms(host, port, tries=5):
    rtts = []
    for _ in range(tries):
        t = time.monotonic()
        try:
            s = socket.create_connection((host, port), timeout=10)
            rtts.append((time.monotonic() - t) * 1000.0)
            s.close()
        except OSError:
            pass
        time.sleep(0.2)
    return rtts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11883)
    ap.add_argument("--scenarios", default=os.path.join(HERE, "scenarios.json"))
    ap.add_argument("--bench", default=os.path.join(HERE, "mqtt_bench.py"))
    ap.add_argument("--exec-helper", default="")
    ap.add_argument("--target-name", default="")
    ap.add_argument("--stack-image", default="erlang:27")
    ap.add_argument("--publish-sec", type=float, default=0, help="override scenarios.json publish duration")
    ap.add_argument("--settle-sec", type=float, default=20, help="pause between scenarios")
    ap.add_argument("--only", default="", help="comma-separated scenario ids to run")
    ap.add_argument("--out", default=os.path.join(HERE, "benchmark_results_v5.json"))
    args = ap.parse_args()

    with open(args.scenarios) as f:
        spec = json.load(f)
    scenarios = spec["scenarios"]
    if args.only:
        want = set(args.only.split(","))
        scenarios = [s for s in scenarios if s["id"] in want]

    sampling = bool(args.exec_helper and args.target_name)
    env = {
        "stack_image": args.stack_image,
        "target_name": args.target_name or "n/a (no resource sampling)",
        "mqtt_endpoint": f"{args.host}:{args.port}",
        "load_generator": f"{platform.system()} {platform.release()} {platform.machine()}, "
                          f"python {platform.python_version()}, "
                          f"benchmark_suite/mqtt_bench.py over TCP to the remote broker host",
        "generator_tcp_connect_rtt_ms": tcp_rtt_ms(args.host, args.port),
    }
    if sampling:
        env.update(container_info(args.exec_helper, args.target_name))
    try:
        stack_ncpu = int(env.get("cpus", 1))
    except (ValueError, TypeError):
        stack_ncpu = 1

    rows = []
    for n, sc in enumerate(scenarios):
        publish = args.publish_sec or spec.get("publish_sec", 20)
        rate = sc["pubs"] * 1000.0 / sc["interval_ms"]
        drain = sc.get("drain_sec", 10)
        print(f"[{n + 1}/{len(scenarios)}] {sc['id']}: "
              f"qos={sc['qos']} pubs={sc['pubs']} subs={sc['subs']} "
              f"payload={sc['payload_bytes']} interval={sc['interval_ms']}ms "
              f"target_rate={rate:.0f}/s publish={publish}s drain={drain}s", flush=True)

        res = {}
        sampler = None
        if sampling:
            sampler = threading.Thread(
                target=lambda: res.update(sample_resources(
                    args.exec_helper, args.target_name, publish + drain + 8, ncpu=stack_ncpu)))
            sampler.start()

        out_file = args.out + f".{sc['id']}.tmp.json"
        cmd = [sys.executable, args.bench, "--host", args.host, "--port", str(args.port),
               "--pubs", str(sc["pubs"]), "--subs", str(sc["subs"]),
               "--rate", str(rate), "--duration", str(publish),
               "--payload", str(sc["payload_bytes"]), "--drain", str(drain),
               "--qos", str(sc["qos"]), "--shared", str(sc.get("shared", 0)),
               "--tag", sc["id"],
               "--out", out_file]
        t0 = time.time()
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=publish + drain + 300)
        wall = time.time() - t0
        if p.returncode != 0:
            print(f"SCENARIO_FAILED {sc['id']} rc={p.returncode}\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}")
            continue
        with open(out_file) as f:
            rep = json.load(f)
        try:
            os.remove(out_file)
        except OSError:
            pass
        if sampler is not None:
            sampler.join()
        agg = res if res else {"indramqtt": {"rss_kb_peak": 0, "cpu_avg": None, "cpu_peak": None},
                              "beam.smp": {"rss_kb_peak": 0, "cpu_avg": None, "cpu_peak": None}}
        rust = agg.get("indramqtt", {})
        beam = agg.get("beam.smp", {})
        rust_cpu = rust.get("cpu_avg")
        beam_cpu = beam.get("cpu_avg")
        combined = (rust_cpu or 0) + (beam_cpu or 0) if (rust_cpu is not None or beam_cpu is not None) else None
        cores_used = combined / 100.0 if combined is not None else None
        stack_cpus = stack_ncpu or None
        total_tps = rep["in_rate"] + rep["out_rate"]
        lat = rep["latency_ms"]
        row = {
            "scenario": sc["v4_name"],
            "scenario_id": sc["id"],
            "qos": sc["qos"],
            "pub_clients": sc["pubs"],
            "sub_clients": sc["subs"],
            "payload_bytes": sc["payload_bytes"],
            "interval_ms": sc["interval_ms"],
            "duration_sec": publish,
            "drain_sec": drain,
            "target_rate": rate,
            "in_rate": rep["in_rate"],
            "out_rate": rep["out_rate"],
            "total_tps": total_tps,
            "avg_latency_ms": lat["avg"],
            "p50_latency_ms": lat["p50"],
            "p99_latency_ms": lat["p99"],
            "max_latency_ms": lat["max"],
            "delivery_pct": rep["delivered_pct"],
            "rust_avg_cpu": rust_cpu,
            "rust_peak_cpu": rust.get("cpu_peak"),
            "rust_rss_mb": (rust.get("rss_kb_peak") or 0) / 1024.0 if sampling else None,
            "beam_avg_cpu": beam_cpu,
            "beam_peak_cpu": beam.get("cpu_peak"),
            "beam_rss_mb": (beam.get("rss_kb_peak") or 0) / 1024.0 if sampling else None,
            "combined_cpu_pct": combined,
            "combined_peak_cpu_pct": ((rust.get("cpu_peak") or 0) + (beam.get("cpu_peak") or 0))
            if (rust.get("cpu_peak") is not None or beam.get("cpu_peak") is not None) else None,
            "cores_utilized": cores_used,
            "combined_ram_mb": ((rust.get("rss_kb_peak") or 0) + (beam.get("rss_kb_peak") or 0)) / 1024.0
            if sampling else None,
            "tps_per_core_allocated": total_tps / stack_cpus if stack_cpus else None,
            "tps_per_core_utilized": total_tps / cores_used if cores_used else None,
            "sent": rep["sent"],
            "received": rep["received"],
            "fanout": rep["fanout"],
            "pub_errors": rep["pub_errors"],
            "sub_disconnects": rep["sub_disconnects"],
            "pub_exceptions": rep.get("pub_exceptions", 0),
            "sub_exceptions": rep.get("sub_exceptions", 0),
            "pubacks_received": rep["pubacks_received"],
            "framing_skips": rep["framing_skips"],
            "latency_invalid_count": rep.get("latency_invalid_count", 0),
            "handshake_ms": rep["handshake_ms"],
            "wall_elapsed": wall,
        }
        rows.append(row)
        print(f"  sent={rep['sent']} received={rep['received']} "
              f"delivered={rep['delivered_pct']:.1f}% in={rep['in_rate']:.0f}/s out={rep['out_rate']:.0f}/s "
              f"avg={lat['avg'] and round(lat['avg'], 1)}ms p99={lat['p99'] and round(lat['p99'], 1)}ms "
              f"neg={rep.get('latency_invalid_count', 0)} skips={rep['framing_skips']} "
              f"rust_cpu={rust_cpu and round(rust_cpu, 1)} beam_cpu={beam_cpu and round(beam_cpu, 1)}", flush=True)
        if n < len(scenarios) - 1:
            time.sleep(args.settle_sec)

    result = {"environment": env, "scenarios": rows}
    with open(args.out, "w") as f:
        json.dump(result, f, indent=1)
    print(f"wrote {args.out} with {len(rows)} scenarios")


if __name__ == "__main__":
    main()
