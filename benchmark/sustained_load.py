#!/usr/bin/env python3
"""Sustained-load search at 1 CPU and 1 GB. One broker runs at a time.

A load step is sustained only if all of these are true:
  - the publishers keep the offered rate,
  - no message is lost,
  - the end-to-end latency stays below 1 s and does not increase,
  - the broker memory does not increase during the step,
  - the subscribers have all messages 2 s after the last publish.
The search finds the highest step of a fixed ladder that is sustained,
then confirms it with a longer run.

Usage: sustained_load.py <outdir> <label=image> [<label=image> ...]
           [--only <regex of scenario names>] [--step <scenario> <n> <seconds>]

A broker is "label=image". More docker arguments follow the image,
separated by "|". "port=N" gives the MQTT port of that broker, and the
arguments after "--" are the command of the container. Example:

  sustained_load.py out
    'ours=indramqtt:test|-e|INDRA_LISTENERS__TCP__NATIVE=true'
    'other=bytebeamio/rumqttd:latest|port=1884|-v|/tmp/r.toml:/r.toml:ro|--|-c|/r.toml'

See README.md in this directory for the method and the environment.
"""
import json, re, statistics, subprocess, sys, threading, time, os

BROKER_CPU = os.environ.get("BENCH_BROKER_CPU", "13")
PUB_CPUS = os.environ.get("BENCH_PUB_CPUS", "1,2,4")
SUB_CPUS = os.environ.get("BENCH_SUB_CPUS", "16,25,26,49")
PUB_CORES, SUB_CORES = len(PUB_CPUS.split(",")), len(SUB_CPUS.split(","))
# An image named "local" runs a build from the work tree. The variable
# holds the docker arguments (mounts, image, command) as a JSON list.
LOCAL_ARGS = json.loads(os.environ.get("BENCH_LOCAL_ARGS", "[]"))
BENCH = "emqx/emqtt-bench:latest"
DEFAULT_PORT = os.environ.get("BENCH_PORT", "1883")
PORT = DEFAULT_PORT
# MQTT protocol version of the generator: 4 (3.1.1) or 5.
VERSION = os.environ.get("BENCH_MQTT_VERSION", "4")
# Extra arguments for the generator, for example "-S" for TLS.
GEN_ARGS = os.environ.get("BENCH_GEN_ARGS", "").split()
NOFILE = "nofile=524288:524288"
STEP_S, CONFIRM_S = 45, 180
PAYLOAD = 256


def sh(*args, timeout=120):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return ""


def logs(name):
    try:
        p = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=60)
        return p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return ""


def rm(*names):
    subprocess.run(["docker", "rm", "-f", *names], capture_output=True)


def port_open():
    import socket
    try:
        socket.create_connection(("127.0.0.1", int(PORT)), timeout=1).close()
        return True
    except OSError:
        return False


def start_broker(image):
    # "image|arg|arg" gives extra docker arguments for this broker.
    # Arguments after "--" are the command of the container.
    # "port=N" gives the MQTT port of this broker.
    global PORT
    image, *extra = image.split("|")
    PORT = DEFAULT_PORT
    for item in list(extra):
        if item.startswith("port="):
            PORT = item[5:]
            extra.remove(item)
    command = []
    if "--" in extra:
        at = extra.index("--")
        extra, command = extra[:at], extra[at + 1:]
    rm("bench-broker", "bench-pub", "bench-sub", "bench-conn")
    for _ in range(30):          # the port of the previous broker must be free
        if not port_open():
            break
        time.sleep(1)
    sh("docker", "run", "-d", "--name", "bench-broker", "--network", "host", "--cpus=1",
       "--cpuset-cpus=" + BROKER_CPU, "--memory=1g", "--memory-swap=1g", "--ulimit", NOFILE,
       *extra, *(LOCAL_ARGS if image == "local" else [image]), *command)
    for _ in range(90):
        if port_open():
            time.sleep(6)
            return True
        time.sleep(1)
    return False


def to_mib(text):
    m = re.match(r"([0-9.]+)([KMG]i?B)", text)
    if not m:
        return 0.0
    v = float(m.group(1))
    return {"K": v / 1024, "M": v, "G": v * 1024}[m.group(2)[0]]


class Sampler(threading.Thread):
    """Reads CPU and memory of the bench containers in a loop."""

    def __init__(self):
        super().__init__(daemon=True)
        self.rows, self.stop = [], False

    def run(self):
        while not self.stop:
            names = [n for n in sh("docker", "ps", "--format", "{{.Names}}").split() if n.startswith("bench-")]
            if not names:
                time.sleep(0.5)
                continue
            out = sh("docker", "stats", "--no-stream", "--format", "{{.Name}} {{.CPUPerc}} {{.MemUsage}}", *names)
            now = time.time()
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        self.rows.append((now, parts[0], float(parts[1].rstrip("%")), to_mib(parts[2])))
                    except ValueError:
                        pass


def last_total(text, key):
    found = re.findall(r"\b%s total=(\d+)" % key, text)
    return int(found[-1]) if found else 0


SCENARIOS = {
    # name: (ladder, description)
    "p2p-qos0": ([25, 50, 75, 100, 150, 200, 250, 300, 400, 500, 600, 800, 1000, 1250, 1500, 2000, 2500, 3000],
                 "N publishers to N subscribers, one topic for each pair, 100 msg/s for each publisher, QoS 0"),
    "p2p-qos1": ([10, 25, 50, 75, 100, 150, 200, 250, 300, 400, 500, 600, 800, 1000, 1250, 1500, 2000],
                 "N publishers to N subscribers, one topic for each pair, 100 msg/s for each publisher, QoS 1"),
    "fan-in-qos0": ([25, 50, 75, 100, 150, 200, 250, 300, 400, 500, 600, 800, 1000, 1250, 1500, 2000, 2500, 3000],
                    "N publishers at 100 msg/s each to 1 subscriber with a wildcard filter, QoS 0"),
    "fan-out-qos0": ([500, 1000, 1500, 2000, 3000, 4000, 5000, 6000, 8000, 10000, 12000, 16000, 20000, 25000],
                     "1 publisher at 10 msg/s to N subscribers of one topic, QoS 0"),
}


def plan(scn, n, dur):
    """Returns (subs, sub_topic, qos, pubs, pub_topic, interval_ms, total_publishes, expected_recv, offered)."""
    if scn == "p2p-qos0":
        return n, "b/p/%i", 0, n, "b/p/%i", 10, n * 100 * dur, n * 100 * dur, n * 100
    if scn == "p2p-qos1":
        return n, "b/q/%i", 1, n, "b/q/%i", 10, n * 100 * dur, n * 100 * dur, n * 100
    if scn == "fan-in-qos0":
        return 1, "b/fi/#", 0, n, "b/fi/%i", 10, n * 100 * dur, n * 100 * dur, n * 100
    if scn == "fan-out-qos0":
        return n, "b/fo", 0, 1, "b/fo", 100, 10 * dur, 10 * dur * n, 10 * n
    raise ValueError(scn)


def step(label, image, scn, n, dur, outdir, tag):
    subs, stopic, qos, pubs, ptopic, ival, total, expected, offered = plan(scn, n, dur)
    res = {"broker": label, "scenario": scn, "n": n, "duration_s": dur, "offered_msg_s": offered,
           "expected": expected, "tag": tag}
    if not start_broker(image):
        res.update(verdict="broker-did-not-start")
        return res
    sh("docker", "run", "-d", "--name", "bench-sub", "--network", "host", "--cpuset-cpus=" + SUB_CPUS,
       "--ulimit", NOFILE, BENCH, "sub", "-h", "127.0.0.1", "-p", PORT, "-V", VERSION, "-c", str(subs),
       "-i", "1", "-t", stopic, "-q", str(qos), "--payload-hdrs", "ts", *GEN_ARGS)
    t_wait = time.time()
    while time.time() - t_wait < 180 and last_total(logs("bench-sub"), "sub") < subs:
        time.sleep(1)
    if last_total(logs("bench-sub"), "sub") < subs:
        res.update(verdict="subscribers-did-not-connect", subscribed=last_total(logs("bench-sub"), "sub"))
        return res
    time.sleep(3)
    sampler = Sampler()
    sampler.start()
    sh("docker", "run", "-d", "--name", "bench-pub", "--network", "host", "--cpuset-cpus=" + PUB_CPUS,
       "--ulimit", NOFILE, BENCH, "pub", "-h", "127.0.0.1", "-p", PORT, "-V", VERSION, "-c", str(pubs),
       "-i", "1", "-t", ptopic, "-q", str(qos), "-I", str(ival), "-L", str(total), "-s", str(PAYLOAD),
       "-F", "100", "--payload-hdrs", "ts", "-w", "true", *GEN_ARGS)
    t_start = None
    t0 = time.time()
    while time.time() - t0 < 120:
        if "start publishing" in logs("bench-pub"):
            t_start = time.time()
            break
        time.sleep(0.3)
    if t_start is None:
        sampler.stop = True
        res.update(verdict="publishers-did-not-connect")
        return res
    # Wait for the publishers to complete. A broker that cannot keep the
    # rate makes this longer than the planned duration.
    t_complete = None
    deadline = t_start + dur * 2.5 + 30
    while time.time() < deadline:
        if "publish complete" in logs("bench-pub"):
            t_complete = time.time()
            break
        if "true" not in sh("docker", "inspect", "-f", "{{.State.Running}}", "bench-broker"):
            break
        time.sleep(0.5)
    t_pub_end = t_complete or time.time()
    # Drain: time until the subscribers have all messages.
    t_drain = None
    recv = prev = 0
    stable_since = time.time()
    while time.time() - t_pub_end < 40:
        recv = last_total(logs("bench-sub"), "recv")
        if recv >= expected:
            t_drain = time.time() - t_pub_end
            break
        if recv != prev:
            prev, stable_since = recv, time.time()
        elif time.time() - stable_since > 12:
            break
        time.sleep(0.5)
    sampler.stop = True
    sampler.join(timeout=10)
    sub_log, pub_log = logs("bench-sub"), logs("bench-pub")
    base = os.path.join(outdir, "%s-%s-n%d-%s" % (label, scn, n, tag))
    open(base + ".sub.log", "w").write(sub_log)
    open(base + ".pub.log", "w").write(pub_log)
    with open(base + ".stats", "w") as f:
        for r in sampler.rows:
            f.write("%.1f %s %.1f %.1f\n" % (r[0] - t_start, r[1], r[2], r[3]))
    recv = last_total(sub_log, "recv")
    state = sh("docker", "inspect", "-f", "{{.State.OOMKilled}} {{.State.Running}}", "bench-broker").split()
    oom = state[:1] == ["true"]
    alive = state[1:2] == ["true"]

    # Publish window, without the first 25 % (warm-up).
    warm = t_start + dur * 0.25
    brk = [(t, cpu, mem) for (t, name, cpu, mem) in sampler.rows if name == "bench-broker" and warm <= t <= t_pub_end]
    mem = [m for (_, _, m) in brk]
    third = max(1, len(mem) // 3)
    mem_first = statistics.mean(mem[:third]) if mem else 0
    mem_last = statistics.mean(mem[-third:]) if mem else 0
    mem_growth = mem_last - mem_first
    all_brk = [(cpu, m) for (t, name, cpu, m) in sampler.rows if name == "bench-broker"]
    lat = [int(x) for x in re.findall(r"publish_latency avg=(\d+)ms", sub_log)]
    lat_w = lat[len(lat) // 4:] if len(lat) >= 4 else lat
    lt = max(1, len(lat_w) // 3)
    lat_first = statistics.median(lat_w[:lt]) if lat_w else None
    lat_last = statistics.median(lat_w[-lt:]) if lat_w else None
    pub_time = (t_complete - t_start) if t_complete else None
    gen_pub = max([cpu for (t, name, cpu, m) in sampler.rows if name == "bench-pub"] or [0])
    gen_sub = max([cpu for (t, name, cpu, m) in sampler.rows if name == "bench-sub"] or [0])

    checks = {
        "rate_kept": pub_time is not None and pub_time <= dur * 1.08 + 2,
        "no_loss": recv >= expected,
        "latency_below_1s": bool(lat_w) and max(lat_w) < 1000,
        "latency_flat": bool(lat_w) and lat_last <= 2 * lat_first + 50,
        "memory_flat": bool(mem) and mem_growth < max(15.0, 0.04 * mem_first),
        "drained_in_2s": t_drain is not None and t_drain <= 2.0,
        "broker_alive": alive and not oom,
    }
    generator_limited = (gen_pub >= PUB_CORES * 100 * 0.92) or (gen_sub >= SUB_CORES * 100 * 0.92)
    ok = all(checks.values())
    res.update(
        verdict="sustained" if ok else ("generator-limited" if generator_limited else "not-sustained"),
        failed=[k for k, v in checks.items() if not v],
        received=recv, loss_pct=round((expected - recv) * 100.0 / expected, 4) if expected else 0,
        publish_time_s=round(pub_time, 1) if pub_time else None,
        drain_s=round(t_drain, 1) if t_drain is not None else None,
        recv_msg_s=round(recv / (t_pub_end - t_start + (t_drain or 0)), 0) if t_pub_end > t_start else 0,
        lat_ms_median=statistics.median(lat_w) if lat_w else None,
        lat_ms_max=max(lat_w) if lat_w else None,
        lat_ms_first=lat_first, lat_ms_last=lat_last,
        mem_mib_first=round(mem_first, 1), mem_mib_last=round(mem_last, 1), mem_growth_mib=round(mem_growth, 1),
        mem_mib_peak=round(max([m for (_, m) in all_brk] or [0]), 1),
        cpu_pct_avg=round(statistics.mean([c for (_, c, _) in brk]), 1) if brk else 0,
        gen_pub_cpu_max=round(gen_pub), gen_sub_cpu_max=round(gen_sub), oom=oom,
    )
    return res


def conn_test(label, image, count, outdir):
    res = {"broker": label, "scenario": "connections", "n": count, "tag": "hold"}
    if not start_broker(image):
        res.update(verdict="broker-did-not-start")
        return res
    idle = sh("docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", "bench-broker").split()
    res["idle_mem_mib"] = round(to_mib(idle[0]), 1) if idle else None
    t0 = time.time()
    sh("docker", "run", "-d", "--name", "bench-conn", "--network", "host", "--cpuset-cpus=" + PUB_CPUS + "," + SUB_CPUS,
       "--ulimit", NOFILE, BENCH, "conn", "-h", "127.0.0.1", "-p", PORT, "-V", VERSION, "-c", str(count), "-i", "1", "-k", "300", *GEN_ARGS)
    n = 0
    while time.time() - t0 < 240:
        n = last_total(logs("bench-conn"), "connect_succ")
        if n >= count:
            break
        time.sleep(1)
    res["connect_time_s"] = round(time.time() - t0, 1)
    time.sleep(30)
    mem = sh("docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", "bench-broker").split()
    log = logs("bench-conn")
    state = sh("docker", "inspect", "-f", "{{.State.OOMKilled}} {{.State.Running}}", "bench-broker").split()
    res.update(connected=n, connect_fail=last_total(log, "connect_fail"),
               mem_mib_at_rest=round(to_mib(mem[0]), 1) if mem else None,
               oom=state[:1] == ["true"], verdict="ok" if n >= count and state[1:2] == ["true"] else "failed")
    if res.get("mem_mib_at_rest") and res.get("idle_mem_mib") is not None and n:
        res["kib_per_connection"] = round((res["mem_mib_at_rest"] - res["idle_mem_mib"]) * 1024 / n, 1)
    return res


def main():
    argv = sys.argv[1:]
    only = "."
    if "--only" in argv:
        at = argv.index("--only")
        only = argv[at + 1]
        del argv[at:at + 2]
    args = [a for a in argv if not a.startswith("--")]
    outdir, brokers = args[0], [a.split("=", 1) for a in args[1:]]
    quick = "--quick" in sys.argv
    one = None
    if "--step" in argv:
        at = argv.index("--step")
        one = (argv[at + 1], int(argv[at + 2]), int(argv[at + 3]))
        del argv[at:at + 4]
        args = [a for a in argv if not a.startswith("--")]
        outdir, brokers = args[0], [a.split("=", 1) for a in args[1:]]
    os.makedirs(outdir, exist_ok=True)
    out = open(os.path.join(outdir, "results.jsonl"), "a")
    if one:
        for label, image in brokers:
            r = step(label, image, one[0], one[1], one[2], outdir, "step")
            out.write(json.dumps(r) + chr(10))
            print(json.dumps(r), flush=True)
        rm("bench-broker", "bench-pub", "bench-sub", "bench-conn")
        return

    def emit(r):
        out.write(json.dumps(r) + "\n")
        out.flush()
        print(json.dumps(r), flush=True)

    if re.search(only, "connections"):
        for label, image in brokers:
            emit(conn_test(label, image, 10000, outdir))

    for scn, (ladder, _) in SCENARIOS.items():
        if not re.search(only, scn):
            continue
        for label, image in brokers:
            if quick:
                emit(step(label, image, scn, ladder[0], 20, outdir, "quick"))
                continue
            # Binary search on the ladder for the highest sustained step.
            lo, hi, best = 0, len(ladder) - 1, None
            seen = {}
            while lo <= hi:
                mid = (lo + hi) // 2
                r = step(label, image, scn, ladder[mid], STEP_S, outdir, "search")
                emit(r)
                seen[mid] = r["verdict"]
                if r["verdict"] == "sustained":
                    best, lo = mid, mid + 1
                else:
                    hi = mid - 1
            # Confirm with a longer run. Go down one step when it fails.
            idx = best
            confirmed = None
            while idx is not None and idx >= 0:
                r = step(label, image, scn, ladder[idx], CONFIRM_S, outdir, "confirm")
                emit(r)
                if r["verdict"] == "sustained":
                    confirmed = r
                    break
                idx -= 1
            emit({"broker": label, "scenario": scn, "tag": "summary",
                  "sustained_n": confirmed["n"] if confirmed else None,
                  "sustained_msg_s": confirmed["offered_msg_s"] if confirmed else 0,
                  "search": {str(ladder[k]): v for k, v in sorted(seen.items())},
                  "ladder_top_reached": best == len(ladder) - 1})
    rm("bench-broker", "bench-pub", "bench-sub", "bench-conn")


if __name__ == "__main__":
    main()
