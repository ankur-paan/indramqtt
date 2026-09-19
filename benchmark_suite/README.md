# IndraMQTT end-to-end benchmark suite (v5)

Committed, re-runnable network benchmark harness. It replaces the
uncommitted tool behind `benchmark_results_v3/v4.json` (which reported
`avg_latency_ms: 0.0` / `p99_latency_ms: 0.0` on every row) with real
end-to-end latency on the same 15 scenarios and parameters.

## Layout

* `scenarios.json` — the 15 scenarios: publisher/subscriber counts,
  payload sizes and publish intervals taken from v4, with a 20 s publish
  window and a drain window per scenario.
* `mqtt_bench.py` — per-scenario load generator (raw MQTT 3.1.1 over
  asyncio, QoS 0 and QoS 1). Reuses the framing helpers of the vendored
  tool below; adds `--qos` and counts (rather than crashes on) truncated
  PUBLISH bodies.
* `vendor/mqtt_load.py` — byte-identical copy of
  `team/perf/tools/mqtt_load.py` (sha256
  `69f0567efc304472ed248640ed852dc60dc4d0c5540497bdeab708bd40322a1f`).
  Vendored instead of imported because that file lives outside this repo;
  it is kept byte-identical so any divergence is detectable by checksum.
* `run_benchmarks.py` — runs all scenarios end to end, samples broker
  RSS/CPU inside the stack container, writes `benchmark_results_v5.json`.
* `benchmark_results_v5.json` — results of an actual run (see
  `environment` block inside for hardware and placement).

## Re-running

1. Start a stack (kernel + edge) per `team/perf/remote host-STACK.md`, e.g. in a
   container `broker-bench` with MQTT on 11883 (host port 13486),
   API on 28083 (host port 13487), BrokerLink on 28883. The kernel needs
   `--allow-anonymous` (the generator connects without credentials).
2. From the repo root, with `python` (3.12) on the load host:
   ```bash
   python benchmark_suite/run_benchmarks.py \
     --host 100.104.51.36 --port 13486 \
     --exec-helper ../team-workspace/team/exec_helper.sh \
     --target-name broker-bench \
     --out benchmark_suite/benchmark_results_v5.json
   ```
   Without `--exec-helper/--target-name`, throughput/latency/delivery are
   still measured; only the `*_cpu`/`*_rss_mb` fields become `null`.
   `--only qos0-5k,model-fanout` runs a subset; `--publish-sec` overrides
   the 20 s window; `--settle-sec` sets the pause between scenarios.

## Methodology notes

* Target aggregate rate = `pubs * 1000 / interval_ms`, matching v4's
  parameters. The achieved `in_rate` is reported; when the generator or
  the broker cannot keep up, the achieved rate (not the target) is what
  the delivery and latency numbers refer to.
* Duration: 20 s publish for every scenario (v4 ran 2.4–10.4 s, ending
  while messages were still in flight) plus a 10 s drain (15 s for the
  fan-out/fan-in rows) during which publishers have stopped and
  subscribers keep counting late deliveries. A 20 s settle pause
  separates scenarios.
* Latency: each payload carries its send timestamp (`time.time_ns()`) in
  the first 8 bytes; latency uses that single clock, so no cross-host
  sync error. Reported as avg/p50/p90/p99/max over valid deliveries.
  An impossible latency (negative, or older than the run itself) means
  corrupt stamp bytes on the wire; those deliveries are counted in
  `latency_invalid_count` (and truncated bodies in `framing_skips`) instead
  of silently skewing the percentiles.
* Topologies: paired 1:1 (`bench/pair/<i>`, subscriber `i` subscribes
  only to its own topic, fanout 1) for the QoS and payload sweeps and the
  symmetric model; shared topics (`bench/fan/<i>`, every subscriber
  subscribes to every topic) for fan-out (10 pubs / 500 subs / 10 topics,
  fanout 500) and fan-in (500 pubs / 10 subs / 500 topics, fanout 10).
* Client isolation: `run_benchmarks.py` passes `--tag <scenario-id>` so
  every scenario uses fresh client ids. This matters because the kernel
  keeps a reconnecting client's old subscriptions even across a clean
  disconnect (observed 2026-09-19: re-running with the same client ids
  after an all-topic run delivered 5x to single-topic subscribers).
  Reusing client ids across scenarios would corrupt delivery counts.
* `delivery_pct` is the true delivery ratio
  `100 * received / (sent * fanout)`. v4's fan-out row (20%) and fan-in
  row (0.6%) report `out/in`, i.e. they ignore fanout; the comparable
  v5 quantities are `out/in` = `delivery_pct * fanout / 100`... stated
  per-row in the T-29 report. Direct `delivery_pct` comparison is only
  valid for the fanout-1 rows.
* Resource fields: `rust_*` = `indramqtt` process, `beam_*` = `beam.smp`
  process, sampled every 2 s via a `/proc` scan loop inside the stack
  container. CPU is percent of one core (100 = one core saturated);
  `cores_utilized = combined_cpu_pct / 100`;
  `tps_per_core_allocated = total_tps / <stack container CPUs>`;
  `tps_per_core_utilized = total_tps / cores_utilized`.
* QoS 1 publishes are pipelined (no per-message ack wait); PUBACKs are
  counted in `pubacks_received`. Subscribers send PUBACK for each QoS 1
  delivery. Truncated PUBLISH bodies are counted in `framing_skips`,
  never fatal.
