# Broker comparison at 1 CPU and 1 GB

This directory contains the method, the tool and the raw results of the
broker comparison in the main README. You can do the test again with
the tool in this directory.

- Date of the runs: 2026-10-05.
- Tool: [`sustained_load.py`](sustained_load.py).
- Raw results: [`results/`](results/). One JSON line for each load step.

## 1. What the test measures

The test finds the highest load that a broker can hold with 1 CPU and
1 GB of memory. A load counts only if the broker holds it without a
backlog. The test does not measure a short peak.

One load step is **sustained** only if all these conditions are true:

| Condition | Rule |
|---|---|
| Rate kept | The publishers complete the planned load in the planned time (8 % and 2 s tolerance). |
| No loss | The subscribers receive each message. The publishers send an exact number of messages. |
| Latency below 1 s | No interval after the warm-up has a mean latency of 1 s or more. |
| Latency level | The median latency of the last third of the step is not more than two times the median of the first third plus 50 ms. |
| Memory level | The broker memory does not increase more than 15 MiB or 4 % between the first third and the last third of the step. |
| No backlog | The subscribers have all messages 2 s after the last publish. |
| Broker alive | The broker is not stopped and not killed for memory. |

If the memory increases during a step, the broker keeps messages in a
buffer. Such a step is not a sustained load.

For each scenario, the tool does a binary search on a fixed list of load
steps. Each search step runs for 45 s on a new broker. The tool then
runs the best step again for 180 s. If that run fails, the tool goes one
step down and runs 180 s again. The result in the tables is always a
180 s run.

## 2. Scenarios

All scenarios use a payload of 256 bytes.

| Scenario | Shape | Load |
|---|---|---|
| Connections | 10,000 clients connect and stay idle for 30 s. | Time to connect, memory at rest. |
| Point-to-point QoS 0 | N publishers, N subscribers, one topic for each pair. | 100 msg/s for each publisher. |
| Point-to-point QoS 1 | The same with QoS 1 for the publish and the subscription. | 100 msg/s for each publisher. |
| Fan-in QoS 0 | N publishers, 1 subscriber with a wildcard filter. | 100 msg/s for each publisher. |
| Fan-out QoS 0 | 1 publisher, N subscribers of one topic. | 10 msg/s, thus 10 × N deliveries/s. |

## 3. Environment

- One Linux container on a shared server: Intel Xeon E5-2697A v4,
  2.60 GHz, Linux kernel 7.0.14. Other workloads run on the same server.
- Each broker runs alone in a Docker container with
  `--cpus=1 --cpuset-cpus=<one CPU> --memory=1g --memory-swap=1g`, host
  network and a file limit of 524,288.
- The load generator is `emqx/emqtt-bench`
  (`sha256:ae7f2d56cd49b14824c835140c808b093c5e3f2defb3a29b34b17560feb456cd`).
  It runs on 21 other logical CPUs: 10 for the publishers and 11 for the
  subscribers. The tool reports a step as "generator-limited" when the
  generator uses its CPUs fully, and such a step does not count.
- The memory and the CPU of the broker come from `docker stats`, read
  in a loop during the step.
- The latency is the value that the generator prints: the mean
  end-to-end latency of each interval, from a time stamp in the payload.
  The tables show the median of these values in the 180 s run.

## 4. Brokers and settings

| Broker | Image | Settings |
|---|---|---|
| IndraMQTT | built from this repository with the `Dockerfile` | Default settings. The kernel owns the MQTT listener (`listeners.tcp.native = true`). |
| EMQX Enterprise 6.3.0 | `emqx/emqx-enterprise:6.3.0` (`sha256:3b6d9c0c419930074b7e0e6cba07baceea584b2094d22f16ff02f6c075c3d5b8`) | Default settings and the default licence of the image. |
| rumqttd 0.19.0 | `bytebeamio/rumqttd:latest` (`sha256:1680d711368202be466128ee771c5f5cf84224166fe2b62f7a16728b747ac1ba`) | The output of `rumqttd generate-config` with two changes: `max_connections = 40000` and `max_segment_size = 1048576`. MQTT 5 uses its listener on port 1884. |

Notes about the settings:

- rumqttd keeps a message log in memory. The default is 100 MiB for
  each segment and 10 segments, which is the full memory limit of this
  test. The test sets the segment to 1 MiB. With this value the memory
  of rumqttd still increases in the point-to-point scenarios, because
  each topic has its own log. By the rule in section 1, those steps are
  not sustained. rumqttd lost no message in those steps up to
  10,000 msg/s, and its latency was 0 to 2 ms.
- The IndraMQTT numbers come from two builds of this change. The build
  in `mqtt311-three-brokers.jsonl` is an earlier build. The build in
  `mqtt311-ours-newer-build.jsonl` and `mqtt5-three-brokers.jsonl`
  contains the correction of the subscription statistics. In these
  builds an environment variable selected the kernel listener. The
  setting `listeners.tcp.native` replaced it after the runs. The data
  path is the same.
- In these runs the IndraMQTT container also runs the edge process,
  which has no clients. Its memory (about 48 MiB) is in the IndraMQTT
  numbers.

## 5. Results for MQTT 3.1.1

Highest sustained load, 180 s run. Latency is the median at that load.

| Scenario | IndraMQTT | EMQX Enterprise 6.3.0 | rumqttd 0.19.0 |
|---|---|---|---|
| Point-to-point QoS 0 | 100,000 msg/s (240 ms) | 10,000 msg/s (122 ms) | none: memory increases |
| Point-to-point QoS 1 | 30,000 msg/s (14 ms) | 2,500 msg/s (5 ms) | none: memory increases |
| Fan-in QoS 0 | 40,000 msg/s (2 ms) | 2,500 msg/s (3 ms) | 30,000 msg/s (20 ms) |
| Fan-out QoS 0 | 200,000 deliveries/s (345 ms) | 10,000 deliveries/s (37 ms) | 60,000 deliveries/s (188 ms) |
| 10,000 connections, time | 13.6 s | 14.9 s | 240 s, 65 clients not connected |
| 10,000 connections, memory | 283 MiB | 566 MiB | 644 MiB |
| Memory for each connection | 21 KiB | 18 KiB | 66 KiB |
| Memory with no clients | 76 MiB | 391 MiB | 1.6 MiB |

## 6. Results for MQTT 5

| Scenario | IndraMQTT | EMQX Enterprise 6.3.0 | rumqttd 0.19.0 |
|---|---|---|---|
| Point-to-point QoS 0 | 100,000 msg/s (223 ms) | 20,000 msg/s (25 ms) | none: memory increases |
| Point-to-point QoS 1 | 30,000 msg/s (15 ms) | 7,500 msg/s (14 ms) | none: memory increases |
| Fan-in QoS 0 | 40,000 msg/s (1 ms) | 10,000 msg/s (5 ms) | 80,000 msg/s (22 ms) |
| Fan-out QoS 0 | 160,000 deliveries/s (240 ms) | 20,000 deliveries/s (33 ms) | 80,000 deliveries/s (102 ms) |
| 10,000 connections, time | 13.6 s | 13.6 s | 240 s, 161 clients not connected |
| 10,000 connections, memory | 283 MiB | 720 MiB | 638 MiB |
| Memory for each connection | 21 KiB | 41 KiB | 66 KiB |

## 7. Where IndraMQTT is behind

- **Fan-in with MQTT 5:** rumqttd holds 80,000 msg/s and IndraMQTT
  holds 40,000 msg/s.
- **Memory with no clients:** rumqttd uses 1.6 MiB and IndraMQTT uses
  76 MiB.
- **Memory for each connection with MQTT 3.1.1:** EMQX uses 18 KiB and
  IndraMQTT uses 21 KiB.
- **Many subscribers of one topic:** 25,000 subscribers of one topic
  did not complete their subscriptions in 180 s. The fan-out result of
  IndraMQTT stops at this limit.

## 8. Limits of this test

- Each result is one search and one 180 s run. The test was not done
  again to measure the variation.
- The server is shared, and the load generator runs on the same server
  as the broker.
- The latency values are at the highest load of each broker. The loads
  are different, thus the latency columns do not compare the brokers at
  the same load.
- The test uses MQTT without TLS, one payload size and one message rate
  for each client.
- `docker stats` showed more than 100 % CPU for a broker in some steps.
  The container cannot use more than one CPU. This is an error of the
  sampling.
- The test does not use the durable sessions, the rules, the connectors
  or the cluster functions of a broker.

## 9. How to do the test again

Requirements: Linux, Docker, Python 3, and more logical CPUs than the
publishers and the subscribers of the generator need.

```bash
# Build the IndraMQTT image from the repository root.
docker build -t indramqtt:test .

# The settings of rumqttd for this test.
docker run --rm bytebeamio/rumqttd:latest generate-config \
  | sed -e 's/^max_connections = 10010/max_connections = 40000/' \
        -e 's/^max_segment_size = 104857600/max_segment_size = 1048576/' \
  > /tmp/rumqttd.toml

# One CPU for the broker, the other CPUs for the generator.
export BENCH_BROKER_CPU=13
export BENCH_PUB_CPUS=0,1,2,3,4,5,6,7,8,9
export BENCH_SUB_CPUS=10,11,12,14,15,16,19,20,21,25,26
export BENCH_MQTT_VERSION=4        # 5 for MQTT 5

python3 benchmark/sustained_load.py /tmp/bench-out \
  'indramqtt=indramqtt:test|-e|INDRA_LISTENERS__TCP__NATIVE=true' \
  'emqx=emqx/emqx-enterprise:6.3.0' \
  'rumqttd=bytebeamio/rumqttd:latest|-v|/tmp/rumqttd.toml:/rumqttd.toml:ro|--|-c|/rumqttd.toml'
```

For MQTT 5, add `port=1884` to the rumqttd entry (after the image
name, with a `|` before it).

The tool writes one JSON line for each step to
`/tmp/bench-out/results.jsonl` and keeps the logs of the generator and
the samples of `docker stats` for each step in the same directory. A
line with `"tag": "confirm"` and `"verdict": "sustained"` is a result of
the tables above. The field `failed` names the conditions that a step
did not meet.

One full run with three brokers takes approximately 2.5 hours.

## 10. Files in `results/`

| File | Content |
|---|---|
| `mqtt311-three-brokers.jsonl` | MQTT 3.1.1, the three brokers, earlier IndraMQTT build. The EMQX and rumqttd rows of section 5 come from this file. |
| `mqtt311-ours-newer-build.jsonl` | MQTT 3.1.1, the newer IndraMQTT build. The IndraMQTT rows of section 5 come from this file. |
| `mqtt5-three-brokers.jsonl` | MQTT 5, the three brokers. Section 6 comes from this file. |

In these files the label `indra` is IndraMQTT and the label `ref` is
EMQX Enterprise 6.3.0.
