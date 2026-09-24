//! QoS 0 backlog workload for the slow-subscriptions hook (FX-03).
//!
//! BENCH: crates/broker-node/tests/slow_subs_bench.rs :: cargo +1.96.0 test --release -p broker-node --test slow_subs_bench -- --ignored --nocapture --test-threads=1
//!
//! Measures the bounded QoS 0 egress path the hook observes: route one
//! flood into a single subscriber backlog (`ConnTable::route`), read the
//! backlog depth once per publish (`ConnTable::qos0_len`, the whole-path
//! queued-time signal FX-03 adds to the hook), then drain it. Uses only
//! APIs that exist on the task's base commit (`ConnTable`, `BrokerFrame`,
//! `OpCode`) so the gates can run it on the base and on the tree; only
//! `BENCH` lines carry numbers, everything else is context. `#[ignore]`
//! so normal `cargo test` skips it. Counts are CI sample sizes, not SLOs.

use broker_router::ConnTable;
use brokerlink::{BrokerFrame, OpCode};
use bytes::Bytes;
use std::hint::black_box;
use std::time::Instant;

/// Bound for the bench backlog: 1024 frames.
/// Rationale: matches the slow-record handoff bound so the bench burst
/// shares one memory story with the recorder it feeds, absorbs the
/// 5000-message flood below without growing, and keeps the queued burst
/// near a few hundred kilobytes of small frames.
const BENCH_QOS0_BOUND: usize = 1024;
/// Flood size mirroring the slow-subscriptions scenario burst.
const BENCH_FLOOD: usize = 5000;

fn qos0_frame(conn_id: u64, seq: u64, payload_byte: u8) -> BrokerFrame {
    let topic = "bench/slow";
    let mut meta = Vec::with_capacity(2 + topic.len() + 2 + 3);
    meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    meta.extend_from_slice(topic.as_bytes());
    meta.extend_from_slice(&0u16.to_be_bytes());
    meta.push(0u8);
    meta.push(0u8);
    meta.push(0u8);
    let payload = vec![payload_byte; 64];
    BrokerFrame::new(
        OpCode::PublishOut,
        conn_id,
        seq,
        Bytes::from(meta),
        Bytes::from(payload),
    )
    .expect("bench frame fits wire bounds")
}

/// QoS 0 route plus one backlog-depth read per publish (the hook's
/// queued-time signal), then a full drain. Prints `BENCH` lines for the
/// gates; asserts only exact routing counts, never a rate threshold.
#[ignore]
#[test]
fn slow_qos0_backlog_workload_timings() {
    let table = ConnTable::with_qos0_bound(BENCH_QOS0_BOUND);
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<BrokerFrame>();
    table.register(61, tx);

    // Route the flood, reading the backlog depth once per publish exactly
    // as the enabled hook does (one bounded `qos0_len` read per fan-out).
    let route_start = Instant::now();
    let mut routed = 0usize;
    let mut depths = 0usize;
    for i in 0..BENCH_FLOOD {
        let frame = qos0_frame(61, i as u64 + 1, (i % 251) as u8);
        assert!(
            table.route(61, frame),
            "bounded QoS 0 route never drops the connection"
        );
        routed += 1;
        depths += table.qos0_len(61);
    }
    let route_elapsed = route_start.elapsed();
    black_box(depths);
    assert_eq!(routed, BENCH_FLOOD, "every flood publish routes");
    assert_eq!(
        table.qos0_len(61),
        BENCH_QOS0_BOUND,
        "an undrained 5000-message flood fills the bounded backlog"
    );

    // Drain everything back out, oldest first.
    let drain_start = Instant::now();
    let mut drained = 0usize;
    while let Some(frame) = table.pop_qos0(61) {
        black_box(frame.total_frame_len());
        drained += 1;
    }
    let drain_elapsed = drain_start.elapsed();
    assert_eq!(
        drained, BENCH_QOS0_BOUND,
        "drain returns exactly the bounded backlog"
    );
    assert_eq!(table.qos0_len(61), 0, "drain empties the backlog");

    let route_rate = BENCH_FLOOD as f64 / route_elapsed.as_secs_f64();
    let route_avg_ns = route_elapsed.as_nanos() as f64 / BENCH_FLOOD as f64;
    let drain_rate = drained as f64 / drain_elapsed.as_secs_f64();
    let drain_avg_ns = drain_elapsed.as_nanos() as f64 / drained as f64;

    // Leading blank line so the first BENCH line starts at column 0.
    println!();
    println!("BENCH slow_qos0_route_per_sec {route_rate:.0} ops/s");
    println!("BENCH slow_qos0_route_ns_per_msg {route_avg_ns:.1} ns");
    println!("BENCH slow_qos0_drain_per_sec {drain_rate:.0} ops/s");
    println!("BENCH slow_qos0_drain_ns_per_msg {drain_avg_ns:.1} ns");
    println!("BENCH slow_qos0_flood_depth_sum {depths} frames");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
}
