//! B4-06 pipeline benchmark: offline-queue disconnect-reconnect workload.
//!
//! `#[ignore]` so the pipeline's bench runner picks it up (three runs on
//! the base commit and three runs on the tree); normal `cargo test` skips
//! it. Uses only APIs that exist on the base commit (`SessionManager::
//! new_with_limits`, `get_or_create`, `push_offline_with_limit` as a
//! statement, `drain_offline`, `offline_len`), so the same file compiles
//! and runs on both sides. Prints lines starting
//! `BENCH <metric> <value> <unit>` for the gates log. Counts are CI sample
//! sizes, not SLOs: 2,000 messages buffer a reconnect storm without drops
//! under the unbounded test manager while staying fast enough for CI.

use broker_protocol::{QoS, Topic};
use broker_session::{QueuedMessage, SessionManager};
use bytes::Bytes;
use std::hint::black_box;
use std::time::Instant;

#[test]
#[ignore]
fn offline_queue_disconnect_reconnect_bench() {
    let sessions = SessionManager::new_with_limits(None);
    let (session, _) = sessions.get_or_create("bench-sub", false);
    let topic = Topic::new("bench/backlog").unwrap();
    let payload = Bytes::from_static(b"x");
    // 2,000 messages: a reconnect storm that fits CI time on both the
    // memory-only base path and the durable tree path.
    let iters = 2_000usize;
    let start = Instant::now();
    for _ in 0..iters {
        let payload = black_box(payload.clone());
        session.push_offline_with_limit(
            QueuedMessage {
                topic: topic.clone(),
                qos: QoS::AtMostOnce,
                retain: false,
                payload,
                publish_at_ms: None,
            },
            None,
        );
    }
    let elapsed = start.elapsed();
    assert_eq!(session.offline_len(), iters);
    let rate = iters as f64 / elapsed.as_secs_f64();
    let avg_ns = elapsed.as_nanos() as f64 / iters as f64;
    println!("BENCH offline_queue_bench_buffer_rate {rate:.0} msgs_per_sec");
    println!("BENCH offline_queue_bench_buffer_per_msg {avg_ns:.1} ns_per_msg");

    let start = Instant::now();
    let drained = session.drain_offline();
    let elapsed = start.elapsed();
    assert_eq!(drained.len(), iters);
    let rate = iters as f64 / elapsed.as_secs_f64();
    let avg_ns = elapsed.as_nanos() as f64 / iters as f64;
    println!("BENCH offline_queue_bench_drain_rate {rate:.0} msgs_per_sec");
    println!("BENCH offline_queue_bench_drain_per_msg {avg_ns:.1} ns_per_msg");
}
