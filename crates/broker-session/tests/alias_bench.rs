//! Pipeline benchmark hook for B4-05 topic aliases (T-92).
//!
//! Hot-path numbers are measured by the pipeline, never by an agent
//! (rulebook §2 "Where do numbers come from?"): the gates run this file
//! three times on the base commit (with this file copied in) and three
//! times on the tree, and the numbers land in the gates log. It therefore
//! uses only session APIs that exist on the base commit `abe6ed5`
//! (`Session::new`, `push_offline`, `drain_offline`, `Topic::new` and the
//! `QueuedMessage` fields), so the same file compiles and runs on both
//! sides. The alias table methods are absent on the base commit and are
//! deliberately not referenced here.
//!
//! What it measures is the per-message session-path cost the alias
//! feature sits next to: one publish-shaped queue insert plus one
//! deliver-shaped drain per session, with no aliases in use (the cost
//! every client now pays). Memory stays flat: at most one message is
//! ever queued per session, so the measured cost is handling, not growth.

use broker_protocol::{QoS, Topic};
use broker_session::{QueuedMessage, Session, SessionId};
use bytes::Bytes;
use std::hint::black_box;
use std::time::Instant;

/// Pipeline benchmark hook (B4-05 hot path): ordinary publish-to-deliver
/// session work for 1000 alias-free sessions, printing `BENCH` lines for
/// the gates. `#[ignore]` so normal `cargo test` runs skip it and the
/// pipeline's bench runner picks it up explicitly.
#[test]
#[ignore]
fn publish_deliver_no_alias_bench() {
    // 1000 sessions with no aliases in use: the ruling's required shape,
    // since this is the cost every client now pays on the publish and
    // deliver path. Fixed count, not an SLO: sample size only.
    let session_count = 1000usize;
    // One message per session: publish inserts it, deliver drains it, so
    // one round is one publish-to-deliver pass through the session.
    // Fixed count, not an SLO: sample size only.
    let rounds_per_session = 1usize;
    // 1-byte payload keeps the cost in session handling (queue + drain),
    // not memcpy. Fixed size, not an SLO.
    let payload = Bytes::from_static(b"x");
    let sessions: Vec<Session> = (0..session_count)
        .map(|i| Session::new(SessionId(i as u64), format!("alias-bench-{i}"), true))
        .collect();
    let mut latencies: Vec<u128> = Vec::with_capacity(session_count * rounds_per_session);
    let start = Instant::now();
    let mut delivered = 0usize;
    for session in &sessions {
        for _ in 0..rounds_per_session {
            let op_start = Instant::now();
            let topic = Topic::new("bench/t").expect("bench topic parses");
            // `let _ =` because `push_offline` returns `()` on the base
            // commit and `bool` on the tree; the return is irrelevant here
            // (durable backing is never installed in this bench).
            let _ = session.push_offline(QueuedMessage {
                topic,
                qos: QoS::AtMostOnce,
                retain: false,
                payload: payload.clone(),
                publish_at_ms: None,
            });
            let got = session.drain_offline();
            delivered += got.len();
            black_box(got);
            latencies.push(op_start.elapsed().as_nanos());
        }
    }
    let elapsed = start.elapsed();
    let total = (session_count * rounds_per_session) as f64;
    let rate = total / elapsed.as_secs_f64();
    latencies.sort_unstable();
    // Nearest-rank 99th percentile of the per-round nanos: index
    // `ceil(0.99 * n) - 1`, so element 990 of 1000. Fixed rank, not an SLO.
    let p99_index = (latencies.len() * 99).div_ceil(100).saturating_sub(1);
    let p99_ns = latencies[p99_index];
    assert_eq!(
        delivered,
        session_count * rounds_per_session,
        "every publish drained once"
    );
    println!(
        "publish-to-deliver no-alias round: {rate:.0} ops/sec, p99 {p99_ns} ns/op ({} rounds in {elapsed:?})",
        session_count * rounds_per_session,
    );
    println!("BENCH deliver_per_sec {rate:.0} ops/s");
    println!("BENCH deliver_p99_ns {p99_ns} ns");
}
