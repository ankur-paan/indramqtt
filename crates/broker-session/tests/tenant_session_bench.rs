//! Pipeline benchmark hook for MT-03 tenant-keyed sessions.
//!
//! Hot-path numbers are measured by the pipeline, never by an agent
//! (rulebook §2 "Where do numbers come from?"): the gates run this file
//! three times on the base commit (with this file copied in) and three
//! times on the tree, and the numbers land in the gates log. It therefore
//! uses only session APIs that exist on the base commit (MT-02:
//! `SessionManager::new`, `get_or_create`, `get`, `queue_offline`,
//! `bind_session`, `unbind_connection`, `Topic::new` and the
//! `QueuedMessage` fields), so the same file compiles and runs on both
//! sides. The `*_in_tenant` methods are absent on the base commit and are
//! deliberately not referenced here.
//!
//! What it measures is the single-tenant session-path cost the tenant
//! keying sits next to: session creation, session lookup, and delivery
//! (lookup plus one offline-queue insert) for 100 000 sessions through
//! the default-tenant shims, which must behave exactly as before the
//! change. Accept bar: no regression beyond run-to-run spread for
//! single-tenant installs.
//!
//! Both tests below print `BENCH` lines on every run, before and after,
//! so the gates log always holds a comparable before/after pair for each
//! workload: `tenant_session_publish_deliver_bench` prints the spec's
//! `BENCH throughput` / `BENCH p99` single-tenant publish-to-deliver
//! pair (the same metric names the pre-amendment hook printed, so a gate
//! run on either side of the amendment still compares like with like),
//! and `tenant_session_hot_path_bench` prints the ruling's per-operation
//! session costs.

use broker_protocol::{QoS, Topic};
use broker_session::{QueuedMessage, SessionManager};
use bytes::Bytes;
use std::hint::black_box;
use std::time::Instant;

/// Number of publish-to-deliver rounds. Reason: 2 000 rounds run in well
/// under a minute in release while giving a stable median across repeats;
/// larger counts add wall time without narrowing the spread.
const PUBLISH_DELIVER_ROUNDS: usize = 2_000;

/// Single-tenant publish-to-deliver load (spec MT-03:75-79 BENCH gate):
/// one durable subscriber, detached, receives one buffered message per
/// round through the default-tenant shims — the same session writes the
/// kernel deliver path makes (`get` plus `queue_offline`, the lookup plus
/// queue insert of buffering for a detached session). Prints the spec's
/// `BENCH throughput <value> msg_per_sec` and `BENCH p99 <value> ms`
/// pair. Accept bar: no regression beyond run-to-run spread for
/// single-tenant installs. Uses only base-commit session APIs so the
/// pipeline's before run (this file copied onto the base commit) prints
/// the same metric names as the after run: the pair is comparable by
/// construction.
#[test]
#[ignore]
fn tenant_session_publish_deliver_bench() {
    let manager = SessionManager::new();
    // Durable subscriber (`clean_start = false`), detached: every round
    // buffers exactly as the kernel deliver path does for a detached
    // durable match.
    let (session, present) = manager.get_or_create("bench-sub", false);
    assert!(!present, "first create must be fresh");
    *session.connected.write() = false;
    *session.conn_id.write() = None;

    let topic = Topic::new("bench/t").expect("bench topic parses");
    let payload = Bytes::from_static(b"x");
    // Warmup so code pages and caches settle before timing, over the
    // same lookup-plus-buffer path the measurement drives.
    for _ in 0..100 {
        let session = manager.get("bench-sub").expect("bench session stays known");
        black_box(session);
    }

    let mut latencies_ns: Vec<u64> = Vec::with_capacity(PUBLISH_DELIVER_ROUNDS);
    let start = Instant::now();
    for _ in 0..PUBLISH_DELIVER_ROUNDS {
        let point = Instant::now();
        // Publish: resolve the subscriber session (lookup).
        let session = manager.get("bench-sub").expect("bench session stays known");
        // Deliver: buffer one message for the detached durable session.
        let queued = manager.queue_offline(
            "bench-sub",
            QueuedMessage {
                topic: topic.clone(),
                qos: QoS::AtLeastOnce,
                retain: false,
                payload: payload.clone(),
                publish_at_ms: None,
            },
        );
        assert!(queued, "detached durable session must buffer");
        black_box(session);
        latencies_ns.push(point.elapsed().as_nanos().min(u64::MAX as u128) as u64);
    }
    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(1e-9);
    let throughput = PUBLISH_DELIVER_ROUNDS as f64 / elapsed_secs;

    latencies_ns.sort_unstable();
    let rank =
        ((0.99 * PUBLISH_DELIVER_ROUNDS as f64).ceil() as usize).clamp(1, PUBLISH_DELIVER_ROUNDS);
    let p99_ns = latencies_ns[rank - 1];
    let p99_ms = p99_ns as f64 / 1_000_000.0;

    println!(
        "tenant session publish-to-deliver: {throughput:.0} ops/sec, p99 {p99_ns} ns/op ({PUBLISH_DELIVER_ROUNDS} rounds in {elapsed:?})"
    );
    println!("BENCH throughput {throughput:.1} msg_per_sec");
    println!("BENCH p99 {p99_ms:.4} ms");
}

/// Pipeline benchmark hook (MT-03 hot path): create and look up 100 000
/// sessions and deliver one message to each, printing `BENCH` lines for
/// the gates. `#[ignore]` so normal `cargo test` runs skip it and the
/// pipeline's bench runner picks it up explicitly.
#[test]
#[ignore]
fn tenant_session_hot_path_bench() {
    // 100 000 sessions through the default-tenant shims: the ruling's
    // required shape, since this is the cost every single-tenant install
    // pays on connect and deliver. Fixed count, not an SLO: sample size
    // only.
    let session_count = 100_000usize;
    // 1-byte payload keeps the cost in session handling (lookup + queue),
    // not memcpy. Fixed size, not an SLO.
    let payload = Bytes::from_static(b"x");
    let manager = SessionManager::new();

    // Phase 1: creation. Durable sessions (`clean_start = false`) so the
    // detach in phase 3 exercises the durable path every install takes.
    let start = Instant::now();
    for i in 0..session_count {
        let client_id = format!("bench-{i:06}");
        let (session, present) = manager.get_or_create(&client_id, false);
        black_box(session);
        assert!(!present, "first create must be fresh");
    }
    let create_secs = start.elapsed().as_secs_f64();
    let create_per_sec = session_count as f64 / create_secs;

    // Phase 2: lookup. One borrowed `get` per session; p99 over the
    // per-lookup nanos.
    let mut latencies: Vec<u128> = Vec::with_capacity(session_count);
    for i in 0..session_count {
        let client_id = format!("bench-{i:06}");
        let op_start = Instant::now();
        let session = manager.get(&client_id).expect("session exists");
        black_box(session);
        latencies.push(op_start.elapsed().as_nanos());
    }
    latencies.sort_unstable();
    // Nearest-rank 99th percentile of the per-lookup nanos: index
    // `ceil(0.99 * n) - 1`. Fixed rank, not an SLO.
    let p99_index = (latencies.len() * 99).div_ceil(100).saturating_sub(1);
    let lookup_p99_ns = latencies[p99_index];

    // Phase 3: delivery. Buffer one message per session through
    // `queue_offline`: lookup plus queue insert, the deliver-shaped work
    // of buffering for a session. Sessions stay connected so the bench
    // measures handling, not growth: 100 000 individual detaches would
    // serialize 100 000 full-map prune scans instead of the per-delivery
    // cost this hook exists to measure.
    let start = Instant::now();
    let mut delivered = 0usize;
    for i in 0..session_count {
        let client_id = format!("bench-{i:06}");
        let topic = Topic::new("bench/t").expect("bench topic parses");
        let queued = manager.queue_offline(
            &client_id,
            QueuedMessage {
                topic,
                qos: QoS::AtLeastOnce,
                retain: false,
                payload: payload.clone(),
                publish_at_ms: None,
            },
        );
        assert!(queued, "session must buffer");
        delivered += 1;
    }
    let deliver_secs = start.elapsed().as_secs_f64();
    let deliver_per_sec = delivered as f64 / deliver_secs;

    println!(
        "tenant session hot path: {create_per_sec:.0} creates/sec, lookup p99 {lookup_p99_ns} ns, {deliver_per_sec:.0} delivers/sec ({} sessions)",
        session_count,
    );
    println!("BENCH session_create_per_sec {create_per_sec:.0} per_sec");
    println!("BENCH session_lookup_p99_ns {lookup_p99_ns} ns");
    println!("BENCH deliver_lookup_per_sec {deliver_per_sec:.0} per_sec");
}
