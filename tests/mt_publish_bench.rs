//! MT-07 single-tenant publish-to-deliver load (BENCH gate).
//!
//! Driven by the pipeline, never by the agent: an `#[ignore]`
//! integration test using only APIs present on this task's base commit
//! (d5874f0: `SessionManager::{new,get_or_create,bind_session,get,
//! add_subscription}`, `Router::{new,subscribe,matches}`,
//! `Subscription::new`, `Topic::new`, `TopicFilter::new`).
//! It connects real clients (session records via `get_or_create` plus
//! `bind_session`, the same session writes the kernel bind hook makes),
//! subscribes one of them through the router, then drives a
//! single-tenant publish-to-deliver load: each iteration publishes
//! (`Router::matches`) and delivers (resolves every match to its live
//! session, verifies it is connected on the subscribing connection, and
//! counts the delivery). It prints `BENCH throughput <value>
//! msg_per_sec` and `BENCH p99 <value> ms`. Accept bar: no regression
//! beyond run-to-run spread for single-tenant installs (MT-07 records
//! the tenant on bind only, so the publish path is unchanged).

use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::{Router, Subscription};
use broker_session::SessionManager;
use std::time::Instant;

/// Number of publish-to-deliver iterations. Reason: 20k round trips run
/// in well under a minute in debug while giving a stable median across
/// repeats; larger counts add wall time without narrowing the spread.
const BENCH_ITERATIONS: usize = 20_000;

/// Single-tenant publish-to-deliver load: connect, publish, deliver.
#[test]
#[ignore]
fn mt_single_tenant_publish_to_deliver() {
    let router = Router::new();
    let sessions = SessionManager::new();

    // Connect two real clients: a subscriber and a publisher. The
    // session writes mirror the kernel bind hook (create the record,
    // pin the edge connection, record the keepalive).
    let (sub_session, _) = sessions.get_or_create("mt-bench-sub", true);
    sessions.bind_session(&sub_session, 9001);
    *sub_session.keepalive_secs.write() = 60;
    let (pub_session, _) = sessions.get_or_create("mt-bench-pub", true);
    sessions.bind_session(&pub_session, 9002);
    *pub_session.keepalive_secs.write() = 60;
    assert!(*sub_session.connected.read());
    assert!(*pub_session.connected.read());

    // Subscribe the subscriber through the router, mirrored on the
    // session exactly as the kernel subscribe path records it.
    let filter = TopicFilter::new("mt/bench/data").unwrap();
    router.subscribe(
        &filter,
        Subscription::new("mt-bench-sub", 9001, QoS::AtMostOnce),
    );
    sessions.add_subscription(
        "mt-bench-sub",
        TopicFilter::new("mt/bench/data").unwrap(),
        QoS::AtMostOnce,
    );

    let topic = Topic::new("mt/bench/data").unwrap();
    // Warmup so code pages and caches settle before timing, over the
    // same publish-to-deliver path the measurement drives.
    for _ in 0..1000 {
        let matched = router.matches(&topic);
        assert_eq!(matched.len(), 1);
        for sub in matched.iter() {
            let session = sessions
                .get(&sub.client_id)
                .expect("bench subscriber stays known");
            assert!(*session.connected.read());
        }
    }

    let mut latencies_ns: Vec<u64> = Vec::with_capacity(BENCH_ITERATIONS);
    let mut delivered_total: u64 = 0;
    let start = Instant::now();
    for _ in 0..BENCH_ITERATIONS {
        let point = Instant::now();
        // Publish: route to matching subscriptions.
        let matched = router.matches(&topic);
        assert_eq!(matched.len(), 1, "single-tenant bench keeps one match");
        // Deliver: resolve every match to its live session and hand it
        // over only when that client is still connected on the
        // subscribing connection.
        let mut delivered = 0;
        for sub in matched.iter() {
            let session = sessions
                .get(&sub.client_id)
                .expect("bench subscriber stays known");
            assert!(*session.connected.read());
            assert_eq!(*session.conn_id.read(), Some(sub.conn_id));
            delivered += 1;
        }
        assert_eq!(delivered, 1, "every publish is delivered once");
        delivered_total += delivered;
        latencies_ns.push(point.elapsed().as_nanos().min(u64::MAX as u128) as u64);
    }
    assert_eq!(delivered_total, BENCH_ITERATIONS as u64);
    let elapsed_secs = start.elapsed().as_secs_f64().max(1e-9);
    let throughput = BENCH_ITERATIONS as f64 / elapsed_secs;

    latencies_ns.sort_unstable();
    let rank = ((0.99 * BENCH_ITERATIONS as f64).ceil() as usize).clamp(1, BENCH_ITERATIONS);
    let p99_ms = latencies_ns[rank - 1] as f64 / 1_000_000.0;

    println!("BENCH throughput {throughput:.1} msg_per_sec");
    println!("BENCH p99 {p99_ms:.4} ms");
}
