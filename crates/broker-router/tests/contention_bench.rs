//! B4-08 router contention benchmark (CTO ruling B4-08.1).
//!
//! One `#[ignore]` test the pipeline runs three times on the base commit
//! (checkpoint B4-07) and three times on the tree:
//!
//! ```text
//! BENCH: crates/broker-router/tests/contention_bench.rs ::
//!   cargo +1.96.0 test --release -p broker-router --test contention_bench --
//!     --ignored --nocapture --test-threads=1
//! ```
//!
//! Base-commit constraint: this file uses only `Router::new`, `subscribe`,
//! `unsubscribe`, `matches` and the `Subscription`, `TopicFilter`, `Topic`
//! types, which all exist on the base commit, so the same file compiles and
//! runs on both sides. Do not call `matches_with_publisher`, shared
//! helpers, or any other router API from here.
//!
//! Output contract: every result line starts with `BENCH <metric> <value>
//! <unit>` so the gates log can be scraped mechanically.

use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::{Router, Subscription};
use std::sync::Arc;
use std::time::Instant;

/// Steady subscriptions the readers match against. Reason: 10 000 is
/// large enough that the match walk shares cache lines with the churn
/// writers' mutations, yet small enough that release-mode setup stays
/// well under a second on the pipeline runner.
const NUM_BASE_SUBSCRIPTIONS: usize = 10_000;

/// Reader (publisher-side match) threads. Reason: one per core of the
/// 8-core test host, the production shape where fan-out reads outnumber
/// subscription writes by orders of magnitude.
const NUM_READERS: usize = 8;

/// Churn (subscribe/unsubscribe) threads. Reason: subscribes are rarer
/// than publishes in production; two writers create real write
/// contention on the mutation path without starving the readers.
const NUM_WRITERS: usize = 2;

/// Matches per reader thread. Reason: 2 000 × 8 readers = 16 000 timed
/// matches, enough for a stable p99 while keeping the ignored test to
/// seconds in release mode.
const MATCHES_PER_READER: usize = 2_000;

/// Subscribe/unsubscribe pairs per churn thread. Reason: 300 pairs × 2
/// writers = 1 200 mutations interleaved with the reads, enough to make
/// a serialising lock visible without dominating the wall time.
const CHURN_ITERS_PER_WRITER: usize = 300;

/// Distinct churn filters rotated by each writer. Reason: 50 per writer
/// keeps the churn set resident but small next to the 10 000 steady
/// subscriptions, so the storm shape is "few hot writers, large settled
/// trie" rather than unbounded growth.
const CHURN_FILTERS_PER_WRITER: usize = 50;

/// Fixed seed for the deterministic topic rotation. Reason:
/// reproducibility — the identical match sequence runs on the base
/// commit and on the tree, so the comparison measures the lock
/// discipline, never the workload draw.
const FIXED_SEED: u64 = 0x9E3779B97F4A7C15;

/// Fixed stride for the deterministic topic rotation. Reason: an odd
/// stride coprime to the subscription count walks the whole steady set
/// instead of hammering one trie branch.
const STRIDE: usize = 7_919;

/// Deterministic steady topic for `(reader, iter)`: a fixed-seed offset
/// plus a strided walk over the base subscriptions. No RNG, no shared
/// state, identical on both sides of the comparison.
fn steady_topic(reader: usize, iter: usize) -> String {
    let offset = (FIXED_SEED as usize) % NUM_BASE_SUBSCRIPTIONS;
    let idx = (offset + reader * 1_009 + iter * STRIDE) % NUM_BASE_SUBSCRIPTIONS;
    format!("bench/sensor/{idx:05}")
}

/// Percentile of a sorted sample (`q` in `[0, 1]`), nearest-rank.
fn percentile(sorted: &[f64], q: f64) -> f64 {
    debug_assert!(!sorted.is_empty());
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// B4-08 contention benchmark: 8 reader threads match against 10 000
/// steady subscriptions while 2 threads churn subscribe/unsubscribe.
/// Prints `BENCH` lines for the gates log; asserts only exact routing
/// correctness (probe subscribe resolves, probe unsubscribe silences),
/// never a time threshold, so the test is stable on loaded runners.
#[ignore]
#[test]
fn router_contention_bench() {
    let router = Arc::new(Router::new());

    // Settle the trie before timing: one exact subscription per sensor
    // id, each owned by a distinct client.
    for i in 0..NUM_BASE_SUBSCRIPTIONS {
        let filter = TopicFilter::new(format!("bench/sensor/{i:05}")).expect("valid bench filter");
        router.subscribe(
            &filter,
            Subscription::new(format!("bench-client-{i:05}"), i as u64, QoS::AtMostOnce),
        );
    }
    let probe = Topic::new("bench/sensor/00042").expect("valid probe topic");
    assert_eq!(
        router.matches(&probe).len(),
        1,
        "settled trie resolves a steady subscription"
    );

    let wall = Instant::now();
    std::thread::scope(|scope| {
        // Readers: timed matches over the deterministic rotation.
        let mut reader_handles = Vec::with_capacity(NUM_READERS);
        for reader in 0..NUM_READERS {
            let router = Arc::clone(&router);
            reader_handles.push(scope.spawn(move || {
                let mut lat_ns = Vec::with_capacity(MATCHES_PER_READER);
                let mut count = 0u64;
                for iter in 0..MATCHES_PER_READER {
                    let topic = Topic::new(steady_topic(reader, iter)).expect("valid bench topic");
                    let start = Instant::now();
                    let matched = router.matches(&topic);
                    lat_ns.push(start.elapsed().as_nanos() as f64);
                    debug_assert_eq!(matched.len(), 1);
                    count += 1;
                }
                (count, lat_ns)
            }));
        }
        // Writers: timed subscribe/unsubscribe churn on dedicated
        // filters disjoint from the steady set and from each other.
        let mut writer_handles = Vec::with_capacity(NUM_WRITERS);
        for writer in 0..NUM_WRITERS {
            let router = Arc::clone(&router);
            writer_handles.push(scope.spawn(move || {
                let mut sub_us = Vec::with_capacity(CHURN_ITERS_PER_WRITER);
                let mut ops = 0u64;
                for iter in 0..CHURN_ITERS_PER_WRITER {
                    let slot = iter % CHURN_FILTERS_PER_WRITER;
                    let filter = TopicFilter::new(format!("bench/churn/{writer}/{slot:03}"))
                        .expect("valid churn filter");
                    let client = format!("churn-{writer}-{slot:03}");
                    let start = Instant::now();
                    router.subscribe(
                        &filter,
                        Subscription::new(client.clone(), 1_000_000 + iter as u64, QoS::AtMostOnce),
                    );
                    sub_us.push(start.elapsed().as_secs_f64() * 1e6);
                    // One churn op is one subscribe plus one
                    // unsubscribe; both serialize on the mutation path.
                    router.unsubscribe(&filter, &client);
                    ops += 2;
                }
                (ops, sub_us)
            }));
        }

        let mut total_matches = 0u64;
        let mut match_ns: Vec<f64> = Vec::with_capacity(NUM_READERS * MATCHES_PER_READER);
        for handle in reader_handles {
            let (count, mut lat) = handle.join().expect("reader joins");
            total_matches += count;
            match_ns.append(&mut lat);
        }
        let mut total_churn_ops = 0u64;
        let mut sub_us: Vec<f64> = Vec::with_capacity(NUM_WRITERS * CHURN_ITERS_PER_WRITER);
        for handle in writer_handles {
            let (ops, mut lat) = handle.join().expect("writer joins");
            total_churn_ops += ops;
            sub_us.append(&mut lat);
        }

        let secs = wall.elapsed().as_secs_f64().max(f64::EPSILON);
        match_ns.sort_by(|a, b| a.total_cmp(b));
        sub_us.sort_by(|a, b| a.total_cmp(b));
        // Leading blank line so the first BENCH line starts at column 0.
        // Reason: the test harness prints `test <name> ... ` with no
        // trailing newline, so without this the first BENCH line shares
        // that line and the pipeline's `grep -E '^BENCH '` misses
        // `matches_per_sec` (ruling B4-08.1 requires it).
        println!();
        println!(
            "BENCH matches_per_sec {:.0} ops/s",
            total_matches as f64 / secs
        );
        println!("BENCH match_p50_ns {:.1} ns", percentile(&match_ns, 0.50));
        println!("BENCH match_p99_ns {:.1} ns", percentile(&match_ns, 0.99));
        println!("BENCH match_max_ns {:.1} ns", match_ns[match_ns.len() - 1]);
        println!("BENCH subscribe_p50_us {:.3} us", percentile(&sub_us, 0.50));
        println!("BENCH subscribe_p99_us {:.3} us", percentile(&sub_us, 0.99));
        println!("BENCH subscribe_max_us {:.3} us", sub_us[sub_us.len() - 1]);
        println!(
            "BENCH churn_ops_per_sec {:.0} ops/s",
            total_churn_ops as f64 / secs
        );
    });

    // Exactness, not timing: a fresh probe resolves while subscribed
    // and goes silent after its unsubscribe completes.
    let filter = TopicFilter::new("bench/probe/exact").expect("valid probe filter");
    router.subscribe(
        &filter,
        Subscription::new("bench-probe", u64::MAX - 1, QoS::AtMostOnce),
    );
    let topic = Topic::new("bench/probe/exact").expect("valid probe topic");
    let matched = router.matches(&topic);
    assert_eq!(matched.len(), 1, "probe resolves after subscribe");
    assert_eq!(
        matched.iter().next().unwrap().client_id.as_ref(),
        "bench-probe"
    );
    router.unsubscribe(&filter, "bench-probe");
    assert!(
        router.matches(&topic).is_empty(),
        "probe silent after unsubscribe"
    );
}
