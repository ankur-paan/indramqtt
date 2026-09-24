//! Pipeline benchmark hook for B5-04 webhook publish authorization (T-97).
//!
//! Hot-path numbers are measured by the pipeline, never by an agent
//! (rulebook §2 "Where do numbers come from?"): the gates run this file
//! three times on the base commit (with this file copied in) and three
//! times on the tree, and the numbers land in the gates log as lines
//! starting `BENCH <metric> <value> <unit>`.
//!
//! Base-commit compatibility: the gates copy only this file onto the base
//! commit, where the webhook types do not exist yet, so the webhook leg
//! (publish authorization against a real loopback verdict endpoint)
//! compiles under the `webhook-bench` feature (on by default on the tree).
//! Without the feature the same file measures the base publish path
//! (`MemoryAuth::authorize_publish`, the local ACL check every publish
//! pays on the base commit) under the same `BENCH` metric names: the base
//! run measures that path without the task's new work, the tree run with
//! it. Outcomes per leg are printed as plain `outcome` lines so the
//! before/after logs stay interpretable; only `BENCH` lines carry
//! numbers.
//!
//! What each leg measures is the per-packet publish-authorization cost:
//! the no-webhook leg pays the local ACL check only (the unconfigured
//! fast path: no lock, no allocation, one flag check per `Option`);
//! the webhook leg pays one short mutex plus a hash lookup on a cache
//! hit (no I/O, no allocation past the key) against a real loopback
//! verdict endpoint owned by the test. Bounds: pool 4 permits, timeout
//! 2000 ms, breaker 5 failures with a 30000 ms reset, cache 128 entries
//! with a 60 s TTL. Memory stays flat: the no-webhook leg holds no
//! state, the webhook leg caches one verdict, so the measured cost is
//! handling, not growth.
//!
//! The bench endpoint always allows: cost, not correctness, is measured
//! here. Correctness (the endpoint verifies the credential it receives,
//! deny/flap/stop faults, breaker and TTL with exact contact counts) is
//! covered by the broker-path tests in `crates/broker-auth/src/webhook.rs`
//! and `crates/broker-node/src/main.rs`.
//!
//! Counts are CI sample sizes, not SLOs: 200 publishes per leg give a
//! mean rate and a stable p99 without stalling CI on loopback.

use broker_auth::{Authorizer, MemoryAuth};
use broker_protocol::Topic;
use std::hint::black_box;
#[cfg(feature = "webhook-bench")]
use std::sync::Arc;
use std::time::Instant;

/// Sample size per leg (a CI sample size, not an SLO): large enough for
/// a stable p99, small enough to stay fast on loopback.
const ITERS: usize = 200;

/// Sorted per-operation latencies into a p99 in whole microseconds.
fn p99_us(mut latencies: Vec<u128>) -> u128 {
    latencies.sort_unstable();
    latencies[(latencies.len() * 99).div_ceil(100).saturating_sub(1)]
}

/// Time one publish-authorization leg (`ITERS` publishes of `topic` for
/// `client`), asserting every verdict allows (never the timings, so a
/// loaded runner cannot flake it), and print the pipeline `BENCH` lines
/// for the leg.
async fn time_publish_leg(
    auth: &impl Authorizer,
    client: &str,
    topic: &Topic,
    leg: &str,
    endpoint_contacts: Option<usize>,
) {
    let mut latencies = Vec::with_capacity(ITERS);
    let start = Instant::now();
    for _ in 0..ITERS {
        let op = Instant::now();
        let outcome = black_box(auth.authorize_publish(client, topic).await);
        latencies.push(op.elapsed().as_micros());
        assert!(outcome.is_ok(), "{leg} publish must allow");
    }
    let elapsed_secs = start.elapsed().as_secs_f64();
    let per_sec = ITERS as f64 / elapsed_secs;
    let p99 = p99_us(latencies);
    if let Some(contacts) = endpoint_contacts {
        println!("outcome publish_bench leg={leg} endpoint_contacts={contacts}");
    } else {
        println!("outcome publish_bench leg={leg} endpoint_contacts=n/a (no webhook)");
    }
    println!("BENCH publish_per_sec {per_sec:.1} per_sec");
    println!("BENCH publish_p99_us {p99} us");
}

/// Tree-only (`webhook-bench`): real loopback verdict endpoint plus the
/// configured client. The base commit has no webhook types.
#[cfg(feature = "webhook-bench")]
mod webhook_leg {
    use broker_auth::WebhookConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Test-owned verdict endpoint on loopback. Always allows: the bench
    /// measures cost, so every check is an allow. Every request bumps
    /// `hits` so the bench asserts exact endpoint contact (cache hits
    /// must not contact it).
    pub struct BenchServer {
        pub hits: AtomicUsize,
    }

    async fn bench_handler(
        axum::extract::State(server): axum::extract::State<Arc<BenchServer>>,
        _body: axum::body::Bytes,
    ) -> (axum::http::StatusCode, String) {
        server.hits.fetch_add(1, Ordering::Relaxed);
        (
            axum::http::StatusCode::OK,
            serde_json::json!({"allow": true}).to_string(),
        )
    }

    pub async fn start_bench_server(
        server: Arc<BenchServer>,
    ) -> (tokio::task::JoinHandle<()>, String) {
        let app = axum::Router::new()
            .route("/", axum::routing::post(bench_handler))
            .with_state(server);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve verdicts");
        });
        (handle, url)
    }

    pub fn test_config(url: String) -> WebhookConfig {
        WebhookConfig {
            endpoint_url: url,
            pool_size: 4,
            request_timeout_ms: 2_000,
            breaker_failure_threshold: 5,
            breaker_reset_timeout_ms: 30_000,
            cache_max_entries: 128,
            cache_ttl_secs: 60,
        }
    }

    pub fn contacts(server: &BenchServer) -> usize {
        server.hits.load(Ordering::Relaxed)
    }
}

/// Pipeline benchmark hook (B5-04 publish path): per-packet publish
/// authorization rate and p99 with no webhook configured and with a
/// webhook configured against an in-process server. `#[ignore]` so
/// normal `cargo test` runs skip it and the pipeline's bench runner
/// picks it up explicitly.
/// Tree-only (`webhook-bench`): the base commit runs the fallback below.
#[cfg(feature = "webhook-bench")]
#[tokio::test]
#[ignore]
async fn publish_authorize_cost() {
    // No-webhook leg: the local ACL check every publish pays when no
    // webhook is configured. Empty rule set allows everything.
    let local = MemoryAuth::new();
    let topic = Topic::new("bench/topic").expect("bench topic parses");
    time_publish_leg(&local, "bench-client", &topic, "no_webhook", None).await;

    // Webhook leg: configured endpoint on loopback, warmed once so lazy
    // client init stays out of the window and every timed check is a
    // cache hit (the steady-publisher fast path).
    let server = Arc::new(webhook_leg::BenchServer {
        hits: std::sync::atomic::AtomicUsize::new(0),
    });
    let (handle, url) = webhook_leg::start_bench_server(server.clone()).await;
    let auth = broker_auth::WebhookAuth::new(webhook_leg::test_config(url));
    let warm = Topic::new("webhook/bench/warm").expect("bench topic parses");
    auth.authorize_publish("bench-client", &warm)
        .await
        .expect("warmup allows");
    assert_eq!(
        webhook_leg::contacts(&server),
        1,
        "warmup must contact the endpoint exactly once"
    );
    time_publish_leg(
        &auth,
        "bench-client",
        &warm,
        "webhook_hit",
        Some(webhook_leg::contacts(&server)),
    )
    .await;
    assert_eq!(
        webhook_leg::contacts(&server),
        1,
        "cache hits must not contact the endpoint"
    );

    // Flush stdout so all BENCH lines reach the gates log before exit.
    use std::io::Write as _;
    std::io::stdout().flush().ok();
    handle.abort();
}

/// Base-commit fallback for the same hook: the webhook types do not exist
/// on the base commit, so the same `BENCH` metric names measure the base
/// publish path (`MemoryAuth::authorize_publish`, the local ACL check)
/// instead — the no-webhook leg. `#[ignore]` like the tree leg; only one
/// of the two bodies compiles, selected by the `webhook-bench` feature
/// (on by default on the tree, absent on the base commit where only this
/// file is copied in). Uses only base-commit interfaces
/// (`MemoryAuth::new`, `Topic::new`, `authorize_publish`).
#[cfg(not(feature = "webhook-bench"))]
#[tokio::test]
#[ignore]
async fn publish_authorize_cost() {
    let local = MemoryAuth::new();
    let topic = Topic::new("bench/topic").expect("bench topic parses");
    time_publish_leg(&local, "bench-client", &topic, "no_webhook", None).await;

    // Flush stdout so all BENCH lines reach the gates log before exit.
    use std::io::Write as _;
    std::io::stdout().flush().ok();
}
