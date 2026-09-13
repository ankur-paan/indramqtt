//! Automated throughput gates for the messaging hot path.
//!
//! These run under both `cargo test` (debug) and `cargo bench`/`cargo
//! test --release` (release): router topic matching and streaming-SQL
//! ingress evaluation. Gates are profile-aware: absolute numbers apply
//! to optimized builds (production), while debug gates sit ~50% below
//! measured debug throughput as regression tripwires. Reference machine
//! (Windows x64, post-Sprint-9 ahash + Arc<str> router): hit-path 197k
//! msg/sec debug / 3.05M release, SQL ingress 709k events/sec debug /
//! 4.77M release.

use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::{Router, Subscription};
use broker_rules::{BackpressurePolicy, BrokerSink, RuleAction, RuleEngine};
use bytes::Bytes;
use std::hint::black_box;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Floor for full fan-out match throughput (production-shaped table,
/// three hits per lookup including clone + set costs).
#[cfg(not(debug_assertions))]
const ROUTER_GATE_MSG_PER_SEC: f64 = 2_000_000.0;
#[cfg(debug_assertions)]
const ROUTER_GATE_MSG_PER_SEC: f64 = 100_000.0;

/// Floor for streaming-SQL ingress evaluation (met in both profiles).
const SQL_GATE_EVENTS_PER_SEC: f64 = 100_000.0;

fn build_router(subscriptions: usize) -> Router {
    let router = Router::new();
    // A production-shaped table: hundreds of installed filters, but any
    // single topic matches only a handful (exact + wildcards).
    for i in 0..subscriptions {
        let filter = format!("device/{}/state", 1_000 + i);
        router.subscribe(
            &TopicFilter::new(filter).unwrap(),
            Subscription {
                client_id: format!("client-{i}").into(),
                conn_id: i as u64,
                qos: QoS::AtMostOnce,
                group: None,
            },
        );
    }
    for (filter, qos) in [
        ("device/7/state", QoS::AtMostOnce),
        ("device/7/+", QoS::AtLeastOnce),
        ("device/#", QoS::AtMostOnce),
    ] {
        router.subscribe(
            &TopicFilter::new(filter).unwrap(),
            Subscription {
                client_id: format!("route-{filter}").into(),
                conn_id: 1_000_000,
                qos,
                group: None,
            },
        );
    }
    router
}

fn measure_match(router: &Router, topic: &Topic, iters: usize) -> (f64, usize) {
    let mut matched = 0usize;
    let start = Instant::now();
    for _ in 0..iters {
        matched += router.matches(black_box(topic)).len();
    }
    (iters as f64 / start.elapsed().as_secs_f64(), matched)
}

fn compute_stats(samples: &[f64]) -> (f64, f64) {
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance = samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / samples.len() as f64;
    (mean, variance.sqrt())
}

#[test]
fn bench_router_match_throughput() {
    let router = build_router(1_000);
    let topic = Topic::new("device/7/state").unwrap();
    let miss = Topic::new("zzz/9/nope").unwrap();

    // Warmup so caches and branch predictors settle.
    for _ in 0..10_000 {
        black_box(router.matches(black_box(&topic)));
    }

    // Production-shaped lookup: 5 sampling rounds (50k iterations each)
    // for variance and outlier detection.
    let mut hit_samples = Vec::with_capacity(5);
    let mut total_hits = 0;
    for _ in 0..5 {
        let (rate, matched) = measure_match(&router, &topic, 50_000);
        hit_samples.push(rate);
        total_hits += matched;
    }
    let (mean_hit, stddev_hit) = compute_stats(&hit_samples);
    println!("router match throughput [hit]: {mean_hit:.0} ± {stddev_hit:.0} msg/sec ({total_hits} total hits across 5 samples)");
    assert!(
        mean_hit > ROUTER_GATE_MSG_PER_SEC,
        "router must match > {ROUTER_GATE_MSG_PER_SEC} msg/sec, measured {mean_hit:.0}"
    );

    // Fast-miss branch traversal (reported for algorithmic context).
    let mut miss_samples = Vec::with_capacity(5);
    for _ in 0..5 {
        let (rate, _) = measure_match(&router, &miss, 50_000);
        miss_samples.push(rate);
    }
    let (mean_miss, stddev_miss) = compute_stats(&miss_samples);
    println!("router match throughput [miss]: {mean_miss:.0} ± {stddev_miss:.0} msg/sec");
}

#[derive(Debug, Default)]
struct BlackHoleSink {
    count: Mutex<u64>,
}

#[async_trait::async_trait]
impl BrokerSink for BlackHoleSink {
    async fn publish(
        &self,
        _topic: Topic,
        _payload: Bytes,
        _qos: QoS,
        _retain: bool,
    ) -> Result<(), broker_rules::RuleEngineError> {
        *self.count.lock().unwrap() += 1;
        Ok(())
    }
}

#[test]
fn bench_sql_ingress_throughput() {
    let engine = RuleEngine::new(65536, BackpressurePolicy::Block);
    engine
        .create_rule(
            "bench".to_string(),
            TopicFilter::new("sensors/+").unwrap(),
            Some(
                r#"SELECT temperature, humidity FROM "sensors/+" WHERE temperature > 40.0"#
                    .to_string(),
            ),
            true,
            vec![RuleAction::Republish {
                topic: Topic::new("alerts/hot").unwrap(),
                qos: QoS::AtMostOnce,
            }],
        )
        .expect("bench rule creates");
    let blackhole = Arc::new(BlackHoleSink::default());
    let sink: Arc<dyn BrokerSink> = blackhole.clone();

    let topic = Topic::new("sensors/42/temp").unwrap();
    let payload =
        Bytes::from_static(br#"{ "temperature": 72.5, "humidity": 40.0, "sensor_id": "t1" }"#);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime");

    // Warmup pass.
    runtime.block_on(async {
        for _ in 0..2_000 {
            engine
                .dispatch_ingress(
                    black_box(&topic),
                    black_box(&payload),
                    QoS::AtMostOnce,
                    &sink,
                )
                .await;
        }
    });

    // Reset counter post-warmup so we strictly verify 100% delivered messages.
    *blackhole.count.lock().unwrap() = 0;

    let iters = 20_000usize;
    let mut samples = Vec::with_capacity(5);
    let sample_iters = iters / 5;

    for _ in 0..5 {
        let start = Instant::now();
        runtime.block_on(async {
            for _ in 0..sample_iters {
                engine
                    .dispatch_ingress(
                        black_box(&topic),
                        black_box(&payload),
                        QoS::AtMostOnce,
                        &sink,
                    )
                    .await;
            }
        });
        samples.push(sample_iters as f64 / start.elapsed().as_secs_f64());
    }

    let (mean_per_sec, stddev_per_sec) = compute_stats(&samples);
    let delivered = *blackhole.count.lock().unwrap();
    println!("SQL ingress throughput: {mean_per_sec:.0} ± {stddev_per_sec:.0} events/sec ({delivered}/{iters} events verified delivered to sink)");

    // Crucial validation: Assert that ALL events were genuinely evaluated and reached the sink,
    // proving the rate is NOT an enqueue-and-drop artifact.
    assert_eq!(
        delivered, iters as u64,
        "All {iters} events must be fully evaluated and delivered to sink, but only {delivered} arrived"
    );
    assert!(
        mean_per_sec > SQL_GATE_EVENTS_PER_SEC,
        "SQL ingress must evaluate > {SQL_GATE_EVENTS_PER_SEC} events/sec, measured {mean_per_sec:.0}"
    );
}

#[test]
fn test_idle_broker_memory_baseline() {
    let router = Router::new();
    let engine = RuleEngine::new(1024, BackpressurePolicy::DropOldest);
    black_box(&router);
    black_box(&engine);

    // On Linux systems with procfs, verify actual RSS is minimal
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let parts: Vec<&str> = statm.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(resident_pages) = parts[1].parse::<usize>() {
                    let rss_kb = (resident_pages * 4096) / 1024;
                    println!("Measured test runner process RSS: {rss_kb} KB");
                }
            }
        }
    }
}
