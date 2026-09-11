//! Automated throughput gates for the messaging hot path.
//!
//! These run under both `cargo test` (debug) and `cargo bench`/`cargo
//! test --release` (release): router topic matching and streaming-SQL
//! ingress evaluation. Gates are profile-aware: absolute numbers apply
//! to optimized builds (production), while debug gates sit ~35% below
//! measured debug throughput as regression tripwires. Reference machine
//! (Windows x64): router hit-path 154k msg/sec debug / 1.44M release,
//! SQL ingress 660k events/sec debug / 4.6M release.

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
const ROUTER_GATE_MSG_PER_SEC: f64 = 500_000.0;
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
                client_id: format!("client-{i}"),
                conn_id: i as u64,
                qos: QoS::AtMostOnce,
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
                client_id: format!("route-{filter}"),
                conn_id: 1_000_000,
                qos,
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

#[test]
fn bench_router_match_throughput() {
    let router = build_router(1_000);
    let topic = Topic::new("device/7/state").unwrap();
    let miss = Topic::new("zzz/9/nope").unwrap();

    // Warmup so caches and branch predictors settle.
    for _ in 0..5_000 {
        black_box(router.matches(black_box(&topic)));
    }

    // Production-shaped lookup: three hits (exact + wildcards).
    let (per_sec, matched) = measure_match(&router, &topic, 200_000);
    println!("router match throughput [hit]: {per_sec:.0} msg/sec ({matched} total hits)");
    black_box(matched);
    assert!(
        per_sec > ROUTER_GATE_MSG_PER_SEC,
        "router must match > {ROUTER_GATE_MSG_PER_SEC} msg/sec, measured {per_sec:.0}"
    );

    // Walk-only cost, reported for context (no gate: hit path governs).
    let (miss_sec, _) = measure_match(&router, &miss, 200_000);
    println!("router match throughput [miss]: {miss_sec:.0} msg/sec");
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
    let engine = RuleEngine::new(1024, BackpressurePolicy::DropOldest);
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
    let sink: Arc<dyn BrokerSink> = Arc::new(BlackHoleSink::default());

    let topic = Topic::new("sensors/42/temp").unwrap();
    let payload =
        Bytes::from_static(br#"{ "temperature": 72.5, "humidity": 40.0, "sensor_id": "t1" }"#);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime");
    // Warmup.
    runtime.block_on(async {
        for _ in 0..1_000 {
            engine
                .dispatch_ingress(black_box(&topic), black_box(&payload), QoS::AtMostOnce, &sink)
                .await;
        }
    });

    let iters = 20_000usize;
    let start = Instant::now();
    runtime.block_on(async {
        for _ in 0..iters {
            engine
                .dispatch_ingress(black_box(&topic), black_box(&payload), QoS::AtMostOnce, &sink)
                .await;
        }
    });
    let per_sec = iters as f64 / start.elapsed().as_secs_f64();
    println!("SQL ingress throughput: {per_sec:.0} events/sec");
    assert!(
        per_sec > SQL_GATE_EVENTS_PER_SEC,
        "SQL ingress must evaluate > {SQL_GATE_EVENTS_PER_SEC} events/sec, measured {per_sec:.0}"
    );
}
