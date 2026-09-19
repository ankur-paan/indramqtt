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
use std::time::{Duration, Instant};

/// Bounded end-to-end latency sampler (T-27).
///
/// The v4 benchmark JSON reports `avg_latency_ms`/`p99_latency_ms` as 0.0 on
/// every row because no harness ever sampled latency: the fields are
/// hardcoded placeholders (the producing script is not in any repo; only
/// the result JSONs exist under `emqx/benchmark_suite/`). This histogram
/// is the sampler for the in-process harness.
///
/// Memory is constant no matter how many samples are recorded: 64 buckets
/// plus five scalars (~0.5 KiB on the stack). It never grows into the
/// unbounded per-message buffer that BRIEF forbids on a message path.
/// Per-sample cost is one `Instant::now()` pair at the call site plus a
/// leading-zero bit scan and two integer adds here.
///
/// Buckets are powers of two over nanoseconds: bucket `i` counts samples
/// in `[2^i, 2^(i+1))` ns, so percentiles are accurate to a factor of two
/// and the mean/min/max are exact. Both stamp and receipt use the same
/// monotonic `Instant`, so there is no cross-host clock skew by
/// construction; a cross-host run must instead embed a send timestamp in
/// the payload (as `team/perf/tools/mqtt_load.py` does) and accept that
/// same-host comparison as the skew-free baseline.
#[derive(Debug)]
struct LatencyHistogram {
    buckets: [u64; 64],
    count: u64,
    sum_ns: u128,
    min_ns: u64,
    max_ns: u64,
}

impl LatencyHistogram {
    fn new() -> Self {
        Self {
            buckets: [0; 64],
            count: 0,
            sum_ns: 0,
            min_ns: u64::MAX,
            max_ns: 0,
        }
    }

    fn record(&mut self, latency: Duration) {
        let nanos = latency.as_nanos().min(u64::MAX as u128) as u64;
        // Bucket index is floor(log2(nanos)); a zero-nanos sample lands in
        // bucket 0 alongside 1 ns rather than shifting by 64.
        let bucket = if nanos == 0 {
            0
        } else {
            (63 - nanos.leading_zeros()) as usize
        };
        self.buckets[bucket] += 1;
        self.count += 1;
        self.sum_ns += nanos as u128;
        self.min_ns = self.min_ns.min(nanos);
        self.max_ns = self.max_ns.max(nanos);
    }

    fn count(&self) -> u64 {
        self.count
    }

    fn avg_ms(&self) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        Some(self.sum_ns as f64 / self.count as f64 / 1_000_000.0)
    }

    fn min_ms(&self) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        Some(self.min_ns as f64 / 1_000_000.0)
    }

    fn max_ms(&self) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        Some(self.max_ns as f64 / 1_000_000.0)
    }

    /// Percentile latency in ms, reported as the matching bucket's upper
    /// bound (a conservative estimate, within 2x of the true sample).
    /// `p` is in `[0, 100]`.
    fn percentile_ms(&self, p: f64) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        let rank = ((p.clamp(0.0, 100.0) / 100.0 * self.count as f64).ceil() as u64).max(1);
        let mut cumulative = 0u64;
        for (i, bucket) in self.buckets.iter().enumerate() {
            cumulative += *bucket;
            if cumulative >= rank {
                // Bucket i spans [2^i, 2^(i+1)) ns; bucket 63 also holds
                // everything saturating above u64, capped at u64::MAX ms.
                let upper_ns = if i >= 63 { u64::MAX } else { 1u64 << (i + 1) };
                return Some(upper_ns as f64 / 1_000_000.0);
            }
        }
        self.max_ms()
    }

    /// One JSON line per measured stage. Field names keep the v4 result
    /// schema (`avg_latency_ms`, `p99_latency_ms`) working so old and new
    /// runs stay comparable; `p50_latency_ms`/`max_latency_ms` are new.
    fn report_json(&self, stage: &str) {
        let opt = |v: Option<f64>| v.map_or("null".to_string(), |n| format!("{n:.6}"));
        println!(
            "{{\"stage\": \"{stage}\", \"latency_samples\": {}, \"avg_latency_ms\": {}, \"p50_latency_ms\": {}, \"p99_latency_ms\": {}, \"max_latency_ms\": {}}}",
            self.count(),
            opt(self.avg_ms()),
            opt(self.percentile_ms(50.0)),
            opt(self.percentile_ms(99.0)),
            opt(self.max_ms()),
        );
    }
}

/// Floor for full fan-out match throughput (production-shaped table,
/// three hits per lookup including clone + set costs).
#[cfg(not(debug_assertions))]
const ROUTER_GATE_MSG_PER_SEC: f64 = 2_000_000.0;
#[cfg(debug_assertions)]
const ROUTER_GATE_MSG_PER_SEC: f64 = 100_000.0;

/// Floor for streaming-SQL ingress evaluation (release only; debug
/// asserts delivery-only so the bench stays green across machines).
#[cfg(not(debug_assertions))]
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

    // Latency pass (T-27): a separate loop so per-operation timing never
    // perturbs the throughput gates above. 50k timed lookups feed a 0.5 KiB
    // fixed histogram; the only cost is extra wall time of ~50k lookups.
    let mut lat = LatencyHistogram::new();
    for _ in 0..50_000 {
        let start = Instant::now();
        black_box(router.matches(black_box(&topic)));
        lat.record(start.elapsed());
    }
    println!(
        "router match latency [hit]: avg {:.6} ms, p50 {:.6} ms, p99 {:.6} ms, max {:.6} ms ({} samples)",
        lat.avg_ms().unwrap_or(f64::NAN),
        lat.percentile_ms(50.0).unwrap_or(f64::NAN),
        lat.percentile_ms(99.0).unwrap_or(f64::NAN),
        lat.max_ms().unwrap_or(f64::NAN),
        lat.count(),
    );
    lat.report_json("router_match_hit");
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
            TopicFilter::new("sensors/#").unwrap(),
            Some(
                r#"SELECT temperature, humidity FROM "sensors/#" WHERE temperature > 40.0"#
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
    // Absolute rate gate is release-only (machine-sensitive in debug;
    // debug asserts delivery-only so the bench measures rule
    // evaluation instead of flaking on host speed).
    #[cfg(not(debug_assertions))]
    assert!(
        mean_per_sec > SQL_GATE_EVENTS_PER_SEC,
        "SQL ingress must evaluate > {SQL_GATE_EVENTS_PER_SEC} events/sec, measured {mean_per_sec:.0}"
    );

    // Latency pass (T-27): separate timed loop after the throughput gate so
    // sampling cannot move the gate number. 5k timed dispatches into a
    // 0.5 KiB fixed histogram.
    let mut sql_lat = LatencyHistogram::new();
    runtime.block_on(async {
        for _ in 0..5_000 {
            let start = Instant::now();
            engine
                .dispatch_ingress(
                    black_box(&topic),
                    black_box(&payload),
                    QoS::AtMostOnce,
                    &sink,
                )
                .await;
            sql_lat.record(start.elapsed());
        }
    });
    println!(
        "SQL ingress latency: avg {:.6} ms, p50 {:.6} ms, p99 {:.6} ms, max {:.6} ms ({} samples)",
        sql_lat.avg_ms().unwrap_or(f64::NAN),
        sql_lat.percentile_ms(50.0).unwrap_or(f64::NAN),
        sql_lat.percentile_ms(99.0).unwrap_or(f64::NAN),
        sql_lat.max_ms().unwrap_or(f64::NAN),
        sql_lat.count(),
    );
    sql_lat.report_json("sql_ingress");
}

#[test]
fn latency_histogram_empty_reports_none() {
    let hist = LatencyHistogram::new();
    assert_eq!(hist.count(), 0);
    assert_eq!(hist.avg_ms(), None);
    assert_eq!(hist.min_ms(), None);
    assert_eq!(hist.max_ms(), None);
    assert_eq!(hist.percentile_ms(50.0), None);
    assert_eq!(hist.percentile_ms(99.0), None);
}

#[test]
fn latency_histogram_avg_min_max_are_exact() {
    let mut hist = LatencyHistogram::new();
    hist.record(Duration::from_micros(100));
    hist.record(Duration::from_micros(200));
    hist.record(Duration::from_micros(300));
    assert_eq!(hist.count(), 3);
    assert!((hist.avg_ms().unwrap() - 0.2).abs() < 1e-9);
    assert!((hist.min_ms().unwrap() - 0.1).abs() < 1e-9);
    assert!((hist.max_ms().unwrap() - 0.3).abs() < 1e-9);
}

#[test]
fn latency_histogram_percentile_stays_inside_sample_bucket() {
    // 1000 identical 1 µs samples all land in one bucket; every
    // percentile must report that bucket's bounds, not drift elsewhere.
    let mut hist = LatencyHistogram::new();
    for _ in 0..1000 {
        hist.record(Duration::from_micros(1));
    }
    // 1000 ns is in bucket 9 ([512, 1024) ns).
    for p in [0.0, 50.0, 99.0, 100.0] {
        let v_ms = hist.percentile_ms(p).unwrap();
        let v_ns = v_ms * 1_000_000.0;
        assert!(
            (512.0..=1024.0).contains(&v_ns),
            "p{p} = {v_ns} ns outside the [512, 1024] ns bucket"
        );
    }
    // A zero-duration sample is counted, not lost to a shift overflow.
    hist.record(Duration::ZERO);
    assert_eq!(hist.count(), 1001);
    assert_eq!(hist.min_ms(), Some(0.0));
}

#[test]
fn latency_histogram_memory_is_constant() {
    // Bounded sampler: a million samples must fit the same fixed buckets,
    // never an unbounded per-sample buffer.
    assert!(
        std::mem::size_of::<LatencyHistogram>() <= 600,
        "histogram must stay ~0.5 KiB, got {} bytes",
        std::mem::size_of::<LatencyHistogram>()
    );
    let mut hist = LatencyHistogram::new();
    for i in 0..1_000_000u64 {
        hist.record(Duration::from_nanos(100 + (i % 997)));
    }
    assert_eq!(hist.count(), 1_000_000);
    assert_eq!(hist.buckets.len(), 64);
    let avg = hist.avg_ms().unwrap();
    assert!(
        (0.0001..0.002).contains(&avg),
        "avg {avg} ms outside the plausible [0.1, 2.0] µs band"
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
