#![allow(future_incompatible)]

//! Enterprise windowed stream processing for IndraMQTT rules.
//!
//! Community rules (no window clause) evaluate statelessly at ingress
//! inside `broker-rules` and never touch this crate: that crate has no
//! dependency edge to this one, so a community-only deployment carries
//! no window-execution code. This crate layers the stateful operators on
//! top: every rule whose SQL carries a `GROUP BY` window clause
//! (`TUMBLINGWINDOW`, `HOPPINGWINDOW`, `SLIDINGWINDOW`, `COUNTWINDOW`)
//! accumulates matching records in a per-rule background worker and
//! evaluates multi-event aggregations per window close.
//!
//! Wiring: the kernel attaches one [`EnterpriseWindowExecutor`] to each
//! production [`RuleEngine`](broker_rules::RuleEngine) via [`attach`]
//! (or [`attach_with_depth`]) before any rule is created. Flush rows are
//! dispatched back through the engine, so action semantics, counters,
//! connector throttling and the broker sink stay exactly the engine's.

use broker_protocol::Topic;
use broker_rules::{aggregate_partitioned, Rule, RuleEngine, RuleTier, WindowExecutor};
use bytes::Bytes;
use parking_lot::RwLock;
use rekuiper_sql::{Evaluator, SelectStmt, TimeUnit, WindowDef};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Weak};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Default per-rule window worker ingress depth (INDRA-215): large
/// enough for high-scale bursts without drops, still bounded so a
/// stalled worker cannot grow memory without limit. Backpressure stays
/// at the edge input queue; a full worker buffer drops with a warning,
/// never blocks. Override per executor via [`attach_with_depth`] or
/// [`EnterpriseWindowExecutor::with_depth`].
pub const DEFAULT_WINDOW_CHANNEL_DEPTH: usize = 65_536;

/// Wall-clock milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Window length in milliseconds (saturating; clamped to at least 1ms so
/// degenerate `TUMBLINGWINDOW(ss, 0)` style definitions tick instead of
/// panicking the ticker).
fn window_length_ms(unit: &TimeUnit, length: u64) -> u64 {
    let per_unit: u64 = match unit {
        TimeUnit::Ms => 1,
        TimeUnit::Ss => 1_000,
        TimeUnit::Mi => 60_000,
        TimeUnit::Hh => 3_600_000,
        TimeUnit::Dd => 86_400_000,
    };
    length.saturating_mul(per_unit).max(1)
}

/// One timestamped record waiting inside a window buffer. The ingress
/// topic travels along so flush dispatches carry real routing context.
#[derive(Debug, Clone)]
struct TimedRecord {
    arrived_ms: u64,
    topic: Topic,
    record: HashMap<String, serde_json::Value>,
}

/// Background aggregation worker for one Enterprise window rule.
struct WindowWorker {
    handle: tokio::task::JoinHandle<()>,
    tx: mpsc::Sender<TimedRecord>,
}

/// Enterprise window execution attached to one [`RuleEngine`](broker_rules::RuleEngine).
///
/// Owns the per-rule background workers and their channel depth. Flush
/// rows dispatch back through the engine
/// ([`RuleEngine::dispatch_window_row`](broker_rules::RuleEngine::dispatch_window_row)),
/// so counters, throttling, connectors and the broker sink are the
/// engine's own: this executor adds no second copy of any of them.
pub struct EnterpriseWindowExecutor {
    workers: RwLock<HashMap<String, WindowWorker>>,
    channel_depth: usize,
    engine: std::sync::OnceLock<Weak<RuleEngine>>,
}

impl EnterpriseWindowExecutor {
    /// Executor with [`DEFAULT_WINDOW_CHANNEL_DEPTH`]. Attach with
    /// [`attach`] (or [`EnterpriseWindowExecutor::install`]) before the
    /// engine creates rules.
    pub fn new() -> Self {
        Self::with_depth(DEFAULT_WINDOW_CHANNEL_DEPTH)
    }

    /// Executor with an explicit per-rule worker channel depth (`depth`
    /// floors at 1, no ceiling). Use 65,536+ for high-scale bursts.
    pub fn with_depth(depth: usize) -> Self {
        Self {
            workers: RwLock::new(HashMap::new()),
            channel_depth: depth.max(1),
            engine: std::sync::OnceLock::new(),
        }
    }

    /// Configured per-rule worker channel depth.
    pub fn channel_depth(&self) -> usize {
        self.channel_depth
    }

    /// Install this executor on `engine` (replacing any previous one)
    /// and spawn workers for the engine's existing Enterprise rules, so
    /// attaching after rules were created still covers them. The normal
    /// path attaches before any rule exists, making this a no-op.
    pub fn install(self: &Arc<Self>, engine: &Arc<RuleEngine>) {
        let _ = self.engine.set(Arc::downgrade(engine));
        let executor: Arc<dyn WindowExecutor> = self.clone();
        engine.set_window_executor(executor);
        for rule in engine.list_rules() {
            if rule.tier == RuleTier::Enterprise {
                self.ensure_worker(&rule);
            }
        }
    }
}

impl Default for EnterpriseWindowExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Attach a default-depth executor to `engine` and return it.
pub fn attach(engine: &Arc<RuleEngine>) -> Arc<EnterpriseWindowExecutor> {
    attach_with_depth(engine, DEFAULT_WINDOW_CHANNEL_DEPTH)
}

/// Attach an executor with an explicit worker channel depth to `engine`
/// and return it.
pub fn attach_with_depth(engine: &Arc<RuleEngine>, depth: usize) -> Arc<EnterpriseWindowExecutor> {
    let executor = Arc::new(EnterpriseWindowExecutor::with_depth(depth));
    executor.install(engine);
    executor
}

impl WindowExecutor for EnterpriseWindowExecutor {
    /// Route one matching record into this rule's window worker: parse
    /// the JSON payload, evaluate the rule WHERE clause, and push passing
    /// records into the worker channel. Lazily spawns a missing worker
    /// (creation outside a runtime defers it to this point).
    fn route_record(&self, rule: &Rule, topic: &Topic, payload: &Bytes) {
        let stmt = match rule.parsed_query.as_ref() {
            Some(stmt) => stmt,
            None => return,
        };
        let record: HashMap<String, serde_json::Value> = match serde_json::from_slice(payload) {
            Ok(serde_json::Value::Object(map)) => map.into_iter().collect(),
            _ => return,
        };
        let passes = match stmt.where_clause.as_ref() {
            Some(condition) => Evaluator::eval_bool(condition, &record),
            None => true,
        };
        if !passes {
            return;
        }
        self.ensure_worker(rule);
        let workers = self.workers.read();
        let Some(worker) = workers.get(&rule.id) else {
            return;
        };
        if worker
            .tx
            .try_send(TimedRecord {
                arrived_ms: now_ms(),
                topic: topic.clone(),
                record,
            })
            .is_err()
        {
            tracing::warn!(
                rule_id = %rule.id,
                "window worker buffer full; ingress record dropped"
            );
        }
    }

    /// Ensure a background worker exists for an Enterprise window rule.
    /// Idempotent: a second call for the same id is a no-op. Requires a
    /// Tokio runtime (returns silently without one; routing retries).
    fn ensure_worker(&self, rule: &Rule) {
        let window = match rule
            .parsed_query
            .as_ref()
            .and_then(|stmt| stmt.window.clone())
        {
            Some(window) => window,
            None => return,
        };
        if self.workers.read().contains_key(&rule.id) {
            return;
        }
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle,
            Err(_) => {
                tracing::warn!(
                    rule_id = %rule.id,
                    "no async runtime: window worker deferred until first ingress"
                );
                return;
            }
        };
        let (tx, rx) = mpsc::channel(self.channel_depth);
        let stmt = match rule.parsed_query.clone() {
            Some(stmt) => stmt,
            None => return,
        };
        let engine = self.engine.get().cloned().unwrap_or_else(Weak::new);
        let worker = WindowWorker {
            tx,
            handle: runtime.spawn(window_worker_loop(
                rule.id.clone(),
                stmt,
                engine,
                rx,
                window,
            )),
        };
        self.workers.write().insert(rule.id.clone(), worker);
    }

    /// Abort the worker for one rule id, if any.
    fn remove_worker(&self, rule_id: &str) {
        if let Some(worker) = self.workers.write().remove(rule_id) {
            worker.handle.abort();
        }
    }

    /// Abort every worker. The engine calls this before replacing all
    /// rules from a snapshot, so no orphan task survives its rule.
    fn abort_all(&self) {
        for (_, worker) in self.workers.write().drain() {
            worker.handle.abort();
        }
    }

    /// Live window worker count (observability/testing hook).
    fn worker_count(&self) -> usize {
        self.workers.read().len()
    }
}

/// Background aggregation loop for one Enterprise window rule. Time
/// windows tick; count windows flush on arrivals; sliding windows
/// aggregate on every arrival. An empty window never dispatches.
async fn window_worker_loop(
    rule_id: String,
    stmt: SelectStmt,
    engine: Weak<RuleEngine>,
    mut rx: mpsc::Receiver<TimedRecord>,
    window: WindowDef,
) {
    match window {
        WindowDef::TumblingTime { unit, length } => {
            let period = std::time::Duration::from_millis(window_length_ms(&unit, length));
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut window_start = now_ms();
            let mut buffer: Vec<TimedRecord> = Vec::new();
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let end = now_ms();
                        let batch = std::mem::take(&mut buffer);
                        flush_window(&rule_id, &stmt, batch, window_start, end, &engine).await;
                        window_start = end;
                    }
                    rec = rx.recv() => {
                        match rec {
                            Some(record) => buffer.push(record),
                            None => break,
                        }
                    }
                }
            }
        }
        WindowDef::Count { size, interval } => {
            let size = size.max(1);
            let mut buffer: Vec<TimedRecord> = Vec::new();
            let mut since_flush = 0usize;
            while let Some(record) = rx.recv().await {
                buffer.push(record);
                since_flush += 1;
                let step = interval.unwrap_or(size).max(1);
                if buffer.len() >= size && since_flush >= step {
                    let end = now_ms();
                    let batch = if interval.is_some() {
                        // Sliding count: aggregate the trailing window,
                        // retain it for the next step.
                        let start = buffer.len().saturating_sub(size);
                        buffer[start..].to_vec()
                    } else {
                        std::mem::take(&mut buffer)
                    };
                    let start = batch.first().map(|r| r.arrived_ms).unwrap_or(end);
                    flush_window(&rule_id, &stmt, batch, start, end, &engine).await;
                    since_flush = 0;
                }
                // Sliding retention cap: never hold more than one window.
                if interval.is_some() {
                    let excess = buffer.len().saturating_sub(size);
                    buffer.drain(..excess);
                }
            }
        }
        WindowDef::HoppingTime {
            unit,
            length,
            interval,
        } => {
            let period = std::time::Duration::from_millis(window_length_ms(&unit, interval));
            let span = window_length_ms(&unit, length);
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut buffer: VecDeque<TimedRecord> = VecDeque::new();
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let end = now_ms();
                        let cutoff = end.saturating_sub(span);
                        while buffer.front().map(|r| r.arrived_ms < cutoff).unwrap_or(false) {
                            buffer.pop_front();
                        }
                        let batch: Vec<TimedRecord> = buffer.iter().cloned().collect();
                        flush_window(
                            &rule_id,
                            &stmt,
                            batch,
                            cutoff,
                            end,
                            &engine,
                        )
                        .await;
                    }
                    rec = rx.recv() => {
                        match rec {
                            Some(record) => buffer.push_back(record),
                            None => break,
                        }
                    }
                }
            }
        }
        WindowDef::SlidingTime { unit, length, .. } => {
            let span = window_length_ms(&unit, length);
            let mut buffer: VecDeque<TimedRecord> = VecDeque::new();
            while let Some(record) = rx.recv().await {
                let end = now_ms();
                let cutoff = end.saturating_sub(span);
                buffer.push_back(record);
                while buffer
                    .front()
                    .map(|r| r.arrived_ms < cutoff)
                    .unwrap_or(false)
                {
                    buffer.pop_front();
                }
                // Aggregate the trailing window on every arrival.
                let batch: Vec<TimedRecord> = buffer.iter().cloned().collect();
                flush_window(&rule_id, &stmt, batch, cutoff, end, &engine).await;
            }
        }
        WindowDef::Session {
            unit,
            max_duration,
            timeout,
        } => {
            let timeout_ms = window_length_ms(&unit, timeout);
            let max_duration_ms = window_length_ms(&unit, max_duration);
            let mut buffer: Vec<TimedRecord> = Vec::new();
            let mut session_start: Option<u64> = None;
            let mut last_arrival: Option<u64> = None;
            loop {
                let sleep_duration = match last_arrival {
                    Some(last) => {
                        let elapsed = now_ms().saturating_sub(last);
                        std::time::Duration::from_millis(timeout_ms.saturating_sub(elapsed).max(1))
                    }
                    None => std::time::Duration::from_secs(3600),
                };
                tokio::select! {
                    _ = tokio::time::sleep(sleep_duration), if last_arrival.is_some() => {
                        let end = now_ms();
                        let start = session_start.unwrap_or(end);
                        let batch = std::mem::take(&mut buffer);
                        flush_window(&rule_id, &stmt, batch, start, end, &engine).await;
                        session_start = None;
                        last_arrival = None;
                    }
                    rec = rx.recv() => {
                        match rec {
                            Some(record) => {
                                let now = record.arrived_ms;
                                let start = match session_start {
                                    Some(s) => s,
                                    None => {
                                        session_start = Some(now);
                                        now
                                    }
                                };
                                buffer.push(record);
                                last_arrival = Some(now);
                                if now.saturating_sub(start) >= max_duration_ms {
                                    let batch = std::mem::take(&mut buffer);
                                    flush_window(&rule_id, &stmt, batch, start, now, &engine).await;
                                    session_start = None;
                                    last_arrival = None;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        }
    }
}

/// Flush one closed window: inject `__window_start__`,
/// `__window_end__`, `window_start`, `window_end` epoch millis into every
/// record (so `window_start()`/`window_end()` resolve), partition by
/// `GROUP BY` when present, evaluate aggregates per partition, and
/// dispatch each resulting row back through the engine. Empty windows
/// and fully-having-filtered windows dispatch nothing. Each row routes
/// with its partition's first record topic. A dropped engine (only
/// possible while shutting down) drops the batch.
async fn flush_window(
    rule_id: &str,
    stmt: &SelectStmt,
    batch: Vec<TimedRecord>,
    window_start_ms: u64,
    window_end_ms: u64,
    engine: &Weak<RuleEngine>,
) {
    if batch.is_empty() {
        return;
    }
    let Some(engine) = engine.upgrade() else {
        return;
    };
    let records: Vec<(Topic, HashMap<String, serde_json::Value>)> = batch
        .into_iter()
        .map(|timed| {
            let mut map = timed.record;
            map.insert(
                "__window_start__".to_string(),
                serde_json::Value::from(window_start_ms),
            );
            map.insert(
                "__window_end__".to_string(),
                serde_json::Value::from(window_end_ms),
            );
            map.insert(
                "window_start".to_string(),
                serde_json::Value::from(window_start_ms),
            );
            map.insert(
                "window_end".to_string(),
                serde_json::Value::from(window_end_ms),
            );
            (timed.topic, map)
        })
        .collect();
    for (topic, row) in aggregate_partitioned(stmt, records) {
        let object: serde_json::Map<String, serde_json::Value> = row.into_iter().collect();
        let bytes = match serde_json::to_vec(&serde_json::Value::Object(object)) {
            Ok(bytes) => Bytes::from(bytes),
            Err(e) => {
                tracing::warn!(
                    rule_id = %rule_id,
                    error = %e,
                    "window row not serializable; dropped"
                );
                continue;
            }
        };
        engine.dispatch_window_row(rule_id, &topic, bytes).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_protocol::{QoS, Topic, TopicFilter};
    use broker_rules::{
        BackpressurePolicy, BrokerSink, Rule, RuleAction, RuleEngine, RuleEngineError, RuleTier,
    };
    use std::sync::Mutex as StdMutex;

    #[derive(Debug, Default)]
    struct RecordingSink {
        published: StdMutex<Vec<(Topic, Bytes, QoS, bool)>>,
    }

    #[async_trait::async_trait]
    impl BrokerSink for RecordingSink {
        async fn publish(
            &self,
            topic: Topic,
            payload: Bytes,
            qos: QoS,
            retain: bool,
        ) -> Result<(), RuleEngineError> {
            self.published
                .lock()
                .unwrap()
                .push((topic, payload, qos, retain));
            Ok(())
        }
    }

    /// Build an engine with the enterprise executor attached and one
    /// rule; returns engine, sink handle, and the stored rule (for tier
    /// assertions). Mirrors production wiring: the same sink serves
    /// inline dispatch and window flushes.
    fn window_rule(
        sql: Option<&str>,
        actions: Vec<RuleAction>,
    ) -> (
        Arc<RuleEngine>,
        Arc<RecordingSink>,
        Arc<dyn BrokerSink>,
        Rule,
    ) {
        let engine = Arc::new(RuleEngine::new(16, BackpressurePolicy::DropOldest));
        attach(&engine);
        let rule = engine
            .create_rule(
                "window-probe".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                sql.map(str::to_string),
                true,
                actions,
            )
            .expect("rule creates");
        let sink = Arc::new(RecordingSink::default());
        let sink_obj: Arc<dyn BrokerSink> = sink.clone();
        engine.set_broker_sink(sink_obj.clone());
        (engine, sink, sink_obj, rule)
    }

    async fn ingress(
        engine: &RuleEngine,
        sink: &Arc<dyn BrokerSink>,
        payload: &'static [u8],
    ) -> usize {
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(payload),
                QoS::AtMostOnce,
                sink,
            )
            .await
    }

    fn published_rows(sink: &RecordingSink) -> Vec<serde_json::Value> {
        sink.published
            .lock()
            .unwrap()
            .iter()
            .map(|(_, payload, _, _)| serde_json::from_slice(payload).expect("row is JSON"))
            .collect()
    }

    async fn wait_rows(sink: &Arc<RecordingSink>, n: usize) {
        for _ in 0..60 {
            if sink.published.lock().unwrap().len() >= n {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!(
            "timed out waiting for {n} rows (got {})",
            sink.published.lock().unwrap().len()
        );
    }

    fn republish_action() -> Vec<RuleAction> {
        vec![RuleAction::Republish {
            topic: Topic::new("alerts/agg").unwrap(),
            qos: QoS::AtMostOnce,
        }]
    }

    #[tokio::test]
    async fn test_window_worker_lifecycle() {
        let engine = Arc::new(RuleEngine::new(16, BackpressurePolicy::DropOldest));
        attach(&engine);
        assert_eq!(engine.window_worker_count(), 0);
        let rule = engine
            .create_rule(
                "w".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY TUMBLINGWINDOW(ss, 30)"#
                        .to_string(),
                ),
                true,
                vec![RuleAction::Log],
            )
            .expect("rule creates");
        assert_eq!(engine.window_worker_count(), 1);
        // Re-creating is per-rule; removing aborts the worker.
        assert!(engine
            .remove_rule(&rule.id)
            .expect("memory-only remove cannot fail"));
        assert_eq!(engine.window_worker_count(), 0);
        assert!(!engine
            .remove_rule(&rule.id)
            .expect("memory-only remove cannot fail"));
        assert!(!engine
            .remove_rule("rule-999")
            .expect("memory-only remove cannot fail"));
    }

    #[tokio::test]
    async fn test_count_window_aggregates_on_threshold() {
        let (engine, sink, sink_obj, rule) = window_rule(
            Some(r#"SELECT avg(temperature) AS avg_temp FROM "sensors/+" GROUP BY COUNTWINDOW(2)"#),
            republish_action(),
        );
        assert_eq!(rule.tier, RuleTier::Enterprise);

        // Two records close one window: exactly one aggregate row.
        ingress(&engine, &sink_obj, br#"{ "temperature": 10.0 }"#).await;
        ingress(&engine, &sink_obj, br#"{ "temperature": 30.0 }"#).await;
        wait_rows(&sink, 1).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let rows = published_rows(&sink);
        assert_eq!(rows.len(), 1, "one row per closed window, got {rows:?}");
        assert_eq!(rows[0]["avg_temp"], serde_json::json!(20.0));
    }

    #[tokio::test]
    async fn test_count_window_where_gate() {
        let (engine, sink, sink_obj, _) = window_rule(
            Some(
                r#"SELECT avg(temperature) AS avg_temp FROM "sensors/+" WHERE temperature > 50.0 GROUP BY COUNTWINDOW(2)"#,
            ),
            republish_action(),
        );

        // Below-threshold ingress never reaches the buffer...
        ingress(&engine, &sink_obj, br#"{ "temperature": 10.0 }"#).await;
        // ...so these two close the first window alone.
        ingress(&engine, &sink_obj, br#"{ "temperature": 60.0 }"#).await;
        ingress(&engine, &sink_obj, br#"{ "temperature": 70.0 }"#).await;
        wait_rows(&sink, 1).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let rows = published_rows(&sink);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["avg_temp"], serde_json::json!(65.0));
    }

    #[tokio::test]
    async fn test_tumbling_window_aggregates_and_skips_empty() {
        let (engine, sink, sink_obj, _) = window_rule(
            Some(
                r#"SELECT avg(temperature) AS avg_temp, sum(temperature) AS total, count(*) AS n, min(temperature) AS lo, max(temperature) AS hi FROM "sensors/+" GROUP BY TUMBLINGWINDOW(ms, 150)"#,
            ),
            republish_action(),
        );

        ingress(&engine, &sink_obj, br#"{ "temperature": 10.0 }"#).await;
        ingress(&engine, &sink_obj, br#"{ "temperature": 20.0 }"#).await;
        ingress(&engine, &sink_obj, br#"{ "temperature": 30.0 }"#).await;
        wait_rows(&sink, 1).await;
        let rows = published_rows(&sink);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["avg_temp"], serde_json::json!(20.0));
        assert_eq!(rows[0]["total"], serde_json::json!(60.0));
        assert_eq!(rows[0]["n"], serde_json::json!(3));
        assert_eq!(rows[0]["lo"], serde_json::json!(10.0));
        assert_eq!(rows[0]["hi"], serde_json::json!(30.0));

        // Empty windows dispatch nothing: still exactly one row later.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(published_rows(&sink).len(), 1);
    }

    #[tokio::test]
    async fn test_group_by_partitions_per_sensor() {
        let (engine, sink, sink_obj, _) = window_rule(
            Some(
                r#"SELECT sensor_id, avg(temperature) AS avg_temp FROM "sensors/+" GROUP BY sensor_id, COUNTWINDOW(3)"#,
            ),
            republish_action(),
        );

        ingress(
            &engine,
            &sink_obj,
            br#"{ "sensor_id": "a", "temperature": 10.0 }"#,
        )
        .await;
        ingress(
            &engine,
            &sink_obj,
            br#"{ "sensor_id": "b", "temperature": 30.0 }"#,
        )
        .await;
        ingress(
            &engine,
            &sink_obj,
            br#"{ "sensor_id": "a", "temperature": 20.0 }"#,
        )
        .await;
        wait_rows(&sink, 2).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let rows = published_rows(&sink);
        assert_eq!(rows.len(), 2, "one row per group, got {rows:?}");
        // First-seen group order is deterministic.
        assert_eq!(rows[0]["sensor_id"], serde_json::json!("a"));
        assert_eq!(rows[0]["avg_temp"], serde_json::json!(15.0));
        assert_eq!(rows[1]["sensor_id"], serde_json::json!("b"));
        assert_eq!(rows[1]["avg_temp"], serde_json::json!(30.0));
    }

    #[tokio::test]
    async fn test_window_bounds_resolve_in_output() {
        let (engine, sink, sink_obj, _) = window_rule(
            Some(
                r#"SELECT avg(temperature) AS a, window_start() AS ws, window_end() AS we FROM "sensors/+" GROUP BY COUNTWINDOW(1)"#,
            ),
            republish_action(),
        );

        ingress(&engine, &sink_obj, br#"{ "temperature": 5.0 }"#).await;
        wait_rows(&sink, 1).await;
        let rows = published_rows(&sink);
        assert_eq!(rows.len(), 1);
        let ws = rows[0]["ws"].as_u64().expect("window_start resolves");
        let we = rows[0]["we"].as_u64().expect("window_end resolves");
        assert!(ws > 0 && we >= ws, "sane bounds: ws={ws} we={we}");
        assert!(
            we - ws < 60_000,
            "count-window bounds span the batch, not history"
        );
    }

    #[tokio::test]
    async fn test_hopping_window_smoke() {
        let (engine, sink, sink_obj, _) = window_rule(
            Some(
                r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY HOPPINGWINDOW(ms, 300, 150)"#,
            ),
            republish_action(),
        );

        ingress(&engine, &sink_obj, br#"{ "temperature": 10.0 }"#).await;
        ingress(&engine, &sink_obj, br#"{ "temperature": 30.0 }"#).await;
        // Overlapping ticks eventually flush the trailing window.
        wait_rows(&sink, 1).await;
        let rows = published_rows(&sink);
        assert!(!rows.is_empty());
        assert!(rows[0]["a"].is_number());
    }

    #[tokio::test]
    async fn test_sliding_window_aggregates_per_arrival() {
        let (engine, sink, sink_obj, _) = window_rule(
            Some(r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY SLIDINGWINDOW(ss, 60)"#),
            republish_action(),
        );

        // Every arrival re-aggregates the trailing window, in order.
        ingress(&engine, &sink_obj, br#"{ "temperature": 10.0 }"#).await;
        ingress(&engine, &sink_obj, br#"{ "temperature": 30.0 }"#).await;
        wait_rows(&sink, 2).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let rows = published_rows(&sink);
        assert_eq!(rows.len(), 2, "one row per arrival, got {rows:?}");
        assert_eq!(rows[0]["a"], serde_json::json!(10.0));
        assert_eq!(rows[1]["a"], serde_json::json!(20.0));
    }

    #[tokio::test]
    async fn test_window_forward_connector_dispatch() {
        use broker_connectors::Sink as ConnectorSinkTrait;

        #[derive(Debug, Default)]
        struct ProbeConnector {
            events: StdMutex<Vec<serde_json::Value>>,
        }

        #[async_trait::async_trait]
        impl ConnectorSinkTrait for ProbeConnector {
            async fn send(
                &self,
                _topic: &Topic,
                payload: &Bytes,
                _qos: QoS,
            ) -> Result<(), broker_connectors::ConnectorError> {
                self.events
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(payload).expect("row JSON"));
                Ok(())
            }

            fn kind(&self) -> &'static str {
                "probe"
            }
        }

        let engine = Arc::new(RuleEngine::new(16, BackpressurePolicy::DropOldest));
        attach(&engine);
        let probe = Arc::new(ProbeConnector::default());
        engine.connectors().register("probe", probe.clone());
        engine
            .create_rule(
                "w".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY COUNTWINDOW(2)"#
                        .to_string(),
                ),
                true,
                vec![RuleAction::ForwardConnector {
                    connector_id: "probe".to_string(),
                }],
            )
            .expect("rule creates");
        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        let sink_obj = sink;

        ingress(&engine, &sink_obj, br#"{ "temperature": 8.0 }"#).await;
        ingress(&engine, &sink_obj, br#"{ "temperature": 12.0 }"#).await;
        for _ in 0..60 {
            if !probe.events.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let events = probe.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["a"], serde_json::json!(10.0));
    }

    #[test]
    fn test_window_channel_depth_configurable() {
        // INDRA-215: default is the high-scale 65,536; the constructor
        // overrides with a floor of 1 and no ceiling.
        assert_eq!(DEFAULT_WINDOW_CHANNEL_DEPTH, 65_536);
        assert_eq!(EnterpriseWindowExecutor::new().channel_depth(), 65_536);
        assert_eq!(
            EnterpriseWindowExecutor::with_depth(10_000).channel_depth(),
            10_000
        );
        assert_eq!(
            EnterpriseWindowExecutor::with_depth(1_000_000).channel_depth(),
            1_000_000
        );
        assert_eq!(EnterpriseWindowExecutor::with_depth(0).channel_depth(), 1);
    }

    #[tokio::test]
    async fn test_window_channel_depth_reaches_worker() {
        // The spawned worker's channel bound equals the configured depth.
        async fn worker_capacity(depth: usize) -> usize {
            let engine = Arc::new(RuleEngine::new(16, BackpressurePolicy::DropOldest));
            let executor = attach_with_depth(&engine, depth);
            assert_eq!(executor.channel_depth(), depth.max(1));
            let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
            engine
                .create_rule(
                    "w".to_string(),
                    TopicFilter::new("sensors/+").unwrap(),
                    Some(
                        r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY COUNTWINDOW(2)"#
                            .to_string(),
                    ),
                    true,
                    vec![],
                )
                .expect("rule creates");
            ingress(&engine, &sink, br#"{ "temperature": 1.0 }"#).await;
            let workers = executor.workers.read();
            let worker = workers.get("rule-1").expect("worker spawned");
            worker.tx.max_capacity()
        }
        assert_eq!(worker_capacity(65_536).await, 65_536);
        assert_eq!(worker_capacity(10_000).await, 10_000);
    }

    #[tokio::test]
    async fn test_window_burst_twelve_k_without_drop() {
        // INDRA-215: 12,000 ingress events over COUNTWINDOW(100) flush
        // 120 windows with zero drops at the default depth.
        #[derive(Debug, Default)]
        struct BurstProbe {
            events: StdMutex<Vec<serde_json::Value>>,
        }
        #[async_trait::async_trait]
        impl broker_connectors::Sink for BurstProbe {
            async fn send(
                &self,
                _topic: &Topic,
                payload: &Bytes,
                _qos: QoS,
            ) -> Result<(), broker_connectors::ConnectorError> {
                self.events
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(payload).expect("row JSON"));
                Ok(())
            }

            fn kind(&self) -> &'static str {
                "burst-probe"
            }
        }

        let engine = Arc::new(RuleEngine::new(65_536, BackpressurePolicy::DropOldest));
        attach(&engine);
        let probe = Arc::new(BurstProbe::default());
        engine.connectors().register("burst", probe.clone());
        engine
            .create_rule(
                "burst-rule".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY COUNTWINDOW(100)"#
                        .to_string(),
                ),
                true,
                vec![RuleAction::ForwardConnector {
                    connector_id: "burst".to_string(),
                }],
            )
            .expect("rule creates");
        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        for _ in 0..12_000 {
            ingress(&engine, &sink, br#"{ "temperature": 20.0 }"#).await;
        }
        for _ in 0..400 {
            if probe.events.lock().unwrap().len() >= 120 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let events = probe.events.lock().unwrap();
        assert_eq!(events.len(), 120, "burst dropped window flushes");
        assert_eq!(events[0]["a"], serde_json::json!(20.0));
    }

    #[tokio::test]
    async fn test_remove_rule_stops_window_delivery() {
        let (engine, sink, sink_obj, rule) = window_rule(
            Some(
                r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY TUMBLINGWINDOW(ss, 30)"#,
            ),
            republish_action(),
        );
        assert_eq!(engine.window_worker_count(), 1);

        // Records buffer, then the rule disappears before any close.
        for _ in 0..5 {
            ingress(&engine, &sink_obj, br#"{ "temperature": 1.0 }"#).await;
        }
        assert!(engine
            .remove_rule(&rule.id)
            .expect("memory-only remove cannot fail"));
        assert_eq!(engine.window_worker_count(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            published_rows(&sink).is_empty(),
            "aborted worker must not deliver"
        );
    }

    #[tokio::test]
    async fn test_attach_backfills_previously_created_rules() {
        // Attaching after rules exist still covers them: the kernel
        // attaches before creation, but late attach must not strand a
        // rule without its worker.
        let engine = Arc::new(RuleEngine::new(16, BackpressurePolicy::DropOldest));
        engine
            .create_rule(
                "late".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY COUNTWINDOW(1)"#
                        .to_string(),
                ),
                true,
                republish_action(),
            )
            .expect("rule creates");
        assert_eq!(engine.window_worker_count(), 0);
        attach(&engine);
        assert_eq!(engine.window_worker_count(), 1);
        let sink = Arc::new(RecordingSink::default());
        let sink_obj: Arc<dyn BrokerSink> = sink.clone();
        engine.set_broker_sink(sink_obj.clone());
        ingress(&engine, &sink_obj, br#"{ "temperature": 7.0 }"#).await;
        wait_rows(&sink, 1).await;
        assert_eq!(published_rows(&sink)[0]["a"], serde_json::json!(7.0));
    }

    /// Sprint 18 e2e (INDRA-216): streaming SQL rules with `INTO
    /// connector(...)` fan out to the object-storage and search sinks.
    /// A stateless cold-storage rule feeds mock S3, a stateless log
    /// rule feeds mock Elasticsearch, and a count-window metrics rule
    /// feeds the mock TimescaleDB hypertable. No broker anywhere.
    ///
    /// Lives here (moved from `broker-rules` under X1-06): that crate
    /// cannot dev-depend on this one — the executor's
    /// `attach(&Arc<RuleEngine>)` would then resolve `RuleEngine`
    /// through a second crate instance and fail with E0308. The
    /// windowed timescale rule below exercises the enterprise
    /// executor end to end, exactly as before the split.
    /// X1-09: needs the community `s3` feature (S3 mock absent by default).
    #[cfg(feature = "s3")]
    #[tokio::test]
    async fn test_into_fans_out_to_s3_elasticsearch_timescaledb() {
        use broker_connectors::{
            ElasticsearchSink, ElasticsearchSinkConfig, MockElasticsearchTransport,
            MockS3Transport, MockTimescaleTransport, S3Sink, S3SinkConfig, TimescaleDbSink,
            TimescaleDbSinkConfig,
        };

        let engine = Arc::new(RuleEngine::new(65_536, BackpressurePolicy::DropOldest));
        // COUNTWINDOW rules execute in this crate; attach the executor
        // so the windowed timescale rule below flushes exactly as
        // before the split.
        attach(&engine);

        // S3 cold storage (auto-flush every row).
        let s3_transport = Arc::new(MockS3Transport::new());
        let s3 = Arc::new(
            S3Sink::new(
                S3SinkConfig {
                    endpoint: "http://127.0.0.1:9000".to_string(),
                    bucket: "telemetry-cold-store".to_string(),
                    region: "us-east-1".to_string(),
                    access_key_id: String::new(),
                    secret_access_key: String::new(),
                    key_template:
                        "telemetry/year=${YYYY}/month=${MM}/day=${DD}/${topic}_${seq}.ndjson"
                            .to_string(),
                    compression: broker_connectors::S3Compression::None,
                    batch_size: 1,
                    batch_bytes: 5 * 1024 * 1024,
                    batch_timeout_ms: 60_000,
                    timeout_ms: None,
                },
                s3_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("s3-telemetry-archive", s3.clone());

        // Elasticsearch log search (auto-flush every row).
        let es_transport = Arc::new(MockElasticsearchTransport::new());
        let es = Arc::new(
            ElasticsearchSink::new(
                ElasticsearchSinkConfig {
                    endpoint: "http://127.0.0.1:9200".to_string(),
                    index_template: "iot-telemetry-${YYYY.MM.dd}".to_string(),
                    doc_id_template: None,
                    auth: broker_connectors::ElasticsearchAuth::None,
                    batch_size: 1,
                    batch_timeout_ms: 100,
                    max_retries: 3,
                    request_timeout_ms: None,
                },
                es_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("es-cluster", es.clone());

        // TimescaleDB metrics hypertable (auto-flush every row).
        let ts_transport = Arc::new(MockTimescaleTransport::new());
        let ts = Arc::new(
            TimescaleDbSink::new(
                TimescaleDbSinkConfig {
                    connection_url: "postgresql://u:p@unused:5432/timeseries".to_string(),
                    hypertable: "sensor_metrics".to_string(),
                    time_column: "time".to_string(),
                    sql_template: "INSERT INTO sensor_metrics (time, device_id, topic, metrics) \
                         VALUES ($1, $2, $3, $4::jsonb) \
                         ON CONFLICT (time, device_id) DO UPDATE SET metrics = EXCLUDED.metrics"
                        .to_string(),
                    pool_size: 1,
                    batch_size: 1,
                    batch_timeout_ms: 50,
                },
                ts_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("timescale-metrics", ts.clone());

        // One INTO rule per sink, mirroring the directive's SQL shapes
        // (count windows keep the test fast; tumbling time windows use
        // the same dispatch path).
        for (id, sql) in [
            (
                "cold-store",
                r#"SELECT * FROM "sensors/#" INTO connector("s3-telemetry-archive")"#,
            ),
            (
                "log-search",
                r#"SELECT device_id, message FROM "logs/+" INTO connector("es-cluster")"#,
            ),
            (
                "metrics",
                r#"SELECT avg(temp) AS avg_temp FROM "sensors/+" GROUP BY COUNTWINDOW(2) INTO connector("timescale-metrics")"#,
            ),
        ] {
            engine
                .create_rule(
                    id.to_string(),
                    TopicFilter::new(if id == "log-search" {
                        "logs/+"
                    } else {
                        "sensors/+"
                    })
                    .unwrap(),
                    Some(sql.to_string()),
                    true,
                    vec![],
                )
                .expect("rule creates");
        }

        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        // Two sensor rows close one count window; one log row feeds ES.
        for payload in [
            &br#"{ "device_id": "d7", "temp": 20.0 }"#[..],
            &br#"{ "device_id": "d7", "temp": 22.0 }"#[..],
        ] {
            engine
                .dispatch_ingress(
                    &Topic::new("sensors/kitchen").unwrap(),
                    &Bytes::from_static(payload),
                    QoS::AtMostOnce,
                    &sink,
                )
                .await;
        }
        engine
            .dispatch_ingress(
                &Topic::new("logs/app").unwrap(),
                &Bytes::from_static(br#"{ "device_id": "d7", "message": "ok" }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        // S3 + ES flushed inline (batch_size 1); the window flush
        // arrives in the background.
        for _ in 0..200 {
            if !ts_transport.batches().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // S3: two partitioned ndjson objects with full projected rows.
        let puts = s3_transport.puts();
        assert_eq!(puts.len(), 2);
        assert!(puts[0].key.starts_with("telemetry/year="));
        assert!(puts[0].key.contains("sensors/kitchen"));
        assert!(puts[0].key.ends_with(".ndjson"));
        let row: serde_json::Value =
            serde_json::from_str(String::from_utf8(puts[0].body.clone()).unwrap().trim_end())
                .unwrap();
        assert_eq!(row["topic"], "sensors/kitchen");
        assert_eq!(row["payload"]["temp"], 20.0);

        // Elasticsearch: one _bulk with the projected log document.
        let captured = es_transport.captured();
        assert_eq!(captured.len(), 1);
        let body = String::from_utf8(captured[0].body.clone()).unwrap();
        assert!(body.ends_with('\n'));
        let mut body_lines = body.lines();
        let action: serde_json::Value = serde_json::from_str(body_lines.next().unwrap()).unwrap();
        assert!(action["index"]["_index"]
            .as_str()
            .unwrap()
            .starts_with("iot-telemetry-"));
        let doc: serde_json::Value = serde_json::from_str(body_lines.next().unwrap()).unwrap();
        assert!(body_lines.next().is_none());
        assert_eq!(doc["topic"], "logs/app");
        assert_eq!(doc["payload"]["message"], "ok");
        assert!(doc["payload"].get("temp").is_none());

        // TimescaleDB: one window row (avg 21.0); no device_id in the
        // projection, so the topic backs the device column.
        let batches = ts_transport.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].rows.len(), 1);
        assert_eq!(batches[0].rows[0][1], b"sensors/kitchen".to_vec());
        assert_eq!(batches[0].rows[0][2], b"sensors/kitchen".to_vec());
        let metrics: serde_json::Value = serde_json::from_slice(&batches[0].rows[0][3]).unwrap();
        assert_eq!(metrics, serde_json::json!({"avg_temp": 21.0}));
    }
}
