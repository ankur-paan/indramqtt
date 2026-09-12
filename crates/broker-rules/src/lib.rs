use async_trait::async_trait;
use broker_connectors::ConnectorManager;
use bytes::Bytes;
use broker_protocol::{QoS, Topic, TopicFilter};
use parking_lot::RwLock;
use rekuiper_sql::{Evaluator, SelectStmt, TimeUnit, WindowDef};

/// The streaming-SQL function catalog (name, category, aggregate flag,
/// arity, example) served to the dashboard SQL studio.
pub use rekuiper_sql::{builtin_function_metadata, FunctionMeta};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

#[derive(Error, Debug)]
pub enum RuleEngineError {
    #[error("Event input buffer overflow: {0:?}")]
    Overflow(OverflowReason),

    #[error("Rule execution failed: {0}")]
    Execution(String),

    #[error("Invalid rule: {0}")]
    InvalidRule(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverflowReason {
    DroppedNewest,
    DroppedOldest,
    BufferFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackpressurePolicy {
    Block,
    DropNewest,
    DropOldest,
    SpillToDisk,
    RejectPublisher,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    Enqueued,
    Dropped(OverflowReason),
    SpilledToDisk(u64),
}

#[derive(Debug, Clone)]
pub struct StreamEvent {
    pub topic: Topic,
    pub payload: Bytes,
    pub timestamp_millis: i64,
    pub client_id: Option<String>,
}

impl StreamEvent {
    pub fn new(topic: Topic, payload: Bytes) -> Self {
        let timestamp_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Self {
            topic,
            payload,
            timestamp_millis,
            client_id: None,
        }
    }
}

#[async_trait]
pub trait EventInput: Send + Sync {
    async fn push(&self, event: StreamEvent) -> Result<PushOutcome, RuleEngineError>;
}

/// Direct in-memory sink for rules to publish messages back into the broker
/// without paying the cost of establishing an external loopback network connection.
#[async_trait]
pub trait BrokerSink: Send + Sync {
    async fn publish(
        &self,
        topic: Topic,
        payload: Bytes,
        qos: QoS,
        retain: bool,
    ) -> Result<(), RuleEngineError>;
}

/// Bounded in-memory event queue implementing [`EventInput`].
///
/// `Block` waits for capacity inside `push`; `DropNewest` discards the
/// incoming event when full; `DropOldest` evicts the oldest queued event
/// to make room. `SpillToDisk` (not yet implemented) and
/// `RejectPublisher` report overflow as an error instead of queueing.
pub struct BoundedEventInput {
    tx: mpsc::Sender<StreamEvent>,
    rx: Mutex<mpsc::Receiver<StreamEvent>>,
    policy: BackpressurePolicy,
}

impl BoundedEventInput {
    pub fn new(capacity: usize, policy: BackpressurePolicy) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        Arc::new(Self {
            tx,
            rx: Mutex::new(rx),
            policy,
        })
    }

    /// Non-blocking enqueue attempt. `Block` never blocks here: a full
    /// buffer reports `WouldBlock`-style success value... see below.
    pub fn try_push(&self, event: StreamEvent) -> Result<PushOutcome, RuleEngineError> {
        match self.tx.try_send(event) {
            Ok(()) => Ok(PushOutcome::Enqueued),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(RuleEngineError::Overflow(OverflowReason::BufferFull))
            }
            Err(mpsc::error::TrySendError::Full(event)) => self.apply_full_policy(event),
        }
    }

    fn apply_full_policy(&self, event: StreamEvent) -> Result<PushOutcome, RuleEngineError> {
        match self.policy {
            // Synchronous callers cannot block: use `push().await` for
            // true blocking behaviour under the Block policy.
            BackpressurePolicy::Block => Ok(PushOutcome::Dropped(OverflowReason::BufferFull)),
            BackpressurePolicy::DropNewest => {
                Ok(PushOutcome::Dropped(OverflowReason::DroppedNewest))
            }
            BackpressurePolicy::DropOldest => {
                // Best-effort eviction without blocking: only a stale
                // receiver can defeat this, in which case the event drops.
                if let Ok(mut rx) = self.rx.try_lock() {
                    let _ = rx.try_recv();
                    match self.tx.try_send(event) {
                        Ok(()) => Ok(PushOutcome::Dropped(OverflowReason::DroppedOldest)),
                        Err(_) => Ok(PushOutcome::Dropped(OverflowReason::DroppedNewest)),
                    }
                } else {
                    Ok(PushOutcome::Dropped(OverflowReason::DroppedNewest))
                }
            }
            BackpressurePolicy::SpillToDisk | BackpressurePolicy::RejectPublisher => {
                Err(RuleEngineError::Overflow(OverflowReason::BufferFull))
            }
        }
    }

    /// Take the next queued event (consumer side).
    pub async fn next_event(&self) -> Option<StreamEvent> {
        self.rx.lock().await.recv().await
    }
}

#[async_trait]
impl EventInput for BoundedEventInput {
    async fn push(&self, event: StreamEvent) -> Result<PushOutcome, RuleEngineError> {
        match self.policy {
            BackpressurePolicy::Block => self
                .tx
                .send(event)
                .await
                .map(|()| PushOutcome::Enqueued)
                .map_err(|_| RuleEngineError::Overflow(OverflowReason::BufferFull)),
            _ => self.try_push(event),
        }
    }
}

/// One native stream rule: match ingress by topic filter, run actions.
///
/// Open-core licensing tier of a rule, derived from its SQL at creation:
/// any `GROUP BY` window clause (`TUMBLINGWINDOW`, `HOPPINGWINDOW`,
/// `SLIDINGWINDOW`, `COUNTWINDOW`) makes a rule Enterprise; everything
/// else is Community.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleTier {
    Community,
    Enterprise,
}

/// `sql_query` is an optional streaming-SQL program parsed once at
/// creation into `parsed_query`. Community rules (no window clause) run
/// statelessly at ingress: matching JSON payloads are filtered (WHERE)
/// and projected (SELECT). Enterprise rules (window clause present)
/// accumulate matching records in a background worker and evaluate
/// multi-event aggregations per window close. `parsed_query` is skipped
/// in JSON output: the wire form carries the source SQL string, which
/// re-parses on creation.
#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub topic_filter: TopicFilter,
    pub sql_query: Option<String>,
    #[serde(skip_serializing)]
    pub parsed_query: Option<SelectStmt>,
    pub tier: RuleTier,
    pub enabled: bool,
    pub actions: Vec<RuleAction>,
}

/// Actions a rule may execute per matched ingress event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleAction {
    /// Republish the (possibly transformed) payload in Rust memory via
    /// [`BrokerSink`]. Never opens an MQTT loopback connection.
    Republish {
        topic: Topic,
        #[serde(with = "qos_serde")]
        qos: QoS,
    },
    /// Emit a structured log line for the matched event.
    Log,
    /// Forward the (possibly transformed) payload to a registered
    /// external connector (e.g. an HTTP webhook) by id.
    ForwardConnector { connector_id: String },
}

/// Serde helper: [`QoS`] as its MQTT wire number (0/1/2).
mod qos_serde {
    use super::QoS;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(qos: &QoS, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8((*qos).into())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<QoS, D::Error> {
        let raw = u8::deserialize(deserializer)?;
        QoS::try_from(raw).map_err(serde::de::Error::custom)
    }
}

/// Ingress-only rule engine shared by every connection task on a node.
///
/// Rules are matched with [`TopicFilter::matches`] at message ingress on
/// the receiving node. Republished messages flow straight into the sink
/// and are never re-dispatched, so rules cannot recurse through their
/// own output.
///
/// Enterprise (windowed) rules do not execute inline: matching records
/// are pushed to a per-rule background worker ([`WindowWorker`]) that
/// aggregates per window close and dispatches through the actions.
pub struct RuleEngine {
    rules: RwLock<HashMap<String, Rule>>,
    next_id: AtomicU64,
    input: Arc<BoundedEventInput>,
    connectors: Arc<ConnectorManager>,
    flush_ctx: Arc<FlushContext>,
    window_workers: RwLock<HashMap<String, WindowWorker>>,
}

/// Shared flush context: what a window worker needs at flush time. The
/// broker sink is installed post-construction via
/// [`RuleEngine::set_broker_sink`] (the engine is built before the node
/// sink exists); connectors are shared with the engine itself.
struct FlushContext {
    connectors: Arc<ConnectorManager>,
    broker_sink: RwLock<Option<Arc<dyn BrokerSink>>>,
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

/// Worker ingress channel depth: backpressure stays at the edge input
/// queue, so a full worker buffer drops with a warning, never blocks.
const WINDOW_CHANNEL_DEPTH: usize = 1024;

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

impl RuleEngine {
    /// Create an engine with a bounded ingress queue (`capacity` floors at
    /// 1). The queue backs future async ingestion; the hot path calls
    /// [`RuleEngine::dispatch_ingress`] synchronously for determinism.
    pub fn new(queue_capacity: usize, policy: BackpressurePolicy) -> Self {
        let connectors = Arc::new(ConnectorManager::new());
        Self {
            rules: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            input: BoundedEventInput::new(queue_capacity, policy),
            connectors: connectors.clone(),
            flush_ctx: Arc::new(FlushContext {
                connectors,
                broker_sink: RwLock::new(None),
            }),
            window_workers: RwLock::new(HashMap::new()),
        }
    }

    /// Bounded ingress queue for flood protection at outer boundaries.
    pub fn input(&self) -> &Arc<BoundedEventInput> {
        &self.input
    }

    /// Live outbound connectors addressable by `ForwardConnector` actions.
    pub fn connectors(&self) -> &Arc<ConnectorManager> {
        &self.connectors
    }

    /// Install (or replace) the broker sink used by window-flush
    /// republish actions. Called once by the node after the shared sink
    /// exists; the inline stateless path keeps taking its sink per call.
    pub fn set_broker_sink(&self, sink: Arc<dyn BrokerSink>) {
        *self.flush_ctx.broker_sink.write() = Some(sink);
    }

    /// The currently installed flush sink, if any.
    pub fn broker_sink(&self) -> Option<Arc<dyn BrokerSink>> {
        self.flush_ctx.broker_sink.read().clone()
    }

    /// Live window worker count (observability/testing hook).
    pub fn window_worker_count(&self) -> usize {
        self.window_workers.read().len()
    }

    /// Build and store a rule, assigning its id (`rule-<n>`).
    /// Callers pass already-validated types; fallible parsing
    /// ([`TopicFilter::new`], [`Topic::new`]) happens at the API boundary.
    /// A present `sql_query` is parsed immediately: invalid SQL fails
    /// creation with [`RuleEngineError::InvalidRule`] so a broken rule
    /// can never go live.
    pub fn create_rule(
        &self,
        name: String,
        topic_filter: TopicFilter,
        sql_query: Option<String>,
        enabled: bool,
        mut actions: Vec<RuleAction>,
    ) -> Result<Rule, RuleEngineError> {
        // The upstream parser only accepts bare-word stream names after
        // FROM, while MQTT rules naturally reference quoted topic filters
        // (`FROM "sensors/+"`). Per-record evaluation keys off the rule's
        // `topic_filter` and never reads `stmt.from`, so the target is
        // normalized to a dummy identifier before parsing. The original
        // SQL string is preserved verbatim on the rule.
        //
        // A trailing `INTO connector("<id>")` clause desugars to an
        // equivalent `ForwardConnector` action (deduped): the streaming
        // bridge to external sinks without a separate code path. The
        // stored `sql_query` keeps the original text for display.
        let stripped_sql = match &sql_query {
            Some(sql) => {
                let (stripped, into_connector) = split_into_connector(sql)?;
                if let Some(connector_id) = into_connector {
                    let already = actions.iter().any(|action| {
                        matches!(action, RuleAction::ForwardConnector { connector_id: id } if id == &connector_id)
                    });
                    if !already {
                        actions.push(RuleAction::ForwardConnector { connector_id });
                    }
                }
                Some(stripped)
            }
            None => None,
        };
        let parsed_query = match &stripped_sql {
            Some(sql) => {
                let normalized = normalize_from_target(sql);
                let stmt = rekuiper_sql::Parser::new(&normalized)
                    .parse_select()
                    .map_err(|e| RuleEngineError::InvalidRule(format!("invalid sql_query: {e}")))?;
                Some(stmt)
            }
            None => None,
        };
        let id = format!("rule-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        let tier = match &parsed_query {
            Some(stmt) if stmt.window.is_some() => RuleTier::Enterprise,
            _ => RuleTier::Community,
        };
        let rule = Rule {
            id: id.clone(),
            name,
            topic_filter,
            sql_query,
            parsed_query,
            tier,
            enabled,
            actions,
        };
        self.rules.write().insert(id.clone(), rule.clone());
        // Eager worker start when a runtime is available; otherwise the
        // first matching ingress spawns it lazily (see dispatch_ingress).
        if tier == RuleTier::Enterprise {
            self.ensure_worker(&rule);
        }
        Ok(rule)
    }

    pub fn get_rule(&self, id: &str) -> Option<Rule> {
        self.rules.read().get(id).cloned()
    }

    pub fn list_rules(&self) -> Vec<Rule> {
        let mut rules: Vec<Rule> = self.rules.read().values().cloned().collect();
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        rules
    }

    pub fn remove_rule(&self, id: &str) -> bool {
        // Abort the window worker first so no orphan task survives its rule.
        if let Some(worker) = self.window_workers.write().remove(id) {
            worker.handle.abort();
        }
        self.rules.write().remove(id).is_some()
    }

    /// Route one matching record into an Enterprise window worker: parse
    /// the JSON payload, evaluate the rule WHERE clause, and push passing
    /// records into the worker channel. Lazily spawns a missing worker
    /// (creation outside a runtime defers it to this point).
    fn dispatch_windowed(&self, rule: &Rule, topic: &Topic, payload: &Bytes) {
        let stmt = match rule.parsed_query.as_ref() {
            Some(stmt) => stmt,
            None => return,
        };
        let record: HashMap<String, serde_json::Value> =
            match serde_json::from_slice(payload) {
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
        let workers = self.window_workers.read();
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
    /// Tokio runtime (returns silently without one; dispatch retries).
    fn ensure_worker(&self, rule: &Rule) {
        let window = match rule
            .parsed_query
            .as_ref()
            .and_then(|stmt| stmt.window.clone())
        {
            Some(window) => window,
            None => return,
        };
        if self.window_workers.read().contains_key(&rule.id) {
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
        let (tx, rx) = mpsc::channel(WINDOW_CHANNEL_DEPTH);
        let stmt = match rule.parsed_query.clone() {
            Some(stmt) => stmt,
            None => return,
        };
        let worker = WindowWorker {
            tx,
            handle: runtime.spawn(window_worker_loop(
                rule.id.clone(),
                stmt,
                rule.actions.clone(),
                self.flush_ctx.clone(),
                rx,
                window,
            )),
        };
        self.window_workers
            .write()
            .insert(rule.id.clone(), worker);
    }

    /// Execute every enabled rule whose filter matches `topic`.
    /// Delivery QoS per republish is `min(ingress QoS, action QoS)` so a
    /// rule can never upgrade delivery guarantees. Rules carrying SQL
    /// first run the payload through `rekuiper-sql`: non-JSON or
    /// non-object payloads cannot be evaluated and skip the rule, a false
    /// WHERE skips its actions, and SELECT projection replaces the bytes
    /// forwarded to the sink. Sink failures are logged; remaining actions
    /// still run. Returns the number of rules that matched (for the
    /// `indramqtt_rules_executed_total` counter).
    ///
    /// Enterprise window rules never execute inline: matching records
    /// passing the WHERE clause are pushed to the rule's background
    /// worker instead (still counted as matched).
    pub async fn dispatch_ingress(
        &self,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
        broker_sink: &Arc<dyn BrokerSink>,
    ) -> usize {
        // Snapshot matching rules so the sink (which may touch the router,
        // never this map) runs without holding the lock.
        let matched: Vec<Rule> = {
            let rules = self.rules.read();
            rules
                .values()
                .filter(|rule| rule.enabled && rule.topic_filter.matches(topic))
                .cloned()
                .collect()
        };
        for rule in &matched {
            if rule.tier == RuleTier::Enterprise
                && rule.parsed_query.as_ref().is_some_and(|stmt| stmt.window.is_some())
            {
                self.dispatch_windowed(&rule, topic, payload);
                continue;
            }
            let Some(data) = apply_sql(&rule.parsed_query, payload, &rule.id) else {
                continue;
            };
            run_actions(
                &rule.id,
                &rule.actions,
                topic,
                data,
                qos,
                &self.connectors,
                Some(broker_sink),
            )
            .await;
        }
        matched.len()
    }
}

/// Execute one rule's actions for a single output row. Shared by the
/// inline stateless path and window flushes. `qos_cap` floors delivery:
/// the inline path passes the ingress QoS (`min(action, ingress)`), the
/// flush path passes [`QoS::ExactlyOnce`] so the action QoS applies
/// verbatim. A missing broker sink drops republish actions with a
/// warning instead of panicking.
#[allow(clippy::too_many_arguments)]
async fn run_actions(
    rule_id: &str,
    actions: &[RuleAction],
    topic: &Topic,
    payload: Bytes,
    qos_cap: QoS,
    connectors: &Arc<ConnectorManager>,
    broker_sink: Option<&Arc<dyn BrokerSink>>,
) {
    for action in actions {
        match action {
            RuleAction::Republish {
                topic: dst,
                qos: action_qos,
            } => {
                let effective = std::cmp::min(*action_qos, qos_cap);
                match broker_sink {
                    Some(sink) => {
                        if let Err(e) = sink
                            .publish(dst.clone(), payload.clone(), effective, false)
                            .await
                        {
                            tracing::warn!(
                                rule_id = %rule_id,
                                error = %e,
                                "Rule republish failed; continuing with remaining actions"
                            );
                        }
                    }
                    None => {
                        tracing::warn!(
                            rule_id = %rule_id,
                            "no broker sink configured; republish dropped"
                        );
                    }
                }
            }
            RuleAction::Log => {
                tracing::info!(
                    rule_id = %rule_id,
                    topic = %topic,
                    "Rule matched ingress event"
                );
            }
            RuleAction::ForwardConnector { connector_id } => {
                if let Err(e) = connectors
                    .send(connector_id, topic, &payload, qos_cap)
                    .await
                {
                    tracing::warn!(
                        rule_id = %rule_id,
                        connector = %connector_id,
                        error = %e,
                        "Rule connector forward failed; continuing with remaining actions"
                    );
                }
            }
        }
    }
}

/// Background aggregation loop for one Enterprise window rule. Time
/// windows tick; count windows flush on arrivals; sliding windows
/// aggregate on every arrival. An empty window never dispatches.
async fn window_worker_loop(
    rule_id: String,
    stmt: SelectStmt,
    actions: Vec<RuleAction>,
    flush_ctx: Arc<FlushContext>,
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
                        flush_window(&rule_id, &stmt, &actions, batch, window_start, end, &flush_ctx).await;
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
                    flush_window(&rule_id, &stmt, &actions, batch, start, end, &flush_ctx).await;
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
                            &actions,
                            batch,
                            cutoff,
                            end,
                            &flush_ctx,
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
                while buffer.front().map(|r| r.arrived_ms < cutoff).unwrap_or(false) {
                    buffer.pop_front();
                }
                // Aggregate the trailing window on every arrival.
                let batch: Vec<TimedRecord> = buffer.iter().cloned().collect();
                flush_window(&rule_id, &stmt, &actions, batch, cutoff, end, &flush_ctx).await;
            }
        }
    }
}

/// Flush one closed window: inject `__window_start__`,
/// `__window_end__`, `window_start`, `window_end` epoch millis into every
/// record (so `window_start()`/`window_end()` resolve), partition by
/// `GROUP BY` when present, evaluate aggregates per partition, and
/// dispatch each resulting row through the rule actions. Empty windows
/// and fully-having-filtered windows dispatch nothing. Each row routes
/// with its partition's first record topic.
async fn flush_window(
    rule_id: &str,
    stmt: &SelectStmt,
    actions: &[RuleAction],
    batch: Vec<TimedRecord>,
    window_start_ms: u64,
    window_end_ms: u64,
    flush_ctx: &FlushContext,
) {
    if batch.is_empty() {
        return;
    }
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
    // The sink snapshot is shared across this flush's rows.
    let sink = flush_ctx.broker_sink.read().clone();
    for (topic, row) in aggregate_partitioned(stmt, records) {
        let object: serde_json::Map<String, serde_json::Value> =
            row.into_iter().collect();
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
        run_actions(
            rule_id,
            actions,
            &topic,
            bytes,
            QoS::ExactlyOnce,
            &flush_ctx.connectors,
            sink.as_ref(),
        )
        .await;
    }
}

/// Partition records by `GROUP BY` expressions and evaluate one
/// aggregate row per partition (first-seen group order). Without
/// `GROUP BY`, the whole batch is a single partition. Used by window
/// flushes and the batch dry-run tester alike so both agree.
fn aggregate_partitioned(
    stmt: &SelectStmt,
    records: Vec<(Topic, HashMap<String, serde_json::Value>)>,
) -> Vec<(Topic, HashMap<String, serde_json::Value>)> {
    if records.is_empty() {
        return Vec::new();
    }
    if stmt.group_by.is_empty() {
        let topic = records[0].0.clone();
        let maps: Vec<HashMap<String, serde_json::Value>> =
            records.into_iter().map(|(_, map)| map).collect();
        return Evaluator::eval_aggregate(stmt, &maps)
            .map(|row| vec![(topic, row)])
            .unwrap_or_default();
    }
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, (Topic, Vec<HashMap<String, serde_json::Value>>)> =
        HashMap::new();
    for (topic, map) in records {
        let key = group_key(&stmt.group_by, &map);
        let entry = groups.entry(key.clone()).or_insert_with(|| {
            order.push(key);
            (topic, Vec::new())
        });
        entry.1.push(map);
    }
    let mut out = Vec::new();
    for key in order {
        let (topic, maps) = groups.remove(&key).expect("group just inserted");
        if let Some(row) = Evaluator::eval_aggregate(stmt, &maps) {
            out.push((topic, row));
        }
    }
    out
}

/// Canonical group key: type-tagged so `1`, `"1"` and `true` never
/// collide across JSON types.
fn group_key(
    exprs: &[rekuiper_sql::Expr],
    record: &HashMap<String, serde_json::Value>,
) -> String {
    exprs
        .iter()
        .map(|expr| match Evaluator::eval_val(expr, record) {
            serde_json::Value::Null => "null".to_string(),
            serde_json::Value::Bool(value) => format!("b:{value}"),
            serde_json::Value::Number(value) => format!("n:{value}"),
            serde_json::Value::String(value) => format!("s:{value}"),
            other => format!("j:{other}"),
        })
        .collect::<Vec<_>>()
        .join("\x1f")
}

/// Replace the stream reference after the first top-level FROM with a
/// dummy identifier.
///
/// `rekuiper-sql` tokenizes the FROM target as a bare word, but MQTT
/// rules name quoted topic filters (`FROM "sensors/+"`, `FROM a/#`).
/// Rule dispatch matches on `topic_filter` and `eval_select` never reads
/// `stmt.from`, so the target is semantically inert here. A field
/// literally named `from` is not supported (creation fails loudly rather
/// than misparsing silently only if the rewrite breaks the statement).
fn normalize_from_target(sql: &str) -> String {
    let chars: Vec<(usize, char)> = sql.char_indices().collect();
    let n = chars.len();
    let is_word_char = |c: char| c.is_alphanumeric() || c == '_';

    let mut ci = 0;
    while ci < n {
        let (b, c) = chars[ci];
        let is_from = (c == 'f' || c == 'F')
            && sql.len() - b >= 4
            && sql[b..b + 4].eq_ignore_ascii_case("from")
            && (b == 0 || !is_word_char(sql[..b].chars().next_back().unwrap_or(' ')))
            && (b + 4 >= sql.len()
                || !is_word_char(sql[b + 4..].chars().next().unwrap_or(' ')));
        if !is_from {
            ci += 1;
            continue;
        }
        // Skip whitespace after FROM.
        let mut cj = ci + 4;
        while cj < n && chars[cj].1.is_whitespace() {
            cj += 1;
        }
        if cj >= n {
            return sql.to_string();
        }
        let jb = chars[cj].0;
        let kb = {
            let q = chars[cj].1;
            if q == '"' || q == '\'' || q == '`' {
                let mut ck = cj + 1;
                while ck < n && chars[ck].1 != q {
                    ck += 1;
                }
                if ck >= n {
                    return sql.to_string();
                }
                chars[ck].0 + q.len_utf8()
            } else {
                let mut ck = cj;
                while ck < n {
                    let ch = chars[ck].1;
                    if ch.is_whitespace() || matches!(ch, ';' | ',' | '(' | ')') {
                        break;
                    }
                    ck += 1;
                }
                if ck < n {
                    chars[ck].0
                } else {
                    sql.len()
                }
            }
        };
        return format!("{}stream{}", &sql[..jb], &sql[kb..]);
    }
    sql.to_string()
}

/// Dry-run SQL evaluation for the management console's payload tester.
///
/// Parses `sql` (if any), checks `topic_filter` coverage when given, and
/// evaluates WHERE + SELECT over a JSON `payload`. Returns
/// `(matched, projected)`: `projected` is `Some` with the (possibly
/// projected) value on match and `None` when the predicate is false or
/// the payload is not a JSON object. Invalid SQL, topics, or filters
/// fail with a message.
pub fn try_evaluate(
    sql: Option<&str>,
    topic_filter: Option<&str>,
    topic: &str,
    payload: &serde_json::Value,
) -> Result<(bool, Option<serde_json::Value>), String> {
    let probe = Topic::new(topic).map_err(|e| e.to_string())?;
    if let Some(filter) = topic_filter {
        if !filter.trim().is_empty() {
            let parsed =
                TopicFilter::new(filter).map_err(|e| format!("invalid topic_filter: {e}"))?;
            if !parsed.matches(&probe) {
                return Ok((false, None));
            }
        }
    }
    let stmt = match sql {
        Some(sql) if !sql.trim().is_empty() => {
            let normalized = normalize_from_target(sql);
            Some(
                rekuiper_sql::Parser::new(&normalized)
                    .parse_select()
                    .map_err(|e| format!("invalid sql_query: {e}"))?,
            )
        }
        _ => None,
    };
    match payload {
        serde_json::Value::Array(elements) => {
            // Batch dry-run: multi-event aggregation over the object
            // elements (non-objects skipped), one row per group.
            let records: Vec<(Topic, HashMap<String, serde_json::Value>)> = elements
                .iter()
                .filter_map(|element| match element {
                    serde_json::Value::Object(map) => Some((
                        probe.clone(),
                        map.clone().into_iter().collect(),
                    )),
                    _ => None,
                })
                .collect();
            if records.is_empty() {
                return Ok((false, None));
            }
            match stmt {
                None => {
                    // No SQL: the batch passes through as given.
                    Ok((true, Some(payload.clone())))
                }
                Some(stmt) => {
                    let rows: Vec<serde_json::Value> = aggregate_partitioned(&stmt, records)
                        .into_iter()
                        .map(|(_, row)| {
                            serde_json::Value::Object(
                                row.into_iter().collect(),
                            )
                        })
                        .collect();
                    if rows.is_empty() {
                        Ok((false, None))
                    } else {
                        Ok((true, Some(serde_json::Value::Array(rows))))
                    }
                }
            }
        }
        serde_json::Value::Object(map) => {
            let record: HashMap<String, serde_json::Value> =
                map.clone().into_iter().collect();
            match stmt {
                None => Ok((true, Some(payload.clone()))),
                Some(stmt) => match Evaluator::eval_select(&stmt, &record) {
                    Some(projected) => {
                        let object: serde_json::Map<String, serde_json::Value> =
                            projected.into_iter().collect();
                        Ok((true, Some(serde_json::Value::Object(object))))
                    }
                    None => Ok((false, None)),
                },
            }
        }
        _ => Ok((false, None)),
    }
}

/// Split a trailing `INTO connector("<id>")` clause off a rule SQL
/// statement, returning `(statement_without_into, connector_id)`.
///
/// The scan is top-level only (parentheses and quoted strings are
/// skipped), case-insensitive, and strict: a malformed INTO fails rule
/// creation instead of silently changing routing. A field literally
/// named `into` is unsupported (creation fails loudly in that case).
fn split_into_connector(sql: &str) -> Result<(String, Option<String>), RuleEngineError> {
    fn invalid(reason: impl Into<String>) -> RuleEngineError {
        RuleEngineError::InvalidRule(format!("invalid INTO clause: {}", reason.into()))
    }
    let chars: Vec<(usize, char)> = sql.char_indices().collect();
    let n = chars.len();
    let is_word = |c: char| c.is_alphanumeric() || c == '_';

    let mut i = 0;
    let mut depth = 0u32;
    let mut in_string: Option<char> = None;
    while i < n {
        let (b, c) = chars[i];
        if let Some(quote) = in_string {
            if c == quote {
                in_string = None;
            }
            i += 1;
            continue;
        }
        match c {
            '"' | '\'' | '`' => {
                in_string = Some(c);
                i += 1;
            }
            '(' => {
                depth += 1;
                i += 1;
            }
            ')' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ => {
                let is_into = depth == 0
                    && (c == 'i' || c == 'I')
                    && sql.len() - b >= 4
                    && sql[b..b + 4].eq_ignore_ascii_case("into")
                    && (b == 0 || !is_word(sql[..b].chars().next_back().unwrap_or(' ')))
                    && (b + 4 >= sql.len()
                        || !is_word(sql[b + 4..].chars().next().unwrap_or(' ')));
                if !is_into {
                    i += 1;
                    continue;
                }
                let mut j = i + 4;
                while j < n && chars[j].1.is_whitespace() {
                    j += 1;
                }
                let word_start = j;
                while j < n && (chars[j].1.is_alphanumeric() || chars[j].1 == '_') {
                    j += 1;
                }
                let word: String = chars[word_start..j].iter().map(|(_, c)| *c).collect();
                if !word.eq_ignore_ascii_case("connector") {
                    return Err(invalid("INTO must target connector(\"<id>\")"));
                }
                while j < n && chars[j].1.is_whitespace() {
                    j += 1;
                }
                if j >= n || chars[j].1 != '(' {
                    return Err(invalid("expected '(' after connector"));
                }
                j += 1;
                while j < n && chars[j].1.is_whitespace() {
                    j += 1;
                }
                if j >= n || !matches!(chars[j].1, '"' | '\'') {
                    return Err(invalid("connector id must be quoted"));
                }
                let quote = chars[j].1;
                j += 1;
                let id_start = j;
                while j < n && chars[j].1 != quote {
                    j += 1;
                }
                if j >= n {
                    return Err(invalid("unterminated connector id"));
                }
                let id: String = chars[id_start..j].iter().map(|(_, c)| *c).collect();
                j += 1;
                while j < n && chars[j].1.is_whitespace() {
                    j += 1;
                }
                if j >= n || chars[j].1 != ')' {
                    return Err(invalid("expected ')' after connector id"));
                }
                j += 1;
                if id.is_empty() {
                    return Err(invalid("connector id must not be empty"));
                }
                let tail: String = chars[j..].iter().map(|(_, c)| *c).collect();
                let tail_trimmed = tail.trim().trim_end_matches(';').trim_end();
                if !tail_trimmed.is_empty() {
                    return Err(invalid("unexpected trailing input after ')'"));
                }
                let stripped = sql[..b].trim_end().to_string();
                return Ok((stripped, Some(id)));
            }
        }
    }
    Ok((sql.to_string(), None))
}

/// Run one ingress payload through an optional parsed query.
///
/// Returns the bytes to forward: the raw payload when no SQL is present,
/// the projected JSON when evaluation succeeds, or `None` to skip the
/// rule (WHERE false, non-JSON/non-object payload, serialization
/// failure). Never panics on attacker-controlled bytes.
fn apply_sql(
    parsed: &Option<SelectStmt>,
    payload: &Bytes,
    rule_id: &str,
) -> Option<Bytes> {
    let stmt = match parsed {
        None => return Some(payload.clone()),
        Some(stmt) => stmt,
    };
    let record: HashMap<String, serde_json::Value> = match serde_json::from_slice(payload) {
        Ok(serde_json::Value::Object(map)) => map.into_iter().collect(),
        _ => {
            tracing::debug!(
                rule_id = %rule_id,
                "SQL rule skipped: ingress payload is not a JSON object"
            );
            return None;
        }
    };
    match Evaluator::eval_select(stmt, &record) {
        Some(projected) => {
            // serde_json::Map is key-sorted: deterministic wire bytes.
            let object: serde_json::Map<String, serde_json::Value> =
                projected.into_iter().collect();
            match serde_json::to_vec(&serde_json::Value::Object(object)) {
                Ok(bytes) => Some(Bytes::from(bytes)),
                Err(e) => {
                    tracing::warn!(
                        rule_id = %rule_id,
                        error = %e,
                        "SQL rule skipped: projected payload not serializable"
                    );
                    None
                }
            }
        }
        // WHERE predicate false: rule does not fire.
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    struct MockInput {
        policy: BackpressurePolicy,
    }

    #[async_trait]
    impl EventInput for MockInput {
        async fn push(&self, _event: StreamEvent) -> Result<PushOutcome, RuleEngineError> {
            match self.policy {
                BackpressurePolicy::DropNewest => Ok(PushOutcome::Dropped(OverflowReason::DroppedNewest)),
                _ => Ok(PushOutcome::Enqueued),
            }
        }
    }

    #[derive(Debug, Default)]
    struct RecordingSink {
        published: StdMutex<Vec<(Topic, Bytes, QoS, bool)>>,
    }

    #[async_trait]
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

    fn test_event(topic: &str, payload: &'static [u8]) -> StreamEvent {
        StreamEvent::new(Topic::new(topic).unwrap(), Bytes::from_static(payload))
    }

    #[tokio::test]
    async fn test_event_input_mock() {
        let input = MockInput { policy: BackpressurePolicy::DropNewest };
        let event = StreamEvent {
            topic: Topic::new("sensors/temp").unwrap(),
            payload: Bytes::from_static(b"{\"temp\": 23}"),
            timestamp_millis: 1700000000,
            client_id: Some("c1".to_string()),
        };

        let outcome = input.push(event).await.unwrap();
        assert_eq!(outcome, PushOutcome::Dropped(OverflowReason::DroppedNewest));
    }

    #[tokio::test]
    async fn test_rule_republish_executes_on_match() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        engine.create_rule(
            "republish-temp".to_string(),
            TopicFilter::new("sensors/+").unwrap(),
            None,
            true,
            vec![RuleAction::Republish {
                topic: Topic::new("alerts/critical").unwrap(),
                qos: QoS::AtLeastOnce,
            }],
        )
        .expect("rule creates");
        let sink = Arc::new(RecordingSink::default());
        let sink_obj: Arc<dyn BrokerSink> = sink.clone();

        engine
            .dispatch_ingress(
                &Topic::new("sensors/temperature").unwrap(),
                &Bytes::from_static(b"21.5C"),
                QoS::AtMostOnce,
                &sink_obj,
            )
            .await;

        let published = sink
            .published
            .lock()
            .unwrap()
            .iter()
            .map(|(t, p, q, r)| (t.as_str().to_string(), p.clone(), *q, *r))
            .collect::<Vec<_>>();
        // Effective QoS is min(ingress 0, action 1) = 0; retain stays false.
        assert_eq!(
            published,
            vec![("alerts/critical".to_string(), Bytes::from_static(b"21.5C"), QoS::AtMostOnce, false)]
        );
    }

    #[tokio::test]
    async fn test_rule_skips_disabled_and_non_matching() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        engine.create_rule(
            "disabled".to_string(),
            TopicFilter::new("sensors/+").unwrap(),
            None,
            false,
            vec![RuleAction::Log],
        )
        .expect("rule creates");
        engine.create_rule(
            "other-branch".to_string(),
            TopicFilter::new("factory/#").unwrap(),
            None,
            true,
            vec![RuleAction::Republish {
                topic: Topic::new("alerts/other").unwrap(),
                qos: QoS::AtMostOnce,
            }],
        )
        .expect("rule creates");
        let sink = Arc::new(RecordingSink::default());
        let sink_obj: Arc<dyn BrokerSink> = sink.clone();

        engine
            .dispatch_ingress(
                &Topic::new("sensors/temperature").unwrap(),
                &Bytes::from_static(b"21.5C"),
                QoS::AtMostOnce,
                &sink_obj,
            )
            .await;

        assert!(sink.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_rule_crud_lifecycle() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let rule = engine.create_rule(
            "r1".to_string(),
            TopicFilter::new("a/#").unwrap(),
            Some("SELECT * FROM a/#".to_string()),
            true,
            vec![RuleAction::Log],
        )
        .expect("rule creates");
        assert_eq!(rule.id, "rule-1");
        assert!(engine.get_rule("rule-1").is_some());
        assert!(engine.get_rule("rule-999").is_none());
        assert_eq!(engine.list_rules().len(), 1);
        assert!(engine.remove_rule("rule-1"));
        assert!(!engine.remove_rule("rule-1"));
        assert!(engine.list_rules().is_empty());
    }

    #[tokio::test]
    async fn test_drop_oldest_under_saturation() {
        let engine = RuleEngine::new(2, BackpressurePolicy::DropOldest);
        let input = engine.input();
        assert_eq!(input.try_push(test_event("t", b"one")).unwrap(), PushOutcome::Enqueued);
        assert_eq!(input.try_push(test_event("t", b"two")).unwrap(), PushOutcome::Enqueued);
        assert_eq!(
            input.try_push(test_event("t", b"three")).unwrap(),
            PushOutcome::Dropped(OverflowReason::DroppedOldest)
        );

        assert_eq!(input.next_event().await.unwrap().payload, Bytes::from_static(b"two"));
        assert_eq!(input.next_event().await.unwrap().payload, Bytes::from_static(b"three"));
    }

    #[tokio::test]
    async fn test_drop_newest_under_saturation() {
        let engine = RuleEngine::new(2, BackpressurePolicy::DropNewest);
        let input = engine.input();
        assert_eq!(input.try_push(test_event("t", b"one")).unwrap(), PushOutcome::Enqueued);
        assert_eq!(input.try_push(test_event("t", b"two")).unwrap(), PushOutcome::Enqueued);
        assert_eq!(
            input.try_push(test_event("t", b"three")).unwrap(),
            PushOutcome::Dropped(OverflowReason::DroppedNewest)
        );

        assert_eq!(input.next_event().await.unwrap().payload, Bytes::from_static(b"one"));
        assert_eq!(input.next_event().await.unwrap().payload, Bytes::from_static(b"two"));
    }

    #[tokio::test]
    async fn test_block_waits_for_capacity() {
        let engine = RuleEngine::new(1, BackpressurePolicy::Block);
        let input = engine.input();
        assert_eq!(input.try_push(test_event("t", b"one")).unwrap(), PushOutcome::Enqueued);
        // Synchronous callers cannot block: a full buffer reports overflow.
        assert_eq!(
            input.try_push(test_event("t", b"two")).unwrap(),
            PushOutcome::Dropped(OverflowReason::BufferFull)
        );

        // The async push waits until the consumer drains one slot.
        let slow = input.push(test_event("t", b"three"));
        tokio::pin!(slow);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut slow)
                .await
                .is_err(),
            "blocked push must pend while full"
        );
        assert_eq!(input.next_event().await.unwrap().payload, Bytes::from_static(b"one"));
        tokio::time::timeout(std::time::Duration::from_secs(2), slow)
            .await
            .expect("push completes after drain")
            .unwrap();
        assert_eq!(input.next_event().await.unwrap().payload, Bytes::from_static(b"three"));
    }

    #[tokio::test]
    async fn test_reject_and_spill_report_overflow_when_full() {
        for policy in [BackpressurePolicy::RejectPublisher, BackpressurePolicy::SpillToDisk] {
            let engine = RuleEngine::new(1, policy);
            let input = engine.input();
            assert!(input.try_push(test_event("t", b"one")).is_ok());
            assert!(matches!(
                input.try_push(test_event("t", b"two")),
                Err(RuleEngineError::Overflow(OverflowReason::BufferFull))
            ));
        }
    }

    fn sql_rule(
        engine: &RuleEngine,
        sql: &str,
        topic: &str,
    ) -> (Arc<RecordingSink>, Arc<dyn BrokerSink>) {
        engine
            .create_rule(
                "sql-rule".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(sql.to_string()),
                true,
                vec![RuleAction::Republish {
                    topic: Topic::new(topic).unwrap(),
                    qos: QoS::AtMostOnce,
                }],
            )
            .expect("SQL rule creates");
        let sink = Arc::new(RecordingSink::default());
        let sink_obj: Arc<dyn BrokerSink> = sink.clone();
        (sink, sink_obj)
    }

    fn published_json(sink: &RecordingSink) -> Vec<serde_json::Value> {
        sink.published
            .lock()
            .unwrap()
            .iter()
            .map(|(_, payload, _, _)| {
                serde_json::from_slice(payload).expect("sink payload is JSON")
            })
            .collect()
    }

    #[tokio::test]
    async fn test_sql_where_filters_non_matching_messages() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let (sink, sink_obj) = sql_rule(
            &engine,
            r#"SELECT * FROM "sensors/+" WHERE temperature > 50.0"#,
            "alerts/hot",
        );
        let topic = Topic::new("sensors/temperature").unwrap();

        // Below threshold: predicate false, no action fires.
        engine
            .dispatch_ingress(
                &topic,
                &Bytes::from_static(br#"{ "temperature": 25.0 }"#),
                QoS::AtMostOnce,
                &sink_obj,
            )
            .await;
        assert!(sink.published.lock().unwrap().is_empty());

        // Above threshold: full record passes through SELECT *.
        engine
            .dispatch_ingress(
                &topic,
                &Bytes::from_static(br#"{ "temperature": 65.0, "unit": "C" }"#),
                QoS::AtMostOnce,
                &sink_obj,
            )
            .await;
        assert_eq!(
            published_json(&sink),
            vec![serde_json::json!({ "temperature": 65.0, "unit": "C" })]
        );
    }

    #[tokio::test]
    async fn test_sql_select_projects_fields() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let (sink, sink_obj) = sql_rule(
            &engine,
            r#"SELECT temperature FROM "sensors/+" WHERE temperature > 0"#,
            "alerts/projected",
        );

        engine
            .dispatch_ingress(
                &Topic::new("sensors/temperature").unwrap(),
                &Bytes::from_static(
                    br#"{ "temperature": 72.5, "sensor_id": "temp_1", "raw_adc": 1024 }"#,
                ),
                QoS::AtMostOnce,
                &sink_obj,
            )
            .await;

        // Only the projected field survives; secrets never reach the sink.
        assert_eq!(
            published_json(&sink),
            vec![serde_json::json!({ "temperature": 72.5 })]
        );
    }

    #[tokio::test]
    async fn test_sql_skips_non_json_payloads() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let (sink, sink_obj) = sql_rule(
            &engine,
            r#"SELECT * FROM "sensors/+" WHERE temperature > 0"#,
            "alerts/x",
        );
        let topic = Topic::new("sensors/temperature").unwrap();

        for payload in [
            Bytes::from_static(b"not json at all"),
            Bytes::from_static(br#"[1, 2, 3]"#),
            Bytes::from_static(br#"42"#),
        ] {
            engine
                .dispatch_ingress(&topic, &payload, QoS::AtMostOnce, &sink_obj)
                .await;
        }
        assert!(sink.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_invalid_sql_rejected_at_creation() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let err = engine
            .create_rule(
                "broken".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some("SELECT WHERE WHERE".to_string()),
                true,
                vec![RuleAction::Log],
            )
            .expect_err("invalid SQL must fail creation");
        assert!(matches!(err, RuleEngineError::InvalidRule(_)));
        assert!(engine.list_rules().is_empty());
    }

    // ------------------------------------------------------------------
    // INDRA-210: scalar function catalog validation (Community tier).
    // Every rule below is stateless: it must classify Community, spawn
    // no worker, and evaluate inline on the ingress hot path.
    // ------------------------------------------------------------------

    /// Run one stateless SELECT through the real ingress path and return
    /// the projected row.
    async fn project_one(
        sql: &str,
        payload: &'static [u8],
    ) -> serde_json::Value {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let rule = engine
            .create_rule(
                "probe".to_string(),
                TopicFilter::new("t").unwrap(),
                Some(sql.to_string()),
                true,
                vec![RuleAction::Republish {
                    topic: Topic::new("out").unwrap(),
                    qos: QoS::AtMostOnce,
                }],
            )
            .expect("probe rule creates");
        assert_eq!(rule.tier, RuleTier::Community);
        assert_eq!(engine.window_worker_count(), 0);
        let sink = Arc::new(RecordingSink::default());
        let sink_obj: Arc<dyn BrokerSink> = sink.clone();
        engine
            .dispatch_ingress(
                &Topic::new("t").unwrap(),
                &Bytes::from_static(payload),
                QoS::AtMostOnce,
                &sink_obj,
            )
            .await;
        let published = sink.published.lock().unwrap();
        assert_eq!(published.len(), 1, "stateless rule must fire inline");
        serde_json::from_slice(&published[0].1).expect("projected JSON")
    }

    fn num(value: &serde_json::Value, field: &str) -> f64 {
        value
            .get(field)
            .and_then(|v| v.as_f64())
            .unwrap_or_else(|| panic!("numeric field {field}: {value}"))
    }

    #[test]
    fn test_function_catalog_has_185_entries() {
        let catalog = rekuiper_sql::builtin_function_metadata();
        assert_eq!(catalog.len(), 185);
        // Spot-check categories and aggregate flags the engine honors.
        let by_name = |name: &str| {
            catalog
                .iter()
                .find(|meta| meta.name == name)
                .unwrap_or_else(|| panic!("catalog missing {name}"))
        };
        assert!(!by_name("sin").aggregate);
        assert!(!by_name("concat").aggregate);
        assert!(!by_name("coalesce").aggregate);
        assert!(!by_name("window_start").aggregate);
        assert_eq!(by_name("window_start").category, "system");
        assert!(by_name("avg").aggregate);
        assert!(by_name("count").aggregate);
    }

    #[tokio::test]
    async fn test_scalar_trig_identities() {
        let row = project_one(
            r#"SELECT sin(0.0) AS s, cos(0.0) AS c, tan(0.0) AS t FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(num(&row, "s"), 0.0);
        assert_eq!(num(&row, "c"), 1.0);
        assert_eq!(num(&row, "t"), 0.0);

        let row = project_one(
            r#"SELECT asin(0.0) AS a, acos(1.0) AS b, atan(0.0) AS c, atan2(0.0, 1.0) AS d FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(num(&row, "a"), 0.0);
        assert_eq!(num(&row, "b"), 0.0);
        assert_eq!(num(&row, "c"), 0.0);
        assert_eq!(num(&row, "d"), 0.0);

        let row = project_one(
            r#"SELECT sinh(0.0) AS a, cosh(0.0) AS b, tanh(0.0) AS c FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(num(&row, "a"), 0.0);
        assert_eq!(num(&row, "b"), 1.0);
        assert_eq!(num(&row, "c"), 0.0);
    }

    #[tokio::test]
    async fn test_scalar_math_functions() {
        let row = project_one(
            r#"SELECT sqrt(16.0) AS a, power(2.0, 10.0) AS b, pow(3.0, 2.0) AS c, exp(0.0) AS d FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(num(&row, "a"), 4.0);
        assert_eq!(num(&row, "b"), 1024.0);
        assert_eq!(num(&row, "c"), 9.0);
        assert_eq!(num(&row, "d"), 1.0);

        let row = project_one(
            r#"SELECT ln(1.0) AS a, log(10.0, 100.0) AS b, log2(8.0) AS c, log10(1000.0) AS d FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(num(&row, "a"), 0.0);
        assert_eq!(num(&row, "b"), 2.0);
        assert_eq!(num(&row, "c"), 3.0);
        assert_eq!(num(&row, "d"), 3.0);

        let row = project_one(
            r#"SELECT round(2.4) AS a, round(2.567, 2) AS b, ceil(2.1) AS c, floor(2.9) AS d FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(num(&row, "a"), 2.0);
        assert_eq!(num(&row, "b"), 2.57);
        assert_eq!(num(&row, "c"), 3.0);
        assert_eq!(num(&row, "d"), 2.0);

        let row = project_one(
            r#"SELECT abs(-3) AS a, abs(-2.5) AS b, sign(-5) AS c, sign(0) AS d, mod(10, 3) AS e FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(num(&row, "a"), 3.0);
        assert_eq!(num(&row, "b"), 2.5);
        assert_eq!(num(&row, "c"), -1.0);
        assert_eq!(num(&row, "d"), 0.0);
        assert_eq!(num(&row, "e"), 1.0);
    }

    #[tokio::test]
    async fn test_scalar_bitwise_functions() {
        let row = project_one(
            r#"SELECT bitand(6, 3) AS a, bitor(6, 3) AS b, bitxor(6, 3) AS c, bitnot(0) AS d FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(num(&row, "a"), 2.0);
        assert_eq!(num(&row, "b"), 7.0);
        assert_eq!(num(&row, "c"), 5.0);
        assert_eq!(num(&row, "d"), -1.0);
    }

    #[tokio::test]
    async fn test_scalar_string_functions() {
        let row = project_one(
            r#"SELECT concat('a', 'b', 'c') AS a, lower('AbC') AS b, upper('AbC') AS c, length('hello') AS d FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(row["a"], serde_json::json!("abc"));
        assert_eq!(row["b"], serde_json::json!("abc"));
        assert_eq!(row["c"], serde_json::json!("ABC"));
        assert_eq!(num(&row, "d"), 5.0);

        let row = project_one(
            r#"SELECT trim('  x  ') AS a, ltrim('  x  ') AS b, rtrim('  x  ') AS c FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(row["a"], serde_json::json!("x"));
        assert_eq!(row["b"], serde_json::json!("x  "));
        assert_eq!(row["c"], serde_json::json!("  x"));

        let row = project_one(
            r#"SELECT lpad('7', 3, '0') AS a, rpad('7', 3, '0') AS b, replace('aaa', 'a', 'b') AS c FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(row["a"], serde_json::json!("007"));
        assert_eq!(row["b"], serde_json::json!("700"));
        assert_eq!(row["c"], serde_json::json!("bbb"));

        // Default pad character is a space.
        let row = project_one(
            r#"SELECT lpad('7', 3) AS a, rpad('7', 3) AS b FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(row["a"], serde_json::json!("  7"));
        assert_eq!(row["b"], serde_json::json!("7  "));

        let row = project_one(
            r#"SELECT split('a,b,c', ',') AS a, reverse('abc') AS b FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(row["a"], serde_json::json!(["a", "b", "c"]));
        assert_eq!(row["b"], serde_json::json!("cba"));

        let row = project_one(
            r#"SELECT substr('hello', 2, 3) AS a, substring('hello', 2) AS b FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(row["a"], serde_json::json!("ell"));
        assert_eq!(row["b"], serde_json::json!("ello"));

        let row = project_one(
            r#"SELECT startswith('hello', 'he') AS a, endswith('hello', 'lo') AS b FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(row["a"], serde_json::json!(true));
        assert_eq!(row["b"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn test_scalar_datetime_functions() {
        let row = project_one(r#"SELECT now() AS ts FROM s"#, br#"{ "v": 1 }"#).await;
        assert!(
            num(&row, "ts") > 0.0,
            "now() must return a positive epoch millis"
        );

        let row = project_one(
            r#"SELECT format_date(0, '%Y') AS year FROM s"#,
            br#"{ "v": 1 }"#,
        )
        .await;
        assert_eq!(row["year"], serde_json::json!("1970"));
    }

    #[tokio::test]
    async fn test_scalar_case_and_coalesce() {
        let row = project_one(
            r#"SELECT CASE WHEN temperature > 40 THEN 'hot' ELSE 'ok' END AS state FROM s"#,
            br#"{ "temperature": 72.5 }"#,
        )
        .await;
        assert_eq!(row["state"], serde_json::json!("hot"));

        let row = project_one(
            r#"SELECT CASE WHEN temperature > 40 THEN 'hot' ELSE 'ok' END AS state FROM s"#,
            br#"{ "temperature": 20.0 }"#,
        )
        .await;
        assert_eq!(row["state"], serde_json::json!("ok"));

        let row = project_one(
            r#"SELECT coalesce(missing, 42) AS v FROM s"#,
            br#"{ "other": 1 }"#,
        )
        .await;
        assert_eq!(num(&row, "v"), 42.0);
    }

    #[test]
    fn test_normalize_from_target_vectors() {
        assert_eq!(
            normalize_from_target(r#"SELECT * FROM "sensors/+" WHERE temperature > 50.0"#),
            "SELECT * FROM stream WHERE temperature > 50.0"
        );
        assert_eq!(
            normalize_from_target("SELECT temperature FROM telemetry WHERE temperature > 0"),
            "SELECT temperature FROM stream WHERE temperature > 0"
        );
        assert_eq!(
            normalize_from_target("select a from s"),
            "select a from stream"
        );
        // No FROM at all: untouched (the parser then reports it).
        assert_eq!(normalize_from_target("SELECT 1"), "SELECT 1");
        // Bare topic-style target.
        assert_eq!(
            normalize_from_target("SELECT * FROM a/#"),
            "SELECT * FROM stream"
        );
    }

    #[derive(Debug, Default)]
    struct RecordingConnector {
        events: StdMutex<Vec<(String, Vec<u8>, u8)>>,
    }

    #[async_trait]
    impl broker_connectors::Sink for RecordingConnector {
        async fn send(
            &self,
            topic: &Topic,
            payload: &Bytes,
            qos: QoS,
        ) -> Result<(), broker_connectors::ConnectorError> {
            self.events.lock().unwrap().push((
                topic.as_str().to_string(),
                payload.to_vec(),
                u8::from(qos),
            ));
            Ok(())
        }

        fn kind(&self) -> &'static str {
            "test"
        }
    }

    #[tokio::test]
    async fn test_forward_connector_receives_projected_payload() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let recorder: Arc<RecordingConnector> = Arc::new(RecordingConnector::default());
        engine
            .connectors()
            .register("webhook", recorder.clone());

        engine
            .create_rule(
                "to-webhook".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(r#"SELECT temperature FROM "sensors/+" WHERE temperature > 0"#.to_string()),
                true,
                vec![RuleAction::ForwardConnector {
                    connector_id: "webhook".to_string(),
                }],
            )
            .expect("rule creates");
        let mqtt_sink = Arc::new(RecordingSink::default());
        let sink: Arc<dyn BrokerSink> = mqtt_sink.clone();

        engine
            .dispatch_ingress(
                &Topic::new("sensors/temperature").unwrap(),
                &Bytes::from_static(
                    br#"{ "temperature": 72.5, "secret": "hide_me" }"#,
                ),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        // Connector got the projected payload (secret stripped), the MQTT
        // sink got nothing (no Republish action on this rule).
        let events = recorder.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "sensors/temperature");
        let body: serde_json::Value =
            serde_json::from_slice(&events[0].1).expect("connector payload is JSON");
        assert_eq!(body, serde_json::json!({ "temperature": 72.5 }));
        assert!(mqtt_sink.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_forward_connector_missing_id_is_tolerated() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        engine
            .create_rule(
                "to-nowhere".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                None,
                true,
                vec![
                    RuleAction::ForwardConnector {
                        connector_id: "ghost".to_string(),
                    },
                    RuleAction::Log,
                ],
            )
            .expect("rule creates");
        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());

        // Unknown connector id: warned, skipped, remaining actions run.
        engine
            .dispatch_ingress(
                &Topic::new("sensors/temperature").unwrap(),
                &Bytes::from_static(b"21.5C"),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
    }

    // ------------------------------------------------------------------
    // INDRA-211/212/213: tiering, window workers, aggregations, flush.
    // ------------------------------------------------------------------

    /// Build an engine with one rule; returns engine, sink handle, and
    /// the stored rule (for tier assertions). Mirrors production wiring:
    /// the same sink serves inline dispatch and window flushes.
    fn window_rule(
        sql: Option<&str>,
        actions: Vec<RuleAction>,
    ) -> (RuleEngine, Arc<RecordingSink>, Arc<dyn BrokerSink>, Rule) {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
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
            .map(|(_, payload, _, _)| {
                serde_json::from_slice(payload).expect("row is JSON")
            })
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

    #[test]
    fn test_tier_classification() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let mk = |sql: Option<&str>| {
            engine
                .create_rule(
                    "t".to_string(),
                    TopicFilter::new("sensors/+").unwrap(),
                    sql.map(str::to_string),
                    true,
                    vec![RuleAction::Log],
                )
                .expect("rule creates")
                .tier
        };
        // No SQL, plain SELECT, and GROUP BY without a window: Community.
        assert_eq!(mk(None), RuleTier::Community);
        assert_eq!(
            mk(Some(r#"SELECT temperature FROM "sensors/+""#)),
            RuleTier::Community
        );
        assert_eq!(
            mk(Some(
                r#"SELECT sensor_id, avg(temperature) AS a FROM "sensors/+" GROUP BY sensor_id"#
            )),
            RuleTier::Community
        );
        // Any window clause makes the rule Enterprise — even disabled.
        assert_eq!(
            mk(Some(
                r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY TUMBLINGWINDOW(ss, 10)"#
            )),
            RuleTier::Enterprise
        );
        let disabled = engine
            .create_rule(
                "d".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY COUNTWINDOW(5)"#
                        .to_string(),
                ),
                false,
                vec![RuleAction::Log],
            )
            .expect("rule creates");
        assert_eq!(disabled.tier, RuleTier::Enterprise);
    }

    #[test]
    fn test_window_rule_created_outside_runtime_defers_worker() {
        // Plain #[test]: no Tokio runtime, so eager spawn is impossible.
        // Creation still succeeds; the worker arrives on first ingress.
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let rule = engine
            .create_rule(
                "w".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY TUMBLINGWINDOW(ss, 10)"#
                        .to_string(),
                ),
                true,
                vec![RuleAction::Log],
            )
            .expect("rule creates");
        assert_eq!(rule.tier, RuleTier::Enterprise);
        assert_eq!(engine.window_worker_count(), 0);
        assert!(engine.get_rule(&rule.id).is_some());
    }

    #[tokio::test]
    async fn test_window_worker_lifecycle() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
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
        assert!(engine.remove_rule(&rule.id));
        assert_eq!(engine.window_worker_count(), 0);
        assert!(!engine.remove_rule(&rule.id));
        assert!(!engine.remove_rule("rule-999"));
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

        ingress(&engine, &sink_obj, br#"{ "sensor_id": "a", "temperature": 10.0 }"#).await;
        ingress(&engine, &sink_obj, br#"{ "sensor_id": "b", "temperature": 30.0 }"#).await;
        ingress(&engine, &sink_obj, br#"{ "sensor_id": "a", "temperature": 20.0 }"#).await;
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
            Some(
                r#"SELECT avg(temperature) AS a FROM "sensors/+" GROUP BY SLIDINGWINDOW(ss, 60)"#,
            ),
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

        #[async_trait]
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

        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
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
            if probe.events.lock().unwrap().len() >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let events = probe.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["a"], serde_json::json!(10.0));
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
        assert!(engine.remove_rule(&rule.id));
        assert_eq!(engine.window_worker_count(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            published_rows(&sink).is_empty(),
            "aborted worker must not deliver"
        );
    }

    #[test]
    fn test_try_evaluate_vectors() {        let payload = serde_json::json!({ "temperature": 72.5, "secret": "x" });

        // SQL match with projection.
        let (matched, projected) = try_evaluate(
            Some(r#"SELECT temperature FROM "sensors/+" WHERE temperature > 0"#),
            Some("sensors/+"),
            "sensors/kitchen",
            &payload,
        )
        .expect("evaluates");
        assert!(matched);
        assert_eq!(projected, Some(serde_json::json!({ "temperature": 72.5 })));

        // Predicate false: no match, no projection.
        let (matched, projected) = try_evaluate(
            Some(r#"SELECT * FROM "sensors/+" WHERE temperature > 100.0"#),
            Some("sensors/+"),
            "sensors/kitchen",
            &payload,
        )
        .expect("evaluates");
        assert!(!matched);
        assert_eq!(projected, None);

        // Filter mismatch short-circuits before SQL.
        let (matched, projected) = try_evaluate(
            Some(r#"SELECT * FROM "sensors/+" WHERE temperature > 0"#),
            Some("factory/#"),
            "sensors/kitchen",
            &payload,
        )
        .expect("evaluates");
        assert!(!matched);
        assert_eq!(projected, None);

        // No SQL: raw passthrough on match.
        let (matched, projected) =
            try_evaluate(None, Some("sensors/+"), "sensors/kitchen", &payload)
                .expect("evaluates");
        assert!(matched);
        assert_eq!(projected, Some(payload.clone()));

        // Non-object payloads never match SQL rules.
        let scalar = serde_json::json!(42);
        let (matched, _) = try_evaluate(
            Some(r#"SELECT * FROM "sensors/+" WHERE temperature > 0"#),
            None,
            "sensors/kitchen",
            &scalar,
        )
        .expect("evaluates");
        assert!(!matched);

        // Invalid inputs fail loudly.
        assert!(try_evaluate(Some("SELECT WHERE WHERE"), None, "t", &payload).is_err());
        assert!(try_evaluate(None, Some("a/#/b"), "t", &payload).is_err());
        assert!(try_evaluate(None, None, "", &payload).is_err());
    }

    #[test]
    fn test_split_into_connector_vectors() {
        // No INTO: untouched, no binding.
        let (stripped, bound) =
            split_into_connector(r#"SELECT * FROM "sensors/+" WHERE temperature > 0"#)
                .expect("parses");
        assert_eq!(stripped, r#"SELECT * FROM "sensors/+" WHERE temperature > 0"#);
        assert_eq!(bound, None);

        // Trailing INTO binds the connector and strips cleanly.
        let (stripped, bound) = split_into_connector(
            r#"SELECT temperature FROM "sensors/+" WHERE temperature > 0 INTO connector("kafka-sink-1")"#,
        )
        .expect("parses");
        assert_eq!(
            stripped,
            r#"SELECT temperature FROM "sensors/+" WHERE temperature > 0"#
        );
        assert_eq!(bound, Some("kafka-sink-1".to_string()));

        // Single quotes, extra whitespace, trailing semicolon tolerated.
        let (stripped, bound) = split_into_connector(
            "SELECT a FROM s WHERE v > 1   INTO   connector( 'r1' ) ;",
        )
        .expect("parses");
        assert_eq!(stripped, "SELECT a FROM s WHERE v > 1");
        assert_eq!(bound, Some("r1".to_string()));

        // INTO inside a string literal is data, not a clause.
        let (stripped, bound) =
            split_into_connector(r#"SELECT * FROM s WHERE note = 'INTO the void'"#)
                .expect("parses");
        assert_eq!(bound, None);
        assert!(stripped.contains("INTO the void"));

        // Malformed INTO fails creation loudly.
        for bad in [
            r#"SELECT * FROM s INTO connector()"#,
            r#"SELECT * FROM s INTO connector("unclosed)"#,
            r#"SELECT * FROM s INTO connector"#,
            r#"SELECT * FROM s INTO topic("x")"#,
            r#"SELECT * FROM s INTO connector("x") TRAILING"#,
        ] {
            assert!(
                split_into_connector(bad).is_err(),
                "must reject: {bad}"
            );
        }
    }

    #[tokio::test]
    async fn test_into_connector_desugars_to_forward_action() {
        use broker_connectors::{KafkaSink, KafkaSinkConfig, MemoryKafkaTransport};

        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let transport = Arc::new(MemoryKafkaTransport::new());
        let kafka = Arc::new(
            KafkaSink::new(
                KafkaSinkConfig {
                    bootstrap_servers: "unused:9092".to_string(),
                    topic_template: "out-${topic}".to_string(),
                    partition_key_field: Some("device_id".to_string()),
                    partitions: 4,
                    client_id: "test".to_string(),
                    acks: "1".to_string(),
                    batch_max_records: 100,
                    batch_max_bytes: 1024 * 1024,
                },
                transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("kafka-sink-1", kafka.clone());

        // INTO appends the ForwardConnector action; the original SQL is
        // preserved verbatim on the stored rule.
        let rule = engine
            .create_rule(
                "bridge".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT temperature, device_id FROM "sensors/+" WHERE temperature > 0 INTO connector("kafka-sink-1")"#
                        .to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");
        assert_eq!(
            rule.sql_query.as_deref(),
            Some(r#"SELECT temperature, device_id FROM "sensors/+" WHERE temperature > 0 INTO connector("kafka-sink-1")"#)
        );
        assert!(rule.actions.iter().any(|action| matches!(
            action,
            RuleAction::ForwardConnector { connector_id } if connector_id == "kafka-sink-1"
        )));

        // End to end: ingress MQTT bytes trigger SQL projection into the
        // mock Kafka buffer (no broker anywhere in the loop). Batching
        // holds records until the batch limit or an explicit flush.
        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(
                    br#"{ "temperature": 72.5, "device_id": "d7", "secret": "hide_me" }"#,
                ),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(kafka.buffered_records(), 1);
        kafka.flush().await.expect("flush");

        let records = transport.records_flat();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].topic, "out-sensors/kitchen");
        assert_eq!(records[0].key, Some(Bytes::from_static(b"d7")));
        let body: serde_json::Value =
            serde_json::from_slice(&records[0].value).expect("projected JSON");
        assert_eq!(
            body,
            serde_json::json!({ "temperature": 72.5, "device_id": "d7" })
        );
        let header_map: std::collections::HashMap<&str, &Bytes> = records[0]
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect();
        assert_eq!(
            header_map.get("mqtt.topic"),
            Some(&&Bytes::from_static(b"sensors/kitchen"))
        );

        // Below-threshold ingress fires nothing anywhere.
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(br#"{ "temperature": -5.0, "device_id": "d7" }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(transport.records_flat().len(), 1);
    }

    #[tokio::test]
    async fn test_into_malformed_rejected_at_creation() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let err = engine
            .create_rule(
                "broken-into".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(r#"SELECT * FROM "sensors/+" WHERE temperature > 0 INTO connector()"#.to_string()),
                true,
                vec![],
            )
            .expect_err("malformed INTO must fail creation");
        assert!(matches!(err, RuleEngineError::InvalidRule(_)));
        assert!(engine.list_rules().is_empty());
    }

    /// End to end across two database sinks: one ingress event fans out
    /// through SQL projection into a mock Postgres batch buffer and a
    /// mock Redis stream buffer, with secrets stripped by the SELECT.
    #[tokio::test]
    async fn test_sql_fans_out_to_postgres_and_redis() {
        use broker_connectors::{
            MemoryPgTransport, MemoryRedisTransport, PostgreSqlSink,
            PostgreSqlSinkConfig, RedisCommandKind, RedisSink, RedisSinkConfig,
        };

        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);

        let pg_transport = Arc::new(MemoryPgTransport::new());
        let pg = Arc::new(
            PostgreSqlSink::new(
                PostgreSqlSinkConfig {
                    connection_url: "postgresql://u:p@db/db".to_string(),
                    sql_template: "INSERT INTO device_status (topic, qos, payload) VALUES ($1, $2, $3::jsonb)".to_string(),
                    pool_size: 1,
                    batch_size: 100,
                    batch_timeout_ms: 50,
                },
                pg_transport.clone(),
            )
            .expect("valid pg sink"),
        );
        engine.connectors().register("pg-device-state", pg.clone());

        let redis_transport = Arc::new(MemoryRedisTransport::new());
        let redis = Arc::new(
            RedisSink::new(
                RedisSinkConfig {
                    endpoint: "redis://127.0.0.1:6379".to_string(),
                    command: RedisCommandKind::XAdd {
                        stream_template: "stream:${topic}".to_string(),
                        maxlen: Some(1000),
                    },
                },
                redis_transport.clone(),
            )
            .expect("valid redis sink"),
        );
        engine.connectors().register("redis-device-state", redis);

        engine
            .create_rule(
                "persist-status".to_string(),
                TopicFilter::new("devices/+/status").unwrap(),
                Some(
                    r#"SELECT status, battery FROM "devices/+/status" WHERE battery > 0 INTO connector("pg-device-state")"#
                        .to_string(),
                ),
                true,
                vec![],
            )
            .expect("pg rule creates");
        engine
            .create_rule(
                "stream-status".to_string(),
                TopicFilter::new("devices/+/status").unwrap(),
                Some(
                    r#"SELECT status FROM "devices/+/status" INTO connector("redis-device-state")"#
                        .to_string(),
                ),
                true,
                vec![],
            )
            .expect("redis rule creates");

        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("devices/thermostat/status").unwrap(),
                &Bytes::from_static(
                    br#"{ "status": "online", "battery": 87, "secret": "hide_me" }"#,
                ),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        pg.flush().await.expect("pg flush");

        // Postgres received one projected row: secrets stripped, full
        // topic + qos bound as parameters, never interpolated.
        let batches = pg_transport.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].rows.len(), 1);
        assert_eq!(batches[0].rows[0][0], b"devices/thermostat/status");
        assert_eq!(batches[0].rows[0][1], b"0");
        let stored: serde_json::Value =
            serde_json::from_slice(&batches[0].rows[0][2]).expect("stored JSON");
        assert_eq!(
            stored,
            serde_json::json!({ "status": "online", "battery": 87 })
        );
        assert!(!batches[0].sql.contains("thermostat"), "values stay bound");

        // Redis received one XADD with the projected payload.
        let commands = redis_transport.commands();
        assert_eq!(commands.len(), 1);
        let encoded = String::from_utf8_lossy(&commands[0].encode_resp()).to_string();
        assert!(encoded.contains("stream:devices/thermostat/status"), "stream key");
        assert!(encoded.contains("MAXLEN"), "trim directive");
        assert!(encoded.contains(r#""status":"online""#), "projected payload");
        assert!(!encoded.contains("hide_me"), "secrets never leave the rule");
    }
}
