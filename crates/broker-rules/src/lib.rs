use async_trait::async_trait;
use broker_connectors::ConnectorManager;
use broker_protocol::{QoS, Topic, TopicFilter};
use bytes::Bytes;
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

    /// The in-memory mutation applied but the registry commit or atomic
    /// save failed. Callers map this to 500; it is never silent.
    #[error("cannot persist rules: {0}")]
    Persist(String),
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
    #[serde(skip_serializing)]
    pub matched_cnt: Arc<AtomicU64>,
    #[serde(skip_serializing)]
    pub passed_cnt: Arc<AtomicU64>,
    #[serde(skip_serializing)]
    pub failed_cnt: Arc<AtomicU64>,
    #[serde(skip_serializing)]
    pub actions_total_cnt: Arc<AtomicU64>,
    #[serde(skip_serializing)]
    pub actions_success_cnt: Arc<AtomicU64>,
    #[serde(skip_serializing)]
    pub actions_failed_cnt: Arc<AtomicU64>,
}

/// Per-action outcome counters shared with every `run_actions` call site.
#[derive(Debug, Clone)]
struct ActionCounters {
    total: Arc<AtomicU64>,
    success: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
}

impl ActionCounters {
    fn from_rule(rule: &Rule) -> Self {
        Self {
            total: rule.actions_total_cnt.clone(),
            success: rule.actions_success_cnt.clone(),
            failed: rule.actions_failed_cnt.clone(),
        }
    }
}

/// Throttle state for one (rule id, connector id) pair: when the last
/// forward-failure line was logged and how many failures were suppressed
/// since then.
#[derive(Debug, Clone, Copy)]
struct ThrottleEntry {
    last_logged_ms: u64,
    suppressed: u64,
}

/// Maximum one forward-failure `warn!` per (rule id, connector id) per
/// window; later failures inside the window are only counted.
const FORWARD_FAILURE_LOG_WINDOW_MS: u64 = 10_000;

/// Returns `Some(suppressed)` when the caller must log (first failure, or
/// the window elapsed since the previous line), `None` when the failure
/// must only be counted.
fn forward_failure_should_log(
    throttle: &parking_lot::Mutex<HashMap<(String, String), ThrottleEntry>>,
    rule_id: &str,
    connector_id: &str,
    now_ms: u64,
) -> Option<u64> {
    let mut guard = throttle.lock();
    let key = (rule_id.to_string(), connector_id.to_string());
    match guard.get_mut(&key) {
        None => {
            guard.insert(
                key,
                ThrottleEntry {
                    last_logged_ms: now_ms,
                    suppressed: 0,
                },
            );
            Some(0)
        }
        Some(entry) => {
            if now_ms.saturating_sub(entry.last_logged_ms) >= FORWARD_FAILURE_LOG_WINDOW_MS {
                let suppressed = entry.suppressed;
                entry.last_logged_ms = now_ms;
                entry.suppressed = 0;
                Some(suppressed)
            } else {
                entry.suppressed += 1;
                None
            }
        }
    }
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
    window_channel_depth: usize,
    forward_throttle: Arc<parking_lot::Mutex<HashMap<(String, String), ThrottleEntry>>>,
    /// Kernel config registry receiving every rule mutation (`None` in
    /// unit tests and standalone state, which stay memory-only).
    registry: RwLock<Option<Arc<broker_config::ConfigRegistry>>>,
    /// Serialises export-commit-save so concurrent mutations cannot
    /// interleave into a lost update on disk.
    save_lock: parking_lot::Mutex<()>,
}

/// Shared flush context: what a window worker needs at flush time. The
/// broker sink is installed post-construction via
/// [`RuleEngine::set_broker_sink`] (the engine is built before the node
/// sink exists); connectors are shared with the engine itself.
struct FlushContext {
    connectors: Arc<ConnectorManager>,
    broker_sink: RwLock<Option<Arc<dyn BrokerSink>>>,
    forward_throttle: Arc<parking_lot::Mutex<HashMap<(String, String), ThrottleEntry>>>,
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

/// Default per-rule window worker ingress depth (INDRA-215): large
/// enough for high-scale bursts without drops, still bounded so a
/// stalled worker cannot grow memory without limit. Backpressure stays
/// at the edge input queue; a full worker buffer drops with a warning,
/// never blocks. Override per engine via
/// [`RuleEngine::new_with_window_depth`] or
/// [`RuleEngine::with_window_channel_depth`].
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

impl RuleEngine {
    /// Create an engine with a bounded ingress queue (`capacity` floors at
    /// 1). The queue backs future async ingestion; the hot path calls
    /// [`RuleEngine::dispatch_ingress`] synchronously for determinism.
    /// Window worker channels use [`DEFAULT_WINDOW_CHANNEL_DEPTH`].
    pub fn new(queue_capacity: usize, policy: BackpressurePolicy) -> Self {
        Self::new_with_window_depth(queue_capacity, policy, DEFAULT_WINDOW_CHANNEL_DEPTH)
    }

    /// Create an engine with an explicit per-rule window worker channel
    /// depth (`depth` floors at 1, no ceiling). Use 65,536+ for
    /// high-scale bursts.
    pub fn new_with_window_depth(
        queue_capacity: usize,
        policy: BackpressurePolicy,
        window_channel_depth: usize,
    ) -> Self {
        let connectors = Arc::new(ConnectorManager::new());
        let forward_throttle = Arc::new(parking_lot::Mutex::new(HashMap::new()));
        Self {
            rules: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            input: BoundedEventInput::new(queue_capacity, policy),
            connectors: connectors.clone(),
            flush_ctx: Arc::new(FlushContext {
                connectors,
                broker_sink: RwLock::new(None),
                forward_throttle: forward_throttle.clone(),
            }),
            window_workers: RwLock::new(HashMap::new()),
            window_channel_depth: window_channel_depth.max(1),
            forward_throttle,
            registry: RwLock::new(None),
            save_lock: parking_lot::Mutex::new(()),
        }
    }

    /// Override the window worker channel depth after construction
    /// (floors at 1, no ceiling). Applies to workers spawned from here on.
    pub fn with_window_channel_depth(mut self, depth: usize) -> Self {
        self.window_channel_depth = depth.max(1);
        self
    }

    /// Configured per-rule window worker channel depth.
    pub fn window_channel_depth(&self) -> usize {
        self.window_channel_depth
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
    /// can never go live. The mutation commits the exported
    /// [`broker_config::RulesConf`] root and atomically saves it when a
    /// registry is attached; a save failure is returned and the in-memory
    /// rule stays (commit precedes the atomic save).
    pub fn create_rule(
        &self,
        name: String,
        topic_filter: TopicFilter,
        sql_query: Option<String>,
        enabled: bool,
        actions: Vec<RuleAction>,
    ) -> Result<Rule, RuleEngineError> {
        let id = format!("rule-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        let rule = self.insert_rule_with_id(id, name, topic_filter, sql_query, enabled, actions)?;
        self.persist()?;
        Ok(rule)
    }

    /// Insert a rule under a preserved id (boot replay path). Shares the
    /// same SQL validation as [`RuleEngine::create_rule`]: invalid SQL
    /// fails loudly instead of being skipped. A duplicate id fails
    /// loudly. Advances `next_id` past any numeric `rule-<n>` suffix so
    /// later creates never collide. Does not persist; callers persist
    /// once after bulk loads.
    fn insert_rule_with_id(
        &self,
        id: String,
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
        if self.rules.read().contains_key(&id) {
            return Err(RuleEngineError::InvalidRule(format!(
                "duplicate rule id: {id}"
            )));
        }
        if let Some(suffix) = id.strip_prefix("rule-") {
            if let Ok(n) = suffix.parse::<u64>() {
                self.next_id.fetch_max(n + 1, Ordering::SeqCst);
            }
        }
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
            matched_cnt: Arc::new(AtomicU64::new(0)),
            passed_cnt: Arc::new(AtomicU64::new(0)),
            failed_cnt: Arc::new(AtomicU64::new(0)),
            actions_total_cnt: Arc::new(AtomicU64::new(0)),
            actions_success_cnt: Arc::new(AtomicU64::new(0)),
            actions_failed_cnt: Arc::new(AtomicU64::new(0)),
        };
        self.rules.write().insert(id.clone(), rule.clone());
        // Eager worker start when a runtime is available; otherwise the
        // first matching ingress spawns it lazily (see dispatch_ingress).
        if tier == RuleTier::Enterprise {
            self.ensure_worker(&rule);
        }
        Ok(rule)
    }

    /// Seed from a validated snapshot root. An empty snapshot yields
    /// today's empty behaviour (no rules). Memory-only: mutations are
    /// not persisted.
    ///
    /// Boot replays the snapshot through the same validated create path
    /// as [`RuleEngine::create_rule`]: an invalid topic filter, action,
    /// or SQL fails loudly instead of being skipped silently.
    ///
    /// Rule metric counters (`matched_cnt` etc.) are deliberately NOT
    /// persisted: they are monotonic runtime counters that reset to zero
    /// on every rebuild.
    pub fn from_snapshot(conf: &broker_config::RulesConf) -> Result<Self, RuleEngineError> {
        let engine = Self::new(1024, BackpressurePolicy::DropOldest);
        engine.seed_from_snapshot(conf)?;
        Ok(engine)
    }

    /// Seed from the registry's current snapshot and persist every later
    /// rule mutation back through it. This is the kernel boot path: an
    /// empty snapshot yields today's empty behaviour, and an invalid
    /// stored rule fails boot loudly.
    pub fn from_registry(
        registry: &Arc<broker_config::ConfigRegistry>,
    ) -> Result<Self, RuleEngineError> {
        let engine = Self::from_snapshot(&registry.snapshot().rules)?;
        *engine.registry.write() = Some(Arc::clone(registry));
        Ok(engine)
    }

    /// Attach the registry and replace the current contents with its
    /// snapshot, in place on the same instance. Invalid stored rules
    /// fail loudly; metric counters reset to zero (see
    /// [`RuleEngine::from_snapshot`]).
    pub fn seed_from_registry(
        &self,
        registry: &Arc<broker_config::ConfigRegistry>,
    ) -> Result<(), RuleEngineError> {
        self.seed_from_snapshot(&registry.snapshot().rules)?;
        *self.registry.write() = Some(Arc::clone(registry));
        Ok(())
    }

    /// Replace all rules with the snapshot contents through the validated
    /// create path. Existing window workers are aborted first so no
    /// orphan task survives its rule; `next_id` restarts at 1 and
    /// advances past every restored numeric suffix.
    fn seed_from_snapshot(&self, conf: &broker_config::RulesConf) -> Result<(), RuleEngineError> {
        conf.validate()
            .map_err(|e| RuleEngineError::InvalidRule(format!("invalid rules snapshot: {e}")))?;
        for (_, worker) in self.window_workers.write().drain() {
            worker.handle.abort();
        }
        self.rules.write().clear();
        self.next_id.store(1, Ordering::SeqCst);
        for entry in &conf.rules {
            let topic_filter = TopicFilter::new(&entry.topic_filter).map_err(|e| {
                RuleEngineError::InvalidRule(format!("invalid topic_filter for {}: {e}", entry.id))
            })?;
            let mut actions = Vec::with_capacity(entry.actions.len());
            for action in &entry.actions {
                actions.push(Self::action_from_entry(&entry.id, action)?);
            }
            self.insert_rule_with_id(
                entry.id.clone(),
                entry.name.clone(),
                topic_filter,
                entry.sql_query.clone(),
                entry.enabled,
                actions,
            )?;
        }
        Ok(())
    }

    /// Export the current contents as a validated config root: rules
    /// sorted by id so the persisted file is deterministic, with the
    /// full action list (every variant field, no display coercion).
    /// Metric counters are runtime-only and are never exported.
    fn export_conf(&self) -> broker_config::RulesConf {
        let mut rules: Vec<Rule> = self.rules.read().values().cloned().collect();
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        let entries = rules
            .iter()
            .map(|rule| broker_config::RuleEntry {
                id: rule.id.clone(),
                name: rule.name.clone(),
                topic_filter: rule.topic_filter.as_str().to_string(),
                sql_query: rule.sql_query.clone(),
                enabled: rule.enabled,
                actions: rule.actions.iter().map(Self::action_to_entry).collect(),
            })
            .collect();
        broker_config::RulesConf { rules: entries }
    }

    /// Commit the exported root and atomically save it. A no-op without
    /// a registry; any commit or save failure surfaces as
    /// [`RuleEngineError::Persist`] so callers answer 500 and the loss
    /// is never silent.
    fn persist(&self) -> Result<(), RuleEngineError> {
        let Some(registry) = self.registry.read().clone() else {
            return Ok(());
        };
        let _guard = self.save_lock.lock();
        let conf = self.export_conf();
        registry
            .commit_rules(conf)
            .map_err(|e| RuleEngineError::Persist(e.to_string()))?;
        registry
            .save()
            .map_err(|e| RuleEngineError::Persist(e.to_string()))?;
        Ok(())
    }

    /// Map one live action to its lossless persisted form.
    fn action_to_entry(action: &RuleAction) -> broker_config::RuleActionEntry {
        match action {
            RuleAction::Republish { topic, qos } => broker_config::RuleActionEntry::Republish {
                topic: topic.as_str().to_string(),
                qos: (*qos).into(),
            },
            RuleAction::Log => broker_config::RuleActionEntry::Log,
            RuleAction::ForwardConnector { connector_id } => {
                broker_config::RuleActionEntry::ForwardConnector {
                    connector_id: connector_id.clone(),
                }
            }
        }
    }

    /// Map one persisted action back to its live form through the same
    /// validation the API applies: invalid topics or QoS fail loudly.
    fn action_from_entry(
        rule_id: &str,
        entry: &broker_config::RuleActionEntry,
    ) -> Result<RuleAction, RuleEngineError> {
        match entry {
            broker_config::RuleActionEntry::Republish { topic, qos } => {
                let topic = Topic::new(topic).map_err(|e| {
                    RuleEngineError::InvalidRule(format!(
                        "invalid republish topic for {rule_id}: {e}"
                    ))
                })?;
                let qos = QoS::try_from(*qos).map_err(|e| {
                    RuleEngineError::InvalidRule(format!(
                        "invalid republish qos for {rule_id}: {e}"
                    ))
                })?;
                Ok(RuleAction::Republish { topic, qos })
            }
            broker_config::RuleActionEntry::Log => Ok(RuleAction::Log),
            broker_config::RuleActionEntry::ForwardConnector { connector_id } => {
                if connector_id.trim().is_empty() {
                    return Err(RuleEngineError::InvalidRule(format!(
                        "invalid connector_id for {rule_id}: must not be empty (field `connector_id`)"
                    )));
                }
                Ok(RuleAction::ForwardConnector {
                    connector_id: connector_id.clone(),
                })
            }
        }
    }

    pub fn get_rule(&self, id: &str) -> Option<Rule> {
        self.rules.read().get(id).cloned()
    }

    pub fn list_rules(&self) -> Vec<Rule> {
        let mut rules: Vec<Rule> = self.rules.read().values().cloned().collect();
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        rules
    }

    /// Remove a rule (false when unknown; unknown ids persist nothing).
    /// Persists through the registry when one is attached; a save
    /// failure is returned and the in-memory removal stays (commit
    /// precedes the atomic save).
    pub fn remove_rule(&self, id: &str) -> Result<bool, RuleEngineError> {
        // Abort the window worker first so no orphan task survives its rule.
        if let Some(worker) = self.window_workers.write().remove(id) {
            worker.handle.abort();
        }
        let removed = self.rules.write().remove(id).is_some();
        if removed {
            self.persist()?;
        }
        Ok(removed)
    }

    /// Enable or disable a rule (false when unknown; unknown ids persist
    /// nothing). Persists through the registry when one is attached.
    pub fn set_rule_enabled(&self, id: &str, enabled: bool) -> Result<bool, RuleEngineError> {
        let found = if let Some(rule) = self.rules.write().get_mut(id) {
            rule.enabled = enabled;
            true
        } else {
            false
        };
        if found {
            self.persist()?;
        }
        Ok(found)
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
        let (tx, rx) = mpsc::channel(self.window_channel_depth);
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
                ActionCounters::from_rule(rule),
            )),
        };
        self.window_workers.write().insert(rule.id.clone(), worker);
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
            rule.matched_cnt.fetch_add(1, Ordering::Relaxed);
            if rule.tier == RuleTier::Enterprise
                && rule
                    .parsed_query
                    .as_ref()
                    .is_some_and(|stmt| stmt.window.is_some())
            {
                self.dispatch_windowed(rule, topic, payload);
                continue;
            }
            let Some(data) = apply_sql(&rule.parsed_query, payload, &rule.id) else {
                rule.failed_cnt.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            rule.passed_cnt.fetch_add(1, Ordering::Relaxed);
            run_actions(
                &rule.id,
                &rule.actions,
                topic,
                data,
                qos,
                &self.connectors,
                Some(broker_sink),
                &ActionCounters::from_rule(rule),
                &self.forward_throttle,
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
    counters: &ActionCounters,
    throttle: &parking_lot::Mutex<HashMap<(String, String), ThrottleEntry>>,
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
                            counters.total.fetch_add(1, Ordering::Relaxed);
                            counters.failed.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                rule_id = %rule_id,
                                error = %e,
                                "Rule republish failed; continuing with remaining actions"
                            );
                        } else {
                            counters.total.fetch_add(1, Ordering::Relaxed);
                            counters.success.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    None => {
                        counters.total.fetch_add(1, Ordering::Relaxed);
                        counters.failed.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            rule_id = %rule_id,
                            "no broker sink configured; republish dropped"
                        );
                    }
                }
            }
            RuleAction::Log => {
                counters.total.fetch_add(1, Ordering::Relaxed);
                counters.success.fetch_add(1, Ordering::Relaxed);
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
                    counters.total.fetch_add(1, Ordering::Relaxed);
                    counters.failed.fetch_add(1, Ordering::Relaxed);
                    if let Some(suppressed) =
                        forward_failure_should_log(throttle, rule_id, connector_id, now_ms())
                    {
                        tracing::warn!(
                            rule_id = %rule_id,
                            connector = %connector_id,
                            error = %e,
                            suppressed = suppressed,
                            "Rule connector forward failed; continuing with remaining actions"
                        );
                    }
                } else {
                    counters.total.fetch_add(1, Ordering::Relaxed);
                    counters.success.fetch_add(1, Ordering::Relaxed);
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
    counters: ActionCounters,
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
                        flush_window(&rule_id, &stmt, &actions, batch, window_start, end, &flush_ctx, &counters).await;
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
                    flush_window(
                        &rule_id, &stmt, &actions, batch, start, end, &flush_ctx, &counters,
                    )
                    .await;
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
                            &counters,
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
                flush_window(
                    &rule_id, &stmt, &actions, batch, cutoff, end, &flush_ctx, &counters,
                )
                .await;
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
                        flush_window(&rule_id, &stmt, &actions, batch, start, end, &flush_ctx, &counters).await;
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
                                    flush_window(&rule_id, &stmt, &actions, batch, start, now, &flush_ctx, &counters).await;
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
/// dispatch each resulting row through the rule actions. Empty windows
/// and fully-having-filtered windows dispatch nothing. Each row routes
/// with its partition's first record topic.
#[allow(clippy::too_many_arguments)]
async fn flush_window(
    rule_id: &str,
    stmt: &SelectStmt,
    actions: &[RuleAction],
    batch: Vec<TimedRecord>,
    window_start_ms: u64,
    window_end_ms: u64,
    flush_ctx: &FlushContext,
    counters: &ActionCounters,
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
        run_actions(
            rule_id,
            actions,
            &topic,
            bytes,
            QoS::ExactlyOnce,
            &flush_ctx.connectors,
            sink.as_ref(),
            counters,
            &flush_ctx.forward_throttle,
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
fn group_key(exprs: &[rekuiper_sql::Expr], record: &HashMap<String, serde_json::Value>) -> String {
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
            && (b + 4 >= sql.len() || !is_word_char(sql[b + 4..].chars().next().unwrap_or(' ')));
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
                    serde_json::Value::Object(map) => {
                        Some((probe.clone(), map.clone().into_iter().collect()))
                    }
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
                        .map(|(_, row)| serde_json::Value::Object(row.into_iter().collect()))
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
            let record: HashMap<String, serde_json::Value> = map.clone().into_iter().collect();
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
                    && (b + 4 >= sql.len() || !is_word(sql[b + 4..].chars().next().unwrap_or(' ')));
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
fn apply_sql(parsed: &Option<SelectStmt>, payload: &Bytes, rule_id: &str) -> Option<Bytes> {
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
                BackpressurePolicy::DropNewest => {
                    Ok(PushOutcome::Dropped(OverflowReason::DroppedNewest))
                }
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
        let input = MockInput {
            policy: BackpressurePolicy::DropNewest,
        };
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
        engine
            .create_rule(
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
            vec![(
                "alerts/critical".to_string(),
                Bytes::from_static(b"21.5C"),
                QoS::AtMostOnce,
                false
            )]
        );
    }

    #[tokio::test]
    async fn test_rule_skips_disabled_and_non_matching() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        engine
            .create_rule(
                "disabled".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                None,
                false,
                vec![RuleAction::Log],
            )
            .expect("rule creates");
        engine
            .create_rule(
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
        let rule = engine
            .create_rule(
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
        assert!(engine
            .remove_rule("rule-1")
            .expect("memory-only remove cannot fail"));
        assert!(!engine
            .remove_rule("rule-1")
            .expect("memory-only remove cannot fail"));
        assert!(engine.list_rules().is_empty());
    }

    #[tokio::test]
    async fn test_drop_oldest_under_saturation() {
        let engine = RuleEngine::new(2, BackpressurePolicy::DropOldest);
        let input = engine.input();
        assert_eq!(
            input.try_push(test_event("t", b"one")).unwrap(),
            PushOutcome::Enqueued
        );
        assert_eq!(
            input.try_push(test_event("t", b"two")).unwrap(),
            PushOutcome::Enqueued
        );
        assert_eq!(
            input.try_push(test_event("t", b"three")).unwrap(),
            PushOutcome::Dropped(OverflowReason::DroppedOldest)
        );

        assert_eq!(
            input.next_event().await.unwrap().payload,
            Bytes::from_static(b"two")
        );
        assert_eq!(
            input.next_event().await.unwrap().payload,
            Bytes::from_static(b"three")
        );
    }

    #[tokio::test]
    async fn test_drop_newest_under_saturation() {
        let engine = RuleEngine::new(2, BackpressurePolicy::DropNewest);
        let input = engine.input();
        assert_eq!(
            input.try_push(test_event("t", b"one")).unwrap(),
            PushOutcome::Enqueued
        );
        assert_eq!(
            input.try_push(test_event("t", b"two")).unwrap(),
            PushOutcome::Enqueued
        );
        assert_eq!(
            input.try_push(test_event("t", b"three")).unwrap(),
            PushOutcome::Dropped(OverflowReason::DroppedNewest)
        );

        assert_eq!(
            input.next_event().await.unwrap().payload,
            Bytes::from_static(b"one")
        );
        assert_eq!(
            input.next_event().await.unwrap().payload,
            Bytes::from_static(b"two")
        );
    }

    #[tokio::test]
    async fn test_block_waits_for_capacity() {
        let engine = RuleEngine::new(1, BackpressurePolicy::Block);
        let input = engine.input();
        assert_eq!(
            input.try_push(test_event("t", b"one")).unwrap(),
            PushOutcome::Enqueued
        );
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
        assert_eq!(
            input.next_event().await.unwrap().payload,
            Bytes::from_static(b"one")
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), slow)
            .await
            .expect("push completes after drain")
            .unwrap();
        assert_eq!(
            input.next_event().await.unwrap().payload,
            Bytes::from_static(b"three")
        );
    }

    #[tokio::test]
    async fn test_reject_and_spill_report_overflow_when_full() {
        for policy in [
            BackpressurePolicy::RejectPublisher,
            BackpressurePolicy::SpillToDisk,
        ] {
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
    async fn project_one(sql: &str, payload: &'static [u8]) -> serde_json::Value {
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
        engine.connectors().register("webhook", recorder.clone());

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
                &Bytes::from_static(br#"{ "temperature": 72.5, "secret": "hide_me" }"#),
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
        // and builder override with a floor of 1 and no ceiling.
        assert_eq!(DEFAULT_WINDOW_CHANNEL_DEPTH, 65_536);
        assert_eq!(
            RuleEngine::new(16, BackpressurePolicy::DropOldest).window_channel_depth(),
            65_536
        );
        assert_eq!(
            RuleEngine::new_with_window_depth(16, BackpressurePolicy::DropOldest, 10_000)
                .window_channel_depth(),
            10_000
        );
        assert_eq!(
            RuleEngine::new(16, BackpressurePolicy::DropOldest)
                .with_window_channel_depth(1_000_000)
                .window_channel_depth(),
            1_000_000
        );
        assert_eq!(
            RuleEngine::new(16, BackpressurePolicy::DropOldest)
                .with_window_channel_depth(0)
                .window_channel_depth(),
            1
        );
    }

    #[tokio::test]
    async fn test_window_channel_depth_reaches_worker() {
        // The spawned worker's channel bound equals the configured depth.
        async fn worker_capacity(depth: usize) -> usize {
            let engine =
                RuleEngine::new_with_window_depth(16, BackpressurePolicy::DropOldest, depth);
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
            let workers = engine.window_workers.read();
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

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
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

    #[test]
    fn test_try_evaluate_vectors() {
        let payload = serde_json::json!({ "temperature": 72.5, "secret": "x" });

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
            try_evaluate(None, Some("sensors/+"), "sensors/kitchen", &payload).expect("evaluates");
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
        assert_eq!(
            stripped,
            r#"SELECT * FROM "sensors/+" WHERE temperature > 0"#
        );
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
        let (stripped, bound) =
            split_into_connector("SELECT a FROM s WHERE v > 1   INTO   connector( 'r1' ) ;")
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
            assert!(split_into_connector(bad).is_err(), "must reject: {bad}");
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
            Some(
                r#"SELECT temperature, device_id FROM "sensors/+" WHERE temperature > 0 INTO connector("kafka-sink-1")"#
            )
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
        // Kafka topics cannot contain `/`, so `/` renders as `.`.
        assert_eq!(records[0].topic, "out-sensors.kitchen");
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

    /// Sprint 17 e2e: one rule fans out to all five analytical sinks
    /// (Kafka, Redis, MySQL, ClickHouse, InfluxDB) via distinct
    /// connectors. TCP sinks use in-memory transports, HTTP sinks use
    /// in-process axum fakes: no broker anywhere in the loop.
    #[tokio::test]
    async fn test_rule_fans_out_to_five_analytical_sinks() {
        use axum::{extract::State, routing::post, Router};
        use broker_connectors::{
            ClickHouseSink, ClickHouseSinkConfig, InfluxDbSink, InfluxDbSinkConfig, KafkaSink,
            KafkaSinkConfig, MemoryKafkaTransport, MemoryMySqlTransport, MemoryRedisTransport,
            MySqlSink, MySqlSinkConfig, RedisCommandKind, RedisSink, RedisSinkConfig,
        };
        use tokio::net::TcpListener;

        async fn serve_capture(route: &str, captured: Arc<parking_lot::Mutex<String>>) -> u16 {
            async fn handler(
                State(captured): State<Arc<parking_lot::Mutex<String>>>,
                body: String,
            ) -> axum::http::StatusCode {
                *captured.lock() = body;
                axum::http::StatusCode::OK
            }
            let app = Router::new()
                .route(route, post(handler))
                .with_state(captured);
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().expect("addr").port();
            tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve");
            });
            port
        }

        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);

        // Kafka (memory transport).
        let kafka_transport = Arc::new(MemoryKafkaTransport::new());
        let kafka = Arc::new(
            KafkaSink::new(
                KafkaSinkConfig {
                    bootstrap_servers: "unused:9092".to_string(),
                    topic_template: "out-${topic}".to_string(),
                    partition_key_field: None,
                    partitions: 4,
                    client_id: "test".to_string(),
                    acks: "1".to_string(),
                    batch_max_records: 100,
                    batch_max_bytes: 1024 * 1024,
                },
                kafka_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("kafka-an", kafka.clone());

        // Redis (memory transport, immediate dispatch).
        let redis_transport = Arc::new(MemoryRedisTransport::new());
        let redis = Arc::new(
            RedisSink::new(
                RedisSinkConfig {
                    endpoint: "redis://unused:6379".to_string(),
                    command: RedisCommandKind::Publish {
                        channel_template: "fanout".to_string(),
                    },
                },
                redis_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("redis-an", redis.clone());

        // MySQL (memory transport).
        let mysql_transport = Arc::new(MemoryMySqlTransport::new());
        let mysql = Arc::new(
            MySqlSink::new(
                MySqlSinkConfig {
                    connection_url: "mysql://u:p@unused:3306/db".to_string(),
                    sql_template: "INSERT INTO mqtt_events (topic, qos, payload) VALUES (?, ?, ?)"
                        .to_string(),
                    pool_size: 1,
                    batch_size: 100,
                    batch_timeout_ms: 50,
                },
                mysql_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("mysql-an", mysql.clone());

        // ClickHouse (axum fake).
        let ch_body = Arc::new(parking_lot::Mutex::new(String::new()));
        let ch_port = serve_capture("/", ch_body.clone()).await;
        let clickhouse = Arc::new(
            ClickHouseSink::new(
                ClickHouseSinkConfig {
                    endpoint: format!("http://127.0.0.1:{ch_port}"),
                    database: "indra".to_string(),
                    table: "mqtt_events".to_string(),
                    format: "JSONEachRow".to_string(),
                    batch_size: 100,
                    batch_timeout_ms: 100,
                    request_timeout_ms: None,
                },
                reqwest::Client::new(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("ch-an", clickhouse.clone());

        // InfluxDB (axum fake).
        let influx_body = Arc::new(parking_lot::Mutex::new(String::new()));
        let influx_port = serve_capture("/api/v2/write", influx_body.clone()).await;
        let influx = Arc::new(
            InfluxDbSink::new(
                InfluxDbSinkConfig {
                    endpoint: format!("http://127.0.0.1:{influx_port}"),
                    bucket: "mqtt".to_string(),
                    org: "indra".to_string(),
                    token: "secret".to_string(),
                    measurement_template: "mqtt_events".to_string(),
                    precision: "ms".to_string(),
                    batch_size: 100,
                    batch_timeout_ms: 50,
                    request_timeout_ms: None,
                },
                reqwest::Client::new(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("influx-an", influx.clone());

        // One rule, five ForwardConnector actions, SQL projection.
        engine
            .create_rule(
                "fanout-five".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(r#"SELECT temperature FROM "sensors/+""#.to_string()),
                true,
                ["kafka-an", "redis-an", "mysql-an", "ch-an", "influx-an"]
                    .into_iter()
                    .map(|id| RuleAction::ForwardConnector {
                        connector_id: id.to_string(),
                    })
                    .collect(),
            )
            .expect("rule creates");

        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(br#"{ "temperature": 72.5, "secret": "hide_me" }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        // Buffered sinks flush explicitly (Redis dispatches inline).
        kafka.flush().await.expect("kafka flush");
        mysql.flush().await.expect("mysql flush");
        clickhouse.flush().await.expect("clickhouse flush");
        influx.flush().await.expect("influx flush");

        let projected = serde_json::json!({ "temperature": 72.5 });

        let records = kafka_transport.records_flat();
        assert_eq!(records.len(), 1);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&records[0].value).unwrap(),
            projected
        );

        let commands = redis_transport.commands();
        assert_eq!(commands.len(), 1);
        let argv = &commands[0].argv;
        assert_eq!(argv[0], b"PUBLISH".to_vec());
        assert_eq!(argv[1], b"fanout".to_vec());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&argv[2]).unwrap(),
            projected
        );

        let batches = mysql_transport.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].rows.len(), 1);
        assert_eq!(batches[0].rows[0][0], b"sensors/kitchen".to_vec());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&batches[0].rows[0][2]).unwrap(),
            projected
        );

        let ch_lines: Vec<String> = ch_body.lock().lines().map(str::to_string).collect();
        assert_eq!(ch_lines.len(), 1);
        let ch_row: serde_json::Value = serde_json::from_str(&ch_lines[0]).unwrap();
        assert_eq!(ch_row["topic"], "sensors/kitchen");
        assert_eq!(ch_row["payload"], projected.to_string());

        let influx_lines: Vec<String> = influx_body.lock().lines().map(str::to_string).collect();
        assert_eq!(influx_lines.len(), 1);
        assert!(
            influx_lines[0].starts_with("mqtt_events,topic=sensors/kitchen "),
            "unexpected line: {}",
            influx_lines[0]
        );
        assert!(influx_lines[0].contains("payload=\"{\\\"temperature\\\":72.5}\""));

        // Non-JSON ingress matches nothing: all five sinks stay silent.
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(b"not json"),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        kafka.flush().await.expect("kafka flush");
        mysql.flush().await.expect("mysql flush");
        clickhouse.flush().await.expect("clickhouse flush");
        influx.flush().await.expect("influx flush");
        assert_eq!(kafka_transport.records_flat().len(), 1);
        assert_eq!(redis_transport.commands().len(), 1);
        assert_eq!(mysql_transport.batches().len(), 1);
        assert_eq!(ch_body.lock().lines().count(), 1);
        assert_eq!(influx_body.lock().lines().count(), 1);
    }

    /// Sprint 18 e2e (INDRA-216): streaming SQL rules with `INTO
    /// connector(...)` fan out to the object-storage and search sinks.
    /// A stateless cold-storage rule feeds mock S3, a stateless log
    /// rule feeds mock Elasticsearch, and a count-window metrics rule
    /// feeds the mock TimescaleDB hypertable. No broker anywhere.
    #[tokio::test]
    async fn test_into_fans_out_to_s3_elasticsearch_timescaledb() {
        use broker_connectors::{
            ElasticsearchSink, ElasticsearchSinkConfig, MockElasticsearchTransport,
            MockS3Transport, MockTimescaleTransport, S3Sink, S3SinkConfig, TimescaleDbSink,
            TimescaleDbSinkConfig,
        };

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);

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

    /// Industrial e2e (INDRA-217): one Sparkplug telemetry ingress
    /// routes through streaming SQL `INTO connector(...)` rules and
    /// fans out simultaneously to the webhook, MQTT bridge, disk log
    /// and Sparkplug B sinks. All transports are in-memory.
    #[tokio::test]
    async fn test_into_fans_out_to_industrial_sinks() {
        use broker_connectors::{
            DiskLogSink, DiskLogSinkConfig, HttpSink, HttpSinkConfig, MemoryDiskLogWriter,
            MemoryMqttBridgeTransport, MemorySparkplugTransport, MockHttpTransport, MqttBridgeSink,
            MqttBridgeSinkConfig, SparkplugBSink, SparkplugSinkConfig,
        };

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);

        // Webhook (auto-flush every row).
        let hook_transport = Arc::new(MockHttpTransport::new());
        let hook = Arc::new(
            HttpSink::new(
                HttpSinkConfig {
                    url: "https://hooks.example.com/ingest/${topic}".to_string(),
                    method: broker_connectors::HttpMethod::Post,
                    headers: HashMap::new(),
                    auth: broker_connectors::HttpAuth::None,
                    body_format: broker_connectors::HttpBodyFormat::RawJson,
                    signature: None,
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: None,
                    timeout_ms: Some(5_000),
                    max_retries: Some(3),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                },
                hook_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("hook-industrial", hook.clone());

        // MQTT bridge (auto-flush every row).
        let bridge_transport = Arc::new(MemoryMqttBridgeTransport::new());
        let bridge = Arc::new(
            MqttBridgeSink::new(
                MqttBridgeSinkConfig {
                    broker_address: "mqtt://upstream:1883".to_string(),
                    client_id: "indra-bridge-test".to_string(),
                    clean_start: true,
                    username: None,
                    password: None,
                    keep_alive_secs: 60,
                    topic_prefix: Some("upstream/".to_string()),
                    topic_template: None,
                    qos_override: None,
                    retain_override: None,
                    max_inflight: Some(10_000),
                    max_batch_size: Some(1),
                    linger_ms: Some(10),
                    protocol: broker_connectors::MqttBridgeProtocol::V311,
                },
                bridge_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("bridge-upstream", bridge.clone());

        // Disk audit log (write-through, in-memory segments).
        let disk_writer = Arc::new(
            MemoryDiskLogWriter::new(&DiskLogSinkConfig {
                directory: "memory://audit".to_string(),
                filename_prefix: "audit".to_string(),
                filename_extension: "log".to_string(),
                format: broker_connectors::DiskLogFormat::Ndjson,
                max_file_size_bytes: None,
                max_file_age_secs: None,
                compression: broker_connectors::DiskLogCompression::None,
                max_backup_files: None,
                max_retention_days: None,
                sync_mode: broker_connectors::DiskSyncMode::OsDefault,
                timeout_ms: None,
            })
            .expect("valid writer"),
        );
        let disk = Arc::new(
            DiskLogSink::new(
                DiskLogSinkConfig {
                    directory: "memory://audit".to_string(),
                    filename_prefix: "audit".to_string(),
                    filename_extension: "log".to_string(),
                    format: broker_connectors::DiskLogFormat::Ndjson,
                    max_file_size_bytes: None,
                    max_file_age_secs: None,
                    compression: broker_connectors::DiskLogCompression::None,
                    max_backup_files: None,
                    max_retention_days: None,
                    sync_mode: broker_connectors::DiskSyncMode::OsDefault,
                    timeout_ms: None,
                },
                disk_writer.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("disk-audit", disk.clone());

        // Sparkplug B frames (auto-flush every row).
        let spb_transport = Arc::new(MemorySparkplugTransport::new());
        let spb = Arc::new(
            SparkplugBSink::new(
                SparkplugSinkConfig {
                    topic_prefix: Some("spBv1.0/plant1".to_string()),
                    tier: "enterprise".to_string(),
                    batch_size: Some(1),
                    linger_ms: Some(50),
                    timeout_ms: None,
                },
                spb_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("spb-metrics", spb.clone());

        // One INTO rule per sink over the same Sparkplug stream.
        for (id, connector) in [
            ("hook-rule", "hook-industrial"),
            ("bridge-rule", "bridge-upstream"),
            ("disk-rule", "disk-audit"),
            ("spb-rule", "spb-metrics"),
        ] {
            engine
                .create_rule(
                    id.to_string(),
                    TopicFilter::new("spBv1.0/#").unwrap(),
                    Some(format!(
                        r#"SELECT metrics FROM "spBv1.0/#" WHERE metrics.Temperature > 80.0 INTO connector("{connector}")"#
                    )),
                    true,
                    vec![],
                )
                .expect("rule creates");
        }

        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("spBv1.0/plant1/DDATA/edge7/plc3").unwrap(),
                &Bytes::from_static(br#"{ "metrics": { "Temperature": 82.5 }, "seq": 14 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        let projected = serde_json::json!({"metrics": {"Temperature": 82.5}});

        // Webhook got the projected JSON at the templated URL.
        let captured = hook_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            captured[0].url,
            "https://hooks.example.com/ingest/spBv1.0/plant1/DDATA/edge7/plc3"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&captured[0].body).unwrap(),
            projected
        );

        // Bridge got one QoS 0 frame on the prefixed topic.
        let packets = bridge_transport.packets();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].topic, "upstream/spBv1.0/plant1/DDATA/edge7/plc3");
        let decoded = broker_connectors::decode_publish(&packets[0].bytes, false).unwrap();
        assert_eq!(decoded.qos, 0);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&decoded.payload).unwrap(),
            projected
        );

        // Disk got one ndjson audit line.
        let current = String::from_utf8(disk_writer.current_bytes()).unwrap();
        assert_eq!(current.lines().count(), 1);
        let row: serde_json::Value = serde_json::from_str(current.trim_end()).unwrap();
        assert_eq!(row["topic"], "spBv1.0/plant1/DDATA/edge7/plc3");
        assert_eq!(row["payload"], projected);

        // Sparkplug got one Protobuf frame decoding back to metrics.
        let frames = spb_transport.frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].topic, "spBv1.0/plant1/DDATA/edge7/plc3");
        let back = broker_connectors::decode_payload(&frames[0].payload).unwrap();
        let metrics: HashMap<String, broker_connectors::SpbValue> = back
            .metrics
            .into_iter()
            .map(|metric| (metric.name.clone().unwrap(), metric.value))
            .collect();
        assert_eq!(
            metrics["Temperature"],
            broker_connectors::SpbValue::Double(82.5)
        );

        // Below-threshold telemetry fires nothing anywhere.
        engine
            .dispatch_ingress(
                &Topic::new("spBv1.0/plant1/DDATA/edge7/plc3").unwrap(),
                &Bytes::from_static(br#"{ "metrics": { "Temperature": 70.0 } }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(hook_transport.captured().len(), 1);
        assert_eq!(bridge_transport.packets().len(), 1);
        let current = String::from_utf8(disk_writer.current_bytes()).unwrap();
        assert_eq!(current.lines().count(), 1);
        assert_eq!(spb_transport.frames().len(), 1);
    }

    /// Multi-cloud e2e (INDRA-218): one ingress event routes through
    /// streaming SQL `INTO connector(...)` rules and fans out
    /// simultaneously to the Kinesis, GCP Pub/Sub, Azure Event Hubs
    /// and Pulsar mocks. All transports are in-memory.
    #[tokio::test]
    async fn test_into_fans_out_to_cloud_sinks() {
        use broker_connectors::{
            AzureEventHubsSink, AzureEventHubsSinkConfig, GcpPubSubSink, GcpPubSubSinkConfig,
            KinesisSink, KinesisSinkConfig, MemoryPulsarTransport, MockAzureEventHubsTransport,
            MockGcpPubSubTransport, MockKinesisTransport, PulsarSink, PulsarSinkConfig,
        };

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);

        // Kinesis (auto-flush every row, clean mock).
        let kinesis_transport = Arc::new(MockKinesisTransport::new());
        let kinesis = Arc::new(
            KinesisSink::new(
                KinesisSinkConfig {
                    stream_name: "telemetry-stream".to_string(),
                    region: "us-east-1".to_string(),
                    endpoint: None,
                    access_key_id: "AKID".to_string(),
                    secret_access_key: "secret".to_string(),
                    session_token: None,
                    partition_key_template: Some("${client_id}".to_string()),
                    explicit_hash_key: None,
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(20),
                    max_retries: Some(5),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                kinesis_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("aws-kinesis", kinesis.clone());

        // GCP Pub/Sub (auto-flush every row).
        let gcp_transport = Arc::new(MockGcpPubSubTransport::new());
        let gcp = Arc::new(
            GcpPubSubSink::new(
                GcpPubSubSinkConfig {
                    project_id: "my-iot-project".to_string(),
                    topic_id: "telemetry-events".to_string(),
                    endpoint: None,
                    auth: broker_connectors::GcpAuth::None,
                    ordering_key_template: Some("${client_id}".to_string()),
                    attributes: HashMap::from([("source".to_string(), "indramqtt".to_string())]),
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(10),
                    max_retries: Some(3),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                gcp_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("gcp-pubsub", gcp.clone());

        // Azure Event Hubs (auto-flush every row).
        let azure_transport = Arc::new(MockAzureEventHubsTransport::new());
        let azure = Arc::new(
            AzureEventHubsSink::new(
                AzureEventHubsSinkConfig {
                    namespace: "my-eventhub-ns".to_string(),
                    event_hub: "telemetry-hub".to_string(),
                    endpoint: None,
                    shared_access_key_name: "SendPolicy".to_string(),
                    shared_access_key: "c2VjcmV0".to_string(),
                    partition_key_template: Some("${client_id}".to_string()),
                    user_properties: HashMap::new(),
                    token_ttl_secs: 3_600,
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(20),
                    max_retries: Some(4),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                azure_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("azure-eventhubs", azure.clone());

        // Pulsar (auto-flush every row).
        let pulsar_transport = Arc::new(MemoryPulsarTransport::new());
        let pulsar = Arc::new(
            PulsarSink::new(
                PulsarSinkConfig {
                    service_url: "pulsar://unused:6650".to_string(),
                    tenant: "public".to_string(),
                    namespace: "default".to_string(),
                    topic: "${topic}".to_string(),
                    auth: broker_connectors::PulsarAuth::None,
                    partition_key_template: Some("${client_id}".to_string()),
                    properties: HashMap::new(),
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(10),
                    max_retries: Some(3),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                pulsar_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("pulsar-sink", pulsar.clone());

        // One INTO rule per cloud.
        for (id, connector) in [
            ("kinesis-rule", "aws-kinesis"),
            ("gcp-rule", "gcp-pubsub"),
            ("azure-rule", "azure-eventhubs"),
            ("pulsar-rule", "pulsar-sink"),
        ] {
            engine
                .create_rule(
                    id.to_string(),
                    TopicFilter::new("sensors/+").unwrap(),
                    Some(format!(
                        r#"SELECT client_id, temp FROM "sensors/+" WHERE temp > 20.0 INTO connector("{connector}")"#
                    )),
                    true,
                    vec![],
                )
                .expect("rule creates");
        }

        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "device-42", "temp": 22.5 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        let projected = serde_json::json!({"client_id": "device-42", "temp": 22.5});

        // Kinesis: one batch, keyed by client_id, base64 body.
        let captured = kinesis_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].stream_name, "telemetry-stream");
        assert_eq!(captured[0].records.len(), 1);
        assert_eq!(captured[0].records[0].partition_key, "device-42");
        let payload = base64_decode(&captured[0].records[0].data_b64);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&payload).unwrap(),
            projected
        );

        // GCP: one message with ordering key + attributes.
        let captured = gcp_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].project, "my-iot-project");
        assert_eq!(captured[0].messages.len(), 1);
        assert_eq!(
            captured[0].messages[0].ordering_key.as_deref(),
            Some("device-42")
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&base64_decode(
                &captured[0].messages[0].data_b64
            ))
            .unwrap(),
            projected
        );

        // Azure: one event with the partition key + SAS token.
        let captured = azure_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].hub, "telemetry-hub");
        assert_eq!(captured[0].events.len(), 1);
        assert_eq!(
            captured[0].events[0].partition_key.as_deref(),
            Some("device-42")
        );
        assert!(captured[0]
            .sas_token
            .starts_with("SharedAccessSignature sr="));
        let payload = base64_decode(&captured[0].events[0].body_b64);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&payload).unwrap(),
            projected
        );

        // Pulsar: one message on the canonical topic path.
        let captured = pulsar_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            captured[0].topic_path,
            "persistent://public/default/sensors.kitchen"
        );
        assert_eq!(captured[0].messages.len(), 1);
        assert_eq!(captured[0].messages[0].sequence_id, 0);
        assert_eq!(
            captured[0].messages[0].partition_key.as_deref(),
            Some("device-42")
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&captured[0].messages[0].payload).unwrap(),
            projected
        );

        // Below-threshold telemetry fires nothing anywhere.
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "device-42", "temp": 10.0 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(kinesis_transport.captured().len(), 1);
        assert_eq!(gcp_transport.captured().len(), 1);
        assert_eq!(azure_transport.captured().len(), 1);
        assert_eq!(pulsar_transport.captured().len(), 1);
    }

    /// IoT + industrial e2e (INDRA-219/220): one ingress event fans
    /// out through streaming SQL `INTO connector(...)` rules to the
    /// OCI, AWS IoT, Azure IoT and GCP IoT mocks, while a raw scalar
    /// ingress forwards (no SQL projection, bytes verbatim) into the
    /// OPC-UA memory transport as a typed node write. All transports
    /// are in-memory; the RSA key is a fixed test key (never deployed).
    #[tokio::test]
    async fn test_into_fans_out_to_iot_industrial_sinks() {
        use broker_connectors::{
            AwsIotAuth, AwsIotConfig, AwsIotSink, AzureIotAuth, AzureIotConfig, AzureIotSink,
            BridgeTopicMapping, GcpIotAlgorithm, GcpIotConfig, GcpIotSink, MemoryOpcUaTransport,
            MockAwsIotTransport, MockAzureIotTransport, MockGcpIotTransport,
            MockOciStreamingTransport, NodeSubscriptionConfig, OciStreamingSink,
            OciStreamingSinkConfig, OpcUaAuth, OpcUaSecurityMode, OpcUaSecurityPolicy, OpcUaSink,
            OpcUaSinkConfig, OpcUaVariant,
        };
        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);

        // Fixed test RSA key for the OCI signature + GCP JWT legs
        // (openssl-generated, in-memory, never deployed).
        let test_pem = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCgQlU8hDdoMjP5
QU2fhr0g+2n5HQSvgQaDKkpZFftqbrMixmFg3pGQN+GZp9vIscT+BlNrJueigXpn
pRbhI0RRj8EvVl+4Or+0hdzeLDmfGl/9SIhnyiRsJ7YDeO3uZq/Cff2zMeXqqbk4
RgKwbQksnJPOOYgVOfPrLjHJdEkNcSxT44tyOVrhBVISYm+zUw4By4GSQXp4RoTa
8UFX/gHoa+31um/9yZfDf9ekzelBys+4iSBeJ6imdStCjt8K+71yxewMSMD6HiCj
2GWvp+mPixqf4GcwaiqoFgJj+IKspc3eyozqJY/+610aaSw/ooO2AFXfErJlJEBP
H5hITBUlAgMBAAECggEAErJqe1r5k+B3i9cAlWIE4royTOwDxe4JsnfWoLod0PcF
U0NNzR1qYicC3Qhmbe2/i9t1FAU/9QeiHkF2f+G7cMCSy1EKbdX807TiZdFHD7bm
CAjUUTeWNEAVziXnrG6yhsBoPuXNaylOALC6U5cFAP1riR3RMJjISmHjURuOAlFI
W8tlKq77I5a4L93IW+2/elDPTjhUYsQnSEtJPWG/BizSVihHSiHh2lAN0JLZChWk
6J2e2FaZYC28Swu/V+GLXLg0Ai8GkSZNYTqOf8HqnkB7X3G7+OMnLPW+0I5GPOh+
9aX9WXhGAI6gxJf6UjcD5axHV+mdfgQnxBsJY4HxqQKBgQDfUbtYzfLBxnnxk0H7
N+lhdiANA/YXiR4OljziTSTjnnSDdabktr3ubIofpEwjvAqKIdn5ruyqdT/9GOZt
/7sai0aqyIzGlQiLhkxHvHBIxGajRBbPq2BhLqQYBeL0Xy4oMcD5NjGoUuhcck0b
bw6h935CIJYzJQtx+K/U4I2DwwKBgQC3timBQPbq+wJx4yuyf+VOy4r9qW0/4DUM
pw3qo1tqOk1hKN6pZazov0qfrGEKIOG4Ws0rLCKgwKwocdfFfzPwTgg8srl5r5XM
k5r97mHNYqSlboAE2YIM+CziUmVqklkMqQ4Hs38jk3tswt6yY+syrfZbp/Rhh/XK
pVv1itr89wKBgQDBi1VihsNw+7IuE2Eo9/E1faoTfa5oAXdiTwUfYJqrB2aVlH77
VAHSRJGFEODIS62av/Hpepg0t3+ovE7hYLTpMXIii8OuS/Xm7pLnzUJHXqhRsa5P
d4kFUOX4yAlFn8QiI9TKaBSrfIdTr+Bx+VNmPlhXuWRTmTSNJ2pEhgU//wKBgAt7
Vxy88rG8/mofyJtfYvWJwyYXcLyNRsODrVr82rnI6w0ngMMVl7j0O7W/EFGRvInJ
IwmPuJpTcG8WrmWpjZV3SwyAHxd74eDnWMiGHZa4k5HDVjz3Wyl0WVnLzIrcmrQv
3LCeh1Ox5AToKQL9O7XvKXaRCLUPykzgCN9PzmABAoGAUW/AIrYerL0oU0KBRZ5B
6NX+5++R6jugN/spvVs4OLwPM5a6ud6Bq/+BA3aT7NWdfypVgybotEytsb/y1oe2
XdFhno110rcMp6WoQHM4dCWw3cmRNbMv2aleY2FrTZlpxEXeA47iF5/if1VHldmR
Y7LzJJ6LCjfUFy8dMINZC7M=
-----END PRIVATE KEY-----
"
        .to_string();

        // OCI Streaming (auto-flush every row, clean mock).
        let oci_transport = Arc::new(MockOciStreamingTransport::new());
        let oci = Arc::new(
            OciStreamingSink::new(
                OciStreamingSinkConfig {
                    endpoint: "https://cell-1.streaming.us-east-1.oci.oraclecloud.com".to_string(),
                    stream_pool_id: "ocid1.streampool.oc1..testpool".to_string(),
                    stream_id: "ocid1.stream.oc1..teststream".to_string(),
                    tenancy_ocid: "ocid1.tenancy.oc1..test".to_string(),
                    user_ocid: "ocid1.user.oc1..test".to_string(),
                    fingerprint: "20:3b:97:13:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55".to_string(),
                    private_key_pem: test_pem.clone(),
                    partition_key_template: "${client_id}".to_string(),
                    batch_size: Some(1),
                    buffer_capacity: None,
                    batch_bytes: None,
                    linger_ms: Some(10),
                    max_retries: Some(5),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                oci_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("oci-sink", oci.clone());

        // AWS IoT Core (SigV4 dummies; the mock never signs).
        let aws_transport = Arc::new(MockAwsIotTransport::new());
        let aws = Arc::new(
            AwsIotSink::new(
                AwsIotConfig {
                    endpoint: "abc-ats.iot.us-east-1.amazonaws.com".to_string(),
                    region: "us-east-1".to_string(),
                    client_id: "e2e-bridge".to_string(),
                    auth: AwsIotAuth::SigV4 {
                        access_key_id: "AKID".to_string(),
                        secret_access_key: "secret".to_string(),
                        session_token: None,
                    },
                    topic_mappings: vec![BridgeTopicMapping {
                        local_topic: "sensors/+".to_string(),
                        remote_topic: "indra/up".to_string(),
                        direction: broker_connectors::BridgeDirection::LocalToRemote,
                    }],
                    shadow_sync: None,
                    batch_size: Some(1),
                    buffer_capacity: None,
                    linger_ms: Some(10),
                    max_retries: Some(5),
                    timeout_ms: None,
                    connect_timeout_ms: None,
                    handshake_timeout_ms: None,
                    ca_bundle_pem: None,
                    alpn_protocols: None,
                },
                aws_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("aws-iot-sink", aws.clone());

        // Azure IoT Hub (SAS minted locally with HMAC, no network).
        let azure_transport = Arc::new(MockAzureIotTransport::new());
        let azure = Arc::new(
            AzureIotSink::new(
                AzureIotConfig {
                    iot_hub_name: "e2e-hub".to_string(),
                    device_id: "e2e-device".to_string(),
                    module_id: None,
                    auth: AzureIotAuth::SharedAccessKey {
                        key: "c2VjcmV0".to_string(),
                        key_name: Some("device".to_string()),
                    },
                    api_version: "2021-04-12".to_string(),
                    direct_methods_enabled: false,
                    twin_sync_enabled: false,
                    batch_size: Some(1),
                    buffer_capacity: None,
                    linger_ms: Some(10),
                    max_retries: Some(5),
                    timeout_ms: None,
                    connect_timeout_ms: None,
                    handshake_timeout_ms: None,
                    ca_bundle_pem: None,
                    sas_ttl_secs: None,
                },
                azure_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("azure-iot-sink", azure.clone());

        // GCP IoT Core (RS256 JWT minted with the test key).
        let gcp_transport = Arc::new(MockGcpIotTransport::new());
        let gcp = Arc::new(
            GcpIotSink::new(
                GcpIotConfig {
                    project_id: "e2e-project".to_string(),
                    cloud_region: "us-central1".to_string(),
                    registry_id: "e2e-registry".to_string(),
                    device_id: "e2e-device".to_string(),
                    private_key_pem: test_pem,
                    algorithm: GcpIotAlgorithm::Rs256,
                    token_lifetime_secs: 3_600,
                    endpoint: "mqtt.googleapis.com:8883".to_string(),
                    batch_size: Some(1),
                    buffer_capacity: None,
                    linger_ms: Some(10),
                    max_retries: Some(5),
                    timeout_ms: None,
                },
                gcp_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("gcp-iot-sink", gcp.clone());

        // OPC-UA (memory transport; the write leg matches a raw scalar
        // ingress against `write_topic_pattern`, no SQL projection).
        let opcua_transport = Arc::new(MemoryOpcUaTransport::new());
        let opcua = Arc::new(
            OpcUaSink::new(
                OpcUaSinkConfig {
                    endpoint_url: "opc.tcp://127.0.0.1:4840".to_string(),
                    security_policy: OpcUaSecurityPolicy::None,
                    security_mode: OpcUaSecurityMode::None,
                    auth: OpcUaAuth::Anonymous,
                    node_subscriptions: vec![NodeSubscriptionConfig {
                        node_id: "ns=2;s=Setpoint".to_string(),
                        sampling_interval_ms: 1_000,
                        publish_topic_template: "opcua/setpoint".to_string(),
                        write_topic_pattern: Some("factory/setpoint/+".to_string()),
                    }],
                    buffer_capacity: None,
                    batch_size: Some(1),
                    linger_ms: Some(10),
                    timeout_ms: None,
                },
                opcua_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("opcua-sink", opcua.clone());

        // One INTO rule per IoT cloud.
        for (id, connector) in [
            ("oci-rule", "oci-sink"),
            ("aws-rule", "aws-iot-sink"),
            ("azure-rule", "azure-iot-sink"),
            ("gcp-rule", "gcp-iot-sink"),
        ] {
            engine
                .create_rule(
                    id.to_string(),
                    TopicFilter::new("sensors/+").unwrap(),
                    Some(format!(
                        r#"SELECT client_id, temp FROM "sensors/+" WHERE temp > 20.0 INTO connector("{connector}")"#
                    )),
                    true,
                    vec![],
                )
                .expect("rule creates");
        }
        // OPC-UA: verbatim forward, no projection (scalars only).
        engine
            .create_rule(
                "opcua-rule".to_string(),
                TopicFilter::new("factory/setpoint/+").unwrap(),
                None,
                true,
                vec![RuleAction::ForwardConnector {
                    connector_id: "opcua-sink".to_string(),
                }],
            )
            .expect("rule creates");

        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "device-42", "temp": 22.5 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        let projected = serde_json::json!({"client_id": "device-42", "temp": 22.5});

        // OCI: one entry, partitioned by client_id, signed auth attached.
        let captured = oci_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].messages.len(), 1);
        assert_eq!(
            base64_decode(&captured[0].messages[0].key_b64),
            b"device-42".to_vec()
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&base64_decode(
                &captured[0].messages[0].value_b64
            ))
            .unwrap(),
            projected
        );
        assert!(captured[0]
            .auth
            .authorization
            .starts_with("Signature version=\"1\""));

        // AWS IoT: one frame on the mapped remote topic.
        let captured = aws_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].remote_topic, "indra/up");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&captured[0].payload).unwrap(),
            projected
        );

        // Azure IoT: one D2C publish with a SAS token.
        let captured = azure_transport.captured();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].topic.contains("e2e-device"));
        assert!(captured[0]
            .sas_token
            .starts_with("SharedAccessSignature sr="));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&captured[0].body).unwrap(),
            projected
        );

        // GCP IoT: one telemetry publish with a JWT password.
        let captured = gcp_transport.captured();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].topic.contains("e2e-device"));
        assert_eq!(captured[0].password_token.split('.').count(), 3);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&captured[0].body).unwrap(),
            projected
        );

        // OPC-UA: raw scalar ingress becomes a typed node write.
        engine
            .dispatch_ingress(
                &Topic::new("factory/setpoint/line1").unwrap(),
                &Bytes::from_static(b"22.5"),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        let writes = opcua_transport.writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].variant, OpcUaVariant::Double(22.5));
        assert!(format!("{:?}", writes[0].node_id).contains("Setpoint"));

        // Below-threshold telemetry fires nothing anywhere.
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "device-42", "temp": 10.0 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(oci_transport.captured().len(), 1);
        assert_eq!(aws_transport.captured().len(), 1);
        assert_eq!(azure_transport.captured().len(), 1);
        assert_eq!(gcp_transport.captured().len(), 1);
        assert_eq!(opcua_transport.writes().len(), 1);
    }

    fn base64_decode(input: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(input)
            .unwrap()
    }

    /// Multi-store e2e (INDRA-220): one ingress event routes through
    /// streaming SQL `INTO connector(...)` rules and fans out
    /// simultaneously to the MongoDB, MSSQL, Cassandra and Couchbase
    /// mocks with zero drops. All transports are in-memory.
    #[tokio::test]
    async fn test_into_fans_out_to_database_sinks() {
        use broker_connectors::{
            CassandraSink, CassandraSinkConfig, CouchbaseSink, CouchbaseSinkConfig,
            MockCassandraTransport, MockCouchbaseTransport, MockMongoDbTransport,
            MockMssqlTransport, MongoDbSink, MongoDbSinkConfig, MssqlSink, MssqlSinkConfig,
        };

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);

        // MongoDB documents (auto-flush every row).
        let mongo_transport = Arc::new(MockMongoDbTransport::new());
        let mongo = Arc::new(
            MongoDbSink::new(
                MongoDbSinkConfig {
                    connection_string: "mongodb://u:p@unused:27017".to_string(),
                    database: "telemetry".to_string(),
                    collection_template: "readings".to_string(),
                    operation: broker_connectors::MongoOperation::InsertOne,
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(20),
                    max_retries: Some(4),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                mongo_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("mongodb-sink", mongo.clone());

        // MSSQL rows (auto-flush every row).
        let mssql_transport = Arc::new(MockMssqlTransport::new());
        let mssql = Arc::new(
            MssqlSink::new(
                MssqlSinkConfig {
                    host: "unused".to_string(),
                    port: None,
                    database: "telemetry".to_string(),
                    table_template: "dbo.SensorEvents".to_string(),
                    auth: broker_connectors::MssqlAuth::Integrated,
                    query_mode: broker_connectors::MssqlQueryMode::InsertJson,
                    trust_server_certificate: true,
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(20),
                    max_retries: Some(3),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                mssql_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("mssql-sink", mssql.clone());

        // Cassandra statements (auto-flush every row).
        let cassandra_transport = Arc::new(MockCassandraTransport::new());
        let cassandra = Arc::new(
            CassandraSink::new(
                CassandraSinkConfig {
                    contact_points: vec!["10.0.0.1:9042".to_string()],
                    keyspace: "telemetry".to_string(),
                    table_template: "events".to_string(),
                    auth: broker_connectors::CassandraAuth::None,
                    consistency: broker_connectors::CqlConsistency::LocalQuorum,
                    partition_key_template: "${client_id}".to_string(),
                    cql_statement_template: "INSERT INTO telemetry.events (device_id, bucket_hour, event_time, payload) VALUES (?, ?, ?, ?)".to_string(),
                    ttl_secs: None,
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(10),
                    max_retries: Some(4),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                cassandra_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("cassandra-sink", cassandra.clone());

        // Couchbase documents (auto-flush every row).
        let couchbase_transport = Arc::new(MockCouchbaseTransport::new());
        couchbase_transport.set_operation_tag(0);
        let couchbase = Arc::new(
            CouchbaseSink::new(
                CouchbaseSinkConfig {
                    connection_string: "couchbase://unused".to_string(),
                    bucket: "telemetry".to_string(),
                    scope: None,
                    collection: None,
                    auth: broker_connectors::CouchbaseAuth {
                        username: "Administrator".to_string(),
                        password: "secret".to_string(),
                    },
                    doc_id_template: "${client_id}::${timestamp}".to_string(),
                    operation: broker_connectors::CouchbaseOperation::Upsert,
                    expiry_secs: None,
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(10),
                    max_retries: Some(3),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                couchbase_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("couchbase-sink", couchbase.clone());

        // One INTO rule per store.
        for (id, connector) in [
            ("mongo-rule", "mongodb-sink"),
            ("mssql-rule", "mssql-sink"),
            ("cassandra-rule", "cassandra-sink"),
            ("couchbase-rule", "couchbase-sink"),
        ] {
            engine
                .create_rule(
                    id.to_string(),
                    TopicFilter::new("sensors/+").unwrap(),
                    Some(format!(
                        r#"SELECT client_id, device_id, temp FROM "sensors/+" WHERE temp > 20.0 INTO connector("{connector}")"#
                    )),
                    true,
                    vec![],
                )
                .expect("rule creates");
        }

        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(
                    br#"{ "client_id": "device-42", "device_id": "device-42", "temp": 22.5 }"#,
                ),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        let projected =
            serde_json::json!({"client_id": "device-42", "device_id": "device-42", "temp": 22.5});

        // MongoDB: one document with _mqtt metadata in `readings`.
        let captured = mongo_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].db, "telemetry");
        assert_eq!(captured[0].collection, "readings");
        assert_eq!(captured[0].docs.len(), 1);
        let document = &captured[0].docs[0].document;
        assert!(matches!(
            document.get("_id"),
            Some(broker_connectors::BsonValue::ObjectId(_))
        ));
        assert_eq!(
            document.get("temp"),
            Some(&broker_connectors::BsonValue::Double(22.5))
        );
        assert_eq!(
            document.get("_mqtt").and_then(|meta| match meta {
                broker_connectors::BsonValue::Document(meta) => meta.get("topic").cloned(),
                _ => None,
            }),
            Some(broker_connectors::BsonValue::String(
                "sensors/kitchen".to_string()
            ))
        );

        // MSSQL: one typed row in dbo.SensorEvents.
        let captured = mssql_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].table, "dbo.SensorEvents");
        assert_eq!(captured[0].rows.len(), 1);
        assert_eq!(captured[0].rows[0].topic, "sensors/kitchen");
        assert_eq!(captured[0].rows[0].client_id, "device-42");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&captured[0].rows[0].payload_json).unwrap(),
            projected
        );

        // Cassandra: one bound statement keyed by client_id.
        let captured = cassandra_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].keyspace, "telemetry");
        assert_eq!(captured[0].batch.len(), 1);
        assert_eq!(captured[0].batch[0].values[0], b"device-42");
        assert_eq!(
            captured[0].batch[0].partition_token,
            broker_connectors::murmur3_token(b"device-42")
        );

        // Couchbase: one document under client_id::timestamp.
        let captured = couchbase_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].bucket, "telemetry");
        assert_eq!(captured[0].scope, "_default");
        assert_eq!(captured[0].collection, "_default");
        assert_eq!(captured[0].items.len(), 1);
        assert!(captured[0].items[0].key.starts_with("device-42::"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&captured[0].items[0].body).unwrap()
                ["temp"],
            serde_json::json!(22.5)
        );

        // Below-threshold telemetry fires nothing anywhere.
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "device-42", "temp": 10.0 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(mongo_transport.captured().len(), 1);
        assert_eq!(mssql_transport.captured().len(), 1);
        assert_eq!(cassandra_transport.captured().len(), 1);
        assert_eq!(couchbase_transport.captured().len(), 1);
    }

    /// Time-series e2e (INDRA-221): one ingress event routes through
    /// streaming SQL `INTO connector(...)` rules and fans out
    /// simultaneously to the TDengine, IoTDB, Timestream and DynamoDB
    /// mocks with zero drops. All transports are in-memory.
    #[tokio::test]
    async fn test_into_fans_out_to_timeseries_sinks() {
        use broker_connectors::{
            DynamoDbSink, DynamoDbSinkConfig, IotDbSink, IotDbSinkConfig, MockDynamoDbTransport,
            MockIotDbTransport, MockTdengineTransport, MockTimestreamTransport, TdengineSink,
            TdengineSinkConfig, TimestreamSink, TimestreamSinkConfig,
        };
        use std::collections::HashMap;

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);

        // TDengine super-table rows (auto-flush every row).
        let tdengine_transport = Arc::new(MockTdengineTransport::new());
        let tdengine = Arc::new(
            TdengineSink::new(
                TdengineSinkConfig {
                    endpoint: "http://127.0.0.1:6041/rest/sql".to_string(),
                    database: "power".to_string(),
                    stable_name: "meters".to_string(),
                    subtable_template: "d_${client_id}".to_string(),
                    auth: broker_connectors::TdengineAuth::Basic {
                        username: "root".to_string(),
                        password: "taosdata".to_string(),
                    },
                    tags_template: HashMap::new(),
                    metrics_template: HashMap::from([
                        (
                            "temperature".to_string(),
                            "${payload.temperature}".to_string(),
                        ),
                        ("humidity".to_string(), "${payload.humidity}".to_string()),
                    ]),
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(20),
                    max_retries: Some(4),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                tdengine_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("tdengine-sink", tdengine.clone());

        // IoTDB tablet rows (auto-flush every row).
        let iotdb_transport = Arc::new(MockIotDbTransport::new());
        let iotdb = Arc::new(
            IotDbSink::new(
                IotDbSinkConfig {
                    endpoint: "http://127.0.0.1:18080/rest/v2".to_string(),
                    device_path_template: "root.factory.${payload.plant_id}.${client_id}"
                        .to_string(),
                    auth: broker_connectors::IotDbAuth {
                        username: "root".to_string(),
                        password: "root".to_string(),
                    },
                    is_aligned: false,
                    measurements: vec!["temperature".to_string(), "humidity".to_string()],
                    data_types: vec![
                        broker_connectors::IotDbDataType::Double,
                        broker_connectors::IotDbDataType::Double,
                    ],
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(10),
                    max_retries: Some(3),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                iotdb_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("iotdb-sink", iotdb.clone());

        // Timestream multi-measure records (auto-flush every row).
        let timestream_transport = Arc::new(MockTimestreamTransport::new());
        let timestream = Arc::new(
            TimestreamSink::new(
                TimestreamSinkConfig {
                    database_name: "iot_database".to_string(),
                    table_name: "telemetry".to_string(),
                    region: "us-east-1".to_string(),
                    endpoint: None,
                    access_key_id: "AKID".to_string(),
                    secret_access_key: "secret".to_string(),
                    session_token: None,
                    dimensions: HashMap::from([(
                        "device_id".to_string(),
                        "${client_id}".to_string(),
                    )]),
                    time_unit: broker_connectors::TimestreamTimeUnit::Milliseconds,
                    measure_name_template: Some("sensor_metrics".to_string()),
                    multi_measure_mappings: HashMap::from([
                        ("temperature".to_string(), "DOUBLE".to_string()),
                        ("humidity".to_string(), "DOUBLE".to_string()),
                    ]),
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(20),
                    max_retries: Some(4),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                timestream_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("timestream-sink", timestream.clone());

        // DynamoDB items (auto-flush every row).
        let dynamodb_transport = Arc::new(MockDynamoDbTransport::new());
        let dynamodb = Arc::new(
            DynamoDbSink::new(
                DynamoDbSinkConfig {
                    table_name: "telemetry_table".to_string(),
                    region: "us-east-1".to_string(),
                    endpoint: None,
                    access_key_id: "AKID".to_string(),
                    secret_access_key: "secret".to_string(),
                    session_token: None,
                    partition_key: broker_connectors::DynamoKeyConfig {
                        name: "device_id".to_string(),
                        template: "${client_id}".to_string(),
                        key_type: "S".to_string(),
                    },
                    sort_key: None,
                    ttl_attribute: None,
                    ttl_secs: None,
                    attributes_mapping: HashMap::from([(
                        "temperature".to_string(),
                        "${payload.temperature}".to_string(),
                    )]),
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(10),
                    max_retries: Some(4),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                dynamodb_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("dynamodb-sink", dynamodb.clone());

        // One INTO rule per store over the same telemetry stream.
        for (id, connector) in [
            ("tdengine-rule", "tdengine-sink"),
            ("iotdb-rule", "iotdb-sink"),
            ("timestream-rule", "timestream-sink"),
            ("dynamodb-rule", "dynamodb-sink"),
        ] {
            engine
                .create_rule(
                    id.to_string(),
                    TopicFilter::new("sensors/+").unwrap(),
                    Some(format!(
                        r#"SELECT client_id, plant_id, temperature, humidity FROM "sensors/+" WHERE temperature > 20.0 INTO connector("{connector}")"#
                    )),
                    true,
                    vec![],
                )
                .expect("rule creates");
        }

        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(
                    br#"{ "client_id": "sensor101", "plant_id": "plant1", "temperature": 24.5, "humidity": 61.2 }"#,
                ),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        // TDengine: one INSERT with the sub-table + measures.
        let captured = tdengine_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].database, "power");
        assert!(captured[0]
            .sql
            .starts_with("INSERT INTO d_sensor101 USING meters TAGS ()"));
        assert!(captured[0].sql.contains("61.2, 24.5"));

        // IoTDB: one tablet on the hierarchical device path.
        let captured = iotdb_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].tablet.device, "root.factory.plant1.sensor101");
        assert_eq!(captured[0].tablet.values.len(), 1);
        assert_eq!(captured[0].tablet.values[0][0], serde_json::json!(24.5));
        assert_eq!(captured[0].tablet.values[0][1], serde_json::json!(61.2));

        // Timestream: one multi-measure record with dimensions.
        let captured = timestream_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].database, "iot_database");
        assert_eq!(captured[0].records.len(), 1);
        assert_eq!(captured[0].records[0].measure_name, "sensor_metrics");
        assert!(captured[0].records[0]
            .dimensions
            .iter()
            .any(|(name, value)| name == "device_id" && value == "sensor101"));
        assert!(captured[0].records[0]
            .measures
            .iter()
            .any(|(name, value, measure_type)| name == "temperature"
                && value == "24.5"
                && measure_type == "DOUBLE"));

        // DynamoDB: one item keyed by client_id with the unpacked doc.
        let captured = dynamodb_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].table, "telemetry_table");
        assert_eq!(captured[0].items.len(), 1);
        let item: serde_json::Value = serde_json::from_str(&captured[0].items[0].body).unwrap();
        assert_eq!(item["device_id"], serde_json::json!({"S": "sensor101"}));
        assert_eq!(item["temperature"], serde_json::json!({"N": "24.5"}));

        // Below-threshold telemetry fires nothing anywhere.
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "sensor101", "temperature": 10.0 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(tdengine_transport.captured().len(), 1);
        assert_eq!(iotdb_transport.captured().len(), 1);
        assert_eq!(timestream_transport.captured().len(), 1);
        assert_eq!(dynamodb_transport.captured().len(), 1);
    }

    /// Lakehouse e2e (INDRA-222): one ingress event routes through
    /// streaming SQL `INTO connector(...)` rules and fans out
    /// simultaneously to the Snowflake, Databricks, Doris, BigQuery
    /// and Redshift mocks with zero drops. All transports in-memory.
    #[tokio::test]
    async fn test_into_fans_out_to_lakehouse_sinks() {
        use broker_connectors::{
            BigQuerySink, BigQuerySinkConfig, DatabricksSink, DatabricksSinkConfig, DorisSink,
            DorisSinkConfig, MockBigQueryTransport, MockDatabricksTransport, MockDorisTransport,
            MockRedshiftTransport, MockSnowflakeTransport, RedshiftSink, RedshiftSinkConfig,
            SnowflakeSink, SnowflakeSinkConfig,
        };
        use std::collections::HashMap;

        // Test-only RSA key (openssl-generated, never deployed).
        const SNOWFLAKE_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCwQ2w63oB3FtHg\n7xysQK8MuX9S0WkbAVlxWpLHDNIdRVxA9Ra2gFFpKy8jX45UMSow6Yny7IvYWFzZ\nL4y9yoFiqu+LxhlJHIO6JO8+ZmeBoNwuDiIzgesbZwjyQiQ2M7p/4c18a2ffGPWF\nBETT7uVwVKJ3hTp97RN7Mc1/eFMimuT/TC11I+sFCZUHgrbhEG3L5Gg3RJ2MKbcX\nGEIxjFDJdLJ9RK0BopD6lxR1a4zeYr+iF/m3+JeJPAaS15yMD+sB1g5C7XZ1OIsB\nNBBnHWHpNhYO2IrCc9lZeSSzSkbRC6k1oqvTurFRzHWZqBKQGYnH8BftubIPSTBg\nU/BM4rR3AgMBAAECggEAHSRwmwUZoVb1CWcPSw2Aw65RtkwoQA5Hjv3GIcHlZXCH\n0beT80Wg8C3zI7qTSik8zAx4weDJOFJXu5LohqKaJMmVRHtSx+s+fkLICX2d5GlH\nrhepIPH8gLHW4VL9MLb5wVYAhu8tI845Ha54gL/RUHK1z+QHqTVO0MIJs2cd+6zx\nKsAtnqEQJMFpl1D0y0uutuboK4soHJMyRyrHBNWdgfzmTrCsngzu2zVM4aZh/gQY\nHcQgJ1rK6Wnen/GGPrNluwWU+bfLdlWO2qiXXwGLfhyx2H6cuROGdoU607BFJNpM\nkAudvEuLa0fOi1ym6lJ5pcJ6pSLkbeveW6+thkO2fQKBgQDXc2GiKx15vQHmdDmZ\nUJEiPJ+hSry5fjaowzrfgqJHyeNfUjnM/E9WlNn2AuxKDWGc3UNEr6jB9V7leKev\nQaPB2LAgXt0YVHmyim51/gTDguE9TOTGWqL4npZG9Nqh8xMxWt08ULvknkOQQOso\nzCoZQYlG4BHegAG7n0/5IN7HdQKBgQDRb/VbJ9iE0wtY/A3e3eWPbGfTF7AZREUu\n/mt94tFEWDDvedX1EPi4DJgPMqQ4eHnBZb3+G7jPcRdm6/KQzR5QiRMHSylfIQRH\nLqqfHBzZDDSZINLW1FMReC9xGfkRoG0Tlt2iQzXOy90+uE/9k5BGSbQNakfVDXJs\n3JAHDMy6uwKBgQCaazxC+xv5MRq3jf3qgPBE1aaj9+kkGe4bLzJ3GC4vveeVXl3H\nKd/DcpR12sp4mPapc3zPMgeGXNNTLRMiba1tNl2mFdfppEJFUSqyrwnDB39gbEhc\nUoIUJ7YVzVEWWh4bdcCzhjnlNfm+3oitiQdzaqF1hwvHqX+Udi7fpEuIMQKBgQC5\nu0bkQu7Rw/MRQ93tIe19ho6AdkZV8eREq52Z8vbQXEFxbiOfBCD93zVObQOTjMu1\nBcw6uEzpsgol3OKtJSpYE2eLlU0oLriDg9AN8DlpBljy31f66iqMmH/CFl16E0II\nGEeOqXnjXYlkIMHXR/CvVJdXOkRfnWA3SFZ12hUJFwKBgD8JlGTyrVfNsNMOaTDV\nNopoYnUQ6ljFmJi6TGmnkliCRXPuqBl+2hVxiKeWI2MprJ5Ya8qLbL6M56uCwAD2\nqEhvjEuatma5rJyE5NULOjAXA5tLw9qM1M9j1FNOaXnFC9/Yii2a49R8zu05wRB2\nH+dMMSDXQ4EHHYcKIFJjDbxn\n-----END PRIVATE KEY-----\n";

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);

        // Snowflake streaming rows (auto-flush every row).
        let snowflake_transport = Arc::new(MockSnowflakeTransport::new());
        let snowflake = Arc::new(
            SnowflakeSink::new(
                SnowflakeSinkConfig {
                    account: "xy12345.us-east-1".to_string(),
                    user: "indra_loader".to_string(),
                    database: "IOT".to_string(),
                    schema: "PUBLIC".to_string(),
                    table_template: "TELEMETRY_${topic}".to_string(),
                    private_key_pem: SNOWFLAKE_TEST_KEY.to_string(),
                    endpoint: None,
                    role: None,
                    channel: "INDRA_CHANNEL".to_string(),
                    column_mappings: HashMap::from([
                        ("device_id".to_string(), "${client_id}".to_string()),
                        (
                            "temperature".to_string(),
                            "${payload.temperature}".to_string(),
                        ),
                    ]),
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(20),
                    max_retries: Some(4),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                snowflake_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("snowflake-sink", snowflake.clone());

        // Databricks lakehouse rows (auto-flush every row).
        let databricks_transport = Arc::new(MockDatabricksTransport::new());
        let databricks = Arc::new(
            DatabricksSink::new(
                DatabricksSinkConfig {
                    host: "dbc-test.cloud.databricks.com".to_string(),
                    token: "dapi-test".to_string(),
                    catalog: "main".to_string(),
                    schema: "default".to_string(),
                    table_template: "sensor_readings".to_string(),
                    http_path: None,
                    partition_key_template: None,
                    column_mappings: HashMap::from([
                        ("device_id".to_string(), "${client_id}".to_string()),
                        (
                            "temperature".to_string(),
                            "${payload.temperature}".to_string(),
                        ),
                    ]),
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(10),
                    max_retries: Some(3),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                databricks_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("databricks-sink", databricks.clone());

        // Doris stream load (auto-flush every row).
        let doris_transport = Arc::new(MockDorisTransport::new());
        let doris = Arc::new(
            DorisSink::new(
                DorisSinkConfig {
                    fe_host: "127.0.0.1".to_string(),
                    http_port: 8030,
                    database: "telemetry".to_string(),
                    table_template: "events".to_string(),
                    auth: broker_connectors::DorisAuth {
                        username: "root".to_string(),
                        password: String::new(),
                    },
                    format: broker_connectors::DorisFormat::Json,
                    jsonpaths: None,
                    strip_outer_array: true,
                    max_filter_ratio: Some(0.0),
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(10),
                    max_retries: Some(4),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                doris_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("doris-sink", doris.clone());

        // BigQuery streaming rows (auto-flush every row).
        let bigquery_transport = Arc::new(MockBigQueryTransport::new());
        let bigquery = Arc::new(
            BigQuerySink::new(
                BigQuerySinkConfig {
                    project_id: "my-iot-project".to_string(),
                    dataset_id: "telemetry".to_string(),
                    table_template: "sensor_logs".to_string(),
                    endpoint: None,
                    auth: broker_connectors::GcpAuth::None,
                    ignore_unknown_values: true,
                    skip_invalid_rows: false,
                    template_suffix: None,
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(20),
                    max_retries: Some(4),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                bigquery_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("bigquery-sink", bigquery.clone());

        // Redshift statements (auto-flush every row).
        let redshift_transport = Arc::new(MockRedshiftTransport::new());
        let redshift = Arc::new(
            RedshiftSink::new(
                RedshiftSinkConfig {
                    database: "analytics".to_string(),
                    table_template: "sensor_logs".to_string(),
                    cluster_identifier: None,
                    workgroup_name: Some("iot-workgroup".to_string()),
                    region: "us-east-1".to_string(),
                    endpoint: None,
                    access_key_id: "AKID".to_string(),
                    secret_access_key: "secret".to_string(),
                    session_token: None,
                    db_user: None,
                    sql_template: None,
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(20),
                    max_retries: Some(4),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                redshift_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("redshift-sink", redshift.clone());

        // One INTO rule per lakehouse over the same telemetry stream.
        for (id, connector) in [
            ("snowflake-rule", "snowflake-sink"),
            ("databricks-rule", "databricks-sink"),
            ("doris-rule", "doris-sink"),
            ("bigquery-rule", "bigquery-sink"),
            ("redshift-rule", "redshift-sink"),
        ] {
            engine
                .create_rule(
                    id.to_string(),
                    TopicFilter::new("factory/+").unwrap(),
                    Some(format!(
                        r#"SELECT client_id, temperature FROM "factory/+" WHERE temperature > 70.0 INTO connector("{connector}")"#
                    )),
                    true,
                    vec![],
                )
                .expect("rule creates");
        }

        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("factory/temp").unwrap(),
                &Bytes::from_static(
                    br#"{ "client_id": "sensor-101", "temperature": 75.2, "status": "normal" }"#,
                ),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        let projected = serde_json::json!({"client_id": "sensor-101", "temperature": 75.2});

        // Snowflake: uppercased table with mapped columns + metadata.
        let captured = snowflake_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].table, "TELEMETRY_FACTORY_TEMP");
        assert_eq!(captured[0].rows.len(), 1);
        let fields: HashMap<String, &serde_json::Value> = captured[0].rows[0]
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();
        assert_eq!(fields["DEVICE_ID"], &serde_json::json!("sensor-101"));
        assert_eq!(fields["TEMPERATURE"], &serde_json::json!(75.2));

        // Databricks: qualified INSERT with typed params.
        let captured = databricks_transport.captured();
        assert_eq!(captured.len(), 1);
        assert!(captured[0]
            .statement
            .starts_with("INSERT INTO main.default.sensor_readings"));
        assert!(captured[0]
            .params
            .iter()
            .any(|param| param.value == "sensor-101"));

        // Doris: one JSON array load with the projected row.
        let captured = doris_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].table, "events");
        let body: serde_json::Value = serde_json::from_slice(&captured[0].body).unwrap();
        assert_eq!(body.as_array().expect("array").len(), 1);
        assert_eq!(body[0]["temperature"], serde_json::json!(75.2));

        // BigQuery: one row with a UUID insert id.
        let captured = bigquery_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].table, "sensor_logs");
        assert_eq!(captured[0].rows.len(), 1);
        assert_eq!(captured[0].rows[0].json, projected);
        assert_eq!(captured[0].rows[0].insert_id.len(), 36);

        // Redshift: one statement carrying the projected payload.
        let captured = redshift_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].workgroup_name.as_deref(), Some("iot-workgroup"));
        assert_eq!(captured[0].statements.len(), 1);
        assert!(captured[0].statements[0].contains("'sensor-101'"));

        // Below-threshold telemetry fires nothing anywhere.
        engine
            .dispatch_ingress(
                &Topic::new("factory/temp").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "sensor-101", "temperature": 60.0 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(snowflake_transport.captured().len(), 1);
        assert_eq!(databricks_transport.captured().len(), 1);
        assert_eq!(doris_transport.captured().len(), 1);
        assert_eq!(bigquery_transport.captured().len(), 1);
        assert_eq!(redshift_transport.captured().len(), 1);
    }

    #[tokio::test]
    async fn test_into_malformed_rejected_at_creation() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let err = engine
            .create_rule(
                "broken-into".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT * FROM "sensors/+" WHERE temperature > 0 INTO connector()"#
                        .to_string(),
                ),
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
            MemoryPgTransport, MemoryRedisTransport, PostgreSqlSink, PostgreSqlSinkConfig,
            RedisCommandKind, RedisSink, RedisSinkConfig,
        };

        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);

        let pg_transport = Arc::new(MemoryPgTransport::new());
        let pg = Arc::new(
            PostgreSqlSink::new(
                PostgreSqlSinkConfig {
                    connection_url: "postgresql://u:p@db/db".to_string(),
                    sql_template:
                        "INSERT INTO device_status (topic, qos, payload) VALUES ($1, $2, $3::jsonb)"
                            .to_string(),
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
        assert!(
            encoded.contains("stream:devices/thermostat/status"),
            "stream key"
        );
        assert!(encoded.contains("MAXLEN"), "trim directive");
        assert!(
            encoded.contains(r#""status":"online""#),
            "projected payload"
        );
        assert!(!encoded.contains("hide_me"), "secrets never leave the rule");
    }

    /// Sprint 25 studio fanout (INDRA-224): one ingress event routes
    /// through five streaming SQL `INTO connector(...)` rules and lands
    /// simultaneously in the Azure Blob, Tablestore, S3 Tables,
    /// Confluent and RocketMQ mocks. All transports are in-memory.
    #[tokio::test]
    async fn test_into_fans_out_to_storage_messaging_sinks() {
        use broker_connectors::{
            AttributeColumnMapping, AttributeColumnType, AzureBlobAuth, AzureBlobSink,
            AzureBlobSinkConfig, ConfluentKafkaConfig, ConfluentKafkaSink, IcebergPartitionField,
            IcebergTransform, MemoryConfluentTransport, MockAzureBlobTransport,
            MockRocketMqTransport, MockS3TablesTransport, MockTablestoreTransport,
            PrimaryKeyMapping, PrimaryKeyType, RocketMqSink, RocketMqSinkConfig, S3TablesSink,
            S3TablesSinkConfig, SaslMechanism, TablestoreSink, TablestoreSinkConfig,
        };

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);

        // Azure Blob (auto-flush every row, SharedKey proof runs).
        let blob_transport = Arc::new(MockAzureBlobTransport::new());
        let blob = Arc::new(
            AzureBlobSink::new(
                AzureBlobSinkConfig {
                    account_name: "mydeviceblobs".to_string(),
                    container_name: "telemetry".to_string(),
                    endpoint: None,
                    auth: AzureBlobAuth::SharedKey {
                        account_key:
                            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".to_string(),
                    },
                    blob_path_template:
                        "telemetry/year=${date.year}/month=${date.month}/day=${date.day}/${batch_id}.json"
                            .to_string(),
                    compression: broker_connectors::AzureBlobCompression::None,
                    max_records_per_blob: Some(1),
                    max_bytes_per_blob: None,
                    flush_interval_secs: 60,
                    buffer_capacity: None,
                    timeout_ms: None,
                },
                blob_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("blob_store", blob.clone());

        // Tablestore (auto-flush every row).
        let ots_transport = Arc::new(MockTablestoreTransport::new());
        let ots = Arc::new(
            TablestoreSink::new(
                TablestoreSinkConfig {
                    endpoint: "https://test-instance.cn-hangzhou.ots.aliyuncs.com".to_string(),
                    instance_name: "test-instance".to_string(),
                    table_name: "telemetry".to_string(),
                    access_key_id: "test-key-id".to_string(),
                    access_key_secret: "test-secret".to_string(),
                    primary_keys: vec![PrimaryKeyMapping {
                        name: "device_id".to_string(),
                        source: "${client_id}".to_string(),
                        data_type: PrimaryKeyType::String,
                    }],
                    attribute_columns: vec![AttributeColumnMapping {
                        name: "val".to_string(),
                        source: "${payload.sensor_val}".to_string(),
                        data_type: AttributeColumnType::Double,
                    }],
                    batch_size: Some(1),
                    buffer_capacity: None,
                    linger_ms: Some(10),
                    timeout_ms: None,
                },
                ots_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("ots_store", ots.clone());

        // S3 Tables (auto-flush every row).
        let tables_transport = Arc::new(MockS3TablesTransport::new());
        let tables = Arc::new(
            S3TablesSink::new(
                S3TablesSinkConfig {
                    table_bucket_arn:
                        "arn:aws:s3tables:us-east-1:123456789012:bucket/telemetry-bucket"
                            .to_string(),
                    namespace: "production_iot".to_string(),
                    table_name: "device_events".to_string(),
                    region: "us-east-1".to_string(),
                    access_key_id: "AKID".to_string(),
                    secret_access_key: "secret".to_string(),
                    session_token: None,
                    endpoint: None,
                    partition_spec: vec![
                        IcebergPartitionField {
                            source_name: "date".to_string(),
                            transform: IcebergTransform::Day,
                        },
                        IcebergPartitionField {
                            source_name: "device_id".to_string(),
                            transform: IcebergTransform::Identity,
                        },
                    ],
                    target_format: broker_connectors::S3TablesFormat::NdjsonCompressed,
                    batch_size: Some(1),
                    buffer_capacity: None,
                    linger_ms: Some(10),
                    timeout_ms: None,
                },
                tables_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("iceberg_table", tables.clone());

        // Confluent Cloud (auto-flush every row, SASL dummies).
        let confluent_transport = Arc::new(MemoryConfluentTransport::new());
        let confluent = Arc::new(
            ConfluentKafkaSink::new(
                ConfluentKafkaConfig {
                    bootstrap_servers: vec![
                        "pkc-test.us-east-1.aws.confluent.cloud:9092".to_string()
                    ],
                    api_key: "confluent-key".to_string(),
                    api_secret: "confluent-secret".to_string(),
                    auth_mechanism: SaslMechanism::Plain,
                    topic_template: "telemetry-${topic_segment_2}".to_string(),
                    partition_key_template: Some("${client_id}".to_string()),
                    schema_registry: None,
                    partitions: 12,
                    batch_size: Some(1),
                    buffer_capacity: None,
                    timeout_ms: None,
                },
                confluent_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine
            .connectors()
            .register("cloud_kafka", confluent.clone());

        // RocketMQ (auto-flush every row, anonymous proxy).
        let rmq_transport = Arc::new(MockRocketMqTransport::new());
        let rmq = Arc::new(
            RocketMqSink::new(
                RocketMqSinkConfig {
                    endpoints: vec!["127.0.0.1:8081".to_string()],
                    topic: "rocket-telemetry".to_string(),
                    tag_template: Some("${topic_segment_2}".to_string()),
                    keys_template: Some("${client_id}-${message_id}".to_string()),
                    message_group_template: None,
                    access_key: None,
                    secret_key: None,
                    batch_size: Some(1),
                    buffer_capacity: None,
                    linger_ms: Some(10),
                    timeout_ms: None,
                },
                rmq_transport.clone(),
            )
            .expect("valid sink"),
        );
        engine.connectors().register("rocket_producer", rmq.clone());

        // One INTO rule per studio connector.
        for (id, connector) in [
            ("blob-rule", "blob_store"),
            ("ots-rule", "ots_store"),
            ("tables-rule", "iceberg_table"),
            ("confluent-rule", "cloud_kafka"),
            ("rmq-rule", "rocket_producer"),
        ] {
            engine
                .create_rule(
                    id.to_string(),
                    TopicFilter::new("storage/stream/#").unwrap(),
                    Some(format!(
                        r#"SELECT client_id, sensor_val, now() AS ts FROM "storage/stream/#" WHERE sensor_val > 100.0 INTO connector("{connector}")"#
                    )),
                    true,
                    vec![],
                )
                .expect("rule creates");
        }

        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("storage/stream/line1").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "sensor-42", "sensor_val": 150.0 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        // Azure Blob: one object with the projected row.
        let puts = blob_transport.puts();
        assert_eq!(puts.len(), 1);
        assert!(puts[0].path.ends_with("/0.json"), "got {:?}", puts[0].path);
        let row: serde_json::Value =
            serde_json::from_str(String::from_utf8(puts[0].body.clone()).unwrap().trim_end())
                .unwrap();
        assert_eq!(row["payload"]["client_id"], "sensor-42");
        assert_eq!(row["payload"]["sensor_val"], 150.0);
        assert!(row["payload"]["ts"].as_i64().unwrap_or(0) > 0);

        // Tablestore: one typed row (string PK, double attribute).
        let batches = ots_transport.captured();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 1);
        assert_eq!(
            batches[0][0].primary_keys[0].1,
            broker_connectors::OtsValue::String("sensor-42".to_string())
        );
        assert_eq!(
            batches[0][0].attributes[0].1,
            broker_connectors::OtsValue::Double(150.0)
        );

        // S3 Tables: one gzip data file on the day/device partition.
        let files = tables_transport.puts();
        assert_eq!(files.len(), 1);
        assert!(
            files[0].key.contains("device_id=__null__/"),
            "got {:?}",
            files[0].key
        );
        assert!(files[0].key.ends_with(".data.gz"));

        // Confluent: one record on the templated topic, keyed by client.
        let records = confluent_transport.records_flat();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].topic, "telemetry-stream");
        assert_eq!(records[0].key, Some(Bytes::from_static(b"sensor-42")));
        let value: serde_json::Value = serde_json::from_slice(&records[0].value).unwrap();
        assert_eq!(value["sensor_val"], 150.0);

        // RocketMQ: one envelope with tag + business keys.
        let envelopes = rmq_transport.envelopes();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].topic, "rocket-telemetry");
        assert_eq!(envelopes[0].messages.len(), 1);
        assert_eq!(
            envelopes[0].messages[0].system_properties.tag.as_deref(),
            Some("stream")
        );
        assert_eq!(
            envelopes[0].messages[0].system_properties.keys,
            vec!["sensor-42-0".to_string()]
        );

        // Below-threshold telemetry fires nothing anywhere.
        engine
            .dispatch_ingress(
                &Topic::new("storage/stream/line1").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "sensor-42", "sensor_val": 50.0 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(blob_transport.puts().len(), 1);
        assert_eq!(ots_transport.captured().len(), 1);
        assert_eq!(tables_transport.puts().len(), 1);
        assert_eq!(confluent_transport.records_flat().len(), 1);
        assert_eq!(rmq_transport.envelopes().len(), 1);
    }

    /// Sprint 26 studio fanout (INDRA-225): one ingress event routes
    /// through six streaming SQL `INTO connector(...)` rules and lands
    /// simultaneously in the Oracle, CockroachDB, AlloyDB, OpenTSDB,
    /// GreptimeDB, and Datalayers mocks. All transports are in-memory.
    #[tokio::test]
    async fn test_into_fans_out_to_databases_and_timeseries_sinks() {
        use broker_connectors::{
            AlloydbAuth, AlloydbColumnMapping, AlloydbConfig, AlloydbSink, CockroachDbConfig,
            CockroachDbSink, DatalayersConfig, DatalayersSink, GreptimeDbConfig, GreptimeDbSink,
            GreptimeFormat, GreptimePrecision, MockAlloydbTransport, MockCockroachDbTransport,
            MockDatalayersTransport, MockGreptimeDbTransport, MockOpenTsdbTransport,
            MockOracleTransport, OpenTsdbCompression, OpenTsdbConfig, OpenTsdbProtocol,
            OpenTsdbSink, OracleSink, OracleSinkConfig,
        };

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);

        // 1. Oracle (MERGE INTO atomic upsert)
        let oracle_transport = Arc::new(MockOracleTransport::new());
        let oracle = Arc::new(
            OracleSink::new(
                OracleSinkConfig {
                    url: "https://oracle-host:8080/ords/admin/_/sql".to_string(),
                    schema: "ADMIN".to_string(),
                    table: "telemetry".to_string(),
                    username: "admin".to_string(),
                    password: "secret".to_string(),
                    custom_upsert: None,
                    key_columns: vec!["device_id".to_string()],
                    batch_size: Some(1),
                    buffer_capacity: None,
                    timeout_ms: None,
                },
                oracle_transport.clone(),
            )
            .expect("valid oracle sink"),
        );
        engine.connectors().register("oracle_sink", oracle.clone());

        // 2. CockroachDB (multi-row UPSERT)
        let cockroach_transport = Arc::new(MockCockroachDbTransport::new());
        let cockroach = Arc::new(
            CockroachDbSink::new(
                CockroachDbConfig {
                    connection_string: "postgresql://root@127.0.0.1:26257/defaultdb".to_string(),
                    table: "telemetry".to_string(),
                    upsert_conflict_columns: vec!["device_id".to_string()],
                    batch_size: Some(1),
                    max_retry_attempts: 5,
                    buffer_capacity: None,
                    timeout_ms: None,
                },
                cockroach_transport.clone(),
            )
            .expect("valid cockroach sink"),
        );
        engine
            .connectors()
            .register("cockroach_sink", cockroach.clone());

        // 3. AlloyDB (accelerated multi-row INSERT)
        let alloydb_transport = Arc::new(MockAlloydbTransport::new());
        let alloydb = Arc::new(
            AlloydbSink::new(
                AlloydbConfig {
                    host: "10.0.0.1".to_string(),
                    port: 5432,
                    database: "telemetry".to_string(),
                    username: "postgres".to_string(),
                    auth: AlloydbAuth::Password {
                        password: "secret".to_string(),
                    },
                    table: "readings".to_string(),
                    column_mappings: vec![
                        AlloydbColumnMapping {
                            db_column: "device_id".to_string(),
                            source_field: "device_id".to_string(),
                            data_type: None,
                        },
                        AlloydbColumnMapping {
                            db_column: "temp".to_string(),
                            source_field: "temp".to_string(),
                            data_type: None,
                        },
                    ],
                    batch_size: Some(1),
                    buffer_capacity: None,
                    timeout_ms: None,
                },
                alloydb_transport.clone(),
            )
            .expect("valid alloydb sink"),
        );
        engine
            .connectors()
            .register("alloydb_sink", alloydb.clone());

        // 4. OpenTSDB (HTTP PUT summary)
        let opentsdb_transport = Arc::new(MockOpenTsdbTransport::new());
        let mut tags = std::collections::HashMap::new();
        tags.insert("device".to_string(), "${payload.device_id}".to_string());
        let opentsdb = Arc::new(
            OpenTsdbSink::new(
                OpenTsdbConfig {
                    endpoint: "http://127.0.0.1:4242".to_string(),
                    protocol: OpenTsdbProtocol::Http,
                    metric_template: "factory.temp".to_string(),
                    tag_mappings: tags,
                    value_field: "temp".to_string(),
                    summary: true,
                    compression: OpenTsdbCompression::None,
                    batch_size: Some(1),
                    buffer_capacity: None,
                    timeout_ms: None,
                },
                opentsdb_transport.clone(),
            )
            .expect("valid opentsdb sink"),
        );
        engine
            .connectors()
            .register("opentsdb_sink", opentsdb.clone());

        // 5. GreptimeDB (SQL INSERT / Influx Line Protocol)
        let greptimedb_transport = Arc::new(MockGreptimeDbTransport::new());
        let greptimedb = Arc::new(
            GreptimeDbSink::new(
                GreptimeDbConfig {
                    endpoint: "http://127.0.0.1:4000".to_string(),
                    database: "public".to_string(),
                    auth: None,
                    format: GreptimeFormat::SqlInsert,
                    table_template: "sensor_readings".to_string(),
                    timestamp_precision: GreptimePrecision::Millisecond,
                    batch_size: Some(1),
                    buffer_capacity: None,
                    timeout_ms: None,
                },
                greptimedb_transport.clone(),
            )
            .expect("valid greptimedb sink"),
        );
        engine
            .connectors()
            .register("greptimedb_sink", greptimedb.clone());

        // 6. Datalayers (industrial time-series write)
        let datalayers_transport = Arc::new(MockDatalayersTransport::new());
        let datalayers = Arc::new(
            DatalayersSink::new(
                DatalayersConfig {
                    endpoint: "http://127.0.0.1:8360".to_string(),
                    database: "telemetry".to_string(),
                    table: "metrics".to_string(),
                    auth_token: Some("secret-bearer-token".to_string()),
                    timestamp_field: None,
                    tag_columns: vec!["device_id".to_string()],
                    field_columns: vec!["temp".to_string()],
                    batch_size: Some(1),
                    buffer_capacity: None,
                    timeout_ms: None,
                },
                datalayers_transport.clone(),
            )
            .expect("valid datalayers sink"),
        );
        engine
            .connectors()
            .register("datalayers_sink", datalayers.clone());

        // Six INTO rules routing to the six database & TS sinks
        for (id, connector) in [
            ("oracle-rule", "oracle_sink"),
            ("cockroach-rule", "cockroach_sink"),
            ("alloydb-rule", "alloydb_sink"),
            ("opentsdb-rule", "opentsdb_sink"),
            ("greptimedb-rule", "greptimedb_sink"),
            ("datalayers-rule", "datalayers_sink"),
        ] {
            engine
                .create_rule(
                    id.to_string(),
                    TopicFilter::new("factory/+/telemetry").unwrap(),
                    Some(format!(
                        r#"SELECT device_id, temp FROM "factory/+/telemetry" WHERE temp > 50.0 INTO connector("{connector}")"#
                    )),
                    true,
                    vec![],
                )
                .expect("rule creates");
        }

        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());

        // Ingress above threshold: temp = 68.5 > 50.0
        engine
            .dispatch_ingress(
                &Topic::new("factory/line1/telemetry").unwrap(),
                &Bytes::from_static(br#"{ "device_id": "sensor-01", "temp": 68.5 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        // Verify executions inside isolated block so all MutexGuards drop before next await
        {
            let ora_execs = oracle_transport.executions.lock();
            assert_eq!(ora_execs.len(), 1);
            assert!(ora_execs[0].statement.contains("MERGE INTO telemetry"));

            let crdb_execs = cockroach_transport.executions.lock();
            assert_eq!(crdb_execs.len(), 1);
            assert!(
                crdb_execs[0].query.contains("INTO telemetry")
                    && crdb_execs[0]
                        .query
                        .contains("ON CONFLICT (device_id) DO UPDATE SET")
            );

            let alloy_execs = alloydb_transport.executions.lock();
            assert_eq!(alloy_execs.len(), 1);
            assert!(alloy_execs[0].query.contains("INSERT INTO readings"));

            let opentsdb_pts = opentsdb_transport.captured_points.lock();
            assert_eq!(opentsdb_pts.len(), 1);
            assert_eq!(opentsdb_pts[0].metric, "factory.temp");
            assert_eq!(opentsdb_pts[0].value, 68.5);

            let grep_sqls = greptimedb_transport.captured_sqls.lock();
            assert_eq!(grep_sqls.len(), 1);
            assert!(grep_sqls[0].contains("INSERT INTO sensor_readings"));

            let dl_reqs = datalayers_transport.captured_requests.lock();
            assert_eq!(dl_reqs.len(), 1);
            assert_eq!(dl_reqs[0].table, "metrics");
            assert_eq!(dl_reqs[0].records.len(), 1);
            assert_eq!(
                dl_reqs[0].records[0].tags.get("device_id").unwrap(),
                "sensor-01"
            );
        }

        // Ingress below threshold: temp = 32.0 <= 50.0 -> no actions should fire
        engine
            .dispatch_ingress(
                &Topic::new("factory/line1/telemetry").unwrap(),
                &Bytes::from_static(br#"{ "device_id": "sensor-01", "temp": 32.0 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;

        assert_eq!(oracle_transport.executions.lock().len(), 1);
        assert_eq!(cockroach_transport.executions.lock().len(), 1);
        assert_eq!(alloydb_transport.executions.lock().len(), 1);
        assert_eq!(opentsdb_transport.captured_points.lock().len(), 1);
        assert_eq!(greptimedb_transport.captured_sqls.lock().len(), 1);
        assert_eq!(datalayers_transport.captured_requests.lock().len(), 1);
    }

    // ------------------------------------------------------------------
    // R22: forward failures counted in action metrics, throttled log.
    // ------------------------------------------------------------------

    #[derive(Debug, Default)]
    struct AlwaysFailConnector;

    #[async_trait]
    impl broker_connectors::Sink for AlwaysFailConnector {
        async fn send(
            &self,
            _topic: &Topic,
            _payload: &Bytes,
            _qos: QoS,
        ) -> Result<(), broker_connectors::ConnectorError> {
            Err(broker_connectors::ConnectorError::Dispatch(
                "target down".to_string(),
            ))
        }

        fn kind(&self) -> &'static str {
            "always-fail"
        }
    }

    fn failing_forward_engine(connector_id: &str) -> (RuleEngine, Arc<dyn BrokerSink>) {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        engine
            .connectors()
            .register(connector_id, Arc::new(AlwaysFailConnector));
        engine
            .create_rule(
                "forward-fail".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                None,
                true,
                vec![RuleAction::ForwardConnector {
                    connector_id: connector_id.to_string(),
                }],
            )
            .expect("rule creates");
        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        (engine, sink)
    }

    #[tokio::test]
    async fn test_forward_failures_counted_in_action_metrics() {
        let (engine, sink) = failing_forward_engine("down");
        let topic = Topic::new("sensors/temperature").unwrap();
        for _ in 0..50 {
            engine
                .dispatch_ingress(
                    &topic,
                    &Bytes::from_static(b"21.5C"),
                    QoS::AtMostOnce,
                    &sink,
                )
                .await;
        }
        let rule = engine.get_rule("rule-1").expect("rule stored");
        assert_eq!(rule.matched_cnt.load(Ordering::Relaxed), 50);
        assert_eq!(rule.passed_cnt.load(Ordering::Relaxed), 50);
        assert_eq!(rule.actions_total_cnt.load(Ordering::Relaxed), 50);
        assert_eq!(rule.actions_success_cnt.load(Ordering::Relaxed), 0);
        assert_eq!(rule.actions_failed_cnt.load(Ordering::Relaxed), 50);
    }

    #[test]
    fn test_forward_failure_throttle_decisions() {
        let throttle = parking_lot::Mutex::new(HashMap::new());
        assert_eq!(
            forward_failure_should_log(&throttle, "rule-1", "down", 1_000),
            Some(0)
        );
        for now in 1_001..=1_049 {
            assert_eq!(
                forward_failure_should_log(&throttle, "rule-1", "down", now),
                None,
                "failures inside the window must only be counted"
            );
        }
        assert_eq!(
            forward_failure_should_log(
                &throttle,
                "rule-1",
                "down",
                1_000 + FORWARD_FAILURE_LOG_WINDOW_MS
            ),
            Some(49)
        );
        assert_eq!(
            forward_failure_should_log(
                &throttle,
                "rule-1",
                "down",
                1_000 + FORWARD_FAILURE_LOG_WINDOW_MS
            ),
            None
        );
        assert_eq!(
            forward_failure_should_log(&throttle, "rule-1", "other", 1_050),
            Some(0)
        );
    }

    #[tokio::test]
    async fn test_forward_success_counted() {
        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
        let recorder: Arc<RecordingConnector> = Arc::new(RecordingConnector::default());
        engine.connectors().register("up", recorder);
        engine
            .create_rule(
                "forward-ok".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                None,
                true,
                vec![RuleAction::ForwardConnector {
                    connector_id: "up".to_string(),
                }],
            )
            .expect("rule creates");
        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        let topic = Topic::new("sensors/temperature").unwrap();
        for _ in 0..5 {
            engine
                .dispatch_ingress(
                    &topic,
                    &Bytes::from_static(b"21.5C"),
                    QoS::AtMostOnce,
                    &sink,
                )
                .await;
        }
        let rule = engine.get_rule("rule-1").expect("rule stored");
        assert_eq!(rule.actions_total_cnt.load(Ordering::Relaxed), 5);
        assert_eq!(rule.actions_success_cnt.load(Ordering::Relaxed), 5);
        assert_eq!(rule.actions_failed_cnt.load(Ordering::Relaxed), 0);
    }

    /// Unique scratch data dir under the OS temp dir (no dev-dependency).
    fn unique_rules_data_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "broker-rules-{prefix}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn persisted_rule_snapshot(rule: &Rule) -> (String, String, String, Option<String>, bool) {
        (
            rule.id.clone(),
            rule.name.clone(),
            rule.topic_filter.as_str().to_string(),
            rule.sql_query.clone(),
            rule.enabled,
        )
    }

    fn persisted_actions_value(rule: &Rule) -> serde_json::Value {
        serde_json::to_value(&rule.actions).expect("actions serialise")
    }

    #[tokio::test]
    async fn rules_survive_restart() {
        let dir = unique_rules_data_dir("restart");
        let registry =
            Arc::new(broker_config::ConfigRegistry::load(&dir).expect("fresh data dir loads"));
        let engine = RuleEngine::from_registry(&registry).expect("empty snapshot boots");
        // All three action variants; the republish rule stays disabled.
        engine
            .create_rule(
                "republish-rule".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(r#"SELECT temperature FROM "sensors/+" WHERE temperature > 0"#.to_string()),
                false,
                vec![RuleAction::Republish {
                    topic: Topic::new("alerts/hot").unwrap(),
                    qos: QoS::AtLeastOnce,
                }],
            )
            .expect("republish rule persists");
        engine
            .create_rule(
                "log-rule".to_string(),
                TopicFilter::new("logs/#").unwrap(),
                None,
                true,
                vec![RuleAction::Log],
            )
            .expect("log rule persists");
        engine
            .create_rule(
                "forward-rule".to_string(),
                TopicFilter::new("factory/#").unwrap(),
                Some(r#"SELECT * FROM "factory/#""#.to_string()),
                true,
                vec![RuleAction::ForwardConnector {
                    connector_id: "webhook".to_string(),
                }],
            )
            .expect("forward rule persists");
        assert!(dir.join(broker_config::STATE_FILE_NAME).is_file());
        let before = engine.list_rules();
        assert_eq!(before.len(), 3);

        // Rebuild from the same data dir (simulating a kernel restart).
        let reloaded =
            Arc::new(broker_config::ConfigRegistry::load(&dir).expect("data dir reloads"));
        let restarted = RuleEngine::from_registry(&reloaded).expect("snapshot replays");
        let after = restarted.list_rules();
        assert_eq!(after.len(), 3);
        for (before_rule, after_rule) in before.iter().zip(after.iter()) {
            assert_eq!(
                persisted_rule_snapshot(before_rule),
                persisted_rule_snapshot(after_rule),
                "id/name/filter/sql/enable must round-trip"
            );
            assert_eq!(
                persisted_actions_value(before_rule),
                persisted_actions_value(after_rule),
                "full action list must round-trip without loss"
            );
            // Metric counters are runtime-only and reset to zero.
            assert_eq!(after_rule.matched_cnt.load(Ordering::Relaxed), 0);
        }
        let disabled = restarted
            .get_rule(&before[0].id)
            .expect("disabled rule reloads");
        assert!(!disabled.enabled, "disabled rule stays disabled");
        assert!(
            restarted
                .get_rule(&before[1].id)
                .expect("log rule reloads")
                .enabled
        );
        // The republish variant kept every field (topic + qos).
        let republished = restarted
            .get_rule(&before[0].id)
            .expect("republish rule reloads");
        assert!(matches!(
            &republished.actions[..],
            [RuleAction::Republish { topic, qos }]
                if topic.as_str() == "alerts/hot" && *qos == QoS::AtLeastOnce
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn rule_delete_survives_restart() {
        let dir = unique_rules_data_dir("delete");
        let registry =
            Arc::new(broker_config::ConfigRegistry::load(&dir).expect("fresh data dir loads"));
        let engine = RuleEngine::from_registry(&registry).expect("empty snapshot boots");
        let rule = engine
            .create_rule(
                "temp".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                None,
                true,
                vec![RuleAction::Republish {
                    topic: Topic::new("alerts/all").unwrap(),
                    qos: QoS::AtMostOnce,
                }],
            )
            .expect("rule persists");
        let recorder = Arc::new(RecordingSink::default());
        let sink: Arc<dyn BrokerSink> = recorder.clone();
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(b"21.5C"),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(recorder.published.lock().unwrap().len(), 1);
        assert!(engine.remove_rule(&rule.id).expect("persist rule delete"));

        // Rebuild from the same data dir: the deleted rule stays gone and
        // routing no longer matches it.
        let reloaded =
            Arc::new(broker_config::ConfigRegistry::load(&dir).expect("data dir reloads"));
        let restarted = RuleEngine::from_registry(&reloaded).expect("snapshot replays");
        assert!(restarted.get_rule(&rule.id).is_none());
        assert!(restarted.list_rules().is_empty());
        let recorder_after = Arc::new(RecordingSink::default());
        let sink_after: Arc<dyn BrokerSink> = recorder_after.clone();
        let matched = restarted
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(b"21.5C"),
                QoS::AtMostOnce,
                &sink_after,
            )
            .await;
        assert_eq!(matched, 0);
        assert!(recorder_after.published.lock().unwrap().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn invalid_stored_rule_fails_boot_loudly() {
        // An empty connector id passes TOML parsing but must fail boot
        // loudly (never skipped silently).
        let bad_connector = broker_config::RulesConf {
            rules: vec![broker_config::RuleEntry {
                id: "rule-1".to_string(),
                name: "bad".to_string(),
                topic_filter: "sensors/#".to_string(),
                sql_query: None,
                enabled: true,
                actions: vec![broker_config::RuleActionEntry::ForwardConnector {
                    connector_id: String::new(),
                }],
            }],
        };
        let err = match RuleEngine::from_snapshot(&bad_connector) {
            Ok(_) => panic!("empty connector must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("connector_id"),
            "error must name the field, got: {err}"
        );
        // Invalid stored SQL fails boot loudly as well.
        let bad_sql = broker_config::RulesConf {
            rules: vec![broker_config::RuleEntry {
                id: "rule-1".to_string(),
                name: "bad".to_string(),
                topic_filter: "sensors/#".to_string(),
                sql_query: Some("SELECT FROM WHERE".to_string()),
                enabled: true,
                actions: Vec::new(),
            }],
        };
        let err = match RuleEngine::from_snapshot(&bad_sql) {
            Ok(_) => panic!("invalid SQL must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("invalid"),
            "error must fail loudly, got: {err}"
        );
    }
}
