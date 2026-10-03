#![allow(future_incompatible)]

use async_trait::async_trait;
use broker_connectors::ConnectorManager;
use broker_protocol::{QoS, Topic, TopicFilter};
use bytes::Bytes;
use parking_lot::RwLock;
use rekuiper_sql::{Evaluator, SelectStmt};

/// Bounded on-disk spill buffer behind [`BackpressurePolicy::SpillToDisk`].
pub mod spill;

/// The streaming-SQL function catalog (name, category, aggregate flag,
/// arity, example) served to the dashboard SQL studio.
pub use rekuiper_sql::{builtin_function_metadata, FunctionMeta};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

use spill::SpillLog;
pub use spill::{
    SpillConfig, SpillOutcome, SpillStats, DEFAULT_SPILL_MAX_BYTES, DEFAULT_SPILL_SEGMENT_MAX_BYTES,
};

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
/// to make room. `RejectPublisher` reports overflow as an error instead
/// of queueing. `SpillToDisk` appends overflow events to the bounded
/// on-disk spill buffer ([`spill::SpillLog`]) instead of erroring, and
/// the consumer replays them in order once the pressure eases; without
/// a spill directory configured (plain [`BoundedEventInput::new`]) it
/// refuses loudly like `RejectPublisher` and counts the drop, failing
/// closed rather than pretending to be durable.
pub struct BoundedEventInput {
    tx: mpsc::Sender<StreamEvent>,
    rx: Mutex<mpsc::Receiver<StreamEvent>>,
    policy: BackpressurePolicy,
    /// Disk behind `SpillToDisk`, if one was configured. `None` for the
    /// other four policies and for directory-less `SpillToDisk` inputs.
    /// Held across the check-send-spill sequence so concurrent pushes
    /// keep one global order (memory first, then disk, sticky while a
    /// backlog exists). Steady-state `SpillToDisk` pushes pay one
    /// uncontended mutex; the other policies never touch it.
    spill: parking_lot::Mutex<Option<SpillLog>>,
    /// Lock-free spill-enabled flag for the live publish path: set once
    /// when a spill directory opens, never flipped back. `dispatch_ingress`
    /// checks this single relaxed load (no mutex) so the default
    /// memory-only engine pays no new lock on publish; only spill-backed
    /// engines take the push path below.
    spill_enabled: AtomicU64,
    /// Lock-free mirror of the on-disk backlog for tests and for the
    /// sticky-spill fast check. Maintained under the spill mutex
    /// wherever the log mutates (mirrors `inflight_spill.len()` the way
    /// the session spill count does).
    spill_backlog: AtomicU64,
    /// Outcome counters for the spill backend. Bumped on every spill,
    /// replay, refusal and recovery outcome so the behaviour is visible
    /// and never silent; mirrored into the node metrics when attached.
    spilled: AtomicU64,
    replayed: AtomicU64,
    spill_dropped: AtomicU64,
    torn_discarded: AtomicU64,
    spill_recovered: AtomicU64,
    /// Node metrics mirror for the counters above (`None` in unit
    /// tests and standalone state). Attached once via
    /// [`BoundedEventInput::set_metrics`]; the first attach also
    /// carries the counts accumulated so far.
    metrics: OnceLock<Arc<broker_observability::Metrics>>,
}

impl BoundedEventInput {
    pub fn new(capacity: usize, policy: BackpressurePolicy) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        Arc::new(Self {
            tx,
            rx: Mutex::new(rx),
            policy,
            spill: parking_lot::Mutex::new(None),
            spill_enabled: AtomicU64::new(0),
            spill_backlog: AtomicU64::new(0),
            spilled: AtomicU64::new(0),
            replayed: AtomicU64::new(0),
            spill_dropped: AtomicU64::new(0),
            torn_discarded: AtomicU64::new(0),
            spill_recovered: AtomicU64::new(0),
            metrics: OnceLock::new(),
        })
    }

    /// Spill-backed input: `SpillToDisk` policy with a bounded on-disk
    /// buffer behind the push path. Opening recovers the directory
    /// (replaying whatever a previous engine left), so recreating the
    /// input on the same directory survives a restart. A bad directory
    /// or config fails here, loudly, before anything can pretend to be
    /// durable.
    pub fn with_spill(capacity: usize, config: SpillConfig) -> io::Result<Arc<Self>> {
        let input = Self::new(capacity, BackpressurePolicy::SpillToDisk);
        let (log, outcome) = SpillLog::open(&config)?;
        input
            .spill_recovered
            .fetch_add(outcome.recovered, Ordering::Relaxed);
        input
            .torn_discarded
            .fetch_add(outcome.torn, Ordering::Relaxed);
        input.spill_backlog.store(log.backlog(), Ordering::Relaxed);
        input.spill_enabled.store(1, Ordering::Relaxed);
        *input.spill.lock() = Some(log);
        Ok(input)
    }

    /// Attach the node metrics mirror for the spill counters. The first
    /// attach wins and also carries the counts accumulated so far, so
    /// recovery outcomes (counted at open, before any attach) still
    /// reach the existing observability path exactly once.
    pub fn set_metrics(&self, metrics: &Arc<broker_observability::Metrics>) {
        if self.metrics.set(Arc::clone(metrics)).is_ok() {
            metrics.inc_rule_spill_spilled_by(self.spilled.load(Ordering::Relaxed));
            metrics.inc_rule_spill_replayed_by(self.replayed.load(Ordering::Relaxed));
            metrics.inc_rule_spill_dropped_by(self.spill_dropped.load(Ordering::Relaxed));
            metrics.inc_rule_spill_torn_by(self.torn_discarded.load(Ordering::Relaxed));
            metrics.inc_rule_spill_recovered_by(self.spill_recovered.load(Ordering::Relaxed));
        }
    }

    /// Current spill outcome counts (zeros when no spill backend is
    /// configured, apart from refusals, which are always counted).
    pub fn spill_stats(&self) -> SpillStats {
        SpillStats {
            spilled: self.spilled.load(Ordering::Relaxed),
            replayed: self.replayed.load(Ordering::Relaxed),
            dropped: self.spill_dropped.load(Ordering::Relaxed),
            torn_discarded: self.torn_discarded.load(Ordering::Relaxed),
            recovered: self.spill_recovered.load(Ordering::Relaxed),
        }
    }

    /// True while a spill directory is configured behind this input.
    pub fn has_spill(&self) -> bool {
        self.spill.lock().is_some()
    }

    /// Lock-free spill check for the live publish path: one relaxed
    /// atomic load, no mutex. The publish path (`dispatch_ingress`)
    /// uses this, never [`BoundedEventInput::has_spill`].
    pub fn spill_enabled(&self) -> bool {
        self.spill_enabled.load(Ordering::Relaxed) != 0
    }

    /// Events currently awaiting replay on disk.
    pub fn spill_backlog_len(&self) -> u64 {
        self.spill_backlog.load(Ordering::Relaxed)
    }

    /// Force the active spill segment to stable storage. The spill
    /// path itself never syncs (see [`spill`]); call this before an
    /// orderly shutdown or a restart handoff. No backend is a no-op.
    pub fn sync_spill(&self) -> io::Result<()> {
        let guard = self.spill.lock();
        if let Some(log) = guard.as_ref() {
            log.sync()?;
        }
        Ok(())
    }

    fn count_spilled(&self) {
        self.spilled.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = self.metrics.get() {
            metrics.inc_rule_spill_spilled();
        }
    }

    fn count_replayed(&self) {
        self.replayed.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = self.metrics.get() {
            metrics.inc_rule_spill_replayed();
        }
    }

    fn count_dropped(&self) {
        self.spill_dropped.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = self.metrics.get() {
            metrics.inc_rule_spill_dropped();
        }
    }

    fn count_torn_by(&self, n: u64) {
        self.torn_discarded.fetch_add(n, Ordering::Relaxed);
        if let Some(metrics) = self.metrics.get() {
            metrics.inc_rule_spill_torn_by(n);
        }
    }

    /// Non-blocking enqueue attempt. `Block` never blocks here: a full
    /// buffer reports `WouldBlock`-style success value... see below.
    ///
    /// Publish-path cost (B4-07, measured by
    /// `test_spill_workload_timings`, which prints both rates into the
    /// gate log): steady-state (no pressure, no disk backlog) pays two
    /// relaxed atomic loads plus one `try_send` — no spill mutex, no
    /// allocation, no file I/O, identical to the other four policies.
    /// Only overflow (full memory, or a disk backlog while sticky) takes
    /// the spill mutex plus one page-cache `write + flush` (encode `Vec`
    /// allocs bounded by the event size and capped by
    /// `MAX_FRAME_BODY_BYTES`, never an `fsync`); refusals (cap, oversize,
    /// I/O error) fail closed and counted.
    pub fn try_push(&self, event: StreamEvent) -> Result<PushOutcome, RuleEngineError> {
        // Sticky-spill order: while a disk backlog exists every arrival
        // joins the disk (memory always predates it), so replay stays
        // memory-then-disk, oldest first. The backlog mirror is lock-free;
        // steady-state (`0`) skips the mutex entirely.
        if self.policy == BackpressurePolicy::SpillToDisk
            && self.spill_backlog.load(Ordering::Relaxed) != 0
        {
            return self.spill_or_refuse(event);
        }
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
            BackpressurePolicy::SpillToDisk => self.spill_or_refuse(event),
            BackpressurePolicy::RejectPublisher => {
                self.count_dropped();
                Err(RuleEngineError::Overflow(OverflowReason::BufferFull))
            }
        }
    }

    /// Overflow path for `SpillToDisk`: memory first, disk behind it,
    /// refusal only when there is nowhere to put the event. The spill
    /// mutex is held across the check-send-spill sequence so concurrent
    /// pushes keep one global order: while a disk backlog exists every
    /// arrival joins it (sticky spill), so replay order is always
    /// memory-then-disk, oldest first. The disk write is `write +
    /// flush` to the page cache, never an `fsync`: the live event path
    /// never blocks on stable storage.
    fn spill_or_refuse(&self, event: StreamEvent) -> Result<PushOutcome, RuleEngineError> {
        let mut spill = self.spill.lock();
        let Some(log) = spill.as_mut() else {
            // No disk behind the variant: refuse loudly and count the
            // drop. Fail closed rather than pretending to be durable.
            self.count_dropped();
            tracing::warn!(
                "rule input SpillToDisk overflow refused: no spill directory configured"
            );
            return Err(RuleEngineError::Overflow(OverflowReason::BufferFull));
        };
        let event = if log.backlog() == 0 {
            match self.tx.try_send(event) {
                Ok(()) => return Ok(PushOutcome::Enqueued),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.count_dropped();
                    return Err(RuleEngineError::Overflow(OverflowReason::BufferFull));
                }
                Err(mpsc::error::TrySendError::Full(event)) => event,
            }
        } else {
            event
        };
        match log.spill(&event) {
            Ok(seq) => {
                self.spill_backlog.store(log.backlog(), Ordering::Relaxed);
                self.count_spilled();
                Ok(PushOutcome::SpilledToDisk(seq))
            }
            Err(e) => {
                self.spill_backlog.store(log.backlog(), Ordering::Relaxed);
                self.count_dropped();
                tracing::warn!(error = %e, "rule input spill refused: failing closed");
                Err(RuleEngineError::Overflow(OverflowReason::BufferFull))
            }
        }
    }

    /// Replay one spilled event under the spill mutex. Counters stay in
    /// sync with the log: the backlog mirror follows every mutation,
    /// replays and torn repairs are counted and mirrored.
    fn replay_one_locked(&self) -> Option<StreamEvent> {
        let mut spill = self.spill.lock();
        let log = spill.as_mut()?;
        let (event, torn) = log.replay_one();
        self.spill_backlog.store(log.backlog(), Ordering::Relaxed);
        if torn > 0 {
            self.count_torn_by(torn);
        }
        if event.is_some() {
            self.count_replayed();
        }
        event
    }

    /// Take the next queued event (consumer side): memory first (it
    /// always predates the disk backlog under sticky spill), then one
    /// disk replay, then pend for the next memory arrival. A pending
    /// consumer cannot miss spilled events: pushes join the disk while
    /// a backlog exists, and every wake re-checks memory before disk.
    ///
    /// Locking: the async channel mutex is held only for the
    /// non-blocking `try_recv` and for the final pending `recv`; it is
    /// never held across disk I/O (`replay_one_locked` takes only the
    /// short sync spill mutex for a page-cache read plus at most one
    /// repair truncation). Steady-state consumers pay no disk work at
    /// all.
    pub async fn next_event(&self) -> Option<StreamEvent> {
        // Fast path: one short channel lock, released before any disk.
        {
            let mut rx = self.rx.lock().await;
            match rx.try_recv() {
                Ok(event) => return Some(event),
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    drop(rx);
                    return self.replay_one_locked();
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }
        // Memory empty: one disk replay with no channel lock held.
        if let Some(event) = self.replay_one_locked() {
            return Some(event);
        }
        // Nothing anywhere: pend for the next memory arrival (channel
        // lock only across the sleep). A spill that lands while pending
        // wakes via the channel only when it also enqueued to memory;
        // sticky disk-only arrivals are picked up on the next wake by
        // re-checking memory before disk.
        let mut rx = self.rx.lock().await;
        // Re-check memory first: an arrival between the replay above and
        // this lock must not be overtaken by disk.
        match rx.try_recv() {
            Ok(event) => Some(event),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                drop(rx);
                self.replay_one_locked()
            }
            Err(mpsc::error::TryRecvError::Empty) => match rx.recv().await {
                Some(event) => Some(event),
                None => {
                    drop(rx);
                    self.replay_one_locked()
                }
            },
        }
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

/// Wall-clock milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

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
/// are handed to the installed [`WindowExecutor`] (provided by the
/// enterprise window crate and attached at kernel boot), which aggregates
/// per window close and dispatches back through the engine. Without an
/// installed executor the records are counted as matched and skipped
/// (see [`RuleEngine::dispatch_ingress`]).
pub struct RuleEngine {
    rules: RwLock<HashMap<String, Rule>>,
    next_id: AtomicU64,
    input: Arc<BoundedEventInput>,
    connectors: Arc<ConnectorManager>,
    broker_sink: RwLock<Option<Arc<dyn BrokerSink>>>,
    window_executor: RwLock<Option<Arc<dyn WindowExecutor>>>,
    forward_throttle: Arc<parking_lot::Mutex<HashMap<(String, String), ThrottleEntry>>>,
    /// Kernel config registry receiving every rule mutation (`None` in
    /// unit tests and standalone state, which stay memory-only).
    registry: RwLock<Option<Arc<broker_config::ConfigRegistry>>>,
    /// Serialises export-commit-save so concurrent mutations cannot
    /// interleave into a lost update on disk.
    save_lock: parking_lot::Mutex<()>,
}

/// Seam for enterprise windowed execution, implemented outside this
/// crate so the community rule path carries no dependency edge to the
/// window workers. The kernel installs the enterprise implementation at
/// boot; every method is a no-op-safe delegation point owned by the
/// engine's rule lifecycle (create, remove, snapshot seed, ingress).
pub trait WindowExecutor: Send + Sync {
    /// Route one matching record into this rule's window worker.
    fn route_record(&self, rule: &Rule, topic: &Topic, payload: &Bytes);
    /// Ensure a background worker exists for an Enterprise window rule.
    fn ensure_worker(&self, rule: &Rule);
    /// Abort the worker for one rule id, if any.
    fn remove_worker(&self, rule_id: &str);
    /// Abort every worker (snapshot replace path).
    fn abort_all(&self);
    /// Live window worker count (observability/testing hook).
    fn worker_count(&self) -> usize;
}

impl RuleEngine {
    /// Create an engine with a bounded ingress queue (`capacity` floors at
    /// 1). The queue backs future async ingestion; the hot path calls
    /// [`RuleEngine::dispatch_ingress`] synchronously for determinism.
    /// Windowed rules additionally need a [`WindowExecutor`] installed
    /// via [`RuleEngine::set_window_executor`] (the kernel does this at
    /// boot before any rule is created).
    pub fn new(queue_capacity: usize, policy: BackpressurePolicy) -> Self {
        Self::with_input(BoundedEventInput::new(queue_capacity, policy))
    }

    /// Create an engine whose ingress queue spills to disk under
    /// pressure (`SpillToDisk` policy with a bounded buffer in `dir`).
    /// Opening recovers the directory, so a previous engine's spilled
    /// events survive the restart. A bad directory fails loudly.
    pub fn new_with_spill(
        queue_capacity: usize,
        spill_dir: impl Into<std::path::PathBuf>,
    ) -> io::Result<Self> {
        Self::new_with_spill_config(queue_capacity, SpillConfig::new(spill_dir))
    }

    /// Create a spill-backed engine with an explicit disk policy
    /// (segment and total caps, for tests and tuned deployments).
    pub fn new_with_spill_config(
        queue_capacity: usize,
        spill_config: SpillConfig,
    ) -> io::Result<Self> {
        let input = BoundedEventInput::with_spill(queue_capacity, spill_config)?;
        Ok(Self::with_input(input))
    }

    /// Shared construction from a ready ingress queue.
    fn with_input(input: Arc<BoundedEventInput>) -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            input,
            connectors: Arc::new(ConnectorManager::new()),
            broker_sink: RwLock::new(None),
            window_executor: RwLock::new(None),
            forward_throttle: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            registry: RwLock::new(None),
            save_lock: parking_lot::Mutex::new(()),
        }
    }

    /// Bounded ingress queue for flood protection at outer boundaries.
    pub fn input(&self) -> &Arc<BoundedEventInput> {
        &self.input
    }

    /// Spill outcome counts for the ingress queue (zeros when no spill
    /// directory is configured, apart from refusals, which count).
    pub fn spill_stats(&self) -> SpillStats {
        self.input.spill_stats()
    }

    /// Attach the node metrics mirror for the ingress spill counters.
    /// Called once by the node after the shared metrics exist; the
    /// first attach wins and carries the counts so far (including
    /// recovery outcomes from open).
    pub fn set_metrics(&self, metrics: &Arc<broker_observability::Metrics>) {
        self.input.set_metrics(metrics);
    }

    /// Live outbound connectors addressable by `ForwardConnector` actions.
    pub fn connectors(&self) -> &Arc<ConnectorManager> {
        &self.connectors
    }

    /// Install (or replace) the broker sink used by window-flush
    /// republish actions (window rows dispatch back through this engine,
    /// so one sink serves both paths). Called once by the node after the
    /// shared sink exists; the inline stateless path keeps taking its
    /// sink per call.
    pub fn set_broker_sink(&self, sink: Arc<dyn BrokerSink>) {
        *self.broker_sink.write() = Some(sink);
    }

    /// The currently installed broker sink, if any.
    pub fn broker_sink(&self) -> Option<Arc<dyn BrokerSink>> {
        self.broker_sink.read().clone()
    }

    /// Install the enterprise window executor (the kernel does this at
    /// boot before any rule is created). Replaces any previous one.
    pub fn set_window_executor(&self, executor: Arc<dyn WindowExecutor>) {
        *self.window_executor.write() = Some(executor);
    }

    /// Live window worker count (observability/testing hook). Zero when
    /// no executor is installed.
    pub fn window_worker_count(&self) -> usize {
        self.window_executor
            .read()
            .as_ref()
            .map(|executor| executor.worker_count())
            .unwrap_or(0)
    }

    /// Dispatch one flushed window aggregate row through this rule's
    /// actions. Called by the window executor per result row: the rule is
    /// resolved here (a rule removed mid-flush drops its late rows with a
    /// warning), delivery QoS is capped at [`QoS::ExactlyOnce`] so the
    /// action QoS applies verbatim, and counters, connectors, throttle
    /// and sink are the engine's own, exactly as on the inline path.
    pub async fn dispatch_window_row(&self, rule_id: &str, topic: &Topic, payload: Bytes) {
        let Some(rule) = self.get_rule(rule_id) else {
            tracing::warn!(
                rule_id = %rule_id,
                "window row dropped: rule no longer exists"
            );
            return;
        };
        let sink = self.broker_sink();
        run_actions(
            rule_id,
            &rule.actions,
            topic,
            payload,
            QoS::ExactlyOnce,
            &self.connectors,
            sink.as_ref(),
            &ActionCounters::from_rule(&rule),
            &self.forward_throttle,
        )
        .await;
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
        // No executor installed (unit-test engines) means no worker yet;
        // routing retries the spawn.
        if tier == RuleTier::Enterprise {
            self.ensure_window_worker(&rule);
        }
        Ok(rule)
    }

    /// Delegate a worker spawn to the installed executor, if any.
    fn ensure_window_worker(&self, rule: &Rule) {
        if let Some(executor) = self.window_executor.read().clone() {
            executor.ensure_worker(rule);
        }
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

    /// Replace all rules with one validated snapshot root (M1-05 runtime
    /// apply path for the `rules` root).
    ///
    /// Runs the same validated create path as boot; driven afterwards by
    /// publish ingress (each ingress evaluates this store). Window workers
    /// of replaced rules are aborted so no orphan task survives.
    pub fn apply_snapshot_conf(
        &self,
        conf: &broker_config::RulesConf,
    ) -> Result<(), RuleEngineError> {
        self.seed_from_snapshot(conf)
    }

    /// Replace all rules with the snapshot contents through the validated
    /// create path. Existing window workers are aborted first so no
    /// orphan task survives its rule; `next_id` restarts at 1 and
    /// advances past every restored numeric suffix.
    fn seed_from_snapshot(&self, conf: &broker_config::RulesConf) -> Result<(), RuleEngineError> {
        conf.validate()
            .map_err(|e| RuleEngineError::InvalidRule(format!("invalid rules snapshot: {e}")))?;
        if let Some(executor) = self.window_executor.read().clone() {
            executor.abort_all();
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
        if let Some(executor) = self.window_executor.read().clone() {
            executor.remove_worker(id);
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

    /// Route one matching record into the installed window executor.
    /// Hands the rule, topic and payload to the executor, which parses,
    /// filters and buffers (lazily spawning a missing worker). With no
    /// executor installed the record is counted as matched upstream and
    /// skipped here (see [`RuleEngine::dispatch_ingress`]).
    fn dispatch_windowed(&self, rule: &Rule, topic: &Topic, payload: &Bytes) {
        if let Some(executor) = self.window_executor.read().clone() {
            executor.route_record(rule, topic, payload);
        } else {
            // TODO(parity): no window executor decides this open case yet.
            // The conservative choice is to skip window execution rather
            // than run it inline or invent results. Production engines
            // always carry the enterprise executor (attached at kernel
            // boot), so this only triggers on unwired test engines.
            tracing::warn!(
                rule_id = %rule.id,
                "windowed rule skipped: no window executor installed"
            );
        }
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
    /// are handed to the installed window executor instead (still counted
    /// as matched).
    pub async fn dispatch_ingress(
        &self,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
        broker_sink: &Arc<dyn BrokerSink>,
    ) -> usize {
        // Snapshot matching rules so the sink (which may touch the router,
        // never this map) runs without holding the lock.
        // B4-07 live wiring (durability push after match, see below).
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
        // B4-07 live wiring: every broker ingress (see
        // `crates/broker-node/src/main.rs:ingress_pipeline_with_publisher`,
        // the single prod caller of `push`/`try_push` via this method)
        // mirrors a durability copy through the bounded input queue after
        // inline matching. Memory-only engines skip this with one
        // lock-free load, so the other four policies are unchanged.
        // Spill-backed engines append overflow to disk instead of erroring
        // (`SpillLog::spill` at `spill.rs:580`, page-cache `write + flush`,
        // never `fsync` on this path); the copy carries topic/payload for
        // order verification and crash durability, while live matching
        // above still uses the original `qos` inline, so delivery
        // guarantees never change. Pushed after the match so a crash
        // between match and push leaves an already-executed event without
        // a copy (safe to discard after restart); a crash before the match
        // leaves nothing (QoS 1 retries via MQTT, QoS 0 loss is
        // best-effort). The broker spill drain task (`broker-node`)
        // replays via `next_event` after the pressure eases; restart
        // recovery reopens the same directory (`SpillLog::open` at
        // `spill.rs:491`). Driven by the rule-ingress event; disk writes
        // consult `crates/broker-rules/src/spill.rs:580`
        // (`SpillLog::spill`) and replays consult
        // `crates/broker-rules/src/spill.rs:637` (`SpillLog::replay_one`).
        if self.input.spill_enabled() {
            let durability = StreamEvent::new(topic.clone(), payload.clone());
            // Counted (spilled/dropped) inside `try_push`; overflow
            // refuses fail-closed without blocking publish.
            let _ = self.input.try_push(durability);
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

/// Partition records by `GROUP BY` expressions and evaluate one
/// aggregate row per partition (first-seen group order). Without
/// `GROUP BY`, the whole batch is a single partition. Shared by the
/// enterprise window flushes (which call back through
/// [`RuleEngine::dispatch_window_row`]) and the batch dry-run tester
/// alike so both agree.
pub fn aggregate_partitioned(
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

    // ------------------------------------------------------------------
    // B4-07: SpillToDisk is a real bounded disk buffer, not a silent
    // alias for rejection. The tests below are buffer units through the
    // broker's rule engine input (never a bare store); the Done-when
    // broker-path coverage (fill via publish/deliver through
    // `ingress_pipeline`, spill, replay in order) lives in
    // `crates/broker-node/src/main.rs:rule_spill_broker_path_spills_and_replays_in_order`.
    // Every test cleans up its scratch directory.
    // ------------------------------------------------------------------

    static SPILL_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    /// Unique scratch directory for one spill test (no new crates:
    /// process id plus a counter). Callers remove it when done.
    fn spill_test_dir(tag: &str) -> std::path::PathBuf {
        let seq = SPILL_TEST_SEQ.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "indra-rule-spill-{tag}-{}-{seq}",
            std::process::id()
        ))
    }

    fn remove_spill_dir(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Fill the in-memory queue through the broker input path, push
    /// past it, and drain: overflow spills to disk instead of erroring
    /// and replays oldest-first after the memory events.
    #[tokio::test]
    async fn test_spill_to_disk_spills_and_replays_in_order() {
        let dir = spill_test_dir("order");
        remove_spill_dir(&dir);
        let engine = RuleEngine::new_with_spill(2, dir.clone()).expect("spill engine opens");
        let metrics = Arc::new(broker_observability::Metrics::new());
        engine.set_metrics(&metrics);
        let input = engine.input();
        assert!(input.has_spill());

        assert_eq!(
            input.push(test_event("t", b"one")).await.unwrap(),
            PushOutcome::Enqueued
        );
        assert_eq!(
            input.push(test_event("t", b"two")).await.unwrap(),
            PushOutcome::Enqueued
        );
        assert_eq!(
            input.push(test_event("t", b"three")).await.unwrap(),
            PushOutcome::SpilledToDisk(0)
        );
        assert_eq!(
            input.push(test_event("t", b"four")).await.unwrap(),
            PushOutcome::SpilledToDisk(1)
        );

        // Rule matching is unchanged on a spill-backed engine, and live
        // ingress now mirrors a durability copy through the input queue
        // (`dispatch_ingress` pushes when spill-backed): with a disk
        // backlog present the copy joins the disk (sticky spill), so it
        // replays last after the four events below.
        engine
            .create_rule(
                "spill-probe".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                None,
                true,
                vec![RuleAction::Log],
            )
            .expect("rule creates");
        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        assert_eq!(
            engine
                .dispatch_ingress(
                    &Topic::new("sensors/kitchen").unwrap(),
                    &Bytes::from_static(b"21.5C"),
                    QoS::AtMostOnce,
                    &sink,
                )
                .await,
            1
        );

        // Drain: memory events first in order, then spilled in order,
        // then the live-ingress durability copy (`21.5C`) last.
        for want in [
            b"one".as_slice(),
            b"two".as_slice(),
            b"three".as_slice(),
            b"four".as_slice(),
            b"21.5C".as_slice(),
        ] {
            let event = input.next_event().await.expect("replay delivers");
            assert_eq!(event.payload, Bytes::from_static(want));
        }
        let stats = engine.spill_stats();
        assert_eq!(stats.spilled, 3);
        assert_eq!(stats.replayed, 3);
        assert_eq!(stats.dropped, 0);
        assert_eq!(stats.recovered, 0);
        assert_eq!(input.spill_backlog_len(), 0);
        // The existing observability path mirrors every outcome.
        assert_eq!(metrics.rule_spill_spilled(), 3);
        assert_eq!(metrics.rule_spill_replayed(), 3);
        assert_eq!(metrics.rule_spill_dropped(), 0);

        input.sync_spill().expect("sync");
        remove_spill_dir(&dir);
    }

    /// Spilled events survive an engine rebuild from the same spill
    /// directory (restart). Memory-queued events do not: only overflow
    /// is durable, which the test asserts explicitly.
    #[tokio::test]
    async fn test_spill_survives_engine_rebuild() {
        let dir = spill_test_dir("restart");
        remove_spill_dir(&dir);
        {
            let engine = RuleEngine::new_with_spill(1, dir.clone()).expect("spill engine opens");
            let input = engine.input();
            assert_eq!(
                input.push(test_event("t", b"memory-only")).await.unwrap(),
                PushOutcome::Enqueued
            );
            assert_eq!(
                input.push(test_event("t", b"spilled-a")).await.unwrap(),
                PushOutcome::SpilledToDisk(0)
            );
            assert_eq!(
                input.push(test_event("t", b"spilled-b")).await.unwrap(),
                PushOutcome::SpilledToDisk(1)
            );
            input.sync_spill().expect("sync before restart");
        }
        // Recreate from the same directory: the two spilled events are
        // recovered, the memory event is gone by design.
        let engine = RuleEngine::new_with_spill(1, dir.clone()).expect("spill engine reopens");
        let metrics = Arc::new(broker_observability::Metrics::new());
        // Attaching after open still mirrors the recovery counts: the
        // first attach carries everything accumulated so far.
        engine.set_metrics(&metrics);
        assert_eq!(engine.spill_stats().recovered, 2);
        assert_eq!(metrics.rule_spill_recovered(), 2);
        let input = engine.input();
        assert_eq!(
            input.next_event().await.expect("first replay").payload,
            Bytes::from_static(b"spilled-a")
        );
        assert_eq!(
            input.next_event().await.expect("second replay").payload,
            Bytes::from_static(b"spilled-b")
        );
        assert_eq!(engine.spill_stats().replayed, 2);
        // Nothing left anywhere: the consumer pends instead of
        // inventing an event.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), input.next_event())
                .await
                .is_err(),
            "drained spill must pend, not invent"
        );
        remove_spill_dir(&dir);
    }

    /// A spill file truncated mid-record recovers everything before
    /// the tear, discards the torn tail, and counts it.
    #[tokio::test]
    async fn test_spill_torn_tail_discarded_and_counted() {
        use std::fs::OpenOptions;

        let dir = spill_test_dir("torn");
        remove_spill_dir(&dir);
        {
            let engine = RuleEngine::new_with_spill(1, dir.clone()).expect("spill engine opens");
            let input = engine.input();
            assert_eq!(
                input.push(test_event("t", b"pad")).await.unwrap(),
                PushOutcome::Enqueued
            );
            for (seq, payload) in [b"keep-a", b"keep-b", b"torn-c"].into_iter().enumerate() {
                assert_eq!(
                    input.push(test_event("t", payload)).await.unwrap(),
                    PushOutcome::SpilledToDisk(seq as u64)
                );
            }
            input.sync_spill().expect("sync");
        }
        // Truncate the single segment three bytes into the second
        // spilled frame: parse the first frame header to land strictly
        // inside a later frame rather than on a boundary.
        let seg = std::fs::read_dir(&dir)
            .expect("spill dir lists")
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .find(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("spill-") && n.ends_with(".log"))
            })
            .expect("one segment file");
        let data = std::fs::read(&seg).expect("segment reads");
        assert!(data.len() > 16, "segment must hold frames");
        let first_len = u32::from_be_bytes(data[4..8].try_into().expect("header")) as usize;
        let cut = 8 + first_len + 4 + 3;
        assert!(cut < data.len(), "cut must land inside a later frame");
        drop(data);
        OpenOptions::new()
            .write(true)
            .open(&seg)
            .expect("segment opens")
            .set_len(cut as u64)
            .expect("truncate");

        let engine = RuleEngine::new_with_spill(1, dir.clone()).expect("spill engine reopens");
        let stats = engine.spill_stats();
        assert_eq!(stats.torn_discarded, 1, "one torn tail counted");
        assert_eq!(
            stats.recovered, 1,
            "everything before the tear survives, got {stats:?}"
        );
        // The intact first frame replays; nothing follows it.
        let input = engine.input();
        let first = input.next_event().await.expect("first frame replays");
        assert_eq!(first.payload, Bytes::from_static(b"keep-a"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), input.next_event())
                .await
                .is_err(),
            "torn tail must not replay"
        );
        remove_spill_dir(&dir);
    }

    /// SpillToDisk without a directory refuses loudly and counts the
    /// drop: fail closed, never silently memory-only.
    #[tokio::test]
    async fn test_spill_without_directory_refuses_and_counts() {
        let engine = RuleEngine::new(1, BackpressurePolicy::SpillToDisk);
        let input = engine.input();
        assert!(!input.has_spill());
        assert!(input.push(test_event("t", b"one")).await.is_ok());
        assert!(matches!(
            input.push(test_event("t", b"two")).await,
            Err(RuleEngineError::Overflow(OverflowReason::BufferFull))
        ));
        assert_eq!(engine.spill_stats().dropped, 1);
    }

    /// Publish-path cost, before and after (B4-07): time the
    /// steady-state push loop (no pressure, no disk, no spill mutex) and
    /// the overflow spill-append loop (page-cache writes, no fsync) plus
    /// the replay loop, printing msgs/sec for the gate log.
    /// Steady-state pushes (no pressure) never touch disk; only overflow
    /// pays the spill mutex plus one page-cache `write + flush`.
    #[tokio::test]
    async fn test_spill_workload_timings() {
        // BEFORE: steady-state pushes with room — no pressure, no disk.
        // One relaxed load for the sticky check plus one `try_send`; no
        // spill mutex, no `Vec` alloc, no file I/O.
        let dir_base = spill_test_dir("timings-base");
        remove_spill_dir(&dir_base);
        let engine_base =
            RuleEngine::new_with_spill(4096, dir_base.clone()).expect("spill engine opens");
        let input_base = engine_base.input();
        let total = 2_000usize;
        let start = std::time::Instant::now();
        for i in 0..total {
            let payload = format!("event-{i:05}");
            let event = StreamEvent {
                topic: Topic::new("t").unwrap(),
                payload: Bytes::from(payload.into_bytes()),
                timestamp_millis: 1700000000,
                client_id: None,
            };
            assert_eq!(
                input_base.push(event).await.expect("memory admits"),
                PushOutcome::Enqueued,
                "baseline must never touch disk"
            );
        }
        let elapsed = start.elapsed();
        let rate = total as f64 / elapsed.as_secs_f64();
        println!(
            "rule spill steady-state workload: {total} enqueued pushes in {elapsed:?} \
             ({rate:.0} msgs/sec, avg {:.1} ns/msg, no disk, no spill mutex)",
            elapsed.as_nanos() as f64 / total as f64
        );
        assert_eq!(engine_base.spill_stats().spilled, 0);
        // Drain the baseline so the scratch dir check stays clean.
        for _ in 0..total {
            input_base.next_event().await.expect("baseline drains");
        }
        remove_spill_dir(&dir_base);
        // AFTER: overflow pushes spill to disk (one spill mutex plus one
        // page-cache write+flush each, never fsync) and replay reads back.
        let dir = spill_test_dir("timings");
        remove_spill_dir(&dir);
        let engine = RuleEngine::new_with_spill(128, dir.clone()).expect("spill engine opens");
        let input = engine.input();
        let total = 2_000usize;
        let start = std::time::Instant::now();
        let mut spilled = 0usize;
        for i in 0..total {
            let payload = format!("event-{i:05}");
            let event = StreamEvent {
                topic: Topic::new("t").unwrap(),
                payload: Bytes::from(payload.into_bytes()),
                timestamp_millis: 1700000000,
                client_id: None,
            };
            match input.push(event).await.expect("spill admits") {
                PushOutcome::Enqueued => {}
                PushOutcome::SpilledToDisk(_) => spilled += 1,
                PushOutcome::Dropped(reason) => panic!("spill must not drop: {reason:?}"),
            }
        }
        let elapsed = start.elapsed();
        assert!(spilled > 0, "the run must actually exercise the disk path");
        let rate = total as f64 / elapsed.as_secs_f64();
        println!(
            "rule spill workload: {total} pushes ({spilled} spilled) in {elapsed:?} \
             ({rate:.0} msgs/sec, avg {:.1} ns/msg)",
            elapsed.as_nanos() as f64 / total as f64
        );
        let start = std::time::Instant::now();
        for i in 0..total {
            let event = input.next_event().await.expect("replay delivers");
            assert_eq!(
                event.payload,
                Bytes::from(format!("event-{i:05}").into_bytes()),
                "replay keeps global order"
            );
        }
        let elapsed = start.elapsed();
        let rate = total as f64 / elapsed.as_secs_f64();
        println!(
            "rule spill replay workload: {total} replays in {elapsed:?} \
             ({rate:.0} msgs/sec, avg {:.1} ns/msg)",
            elapsed.as_nanos() as f64 / total as f64
        );
        let stats = engine.spill_stats();
        assert_eq!(stats.spilled as usize, spilled);
        assert_eq!(stats.replayed as usize, spilled);
        assert_eq!(stats.dropped, 0);
        remove_spill_dir(&dir);
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

        // ClickHouse (mock driver transport, offline).
        let ch_transport = Arc::new(broker_connectors::MockClickHouseTransport::new(
            "indra",
            "mqtt_events",
            "JSONEachRow",
        ));
        let clickhouse = Arc::new(
            ClickHouseSink::new(
                ClickHouseSinkConfig {
                    endpoint: "http://127.0.0.1:8123".to_string(),
                    database: "indra".to_string(),
                    table: "mqtt_events".to_string(),
                    format: "JSONEachRow".to_string(),
                    batch_size: 100,
                    batch_timeout_ms: 100,
                    username: "default".to_string(),
                    password: String::new(),
                    request_timeout_ms: None,
                },
                ch_transport.clone(),
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

        let ch_captured = ch_transport.captured();
        assert_eq!(ch_captured.len(), 1);
        assert_eq!(ch_captured[0].rows.len(), 1);
        assert_eq!(ch_captured[0].rows[0].topic, "sensors/kitchen");
        assert_eq!(ch_captured[0].rows[0].payload, projected.to_string());

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
        assert_eq!(ch_transport.captured().len(), 1);
        assert_eq!(influx_body.lock().lines().count(), 1);
    }

    /// Industrial e2e (INDRA-217): one Sparkplug telemetry ingress
    /// routes through streaming SQL `INTO connector(...)` rules and
    /// fans out simultaneously to the webhook, MQTT bridge, disk log
    /// and Sparkplug B sinks. All transports are in-memory.
    #[tokio::test]
    async fn test_into_fans_out_to_industrial_sinks() {
        use broker_connectors::{
            DiskLogSink, DiskLogSinkConfig, HttpSink, HttpSinkConfig, MemoryDiskLogWriter,
            MemoryMqttBridgeTransport, MockHttpTransport, MqttBridgeSink, MqttBridgeSinkConfig,
        };
        use broker_connectors_enterprise::{
            MemorySparkplugTransport, SparkplugBSink, SparkplugSinkConfig,
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
                    buffer_capacity: Some(10_000),
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
        let back = broker_connectors_enterprise::decode_payload(&frames[0].payload).unwrap();
        let metrics: HashMap<String, broker_connectors_enterprise::SpbValue> = back
            .metrics
            .into_iter()
            .map(|metric| (metric.name.clone().unwrap(), metric.value))
            .collect();
        assert_eq!(
            metrics["Temperature"],
            broker_connectors_enterprise::SpbValue::Double(82.5)
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
        use broker_connectors_enterprise::{
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
                    auth: broker_connectors_enterprise::GcpAuth::None,
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
                    auth: broker_connectors_enterprise::PulsarAuth::None,
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
        use broker_connectors_enterprise::{
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
                        direction: broker_connectors_enterprise::BridgeDirection::LocalToRemote,
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
                    ca_bundle_pem: None,
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
        use broker_connectors_enterprise::{
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
                    operation: broker_connectors_enterprise::MongoOperation::InsertOne,
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
                    auth: broker_connectors_enterprise::MssqlAuth::Integrated,
                    query_mode: broker_connectors_enterprise::MssqlQueryMode::InsertJson,
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
                    auth: broker_connectors_enterprise::CassandraAuth::None,
                    consistency: broker_connectors_enterprise::CqlConsistency::LocalQuorum,
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
                    auth: broker_connectors_enterprise::CouchbaseAuth {
                        username: "Administrator".to_string(),
                        password: "secret".to_string(),
                    },
                    doc_id_template: "${client_id}::${timestamp}".to_string(),
                    operation: broker_connectors_enterprise::CouchbaseOperation::Upsert,
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
            Some(broker_connectors_enterprise::BsonValue::ObjectId(_))
        ));
        assert_eq!(
            document.get("temp"),
            Some(&broker_connectors_enterprise::BsonValue::Double(22.5))
        );
        assert_eq!(
            document.get("_mqtt").and_then(|meta| match meta {
                broker_connectors_enterprise::BsonValue::Document(meta) =>
                    meta.get("topic").cloned(),
                _ => None,
            }),
            Some(broker_connectors_enterprise::BsonValue::String(
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
            broker_connectors_enterprise::murmur3_token(b"device-42")
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
        use broker_connectors_enterprise::{
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
                    auth: broker_connectors_enterprise::TdengineAuth::Basic {
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
                    auth: broker_connectors_enterprise::IotDbAuth {
                        username: "root".to_string(),
                        password: "root".to_string(),
                    },
                    is_aligned: false,
                    measurements: vec!["temperature".to_string(), "humidity".to_string()],
                    data_types: vec![
                        broker_connectors_enterprise::IotDbDataType::Double,
                        broker_connectors_enterprise::IotDbDataType::Double,
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
                    time_unit: broker_connectors_enterprise::TimestreamTimeUnit::Milliseconds,
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
                    partition_key: broker_connectors_enterprise::DynamoKeyConfig {
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
        use broker_connectors_enterprise::{
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
                    auth: broker_connectors_enterprise::DorisAuth {
                        username: "root".to_string(),
                        password: String::new(),
                    },
                    format: broker_connectors_enterprise::DorisFormat::Json,
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
                    auth: broker_connectors_enterprise::GcpAuth::None,
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

    /// B3-06 broker proof: 1000 rule-shaped rows stream via
    /// `dispatch_ingress` through `BigQuerySink` on the maintained
    /// `SdkBigQueryTransport` to a loopback `insertAll` fake. Row count is
    /// asserted on the fake (not just the sink counters), plus selective
    /// requeue of only failed rows through the same rule path.
    #[tokio::test]
    async fn test_bigquery_sdk_sink_via_rule_against_fake() {
        use axum::{extract::State, http::StatusCode, routing::post, Router};
        use broker_connectors::Sink;
        use broker_connectors_enterprise::{
            BigQuerySink, BigQuerySinkConfig, SdkBigQueryTransport,
        };

        #[derive(Default)]
        struct FakeBigQuery {
            bodies: parking_lot::Mutex<Vec<serde_json::Value>>,
            script: parking_lot::Mutex<std::collections::VecDeque<(u16, serde_json::Value)>>,
        }

        async fn serve_fake(fake: Arc<FakeBigQuery>) -> String {
            async fn handler(
                State(fake): State<Arc<FakeBigQuery>>,
                body: String,
            ) -> (StatusCode, String) {
                let parsed: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                fake.bodies.lock().push(parsed);
                let next = fake.script.lock().pop_front();
                match next {
                    Some((status, value)) => (
                        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
                        value.to_string(),
                    ),
                    None => (StatusCode::OK, "{}".to_string()),
                }
            }
            let app = Router::new()
                .route("/*rest", post(handler))
                .with_state(fake);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake bigquery");
            let port = listener.local_addr().expect("fake addr").port();
            tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve fake");
            });
            format!("http://127.0.0.1:{port}")
        }

        let fake = Arc::new(FakeBigQuery::default());
        let endpoint = serve_fake(fake.clone()).await;
        let config = BigQuerySinkConfig {
            project_id: "my-iot-project".to_string(),
            dataset_id: "telemetry".to_string(),
            table_template: "sensor_logs".to_string(),
            endpoint: Some(endpoint),
            auth: broker_connectors_enterprise::GcpAuth::None,
            ignore_unknown_values: true,
            skip_invalid_rows: false,
            template_suffix: None,
            batch_size: Some(100),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(1),
            max_backoff_ms: Some(2),
            timeout_ms: Some(15_000),
        };
        let transport = Arc::new(
            SdkBigQueryTransport::new(&config, reqwest::Client::new()).expect("sdk transport"),
        );
        let bigquery = Arc::new(BigQuerySink::new(config, transport).expect("sink"));
        assert_eq!(bigquery.kind(), "bigquery");

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        engine
            .connectors()
            .register("bigquery-sdk-sink", bigquery.clone());
        engine
            .create_rule(
                "bq-sdk-rule".to_string(),
                TopicFilter::new("sensors/qual").unwrap(),
                Some(
                    r#"SELECT device_id, temp, seq FROM "sensors/qual" INTO connector("bigquery-sdk-sink")"#
                        .to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");

        let probe: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        for seq in 0..1000 {
            let payload = Bytes::from(format!(
                r#"{{"device_id":"dev-{seq:04}","temp":{temp},"seq":{seq}}}"#,
                temp = 20.0 + f64::from(seq) * 0.01
            ));
            engine
                .dispatch_ingress(
                    &Topic::new("sensors/qual").unwrap(),
                    &payload,
                    QoS::AtLeastOnce,
                    &probe,
                )
                .await;
        }
        bigquery.flush().await.expect("flush");
        assert_eq!(bigquery.sent_records(), 1000);
        let total: usize = fake
            .bodies
            .lock()
            .iter()
            .map(|body| body["rows"].as_array().map_or(0, |rows| rows.len()))
            .sum();
        assert_eq!(total, 1000);
        let first = fake.bodies.lock()[0].clone();
        assert_eq!(
            first["rows"][0]["json"]["device_id"]
                .as_str()
                .expect("device"),
            "dev-0000"
        );

        // Partial-failure retry through the same rule path requeues only
        // the failed row.
        let partial_fake = Arc::new(FakeBigQuery {
            bodies: parking_lot::Mutex::new(Vec::new()),
            script: parking_lot::Mutex::new(
                vec![
                    (
                        200,
                        serde_json::json!({
                            "insertErrors": [{"index": 1, "errors": [{"reason": "rateLimitExceeded"}]}]
                        }),
                    ),
                    (200, serde_json::json!({})),
                ]
                .into_iter()
                .collect(),
            ),
        });
        let partial_endpoint = serve_fake(partial_fake.clone()).await;
        let partial_config = BigQuerySinkConfig {
            project_id: "my-iot-project".to_string(),
            dataset_id: "telemetry".to_string(),
            table_template: "sensor_logs".to_string(),
            endpoint: Some(partial_endpoint),
            auth: broker_connectors_enterprise::GcpAuth::None,
            ignore_unknown_values: true,
            skip_invalid_rows: false,
            template_suffix: None,
            batch_size: Some(10),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(1),
            max_backoff_ms: Some(2),
            timeout_ms: Some(15_000),
        };
        let partial_transport = Arc::new(
            SdkBigQueryTransport::new(&partial_config, reqwest::Client::new())
                .expect("partial transport"),
        );
        let partial_sink =
            Arc::new(BigQuerySink::new(partial_config, partial_transport).expect("sink"));
        let partial_engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        partial_engine
            .connectors()
            .register("bq-partial-sink", partial_sink.clone());
        partial_engine
            .create_rule(
                "bq-partial-rule".to_string(),
                TopicFilter::new("sensors/retry").unwrap(),
                Some(
                    r#"SELECT temp FROM "sensors/retry" INTO connector("bq-partial-sink")"#
                        .to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");
        for temp in [20.5, 21.5] {
            partial_engine
                .dispatch_ingress(
                    &Topic::new("sensors/retry").unwrap(),
                    &Bytes::from(format!(r#"{{"temp":{temp}}}"#)),
                    QoS::AtMostOnce,
                    &probe,
                )
                .await;
        }
        partial_sink.flush().await.expect("retry flush");
        assert_eq!(partial_fake.bodies.lock().len(), 2);
        let retry_bodies = partial_fake.bodies.lock().clone();
        assert_eq!(retry_bodies[1]["rows"].as_array().expect("rows").len(), 1);
        assert_eq!(
            retry_bodies[1]["rows"][0]["json"]["temp"],
            serde_json::json!(21.5)
        );
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
        use broker_connectors_enterprise::{
            AttributeColumnMapping, AttributeColumnType, AzureBlobAuth, AzureBlobSink,
            AzureBlobSinkConfig, ConfluentKafkaConfig, ConfluentKafkaSink,
            ConfluentSecurityProtocol, IcebergPartitionField, IcebergTransform,
            MemoryConfluentTransport, MockAzureBlobTransport, MockRocketMqTransport,
            MockS3TablesTransport, MockTablestoreTransport, PrimaryKeyMapping, PrimaryKeyType,
            RocketMqSink, RocketMqSinkConfig, S3TablesSink, S3TablesSinkConfig, SaslMechanism,
            TablestoreSink, TablestoreSinkConfig,
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
                    compression: broker_connectors_enterprise::AzureBlobCompression::None,
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
                    target_format: broker_connectors_enterprise::S3TablesFormat::NdjsonCompressed,
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
                    security_protocol: ConfluentSecurityProtocol::SaslSsl,
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
            broker_connectors_enterprise::OtsValue::String("sensor-42".to_string())
        );
        assert_eq!(
            batches[0][0].attributes[0].1,
            broker_connectors_enterprise::OtsValue::Double(150.0)
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

    /// Azure Blob REST write via the broker: one ingress publish
    /// routes through `ForwardConnector` into `AzureBlobSink` on
    /// `HttpAzureBlobTransport`, whose idempotent container create plus
    /// block-blob upload land on a local HTTP fake. Every request pins
    /// x-ms-version 2021-08-06.
    #[tokio::test]
    async fn test_azure_blob_rest_write_via_dispatch_against_loopback() {
        use broker_connectors::Sink as _;
        use broker_connectors_enterprise::{
            AzureBlobAuth, AzureBlobSink, AzureBlobSinkConfig, HttpAzureBlobTransport,
            AZURE_STORAGE_VERSION,
        };

        #[derive(Debug, Default)]
        struct Captured {
            inner: parking_lot::Mutex<Vec<CapturedPut>>,
        }
        #[derive(Debug)]
        struct CapturedPut {
            path: String,
            query: Option<String>,
            version: Option<String>,
            auth: Option<String>,
        }

        let captured = Arc::new(Captured::default());
        let app = axum::Router::new().fallback(axum::routing::put({
            let captured = captured.clone();
            move |uri: axum::http::Uri, headers: axum::http::HeaderMap, _body: Bytes| {
                let captured = captured.clone();
                async move {
                    captured.inner.lock().push(CapturedPut {
                        path: uri.path().to_string(),
                        query: uri.query().map(str::to_string),
                        version: headers
                            .get("x-ms-version")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string),
                        auth: headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string),
                    });
                    (
                        axum::http::StatusCode::CREATED,
                        [
                            ("x-ms-request-id", "00000000-0000-0000-0000-000000000000"),
                            ("x-ms-version", AZURE_STORAGE_VERSION),
                            ("ETag", "\"0x8DD000000000000\""),
                            ("Last-Modified", "Tue, 22 Sep 2026 20:00:00 GMT"),
                            ("Date", "Tue, 22 Sep 2026 20:00:00 GMT"),
                            ("x-ms-request-server-encrypted", "false"),
                        ],
                        "",
                    )
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        let config = AzureBlobSinkConfig {
            account_name: "mydeviceblobs".to_string(),
            container_name: "telemetry".to_string(),
            endpoint: Some(format!("http://127.0.0.1:{port}/devstoreaccount1")),
            auth: AzureBlobAuth::SharedKey {
                account_key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".to_string(),
            },
            blob_path_template: "telemetry/${batch_id}.json".to_string(),
            compression: broker_connectors_enterprise::AzureBlobCompression::None,
            max_records_per_blob: Some(1),
            max_bytes_per_blob: None,
            flush_interval_secs: 60,
            buffer_capacity: None,
            timeout_ms: Some(5_000),
        };
        let transport = Arc::new(
            HttpAzureBlobTransport::new(&config, reqwest::Client::new())
                .expect("rest builds with loopback"),
        );
        let sink = Arc::new(AzureBlobSink::new(config, transport).expect("valid sink"));
        engine.connectors().register("rest_blob", sink.clone());
        engine
            .create_rule(
                "rest-blob-rule".to_string(),
                TopicFilter::new("sdk/blob/#").unwrap(),
                Some(
                    r#"SELECT client_id FROM "sdk/blob/#" INTO connector("rest_blob")"#.to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");

        let broker_sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("sdk/blob/line1").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "sensor-42" }"#),
                QoS::AtMostOnce,
                &broker_sink,
            )
            .await;
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.kind(), "azure_blob");

        let puts = captured.inner.lock();
        // One flush = idempotent container create + one blob upload.
        assert_eq!(puts.len(), 2, "got {puts:?}");
        assert!(
            puts.iter().any(|p| p
                .query
                .as_deref()
                .unwrap_or("")
                .contains("restype=container")),
            "container create missing: {puts:?}"
        );
        for put in puts.iter() {
            assert_eq!(put.version.as_deref(), Some(AZURE_STORAGE_VERSION));
            assert!(put.path.contains("telemetry"), "got {put:?}");
            assert!(
                put.auth
                    .as_deref()
                    .unwrap_or("")
                    .starts_with("SharedKey mydeviceblobs:"),
                "SharedKey missing: {put:?}"
            );
        }
        server.abort();
    }

    /// Azure Event Hubs REST write via the broker: one ingress publish
    /// routes through `ForwardConnector` into `AzureEventHubsSink` on
    /// `HttpAzureEventHubsTransport`, whose signed `POST {hub}/messages`
    /// lands on a local HTTP fake. The SAS header carries the key name
    /// (never a pre-formed token in config), so the sink renews it from
    /// the stored key on every attempt.
    #[tokio::test]
    async fn test_azure_eventhubs_rest_write_via_dispatch_against_loopback() {
        use broker_connectors::Sink as _;
        use broker_connectors_enterprise::{
            AzureEventHubsSink, AzureEventHubsSinkConfig, HttpAzureEventHubsTransport,
        };

        #[derive(Debug, Default)]
        struct Captured {
            inner: parking_lot::Mutex<Vec<CapturedPost>>,
        }
        #[derive(Debug)]
        struct CapturedPost {
            path: String,
            auth: Option<String>,
            body: Vec<u8>,
        }

        let captured = Arc::new(Captured::default());
        let app = axum::Router::new().fallback(axum::routing::post({
            let captured = captured.clone();
            move |uri: axum::http::Uri, headers: axum::http::HeaderMap, body: Bytes| {
                let captured = captured.clone();
                async move {
                    captured.inner.lock().push(CapturedPost {
                        path: uri.path().to_string(),
                        auth: headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string),
                        body: body.to_vec(),
                    });
                    axum::http::StatusCode::CREATED
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        let config = AzureEventHubsSinkConfig {
            namespace: "my-eventhub-ns".to_string(),
            event_hub: "telemetry-hub".to_string(),
            endpoint: Some(format!("http://127.0.0.1:{port}")),
            shared_access_key_name: "SendPolicy".to_string(),
            shared_access_key: "dGVzdC1rZXktbWF0ZXJpYWwtMzItYnl0ZXMhIU9L".to_string(),
            partition_key_template: Some("${client_id}".to_string()),
            user_properties: std::collections::HashMap::new(),
            token_ttl_secs: 3_600,
            batch_size: Some(1),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(20),
            max_retries: Some(2),
            initial_backoff_ms: Some(1),
            max_backoff_ms: Some(2),
            timeout_ms: Some(5_000),
        };
        let transport = Arc::new(
            HttpAzureEventHubsTransport::new(&config, reqwest::Client::new())
                .expect("rest builds offline"),
        );
        let sink = Arc::new(AzureEventHubsSink::new(config, transport).expect("valid sink"));
        engine.connectors().register("rest_eventhubs", sink.clone());
        engine
            .create_rule(
                "rest-eventhubs-rule".to_string(),
                TopicFilter::new("sdk/eh/#").unwrap(),
                Some(
                    r#"SELECT client_id FROM "sdk/eh/#" INTO connector("rest_eventhubs")"#
                        .to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");

        let broker_sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("sdk/eh/line1").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "sensor-42" }"#),
                QoS::AtMostOnce,
                &broker_sink,
            )
            .await;
        // The publish travelled the broker into the sink and flushed
        // (batch of 1): one signed POST landed on the fake.
        assert_eq!(sink.kind(), "azure_eventhubs");
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.buffered_rows(), 0);

        let posts = captured.inner.lock();
        assert_eq!(posts.len(), 1, "got {posts:?}");
        assert_eq!(posts[0].path, "/telemetry-hub/messages");
        let auth = posts[0].auth.as_deref().expect("SAS header");
        assert!(auth.starts_with("SharedAccessSignature sr="));
        assert!(auth.contains("&skn=SendPolicy"));
        let doc: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&posts[0].body).unwrap()).unwrap();
        assert_eq!(doc[0]["BrokerProperties"]["PartitionKey"], "sensor-42");
        server.abort();
    }

    /// Sprint 26 studio fanout (INDRA-225): one ingress event routes
    /// through six streaming SQL `INTO connector(...)` rules and lands
    /// simultaneously in the Oracle, CockroachDB, AlloyDB, OpenTSDB,
    /// GreptimeDB, and Datalayers mocks. All transports are in-memory.
    #[tokio::test]
    async fn test_into_fans_out_to_databases_and_timeseries_sinks() {
        use broker_connectors::{
            GreptimeDbConfig, GreptimeDbSink, GreptimeFormat, GreptimePrecision,
            MockGreptimeDbTransport, MockOpenTsdbTransport, OpenTsdbCompression, OpenTsdbConfig,
            OpenTsdbProtocol, OpenTsdbSink,
        };
        use broker_connectors_enterprise::{
            AlloydbAuth, AlloydbColumnMapping, AlloydbConfig, AlloydbSink, CockroachDbConfig,
            CockroachDbSink, DatalayersConfig, DatalayersSink, MockAlloydbTransport,
            MockCockroachDbTransport, MockDatalayersTransport, MockOracleTransport, OracleSink,
            OracleSinkConfig,
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
                    tls: None,
                    ca_bundle_pem: None,
                    tls_ca_file: None,
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

    /// Qualification (QUAL-NONE: a generic webhook is a test-owned
    /// endpoint, not a server product, so no container is needed) for
    /// the enterprise HTTP webhook sink on the maintained `reqwest`
    /// driver.
    ///
    /// Serves its own loopback receiver (ephemeral `axum` server with
    /// HMAC verification plus scripted `429`-then-`200` and `500`
    /// faults), registers the sink with the engine's connector
    /// manager, creates `ForwardConnector` rules, publishes 500 events
    /// through [`RuleEngine::dispatch_ingress`] (never `sink.send`
    /// directly), asserts byte-identical bodies with valid HMAC headers
    /// and exact counts, proves `429`-then-`200` retries to success,
    /// and proves a persistent `500` aborts with the buffer retained.
    /// Runs offline: needs only loopback, never skips. Bind failure
    /// panics (fail closed).
    ///
    /// Run with e.g.:
    /// `cargo test -p broker-rules --lib tests::test_qualify_webhook_write_path_through_rule_engine -- --nocapture`
    #[tokio::test]
    async fn test_qualify_webhook_write_path_through_rule_engine() {
        use axum::{extract::State, http::StatusCode, routing::post, Router};
        use broker_connectors::{
            ConnectorError, HmacAlgorithm, HmacEncoding, HttpAuth, HttpBodyFormat,
            HttpHmacSignature, HttpMethod, HttpSink, HttpSinkConfig, ReqwestHttpTransport,
            Sink as _,
        };
        use std::collections::HashMap;
        use std::sync::{
            atomic::{AtomicU64, Ordering as AtomicOrdering},
            Mutex as StdMutex,
        };

        const SECRET: &str = "qual-hmac-secret";
        const EVENTS: usize = 500;

        #[derive(Debug, Default)]
        struct QualState {
            bodies: StdMutex<Vec<Vec<u8>>>,
            signatures: StdMutex<Vec<String>>,
            bad_hmac: AtomicU64,
            flaky_calls: AtomicU64,
            dead_calls: AtomicU64,
        }

        fn expected_signature(body: &[u8]) -> String {
            HttpHmacSignature {
                header_name: "X-Signature-SHA256".to_string(),
                algorithm: HmacAlgorithm::Sha256,
                secret: SECRET.to_string(),
                encoding: HmacEncoding::Hex,
            }
            .sign(body)
        }

        async fn hook_handler(
            State(state): State<Arc<QualState>>,
            headers: axum::http::HeaderMap,
            body: Bytes,
        ) -> (StatusCode, String) {
            let signature = headers
                .get("X-Signature-SHA256")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            if signature != expected_signature(&body) {
                state.bad_hmac.fetch_add(1, AtomicOrdering::SeqCst);
                return (StatusCode::BAD_REQUEST, "bad hmac".to_string());
            }
            state.signatures.lock().unwrap().push(signature);
            state.bodies.lock().unwrap().push(body.to_vec());
            (StatusCode::OK, "ok".to_string())
        }

        async fn flaky_handler(
            State(state): State<Arc<QualState>>,
            headers: axum::http::HeaderMap,
            body: Bytes,
        ) -> (StatusCode, String) {
            let call = state.flaky_calls.fetch_add(1, AtomicOrdering::SeqCst);
            if call == 0 {
                return (StatusCode::TOO_MANY_REQUESTS, "slow down".to_string());
            }
            hook_handler(State(state), headers, body).await
        }

        async fn dead_handler(
            State(state): State<Arc<QualState>>,
            _headers: axum::http::HeaderMap,
            body: Bytes,
        ) -> (StatusCode, String) {
            state.dead_calls.fetch_add(1, AtomicOrdering::SeqCst);
            state.bodies.lock().unwrap().push(body.to_vec());
            (StatusCode::INTERNAL_SERVER_ERROR, "nope".to_string())
        }

        let state = Arc::new(QualState::default());
        let app = Router::new()
            .route("/hook", post(hook_handler))
            .route("/flaky", post(flaky_handler))
            .route("/dead", post(dead_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("qual bind loopback");
        let port = listener.local_addr().expect("qual addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("qual serve");
        });

        fn qual_config(url: &str) -> HttpSinkConfig {
            HttpSinkConfig {
                url: url.to_string(),
                method: HttpMethod::Post,
                headers: HashMap::new(),
                auth: HttpAuth::None,
                body_format: HttpBodyFormat::RawJson,
                signature: Some(HttpHmacSignature {
                    header_name: "X-Signature-SHA256".to_string(),
                    algorithm: HmacAlgorithm::Sha256,
                    secret: SECRET.to_string(),
                    encoding: HmacEncoding::Hex,
                }),
                batch_size: Some(EVENTS),
                batch_bytes: Some(1_048_576),
                linger_ms: Some(50),
                timeout_ms: Some(5_000),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                buffer_capacity: Some(10_000),
            }
        }

        // 500 events end to end over the real `reqwest` driver, through
        // the broker's rule path (rule registered with the connector
        // manager, message published through the rule engine).
        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        let config = qual_config(&format!("http://127.0.0.1:{port}/hook"));
        let transport = Arc::new(
            ReqwestHttpTransport::new(&config, reqwest::Client::new()).expect("qual transport"),
        );
        let sink = Arc::new(HttpSink::new(config, transport).expect("qual sink"));
        assert_eq!(sink.kind(), "webhook");
        engine.connectors().register("qual-http", sink.clone());
        engine
            .create_rule(
                "qual-http-rule".to_string(),
                TopicFilter::new("sensors/qual").unwrap(),
                None,
                true,
                vec![RuleAction::ForwardConnector {
                    connector_id: "qual-http".to_string(),
                }],
            )
            .expect("qual rule creates");
        let broker_sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());

        let topic = Topic::new("sensors/qual").unwrap();
        let mut expected_bodies = Vec::with_capacity(EVENTS);
        for seq in 0..EVENTS {
            let payload = format!(r#"{{"seq":{seq},"device":"dev-{:02}"}}"#, seq % 16);
            // The sink forwards the projected JSON verbatim, so the wire
            // body is the canonical re-serialization of the payload.
            let document: serde_json::Value =
                serde_json::from_str(&payload).expect("qual payload parses");
            expected_bodies.push(serde_json::to_vec(&document).expect("qual body encodes"));
            let matched = engine
                .dispatch_ingress(
                    &topic,
                    &Bytes::from(payload),
                    QoS::AtLeastOnce,
                    &broker_sink,
                )
                .await;
            assert_eq!(matched, 1, "qual rule must fire once per event");
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), EVENTS as u64, "qual row count");
        assert_eq!(sink.sent_requests(), EVENTS as u64, "qual request count");
        assert_eq!(sink.buffered_rows(), 0);
        eprintln!("qual rows sent: records={EVENTS}");

        // Byte-identical bodies with valid HMAC headers, exact counts, no
        // tolerance: every key present, none extra, none mutated.
        let captured = state.bodies.lock().unwrap().clone();
        assert_eq!(captured.len(), EVENTS, "qual captured count");
        for (index, (got, want)) in captured.iter().zip(expected_bodies.iter()).enumerate() {
            assert_eq!(got, want, "qual body byte mismatch at {index}");
        }
        assert_eq!(
            state.bad_hmac.load(AtomicOrdering::SeqCst),
            0,
            "every request must carry a valid HMAC header"
        );
        assert_eq!(
            state.signatures.lock().unwrap().len(),
            EVENTS,
            "every request must carry the signature header"
        );
        eprintln!("qual rows asserted: count={EVENTS} byte-identical with valid HMAC");

        // 429-then-200 retries to success on the same body, through the
        // rule path as well.
        let flaky_config = HttpSinkConfig {
            url: format!("http://127.0.0.1:{port}/flaky"),
            batch_size: Some(10),
            initial_backoff_ms: Some(1),
            max_backoff_ms: Some(2),
            ..qual_config(&format!("http://127.0.0.1:{port}/flaky"))
        };
        let flaky_transport = Arc::new(
            ReqwestHttpTransport::new(&flaky_config, reqwest::Client::new())
                .expect("qual flaky transport"),
        );
        let flaky_sink =
            Arc::new(HttpSink::new(flaky_config, flaky_transport).expect("qual flaky sink"));
        engine
            .connectors()
            .register("qual-flaky", flaky_sink.clone());
        engine
            .create_rule(
                "qual-flaky-rule".to_string(),
                TopicFilter::new("sensors/qual-flaky").unwrap(),
                None,
                true,
                vec![RuleAction::ForwardConnector {
                    connector_id: "qual-flaky".to_string(),
                }],
            )
            .expect("qual flaky rule creates");
        let flaky_topic = Topic::new("sensors/qual-flaky").unwrap();
        let bodies_before = state.bodies.lock().unwrap().len();
        let matched = engine
            .dispatch_ingress(
                &flaky_topic,
                &Bytes::from_static(br#"{"seq":"retry-probe"}"#),
                QoS::AtLeastOnce,
                &broker_sink,
            )
            .await;
        assert_eq!(matched, 1, "qual flaky rule must fire");
        flaky_sink.flush().await.expect("429-then-200 must succeed");
        assert_eq!(
            state.flaky_calls.load(AtomicOrdering::SeqCst),
            2,
            "one 429 plus one 200"
        );
        assert_eq!(flaky_sink.sent_requests(), 1);
        assert_eq!(flaky_sink.sent_records(), 1);
        assert_eq!(flaky_sink.buffered_rows(), 0);
        // The retried body arrived intact with a valid HMAC.
        let after_retry = state.bodies.lock().unwrap().clone();
        assert_eq!(after_retry.len(), bodies_before + 1);
        let probe: serde_json::Value =
            serde_json::from_slice(&after_retry[bodies_before]).expect("retry body parses");
        assert_eq!(probe, serde_json::json!({"seq": "retry-probe"}));
        eprintln!("qual retry asserted: 429-then-200 delivered once with valid HMAC");

        // Persistent 500 aborts: retries exhausted, buffer retained for
        // inspection, fail-fast breaker engaged.
        let dead_config = HttpSinkConfig {
            url: format!("http://127.0.0.1:{port}/dead"),
            batch_size: Some(10),
            max_retries: Some(1),
            initial_backoff_ms: Some(1),
            max_backoff_ms: Some(2),
            ..qual_config(&format!("http://127.0.0.1:{port}/dead"))
        };
        let dead_transport = Arc::new(
            ReqwestHttpTransport::new(&dead_config, reqwest::Client::new())
                .expect("qual dead transport"),
        );
        let dead_sink =
            Arc::new(HttpSink::new(dead_config, dead_transport).expect("qual dead sink"));
        engine.connectors().register("qual-dead", dead_sink.clone());
        engine
            .create_rule(
                "qual-dead-rule".to_string(),
                TopicFilter::new("sensors/qual-dead").unwrap(),
                None,
                true,
                vec![RuleAction::ForwardConnector {
                    connector_id: "qual-dead".to_string(),
                }],
            )
            .expect("qual dead rule creates");
        let dead_topic = Topic::new("sensors/qual-dead").unwrap();
        let matched = engine
            .dispatch_ingress(
                &dead_topic,
                &Bytes::from_static(br#"{"seq":"abort-probe"}"#),
                QoS::AtLeastOnce,
                &broker_sink,
            )
            .await;
        assert_eq!(matched, 1, "qual dead rule must fire");
        let err = dead_sink.flush().await.expect_err("500 must abort");
        assert!(
            matches!(err, ConnectorError::Connection(_)),
            "exhausted 500s are backpressure, got {err:?}"
        );
        assert_eq!(
            state.dead_calls.load(AtomicOrdering::SeqCst),
            2,
            "initial attempt plus one retry"
        );
        assert_eq!(dead_sink.buffered_rows(), 1);
        let calls = state.dead_calls.load(AtomicOrdering::SeqCst);
        assert!(dead_sink.flush().await.is_err());
        assert_eq!(
            state.dead_calls.load(AtomicOrdering::SeqCst),
            calls,
            "breaker must fail fast without touching the transport"
        );
        eprintln!("qual abort asserted: persistent 500 aborts with buffer retained");

        // Cleanup: stop the loopback receiver (nothing else to remove;
        // no table, bucket, or container was created).
        server.abort();
        eprintln!("qual done: rows={EVENTS} cleaned loopback receiver");
    }
}
