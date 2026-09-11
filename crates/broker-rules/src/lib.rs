use async_trait::async_trait;
use bytes::Bytes;
use broker_protocol::{QoS, Topic, TopicFilter};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
/// `sql_query` is carried opaquely for now (projection/predicate pushdown
/// is a later sprint); matching and actions execute natively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub topic_filter: TopicFilter,
    pub sql_query: Option<String>,
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
pub struct RuleEngine {
    rules: RwLock<HashMap<String, Rule>>,
    next_id: AtomicU64,
    input: Arc<BoundedEventInput>,
}

impl RuleEngine {
    /// Create an engine with a bounded ingress queue (`capacity` floors at
    /// 1). The queue backs future async ingestion; the hot path calls
    /// [`RuleEngine::dispatch_ingress`] synchronously for determinism.
    pub fn new(queue_capacity: usize, policy: BackpressurePolicy) -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            input: BoundedEventInput::new(queue_capacity, policy),
        }
    }

    /// Bounded ingress queue for flood protection at outer boundaries.
    pub fn input(&self) -> &Arc<BoundedEventInput> {
        &self.input
    }

    /// Build and store a rule, assigning its id (`rule-<n>`).
    /// Callers pass already-validated types; fallible parsing
    /// ([`TopicFilter::new`], [`Topic::new`]) happens at the API boundary.
    pub fn create_rule(
        &self,
        name: String,
        topic_filter: TopicFilter,
        sql_query: Option<String>,
        enabled: bool,
        actions: Vec<RuleAction>,
    ) -> Rule {
        let id = format!("rule-{}", self.next_id.fetch_add(1, Ordering::SeqCst));
        let rule = Rule {
            id: id.clone(),
            name,
            topic_filter,
            sql_query,
            enabled,
            actions,
        };
        self.rules.write().insert(id, rule.clone());
        rule
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
        self.rules.write().remove(id).is_some()
    }

    /// Execute every enabled rule whose filter matches `topic`.
    /// Delivery QoS per republish is `min(ingress QoS, action QoS)` so a
    /// rule can never upgrade delivery guarantees. Sink failures are
    /// logged; remaining actions still run.
    pub async fn dispatch_ingress(
        &self,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
        broker_sink: &Arc<dyn BrokerSink>,
    ) {
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
            for action in &rule.actions {
                match action {
                    RuleAction::Republish {
                        topic: dst,
                        qos: action_qos,
                    } => {
                        let effective = std::cmp::min(*action_qos, qos);
                        if let Err(e) = broker_sink
                            .publish(dst.clone(), payload.clone(), effective, false)
                            .await
                        {
                            tracing::warn!(
                                rule_id = %rule.id,
                                error = %e,
                                "Rule republish failed; continuing with remaining actions"
                            );
                        }
                    }
                    RuleAction::Log => {
                        tracing::info!(
                            rule_id = %rule.id,
                            topic = %topic,
                            "Rule matched ingress event"
                        );
                    }
                }
            }
        }
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
        );
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
        );
        engine.create_rule(
            "other-branch".to_string(),
            TopicFilter::new("factory/#").unwrap(),
            None,
            true,
            vec![RuleAction::Republish {
                topic: Topic::new("alerts/other").unwrap(),
                qos: QoS::AtMostOnce,
            }],
        );
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
        );
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
}
