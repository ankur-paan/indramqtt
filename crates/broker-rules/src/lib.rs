use async_trait::async_trait;
use broker_connectors::ConnectorManager;
use bytes::Bytes;
use broker_protocol::{QoS, Topic, TopicFilter};
use parking_lot::RwLock;
use rekuiper_sql::{Evaluator, SelectStmt};
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
/// `sql_query` is an optional streaming-SQL program parsed once at
/// creation into `parsed_query`. At ingress, matching JSON payloads are
/// filtered (WHERE) and projected (SELECT) through `rekuiper-sql`; rules
/// without SQL pass the raw payload through. Stateful constructs
/// (windows, GROUP BY, aggregations) are accepted by the parser but
/// evaluated per-record for now — stateful dispatch is a later sprint.
/// `parsed_query` is skipped in JSON output: the wire form carries the
/// source SQL string, which re-parses on creation.
#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub topic_filter: TopicFilter,
    pub sql_query: Option<String>,
    #[serde(skip_serializing)]
    pub parsed_query: Option<SelectStmt>,
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
pub struct RuleEngine {
    rules: RwLock<HashMap<String, Rule>>,
    next_id: AtomicU64,
    input: Arc<BoundedEventInput>,
    connectors: Arc<ConnectorManager>,
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
            connectors: Arc::new(ConnectorManager::new()),
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
        let rule = Rule {
            id: id.clone(),
            name,
            topic_filter,
            sql_query,
            parsed_query,
            enabled,
            actions,
        };
        self.rules.write().insert(id, rule.clone());
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
        self.rules.write().remove(id).is_some()
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
            let Some(data) = apply_sql(&rule.parsed_query, payload, &rule.id) else {
                continue;
            };
            for action in &rule.actions {
                match action {
                    RuleAction::Republish {
                        topic: dst,
                        qos: action_qos,
                    } => {
                        let effective = std::cmp::min(*action_qos, qos);
                        if let Err(e) = broker_sink
                            .publish(dst.clone(), data.clone(), effective, false)
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
                    RuleAction::ForwardConnector { connector_id } => {
                        if let Err(e) = self.connectors.send(
                            connector_id,
                            topic,
                            &data,
                            qos,
                        )
                        .await
                        {
                            tracing::warn!(
                                rule_id = %rule.id,
                                connector = %connector_id,
                                error = %e,
                                "Rule connector forward failed; continuing with remaining actions"
                            );
                        }
                    }
                }
            }
        }
        matched.len()
    }
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
    Topic::new(topic).map_err(|e| e.to_string())?;
    if let Some(filter) = topic_filter {
        if !filter.trim().is_empty() {
            let parsed =
                TopicFilter::new(filter).map_err(|e| format!("invalid topic_filter: {e}"))?;
            let probe = Topic::new(topic).map_err(|e| e.to_string())?;
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
    let record: HashMap<String, serde_json::Value> = match payload {
        serde_json::Value::Object(map) => map.clone().into_iter().collect(),
        _ => return Ok((false, None)),
    };
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
    async fn test_invalid_sql_rejected_at_creation() {        let engine = RuleEngine::new(16, BackpressurePolicy::DropOldest);
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
