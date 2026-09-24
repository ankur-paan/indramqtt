//! Amazon DynamoDB sink (INDRA-179).
//!
//! Buffers MQTT events as DynamoDB items and writes them with
//! `BatchWriteItem` (`DynamoDB_20120810.BatchWriteItem` over HTTP
//! POST, `application/x-amz-json-1.0`), signed with AWS Signature
//! Version 4 for service `dynamodb`.
//!
//! The write path runs on the maintained `aws-sdk-dynamodb` driver
//! ([`SdkDynamoDbTransport`] below): typed `AttributeValue` maps
//! with driver-owned SigV4 (static access-key credentials, session
//! token when configured, endpoint override for local servers). The
//! legacy hand-written [`HttpDynamoDbTransport`] (shared signer in
//! `super`) is retained for endpoint overrides and offline unit
//! tests only; production wiring uses the driver transport.
//! Keys derive from templates, TTL attributes compute as
//! `now + ttl_secs`, and whole JSON documents unpack into typed
//! attributes (`S`, `N`, `BOOL`, `M`, `L`, `NULL`).
//!
//! Unprocessed items requeue selectively: the transport reports the
//! unprocessed subset, which retries alone with jittered backoff
//! while clean items stay written.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

pub const DYNAMODB_TARGET: &str = "DynamoDB_20120810.BatchWriteItem";
pub const DYNAMODB_CONTENT_TYPE: &str = "application/x-amz-json-1.0";

/// DynamoDB key configuration: attribute name, value template and
/// scalar type (`S` string or `N` number).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamoKeyConfig {
    pub name: String,
    pub template: String,
    pub key_type: String,
}

impl DynamoKeyConfig {
    pub fn validate(&self, role: &str) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(ConnectorError::Dispatch(format!(
                "dynamodb {role} key name must not be empty"
            )));
        }
        if self.key_type != "S" && self.key_type != "N" {
            return Err(ConnectorError::Dispatch(format!(
                "dynamodb {role} key_type must be \"S\" or \"N\": {:?}",
                self.key_type
            )));
        }
        if self.template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(format!(
                "dynamodb {role} key template must not be empty"
            )));
        }
        Ok(())
    }

    /// Render + type-check the key value for one event.
    pub fn render(
        &self,
        role: &str,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
    ) -> Result<String> {
        let vars = event_variables(topic, payload, qos, millis, &self.template);
        let value = render_key_template(&self.template, &vars)?;
        if value.trim().is_empty() {
            return Err(ConnectorError::Dispatch(format!(
                "dynamodb {role} key rendered empty"
            )));
        }
        if self.key_type == "N" && value.trim().parse::<f64>().is_err() {
            return Err(ConnectorError::Dispatch(format!(
                "dynamodb {role} key must be numeric for N: {value:?}"
            )));
        }
        Ok(value)
    }
}

/// Owned template variables for one event: base set (`topic`,
/// `client_id`, `qos`, `timestamp`) plus the `${payload.<field>}`
/// names the template actually references (empty when absent, so
/// validation-time dummies never trip unknown-variable errors).
fn event_variables(
    topic: &str,
    payload: &[u8],
    qos: QoS,
    millis: i64,
    template: &str,
) -> Vec<(String, String)> {
    let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
    let field = |name: &str| match doc.get(name) {
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
        _ => String::new(),
    };
    let mut vars = vec![
        ("topic".to_string(), topic.to_string()),
        ("client_id".to_string(), field("client_id")),
        ("qos".to_string(), u8::from(qos).to_string()),
        ("timestamp".to_string(), millis.to_string()),
    ];
    let mut rest = template;
    while let Some(start) = rest.find("${payload.") {
        let after = &rest[start + "${payload.".len()..];
        if let Some(close) = after.find('}') {
            let name = &after[..close];
            let key = format!("payload.{name}");
            if !vars.iter().any(|(k, _)| k == &key) {
                vars.push((key, field(name)));
            }
            rest = &after[close + 1..];
        } else {
            break;
        }
    }
    vars
}

/// Render a template over owned event variables.
fn render_key_template(template: &str, vars: &[(String, String)]) -> Result<String> {
    let borrowed: Vec<(&str, String)> = vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    render_template(template, &borrowed)
}

fn default_batch_size() -> Option<usize> {
    Some(25)
}

fn default_batch_bytes() -> Option<usize> {
    Some(1_048_576)
}

fn default_linger_ms() -> Option<u64> {
    Some(10)
}

fn default_max_retries() -> Option<usize> {
    Some(4)
}

fn default_initial_backoff_ms() -> Option<u64> {
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    Some(2_000)
}

/// DynamoDB sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamoDbSinkConfig {
    /// Table name.
    pub table_name: String,
    /// AWS region, e.g. `us-east-1`.
    pub region: String,
    /// Custom endpoint (DynamoDB Local / LocalStack); defaults to
    /// `https://dynamodb.{region}.amazonaws.com`.
    #[serde(default)]
    pub endpoint: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// STS session token for temporary credentials.
    #[serde(default)]
    pub session_token: Option<String>,
    pub partition_key: DynamoKeyConfig,
    /// Optional sort key.
    #[serde(default)]
    pub sort_key: Option<DynamoKeyConfig>,
    /// TTL attribute name (written as `now_secs + ttl_secs`).
    #[serde(default)]
    pub ttl_attribute: Option<String>,
    /// TTL duration in seconds (needs `ttl_attribute` to take effect).
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Attribute templates; the exact value `"${payload}"` unpacks
    /// the whole JSON document into attributes.
    #[serde(default)]
    pub attributes_mapping: HashMap<String, String>,
    /// Items per `BatchWriteItem` (default 25, API cap).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 1 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 10).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on throttles/unprocessed (default 4, `None` unbounded).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 2000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl DynamoDbSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.table_name.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "dynamodb table_name must not be empty".to_string(),
            ));
        }
        if self.region.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "dynamodb region must not be empty".to_string(),
            ));
        }
        if let Some(endpoint) = &self.endpoint {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(ConnectorError::Dispatch(format!(
                    "dynamodb endpoint must be http(s): {endpoint:?}"
                )));
            }
        }
        if self.access_key_id.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "dynamodb access_key_id must not be empty".to_string(),
            ));
        }
        if self.secret_access_key.is_empty() {
            return Err(ConnectorError::Dispatch(
                "dynamodb secret_access_key must not be empty".to_string(),
            ));
        }
        self.partition_key.validate("partition")?;
        if let Some(sort_key) = &self.sort_key {
            sort_key.validate("sort")?;
        }
        // Strict template checks with dummy values (syntax + key types).
        self.partition_key.render(
            "partition",
            "dummy",
            br#"{"client_id":"dummy"}"#,
            QoS::AtMostOnce,
            0,
        )?;
        if let Some(sort_key) = &self.sort_key {
            sort_key.render(
                "sort",
                "dummy",
                br#"{"client_id":"dummy"}"#,
                QoS::AtMostOnce,
                0,
            )?;
        }
        for (name, template) in &self.attributes_mapping {
            if name.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "dynamodb attribute names must not be empty".to_string(),
                ));
            }
            if template != "${payload}" {
                self.render_text(
                    template,
                    "dummy",
                    br#"{"client_id":"dummy"}"#,
                    QoS::AtMostOnce,
                    0,
                )?;
            }
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "dynamodb batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "dynamodb batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn endpoint_url(&self) -> String {
        match &self.endpoint {
            Some(endpoint) => endpoint.trim_end_matches('/').to_string(),
            None => format!("https://dynamodb.{}.amazonaws.com", self.region),
        }
    }

    pub fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_batch_bytes(&self) -> usize {
        self.batch_bytes.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_linger(&self) -> Duration {
        self.linger_ms
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }

    /// Build the owned variable set, then render (two-phase so the
    /// strict renderer borrows safely).
    fn render_text(
        &self,
        template: &str,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
    ) -> Result<String> {
        let vars = event_variables(topic, payload, qos, millis, template);
        render_key_template(template, &vars)
    }
}

// ---------------------------------------------------------------------------
// DynamoDB JSON typing.
// ---------------------------------------------------------------------------

/// Render one JSON value as a DynamoDB AttributeValue JSON fragment.
pub fn dynamodb_attribute(value: &serde_json::Value) -> Result<String> {
    match value {
        serde_json::Value::Null => Ok("{\"NULL\":true}".to_string()),
        serde_json::Value::Bool(v) => Ok(format!("{{\"BOOL\":{v}}}")),
        serde_json::Value::Number(n) => Ok(format!("{{\"N\":\"{n}\"}}")),
        serde_json::Value::String(text) => Ok(format!(
            "{{\"S\":{}}}",
            serde_json::to_string(text).unwrap_or_default()
        )),
        serde_json::Value::Array(items) => {
            let mut out = String::from("{\"L\":[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&dynamodb_attribute(item)?);
            }
            out.push_str("]}");
            Ok(out)
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{\"M\":{");
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                out.push_str(&dynamodb_attribute(&map[*key])?);
            }
            out.push_str("}}");
            Ok(out)
        }
    }
}

/// Build one item body: keys + TTL + mapped attributes (`${payload}`
/// unpacks the whole document; explicit mappings win on collision).
pub fn build_item_body(
    config: &DynamoDbSinkConfig,
    topic: &str,
    payload: &[u8],
    qos: QoS,
    millis: i64,
) -> Result<String> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| ConnectorError::Dispatch("dynamodb payload must be UTF-8".to_string()))?;
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|_| ConnectorError::Dispatch("dynamodb payload must be JSON".to_string()))?;
    let partition = config
        .partition_key
        .render("partition", topic, payload, qos, millis)?;
    let mut item = String::from("{");
    item.push_str(&serde_json::to_string(&config.partition_key.name).unwrap_or_default());
    item.push(':');
    if config.partition_key.key_type == "N" {
        item.push_str(&format!("{{\"N\":\"{partition}\"}}"));
    } else {
        item.push_str(&format!(
            "{{\"S\":{}}}",
            serde_json::to_string(&partition).unwrap_or_default()
        ));
    }
    if let Some(sort_key) = &config.sort_key {
        let sort = sort_key.render("sort", topic, payload, qos, millis)?;
        item.push(',');
        item.push_str(&serde_json::to_string(&sort_key.name).unwrap_or_default());
        item.push(':');
        if sort_key.key_type == "N" {
            item.push_str(&format!("{{\"N\":\"{sort}\"}}"));
        } else {
            item.push_str(&format!(
                "{{\"S\":{}}}",
                serde_json::to_string(&sort).unwrap_or_default()
            ));
        }
    }
    if let (Some(ttl_attribute), Some(ttl_secs)) = (&config.ttl_attribute, config.ttl_secs) {
        let expire_at = (millis.max(0) as u64 / 1_000).saturating_add(ttl_secs);
        item.push(',');
        item.push_str(&serde_json::to_string(ttl_attribute).unwrap_or_default());
        item.push(':');
        item.push_str(&format!("{{\"N\":\"{expire_at}\"}}"));
    }
    // Attribute mappings: sorted for determinism; explicit wins.
    let mut names: Vec<&String> = config.attributes_mapping.keys().collect();
    names.sort();
    let mut unpacked: Vec<(String, serde_json::Value)> = Vec::new();
    if config
        .attributes_mapping
        .values()
        .any(|t| t == "${payload}")
    {
        match &value {
            serde_json::Value::Object(map) => {
                for (key, field) in map {
                    unpacked.push((key.clone(), field.clone()));
                }
            }
            _ => {
                return Err(ConnectorError::Dispatch(
                    "dynamodb ${payload} needs a JSON object".to_string(),
                ))
            }
        }
    }
    for name in names {
        let template = &config.attributes_mapping[name];
        if template == "${payload}" {
            continue;
        }
        let rendered = config.render_text(template, topic, payload, qos, millis)?;
        // Rendered numbers/bools keep their DynamoDB types so payload
        // passthrough preserves N/BOOL (raw text stays S).
        let value = serde_json::from_str::<serde_json::Value>(&rendered)
            .ok()
            .filter(|v| v.is_number() || v.is_boolean() || v.is_null())
            .unwrap_or(serde_json::Value::String(rendered));
        unpacked.push((name.clone(), value));
    }
    unpacked.sort_by(|a, b| a.0.cmp(&b.0));
    // Explicit mappings win: last write wins per key.
    let mut merged: Vec<(String, serde_json::Value)> = Vec::new();
    for (key, field) in unpacked {
        if let Some(slot) = merged.iter_mut().find(|(k, _)| k == &key) {
            slot.1 = field;
        } else {
            merged.push((key, field));
        }
    }
    for (key, field) in &merged {
        // Keys already present (partition/sort/ttl) are not overwritten.
        if key == &config.partition_key.name
            || config
                .sort_key
                .as_ref()
                .is_some_and(|sort| key == &sort.name)
            || config.ttl_attribute.as_ref().is_some_and(|ttl| key == ttl)
        {
            continue;
        }
        item.push(',');
        item.push_str(&serde_json::to_string(key).unwrap_or_default());
        item.push(':');
        item.push_str(&dynamodb_attribute(field)?);
    }
    item.push('}');
    Ok(item)
}

/// Render the `BatchWriteItem` JSON body for table + item bodies.
pub fn render_batch_body(table: &str, items: &[String]) -> Vec<u8> {
    let mut body = String::from("{\"RequestItems\":{");
    body.push_str(&serde_json::to_string(table).unwrap_or_default());
    body.push_str(":[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str("{\"PutRequest\":{\"Item\":");
        body.push_str(item);
        body.push_str("}}");
    }
    body.push_str("]}}");
    body.into_bytes()
}

/// Parse a `BatchWriteItem` response into unprocessed item bodies
/// (empty when everything was written).
pub fn parse_unprocessed(table: &str, body: &[u8]) -> Result<Vec<String>> {
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ConnectorError::Connection(format!("dynamodb bad response JSON: {e}")))?;
    let empty = Vec::new();
    let pending = doc
        .get("UnprocessedItems")
        .and_then(|v| v.get(table))
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut items = Vec::new();
    for entry in pending {
        if let Some(item) = entry.get("PutRequest").and_then(|v| v.get("Item")) {
            items.push(item.to_string());
        }
    }
    Ok(items)
}

/// Sign a `BatchWriteItem` POST with SigV4 (service `dynamodb`),
/// returning the `Authorization` value plus the `x-amz-date` stamp.
pub fn sign_batch_write(
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    region: &str,
    host: &str,
    body: &[u8],
    millis: i64,
) -> (String, String) {
    let payload_hash = super::sha256_hex(body);
    let date = super::amz_date(millis);
    let mut headers = vec![
        (
            "content-type".to_string(),
            DYNAMODB_CONTENT_TYPE.to_string(),
        ),
        ("host".to_string(), host.to_string()),
        ("x-amz-date".to_string(), date.clone()),
        ("x-amz-target".to_string(), DYNAMODB_TARGET.to_string()),
    ];
    if let Some(token) = session_token {
        headers.push(("x-amz-security-token".to_string(), token.to_string()));
    }
    let auth = super::sigv4_authorization(&super::SigV4Signing {
        method: "POST",
        canonical_uri: "/".to_string(),
        canonical_query: String::new(),
        headers,
        payload_hash,
        access_key_id,
        secret_access_key,
        region,
        service: "dynamodb",
        millis,
    });
    (auth, date)
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// One item write on the wire (body + original row index for
/// unprocessed-item mapping).
#[derive(Debug, Clone)]
pub struct DynamoDbItem {
    pub body: String,
    pub row_index: usize,
}

/// One `BatchWriteItem` call.
#[derive(Debug, Clone)]
pub struct DynamoDbBatchWriteRequest {
    pub table: String,
    pub items: Vec<DynamoDbItem>,
}

/// Scripted per-call outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockDynamoDbOutcome {
    /// Everything written.
    Accepted,
    /// These row indices come back unprocessed (requeued selectively).
    Unprocessed(Vec<usize>),
    /// Whole-batch throttle (retries everything).
    Throttled,
    /// Terminal dispatch failure.
    Terminal(String),
}

#[async_trait]
pub trait DynamoDbTransport: Send + Sync {
    async fn batch_write_item(&self, req: &DynamoDbBatchWriteRequest) -> Result<Vec<usize>>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
/// Returns unprocessed row indices (empty = all written).
#[derive(Debug, Default)]
pub struct MockDynamoDbTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockDynamoDbOutcome>>,
    captured: parking_lot::Mutex<Vec<DynamoDbBatchWriteRequest>>,
    calls: AtomicU64,
}

impl MockDynamoDbTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: all accepted).
    pub fn script_outcomes(&self, outcomes: Vec<MockDynamoDbOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<DynamoDbBatchWriteRequest> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DynamoDbTransport for MockDynamoDbTransport {
    async fn batch_write_item(&self, req: &DynamoDbBatchWriteRequest) -> Result<Vec<usize>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(DynamoDbBatchWriteRequest {
            table: req.table.clone(),
            items: req.items.clone(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockDynamoDbOutcome::Accepted) => Ok(Vec::new()),
            Some(MockDynamoDbOutcome::Unprocessed(indices)) => Ok(indices),
            Some(MockDynamoDbOutcome::Throttled) => Err(ConnectorError::Connection(
                "mock dynamodb throttled".to_string(),
            )),
            Some(MockDynamoDbOutcome::Terminal(message)) => Err(ConnectorError::Dispatch(message)),
        }
    }
}

/// Production transport: signed `POST {endpoint}/` with the JSON body.
/// Unprocessed items map back to row indices by deep-matching item
/// bodies against the sent batch (first-unmatched wins).
pub struct HttpDynamoDbTransport {
    endpoint: String,
    host: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    client: reqwest::Client,
}

impl HttpDynamoDbTransport {
    pub fn new(config: &DynamoDbSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        let endpoint = config.endpoint_url();
        let host = endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default()
            .to_string();
        Ok(Self {
            endpoint,
            host,
            region: config.region.clone(),
            access_key_id: config.access_key_id.clone(),
            secret_access_key: config.secret_access_key.clone(),
            session_token: config.session_token.clone(),
            client,
        })
    }
}

#[async_trait]
impl DynamoDbTransport for HttpDynamoDbTransport {
    async fn batch_write_item(&self, req: &DynamoDbBatchWriteRequest) -> Result<Vec<usize>> {
        let bodies: Vec<String> = req.items.iter().map(|item| item.body.clone()).collect();
        let body = render_batch_body(&req.table, &bodies);
        let millis = now_millis();
        let (auth, date) = sign_batch_write(
            &self.access_key_id,
            &self.secret_access_key,
            self.session_token.as_deref(),
            &self.region,
            &self.host,
            &body,
            millis,
        );
        let mut request = self
            .client
            .post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE, DYNAMODB_CONTENT_TYPE)
            .header("X-Amz-Target", DYNAMODB_TARGET)
            .header("X-Amz-Date", date)
            .header(reqwest::header::AUTHORIZATION, auth)
            .body(body);
        if let Some(token) = &self.session_token {
            request = request.header("X-Amz-Security-Token", token.as_str());
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("dynamodb write failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 429 || (500..=504).contains(&status) {
            return Err(ConnectorError::Connection(format!(
                "dynamodb throttled with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(ConnectorError::Dispatch(format!(
                "dynamodb write failed with {status}"
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("dynamodb read failed: {e}")))?;
        let unprocessed = parse_unprocessed(&req.table, &bytes)?;
        // Map unprocessed bodies back to row indices (first match wins).
        let mut used = vec![false; req.items.len()];
        let mut indices = Vec::new();
        for body in unprocessed {
            if let Some(position) = req
                .items
                .iter()
                .position(|item| !used[item.row_index] && item.body == body)
            {
                used[req.items[position].row_index] = true;
                indices.push(req.items[position].row_index);
            }
        }
        Ok(indices)
    }
}

// ---------------------------------------------------------------------------
// Maintained-driver transport (`aws-sdk-dynamodb`).
// ---------------------------------------------------------------------------

/// Convert one DynamoDB-JSON attribute (`{"S": ...}`, `{"N": ...}`,
/// `{"BOOL": ...}`, `{"NULL": ...}`, `{"M": ...}`, `{"L": ...}`) into
/// the driver's typed `AttributeValue`. Only the shapes
/// [`dynamodb_attribute`] emits are accepted; anything else is a
/// terminal dispatch error (fail closed, never a guessed type).
pub fn attribute_value_from_dynamodb_json(
    value: &serde_json::Value,
) -> Result<aws_sdk_dynamodb::types::AttributeValue> {
    use aws_sdk_dynamodb::types::AttributeValue;
    let obj = value.as_object().ok_or_else(|| {
        ConnectorError::Dispatch("dynamodb attribute must be a typed object".to_string())
    })?;
    if let Some(text) = obj.get("S").and_then(|v| v.as_str()) {
        return Ok(AttributeValue::S(text.to_string()));
    }
    if let Some(number) = obj.get("N").and_then(|v| v.as_str()) {
        return Ok(AttributeValue::N(number.to_string()));
    }
    if let Some(flag) = obj.get("BOOL").and_then(|v| v.as_bool()) {
        return Ok(AttributeValue::Bool(flag));
    }
    if let Some(null) = obj.get("NULL").and_then(|v| v.as_bool()) {
        return Ok(AttributeValue::Null(null));
    }
    if let Some(map) = obj.get("M").and_then(|v| v.as_object()) {
        let mut fields = HashMap::with_capacity(map.len());
        for (key, field) in map {
            fields.insert(key.clone(), attribute_value_from_dynamodb_json(field)?);
        }
        return Ok(AttributeValue::M(fields));
    }
    if let Some(list) = obj.get("L").and_then(|v| v.as_array()) {
        let mut items = Vec::with_capacity(list.len());
        for entry in list {
            items.push(attribute_value_from_dynamodb_json(entry)?);
        }
        return Ok(AttributeValue::L(items));
    }
    Err(ConnectorError::Dispatch(
        "dynamodb attribute has an unsupported type (expected S/N/BOOL/NULL/M/L)".to_string(),
    ))
}

/// Convert one item body from [`build_item_body`] into the driver's
/// attribute map for `PutRequest`.
pub fn item_body_to_attribute_map(
    body: &str,
) -> Result<HashMap<String, aws_sdk_dynamodb::types::AttributeValue>> {
    let doc: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| ConnectorError::Dispatch(format!("dynamodb item is not JSON: {e}")))?;
    let map = doc.as_object().ok_or_else(|| {
        ConnectorError::Dispatch("dynamodb item must be a JSON object".to_string())
    })?;
    let mut out = HashMap::with_capacity(map.len());
    for (key, value) in map {
        out.insert(key.clone(), attribute_value_from_dynamodb_json(value)?);
    }
    Ok(out)
}

/// Retryable DynamoDB failure text: provisioned-throughput exceeded,
/// throttling, request-limit, write conflicts, internal failures,
/// timeouts and transport errors. The sink retries these with
/// jittered backoff; anything else (validation, missing resources,
/// auth) is terminal. Matching is by error text so it stays correct
/// across driver revisions without depending on generated variant
/// names.
// TODO(parity): the retry-vs-terminal split per BatchWriteItem error
// code is not pinned by the spec; recheck this list against the
// structured BatchWriteItemError variants on driver upgrades.
fn is_retryable_dynamodb_error(text: &str) -> bool {
    const RETRYABLE: &[&str] = &[
        "provisionedthroughputexceeded",
        "throttl",
        "requestlimitexceeded",
        "replicatedwriteconflict",
        "internalservererror",
        "internalfailure",
        "serviceunavailable",
        "timeout",
        "timed out",
        "connection",
        "dispatch",
        "unavailable",
    ];
    let lower = text.to_lowercase();
    RETRYABLE.iter().any(|marker| lower.contains(marker))
}

fn classify_dynamodb_sdk_error(text: String) -> ConnectorError {
    if is_retryable_dynamodb_error(&text) {
        ConnectorError::Connection(text)
    } else {
        ConnectorError::Dispatch(text)
    }
}

/// Map driver-returned unprocessed `WriteRequest`s back to the
/// request's row positions by structural match (first-unmatched
/// wins), mirroring the legacy HTTP transport. Absent or empty means
/// everything was written. An entry that matches nothing fails
/// closed as a connection error so the sink retries the whole batch
/// instead of dropping it.
fn map_unprocessed_indices(
    pending: &[HashMap<String, aws_sdk_dynamodb::types::AttributeValue>],
    unprocessed: Option<&HashMap<String, Vec<aws_sdk_dynamodb::types::WriteRequest>>>,
    table: &str,
) -> Result<Vec<usize>> {
    let empty: Vec<aws_sdk_dynamodb::types::WriteRequest> = Vec::new();
    let entries = unprocessed
        .and_then(|map| map.get(table))
        .map(Vec::as_slice)
        .unwrap_or(&empty);
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let mut used = vec![false; pending.len()];
    let mut indices = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(item) = entry.put_request().map(|put| put.item()) else {
            return Err(ConnectorError::Connection(
                "dynamodb returned an unprocessed entry without an item; retrying whole batch"
                    .to_string(),
            ));
        };
        let Some(position) = pending
            .iter()
            .enumerate()
            .position(|(index, map)| !used[index] && map == item)
        else {
            return Err(ConnectorError::Connection(
                "dynamodb returned an unprocessed item that was never sent; retrying whole batch"
                    .to_string(),
            ));
        };
        used[position] = true;
        indices.push(position);
    }
    Ok(indices)
}

/// Production transport on the maintained `aws-sdk-dynamodb` driver:
/// `BatchWriteItem` with driver-owned SigV4 (static access-key
/// credentials, session token when configured, endpoint override for
/// local servers). One driver round trip is bounded by the configured
/// request timeout so a slow server surfaces as a retryable
/// connection error instead of stalling the rule path.
pub struct SdkDynamoDbTransport {
    client: aws_sdk_dynamodb::Client,
    timeout: Duration,
}

impl SdkDynamoDbTransport {
    pub fn new(config: &DynamoDbSinkConfig) -> Result<Self> {
        config.validate()?;
        let region = aws_sdk_dynamodb::config::Region::new(config.region.clone());
        let credentials = aws_sdk_dynamodb::config::Credentials::new(
            config.access_key_id.clone(),
            config.secret_access_key.clone(),
            config.session_token.clone(),
            None,
            "indramqtt-static",
        );
        let provider = aws_sdk_dynamodb::config::SharedCredentialsProvider::new(credentials);
        let mut builder = aws_sdk_dynamodb::Config::builder()
            .behavior_version_latest()
            .region(region)
            .credentials_provider(provider);
        if let Some(endpoint) = &config.endpoint {
            builder = builder.endpoint_url(endpoint.trim_end_matches('/'));
        }
        let sdk_config = builder.build();
        Ok(Self {
            client: aws_sdk_dynamodb::Client::from_conf(sdk_config),
            timeout: config.timeout(),
        })
    }

    /// Borrow the driver client (table setup and query-back for
    /// qualification; the write path stays behind the trait).
    pub fn client(&self) -> &aws_sdk_dynamodb::Client {
        &self.client
    }

    /// Test hook proving `new` stores the configured timeout; the
    /// production path applies `self.timeout` to the driver call.
    #[cfg(test)]
    fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[async_trait]
impl DynamoDbTransport for SdkDynamoDbTransport {
    async fn batch_write_item(&self, req: &DynamoDbBatchWriteRequest) -> Result<Vec<usize>> {
        use aws_sdk_dynamodb::types::{PutRequest, WriteRequest};
        // Owned attribute maps ride alongside the request so
        // unprocessed entries map back structurally.
        let mut pending = Vec::with_capacity(req.items.len());
        let mut writes = Vec::with_capacity(req.items.len());
        for item in &req.items {
            let map = item_body_to_attribute_map(&item.body)?;
            let put = PutRequest::builder()
                .set_item(Some(map.clone()))
                .build()
                .map_err(|e| ConnectorError::Dispatch(format!("dynamodb put build: {e}")))?;
            writes.push(WriteRequest::builder().put_request(put).build());
            pending.push(map);
        }
        let mut request_items = HashMap::with_capacity(1);
        request_items.insert(req.table.clone(), writes);
        let timeout = self.timeout;
        let output = tokio::time::timeout(
            timeout,
            self.client
                .batch_write_item()
                .set_request_items(Some(request_items))
                .send(),
        )
        .await
        .map_err(|_| {
            ConnectorError::Connection(format!(
                "dynamodb driver timed out after {}ms",
                timeout.as_millis()
            ))
        })?
        .map_err(|e| classify_dynamodb_sdk_error(format!("dynamodb write failed: {e:?} ({e})")))?;
        map_unprocessed_indices(&pending, output.unprocessed_items(), &req.table)
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row: item body + byte size.
#[derive(Debug, Clone)]
struct DynamoRow {
    body: String,
}

struct DynamoBuffer {
    queue: BatchQueue<DynamoRow>,
    bytes: usize,
}

/// DynamoDB sink: buffers items, writes batches with selective
/// unprocessed-item requeue.
pub struct DynamoDbSink {
    config: DynamoDbSinkConfig,
    transport: Arc<dyn DynamoDbTransport>,
    buffer: parking_lot::Mutex<DynamoBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl DynamoDbSink {
    pub fn new(config: DynamoDbSinkConfig, transport: Arc<dyn DynamoDbTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(DynamoBuffer {
                queue: BatchQueue::new(config.effective_batch_size(), linger),
                bytes: 0,
            }),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &DynamoDbSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().queue.len()
    }

    fn backoff_delay(&self, attempt: usize) -> Duration {
        let initial = self.config.initial_backoff_ms.unwrap_or(100).max(1);
        let max = self.config.max_backoff_ms.unwrap_or(2_000).max(1);
        let grown = initial
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(max);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(max.saturating_mul(2)))
    }

    /// Flush buffered rows (no-op when empty). Unprocessed indices
    /// requeue selectively; throttles retry everything; terminal
    /// outcomes restore the pending set and propagate.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest, taken_bytes) = {
            let mut buffer = self.buffer.lock();
            let (rows, oldest) = buffer.queue.take_batch();
            let taken = std::mem::replace(&mut buffer.bytes, 0);
            (rows, oldest, taken)
        };
        if rows.is_empty() {
            return Ok(());
        }
        let mut pending: Vec<DynamoRow> = rows;
        let total = pending.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            let request = DynamoDbBatchWriteRequest {
                table: self.config.table_name.clone(),
                items: pending
                    .iter()
                    .enumerate()
                    .map(|(position, row)| DynamoDbItem {
                        body: row.body.clone(),
                        row_index: position,
                    })
                    .collect(),
            };
            match self.transport.batch_write_item(&request).await {
                Ok(unprocessed) if unprocessed.is_empty() => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
                    self.sent_records.fetch_add(total, Ordering::Relaxed);
                    return Ok(());
                }
                Ok(unprocessed) => {
                    if attempt >= max_retries {
                        return self.restore_err(
                            pending,
                            oldest,
                            taken_bytes,
                            ConnectorError::Connection(format!(
                                "dynamodb {} unprocessed after {attempt} retries",
                                unprocessed.len()
                            )),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                    let mut next = Vec::with_capacity(unprocessed.len());
                    for index in unprocessed {
                        if let Some(row) = pending.get(index).cloned() {
                            next.push(row);
                        }
                    }
                    pending = next;
                }
                Err(ConnectorError::Connection(message)) => {
                    if attempt >= max_retries {
                        return self.restore_err(
                            pending,
                            oldest,
                            taken_bytes,
                            ConnectorError::Connection(message),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                }
                Err(e) => {
                    return self.restore_err(pending, oldest, taken_bytes, e);
                }
            }
        }
    }

    fn restore_err(
        &self,
        rows: Vec<DynamoRow>,
        oldest: Option<std::time::Instant>,
        bytes: usize,
        error: ConnectorError,
    ) -> Result<()> {
        let mut buffer = self.buffer.lock();
        buffer.queue.restore(rows, oldest);
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        self.backoff.lock().failure();
        Err(error)
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full, stale, or over the byte limit (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "dynamodb row requires a non-empty topic".to_string(),
            ));
        }
        let millis = now_millis();
        let body = build_item_body(&self.config, topic.as_str(), payload, qos, millis)?;
        let bytes = body.len();
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(DynamoRow { body });
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for DynamoDbSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "dynamodb"
    }
}

/// Management connector handle pairing an id with a DynamoDB sink.
pub struct DynamoDbConnector {
    id: String,
    sink: Arc<DynamoDbSink>,
}

impl DynamoDbConnector {
    pub fn new(id: impl Into<String>, sink: Arc<DynamoDbSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for DynamoDbConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        self.sink.kind()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sink;

    fn test_config() -> DynamoDbSinkConfig {
        DynamoDbSinkConfig {
            table_name: "telemetry_table".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: None,
            partition_key: DynamoKeyConfig {
                name: "device_id".to_string(),
                template: "${client_id}".to_string(),
                key_type: "S".to_string(),
            },
            sort_key: Some(DynamoKeyConfig {
                name: "timestamp".to_string(),
                template: "${timestamp}".to_string(),
                key_type: "N".to_string(),
            }),
            ttl_attribute: Some("expire_at".to_string()),
            ttl_secs: Some(86_400),
            attributes_mapping: HashMap::from([(
                "temperature".to_string(),
                "${payload.temperature}".to_string(),
            )]),
            batch_size: Some(25),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(10),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_000),
            timeout_ms: None,
        }
    }

    fn test_sink(config: DynamoDbSinkConfig) -> (Arc<DynamoDbSink>, Arc<MockDynamoDbTransport>) {
        let transport = Arc::new(MockDynamoDbTransport::new());
        let sink = Arc::new(DynamoDbSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.endpoint_url(),
            "https://dynamodb.us-east-1.amazonaws.com"
        );

        config.table_name.clear();
        assert!(config.validate().is_err());
        config.table_name = "telemetry_table".to_string();

        config.partition_key.key_type = "B".to_string();
        assert!(config.validate().is_err());
        config.partition_key.key_type = "S".to_string();

        config.partition_key.template = "${nope}".to_string();
        assert!(config.validate().is_err());
        config.partition_key.template = "${client_id}".to_string();

        config
            .attributes_mapping
            .insert("".to_string(), "x".to_string());
        assert!(config.validate().is_err());
        config.attributes_mapping.remove("");

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_item_typing_and_keys() {
        let config = test_config();
        let body = build_item_body(
            &config,
            "factory/line1/temp",
            br#"{"client_id":"sensor-01","temperature":84.2,"ok":true,"meta":{"line":1},"tags":["a","b"],"nothing":null}"#,
            QoS::AtLeastOnce,
            1_789_211_889_123,
        )
        .unwrap();
        let item: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(item["device_id"], serde_json::json!({"S": "sensor-01"}));
        assert_eq!(item["timestamp"], serde_json::json!({"N": "1789211889123"}));
        assert_eq!(item["temperature"], serde_json::json!({"N": "84.2"}));
        // TTL computes as now_secs + ttl_secs.
        assert_eq!(item["expire_at"], serde_json::json!({"N": "1789298289"}));
        // ${payload} is not configured: only mapped attributes land.
        assert!(item.get("ok").is_none());

        // Numeric sort keys reject non-numeric renders.
        let mut numeric = test_config();
        numeric.sort_key = Some(DynamoKeyConfig {
            name: "timestamp".to_string(),
            template: "${client_id}".to_string(),
            key_type: "N".to_string(),
        });
        assert!(
            build_item_body(&numeric, "t", br#"{"client_id":"abc"}"#, QoS::AtMostOnce, 0).is_err()
        );
    }

    #[test]
    fn test_payload_unpack_and_ttl() {
        let mut config = test_config();
        config.ttl_attribute = None;
        config.ttl_secs = None;
        config.sort_key = None;
        config.attributes_mapping = HashMap::from([("doc".to_string(), "${payload}".to_string())]);
        let body = build_item_body(
            &config,
            "t",
            br#"{"client_id":"d","temperature":84.2,"ok":true,"meta":{"line":1},"tags":["a"],"nothing":null}"#,
            QoS::AtMostOnce,
            0,
        )
        .unwrap();
        let item: serde_json::Value = serde_json::from_str(&body).unwrap();
        // Whole-document unpack with S/N/BOOL/M/L/NULL typing.
        assert_eq!(item["client_id"], serde_json::json!({"S": "d"}));
        assert_eq!(item["temperature"], serde_json::json!({"N": "84.2"}));
        assert_eq!(item["ok"], serde_json::json!({"BOOL": true}));
        assert_eq!(item["meta"], serde_json::json!({"M": {"line": {"N": "1"}}}));
        assert_eq!(item["tags"], serde_json::json!({"L": [{"S": "a"}]}));
        assert_eq!(item["nothing"], serde_json::json!({"NULL": true}));
        assert!(item.get("expire_at").is_none());

        // Non-object payloads cannot unpack.
        assert!(build_item_body(&config, "t", b"42", QoS::AtMostOnce, 0).is_err());
    }

    #[test]
    fn test_explicit_mapping_wins_over_unpack() {
        // ${payload} unpacks everything, but an explicit mapping for
        // the same key wins with its rendered (re-typed) value.
        let mut config = test_config();
        config.sort_key = None;
        config.ttl_attribute = None;
        config.ttl_secs = None;
        config.attributes_mapping = HashMap::from([
            ("doc".to_string(), "${payload}".to_string()),
            ("temperature".to_string(), "fixed".to_string()),
        ]);
        let body = build_item_body(
            &config,
            "t",
            br#"{"client_id":"d","temperature":84.2}"#,
            QoS::AtMostOnce,
            0,
        )
        .unwrap();
        let item: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(item["temperature"], serde_json::json!({"S": "fixed"}));
        assert_eq!(item["client_id"], serde_json::json!({"S": "d"}));
    }

    #[test]
    fn test_request_framing_and_unprocessed() {
        let bodies = vec!["{\"a\":1}".to_string(), "{\"b\":2}".to_string()];
        let body = render_batch_body("telemetry_table", &bodies);
        assert_eq!(
            String::from_utf8(body).unwrap(),
            r#"{"RequestItems":{"telemetry_table":[{"PutRequest":{"Item":{"a":1}}},{"PutRequest":{"Item":{"b":2}}}]}}"#
        );
        assert_eq!(
            parse_unprocessed(
                "telemetry_table",
                br#"{"UnprocessedItems":{"telemetry_table":[{"PutRequest":{"Item":{"b":2}}}]}}"#
            )
            .unwrap(),
            vec!["{\"b\":2}".to_string()]
        );
        assert!(
            parse_unprocessed("telemetry_table", br#"{"UnprocessedItems":{}}"#)
                .unwrap()
                .is_empty()
        );
        assert!(
            parse_unprocessed("other", br#"{"UnprocessedItems":{"telemetry_table":[]}}"#)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_sigv4_known_answer() {
        // Independent Python (hmac/hashlib) vector.
        let body = br#"{"RequestItems":{"telemetry_table":[{"PutRequest":{"Item":{"device_id":{"S":"sensor-01"},"timestamp":{"N":"1726160000000"}}}}]}}"#;
        let (auth, date) = sign_batch_write(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
            "us-east-1",
            "dynamodb.us-east-1.amazonaws.com",
            body,
            1_789_211_889_000,
        );
        assert_eq!(date, "20260912T111809Z");
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260912/us-east-1/dynamodb/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date;x-amz-target, \
             Signature=72eec649e8834f2cf1855befcabc40e4782e6a7b96e768427f1e9224546de3d3"
        );
    }

    #[tokio::test]
    async fn test_unprocessed_requeues_selectively() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        // First pass leaves row 1 unprocessed; the retry carries it alone.
        transport.script_outcomes(vec![
            MockDynamoDbOutcome::Unprocessed(vec![1]),
            MockDynamoDbOutcome::Accepted,
        ]);

        let topic = Topic::new("t").unwrap();
        for temp in [20.5, 21.5] {
            sink.send(
                &topic,
                &Bytes::from(format!("{{\"client_id\":\"d\",\"temperature\":{temp}}}")),
                QoS::AtMostOnce,
            )
            .await
            .unwrap();
        }
        sink.flush().await.unwrap();

        assert_eq!(transport.calls(), 2);
        let captured = transport.captured();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].table, "telemetry_table");
        assert_eq!(captured[0].items.len(), 2);
        assert_eq!(captured[1].items.len(), 1);
        assert!(captured[1].items[0].body.contains("\"21.5\""));
        assert_eq!(sink.sent_records(), 2);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_throttle_and_terminal_paths() {
        // Throttle exhaustion restores everything, then fails fast.
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(0);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![MockDynamoDbOutcome::Throttled]);
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{\"client_id\":\"d\"}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("throttle must exhaust");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), 1);

        // Terminal failure: no retry, buffer retained.
        let (sink, transport) = test_sink(test_config());
        transport.script_outcomes(vec![MockDynamoDbOutcome::Terminal(
            "ValidationException".to_string(),
        )]);
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{\"client_id\":\"d\"}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("terminal must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[test]
    fn test_sdk_item_conversion_keeps_types() {
        use aws_sdk_dynamodb::types::AttributeValue;
        // Keys + TTL + mapped scalar from the standard fixture.
        let body = build_item_body(
            &test_config(),
            "t",
            br#"{"client_id":"d","temperature":84.2}"#,
            QoS::AtMostOnce,
            0,
        )
        .unwrap();
        let map = item_body_to_attribute_map(&body).unwrap();
        assert_eq!(map["device_id"], AttributeValue::S("d".to_string()));
        assert_eq!(map["timestamp"], AttributeValue::N("0".to_string()));
        assert_eq!(map["expire_at"], AttributeValue::N("86400".to_string()));
        assert_eq!(map["temperature"], AttributeValue::N("84.2".to_string()));

        // Whole-document unpack preserves S/N/BOOL/M/L/NULL typing.
        let mut config = test_config();
        config.sort_key = None;
        config.ttl_attribute = None;
        config.ttl_secs = None;
        config.attributes_mapping = HashMap::from([("doc".to_string(), "${payload}".to_string())]);
        let body = build_item_body(
            &config,
            "t",
            br#"{"client_id":"d","temperature":84.2,"ok":true,"meta":{"line":1},"tags":["a"],"nothing":null}"#,
            QoS::AtMostOnce,
            0,
        )
        .unwrap();
        let map = item_body_to_attribute_map(&body).unwrap();
        assert_eq!(map["client_id"], AttributeValue::S("d".to_string()));
        assert_eq!(map["temperature"], AttributeValue::N("84.2".to_string()));
        assert_eq!(map["ok"], AttributeValue::Bool(true));
        assert_eq!(map["nothing"], AttributeValue::Null(true));
        assert_eq!(
            map["meta"],
            AttributeValue::M(HashMap::from([(
                "line".to_string(),
                AttributeValue::N("1".to_string())
            )]))
        );
        assert_eq!(
            map["tags"],
            AttributeValue::L(vec![AttributeValue::S("a".to_string())])
        );

        // Shapes the sink never emits are rejected, never guessed.
        assert!(attribute_value_from_dynamodb_json(&serde_json::json!({"SS": ["a"]})).is_err());
        assert!(attribute_value_from_dynamodb_json(&serde_json::json!({"B": "aGk="})).is_err());
        assert!(attribute_value_from_dynamodb_json(&serde_json::json!("plain")).is_err());
        assert!(item_body_to_attribute_map("not json").is_err());
    }

    #[test]
    fn test_sdk_error_classification() {
        // Provisioned-throughput and throttling take the retry path.
        for retryable in [
            "ProvisionedThroughputExceededException: exceeded throughput",
            "ThrottlingException: rate exceeded",
            "RequestLimitExceeded",
            "ReplicatedWriteConflictException",
            "InternalServerError",
            "dynamodb driver timed out after 5000ms",
            "dispatch failure: connection reset",
            "ServiceUnavailable",
        ] {
            assert!(
                is_retryable_dynamodb_error(retryable),
                "must retry: {retryable}"
            );
            assert!(
                matches!(
                    classify_dynamodb_sdk_error(retryable.to_string()),
                    ConnectorError::Connection(_)
                ),
                "must be a connection error: {retryable}"
            );
        }
        // Validation, missing resources and auth are terminal.
        for terminal in [
            "ValidationException: unsupported document",
            "ResourceNotFoundException: table missing",
            "AccessDeniedException: not authorized",
        ] {
            assert!(
                !is_retryable_dynamodb_error(terminal),
                "must not retry: {terminal}"
            );
            assert!(
                matches!(
                    classify_dynamodb_sdk_error(terminal.to_string()),
                    ConnectorError::Dispatch(_)
                ),
                "must be a dispatch error: {terminal}"
            );
        }
    }

    #[test]
    fn test_sdk_unprocessed_index_mapping() {
        use aws_sdk_dynamodb::types::{AttributeValue, PutRequest, WriteRequest};
        let write = |id: &str| {
            let put = PutRequest::builder()
                .set_item(Some(HashMap::from([(
                    "id".to_string(),
                    AttributeValue::S(id.to_string()),
                )])))
                .build()
                .expect("put builds");
            WriteRequest::builder().put_request(put).build()
        };
        let pending: Vec<HashMap<String, AttributeValue>> = vec![
            HashMap::from([("id".to_string(), AttributeValue::S("a".to_string()))]),
            HashMap::from([("id".to_string(), AttributeValue::S("b".to_string()))]),
        ];
        // Unprocessed carries the second row alone: selective retry.
        let unprocessed = HashMap::from([("telemetry_table".to_string(), vec![write("b")])]);
        assert_eq!(
            map_unprocessed_indices(&pending, Some(&unprocessed), "telemetry_table").unwrap(),
            vec![1]
        );
        // Absent, empty or other-table means everything was written.
        assert!(map_unprocessed_indices(&pending, None, "telemetry_table")
            .unwrap()
            .is_empty());
        assert!(
            map_unprocessed_indices(&pending, Some(&HashMap::new()), "telemetry_table")
                .unwrap()
                .is_empty()
        );
        assert!(map_unprocessed_indices(
            &pending,
            Some(&HashMap::from([("other".to_string(), vec![write("a")])])),
            "telemetry_table"
        )
        .unwrap()
        .is_empty());
        // An unprocessed item that was never sent fails closed: the
        // caller retries the whole batch instead of dropping it.
        let ghost = HashMap::from([("telemetry_table".to_string(), vec![write("ghost")])]);
        assert!(map_unprocessed_indices(&pending, Some(&ghost), "telemetry_table").is_err());
    }

    #[test]
    fn test_sdk_transport_construction() {
        let config = test_config();
        // Building the driver client is lazy: no I/O, safe offline.
        let transport = SdkDynamoDbTransport::new(&config).expect("sdk transport builds");
        assert_eq!(transport.timeout(), config.timeout());
        let mut bad = test_config();
        bad.table_name.clear();
        assert!(SdkDynamoDbTransport::new(&bad).is_err());
    }

    #[tokio::test]
    async fn test_sdk_unreachable_fails_closed_through_manager() {
        // Unreachable server through the broker path: connection
        // failure, never access granted.
        use crate::ConnectorManager;
        let mut config = test_config();
        config.endpoint = Some("http://127.0.0.1:1".to_string());
        config.batch_size = Some(1);
        config.timeout_ms = Some(500);
        let transport = Arc::new(SdkDynamoDbTransport::new(&config).expect("sdk transport"));
        let sink = Arc::new(DynamoDbSink::new(config, transport).expect("sink"));
        assert_eq!(sink.kind(), "dynamodb");
        let manager = ConnectorManager::new();
        manager.register("ddb-dead", sink.clone());
        let err = manager
            .send(
                "ddb-dead",
                &Topic::new("sensors/qual").unwrap(),
                &Bytes::from_static(br#"{"client_id":"d"}"#),
                QoS::AtLeastOnce,
            )
            .await
            .expect_err("unreachable must fail");
        assert!(
            matches!(err, ConnectorError::Connection(_)),
            "unreachable must be a connection failure, got {err:?}"
        );
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    /// Qualification against a real DynamoDB server via the maintained
    /// `aws-sdk-dynamodb` driver.
    ///
    /// Run with e.g.:
    /// `DYNAMODB_ENDPOINT=http://127.0.0.1:8000 DYNAMODB_TABLE=qual_b316 \
    ///  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
    ///  cargo test -p broker-connectors --lib dynamodb::tests::test_qualify_driver_write_path -- --ignored --nocapture`
    ///
    /// Creates the table, streams 1000 items through the broker
    /// ([`crate::ConnectorManager`] -> [`DynamoDbSink`] on
    /// [`SdkDynamoDbTransport`]), asserts `Scan` count returns 1000,
    /// proves the mock unprocessed-item path still requeues only
    /// failed rows and the throttle path backs off, then deletes the
    /// table it created.
    #[tokio::test]
    #[ignore = "needs a real DynamoDB server (see DYNAMODB_* env)"]
    async fn test_qualify_driver_write_path() {
        use crate::ConnectorManager;
        use aws_sdk_dynamodb::types::{
            AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
            Select,
        };
        let endpoint = qual_env("DYNAMODB_ENDPOINT").unwrap_or_else(|| {
            panic!(
                "DYNAMODB_ENDPOINT must point at a real DynamoDB server for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. DYNAMODB_ENDPOINT=http://127.0.0.1:8000)"
            )
        });
        let table = qual_env("DYNAMODB_TABLE").unwrap_or_else(|| "qual_b316".to_string());
        let region = qual_env("DYNAMODB_REGION")
            .or_else(|| qual_env("AWS_REGION"))
            .unwrap_or_else(|| "us-east-1".to_string());
        // Static credentials default to the local-server test pair;
        // real deployments export the usual AWS variables instead.
        // TODO(parity): DynamoDB exposes no server-version API, so the
        // report carries the endpoint plus DescribeTable output instead
        // of a version string; is that an acceptable "server version"?
        let access_key = qual_env("DYNAMODB_ACCESS_KEY_ID")
            .or_else(|| qual_env("AWS_ACCESS_KEY_ID"))
            .unwrap_or_else(|| "test".to_string());
        let secret_key = qual_env("DYNAMODB_SECRET_ACCESS_KEY")
            .or_else(|| qual_env("AWS_SECRET_ACCESS_KEY"))
            .unwrap_or_else(|| "test".to_string());

        let mut config = test_config();
        config.table_name = table.clone();
        config.region = region.clone();
        config.endpoint = Some(endpoint.clone());
        config.access_key_id = access_key;
        config.secret_access_key = secret_key;
        config.partition_key = DynamoKeyConfig {
            name: "device_id".to_string(),
            template: "${client_id}".to_string(),
            key_type: "S".to_string(),
        };
        config.sort_key = Some(DynamoKeyConfig {
            name: "seq".to_string(),
            // `${timestamp}` (not `${payload.seq}`): validation renders
            // templates against a dummy payload, so a payload-field
            // sort key would fail the numeric check before any write.
            template: "${timestamp}".to_string(),
            key_type: "N".to_string(),
        });
        config.ttl_attribute = None;
        config.ttl_secs = None;
        config.attributes_mapping = HashMap::from([(
            "temperature".to_string(),
            "${payload.temperature}".to_string(),
        )]);
        config.batch_size = Some(25);
        config.batch_bytes = Some(1_048_576);
        config.linger_ms = Some(10);
        config.max_retries = Some(4);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        config.timeout_ms = Some(15_000);
        config.validate().expect("qual config validates");

        let transport = Arc::new(SdkDynamoDbTransport::new(&config).expect("qual transport"));
        let client = transport.client().clone();

        // Fresh table (delete stale, create, wait until describable).
        let _ = client.delete_table().table_name(&table).send().await;
        client
            .create_table()
            .table_name(&table)
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("device_id")
                    .key_type(KeyType::Hash)
                    .build()
                    .expect("qual key schema"),
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("seq")
                    .key_type(KeyType::Range)
                    .build()
                    .expect("qual sort schema"),
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("device_id")
                    .attribute_type(ScalarAttributeType::S)
                    .build()
                    .expect("qual attr def"),
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("seq")
                    .attribute_type(ScalarAttributeType::N)
                    .build()
                    .expect("qual sort def"),
            )
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await
            .expect("qual create table");
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if client
                    .describe_table()
                    .table_name(&table)
                    .send()
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .expect("qual table never became describable");
        let described = client
            .describe_table()
            .table_name(&table)
            .send()
            .await
            .expect("qual describe");
        eprintln!("qual server: endpoint={endpoint} table={table} describe={described:?}");

        let sink = Arc::new(DynamoDbSink::new(config, transport).expect("qual sink"));
        assert_eq!(sink.kind(), "dynamodb");
        // The broker's path: rule actions deliver through the shared
        // connector manager, so the qualification sends through it.
        let manager = ConnectorManager::new();
        manager.register("qual-ddb", sink.clone());

        let topic = Topic::new("sensors/qual").unwrap();
        for seq in 0..1000u32 {
            let payload = Bytes::from(format!(
                r#"{{"client_id":"dev-{seq:04}","seq":{seq},"temperature":{:.2}}}"#,
                20.0 + f64::from(seq) * 0.01
            ));
            manager
                .send("qual-ddb", &topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual send");
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), 1000);
        eprintln!("qual rows sent: records=1000 table={table}");

        // Row count asserted back from the server, not the counters.
        let mut counted = 0i32;
        let mut start_key: Option<HashMap<String, aws_sdk_dynamodb::types::AttributeValue>> = None;
        loop {
            let page = client
                .scan()
                .table_name(&table)
                .select(Select::Count)
                .set_exclusive_start_key(start_key)
                .send()
                .await
                .expect("qual scan");
            counted += page.count();
            match page.last_evaluated_key() {
                Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                _ => break,
            }
        }
        assert_eq!(counted, 1000);
        eprintln!("qual rows asserted: count=1000 table={table}");

        // Unprocessed items still requeue selectively (mock path).
        let mut mock_config = test_config();
        mock_config.batch_size = Some(10);
        mock_config.initial_backoff_ms = Some(1);
        mock_config.max_backoff_ms = Some(2);
        let (mock_sink, mock_transport) = test_sink(mock_config);
        mock_transport.script_outcomes(vec![
            MockDynamoDbOutcome::Unprocessed(vec![1]),
            MockDynamoDbOutcome::Accepted,
        ]);
        let mock_topic = Topic::new("t").unwrap();
        for temp in [20.5, 21.5] {
            mock_sink
                .send(
                    &mock_topic,
                    &Bytes::from(format!("{{\"client_id\":\"d\",\"temperature\":{temp}}}")),
                    QoS::AtMostOnce,
                )
                .await
                .unwrap();
        }
        mock_sink.flush().await.unwrap();
        assert_eq!(mock_transport.calls(), 2);
        assert_eq!(mock_transport.captured()[1].items.len(), 1);

        // Provisioned-throughput backoff: throttle exhausts retries,
        // retains the buffer, then fails fast while backing off.
        let mut throttle_config = test_config();
        throttle_config.batch_size = Some(10);
        throttle_config.max_retries = Some(0);
        let (throttle_sink, throttle_transport) = test_sink(throttle_config);
        throttle_transport.script_outcomes(vec![MockDynamoDbOutcome::Throttled]);
        throttle_sink
            .send(
                &mock_topic,
                &Bytes::from("{\"client_id\":\"d\"}"),
                QoS::AtMostOnce,
            )
            .await
            .unwrap();
        let err = throttle_sink
            .flush()
            .await
            .expect_err("throttle must exhaust");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(throttle_sink.buffered_rows(), 1);

        // Cleanup the table we created.
        client
            .delete_table()
            .table_name(&table)
            .send()
            .await
            .expect("qual cleanup table");
    }
}
