//! Amazon Redshift sink (INDRA-187).
//!
//! Buffers MQTT events as SQL statements and executes them with the
//! Redshift Data API (`RedshiftData.BatchExecuteStatement` over HTTP
//! POST, `application/x-amz-json-1.1`), signed with AWS Signature
//! Version 4 for service `redshift-data` via the shared signer in
//! `super`. One of `WorkgroupName` (Serverless) or
//! `ClusterIdentifier` (provisioned) targets every call.
//!
//! Statements render from a 5-column convention (time, topic,
//! client id, QoS, payload JSON) with `$1..$5` substitution and SQL
//! string escaping — the batch API carries no parameter channel, so
//! escaping is the injection boundary and is unit-tested. Throttles
//! (429) and transport failures retry with backoff; query failures
//! are terminal dispatch errors.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use broker_connectors::{
    now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink,
};

pub const REDSHIFT_TARGET: &str = "RedshiftData.BatchExecuteStatement";
pub const REDSHIFT_CONTENT_TYPE: &str = "application/x-amz-json-1.1";

fn default_batch_size() -> Option<usize> {
    Some(100)
}

fn default_batch_bytes() -> Option<usize> {
    Some(1_048_576)
}

fn default_linger_ms() -> Option<u64> {
    Some(20)
}

fn default_max_retries() -> Option<usize> {
    Some(4)
}

fn default_initial_backoff_ms() -> Option<u64> {
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    Some(2_500)
}

/// Redshift sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedshiftSinkConfig {
    /// Redshift database name.
    pub database: String,
    /// Table template (`${topic}`, `${client_id}`, ...).
    pub table_template: String,
    /// Provisioned cluster identifier (exactly one of cluster /
    /// workgroup must be set).
    #[serde(default)]
    pub cluster_identifier: Option<String>,
    /// Serverless workgroup name (exactly one of cluster /
    /// workgroup must be set).
    #[serde(default)]
    pub workgroup_name: Option<String>,
    /// AWS region, e.g. `us-east-1`.
    pub region: String,
    /// Custom endpoint; defaults to
    /// `https://redshift-data.{region}.amazonaws.com`.
    #[serde(default)]
    pub endpoint: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// STS session token for temporary credentials.
    #[serde(default)]
    pub session_token: Option<String>,
    /// Database username (sent as `DbUser` when set).
    #[serde(default)]
    pub db_user: Option<String>,
    /// Custom SQL with `$1..$5` markers (time, topic, client id,
    /// QoS, payload JSON). Defaults to a 5-column INSERT.
    #[serde(default)]
    pub sql_template: Option<String>,
    /// Statements per `BatchExecuteStatement` (default 100).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 1 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 20).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on 429/transport (default 4, `None` unbounded, 0 none).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 2500).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl RedshiftSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.database.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "redshift database must not be empty".to_string(),
            ));
        }
        if self.table_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "redshift table_template must not be empty".to_string(),
            ));
        }
        match (&self.cluster_identifier, &self.workgroup_name) {
            (Some(_), Some(_)) => {
                return Err(ConnectorError::Dispatch(
                    "redshift sets exactly one of cluster_identifier / workgroup_name".to_string(),
                ))
            }
            (None, None) => {
                return Err(ConnectorError::Dispatch(
                    "redshift needs cluster_identifier or workgroup_name".to_string(),
                ))
            }
            _ => {}
        }
        if self.region.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "redshift region must not be empty".to_string(),
            ));
        }
        if let Some(endpoint) = &self.endpoint {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(ConnectorError::Dispatch(format!(
                    "redshift endpoint must be http(s): {endpoint:?}"
                )));
            }
        }
        if self.access_key_id.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "redshift access_key_id must not be empty".to_string(),
            ));
        }
        if self.secret_access_key.is_empty() {
            return Err(ConnectorError::Dispatch(
                "redshift secret_access_key must not be empty".to_string(),
            ));
        }
        // Strict template checks with dummy values.
        self.resolve_table("dummy/topic", b"{}", QoS::AtMostOnce, 0)?;
        if let Some(template) = &self.sql_template {
            let mut referenced = broker_connectors::postgres::referenced_params(template)?;
            referenced.sort_unstable();
            referenced.dedup();
            if referenced.is_empty() || referenced.iter().any(|n| *n == 0 || *n > 5) {
                return Err(ConnectorError::Dispatch(format!(
                    "redshift sql_template must reference $1..$5, got {referenced:?}"
                )));
            }
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "redshift batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "redshift batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn endpoint_url(&self) -> String {
        match &self.endpoint {
            Some(endpoint) => endpoint.trim_end_matches('/').to_string(),
            None => format!("https://redshift-data.{}.amazonaws.com", self.region),
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

    /// Resolve + sanitize the table: template first, then anything
    /// outside `[A-Za-z0-9_.]` becomes `_`.
    pub fn resolve_table(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
    ) -> Result<String> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| match doc.get(name) {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        let vars = [
            ("topic", topic.to_string()),
            ("client_id", field("client_id")),
            ("qos", u8::from(qos).to_string()),
            ("timestamp", millis.to_string()),
        ];
        let borrowed: Vec<(&str, String)> = vars.iter().map(|(k, v)| (*k, v.clone())).collect();
        let rendered = render_template(&self.table_template, &borrowed)?;
        let sanitized: String = rendered
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if sanitized.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "redshift table resolved empty".to_string(),
            ));
        }
        Ok(sanitized)
    }
}

/// SQL-escape one text literal (single quotes double up).
fn sql_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// Render one statement: `$1..$5` become escaped literals for
/// (time_ms, topic, client_id, qos, payload_json).
pub fn render_statement(
    template: &str,
    table: &str,
    time_ms: i64,
    topic: &str,
    client_id: &str,
    qos: u8,
    payload_json: &str,
) -> String {
    // TABLE is a separate substitution (identifiers never quote).
    let mut sql = template.replace("$table", table);
    let values = [
        time_ms.to_string(),
        sql_quote(topic),
        sql_quote(client_id),
        qos.to_string(),
        sql_quote(payload_json),
    ];
    // NOTE: $5 must substitute before $1-style prefixes collide;
    // none of the markers is a prefix of another ($1..$5), so a
    // single ordered pass is exact.
    for (index, value) in values.iter().enumerate() {
        sql = sql.replace(&format!("${}", index + 1), value);
    }
    sql
}

/// Default 5-column INSERT for a table.
pub fn default_insert(table: &str) -> String {
    format!(
        "INSERT INTO {table} (time_ms, topic, client_id, qos, payload) VALUES ($1, $2, $3, $4, $5)"
    )
}

/// Sign a `BatchExecuteStatement` POST with SigV4 (service
/// `redshift-data`), returning `Authorization` + `x-amz-date`.
pub fn sign_batch_execute(
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    region: &str,
    host: &str,
    body: &[u8],
    millis: i64,
) -> (String, String) {
    let payload_hash = broker_connectors::sha256_hex(body);
    let date = broker_connectors::amz_date(millis);
    let mut headers = vec![
        (
            "content-type".to_string(),
            REDSHIFT_CONTENT_TYPE.to_string(),
        ),
        ("host".to_string(), host.to_string()),
        ("x-amz-date".to_string(), date.clone()),
        ("x-amz-target".to_string(), REDSHIFT_TARGET.to_string()),
    ];
    if let Some(token) = session_token {
        headers.push(("x-amz-security-token".to_string(), token.to_string()));
    }
    let auth = broker_connectors::sigv4_authorization(&broker_connectors::SigV4Signing {
        method: "POST",
        canonical_uri: "/".to_string(),
        canonical_query: String::new(),
        headers,
        payload_hash,
        access_key_id,
        secret_access_key,
        region,
        service: "redshift-data",
        millis,
    });
    (auth, date)
}

// ---------------------------------------------------------------------------
// Wire framing.
// ---------------------------------------------------------------------------

/// One `BatchExecuteStatement` call.
#[derive(Debug, Clone)]
pub struct RedshiftBatchRequest {
    pub database: String,
    pub cluster_identifier: Option<String>,
    pub workgroup_name: Option<String>,
    pub db_user: Option<String>,
    pub statements: Vec<String>,
}

/// Parsed batch outcome (statement id when accepted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedshiftBatchResponse {
    pub id: String,
}

/// Render the `BatchExecuteStatement` JSON body.
pub fn render_batch_body(req: &RedshiftBatchRequest) -> Vec<u8> {
    let mut body = String::from("{\"Database\":");
    body.push_str(&serde_json::to_string(&req.database).unwrap_or_default());
    if let Some(cluster) = &req.cluster_identifier {
        body.push_str(",\"ClusterIdentifier\":");
        body.push_str(&serde_json::to_string(cluster).unwrap_or_default());
    }
    if let Some(workgroup) = &req.workgroup_name {
        body.push_str(",\"WorkgroupName\":");
        body.push_str(&serde_json::to_string(workgroup).unwrap_or_default());
    }
    if let Some(user) = &req.db_user {
        body.push_str(",\"DbUser\":");
        body.push_str(&serde_json::to_string(user).unwrap_or_default());
    }
    body.push_str(",\"Sqls\":[");
    for (index, statement) in req.statements.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str(&serde_json::to_string(statement).unwrap_or_default());
    }
    body.push_str("]}");
    body.into_bytes()
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockRedshiftOutcome {
    Accepted {
        id: String,
    },
    /// Query/terminal failure (no retry).
    Failed {
        message: String,
    },
    /// 429 concurrency limit (retries the batch).
    Throttled,
    /// Transport failure (retries in-loop).
    ConnectionError(String),
}

#[async_trait]
pub trait RedshiftTransport: Send + Sync {
    async fn execute_batch(&self, req: &RedshiftBatchRequest) -> Result<RedshiftBatchResponse>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockRedshiftTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockRedshiftOutcome>>,
    captured: parking_lot::Mutex<Vec<RedshiftBatchRequest>>,
    calls: AtomicU64,
}

impl MockRedshiftTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: accepted).
    pub fn script_outcomes(&self, outcomes: Vec<MockRedshiftOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<RedshiftBatchRequest> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl RedshiftTransport for MockRedshiftTransport {
    async fn execute_batch(&self, req: &RedshiftBatchRequest) -> Result<RedshiftBatchResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(RedshiftBatchRequest {
            database: req.database.clone(),
            cluster_identifier: req.cluster_identifier.clone(),
            workgroup_name: req.workgroup_name.clone(),
            db_user: req.db_user.clone(),
            statements: req.statements.clone(),
        });
        match self.scripted.lock().pop_front() {
            None => Ok(RedshiftBatchResponse {
                id: "stmt-1".to_string(),
            }),
            Some(MockRedshiftOutcome::Accepted { id }) => Ok(RedshiftBatchResponse { id }),
            Some(MockRedshiftOutcome::Failed { message }) => Err(ConnectorError::Dispatch(message)),
            Some(MockRedshiftOutcome::Throttled) => Err(ConnectorError::Connection(
                "mock redshift throttled".to_string(),
            )),
            Some(MockRedshiftOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
        }
    }
}

/// Production transport: signed `POST {endpoint}/` with the JSON body.
pub struct HttpRedshiftTransport {
    endpoint: String,
    host: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    client: reqwest::Client,
}

impl HttpRedshiftTransport {
    pub fn new(config: &RedshiftSinkConfig, client: reqwest::Client) -> Result<Self> {
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
impl RedshiftTransport for HttpRedshiftTransport {
    async fn execute_batch(&self, req: &RedshiftBatchRequest) -> Result<RedshiftBatchResponse> {
        let body = render_batch_body(req);
        let millis = now_millis();
        let (auth, date) = sign_batch_execute(
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
            .header(reqwest::header::CONTENT_TYPE, REDSHIFT_CONTENT_TYPE)
            .header("X-Amz-Target", REDSHIFT_TARGET)
            .header("X-Amz-Date", date)
            .header(reqwest::header::AUTHORIZATION, auth)
            .body(body);
        if let Some(token) = &self.session_token {
            request = request.header("X-Amz-Security-Token", token.as_str());
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("redshift write failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 429 || (500..=504).contains(&status) {
            return Err(ConnectorError::Connection(format!(
                "redshift throttled with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(ConnectorError::Dispatch(format!(
                "redshift write failed with {status}"
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("redshift read failed: {e}")))?;
        let doc: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| ConnectorError::Connection(format!("redshift bad response JSON: {e}")))?;
        let id = doc
            .get("Id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ConnectorError::Dispatch("redshift response lacks Id".to_string()))?;
        Ok(RedshiftBatchResponse { id: id.to_string() })
    }
}

/// Retryable-vs-terminal mapping for the Redshift Data driver.
/// Throttles, quota/active-limit rejections, internal failures and
/// transport/timeout text retry as connections; auth, validation and
/// query failures are terminal dispatches (fail closed, never retried
/// with the same statement).
fn is_retryable_redshift_error(text: &str) -> bool {
    const RETRYABLE: &[&str] = &[
        "throttl",
        "too many",
        "toomany",
        "active statements exceeded",
        "active sessions exceeded",
        "active waiting requests exceeded",
        // CamelCase SDK exception names carry no spaces
        // (e.g. ActiveStatementsExceededException), so match the
        // space-stripped forms too. Reason: Redshift Data quota /
        // concurrency rejections are throttle-like and safe to retry.
        "activestatements",
        "activesessions",
        "activewaiting",
        "internalservererror",
        // Bare InternalServerException (no "Error" suffix) is the same
        // transient server failure. Reason: vendor transient fault.
        "internalserver",
        "internalfailure",
        "serviceunavailable",
        "timeout",
        "timed out",
        "connection",
        "unavailable",
    ];
    let lower = text.to_lowercase();
    RETRYABLE.iter().any(|marker| lower.contains(marker))
}

fn classify_redshift_sdk_error(text: String) -> ConnectorError {
    if is_retryable_redshift_error(&text) {
        ConnectorError::Connection(text)
    } else {
        ConnectorError::Dispatch(text)
    }
}

/// Polls per batch execution (default 180): 180 x 1 s is a 3 min upper
/// bound per batch so one slow Serverless workgroup cannot stall a
/// flush forever; past the bound the sink retry loop re-executes the
/// batch (at-least-once, like the sibling batch sinks). Reason:
/// Serverless cold starts plus 100-statement batches run for tens of
/// seconds while compute is billed, so the bound covers a cold batch
/// without letting a stuck statement hold the rule path.
const DEFAULT_MAX_POLLS: usize = 180;
/// Delay between status polls (default 1000 ms): batches run for
/// seconds and the Data API bills per call, so faster polling only
/// burns quota. Reason: vendor per-call billing plus second-scale
/// batch latency.
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;

/// Maximum `Sqls` per `BatchExecuteStatement` call (40): the vendor
/// rejects larger arrays with `ValidationException`, so bigger sink
/// batches are split into sequential calls. Reason: vendor API limit
/// (`BatchExecuteStatement` `Sqls` min 1 / max 40, statements run
/// serially as one transaction per call).
pub const REDSHIFT_MAX_SQLS_PER_BATCH: usize = 40;

/// Production transport on the maintained `aws-sdk-redshiftdata`
/// driver: `BatchExecuteStatement` with driver-owned SigV4 (static
/// access-key credentials, session token when configured, endpoint
/// override for local servers) plus `DescribeStatement` polling to
/// FINISHED. One driver round trip is bounded by the configured
/// request timeout so a slow workgroup surfaces as a retryable
/// connection error instead of stalling the rule path. `FAILED` /
/// `ABORTED` outcomes are terminal dispatches that carry the failed
/// statement text, so a syntax error names the statement that broke.
pub struct SdkRedshiftTransport {
    client: aws_sdk_redshiftdata::Client,
    timeout: Duration,
    poll_interval: Duration,
    max_polls: usize,
}

impl SdkRedshiftTransport {
    pub fn new(config: &RedshiftSinkConfig) -> Result<Self> {
        Self::with_polling(
            config,
            Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
            DEFAULT_MAX_POLLS,
        )
    }

    /// Constructor with explicit polling bounds (qualification and
    /// tests; cold Serverless workgroups take minutes, loopback fakes
    /// take none).
    pub fn with_polling(
        config: &RedshiftSinkConfig,
        poll_interval: Duration,
        max_polls: usize,
    ) -> Result<Self> {
        config.validate()?;
        let region = aws_sdk_redshiftdata::config::Region::new(config.region.clone());
        let credentials = aws_sdk_redshiftdata::config::Credentials::new(
            config.access_key_id.clone(),
            config.secret_access_key.clone(),
            config.session_token.clone(),
            None,
            "indramqtt-static",
        );
        let provider = aws_sdk_redshiftdata::config::SharedCredentialsProvider::new(credentials);
        let mut builder = aws_sdk_redshiftdata::Config::builder()
            .behavior_version_latest()
            .region(region)
            .credentials_provider(provider);
        if let Some(endpoint) = &config.endpoint {
            builder = builder.endpoint_url(endpoint.trim_end_matches('/'));
        }
        let sdk_config = builder.build();
        Ok(Self {
            client: aws_sdk_redshiftdata::Client::from_conf(sdk_config),
            timeout: config.timeout(),
            poll_interval,
            max_polls: max_polls.max(1),
        })
    }

    /// Borrow the driver client (table setup and read-back for
    /// qualification; the write path stays behind the trait).
    pub fn client(&self) -> &aws_sdk_redshiftdata::Client {
        &self.client
    }

    /// Test hook proving `new` stores the configured timeout; the
    /// production path applies `self.timeout` to every driver call.
    #[cfg(test)]
    fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Poll one batch id to a terminal state. `FINISHED` completes;
    /// `FAILED` / `ABORTED` are terminal dispatches carrying the
    /// failed statement text; exhaustion is retryable so the sink
    /// re-executes the batch at-least-once.
    async fn poll_to_finished(&self, id: &str, statements: &[String]) -> Result<()> {
        for _ in 0..self.max_polls {
            tokio::time::sleep(self.poll_interval).await;
            let timeout = self.timeout;
            let described = tokio::time::timeout(
                timeout,
                self.client
                    .describe_statement()
                    .set_id(Some(id.to_string()))
                    .send(),
            )
            .await
            .map_err(|_| {
                ConnectorError::Connection(format!(
                    "redshift driver timed out after {}ms",
                    timeout.as_millis()
                ))
            })?
            .map_err(|e| {
                classify_redshift_sdk_error(format!(
                    "redshift describe statement failed: {e:?} ({e})"
                ))
            })?;
            let status = described.status().map(|s| s.as_str()).unwrap_or("");
            match status {
                "FINISHED" => return Ok(()),
                "FAILED" | "ABORTED" => {
                    let server_error = described.error().unwrap_or("unknown error");
                    let query = described.query_string().unwrap_or("");
                    let mut detail = format!("redshift statement {id} {status}: {server_error}");
                    if !query.is_empty() {
                        detail.push_str(&format!(" :: {query}"));
                    }
                    let mut saw_sub_failure = false;
                    for sub in described.sub_statements() {
                        let sub_status = sub.status().map(|s| s.as_str()).unwrap_or("");
                        if sub_status == "FAILED" || sub_status == "ABORTED" {
                            saw_sub_failure = true;
                            let sub_error = sub.error().unwrap_or("");
                            let sub_query = sub.query_string().unwrap_or("");
                            detail.push_str(&format!(
                                "; sub-statement {sub_status}: {sub_error} :: {sub_query}"
                            ));
                        }
                    }
                    if query.is_empty() && !saw_sub_failure {
                        if let Some(first) = statements.first() {
                            detail.push_str(&format!(" :: {first}"));
                        }
                    }
                    return Err(ConnectorError::Dispatch(detail));
                }
                _ => {}
            }
        }
        Err(ConnectorError::Connection(format!(
            "redshift statement {id} still pending after {} polls",
            self.max_polls
        )))
    }
}

#[async_trait]
impl RedshiftTransport for SdkRedshiftTransport {
    async fn execute_batch(&self, req: &RedshiftBatchRequest) -> Result<RedshiftBatchResponse> {
        if req.statements.is_empty() {
            return Err(ConnectorError::Dispatch(
                "redshift batch has no statements".to_string(),
            ));
        }
        let mut last_id = String::new();
        // Split oversized batches so no single `BatchExecuteStatement`
        // exceeds the vendor `Sqls` max (40); chunks run serially and
        // each polls to FINISHED, so a 100-row sink batch becomes
        // 40 + 40 + 20 without a validation failure.
        for chunk in req.statements.chunks(REDSHIFT_MAX_SQLS_PER_BATCH) {
            let mut builder = self
                .client
                .batch_execute_statement()
                .set_database(Some(req.database.clone()))
                .set_sqls(Some(chunk.to_vec()));
            if let Some(cluster) = &req.cluster_identifier {
                builder = builder.set_cluster_identifier(Some(cluster.clone()));
            }
            if let Some(workgroup) = &req.workgroup_name {
                builder = builder.set_workgroup_name(Some(workgroup.clone()));
            }
            if let Some(user) = &req.db_user {
                builder = builder.set_db_user(Some(user.clone()));
            }
            let timeout = self.timeout;
            let output = tokio::time::timeout(timeout, builder.send())
                .await
                .map_err(|_| {
                    ConnectorError::Connection(format!(
                        "redshift driver timed out after {}ms",
                        timeout.as_millis()
                    ))
                })?
                .map_err(|e| {
                    classify_redshift_sdk_error(format!(
                        "redshift batch execute failed: {e:?} ({e})"
                    ))
                })?;
            let id = output.id().map(str::to_string).ok_or_else(|| {
                ConnectorError::Dispatch("redshift response lacks Id".to_string())
            })?;
            self.poll_to_finished(&id, chunk).await?;
            last_id = id;
        }
        Ok(RedshiftBatchResponse { id: last_id })
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row: rendered statement + byte size.
#[derive(Debug, Clone)]
struct RedshiftRow {
    statement: String,
}

struct RedshiftBuffer {
    queue: BatchQueue<RedshiftRow>,
    bytes: usize,
}

/// Redshift sink: buffers statements, executes batches.
pub struct RedshiftSink {
    config: RedshiftSinkConfig,
    transport: Arc<dyn RedshiftTransport>,
    buffer: parking_lot::Mutex<RedshiftBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl RedshiftSink {
    pub fn new(config: RedshiftSinkConfig, transport: Arc<dyn RedshiftTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(RedshiftBuffer {
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

    pub fn config(&self) -> &RedshiftSinkConfig {
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
        let max = self.config.max_backoff_ms.unwrap_or(2_500).max(1);
        let grown = initial
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(max);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(max.saturating_mul(2)))
    }

    /// Render one statement for an event (default 5-column INSERT or
    /// the custom template, both through `$1..$5` substitution).
    fn render_row_statement(
        config: &RedshiftSinkConfig,
        table: &str,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
        millis: i64,
    ) -> Result<String> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("redshift payload must be UTF-8".to_string()))?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("redshift payload must be JSON".to_string()))?;
        let client_id = value
            .get("client_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let template = match &config.sql_template {
            Some(template) => template.clone(),
            None => default_insert("$table"),
        };
        let mut statement = template.replace("$table", table);
        statement = render_statement(
            &statement,
            table,
            millis,
            topic.as_str(),
            client_id,
            u8::from(qos),
            text,
        );
        Ok(statement)
    }

    /// Flush buffered rows (no-op when empty). Throttles retry in
    /// place; terminal failures and exhaustion restore the buffer,
    /// engage backoff, and propagate.
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
        let statements: Vec<String> = rows.iter().map(|row| row.statement.clone()).collect();
        let request = RedshiftBatchRequest {
            database: self.config.database.clone(),
            cluster_identifier: self.config.cluster_identifier.clone(),
            workgroup_name: self.config.workgroup_name.clone(),
            db_user: self.config.db_user.clone(),
            statements,
        };
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            match self.transport.execute_batch(&request).await {
                Ok(_) => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
                    self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                    return Ok(());
                }
                Err(ConnectorError::Connection(message)) => {
                    if attempt >= max_retries {
                        return self.restore_err(
                            rows,
                            oldest,
                            taken_bytes,
                            ConnectorError::Connection(message),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                }
                Err(e) => {
                    return self.restore_err(rows, oldest, taken_bytes, e);
                }
            }
        }
    }

    fn restore_err(
        &self,
        rows: Vec<RedshiftRow>,
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
                "redshift row requires a non-empty topic".to_string(),
            ));
        }
        let millis = now_millis();
        let table = self
            .config
            .resolve_table(topic.as_str(), payload, qos, millis)?;
        let statement =
            Self::render_row_statement(&self.config, &table, topic, payload, qos, millis)?;
        let bytes = statement.len();
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(RedshiftRow { statement });
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for RedshiftSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "redshift"
    }
}

/// Management connector handle pairing an id with a Redshift sink.
pub struct RedshiftConnector {
    id: String,
    sink: Arc<RedshiftSink>,
}

impl RedshiftConnector {
    pub fn new(id: impl Into<String>, sink: Arc<RedshiftSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl broker_connectors::Connector for RedshiftConnector {
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
    use broker_connectors::Sink;

    fn test_config() -> RedshiftSinkConfig {
        RedshiftSinkConfig {
            database: "analytics".to_string(),
            table_template: "sensor_logs".to_string(),
            cluster_identifier: None,
            workgroup_name: Some("iot-workgroup".to_string()),
            region: "us-east-1".to_string(),
            endpoint: None,
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: None,
            db_user: None,
            sql_template: None,
            batch_size: Some(100),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_500),
            timeout_ms: None,
        }
    }

    fn test_sink(config: RedshiftSinkConfig) -> (Arc<RedshiftSink>, Arc<MockRedshiftTransport>) {
        let transport = Arc::new(MockRedshiftTransport::new());
        let sink = Arc::new(RedshiftSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.endpoint_url(),
            "https://redshift-data.us-east-1.amazonaws.com"
        );

        config.database.clear();
        assert!(config.validate().is_err());
        config.database = "analytics".to_string();

        // Exactly one of cluster / workgroup.
        config.cluster_identifier = Some("cluster-1".to_string());
        assert!(config.validate().is_err());
        config.cluster_identifier = None;
        config.workgroup_name = None;
        assert!(config.validate().is_err());
        config.workgroup_name = Some("iot-workgroup".to_string());

        config.sql_template = Some("SELECT $9".to_string());
        assert!(config.validate().is_err());
        config.sql_template = Some("UPDATE t SET payload = $5 WHERE topic = $2".to_string());
        assert!(config.validate().is_ok());
        config.sql_template = None;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_table_sanitization() {
        let mut config = test_config();
        config.table_template = "${topic}".to_string();
        assert_eq!(
            config
                .resolve_table("sensors/kitchen x", b"{}", QoS::AtMostOnce, 0)
                .unwrap(),
            "sensors_kitchen_x"
        );
        assert!(config.resolve_table("", b"{}", QoS::AtMostOnce, 0).is_err());
    }

    #[test]
    fn test_statement_rendering_and_escaping() {
        let sql = render_statement(
            "INSERT INTO sensor_logs (device_id, temp, ts) VALUES ($1, $2, $3)",
            "sensor_logs",
            1_726_160_000_000,
            "sensors/t1",
            "sensor-1",
            1,
            "{\"temp\": 42.5}",
        );
        // Only $1..$3 exist here; $4/$5 untouched (absent).
        assert_eq!(
            sql,
            "INSERT INTO sensor_logs (device_id, temp, ts) VALUES (1726160000000, 'sensors/t1', 'sensor-1')"
        );
        // Single quotes double up (injection boundary).
        let sql = render_statement("$table: $2", "t", 0, "a'b", "c", 0, "{}");
        assert_eq!(sql, "t: 'a''b'");

        let default = default_insert("sensor_logs");
        assert!(default.contains("$1") && default.contains("$5"));
        let rendered = render_statement(&default, "sensor_logs", 7, "t", "d", 0, "{\"v\":1}");
        assert!(rendered.starts_with("INSERT INTO sensor_logs (time_ms, topic, client_id, qos, payload) VALUES (7, 't', 'd', 0, "));
    }

    #[test]
    fn test_db_user_inclusion() {
        let mut config = test_config();
        config.db_user = Some("loader".to_string());
        let req = RedshiftBatchRequest {
            database: "analytics".to_string(),
            cluster_identifier: None,
            workgroup_name: Some("iot-workgroup".to_string()),
            db_user: config.db_user.clone(),
            statements: vec!["SELECT 1".to_string()],
        };
        let body = String::from_utf8(render_batch_body(&req)).unwrap();
        assert!(body.contains("\"DbUser\":\"loader\""));
    }

    #[test]
    fn test_request_framing() {
        let req = RedshiftBatchRequest {
            database: "analytics".to_string(),
            cluster_identifier: None,
            workgroup_name: Some("iot-workgroup".to_string()),
            db_user: Some("loader".to_string()),
            statements: vec![
                "INSERT INTO sensor_logs (device_id, temp, ts) VALUES ('sensor-1', 42.5, 1726160000000)".to_string(),
            ],
        };
        assert_eq!(
            String::from_utf8(render_batch_body(&req)).unwrap(),
            r#"{"Database":"analytics","WorkgroupName":"iot-workgroup","DbUser":"loader","Sqls":["INSERT INTO sensor_logs (device_id, temp, ts) VALUES ('sensor-1', 42.5, 1726160000000)"]}"#
        );
        // Cluster targeting swaps the key; absent DbUser omits it.
        let mut cluster_req = req.clone();
        cluster_req.workgroup_name = None;
        cluster_req.cluster_identifier = Some("cluster-1".to_string());
        cluster_req.db_user = None;
        let body = String::from_utf8(render_batch_body(&cluster_req)).unwrap();
        assert!(body.contains("\"ClusterIdentifier\":\"cluster-1\""));
        assert!(!body.contains("WorkgroupName"));
        assert!(!body.contains("DbUser"));
    }

    #[test]
    fn test_sigv4_known_answer() {
        // Independent Python (hmac/hashlib) vector, byte-identical body.
        let body = br#"{"Database":"analytics","WorkgroupName":"iot-workgroup","Sqls":["INSERT INTO sensor_logs (device_id, temp, ts) VALUES ('sensor-1', 42.5, 1726160000000)"]}"#;
        let (auth, date) = sign_batch_execute(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
            "us-east-1",
            "redshift-data.us-east-1.amazonaws.com",
            body,
            1_789_211_889_000,
        );
        assert_eq!(date, "20260912T111809Z");
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260912/us-east-1/redshift-data/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date;x-amz-target, \
             Signature=860929472bd10d09e40fac9fca3c0788522e2050ef1c9c3407c08b9ef6644674"
        );
    }

    #[tokio::test]
    async fn test_batch_flow_and_targeting() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"client_id":"sensor-1","temp":42.5}"#),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].database, "analytics");
        assert_eq!(captured[0].workgroup_name.as_deref(), Some("iot-workgroup"));
        assert_eq!(captured[0].cluster_identifier, None);
        assert_eq!(captured[0].statements.len(), 1);
        assert!(captured[0].statements[0].contains("INSERT INTO sensor_logs"));
        assert!(captured[0].statements[0].contains("'sensor-1'"));
        assert_eq!(sink.sent_records(), 1);
    }

    #[tokio::test]
    async fn test_throttle_retries_then_succeeds() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockRedshiftOutcome::Throttled,
            MockRedshiftOutcome::Accepted {
                id: "stmt-9".to_string(),
            },
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(transport.calls(), 2);
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_query_failure_is_terminal() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockRedshiftOutcome::Failed {
                message: "syntax error".to_string(),
            },
            MockRedshiftOutcome::Accepted {
                id: "stmt-9".to_string(),
            },
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("failure must abort");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[test]
    fn test_sdk_transport_construction() {
        let config = test_config();
        // Building the driver client is lazy: no I/O, safe offline.
        let transport = SdkRedshiftTransport::new(&config).expect("sdk transport builds");
        assert_eq!(transport.timeout(), config.timeout());
        let mut bad = test_config();
        bad.database.clear();
        assert!(SdkRedshiftTransport::new(&bad).is_err());
    }

    #[test]
    fn test_sdk_batch_splitting_respects_vendor_limit() {
        // Vendor `BatchExecuteStatement` `Sqls` max is 40: a 100-row
        // sink batch must ride 40 + 40 + 20, never one call of 100.
        assert_eq!(REDSHIFT_MAX_SQLS_PER_BATCH, 40);
        let statements: Vec<String> = (0..100).map(|n| format!("SELECT {n}")).collect();
        let chunks: Vec<&[String]> = statements.chunks(REDSHIFT_MAX_SQLS_PER_BATCH).collect();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 40);
        assert_eq!(chunks[1].len(), 40);
        assert_eq!(chunks[2].len(), 20);
    }

    #[tokio::test]
    async fn test_sdk_empty_batch_fails_closed() {
        // Empty batches never touch the driver: terminal dispatch,
        // safe offline.
        let transport = SdkRedshiftTransport::new(&test_config()).expect("sdk transport builds");
        let req = RedshiftBatchRequest {
            database: "analytics".to_string(),
            cluster_identifier: None,
            workgroup_name: Some("iot-workgroup".to_string()),
            db_user: None,
            statements: vec![],
        };
        let err = transport
            .execute_batch(&req)
            .await
            .expect_err("empty batch must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
    }

    #[test]
    fn test_sdk_error_classification() {
        // Throttles, quota and transport failures retry; terminal
        // failures (auth, validation, query errors) do not.
        for retryable in [
            "redshift batch execute failed: ThrottlingException (throttled)",
            "redshift batch execute failed: ActiveStatementsExceededException",
            "redshift batch execute failed: InternalServerException",
            "redshift batch execute failed: ServiceUnavailable",
            "redshift driver timed out after 5000ms",
            "redshift describe statement failed: connection reset (dispatch failure)",
        ] {
            assert!(
                matches!(
                    classify_redshift_sdk_error(retryable.to_string()),
                    ConnectorError::Connection(_)
                ),
                "{retryable:?} must be retryable"
            );
        }
        for terminal in [
            "redshift batch execute failed: AccessDeniedException",
            "redshift batch execute failed: ValidationException (unknown workgroup)",
            "redshift statement stmt-1 FAILED: syntax error :: THIS IS NOT SQL",
        ] {
            assert!(
                matches!(
                    classify_redshift_sdk_error(terminal.to_string()),
                    ConnectorError::Dispatch(_)
                ),
                "{terminal:?} must be terminal"
            );
        }
    }

    #[tokio::test]
    async fn test_sdk_unreachable_fails_closed_through_manager() {
        // Unreachable server through the broker path: connection
        // failure, never access granted.
        use broker_connectors::ConnectorManager;
        let mut config = test_config();
        config.endpoint = Some("http://127.0.0.1:1".to_string());
        config.batch_size = Some(1);
        config.timeout_ms = Some(500);
        let transport = Arc::new(SdkRedshiftTransport::new(&config).expect("sdk transport"));
        let sink = Arc::new(RedshiftSink::new(config, transport).expect("sink"));
        assert_eq!(sink.kind(), "redshift");
        let manager = ConnectorManager::new();
        manager.register("redshift-dead", sink.clone());
        let err = manager
            .send(
                "redshift-dead",
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

    fn qual_require(name: &str) -> String {
        qual_env(name).unwrap_or_else(|| {
            panic!(
                "{name} must name a real Amazon Redshift server for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. REDSHIFT_WORKGROUP=qual-wg)"
            )
        })
    }

    fn qual_identifier(name: &str, value: &str) -> String {
        assert!(
            !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "qual {name} must match [A-Za-z0-9_]+, got {value:?} (failing closed)"
        );
        value.to_string()
    }

    /// Discards unmatched egress for the rule-path qualification (the
    /// connector under test receives everything through its rule).
    struct NullBrokerSink;

    #[async_trait::async_trait]
    impl broker_rules::BrokerSink for NullBrokerSink {
        async fn publish(
            &self,
            _topic: Topic,
            _payload: Bytes,
            _qos: QoS,
            _retain: bool,
        ) -> std::result::Result<(), broker_rules::RuleEngineError> {
            Ok(())
        }
    }

    fn field_to_string(field: &aws_sdk_redshiftdata::types::Field) -> String {
        use aws_sdk_redshiftdata::types::Field;
        match field {
            Field::StringValue(text) => text.clone(),
            Field::LongValue(n) => n.to_string(),
            Field::DoubleValue(d) => d.to_string(),
            Field::BooleanValue(b) => b.to_string(),
            Field::IsNull(_) => String::new(),
            _ => format!("{field:?}"),
        }
    }

    /// Run one SQL statement through the driver and poll
    /// `DescribeStatement` to FINISHED, returning the statement id.
    /// `FAILED` / `ABORTED` surface the server error plus the
    /// statement text as a terminal dispatch error.
    async fn qual_run_sql(
        client: &aws_sdk_redshiftdata::Client,
        database: &str,
        workgroup: Option<&str>,
        cluster: Option<&str>,
        db_user: Option<&str>,
        sql: &str,
        timeout: Duration,
    ) -> String {
        let mut builder = client
            .execute_statement()
            .set_database(Some(database.to_string()))
            .set_sql(Some(sql.to_string()));
        if let Some(cluster) = cluster {
            builder = builder.set_cluster_identifier(Some(cluster.to_string()));
        }
        if let Some(workgroup) = workgroup {
            builder = builder.set_workgroup_name(Some(workgroup.to_string()));
        }
        if let Some(user) = db_user {
            builder = builder.set_db_user(Some(user.to_string()));
        }
        let id = tokio::time::timeout(timeout, builder.send())
            .await
            .expect("qual execute timed out")
            .unwrap_or_else(|e| panic!("qual execute failed: {e:?} ({e})"))
            .id()
            .map(str::to_string)
            .expect("qual execute lacks Id");
        // Poll to a terminal state (cold Serverless workgroups resume
        // for minutes; 300 x 2 s is a 10 min upper bound per setup
        // statement, matching the sink's bounded polling).
        for _ in 0..300 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let described = tokio::time::timeout(
                timeout,
                client.describe_statement().set_id(Some(id.clone())).send(),
            )
            .await
            .expect("qual describe timed out")
            .unwrap_or_else(|e| panic!("qual describe failed: {e:?} ({e})"));
            let status = described.status().map(|s| s.as_str()).unwrap_or("");
            match status {
                "FINISHED" => return id,
                "FAILED" | "ABORTED" => {
                    let server_error = described.error().unwrap_or("unknown error");
                    let query = described.query_string().unwrap_or("");
                    panic!("qual statement {id} {status}: {server_error} :: {query}");
                }
                _ => {}
            }
        }
        panic!("qual statement {id} still pending after 300 polls");
    }

    /// Fetch every result row for a finished statement id,
    /// following pagination tokens to the end.
    async fn qual_fetch_all(
        client: &aws_sdk_redshiftdata::Client,
        id: &str,
        timeout: Duration,
    ) -> Vec<Vec<String>> {
        let mut rows = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut builder = client.get_statement_result().set_id(Some(id.to_string()));
            if let Some(token) = next {
                builder = builder.set_next_token(Some(token));
            }
            let page = tokio::time::timeout(timeout, builder.send())
                .await
                .expect("qual fetch timed out")
                .unwrap_or_else(|e| panic!("qual fetch failed: {e:?} ({e})"));
            for record in page.records() {
                rows.push(record.iter().map(field_to_string).collect());
            }
            match page.next_token() {
                Some(token) => next = Some(token.to_string()),
                None => break,
            }
        }
        rows
    }

    /// Qualification against a real Amazon Redshift Serverless
    /// workgroup through the Redshift Data API on the maintained
    /// `aws-sdk-redshiftdata` driver.
    ///
    /// Run with e.g.:
    /// `REDSHIFT_WORKGROUP=qual-wg REDSHIFT_DATABASE=dev REDSHIFT_REGION=ap-south-1 \
    ///  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
    ///  cargo test -p broker-connectors-enterprise --lib redshift::tests::test_qualify_driver_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Creates a table, streams 500 sequence-keyed rows through the
    /// broker ([`broker_rules::RuleEngine`] dispatch into a
    /// [`RedshiftSink`] on [`SdkRedshiftTransport`], never `sink.send`
    /// directly) in few `BatchExecuteStatement` calls, polls each
    /// statement to FINISHED, asserts `COUNT(*)` returns 500 with
    /// every key present, proves a syntax error surfaces the
    /// statement text, then drops the table it created. Panics when
    /// its environment is missing (fail closed, never skips).
    ///
    /// NOTE: the task spec's `QUAL-CMD` names `-p broker-connectors`
    /// (the pre-split crate path); the sink lives in
    /// `broker-connectors-enterprise`, so the gates must run the
    /// enterprise path above (a shim under `-p broker-connectors`
    /// drives the same sink through the same rule path).
    #[tokio::test]
    #[ignore = "needs a real Amazon Redshift server (see REDSHIFT_* env)"]
    async fn test_qualify_driver_write_path() {
        use broker_protocol::TopicFilter;
        use broker_rules::{BackpressurePolicy, RuleEngine};
        use std::collections::HashSet;

        const ROWS: usize = 500;

        let workgroup = qual_require("REDSHIFT_WORKGROUP");
        let database = qual_require("REDSHIFT_DATABASE");
        let region = qual_require("REDSHIFT_REGION");
        let table = qual_identifier(
            "table",
            &qual_env("REDSHIFT_TABLE").unwrap_or_else(|| "qual_b338".to_string()),
        );
        let access_key = qual_env("AWS_ACCESS_KEY_ID").unwrap_or_else(|| {
            panic!("AWS_ACCESS_KEY_ID must be set for qualification; failing closed")
        });
        let secret_key = qual_env("AWS_SECRET_ACCESS_KEY").unwrap_or_else(|| {
            panic!("AWS_SECRET_ACCESS_KEY must be set for qualification; failing closed")
        });
        let session_token = qual_env("AWS_SESSION_TOKEN");
        // Optional database user (temporary-credential mapping); the
        // real service needs none when the IAM identity maps directly.
        let db_user = qual_env("REDSHIFT_DB_USER");
        // TODO(parity): the Data API exposes no dedicated server-version
        // call, so the report carries `SELECT version()` output plus the
        // workgroup/region instead of a version string; is that an
        // acceptable "server version"?

        let mut config = test_config();
        config.database = database.clone();
        config.table_template = table.clone();
        config.cluster_identifier = None;
        config.workgroup_name = Some(workgroup.clone());
        config.region = region.clone();
        config.endpoint = None;
        config.access_key_id = access_key;
        config.secret_access_key = secret_key;
        config.session_token = session_token;
        config.db_user = db_user.clone();
        config.sql_template = None;
        // Few billed statements: 500 rows in 5 batches of 100.
        config.batch_size = Some(100);
        config.batch_bytes = Some(1_048_576);
        config.linger_ms = Some(60_000); // explicit flushes only; keeps auto-batches exact
        config.max_retries = Some(5);
        config.initial_backoff_ms = Some(100);
        config.max_backoff_ms = Some(2_500);
        config.timeout_ms = Some(30_000);
        config.validate().expect("qual config validates");

        // Cold Serverless workgroups resume for minutes: the
        // per-batch poll bound is generous (5 min) so the first batch
        // survives a resume without stalling the rule path forever.
        let transport = Arc::new(
            SdkRedshiftTransport::with_polling(&config, Duration::from_secs(1), 300)
                .expect("qual transport"),
        );
        let client = transport.client().clone();
        let admin_timeout = Duration::from_secs(60);

        // Server version for the report (connectivity is already
        // proved by the call below; the version string is context).
        let version_id = qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            "SELECT version()",
            admin_timeout,
        )
        .await;
        let version_rows = qual_fetch_all(&client, &version_id, admin_timeout).await;
        let version = version_rows
            .first()
            .and_then(|row| row.first())
            .cloned()
            .unwrap_or_default();
        eprintln!("qual server: version={version} workgroup={workgroup} region={region}");

        qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            &format!("DROP TABLE IF EXISTS {table}"),
            admin_timeout,
        )
        .await;
        qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            &format!(
                "CREATE TABLE {table} (\
                 time_ms BIGINT NOT NULL, \
                 topic VARCHAR(256) NOT NULL, \
                 client_id VARCHAR(256) NOT NULL, \
                 qos INTEGER NOT NULL, \
                 payload VARCHAR(65535) NOT NULL)"
            ),
            admin_timeout,
        )
        .await;
        eprintln!("qual table created: {table} (BIGINT/VARCHAR/INTEGER)");

        // The broker's path: a rule registered on the connector
        // manager, messages published through the rule engine, so the
        // qualification sends through `dispatch_ingress`, never
        // `sink.send` directly.
        let sink = Arc::new(RedshiftSink::new(config, transport.clone()).expect("qual sink"));
        assert_eq!(sink.kind(), "redshift");
        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        engine.connectors().register("qual-redshift", sink.clone());
        engine
            .create_rule(
                "qual-redshift-rule".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT client_id, seq FROM "sensors/+" INTO connector("qual-redshift")"#
                        .to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");
        let egress: Arc<dyn broker_rules::BrokerSink> = Arc::new(NullBrokerSink);

        let topic = Topic::new("sensors/qual").unwrap();
        for seq in 0..ROWS {
            let payload = Bytes::from(format!(r#"{{"client_id":"qual-{seq:06}","seq":{seq}}}"#));
            engine
                .dispatch_ingress(&topic, &payload, QoS::AtLeastOnce, &egress)
                .await;
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), ROWS as u64, "qual sent records");
        eprintln!("qual rows sent: records={ROWS} table={table}");

        // Row count asserted back from the server, not the counters.
        let count_id = qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            &format!("SELECT COUNT(*) FROM {table}"),
            admin_timeout,
        )
        .await;
        let count_rows = qual_fetch_all(&client, &count_id, admin_timeout).await;
        let count: i64 = count_rows
            .first()
            .and_then(|row| row.first())
            .and_then(|value| value.parse().ok())
            .expect("qual count value");
        assert_eq!(count, ROWS as i64, "qual count mismatch");
        eprintln!("qual rows asserted: count={ROWS} table={table}");

        // Every key asserted back from the server (at-least-once
        // permits duplicates, never loss).
        let keys_id = qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            &format!("SELECT client_id FROM {table}"),
            admin_timeout,
        )
        .await;
        let key_rows = qual_fetch_all(&client, &keys_id, admin_timeout).await;
        let seen: HashSet<String> = key_rows
            .into_iter()
            .filter_map(|row| row.into_iter().next())
            .collect();
        assert_eq!(seen.len(), ROWS, "qual distinct keys mismatch");
        for seq in 0..ROWS {
            let key = format!("qual-{seq:06}");
            assert!(seen.contains(&key), "qual missing key {key}");
        }
        eprintln!("qual keys asserted: keys={ROWS} table={table}");

        // A syntax error surfaces the statement text (terminal
        // dispatch, never a silent drop).
        let probe = "THIS IS NOT VALID SQL __qual_syntax_probe__";
        let bad_request = RedshiftBatchRequest {
            database: database.clone(),
            cluster_identifier: None,
            workgroup_name: Some(workgroup.clone()),
            db_user: db_user.clone(),
            statements: vec![probe.to_string()],
        };
        let err = transport
            .execute_batch(&bad_request)
            .await
            .expect_err("syntax error must fail");
        assert!(
            matches!(err, ConnectorError::Dispatch(_)),
            "syntax error must be terminal, got {err:?}"
        );
        assert!(
            format!("{err}").contains("__qual_syntax_probe__"),
            "syntax error must surface the statement text, got {err:?}"
        );
        eprintln!("qual syntax asserted: statement text surfaces ({err})");

        // Cleanup the table we created.
        qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            &format!("DROP TABLE IF EXISTS {table}"),
            admin_timeout,
        )
        .await;
        eprintln!("qual cleanup: dropped table {table}");
    }
}
