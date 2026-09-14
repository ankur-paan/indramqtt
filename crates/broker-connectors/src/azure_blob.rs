//! Azure Blob Storage / Azurite block-blob sink (INDRA-189).
//!
//! Buffers MQTT events as newline-delimited JSON (ndjson) micro-batches
//! and uploads one block blob per flush with HTTP
//! `PUT /{container}/{blob_path}`. Blob paths come from a partitioned
//! [`AzureBlobSinkConfig::blob_path_template`] (`${date.year}`,
//! `${date.month}`, `${date.day}`, `${date.hour}`, `${batch_id}`).
//! Payloads can optionally ride gzip (`Content-Encoding: gzip`).
//!
//! Authentication covers all three production schemes: Shared Key
//! (clean-room HMAC-SHA256 `StringToSign` below), SAS token (appended
//! to the URL query, signature untouched), and Azure AD bearer token.
//! Batching, restore-on-failure and backoff reuse the shared
//! [`super::BatchQueue`] / [`super::BackoffState`] helpers, so failed
//! flushes keep the buffer, engage backoff, and propagate the error.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{
    hmac_sha256, hms_milli_from_millis, now_millis, render_template, ymd_from_millis, BackoffState,
    BatchQueue, ConnectorError, Result, Sink,
};

/// Object body compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AzureBlobCompression {
    /// Raw ndjson bytes.
    #[default]
    None,
    /// RFC 1952 gzip member (`Content-Encoding: gzip`).
    Gzip,
}

/// Azure Blob authentication scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum AzureBlobAuth {
    /// Shared Key: `Authorization: SharedKey {account}:{signature}`.
    SharedKey {
        /// Base64-encoded storage account key.
        account_key: String,
    },
    /// Shared Access Signature appended to the blob URL query.
    SasToken {
        /// Query string with or without a leading `?`.
        sas_token: String,
    },
    /// Azure AD OAuth 2.0 bearer token.
    BearerToken {
        /// Raw token (sent as `Authorization: Bearer ...`).
        token: String,
    },
}

fn default_max_records() -> Option<usize> {
    Some(10_000)
}

fn default_max_bytes() -> Option<usize> {
    Some(10_485_760)
}

fn default_flush_interval_secs() -> u64 {
    60
}

/// Azure Blob sink configuration. Every depth is user-configurable
/// with no clamped ceiling (`None` = unbounded), so blobs scale to
/// millions of events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureBlobSinkConfig {
    /// Storage account name, e.g. `mydeviceblobs`.
    pub account_name: String,
    /// Destination container, e.g. `telemetry`.
    pub container_name: String,
    /// Custom endpoint (Azurite / custom domains); defaults to
    /// `https://{account_name}.blob.core.windows.net`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Authentication scheme.
    pub auth: AzureBlobAuth,
    /// Partitioned blob path template, e.g.
    /// `telemetry/year=${date.year}/month=${date.month}/day=${date.day}/hour=${date.hour}/${batch_id}.json.gz`.
    pub blob_path_template: String,
    /// Body compression (default none).
    #[serde(default)]
    pub compression: AzureBlobCompression,
    /// Flush trigger record count (default 10,000).
    #[serde(default = "default_max_records")]
    pub max_records_per_blob: Option<usize>,
    /// Flush trigger byte limit over buffered ndjson (default 10 MiB).
    #[serde(default = "default_max_bytes")]
    pub max_bytes_per_blob: Option<usize>,
    /// Linger flush window in seconds (default 60).
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,
    /// Buffer capacity (`None` = unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl AzureBlobSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        validate_account_name(&self.account_name)?;
        validate_container_name(&self.container_name)?;
        match &self.auth {
            AzureBlobAuth::SharedKey { account_key } => {
                if account_key.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "azure_blob SharedKey account_key must not be empty".to_string(),
                    ));
                }
                // The key must be valid base64 (decoded at sign time).
                decode_account_key(account_key)?;
            }
            AzureBlobAuth::SasToken { sas_token } => {
                if sas_token.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "azure_blob SasToken sas_token must not be empty".to_string(),
                    ));
                }
            }
            AzureBlobAuth::BearerToken { token } => {
                if token.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "azure_blob BearerToken token must not be empty".to_string(),
                    ));
                }
            }
        }
        if self.blob_path_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "azure_blob blob_path_template must not be empty".to_string(),
            ));
        }
        // Strict template check with dummy values: unknown or unclosed
        // variables fail here, not on the hot path.
        self.resolve_path(0, 0)?;
        if self.max_records_per_blob == Some(0) {
            return Err(ConnectorError::Dispatch(
                "azure_blob max_records_per_blob must be >= 1".to_string(),
            ));
        }
        if self.max_bytes_per_blob == Some(0) {
            return Err(ConnectorError::Dispatch(
                "azure_blob max_bytes_per_blob must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// Base endpoint without a trailing slash.
    pub fn base_endpoint(&self) -> String {
        match &self.endpoint {
            Some(custom) => custom.trim_end_matches('/').to_string(),
            None => format!("https://{}.blob.core.windows.net", self.account_name),
        }
    }

    /// Render the blob path for one flush: `${date.year}` /
    /// `${date.month}` / `${date.day}` / `${date.hour}` come from
    /// `millis` (UTC), `${batch_id}` is the flush sequence number.
    /// A leading `/` is rejected so paths stay relative.
    pub fn resolve_path(&self, batch_id: u64, millis: i64) -> Result<String> {
        let (year, month, day) = ymd_from_millis(millis);
        let (hour, _, _, _) = hms_milli_from_millis(millis);
        let vars = [
            ("date.year", format!("{year:04}")),
            ("date.month", format!("{month:02}")),
            ("date.day", format!("{day:02}")),
            ("date.hour", format!("{hour:02}")),
            ("batch_id", batch_id.to_string()),
        ];
        let path = render_template(&self.blob_path_template, &vars)?;
        if path.is_empty() || path.starts_with('/') {
            return Err(ConnectorError::Dispatch(format!(
                "azure_blob blob_path_template resolved to an invalid path: {path:?}"
            )));
        }
        Ok(path)
    }

    /// Full blob URL for a rendered path (SAS query preserved verbatim
    /// when the auth scheme is [`AzureBlobAuth::SasToken`]).
    pub fn blob_url(&self, path: &str) -> String {
        let base = format!(
            "{}/{}/{}",
            self.base_endpoint(),
            self.container_name,
            path.trim_start_matches('/')
        );
        match &self.auth {
            AzureBlobAuth::SasToken { sas_token } => {
                let query = sas_token.trim_start_matches('?');
                format!("{base}?{query}")
            }
            _ => base,
        }
    }

    pub(crate) fn effective_batch_size(&self) -> usize {
        self.max_records_per_blob.unwrap_or(usize::MAX)
    }

    pub(crate) fn effective_batch_bytes(&self) -> usize {
        self.max_bytes_per_blob.unwrap_or(usize::MAX)
    }

    pub(crate) fn effective_buffer(&self) -> usize {
        self.buffer_capacity.unwrap_or(usize::MAX)
    }

    pub(crate) fn linger(&self) -> Duration {
        Duration::from_secs(self.flush_interval_secs.max(1))
    }
}

fn validate_account_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.len() < 3 || bytes.len() > 24 {
        return Err(ConnectorError::Dispatch(format!(
            "azure_blob account_name must be 3..=24 chars: {name:?}"
        )));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(ConnectorError::Dispatch(format!(
            "azure_blob account_name must match [a-z0-9]: {name:?}"
        )));
    }
    Ok(())
}

fn validate_container_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.len() < 3 || bytes.len() > 63 {
        return Err(ConnectorError::Dispatch(format!(
            "azure_blob container_name must be 3..=63 chars: {name:?}"
        )));
    }
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(ConnectorError::Dispatch(format!(
            "azure_blob container_name must start/end alphanumeric: {name:?}"
        )));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(ConnectorError::Dispatch(format!(
            "azure_blob container_name must match [a-z0-9-]: {name:?}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Azure Storage Shared Key signing (clean-room, Blob service 2021-08-06).
// ---------------------------------------------------------------------------

/// Canonicalized resource for one blob PUT.
pub fn canonicalized_resource(account: &str, container: &str, blob_path: &str) -> String {
    format!("/{account}/{container}/{blob_path}")
}

/// Build the Shared Key `StringToSign` for `PUT /{container}/{path}`.
///
/// ```text
/// PUT\n\n\n{content_length}\n\n{content_type}\n\n\n\n\n\n\n
/// x-ms-blob-type:BlockBlob\nx-ms-date:{date}\nx-ms-version:2021-08-06\n
/// /{account}/{container}/{blob_path}
/// ```
pub fn string_to_sign(
    account: &str,
    container: &str,
    blob_path: &str,
    content_length: usize,
    content_type: &str,
    date: &str,
) -> String {
    format!(
        "PUT\n\n\n{content_length}\n\n{content_type}\n\n\n\n\n\n\n\
         x-ms-blob-type:BlockBlob\n\
         x-ms-date:{date}\n\
         x-ms-version:{AZURE_STORAGE_VERSION}\n\
         {}",
        canonicalized_resource(account, container, blob_path)
    )
}

/// Storage service version pinned on every request.
pub const AZURE_STORAGE_VERSION: &str = "2021-08-06";

fn decode_account_key(account_key: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(account_key.trim())
        .map_err(|e| ConnectorError::Dispatch(format!("azure_blob account_key is not base64: {e}")))
}

/// `Authorization: SharedKey {account}:{Base64(HMAC_SHA256(key, sts))}`.
pub fn shared_key_authorization(
    account: &str,
    account_key_b64: &str,
    string_to_sign: &str,
) -> Result<String> {
    let key = decode_account_key(account_key_b64)?;
    use base64::Engine;
    let signature = base64::engine::general_purpose::STANDARD
        .encode(hmac_sha256(&key, string_to_sign.as_bytes()));
    Ok(format!("SharedKey {account}:{signature}"))
}

// ---------------------------------------------------------------------------
// Payload framing.
// ---------------------------------------------------------------------------

/// One buffered ndjson line.
#[derive(Debug, Clone)]
struct AzureBlobRow {
    line: String,
}

fn render_row(topic: &Topic, payload: &Bytes, qos: QoS, millis: i64) -> Result<AzureBlobRow> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| ConnectorError::Dispatch("azure_blob payload must be UTF-8".to_string()))?;
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => serde_json::Value::String(text.to_string()),
    };
    let line = serde_json::json!({
        "topic": topic.as_str(),
        "qos": u8::from(qos),
        "payload": value,
        "timestamp": super::rfc3339_millis(millis),
    })
    .to_string();
    Ok(AzureBlobRow { line })
}

fn gzip_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), GzCompression::default());
    encoder
        .write_all(raw)
        .map_err(|e| ConnectorError::Dispatch(format!("azure_blob gzip failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| ConnectorError::Dispatch(format!("azure_blob gzip failed: {e}")))
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// One block-blob upload: rendered path, body and content headers.
#[derive(Debug, Clone)]
pub struct AzureBlobPut {
    pub path: String,
    pub url: String,
    pub body: Vec<u8>,
    pub content_type: &'static str,
    pub content_encoding: Option<&'static str>,
}

/// Classified PUT outcome: success, retryable (backoff + restore) or
/// terminal (drop + dispatch error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AzureBlobOutcome {
    Success,
    Retryable,
    Terminal,
}

/// Pull the Azure `<Code>` element out of an XML error body.
pub fn azure_error_code(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let start = text.find("<Code>")? + "<Code>".len();
    let end = text[start..].find("</Code>")?;
    Some(text[start..start + end].trim().to_string())
}

/// Classify an HTTP PUT status (+ optional XML error body).
///
/// 403 `AuthenticationFailed` and 404 `ContainerNotFound` are
/// terminal; 500 `ServerBusy` / 503 `ServiceUnavailable` (and 429)
/// are retryable with backoff; other 2xx succeed; other 4xx are
/// terminal dispatch errors; other 5xx are retryable.
pub fn classify_blob_status(status: u16, body: &[u8]) -> AzureBlobOutcome {
    if (200..300).contains(&status) {
        return AzureBlobOutcome::Success;
    }
    if let Some(code) = azure_error_code(body) {
        match code.as_str() {
            "AuthenticationFailed" | "ContainerNotFound" => return AzureBlobOutcome::Terminal,
            "ServerBusy" | "ServiceUnavailable" => return AzureBlobOutcome::Retryable,
            _ => {}
        }
    }
    match status {
        403 | 404 => AzureBlobOutcome::Terminal,
        429 => AzureBlobOutcome::Retryable,
        400..=499 => AzureBlobOutcome::Terminal,
        _ => AzureBlobOutcome::Retryable,
    }
}

#[async_trait]
pub trait AzureBlobTransport: Send + Sync {
    async fn put_blob(
        &self,
        put: &AzureBlobPut,
        date: &str,
        authorization: Option<&str>,
    ) -> Result<()>;
}

/// In-memory transport recording every upload (tests, dry runs). The
/// scripted status lets tests drive classification end to end.
#[derive(Debug, Default)]
pub struct MockAzureBlobTransport {
    puts: parking_lot::Mutex<Vec<AzureBlobPut>>,
    /// Next-call HTTP status (default 201).
    next_status: parking_lot::Mutex<Option<u16>>,
    next_body: parking_lot::Mutex<Vec<u8>>,
    calls: AtomicU64,
    pub last_date: parking_lot::Mutex<Option<String>>,
    pub last_authorization: parking_lot::Mutex<Option<String>>,
}

impl MockAzureBlobTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next upload with a scripted HTTP status + XML body.
    pub fn fail_next(&self, status: u16, body: impl Into<Vec<u8>>) {
        *self.next_status.lock() = Some(status);
        *self.next_body.lock() = body.into();
    }

    pub fn puts(&self) -> Vec<AzureBlobPut> {
        self.puts.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl AzureBlobTransport for MockAzureBlobTransport {
    async fn put_blob(
        &self,
        put: &AzureBlobPut,
        date: &str,
        authorization: Option<&str>,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_date.lock() = Some(date.to_string());
        *self.last_authorization.lock() = authorization.map(str::to_string);
        if let Some(status) = self.next_status.lock().take() {
            let body = std::mem::take(&mut *self.next_body.lock());
            return match classify_blob_status(status, &body) {
                AzureBlobOutcome::Success => {
                    self.puts.lock().push(put.clone());
                    Ok(())
                }
                AzureBlobOutcome::Retryable => Err(ConnectorError::Connection(format!(
                    "mock azure_blob answered {status}"
                ))),
                AzureBlobOutcome::Terminal => Err(ConnectorError::Dispatch(format!(
                    "mock azure_blob answered {status}"
                ))),
            };
        }
        self.puts.lock().push(put.clone());
        Ok(())
    }
}

/// HTTP transport: `PUT {url}` with the version/date/type headers and
/// per-scheme auth (SharedKey header, SAS query, bearer header).
pub struct HttpAzureBlobTransport {
    client: reqwest::Client,
}

impl HttpAzureBlobTransport {
    pub fn new(config: &AzureBlobSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self { client })
    }
}

#[async_trait]
impl AzureBlobTransport for HttpAzureBlobTransport {
    async fn put_blob(
        &self,
        put: &AzureBlobPut,
        date: &str,
        authorization: Option<&str>,
    ) -> Result<()> {
        let mut request = self
            .client
            .put(&put.url)
            .header("x-ms-blob-type", "BlockBlob")
            .header("x-ms-version", AZURE_STORAGE_VERSION)
            .header("x-ms-date", date)
            .header(reqwest::header::CONTENT_TYPE, put.content_type)
            .body(put.body.clone());
        if let Some(encoding) = put.content_encoding {
            request = request.header(reqwest::header::CONTENT_ENCODING, encoding);
        }
        if let Some(auth) = authorization {
            request = request.header(reqwest::header::AUTHORIZATION, auth);
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("azure_blob put failed: {e}")))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("azure_blob read failed: {e}")))?;
        match classify_blob_status(status, &body) {
            AzureBlobOutcome::Success => Ok(()),
            AzureBlobOutcome::Retryable => Err(ConnectorError::Connection(format!(
                "azure_blob {} answered {status}",
                put.path
            ))),
            AzureBlobOutcome::Terminal => Err(ConnectorError::Dispatch(format!(
                "azure_blob {} answered {status}",
                put.path
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

struct AzureBlobBuffer {
    queue: BatchQueue<AzureBlobRow>,
    bytes: usize,
}

/// Azure Blob sink: buffers ndjson rows, uploads one block blob per flush.
pub struct AzureBlobSink {
    config: AzureBlobSinkConfig,
    transport: Arc<dyn AzureBlobTransport>,
    buffer: parking_lot::Mutex<AzureBlobBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    batch_seq: AtomicU64,
    sent_blobs: AtomicU64,
    sent_records: AtomicU64,
}

impl AzureBlobSink {
    pub fn new(
        config: AzureBlobSinkConfig,
        transport: Arc<dyn AzureBlobTransport>,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            buffer: parking_lot::Mutex::new(AzureBlobBuffer {
                queue: BatchQueue::new(config.effective_batch_size(), config.linger()),
                bytes: 0,
            }),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            batch_seq: AtomicU64::new(0),
            sent_blobs: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &AzureBlobSinkConfig {
        &self.config
    }

    pub fn sent_blobs(&self) -> u64 {
        self.sent_blobs.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().queue.len()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffer.lock().bytes
    }

    /// Flush buffered rows as one block blob (no-op when empty). While
    /// backing off, fails fast without touching the transport. Any
    /// failure restores rows + byte count, engages backoff, propagates.
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
        let batch_id = self.batch_seq.fetch_add(1, Ordering::SeqCst);
        let millis = now_millis();
        let path = self
            .config
            .resolve_path(batch_id, millis)
            .unwrap_or_else(|_| format!("unkeyed/{batch_id}.ndjson"));
        let mut raw = String::new();
        for row in &rows {
            raw.push_str(&row.line);
            raw.push('\n');
        }
        let (body, content_encoding, content_type) = match self.config.compression {
            AzureBlobCompression::None => (raw.into_bytes(), None, "application/x-ndjson"),
            AzureBlobCompression::Gzip => (
                gzip_bytes(raw.as_bytes())?,
                Some("gzip"),
                "application/octet-stream",
            ),
        };
        let date = super::oci_streaming::rfc1123_date(millis);
        let authorization = match &self.config.auth {
            AzureBlobAuth::SharedKey { account_key } => Some(shared_key_authorization(
                &self.config.account_name,
                account_key,
                &string_to_sign(
                    &self.config.account_name,
                    &self.config.container_name,
                    &path,
                    body.len(),
                    content_type,
                    &date,
                ),
            )?),
            AzureBlobAuth::BearerToken { token } => Some(format!("Bearer {token}")),
            AzureBlobAuth::SasToken { .. } => None,
        };
        let put = AzureBlobPut {
            url: self.config.blob_url(&path),
            path,
            body,
            content_type,
            content_encoding,
        };
        let record_count = rows.len() as u64;
        match self
            .transport
            .put_blob(&put, &date, authorization.as_deref())
            .await
        {
            Ok(()) => {
                self.backoff.lock().success();
                self.sent_blobs.fetch_add(1, Ordering::Relaxed);
                self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                let mut buffer = self.buffer.lock();
                buffer.queue.restore(rows, oldest);
                buffer.bytes = buffer.bytes.saturating_add(taken_bytes);
                self.backoff.lock().failure();
                Err(e)
            }
        }
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full, stale, or over the byte limit (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "azure_blob row requires a non-empty topic".to_string(),
            ));
        }
        if self.buffer.lock().queue.len() >= self.config.effective_buffer() {
            return Err(ConnectorError::Connection(
                "azure_blob buffer limit reached".to_string(),
            ));
        }
        let row = render_row(topic, payload, qos, now_millis())?;
        let added = row.line.len() + 1; // line plus its newline
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(row);
        buffer.bytes = buffer.bytes.saturating_add(added);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for AzureBlobSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "azure_blob"
    }
}

/// Management connector handle pairing an id with an Azure Blob sink.
pub struct AzureBlobConnector {
    id: String,
    sink: Arc<AzureBlobSink>,
}

impl AzureBlobConnector {
    pub fn new(id: impl Into<String>, sink: Arc<AzureBlobSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for AzureBlobConnector {
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
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn test_config() -> AzureBlobSinkConfig {
        AzureBlobSinkConfig {
            account_name: "mydeviceblobs".to_string(),
            container_name: "telemetry".to_string(),
            endpoint: None,
            auth: AzureBlobAuth::SharedKey {
                account_key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".to_string(),
            },
            blob_path_template: "telemetry/year=${date.year}/month=${date.month}/day=${date.day}/hour=${date.hour}/${batch_id}.json"
                .to_string(),
            compression: AzureBlobCompression::None,
            max_records_per_blob: Some(10_000),
            max_bytes_per_blob: Some(10_485_760),
            flush_interval_secs: 60,
            buffer_capacity: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.account_name = "AB".to_string();
        assert!(config.validate().is_err());
        config.account_name = "HAS_UPPER".to_string();
        assert!(config.validate().is_err());
        config.account_name = "mydeviceblobs".to_string();

        config.container_name = "ab".to_string();
        assert!(config.validate().is_err());
        config.container_name = "HasUpper".to_string();
        assert!(config.validate().is_err());
        config.container_name = "telemetry".to_string();

        config.auth = AzureBlobAuth::SharedKey {
            account_key: "!!!not-base64!!!".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = AzureBlobAuth::SasToken {
            sas_token: "   ".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = AzureBlobAuth::BearerToken {
            token: String::new(),
        };
        assert!(config.validate().is_err());
        config.auth = test_config().auth;

        config.blob_path_template = "telemetry/${nope}.json".to_string();
        assert!(config.validate().is_err());
        config.blob_path_template = "telemetry/${date.year".to_string();
        assert!(config.validate().is_err());
        config.blob_path_template = test_config().blob_path_template;

        config.max_records_per_blob = Some(0);
        assert!(config.validate().is_err());
        config.max_records_per_blob = Some(10_000_000);

        config.max_bytes_per_blob = Some(0);
        assert!(config.validate().is_err());
        config.max_bytes_per_blob = None;

        // Zero clamped ceilings: huge depths are accepted.
        assert!(config.validate().is_ok());
        assert_eq!(
            config.base_endpoint(),
            "https://mydeviceblobs.blob.core.windows.net"
        );
    }

    #[test]
    fn test_string_to_sign_builder() {
        let sts = string_to_sign(
            "mydeviceblobs",
            "telemetry",
            "telemetry/year=2026/month=09/day=12/0.json",
            17,
            "application/x-ndjson",
            "Sat, 12 Sep 2026 11:18:09 GMT",
        );
        assert_eq!(
            sts,
            "PUT\n\n\n17\n\napplication/x-ndjson\n\n\n\n\n\n\n\
             x-ms-blob-type:BlockBlob\n\
             x-ms-date:Sat, 12 Sep 2026 11:18:09 GMT\n\
             x-ms-version:2021-08-06\n\
             /mydeviceblobs/telemetry/telemetry/year=2026/month=09/day=12/0.json"
        );
    }

    #[test]
    fn test_shared_key_known_answer() {
        // Independent Python (hmac/hashlib/base64) vector over the
        // StringToSign above with key b"0123456789abcdef"*2.
        let auth = shared_key_authorization(
            "mydeviceblobs",
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
            &string_to_sign(
                "mydeviceblobs",
                "telemetry",
                "telemetry/year=2026/month=09/day=12/0.json",
                17,
                "application/x-ndjson",
                "Sat, 12 Sep 2026 11:18:09 GMT",
            ),
        )
        .unwrap();
        assert_eq!(
            auth,
            "SharedKey mydeviceblobs:0YVfGfMhURBZYesEg/YGIHGaoYV5SgkpNnfmDQ91AZg="
        );
    }

    #[test]
    fn test_blob_path_template_resolution() {
        let config = test_config();
        // 2026-09-12T11:18:09.123Z.
        let path = config.resolve_path(0, 1_789_211_889_123).unwrap();
        assert_eq!(path, "telemetry/year=2026/month=09/day=12/hour=11/0.json");
        let next = config.resolve_path(41, 0).unwrap();
        assert_eq!(next, "telemetry/year=1970/month=01/day=01/hour=00/41.json");

        // Leading slashes are rejected (paths stay relative).
        let mut absolute = test_config();
        absolute.blob_path_template = "/abs/${batch_id}.json".to_string();
        assert!(absolute.resolve_path(0, 0).is_err());
    }

    #[test]
    fn test_sas_url_query_preservation() {
        let mut config = test_config();
        config.auth = AzureBlobAuth::SasToken {
            sas_token: "?sv=2021-08-06&sr=c&sig=abc%2Fdef".to_string(),
        };
        assert_eq!(
            config.blob_url("telemetry/0.json"),
            "https://mydeviceblobs.blob.core.windows.net/telemetry/telemetry/0.json\
             ?sv=2021-08-06&sr=c&sig=abc%2Fdef"
        );
        // Leading `?` is optional.
        config.auth = AzureBlobAuth::SasToken {
            sas_token: "sv=2021-08-06".to_string(),
        };
        assert!(config
            .blob_url("telemetry/0.json")
            .ends_with("?sv=2021-08-06"));

        // SharedKey/Bearer URLs carry no query string.
        assert_eq!(
            test_config().blob_url("telemetry/0.json"),
            "https://mydeviceblobs.blob.core.windows.net/telemetry/telemetry/0.json"
        );

        // Custom endpoint (Azurite) wins over the default.
        config.endpoint = Some("http://127.0.0.1:10000/devstoreaccount1".to_string());
        assert!(config
            .blob_url("telemetry/0.json")
            .starts_with("http://127.0.0.1:10000/devstoreaccount1/telemetry/telemetry/0.json"));
    }

    #[test]
    fn test_gzip_round_trip_and_row_json() {
        let raw = b"{\"topic\":\"t\"}\n";
        let gz = gzip_bytes(raw).unwrap();
        assert_eq!(&gz[..2], &[0x1f, 0x8b], "gzip magic");
        let mut decoder = GzDecoder::new(&gz[..]);
        let mut back = Vec::new();
        decoder.read_to_end(&mut back).unwrap();
        assert_eq!(back, raw);

        let row = render_row(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from(r#"{"v":1}"#),
            QoS::AtMostOnce,
            1_789_211_889_123,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&row.line).unwrap();
        assert_eq!(value["topic"], "sensors/t1");
        assert_eq!(value["payload"], serde_json::json!({"v": 1}));
        assert_eq!(value["timestamp"], "2026-09-12T11:18:09.123Z");
    }

    #[test]
    fn test_status_classification() {
        assert_eq!(classify_blob_status(201, b""), AzureBlobOutcome::Success);
        assert_eq!(classify_blob_status(200, b""), AzureBlobOutcome::Success);
        // Terminal XML codes win over any status.
        assert_eq!(
            classify_blob_status(
                500,
                br#"<?xml version="1.0"?><Error><Code>AuthenticationFailed</Code></Error>"#
            ),
            AzureBlobOutcome::Terminal
        );
        assert_eq!(
            classify_blob_status(404, br#"<Error><Code>ContainerNotFound</Code></Error>"#),
            AzureBlobOutcome::Terminal
        );
        assert_eq!(classify_blob_status(403, b""), AzureBlobOutcome::Terminal);
        assert_eq!(classify_blob_status(404, b""), AzureBlobOutcome::Terminal);
        assert_eq!(classify_blob_status(400, b""), AzureBlobOutcome::Terminal);
        // Retryable codes and statuses.
        assert_eq!(
            classify_blob_status(500, br#"<Error><Code>ServerBusy</Code></Error>"#),
            AzureBlobOutcome::Retryable
        );
        assert_eq!(
            classify_blob_status(503, br#"<Error><Code>ServiceUnavailable</Code></Error>"#),
            AzureBlobOutcome::Retryable
        );
        assert_eq!(classify_blob_status(503, b""), AzureBlobOutcome::Retryable);
        assert_eq!(classify_blob_status(500, b""), AzureBlobOutcome::Retryable);
        assert_eq!(classify_blob_status(429, b""), AzureBlobOutcome::Retryable);
    }

    #[tokio::test]
    async fn test_flush_flow_and_backoff() {
        let transport = Arc::new(MockAzureBlobTransport::new());
        let mut config = test_config();
        config.max_records_per_blob = Some(2);
        let sink = AzureBlobSink::new(config, transport.clone()).unwrap();

        let topic = Topic::new("sensors/t1").unwrap();
        sink.send(&topic, &Bytes::from(r#"{"v":1}"#), QoS::AtMostOnce)
            .await
            .unwrap();
        assert_eq!(sink.buffered_rows(), 1);
        sink.flush().await.unwrap();
        let puts = transport.puts();
        assert_eq!(puts.len(), 1);
        assert!(puts[0].path.ends_with("/0.json"), "got {:?}", puts[0].path);
        assert_eq!(puts[0].content_type, "application/x-ndjson");
        assert_eq!(puts[0].content_encoding, None);
        assert_eq!(sink.sent_blobs(), 1);
        assert_eq!(sink.sent_records(), 1);
        // SharedKey proof ran: mock saw date + SharedKey authorization.
        assert!(transport
            .last_date
            .lock()
            .as_deref()
            .unwrap()
            .ends_with("GMT"));
        assert!(transport
            .last_authorization
            .lock()
            .as_deref()
            .unwrap()
            .starts_with("SharedKey mydeviceblobs:"));

        // Scripted 503 retries in-loop... here: backoff engages.
        transport.fail_next(503, "<Error><Code>ServiceUnavailable</Code></Error>");
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("503 must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(sink.buffered_rows(), 1);
        assert_eq!(sink.sent_blobs(), 1);

        // Scripted 403 is terminal: dispatch error, rows restored.
        // (Backoff from the 503 must expire first; drive a fresh sink.)
        let transport = Arc::new(MockAzureBlobTransport::new());
        transport.fail_next(403, "<Error><Code>AuthenticationFailed</Code></Error>");
        let mut config = test_config();
        config.max_records_per_blob = Some(10);
        let sink = AzureBlobSink::new(config, transport.clone()).unwrap();
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("403 must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
    }

    #[tokio::test]
    async fn test_loopback_put_headers() {
        use axum::{http::StatusCode, routing::put, Router};

        #[derive(Debug, Default)]
        struct Captured {
            inner: parking_lot::Mutex<Vec<CapturedPut>>,
        }
        #[derive(Debug)]
        struct CapturedPut {
            path: String,
            blob_type: Option<String>,
            version: Option<String>,
            content_type: Option<String>,
            auth: Option<String>,
            body: Vec<u8>,
        }

        let captured = Arc::new(Captured::default());
        let app = Router::new().fallback(put({
            let captured = captured.clone();
            move |uri: axum::http::Uri, headers: axum::http::HeaderMap, body: Bytes| {
                let captured = captured.clone();
                async move {
                    let get = |name: &str| {
                        headers
                            .get(name)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string)
                    };
                    captured.inner.lock().push(CapturedPut {
                        path: uri.path().to_string(),
                        blob_type: get("x-ms-blob-type"),
                        version: get("x-ms-version"),
                        content_type: get("content-type"),
                        auth: get("authorization"),
                        body: body.to_vec(),
                    });
                    StatusCode::CREATED
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

        let mut config = test_config();
        config.endpoint = Some(format!("http://127.0.0.1:{port}"));
        config.max_records_per_blob = Some(1);
        let transport =
            Arc::new(HttpAzureBlobTransport::new(&config, reqwest::Client::new()).unwrap());
        let sink = AzureBlobSink::new(config, transport).unwrap();
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from(r#"{"v":9}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.sent_blobs(), 1);

        let puts = captured.inner.lock();
        assert_eq!(puts.len(), 1);
        assert!(puts[0].path.starts_with("/telemetry/telemetry/"));
        assert_eq!(puts[0].blob_type.as_deref(), Some("BlockBlob"));
        assert_eq!(puts[0].version.as_deref(), Some("2021-08-06"));
        assert_eq!(
            puts[0].content_type.as_deref(),
            Some("application/x-ndjson")
        );
        assert!(puts[0]
            .auth
            .as_deref()
            .unwrap()
            .starts_with("SharedKey mydeviceblobs:"));
        let row: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&puts[0].body).unwrap().trim_end()).unwrap();
        assert_eq!(row["payload"], serde_json::json!({"v": 9}));
        server.abort();
    }
}
