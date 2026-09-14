//! Datalayers industrial time-series sink (INDRA-177).
//!
//! Industrial edge-to-cloud time-series database sink with batched records,
//! Bearer token authentication, tag/field segregation, microsecond timestamps,
//! and HTTP status code classification.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use parking_lot::Mutex;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{now_millis, BackoffState, BatchQueue, Connector, ConnectorError, Result, Sink};

fn default_batch_size_500() -> Option<usize> {
    Some(500)
}

/// Configuration for the Datalayers industrial time-series sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatalayersConfig {
    /// Datalayers REST endpoint (e.g. `http://datalayers-node:8360`).
    pub endpoint: String,
    /// Target database name.
    pub database: String,
    /// Target measurement/table name.
    pub table: String,
    /// Optional Bearer token for authorization.
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Optional field source for timestamp (defaults to current wall-clock).
    #[serde(default)]
    pub timestamp_field: Option<String>,
    /// Vector of column names to treat as indexed tags.
    #[serde(default)]
    pub tag_columns: Vec<String>,
    /// Vector of column names to treat as measurement fields.
    #[serde(default)]
    pub field_columns: Vec<String>,
    /// Batch flush size (unbounded scale, default 500).
    #[serde(default = "default_batch_size_500")]
    pub batch_size: Option<usize>,
    /// In-memory queue buffer capacity (`None` = unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Network request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl DatalayersConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "datalayers endpoint cannot be empty".into(),
            ));
        }
        if self.database.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "datalayers database cannot be empty".into(),
            ));
        }
        if self.table.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "datalayers table cannot be empty".into(),
            ));
        }
        Ok(())
    }

    pub fn auth_header_value(&self) -> Option<String> {
        self.auth_token
            .as_ref()
            .map(|t| format!("Bearer {}", t.trim()))
    }
}

/// A single time-series record in Datalayers payload format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatalayersRecord {
    /// Timestamp in microseconds since Unix epoch.
    pub time: i64,
    /// Indexed string metadata tags.
    pub tags: HashMap<String, String>,
    /// Measurement numeric/string/bool metric fields.
    pub fields: HashMap<String, serde_json::Value>,
}

/// Request body sent to Datalayers `POST /api/v1/write?db={database}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatalayersWriteRequest {
    pub table: String,
    pub records: Vec<DatalayersRecord>,
}

/// Extract microseconds timestamp from payload or fallback to wall-clock.
pub fn extract_microsecond_timestamp(json_val: &serde_json::Value, field_opt: Option<&str>) -> i64 {
    if let Some(field) = field_opt {
        if let Some(ts_val) = json_val.get(field) {
            if let Some(i) = ts_val.as_i64() {
                // If seconds, scale to micros; if millis, scale to micros; if micros, keep
                if i < 10_000_000_000 {
                    return i * 1_000_000;
                } else if i < 10_000_000_000_000 {
                    return i * 1_000;
                } else {
                    return i;
                }
            }
        }
    }
    now_millis() * 1000
}

/// Extract single Datalayers record from MQTT event.
pub fn extract_datalayers_record(
    payload: &[u8],
    topic: &str,
    config: &DatalayersConfig,
) -> Result<DatalayersRecord> {
    let json_val: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| ConnectorError::Dispatch(format!("invalid JSON payload: {e}")))?;

    let time = extract_microsecond_timestamp(&json_val, config.timestamp_field.as_deref());

    let mut tags = HashMap::new();
    let mut fields = HashMap::new();

    if let serde_json::Value::Object(map) = &json_val {
        let empty_map = serde_json::Map::new();
        let payload_map = map
            .get("payload")
            .and_then(|p| p.as_object())
            .unwrap_or(&empty_map);

        for (k, v) in map {
            if k == "payload" {
                continue;
            }
            if config.tag_columns.contains(k) {
                let tag_str = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                tags.insert(k.clone(), tag_str);
            } else if config.field_columns.is_empty() || config.field_columns.contains(k) {
                fields.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in payload_map {
            if config.tag_columns.contains(k) {
                let tag_str = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                tags.insert(k.clone(), tag_str);
            } else if config.field_columns.is_empty() || config.field_columns.contains(k) {
                fields.insert(k.clone(), v.clone());
            }
        }
    } else {
        fields.insert("val".to_string(), json_val);
    }

    if tags.is_empty() {
        tags.insert("topic".to_string(), topic.to_string());
    }

    Ok(DatalayersRecord { time, tags, fields })
}

/// Transport abstraction for Datalayers.
#[async_trait]
pub trait DatalayersTransport: Send + Sync {
    async fn write_batch(&self, request: &DatalayersWriteRequest) -> Result<()>;
}

/// Production HTTP transport for Datalayers.
pub struct HttpDatalayersTransport {
    client: reqwest::Client,
    write_url: String,
    auth_header: Option<String>,
}

impl HttpDatalayersTransport {
    pub fn new(config: &DatalayersConfig) -> Self {
        let base = config.endpoint.trim_end_matches('/');
        let write_url = format!("{base}/api/v1/write?db={}", config.database);
        let auth_header = config.auth_header_value();

        Self {
            client: reqwest::Client::builder()
                .timeout(config.timeout())
                .build()
                .unwrap_or_default(),
            write_url,
            auth_header,
        }
    }
}

#[async_trait]
impl DatalayersTransport for HttpDatalayersTransport {
    async fn write_batch(&self, request: &DatalayersWriteRequest) -> Result<()> {
        let mut req = self
            .client
            .post(&self.write_url)
            .header(CONTENT_TYPE, "application/json")
            .json(request);

        if let Some(ref auth) = self.auth_header {
            req = req.header(AUTHORIZATION, auth);
        }

        let resp = req.send().await.map_err(|e| {
            ConnectorError::Connection(format!("datalayers http request failed: {e}"))
        })?;

        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            Ok(())
        } else if status.as_u16() == 429 || status.as_u16() >= 500 {
            Err(ConnectorError::Connection(format!(
                "datalayers transient error {status}: {body_text}"
            )))
        } else {
            Err(ConnectorError::Dispatch(format!(
                "datalayers terminal error {status}: {body_text}"
            )))
        }
    }
}

/// Mock transport for testing Datalayers sink.
pub struct MockDatalayersTransport {
    pub captured_requests: Mutex<Vec<DatalayersWriteRequest>>,
    pub fail_count: Mutex<usize>,
    pub is_terminal: Mutex<bool>,
}

impl MockDatalayersTransport {
    pub fn new() -> Self {
        Self {
            captured_requests: Mutex::new(Vec::new()),
            fail_count: Mutex::new(0),
            is_terminal: Mutex::new(false),
        }
    }

    pub fn with_transient_failures(failures: usize) -> Self {
        Self {
            captured_requests: Mutex::new(Vec::new()),
            fail_count: Mutex::new(failures),
            is_terminal: Mutex::new(false),
        }
    }

    pub fn with_terminal_failure() -> Self {
        Self {
            captured_requests: Mutex::new(Vec::new()),
            fail_count: Mutex::new(1),
            is_terminal: Mutex::new(true),
        }
    }
}

impl Default for MockDatalayersTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DatalayersTransport for MockDatalayersTransport {
    async fn write_batch(&self, request: &DatalayersWriteRequest) -> Result<()> {
        self.captured_requests.lock().push(request.clone());

        let mut fails = self.fail_count.lock();
        if *fails > 0 {
            *fails -= 1;
            if *self.is_terminal.lock() {
                return Err(ConnectorError::Dispatch(
                    "mock datalayers 400 bad request".into(),
                ));
            } else {
                return Err(ConnectorError::Connection(
                    "mock datalayers 503 service unavailable".into(),
                ));
            }
        }

        Ok(())
    }
}

/// Datalayers industrial time-series sink.
pub struct DatalayersSink {
    config: DatalayersConfig,
    transport: Arc<dyn DatalayersTransport>,
    queue: Mutex<BatchQueue<DatalayersRecord>>,
    backoff: Mutex<BackoffState>,
    sent: AtomicU64,
}

impl DatalayersSink {
    pub fn new(config: DatalayersConfig, transport: Arc<dyn DatalayersTransport>) -> Result<Self> {
        config.validate()?;
        let batch_size = config.batch_size.unwrap_or(500).max(1);
        Ok(Self {
            config,
            transport,
            queue: Mutex::new(BatchQueue::new(batch_size, Duration::from_millis(50))),
            backoff: Mutex::new(BackoffState::default()),
            sent: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &DatalayersConfig {
        &self.config
    }

    pub fn sent_count(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub async fn flush(&self) -> Result<()> {
        let (records, oldest) = {
            let mut q = self.queue.lock();
            if q.is_empty() {
                return Ok(());
            }
            q.take_batch()
        };

        if records.is_empty() {
            return Ok(());
        }

        self.backoff.lock().check()?;

        let request = DatalayersWriteRequest {
            table: self.config.table.clone(),
            records,
        };

        match self.transport.write_batch(&request).await {
            Ok(_) => {
                self.backoff.lock().success();
                self.sent
                    .fetch_add(request.records.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.backoff.lock().failure();
                self.queue.lock().restore(request.records, oldest);
                Err(e)
            }
        }
    }
}

#[async_trait]
impl Sink for DatalayersSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<()> {
        let rec = extract_datalayers_record(payload, topic.as_str(), &self.config)?;
        let should_flush = {
            let mut q = self.queue.lock();
            q.push(rec)
        };

        if should_flush {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "datalayers"
    }
}

/// Addressable registered connector for Datalayers.
pub struct DatalayersConnector {
    id: String,
    sink: Arc<DatalayersSink>,
}

impl DatalayersConnector {
    pub fn new(id: impl Into<String>, sink: Arc<DatalayersSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }

    pub fn sink(&self) -> Arc<DatalayersSink> {
        self.sink.clone()
    }
}

impl Connector for DatalayersConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        "datalayers"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> DatalayersConfig {
        DatalayersConfig {
            endpoint: "http://datalayers-node:8360".to_string(),
            database: "factory_db".to_string(),
            table: "machinery".to_string(),
            auth_token: Some("dl-secret-token-12345".to_string()),
            timestamp_field: Some("custom_ts".to_string()),
            tag_columns: vec!["line".to_string(), "machine".to_string()],
            field_columns: vec!["pressure".to_string(), "temperature".to_string()],
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn test_config_validation_and_auth_header() {
        let cfg = sample_config();
        assert!(cfg.validate().is_ok());
        assert_eq!(
            cfg.auth_header_value(),
            Some("Bearer dl-secret-token-12345".to_string())
        );
    }

    #[test]
    fn test_timestamp_microsecond_scaling() {
        // Seconds
        let sec_val = serde_json::json!({"ts": 1726000000});
        assert_eq!(
            extract_microsecond_timestamp(&sec_val, Some("ts")),
            1726000000000000
        );

        // Millis
        let ms_val = serde_json::json!({"ts": 1726000000123i64});
        assert_eq!(
            extract_microsecond_timestamp(&ms_val, Some("ts")),
            1726000000123000
        );

        // Micros
        let us_val = serde_json::json!({"ts": 1726000000123456i64});
        assert_eq!(
            extract_microsecond_timestamp(&us_val, Some("ts")),
            1726000000123456
        );
    }

    #[test]
    fn test_record_extraction_with_tag_field_segregation() {
        let cfg = sample_config();
        let payload = br#"{
            "custom_ts": 1726000000,
            "line": "A1",
            "machine": "press_03",
            "pressure": 150.2,
            "temperature": 75.8,
            "unmapped_col": "ignore_me"
        }"#;

        let rec = extract_datalayers_record(payload, "factory/p1", &cfg).expect("valid extraction");
        assert_eq!(rec.time, 1726000000000000);
        assert_eq!(rec.tags.get("line").unwrap(), "A1");
        assert_eq!(rec.tags.get("machine").unwrap(), "press_03");
        assert_eq!(
            rec.fields.get("pressure").unwrap(),
            &serde_json::json!(150.2)
        );
        assert_eq!(
            rec.fields.get("temperature").unwrap(),
            &serde_json::json!(75.8)
        );
        assert!(!rec.fields.contains_key("unmapped_col"));
    }

    #[test]
    fn test_write_request_serialization() {
        let mut tags = HashMap::new();
        tags.insert("station".to_string(), "st-4".to_string());
        let mut fields = HashMap::new();
        fields.insert("rpm".to_string(), serde_json::json!(3400));

        let req = DatalayersWriteRequest {
            table: "motors".to_string(),
            records: vec![DatalayersRecord {
                time: 1726000000000000,
                tags,
                fields,
            }],
        };

        let json_str = serde_json::to_string(&req).expect("valid json");
        assert!(json_str.contains("\"table\":\"motors\""));
        assert!(json_str.contains("\"station\":\"st-4\""));
        assert!(json_str.contains("\"rpm\":3400"));
    }

    #[tokio::test]
    async fn test_datalayers_sink_loopback_success() {
        let cfg = sample_config();
        let transport = Arc::new(MockDatalayersTransport::new());
        let sink = DatalayersSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("machinery/lineA").unwrap();
        let payload = Bytes::from_static(
            br#"{
            "line": "L2",
            "machine": "cnc_01",
            "pressure": 82.5,
            "temperature": 60.1
        }"#,
        );

        sink.send(&topic, &payload, QoS::AtLeastOnce)
            .await
            .expect("send succeeds");

        let reqs = transport.captured_requests.lock();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].table, "machinery");
        assert_eq!(reqs[0].records.len(), 1);
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_datalayers_sink_transient_retry_and_terminal_error() {
        let cfg = sample_config();
        // 1 transient failure then success
        let transport = Arc::new(MockDatalayersTransport::with_transient_failures(1));
        let sink = DatalayersSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("machinery/lineA").unwrap();
        let payload = Bytes::from_static(br#"{"pressure": 10.0}"#);

        let res = sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(res.is_err());

        // Reset backoff and retry flush
        *sink.backoff.lock() = BackoffState::default();
        sink.flush().await.expect("retry flush succeeds");
        assert_eq!(sink.sent_count(), 1);

        // Terminal error check
        let term_transport = Arc::new(MockDatalayersTransport::with_terminal_failure());
        let term_sink = DatalayersSink::new(sample_config(), term_transport).expect("valid sink");
        let term_res = term_sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(term_res.is_err());
        assert!(matches!(
            term_res.err().unwrap(),
            ConnectorError::Dispatch(_)
        ));
    }
}
