//! Microsoft SQL Server / Azure SQL sink (INDRA-165).
//!
//! Buffers MQTT events as 5-column rows (time, topic, client id, QoS,
//! payload JSON) and writes them through the TDS protocol with
//! `sp_executesql` RPC batches: every value rides typed RPC
//! parameters (`DATETIMEOFFSET`, `NVARCHAR`, `BIGINT`), never string
//! interpolation. Deadlock error 1205 and transport disconnects retry
//! with backoff; other server errors are terminal.
//!
//! Wire framing is a clean-room TDS subset: packet headers, PRELOGIN
//! negotiation (aborts loudly when the server *requires* TLS —
//! terminate TLS in a sidecar or enable it on the edge), LOGIN7 with
//! obscured SQL password, RPC `sp_executesql` batches, and DONE/ERROR
//! token parsing.

#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// Days since 0001-01-01 (proleptic Gregorian) for a civil date
/// (Howard Hinnant's days-from-civil).
pub fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let adjusted_year = if month <= 2 { year - 1 } else { year };
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let yoe = (adjusted_year - era * 400) as i64;
    let mp = (month as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146_097 + doe - 719_468
}

/// TDS password obfuscation: per byte, swap nibbles then XOR 0xA5.
pub fn obscure_password(password: &str) -> Vec<u8> {
    let mut utf16 = Vec::with_capacity(password.len() * 2);
    for unit in password.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    utf16
        .iter()
        .map(|byte| ((byte & 0x0F) << 4 | (byte & 0xF0) >> 4) ^ 0xA5)
        .collect()
}

fn encode_ucs2(text: &str, out: &mut Vec<u8>) {
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
}

/// MSSQL authentication. `ActiveDirectoryPassword` currently
/// authenticates as SQL password credentials (no FEDAUTH token flow);
/// use a sidecar or managed identity proxy for true AAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum MssqlAuth {
    #[serde(alias = "sql_password")]
    SqlPassword { username: String, password: String },
    #[default]
    Integrated,
    #[serde(alias = "ad_password")]
    ActiveDirectoryPassword { username: String, password: String },
}

/// Query shape: fixed 5-column insert or custom UPSERT template with
/// `$1..$5` markers (time, topic, client id, QoS, payload JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "mode")]
pub enum MssqlQueryMode {
    #[default]
    InsertJson,
    CustomUpsert {
        sql_template: String,
    },
}

fn default_port() -> Option<u16> {
    None
}

fn default_batch_size() -> Option<usize> {
    Some(200)
}

fn default_batch_bytes() -> Option<usize> {
    Some(2_097_152)
}

fn default_linger_ms() -> Option<u64> {
    Some(20)
}

fn default_max_retries() -> Option<usize> {
    Some(3)
}

fn default_initial_backoff_ms() -> Option<u64> {
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    Some(2_500)
}

/// MSSQL sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MssqlSinkConfig {
    /// Server hostname or IP.
    pub host: String,
    /// TCP port (default 1433).
    #[serde(default = "default_port")]
    pub port: Option<u16>,
    /// Target database name.
    pub database: String,
    /// Table template (`${topic}` supported, sanitized).
    pub table_template: String,
    /// Authentication (default integrated).
    #[serde(default)]
    pub auth: MssqlAuth,
    /// Query shape (default 5-column insert).
    #[serde(default)]
    pub query_mode: MssqlQueryMode,
    /// Accept self-signed/untrusted server certificates (default true
    /// for edge environments; only governs TLS deployments).
    #[serde(default = "default_true")]
    pub trust_server_certificate: bool,
    /// Rows per batch (default 200).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 2 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 20).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on deadlocks/disconnects (default 3, `None` unbounded).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 2500).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Network connect/query timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

fn default_true() -> bool {
    true
}

impl MssqlSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.host.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "mssql host must not be empty".to_string(),
            ));
        }
        if self.port == Some(0) {
            return Err(ConnectorError::Dispatch(
                "mssql port must be 1..=65535".to_string(),
            ));
        }
        if self.database.trim().is_empty() || self.database.contains([';', '\0']) {
            return Err(ConnectorError::Dispatch(format!(
                "mssql database must be a bare name: {:?}",
                self.database
            )));
        }
        if self.table_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "mssql table_template must not be empty".to_string(),
            ));
        }
        self.resolve_table("dummy/topic", QoS::AtMostOnce, 0)?;
        match &self.auth {
            MssqlAuth::SqlPassword { username, .. }
            | MssqlAuth::ActiveDirectoryPassword { username, .. } => {
                if username.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "mssql username must not be empty".to_string(),
                    ));
                }
            }
            MssqlAuth::Integrated => {}
        }
        if let MssqlQueryMode::CustomUpsert { sql_template } = &self.query_mode {
            let mut referenced = super::postgres::referenced_params(sql_template)?;
            referenced.sort_unstable();
            referenced.dedup();
            if referenced.is_empty() || referenced.iter().any(|n| *n == 0 || *n > 5) {
                return Err(ConnectorError::Dispatch(format!(
                    "mssql sql_template must reference $1..$5, got {referenced:?}"
                )));
            }
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "mssql batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "mssql batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn port_or_default(&self) -> u16 {
        self.port.unwrap_or(1433)
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

    /// Resolve + sanitize the destination table: template variables
    /// first, then anything outside `[A-Za-z0-9_.]` becomes `_`
    /// (dots preserved for `schema.table`).
    pub fn resolve_table(&self, topic: &str, qos: QoS, millis: i64) -> Result<String> {
        let vars = [
            ("topic".to_string(), topic.to_string()),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ];
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
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
        if sanitized.trim().is_empty()
            || sanitized.starts_with('.')
            || sanitized.contains("..")
            || sanitized.contains([';', '\0'])
        {
            return Err(ConnectorError::Dispatch(format!(
                "mssql table resolved invalid: {sanitized:?}"
            )));
        }
        Ok(sanitized)
    }
}

// ---------------------------------------------------------------------------
// TDS wire subset.
// ---------------------------------------------------------------------------

/// TDS packet types used here.
mod packet {
    pub const PRELOGIN: u8 = 0x12;
    pub const LOGIN: u8 = 0x10;
    pub const RPC: u8 = 0x03;
    pub const REPLY: u8 = 0x04;
}

/// Wrap a payload in an 8-byte TDS packet header (EOM set).
fn tds_packet(packet_type: u8, packet_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.push(packet_type);
    out.push(0x01); // status: EOM
    let length = (8 + payload.len()) as u16;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00]); // SPID
    out.push(packet_id);
    out.push(0x00); // window
    out.extend_from_slice(payload);
    out
}

/// Build a PRELOGIN request offering no encryption (edge default).
/// Token offsets measure from the start of the message: 5 option
/// tokens (25 bytes) plus the terminator put the data section at 26.
fn encode_prelogin() -> Vec<u8> {
    let version = [0x0Du8, 0x00, 0x00, 0x00, 0x00, 0x00]; // 13.0.0.0
    let encryption = [0x02u8]; // ENCRYPT_NOT_SUP
    let threadid = [0x00u8, 0x00, 0x00, 0x00];
    let mars = [0x00u8]; // off
    let mut out = Vec::new();
    let mut offset = 26u16;
    let mut token = |id: u8, data: &[u8], offset: &mut u16| {
        out.push(id);
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        *offset += data.len() as u16;
    };
    token(0x00, &version, &mut offset);
    token(0x01, &encryption, &mut offset);
    token(0x02, &[], &mut offset);
    token(0x03, &threadid, &mut offset);
    token(0x04, &mars, &mut offset);
    out.push(0xFF); // TERMINATOR
    out.extend_from_slice(&version);
    out.extend_from_slice(&encryption);
    out.extend_from_slice(&threadid);
    out.extend_from_slice(&mars);
    out
}

/// Parse a PRELOGIN response into the server ENCRYPTION byte.
fn decode_prelogin_encryption(payload: &[u8]) -> Result<u8> {
    let mut index = 0;
    let mut encryption_offset = None;
    let mut encryption_len = 0usize;
    while index < payload.len() {
        let token = payload[index];
        index += 1;
        if token == 0xFF {
            break;
        }
        if payload.len() < index + 4 {
            return Err(ConnectorError::Connection(
                "mssql truncated prelogin token".to_string(),
            ));
        }
        let offset = u16::from_be_bytes([payload[index], payload[index + 1]]) as usize;
        let length = u16::from_be_bytes([payload[index + 2], payload[index + 3]]) as usize;
        if token == 0x01 {
            encryption_offset = Some(offset);
            encryption_len = length;
        }
        index += 4;
    }
    let offset = encryption_offset
        .ok_or_else(|| ConnectorError::Connection("mssql prelogin lacks ENCRYPTION".to_string()))?;
    if encryption_len != 1 || payload.len() <= offset {
        return Err(ConnectorError::Connection(
            "mssql bad prelogin ENCRYPTION".to_string(),
        ));
    }
    Ok(payload[offset])
}

/// Build a LOGIN7 packet (SQL password obscured; integrated sends no
/// credentials). Variable strings lay out sequentially after the
/// fixed header; the offset table is patched deterministically.
fn encode_login(
    hostname: &str,
    username: Option<&str>,
    password: Option<&str>,
    app_name: &str,
    server_name: &str,
    database: &str,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes()); // total length (patched)
    body.extend_from_slice(&0x7400_0004u32.to_le_bytes()); // TDS 2012
    body.extend_from_slice(&4096u32.to_le_bytes()); // packet size
    body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // client version
    body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // PID
    body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // connection id
    body.push(0xE0); // option flags 1 (conventional)
    body.push(0x00); // option flags 2
    body.push(0x00); // type flags
    body.push(0x00); // option flags 3
    body.extend_from_slice(&[0x00; 4]); // client timezone
    body.extend_from_slice(&[0x00; 4]); // LCID
                                        // Slots: hostname, username, password, app, server, ext, int, lang, db.
    let text = |value: &str| {
        let mut bytes = Vec::new();
        encode_ucs2(value, &mut bytes);
        (value.encode_utf16().count(), bytes)
    };
    let ordered: Vec<(usize, Vec<u8>)> = vec![
        text(hostname),
        text(username.unwrap_or_default()),
        (
            password.map(|p| p.encode_utf16().count()).unwrap_or(0),
            password.map(obscure_password).unwrap_or_default(),
        ),
        text(app_name),
        text(server_name),
        text(""),
        text(""),
        text(""),
        text(database),
    ];
    let table_start = body.len();
    body.extend_from_slice(&[0u8; 9 * 2 * 2]);
    // Offsets point past the fixed header + table, laid sequentially.
    let mut cursor = table_start + 9 * 2 * 2;
    for (slot, (chars, bytes)) in ordered.iter().enumerate() {
        body[table_start + slot * 4..table_start + slot * 4 + 2]
            .copy_from_slice(&(cursor as u16).to_le_bytes());
        body[table_start + slot * 4 + 2..table_start + slot * 4 + 4]
            .copy_from_slice(&(*chars as u16).to_le_bytes());
        cursor += bytes.len();
    }
    for (_, bytes) in &ordered {
        body.extend_from_slice(bytes);
    }
    let total = body.len() as u32;
    body[..4].copy_from_slice(&total.to_le_bytes());
    body
}

/// DATETIMEOFFSET bytes for millis (scale 7: 5-byte 100ns time LE +
/// 3-byte days-since-0001-01-01 LE + 2-byte UTC offset LE).
pub fn encode_datetimeoffset(millis: i64) -> [u8; 10] {
    let millis = millis.max(0);
    let days = millis.div_euclid(86_400_000);
    let day_ms = millis.rem_euclid(86_400_000) as u64;
    let ticks = day_ms * 10_000; // 100ns units
    let date_days = (days + 719_162) as u64; // since 0001-01-01
    let mut out = [0u8; 10];
    for (index, byte) in ticks.to_le_bytes().iter().take(5).enumerate() {
        out[index] = *byte;
    }
    for (index, byte) in date_days.to_le_bytes().iter().take(3).enumerate() {
        out[5 + index] = *byte;
    }
    out
}

/// One RPC parameter value.
#[derive(Debug, Clone)]
enum RpcParam {
    NVarChar(String),
    BigInt(i64),
    DateTimeOffset(i64),
}

/// Render one RPC parameter (name, declaration fragment, bytes).
fn encode_rpc_param(name: &str, param: &RpcParam, out: &mut Vec<u8>) {
    out.push(name.encode_utf16().count() as u8);
    encode_ucs2(&format!("@{name}"), out);
    out.push(0x00); // input
    match param {
        RpcParam::NVarChar(text) => {
            out.push(0xE7); // NVARCHAR
            let chars = text.encode_utf16().count().min(4000) as u16;
            out.extend_from_slice(&chars.to_be_bytes());
            out.extend_from_slice(&[0x09, 0x04, 0xD0, 0x00, 0x34]); // collation
            let mut bytes = Vec::new();
            encode_ucs2(text, &mut bytes);
            let byte_len = bytes.len().min(8000) as u16;
            out.extend_from_slice(&byte_len.to_be_bytes());
            out.extend_from_slice(&bytes[..byte_len as usize]);
        }
        RpcParam::BigInt(value) => {
            out.push(0x7F); // BIGINT
            out.push(8);
            out.extend_from_slice(&value.to_le_bytes());
        }
        RpcParam::DateTimeOffset(millis) => {
            out.push(0x6F); // DATETIMEOFFSETN
            out.push(7); // scale
            out.push(10); // length
            out.extend_from_slice(&encode_datetimeoffset(*millis));
        }
    }
}

fn rpc_declaration(name: &str, param: &RpcParam) -> String {
    match param {
        RpcParam::NVarChar(_) => format!("@{name} nvarchar(4000)"),
        RpcParam::BigInt(_) => format!("@{name} bigint"),
        RpcParam::DateTimeOffset(_) => format!("@{name} datetimeoffset"),
    }
}

/// Build an `sp_executesql` RPC packet for one 5-column row.
/// Returns (packet bytes, statement text) for assertions.
pub fn encode_executesql(
    statement: &str,
    time_ms: i64,
    topic: &str,
    client_id: &str,
    qos: u8,
    payload_json: &str,
) -> (Vec<u8>, String) {
    // $n markers become @pn parameters in declaration order.
    let mut params: Vec<(&str, RpcParam)> = vec![
        ("p1", RpcParam::DateTimeOffset(time_ms)),
        ("p2", RpcParam::NVarChar(topic.to_string())),
        ("p3", RpcParam::NVarChar(client_id.to_string())),
        ("p4", RpcParam::BigInt(i64::from(qos))),
        ("p5", RpcParam::NVarChar(payload_json.to_string())),
    ];
    let mut sql = statement.to_string();
    for (name, _) in &params {
        let from = format!("${}", &name[1..]);
        sql = sql.replace(&from, &format!("@{name}"));
    }
    let declarations = params
        .iter()
        .map(|(name, param)| rpc_declaration(name, param))
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes()); // total length (patched)
    body.extend_from_slice(&0u32.to_le_bytes()); // headers length = 0
                                                 // RPC by name: length-prefixed UCS-2 "sp_executesql".
    let proc_name = "sp_executesql";
    body.extend_from_slice(&(proc_name.encode_utf16().count() as u16).to_le_bytes());
    encode_ucs2(proc_name, &mut body);
    body.extend_from_slice(&0u16.to_le_bytes()); // options
                                                 // @stmt + @params + row params.
    let mut all: Vec<(&str, RpcParam)> = vec![
        ("stmt", RpcParam::NVarChar(sql.clone())),
        ("params", RpcParam::NVarChar(declarations)),
    ];
    all.append(&mut params);
    for (name, param) in &all {
        encode_rpc_param(name, param, &mut body);
    }
    let total = body.len() as u32;
    body[..4].copy_from_slice(&total.to_le_bytes());
    (tds_packet(packet::RPC, 1, &body), sql)
}

/// Reply token: DONE-family or ERROR detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TdsReply {
    Done,
    Error { number: i32, message: String },
}

/// Parse reply tokens until a DONE-family token with MORE clear or an
/// ERROR token. Returns the first terminal outcome.
pub fn parse_reply_tokens(mut cursor: &[u8]) -> Result<TdsReply> {
    loop {
        if cursor.is_empty() {
            return Err(ConnectorError::Connection(
                "mssql truncated reply".to_string(),
            ));
        }
        let token = cursor[0];
        cursor = &cursor[1..];
        match token {
            0xFD..=0xFF => {
                if cursor.len() < 12 {
                    return Err(ConnectorError::Connection(
                        "mssql truncated DONE".to_string(),
                    ));
                }
                let status = u16::from_le_bytes([cursor[0], cursor[1]]);
                if status & 0x01 == 0 {
                    return Ok(TdsReply::Done);
                }
                cursor = &cursor[12..];
            }
            0xAA => {
                if cursor.len() < 10 {
                    return Err(ConnectorError::Connection(
                        "mssql truncated ERROR".to_string(),
                    ));
                }
                let _length = u16::from_le_bytes([cursor[0], cursor[1]]);
                let number = i32::from_le_bytes([cursor[2], cursor[3], cursor[4], cursor[5]]);
                cursor = &cursor[8..];
                if cursor.len() < 2 {
                    return Err(ConnectorError::Connection(
                        "mssql truncated ERROR text".to_string(),
                    ));
                }
                let chars = u16::from_le_bytes([cursor[0], cursor[1]]) as usize;
                cursor = &cursor[2..];
                if cursor.len() < chars * 2 {
                    return Err(ConnectorError::Connection(
                        "mssql truncated ERROR message".to_string(),
                    ));
                }
                let units: Vec<u16> = cursor[..chars * 2]
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect();
                return Ok(TdsReply::Error {
                    number,
                    message: String::from_utf16_lossy(&units),
                });
            }
            0xAD => {
                // LOGINACK: version + program name; skip to DONE.
                if cursor.len() < 2 {
                    return Err(ConnectorError::Connection(
                        "mssql truncated LOGINACK".to_string(),
                    ));
                }
                let length = u16::from_le_bytes([cursor[0], cursor[1]]) as usize;
                if cursor.len() < 2 + length {
                    return Err(ConnectorError::Connection(
                        "mssql truncated LOGINACK body".to_string(),
                    ));
                }
                cursor = &cursor[2 + length..];
            }
            _ => {
                return Err(ConnectorError::Connection(format!(
                    "mssql unsupported reply token 0x{token:02x}"
                )));
            }
        }
    }
}

/// Read one TDS packet payload (strips the 8-byte header, requires
/// a REPLY packet).
async fn read_packet(stream: &mut tokio::net::TcpStream, timeout: Duration) -> Result<Vec<u8>> {
    let mut header = [0u8; 8];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| ConnectorError::Connection("mssql read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("mssql read failed: {e}")))?;
    if header[0] != packet::REPLY {
        return Err(ConnectorError::Connection(format!(
            "mssql expected REPLY packet, got 0x{:02x}",
            header[0]
        )));
    }
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    if !(8..=4 * 1024 * 1024).contains(&length) {
        return Err(ConnectorError::Connection(format!(
            "mssql bad packet length {length}"
        )));
    }
    let mut body = vec![0u8; length - 8];
    tokio::time::timeout(timeout, stream.read_exact(&mut body))
        .await
        .map_err(|_| ConnectorError::Connection("mssql read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("mssql read failed: {e}")))?;
    Ok(body)
}

// ---------------------------------------------------------------------------
// Config rows + transport.
// ---------------------------------------------------------------------------

/// One batch row: the five typed columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MssqlRowItem {
    pub time_ms: i64,
    pub topic: String,
    pub client_id: String,
    pub qos: u8,
    pub payload_json: String,
}

#[async_trait]
pub trait MssqlTransport: Send + Sync {
    async fn execute_batch(&self, table: &str, rows: Vec<MssqlRowItem>) -> Result<()>;
}

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockMssqlOutcome {
    Ok,
    /// Transport failure (reconnects + retries in-loop).
    ConnectionError(String),
    /// Server error number (1205 retries; others terminal).
    TdsError {
        number: i32,
        message: String,
    },
}

/// One captured batch call.
#[derive(Debug, Clone)]
pub struct CapturedMssqlBatch {
    pub table: String,
    pub rows: Vec<MssqlRowItem>,
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockMssqlTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockMssqlOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedMssqlBatch>>,
    calls: AtomicU64,
}

impl MockMssqlTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockMssqlOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedMssqlBatch> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl MssqlTransport for MockMssqlTransport {
    async fn execute_batch(&self, table: &str, rows: Vec<MssqlRowItem>) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedMssqlBatch {
            table: table.to_string(),
            rows: rows.clone(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockMssqlOutcome::Ok) => Ok(()),
            Some(MockMssqlOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockMssqlOutcome::TdsError { number, message }) => Err(match number {
                1205 => {
                    ConnectorError::Connection(format!("mock mssql deadlock {number}: {message}"))
                }
                _ => ConnectorError::Dispatch(format!("mock mssql error {number}: {message}")),
            }),
        }
    }
}

/// Native transport: PRELOGIN, LOGIN7, then `sp_executesql` RPCs.
pub struct NativeMssqlTransport {
    host: String,
    port: u16,
    database: String,
    username: Option<String>,
    password: Option<String>,
    query_mode: MssqlQueryMode,
    stream: tokio::sync::Mutex<Option<tokio::net::TcpStream>>,
    packet_id: AtomicU64,
    timeout: Duration,
}

impl NativeMssqlTransport {
    pub fn new(config: &MssqlSinkConfig) -> Result<Self> {
        config.validate()?;
        let (username, password) = match &config.auth {
            MssqlAuth::SqlPassword { username, password }
            | MssqlAuth::ActiveDirectoryPassword { username, password } => {
                (Some(username.clone()), Some(password.clone()))
            }
            MssqlAuth::Integrated => (None, None),
        };
        Ok(Self {
            host: config.host.clone(),
            port: config.port_or_default(),
            database: config.database.clone(),
            username,
            password,
            query_mode: config.query_mode.clone(),
            stream: tokio::sync::Mutex::new(None),
            packet_id: AtomicU64::new(0),
            timeout: config.timeout(),
        })
    }

    /// Dial, negotiate PRELOGIN, and log in (idempotent once open).
    pub async fn connect(&self) -> Result<()> {
        if self.stream.lock().await.is_some() {
            return Ok(());
        }
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| ConnectorError::Connection(format!("mssql connect timeout: {addr}")))?
            .map_err(|e| ConnectorError::Connection(format!("mssql connect failed: {e}")))?;
        // PRELOGIN.
        stream
            .write_all(&tds_packet(packet::PRELOGIN, 0, &encode_prelogin()))
            .await
            .map_err(|e| ConnectorError::Connection(format!("mssql prelogin write failed: {e}")))?;
        let reply = read_packet(&mut stream, self.timeout).await?;
        if decode_prelogin_encryption(&reply)? == 0x03 {
            return Err(ConnectorError::Dispatch(
                "mssql server requires TLS encryption; terminate TLS in a sidecar proxy"
                    .to_string(),
            ));
        }
        // LOGIN7.
        let login = encode_login(
            "indra-edge",
            self.username.as_deref(),
            self.password.as_deref(),
            "IndraMQTT",
            &self.host,
            &self.database,
        );
        stream
            .write_all(&tds_packet(packet::LOGIN, 1, &login))
            .await
            .map_err(|e| ConnectorError::Connection(format!("mssql login write failed: {e}")))?;
        let reply = read_packet(&mut stream, self.timeout).await?;
        match parse_reply_tokens(&reply)? {
            TdsReply::Done => {}
            TdsReply::Error { number, message } => {
                return Err(ConnectorError::Dispatch(format!(
                    "mssql login refused {number}: {message}"
                )))
            }
        }
        *self.stream.lock().await = Some(stream);
        Ok(())
    }
}

#[async_trait]
impl MssqlTransport for NativeMssqlTransport {
    async fn execute_batch(&self, table: &str, rows: Vec<MssqlRowItem>) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        self.connect().await?;
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ConnectorError::Connection("mssql not connected".to_string()))?;
        for row in &rows {
            let statement = match &self.query_mode {
                MssqlQueryMode::InsertJson => format!(
                    "INSERT INTO {table} (timestamp, topic, client_id, qos, payload) VALUES ($1, $2, $3, $4, $5)"
                ),
                MssqlQueryMode::CustomUpsert { sql_template } => sql_template.clone(),
            };
            let (packet, _) = encode_executesql(
                &statement,
                row.time_ms,
                &row.topic,
                &row.client_id,
                row.qos,
                &row.payload_json,
            );
            // Stamp a fresh packet id per RPC.
            let mut packet = packet;
            packet[6] = self.packet_id.fetch_add(1, Ordering::SeqCst) as u8;
            stream.write_all(&packet).await.map_err(|e| {
                ConnectorError::Connection(format!("mssql batch write failed: {e}"))
            })?;
            let reply = read_packet(stream, self.timeout).await?;
            match parse_reply_tokens(&reply)? {
                TdsReply::Done => {}
                TdsReply::Error { number, message } => {
                    if number == 1205 {
                        return Err(ConnectorError::Connection(format!(
                            "mssql deadlock 1205: {message}"
                        )));
                    }
                    return Err(ConnectorError::Dispatch(format!(
                        "mssql error {number}: {message}"
                    )));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row with its destination table.
#[derive(Debug, Clone)]
struct MssqlRow {
    table: String,
    item: MssqlRowItem,
}

struct MssqlBuffer {
    queue: BatchQueue<MssqlRow>,
    bytes: usize,
}

/// MSSQL sink: buffers rows, writes RPC batches grouped by table.
pub struct MssqlSink {
    config: MssqlSinkConfig,
    transport: Arc<dyn MssqlTransport>,
    buffer: parking_lot::Mutex<MssqlBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl MssqlSink {
    pub fn new(config: MssqlSinkConfig, transport: Arc<dyn MssqlTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(MssqlBuffer {
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

    pub fn config(&self) -> &MssqlSinkConfig {
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

    /// Flush buffered rows grouped by table (no-op when empty).
    /// Deadlocks and disconnects retry in place; terminal errors and
    /// exhaustion restore the buffer, engage backoff, and propagate.
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
        let mut groups: Vec<(String, Vec<MssqlRowItem>)> = Vec::new();
        for row in &rows {
            match groups.iter_mut().find(|(table, _)| table == &row.table) {
                Some((_, items)) => items.push(row.item.clone()),
                None => groups.push((row.table.clone(), vec![row.item.clone()])),
            }
        }
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            let mut outcome: Result<()> = Ok(());
            for (table, items) in &groups {
                if let Err(e) = self.transport.execute_batch(table, items.clone()).await {
                    outcome = Err(e);
                    break;
                }
            }
            match outcome {
                Ok(()) => {
                    self.backoff.lock().success();
                    self.sent_batches
                        .fetch_add(groups.len() as u64, Ordering::Relaxed);
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
        rows: Vec<MssqlRow>,
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
                "mssql row requires a non-empty topic".to_string(),
            ));
        }
        let text = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("mssql payload must be UTF-8".to_string()))?;
        // Payload JSON is stored verbatim as NVARCHAR text.
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("mssql payload must be JSON".to_string()))?;
        let client_id = value
            .get("client_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let millis = now_millis();
        let table = self.config.resolve_table(topic.as_str(), qos, millis)?;
        let item = MssqlRowItem {
            time_ms: millis,
            topic: topic.as_str().to_string(),
            client_id,
            qos: u8::from(qos),
            payload_json: text.to_string(),
        };
        let added = item.payload_json.len() + item.topic.len() + 64;
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(MssqlRow { table, item });
        buffer.bytes = buffer.bytes.saturating_add(added);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for MssqlSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "mssql"
    }
}

/// Management connector handle pairing an id with an MSSQL sink.
pub struct MssqlConnector {
    id: String,
    sink: Arc<MssqlSink>,
}

impl MssqlConnector {
    pub fn new(id: impl Into<String>, sink: Arc<MssqlSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for MssqlConnector {
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

    fn test_config() -> MssqlSinkConfig {
        MssqlSinkConfig {
            host: "127.0.0.1".to_string(),
            port: None,
            database: "telemetry".to_string(),
            table_template: "dbo.SensorEvents".to_string(),
            auth: MssqlAuth::SqlPassword {
                username: "sa".to_string(),
                password: "secret".to_string(),
            },
            query_mode: MssqlQueryMode::InsertJson,
            trust_server_certificate: true,
            batch_size: Some(200),
            batch_bytes: Some(2_097_152),
            linger_ms: Some(20),
            max_retries: Some(3),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_500),
            timeout_ms: None,
        }
    }

    fn test_sink(config: MssqlSinkConfig) -> (Arc<MssqlSink>, Arc<MockMssqlTransport>) {
        let transport = Arc::new(MockMssqlTransport::new());
        let sink = Arc::new(MssqlSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(config.port_or_default(), 1433);

        config.host.clear();
        assert!(config.validate().is_err());
        config.host = "sql.example.com".to_string();

        config.port = Some(0);
        assert!(config.validate().is_err());
        config.port = Some(1434);
        assert_eq!(config.port_or_default(), 1434);
        config.port = None;

        config.database = "a;b".to_string();
        assert!(config.validate().is_err());
        config.database = "telemetry".to_string();

        config.table_template = "   ".to_string();
        assert!(config.validate().is_err());
        config.table_template = "dbo.SensorEvents".to_string();

        config.auth = MssqlAuth::SqlPassword {
            username: "  ".to_string(),
            password: "x".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = test_config().auth;

        config.query_mode = MssqlQueryMode::CustomUpsert {
            sql_template: "MERGE INTO t USING (SELECT $1, $9) AS s ON 1=1 WHEN NOT MATCHED THEN INSERT VALUES ($1, $9)".to_string(),
        };
        assert!(config.validate().is_err());
        config.query_mode = MssqlQueryMode::CustomUpsert {
            sql_template: "UPDATE t SET payload = $5 WHERE topic = $2".to_string(),
        };
        assert!(config.validate().is_ok());
        config.query_mode = MssqlQueryMode::InsertJson;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_days_from_civil_vectors() {
        // Independent Python (datetime) vectors.
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2026, 9, 12), 20_708);
        assert_eq!(days_from_civil(1, 1, 1), -719_162);
        assert_eq!(days_from_civil(9_999, 12, 31), 2_932_896);
        assert_eq!(days_from_civil(2024, 2, 29), 19_782);
    }

    #[test]
    fn test_obscure_password_vector() {
        // "a" (UCS-2 0x61 0x00): nibble-swap then XOR 0xA5.
        assert_eq!(obscure_password("a"), vec![0xB3, 0xA5]);
        assert_eq!(obscure_password("").len(), 0);
        // Round-trip property: obscuring twice restores the bytes.
        let obscured = obscure_password("sa:p@ss");
        let restored: Vec<u8> = obscured
            .iter()
            .map(|byte| ((byte ^ 0xA5) & 0x0F) << 4 | ((byte ^ 0xA5) & 0xF0) >> 4)
            .collect();
        let mut expected = Vec::new();
        for unit in "sa:p@ss".encode_utf16() {
            expected.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(restored, expected);
    }

    #[test]
    fn test_datetimeoffset_encoding() {
        // 2026-09-12T11:18:09.123Z: date 739870 LE (3B), 100ns time LE
        // (5B), zero UTC offset LE (2B).
        let encoded = encode_datetimeoffset(1_789_211_889_123);
        assert_eq!(&encoded[5..8], &[0x1E, 0x4A, 0x0B]);
        let ticks = 11 * 3_600_000 + 18 * 60_000 + 9 * 1_000 + 123;
        let expected_ticks = (ticks as u64) * 10_000;
        assert_eq!(&encoded[..5], &expected_ticks.to_le_bytes()[..5]);
        assert_eq!(&encoded[8..10], &[0x00, 0x00]);
        assert_eq!(encode_datetimeoffset(-5), encode_datetimeoffset(0));
    }

    #[test]
    fn test_executesql_shapes() {
        let (packet, sql) = encode_executesql(
            "INSERT INTO dbo.SensorEvents (timestamp, topic, client_id, qos, payload) VALUES ($1, $2, $3, $4, $5)",
            1_789_211_889_123,
            "sensors/t1",
            "d7",
            1,
            "{\"v\":1}",
        );
        // Markers become @pn parameters.
        assert!(sql.contains("@p1") && sql.contains("@p5") && !sql.contains('$'));
        // RPC packet header: type 0x03 with EOM status.
        assert_eq!(packet[0], 0x03);
        assert_eq!(packet[1], 0x01);
        let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        assert_eq!(length, packet.len());
        // sp_executesql by name rides the RPC name slot.
        let body = &packet[8..];
        let proc_needle: Vec<u8> = "sp_executesql"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert!(body
            .windows(proc_needle.len())
            .any(|w| w == proc_needle.as_slice()));
        // Payload text rides UCS-2 inside the packet.
        let needle: Vec<u8> = "{\"v\":1}"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert!(body.windows(needle.len()).any(|w| w == needle.as_slice()));
        // DATETIMEOFFSET marker + 10 payload bytes present.
        assert!(body.windows(2).any(|w| w == [0x6F, 0x07]));
    }

    #[tokio::test]
    async fn test_insert_batch_capture() {
        let mut config = test_config();
        config.table_template = "telemetry_${topic}".to_string();
        config.batch_size = Some(10);
        let (sink, transport) = test_sink(config);
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"client_id":"d7","v":1}"#),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].table, "telemetry_sensors_t1");
        assert_eq!(captured[0].rows.len(), 1);
        let row = &captured[0].rows[0];
        assert_eq!(row.topic, "sensors/t1");
        assert_eq!(row.client_id, "d7");
        assert_eq!(row.qos, 1);
        assert_eq!(row.payload_json, "{\"client_id\":\"d7\",\"v\":1}");
        assert!(row.time_ms > 0);
        assert_eq!(sink.sent_records(), 1);
    }

    #[tokio::test]
    async fn test_custom_upsert_wiring() {
        // CustomUpsert mode flows through the same typed rows; the SQL
        // text itself is a transport-side concern (covered by shapes).
        let mut config = test_config();
        config.query_mode = MssqlQueryMode::CustomUpsert {
            sql_template: "UPDATE dbo.SensorEvents SET payload = $5 WHERE topic = $2".to_string(),
        };
        config.batch_size = Some(1);
        let (sink, transport) = test_sink(config);
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"client_id":"d7"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.sent_records(), 1);
        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].rows[0].client_id, "d7");
    }

    #[tokio::test]
    async fn test_deadlock_retries_then_succeeds() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockMssqlOutcome::TdsError {
                number: 1205,
                message: "deadlock victim".to_string(),
            },
            MockMssqlOutcome::Ok,
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
    async fn test_terminal_error_aborts_without_retry() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockMssqlOutcome::TdsError {
                number: 208,
                message: "invalid object".to_string(),
            },
            MockMssqlOutcome::Ok,
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("208 must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[tokio::test]
    async fn test_tcp_loopback_prelogin_login_batch() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // PRELOGIN request: type 0x12, first token VERSION(0x00).
            let request = read_packet(&mut stream).await;
            assert_eq!(request[0], 0x00);
            // Reply: ENCRYPTION NOT_SUP(2) so the client proceeds.
            // Header (6B): ENCRYPTION token @6 len 1, then TERMINATOR.
            let reply = [
                0x01u8, 0x00, 0x06, 0x00, 0x01, // ENCRYPTION @6 len 1
                0xFF, // TERMINATOR
                0x02, // NOT_SUP
            ];
            let mut packet = vec![0x04u8, 0x01];
            packet.extend_from_slice(&(8 + reply.len() as u16).to_be_bytes());
            packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            packet.extend_from_slice(&reply);
            stream.write_all(&packet).await.expect("prelogin reply");
            // LOGIN7: type 0x10; username rides UCS-2 inside.
            let login = read_packet(&mut stream).await;
            assert!(login.len() > 64);
            let needle: Vec<u8> = "sa".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            assert!(login.windows(needle.len()).any(|w| w == needle.as_slice()));
            let loginack: Vec<u8> = {
                let mut token = vec![0xADu8];
                token.extend_from_slice(&6u16.to_le_bytes());
                token.extend_from_slice(&[0x00, 0x71, 0x0F, 0x00, 0x0D, 0x00]);
                token
            };
            let mut done = vec![0xFDu8];
            done.extend_from_slice(&0u16.to_le_bytes());
            done.extend_from_slice(&0u16.to_le_bytes());
            done.extend_from_slice(&0u64.to_le_bytes());
            let mut payload = loginack;
            payload.extend_from_slice(&done);
            let mut packet = vec![0x04u8, 0x01];
            packet.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
            packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            packet.extend_from_slice(&payload);
            stream.write_all(&packet).await.expect("login reply");
            // RPC batch: type 0x03; answer DONE.
            let batch = read_packet(&mut stream).await;
            assert!(batch.len() > 16);
            let mut done = vec![0xFDu8];
            done.extend_from_slice(&0u16.to_le_bytes());
            done.extend_from_slice(&0u16.to_le_bytes());
            done.extend_from_slice(&1u64.to_le_bytes());
            let mut packet = vec![0x04u8, 0x01];
            packet.extend_from_slice(&(8 + done.len() as u16).to_be_bytes());
            packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            packet.extend_from_slice(&done);
            stream.write_all(&packet).await.expect("done");
        });

        async fn read_packet(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
            let mut header = [0u8; 8];
            stream.read_exact(&mut header).await.expect("head");
            let length = u16::from_be_bytes([header[2], header[3]]) as usize;
            let mut body = vec![0u8; length - 8];
            stream.read_exact(&mut body).await.expect("body");
            body
        }

        let mut config = test_config();
        config.host = "127.0.0.1".to_string();
        config.port = Some(port);
        config.batch_size = Some(1);
        let transport = Arc::new(NativeMssqlTransport::new(&config).unwrap());
        let sink = MssqlSink::new(config, transport).unwrap();
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"client_id":"d7"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.sent_records(), 1);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server done")
            .expect("server task");
    }
}
