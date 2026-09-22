//! Ban list with matchers and expiry for the v5 management API.
//!
//! Covers `GET /banned` (paged list), `POST /banned` (create one entry),
//! `DELETE /banned` (clear all) and `DELETE /banned/{as}/{who}` (drop one
//! entry). Single-node, management-plane writes:
//! the broker consults the store on the connect path (before the session
//! is created) and on publish authorisation (so a client banned
//! mid-session stops being served). Both reads take one short read lock
//! and scan at most the stored entries; an empty store returns after one
//! length check, so the common case costs almost nothing on the publish
//! path (see [`BanStore::is_banned`]).
//!
//! Store bounds (both stated here and enforced below):
//! - at most [`MAX_BANS`] entries in the matcher map; creates past the
//!   cap are rejected instead of growing without limit;
//! - `who` is capped at 512 chars and `by`/`reason` at 1024 chars, so one
//!   entry cannot balloon memory;
//! - expiry is lazy: entries whose `until` has passed are dropped on the
//!   next list or create (no background task), and live-match checks
//!   skip them without taking a write lock.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::errors::ApiError;
use crate::pagination::{meta_page, paginate, PageParams};
use crate::ApiState;

/// Upper bound for stored bans. Creates past this size are rejected with
/// `BAD_REQUEST` instead of growing the map without limit.
pub const MAX_BANS: usize = 10_000;
/// Longest accepted `who` value (client id, user name, address or pattern).
const MAX_WHO_LEN: usize = 512;
/// Longest accepted `by`/`reason` detail strings.
const MAX_DETAIL_LEN: usize = 1024;

/// Ban kinds the list accepts. Exact identifiers plus pattern forms for
/// client ids, user names and source addresses.
const VALID_AS: &[&str] = &[
    "clientid",
    "username",
    "peerhost",
    "clientid_re",
    "username_re",
    "peerhost_net",
];

/// One stored ban: what-kind (`as`), who-value (`who`), who added it
/// (`by`), why (`reason`), when it starts (`at`, RFC 3339) and when it
/// ends (`until`, RFC 3339 or the literal `"infinity"` for no expiry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEntry {
    pub as_type: String,
    pub who: String,
    pub by: String,
    pub reason: String,
    pub at: String,
    pub until: String,
}

impl BanEntry {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "as": self.as_type,
            "who": self.who,
            "by": self.by,
            "reason": self.reason,
            "at": self.at,
            "until": self.until,
        })
    }
}

/// In-memory ban directory keyed by (`as`, `who`).
///
/// Single-node map behind one lock; every method finishes quickly.
/// Management writes take the write lock; the broker's connect and
/// publish checks take a short read lock and never mutate, so delivery
/// never blocks on a management write beyond one lock hold.
pub struct BanStore {
    inner: RwLock<HashMap<(String, String), BanEntry>>,
}

impl BanStore {
    /// Empty directory.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Snapshot of live entries sorted by (`as`, `who`) for stable pages.
    /// Drops expired entries first (lazy expiry sweep).
    pub fn list_live(&self) -> Vec<BanEntry> {
        let now = now_epoch_secs();
        let mut map = self.inner.write().expect("ban store lock");
        sweep_expired_locked(&mut map, now);
        let mut out: Vec<BanEntry> = map.values().cloned().collect();
        out.sort_by(|a, b| (&a.as_type, &a.who).cmp(&(&b.as_type, &b.who)));
        out
    }

    /// Insert one entry. Fails cleanly when the (`as`, `who`) pair already
    /// exists (caller maps to `ALREADY_EXISTS`) or the store is at
    /// [`MAX_BANS`] (caller maps to `BAD_REQUEST`).
    pub fn insert(&self, entry: BanEntry) -> Result<BanEntry, BanInsertError> {
        let now = now_epoch_secs();
        let mut map = self.inner.write().expect("ban store lock");
        sweep_expired_locked(&mut map, now);
        let key = (entry.as_type.clone(), entry.who.clone());
        if map.contains_key(&key) {
            return Err(BanInsertError::Duplicate);
        }
        if map.len() >= MAX_BANS {
            return Err(BanInsertError::Full);
        }
        map.insert(key, entry.clone());
        Ok(entry)
    }

    /// Remove every entry.
    pub fn clear(&self) {
        self.inner.write().expect("ban store lock").clear();
    }

    /// Drop the (`as`, `who`) entry. Sweeps expired entries first so an
    /// already-expired row reads as absent. Returns true when a live
    /// entry was removed, false when nothing was stored under the key.
    pub fn remove(&self, as_type: &str, who: &str) -> bool {
        let now = now_epoch_secs();
        let mut map = self.inner.write().expect("ban store lock");
        sweep_expired_locked(&mut map, now);
        map.remove(&(as_type.to_string(), who.to_string()))
            .is_some()
    }

    /// Whether the given identity is currently banned (B1-03 enforcement).
    ///
    /// Consulted by the broker on CONNECT (before the session is created)
    /// and on publish authorisation (so a client banned mid-session stops
    /// being served). Expired entries never match; they are skipped here
    /// without mutating, and the next list/create sweeps them.
    ///
    /// Cost: one read lock plus a scan of at most the stored entries. An
    /// empty store returns after one length check. Exact kinds
    /// (`clientid`, `username`, `peerhost`) compare by value; pattern
    /// kinds compile their stored pattern per call (`clientid_re` /
    /// `username_re` as regex search, `peerhost_net` as CIDR containment),
    /// so a store holding pattern bans costs more per publish than an
    /// exact-only store. Unknown kinds never match.
    pub fn is_banned(
        &self,
        client_id: &str,
        username: Option<&str>,
        peerhost: Option<&str>,
    ) -> bool {
        let now = now_epoch_secs();
        let map = self.inner.read().expect("ban store lock");
        if map.is_empty() {
            return false;
        }
        // Parse the peer address once: the edge always sends an IP
        // literal, so an unparseable value simply matches no address ban.
        let peer_ip: Option<std::net::IpAddr> = peerhost.and_then(|s| s.trim().parse().ok());
        for entry in map.values() {
            if until_is_expired(&entry.until, now) {
                continue;
            }
            if entry_matches_identity(entry, client_id, username, peerhost, peer_ip) {
                return true;
            }
        }
        false
    }
}

impl Default for BanStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Why [`BanStore::insert`] refused an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanInsertError {
    /// The (`as`, `who`) pair is already stored.
    Duplicate,
    /// The store holds [`MAX_BANS`] live entries.
    Full,
}

/// Documented list filters. Every field is optional; unknown query keys
/// are ignored by the `Query` extractor so new parameters degrade to an
/// unfiltered page instead of a 400.
#[derive(Deserialize, Default)]
pub struct BannedFilters {
    #[serde(default)]
    pub clientid: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub peerhost: Option<String>,
    #[serde(default)]
    pub like_clientid: Option<String>,
    #[serde(default)]
    pub like_username: Option<String>,
    #[serde(default)]
    pub like_peerhost: Option<String>,
    #[serde(default)]
    pub like_peerhost_net: Option<String>,
}

/// `GET /banned`: wrapped page (`data` plus `meta`). An empty store reads
/// as an empty page, never an error. Unknown query keys are ignored and
/// malformed `page`/`limit` fall back to defaults via [`PageParams`].
pub async fn list_banned(
    State(state): State<ApiState>,
    params: PageParams,
    Query(filters): Query<BannedFilters>,
) -> Response {
    let live = state.bans.list_live();
    let matching: Vec<BanEntry> = live
        .into_iter()
        .filter(|e| entry_matches(e, &filters))
        .collect();
    let total = matching.len();
    let page_items = paginate(&matching, params.page, params.limit);
    let data: Vec<serde_json::Value> = page_items.iter().map(BanEntry::to_json).collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": meta_page(params.page, params.limit, total),
        })),
    )
        .into_response()
}

fn entry_matches(entry: &BanEntry, filters: &BannedFilters) -> bool {
    if let Some(want) = filters.clientid.as_deref() {
        if entry.as_type != "clientid" || entry.who != want {
            return false;
        }
    }
    if let Some(want) = filters.username.as_deref() {
        if entry.as_type != "username" || entry.who != want {
            return false;
        }
    }
    if let Some(want) = filters.peerhost.as_deref() {
        if entry.as_type != "peerhost" || entry.who != want {
            return false;
        }
    }
    if let Some(want) = filters.like_clientid.as_deref() {
        if !(entry.as_type == "clientid" || entry.as_type == "clientid_re")
            || !entry.who.contains(want)
        {
            return false;
        }
    }
    if let Some(want) = filters.like_username.as_deref() {
        if !(entry.as_type == "username" || entry.as_type == "username_re")
            || !entry.who.contains(want)
        {
            return false;
        }
    }
    if let Some(want) = filters.like_peerhost.as_deref() {
        if entry.as_type != "peerhost" || !entry.who.contains(want) {
            return false;
        }
    }
    if let Some(want) = filters.like_peerhost_net.as_deref() {
        if entry.as_type != "peerhost_net" || !entry.who.contains(want) {
            return false;
        }
    }
    true
}

/// `POST /banned`: create one entry from a who-value plus what-kind and
/// why, with an optional expiry. Returns the stored entry with 200.
/// Malformed bodies fail with `BAD_REQUEST`; an existing (`as`, `who`)
/// pair fails with `ALREADY_EXISTS` instead of being overwritten.
pub async fn create_banned(State(state): State<ApiState>, body: Bytes) -> Response {
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return ApiError::BadRequest(format!("invalid ban body: {e}")).into_response();
        }
    };
    let entry = match parse_ban_request(&value) {
        Ok(e) => e,
        Err(msg) => return ApiError::BadRequest(msg).into_response(),
    };
    match state.bans.insert(entry) {
        Ok(stored) => (StatusCode::OK, Json(stored.to_json())).into_response(),
        Err(BanInsertError::Duplicate) => {
            ApiError::AlreadyExists("ban already exists".to_string()).into_response()
        }
        Err(BanInsertError::Full) => {
            ApiError::BadRequest("ban store is full".to_string()).into_response()
        }
    }
}

/// `DELETE /banned`: drop every entry and report success with 204.
/// Query strings (including unknown keys) are ignored by design.
pub async fn clear_banned(State(state): State<ApiState>) -> Response {
    state.bans.clear();
    StatusCode::NO_CONTENT.into_response()
}

/// `DELETE /banned/{as}/{who}`: drop one entry addressed by its kind plus
/// its value. A stored entry reports success with 204; a missing pair
/// reports `NOT_FOUND` instead of success; an unknown kind reports
/// `BAD_REQUEST` with the documented error shape.
pub async fn delete_banned_one(
    State(state): State<ApiState>,
    Path((as_type, who)): Path<(String, String)>,
) -> Response {
    if !VALID_AS.contains(&as_type.as_str()) {
        return ApiError::BadRequest(format!("unknown ban kind `as`: {as_type}")).into_response();
    }
    if !state.bans.remove(&as_type, &who) {
        return ApiError::NotFound("ban not found".to_string()).into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Validate a create body into a stored entry.
///
/// Required: `as` (one of the six kinds) and `who` (non-empty, length
/// capped; address kinds additionally shape-checked). Optional: `by`,
/// `reason` (defaulted when absent) and `at`/`until` (RFC 3339 or epoch
/// seconds; `until` also accepts `"infinity"` and defaults to it).
fn parse_ban_request(value: &serde_json::Value) -> Result<BanEntry, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "ban must be a JSON object".to_string())?;
    let as_type = obj
        .get("as")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "field `as` is required".to_string())?;
    if !VALID_AS.contains(&as_type) {
        return Err(format!("unknown ban kind `as`: {as_type}"));
    }
    let who = obj
        .get("who")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "field `who` is required".to_string())?;
    if who.trim().is_empty() {
        return Err("field `who` must not be empty".to_string());
    }
    if who.len() > MAX_WHO_LEN {
        return Err("field `who` is too long".to_string());
    }
    validate_who_shape(as_type, who)?;
    let by = obj
        .get("by")
        .and_then(|v| v.as_str())
        .unwrap_or("api")
        .to_string();
    if by.len() > MAX_DETAIL_LEN {
        return Err("field `by` is too long".to_string());
    }
    let reason = obj
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if reason.len() > MAX_DETAIL_LEN {
        return Err("field `reason` is too long".to_string());
    }
    let at = match obj.get("at") {
        None => epoch_to_rfc3339(now_epoch_secs()),
        Some(v) => parse_at_value(v)
            .ok_or_else(|| "field `at` must be RFC 3339 or epoch seconds".to_string())?,
    };
    let until = match obj.get("until") {
        None => "infinity".to_string(),
        Some(v) => parse_until_value(v)
            .ok_or_else(|| "field `until` must be RFC 3339, epoch or infinity".to_string())?,
    };
    // An expiry in the past is still stored (reads sweep it lazily); only
    // the shape is validated here so callers get a clean client error for
    // malformed times instead of a silent drop.
    Ok(BanEntry {
        as_type: as_type.to_string(),
        who: who.to_string(),
        by,
        reason,
        at,
        until,
    })
}

/// Shape-check `who` for the address kinds. Identifier and pattern kinds
/// accept any non-empty value (patterns are stored verbatim; matching
/// happens against the stored string without compiling here).
fn validate_who_shape(as_type: &str, who: &str) -> Result<(), String> {
    match as_type {
        "peerhost" => {
            if who.parse::<std::net::IpAddr>().is_err() {
                return Err("field `who` must be an IP address for `peerhost`".to_string());
            }
            Ok(())
        }
        "peerhost_net" => {
            if parse_cidr(who).is_err() {
                return Err("field `who` must be CIDR for `peerhost_net`".to_string());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_cidr(s: &str) -> Result<(), ()> {
    let (addr, prefix) = s.split_once('/').ok_or(())?;
    let is_v6 = addr.contains(':');
    addr.parse::<std::net::IpAddr>().map_err(|_| ())?;
    let bits: u32 = prefix.parse().map_err(|_| ())?;
    let max = if is_v6 { 128 } else { 32 };
    if bits > max {
        return Err(());
    }
    Ok(())
}

fn parse_at_value(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Number(n) => {
            let secs = n.as_u64()?;
            Some(epoch_to_rfc3339(secs))
        }
        serde_json::Value::String(s) => {
            if s == "infinity" {
                return None;
            }
            if let Ok(secs) = s.parse::<u64>() {
                return Some(epoch_to_rfc3339(secs));
            }
            parse_rfc3339_to_epoch(s)?;
            Some(s.clone())
        }
        _ => None,
    }
}

fn parse_until_value(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Number(n) => {
            let secs = n.as_u64()?;
            Some(epoch_to_rfc3339(secs))
        }
        serde_json::Value::String(s) => {
            if s == "infinity" {
                return Some("infinity".to_string());
            }
            if let Ok(secs) = s.parse::<u64>() {
                return Some(epoch_to_rfc3339(secs));
            }
            parse_rfc3339_to_epoch(s)?;
            Some(s.clone())
        }
        _ => None,
    }
}

fn sweep_expired_locked(map: &mut HashMap<(String, String), BanEntry>, now: u64) {
    map.retain(|_, e| !until_is_expired(&e.until, now));
}

/// Whether one stored ban matches the connecting/publishing identity.
/// Exact kinds compare by value; `clientid_re` / `username_re` run the
/// stored pattern as a regex search; `peerhost_net` checks CIDR
/// containment of the parsed peer address.
fn entry_matches_identity(
    entry: &BanEntry,
    client_id: &str,
    username: Option<&str>,
    peerhost: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> bool {
    match entry.as_type.as_str() {
        "clientid" => entry.who == client_id,
        "username" => username == Some(entry.who.as_str()),
        "peerhost" => match (peer_ip, entry.who.parse::<std::net::IpAddr>()) {
            (Some(ip), Ok(want)) => ip == want,
            // Either side unparseable: fall back to the raw string so an
            // exact literal still matches instead of silently missing.
            _ => peerhost == Some(entry.who.as_str()),
        },
        "clientid_re" => regex_ban_matches(&entry.who, client_id),
        "username_re" => username
            .map(|name| regex_ban_matches(&entry.who, name))
            .unwrap_or(false),
        "peerhost_net" => peer_ip
            .map(|ip| cidr_ban_contains(&entry.who, ip))
            .unwrap_or(false),
        _ => false,
    }
}

/// Regex search of a stored pattern against a value. Patterns are stored
/// verbatim (management validation does not compile them), so an invalid
/// pattern matches nothing instead of failing the lookup. Compiled per
/// call: ban checks run per connect and per publish, and the store holds
/// no compiled cache (B1-03 keeps no new cache layer).
fn regex_ban_matches(pattern: &str, value: &str) -> bool {
    match regex::Regex::new(pattern) {
        Ok(re) => re.is_match(value),
        Err(_) => false,
    }
}

/// Whether `ip` falls inside the stored `addr/prefix` network. A malformed
/// network, an out-of-range prefix, or a v4/v6 family mismatch matches
/// nothing.
fn cidr_ban_contains(cidr: &str, ip: std::net::IpAddr) -> bool {
    let (net_str, prefix_str) = match cidr.split_once('/') {
        Some(parts) => parts,
        None => return false,
    };
    let Ok(net) = net_str.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u32>() else {
        return false;
    };
    match (net, ip) {
        (std::net::IpAddr::V4(net), std::net::IpAddr::V4(ip)) => {
            if prefix > 32 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        }
        (std::net::IpAddr::V6(net), std::net::IpAddr::V6(ip)) => {
            if prefix > 128 {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(net) & mask) == (u128::from(ip) & mask)
        }
        _ => false,
    }
}

fn until_is_expired(until: &str, now: u64) -> bool {
    if until == "infinity" {
        return false;
    }
    if let Ok(secs) = until.parse::<u64>() {
        return secs < now;
    }
    match parse_rfc3339_to_epoch(until) {
        Some(secs) => secs < now,
        None => false,
    }
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format epoch seconds as `YYYY-MM-DDTHH:MM:SS+00:00` (always UTC).
fn epoch_to_rfc3339(secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_epoch(secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}+00:00")
}

fn civil_from_epoch(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let sod = (secs % 86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, sod / 3600, (sod % 3600) / 60, sod % 60)
}

// Howard Hinnant's civil_from_days: days since 1970-01-01 to y/m/d.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = (m as u64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Parse an RFC 3339 timestamp to epoch seconds. Accepts `Z` or numeric
/// offsets (`+08:00`, `+0800`, `+08`); fractional seconds are ignored.
fn parse_rfc3339_to_epoch(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date_part, rest) = s.split_once(['T', 't', ' '])?;
    let (y, m, d) = parse_date(date_part)?;
    let (time_part, offset_secs) = split_timezone(rest)?;
    let (hh, mm, ss) = parse_time_of_day(time_part)?;
    let days = days_from_civil(y, m, d);
    let sod = hh as i64 * 3600 + mm as i64 * 60 + ss as i64 - offset_secs;
    let total = days * 86_400 + sod;
    if total < 0 {
        return None;
    }
    Some(total as u64)
}

fn parse_date(s: &str) -> Option<(i64, u32, u32)> {
    let mut it = s.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: u32 = it.next()?.parse().ok()?;
    let d: u32 = it.next()?.parse().ok()?;
    if it.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

fn split_timezone(s: &str) -> Option<(&str, i64)> {
    if let Some(t) = s.strip_suffix('Z').or_else(|| s.strip_suffix('z')) {
        return Some((t, 0));
    }
    // Find the last + or - that starts the offset (after the time).
    let bytes = s.as_bytes();
    let mut pos = None;
    for (i, &b) in bytes.iter().enumerate() {
        if (b == b'+' || b == b'-') && i >= 8 {
            pos = Some(i);
        }
    }
    let i = pos?;
    let time_part = &s[..i];
    let off = &s[i..];
    Some((time_part, parse_tz_offset(off)?))
}

fn parse_tz_offset(s: &str) -> Option<i64> {
    let sign = match s.as_bytes().first()? {
        b'+' => 1i64,
        b'-' => -1i64,
        _ => return None,
    };
    let body = s[1..].replace(':', "");
    let (h, m) = match body.len() {
        2 => (body.parse::<i64>().ok()?, 0),
        4 => (
            body[..2].parse::<i64>().ok()?,
            body[2..].parse::<i64>().ok()?,
        ),
        _ => return None,
    };
    if h > 23 || m > 59 {
        return None;
    }
    Some(sign * (h * 3600 + m * 60))
}

fn parse_time_of_day(s: &str) -> Option<(u32, u32, u32)> {
    let time_only = s.split('.').next()?;
    let mut it = time_only.split(':');
    let hh: u32 = it.next()?.parse().ok()?;
    let mm: u32 = it.next()?.parse().ok()?;
    let ss: u32 = it.next().unwrap_or("0").parse().ok()?;
    if it.next().is_some() || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    Some((hh, mm, ss))
}

#[cfg(test)]
mod ban_match_tests {
    use super::*;

    fn entry(as_type: &str, who: &str, until: &str) -> BanEntry {
        BanEntry {
            as_type: as_type.to_string(),
            who: who.to_string(),
            by: "test".to_string(),
            reason: "test".to_string(),
            at: epoch_to_rfc3339(now_epoch_secs()),
            until: until.to_string(),
        }
    }

    fn store_with(entries: Vec<BanEntry>) -> BanStore {
        let store = BanStore::new();
        for e in entries {
            store.insert(e).expect("fixture insert");
        }
        store
    }

    #[test]
    fn empty_store_bans_nobody() {
        let store = BanStore::new();
        assert!(!store.is_banned("any", Some("user"), Some("10.0.0.1")));
        assert!(!store.is_banned("any", None, None));
    }

    #[test]
    fn exact_kinds_match_by_value() {
        let store = store_with(vec![
            entry("clientid", "banned-id", "infinity"),
            entry("username", "banned-user", "infinity"),
            entry("peerhost", "192.0.2.7", "infinity"),
        ]);
        assert!(store.is_banned("banned-id", None, None));
        assert!(!store.is_banned("other-id", None, None));
        assert!(store.is_banned("other-id", Some("banned-user"), None));
        assert!(!store.is_banned("other-id", Some("other-user"), None));
        assert!(!store.is_banned("other-id", None, None));
        assert!(store.is_banned("other-id", None, Some("192.0.2.7")));
        assert!(!store.is_banned("other-id", None, Some("192.0.2.8")));
        assert!(!store.is_banned("other-id", None, None));
    }

    #[test]
    fn pattern_kinds_match() {
        let store = store_with(vec![
            entry("clientid_re", "^spam-", "infinity"),
            entry("username_re", "bot$", "infinity"),
            entry("peerhost_net", "10.9.0.0/16", "infinity"),
        ]);
        assert!(store.is_banned("spam-1", None, None));
        assert!(!store.is_banned("ham-1", None, None));
        assert!(store.is_banned("ham-1", Some("chatbot"), None));
        assert!(!store.is_banned("ham-1", Some("human"), None));
        assert!(!store.is_banned("ham-1", None, None));
        assert!(store.is_banned("ham-1", None, Some("10.9.4.22")));
        assert!(!store.is_banned("ham-1", None, Some("10.10.4.22")));
        assert!(!store.is_banned("ham-1", None, None));
    }

    #[test]
    fn invalid_patterns_and_bad_cidr_match_nobody() {
        let store = store_with(vec![
            entry("clientid_re", "([unclosed", "infinity"),
            entry("peerhost_net", "10.9.0.0/33", "infinity"),
        ]);
        assert!(!store.is_banned("anything", Some("anyone"), Some("10.9.0.9")));
    }

    #[test]
    fn expired_entries_match_nobody() {
        let past = epoch_to_rfc3339(now_epoch_secs().saturating_sub(60));
        let store = store_with(vec![
            entry("clientid", "old-id", &past),
            entry("username", "old-user", &past),
            entry("peerhost", "192.0.2.9", &past),
        ]);
        assert!(!store.is_banned("old-id", Some("old-user"), Some("192.0.2.9")));
    }
}
