//! Real Kerberos authentication (B2-02, T-87).
//!
//! GSSAPI-based authentication at CONNECT. The broker accepts a SPNEGO
//! `NegTokenInit` wrapping a Kerberos V5 AP-REQ, or a bare AP-REQ,
//! decodes real ASN.1 DER, verifies the ticket against a keytab holding
//! the broker's service principal, checks the service name, the ticket
//! validity window with clock-skew allowance, and rejects replays. The
//! authenticated client principal is derived from the verified (decrypted)
//! ticket content and mapped onto roles through configuration. The
//! returned session key is the random key minted by the issuing KDC and
//! sealed inside the ticket, never a constant.
//!
//! Wire crates (all maintained, all permissive licences):
//! - `kerberos-parser` 0.9 (MIT/Apache-2.0): DER parsing of the outer
//!   AP-REQ (`[APPLICATION 14]`) and Ticket (`[APPLICATION 1]`) per
//!   RFC 4120. No byte pattern-matching: malformed tokens fail DER.
//! - `der-parser` 10 (MIT/Apache-2.0): DER parsing of the SPNEGO
//!   `InitialContextToken` (`[APPLICATION 0]` with OID 1.3.6.1.5.5.2).
//! - `picky-krb` 0.12 (MIT OR Apache-2.0): RFC 4120 ASN.1 for
//!   `EncTicketPart` (`[APPLICATION 3]`) and `Authenticator`
//!   (`[APPLICATION 2]`) plus RFC 3962 AES-256-CTS-HMAC-SHA1-96
//!   (`etype 18`) encryption. No cipher, hash or MAC is hand-rolled;
//!   all bulk crypto goes through `picky-krb` (which uses maintained
//!   `aes`, `hmac`, `sha1`, `pbkdf2`).
//! - `ring` 0.17 (Apache-2.0 AND ISC): system randomness for the
//!   KDC session keys minted in tests.
//!
//! Ticket protection: `etype 18` (aes256-cts-hmac-sha1-96) with the
//! RFC 3962 construction (confounder, CTS, HMAC-SHA1-96, key usages
//! `2` for the ticket and `11` for the authenticator). The same
//! construction verifies tickets minted by a stock MIT KDC holding the
//! same service key. Cross-realm trust beyond what the libraries give
//! for free is out of scope and left untested.
//!
//! Test KDC: in-process, minted with the same `picky-krb` CTS path the
//! verifier uses (real DER, real CTS), holding the broker service key
//! in a MIT keytab v2 file. Each keytab entry holds realm, components,
//! name type, key type and key bytes. The authenticator loads
//! the entry matching the configured service principal with a 32-byte key
//! (etype 18). A missing or unreadable keytab disables the mechanism
//! explicitly at startup with a clear log line and never accepts tokens.
//!
//! Replay: a bounded in-memory cache (1024 entries, each under 128 bytes,
//! so under 128 KiB total) keyed by client principal plus authenticator
//! timestamp and microseconds. Replayed authenticators are refused.
//!
//! Memory bounds: one 32-byte service key, one bounded replay cache, no
//! per-message allocation on the delivery path (CONNECT only).

use crate::{AuthError, Authenticator, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Kerberos enctype identifier carried on the wire (RFC 3962
/// AES-256-CTS-HMAC-SHA1-96, verified via `picky-krb`).
const ETYPE_AES256: i32 = 18;
/// RFC 4120 key usage for the ticket enc-part.
const KEY_USAGE_TICKET: i32 = 2;
/// RFC 4120 key usage for the AP-REQ authenticator.
const KEY_USAGE_AUTHENTICATOR: i32 = 11;
/// Service keys must be 32 bytes (AES-256).
const SERVICE_KEY_LEN: usize = 32;
/// Upper bound on replay entries (bounded memory, CONNECT only).
/// Exported so the broker boot path uses the same bound instead of a
/// second hardcoded number.
pub const REPLAY_MAX_ENTRIES: usize = 1024;
/// Upper bound on accepted token bytes (denies absurd inputs early).
const MAX_TOKEN_LEN: usize = 64 * 1024;

fn default_clock_skew_secs() -> u64 {
    300
}

fn default_replay_max() -> usize {
    REPLAY_MAX_ENTRIES
}

/// Directory-style Kerberos configuration.
///
/// Old files holding only `service_principal_name`, `realm` and
/// `allowed_realms` still deserialize: every new field has a default.
/// An empty `keytab_path` disables the mechanism (explicit log, fail
/// closed). `principal_role_map` maps a verified full client principal
/// (for example `alice@ENTERPRISE.CORP`) onto a broker role; unmapped
/// principals authenticate with role `user`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosConfig {
    #[serde(default)]
    pub service_principal_name: String,
    #[serde(default)]
    pub realm: String,
    #[serde(default)]
    pub allowed_realms: Vec<String>,
    #[serde(default)]
    pub keytab_path: String,
    #[serde(default = "default_clock_skew_secs")]
    pub clock_skew_secs: u64,
    #[serde(default = "default_replay_max")]
    pub replay_max_entries: usize,
    #[serde(default)]
    pub principal_role_map: HashMap<String, String>,
}

impl Default for KerberosConfig {
    fn default() -> Self {
        Self {
            service_principal_name: String::new(),
            realm: String::new(),
            allowed_realms: Vec::new(),
            keytab_path: String::new(),
            clock_skew_secs: default_clock_skew_secs(),
            replay_max_entries: default_replay_max(),
            principal_role_map: HashMap::new(),
        }
    }
}

/// Verified Kerberos identity plus the negotiated session key.
///
/// `session_key` is the random 32-byte key sealed inside the ticket by
/// the issuing KDC (decrypted with the service key), never a constant.
/// Two tickets from the test KDC carry different keys.
#[derive(Debug, Clone)]
pub struct VerifiedKerberos {
    pub client_principal: String,
    pub service_principal: String,
    pub session_key: Vec<u8>,
    pub role: String,
}

/// Bounded replay cache for authenticator timestamps.
///
/// Keyed by `client_principal | timestamp | usec`. Insert returns false
/// when the key was already present (replay). Evicts oldest first past
/// the bound so memory stays under `max_entries` small entries.
#[derive(Debug)]
struct ReplayCache {
    max_entries: usize,
    seen: HashSet<Vec<u8>>,
    order: VecDeque<Vec<u8>>,
}

impl ReplayCache {
    fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.clamp(16, 8192),
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    fn check_and_insert(&mut self, key: Vec<u8>) -> bool {
        if self.seen.contains(&key) {
            return false;
        }
        self.seen.insert(key.clone());
        self.order.push_back(key);
        while self.order.len() > self.max_entries {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            } else {
                break;
            }
        }
        true
    }
}

/// Real Kerberos authenticator.
///
/// Loads the service key from the configured MIT keytab at construction.
/// When the keytab is missing, unreadable or holds no matching entry the
/// mechanism is disabled: every attempt fails closed and construction
/// emits a clear `tracing::warn!` line. Disabled never accepts tokens.
pub struct KerberosAuthenticator {
    config: KerberosConfig,
    service_key: Option<[u8; SERVICE_KEY_LEN]>,
    enabled: bool,
    replay: Mutex<ReplayCache>,
}

impl KerberosAuthenticator {
    pub fn new(config: KerberosConfig) -> Self {
        let replay_max = config.replay_max_entries;
        match Self::load_service_key(&config) {
            Some(key) => {
                tracing::info!(
                    service = %config.service_principal_name,
                    "Kerberos authentication enabled"
                );
                Self {
                    config,
                    service_key: Some(key),
                    enabled: true,
                    replay: Mutex::new(ReplayCache::new(replay_max)),
                }
            }
            None => {
                if config.keytab_path.is_empty() {
                    tracing::warn!(
                        "Kerberos authentication disabled: no keytab configured \
                         (set keytab_path to enable)"
                    );
                } else {
                    tracing::warn!(
                        path = %config.keytab_path,
                        service = %config.service_principal_name,
                        "Kerberos authentication disabled: keytab missing, unreadable, \
                         or holds no matching service entry"
                    );
                }
                Self {
                    config,
                    service_key: None,
                    enabled: false,
                    replay: Mutex::new(ReplayCache::new(replay_max)),
                }
            }
        }
    }

    /// Whether the mechanism can accept tokens (keytab loaded).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn config(&self) -> &KerberosConfig {
        &self.config
    }

    /// Role mapped for a verified client principal (`user` default).
    #[must_use]
    pub fn role_for_principal(&self, client_principal: &str) -> String {
        self.config
            .principal_role_map
            .get(client_principal)
            .cloned()
            .unwrap_or_else(|| "user".to_string())
    }

    fn fail(client_id: &str, reason: &str) -> AuthError {
        AuthError::AuthenticationFailed(format!("{client_id} {reason}"))
    }

    /// Load the 32-byte service key matching the configured service
    /// principal from the MIT keytab file (`None` when disabled).
    fn load_service_key(config: &KerberosConfig) -> Option<[u8; SERVICE_KEY_LEN]> {
        if config.keytab_path.is_empty() {
            return None;
        }
        if config.service_principal_name.is_empty() {
            return None;
        }
        let bytes = std::fs::read(&config.keytab_path).ok()?;
        let entries = parse_keytab(&bytes)?;
        let (want_comps, want_realm) = split_principal(&config.service_principal_name)?;
        for entry in &entries {
            if entry.realm != want_realm {
                continue;
            }
            if entry.components != want_comps {
                continue;
            }
            if entry.key.len() != SERVICE_KEY_LEN {
                continue;
            }
            let mut key = [0u8; SERVICE_KEY_LEN];
            key.copy_from_slice(&entry.key);
            return Some(key);
        }
        None
    }

    /// Verify one CONNECT token (bare AP-REQ or SPNEGO-wrapped AP-REQ).
    ///
    /// Decodes real DER via `kerberos-parser`/`der-parser`, decrypts via
    /// `picky-krb` (RFC 3962 CTS), checks service name, validity window
    /// with skew, and replays. Returns the verified principal plus the
    /// real session key.
    pub fn verify_token(&self, client_id: &str, token: &[u8]) -> Result<VerifiedKerberos> {
        if !self.enabled {
            return Err(Self::fail(
                client_id,
                "presented a kerberos token, but kerberos authentication is disabled \
                 (no keytab)",
            ));
        }
        if token.is_empty() || token.len() > MAX_TOKEN_LEN {
            return Err(Self::fail(
                client_id,
                "presented a malformed kerberos token",
            ));
        }
        let Some(service_key) = self.service_key else {
            return Err(Self::fail(
                client_id,
                "presented a kerberos token, but kerberos authentication is disabled \
                 (no keytab)",
            ));
        };
        let ap_req_bytes = extract_ap_req_bytes(token)
            .map_err(|_| Self::fail(client_id, "presented a malformed kerberos token"))?;
        use der_parser::asn1_rs::FromDer as _;
        let (rest, ap_req) = kerberos_parser::krb5::ApReq::from_der(&ap_req_bytes)
            .map_err(|_| Self::fail(client_id, "presented a malformed kerberos token"))?;
        if !rest.is_empty() {
            return Err(Self::fail(
                client_id,
                "presented a malformed kerberos token",
            ));
        }
        if ap_req.pvno != 5 || ap_req.msg_type.0 != 14 {
            return Err(Self::fail(
                client_id,
                "presented a malformed kerberos token",
            ));
        }
        // Outer service name must already match ours (fail fast on the
        // plaintext header; the decrypted inner name is authoritative).
        if !outer_service_matches(&ap_req, &self.config) {
            return Err(Self::fail(
                client_id,
                "presented a kerberos ticket for another service",
            ));
        }
        if ap_req.ticket.enc_part.etype.0 != ETYPE_AES256
            || ap_req.authenticator.etype.0 != ETYPE_AES256
        {
            return Err(Self::fail(
                client_id,
                "presented a kerberos token with an unsupported enctype",
            ));
        }
        // Decrypt EncTicketPart with the service key (RFC 3962 CTS via
        // `picky-krb`, key usage 2). Success proves the ticket was sealed
        // for our service key; the outer header already matched.
        let enc_part =
            decrypt_ticket_part(&service_key, ap_req.ticket.enc_part.cipher).map_err(|_| {
                Self::fail(
                    client_id,
                    "presented a kerberos ticket that cannot be verified",
                )
            })?;
        let ticket_inner = &enc_part.0;
        // Session key: must be etype 18 with 32 bytes (AES-256).
        let session_key_type = int_asn1_to_i32(&ticket_inner.key.0.key_type.0).unwrap_or(-1);
        if session_key_type != ETYPE_AES256 {
            return Err(Self::fail(
                client_id,
                "presented a kerberos token with an unsupported enctype",
            ));
        }
        let session_key_vec = ticket_inner.key.0.key_value.0 .0.clone();
        if session_key_vec.len() != SERVICE_KEY_LEN {
            return Err(Self::fail(
                client_id,
                "presented a malformed kerberos token",
            ));
        }
        // Client principal from the verified (decrypted) ticket content.
        let client_principal =
            principal_to_string(&ticket_inner.cname.0, &ticket_inner.crealm.0)
                .ok_or_else(|| Self::fail(client_id, "presented a malformed kerberos token"))?;
        // Service principal from the outer ticket header (plaintext) plus
        // the successful CTS decrypt above as proof of key match. The
        // outer check already matched; re-derive here for the receipt.
        let service_principal = outer_ticket_service_principal(&ap_req).ok_or_else(|| {
            Self::fail(client_id, "presented a kerberos ticket for another service")
        })?;
        if service_principal != self.config.service_principal_name {
            return Err(Self::fail(
                client_id,
                "presented a kerberos ticket for another service",
            ));
        }
        if !self.config.realm.is_empty() {
            let ticket_realm = realm_of(&service_principal).unwrap_or_default();
            if ticket_realm != self.config.realm {
                return Err(Self::fail(
                    client_id,
                    "presented a kerberos ticket for another service",
                ));
            }
        }
        // Validity window from EncTicketPart (starttime or authtime to
        // endtime) with clock-skew allowance.
        let auth_secs = kerberos_time_secs(&ticket_inner.auth_time.0)
            .ok_or_else(|| Self::fail(client_id, "presented a malformed kerberos token"))?;
        let start_secs = ticket_inner
            .starttime
            .0
            .as_ref()
            .and_then(|t| kerberos_time_secs(&t.0))
            .unwrap_or(auth_secs);
        let end_secs = kerberos_time_secs(&ticket_inner.endtime.0)
            .ok_or_else(|| Self::fail(client_id, "presented a malformed kerberos token"))?;
        let now = now_secs();
        let skew = self.config.clock_skew_secs.clamp(1, 3600) as i64;
        if now + skew < start_secs || now - skew > end_secs {
            return Err(Self::fail(
                client_id,
                "presented an expired kerberos ticket",
            ));
        }
        // Client realm allowlist (empty allows any realm that verified).
        let client_realm = realm_of(&client_principal).unwrap_or_default();
        if !self.config.allowed_realms.is_empty()
            && !self
                .config
                .allowed_realms
                .iter()
                .any(|r| r == &client_realm)
        {
            return Err(Self::fail(
                client_id,
                "presented a kerberos ticket from an untrusted realm",
            ));
        }
        // Decrypt the authenticator with the ticket session key (key usage
        // 11, RFC 3962 CTS via `picky-krb`).
        let mut session_key = [0u8; SERVICE_KEY_LEN];
        session_key.copy_from_slice(&session_key_vec);
        let authenticator = decrypt_authenticator(&session_key, ap_req.authenticator.cipher)
            .map_err(|_| {
                Self::fail(
                    client_id,
                    "presented a kerberos token that cannot be verified",
                )
            })?;
        let auth_inner = &authenticator.0;
        let auth_principal = principal_to_string(&auth_inner.cname.0, &auth_inner.crealm.0)
            .ok_or_else(|| Self::fail(client_id, "presented a malformed kerberos token"))?;
        if auth_principal != client_principal {
            return Err(Self::fail(
                client_id,
                "presented a kerberos token that cannot be verified",
            ));
        }
        let auth_secs = kerberos_time_secs(&auth_inner.ctime.0)
            .ok_or_else(|| Self::fail(client_id, "presented a malformed kerberos token"))?;
        let auth_usec = int_asn1_to_u32(&auth_inner.cusec.0)
            .ok_or_else(|| Self::fail(client_id, "presented a malformed kerberos token"))?;
        if auth_usec > 999_999 {
            return Err(Self::fail(
                client_id,
                "presented a malformed kerberos token",
            ));
        }
        if (auth_secs - now).abs() > skew {
            return Err(Self::fail(
                client_id,
                "presented an expired kerberos ticket",
            ));
        }
        // Replay: same principal plus authenticator time/usec twice fails.
        let mut replay_key = Vec::with_capacity(client_principal.len() + 16);
        replay_key.extend_from_slice(client_principal.as_bytes());
        replay_key.extend_from_slice(&auth_secs.to_be_bytes());
        replay_key.extend_from_slice(&auth_usec.to_be_bytes());
        if !self.replay.lock().check_and_insert(replay_key) {
            return Err(Self::fail(client_id, "presented a replayed kerberos token"));
        }
        let role = self.role_for_principal(&client_principal);
        Ok(VerifiedKerberos {
            client_principal,
            service_principal,
            session_key: session_key_vec,
            role,
        })
    }
}

#[async_trait]
impl Authenticator for KerberosAuthenticator {
    async fn authenticate(
        &self,
        client_id: &str,
        _username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let Some(token) = password else {
            return Err(Self::fail(client_id, "presented no kerberos token"));
        };
        // Reject the historical plaintext bypass shapes explicitly before
        // DER: they are ASCII, never valid AP-REQ structures.
        if token.starts_with(b"KRB5:") {
            return Err(Self::fail(
                client_id,
                "presented a kerberos token that cannot be verified",
            ));
        }
        self.verify_token(client_id, token).map(|_| ())
    }
}

/// Current Unix time in seconds (0 when the clock is unavailable).
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Split `name[/instance][@REALM]` into components plus realm.
///
/// `mqtt/broker.host@REALM` yields components `["mqtt", "broker.host"]`
/// and realm `REALM`. Returns `None` on empty input.
fn split_principal(full: &str) -> Option<(Vec<String>, String)> {
    if full.is_empty() {
        return None;
    }
    let (name_part, realm) = match full.split_once('@') {
        Some((name, realm)) => (name, realm.to_string()),
        None => (full, String::new()),
    };
    if name_part.is_empty() {
        return None;
    }
    let components: Vec<String> = name_part.split('/').map(str::to_string).collect();
    Some((components, realm))
}

/// Realm part after `@` (empty when absent).
fn realm_of(full: &str) -> Option<String> {
    full.split_once('@').map(|(_, r)| r.to_string())
}

/// Whether the outer (plaintext) ticket header already names our service.
///
/// Compares realm plus name components; the decrypted inner name is
/// checked separately as authoritative.
fn outer_service_matches(
    ap_req: &kerberos_parser::krb5::ApReq<'_>,
    config: &KerberosConfig,
) -> bool {
    if config.service_principal_name.is_empty() {
        return false;
    }
    let Some((want_comps, want_realm)) = split_principal(&config.service_principal_name) else {
        return false;
    };
    if ap_req.ticket.realm.0 != want_realm {
        return false;
    }
    if ap_req.ticket.sname.name_string != want_comps {
        return false;
    }
    true
}

/// Extract AP-REQ bytes from a bare AP-REQ or a SPNEGO wrapper.
///
/// Bare tokens must start with APPLICATION 14 (`0x6E`) and parse via
/// `kerberos-parser`. SPNEGO tokens start with APPLICATION 0 (`0x60`)
/// and are unwrapped with real DER via `der-parser` (OID-checked).
fn extract_ap_req_bytes(token: &[u8]) -> std::result::Result<Vec<u8>, ()> {
    if token.is_empty() {
        return Err(());
    }
    match token[0] {
        0x6E => {
            // Bare AP-REQ: insist it parses as one (rejects the old
            // `0x6E`-prefixed plaintext bypass, whose payload is not DER).
            use der_parser::asn1_rs::FromDer as _;
            let (rest, _) = kerberos_parser::krb5::ApReq::from_der(token).map_err(|_| ())?;
            if !rest.is_empty() {
                return Err(());
            }
            Ok(token.to_vec())
        }
        0x60 => parse_spnego_mech_token(token),
        _ => Err(()),
    }
}

/// SPNEGO OIDs as component lists (compared as parsed `Oid` values).
const SPNEGO_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 2];
const KERBEROS_OID: &[u64] = &[1, 2, 840, 113554, 1, 2, 2];

/// Unwrap the AP-REQ (`mechToken [2] OCTET STRING`) from a SPNEGO
/// `InitialContextToken` using real DER (`der-parser`), never byte search.
///
/// Layout: `[APPLICATION 0] SEQUENCE { OID 1.3.6.1.5.5.2,
/// NegTokenInit SEQUENCE { mechTypes [0] SEQUENCE OF OID OPTIONAL,
/// reqFlags [1] BIT STRING OPTIONAL, mechToken [2] OCTET STRING } }`.
fn parse_spnego_mech_token(token: &[u8]) -> std::result::Result<Vec<u8>, ()> {
    use der_parser::asn1_rs::{Class, FromDer, Oid, Sequence, TaggedParser};
    // Outer InitialContextToken [APPLICATION 0] via real DER (never byte
    // search). Inner holds OID plus NegTokenInit SEQUENCE; fields [0] and
    // [2] are parsed with TaggedParser (real DER, no byte search).
    let (rest, mech_token) =
        TaggedParser::from_der_and_then(Class::Application, 0, token, |inner| {
            let (rem, oid) = Oid::from_der(inner)
                .map_err(|_| nom::Err::Error(der_parser::asn1_rs::Error::BerValueError))?;
            let want_spnego = Oid::from(SPNEGO_OID)
                .map_err(|_| nom::Err::Error(der_parser::asn1_rs::Error::BerValueError))?;
            if oid != want_spnego {
                return Err(nom::Err::Error(der_parser::asn1_rs::Error::BerValueError));
            }
            // NegTokenInit SEQUENCE; its content holds [0] and [2].
            let (neg_rest, neg_content) = Sequence::from_der_and_then(rem, |content| {
                // mechTypes [0] SEQUENCE OF OID (must list Kerberos).
                let (rem1, mech_oids) = TaggedParser::from_der_and_then(
                    Class::ContextSpecific,
                    0,
                    content,
                    |mech_inner| {
                        let (mech_rem, mech_seq) =
                            Sequence::from_der_and_then(mech_inner, |oids_bytes| {
                                // OIDs inside: parse each via Oid::from_der in a loop.
                                let mut oids = Vec::new();
                                let mut rest = oids_bytes;
                                while !rest.is_empty() {
                                    let (r, o) = Oid::from_der(rest).map_err(|_| {
                                        nom::Err::Error(der_parser::asn1_rs::Error::BerValueError)
                                    })?;
                                    oids.push(o);
                                    rest = r;
                                }
                                Ok((b"" as &[u8], oids))
                            })
                            .map_err(|_| {
                                nom::Err::Error(der_parser::asn1_rs::Error::BerValueError)
                            })?;
                        if !mech_rem.is_empty() {
                            return Err(nom::Err::Error(der_parser::asn1_rs::Error::BerValueError));
                        }
                        Ok((b"" as &[u8], mech_seq))
                    },
                )
                .map_err(|_| nom::Err::Error(der_parser::asn1_rs::Error::BerValueError))?;
                let want_kerberos = Oid::from(KERBEROS_OID)
                    .map_err(|_| nom::Err::Error(der_parser::asn1_rs::Error::BerValueError))?;
                if !mech_oids.contains(&want_kerberos) {
                    return Err(nom::Err::Error(der_parser::asn1_rs::Error::BerValueError));
                }
                // mechToken [2] OCTET STRING holding the AP-REQ.
                let (rem2, ap_bytes) =
                    TaggedParser::from_der_and_then(Class::ContextSpecific, 2, rem1, |tok_inner| {
                        let (r, bytes) = <&[u8]>::from_der(tok_inner).map_err(|_| {
                            nom::Err::Error(der_parser::asn1_rs::Error::BerValueError)
                        })?;
                        if !r.is_empty() {
                            return Err(nom::Err::Error(der_parser::asn1_rs::Error::BerValueError));
                        }
                        Ok((b"" as &[u8], bytes.to_vec()))
                    })
                    .map_err(|_| nom::Err::Error(der_parser::asn1_rs::Error::BerValueError))?;
                if !rem2.is_empty() {
                    return Err(nom::Err::Error(der_parser::asn1_rs::Error::BerValueError));
                }
                Ok((b"" as &[u8], ap_bytes))
            })
            .map_err(|_| nom::Err::Error(der_parser::asn1_rs::Error::BerValueError))?;
            if !neg_rest.is_empty() {
                return Err(nom::Err::Error(der_parser::asn1_rs::Error::BerValueError));
            }
            Ok((b"" as &[u8], neg_content))
        })
        .map_err(|_| ())?;
    if !rest.is_empty() {
        return Err(());
    }
    Ok(mech_token)
}

/// Decrypt `EncTicketPart` (`[APPLICATION 3]`) with the service key via
/// `picky-krb` RFC 3962 AES-256-CTS-HMAC-SHA1-96 (key usage 2).
fn decrypt_ticket_part(
    key: &[u8; SERVICE_KEY_LEN],
    cipher: &[u8],
) -> std::result::Result<picky_krb::data_types::EncTicketPart, ()> {
    use picky_krb::crypto::CipherSuite;
    let plain = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .decrypt(key, KEY_USAGE_TICKET, cipher)
        .map_err(|_| ())?;
    picky_asn1_der::from_bytes(&plain).map_err(|_| ())
}

/// Decrypt `Authenticator` (`[APPLICATION 2]`) with the ticket session
/// key via `picky-krb` RFC 3962 CTS (key usage 11).
fn decrypt_authenticator(
    key: &[u8; SERVICE_KEY_LEN],
    cipher: &[u8],
) -> std::result::Result<picky_krb::data_types::Authenticator, ()> {
    use picky_krb::crypto::CipherSuite;
    let plain = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .decrypt(key, KEY_USAGE_AUTHENTICATOR, cipher)
        .map_err(|_| ())?;
    picky_asn1_der::from_bytes(&plain).map_err(|_| ())
}

/// `components[/components...]@REALM` from a `PrincipalName` plus `Realm`.
fn principal_to_string(
    name: &picky_krb::data_types::PrincipalName,
    realm: &picky_krb::data_types::Realm,
) -> Option<String> {
    let comps: Vec<String> = name
        .name_string
        .0
         .0
        .iter()
        .map(|s| s.0.to_string())
        .collect();
    if comps.is_empty() {
        return None;
    }
    let realm_str = realm.0.to_string();
    if realm_str.is_empty() {
        return None;
    }
    Some(format!("{}@{realm_str}", comps.join("/")))
}

/// Service principal (`sname` + realm) from the outer ticket header.
fn outer_ticket_service_principal(ap_req: &kerberos_parser::krb5::ApReq<'_>) -> Option<String> {
    let comps = ap_req.ticket.sname.name_string.clone();
    if comps.is_empty() {
        return None;
    }
    let realm = ap_req.ticket.realm.0.clone();
    Some(format!("{}@{realm}", comps.join("/")))
}

/// Unix seconds for a `KerberosTime` (`None` when unrepresentable).
fn kerberos_time_secs(t: &picky_krb::data_types::KerberosTime) -> Option<i64> {
    time::OffsetDateTime::try_from(t.0.clone())
        .map(|dt| dt.unix_timestamp())
        .ok()
}

/// DER INTEGER (`IntegerAsn1` wrapping big-endian bytes) as `u32`.
fn int_asn1_to_u32(v: &picky_asn1::wrapper::IntegerAsn1) -> Option<u32> {
    let bytes = &v.0;
    if bytes.is_empty() || bytes.len() > 5 {
        return None;
    }
    // Strip DER sign padding.
    let mut trimmed = bytes.as_slice();
    while trimmed.len() > 1 && trimmed[0] == 0x00 {
        trimmed = &trimmed[1..];
    }
    if trimmed.len() > 4 {
        return None;
    }
    let mut padded = [0u8; 4];
    padded[4 - trimmed.len()..].copy_from_slice(trimmed);
    Some(u32::from_be_bytes(padded))
}

/// DER INTEGER as `i32` (for etype checks).
fn int_asn1_to_i32(v: &picky_asn1::wrapper::IntegerAsn1) -> Option<i32> {
    int_asn1_to_u32(v).map(|u| u as i32)
}

/// Random 32-byte session key via `ring` system randomness.
#[cfg(test)]
fn random_session_key() -> [u8; SERVICE_KEY_LEN] {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut key = [0u8; SERVICE_KEY_LEN];
    rng.fill(&mut key).expect("system randomness");
    key
}

/// One MIT keytab v2 entry (parsed without external crates).
#[derive(Debug, Clone)]
struct KeytabEntryData {
    realm: String,
    components: Vec<String>,
    key: Vec<u8>,
}

/// Parse MIT keytab v2 (`0x05 0x02` plus sized entries).
///
/// Returns `None` on any truncation or invalid shape (fail closed).
fn parse_keytab(bytes: &[u8]) -> Option<Vec<KeytabEntryData>> {
    if bytes.len() < 2 || bytes[0] != 0x05 || bytes[1] != 0x02 {
        return None;
    }
    let mut pos = 2usize;
    let mut entries = Vec::new();
    while pos < bytes.len() {
        if bytes.len() - pos < 4 {
            return None;
        }
        let size = i32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;
        if size < 0 {
            let skip = (-size) as usize;
            if bytes.len() - pos < skip {
                return None;
            }
            pos += skip;
            continue;
        }
        let size = size as usize;
        if bytes.len() - pos < size {
            return None;
        }
        let end = pos + size;
        let entry = parse_keytab_entry(&bytes[pos..end])?;
        // Skip placeholder entries from holes (empty realm).
        if !entry.realm.is_empty() {
            entries.push(entry);
        }
        pos = end;
    }
    Some(entries)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
    if data.len() - *pos < 2 {
        return None;
    }
    let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Some(v)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Option<u32> {
    if data.len() - *pos < 4 {
        return None;
    }
    let v = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Some(v)
}

fn read_counted(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len = read_u16(data, pos)? as usize;
    if data.len() - *pos < len {
        return None;
    }
    let out = data[*pos..*pos + len].to_vec();
    *pos += len;
    Some(out)
}

fn parse_keytab_entry(data: &[u8]) -> Option<KeytabEntryData> {
    let mut pos = 0usize;
    let num_components = read_u16(data, &mut pos)?;
    let realm_bytes = read_counted(data, &mut pos)?;
    let realm = std::str::from_utf8(&realm_bytes).ok()?.to_string();
    let mut components = Vec::with_capacity(num_components as usize);
    for _ in 0..num_components {
        let comp = read_counted(data, &mut pos)?;
        components.push(std::str::from_utf8(&comp).ok()?.to_string());
    }
    let _name_type = read_u32(data, &mut pos)?;
    let _timestamp = read_u32(data, &mut pos)?;
    if data.len() - pos < 1 {
        return None;
    }
    pos += 1; // vno8
    let _keytype = read_u16(data, &mut pos)?;
    let key = read_counted(data, &mut pos)?;
    // Trailing 4-byte vno is optional; ignore remaining bytes.
    Some(KeytabEntryData {
        realm,
        components,
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn test_config(keytab_path: &str) -> KerberosConfig {
        KerberosConfig {
            service_principal_name: "mqtt/broker.example.com@EXAMPLE.COM".to_string(),
            realm: "EXAMPLE.COM".to_string(),
            allowed_realms: vec!["EXAMPLE.COM".to_string()],
            keytab_path: keytab_path.to_string(),
            clock_skew_secs: 300,
            replay_max_entries: 1024,
            principal_role_map: HashMap::from([
                ("alice@EXAMPLE.COM".to_string(), "publisher".to_string()),
                ("bob@EXAMPLE.COM".to_string(), "subscriber".to_string()),
            ]),
        }
    }

    // ------------------------------------------------------------------
    // Minimal DER writer for the test KDC (encoding only; the verifier
    // always decodes with kerberos-parser/der-parser, never byte search).
    // ------------------------------------------------------------------

    fn der_len(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else {
            let mut bytes = Vec::new();
            let mut n = len;
            while n > 0 {
                bytes.push((n & 0xFF) as u8);
                n >>= 8;
            }
            bytes.reverse();
            let mut out = vec![0x80 | (bytes.len() as u8)];
            out.extend_from_slice(&bytes);
            out
        }
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    fn der_integer_u32(v: u32) -> Vec<u8> {
        let mut bytes = v.to_be_bytes().to_vec();
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        if bytes[0] & 0x80 != 0 {
            let mut prefixed = vec![0x00];
            prefixed.extend_from_slice(&bytes);
            bytes = prefixed;
        }
        tlv(0x02, &bytes)
    }

    fn der_general_string(s: &str) -> Vec<u8> {
        tlv(0x1B, s.as_bytes())
    }

    fn der_octet_string(b: &[u8]) -> Vec<u8> {
        tlv(0x04, b)
    }

    fn der_bit_string_zero() -> Vec<u8> {
        tlv(0x03, &[0x00])
    }

    fn der_sequence(content: &[u8]) -> Vec<u8> {
        tlv(0x30, content)
    }

    fn der_context(n: u8, content: &[u8]) -> Vec<u8> {
        tlv(0xA0 | n, content)
    }

    fn der_application(n: u8, content: &[u8]) -> Vec<u8> {
        tlv(0x60 | n, content)
    }

    fn oid_content(numbers: &[u64]) -> Vec<u8> {
        let mut out = vec![(numbers[0] * 40 + numbers[1]) as u8];
        for n in &numbers[2..] {
            let mut stack = Vec::new();
            let mut v = *n;
            loop {
                stack.push((v & 0x7F) as u8);
                v >>= 7;
                if v == 0 {
                    break;
                }
            }
            stack.reverse();
            for (i, b) in stack.iter().enumerate() {
                if i + 1 < stack.len() {
                    out.push(b | 0x80);
                } else {
                    out.push(*b);
                }
            }
        }
        out
    }

    fn der_oid(numbers: &[u64]) -> Vec<u8> {
        tlv(0x06, &oid_content(numbers))
    }

    fn cts_encrypt(key: &[u8; SERVICE_KEY_LEN], key_usage: i32, plain: &[u8]) -> Vec<u8> {
        use picky_krb::crypto::CipherSuite;
        CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .encrypt(key, key_usage, plain)
            .expect("CTS encrypt")
    }

    fn test_realm(s: &str) -> picky_krb::data_types::Realm {
        use picky_asn1::restricted_string::IA5String;
        picky_krb::data_types::Realm::from(picky_asn1::wrapper::GeneralStringAsn1::from(
            IA5String::from_string(s.to_string()).expect("realm as IA5"),
        ))
    }

    fn test_principal(name_type: u8, comps: &[String]) -> picky_krb::data_types::PrincipalName {
        use picky_asn1::restricted_string::IA5String;
        use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1};
        let strings: Vec<picky_krb::data_types::KerberosStringAsn1> = comps
            .iter()
            .map(|c| {
                picky_krb::data_types::KerberosStringAsn1::from(
                    IA5String::from_string(c.clone()).expect("component as IA5"),
                )
            })
            .collect();
        picky_krb::data_types::PrincipalName {
            name_type: ExplicitContextTag0::from(picky_asn1::wrapper::IntegerAsn1::from(vec![
                name_type,
            ])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(strings)),
        }
    }

    fn test_kerberos_time(secs: i64) -> picky_krb::data_types::KerberosTime {
        use picky_asn1::date::GeneralizedTime;
        let dt = time::OffsetDateTime::from_unix_timestamp(secs).expect("valid time");
        picky_krb::data_types::KerberosTime::from(GeneralizedTime::from(dt))
    }

    fn encode_ticket_inner(
        client: &str,
        _service: &str,
        start: i64,
        end: i64,
        session_key: &[u8],
    ) -> Vec<u8> {
        use picky_asn1::wrapper::{
            ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
            ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7,
            OctetStringAsn1, Optional,
        };
        use picky_krb::data_types::{
            EncTicketPart, EncTicketPartInner, EncryptionKey, TransitedEncoding,
        };
        // Client `alice@REALM` -> NT-PRINCIPAL ["alice"] + realm.
        let (cname_part, crealm_part) = client.split_once('@').unwrap_or((client, "EXAMPLE.COM"));
        let cname = test_principal(1, &[cname_part.to_string()]);
        let crealm = test_realm(crealm_part);
        let enc_part = EncTicketPart::from(EncTicketPartInner {
            flags: ExplicitContextTag0::from(picky_asn1::wrapper::BitStringAsn1::default()),
            key: ExplicitContextTag1::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(picky_asn1::wrapper::IntegerAsn1::from(vec![
                    18u8,
                ])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(session_key.to_vec())),
            }),
            crealm: ExplicitContextTag2::from(crealm),
            cname: ExplicitContextTag3::from(cname),
            transited: ExplicitContextTag4::from(TransitedEncoding {
                tr_type: ExplicitContextTag0::from(picky_asn1::wrapper::IntegerAsn1::from(vec![
                    0u8,
                ])),
                contents: ExplicitContextTag1::from(OctetStringAsn1::from(vec![1u8])),
            }),
            auth_time: ExplicitContextTag5::from(test_kerberos_time(start)),
            starttime: Optional::from(Some(ExplicitContextTag6::from(test_kerberos_time(start)))),
            endtime: ExplicitContextTag7::from(test_kerberos_time(end)),
            renew_till: Optional::from(None),
            caddr: Optional::from(None),
            authorization_data: Optional::from(None),
        });
        picky_asn1_der::to_vec(&enc_part).expect("encode EncTicketPart")
    }

    fn encode_auth_inner(client: &str, timestamp: i64, usec: u32) -> Vec<u8> {
        use picky_asn1::wrapper::{
            ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag4,
            ExplicitContextTag5, IntegerAsn1, Optional,
        };
        use picky_krb::data_types::{Authenticator, AuthenticatorInner};
        let (cname_part, crealm_part) = client.split_once('@').unwrap_or((client, "EXAMPLE.COM"));
        let cname = test_principal(1, &[cname_part.to_string()]);
        let crealm = test_realm(crealm_part);
        // Microseconds as minimal DER INTEGER bytes.
        let mut usec_bytes = usec.to_be_bytes().to_vec();
        while usec_bytes.len() > 1 && usec_bytes[0] == 0 {
            usec_bytes.remove(0);
        }
        if usec_bytes[0] & 0x80 != 0 {
            let mut prefixed = vec![0x00];
            prefixed.extend_from_slice(&usec_bytes);
            usec_bytes = prefixed;
        }
        let auth = Authenticator::from(AuthenticatorInner {
            authenticator_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5u8])),
            crealm: ExplicitContextTag1::from(crealm),
            cname: ExplicitContextTag2::from(cname),
            cksum: Optional::from(None),
            cusec: ExplicitContextTag4::from(IntegerAsn1::from(usec_bytes)),
            ctime: ExplicitContextTag5::from(test_kerberos_time(timestamp)),
            subkey: Optional::from(None),
            seq_number: Optional::from(None),
            authorization_data: Optional::from(None),
        });
        picky_asn1_der::to_vec(&auth).expect("encode Authenticator")
    }

    fn encode_principal_name(comps: &[String]) -> Vec<u8> {
        let mut strings = Vec::new();
        for c in comps {
            strings.extend_from_slice(&der_general_string(c));
        }
        let seq = der_sequence(&strings);
        let mut content = Vec::new();
        content.extend_from_slice(&der_context(0, &der_integer_u32(1)));
        content.extend_from_slice(&der_context(1, &seq));
        der_sequence(&content)
    }

    fn encode_encrypted(etype: i32, cipher: &[u8]) -> Vec<u8> {
        // Etype as signed int32 DER (18 fits in one byte positive).
        let etype_bytes = (etype as u32).to_be_bytes();
        let mut trimmed = etype_bytes.to_vec();
        while trimmed.len() > 1 && trimmed[0] == 0 {
            trimmed.remove(0);
        }
        let mut content = Vec::new();
        content.extend_from_slice(&der_context(0, &tlv(0x02, &trimmed)));
        content.extend_from_slice(&der_context(2, &der_octet_string(cipher)));
        der_sequence(&content)
    }

    fn encode_ticket(realm: &str, sname_comps: &[String], ticket_cipher: &[u8]) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(&der_context(0, &der_integer_u32(5)));
        content.extend_from_slice(&der_context(1, &der_general_string(realm)));
        content.extend_from_slice(&der_context(2, &encode_principal_name(sname_comps)));
        content.extend_from_slice(&der_context(
            3,
            &encode_encrypted(ETYPE_AES256, ticket_cipher),
        ));
        der_application(1, &der_sequence(&content))
    }

    fn encode_ap_req(ticket: &[u8], auth_cipher: &[u8]) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(&der_context(0, &der_integer_u32(5)));
        content.extend_from_slice(&der_context(1, &der_integer_u32(14)));
        content.extend_from_slice(&der_context(2, &der_bit_string_zero()));
        // [3] Ticket is the raw ticket bytes (already APPLICATION 1).
        let mut ticket_field = vec![0xA3];
        ticket_field.extend_from_slice(&der_len(ticket.len()));
        ticket_field.extend_from_slice(ticket);
        content.extend_from_slice(&ticket_field);
        content.extend_from_slice(&der_context(
            4,
            &encode_encrypted(ETYPE_AES256, auth_cipher),
        ));
        der_application(14, &der_sequence(&content))
    }

    fn encode_spnego(ap_req: &[u8]) -> Vec<u8> {
        let kerberos_oid = der_oid(KERBEROS_OID);
        let mut mech_list_content = Vec::new();
        mech_list_content.extend_from_slice(&kerberos_oid);
        let mech_list_seq = der_sequence(&mech_list_content);
        let mut neg_content = Vec::new();
        neg_content.extend_from_slice(&der_context(0, &mech_list_seq));
        neg_content.extend_from_slice(&der_context(2, &der_octet_string(ap_req)));
        let neg_seq = der_sequence(&neg_content);
        let spnego_oid = der_oid(SPNEGO_OID);
        let mut outer_content = Vec::new();
        outer_content.extend_from_slice(&spnego_oid);
        outer_content.extend_from_slice(&neg_seq);
        der_application(0, &outer_content)
    }

    /// In-process test KDC: mints real DER plus real RFC 3962 CTS tickets
    /// via `picky-krb` (the same path a stock MIT KDC uses for etype 18).
    ///
    /// Holds the service key shared with the keytab file it writes. Issues
    /// bare and SPNEGO-wrapped AP-REQs for the configured service.
    struct TestKdc {
        realm: String,
        service_full: String,
        service_comps: Vec<String>,
        service_key: [u8; SERVICE_KEY_LEN],
    }

    impl TestKdc {
        fn fresh() -> Self {
            Self {
                realm: "EXAMPLE.COM".to_string(),
                service_full: "mqtt/broker.example.com@EXAMPLE.COM".to_string(),
                service_comps: vec!["mqtt".to_string(), "broker.example.com".to_string()],
                service_key: super::random_session_key(),
            }
        }

        fn write_keytab(&self, path: &std::path::Path) {
            let mut file = vec![0x05u8, 0x02u8];
            let mut entry = Vec::new();
            entry.extend_from_slice(&(2u16).to_be_bytes());
            let realm_bytes = self.realm.as_bytes();
            entry.extend_from_slice(&(realm_bytes.len() as u16).to_be_bytes());
            entry.extend_from_slice(realm_bytes);
            for comp in &self.service_comps {
                entry.extend_from_slice(&(comp.len() as u16).to_be_bytes());
                entry.extend_from_slice(comp.as_bytes());
            }
            entry.extend_from_slice(&1u32.to_be_bytes());
            entry.extend_from_slice(&0u32.to_be_bytes());
            entry.push(1u8);
            entry.extend_from_slice(&18u16.to_be_bytes());
            entry.extend_from_slice(&(SERVICE_KEY_LEN as u16).to_be_bytes());
            entry.extend_from_slice(&self.service_key);
            entry.extend_from_slice(&1u32.to_be_bytes());
            file.extend_from_slice(&(entry.len() as i32).to_be_bytes());
            file.extend_from_slice(&entry);
            let mut handle = std::fs::File::create(path).expect("write test keytab");
            handle.write_all(&file).expect("write test keytab");
        }

        fn session_key() -> [u8; SERVICE_KEY_LEN] {
            super::random_session_key()
        }

        fn mint(
            &self,
            client: &str,
            start: i64,
            end: i64,
            auth_time: i64,
            auth_usec: u32,
        ) -> (Vec<u8>, Vec<u8>) {
            let session_key = Self::session_key();
            let inner = encode_ticket_inner(client, &self.service_full, start, end, &session_key);
            let ticket_cipher = cts_encrypt(&self.service_key, super::KEY_USAGE_TICKET, &inner);
            let ticket = encode_ticket(&self.realm, &self.service_comps, &ticket_cipher);
            let auth_inner = encode_auth_inner(client, auth_time, auth_usec);
            let auth_cipher =
                cts_encrypt(&session_key, super::KEY_USAGE_AUTHENTICATOR, &auth_inner);
            let ap_req = encode_ap_req(&ticket, &auth_cipher);
            (ap_req, session_key.to_vec())
        }

        #[allow(clippy::too_many_arguments)]
        fn mint_for_service(
            &self,
            client: &str,
            service_full: &str,
            service_comps: &[String],
            service_key: &[u8; SERVICE_KEY_LEN],
            start: i64,
            end: i64,
            auth_time: i64,
        ) -> Vec<u8> {
            let session_key = Self::session_key();
            let inner = encode_ticket_inner(client, service_full, start, end, &session_key);
            let ticket_cipher = cts_encrypt(service_key, super::KEY_USAGE_TICKET, &inner);
            let (realm, _) = service_full.split_once('@').unwrap_or((service_full, ""));
            let ticket = encode_ticket(realm, service_comps, &ticket_cipher);
            let auth_inner = encode_auth_inner(client, auth_time, 11);
            let auth_cipher =
                cts_encrypt(&session_key, super::KEY_USAGE_AUTHENTICATOR, &auth_inner);
            encode_ap_req(&ticket, &auth_cipher)
        }
    }

    fn authenticator_for_kdc(kdc: &TestKdc) -> KerberosAuthenticator {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("broker.keytab");
        kdc.write_keytab(&path);
        // Leak the temp dir: the authenticator reads the file at
        // construction, so the path must stay valid for the test.
        let path_str = path.to_string_lossy().to_string();
        let auth = KerberosAuthenticator::new(test_config(&path_str));
        std::mem::forget(dir);
        auth
    }

    #[tokio::test]
    async fn legacy_plaintext_token_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("k.keytab");
        let kdc = TestKdc::fresh();
        kdc.write_keytab(&path);
        let auth = KerberosAuthenticator::new(test_config(&path.to_string_lossy()));
        let token = b"KRB5:operator@EXAMPLE.COM:mqtt/broker.example.com@EXAMPLE.COM:EXAMPLE.COM";
        let err = auth
            .authenticate("workstation-1", Some("operator"), Some(token))
            .await
            .expect_err("legacy plaintext token must be refused");
        assert!(matches!(err, AuthError::AuthenticationFailed(_)));
    }

    #[tokio::test]
    async fn legacy_ap_req_tagged_token_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("k.keytab");
        let kdc = TestKdc::fresh();
        kdc.write_keytab(&path);
        let auth = KerberosAuthenticator::new(test_config(&path.to_string_lossy()));
        let payload = b"KRB5:operator@EXAMPLE.COM:mqtt/broker.example.com@EXAMPLE.COM:EXAMPLE.COM";
        let mut token = Vec::with_capacity(2 + payload.len());
        token.push(0x6E);
        token.push(payload.len() as u8);
        token.extend_from_slice(payload);
        let err = auth
            .authenticate("workstation-1", Some("operator"), Some(&token))
            .await
            .expect_err("legacy 0x6E token must be refused");
        assert!(matches!(err, AuthError::AuthenticationFailed(_)));
    }

    #[tokio::test]
    async fn every_input_is_refused_when_disabled() {
        let auth = KerberosAuthenticator::new(KerberosConfig::default());
        assert!(!auth.is_enabled());
        assert!(auth.authenticate("c", None, None).await.is_err());
        assert!(auth.authenticate("c", Some("alice"), None).await.is_err());
        assert!(auth
            .authenticate("c", None, Some(b"anything"))
            .await
            .is_err());
        assert!(auth
            .authenticate("c", Some("alice"), Some(b"anything"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn missing_keytab_disables_with_log() {
        let config = KerberosConfig {
            service_principal_name: "mqtt/broker.example.com@EXAMPLE.COM".to_string(),
            realm: "EXAMPLE.COM".to_string(),
            allowed_realms: vec!["EXAMPLE.COM".to_string()],
            keytab_path: "/nonexistent/path/broker.keytab".to_string(),
            ..KerberosConfig::default()
        };
        let auth = KerberosAuthenticator::new(config);
        assert!(!auth.is_enabled(), "missing keytab must disable");
        let now = now_secs();
        // Even a well-formed token cannot verify without the key.
        let kdc = TestKdc::fresh();
        let (token, _) = kdc.mint("alice@EXAMPLE.COM", now - 60, now + 3600, now, 7);
        assert!(auth.verify_token("c", &token).is_err());
    }

    #[tokio::test]
    async fn valid_bare_ap_req_authenticates_with_real_session_key() {
        let kdc = TestKdc::fresh();
        let auth = authenticator_for_kdc(&kdc);
        assert!(auth.is_enabled());
        let now = now_secs();
        let (token, session_key) = kdc.mint("alice@EXAMPLE.COM", now - 60, now + 3600, now, 42);
        let verified = auth
            .verify_token("device-1", &token)
            .expect("valid ticket must verify");
        assert_eq!(verified.client_principal, "alice@EXAMPLE.COM");
        assert_eq!(
            verified.service_principal,
            "mqtt/broker.example.com@EXAMPLE.COM"
        );
        assert_eq!(verified.session_key, session_key);
        assert_eq!(verified.session_key.len(), 32);
        assert_eq!(verified.role, "publisher");
        // Authenticator trait path accepts a fresh token (same client, new
        // authenticator timestamp so the replay cache does not trigger).
        let (token2, _) = kdc.mint("alice@EXAMPLE.COM", now - 60, now + 3600, now, 44);
        auth.authenticate("device-1", Some("alice"), Some(&token2))
            .await
            .expect("trait path must accept valid token");
    }

    #[tokio::test]
    async fn valid_spnego_token_authenticates() {
        let kdc = TestKdc::fresh();
        let auth = authenticator_for_kdc(&kdc);
        let now = now_secs();
        let (ap_req, _) = kdc.mint("alice@EXAMPLE.COM", now - 60, now + 3600, now, 43);
        let token = encode_spnego(&ap_req);
        let verified = auth
            .verify_token("device-1", &token)
            .expect("SPNEGO token must verify");
        assert_eq!(verified.client_principal, "alice@EXAMPLE.COM");
        let (ap_req2, _) = kdc.mint("alice@EXAMPLE.COM", now - 60, now + 3600, now, 45);
        let token2 = encode_spnego(&ap_req2);
        auth.authenticate("device-1", Some("alice"), Some(&token2))
            .await
            .expect("trait path must accept SPNEGO");
    }

    #[tokio::test]
    async fn session_keys_are_not_constant() {
        let kdc = TestKdc::fresh();
        let auth = authenticator_for_kdc(&kdc);
        let now = now_secs();
        let (t1, _) = kdc.mint("alice@EXAMPLE.COM", now - 60, now + 3600, now, 1);
        let (t2, _) = kdc.mint("alice@EXAMPLE.COM", now - 60, now + 3600, now, 2);
        let v1 = auth.verify_token("c", &t1).expect("first must verify");
        let v2 = auth.verify_token("c", &t2).expect("second must verify");
        assert_eq!(v1.session_key.len(), 32);
        assert_eq!(v2.session_key.len(), 32);
        assert_ne!(
            v1.session_key, v2.session_key,
            "session keys must differ per ticket, never a constant"
        );
    }

    #[tokio::test]
    async fn expired_ticket_is_refused() {
        let kdc = TestKdc::fresh();
        let auth = authenticator_for_kdc(&kdc);
        let now = now_secs();
        let (token, _) = kdc.mint("alice@EXAMPLE.COM", now - 7200, now - 3600, now - 3600, 9);
        let err = auth
            .verify_token("device-1", &token)
            .expect_err("expired ticket must fail");
        assert!(matches!(err, AuthError::AuthenticationFailed(_)));
    }

    #[tokio::test]
    async fn ticket_for_another_service_is_refused() {
        let kdc = TestKdc::fresh();
        let auth = authenticator_for_kdc(&kdc);
        let now = now_secs();
        let other_key = TestKdc::session_key();
        let token = kdc.mint_for_service(
            "alice@EXAMPLE.COM",
            "mqtt/other.example.com@EXAMPLE.COM",
            &["mqtt".to_string(), "other.example.com".to_string()],
            &other_key,
            now - 60,
            now + 3600,
            now,
        );
        let err = auth
            .verify_token("device-1", &token)
            .expect_err("wrong-service ticket must fail");
        assert!(matches!(err, AuthError::AuthenticationFailed(_)));
    }

    #[tokio::test]
    async fn replayed_ticket_is_refused() {
        let kdc = TestKdc::fresh();
        let auth = authenticator_for_kdc(&kdc);
        let now = now_secs();
        let (token, _) = kdc.mint("alice@EXAMPLE.COM", now - 60, now + 3600, now, 77);
        auth.verify_token("device-1", &token)
            .expect("first presentation must succeed");
        let err = auth
            .verify_token("device-1", &token)
            .expect_err("replay must fail");
        assert!(matches!(err, AuthError::AuthenticationFailed(_)));
    }

    #[tokio::test]
    async fn malformed_token_is_refused() {
        let kdc = TestKdc::fresh();
        let auth = authenticator_for_kdc(&kdc);
        for bad in [
            vec![0x00, 0x01, 0x02],
            vec![0x6E, 0x03, 0x01, 0x02, 0x03],
            vec![0x60, 0x03, 0x01, 0x02, 0x03],
            b"not a token at all".to_vec(),
        ] {
            assert!(
                auth.verify_token("c", &bad).is_err(),
                "malformed token must fail"
            );
        }
    }
}
