use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use tracing::{error, info, warn};

/// Token prefix for hardware-rooted (ECDSA P-256) enterprise licences.
///
/// `INDRA-ENT-V1` tokens were Ed25519 with a single compiled-in key and are
/// no longer accepted. Every V2 payload carries the `kid` it was signed
/// with; verification selects the key by that id and fails closed on an
/// unknown id so a retired key stays trusted until its last licence expires
/// while a forged id never verifies.
pub const TOKEN_PREFIX: &str = "INDRA-ENT-V2";

/// Days of trial for a fresh installation with no licence.
pub const TRIAL_DAYS: u64 = 90;
/// Default grace period past expiry during which entitlements keep working.
pub const DEFAULT_GRACE_DAYS: u64 = 90;
/// Seconds in one day, for trial and grace arithmetic.
pub const SECS_PER_DAY: u64 = 86_400;
/// Entitlements this product version understands.
pub const KNOWN_ENTITLEMENTS: &[&str] = &["clustering"];
/// Name of the persisted cluster-identity file inside the data directory.
pub const IDENTITY_FILE_NAME: &str = "cluster_identity.json";
/// Name of the persisted licence-token file inside the data directory.
pub const LICENCE_FILE_NAME: &str = "licence.token";

fn default_grace_days() -> u64 {
    DEFAULT_GRACE_DAYS
}

/// True for an entitlement this build knows how to enforce.
#[must_use]
pub fn is_known_entitlement(name: &str) -> bool {
    KNOWN_ENTITLEMENTS.contains(&name)
}

fn validate_entitlements(features: &[String]) -> Result<(), String> {
    for feature in features {
        let name = feature.trim();
        if name.is_empty() {
            return Err("licence carries an empty entitlement".to_string());
        }
        if !is_known_entitlement(name) {
            return Err(format!("unknown entitlement '{name}'"));
        }
    }
    Ok(())
}

/// Licensing status for the distributed clustering engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseStatus {
    /// Permissive Community Evaluation Mode (Non-Production trial).
    CommunityEvaluation { max_eval_nodes: usize },
    /// Valid active Enterprise Commercial License.
    EnterpriseValid {
        customer: String,
        max_nodes: usize,
        expires_at: u64,
        features: Vec<String>,
    },
    /// Past expiry but inside the grace period: every entitlement keeps
    /// working. Distinct from expired so operators can see the difference.
    Grace {
        customer: String,
        expires_at: u64,
        days_remaining: u64,
        max_nodes: usize,
        features: Vec<String>,
    },
    /// Expired Enterprise License (past expiry plus the grace period).
    Expired { customer: String, expired_at: u64 },
    /// Cluster size exceeds the purchased node quota.
    QuotaExceeded {
        customer: String,
        current_nodes: usize,
        max_nodes: usize,
    },
    /// Malformed or cryptographic signature mismatch.
    InvalidSignature(String),
}

impl fmt::Display for LicenseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LicenseStatus::CommunityEvaluation { max_eval_nodes } => {
                write!(
                    f,
                    "Community Evaluation Mode (Non-Production, Max {} nodes)",
                    max_eval_nodes
                )
            }
            LicenseStatus::EnterpriseValid {
                customer,
                max_nodes,
                expires_at,
                ..
            } => {
                write!(
                    f,
                    "Enterprise Commercial License: '{}' (Max {} nodes, Expires at {})",
                    customer, max_nodes, expires_at
                )
            }
            LicenseStatus::Grace {
                customer,
                expires_at,
                days_remaining,
                ..
            } => {
                write!(
                    f,
                    "Enterprise License GRACE for '{}' expired at {} ({} days remaining)",
                    customer, expires_at, days_remaining
                )
            }
            LicenseStatus::Expired {
                customer,
                expired_at,
            } => {
                write!(
                    f,
                    "Enterprise License EXPIRED for '{}' at timestamp {}",
                    customer, expired_at
                )
            }
            LicenseStatus::QuotaExceeded {
                customer,
                current_nodes,
                max_nodes,
            } => {
                write!(
                    f,
                    "Enterprise Node Quota Exceeded for '{}': active {} nodes exceeds limit of {}",
                    customer, current_nodes, max_nodes
                )
            }
            LicenseStatus::InvalidSignature(reason) => {
                write!(f, "Invalid Enterprise License: {}", reason)
            }
        }
    }
}

/// JSON payload embedded inside an enterprise license token.
///
/// Field order is the canonical order: the signing tool serialises this
/// struct with `serde_json::to_vec` (struct order, no whitespace) and the
/// signature covers exactly those bytes, so the same licence always signs
/// the same bytes. Verification checks the signature over the transmitted
/// bytes rather than re-serialising, so no second canonicaliser can drift.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicensePayload {
    pub customer: String,
    pub max_nodes: usize,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub features: Vec<String>,
    /// Node identity this licence was issued for. Verification requires an
    /// exact match against the local node id.
    pub node_id: String,
    /// Id of the signing key, copied from the licence request ceremony.
    /// Selects the verifying key out of the trusted set; the signature
    /// covers this field, so relabelling a token voids it.
    #[serde(default)]
    pub kid: String,
    /// Grace period in days past `expires_at` during which every
    /// entitlement keeps working. Carried in the licence so a customer can
    /// be given longer without a new build; defaults to 90 days.
    #[serde(default = "default_grace_days")]
    pub grace_period_days: u64,
}

/// Serialise a payload to the canonical bytes that are signed.
///
/// This is the single definition of "canonical": struct field order, no
/// whitespace, `serde_json::to_vec`. The offline signing tool builds the
/// same struct in the same order; keeping the function here documents the
/// contract without giving the shipped crate any way to sign.
pub fn canonical_json_bytes(payload: &LicensePayload) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(payload)
}

/// Set of trusted licence-signing public keys, loaded from configuration.
///
/// Keys are configuration, not constants: the broker loads them at startup
/// from a JSON file or a directory of JSON files and logs the key ids it
/// will accept. Adding a key enrols a new token device; removing one
/// retires it. Retired keys must stay in the file until the last licence
/// they signed expires, otherwise those licences stop verifying.
#[derive(Debug, Clone, Default)]
pub struct TrustedKeys {
    keys: HashMap<String, VerifyingKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustedKeyEntry {
    kid: String,
    /// Hex of the SEC1 encoding (compressed 33 bytes or uncompressed 65).
    public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustedKeysFile {
    #[serde(default)]
    keys: Vec<TrustedKeyEntry>,
}

fn valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= 128
        && kid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn decode_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length ({})", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| format!("invalid hex at offset {i}"))?;
        out.push(byte);
    }
    Ok(out)
}

impl TrustedKeys {
    /// Empty trust set: verifies nothing, so every enterprise token is
    /// rejected as an unknown key while community mode still boots.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one trusted key. Public keys only; there is no signing path
    /// in this crate, so inserting a key can never mint a token.
    pub fn insert(&mut self, kid: String, key: VerifyingKey) {
        self.keys.insert(kid, key);
    }

    /// Number of trusted keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set holds no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Sorted key ids, for boot logging and operator visibility.
    pub fn kids(&self) -> Vec<String> {
        let mut kids: Vec<String> = self.keys.keys().cloned().collect();
        kids.sort();
        kids
    }

    fn insert_entry(&mut self, entry: TrustedKeyEntry, origin: &str) -> Result<(), String> {
        let kid = entry.kid.trim().to_string();
        if !valid_kid(&kid) {
            return Err(format!(
                "{origin}: invalid key id {kid:?}: use 1-128 chars of [A-Za-z0-9._-]"
            ));
        }
        if self.keys.contains_key(&kid) {
            return Err(format!("{origin}: duplicate key id {kid:?}"));
        }
        let raw = decode_hex_bytes(&entry.public_key_hex)
            .map_err(|e| format!("{origin}: key {kid:?}: {e}"))?;
        if raw.len() != 33 && raw.len() != 65 {
            return Err(format!(
                "{origin}: key {kid:?}: expected 33 or 65 SEC1 bytes, got {}",
                raw.len()
            ));
        }
        let key = VerifyingKey::from_sec1_bytes(&raw)
            .map_err(|_| format!("{origin}: key {kid:?}: not a valid P-256 SEC1 public key"))?;
        self.keys.insert(kid, key);
        Ok(())
    }

    fn load_file_into(&mut self, path: &Path) -> Result<(), String> {
        let origin = path.display().to_string();
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("cannot read {origin}: {e}"))?;
        let file: TrustedKeysFile =
            serde_json::from_str(&text).map_err(|e| format!("{origin}: malformed JSON: {e}"))?;
        if file.keys.is_empty() {
            return Err(format!("{origin}: no keys listed"));
        }
        for entry in file.keys {
            self.insert_entry(entry, &origin)?;
        }
        Ok(())
    }

    /// Load the trusted set from a path naming either a JSON file of the
    /// form `{"keys": [{"kid": "...", "public_key_hex": "..."}]}` or a
    /// directory of such files (merged, `*.json`, sorted by file name).
    /// Any error fails closed: the caller must refuse to boot enterprise
    /// features rather than run with a half-loaded set.
    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let mut set = Self::new();
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("cannot open trusted keys at {}: {e}", path.display()))?;
        if meta.is_dir() {
            let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(path)
                .map_err(|e| format!("cannot list {}: {e}", path.display()))?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
                .collect();
            files.sort();
            if files.is_empty() {
                return Err(format!(
                    "no trusted key files (*.json) in {}",
                    path.display()
                ));
            }
            for file in files {
                set.load_file_into(&file)?;
            }
        } else {
            set.load_file_into(path)?;
        }
        Ok(set)
    }

    /// Log the trusted set at boot so an operator can see what this node
    /// will accept. Called once from the kernel boot path.
    pub fn log_at_boot(&self) {
        if self.is_empty() {
            warn!("licence trust set is empty: enterprise licences will be rejected");
        } else {
            info!(
                "licence trust set: {} key(s): {}",
                self.len(),
                self.kids().join(", ")
            );
        }
    }
}

/// Core license verification engine for `crates/broker-cluster`.
///
/// Verification only: this crate cannot mint tokens. Signing lives in
/// `tools/license-signer`, outside the workspace build, against a hardware
/// token that never releases the private key.
pub struct ClusterLicense;

impl ClusterLicense {
    /// Default node limit permitted under Community Evaluation mode without a commercial key.
    pub const DEFAULT_EVAL_NODES: usize = 3;

    /// Evaluate an optional license key against current cluster conditions.
    ///
    /// `expected_node_id` is the local node identity the licence must be
    /// bound to, and `trusted` is the configured key set. Expiry and node
    /// binding are both enforced; any failure returns an explicit
    /// non-valid status and never falls back to community mode. A token
    /// naming an unknown key id is rejected without consulting any key.
    pub fn evaluate(
        key: Option<&str>,
        current_nodes: usize,
        current_epoch_sec: u64,
        expected_node_id: &str,
        trusted: &TrustedKeys,
    ) -> LicenseStatus {
        let key_str = match key {
            Some(k) if !k.trim().is_empty() => k.trim(),
            _ => {
                return LicenseStatus::CommunityEvaluation {
                    max_eval_nodes: Self::DEFAULT_EVAL_NODES,
                };
            }
        };

        // Format: INDRA-ENT-V2.<PAYLOAD_B64URL>.<SIGNATURE_B64URL>
        // where the signature is a detached ECDSA P-256 (SHA-256) signature
        // over the raw canonical JSON payload bytes, and the payload carries
        // the `kid` selecting the verifying key.
        let mut parts = key_str.split('.');
        let (Some(prefix), Some(payload_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return LicenseStatus::InvalidSignature("Unsupported license token format".into());
        };
        if prefix != TOKEN_PREFIX {
            return LicenseStatus::InvalidSignature(
                "Unsupported license token format (expected INDRA-ENT-V2)".into(),
            );
        }

        let payload_bytes = match URL_SAFE_NO_PAD.decode(payload_b64) {
            Ok(b) => b,
            Err(_) => {
                return LicenseStatus::InvalidSignature(
                    "Invalid encoding in license payload".into(),
                );
            }
        };
        let sig_bytes = match URL_SAFE_NO_PAD.decode(sig_b64) {
            Ok(b) => b,
            Err(_) => {
                return LicenseStatus::InvalidSignature(
                    "Invalid encoding in license signature".into(),
                );
            }
        };
        if sig_bytes.len() != 64 {
            return LicenseStatus::InvalidSignature("Malformed license signature".into());
        }
        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => {
                return LicenseStatus::InvalidSignature("Malformed license signature".into());
            }
        };

        // Select the key by the id carried in the (still unverified)
        // payload. Nothing else in the payload is trusted before the
        // signature check below.
        let unverified: LicensePayload = match serde_json::from_slice(&payload_bytes) {
            Ok(p) => p,
            Err(e) => {
                return LicenseStatus::InvalidSignature(format!("Malformed payload JSON: {e}"));
            }
        };
        if unverified.kid.trim().is_empty() {
            return LicenseStatus::InvalidSignature("licence missing key id".into());
        }
        let verifying_key = match trusted.keys.get(unverified.kid.trim()) {
            Some(k) => k,
            None => {
                return LicenseStatus::InvalidSignature(format!(
                    "unknown signing key '{}'",
                    unverified.kid.trim()
                ));
            }
        };
        if verifying_key.verify(&payload_bytes, &signature).is_err() {
            return LicenseStatus::InvalidSignature("Cryptographic signature mismatch".into());
        }

        let payload = unverified;
        if payload.node_id.trim().is_empty() {
            return LicenseStatus::InvalidSignature("licence missing node binding".into());
        }
        if payload.node_id != expected_node_id {
            return LicenseStatus::InvalidSignature(format!(
                "licence identity mismatch: issued for '{}', not '{}'",
                payload.node_id, expected_node_id
            ));
        }
        if let Err(reason) = validate_entitlements(&payload.features) {
            return LicenseStatus::InvalidSignature(format!("unknown entitlement: {reason}"));
        }

        // Expiry is not a cliff: past expiry but inside the grace window
        // reports grace with days remaining and keeps every entitlement
        // working; only past grace reports expired.
        if current_epoch_sec > payload.expires_at {
            let grace_secs = payload.grace_period_days.saturating_mul(SECS_PER_DAY);
            let elapsed = current_epoch_sec.saturating_sub(payload.expires_at);
            if elapsed <= grace_secs {
                let remaining_secs = grace_secs.saturating_sub(elapsed);
                let days_remaining = remaining_secs / SECS_PER_DAY;
                return LicenseStatus::Grace {
                    customer: payload.customer,
                    expires_at: payload.expires_at,
                    days_remaining,
                    max_nodes: payload.max_nodes,
                    features: payload.features,
                };
            }
            return LicenseStatus::Expired {
                customer: payload.customer,
                expired_at: payload.expires_at,
            };
        }

        // Check node quota
        if current_nodes > payload.max_nodes {
            return LicenseStatus::QuotaExceeded {
                customer: payload.customer,
                current_nodes,
                max_nodes: payload.max_nodes,
            };
        }

        LicenseStatus::EnterpriseValid {
            customer: payload.customer,
            max_nodes: payload.max_nodes,
            expires_at: payload.expires_at,
            features: payload.features,
        }
    }

    /// Log a prominent operational notice reflecting license state.
    pub fn log_status_banner(status: &LicenseStatus) {
        match status {
            LicenseStatus::CommunityEvaluation { max_eval_nodes } => {
                warn!("================================================================================");
                warn!(
                    " [LICENSE NOTICE] IndraMQTT Clustering running in COMMUNITY EVALUATION MODE"
                );
                warn!(
                    " Non-production use only. Max evaluation cluster limit: {} nodes.",
                    max_eval_nodes
                );
                warn!(" For commercial production clustering licenses: sales@i-dacs.com");
                warn!("================================================================================");
            }
            LicenseStatus::EnterpriseValid {
                customer,
                max_nodes,
                expires_at,
                ..
            } => {
                info!("================================================================================");
                info!(" [LICENSE ACTIVE] IndraMQTT Enterprise Clustering Validated");
                info!(" Licensed Customer : {}", customer);
                info!(" Node Quota         : {} nodes", max_nodes);
                info!(" Expiration Epoch   : {}", expires_at);
                info!("================================================================================");
            }
            LicenseStatus::Grace {
                customer,
                expires_at,
                days_remaining,
                ..
            } => {
                warn!("================================================================================");
                warn!(
                    " [LICENSE GRACE] Enterprise licence for '{}' expired at {}; {} days remaining",
                    customer, expires_at, days_remaining
                );
                warn!(" Renew promptly: entitlements stop when grace runs out.");
                warn!("================================================================================");
            }
            LicenseStatus::Expired {
                customer,
                expired_at,
            } => {
                error!("================================================================================");
                error!(
                    " [LICENSE EXPIRED] Enterprise clustering license for '{}' expired at {}",
                    customer, expired_at
                );
                error!(" Please renew your commercial license: sales@i-dacs.com");
                error!("================================================================================");
            }
            LicenseStatus::QuotaExceeded {
                customer,
                current_nodes,
                max_nodes,
            } => {
                error!("================================================================================");
                error!(" [LICENSE QUOTA] Cluster size ({} nodes) exceeds purchased quota ({} nodes) for '{}'", current_nodes, max_nodes, customer);
                error!(" Contact sales@i-dacs.com to expand your cluster node quota.");
                error!("================================================================================");
            }
            LicenseStatus::InvalidSignature(reason) => {
                error!("================================================================================");
                error!(
                    " [LICENSE ERROR] Enterprise license validation failed: {}",
                    reason
                );
                error!("================================================================================");
            }
        }
    }
}

/// Distinct rejection reason for licence installation.
///
/// Every variant renders with a distinct prefix so an operator copying a
/// licence to a second cluster (identity mismatch) is never confused with
/// a forged token (signature mismatch), an expired token, an unknown
/// signing key, an unknown entitlement, or a malformed token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallError {
    Malformed(String),
    UnknownKey(String),
    InvalidSignature(String),
    IdentityMismatch { expected: String, found: String },
    Expired { expired_at: u64 },
    UnknownEntitlement(String),
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstallError::Malformed(reason) => write!(f, "malformed licence: {reason}"),
            InstallError::UnknownKey(kid) => write!(f, "unknown signing key '{kid}'"),
            InstallError::InvalidSignature(reason) => {
                write!(f, "invalid signature: {reason}")
            }
            InstallError::IdentityMismatch { expected, found } => write!(
                f,
                "licence identity mismatch: issued for '{found}', not '{expected}'"
            ),
            InstallError::Expired { expired_at } => {
                write!(f, "licence expired at {expired_at}")
            }
            InstallError::UnknownEntitlement(reason) => {
                write!(f, "unknown entitlement: {reason}")
            }
        }
    }
}

impl std::error::Error for InstallError {}

fn install_malformed(reason: impl Into<String>) -> InstallError {
    InstallError::Malformed(reason.into())
}

/// Verify a licence token for installation against this installation.
///
/// Checks, in order: token shape, base64 and signature encodings,
/// payload JSON, signing-key selection by key id (unknown key is its own
/// reason), ECDSA P-256 signature, cluster-identity binding (mismatch is
/// its own reason, distinct from a bad signature), expiry at `now_secs`,
/// and entitlements this build understands. Returns the verified payload;
/// storing is left to the caller so a failed install never touches the
/// previously stored licence.
pub fn verify_for_install(
    token: &str,
    expected_identity: &str,
    trusted: &TrustedKeys,
    now_secs: u64,
) -> Result<LicensePayload, InstallError> {
    let token = token.trim();
    let mut parts = token.split('.');
    let (prefix, payload_b64, sig_b64, rest) =
        (parts.next(), parts.next(), parts.next(), parts.next());
    match (prefix, payload_b64, sig_b64, rest) {
        (Some(prefix), Some(payload_b64), Some(sig_b64), None) if prefix == TOKEN_PREFIX => {
            let payload_bytes = URL_SAFE_NO_PAD
                .decode(payload_b64)
                .map_err(|_| install_malformed("invalid base64 in licence payload"))?;
            let sig_bytes = URL_SAFE_NO_PAD
                .decode(sig_b64)
                .map_err(|_| install_malformed("invalid base64 in licence signature"))?;
            if sig_bytes.len() != 64 {
                return Err(install_malformed("licence signature must be 64 bytes"));
            }
            let signature = Signature::from_slice(&sig_bytes)
                .map_err(|_| install_malformed("malformed licence signature"))?;
            let unverified: LicensePayload = serde_json::from_slice(&payload_bytes)
                .map_err(|e| install_malformed(format!("malformed payload JSON: {e}")))?;
            let kid = unverified.kid.trim().to_string();
            if kid.is_empty() {
                return Err(install_malformed("licence missing key id"));
            }
            let verifying = trusted
                .keys
                .get(&kid)
                .ok_or_else(|| InstallError::UnknownKey(kid.clone()))?;
            verifying
                .verify(&payload_bytes, &signature)
                .map_err(|_| InstallError::InvalidSignature("signature mismatch".to_string()))?;
            if unverified.node_id.trim().is_empty() {
                return Err(install_malformed("licence missing cluster binding"));
            }
            if unverified.node_id != expected_identity {
                return Err(InstallError::IdentityMismatch {
                    expected: expected_identity.to_string(),
                    found: unverified.node_id.clone(),
                });
            }
            if now_secs > unverified.expires_at {
                return Err(InstallError::Expired {
                    expired_at: unverified.expires_at,
                });
            }
            validate_entitlements(&unverified.features)
                .map_err(InstallError::UnknownEntitlement)?;
            Ok(unverified)
        }
        _ => Err(install_malformed(
            "unsupported licence token format (expected INDRA-ENT-V2)",
        )),
    }
}

/// Licence request produced by a customer installation, like a certificate
/// signing request. A small JSON file the customer can email: identity of
/// the installation, its public key, product version, requested
/// entitlements, and a human-readable summary so the customer sees what
/// they are sending. The signer copies the identity verbatim into the
/// licence and never invents one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenceRequest {
    pub installation_identity: String,
    #[serde(default)]
    pub cluster_public_key_hex: String,
    #[serde(default)]
    pub product_version: String,
    #[serde(default)]
    pub requested_max_nodes: Option<usize>,
    #[serde(default)]
    pub requested_features: Vec<String>,
    #[serde(default)]
    pub customer_hint: String,
    #[serde(default)]
    pub summary: String,
}

impl LicenceRequest {
    /// Build a request for `identity`, rendered with the product version
    /// and the requested entitlements. The summary names the installation
    /// and the request contents so the file is self-describing.
    pub fn generate(
        identity: &ClusterIdentity,
        product_version: &str,
        requested_max_nodes: Option<usize>,
        requested_features: Vec<String>,
        customer_hint: &str,
    ) -> Self {
        let nodes = requested_max_nodes.map_or("(unspecified)".to_string(), |n| n.to_string());
        let features = if requested_features.is_empty() {
            "(none)".to_string()
        } else {
            requested_features.join(", ")
        };
        let summary = format!(
            "Licence request for installation '{}' (product {}): max_nodes={}, features=[{}]. Send this file to sales to receive a licence bound to this installation.",
            identity.identity,
            product_version,
            nodes,
            features
        );
        Self {
            installation_identity: identity.identity.clone(),
            cluster_public_key_hex: identity.public_key_hex.clone(),
            product_version: product_version.to_string(),
            requested_max_nodes,
            requested_features,
            customer_hint: customer_hint.to_string(),
            summary,
        }
    }

    /// Canonical bytes of the request (struct field order, no whitespace),
    /// safe to email as JSON text.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Write the request to `path` as pretty JSON (human-readable on top
    /// of canonical: the signer parses JSON, so whitespace is irrelevant).
    pub fn write_to_path(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| format!("cannot encode licence request: {e}"))?;
        atomic_write(path, text.as_bytes())
    }

    /// Read a request file, refusing one with no installation identity
    /// rather than inventing an identity.
    pub fn read_from_path(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read licence request {}: {e}", path.display()))?;
        let request: Self = serde_json::from_str(&text)
            .map_err(|e| format!("licence request {} is not valid JSON: {e}", path.display()))?;
        if request.installation_identity.trim().is_empty() {
            return Err(format!(
                "licence request {} carries no installation identity",
                path.display()
            ));
        }
        Ok(request)
    }
}

/// One-line hint telling an operator how to generate a licence request.
/// Surfaced in trial/expiry warnings so the message is actionable.
#[must_use]
pub fn trial_request_hint() -> &'static str {
    "generate a licence request via GET /api/v1/licence/request or `indramqtt --licence-request-out <file>`"
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Atomically replace `path` with `bytes`: write a sibling temp file,
/// flush it, then rename. A failed install never leaves a node with
/// nothing when it had a good licence, and a crash never leaves a half
/// file: the old file is either intact or replaced.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("no parent for {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    let tmp = parent.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::write(&tmp, bytes).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        std::fs::remove_file(&tmp).ok();
        format!("cannot replace {}: {e}", path.display())
    })?;
    Ok(())
}

/// Stable identity of one cluster: a P-256 keypair plus an identity
/// derived from its public key, persisted in the data directory and held
/// in cluster metadata. The first node to start creates it; a node
/// joining an existing cluster adopts the cluster identity and discards
/// any it generated while standing alone. A single node is a cluster of
/// one, so nothing is special about the unclustered case.
///
/// The trial belongs to the cluster, not to a process: `trial_started_at`
/// is recorded with the identity, so restarting does not restart the
/// trial and adding a node does not either. `highest_seen_secs` is the
/// highest wall-clock timestamp ever observed; grace is measured against
/// it so setting the clock back cannot extend grace (and cannot make a
/// valid licence look expired either).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterIdentity {
    /// Stable identity: lowercase hex of the SEC1 compressed public key.
    pub identity: String,
    /// Hex of the SEC1 public key (compressed 33 bytes).
    pub public_key_hex: String,
    /// Hex of the 32-byte private scalar, kept in the data directory so a
    /// restart reloads the same identity. Never logged.
    pub private_key_hex: String,
    /// Trial start, unix epoch seconds, fixed at creation.
    pub trial_started_at: u64,
    /// Highest timestamp ever seen, unix epoch seconds. Updated whenever
    /// a later timestamp is observed; a lower timestamp is never treated
    /// as current.
    pub highest_seen_secs: u64,
}

impl ClusterIdentity {
    /// Derive the stable identity for a SEC1 compressed public key.
    #[must_use]
    pub fn identity_for_public(compressed_sec1: &[u8]) -> String {
        encode_hex(compressed_sec1)
    }

    /// Generate a fresh identity with a new P-256 keypair. The private
    /// scalar comes from the OS RNG; rejection-sampled until valid.
    pub fn generate(now_secs: u64) -> Self {
        loop {
            let scalar: [u8; 32] = rand::random();
            if scalar.iter().all(|b| *b == 0) {
                continue;
            }
            let field =
                p256::elliptic_curve::generic_array::GenericArray::clone_from_slice(&scalar);
            if let Ok(signing) = SigningKey::from_bytes(&field) {
                let verifying = VerifyingKey::from(&signing);
                let compressed = verifying.to_encoded_point(true);
                let public_key_hex = encode_hex(compressed.as_bytes());
                let identity = Self::identity_for_public(compressed.as_bytes());
                return Self {
                    identity,
                    public_key_hex,
                    private_key_hex: encode_hex(&scalar),
                    trial_started_at: now_secs,
                    highest_seen_secs: now_secs,
                };
            }
        }
    }

    fn path_for(data_dir: &Path) -> std::path::PathBuf {
        data_dir.join(IDENTITY_FILE_NAME)
    }

    /// Persist the identity atomically.
    pub fn save(&self, data_dir: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| format!("cannot encode cluster identity: {e}"))?;
        atomic_write(&Self::path_for(data_dir), text.as_bytes())
    }

    /// Load the identity, creating and persisting a fresh one when absent.
    /// A corrupt file fails loudly rather than silently minting a new
    /// identity (which would silently restart the trial).
    pub fn load_or_create(data_dir: &Path, now_secs: u64) -> Result<Self, String> {
        let path = Self::path_for(data_dir);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let mut identity: Self = serde_json::from_str(&text)
                    .map_err(|e| format!("cluster identity {} is corrupt: {e}", path.display()))?;
                if identity.identity.trim().is_empty() {
                    return Err(format!(
                        "cluster identity {} carries no identity",
                        path.display()
                    ));
                }
                if now_secs > identity.highest_seen_secs {
                    identity.highest_seen_secs = now_secs;
                    identity.save(data_dir)?;
                }
                Ok(identity)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let identity = Self::generate(now_secs);
                identity.save(data_dir)?;
                Ok(identity)
            }
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }

    /// Effective current time: never below the highest timestamp seen, so
    /// the clock going backwards cannot extend grace or trial.
    #[must_use]
    pub fn effective_now(&self, now_secs: u64) -> u64 {
        now_secs.max(self.highest_seen_secs)
    }

    /// Record `now_secs` when it advances the high-water mark. Returns the
    /// effective time. The caller persists with `save` when this reports
    /// an advance (kept separate so tests stay pure).
    pub fn record_now(&mut self, now_secs: u64) -> u64 {
        if now_secs > self.highest_seen_secs {
            self.highest_seen_secs = now_secs;
        }
        self.highest_seen_secs
    }
}

/// Lifecycle state of one installation, always visible to the customer.
///
/// - `Trial`: fresh installation, no licence yet, every entitlement
///   working for 90 days from first start.
/// - `Valid`: licensed, before the expiry date.
/// - `Grace`: past expiry but inside the grace window, everything still
///   working.
/// - `Lapsed`: trial or grace ran out, enterprise entitlements off, MQTT
///   still serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallationState {
    Trial {
        days_remaining: u64,
    },
    Valid {
        customer: String,
        expires_at: u64,
        max_nodes: usize,
        features: Vec<String>,
        kid: String,
        days_remaining: u64,
    },
    Grace {
        customer: String,
        expires_at: u64,
        days_remaining: u64,
        grace_total_days: u64,
        max_nodes: usize,
        features: Vec<String>,
        kid: String,
    },
    Lapsed {
        reason: String,
    },
}

impl InstallationState {
    /// Short state name for the status route and logs.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            InstallationState::Trial { .. } => "trial",
            InstallationState::Valid { .. } => "valid",
            InstallationState::Grace { .. } => "grace",
            InstallationState::Lapsed { .. } => "lapsed",
        }
    }

    /// Whether enterprise entitlements are on. Trial, valid and grace all
    /// work; only lapsed turns them off. MQTT connect, publish and
    /// subscribe keep working in every state.
    #[must_use]
    pub fn entitlements_on(&self) -> bool {
        !matches!(self, InstallationState::Lapsed { .. })
    }

    /// Whole days remaining in the current state (trial, valid or grace).
    /// Lapsed reports zero.
    #[must_use]
    pub fn days_remaining(&self) -> u64 {
        match self {
            InstallationState::Trial { days_remaining } => *days_remaining,
            InstallationState::Valid { days_remaining, .. } => *days_remaining,
            InstallationState::Grace { days_remaining, .. } => *days_remaining,
            InstallationState::Lapsed { .. } => 0,
        }
    }
}

fn trial_days_remaining(trial_started_at: u64, now_secs: u64) -> Option<u64> {
    let trial_secs = TRIAL_DAYS.saturating_mul(SECS_PER_DAY);
    let elapsed = now_secs.saturating_sub(trial_started_at);
    if elapsed < trial_secs {
        Some((trial_secs - elapsed) / SECS_PER_DAY)
    } else {
        None
    }
}

/// Evaluate the installation lifecycle at `now_secs`.
///
/// `effective_now` is the high-water timestamp (never below the highest
/// seen), so a backwards clock cannot extend trial or grace. With no
/// stored licence the trial runs 90 days from the cluster identity, then
/// lapses with entitlements off and MQTT still serving. With a stored
/// licence the signature and binding are re-checked (an unknown key after
/// rotation lapses rather than silently passing), then valid/grace/lapsed
/// follow the licence expiry plus its carried grace length.
pub fn evaluate_installation(
    identity: &ClusterIdentity,
    stored_token: Option<&str>,
    trusted: &TrustedKeys,
    now_secs: u64,
) -> InstallationState {
    let effective = identity.effective_now(now_secs);
    let Some(token) = stored_token.map(str::trim).filter(|s| !s.is_empty()) else {
        return match trial_days_remaining(identity.trial_started_at, effective) {
            Some(days_remaining) => InstallationState::Trial { days_remaining },
            None => InstallationState::Lapsed {
                reason: format!(
                    "trial of {} days ended; {}",
                    TRIAL_DAYS,
                    trial_request_hint()
                ),
            },
        };
    };
    match verify_token_at_time(token, &identity.identity, trusted, effective) {
        Ok(payload) => {
            if effective <= payload.expires_at {
                let days_remaining = payload.expires_at.saturating_sub(effective) / SECS_PER_DAY;
                InstallationState::Valid {
                    customer: payload.customer,
                    expires_at: payload.expires_at,
                    max_nodes: payload.max_nodes,
                    features: payload.features,
                    kid: payload.kid,
                    days_remaining,
                }
            } else {
                let grace_secs = payload.grace_period_days.saturating_mul(SECS_PER_DAY);
                let elapsed = effective.saturating_sub(payload.expires_at);
                if elapsed <= grace_secs {
                    let days_remaining = grace_secs.saturating_sub(elapsed) / SECS_PER_DAY;
                    InstallationState::Grace {
                        customer: payload.customer,
                        expires_at: payload.expires_at,
                        days_remaining,
                        grace_total_days: payload.grace_period_days,
                        max_nodes: payload.max_nodes,
                        features: payload.features,
                        kid: payload.kid,
                    }
                } else {
                    InstallationState::Lapsed {
                        reason: format!(
                            "licence for '{}' expired at {} and grace of {} days ran out",
                            payload.customer, payload.expires_at, payload.grace_period_days
                        ),
                    }
                }
            }
        }
        Err(reason) => InstallationState::Lapsed { reason },
    }
}

fn verify_token_at_time(
    token: &str,
    expected_identity: &str,
    trusted: &TrustedKeys,
    now_secs: u64,
) -> Result<LicensePayload, String> {
    match verify_for_install(token, expected_identity, trusted, now_secs) {
        Ok(payload) => Ok(payload),
        Err(InstallError::Expired { expired_at }) => {
            verify_expired_with_grace(token, expected_identity, trusted, expired_at)
        }
        Err(other) => Err(other.to_string()),
    }
}

fn verify_expired_with_grace(
    token: &str,
    expected_identity: &str,
    trusted: &TrustedKeys,
    expired_at: u64,
) -> Result<LicensePayload, String> {
    let mut parts = token.trim().split('.');
    let (Some(prefix), Some(payload_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(InstallError::Malformed(
            "unsupported licence token format (expected INDRA-ENT-V2)".to_string(),
        )
        .to_string());
    };
    if prefix != TOKEN_PREFIX {
        return Err(InstallError::Malformed(
            "unsupported licence token format (expected INDRA-ENT-V2)".to_string(),
        )
        .to_string());
    }
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| {
        InstallError::Malformed("invalid base64 in licence payload".to_string()).to_string()
    })?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).map_err(|_| {
        InstallError::Malformed("invalid base64 in licence signature".to_string()).to_string()
    })?;
    if sig_bytes.len() != 64 {
        return Err(
            InstallError::Malformed("licence signature must be 64 bytes".to_string()).to_string(),
        );
    }
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| {
        InstallError::Malformed("malformed licence signature".to_string()).to_string()
    })?;
    let payload: LicensePayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| InstallError::Malformed(format!("malformed payload JSON: {e}")).to_string())?;
    let kid = payload.kid.trim().to_string();
    if kid.is_empty() {
        return Err(InstallError::Malformed("licence missing key id".to_string()).to_string());
    }
    let verifying = trusted
        .keys
        .get(&kid)
        .ok_or_else(|| InstallError::UnknownKey(kid.clone()).to_string())?;
    verifying.verify(&payload_bytes, &signature).map_err(|_| {
        InstallError::InvalidSignature("signature mismatch".to_string()).to_string()
    })?;
    if payload.node_id.trim().is_empty() {
        return Err(
            InstallError::Malformed("licence missing cluster binding".to_string()).to_string(),
        );
    }
    if payload.node_id != expected_identity {
        return Err(InstallError::IdentityMismatch {
            expected: expected_identity.to_string(),
            found: payload.node_id.clone(),
        }
        .to_string());
    }
    validate_entitlements(&payload.features)
        .map_err(|reason| InstallError::UnknownEntitlement(reason).to_string())?;
    let _ = expired_at;
    Ok(payload)
}

/// Path of the stored licence token inside the data directory.
#[must_use]
pub fn licence_file_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(LICENCE_FILE_NAME)
}

/// Load the stored licence token, if any. Missing file reads as no
/// licence (trial); a corrupt file fails loudly rather than silently
/// running unlicensed.
pub fn load_stored_licence(data_dir: &Path) -> Result<Option<String>, String> {
    let path = licence_file_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let trimmed = text.trim().to_string();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// Install a licence token: verify first, then atomically replace the
/// stored file. A failed install never touches the previously stored
/// licence: verification happens before any write, so a node that had a
/// good licence keeps it.
pub fn install_licence(
    data_dir: &Path,
    token: &str,
    expected_identity: &str,
    trusted: &TrustedKeys,
    now_secs: u64,
) -> Result<LicensePayload, InstallError> {
    let payload = verify_for_install(token, expected_identity, trusted, now_secs)?;
    atomic_write(&licence_file_path(data_dir), token.trim().as_bytes())
        .map_err(InstallError::Malformed)?;
    Ok(payload)
}

/// Admission check for a node joining a cluster: when the installation is
/// licensed (valid or grace) and the join would exceed the licensed node
/// ceiling, refuse membership with a reason naming the ceiling and the
/// current count. The refused node keeps serving MQTT standalone; it is
/// refused from the cluster, not stopped as a broker.
pub fn join_admission(
    current_count_incl_joiner: usize,
    state: &InstallationState,
) -> Result<(), String> {
    let (max_nodes, _customer) = match state {
        InstallationState::Valid {
            max_nodes,
            customer,
            ..
        } => (*max_nodes, customer.clone()),
        InstallationState::Grace {
            max_nodes,
            customer,
            ..
        } => (*max_nodes, customer.clone()),
        InstallationState::Trial { .. } | InstallationState::Lapsed { .. } => return Ok(()),
    };
    if current_count_incl_joiner > max_nodes {
        return Err(format!(
            "node beyond licensed ceiling: ceiling {max_nodes} nodes, cluster would have {current_count_incl_joiner} nodes"
        ));
    }
    Ok(())
}

/// Log the identity handover when a joining node adopts the cluster
/// identity, naming both identities rather than silently dropping the
/// joiner's licence (which is no longer valid for it afterwards).
pub fn log_identity_adoption(joiner_identity: &str, cluster_identity: &str) {
    warn!(
        "cluster identity adoption: node identity '{joiner_identity}' adopts cluster identity '{cluster_identity}'; any licence bound to '{joiner_identity}' is no longer valid for this node"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    /// Build a deterministic P-256 signing key from a non-zero seed byte.
    /// Test-only: the key is ephemeral and never leaves this process.
    fn test_signing_key(seed: u8) -> SigningKey {
        let mut bytes = [seed; 32];
        // P-256 order is close to 2^256; tiny repeating values are safely
        // inside it, but avoid the all-zero scalar which is invalid.
        if seed == 0 {
            bytes[31] = 1;
        }
        let field_bytes =
            p256::elliptic_curve::generic_array::GenericArray::clone_from_slice(&bytes);
        SigningKey::from_bytes(&field_bytes).expect("test seed is a valid scalar")
    }

    fn test_trusted(keys: &[(&str, &SigningKey)]) -> TrustedKeys {
        let mut trusted = TrustedKeys::new();
        for (kid, signing) in keys {
            let verifying = VerifyingKey::from(*signing);
            trusted.insert((*kid).to_string(), verifying);
        }
        trusted
    }

    fn mint(
        signing: &SigningKey,
        kid: &str,
        customer: &str,
        max_nodes: usize,
        issued_at: u64,
        expires_at: u64,
        node_id: &str,
    ) -> String {
        let payload = LicensePayload {
            customer: customer.to_string(),
            max_nodes,
            issued_at,
            expires_at,
            features: vec!["clustering".to_string()],
            node_id: node_id.to_string(),
            kid: kid.to_string(),
            grace_period_days: DEFAULT_GRACE_DAYS,
        };
        let payload_json = canonical_json_bytes(&payload).expect("test payload serialises");
        let sig: Signature = signing.sign(&payload_json);
        format!(
            "{}.{}.{}",
            TOKEN_PREFIX,
            URL_SAFE_NO_PAD.encode(&payload_json),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        )
    }

    #[test]
    fn test_community_evaluation_when_no_key_provided() {
        let trusted = test_trusted(&[]);
        let status = ClusterLicense::evaluate(None, 1, 1700000000, "test-node-1", &trusted);
        assert_eq!(
            status,
            LicenseStatus::CommunityEvaluation {
                max_eval_nodes: ClusterLicense::DEFAULT_EVAL_NODES
            }
        );

        let status_empty =
            ClusterLicense::evaluate(Some("   "), 2, 1700000000, "test-node-1", &trusted);
        assert_eq!(
            status_empty,
            LicenseStatus::CommunityEvaluation {
                max_eval_nodes: ClusterLicense::DEFAULT_EVAL_NODES
            }
        );
    }

    #[test]
    fn test_valid_signature_from_first_enrolled_key() {
        let a = test_signing_key(0xA1);
        let b = test_signing_key(0xB2);
        let trusted = test_trusted(&[("key-a", &a), ("key-b", &b)]);
        let token = mint(
            &a,
            "key-a",
            "Acme Industrial IoT",
            10,
            1700000000,
            2000000000,
            "node-1",
        );
        let status = ClusterLicense::evaluate(Some(&token), 5, 1750000000, "node-1", &trusted);
        match status {
            LicenseStatus::EnterpriseValid {
                customer,
                max_nodes,
                expires_at,
                features,
            } => {
                assert_eq!(customer, "Acme Industrial IoT");
                assert_eq!(max_nodes, 10);
                assert_eq!(expires_at, 2000000000);
                assert_eq!(features, vec!["clustering".to_string()]);
            }
            other => panic!("Expected EnterpriseValid, got {other:?}"),
        }
    }

    #[test]
    fn test_valid_signature_from_second_enrolled_key() {
        let a = test_signing_key(0xA1);
        let b = test_signing_key(0xB2);
        let trusted = test_trusted(&[("key-a", &a), ("key-b", &b)]);
        let token = mint(
            &b,
            "key-b",
            "Second Customer",
            4,
            1700000000,
            2000000000,
            "node-1",
        );
        let status = ClusterLicense::evaluate(Some(&token), 2, 1750000000, "node-1", &trusted);
        match status {
            LicenseStatus::EnterpriseValid { customer, .. } => {
                assert_eq!(customer, "Second Customer");
            }
            other => panic!("Expected EnterpriseValid, got {other:?}"),
        }
    }

    #[test]
    fn test_forged_signature_rejected() {
        let a = test_signing_key(0xA1);
        let trusted = test_trusted(&[("key-a", &a)]);
        let token = mint(&a, "key-a", "Acme", 10, 1700000000, 2000000000, "node-1");
        // Flip the last payload character: the signature no longer matches.
        let mut tampered = token.clone();
        tampered.pop();
        tampered.push(if token.ends_with('A') { 'B' } else { 'A' });
        let status = ClusterLicense::evaluate(Some(&tampered), 1, 1750000000, "node-1", &trusted);
        assert!(matches!(status, LicenseStatus::InvalidSignature(_)));
    }

    #[test]
    fn test_edited_payload_rejected() {
        let a = test_signing_key(0xA1);
        let trusted = test_trusted(&[("key-a", &a)]);
        let token = mint(&a, "key-a", "Acme", 10, 1700000000, 2000000000, "node-1");
        let mut parts = token.split('.');
        let payload_b64 = parts.nth(1).expect("test token shape");
        let sig_b64 = parts.next().expect("test token shape");
        let mut payload_json = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("test token payload");
        let mut value: serde_json::Value =
            serde_json::from_slice(&payload_json).expect("test token json");
        value["max_nodes"] = serde_json::json!(999);
        payload_json = serde_json::to_vec(&value).expect("re-encode");
        let edited = format!(
            "{}.{}.{}",
            TOKEN_PREFIX,
            URL_SAFE_NO_PAD.encode(&payload_json),
            sig_b64
        );
        let status = ClusterLicense::evaluate(Some(&edited), 1, 1750000000, "node-1", &trusted);
        assert!(matches!(status, LicenseStatus::InvalidSignature(_)));
    }

    #[test]
    fn test_key_id_mismatch_rejected() {
        // Signed with key A but labelled key B: key B is trusted, yet the
        // signature was not made by it, so verification must fail.
        let a = test_signing_key(0xA1);
        let b = test_signing_key(0xB2);
        let trusted = test_trusted(&[("key-a", &a), ("key-b", &b)]);
        let token = mint(&a, "key-b", "Acme", 10, 1700000000, 2000000000, "node-1");
        let status = ClusterLicense::evaluate(Some(&token), 1, 1750000000, "node-1", &trusted);
        match status {
            LicenseStatus::InvalidSignature(reason) => {
                assert!(
                    reason.contains("mismatch"),
                    "kid mismatch must read as a signature mismatch, got: {reason}"
                );
            }
            other => panic!("Expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn test_unknown_key_id_rejected_closed() {
        let a = test_signing_key(0xA1);
        let trusted = test_trusted(&[("key-a", &a)]);
        let token = mint(
            &a,
            "retired-or-forged",
            "Acme",
            10,
            1700000000,
            2000000000,
            "node-1",
        );
        let status = ClusterLicense::evaluate(Some(&token), 1, 1750000000, "node-1", &trusted);
        match status {
            LicenseStatus::InvalidSignature(reason) => {
                assert!(
                    reason.contains("unknown signing key"),
                    "unknown kid must fail closed, got: {reason}"
                );
            }
            other => panic!("Expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn test_legacy_v1_token_rejected() {
        let trusted = test_trusted(&[]);
        let status = ClusterLicense::evaluate(
            Some("INDRA-ENT-V1.cGF5bG9hZA.c2ln"),
            1,
            1750000000,
            "node-1",
            &trusted,
        );
        assert!(matches!(status, LicenseStatus::InvalidSignature(_)));
    }

    #[test]
    fn test_expired_token_rejected() {
        let a = test_signing_key(0xA1);
        let trusted = test_trusted(&[("key-a", &a)]);
        let token = mint(
            &a,
            "key-a",
            "Legacy Corp",
            5,
            1700000000,
            1710000000,
            "node-1",
        );
        let status = ClusterLicense::evaluate(Some(&token), 2, 1720000000, "node-1", &trusted);
        assert_eq!(
            status,
            LicenseStatus::Expired {
                customer: "Legacy Corp".into(),
                expired_at: 1710000000
            }
        );
    }

    #[test]
    fn test_token_for_another_node_rejected() {
        let a = test_signing_key(0xA1);
        let trusted = test_trusted(&[("key-a", &a)]);
        let token = mint(&a, "key-a", "Acme", 10, 1700000000, 2000000000, "node-1");
        let status =
            ClusterLicense::evaluate(Some(&token), 1, 1750000000, "other-node-9", &trusted);
        match status {
            LicenseStatus::InvalidSignature(reason) => {
                assert!(
                    reason.contains("not 'other-node-9'"),
                    "node mismatch must name both identities, got: {reason}"
                );
            }
            other => panic!("Expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn test_quota_exceeded() {
        let a = test_signing_key(0xA1);
        let trusted = test_trusted(&[("key-a", &a)]);
        let token = mint(
            &a,
            "key-a",
            "Small Business",
            3,
            1700000000,
            1800000000,
            "node-1",
        );
        let status = ClusterLicense::evaluate(Some(&token), 5, 1750000000, "node-1", &trusted);
        assert_eq!(
            status,
            LicenseStatus::QuotaExceeded {
                customer: "Small Business".into(),
                current_nodes: 5,
                max_nodes: 3
            }
        );
    }

    #[test]
    fn test_canonical_bytes_are_stable() {
        let payload = LicensePayload {
            customer: "Acme".to_string(),
            max_nodes: 10,
            issued_at: 1700000000,
            expires_at: 2000000000,
            features: vec!["clustering".to_string()],
            node_id: "node-1".to_string(),
            kid: "key-a".to_string(),
            grace_period_days: DEFAULT_GRACE_DAYS,
        };
        let first = canonical_json_bytes(&payload).expect("serialises");
        let second = canonical_json_bytes(&payload).expect("serialises");
        assert_eq!(first, second);
        // Struct field order is the canonical order: customer first, grace last.
        let text = String::from_utf8(first).expect("JSON is UTF-8");
        assert!(
            text.starts_with(r#"{"customer":"Acme""#),
            "unexpected order: {text}"
        );
        assert!(
            text.ends_with(r#""grace_period_days":90}"#),
            "unexpected order: {text}"
        );
        assert!(
            text.contains(r#""kid":"key-a""#),
            "kid must be covered: {text}"
        );
    }

    #[test]
    fn test_trust_file_round_trip_from_dir() {
        use std::io::Write as _;

        let a = test_signing_key(0xA1);
        let b = test_signing_key(0xB2);
        let dir = std::env::temp_dir().join(format!(
            "indramqtt-lic-trust-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        for (name, key, kid) in [("a.json", &a, "key-a"), ("b.json", &b, "key-b")] {
            let verifying = VerifyingKey::from(key);
            let point = verifying.to_encoded_point(false);
            let hex: String = point
                .as_bytes()
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect();
            let doc = serde_json::json!({"keys": [{"kid": kid, "public_key_hex": hex}]});
            let mut file = std::fs::File::create(dir.join(name)).expect("scratch file");
            file.write_all(doc.to_string().as_bytes()).expect("write");
        }
        let loaded = TrustedKeys::load_from_path(&dir).expect("loads directory");
        assert_eq!(
            loaded.kids(),
            vec!["key-a".to_string(), "key-b".to_string()]
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod b2_04_tests {
    use super::*;
    use p256::ecdsa::signature::Signer;

    fn key(seed: u8) -> SigningKey {
        let mut bytes = [seed; 32];
        if seed == 0 {
            bytes[31] = 1;
        }
        let field = p256::elliptic_curve::generic_array::GenericArray::clone_from_slice(&bytes);
        SigningKey::from_bytes(&field).expect("test seed is a valid scalar")
    }

    fn trusted_for(signing: &SigningKey, kid: &str) -> TrustedKeys {
        let mut trusted = TrustedKeys::new();
        trusted.insert(kid.to_string(), VerifyingKey::from(signing));
        trusted
    }

    #[allow(clippy::too_many_arguments)]
    fn mint_full(
        signing: &SigningKey,
        kid: &str,
        customer: &str,
        max_nodes: usize,
        issued_at: u64,
        expires_at: u64,
        node_id: &str,
        features: Vec<String>,
        grace_days: u64,
    ) -> String {
        let payload = LicensePayload {
            customer: customer.to_string(),
            max_nodes,
            issued_at,
            expires_at,
            features,
            node_id: node_id.to_string(),
            kid: kid.to_string(),
            grace_period_days: grace_days,
        };
        let bytes = canonical_json_bytes(&payload).expect("test payload serialises");
        let sig: Signature = signing.sign(&bytes);
        format!(
            "{}.{}.{}",
            TOKEN_PREFIX,
            URL_SAFE_NO_PAD.encode(&bytes),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        )
    }

    fn mint_simple(
        signing: &SigningKey,
        kid: &str,
        node_id: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> String {
        mint_full(
            signing,
            kid,
            "Acme",
            5,
            issued_at,
            expires_at,
            node_id,
            vec!["clustering".to_string()],
            DEFAULT_GRACE_DAYS,
        )
    }

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "indramqtt-b204-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn test_identity(name: &str, trial_start: u64, seen: u64) -> ClusterIdentity {
        ClusterIdentity {
            identity: name.to_string(),
            public_key_hex: "aa".to_string(),
            private_key_hex: "bb".to_string(),
            trial_started_at: trial_start,
            highest_seen_secs: seen,
        }
    }

    #[test]
    fn b2_04_request_sign_install_restart_survives() {
        let signing = key(0xC1);
        let trusted = trusted_for(&signing, "key-c1");
        let data_dir = scratch_dir("install");
        let now = 1_750_000_000u64;
        let identity = ClusterIdentity::load_or_create(&data_dir, now).expect("identity");
        let request = LicenceRequest::generate(
            &identity,
            "0.1.0",
            Some(5),
            vec!["clustering".to_string()],
            "Acme",
        );
        assert_eq!(request.installation_identity, identity.identity);
        assert!(request.summary.contains(&identity.identity));
        let token = mint_simple(
            &signing,
            "key-c1",
            &identity.identity,
            now - 100,
            now + 10_000_000,
        );
        let payload = install_licence(&data_dir, &token, &identity.identity, &trusted, now)
            .expect("installs");
        assert_eq!(payload.customer, "Acme");
        let stored = load_stored_licence(&data_dir)
            .expect("loads")
            .expect("present");
        assert_eq!(stored, token.trim());
        let reloaded = ClusterIdentity::load_or_create(&data_dir, now + 60).expect("reload");
        assert_eq!(reloaded.identity, identity.identity);
        assert_eq!(reloaded.trial_started_at, identity.trial_started_at);
        let stored2 = load_stored_licence(&data_dir)
            .expect("loads")
            .expect("present");
        let state = evaluate_installation(&reloaded, Some(&stored2), &trusted, now + 60);
        assert_eq!(state.name(), "valid");
        assert!(state.entitlements_on());
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn b2_04_identity_mismatch_distinct() {
        let signing = key(0xC2);
        let trusted = trusted_for(&signing, "key-c2");
        let now = 1_750_000_000u64;
        let token = mint_simple(
            &signing,
            "key-c2",
            "cluster-aaa",
            now - 100,
            now + 10_000_000,
        );
        let err = verify_for_install(&token, "cluster-bbb", &trusted, now).expect_err("mismatch");
        match err {
            InstallError::IdentityMismatch { expected, found } => {
                assert_eq!(expected, "cluster-bbb");
                assert_eq!(found, "cluster-aaa");
            }
            other => panic!("expected IdentityMismatch, got {other:?}"),
        }
        let text = verify_for_install(&token, "cluster-bbb", &trusted, now)
            .expect_err("again")
            .to_string();
        assert!(
            text.contains("identity mismatch"),
            "must name identity: {text}"
        );
        assert!(
            text.contains("cluster-aaa") && text.contains("cluster-bbb"),
            "must name both: {text}"
        );
    }

    #[test]
    fn b2_04_tampered_expired_unknownkey_malformed_distinct() {
        let signing = key(0xC3);
        let trusted = trusted_for(&signing, "key-c3");
        let now = 1_750_000_000u64;
        let token = mint_simple(&signing, "key-c3", "cluster-x", now - 100, now + 10_000_000);
        let payload_b64 = token.split('.').nth(1).expect("token shape");
        let sig_b64 = token.rsplit('.').next().expect("token sig");
        let mut payload_json = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("payload decodes");
        let flip_at = payload_json.len() / 2;
        payload_json[flip_at] ^= 0x01;
        let tampered = format!(
            "{}.{}.{}",
            TOKEN_PREFIX,
            URL_SAFE_NO_PAD.encode(&payload_json),
            sig_b64
        );
        let err = verify_for_install(&tampered, "cluster-x", &trusted, now).expect_err("tampered");
        assert!(
            matches!(err, InstallError::InvalidSignature(_)),
            "tampered: {err:?}"
        );
        let expired = mint_simple(&signing, "key-c3", "cluster-x", now - 20_000_000, now - 100);
        let err = verify_for_install(&expired, "cluster-x", &trusted, now).expect_err("expired");
        assert!(
            matches!(err, InstallError::Expired { .. }),
            "expired: {err:?}"
        );
        let other = key(0xC4);
        let foreign = mint_simple(
            &other,
            "key-foreign",
            "cluster-x",
            now - 100,
            now + 10_000_000,
        );
        let err =
            verify_for_install(&foreign, "cluster-x", &trusted, now).expect_err("unknown key");
        assert!(
            matches!(err, InstallError::UnknownKey(_)),
            "unknown key: {err:?}"
        );
        let err =
            verify_for_install("not-a-licence", "cluster-x", &trusted, now).expect_err("malformed");
        assert!(
            matches!(err, InstallError::Malformed(_)),
            "malformed: {err:?}"
        );
        let bad_feat = mint_full(
            &signing,
            "key-c3",
            "Acme",
            5,
            now - 100,
            now + 10_000_000,
            "cluster-x",
            vec!["teleportation".to_string()],
            DEFAULT_GRACE_DAYS,
        );
        let err =
            verify_for_install(&bad_feat, "cluster-x", &trusted, now).expect_err("entitlement");
        assert!(
            matches!(err, InstallError::UnknownEntitlement(_)),
            "entitlement: {err:?}"
        );
        let t0 = verify_for_install(&tampered, "cluster-x", &trusted, now)
            .expect_err("t")
            .to_string();
        let t1 = verify_for_install(&expired, "cluster-x", &trusted, now)
            .expect_err("e")
            .to_string();
        let t2 = verify_for_install(&foreign, "cluster-x", &trusted, now)
            .expect_err("u")
            .to_string();
        let t3 = verify_for_install("not-a-licence", "cluster-x", &trusted, now)
            .expect_err("m")
            .to_string();
        let t4 = verify_for_install(&bad_feat, "cluster-x", &trusted, now)
            .expect_err("f")
            .to_string();
        assert!(t0.contains("invalid signature"), "{t0}");
        assert!(t1.contains("expired"), "{t1}");
        assert!(t2.contains("unknown signing key"), "{t2}");
        assert!(t3.contains("malformed"), "{t3}");
        assert!(t4.contains("unknown entitlement"), "{t4}");
    }

    #[test]
    fn b2_04_failed_install_keeps_previous() {
        let signing = key(0xC5);
        let trusted = trusted_for(&signing, "key-c5");
        let data_dir = scratch_dir("keep");
        let now = 1_750_000_000u64;
        let identity = ClusterIdentity::load_or_create(&data_dir, now).expect("identity");
        let good = mint_simple(
            &signing,
            "key-c5",
            &identity.identity,
            now - 100,
            now + 10_000_000,
        );
        install_licence(&data_dir, &good, &identity.identity, &trusted, now)
            .expect("good installs");
        let bad = mint_simple(
            &signing,
            "key-c5",
            "other-cluster",
            now - 100,
            now + 10_000_000,
        );
        assert!(install_licence(&data_dir, &bad, &identity.identity, &trusted, now).is_err());
        let stored = load_stored_licence(&data_dir)
            .expect("loads")
            .expect("present");
        assert_eq!(stored, good.trim());
        std::fs::remove_dir_all(&data_dir).ok();
    }

    #[test]
    fn b2_04_one_day_past_expiry_grace_entitlements_on() {
        let signing = key(0xC6);
        let trusted = trusted_for(&signing, "key-c6");
        let now = 1_750_000_000u64;
        let expires_at = now - SECS_PER_DAY;
        let identity = test_identity("cluster-g", now - 10, now - 10);
        let token = mint_simple(
            &signing,
            "key-c6",
            "cluster-g",
            expires_at - 10_000_000,
            expires_at,
        );
        let state = evaluate_installation(&identity, Some(&token), &trusted, now);
        match state.clone() {
            InstallationState::Grace { days_remaining, .. } => {
                assert!(
                    (88..=89).contains(&days_remaining),
                    "days: {days_remaining}"
                );
            }
            other => panic!("must be grace, got {other:?}"),
        }
        assert_eq!(state.name(), "grace");
        assert!(state.entitlements_on());
    }

    #[test]
    fn b2_04_past_grace_lapsed_entitlements_off() {
        let signing = key(0xC7);
        let trusted = trusted_for(&signing, "key-c7");
        let now = 1_750_000_000u64;
        let expires_at = now - (DEFAULT_GRACE_DAYS + 1) * SECS_PER_DAY - 100;
        let identity = test_identity("cluster-l", now - 10, now - 10);
        let token = mint_simple(
            &signing,
            "key-c7",
            "cluster-l",
            expires_at - 10_000_000,
            expires_at,
        );
        let state = evaluate_installation(&identity, Some(&token), &trusted, now);
        assert_eq!(state.name(), "lapsed");
        assert!(!state.entitlements_on());
    }

    #[test]
    fn b2_04_clock_backwards_does_not_extend_grace() {
        let signing = key(0xC8);
        let trusted = trusted_for(&signing, "key-c8");
        let expires_at = 1_750_000_000u64;
        let late = expires_at + 10 * SECS_PER_DAY;
        let mut identity = test_identity("cluster-t", expires_at - 10_000_000, late);
        let token = mint_simple(
            &signing,
            "key-c8",
            "cluster-t",
            expires_at - 10_000_000,
            expires_at,
        );
        let ahead = evaluate_installation(&identity, Some(&token), &trusted, late);
        assert_eq!(ahead.name(), "grace");
        let ahead_days = ahead.days_remaining();
        let back =
            evaluate_installation(&identity, Some(&token), &trusted, expires_at + SECS_PER_DAY);
        assert_eq!(back.name(), "grace");
        assert_eq!(back.days_remaining(), ahead_days);
        identity.record_now(expires_at);
        assert_eq!(identity.highest_seen_secs, late);
    }
}

#[cfg(test)]
mod b2_04_b {
    use super::*;

    fn trial_id(name: &str, trial_start: u64, seen: u64) -> ClusterIdentity {
        ClusterIdentity {
            identity: name.to_string(),
            public_key_hex: "aa".to_string(),
            private_key_hex: "bb".to_string(),
            trial_started_at: trial_start,
            highest_seen_secs: seen,
        }
    }

    #[test]
    fn b2_04_fresh_install_trial_90_days() {
        let trusted = TrustedKeys::new();
        let now = 1_750_000_000u64;
        let identity = trial_id("cluster-fresh", now, now);
        let state = evaluate_installation(&identity, None, &trusted, now);
        match state {
            InstallationState::Trial { days_remaining } => assert_eq!(days_remaining, 90),
            other => panic!("fresh must be trial, got {other:?}"),
        }
        assert!(evaluate_installation(&identity, None, &trusted, now).entitlements_on());
    }

    #[test]
    fn b2_04_trial_past_90_days_lapsed() {
        let trusted = TrustedKeys::new();
        let trial_start = 1_700_000_000u64;
        let now = trial_start + TRIAL_DAYS * SECS_PER_DAY + 10;
        let identity = trial_id("cluster-old", trial_start, trial_start);
        let state = evaluate_installation(&identity, None, &trusted, now);
        assert_eq!(state.name(), "lapsed");
        assert!(!state.entitlements_on());
    }

    #[test]
    fn b2_04_restart_does_not_restart_trial() {
        let dir = std::env::temp_dir().join(format!(
            "indramqtt-b204-restart-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let start = 1_750_000_000u64;
        let first = ClusterIdentity::load_or_create(&dir, start).expect("create");
        let mid = start + 10 * SECS_PER_DAY;
        let reloaded = ClusterIdentity::load_or_create(&dir, mid).expect("reload");
        assert_eq!(reloaded.identity, first.identity);
        assert_eq!(reloaded.trial_started_at, first.trial_started_at);
        let trusted = TrustedKeys::new();
        let state = evaluate_installation(&reloaded, None, &trusted, mid);
        match state {
            InstallationState::Trial { days_remaining } => assert_eq!(days_remaining, 80),
            other => panic!("restart must not restart trial, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn b2_04_joiner_adopts_cluster_trial_days() {
        let now = 1_750_000_000u64;
        let cluster = trial_id("cluster-main", now - 10 * SECS_PER_DAY, now);
        let trusted = TrustedKeys::new();
        assert_eq!(
            evaluate_installation(&cluster, None, &trusted, now).days_remaining(),
            80
        );
        let joiner = trial_id("lone-node", now, now);
        log_identity_adoption(&joiner.identity, &cluster.identity);
        let adopted = ClusterIdentity {
            identity: cluster.identity.clone(),
            public_key_hex: cluster.public_key_hex.clone(),
            private_key_hex: joiner.private_key_hex.clone(),
            trial_started_at: cluster.trial_started_at,
            highest_seen_secs: now,
        };
        assert_eq!(
            evaluate_installation(&adopted, None, &trusted, now).days_remaining(),
            80
        );
    }

    #[test]
    fn b2_04_install_during_trial_moves_to_valid() {
        use p256::ecdsa::signature::Signer;
        let bytes = [0xC9u8; 32];
        let field = p256::elliptic_curve::generic_array::GenericArray::clone_from_slice(&bytes);
        let signing = SigningKey::from_bytes(&field).expect("seed");
        let mut trusted = TrustedKeys::new();
        trusted.insert("key-c9".to_string(), VerifyingKey::from(&signing));
        let now = 1_750_000_000u64;
        let identity = trial_id(
            "cluster-mid",
            now - 10 * SECS_PER_DAY,
            now - 10 * SECS_PER_DAY,
        );
        assert_eq!(
            evaluate_installation(&identity, None, &trusted, now).name(),
            "trial"
        );
        let expires_at = now + 365 * SECS_PER_DAY;
        let payload = LicensePayload {
            customer: "Acme".to_string(),
            max_nodes: 5,
            issued_at: now - 100,
            expires_at,
            features: vec!["clustering".to_string()],
            node_id: "cluster-mid".to_string(),
            kid: "key-c9".to_string(),
            grace_period_days: DEFAULT_GRACE_DAYS,
        };
        let bytes_json = canonical_json_bytes(&payload).expect("json");
        let sig: Signature = signing.sign(&bytes_json);
        let token = format!(
            "{}.{}.{}",
            TOKEN_PREFIX,
            URL_SAFE_NO_PAD.encode(&bytes_json),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );
        let dir = std::env::temp_dir().join(format!(
            "indramqtt-b204-trialinst-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        identity.save(&dir).expect("save");
        install_licence(&dir, &token, &identity.identity, &trusted, now).expect("install");
        let stored = load_stored_licence(&dir).expect("loads").expect("present");
        let state = evaluate_installation(&identity, Some(&stored), &trusted, now);
        match state {
            InstallationState::Valid {
                expires_at: got,
                days_remaining,
                ..
            } => {
                assert_eq!(got, expires_at);
                assert!((364..=365).contains(&days_remaining), "{days_remaining}");
            }
            other => panic!("must move to valid, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn b2_04_unlicensed_cluster_forms_and_requests() {
        let now = 1_750_000_000u64;
        let identity = ClusterIdentity::generate(now);
        assert!(!identity.identity.is_empty());
        assert!(!identity.public_key_hex.is_empty());
        let trusted = TrustedKeys::new();
        let state = evaluate_installation(&identity, None, &trusted, now);
        assert_eq!(state.name(), "trial");
        let request = LicenceRequest::generate(&identity, "0.1.0", Some(3), vec![], "bootstrap");
        assert_eq!(request.installation_identity, identity.identity);
        assert!(!request.cluster_public_key_hex.is_empty());
        assert_eq!(request.product_version, "0.1.0");
        assert!(request.summary.contains("Send this file"));
        assert!(join_admission(5, &state).is_ok());
    }

    #[test]
    fn b2_04_ceiling_refused_names_ceiling() {
        let now = 1_750_000_000u64;
        let state = InstallationState::Valid {
            customer: "Acme".to_string(),
            expires_at: now + 10_000_000,
            max_nodes: 2,
            features: vec!["clustering".to_string()],
            kid: "key-c".to_string(),
            days_remaining: 100,
        };
        let err = join_admission(3, &state).expect_err("refused");
        assert!(err.contains('2'), "{err}");
        assert!(err.contains('3'), "{err}");
        assert!(join_admission(2, &state).is_ok());
    }

    #[test]
    fn b2_04_grace_join_allowed_ceiling_enforced() {
        let now = 1_750_000_000u64;
        let grace = InstallationState::Grace {
            customer: "Acme".to_string(),
            expires_at: now - 100,
            days_remaining: 80,
            grace_total_days: 90,
            max_nodes: 2,
            features: vec!["clustering".to_string()],
            kid: "key-c".to_string(),
        };
        assert!(grace.entitlements_on());
        assert!(join_admission(2, &grace).is_ok());
        assert!(join_admission(3, &grace).is_err());
        let lapsed = InstallationState::Lapsed {
            reason: "out".to_string(),
        };
        assert!(!lapsed.entitlements_on());
        assert!(join_admission(9, &lapsed).is_ok());
    }

    #[test]
    fn b2_04_request_round_trip_through_file() {
        let now = 1_750_000_000u64;
        let identity = trial_id("cluster-file", now, now);
        let request = LicenceRequest::generate(
            &identity,
            "0.1.0",
            Some(4),
            vec!["clustering".to_string()],
            "Acme",
        );
        let dir = std::env::temp_dir().join(format!(
            "indramqtt-b204-req-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("request.json");
        request.write_to_path(&path).expect("write");
        let back = LicenceRequest::read_from_path(&path).expect("read");
        assert_eq!(back.installation_identity, identity.identity);
        assert_eq!(back.requested_max_nodes, Some(4));
        std::fs::remove_dir_all(&dir).ok();
    }
}
