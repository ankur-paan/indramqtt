//! Licence request, installation and lifecycle reporting (B2-04).
//!
//! The customer half of the hardware-rooted signing workflow: the
//! installation generates a licence request (like a certificate signing
//! request) carrying the cluster identity, the operator sends that file to
//! sales, and the signed licence is installed back into the same
//! installation. No call home and no activation server in either direction,
//! so air-gapped sites work the same way as connected ones.
//!
//! Management-plane only: the request, install and status routes never run
//! on the per-message path, add no buffering to fan-out or fan-in, and
//! never gate MQTT traffic (connect, publish and subscribe keep working in
//! every licence state). Persistence is atomic: a failed install never
//! leaves a node with nothing when it had a good licence.

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use broker_cluster::{
    evaluate_installation, install_licence as cluster_install, load_stored_licence,
    trial_request_hint, ClusterIdentity, InstallError, InstallationState, LicenceRequest,
    LicensePayload, TrustedKeys,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::ApiState;

/// Days before expiry that the status route starts reporting
/// `approaching_expiry`, and the node raises the approaching alarm.
/// Configurable per installation; the default gives operators a month.
pub const EXPIRY_WARN_DAYS_DEFAULT: u64 = 30;

/// In-memory view of the installation licence, backed by the data
/// directory when the kernel wires one in. The store holds the loaded
/// cluster identity, the stored token (if any) and the trusted signing
/// set; every method finishes quickly behind short locks and nothing here
/// touches the delivery path.
pub struct LicenceStore {
    data_dir: RwLock<Option<PathBuf>>,
    identity: RwLock<Option<ClusterIdentity>>,
    token: RwLock<Option<String>>,
    trusted: RwLock<Arc<TrustedKeys>>,
    expiry_warn_days: RwLock<u64>,
}

impl LicenceStore {
    /// Empty store: no identity, no licence, no trusted keys. The kernel
    /// populates it at boot via [`Self::load_from_data_dir`]; tests seed
    /// it directly.
    pub fn new() -> Self {
        Self {
            data_dir: RwLock::new(None),
            identity: RwLock::new(None),
            token: RwLock::new(None),
            trusted: RwLock::new(Arc::new(TrustedKeys::new())),
            expiry_warn_days: RwLock::new(EXPIRY_WARN_DAYS_DEFAULT),
        }
    }

    /// Load (or create) the cluster identity from `data_dir` and read the
    /// stored licence, if any. Records the data directory so later
    /// installs persist atomically.
    pub fn load_from_data_dir(
        &self,
        data_dir: &Path,
        now_secs: u64,
    ) -> Result<InstallationState, String> {
        let identity = ClusterIdentity::load_or_create(data_dir, now_secs)?;
        let token = load_stored_licence(data_dir)?;
        *self.data_dir.write().expect("licence store lock") = Some(data_dir.to_path_buf());
        *self.identity.write().expect("licence store lock") = Some(identity.clone());
        *self.token.write().expect("licence store lock") = token.clone();
        Ok(self.evaluate_with(&identity, token.as_deref(), now_secs))
    }

    /// Install the trusted signing set (a file or directory of public
    /// keys loaded at boot). Adding a key enrols a new device; removing
    /// one retires it once its last licence expires.
    pub fn set_trusted_keys(&self, trusted: TrustedKeys) {
        *self.trusted.write().expect("licence store lock") = Arc::new(trusted);
    }

    /// Window in days before expiry that counts as approaching.
    pub fn set_expiry_warn_days(&self, days: u64) {
        *self.expiry_warn_days.write().expect("licence store lock") = days;
    }

    /// Stable cluster identity, once loaded.
    pub fn cluster_identity(&self) -> Option<String> {
        self.identity
            .read()
            .expect("licence store lock")
            .clone()
            .map(|i| i.identity)
    }

    /// Stored licence token, once loaded.
    pub fn stored_token(&self) -> Option<String> {
        self.token.read().expect("licence store lock").clone()
    }

    /// Trial start carried with the cluster identity, once loaded.
    pub fn cluster_trial_started_at(&self) -> Option<u64> {
        self.identity
            .read()
            .expect("licence store lock")
            .clone()
            .map(|i| i.trial_started_at)
    }

    /// Seed an identity directly (tests and tools).
    pub fn set_identity_for_tests(&self, identity: ClusterIdentity) {
        *self.identity.write().expect("licence store lock") = Some(identity);
    }

    fn evaluate_with(
        &self,
        identity: &ClusterIdentity,
        token: Option<&str>,
        now_secs: u64,
    ) -> InstallationState {
        let trusted = self.trusted.read().expect("licence store lock").clone();
        evaluate_installation(identity, token, &trusted, now_secs)
    }

    /// Current lifecycle state at `now_secs`. Missing identity reads as a
    /// fresh trial only when nothing was ever loaded; once loaded the
    /// recorded trial start governs restarts.
    pub fn status_at(&self, now_secs: u64) -> serde_json::Value {
        let identity = self.identity.read().expect("licence store lock").clone();
        let token = self.token.read().expect("licence store lock").clone();
        let warn_days = *self.expiry_warn_days.read().expect("licence store lock");
        match identity {
            None => serde_json::json!({
                "state": "trial",
                "identity": null,
                "customer": null,
                "expires_at": null,
                "entitlements": ["clustering"],
                "entitlements_on": true,
                "days_remaining": broker_cluster::TRIAL_DAYS,
                "expiry_warn_days": warn_days,
                "hint": trial_request_hint(),
            }),
            Some(identity) => {
                let state = self.evaluate_with(&identity, token.as_deref(), now_secs);
                status_json(&identity.identity, &state, warn_days)
            }
        }
    }

    /// Build a licence request for the loaded identity.
    pub fn generate_request(
        &self,
        requested_max_nodes: Option<usize>,
        requested_features: Vec<String>,
        customer_hint: &str,
    ) -> Result<LicenceRequest, String> {
        let identity = self
            .identity
            .read()
            .expect("licence store lock")
            .clone()
            .ok_or_else(|| "no cluster identity loaded".to_string())?;
        Ok(LicenceRequest::generate(
            &identity,
            env!("CARGO_PKG_VERSION"),
            requested_max_nodes,
            requested_features,
            customer_hint,
        ))
    }

    /// Verify `token` against the loaded identity and, on success, store
    /// it (atomically when a data directory is wired in, in memory
    /// otherwise). A failure leaves any previously stored licence in
    /// place and returns its distinct reason.
    pub fn install(&self, token: &str, now_secs: u64) -> Result<LicensePayload, InstallError> {
        let identity = self
            .identity
            .read()
            .expect("licence store lock")
            .clone()
            .ok_or_else(|| InstallError::Malformed("no cluster identity loaded".to_string()))?;
        let trusted = self.trusted.read().expect("licence store lock").clone();
        let payload =
            broker_cluster::verify_for_install(token, &identity.identity, &trusted, now_secs)?;
        if let Some(dir) = self.data_dir.read().expect("licence store lock").clone() {
            cluster_install(&dir, token, &identity.identity, &trusted, now_secs)?;
        }
        *self.token.write().expect("licence store lock") = Some(token.trim().to_string());
        Ok(payload)
    }

    /// Refresh licence alarms from the current state. Idempotent: active
    /// names are (re)activated, stale ones deactivated. The grace alarm
    /// stays active for the whole grace period; the approaching alarms
    /// fire inside the configured window; lapsing is named explicitly.
    pub fn refresh_alarms(
        &self,
        alarms: &crate::v5::alarms::AlarmStore,
        now_secs: u64,
    ) -> InstallationState {
        let identity = self.identity.read().expect("licence store lock").clone();
        let token = self.token.read().expect("licence store lock").clone();
        let warn_days = *self.expiry_warn_days.read().expect("licence store lock");
        let Some(identity) = identity else {
            return InstallationState::Trial {
                days_remaining: broker_cluster::TRIAL_DAYS,
            };
        };
        let state = self.evaluate_with(&identity, token.as_deref(), now_secs);
        match &state {
            InstallationState::Trial { days_remaining } => {
                alarms.deactivate("licence_grace");
                alarms.deactivate("licence_lapsed");
                alarms.deactivate("licence_expiry_approaching");
                if *days_remaining <= warn_days {
                    alarms.activate("licence_trial_approaching", &format!("trial ends in {days_remaining} days; {}", trial_request_hint()), serde_json::json!({"identity": identity.identity, "days_remaining": days_remaining}));
                } else {
                    alarms.deactivate("licence_trial_approaching");
                }
            }
            InstallationState::Valid {
                days_remaining,
                customer,
                expires_at,
                ..
            } => {
                for name in [
                    "licence_grace",
                    "licence_lapsed",
                    "licence_trial_approaching",
                ] {
                    alarms.deactivate(name);
                }
                if *days_remaining <= warn_days {
                    alarms.activate("licence_expiry_approaching", &format!("licence for '{customer}' expires in {days_remaining} days (at {expires_at})"), serde_json::json!({"customer": customer, "expires_at": expires_at, "days_remaining": days_remaining}));
                } else {
                    alarms.deactivate("licence_expiry_approaching");
                }
            }
            InstallationState::Grace {
                days_remaining,
                customer,
                expires_at,
                ..
            } => {
                for name in [
                    "licence_trial_approaching",
                    "licence_lapsed",
                    "licence_expiry_approaching",
                ] {
                    alarms.deactivate(name);
                }
                alarms.activate("licence_grace", &format!("licence for '{customer}' expired at {expires_at}; {days_remaining} grace days remaining"), serde_json::json!({"customer": customer, "expires_at": expires_at, "days_remaining": days_remaining}));
            }
            InstallationState::Lapsed { reason } => {
                for name in [
                    "licence_trial_approaching",
                    "licence_grace",
                    "licence_expiry_approaching",
                ] {
                    alarms.deactivate(name);
                }
                alarms.activate(
                    "licence_lapsed",
                    &format!(
                        "licence lapsed: {reason}; enterprise entitlements off, MQTT still serving"
                    ),
                    serde_json::json!({"reason": reason}),
                );
            }
        }
        state
    }

    /// Record a node-ceiling refusal as an alarm that names the ceiling
    /// and the count, so the operator sees why membership was refused.
    pub fn note_ceiling_refusal(&self, alarms: &crate::v5::alarms::AlarmStore, message: &str) {
        alarms.activate("licence_node_ceiling", message, serde_json::json!({}));
    }
}

impl Default for LicenceStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Status document for the operator: identity, customer, expiry,
/// entitlements, signing key id and time remaining, so nobody needs the
/// logs to answer what they are licensed for.
fn status_json(identity: &str, state: &InstallationState, warn_days: u64) -> serde_json::Value {
    match state {
        InstallationState::Trial { days_remaining } => serde_json::json!({
            "state": "trial",
            "identity": identity,
            "customer": null,
            "expires_at": null,
            "entitlements": ["clustering"],
            "entitlements_on": true,
            "days_remaining": days_remaining,
            "grace_total_days": null,
            "max_nodes": null,
            "kid": null,
            "expiry_warn_days": warn_days,
            "approaching_expiry": days_remaining <= &warn_days,
            "hint": trial_request_hint(),
        }),
        InstallationState::Valid {
            customer,
            expires_at,
            max_nodes,
            features,
            kid,
            days_remaining,
        } => serde_json::json!({
            "state": "valid",
            "identity": identity,
            "customer": customer,
            "expires_at": expires_at,
            "entitlements": features,
            "entitlements_on": true,
            "days_remaining": days_remaining,
            "grace_total_days": null,
            "max_nodes": max_nodes,
            "kid": kid,
            "expiry_warn_days": warn_days,
            "approaching_expiry": days_remaining <= &warn_days,
        }),
        InstallationState::Grace {
            customer,
            expires_at,
            days_remaining,
            grace_total_days,
            max_nodes,
            features,
            kid,
        } => serde_json::json!({
            "state": "grace",
            "identity": identity,
            "customer": customer,
            "expires_at": expires_at,
            "entitlements": features,
            "entitlements_on": true,
            "days_remaining": days_remaining,
            "grace_total_days": grace_total_days,
            "max_nodes": max_nodes,
            "kid": kid,
            "expiry_warn_days": warn_days,
            "approaching_expiry": true,
        }),
        InstallationState::Lapsed { reason } => serde_json::json!({
            "state": "lapsed",
            "identity": identity,
            "customer": null,
            "expires_at": null,
            "entitlements": [],
            "entitlements_on": false,
            "days_remaining": 0,
            "grace_total_days": null,
            "max_nodes": null,
            "kid": null,
            "expiry_warn_days": warn_days,
            "approaching_expiry": false,
            "reason": reason,
        }),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// `GET /api/v1/licence/request`: the installation licence request as
/// JSON (identity, public key, product version, requested entitlements
/// and a human-readable summary). Safe to email to sales.
pub async fn get_request(State(state): State<ApiState>) -> Response {
    match state
        .licence
        .generate_request(Some(3), vec!["clustering".to_string()], "")
    {
        Ok(request) => (axum::http::StatusCode::OK, Json(request)).into_response(),
        Err(reason) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": reason})),
        )
            .into_response(),
    }
}

/// Installation body for `POST /api/v1/licence/install`.
#[derive(Debug, Deserialize)]
pub struct InstallBody {
    /// The `INDRA-ENT-V2.<payload>.<signature>` token text.
    pub token: String,
}

/// `POST /api/v1/licence/install {"token"}`: verify and atomically store
/// the licence. Identity mismatch is its own 409 reason (the copy-to-a-
/// second-cluster case); every other rejection is a 400 with its own
/// distinct message. A failed install leaves any previous licence in
/// place.
pub async fn install_licence(
    State(state): State<ApiState>,
    Json(body): Json<InstallBody>,
) -> Response {
    let now = now_secs();
    match state.licence.install(&body.token, now) {
        Ok(payload) => {
            state.licence.refresh_alarms(&state.alarms, now);
            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({
                    "customer": payload.customer,
                    "expires_at": payload.expires_at,
                    "max_nodes": payload.max_nodes,
                    "kid": payload.kid,
                })),
            )
                .into_response()
        }
        Err(e @ InstallError::IdentityMismatch { .. }) => (
            axum::http::StatusCode::CONFLICT,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(other) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": other.to_string()})),
        )
            .into_response(),
    }
}

/// `GET /api/v1/licence/status`: identity, customer, expiry,
/// entitlements, signing key id and time remaining.
pub async fn get_status(State(state): State<ApiState>) -> Response {
    (
        axum::http::StatusCode::OK,
        Json(state.licence.status_at(now_secs())),
    )
        .into_response()
}

/// Request overrides for programmatic generation (kept serialisable so
/// the dashboard can offer the same file the node command writes).
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct RequestOverrides {
    #[serde(default)]
    pub requested_max_nodes: Option<usize>,
    #[serde(default)]
    pub requested_features: Vec<String>,
    #[serde(default)]
    pub customer_hint: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_cluster::{
        canonical_json_bytes, license::TOKEN_PREFIX, LicensePayload, TrustedKeys,
    };
    use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};

    fn signing_key(seed: u8) -> SigningKey {
        let bytes = [seed; 32];
        let field = p256::elliptic_curve::generic_array::GenericArray::clone_from_slice(&bytes);
        SigningKey::from_bytes(&field).expect("seed")
    }

    fn mint(
        signing: &SigningKey,
        kid: &str,
        node_id: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> String {
        let payload = LicensePayload {
            customer: "Acme".to_string(),
            max_nodes: 5,
            issued_at,
            expires_at,
            features: vec!["clustering".to_string()],
            node_id: node_id.to_string(),
            kid: kid.to_string(),
            grace_period_days: broker_cluster::DEFAULT_GRACE_DAYS,
        };
        let bytes = canonical_json_bytes(&payload).expect("json");
        let sig: p256::ecdsa::Signature = signing.sign(&bytes);
        format!(
            "{}.{}.{}",
            TOKEN_PREFIX,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
        )
    }

    fn seeded_store(identity: &str) -> (Arc<LicenceStore>, SigningKey) {
        let signing = signing_key(0xD1);
        let mut trusted = TrustedKeys::new();
        trusted.insert("key-d1".to_string(), VerifyingKey::from(&signing));
        let store = Arc::new(LicenceStore::new());
        store.set_trusted_keys(trusted);
        store.set_identity_for_tests(ClusterIdentity {
            identity: identity.to_string(),
            public_key_hex: "aa".to_string(),
            private_key_hex: "bb".to_string(),
            trial_started_at: 1_750_000_000,
            highest_seen_secs: 1_750_000_000,
        });
        (store, signing)
    }

    use base64::Engine as _;

    #[test]
    fn b2_04_api_request_install_status_round_trip() {
        let (store, signing) = seeded_store("cluster-api-1");
        let request = store
            .generate_request(Some(5), vec!["clustering".to_string()], "Acme")
            .expect("request");
        assert_eq!(request.installation_identity, "cluster-api-1");
        assert!(!request.cluster_public_key_hex.is_empty());
        assert!(request.summary.contains("cluster-api-1"));
        let token = mint(
            &signing,
            "key-d1",
            "cluster-api-1",
            1_749_999_900,
            1_760_000_000,
        );
        store.install(&token, 1_750_000_000).expect("installs");
        let status = store.status_at(1_750_000_000);
        assert_eq!(status["state"], "valid");
        assert_eq!(status["identity"], "cluster-api-1");
        assert_eq!(status["customer"], "Acme");
        assert_eq!(status["kid"], "key-d1");
        assert!(status["entitlements_on"].as_bool().expect("bool"));
    }

    #[test]
    fn b2_04_api_identity_mismatch_is_distinct() {
        let (store, signing) = seeded_store("cluster-api-2");
        let token = mint(
            &signing,
            "key-d1",
            "other-cluster",
            1_749_999_900,
            1_760_000_000,
        );
        let err = store.install(&token, 1_750_000_000).expect_err("mismatch");
        assert!(
            matches!(err, InstallError::IdentityMismatch { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("identity mismatch"));
    }

    #[test]
    fn b2_04_api_failed_install_keeps_previous() {
        let (store, signing) = seeded_store("cluster-api-3");
        let good = mint(
            &signing,
            "key-d1",
            "cluster-api-3",
            1_749_999_900,
            1_760_000_000,
        );
        store.install(&good, 1_750_000_000).expect("good");
        let bad = mint(
            &signing,
            "key-d1",
            "elsewhere",
            1_749_999_900,
            1_760_000_000,
        );
        assert!(store.install(&bad, 1_750_000_000).is_err());
        let status = store.status_at(1_750_000_000);
        assert_eq!(status["state"], "valid");
        assert_eq!(status["identity"], "cluster-api-3");
    }

    #[test]
    fn b2_04_api_grace_reports_days_remaining() {
        let (store, signing) = seeded_store("cluster-api-4");
        let now = 1_750_000_000u64;
        let token = mint(
            &signing,
            "key-d1",
            "cluster-api-4",
            now - 10_000_000,
            now - broker_cluster::SECS_PER_DAY,
        );
        // Expired one day ago: install rejects, but evaluation of the same
        // token reports grace with entitlements on.
        assert!(store.install(&token, now).is_err());
        let trusted = TrustedKeys::new();
        let _ = trusted;
        let identity = ClusterIdentity {
            identity: "cluster-api-4".to_string(),
            public_key_hex: "aa".to_string(),
            private_key_hex: "bb".to_string(),
            trial_started_at: now - 10,
            highest_seen_secs: now - 10,
        };
        let state = broker_cluster::evaluate_installation(
            &identity,
            Some(&token),
            &store.trusted.read().expect("lock").clone(),
            now,
        );
        assert_eq!(state.name(), "grace");
        assert!(state.entitlements_on());
    }

    #[test]
    fn b2_04_api_ceiling_refusal_raises_alarm() {
        use broker_cluster::join_admission;
        let alarms = crate::v5::alarms::AlarmStore::new();
        let state = InstallationState::Valid {
            customer: "Acme".to_string(),
            expires_at: 1_760_000_000,
            max_nodes: 2,
            features: vec!["clustering".to_string()],
            kid: "key-d1".to_string(),
            days_remaining: 100,
        };
        let err = join_admission(3, &state).expect_err("refused");
        let store = LicenceStore::new();
        store.note_ceiling_refusal(&alarms, &err);
        let active = alarms.list_active();
        assert!(
            active.iter().any(|a| a.name == "licence_node_ceiling"),
            "ceiling alarm raised"
        );
        let entry = active
            .iter()
            .find(|a| a.name == "licence_node_ceiling")
            .expect("entry");
        assert!(
            entry.message.contains('2'),
            "alarm names ceiling: {}",
            entry.message
        );
    }

    #[test]
    fn b2_04_api_grace_alarm_stays_active() {
        let (store, _signing) = seeded_store("cluster-api-5");
        let alarms = crate::v5::alarms::AlarmStore::new();
        // Drive the store into grace by installing a token that expires
        // then moving the clock: install while valid, then refresh later.
        let now = 1_750_000_000u64;
        let signing = signing_key(0xD2);
        let mut trusted = TrustedKeys::new();
        trusted.insert("key-d2".to_string(), VerifyingKey::from(&signing));
        store.set_trusted_keys(trusted);
        let token = mint(
            &signing,
            "key-d2",
            "cluster-api-5",
            now - 100,
            now + 10 * broker_cluster::SECS_PER_DAY,
        );
        store.install(&token, now).expect("installs while valid");
        let later = now + 11 * broker_cluster::SECS_PER_DAY;
        let state = store.refresh_alarms(&alarms, later);
        assert_eq!(state.name(), "grace");
        let active = alarms.list_active();
        assert!(
            active.iter().any(|a| a.name == "licence_grace"),
            "grace alarm stays active"
        );
    }

    #[tokio::test]
    async fn b2_04_api_status_route_shape() {
        let api = crate::ApiState::standalone(Arc::new(broker_rules::RuleEngine::new(
            16,
            broker_rules::BackpressurePolicy::DropOldest,
        )));
        api.licence.set_identity_for_tests(ClusterIdentity {
            identity: "cluster-http".to_string(),
            public_key_hex: "aa".to_string(),
            private_key_hex: "bb".to_string(),
            trial_started_at: 1_750_000_000,
            highest_seen_secs: 1_750_000_000,
        });
        let response = get_status(State(api)).await.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
