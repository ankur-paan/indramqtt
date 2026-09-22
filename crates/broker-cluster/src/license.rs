use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use tracing::{error, info, warn};

/// Ed25519 public key that verifies enterprise licence tokens.
///
/// The matching private key lives in offline provisioning only and is never
/// committed to this repository. Tokens carry a detached Ed25519 signature
/// over the JSON licence payload.
pub const LICENSE_PUBLIC_KEY_BYTES: [u8; 32] = [
    49, 149, 157, 81, 38, 112, 179, 198, 72, 164, 240, 172, 227, 86, 244, 16, 246, 103, 223, 238,
    238, 203, 212, 77, 28, 68, 212, 24, 113, 43, 182, 133,
];

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
    /// Expired Enterprise License.
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
}

/// Core license verification engine for `crates/broker-cluster`.
///
/// Verification only: this crate cannot mint tokens. Signing lives in
/// `tools/license-signer`, outside the workspace build, reading the private
/// key from a file path.
pub struct ClusterLicense;

impl ClusterLicense {
    /// Default node limit permitted under Community Evaluation mode without a commercial key.
    pub const DEFAULT_EVAL_NODES: usize = 3;

    /// Evaluate an optional license key against current cluster conditions.
    ///
    /// `expected_node_id` is the local node identity the licence must be
    /// bound to. Expiry and node binding are both enforced; any failure
    /// returns an explicit non-valid status and never falls back to
    /// community mode.
    pub fn evaluate(
        key: Option<&str>,
        current_nodes: usize,
        current_epoch_sec: u64,
        expected_node_id: &str,
    ) -> LicenseStatus {
        let verifying_key = match VerifyingKey::from_bytes(&LICENSE_PUBLIC_KEY_BYTES) {
            Ok(k) => k,
            Err(_) => {
                return LicenseStatus::InvalidSignature("licence verifier misconfigured".into());
            }
        };
        Self::evaluate_with_key(
            key,
            current_nodes,
            current_epoch_sec,
            expected_node_id,
            &verifying_key,
        )
    }

    /// Verify with an explicit public key. Used by tests with ephemeral keys;
    /// production paths call [`ClusterLicense::evaluate`], which pins the
    /// shipped public key above.
    pub fn evaluate_with_key(
        key: Option<&str>,
        current_nodes: usize,
        current_epoch_sec: u64,
        expected_node_id: &str,
        verifying_key: &VerifyingKey,
    ) -> LicenseStatus {
        let key_str = match key {
            Some(k) if !k.trim().is_empty() => k.trim(),
            _ => {
                return LicenseStatus::CommunityEvaluation {
                    max_eval_nodes: Self::DEFAULT_EVAL_NODES,
                };
            }
        };

        // Format: INDRA-ENT-V1.<PAYLOAD_B64URL>.<SIGNATURE_B64URL>
        // where the signature is a detached Ed25519 signature over the raw
        // JSON payload bytes.
        let mut parts = key_str.split('.');
        let (Some(prefix), Some(payload_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return LicenseStatus::InvalidSignature("Unsupported license token format".into());
        };
        if prefix != "INDRA-ENT-V1" {
            return LicenseStatus::InvalidSignature("Unsupported license token format".into());
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
        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => {
                return LicenseStatus::InvalidSignature("Malformed license signature".into());
            }
        };
        if verifying_key.verify(&payload_bytes, &signature).is_err() {
            return LicenseStatus::InvalidSignature("Cryptographic signature mismatch".into());
        }

        let payload: LicensePayload = match serde_json::from_slice(&payload_bytes) {
            Ok(p) => p,
            Err(e) => {
                return LicenseStatus::InvalidSignature(format!("Malformed payload JSON: {e}"));
            }
        };

        if payload.node_id.trim().is_empty() {
            return LicenseStatus::InvalidSignature("licence missing node binding".into());
        }
        if payload.node_id != expected_node_id {
            return LicenseStatus::InvalidSignature(format!(
                "licence issued for '{}', not '{}'",
                payload.node_id, expected_node_id
            ));
        }

        // Check expiration
        if current_epoch_sec > payload.expires_at {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Token minted offline with the private counterpart of
    /// [`LICENSE_PUBLIC_KEY_BYTES`]. The private key was discarded after
    /// minting; only this token and the public key remain in the tree.
    const EMBEDDED_VALID_TOKEN: &str = "INDRA-ENT-V1.eyJjdXN0b21lciI6IkFjbWUgSW5kdXN0cmlhbCBJb1QiLCJtYXhfbm9kZXMiOjEwLCJpc3N1ZWRfYXQiOjE3MDAwMDAwMDAsImV4cGlyZXNfYXQiOjIwMDAwMDAwMDAsImZlYXR1cmVzIjpbImNsdXN0ZXJpbmciLCJ3YW5fbWVzaCJdLCJub2RlX2lkIjoidGVzdC1ub2RlLTEifQ.xpywSCA4CV9X_2RNYU-sEDiMBJadRKXMrWsLeK-IS9WG_IsQuI8fkFgEHodH2dmqG1NVOhZ5QQpwviNq4f43Bw";
    const EMBEDDED_EXPIRED_TOKEN: &str = "INDRA-ENT-V1.eyJjdXN0b21lciI6IkxlZ2FjeSBDb3JwIiwibWF4X25vZGVzIjo1LCJpc3N1ZWRfYXQiOjE3MDAwMDAwMDAsImV4cGlyZXNfYXQiOjE3MTAwMDAwMDAsImZlYXR1cmVzIjpbXSwibm9kZV9pZCI6InRlc3Qtbm9kZS0xIn0.B9yTPBNMK1Vx7SM3rq-izY9Nx90Fho-wu9j3hsB66-_tHpn36jzs6oHMPf051IekhfFmWNLW1exuLi981GbYBQ";

    #[test]
    fn test_community_evaluation_when_no_key_provided() {
        let status = ClusterLicense::evaluate(None, 1, 1700000000, "test-node-1");
        assert_eq!(
            status,
            LicenseStatus::CommunityEvaluation {
                max_eval_nodes: ClusterLicense::DEFAULT_EVAL_NODES
            }
        );

        let status_empty = ClusterLicense::evaluate(Some("   "), 2, 1700000000, "test-node-1");
        assert_eq!(
            status_empty,
            LicenseStatus::CommunityEvaluation {
                max_eval_nodes: ClusterLicense::DEFAULT_EVAL_NODES
            }
        );
    }

    #[test]
    fn test_valid_token_signed_with_real_private_key_verifies() {
        let status =
            ClusterLicense::evaluate(Some(EMBEDDED_VALID_TOKEN), 5, 1750000000, "test-node-1");
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
                assert_eq!(features.len(), 2);
            }
            other => panic!("Expected EnterpriseValid, got {other:?}"),
        }
    }

    #[test]
    fn test_forged_signature_rejected() {
        let mut tampered = EMBEDDED_VALID_TOKEN.to_string();
        tampered.push('A');
        let status = ClusterLicense::evaluate(Some(&tampered), 1, 1750000000, "test-node-1");
        assert!(matches!(status, LicenseStatus::InvalidSignature(_)));
    }

    #[test]
    fn test_edited_payload_rejected() {
        let mut parts = EMBEDDED_VALID_TOKEN.split('.');
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
            "INDRA-ENT-V1.{}.{}",
            URL_SAFE_NO_PAD.encode(&payload_json),
            sig_b64
        );
        let status = ClusterLicense::evaluate(Some(&edited), 1, 1750000000, "test-node-1");
        assert!(matches!(status, LicenseStatus::InvalidSignature(_)));
    }

    #[test]
    fn test_expired_token_rejected() {
        let status =
            ClusterLicense::evaluate(Some(EMBEDDED_EXPIRED_TOKEN), 2, 1720000000, "test-node-1");
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
        let status =
            ClusterLicense::evaluate(Some(EMBEDDED_VALID_TOKEN), 1, 1750000000, "other-node-9");
        assert!(matches!(status, LicenseStatus::InvalidSignature(_)));
    }

    #[test]
    fn test_quota_exceeded_with_ephemeral_key() {
        use ed25519_dalek::{Signer, SigningKey};

        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        let payload = LicensePayload {
            customer: "Small Business".into(),
            max_nodes: 3,
            issued_at: 1700000000,
            expires_at: 1800000000,
            features: vec![],
            node_id: "test-node-1".into(),
        };
        let payload_json = serde_json::to_vec(&payload).expect("json");
        let sig = signing.sign(&payload_json);
        let token = format!(
            "INDRA-ENT-V1.{}.{}",
            URL_SAFE_NO_PAD.encode(&payload_json),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );
        let status = ClusterLicense::evaluate_with_key(
            Some(&token),
            5,
            1750000000,
            "test-node-1",
            &verifying,
        );
        assert_eq!(
            status,
            LicenseStatus::QuotaExceeded {
                customer: "Small Business".into(),
                current_nodes: 5,
                max_nodes: 3
            }
        );
    }
}
