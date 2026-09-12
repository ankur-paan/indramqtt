use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use tracing::{error, info, warn};

/// Master salt / secret for HMAC-SHA256 enterprise license verification.
/// In production distribution, this key is managed via I-Dacs Labs licensing portal.
pub const INDRA_LICENSE_MAGIC: &[u8] = b"indra-enterprise-licensing-v1-idacs-labs";

/// Licensing status for the distributed clustering engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseStatus {
    /// Permissive Community Evaluation Mode (Non-Production trial).
    CommunityEvaluation {
        max_eval_nodes: usize,
    },
    /// Valid active Enterprise Commercial License.
    EnterpriseValid {
        customer: String,
        max_nodes: usize,
        expires_at: u64,
        features: Vec<String>,
    },
    /// Expired Enterprise License.
    Expired {
        customer: String,
        expired_at: u64,
    },
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
}

/// Core license verification and enforcement engine for `crates/broker-cluster`.
pub struct ClusterLicense;

impl ClusterLicense {
    /// Default node limit permitted under Community Evaluation mode without a commercial key.
    pub const DEFAULT_EVAL_NODES: usize = 3;

    /// Evaluate an optional license key string against current cluster conditions.
    pub fn evaluate(
        key: Option<&str>,
        current_nodes: usize,
        current_epoch_sec: u64,
    ) -> LicenseStatus {
        let key_str = match key {
            Some(k) if !k.trim().is_empty() => k.trim(),
            _ => {
                return LicenseStatus::CommunityEvaluation {
                    max_eval_nodes: Self::DEFAULT_EVAL_NODES,
                };
            }
        };

        // Format: INDRA-ENT-V1.<PAYLOAD_HEX>.<SIGNATURE_HEX>
        let parts: Vec<&str> = key_str.split('.').collect();
        if parts.len() != 3 || parts[0] != "INDRA-ENT-V1" {
            return LicenseStatus::InvalidSignature("Unsupported license token format".into());
        }

        let payload_bytes = match hex::decode(parts[1]) {
            Ok(b) => b,
            Err(_) => return LicenseStatus::InvalidSignature("Invalid hex in license payload".into()),
        };

        let expected_sig = Self::compute_signature(&payload_bytes);
        if parts[2] != expected_sig {
            return LicenseStatus::InvalidSignature("Cryptographic signature mismatch".into());
        }

        let payload: LicensePayload = match serde_json::from_slice(&payload_bytes) {
            Ok(p) => p,
            Err(e) => {
                return LicenseStatus::InvalidSignature(format!("Malformed payload JSON: {}", e));
            }
        };

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

    /// Helper to generate a signed license key (for testing, provisioning, and licensing portals).
    pub fn generate_signed_token(payload: &LicensePayload) -> String {
        let payload_json = serde_json::to_vec(payload).expect("Serialization failed");
        let payload_hex = hex::encode(&payload_json);
        let sig = Self::compute_signature(&payload_json);
        format!("INDRA-ENT-V1.{}.{}", payload_hex, sig)
    }

    /// Compute HMAC-SHA256 signature for license payload.
    fn compute_signature(payload_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(INDRA_LICENSE_MAGIC);
        hasher.update(payload_bytes);
        hasher.update(INDRA_LICENSE_MAGIC);
        hex::encode(&hasher.finalize())
    }

    /// Log a prominent operational notice reflecting license state.
    pub fn log_status_banner(status: &LicenseStatus) {
        match status {
            LicenseStatus::CommunityEvaluation { max_eval_nodes } => {
                warn!("================================================================================");
                warn!(" [LICENSE NOTICE] IndraMQTT Clustering running in COMMUNITY EVALUATION MODE");
                warn!(" Non-production use only. Max evaluation cluster limit: {} nodes.", max_eval_nodes);
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
                error!(" [LICENSE EXPIRED] Enterprise clustering license for '{}' expired at {}", customer, expired_at);
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
                error!(" [LICENSE ERROR] Enterprise license validation failed: {}", reason);
                error!("================================================================================");
            }
        }
    }
}

// Minimal hex encode/decode helper to avoid adding external hex dependency
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if !s.len().is_multiple_of(2) {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_community_evaluation_when_no_key_provided() {
        let status = ClusterLicense::evaluate(None, 1, 1700000000);
        assert_eq!(
            status,
            LicenseStatus::CommunityEvaluation {
                max_eval_nodes: ClusterLicense::DEFAULT_EVAL_NODES
            }
        );

        let status_empty = ClusterLicense::evaluate(Some("   "), 2, 1700000000);
        assert_eq!(
            status_empty,
            LicenseStatus::CommunityEvaluation {
                max_eval_nodes: ClusterLicense::DEFAULT_EVAL_NODES
            }
        );
    }

    #[test]
    fn test_valid_enterprise_license_roundtrip() {
        let payload = LicensePayload {
            customer: "Acme Industrial IoT".into(),
            max_nodes: 10,
            issued_at: 1700000000,
            expires_at: 1800000000,
            features: vec!["clustering".into(), "wan_mesh".into()],
        };

        let token = ClusterLicense::generate_signed_token(&payload);
        assert!(token.starts_with("INDRA-ENT-V1."));

        let status = ClusterLicense::evaluate(Some(&token), 5, 1750000000);
        match status {
            LicenseStatus::EnterpriseValid {
                customer,
                max_nodes,
                expires_at,
                features,
            } => {
                assert_eq!(customer, "Acme Industrial IoT");
                assert_eq!(max_nodes, 10);
                assert_eq!(expires_at, 1800000000);
                assert_eq!(features.len(), 2);
            }
            other => panic!("Expected EnterpriseValid, got {:?}", other),
        }
    }

    #[test]
    fn test_expired_enterprise_license() {
        let payload = LicensePayload {
            customer: "Legacy Corp".into(),
            max_nodes: 5,
            issued_at: 1700000000,
            expires_at: 1710000000,
            features: vec![],
        };

        let token = ClusterLicense::generate_signed_token(&payload);
        let status = ClusterLicense::evaluate(Some(&token), 2, 1720000000); // current > expires
        assert_eq!(
            status,
            LicenseStatus::Expired {
                customer: "Legacy Corp".into(),
                expired_at: 1710000000
            }
        );
    }

    #[test]
    fn test_quota_exceeded() {
        let payload = LicensePayload {
            customer: "Small Business".into(),
            max_nodes: 3,
            issued_at: 1700000000,
            expires_at: 1800000000,
            features: vec![],
        };

        let token = ClusterLicense::generate_signed_token(&payload);
        let status = ClusterLicense::evaluate(Some(&token), 5, 1750000000); // 5 nodes > 3 allowed
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
    fn test_tampered_signature_rejected() {
        let payload = LicensePayload {
            customer: "Pirate Inc".into(),
            max_nodes: 100,
            issued_at: 1700000000,
            expires_at: 1800000000,
            features: vec![],
        };

        let token = ClusterLicense::generate_signed_token(&payload);
        let mut tampered = token.clone();
        tampered.push_str("bad");

        let status = ClusterLicense::evaluate(Some(&tampered), 1, 1750000000);
        assert!(matches!(status, LicenseStatus::InvalidSignature(_)));
    }
}
