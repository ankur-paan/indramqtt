//! OCPP (Open Charge Point Protocol 1.6-J & 2.0.1-J) Gateway for IndraMQTT.
//!
//! Implements JSON-over-WebSocket framing for EV charging infrastructure:
//! - JSON-RPC frame codec:
//!   - `[2, "<uniqueId>", "<action>", { ... }]` (Call)
//!   - `[3, "<uniqueId>", { ... }]` (CallResult)
//!   - `[4, "<uniqueId>", "<errorCode>", "<errorDescription>", { ... }]` (CallError)
//! - Core action processing:
//!   - `BootNotification`
//!   - `Heartbeat`
//!   - `StatusNotification`
//!   - `MeterValues`
//!   - `Authorize`
//!   - `StartTransaction`
//!   - `StopTransaction`
//! - Bidirectional translation between EV charge stations and MQTT topics:
//!   - Uplink: `ocpp/{charge_point_id}/up/{action}`
//!   - Downlink: `ocpp/{charge_point_id}/dn/{action}`

use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum OcppError {
    #[error("Malformed JSON array frame")]
    MalformedFrame,
    #[error("Unsupported message type ID: {0}")]
    UnsupportedMessageType(u64),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Action not supported: {0}")]
    ActionNotSupported(String),
}

/// OCPP Message Type ID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcppMessageType {
    Call = 2,
    CallResult = 3,
    CallError = 4,
}

impl OcppMessageType {
    pub fn from_u64(val: u64) -> Option<Self> {
        match val {
            2 => Some(Self::Call),
            3 => Some(Self::CallResult),
            4 => Some(Self::CallError),
            _ => None,
        }
    }
}

/// Structured OCPP Message
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OcppMessage {
    Call {
        message_id: String,
        action: String,
        payload: Value,
    },
    CallResult {
        message_id: String,
        payload: Value,
    },
    CallError {
        message_id: String,
        error_code: String,
        error_description: String,
        error_details: Value,
    },
}

impl OcppMessage {
    /// Parse a raw JSON text frame into an OCPP message
    pub fn parse(raw: &str) -> Result<Self, OcppError> {
        let val: Value =
            serde_json::from_str(raw).map_err(|e| OcppError::Serialization(e.to_string()))?;

        let arr = val.as_array().ok_or(OcppError::MalformedFrame)?;
        if arr.is_empty() {
            return Err(OcppError::MalformedFrame);
        }

        let type_id = arr[0].as_u64().ok_or(OcppError::MalformedFrame)?;

        match OcppMessageType::from_u64(type_id) {
            Some(OcppMessageType::Call) => {
                if arr.len() < 4 {
                    return Err(OcppError::MalformedFrame);
                }
                let message_id = arr[1]
                    .as_str()
                    .ok_or(OcppError::MalformedFrame)?
                    .to_string();
                let action = arr[2]
                    .as_str()
                    .ok_or(OcppError::MalformedFrame)?
                    .to_string();
                let payload = arr[3].clone();
                Ok(Self::Call {
                    message_id,
                    action,
                    payload,
                })
            }
            Some(OcppMessageType::CallResult) => {
                if arr.len() < 3 {
                    return Err(OcppError::MalformedFrame);
                }
                let message_id = arr[1]
                    .as_str()
                    .ok_or(OcppError::MalformedFrame)?
                    .to_string();
                let payload = arr[2].clone();
                Ok(Self::CallResult {
                    message_id,
                    payload,
                })
            }
            Some(OcppMessageType::CallError) => {
                if arr.len() < 4 {
                    return Err(OcppError::MalformedFrame);
                }
                let message_id = arr[1]
                    .as_str()
                    .ok_or(OcppError::MalformedFrame)?
                    .to_string();
                let error_code = arr[2]
                    .as_str()
                    .ok_or(OcppError::MalformedFrame)?
                    .to_string();
                let error_description = arr[3].as_str().unwrap_or("").to_string();
                let error_details = arr
                    .get(4)
                    .cloned()
                    .unwrap_or(Value::Object(Default::default()));
                Ok(Self::CallError {
                    message_id,
                    error_code,
                    error_description,
                    error_details,
                })
            }
            None => Err(OcppError::UnsupportedMessageType(type_id)),
        }
    }

    /// Serialize this message to an OCPP JSON array string
    pub fn to_json_string(&self) -> Result<String, OcppError> {
        let val = match self {
            Self::Call {
                message_id,
                action,
                payload,
            } => {
                serde_json::json!([2, message_id, action, payload])
            }
            Self::CallResult {
                message_id,
                payload,
            } => {
                serde_json::json!([3, message_id, payload])
            }
            Self::CallError {
                message_id,
                error_code,
                error_description,
                error_details,
            } => {
                serde_json::json!([4, message_id, error_code, error_description, error_details])
            }
        };

        serde_json::to_string(&val).map_err(|e| OcppError::Serialization(e.to_string()))
    }
}

/// State of an active EV Charge Point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChargePointState {
    pub charge_point_id: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub status: String,
    pub last_heartbeat: u64,
    pub current_transaction_id: Option<u64>,
}

/// OCPP Gateway Manager for IndraMQTT
pub struct OcppGateway {
    charge_points: Arc<RwLock<HashMap<String, ChargePointState>>>,
    heartbeat_interval_secs: u64,
}

impl Default for OcppGateway {
    fn default() -> Self {
        Self::new(300)
    }
}

impl OcppGateway {
    pub fn new(heartbeat_interval_secs: u64) -> Self {
        Self {
            charge_points: Arc::new(RwLock::new(HashMap::new())),
            heartbeat_interval_secs,
        }
    }

    fn now_iso8601() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{now}")
    }

    /// Handle an incoming message from a charge point:
    /// 1. Updates charge point status state.
    /// 2. Produces standard MQTT topic & payload for core broker routing.
    /// 3. Returns an automated OCPP CallResult frame to respond to the charge point.
    pub fn handle_inbound_message(
        &self,
        charge_point_id: &str,
        raw_frame: &str,
    ) -> Result<(String, Bytes, Option<String>), OcppError> {
        let msg = OcppMessage::parse(raw_frame)?;

        match msg {
            OcppMessage::Call {
                message_id,
                action,
                payload,
            } => {
                let topic = format!("ocpp/{charge_point_id}/up/{action}");
                let mqtt_payload = serde_json::json!({
                    "charge_point_id": charge_point_id,
                    "action": action,
                    "timestamp": Self::now_iso8601(),
                    "payload": payload
                });

                // Generate protocol response for known actions
                let response_payload = match action.as_str() {
                    "BootNotification" => {
                        let vendor = payload["chargePointVendor"].as_str().map(|s| s.to_string());
                        let model = payload["chargePointModel"].as_str().map(|s| s.to_string());
                        let fw = payload["firmwareVersion"].as_str().map(|s| s.to_string());

                        let mut points = self.charge_points.write();
                        points.insert(
                            charge_point_id.to_string(),
                            ChargePointState {
                                charge_point_id: charge_point_id.to_string(),
                                vendor,
                                model,
                                firmware_version: fw,
                                status: "Available".to_string(),
                                last_heartbeat: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                current_transaction_id: None,
                            },
                        );

                        serde_json::json!({
                            "status": "Accepted",
                            "currentTime": Self::now_iso8601(),
                            "interval": self.heartbeat_interval_secs
                        })
                    }
                    "Heartbeat" => {
                        if let Some(cp) = self.charge_points.write().get_mut(charge_point_id) {
                            cp.last_heartbeat = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                        }
                        serde_json::json!({
                            "currentTime": Self::now_iso8601()
                        })
                    }
                    "StatusNotification" => {
                        let status = payload["status"].as_str().unwrap_or("Available");
                        if let Some(cp) = self.charge_points.write().get_mut(charge_point_id) {
                            cp.status = status.to_string();
                        }
                        serde_json::json!({})
                    }
                    "Authorize" => {
                        serde_json::json!({
                            "idTagInfo": {
                                "status": "Accepted",
                                "expiryDate": "2030-01-01T00:00:00Z",
                                "parentIdTag": null
                            }
                        })
                    }
                    "StartTransaction" => {
                        let tx_id = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;

                        if let Some(cp) = self.charge_points.write().get_mut(charge_point_id) {
                            cp.status = "Charging".to_string();
                            cp.current_transaction_id = Some(tx_id);
                        }

                        serde_json::json!({
                            "transactionId": tx_id,
                            "idTagInfo": {
                                "status": "Accepted"
                            }
                        })
                    }
                    "StopTransaction" => {
                        if let Some(cp) = self.charge_points.write().get_mut(charge_point_id) {
                            cp.status = "Available".to_string();
                            cp.current_transaction_id = None;
                        }

                        serde_json::json!({
                            "idTagInfo": {
                                "status": "Accepted"
                            }
                        })
                    }
                    "MeterValues" => {
                        serde_json::json!({})
                    }
                    _ => {
                        serde_json::json!({})
                    }
                };

                let response_frame = OcppMessage::CallResult {
                    message_id,
                    payload: response_payload,
                }
                .to_json_string()?;

                let mqtt_bytes = Bytes::from(serde_json::to_vec(&mqtt_payload).unwrap());
                Ok((topic, mqtt_bytes, Some(response_frame)))
            }
            OcppMessage::CallResult {
                message_id,
                payload,
            } => {
                let topic = format!("ocpp/{charge_point_id}/up/result");
                let mqtt_payload = serde_json::json!({
                    "charge_point_id": charge_point_id,
                    "message_id": message_id,
                    "payload": payload
                });
                let mqtt_bytes = Bytes::from(serde_json::to_vec(&mqtt_payload).unwrap());
                Ok((topic, mqtt_bytes, None))
            }
            OcppMessage::CallError {
                message_id,
                error_code,
                error_description,
                error_details,
            } => {
                let topic = format!("ocpp/{charge_point_id}/up/error");
                let mqtt_payload = serde_json::json!({
                    "charge_point_id": charge_point_id,
                    "message_id": message_id,
                    "error_code": error_code,
                    "error_description": error_description,
                    "error_details": error_details,
                });
                let mqtt_bytes = Bytes::from(serde_json::to_vec(&mqtt_payload).unwrap());
                Ok((topic, mqtt_bytes, None))
            }
        }
    }

    /// Build a downlink Call frame to send to a charge point (e.g. RemoteStartTransaction, Reset)
    pub fn build_downlink_call(
        message_id: &str,
        action: &str,
        payload: Value,
    ) -> Result<String, OcppError> {
        OcppMessage::Call {
            message_id: message_id.to_string(),
            action: action.to_string(),
            payload,
        }
        .to_json_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocpp_message_codec() {
        // 1. Call frame
        let call_json = r#"[2,"19223201","BootNotification",{"chargePointVendor":"IndraCharge","chargePointModel":"HyperCharger-350kW"}]"#;
        let msg = OcppMessage::parse(call_json).expect("parse call");
        match &msg {
            OcppMessage::Call {
                message_id,
                action,
                payload,
            } => {
                assert_eq!(message_id, "19223201");
                assert_eq!(action, "BootNotification");
                assert_eq!(payload["chargePointVendor"], "IndraCharge");
            }
            _ => panic!("expected Call"),
        }

        let serialized = msg.to_json_string().unwrap();
        assert!(serialized.contains("BootNotification"));

        // 2. CallResult frame
        let res_json = r#"[3,"19223201",{"status":"Accepted"}]"#;
        let res_msg = OcppMessage::parse(res_json).expect("parse call result");
        assert!(matches!(res_msg, OcppMessage::CallResult { .. }));

        // 3. CallError frame
        let err_json = r#"[4,"19223201","NotSupported","Feature not implemented",{}]"#;
        let err_msg = OcppMessage::parse(err_json).expect("parse call error");
        assert!(matches!(err_msg, OcppMessage::CallError { .. }));
    }

    #[test]
    fn test_ocpp_gateway_inbound_flow() {
        let gw = OcppGateway::new(300);

        // 1. BootNotification
        let boot_req = r#"[2,"msg-1","BootNotification",{"chargePointVendor":"Tesla","chargePointModel":"SuperchargerV4","firmwareVersion":"2026.4.1"}]"#;
        let (topic, payload, resp) = gw
            .handle_inbound_message("charger-station-01", boot_req)
            .expect("boot handle");

        assert_eq!(topic, "ocpp/charger-station-01/up/BootNotification");
        let parsed: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed["charge_point_id"], "charger-station-01");
        assert!(resp.is_some());
        let resp_str = resp.unwrap();
        assert!(resp_str.contains("\"status\":\"Accepted\""));

        // 2. MeterValues
        let meter_req = r#"[2,"msg-2","MeterValues",{"connectorId":1,"transactionId":10001,"meterValue":[{"timestamp":"2026-09-13T12:00:00Z","sampledValue":[{"value":"45.8","unit":"kWh"}]}]}]"#;
        let (m_topic, m_payload, m_resp) = gw
            .handle_inbound_message("charger-station-01", meter_req)
            .expect("meter values handle");

        assert_eq!(m_topic, "ocpp/charger-station-01/up/MeterValues");
        let m_parsed: Value = serde_json::from_slice(&m_payload).unwrap();
        assert_eq!(m_parsed["payload"]["connectorId"], 1);
        assert!(m_resp.is_some());
    }
}
