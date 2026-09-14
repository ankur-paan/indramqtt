//! Multi-Protocol Gateway Engine for IndraMQTT.
//!
//! Provides protocol adaptation and framing for non-MQTT IoT and Industrial protocols:
//! - **CoAP (RFC 7252)**: UDP pub/sub endpoint mapping (`/ps/<topic>`).
//! - **LwM2M (OMA Spec)**: Device lifecycle registration (`/rd`), OMA TLV / SenML JSON telemetry, and downlink commands.
//! - **OCPP (1.6-J & 2.0.1-J)**: Electric Vehicle Charge Point JSON-over-WebSocket protocol with automated CallResult dispatch.

pub mod coap;
pub mod lwm2m;
pub mod ocpp;

use broker_protocol::QoS;
use bytes::Bytes;
use coap::{CoapGatewayHandler, CoapMessage};
use lwm2m::Lwm2mGateway;
use ocpp::OcppGateway;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayProtocol {
    CoAP,
    LwM2M,
    OCPP,
}

/// Normalized Gateway Inbound Message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayMessage {
    pub protocol: GatewayProtocol,
    pub client_id: String,
    pub topic: String,
    pub payload: Bytes,
    pub qos: QoS,
}

/// Unified Gateway Manager coordinating CoAP, LwM2M, and OCPP adapters
pub struct GatewayManager {
    pub coap_handler: Arc<CoapGatewayHandler>,
    pub lwm2m: Arc<Lwm2mGateway>,
    pub ocpp: Arc<OcppGateway>,
    inbound_tx: UnboundedSender<GatewayMessage>,
}

impl GatewayManager {
    pub fn new(heartbeat_interval_secs: u64) -> (Self, UnboundedReceiver<GatewayMessage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mgr = Self {
            coap_handler: Arc::new(CoapGatewayHandler::new()),
            lwm2m: Arc::new(Lwm2mGateway::new()),
            ocpp: Arc::new(OcppGateway::new(heartbeat_interval_secs)),
            inbound_tx: tx,
        };
        (mgr, rx)
    }

    /// Process an incoming CoAP message, emit a normalized GatewayMessage if it's a publish,
    /// and return the CoAP response message (if any).
    pub fn handle_coap(
        &self,
        client_id: &str,
        msg: &CoapMessage,
    ) -> Result<Option<CoapMessage>, coap::CoapError> {
        let resp = self.coap_handler.handle_message(msg)?;

        // If this was a publish (POST or PUT), forward to core broker
        if msg.code == coap::CoapCode::POST || msg.code == coap::CoapCode::PUT {
            let path = msg.uri_path();
            let topic = path.strip_prefix("ps/").unwrap_or(&path).to_string();
            if !topic.is_empty() {
                let _ = self.inbound_tx.send(GatewayMessage {
                    protocol: GatewayProtocol::CoAP,
                    client_id: client_id.to_string(),
                    topic,
                    payload: msg.payload.clone(),
                    qos: QoS::AtLeastOnce,
                });
            }
        }

        Ok(resp)
    }

    /// Process an incoming LwM2M TLV message, emit normalized GatewayMessage,
    /// and return `(topic, json_payload)`.
    pub fn handle_lwm2m_tlv(
        &self,
        endpoint: &str,
        object_id: u16,
        instance_id: u16,
        tlv_bytes: &[u8],
    ) -> Result<(String, Bytes), lwm2m::Lwm2mError> {
        let (topic, payload) =
            self.lwm2m
                .process_uplink_tlv(endpoint, object_id, instance_id, tlv_bytes)?;

        let _ = self.inbound_tx.send(GatewayMessage {
            protocol: GatewayProtocol::LwM2M,
            client_id: endpoint.to_string(),
            topic: topic.clone(),
            payload: payload.clone(),
            qos: QoS::AtLeastOnce,
        });

        Ok((topic, payload))
    }

    /// Process an incoming OCPP JSON frame, emit normalized GatewayMessage,
    /// and return the automated response frame.
    pub fn handle_ocpp_frame(
        &self,
        charge_point_id: &str,
        raw_frame: &str,
    ) -> Result<(String, Bytes, Option<String>), ocpp::OcppError> {
        let (topic, payload, resp) = self
            .ocpp
            .handle_inbound_message(charge_point_id, raw_frame)?;

        let _ = self.inbound_tx.send(GatewayMessage {
            protocol: GatewayProtocol::OCPP,
            client_id: charge_point_id.to_string(),
            topic: topic.clone(),
            payload: payload.clone(),
            qos: QoS::AtLeastOnce,
        });

        Ok((topic, payload, resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_manager_flow() {
        let (mgr, mut rx) = GatewayManager::new(300);

        // 1. CoAP publish
        let coap_msg = CoapMessage {
            message_type: coap::CoapType::Confirmable,
            code: coap::CoapCode::POST,
            message_id: 1,
            token: Bytes::from_static(b"t1"),
            options: vec![
                coap::CoapOption {
                    number: coap::option_number::URI_PATH,
                    value: Bytes::from_static(b"ps"),
                },
                coap::CoapOption {
                    number: coap::option_number::URI_PATH,
                    value: Bytes::from_static(b"coap/temp"),
                },
            ],
            payload: Bytes::from_static(b"{\"temperature\": 26.3}"),
        };

        let resp = mgr.handle_coap("coap-client-1", &coap_msg).unwrap();
        assert!(resp.is_some());

        let gw_msg = rx.try_recv().expect("receive coap gateway message");
        assert_eq!(gw_msg.protocol, GatewayProtocol::CoAP);
        assert_eq!(gw_msg.topic, "coap/temp");
        assert_eq!(
            gw_msg.payload,
            Bytes::from_static(b"{\"temperature\": 26.3}")
        );

        // 2. LwM2M TLV
        let temp_val = 21.5f32.to_be_bytes().to_vec();
        let tlv_rec = lwm2m::TlvRecord::resource_value(5700, temp_val);
        let tlv_bytes = tlv_rec.encode();

        let (l_topic, _) = mgr
            .handle_lwm2m_tlv("lwm2m-node-88", 3303, 0, &tlv_bytes)
            .unwrap();
        assert_eq!(l_topic, "lwm2m/lwm2m-node-88/up/data");

        let l_gw_msg = rx.try_recv().expect("receive lwm2m gateway message");
        assert_eq!(l_gw_msg.protocol, GatewayProtocol::LwM2M);
        assert_eq!(l_gw_msg.topic, "lwm2m/lwm2m-node-88/up/data");

        // 3. OCPP
        let ocpp_frame = r#"[2,"ocpp-10","Heartbeat",{}]"#;
        let (o_topic, _, o_resp) = mgr.handle_ocpp_frame("ev-charger-55", ocpp_frame).unwrap();
        assert_eq!(o_topic, "ocpp/ev-charger-55/up/Heartbeat");
        assert!(o_resp.is_some());

        let o_gw_msg = rx.try_recv().expect("receive ocpp gateway message");
        assert_eq!(o_gw_msg.protocol, GatewayProtocol::OCPP);
        assert_eq!(o_gw_msg.topic, "ocpp/ev-charger-55/up/Heartbeat");
    }
}
