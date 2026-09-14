//! LwM2M (Lightweight M2M) Gateway for IndraMQTT.
//!
//! Provides OMA LwM2M v1.0/v1.1/v1.2 device management and telemetry translation:
//! - Device registration interface (`/rd?ep={endpoint}&lt={lifetime}`)
//! - OMA TLV (Type-Length-Value) parser and encoder
//! - LwM2M JSON (SenML / OMA JSON) parser and encoder
//! - Bidirectional mapping between LwM2M objects and MQTT topics:
//!   - Uplink: `lwm2m/{endpoint}/up/data`
//!   - Downlink: `lwm2m/{endpoint}/dn/write` and `lwm2m/{endpoint}/dn/read`

use bytes::{Buf, BufMut, Bytes, BytesMut};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Lwm2mError {
    #[error("Buffer too short for LwM2M TLV")]
    BufferTooShort,
    #[error("Invalid TLV identifier length")]
    InvalidIdentifierLength,
    #[error("Invalid TLV length field")]
    InvalidLengthField,
    #[error("Malformed JSON payload: {0}")]
    JsonError(String),
    #[error("Device not registered: {0}")]
    DeviceNotFound(String),
    #[error("Missing endpoint query parameter in registration")]
    MissingEndpoint,
}

/// OMA TLV Identifier Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvType {
    ObjectInstance = 0b00,
    ResourceInstance = 0b01,
    MultipleResource = 0b10,
    ResourceWithValue = 0b11,
}

impl TlvType {
    pub fn from_u8(val: u8) -> Self {
        match val & 0b11 {
            0b00 => Self::ObjectInstance,
            0b01 => Self::ResourceInstance,
            0b10 => Self::MultipleResource,
            _ => Self::ResourceWithValue,
        }
    }
}

/// A parsed OMA LwM2M TLV record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlvRecord {
    pub tlv_type: u8,
    pub identifier: u16,
    pub value: Vec<u8>,
    pub children: Vec<TlvRecord>,
}

impl TlvRecord {
    /// Encode a single resource with value as TLV bytes
    pub fn resource_value(id: u16, val: Vec<u8>) -> Self {
        Self {
            tlv_type: TlvType::ResourceWithValue as u8,
            identifier: id,
            value: val,
            children: Vec::new(),
        }
    }

    /// Encode an object instance containing multiple resources
    pub fn object_instance(instance_id: u16, children: Vec<TlvRecord>) -> Self {
        Self {
            tlv_type: TlvType::ObjectInstance as u8,
            identifier: instance_id,
            value: Vec::new(),
            children,
        }
    }

    /// Decode raw TLV bytes into a list of TLV records
    pub fn decode_all(mut src: &[u8]) -> Result<Vec<Self>, Lwm2mError> {
        let mut records = Vec::new();
        while !src.is_empty() {
            let record = Self::decode_one(&mut src)?;
            records.push(record);
        }
        Ok(records)
    }

    fn decode_one(src: &mut &[u8]) -> Result<Self, Lwm2mError> {
        if src.is_empty() {
            return Err(Lwm2mError::BufferTooShort);
        }

        let header = src.get_u8();
        let type_val = (header >> 6) & 0b11;
        let id_len_16 = (header & 0b0010_0000) != 0;
        let len_type = (header >> 3) & 0b11;
        let inline_len = (header & 0b0000_0111) as usize;

        // Read Identifier (8-bit or 16-bit)
        let identifier = if id_len_16 {
            if src.len() < 2 {
                return Err(Lwm2mError::InvalidIdentifierLength);
            }
            src.get_u16()
        } else {
            if src.is_empty() {
                return Err(Lwm2mError::InvalidIdentifierLength);
            }
            src.get_u8() as u16
        };

        // Read Length
        let value_len = match len_type {
            0b00 => inline_len,
            0b01 => {
                if src.is_empty() {
                    return Err(Lwm2mError::InvalidLengthField);
                }
                src.get_u8() as usize
            }
            0b10 => {
                if src.len() < 2 {
                    return Err(Lwm2mError::InvalidLengthField);
                }
                src.get_u16() as usize
            }
            0b11 => {
                if src.len() < 3 {
                    return Err(Lwm2mError::InvalidLengthField);
                }
                let b0 = src.get_u8() as usize;
                let b1 = src.get_u8() as usize;
                let b2 = src.get_u8() as usize;
                (b0 << 16) | (b1 << 8) | b2
            }
            _ => unreachable!(),
        };

        if src.len() < value_len {
            return Err(Lwm2mError::BufferTooShort);
        }

        let val_bytes = &src[..value_len];
        src.advance(value_len);

        // If this is an ObjectInstance or MultipleResource, parse children
        let (val, children) = if type_val == (TlvType::ObjectInstance as u8)
            || type_val == (TlvType::MultipleResource as u8)
        {
            let mut sub_slice = val_bytes;
            let mut child_list = Vec::new();
            while !sub_slice.is_empty() {
                child_list.push(Self::decode_one(&mut sub_slice)?);
            }
            (Vec::new(), child_list)
        } else {
            (val_bytes.to_vec(), Vec::new())
        };

        Ok(Self {
            tlv_type: type_val,
            identifier,
            value: val,
            children,
        })
    }

    /// Encode this TLV record into bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        self.encode_into(&mut buf);
        buf.freeze()
    }

    fn encode_into(&self, buf: &mut BytesMut) {
        let payload = if !self.children.is_empty() {
            let mut sub_buf = BytesMut::new();
            for child in &self.children {
                child.encode_into(&mut sub_buf);
            }
            sub_buf.freeze()
        } else {
            Bytes::copy_from_slice(&self.value)
        };

        let val_len = payload.len();
        let id_is_16 = self.identifier > 255;

        let (len_type, inline_len) = if val_len <= 7 {
            (0b00u8, val_len as u8)
        } else if val_len <= 255 {
            (0b01u8, 0)
        } else if val_len <= 65535 {
            (0b10u8, 0)
        } else {
            (0b11u8, 0)
        };

        let mut header = (self.tlv_type & 0b11) << 6;
        if id_is_16 {
            header |= 0b0010_0000;
        }
        header |= (len_type & 0b11) << 3;
        header |= inline_len & 0b0000_0111;

        buf.put_u8(header);

        if id_is_16 {
            buf.put_u16(self.identifier);
        } else {
            buf.put_u8(self.identifier as u8);
        }

        match len_type {
            0b01 => buf.put_u8(val_len as u8),
            0b10 => buf.put_u16(val_len as u16),
            0b11 => {
                buf.put_u8(((val_len >> 16) & 0xFF) as u8);
                buf.put_u8(((val_len >> 8) & 0xFF) as u8);
                buf.put_u8((val_len & 0xFF) as u8);
            }
            _ => {}
        }

        buf.put_slice(&payload);
    }
}

/// SenML / LwM2M JSON record
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SenMlRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bn: Option<String>, // Base Name (e.g. "/3303/0/")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bt: Option<f64>, // Base Time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>, // Name (e.g. "5700")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v: Option<f64>, // Value (numeric)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vs: Option<String>, // Value (string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vb: Option<bool>, // Value (boolean)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub u: Option<String>, // Unit
}

/// Registered LwM2M Device
#[derive(Debug, Clone)]
pub struct Lwm2mDevice {
    pub endpoint: String,
    pub registration_id: String,
    pub lifetime: Duration,
    pub last_seen: Instant,
    pub binding: String,
    pub version: String,
}

/// LwM2M Gateway Engine
pub struct Lwm2mGateway {
    devices: Arc<RwLock<HashMap<String, Lwm2mDevice>>>, // endpoint -> device
    reg_id_to_endpoint: Arc<RwLock<HashMap<String, String>>>, // reg_id -> endpoint
}

impl Default for Lwm2mGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl Lwm2mGateway {
    pub fn new() -> Self {
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
            reg_id_to_endpoint: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Handle `/rd?ep={endpoint}&lt={lifetime}&b={binding}` registration
    pub fn register(
        &self,
        endpoint: &str,
        lifetime_secs: u64,
        binding: &str,
        version: &str,
    ) -> String {
        let reg_id = format!("rd-{}", uuid::Uuid::new_v4().simple());
        let device = Lwm2mDevice {
            endpoint: endpoint.to_string(),
            registration_id: reg_id.clone(),
            lifetime: Duration::from_secs(lifetime_secs.max(60)),
            last_seen: Instant::now(),
            binding: binding.to_string(),
            version: version.to_string(),
        };

        self.devices.write().insert(endpoint.to_string(), device);
        self.reg_id_to_endpoint
            .write()
            .insert(reg_id.clone(), endpoint.to_string());
        reg_id
    }

    /// Handle registration update (heartbeat/keepalive)
    pub fn update_registration(&self, reg_id: &str) -> Result<(), Lwm2mError> {
        let ep = self
            .reg_id_to_endpoint
            .read()
            .get(reg_id)
            .cloned()
            .ok_or_else(|| Lwm2mError::DeviceNotFound(reg_id.to_string()))?;

        if let Some(dev) = self.devices.write().get_mut(&ep) {
            dev.last_seen = Instant::now();
            Ok(())
        } else {
            Err(Lwm2mError::DeviceNotFound(ep))
        }
    }

    /// Handle deregistration
    pub fn deregister(&self, reg_id: &str) -> bool {
        if let Some(ep) = self.reg_id_to_endpoint.write().remove(reg_id) {
            self.devices.write().remove(&ep);
            true
        } else {
            false
        }
    }

    /// Translate uplink TLV or JSON payload from LwM2M device to standard MQTT payload and topic:
    /// returns `(topic, json_payload_bytes)`
    pub fn process_uplink_tlv(
        &self,
        endpoint: &str,
        object_id: u16,
        instance_id: u16,
        tlv_bytes: &[u8],
    ) -> Result<(String, Bytes), Lwm2mError> {
        let records = TlvRecord::decode_all(tlv_bytes)?;
        let topic = format!("lwm2m/{endpoint}/up/data");

        let mut payload_map = serde_json::Map::new();
        payload_map.insert("endpoint".to_string(), serde_json::json!(endpoint));
        payload_map.insert("object_id".to_string(), serde_json::json!(object_id));
        payload_map.insert("instance_id".to_string(), serde_json::json!(instance_id));

        let mut resources_json = serde_json::Map::new();
        for r in records {
            let res_key = r.identifier.to_string();
            // Try parsing as float or int, else hex/bytes
            if r.value.len() == 4 {
                let f = f32::from_be_bytes(r.value.as_slice().try_into().unwrap_or_default());
                resources_json.insert(res_key, serde_json::json!(f));
            } else if r.value.len() == 8 {
                let f = f64::from_be_bytes(r.value.as_slice().try_into().unwrap_or_default());
                resources_json.insert(res_key, serde_json::json!(f));
            } else if let Ok(s) = std::str::from_utf8(&r.value) {
                resources_json.insert(res_key, serde_json::json!(s));
            } else {
                resources_json.insert(res_key, serde_json::json!(r.value));
            }
        }
        payload_map.insert(
            "resources".to_string(),
            serde_json::Value::Object(resources_json),
        );

        let json_str = serde_json::to_string(&payload_map)
            .map_err(|e| Lwm2mError::JsonError(e.to_string()))?;

        Ok((topic, Bytes::from(json_str)))
    }

    /// Translate uplink SenML/LwM2M JSON payload to standard MQTT payload and topic
    pub fn process_uplink_json(
        &self,
        endpoint: &str,
        json_bytes: &[u8],
    ) -> Result<(String, Bytes), Lwm2mError> {
        let records: Vec<SenMlRecord> =
            serde_json::from_slice(json_bytes).map_err(|e| Lwm2mError::JsonError(e.to_string()))?;

        let topic = format!("lwm2m/{endpoint}/up/data");
        let payload_json = serde_json::json!({
            "endpoint": endpoint,
            "records": records,
        });

        let json_str = serde_json::to_string(&payload_json)
            .map_err(|e| Lwm2mError::JsonError(e.to_string()))?;

        Ok((topic, Bytes::from(json_str)))
    }

    /// Build downlink command topic for an endpoint
    pub fn downlink_write_topic(endpoint: &str) -> String {
        format!("lwm2m/{endpoint}/dn/write")
    }

    /// Build downlink read topic for an endpoint
    pub fn downlink_read_topic(endpoint: &str) -> String {
        format!("lwm2m/{endpoint}/dn/read")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_encode_decode_roundtrip() {
        // Temperature sensor reading (Object 3303, Instance 0, Resource 5700 Sensor Value = 24.5f32)
        let temp_val = 24.5f32.to_be_bytes().to_vec();
        let child_res = TlvRecord::resource_value(5700, temp_val.clone());
        let parent_inst = TlvRecord::object_instance(0, vec![child_res]);

        let encoded = parent_inst.encode();
        let decoded = TlvRecord::decode_all(&encoded).expect("decode TLV");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].tlv_type, TlvType::ObjectInstance as u8);
        assert_eq!(decoded[0].identifier, 0);
        assert_eq!(decoded[0].children.len(), 1);

        let res = &decoded[0].children[0];
        assert_eq!(res.tlv_type, TlvType::ResourceWithValue as u8);
        assert_eq!(res.identifier, 5700);
        assert_eq!(res.value, temp_val);
    }

    #[test]
    fn test_lwm2m_registration_and_uplink() {
        let gw = Lwm2mGateway::new();

        // 1. Register device
        let reg_id = gw.register("sensor-node-42", 300, "U", "1.1");
        assert!(reg_id.starts_with("rd-"));

        // 2. Update heartbeat
        assert!(gw.update_registration(&reg_id).is_ok());

        // 3. Process uplink TLV
        let temp_bytes = 22.8f32.to_be_bytes().to_vec();
        let rec = TlvRecord::resource_value(5700, temp_bytes);
        let tlv_bytes = rec.encode();

        let (topic, payload) = gw
            .process_uplink_tlv("sensor-node-42", 3303, 0, &tlv_bytes)
            .expect("process TLV");

        assert_eq!(topic, "lwm2m/sensor-node-42/up/data");
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed["endpoint"], "sensor-node-42");
        assert_eq!(parsed["object_id"], 3303);
        assert_eq!(parsed["instance_id"], 0);
        assert!((parsed["resources"]["5700"].as_f64().unwrap() - 22.8).abs() < 1e-4);

        // 4. Deregister
        assert!(gw.deregister(&reg_id));
        assert!(gw.update_registration(&reg_id).is_err());
    }

    #[test]
    fn test_lwm2m_senml_json_uplink() {
        let gw = Lwm2mGateway::new();
        let senml = r#"[
            {"bn":"/3303/0/","n":"5700","v":25.4,"u":"Cel"},
            {"n":"5701","vs":"Celsius"}
        ]"#;

        let (topic, payload) = gw
            .process_uplink_json("device-99", senml.as_bytes())
            .expect("process json");

        assert_eq!(topic, "lwm2m/device-99/up/data");
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed["endpoint"], "device-99");
        assert_eq!(parsed["records"].as_array().unwrap().len(), 2);
    }
}
