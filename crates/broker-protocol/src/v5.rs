//! Minimal MQTT 5 topic-alias helpers (B4-05, T-92).
//!
//! This module covers topic aliases only, not full MQTT 5 support. It
//! provides the property identifiers, the reason code and the small
//! encode/decode helpers the kernel and the edge share:
//!
//! * property 34 (`Topic Alias Maximum`, `u16`) travels in CONNECT
//!   (client receive limit, bounding the kernel outbound table) and in
//!   CONNACK (kernel receive limit, bounding the kernel inbound table).
//! * property 35 (`Topic Alias`, `u16`) travels in PUBLISH. Alias 0 is
//!   never valid on the wire; aliases are 1..=negotiated-maximum.
//! * reason code `0x94` (148, "Topic Alias Invalid") rejects a publish
//!   that carries an alias above the negotiated maximum or an empty
//!   topic whose alias was never registered.
//!
//! The tables themselves live in the kernel session (`broker-session`):
//! the edge only frames bytes. Table ownership and the events that drive
//! each write are documented where the tables live.

use crate::ProtocolError;

/// Property identifier for `Topic Alias Maximum` (CONNECT/CONNACK).
pub const TOPIC_ALIAS_MAXIMUM_PROPERTY_ID: u8 = 34;

/// Property identifier for `Topic Alias` (PUBLISH).
pub const TOPIC_ALIAS_PROPERTY_ID: u8 = 35;

/// Reason code rejecting a publish with an unusable alias.
pub const REASON_TOPIC_ALIAS_INVALID: u8 = 0x94;

/// Largest alias value the wire format can carry (`u16`, minus 0).
pub const MAX_TOPIC_ALIAS: u16 = u16::MAX;

/// Alias value meaning "no alias carried" in kernel APIs.
pub const NO_TOPIC_ALIAS: u16 = 0;

/// Protocol-level default: no aliases until a maximum is negotiated.
/// The kernel applies its own configured default on top of this.
pub const DEFAULT_TOPIC_ALIAS_MAXIMUM: u16 = 0;

/// True when `alias` may be used under `max` (1..=max, max > 0).
#[must_use]
pub fn alias_in_range(alias: u16, max: u16) -> bool {
    alias != NO_TOPIC_ALIAS && max != 0 && alias <= max
}

/// Validate one inbound alias use. `Ok(())` means the alias may be
/// registered (topic present) or resolved (topic absent); `Err` carries
/// the reason code the publisher must receive. Alias 0 is never valid
/// on the wire (MQTT 5.0 §3.3.2.3.4: protocol error, DISCONNECT 0x94);
/// "no alias carried" is the absence of the property, never an explicit
/// 0, so this helper rejects 0 even though the kernel `alias_present`
/// fast path handles absence before calling it.
pub fn check_inbound_alias(alias: u16, max: u16) -> Result<(), ProtocolError> {
    if alias == NO_TOPIC_ALIAS {
        return Err(ProtocolError::InvalidTopic(
            "topic alias 0 is never valid".to_string(),
        ));
    }
    if max == 0 || alias > max {
        return Err(ProtocolError::InvalidTopic(format!(
            "topic alias {alias} above negotiated maximum {max}"
        )));
    }
    Ok(())
}

/// Encode a `Topic Alias Maximum` property value (`u16`, big-endian).
#[must_use]
pub fn encode_alias_maximum(max: u16) -> [u8; 2] {
    max.to_be_bytes()
}

/// Decode a `Topic Alias Maximum` property value. `None` on truncation.
#[must_use]
pub fn decode_alias_maximum(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Encode a `Topic Alias` property value (`u16`, big-endian).
#[must_use]
pub fn encode_topic_alias(alias: u16) -> [u8; 2] {
    alias.to_be_bytes()
}

/// Decode a `Topic Alias` property value. `None` on truncation.
#[must_use]
pub fn decode_topic_alias(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_range_rejects_zero_and_over_max() {
        assert!(!alias_in_range(0, 10));
        assert!(!alias_in_range(1, 0));
        assert!(!alias_in_range(11, 10));
        assert!(alias_in_range(1, 10));
        assert!(alias_in_range(10, 10));
    }

    #[test]
    fn alias_maximum_round_trips() {
        for max in [0u16, 1, 10, 65535] {
            assert_eq!(decode_alias_maximum(&encode_alias_maximum(max)), Some(max));
        }
        assert_eq!(decode_alias_maximum(&[0x00]), None);
    }

    #[test]
    fn topic_alias_round_trips() {
        for alias in [0u16, 1, 7, 65535] {
            assert_eq!(decode_topic_alias(&encode_topic_alias(alias)), Some(alias));
        }
        assert_eq!(decode_topic_alias(&[0x00]), None);
    }

    #[test]
    fn inbound_check_maps_over_max_to_error() {
        assert!(check_inbound_alias(0, 0).is_err());
        assert!(check_inbound_alias(0, 10).is_err());
        assert!(check_inbound_alias(1, 0).is_err());
        assert!(check_inbound_alias(11, 10).is_err());
        assert!(check_inbound_alias(10, 10).is_ok());
    }
}
