//! BrokerLink opcode registry.
//!
//! Contracts (mirrored in `broker-node/src/main.rs`):
//! * `ConnClose` carries empty metadata and an empty payload; `conn_id`
//!   in the header identifies the edge connection to close.
//! * The kernel sends it and expects no reply.
//! * An edge that receives it must close the socket (W0-25).
use crate::error::BrokerLinkError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum OpCode {
    Ping = 0x0001,
    Pong = 0x0002,

    // Connection Lifecycle
    BindConnection = 0x0010,
    SessionBinding = 0x0011,
    UnbindConnection = 0x0012,

    // Publish & Acks
    PublishIn = 0x0020,
    PublishOut = 0x0021,
    PubAckIn = 0x0022,
    PubAckOut = 0x0023,
    PubRecIn = 0x0024,
    PubRecOut = 0x0025,
    PubRelIn = 0x0026,
    PubRelOut = 0x0027,
    PubCompIn = 0x0028,
    PubCompOut = 0x0029,

    // Subscriptions
    SubscribeIn = 0x0030,
    SubAckOut = 0x0031,
    UnsubscribeIn = 0x0032,
    UnsubAckOut = 0x0033,

    // Disconnect
    DisconnectIn = 0x0040,
    ConnClose = 0x0041,
}

impl TryFrom<u16> for OpCode {
    type Error = BrokerLinkError;

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0001 => Ok(Self::Ping),
            0x0002 => Ok(Self::Pong),
            0x0010 => Ok(Self::BindConnection),
            0x0011 => Ok(Self::SessionBinding),
            0x0012 => Ok(Self::UnbindConnection),
            0x0020 => Ok(Self::PublishIn),
            0x0021 => Ok(Self::PublishOut),
            0x0022 => Ok(Self::PubAckIn),
            0x0023 => Ok(Self::PubAckOut),
            0x0024 => Ok(Self::PubRecIn),
            0x0025 => Ok(Self::PubRecOut),
            0x0026 => Ok(Self::PubRelIn),
            0x0027 => Ok(Self::PubRelOut),
            0x0028 => Ok(Self::PubCompIn),
            0x0029 => Ok(Self::PubCompOut),
            0x0030 => Ok(Self::SubscribeIn),
            0x0031 => Ok(Self::SubAckOut),
            0x0032 => Ok(Self::UnsubscribeIn),
            0x0033 => Ok(Self::UnsubAckOut),
            0x0040 => Ok(Self::DisconnectIn),
            0x0041 => Ok(Self::ConnClose),
            other => Err(BrokerLinkError::UnknownOpcode(other)),
        }
    }
}

impl From<OpCode> for u16 {
    fn from(op: OpCode) -> Self {
        op as u16
    }
}
