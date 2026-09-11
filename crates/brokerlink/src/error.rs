use thiserror::Error;

#[derive(Error, Debug)]
pub enum BrokerLinkError {
    #[error("Invalid frame magic: expected [0x42, 0x4C], found [{0:#04x}, {1:#04x}]")]
    InvalidMagic(u8, u8),

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("Unknown opcode: {0:#06x}")]
    UnknownOpcode(u16),

    #[error("Frame too large: header claims {0} bytes, maximum allowed is {1}")]
    FrameTooLarge(usize, usize),

    #[error("Incomplete frame: expected {expected} bytes, but only {available} available")]
    IncompleteFrame { expected: usize, available: usize },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Transport error: {0}")]
    Transport(String),
}

pub type Result<T> = std::result::Result<T, BrokerLinkError>;
