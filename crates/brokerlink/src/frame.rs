use bytes::{Bytes, BytesMut};
use crate::error::{BrokerLinkError, Result};
use crate::header::{FrameHeader, HEADER_LEN};
use crate::opcode::OpCode;

pub const DEFAULT_MAX_FRAME_SIZE: usize = 64 * 1024 * 1024; // 64 MB

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerFrame {
    pub header: FrameHeader,
    pub metadata: Bytes,
    pub payload: Bytes,
}

impl BrokerFrame {
    pub fn new(
        opcode: OpCode,
        conn_id: u64,
        sequence_no: u64,
        metadata: impl Into<Bytes>,
        payload: impl Into<Bytes>,
    ) -> Result<Self> {
        let meta_bytes = metadata.into();
        let payload_bytes = payload.into();

        if meta_bytes.len() > u16::MAX as usize {
            return Err(BrokerLinkError::FrameTooLarge(meta_bytes.len(), u16::MAX as usize));
        }
        if payload_bytes.len() > u32::MAX as usize {
            return Err(BrokerLinkError::FrameTooLarge(payload_bytes.len(), u32::MAX as usize));
        }

        let header = FrameHeader::new(
            opcode,
            conn_id,
            sequence_no,
            meta_bytes.len() as u16,
            payload_bytes.len() as u32,
        );

        Ok(Self {
            header,
            metadata: meta_bytes,
            payload: payload_bytes,
        })
    }

    pub fn ping(conn_id: u64, sequence_no: u64) -> Self {
        Self::new(OpCode::Ping, conn_id, sequence_no, Bytes::new(), Bytes::new())
            .expect("Ping frame within size bounds")
    }

    pub fn pong(conn_id: u64, sequence_no: u64) -> Self {
        Self::new(OpCode::Pong, conn_id, sequence_no, Bytes::new(), Bytes::new())
            .expect("Pong frame within size bounds")
    }

    pub fn total_frame_len(&self) -> usize {
        HEADER_LEN + self.metadata.len() + self.payload.len()
    }

    pub fn encode(&self, dst: &mut BytesMut) {
        dst.reserve(self.total_frame_len());
        self.header.encode(dst);
        dst.extend_from_slice(&self.metadata);
        dst.extend_from_slice(&self.payload);
    }
}
