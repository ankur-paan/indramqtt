use bytes::{Buf, BytesMut};
use crate::error::{BrokerLinkError, Result};
use crate::frame::{BrokerFrame, DEFAULT_MAX_FRAME_SIZE};
use crate::header::{FrameHeader, HEADER_LEN, MAGIC, PROTOCOL_VERSION_1};
use crate::opcode::OpCode;

#[derive(Debug, Clone)]
pub struct FrameCodec {
    max_frame_size: usize,
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_SIZE)
    }
}

impl FrameCodec {
    pub fn new(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }

    pub fn encode(&self, frame: &BrokerFrame, dst: &mut BytesMut) -> Result<()> {
        let total_len = frame.total_frame_len();
        if total_len > self.max_frame_size {
            return Err(BrokerLinkError::FrameTooLarge(total_len, self.max_frame_size));
        }
        frame.encode(dst);
        Ok(())
    }

    pub fn decode(&self, src: &mut BytesMut) -> Result<Option<BrokerFrame>> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        // Fast magic check without advancing the buffer
        let m0 = src[0];
        let m1 = src[1];
        if [m0, m1] != MAGIC {
            return Err(BrokerLinkError::InvalidMagic(m0, m1));
        }

        let version = src[2];
        if version != PROTOCOL_VERSION_1 {
            return Err(BrokerLinkError::UnsupportedVersion(version));
        }

        let flags = src[3];
        let opcode_raw = u16::from_be_bytes([src[4], src[5]]);
        let opcode = OpCode::try_from(opcode_raw)?;

        let conn_id = u64::from_be_bytes([
            src[6], src[7], src[8], src[9], src[10], src[11], src[12], src[13],
        ]);
        let sequence_no = u64::from_be_bytes([
            src[14], src[15], src[16], src[17], src[18], src[19], src[20], src[21],
        ]);
        let meta_len = u16::from_be_bytes([src[22], src[23]]) as usize;
        let payload_len = u32::from_be_bytes([src[24], src[25], src[26], src[27]]) as usize;

        let total_body_len = meta_len + payload_len;
        let total_frame_len = HEADER_LEN + total_body_len;

        if total_frame_len > self.max_frame_size {
            return Err(BrokerLinkError::FrameTooLarge(total_frame_len, self.max_frame_size));
        }

        if src.len() < total_frame_len {
            // Need more data from the network
            return Ok(None);
        }

        // Consume header
        src.advance(HEADER_LEN);

        // Zero-copy split for metadata and payload
        let metadata = src.split_to(meta_len).freeze();
        let payload = src.split_to(payload_len).freeze();

        let header = FrameHeader {
            version,
            flags,
            opcode,
            conn_id,
            sequence_no,
            meta_len: meta_len as u16,
            payload_len: payload_len as u32,
        };

        Ok(Some(BrokerFrame {
            header,
            metadata,
            payload,
        }))
    }
}
