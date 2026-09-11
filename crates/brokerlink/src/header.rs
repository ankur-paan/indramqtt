use bytes::{Buf, BufMut, BytesMut};
use crate::error::{BrokerLinkError, Result};
use crate::opcode::OpCode;

pub const MAGIC: [u8; 2] = [0x42, 0x4C]; // 'B', 'L'
pub const PROTOCOL_VERSION_1: u8 = 1;
pub const HEADER_LEN: usize = 28;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u8,
    pub flags: u8,
    pub opcode: OpCode,
    pub conn_id: u64,
    pub sequence_no: u64,
    pub meta_len: u16,
    pub payload_len: u32,
}

impl FrameHeader {
    pub fn new(opcode: OpCode, conn_id: u64, sequence_no: u64, meta_len: u16, payload_len: u32) -> Self {
        Self {
            version: PROTOCOL_VERSION_1,
            flags: 0,
            opcode,
            conn_id,
            sequence_no,
            meta_len,
            payload_len,
        }
    }

    pub fn total_body_len(&self) -> usize {
        (self.meta_len as usize) + (self.payload_len as usize)
    }

    pub fn encode(&self, dst: &mut BytesMut) {
        dst.put_slice(&MAGIC);
        dst.put_u8(self.version);
        dst.put_u8(self.flags);
        dst.put_u16(self.opcode.into());
        dst.put_u64(self.conn_id);
        dst.put_u64(self.sequence_no);
        dst.put_u16(self.meta_len);
        dst.put_u32(self.payload_len);
    }

    pub fn decode(src: &mut impl Buf) -> Result<Self> {
        if src.remaining() < HEADER_LEN {
            return Err(BrokerLinkError::IncompleteFrame {
                expected: HEADER_LEN,
                available: src.remaining(),
            });
        }

        let m0 = src.get_u8();
        let m1 = src.get_u8();
        if [m0, m1] != MAGIC {
            return Err(BrokerLinkError::InvalidMagic(m0, m1));
        }

        let version = src.get_u8();
        if version != PROTOCOL_VERSION_1 {
            return Err(BrokerLinkError::UnsupportedVersion(version));
        }

        let flags = src.get_u8();
        let opcode_raw = src.get_u16();
        let opcode = OpCode::try_from(opcode_raw)?;
        let conn_id = src.get_u64();
        let sequence_no = src.get_u64();
        let meta_len = src.get_u16();
        let payload_len = src.get_u32();

        Ok(Self {
            version,
            flags,
            opcode,
            conn_id,
            sequence_no,
            meta_len,
            payload_len,
        })
    }
}
