pub mod codec;
pub mod error;
pub mod frame;
pub mod header;
pub mod lane;
pub mod opcode;
pub mod transport;

pub use codec::FrameCodec;
pub use error::{BrokerLinkError, Result};
pub use frame::BrokerFrame;
pub use header::{FrameHeader, HEADER_LEN, MAGIC, PROTOCOL_VERSION_1};
pub use lane::LaneDispatcher;
pub use opcode::OpCode;
pub use transport::{BrokerLinkTransport, FramedTransport};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Bytes, BytesMut};
    use std::sync::Arc;
    use tokio::io::duplex;

    #[test]
    fn test_header_round_trip() {
        let header = FrameHeader::new(OpCode::PublishIn, 12345, 67890, 42, 1024);
        let mut buf = BytesMut::new();
        header.encode(&mut buf);

        assert_eq!(buf.len(), HEADER_LEN);
        assert_eq!(HEADER_LEN, 28);

        let decoded = FrameHeader::decode(&mut buf).expect("Failed to decode header");
        assert_eq!(decoded, header);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_frame_codec_round_trip() {
        let codec = FrameCodec::default();
        let metadata = Bytes::from_static(b"test-metadata-proto");
        let payload = Bytes::from_static(b"{\"temperature\": 23.4, \"humidity\": 60.1}");

        let frame = BrokerFrame::new(
            OpCode::PublishIn,
            987654321,
            1,
            metadata.clone(),
            payload.clone(),
        )
        .expect("Valid frame creation");

        let mut buf = BytesMut::new();
        codec.encode(&frame, &mut buf).expect("Encoding failed");

        let decoded = codec
            .decode(&mut buf)
            .expect("Decoding failed")
            .expect("Frame should be complete");

        assert_eq!(decoded.header.opcode, OpCode::PublishIn);
        assert_eq!(decoded.header.conn_id, 987654321);
        assert_eq!(decoded.header.sequence_no, 1);
        assert_eq!(decoded.metadata, metadata);
        assert_eq!(decoded.payload, payload);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let codec = FrameCodec::default();
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x01, 0x00][..]);
        // Pad to header length
        buf.resize(HEADER_LEN, 0);

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(BrokerLinkError::InvalidMagic(0x00, 0x00))));
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let codec = FrameCodec::default();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&[99, 0]); // Version 99
        buf.resize(HEADER_LEN, 0);

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(BrokerLinkError::UnsupportedVersion(99))));
    }

    #[test]
    fn test_unknown_opcode_rejected() {
        let codec = FrameCodec::default();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&[PROTOCOL_VERSION_1, 0]);
        buf.extend_from_slice(&0xFFFFu16.to_be_bytes()); // Invalid OpCode
        buf.resize(HEADER_LEN, 0);

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(BrokerLinkError::UnknownOpcode(0xFFFF))));
    }

    #[test]
    fn test_frame_too_large_rejected() {
        let codec = FrameCodec::new(100); // 100 bytes max
        let large_payload = Bytes::from(vec![0u8; 150]);
        let frame = BrokerFrame::new(OpCode::PublishIn, 1, 1, Bytes::new(), large_payload)
            .expect("Frame created");

        let mut buf = BytesMut::new();
        let result = codec.encode(&frame, &mut buf);
        assert!(matches!(result, Err(BrokerLinkError::FrameTooLarge(..))));
    }

    #[test]
    fn test_incremental_streaming_decode() {
        let codec = FrameCodec::default();
        let frame = BrokerFrame::new(
            OpCode::PublishOut,
            42,
            100,
            Bytes::from_static(b"meta"),
            Bytes::from_static(b"payload-data-stream"),
        )
        .unwrap();

        let mut encoded = BytesMut::new();
        codec.encode(&frame, &mut encoded).unwrap();
        let total_bytes = encoded.len();

        let mut partial = BytesMut::new();
        // Feed byte-by-byte or small chunks
        for i in 0..total_bytes - 1 {
            partial.extend_from_slice(&encoded[i..i + 1]);
            let res = codec.decode(&mut partial).unwrap();
            assert!(res.is_none(), "Should not decode until all bytes arrive");
        }

        // Feed the final byte
        partial.extend_from_slice(&encoded[total_bytes - 1..total_bytes]);
        let res = codec.decode(&mut partial).unwrap();
        assert!(res.is_some(), "Should successfully decode once final byte arrives");
        assert_eq!(res.unwrap(), frame);
        assert!(partial.is_empty());
    }

    #[tokio::test]
    async fn test_transport_bidirectional_duplex() {
        let (client_io, server_io) = duplex(1024);
        let client_transport = FramedTransport::new(client_io);
        let server_transport = FramedTransport::new(server_io);

        let send_frame = BrokerFrame::ping(1001, 1);
        let expected_frame = send_frame.clone();

        tokio::spawn(async move {
            client_transport.send(send_frame).await.unwrap();
        });

        let received = server_transport.recv().await.unwrap();
        assert_eq!(received, expected_frame);
    }

    #[tokio::test]
    async fn test_lane_dispatcher_affinity() {
        let mut lanes: Vec<Arc<dyn BrokerLinkTransport>> = Vec::new();
        for _ in 0..8 {
            let (io1, _io2) = duplex(1024);
            lanes.push(Arc::new(FramedTransport::new(io1)));
        }

        let dispatcher = LaneDispatcher::new(lanes);
        assert_eq!(dispatcher.lane_count(), 8);

        // Same connection id MUST always hit the exact same lane
        let conn_id = 999999;
        let expected_lane = (conn_id as usize) % 8;
        assert_eq!(dispatcher.lane_for_conn(conn_id), expected_lane);

        for _ in 0..100 {
            assert_eq!(dispatcher.lane_for_conn(conn_id), expected_lane);
        }
    }
}
