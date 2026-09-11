use broker_session::SessionManager;
use brokerlink::{BrokerFrame, BrokerLinkTransport, FramedTransport, OpCode};
use bytes::Bytes;
use clap::Parser;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(name = "indramqtt", version, about = "IndraMQTT Distributed Broker Kernel")]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:1883")]
    bind: String,

    /// BrokerLink IPC listen address for BEAM edge clients (TCP loopback).
    #[arg(long, default_value = "127.0.0.1:18883")]
    brokerlink_bind: String,
}

/// Map an inbound frame to its synchronous reply, if any.
///
/// Contracts (mirrored in `beam/src/indra_brokerlink.erl`):
/// * `Ping` is answered immediately with a `Pong` carrying the identical
///   `conn_id` and `sequence_no`.
/// * `BindConnection` metadata is `ClientIdLen:16be | ClientId (UTF-8)
///   | Flags:8 (bit 0 = clean_start) | Keepalive:16be`. The canonical
///   session is resolved via `SessionManager::get_or_create` and answered
///   with `SessionBinding` metadata `SessionId:64be | Present:8
///   | ReturnCode:8` (RC 0 = accepted, 2 = identifier rejected).
///   Replies always mirror the request `conn_id` and `sequence_no`.
/// * All other opcodes have no synchronous reply yet and return `None`.
fn reply_for_frame(frame: &BrokerFrame, sessions: &SessionManager) -> Option<BrokerFrame> {
    match frame.header.opcode {
        OpCode::Ping => Some(BrokerFrame::pong(
            frame.header.conn_id,
            frame.header.sequence_no,
        )),
        OpCode::BindConnection => Some(bind_connection_reply(frame, sessions)),
        _ => None,
    }
}

/// Resolve one `BindConnection` frame into its `SessionBinding` reply.
///
/// Every `BindConnection` yields exactly one reply so the BEAM edge never
/// hangs waiting for CONNACK parameters: malformed metadata (or a
/// non-UTF-8 client id) is answered with return code 2, mirroring the
/// MQTT 3.1.1 CONNACK "identifier rejected" code.
fn bind_connection_reply(frame: &BrokerFrame, sessions: &SessionManager) -> BrokerFrame {
    let (session_id, present, return_code) = match decode_bind_meta(&frame.metadata) {
        Ok((client_id, clean_start)) => {
            let (session, present) = sessions.get_or_create(&client_id, clean_start);
            (session.id.0, present, 0u8)
        }
        Err(_) => (0u64, false, 2u8),
    };

    let mut meta = Vec::with_capacity(10);
    meta.extend_from_slice(&session_id.to_be_bytes());
    meta.push(u8::from(present));
    meta.push(return_code);

    BrokerFrame::new(
        OpCode::SessionBinding,
        frame.header.conn_id,
        frame.header.sequence_no,
        Bytes::from(meta),
        Bytes::new(),
    )
    .expect("SessionBinding reply within size bounds")
}

/// Decode `BindConnection` metadata into `(client_id, clean_start)`.
///
/// Layout: `ClientIdLen:16be | ClientId | Flags:8 | Keepalive:16be`.
/// The keepalive is framing-validated here; supervision lives on the edge.
fn decode_bind_meta(meta: &[u8]) -> Result<(String, bool), &'static str> {
    if meta.len() < 5 {
        return Err("bind meta too short");
    }
    let id_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    if meta.len() != 2 + id_len + 1 + 2 {
        return Err("bind meta length mismatch");
    }
    let id_bytes = &meta[2..2 + id_len];
    let flags = meta[2 + id_len];
    let client_id = std::str::from_utf8(id_bytes).map_err(|_| "client id not UTF-8")?;
    Ok((client_id.to_string(), flags & 0x01 != 0))
}

async fn handle_connection(
    stream: TcpStream,
    sessions: Arc<SessionManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    debug!("BrokerLink IPC connection from {}", peer);

    let transport = FramedTransport::new(stream);
    loop {
        let frame = match transport.recv().await {
            Ok(frame) => frame,
            Err(brokerlink::BrokerLinkError::ConnectionClosed) => {
                debug!("BrokerLink IPC peer {} closed", peer);
                return Ok(());
            }
            Err(e) => {
                warn!("BrokerLink IPC error from {}: {}", peer, e);
                return Err(Box::new(e));
            }
        };

        debug!(
            "BrokerLink recv opcode={:?} conn_id={} seq={}",
            frame.header.opcode, frame.header.conn_id, frame.header.sequence_no
        );

        if let Some(reply) = reply_for_frame(&frame, &sessions) {
            transport.send(reply).await?;
        }
    }
}

async fn serve_brokerlink(bind: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(bind).await?;
    info!("BrokerLink IPC listening on {}", bind);
    let sessions = Arc::new(SessionManager::new());

    loop {
        let (stream, addr) = listener.accept().await?;
        debug!("BrokerLink IPC accepted {}", addr);
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, sessions).await {
                warn!("BrokerLink connection {} ended with error: {}", addr, e);
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    broker_observability::init_tracing();
    let args = Args::parse();

    info!(
        "Starting IndraMQTT Kernel v{} on {}",
        env!("CARGO_PKG_VERSION"),
        args.bind
    );
    info!("BrokerLink IPC protocol initialized");
    info!("Clean-room architecture ready");

    serve_brokerlink(&args.brokerlink_bind).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode `BindConnection` metadata (test mirror of the BEAM
    /// `indra_brokerlink:encode_bind_meta/3` contract).
    fn encode_bind_meta(client_id: &str, clean_start: bool, keepalive: u16) -> Bytes {
        let id = client_id.as_bytes();
        let mut meta = Vec::with_capacity(2 + id.len() + 1 + 2);
        meta.extend_from_slice(&(id.len() as u16).to_be_bytes());
        meta.extend_from_slice(id);
        meta.push(u8::from(clean_start));
        meta.extend_from_slice(&keepalive.to_be_bytes());
        Bytes::from(meta)
    }

    /// Decode `SessionBinding` metadata into `(session_id, present, rc)`.
    fn decode_session_binding_meta(meta: &[u8]) -> (u64, bool, u8) {
        assert_eq!(meta.len(), 10, "SessionBinding meta must be 10 bytes");
        let session_id = u64::from_be_bytes(meta[0..8].try_into().unwrap());
        (session_id, meta[8] != 0, meta[9])
    }

    fn bind_frame(conn_id: u64, seq: u64, meta: Bytes) -> BrokerFrame {
        BrokerFrame::new(OpCode::BindConnection, conn_id, seq, meta, Bytes::new())
            .expect("valid bind frame")
    }

    #[test]
    fn ping_maps_to_matching_pong() {
        let sessions = SessionManager::new();
        let ping = BrokerFrame::ping(1234, 56);
        let reply = reply_for_frame(&ping, &sessions).expect("Ping must produce a reply");
        assert_eq!(reply.header.opcode, OpCode::Pong);
        assert_eq!(reply.header.conn_id, 1234);
        assert_eq!(reply.header.sequence_no, 56);
        assert!(reply.metadata.is_empty());
        assert!(reply.payload.is_empty());
    }

    #[test]
    fn ping_pong_preserves_max_ids() {
        let sessions = SessionManager::new();
        let ping = BrokerFrame::ping(u64::MAX, u64::MAX);
        let reply = reply_for_frame(&ping, &sessions).expect("Ping must produce a reply");
        assert_eq!(reply.header.conn_id, u64::MAX);
        assert_eq!(reply.header.sequence_no, u64::MAX);
    }

    #[test]
    fn non_handshake_frames_have_no_reply() {
        let sessions = SessionManager::new();
        for opcode in [
            OpCode::Pong,
            OpCode::SessionBinding,
            OpCode::UnbindConnection,
            OpCode::PublishIn,
            OpCode::PublishOut,
            OpCode::SubscribeIn,
            OpCode::DisconnectIn,
        ] {
            let frame = BrokerFrame::new(
                opcode,
                7,
                9,
                Bytes::from_static(b"meta"),
                Bytes::from_static(b"payload"),
            )
            .expect("valid frame");
            assert!(
                reply_for_frame(&frame, &sessions).is_none(),
                "opcode {:?} must not produce a sync reply",
                opcode
            );
        }
    }

    #[test]
    fn bind_connection_creates_session_without_present_flag() {
        let sessions = SessionManager::new();
        let frame = bind_frame(11, 1, encode_bind_meta("device-001", true, 60));

        let reply = reply_for_frame(&frame, &sessions).expect("Bind must produce a reply");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        assert_eq!(reply.header.conn_id, 11);
        assert_eq!(reply.header.sequence_no, 1);

        let (session_id, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_ne!(session_id, 0, "fresh session must have a nonzero id");
        assert!(!present, "first clean-start bind must report session_present=false");
        assert_eq!(rc, 0, "accepted bind must carry return code 0");
    }

    #[test]
    fn bind_connection_resumes_session_with_present_flag() {
        let sessions = SessionManager::new();
        let first = bind_frame(11, 1, encode_bind_meta("device-007", true, 60));
        let first_reply = reply_for_frame(&first, &sessions).expect("first bind replies");
        let (first_id, first_present, _) = decode_session_binding_meta(&first_reply.metadata);
        assert!(!first_present);

        let second = bind_frame(12, 1, encode_bind_meta("device-007", false, 60));
        let second_reply = reply_for_frame(&second, &sessions).expect("second bind replies");
        assert_eq!(second_reply.header.conn_id, 12, "reply mirrors requesting conn");
        let (second_id, second_present, rc) = decode_session_binding_meta(&second_reply.metadata);
        assert!(second_present, "resumed session must report session_present=true");
        assert_eq!(second_id, first_id, "resumed bind must reuse the session id");
        assert_eq!(rc, 0);
    }

    #[test]
    fn bind_connection_clean_start_replaces_session() {
        let sessions = SessionManager::new();
        let first = bind_frame(11, 1, encode_bind_meta("device-009", true, 60));
        let (first_id, _, _) =
            decode_session_binding_meta(&reply_for_frame(&first, &sessions).unwrap().metadata);

        let second = bind_frame(11, 2, encode_bind_meta("device-009", true, 60));
        let reply = reply_for_frame(&second, &sessions).expect("rebind replies");
        let (second_id, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_ne!(second_id, first_id, "clean start must mint a fresh session id");
        assert!(!present);
        assert_eq!(rc, 0);
    }

    #[test]
    fn bind_connection_rejects_garbage_meta_with_rc2() {
        let sessions = SessionManager::new();
        // Truncated meta: claims 5 id bytes but carries none of the tail.
        let bad = bind_frame(11, 3, Bytes::from(vec![0x00, 0x05, b'a', b'b']));
        let reply = reply_for_frame(&bad, &sessions).expect("malformed bind still replies");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        assert_eq!(reply.header.conn_id, 11);
        assert_eq!(reply.header.sequence_no, 3);
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert!(!present);
        assert_eq!(rc, 2, "malformed bind must carry return code 2");
    }

    #[test]
    fn bind_connection_rejects_non_utf8_client_id_with_rc2() {
        let sessions = SessionManager::new();
        // id_len=2, bytes 0xFF 0xFE are not valid UTF-8.
        let bad = bind_frame(
            11,
            4,
            Bytes::from(vec![0x00, 0x02, 0xFF, 0xFE, 0x01, 0x00, 0x3C]),
        );
        let reply = reply_for_frame(&bad, &sessions).expect("non-UTF8 bind still replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 2, "non-UTF8 client id must carry return code 2");
    }

    #[tokio::test]
    async fn ping_pong_round_trip_over_transport() {
        let sessions = SessionManager::new();
        let (client_io, server_io) = tokio::io::duplex(1024);
        let client = FramedTransport::new(client_io);
        let server = FramedTransport::new(server_io);

        let ping = BrokerFrame::ping(4242, 7);
        client.send(ping).await.expect("client send");

        let received = server.recv().await.expect("server recv");
        assert_eq!(received.header.opcode, OpCode::Ping);

        let reply = reply_for_frame(&received, &sessions).expect("server reply");
        server.send(reply).await.expect("server send");

        let pong = client.recv().await.expect("client recv");
        assert_eq!(pong.header.opcode, OpCode::Pong);
        assert_eq!(pong.header.conn_id, 4242);
        assert_eq!(pong.header.sequence_no, 7);
    }

    #[tokio::test]
    async fn server_replies_pong_to_ping_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_connection(stream, Arc::new(SessionManager::new()))
                .await
                .expect("handle");
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect");
        let client = FramedTransport::new(stream);
        client
            .send(BrokerFrame::ping(99, 100))
            .await
            .expect("send ping");
        let pong = client.recv().await.expect("recv pong");
        assert_eq!(pong.header.opcode, OpCode::Pong);
        assert_eq!(pong.header.conn_id, 99);
        assert_eq!(pong.header.sequence_no, 100);

        server_task.abort();
    }

    #[tokio::test]
    async fn server_binds_session_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_connection(stream, Arc::new(SessionManager::new()))
                .await
                .expect("handle");
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect");
        let client = FramedTransport::new(stream);
        client
            .send(bind_frame(55, 9, encode_bind_meta("e2e-device", true, 30)))
            .await
            .expect("send bind");
        let reply = client.recv().await.expect("recv binding");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        assert_eq!(reply.header.conn_id, 55);
        assert_eq!(reply.header.sequence_no, 9);
        let (session_id, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_ne!(session_id, 0);
        assert!(!present);
        assert_eq!(rc, 0);

        server_task.abort();
    }
}
