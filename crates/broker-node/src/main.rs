use brokerlink::{BrokerFrame, BrokerLinkTransport, FramedTransport, OpCode};
use clap::Parser;
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
/// Sprint 1 contract: `Ping` is answered immediately with a `Pong`
/// carrying the identical `conn_id` and `sequence_no`. All other
/// opcodes have no synchronous reply yet and return `None`.
fn reply_for_frame(frame: &BrokerFrame) -> Option<BrokerFrame> {
    match frame.header.opcode {
        OpCode::Ping => Some(BrokerFrame::pong(
            frame.header.conn_id,
            frame.header.sequence_no,
        )),
        _ => None,
    }
}

async fn handle_connection(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
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

        if let Some(reply) = reply_for_frame(&frame) {
            transport.send(reply).await?;
        }
    }
}

async fn serve_brokerlink(bind: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(bind).await?;
    info!("BrokerLink IPC listening on {}", bind);

    loop {
        let (stream, addr) = listener.accept().await?;
        debug!("BrokerLink IPC accepted {}", addr);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
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
    use bytes::Bytes;

    #[test]
    fn ping_maps_to_matching_pong() {
        let ping = BrokerFrame::ping(1234, 56);
        let reply = reply_for_frame(&ping).expect("Ping must produce a reply");
        assert_eq!(reply.header.opcode, OpCode::Pong);
        assert_eq!(reply.header.conn_id, 1234);
        assert_eq!(reply.header.sequence_no, 56);
        assert!(reply.metadata.is_empty());
        assert!(reply.payload.is_empty());
    }

    #[test]
    fn ping_pong_preserves_max_ids() {
        let ping = BrokerFrame::ping(u64::MAX, u64::MAX);
        let reply = reply_for_frame(&ping).expect("Ping must produce a reply");
        assert_eq!(reply.header.conn_id, u64::MAX);
        assert_eq!(reply.header.sequence_no, u64::MAX);
    }

    #[test]
    fn non_ping_frames_have_no_reply() {
        for opcode in [
            OpCode::Pong,
            OpCode::BindConnection,
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
                reply_for_frame(&frame).is_none(),
                "opcode {:?} must not produce a sync reply",
                opcode
            );
        }
    }

    #[tokio::test]
    async fn ping_pong_round_trip_over_transport() {
        let (client_io, server_io) = tokio::io::duplex(1024);
        let client = FramedTransport::new(client_io);
        let server = FramedTransport::new(server_io);

        let ping = BrokerFrame::ping(4242, 7);
        client.send(ping).await.expect("client send");

        let received = server.recv().await.expect("server recv");
        assert_eq!(received.header.opcode, OpCode::Ping);

        let reply = reply_for_frame(&received).expect("server reply");
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
            handle_connection(stream).await.expect("handle");
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
}
