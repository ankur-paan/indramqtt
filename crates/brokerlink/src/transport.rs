use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::codec::FrameCodec;
use crate::error::{BrokerLinkError, Result};
use crate::frame::BrokerFrame;

/// Max frames coalesced into one socket write (PERF-05).
///
/// Bounds the per-poll drain in the kernel outbound arm so one slow
/// connection cannot starve the task: 64 small `PublishOut` frames are
/// well under a millisecond of encoding.
pub const MAX_BATCH_FRAMES: usize = 64;
/// Max encoded bytes coalesced into one socket write (PERF-05).
pub const MAX_BATCH_BYTES: usize = 64 * 1024;

/// Send buffer size for BrokerLink sockets (PERF-08).
///
/// Matches the Erlang edge `{sndbuf, 65536}` from PERF-07: 64 KiB bounds
/// per-connection memory at scale while fitting the 64 KiB
/// `FramedTransport` write buffer above.
pub const BROKERLINK_SEND_BUF_BYTES: usize = 64 * 1024;
/// Receive buffer size for BrokerLink sockets (PERF-08).
///
/// Matches the Erlang edge `{recbuf, 65536}` from PERF-07.
pub const BROKERLINK_RECV_BUF_BYTES: usize = 64 * 1024;

/// Apply hot-path socket tuning to an accepted BrokerLink `TcpStream`
/// (PERF-08).
///
/// Enables `TCP_NODELAY` and sets 64 KiB send/recv buffers, matching the
/// Erlang edge options from PERF-07. Small BrokerLink frames would
/// otherwise risk a 40 ms delayed-ACK interaction, cross-host especially;
/// loopback RTT hides it, so expect no local latency change. Tuning
/// failures never fail the connection: each error is logged and tuning
/// continues with whatever the OS provided.
pub fn tune_brokerlink_tcp(stream: &tokio::net::TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::warn!("BrokerLink socket set_nodelay(true) failed: {}", e);
    }
    let sock = socket2::SockRef::from(stream);
    if let Err(e) = sock.set_send_buffer_size(BROKERLINK_SEND_BUF_BYTES) {
        tracing::warn!(
            "BrokerLink socket set_send_buffer_size({}) failed: {}",
            BROKERLINK_SEND_BUF_BYTES,
            e
        );
    }
    if let Err(e) = sock.set_recv_buffer_size(BROKERLINK_RECV_BUF_BYTES) {
        tracing::warn!(
            "BrokerLink socket set_recv_buffer_size({}) failed: {}",
            BROKERLINK_RECV_BUF_BYTES,
            e
        );
    }
}

#[async_trait]
pub trait BrokerLinkTransport: Send + Sync {
    async fn send(&self, frame: BrokerFrame) -> Result<()>;
    async fn recv(&self) -> Result<BrokerFrame>;
}

/// A framed streaming transport wrapping any bidirectional AsyncRead + AsyncWrite stream.
pub struct FramedTransport<S> {
    stream: Mutex<S>,
    codec: FrameCodec,
    read_buf: Mutex<BytesMut>,
    write_buf: Mutex<BytesMut>,
}

impl<S> FramedTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(stream: S) -> Self {
        Self::with_codec(stream, FrameCodec::default())
    }

    pub fn with_codec(stream: S, codec: FrameCodec) -> Self {
        Self {
            stream: Mutex::new(stream),
            codec,
            read_buf: Mutex::new(BytesMut::with_capacity(64 * 1024)),
            write_buf: Mutex::new(BytesMut::with_capacity(64 * 1024)),
        }
    }

    /// Encode `frames` in arrival order into one buffer and issue a
    /// single `write_all` + `flush` (PERF-05).
    ///
    /// Coalesces only what the caller already holds (typically the
    /// kernel outbound drain); no waiting, no reordering. Empty input
    /// is a no-op with no syscall. Single-frame batches behave exactly
    /// like [`BrokerLinkTransport::send`].
    pub async fn send_batch(&self, frames: &[BrokerFrame]) -> Result<()> {
        if frames.is_empty() {
            return Ok(());
        }
        let mut write_buf = self.write_buf.lock().await;
        write_buf.clear();
        for frame in frames {
            self.codec.encode(frame, &mut write_buf)?;
        }

        let mut stream = self.stream.lock().await;
        stream.write_all(&write_buf).await?;
        stream.flush().await?;
        Ok(())
    }
}

#[async_trait]
impl<S> BrokerLinkTransport for FramedTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async fn send(&self, frame: BrokerFrame) -> Result<()> {
        let mut write_buf = self.write_buf.lock().await;
        write_buf.clear();
        self.codec.encode(&frame, &mut write_buf)?;

        let mut stream = self.stream.lock().await;
        stream.write_all(&write_buf).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv(&self) -> Result<BrokerFrame> {
        let mut read_buf = self.read_buf.lock().await;

        loop {
            // Attempt to decode any already-buffered frame
            if let Some(frame) = self.codec.decode(&mut read_buf)? {
                return Ok(frame);
            }

            // Read more data from socket
            let mut stream = self.stream.lock().await;
            let bytes_read = stream.read_buf(&mut *read_buf).await?;
            if bytes_read == 0 {
                if read_buf.is_empty() {
                    return Err(BrokerLinkError::ConnectionClosed);
                } else {
                    return Err(BrokerLinkError::IncompleteFrame {
                        expected: 1,
                        available: read_buf.len(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::DuplexStream;

    /// Write side wrapper that counts `flush` calls so the batch test
    /// can tell one coalesced write apart from N per-frame flushes.
    struct FlushCountingStream {
        inner: DuplexStream,
        flushes: Arc<AtomicUsize>,
    }

    impl AsyncRead for FlushCountingStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for FlushCountingStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn test_send_batch_single_flush_in_order() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let flushes = Arc::new(AtomicUsize::new(0));
        let client = FramedTransport::new(FlushCountingStream {
            inner: client_io,
            flushes: flushes.clone(),
        });
        let server = FramedTransport::new(server_io);

        // Baseline: N individual sends cost N flushes.
        let baseline: Vec<BrokerFrame> = (0..4u64).map(|i| BrokerFrame::ping(i, i)).collect();
        for frame in &baseline {
            client.send(frame.clone()).await.unwrap();
        }
        assert_eq!(flushes.load(Ordering::SeqCst), 4);
        for expected in &baseline {
            assert_eq!(server.recv().await.unwrap(), *expected);
        }

        // Batched: N frames ride one flush, still in arrival order.
        flushes.store(0, Ordering::SeqCst);
        let batch: Vec<BrokerFrame> = (0..16u64).map(|i| BrokerFrame::ping(100 + i, i)).collect();
        client.send_batch(&batch).await.unwrap();
        assert_eq!(flushes.load(Ordering::SeqCst), 1);
        for expected in &batch {
            assert_eq!(server.recv().await.unwrap(), *expected);
        }

        // Empty batch is a no-op with no syscall.
        client.send_batch(&[]).await.unwrap();
        assert_eq!(flushes.load(Ordering::SeqCst), 1);
    }

    /// PERF-08: the post-accept tuning helper must leave `TCP_NODELAY`
    /// on and the 64 KiB send/recv buffers in place. Fails on the
    /// untuned socket (nodelay off by default), passes after tuning.
    #[tokio::test]
    async fn test_tune_brokerlink_tcp_enables_nodelay_and_buffers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect =
            tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
        let (accepted, _) = listener.accept().await.unwrap();
        let _client = connect.await.unwrap();

        assert!(
            !accepted.nodelay().unwrap(),
            "precondition: fresh socket has nodelay off"
        );

        super::tune_brokerlink_tcp(&accepted);

        assert!(
            accepted.nodelay().unwrap(),
            "TCP_NODELAY must be on after tuning"
        );
        let sock = socket2::SockRef::from(&accepted);
        // Linux doubles the requested SO_SNDBUF/SO_RCVBUF, Windows
        // reports the exact value, so `>=` holds on both.
        assert!(
            sock.send_buffer_size().unwrap() >= super::BROKERLINK_SEND_BUF_BYTES,
            "send buffer below requested {}",
            super::BROKERLINK_SEND_BUF_BYTES
        );
        assert!(
            sock.recv_buffer_size().unwrap() >= super::BROKERLINK_RECV_BUF_BYTES,
            "recv buffer below requested {}",
            super::BROKERLINK_RECV_BUF_BYTES
        );
    }
}
