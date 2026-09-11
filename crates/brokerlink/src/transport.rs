use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::codec::FrameCodec;
use crate::error::{BrokerLinkError, Result};
use crate::frame::BrokerFrame;

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
