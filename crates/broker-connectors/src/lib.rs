use async_trait::async_trait;
use bytes::Bytes;
use broker_protocol::{QoS, Topic};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConnectorError {
    #[error("Connector dispatch failure: {0}")]
    Dispatch(String),

    #[error("Connector connection error: {0}")]
    Connection(String),
}

pub type Result<T> = std::result::Result<T, ConnectorError>;

#[async_trait]
pub trait SinkConnector: Send + Sync {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()>;
}

#[async_trait]
pub trait SourceConnector: Send + Sync {
    async fn poll(&self) -> Result<Option<(Topic, Bytes)>>;
}
