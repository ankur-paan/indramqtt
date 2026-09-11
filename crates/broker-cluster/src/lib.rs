use async_trait::async_trait;
use bytes::Bytes;
use broker_protocol::{QoS, Topic, TopicFilter};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClusterError {
    #[error("Node unreachable: {0}")]
    NodeUnreachable(String),

    #[error("Cluster communication failure: {0}")]
    Transport(String),
}

pub type Result<T> = std::result::Result<T, ClusterError>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(pub String);

#[async_trait]
pub trait ClusterMembership: Send + Sync {
    fn local_node_id(&self) -> &NodeId;
    async fn active_nodes(&self) -> Result<Vec<NodeId>>;
}

#[async_trait]
pub trait RoutingPlane: Send + Sync {
    /// Announce a new topic filter subscription from this node to the cluster
    async fn announce_filter(&self, filter: &TopicFilter) -> Result<()>;

    /// Revoke a topic filter subscription from this node
    async fn revoke_filter(&self, filter: &TopicFilter) -> Result<()>;

    /// Query which nodes have subscribers matching a concrete topic
    async fn resolve_route(&self, topic: &Topic) -> Result<HashSet<NodeId>>;

    /// Publish a message once to a target node
    async fn forward_message(&self, target: &NodeId, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()>;
}
