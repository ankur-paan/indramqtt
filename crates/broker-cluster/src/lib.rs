pub mod license;
pub use license::{ClusterLicense, LicensePayload, LicenseStatus};

use async_trait::async_trait;
use bytes::Bytes;
use broker_protocol::{QoS, Topic, TopicFilter};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

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

impl NodeId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[async_trait]
pub trait ClusterMembership: Send + Sync {
    fn local_node_id(&self) -> &NodeId;
    async fn active_nodes(&self) -> Result<Vec<NodeId>>;
}

/// One message forwarded between cluster nodes. Live fan-out only:
/// retained state and rule execution stay at the ingress node.
#[derive(Debug, Clone)]
pub struct ClusterMessage {
    pub topic: Topic,
    pub payload: Bytes,
    pub qos: QoS,
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

    /// Receive the next message forwarded to this node (`None` when the
    /// plane is shut down).
    async fn recv_message(&self) -> Option<ClusterMessage>;
}

/// Cluster directory: `TopicFilter -> HashSet<NodeId>`.
///
/// Route summaries only — individual client subscriptions never cross
/// the cluster. The local node is always excluded from resolutions so a
/// node never forwards to itself.
#[derive(Debug, Default)]
struct RouteTrieNode {
    children: HashMap<String, RouteTrieNode>,
    single_wildcard: Option<Box<RouteTrieNode>>,
    multi_wildcard_nodes: HashSet<NodeId>,
    exact_nodes: HashSet<NodeId>,
}

#[derive(Debug)]
pub struct ClusterRouteTable {
    local: NodeId,
    root: RwLock<RouteTrieNode>,
}

impl ClusterRouteTable {
    pub fn new(local: NodeId) -> Self {
        Self {
            local,
            root: RwLock::new(RouteTrieNode::default()),
        }
    }

    pub fn local_node_id(&self) -> &NodeId {
        &self.local
    }

    pub fn add_route(&self, filter: &TopicFilter, node_id: NodeId) {
        let mut root = self.root.write();
        let levels: Vec<&str> = filter.as_str().split('/').collect();
        let mut curr = &mut *root;

        for (idx, &level) in levels.iter().enumerate() {
            if level == "#" {
                curr.multi_wildcard_nodes.insert(node_id);
                return;
            } else if level == "+" {
                if curr.single_wildcard.is_none() {
                    curr.single_wildcard = Some(Box::new(RouteTrieNode::default()));
                }
                curr = curr.single_wildcard.as_mut().unwrap();
            } else {
                curr = curr.children.entry(level.to_string()).or_default();
            }

            if idx == levels.len() - 1 {
                curr.exact_nodes.insert(node_id);
                return;
            }
        }
    }

    pub fn remove_route(&self, filter: &TopicFilter, node_id: &NodeId) {
        let mut root = self.root.write();
        let levels: Vec<&str> = filter.as_str().split('/').collect();
        let mut curr = &mut *root;

        for (idx, &level) in levels.iter().enumerate() {
            if level == "#" {
                curr.multi_wildcard_nodes.remove(node_id);
                return;
            } else if level == "+" {
                if let Some(ref mut child) = curr.single_wildcard {
                    curr = child;
                } else {
                    return;
                }
            } else if let Some(child) = curr.children.get_mut(level) {
                curr = child;
            } else {
                return;
            }

            if idx == levels.len() - 1 {
                curr.exact_nodes.remove(node_id);
                return;
            }
        }
    }

    /// Nodes (other than local) whose filters match `topic`: exactly one
    /// forward per node, no self-delivery.
    pub fn resolve_nodes(&self, topic: &Topic) -> HashSet<NodeId> {
        let root = self.root.read();
        let levels: Vec<&str> = topic.as_str().split('/').collect();
        let mut matched = HashSet::new();
        Self::match_recursive(&root, &levels, 0, &mut matched);
        matched.remove(&self.local);
        matched
    }

    fn match_recursive(
        node: &RouteTrieNode,
        levels: &[&str],
        depth: usize,
        matched: &mut HashSet<NodeId>,
    ) {
        matched.extend(node.multi_wildcard_nodes.iter().cloned());

        if depth >= levels.len() {
            matched.extend(node.exact_nodes.iter().cloned());
            return;
        }

        let segment = levels[depth];
        if let Some(child) = node.children.get(segment) {
            Self::match_recursive(child, levels, depth + 1, matched);
        }
        if let Some(ref child) = node.single_wildcard {
            Self::match_recursive(child, levels, depth + 1, matched);
        }
    }
}

/// Static membership for tests and fixed topologies.
#[derive(Debug)]
pub struct StaticMembership {
    local: NodeId,
    nodes: RwLock<Vec<NodeId>>,
}

impl StaticMembership {
    pub fn new(local: NodeId, nodes: Vec<NodeId>) -> Self {
        Self {
            local,
            nodes: RwLock::new(nodes),
        }
    }

    pub fn add_node(&self, node: NodeId) {
        let mut nodes = self.nodes.write();
        if !nodes.contains(&node) {
            nodes.push(node);
        }
    }

    pub fn remove_node(&self, node: &NodeId) {
        self.nodes.write().retain(|n| n != node);
    }
}

#[async_trait]
impl ClusterMembership for StaticMembership {
    fn local_node_id(&self) -> &NodeId {
        &self.local
    }

    async fn active_nodes(&self) -> Result<Vec<NodeId>> {
        Ok(self.nodes.read().clone())
    }
}

/// A cluster member: identity, route directory, and membership view.
pub struct ClusterNode {
    pub node_id: NodeId,
    pub route_table: Arc<ClusterRouteTable>,
    pub membership: Arc<dyn ClusterMembership>,
}

impl ClusterNode {
    pub fn new(node_id: NodeId, membership: Arc<dyn ClusterMembership>) -> Self {
        Self {
            route_table: Arc::new(ClusterRouteTable::new(node_id.clone())),
            node_id,
            membership,
        }
    }
}

/// In-process, network-pluggable [`RoutingPlane`] over `tokio` channels.
///
/// Each plane owns its route directory; [`ChannelRoutingPlane::link`]
/// meshes two planes by exchanging mailboxes and disseminating later
/// announcements to the peer (instant-gossip stand-in for tests and
/// single-process deployments; a network transport implements the same
/// trait for real clusters).
pub struct ChannelRoutingPlane {
    local: NodeId,
    table: Arc<ClusterRouteTable>,
    inbox_tx: mpsc::UnboundedSender<ClusterMessage>,
    inbox_rx: Mutex<mpsc::UnboundedReceiver<ClusterMessage>>,
    peers: RwLock<HashMap<NodeId, PeerLink>>,
}

struct PeerLink {
    tx: mpsc::UnboundedSender<ClusterMessage>,
    table: Arc<ClusterRouteTable>,
}

impl ChannelRoutingPlane {
    pub fn new(local: NodeId) -> Arc<Self> {
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            table: Arc::new(ClusterRouteTable::new(local.clone())),
            local,
            inbox_tx,
            inbox_rx: Mutex::new(inbox_rx),
            peers: RwLock::new(HashMap::new()),
        })
    }

    /// Bidirectionally mesh two planes: each learns the other's mailbox
    /// and directory for announcement dissemination.
    pub fn link(a: &Arc<Self>, b: &Arc<Self>) {
        a.peers.write().insert(
            b.local.clone(),
            PeerLink {
                tx: b.inbox_tx.clone(),
                table: b.table.clone(),
            },
        );
        b.peers.write().insert(
            a.local.clone(),
            PeerLink {
                tx: a.inbox_tx.clone(),
                table: a.table.clone(),
            },
        );
    }

    pub fn local_node_id(&self) -> &NodeId {
        &self.local
    }

    pub fn route_table(&self) -> &Arc<ClusterRouteTable> {
        &self.table
    }
}

#[async_trait]
impl RoutingPlane for ChannelRoutingPlane {
    async fn announce_filter(&self, filter: &TopicFilter) -> Result<()> {
        self.table.add_route(filter, self.local.clone());
        // Instant dissemination to meshed peers (stand-in for gossip).
        for peer in self.peers.read().values() {
            peer.table.add_route(filter, self.local.clone());
        }
        Ok(())
    }

    async fn revoke_filter(&self, filter: &TopicFilter) -> Result<()> {
        self.table.remove_route(filter, &self.local);
        for peer in self.peers.read().values() {
            peer.table.remove_route(filter, &self.local);
        }
        Ok(())
    }

    async fn resolve_route(&self, topic: &Topic) -> Result<HashSet<NodeId>> {
        Ok(self.table.resolve_nodes(topic))
    }

    async fn forward_message(
        &self,
        target: &NodeId,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
    ) -> Result<()> {
        let tx = self
            .peers
            .read()
            .get(target)
            .map(|peer| peer.tx.clone());
        match tx {
            Some(tx) => tx
                .send(ClusterMessage {
                    topic: topic.clone(),
                    payload: payload.clone(),
                    qos,
                })
                .map_err(|_| ClusterError::NodeUnreachable(target.to_string())),
            None => Err(ClusterError::NodeUnreachable(target.to_string())),
        }
    }

    async fn recv_message(&self) -> Option<ClusterMessage> {
        self.inbox_rx.lock().await.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(s: &str) -> TopicFilter {
        TopicFilter::new(s).unwrap()
    }

    fn topic(s: &str) -> Topic {
        Topic::new(s).unwrap()
    }

    fn node(s: &str) -> NodeId {
        NodeId::new(s)
    }

    #[test]
    fn test_route_table_wildcard_resolution() {
        let table = ClusterRouteTable::new(node("local"));
        table.add_route(&filter("sensors/+"), node("node-b"));
        table.add_route(&filter("#"), node("node-c"));
        table.add_route(&filter("sensors/temp"), node("local"));

        // Exact + single-wildcard + multi-wildcard converge; local excluded.
        let resolved = table.resolve_nodes(&topic("sensors/temp"));
        assert_eq!(resolved, HashSet::from([node("node-b"), node("node-c")]));

        // Only the multi-wildcard matches here.
        let resolved = table.resolve_nodes(&topic("other/x"));
        assert_eq!(resolved, HashSet::from([node("node-c")]));

        // Revoking drops the node from future resolutions.
        table.remove_route(&filter("#"), &node("node-c"));
        assert!(table.resolve_nodes(&topic("other/x")).is_empty());
        let resolved = table.resolve_nodes(&topic("sensors/temp"));
        assert_eq!(resolved, HashSet::from([node("node-b")]));

        // Revoking unknown entries is a no-op.
        table.remove_route(&filter("nope/#"), &node("node-zzz"));
        table.remove_route(&filter("sensors/+"), &node("node-zzz"));
        assert_eq!(table.resolve_nodes(&topic("sensors/temp")), HashSet::from([node("node-b")]));
    }

    #[tokio::test]
    async fn test_static_membership() {
        let membership = StaticMembership::new(node("n1"), vec![node("n1"), node("n2")]);
        assert_eq!(membership.local_node_id(), &node("n1"));
        membership.add_node(node("n3"));
        membership.add_node(node("n3"));
        membership.remove_node(&node("n2"));
        let nodes = membership.active_nodes().await.unwrap();
        assert_eq!(nodes, vec![node("n1"), node("n3")]);
    }

    #[tokio::test]
    async fn test_channel_plane_announce_resolve_forward() {
        let a = ChannelRoutingPlane::new(node("node-a"));
        let b = ChannelRoutingPlane::new(node("node-b"));
        ChannelRoutingPlane::link(&a, &b);

        // Node A announces; node B resolves A for a matching topic.
        a.announce_filter(&filter("sport/+")).await.unwrap();
        let targets = b.resolve_route(&topic("sport/tennis")).await.unwrap();
        assert_eq!(targets, HashSet::from([node("node-a")]));

        // Non-matching topics resolve to nobody.
        assert!(b
            .resolve_route(&topic("unrelated/foo"))
            .await
            .unwrap()
            .is_empty());

        // A single forward lands in A's inbox with payload intact.
        b.forward_message(
            &node("node-a"),
            &topic("sport/tennis"),
            &Bytes::from_static(b"match-point"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let msg = a.recv_message().await.expect("forwarded message");
        assert_eq!(msg.topic.as_str(), "sport/tennis");
        assert_eq!(msg.payload, Bytes::from_static(b"match-point"));

        // Unknown targets fail instead of dropping silently.
        let err = b
            .forward_message(
                &node("node-ghost"),
                &topic("sport/tennis"),
                &Bytes::from_static(b"x"),
                QoS::AtMostOnce,
            )
            .await
            .expect_err("unknown node must fail");
        assert!(matches!(err, ClusterError::NodeUnreachable(_)));

        // Revoking withdraws the route cluster-wide.
        a.revoke_filter(&filter("sport/+")).await.unwrap();
        assert!(b
            .resolve_route(&topic("sport/tennis"))
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_cluster_node_holds_directory_and_membership() {
        let membership: Arc<dyn ClusterMembership> = Arc::new(StaticMembership::new(
            node("n1"),
            vec![node("n1")],
        ));
        let member = ClusterNode::new(node("n1"), membership.clone());
        assert_eq!(member.node_id, node("n1"));
        assert_eq!(member.route_table.local_node_id(), &node("n1"));
        assert_eq!(member.membership.local_node_id(), &node("n1"));
    }
}
