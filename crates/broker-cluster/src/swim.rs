use crate::{
    license::{ClusterLicense, LicenseStatus},
    ClusterError, ClusterMembership, ClusterRouteTable, NodeId,
};
use async_trait::async_trait;
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Notify};
use tracing::{debug, info, warn};

/// Node operational status in the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    Alive,
    Suspect,
    Dead,
    Left,
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeStatus::Alive => write!(f, "Alive"),
            NodeStatus::Suspect => write!(f, "Suspect"),
            NodeStatus::Dead => write!(f, "Dead"),
            NodeStatus::Left => write!(f, "Left"),
        }
    }
}

/// Metadata and state for a single cluster member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberState {
    pub node_id: NodeId,
    pub status: NodeStatus,
    pub incarnation: u64,
    pub address: Option<String>,
    pub last_updated_epoch: u64,
}

/// A gossip item disseminated across the cluster mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipItem {
    MemberUpdate {
        node_id: NodeId,
        status: NodeStatus,
        incarnation: u64,
        address: Option<String>,
    },
    RouteUpdate {
        node_id: NodeId,
        filter: String,
        is_add: bool,
    },
}

/// Protocol messages exchanged between SWIM cluster peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwimMessage {
    Ping {
        seq: u64,
        from: NodeId,
        gossip: Vec<GossipItem>,
    },
    Ack {
        seq: u64,
        from: NodeId,
        gossip: Vec<GossipItem>,
    },
    PingReq {
        seq: u64,
        from: NodeId,
        target: NodeId,
        gossip: Vec<GossipItem>,
    },
    Join {
        from: NodeId,
        address: Option<String>,
        gossip: Vec<GossipItem>,
    },
    JoinAck {
        from: NodeId,
        members: Vec<MemberState>,
        gossip: Vec<GossipItem>,
    },
    Leave {
        from: NodeId,
        incarnation: u64,
    },
}

/// Configuration parameters for the SWIM failure detector and gossip protocol.
#[derive(Debug, Clone)]
pub struct SwimConfig {
    pub probe_interval: Duration,
    pub probe_timeout: Duration,
    pub ping_req_timeout: Duration,
    pub ping_req_members: usize,
    pub suspicion_timeout: Duration,
    pub gossip_fanout: usize,
    pub max_gossip_transmissions: usize,
}

impl Default for SwimConfig {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_millis(200),
            probe_timeout: Duration::from_millis(80),
            ping_req_timeout: Duration::from_millis(150),
            ping_req_members: 3,
            suspicion_timeout: Duration::from_millis(500),
            gossip_fanout: 8,
            max_gossip_transmissions: 3,
        }
    }
}

/// Transport abstraction for transmitting SWIM messages.
#[async_trait]
pub trait SwimTransport: Send + Sync {
    async fn send_to(&self, target: &NodeId, msg: &SwimMessage) -> Result<(), ClusterError>;
    async fn recv(&self) -> Option<(NodeId, SwimMessage)>;
}

type ChannelNodeMap = HashMap<NodeId, mpsc::UnboundedSender<(NodeId, SwimMessage)>>;

/// In-process shared network for testing multi-node clusters with zero OS sockets.
#[derive(Clone, Default)]
pub struct ChannelSwimNetwork {
    nodes: Arc<RwLock<ChannelNodeMap>>,
}

impl ChannelSwimNetwork {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register(&self, node_id: NodeId) -> Arc<ChannelSwimTransport> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.nodes.write().insert(node_id.clone(), tx);
        Arc::new(ChannelSwimTransport {
            local: node_id,
            network: self.clone(),
            inbox_rx: Mutex::new(rx),
        })
    }

    pub fn unregister(&self, node_id: &NodeId) {
        self.nodes.write().remove(node_id);
    }
}

pub struct ChannelSwimTransport {
    local: NodeId,
    network: ChannelSwimNetwork,
    inbox_rx: Mutex<mpsc::UnboundedReceiver<(NodeId, SwimMessage)>>,
}

#[async_trait]
impl SwimTransport for ChannelSwimTransport {
    async fn send_to(&self, target: &NodeId, msg: &SwimMessage) -> Result<(), ClusterError> {
        let tx = {
            let nodes = self.network.nodes.read();
            nodes.get(target).cloned()
        };
        match tx {
            Some(sender) => sender
                .send((self.local.clone(), msg.clone()))
                .map_err(|_| ClusterError::NodeUnreachable(target.to_string())),
            None => Err(ClusterError::NodeUnreachable(target.to_string())),
        }
    }

    async fn recv(&self) -> Option<(NodeId, SwimMessage)> {
        self.inbox_rx.lock().await.recv().await
    }
}

/// Production UDP transport for cluster communication over real network interfaces.
pub struct UdpSwimTransport {
    local: NodeId,
    socket: Arc<UdpSocket>,
    address_book: Arc<RwLock<HashMap<NodeId, SocketAddr>>>,
    reverse_map: Arc<RwLock<HashMap<SocketAddr, NodeId>>>,
}

impl UdpSwimTransport {
    pub async fn bind(local: NodeId, bind_addr: SocketAddr) -> std::io::Result<Arc<Self>> {
        let socket = UdpSocket::bind(bind_addr).await?;
        Ok(Arc::new(Self {
            local,
            socket: Arc::new(socket),
            address_book: Arc::new(RwLock::new(HashMap::new())),
            reverse_map: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    pub fn register_peer(&self, node: NodeId, addr: SocketAddr) {
        self.address_book.write().insert(node.clone(), addr);
        self.reverse_map.write().insert(addr, node);
    }

    pub fn local_node_id(&self) -> &NodeId {
        &self.local
    }
}

#[async_trait]
impl SwimTransport for UdpSwimTransport {
    async fn send_to(&self, target: &NodeId, msg: &SwimMessage) -> Result<(), ClusterError> {
        let addr = {
            let book = self.address_book.read();
            book.get(target).copied()
        };
        let addr = addr.ok_or_else(|| ClusterError::NodeUnreachable(target.to_string()))?;

        let bytes = serde_json::to_vec(msg)
            .map_err(|e| ClusterError::Transport(format!("serialization error: {}", e)))?;
        self.socket
            .send_to(&bytes, addr)
            .await
            .map_err(|e| ClusterError::Transport(format!("udp send error: {}", e)))?;
        Ok(())
    }

    async fn recv(&self) -> Option<(NodeId, SwimMessage)> {
        let mut buf = [0u8; 65507];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    if let Ok(msg) = serde_json::from_slice::<SwimMessage>(&buf[..len]) {
                        let from = {
                            let map = self.reverse_map.read();
                            map.get(&peer_addr).cloned()
                        };
                        let from_node = from.unwrap_or_else(|| match &msg {
                            SwimMessage::Ping { from, .. } => from.clone(),
                            SwimMessage::Ack { from, .. } => from.clone(),
                            SwimMessage::PingReq { from, .. } => from.clone(),
                            SwimMessage::Join { from, .. } => from.clone(),
                            SwimMessage::JoinAck { from, .. } => from.clone(),
                            SwimMessage::Leave { from, .. } => from.clone(),
                        });
                        return Some((from_node, msg));
                    }
                }
                Err(e) => {
                    warn!("UDP receive error: {}", e);
                    return None;
                }
            }
        }
    }
}

struct InternalMemberRecord {
    state: MemberState,
    suspect_since: Option<Instant>,
}

struct GossipRecord {
    item: GossipItem,
    transmissions_left: usize,
}

/// Decentralized SWIM cluster node with failure detector and gossip dissemination.
pub struct SwimMembership {
    local: NodeId,
    address: Option<String>,
    config: SwimConfig,
    incarnation: AtomicU64,
    seq: AtomicU64,
    transport: Arc<dyn SwimTransport>,
    members: RwLock<HashMap<NodeId, InternalMemberRecord>>,
    gossip_queue: Mutex<VecDeque<GossipRecord>>,
    route_table: RwLock<Option<Arc<ClusterRouteTable>>>,
    pending_acks: Mutex<HashMap<u64, Arc<Notify>>>,
    license_key: RwLock<Option<String>>,
}

impl SwimMembership {
    pub fn new(
        local: NodeId,
        address: Option<String>,
        config: SwimConfig,
        transport: Arc<dyn SwimTransport>,
    ) -> Arc<Self> {
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let initial_state = MemberState {
            node_id: local.clone(),
            status: NodeStatus::Alive,
            incarnation: 0,
            address: address.clone(),
            last_updated_epoch: now_epoch,
        };

        let mut map = HashMap::new();
        map.insert(
            local.clone(),
            InternalMemberRecord {
                state: initial_state,
                suspect_since: None,
            },
        );

        Arc::new(Self {
            local,
            address,
            config,
            incarnation: AtomicU64::new(0),
            seq: AtomicU64::new(1),
            transport,
            members: RwLock::new(map),
            gossip_queue: Mutex::new(VecDeque::new()),
            route_table: RwLock::new(None),
            pending_acks: Mutex::new(HashMap::new()),
            license_key: RwLock::new(None),
        })
    }

    pub fn set_license_key(&self, key: Option<String>) {
        *self.license_key.write() = key;
    }

    pub fn attach_route_table(&self, route_table: Arc<ClusterRouteTable>) {
        *self.route_table.write() = Some(route_table);
    }

    pub fn current_incarnation(&self) -> u64 {
        self.incarnation.load(Ordering::SeqCst)
    }

    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    /// Enqueue a gossip item for cluster-wide dissemination.
    pub async fn broadcast_gossip(&self, item: GossipItem) {
        let mut queue = self.gossip_queue.lock().await;
        queue.push_back(GossipRecord {
            item,
            transmissions_left: self.config.max_gossip_transmissions,
        });
    }

    /// Harvest up to `gossip_fanout` items to piggyback on outgoing envelopes.
    async fn harvest_gossip(&self) -> Vec<GossipItem> {
        let mut queue = self.gossip_queue.lock().await;
        let mut selected = Vec::new();
        let mut retained = VecDeque::new();

        while let Some(mut record) = queue.pop_front() {
            if selected.len() < self.config.gossip_fanout {
                selected.push(record.item.clone());
                if record.transmissions_left > 1 {
                    record.transmissions_left -= 1;
                    retained.push_back(record);
                }
            } else {
                retained.push_back(record);
            }
        }
        *queue = retained;
        selected
    }

    /// Apply an incoming gossip rumor using SWIM incarnation precedence and self-refutation.
    pub async fn apply_member_update(
        &self,
        node: NodeId,
        status: NodeStatus,
        incarnation: u64,
        address: Option<String>,
    ) {
        let current_inc = self.incarnation.load(Ordering::SeqCst);

        // Self-refutation: If someone claims I am Suspect or Dead, refute it!
        if node == self.local {
            if (status == NodeStatus::Suspect || status == NodeStatus::Dead)
                && incarnation >= current_inc
            {
                let new_inc = incarnation + 1;
                self.incarnation.store(new_inc, Ordering::SeqCst);
                info!(
                    "Self-refuting false status {:?} at incarnation {} with new incarnation {}",
                    status, incarnation, new_inc
                );
                self.broadcast_gossip(GossipItem::MemberUpdate {
                    node_id: self.local.clone(),
                    status: NodeStatus::Alive,
                    incarnation: new_inc,
                    address: self.address.clone(),
                })
                .await;
            }
            return;
        }

        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut members = self.members.write();
        let record = members.entry(node.clone()).or_insert_with(|| {
            info!("Discovered new cluster node: {}", node);
            InternalMemberRecord {
                state: MemberState {
                    node_id: node.clone(),
                    status: NodeStatus::Alive,
                    incarnation: 0,
                    address: address.clone(),
                    last_updated_epoch: now_epoch,
                },
                suspect_since: None,
            }
        });

        let should_update = match incarnation.cmp(&record.state.incarnation) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => matches!(
                (record.state.status, status),
                (NodeStatus::Alive, NodeStatus::Suspect)
                    | (NodeStatus::Alive, NodeStatus::Dead)
                    | (NodeStatus::Suspect, NodeStatus::Dead)
            ),
            std::cmp::Ordering::Less => false,
        };

        if should_update {
            let prev_status = record.state.status;
            record.state.status = status;
            record.state.incarnation = incarnation;
            record.state.last_updated_epoch = now_epoch;
            if address.is_some() {
                record.state.address = address;
            }

            if status == NodeStatus::Suspect {
                record.suspect_since = Some(Instant::now());
                warn!(
                    "Node {} is now SUSPECT at incarnation {}",
                    node, incarnation
                );
            } else {
                record.suspect_since = None;
                if status == NodeStatus::Dead || status == NodeStatus::Left {
                    warn!("Node {} is marked {:?}!", node, status);
                    if let Some(ref rt) = *self.route_table.read() {
                        rt.remove_all_for_node(&node);
                    }
                } else if prev_status != NodeStatus::Alive && status == NodeStatus::Alive {
                    info!(
                        "Node {} recovered to ALIVE at incarnation {}",
                        node, incarnation
                    );
                }
            }
        }
    }

    /// Process a batch of piggybacked gossip items.
    pub async fn apply_gossip_batch(&self, items: Vec<GossipItem>) {
        for item in items {
            match item {
                GossipItem::MemberUpdate {
                    node_id,
                    status,
                    incarnation,
                    address,
                } => {
                    self.apply_member_update(node_id, status, incarnation, address)
                        .await;
                }
                GossipItem::RouteUpdate {
                    node_id,
                    filter,
                    is_add,
                } => {
                    if let Some(ref rt) = *self.route_table.read() {
                        if let Ok(tf) = broker_protocol::TopicFilter::new(&filter) {
                            if is_add {
                                rt.add_route(&tf, node_id);
                            } else {
                                rt.remove_route(&tf, &node_id);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Join an existing cluster seed node.
    pub async fn join_seed(&self, seed: &NodeId) -> Result<(), ClusterError> {
        let gossip = self.harvest_gossip().await;
        let join_msg = SwimMessage::Join {
            from: self.local.clone(),
            address: self.address.clone(),
            gossip,
        };
        self.transport.send_to(seed, &join_msg).await?;
        Ok(())
    }

    /// Mark this node as Left and broadcast departure.
    pub async fn leave(&self) -> Result<(), ClusterError> {
        let inc = self.incarnation.load(Ordering::SeqCst);
        let leave_msg = SwimMessage::Leave {
            from: self.local.clone(),
            incarnation: inc,
        };
        let active = self.get_active_members();
        for peer in active {
            if peer != self.local {
                let _ = self.transport.send_to(&peer, &leave_msg).await;
            }
        }
        let mut members = self.members.write();
        if let Some(rec) = members.get_mut(&self.local) {
            rec.state.status = NodeStatus::Left;
        }
        Ok(())
    }

    /// Get list of all currently active (Alive or Suspect) member IDs.
    pub fn get_active_members(&self) -> Vec<NodeId> {
        let members = self.members.read();
        members
            .iter()
            .filter(|(_, rec)| {
                rec.state.status == NodeStatus::Alive || rec.state.status == NodeStatus::Suspect
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Select a random peer from alive or suspect members excluding local node.
    fn select_random_peer(&self) -> Option<NodeId> {
        let mut candidates: Vec<NodeId> = self
            .get_active_members()
            .into_iter()
            .filter(|id| id != &self.local)
            .collect();

        if candidates.is_empty() {
            None
        } else {
            let mut rng = rand::rng();
            candidates.shuffle(&mut rng);
            Some(candidates.remove(0))
        }
    }

    /// Select up to `k` random intermediary peers excluding local node and target.
    fn select_k_intermediaries(&self, target: &NodeId, k: usize) -> Vec<NodeId> {
        let mut candidates: Vec<NodeId> = self
            .get_active_members()
            .into_iter()
            .filter(|id| id != &self.local && id != target)
            .collect();

        let mut rng = rand::rng();
        candidates.shuffle(&mut rng);
        candidates.truncate(k);
        candidates
    }

    /// Perform a single failure detector probe step:
    /// Direct Ping -> Wait for Ack -> On Timeout: Indirect PingReq -> If all fail: mark Suspect.
    pub async fn step_probe(&self) -> Result<(), ClusterError> {
        let target = match self.select_random_peer() {
            Some(node) => node,
            None => return Ok(()),
        };

        let seq = self.next_seq();
        let notify = Arc::new(Notify::new());
        {
            let mut acks = self.pending_acks.lock().await;
            acks.insert(seq, notify.clone());
        }

        let gossip = self.harvest_gossip().await;
        let ping_msg = SwimMessage::Ping {
            seq,
            from: self.local.clone(),
            gossip,
        };

        let direct_send = self.transport.send_to(&target, &ping_msg).await;
        let ack_received = if direct_send.is_ok() {
            tokio::time::timeout(self.config.probe_timeout, notify.notified())
                .await
                .is_ok()
        } else {
            false
        };

        if ack_received {
            let mut acks = self.pending_acks.lock().await;
            acks.remove(&seq);
            return Ok(());
        }

        // Direct Ping timed out or failed; initiate Indirect Probe (PingReq) via k members
        debug!(
            "Direct probe to {} timed out, starting indirect PingReq",
            target
        );
        let intermediaries = self.select_k_intermediaries(&target, self.config.ping_req_members);
        if intermediaries.is_empty() {
            self.mark_node_suspect(&target).await;
            let mut acks = self.pending_acks.lock().await;
            acks.remove(&seq);
            return Ok(());
        }

        for intermediary in &intermediaries {
            let ping_req = SwimMessage::PingReq {
                seq,
                from: self.local.clone(),
                target: target.clone(),
                gossip: Vec::new(),
            };
            let _ = self.transport.send_to(intermediary, &ping_req).await;
        }

        let indirect_ack = tokio::time::timeout(self.config.ping_req_timeout, notify.notified())
            .await
            .is_ok();

        {
            let mut acks = self.pending_acks.lock().await;
            acks.remove(&seq);
        }

        if !indirect_ack {
            self.mark_node_suspect(&target).await;
        }

        Ok(())
    }

    async fn mark_node_suspect(&self, target: &NodeId) {
        let (inc, addr) = {
            let members = self.members.read();
            match members.get(target) {
                Some(rec) => (rec.state.incarnation, rec.state.address.clone()),
                None => return,
            }
        };

        self.apply_member_update(target.clone(), NodeStatus::Suspect, inc, addr)
            .await;
        self.broadcast_gossip(GossipItem::MemberUpdate {
            node_id: target.clone(),
            status: NodeStatus::Suspect,
            incarnation: inc,
            address: None,
        })
        .await;
    }

    /// Sweep through suspect nodes: if suspicion timeout exceeded, transition to Dead.
    pub async fn sweep_suspects(&self) {
        let mut to_dead = Vec::new();
        {
            let members = self.members.read();
            let now = Instant::now();
            for (id, rec) in members.iter() {
                if rec.state.status == NodeStatus::Suspect {
                    if let Some(since) = rec.suspect_since {
                        if now.duration_since(since) >= self.config.suspicion_timeout {
                            to_dead.push((
                                id.clone(),
                                rec.state.incarnation,
                                rec.state.address.clone(),
                            ));
                        }
                    }
                }
            }
        }

        for (id, inc, addr) in to_dead {
            warn!("Suspicion timeout expired for node {}, marking DEAD", id);
            self.apply_member_update(id.clone(), NodeStatus::Dead, inc, addr)
                .await;
            self.broadcast_gossip(GossipItem::MemberUpdate {
                node_id: id,
                status: NodeStatus::Dead,
                incarnation: inc,
                address: None,
            })
            .await;
        }
    }

    /// Handle an incoming message from a cluster member.
    pub async fn handle_message(
        &self,
        _from: NodeId,
        msg: SwimMessage,
    ) -> Result<(), ClusterError> {
        match msg {
            SwimMessage::Ping { seq, from, gossip } => {
                self.apply_gossip_batch(gossip).await;
                let ack_gossip = self.harvest_gossip().await;
                let ack = SwimMessage::Ack {
                    seq,
                    from: self.local.clone(),
                    gossip: ack_gossip,
                };
                self.transport.send_to(&from, &ack).await?;
            }
            SwimMessage::Ack {
                seq,
                from: _,
                gossip,
            } => {
                self.apply_gossip_batch(gossip).await;
                let notify = {
                    let acks = self.pending_acks.lock().await;
                    acks.get(&seq).cloned()
                };
                if let Some(n) = notify {
                    n.notify_one();
                }
            }
            SwimMessage::PingReq {
                seq,
                from,
                target,
                gossip,
            } => {
                self.apply_gossip_batch(gossip).await;
                let this = self;
                let transport = this.transport.clone();
                let local = this.local.clone();
                let ping = SwimMessage::Ping {
                    seq,
                    from: local,
                    gossip: Vec::new(),
                };
                // Forward ping to target
                let _ = transport.send_to(&target, &ping).await;
                // If we already know target is alive, send Ack directly to requester
                let is_alive = {
                    let members = this.members.read();
                    members
                        .get(&target)
                        .map(|r| r.state.status == NodeStatus::Alive)
                        .unwrap_or(false)
                };
                if is_alive {
                    let ack = SwimMessage::Ack {
                        seq,
                        from: target,
                        gossip: Vec::new(),
                    };
                    let _ = transport.send_to(&from, &ack).await;
                }
            }
            SwimMessage::Join {
                from,
                address,
                gossip,
            } => {
                self.apply_gossip_batch(gossip).await;

                // Enterprise License validation before admitting node
                let current_count = self.get_active_members().len();
                let now_epoch = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let lic_key = self.license_key.read().clone();
                let status =
                    ClusterLicense::evaluate(lic_key.as_deref(), current_count + 1, now_epoch);

                match status {
                    LicenseStatus::QuotaExceeded {
                        current_nodes,
                        max_nodes,
                        customer,
                    } => {
                        warn!(
                            "Rejecting node {} join: license quota exceeded ({}/{} nodes) for {}",
                            from, current_nodes, max_nodes, customer
                        );
                        return Err(ClusterError::Transport("License quota exceeded".into()));
                    }
                    LicenseStatus::Expired {
                        customer,
                        expired_at,
                    } => {
                        warn!(
                            "Rejecting node {} join: license expired for {} at {}",
                            from, customer, expired_at
                        );
                        return Err(ClusterError::Transport("License expired".into()));
                    }
                    _ => {}
                }

                self.apply_member_update(from.clone(), NodeStatus::Alive, 0, address)
                    .await;

                let member_states: Vec<MemberState> = {
                    let members = self.members.read();
                    members.values().map(|r| r.state.clone()).collect()
                };

                let reply_gossip = self.harvest_gossip().await;
                let join_ack = SwimMessage::JoinAck {
                    from: self.local.clone(),
                    members: member_states,
                    gossip: reply_gossip,
                };
                self.transport.send_to(&from, &join_ack).await?;
            }
            SwimMessage::JoinAck {
                from: _,
                members,
                gossip,
            } => {
                self.apply_gossip_batch(gossip).await;
                for state in members {
                    self.apply_member_update(
                        state.node_id,
                        state.status,
                        state.incarnation,
                        state.address,
                    )
                    .await;
                }
            }
            SwimMessage::Leave { from, incarnation } => {
                self.apply_member_update(from, NodeStatus::Left, incarnation, None)
                    .await;
            }
        }
        Ok(())
    }

    /// Run the background failure detection and gossip dispatch loops.
    pub fn run_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut probe_interval = tokio::time::interval(self.config.probe_interval);
            let mut sweep_interval = tokio::time::interval(self.config.probe_interval * 2);

            let node_recv = self.clone();
            let _recv_handle = tokio::spawn(async move {
                while let Some((from, msg)) = node_recv.transport.recv().await {
                    if let Err(e) = node_recv.handle_message(from, msg).await {
                        debug!("Error handling cluster message: {}", e);
                    }
                }
            });

            loop {
                tokio::select! {
                    _ = probe_interval.tick() => {
                        let _ = self.step_probe().await;
                    }
                    _ = sweep_interval.tick() => {
                        self.sweep_suspects().await;
                    }
                }
            }
        })
    }
}

#[async_trait]
impl ClusterMembership for SwimMembership {
    fn local_node_id(&self) -> &NodeId {
        &self.local
    }

    async fn active_nodes(&self) -> Result<Vec<NodeId>, ClusterError> {
        Ok(self.get_active_members())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId::new(s)
    }

    #[tokio::test]
    async fn test_incarnation_precedence_and_self_refutation() {
        let net = ChannelSwimNetwork::new();
        let t1 = net.register(node("node-1"));
        let swim1 = SwimMembership::new(node("node-1"), None, SwimConfig::default(), t1);

        assert_eq!(swim1.current_incarnation(), 0);

        // Rumor: node-1 is Suspect at incarnation 0.
        // Node-1 must self-refute by bumping incarnation to 1 and staying Alive.
        swim1
            .apply_member_update(node("node-1"), NodeStatus::Suspect, 0, None)
            .await;

        assert_eq!(swim1.current_incarnation(), 1);
        let active = swim1.get_active_members();
        assert!(active.contains(&node("node-1")));

        // Another node rumor: node-2 is Alive at incarnation 0
        swim1
            .apply_member_update(node("node-2"), NodeStatus::Alive, 0, None)
            .await;
        assert_eq!(swim1.get_active_members().len(), 2);

        // Rumor: node-2 is Suspect at same incarnation (0) -> transitions to Suspect
        swim1
            .apply_member_update(node("node-2"), NodeStatus::Suspect, 0, None)
            .await;
        {
            let members = swim1.members.read();
            assert_eq!(
                members.get(&node("node-2")).unwrap().state.status,
                NodeStatus::Suspect
            );
        }

        // Stale rumor: node-2 is Alive at incarnation 0 -> rejected, still Suspect
        swim1
            .apply_member_update(node("node-2"), NodeStatus::Alive, 0, None)
            .await;
        {
            let members = swim1.members.read();
            assert_eq!(
                members.get(&node("node-2")).unwrap().state.status,
                NodeStatus::Suspect
            );
        }

        // Higher incarnation rumor: node-2 is Alive at incarnation 1 -> accepted!
        swim1
            .apply_member_update(node("node-2"), NodeStatus::Alive, 1, None)
            .await;
        {
            let members = swim1.members.read();
            assert_eq!(
                members.get(&node("node-2")).unwrap().state.status,
                NodeStatus::Alive
            );
        }
    }

    #[tokio::test]
    async fn test_direct_ping_ack_cycle() {
        let net = ChannelSwimNetwork::new();
        let t1 = net.register(node("node-1"));
        let t2 = net.register(node("node-2"));

        let swim1 = SwimMembership::new(node("node-1"), None, SwimConfig::default(), t1);
        let swim2 = SwimMembership::new(node("node-2"), None, SwimConfig::default(), t2);

        // Spawn listener for node-2
        let s2_clone = swim2.clone();
        let handle2 = tokio::spawn(async move {
            if let Some((from, msg)) = s2_clone.transport.recv().await {
                s2_clone.handle_message(from, msg).await.unwrap();
            }
        });

        // Spawn listener for node-1 (to catch Ack)
        let s1_clone = swim1.clone();
        let handle1 = tokio::spawn(async move {
            if let Some((from, msg)) = s1_clone.transport.recv().await {
                s1_clone.handle_message(from, msg).await.unwrap();
            }
        });

        // Add node-2 to node-1's known members
        swim1
            .apply_member_update(node("node-2"), NodeStatus::Alive, 0, None)
            .await;

        let result = swim1.step_probe().await;
        assert!(result.is_ok());

        let _ = tokio::join!(handle1, handle2);
        assert!(swim1.get_active_members().contains(&node("node-2")));
    }

    #[tokio::test]
    async fn test_suspicion_to_dead_lifecycle() {
        let net = ChannelSwimNetwork::new();
        let t1 = net.register(node("node-1"));
        let cfg = SwimConfig {
            suspicion_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let swim1 = SwimMembership::new(node("node-1"), None, cfg, t1);

        // Discovered node-2
        swim1
            .apply_member_update(node("node-2"), NodeStatus::Alive, 0, None)
            .await;
        assert_eq!(swim1.get_active_members().len(), 2);

        // Node-2 becomes suspect
        swim1
            .apply_member_update(node("node-2"), NodeStatus::Suspect, 0, None)
            .await;
        assert_eq!(swim1.get_active_members().len(), 2);

        // Wait beyond suspicion timeout
        tokio::time::sleep(Duration::from_millis(70)).await;
        swim1.sweep_suspects().await;

        // Node-2 is now Dead and excluded from active members
        let active = swim1.get_active_members();
        assert_eq!(active, vec![node("node-1")]);
    }

    #[tokio::test]
    async fn test_route_table_cleanup_on_node_death() {
        let net = ChannelSwimNetwork::new();
        let t1 = net.register(node("node-1"));
        let swim1 = SwimMembership::new(node("node-1"), None, SwimConfig::default(), t1);

        let rt = Arc::new(ClusterRouteTable::new(node("node-1")));
        let filter = broker_protocol::TopicFilter::new("telemetry/#").unwrap();
        let topic = broker_protocol::Topic::new("telemetry/temperature").unwrap();

        rt.add_route(&filter, node("node-2"));
        assert_eq!(
            rt.resolve_nodes(&topic),
            std::collections::HashSet::from([node("node-2")])
        );

        swim1.attach_route_table(rt.clone());

        // Mark node-2 dead
        swim1
            .apply_member_update(node("node-2"), NodeStatus::Dead, 0, None)
            .await;

        // Route table automatically purged
        assert!(rt.resolve_nodes(&topic).is_empty());
    }

    #[tokio::test]
    async fn test_piggybacked_gossip_dissemination() {
        let net = ChannelSwimNetwork::new();
        let t1 = net.register(node("node-1"));
        let swim1 = SwimMembership::new(node("node-1"), None, SwimConfig::default(), t1);

        swim1
            .broadcast_gossip(GossipItem::MemberUpdate {
                node_id: node("node-3"),
                status: NodeStatus::Alive,
                incarnation: 5,
                address: Some("127.0.0.1:19885".into()),
            })
            .await;

        let harvest = swim1.harvest_gossip().await;
        assert_eq!(harvest.len(), 1);
        match &harvest[0] {
            GossipItem::MemberUpdate {
                node_id,
                incarnation,
                ..
            } => {
                assert_eq!(node_id, &node("node-3"));
                assert_eq!(*incarnation, 5);
            }
            _ => panic!("Expected MemberUpdate"),
        }
    }

    #[tokio::test]
    async fn test_graceful_leave() {
        let net = ChannelSwimNetwork::new();
        let t1 = net.register(node("node-1"));
        let swim1 = SwimMembership::new(node("node-1"), None, SwimConfig::default(), t1);

        assert!(swim1.get_active_members().contains(&node("node-1")));
        swim1.leave().await.unwrap();

        // Status is now Left
        let members = swim1.members.read();
        assert_eq!(
            members.get(&node("node-1")).unwrap().state.status,
            NodeStatus::Left
        );
    }

    #[tokio::test]
    async fn test_cluster_membership_trait_integration() {
        let net = ChannelSwimNetwork::new();
        let t1 = net.register(node("node-1"));
        let swim1: Arc<dyn ClusterMembership> =
            SwimMembership::new(node("node-1"), None, SwimConfig::default(), t1);

        assert_eq!(swim1.local_node_id(), &node("node-1"));
        let active = swim1.active_nodes().await.unwrap();
        assert_eq!(active, vec![node("node-1")]);
    }

    #[tokio::test]
    async fn test_indirect_ping_req_recovery() {
        let net = ChannelSwimNetwork::new();
        let t1 = net.register(node("node-1"));
        let t2 = net.register(node("node-2"));
        let t3 = net.register(node("node-3"));

        let cfg = SwimConfig {
            probe_timeout: Duration::from_millis(30),
            ping_req_timeout: Duration::from_millis(150),
            ..Default::default()
        };

        let swim1 = SwimMembership::new(node("node-1"), None, cfg.clone(), t1);
        let swim2 = SwimMembership::new(node("node-2"), None, cfg.clone(), t2);
        let _swim3 = SwimMembership::new(node("node-3"), None, cfg.clone(), t3);

        // Node-1 knows Node-2 and Node-3
        swim1
            .apply_member_update(node("node-2"), NodeStatus::Alive, 0, None)
            .await;
        swim1
            .apply_member_update(node("node-3"), NodeStatus::Alive, 0, None)
            .await;

        // Node-2 listener responds to PingReq by confirming target is alive
        let s2_clone = swim2.clone();
        let handle2 = tokio::spawn(async move {
            // Node-2 knows Node-3 is Alive
            s2_clone
                .apply_member_update(node("node-3"), NodeStatus::Alive, 0, None)
                .await;
            if let Some((from, msg)) = s2_clone.transport.recv().await {
                let _ = s2_clone.handle_message(from, msg).await;
            }
        });

        // Spawn listener for node-1 to receive indirect Ack
        let s1_clone = swim1.clone();
        let handle1 = tokio::spawn(async move {
            if let Some((from, msg)) = s1_clone.transport.recv().await {
                let _ = s1_clone.handle_message(from, msg).await;
            }
        });

        // Force probe to node-3 (which has no direct listener, so direct ping times out)
        // Intermediary node-2 will answer PingReq because it knows node-3 is Alive!
        let result = swim1.step_probe().await;
        assert!(result.is_ok());

        let _ = tokio::join!(handle1, handle2);
    }

    #[tokio::test]
    async fn test_license_quota_enforcement() {
        let net = ChannelSwimNetwork::new();
        let t1 = net.register(node("node-1"));
        let _t2 = net.register(node("node-2"));
        let _t3 = net.register(node("node-3"));
        let swim1 = SwimMembership::new(node("node-1"), None, SwimConfig::default(), t1);

        // Create an enterprise license key limited to 2 nodes
        let payload = crate::license::LicensePayload {
            customer: "Acme Industrial IoT".into(),
            max_nodes: 2,
            issued_at: 1700000000,
            expires_at: 2000000000,
            features: vec!["clustering".into()],
        };
        let key = crate::license::ClusterLicense::generate_signed_token(&payload);
        swim1.set_license_key(Some(key));

        // Node-2 joins -> admitted (2/2 nodes)
        let join2 = SwimMessage::Join {
            from: node("node-2"),
            address: None,
            gossip: Vec::new(),
        };
        let res2 = swim1.handle_message(node("node-2"), join2).await;
        assert!(res2.is_ok());

        // Node-3 joins -> rejected because max_nodes is 2
        let join3 = SwimMessage::Join {
            from: node("node-3"),
            address: None,
            gossip: Vec::new(),
        };
        let res3 = swim1.handle_message(node("node-3"), join3).await;
        assert!(res3.is_err());
        assert!(matches!(res3, Err(ClusterError::Transport(_))));
    }

    #[tokio::test]
    async fn test_udp_swim_transport_loopback() {
        let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let u1 = UdpSwimTransport::bind(node("u1"), addr1).await.unwrap();
        let u2 = UdpSwimTransport::bind(node("u2"), addr2).await.unwrap();

        let real_addr1 = u1.socket.local_addr().unwrap();
        let real_addr2 = u2.socket.local_addr().unwrap();

        u1.register_peer(node("u2"), real_addr2);
        u2.register_peer(node("u1"), real_addr1);

        let msg = SwimMessage::Ping {
            seq: 42,
            from: node("u1"),
            gossip: vec![GossipItem::MemberUpdate {
                node_id: node("u1"),
                status: NodeStatus::Alive,
                incarnation: 1,
                address: Some(real_addr1.to_string()),
            }],
        };

        u1.send_to(&node("u2"), &msg).await.unwrap();

        let (from, received) = tokio::time::timeout(Duration::from_millis(500), u2.recv())
            .await
            .expect("timeout")
            .expect("received packet");

        assert_eq!(from, node("u1"));
        match received {
            SwimMessage::Ping {
                seq,
                from: f,
                gossip,
            } => {
                assert_eq!(seq, 42);
                assert_eq!(f, node("u1"));
                assert_eq!(gossip.len(), 1);
            }
            _ => panic!("Expected Ping message"),
        }
    }
}
