use ahash::{AHashMap, AHashSet};
use broker_observability::Metrics;
use broker_protocol::{QoS, Topic, TopicFilter};
use brokerlink::{BrokerFrame, OpCode};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Notify;

/// One client's subscription. `client_id` is reference-counted so fan-out
/// matching clones pointers instead of heap strings. `group` carries a
/// shared-subscription group (`$share/<group>/...`): members of one group
/// split matching messages round-robin instead of each receiving a copy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Subscription {
    pub client_id: Arc<str>,
    /// Ephemeral edge connection owning this subscription copy. A
    /// re-subscribe from a new connection replaces the entry, so at most
    /// one `conn_id` per `(filter node, client_id)` exists.
    pub conn_id: u64,
    pub qos: QoS,
    pub group: Option<Arc<str>>,
}

impl Subscription {
    /// Plain (non-shared) subscription.
    pub fn new(client_id: impl Into<Arc<str>>, conn_id: u64, qos: QoS) -> Self {
        Self {
            client_id: client_id.into(),
            conn_id,
            qos,
            group: None,
        }
    }

    /// Shared-subscription member of `group`.
    pub fn shared(
        client_id: impl Into<Arc<str>>,
        conn_id: u64,
        qos: QoS,
        group: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            conn_id,
            qos,
            group: Some(group.into()),
        }
    }
}

/// Split a `$delayed/<seconds>/<topic>` publish target into its delay
/// and inner topic. Returns `None` for ordinary topics. The delay must
/// be a non-negative integer and the inner topic non-empty; anything
/// else is also `None` (the caller treats it as malformed).
pub fn strip_delayed_prefix(topic: &str) -> Option<(u64, &str)> {
    let rest = topic.strip_prefix("$delayed/")?;
    let (secs, inner) = rest.split_once('/')?;
    if inner.is_empty() {
        return None;
    }
    secs.parse::<u64>().ok().map(|delay| (delay, inner))
}

/// Split a `$share/<group>/<filter>` request into its group and inner
/// filter. Plain filters pass through with `group = None`. Returns `None`
/// only for malformed shared requests (empty group or invalid inner
/// filter); the caller should reject the subscription.
pub fn split_shared_filter(filter: &TopicFilter) -> Option<(Option<Arc<str>>, TopicFilter)> {
    let raw = filter.as_str();
    let rest = match raw.strip_prefix("$share/") {
        Some(rest) => rest,
        None => return Some((None, filter.clone())),
    };
    let (group, inner) = rest.split_once('/')?;
    if group.is_empty() || inner.is_empty() {
        return None;
    }
    let inner_filter = TopicFilter::new(inner).ok()?;
    Some((Some(group.into()), inner_filter))
}

/// Match result set. `ahash` keeps debug and release builds fast;
/// iteration order is unspecified (assert on membership, not order).
pub type SubscriptionSet = AHashSet<Subscription>;

#[derive(Default)]
struct TrieNode {
    // Exact child path segments (shared, never cloned on match)
    children: AHashMap<Arc<str>, TrieNode>,
    // Single-level wildcard '+' child
    single_wildcard: Option<Box<TrieNode>>,
    // Multi-level wildcard '#' subscriptions at this level
    multi_wildcard_subs: SubscriptionSet,
    // Exact subscriptions attached at this terminal node
    exact_subs: SubscriptionSet,
}

/// Maximum concrete topics remembered by the topic index (W1-15).
/// The list read snapshots at most this many names under a short lock,
/// sorted for a deterministic page order, then the W0 paging helper
/// slices the requested page. Per-topic state is one shared string;
/// publishes past the cap are dropped from the index (delivery still
/// proceeds) so one client cannot balloon the node. Management-plane
/// only: the fan-out match path never touches this set.
pub const MAX_KNOWN_TOPICS: usize = 100_000;

/// Default bound for the per-subscriber QoS 0 egress backlog (D1-02).
///
/// Each live connection queues at most this many QoS 0 `PublishOut`
/// frames in its [`ConnTable`] mailbox; past it the oldest queued QoS 0
/// frame drops (counted via `egress_qos0_shed`, labelled by client) so a
/// slow or absent consumer costs a bounded amount of memory and never
/// slows publishers. QoS 1/2 never shed: they bypass this bound on the
/// guaranteed path.
///
/// Rationale: 1,000 matches the existing detached offline bound
/// (`MAX_OFFLINE_QUEUE` = 1024) so live and detached backlogs share one
/// memory story, absorbs a ~1 s burst at 1k msg/s per subscriber without
/// drops, and caps per-subscriber QoS 0 memory near 1,000 small frames
/// (128 B payloads stay well under 1 MB with framing overhead). The
/// symmetric QoS 0 load that motivated this task queued without limit
/// (tens of seconds of latency, ~1M deep); 1,000 keeps p99 latency near
/// the drain rate instead of the backlog depth. Override per table via
/// [`ConnTable::with_qos0_bound`] / [`ConnTable::set_qos0_bound`].
pub const DEFAULT_QOS0_BACKLOG: usize = 1_000;

/// True when `frame` is a QoS 0 `PublishOut` (the only sheddable shape).
/// Parses the `PublishOut` meta `TopicLen:16be | Topic | PacketId:16be |
/// QoS:8 | Retain:8 | Dup:8`; anything unparseable is not QoS 0 so a
/// malformed frame can never trigger a shed of guaranteed traffic.
pub fn is_qos0_publish_out(frame: &BrokerFrame) -> bool {
    if frame.header.opcode != OpCode::PublishOut {
        return false;
    }
    let meta = &frame.metadata;
    if meta.len() < 7 {
        return false;
    }
    let topic_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    if meta.len() != 2 + topic_len + 5 {
        return false;
    }
    meta[2 + topic_len + 2] == 0
}

pub struct Router {
    root: RwLock<TrieNode>,
    /// Round-robin cursors per shared-subscription group. Mutated under
    /// `matches`, hence behind the lock; keyed by group name alone so one
    /// group balances across all its filters.
    rr_cursors: RwLock<AHashMap<Arc<str>, usize>>,
    /// Known concrete topics seen on publishes (W1-15). Separate lock
    /// from the subscription trie so management list reads never block
    /// the routing path and publishes only take a short write.
    known_topics: RwLock<AHashSet<Arc<str>>>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    pub fn new() -> Self {
        Self {
            root: RwLock::new(TrieNode::default()),
            rr_cursors: RwLock::new(AHashMap::new()),
            known_topics: RwLock::new(AHashSet::new()),
        }
    }

    /// Remember one concrete publish topic for the management topic
    /// index (W1-15). Exact topic string only, no wildcard expansion.
    /// Bounded by [`MAX_KNOWN_TOPICS`]: inserts past the cap are
    /// ignored while delivery proceeds. Empty and over-long names are
    /// ignored (publishes already validate). Takes only a short lock;
    /// never allocates on the fan-out match path beyond the insert
    /// itself. Management-plane index; fan-in/fan-out never read it.
    pub fn record_topic(&self, topic: &str) {
        if topic.is_empty() || topic.len() > u16::MAX as usize {
            return;
        }
        {
            let known = self.known_topics.read();
            if known.contains(topic) {
                return;
            }
            if known.len() >= MAX_KNOWN_TOPICS {
                return;
            }
        }
        let mut known = self.known_topics.write();
        if known.len() >= MAX_KNOWN_TOPICS && !known.contains(topic) {
            return;
        }
        known.insert(topic.into());
    }

    /// Snapshot every known topic, sorted for a deterministic page
    /// order (W1-15). Clones at most [`MAX_KNOWN_TOPICS`] shared
    /// strings under a short lock; the caller slices the page.
    /// Management-plane only: the routing trie is never touched.
    pub fn list_topics(&self) -> Vec<String> {
        let known = self.known_topics.read();
        let mut out: Vec<String> = known.iter().map(|t| t.to_string()).collect();
        drop(known);
        out.sort();
        if out.len() > MAX_KNOWN_TOPICS {
            out.truncate(MAX_KNOWN_TOPICS);
        }
        out
    }

    /// Exact topic membership for the detail read (W1-15). The path
    /// parameter arrives percent-decoded by the extractor, so this is
    /// a plain exact comparison with no wildcard or prefix matching.
    pub fn contains_topic(&self, topic: &str) -> bool {
        self.known_topics.read().contains(topic)
    }

    pub fn subscribe(&self, filter: &TopicFilter, sub: Subscription) {
        let mut root = self.root.write();
        let mut curr = &mut *root;
        // Peekable so the terminal level is known without collecting.
        let mut levels = filter.as_str().split('/').peekable();

        while let Some(level) = levels.next() {
            if level == "#" {
                // Re-subscribing from a new connection replaces the old copy.
                curr.multi_wildcard_subs
                    .retain(|s| s.client_id != sub.client_id);
                curr.multi_wildcard_subs.insert(sub);
                return;
            } else if level == "+" {
                if curr.single_wildcard.is_none() {
                    curr.single_wildcard = Some(Box::new(TrieNode::default()));
                }
                curr = curr.single_wildcard.as_mut().unwrap();
            } else {
                curr = curr.children.entry(level.into()).or_default();
            }

            if levels.peek().is_none() {
                curr.exact_subs.retain(|s| s.client_id != sub.client_id);
                curr.exact_subs.insert(sub);
                return;
            }
        }
    }

    pub fn unsubscribe(&self, filter: &TopicFilter, client_id: &str) {
        let mut root = self.root.write();
        let mut curr = &mut *root;
        let mut levels = filter.as_str().split('/').peekable();

        while let Some(level) = levels.next() {
            if level == "#" {
                curr.multi_wildcard_subs
                    .retain(|s| s.client_id.as_ref() != client_id);
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

            if levels.peek().is_none() {
                curr.exact_subs
                    .retain(|s| s.client_id.as_ref() != client_id);
                return;
            }
        }
    }

    pub fn matches(&self, topic: &Topic) -> SubscriptionSet {
        let root = self.root.read();
        let mut matched = SubscriptionSet::default();
        Self::match_recursive(&root, topic.as_str(), &mut matched);
        self.balance_shared_groups(&mut matched);
        matched
    }

    /// Reduce each shared group in `matched` to exactly one member,
    /// round-robin by group. Members sort by client id first so the
    /// rotation is deterministic. Plain subscriptions pass through.
    fn balance_shared_groups(&self, matched: &mut SubscriptionSet) {
        if !matched.iter().any(|s| s.group.is_some()) {
            return;
        }
        let mut groups: AHashMap<Arc<str>, Vec<Subscription>> = AHashMap::new();
        matched.retain(|sub| match &sub.group {
            Some(group) => {
                groups.entry(group.clone()).or_default().push(sub.clone());
                false
            }
            None => true,
        });
        if groups.is_empty() {
            return;
        }
        let mut cursors = self.rr_cursors.write();
        for (group, mut members) in groups {
            members.sort_by(|a, b| a.client_id.cmp(&b.client_id));
            let cursor = cursors.entry(group).or_insert(0);
            let pick = members[*cursor % members.len()].clone();
            *cursor = cursor.wrapping_add(1);
            matched.insert(pick);
        }
    }

    /// Walk one topic remainder without allocating: `split_once` borrows
    /// slices of the original topic instead of collecting a level vector.
    fn match_recursive(node: &TrieNode, topic: &str, matched: &mut SubscriptionSet) {
        // Multi-level '#' matches all subtopics at this level and deeper.
        matched.extend(node.multi_wildcard_subs.iter().cloned());

        match topic.split_once('/') {
            Some((head, tail)) => {
                // Match exact segment.
                if let Some(child) = node.children.get(head) {
                    Self::match_recursive(child, tail, matched);
                }
                // Match single wildcard '+'.
                if let Some(ref child) = node.single_wildcard {
                    Self::match_recursive(child, tail, matched);
                }
            }
            None => {
                // Final segment: descend once more for terminal sets.
                if let Some(child) = node.children.get(topic) {
                    matched.extend(child.multi_wildcard_subs.iter().cloned());
                    matched.extend(child.exact_subs.iter().cloned());
                }
                if let Some(ref child) = node.single_wildcard {
                    matched.extend(child.multi_wildcard_subs.iter().cloned());
                    matched.extend(child.exact_subs.iter().cloned());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_wildcard_fanout() {
        let router = Router::new();

        let sub1 = Subscription::new("c1", 101, QoS::AtMostOnce);
        let sub2 = Subscription::new("c2", 102, QoS::AtLeastOnce);
        let sub3 = Subscription::new("c3", 103, QoS::ExactlyOnce);

        router.subscribe(&TopicFilter::new("sports/tennis/+").unwrap(), sub1.clone());
        router.subscribe(&TopicFilter::new("sports/#").unwrap(), sub2.clone());
        router.subscribe(&TopicFilter::new("finance/stocks").unwrap(), sub3.clone());

        let matches = router.matches(&Topic::new("sports/tennis/wimbledon").unwrap());
        assert_eq!(matches.len(), 2);
        assert!(matches.contains(&sub1));
        assert!(matches.contains(&sub2));

        let matches_other = router.matches(&Topic::new("finance/stocks").unwrap());
        assert_eq!(matches_other.len(), 1);
        assert!(matches_other.contains(&sub3));

        // Unsubscribe c1
        router.unsubscribe(&TopicFilter::new("sports/tennis/+").unwrap(), "c1");
        let matches_after = router.matches(&Topic::new("sports/tennis/wimbledon").unwrap());
        assert_eq!(matches_after.len(), 1);
        assert!(matches_after.contains(&sub2));
    }

    #[test]
    fn test_resubscribe_replaces_conn_id() {
        let router = Router::new();
        let filter = TopicFilter::new("sports/tennis").unwrap();

        router.subscribe(&filter, Subscription::new("c1", 101, QoS::AtMostOnce));
        router.subscribe(&filter, Subscription::new("c1", 202, QoS::AtLeastOnce));

        let matches = router.matches(&Topic::new("sports/tennis").unwrap());
        assert_eq!(matches.len(), 1);
        let only = matches.iter().next().unwrap();
        assert_eq!(only.conn_id, 202);
        assert_eq!(only.qos, QoS::AtLeastOnce);
    }

    #[test]
    fn test_split_shared_filter_vectors() {
        // Plain filters pass through untouched.
        let (group, inner) =
            split_shared_filter(&TopicFilter::new("tasks/#").unwrap()).expect("plain");
        assert!(group.is_none());
        assert_eq!(inner.as_str(), "tasks/#");

        // Shared requests split into group + inner filter.
        let (group, inner) =
            split_shared_filter(&TopicFilter::new("$share/worker_pool/tasks/#").unwrap())
                .expect("shared");
        assert_eq!(group.as_deref(), Some("worker_pool"));
        assert_eq!(inner.as_str(), "tasks/#");

        // Malformed shared requests are rejected.
        assert!(split_shared_filter(&TopicFilter::new("$share/").unwrap()).is_none());
        assert!(split_shared_filter(&TopicFilter::new("$share//tasks").unwrap()).is_none());
        assert!(split_shared_filter(&TopicFilter::new("$share/g/").unwrap()).is_none());
    }

    #[test]
    fn test_strip_delayed_prefix_vectors() {
        // Ordinary topics pass through untouched.
        assert_eq!(strip_delayed_prefix("sensors/temp"), None);
        assert_eq!(strip_delayed_prefix("$share/g/t"), None);
        // Well-formed delayed targets split into delay + inner topic.
        assert_eq!(
            strip_delayed_prefix("$delayed/5/sensors/temp"),
            Some((5, "sensors/temp"))
        );
        assert_eq!(strip_delayed_prefix("$delayed/0/a"), Some((0, "a")));
        // Malformed variants are all rejected.
        assert_eq!(strip_delayed_prefix("$delayed/"), None);
        assert_eq!(strip_delayed_prefix("$delayed/5/"), None);
        assert_eq!(strip_delayed_prefix("$delayed/soon/t"), None);
        assert_eq!(strip_delayed_prefix("$delayed/-3/t"), None);
    }

    #[test]
    fn test_shared_group_round_robin_distributes() {
        let router = Router::new();
        let inner = TopicFilter::new("tasks").unwrap();
        router.subscribe(
            &inner,
            Subscription::shared("worker-a", 1, QoS::AtMostOnce, "group1"),
        );
        router.subscribe(
            &inner,
            Subscription::shared("worker-b", 2, QoS::AtMostOnce, "group1"),
        );

        // Four sequential matches alternate deterministically (members
        // sort by client id; cursor starts at zero).
        let topic = Topic::new("tasks").unwrap();
        let mut owners = Vec::new();
        for _ in 0..4 {
            let matched = router.matches(&topic);
            assert_eq!(matched.len(), 1, "exactly one member per group");
            owners.push(matched.iter().next().unwrap().client_id.to_string());
        }
        assert_eq!(
            owners,
            vec![
                "worker-a".to_string(),
                "worker-b".to_string(),
                "worker-a".to_string(),
                "worker-b".to_string()
            ]
        );
    }

    #[test]
    fn test_shared_and_plain_subscribers_coexist() {
        let router = Router::new();
        let inner = TopicFilter::new("jobs/+").unwrap();
        router.subscribe(
            &inner,
            Subscription::shared("worker-a", 1, QoS::AtMostOnce, "pool"),
        );
        router.subscribe(
            &inner,
            Subscription::shared("worker-b", 2, QoS::AtMostOnce, "pool"),
        );
        router.subscribe(
            &TopicFilter::new("jobs/+").unwrap(),
            Subscription::new("plain-c", 3, QoS::AtMostOnce),
        );

        // Plain subscriber always present; exactly one group member joins.
        for _ in 0..4 {
            let matched = router.matches(&Topic::new("jobs/9").unwrap());
            assert_eq!(matched.len(), 2);
            assert!(matched.iter().any(|s| s.client_id.as_ref() == "plain-c"));
            assert_eq!(matched.iter().filter(|s| s.group.is_some()).count(), 1);
        }
    }

    #[test]
    fn test_shared_unsubscribe_removes_member() {
        let router = Router::new();
        let inner = TopicFilter::new("tasks").unwrap();
        router.subscribe(
            &inner,
            Subscription::shared("worker-a", 1, QoS::AtMostOnce, "group1"),
        );
        router.subscribe(
            &inner,
            Subscription::shared("worker-b", 2, QoS::AtMostOnce, "group1"),
        );

        router.unsubscribe(&inner, "worker-a");
        for _ in 0..3 {
            let matched = router.matches(&Topic::new("tasks").unwrap());
            assert_eq!(matched.len(), 1);
            assert_eq!(
                matched.iter().next().unwrap().client_id.as_ref(),
                "worker-b"
            );
        }
    }

    #[test]
    fn topic_index_records_lists_and_matches_exactly() {
        let router = Router::new();
        assert!(router.list_topics().is_empty());
        assert!(!router.contains_topic("w1-15/a"));

        // Subscribing alone never creates a topic row.
        router.subscribe(
            &TopicFilter::new("w1-15/+").unwrap(),
            Subscription::new("c1", 1, QoS::AtMostOnce),
        );
        assert!(router.list_topics().is_empty());

        // Recording is exact and sorted; duplicates do not duplicate.
        router.record_topic("w1-15/b");
        router.record_topic("w1-15/a");
        router.record_topic("w1-15/a");
        assert_eq!(
            router.list_topics(),
            vec!["w1-15/a".to_string(), "w1-15/b".to_string()]
        );
        assert!(router.contains_topic("w1-15/a"));
        assert!(!router.contains_topic("w1-15"));
        assert!(!router.contains_topic("w1-15/a/b"));

        // Empty and over-long names are ignored.
        router.record_topic("");
        assert_eq!(router.list_topics().len(), 2);
    }

    #[test]
    fn route_stamps_per_destination_sequence_under_shards() {
        // Conn ids 0 and 1 land in different buckets
        // (`conn_id as usize % 16`), so interleaved routes must still
        // stamp each destination 1, 2, 3, ... independently.
        let table = ConnTable::default();
        let (tx_a, mut rx_a) = tokio::sync::mpsc::unbounded_channel();
        let (tx_b, mut rx_b) = tokio::sync::mpsc::unbounded_channel();
        table.register(0, tx_a);
        table.register(1, tx_b);

        for _ in 0..3 {
            table.route(0, BrokerFrame::ping(0, 0));
            table.route(1, BrokerFrame::ping(1, 0));
        }

        for expected in 1..=3u64 {
            let frame_a = rx_a.try_recv().expect("conn 0 frame");
            assert_eq!(frame_a.header.sequence_no, expected);
            let frame_b = rx_b.try_recv().expect("conn 1 frame");
            assert_eq!(frame_b.header.sequence_no, expected);
        }
        assert!(rx_a.try_recv().is_err());
        assert!(rx_b.try_recv().is_err());

        // Unknown destinations keep drop-and-forget semantics.
        assert!(
            !table.route(9999, BrokerFrame::ping(9999, 0)),
            "unknown destination must report dropped"
        );
    }

    #[test]
    fn route_reports_whether_the_frame_reached_a_live_mailbox() {
        let table = ConnTable::default();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        table.register(7, tx);
        assert!(
            table.route(7, BrokerFrame::ping(7, 0)),
            "live mailbox must report enqueued"
        );
        assert!(
            !table.route(9999, BrokerFrame::ping(9999, 0)),
            "unknown destination reports dropped"
        );
    }

    #[test]
    fn route_reports_dead_mailbox_and_prunes_it() {
        let table = ConnTable::default();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        table.register(8, tx);
        drop(rx);
        assert!(
            !table.route(8, BrokerFrame::ping(8, 0)),
            "dead mailbox must report dropped"
        );
        assert!(
            !table.route(8, BrokerFrame::ping(8, 0)),
            "dead destination stays pruned"
        );
    }

    #[test]
    fn route_unknown_conn_counts_drop_only() {
        // PERF-10: three frames to a conn_id with no mailbox must bump
        // exactly the unknown-conn counter, nothing else.
        let metrics = Arc::new(Metrics::new());
        let table = ConnTable::default();
        table.set_metrics(&metrics);

        for _ in 0..3 {
            table.route(9999, BrokerFrame::ping(9999, 0));
        }

        assert_eq!(metrics.unknown_conn_dropped(), 3);
        assert_eq!(metrics.dead_mailbox_dropped(), 0);
        assert_eq!(metrics.detached_clean_dropped(), 0);
        assert_eq!(metrics.offline_queue_evicted(), 0);
    }

    #[test]
    fn route_dead_mailbox_counts_drop_only() {
        // PERF-10: one frame into a mailbox whose receiver is gone must
        // bump exactly the dead-mailbox counter (and unregister, as
        // before), nothing else.
        let metrics = Arc::new(Metrics::new());
        let table = ConnTable::default();
        table.set_metrics(&metrics);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        table.register(7, tx);
        drop(rx);

        table.route(7, BrokerFrame::ping(7, 0));

        assert_eq!(metrics.dead_mailbox_dropped(), 1);
        assert_eq!(metrics.unknown_conn_dropped(), 0);
        assert_eq!(metrics.detached_clean_dropped(), 0);
        assert_eq!(metrics.offline_queue_evicted(), 0);
    }

    #[test]
    fn concurrent_routes_do_not_lose_frames() {
        // Eight connections spread across buckets, hammered from eight
        // threads at once: every routed frame must arrive exactly once
        // and each destination's stamps must cover 1..=N with no gaps.
        const CONNS: u64 = 8;
        const PER_CONN_PER_THREAD: usize = 100;
        const THREADS: usize = 8;
        const PER_CONN: usize = PER_CONN_PER_THREAD * THREADS;

        let table = Arc::new(ConnTable::default());
        let mut receivers = Vec::new();
        for conn_id in 0..CONNS {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            table.register(conn_id, tx);
            receivers.push((conn_id, rx));
        }

        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    for _ in 0..PER_CONN_PER_THREAD {
                        for conn_id in 0..CONNS {
                            table.route(conn_id, BrokerFrame::ping(conn_id, 0));
                        }
                    }
                });
            }
        });

        for (conn_id, mut rx) in receivers {
            let mut seqs = Vec::with_capacity(PER_CONN);
            while let Ok(frame) = rx.try_recv() {
                seqs.push(frame.header.sequence_no);
            }
            assert_eq!(seqs.len(), PER_CONN, "conn {conn_id} lost frames");
            seqs.sort_unstable();
            let expected: Vec<u64> = (1..=PER_CONN as u64).collect();
            assert_eq!(seqs, expected, "conn {conn_id} sequence gap");
            assert!(rx.try_recv().is_err());
        }
    }

    #[test]
    fn qos0_backlog_default_matches_documented_bound() {
        assert_eq!(super::DEFAULT_QOS0_BACKLOG, 1_000);
        assert_eq!(ConnTable::default().qos0_bound(), 1_000);
        assert_eq!(ConnTable::with_qos0_bound(0).qos0_bound(), 1);
        let table = ConnTable::default();
        table.set_qos0_bound(0);
        assert_eq!(table.qos0_bound(), 1);
        table.set_qos0_bound(5);
        assert_eq!(table.qos0_bound(), 5);
    }

    fn qos0_frame(conn_id: u64, payload_byte: u8) -> BrokerFrame {
        let topic = "t";
        let mut meta = Vec::with_capacity(2 + topic.len() + 5);
        meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        meta.extend_from_slice(topic.as_bytes());
        meta.extend_from_slice(&0u16.to_be_bytes());
        meta.push(0u8);
        meta.push(0u8);
        meta.push(0u8);
        BrokerFrame::new(
            brokerlink::OpCode::PublishOut,
            conn_id,
            0,
            meta,
            vec![payload_byte],
        )
        .expect("valid QoS 0 frame")
    }

    fn qos1_frame(conn_id: u64, payload_byte: u8) -> BrokerFrame {
        let topic = "t";
        let mut meta = Vec::with_capacity(2 + topic.len() + 5);
        meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        meta.extend_from_slice(topic.as_bytes());
        meta.extend_from_slice(&7u16.to_be_bytes());
        meta.push(1u8);
        meta.push(0u8);
        meta.push(0u8);
        BrokerFrame::new(
            brokerlink::OpCode::PublishOut,
            conn_id,
            0,
            meta,
            vec![payload_byte],
        )
        .expect("valid QoS 1 frame")
    }

    #[test]
    fn is_qos0_publish_out_vectors() {
        assert!(!super::is_qos0_publish_out(&BrokerFrame::ping(1, 0)));
        assert!(super::is_qos0_publish_out(&qos0_frame(1, 9)));
        assert!(!super::is_qos0_publish_out(&qos1_frame(1, 9)));
    }

    #[test]
    fn qos0_sheds_oldest_and_counts_labelled() {
        let metrics = Arc::new(Metrics::new());
        let table = ConnTable::with_qos0_bound(3);
        table.set_metrics(&metrics);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        table.register(11, tx);
        table.set_client_label(11, "slow-1");

        for byte in 0..5u8 {
            assert!(
                table.route(11, qos0_frame(11, byte)),
                "QoS 0 enqueue never fails while registered"
            );
        }
        assert_eq!(table.qos0_len(11), 3);
        let drained = table.drain_qos0(11, 10);
        let payloads: Vec<u8> = drained.iter().map(|f| f.payload[0]).collect();
        assert_eq!(
            payloads,
            vec![2, 3, 4],
            "overflow must drop oldest, keep newest in order"
        );
        assert_eq!(metrics.egress_qos0_shed(), 2);
        assert_eq!(metrics.egress_qos0_shed_for("slow-1"), 2);
        assert_eq!(metrics.unknown_conn_dropped(), 0);
        assert_eq!(metrics.dead_mailbox_dropped(), 0);
    }

    #[test]
    fn qos0_fast_alongside_stalled_keeps_receiving() {
        let metrics = Arc::new(Metrics::new());
        let table = ConnTable::with_qos0_bound(4);
        table.set_metrics(&metrics);
        let (tx_fast, _rx_fast) = tokio::sync::mpsc::unbounded_channel();
        let (tx_stalled, _rx_stalled) = tokio::sync::mpsc::unbounded_channel();
        table.register(21, tx_fast);
        table.register(22, tx_stalled);
        table.set_client_label(21, "fast");
        table.set_client_label(22, "stalled");

        let mut fast_received: Vec<u8> = Vec::new();
        for byte in 0..10u8 {
            assert!(table.route(21, qos0_frame(21, byte)));
            assert!(table.route(22, qos0_frame(22, byte)));
            // Fast drains immediately (its edge keeps up); stalled never
            // drains (its edge is gone but the mailbox stays registered).
            fast_received.extend(table.drain_qos0(21, 8).iter().map(|f| f.payload[0]));
        }
        fast_received.extend(table.drain_qos0(21, 8).iter().map(|f| f.payload[0]));
        assert_eq!(
            fast_received,
            (0..10u8).collect::<Vec<_>>(),
            "fast subscriber must see every publish in order"
        );
        assert_eq!(table.qos0_len(21), 0);
        assert_eq!(table.qos0_len(22), 4);
        let stalled: Vec<u8> = table
            .drain_qos0(22, 8)
            .iter()
            .map(|f| f.payload[0])
            .collect();
        assert_eq!(stalled, vec![6, 7, 8, 9], "stalled keeps newest");
        assert_eq!(metrics.egress_qos0_shed_for("stalled"), 6);
        assert_eq!(metrics.egress_qos0_shed_for("fast"), 0);
        assert_eq!(metrics.egress_qos0_shed(), 6);
    }

    #[test]
    fn qos0_bound_never_blocks_publisher() {
        let metrics = Arc::new(Metrics::new());
        let table = ConnTable::with_qos0_bound(16);
        table.set_metrics(&metrics);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        table.register(31, tx);
        table.set_client_label(31, "stalled-only");
        // Ten thousand synchronous enqueues to a never-drained backlog:
        // a blocking queue would hang here; the bounded drop-oldest
        // queue returns immediately every time.
        for byte in 0..10_000u32 {
            assert!(table.route(31, qos0_frame(31, (byte % 251) as u8)));
        }
        assert_eq!(table.qos0_len(31), 16);
        assert_eq!(metrics.egress_qos0_shed(), 10_000 - 16);
        assert_eq!(metrics.egress_qos0_shed_for("stalled-only"), 10_000 - 16);
    }

    #[test]
    fn qos1_never_sheds_on_qos0_pressure() {
        let metrics = Arc::new(Metrics::new());
        let table = ConnTable::with_qos0_bound(2);
        table.set_metrics(&metrics);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        table.register(41, tx);
        table.set_client_label(41, "mixed");

        for byte in 0..4u8 {
            assert!(table.route(41, qos0_frame(41, byte)));
        }
        assert_eq!(metrics.egress_qos0_shed(), 2);

        // QoS 1 rides the guaranteed mailbox even while the QoS 0
        // backlog is full: it is queued, never shed, and readable.
        assert!(table.route(41, qos1_frame(41, 99)));
        assert_eq!(
            table.qos0_len(41),
            2,
            "QoS 1 must not touch the QoS 0 backlog"
        );
        assert_eq!(metrics.egress_qos0_shed(), 2, "QoS 1 must not shed");
        let guaranteed = rx.try_recv().expect("QoS 1 via guaranteed mailbox");
        assert_eq!(guaranteed.payload[0], 99);
        assert!(rx.try_recv().is_err());
    }
}

/// Ephemeral delivery table: edge `conn_id` -> mailbox of the task owning
/// that connection (BrokerLink IPC task or dashboard WebSocket task).
/// Lets any publisher's task deliver `PublishOut` frames to a subscriber
/// served by a different task. Shared by `broker-node` and `broker-api`
/// so both transports fan out through one directory.
///
/// Sharded into per-bucket locks so fan-out to different connections
/// does not serialize on one global mutex: each `conn_id` maps to
/// exactly one bucket and every operation locks only that bucket
/// (`prune_sender` visits each bucket in turn, never holding more than
/// one at a time).
#[derive(Debug)]
pub struct ConnTable {
    shards: [Mutex<HashMap<u64, ConnSlot>>; NUM_SHARDS],
    /// PERF-10 silent-drop accounting. Set once by the owning kernel
    /// (`set_metrics`); a table without metrics (tests, API transports
    /// that never wire one) routes exactly as before, only uncounted.
    /// `OnceLock` keeps the hot path to one atomic load: no per-route
    /// lock, no behaviour change when unset.
    metrics: std::sync::OnceLock<Arc<Metrics>>,
    /// Per-subscriber QoS 0 backlog bound (D1-02). Read on every
    /// `route_qos0` via one relaxed atomic load; writers use
    /// [`ConnTable::set_qos0_bound`]. Floored at 1 on read so a zero
    /// can never wedge a subscriber.
    qos0_bound: AtomicUsize,
    /// Signalled (via `notify_one`, which stores a permit when no task
    /// is waiting) on every QoS 0 enqueue so an idle edge task draining
    /// [`ConnTable::pop_qos0`] never sleeps through a backlog when its
    /// `rx` (guaranteed traffic) is empty. Transports also drain
    /// opportunistically after every inbound frame, so a notification
    /// that lands while the owner is busy still arrives promptly.
    qos0_notify: Arc<Notify>,
}

/// Number of `ConnTable` buckets. A power of two so the bucket mapping
/// stays a cheap modulo; large enough that concurrent fan-out rarely
/// collides on one bucket.
const NUM_SHARDS: usize = 16;

impl Default for ConnTable {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            metrics: std::sync::OnceLock::new(),
            qos0_bound: AtomicUsize::new(DEFAULT_QOS0_BACKLOG),
            qos0_notify: Arc::new(Notify::new()),
        }
    }
}

impl ConnTable {
    /// Create a table with an explicit QoS 0 backlog bound (floored at
    /// 1; see [`DEFAULT_QOS0_BACKLOG`] for the documented default).
    pub fn with_qos0_bound(bound: usize) -> Self {
        let table = Self::default();
        table.set_qos0_bound(bound);
        table
    }
}

#[derive(Debug)]
struct ConnSlot {
    tx: UnboundedSender<BrokerFrame>,
    /// Next `sequence_no` for frames routed to this connection. Starts at
    /// 1; direct replies (Pong, SessionBinding, SubAck, PubAck) mirror the
    /// request sequence instead. Shared by the guaranteed (`route`) and
    /// QoS 0 (`route_qos0`) paths so per-destination order stays total.
    next_seq: AtomicU64,
    /// Bounded QoS 0 backlog for this subscriber (D1-02). Guaranteed
    /// traffic (QoS 1/2, acks, control) never enters here: it rides
    /// `tx` exactly as before. Only QoS 0 pushes here and only
    /// `pop_qos0`/`drain_qos0` pops, so the queue length is the live
    /// outstanding QoS 0 for this connection.
    qos0: Mutex<VecDeque<BrokerFrame>>,
    /// Client id owning this connection, for per-client shed labels.
    /// Set by [`ConnTable::set_client_label`] on bind; `route` falls
    /// back to the global shed counter alone when unset (tests that
    /// never bind still count every drop).
    client: RwLock<Option<Arc<str>>>,
    /// Per-transport wakeup for QoS 0 arrivals (D1-02). The owning edge
    /// task sets its own [`Notify`] via [`ConnTable::set_waker`] on
    /// bind; `route`/`route_qos0` signal exactly this task
    /// (`notify_one`, permit-storing) so a QoS 0 burst never wakes the
    /// wrong transport while its owner sleeps. Unset (tests that drain
    /// manually) means no directed wakeup; the global
    /// [`ConnTable::qos0_notify`] still fires.
    waker: RwLock<Option<Arc<Notify>>>,
}

impl ConnTable {
    /// Owning bucket for `conn_id`. `conn_id`s are ephemeral edge
    /// handles that increase over time, so the identity modulo spreads
    /// neighbours across buckets.
    fn shard(&self, conn_id: u64) -> &Mutex<HashMap<u64, ConnSlot>> {
        &self.shards[(conn_id as usize) % NUM_SHARDS]
    }

    /// Attach the kernel [`Metrics`] for silent-drop accounting. The
    /// first call wins; later calls are ignored so a shared table
    /// cannot be rewired mid-flight.
    pub fn set_metrics(&self, metrics: &Arc<Metrics>) {
        let _ = self.metrics.set(metrics.clone());
    }

    pub fn register(&self, conn_id: u64, tx: UnboundedSender<BrokerFrame>) {
        self.shard(conn_id).lock().insert(
            conn_id,
            ConnSlot {
                tx,
                next_seq: AtomicU64::new(1),
                qos0: Mutex::new(VecDeque::new()),
                client: RwLock::new(None),
                waker: RwLock::new(None),
            },
        );
    }

    /// Remember which client owns `conn_id` for per-client shed labels.
    /// Called on bind/connect after [`ConnTable::register`]; re-binds
    /// overwrite. Unknown connections are ignored. Never blocks the
    /// matching path: one short shard read plus one short slot write.
    pub fn set_client_label(&self, conn_id: u64, client_id: &str) {
        let shard = self.shard(conn_id).lock();
        if let Some(slot) = shard.get(&conn_id) {
            *slot.client.write() = Some(Arc::<str>::from(client_id));
        }
    }

    /// Remember which edge task owns `conn_id` for directed QoS 0
    /// wakeups. Called on bind/connect after [`ConnTable::register`]
    /// with the task's own [`Notify`]; re-binds overwrite. Unknown
    /// connections are ignored. The task waits on its own `Notify`
    /// alongside its guaranteed `rx`, so a QoS 0 burst wakes exactly
    /// its owner (permit-storing `notify_one`, never lost) and never
    /// the wrong transport.
    pub fn set_waker(&self, conn_id: u64, waker: &Arc<Notify>) {
        let shard = self.shard(conn_id).lock();
        if let Some(slot) = shard.get(&conn_id) {
            *slot.waker.write() = Some(waker.clone());
        }
    }

    /// Configured QoS 0 backlog bound (floored at 1 on write).
    pub fn qos0_bound(&self) -> usize {
        self.qos0_bound.load(Ordering::Relaxed).max(1)
    }

    /// Override the QoS 0 backlog bound (floored at 1; huge values have
    /// no ceiling). Takes effect on the very next `route_qos0`.
    pub fn set_qos0_bound(&self, bound: usize) {
        self.qos0_bound.store(bound.max(1), Ordering::Relaxed);
    }

    /// Wakeup signalled on every QoS 0 enqueue. Edge tasks wait on this
    /// alongside their guaranteed `rx` so a QoS-0-only burst never
    /// sleeps through draining.
    pub fn qos0_notify(&self) -> Arc<Notify> {
        self.qos0_notify.clone()
    }

    /// Queued QoS 0 frames for `conn_id` (0 when unknown). Test and
    /// drain-loop hook; never blocks.
    pub fn qos0_len(&self, conn_id: u64) -> usize {
        let shard = self.shard(conn_id).lock();
        shard
            .get(&conn_id)
            .map(|slot| slot.qos0.lock().len())
            .unwrap_or(0)
    }

    /// Pop one queued QoS 0 frame for `conn_id`, oldest-first. Returns
    /// `None` when the backlog is empty or the destination is unknown.
    /// Never blocks; the caller retries after [`ConnTable::qos0_notify`].
    pub fn pop_qos0(&self, conn_id: u64) -> Option<BrokerFrame> {
        let shard = self.shard(conn_id).lock();
        shard
            .get(&conn_id)
            .and_then(|slot| slot.qos0.lock().pop_front())
    }

    /// Drain up to `max_frames` queued QoS 0 frames for `conn_id`,
    /// oldest-first. Returns empty when the backlog is empty or the
    /// destination is unknown. Never blocks.
    pub fn drain_qos0(&self, conn_id: u64, max_frames: usize) -> Vec<BrokerFrame> {
        let shard = self.shard(conn_id).lock();
        let Some(slot) = shard.get(&conn_id) else {
            return Vec::new();
        };
        let mut queue = slot.qos0.lock();
        let take = max_frames.min(queue.len());
        queue.drain(..take).collect()
    }

    /// Drain up to `max_frames` QoS 0 frames for `conn_id` within
    /// `max_bytes` of encoded size, oldest-first. A single frame larger
    /// than the whole budget still drains alone so a large payload can
    /// never wedge its connection. Never blocks.
    pub fn drain_qos0_with_budget(
        &self,
        conn_id: u64,
        max_frames: usize,
        max_bytes: usize,
    ) -> Vec<BrokerFrame> {
        let shard = self.shard(conn_id).lock();
        let Some(slot) = shard.get(&conn_id) else {
            return Vec::new();
        };
        let mut queue = slot.qos0.lock();
        let mut out = Vec::new();
        let mut out_bytes = 0usize;
        while out.len() < max_frames && !queue.is_empty() {
            let front_len = queue
                .front()
                .map(|frame| frame.total_frame_len())
                .unwrap_or(0);
            if out_bytes + front_len > max_bytes && !out.is_empty() {
                break;
            }
            if let Some(frame) = queue.pop_front() {
                out_bytes += front_len;
                out.push(frame);
                if out_bytes >= max_bytes {
                    break;
                }
            } else {
                break;
            }
        }
        out
    }

    /// Enqueue one QoS 0 `PublishOut` for `conn_id` on the bounded
    /// per-subscriber backlog (D1-02). Stamps the per-destination
    /// sequence number from the same counter as [`ConnTable::route`] so
    /// order stays total per connection.
    ///
    /// When the backlog is full the oldest queued QoS 0 frame drops to
    /// make room (counted once via `egress_qos0_shed` plus once under
    /// `client_id`); the newest frame is always kept and the connection
    /// is never dropped. QoS 1/2 and non-`PublishOut` frames must use
    /// [`ConnTable::route`]: if one arrives here it bypasses shedding
    /// and queues without bound so guarantees can never be shed by
    /// misuse. Unknown destinations count `unknown_conn_dropped` and
    /// return false, exactly like `route`.
    ///
    /// Never blocks and never awaits: publishers pay one shard lock
    /// plus one short queue lock, so a stalled subscriber cannot slow
    /// the publish path.
    pub fn route_qos0(&self, conn_id: u64, client_id: &str, mut frame: BrokerFrame) -> bool {
        let (shed, waker): (u64, Option<Arc<Notify>>) = {
            let shard = self.shard(conn_id).lock();
            let Some(slot) = shard.get(&conn_id) else {
                drop(shard);
                if let Some(metrics) = self.metrics.get() {
                    metrics.inc_unknown_conn_dropped();
                }
                return false;
            };
            let seq = slot.next_seq.fetch_add(1, Ordering::Relaxed);
            frame.header.sequence_no = seq;
            if !is_qos0_publish_out(&frame) {
                let tx = slot.tx.clone();
                drop(shard);
                if tx.send(frame).is_ok() {
                    return true;
                }
                self.unregister(conn_id);
                if let Some(metrics) = self.metrics.get() {
                    metrics.inc_dead_mailbox_dropped();
                }
                return false;
            }
            let bound = self.qos0_bound.load(Ordering::Relaxed).max(1);
            let mut queue = slot.qos0.lock();
            let mut dropped = 0u64;
            while queue.len() >= bound {
                if queue.pop_front().is_some() {
                    dropped += 1;
                } else {
                    break;
                }
            }
            queue.push_back(frame);
            let waker = slot.waker.read().clone();
            (dropped, waker)
        };
        if shed > 0 {
            if let Some(metrics) = self.metrics.get() {
                for _ in 0..shed {
                    metrics.inc_egress_qos0_shed_for(client_id);
                }
            }
        }
        if let Some(waker) = waker {
            waker.notify_one();
        }
        self.qos0_notify.notify_one();
        true
    }

    pub fn unregister(&self, conn_id: u64) {
        self.shard(conn_id).lock().remove(&conn_id);
    }

    /// Remove every entry owned by a dead task (its sender is unique per
    /// connection task, so channel identity is a safe ownership test).
    /// Visits one bucket at a time so concurrent `route` calls to other
    /// buckets are never blocked on a whole-table lock.
    pub fn prune_sender(&self, tx: &UnboundedSender<BrokerFrame>) {
        for shard in &self.shards {
            shard.lock().retain(|_, slot| !slot.tx.same_channel(tx));
        }
    }

    /// Deliver one frame to a connection, stamping a per-destination
    /// sequence number. Returns true when the frame reached a live
    /// mailbox, false when the destination is unknown or its task is
    /// gone (the frame is dropped and the dead destination pruned).
    /// Callers must only count deliveries on true: a false return is a
    /// real loss (QoS 1 has no retry yet), never a successful delivery.
    /// The stamp orders frames per destination only, so `Relaxed` is
    /// sufficient; it is never used for cross-connection synchronization.
    ///
    /// PERF-10: each silent drop also bumps its kernel counter (unknown
    /// destination vs. dead mailbox) exactly where the frame is
    /// discarded. Drops that happened before still happen. Callers must
    /// not bump those counters themselves: one undeliverable frame
    /// increments exactly one counter by exactly one, inside this method.
    ///
    /// D1-02: QoS 0 `PublishOut` frames ride the bounded per-subscriber
    /// backlog instead of the unbounded mailbox. When the backlog is
    /// full the oldest queued QoS 0 frame drops (counted via
    /// `egress_qos0_shed`, labelled by the stored client when
    /// [`ConnTable::set_client_label`] ran on bind); the newest frame is
    /// always kept, the connection is never dropped, and this method
    /// never blocks, so publishers never stall on a slow subscriber.
    /// QoS 1/2 and control frames keep the existing guaranteed path and
    /// are never shed.
    pub fn route(&self, conn_id: u64, mut frame: BrokerFrame) -> bool {
        if is_qos0_publish_out(&frame) {
            let (shed, label, waker): (u64, Option<Arc<str>>, Option<Arc<Notify>>) = {
                let shard = self.shard(conn_id).lock();
                let Some(slot) = shard.get(&conn_id) else {
                    drop(shard);
                    if let Some(metrics) = self.metrics.get() {
                        metrics.inc_unknown_conn_dropped();
                    }
                    return false;
                };
                let seq = slot.next_seq.fetch_add(1, Ordering::Relaxed);
                frame.header.sequence_no = seq;
                let bound = self.qos0_bound.load(Ordering::Relaxed).max(1);
                let mut queue = slot.qos0.lock();
                let mut dropped = 0u64;
                while queue.len() >= bound {
                    if queue.pop_front().is_some() {
                        dropped += 1;
                    } else {
                        break;
                    }
                }
                queue.push_back(frame);
                let label = slot.client.read().clone();
                let waker = slot.waker.read().clone();
                (dropped, label, waker)
            };
            if shed > 0 {
                if let Some(metrics) = self.metrics.get() {
                    match &label {
                        Some(client) => {
                            for _ in 0..shed {
                                metrics.inc_egress_qos0_shed_for(client);
                            }
                        }
                        None => {
                            for _ in 0..shed {
                                metrics.inc_egress_qos0_shed();
                            }
                        }
                    }
                }
            }
            if let Some(waker) = waker {
                waker.notify_one();
            }
            self.qos0_notify.notify_one();
            return true;
        }
        let tx = {
            let shard = self.shard(conn_id).lock();
            shard.get(&conn_id).map(|slot| {
                let seq = slot.next_seq.fetch_add(1, Ordering::Relaxed);
                frame.header.sequence_no = seq;
                slot.tx.clone()
            })
        };
        if let Some(tx) = tx {
            if tx.send(frame).is_ok() {
                return true;
            }
            self.unregister(conn_id);
            if let Some(metrics) = self.metrics.get() {
                metrics.inc_dead_mailbox_dropped();
            }
        } else if let Some(metrics) = self.metrics.get() {
            metrics.inc_unknown_conn_dropped();
        }
        false
    }
}
