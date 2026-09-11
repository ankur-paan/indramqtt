use ahash::{AHashMap, AHashSet};
use broker_protocol::{QoS, Topic, TopicFilter};
use brokerlink::BrokerFrame;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

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

pub struct Router {
    root: RwLock<TrieNode>,
    /// Round-robin cursors per shared-subscription group. Mutated under
    /// `matches`, hence behind the lock; keyed by group name alone so one
    /// group balances across all its filters.
    rr_cursors: RwLock<AHashMap<Arc<str>, usize>>,
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
        }
    }

    pub fn subscribe(&self, filter: &TopicFilter, sub: Subscription) {
        let mut root = self.root.write();
        let mut curr = &mut *root;
        // Peekable so the terminal level is known without collecting.
        let mut levels = filter.as_str().split('/').peekable();

        while let Some(level) = levels.next() {
            if level == "#" {
                // Re-subscribing from a new connection replaces the old copy.
                curr.multi_wildcard_subs.retain(|s| s.client_id != sub.client_id);
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
                curr.multi_wildcard_subs.retain(|s| s.client_id.as_ref() != client_id);
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
                curr.exact_subs.retain(|s| s.client_id.as_ref() != client_id);
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

        router.subscribe(
            &filter,
            Subscription::new("c1", 101, QoS::AtMostOnce),
        );
        router.subscribe(
            &filter,
            Subscription::new("c1", 202, QoS::AtLeastOnce),
        );

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
        router.subscribe(&inner, Subscription::shared("worker-a", 1, QoS::AtMostOnce, "group1"));
        router.subscribe(&inner, Subscription::shared("worker-b", 2, QoS::AtMostOnce, "group1"));

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
            vec!["worker-a".to_string(), "worker-b".to_string(),
                 "worker-a".to_string(), "worker-b".to_string()]
        );
    }

    #[test]
    fn test_shared_and_plain_subscribers_coexist() {
        let router = Router::new();
        let inner = TopicFilter::new("jobs/+").unwrap();
        router.subscribe(&inner, Subscription::shared("worker-a", 1, QoS::AtMostOnce, "pool"));
        router.subscribe(&inner, Subscription::shared("worker-b", 2, QoS::AtMostOnce, "pool"));
        router.subscribe(
            &TopicFilter::new("jobs/+").unwrap(),
            Subscription::new("plain-c", 3, QoS::AtMostOnce),
        );

        // Plain subscriber always present; exactly one group member joins.
        for _ in 0..4 {
            let matched = router.matches(&Topic::new("jobs/9").unwrap());
            assert_eq!(matched.len(), 2);
            assert!(matched.iter().any(|s| s.client_id.as_ref() == "plain-c"));
            assert_eq!(
                matched.iter().filter(|s| s.group.is_some()).count(),
                1
            );
        }
    }

    #[test]
    fn test_shared_unsubscribe_removes_member() {
        let router = Router::new();
        let inner = TopicFilter::new("tasks").unwrap();
        router.subscribe(&inner, Subscription::shared("worker-a", 1, QoS::AtMostOnce, "group1"));
        router.subscribe(&inner, Subscription::shared("worker-b", 2, QoS::AtMostOnce, "group1"));

        router.unsubscribe(&inner, "worker-a");
        for _ in 0..3 {
            let matched = router.matches(&Topic::new("tasks").unwrap());
            assert_eq!(matched.len(), 1);
            assert_eq!(matched.iter().next().unwrap().client_id.as_ref(), "worker-b");
        }
    }
}

/// Ephemeral delivery table: edge `conn_id` -> mailbox of the task owning
/// that connection (BrokerLink IPC task or dashboard WebSocket task).
/// Lets any publisher's task deliver `PublishOut` frames to a subscriber
/// served by a different task. Shared by `broker-node` and `broker-api`
/// so both transports fan out through one directory.
#[derive(Debug, Default)]
pub struct ConnTable {
    inner: Mutex<HashMap<u64, ConnSlot>>,
}

#[derive(Debug)]
struct ConnSlot {
    tx: UnboundedSender<BrokerFrame>,
    /// Next `sequence_no` for frames routed to this connection. Starts at
    /// 1; direct replies (Pong, SessionBinding, SubAck, PubAck) mirror the
    /// request sequence instead.
    next_seq: AtomicU64,
}

impl ConnTable {
    pub fn register(&self, conn_id: u64, tx: UnboundedSender<BrokerFrame>) {
        self.inner.lock().insert(
            conn_id,
            ConnSlot {
                tx,
                next_seq: AtomicU64::new(1),
            },
        );
    }

    pub fn unregister(&self, conn_id: u64) {
        self.inner.lock().remove(&conn_id);
    }

    /// Remove every entry owned by a dead task (its sender is unique per
    /// connection task, so channel identity is a safe ownership test).
    pub fn prune_sender(&self, tx: &UnboundedSender<BrokerFrame>) {
        self.inner
            .lock()
            .retain(|_, slot| !slot.tx.same_channel(tx));
    }

    /// Deliver one frame to a connection, stamping a per-destination
    /// sequence number. Drops (and forgets) dead destinations.
    pub fn route(&self, conn_id: u64, mut frame: BrokerFrame) {
        let tx = self.inner.lock().get(&conn_id).map(|slot| {
            let seq = slot.next_seq.fetch_add(1, Ordering::SeqCst);
            frame.header.sequence_no = seq;
            slot.tx.clone()
        });
        if let Some(tx) = tx {
            if tx.send(frame).is_err() {
                self.unregister(conn_id);
            }
        }
    }
}
