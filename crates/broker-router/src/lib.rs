use ahash::{AHashMap, AHashSet};
use broker_protocol::{QoS, Topic, TopicFilter};
use parking_lot::RwLock;
use std::sync::Arc;

/// One client's subscription. `client_id` is reference-counted so fan-out
/// matching clones pointers instead of heap strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Subscription {
    pub client_id: Arc<str>,
    /// Ephemeral edge connection owning this subscription copy. A
    /// re-subscribe from a new connection replaces the entry, so at most
    /// one `conn_id` per `(filter node, client_id)` exists.
    pub conn_id: u64,
    pub qos: QoS,
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
        matched
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

        let sub1 = Subscription {
            client_id: "c1".into(),
            conn_id: 101,
            qos: QoS::AtMostOnce,
        };
        let sub2 = Subscription {
            client_id: "c2".into(),
            conn_id: 102,
            qos: QoS::AtLeastOnce,
        };
        let sub3 = Subscription {
            client_id: "c3".into(),
            conn_id: 103,
            qos: QoS::ExactlyOnce,
        };

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
            Subscription {
                client_id: "c1".into(),
                conn_id: 101,
                qos: QoS::AtMostOnce,
            },
        );
        router.subscribe(
            &filter,
            Subscription {
                client_id: "c1".into(),
                conn_id: 202,
                qos: QoS::AtLeastOnce,
            },
        );

        let matches = router.matches(&Topic::new("sports/tennis").unwrap());
        assert_eq!(matches.len(), 1);
        let only = matches.iter().next().unwrap();
        assert_eq!(only.conn_id, 202);
        assert_eq!(only.qos, QoS::AtLeastOnce);
    }
}
