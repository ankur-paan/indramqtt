use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
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

/// Maximum ordered topic-rewrite rules held by one router (B4-04).
///
/// Each rule is one precompiled regex plus a short replacement string
/// (tens of KB worst case per rule), so 64 caps the table in the low
/// hundreds of KB. Rationale: deployments carry tens of rules at most;
/// past 64 the configuration is almost certainly generated in a loop,
/// and rejecting it fail-closed protects the per-message evaluation
/// budget below. Set once on the config plane; the publish path only
/// takes a read lock over the table.
pub const MAX_REWRITE_RULES: usize = 64;

/// Maximum bytes of one rewrite input or output (B4-04).
///
/// Matches the on-the-wire topic length field (u16), so any concrete
/// topic or filter that can reach the router fits, and no replacement
/// can grow a name past what the protocol can carry. Inputs past this
/// length fail closed to no-rewrite with the budget counter bumped;
/// replacements that would exceed it fail the same way, never truncating.
pub const MAX_REWRITE_LEN: usize = u16::MAX as usize;

/// Per-direction scope of one rewrite rule (B4-04): publish ingress,
/// subscribe filters, or both. Stored per rule and honoured in
/// configuration order; a rule never fires outside its scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RewriteScope {
    /// Fire on publish topics and subscribe filters alike.
    #[default]
    Both,
    /// Fire on publish topics only.
    Publish,
    /// Fire on subscribe filters only.
    Subscribe,
}

/// Documented scope names accepted by [`RewriteScope::parse`].
pub const VALID_REWRITE_SCOPES: &[&str] = &["publish", "subscribe", "both"];

/// Errors for topic-rewrite configuration (B4-04). Every variant names
/// the value at fault; the table is unchanged when configuration fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RewriteRuleError {
    /// More rules than [`MAX_REWRITE_RULES`].
    #[error("too many topic-rewrite rules (cap {0}) (field `rules`)")]
    TooManyRules(usize),
    /// The pattern does not compile.
    #[error(
        "invalid topic-rewrite pattern {0:?}: not a valid regular expression (field `pattern`)"
    )]
    InvalidPattern(String),
    /// The pattern was empty.
    #[error("topic-rewrite pattern must not be empty (field `pattern`)")]
    EmptyPattern,
    /// The replacement alone already exceeds [`MAX_REWRITE_LEN`].
    #[error("topic-rewrite replacement exceeds {0} bytes (field `replacement`)")]
    ReplacementTooLong(usize),
}

impl RewriteScope {
    /// Parse a documented scope name (case-insensitive, trimmed).
    /// Unknown names return `None` so callers fail closed instead of
    /// guessing a direction.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "publish" | "pub" => Some(Self::Publish),
            "subscribe" | "sub" => Some(Self::Subscribe),
            "both" | "all" => Some(Self::Both),
            _ => None,
        }
    }

    /// Canonical documented name for this scope.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Publish => "publish",
            Self::Subscribe => "subscribe",
        }
    }

    /// True when this rule fires on the publish path.
    #[must_use]
    pub fn applies_to_publish(self) -> bool {
        matches!(self, Self::Publish | Self::Both)
    }

    /// True when this rule fires on the subscribe path.
    #[must_use]
    pub fn applies_to_subscribe(self) -> bool {
        matches!(self, Self::Subscribe | Self::Both)
    }
}

/// One topic-rewrite rule as configured (B4-04): a regex pattern with a
/// capture-group replacement (`$1`, `${name}`) plus the direction it
/// fires in. Compiled once by [`Router::set_rewrite_rules`]; the
/// per-message path never compiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteRuleConfig {
    /// Regular expression matched against the whole topic or filter.
    pub pattern: String,
    /// Replacement with `$1`-style capture references.
    pub replacement: String,
    /// Direction this rule fires in.
    pub scope: RewriteScope,
}

impl RewriteRuleConfig {
    /// Build one rule. Empty patterns are rejected later by
    /// [`Router::set_rewrite_rules`] with [`RewriteRuleError::EmptyPattern`].
    pub fn new(
        pattern: impl Into<String>,
        replacement: impl Into<String>,
        scope: RewriteScope,
    ) -> Self {
        Self {
            pattern: pattern.into(),
            replacement: replacement.into(),
            scope,
        }
    }
}

/// One compiled rewrite rule: the configured strings plus the regex
/// built once at configuration time. The match path borrows these;
/// nothing here is rebuilt per message.
#[derive(Debug)]
struct CompiledRewriteRule {
    scope: RewriteScope,
    replacement: String,
    regex: regex::Regex,
}

/// Snapshot of the rewrite counters for operators and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RewriteStats {
    /// Rules currently installed (configuration order = evaluation order).
    pub rules: usize,
    /// Messages rewritten (first matching rule applied).
    pub rewritten: u64,
    /// Messages that matched nothing and passed through unchanged.
    pub passthrough: u64,
    /// Messages left unchanged because an input or output exceeded
    /// [`MAX_REWRITE_LEN`] (fail closed, never stalled or truncated).
    pub budget_exceeded: u64,
}

/// Per-group shared-subscription dispatch strategy (B4-02).
///
/// Documented names (read from group configuration, never invented per
/// message): `round_robin` (the default when a group has no entry),
/// `random`, `hash_clientid` (stable member per publisher id),
/// `hash_topic` (stable member per concrete publish topic) and `sticky`
/// (pinned member while the membership is stable). An unknown name is
/// rejected by [`SharedStrategy::parse`] with [`SharedStrategyError`],
/// never silently mapped to round-robin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SharedStrategy {
    /// Cycle across members in deterministic client-id order.
    #[default]
    RoundRobin,
    /// Uniform pick across members on every delivery.
    Random,
    /// Stable member per publisher client id (`hash_clientid`).
    HashClientId,
    /// Stable member per concrete publish topic (`hash_topic`).
    HashTopic,
    /// Pinned member while the membership is stable (see
    /// [`Router::set_shared_strategy`] for the rebalance rule).
    Sticky,
}

/// Documented strategy names accepted by [`SharedStrategy::parse`].
pub const VALID_SHARED_STRATEGIES: &[&str] = &[
    "round_robin",
    "random",
    "hash_clientid",
    "hash_topic",
    "sticky",
];

/// Errors for shared-subscription group configuration (B4-02). Every
/// variant names the field or value at fault; unknown strategy names
/// list the documented set so callers can surface the message as-is.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SharedStrategyError {
    /// The strategy name is not one of [`VALID_SHARED_STRATEGIES`].
    #[error(
        "unknown shared-subscription strategy {0:?}: expected one of round_robin, random, hash_clientid, hash_topic, sticky (field `strategy`)"
    )]
    Unknown(String),
    /// The group name was empty.
    #[error("shared-subscription group name must not be empty (field `group`)")]
    EmptyGroup,
    /// The group configuration table is full.
    #[error("too many shared-subscription groups (cap {0}) (field `group`)")]
    TooManyGroups(usize),
}

impl SharedStrategy {
    /// Parse a documented strategy name (case-insensitive, trimmed).
    /// Unknown names return [`SharedStrategyError::Unknown`].
    pub fn parse(name: &str) -> Result<Self, SharedStrategyError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "round_robin" | "round-robin" | "roundrobin" => Ok(Self::RoundRobin),
            "random" => Ok(Self::Random),
            "hash_clientid" | "hash-clientid" | "hash-client-id" => Ok(Self::HashClientId),
            "hash_topic" | "hash-topic" => Ok(Self::HashTopic),
            "sticky" => Ok(Self::Sticky),
            other => Err(SharedStrategyError::Unknown(other.to_string())),
        }
    }

    /// Canonical documented name for this strategy.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::Random => "random",
            Self::HashClientId => "hash_clientid",
            Self::HashTopic => "hash_topic",
            Self::Sticky => "sticky",
        }
    }
}

/// Maximum shared-subscription groups with live per-message delivery
/// state (round-robin cursors plus sticky affinity entries, B4-02).
///
/// Each entry is one map slot plus a small value, so the table costs a
/// few tens of bytes per group and stays in the low tens of KB at the
/// cap. Rationale: 1,024 matches the detached offline bound
/// (`MAX_OFFLINE_QUEUE` = 1024) so group state shares one memory story
/// with the existing per-subscriber queues; a deployment with more than
/// a thousand live shared groups at once is a configuration problem, not
/// a routing problem, and the eviction rule below keeps delivery working
/// while bounding memory.
///
/// Eviction rule (documented): cursors and affinity entries are keyed by
/// group name alone. When a delivery arrives for a group with no entry
/// and the table is full, one arbitrary existing entry (the first key in
/// iteration order) is evicted to make room. The evicted group's next
/// delivery re-creates its entry from scratch (round-robin restarts at
/// zero, sticky re-picks deterministically), so eviction costs at most
/// one rotation step, never a drop.
pub const MAX_SHARED_GROUPS: usize = 1_024;

/// FNV-1a 64-bit hash over a string. Deterministic across runs (unlike
/// the randomised per-process hashers), allocation-free, and cheap
/// enough for the match path. Used for `hash_clientid`, `hash_topic`,
/// sticky fingerprints and sticky initial picks.
fn fnv1a64(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Fingerprint of a sorted member set for sticky stability checks:
/// FNV-1a folded over each member client id with a separator so
/// `["ab", "c"]` and `["a", "bc"]` never collide. `members` must
/// already be sorted by client id. O(members), no allocation.
fn fingerprint_members(members: &[Subscription]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for member in members {
        for byte in member.client_id.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Sticky affinity entry: the pinned member plus the membership
/// fingerprint it was picked for. While the fingerprint is unchanged
/// the pinned member serves every delivery; any join or leave changes
/// the fingerprint and triggers a deterministic re-pick.
#[derive(Debug, Clone)]
struct StickyEntry {
    pinned: Arc<str>,
    fingerprint: u64,
}

#[derive(Default, Clone)]
struct TrieNode {
    // Exact child path segments. Children are `Arc`-shared so a writer's
    // shallow `clone()` of a node shares every unchanged subtree and only
    // the nodes on the mutated filter path are replaced (B4-08 path
    // copy). Readers never clone here: the match walk borrows.
    children: AHashMap<Arc<str>, Arc<TrieNode>>,
    // Single-level wildcard '+' child, shared the same way.
    single_wildcard: Option<Arc<TrieNode>>,
    // Multi-level wildcard '#' subscriptions at this level
    multi_wildcard_subs: SubscriptionSet,
    // Exact subscriptions attached at this terminal node
    exact_subs: SubscriptionSet,
}

/// Maximum live subscription entries held by one router trie (B4-08).
///
/// Each entry is one `Subscription` set slot (client id and group are
/// shared `Arc<str>` pointers, so tens of bytes plus the set overhead),
/// and each distinct filter path costs one node per level. At the cap the
/// steady trie costs low tens of MB, and a writer's path copy clones only
/// the nodes on one filter path (depth bounded by the filter byte length,
/// one map clone per level sharing every unchanged child `Arc`), so the
/// transient is one extra path, never a second whole trie.
///
/// Rationale: 100 000 matches [`MAX_KNOWN_TOPICS`] so the subscription
/// trie shares one memory story with the existing topic index; the B4-08
/// storm settles 10 000 subscriptions, so the cap leaves 10x headroom for
/// that workload while keeping a subscribe storm from growing the trie
/// without limit. Past the cap a new `(filter, client)` entry is denied
/// (fail closed, delivery of existing subscriptions proceeds); a
/// re-subscribe that replaces the same client's entry always succeeds and
/// an unsubscribe always succeeds.
pub const MAX_SUBSCRIPTIONS: usize = 100_000;

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
/// QoS:8 | Retain:8 | Dup:8`, optionally followed by the B4-05 alias
/// section `Alias:16be`; anything unparseable is not QoS 0 so a
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
    let old_len = 2 + topic_len + 5;
    if meta.len() != old_len && meta.len() != old_len + 2 {
        return false;
    }
    meta[2 + topic_len + 2] == 0
}

/// Shards for per-group shared-subscription delivery state (B4-08).
/// One group maps to exactly one shard, so deliveries for different
/// groups never contend on the same lock. Each shard is bounded
/// independently (see [`MAX_SHARED_GROUPS_PER_SHARD`]); the global table
/// stays within [`MAX_SHARED_GROUPS`] by construction.
///
/// Rationale for 32: the pipeline runs the B4-08 storm on an 8-core host
/// with 8 concurrent match threads (`NUM_READERS = 8` in
/// `crates/broker-router/tests/contention_bench.rs`), so 32 shards is 4x
/// the observed delivery parallelism and distinct groups rarely share a
/// shard; a power of two keeps the FNV-1a modulo on the match path to one
/// multiply-free mask-style remainder, and 32 shard headers cost only a
/// few KB while each shard caps at 32 groups (1024 / 32) so per-shard
/// eviction scans stay short.
const NUM_GROUP_SHARDS: usize = 32;

/// Per-shard cap implied by [`MAX_SHARED_GROUPS`] over
/// [`NUM_GROUP_SHARDS`] shards (1024 / 32 = 32). A shard that is full
/// evicts one arbitrary entry in that same shard to make room; the
/// evicted group's next delivery re-creates its entry from scratch, so
/// eviction costs at most one rotation step, never a drop.
const MAX_SHARED_GROUPS_PER_SHARD: usize = MAX_SHARED_GROUPS / NUM_GROUP_SHARDS;

/// Sharded round-robin cursors: one atomic counter per group, striped so
/// the match path never takes a global lock. Reads hit one shard's read
/// lock to fetch the counter; only a missing group takes that shard's
/// write lock. Increments are lock-free relaxed `fetch_add`s.
struct ShardedCursors {
    shards: [RwLock<AHashMap<Arc<str>, AtomicUsize>>; NUM_GROUP_SHARDS],
}

impl Default for ShardedCursors {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| RwLock::new(AHashMap::new())),
        }
    }
}

/// Sharded sticky affinity: one [`StickyEntry`] per group, striped the
/// same way as the cursors. A delivery locks only its own group's shard
/// (read first, write only on a miss or membership change).
struct ShardedSticky {
    shards: [RwLock<AHashMap<Arc<str>, StickyEntry>>; NUM_GROUP_SHARDS],
}

impl Default for ShardedSticky {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| RwLock::new(AHashMap::new())),
        }
    }
}

/// Shard owning `group`: FNV-1a of the name modulo the shard count.
/// Deterministic, allocation-free, stable across calls.
fn group_shard(group: &str) -> usize {
    (fnv1a64(group) as usize) % NUM_GROUP_SHARDS
}

pub struct Router {
    /// Copy-on-write subscription trie (B4-08) with structural sharing.
    /// Readers load a snapshot with one lock-free `ArcSwap` load and
    /// match without holding any trie lock, so a subscribe storm never
    /// blocks the fan-out path; the worst reader wait is a single pointer
    /// load plus a refcount bump. Writers serialize on `trie_write`,
    /// shallow-clone the snapshot (child subtrees stay shared `Arc`s),
    /// copy only the nodes on the mutated filter path, and store the new
    /// root atomically. Steady state holds one trie; transiently (inside
    /// one writer critical section) the old root plus one new path whose
    /// depth is bounded by the filter byte length. Live entries are
    /// bounded by [`MAX_SUBSCRIPTIONS`].
    root: ArcSwap<TrieNode>,
    /// Serializes copy-on-write trie writers. Readers never take it.
    trie_write: Mutex<()>,
    /// Live subscription entries in the trie, bounded by
    /// [`MAX_SUBSCRIPTIONS`]. Updated only under `trie_write`, read
    /// lock-free. A re-subscribe that replaces the same client's entry
    /// does not change the count.
    subscription_count: AtomicUsize,
    /// Round-robin cursors per shared-subscription group, sharded (B4-08).
    /// Keyed by group name alone so one group balances across all its
    /// filters. No global lock on the match path: each delivery touches
    /// only its group's shard.
    rr_cursors: ShardedCursors,
    /// Per-group dispatch strategy (B4-02), copy-on-write (B4-08).
    /// Written by [`Router::set_shared_strategy`] under `strategy_write`
    /// (clone, mutate, swap); read on every shared delivery by
    /// `balance_shared_groups` with one lock-free `ArcSwap` load. Keyed
    /// by group name; unconfigured groups read as
    /// [`SharedStrategy::RoundRobin`]. Bounded by [`MAX_SHARED_GROUPS`]:
    /// new groups past the cap are rejected with
    /// [`SharedStrategyError::TooManyGroups`] (fail closed, never an
    /// unbounded config map).
    strategies: ArcSwap<AHashMap<Arc<str>, SharedStrategy>>,
    /// Serializes strategy-table writers. Readers never take it.
    strategy_write: Mutex<()>,
    /// Sticky affinity per shared-subscription group (B4-02), sharded
    /// (B4-08). Keyed by group name alone. See [`StickyEntry`] for the
    /// pin/re-pick rule.
    sticky: ShardedSticky,
    /// Xorshift random seed for the `random` strategy. One relaxed atomic
    /// add per random delivery; no lock, no allocation, no per-message
    /// map. Seeded once from the wall clock (fallback constant when the
    /// clock is unavailable) so restarts do not repeat one sequence.
    random_seed: std::sync::atomic::AtomicU64,
    /// Known concrete topics seen on publishes (W1-15). Separate lock
    /// from the subscription trie so management list reads never block
    /// the routing path and publishes only take a short write.
    known_topics: RwLock<AHashSet<Arc<str>>>,
    /// Ordered compiled rewrite rules (B4-04). Written once per
    /// configuration change under a write lock; the publish and
    /// subscribe paths take only a short read lock and evaluate at most
    /// this many precompiled regexes in order, first match wins.
    /// Bounded by [`MAX_REWRITE_RULES`].
    rewrite_rules: RwLock<Vec<CompiledRewriteRule>>,
    /// Rewrite outcomes (B4-04). Relaxed atomics bumped on the match
    /// path; no lock, no allocation.
    rewrite_rewritten: AtomicU64,
    /// Messages that matched no rule and passed through unchanged.
    rewrite_passthrough: AtomicU64,
    /// Inputs or outputs past [`MAX_REWRITE_LEN`], left unchanged
    /// (fail closed, never truncated).
    rewrite_budget_exceeded: AtomicU64,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    pub fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        // A zero seed would stick one xorshift tap at zero; fold in the
        // process id and a nonzero constant instead.
        let seed = seed
            .wrapping_add((std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15))
            .wrapping_add(0x2545F4914F6CDD1D)
            | 1;
        Self {
            root: ArcSwap::from(Arc::new(TrieNode::default())),
            trie_write: Mutex::new(()),
            subscription_count: AtomicUsize::new(0),
            rr_cursors: ShardedCursors::default(),
            strategies: ArcSwap::from(Arc::new(AHashMap::new())),
            strategy_write: Mutex::new(()),
            sticky: ShardedSticky::default(),
            random_seed: std::sync::atomic::AtomicU64::new(seed),
            known_topics: RwLock::new(AHashSet::new()),
            rewrite_rules: RwLock::new(Vec::new()),
            rewrite_rewritten: AtomicU64::new(0),
            rewrite_passthrough: AtomicU64::new(0),
            rewrite_budget_exceeded: AtomicU64::new(0),
        }
    }

    /// Set the dispatch strategy for one shared-subscription group
    /// (B4-02). The name must be one of [`VALID_SHARED_STRATEGIES`];
    /// unknown names are rejected with [`SharedStrategyError::Unknown`],
    /// never mapped to a default. Empty group names are rejected. New
    /// groups past [`MAX_SHARED_GROUPS`] are rejected with
    /// [`SharedStrategyError::TooManyGroups`]; updating an existing
    /// group's strategy always succeeds. Called off the delivery path
    /// (management/config plane); deliveries only read.
    pub fn set_shared_strategy(
        &self,
        group: &str,
        strategy_name: &str,
    ) -> Result<(), SharedStrategyError> {
        if group.is_empty() {
            return Err(SharedStrategyError::EmptyGroup);
        }
        let strategy = SharedStrategy::parse(strategy_name)?;
        let _guard = self.strategy_write.lock();
        let current = self.strategies.load_full();
        if !current.contains_key(group) && current.len() >= MAX_SHARED_GROUPS {
            return Err(SharedStrategyError::TooManyGroups(MAX_SHARED_GROUPS));
        }
        let mut next = (*current).clone();
        next.insert(group.into(), strategy);
        self.strategies.store(Arc::new(next));
        Ok(())
    }

    /// Dispatch strategy for `group`: the configured value, or
    /// [`SharedStrategy::RoundRobin`] when the group has no entry. One
    /// lock-free snapshot load; no lock, no allocation on the hit path.
    pub fn shared_strategy(&self, group: &str) -> SharedStrategy {
        self.strategies
            .load_full()
            .get(group)
            .copied()
            .unwrap_or_default()
    }

    /// Forget one group's configured strategy (management/config plane).
    /// The group falls back to round-robin. Returns true when an entry
    /// existed.
    pub fn clear_shared_strategy(&self, group: &str) -> bool {
        let _guard = self.strategy_write.lock();
        let current = self.strategies.load_full();
        if !current.contains_key(group) {
            return false;
        }
        let mut next = (*current).clone();
        next.remove(group);
        self.strategies.store(Arc::new(next));
        true
    }

    /// Number of groups with an explicit strategy entry (config-plane
    /// hook for tests and operators).
    pub fn shared_strategy_count(&self) -> usize {
        self.strategies.load_full().len()
    }

    /// Number of live round-robin cursor entries across all shards
    /// (operator/test hook for the B4-08 bound check).
    pub fn rr_cursor_count(&self) -> usize {
        self.rr_cursors
            .shards
            .iter()
            .map(|shard| shard.read().len())
            .sum()
    }

    /// Number of live sticky affinity entries across all shards
    /// (operator/test hook for the B4-08 bound check).
    pub fn sticky_count(&self) -> usize {
        self.sticky
            .shards
            .iter()
            .map(|shard| shard.read().len())
            .sum()
    }

    /// Number of live subscription entries in the trie (operator/test
    /// hook for the B4-08 bound check). Never exceeds
    /// [`MAX_SUBSCRIPTIONS`]: new entries past the cap are denied while
    /// replacements and removals always proceed.
    pub fn subscription_count(&self) -> usize {
        self.subscription_count.load(Ordering::Relaxed)
    }

    /// Install the ordered rewrite table (B4-04, config plane). Every
    /// pattern compiles here, once; the per-message path never compiles.
    /// The table swaps atomically under one write lock: readers always
    /// see the old or the new table, never a mix. Rejects fail closed
    /// with the table unchanged: too many rules, an empty pattern, an
    /// uncompilable pattern, or a replacement already past
    /// [`MAX_REWRITE_LEN`].
    pub fn set_rewrite_rules(
        &self,
        configs: Vec<RewriteRuleConfig>,
    ) -> Result<(), RewriteRuleError> {
        if configs.len() > MAX_REWRITE_RULES {
            return Err(RewriteRuleError::TooManyRules(MAX_REWRITE_RULES));
        }
        let mut compiled = Vec::with_capacity(configs.len());
        for config in &configs {
            if config.pattern.is_empty() {
                return Err(RewriteRuleError::EmptyPattern);
            }
            if config.replacement.len() > MAX_REWRITE_LEN {
                return Err(RewriteRuleError::ReplacementTooLong(MAX_REWRITE_LEN));
            }
            let regex = regex::Regex::new(&config.pattern)
                .map_err(|_| RewriteRuleError::InvalidPattern(config.pattern.clone()))?;
            compiled.push(CompiledRewriteRule {
                scope: config.scope,
                replacement: config.replacement.clone(),
                regex,
            });
        }
        *self.rewrite_rules.write() = compiled;
        Ok(())
    }

    /// Drop every rewrite rule (config plane). Delivery passes through
    /// unchanged afterwards; counters keep their values.
    pub fn clear_rewrite_rules(&self) {
        self.rewrite_rules.write().clear();
    }

    /// Number of installed rewrite rules in evaluation order.
    pub fn rewrite_rule_count(&self) -> usize {
        self.rewrite_rules.read().len()
    }

    /// Copy the rewrite counters in one call for operators and tests.
    pub fn rewrite_stats(&self) -> RewriteStats {
        RewriteStats {
            rules: self.rewrite_rules.read().len(),
            rewritten: self.rewrite_rewritten.load(Ordering::Relaxed),
            passthrough: self.rewrite_passthrough.load(Ordering::Relaxed),
            budget_exceeded: self.rewrite_budget_exceeded.load(Ordering::Relaxed),
        }
    }

    /// Rewrite one publish topic (B4-04). Evaluates publish/both rules
    /// in configuration order; the first regex that matches wins and
    /// its capture-group replacement is returned. `None` means deliver
    /// unchanged (no rules, no match, system prefix, or budget failure).
    ///
    /// Called by the publish ingress event before auth, retained state,
    /// rules and fan-out observe the topic, so every downstream stage
    /// sees the rewritten name.
    pub fn rewrite_publish(&self, topic: &str) -> Option<String> {
        self.rewrite_for(topic, true)
    }

    /// Rewrite one subscribe filter (B4-04). Same ordered first-match
    /// rule, restricted to subscribe/both rules. `None` means subscribe
    /// with the filter unchanged.
    ///
    /// Called by the subscribe event before validation and group
    /// splitting observe the filter, so the router, the session mirror
    /// and retained replay all see the rewritten filter.
    pub fn rewrite_subscribe(&self, filter: &str) -> Option<String> {
        self.rewrite_for(filter, false)
    }

    /// Shared ordered evaluation for both directions. Per-message cost:
    /// one short read lock, at most one `is_match` probe per installed
    /// rule (at most [`MAX_REWRITE_RULES`], linear-time engine in the
    /// input length, early exit on the first match), plus a single
    /// bounded replacement allocation (at most [`MAX_REWRITE_LEN`]
    /// bytes) on a hit. No compilation, no unbounded allocation, no
    /// waiting: an over-long input or output fails closed to `None`
    /// with the budget counter bumped.
    fn rewrite_for(&self, input: &str, is_publish: bool) -> Option<String> {
        if input.len() > MAX_REWRITE_LEN {
            self.rewrite_budget_exceeded.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if input.is_empty() {
            self.rewrite_passthrough.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // TODO(parity): should system-prefixed names (`$...`, covering
        // delayed markers and shared-subscription requests) be rewritable?
        // Neither this rulebook nor the task spec decides; current choice
        // is the conservative one (leave them untouched) so rewrite rules
        // can never change delayed or shared-subscription semantics.
        if input.starts_with('$') {
            self.rewrite_passthrough.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let rules = self.rewrite_rules.read();
        for rule in rules.iter() {
            let in_scope = if is_publish {
                rule.scope.applies_to_publish()
            } else {
                rule.scope.applies_to_subscribe()
            };
            if !in_scope {
                continue;
            }
            if !rule.regex.is_match(input) {
                continue;
            }
            let out = rule.regex.replace(input, rule.replacement.as_str());
            if out.len() > MAX_REWRITE_LEN {
                drop(rules);
                self.rewrite_budget_exceeded.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            drop(rules);
            self.rewrite_rewritten.fetch_add(1, Ordering::Relaxed);
            return Some(out.into_owned());
        }
        drop(rules);
        self.rewrite_passthrough.fetch_add(1, Ordering::Relaxed);
        None
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

    /// Subscribe event: insert `sub` at `filter` with copy-on-write
    /// isolation and structural sharing (B4-08). The writer shallow-clones
    /// the snapshot root under `trie_write` (unchanged subtrees stay shared
    /// `Arc`s), copies only the nodes on the filter path, and swaps the new
    /// root into view; readers holding the old snapshot finish against it
    /// without waiting. Match semantics are unchanged (B4-02 strategies
    /// untouched). Mutation-path cost only (never on the match path): one
    /// shallow root clone plus one new node per filter level, each cloning
    /// only its level's sibling map while sharing every unchanged child
    /// `Arc`, so steady state holds one trie bounded by
    /// [`MAX_SUBSCRIPTIONS`] and transiently the old root plus one new
    /// path; per-subscribe latency is measured by
    /// `subscribe_storm_alongside_matches_keeps_semantics` (before and
    /// after min/median/max) and stays off the publish/deliver path. New
    /// entries past [`MAX_SUBSCRIPTIONS`] are denied (fail closed, existing
    /// delivery proceeds, returns `false` so the caller never reports
    /// success); replacing the same client's entry always succeeds and
    /// returns `true`.
    pub fn subscribe(&self, filter: &TopicFilter, sub: Subscription) -> bool {
        let _guard = self.trie_write.lock();
        let current = self.root.load_full();
        if !Self::terminal_contains(&current, filter, sub.client_id.as_ref())
            && self.subscription_count.load(Ordering::Relaxed) >= MAX_SUBSCRIPTIONS
        {
            return false;
        }
        let levels: Vec<&str> = filter.as_str().split('/').collect();
        let root_owned = (*current).clone();
        let (next, added) = Self::insert_owned(root_owned, &levels, 0, sub);
        if added {
            self.subscription_count.fetch_add(1, Ordering::Relaxed);
        }
        self.root.store(Arc::new(next));
        true
    }

    /// Insert helper with path copying on a shallow-cloned root. Only the
    /// nodes on the filter path are replaced; every other child `Arc` is
    /// shared with the previous snapshot. Same traversal as before: `#`
    /// attaches at the current level, `+` descends the single-wildcard
    /// child, other levels descend exact children, and a re-subscribe from
    /// a new connection replaces the old copy. Returns the new node plus
    /// whether a new `(filter, client)` entry was added (false for a
    /// same-client replacement).
    fn insert_owned(
        mut node: TrieNode,
        levels: &[&str],
        pos: usize,
        sub: Subscription,
    ) -> (TrieNode, bool) {
        let level = levels[pos];
        let is_last = pos + 1 == levels.len();
        if level == "#" {
            let existed = node
                .multi_wildcard_subs
                .iter()
                .any(|s| s.client_id == sub.client_id);
            node.multi_wildcard_subs
                .retain(|s| s.client_id != sub.client_id);
            node.multi_wildcard_subs.insert(sub);
            return (node, !existed);
        }
        if level == "+" {
            if is_last {
                let mut child = match node.single_wildcard.take() {
                    Some(child) => (*child).clone(),
                    None => TrieNode::default(),
                };
                let existed = child
                    .exact_subs
                    .iter()
                    .any(|s| s.client_id == sub.client_id);
                child.exact_subs.retain(|s| s.client_id != sub.client_id);
                child.exact_subs.insert(sub);
                node.single_wildcard = Some(Arc::new(child));
                return (node, !existed);
            }
            let mut child = match node.single_wildcard.take() {
                Some(child) => (*child).clone(),
                None => TrieNode::default(),
            };
            let (next_child, added) = Self::insert_owned(child, levels, pos + 1, sub);
            child = next_child;
            node.single_wildcard = Some(Arc::new(child));
            return (node, added);
        }
        if is_last {
            let mut child = match node.children.remove(level) {
                Some(child) => (*child).clone(),
                None => TrieNode::default(),
            };
            let existed = child
                .exact_subs
                .iter()
                .any(|s| s.client_id == sub.client_id);
            child.exact_subs.retain(|s| s.client_id != sub.client_id);
            child.exact_subs.insert(sub);
            node.children.insert(level.into(), Arc::new(child));
            return (node, !existed);
        }
        let child = match node.children.remove(level) {
            Some(child) => (*child).clone(),
            None => TrieNode::default(),
        };
        let (next_child, added) = Self::insert_owned(child, levels, pos + 1, sub);
        node.children.insert(level.into(), Arc::new(next_child));
        (node, added)
    }

    /// Probe the snapshot for a live `(filter, client)` entry: true when
    /// the filter path exists and its terminal set already holds
    /// `client_id`. Used to tell a same-client replacement (always
    /// allowed) from a new entry (counted against [`MAX_SUBSCRIPTIONS`]),
    /// and to skip no-op unsubscribes without copying.
    fn terminal_contains(node: &TrieNode, filter: &TopicFilter, client_id: &str) -> bool {
        let mut curr = node;
        let levels: Vec<&str> = filter.as_str().split('/').collect();
        for (pos, level) in levels.iter().enumerate() {
            if *level == "#" {
                return curr
                    .multi_wildcard_subs
                    .iter()
                    .any(|s| s.client_id.as_ref() == client_id);
            }
            let is_last = pos + 1 == levels.len();
            if *level == "+" {
                match curr.single_wildcard.as_ref() {
                    Some(child) => {
                        if is_last {
                            return child
                                .exact_subs
                                .iter()
                                .any(|s| s.client_id.as_ref() == client_id);
                        }
                        curr = &**child;
                    }
                    None => return false,
                }
            } else {
                match curr.children.get(*level) {
                    Some(child) => {
                        if is_last {
                            return child
                                .exact_subs
                                .iter()
                                .any(|s| s.client_id.as_ref() == client_id);
                        }
                        curr = &**child;
                    }
                    None => return false,
                }
            }
        }
        false
    }

    /// Unsubscribe event: remove `client_id` at `filter` with the same
    /// path-copying discipline as [`Router::subscribe`]. A filter path
    /// without a live entry for `client_id` returns after one lock-free
    /// snapshot load and one probe, with no copy and no store, so no-op
    /// unsubscribes pay no allocation. A real removal copies only the
    /// filter path, prunes nodes left empty, and decrements the
    /// [`MAX_SUBSCRIPTIONS`] count.
    pub fn unsubscribe(&self, filter: &TopicFilter, client_id: &str) {
        let _guard = self.trie_write.lock();
        let current = self.root.load_full();
        if !Self::path_exists(&current, filter) {
            return;
        }
        if !Self::terminal_contains(&current, filter, client_id) {
            return;
        }
        let levels: Vec<&str> = filter.as_str().split('/').collect();
        let root_owned = (*current).clone();
        let (next, changed) = Self::remove_owned(root_owned, &levels, 0, client_id);
        if changed {
            self.subscription_count.fetch_sub(1, Ordering::Relaxed);
            self.root.store(Arc::new(next));
        }
    }

    /// Read-only probe: true when every level of `filter` exists in
    /// `node` (so a removal could change something). `#` always counts
    /// as present at its level; missing exact or `+` children mean no
    /// unsubscribe work is needed.
    fn path_exists(node: &TrieNode, filter: &TopicFilter) -> bool {
        let mut curr = node;
        for level in filter.as_str().split('/') {
            if level == "#" {
                return true;
            } else if level == "+" {
                match curr.single_wildcard.as_ref() {
                    Some(child) => curr = child.as_ref(),
                    None => return false,
                }
            } else {
                match curr.children.get(level) {
                    Some(child) => curr = child.as_ref(),
                    None => return false,
                }
            }
        }
        true
    }

    /// True when a node holds no subscriptions and no children, so its
    /// parent can drop the entry instead of keeping an empty branch. Keeps
    /// trie memory bounded by live entries under [`MAX_SUBSCRIPTIONS`]
    /// rather than by churn history.
    fn is_empty_node(node: &TrieNode) -> bool {
        node.exact_subs.is_empty()
            && node.multi_wildcard_subs.is_empty()
            && node.children.is_empty()
            && node.single_wildcard.is_none()
    }

    /// Removal helper with path copying on a shallow-cloned root. Returns
    /// the new node plus whether an entry was actually removed (the caller
    /// stores the clone only then). Empty branches are pruned so
    /// subscribe/unsubscribe churn over rotating filters cannot grow the
    /// trie without limit. Traversal mirrors [`Router::insert_owned`].
    fn remove_owned(
        mut node: TrieNode,
        levels: &[&str],
        pos: usize,
        client_id: &str,
    ) -> (TrieNode, bool) {
        let level = levels[pos];
        let is_last = pos + 1 == levels.len();
        if level == "#" {
            let before = node.multi_wildcard_subs.len();
            node.multi_wildcard_subs
                .retain(|s| s.client_id.as_ref() != client_id);
            let changed = node.multi_wildcard_subs.len() != before;
            return (node, changed);
        }
        if level == "+" {
            let child = match node.single_wildcard.take() {
                Some(child) => (*child).clone(),
                None => return (node, false),
            };
            if is_last {
                let before = child.exact_subs.len();
                let mut child = child;
                child
                    .exact_subs
                    .retain(|s| s.client_id.as_ref() != client_id);
                if child.exact_subs.len() == before {
                    node.single_wildcard = Some(Arc::new(child));
                    return (node, false);
                }
                if !Self::is_empty_node(&child) {
                    node.single_wildcard = Some(Arc::new(child));
                }
                return (node, true);
            }
            let (next_child, changed) = Self::remove_owned(child, levels, pos + 1, client_id);
            if !changed {
                node.single_wildcard = Some(Arc::new(next_child));
                return (node, false);
            }
            if !Self::is_empty_node(&next_child) {
                node.single_wildcard = Some(Arc::new(next_child));
            }
            return (node, true);
        }
        let child = match node.children.remove(level) {
            Some(child) => (*child).clone(),
            None => return (node, false),
        };
        if is_last {
            let before = child.exact_subs.len();
            let mut child = child;
            child
                .exact_subs
                .retain(|s| s.client_id.as_ref() != client_id);
            if child.exact_subs.len() == before {
                node.children.insert(level.into(), Arc::new(child));
                return (node, false);
            }
            if !Self::is_empty_node(&child) {
                node.children.insert(level.into(), Arc::new(child));
            }
            return (node, true);
        }
        let (next_child, changed) = Self::remove_owned(child, levels, pos + 1, client_id);
        if !changed {
            node.children.insert(level.into(), Arc::new(next_child));
            return (node, false);
        }
        if !Self::is_empty_node(&next_child) {
            node.children.insert(level.into(), Arc::new(next_child));
        }
        (node, true)
    }

    pub fn matches(&self, topic: &Topic) -> SubscriptionSet {
        self.matches_with_publisher(topic, None)
    }

    /// Match plus shared-group reduction with publisher context (B4-02).
    ///
    /// Locking (B4-08, `crates/broker-router/src/lib.rs`): the match path
    /// loads one `ArcSwap` snapshot (`Router::root` via `load_full`) and
    /// walks it with no trie lock held, then releases the snapshot before
    /// `balance_shared_groups`, which touches only its group's shard
    /// (`ShardedCursors` / `ShardedSticky`) plus lock-free strategy and
    /// random state. Readers never wait on writers longer than one
    /// pointer load plus a refcount bump; writers never wait on readers.
    /// Driven by the publish delivery event (`matches` /
    /// `matches_with_publisher` on every publish fan-out) and by the
    /// subscribe/unsubscribe events for the mutation path.
    ///
    /// The delivery path calls this with the publishing client id so the
    /// `hash_clientid` strategy hashes a real key; callers without a
    /// publisher (management reads, rule republishes, retained replays)
    /// pass `None`. A `None` publisher under `hash_clientid` hashes the
    /// empty string deterministically (stable, still one member); see
    /// the open-question note at the call site for what key those paths
    /// should hash.
    ///
    /// Per-match cost: one lock-free snapshot load, one trie walk that
    /// clones only the matched subscriptions (pointer clones, no heap
    /// strings), plus the per-group reduction cost documented on
    /// `balance_shared_groups`. No allocation, lock, or unbounded work
    /// beyond the matched set itself. Measured by
    /// `subscribe_storm_alongside_matches_keeps_semantics` (storm
    /// matches/s, run with `-- --nocapture`) and
    /// `router_match_cost_reports_min_median_max` (settled single-thread
    /// ns/match with min/median/max across repeats).
    pub fn matches_with_publisher(
        &self,
        topic: &Topic,
        publisher: Option<&str>,
    ) -> SubscriptionSet {
        let snapshot = self.root.load_full();
        let mut matched = SubscriptionSet::default();
        Self::match_recursive(&snapshot, topic.as_str(), &mut matched);
        drop(snapshot);
        // No trie lock is held across balancing: the balance step takes
        // only short per-group shard locks (or no lock for hash/random),
        // never a global critical section, so subscribers never block
        // deliveries.
        self.balance_shared_groups(&mut matched, topic, publisher);
        matched
    }

    /// Reduce each shared group in `matched` to exactly one member using
    /// that group's configured [`SharedStrategy`] (B4-02). Members sort
    /// by client id first so every strategy but `random` is
    /// deterministic. Plain subscriptions pass through untouched.
    ///
    /// Consulted by the publish delivery event: `matches` /
    /// `matches_with_publisher` call this on every publish fan-out, and
    /// the node delivery path (`build_downlink_frames` in
    /// `crates/broker-node/src/main.rs`) consumes the reduced set.
    ///
    /// Per-delivery cost: one sort per group (O(m log m) in the member
    /// count, the dominant term for large groups), then O(members) or
    /// better selection with no allocation beyond the existing group
    /// buckets and the single picked clone: round-robin is one short
    /// shard read plus one lock-free atomic increment, random is one
    /// relaxed atomic scramble, the hashes are one FNV pass over the key,
    /// and sticky is one FNV fingerprint pass plus at most one short
    /// shard write when the membership changed. No per-message map grows
    /// without bound: cursors and affinity entries stay within
    /// [`MAX_SHARED_GROUPS`] (`MAX_SHARED_GROUPS_PER_SHARD` per shard).
    /// No global lock is taken here: each group touches only its own
    /// shard (`crates/broker-router/src/lib.rs`, `ShardedCursors` /
    /// `ShardedSticky`), and strategies load lock-free. Measured by
    /// `router_match_cost_reports_min_median_max` (run with
    /// `-- --nocapture` for the ns/match min/median/max report).
    fn balance_shared_groups(
        &self,
        matched: &mut SubscriptionSet,
        topic: &Topic,
        publisher: Option<&str>,
    ) {
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
        // Lock-free strategy snapshot: one `ArcSwap` load for the whole
        // delivery, then no lock per group on the hot path.
        let strategies = self.strategies.load_full();
        for (group, mut members) in groups {
            members.sort_by(|a, b| a.client_id.cmp(&b.client_id));
            let strategy = strategies.get(&group).copied().unwrap_or_default();
            let pick = match strategy {
                SharedStrategy::RoundRobin => self.pick_round_robin(&group, &members),
                SharedStrategy::Random => self.pick_random(&members),
                SharedStrategy::HashClientId => {
                    // TODO(parity): what key should non-MQTT delivery paths
                    // (rule republishes, retained replays, cluster forwards,
                    // management publishes) hash when there is no publisher
                    // id? Current choice hashes the empty string: stable
                    // (one member) but arbitrary. The MQTT ingress path
                    // always passes the real publisher id.
                    let key = publisher.unwrap_or("");
                    Self::pick_hash(&members, key)
                }
                SharedStrategy::HashTopic => Self::pick_hash(&members, topic.as_str()),
                SharedStrategy::Sticky => self.pick_sticky(&group, &members),
            };
            matched.insert(pick);
        }
    }

    /// Round-robin pick: cursor per group, deterministic client-id order.
    /// Locking (`crates/broker-router/src/lib.rs`, `ShardedCursors`):
    /// exactly one shard is touched. The fast path takes that shard's
    /// read lock to fetch the atomic counter and bumps it lock-free with
    /// `fetch_add`; only a missing group takes the shard's write lock to
    /// insert. Bounded per shard by [`MAX_SHARED_GROUPS_PER_SHARD`]: a
    /// missing group in a full shard evicts one arbitrary entry of that
    /// same shard first (documented on the constant).
    fn pick_round_robin(&self, group: &Arc<str>, members: &[Subscription]) -> Subscription {
        debug_assert!(!members.is_empty());
        let shard = &self.rr_cursors.shards[group_shard(group)];
        // Fast path: the group already has a cursor.
        {
            let cursors = shard.read();
            if let Some(cursor) = cursors.get(group) {
                let prev = cursor.fetch_add(1, Ordering::Relaxed);
                return members[prev % members.len()].clone();
            }
        }
        // Slow path: install the cursor (at most one shard write).
        let mut cursors = shard.write();
        if let Some(cursor) = cursors.get(group) {
            let prev = cursor.fetch_add(1, Ordering::Relaxed);
            return members[prev % members.len()].clone();
        }
        if cursors.len() >= MAX_SHARED_GROUPS_PER_SHARD {
            if let Some(victim) = cursors.keys().next().cloned() {
                cursors.remove(&victim);
            }
        }
        cursors.insert(group.clone(), AtomicUsize::new(1));
        members[0].clone()
    }

    /// Uniform random pick. One relaxed atomic add plus an xorshift
    /// scramble; no lock, no allocation.
    fn pick_random(&self, members: &[Subscription]) -> Subscription {
        debug_assert!(!members.is_empty());
        let mut x = self
            .random_seed
            .fetch_add(0x9E3779B97F4A7C15, Ordering::Relaxed);
        if x == 0 {
            x = 0x2545F4914F6CDD1D;
        }
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let mixed = x.wrapping_mul(0x2545F4914F6CDD1D);
        let index = (mixed >> 32) as usize % members.len();
        members[index].clone()
    }

    /// Stable hash pick: member at `fnv1a64(key) % len` in sorted order.
    /// O(key) + O(1); no lock, no allocation, no router state.
    fn pick_hash(members: &[Subscription], key: &str) -> Subscription {
        debug_assert!(!members.is_empty());
        let index = (fnv1a64(key) as usize) % members.len();
        members[index].clone()
    }

    /// Sticky pick (B4-02 rule): the first delivery for a group picks
    /// deterministically at `fnv1a64(group) % members` in sorted order
    /// and pins that client id. While the sorted membership fingerprint
    /// is unchanged the pinned member serves every delivery. Any join or
    /// leave changes the fingerprint and triggers a deterministic
    /// re-pick at the new `fnv1a64(group) % members`. Pinning is by
    /// client id (not connection), so a re-subscribe from a new
    /// connection keeps the pin and delivers to the freshest member
    /// object. Locking (`crates/broker-router/src/lib.rs`,
    /// `ShardedSticky`): exactly one shard is touched (read first, write
    /// only on a miss or membership change). Bounded per shard by
    /// [`MAX_SHARED_GROUPS_PER_SHARD`] with the same arbitrary-evict
    /// rule as the cursors.
    fn pick_sticky(&self, group: &Arc<str>, members: &[Subscription]) -> Subscription {
        debug_assert!(!members.is_empty());
        let fingerprint = fingerprint_members(members);
        let shard = &self.sticky.shards[group_shard(group)];
        {
            let sticky = shard.read();
            if let Some(entry) = sticky.get(group) {
                if entry.fingerprint == fingerprint {
                    if let Some(pinned) = members.iter().find(|m| m.client_id == entry.pinned) {
                        return pinned.clone();
                    }
                }
            }
        }
        let index = (fnv1a64(group.as_ref()) as usize) % members.len();
        let pick = members[index].clone();
        let mut sticky = shard.write();
        // Re-check under the write lock: another delivery may have
        // installed the current membership while we were unlocked.
        if let Some(entry) = sticky.get(group) {
            if entry.fingerprint == fingerprint {
                if let Some(pinned) = members.iter().find(|m| m.client_id == entry.pinned) {
                    return pinned.clone();
                }
            }
        }
        if !sticky.contains_key(group) && sticky.len() >= MAX_SHARED_GROUPS_PER_SHARD {
            if let Some(victim) = sticky.keys().next().cloned() {
                sticky.remove(&victim);
            }
        }
        sticky.insert(
            group.clone(),
            StickyEntry {
                pinned: pick.client_id.clone(),
                fingerprint,
            },
        );
        pick
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

    /// Reconstructed pre-B4-08 single-lock discipline (B4-08 before
    /// numbers). Wraps the current trie behind one global `RwLock`:
    /// subscribes take it for writing, matches take it for reading, so
    /// readers block on writers exactly as the old
    /// `RwLock<TrieNode>` root did. Same traversal as the CoW writer plus
    /// the global lock (not conservative: the true old writer mutated
    /// in place without a clone, so this baseline pays a path copy the
    /// old code never paid and any measured match-throughput gain
    /// overstates the contention removed by the cutover).
    /// Driven by the same subscribe/unsubscribe and publish delivery
    /// events as [`Router`]; the before side of the B4-08 storm
    /// comparison (spec B4-08:53-60), reported through the gates log.
    struct SingleLockBaseline {
        inner: Router,
        lock: parking_lot::RwLock<()>,
    }

    impl SingleLockBaseline {
        fn new() -> Self {
            Self {
                inner: Router::new(),
                lock: parking_lot::RwLock::new(()),
            }
        }

        fn subscribe(&self, filter: &TopicFilter, sub: Subscription) {
            let _guard = self.lock.write();
            self.inner.subscribe(filter, sub);
        }

        fn matches(&self, topic: &Topic) -> SubscriptionSet {
            let _guard = self.lock.read();
            self.inner.matches(topic)
        }

        fn unsubscribe(&self, filter: &TopicFilter, client_id: &str) {
            let _guard = self.lock.write();
            self.inner.unsubscribe(filter, client_id);
        }
    }

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

    fn shared_router_with(strategy: &str, group: &str) -> Router {
        let router = Router::new();
        let inner = TopicFilter::new("tasks").unwrap();
        router.subscribe(
            &inner,
            Subscription::shared("worker-a", 1, QoS::AtMostOnce, group),
        );
        router.subscribe(
            &inner,
            Subscription::shared("worker-b", 2, QoS::AtMostOnce, group),
        );
        router.subscribe(
            &inner,
            Subscription::shared("worker-c", 3, QoS::AtMostOnce, group),
        );
        router
            .set_shared_strategy(group, strategy)
            .expect("documented strategy sets");
        router
    }

    #[test]
    fn test_shared_strategy_parse_vectors() {
        assert_eq!(
            SharedStrategy::parse("round_robin").unwrap(),
            SharedStrategy::RoundRobin
        );
        assert_eq!(
            SharedStrategy::parse("random").unwrap(),
            SharedStrategy::Random
        );
        assert_eq!(
            SharedStrategy::parse("hash_clientid").unwrap(),
            SharedStrategy::HashClientId
        );
        assert_eq!(
            SharedStrategy::parse("hash_topic").unwrap(),
            SharedStrategy::HashTopic
        );
        assert_eq!(
            SharedStrategy::parse("sticky").unwrap(),
            SharedStrategy::Sticky
        );
        assert_eq!(SharedStrategy::default(), SharedStrategy::RoundRobin);
    }

    #[test]
    fn test_shared_unknown_strategy_rejected_not_mapped() {
        let router = Router::new();
        let err = router
            .set_shared_strategy("g1", "least-connections")
            .expect_err("unknown strategy must fail");
        assert!(matches!(err, SharedStrategyError::Unknown(_)));
        assert!(err.to_string().contains("round_robin"));
        // Rejected write leaves the default in place (round-robin), it
        // does not install a silent mapping.
        assert_eq!(router.shared_strategy("g1"), SharedStrategy::RoundRobin);
        assert_eq!(router.shared_strategy_count(), 0);
        assert!(!router.clear_shared_strategy("g1"));
    }

    #[test]
    fn test_shared_hash_clientid_stable_per_publisher() {
        let router = shared_router_with("hash_clientid", "hcid");
        let topic = Topic::new("tasks").unwrap();
        for publisher in ["pub-1", "pub-2", "pub-3"] {
            let first = router
                .matches_with_publisher(&topic, Some(publisher))
                .iter()
                .next()
                .unwrap()
                .client_id
                .to_string();
            for _ in 0..8 {
                let again = router
                    .matches_with_publisher(&topic, Some(publisher))
                    .iter()
                    .next()
                    .unwrap()
                    .client_id
                    .to_string();
                assert_eq!(again, first, "one publisher id pins one member");
            }
        }
    }

    #[test]
    fn test_shared_hash_topic_stable_per_topic() {
        let router = shared_router_with("hash_topic", "htopic");
        let a = Topic::new("tasks").unwrap();
        let b = Topic::new("tasks").unwrap();
        let first = router
            .matches_with_publisher(&a, None)
            .iter()
            .next()
            .unwrap()
            .client_id
            .to_string();
        for _ in 0..8 {
            let again = router
                .matches_with_publisher(&b, None)
                .iter()
                .next()
                .unwrap()
                .client_id
                .to_string();
            assert_eq!(again, first, "one topic pins one member");
        }
    }

    #[test]
    fn test_shared_sticky_pins_while_stable_and_rebalances_on_leave() {
        let router = shared_router_with("sticky", "stick");
        let topic = Topic::new("tasks").unwrap();
        let first = router
            .matches(&topic)
            .iter()
            .next()
            .unwrap()
            .client_id
            .to_string();
        for _ in 0..16 {
            let again = router
                .matches(&topic)
                .iter()
                .next()
                .unwrap()
                .client_id
                .to_string();
            assert_eq!(again, first, "sticky holds while members stable");
        }
        // A leave changes the fingerprint and re-picks deterministically.
        let inner = TopicFilter::new("tasks").unwrap();
        router.unsubscribe(&inner, &first);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            seen.insert(
                router
                    .matches(&topic)
                    .iter()
                    .next()
                    .unwrap()
                    .client_id
                    .to_string(),
            );
        }
        assert_eq!(seen.len(), 1, "re-pick pins the new member");
        assert!(
            !seen.contains(&first),
            "departed member must not stay pinned"
        );
    }

    #[test]
    fn test_shared_random_reaches_every_member() {
        let router = shared_router_with("random", "rand");
        let topic = Topic::new("tasks").unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..90 {
            seen.insert(
                router
                    .matches(&topic)
                    .iter()
                    .next()
                    .unwrap()
                    .client_id
                    .to_string(),
            );
        }
        assert_eq!(
            seen.len(),
            3,
            "random must show liveness across all members, saw {seen:?}"
        );
    }

    #[test]
    fn test_shared_state_stays_bounded_by_group_cap() {
        assert_eq!(MAX_SHARED_GROUPS, 1_024);
        let router = Router::new();
        let inner = TopicFilter::new("t").unwrap();
        // Drive deliveries for more groups than the cap: cursors and
        // sticky entries must evict instead of growing without bound.
        for i in 0..(MAX_SHARED_GROUPS + 64) {
            let group = format!("cap-g{i}");
            router.subscribe(
                &inner,
                Subscription::shared("m-a", 1, QoS::AtMostOnce, group.as_str()),
            );
            router.subscribe(
                &inner,
                Subscription::shared("m-b", 2, QoS::AtMostOnce, group.as_str()),
            );
            if i % 2 == 0 {
                router.set_shared_strategy(&group, "sticky").expect("set");
            }
            let topic = Topic::new("t").unwrap();
            assert_eq!(router.matches(&topic).len(), 1);
        }
        assert!(router.rr_cursor_count() <= MAX_SHARED_GROUPS);
        assert!(router.sticky_count() <= MAX_SHARED_GROUPS);
    }

    #[test]
    fn subscribe_storm_alongside_matches_keeps_semantics() {
        // B4-08 contention harness: the same subscribe storm + steady
        // match workload runs against the reconstructed single-lock
        // baseline (before numbers) and the CoW router (after numbers).
        // Writer threads churn distinct filters while reader threads
        // match a steady topic; readers must always see the steady
        // subscriber and the final snapshot must equal the sequential
        // expectation. Throughputs report min/median/max across repeats
        // (spec B4-08:53-60); settled subscribe latency reports
        // min/median/max per subscribe. Asserts exact delivery counts
        // plus correctness, never an absolute time threshold, so the
        // test is stable on loaded runners.
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::Instant;

        const WRITERS: usize = 4;
        const FILTERS_PER_WRITER: usize = 25;
        const READERS: usize = 4;
        const MATCHES_PER_READER: usize = 200;
        const REPEATS: usize = 5;
        const SUB_LATENCY_OPS: usize = 200;

        fn storm_once(
            subscribe: &(dyn Fn(usize, usize) + Sync),
            matches: &(dyn Fn() -> usize + Sync),
            steady_visible: &(dyn Fn() -> bool + Sync),
        ) -> (f64, f64) {
            let matched_total = Arc::new(AtomicU64::new(0));
            let start = Instant::now();
            std::thread::scope(|scope| {
                for writer in 0..WRITERS {
                    scope.spawn(move || {
                        for i in 0..FILTERS_PER_WRITER {
                            subscribe(writer, i);
                        }
                    });
                }
                for _ in 0..READERS {
                    let matched_total = matched_total.clone();
                    scope.spawn(move || {
                        for _ in 0..MATCHES_PER_READER {
                            let n = matches();
                            assert!(steady_visible(), "steady subscriber visible under storm");
                            matched_total.fetch_add(n as u64, Ordering::Relaxed);
                        }
                    });
                }
            });
            let elapsed_secs = start.elapsed().as_secs_f64().max(f64::EPSILON);
            let total = matched_total.load(Ordering::Relaxed);
            assert_eq!(total, (READERS * MATCHES_PER_READER) as u64);
            let subscribes = (WRITERS * FILTERS_PER_WRITER) as u64;
            (
                total as f64 / elapsed_secs,
                subscribes as f64 / elapsed_secs,
            )
        }

        fn settled_sub_latency_ns(subscribe_one: &dyn Fn(usize)) -> (f64, f64, f64) {
            let mut per_op_ns = Vec::with_capacity(SUB_LATENCY_OPS);
            for i in 0..SUB_LATENCY_OPS {
                let start = Instant::now();
                subscribe_one(i);
                per_op_ns.push(start.elapsed().as_secs_f64() * 1e9);
            }
            per_op_ns.sort_by(|a, b| a.total_cmp(b));
            (
                per_op_ns[0],
                per_op_ns[SUB_LATENCY_OPS / 2],
                per_op_ns[SUB_LATENCY_OPS - 1],
            )
        }

        // Before numbers: single-lock baseline, same workload family.
        let mut base_match = Vec::with_capacity(REPEATS);
        let mut base_sub = Vec::with_capacity(REPEATS);
        for _ in 0..REPEATS {
            let baseline = Arc::new(SingleLockBaseline::new());
            baseline.subscribe(
                &TopicFilter::new("storm/steady").unwrap(),
                Subscription::new("steady", 1, QoS::AtMostOnce),
            );
            let steady_topic = Topic::new("storm/steady").unwrap();
            let b = baseline.clone();
            let (m, s) = storm_once(
                &|writer, i| {
                    let filter = TopicFilter::new(format!("storm/w{writer}/t{i}"))
                        .expect("valid test filter");
                    b.subscribe(
                        &filter,
                        Subscription::new(
                            format!("storm-w{writer}-{i}"),
                            writer as u64 * 1000 + i as u64,
                            QoS::AtMostOnce,
                        ),
                    );
                },
                &|| b.matches(&steady_topic).len(),
                &|| {
                    b.matches(&steady_topic)
                        .iter()
                        .any(|s| s.client_id.as_ref() == "steady")
                },
            );
            base_match.push(m);
            base_sub.push(s);
            // Baseline correctness: every storm filter resolves exactly.
            for writer in 0..WRITERS {
                for i in 0..FILTERS_PER_WRITER {
                    let topic =
                        Topic::new(format!("storm/w{writer}/t{i}")).expect("valid test topic");
                    let matched = baseline.matches(&topic);
                    assert_eq!(
                        matched.len(),
                        1,
                        "baseline storm filter {writer}/{i} matches once"
                    );
                    assert_eq!(
                        matched.iter().next().unwrap().client_id.as_ref(),
                        format!("storm-w{writer}-{i}")
                    );
                }
            }
            // Baseline unsubscribe path (same events as `Router`): remove
            // one storm filter and confirm it no longer resolves, then
            // restore it so the baseline keeps full coverage.
            {
                let filter = TopicFilter::new("storm/w0/t0").expect("valid test filter");
                let probe = Topic::new("storm/w0/t0").expect("valid test topic");
                baseline.unsubscribe(&filter, "storm-w0-0");
                assert!(
                    baseline.matches(&probe).is_empty(),
                    "baseline unsubscribe removes the filter"
                );
                baseline.subscribe(&filter, Subscription::new("storm-w0-0", 0, QoS::AtMostOnce));
                assert_eq!(baseline.matches(&probe).len(), 1);
            }
        }
        base_match.sort_by(|a, b| a.total_cmp(b));
        base_sub.sort_by(|a, b| a.total_cmp(b));
        eprintln!(
            "B4-08 baseline storm: matches/s min={:.0} median={:.0} max={:.0}; \
            subscribes/s min={:.0} median={:.0} max={:.0} \
            ({} matches + {} subscribes x {REPEATS} repeats)",
            base_match[0],
            base_match[REPEATS / 2],
            base_match[REPEATS - 1],
            base_sub[0],
            base_sub[REPEATS / 2],
            base_sub[REPEATS - 1],
            READERS * MATCHES_PER_READER,
            WRITERS * FILTERS_PER_WRITER,
        );
        assert!(
            base_match[0] > 0.0 && base_match[0].is_finite() && base_match[REPEATS - 1].is_finite()
        );
        // Baseline settled subscribe latency (before number for SLOP2/SLOP3).
        let probe = SingleLockBaseline::new();
        let (bmin, bmed, bmax) = settled_sub_latency_ns(&|i| {
            let filter = TopicFilter::new(format!("storm/lat/{i}")).expect("valid test filter");
            probe.subscribe(
                &filter,
                Subscription::new(format!("lat-{i}"), 5000 + i as u64, QoS::AtMostOnce),
            );
        });
        eprintln!(
            "B4-08 baseline subscribe latency: min={bmin:.1}ns median={bmed:.1}ns max={bmax:.1}ns \
            ({SUB_LATENCY_OPS} subscribes)"
        );
        assert!(bmin > 0.0 && bmin.is_finite() && bmax.is_finite());

        // After numbers: CoW router, identical workload.
        let mut after_match = Vec::with_capacity(REPEATS);
        let mut after_sub = Vec::with_capacity(REPEATS);
        let mut last_router: Option<Arc<Router>> = None;
        let mut last_steady = Topic::new("storm/steady").unwrap();
        for _ in 0..REPEATS {
            let router = Arc::new(Router::new());
            router.subscribe(
                &TopicFilter::new("storm/steady").unwrap(),
                Subscription::new("steady", 1, QoS::AtMostOnce),
            );
            let steady_topic = Topic::new("storm/steady").unwrap();
            let r = router.clone();
            let (m, s) = storm_once(
                &|writer, i| {
                    let filter = TopicFilter::new(format!("storm/w{writer}/t{i}"))
                        .expect("valid test filter");
                    r.subscribe(
                        &filter,
                        Subscription::new(
                            format!("storm-w{writer}-{i}"),
                            writer as u64 * 1000 + i as u64,
                            QoS::AtMostOnce,
                        ),
                    );
                },
                &|| r.matches(&steady_topic).len(),
                &|| {
                    r.matches(&steady_topic)
                        .iter()
                        .any(|s| s.client_id.as_ref() == "steady")
                },
            );
            after_match.push(m);
            after_sub.push(s);
            last_router = Some(router);
            last_steady = steady_topic;
        }
        after_match.sort_by(|a, b| a.total_cmp(b));
        after_sub.sort_by(|a, b| a.total_cmp(b));
        let total = (READERS * MATCHES_PER_READER) as u64;
        let subscribes = (WRITERS * FILTERS_PER_WRITER) as u64;
        eprintln!(
            "B4-08 storm: {total} matches + {subscribes} subscribes per repeat; \
            matches/s min={:.0} median={:.0} max={:.0}; \
            subscribes/s min={:.0} median={:.0} max={:.0} \
            (x {REPEATS} repeats)",
            after_match[0],
            after_match[REPEATS / 2],
            after_match[REPEATS - 1],
            after_sub[0],
            after_sub[REPEATS / 2],
            after_sub[REPEATS - 1],
        );
        assert!(
            after_match[0] > 0.0
                && after_match[0].is_finite()
                && after_match[REPEATS - 1].is_finite()
        );
        assert!(
            after_sub[0] > 0.0 && after_sub[0].is_finite() && after_sub[REPEATS - 1].is_finite()
        );
        // Settled subscribe latency on the CoW path (writer clone cost).
        let probe = Router::new();
        let (amin, amed, amax) = settled_sub_latency_ns(&|i| {
            let filter = TopicFilter::new(format!("storm/lat/{i}")).expect("valid test filter");
            probe.subscribe(
                &filter,
                Subscription::new(format!("lat-{i}"), 6000 + i as u64, QoS::AtMostOnce),
            );
        });
        eprintln!(
            "B4-08 subscribe latency: min={amin:.1}ns median={amed:.1}ns max={amax:.1}ns \
            ({SUB_LATENCY_OPS} subscribes)"
        );
        assert!(amin > 0.0 && amin.is_finite() && amax.is_finite());

        // Final snapshot agrees with the sequential expectation on the
        // last CoW router: every storm filter matches exactly once, plus
        // wildcard levels and shared-group reduction.
        let router = last_router.expect("at least one repeat");
        let steady = router.matches(&last_steady);
        assert!(steady.iter().any(|s| s.client_id.as_ref() == "steady"));
        assert_eq!(steady.len(), 1);
        for writer in 0..WRITERS {
            for i in 0..FILTERS_PER_WRITER {
                let topic = Topic::new(format!("storm/w{writer}/t{i}")).expect("valid test topic");
                let matched = router.matches(&topic);
                assert_eq!(matched.len(), 1, "storm filter {writer}/{i} matches once");
                assert_eq!(
                    matched.iter().next().unwrap().client_id.as_ref(),
                    format!("storm-w{writer}-{i}")
                );
            }
        }
        router.subscribe(
            &TopicFilter::new("storm/+").unwrap(),
            Subscription::new("wild", 999, QoS::AtMostOnce),
        );
        let wild = router.matches(&last_steady);
        assert_eq!(wild.len(), 2);
        assert!(wild.iter().any(|s| s.client_id.as_ref() == "wild"));
        assert!(wild.iter().any(|s| s.client_id.as_ref() == "steady"));
        router.unsubscribe(&TopicFilter::new("storm/+").unwrap(), "wild");
        let after = router.matches(&last_steady);
        assert_eq!(after.len(), 1);
        assert!(!after.iter().any(|s| s.client_id.as_ref() == "wild"));
        assert!(after.iter().any(|s| s.client_id.as_ref() == "steady"));
        // Shared-group reduction still agrees after the storm.
        router.subscribe(
            &TopicFilter::new("storm/shared").unwrap(),
            Subscription::shared("sg-a", 1001, QoS::AtMostOnce, "storm-sg"),
        );
        router.subscribe(
            &TopicFilter::new("storm/shared").unwrap(),
            Subscription::shared("sg-b", 1002, QoS::AtMostOnce, "storm-sg"),
        );
        let shared_topic = Topic::new("storm/shared").unwrap();
        let reduced = router.matches(&shared_topic);
        assert_eq!(reduced.len(), 1, "shared group reduces to one member");
        assert!(router.rr_cursor_count() <= MAX_SHARED_GROUPS);
        assert!(router.sticky_count() <= MAX_SHARED_GROUPS);
    }

    #[test]
    fn router_match_cost_reports_min_median_max() {
        // B4-08 per-match cost harness (RULEBOOK hot-path row): settled
        // single-thread matches on one topic, repeated so the gate log
        // carries min/median/max for the single-lock baseline (before)
        // and the CoW + sharded-cursor router (after). The match path
        // under test is `Router::root` snapshot load
        // (`crates/broker-router/src/lib.rs`, `matches_with_publisher`)
        // plus the trie walk; shared-group reduction is plain
        // subscriptions here so the comparison isolates the trie-lock
        // removal. Asserts only positivity and correctness, never an
        // absolute time threshold, so it is stable on loaded runners.
        use std::time::Instant;

        const REPEATS: usize = 5;
        const MATCHES_PER_REPEAT: usize = 5_000;

        fn settled_cost(matches: &dyn Fn() -> usize, expected: usize) -> (f64, f64, f64, f64) {
            let mut per_match_ns = Vec::with_capacity(REPEATS);
            for _ in 0..REPEATS {
                let start = Instant::now();
                let mut sink = 0usize;
                for _ in 0..MATCHES_PER_REPEAT {
                    sink += matches();
                }
                std::hint::black_box(sink);
                assert_eq!(sink, expected * MATCHES_PER_REPEAT);
                let ns = start.elapsed().as_secs_f64() * 1e9 / MATCHES_PER_REPEAT as f64;
                per_match_ns.push(ns);
            }
            per_match_ns.sort_by(|a, b| a.total_cmp(b));
            let min = per_match_ns[0];
            let median = per_match_ns[REPEATS / 2];
            let max = per_match_ns[REPEATS - 1];
            let mean = per_match_ns.iter().sum::<f64>() / REPEATS as f64;
            (min, median, max, mean)
        }

        // Before: single global read lock per match.
        let baseline = SingleLockBaseline::new();
        baseline.subscribe(
            &TopicFilter::new("cost/steady").unwrap(),
            Subscription::new("steady", 1, QoS::AtMostOnce),
        );
        baseline.subscribe(
            &TopicFilter::new("cost/+").unwrap(),
            Subscription::new("wild", 2, QoS::AtMostOnce),
        );
        let btopic = Topic::new("cost/steady").unwrap();
        assert_eq!(baseline.matches(&btopic).len(), 2);
        let (bmin, bmed, bmax, bmean) = settled_cost(&|| baseline.matches(&btopic).len(), 2);
        eprintln!(
            "B4-08 baseline per-match cost: min={bmin:.1}ns median={bmed:.1}ns max={bmax:.1}ns mean={bmean:.1}ns \
            ({MATCHES_PER_REPEAT} matches x {REPEATS} repeats)"
        );
        assert!(
            bmin > 0.0 && bmin.is_finite() && bmax.is_finite(),
            "baseline per-match cost must report positive finite ns/match"
        );

        let router = Router::new();
        router.subscribe(
            &TopicFilter::new("cost/steady").unwrap(),
            Subscription::new("steady", 1, QoS::AtMostOnce),
        );
        router.subscribe(
            &TopicFilter::new("cost/+").unwrap(),
            Subscription::new("wild", 2, QoS::AtMostOnce),
        );
        let topic = Topic::new("cost/steady").unwrap();
        assert_eq!(router.matches(&topic).len(), 2);

        let mut per_match_ns = Vec::with_capacity(REPEATS);
        for _ in 0..REPEATS {
            let start = Instant::now();
            let mut sink = 0usize;
            for _ in 0..MATCHES_PER_REPEAT {
                sink += router.matches(&topic).len();
            }
            std::hint::black_box(sink);
            assert_eq!(sink, 2 * MATCHES_PER_REPEAT);
            let ns = start.elapsed().as_secs_f64() * 1e9 / MATCHES_PER_REPEAT as f64;
            per_match_ns.push(ns);
        }
        per_match_ns.sort_by(|a, b| a.total_cmp(b));
        let min = per_match_ns[0];
        let median = per_match_ns[REPEATS / 2];
        let max = per_match_ns[REPEATS - 1];
        let mean = per_match_ns.iter().sum::<f64>() / REPEATS as f64;
        eprintln!(
            "B4-08 per-match cost: min={min:.1}ns median={median:.1}ns max={max:.1}ns mean={mean:.1}ns \
            ({MATCHES_PER_REPEAT} matches x {REPEATS} repeats)"
        );
        assert!(
            min > 0.0 && min.is_finite() && max.is_finite(),
            "per-match cost must report positive finite ns/match"
        );
        assert!(
            (mean - median).abs() <= median.max(1.0) * 10.0,
            "per-match repeats must be broadly consistent"
        );
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

    #[test]
    fn rewrite_publish_capture_group_rewrites_and_miss_passes_through() {
        let router = Router::new();
        router
            .set_rewrite_rules(vec![RewriteRuleConfig::new(
                "^sensors/(.*)$",
                "devices/$1",
                RewriteScope::Publish,
            )])
            .expect("valid rule installs");
        // Fails before the B4-04 implementation: no rewrite existed, so
        // the topic passed through unchanged.
        assert_eq!(
            router.rewrite_publish("sensors/temp"),
            Some("devices/temp".to_string())
        );
        assert_eq!(router.rewrite_publish("other/temp"), None);
        let stats = router.rewrite_stats();
        assert_eq!(stats.rules, 1);
        assert_eq!(stats.rewritten, 1);
        assert_eq!(stats.passthrough, 1);
        assert_eq!(stats.budget_exceeded, 0);
    }

    #[test]
    fn rewrite_scopes_fire_only_in_their_direction() {
        let router = Router::new();
        router
            .set_rewrite_rules(vec![
                RewriteRuleConfig::new("^p/(.*)$", "pub/$1", RewriteScope::Publish),
                RewriteRuleConfig::new("^s/(.*)$", "sub/$1", RewriteScope::Subscribe),
                RewriteRuleConfig::new("^b/(.*)$", "both/$1", RewriteScope::Both),
            ])
            .expect("valid rules install");
        // Publish-scoped rule fires on publish, never on subscribe.
        assert_eq!(router.rewrite_publish("p/a"), Some("pub/a".to_string()));
        assert_eq!(router.rewrite_subscribe("p/a"), None);
        // Subscribe-scoped rule fires on subscribe, never on publish.
        assert_eq!(router.rewrite_subscribe("s/a"), Some("sub/a".to_string()));
        assert_eq!(router.rewrite_publish("s/a"), None);
        // Both-scoped rule fires in either direction.
        assert_eq!(router.rewrite_publish("b/a"), Some("both/a".to_string()));
        assert_eq!(router.rewrite_subscribe("b/a"), Some("both/a".to_string()));
        let stats = router.rewrite_stats();
        assert_eq!(stats.rewritten, 4);
        assert_eq!(stats.passthrough, 2);
    }

    #[test]
    fn rewrite_first_match_wins_in_configuration_order() {
        let router = Router::new();
        router
            .set_rewrite_rules(vec![
                RewriteRuleConfig::new("^(.*)$", "first/$1", RewriteScope::Both),
                RewriteRuleConfig::new("^(.*)$", "second/$1", RewriteScope::Both),
            ])
            .expect("valid rules install");
        assert_eq!(router.rewrite_publish("a/b"), Some("first/a/b".to_string()));
        assert_eq!(
            router.rewrite_subscribe("a/b"),
            Some("first/a/b".to_string())
        );
        // Reversing the configuration reverses the winner.
        router
            .set_rewrite_rules(vec![
                RewriteRuleConfig::new("^(.*)$", "second/$1", RewriteScope::Both),
                RewriteRuleConfig::new("^(.*)$", "first/$1", RewriteScope::Both),
            ])
            .expect("reinstall works");
        assert_eq!(
            router.rewrite_publish("a/b"),
            Some("second/a/b".to_string())
        );
    }

    #[test]
    fn rewrite_rule_count_bound_rejects_fail_closed() {
        assert_eq!(super::MAX_REWRITE_RULES, 64);
        let router = Router::new();
        let too_many: Vec<RewriteRuleConfig> = (0..(super::MAX_REWRITE_RULES + 1))
            .map(|i| {
                RewriteRuleConfig::new(format!("^overflow{i}/(.*)$"), "x/$1", RewriteScope::Both)
            })
            .collect();
        let err = router
            .set_rewrite_rules(too_many)
            .expect_err("over-cap install must fail");
        assert!(matches!(err, RewriteRuleError::TooManyRules(64)));
        // Rejected install leaves the table unchanged (fail closed).
        assert_eq!(router.rewrite_rule_count(), 0);
        assert_eq!(router.rewrite_publish("overflow0/a"), None);

        // Bad patterns also fail closed at configuration time.
        assert!(matches!(
            router.set_rewrite_rules(vec![RewriteRuleConfig::new(
                "(unclosed",
                "x",
                RewriteScope::Both
            )]),
            Err(RewriteRuleError::InvalidPattern(_))
        ));
        assert!(matches!(
            router.set_rewrite_rules(vec![RewriteRuleConfig::new("", "x", RewriteScope::Both)]),
            Err(RewriteRuleError::EmptyPattern)
        ));
        assert_eq!(router.rewrite_rule_count(), 0);
    }

    #[test]
    fn rewrite_budget_fails_closed_to_no_rewrite_with_counter() {
        let router = Router::new();
        // An input past the length bound never rewrites: counted, never
        // stalled or truncated.
        let huge = "t".repeat(super::MAX_REWRITE_LEN + 1);
        assert_eq!(router.rewrite_publish(&huge), None);
        assert_eq!(router.rewrite_stats().budget_exceeded, 1);
        assert_eq!(router.rewrite_stats().rewritten, 0);
        // A replacement that alone exceeds the bound is rejected at
        // configuration time (fail closed, table unchanged).
        let long_replacement = "r".repeat(super::MAX_REWRITE_LEN + 1);
        assert!(matches!(
            router.set_rewrite_rules(vec![RewriteRuleConfig::new(
                "^(.*)$",
                long_replacement,
                RewriteScope::Both
            )]),
            Err(RewriteRuleError::ReplacementTooLong(_))
        ));
        assert_eq!(router.rewrite_rule_count(), 0);
        // System-prefixed names pass through untouched so rewrite rules
        // can never change delayed or shared-subscription semantics.
        router
            .set_rewrite_rules(vec![RewriteRuleConfig::new(
                "^(.*)$",
                "rewritten/$1",
                RewriteScope::Both,
            )])
            .expect("catch-all installs");
        assert_eq!(router.rewrite_publish("$delayed/5/a/b"), None);
        assert_eq!(router.rewrite_subscribe("$share/g/a/b"), None);
    }

    #[test]
    fn rewrite_scope_parse_vectors() {
        assert_eq!(RewriteScope::parse("publish"), Some(RewriteScope::Publish));
        assert_eq!(
            RewriteScope::parse("subscribe"),
            Some(RewriteScope::Subscribe)
        );
        assert_eq!(RewriteScope::parse("both"), Some(RewriteScope::Both));
        assert_eq!(RewriteScope::parse("nope"), None);
        assert_eq!(RewriteScope::default(), RewriteScope::Both);
        assert_eq!(RewriteScope::Publish.as_str(), "publish");
        assert_eq!(RewriteScope::Subscribe.as_str(), "subscribe");
        assert_eq!(RewriteScope::Both.as_str(), "both");
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
