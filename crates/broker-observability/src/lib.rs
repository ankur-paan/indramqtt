use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_tracing() {
    let _ = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .try_init();
}

/// Lock-free node metrics. An instance lives in node `Shared` state and
/// is shared with the management API; per-instance (never global) so
/// multi-node in-process tests stay isolated.
#[derive(Debug, Default)]
pub struct Metrics {
    messages_received: AtomicU64,
    messages_forwarded: AtomicU64,
    messages_dropped: AtomicU64,
    rules_executed: AtomicU64,
    connections_active: AtomicI64,
    // Packet families (W1 `/metrics`, `/stats`, `/monitor_current`).
    connect_received: AtomicU64,
    connack_sent: AtomicU64,
    publish_received: AtomicU64,
    publish_sent: AtomicU64,
    subscribe_received: AtomicU64,
    suback_sent: AtomicU64,
    pingreq_received: AtomicU64,
    pingresp_sent: AtomicU64,
    // Measured BrokerLink frame bytes (never `count * 64`).
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    // Ingress QoS split.
    qos0_received: AtomicU64,
    qos1_received: AtomicU64,
    qos2_received: AtomicU64,
    // Delivery, overload and auth outcomes.
    delivered: AtomicU64,
    overload_dropped: AtomicU64,
    auth_failures: AtomicU64,
    // Silent QoS 0 loss points (PERF-10 drop accounting). Each bumps
    // exactly where its frame is already being dropped; drops that
    // happened before still happen, they are now counted.
    unknown_conn_dropped: AtomicU64,
    dead_mailbox_dropped: AtomicU64,
    detached_clean_dropped: AtomicU64,
    offline_queue_evicted: AtomicU64,
    // QoS 1 downlinks delivered live once but not tracked for redelivery
    // because the per-session inflight window (T-31) was full.
    inflight_dropped: AtomicU64,
    // QoS 1 downlinks spilled past the in-memory window into the bounded
    // per-session overflow buffer (B4-01). Each bump means one live
    // delivery that IS still tracked for DUP redelivery, unlike
    // `inflight_dropped`.
    inflight_spilled: AtomicU64,
    // Spilled overflow entries redelivered with DUP set on reconnect
    // replay (B4-01). Bumped once per spilled frame that reaches the new
    // mailbox; window replays keep counting through `delivered` only.
    inflight_spill_replayed: AtomicU64,
    // Spill evictions: live deliveries past both window and spill bounds,
    // left untracked. Each also bumps `inflight_dropped` so the old
    // untracked-delivery alert keeps firing.
    inflight_spill_evicted: AtomicU64,
    // Rule ingress queue spill-to-disk outcomes (B4-07). Each bumps
    // where its event is already being spilled, replayed, refused or
    // recovered; overflows that happened before still happen, they are
    // now counted instead of silent.
    rule_spill_spilled: AtomicU64,
    rule_spill_replayed: AtomicU64,
    rule_spill_dropped: AtomicU64,
    rule_spill_torn: AtomicU64,
    rule_spill_recovered: AtomicU64,
    // Kernel-to-edge delivery accounting (egress redesign, stage 0).
    // `messages_forwarded` counts admission into the shard transport
    // mailbox at `route()` time; `transport_sent` counts frames actually
    // written toward the edge by a successful batch write. The gap
    // between them is the hidden transport backlog: reconcile delivery
    // as `transport_sent = received_by_tool + still_queued +
    // shed_counted + discarded_at_close`, never from `forwarded` alone.
    transport_sent: AtomicU64,
    transport_send_failed: AtomicU64,
    // Egress queue bounds (D1-02 bounded QoS 0 backlog; the remaining
    // credit stages still read zero until their split lands).
    egress_qos0_shed: AtomicU64,
    /// QoS 0 sheds labelled by client id (D1-02). Every increment of
    /// [`Metrics::egress_qos0_shed`] through
    /// [`Metrics::inc_egress_qos0_shed_for`] also bumps the caller's
    /// entry here, so a drop is always visible per subscriber and never
    /// silent. Guarded by a plain mutex: bumps happen only when a drop
    /// happens (not on the fast delivery path), reads clone the map.
    qos0_shed_by_client: std::sync::RwLock<HashMap<String, u64>>,
    puback_deferred: AtomicU64,
    puback_deferred_released: AtomicU64,
    credit_clamped: AtomicU64,
    credit_exhausted: AtomicU64,
    // Edge flow-control frames observed. Counted on receipt today;
    // per-connection gating against them lands with the kernel queue
    // split, so no delivery decision may depend on this yet.
    credit_received: AtomicU64,
}

/// One consistent read of every counter for API handlers.
///
/// Plain data (no atomics): handlers copy once per request instead of
/// racing individual loads across a scrape.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub messages_received: u64,
    pub messages_forwarded: u64,
    pub messages_dropped: u64,
    pub rules_executed: u64,
    pub connections_active: i64,
    pub connect_received: u64,
    pub connack_sent: u64,
    pub publish_received: u64,
    pub publish_sent: u64,
    pub subscribe_received: u64,
    pub suback_sent: u64,
    pub pingreq_received: u64,
    pub pingresp_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub qos0_received: u64,
    pub qos1_received: u64,
    pub qos2_received: u64,
    pub delivered: u64,
    pub overload_dropped: u64,
    pub auth_failures: u64,
    pub unknown_conn_dropped: u64,
    pub dead_mailbox_dropped: u64,
    pub detached_clean_dropped: u64,
    pub offline_queue_evicted: u64,
    pub inflight_dropped: u64,
    pub inflight_spilled: u64,
    pub inflight_spill_replayed: u64,
    pub inflight_spill_evicted: u64,
    pub rule_spill_spilled: u64,
    pub rule_spill_replayed: u64,
    pub rule_spill_dropped: u64,
    pub rule_spill_torn: u64,
    pub rule_spill_recovered: u64,
    pub transport_sent: u64,
    pub transport_send_failed: u64,
    pub egress_qos0_shed: u64,
    pub puback_deferred: u64,
    pub puback_deferred_released: u64,
    pub credit_clamped: u64,
    pub credit_exhausted: u64,
    pub credit_received: u64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// One MQTT ingress message accepted over BrokerLink.
    pub fn inc_messages_received(&self) -> u64 {
        self.messages_received.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// One `PublishOut` frame admitted into the shard transport mailbox
    /// at `route()` time. This is transport enqueue, not edge arrival:
    /// compare with `transport_sent` for what actually reached the edge.
    pub fn inc_messages_forwarded(&self) -> u64 {
        self.inc_messages_forwarded_by(1)
    }

    pub fn inc_messages_forwarded_by(&self, n: u64) -> u64 {
        self.messages_forwarded.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One ingress message dropped before fan-out (quota/rate policing).
    pub fn inc_messages_dropped(&self) -> u64 {
        self.messages_dropped.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// One rule whose filter matched at ingress (regardless of actions).
    pub fn inc_rules_executed(&self) -> u64 {
        self.inc_rules_executed_by(1)
    }

    pub fn inc_rules_executed_by(&self, n: u64) -> u64 {
        self.rules_executed.fetch_add(n, Ordering::Relaxed) + n
    }

    pub fn inc_connections(&self) -> i64 {
        self.connections_active.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn dec_connections(&self) -> i64 {
        self.connections_active.fetch_sub(1, Ordering::Relaxed) - 1
    }

    /// Reconcile the gauge (e.g. after a state rebuild).
    pub fn set_active_connections(&self, count: u64) {
        self.connections_active
            .store(count as i64, Ordering::Relaxed);
    }

    pub fn messages_received(&self) -> u64 {
        self.messages_received.load(Ordering::Relaxed)
    }

    pub fn messages_forwarded(&self) -> u64 {
        self.messages_forwarded.load(Ordering::Relaxed)
    }

    pub fn messages_dropped(&self) -> u64 {
        self.messages_dropped.load(Ordering::Relaxed)
    }

    pub fn rules_executed(&self) -> u64 {
        self.rules_executed.load(Ordering::Relaxed)
    }

    pub fn connections_active(&self) -> i64 {
        self.connections_active.load(Ordering::Relaxed)
    }

    /// One CONNECT packet (`BindConnection`) received from the edge.
    pub fn inc_connect_received(&self) -> u64 {
        self.inc_connect_received_by(1)
    }

    pub fn inc_connect_received_by(&self, n: u64) -> u64 {
        self.connect_received.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One CONNACK (`SessionBinding`) sent toward the edge, including
    /// rejections (bad password, anonymous denied): every bind is answered.
    pub fn inc_connack_sent(&self) -> u64 {
        self.inc_connack_sent_by(1)
    }

    pub fn inc_connack_sent_by(&self, n: u64) -> u64 {
        self.connack_sent.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One PUBLISH packet (`PublishIn`) received, before validation.
    pub fn inc_publish_received(&self) -> u64 {
        self.inc_publish_received_by(1)
    }

    pub fn inc_publish_received_by(&self, n: u64) -> u64 {
        self.publish_received.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One `PublishOut` delivery fanned out toward a live edge connection.
    pub fn inc_publish_sent(&self) -> u64 {
        self.inc_publish_sent_by(1)
    }

    pub fn inc_publish_sent_by(&self, n: u64) -> u64 {
        self.publish_sent.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One SUBSCRIBE packet (`SubscribeIn`) received, before validation.
    pub fn inc_subscribe_received(&self) -> u64 {
        self.inc_subscribe_received_by(1)
    }

    pub fn inc_subscribe_received_by(&self, n: u64) -> u64 {
        self.subscribe_received.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One SUBACK (`SubAckOut`) sent toward the edge.
    pub fn inc_suback_sent(&self) -> u64 {
        self.inc_suback_sent_by(1)
    }

    pub fn inc_suback_sent_by(&self, n: u64) -> u64 {
        self.suback_sent.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One PINGREQ (`Ping`) received from the edge.
    pub fn inc_pingreq_received(&self) -> u64 {
        self.inc_pingreq_received_by(1)
    }

    pub fn inc_pingreq_received_by(&self, n: u64) -> u64 {
        self.pingreq_received.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One PINGRESP (`Pong`) sent toward the edge.
    pub fn inc_pingresp_sent(&self) -> u64 {
        self.inc_pingresp_sent_by(1)
    }

    pub fn inc_pingresp_sent_by(&self, n: u64) -> u64 {
        self.pingresp_sent.fetch_add(n, Ordering::Relaxed) + n
    }

    /// Ingress bytes measured from real BrokerLink frame lengths.
    pub fn inc_bytes_received(&self) -> u64 {
        self.inc_bytes_received_by(1)
    }

    pub fn inc_bytes_received_by(&self, n: u64) -> u64 {
        self.bytes_received.fetch_add(n, Ordering::Relaxed) + n
    }

    /// Egress `PublishOut` bytes measured from real frame lengths.
    pub fn inc_bytes_sent(&self) -> u64 {
        self.inc_bytes_sent_by(1)
    }

    pub fn inc_bytes_sent_by(&self, n: u64) -> u64 {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One ingress publish with QoS 0 accepted for routing.
    pub fn inc_qos0_received(&self) -> u64 {
        self.inc_qos0_received_by(1)
    }

    pub fn inc_qos0_received_by(&self, n: u64) -> u64 {
        self.qos0_received.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One ingress publish with QoS 1 accepted for routing.
    pub fn inc_qos1_received(&self) -> u64 {
        self.inc_qos1_received_by(1)
    }

    pub fn inc_qos1_received_by(&self, n: u64) -> u64 {
        self.qos1_received.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One ingress publish with QoS 2 accepted for routing.
    pub fn inc_qos2_received(&self) -> u64 {
        self.inc_qos2_received_by(1)
    }

    pub fn inc_qos2_received_by(&self, n: u64) -> u64 {
        self.qos2_received.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One live delivery toward an edge connection (mirrors `publish_sent`
    /// until per-ack tracking lands; offline buffering counts on replay).
    pub fn inc_delivered(&self) -> u64 {
        self.inc_delivered_by(1)
    }

    pub fn inc_delivered_by(&self, n: u64) -> u64 {
        self.delivered.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One ingress message dropped by overload/quota policing.
    pub fn inc_overload_dropped(&self) -> u64 {
        self.inc_overload_dropped_by(1)
    }

    pub fn inc_overload_dropped_by(&self, n: u64) -> u64 {
        self.overload_dropped.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One bind rejected on credential verification (bad password or
    /// anonymous denied while users exist).
    pub fn inc_auth_failures(&self) -> u64 {
        self.inc_auth_failures_by(1)
    }

    pub fn inc_auth_failures_by(&self, n: u64) -> u64 {
        self.auth_failures.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One frame routed to a `conn_id` with no registered mailbox
    /// (`ConnTable::route` unknown-destination drop).
    pub fn inc_unknown_conn_dropped(&self) -> u64 {
        self.inc_unknown_conn_dropped_by(1)
    }

    pub fn inc_unknown_conn_dropped_by(&self, n: u64) -> u64 {
        self.unknown_conn_dropped.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One frame sent into a dead mailbox whose receiver is gone
    /// (`ConnTable::route` send-failure drop; the destination is
    /// unregistered as before).
    pub fn inc_dead_mailbox_dropped(&self) -> u64 {
        self.inc_dead_mailbox_dropped_by(1)
    }

    pub fn inc_dead_mailbox_dropped_by(&self, n: u64) -> u64 {
        self.dead_mailbox_dropped.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One frame for a detached clean session: no live connection and
    /// no offline queue, so the frame is dropped.
    pub fn inc_detached_clean_dropped(&self) -> u64 {
        self.inc_detached_clean_dropped_by(1)
    }

    pub fn inc_detached_clean_dropped_by(&self, n: u64) -> u64 {
        self.detached_clean_dropped.fetch_add(n, Ordering::Relaxed) + n
    }

    /// Offline-queue evictions for detached durable sessions: each
    /// counted message is an oldest entry displaced by a newer arrival
    /// (the queueing itself is unchanged).
    pub fn inc_offline_queue_evicted(&self) -> u64 {
        self.inc_offline_queue_evicted_by(1)
    }

    pub fn inc_offline_queue_evicted_by(&self, n: u64) -> u64 {
        self.offline_queue_evicted.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One QoS 1 downlink delivered live but left untracked because the
    /// per-session inflight window was full (T-31 drop-newest-from-track).
    pub fn inc_inflight_dropped(&self) -> u64 {
        self.inc_inflight_dropped_by(1)
    }

    pub fn inc_inflight_dropped_by(&self, n: u64) -> u64 {
        self.inflight_dropped.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One QoS 1 downlink spilled past the window into the bounded
    /// overflow buffer (B4-01). The live delivery still goes out once and
    /// stays tracked for DUP redelivery.
    pub fn inc_inflight_spilled(&self) -> u64 {
        self.inc_inflight_spilled_by(1)
    }

    pub fn inc_inflight_spilled_by(&self, n: u64) -> u64 {
        self.inflight_spilled.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One spilled overflow entry redelivered with DUP set on reconnect
    /// replay (B4-01).
    pub fn inc_inflight_spill_replayed(&self) -> u64 {
        self.inc_inflight_spill_replayed_by(1)
    }

    pub fn inc_inflight_spill_replayed_by(&self, n: u64) -> u64 {
        self.inflight_spill_replayed.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One live delivery past both window and spill bounds, left
    /// untracked. Callers also bump `inflight_dropped` so the legacy
    /// untracked-delivery counter keeps covering every silent loss.
    pub fn inc_inflight_spill_evicted(&self) -> u64 {
        self.inc_inflight_spill_evicted_by(1)
    }

    pub fn inc_inflight_spill_evicted_by(&self, n: u64) -> u64 {
        self.inflight_spill_evicted.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One rule-ingress event appended to the on-disk spill buffer
    /// instead of erroring (B4-07).
    pub fn inc_rule_spill_spilled(&self) -> u64 {
        self.inc_rule_spill_spilled_by(1)
    }

    pub fn inc_rule_spill_spilled_by(&self, n: u64) -> u64 {
        self.rule_spill_spilled.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One spilled rule-ingress event replayed to the consumer in order
    /// (B4-07).
    pub fn inc_rule_spill_replayed(&self) -> u64 {
        self.inc_rule_spill_replayed_by(1)
    }

    pub fn inc_rule_spill_replayed_by(&self, n: u64) -> u64 {
        self.rule_spill_replayed.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One rule-ingress overflow event refused: no spill directory, an
    /// oversize event, the disk cap, or an I/O error (B4-07, fail
    /// closed and counted).
    pub fn inc_rule_spill_dropped(&self) -> u64 {
        self.inc_rule_spill_dropped_by(1)
    }

    pub fn inc_rule_spill_dropped_by(&self, n: u64) -> u64 {
        self.rule_spill_dropped.fetch_add(n, Ordering::Relaxed) + n
    }

    /// One torn spill tail truncated (plus later segments discarded)
    /// on recovery or replay (B4-07).
    pub fn inc_rule_spill_torn(&self) -> u64 {
        self.inc_rule_spill_torn_by(1)
    }

    pub fn inc_rule_spill_torn_by(&self, n: u64) -> u64 {
        self.rule_spill_torn.fetch_add(n, Ordering::Relaxed) + n
    }

    /// Rule-ingress events found on disk when a spill directory opened
    /// (B4-07 restart survival).
    pub fn inc_rule_spill_recovered_by(&self, n: u64) -> u64 {
        self.rule_spill_recovered.fetch_add(n, Ordering::Relaxed) + n
    }

    /// Frames actually written toward the edge by a successful transport
    /// batch write (compare with `messages_forwarded`, which counts
    /// admission into the transport mailbox).
    pub fn inc_transport_sent_by(&self, n: u64) -> u64 {
        self.transport_sent.fetch_add(n, Ordering::Relaxed) + n
    }

    /// Failed transport batch writes toward the edge (the owning task
    /// ends after one; its connections detach through the existing path).
    pub fn inc_transport_send_failed(&self) -> u64 {
        self.transport_send_failed.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// QoS 0 frames shed at route time by the per-subscriber egress
    /// bound (D1-02). Counts every oldest-dropped frame; the per-client
    /// label is recorded separately via
    /// [`Metrics::inc_egress_qos0_shed_for`].
    pub fn inc_egress_qos0_shed(&self) -> u64 {
        self.egress_qos0_shed.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Count one QoS 0 shed for `client_id`: bumps the global
    /// `egress_qos0_shed` and the per-client entry together so the two
    /// can never drift. Returns the new global total.
    pub fn inc_egress_qos0_shed_for(&self, client_id: &str) -> u64 {
        let total = self.egress_qos0_shed.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(mut by_client) = self.qos0_shed_by_client.write() {
            *by_client.entry(client_id.to_string()).or_insert(0) += 1;
        }
        total
    }

    /// Sheds recorded for one client id, if any.
    pub fn egress_qos0_shed_for(&self, client_id: &str) -> u64 {
        self.qos0_shed_by_client
            .read()
            .map(|by_client| by_client.get(client_id).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    /// Snapshot of every per-client shed count, keyed by client id.
    pub fn egress_qos0_shed_by_client(&self) -> HashMap<String, u64> {
        self.qos0_shed_by_client
            .read()
            .map(|by_client| by_client.clone())
            .unwrap_or_default()
    }

    /// QoS 1 publishes whose PUBACK is deferred for credit (fires with
    /// the kernel queue split; zero until then).
    pub fn inc_puback_deferred(&self) -> u64 {
        self.puback_deferred.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Deferred PUBACKs released after credit arrived.
    pub fn inc_puback_deferred_released(&self) -> u64 {
        self.puback_deferred_released
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    /// Edge flow-control snapshots applied to a kernel credit balance
    /// (fires with the kernel queue split; zero until then).
    pub fn inc_credit_clamped(&self) -> u64 {
        self.credit_clamped.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Route refusals for exhausted credit (fires with the kernel queue
    /// split; zero until then).
    pub fn inc_credit_exhausted(&self) -> u64 {
        self.credit_exhausted.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Edge flow-control frames observed (counted today, gating later).
    pub fn inc_credit_received(&self) -> u64 {
        self.credit_received.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn connect_received(&self) -> u64 {
        self.connect_received.load(Ordering::Relaxed)
    }

    pub fn connack_sent(&self) -> u64 {
        self.connack_sent.load(Ordering::Relaxed)
    }

    pub fn publish_received(&self) -> u64 {
        self.publish_received.load(Ordering::Relaxed)
    }

    pub fn publish_sent(&self) -> u64 {
        self.publish_sent.load(Ordering::Relaxed)
    }

    pub fn subscribe_received(&self) -> u64 {
        self.subscribe_received.load(Ordering::Relaxed)
    }

    pub fn suback_sent(&self) -> u64 {
        self.suback_sent.load(Ordering::Relaxed)
    }

    pub fn pingreq_received(&self) -> u64 {
        self.pingreq_received.load(Ordering::Relaxed)
    }

    pub fn pingresp_sent(&self) -> u64 {
        self.pingresp_sent.load(Ordering::Relaxed)
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn qos0_received(&self) -> u64 {
        self.qos0_received.load(Ordering::Relaxed)
    }

    pub fn qos1_received(&self) -> u64 {
        self.qos1_received.load(Ordering::Relaxed)
    }

    pub fn qos2_received(&self) -> u64 {
        self.qos2_received.load(Ordering::Relaxed)
    }

    pub fn delivered(&self) -> u64 {
        self.delivered.load(Ordering::Relaxed)
    }

    pub fn overload_dropped(&self) -> u64 {
        self.overload_dropped.load(Ordering::Relaxed)
    }

    pub fn auth_failures(&self) -> u64 {
        self.auth_failures.load(Ordering::Relaxed)
    }

    pub fn unknown_conn_dropped(&self) -> u64 {
        self.unknown_conn_dropped.load(Ordering::Relaxed)
    }

    pub fn dead_mailbox_dropped(&self) -> u64 {
        self.dead_mailbox_dropped.load(Ordering::Relaxed)
    }

    pub fn detached_clean_dropped(&self) -> u64 {
        self.detached_clean_dropped.load(Ordering::Relaxed)
    }

    pub fn offline_queue_evicted(&self) -> u64 {
        self.offline_queue_evicted.load(Ordering::Relaxed)
    }

    pub fn inflight_dropped(&self) -> u64 {
        self.inflight_dropped.load(Ordering::Relaxed)
    }

    pub fn inflight_spilled(&self) -> u64 {
        self.inflight_spilled.load(Ordering::Relaxed)
    }

    pub fn inflight_spill_replayed(&self) -> u64 {
        self.inflight_spill_replayed.load(Ordering::Relaxed)
    }

    pub fn inflight_spill_evicted(&self) -> u64 {
        self.inflight_spill_evicted.load(Ordering::Relaxed)
    }

    pub fn rule_spill_spilled(&self) -> u64 {
        self.rule_spill_spilled.load(Ordering::Relaxed)
    }

    pub fn rule_spill_replayed(&self) -> u64 {
        self.rule_spill_replayed.load(Ordering::Relaxed)
    }

    pub fn rule_spill_dropped(&self) -> u64 {
        self.rule_spill_dropped.load(Ordering::Relaxed)
    }

    pub fn rule_spill_torn(&self) -> u64 {
        self.rule_spill_torn.load(Ordering::Relaxed)
    }

    pub fn rule_spill_recovered(&self) -> u64 {
        self.rule_spill_recovered.load(Ordering::Relaxed)
    }

    pub fn transport_sent(&self) -> u64 {
        self.transport_sent.load(Ordering::Relaxed)
    }

    pub fn transport_send_failed(&self) -> u64 {
        self.transport_send_failed.load(Ordering::Relaxed)
    }

    pub fn egress_qos0_shed(&self) -> u64 {
        self.egress_qos0_shed.load(Ordering::Relaxed)
    }

    pub fn puback_deferred(&self) -> u64 {
        self.puback_deferred.load(Ordering::Relaxed)
    }

    pub fn puback_deferred_released(&self) -> u64 {
        self.puback_deferred_released.load(Ordering::Relaxed)
    }

    pub fn credit_clamped(&self) -> u64 {
        self.credit_clamped.load(Ordering::Relaxed)
    }

    pub fn credit_exhausted(&self) -> u64 {
        self.credit_exhausted.load(Ordering::Relaxed)
    }

    pub fn credit_received(&self) -> u64 {
        self.credit_received.load(Ordering::Relaxed)
    }

    /// Copy every counter in one call for API handlers.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            messages_received: self.messages_received(),
            messages_forwarded: self.messages_forwarded(),
            messages_dropped: self.messages_dropped(),
            rules_executed: self.rules_executed(),
            connections_active: self.connections_active(),
            connect_received: self.connect_received(),
            connack_sent: self.connack_sent(),
            publish_received: self.publish_received(),
            publish_sent: self.publish_sent(),
            subscribe_received: self.subscribe_received(),
            suback_sent: self.suback_sent(),
            pingreq_received: self.pingreq_received(),
            pingresp_sent: self.pingresp_sent(),
            bytes_received: self.bytes_received(),
            bytes_sent: self.bytes_sent(),
            qos0_received: self.qos0_received(),
            qos1_received: self.qos1_received(),
            qos2_received: self.qos2_received(),
            delivered: self.delivered(),
            overload_dropped: self.overload_dropped(),
            auth_failures: self.auth_failures(),
            unknown_conn_dropped: self.unknown_conn_dropped(),
            dead_mailbox_dropped: self.dead_mailbox_dropped(),
            detached_clean_dropped: self.detached_clean_dropped(),
            offline_queue_evicted: self.offline_queue_evicted(),
            inflight_dropped: self.inflight_dropped(),
            inflight_spilled: self.inflight_spilled(),
            inflight_spill_replayed: self.inflight_spill_replayed(),
            inflight_spill_evicted: self.inflight_spill_evicted(),
            rule_spill_spilled: self.rule_spill_spilled(),
            rule_spill_replayed: self.rule_spill_replayed(),
            rule_spill_dropped: self.rule_spill_dropped(),
            rule_spill_torn: self.rule_spill_torn(),
            rule_spill_recovered: self.rule_spill_recovered(),
            transport_sent: self.transport_sent(),
            transport_send_failed: self.transport_send_failed(),
            egress_qos0_shed: self.egress_qos0_shed(),
            puback_deferred: self.puback_deferred(),
            puback_deferred_released: self.puback_deferred_released(),
            credit_clamped: self.credit_clamped(),
            credit_exhausted: self.credit_exhausted(),
            credit_received: self.credit_received(),
        }
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render_prometheus_metrics(&self) -> String {
        format!(
            "# HELP indramqtt_messages_received_total Total MQTT ingress messages accepted over BrokerLink.\n\
             # TYPE indramqtt_messages_received_total counter\n\
             indramqtt_messages_received_total {}\n\
              # HELP indramqtt_messages_forwarded_total Total PublishOut frames admitted into the shard transport mailbox (transport enqueue, not edge arrival; compare with transport_sent).\n\
             # TYPE indramqtt_messages_forwarded_total counter\n\
             indramqtt_messages_forwarded_total {}\n\
             # HELP indramqtt_messages_dropped_total Total ingress messages dropped by quota/rate policing.\n\
             # TYPE indramqtt_messages_dropped_total counter\n\
             indramqtt_messages_dropped_total {}\n\
             # HELP indramqtt_rules_executed_total Total ingress rules whose filter matched.\n\
             # TYPE indramqtt_rules_executed_total counter\n\
             indramqtt_rules_executed_total {}\n\
              # HELP indramqtt_connections_active Currently bound edge connections.\n\
              # TYPE indramqtt_connections_active gauge\n\
              indramqtt_connections_active {}\n\
              # HELP indramqtt_unknown_conn_dropped_total Frames routed to a conn_id with no registered mailbox.\n\
              # TYPE indramqtt_unknown_conn_dropped_total counter\n\
              indramqtt_unknown_conn_dropped_total {}\n\
              # HELP indramqtt_dead_mailbox_dropped_total Frames sent into a dead mailbox whose receiver is gone.\n\
              # TYPE indramqtt_dead_mailbox_dropped_total counter\n\
              indramqtt_dead_mailbox_dropped_total {}\n\
              # HELP indramqtt_detached_clean_dropped_total Frames dropped for detached clean sessions.\n\
              # TYPE indramqtt_detached_clean_dropped_total counter\n\
              indramqtt_detached_clean_dropped_total {}\n\
              # HELP indramqtt_offline_queue_evicted_total Offline-queue entries evicted for detached durable sessions.\n\
              # TYPE indramqtt_offline_queue_evicted_total counter\n\
              indramqtt_offline_queue_evicted_total {}\n\
              # HELP indramqtt_inflight_dropped_total QoS 1 downlinks delivered live but untracked for redelivery (per-session inflight window full).\n\
              # TYPE indramqtt_inflight_dropped_total counter\n\
              indramqtt_inflight_dropped_total {}\n\
              # HELP indramqtt_inflight_spilled_total QoS 1 downlinks spilled past the window into the bounded overflow buffer (still tracked for DUP redelivery).\n\
              # TYPE indramqtt_inflight_spilled_total counter\n\
              indramqtt_inflight_spilled_total {}\n\
              # HELP indramqtt_inflight_spill_replayed_total Spilled QoS 1 entries redelivered with DUP set on reconnect replay.\n\
              # TYPE indramqtt_inflight_spill_replayed_total counter\n\
              indramqtt_inflight_spill_replayed_total {}\n\
              # HELP indramqtt_inflight_spill_evicted_total Live QoS 1 deliveries past both window and spill bounds, left untracked.\n\
              # TYPE indramqtt_inflight_spill_evicted_total counter\n\
              indramqtt_inflight_spill_evicted_total {}\n\
              # HELP indramqtt_rule_spill_spilled_total Rule-ingress events appended to the on-disk spill buffer instead of erroring.\n\
              # TYPE indramqtt_rule_spill_spilled_total counter\n\
              indramqtt_rule_spill_spilled_total {}\n\
              # HELP indramqtt_rule_spill_replayed_total Spilled rule-ingress events replayed to the consumer in order.\n\
              # TYPE indramqtt_rule_spill_replayed_total counter\n\
              indramqtt_rule_spill_replayed_total {}\n\
              # HELP indramqtt_rule_spill_dropped_total Rule-ingress overflow events refused (no spill directory, oversize event, disk cap, I/O error).\n\
              # TYPE indramqtt_rule_spill_dropped_total counter\n\
              indramqtt_rule_spill_dropped_total {}\n\
              # HELP indramqtt_rule_spill_torn_total Torn spill tails truncated (plus later segments discarded) on recovery or replay.\n\
              # TYPE indramqtt_rule_spill_torn_total counter\n\
              indramqtt_rule_spill_torn_total {}\n\
              # HELP indramqtt_rule_spill_recovered_total Rule-ingress events found on disk when a spill directory opened.\n\
              # TYPE indramqtt_rule_spill_recovered_total counter\n\
              indramqtt_rule_spill_recovered_total {}\n\
              # HELP indramqtt_transport_sent_total Frames actually written toward the edge by successful transport batch writes.\n\
              # TYPE indramqtt_transport_sent_total counter\n\
              indramqtt_transport_sent_total {}\n\
              # HELP indramqtt_transport_send_failed_total Failed transport batch writes toward the edge.\n\
              # TYPE indramqtt_transport_send_failed_total counter\n\
              indramqtt_transport_send_failed_total {}\n\
              # HELP indramqtt_egress_qos0_shed_total QoS 0 frames shed at route time by the per-connection egress bound.\n\
              # TYPE indramqtt_egress_qos0_shed_total counter\n\
              indramqtt_egress_qos0_shed_total {}\n\
              # HELP indramqtt_puback_deferred_total QoS 1 publishes whose PUBACK is deferred for credit.\n\
              # TYPE indramqtt_puback_deferred_total counter\n\
              indramqtt_puback_deferred_total {}\n\
              # HELP indramqtt_puback_deferred_released_total Deferred PUBACKs released after credit arrived.\n\
              # TYPE indramqtt_puback_deferred_released_total counter\n\
              indramqtt_puback_deferred_released_total {}\n\
              # HELP indramqtt_credit_clamped_total Edge flow-control snapshots applied to a kernel credit balance.\n\
              # TYPE indramqtt_credit_clamped_total counter\n\
              indramqtt_credit_clamped_total {}\n\
              # HELP indramqtt_credit_exhausted_total Route refusals for exhausted credit.\n\
              # TYPE indramqtt_credit_exhausted_total counter\n\
              indramqtt_credit_exhausted_total {}\n\
              # HELP indramqtt_credit_received_total Edge flow-control frames observed.\n\
              # TYPE indramqtt_credit_received_total counter\n\
              indramqtt_credit_received_total {}\n",
            self.messages_received(),
            self.messages_forwarded(),
            self.messages_dropped(),
            self.rules_executed(),
            self.connections_active(),
            self.unknown_conn_dropped(),
            self.dead_mailbox_dropped(),
            self.detached_clean_dropped(),
            self.offline_queue_evicted(),
            self.inflight_dropped(),
            self.inflight_spilled(),
            self.inflight_spill_replayed(),
            self.inflight_spill_evicted(),
            self.rule_spill_spilled(),
            self.rule_spill_replayed(),
            self.rule_spill_dropped(),
            self.rule_spill_torn(),
            self.rule_spill_recovered(),
            self.transport_sent(),
            self.transport_send_failed(),
            self.egress_qos0_shed(),
            self.puback_deferred(),
            self.puback_deferred_released(),
            self.credit_clamped(),
            self.credit_exhausted(),
            self.credit_received(),
        )
    }
}

/// Node readiness flag behind `GET /status`.
///
/// Single atomic bool, set once the management plane can answer. Reads are
/// one relaxed atomic load per request (constant time), writes happen only
/// at lifecycle points (boot ready, shutdown draining). Per-instance like
/// [`Metrics`] (never global) so multi-node in-process tests stay isolated.
///
/// Store bounds: exactly one bool; no map, queue or buffer grows with
/// connections, sessions or subscriptions. Management-plane only; never
/// touched on the per-message path, so fan-out and fan-in take no new lock
/// and no new buffering.
#[derive(Debug)]
pub struct NodeReadiness {
    ready: AtomicBool,
}

impl NodeReadiness {
    /// Ready flag, set: the node is up whenever the management plane
    /// answers, which is exactly when this handler can run.
    pub fn new() -> Self {
        Self {
            ready: AtomicBool::new(true),
        }
    }

    /// Mark the node ready (up). Constant-time single store.
    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Relaxed);
    }

    /// Mark the node not ready (down). Constant-time single store.
    pub fn mark_not_ready(&self) {
        self.ready.store(false, Ordering::Relaxed);
    }

    /// Constant-time single load for the status handler.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }
}

impl Default for NodeReadiness {
    fn default() -> Self {
        Self::new()
    }
}

/// Gauge-plus-high-water-mark store for the documented `/stats` semantics.
///
/// Gauges move only through the explicit `set_*` calls from kernel
/// lifecycle points; each `set_*` also raises the matching `*_max` via
/// an atomic max. Maxima never fall except through `reset_maxima()`
/// (explicit reset endpoints; no auto-decay). Per-instance like
/// [`Metrics`] (never global) so multi-node in-process tests stay
/// isolated.
#[derive(Debug, Default)]
pub struct StatsStore {
    connections: AtomicU64,
    connections_max: AtomicU64,
    subscriptions: AtomicU64,
    subscriptions_max: AtomicU64,
    topics: AtomicU64,
    topics_max: AtomicU64,
    retained: AtomicU64,
    retained_max: AtomicU64,
}

/// One consistent read of every gauge and maximum for API handlers.
///
/// Plain data (no atomics): handlers copy once per request instead of
/// racing individual loads across a scrape.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub connections: u64,
    pub connections_max: u64,
    pub subscriptions: u64,
    pub subscriptions_max: u64,
    pub topics: u64,
    pub topics_max: u64,
    pub retained: u64,
    pub retained_max: u64,
}

/// Raise `atom` to at least `value` (compare-and-swap loop).
fn raise_max(atom: &AtomicU64, value: u64) {
    let mut current = atom.load(Ordering::Relaxed);
    while current < value {
        match atom.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

impl StatsStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current bound edge connections (mirrors `connections_active`).
    pub fn set_connections(&self, count: u64) {
        self.connections.store(count, Ordering::Relaxed);
        raise_max(&self.connections_max, count);
    }

    /// Current subscriptions across active sessions.
    pub fn set_subscriptions(&self, count: u64) {
        self.subscriptions.store(count, Ordering::Relaxed);
        raise_max(&self.subscriptions_max, count);
    }

    /// Current distinct topic filters across active sessions.
    pub fn set_topics(&self, count: u64) {
        self.topics.store(count, Ordering::Relaxed);
        raise_max(&self.topics_max, count);
    }

    /// Current retained topics in the retained store.
    pub fn set_retained(&self, count: u64) {
        self.retained.store(count, Ordering::Relaxed);
        raise_max(&self.retained_max, count);
    }

    /// Re-baseline every maximum to its current gauge (explicit reset
    /// endpoints and tests; the only way maxima fall).
    pub fn reset_maxima(&self) {
        self.connections_max
            .store(self.connections.load(Ordering::Relaxed), Ordering::Relaxed);
        self.subscriptions_max.store(
            self.subscriptions.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.topics_max
            .store(self.topics.load(Ordering::Relaxed), Ordering::Relaxed);
        self.retained_max
            .store(self.retained.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    pub fn connections_max(&self) -> u64 {
        self.connections_max.load(Ordering::Relaxed)
    }

    pub fn subscriptions(&self) -> u64 {
        self.subscriptions.load(Ordering::Relaxed)
    }

    pub fn subscriptions_max(&self) -> u64 {
        self.subscriptions_max.load(Ordering::Relaxed)
    }

    pub fn topics(&self) -> u64 {
        self.topics.load(Ordering::Relaxed)
    }

    pub fn topics_max(&self) -> u64 {
        self.topics_max.load(Ordering::Relaxed)
    }

    pub fn retained(&self) -> u64 {
        self.retained.load(Ordering::Relaxed)
    }

    pub fn retained_max(&self) -> u64 {
        self.retained_max.load(Ordering::Relaxed)
    }

    /// Copy every gauge and maximum in one call for API handlers.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            connections: self.connections(),
            connections_max: self.connections_max(),
            subscriptions: self.subscriptions(),
            subscriptions_max: self.subscriptions_max(),
            topics: self.topics(),
            topics_max: self.topics_max(),
            retained: self.retained(),
            retained_max: self.retained_max(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_counters_and_gauge() {
        let metrics = Metrics::new();
        assert_eq!(metrics.inc_messages_received(), 1);
        assert_eq!(metrics.inc_messages_received(), 2);
        assert_eq!(metrics.inc_messages_forwarded_by(5), 5);
        assert_eq!(metrics.inc_messages_dropped(), 1);
        assert_eq!(metrics.messages_dropped(), 1);
        assert_eq!(metrics.inc_rules_executed_by(3), 3);
        assert_eq!(metrics.inc_connections(), 1);
        assert_eq!(metrics.inc_connections(), 2);
        assert_eq!(metrics.dec_connections(), 1);
        metrics.set_active_connections(42);
        assert_eq!(metrics.connections_active(), 42);

        let text = metrics.render_prometheus_metrics();
        assert!(text.contains("indramqtt_messages_received_total 2\n"));
        assert!(text.contains("indramqtt_messages_forwarded_total 5\n"));
        assert!(text.contains("indramqtt_messages_dropped_total 1\n"));
        assert!(text.contains("indramqtt_rules_executed_total 3\n"));
        assert!(text.contains("indramqtt_connections_active 42\n"));
        assert!(text.contains("# TYPE indramqtt_connections_active gauge\n"));
    }

    #[test]
    fn test_packet_counters_start_zero_and_increment() {
        let metrics = Metrics::new();
        assert_eq!(metrics.connect_received(), 0);
        assert_eq!(metrics.connack_sent(), 0);
        assert_eq!(metrics.publish_received(), 0);
        assert_eq!(metrics.publish_sent(), 0);
        assert_eq!(metrics.subscribe_received(), 0);
        assert_eq!(metrics.suback_sent(), 0);
        assert_eq!(metrics.pingreq_received(), 0);
        assert_eq!(metrics.pingresp_sent(), 0);

        assert_eq!(metrics.inc_connect_received(), 1);
        assert_eq!(metrics.inc_connack_sent(), 1);
        assert_eq!(metrics.inc_publish_received(), 1);
        assert_eq!(metrics.inc_publish_received(), 2);
        assert_eq!(metrics.inc_publish_sent_by(3), 3);
        assert_eq!(metrics.inc_subscribe_received(), 1);
        assert_eq!(metrics.inc_suback_sent(), 1);
        assert_eq!(metrics.inc_pingreq_received(), 1);
        assert_eq!(metrics.inc_pingresp_sent(), 1);

        assert_eq!(metrics.connect_received(), 1);
        assert_eq!(metrics.publish_received(), 2);
        assert_eq!(metrics.publish_sent(), 3);
        let snap = metrics.snapshot();
        assert_eq!(snap.connect_received, 1);
        assert_eq!(snap.connack_sent, 1);
        assert_eq!(snap.publish_received, 2);
        assert_eq!(snap.publish_sent, 3);
        assert_eq!(snap.subscribe_received, 1);
        assert_eq!(snap.suback_sent, 1);
        assert_eq!(snap.pingreq_received, 1);
        assert_eq!(snap.pingresp_sent, 1);
    }

    #[test]
    fn test_byte_counters_measure_real_frame_sizes() {
        let metrics = Metrics::new();
        assert_eq!(metrics.bytes_received(), 0);
        assert_eq!(metrics.bytes_sent(), 0);

        // Real BrokerLink frame lengths, never `count * 64`.
        assert_eq!(metrics.inc_bytes_received_by(128), 128);
        assert_eq!(metrics.inc_bytes_received_by(64), 192);
        assert_eq!(metrics.inc_bytes_sent_by(1024), 1024);
        assert_eq!(metrics.inc_bytes_sent(), 1025);

        assert_eq!(metrics.bytes_received(), 192);
        assert_eq!(metrics.bytes_sent(), 1025);
        let snap = metrics.snapshot();
        assert_eq!(snap.bytes_received, 192);
        assert_eq!(snap.bytes_sent, 1025);
    }

    #[test]
    fn test_qos_delivery_overload_auth_counters() {
        let metrics = Metrics::new();
        assert_eq!(metrics.qos0_received(), 0);
        assert_eq!(metrics.qos1_received(), 0);
        assert_eq!(metrics.qos2_received(), 0);
        assert_eq!(metrics.delivered(), 0);
        assert_eq!(metrics.overload_dropped(), 0);
        assert_eq!(metrics.auth_failures(), 0);

        assert_eq!(metrics.inc_qos0_received(), 1);
        assert_eq!(metrics.inc_qos1_received_by(2), 2);
        assert_eq!(metrics.inc_qos2_received(), 1);
        assert_eq!(metrics.inc_delivered_by(4), 4);
        assert_eq!(metrics.inc_overload_dropped(), 1);
        assert_eq!(metrics.inc_auth_failures_by(2), 2);

        let snap = metrics.snapshot();
        assert_eq!(snap.qos0_received, 1);
        assert_eq!(snap.qos1_received, 2);
        assert_eq!(snap.qos2_received, 1);
        assert_eq!(snap.delivered, 4);
        assert_eq!(snap.overload_dropped, 1);
        assert_eq!(snap.auth_failures, 2);
    }

    #[test]
    fn test_snapshot_consistent_and_per_instance_isolated() {
        let metrics = Metrics::new();
        metrics.inc_messages_received();
        metrics.inc_connect_received();
        metrics.inc_bytes_received_by(100);
        metrics.inc_qos1_received();
        metrics.inc_delivered_by(2);
        metrics.inc_connections();

        let snap = metrics.snapshot();
        assert_eq!(snap.messages_received, 1);
        assert_eq!(snap.connect_received, 1);
        assert_eq!(snap.bytes_received, 100);
        assert_eq!(snap.qos1_received, 1);
        assert_eq!(snap.delivered, 2);
        assert_eq!(snap.connections_active, 1);
        // Untouched families stay zero in the same snapshot.
        assert_eq!(snap.qos2_received, 0);
        assert_eq!(snap.auth_failures, 0);

        // Per-instance state only: a second instance sees nothing.
        let other = Metrics::new();
        let other_snap = other.snapshot();
        assert_eq!(other_snap, MetricsSnapshot::default());
        assert_ne!(snap, other_snap);
    }

    #[test]
    fn test_egress_stage_counters_increment_and_render() {
        let metrics = Metrics::new();
        assert_eq!(metrics.inc_transport_sent_by(3), 3);
        assert_eq!(metrics.inc_transport_sent_by(2), 5);
        assert_eq!(metrics.inc_transport_send_failed(), 1);
        assert_eq!(metrics.inc_egress_qos0_shed(), 1);
        assert_eq!(metrics.inc_puback_deferred(), 1);
        assert_eq!(metrics.inc_puback_deferred_released(), 1);
        assert_eq!(metrics.inc_credit_clamped(), 1);
        assert_eq!(metrics.inc_credit_exhausted(), 1);
        assert_eq!(metrics.inc_credit_received(), 1);

        let snap = metrics.snapshot();
        assert_eq!(snap.transport_sent, 5);
        assert_eq!(snap.transport_send_failed, 1);
        assert_eq!(snap.egress_qos0_shed, 1);
        assert_eq!(snap.puback_deferred, 1);
        assert_eq!(snap.puback_deferred_released, 1);
        assert_eq!(snap.credit_clamped, 1);
        assert_eq!(snap.credit_exhausted, 1);
        assert_eq!(snap.credit_received, 1);

        let text = metrics.render_prometheus_metrics();
        assert!(text.contains("indramqtt_transport_sent_total 5\n"));
        assert!(text.contains("indramqtt_transport_send_failed_total 1\n"));
        assert!(text.contains("indramqtt_egress_qos0_shed_total 1\n"));
        assert!(text.contains("indramqtt_puback_deferred_total 1\n"));
        assert!(text.contains("indramqtt_puback_deferred_released_total 1\n"));
        assert!(text.contains("indramqtt_credit_clamped_total 1\n"));
        assert!(text.contains("indramqtt_credit_exhausted_total 1\n"));
        assert!(text.contains("indramqtt_credit_received_total 1\n"));
    }

    #[test]
    fn test_inflight_spill_counters_increment_and_render() {
        let metrics = Metrics::new();
        assert_eq!(metrics.inflight_spilled(), 0);
        assert_eq!(metrics.inflight_spill_replayed(), 0);
        assert_eq!(metrics.inflight_spill_evicted(), 0);

        assert_eq!(metrics.inc_inflight_spilled_by(2), 2);
        assert_eq!(metrics.inc_inflight_spill_replayed(), 1);
        assert_eq!(metrics.inc_inflight_spill_evicted(), 1);
        assert_eq!(metrics.inc_inflight_dropped(), 1);

        let snap = metrics.snapshot();
        assert_eq!(snap.inflight_spilled, 2);
        assert_eq!(snap.inflight_spill_replayed, 1);
        assert_eq!(snap.inflight_spill_evicted, 1);
        assert_eq!(snap.inflight_dropped, 1);

        let text = metrics.render_prometheus_metrics();
        assert!(text.contains("indramqtt_inflight_spilled_total 2\n"));
        assert!(text.contains("indramqtt_inflight_spill_replayed_total 1\n"));
        assert!(text.contains("indramqtt_inflight_spill_evicted_total 1\n"));
        assert!(text.contains("indramqtt_inflight_dropped_total 1\n"));
    }

    #[test]
    fn test_rule_spill_counters_increment_and_render() {
        let metrics = Metrics::new();
        assert_eq!(metrics.rule_spill_spilled(), 0);
        assert_eq!(metrics.rule_spill_replayed(), 0);
        assert_eq!(metrics.rule_spill_dropped(), 0);
        assert_eq!(metrics.rule_spill_torn(), 0);
        assert_eq!(metrics.rule_spill_recovered(), 0);

        assert_eq!(metrics.inc_rule_spill_spilled_by(3), 3);
        assert_eq!(metrics.inc_rule_spill_replayed(), 1);
        assert_eq!(metrics.inc_rule_spill_dropped(), 1);
        assert_eq!(metrics.inc_rule_spill_torn_by(2), 2);
        assert_eq!(metrics.inc_rule_spill_recovered_by(3), 3);

        let snap = metrics.snapshot();
        assert_eq!(snap.rule_spill_spilled, 3);
        assert_eq!(snap.rule_spill_replayed, 1);
        assert_eq!(snap.rule_spill_dropped, 1);
        assert_eq!(snap.rule_spill_torn, 2);
        assert_eq!(snap.rule_spill_recovered, 3);

        let text = metrics.render_prometheus_metrics();
        assert!(text.contains("indramqtt_rule_spill_spilled_total 3\n"));
        assert!(text.contains("indramqtt_rule_spill_replayed_total 1\n"));
        assert!(text.contains("indramqtt_rule_spill_dropped_total 1\n"));
        assert!(text.contains("indramqtt_rule_spill_torn_total 2\n"));
        assert!(text.contains("indramqtt_rule_spill_recovered_total 3\n"));
    }

    #[test]
    fn test_egress_qos0_shed_labelled_by_client() {
        let metrics = Metrics::new();
        assert_eq!(metrics.egress_qos0_shed_for("ghost"), 0);
        assert!(metrics.egress_qos0_shed_by_client().is_empty());

        assert_eq!(metrics.inc_egress_qos0_shed_for("slow-1"), 1);
        assert_eq!(metrics.inc_egress_qos0_shed_for("slow-1"), 2);
        assert_eq!(metrics.inc_egress_qos0_shed_for("fast-1"), 3);

        assert_eq!(metrics.egress_qos0_shed(), 3);
        assert_eq!(metrics.egress_qos0_shed_for("slow-1"), 2);
        assert_eq!(metrics.egress_qos0_shed_for("fast-1"), 1);
        assert_eq!(metrics.egress_qos0_shed_for("ghost"), 0);
        let by_client = metrics.egress_qos0_shed_by_client();
        assert_eq!(by_client.len(), 2);
        assert_eq!(by_client.get("slow-1"), Some(&2));
        assert_eq!(by_client.get("fast-1"), Some(&1));

        let other = Metrics::new();
        assert!(other.egress_qos0_shed_by_client().is_empty());
    }

    #[test]
    fn test_stats_hwm_rises_and_never_falls() {
        let stats = StatsStore::new();
        let empty = stats.snapshot();
        assert_eq!(empty, StatsSnapshot::default());

        stats.set_connections(5);
        stats.set_subscriptions(7);
        stats.set_topics(3);
        stats.set_retained(2);
        let peak = stats.snapshot();
        assert_eq!(peak.connections, 5);
        assert_eq!(peak.connections_max, 5);
        assert_eq!(peak.subscriptions_max, 7);
        assert_eq!(peak.topics_max, 3);
        assert_eq!(peak.retained_max, 2);

        // Gauges drop, maxima hold the peaks.
        stats.set_connections(2);
        stats.set_subscriptions(0);
        stats.set_topics(1);
        stats.set_retained(0);
        let snap = stats.snapshot();
        assert_eq!(snap.connections, 2);
        assert_eq!(snap.connections_max, 5);
        assert_eq!(snap.subscriptions, 0);
        assert_eq!(snap.subscriptions_max, 7);
        assert_eq!(snap.topics, 1);
        assert_eq!(snap.topics_max, 3);
        assert_eq!(snap.retained, 0);
        assert_eq!(snap.retained_max, 2);

        // A new peak raises only its own maximum.
        stats.set_topics(9);
        assert_eq!(stats.topics(), 9);
        assert_eq!(stats.topics_max(), 9);
        assert_eq!(stats.connections_max(), 5);
    }

    #[test]
    fn test_stats_reset_maxima_rebaselines_to_current() {
        let stats = StatsStore::new();
        stats.set_connections(12);
        stats.set_subscriptions(30);
        stats.set_topics(11);
        stats.set_retained(4);
        stats.set_connections(3);
        stats.set_subscriptions(8);

        stats.reset_maxima();
        let snap = stats.snapshot();
        assert_eq!(snap.connections, 3);
        assert_eq!(snap.connections_max, 3);
        assert_eq!(snap.subscriptions, 8);
        assert_eq!(snap.subscriptions_max, 8);
        assert_eq!(snap.topics, 11);
        assert_eq!(snap.topics_max, 11);
        assert_eq!(snap.retained, 4);
        assert_eq!(snap.retained_max, 4);

        // Peaks after the reset raise the maxima again.
        stats.set_retained(6);
        assert_eq!(stats.retained_max(), 6);
    }

    #[test]
    fn test_stats_concurrent_setters_keep_true_peak() {
        use std::sync::Arc;
        use std::thread;

        let stats = Arc::new(StatsStore::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let stats = stats.clone();
            handles.push(thread::spawn(move || {
                // Every thread climbs through the full range, so the
                // true peak (99) is set by every thread; interleavings
                // must never lose it.
                for n in 0..100u64 {
                    stats.set_connections(n);
                    stats.set_subscriptions(n * 2);
                    stats.set_topics(n);
                    stats.set_retained(n % 10);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("setter thread joins");
        }

        let snap = stats.snapshot();
        assert_eq!(snap.connections_max, 99);
        assert_eq!(snap.subscriptions_max, 198);
        assert_eq!(snap.topics_max, 99);
        assert_eq!(snap.retained_max, 9);
        assert!(snap.connections <= 99);
        assert!(snap.subscriptions <= 198);
    }
}
