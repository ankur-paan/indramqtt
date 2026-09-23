use async_trait::async_trait;
use broker_auth::{
    Authenticator, Authorizer, KerberosAuthenticator, KerberosConfig, LdapAuthenticator,
    LdapConfig, MemoryAuth,
};
use broker_cluster::{
    ClusterLicense, ClusterMessage, InstallationState, RoutingPlane, TrustedKeys,
};
use broker_config::{ConfigError, ConfigRegistry};
use broker_gateway::coap::{CoapCode, CoapGatewayHandler, CoapMessage};
use broker_observability::{Metrics, NodeReadiness, StatsStore};
use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::{split_shared_filter, strip_delayed_prefix, ConnTable, Router, Subscription};
use broker_rules::{BackpressurePolicy, BrokerSink, RuleEngine};
use broker_session::{
    InflightMessage, InflightTrackOutcome, Qos2InboundEntry, Qos2OutboundEntry, QueuedMessage,
    SessionManager,
};
use broker_storage::stream::{DurableStreamStore, StreamConfig};
use broker_storage::{MemoryStore, RetainedStore};
use brokerlink::{BrokerFrame, BrokerLinkTransport, FramedTransport, OpCode};
use bytes::Bytes;
use clap::Parser;
use delayed::{DelayedEntry, DelayedScheduler, DEFAULT_MAX_DELAYED_SECS, DELAYED_TICK_MS};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

mod delayed;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "indramqtt",
    version,
    about = "IndraMQTT Distributed Broker Kernel"
)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:1883")]
    bind: String,

    /// BrokerLink IPC listen address for BEAM edge clients (TCP loopback).
    #[arg(long, default_value = "127.0.0.1:18883")]
    brokerlink_bind: String,

    /// Management REST API listen address. Empty disables the API
    /// (useful for test environments).
    #[arg(long, default_value = "127.0.0.1:18083")]
    api_bind: String,

    /// Directory holding kernel persistent state (`state.toml`).
    /// Created on boot when missing.
    #[arg(long, default_value = "./data")]
    data_dir: String,

    /// Enterprise commercial license key for multi-node clustering (or via INDRA_LICENSE_KEY env).
    #[arg(long)]
    license_key: Option<String>,

    /// Trusted licence-signing keys (B2-03): a JSON file or a directory of
    /// JSON files of the form
    /// `{"keys": [{"kid": "...", "public_key_hex": "<SEC1 hex>"}]}`.
    /// Empty (the default) trusts nothing: enterprise licences are then
    /// rejected as unknown keys while community mode still boots. A
    /// missing or corrupt path fails boot loudly rather than silently
    /// running unlicensed.
    #[arg(long, default_value = "")]
    license_keys: String,

    /// Write the installation licence request to this path and exit, for
    /// sites with no dashboard. The file carries the cluster identity and
    /// is safe to email to sales.
    #[arg(long, default_value = "")]
    licence_request_out: String,

    /// Install the licence token read from this path and exit. Verified
    /// before any write, so a failed install never touches the stored
    /// licence.
    #[arg(long, default_value = "")]
    licence_install_file: String,

    /// Days before expiry that the approaching-expiry alarm and log
    /// warning start. Applies to the trial and to licensed expiry alike.
    #[arg(long, default_value_t = 30)]
    licence_expiry_warn_days: u64,

    /// Cluster seed nodes (e.g. 127.0.0.1:19883). Specifying enables distributed clustering.
    #[arg(long)]
    cluster_seeds: Option<String>,

    /// Cluster UDP/gossip bind address for distributed clustering (e.g. 127.0.0.1:19883).
    #[arg(long, default_value = "127.0.0.1:19883")]
    cluster_bind: String,

    /// Unique cluster node identity. Defaults to "indra-node-1".
    #[arg(long, default_value = "indra-node-1")]
    node_id: String,

    /// Accept MQTT connections without credentials while no users are
    /// configured. Ignored once users exist: a non-empty user store
    /// always rejects unauthenticated clients.
    #[arg(long)]
    allow_anonymous: bool,

    /// Per-subscriber QoS 0 egress backlog bound (D1-02). Each live
    /// connection queues at most this many QoS 0 frames; past it the
    /// oldest queued QoS 0 frame drops (counted via `egress_qos0_shed`,
    /// labelled by client). QoS 1/2 never shed. Default 1000 matches
    /// the detached offline bound and caps per-subscriber QoS 0 memory
    /// near 1,000 small frames while absorbing a ~1 s burst at 1k
    /// msg/s without drops.
    #[arg(long, default_value_t = broker_router::DEFAULT_QOS0_BACKLOG)]
    qos0_backlog: usize,

    /// Per-session QoS 1 inflight window bound (B4-01). Each live session
    /// tracks at most this many unacknowledged QoS 1 downlinks in the
    /// fast in-memory window; past it overflow spills into the bounded
    /// per-session spill buffer (still tracked for DUP redelivery).
    /// Default 100 caps per-session live unacked state near 100 small
    /// frames while absorbing a short ack stall without spilling.
    #[arg(long, default_value_t = broker_session::DEFAULT_MAX_QOS1_INFLIGHT)]
    qos1_inflight_window: usize,

    /// Per-session QoS 1 spill bound past the window (B4-01). Overflow
    /// beyond the window is still delivered live once and tracked here
    /// for oldest-first DUP replay; past window + spill the newest live
    /// delivery stays untracked (counted). Default 1000 (10x the window)
    /// absorbs roughly a 1 s burst at 1k msg/s from a stalled
    /// acknowledger while keeping per-session tracked memory bounded
    /// near 1,100 messages total.
    #[arg(long, default_value_t = broker_session::DEFAULT_MAX_QOS1_SPILL)]
    qos1_spill: usize,

    /// CoAP gateway UDP listen address (B1-04). Empty disables the
    /// gateway (the default): nothing listens, nothing is dispatched,
    /// and the crate stays out of the data path. Set explicitly
    /// (e.g. `127.0.0.1:5683`) to run the gateway: CoAP POST/PUT to
    /// `/ps/<topic>` publishes through the kernel router so ordinary
    /// MQTT subscribers receive it, GET reads the retained store, and
    /// GET with Observe registers a bounded observer notified on later
    /// publishes.
    #[arg(long, default_value = "")]
    coap_bind: String,

    /// Durable stream journal directory (B1-07). Empty (the default)
    /// disables journaling: publishes pay one `is_none` check and no disk
    /// I/O. Set to a directory (e.g. `<data-dir>/streams`) to journal
    /// every publish through a bounded channel drained by a background
    /// task that appends to [`DurableStreamStore`] with an fsync per
    /// record. Disabled by default so benchmarks and existing deployments
    /// see no new work on the fan-out path.
    #[arg(long, default_value = "")]
    stream_dir: String,

    /// Directory server URL for LDAP authentication (B2-01). Empty (the
    /// default) disables LDAP: CONNECT falls back to the local user
    /// store only. Set to `ldap://host:port` or `ldaps://host:port` to
    /// enable directory-backed authentication at CONNECT (service bind,
    /// search, then bind as the entry DN). TLS verification is on by
    /// default for `ldaps://`; point `--ldap-ca-cert` at a PEM CA file
    /// for private directories.
    #[arg(long, default_value = "")]
    ldap_url: String,

    /// Base DN under which directory users are searched.
    #[arg(long, default_value = "")]
    ldap_base_dn: String,

    /// Service account DN used for the initial bind plus search.
    #[arg(long, default_value = "")]
    ldap_bind_dn: String,

    /// Service account password for the initial bind.
    #[arg(long, default_value = "")]
    ldap_bind_password: String,

    /// User search filter with a `{username}` placeholder, escaped per
    /// RFC 4515 (default `(uid={username})`).
    #[arg(long, default_value = "(uid={username})")]
    ldap_user_filter: String,

    /// User-entry attribute listing directory groups (`memberOf`).
    #[arg(long, default_value = "memberOf")]
    ldap_group_attribute: String,

    /// Required group DN: empty disables the group check, otherwise the
    /// entry must list this DN to connect.
    #[arg(long, default_value = "")]
    ldap_required_group: String,

    /// Path to a PEM CA certificate for private directories (`ldaps://`).
    #[arg(long, default_value = "")]
    ldap_ca_cert: String,

    /// Keytab file for Kerberos authentication (B2-02). Empty (the
    /// default) disables Kerberos: CONNECT falls back to the local user
    /// store (plus LDAP when configured). Set to a MIT keytab v2 file
    /// holding the broker's service principal to enable GSSAPI-based
    /// authentication at CONNECT (SPNEGO NegTokenInit wrapping AP-REQ,
    /// or bare AP-REQ). A missing or unreadable keytab disables the
    /// mechanism explicitly with a clear log line and never accepts
    /// tokens.
    #[arg(long, default_value = "")]
    kerberos_keytab: String,

    /// Service principal name held in the keytab (for example
    /// `mqtt/broker.example.com@EXAMPLE.COM`). Must match the ticket's
    /// service name or CONNECT is refused.
    #[arg(long, default_value = "")]
    kerberos_service_principal: String,

    /// Expected service realm (for example `EXAMPLE.COM`). Empty disables
    /// the realm check on the service name.
    #[arg(long, default_value = "")]
    kerberos_realm: String,

    /// Comma-separated list of trusted client realms (for example
    /// `EXAMPLE.COM`). Empty allows any realm that verifies.
    #[arg(long, default_value = "")]
    kerberos_allowed_realms: String,

    /// Clock-skew allowance in seconds for ticket validity and
    /// authenticator timestamps (default 300, clamped 1..3600).
    #[arg(long, default_value_t = 300)]
    kerberos_clock_skew_secs: u64,

    /// Comma-separated `principal=role` mappings for verified Kerberos
    /// client principals (for example
    /// `alice@EXAMPLE.COM=publisher,bob@EXAMPLE.COM=subscriber`).
    /// Unmapped principals authenticate with role `user`. Empty (the
    /// default) leaves every principal at `user`.
    #[arg(long, default_value = "")]
    kerberos_role_map: String,

    /// Replay-cache bound for Kerberos authenticators (default 1024,
    /// clamped 16..8192). Bounds CONNECT-only memory: each entry is
    /// under 128 bytes, so the default holds under 128 KiB.
    #[arg(long, default_value_t = broker_auth::REPLAY_MAX_ENTRIES)]
    kerberos_replay_max: usize,

    /// Upper bound for `$delayed` deferrals in seconds (B4-03). Past it
    /// the request is dropped with a warning instead of pinning a wheel
    /// slot and a file row indefinitely. Default one day: longer
    /// deferrals pin memory for no realistic device schedule, and the
    /// previous per-message sleep used the same one-day ceiling so
    /// existing publishers see the same limit.
    #[arg(long, default_value_t = DEFAULT_MAX_DELAYED_SECS)]
    delayed_max_secs: u64,
}

/// Map an inbound frame to its synchronous reply, if any.
///
/// Contracts (mirrored in `beam/src/indra_brokerlink.erl`):
/// * `Ping` is answered immediately with a `Pong` carrying the identical
///   `conn_id` and `sequence_no`.
/// * `BindConnection` metadata is `ClientIdLen:16be | ClientId (UTF-8)
///   | Flags:8 (bit 0 = clean_start) | Keepalive:16be`. The canonical
///   session is resolved via `SessionManager::get_or_create` and answered
///   with `SessionBinding` metadata `SessionId:64be | Present:8
///   | ReturnCode:8` (RC 0 = accepted, 2 = identifier rejected).
///   Replies always mirror the request `conn_id` and `sequence_no`.
/// * All other opcodes have no synchronous reply yet and return `None`.
fn reply_for_frame(frame: &BrokerFrame, sessions: &SessionManager) -> Option<BrokerFrame> {
    match frame.header.opcode {
        OpCode::Ping => Some(BrokerFrame::pong(
            frame.header.conn_id,
            frame.header.sequence_no,
        )),
        OpCode::BindConnection => Some(bind_connection_reply(frame, sessions)),
        _ => None,
    }
}

/// Resolve one `BindConnection` frame into its `SessionBinding` reply.
///
/// Every `BindConnection` yields exactly one reply so the BEAM edge never
/// hangs waiting for CONNACK parameters: malformed metadata (or a
/// non-UTF-8 client id) is answered with return code 2, mirroring the
/// MQTT 3.1.1 CONNACK "identifier rejected" code.
fn bind_connection_reply(frame: &BrokerFrame, sessions: &SessionManager) -> BrokerFrame {
    let (session_id, present, return_code) = match decode_bind_meta(&frame.metadata) {
        Ok(req) => {
            let (session, present) = sessions.get_or_create(&req.client_id, req.clean_start);
            // Connection != Session: pin this edge connection to the session
            // so Unbind can later verify ownership before detaching.
            // Indexed (PERF-04): keeps conn_id -> client_id O(1).
            sessions.bind_session(&session, frame.header.conn_id);
            *session.keepalive_secs.write() = req.keepalive_secs;
            (session.id.0, present, 0u8)
        }
        Err(_) => (0u64, false, 2u8),
    };

    session_binding_reply(frame, session_id, present, return_code)
}

/// Build one `SessionBinding` reply frame.
fn session_binding_reply(
    frame: &BrokerFrame,
    session_id: u64,
    present: bool,
    return_code: u8,
) -> BrokerFrame {
    let mut meta = Vec::with_capacity(10);
    meta.extend_from_slice(&session_id.to_be_bytes());
    meta.push(u8::from(present));
    meta.push(return_code);

    BrokerFrame::new(
        OpCode::SessionBinding,
        frame.header.conn_id,
        frame.header.sequence_no,
        Bytes::from(meta),
        Bytes::new(),
    )
    .expect("SessionBinding reply within size bounds")
}

/// Authenticated bind for the live path: credentialed requests verify
/// against the auth store first (failure short-circuits to return code
/// `0x86`, bad username/password, with no session created), then the
/// per-user connection quota applies (overage short-circuits to `0x8B`),
/// then the standard session resolution applies.
async fn apply_bind(frame: &BrokerFrame, shared: &Shared) -> Option<BrokerFrame> {
    // B2-02: verified Kerberos identity for this CONNECT. Set inside the
    // auth block on Kerberos success and read by the ownership stamp below
    // without re-verifying the same token (the replay cache would refuse a
    // second verify). CONNECT-only, never on the delivery path.
    let mut kerberos_principal: Option<String> = None;
    let mut kerberos_role: Option<String> = None;
    if let Ok(req) = decode_bind_meta(&frame.metadata) {
        // B1-03: banned identities never reach the session. Checked
        // before credentials and quotas so a banned client is refused
        // with the banned return code (0x8A, mapped to CONNACK 5 on the
        // edge) with no session created and no quota slot consumed.
        // A connect is not the delivery path, so one read lock here
        // costs the message path nothing.
        if shared.bans.is_banned(
            &req.client_id,
            req.username.as_deref(),
            req.peerhost.as_deref(),
        ) {
            shared.metrics.inc_auth_failures();
            return Some(session_binding_reply(frame, 0, false, 0x8A));
        }
        if req.username.is_none() {
            // A non-empty user store always wins over `--allow-anonymous`:
            // unauthenticated clients are rejected whenever users exist.
            // A configured directory does the same: anonymous never
            // authenticates against LDAP or Kerberos. The flag only opens
            // the broker while the store is empty and no directory or
            // enabled Kerberos mechanism is configured.
            let kerberos_enabled = shared.kerberos.as_ref().is_some_and(|k| k.is_enabled());
            if shared.auth.user_count() > 0 || shared.ldap.is_some() || kerberos_enabled {
                shared.metrics.inc_auth_failures();
                return Some(session_binding_reply(frame, 0, false, 0x87));
            }
        } else {
            let password = req.password.as_deref();
            // B2-01: local users first, then the directory. With an empty
            // local store and no directory the broker stays open (existing
            // behaviour); with a directory configured the open mode is
            // disabled and every credentialed CONNECT goes through the
            // directory unless a local user matches. A directory outage
            // fails closed with a clear log line inside the authenticator
            // and never grants access.
            // B2-02: Kerberos tokens (SPNEGO `0x60` or AP-REQ `0x6E`) go
            // through the Kerberos authenticator when enabled (real DER
            // plus keytab verification, never a bypass). Other passwords
            // keep the LDAP path. An enabled Kerberos mechanism disables
            // the open mode like LDAP does: non-Kerberos passwords fail
            // closed with 0x86 instead of falling through.
            let local_has_users = shared.auth.user_count() > 0;
            let kerberos_enabled = shared.kerberos.as_ref().is_some_and(|k| k.is_enabled());
            let looks_kerberos =
                password.is_some_and(|p| !p.is_empty() && (p[0] == 0x60 || p[0] == 0x6E));
            let mut via_ldap = false;
            let mut via_kerberos = false;
            if local_has_users {
                let local_ok = shared
                    .auth
                    .authenticate(&req.client_id, req.username.as_deref(), password)
                    .await
                    .is_ok();
                if local_ok {
                    // Local credential accepted; quotas apply below.
                } else if kerberos_enabled && looks_kerberos {
                    let Some(kerberos) = shared.kerberos.as_ref() else {
                        shared.metrics.inc_auth_failures();
                        return Some(session_binding_reply(frame, 0, false, 0x86));
                    };
                    let Some(token) = password else {
                        shared.metrics.inc_auth_failures();
                        return Some(session_binding_reply(frame, 0, false, 0x86));
                    };
                    match kerberos.verify_token(&req.client_id, token) {
                        Ok(verified) => {
                            // Wire every verified field live: client and
                            // service principals, session-key length and
                            // mapped role, plus the authenticator config
                            // for the expected service. Audit-logged for
                            // SSO traceability; CONNECT-only.
                            let expected_service = kerberos.config().service_principal_name.clone();
                            tracing::info!(
                                client_principal = %verified.client_principal,
                                service_principal = %verified.service_principal,
                                expected_service = %expected_service,
                                role = %verified.role,
                                session_key_len = verified.session_key.len(),
                                "Kerberos CONNECT accepted"
                            );
                            debug_assert_eq!(verified.service_principal, expected_service);
                            debug_assert_eq!(verified.session_key.len(), 32);
                            via_kerberos = true;
                            kerberos_principal = Some(verified.client_principal);
                            kerberos_role = Some(verified.role);
                        }
                        Err(_) => {
                            shared.metrics.inc_auth_failures();
                            return Some(session_binding_reply(frame, 0, false, 0x86));
                        }
                    }
                } else if let Some(ldap) = shared.ldap.as_ref() {
                    if ldap
                        .authenticate(&req.client_id, req.username.as_deref(), password)
                        .await
                        .is_ok()
                    {
                        via_ldap = true;
                    } else {
                        shared.metrics.inc_auth_failures();
                        return Some(session_binding_reply(frame, 0, false, 0x86));
                    }
                } else {
                    // No LDAP and (no enabled Kerberos or a non-Kerberos
                    // password): with local users present the failure is
                    // final. When Kerberos is enabled a non-Kerberos
                    // password is not an open-mode accept.
                    if kerberos_enabled {
                        shared.metrics.inc_auth_failures();
                        return Some(session_binding_reply(frame, 0, false, 0x86));
                    }
                    shared.metrics.inc_auth_failures();
                    return Some(session_binding_reply(frame, 0, false, 0x86));
                }
            } else if kerberos_enabled && looks_kerberos {
                let Some(kerberos) = shared.kerberos.as_ref() else {
                    shared.metrics.inc_auth_failures();
                    return Some(session_binding_reply(frame, 0, false, 0x86));
                };
                let Some(token) = password else {
                    shared.metrics.inc_auth_failures();
                    return Some(session_binding_reply(frame, 0, false, 0x86));
                };
                match kerberos.verify_token(&req.client_id, token) {
                    Ok(verified) => {
                        // Same live wiring as above: every verified field
                        // plus the authenticator config is read here.
                        let expected_service = kerberos.config().service_principal_name.clone();
                        tracing::info!(
                            client_principal = %verified.client_principal,
                            service_principal = %verified.service_principal,
                            expected_service = %expected_service,
                            role = %verified.role,
                            session_key_len = verified.session_key.len(),
                            "Kerberos CONNECT accepted"
                        );
                        debug_assert_eq!(verified.service_principal, expected_service);
                        debug_assert_eq!(verified.session_key.len(), 32);
                        via_kerberos = true;
                        kerberos_principal = Some(verified.client_principal);
                        kerberos_role = Some(verified.role);
                    }
                    Err(_) => {
                        shared.metrics.inc_auth_failures();
                        return Some(session_binding_reply(frame, 0, false, 0x86));
                    }
                }
            } else if let Some(ldap) = shared.ldap.as_ref() {
                if ldap
                    .authenticate(&req.client_id, req.username.as_deref(), password)
                    .await
                    .is_ok()
                {
                    via_ldap = true;
                } else {
                    shared.metrics.inc_auth_failures();
                    return Some(session_binding_reply(frame, 0, false, 0x86));
                }
            } else if kerberos_enabled {
                // Enabled Kerberos disables the open mode: a credentialed
                // CONNECT without a Kerberos token fails closed.
                shared.metrics.inc_auth_failures();
                return Some(session_binding_reply(frame, 0, false, 0x86));
            } else {
                // Open broker: no users, no directory, no enabled Kerberos.
                // Fall through to the session resolution below (rc 0).
            }
            // Effective identity for quotas and takeover: the verified
            // Kerberos principal when present, else the MQTT username.
            let effective_username: Option<String> =
                kerberos_principal.clone().or_else(|| req.username.clone());
            // Takeover pre-release: a live session for this client means
            // the previous holder was orphaned by this very bind.
            let already_live = shared
                .sessions
                .get(&req.client_id)
                .map(|session| *session.connected.read())
                .unwrap_or(false);
            if already_live {
                if let Some(username) = &effective_username {
                    shared.sessions.release_connection_slot(username);
                }
            }
            if let Some(username) = &effective_username {
                // Directory and Kerberos users have no local quotas:
                // unlimited. The invariant below reads the live role so
                // `VerifiedKerberos::role` is wired, not test-only:
                // every Kerberos CONNECT sets a role alongside the
                // principal, and non-Kerberos CONNECTs set neither.
                debug_assert!(via_kerberos == kerberos_role.is_some());
                let max = if via_ldap || via_kerberos {
                    None
                } else {
                    shared
                        .auth
                        .get_quotas(username)
                        .and_then(|quotas| quotas.max_connections)
                };
                if !shared.sessions.acquire_connection_slot(username, max) {
                    return Some(session_binding_reply(frame, 0, false, 0x8B));
                }
            }
        }
    }
    // Clean-start bind discards any previous state for this client id,
    // including router entries left by an earlier session: snapshot them
    // before `get_or_create` drops the old session object.
    let stale: (String, Vec<broker_protocol::TopicFilter>) = match decode_bind_meta(&frame.metadata)
    {
        Ok(req) if req.clean_start => (
            req.client_id.clone(),
            shared.sessions.subscription_filters(&req.client_id),
        ),
        Ok(req) => (req.client_id.clone(), Vec::new()),
        Err(_) => (String::new(), Vec::new()),
    };
    let reply = reply_for_frame(frame, &shared.sessions);
    // Sweep the stale router copies so a clean reconnect resubscribes
    // from nothing. Off the hot path (bind only); fan-out takes no new
    // lock and delivery cost is unchanged.
    for filter in &stale.1 {
        shared.router.unsubscribe(filter, &stale.0);
    }
    if !stale.1.is_empty() {
        refresh_subscription_stats(shared);
    }
    // Stamp ownership for quota release and publish attribution. Kerberos
    // CONNECTs stamp the verified client principal (not the MQTT username
    // string, which the ticket supersedes); all other paths keep the MQTT
    // username. The principal was verified above, never re-verified here.
    if let Ok(req) = decode_bind_meta(&frame.metadata) {
        if let Some(session) = shared.sessions.get(&req.client_id) {
            if let Some(principal) = &kerberos_principal {
                *session.username.write() = Some(principal.clone());
            } else if let Some(username) = &req.username {
                *session.username.write() = Some(username.clone());
            }
        }
        // Stamp the peer address for publish-time ban checks (B1-03):
        // only overwritten when the edge forwarded one, so a rebind
        // without a peer section keeps the last known address.
        if let (Some(session), Some(peerhost)) =
            (shared.sessions.get(&req.client_id), &req.peerhost)
        {
            *session.peerhost.write() = Some(peerhost.clone());
        }
    }
    reply
}

/// Whether a `SessionBinding` reply accepted the connection.
///
/// The reply metadata is `SessionId:64be | Present:8 | ReturnCode:8`;
/// only return code 0 proceeds to the auto-subscribe hook. Malformed
/// replies never trigger subscriptions.
fn is_binding_accepted(reply: &BrokerFrame) -> bool {
    reply.metadata.len() == 10 && reply.metadata[9] == 0
}

/// Subscribe one freshly bound connection to the configured
/// auto-subscribe list (W1-39).
///
/// Runs once per successful bind, never on the per-message path: it
/// clones the capped list once, renders `${clientid}`/`${username}`/
/// `${host}` per entry, and registers each valid filter in the router
/// plus the session mirror. Invalid rendered filters are skipped so one
/// bad template can never fail a connect; the stored templates themselves
/// are validated at the management write, so skips only cover
/// placeholder edge cases.
fn apply_auto_subscribe(shared: &Shared, client_id: &str, username: Option<&str>, conn_id: u64) {
    let entries = shared.auto_subscribe.list();
    if entries.is_empty() {
        return;
    }
    let mut applied = false;
    for entry in &entries {
        let rendered =
            broker_api::v5::auto_subscribe::render_auto_topic(&entry.topic, client_id, username);
        let Ok(filter) = TopicFilter::new(&rendered) else {
            continue;
        };
        let Ok(qos) = QoS::try_from(entry.qos) else {
            continue;
        };
        shared.router.subscribe(
            &filter,
            Subscription {
                client_id: client_id.into(),
                conn_id,
                qos,
                group: None,
            },
        );
        shared
            .sessions
            .add_subscription_with_options(client_id, filter, qos, entry.nl, entry.rap, entry.rh);
        applied = true;
    }
    if applied {
        refresh_subscription_stats(shared);
    }
}

/// Decode `BindConnection` metadata.
///
/// Layout: `ClientIdLen:16be | ClientId | Flags:8 | Keepalive:16be`,
/// optionally followed by a credentials section `UserLen:16be | Username
/// | PassLen:16be | Password` (absent entirely when the client connects
/// anonymously), optionally followed by a peer-address section
/// `PeerLen:16be | PeerIp` carrying the client IP literal the edge saw
/// on its socket (B1-03: drives `peerhost` / `peerhost_net` bans).
/// Binds encoded before the peer section existed carry no trailing bytes
/// and still decode with `peerhost` unset. The keepalive is
/// framing-validated here; supervision lives on the edge.
struct BindRequest {
    client_id: String,
    clean_start: bool,
    keepalive_secs: u16,
    username: Option<String>,
    password: Option<Vec<u8>>,
    peerhost: Option<String>,
}

fn decode_bind_meta(meta: &[u8]) -> Result<BindRequest, &'static str> {
    if meta.len() < 5 {
        return Err("bind meta too short");
    }
    let id_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    if meta.len() < 2 + id_len + 1 + 2 {
        return Err("bind meta too short");
    }
    let id_bytes = &meta[2..2 + id_len];
    let flags = meta[2 + id_len];
    let keepalive_secs = u16::from_be_bytes([meta[3 + id_len], meta[4 + id_len]]);
    let client_id = std::str::from_utf8(id_bytes).map_err(|_| "client id not UTF-8")?;
    let rest = &meta[5 + id_len..];
    let identity = decode_bind_identity(rest)?;
    Ok(BindRequest {
        client_id: client_id.to_string(),
        clean_start: flags & 0x01 != 0,
        keepalive_secs,
        username: identity.username,
        password: identity.password,
        peerhost: identity.peerhost,
    })
}

/// Credentials plus peer address decoded from the bind tail.
struct BindIdentity {
    username: Option<String>,
    password: Option<Vec<u8>>,
    peerhost: Option<String>,
}

/// Decode the optional trailing credentials and peer-address sections:
/// empty means anonymous with no peer address; otherwise a credentials
/// section `UserLen | Username | PassLen | Password`, optionally followed
/// by a peer section `PeerLen:16be | PeerIp` (an IP literal). An anonymous
/// bind from a peer-aware edge carries only the peer section. A trailing
/// section that is neither valid credentials nor a valid peer address is
/// malformed, exactly as trailing garbage was before the peer section.
fn decode_bind_identity(rest: &[u8]) -> Result<BindIdentity, &'static str> {
    if rest.is_empty() {
        return Ok(BindIdentity {
            username: None,
            password: None,
            peerhost: None,
        });
    }
    if rest.len() < 2 {
        return Err("bind credentials truncated");
    }
    let user_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + user_len + 2 {
        // Too short for credentials: it can only be an anonymous bind
        // carrying just the peer section.
        return match decode_peer_section(rest) {
            Some(peerhost) => Ok(BindIdentity {
                username: None,
                password: None,
                peerhost: Some(peerhost),
            }),
            None => Err("bind credentials truncated"),
        };
    }
    let username = std::str::from_utf8(&rest[2..2 + user_len]).map_err(|_| "username not UTF-8")?;
    let base = 2 + user_len;
    let pass_len = u16::from_be_bytes([rest[base], rest[base + 1]]) as usize;
    if rest.len() < base + 2 + pass_len {
        return Err("bind credentials truncated");
    }
    let password = rest[base + 2..base + 2 + pass_len].to_vec();
    let tail = &rest[base + 2 + pass_len..];
    if tail.is_empty() {
        return Ok(BindIdentity {
            username: Some(username.to_string()),
            password: Some(password),
            peerhost: None,
        });
    }
    match decode_peer_section(tail) {
        Some(peerhost) => Ok(BindIdentity {
            username: Some(username.to_string()),
            password: Some(password),
            peerhost: Some(peerhost),
        }),
        None => Err("bind meta length mismatch"),
    }
}

/// Decode one peer-address section `PeerLen:16be | PeerIp`: exactly those
/// bytes and an IP literal, otherwise `None`.
fn decode_peer_section(section: &[u8]) -> Option<String> {
    if section.len() < 2 {
        return None;
    }
    let peer_len = u16::from_be_bytes([section[0], section[1]]) as usize;
    if section.len() != 2 + peer_len {
        return None;
    }
    let literal = std::str::from_utf8(&section[2..]).ok()?;
    // Only IP literals travel here; anything else is malformed input,
    // never a peer identity to match bans against.
    literal.parse::<std::net::IpAddr>().ok()?;
    Some(literal.to_string())
}

/// State shared by every BrokerLink connection task on this node.
/// One publish queued for the background stream writer.
#[derive(Debug)]
struct JournalEntry {
    topic: Topic,
    qos: QoS,
    payload: Bytes,
    timestamp_ms: u64,
}

/// Bounded async journal from the publish path to [`DurableStreamStore`].
///
/// The publish path calls [`try_record`](StreamJournalHandle::try_record),
/// which does one non-blocking `try_send` and never awaits file I/O, so an
/// fsync can never stall delivery. A single background task owns the
/// receiver and calls `append_with_timestamp` (fsync per record under the
/// default policy). Capacity is 1024 entries; when full the newest record
/// is dropped and `dropped` increments. Durability window: channel delay
/// plus one fsync (usually well under 10 ms); dropped records are lost and
/// counted, never retried. Memory is bounded by the channel plus one
/// in-flight append.
#[derive(Debug)]
#[allow(dead_code)]
struct StreamJournalHandle {
    store: Arc<DurableStreamStore>,
    tx: tokio::sync::mpsc::Sender<JournalEntry>,
    dropped: Arc<AtomicU64>,
}

#[allow(dead_code)]
impl StreamJournalHandle {
    fn open(
        dir: impl AsRef<std::path::Path>,
        config: StreamConfig,
    ) -> std::result::Result<Arc<Self>, broker_storage::StorageError> {
        let store = Arc::new(DurableStreamStore::open_with_config(dir, config)?);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<JournalEntry>(1024);
        let writer = store.clone();
        tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                if let Err(e) = writer.append_with_timestamp(
                    entry.topic,
                    entry.qos,
                    entry.payload,
                    std::collections::HashMap::new(),
                    entry.timestamp_ms,
                ) {
                    warn!("Stream journal append failed: {e}");
                }
            }
        });
        Ok(Arc::new(Self {
            store,
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        }))
    }

    /// Enqueue one publish without blocking. Drops (and counts) the record
    /// when the channel is full so delivery never waits for disk.
    fn try_record(&self, topic: &Topic, qos: QoS, payload: &Bytes) {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let entry = JournalEntry {
            topic: topic.clone(),
            qos,
            payload: payload.clone(),
            timestamp_ms,
        };
        if self.tx.try_send(entry).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Journal one publish when enabled, otherwise one `is_none` check.
///
/// Off the hot path by construction: no await, no file I/O, at most a
/// small clone plus a channel send. Empty journals (the default) cost the
/// branch only.
fn maybe_journal_stream(shared: &Shared, topic: &Topic, qos: QoS, payload: &Bytes) {
    if let Some(journal) = shared.stream_journal.as_ref() {
        journal.try_record(topic, qos, payload);
    }
}

#[derive(Clone)]
struct Shared {
    sessions: Arc<SessionManager>,
    router: Arc<Router>,
    conns: Arc<ConnTable>,
    engine: Arc<RuleEngine>,
    sink: Arc<dyn BrokerSink>,
    retained: Arc<dyn RetainedStore>,
    /// Retained-delivery settings for W1-28: shared with the management
    /// API so kernel ingress and management publishes enforce the same
    /// configurable limits. One Arc clone at boot; reads take a short
    /// lock on retained publishes only, never on the fan-out path.
    retainer_config: Arc<broker_api::v5::retainer::RetainerConfigStore>,
    /// Auto-subscribe list for W1-39: shared with the management API so
    /// validated writes are visible to the connect hook without a
    /// restart. One Arc clone; the hook clones the capped list once per
    /// bind, never per message.
    auto_subscribe: Arc<broker_api::v5::auto_subscribe::AutoSubscribeStore>,
    /// Ban directory for B1-03: shared with the management API so
    /// validated ban writes are visible to the connect and publish
    /// checks without a restart. One Arc clone; connects take one read
    /// lock off the delivery path, publishes take one read lock that
    /// returns after a length check when the store is empty.
    bans: Arc<broker_api::v5::banned::BanStore>,
    /// Licence request/install/status store for B2-04: cluster identity,
    /// stored token and trusted signing set, shared with the management
    /// API so validated installs are visible without a restart. One Arc
    /// clone; the publish path never touches it.
    licence: Arc<broker_api::licence::LicenceStore>,
    /// Alarm directory shared with the management API so licence lifecycle
    /// events (trial/expiry/grace/lapse/ceiling) are visible via the API.
    /// One Arc clone; management-plane only.
    alarms: Arc<broker_api::v5::alarms::AlarmStore>,
    /// Cluster routing plane. `None` runs standalone; `Some` announces
    /// local subscriptions and forwards each publish once per matching
    /// remote node (single forward per node; remotes fan out locally).
    cluster: Option<Arc<dyn RoutingPlane>>,
    metrics: Arc<Metrics>,
    /// Gauge-plus-high-water-mark store for the broker `/stats` endpoint (W1 reads it;
    /// lifecycle points below keep it exact).
    stats: Arc<StatsStore>,
    /// Node readiness flag for `GET /api/v5/status` (W1-27): single atomic
    /// bool shared with the management API. Set at boot; the handler does
    /// one constant-time load per request. Management-plane only; never
    /// touched on the per-message path.
    readiness: Arc<NodeReadiness>,
    auth: Arc<MemoryAuth>,
    /// Directory authenticator for B2-01 (`None` disables LDAP). Consulted
    /// at CONNECT when the local store refuses the credentials; a
    /// directory outage fails closed. One `Arc` clone at boot; connects
    /// take a semaphore permit off the delivery path.
    ldap: Option<Arc<LdapAuthenticator>>,
    /// Kerberos authenticator for B2-02 (`None` disables Kerberos).
    /// Consulted at CONNECT for SPNEGO/AP-REQ tokens when the local store
    /// refuses; a missing keytab disables explicitly with a log line and
    /// never accepts tokens. One `Arc` clone at boot; CONNECT-only (one
    /// bounded replay-cache lock, never on the delivery path).
    kerberos: Option<Arc<KerberosAuthenticator>>,
    allow_anonymous: bool,
    /// Kernel-owned configuration registry: loaded from `--data-dir` at
    /// boot; validated defaults in tests and before boot wiring runs.
    config: Arc<ConfigRegistry>,
    /// Local node name (`--node-id`), passed into the API layer for the
    /// node-scope helper. Stored only until W1 wires it in.
    node_id: String,
    /// CoAP gateway translator and bounded observer table (B1-04).
    /// Always present so the publish path needs no `Option` branch;
    /// empty when `--coap-bind` is unset, in which case the gateway
    /// task never runs and the publish hook returns after one length
    /// check. One `Arc` clone at boot; registrations take a short
    /// write lock off the delivery path.
    coap: Arc<CoapGatewayHandler>,
    /// UDP socket the gateway listener bound (B1-04). `None` unless
    /// `--coap-bind` names an address: set once at boot before any
    /// task clones `Shared`, read-only afterwards. The publish hook
    /// snapshots observers and spawns the UDP sends off the hot path;
    /// unit tests leave it `None` so the hook is a no-op.
    coap_socket: Option<Arc<tokio::net::UdpSocket>>,
    /// Durable stream journal (B1-07). `None` (the default) disables
    /// journaling with a single branch on the publish path. `Some` journals
    /// every publish through a bounded channel drained off the hot path.
    /// One `Arc` clone at boot; the hook never blocks delivery.
    stream_journal: Option<Arc<StreamJournalHandle>>,
    /// Delayed-publish scheduler (B4-03): one shared hierarchical timer
    /// wheel plus the file-backed pending log behind it. The publish
    /// event records here before the publisher is acknowledged; a single
    /// background driver ticks the wheel and delivers due entries through
    /// the normal ingress pipeline. One `Arc` clone at boot; the publish
    /// path pays one atomic load, one bounded file append and one short
    /// wheel-lock insert, while cascading and file rewrites stay in the
    /// driver task. Measured before/after rates print in
    /// `delayed_delivery_workload_timings`. Bounded by the pending cap
    /// and the per-message
    /// payload cap documented in `delayed.rs`.
    delayed: Arc<DelayedScheduler>,
}

impl Shared {
    fn new() -> Self {
        let sessions = Arc::new(SessionManager::new());
        let router = Arc::new(Router::new());
        let conns = Arc::new(ConnTable::default());
        let engine = Arc::new(RuleEngine::new(1024, BackpressurePolicy::DropOldest));
        let metrics = Arc::new(Metrics::new());
        // PERF-10: attach drop accounting to the delivery table so
        // `ConnTable::route` counts unknown-conn and dead-mailbox drops
        // exactly where it discards them.
        conns.set_metrics(&metrics);
        let stats = Arc::new(StatsStore::new());
        let readiness = Arc::new(NodeReadiness::new());
        // NO MQTT LOOPBACK: rule republishes route straight into the local
        // router/mailboxes through this in-memory sink. The same sink
        // serves window-flush republish actions (INDRA-213).
        let sink: Arc<dyn BrokerSink> = Arc::new(InMemoryBrokerSink {
            router: router.clone(),
            sessions: sessions.clone(),
            conns: conns.clone(),
            metrics: metrics.clone(),
        });
        engine.set_broker_sink(sink.clone());

        // Pre-seed end-to-end streaming pipelines connecting Ingress Source -> Rule SQL -> Connector Sink
        let _ = engine.create_rule(
            "factory-telemetry-to-kafka".to_string(),
            TopicFilter::new("sensors/+/telemetry").unwrap(),
            Some("SELECT payload.temperature as temp, payload.pressure as pressure, clientid FROM \"sensors/+/telemetry\" WHERE payload.temperature > 25".to_string()),
            true,
            vec![broker_rules::RuleAction::ForwardConnector {
                connector_id: "kafka:kafka-prod".to_string(),
            }],
        );
        let _ = engine.create_rule(
            "critical-alerts-to-webhook".to_string(),
            TopicFilter::new("sensors/+/alerts").unwrap(),
            Some("SELECT payload.level as alert_level, payload.msg as message, clientid FROM \"sensors/+/alerts\" WHERE payload.level = 'CRITICAL'".to_string()),
            true,
            vec![broker_rules::RuleAction::ForwardConnector {
                connector_id: "http:webhook-alerts".to_string(),
            }],
        );
        let _ = engine.create_rule(
            "telemetry-to-postgres".to_string(),
            TopicFilter::new("sensors/+/telemetry").unwrap(),
            Some(
                "SELECT payload.temperature as temp, clientid FROM \"sensors/+/telemetry\""
                    .to_string(),
            ),
            true,
            vec![broker_rules::RuleAction::ForwardConnector {
                connector_id: "pgsql:postgres-analytics".to_string(),
            }],
        );
        Self {
            sessions,
            router,
            conns,
            engine,
            sink,
            retained: Arc::new(MemoryStore::new()),
            retainer_config: Arc::new(broker_api::v5::retainer::RetainerConfigStore::new()),
            auto_subscribe: Arc::new(broker_api::v5::auto_subscribe::AutoSubscribeStore::new()),
            bans: Arc::new(broker_api::v5::banned::BanStore::new()),
            licence: Arc::new(broker_api::licence::LicenceStore::new()),
            alarms: Arc::new(broker_api::v5::alarms::AlarmStore::new()),
            cluster: None,
            metrics,
            stats,
            readiness,
            auth: Arc::new(MemoryAuth::new()),
            ldap: None,
            kerberos: None,
            allow_anonymous: false,
            config: defaults_registry(),
            node_id: "indra-node-1".to_string(),
            coap: Arc::new(CoapGatewayHandler::new()),
            coap_socket: None,
            stream_journal: None,
            delayed: Arc::new(DelayedScheduler::new()),
        }
    }

    /// Start the single delayed-delivery driver task for this node. The
    /// first caller wins (the scheduler's claim bit); later callers are
    /// no-ops so connection tasks can call this freely without spawning
    /// a driver per connection. The driver ticks every 100 ms off the
    /// delivery path and routes due entries through the normal ingress
    /// pipeline.
    fn spawn_delayed_driver(&self) {
        if !self.delayed.claim_driver() {
            return;
        }
        let shared = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(DELAYED_TICK_MS)).await;
                let due = shared.delayed.tick_due();
                if due.is_empty() {
                    continue;
                }
                let mut fired_ids = Vec::with_capacity(due.len());
                for entry in due {
                    fired_ids.push(entry.id);
                    deliver_delayed_entry(&shared, entry).await;
                }
                shared.delayed.remove_ids(&fired_ids);
            }
        });
    }
}

/// Deliver one due delayed entry through the same ingress pipeline an
/// immediate publish takes (retained store, rules, fan-out, cluster
/// forward), then count it. Runs in the delayed driver task, never on
/// the live publish or deliver path.
async fn deliver_delayed_entry(shared: &Shared, entry: DelayedEntry) {
    let Ok(topic) = Topic::new(entry.topic.clone()) else {
        shared.delayed.note_malformed();
        warn!("Dropping delayed entry with bad inner topic");
        return;
    };
    let Ok(qos) = QoS::try_from(entry.qos) else {
        shared.delayed.note_malformed();
        warn!("Dropping delayed entry with bad QoS");
        return;
    };
    let payload = Bytes::from(entry.payload.clone());
    let deliveries = ingress_pipeline_with_publisher(
        shared,
        &topic,
        qos,
        entry.retain,
        &payload,
        entry.publisher.as_deref(),
    )
    .await;
    let mut enqueued = 0u64;
    let mut enqueued_bytes = 0u64;
    for (conn_id, routed) in deliveries {
        let len = routed.total_frame_len() as u64;
        if shared.conns.route(conn_id, routed) {
            enqueued += 1;
            enqueued_bytes += len;
        }
    }
    shared.metrics.inc_messages_forwarded_by(enqueued);
    shared.metrics.inc_publish_sent_by(enqueued);
    shared.metrics.inc_delivered_by(enqueued);
    shared.metrics.inc_bytes_sent_by(enqueued_bytes);
    forward_cluster(shared, &topic, qos, &payload).await;
    shared.delayed.note_delivered();
}

/// Defaults-only registry for fresh `Shared` state (tests and pre-boot).
///
/// Loads from a unique scratch path that is never created, so `load`
/// yields validated empty roots with no filesystem writes and never
/// observes the kernel data dir.
fn defaults_registry() -> Arc<ConfigRegistry> {
    static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);
    let slot = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "indramqtt-kernel-{nanos}-{}-{slot}",
        std::process::id()
    ));
    Arc::new(ConfigRegistry::load(&dir).expect("validated defaults always load"))
}

/// Load the kernel config registry from `data_dir`.
///
/// Creates the directory when missing, then loads `<dir>/state.toml`
/// (a missing file yields validated defaults). A corrupt file or an
/// invalid snapshot is a fatal error naming the file and the field;
/// defaults are never silently substituted.
/// Log the licence lifecycle state at boot (B2-04).
///
/// Names the state, the days remaining and what stopped where relevant, so
/// an operator never needs the status route to answer what they are
/// licensed for. MQTT serving never depends on this state: trial, grace
/// and lapsed alike keep connect, publish and subscribe working, and only
/// enterprise entitlements turn off when lapsed.
fn log_licence_lifecycle(state: &InstallationState, warn_days: u64) {
    match state {
        InstallationState::Trial { days_remaining } => {
            info!(
                "Licence state: trial ({} days remaining, every entitlement working)",
                days_remaining
            );
            if *days_remaining <= warn_days {
                warn!(
                    "Trial ends in {} days; generate a licence request via GET /api/v1/licence/request or `indramqtt --licence-request-out <file>`",
                    days_remaining
                );
            }
        }
        InstallationState::Valid {
            customer,
            expires_at,
            max_nodes,
            days_remaining,
            ..
        } => {
            info!(
                "Licence state: valid for '{}' (max {} nodes, expires at {}, {} days remaining)",
                customer, max_nodes, expires_at, days_remaining
            );
            if *days_remaining <= warn_days {
                warn!(
                    "Licence for '{}' expires in {} days (at {}); renew before grace runs out",
                    customer, days_remaining, expires_at
                );
            }
        }
        InstallationState::Grace {
            customer,
            expires_at,
            days_remaining,
            ..
        } => {
            warn!(
                "Licence state: grace for '{}' (expired at {}, {} days remaining); every entitlement still working",
                customer, expires_at, days_remaining
            );
        }
        InstallationState::Lapsed { reason } => {
            warn!(
                "Licence state: lapsed ({reason}); enterprise entitlements off, MQTT still serving"
            );
        }
    }
}

fn load_data_dir_registry(data_dir: &str) -> Result<ConfigRegistry, ConfigError> {
    std::fs::create_dir_all(data_dir).map_err(|err| ConfigError::Load {
        file: data_dir.to_string(),
        reason: format!("cannot create data directory: {err}"),
    })?;
    ConfigRegistry::load(std::path::Path::new(data_dir))
}

/// [`BrokerSink`] that forwards rule output directly to local router
/// subscribers. Pure in-memory fan-out: no sockets, no MQTT loopback.
struct InMemoryBrokerSink {
    router: Arc<Router>,
    sessions: Arc<SessionManager>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
}

#[async_trait]
impl BrokerSink for InMemoryBrokerSink {
    async fn publish(
        &self,
        topic: Topic,
        payload: Bytes,
        qos: QoS,
        retain: bool,
    ) -> Result<(), broker_rules::RuleEngineError> {
        let deliveries = build_downlink_frames(
            &self.router,
            &self.sessions,
            &self.metrics,
            &topic,
            qos,
            retain,
            &payload,
        );
        // Only frames that reached a live mailbox count as
        // forwarded/sent/delivered. Drops are already counted inside
        // `ConnTable::route` (unknown-conn vs. dead-mailbox); counting
        // them here as well would double-count the same loss.
        let mut enqueued = 0u64;
        let mut enqueued_bytes = 0u64;
        for (conn_id, frame) in deliveries {
            let len = frame.total_frame_len() as u64;
            if self.conns.route(conn_id, frame) {
                enqueued += 1;
                enqueued_bytes += len;
            }
        }
        self.metrics.inc_messages_forwarded_by(enqueued);
        self.metrics.inc_publish_sent_by(enqueued);
        self.metrics.inc_delivered_by(enqueued);
        self.metrics.inc_bytes_sent_by(enqueued_bytes);
        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    shared: Shared,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    debug!("BrokerLink IPC connection from {}", peer);

    let transport = FramedTransport::new(stream);
    // Mailbox for guaranteed frames routed to this transport by other
    // tasks (e.g. QoS 1/2 fan-out). QoS 0 rides the bounded
    // per-subscriber backlog in `ConnTable` (D1-02) and is drained
    // alongside this mailbox so a stalled subscriber sheds oldest-first
    // without slowing publishers. The sender is registered under our
    // conn_id once the edge binds. `waker` is this transport's directed
    // QoS 0 wakeup: each bind points its slot at it so fan-out wakes
    // exactly its owner (never the wrong shard).
    let (tx, mut rx) = unbounded_channel::<BrokerFrame>();
    let waker = Arc::new(tokio::sync::Notify::new());
    // Identities bound on this transport. One BrokerLink connection
    // multiplexes every client of its edge shard, so a single slot only
    // remembers the last bind and a dead socket would leak the rest as
    // forever-connected (and their gauge counts). Every bind pushes;
    // Unbind prunes; death detaches whatever remains. Each entry owns
    // exactly one `inc_connections`, balanced by its prune or detach.
    let mut bound: Vec<(String, u64)> = Vec::new();

    loop {
        tokio::select! {
            inbound = transport.recv() => {
                let frame = match inbound {
                    Ok(frame) => frame,
                    Err(brokerlink::BrokerLinkError::ConnectionClosed) => {
                        debug!("BrokerLink IPC peer {} closed", peer);
                        detach(&bound, &shared, &tx);
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("BrokerLink IPC error from {}: {}", peer, e);
                        detach(&bound, &shared, &tx);
                        return Err(Box::new(e));
                    }
                };

                debug!(
                    "BrokerLink recv opcode={:?} conn_id={} seq={}",
                    frame.header.opcode, frame.header.conn_id, frame.header.sequence_no
                );

                handle_inbound_frame(frame, &shared, &tx, &transport, &mut bound, &waker).await?;
                // Opportunistic egress: fan-out in the frame above may
                // have queued QoS 0 for our own bound connections
                // (self-delivery) while we were not waiting on the
                // notify. Drain without waiting so a QoS-0-only burst
                // never depends on winning a notify race.
                if !bound.is_empty() {
                    let mut rx_batch = Vec::new();
                    let mut batch_bytes = 0usize;
                    while rx_batch.len() < brokerlink::transport::MAX_BATCH_FRAMES
                        && batch_bytes < brokerlink::transport::MAX_BATCH_BYTES
                    {
                        match rx.try_recv() {
                            Ok(frame) => {
                                batch_bytes += frame.total_frame_len();
                                rx_batch.push(frame);
                            }
                            Err(_) => break,
                        }
                    }
                    let qos0_batch = drain_qos0_for_transport(
                        &shared,
                        &bound,
                        brokerlink::transport::MAX_BATCH_FRAMES
                            .saturating_sub(rx_batch.len()),
                        brokerlink::transport::MAX_BATCH_BYTES
                            .saturating_sub(batch_bytes),
                    );
                    if !rx_batch.is_empty() || !qos0_batch.is_empty() {
                        let batch = merge_egress_batch(rx_batch, qos0_batch);
                        let batch_len = batch.len() as u64;
                        match transport.send_batch(&batch).await {
                            Ok(()) => {
                                shared.metrics.inc_transport_sent_by(batch_len);
                            }
                            Err(e) => {
                                shared.metrics.inc_transport_send_failed();
                                return Err(Box::new(e));
                            }
                        }
                    }
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(first) => {
                        // PERF-05: flush once per poll. Coalesce what is
                        // already queued (non-blocking drain, bounded by
                        // frames and encoded bytes) into one write_all +
                        // flush; order is arrival order within each class.
                        // Guaranteed frames come from `rx`, QoS 0 from the
                        // bounded backlog; the merge restores per-destination
                        // sequence order so mixed qualities never reorder a
                        // subscriber. No artificial delay: a lone frame
                        // sends immediately.
                        let mut rx_batch = vec![first];
                        let mut batch_bytes =
                            rx_batch[0].total_frame_len();
                        while rx_batch.len() < brokerlink::transport::MAX_BATCH_FRAMES
                            && batch_bytes
                                < brokerlink::transport::MAX_BATCH_BYTES
                        {
                            match rx.try_recv() {
                                Ok(frame) => {
                                    batch_bytes += frame.total_frame_len();
                                    rx_batch.push(frame);
                                }
                                Err(_) => break,
                            }
                        }
                        let qos0_batch = drain_qos0_for_transport(
                            &shared,
                            &bound,
                            brokerlink::transport::MAX_BATCH_FRAMES
                                .saturating_sub(rx_batch.len()),
                            brokerlink::transport::MAX_BATCH_BYTES
                                .saturating_sub(batch_bytes),
                        );
                        let batch = merge_egress_batch(rx_batch, qos0_batch);
                        // Egress stage 0: `messages_forwarded` counted
                        // admission into the mailboxes at `route()` time;
                        // only a successful write counts as edge arrival.
                        let batch_len = batch.len() as u64;
                        match transport.send_batch(&batch).await {
                            Ok(()) => {
                                shared.metrics.inc_transport_sent_by(batch_len);
                            }
                            Err(e) => {
                                shared.metrics.inc_transport_send_failed();
                                return Err(Box::new(e));
                            }
                        }
                    }
                    None => {
                        // Guaranteed senders gone; QoS 0 may still hold
                        // queued frames for our bound connections: drain
                        // what remains before detaching.
                        let qos0_batch = drain_qos0_for_transport(
                            &shared,
                            &bound,
                            brokerlink::transport::MAX_BATCH_FRAMES,
                            brokerlink::transport::MAX_BATCH_BYTES,
                        );
                        if !qos0_batch.is_empty() {
                            let batch_len = qos0_batch.len() as u64;
                            match transport.send_batch(&qos0_batch).await {
                                Ok(()) => {
                                    shared.metrics.inc_transport_sent_by(batch_len);
                                }
                                Err(e) => {
                                    shared.metrics.inc_transport_send_failed();
                                    detach(&bound, &shared, &tx);
                                    return Err(Box::new(e));
                                }
                            }
                        }
                        detach(&bound, &shared, &tx);
                        return Ok(());
                    }
                }
            }
            () = waker.notified() => {
                // QoS-0-only burst for our own bound connections (directed
                // wakeup, never another shard's): drain both mailboxes in
                // one batch so a QoS-0-only workload never sleeps.
                let mut rx_batch = Vec::new();
                let mut batch_bytes = 0usize;
                while rx_batch.len() < brokerlink::transport::MAX_BATCH_FRAMES
                    && batch_bytes < brokerlink::transport::MAX_BATCH_BYTES
                {
                    match rx.try_recv() {
                        Ok(frame) => {
                            batch_bytes += frame.total_frame_len();
                            rx_batch.push(frame);
                        }
                        Err(_) => break,
                    }
                }
                if rx_batch.is_empty() {
                    // Spurious wakeup with nothing for us (another
                    // transport's connections): park again without a
                    // socket write. Check cheaply whether any of our
                    // connections actually holds QoS 0 before draining.
                    let mut ours = false;
                    for (_, conn_id) in &bound {
                        if shared.conns.qos0_len(*conn_id) > 0 {
                            ours = true;
                            break;
                        }
                    }
                    if !ours {
                        continue;
                    }
                }
                let qos0_batch = drain_qos0_for_transport(
                    &shared,
                    &bound,
                    brokerlink::transport::MAX_BATCH_FRAMES
                        .saturating_sub(rx_batch.len()),
                    brokerlink::transport::MAX_BATCH_BYTES
                        .saturating_sub(batch_bytes),
                );
                if rx_batch.is_empty() && qos0_batch.is_empty() {
                    continue;
                }
                let batch = merge_egress_batch(rx_batch, qos0_batch);
                let batch_len = batch.len() as u64;
                match transport.send_batch(&batch).await {
                    Ok(()) => {
                        shared.metrics.inc_transport_sent_by(batch_len);
                    }
                    Err(e) => {
                        shared.metrics.inc_transport_send_failed();
                        return Err(Box::new(e));
                    }
                }
            }
        }
    }
}

/// Drain QoS 0 backlogs for one transport's bound connections,
/// round-robin so one stalled subscriber cannot starve a fast one on
/// the same shard. Respects `max_frames` and `max_bytes` via the
/// budget-aware drain in [`ConnTable`]; stops early when no connection
/// makes progress. Never blocks; pops only what is queued.
fn drain_qos0_for_transport(
    shared: &Shared,
    bound: &[(String, u64)],
    max_frames: usize,
    max_bytes: usize,
) -> Vec<BrokerFrame> {
    let mut out = Vec::new();
    if max_frames == 0 || bound.is_empty() {
        return out;
    }
    let mut out_bytes = 0usize;
    // Round-robin one pass per connection per round: a full backlog on
    // one connection fills at most its fair share of each batch.
    loop {
        if out.len() >= max_frames || out_bytes >= max_bytes {
            break;
        }
        let mut progressed = false;
        for (_, conn_id) in bound {
            if out.len() >= max_frames || out_bytes >= max_bytes {
                break;
            }
            let remaining_frames = max_frames - out.len();
            let remaining_bytes = max_bytes.saturating_sub(out_bytes);
            // Drain at most one frame per visit for fairness; the
            // budget-aware drain still honours a single large frame.
            let frames = shared.conns.drain_qos0_with_budget(
                *conn_id,
                remaining_frames.min(1),
                remaining_bytes,
            );
            if frames.is_empty() {
                // No backlog or budget spent for this connection.
                // A single large frame with an empty batch still drains
                // alone via the budget-aware path above (which returns
                // it even when over budget); empty here means truly
                // empty, so keep scanning the rest.
                continue;
            }
            for frame in frames {
                out_bytes += frame.total_frame_len();
                out.push(frame);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    out
}

/// Merge guaranteed (`rx`) and QoS 0 batches into one socket write
/// while preserving per-destination order. Frames carry independent
/// per-connection sequence numbers, so grouping by `conn_id` and
/// sorting each group by `sequence_no` restores publish order for a
/// subscriber that receives mixed qualities; cross-connection order is
/// irrelevant (different subscribers). Groups emit in `conn_id` order
/// for determinism.
fn merge_egress_batch(
    rx_batch: Vec<BrokerFrame>,
    qos0_batch: Vec<BrokerFrame>,
) -> Vec<BrokerFrame> {
    if qos0_batch.is_empty() {
        return rx_batch;
    }
    if rx_batch.is_empty() {
        return qos0_batch;
    }
    use std::collections::HashMap;
    let mut by_conn: HashMap<u64, Vec<BrokerFrame>> = HashMap::new();
    for frame in rx_batch.into_iter().chain(qos0_batch) {
        by_conn.entry(frame.header.conn_id).or_default().push(frame);
    }
    let mut conn_ids: Vec<u64> = by_conn.keys().copied().collect();
    conn_ids.sort_unstable();
    let mut out = Vec::new();
    for conn_id in conn_ids {
        let mut frames = by_conn.remove(&conn_id).unwrap_or_default();
        frames.sort_by_key(|frame| frame.header.sequence_no);
        out.extend(frames);
    }
    out
}

/// Detach a dead transport: forget its mailbox and detach every
/// session bound on it. Clean sessions drop their subscriptions (session
/// mirror and router copies, plus their unacked QoS 1 inflight state);
/// durable sessions keep subscriptions + offline queue + inflight for
/// reconnect replay. Per-transport work only: each entry touches its own
/// session plus atomics, so deaths on other transports never block this
/// one. Router sweeps run once per detached clean session, off the hot
/// path; fan-out takes no new lock.
fn detach(bound: &[(String, u64)], shared: &Shared, tx: &UnboundedSender<BrokerFrame>) {
    shared.conns.prune_sender(tx);
    if bound.is_empty() {
        return;
    }
    for (client_id, conn_id) in bound {
        let swept = shared.sessions.unbind_connection(client_id, *conn_id);
        for filter in &swept {
            shared.router.unsubscribe(filter, client_id);
        }
        let active = shared.metrics.dec_connections();
        shared.stats.set_connections(active.max(0) as u64);
    }
    refresh_subscription_stats(shared);
}

/// Push subscription/topic gauges into the stats store using the same
/// counting as the management API `gather_stats` (active sessions only,
/// distinct filters), so `/stats` maxima agree exactly with live reads.
/// Lifecycle points only (bind, detach, unbind, subscribe): the
/// per-message publish path performs no session/router scans.
fn refresh_subscription_stats(shared: &Shared) {
    let active_ids = shared.sessions.active_client_ids();
    let mut subs = 0u64;
    let mut topic_set = std::collections::HashSet::new();
    for cid in &active_ids {
        if let Some(s) = shared.sessions.get(cid) {
            let map = s.subscriptions.read();
            subs += map.len() as u64;
            for f in map.keys() {
                topic_set.insert(f.as_str().to_string());
            }
        }
    }
    shared.stats.set_subscriptions(subs);
    shared.stats.set_topics(topic_set.len() as u64);
}

/// Recount retained topics into the stats store after a successful
/// insert/remove. Uses the existing `find_matching("#")` read path (no
/// new store API), so concurrent retained writes self-heal instead of
/// drifting the way check-then-act deltas would.
async fn sync_retained_stat(shared: &Shared) {
    let filter = TopicFilter::new("#").expect("# matches every retained topic");
    match shared.retained.find_matching(&filter).await {
        Ok(matched) => shared.stats.set_retained(matched.len() as u64),
        Err(e) => warn!("Retained recount failed: {}", e),
    }
}

/// Process one frame from the edge: direct replies go back on our own
/// transport, routed frames fan out through the connection table.
async fn handle_inbound_frame<S>(
    frame: BrokerFrame,
    shared: &Shared,
    tx: &UnboundedSender<BrokerFrame>,
    transport: &FramedTransport<S>,
    bound: &mut Vec<(String, u64)>,
    waker: &Arc<tokio::sync::Notify>,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Measured ingress bytes from the real BrokerLink frame length.
    shared
        .metrics
        .inc_bytes_received_by(frame.total_frame_len() as u64);
    match frame.header.opcode {
        OpCode::BindConnection => {
            shared.metrics.inc_connect_received();
            if let Some(reply) = apply_bind(&frame, shared).await {
                let accepted = is_binding_accepted(&reply);
                shared.metrics.inc_connack_sent();
                transport.send(reply).await?;
                shared.conns.register(frame.header.conn_id, tx.clone());
                let active = shared.metrics.inc_connections();
                shared.stats.set_connections(active.max(0) as u64);
                refresh_subscription_stats(shared);
                // Remember who we serve so a dead socket detaches cleanly.
                // One entry per bind: this transport multiplexes its whole
                // shard, and death must detach every client on it.
                if let Ok(req) = decode_bind_meta(&frame.metadata) {
                    // D1-02: label the mailbox for per-client shed
                    // accounting and point it at this transport's directed
                    // wakeup. Short writes on bind only; the per-message
                    // publish path reads them without new work beyond its
                    // existing shard lock.
                    shared
                        .conns
                        .set_client_label(frame.header.conn_id, &req.client_id);
                    shared.conns.set_waker(frame.header.conn_id, waker);
                    bound.push((req.client_id.clone(), frame.header.conn_id));
                    // Auto-subscribe hook (W1-39): only on accepted binds.
                    // Per-connect cost only; fan-out takes no new lock.
                    if accepted {
                        apply_auto_subscribe(
                            shared,
                            &req.client_id,
                            req.username.as_deref(),
                            frame.header.conn_id,
                        );
                    }
                }
                let replayed = replay_offline(&frame, shared).await;
                shared.metrics.inc_messages_forwarded_by(replayed as u64);
            }
        }
        OpCode::Ping => {
            shared.metrics.inc_pingreq_received();
            if let Some(reply) = reply_for_frame(&frame, &shared.sessions) {
                shared.metrics.inc_pingresp_sent();
                transport.send(reply).await?;
            }
        }
        OpCode::SubscribeIn => match apply_subscribe(&frame, shared).await {
            (Some(reply), retained) => {
                shared.metrics.inc_suback_sent();
                transport.send(reply).await?;
                // SUBACK first, then retained state, per MQTT ordering.
                for held in &retained {
                    transport.send(held.clone()).await?;
                }
                shared
                    .metrics
                    .inc_messages_forwarded_by(retained.len() as u64);
                shared.metrics.inc_publish_sent_by(retained.len() as u64);
                shared.metrics.inc_delivered_by(retained.len() as u64);
                shared.metrics.inc_bytes_sent_by(
                    retained
                        .iter()
                        .map(|held| held.total_frame_len() as u64)
                        .sum(),
                );
            }
            (None, _) => {
                warn!(
                    "Dropping malformed SubscribeIn from conn {}",
                    frame.header.conn_id
                );
            }
        },
        OpCode::PublishIn => {
            let (ack, deliveries) = apply_publish(&frame, shared).await;
            if let Some(ack) = ack {
                transport.send(ack).await?;
            }
            // Only frames that reached a live mailbox count as
            // forwarded/sent/delivered. Drops are already counted inside
            // `ConnTable::route` (unknown-conn vs. dead-mailbox); counting
            // them here as well would double-count the same loss.
            let mut enqueued = 0u64;
            let mut enqueued_bytes = 0u64;
            for (conn_id, routed) in deliveries {
                let len = routed.total_frame_len() as u64;
                if shared.conns.route(conn_id, routed) {
                    enqueued += 1;
                    enqueued_bytes += len;
                }
            }
            shared.metrics.inc_messages_forwarded_by(enqueued);
            shared.metrics.inc_publish_sent_by(enqueued);
            shared.metrics.inc_delivered_by(enqueued);
            shared.metrics.inc_bytes_sent_by(enqueued_bytes);
        }
        OpCode::PubAckIn => {
            // T-31: the edge forwards each subscriber PUBACK; release
            // the matching inflight entry so it is never replayed.
            // Unknown connections, unknown sessions and stale ids are
            // ignored: at-most-once PUBACKs from a previous incarnation
            // must never disturb live state.
            apply_puback(&frame, shared);
        }
        OpCode::PubRelIn => {
            // D1-01 inbound second phase: route once, reply PUBCOMP.
            let (comp, deliveries) = apply_qos2_pubrel(&frame, shared).await;
            if let Some(comp) = comp {
                transport.send(comp).await?;
            }
            let mut enqueued = 0u64;
            let mut enqueued_bytes = 0u64;
            for (conn_id, routed) in deliveries {
                let len = routed.total_frame_len() as u64;
                if shared.conns.route(conn_id, routed) {
                    enqueued += 1;
                    enqueued_bytes += len;
                }
            }
            shared.metrics.inc_messages_forwarded_by(enqueued);
            shared.metrics.inc_publish_sent_by(enqueued);
            shared.metrics.inc_delivered_by(enqueued);
            shared.metrics.inc_bytes_sent_by(enqueued_bytes);
        }
        OpCode::PubRecIn => {
            // D1-01 outbound second phase: the subscriber answered our
            // QoS 2 PUBLISH; send PUBREL. Unknown ids are ignored.
            if let Some(rel) = apply_qos2_pubrec(&frame, shared) {
                transport.send(rel).await?;
            }
        }
        OpCode::PubCompIn => {
            // D1-01 outbound completion: release the packet id.
            apply_qos2_pubcomp(&frame, shared);
        }
        OpCode::UnbindConnection => {
            apply_unbind(&frame, shared);
            // Forget this transport's identities for the connection so a
            // long-lived shard never accumulates one entry per bind ever.
            // Each forgotten entry balances its bind's `inc_connections`
            // here, leaving death to settle whatever remains.
            let before = bound.len();
            bound.retain(|(_, conn_id)| *conn_id != frame.header.conn_id);
            for _ in 0..before - bound.len() {
                let active = shared.metrics.dec_connections();
                shared.stats.set_connections(active.max(0) as u64);
            }
            if before != bound.len() {
                refresh_subscription_stats(shared);
            }
        }
        OpCode::Credit => {
            // Egress stage 1: the owning edge connection reports its
            // pressure snapshot. Counted on receipt today; no delivery
            // decision depends on it until the kernel queue split lands.
            // Malformed snapshots are ignored: credit is advisory, and a
            // single bad frame must never disturb live connections.
            if decode_credit_meta(&frame.metadata).is_some() {
                shared.metrics.inc_credit_received();
            }
        }
        _ => {
            if let Some(reply) = reply_for_frame(&frame, &shared.sessions) {
                transport.send(reply).await?;
            }
        }
    }
    Ok(())
}

/// Register the subscriptions of one `SubscribeIn` frame and build its
/// `SubAckOut` reply plus any retained messages for the new subscription.
/// Malformed framing yields `(None, empty)` (the edge treats a missing
/// SubAck as a hung request scoped to that connection).
///
/// Meta layout: `PacketId:16be | IdLen:16be | ClientId | N:16be |
/// (FilterLen:16be | Filter | QoS:8) * N`. Each granted code echoes the
/// requested QoS; invalid filters and ACL denials are answered with
/// `0x80` (not authorized) and `0x87` respectively and register nothing.
/// `$share/<group>/` prefixes are split before routing, ACL checks,
/// retained fetch, and cluster announce so every downstream stage sees
/// the plain inner filter. Retained deliveries carry `retain = true` at
/// `min(subscription QoS, stored QoS)`.
async fn apply_subscribe(
    frame: &BrokerFrame,
    shared: &Shared,
) -> (Option<BrokerFrame>, Vec<BrokerFrame>) {
    shared.metrics.inc_subscribe_received();
    let (packet_id, client_id, subs) = match decode_subscribe_meta(&frame.metadata) {
        Some(parts) => parts,
        None => return (None, Vec::new()),
    };

    let mut codes = Vec::with_capacity(subs.len());
    let mut granted: Vec<(TopicFilter, u8)> = Vec::with_capacity(subs.len());
    for (raw_filter_str, qos_raw) in subs {
        // B4-04 ordered regex filter rewriting (subscribe scope): the
        // first matching subscribe/both rule wins and the router, the
        // session mirror, the cluster announce and retained replay all
        // observe the rewritten filter. `None` subscribes unchanged.
        // System-prefixed filters bypass rewriting inside the router so
        // shared-subscription group splitting keeps its semantics.
        let filter_str = match shared.router.rewrite_subscribe(&raw_filter_str) {
            Some(rewritten) => rewritten,
            None => raw_filter_str,
        };
        // Delayed topics are publish-only markers, never subscriptions.
        if strip_delayed_prefix(&filter_str).is_some() {
            codes.push(0x80);
            continue;
        }
        let parsed = TopicFilter::new(filter_str).ok().and_then(|filter| {
            QoS::try_from(qos_raw).ok().and_then(|qos| {
                split_shared_filter(&filter).map(|(group, inner)| (inner, qos, group))
            })
        });
        let (filter, qos, group) = match parsed {
            Some(parts) => parts,
            None => {
                codes.push(0x80);
                continue;
            }
        };
        if shared
            .auth
            .authorize_subscribe(&client_id, &filter)
            .await
            .is_err()
        {
            // MQTT 5 style "Not Authorized"; registers nothing.
            codes.push(0x87);
            continue;
        }
        shared.router.subscribe(
            &filter,
            Subscription {
                client_id: client_id.clone().into(),
                conn_id: frame.header.conn_id,
                qos,
                group,
            },
        );
        // Mirror the grant on the session for observability (the router
        // stays the routing authority).
        shared
            .sessions
            .add_subscription(&client_id, filter.clone(), qos);
        granted.push((filter, qos_raw));
        codes.push(qos_raw);
    }
    if !granted.is_empty() {
        refresh_subscription_stats(shared);
    }

    let mut meta = Vec::with_capacity(2 + codes.len());
    meta.extend_from_slice(&packet_id.to_be_bytes());
    meta.extend_from_slice(&codes);
    let reply = BrokerFrame::new(
        OpCode::SubAckOut,
        frame.header.conn_id,
        frame.header.sequence_no,
        Bytes::from(meta),
        Bytes::new(),
    )
    .ok();

    // Clustered mode: publish our route summary (filter-level only, never
    // individual subscriptions) so peers forward matching publishes here.
    if let Some(cluster) = &shared.cluster {
        for (filter, _) in &granted {
            if let Err(e) = cluster.announce_filter(filter).await {
                warn!("Cluster announce failed for {}: {}", filter.as_str(), e);
            }
        }
    }

    // Retained state follows the SubAck on the same transport.
    let mut retained = Vec::new();
    let session = shared.sessions.get(&client_id);
    for (filter, sub_qos) in &granted {
        let matched = match shared.retained.find_matching(filter).await {
            Ok(matched) => matched,
            Err(e) => {
                warn!("Retained lookup failed for {}: {}", filter.as_str(), e);
                continue;
            }
        };
        for msg in matched {
            let effective = std::cmp::min(*sub_qos, u8::from(msg.qos));
            let downlink_id = if effective == 0 {
                0u16
            } else {
                match &session {
                    Some(session) => session.next_packet_id(),
                    None => 1u16,
                }
            };
            // D1-01: retained QoS 2 deliveries enter the two-phase
            // exchange like live ones (QoS 1 retained keeps its existing
            // untracked behaviour).
            if effective == 2 {
                if let Some(session) = &session {
                    let tracked = session.track_qos2_outbound(Qos2OutboundEntry {
                        packet_id: downlink_id,
                        topic: msg.topic.clone(),
                        retain: true,
                        payload: msg.payload.clone(),
                        rec_received: false,
                    });
                    if !tracked {
                        shared.metrics.inc_inflight_dropped();
                    }
                }
            }
            let topic_str = msg.topic.as_str();
            let mut meta = Vec::with_capacity(2 + topic_str.len() + 2 + 3);
            meta.extend_from_slice(&(topic_str.len() as u16).to_be_bytes());
            meta.extend_from_slice(topic_str.as_bytes());
            meta.extend_from_slice(&downlink_id.to_be_bytes());
            meta.push(effective);
            meta.push(1u8); // retain: replayed retained state
            meta.push(0u8);
            if let Ok(routed) = BrokerFrame::new(
                OpCode::PublishOut,
                frame.header.conn_id,
                0,
                Bytes::from(meta),
                msg.payload.clone(),
            ) {
                retained.push(routed);
            }
        }
    }

    (reply, retained)
}

/// Replay a resumed durable session's backlog onto its new connection:
/// unacknowledged QoS 1 window downlinks first (T-31, DUP set, original
/// order, same packet ids), then the QoS 1 spill overflow (B4-01, DUP
/// set, arrival order, same packet ids), then uncompleted QoS 2
/// downlinks (D1-01, in queued order: PUBLISH with DUP set while waiting
/// for PUBREC, PUBREL while waiting for PUBCOMP), then the offline queue
/// of never-routed messages. Runs after the `SessionBinding` reply so
/// the edge always observes binding before backlog. Returns the replayed
/// frame count.
async fn replay_offline(frame: &BrokerFrame, shared: &Shared) -> usize {
    let req = match decode_bind_meta(&frame.metadata) {
        Ok(req) => req,
        Err(_) => return 0,
    };
    let session = match shared.sessions.get(&req.client_id) {
        Some(session) => session,
        None => return 0,
    };
    let mut replayed = 0;
    let mut replayed_bytes: u64 = 0;
    // T-31: unacked downlinks predate anything queued while detached,
    // so they replay first. Entries stay held until their PUBACK: a
    // second reconnect without acks replays them again. Same packet id
    // with DUP set, so resume can never collide with ids in use.
    for held in session.inflight_snapshot() {
        let topic_str = held.topic.as_str();
        let mut meta = Vec::with_capacity(2 + topic_str.len() + 2 + 3);
        meta.extend_from_slice(&(topic_str.len() as u16).to_be_bytes());
        meta.extend_from_slice(topic_str.as_bytes());
        meta.extend_from_slice(&held.packet_id.to_be_bytes());
        meta.push(u8::from(held.qos));
        meta.push(u8::from(held.retain));
        meta.push(1u8); // dup: redelivery of an unacked downlink
        if let Ok(routed) = BrokerFrame::new(
            OpCode::PublishOut,
            frame.header.conn_id,
            0, // stamped per-destination by ConnTable::route
            Bytes::from(meta),
            held.payload.clone(),
        ) {
            let len = routed.total_frame_len() as u64;
            if shared.conns.route(frame.header.conn_id, routed) {
                replayed_bytes += len;
                replayed += 1;
            }
        }
    }
    // B4-01: spilled overflow replays immediately after the window, in
    // arrival order, with DUP set and the original packet ids. Entries
    // stay held until their PUBACK like the window. This consults the
    // spilled state written by `build_downlink_frames` on the
    // publish-to-delivery event; driven by the reconnect (SessionBinding)
    // event. Each mailbox arrival also bumps `inflight_spill_replayed`
    // so spill redelivery is never silent. The spill snapshot (one Vec
    // alloc sized by the spill length plus one frame alloc per spilled
    // message, all bounded by max_spill) runs only when spill is
    // non-empty (one relaxed atomic load via `has_spill`);
    // steady-state reconnect with empty spill allocates exactly what the
    // window replay allocated before B4-01. Spill-nonempty snapshot
    // throughput is printed by
    // `broker-session::test_qos1_inflight_hot_path_timings` (slow-path
    // section); broker delivery/replay workload before/after numbers
    // (steady-state `apply_publish` rate as the pre-change baseline vs
    // spill-overflow and `replay_offline` rates) are printed by
    // `qos1_inflight_delivery_workload_timings`; functional spill replay
    // through this path is asserted by
    // `qos1_inflight_spill_redelivers_everything_with_dup`.
    if session.has_spill() {
        for held in session.inflight_spill_snapshot() {
            let topic_str = held.topic.as_str();
            let mut meta = Vec::with_capacity(2 + topic_str.len() + 2 + 3);
            meta.extend_from_slice(&(topic_str.len() as u16).to_be_bytes());
            meta.extend_from_slice(topic_str.as_bytes());
            meta.extend_from_slice(&held.packet_id.to_be_bytes());
            meta.push(u8::from(held.qos));
            meta.push(u8::from(held.retain));
            meta.push(1u8); // dup: redelivery of a spilled unacked downlink
            if let Ok(routed) = BrokerFrame::new(
                OpCode::PublishOut,
                frame.header.conn_id,
                0, // stamped per-destination by ConnTable::route
                Bytes::from(meta),
                held.payload.clone(),
            ) {
                let len = routed.total_frame_len() as u64;
                if shared.conns.route(frame.header.conn_id, routed) {
                    replayed_bytes += len;
                    replayed += 1;
                    shared.metrics.inc_inflight_spill_replayed();
                }
            }
        }
    }
    // D1-01: uncompleted QoS 2 downlinks replay in queued order. Waiting
    // for PUBREC resends PUBLISH with DUP set and the same packet id;
    // waiting for PUBCOMP resends PUBREL. Entries stay held until their
    // PUBCOMP, so a second reconnect without completion replays again.
    for held in session.qos2_outbound_snapshot() {
        if held.rec_received {
            if let Some(routed) = encode_pubrel_out(frame.header.conn_id, held.packet_id) {
                let len = routed.total_frame_len() as u64;
                if shared.conns.route(frame.header.conn_id, routed) {
                    replayed_bytes += len;
                    replayed += 1;
                }
            }
        } else {
            let topic_str = held.topic.as_str();
            if let Some(routed) = encode_publish_out_with_dup(
                frame.header.conn_id,
                topic_str,
                held.packet_id,
                2,
                held.retain,
                true,
                &held.payload,
            ) {
                let len = routed.total_frame_len() as u64;
                if shared.conns.route(frame.header.conn_id, routed) {
                    replayed_bytes += len;
                    replayed += 1;
                }
            }
        }
    }
    for queued in session.drain_offline() {
        let downlink_id = if queued.qos == QoS::AtMostOnce {
            0u16
        } else {
            session.next_packet_id()
        };
        let topic_str = queued.topic.as_str();
        let mut meta = Vec::with_capacity(2 + topic_str.len() + 2 + 3);
        meta.extend_from_slice(&(topic_str.len() as u16).to_be_bytes());
        meta.extend_from_slice(topic_str.as_bytes());
        meta.extend_from_slice(&downlink_id.to_be_bytes());
        meta.push(u8::from(queued.qos));
        meta.push(u8::from(queued.retain));
        meta.push(0u8);
        if let Ok(routed) = BrokerFrame::new(
            OpCode::PublishOut,
            frame.header.conn_id,
            0, // stamped per-destination by ConnTable::route
            Bytes::from(meta),
            queued.payload.clone(),
        ) {
            // QoS 2 offline replays become live QoS 2 downlinks needing
            // PUBREC/PUBCOMP, so track them (QoS 1 offline replays keep
            // their existing untracked behaviour).
            if queued.qos == QoS::ExactlyOnce && downlink_id != 0 {
                let tracked = session.track_qos2_outbound(Qos2OutboundEntry {
                    packet_id: downlink_id,
                    topic: queued.topic.clone(),
                    retain: queued.retain,
                    payload: queued.payload.clone(),
                    rec_received: false,
                });
                if !tracked {
                    shared.metrics.inc_inflight_dropped();
                }
            }
            // Only replays that reached the live mailbox count; a dead
            // mailbox is already counted inside `ConnTable::route`, never
            // a delivery.
            let len = routed.total_frame_len() as u64;
            if shared.conns.route(frame.header.conn_id, routed) {
                replayed_bytes += len;
                replayed += 1;
            }
        }
    }
    shared.metrics.inc_publish_sent_by(replayed as u64);
    shared.metrics.inc_delivered_by(replayed as u64);
    shared.metrics.inc_bytes_sent_by(replayed_bytes);
    replayed
}

/// Route one `PublishIn` frame: an optional `PubAckOut` for the publisher
/// (QoS 1) plus one `PublishOut` per matching subscriber.
///
/// Ingress-only rule execution runs first on the receiving node; the
/// standard router fan-out follows. Delivery QoS is `min(publish QoS,
/// subscription QoS)`; QoS 1 deliveries draw their packet id from the
/// subscriber session so each downstream flow keeps an independent id
/// space. The raw payload bytes are forwarded untouched.
///
/// `$delayed/<secs>/<topic>` targets defer everything except the
/// publisher ack: after the delay the message re-enters through
/// [`ingress_pipeline`] with the inner topic (retained store, rules,
/// fan-out, cluster forward), so delayed delivery observes the same
/// semantics as immediate delivery, just later.
async fn apply_publish(
    frame: &BrokerFrame,
    shared: &Shared,
) -> (Option<BrokerFrame>, Vec<(u64, BrokerFrame)>) {
    shared.metrics.inc_publish_received();
    let (raw_topic_str, packet_id, qos_raw, retain) = match decode_publish_meta(&frame.metadata) {
        Some(parts) => parts,
        None => return (None, Vec::new()),
    };
    // B4-04 ordered regex topic rewriting (publish scope): the first
    // matching publish/both rule wins and every stage below (auth,
    // quota, retained store, rule engine, fan-out, cluster forward)
    // observes the rewritten name. `None` delivers unchanged. QoS 2
    // stores the rewritten name, so its second phase routes without a
    // second rewrite. System-prefixed names (`$delayed/` markers,
    // shared-subscription requests) bypass rewriting inside the router,
    // so delayed entries schedule the literal inner topic and delayed
    // markers keep their semantics.
    let topic_str = match shared.router.rewrite_publish(&raw_topic_str) {
        Some(rewritten) => rewritten,
        None => raw_topic_str,
    };
    let topic = match Topic::new(topic_str.clone()) {
        Ok(topic) => topic,
        Err(_) => {
            // A `$delayed/<secs>/<inner>` marker whose inner topic carries
            // wildcards fails the outer concrete-topic check before the
            // delayed path is reached. Count it as a malformed delayed
            // drop (fail closed, never queued) so the counter observes it.
            if strip_delayed_prefix(&topic_str).is_some() {
                shared.delayed.note_malformed();
                warn!("Dropping delayed publish with bad inner topic");
            }
            return (None, Vec::new());
        }
    };
    let qos = match QoS::try_from(qos_raw) {
        Ok(qos) => qos,
        Err(_) => return (None, Vec::new()),
    };
    match qos {
        QoS::AtMostOnce => {
            shared.metrics.inc_qos0_received();
        }
        QoS::AtLeastOnce => {
            shared.metrics.inc_qos1_received();
        }
        QoS::ExactlyOnce => {
            shared.metrics.inc_qos2_received();
        }
    }
    shared.metrics.inc_messages_received();

    // ACL: the publisher is whoever owns this edge connection. Denied
    // publishes die here (QoS 1 still gets its PubAck, stamped 0x87;
    // QoS 2 completes its handshake with PUBREC so the publisher never
    // stalls, but nothing is stored and the later PUBREL routes nothing).
    if let Some(publisher) = shared.sessions.client_id_for_conn(frame.header.conn_id) {
        // B1-03: a client banned mid-session stops being served. The ban
        // directory is consulted on every publish authorisation: one read
        // lock that returns after a length check when no bans exist, one
        // short scan otherwise (QoS 1 timings before/after are in the
        // B1-03 report). Denied publishes die exactly like ACL denials.
        let (username, peerhost) = match shared.sessions.get(&publisher) {
            Some(session) => (
                session.username.read().clone(),
                session.peerhost.read().clone(),
            ),
            None => (None, None),
        };
        if shared
            .bans
            .is_banned(&publisher, username.as_deref(), peerhost.as_deref())
        {
            let ack = match qos {
                QoS::AtLeastOnce => pub_ack_reply(frame, packet_id, 0x87),
                QoS::ExactlyOnce => qos2_reply(OpCode::PubRecOut, frame, packet_id),
                QoS::AtMostOnce => None,
            };
            return (ack, Vec::new());
        }
        if shared
            .auth
            .authorize_publish(&publisher, &topic)
            .await
            .is_err()
        {
            let ack = match qos {
                QoS::AtLeastOnce => pub_ack_reply(frame, packet_id, 0x87),
                QoS::ExactlyOnce => qos2_reply(OpCode::PubRecOut, frame, packet_id),
                QoS::AtMostOnce => None,
            };
            return (ack, Vec::new());
        }
    }

    // Rate policing (INDRA-128): token bucket per publishing client,
    // configured per user. Over quota the message dies here — QoS 0 is
    // dropped and counted, QoS 1 gets its PubAck stamped 0x97, QoS 2
    // completes its handshake with PUBREC but stores nothing.
    if !check_publish_quota(frame, shared).await {
        shared.metrics.inc_messages_dropped();
        shared.metrics.inc_overload_dropped();
        let ack = match qos {
            QoS::AtLeastOnce => pub_ack_reply(frame, packet_id, 0x97),
            QoS::ExactlyOnce => qos2_reply(OpCode::PubRecOut, frame, packet_id),
            QoS::AtMostOnce => None,
        };
        return (ack, Vec::new());
    }

    // QoS 2 inbound first phase (D1-01): record the packet id against the
    // publisher session and reply PUBREC. A repeat of the same id before
    // PUBREL is a duplicate: reply PUBREC again without storing or
    // routing a second time. Nothing routes until PUBREL arrives.
    if qos == QoS::ExactlyOnce {
        return apply_qos2_publish(frame, shared, &topic_str, topic, packet_id, retain).await;
    }

    // Delayed delivery: ack now (the publisher must not stall), defer
    // everything else past the timer.
    if let Some((delay_secs, inner)) = strip_delayed_prefix(&topic_str) {
        return apply_delayed_publish(frame, shared, delay_secs, inner, qos, retain, packet_id)
            .await;
    }

    let ack = if qos == QoS::AtLeastOnce {
        pub_ack_reply(frame, packet_id, 0)
    } else {
        None
    };

    // B4-02: resolve the publisher once for the shared `hash_clientid`
    // strategy. `None` (unknown session) hashes the empty string in the
    // router; delivery still proceeds to exactly one member.
    let publisher = shared.sessions.client_id_for_conn(frame.header.conn_id);
    let deliveries = ingress_pipeline_with_publisher(
        shared,
        &topic,
        qos,
        retain,
        &frame.payload,
        publisher.as_deref(),
    )
    .await;
    forward_cluster(shared, &topic, qos, &frame.payload).await;

    (ack, deliveries)
}

/// Handle a `$delayed/<secs>/<topic>` publish: immediate ack, deferred
/// pipeline through the shared timer wheel. An unparseable inner topic,
/// an over-limit delay, an oversized payload or a full backlog drops the
/// message with a warning and a counter (it could never be delivered
/// correctly). The entry is recorded in the wheel and in
/// `<data-dir>/delayed.jsonl` (see `delayed.rs`) before the ack is
/// returned, so the publisher is never stalled past the timer and a
/// restart keeps the entry on schedule.
async fn apply_delayed_publish(
    frame: &BrokerFrame,
    shared: &Shared,
    delay_secs: u64,
    inner: &str,
    qos: QoS,
    retain: bool,
    packet_id: u16,
) -> (Option<BrokerFrame>, Vec<(u64, BrokerFrame)>) {
    let inner_topic = match Topic::new(inner.to_string()) {
        Ok(topic) => topic,
        Err(e) => {
            shared.delayed.note_malformed();
            warn!("Dropping delayed publish with bad inner topic: {}", e);
            return (None, Vec::new());
        }
    };
    if delay_secs == 0 {
        let ack = if qos == QoS::AtLeastOnce {
            pub_ack_reply(frame, packet_id, 0)
        } else {
            None
        };
        // B4-02: delayed delivery keeps the publisher when the session
        // still exists so `hash_clientid` stays stable across the defer.
        let publisher = shared.sessions.client_id_for_conn(frame.header.conn_id);
        let deliveries = ingress_pipeline_with_publisher(
            shared,
            &inner_topic,
            qos,
            retain,
            &frame.payload,
            publisher.as_deref(),
        )
        .await;
        forward_cluster(shared, &inner_topic, qos, &frame.payload).await;
        return (ack, deliveries);
    }
    // TODO(parity): a backlog-full, oversized or over-limit drop returns
    // no ack, so a QoS 1 publisher retries and may worsen the overload.
    // The alternative (ack a message that was never queued) lies about
    // acceptance. The rulebook does not decide this case; current choice
    // fails closed.
    let max_secs = shared.delayed.max_secs();
    if delay_secs > max_secs {
        warn!(
            "Dropping delayed publish: {}s exceeds the {}s cap",
            delay_secs, max_secs
        );
    }
    let now_ms = broker_storage::now_ms();
    let entry = DelayedEntry {
        id: shared.delayed.next_id(),
        deliver_at_ms: now_ms.saturating_add(delay_secs.saturating_mul(1_000)),
        topic: inner.to_string(),
        qos: qos as u8,
        retain,
        payload: frame.payload.to_vec(),
        publisher: shared.sessions.client_id_for_conn(frame.header.conn_id),
    };
    match shared.delayed.persist_and_schedule(entry, delay_secs) {
        Ok(()) => {
            let ack = if qos == QoS::AtLeastOnce {
                pub_ack_reply(frame, packet_id, 0)
            } else {
                None
            };
            (ack, Vec::new())
        }
        Err(e) => {
            // The scheduler already bumped the matching drop counter
            // (over-limit, oversized, backlog-full or file error); warn
            // here so the drop is visible in the log like before.
            if delay_secs <= max_secs {
                warn!("Dropping delayed publish: {:?}", e);
            }
            (None, Vec::new())
        }
    }
}

/// QoS 2 inbound first phase (D1-01): store the publish against the
/// publisher session and reply PUBREC. Duplicates (same packet id held)
/// reply PUBREC without storing or routing again. A zero packet id or a
/// missing session yields no reply; a full inbound window yields no
/// reply so the publisher retries. Nothing routes here: routing waits
/// for PUBREL.
async fn apply_qos2_publish(
    frame: &BrokerFrame,
    shared: &Shared,
    topic_str: &str,
    topic: Topic,
    packet_id: u16,
    retain: bool,
) -> (Option<BrokerFrame>, Vec<(u64, BrokerFrame)>) {
    if packet_id == 0 {
        return (None, Vec::new());
    }
    let client_id = match shared.sessions.client_id_for_conn(frame.header.conn_id) {
        Some(client_id) => client_id,
        None => return (None, Vec::new()),
    };
    let session = match shared.sessions.get(&client_id) {
        Some(session) => session,
        None => return (None, Vec::new()),
    };
    if session.has_qos2_inbound(packet_id) {
        return (qos2_reply(OpCode::PubRecOut, frame, packet_id), Vec::new());
    }
    let stored = session.store_qos2_inbound(
        packet_id,
        Qos2InboundEntry {
            topic,
            retain,
            payload: frame.payload.clone(),
        },
    );
    if !stored {
        // Full window (not a duplicate, checked above): no PUBREC so the
        // publisher retries instead of wedging the session.
        return (None, Vec::new());
    }
    let _ = topic_str;
    (qos2_reply(OpCode::PubRecOut, frame, packet_id), Vec::new())
}

/// QoS 2 inbound second phase (D1-01): on PUBREL route the stored message
/// exactly once, reply PUBCOMP and release the packet id. Unknown packet
/// ids reply PUBCOMP with no routing so a retried PUBREL never stalls.
async fn apply_qos2_pubrel(
    frame: &BrokerFrame,
    shared: &Shared,
) -> (Option<BrokerFrame>, Vec<(u64, BrokerFrame)>) {
    let packet_id = match decode_qos2_meta(&frame.metadata) {
        Some(packet_id) => packet_id,
        None => return (None, Vec::new()),
    };
    let client_id = match shared.sessions.client_id_for_conn(frame.header.conn_id) {
        Some(client_id) => client_id,
        None => return (None, Vec::new()),
    };
    let session = match shared.sessions.get(&client_id) {
        Some(session) => session,
        None => return (qos2_reply(OpCode::PubCompOut, frame, packet_id), Vec::new()),
    };
    let stored = match session.take_qos2_inbound(packet_id) {
        Some(stored) => stored,
        None => return (qos2_reply(OpCode::PubCompOut, frame, packet_id), Vec::new()),
    };
    // Delayed targets defer everything except the PUBCOMP: the publisher
    // must not stall past the timer. The entry is recorded on the shared
    // wheel and in `<data-dir>/delayed.jsonl` before the PUBCOMP is
    // returned; the driver delivers it through the normal pipeline.
    if let Some((delay_secs, inner)) = strip_delayed_prefix(stored.topic.as_str()) {
        let comp = qos2_reply(OpCode::PubCompOut, frame, packet_id);
        let Ok(inner_topic) = Topic::new(inner.to_string()) else {
            shared.delayed.note_malformed();
            warn!("Dropping delayed QoS 2 publish with bad inner topic");
            return (comp, Vec::new());
        };
        if delay_secs == 0 {
            // B4-02: the QoS 2 publisher id is the PUBREL sender, so the
            // deferred fan-out hashes the same key as immediate delivery.
            let deliveries = ingress_pipeline_with_publisher(
                shared,
                &inner_topic,
                QoS::ExactlyOnce,
                stored.retain,
                &stored.payload,
                Some(client_id.as_str()),
            )
            .await;
            forward_cluster(shared, &inner_topic, QoS::ExactlyOnce, &stored.payload).await;
            return (comp, deliveries);
        }
        let max_secs = shared.delayed.max_secs();
        if delay_secs > max_secs {
            warn!(
                "Dropping delayed QoS 2 publish: {}s exceeds the {}s cap",
                delay_secs, max_secs
            );
        }
        let entry = DelayedEntry {
            id: shared.delayed.next_id(),
            deliver_at_ms: broker_storage::now_ms()
                .saturating_add(delay_secs.saturating_mul(1_000)),
            topic: inner.to_string(),
            qos: QoS::ExactlyOnce as u8,
            retain: stored.retain,
            payload: stored.payload.to_vec(),
            publisher: Some(client_id.clone()),
        };
        if let Err(e) = shared.delayed.persist_and_schedule(entry, delay_secs) {
            // The scheduler already bumped the matching drop counter;
            // warn here so the drop is visible in the log like before.
            if delay_secs <= max_secs {
                warn!("Dropping delayed QoS 2 publish: {:?}", e);
            }
        }
        return (comp, Vec::new());
    }
    // B4-02: QoS 2 second phase hashes the original publisher id.
    let deliveries = ingress_pipeline_with_publisher(
        shared,
        &stored.topic,
        QoS::ExactlyOnce,
        stored.retain,
        &stored.payload,
        Some(client_id.as_str()),
    )
    .await;
    forward_cluster(shared, &stored.topic, QoS::ExactlyOnce, &stored.payload).await;
    (qos2_reply(OpCode::PubCompOut, frame, packet_id), deliveries)
}

/// QoS 2 outbound second phase (D1-01): on the subscriber's PUBREC send
/// PUBREL and retain only the packet id until PUBCOMP. A duplicate
/// PUBREC for an entry already waiting for PUBCOMP resends PUBREL (the
/// PUBREL was lost). Unknown ids are ignored.
fn apply_qos2_pubrec(frame: &BrokerFrame, shared: &Shared) -> Option<BrokerFrame> {
    let packet_id = decode_qos2_meta(&frame.metadata)?;
    let client_id = shared.sessions.client_id_for_conn(frame.header.conn_id)?;
    let session = shared.sessions.get(&client_id)?;
    if session.complete_qos2_pubrec(packet_id) {
        return qos2_reply(OpCode::PubRelOut, frame, packet_id);
    }
    if session
        .qos2_outbound_snapshot()
        .iter()
        .any(|m| m.packet_id == packet_id)
    {
        return qos2_reply(OpCode::PubRelOut, frame, packet_id);
    }
    None
}

/// QoS 2 outbound completion (D1-01): on the subscriber's PUBCOMP release
/// the packet id. Unknown ids are ignored: PUBCOMPs from a previous
/// incarnation must never disturb live state.
fn apply_qos2_pubcomp(frame: &BrokerFrame, shared: &Shared) {
    let packet_id = match decode_qos2_meta(&frame.metadata) {
        Some(packet_id) => packet_id,
        None => return,
    };
    let client_id = match shared.sessions.client_id_for_conn(frame.header.conn_id) {
        Some(client_id) => client_id,
        None => return,
    };
    if let Some(session) = shared.sessions.get(&client_id) {
        session.ack_qos2_pubcomp(packet_id);
    }
}

/// Build one QoS 2 acknowledgement (`PubRecOut`, `PubRelOut`,
/// `PubCompOut`) mirroring the request identity. Meta is the 2-byte
/// packet id; a zero id yields no reply.
fn qos2_reply(opcode: OpCode, frame: &BrokerFrame, packet_id: u16) -> Option<BrokerFrame> {
    if packet_id == 0 {
        return None;
    }
    BrokerFrame::new(
        opcode,
        frame.header.conn_id,
        frame.header.sequence_no,
        Bytes::from(packet_id.to_be_bytes().to_vec()),
        Bytes::new(),
    )
    .ok()
}

/// Decode QoS 2 acknowledgement metadata into the packet id. Layout is
/// `PacketId:16be` (mirrors the MQTT packet id; the return code that
/// `PubAckIn` carries has no QoS 2 equivalent). The id must be nonzero;
/// trailing bytes are tolerated.
fn decode_qos2_meta(meta: &[u8]) -> Option<u16> {
    if meta.len() < 2 {
        return None;
    }
    let packet_id = u16::from_be_bytes([meta[0], meta[1]]);
    if packet_id == 0 {
        return None;
    }
    Some(packet_id)
}

/// The shared ingress pipeline: retained store/clear, rule execution,
/// and local fan-out. Used by immediate delivery and, after its timer,
/// by delayed delivery alike.
async fn ingress_pipeline(
    shared: &Shared,
    topic: &Topic,
    qos: QoS,
    retain: bool,
    payload: &Bytes,
) -> Vec<(u64, BrokerFrame)> {
    ingress_pipeline_with_publisher(shared, topic, qos, retain, payload, None).await
}

/// [`ingress_pipeline`] with publisher context for shared strategies
/// (B4-02). The MQTT ingress path passes the publishing client id; all
/// other ingress paths (delayed timers without a live session, QoS 2
/// second phase without a stored publisher, CoAP gateway, rule and
/// management publishes) pass `None`.
async fn ingress_pipeline_with_publisher(
    shared: &Shared,
    topic: &Topic,
    qos: QoS,
    retain: bool,
    payload: &Bytes,
    publisher: Option<&str>,
) -> Vec<(u64, BrokerFrame)> {
    // Retained state tracks raw ingress: store (or clear on empty
    // payload) before rules and fan-out observe the message. Enforces
    // the same configurable limits as the management publish path
    // (W1-28): oversized payloads past max_payload_size are delivered
    // but not stored, and new topics past backend.max_retained_messages
    // (when non-zero) are dropped while replacements still land. The
    // hard cap in broker_storage::MAX_RETAINED_MESSAGES always applies
    // inside the store. Retained-only work; non-retained fan-out and
    // fan-in never take the config lock.
    if retain {
        if payload.is_empty() {
            if let Err(e) = shared.retained.clear_retained(topic).await {
                warn!("Retained clear failed for {}: {}", topic.as_str(), e);
            } else {
                sync_retained_stat(shared).await;
            }
        } else {
            let cfg = shared.retainer_config.get();
            let max_bytes =
                broker_api::v5::retainer::parse_bytesize_to_bytes(&cfg.max_payload_size)
                    .unwrap_or(1_048_576);
            let mut drop_new = false;
            if (payload.len() as u64) > max_bytes {
                drop_new = true;
            } else {
                let cap = cfg.backend.max_retained_messages;
                if cap > 0 {
                    let already = shared
                        .retained
                        .get_retained(topic)
                        .await
                        .ok()
                        .flatten()
                        .is_some();
                    if !already && shared.stats.retained() >= cap {
                        drop_new = true;
                    }
                }
            }
            if drop_new {
                // Delivered but not stored, matching the management path.
            } else if let Err(e) = shared
                .retained
                .set_retained(topic.clone(), qos, payload.clone())
                .await
            {
                warn!("Retained store failed for {}: {}", topic.as_str(), e);
            } else {
                sync_retained_stat(shared).await;
            }
        }
    }

    // Rules execute at ingress on this node, before local fan-out.
    // Republished output re-enters through the sink only, so rules can
    // never recurse through their own output.
    let rules_fired = shared
        .engine
        .dispatch_ingress(topic, payload, qos, &shared.sink)
        .await;
    shared.metrics.inc_rules_executed_by(rules_fired as u64);

    // Topic index (W1-15): remember the concrete publish topic so the
    // management list/detail reads observe edge publishes as well as
    // management publishes. Bounded short-lock insert shared with the
    // API layer; delivery proceeds even when the index is full.
    // Management-plane index only, no work on fan-out or fan-in.
    shared.router.record_topic(topic.as_str());

    // Durable stream journal (B1-07): enqueue without blocking so the
    // publish path never waits for disk. Disabled (`None`) costs one
    // branch; enabled costs one bounded `try_send`, with drops counted.
    // The background task fsyncs per record; the window is channel delay
    // plus one fsync.
    maybe_journal_stream(shared, topic, qos, payload);

    let deliveries = build_downlink_frames_with_publisher(
        &shared.router,
        &shared.sessions,
        &shared.metrics,
        topic,
        qos,
        retain,
        payload,
        publisher,
    );
    // CoAP observe fan-out (B1-04): notify bounded observers off the
    // hot path. Empty when the gateway never ran: one read lock that
    // returns after a length check, no spawn, no socket work.
    maybe_notify_coap_observers(shared, topic.as_str(), payload);
    deliveries
}

/// Clustered mode: one forward per matching remote node; each remote
/// fans out locally.
async fn forward_cluster(shared: &Shared, topic: &Topic, qos: QoS, payload: &Bytes) {
    if let Some(cluster) = &shared.cluster {
        match cluster.resolve_route(topic).await {
            Ok(targets) => {
                for target in targets {
                    if let Err(e) = cluster.forward_message(&target, topic, payload, qos).await {
                        warn!("Cluster forward to {} failed: {}", target, e);
                    }
                }
            }
            Err(e) => {
                warn!("Cluster route resolution failed: {}", e);
            }
        }
    }
}

/// CoAP gateway ingress and observe fan-out (B1-04).
///
/// A CoAP POST/PUT to `/ps/<topic>` enters here after URI validation:
/// the payload is stored retained (CoAP has no retain flag; keeping the
/// last value preserves the old gateway's GET semantics on the real
/// retained store) and fanned out through the same [`ingress_pipeline`]
/// an MQTT publish takes, so ordinary MQTT subscribers receive it.
/// Cluster forwarding matches the MQTT path. QoS is `AtMostOnce`:
/// CoAP confirms at its own layer (CHANGED/CONTENT), so the kernel owes
/// no MQTT packet-id tracking for gateway ingress.
///
/// Publish-path cost mirrors the ban check (B1-03): when no observer is
/// registered the notify hook below takes one read lock and returns
/// after a length check. When observers exist the hook snapshots at
/// most 32 entries for this topic and spawns the UDP sends, so fan-out
/// never blocks on the network.
async fn apply_coap_publish(
    shared: &Shared,
    topic_str: &str,
    payload: &Bytes,
) -> Option<Vec<(u64, BrokerFrame)>> {
    let topic = Topic::new(topic_str.to_string()).ok()?;
    shared.metrics.inc_publish_received();
    shared.metrics.inc_qos0_received();
    shared.metrics.inc_messages_received();
    let deliveries = ingress_pipeline(shared, &topic, QoS::AtMostOnce, true, payload).await;
    forward_cluster(shared, &topic, QoS::AtMostOnce, payload).await;
    Some(deliveries)
}

/// Snapshot this topic's observers and send one NON notification each,
/// off the hot path.
///
/// No-op when the gateway never ran (`coap_socket` is `None`) or when
/// nobody observes anything (`has_observers` false): a single length
/// check, no allocation. Otherwise clones at most
/// `MAX_OBSERVERS_PER_TOPIC` small entries and spawns one task that owns
/// its socket clone, payload and observer list; the publish path never
/// awaits the network.
fn maybe_notify_coap_observers(shared: &Shared, topic_str: &str, payload: &Bytes) {
    if !shared.coap.has_observers() {
        return;
    }
    let observers = shared.coap.observers_for(topic_str);
    if observers.is_empty() {
        return;
    }
    let Some(socket) = shared.coap_socket.clone() else {
        return;
    };
    let handler = shared.coap.clone();
    let payload = payload.clone();
    tokio::spawn(async move {
        let seq = handler.next_observe_seq();
        for observer in &observers {
            let notify = handler.build_notify(observer, payload.clone(), seq);
            let bytes = notify.encode();
            let _ = socket.send_to(&bytes, observer.peer).await;
        }
    });
}

/// Serve the CoAP gateway (B1-04) on an already-bound UDP socket.
///
/// Every datagram is validated as `/ps/<topic>` before it touches the
/// router: POST/PUT publishes through [`apply_coap_publish`] (retained
/// store plus router fan-out, then routed into live mailboxes with the
/// same forwarded/sent/delivered accounting as MQTT), GET reads the
/// retained store (CONTENT or NOT FOUND, with an Observe option and
/// registration when the client asked to observe), DELETE clears
/// retained state. Malformed topics answer BAD REQUEST and route
/// nothing, so a listener that accepts bytes can never silently drop
/// them: every accepted publish reaches the router.
async fn run_coap_gateway(shared: Shared, socket: Arc<tokio::net::UdpSocket>) {
    let mut buf = [0u8; 2048];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(next) => next,
            Err(e) => {
                warn!("CoAP gateway recv failed: {e}");
                continue;
            }
        };
        let req = match CoapMessage::decode(&buf[..len]) {
            Ok(req) => req,
            Err(_) => continue,
        };
        match req.code {
            CoapCode::POST | CoapCode::PUT => {
                let Some(topic_str) = CoapGatewayHandler::coap_topic(&req) else {
                    let resp = CoapMessage {
                        message_type: broker_gateway::coap::CoapType::Acknowledgement,
                        code: CoapCode::BAD_REQUEST,
                        message_id: req.message_id,
                        token: req.token.clone(),
                        options: Vec::new(),
                        payload: Bytes::from_static(b"Topic cannot be empty"),
                    };
                    let _ = socket.send_to(&resp.encode(), peer).await;
                    continue;
                };
                if Topic::new(topic_str.clone()).is_err() {
                    let resp = CoapMessage {
                        message_type: broker_gateway::coap::CoapType::Acknowledgement,
                        code: CoapCode::BAD_REQUEST,
                        message_id: req.message_id,
                        token: req.token.clone(),
                        options: Vec::new(),
                        payload: Bytes::from_static(b"Invalid topic"),
                    };
                    let _ = socket.send_to(&resp.encode(), peer).await;
                    continue;
                }
                let payload = req.payload.clone();
                let deliveries = apply_coap_publish(&shared, &topic_str, &payload)
                    .await
                    .unwrap_or_default();
                let mut enqueued = 0u64;
                let mut enqueued_bytes = 0u64;
                for (conn_id, routed) in deliveries {
                    let len = routed.total_frame_len() as u64;
                    if shared.conns.route(conn_id, routed) {
                        enqueued += 1;
                        enqueued_bytes += len;
                    }
                }
                shared.metrics.inc_messages_forwarded_by(enqueued);
                shared.metrics.inc_publish_sent_by(enqueued);
                shared.metrics.inc_delivered_by(enqueued);
                shared.metrics.inc_bytes_sent_by(enqueued_bytes);
                let resp = CoapMessage {
                    message_type: broker_gateway::coap::CoapType::Acknowledgement,
                    code: CoapCode::CHANGED,
                    message_id: req.message_id,
                    token: req.token.clone(),
                    options: Vec::new(),
                    payload: Bytes::new(),
                };
                let _ = socket.send_to(&resp.encode(), peer).await;
            }
            CoapCode::GET => {
                let Some(topic_str) = CoapGatewayHandler::coap_topic(&req) else {
                    let resp = CoapMessage {
                        message_type: broker_gateway::coap::CoapType::Acknowledgement,
                        code: CoapCode::BAD_REQUEST,
                        message_id: req.message_id,
                        token: req.token.clone(),
                        options: Vec::new(),
                        payload: Bytes::from_static(b"Topic cannot be empty"),
                    };
                    let _ = socket.send_to(&resp.encode(), peer).await;
                    continue;
                };
                let Ok(topic) = Topic::new(topic_str.clone()) else {
                    let resp = CoapMessage {
                        message_type: broker_gateway::coap::CoapType::Acknowledgement,
                        code: CoapCode::BAD_REQUEST,
                        message_id: req.message_id,
                        token: req.token.clone(),
                        options: Vec::new(),
                        payload: Bytes::from_static(b"Invalid topic"),
                    };
                    let _ = socket.send_to(&resp.encode(), peer).await;
                    continue;
                };
                let observing = CoapGatewayHandler::is_observe_register(&req);
                if observing {
                    shared
                        .coap
                        .register_observer(&topic_str, peer, req.token.clone());
                }
                let retained = shared.retained.get_retained(&topic).await.ok().flatten();
                match retained {
                    Some(stored) => {
                        let resp = if observing {
                            let seq = shared.coap.next_observe_seq();
                            shared
                                .coap
                                .make_observe_response(&req, stored.payload.clone(), seq)
                        } else {
                            req.make_ack(CoapCode::CONTENT, stored.payload.clone())
                        };
                        let _ = socket.send_to(&resp.encode(), peer).await;
                    }
                    None => {
                        let resp = if observing {
                            let seq = shared.coap.next_observe_seq();
                            shared.coap.make_observe_response(&req, Bytes::new(), seq)
                        } else {
                            req.make_ack(CoapCode::NOT_FOUND, Bytes::from_static(b"Not Found"))
                        };
                        let _ = socket.send_to(&resp.encode(), peer).await;
                    }
                }
            }
            CoapCode::DELETE => {
                let Some(topic_str) = CoapGatewayHandler::coap_topic(&req) else {
                    let resp = CoapMessage {
                        message_type: broker_gateway::coap::CoapType::Acknowledgement,
                        code: CoapCode::BAD_REQUEST,
                        message_id: req.message_id,
                        token: req.token.clone(),
                        options: Vec::new(),
                        payload: Bytes::from_static(b"Topic cannot be empty"),
                    };
                    let _ = socket.send_to(&resp.encode(), peer).await;
                    continue;
                };
                if let Ok(topic) = Topic::new(topic_str) {
                    if shared.retained.clear_retained(&topic).await.is_ok() {
                        sync_retained_stat(&shared).await;
                    }
                }
                let resp = CoapMessage {
                    message_type: broker_gateway::coap::CoapType::Acknowledgement,
                    code: CoapCode::DELETED,
                    message_id: req.message_id,
                    token: req.token.clone(),
                    options: Vec::new(),
                    payload: Bytes::new(),
                };
                let _ = socket.send_to(&resp.encode(), peer).await;
            }
            _ => {
                let resp = req.make_ack(CoapCode::METHOD_NOT_ALLOWED, Bytes::new());
                let _ = socket.send_to(&resp.encode(), peer).await;
            }
        }
    }
}

/// Build one `PublishOut` frame per router match. Shared by the standard
/// fan-out and the rule [`BrokerSink`] so both paths downgrade QoS and
/// allocate downlink packet ids identically.
///
/// Delivery targets the session's live connection: a detached durable
/// session buffers into its offline queue instead, and a detached clean
/// session drops. Sessions unknown to the manager fall back to the
/// router-registered conn_id.
///
/// PERF-10: each silent drop also bumps its kernel counter (detached
/// clean drop, durable-queue eviction) exactly where the frame is
/// discarded. Drops that happened before still happen.
///
/// B4-02: `publisher` carries the publishing client id for the shared
/// `hash_clientid` strategy. The MQTT ingress path passes the real id;
/// rule republishes, retained replays, cluster forwards and management
/// publishes pass `None` (the router hashes the empty string there; see
/// its open-question note on that branch).
fn build_downlink_frames(
    router: &Router,
    sessions: &SessionManager,
    metrics: &Metrics,
    topic: &Topic,
    qos: QoS,
    retain: bool,
    payload: &Bytes,
) -> Vec<(u64, BrokerFrame)> {
    build_downlink_frames_with_publisher(
        router, sessions, metrics, topic, qos, retain, payload, None,
    )
}

/// [`build_downlink_frames`] with publisher context for shared
/// strategies. This is the delivery event that drives
/// `balance_shared_groups` (via `matches_with_publisher`): every publish
/// fan-out reduces the matched shared groups through the router call and
/// consumes the reduced set here.
#[allow(clippy::too_many_arguments)]
fn build_downlink_frames_with_publisher(
    router: &Router,
    sessions: &SessionManager,
    metrics: &Metrics,
    topic: &Topic,
    qos: QoS,
    retain: bool,
    payload: &Bytes,
    publisher: Option<&str>,
) -> Vec<(u64, BrokerFrame)> {
    let qos_raw = u8::from(qos);
    let topic_str = topic.as_str();
    // D1-03: share one payload buffer across all N subscribers.
    // `Bytes::clone` bumps a refcount without copying the bytes, so an
    // 8 KB publish fanned out to N subscribers costs one 8 KB buffer
    // plus N small handles. Per-subscriber memory stays bounded by the
    // existing queue caps (`MAX_OFFLINE_QUEUE`, the QoS 1 window
    // `DEFAULT_MAX_QOS1_INFLIGHT` plus spill `DEFAULT_MAX_QOS1_SPILL`,
    // `MAX_QOS2_INFLIGHT`, the `ConnTable` QoS 0 bound); it is never
    // N copies of the payload. Clone once here so every per-subscriber
    // `clone` below shares this single root.
    let shared = payload.clone();
    let mut deliveries = Vec::new();
    for sub in router.matches_with_publisher(topic, publisher) {
        let effective = std::cmp::min(qos_raw, u8::from(sub.qos));
        match sessions.get(&sub.client_id) {
            Some(session) => {
                let connected = *session.connected.read();
                let live = *session.conn_id.read();
                match (connected, live) {
                    (true, Some(conn_id)) => {
                        let downlink_id = if effective == 0 {
                            0u16
                        } else {
                            session.next_packet_id()
                        };
                        // B4-01: hold every QoS 1 downlink from the moment
                        // it is written until its PUBACK arrives. Inside
                        // the window this is one bounded deque push under
                        // a single lock with no allocation beyond the
                        // message itself, so the publish fast path pays
                        // nothing for the bound. Past the window the entry
                        // spills into the bounded overflow buffer (still
                        // tracked for DUP replay, counted); past window +
                        // spill the frame still goes out live once but is
                        // left untracked (counted), so the live delivery
                        // rate never pays for the window. QoS 0 never
                        // touches session state here. Driven by the
                        // publish-to-delivery event. Before/after
                        // delivery-workload numbers for this path are
                        // printed by
                        // `qos1_inflight_delivery_workload_timings`.
                        if effective == 1 {
                            match session.track_inflight_or_spill(InflightMessage {
                                packet_id: downlink_id,
                                topic: topic.clone(),
                                qos: QoS::try_from(effective).unwrap_or(QoS::AtLeastOnce),
                                retain,
                                payload: shared.clone(),
                            }) {
                                InflightTrackOutcome::Tracked => {}
                                InflightTrackOutcome::Spilled => {
                                    metrics.inc_inflight_spilled();
                                }
                                InflightTrackOutcome::Dropped => {
                                    metrics.inc_inflight_dropped();
                                    metrics.inc_inflight_spill_evicted();
                                }
                            }
                        }
                        // D1-01: hold every QoS 2 downlink until its
                        // PUBCOMP arrives (message until PUBREC, packet id
                        // until PUBCOMP). Same overflow policy as QoS 1:
                        // live delivery still goes out once, untracked.
                        if effective == 2 {
                            let tracked = session.track_qos2_outbound(Qos2OutboundEntry {
                                packet_id: downlink_id,
                                topic: topic.clone(),
                                retain,
                                payload: shared.clone(),
                                rec_received: false,
                            });
                            if !tracked {
                                metrics.inc_inflight_dropped();
                            }
                        }
                        if let Some(frame) = encode_publish_out(
                            conn_id,
                            topic_str,
                            downlink_id,
                            effective,
                            retain,
                            &shared,
                        ) {
                            deliveries.push((conn_id, frame));
                        }
                    }
                    _ => {
                        // Detached (or half-bound) session: durable
                        // sessions buffer for replay, clean ones drop.
                        if !session.clean_start {
                            // Hook only: the eviction itself stays
                            // inside `push_offline`; count what the
                            // push displaced.
                            let before = session.offline_len();
                            session.push_offline(QueuedMessage {
                                topic: topic.clone(),
                                qos: QoS::try_from(effective).unwrap_or(QoS::AtMostOnce),
                                retain,
                                payload: shared.clone(),
                                publish_at_ms: None,
                            });
                            let evicted = (before + 1).saturating_sub(session.offline_len());
                            if evicted > 0 {
                                metrics.inc_offline_queue_evicted_by(evicted as u64);
                            }
                        } else {
                            metrics.inc_detached_clean_dropped();
                        }
                    }
                }
            }
            None => {
                // No session on record: legacy fallback to the
                // router-registered conn_id.
                let downlink_id = if effective == 0 { 0u16 } else { 1u16 };
                if let Some(frame) = encode_publish_out(
                    sub.conn_id,
                    topic_str,
                    downlink_id,
                    effective,
                    retain,
                    &shared,
                ) {
                    deliveries.push((sub.conn_id, frame));
                }
            }
        }
    }
    deliveries
}

/// Token-bucket gate for one publish (INDRA-128). Resolves the owning
/// client, looks up its user's rate quota, and consumes one token.
/// True means route; false means drop. Anonymous, unknown, and
/// unconfigured clients are unlimited.
async fn check_publish_quota(frame: &BrokerFrame, shared: &Shared) -> bool {
    let Some(client_id) = shared.sessions.client_id_for_conn(frame.header.conn_id) else {
        return true;
    };
    let Some(session) = shared.sessions.get(&client_id) else {
        return true;
    };
    let username = session.username.read().clone();
    let Some(username) = username else {
        return true;
    };
    let Some(quotas) = shared.auth.get_quotas(&username) else {
        return true;
    };
    let Some(rate) = quotas.max_publish_rate else {
        return true;
    };
    let burst = quotas.max_publish_burst.unwrap_or(rate);
    shared
        .sessions
        .check_publish_budget(&client_id, rate, burst)
}

/// Build one `PubAckOut` reply mirroring the request identity.
fn pub_ack_reply(frame: &BrokerFrame, packet_id: u16, return_code: u8) -> Option<BrokerFrame> {
    let mut meta = Vec::with_capacity(3);
    meta.extend_from_slice(&packet_id.to_be_bytes());
    meta.push(return_code);
    BrokerFrame::new(
        OpCode::PubAckOut,
        frame.header.conn_id,
        frame.header.sequence_no,
        Bytes::from(meta),
        Bytes::new(),
    )
    .ok()
}

/// Encode one `PublishOut` frame for `conn_id` (sequence stamped later
/// per-destination by `ConnTable::route`).
fn encode_publish_out(
    conn_id: u64,
    topic: &str,
    packet_id: u16,
    qos: u8,
    retain: bool,
    payload: &Bytes,
) -> Option<BrokerFrame> {
    encode_publish_out_with_dup(conn_id, topic, packet_id, qos, retain, false, payload)
}

/// Encode one `PublishOut` frame with explicit DUP (replays set DUP=1,
/// fresh deliveries DUP=0). Sequence is stamped later per-destination by
/// `ConnTable::route`.
fn encode_publish_out_with_dup(
    conn_id: u64,
    topic: &str,
    packet_id: u16,
    qos: u8,
    retain: bool,
    dup: bool,
    payload: &Bytes,
) -> Option<BrokerFrame> {
    let mut meta = Vec::with_capacity(2 + topic.len() + 2 + 3);
    meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    meta.extend_from_slice(topic.as_bytes());
    meta.extend_from_slice(&packet_id.to_be_bytes());
    meta.push(qos);
    meta.push(u8::from(retain));
    meta.push(u8::from(dup));
    BrokerFrame::new(
        OpCode::PublishOut,
        conn_id,
        0, // stamped per-destination by ConnTable::route
        Bytes::from(meta),
        payload.clone(),
    )
    .ok()
}

/// Encode one `PubRelOut` frame for `conn_id` (sequence stamped later
/// per-destination by `ConnTable::route`). Meta is the 2-byte packet id.
fn encode_pubrel_out(conn_id: u64, packet_id: u16) -> Option<BrokerFrame> {
    BrokerFrame::new(
        OpCode::PubRelOut,
        conn_id,
        0, // stamped per-destination by ConnTable::route
        Bytes::from(packet_id.to_be_bytes().to_vec()),
        Bytes::new(),
    )
    .ok()
}

/// Pump messages forwarded from peer nodes until the plane closes.
/// Inbound cluster traffic fans out locally only: only ingress paths
/// forward, so loops cannot form even though messages carry no history.
async fn run_cluster_inbox(shared: Shared) {
    let cluster = match &shared.cluster {
        Some(cluster) => cluster.clone(),
        None => return,
    };
    while let Some(msg) = cluster.recv_message().await {
        deliver_cluster_message(&shared, msg).await;
    }
    debug!("Cluster inbox closed");
}

/// Deliver one peer-forwarded message to local subscribers: pure fan-out
/// with no retained writes, no rule execution (both already happened at
/// the ingress node), and no re-forward.
async fn deliver_cluster_message(shared: &Shared, msg: ClusterMessage) {
    for (conn_id, frame) in build_downlink_frames(
        &shared.router,
        &shared.sessions,
        &shared.metrics,
        &msg.topic,
        msg.qos,
        false,
        &msg.payload,
    ) {
        // A dead mailbox is already counted inside `ConnTable::route`.
        let _ = shared.conns.route(conn_id, frame);
    }
    // CoAP observers see cluster forwards like local ingress (same cheap
    // empty check when the gateway never ran).
    maybe_notify_coap_observers(shared, msg.topic.as_str(), &msg.payload);
}

/// Detach one edge connection: mark its session disconnected (ownership
/// verified against the bound conn_id) and forget its mailbox. A clean
/// session drops its subscriptions (session mirror and router copies, so
/// a later reconnect with the same client id receives nothing until it
/// resubscribes) and its unacked QoS 1 inflight state; durable
/// subscriptions and unacked downlinks survive for reconnect replay. The
/// sweep touches only this session's own filters and runs off the hot path.
fn apply_unbind(frame: &BrokerFrame, shared: &Shared) {
    if let Some(client_id) = decode_unbind_meta(&frame.metadata) {
        let swept = shared
            .sessions
            .unbind_connection(&client_id, frame.header.conn_id);
        for filter in &swept {
            shared.router.unsubscribe(filter, &client_id);
        }
        refresh_subscription_stats(shared);
    }
    shared.conns.unregister(frame.header.conn_id);
}

/// Release one unacknowledged QoS 1 downlink on the subscriber's PUBACK
/// (T-31). The edge reports the downlink packet id via `PubAckIn`;
/// ownership resolves through the `conn_id -> client_id` index, so acks
/// from a superseded connection never release a new incarnation's entry.
fn apply_puback(frame: &BrokerFrame, shared: &Shared) {
    let packet_id = match decode_puback_meta(&frame.metadata) {
        Some(packet_id) => packet_id,
        None => return,
    };
    let client_id = match shared.sessions.client_id_for_conn(frame.header.conn_id) {
        Some(client_id) => client_id,
        None => return,
    };
    if let Some(session) = shared.sessions.get(&client_id) {
        session.ack_inflight(packet_id);
    }
}

/// Decode `PubAckIn` metadata into the downlink packet id. Layout
/// `PacketId:16be | RC:8` (mirrors `indra_brokerlink:encode_puback_meta`);
/// the return code is ignored and trailing bytes tolerated, but the id
/// must be nonzero.
fn decode_puback_meta(meta: &[u8]) -> Option<u16> {
    if meta.len() < 2 {
        return None;
    }
    let packet_id = u16::from_be_bytes([meta[0], meta[1]]);
    if packet_id == 0 {
        return None;
    }
    Some(packet_id)
}

/// Decode an edge flow-control (`Credit`) snapshot into
/// `(used_frames, used_bytes)`. Layout `UsedFrames:32be |
/// UsedBytes:32be` (mirrors `indra_brokerlink:encode_credit_meta/2`);
/// exactly 8 bytes, anything else is malformed.
fn decode_credit_meta(meta: &[u8]) -> Option<(u32, u32)> {
    if meta.len() != 8 {
        return None;
    }
    let used_frames = u32::from_be_bytes([meta[0], meta[1], meta[2], meta[3]]);
    let used_bytes = u32::from_be_bytes([meta[4], meta[5], meta[6], meta[7]]);
    Some((used_frames, used_bytes))
}

/// Decoded `(packet_id, client_id, [(filter, qos)])` subscription metadata.
type SubscribeMeta = (u16, String, Vec<(String, u8)>);

/// Decode `SubscribeMeta` into `(packet_id, client_id, [(filter, qos)])`.
fn decode_subscribe_meta(meta: &[u8]) -> Option<SubscribeMeta> {
    if meta.len() < 6 {
        return None;
    }
    let packet_id = u16::from_be_bytes([meta[0], meta[1]]);
    if packet_id == 0 {
        return None;
    }
    let id_len = u16::from_be_bytes([meta[2], meta[3]]) as usize;
    if meta.len() < 4 + id_len + 2 {
        return None;
    }
    let client_id = std::str::from_utf8(&meta[4..4 + id_len]).ok()?.to_string();
    let mut cursor = 4 + id_len;
    let count = u16::from_be_bytes([meta[cursor], meta[cursor + 1]]) as usize;
    cursor += 2;
    let mut subs = Vec::with_capacity(count);
    for _ in 0..count {
        if meta.len() < cursor + 3 {
            return None;
        }
        let filter_len = u16::from_be_bytes([meta[cursor], meta[cursor + 1]]) as usize;
        if filter_len == 0 || meta.len() < cursor + 2 + filter_len + 1 {
            return None;
        }
        let filter = std::str::from_utf8(&meta[cursor + 2..cursor + 2 + filter_len])
            .ok()?
            .to_string();
        let qos = meta[cursor + 2 + filter_len];
        subs.push((filter, qos));
        cursor += 2 + filter_len + 1;
    }
    if cursor != meta.len() {
        return None;
    }
    Some((packet_id, client_id, subs))
}

/// Decode `PublishMeta` into `(topic, packet_id, qos, retain)`.
fn decode_publish_meta(meta: &[u8]) -> Option<(String, u16, u8, bool)> {
    if meta.len() < 2 + 1 + 2 + 3 {
        return None;
    }
    let topic_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    if topic_len == 0 || meta.len() != 2 + topic_len + 2 + 3 {
        return None;
    }
    let topic = std::str::from_utf8(&meta[2..2 + topic_len])
        .ok()?
        .to_string();
    let base = 2 + topic_len;
    let packet_id = u16::from_be_bytes([meta[base], meta[base + 1]]);
    let qos = meta[base + 2];
    let retain = meta[base + 3] != 0;
    Some((topic, packet_id, qos, retain))
}

/// Decode `UnbindMeta` into the client id.
fn decode_unbind_meta(meta: &[u8]) -> Option<String> {
    if meta.len() < 2 {
        return None;
    }
    let id_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    if meta.len() != 2 + id_len {
        return None;
    }
    std::str::from_utf8(&meta[2..2 + id_len])
        .ok()
        .map(str::to_string)
}

async fn serve_brokerlink(bind: &str, shared: Shared) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(bind).await?;
    info!("BrokerLink IPC listening on {}", bind);

    // Clustered mode pumps peer-forwarded messages alongside edge traffic.
    if shared.cluster.is_some() {
        tokio::spawn(run_cluster_inbox(shared.clone()));
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        debug!("BrokerLink IPC accepted {}", addr);
        // PERF-08: hot-path socket tuning (`TCP_NODELAY` + 64 KiB
        // buffers, matching the Erlang edge from PERF-07). Tuning
        // errors are logged inside and never fail the connection.
        brokerlink::transport::tune_brokerlink_tcp(&stream);
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, shared).await {
                warn!("BrokerLink connection {} ended with error: {}", addr, e);
            }
        });
    }
}

/// Serve the management REST API on an already-bound listener.
async fn serve_api(listener: tokio::net::TcpListener, shared: Shared) -> std::io::Result<()> {
    // Kernel→edge close channel (W0-26): the API kick sends `ConnClose`
    // here after teardown; the forwarder below routes each frame through
    // the connection directory to the owning edge task. The send is
    // non-blocking and a missing edge only warns in the kick path.
    let (edge_tx, mut edge_rx) = unbounded_channel::<BrokerFrame>();
    let mut state = broker_api::ApiState::new(
        shared.engine.clone(),
        shared.sessions.clone(),
        shared.router.clone(),
        shared.metrics.clone(),
        shared.auth.clone(),
        shared.conns.clone(),
        shared.config.clone(),
        shared.node_id.clone(),
        edge_tx,
    );
    // Share the kernel's gauge-plus-high-water-mark store (W1-25) so the
    // node/global stats reads observe the lifecycle points above instead
    // of an empty per-request copy. One `Arc` clone, no new buffering.
    state.stats = shared.stats.clone();
    // Share the kernel's readiness flag (W1-27) so `GET /status` reports
    // the same atomic the kernel marks ready. One `Arc` clone, one load
    // per request, no work on the per-message path.
    state.readiness = shared.readiness.clone();
    // Share the kernel retained store (W1-28) so the single-message read
    // observes the same MQTT ingress state. One `Arc` clone, one short
    // read lock per request, no work on the per-message path.
    state.retained = shared.retained.clone();
    // Share the validated retainer settings (W1-28) so management reads
    // and writes observe the same object the kernel ingress enforces.
    // One Arc clone; the persistence hook stays with the store.
    state.retainer_config = shared.retainer_config.clone();
    // Share the auto-subscribe list (W1-39) so validated management
    // writes are visible to the connect hook without a restart.
    // One Arc clone; reads take a short lock and clone at most 20 rows.
    state.auto_subscribe = shared.auto_subscribe.clone();
    // Share the ban directory (B1-03) so validated management writes
    // are enforced by the connect and publish checks without a restart.
    // One Arc clone; checks take a short read lock, never a write.
    state.bans = shared.bans.clone();
    // Share the licence store and alarms (B2-04) so validated management
    // installs and lifecycle alarms are visible without a restart. One
    // Arc clone each; management-plane only, never on the delivery path.
    state.licence = shared.licence.clone();
    state.alarms = shared.alarms.clone();
    let conns = shared.conns.clone();
    tokio::spawn(async move {
        while let Some(frame) = edge_rx.recv().await {
            conns.route(frame.header.conn_id, frame);
        }
    });
    broker_api::serve(listener, state).await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    broker_observability::init_tracing();
    let args = Args::parse();

    info!(
        "Starting IndraMQTT Kernel v{} on {}",
        env!("CARGO_PKG_VERSION"),
        args.bind
    );
    info!("BrokerLink IPC protocol initialized");
    info!("Clean-room architecture ready");

    let mut shared = Shared::new();
    shared.allow_anonymous = args.allow_anonymous;
    shared.node_id = args.node_id.clone();
    // D1-02: apply the configured per-subscriber QoS 0 backlog bound to
    // the shared delivery table before any edge binds. One atomic store
    // at boot; the hot publish path pays a single relaxed load.
    shared.conns.set_qos0_bound(args.qos0_backlog);
    // B4-01: apply the configured QoS 1 window and spill bounds to the
    // session manager before any edge binds. Two atomic stores at boot;
    // future sessions inherit them at creation, and the publish fast
    // path pays one relaxed load for the window check only.
    shared
        .sessions
        .set_max_qos1_inflight(args.qos1_inflight_window);
    shared.sessions.set_max_qos1_spill(args.qos1_spill);
    // Config registry: create the data dir when missing, then load
    // `state.toml` (missing file yields validated defaults). A corrupt
    // file is a fatal boot error naming the file and the field, never a
    // silent boot with defaults.
    shared.config = Arc::new(load_data_dir_registry(&args.data_dir)?);
    // Delayed publishes (B4-03): apply the configured delay bound, point
    // the wheel at the kernel data dir, reload pending entries, then
    // start the single driver task. Torn or expired rows are discarded
    // with a counter and never served. One atomic store plus one file
    // read at boot; the publish path pays one atomic load, one bounded
    // file append and one short wheel-lock insert afterwards.
    shared.delayed.set_max_secs(args.delayed_max_secs);
    shared.delayed.set_persist_dir(args.data_dir.clone());
    let (delayed_loaded, delayed_torn, delayed_expired) = shared.delayed.load();
    if delayed_loaded > 0 || delayed_torn > 0 || delayed_expired > 0 {
        info!(
            "Delayed backlog reloaded: {} pending, {} torn discarded, {} expired discarded",
            delayed_loaded, delayed_torn, delayed_expired
        );
    }
    shared.spawn_delayed_driver();
    // MQTT users/ACLs: seed the shared `MemoryAuth` in place (the same
    // instance `serve_api` hands to `ApiState`), so the BrokerLink plane
    // enforces persisted credentials from the first accepted connection.
    shared.auth.seed_from_registry(&shared.config);
    // Rules (W0-22): replay the persisted snapshot through the same
    // validated create path as `RuleEngine::create_rule`. An empty
    // snapshot yields today's empty behaviour (no rules); an invalid
    // stored rule fails boot loudly, never skipped silently.
    shared.engine.seed_from_registry(&shared.config)?;
    // Durable stream journal (B1-07): opt-in via `--stream-dir`. Empty
    // leaves `stream_journal` as `None` so the publish hook is one branch
    // and benchmarks see no new disk work. A corrupt stream directory
    // fails boot loudly rather than silently losing history.
    if !args.stream_dir.is_empty() {
        match StreamJournalHandle::open(&args.stream_dir, StreamConfig::default()) {
            Ok(handle) => {
                info!("Stream journal enabled in {}", args.stream_dir);
                shared.stream_journal = Some(handle);
            }
            Err(e) => {
                return Err(format!("cannot open stream journal {}: {e}", args.stream_dir).into());
            }
        }
    }
    // Directory authentication (B2-01): opt-in via `--ldap-url`. Empty
    // leaves `ldap` as `None` so CONNECT pays one `is_some` branch and
    // benchmarks see no new work. When set, CONNECT consults the local
    // store first, then the directory; a directory outage fails closed.
    if !args.ldap_url.is_empty() {
        let ldap_config = LdapConfig {
            server_url: args.ldap_url.clone(),
            base_dn: args.ldap_base_dn.clone(),
            bind_dn: args.ldap_bind_dn.clone(),
            bind_password: args.ldap_bind_password.clone(),
            user_filter: args.ldap_user_filter.clone(),
            group_attribute: args.ldap_group_attribute.clone(),
            required_group: args.ldap_required_group.clone(),
            ca_cert_path: if args.ldap_ca_cert.is_empty() {
                None
            } else {
                Some(args.ldap_ca_cert.clone())
            },
            ..LdapConfig::default()
        };
        info!(
            "LDAP directory authentication enabled for {}",
            args.ldap_url
        );
        shared.ldap = Some(Arc::new(LdapAuthenticator::new(ldap_config)));
    }
    // Kerberos authentication (B2-02): opt-in via `--kerberos-keytab`.
    // Empty leaves `kerberos` as `None` so CONNECT pays one `is_some`
    // branch and benchmarks see no new work. When set, CONNECT consults
    // the local store first, then Kerberos for SPNEGO/AP-REQ tokens; a
    // missing or unreadable keytab disables explicitly with a clear log
    // line inside the authenticator and never accepts tokens.
    if !args.kerberos_keytab.is_empty() {
        let allowed_realms: Vec<String> = args
            .kerberos_allowed_realms
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        // `principal=role` pairs; malformed entries are ignored so one
        // typo cannot disable the whole map (fail closed per-principal:
        // unmapped stays `user`).
        let mut principal_role_map = std::collections::HashMap::new();
        for pair in args.kerberos_role_map.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some((principal, role)) = pair.split_once('=') {
                let principal = principal.trim();
                let role = role.trim();
                if !principal.is_empty() && !role.is_empty() {
                    principal_role_map.insert(principal.to_string(), role.to_string());
                }
            }
        }
        let kerberos_config = KerberosConfig {
            service_principal_name: args.kerberos_service_principal.clone(),
            realm: args.kerberos_realm.clone(),
            allowed_realms,
            keytab_path: args.kerberos_keytab.clone(),
            clock_skew_secs: args.kerberos_clock_skew_secs,
            replay_max_entries: args.kerberos_replay_max,
            principal_role_map,
        };
        info!(
            "Kerberos authentication enabled for {}",
            args.kerberos_service_principal
        );
        shared.kerberos = Some(Arc::new(KerberosAuthenticator::new(kerberos_config)));
    }

    // Licensing lifecycle (B2-04): trusted keys are configuration loaded at
    // startup whether or not clustering is enabled (a single node is a
    // cluster of one). The cluster identity is created on first start and
    // persisted in the data directory with the trial start, so restarts and
    // added nodes never restart the trial. See LICENSING.md for the data
    // directory loss procedure and the two-node join case.
    let trusted_keys = if args.license_keys.trim().is_empty() {
        TrustedKeys::new()
    } else {
        match TrustedKeys::load_from_path(std::path::Path::new(args.license_keys.trim())) {
            Ok(keys) => keys,
            Err(e) => {
                return Err(format!(
                    "cannot load trusted licence keys from {}: {e}",
                    args.license_keys.trim()
                )
                .into());
            }
        }
    };
    trusted_keys.log_at_boot();
    shared.licence.set_trusted_keys(trusted_keys.clone());
    shared
        .licence
        .set_expiry_warn_days(args.licence_expiry_warn_days);
    let now_licence = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let licence_state = match shared
        .licence
        .load_from_data_dir(std::path::Path::new(&args.data_dir), now_licence)
    {
        Ok(state) => state,
        Err(e) => {
            return Err(format!("cannot load licence state from {}: {e}", args.data_dir).into());
        }
    };
    // File commands for sites with no dashboard: generate the request or
    // install a licence, then exit without starting the broker.
    if !args.licence_request_out.trim().is_empty() {
        let request = shared
            .licence
            .generate_request(Some(3), vec!["clustering".to_string()], "")
            .map_err(|e| format!("cannot generate licence request: {e}"))?;
        let text = serde_json::to_string_pretty(&request)
            .map_err(|e| format!("cannot encode licence request: {e}"))?;
        std::fs::write(args.licence_request_out.trim(), text.as_bytes()).map_err(|e| {
            format!(
                "cannot write licence request to {}: {e}",
                args.licence_request_out.trim()
            )
        })?;
        println!(
            "Licence request written to {}\n{}",
            args.licence_request_out.trim(),
            request.summary
        );
        return Ok(());
    }
    if !args.licence_install_file.trim().is_empty() {
        let text = std::fs::read_to_string(args.licence_install_file.trim()).map_err(|e| {
            format!(
                "cannot read licence file {}: {e}",
                args.licence_install_file.trim()
            )
        })?;
        match shared.licence.install(&text, now_licence) {
            Ok(payload) => {
                shared.licence.refresh_alarms(&shared.alarms, now_licence);
                println!(
                    "Licence installed for '{}' (max {} nodes, expires at {})",
                    payload.customer, payload.max_nodes, payload.expires_at
                );
                return Ok(());
            }
            Err(e) => {
                return Err(format!("licence install refused: {e}").into());
            }
        }
    }
    log_licence_lifecycle(&licence_state, args.licence_expiry_warn_days);
    shared.licence.refresh_alarms(&shared.alarms, now_licence);

    if let Some(seeds) = &args.cluster_seeds {
        info!("Cluster mode enabled with seeds: {}", seeds);
        // The licence binds to the stable cluster identity (one licence
        // covers the whole cluster): the stored token wins when present,
        // otherwise the explicit flag or environment provides it. Joiners
        // adopt the cluster identity and receive the licence as part of
        // joining, so adding a node never needs another round trip.
        let cluster_id = shared
            .licence
            .cluster_identity()
            .unwrap_or_else(|| args.node_id.clone());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let license_key = shared
            .licence
            .stored_token()
            .or_else(|| args.license_key.clone())
            .or_else(|| std::env::var("INDRA_LICENSE_KEY").ok());
        let status =
            ClusterLicense::evaluate(license_key.as_deref(), 1, now, &cluster_id, &trusted_keys);
        ClusterLicense::log_status_banner(&status);

        let local_node = broker_cluster::NodeId::new(&args.node_id);
        if let Ok(bind_addr) = args.cluster_bind.parse::<std::net::SocketAddr>() {
            match broker_cluster::UdpSwimTransport::bind(local_node.clone(), bind_addr).await {
                Ok(transport) => {
                    let swim = broker_cluster::SwimMembership::new(
                        local_node.clone(),
                        Some(args.cluster_bind.clone()),
                        broker_cluster::SwimConfig::default(),
                        transport.clone(),
                    );
                    swim.set_license_key(license_key);
                    swim.set_trusted_keys(trusted_keys.clone());
                    swim.set_cluster_identity(
                        cluster_id.clone(),
                        shared.licence.cluster_trial_started_at(),
                    );
                    let route_table =
                        Arc::new(broker_cluster::ClusterRouteTable::new(local_node.clone()));
                    swim.attach_route_table(route_table);
                    swim.clone().run_background();

                    for seed_str in seeds.split(',') {
                        let seed_str = seed_str.trim();
                        if !seed_str.is_empty() {
                            if let Ok(seed_addr) = seed_str.parse::<std::net::SocketAddr>() {
                                let seed_node =
                                    broker_cluster::NodeId::new(format!("seed-{}", seed_addr));
                                transport.register_peer(seed_node.clone(), seed_addr);
                                let _ = swim.join_seed(&seed_node).await;
                            }
                        }
                    }
                    info!(
                        "SWIM gossip cluster engine initialized for node {}",
                        args.node_id
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to bind cluster UDP socket on {}: {}",
                        args.cluster_bind, e
                    );
                }
            }
        }
    }
    if !args.api_bind.is_empty() {
        let listener = tokio::net::TcpListener::bind(&args.api_bind).await?;
        info!("Management API listening on {}", args.api_bind);
        let api_shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_api(listener, api_shared).await {
                warn!("Management API exited: {}", e);
            }
        });
    }
    // CoAP gateway (B1-04): off unless `--coap-bind` names an address.
    // Bound once here so `Shared.coap_socket` is read-only afterwards;
    // the listener task owns a clone and publishes through the router.
    if !args.coap_bind.is_empty() {
        match tokio::net::UdpSocket::bind(&args.coap_bind).await {
            Ok(socket) => {
                let socket = Arc::new(socket);
                shared.coap_socket = Some(socket.clone());
                info!("CoAP gateway listening on {}", args.coap_bind);
                let gateway_shared = shared.clone();
                tokio::spawn(async move {
                    run_coap_gateway(gateway_shared, socket).await;
                });
            }
            Err(e) => {
                warn!("Failed to bind CoAP gateway on {}: {}", args.coap_bind, e);
            }
        }
    }

    serve_brokerlink(&args.brokerlink_bind, shared).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_auth::{AclAction, AclRule};
    use broker_session::MAX_OFFLINE_QUEUE;

    /// Unique scratch data dir under the OS temp dir (no dev-dependency).
    fn unique_data_dir() -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let slot = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "indramqtt-w019-datadir-{}-{nanos}-{slot}",
            std::process::id()
        ))
    }

    #[test]
    fn datadir_boot_creates_and_loads() {
        let dir = unique_data_dir();
        let data_dir = dir.to_str().expect("temp path is UTF-8").to_string();
        assert!(!dir.exists(), "scratch data dir must start missing");

        // Fresh boot: creates the directory, loads validated defaults.
        let registry = load_data_dir_registry(&data_dir).expect("fresh data dir boots");
        assert!(dir.is_dir(), "boot creates the data directory");
        assert_eq!(
            *registry.snapshot(),
            broker_config::FullSnapshot::default(),
            "fresh boot loads empty defaults"
        );

        // First save path creates `state.toml`.
        registry.save().expect("save defaults");
        assert!(
            dir.join(broker_config::STATE_FILE_NAME).is_file(),
            "first save creates state.toml"
        );

        // A pre-existing valid `state.toml` loads its contents into the
        // snapshot exposed through the API state.
        registry
            .commit_admin_users(broker_config::AdminUsersConf {
                users: vec![broker_config::AdminUser {
                    username: "admin".to_string(),
                    password_hash: "hash-admin".to_string(),
                    role: "administrator".to_string(),
                    ..Default::default()
                }],
            })
            .expect("commit admin root");
        registry.save().expect("save admin root");
        let reloaded = load_data_dir_registry(&data_dir).expect("reload data dir");
        let (edge_tx, edge_rx) = unbounded_channel::<BrokerFrame>();
        drop(edge_rx);
        let api = broker_api::ApiState::new(
            Arc::new(RuleEngine::new(16, BackpressurePolicy::DropOldest)),
            Arc::new(SessionManager::new()),
            Arc::new(Router::new()),
            Arc::new(Metrics::new()),
            Arc::new(MemoryAuth::new()),
            Arc::new(ConnTable::default()),
            Arc::new(reloaded),
            "indra-node-1".to_string(),
            edge_tx,
        );
        let snapshot = api.config.snapshot();
        assert_eq!(snapshot.admin_users.users.len(), 1);
        assert_eq!(snapshot.admin_users.users[0].username, "admin");
        assert_eq!(api.node_id, "indra-node-1");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Encode `BindConnection` metadata (test mirror of the BEAM
    /// `indra_brokerlink:encode_bind_meta/3` contract).
    fn encode_bind_meta(client_id: &str, clean_start: bool, keepalive: u16) -> Bytes {
        let id = client_id.as_bytes();
        let mut meta = Vec::with_capacity(2 + id.len() + 1 + 2);
        meta.extend_from_slice(&(id.len() as u16).to_be_bytes());
        meta.extend_from_slice(id);
        meta.push(u8::from(clean_start));
        meta.extend_from_slice(&keepalive.to_be_bytes());
        Bytes::from(meta)
    }

    /// Decode `SessionBinding` metadata into `(session_id, present, rc)`.
    fn decode_session_binding_meta(meta: &[u8]) -> (u64, bool, u8) {
        assert_eq!(meta.len(), 10, "SessionBinding meta must be 10 bytes");
        let session_id = u64::from_be_bytes(meta[0..8].try_into().unwrap());
        (session_id, meta[8] != 0, meta[9])
    }

    fn bind_frame(conn_id: u64, seq: u64, meta: Bytes) -> BrokerFrame {
        BrokerFrame::new(OpCode::BindConnection, conn_id, seq, meta, Bytes::new())
            .expect("valid bind frame")
    }

    /// Encode `BindConnection` metadata with credentials (test mirror of
    /// the BEAM `indra_brokerlink:encode_bind_meta/4` contract).
    fn encode_bind_meta_creds(
        client_id: &str,
        clean_start: bool,
        keepalive: u16,
        username: &str,
        password: &[u8],
    ) -> Bytes {
        let mut meta = encode_bind_meta(client_id, clean_start, keepalive).to_vec();
        meta.extend_from_slice(&(username.len() as u16).to_be_bytes());
        meta.extend_from_slice(username.as_bytes());
        meta.extend_from_slice(&(password.len() as u16).to_be_bytes());
        meta.extend_from_slice(password);
        Bytes::from(meta)
    }

    /// Encode `SubscribeMeta` (test mirror of the BEAM contract).
    fn encode_subscribe_meta(packet_id: u16, client_id: &str, subs: &[(&str, u8)]) -> Bytes {
        let id = client_id.as_bytes();
        let mut meta = Vec::new();
        meta.extend_from_slice(&packet_id.to_be_bytes());
        meta.extend_from_slice(&(id.len() as u16).to_be_bytes());
        meta.extend_from_slice(id);
        meta.extend_from_slice(&(subs.len() as u16).to_be_bytes());
        for (filter, qos) in subs {
            meta.extend_from_slice(&(filter.len() as u16).to_be_bytes());
            meta.extend_from_slice(filter.as_bytes());
            meta.push(*qos);
        }
        Bytes::from(meta)
    }

    /// Encode `PublishMeta` (test mirror of the BEAM contract).
    fn encode_publish_meta(
        topic: &str,
        packet_id: u16,
        qos: u8,
        retain: bool,
        payload: &[u8],
    ) -> (Bytes, Bytes) {
        let mut meta = Vec::new();
        meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        meta.extend_from_slice(topic.as_bytes());
        meta.extend_from_slice(&packet_id.to_be_bytes());
        meta.push(qos);
        meta.push(u8::from(retain));
        meta.push(0u8);
        (Bytes::from(meta), Bytes::from(payload.to_vec()))
    }

    fn decode_publish_meta_parts(meta: &[u8]) -> (String, u16, u8, bool) {
        let topic_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
        let topic = std::str::from_utf8(&meta[2..2 + topic_len])
            .unwrap()
            .to_string();
        let base = 2 + topic_len;
        let packet_id = u16::from_be_bytes([meta[base], meta[base + 1]]);
        (topic, packet_id, meta[base + 2], meta[base + 3] != 0)
    }

    fn decode_publish_dup(meta: &[u8]) -> bool {
        let topic_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
        let base = 2 + topic_len;
        meta[base + 4] != 0
    }

    fn puback_frame(conn_id: u64, seq: u64, packet_id: u16) -> BrokerFrame {
        let mut meta = Vec::with_capacity(3);
        meta.extend_from_slice(&packet_id.to_be_bytes());
        meta.push(0u8);
        BrokerFrame::new(
            OpCode::PubAckIn,
            conn_id,
            seq,
            Bytes::from(meta),
            Bytes::new(),
        )
        .expect("valid puback frame")
    }

    fn subscribe_frame(conn_id: u64, seq: u64, meta: Bytes) -> BrokerFrame {
        BrokerFrame::new(OpCode::SubscribeIn, conn_id, seq, meta, Bytes::new())
            .expect("valid subscribe frame")
    }

    fn publish_frame(conn_id: u64, seq: u64, meta: Bytes, payload: Bytes) -> BrokerFrame {
        BrokerFrame::new(OpCode::PublishIn, conn_id, seq, meta, payload)
            .expect("valid publish frame")
    }

    fn test_shared() -> Shared {
        Shared::new()
    }

    #[test]
    fn downlink_detached_clean_session_counts_drop_only() {
        // PERF-10: one frame for a detached clean session must bump
        // exactly the detached-clean counter and queue nothing.
        let router = Router::new();
        let sessions = SessionManager::new();
        let metrics = Metrics::new();
        let filter = TopicFilter::new("sensors/temp").unwrap();
        router.subscribe(
            &filter,
            Subscription::new("ghost-clean", 77, QoS::AtMostOnce),
        );
        let (session, _) = sessions.get_or_create("ghost-clean", true);
        *session.connected.write() = false;
        *session.conn_id.write() = None;

        let topic = Topic::new("sensors/temp").unwrap();
        let deliveries = build_downlink_frames(
            &router,
            &sessions,
            &metrics,
            &topic,
            QoS::AtMostOnce,
            false,
            &Bytes::from_static(b"21.5"),
        );

        assert!(deliveries.is_empty());
        assert_eq!(session.offline_len(), 0);
        assert_eq!(metrics.detached_clean_dropped(), 1);
        assert_eq!(metrics.unknown_conn_dropped(), 0);
        assert_eq!(metrics.dead_mailbox_dropped(), 0);
        assert_eq!(metrics.offline_queue_evicted(), 0);
    }

    #[test]
    fn downlink_offline_eviction_counts_drop_only() {
        // PERF-10: pushing into a full offline queue keeps the queueing
        // itself unchanged (oldest evicted, length capped) and bumps
        // exactly the eviction counter.
        let router = Router::new();
        let sessions = SessionManager::new();
        let metrics = Metrics::new();
        let filter = TopicFilter::new("jobs/backlog").unwrap();
        router.subscribe(&filter, Subscription::new("durable-1", 78, QoS::AtMostOnce));
        let (session, _) = sessions.get_or_create("durable-1", false);
        *session.connected.write() = false;
        *session.conn_id.write() = None;
        for i in 0..MAX_OFFLINE_QUEUE {
            session.push_offline(QueuedMessage {
                topic: Topic::new("jobs/backlog").unwrap(),
                qos: QoS::AtMostOnce,
                retain: false,
                payload: Bytes::from(format!("seed-{i}")),
                publish_at_ms: None,
            });
        }
        assert_eq!(session.offline_len(), MAX_OFFLINE_QUEUE);

        let topic = Topic::new("jobs/backlog").unwrap();
        let deliveries = build_downlink_frames(
            &router,
            &sessions,
            &metrics,
            &topic,
            QoS::AtMostOnce,
            false,
            &Bytes::from_static(b"new"),
        );

        assert!(deliveries.is_empty());
        assert_eq!(session.offline_len(), MAX_OFFLINE_QUEUE);
        assert_eq!(metrics.offline_queue_evicted(), 1);
        assert_eq!(metrics.unknown_conn_dropped(), 0);
        assert_eq!(metrics.dead_mailbox_dropped(), 0);
        assert_eq!(metrics.detached_clean_dropped(), 0);
    }

    #[test]
    fn ping_maps_to_matching_pong() {
        let sessions = SessionManager::new();
        let ping = BrokerFrame::ping(1234, 56);
        let reply = reply_for_frame(&ping, &sessions).expect("Ping must produce a reply");
        assert_eq!(reply.header.opcode, OpCode::Pong);
        assert_eq!(reply.header.conn_id, 1234);
        assert_eq!(reply.header.sequence_no, 56);
        assert!(reply.metadata.is_empty());
        assert!(reply.payload.is_empty());
    }

    #[test]
    fn ping_pong_preserves_max_ids() {
        let sessions = SessionManager::new();
        let ping = BrokerFrame::ping(u64::MAX, u64::MAX);
        let reply = reply_for_frame(&ping, &sessions).expect("Ping must produce a reply");
        assert_eq!(reply.header.conn_id, u64::MAX);
        assert_eq!(reply.header.sequence_no, u64::MAX);
    }

    #[test]
    fn non_handshake_frames_have_no_reply() {
        let sessions = SessionManager::new();
        for opcode in [
            OpCode::Pong,
            OpCode::SessionBinding,
            OpCode::UnbindConnection,
            OpCode::PublishIn,
            OpCode::PublishOut,
            OpCode::SubscribeIn,
            OpCode::DisconnectIn,
        ] {
            let frame = BrokerFrame::new(
                opcode,
                7,
                9,
                Bytes::from_static(b"meta"),
                Bytes::from_static(b"payload"),
            )
            .expect("valid frame");
            assert!(
                reply_for_frame(&frame, &sessions).is_none(),
                "opcode {:?} must not produce a sync reply",
                opcode
            );
        }
    }

    #[test]
    fn bind_connection_creates_session_without_present_flag() {
        let sessions = SessionManager::new();
        let frame = bind_frame(11, 1, encode_bind_meta("device-001", true, 60));

        let reply = reply_for_frame(&frame, &sessions).expect("Bind must produce a reply");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        assert_eq!(reply.header.conn_id, 11);
        assert_eq!(reply.header.sequence_no, 1);

        let (session_id, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_ne!(session_id, 0, "fresh session must have a nonzero id");
        assert!(
            !present,
            "first clean-start bind must report session_present=false"
        );
        assert_eq!(rc, 0, "accepted bind must carry return code 0");
    }

    #[test]
    fn bind_connection_resumes_session_with_present_flag() {
        let sessions = SessionManager::new();
        let first = bind_frame(11, 1, encode_bind_meta("device-007", true, 60));
        let first_reply = reply_for_frame(&first, &sessions).expect("first bind replies");
        let (first_id, first_present, _) = decode_session_binding_meta(&first_reply.metadata);
        assert!(!first_present);

        let second = bind_frame(12, 1, encode_bind_meta("device-007", false, 60));
        let second_reply = reply_for_frame(&second, &sessions).expect("second bind replies");
        assert_eq!(
            second_reply.header.conn_id, 12,
            "reply mirrors requesting conn"
        );
        let (second_id, second_present, rc) = decode_session_binding_meta(&second_reply.metadata);
        assert!(
            second_present,
            "resumed session must report session_present=true"
        );
        assert_eq!(
            second_id, first_id,
            "resumed bind must reuse the session id"
        );
        assert_eq!(rc, 0);
    }

    #[test]
    fn bind_connection_clean_start_replaces_session() {
        let sessions = SessionManager::new();
        let first = bind_frame(11, 1, encode_bind_meta("device-009", true, 60));
        let (first_id, _, _) =
            decode_session_binding_meta(&reply_for_frame(&first, &sessions).unwrap().metadata);

        let second = bind_frame(11, 2, encode_bind_meta("device-009", true, 60));
        let reply = reply_for_frame(&second, &sessions).expect("rebind replies");
        let (second_id, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_ne!(
            second_id, first_id,
            "clean start must mint a fresh session id"
        );
        assert!(!present);
        assert_eq!(rc, 0);
    }

    #[test]
    fn bind_connection_rejects_garbage_meta_with_rc2() {
        let sessions = SessionManager::new();
        // Truncated meta: claims 5 id bytes but carries none of the tail.
        let bad = bind_frame(11, 3, Bytes::from(vec![0x00, 0x05, b'a', b'b']));
        let reply = reply_for_frame(&bad, &sessions).expect("malformed bind still replies");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        assert_eq!(reply.header.conn_id, 11);
        assert_eq!(reply.header.sequence_no, 3);
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert!(!present);
        assert_eq!(rc, 2, "malformed bind must carry return code 2");
    }

    #[test]
    fn bind_connection_rejects_non_utf8_client_id_with_rc2() {
        let sessions = SessionManager::new();
        // id_len=2, bytes 0xFF 0xFE are not valid UTF-8.
        let bad = bind_frame(
            11,
            4,
            Bytes::from(vec![0x00, 0x02, 0xFF, 0xFE, 0x01, 0x00, 0x3C]),
        );
        let reply = reply_for_frame(&bad, &sessions).expect("non-UTF8 bind still replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 2, "non-UTF8 client id must carry return code 2");
    }

    #[tokio::test]
    async fn ping_pong_round_trip_over_transport() {
        let sessions = SessionManager::new();
        let (client_io, server_io) = tokio::io::duplex(1024);
        let client = FramedTransport::new(client_io);
        let server = FramedTransport::new(server_io);

        let ping = BrokerFrame::ping(4242, 7);
        client.send(ping).await.expect("client send");

        let received = server.recv().await.expect("server recv");
        assert_eq!(received.header.opcode, OpCode::Ping);

        let reply = reply_for_frame(&received, &sessions).expect("server reply");
        server.send(reply).await.expect("server send");

        let pong = client.recv().await.expect("client recv");
        assert_eq!(pong.header.opcode, OpCode::Pong);
        assert_eq!(pong.header.conn_id, 4242);
        assert_eq!(pong.header.sequence_no, 7);
    }

    #[tokio::test]
    async fn server_replies_pong_to_ping_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_connection(stream, Shared::new())
                .await
                .expect("handle");
        });

        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let client = FramedTransport::new(stream);
        client
            .send(BrokerFrame::ping(99, 100))
            .await
            .expect("send ping");
        let pong = client.recv().await.expect("recv pong");
        assert_eq!(pong.header.opcode, OpCode::Pong);
        assert_eq!(pong.header.conn_id, 99);
        assert_eq!(pong.header.sequence_no, 100);

        server_task.abort();
    }

    #[tokio::test]
    async fn server_binds_session_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_connection(stream, Shared::new())
                .await
                .expect("handle");
        });

        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let client = FramedTransport::new(stream);
        client
            .send(bind_frame(55, 9, encode_bind_meta("e2e-device", true, 30)))
            .await
            .expect("send bind");
        let reply = client.recv().await.expect("recv binding");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        assert_eq!(reply.header.conn_id, 55);
        assert_eq!(reply.header.sequence_no, 9);
        let (session_id, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_ne!(session_id, 0);
        assert!(!present);
        assert_eq!(rc, 0);

        server_task.abort();
    }

    #[tokio::test]
    async fn subscribe_registers_and_replies_suback() {
        let shared = test_shared();
        let frame = subscribe_frame(
            21,
            4,
            encode_subscribe_meta(7, "sub-1", &[("sport/tennis", 1), ("news", 0)]),
        );

        let (reply, retained) = apply_subscribe(&frame, &shared).await;
        let reply = reply.expect("subscribe replies");
        assert!(retained.is_empty(), "no retained state stored yet");
        assert_eq!(reply.header.opcode, OpCode::SubAckOut);
        assert_eq!(reply.header.conn_id, 21);
        assert_eq!(reply.header.sequence_no, 4);
        assert_eq!(&reply.metadata[0..2], &7u16.to_be_bytes());
        assert_eq!(&reply.metadata[2..], &[1u8, 0u8]);

        let matches = shared.router.matches(&Topic::new("sport/tennis").unwrap());
        assert_eq!(matches.len(), 1);
        let sub = matches.iter().next().unwrap();
        assert_eq!(sub.client_id.as_ref(), "sub-1");
        assert_eq!(sub.conn_id, 21);
        assert_eq!(sub.qos, QoS::AtLeastOnce);
    }

    #[tokio::test]
    async fn subscribe_invalid_filter_gets_0x80_without_registering() {
        let shared = test_shared();
        let frame = subscribe_frame(
            21,
            4,
            encode_subscribe_meta(9, "sub-bad", &[("sport/#/bogus", 0)]),
        );

        let (reply, retained) = apply_subscribe(&frame, &shared).await;
        let reply = reply.expect("subscribe replies");
        assert!(retained.is_empty());
        assert_eq!(reply.header.opcode, OpCode::SubAckOut);
        assert_eq!(&reply.metadata[0..2], &9u16.to_be_bytes());
        assert_eq!(&reply.metadata[2..], &[0x80u8]);

        let matches = shared.router.matches(&Topic::new("sport/x").unwrap());
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn subscribe_malformed_meta_yields_no_reply() {
        let shared = test_shared();
        let frame = subscribe_frame(21, 4, Bytes::from(vec![0x00, 0x07, 0xAA]));
        let (reply, retained) = apply_subscribe(&frame, &shared).await;
        assert!(reply.is_none());
        assert!(retained.is_empty());
    }

    #[tokio::test]
    async fn publish_qos1_fans_out_with_qos_downshift() {
        let shared = test_shared();
        // Subscriber A wants QoS 1 on an exact filter; B wants QoS 0 via wildcard.
        for (conn, client, filter, qos) in [
            (31u64, "fan-a", "sport/tennis", 1u8),
            (32u64, "fan-b", "sport/#", 0u8),
        ] {
            let frame =
                subscribe_frame(conn, 1, encode_subscribe_meta(1, client, &[(filter, qos)]));
            let (reply, _) = apply_subscribe(&frame, &shared).await;
            reply.expect("subscribe replies");
            // Sessions must exist and be bound for live delivery.
            let (session, _) = shared.sessions.get_or_create(client, true);
            *session.conn_id.write() = Some(conn);
        }

        let (meta, payload) = encode_publish_meta("sport/tennis", 5, 1, false, b"hello");
        let (ack, deliveries) = apply_publish(&publish_frame(40, 2, meta, payload), &shared).await;
        assert!(ack.is_some(), "QoS 1 needs a PubAck");

        assert_eq!(deliveries.len(), 2);
        let mut by_conn: std::collections::HashMap<u64, BrokerFrame> =
            deliveries.into_iter().collect();
        let for_a = by_conn.remove(&31).expect("exact subscriber routed");
        let for_b = by_conn.remove(&32).expect("wildcard subscriber routed");
        for frame in [&for_a, &for_b] {
            assert_eq!(frame.header.opcode, OpCode::PublishOut);
            assert_eq!(frame.payload, Bytes::from_static(b"hello"));
        }
        let (topic_a, pid_a, qos_a, _) = decode_publish_meta_parts(&for_a.metadata);
        assert_eq!(topic_a, "sport/tennis");
        assert_eq!(qos_a, 1, "subscriber QoS preserved under QoS 1 publish");
        assert_ne!(pid_a, 0, "QoS 1 downlink needs a packet id");
        let (_, pid_b, qos_b, _) = decode_publish_meta_parts(&for_b.metadata);
        assert_eq!(qos_b, 0, "delivery downshifted to min(pub, sub)");
        assert_eq!(pid_b, 0, "QoS 0 downlink carries no packet id");
    }

    /// Subscribe one shared-group member through the broker subscribe
    /// path (`apply_subscribe` with a `$share/<group>/tasks` filter) and
    /// bind its session to `conn`, so later publishes deliver live.
    async fn subscribe_shared_member(shared: &Shared, conn: u64, client: &str, group: &str) {
        let filter = format!("$share/{group}/tasks");
        let frame = subscribe_frame(
            conn,
            1,
            encode_subscribe_meta(1, client, &[(filter.as_str(), 0)]),
        );
        let (reply, _) = apply_subscribe(&frame, shared).await;
        reply.expect("shared subscribe replies");
        let (session, _) = shared.sessions.get_or_create(client, true);
        *session.conn_id.write() = Some(conn);
    }

    /// Publish one message through the broker ingress pipeline and
    /// return the receiving connection ids (one per delivery).
    async fn publish_shared_once(
        shared: &Shared,
        topic: &Topic,
        publisher: Option<&str>,
        payload: &[u8],
    ) -> Vec<u64> {
        ingress_pipeline_with_publisher(
            shared,
            topic,
            QoS::AtMostOnce,
            false,
            &Bytes::from(payload.to_vec()),
            publisher,
        )
        .await
        .into_iter()
        .map(|(conn, _)| conn)
        .collect()
    }

    /// B4-02: round-robin through the broker rotates across members.
    #[tokio::test]
    async fn shared_strategy_round_robin_rotates_through_broker() {
        let shared = test_shared();
        for (conn, client) in [(101u64, "rr-a"), (102, "rr-b"), (103, "rr-c")] {
            subscribe_shared_member(&shared, conn, client, "rr").await;
        }
        shared
            .router
            .set_shared_strategy("rr", "round_robin")
            .expect("set");
        let topic = Topic::new("tasks").unwrap();
        let mut owners = Vec::new();
        for i in 0..6u8 {
            let got = publish_shared_once(&shared, &topic, Some("pub"), &[i]).await;
            assert_eq!(got.len(), 1, "exactly one member per publish");
            owners.push(got[0]);
        }
        assert_eq!(owners, vec![101, 102, 103, 101, 102, 103]);
    }

    /// B4-02: `hash_clientid` through the broker pins one member per
    /// publisher id.
    #[tokio::test]
    async fn shared_strategy_hash_clientid_stable_through_broker() {
        let shared = test_shared();
        for (conn, client) in [(111u64, "hc-a"), (112, "hc-b"), (113, "hc-c")] {
            subscribe_shared_member(&shared, conn, client, "hc").await;
        }
        shared
            .router
            .set_shared_strategy("hc", "hash_clientid")
            .expect("set");
        let topic = Topic::new("tasks").unwrap();
        for publisher in ["pub-1", "pub-2", "pub-3"] {
            let first = publish_shared_once(&shared, &topic, Some(publisher), b"x").await;
            assert_eq!(first.len(), 1);
            for _ in 0..5 {
                let again = publish_shared_once(&shared, &topic, Some(publisher), b"x").await;
                assert_eq!(again, first, "one publisher id pins one member");
            }
        }
    }

    /// B4-02: `hash_topic` through the broker pins one member per topic.
    #[tokio::test]
    async fn shared_strategy_hash_topic_stable_through_broker() {
        let shared = test_shared();
        for (conn, client) in [(121u64, "ht-a"), (122, "ht-b"), (123, "ht-c")] {
            subscribe_shared_member(&shared, conn, client, "ht").await;
        }
        shared
            .router
            .set_shared_strategy("ht", "hash_topic")
            .expect("set");
        let topic = Topic::new("tasks").unwrap();
        let first = publish_shared_once(&shared, &topic, Some("pub"), b"x").await;
        assert_eq!(first.len(), 1);
        for _ in 0..5 {
            let again = publish_shared_once(&shared, &topic, Some("other-pub"), b"x").await;
            assert_eq!(
                again, first,
                "one topic pins one member whatever the publisher"
            );
        }
    }

    /// B4-02: sticky through the broker holds one member while the
    /// membership is stable.
    #[tokio::test]
    async fn shared_strategy_sticky_stable_through_broker() {
        let shared = test_shared();
        for (conn, client) in [(131u64, "st-a"), (132, "st-b"), (133, "st-c")] {
            subscribe_shared_member(&shared, conn, client, "st").await;
        }
        shared
            .router
            .set_shared_strategy("st", "sticky")
            .expect("set");
        let topic = Topic::new("tasks").unwrap();
        let first = publish_shared_once(&shared, &topic, Some("pub"), b"x").await;
        assert_eq!(first.len(), 1);
        for i in 0..10u8 {
            let again = publish_shared_once(&shared, &topic, Some("pub"), &[i]).await;
            assert_eq!(again, first, "sticky holds while members stable");
        }
    }

    /// B4-02: random through the broker shows liveness across members.
    #[tokio::test]
    async fn shared_strategy_random_live_through_broker() {
        let shared = test_shared();
        for (conn, client) in [(141u64, "rn-a"), (142, "rn-b"), (143, "rn-c")] {
            subscribe_shared_member(&shared, conn, client, "rn").await;
        }
        shared
            .router
            .set_shared_strategy("rn", "random")
            .expect("set");
        let topic = Topic::new("tasks").unwrap();
        let mut seen = std::collections::HashSet::new();
        for i in 0..60u8 {
            let got = publish_shared_once(&shared, &topic, Some("pub"), &[i]).await;
            assert_eq!(got.len(), 1);
            seen.insert(got[0]);
        }
        assert_eq!(
            seen.len(),
            3,
            "random must reach every member, saw {seen:?}"
        );
    }

    /// B4-02: an unknown strategy name is rejected, never mapped to
    /// round-robin: the set call fails and the group keeps its default.
    #[tokio::test]
    async fn shared_strategy_unknown_rejected_through_broker() {
        let shared = test_shared();
        subscribe_shared_member(&shared, 151, "ux-a", "ux").await;
        subscribe_shared_member(&shared, 152, "ux-b", "ux").await;
        let err = shared
            .router
            .set_shared_strategy("ux", "least-connections")
            .expect_err("unknown strategy must fail");
        assert!(err.to_string().contains("round_robin"));
        assert_eq!(
            shared.router.shared_strategy("ux"),
            broker_router::SharedStrategy::RoundRobin
        );
        // The group still balances (default), it was not left broken.
        let topic = Topic::new("tasks").unwrap();
        let got = publish_shared_once(&shared, &topic, Some("pub"), b"x").await;
        assert_eq!(got.len(), 1);
    }

    /// B4-02: plain subscribers alongside shared members each receive a
    /// copy through the broker.
    #[tokio::test]
    async fn shared_and_plain_coexist_through_broker() {
        let shared = test_shared();
        subscribe_shared_member(&shared, 161, "co-a", "co").await;
        subscribe_shared_member(&shared, 162, "co-b", "co").await;
        let frame = subscribe_frame(
            163,
            1,
            encode_subscribe_meta(1, "co-plain", &[("tasks", 0)]),
        );
        let (reply, _) = apply_subscribe(&frame, &shared).await;
        reply.expect("plain subscribe replies");
        let (session, _) = shared.sessions.get_or_create("co-plain", true);
        *session.conn_id.write() = Some(163);
        let topic = Topic::new("tasks").unwrap();
        for i in 0..4u8 {
            let mut got = publish_shared_once(&shared, &topic, Some("pub"), &[i]).await;
            got.sort_unstable();
            assert_eq!(got.len(), 2, "plain plus exactly one member");
            assert!(got.contains(&163), "plain subscriber always present");
            assert!(
                got.contains(&161) || got.contains(&162),
                "exactly one member joins, saw {got:?}"
            );
        }
    }

    /// D1-03: an 8 KB payload fanned out to N subscribers must share one
    /// buffer instead of copying N times. Fails if any delivery or queued
    /// copy allocates its own 8 KB (e.g. via `to_vec` + `Bytes::from` per
    /// subscriber); passes when every handle is a refcount clone of one
    /// root (`Bytes::ptr_eq`).
    #[tokio::test]
    async fn large_payload_shares_single_buffer_across_subscribers() {
        let shared_state = test_shared();
        for (conn, client) in [(61u64, "large-a"), (62u64, "large-b"), (63u64, "large-c")] {
            let frame = subscribe_frame(
                conn,
                1,
                encode_subscribe_meta(1, client, &[("big/topic", 0)]),
            );
            let (reply, _) = apply_subscribe(&frame, &shared_state).await;
            reply.expect("subscribe replies");
            let (session, _) = shared_state.sessions.get_or_create(client, true);
            *session.conn_id.write() = Some(conn);
        }
        let big = Bytes::from(vec![0xABu8; 8192]);
        let topic = Topic::new("big/topic").unwrap();
        let deliveries = build_downlink_frames(
            &shared_state.router,
            &shared_state.sessions,
            &shared_state.metrics,
            &topic,
            QoS::AtMostOnce,
            false,
            &big,
        );
        assert_eq!(deliveries.len(), 3, "one delivery per subscriber");
        for (_, frame) in &deliveries {
            assert_eq!(frame.payload.len(), 8192);
        }
        // Every delivery payload must point at the same 8 KB buffer.
        for (_, frame) in deliveries.iter().skip(1) {
            assert!(
                deliveries[0].1.payload.as_ptr() == frame.payload.as_ptr(),
                "D1-03: payload copied per subscriber instead of shared"
            );
        }
        // The shared root itself must also be the same buffer: cloning
        // the ingress once and refcounting N times costs 8 KB, not N*8 KB.
        for (_, frame) in &deliveries {
            assert!(
                big.as_ptr() == frame.payload.as_ptr(),
                "D1-03: delivery detached from the ingress buffer"
            );
        }
    }

    /// D1-03 companion: detached durable subscribers queue the same 8 KB
    /// buffer instead of copying it per queue. Two offline queues holding
    /// the same publish must be `ptr_eq`, proving one allocation.
    #[test]
    fn large_payload_offline_queues_share_single_buffer() {
        let router = Router::new();
        let sessions = SessionManager::new();
        let metrics = Metrics::new();
        let filter = TopicFilter::new("big/topic").unwrap();
        for (client, conn) in [("off-a", 71u64), ("off-b", 72u64)] {
            router.subscribe(&filter, Subscription::new(client, conn, QoS::AtMostOnce));
            let (session, _) = sessions.get_or_create(client, false);
            *session.connected.write() = false;
            *session.conn_id.write() = None;
        }
        let big = Bytes::from(vec![0xCDu8; 8192]);
        let topic = Topic::new("big/topic").unwrap();
        let deliveries = build_downlink_frames(
            &router,
            &sessions,
            &metrics,
            &topic,
            QoS::AtMostOnce,
            false,
            &big,
        );
        assert!(deliveries.is_empty(), "detached queues buffer, not deliver");
        let a = sessions.get("off-a").expect("session a");
        let b = sessions.get("off-b").expect("session b");
        assert_eq!(a.offline_len(), 1);
        assert_eq!(b.offline_len(), 1);
        let qa = a.drain_offline();
        let qb = b.drain_offline();
        assert!(big.as_ptr() == qa[0].payload.as_ptr());
        assert!(
            qa[0].payload.as_ptr() == qb[0].payload.as_ptr(),
            "D1-03: offline queues copied the 8 KB payload per subscriber"
        );
    }

    #[tokio::test]
    async fn publish_qos1_acks_publisher_and_routes() {
        let shared = test_shared();
        let (session, _) = shared.sessions.get_or_create("q1-sub", true);
        *session.conn_id.write() = Some(51);
        let sub = subscribe_frame(51, 1, encode_subscribe_meta(3, "q1-sub", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let (meta, payload) = encode_publish_meta("t", 42, 1, false, b"data");
        let (ack, deliveries) = apply_publish(&publish_frame(52, 8, meta, payload), &shared).await;

        let ack = ack.expect("QoS 1 needs PubAck");
        assert_eq!(ack.header.opcode, OpCode::PubAckOut);
        assert_eq!(ack.header.conn_id, 52, "ack mirrors publisher conn");
        assert_eq!(ack.header.sequence_no, 8, "ack mirrors publisher seq");
        assert_eq!(&ack.metadata[..], &[0x00, 0x2A, 0x00]);

        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].0, 51);
        assert_eq!(deliveries[0].1.payload, Bytes::from_static(b"data"));
    }

    /// A QoS 1 publish whose downlink mailbox is unknown must not be
    /// counted as delivered. The publisher still gets its PubAck
    /// (receipt), but the frame never reached any edge mailbox, so
    /// `delivered`/`publish_sent`/`messages_forwarded` must stay zero.
    /// Fails before the fix by counting a delivery to nobody.
    #[tokio::test]
    async fn qos1_publish_to_unknown_mailbox_is_not_counted_delivered() {
        let shared = test_shared();
        // Subscriber session is live and subscribed, but its edge
        // mailbox was never registered (dead/pruned connection): the
        // router still matches, so a delivery frame is built.
        let bind = bind_frame(51, 1, encode_bind_meta("q1-ghost", true, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(51, 2, encode_subscribe_meta(3, "q1-ghost", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        // Drive the real ingress path (ack + outcome counting) over a
        // loopback BrokerLink transport.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client = FramedTransport::new(client_io);
        let server = FramedTransport::new(server_io);
        let (tx, _rx) = unbounded_channel::<BrokerFrame>();
        let mut bound = Vec::new();

        let (meta, payload) = encode_publish_meta("t", 42, 1, false, b"data");
        handle_inbound_frame(
            publish_frame(52, 8, meta, payload),
            &shared,
            &tx,
            &server,
            &mut bound,
            &Arc::new(tokio::sync::Notify::new()),
        )
        .await
        .expect("publish handling succeeds");

        // The publisher is acked (receipt), even though nothing was delivered.
        let ack = client.recv().await.expect("publisher ack");
        assert_eq!(ack.header.opcode, OpCode::PubAckOut);

        // Nothing reached a live mailbox: the loss must be visible, not
        // counted as a delivery.
        assert_eq!(
            shared.metrics.delivered(),
            0,
            "dropped downlink counted as delivered"
        );
        assert_eq!(shared.metrics.publish_sent(), 0);
        assert_eq!(shared.metrics.messages_forwarded(), 0);
        assert_eq!(
            shared.metrics.qos1_received(),
            1,
            "ingress itself was processed"
        );
    }

    /// The same dropped downlink must surface as exactly one drop under
    /// exactly one existing counter (no double counting): an unknown
    /// destination bumps `unknown_conn_dropped` and nothing else.
    #[tokio::test]
    async fn qos1_publish_to_unknown_mailbox_counts_single_drop_only() {
        let shared = test_shared();
        let bind = bind_frame(71, 1, encode_bind_meta("q1-ghost-2", true, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(71, 2, encode_subscribe_meta(3, "q1-ghost-2", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client = FramedTransport::new(client_io);
        let server = FramedTransport::new(server_io);
        let (tx, _rx) = unbounded_channel::<BrokerFrame>();
        let mut bound = Vec::new();

        let (meta, payload) = encode_publish_meta("t", 9, 1, false, b"data");
        handle_inbound_frame(
            publish_frame(72, 8, meta, payload),
            &shared,
            &tx,
            &server,
            &mut bound,
            &Arc::new(tokio::sync::Notify::new()),
        )
        .await
        .expect("publish handling succeeds");
        let ack = client.recv().await.expect("publisher ack");
        assert_eq!(ack.header.opcode, OpCode::PubAckOut);

        assert_eq!(shared.metrics.delivered(), 0);
        assert_eq!(
            shared.metrics.unknown_conn_dropped(),
            1,
            "unknown mailbox must count exactly one unknown-conn drop"
        );
        assert_eq!(shared.metrics.dead_mailbox_dropped(), 0);
        assert_eq!(shared.metrics.detached_clean_dropped(), 0);
        assert_eq!(shared.metrics.offline_queue_evicted(), 0);
    }

    /// A dropped downlink into a dead (receiver-gone) mailbox must bump
    /// exactly `dead_mailbox_dropped` and nothing else.
    #[tokio::test]
    async fn qos1_publish_to_dead_mailbox_counts_single_drop_only() {
        let shared = test_shared();
        let bind = bind_frame(81, 1, encode_bind_meta("q1-ghost-3", true, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(81, 2, encode_subscribe_meta(3, "q1-ghost-3", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");
        // Register then drop the receiver: the mailbox is dead at route
        // time, so `route` prunes it and counts a dead-mailbox drop.
        let (tx_dead, rx_dead) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(81, tx_dead);
        drop(rx_dead);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client = FramedTransport::new(client_io);
        let server = FramedTransport::new(server_io);
        let (tx, _rx) = unbounded_channel::<BrokerFrame>();
        let mut bound = Vec::new();

        let (meta, payload) = encode_publish_meta("t", 11, 1, false, b"data");
        handle_inbound_frame(
            publish_frame(82, 8, meta, payload),
            &shared,
            &tx,
            &server,
            &mut bound,
            &Arc::new(tokio::sync::Notify::new()),
        )
        .await
        .expect("publish handling succeeds");
        let ack = client.recv().await.expect("publisher ack");
        assert_eq!(ack.header.opcode, OpCode::PubAckOut);

        assert_eq!(shared.metrics.delivered(), 0);
        assert_eq!(shared.metrics.dead_mailbox_dropped(), 1);
        assert_eq!(shared.metrics.unknown_conn_dropped(), 0);
        assert_eq!(shared.metrics.detached_clean_dropped(), 0);
        assert_eq!(shared.metrics.offline_queue_evicted(), 0);
    }

    /// Egress stage 0: a well-formed edge flow-control snapshot is
    /// counted and changes nothing else (no gating yet).
    #[tokio::test]
    async fn credit_frame_is_counted_and_changes_nothing_else() {
        let shared = test_shared();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let _client = FramedTransport::new(client_io);
        let server = FramedTransport::new(server_io);
        let (tx, _rx) = unbounded_channel::<BrokerFrame>();
        let mut bound = Vec::new();

        let mut meta = Vec::new();
        meta.extend_from_slice(&7u32.to_be_bytes());
        meta.extend_from_slice(&1024u32.to_be_bytes());
        let credit = BrokerFrame::new(OpCode::Credit, 91, 3, Bytes::from(meta), Bytes::new())
            .expect("valid credit frame");
        handle_inbound_frame(
            credit,
            &shared,
            &tx,
            &server,
            &mut bound,
            &Arc::new(tokio::sync::Notify::new()),
        )
        .await
        .expect("credit handling succeeds");
        assert_eq!(shared.metrics.credit_received(), 1);
        // Nothing gated, nothing delivered, no connection state touched.
        assert_eq!(shared.metrics.messages_forwarded(), 0);
        assert_eq!(shared.metrics.transport_sent(), 0);
        assert!(bound.is_empty());

        // Malformed snapshot: ignored, uncounted.
        let bad = BrokerFrame::new(
            OpCode::Credit,
            91,
            4,
            Bytes::from_static(b"short"),
            Bytes::new(),
        )
        .expect("valid credit frame");
        handle_inbound_frame(
            bad,
            &shared,
            &tx,
            &server,
            &mut bound,
            &Arc::new(tokio::sync::Notify::new()),
        )
        .await
        .expect("malformed credit is ignored");
        assert_eq!(shared.metrics.credit_received(), 1);
    }

    #[test]
    fn credit_meta_decode_accepts_only_eight_bytes() {
        let mut meta = Vec::new();
        meta.extend_from_slice(&7u32.to_be_bytes());
        meta.extend_from_slice(&1024u32.to_be_bytes());
        assert_eq!(decode_credit_meta(&meta), Some((7, 1024)));
        assert_eq!(decode_credit_meta(b"short"), None);
        assert_eq!(decode_credit_meta(&[0u8; 9]), None);
        assert_eq!(decode_credit_meta(&[]), None);
    }

    #[test]
    fn egress_stage_counters_start_at_zero() {
        let metrics = Metrics::new();
        assert_eq!(metrics.transport_sent(), 0);
        assert_eq!(metrics.transport_send_failed(), 0);
        assert_eq!(metrics.egress_qos0_shed(), 0);
        assert_eq!(metrics.puback_deferred(), 0);
        assert_eq!(metrics.puback_deferred_released(), 0);
        assert_eq!(metrics.credit_clamped(), 0);
        assert_eq!(metrics.credit_exhausted(), 0);
        assert_eq!(metrics.credit_received(), 0);
        let snap = metrics.snapshot();
        assert_eq!(snap.transport_sent, 0);
        assert_eq!(snap.credit_received, 0);
        let text = metrics.render_prometheus_metrics();
        assert!(text.contains("indramqtt_transport_sent_total 0\n"));
        assert!(text.contains("indramqtt_credit_received_total 0\n"));
    }

    /// T-31: a durable subscriber that disconnects with a QoS 1
    /// downlink inflight (sent, never acked) must see that message
    /// redelivered on reconnect with DUP set.
    #[tokio::test]
    async fn qos1_unacked_downlink_is_redelivered_after_reconnect() {
        let shared = test_shared();
        let bind = bind_frame(61, 1, encode_bind_meta("q1-durable", false, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(61, 2, encode_subscribe_meta(5, "q1-durable", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        // Live mailbox: the downlink is routed (inflight, unacked).
        let (tx61, mut rx61) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(61, tx61);
        let (meta, payload) = encode_publish_meta("t", 7, 1, false, b"redeliver-me");
        let (_, deliveries) = apply_publish(&publish_frame(62, 3, meta, payload), &shared).await;
        assert_eq!(
            deliveries.len(),
            1,
            "downlink must be built for the live subscriber"
        );
        for (conn_id, frame) in deliveries {
            let _ = shared.conns.route(conn_id, frame);
        }
        let inflight = rx61.try_recv().expect("downlink reached the edge mailbox");
        assert_eq!(inflight.payload, Bytes::from_static(b"redeliver-me"));
        assert!(
            !decode_publish_dup(&inflight.metadata),
            "fresh downlink carries DUP=0"
        );
        let (_, first_pid, _, _) = decode_publish_meta_parts(&inflight.metadata);

        // Subscriber disconnects without acking (durable session keeps
        // subscriptions, offline queue and inflight), then reconnects
        // non-clean with a live mailbox.
        let mut unbind_meta = vec![0x00u8, 0x0Au8];
        unbind_meta.extend_from_slice(b"q1-durable");
        let unbind = BrokerFrame::new(
            OpCode::UnbindConnection,
            61,
            4,
            Bytes::from(unbind_meta),
            Bytes::new(),
        )
        .expect("valid unbind frame");
        apply_unbind(&unbind, &shared);
        let rebind = bind_frame(63, 1, encode_bind_meta("q1-durable", false, 60));
        reply_for_frame(&rebind, &shared.sessions).expect("rebind replies");
        let (tx63, mut rx63) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(63, tx63);

        // The unacked message must come back with DUP set.
        let replayed = replay_offline(&rebind, &shared).await;
        assert!(
            replayed >= 1,
            "T-26: unacked QoS 1 downlink was not redelivered after reconnect"
        );
        assert_eq!(replayed, 1, "exactly the one unacked downlink replays");
        let redelivered = rx63.try_recv().expect("redelivery reached the new mailbox");
        assert_eq!(redelivered.payload, Bytes::from_static(b"redeliver-me"));
        assert!(
            decode_publish_dup(&redelivered.metadata),
            "redelivery must carry DUP=1"
        );
        let (_, replay_pid, _, _) = decode_publish_meta_parts(&redelivered.metadata);
        assert_eq!(
            replay_pid, first_pid,
            "redelivery reuses the downlink packet id"
        );
    }

    #[tokio::test]
    async fn qos1_puback_releases_inflight_nothing_replayed() {
        let shared = test_shared();
        let bind = bind_frame(61, 1, encode_bind_meta("q1-acked", false, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(61, 2, encode_subscribe_meta(5, "q1-acked", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let (tx61, mut rx61) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(61, tx61);
        let (meta, payload) = encode_publish_meta("t", 7, 1, false, b"acked-me");
        let (_, deliveries) = apply_publish(&publish_frame(62, 3, meta, payload), &shared).await;
        assert_eq!(deliveries.len(), 1);
        for (conn_id, frame) in deliveries {
            let _ = shared.conns.route(conn_id, frame);
        }
        let downlink = rx61.try_recv().expect("downlink arrived");
        let (_, pid, _, _) = decode_publish_meta_parts(&downlink.metadata);
        assert_ne!(pid, 0);

        // Subscriber acks before disconnecting: the entry is released.
        apply_puback(&puback_frame(61, 9, pid), &shared);
        let session = shared.sessions.get("q1-acked").expect("session known");
        assert_eq!(session.inflight_len(), 0, "PUBACK must release the entry");

        // Reconnect replays nothing.
        let mut unbind_meta = vec![0x00u8, 0x08u8];
        unbind_meta.extend_from_slice(b"q1-acked");
        let unbind = BrokerFrame::new(
            OpCode::UnbindConnection,
            61,
            4,
            Bytes::from(unbind_meta),
            Bytes::new(),
        )
        .expect("valid unbind frame");
        apply_unbind(&unbind, &shared);
        let rebind = bind_frame(63, 1, encode_bind_meta("q1-acked", false, 60));
        reply_for_frame(&rebind, &shared.sessions).expect("rebind replies");
        let (tx63, mut rx63) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(63, tx63);
        assert_eq!(replay_offline(&rebind, &shared).await, 0);
        assert!(rx63.try_recv().is_err(), "acked message must not replay");
    }

    #[tokio::test]
    async fn qos1_redelivery_preserves_order_with_dup() {
        let shared = test_shared();
        let bind = bind_frame(61, 1, encode_bind_meta("q1-order", false, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(61, 2, encode_subscribe_meta(5, "q1-order", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let (tx61, mut rx61) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(61, tx61);
        let mut sent_pids = Vec::new();
        for (i, body) in [
            b"m-one".as_slice(),
            b"m-two".as_slice(),
            b"m-three".as_slice(),
        ]
        .iter()
        .enumerate()
        {
            let (meta, payload) = encode_publish_meta("t", i as u16, 1, false, body);
            let (_, deliveries) =
                apply_publish(&publish_frame(62, 3 + i as u64, meta, payload), &shared).await;
            assert_eq!(deliveries.len(), 1);
            for (conn_id, frame) in deliveries {
                let _ = shared.conns.route(conn_id, frame);
            }
            let got = rx61.try_recv().expect("downlink arrived");
            let (_, pid, _, _) = decode_publish_meta_parts(&got.metadata);
            sent_pids.push((pid, got.payload.clone()));
        }

        let mut unbind_meta = vec![0x00u8, 0x08u8];
        unbind_meta.extend_from_slice(b"q1-order");
        let unbind = BrokerFrame::new(
            OpCode::UnbindConnection,
            61,
            4,
            Bytes::from(unbind_meta),
            Bytes::new(),
        )
        .expect("valid unbind frame");
        apply_unbind(&unbind, &shared);
        let rebind = bind_frame(63, 1, encode_bind_meta("q1-order", false, 60));
        reply_for_frame(&rebind, &shared.sessions).expect("rebind replies");
        let (tx63, mut rx63) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(63, tx63);

        assert_eq!(replay_offline(&rebind, &shared).await, 3);
        for (pid, payload) in sent_pids {
            let got = rx63.try_recv().expect("ordered redelivery");
            assert_eq!(got.payload, payload, "original order preserved");
            assert!(
                decode_publish_dup(&got.metadata),
                "every replay carries DUP=1"
            );
            let (_, replay_pid, _, _) = decode_publish_meta_parts(&got.metadata);
            assert_eq!(replay_pid, pid, "same packet id reused in order");
        }
        assert!(rx63.try_recv().is_err(), "no new traffic interleaved");
    }

    #[tokio::test]
    async fn qos1_clean_session_resumes_with_empty_inflight() {
        let shared = test_shared();
        let bind = bind_frame(61, 1, encode_bind_meta("q1-clean", true, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(61, 2, encode_subscribe_meta(5, "q1-clean", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let (tx61, mut rx61) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(61, tx61);
        let (meta, payload) = encode_publish_meta("t", 7, 1, false, b"volatile");
        let (_, deliveries) = apply_publish(&publish_frame(62, 3, meta, payload), &shared).await;
        assert_eq!(deliveries.len(), 1);
        for (conn_id, frame) in deliveries {
            let _ = shared.conns.route(conn_id, frame);
        }
        rx61.try_recv().expect("downlink arrived");
        assert_eq!(
            shared
                .sessions
                .get("q1-clean")
                .expect("session known")
                .inflight_len(),
            1
        );

        // Clean disconnect drops inflight state.
        let mut unbind_meta = vec![0x00u8, 0x08u8];
        unbind_meta.extend_from_slice(b"q1-clean");
        let unbind = BrokerFrame::new(
            OpCode::UnbindConnection,
            61,
            4,
            Bytes::from(unbind_meta),
            Bytes::new(),
        )
        .expect("valid unbind frame");
        apply_unbind(&unbind, &shared);
        assert_eq!(
            shared
                .sessions
                .get("q1-clean")
                .expect("session survives unbind")
                .inflight_len(),
            0,
            "clean disconnect keeps no inflight state"
        );

        let rebind = bind_frame(63, 1, encode_bind_meta("q1-clean", true, 60));
        reply_for_frame(&rebind, &shared.sessions).expect("rebind replies");
        let (tx63, mut rx63) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(63, tx63);
        assert_eq!(replay_offline(&rebind, &shared).await, 0);
        assert!(rx63.try_recv().is_err(), "clean resume replays nothing");
    }

    #[tokio::test]
    async fn qos1_inflight_bound_spills_past_window_and_counts() {
        use broker_session::DEFAULT_MAX_QOS1_INFLIGHT;
        let shared = test_shared();
        let bind = bind_frame(61, 1, encode_bind_meta("q1-bound", false, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(61, 2, encode_subscribe_meta(5, "q1-bound", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let (tx61, mut rx61) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(61, tx61);
        for i in 0..DEFAULT_MAX_QOS1_INFLIGHT {
            let (meta, payload) = encode_publish_meta("t", i as u16, 1, false, b"x");
            let (_, deliveries) =
                apply_publish(&publish_frame(62, 3 + i as u64, meta, payload), &shared).await;
            assert_eq!(deliveries.len(), 1, "live delivery unaffected by fill");
            for (conn_id, frame) in deliveries {
                let _ = shared.conns.route(conn_id, frame);
            }
            rx61.try_recv().expect("live downlink arrived");
        }
        let session = shared.sessions.get("q1-bound").expect("session known");
        assert_eq!(session.inflight_len(), DEFAULT_MAX_QOS1_INFLIGHT);
        assert_eq!(shared.metrics.inflight_dropped(), 0);
        assert_eq!(shared.metrics.inflight_spilled(), 0);

        // One past the window: still delivered live once AND still
        // tracked, now in the spill buffer (B4-01, no silent loss).
        let (meta, payload) = encode_publish_meta("t", 0x0FFF, 1, false, b"over");
        let (_, deliveries) = apply_publish(&publish_frame(62, 999, meta, payload), &shared).await;
        assert_eq!(deliveries.len(), 1, "bound never blocks live delivery");
        for (conn_id, frame) in deliveries {
            let _ = shared.conns.route(conn_id, frame);
        }
        rx61.try_recv()
            .expect("over-window downlink still delivered live");
        assert_eq!(
            session.inflight_len(),
            DEFAULT_MAX_QOS1_INFLIGHT,
            "window stays bounded at the limit"
        );
        assert_eq!(
            session.inflight_spill_len(),
            1,
            "overflow is tracked in spill"
        );
        assert_eq!(session.inflight_total_len(), DEFAULT_MAX_QOS1_INFLIGHT + 1);
        assert_eq!(shared.metrics.inflight_spilled(), 1, "spill counted");
        assert_eq!(
            shared.metrics.inflight_dropped(),
            0,
            "nothing untracked while spill has room"
        );
    }

    #[tokio::test]
    async fn qos1_inflight_spill_redelivers_everything_with_dup() {
        use broker_session::{DEFAULT_MAX_QOS1_INFLIGHT, DEFAULT_MAX_QOS1_SPILL};
        let shared = test_shared();
        let bind = bind_frame(61, 1, encode_bind_meta("q1-spill-all", false, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(61, 2, encode_subscribe_meta(5, "q1-spill-all", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        // Stall the acknowledger: publish window + spill + 3 without ever
        // acking, through the broker publish-to-delivery event.
        let (tx61, mut rx61) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(61, tx61);
        let total = DEFAULT_MAX_QOS1_INFLIGHT + 5;
        assert!(
            total < DEFAULT_MAX_QOS1_INFLIGHT + DEFAULT_MAX_QOS1_SPILL,
            "test stays inside the spill bound"
        );
        let mut live_pids = Vec::new();
        let mut live_payloads = Vec::new();
        for i in 0..total {
            let body = format!("spill-{i:04}");
            let (meta, payload) = encode_publish_meta("t", i as u16, 1, false, body.as_bytes());
            let (_, deliveries) =
                apply_publish(&publish_frame(62, 100 + i as u64, meta, payload), &shared).await;
            assert_eq!(deliveries.len(), 1, "live delivery never blocks");
            for (conn_id, frame) in deliveries {
                let _ = shared.conns.route(conn_id, frame);
            }
            let got = rx61.try_recv().expect("live downlink arrived");
            let (_, pid, _, _) = decode_publish_meta_parts(&got.metadata);
            assert_ne!(pid, 0);
            live_pids.push(pid);
            live_payloads.push(got.payload.clone());
        }
        let session = shared.sessions.get("q1-spill-all").expect("session known");
        assert_eq!(session.inflight_len(), DEFAULT_MAX_QOS1_INFLIGHT);
        assert_eq!(session.inflight_spill_len(), 5);
        assert_eq!(shared.metrics.inflight_spilled(), 5);
        assert_eq!(shared.metrics.inflight_dropped(), 0);

        // Disconnect without acking anything, then reconnect: every QoS 1
        // message replays, window oldest-first then spill oldest-first,
        // every replay with DUP set and its original packet id.
        let mut unbind_meta = vec![0x00u8, 0x0Bu8];
        unbind_meta.extend_from_slice(b"q1-spill-all");
        let unbind = BrokerFrame::new(
            OpCode::UnbindConnection,
            61,
            4,
            Bytes::from(unbind_meta),
            Bytes::new(),
        )
        .expect("valid unbind frame");
        apply_unbind(&unbind, &shared);
        let rebind = bind_frame(63, 1, encode_bind_meta("q1-spill-all", false, 60));
        reply_for_frame(&rebind, &shared.sessions).expect("rebind replies");
        let (tx63, mut rx63) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(63, tx63);
        assert_eq!(replay_offline(&rebind, &shared).await, total);
        assert_eq!(shared.metrics.inflight_spill_replayed(), 5);
        for (pid, payload) in live_pids.iter().zip(live_payloads.iter()) {
            let got = rx63.try_recv().expect("ordered redelivery past the window");
            assert_eq!(&got.payload, payload, "original order preserved");
            assert!(
                decode_publish_dup(&got.metadata),
                "every replay past the window carries DUP=1"
            );
            let (_, replay_pid, _, _) = decode_publish_meta_parts(&got.metadata);
            assert_eq!(&replay_pid, pid, "same packet id reused in order");
        }
        assert!(rx63.try_recv().is_err(), "no new traffic interleaved");
    }

    #[tokio::test]
    async fn qos1_inflight_bound_configurable_and_overflow_counted() {
        let shared = test_shared();
        shared.sessions.set_max_qos1_inflight(3);
        shared.sessions.set_max_qos1_spill(2);
        assert_eq!(shared.sessions.max_qos1_inflight(), 3);
        assert_eq!(shared.sessions.max_qos1_spill(), 2);

        let bind = bind_frame(61, 1, encode_bind_meta("q1-tiny", false, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let session = shared.sessions.get("q1-tiny").expect("session known");
        assert_eq!(
            session.max_inflight(),
            3,
            "manager bound reaches the session"
        );
        assert_eq!(session.max_spill(), 2);
        let sub = subscribe_frame(61, 2, encode_subscribe_meta(5, "q1-tiny", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let (tx61, mut rx61) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(61, tx61);
        for i in 0..6u16 {
            let (meta, payload) = encode_publish_meta("t", i, 1, false, b"x");
            let (_, deliveries) = apply_publish(
                &publish_frame(62, 200 + u64::from(i), meta, payload),
                &shared,
            )
            .await;
            assert_eq!(deliveries.len(), 1);
            for (conn_id, frame) in deliveries {
                let _ = shared.conns.route(conn_id, frame);
            }
            rx61.try_recv().expect("live downlink arrived");
        }
        // Window 3 tracked, next 2 spilled, last one past both: live once,
        // untracked, both drop counters bump.
        assert_eq!(session.inflight_len(), 3);
        assert_eq!(session.inflight_spill_len(), 2);
        assert_eq!(session.inflight_total_len(), 5);
        assert_eq!(shared.metrics.inflight_spilled(), 2);
        assert_eq!(shared.metrics.inflight_dropped(), 1);
        assert_eq!(shared.metrics.inflight_spill_evicted(), 1);
    }

    #[tokio::test]
    async fn qos1_inflight_delivery_workload_timings() {
        use broker_session::DEFAULT_MAX_QOS1_INFLIGHT;
        use std::hint::black_box;
        use std::time::Instant;

        // B4-01 delivery-workload before/after numbers (spec Done-when
        // bullet 5, RULEBOOK hot-path row): measured through the broker
        // publish-to-delivery event (`apply_publish`), not just the
        // session store. BEFORE is the steady-state loop with the spill
        // empty: `build_downlink_frames` takes only the window lock here,
        // exactly the pre-B4-01 work plus one relaxed atomic load, so its
        // rate is the pre-change baseline. AFTER is the overflow loop past
        // the window, which additionally takes the spill lock and bumps
        // `inflight_spilled`. Both print msgs/sec and avg ns/msg into the
        // gate output with no threshold assert; counts are CI sample
        // sizes, not SLOs. Per-message bound: window (default 100) + spill
        // (default 1000) entries, each one shared `Bytes` handle plus topic
        // bytes, never N payload copies.
        let shared = test_shared();
        let bind = bind_frame(61, 1, encode_bind_meta("q1-timing", false, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(61, 2, encode_subscribe_meta(5, "q1-timing", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");
        let (tx61, mut rx61) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(61, tx61);
        let session = shared.sessions.get("q1-timing").expect("session known");

        // BEFORE: steady-state publish-to-delivery, spill empty. Every
        // publish is acked at once so the window never fills and the spill
        // lock is never taken (guarded by `has_spill`).
        let steady_iters = 200usize;
        let steady_start = Instant::now();
        for i in 0..steady_iters {
            let (meta, payload) = encode_publish_meta("t", i as u16, 1, false, b"x");
            let (_, deliveries) =
                apply_publish(&publish_frame(62, 1000 + i as u64, meta, payload), &shared).await;
            assert_eq!(deliveries.len(), 1, "live delivery never blocks");
            for (conn_id, frame) in deliveries {
                let _ = shared.conns.route(conn_id, frame);
            }
            let got = rx61.try_recv().expect("live downlink arrived");
            let (_, pid, _, _) = decode_publish_meta_parts(&got.metadata);
            black_box(pid);
            assert!(session.ack_inflight(pid), "steady-state ack releases");
        }
        let steady_elapsed = steady_start.elapsed();
        assert!(
            !session.has_spill(),
            "steady-state loop must never touch the spill"
        );
        let steady_rate = steady_iters as f64 / steady_elapsed.as_secs_f64();
        let steady_avg_ns = steady_elapsed.as_nanos() as f64 / steady_iters as f64;
        println!(
            "qos1 broker delivery workload steady-state (spill empty, before): {steady_rate:.0} msgs/sec, avg {steady_avg_ns:.1} ns/msg ({steady_iters} apply_publish+ack rounds in {steady_elapsed:?})"
        );

        // AFTER: fill the window without acking, then time overflow past it.
        for i in 0..DEFAULT_MAX_QOS1_INFLIGHT {
            let (meta, payload) = encode_publish_meta("t", i as u16, 1, false, b"y");
            let (_, deliveries) =
                apply_publish(&publish_frame(62, 2000 + i as u64, meta, payload), &shared).await;
            assert_eq!(deliveries.len(), 1, "live delivery never blocks");
            for (conn_id, frame) in deliveries {
                let _ = shared.conns.route(conn_id, frame);
            }
            rx61.try_recv().expect("live downlink arrived");
        }
        assert_eq!(session.inflight_len(), DEFAULT_MAX_QOS1_INFLIGHT);
        let spill_iters = 20usize;
        let spill_start = Instant::now();
        for i in 0..spill_iters {
            let (meta, payload) = encode_publish_meta("t", i as u16, 1, false, b"z");
            let (_, deliveries) =
                apply_publish(&publish_frame(62, 3000 + i as u64, meta, payload), &shared).await;
            assert_eq!(deliveries.len(), 1, "bound never blocks live delivery");
            for (conn_id, frame) in deliveries {
                let _ = shared.conns.route(conn_id, frame);
            }
            rx61.try_recv()
                .expect("over-window downlink still delivered live");
        }
        let spill_elapsed = spill_start.elapsed();
        assert_eq!(session.inflight_spill_len(), spill_iters);
        assert_eq!(shared.metrics.inflight_spilled(), spill_iters as u64);
        let spill_rate = spill_iters as f64 / spill_elapsed.as_secs_f64();
        let spill_avg_ns = spill_elapsed.as_nanos() as f64 / spill_iters as f64;
        println!(
            "qos1 broker delivery workload spill-overflow (past window, after): {spill_rate:.0} msgs/sec, avg {spill_avg_ns:.1} ns/msg ({spill_iters} apply_publish rounds in {spill_elapsed:?})"
        );

        // Replay workload through the reconnect event, window then spill.
        let mut unbind_meta = vec![0x00u8, 0x09u8];
        unbind_meta.extend_from_slice(b"q1-timing");
        let unbind = BrokerFrame::new(
            OpCode::UnbindConnection,
            61,
            4,
            Bytes::from(unbind_meta),
            Bytes::new(),
        )
        .expect("valid unbind frame");
        apply_unbind(&unbind, &shared);
        let rebind = bind_frame(63, 1, encode_bind_meta("q1-timing", false, 60));
        reply_for_frame(&rebind, &shared.sessions).expect("rebind replies");
        let (tx63, mut rx63) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(63, tx63);
        let replay_start = Instant::now();
        let replayed = replay_offline(&rebind, &shared).await;
        let replay_elapsed = replay_start.elapsed();
        assert_eq!(replayed, DEFAULT_MAX_QOS1_INFLIGHT + spill_iters);
        let replay_rate = replayed as f64 / replay_elapsed.as_secs_f64();
        let replay_avg_ns = replay_elapsed.as_nanos() as f64 / replayed as f64;
        println!(
            "qos1 broker replay workload (window plus spill, after): {replay_rate:.0} msgs/sec, avg {replay_avg_ns:.1} ns/msg ({replayed} replayed in {replay_elapsed:?})"
        );
        for _ in 0..replayed {
            let got = rx63.try_recv().expect("ordered redelivery");
            assert!(decode_publish_dup(&got.metadata), "replay carries DUP=1");
        }
        assert!(rx63.try_recv().is_err(), "no new traffic interleaved");
    }

    #[tokio::test]
    async fn publish_qos0_needs_no_ack() {
        let shared = test_shared();
        let (meta, payload) = encode_publish_meta("t", 0, 0, false, b"x");
        let (ack, deliveries) = apply_publish(&publish_frame(60, 1, meta, payload), &shared).await;
        assert!(ack.is_none(), "QoS 0 needs no PubAck");
        assert!(deliveries.is_empty(), "no subscribers, no deliveries");
    }

    #[tokio::test]
    async fn publish_malformed_meta_yields_nothing() {
        let shared = test_shared();
        let (ack, deliveries) = apply_publish(
            &publish_frame(60, 1, Bytes::from(vec![0xFF]), Bytes::new()),
            &shared,
        )
        .await;
        assert!(ack.is_none());
        assert!(deliveries.is_empty());
    }

    #[tokio::test]
    async fn unbind_detaches_connection_but_keeps_subscriptions() {
        let shared = test_shared();
        // Durable session (clean_start=false): the detach keeps subscriptions.
        // (Clean sessions are covered by
        // `clean_session_disconnect_drops_subscriptions_no_ghost`, which
        // asserts the router copy is removed.)
        let bind = bind_frame(71, 1, encode_bind_meta("gone-1", false, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(71, 2, encode_subscribe_meta(1, "gone-1", &[("t", 0)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let mut unbind_meta = vec![0x00u8, 0x06u8];
        unbind_meta.extend_from_slice(b"gone-1");
        let unbind = BrokerFrame::new(
            OpCode::UnbindConnection,
            71,
            3,
            Bytes::from(unbind_meta),
            Bytes::new(),
        )
        .expect("valid unbind frame");
        apply_unbind(&unbind, &shared);

        let session = shared
            .sessions
            .get("gone-1")
            .expect("session survives unbind");
        assert!(!*session.connected.read());
        assert_eq!(*session.conn_id.read(), None);
        // Durable subscriptions survive the detach.
        assert_eq!(shared.router.matches(&Topic::new("t").unwrap()).len(), 1);
    }

    fn unbind_frame(conn_id: u64, seq: u64, client_id: &str) -> BrokerFrame {
        let mut meta = Vec::with_capacity(2 + client_id.len());
        meta.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        meta.extend_from_slice(client_id.as_bytes());
        BrokerFrame::new(
            OpCode::UnbindConnection,
            conn_id,
            seq,
            Bytes::from(meta),
            Bytes::new(),
        )
        .expect("valid unbind frame")
    }

    /// TK-04: a clean session leaves no subscriptions behind, so a later
    /// reconnect with the same client id receives nothing until it
    /// resubscribes. Fails before the fix with one ghost delivery.
    #[tokio::test]
    async fn clean_session_disconnect_drops_subscriptions_no_ghost() {
        let shared = test_shared();
        let bind = bind_frame(81, 1, encode_bind_meta("tk04-clean", true, 60));
        apply_bind(&bind, &shared).await.expect("bind replies");
        let sub = subscribe_frame(
            81,
            2,
            encode_subscribe_meta(1, "tk04-clean", &[("tk04/ghost", 0)]),
        );
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");
        assert_eq!(
            shared
                .router
                .matches(&Topic::new("tk04/ghost").unwrap())
                .len(),
            1
        );

        // Clean disconnect sweeps both the session mirror and the router.
        apply_unbind(&unbind_frame(81, 3, "tk04-clean"), &shared);
        let session = shared.sessions.get("tk04-clean").expect("session row");
        assert!(!*session.connected.read());
        assert_eq!(*session.conn_id.read(), None);
        assert!(session.subscriptions.read().is_empty());
        assert!(
            shared
                .router
                .matches(&Topic::new("tk04/ghost").unwrap())
                .is_empty(),
            "clean disconnect must remove the router copy"
        );

        // Reconnect clean with the same client id: fresh session, no subs.
        let rebind = bind_frame(82, 1, encode_bind_meta("tk04-clean", true, 60));
        apply_bind(&rebind, &shared).await.expect("rebind replies");
        assert!(shared
            .router
            .matches(&Topic::new("tk04/ghost").unwrap())
            .is_empty());

        // A publish to the old topic reaches nobody.
        let (meta, payload) = encode_publish_meta("tk04/ghost", 0, 0, false, b"stale");
        let (_, deliveries) = apply_publish(&publish_frame(99, 4, meta, payload), &shared).await;
        assert!(
            deliveries.is_empty(),
            "ghost delivery: clean reconnect must receive nothing until resubscribe"
        );
    }

    /// TK-04 companion: a persistent session keeps its subscription across
    /// the same disconnect/reconnect sequence (what durable redelivery
    /// builds on).
    #[tokio::test]
    async fn durable_session_disconnect_keeps_subscriptions() {
        let shared = test_shared();
        let bind = bind_frame(91, 1, encode_bind_meta("tk04-durable", false, 60));
        apply_bind(&bind, &shared).await.expect("bind replies");
        let sub = subscribe_frame(
            91,
            2,
            encode_subscribe_meta(1, "tk04-durable", &[("tk04/kept", 0)]),
        );
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        apply_unbind(&unbind_frame(91, 3, "tk04-durable"), &shared);
        // Detached durable session: router copy and session mirror survive.
        assert_eq!(
            shared
                .router
                .matches(&Topic::new("tk04/kept").unwrap())
                .len(),
            1
        );
        assert_eq!(
            shared
                .sessions
                .get("tk04-durable")
                .expect("session row")
                .subscriptions
                .read()
                .len(),
            1
        );

        // Reconnect durably on a new connection: the subscription routes.
        let rebind = bind_frame(92, 1, encode_bind_meta("tk04-durable", false, 60));
        apply_bind(&rebind, &shared).await.expect("rebind replies");
        let (meta, payload) = encode_publish_meta("tk04/kept", 0, 0, false, b"live");
        let (_, deliveries) = apply_publish(&publish_frame(99, 4, meta, payload), &shared).await;
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].0, 92);
    }

    #[tokio::test]
    async fn subscribe_then_publish_routes_to_subscriber_transport() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        // Accept exactly two edge connections sharing one kernel.
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            // Park until the test aborts us; handlers are independent tasks.
            std::future::pending::<()>().await;
        });

        // Subscriber: bind as conn 101, subscribe with a wildcard.
        let sub_io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect sub");
        let sub = FramedTransport::new(sub_io);
        sub.send(bind_frame(101, 1, encode_bind_meta("route-me", true, 60)))
            .await
            .expect("bind");
        let binding = sub.recv().await.expect("recv binding");
        assert_eq!(binding.header.opcode, OpCode::SessionBinding);
        sub.send(subscribe_frame(
            101,
            2,
            encode_subscribe_meta(11, "route-me", &[("sport/+", 1)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);
        assert_eq!(&suback.metadata[0..2], &11u16.to_be_bytes());
        assert_eq!(&suback.metadata[2..], &[1u8]);

        // Publisher: bind as conn 102, publish QoS 1.
        let pub_io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect pub");
        let publ = FramedTransport::new(pub_io);
        publ.send(bind_frame(102, 1, encode_bind_meta("writer", true, 60)))
            .await
            .expect("bind");
        let _ = publ.recv().await.expect("recv binding");
        let (meta, payload) = encode_publish_meta("sport/tennis", 77, 1, false, b"match-point");
        publ.send(publish_frame(102, 2, meta, payload))
            .await
            .expect("publish");

        // Publisher gets its PubAck on its own transport.
        let ack = publ.recv().await.expect("recv puback");
        assert_eq!(ack.header.opcode, OpCode::PubAckOut);
        assert_eq!(ack.header.conn_id, 102);
        assert_eq!(&ack.metadata[..], &[0x00, 0x4D, 0x00]);

        // Subscriber gets the routed PublishOut on its own transport.
        let routed = sub.recv().await.expect("recv publish");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert_eq!(routed.header.conn_id, 101);
        assert_eq!(routed.payload, Bytes::from_static(b"match-point"));
        let (topic, _, qos, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "sport/tennis");
        assert_eq!(qos, 1);

        server.abort();
    }

    #[tokio::test]
    async fn rule_republish_reaches_alert_subscriber() {
        use broker_rules::RuleAction;

        let shared = Shared::new();
        // Ingress rule: anything under sensors/+ is republished to
        // alerts/critical. No MQTT loopback involved: delivery flows
        // engine -> in-memory sink -> subscriber mailbox.
        shared
            .engine
            .create_rule(
                "republish-temp".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                None,
                true,
                vec![RuleAction::Republish {
                    topic: Topic::new("alerts/critical").unwrap(),
                    qos: QoS::AtMostOnce,
                }],
            )
            .expect("rule creates");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        // Client A subscribes to alerts/critical as conn 301.
        let sub_io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect sub");
        let sub = FramedTransport::new(sub_io);
        sub.send(bind_frame(
            301,
            1,
            encode_bind_meta("alert-watcher", true, 60),
        ))
        .await
        .expect("bind");
        let _ = sub.recv().await.expect("recv binding");
        sub.send(subscribe_frame(
            301,
            2,
            encode_subscribe_meta(5, "alert-watcher", &[("alerts/critical", 1)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);

        // Client B publishes to sensors/temperature as conn 302.
        let pub_io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect pub");
        let publ = FramedTransport::new(pub_io);
        publ.send(bind_frame(
            302,
            1,
            encode_bind_meta("thermometer", true, 60),
        ))
        .await
        .expect("bind");
        let _ = publ.recv().await.expect("recv binding");
        let (meta, payload) = encode_publish_meta("sensors/temperature", 0, 0, false, b"21.5C");
        publ.send(publish_frame(302, 2, meta, payload))
            .await
            .expect("publish");

        // Client A receives the rule-republished message with the
        // identical payload on its own transport.
        let routed = sub.recv().await.expect("recv republished");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert_eq!(routed.header.conn_id, 301);
        assert_eq!(routed.payload, Bytes::from_static(b"21.5C"));
        let (topic, _, qos, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "alerts/critical");
        assert_eq!(qos, 0);

        server.abort();
    }

    #[tokio::test]
    async fn rule_sql_transforms_payload_end_to_end() {
        use broker_rules::RuleAction;

        let shared = Shared::new();
        // Streaming SQL rule: project only `temperature` out of raw
        // payloads. The secret field must never reach subscribers.
        shared
            .engine
            .create_rule(
                "project-temp".to_string(),
                TopicFilter::new("raw/+").unwrap(),
                Some(r#"SELECT temperature FROM "raw/temp" WHERE temperature > 0"#.to_string()),
                true,
                vec![RuleAction::Republish {
                    topic: Topic::new("transformed/temp").unwrap(),
                    qos: QoS::AtMostOnce,
                }],
            )
            .expect("SQL rule creates");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        // Client A subscribes to transformed/temp as conn 401.
        let sub_io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect sub");
        let sub = FramedTransport::new(sub_io);
        sub.send(bind_frame(401, 1, encode_bind_meta("dashboard", true, 60)))
            .await
            .expect("bind");
        let _ = sub.recv().await.expect("recv binding");
        sub.send(subscribe_frame(
            401,
            2,
            encode_subscribe_meta(5, "dashboard", &[("transformed/temp", 1)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);

        // Client B publishes a wide payload to raw/temp as conn 402.
        let pub_io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect pub");
        let publ = FramedTransport::new(pub_io);
        publ.send(bind_frame(402, 1, encode_bind_meta("sensor-9", true, 60)))
            .await
            .expect("bind");
        let _ = publ.recv().await.expect("recv binding");
        let raw = br#"{ "temperature": 85.0, "secret": "hide_me" }"#;
        let (meta, payload) = encode_publish_meta("raw/temp", 0, 0, false, raw);
        publ.send(publish_frame(402, 2, meta, payload))
            .await
            .expect("publish");

        // Client A receives only the projected field over its transport.
        let routed = sub.recv().await.expect("recv transformed");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert_eq!(routed.header.conn_id, 401);
        let (topic, _, _, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "transformed/temp");
        let body: serde_json::Value =
            serde_json::from_slice(&routed.payload).expect("payload is JSON");
        assert_eq!(body, serde_json::json!({ "temperature": 85.0 }));

        server.abort();
    }

    async fn bind_client(
        addr: std::net::SocketAddr,
        conn_id: u64,
        client_id: &str,
        clean_start: bool,
    ) -> FramedTransport<tokio::net::TcpStream> {
        let io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect client");
        let client = FramedTransport::new(io);
        client
            .send(bind_frame(
                conn_id,
                1,
                encode_bind_meta(client_id, clean_start, 60),
            ))
            .await
            .expect("bind");
        let binding = client.recv().await.expect("recv binding");
        assert_eq!(binding.header.opcode, OpCode::SessionBinding);
        client
    }

    #[tokio::test]
    async fn retained_message_delivered_to_late_subscriber() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        // Client A publishes retained state before anyone subscribes.
        let publ = bind_client(addr, 501, "sensor-a", true).await;
        let (meta, payload) =
            encode_publish_meta("device/state", 0, 0, true, b"{ \"status\": \"online\" }");
        publ.send(publish_frame(501, 2, meta, payload))
            .await
            .expect("publish retained");

        // Client B connects later and subscribes with a wildcard.
        let sub = bind_client(addr, 502, "watcher-b", true).await;
        sub.send(subscribe_frame(
            502,
            2,
            encode_subscribe_meta(7, "watcher-b", &[("device/+", 0)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);

        // The retained message follows the SUBACK immediately.
        let held = sub.recv().await.expect("recv retained");
        assert_eq!(held.header.opcode, OpCode::PublishOut);
        assert_eq!(held.header.conn_id, 502);
        assert_eq!(
            held.payload,
            Bytes::from_static(b"{ \"status\": \"online\" }")
        );
        let (topic, _, qos, retain) = decode_publish_meta_parts(&held.metadata);
        assert_eq!(topic, "device/state");
        assert_eq!(qos, 0);
        assert!(retain, "replayed retained message must carry retain = true");

        // Clearing with an empty retained publish removes the state.
        let (meta, payload) = encode_publish_meta("device/state", 0, 0, true, b"");
        publ.send(publish_frame(501, 3, meta, payload))
            .await
            .expect("clear retained");

        // A later subscriber gets its SUBACK but no retained message.
        let late = bind_client(addr, 503, "watcher-c", true).await;
        late.send(subscribe_frame(
            503,
            2,
            encode_subscribe_meta(8, "watcher-c", &[("device/+", 0)]),
        ))
        .await
        .expect("subscribe");
        let suback = late.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);
        let nothing =
            tokio::time::timeout(std::time::Duration::from_millis(400), late.recv()).await;
        assert!(
            nothing.is_err(),
            "cleared retained state must not be delivered"
        );

        server.abort();
    }

    #[tokio::test]
    async fn offline_queue_replays_on_durable_reconnect() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        // Client A connects durably and subscribes.
        let sub = bind_client(addr, 601, "worker-a", false).await;
        sub.send(subscribe_frame(
            601,
            2,
            encode_subscribe_meta(3, "worker-a", &[("job/queue", 1)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);

        // Unclean disconnect: TCP drops without DISCONNECT. Give the
        // server a beat to detach the session before publishing.
        drop(sub);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        // Client B publishes QoS 1 while A is detached.
        let publ = bind_client(addr, 602, "producer-b", true).await;
        let (meta, payload) = encode_publish_meta("job/queue", 9, 1, false, b"work-item");
        publ.send(publish_frame(602, 2, meta, payload))
            .await
            .expect("publish");
        let ack = publ.recv().await.expect("recv puback");
        assert_eq!(ack.header.opcode, OpCode::PubAckOut);

        // Client A reconnects durably on a new connection.
        let io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("reconnect");
        let resumed = FramedTransport::new(io);
        resumed
            .send(bind_frame(603, 1, encode_bind_meta("worker-a", false, 60)))
            .await
            .expect("rebind");
        let binding = resumed.recv().await.expect("recv binding");
        assert_eq!(binding.header.opcode, OpCode::SessionBinding);
        let (_, present, rc) = decode_session_binding_meta(&binding.metadata);
        assert!(present, "resumed session must report session_present");
        assert_eq!(rc, 0);

        // The queued message replays onto the new connection.
        let replayed = resumed.recv().await.expect("recv replay");
        assert_eq!(replayed.header.opcode, OpCode::PublishOut);
        assert_eq!(replayed.header.conn_id, 603);
        assert_eq!(replayed.payload, Bytes::from_static(b"work-item"));
        let (topic, packet_id, qos, _) = decode_publish_meta_parts(&replayed.metadata);
        assert_eq!(topic, "job/queue");
        assert_eq!(qos, 1);
        assert_ne!(packet_id, 0, "replayed QoS 1 needs a fresh packet id");

        server.abort();
    }

    #[tokio::test]
    async fn cluster_forwards_publish_to_subscribed_node() {
        use broker_cluster::{ChannelRoutingPlane, NodeId};

        // Two nodes meshed over in-process channels.
        let plane1 = ChannelRoutingPlane::new(NodeId::new("node-1"));
        let plane2 = ChannelRoutingPlane::new(NodeId::new("node-2"));
        ChannelRoutingPlane::link(&plane1, &plane2);

        let mut shared1 = Shared::new();
        shared1.cluster = Some(plane1.clone() as Arc<dyn RoutingPlane>);
        let mut shared2 = Shared::new();
        shared2.cluster = Some(plane2.clone() as Arc<dyn RoutingPlane>);

        // One BrokerLink listener + one inbox pump per node.
        async fn serve_one(
            shared: Shared,
        ) -> (std::net::SocketAddr, Vec<tokio::task::JoinHandle<()>>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local addr");
            let accept = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                handle_connection(stream, shared).await.expect("handle");
            });
            (addr, vec![accept])
        }
        let (addr1, mut tasks) = serve_one(shared1.clone()).await;
        let (addr2, mut tasks2) = serve_one(shared2.clone()).await;
        tasks.push(tokio::spawn(run_cluster_inbox(shared1)));
        tasks2.push(tokio::spawn(run_cluster_inbox(shared2)));

        // Client A subscribes to metrics/# on node 1 as conn 701.
        let sub = bind_client(addr1, 701, "metrics-fan", true).await;
        sub.send(subscribe_frame(
            701,
            2,
            encode_subscribe_meta(3, "metrics-fan", &[("metrics/#", 1)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);

        // Client B publishes to metrics/cpu on node 2 as conn 702.
        let publ = bind_client(addr2, 702, "cpu-sensor", true).await;
        let (meta, payload) = encode_publish_meta("metrics/cpu", 0, 0, false, b"42");
        publ.send(publish_frame(702, 2, meta, payload))
            .await
            .expect("publish");

        // Client A receives the single cross-node forward.
        let routed = sub.recv().await.expect("recv forwarded");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert_eq!(routed.header.conn_id, 701);
        assert_eq!(routed.payload, Bytes::from_static(b"42"));
        let (topic, _, qos, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "metrics/cpu");
        assert_eq!(qos, 0);

        // A topic nobody subscribes to is not forwarded: silence proves
        // both no-match suppression and no duplicate delivery.
        let (meta, payload) = encode_publish_meta("unrelated/foo", 0, 0, false, b"zzz");
        publ.send(publish_frame(702, 3, meta, payload))
            .await
            .expect("publish unrelated");
        let silence = tokio::time::timeout(std::time::Duration::from_millis(400), sub.recv()).await;
        assert!(silence.is_err(), "unmatched topics must not cross nodes");

        for task in tasks.into_iter().chain(tasks2) {
            task.abort();
        }
    }

    #[tokio::test]
    async fn cluster_swim_membership_and_discovery_e2e() {
        use broker_cluster::{
            ChannelSwimNetwork, ClusterMembership, NodeId, SwimConfig, SwimMembership,
        };

        let net = ChannelSwimNetwork::new();
        let t1 = net.register(NodeId::new("node-alpha"));
        let t2 = net.register(NodeId::new("node-beta"));

        let swim1 = SwimMembership::new(NodeId::new("node-alpha"), None, SwimConfig::default(), t1);
        let swim2 = SwimMembership::new(NodeId::new("node-beta"), None, SwimConfig::default(), t2);

        // Start background tasks for both nodes
        let h1 = swim1.clone().run_background();
        let h2 = swim2.clone().run_background();

        // Node-2 joins Node-1
        swim2
            .join_seed(&NodeId::new("node-alpha"))
            .await
            .expect("join seed");

        // Wait a brief tick for Join/JoinAck exchange
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let active1 = swim1.active_nodes().await.expect("active nodes 1");
        let active2 = swim2.active_nodes().await.expect("active nodes 2");

        assert!(active1.contains(&NodeId::new("node-beta")));
        assert!(active2.contains(&NodeId::new("node-alpha")));

        h1.abort();
        h2.abort();
    }

    async fn http_get_text(port: u16, path: &str) -> (u16, String) {
        http_request_text(port, "GET", path, None, None).await
    }

    /// Raw HTTP/1.0 request with optional JSON body and bearer token.
    async fn http_request_text(
        port: u16,
        method: &str,
        path: &str,
        body: Option<&str>,
        token: Option<&str>,
    ) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect api");
        let mut req = format!("{method} {path} HTTP/1.0\r\nHost: test\r\n");
        if let Some(token) = token {
            req.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        if let Some(body) = body {
            req.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ));
        } else {
            req.push_str("Connection: close\r\n\r\n");
        }
        stream
            .write_all(req.as_bytes())
            .await
            .expect("write api request");
        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .await
            .expect("read api response");
        let text = String::from_utf8(buf).expect("api response is UTF-8");
        let (head, body) = text.split_once("\r\n\r\n").expect("header/body split");
        let status: u16 = head.lines().next().expect("status line")[9..12]
            .parse()
            .expect("status code");
        (status, body.to_string())
    }

    /// Log in as the default admin, clear the default-password flag and
    /// return a fully-privileged bearer token.
    async fn http_admin_token(port: u16) -> String {
        let login = serde_json::json!({"username": "admin", "password": "public"}).to_string();
        let (status, body) =
            http_request_text(port, "POST", "/api/v5/login", Some(&login), None).await;
        assert_eq!(status, 200);
        let token: String = serde_json::from_str::<serde_json::Value>(&body)
            .expect("login is JSON")["token"]
            .as_str()
            .expect("login token")
            .to_string();
        let change =
            serde_json::json!({"old_pwd": "public", "new_pwd": "Adm1n-test-pass!"}).to_string();
        let (status, _) = http_request_text(
            port,
            "PUT",
            "/api/v5/users/admin/change_pwd",
            Some(&change),
            Some(&token),
        )
        .await;
        assert_eq!(status, 204);
        let login =
            serde_json::json!({"username": "admin", "password": "Adm1n-test-pass!"}).to_string();
        let (status, body) =
            http_request_text(port, "POST", "/api/v5/login", Some(&login), None).await;
        assert_eq!(status, 200);
        serde_json::from_str::<serde_json::Value>(&body).expect("login is JSON")["token"]
            .as_str()
            .expect("login token")
            .to_string()
    }

    #[tokio::test]
    async fn api_serves_embedded_dashboard() {
        let shared = Shared::new();
        let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind api");
        let api_port = api_listener.local_addr().expect("api addr").port();
        let api_task = tokio::spawn(serve_api(api_listener, shared));

        // Root redirects to the console.
        let (status, _) = http_get_text(api_port, "/").await;
        assert_eq!(status, 303);

        // The console shell loads with its key regions.
        let (status, html) = http_get_text(api_port, "/dashboard").await;
        assert_eq!(status, 200);
        for marker in [
            "<title>IndraMQTT Console</title>",
            "Community Edition (MIT)",
            "id=\"metrics\"",
            "id=\"sql-studio\"",
            "id=\"console\"",
            "/ws/mqtt",
        ] {
            assert!(html.contains(marker), "dashboard missing {marker}");
        }

        api_task.abort();
    }

    #[tokio::test]
    async fn api_metrics_reflect_edge_traffic() {
        let shared = Shared::new();

        // Management API on an ephemeral port, sharing node state.
        let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind api");
        let api_port = api_listener.local_addr().expect("api addr").port();
        let api_task = tokio::spawn(serve_api(api_listener, shared.clone()));

        // One edge connection: bind, subscribe, publish.
        let bl_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let bl_addr = bl_listener.local_addr().expect("local addr");
        let edge_task = tokio::spawn(async move {
            let (stream, _) = bl_listener.accept().await.expect("accept");
            handle_connection(stream, shared).await.expect("handle");
        });

        let client = bind_client(bl_addr, 801, "metrics-probe", true).await;
        client
            .send(subscribe_frame(
                801,
                2,
                encode_subscribe_meta(3, "metrics-probe", &[("m/+", 0)]),
            ))
            .await
            .expect("subscribe");
        let suback = client.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);
        let (meta, payload) = encode_publish_meta("m/1", 0, 0, false, b"x");
        client
            .send(publish_frame(801, 3, meta, payload))
            .await
            .expect("publish");
        // Drain our own delivery so the mailbox cannot back up the test.
        let delivered = client.recv().await.expect("recv delivery");
        assert_eq!(delivered.header.opcode, OpCode::PublishOut);

        let token = http_admin_token(api_port).await;
        let (status, body) =
            http_request_text(api_port, "GET", "/api/v1/metrics", None, Some(&token)).await;
        assert_eq!(status, 200);
        assert!(body.contains("indramqtt_messages_received_total 1\n"));
        assert!(body.contains("indramqtt_messages_forwarded_total 1\n"));
        assert!(body.contains("indramqtt_connections_active 1\n"));

        let (status, body) =
            http_request_text(api_port, "GET", "/api/v1/clients", None, Some(&token)).await;
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("clients is JSON"),
            serde_json::json!(["metrics-probe"])
        );

        edge_task.abort();
        api_task.abort();
    }

    #[tokio::test]
    async fn bind_auth_rejects_bad_password_with_0x86() {
        let shared = test_shared();
        shared
            .auth
            .add_user("alice", b"s3cret")
            .expect("memory-only persist cannot fail");

        let frame = bind_frame(
            81,
            1,
            encode_bind_meta_creds("dev-x", true, 60, "alice", b"wrong"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "bad password must yield return code 0x86");
        assert!(!present);
        // Failed binds create no session.
        assert!(shared.sessions.get("dev-x").is_none());
    }

    #[tokio::test]
    async fn bind_auth_rejects_anonymous_when_users_exist() {
        let shared = test_shared();
        shared
            .auth
            .add_user("alice", b"s3cret")
            .expect("memory-only persist cannot fail");

        // Anonymous bind is rejected with 0x87 and creates no session.
        let frame = bind_frame(83, 1, encode_bind_meta("dev-z", true, 60));
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x87, "anonymous bind must yield return code 0x87");
        assert!(!present);
        assert!(shared.sessions.get("dev-z").is_none());

        // A valid credentialed bind in the same store still gets rc 0.
        let frame = bind_frame(
            82,
            1,
            encode_bind_meta_creds("dev-y", true, 60, "alice", b"s3cret"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);
    }

    #[tokio::test]
    async fn bind_auth_accepts_anonymous_when_no_users() {
        let shared = test_shared();

        let frame = bind_frame(83, 1, encode_bind_meta("dev-z", true, 60));
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);
    }

    #[tokio::test]
    async fn bind_auth_rejects_anonymous_with_allow_flag_when_users_exist() {
        // `--allow-anonymous` is ignored once users exist: a non-empty
        // user store always rejects unauthenticated clients with 0x87.
        let mut shared = test_shared();
        shared.allow_anonymous = true;
        shared
            .auth
            .add_user("alice", b"s3cret")
            .expect("memory-only persist cannot fail");

        let frame = bind_frame(83, 1, encode_bind_meta("dev-z", true, 60));
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x87, "anonymous bind must yield return code 0x87");
        assert!(!present);
        assert!(shared.sessions.get("dev-z").is_none());
    }

    #[tokio::test]
    async fn bind_auth_accepts_anonymous_with_allow_flag_when_store_empty() {
        // While the user store is empty the flag keeps its meaning.
        let mut shared = test_shared();
        shared.allow_anonymous = true;

        let frame = bind_frame(83, 1, encode_bind_meta("dev-z", true, 60));
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);
    }

    /// B2-01: directory authentication through the broker CONNECT path.
    ///
    /// Starts a real directory server (yamldap, speaking the LDAP wire
    /// protocol) and drives CONNECTs through `apply_bind`, the same entry
    /// point the BrokerLink edge uses. Valid directory binds are accepted,
    /// wrong passwords, unknown users and wrong-group users are refused
    /// with 0x86, anonymous is refused with 0x87 while the directory is
    /// configured, and an unreachable directory fails closed.
    #[tokio::test]
    async fn ldap_bind_through_broker_connect() {
        const BASE_DN: &str = "dc=example,dc=com";
        const SERVICE_DN: &str = "cn=reader,dc=example,dc=com";
        const SERVICE_PW: &str = "readerpw";
        const REQUIRED_GROUP: &str = "cn=mqtt-users,ou=groups,dc=example,dc=com";

        let dir_yaml = format!(
            "directory:\n  base_dn: {BASE_DN}\nentries:\n  - dn: {BASE_DN}\n    objectClass: [top, domain]\n    dc: example\n  - dn: ou=users,{BASE_DN}\n    objectClass: [top, organizationalUnit]\n    ou: users\n  - dn: ou=groups,{BASE_DN}\n    objectClass: [top, organizationalUnit]\n    ou: groups\n  - dn: {SERVICE_DN}\n    objectClass: [top, person]\n    cn: reader\n    sn: reader\n    userPassword: {SERVICE_PW}\n  - dn: uid=alice,ou=users,{BASE_DN}\n    objectClass: [top, person, inetOrgPerson]\n    uid: alice\n    cn: Alice\n    sn: Alice\n    userPassword: alicepw\n    memberOf: {REQUIRED_GROUP}\n  - dn: uid=bob,ou=users,{BASE_DN}\n    objectClass: [top, person, inetOrgPerson]\n    uid: bob\n    cn: Bob\n    sn: Bob\n    userPassword: bobpw\n    memberOf: cn=other-group,ou=groups,{BASE_DN}\n  - dn: {REQUIRED_GROUP}\n    objectClass: [top, groupOfNames]\n    cn: mqtt-users\n    member: uid=alice,ou=users,{BASE_DN}\n"
        );
        let dir_file = tempfile::NamedTempFile::new().expect("temp directory YAML");
        std::fs::write(dir_file.path(), dir_yaml).expect("write directory YAML");
        let directory_config = yamldap::Config::new(dir_file.path())
            .with_bind_address("127.0.0.1:0".parse().expect("loopback"));
        let directory = yamldap::Server::new(directory_config)
            .await
            .expect("directory starts");
        let handle = directory.start().await.expect("directory listens");
        let url = format!("ldap://{}", handle.local_addr());

        let ldap_config = LdapConfig {
            server_url: url,
            base_dn: BASE_DN.to_string(),
            bind_dn: SERVICE_DN.to_string(),
            bind_password: SERVICE_PW.to_string(),
            user_filter: "(uid={username})".to_string(),
            group_attribute: "memberOf".to_string(),
            required_group: REQUIRED_GROUP.to_string(),
            pool_size: 4,
            connect_timeout_ms: 3_000,
            read_timeout_ms: 3_000,
            timeout_ms: 0,
            tls_verify: true,
            ca_cert_path: None,
            bind_dn_template: String::new(),
            filter_template: String::new(),
        };
        let mut shared = test_shared();
        shared.ldap = Some(std::sync::Arc::new(LdapAuthenticator::new(ldap_config)));
        // Local users keep working alongside the directory.
        shared
            .auth
            .add_user("local-user", b"localpw")
            .expect("seed local user");

        // Valid directory bind through the broker: accepted.
        let frame = bind_frame(
            91,
            1,
            encode_bind_meta_creds("ldap-device-1", true, 60, "alice", b"alicepw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0, "valid directory bind must be accepted");
        assert!(shared.sessions.get("ldap-device-1").is_some());

        // Local user still authenticates with the directory configured.
        let frame = bind_frame(
            92,
            1,
            encode_bind_meta_creds("local-device", true, 60, "local-user", b"localpw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0, "local users keep working with LDAP enabled");

        // Wrong directory password: refused with 0x86, no session.
        let frame = bind_frame(
            93,
            1,
            encode_bind_meta_creds("ldap-device-2", true, 60, "alice", b"wrong"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "wrong directory password must yield 0x86");
        assert!(!present);
        assert!(shared.sessions.get("ldap-device-2").is_none());

        // Unknown directory user: refused with 0x86.
        let frame = bind_frame(
            94,
            1,
            encode_bind_meta_creds("ldap-device-3", true, 60, "mallory", b"anything"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "unknown directory user must yield 0x86");

        // Correct password but wrong group: authorised as denied.
        let frame = bind_frame(
            95,
            1,
            encode_bind_meta_creds("ldap-device-4", true, 60, "bob", b"bobpw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "wrong-group user must be denied with 0x86");
        assert!(shared.sessions.get("ldap-device-4").is_none());

        // Anonymous while a directory is configured: refused with 0x87.
        let frame = bind_frame(96, 1, encode_bind_meta("ldap-anon", true, 60));
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(
            rc, 0x87,
            "anonymous must be refused while LDAP is configured"
        );

        // Unreachable directory fails closed through the same path.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral port");
        let closed_addr = closed.local_addr().expect("local addr");
        drop(closed);
        let down_config = LdapConfig {
            server_url: format!("ldap://{closed_addr}"),
            base_dn: BASE_DN.to_string(),
            bind_dn: SERVICE_DN.to_string(),
            bind_password: SERVICE_PW.to_string(),
            user_filter: "(uid={username})".to_string(),
            group_attribute: "memberOf".to_string(),
            required_group: REQUIRED_GROUP.to_string(),
            pool_size: 2,
            connect_timeout_ms: 1_000,
            read_timeout_ms: 1_000,
            timeout_ms: 0,
            tls_verify: true,
            ca_cert_path: None,
            bind_dn_template: String::new(),
            filter_template: String::new(),
        };
        let mut down_shared = test_shared();
        down_shared.ldap = Some(std::sync::Arc::new(LdapAuthenticator::new(down_config)));
        let frame = bind_frame(
            97,
            1,
            encode_bind_meta_creds("ldap-down", true, 60, "alice", b"alicepw"),
        );
        let reply = apply_bind(&frame, &down_shared)
            .await
            .expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "directory outage must fail closed with 0x86");
        assert!(down_shared.sessions.get("ldap-down").is_none());
    }

    /// B2-02: Kerberos authentication through the broker CONNECT path.
    ///
    /// Starts an in-process test KDC (real DER via manual encoding that the
    /// broker decodes with `kerberos-parser`/`der-parser`, real AES-256-GCM
    /// via `ring`) holding the broker service key in a MIT keytab v2 file,
    /// then drives CONNECTs through `apply_bind`, the same entry point the
    /// edge uses. A valid ticket (bare and SPNEGO-wrapped) is accepted,
    /// expired, wrong-service, replayed and malformed tokens are refused
    /// with 0x86, the old B1-01 plaintext bypasses still fail, anonymous is
    /// refused while Kerberos is enabled, and local users keep working.
    #[tokio::test]
    async fn kerberos_bind_through_broker_connect() {
        use std::collections::HashMap;
        use std::io::Write as _;

        const REALM: &str = "EXAMPLE.COM";
        const SERVICE_FULL: &str = "mqtt/broker.example.com@EXAMPLE.COM";

        fn krb_len(len: usize) -> Vec<u8> {
            if len < 128 {
                vec![len as u8]
            } else {
                let mut bytes = Vec::new();
                let mut n = len;
                while n > 0 {
                    bytes.push((n & 0xFF) as u8);
                    n >>= 8;
                }
                bytes.reverse();
                let mut out = vec![0x80 | (bytes.len() as u8)];
                out.extend_from_slice(&bytes);
                out
            }
        }

        fn krb_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            out.extend_from_slice(&krb_len(content.len()));
            out.extend_from_slice(content);
            out
        }

        fn krb_u32(v: u32) -> Vec<u8> {
            let mut bytes = v.to_be_bytes().to_vec();
            while bytes.len() > 1 && bytes[0] == 0 {
                bytes.remove(0);
            }
            if bytes[0] & 0x80 != 0 {
                let mut prefixed = vec![0x00];
                prefixed.extend_from_slice(&bytes);
                bytes = prefixed;
            }
            krb_tlv(0x02, &bytes)
        }

        fn krb_general_string(s: &str) -> Vec<u8> {
            krb_tlv(0x1B, s.as_bytes())
        }

        fn krb_octets(b: &[u8]) -> Vec<u8> {
            krb_tlv(0x04, b)
        }

        fn krb_seq(content: &[u8]) -> Vec<u8> {
            krb_tlv(0x30, content)
        }

        fn krb_ctx(n: u8, content: &[u8]) -> Vec<u8> {
            krb_tlv(0xA0 | n, content)
        }

        fn krb_app(n: u8, content: &[u8]) -> Vec<u8> {
            krb_tlv(0x60 | n, content)
        }

        fn krb_oid_content(numbers: &[u64]) -> Vec<u8> {
            let mut out = vec![(numbers[0] * 40 + numbers[1]) as u8];
            for n in &numbers[2..] {
                let mut stack = Vec::new();
                let mut v = *n;
                loop {
                    stack.push((v & 0x7F) as u8);
                    v >>= 7;
                    if v == 0 {
                        break;
                    }
                }
                stack.reverse();
                for (i, b) in stack.iter().enumerate() {
                    if i + 1 < stack.len() {
                        out.push(b | 0x80);
                    } else {
                        out.push(*b);
                    }
                }
            }
            out
        }

        fn krb_oid(numbers: &[u64]) -> Vec<u8> {
            krb_tlv(0x06, &krb_oid_content(numbers))
        }

        fn krb_cts_encrypt(key: &[u8; 32], key_usage: i32, plain: &[u8]) -> Vec<u8> {
            use picky_krb::crypto::CipherSuite;
            CipherSuite::Aes256CtsHmacSha196
                .cipher()
                .encrypt(key, key_usage, plain)
                .expect("CTS encrypt")
        }

        fn krb_realm(s: &str) -> picky_krb::data_types::Realm {
            use picky_asn1::restricted_string::IA5String;
            picky_krb::data_types::Realm::from(picky_asn1::wrapper::GeneralStringAsn1::from(
                IA5String::from_string(s.to_string()).expect("realm as IA5"),
            ))
        }

        fn krb_principal(name_type: u8, comps: &[String]) -> picky_krb::data_types::PrincipalName {
            use picky_asn1::restricted_string::IA5String;
            use picky_asn1::wrapper::{Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1};
            let strings: Vec<picky_krb::data_types::KerberosStringAsn1> = comps
                .iter()
                .map(|c| {
                    picky_krb::data_types::KerberosStringAsn1::from(
                        IA5String::from_string(c.clone()).expect("component as IA5"),
                    )
                })
                .collect();
            picky_krb::data_types::PrincipalName {
                name_type: ExplicitContextTag0::from(picky_asn1::wrapper::IntegerAsn1::from(vec![
                    name_type,
                ])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(strings)),
            }
        }

        fn krb_time(secs: i64) -> picky_krb::data_types::KerberosTime {
            use picky_asn1::date::GeneralizedTime;
            let dt = time::OffsetDateTime::from_unix_timestamp(secs).expect("valid time");
            picky_krb::data_types::KerberosTime::from(GeneralizedTime::from(dt))
        }

        fn krb_ticket_inner(
            client: &str,
            _service: &str,
            start: i64,
            end: i64,
            session_key: &[u8],
        ) -> Vec<u8> {
            use picky_asn1::wrapper::{
                ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
                ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7,
                OctetStringAsn1, Optional,
            };
            use picky_krb::data_types::{
                EncTicketPart, EncTicketPartInner, EncryptionKey, TransitedEncoding,
            };
            let (cname_part, crealm_part) =
                client.split_once('@').unwrap_or((client, "EXAMPLE.COM"));
            let cname = krb_principal(1, &[cname_part.to_string()]);
            let crealm = krb_realm(crealm_part);
            let enc_part = EncTicketPart::from(EncTicketPartInner {
                flags: ExplicitContextTag0::from(picky_asn1::wrapper::BitStringAsn1::default()),
                key: ExplicitContextTag1::from(EncryptionKey {
                    key_type: ExplicitContextTag0::from(picky_asn1::wrapper::IntegerAsn1::from(
                        vec![18u8],
                    )),
                    key_value: ExplicitContextTag1::from(OctetStringAsn1::from(
                        session_key.to_vec(),
                    )),
                }),
                crealm: ExplicitContextTag2::from(crealm),
                cname: ExplicitContextTag3::from(cname),
                transited: ExplicitContextTag4::from(TransitedEncoding {
                    tr_type: ExplicitContextTag0::from(picky_asn1::wrapper::IntegerAsn1::from(
                        vec![0u8],
                    )),
                    contents: ExplicitContextTag1::from(OctetStringAsn1::from(vec![1u8])),
                }),
                auth_time: ExplicitContextTag5::from(krb_time(start)),
                starttime: Optional::from(Some(ExplicitContextTag6::from(krb_time(start)))),
                endtime: ExplicitContextTag7::from(krb_time(end)),
                renew_till: Optional::from(None),
                caddr: Optional::from(None),
                authorization_data: Optional::from(None),
            });
            picky_asn1_der::to_vec(&enc_part).expect("encode EncTicketPart")
        }

        fn krb_auth_inner(client: &str, ts: i64, usec: u32) -> Vec<u8> {
            use picky_asn1::wrapper::{
                ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag4,
                ExplicitContextTag5, IntegerAsn1, Optional,
            };
            use picky_krb::data_types::{Authenticator, AuthenticatorInner};
            let (cname_part, crealm_part) =
                client.split_once('@').unwrap_or((client, "EXAMPLE.COM"));
            let cname = krb_principal(1, &[cname_part.to_string()]);
            let crealm = krb_realm(crealm_part);
            let mut usec_bytes = usec.to_be_bytes().to_vec();
            while usec_bytes.len() > 1 && usec_bytes[0] == 0 {
                usec_bytes.remove(0);
            }
            if usec_bytes[0] & 0x80 != 0 {
                let mut prefixed = vec![0x00];
                prefixed.extend_from_slice(&usec_bytes);
                usec_bytes = prefixed;
            }
            let auth = Authenticator::from(AuthenticatorInner {
                authenticator_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5u8])),
                crealm: ExplicitContextTag1::from(crealm),
                cname: ExplicitContextTag2::from(cname),
                cksum: Optional::from(None),
                cusec: ExplicitContextTag4::from(IntegerAsn1::from(usec_bytes)),
                ctime: ExplicitContextTag5::from(krb_time(ts)),
                subkey: Optional::from(None),
                seq_number: Optional::from(None),
                authorization_data: Optional::from(None),
            });
            picky_asn1_der::to_vec(&auth).expect("encode Authenticator")
        }

        fn krb_principal_name(comps: &[String]) -> Vec<u8> {
            let mut strings = Vec::new();
            for c in comps {
                strings.extend_from_slice(&krb_general_string(c));
            }
            let seq = krb_seq(&strings);
            let mut content = Vec::new();
            content.extend_from_slice(&krb_ctx(0, &krb_u32(1)));
            content.extend_from_slice(&krb_ctx(1, &seq));
            krb_seq(&content)
        }

        fn krb_encrypted(cipher: &[u8]) -> Vec<u8> {
            let mut content = Vec::new();
            content.extend_from_slice(&krb_ctx(0, &krb_tlv(0x02, &[18])));
            content.extend_from_slice(&krb_ctx(2, &krb_octets(cipher)));
            krb_seq(&content)
        }

        fn krb_ticket(realm: &str, comps: &[String], cipher: &[u8]) -> Vec<u8> {
            let mut content = Vec::new();
            content.extend_from_slice(&krb_ctx(0, &krb_u32(5)));
            content.extend_from_slice(&krb_ctx(1, &krb_general_string(realm)));
            content.extend_from_slice(&krb_ctx(2, &krb_principal_name(comps)));
            content.extend_from_slice(&krb_ctx(3, &krb_encrypted(cipher)));
            krb_app(1, &krb_seq(&content))
        }

        fn krb_ap_req(ticket: &[u8], auth_cipher: &[u8]) -> Vec<u8> {
            let mut content = Vec::new();
            content.extend_from_slice(&krb_ctx(0, &krb_u32(5)));
            content.extend_from_slice(&krb_ctx(1, &krb_u32(14)));
            content.extend_from_slice(&krb_ctx(2, &krb_tlv(0x03, &[0x00])));
            let mut ticket_field = vec![0xA3];
            ticket_field.extend_from_slice(&krb_len(ticket.len()));
            ticket_field.extend_from_slice(ticket);
            content.extend_from_slice(&ticket_field);
            content.extend_from_slice(&krb_ctx(4, &krb_encrypted(auth_cipher)));
            krb_app(14, &krb_seq(&content))
        }

        fn krb_spnego(ap_req: &[u8]) -> Vec<u8> {
            let kerberos_oid = krb_oid(&[1, 2, 840, 113554, 1, 2, 2]);
            let mut mech_list = Vec::new();
            mech_list.extend_from_slice(&kerberos_oid);
            let mech_seq = krb_seq(&mech_list);
            let mut neg = Vec::new();
            neg.extend_from_slice(&krb_ctx(0, &mech_seq));
            neg.extend_from_slice(&krb_ctx(2, &krb_octets(ap_req)));
            let neg_seq = krb_seq(&neg);
            let spnego_oid = krb_oid(&[1, 3, 6, 1, 5, 5, 2]);
            let mut outer = Vec::new();
            outer.extend_from_slice(&spnego_oid);
            outer.extend_from_slice(&neg_seq);
            krb_app(0, &outer)
        }

        fn krb_now() -> i64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        }

        fn krb_random_key() -> [u8; 32] {
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            let mut key = [0u8; 32];
            rng.fill(&mut key).expect("system randomness");
            key
        }

        // Test KDC state: service key shared with the keytab file.
        let service_key = krb_random_key();
        let service_comps = vec!["mqtt".to_string(), "broker.example.com".to_string()];
        let dir = tempfile::tempdir().expect("temp dir");
        let keytab_path = dir.path().join("broker.keytab");
        {
            let mut file = vec![0x05u8, 0x02u8];
            let mut entry = Vec::new();
            entry.extend_from_slice(&2u16.to_be_bytes());
            entry.extend_from_slice(&(REALM.len() as u16).to_be_bytes());
            entry.extend_from_slice(REALM.as_bytes());
            for comp in &service_comps {
                entry.extend_from_slice(&(comp.len() as u16).to_be_bytes());
                entry.extend_from_slice(comp.as_bytes());
            }
            entry.extend_from_slice(&1u32.to_be_bytes());
            entry.extend_from_slice(&0u32.to_be_bytes());
            entry.push(1u8);
            entry.extend_from_slice(&18u16.to_be_bytes());
            entry.extend_from_slice(&32u16.to_be_bytes());
            entry.extend_from_slice(&service_key);
            entry.extend_from_slice(&1u32.to_be_bytes());
            file.extend_from_slice(&(entry.len() as i32).to_be_bytes());
            file.extend_from_slice(&entry);
            let mut handle = std::fs::File::create(&keytab_path).expect("write keytab");
            handle.write_all(&file).expect("write keytab");
        }
        let mint = |client: &str, start: i64, end: i64, ts: i64, usec: u32| {
            let session_key = krb_random_key();
            let inner = krb_ticket_inner(client, SERVICE_FULL, start, end, &session_key);
            let ticket_cipher = krb_cts_encrypt(&service_key, 2, &inner);
            let ticket = krb_ticket(REALM, &service_comps, &ticket_cipher);
            let auth_inner = krb_auth_inner(client, ts, usec);
            let auth_cipher = krb_cts_encrypt(&session_key, 11, &auth_inner);
            krb_ap_req(&ticket, &auth_cipher)
        };

        let kerberos_config = KerberosConfig {
            service_principal_name: SERVICE_FULL.to_string(),
            realm: REALM.to_string(),
            allowed_realms: vec![REALM.to_string()],
            keytab_path: keytab_path.to_string_lossy().to_string(),
            clock_skew_secs: 300,
            replay_max_entries: broker_auth::REPLAY_MAX_ENTRIES,
            principal_role_map: HashMap::from([(
                "alice@EXAMPLE.COM".to_string(),
                "publisher".to_string(),
            )]),
        };
        let mut shared = test_shared();
        shared.kerberos = Some(std::sync::Arc::new(KerberosAuthenticator::new(
            kerberos_config,
        )));
        assert!(
            shared.kerberos.as_ref().is_some_and(|k| k.is_enabled()),
            "test keytab must enable Kerberos"
        );
        shared
            .auth
            .add_user("local-user", b"localpw")
            .expect("seed local user");

        // Valid bare AP-REQ through the broker: accepted, principal stamped.
        let now = krb_now();
        let token = mint("alice@EXAMPLE.COM", now - 60, now + 3600, now, 21);
        let frame = bind_frame(
            91,
            1,
            encode_bind_meta_creds("krb-device-1", true, 60, "alice", &token),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0, "valid Kerberos ticket must be accepted");
        let session = shared.sessions.get("krb-device-1").expect("session exists");
        assert_eq!(
            session.username.read().clone(),
            Some("alice@EXAMPLE.COM".to_string()),
            "session must carry the verified principal"
        );
        // Role mapping through the broker (live, not store-only): the
        // broker's authenticator maps the verified principal onto its
        // configured role, and its config carries the map.
        let kerberos = shared.kerberos.as_ref().expect("kerberos enabled");
        assert_eq!(
            kerberos.role_for_principal("alice@EXAMPLE.COM"),
            "publisher"
        );
        assert_eq!(kerberos.role_for_principal("mallory@EXAMPLE.COM"), "user");
        assert_eq!(
            kerberos
                .config()
                .principal_role_map
                .get("alice@EXAMPLE.COM")
                .map(String::as_str),
            Some("publisher")
        );

        // Valid SPNEGO-wrapped AP-REQ: accepted.
        let token = krb_spnego(&mint("alice@EXAMPLE.COM", now - 60, now + 3600, now, 22));
        let frame = bind_frame(
            92,
            1,
            encode_bind_meta_creds("krb-device-2", true, 60, "alice", &token),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0, "valid SPNEGO ticket must be accepted");

        // Local users keep working with Kerberos enabled.
        let frame = bind_frame(
            93,
            1,
            encode_bind_meta_creds("local-device", true, 60, "local-user", b"localpw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0, "local users keep working with Kerberos enabled");

        // Expired ticket: refused with 0x86, no session.
        let token = mint("alice@EXAMPLE.COM", now - 7200, now - 3600, now - 3600, 23);
        let frame = bind_frame(
            94,
            1,
            encode_bind_meta_creds("krb-device-3", true, 60, "alice", &token),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "expired ticket must yield 0x86");
        assert!(shared.sessions.get("krb-device-3").is_none());

        // Ticket for another service: refused with 0x86.
        let other_key = krb_random_key();
        let other_inner = krb_ticket_inner(
            "alice@EXAMPLE.COM",
            "mqtt/other.example.com@EXAMPLE.COM",
            now - 60,
            now + 3600,
            &krb_random_key(),
        );
        let other_cipher = krb_cts_encrypt(&other_key, 2, &other_inner);
        let other_ticket = krb_ticket(
            REALM,
            &["mqtt".to_string(), "other.example.com".to_string()],
            &other_cipher,
        );
        // Authenticator for the other ticket (session key unknown to the
        // broker, but the outer service check already fails first).
        let dummy_session = krb_random_key();
        let dummy_auth = krb_cts_encrypt(
            &dummy_session,
            11,
            &krb_auth_inner("alice@EXAMPLE.COM", now, 24),
        );
        let other_token = krb_ap_req(&other_ticket, &dummy_auth);
        let frame = bind_frame(
            95,
            1,
            encode_bind_meta_creds("krb-device-4", true, 60, "alice", &other_token),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "wrong-service ticket must yield 0x86");

        // Replay: same token twice, second refused.
        let token = mint("alice@EXAMPLE.COM", now - 60, now + 3600, now, 25);
        let frame = bind_frame(
            96,
            1,
            encode_bind_meta_creds("krb-device-5", true, 60, "alice", &token),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0, "first presentation must succeed");
        let frame = bind_frame(
            97,
            1,
            encode_bind_meta_creds("krb-device-6", true, 60, "alice", &token),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "replayed token must yield 0x86");

        // Malformed token: refused with 0x86.
        let frame = bind_frame(
            98,
            1,
            encode_bind_meta_creds("krb-device-7", true, 60, "alice", b"not a token"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "malformed token must yield 0x86");

        // Old B1-01 bypasses still fail through the broker.
        let legacy = b"KRB5:operator@EXAMPLE.COM:mqtt/broker.example.com@EXAMPLE.COM:EXAMPLE.COM";
        let frame = bind_frame(
            99,
            1,
            encode_bind_meta_creds("krb-device-8", true, 60, "operator", legacy),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "legacy plaintext bypass must yield 0x86");
        let mut tagged = vec![0x6E, legacy.len() as u8];
        tagged.extend_from_slice(legacy);
        let frame = bind_frame(
            100,
            1,
            encode_bind_meta_creds("krb-device-9", true, 60, "operator", &tagged),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "legacy 0x6E bypass must yield 0x86");

        // Anonymous while Kerberos is enabled: refused with 0x87.
        let frame = bind_frame(101, 1, encode_bind_meta("krb-anon", true, 60));
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(
            rc, 0x87,
            "anonymous must be refused while Kerberos is enabled"
        );
    }

    #[tokio::test]
    async fn bind_quota_overage_returns_0x8b() {
        use broker_auth::UserQuotas;

        let shared = test_shared();
        shared
            .auth
            .add_user("capped-user", b"pw")
            .expect("memory-only persist cannot fail");
        assert!(shared
            .auth
            .set_quotas(
                "capped-user",
                UserQuotas {
                    max_connections: Some(1),
                    max_publish_rate: None,
                    max_publish_burst: None,
                }
            )
            .expect("memory-only persist cannot fail"));

        // First connection admitted.
        let frame = bind_frame(
            84,
            1,
            encode_bind_meta_creds("dev-one", true, 60, "capped-user", b"pw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);

        // Second concurrent connection for the same user: quota exceeded.
        let frame = bind_frame(
            85,
            1,
            encode_bind_meta_creds("dev-two", true, 60, "capped-user", b"pw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x8B, "overage must yield return code 0x8B");
        assert!(!present);
        assert!(shared.sessions.get("dev-two").is_none());

        // Takeover by the same client reuses its slot instead of denying.
        let frame = bind_frame(
            86,
            1,
            encode_bind_meta_creds("dev-one", true, 60, "capped-user", b"pw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);

        // The orphaned first connection detaching afterwards releases
        // nothing (ownership check): the retaken slot stays held.
        shared.sessions.unbind_connection("dev-one", 84);
        let frame = bind_frame(
            87,
            1,
            encode_bind_meta_creds("dev-three", true, 60, "capped-user", b"pw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x8B, "slot still held after orphan detach");
    }

    #[tokio::test]
    async fn publish_rate_overage_returns_0x97_and_drops() {
        use broker_auth::UserQuotas;

        let shared = test_shared();
        shared
            .auth
            .add_user("fast-user", b"pw")
            .expect("memory-only persist cannot fail");
        assert!(shared
            .auth
            .set_quotas(
                "fast-user",
                UserQuotas {
                    max_connections: None,
                    max_publish_rate: Some(2),
                    max_publish_burst: Some(2),
                }
            )
            .expect("memory-only persist cannot fail"));

        // Subscriber soaks up whatever routes (proves the drop below).
        let (listener, _) = shared.sessions.get_or_create("sink", true);
        *listener.conn_id.write() = Some(96);
        let sub = subscribe_frame(96, 1, encode_subscribe_meta(1, "sink", &[("t/rate", 0)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        // Publisher session owned by the capped user.
        let (publ, _) = shared.sessions.get_or_create("throttled", true);
        *publ.conn_id.write() = Some(97);
        *publ.username.write() = Some("fast-user".to_string());

        // Burst of 2 routes; the immediate third is over quota.
        for seq in 2..=3u64 {
            let (meta, payload) = encode_publish_meta("t/rate", seq as u16, 1, false, b"x");
            let (ack, deliveries) =
                apply_publish(&publish_frame(97, seq, meta, payload), &shared).await;
            assert!(ack.is_some());
            assert_eq!(deliveries.len(), 1, "burst publishes must route");
        }
        let (meta, payload) = encode_publish_meta("t/rate", 4, 1, false, b"x");
        let (ack, deliveries) = apply_publish(&publish_frame(97, 4, meta, payload), &shared).await;
        let ack = ack.expect("QoS 1 over-rate still gets a PubAck");
        assert_eq!(&ack.metadata[..], &[0x00, 0x04, 0x97u8]);
        assert!(deliveries.is_empty(), "over-rate publish must not fan out");

        // QoS 0 over-rate drops silently but counts.
        let (meta, payload) = encode_publish_meta("t/rate", 0, 0, false, b"x");
        let (ack, deliveries) = apply_publish(&publish_frame(97, 5, meta, payload), &shared).await;
        assert!(ack.is_none());
        assert!(deliveries.is_empty());
        // Both over-rate drops counted (QoS 1 above + this QoS 0).
        assert_eq!(shared.metrics.messages_dropped(), 2);
    }

    #[tokio::test]
    async fn subscribe_denied_yields_0x87_without_routing() {
        let shared = test_shared();
        shared
            .auth
            .add_rule(AclRule::new("boxed", AclAction::All, "#", false))
            .expect("memory-only persist cannot fail");

        let frame = subscribe_frame(91, 1, encode_subscribe_meta(1, "boxed", &[("t", 0)]));
        let (reply, retained) = apply_subscribe(&frame, &shared).await;
        let reply = reply.expect("suback replies");
        assert_eq!(&reply.metadata[2..], &[0x87u8]);
        assert!(retained.is_empty());
        // Denied subscriptions register nothing.
        assert!(shared.router.matches(&Topic::new("t").unwrap()).is_empty());
    }

    #[tokio::test]
    async fn publish_denied_yields_puback_0x87_and_drops() {
        let shared = test_shared();
        // A live listener proves the drop: it would receive otherwise.
        let (listener, _) = shared.sessions.get_or_create("listener", true);
        *listener.conn_id.write() = Some(93);
        let sub = subscribe_frame(93, 1, encode_subscribe_meta(1, "listener", &[("t", 0)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let (muted, _) = shared.sessions.get_or_create("muted", true);
        *muted.conn_id.write() = Some(92);
        shared
            .auth
            .add_rule(AclRule::new("muted", AclAction::Publish, "#", false))
            .expect("memory-only persist cannot fail");

        let (meta, payload) = encode_publish_meta("t", 5, 1, false, b"shh");
        let (ack, deliveries) = apply_publish(&publish_frame(92, 1, meta, payload), &shared).await;
        let ack = ack.expect("QoS 1 denied publish still gets a PubAck");
        assert_eq!(&ack.metadata[..], &[0x00, 0x05, 0x87u8]);
        assert!(deliveries.is_empty(), "denied publish must not fan out");
    }

    /// Test mirror of the edge peer-address section: append
    /// `PeerLen:16be | PeerIp` to an encoded bind.
    fn encode_bind_meta_peer(base: Bytes, peer: &str) -> Bytes {
        let mut meta = base.to_vec();
        meta.extend_from_slice(&(peer.len() as u16).to_be_bytes());
        meta.extend_from_slice(peer.as_bytes());
        Bytes::from(meta)
    }

    fn ban_entry(as_type: &str, who: &str, until: &str) -> broker_api::v5::banned::BanEntry {
        broker_api::v5::banned::BanEntry {
            as_type: as_type.to_string(),
            who: who.to_string(),
            by: "test".to_string(),
            reason: "test".to_string(),
            at: "2026-01-01T00:00:00+00:00".to_string(),
            until: until.to_string(),
        }
    }

    #[test]
    fn bind_meta_peer_section_round_trip() {
        // Credentials plus peer address decode together.
        let meta = encode_bind_meta_peer(
            encode_bind_meta_creds("dev-p", true, 60, "alice", b"pw"),
            "192.0.2.10",
        );
        let req = decode_bind_meta(&meta).expect("peer bind decodes");
        assert_eq!(req.client_id, "dev-p");
        assert_eq!(req.username.as_deref(), Some("alice"));
        assert_eq!(req.password, Some(b"pw".to_vec()));
        assert_eq!(req.peerhost.as_deref(), Some("192.0.2.10"));
        // Anonymous plus peer address decodes without credentials.
        let meta = encode_bind_meta_peer(encode_bind_meta("dev-a", false, 30), "2001:db8::1");
        let req = decode_bind_meta(&meta).expect("anonymous peer bind decodes");
        assert_eq!(req.client_id, "dev-a");
        assert!(req.username.is_none());
        assert_eq!(req.peerhost.as_deref(), Some("2001:db8::1"));
        // Legacy binds without a peer section still decode with no peer.
        let req = decode_bind_meta(&encode_bind_meta("dev-l", true, 60)).expect("legacy decodes");
        assert!(req.peerhost.is_none());
        let req = decode_bind_meta(&encode_bind_meta_creds("dev-c", true, 60, "u", b"p"))
            .expect("legacy creds decode");
        assert!(req.peerhost.is_none());
        // Trailing bytes that are neither credentials nor a peer address
        // stay malformed, exactly as before the peer section.
        let mut garbage = encode_bind_meta("dev-g", true, 60).to_vec();
        garbage.extend_from_slice(b"not-a-section");
        assert!(decode_bind_meta(&Bytes::from(garbage)).is_err());
    }

    #[tokio::test]
    async fn ban_refuses_banned_client_id_on_connect() {
        let shared = test_shared();
        shared
            .bans
            .insert(ban_entry("clientid", "banned-1", "infinity"))
            .expect("ban insert");

        let frame = bind_frame(91, 1, encode_bind_meta("banned-1", true, 60));
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x8A, "banned client id must yield return code 0x8A");
        assert!(!present);
        assert!(shared.sessions.get("banned-1").is_none());

        // An unbanned id still connects against the same store.
        let frame = bind_frame(92, 1, encode_bind_meta("fine-1", true, 60));
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);
    }

    #[tokio::test]
    async fn ban_refuses_banned_username_on_connect() {
        let shared = test_shared();
        shared
            .auth
            .add_user("banned-user", b"pw")
            .expect("memory-only persist cannot fail");
        shared
            .auth
            .add_user("fine-user", b"pw2")
            .expect("memory-only persist cannot fail");
        shared
            .bans
            .insert(ban_entry("username", "banned-user", "infinity"))
            .expect("ban insert");

        // Valid credentials do not save a banned username.
        let frame = bind_frame(
            91,
            1,
            encode_bind_meta_creds("dev-u", true, 60, "banned-user", b"pw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x8A, "banned username must yield return code 0x8A");
        assert!(!present);
        assert!(shared.sessions.get("dev-u").is_none());

        // The same client id under an unbanned username connects.
        let frame = bind_frame(
            92,
            1,
            encode_bind_meta_creds("dev-u", true, 60, "fine-user", b"pw2"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);
    }

    #[tokio::test]
    async fn ban_refuses_banned_peerhost_on_connect() {
        let shared = test_shared();
        shared
            .bans
            .insert(ban_entry("peerhost", "192.0.2.44", "infinity"))
            .expect("ban insert");
        shared
            .bans
            .insert(ban_entry("peerhost_net", "203.0.113.0/24", "infinity"))
            .expect("ban insert");

        // Exact address ban refuses.
        let meta = encode_bind_meta_peer(encode_bind_meta("ip-client", true, 60), "192.0.2.44");
        let reply = apply_bind(&bind_frame(91, 1, meta), &shared)
            .await
            .expect("bind replies");
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x8A, "banned peer address must yield return code 0x8A");
        assert!(!present);
        assert!(shared.sessions.get("ip-client").is_none());

        // CIDR ban refuses an address inside the network.
        let meta = encode_bind_meta_peer(encode_bind_meta("net-client", true, 60), "203.0.113.9");
        let reply = apply_bind(&bind_frame(92, 1, meta), &shared)
            .await
            .expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x8A, "CIDR-banned peer must yield return code 0x8A");

        // The same id from an unbanned address connects.
        let meta = encode_bind_meta_peer(encode_bind_meta("ip-client", true, 60), "192.0.2.45");
        let reply = apply_bind(&bind_frame(93, 1, meta), &shared)
            .await
            .expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);
    }

    #[tokio::test]
    async fn ban_mid_session_publish_is_refused() {
        let shared = test_shared();
        // A live listener proves the drop: it would receive otherwise.
        let (listener, _) = shared.sessions.get_or_create("ban-listener", true);
        *listener.conn_id.write() = Some(93);
        let sub = subscribe_frame(
            93,
            1,
            encode_subscribe_meta(1, "ban-listener", &[("t/ban", 0)]),
        );
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        // The publisher connects cleanly before any ban exists.
        let frame = bind_frame(92, 1, encode_bind_meta("ban-pub", true, 60));
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);

        // Served before the ban: QoS 1 ack 0 and one delivery.
        let (meta, payload) = encode_publish_meta("t/ban", 5, 1, false, b"before");
        let (ack, deliveries) = apply_publish(&publish_frame(92, 2, meta, payload), &shared).await;
        let ack = ack.expect("QoS 1 publish gets a PubAck");
        assert_eq!(&ack.metadata[..], &[0x00, 0x05, 0x00]);
        assert_eq!(deliveries.len(), 1);

        // The ban lands mid-session: the next publish is refused exactly
        // like an ACL denial (PubAck 0x87, no fan-out).
        shared
            .bans
            .insert(ban_entry("clientid", "ban-pub", "infinity"))
            .expect("ban insert");
        let (meta, payload) = encode_publish_meta("t/ban", 6, 1, false, b"after");
        let (ack, deliveries) = apply_publish(&publish_frame(92, 3, meta, payload), &shared).await;
        let ack = ack.expect("QoS 1 denied publish still gets a PubAck");
        assert_eq!(&ack.metadata[..], &[0x00, 0x06, 0x87]);
        assert!(deliveries.is_empty(), "banned publish must not fan out");
    }

    #[tokio::test]
    async fn expired_ban_refuses_nobody() {
        let shared = test_shared();
        let past = "2000-01-01T00:00:00+00:00";
        for (as_type, who) in [
            ("clientid", "old-id"),
            ("username", "old-user"),
            ("peerhost", "192.0.2.99"),
        ] {
            shared
                .bans
                .insert(ban_entry(as_type, who, past))
                .expect("ban insert");
        }

        // All three identities at once on one connect: still accepted.
        let meta = encode_bind_meta_peer(
            encode_bind_meta_creds("old-id", true, 60, "old-user", b"pw"),
            "192.0.2.99",
        );
        let reply = apply_bind(&bind_frame(91, 1, meta), &shared)
            .await
            .expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0, "expired bans must not refuse the connect");

        // And the publish is served, not refused.
        let (meta, payload) = encode_publish_meta("t/old", 7, 1, false, b"x");
        let (ack, _) = apply_publish(&publish_frame(91, 2, meta, payload), &shared).await;
        let ack = ack.expect("QoS 1 publish gets a PubAck");
        assert_eq!(&ack.metadata[..], &[0x00, 0x07, 0x00]);
    }

    #[tokio::test]
    async fn bind_auth_failure_over_tcp_returns_0x86() {
        let shared = Shared::new();
        shared
            .auth
            .add_user("alice", b"s3cret")
            .expect("memory-only persist cannot fail");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_connection(stream, shared).await.expect("handle");
        });

        // Wrong password over a real transport: 0x86, no session.
        let io = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let client = FramedTransport::new(io);
        client
            .send(bind_frame(
                84,
                1,
                encode_bind_meta_creds("dev-bad", true, 60, "alice", b"nope"),
            ))
            .await
            .expect("bind");
        let reply = client.recv().await.expect("recv binding");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86);
        assert!(!present);

        server.abort();
    }

    #[tokio::test]
    async fn shared_subscriptions_balance_across_workers() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..4 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        // Two workers share one group; one plain subscriber listens too.
        let worker_a = bind_client(addr, 711, "worker-a", true).await;
        worker_a
            .send(subscribe_frame(
                711,
                2,
                encode_subscribe_meta(1, "worker-a", &[("$share/pool/work/jobs", 0)]),
            ))
            .await
            .expect("subscribe a");
        assert_eq!(
            worker_a.recv().await.expect("suback a").header.opcode,
            OpCode::SubAckOut
        );

        let worker_b = bind_client(addr, 712, "worker-b", true).await;
        worker_b
            .send(subscribe_frame(
                712,
                2,
                encode_subscribe_meta(1, "worker-b", &[("$share/pool/work/jobs", 0)]),
            ))
            .await
            .expect("subscribe b");
        assert_eq!(
            worker_b.recv().await.expect("suback b").header.opcode,
            OpCode::SubAckOut
        );

        let plain = bind_client(addr, 713, "plain-c", true).await;
        plain
            .send(subscribe_frame(
                713,
                2,
                encode_subscribe_meta(1, "plain-c", &[("work/jobs", 0)]),
            ))
            .await
            .expect("subscribe c");
        assert_eq!(
            plain.recv().await.expect("suback c").header.opcode,
            OpCode::SubAckOut
        );

        // Publisher emits two jobs.
        let publ = bind_client(addr, 714, "producer", true).await;
        for (seq, job) in [(3u64, "job-1"), (4u64, "job-2")] {
            let (meta, payload) = encode_publish_meta("work/jobs", 0, 0, false, job.as_bytes());
            publ.send(publish_frame(714, seq, meta, payload))
                .await
                .expect("publish job");
        }

        // Deterministic round-robin (members sort by client id): job-1
        // goes to worker-a, job-2 to worker-b, exactly one each.
        let first_a = worker_a.recv().await.expect("worker-a delivery");
        assert_eq!(first_a.header.conn_id, 711);
        assert_eq!(first_a.payload, Bytes::from_static(b"job-1"));
        let first_b = worker_b.recv().await.expect("worker-b delivery");
        assert_eq!(first_b.header.conn_id, 712);
        assert_eq!(first_b.payload, Bytes::from_static(b"job-2"));
        for (worker, name) in [(&worker_a, "a"), (&worker_b, "b")] {
            let extra =
                tokio::time::timeout(std::time::Duration::from_millis(300), worker.recv()).await;
            assert!(extra.is_err(), "worker {name} must receive exactly one job");
        }

        // The plain subscriber still gets the full fan-out: both jobs.
        for expected in [b"job-1".as_slice(), b"job-2".as_slice()] {
            let got = plain.recv().await.expect("plain delivery");
            assert_eq!(got.header.conn_id, 713);
            assert_eq!(got.payload, Bytes::from(expected));
        }

        server.abort();
    }

    #[tokio::test]
    async fn rule_sql_forwards_to_http_webhook() {
        use broker_connectors::HttpWebhookSink;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Minimal HTTP capture endpoint over raw TCP (keeps broker-node
        // free of HTTP server deps): records one POST body, answers 200.
        let hook_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hook");
        let hook_port = hook_listener.local_addr().expect("addr").port();
        let captured: Arc<parking_lot::Mutex<Option<Vec<u8>>>> =
            Arc::new(parking_lot::Mutex::new(None));
        let captured_rx = captured.clone();
        let hook_task = tokio::spawn(async move {
            let (mut stream, _) = hook_listener.accept().await.expect("accept hook");
            let mut buf = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let n = stream.read(&mut chunk).await.expect("read head");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head_end = buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("request head")
                + 4;
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let mut content_length = 0usize;
            for line in head.lines() {
                if let Some((key, value)) = line.split_once(':') {
                    if key.trim().eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
            }
            while buf.len() < head_end + content_length {
                let mut chunk = [0u8; 1024];
                let n = stream.read(&mut chunk).await.expect("read body");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            *captured_rx.lock() = Some(buf[head_end..head_end + content_length].to_vec());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("write hook response");
        });

        let shared = Shared::new();
        // Rule projects telemetry and forwards to the webhook sink: no
        // MQTT subscribers are involved at all.
        let sink = Arc::new(HttpWebhookSink::new(
            format!("http://127.0.0.1:{hook_port}/hook"),
            reqwest::header::HeaderMap::new(),
            reqwest::Client::new(),
        ));
        shared.engine.connectors().register("webhook-1", sink);
        shared
            .engine
            .create_rule(
                "telemetry-webhook".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(r#"SELECT temperature FROM "sensors/+" WHERE temperature > 0"#.to_string()),
                true,
                vec![broker_rules::RuleAction::ForwardConnector {
                    connector_id: "webhook-1".to_string(),
                }],
            )
            .expect("rule creates");

        // Edge client publishes wide telemetry as conn 901.
        let bl_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let bl_addr = bl_listener.local_addr().expect("local addr");
        let edge_task = tokio::spawn(async move {
            let (stream, _) = bl_listener.accept().await.expect("accept");
            handle_connection(stream, shared).await.expect("handle");
        });
        let publ = bind_client(bl_addr, 901, "sensor-x", true).await;
        let raw = br#"{ "temperature": 85.0, "secret": "hide_me" }"#;
        let (meta, payload) = encode_publish_meta("sensors/kitchen", 0, 0, false, raw);
        publ.send(publish_frame(901, 2, meta, payload))
            .await
            .expect("publish");

        // The webhook receives exactly the projected JSON.
        tokio::time::timeout(std::time::Duration::from_secs(5), hook_task)
            .await
            .expect("webhook fired")
            .expect("hook task");
        let body = captured.lock().clone().expect("captured body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("webhook body is JSON");
        assert_eq!(json, serde_json::json!({ "temperature": 85.0 }));

        edge_task.abort();
    }

    /// Drive one delayed publish through `apply_publish` with a live
    /// mailbox registered, returning the immediate reply.
    async fn delayed_setup(
        shared: &Shared,
    ) -> (
        tokio::sync::mpsc::UnboundedReceiver<BrokerFrame>,
        Option<BrokerFrame>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        shared.conns.register(951, tx);
        // D1-02: label for per-client shed accounting; QoS 0 delayed
        // deliveries ride the bounded backlog, not the guaranteed mailbox.
        shared.conns.set_client_label(951, "delayed-sub");
        let (session, _) = shared.sessions.get_or_create("delayed-sub", true);
        *session.conn_id.write() = Some(951);
        let sub = subscribe_frame(
            951,
            1,
            encode_subscribe_meta(1, "delayed-sub", &[("alerts", 0)]),
        );
        let (reply, _) = apply_subscribe(&sub, shared).await;
        reply.expect("subscribe replies");
        // The single shared driver serves the wheel; without it nothing
        // fires (one task per node, never one task per message).
        shared.spawn_delayed_driver();
        let (meta, payload) = encode_publish_meta("$delayed/1/alerts", 0, 0, false, b"later");
        let ack = apply_publish(&publish_frame(952, 1, meta, payload), shared).await;
        (rx, ack.0)
    }

    #[tokio::test]
    async fn delayed_publish_defers_delivery_by_one_second() {
        let shared = test_shared();
        let start = std::time::Instant::now();
        let (mut rx, ack) = delayed_setup(&shared).await;
        // QoS 0: no ack, and crucially no immediate delivery on either
        // mailbox (guaranteed `rx` stays empty; bounded QoS 0 backlog
        // stays empty until the timer fires).
        assert!(ack.is_none());
        let early = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await;
        assert!(early.is_err(), "delayed message must not arrive early");
        assert_eq!(
            shared.conns.qos0_len(951),
            0,
            "bounded backlog must not hold the delayed frame early"
        );

        // ...but it arrives after the delay with the inner topic on the
        // bounded QoS 0 backlog (D1-02: QoS 0 no longer rides `rx`).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let routed = loop {
            if let Some(frame) = shared.conns.pop_qos0(951) {
                break frame;
            }
            if std::time::Instant::now() > deadline {
                panic!("delivery fires");
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert!(start.elapsed() >= std::time::Duration::from_millis(900));
        let (topic, _, _, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "alerts");
        assert_eq!(routed.payload, Bytes::from_static(b"later"));
        // Guaranteed mailbox never saw the QoS 0 frame.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn delayed_publish_rejects_garbage() {
        let shared = test_shared();
        // Non-numeric delay is not a delayed target at all: it publishes
        // literally (no subscribers exist for it here).
        let (meta, payload) = encode_publish_meta("$delayed/soon/t", 0, 0, false, b"x");
        let (ack, deliveries) = apply_publish(&publish_frame(953, 1, meta, payload), &shared).await;
        assert!(ack.is_none());
        assert!(deliveries.is_empty());

        // Absurd delays are dropped, not scheduled, and counted.
        let over_before = shared.delayed.dropped_over_limit();
        let (meta, payload) = encode_publish_meta("$delayed/99999999/t", 0, 0, false, b"x");
        let (ack, deliveries) = apply_publish(&publish_frame(953, 2, meta, payload), &shared).await;
        assert!(ack.is_none());
        assert!(deliveries.is_empty());
        assert_eq!(shared.delayed.dropped_over_limit(), over_before + 1);
        assert!(shared.delayed.is_empty());

        // An inner topic that is not a servable concrete topic is
        // dropped with a warning and a counter, never queued.
        let malformed_before = shared.delayed.dropped_malformed();
        let (meta, payload) = encode_publish_meta("$delayed/1/#/x", 0, 0, false, b"x");
        let (ack, deliveries) = apply_publish(&publish_frame(953, 3, meta, payload), &shared).await;
        assert!(ack.is_none());
        assert!(deliveries.is_empty());
        assert_eq!(shared.delayed.dropped_malformed(), malformed_before + 1);
        assert!(shared.delayed.is_empty());

        // Delayed markers are not subscribable.
        let sub = subscribe_frame(
            954,
            1,
            encode_subscribe_meta(1, "c", &[("$delayed/1/t", 0)]),
        );
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        let reply = reply.expect("suback replies");
        assert_eq!(&reply.metadata[2..], &[0x80u8]);
    }

    #[tokio::test]
    async fn delayed_publish_survives_restart_from_same_dir() {
        // Persistence lives behind the wheel in `<data-dir>/delayed.jsonl`
        // (written by `DelayedScheduler::persist_and_schedule` in
        // `delayed.rs`, consulted by `DelayedScheduler::load`): the
        // publish event drives the write, the boot path drives the
        // reload, and the driver delivers on schedule afterwards.
        let dir = unique_data_dir();
        std::fs::create_dir_all(&dir).expect("scratch data dir");
        let data_dir = dir.to_str().expect("temp path is UTF-8").to_string();

        // First incarnation: publish through the broker but never start
        // its driver, so the entry stays pending in the file.
        let pending = {
            let shared = test_shared();
            shared.delayed.set_persist_dir(&data_dir);
            assert_eq!(shared.delayed.load(), (0, 0, 0));
            let (meta, payload) =
                encode_publish_meta("$delayed/2/restart/alerts", 0, 0, false, b"restart-me");
            let (ack, deliveries) =
                apply_publish(&publish_frame(957, 1, meta, payload), &shared).await;
            assert!(ack.is_none());
            assert!(deliveries.is_empty());
            assert_eq!(shared.delayed.len(), 1);
            assert!(
                dir.join("delayed.jsonl").is_file(),
                "the publish event must persist before ack"
            );
            shared.delayed.scheduled_count()
        };
        assert_eq!(pending, 1);

        // Second incarnation from the same directory: reload, subscribe,
        // then deliver on schedule through the broker.
        let shared = test_shared();
        shared.delayed.set_persist_dir(&data_dir);
        let (loaded, torn, expired) = shared.delayed.load();
        assert_eq!(loaded, 1);
        assert_eq!((torn, expired), (0, 0));
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        shared.conns.register(958, tx);
        shared.conns.set_client_label(958, "restart-sub");
        let (session, _) = shared.sessions.get_or_create("restart-sub", true);
        *session.conn_id.write() = Some(958);
        let sub = subscribe_frame(
            958,
            1,
            encode_subscribe_meta(1, "restart-sub", &[("restart/alerts", 0)]),
        );
        apply_subscribe(&sub, &shared).await.0.expect("subscribe");
        shared.spawn_delayed_driver();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
        let routed = loop {
            if let Some(frame) = shared.conns.pop_qos0(958) {
                break frame;
            }
            if std::time::Instant::now() > deadline {
                panic!("restarted node must still deliver on schedule");
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        let (topic, _, _, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "restart/alerts");
        assert_eq!(routed.payload, Bytes::from_static(b"restart-me"));
        assert_eq!(shared.delayed.delivered_count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn delayed_publish_end_to_end_over_tcp() {
        let shared = Shared::new();
        shared.spawn_delayed_driver();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        let sub = bind_client(addr, 961, "patient", true).await;
        sub.send(subscribe_frame(
            961,
            2,
            encode_subscribe_meta(4, "patient", &[("alerts", 0)]),
        ))
        .await
        .expect("subscribe");
        assert_eq!(
            sub.recv().await.expect("suback").header.opcode,
            OpCode::SubAckOut
        );

        let publ = bind_client(addr, 962, "procrastinator", true).await;
        let start = std::time::Instant::now();
        let (meta, payload) = encode_publish_meta("$delayed/1/alerts", 0, 0, false, b"finally");
        publ.send(publish_frame(962, 2, meta, payload))
            .await
            .expect("publish delayed");

        let routed = sub.recv().await.expect("recv delayed");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert_eq!(routed.header.conn_id, 961);
        assert_eq!(routed.payload, Bytes::from_static(b"finally"));
        let (topic, _, _, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "alerts");
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(900),
            "delivery must honor the 1s delay"
        );

        server.abort();
    }

    #[tokio::test]
    async fn delayed_delivery_workload_timings() {
        use std::hint::black_box;
        use std::time::Instant;

        // B4-03 delayed-delivery workload before/after numbers (spec
        // Done-when bullet 5, RULEBOOK hot-path row): measured through the
        // broker publish event (`apply_publish`), not just the wheel.
        // BEFORE is the steady-state immediate publish-to-delivery loop
        // (no wheel lock, no file append, no fsync): its rate is the
        // pre-change baseline. AFTER is the delayed-schedule loop through
        // `$delayed` (one file_lock hold, one bounded append plus fsync,
        // two short wheel-lock holds, one payload copy). Both print
        // msgs/sec and avg ns/msg into the gate output with no threshold
        // assert; counts are CI sample sizes, not SLOs. On-time behaviour
        // (requested vs actual delay) and pending memory (wheel depth,
        // persisted file bytes) print alongside. Publish-path cost prose
        // lives in `delayed.rs`; this test is the measured numbers behind
        // it.
        let shared = test_shared();
        let (tx_base, _rx_base) = tokio::sync::mpsc::unbounded_channel();
        shared.conns.register(971, tx_base);
        shared.conns.set_client_label(971, "wload-base");
        let (session_base, _) = shared.sessions.get_or_create("wload-base", true);
        *session_base.conn_id.write() = Some(971);
        let sub = subscribe_frame(
            971,
            1,
            encode_subscribe_meta(1, "wload-base", &[("wload/base", 0)]),
        );
        apply_subscribe(&sub, &shared).await.0.expect("subscribe");

        // BEFORE: immediate publish-to-delivery, no delayed work.
        let steady_iters = 200usize;
        let steady_start = Instant::now();
        for i in 0..steady_iters {
            let (meta, payload) = encode_publish_meta("wload/base", 0, 0, false, b"x");
            let (_, deliveries) =
                apply_publish(&publish_frame(970, 1000 + i as u64, meta, payload), &shared).await;
            for (conn_id, frame) in deliveries {
                let _ = shared.conns.route(conn_id, frame);
            }
            let got = shared.conns.pop_qos0(971).expect("live downlink arrived");
            black_box(got);
        }
        let steady_elapsed = steady_start.elapsed();
        let steady_rate = steady_iters as f64 / steady_elapsed.as_secs_f64();
        let steady_avg_ns = steady_elapsed.as_nanos() as f64 / steady_iters as f64;
        println!(
            "delayed broker workload immediate baseline (before): {steady_rate:.0} msgs/sec, avg {steady_avg_ns:.1} ns/msg ({steady_iters} apply_publish rounds in {steady_elapsed:?})"
        );

        // AFTER: delayed schedule through the broker with persistence.
        let dir = unique_data_dir();
        std::fs::create_dir_all(&dir).expect("scratch data dir");
        let data_dir = dir.to_str().expect("temp path is UTF-8").to_string();
        shared.delayed.set_persist_dir(&data_dir);
        assert_eq!(shared.delayed.load(), (0, 0, 0));
        let payload_bytes = b"x".len();
        let delayed_iters = 200usize;
        let delayed_start = Instant::now();
        for i in 0..delayed_iters {
            let (meta, payload) =
                encode_publish_meta("$delayed/60/wload/delayed", 0, 0, false, b"x");
            let (ack, deliveries) =
                apply_publish(&publish_frame(970, 5000 + i as u64, meta, payload), &shared).await;
            black_box(ack);
            assert!(deliveries.is_empty(), "delayed schedule defers delivery");
        }
        let delayed_elapsed = delayed_start.elapsed();
        assert_eq!(shared.delayed.len(), delayed_iters);
        let delayed_rate = delayed_iters as f64 / delayed_elapsed.as_secs_f64();
        let delayed_avg_ns = delayed_elapsed.as_nanos() as f64 / delayed_iters as f64;
        let file_bytes = std::fs::metadata(dir.join("delayed.jsonl"))
            .map(|m| m.len())
            .unwrap_or(0);
        let estimated_payload_bytes = (delayed_iters * payload_bytes) as u64;
        println!(
            "delayed broker schedule workload (wheel plus file append, after): {delayed_rate:.0} msgs/sec, avg {delayed_avg_ns:.1} ns/msg ({delayed_iters} apply_publish rounds in {delayed_elapsed:?})"
        );
        println!(
            "delayed pending memory: wheel depth {delayed_iters} entries, persisted file {file_bytes} bytes, estimated payload {estimated_payload_bytes} bytes ({delayed_iters} entries)"
        );

        // On-time behaviour: short-delay batch through the broker driver.
        let otime = test_shared();
        let (tx_ot, _rx_ot) = tokio::sync::mpsc::unbounded_channel();
        otime.conns.register(972, tx_ot);
        otime.conns.set_client_label(972, "wload-ontime");
        let (session_ot, _) = otime.sessions.get_or_create("wload-ontime", true);
        *session_ot.conn_id.write() = Some(972);
        let sub = subscribe_frame(
            972,
            1,
            encode_subscribe_meta(1, "wload-ontime", &[("wload/ontime", 0)]),
        );
        apply_subscribe(&sub, &otime).await.0.expect("subscribe");
        otime.spawn_delayed_driver();
        let ontime_count = 5usize;
        let ontime_start = Instant::now();
        for i in 0..ontime_count {
            let (meta, payload) = encode_publish_meta("$delayed/1/wload/ontime", 0, 0, false, b"y");
            let (_, deliveries) =
                apply_publish(&publish_frame(973, 9000 + i as u64, meta, payload), &otime).await;
            assert!(deliveries.is_empty(), "delayed schedule defers delivery");
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
        let mut received = 0usize;
        while received < ontime_count {
            if otime.conns.pop_qos0(972).is_some() {
                received += 1;
                continue;
            }
            if std::time::Instant::now() > deadline {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let ontime_elapsed = ontime_start.elapsed();
        let ontime_ms = ontime_elapsed.as_millis() as u64;
        // Requested 1000 ms plus one 100 ms tick of firing slack: late
        // only past that window; early only before the delay.
        let ontime_ok = received == ontime_count && (900..=8_000).contains(&ontime_ms);
        println!(
            "delayed on-time delivery: {received}/{ontime_count} delivered in {ontime_elapsed:?} (requested 1000 ms, on_time={ontime_ok})"
        );
        assert_eq!(received, ontime_count, "short-delay batch must fire");
        assert!(
            ontime_ms >= 900,
            "delivery must honor the 1s delay (got {ontime_elapsed:?})"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn shared_wires_broker_sink_into_engine() {
        // INDRA-213: window-flush republish actions resolve through the
        // same in-memory sink as inline dispatch (no loopback).
        let shared = Shared::new();
        assert!(
            shared.engine.broker_sink().is_some(),
            "Shared::new must install the flush sink"
        );
    }

    #[tokio::test]
    async fn kernel_ingress_enforces_retainer_limits_like_mgmt() {
        // W1-28 parity: kernel ingress and management publishes share
        // the same retainer_config object, so configurable limits apply
        // on both paths. Oversized payloads deliver but are not stored;
        // new topics past the cap are dropped while replacements land.
        use axum::extract::State;
        let shared = Shared::new();
        let engine = std::sync::Arc::new(broker_rules::RuleEngine::new(
            16,
            broker_rules::BackpressurePolicy::DropOldest,
        ));
        let mut api_state = broker_api::ApiState::standalone(engine);
        api_state.retainer_config = shared.retainer_config.clone();
        api_state.retained = shared.retained.clone();
        api_state.stats = shared.stats.clone();
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "max_payload_size": "10B",
                "backend": {"max_retained_messages": 1},
            }))
            .expect("config is JSON"),
        );
        let resp =
            broker_api::v5::retainer::put_retainer_config(State(api_state.clone()), body).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        // Oversized retained publish is dropped from the store.
        let big_topic = broker_protocol::Topic::new("w128/limit/big").expect("topic");
        let big_payload = bytes::Bytes::from(vec![b'x'; 100]);
        ingress_pipeline(
            &shared,
            &big_topic,
            broker_protocol::QoS::AtMostOnce,
            true,
            &big_payload,
        )
        .await;
        let stored = shared
            .retained
            .get_retained(&big_topic)
            .await
            .expect("store reads");
        assert!(stored.is_none(), "oversized payload must not be stored");
        // Reset to a generous size, then exercise the topic cap.
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({"max_payload_size": "1MB"}))
                .expect("config is JSON"),
        );
        let resp =
            broker_api::v5::retainer::put_retainer_config(State(api_state.clone()), body).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let first = broker_protocol::Topic::new("w128/limit/first").expect("topic");
        ingress_pipeline(
            &shared,
            &first,
            broker_protocol::QoS::AtMostOnce,
            true,
            &bytes::Bytes::from_static(b"one"),
        )
        .await;
        assert!(shared
            .retained
            .get_retained(&first)
            .await
            .expect("read")
            .is_some());
        let second = broker_protocol::Topic::new("w128/limit/second").expect("topic");
        ingress_pipeline(
            &shared,
            &second,
            broker_protocol::QoS::AtMostOnce,
            true,
            &bytes::Bytes::from_static(b"two"),
        )
        .await;
        assert!(
            shared
                .retained
                .get_retained(&second)
                .await
                .expect("read")
                .is_none(),
            "new topic past the cap must be dropped"
        );
        // Replacements for an existing topic still land.
        ingress_pipeline(
            &shared,
            &first,
            broker_protocol::QoS::AtMostOnce,
            true,
            &bytes::Bytes::from_static(b"one-v2"),
        )
        .await;
        let replaced = shared
            .retained
            .get_retained(&first)
            .await
            .expect("read")
            .expect("exists");
        assert_eq!(replaced.payload, bytes::Bytes::from_static(b"one-v2"));
    }

    /// W1-39: a fresh bind receives the configured auto-subscriptions.
    /// Fails before the change (empty list, no hook) and passes after:
    /// write one entry via the management write, bind a new client, and
    /// expect the subscription present in both the session mirror and
    /// the router.
    #[tokio::test]
    async fn auto_subscribe_hook_subscribes_new_connection() {
        use axum::extract::State;
        let shared = test_shared();
        let engine = std::sync::Arc::new(broker_rules::RuleEngine::new(
            16,
            broker_rules::BackpressurePolicy::DropOldest,
        ));
        let mut api_state = broker_api::ApiState::standalone(engine);
        api_state.auto_subscribe = shared.auto_subscribe.clone();
        // Write one entry and read it back.
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!([
                {"topic": "conf/auto/w139-hook", "qos": 1},
            ]))
            .expect("config is JSON"),
        );
        let resp =
            broker_api::v5::auto_subscribe::put_auto_subscribe(State(api_state.clone()), body)
                .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(shared.auto_subscribe.list().len(), 1);

        // Fresh client binds successfully.
        let bind = bind_frame(501, 1, encode_bind_meta("w139-fresh", true, 60));
        let reply = apply_bind(&bind, &shared).await.expect("bind replies");
        assert!(is_binding_accepted(&reply));
        apply_auto_subscribe(&shared, "w139-fresh", None, 501);

        // Session mirror and router both hold the new subscription.
        let session = shared.sessions.get("w139-fresh").expect("session row");
        assert!(
            session
                .subscriptions
                .read()
                .keys()
                .any(|f| f.as_str() == "conf/auto/w139-hook"),
            "fresh client must carry the auto subscription"
        );
        assert_eq!(
            shared
                .router
                .matches(&Topic::new("conf/auto/w139-hook").unwrap())
                .len(),
            1
        );

        // Placeholder entries render per client.
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!([
                {"topic": "cmd/${clientid}/z", "qos": 0},
            ]))
            .expect("config is JSON"),
        );
        let resp =
            broker_api::v5::auto_subscribe::put_auto_subscribe(State(api_state.clone()), body)
                .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bind = bind_frame(502, 1, encode_bind_meta("w139-ph", true, 60));
        apply_bind(&bind, &shared).await.expect("bind replies");
        apply_auto_subscribe(&shared, "w139-ph", None, 502);
        assert!(
            shared
                .sessions
                .get("w139-ph")
                .expect("session row")
                .subscriptions
                .read()
                .keys()
                .any(|f| f.as_str() == "cmd/w139-ph/z"),
            "placeholder must render per client"
        );
    }

    fn qos2_frame(opcode: OpCode, conn_id: u64, seq: u64, packet_id: u16) -> BrokerFrame {
        BrokerFrame::new(
            opcode,
            conn_id,
            seq,
            Bytes::from(packet_id.to_be_bytes().to_vec()),
            Bytes::new(),
        )
        .expect("valid QoS 2 ack frame")
    }

    fn decode_qos2_id(meta: &[u8]) -> u16 {
        u16::from_be_bytes([meta[0], meta[1]])
    }

    /// D1-01 normal flow: PUBLISH QoS 2 stores and replies PUBREC with no
    /// routing; PUBREL routes once and replies PUBCOMP; the downlink runs
    /// PUBLISH/PUBREC/PUBREL/PUBCOMP to completion with the payload
    /// delivered exactly once.
    #[tokio::test]
    async fn qos2_normal_flow_routes_once_on_pubrel() {
        let shared = test_shared();
        let bind_sub = bind_frame(51, 1, encode_bind_meta("q2-sub", false, 60));
        reply_for_frame(&bind_sub, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(51, 2, encode_subscribe_meta(3, "q2-sub", &[("t", 2)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");
        let (session_sub, _) = shared.sessions.get_or_create("q2-sub", false);
        *session_sub.conn_id.write() = Some(51);
        let bind_pub = bind_frame(52, 1, encode_bind_meta("q2-pub", true, 60));
        reply_for_frame(&bind_pub, &shared.sessions).expect("bind replies");

        // Phase 1: PUBLISH QoS 2 stores, replies PUBREC, routes nothing.
        let (meta, payload) = encode_publish_meta("t", 7, 2, false, b"exactly-once");
        let (rec, deliveries) = apply_publish(&publish_frame(52, 8, meta, payload), &shared).await;
        let rec = rec.expect("QoS 2 PUBLISH needs PUBREC");
        assert_eq!(rec.header.opcode, OpCode::PubRecOut);
        assert_eq!(rec.header.conn_id, 52);
        assert_eq!(decode_qos2_id(&rec.metadata), 7);
        assert!(deliveries.is_empty(), "nothing routes before PUBREL");
        assert_eq!(
            shared
                .sessions
                .get("q2-pub")
                .expect("pub session")
                .qos2_inbound_len(),
            1
        );

        // Phase 2: PUBREL routes once and replies PUBCOMP.
        let (comp, deliveries) =
            apply_qos2_pubrel(&qos2_frame(OpCode::PubRelIn, 52, 9, 7), &shared).await;
        let comp = comp.expect("PUBREL needs PUBCOMP");
        assert_eq!(comp.header.opcode, OpCode::PubCompOut);
        assert_eq!(decode_qos2_id(&comp.metadata), 7);
        assert_eq!(deliveries.len(), 1, "PUBREL routes exactly once");
        assert_eq!(deliveries[0].0, 51);
        assert_eq!(deliveries[0].1.payload, Bytes::from_static(b"exactly-once"));
        let (topic, downlink_pid, qos, _) = decode_publish_meta_parts(&deliveries[0].1.metadata);
        assert_eq!(topic, "t");
        assert_eq!(qos, 2, "effective QoS is min(pub 2, sub 2)");
        assert_ne!(downlink_pid, 0);
        assert_eq!(
            shared
                .sessions
                .get("q2-pub")
                .expect("pub session")
                .qos2_inbound_len(),
            0,
            "packet id released on PUBREL"
        );

        // Outbound phase 1: subscriber PUBREC yields PUBREL.
        for (conn_id, frame) in deliveries {
            let _ = shared.conns.route(conn_id, frame);
        }
        let session = shared.sessions.get("q2-sub").expect("sub session");
        assert_eq!(session.qos2_outbound_len(), 1);
        let rel = apply_qos2_pubrec(&qos2_frame(OpCode::PubRecIn, 51, 10, downlink_pid), &shared)
            .expect("PUBREC needs PUBREL");
        assert_eq!(rel.header.opcode, OpCode::PubRelOut);
        assert_eq!(decode_qos2_id(&rel.metadata), downlink_pid);

        // Outbound phase 2: subscriber PUBCOMP releases the id.
        apply_qos2_pubcomp(
            &qos2_frame(OpCode::PubCompIn, 51, 11, downlink_pid),
            &shared,
        );
        assert_eq!(session.qos2_outbound_len(), 0);
    }

    /// D1-01 duplicate PUBLISH before PUBREL replies PUBREC without a
    /// second route; a second PUBREL after release completes empty.
    #[tokio::test]
    async fn qos2_duplicate_publish_before_pubrel_no_second_route() {
        let shared = test_shared();
        let bind_sub = bind_frame(51, 1, encode_bind_meta("q2-dup-sub", false, 60));
        reply_for_frame(&bind_sub, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(51, 2, encode_subscribe_meta(3, "q2-dup-sub", &[("t", 2)]));
        apply_subscribe(&sub, &shared)
            .await
            .0
            .expect("subscribe replies");
        let (session_sub, _) = shared.sessions.get_or_create("q2-dup-sub", false);
        *session_sub.conn_id.write() = Some(51);
        let bind_pub = bind_frame(52, 1, encode_bind_meta("q2-dup-pub", true, 60));
        reply_for_frame(&bind_pub, &shared.sessions).expect("bind replies");

        let (meta, payload) = encode_publish_meta("t", 9, 2, false, b"dup");
        let (first_rec, first_deliveries) =
            apply_publish(&publish_frame(52, 2, meta, payload), &shared).await;
        assert!(first_rec.is_some());
        assert!(first_deliveries.is_empty());
        // Repeat of the same packet id before PUBREL: duplicate.
        let (meta, payload) = encode_publish_meta("t", 9, 2, false, b"dup");
        let (second_rec, second_deliveries) =
            apply_publish(&publish_frame(52, 3, meta, payload), &shared).await;
        let second_rec = second_rec.expect("duplicate needs PUBREC again");
        assert_eq!(second_rec.header.opcode, OpCode::PubRecOut);
        assert!(
            second_deliveries.is_empty(),
            "duplicate must not route again"
        );

        // PUBREL routes exactly once; a retried PUBREL completes empty.
        let (_, deliveries) =
            apply_qos2_pubrel(&qos2_frame(OpCode::PubRelIn, 52, 4, 9), &shared).await;
        assert_eq!(deliveries.len(), 1);
        let (comp, redeliveries) =
            apply_qos2_pubrel(&qos2_frame(OpCode::PubRelIn, 52, 5, 9), &shared).await;
        assert!(comp.is_some(), "retried PUBREL still gets PUBCOMP");
        assert!(redeliveries.is_empty(), "retried PUBREL routes nothing");
    }

    /// D1-01 PUBREL for an unknown packet id replies PUBCOMP and routes
    /// nothing, so a retried PUBREL never stalls the publisher.
    #[tokio::test]
    async fn qos2_pubrel_unknown_id_replies_pubcomp_without_route() {
        let shared = test_shared();
        let bind = bind_frame(61, 1, encode_bind_meta("q2-unknown", true, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let (comp, deliveries) =
            apply_qos2_pubrel(&qos2_frame(OpCode::PubRelIn, 61, 2, 1234), &shared).await;
        let comp = comp.expect("unknown PUBREL needs PUBCOMP");
        assert_eq!(comp.header.opcode, OpCode::PubCompOut);
        assert_eq!(comp.header.conn_id, 61);
        assert_eq!(decode_qos2_id(&comp.metadata), 1234);
        assert!(deliveries.is_empty());
        assert_eq!(decode_qos2_meta(&comp.metadata), Some(1234));
    }

    /// D1-01 resend after reconnect: uncompleted QoS 2 downlinks replay in
    /// queued order (PUBLISH with DUP while waiting PUBREC, PUBREL while
    /// waiting PUBCOMP).
    #[tokio::test]
    async fn qos2_uncompleted_downlink_resends_after_reconnect() {
        let shared = test_shared();
        let bind = bind_frame(61, 1, encode_bind_meta("q2-replay", false, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(61, 2, encode_subscribe_meta(5, "q2-replay", &[("t", 2)]));
        apply_subscribe(&sub, &shared)
            .await
            .0
            .expect("subscribe replies");

        let (tx61, mut rx61) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(61, tx61);
        let bind_pub = bind_frame(62, 1, encode_bind_meta("q2-replay-pub", true, 60));
        reply_for_frame(&bind_pub, &shared.sessions).expect("pub bind replies");
        let (meta, payload) = encode_publish_meta("t", 7, 2, false, b"replay-me");
        let (_, deliveries) = apply_publish(&publish_frame(62, 3, meta, payload), &shared).await;
        // First phase alone routes nothing: complete it via PUBREL.
        assert!(deliveries.is_empty());
        let (_, deliveries) =
            apply_qos2_pubrel(&qos2_frame(OpCode::PubRelIn, 62, 4, 7), &shared).await;
        assert_eq!(deliveries.len(), 1);
        for (conn_id, frame) in deliveries {
            let _ = shared.conns.route(conn_id, frame);
        }
        let first = rx61.try_recv().expect("downlink arrived");
        let (_, first_pid, qos, _) = decode_publish_meta_parts(&first.metadata);
        assert_eq!(qos, 2);
        assert!(!decode_publish_dup(&first.metadata));

        // Detach without completing, reconnect: PUBLISH replays with DUP.
        let session = shared.sessions.get("q2-replay").expect("session known");
        *session.conn_id.write() = Some(61);
        apply_unbind(&unbind_frame(61, 5, "q2-replay"), &shared);
        let rebind = bind_frame(63, 1, encode_bind_meta("q2-replay", false, 60));
        reply_for_frame(&rebind, &shared.sessions).expect("rebind replies");
        let (tx63, mut rx63) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(63, tx63);
        assert_eq!(replay_offline(&rebind, &shared).await, 1);
        let replayed = rx63.try_recv().expect("PUBLISH replay arrived");
        assert_eq!(replayed.header.opcode, OpCode::PublishOut);
        assert!(decode_publish_dup(&replayed.metadata));
        let (_, replay_pid, _, _) = decode_publish_meta_parts(&replayed.metadata);
        assert_eq!(replay_pid, first_pid);

        // Subscriber answers PUBREC: the entry now waits for PUBCOMP.
        let rel = apply_qos2_pubrec(&qos2_frame(OpCode::PubRecIn, 63, 2, first_pid), &shared)
            .expect("PUBREC needs PUBREL");
        assert_eq!(rel.header.opcode, OpCode::PubRelOut);
        // Detach again before PUBCOMP, reconnect: PUBREL replays.
        apply_unbind(&unbind_frame(63, 3, "q2-replay"), &shared);
        let rebind2 = bind_frame(64, 1, encode_bind_meta("q2-replay", false, 60));
        reply_for_frame(&rebind2, &shared.sessions).expect("rebind replies");
        let (tx64, mut rx64) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(64, tx64);
        assert_eq!(replay_offline(&rebind2, &shared).await, 1);
        let rel_replay = rx64.try_recv().expect("PUBREL replay arrived");
        assert_eq!(rel_replay.header.opcode, OpCode::PubRelOut);
        assert_eq!(decode_qos2_id(&rel_replay.metadata), first_pid);

        // PUBCOMP completes: a further reconnect replays nothing.
        apply_qos2_pubcomp(&qos2_frame(OpCode::PubCompIn, 64, 4, first_pid), &shared);
        assert_eq!(session.qos2_outbound_len(), 0);
        apply_unbind(&unbind_frame(64, 5, "q2-replay"), &shared);
        let rebind3 = bind_frame(65, 1, encode_bind_meta("q2-replay", false, 60));
        reply_for_frame(&rebind3, &shared.sessions).expect("rebind replies");
        let (tx65, mut rx65) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(65, tx65);
        assert_eq!(replay_offline(&rebind3, &shared).await, 0);
        assert!(rx65.try_recv().is_err());
    }

    /// D1-01 integration: a QoS 2 publish to a QoS 2 subscriber arrives
    /// exactly once end to end, even when the publisher repeats PUBLISH
    /// before PUBREL.
    #[tokio::test]
    async fn qos2_end_to_end_exactly_once() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        let sub_io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect sub");
        let sub = FramedTransport::new(sub_io);
        sub.send(bind_frame(
            101,
            1,
            encode_bind_meta("q2-e2e-sub", false, 60),
        ))
        .await
        .expect("bind");
        let _ = sub.recv().await.expect("recv binding");
        sub.send(subscribe_frame(
            101,
            2,
            encode_subscribe_meta(11, "q2-e2e-sub", &[("q2/e2e", 2)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);

        let pub_io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect pub");
        let publ = FramedTransport::new(pub_io);
        publ.send(bind_frame(102, 1, encode_bind_meta("q2-e2e-pub", true, 60)))
            .await
            .expect("bind");
        let _ = publ.recv().await.expect("recv binding");

        // PUBLISH QoS 2, duplicated before PUBREL: both get PUBREC.
        let (meta, payload) = encode_publish_meta("q2/e2e", 77, 2, false, b"once");
        publ.send(publish_frame(102, 2, meta, payload))
            .await
            .expect("publish");
        let rec1 = publ.recv().await.expect("recv pubrec");
        assert_eq!(rec1.header.opcode, OpCode::PubRecOut);
        assert_eq!(decode_qos2_id(&rec1.metadata), 77);
        let (meta, payload) = encode_publish_meta("q2/e2e", 77, 2, false, b"once");
        publ.send(publish_frame(102, 3, meta, payload))
            .await
            .expect("duplicate");
        let rec2 = publ.recv().await.expect("recv second pubrec");
        assert_eq!(rec2.header.opcode, OpCode::PubRecOut);

        // PUBREL completes the inbound flow.
        publ.send(qos2_frame(OpCode::PubRelIn, 102, 4, 77))
            .await
            .expect("pubrel");
        let comp = publ.recv().await.expect("recv pubcomp");
        assert_eq!(comp.header.opcode, OpCode::PubCompOut);
        assert_eq!(decode_qos2_id(&comp.metadata), 77);

        // Subscriber gets exactly one PUBLISH QoS 2.
        let routed = sub.recv().await.expect("recv publish");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert_eq!(routed.payload, Bytes::from_static(b"once"));
        let (_, downlink_pid, qos, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(qos, 2);
        assert_ne!(downlink_pid, 0);

        // Outbound flow to completion.
        sub.send(qos2_frame(OpCode::PubRecIn, 101, 3, downlink_pid))
            .await
            .expect("pubrec");
        let rel = sub.recv().await.expect("recv pubrel");
        assert_eq!(rel.header.opcode, OpCode::PubRelOut);
        sub.send(qos2_frame(OpCode::PubCompIn, 101, 4, downlink_pid))
            .await
            .expect("pubcomp");

        // No second delivery: the duplicate PUBLISH routed only once.
        let nothing = tokio::time::timeout(std::time::Duration::from_millis(300), sub.recv()).await;
        assert!(nothing.is_err(), "exactly-once: no second delivery");

        server.abort();
    }

    /// D1-02: the bounded QoS 0 backlog drops oldest-first, counts every
    /// drop labelled by client, and keeps a fast subscriber whole while
    /// a stalled one sheds. Drives the real `apply_publish` fan-out plus
    /// `ConnTable::route` (the production egress path), not a test-only
    /// queue.
    #[tokio::test]
    async fn qos0_bounded_backlog_sheds_oldest_fast_keeps_receiving() {
        let shared = test_shared();
        shared.conns.set_qos0_bound(3);

        for (conn, client) in [(61u64, "q0-fast"), (63u64, "q0-stalled")] {
            let frame = subscribe_frame(conn, 1, encode_subscribe_meta(1, client, &[("q0/t", 0)]));
            let (reply, _) = apply_subscribe(&frame, &shared).await;
            reply.expect("subscribe replies");
            let (session, _) = shared.sessions.get_or_create(client, true);
            *session.conn_id.write() = Some(conn);
            let (tx, _rx) = unbounded_channel::<BrokerFrame>();
            shared.conns.register(conn, tx);
            shared.conns.set_client_label(conn, client);
        }

        let mut fast_got: Vec<Vec<u8>> = Vec::new();
        for i in 0..6u8 {
            let (meta, payload) =
                encode_publish_meta("q0/t", 0, 0, false, std::slice::from_ref(&i));
            let (_, deliveries) =
                apply_publish(&publish_frame(99, u64::from(i), meta, payload), &shared).await;
            assert_eq!(deliveries.len(), 2, "both subscribers match every publish");
            for (conn_id, frame) in deliveries {
                assert!(shared.conns.route(conn_id, frame));
            }
            // Fast drains immediately; stalled never drains until the end.
            for frame in shared.conns.drain_qos0(61, 8) {
                fast_got.push(frame.payload.to_vec());
            }
        }
        for frame in shared.conns.drain_qos0(61, 8) {
            fast_got.push(frame.payload.to_vec());
        }
        assert_eq!(
            fast_got,
            vec![vec![0], vec![1], vec![2], vec![3], vec![4], vec![5]],
            "fast subscriber sees every QoS 0 publish in order"
        );
        assert_eq!(shared.conns.qos0_len(61), 0);
        assert_eq!(shared.conns.qos0_len(63), 3);
        let stalled: Vec<Vec<u8>> = shared
            .conns
            .drain_qos0(63, 8)
            .iter()
            .map(|f| f.payload.to_vec())
            .collect();
        assert_eq!(
            stalled,
            vec![vec![3], vec![4], vec![5]],
            "stalled keeps newest, oldest shed"
        );
        assert_eq!(shared.metrics.egress_qos0_shed(), 3);
        assert_eq!(shared.metrics.egress_qos0_shed_for("q0-stalled"), 3);
        assert_eq!(shared.metrics.egress_qos0_shed_for("q0-fast"), 0);
    }

    /// D1-02: publishers never block on a stalled subscriber. Ten
    /// thousand synchronous QoS 0 publishes to a never-drained backlog
    /// complete (each `route` returns true immediately) and the backlog
    /// stays at its bound; the shed counter accounts for the rest.
    #[tokio::test]
    async fn qos0_stalled_subscriber_never_blocks_publisher() {
        let shared = test_shared();
        shared.conns.set_qos0_bound(8);
        let frame = subscribe_frame(61, 1, encode_subscribe_meta(1, "q0-block", &[("q0/b", 0)]));
        let (reply, _) = apply_subscribe(&frame, &shared).await;
        reply.expect("subscribe replies");
        let (session, _) = shared.sessions.get_or_create("q0-block", true);
        *session.conn_id.write() = Some(61);
        let (tx, _rx) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(61, tx);
        shared.conns.set_client_label(61, "q0-block");

        for i in 0..10_000u32 {
            let (meta, payload) = encode_publish_meta("q0/b", 0, 0, false, &[(i % 251) as u8]);
            let (_, deliveries) = apply_publish(
                &publish_frame(99, u64::from(i % 10_000), meta, payload),
                &shared,
            )
            .await;
            assert_eq!(deliveries.len(), 1);
            for (conn_id, frame) in deliveries {
                assert!(shared.conns.route(conn_id, frame));
            }
        }
        assert_eq!(shared.conns.qos0_len(61), 8);
        assert_eq!(shared.metrics.egress_qos0_shed(), 10_000 - 8);
        assert_eq!(shared.metrics.egress_qos0_shed_for("q0-block"), 10_000 - 8);
    }

    /// D1-02: QoS 1 keeps its delivery guarantee under QoS 0 pressure.
    /// Filling a subscriber's QoS 0 backlog must not drop, delay, or
    /// recount its QoS 1 downlink (shared egress path, separate queues).
    #[tokio::test]
    async fn qos1_keeps_guarantee_under_qos0_pressure() {
        let shared = test_shared();
        shared.conns.set_qos0_bound(2);
        let sub0 = subscribe_frame(
            61,
            1,
            encode_subscribe_meta(1, "q01-mixed", &[("q01/t", 0)]),
        );
        let (reply, _) = apply_subscribe(&sub0, &shared).await;
        reply.expect("subscribe replies");
        let sub1 = subscribe_frame(
            61,
            2,
            encode_subscribe_meta(2, "q01-mixed", &[("q01/q1", 1)]),
        );
        let (reply, _) = apply_subscribe(&sub1, &shared).await;
        reply.expect("subscribe replies");
        let (session, _) = shared.sessions.get_or_create("q01-mixed", true);
        *session.conn_id.write() = Some(61);
        let (tx, mut rx) = unbounded_channel::<BrokerFrame>();
        shared.conns.register(61, tx);
        shared.conns.set_client_label(61, "q01-mixed");

        for i in 0..4u8 {
            let (meta, payload) =
                encode_publish_meta("q01/t", 0, 0, false, std::slice::from_ref(&i));
            let (_, deliveries) =
                apply_publish(&publish_frame(99, u64::from(i), meta, payload), &shared).await;
            for (conn_id, frame) in deliveries {
                assert!(shared.conns.route(conn_id, frame));
            }
        }
        let shed_before = shared.metrics.egress_qos0_shed();
        assert_eq!(shed_before, 2);
        assert_eq!(shared.conns.qos0_len(61), 2);

        let (meta, payload) = encode_publish_meta("q01/q1", 41, 1, false, b"keep");
        let (ack, deliveries) = apply_publish(&publish_frame(99, 50, meta, payload), &shared).await;
        assert!(ack.is_some(), "QoS 1 publisher is acked");
        assert_eq!(deliveries.len(), 1);
        for (conn_id, frame) in deliveries {
            assert!(shared.conns.route(conn_id, frame));
        }
        assert_eq!(
            shared.conns.qos0_len(61),
            2,
            "QoS 1 must not disturb the QoS 0 backlog"
        );
        assert_eq!(
            shared.metrics.egress_qos0_shed(),
            shed_before,
            "QoS 1 must not shed"
        );
        let qos1 = rx.try_recv().expect("QoS 1 via guaranteed mailbox");
        assert_eq!(qos1.payload, Bytes::from_static(b"keep"));
        assert_eq!(session.inflight_len(), 1, "QoS 1 tracked for redelivery");
    }

    /// B1-04: a CoAP publish through the gateway reaches an ordinary MQTT
    /// subscriber through the same router path an MQTT publish takes.
    ///
    /// Drives the real gateway entry point (`apply_coap_publish`:
    /// retained store plus `ingress_pipeline` plus cluster forward) and
    /// asserts the router delivers to a session bound via the normal
    /// `apply_subscribe` path. Fails before the wiring (no gateway
    /// ingress reaches the router); passes after it.
    #[tokio::test]
    async fn coap_publish_reaches_mqtt_subscriber() {
        let shared = test_shared();
        // Ordinary MQTT subscriber on the gateway topic.
        let sub = subscribe_frame(
            71,
            1,
            encode_subscribe_meta(1, "mqtt-sub-1", &[("coap/sensors/temp", 0)]),
        );
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");
        let (session, _) = shared.sessions.get_or_create("mqtt-sub-1", true);
        *session.conn_id.write() = Some(71);
        *session.connected.write() = true;

        // CoAP gateway ingress: POST /ps/coap/sensors/temp.
        let payload = Bytes::from_static(b"21.5");
        let deliveries = apply_coap_publish(&shared, "coap/sensors/temp", &payload)
            .await
            .expect("valid CoAP topic routes");
        assert_eq!(deliveries.len(), 1, "one MQTT subscriber must match");
        assert_eq!(deliveries[0].0, 71);
        assert_eq!(deliveries[0].1.payload, payload);
        let (topic, _, _, _) = decode_publish_meta_parts(&deliveries[0].1.metadata);
        assert_eq!(topic, "coap/sensors/temp");

        // Retained so a later CoAP GET reads the same value.
        let stored = shared
            .retained
            .get_retained(&Topic::new("coap/sensors/temp").unwrap())
            .await
            .expect("retained read")
            .expect("CoAP publish is retained");
        assert_eq!(stored.payload, payload);

        // Malformed CoAP topics route nothing.
        assert!(apply_coap_publish(&shared, "coap/#/bad", &payload)
            .await
            .is_none());
        assert!(apply_coap_publish(&shared, "", &payload).await.is_none());
    }

    /// B1-04: an ordinary MQTT publish notifies a registered CoAP
    /// observer over UDP.
    ///
    /// Registers one bounded observer, publishes through the real MQTT
    /// ingress (`apply_publish` -> `ingress_pipeline` -> notify hook),
    /// and asserts the observer socket receives a CONTENT notification
    /// carrying the Observe option and the published payload. Fails
    /// before the hook (no UDP leaves the broker); passes after it.
    #[tokio::test]
    async fn mqtt_publish_notifies_coap_observer_over_udp() {
        let mut shared = test_shared();
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind gateway socket");
        let server = Arc::new(server);
        shared.coap_socket = Some(server.clone());

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind observer socket");
        let client_addr = client.local_addr().expect("observer addr");
        let token = Bytes::from_static(b"ntfy");
        assert!(shared
            .coap
            .register_observer("notify/topic", client_addr, token.clone()));
        assert!(shared.coap.has_observers());

        // Ordinary MQTT publish on the observed topic.
        let (meta, payload) = encode_publish_meta("notify/topic", 7, 0, false, b"hello-udp");
        let (_, deliveries) = apply_publish(&publish_frame(90, 1, meta, payload), &shared).await;
        let _ = deliveries;

        // The notify hook spawns the UDP send off the hot path: wait for it.
        let mut buf = [0u8; 2048];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("observer notified within timeout")
        .expect("udp recv");
        let notify = broker_gateway::coap::CoapMessage::decode(&buf[..len]).expect("decode notify");
        assert_eq!(notify.code, broker_gateway::coap::CoapCode::CONTENT);
        assert_eq!(notify.token, token);
        assert_eq!(notify.payload, Bytes::from_static(b"hello-udp"));
        assert!(
            notify
                .options
                .iter()
                .any(|o| o.number == broker_gateway::coap::option_number::OBSERVE),
            "notification must carry the Observe option"
        );
    }

    /// B1-07: a publish through the real broker ingress lands in the
    /// durable stream journal without blocking delivery.
    ///
    /// Attaches a journal backed by a scratch directory, publishes via
    /// `ingress_pipeline` (the same path MQTT and CoAP publishes take),
    /// and asserts the background writer persisted the record at offset 0
    /// with the right payload. Fails when the store is never wired in
    /// (nothing to read back); passes once the hook enqueues off the hot
    /// path. Also asserts a restart of the store from the same directory
    /// still serves the journalled record.
    #[tokio::test]
    async fn publish_is_journalled_to_durable_stream_off_hot_path() {
        let dir = {
            static SLOT: AtomicU64 = AtomicU64::new(0);
            let slot = SLOT.fetch_add(1, Ordering::SeqCst);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            std::env::temp_dir().join(format!(
                "indramqtt-stream-journal-{}-{nanos}-{slot}",
                std::process::id()
            ))
        };
        let mut shared = Shared::new();
        let journal =
            StreamJournalHandle::open(&dir, StreamConfig::default()).expect("open journal");
        let store = journal.store.clone();
        shared.stream_journal = Some(journal.clone());

        // Real broker ingress, not a direct store call.
        let topic = Topic::new("journal/probe").unwrap();
        let payload = Bytes::from_static(b"journalled-bytes");
        let deliveries = ingress_pipeline(&shared, &topic, QoS::AtLeastOnce, false, &payload).await;
        let _ = deliveries;

        // The publish path never blocks: it only enqueued. The background
        // task persists within milliseconds; poll for it.
        let mut seen = None;
        for _ in 0..100 {
            if store.stream_len("journal/probe") >= 1 {
                seen = Some(store.seek_offset("journal/probe", 0, 1).expect("seek"));
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let records = seen.expect("background journal persists within timeout");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].offset, 0);
        assert_eq!(records[0].payload, Bytes::from_static(b"journalled-bytes"));
        assert_eq!(records[0].topic.as_str(), "journal/probe");
        assert_eq!(journal.dropped_count(), 0);

        // Restarting the store from the same directory keeps the record.
        drop(store);
        drop(journal);
        // Give the background task a moment to exit with its sender.
        tokio::task::yield_now().await;
        let reopened =
            DurableStreamStore::open_with_config(&dir, StreamConfig::default()).expect("reopen");
        assert_eq!(reopened.stream_len("journal/probe"), 1);
        assert_eq!(
            reopened
                .get("journal/probe", 0)
                .expect("replayed after restart")
                .payload,
            Bytes::from_static(b"journalled-bytes")
        );
        std::fs::remove_dir_all(&dir).ok();
    }
    #[test]
    fn b2_04_mqtt_serves_in_trial_grace_and_lapsed() {
        // MQTT connect, publish and subscribe keep working with no
        // licence (trial), with a licence in grace, and with a lapsed
        // licence: only enterprise entitlements turn off, never traffic.
        use broker_cluster::InstallationState;
        let now = 1_750_000_000u64;
        let states = vec![
            InstallationState::Trial { days_remaining: 90 },
            InstallationState::Grace {
                customer: "Acme".to_string(),
                expires_at: now - 1_000,
                days_remaining: 80,
                grace_total_days: 90,
                max_nodes: 5,
                features: vec!["clustering".to_string()],
                kid: "key-a".to_string(),
            },
            InstallationState::Lapsed {
                reason: "trial ended".to_string(),
            },
        ];
        for state in &states {
            let sessions = SessionManager::new();
            let router = Router::new();
            let metrics = Metrics::new();
            let frame = bind_frame(11, 1, encode_bind_meta("device-b204", true, 60));
            let reply = reply_for_frame(&frame, &sessions).expect("bind replies");
            let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
            assert_eq!(rc, 0, "connect works in state {}", state.name());
            let filter = TopicFilter::new("sensors/b204").unwrap();
            router.subscribe(
                &filter,
                Subscription::new("device-b204", 77, QoS::AtLeastOnce),
            );
            let topic = Topic::new("sensors/b204").unwrap();
            let deliveries = build_downlink_frames(
                &router,
                &sessions,
                &metrics,
                &topic,
                QoS::AtLeastOnce,
                false,
                &Bytes::from_static(b"hello"),
            );
            assert!(
                !deliveries.is_empty(),
                "publish/subscribe work in state {}",
                state.name()
            );
            assert_eq!(state.entitlements_on(), state.name() != "lapsed");
        }
    }

    #[test]
    fn b2_04_ceiling_refusal_raises_alarm_and_names_ceiling() {
        // A node joining beyond the licensed ceiling is refused membership
        // with a reason naming the ceiling and the current count, raises an
        // alarm, and keeps serving MQTT standalone (refused from the
        // cluster, not stopped as a broker).
        let shared = test_shared();
        let now = 1_750_000_000u64;
        let state = InstallationState::Valid {
            customer: "Acme".to_string(),
            expires_at: now + 10_000_000,
            max_nodes: 1,
            features: vec!["clustering".to_string()],
            kid: "key-a".to_string(),
            days_remaining: 100,
        };
        let err = broker_cluster::join_admission(2, &state).expect_err("beyond ceiling refused");
        assert!(err.contains('1'), "reason names the ceiling: {err}");
        assert!(err.contains('2'), "reason names the current count: {err}");
        shared.licence.note_ceiling_refusal(&shared.alarms, &err);
        let active = shared.alarms.list_active();
        assert!(
            active.iter().any(|a| a.name == "licence_node_ceiling"),
            "ceiling refusal raises an alarm"
        );
    }

    #[test]
    fn b2_04_restart_keeps_identity_and_trial() {
        // Restarting a node inside a trial does not restart the trial: the
        // identity (with its recorded trial start) survives the restart.
        let dir = unique_data_dir();
        let data_dir = dir.to_str().expect("temp path is UTF-8").to_string();
        let start = 1_750_000_000u64;
        let first =
            broker_cluster::ClusterIdentity::load_or_create(std::path::Path::new(&data_dir), start)
                .expect("create identity");
        let mid = start + 10 * 86_400;
        let reloaded =
            broker_cluster::ClusterIdentity::load_or_create(std::path::Path::new(&data_dir), mid)
                .expect("reload identity");
        assert_eq!(reloaded.identity, first.identity);
        assert_eq!(reloaded.trial_started_at, first.trial_started_at);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn b2_04_unlicensed_node_generates_request() {
        // A fresh installation with no licence is in trial and can
        // generate a licence request: the bootstrap never deadlocks.
        let shared = test_shared();
        let now = 1_750_000_000u64;
        let dir = unique_data_dir();
        let data_dir = dir.to_str().expect("temp path is UTF-8").to_string();
        let state = shared
            .licence
            .load_from_data_dir(std::path::Path::new(&data_dir), now)
            .expect("loads");
        assert_eq!(state.name(), "trial");
        let request = shared
            .licence
            .generate_request(Some(3), vec!["clustering".to_string()], "")
            .expect("request");
        assert!(!request.installation_identity.is_empty());
        assert!(request.summary.contains(&request.installation_identity));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Decode the topic out of a `PublishOut` downlink frame (test mirror
    /// of `encode_publish_out`: `TopicLen:16be | Topic | PacketId:16be |
    /// QoS:8 | Retain:8 | Dup:8`).
    fn downlink_topic(frame: &BrokerFrame) -> String {
        let meta = &frame.metadata;
        let topic_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
        std::str::from_utf8(&meta[2..2 + topic_len])
            .expect("downlink topic is UTF-8")
            .to_string()
    }

    /// B4-04: a publish through the broker with a capture-group rule
    /// delivers the rewritten topic. Subscriber sits on the rewritten
    /// name; the publisher sends the original; the downlink carries the
    /// rewritten name. Fails before the change (no rewrite existed, so
    /// nothing matched and no delivery arrived).
    #[tokio::test]
    async fn rewrite_publish_capture_group_delivers_rewritten_topic() {
        let shared = test_shared();
        shared
            .router
            .set_rewrite_rules(vec![broker_router::RewriteRuleConfig::new(
                "^sensors/(.*)$",
                "devices/$1",
                broker_router::RewriteScope::Publish,
            )])
            .expect("valid rule installs");

        // Subscriber on the rewritten name (publish-scoped rule leaves
        // subscribe filters untouched, so this subscribes literally).
        let (session, _) = shared.sessions.get_or_create("rw-sub", true);
        *session.conn_id.write() = Some(61);
        let sub = subscribe_frame(
            61,
            1,
            encode_subscribe_meta(3, "rw-sub", &[("devices/temp", 0)]),
        );
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        // Publish the original name through the real ingress event.
        let (meta, payload) = encode_publish_meta("sensors/temp", 0, 0, false, b"21.5");
        let (_, deliveries) = apply_publish(&publish_frame(62, 2, meta, payload), &shared).await;

        assert_eq!(deliveries.len(), 1, "rewritten publish must fan out");
        assert_eq!(deliveries[0].0, 61);
        assert_eq!(downlink_topic(&deliveries[0].1), "devices/temp");
        assert_eq!(shared.router.rewrite_stats().rewritten, 1);
    }

    /// B4-04: publish-side, subscribe-side and both-scoped rules act
    /// independently through the broker. A publish-scoped rule never
    /// rewrites a subscription; a subscribe-scoped rule never rewrites
    /// a publish; a both-scoped rule rewrites either.
    #[tokio::test]
    async fn rewrite_scopes_apply_independently_through_broker() {
        // Publish-only: publish rewrites, subscribe does not.
        let shared = test_shared();
        shared
            .router
            .set_rewrite_rules(vec![broker_router::RewriteRuleConfig::new(
                "^p/(.*)$",
                "pub/$1",
                broker_router::RewriteScope::Publish,
            )])
            .expect("publish rule installs");
        let (session, _) = shared.sessions.get_or_create("rw-p", true);
        *session.conn_id.write() = Some(63);
        // Subscribing to the pre-rewrite name stays literal (no match).
        let sub = subscribe_frame(63, 1, encode_subscribe_meta(4, "rw-p", &[("p/a", 0)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");
        // Publishing the same name rewrites away from the subscription.
        let (meta, payload) = encode_publish_meta("p/a", 0, 0, false, b"x");
        let (_, deliveries) = apply_publish(&publish_frame(64, 1, meta, payload), &shared).await;
        assert!(
            deliveries.is_empty(),
            "publish-only rewrite must not match the literal subscription"
        );
        // A subscriber on the rewritten name receives it.
        let sub = subscribe_frame(63, 2, encode_subscribe_meta(5, "rw-p", &[("pub/a", 0)]));
        apply_subscribe(&sub, &shared).await.0.expect("subscribe");
        let (meta, payload) = encode_publish_meta("p/a", 0, 0, false, b"x");
        let (_, deliveries) = apply_publish(&publish_frame(64, 2, meta, payload), &shared).await;
        assert_eq!(deliveries.len(), 1);
        assert_eq!(downlink_topic(&deliveries[0].1), "pub/a");

        // Subscribe-only: subscribe rewrites, publish does not.
        let shared = test_shared();
        shared
            .router
            .set_rewrite_rules(vec![broker_router::RewriteRuleConfig::new(
                "^s/(.*)$",
                "sub/$1",
                broker_router::RewriteScope::Subscribe,
            )])
            .expect("subscribe rule installs");
        let (session, _) = shared.sessions.get_or_create("rw-s", true);
        *session.conn_id.write() = Some(65);
        // Subscribing to the pre-rewrite name lands on the rewritten filter.
        let sub = subscribe_frame(65, 1, encode_subscribe_meta(6, "rw-s", &[("s/a", 0)]));
        apply_subscribe(&sub, &shared).await.0.expect("subscribe");
        // Publishing the rewritten name (untouched by the rule) delivers.
        let (meta, payload) = encode_publish_meta("sub/a", 0, 0, false, b"y");
        let (_, deliveries) = apply_publish(&publish_frame(66, 1, meta, payload), &shared).await;
        assert_eq!(deliveries.len(), 1);
        assert_eq!(downlink_topic(&deliveries[0].1), "sub/a");
        // Publishing the pre-rewrite name does not rewrite, so nothing matches.
        let (meta, payload) = encode_publish_meta("s/a", 0, 0, false, b"y");
        let (_, deliveries) = apply_publish(&publish_frame(66, 2, meta, payload), &shared).await;
        assert!(
            deliveries.is_empty(),
            "subscribe-only rule must not rewrite publishes"
        );

        // Both-scoped: either direction rewrites.
        let shared = test_shared();
        shared
            .router
            .set_rewrite_rules(vec![broker_router::RewriteRuleConfig::new(
                "^b/(.*)$",
                "both/$1",
                broker_router::RewriteScope::Both,
            )])
            .expect("both rule installs");
        let (session, _) = shared.sessions.get_or_create("rw-b", true);
        *session.conn_id.write() = Some(67);
        let sub = subscribe_frame(67, 1, encode_subscribe_meta(7, "rw-b", &[("b/a", 0)]));
        apply_subscribe(&sub, &shared).await.0.expect("subscribe");
        let (meta, payload) = encode_publish_meta("b/a", 0, 0, false, b"z");
        let (_, deliveries) = apply_publish(&publish_frame(68, 1, meta, payload), &shared).await;
        assert_eq!(deliveries.len(), 1);
        assert_eq!(downlink_topic(&deliveries[0].1), "both/a");
    }

    /// B4-04: rule order decides (first match wins) and an unmatched
    /// topic passes through unchanged, through the real broker events.
    #[tokio::test]
    async fn rewrite_order_first_match_wins_and_miss_passes_through() {
        let shared = test_shared();
        shared
            .router
            .set_rewrite_rules(vec![
                broker_router::RewriteRuleConfig::new(
                    "^o/(.*)$",
                    "first/$1",
                    broker_router::RewriteScope::Both,
                ),
                broker_router::RewriteRuleConfig::new(
                    "^o/(.*)$",
                    "second/$1",
                    broker_router::RewriteScope::Both,
                ),
            ])
            .expect("rules install");
        let (session, _) = shared.sessions.get_or_create("rw-o", true);
        *session.conn_id.write() = Some(69);
        for filter in ["first/x", "second/x", "plain/x"] {
            let sub = subscribe_frame(69, 1, encode_subscribe_meta(8, "rw-o", &[(filter, 0)]));
            apply_subscribe(&sub, &shared).await.0.expect("subscribe");
        }
        // First matching rule wins.
        let (meta, payload) = encode_publish_meta("o/x", 0, 0, false, b"o");
        let (_, deliveries) = apply_publish(&publish_frame(70, 1, meta, payload), &shared).await;
        assert_eq!(deliveries.len(), 1);
        assert_eq!(downlink_topic(&deliveries[0].1), "first/x");
        // An unmatched topic passes through unchanged to its subscriber.
        let (meta, payload) = encode_publish_meta("plain/x", 0, 0, false, b"p");
        let (_, deliveries) = apply_publish(&publish_frame(70, 2, meta, payload), &shared).await;
        assert_eq!(deliveries.len(), 1);
        assert_eq!(downlink_topic(&deliveries[0].1), "plain/x");
    }

    /// B4-04: the rule-count bound and the evaluation budget are enforced
    /// with counters. Over-cap installs fail closed (table unchanged);
    /// over-long inputs fail closed to no-rewrite with the budget counter.
    #[tokio::test]
    async fn rewrite_bounds_enforced_with_counters() {
        let shared = test_shared();
        let too_many: Vec<broker_router::RewriteRuleConfig> = (0
            ..(broker_router::MAX_REWRITE_RULES + 1))
            .map(|i| {
                broker_router::RewriteRuleConfig::new(
                    format!("^bound{i}/(.*)$"),
                    "x/$1",
                    broker_router::RewriteScope::Both,
                )
            })
            .collect();
        let err = shared
            .router
            .set_rewrite_rules(too_many)
            .expect_err("over-cap install must fail");
        assert!(
            matches!(err, broker_router::RewriteRuleError::TooManyRules(_)),
            "unexpected error: {err}"
        );
        assert_eq!(shared.router.rewrite_rule_count(), 0);

        // Budget: an input past the length bound never rewrites and bumps
        // exactly the budget counter (delivery would proceed unchanged).
        let huge = "t".repeat(broker_router::MAX_REWRITE_LEN + 1);
        assert_eq!(shared.router.rewrite_publish(&huge), None);
        let stats = shared.router.rewrite_stats();
        assert_eq!(stats.budget_exceeded, 1);
        assert_eq!(stats.rewritten, 0);
    }

    /// B4-04 publish-path workload numbers with rewriting off and on,
    /// measured through the real broker publish event (`apply_publish`),
    /// not just the router. OFF is the no-rules baseline; ON installs one
    /// capture-group rule plus a full 64-rule table miss path on a second
    /// router state. Both print msgs/sec and avg ns/msg into the gate
    /// output with no threshold assert; counts are CI sample sizes, not
    /// SLOs. Per-message cost prose lives on `Router::rewrite_for`; this
    /// test is the measured numbers behind it.
    #[tokio::test]
    async fn rewrite_publish_timing_reports_throughput() {
        use std::hint::black_box;
        use std::time::Instant;

        // OFF: no rules installed.
        let shared = test_shared();
        let (session, _) = shared.sessions.get_or_create("rw-load", true);
        *session.conn_id.write() = Some(71);
        let sub = subscribe_frame(
            71,
            1,
            encode_subscribe_meta(9, "rw-load", &[("devices/load", 0), ("load/plain", 0)]),
        );
        apply_subscribe(&sub, &shared).await.0.expect("subscribe");
        let off_iters = 200usize;
        let off_start = Instant::now();
        for i in 0..off_iters {
            let (meta, payload) = encode_publish_meta("load/plain", 0, 0, false, b"x");
            let (_, deliveries) =
                apply_publish(&publish_frame(72, 100 + i as u64, meta, payload), &shared).await;
            black_box(&deliveries);
            assert_eq!(deliveries.len(), 1, "baseline must deliver");
        }
        let off_elapsed = off_start.elapsed();
        let off_rate = off_iters as f64 / off_elapsed.as_secs_f64();
        let off_avg_ns = off_elapsed.as_nanos() as f64 / off_iters as f64;
        println!(
            "rewrite broker workload baseline (off, no rules): {off_rate:.0} msgs/sec, avg {off_avg_ns:.1} ns/msg ({off_iters} apply_publish rounds in {off_elapsed:?})"
        );

        // ON: one matching capture-group rule plus 63 preceding misses so
        // the measured path pays the worst-case ordered scan.
        let mut rules = Vec::with_capacity(broker_router::MAX_REWRITE_RULES);
        for i in 0..(broker_router::MAX_REWRITE_RULES - 1) {
            rules.push(broker_router::RewriteRuleConfig::new(
                format!("^nomatch{i}/(.*)$"),
                "miss/$1",
                broker_router::RewriteScope::Both,
            ));
        }
        rules.push(broker_router::RewriteRuleConfig::new(
            "^load/(.*)$",
            "devices/$1",
            broker_router::RewriteScope::Both,
        ));
        shared
            .router
            .set_rewrite_rules(rules)
            .expect("full table installs");
        // Resubscribe through the rewritten filter so the ON loop delivers.
        let sub = subscribe_frame(
            71,
            2,
            encode_subscribe_meta(10, "rw-load", &[("load/plain", 0)]),
        );
        apply_subscribe(&sub, &shared).await.0.expect("subscribe");
        let on_iters = 200usize;
        let on_start = Instant::now();
        for i in 0..on_iters {
            let (meta, payload) = encode_publish_meta("load/plain", 0, 0, false, b"x");
            let (_, deliveries) =
                apply_publish(&publish_frame(72, 500 + i as u64, meta, payload), &shared).await;
            black_box(&deliveries);
            assert_eq!(deliveries.len(), 1, "rewritten publish must deliver");
            assert_eq!(downlink_topic(&deliveries[0].1), "devices/plain");
        }
        let on_elapsed = on_start.elapsed();
        let on_rate = on_iters as f64 / on_elapsed.as_secs_f64();
        let on_avg_ns = on_elapsed.as_nanos() as f64 / on_iters as f64;
        println!(
            "rewrite broker workload (on, 64-rule table, last-rule hit): {on_rate:.0} msgs/sec, avg {on_avg_ns:.1} ns/msg ({on_iters} apply_publish rounds in {on_elapsed:?})"
        );
        println!(
            "rewrite counters after workload: {:?}",
            shared.router.rewrite_stats()
        );
    }
}
