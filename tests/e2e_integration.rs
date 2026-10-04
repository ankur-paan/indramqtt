//! End-to-end integration and smoke suite for IndraMQTT core services.
//!
//! Validates the end-to-end messaging pipeline without requiring external network daemons:
//! 1. Multi-topic Radix Trie router registration and matching.
//! 2. Streaming SQL evaluation and rule action dispatch.
//! 3. Session state retention, QoS 1 in-flight tracking, and offline queueing.
//! 4. API kick of a connected client delivers a BrokerLink `ConnClose` to
//!    the edge and the client observes TCP close.

use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::{Router, Subscription};
use broker_rules::{BackpressurePolicy, BrokerSink, RuleAction, RuleEngine};
use broker_session::{QueuedMessage, SessionManager};
use bytes::Bytes;
use std::sync::{Arc, Mutex};

/// Reports a test that cannot run because the edge or `erl` is absent.
///
/// On a developer machine the test prints the reason and stops. If
/// `E2E_REQUIRE_EDGE` is set, the test fails. CI and the build lanes set
/// it, because a test that does not run must not count as a pass.
macro_rules! e2e_skip {
    ($($arg:tt)*) => {{
        let reason = format!($($arg)*);
        if std::env::var_os("E2E_REQUIRE_EDGE").is_some() {
            panic!("{reason}. E2E_REQUIRE_EDGE is set, thus this test must run.");
        }
        eprintln!("{reason}");
    }};
}

#[derive(Debug, Default)]
struct TestBrokerSink {
    published: Mutex<Vec<(Topic, Bytes, QoS, bool)>>,
}

#[async_trait::async_trait]
impl BrokerSink for TestBrokerSink {
    async fn publish(
        &self,
        topic: Topic,
        payload: Bytes,
        qos: QoS,
        retain: bool,
    ) -> Result<(), broker_rules::RuleEngineError> {
        self.published
            .lock()
            .unwrap()
            .push((topic, payload, qos, retain));
        Ok(())
    }
}

#[tokio::test]
async fn test_e2e_router_and_rules_pipeline() {
    let router = Router::new();
    let engine = RuleEngine::new(1024, BackpressurePolicy::Block);
    let sink = Arc::new(TestBrokerSink::default());
    let broker_sink: Arc<dyn BrokerSink> = sink.clone();

    // 1. Install subscriptions
    let filter = TopicFilter::new("industrial/+/telemetry").unwrap();
    router.subscribe(
        &filter,
        Subscription {
            client_id: "scada-gateway-1".into(),
            conn_id: 101,
            qos: QoS::AtLeastOnce,
            group: None,
            tenant: broker_router::DEFAULT_TENANT_ID.into(),
            no_local: false,
            retain_as_published: false,
            retain_handling: 0,
            subscription_id: 0,
        },
    );

    // 2. Install streaming rule with projection
    engine
        .create_rule(
            "temp_alarm".to_string(),
            TopicFilter::new("industrial/+/telemetry").unwrap(),
            Some(
                r#"SELECT machine_id, temperature FROM "industrial/+/telemetry" WHERE temperature > 85.0"#
                    .to_string(),
            ),
            true,
            vec![RuleAction::Republish {
                topic: Topic::new("alarms/high_temperature").unwrap(),
                qos: QoS::AtLeastOnce,
            }],
        )
        .expect("rule created");

    // 3. Ingest matching event below threshold (router matches, but rule filter suppresses action)
    let normal_topic = Topic::new("industrial/line1/telemetry").unwrap();
    let normal_payload = Bytes::from_static(br#"{"machine_id": "M1", "temperature": 72.0}"#);

    assert_eq!(router.matches(&normal_topic).len(), 1);
    engine
        .dispatch_ingress(
            &normal_topic,
            &normal_payload,
            QoS::AtLeastOnce,
            &broker_sink,
        )
        .await;
    assert_eq!(sink.published.lock().unwrap().len(), 0);

    // 4. Ingest matching event above threshold (triggers rule republish action)
    let alarm_topic = Topic::new("industrial/line2/telemetry").unwrap();
    let alarm_payload = Bytes::from_static(br#"{"machine_id": "M2", "temperature": 94.5}"#);

    assert_eq!(router.matches(&alarm_topic).len(), 1);
    engine
        .dispatch_ingress(&alarm_topic, &alarm_payload, QoS::AtLeastOnce, &broker_sink)
        .await;

    let published = sink.published.lock().unwrap();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].0.as_str(), "alarms/high_temperature");
    let projected_json: serde_json::Value =
        serde_json::from_slice(&published[0].1).expect("valid projected JSON");
    assert_eq!(projected_json["machine_id"], "M2");
    assert_eq!(projected_json["temperature"], 94.5);
}

#[test]
fn test_e2e_session_lifecycle_and_offline_queue() {
    let session_mgr = SessionManager::new_with_limits(Some(50));
    let client_id = "edge-station-42";

    // Create durable session
    let (session, present) = session_mgr.get_or_create(client_id, false);
    assert!(!present);
    assert_eq!(session.client_id, client_id);

    // Queue offline messages
    for i in 1..=20 {
        let topic = Topic::new(format!("downstream/job-{i}")).unwrap();
        let payload = Bytes::from(format!("payload-{i}"));
        session.push_offline(QueuedMessage {
            topic,
            qos: QoS::AtLeastOnce,
            retain: false,
            payload,
            publish_at_ms: None,
        });
    }
    assert_eq!(session.offline_len(), 20);

    // Reconnecting retrieves the same session with all 20 queued messages
    let (resumed, present2) = session_mgr.get_or_create(client_id, false);
    assert!(present2);
    assert_eq!(resumed.id, session.id);
    assert_eq!(resumed.offline_len(), 20);

    // Drain offline messages on reconnection
    let drained = resumed.drain_offline();
    assert_eq!(drained.len(), 20);
    assert_eq!(resumed.offline_len(), 0);
}

/// Minimal MQTT 3.1.1 CONNECT packet for `client_id` (clean session,
/// keepalive 60): fixed header plus the `MQTT`/4 variable header and
/// the id payload. Enough for the harness edge to accept the client.
fn mqtt_connect_packet(client_id: &str) -> Vec<u8> {
    let mut rest = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C];
    rest.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    rest.extend_from_slice(client_id.as_bytes());
    let mut packet = vec![0x10];
    let mut len = rest.len();
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        packet.push(byte);
        if len == 0 {
            break;
        }
    }
    packet.extend_from_slice(&rest);
    packet
}

/// Read one MQTT control packet: returns the fixed-header first byte
/// and the remaining body. Only used with an explicit caller timeout.
async fn read_mqtt_packet(sock: &mut tokio::net::TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let mut head = [0u8; 1];
    sock.read_exact(&mut head).await?;
    let mut multiplier = 1usize;
    let mut remaining = 0usize;
    loop {
        let mut byte = [0u8; 1];
        sock.read_exact(&mut byte).await?;
        remaining += ((byte[0] & 0x7F) as usize) * multiplier;
        if byte[0] & 0x80 == 0 {
            break;
        }
        multiplier *= 128;
        if multiplier > 128 * 128 * 128 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "MQTT remaining length overflow",
            ));
        }
    }
    let mut body = vec![0u8; remaining];
    sock.read_exact(&mut body).await?;
    Ok((head[0], body))
}

/// Every socket or channel wait in the kick test is bounded by this:
/// a missing edge or a regressed kick order fails the test instead of
/// hanging the worker (the `broker-api` hang the manager killed).
const KICK_E2E_STEP: std::time::Duration = std::time::Duration::from_secs(5);

/// Bound for launcher probes: spawning `wsl.exe` cold-boots the VM,
/// which takes longer than one step; the probe still fails loudly on
/// expiry (as a SKIP with a reason, never a hang).
const KICK_E2E_PROBE: std::time::Duration = std::time::Duration::from_secs(30);

/// `(client_id, clean_start, keepalive, username, password)` decoded from
/// one `BindConnection` metadata body.
type E2eBind = (String, bool, u16, Option<String>, Option<Vec<u8>>);

/// Decode a `BindConnection` metadata body into [`E2eBind`], mirroring
/// the kernel's `decode_bind_meta` contract (`ClientIdLen:16be |
/// ClientId | Flags:8 | Keepalive:16be`, plus the optional trailing
/// `UserLen | Username | PassLen | Password` credentials section and the
/// optional trailing `PeerLen:16be | PeerIp` peer-address section).
fn decode_e2e_bind(meta: &[u8]) -> Option<E2eBind> {
    if meta.len() < 5 {
        return None;
    }
    let id_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    if meta.len() < 2 + id_len + 3 {
        return None;
    }
    let client_id = std::str::from_utf8(&meta[2..2 + id_len]).ok()?.to_string();
    let flags = meta[2 + id_len];
    let keepalive = u16::from_be_bytes([meta[3 + id_len], meta[4 + id_len]]);
    let rest = &meta[5 + id_len..];
    let (username, password) = if rest.is_empty() {
        (None, None)
    } else {
        if rest.len() < 2 {
            return None;
        }
        let user_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if rest.len() < 2 + user_len + 2 {
            // Too short for credentials: only a peer-only anonymous bind
            // (peer-aware edge appends `PeerLen | PeerIp`) decodes here.
            e2e_decode_peer_section(rest)?;
            (None, None)
        } else {
            let username = std::str::from_utf8(&rest[2..2 + user_len])
                .ok()?
                .to_string();
            let base = 2 + user_len;
            let pass_len = u16::from_be_bytes([rest[base], rest[base + 1]]) as usize;
            if rest.len() < base + 2 + pass_len {
                return None;
            }
            let password = rest[base + 2..base + 2 + pass_len].to_vec();
            let tail = &rest[base + 2 + pass_len..];
            if !tail.is_empty() {
                // Optional trailing peer-address section; anything else
                // is malformed trailing garbage.
                e2e_decode_peer_section(tail)?;
            }
            (Some(username), Some(password))
        }
    };
    Some((client_id, flags & 0x01 != 0, keepalive, username, password))
}

/// Decode one peer-address section `PeerLen:16be | PeerIp`: exactly those
/// bytes and an IP literal, otherwise `None`. Mirrors the kernel's
/// `decode_peer_section`.
fn e2e_decode_peer_section(section: &[u8]) -> Option<String> {
    if section.len() < 2 {
        return None;
    }
    let peer_len = u16::from_be_bytes([section[0], section[1]]) as usize;
    if section.len() != 2 + peer_len {
        return None;
    }
    let literal = std::str::from_utf8(&section[2..]).ok()?;
    literal.parse::<std::net::IpAddr>().ok()?;
    Some(literal.to_string())
}

/// Decode an `UnbindConnection` metadata body (`ClientIdLen:16be |
/// ClientId`), mirroring the kernel's `decode_unbind_meta`.
fn decode_e2e_unbind(meta: &[u8]) -> Option<String> {
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

/// Minimal kernel side of the BrokerLink handshake for one edge
/// connection: answers every `BindConnection` with `SessionBinding`
/// (mirroring `bind_connection_reply`), answers `Ping` with `Pong`,
/// applies `UnbindConnection` like `apply_unbind`, and forwards this
/// connection's mailbox onto the edge transport (mirroring
/// `handle_connection`'s outbound arm). The session directory and the
/// connection directory are the production ones shared with `ApiState`,
/// so the kick route resolves the real session and routes `ConnClose`
/// through the real `ConnTable`. Every wait is bounded by
/// `KICK_E2E_STEP` so a dead edge ends the task instead of hanging it.
async fn e2e_kernel_edge_handler(
    stream: tokio::net::TcpStream,
    sessions: Arc<SessionManager>,
    conns: Arc<broker_router::ConnTable>,
    auth: Arc<broker_auth::MemoryAuth>,
) {
    use broker_auth::Authenticator;
    use brokerlink::{BrokerFrame, BrokerLinkTransport, FramedTransport, OpCode};
    use bytes::Bytes;

    let transport = Arc::new(FramedTransport::new(stream));
    let (mb_tx, mut mb_rx) = tokio::sync::mpsc::unbounded_channel::<BrokerFrame>();
    let mut bound: Option<(String, u64)> = None;
    eprintln!("kick-e2e: kernel accepted an edge connection");
    let detach = |bound: &Option<(String, u64)>,
                  tx: &tokio::sync::mpsc::UnboundedSender<BrokerFrame>| {
        conns.prune_sender(tx);
        if let Some((client_id, conn_id)) = bound {
            sessions.unbind_connection(client_id, *conn_id);
        }
    };
    loop {
        tokio::select! {
            inbound = tokio::time::timeout(KICK_E2E_STEP, transport.recv()) => {
                let frame = match inbound {
                    Ok(Ok(frame)) => frame,
                    // Edge idle: keep serving; edge gone or broken frame:
                    // detach exactly like the kernel does and stop.
                    Err(_) => continue,
                    Ok(Err(brokerlink::BrokerLinkError::ConnectionClosed)) => {
                        detach(&bound, &mb_tx);
                        break;
                    }
                    Ok(Err(_)) => {
                        detach(&bound, &mb_tx);
                        break;
                    }
                };
                let conn_id = frame.header.conn_id;
                let seq = frame.header.sequence_no;
                eprintln!(
                    "kick-e2e: kernel got opcode={:?} conn={conn_id}",
                    frame.header.opcode
                );
                match frame.header.opcode {
                    OpCode::BindConnection => {
                        let mut session_id = 0u64;
                        let mut present = false;
                        let mut return_code = 2u8;
                        if let Some((client_id, clean_start, keepalive, username, password)) =
                            decode_e2e_bind(&frame.metadata)
                        {
                            // Same gates as the kernel's `apply_bind`:
                            // anonymous binds need an empty user store,
                            // credentialed binds authenticate first.
                            if username.is_none() {
                                if auth.user_count() == 0 {
                                    return_code = 0;
                                } else {
                                    return_code = 0x87;
                                }
                            } else if auth
                                .authenticate(&client_id, username.as_deref(), password.as_deref())
                                .await
                                .is_ok()
                            {
                                return_code = 0;
                            } else {
                                return_code = 0x86;
                            }
                            if return_code == 0 {
                                let (session, was_present) =
                                    sessions.get_or_create(&client_id, clean_start);
                                *session.conn_id.write() = Some(conn_id);
                                *session.keepalive_secs.write() = keepalive;
                                *session.connected.write() = true;
                                session_id = session.id.0;
                                present = was_present;
                                conns.register(conn_id, mb_tx.clone());
                                bound = Some((client_id, conn_id));
                            }
                        }
                        let mut reply_meta = Vec::with_capacity(10);
                        reply_meta.extend_from_slice(&session_id.to_be_bytes());
                        reply_meta.push(u8::from(present));
                        reply_meta.push(return_code);
                        let reply = BrokerFrame::new(
                            OpCode::SessionBinding,
                            conn_id,
                            seq,
                            Bytes::from(reply_meta),
                            Bytes::new(),
                        )
                        .expect("SessionBinding reply within size bounds");
                        if tokio::time::timeout(KICK_E2E_STEP, transport.send(reply))
                            .await
                            .is_err()
                        {
                            detach(&bound, &mb_tx);
                            break;
                        }
                    }
                    OpCode::Ping => {
                        let pong = BrokerFrame::pong(conn_id, seq);
                        if tokio::time::timeout(KICK_E2E_STEP, transport.send(pong))
                            .await
                            .is_err()
                        {
                            detach(&bound, &mb_tx);
                            break;
                        }
                    }
                    OpCode::UnbindConnection => {
                        if let Some(client_id) = decode_e2e_unbind(&frame.metadata) {
                            sessions.unbind_connection(&client_id, conn_id);
                        }
                        conns.unregister(conn_id);
                    }
                    _ => {}
                }
            }
            outbound = tokio::time::timeout(KICK_E2E_STEP, mb_rx.recv()) => {
                match outbound {
                    Ok(Some(frame)) => {
                        let send = tokio::time::timeout(KICK_E2E_STEP, transport.send(frame)).await;
                        match send {
                            Ok(Ok(())) => {}
                            _ => {
                                detach(&bound, &mb_tx);
                                break;
                            }
                        }
                    }
                    // Mailbox closed: nothing left to deliver.
                    Ok(None) => {
                        detach(&bound, &mb_tx);
                        break;
                    }
                    // Idle mailbox: keep serving.
                    Err(_) => continue,
                }
            }
        }
    }
}

/// Where the shipped Erlang edge comes from for the kick test.
struct EdgeTarget {
    program: String,
    /// Arguments, including the executable script for the `wsl.exe` fallback.
    args: Vec<String>,
    /// Host the MQTT client dials (loopback natively, the WSL guest IP
    /// when the edge runs under `wsl.exe`).
    mqtt_host: String,
    /// Shell snippet that kills the edge started for `mqtt_port`
    /// (the `wsl.exe` wrapper outlives `kill_on_drop`; native `erl` is
    /// a direct child and needs no extra cleanup).
    cleanup: Option<(String, Vec<String>)>,
    /// Firewall proxy fronting the kernel listener (Windows+WSL branch
    /// only): killed with the edge at the end of the test.
    proxy: Option<tokio::process::Child>,
}

/// Transparent local TCP proxy for the Windows+WSL branch: Windows
/// Firewall lets WSL open connections to `python.exe` listeners but
/// stealth-drops them to this test binary, so the edge dials the
/// proxy and the proxy forwards raw bytes to the real kernel listener
/// on loopback. Usage: `python -c E2E_PROXY_SCRIPT <real_port>`; it
/// prints the proxy port on stdout. Below the BrokerLink codec, so the
/// handshake and kick hops under test are unchanged.
const E2E_PROXY_SCRIPT: &str = r#"
import socket
import sys
import threading

real = int(sys.argv[1])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 0))
print(srv.getsockname()[1], flush=True)
srv.listen(16)


def pipe(source, dest):
    try:
        while True:
            chunk = source.recv(65536)
            if not chunk:
                break
            dest.sendall(chunk)
    except OSError:
        pass
    try:
        dest.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def handle(client):
    try:
        upstream = socket.create_connection(("127.0.0.1", real), timeout=10)
    except OSError:
        client.close()
        return
    relay = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
    relay.start()
    pipe(upstream, client)
    client.close()
    upstream.close()


while True:
    peer, _ = srv.accept()
    threading.Thread(target=handle, args=(peer,), daemon=True).start()
"#;

/// Run `program args` and return its output unless it takes longer than
/// `timeout`.
async fn e2e_command_output(
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> Option<std::process::Output> {
    match tokio::time::timeout(
        timeout,
        tokio::process::Command::new(program).args(args).output(),
    )
    .await
    {
        Ok(Ok(output)) => Some(output),
        _ => None,
    }
}

/// Locate the shipped edge (`beam/ebin` next to this workspace) and an
/// Erlang runtime to run it: native `erl` first (CI installs OTP), then
/// `wsl.exe` on Windows. Returns the launch plus the MQTT port the edge
/// was told to bind (probed in the edge's own network namespace: a port
/// free on Windows may be taken in WSL). Returns `None` with a logged
/// reason when no runtime exists, in which case the caller skips instead
/// of failing.
async fn e2e_edge_target(bl_port: u16) -> Option<(EdgeTarget, u16, u16)> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebin = manifest.join("../../beam/ebin");
    let ebin = ebin.canonicalize().unwrap_or(ebin);
    if !ebin.join("indra_edge.app").is_file() {
        e2e_skip!(
            "SKIP kicked_mqtt_client_sees_disconnect: no compiled edge at {} (build beam/ first)",
            ebin.display()
        );
        return None;
    }
    // Native Erlang: `erl` on PATH (CI's erlef/setup-beam, dev machines).
    let native = e2e_command_output("erl", &["-version"], KICK_E2E_STEP).await;
    if native.as_ref().is_some_and(|out| out.status.success()) {
        let mqtt_port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral MQTT port");
            probe.local_addr().expect("MQTT port").port()
        };
        // The plaintext WebSocket listener rides beside MQTT on its own
        // ephemeral port so parallel tests never share 8083.
        let ws_port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral WS port");
            probe.local_addr().expect("WS port").port()
        };
        let args = vec![
            "-noshell".to_string(),
            "-pa".to_string(),
            ebin.to_string_lossy().into_owned(),
            "-indra_edge".to_string(),
            "mqtt_port".to_string(),
            mqtt_port.to_string(),
            "-indra_edge".to_string(),
            "ws_port".to_string(),
            ws_port.to_string(),
            "-indra_edge".to_string(),
            "kernel_host".to_string(),
            "\"127.0.0.1\"".to_string(),
            "-indra_edge".to_string(),
            "kernel_port".to_string(),
            bl_port.to_string(),
            "-eval".to_string(),
            "{ok,_} = application:ensure_all_started(indra_edge), timer:sleep(infinity)."
                .to_string(),
        ];
        return Some((
            EdgeTarget {
                program: "erl".to_string(),
                args,
                mqtt_host: "127.0.0.1".to_string(),
                cleanup: None,
                proxy: None,
            },
            mqtt_port,
            ws_port,
        ));
    }
    // Windows fallback: Erlang lives in WSL (this repo's edge toolchain).
    // The edge then dials the Windows host through the WSL gateway while
    // the MQTT client dials the guest IP: loopback is not shared there.
    // (`cfg!` keeps this compiling on every platform; it only runs on
    // Windows, where native `erl` was already ruled out above.)
    if cfg!(windows) {
        let has_erl = e2e_command_output(
            "wsl.exe",
            &["-e", "bash", "-lc", "command -v erl"],
            KICK_E2E_PROBE,
        )
        .await;
        if !has_erl.as_ref().is_some_and(|out| out.status.success()) {
            e2e_skip!("SKIP kicked_mqtt_client_sees_disconnect: no `erl` on PATH and none in WSL");
            return None;
        }
        let route = e2e_command_output(
            "wsl.exe",
            &["-e", "bash", "-lc", "ip route show default"],
            KICK_E2E_PROBE,
        )
        .await?;
        let route = String::from_utf8_lossy(&route.stdout);
        let gateway = route
            .split_whitespace()
            .skip_while(|word| *word != "via")
            .nth(1)?
            .to_string();
        let addr = e2e_command_output(
            "wsl.exe",
            &["-e", "bash", "-lc", "ip -4 -o addr show eth0"],
            KICK_E2E_PROBE,
        )
        .await?;
        let addr = String::from_utf8_lossy(&addr.stdout);
        let inet = addr.split_whitespace().find(|word| word.contains('/'))?;
        let guest_ip = inet.split('/').next()?.to_string();
        // A port free in the guest (the edge binds there): probing from
        // Windows would check the wrong namespace.
        let probe = e2e_command_output(
            "wsl.exe",
            &[
                "-e",
                "bash",
                "-lc",
                "python3 -c 'import socket; s = socket.socket(); s.bind((\"0.0.0.0\", 0)); print(s.getsockname()[1])'",
            ],
            KICK_E2E_PROBE,
        )
        .await?;
        if !probe.status.success() {
            return None;
        }
        let mqtt_port: u16 = String::from_utf8_lossy(&probe.stdout).trim().parse().ok()?;
        // The plaintext WebSocket listener gets its own guest-side
        // ephemeral port beside MQTT for the same reason.
        let ws_probe = e2e_command_output(
            "wsl.exe",
            &[
                "-e",
                "bash",
                "-lc",
                "python3 -c 'import socket; s = socket.socket(); s.bind((\"0.0.0.0\", 0)); print(s.getsockname()[1])'",
            ],
            KICK_E2E_PROBE,
        )
        .await?;
        if !ws_probe.status.success() {
            return None;
        }
        let ws_port: u16 = String::from_utf8_lossy(&ws_probe.stdout)
            .trim()
            .parse()
            .ok()?;
        // Firewall proxy (see `E2E_PROXY_SCRIPT`): the edge dials the
        // proxy through the gateway; the proxy forwards to `bl_port`
        // on loopback. Without it the edge's SYNs never reach this
        // binary and the edge never gets past BrokerLink init.
        if !e2e_command_output("python", &["--version"], KICK_E2E_PROBE)
            .await
            .as_ref()
            .is_some_and(|out| out.status.success())
        {
            e2e_skip!(
                "SKIP kicked_mqtt_client_sees_disconnect: no `python` for the WSL firewall proxy"
            );
            return None;
        }
        let mut proxy = tokio::process::Command::new("python")
            .arg("-c")
            .arg(E2E_PROXY_SCRIPT)
            .arg(bl_port.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok()?;
        use tokio::io::{AsyncBufReadExt, BufReader};
        let proxy_stdout = proxy.stdout.take()?;
        let mut lines = BufReader::new(proxy_stdout).lines();
        let first = tokio::time::timeout(KICK_E2E_PROBE, lines.next_line())
            .await
            .ok()?
            .ok()?
            .unwrap_or_default();
        let proxy_port: u16 = first.trim().parse().ok()?;
        eprintln!("kick-e2e: firewall proxy forwards gateway:{proxy_port} -> 127.0.0.1:{bl_port}");
        // Rust `canonicalize` returns a `\\?\`-prefixed UNC path on
        // Windows, which WSL cannot resolve: strip it back to a plain
        // `C:\...` path before translating to `/mnt/c/...`.
        let win = ebin.to_string_lossy();
        let win = win.strip_prefix(r"\\?\").unwrap_or(&win);
        let drive = win.chars().next()?.to_ascii_lowercase();
        let wsl_ebin = if win.as_bytes().get(1) == Some(&b':') {
            format!("/mnt/{drive}{}", win[2..].replace('\\', "/"))
        } else {
            win.to_string()
        };
        let script = format!(
            "cd /tmp && erl -noshell -pa '{wsl_ebin}' \
             -indra_edge mqtt_port {mqtt_port} \
             -indra_edge ws_port {ws_port} \
             -indra_edge kernel_host '\"{gateway}\"' \
             -indra_edge kernel_port {proxy_port} \
             -eval '{{ok,_}} = application:ensure_all_started(indra_edge), timer:sleep(infinity).'"
        );
        let cleanup = format!("pkill -f 'mqtt_port {mqtt_port}'");
        return Some((
            EdgeTarget {
                program: "wsl.exe".to_string(),
                args: vec![
                    "-e".to_string(),
                    "bash".to_string(),
                    "-lc".to_string(),
                    script,
                ],
                mqtt_host: guest_ip,
                cleanup: Some((
                    "wsl.exe".to_string(),
                    vec![
                        "-e".to_string(),
                        "bash".to_string(),
                        "-lc".to_string(),
                        cleanup,
                    ],
                )),
                proxy: Some(proxy),
            },
            mqtt_port,
            ws_port,
        ));
    }
    e2e_skip!("SKIP kicked_mqtt_client_sees_disconnect: no `erl` on PATH");
    None
}

/// Kick loop against the shipped Erlang edge: a real MQTT 3.1.1 client
/// connects through `indra_edge` (spawned from this repo's `beam/ebin`
/// with its MQTT and BrokerLink ports pointed at the harness), the test
/// calls `DELETE /api/v5/clients/{id}`, the kernel routes `ConnClose`
/// to the edge, the edge closes the client socket (W0-25 contract), and
/// the client observes TCP close.
///
/// Kernel side this exercises the production path end to end: the kick
/// route sends on `ApiState`'s kernel→edge sender, the `serve_api`-style
/// forwarder routes the frame through the connection directory
/// (`ConnTable::route`), and the connection mailbox hands it to the
/// BrokerLink transport — the same hops a live connection takes
/// (`serve_api`/`handle_connection` in `broker-node/src/main.rs`).
/// Because the frame is routed *before* the kick unregisters the
/// connection, a regressed unregister-first order drops the close and
/// this test times out instead of passing.
///
/// The only non-production piece is the kernel's BrokerLink acceptor
/// (`e2e_kernel_edge_handler`): it answers `BindConnection`/`Ping`
/// exactly like the kernel's handshake so the edge can boot against a
/// test-scoped session directory. The edge binary, the MQTT framing,
/// the kick route, the session directory and the connection directory
/// are all production. Needs an Erlang runtime (`erl` on PATH, or WSL
/// on Windows); without one the test logs a SKIP and passes.
#[tokio::test]
async fn kicked_mqtt_client_sees_disconnect() {
    use brokerlink::BrokerFrame;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const CLIENT_ID: &str = "kicked-client";
    const TIMEOUT: Duration = KICK_E2E_STEP;
    // Boot budget: the edge starts an OTP VM (slower over WSL's 9p
    // filesystem), so process boot gets a minute while every single
    // wait stays at 5 s and fails loudly on expiry.
    const BOOT_BUDGET: Duration = Duration::from_secs(60);

    // Production kernel-side state, wired exactly as `serve_api` wires it.
    let engine = Arc::new(RuleEngine::new(16, BackpressurePolicy::DropOldest));
    let sessions = Arc::new(SessionManager::new());
    let sub_router = Arc::new(Router::new());
    let metrics = Arc::new(broker_observability::Metrics::new());
    let auth = Arc::new(broker_auth::MemoryAuth::new());
    let conns = Arc::new(broker_router::ConnTable::default());
    let scratch = std::env::temp_dir().join(format!(
        "indramqtt-kick-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let config =
        Arc::new(broker_config::ConfigRegistry::load(&scratch).expect("validated defaults load"));
    let (edge_tx, mut edge_rx) = tokio::sync::mpsc::unbounded_channel::<BrokerFrame>();
    let api_state = broker_api::ApiState::new(
        engine,
        sessions.clone(),
        sub_router,
        metrics,
        auth.clone(),
        conns.clone(),
        config,
        "indra-node-1".to_string(),
        edge_tx,
    );

    // Kernel listener on loopback: natively the edge dials it
    // directly; under WSL a `python` proxy (an allow-listed listener
    // program) forwards the edge's connection to it.
    let bl_listener = tokio::time::timeout(TIMEOUT, TcpListener::bind("127.0.0.1:0"))
        .await
        .expect("bind BrokerLink listener in time")
        .expect("bind BrokerLink listener");
    let bl_port = bl_listener.local_addr().expect("BrokerLink addr").port();
    let (edge, mqtt_port, _ws_port) = match e2e_edge_target(bl_port).await {
        // SKIP already logged when no runtime exists.
        Some(target) => target,
        None => return,
    };
    // The edge's stderr lands here; on a boot failure the tail is
    // quoted in the panic, on success the file is removed.
    let edge_log = std::env::temp_dir().join(format!(
        "indramqtt-kick-edge-{}-{mqtt_port}.log",
        std::process::id()
    ));
    eprintln!(
        "kick-e2e: spawning {} (mqtt={} on {}, brokerlink={} on Windows)",
        edge.program, mqtt_port, edge.mqtt_host, bl_port
    );
    eprintln!("kick-e2e: edge argv: {}", edge.args.join(" "));
    let edge_stderr = std::fs::File::create(&edge_log).expect("edge log file");
    let mut edge_child = tokio::process::Command::new(&edge.program)
        .args(&edge.args)
        .stdout(std::process::Stdio::null())
        .stderr(edge_stderr)
        .kill_on_drop(true)
        .spawn()
        .expect("spawn shipped edge");

    // Kernel acceptor: every edge connection (including reconnects)
    // gets the production-shaped handshake handler.
    let accept_sessions = sessions.clone();
    let accept_conns = conns.clone();
    let accept_auth = auth.clone();
    let acceptor = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(TIMEOUT, bl_listener.accept()).await {
                Ok(Ok((stream, _))) => {
                    let sessions = accept_sessions.clone();
                    let conns = accept_conns.clone();
                    let auth = accept_auth.clone();
                    tokio::spawn(e2e_kernel_edge_handler(stream, sessions, conns, auth));
                }
                // No dial yet (edge still booting): keep listening.
                Err(_) => continue,
                Ok(Err(error)) => panic!("BrokerLink accept failed: {error}"),
            }
        }
    });

    // Production kick forwarder, as `serve_api` wires it: every
    // kernel→edge close frame is routed through the connection
    // directory to the owning connection task. Frames for unregistered
    // connections are dropped there, so the kick must send the close
    // BEFORE unregistering (see `kick_client`).
    let forwarder_conns = conns.clone();
    let forwarder = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(TIMEOUT, edge_rx.recv()).await {
                Ok(Some(frame)) => {
                    let _ = forwarder_conns.route(frame.header.conn_id, frame);
                }
                // All senders gone: nothing left to deliver.
                Ok(None) => break,
                // Idle: keep forwarding.
                Err(_) => continue,
            }
        }
    });

    // Management API on loopback (mirrors `broker_api::serve`).
    let api_listener = tokio::time::timeout(TIMEOUT, TcpListener::bind("127.0.0.1:0"))
        .await
        .expect("bind API listener in time")
        .expect("bind API listener");
    let api_port = api_listener.local_addr().expect("API addr").port();
    let api_task = tokio::spawn(async move { broker_api::serve(api_listener, api_state).await });
    let base = format!("http://127.0.0.1:{api_port}");

    // Wait for the shipped edge's MQTT listener, then complete a real
    // MQTT 3.1.1 handshake through it: CONNECT out, CONNACK back. The
    // edge only sends CONNACK after the kernel answered its
    // `BindConnection`, so success here also proves the bind path.
    let mut client_sock = {
        let deadline = Instant::now() + BOOT_BUDGET;
        loop {
            let dial = tokio::time::timeout(
                TIMEOUT,
                TcpStream::connect((edge.mqtt_host.as_str(), mqtt_port)),
            )
            .await;
            match dial {
                Ok(Ok(sock)) => break sock,
                other => {
                    // The panic below only ever needs the latest dial
                    // error, so it stays a per-iteration local instead of
                    // a carried variable.
                    let last_error = match &other {
                        Ok(Err(error)) => error.to_string(),
                        Err(_) => "dial timed out".to_string(),
                        Ok(Ok(_)) => unreachable!("guarded above"),
                    };
                    if Instant::now() >= deadline {
                        panic!(
                            "shipped edge never opened MQTT port {mqtt_port} (last dial: {last_error})"
                        );
                    }
                    // Fail fast when the edge VM died during boot
                    // instead of polling a dead port for a minute.
                    if let Ok(Some(status)) = edge_child.try_wait() {
                        let log = std::fs::read_to_string(&edge_log).unwrap_or_default();
                        let tail = &log[log.len().saturating_sub(2000)..];
                        panic!("shipped edge exited during boot: {status}\nedge log tail:\n{tail}");
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    };
    tokio::time::timeout(
        TIMEOUT,
        client_sock.write_all(&mqtt_connect_packet(CLIENT_ID)),
    )
    .await
    .expect("client sends CONNECT in time")
    .expect("client sends CONNECT");
    let (packet_type, connack_body) =
        tokio::time::timeout(TIMEOUT, read_mqtt_packet(&mut client_sock))
            .await
            .expect("client reads CONNACK in time")
            .expect("client reads CONNACK");
    assert_eq!(packet_type, 0x20, "edge answers with CONNACK");
    assert_eq!(
        connack_body,
        vec![0x00, 0x00],
        "CONNACK signals session-present=false, return-code=accepted"
    );

    // The edge bound this client to one of its own connections: learn
    // which (the edge assigns the conn id, never the test).
    let edge_conn_id = {
        let deadline = Instant::now() + BOOT_BUDGET;
        loop {
            if let Some(session) = sessions.get(CLIENT_ID) {
                if let Some(conn_id) = *session.conn_id.read() {
                    break conn_id;
                }
            }
            if Instant::now() >= deadline {
                panic!("kernel never bound {CLIENT_ID} (edge bind missing?)");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    // Authenticated kick through the real HTTP route. The first token
    // still carries `must_change_password`, so it only opens the login
    // and password-change routes: change the password, log in again,
    // then kick with the fully-privileged token.
    let http = reqwest::Client::new();
    let login = tokio::time::timeout(
        TIMEOUT,
        http.post(format!("{base}/api/v5/login"))
            .json(&serde_json::json!({"username": "admin", "password": "public"}))
            .send(),
    )
    .await
    .expect("login request in time")
    .expect("login request");
    assert_eq!(login.status(), 200);
    let login_body: serde_json::Value = tokio::time::timeout(TIMEOUT, login.json())
        .await
        .expect("login body in time")
        .expect("login body");
    let fresh = login_body["token"]
        .as_str()
        .expect("login token")
        .to_string();
    let changed = tokio::time::timeout(
        TIMEOUT,
        http.put(format!("{base}/api/v5/users/admin/change_pwd"))
            .bearer_auth(&fresh)
            .json(&serde_json::json!({"old_pwd": "public", "new_pwd": "Kick-e2e-1!"}))
            .send(),
    )
    .await
    .expect("change password request in time")
    .expect("change password request");
    assert_eq!(changed.status(), 204);
    let login = tokio::time::timeout(
        TIMEOUT,
        http.post(format!("{base}/api/v5/login"))
            .json(&serde_json::json!({"username": "admin", "password": "Kick-e2e-1!"}))
            .send(),
    )
    .await
    .expect("second login request in time")
    .expect("second login request");
    assert_eq!(login.status(), 200);
    let login_body: serde_json::Value = tokio::time::timeout(TIMEOUT, login.json())
        .await
        .expect("login body in time")
        .expect("login body");
    let token = login_body["token"]
        .as_str()
        .expect("login token")
        .to_string();

    let kick = tokio::time::timeout(
        TIMEOUT,
        http.delete(format!("{base}/api/v5/clients/{CLIENT_ID}"))
            .bearer_auth(&token)
            .send(),
    )
    .await
    .expect("kick request in time")
    .expect("kick request");
    assert_eq!(kick.status(), 204);

    // The shipped edge got `ConnClose` for its connection and closed
    // the client socket, so the MQTT client observes TCP close. A
    // regressed unregister-first kick order drops the close here and
    // this read times out instead of passing.
    let mut probe = [0u8; 1];
    let closed = tokio::time::timeout(TIMEOUT, client_sock.read(&mut probe))
        .await
        .expect("client sees close in time")
        .expect("client read succeeds");
    assert_eq!(
        closed, 0,
        "client socket for edge conn {edge_conn_id} is closed by the kick"
    );

    // Kernel state is torn down as before.
    let session = sessions.get(CLIENT_ID).expect("session survives kick");
    assert_eq!(*session.conn_id.read(), None);
    assert!(!*session.connected.read());

    api_task.abort();
    acceptor.abort();
    forwarder.abort();
    let _ = edge_child.kill().await;
    if let Some((program, args)) = edge.cleanup {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = e2e_command_output(&program, &refs, TIMEOUT).await;
    }
    if let Some(mut proxy) = edge.proxy {
        let _ = proxy.kill().await;
    }
    let _ = std::fs::remove_file(&edge_log);
}

/// Bound for every BrokerLink wait in the sharded-transports test: a
/// regressed kernel fails the test instead of hanging the worker.
const SHARD_E2E_STEP: std::time::Duration = std::time::Duration::from_secs(10);

/// Budget for spawning the real kernel binary and waiting for its
/// BrokerLink listener (a cold debug boot is slower than one step).
const SHARD_E2E_BOOT: std::time::Duration = std::time::Duration::from_secs(60);

/// Encode `BindConnection` metadata (`ClientIdLen:16be | ClientId |
/// Flags:8 | Keepalive:16be`), mirroring the kernel's `decode_bind_meta`.
fn shard_encode_bind(client_id: &str, clean_start: bool, keepalive: u16) -> bytes::Bytes {
    let id = client_id.as_bytes();
    let mut meta = Vec::with_capacity(2 + id.len() + 1 + 2);
    meta.extend_from_slice(&(id.len() as u16).to_be_bytes());
    meta.extend_from_slice(id);
    meta.push(u8::from(clean_start));
    meta.extend_from_slice(&keepalive.to_be_bytes());
    bytes::Bytes::from(meta)
}

/// Will-carrying bind parameters for [`shard_encode_bind_with_will_and_alias`].
/// Grouped in one struct so the helper stays under the argument-count lint.
struct ShardWillBind<'a> {
    client_id: &'a str,
    clean_start: bool,
    keepalive: u16,
    will_topic: &'a str,
    will_payload: &'a [u8],
    will_qos: u8,
    will_retain: bool,
    client_alias_max: u16,
}

/// Encode `BindConnection` metadata with an F1-01 last-will section plus
/// the B4-05 trailing `ClientAliasMax:16be` (the canonical encoding the
/// edge sends for a WebSocket connection carrying PSK identity, will and
/// alias state together): will-bit head, then
/// `WillQos:8 | WillRetain:8 | TopicLen:16be | Topic |
/// PayloadLen:32be | Payload`, then the alias maximum.
fn shard_encode_bind_with_will_and_alias(params: ShardWillBind<'_>) -> bytes::Bytes {
    let id = params.client_id.as_bytes();
    let mut meta = Vec::new();
    meta.extend_from_slice(&(id.len() as u16).to_be_bytes());
    meta.extend_from_slice(id);
    meta.push(u8::from(params.clean_start) | 0x02);
    meta.extend_from_slice(&params.keepalive.to_be_bytes());
    meta.push(params.will_qos);
    meta.push(u8::from(params.will_retain));
    meta.extend_from_slice(&(params.will_topic.len() as u16).to_be_bytes());
    meta.extend_from_slice(params.will_topic.as_bytes());
    meta.extend_from_slice(&(params.will_payload.len() as u32).to_be_bytes());
    meta.extend_from_slice(params.will_payload);
    meta.extend_from_slice(&params.client_alias_max.to_be_bytes());
    bytes::Bytes::from(meta)
}

/// Encode `PubAckIn` metadata (`PacketId:16be | RC:8`) for one downlink ack.
fn shard_encode_puback(packet_id: u16) -> bytes::Bytes {
    let mut meta = Vec::with_capacity(3);
    meta.extend_from_slice(&packet_id.to_be_bytes());
    meta.push(0u8);
    bytes::Bytes::from(meta)
}

/// Encode `DisconnectIn`/`UnbindConnection` metadata (`IdLen:16be | ClientId`).
fn shard_encode_client_id(client_id: &str) -> bytes::Bytes {
    let id = client_id.as_bytes();
    let mut meta = Vec::with_capacity(2 + id.len());
    meta.extend_from_slice(&(id.len() as u16).to_be_bytes());
    meta.extend_from_slice(id);
    bytes::Bytes::from(meta)
}

/// One ephemeral loopback port for a test kernel's BrokerLink listener.
fn shard_ephemeral_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
    probe.local_addr().expect("port").port()
}

/// Spawn one real kernel with the given extra argv (after the standard
/// `--brokerlink-bind/--api-bind/--data-dir/--allow-anonymous` prefix),
/// wait for its BrokerLink listener, and return the child plus address.
/// The caller owns `child.kill()` (plus scratch cleanup where relevant).
async fn shard_spawn_kernel(
    extra_argv: &[&str],
    scratch: &std::path::Path,
    bl_port: u16,
) -> (tokio::process::Child, std::net::SocketAddr) {
    let mut child = tokio::process::Command::new(shard_kernel_binary());
    child
        .arg("--brokerlink-bind")
        .arg(format!("127.0.0.1:{bl_port}"))
        .arg("--api-bind")
        .arg("")
        .arg("--data-dir")
        .arg(scratch)
        .arg("--allow-anonymous");
    for arg in extra_argv {
        child.arg(arg);
    }
    let mut child = child
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn real kernel");
    let addr: std::net::SocketAddr = format!("127.0.0.1:{bl_port}").parse().expect("addr");
    let deadline = std::time::Instant::now() + SHARD_E2E_BOOT;
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                break;
            }
            Err(error) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill().await;
                    panic!("kernel never opened BrokerLink {bl_port}: {error}");
                }
                if let Ok(Some(status)) = child.try_wait() {
                    panic!("kernel exited during boot: {status}");
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    (child, addr)
}

/// Decode `SessionBinding` metadata into `(session_id, present, rc,
/// alias_max)`. Accepts 10-byte (pre-alias, alias maximum 0) and 12-byte
/// (B4-05 with trailing Topic Alias Maximum) encodings; the trailing
/// maximum is asserted by the alias negotiation test below.
fn shard_decode_binding(meta: &[u8]) -> (u64, bool, u8, u16) {
    assert!(
        meta.len() == 10 || meta.len() == 12,
        "SessionBinding meta must be 10 or 12 bytes, got {}",
        meta.len()
    );
    let session_id = u64::from_be_bytes(meta[0..8].try_into().unwrap());
    let alias_max = if meta.len() == 12 {
        u16::from_be_bytes([meta[10], meta[11]])
    } else {
        0
    };
    (session_id, meta[8] != 0, meta[9], alias_max)
}

/// Decode `SessionBinding` metadata into `(session_id, present, rc)`,
/// ignoring the trailing alias maximum (legacy callers).
fn shard_decode_binding_legacy(meta: &[u8]) -> (u64, bool, u8) {
    let (session_id, present, rc, _) = shard_decode_binding(meta);
    (session_id, present, rc)
}

/// Encode `SubscribeMeta` (`PacketId:16be | IdLen:16be | ClientId |
/// N:16be | (FilterLen:16be | Filter | QoS:8) * N`).
fn shard_encode_subscribe(packet_id: u16, client_id: &str, subs: &[(&str, u8)]) -> bytes::Bytes {
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
    bytes::Bytes::from(meta)
}

/// Encode `PublishMeta` (`TopicLen:16be | Topic | PacketId:16be |
/// QoS:8 | Retain:8 | Dup:8`) plus the raw payload.
fn shard_encode_publish(
    topic: &str,
    packet_id: u16,
    qos: u8,
    retain: bool,
    payload: &[u8],
) -> (bytes::Bytes, bytes::Bytes) {
    let mut meta = Vec::new();
    meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    meta.extend_from_slice(topic.as_bytes());
    meta.extend_from_slice(&packet_id.to_be_bytes());
    meta.push(qos);
    meta.push(u8::from(retain));
    meta.push(0u8);
    (
        bytes::Bytes::from(meta),
        bytes::Bytes::from(payload.to_vec()),
    )
}

/// Encode `PublishMeta` with the trailing B4-05 alias section
/// (`Alias:16be`). An empty topic with a nonzero alias encodes
/// alias-by-reference; absent-alias callers use
/// [`shard_encode_publish`].
fn shard_encode_publish_with_alias(
    topic: &str,
    packet_id: u16,
    qos: u8,
    retain: bool,
    alias: u16,
    payload: &[u8],
) -> (bytes::Bytes, bytes::Bytes) {
    let mut meta = Vec::new();
    meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    meta.extend_from_slice(topic.as_bytes());
    meta.extend_from_slice(&packet_id.to_be_bytes());
    meta.push(qos);
    meta.push(u8::from(retain));
    meta.push(0u8);
    meta.extend_from_slice(&alias.to_be_bytes());
    (
        bytes::Bytes::from(meta),
        bytes::Bytes::from(payload.to_vec()),
    )
}

/// Decode `PublishOut` metadata into `(topic, packet_id, qos, alias)`.
/// The kernel always appends the B4-05 alias section, so the meta is
/// `TopicLen:16be | Topic | PacketId:16be | QoS:8 | Retain:8 | Dup:8 |
/// Alias:16be`, optionally followed by the X1-03 subscription-identifier
/// trailer `SubId:32be` (absent for version-4 deliveries) and the X1-03
/// forwarded v5 section `Format:8 | Expiry:32be | users' (absent when
/// the publish carried no properties).
fn shard_decode_publish_out(meta: &[u8]) -> (String, u16, u8, u16) {
    let topic_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    let base = 2 + topic_len;
    assert!(
        meta.len() == base + 2 + 3 + 2
            || meta.len() == base + 2 + 3 + 2 + 4
            || meta.len() >= base + 2 + 3 + 2 + 4 + 1 + 4 + 2,
        "PublishOut meta must carry the trailing alias section, got {} bytes",
        meta.len()
    );
    let topic = std::str::from_utf8(&meta[2..base])
        .expect("topic UTF-8")
        .to_string();
    let packet_id = u16::from_be_bytes([meta[base], meta[base + 1]]);
    let qos = meta[base + 2];
    let alias = u16::from_be_bytes([meta[base + 5], meta[base + 6]]);
    (topic, packet_id, qos, alias)
}

/// Locate the real kernel binary for the sharded-transports test.
/// `CARGO_BIN_EXE_indramqtt` is set when Cargo builds the test target;
/// the probe fallback covers binaries built by an earlier explicit
/// `cargo build -p broker-node` under either target directory.
fn shard_kernel_binary() -> std::path::PathBuf {
    if let Some(built) = option_env!("CARGO_BIN_EXE_indramqtt") {
        return std::path::PathBuf::from(built);
    }
    let exe = if cfg!(windows) {
        "indramqtt.exe"
    } else {
        "indramqtt"
    };
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for candidate in [
        manifest.join(format!("../target/debug/{exe}")),
        manifest.join(format!("../target/ci-check/debug/{exe}")),
    ] {
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "sharded kernel binary not found: run `cargo build -p broker-node` first \
         (CARGO_BIN_EXE_indramqtt unset and no binary under target/debug or target/ci-check/debug)"
    );
}

/// Extract the downlink packet id from `PublishOut` metadata
/// (`TopicLen:16be | Topic | PacketId:16be | QoS:8 | Retain:8 | Dup:8`).
fn shard_downlink_packet_id(meta: &[u8]) -> u16 {
    let topic_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    let base = 2 + topic_len;
    u16::from_be_bytes([meta[base], meta[base + 1]])
}

/// Bind one client over `transport`, asserting the accepted
/// `SessionBinding` reply. Returns `(session_id, present)`.
async fn shard_bind(
    transport: &brokerlink::FramedTransport<tokio::net::TcpStream>,
    conn_id: u64,
    client_id: &str,
    clean_start: bool,
) -> (u64, bool) {
    use brokerlink::{BrokerFrame, BrokerLinkTransport, OpCode};
    let frame = BrokerFrame::new(
        OpCode::BindConnection,
        conn_id,
        1,
        shard_encode_bind(client_id, clean_start, 60),
        bytes::Bytes::new(),
    )
    .expect("valid bind frame");
    tokio::time::timeout(SHARD_E2E_STEP, transport.send(frame))
        .await
        .expect("bind send in time")
        .expect("bind send");
    let reply = tokio::time::timeout(SHARD_E2E_STEP, transport.recv())
        .await
        .expect("bind reply in time")
        .expect("bind reply");
    assert_eq!(reply.header.opcode, OpCode::SessionBinding);
    assert_eq!(reply.header.conn_id, conn_id);
    let (session_id, present, rc) = shard_decode_binding_legacy(&reply.metadata);
    assert_eq!(rc, 0, "bind of {client_id} must be accepted");
    assert_ne!(session_id, 0);
    (session_id, present)
}

/// B4-05 end-to-end alias assertion through the broker: CONNACK carries
/// the configured Topic Alias Maximum, an alias publish delivers the
/// correct topic, and the alias value itself rides the downlink frame.
#[tokio::test]
async fn sharded_topic_alias_negotiation_and_delivery() {
    use brokerlink::{BrokerFrame, BrokerLinkTransport, FramedTransport, OpCode};
    let scratch = std::env::temp_dir().join(format!(
        "indramqtt-alias-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let bl_port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
        probe.local_addr().expect("port").port()
    };
    let mut child = tokio::process::Command::new(shard_kernel_binary())
        .arg("--brokerlink-bind")
        .arg(format!("127.0.0.1:{bl_port}"))
        .arg("--api-bind")
        .arg("")
        .arg("--data-dir")
        .arg(&scratch)
        .arg("--allow-anonymous")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn real kernel");
    let addr: std::net::SocketAddr = format!("127.0.0.1:{bl_port}").parse().expect("addr");
    let deadline = std::time::Instant::now() + SHARD_E2E_BOOT;
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                break;
            }
            Err(_) => {
                if std::time::Instant::now() >= deadline {
                    panic!("kernel did not listen in time");
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let transport = FramedTransport::new(stream);
    // Bind asserts CONNACK carries the configured maximum (12-byte form).
    let bind = BrokerFrame::new(
        OpCode::BindConnection,
        201,
        1,
        shard_encode_bind("alias-e2e-1", false, 60),
        bytes::Bytes::new(),
    )
    .expect("valid bind");
    tokio::time::timeout(SHARD_E2E_STEP, transport.send(bind))
        .await
        .expect("send in time")
        .expect("send");
    let reply = tokio::time::timeout(SHARD_E2E_STEP, transport.recv())
        .await
        .expect("reply in time")
        .expect("reply");
    let (_, _, rc, alias_max) = shard_decode_binding(&reply.metadata);
    assert_eq!(rc, 0);
    assert!(
        alias_max > 0,
        "CONNACK carries the configured alias maximum"
    );
    // An alias publish through the broker delivers the correct topic,
    // and the alias value itself rides the downlink frame (outbound
    // direction). The subscriber binds on the same transport.
    let pub_conn = 201u64;
    let sub_conn = 202u64;
    let sub_bind = BrokerFrame::new(
        OpCode::BindConnection,
        sub_conn,
        2,
        shard_encode_bind("alias-e2e-2", false, 60),
        bytes::Bytes::new(),
    )
    .expect("valid bind");
    tokio::time::timeout(SHARD_E2E_STEP, transport.send(sub_bind))
        .await
        .expect("send in time")
        .expect("send");
    let sub_reply = tokio::time::timeout(SHARD_E2E_STEP, transport.recv())
        .await
        .expect("reply in time")
        .expect("reply");
    assert_eq!(sub_reply.header.opcode, OpCode::SessionBinding);
    let sub = BrokerFrame::new(
        OpCode::SubscribeIn,
        sub_conn,
        3,
        shard_encode_subscribe(1, "alias-e2e-2", &[("alias/e2e", 0)]),
        bytes::Bytes::new(),
    )
    .expect("valid subscribe frame");
    tokio::time::timeout(SHARD_E2E_STEP, transport.send(sub))
        .await
        .expect("send in time")
        .expect("send");
    let suback = tokio::time::timeout(SHARD_E2E_STEP, transport.recv())
        .await
        .expect("suback in time")
        .expect("suback");
    assert_eq!(suback.header.opcode, OpCode::SubAckOut);
    // First publish carries topic + alias 3: registers the mapping and
    // delivers the full topic with the assigned downlink alias.
    let (meta, body) = shard_encode_publish_with_alias("alias/e2e", 0, 0, false, 3, b"21.5");
    let publish =
        BrokerFrame::new(OpCode::PublishIn, pub_conn, 4, meta, body).expect("valid publish frame");
    tokio::time::timeout(SHARD_E2E_STEP, transport.send(publish))
        .await
        .expect("send in time")
        .expect("send");
    let downlink = tokio::time::timeout(SHARD_E2E_STEP, transport.recv())
        .await
        .expect("downlink in time")
        .expect("downlink");
    assert_eq!(downlink.header.opcode, OpCode::PublishOut);
    assert_eq!(downlink.header.conn_id, sub_conn);
    let (topic, _, _, _) = shard_decode_publish_out(&downlink.metadata);
    assert_eq!(topic, "alias/e2e");
    assert_eq!(downlink.payload, bytes::Bytes::from_static(b"21.5"));
    // Second publish carries the empty topic + alias 3: the broker
    // resolves the alias and the subscriber still sees the topic.
    let (meta2, body2) = shard_encode_publish_with_alias("", 0, 0, false, 3, b"22.5");
    let publish2 = BrokerFrame::new(OpCode::PublishIn, pub_conn, 5, meta2, body2)
        .expect("valid publish frame");
    tokio::time::timeout(SHARD_E2E_STEP, transport.send(publish2))
        .await
        .expect("send in time")
        .expect("send");
    let downlink2 = tokio::time::timeout(SHARD_E2E_STEP, transport.recv())
        .await
        .expect("downlink in time")
        .expect("downlink");
    assert_eq!(downlink2.header.opcode, OpCode::PublishOut);
    assert_eq!(downlink2.header.conn_id, sub_conn);
    let (topic2, _, _, _) = shard_decode_publish_out(&downlink2.metadata);
    assert_eq!(topic2, "alias/e2e", "alias resolves to the correct topic");
    assert_eq!(downlink2.payload, bytes::Bytes::from_static(b"22.5"));
    let _ = child.kill().await;
}

/// K parallel BrokerLink transports against one real kernel are
/// first-class: concurrent publishes from every transport are all
/// answered and routed (no cross-transport serialization), and a dead
/// transport detaches every client bound on it (not just the last
/// bind), so a durable subscriber replays what was published while it
/// was gone.
///
/// Kernel side this exercises the production path end to end: the real
/// `indramqtt` binary serves `serve_brokerlink`, with one
/// `handle_connection` task per transport. The single-`bound` snapshot
/// fails the replay phase: only the last bind on the dropped transport
/// detaches, the first-bound subscriber leaks as connected, its message
/// routes into the pruned mailbox and is lost, and the reconnect sees
/// no replay.
#[tokio::test]
async fn sharded_transports_do_not_serialize() {
    use brokerlink::{BrokerFrame, BrokerLinkTransport, FramedTransport, OpCode};

    // K generic transports; the edge shards by `conn_id rem K`, so the
    // kernel must treat every transport as independent.
    const K: usize = 2;
    const BURST: u16 = 20;

    let scratch = std::env::temp_dir().join(format!(
        "indramqtt-shard-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let bl_port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
        probe.local_addr().expect("port").port()
    };
    let mut child = tokio::process::Command::new(shard_kernel_binary())
        .arg("--brokerlink-bind")
        .arg(format!("127.0.0.1:{bl_port}"))
        .arg("--api-bind")
        .arg("")
        .arg("--data-dir")
        .arg(&scratch)
        .arg("--allow-anonymous")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn real kernel");

    // Wait for the BrokerLink listener.
    let addr: std::net::SocketAddr = format!("127.0.0.1:{bl_port}").parse().expect("addr");
    let deadline = std::time::Instant::now() + SHARD_E2E_BOOT;
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                break;
            }
            Err(error) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill().await;
                    panic!("kernel never opened BrokerLink {bl_port}: {error}");
                }
                if let Ok(Some(status)) = child.try_wait() {
                    panic!("kernel exited during boot: {status}");
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }

    // Open K transports against the one kernel.
    let mut transports = Vec::with_capacity(K);
    for _ in 0..K {
        let io = tokio::time::timeout(SHARD_E2E_STEP, tokio::net::TcpStream::connect(addr))
            .await
            .expect("transport dial in time")
            .expect("transport dial");
        transports.push(FramedTransport::new(io));
    }
    let (t1, t2) = (&transports[0], &transports[1]);

    // Durable subscriber on T1, then a second bind on the same
    // transport (the multiplexing a shard performs).
    let (_, present) = shard_bind(t1, 11, "shard-sub", false).await;
    assert!(!present, "first durable bind reports session_present=false");
    let sub = BrokerFrame::new(
        OpCode::SubscribeIn,
        11,
        2,
        shard_encode_subscribe(1, "shard-sub", &[("shard/topic", 1)]),
        bytes::Bytes::new(),
    )
    .expect("valid subscribe frame");
    tokio::time::timeout(SHARD_E2E_STEP, t1.send(sub))
        .await
        .expect("subscribe in time")
        .expect("subscribe");
    let suback = tokio::time::timeout(SHARD_E2E_STEP, t1.recv())
        .await
        .expect("suback in time")
        .expect("suback");
    assert_eq!(suback.header.opcode, OpCode::SubAckOut);
    assert_eq!(&suback.metadata[..], &[0x00, 0x01, 0x01]);
    shard_bind(t1, 12, "shard-filler", true).await;
    shard_bind(t2, 21, "shard-pub", true).await;

    // Concurrent publishes from both transports: a burst on T2, one on
    // T1. Every publish is QoS 1, so each needs its own PubAck, and the
    // subscriber must see every delivery.
    for seq in 1..=BURST {
        let payload = format!("burst-{seq}");
        let (meta, body) = shard_encode_publish("shard/topic", seq, 1, false, payload.as_bytes());
        let frame = BrokerFrame::new(OpCode::PublishIn, 21, u64::from(seq) + 100, meta, body)
            .expect("valid publish frame");
        tokio::time::timeout(SHARD_E2E_STEP, t2.send(frame))
            .await
            .expect("burst send in time")
            .expect("burst send");
    }
    let (meta, body) = shard_encode_publish("shard/topic", 1, 1, false, b"solo");
    let solo =
        BrokerFrame::new(OpCode::PublishIn, 12, 200, meta, body).expect("valid publish frame");
    tokio::time::timeout(SHARD_E2E_STEP, t1.send(solo))
        .await
        .expect("solo send in time")
        .expect("solo send");

    // T1 carries both the subscriber (conn 11) and the solo publisher
    // (conn 12), so its PublishOut deliveries interleave with the solo
    // PubAck on the same transport. Drain T1 until the solo ack is seen
    // and every delivery arrived: T1's answer never stalls behind T2's
    // burst, and no delivery is lost or duped.
    let mut solo_acked = false;
    let mut seen = std::collections::HashSet::new();
    while !solo_acked || seen.len() < BURST as usize + 1 {
        let frame = tokio::time::timeout(SHARD_E2E_STEP, t1.recv())
            .await
            .expect("T1 frame in time")
            .expect("T1 frame");
        match frame.header.opcode {
            OpCode::PubAckOut => {
                assert_eq!(frame.header.conn_id, 12);
                assert_eq!(&frame.metadata[..], &[0x00, 0x01, 0x00]);
                assert!(!solo_acked, "solo PubAck delivered exactly once");
                solo_acked = true;
            }
            OpCode::PublishOut => {
                assert_eq!(frame.header.conn_id, 11);
                assert!(seen.insert(frame.payload.to_vec()), "no duped delivery");
                // T-31: ack every live QoS 1 downlink (correct MQTT
                // client behaviour) so nothing stays inflight at
                // detach; the reconnect then replays only what was
                // published while detached. No assertion below changes.
                let pid = shard_downlink_packet_id(&frame.metadata);
                assert_ne!(pid, 0, "QoS 1 downlink carries a packet id");
                let ack = BrokerFrame::new(
                    OpCode::PubAckIn,
                    11,
                    400 + seen.len() as u64,
                    shard_encode_puback(pid),
                    bytes::Bytes::new(),
                )
                .expect("valid puback frame");
                tokio::time::timeout(SHARD_E2E_STEP, t1.send(ack))
                    .await
                    .expect("puback in time")
                    .expect("puback send");
            }
            other => panic!("unexpected frame on T1: {other:?}"),
        }
    }
    assert!(seen.contains(b"solo".as_slice()));
    for seq in 1..=BURST {
        assert!(seen.contains(&format!("burst-{seq}").into_bytes()));
    }
    for seq in 1..=BURST {
        let ack = tokio::time::timeout(SHARD_E2E_STEP, t2.recv())
            .await
            .expect("burst PubAck in time")
            .expect("burst PubAck");
        assert_eq!(ack.header.opcode, OpCode::PubAckOut);
        assert_eq!(ack.header.conn_id, 21);
        assert_eq!(
            &ack.metadata[..],
            &[(seq >> 8) as u8, seq as u8, 0x00],
            "burst PubAck {seq} mirrors its packet id"
        );
    }

    // Kill T1 without DISCONNECT: both of its clients must detach.
    // (Dropping the transport closes its TCP connection; T2 stays live
    // at index 0 afterwards.)
    drop(transports.remove(0));
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Published while the durable subscriber is detached: queued, not
    // routed to the dead mailbox.
    let t2 = &transports[0];
    let (meta, body) = shard_encode_publish("shard/topic", 101, 1, false, b"replay-me");
    let frame =
        BrokerFrame::new(OpCode::PublishIn, 21, 300, meta, body).expect("valid publish frame");
    tokio::time::timeout(SHARD_E2E_STEP, t2.send(frame))
        .await
        .expect("detached publish in time")
        .expect("detached publish");
    let ack = tokio::time::timeout(SHARD_E2E_STEP, t2.recv())
        .await
        .expect("detached PubAck in time")
        .expect("detached PubAck");
    assert_eq!(ack.header.opcode, OpCode::PubAckOut);

    // Reconnect the durable subscriber on a fresh transport: the queued
    // message replays. On the single-`bound` snapshot this times out:
    // the first-bound client never detached, so the publish above was
    // dropped into the pruned mailbox instead of queued.
    let io = tokio::time::timeout(SHARD_E2E_STEP, tokio::net::TcpStream::connect(addr))
        .await
        .expect("reconnect in time")
        .expect("reconnect");
    let t3 = FramedTransport::new(io);
    let (_, present) = shard_bind(&t3, 31, "shard-sub", false).await;
    assert!(present, "resumed session must report session_present=true");
    let replayed = tokio::time::timeout(SHARD_E2E_STEP, t3.recv())
        .await
        .expect("replay arrives: every bind on a dead transport must detach")
        .expect("replay");
    assert_eq!(replayed.header.opcode, OpCode::PublishOut);
    assert_eq!(replayed.header.conn_id, 31);
    assert_eq!(replayed.payload, bytes::Bytes::from_static(b"replay-me"));

    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&scratch);
}

/// SY-02 edge harness: a spawned kernel plus the shipped Erlang edge.
///
/// The three SY-02 tests speak real MQTT through the edge (TCP and
/// WebSocket) the way production clients do, never `SessionManager` or
/// `Router` directly. Returns `None` (with a logged SKIP reason, like
/// [`e2e_edge_target`]) when the edge cannot run here; a spawned edge
/// that never opens its ports is a loud failure, never a skip.
struct Sy02Edge {
    child: tokio::process::Child,
    edge: EdgeTarget,
    log: std::path::PathBuf,
    mqtt_port: u16,
    ws_port: u16,
}

async fn sy02_spawn_edge(bl_port: u16) -> Option<Sy02Edge> {
    use std::time::{Duration, Instant};
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebin = manifest.join("../../beam/ebin");
    // The WebSocket listener beams must exist; without them the edge
    // supervisor cannot start and no port ever opens.
    if !ebin.join("indra_ws_listener.beam").is_file() {
        e2e_skip!(
            "SKIP sy02 edge test: no WS edge beams at {} (build beam/ first)",
            ebin.display()
        );
        return None;
    }
    let (edge, mqtt_port, ws_port) = e2e_edge_target(bl_port).await?;
    let log = std::env::temp_dir().join(format!(
        "indramqtt-sy02-edge-{}-{mqtt_port}.log",
        std::process::id()
    ));
    let edge_stderr = std::fs::File::create(&log).expect("edge log file");
    let mut child = tokio::process::Command::new(&edge.program)
        .args(&edge.args)
        .stdout(std::process::Stdio::null())
        .stderr(edge_stderr)
        .kill_on_drop(true)
        .spawn()
        .expect("spawn shipped edge");
    // Both listeners must open: the TCP MQTT port and the WebSocket
    // port. Fail fast when the VM dies instead of polling dead ports.
    let deadline = Instant::now() + SHARD_E2E_BOOT;
    loop {
        let mqtt_open = tokio::net::TcpStream::connect((edge.mqtt_host.as_str(), mqtt_port))
            .await
            .is_ok();
        let ws_open = tokio::net::TcpStream::connect((edge.mqtt_host.as_str(), ws_port))
            .await
            .is_ok();
        if mqtt_open && ws_open {
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let log_text = std::fs::read_to_string(&log).unwrap_or_default();
            let tail = &log_text[log_text.len().saturating_sub(2000)..];
            panic!("shipped edge exited during boot: {status}\nedge log tail:\n{tail}");
        }
        if Instant::now() >= deadline {
            let _ = child.kill().await;
            panic!("shipped edge never opened MQTT {mqtt_port} and WS {ws_port}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Some(Sy02Edge {
        child,
        edge,
        log,
        mqtt_port,
        ws_port,
    })
}

impl Sy02Edge {
    fn host(&self) -> &str {
        &self.edge.mqtt_host
    }

    async fn finish(mut self) {
        let _ = self.child.kill().await;
        if let Some((program, args)) = self.edge.cleanup {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = e2e_command_output(&program, &refs, KICK_E2E_STEP).await;
        }
        if let Some(mut proxy) = self.edge.proxy {
            let _ = proxy.kill().await;
        }
        let _ = std::fs::remove_file(&self.log);
    }
}

/// Encode an MQTT remaining length (variable-byte integer).
fn sy02_mqtt_rl(mut len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
    out
}

/// Encode an MQTT UTF-8 string (`len:16be | bytes`).
fn sy02_mqtt_str(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + s.len());
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out
}

/// Minimal MQTT 3.1.1 CONNECT with optional credentials.
fn sy02_connect311(
    client_id: &str,
    clean_start: bool,
    keepalive: u16,
    creds: Option<(&str, &[u8])>,
) -> Vec<u8> {
    let mut rest = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04];
    let mut flags = 0u8;
    if clean_start {
        flags |= 0x02;
    }
    if let Some((_, pass)) = creds {
        flags |= 0x80;
        if !pass.is_empty() {
            flags |= 0x40;
        }
    }
    rest.push(flags);
    rest.extend_from_slice(&keepalive.to_be_bytes());
    rest.extend_from_slice(&sy02_mqtt_str(client_id));
    if let Some((user, pass)) = creds {
        rest.extend_from_slice(&sy02_mqtt_str(user));
        rest.extend_from_slice(&(pass.len() as u16).to_be_bytes());
        rest.extend_from_slice(pass);
    }
    let mut packet = vec![0x10];
    packet.extend_from_slice(&sy02_mqtt_rl(rest.len()));
    packet.extend_from_slice(&rest);
    packet
}

/// MQTT 5 CONNECT with optional credentials, an optional last will and
/// the client's Topic Alias Maximum (property 34, the kernel outbound
/// bound; 0 sends an empty property section).
fn sy02_connect5(
    client_id: &str,
    clean_start: bool,
    keepalive: u16,
    creds: Option<(&str, &[u8])>,
    will: Option<(&str, &[u8])>,
    alias_max: u16,
) -> Vec<u8> {
    let mut rest = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x05];
    let mut flags = 0u8;
    if let Some((_, pass)) = creds {
        flags |= 0x80;
        if !pass.is_empty() {
            flags |= 0x40;
        }
    }
    if will.is_some() {
        flags |= 0x04;
    }
    if clean_start {
        flags |= 0x02;
    }
    rest.push(flags);
    rest.extend_from_slice(&keepalive.to_be_bytes());
    let mut props: Vec<u8> = Vec::new();
    if !clean_start {
        // MQTT 5: a session stays after the disconnect only if the client
        // sends a Session Expiry Interval (property 17). A client that
        // resumes its session asks for one hour.
        props.push(17);
        props.extend_from_slice(&3600u32.to_be_bytes());
    }
    if alias_max != 0 {
        props.push(34);
        props.extend_from_slice(&alias_max.to_be_bytes());
    }
    rest.push(props.len() as u8);
    rest.extend_from_slice(&props);
    rest.extend_from_slice(&sy02_mqtt_str(client_id));
    if will.is_some() {
        // Empty will-property section, then topic and payload.
        rest.push(0x00);
    }
    if let Some((will_topic, will_payload)) = will {
        rest.extend_from_slice(&sy02_mqtt_str(will_topic));
        rest.extend_from_slice(&(will_payload.len() as u16).to_be_bytes());
        rest.extend_from_slice(will_payload);
    }
    if let Some((user, pass)) = creds {
        rest.extend_from_slice(&sy02_mqtt_str(user));
        rest.extend_from_slice(&(pass.len() as u16).to_be_bytes());
        rest.extend_from_slice(pass);
    }
    let mut packet = vec![0x10];
    packet.extend_from_slice(&sy02_mqtt_rl(rest.len()));
    packet.extend_from_slice(&rest);
    packet
}

/// Classic SUBSCRIBE (`packet id | filter | qos ...`): the shape the
/// edge decodes on every session, 3.1.1 and 5 alike.
fn sy02_subscribe(packet_id: u16, subs: &[(&str, u8)]) -> Vec<u8> {
    let mut rest = Vec::new();
    rest.extend_from_slice(&packet_id.to_be_bytes());
    for (filter, qos) in subs {
        rest.extend_from_slice(&sy02_mqtt_str(filter));
        rest.push(*qos);
    }
    let mut packet = vec![0x82];
    packet.extend_from_slice(&sy02_mqtt_rl(rest.len()));
    packet.extend_from_slice(&rest);
    packet
}

/// MQTT 3.1.1 PUBLISH (client to edge).
fn sy02_publish311(topic: &str, packet_id: u16, qos: u8, retain: bool, payload: &[u8]) -> Vec<u8> {
    let mut rest = sy02_mqtt_str(topic);
    if qos > 0 {
        rest.extend_from_slice(&packet_id.to_be_bytes());
    }
    rest.extend_from_slice(payload);
    let mut flags = qos << 1;
    if retain {
        flags |= 0x01;
    }
    let mut packet = vec![0x30 | flags];
    packet.extend_from_slice(&sy02_mqtt_rl(rest.len()));
    packet.extend_from_slice(&rest);
    packet
}

/// MQTT 5 PUBLISH (client to edge): `topic | packet id | properties |
/// payload`. `Some(alias)` registers the alias (property 35);
/// `None` sends an empty property section.
fn sy02_publish5(
    topic: &str,
    packet_id: u16,
    qos: u8,
    retain: bool,
    alias: Option<u16>,
    payload: &[u8],
) -> Vec<u8> {
    let mut rest = sy02_mqtt_str(topic);
    if qos > 0 {
        rest.extend_from_slice(&packet_id.to_be_bytes());
    }
    match alias {
        Some(value) => {
            rest.push(0x03);
            rest.push(35);
            rest.extend_from_slice(&value.to_be_bytes());
        }
        None => rest.push(0x00),
    }
    rest.extend_from_slice(payload);
    let mut flags = qos << 1;
    if retain {
        flags |= 0x01;
    }
    let mut packet = vec![0x30 | flags];
    packet.extend_from_slice(&sy02_mqtt_rl(rest.len()));
    packet.extend_from_slice(&rest);
    packet
}

/// Two-byte PUBACK (packet id only): the shape the edge forwards to the
/// kernel on every session, 3.1.1 and 5 alike.
fn sy02_puback(packet_id: u16) -> Vec<u8> {
    vec![0x40, 0x02, (packet_id >> 8) as u8, (packet_id & 0xff) as u8]
}

/// Encode a variable-byte integer (MQTT property lengths and ids).
fn sy02_encode_varint(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

/// MQTT 5 SUBSCRIBE with per-filter options plus the packet-wide
/// subscription identifier (X1-03): `packet id | props | filters`.
/// `sub_id` 0 sends an empty property section.
fn sy02_subscribe_v5(packet_id: u16, subs: &[(&str, u8)], sub_id: u32) -> Vec<u8> {
    let mut props = Vec::new();
    if sub_id != 0 {
        props.push(11u8);
        props.extend_from_slice(&sy02_encode_varint(sub_id));
    }
    let mut rest = Vec::new();
    rest.extend_from_slice(&packet_id.to_be_bytes());
    rest.extend_from_slice(&sy02_encode_varint(props.len() as u32));
    rest.extend_from_slice(&props);
    for (filter, opts) in subs {
        rest.extend_from_slice(&sy02_mqtt_str(filter));
        rest.push(*opts);
    }
    let mut packet = vec![0x82];
    packet.extend_from_slice(&sy02_mqtt_rl(rest.len()));
    packet.extend_from_slice(&rest);
    packet
}

/// MQTT 5 PUBLISH with forwarded properties (X1-03): payload format,
/// message expiry and user properties ride the property section.
/// `format`/`expiry` `None` omits the property; empty `users` omits it.
fn sy02_publish5_with_props(
    topic: &str,
    qos: u8,
    retain: bool,
    format: Option<u8>,
    expiry: Option<u32>,
    users: &[(&str, &str)],
    payload: &[u8],
) -> Vec<u8> {
    let mut props = Vec::new();
    if let Some(f) = format {
        props.push(1u8);
        props.push(f);
    }
    if let Some(e) = expiry {
        props.push(2u8);
        props.extend_from_slice(&e.to_be_bytes());
    }
    for (k, v) in users {
        props.push(38u8);
        props.extend_from_slice(&sy02_mqtt_str(k));
        props.extend_from_slice(&sy02_mqtt_str(v));
    }
    let mut rest = sy02_mqtt_str(topic);
    // QoS 0 in this test: no packet id.
    assert_eq!(qos, 0, "X1-03 edge test uses QoS 0");
    rest.extend_from_slice(&sy02_encode_varint(props.len() as u32));
    rest.extend_from_slice(&props);
    rest.extend_from_slice(payload);
    let mut flags = qos << 1;
    if retain {
        flags |= 0x01;
    }
    let mut packet = vec![0x30 | flags];
    packet.extend_from_slice(&sy02_mqtt_rl(rest.len()));
    packet.extend_from_slice(&rest);
    packet
}

/// MQTT 5 DISCONNECT with a reason code (X1-03): `reason | props(empty)`.
fn sy02_disconnect_v5(reason: u8) -> Vec<u8> {
    let body = vec![reason, 0x00];
    let mut packet = vec![0xE0];
    packet.extend_from_slice(&sy02_mqtt_rl(body.len()));
    packet.extend_from_slice(&body);
    packet
}

/// Parse an MQTT 5 SUBACK body into `(packet_id, granted codes)`,
/// skipping the property section.
fn sy02_parse_suback5(body: &[u8]) -> (u16, Vec<u8>) {
    assert!(body.len() >= 3, "v5 SUBACK carries packet id and props");
    let packet_id = u16::from_be_bytes([body[0], body[1]]);
    let (prop_len, used) = sy02_varint(&body[2..]).expect("SUBACK property length");
    assert!(body.len() >= 2 + used + prop_len, "SUBACK props fit");
    (packet_id, body[2 + used + prop_len..].to_vec())
}

/// One MQTT 5 PUBLISH as the edge delivers it, with forwarded props.
struct Sy02Publish5 {
    topic: String,
    qos: u8,
    sub_id: u32,
    format: u8,
    expiry: u32,
    users: Vec<(String, String)>,
    payload: Vec<u8>,
}

/// Parse an MQTT 5 PUBLISH body (QoS 0): topic, property section
/// (subscription id 11, format 1, expiry 2, user 38, alias 35 skipped)
/// and payload.
fn sy02_parse_publish_v5(header: u8, body: &[u8]) -> Sy02Publish5 {
    let qos = (header >> 1) & 0x03;
    assert_eq!(qos, 0, "X1-03 edge test uses QoS 0");
    assert!(body.len() >= 2, "PUBLISH carries a topic");
    let topic_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let topic = std::str::from_utf8(&body[2..2 + topic_len])
        .expect("topic UTF-8")
        .to_string();
    let mut rest = &body[2 + topic_len..];
    let (prop_len, used) = sy02_varint(rest).expect("PUBLISH property length");
    rest = &rest[used..];
    assert!(rest.len() >= prop_len, "PUBLISH props fit");
    let mut props = &rest[..prop_len];
    let mut sub_id = 0u32;
    let mut format = 0u8;
    let mut expiry = 0u32;
    let mut users = Vec::new();
    while !props.is_empty() {
        let (id, used) = sy02_varint(props).expect("property id");
        props = &props[used..];
        match id {
            11 => {
                let (v, used) = sy02_varint(props).expect("sub id varint");
                sub_id = v as u32;
                props = &props[used..];
            }
            1 => {
                assert!(!props.is_empty(), "format carries a byte");
                format = props[0];
                props = &props[1..];
            }
            2 => {
                assert!(props.len() >= 4, "expiry carries a u32");
                expiry = u32::from_be_bytes([props[0], props[1], props[2], props[3]]);
                props = &props[4..];
            }
            35 => {
                assert!(props.len() >= 2, "alias carries a u16");
                props = &props[2..];
            }
            38 => {
                assert!(props.len() >= 2, "user key length");
                let k_len = u16::from_be_bytes([props[0], props[1]]) as usize;
                assert!(props.len() >= 2 + k_len + 2, "user key fits");
                let k = std::str::from_utf8(&props[2..2 + k_len])
                    .expect("user key UTF-8")
                    .to_string();
                let v_len = u16::from_be_bytes([props[2 + k_len], props[2 + k_len + 1]]) as usize;
                assert!(props.len() >= 2 + k_len + 2 + v_len, "user value fits");
                let v = std::str::from_utf8(&props[2 + k_len + 2..2 + k_len + 2 + v_len])
                    .expect("user value UTF-8")
                    .to_string();
                users.push((k, v));
                props = &props[2 + k_len + 2 + v_len..];
            }
            _ => panic!("unexpected v5 PUBLISH property {id}"),
        }
    }
    Sy02Publish5 {
        topic,
        qos,
        sub_id,
        format,
        expiry,
        users,
        payload: rest[prop_len..].to_vec(),
    }
}

/// Decode one variable-byte integer, returning `(value, bytes used)`.
fn sy02_varint(mut bytes: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    let mut used = 0usize;
    loop {
        let byte = *bytes.first()?;
        bytes = &bytes[1..];
        used += 1;
        value += ((byte & 0x7F) as usize) * (128usize.pow(used as u32 - 1));
        if byte & 0x80 == 0 {
            return Some((value, used));
        }
        if used == 4 {
            return None;
        }
    }
}

/// Parse a 3.1.1 CONNACK body into `(session_present, return_code)`.
fn sy02_parse_connack311(body: &[u8]) -> (bool, u8) {
    assert_eq!(body.len(), 2, "3.1.1 CONNACK body is two bytes");
    (body[0] & 0x01 != 0, body[1])
}

/// Parse an MQTT 5 CONNACK body into `(session_present, reason, alias_max)`.
/// Scans the property section for the Topic Alias Maximum (34) while
/// accepting every other property the edge may advertise on the live
/// handshake path (X1-02): session expiry (17, u32), assigned client
/// id (18, UTF-8), server receive maximum (33, u16), server maximum
/// packet size (39, u32), reason string (31, UTF-8) and user
/// properties (38, UTF-8 pair). A strict match on 34 alone rejects the
/// negotiated limits the kernel advertises on every v5 CONNACK, so the
/// parser records the alias maximum and skips the rest instead.
fn sy02_parse_connack5(body: &[u8]) -> (bool, u8, u16) {
    assert!(
        body.len() >= 3,
        "MQTT 5 CONNACK carries flags, reason and properties"
    );
    let present = body[0] & 0x01 != 0;
    let reason = body[1];
    let (prop_len, used) = sy02_varint(&body[2..]).expect("CONNACK property length");
    let mut props = &body[2 + used..];
    assert!(props.len() >= prop_len, "CONNACK properties fit the body");
    props = &props[..prop_len];
    // Skip one length-prefixed UTF-8 string, returning the remainder.
    fn skip_utf8<'a>(buf: &'a [u8], what: &str) -> &'a [u8] {
        assert!(buf.len() >= 2, "{what} carries a length");
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        assert!(buf.len() >= 2 + len, "{what} fits the body");
        &buf[2 + len..]
    }
    let mut alias_max = 0u16;
    while !props.is_empty() {
        let (id, used) = sy02_varint(props).expect("CONNACK property id");
        props = &props[used..];
        match id {
            17 => {
                assert!(props.len() >= 4, "session-expiry property carries a u32");
                props = &props[4..];
            }
            18 => {
                props = skip_utf8(props, "assigned-client-id property");
            }
            33 => {
                assert!(props.len() >= 2, "receive-maximum property carries a u16");
                props = &props[2..];
            }
            34 => {
                assert!(props.len() >= 2, "alias-maximum property carries a u16");
                alias_max = u16::from_be_bytes([props[0], props[1]]);
                props = &props[2..];
            }
            28 | 31 => {
                props = skip_utf8(props, "reason-string property");
            }
            38 => {
                props = skip_utf8(props, "user-property key");
                props = skip_utf8(props, "user-property value");
            }
            39 => {
                assert!(
                    props.len() >= 4,
                    "maximum-packet-size property carries a u32"
                );
                props = &props[4..];
            }
            _ => panic!("unexpected CONNACK property {id}"),
        }
    }
    (present, reason, alias_max)
}

/// Parse a classic SUBACK body into `(packet_id, granted codes)`.
fn sy02_parse_suback(body: &[u8]) -> (u16, Vec<u8>) {
    assert!(body.len() >= 3, "SUBACK carries a packet id plus codes");
    (u16::from_be_bytes([body[0], body[1]]), body[2..].to_vec())
}

/// One PUBLISH as the edge delivers it to a subscribing client.
struct Sy02Publish {
    topic: String,
    packet_id: u16,
    qos: u8,
    retain: bool,
    dup: bool,
    alias: u16,
    payload: Vec<u8>,
}

/// Parse a classic-shape PUBLISH (no property section): live retained
/// replays, offline replays and every delivery toward a client that
/// negotiated no outbound alias.
fn sy02_parse_publish_classic(header: u8, body: &[u8]) -> Sy02Publish {
    let dup = header & 0x08 != 0;
    let qos = (header >> 1) & 0x03;
    let retain = header & 0x01 != 0;
    assert!(body.len() >= 2, "PUBLISH carries a topic");
    let topic_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    assert!(body.len() >= 2 + topic_len, "PUBLISH topic fits the body");
    let topic = std::str::from_utf8(&body[2..2 + topic_len])
        .expect("PUBLISH topic UTF-8")
        .to_string();
    let mut rest = &body[2 + topic_len..];
    let packet_id = if qos > 0 {
        assert!(rest.len() >= 2, "PUBLISH carries a packet id");
        let id = u16::from_be_bytes([rest[0], rest[1]]);
        rest = &rest[2..];
        id
    } else {
        0
    };
    Sy02Publish {
        topic,
        packet_id,
        qos,
        retain,
        dup,
        alias: 0,
        payload: rest.to_vec(),
    }
}

/// Parse an alias-carrying PUBLISH (the edge appends the alias property
/// after a one-byte property length when the kernel assigned one):
/// live deliveries toward a subscriber that negotiated a maximum.
fn sy02_parse_publish_alias(header: u8, body: &[u8]) -> Sy02Publish {
    let dup = header & 0x08 != 0;
    let qos = (header >> 1) & 0x03;
    let retain = header & 0x01 != 0;
    assert!(body.len() >= 3, "PUBLISH carries a topic and properties");
    let topic_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    assert!(body.len() > 2 + topic_len, "PUBLISH topic fits the body");
    let topic = std::str::from_utf8(&body[2..2 + topic_len])
        .expect("PUBLISH topic UTF-8")
        .to_string();
    let mut rest = &body[2 + topic_len..];
    let packet_id = if qos > 0 {
        assert!(rest.len() >= 2, "PUBLISH carries a packet id");
        let id = u16::from_be_bytes([rest[0], rest[1]]);
        rest = &rest[2..];
        id
    } else {
        0
    };
    let (prop_len, used) = sy02_varint(rest).expect("PUBLISH property length");
    rest = &rest[used..];
    assert!(rest.len() >= prop_len, "PUBLISH properties fit the body");
    let mut props = &rest[..prop_len];
    let mut alias = 0u16;
    while !props.is_empty() {
        let (id, used) = sy02_varint(props).expect("PUBLISH property id");
        props = &props[used..];
        match id {
            35 => {
                assert!(props.len() >= 2, "alias property carries a u16");
                alias = u16::from_be_bytes([props[0], props[1]]);
                props = &props[2..];
            }
            _ => panic!("unexpected PUBLISH property {id}"),
        }
    }
    assert_ne!(alias, 0, "alias-carrying PUBLISH holds a nonzero alias");
    Sy02Publish {
        topic,
        packet_id,
        qos,
        retain,
        dup,
        alias,
        payload: rest[prop_len..].to_vec(),
    }
}

/// Connect a TCP MQTT client and read its CONNACK, retrying through edge
/// boot: the edge accepts the socket before its BrokerLink shard is up,
/// and an early CONNECT can be dropped. Uses a throwaway clean session
/// so retries leave no state behind.
async fn sy02_mqtt_ready(host: &str, port: u16) {
    use std::time::{Duration, Instant};
    use tokio::io::AsyncWriteExt;
    let deadline = Instant::now() + SHARD_E2E_BOOT;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let dial =
            tokio::time::timeout(SHARD_E2E_STEP, tokio::net::TcpStream::connect((host, port)))
                .await;
        if let Ok(Ok(mut sock)) = dial {
            let probe = sy02_connect311(&format!("sy02-probe-{attempt}"), true, 60, None);
            let sent = tokio::time::timeout(SHARD_E2E_STEP, sock.write_all(&probe)).await;
            if sent.as_ref().is_ok_and(|r| r.is_ok()) {
                if let Ok(Ok((head, body))) =
                    tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut sock)).await
                {
                    if head == 0x20 && body == vec![0x00, 0x00] {
                        return;
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            panic!("edge MQTT {port} never answered a CONNECT");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// RFC 6455 example key: the server cannot echo the right accept value
/// without computing it, so asserting the known answer verifies the
/// handshake.
const SY02_WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const SY02_WS_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// Complete a WebSocket upgrade for MQTT against the edge and verify
/// the 101 answer (accept key plus `mqtt` subprotocol).
async fn sy02_ws_handshake(
    sock: &mut tokio::net::TcpStream,
    host: &str,
    port: u16,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let request = format!(
        "GET /mqtt HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {SY02_WS_KEY}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n"
    );
    sock.write_all(request.as_bytes()).await?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        sock.read_exact(&mut byte).await?;
        head.push(byte[0]);
        if head.len() >= 4 && head[head.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if head.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "WS handshake head too long",
            ));
        }
    }
    let head_text = String::from_utf8_lossy(&head);
    let mut lines = head_text.lines();
    let status = lines.next().unwrap_or_default();
    assert!(
        status.starts_with("HTTP/1.1 101"),
        "WS upgrade accepted, got: {status}"
    );
    let mut accept_ok = false;
    let mut proto_ok = false;
    for line in lines {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("Sec-WebSocket-Accept:") {
            accept_ok = value.trim() == SY02_WS_ACCEPT;
        } else if let Some(value) = line.strip_prefix("Sec-WebSocket-Protocol:") {
            proto_ok = value.split(',').any(|token| token.trim() == "mqtt");
        }
    }
    assert!(accept_ok, "WS accept key matches the offered key");
    assert!(proto_ok, "WS subprotocol negotiates mqtt");
    Ok(())
}

/// Send one masked client-to-server binary frame.
async fn sy02_ws_send(sock: &mut tokio::net::TcpStream, payload: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    // Fixed mask: RFC-compliant (present), deterministic for the harness.
    const MASK: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
    let mut frame = vec![0x82];
    if payload.len() < 126 {
        frame.push(0x80 | payload.len() as u8);
    } else if payload.len() < 65536 {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(&MASK);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ MASK[index % 4]);
    }
    sock.write_all(&frame).await
}

/// What one server-to-client frame read yields.
enum Sy02WsMsg {
    Binary(Vec<u8>),
    Closed,
}

/// Read server frames until a binary message or a close arrives,
/// answering pings on the way. Only used with a caller timeout.
async fn sy02_ws_recv(sock: &mut tokio::net::TcpStream) -> std::io::Result<Sy02WsMsg> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let mut head = [0u8; 2];
        sock.read_exact(&mut head).await?;
        let opcode = head[0] & 0x0F;
        let masked = head[1] & 0x80 != 0;
        assert!(!masked, "server-to-client frames are unmasked");
        let mut length = (head[1] & 0x7F) as u64;
        if length == 126 {
            let mut ext = [0u8; 2];
            sock.read_exact(&mut ext).await?;
            length = u16::from_be_bytes(ext) as u64;
        } else if length == 127 {
            let mut ext = [0u8; 8];
            sock.read_exact(&mut ext).await?;
            length = u64::from_be_bytes(ext);
        }
        assert!(length <= 16_777_216, "WS frame bounded");
        let mut payload = vec![0u8; length as usize];
        sock.read_exact(&mut payload).await?;
        match opcode {
            0x2 => return Ok(Sy02WsMsg::Binary(payload)),
            0x8 => return Ok(Sy02WsMsg::Closed),
            0x9 => {
                // Answer pings so an idle peer is never dropped: one
                // masked pong carrying the ping payload.
                const MASK: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
                let mut frame = vec![0x8A];
                if payload.len() < 126 {
                    frame.push(0x80 | payload.len() as u8);
                } else {
                    frame.push(0x80 | 126);
                    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                }
                frame.extend_from_slice(&MASK);
                for (index, byte) in payload.iter().enumerate() {
                    frame.push(byte ^ MASK[index % 4]);
                }
                sock.write_all(&frame).await?;
                continue;
            }
            0xA => continue,
            other => panic!("unexpected WS opcode {other}"),
        }
    }
}

/// SY-02: a last will fires to a subscriber on ungraceful close, through
/// the real broker, on both transports.
///
/// The edge sends one canonical bind for a WebSocket connection carrying
/// PSK identity, will and alias state together; the kernel cannot tell WS
/// binds from TCP binds past that. The first leg drives that exact
/// encoding (will section plus trailing `ClientAliasMax`) over a real
/// BrokerLink socket: the subscriber binds and subscribes, the publisher
/// binds with a last will, drops with `DisconnectIn` (no
/// `DISCONNECT`/unbind), and the subscriber's transport receives the
/// will payload. The second leg connects a real MQTT 5 client over
/// WebSocket through the shipped edge with a will, drops the socket with
/// no DISCONNECT, and the same subscriber receives that will too. Bind,
/// subscribe, disconnect and delivery all run through the broker, never
/// the store.
#[tokio::test]
async fn sy02_ws_mqtt5_will_fires_to_subscriber() {
    use brokerlink::{BrokerFrame, BrokerLinkTransport, FramedTransport, OpCode};
    let scratch = std::env::temp_dir().join(format!(
        "indramqtt-sy02-will-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let bl_port = shard_ephemeral_port();
    let (mut child, addr) = shard_spawn_kernel(&[], &scratch, bl_port).await;

    let sub_io = tokio::time::timeout(SHARD_E2E_STEP, tokio::net::TcpStream::connect(addr))
        .await
        .expect("subscriber dial in time")
        .expect("subscriber dial");
    let sub = FramedTransport::new(sub_io);
    let pub_io = tokio::time::timeout(SHARD_E2E_STEP, tokio::net::TcpStream::connect(addr))
        .await
        .expect("publisher dial in time")
        .expect("publisher dial");
    let publisher = FramedTransport::new(pub_io);

    // Subscriber binds durably and subscribes to the will topic.
    let (_, present) = shard_bind(&sub, 7001, "sy02-ws-sub", false).await;
    assert!(!present, "first durable bind reports session_present=false");
    let sub_frame = BrokerFrame::new(
        OpCode::SubscribeIn,
        7001,
        2,
        shard_encode_subscribe(1, "sy02-ws-sub", &[("sy02/ws/will", 0)]),
        bytes::Bytes::new(),
    )
    .expect("valid subscribe frame");
    tokio::time::timeout(SHARD_E2E_STEP, sub.send(sub_frame))
        .await
        .expect("subscribe in time")
        .expect("subscribe");
    let suback = tokio::time::timeout(SHARD_E2E_STEP, sub.recv())
        .await
        .expect("suback in time")
        .expect("suback");
    assert_eq!(suback.header.opcode, OpCode::SubAckOut);
    assert_eq!(&suback.metadata[..], &[0x00, 0x01, 0x00]);

    // Publisher binds with the WS-equivalent encoding: will section plus
    // the client's alias maximum. CONNACK carries the kernel alias bound.
    let pub_bind = BrokerFrame::new(
        OpCode::BindConnection,
        7002,
        1,
        shard_encode_bind_with_will_and_alias(ShardWillBind {
            client_id: "sy02-ws-pub",
            clean_start: true,
            keepalive: 60,
            will_topic: "sy02/ws/will",
            will_payload: b"ws-will-bytes",
            will_qos: 0,
            will_retain: false,
            client_alias_max: 10,
        }),
        bytes::Bytes::new(),
    )
    .expect("valid bind frame");
    tokio::time::timeout(SHARD_E2E_STEP, publisher.send(pub_bind))
        .await
        .expect("pub bind in time")
        .expect("pub bind send");
    let pub_reply = tokio::time::timeout(SHARD_E2E_STEP, publisher.recv())
        .await
        .expect("pub bind reply in time")
        .expect("pub bind reply");
    assert_eq!(pub_reply.header.opcode, OpCode::SessionBinding);
    let (_, _, rc, alias_max) = shard_decode_binding(&pub_reply.metadata);
    assert_eq!(rc, 0, "will-carrying bind must be accepted");
    assert!(alias_max > 0, "CONNACK carries the alias maximum");

    // Ungraceful close: DisconnectIn with no preceding unbind (no clean
    // DISCONNECT). The kernel fires the stored will once.
    let drop_frame = BrokerFrame::new(
        OpCode::DisconnectIn,
        7002,
        2,
        shard_encode_client_id("sy02-ws-pub"),
        bytes::Bytes::new(),
    )
    .expect("valid disconnect frame");
    tokio::time::timeout(SHARD_E2E_STEP, publisher.send(drop_frame))
        .await
        .expect("disconnect in time")
        .expect("disconnect send");

    // The subscriber receives the will over its live transport.
    let downlink = tokio::time::timeout(SHARD_E2E_STEP, sub.recv())
        .await
        .expect("will arrives in time")
        .expect("will delivery");
    assert_eq!(downlink.header.opcode, OpCode::PublishOut);
    assert_eq!(downlink.header.conn_id, 7001);
    assert_eq!(
        downlink.payload,
        bytes::Bytes::from_static(b"ws-will-bytes")
    );
    let (topic, _, _, _) = shard_decode_publish_out(&downlink.metadata);
    assert_eq!(topic, "sy02/ws/will");

    // Second leg: a real MQTT 5 client over WebSocket. The edge is
    // spawned against the same kernel; the publisher completes the WS
    // upgrade, connects with a will, and drops the socket with no
    // DISCONNECT and no WS close frame. The same subscriber receives
    // the will, proving the WS transport gets will handling exactly
    // like the BrokerLink path above.
    let edge = match sy02_spawn_edge(bl_port).await {
        Some(edge) => edge,
        None => {
            // SKIP already logged: the kernel leg above still verified
            // the will through the broker.
            let _ = child.kill().await;
            let _ = std::fs::remove_dir_all(&scratch);
            return;
        }
    };
    sy02_mqtt_ready(edge.host(), edge.mqtt_port).await;
    let ws_io = tokio::time::timeout(
        SHARD_E2E_STEP,
        tokio::net::TcpStream::connect((edge.host(), edge.ws_port)),
    )
    .await
    .expect("WS dial in time")
    .expect("WS dial");
    let mut ws = ws_io;
    tokio::time::timeout(
        SHARD_E2E_STEP,
        sy02_ws_handshake(&mut ws, edge.host(), edge.ws_port),
    )
    .await
    .expect("WS handshake in time")
    .expect("WS handshake");
    let connect = sy02_connect5(
        "sy02-ws5-pub",
        true,
        60,
        None,
        Some(("sy02/ws/will", b"ws5-will-bytes")),
        10,
    );
    tokio::time::timeout(SHARD_E2E_STEP, sy02_ws_send(&mut ws, &connect))
        .await
        .expect("WS CONNECT in time")
        .expect("WS CONNECT send");
    let connack = tokio::time::timeout(SHARD_E2E_STEP, sy02_ws_recv(&mut ws))
        .await
        .expect("WS CONNACK in time")
        .expect("WS CONNACK");
    let (present, reason, alias_max) = match connack {
        Sy02WsMsg::Binary(frame) => {
            assert_eq!(frame[0] & 0xF0, 0x20, "edge answers with CONNACK");
            let body = &frame[2..];
            sy02_parse_connack5(body)
        }
        Sy02WsMsg::Closed => panic!("edge closed the WS socket on CONNECT"),
    };
    assert!(!present, "first WS bind reports session_present=false");
    assert_eq!(reason, 0, "will-carrying WS CONNECT must be accepted");
    assert_eq!(alias_max, 10, "WS CONNACK carries the kernel alias maximum");
    // Ungraceful close: drop the socket with no DISCONNECT. The edge
    // reports the close and the kernel fires the stored will once.
    drop(ws);
    let downlink = tokio::time::timeout(SHARD_E2E_STEP, sub.recv())
        .await
        .expect("WS will arrives in time")
        .expect("WS will delivery");
    assert_eq!(downlink.header.opcode, OpCode::PublishOut);
    assert_eq!(downlink.header.conn_id, 7001);
    assert_eq!(
        downlink.payload,
        bytes::Bytes::from_static(b"ws5-will-bytes")
    );
    let (topic, _, _, _) = shard_decode_publish_out(&downlink.metadata);
    assert_eq!(topic, "sy02/ws/will");

    edge.finish().await;
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&scratch);
}

/// X1-03: end-to-end through the edge with real MQTT 5 clients.
///
/// A version-5 subscriber connects with properties, subscribes with
/// options plus a subscription identifier, and receives a version-5
/// publish carrying the same user properties (plus the identifier) on
/// delivery; the publisher disconnects with a reason code. The same
/// scenario over version 4 still passes unchanged (proves 3.1.1 is
/// untouched). Goes through the broker (edge codec, subscribe event,
/// publish event, delivery to socket), never the store.
#[tokio::test]
async fn x103_v5_subscriptions_reasons_edge_e2e() {
    use tokio::io::AsyncWriteExt;
    let tag = format!(
        "x103-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let scratch = std::env::temp_dir().join(format!("indramqtt-{tag}"));
    let bl_port = shard_ephemeral_port();
    let (mut child, _addr) = shard_spawn_kernel(&[], &scratch, bl_port).await;
    let edge = match sy02_spawn_edge(bl_port).await {
        Some(edge) => edge,
        None => {
            let _ = child.kill().await;
            let _ = std::fs::remove_dir_all(&scratch);
            return;
        }
    };
    sy02_mqtt_ready(edge.host(), edge.mqtt_port).await;
    async fn dial(host: &str, port: u16) -> tokio::net::TcpStream {
        tokio::time::timeout(SHARD_E2E_STEP, tokio::net::TcpStream::connect((host, port)))
            .await
            .expect("dial in time")
            .expect("dial")
    }
    async fn recv(sock: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
        tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(sock))
            .await
            .expect("packet in time")
            .expect("packet")
    }
    async fn send(sock: &mut tokio::net::TcpStream, bytes: &[u8]) {
        tokio::time::timeout(SHARD_E2E_STEP, sock.write_all(bytes))
            .await
            .expect("send in time")
            .expect("send");
    }
    // Version-5 leg: CONNECT with properties (alias maximum), SUBSCRIBE
    // with options plus identifier, PUBLISH with user properties,
    // DISCONNECT with a reason code.
    let mut sub = dial(edge.host(), edge.mqtt_port).await;
    send(
        &mut sub,
        &sy02_connect5("x103-v5-sub", true, 60, None, None, 10),
    )
    .await;
    let (head, body) = recv(&mut sub).await;
    assert_eq!(head & 0xF0, 0x20, "edge answers with CONNACK");
    let (_, reason, _) = sy02_parse_connack5(&body);
    assert_eq!(reason, 0, "v5 CONNECT accepted");
    // Options: QoS 0, no-local 0, rap 0, retain-handling 0.
    send(&mut sub, &sy02_subscribe_v5(7, &[("x103/v5/props", 0)], 42)).await;
    let (head, body) = recv(&mut sub).await;
    assert_eq!(head & 0xF0, 0x90, "edge answers with SUBACK");
    let (packet_id, codes) = sy02_parse_suback5(&body);
    assert_eq!(packet_id, 7);
    assert_eq!(codes, vec![0u8], "v5 subscribe granted QoS 0");
    let mut publisher = dial(edge.host(), edge.mqtt_port).await;
    send(
        &mut publisher,
        &sy02_connect5("x103-v5-pub", true, 60, None, None, 10),
    )
    .await;
    let (head, body) = recv(&mut publisher).await;
    assert_eq!(head & 0xF0, 0x20, "publisher CONNACK");
    let (_, reason, _) = sy02_parse_connack5(&body);
    assert_eq!(reason, 0);
    send(
        &mut publisher,
        &sy02_publish5_with_props(
            "x103/v5/props",
            0,
            false,
            Some(1),
            None,
            &[("k", "v")],
            b"hello-v5",
        ),
    )
    .await;
    let (head, body) = recv(&mut sub).await;
    assert_eq!(head & 0xF0, 0x30, "downlink is PUBLISH");
    let got = sy02_parse_publish_v5(head, &body);
    assert_eq!(got.topic, "x103/v5/props");
    assert_eq!(got.payload, b"hello-v5");
    assert_eq!(got.qos, 0, "delivery keeps QoS 0");
    assert_eq!(got.sub_id, 42, "delivery carries the subscription id");
    assert_eq!(got.format, 1, "delivery forwards payload format");
    assert_eq!(got.expiry, 0, "delivery forwards message expiry");
    assert_eq!(
        got.users,
        vec![("k".to_string(), "v".to_string())],
        "delivery forwards user properties"
    );
    // DISCONNECT with reason 0 succeeds (clean close, no will).
    send(&mut publisher, &sy02_disconnect_v5(0)).await;
    drop(publisher);
    // A malformed option fails only its own filter: one good filter
    // plus one with reserved bits set. The good filter grants QoS 0,
    // the bad one answers 0x8F, and the good filter still delivers.
    send(
        &mut sub,
        &sy02_subscribe_v5(8, &[("x103/v5/mixed", 0), ("x103/v5/bad", 0xC1)], 0),
    )
    .await;
    let (head, body) = recv(&mut sub).await;
    assert_eq!(head & 0xF0, 0x90, "edge answers mixed SUBACK");
    let (packet_id, codes) = sy02_parse_suback5(&body);
    assert_eq!(packet_id, 8);
    assert_eq!(
        codes,
        vec![0u8, 0x8Fu8],
        "good filter grants, bad filter fails alone"
    );
    // Version-4 leg unchanged: classic CONNECT/SUBSCRIBE/PUBLISH.
    let mut sub4 = dial(edge.host(), edge.mqtt_port).await;
    send(&mut sub4, &sy02_connect311("x103-v4-sub", true, 60, None)).await;
    let (head, body) = recv(&mut sub4).await;
    assert_eq!(head, 0x20, "v4 CONNACK");
    assert_eq!(sy02_parse_connack311(&body), (false, 0));
    send(&mut sub4, &sy02_subscribe(1, &[("x103/v4/plain", 0)])).await;
    let (head, body) = recv(&mut sub4).await;
    assert_eq!(head & 0xF0, 0x90, "v4 SUBACK");
    assert_eq!(sy02_parse_suback(&body), (1, vec![0u8]));
    let mut pub4 = dial(edge.host(), edge.mqtt_port).await;
    send(&mut pub4, &sy02_connect311("x103-v4-pub", true, 60, None)).await;
    let (head, body) = recv(&mut pub4).await;
    assert_eq!(head, 0x20);
    assert_eq!(sy02_parse_connack311(&body), (false, 0));
    send(
        &mut pub4,
        &sy02_publish311("x103/v4/plain", 0, 0, false, b"hello-v4"),
    )
    .await;
    let (head, body) = recv(&mut sub4).await;
    assert_eq!(head & 0xF0, 0x30, "v4 downlink is PUBLISH");
    let got4 = sy02_parse_publish_classic(head, &body);
    assert_eq!(got4.topic, "x103/v4/plain");
    assert_eq!(got4.payload, b"hello-v4");
    edge.finish().await;
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&scratch);
}

/// SY-02: the QoS 1 inflight window set through `indra.toml` and its
/// `INDRA_` variable is enforced on real MQTT connections.
///
/// The config file sets `session.max_qos1_inflight = 2` /
/// `session.max_qos1_spill = 2`; the environment overrides both to 1.
/// The kernel boots against that config dir with the environment set, so
/// the resolved window is 1 and spill is 1, and the shipped edge serves
/// real MQTT clients against it. A durable subscriber receives three
/// live QoS 1 downlinks without acking; it then drops and reconnects.
/// Only the two tracked downlinks (window oldest-first, then spill)
/// replay with DUP set — the third, delivered live once but past
/// window+spill, stays untracked and never replays. That replay count is
/// the enforcement observed on real connections, and it matches the env
/// override (1+1), not the file (2+2). Acking the replays then releases
/// the hold: a fourth publish is tracked again and replays alone after
/// the next drop, proving the broker holds the excess only until acks
/// arrive.
#[tokio::test]
async fn sy02_qos1_window_from_toml_and_env_enforced() {
    let tag = format!(
        "sy02-qos1-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let scratch = std::env::temp_dir().join(format!("indramqtt-{tag}"));
    let config_dir = std::env::temp_dir().join(format!("indramqtt-{tag}-cfg"));
    std::fs::create_dir_all(&config_dir).expect("create temp config dir");
    std::fs::write(
        config_dir.join("indra.toml"),
        "[session]\nmax_qos1_inflight = 2\nmax_qos1_spill = 2\n",
    )
    .expect("write indra.toml");

    // The file layer alone resolves to 2/2 through the real loader.
    {
        use broker_config::layers::{load_layered_with_env, CliOverrides};
        let layered =
            load_layered_with_env(&config_dir, &[], &CliOverrides::default()).expect("load file");
        assert_eq!(layered.config().session.max_qos1_inflight, 2);
        assert_eq!(layered.config().session.max_qos1_spill, 2);
    }

    // The environment overrides the file for the booted kernel below.
    let prev_window = std::env::var("INDRA_SESSION__MAX_QOS1_INFLIGHT").ok();
    let prev_spill = std::env::var("INDRA_SESSION__MAX_QOS1_SPILL").ok();
    std::env::set_var("INDRA_SESSION__MAX_QOS1_INFLIGHT", "1");
    std::env::set_var("INDRA_SESSION__MAX_QOS1_SPILL", "1");

    let bl_port = shard_ephemeral_port();
    let config_arg = format!("--config-dir={}", config_dir.display());
    let (mut child, _addr) = shard_spawn_kernel(&[config_arg.as_str()], &scratch, bl_port).await;

    std::env::remove_var("INDRA_SESSION__MAX_QOS1_INFLIGHT");
    std::env::remove_var("INDRA_SESSION__MAX_QOS1_SPILL");
    if let Some(v) = prev_window {
        std::env::set_var("INDRA_SESSION__MAX_QOS1_INFLIGHT", v);
    }
    if let Some(v) = prev_spill {
        std::env::set_var("INDRA_SESSION__MAX_QOS1_SPILL", v);
    }

    // Real MQTT clients through the shipped edge, served by the kernel
    // above (same config dir, same env-resolved window).
    let edge = match sy02_spawn_edge(bl_port).await {
        Some(edge) => edge,
        None => {
            // SKIP already logged.
            let _ = child.kill().await;
            let _ = std::fs::remove_dir_all(&scratch);
            let _ = std::fs::remove_dir_all(&config_dir);
            return;
        }
    };
    sy02_mqtt_ready(edge.host(), edge.mqtt_port).await;

    use tokio::io::AsyncWriteExt;

    // Durable subscriber over real MQTT: CONNECT (clean_start=false),
    // then a QoS 1 subscribe.
    let mut sub = tokio::time::timeout(
        SHARD_E2E_STEP,
        tokio::net::TcpStream::connect((edge.host(), edge.mqtt_port)),
    )
    .await
    .expect("subscriber dial in time")
    .expect("subscriber dial");
    let connect = sy02_connect311("sy02-qos1-sub", false, 60, None);
    tokio::time::timeout(SHARD_E2E_STEP, sub.write_all(&connect))
        .await
        .expect("CONNECT in time")
        .expect("CONNECT send");
    let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut sub))
        .await
        .expect("CONNACK in time")
        .expect("CONNACK");
    assert_eq!(head, 0x20, "edge answers with CONNACK");
    assert_eq!(
        sy02_parse_connack311(&body),
        (false, 0),
        "first durable CONNECT accepted with session_present=false"
    );
    let subscribe = sy02_subscribe(1, &[("sy02/qos1", 1)]);
    tokio::time::timeout(SHARD_E2E_STEP, sub.write_all(&subscribe))
        .await
        .expect("SUBSCRIBE in time")
        .expect("SUBSCRIBE send");
    let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut sub))
        .await
        .expect("SUBACK in time")
        .expect("SUBACK");
    assert_eq!(head, 0x90, "edge answers with SUBACK");
    assert_eq!(
        sy02_parse_suback(&body),
        (1, vec![1]),
        "QoS 1 subscription granted"
    );

    // Publisher over real MQTT.
    let mut publisher = tokio::time::timeout(
        SHARD_E2E_STEP,
        tokio::net::TcpStream::connect((edge.host(), edge.mqtt_port)),
    )
    .await
    .expect("publisher dial in time")
    .expect("publisher dial");
    let connect = sy02_connect311("sy02-qos1-pub", true, 60, None);
    tokio::time::timeout(SHARD_E2E_STEP, publisher.write_all(&connect))
        .await
        .expect("publisher CONNECT in time")
        .expect("publisher CONNECT send");
    let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut publisher))
        .await
        .expect("publisher CONNACK in time")
        .expect("publisher CONNACK");
    assert_eq!(head, 0x20, "edge answers the publisher with CONNACK");
    assert_eq!(sy02_parse_connack311(&body), (false, 0));

    // Three QoS 1 publishes; the subscriber receives all three live (live
    // delivery always goes out once) and acks nothing. The publisher
    // drains its own PUBACKs to stay in sync.
    for (seq, payload) in [(1u16, "qos1-1"), (2, "qos1-2"), (3, "qos1-3")] {
        let publish = sy02_publish311("sy02/qos1", seq, 1, false, payload.as_bytes());
        tokio::time::timeout(SHARD_E2E_STEP, publisher.write_all(&publish))
            .await
            .expect("publish in time")
            .expect("publish send");
        let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut publisher))
            .await
            .expect("PUBACK in time")
            .expect("PUBACK");
        assert_eq!(head, 0x40, "publisher sees PUBACK");
        assert_eq!(
            body,
            vec![(seq >> 8) as u8, (seq & 0xff) as u8],
            "PUBACK mirrors its packet id"
        );
    }
    let mut live = Vec::new();
    for _ in 0..3 {
        let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut sub))
            .await
            .expect("live downlink in time")
            .expect("live downlink");
        assert_eq!(head & 0xF0, 0x30, "downlink is PUBLISH");
        let downlink = sy02_parse_publish_classic(head, &body);
        assert_eq!(downlink.qos, 1, "downlink keeps QoS 1");
        assert!(!downlink.dup, "live delivery carries no DUP");
        live.push(downlink.payload);
    }
    assert_eq!(
        live,
        vec![b"qos1-1".to_vec(), b"qos1-2".to_vec(), b"qos1-3".to_vec()],
        "all three publish live exactly once"
    );

    // Ungraceful drop of the subscriber socket, then reconnect the
    // durable session on a fresh socket.
    drop(sub);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let mut re = tokio::time::timeout(
        SHARD_E2E_STEP,
        tokio::net::TcpStream::connect((edge.host(), edge.mqtt_port)),
    )
    .await
    .expect("reconnect in time")
    .expect("reconnect");
    let connect = sy02_connect311("sy02-qos1-sub", false, 60, None);
    tokio::time::timeout(SHARD_E2E_STEP, re.write_all(&connect))
        .await
        .expect("reconnect CONNECT in time")
        .expect("reconnect CONNECT send");
    let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut re))
        .await
        .expect("reconnect CONNACK in time")
        .expect("reconnect CONNACK");
    assert_eq!(head, 0x20, "edge answers the reconnect with CONNACK");
    assert_eq!(
        sy02_parse_connack311(&body),
        (true, 0),
        "resumed session reports session_present=true"
    );

    // Exactly window+spill (1+1 from the env override) replay with DUP,
    // oldest-first; the third live-only delivery never replays.
    let mut replayed = Vec::new();
    let mut replay_ids = Vec::new();
    for _ in 0..2 {
        let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut re))
            .await
            .expect("replay in time")
            .expect("replay");
        assert_eq!(head & 0xF0, 0x30, "replay is PUBLISH");
        let downlink = sy02_parse_publish_classic(head, &body);
        assert!(downlink.dup, "replayed downlink carries DUP");
        replay_ids.push(downlink.packet_id);
        replayed.push(downlink.payload);
    }
    assert_eq!(
        replayed,
        vec![b"qos1-1".to_vec(), b"qos1-2".to_vec()],
        "window oldest-first, then spill; live-only third never replays"
    );
    let nothing =
        tokio::time::timeout(std::time::Duration::from_secs(2), read_mqtt_packet(&mut re)).await;
    assert!(
        nothing.is_err(),
        "no third replay: window+spill bound enforced"
    );

    // Acking the replays releases the hold: a fourth publish is tracked
    // again and replays alone after the next drop, proving the broker
    // holds the excess only until acks arrive.
    for packet_id in &replay_ids {
        tokio::time::timeout(SHARD_E2E_STEP, re.write_all(&sy02_puback(*packet_id)))
            .await
            .expect("PUBACK in time")
            .expect("PUBACK send");
    }
    // Let the PUBACKs land before the next publish races them.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let publish = sy02_publish311("sy02/qos1", 4, 1, false, b"qos1-4");
    tokio::time::timeout(SHARD_E2E_STEP, publisher.write_all(&publish))
        .await
        .expect("fourth publish in time")
        .expect("fourth publish send");
    let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut publisher))
        .await
        .expect("fourth PUBACK in time")
        .expect("fourth PUBACK");
    assert_eq!(head, 0x40, "publisher sees the fourth PUBACK");
    assert_eq!(body, vec![0x00, 0x04]);
    let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut re))
        .await
        .expect("fourth live downlink in time")
        .expect("fourth live downlink");
    assert_eq!(head & 0xF0, 0x30, "fourth downlink is PUBLISH");
    let downlink = sy02_parse_publish_classic(head, &body);
    assert!(!downlink.dup, "live delivery carries no DUP");
    assert_eq!(downlink.payload, b"qos1-4");
    drop(re);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let mut re2 = tokio::time::timeout(
        SHARD_E2E_STEP,
        tokio::net::TcpStream::connect((edge.host(), edge.mqtt_port)),
    )
    .await
    .expect("second reconnect in time")
    .expect("second reconnect");
    let connect = sy02_connect311("sy02-qos1-sub", false, 60, None);
    tokio::time::timeout(SHARD_E2E_STEP, re2.write_all(&connect))
        .await
        .expect("second reconnect CONNECT in time")
        .expect("second reconnect CONNECT send");
    let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut re2))
        .await
        .expect("second reconnect CONNACK in time")
        .expect("second reconnect CONNACK");
    assert_eq!(head, 0x20, "edge answers with CONNACK");
    assert_eq!(
        sy02_parse_connack311(&body),
        (true, 0),
        "resumed session reports session_present=true"
    );
    let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut re2))
        .await
        .expect("fourth replay in time")
        .expect("fourth replay");
    assert_eq!(head & 0xF0, 0x30, "replay is PUBLISH");
    let downlink = sy02_parse_publish_classic(head, &body);
    assert!(downlink.dup, "replayed downlink carries DUP");
    assert_eq!(
        downlink.payload, b"qos1-4",
        "only the acked-after publish replays: acks released the hold"
    );
    let nothing = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_mqtt_packet(&mut re2),
    )
    .await;
    assert!(
        nothing.is_err(),
        "no second replay: acked entries stay released"
    );

    edge.finish().await;
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&scratch);
    let _ = std::fs::remove_dir_all(&config_dir);
}

/// SY-02: two tenants cannot see each other's messages while aliases,
/// retained messages and offline queues work in each, over real MQTT.
///
/// The kernel boots with one tenant rule (`t-${username}`) installed from
/// `indra.toml` via `TenantsConf -> TenantRegistry::replace`, and the
/// shipped edge serves real MQTT 5 clients against it, so CONNECTs
/// carrying username `user-a` land in one tenant and `user-b` in another.
/// In each tenant: the subscriber connects durably with an alias maximum,
/// a topic+alias publish registers the inbound alias and arrives with the
/// full topic plus an outbound alias, an alias-by-reference publish
/// resolves to the same topic, a retained publish is visible only inside
/// its own tenant, then the subscriber drops and a publish while detached
/// replays on reconnect (with the same username, so the same tenant).
/// Every client receives exactly its own tenant's payloads — the spec's
/// isolation, observed over real connections through the broker, never
/// the store.
#[tokio::test]
async fn sy02_tenants_isolated_with_aliases_and_offline() {
    let tag = format!(
        "sy02-tenant-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let scratch = std::env::temp_dir().join(format!("indramqtt-{tag}"));
    let config_dir = std::env::temp_dir().join(format!("indramqtt-{tag}-cfg"));
    std::fs::create_dir_all(&config_dir).expect("create temp config dir");
    std::fs::write(
        config_dir.join("indra.toml"),
        "[[tenants.rules]]\nexpression = \"t-${username}\"\n",
    )
    .expect("write indra.toml");

    let bl_port = shard_ephemeral_port();
    let config_arg = format!("--config-dir={}", config_dir.display());
    let (mut child, _addr) = shard_spawn_kernel(&[config_arg.as_str()], &scratch, bl_port).await;

    // Real MQTT 5 clients through the shipped edge, served by the kernel
    // above (same tenant config). One socket per client so every
    // downlink is attributable.
    let edge = match sy02_spawn_edge(bl_port).await {
        Some(edge) => edge,
        None => {
            // SKIP already logged.
            let _ = child.kill().await;
            let _ = std::fs::remove_dir_all(&scratch);
            let _ = std::fs::remove_dir_all(&config_dir);
            return;
        }
    };
    sy02_mqtt_ready(edge.host(), edge.mqtt_port).await;

    // One socket per client so every downlink is attributable.
    async fn dial(host: &str, port: u16) -> tokio::net::TcpStream {
        tokio::time::timeout(SHARD_E2E_STEP, tokio::net::TcpStream::connect((host, port)))
            .await
            .expect("dial in time")
            .expect("dial")
    }
    // CONNECT with the tenant username over MQTT 5 (alias maximum 10),
    // returning session-present. The CONNECT is accepted (rc 0) with the
    // kernel alias bound every time.
    async fn connect_tenant(
        sock: &mut tokio::net::TcpStream,
        client_id: &str,
        clean_start: bool,
        username: &str,
    ) -> bool {
        use tokio::io::AsyncWriteExt;
        let connect = sy02_connect5(
            client_id,
            clean_start,
            60,
            Some((username, b"pw")),
            None,
            10,
        );
        tokio::time::timeout(SHARD_E2E_STEP, sock.write_all(&connect))
            .await
            .expect("CONNECT in time")
            .expect("CONNECT send");
        let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(sock))
            .await
            .expect("CONNACK in time")
            .expect("CONNACK");
        assert_eq!(head, 0x20, "edge answers {client_id} with CONNACK");
        let (present, reason, alias_max) = sy02_parse_connack5(&body);
        assert_eq!(reason, 0, "CONNECT of {client_id} must be accepted");
        assert_eq!(alias_max, 10, "CONNACK carries the kernel alias maximum");
        present
    }
    async fn subscribe_qos1(sock: &mut tokio::net::TcpStream, client_id: &str, filter: &str) {
        use tokio::io::AsyncWriteExt;
        // Speak MQTT 5 on a v5 socket. Options hold QoS 1
        // with retain-as-published set, so retained replay
        // keeps the retain flag like the old v4 path.
        let subscribe = sy02_subscribe_v5(1, &[(filter, 9)], 0);
        tokio::time::timeout(SHARD_E2E_STEP, sock.write_all(&subscribe))
            .await
            .expect("SUBSCRIBE in time")
            .expect("SUBSCRIBE send");
        let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(sock))
            .await
            .expect("SUBACK in time")
            .expect("SUBACK");
        assert_eq!(head & 0xF0, 0x90, "edge answers with SUBACK");
        assert_eq!(
            sy02_parse_suback5(&body),
            (1, vec![1]),
            "QoS 1 subscription of {client_id} to {filter} must be granted"
        );
    }
    async fn recv_packet(sock: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
        tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(sock))
            .await
            .expect("downlink in time")
            .expect("downlink")
    }
    async fn publish_qos1(
        sock: &mut tokio::net::TcpStream,
        topic: &str,
        packet_id: u16,
        retain: bool,
        alias: Option<u16>,
        payload: &[u8],
    ) {
        use tokio::io::AsyncWriteExt;
        let publish = sy02_publish5(topic, packet_id, 1, retain, alias, payload);
        tokio::time::timeout(SHARD_E2E_STEP, sock.write_all(&publish))
            .await
            .expect("publish in time")
            .expect("publish send");
        let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(sock))
            .await
            .expect("PUBACK in time")
            .expect("PUBACK");
        assert_eq!(head, 0x40, "publisher sees PUBACK");
        assert_eq!(
            body,
            vec![(packet_id >> 8) as u8, (packet_id & 0xff) as u8],
            "PUBACK mirrors its packet id"
        );
    }
    async fn ack(sock: &mut tokio::net::TcpStream, packet_id: u16) {
        use tokio::io::AsyncWriteExt;
        tokio::time::timeout(SHARD_E2E_STEP, sock.write_all(&sy02_puback(packet_id)))
            .await
            .expect("PUBACK in time")
            .expect("PUBACK send");
    }
    async fn expect_silence(sock: &mut tokio::net::TcpStream, what: &str) {
        let extra =
            tokio::time::timeout(std::time::Duration::from_secs(2), read_mqtt_packet(sock)).await;
        assert!(extra.is_err(), "{what}");
    }

    let mut a_sub = dial(edge.host(), edge.mqtt_port).await;
    let mut a_pub = dial(edge.host(), edge.mqtt_port).await;
    let mut b_sub = dial(edge.host(), edge.mqtt_port).await;
    let mut b_pub = dial(edge.host(), edge.mqtt_port).await;

    assert!(
        !connect_tenant(&mut a_sub, "sy02-a-sub", false, "user-a").await,
        "tenant-a first CONNECT reports session_present=false"
    );
    assert!(
        !connect_tenant(&mut b_sub, "sy02-b-sub", false, "user-b").await,
        "tenant-b first CONNECT reports session_present=false"
    );
    subscribe_qos1(&mut a_sub, "sy02-a-sub", "sy02/iso").await;
    subscribe_qos1(&mut b_sub, "sy02-b-sub", "sy02/iso").await;
    connect_tenant(&mut a_pub, "sy02-a-pub", true, "user-a").await;
    connect_tenant(&mut b_pub, "sy02-b-pub", true, "user-b").await;

    // Alias leg per tenant: topic+alias registers, alias-by-reference
    // resolves, downlink carries the full topic plus an outbound alias.
    publish_qos1(&mut a_pub, "sy02/iso", 1, false, Some(3), b"a-1").await;
    publish_qos1(&mut b_pub, "sy02/iso", 1, false, Some(5), b"b-1").await;
    let (head, body) = recv_packet(&mut a_sub).await;
    assert_eq!(head & 0xF0, 0x30, "downlink is PUBLISH");
    let a1 = sy02_parse_publish_alias(head, &body);
    assert_eq!(a1.topic, "sy02/iso");
    assert_eq!(a1.payload, b"a-1");
    assert!(!a1.dup, "live delivery carries no DUP");
    assert_ne!(a1.alias, 0, "downlink carries an outbound alias");
    let (head, body) = recv_packet(&mut b_sub).await;
    assert_eq!(head & 0xF0, 0x30, "downlink is PUBLISH");
    let b1 = sy02_parse_publish_alias(head, &body);
    assert_eq!(b1.topic, "sy02/iso");
    assert_eq!(b1.payload, b"b-1");
    assert!(!b1.dup, "live delivery carries no DUP");
    assert_ne!(b1.alias, 0, "downlink carries an outbound alias");
    ack(&mut a_sub, a1.packet_id).await;
    ack(&mut b_sub, b1.packet_id).await;

    // Alias-by-reference in each tenant resolves to the same topic.
    publish_qos1(&mut a_pub, "", 2, false, Some(3), b"a-2").await;
    publish_qos1(&mut b_pub, "", 2, false, Some(5), b"b-2").await;
    let (head, body) = recv_packet(&mut a_sub).await;
    assert_eq!(head & 0xF0, 0x30, "downlink is PUBLISH");
    let a2 = sy02_parse_publish_alias(head, &body);
    assert_eq!(a2.topic, "sy02/iso", "alias resolves in tenant-a");
    assert_eq!(a2.payload, b"a-2");
    assert_ne!(a2.alias, 0, "downlink carries an outbound alias");
    let (head, body) = recv_packet(&mut b_sub).await;
    assert_eq!(head & 0xF0, 0x30, "downlink is PUBLISH");
    let b2 = sy02_parse_publish_alias(head, &body);
    assert_eq!(b2.topic, "sy02/iso", "alias resolves in tenant-b");
    assert_eq!(b2.payload, b"b-2");
    assert_ne!(b2.alias, 0, "downlink carries an outbound alias");
    ack(&mut a_sub, a2.packet_id).await;
    ack(&mut b_sub, b2.packet_id).await;

    // Retained leg: the same topic string holds one retained message
    // per tenant, and each tenant's new subscriber sees only its own.
    publish_qos1(&mut a_pub, "sy02/retained", 3, true, None, b"a-ret").await;
    publish_qos1(&mut b_pub, "sy02/retained", 3, true, None, b"b-ret").await;
    let mut a_ret = dial(edge.host(), edge.mqtt_port).await;
    assert!(
        !connect_tenant(&mut a_ret, "sy02-a-ret", true, "user-a").await,
        "tenant-a retained reader connects clean"
    );
    subscribe_qos1(&mut a_ret, "sy02-a-ret", "sy02/retained").await;
    let (head, body) = recv_packet(&mut a_ret).await;
    assert_eq!(head & 0xF0, 0x30, "retained downlink is PUBLISH");
    let retained_a = sy02_parse_publish_classic(head, &body);
    assert_eq!(retained_a.topic, "sy02/retained");
    assert_eq!(
        retained_a.payload, b"a-ret",
        "tenant-a sees only its own retained message"
    );
    assert!(retained_a.retain, "retained replay carries retain");
    expect_silence(&mut a_ret, "tenant-a holds only its own retained message").await;
    let mut b_ret = dial(edge.host(), edge.mqtt_port).await;
    assert!(
        !connect_tenant(&mut b_ret, "sy02-b-ret", true, "user-b").await,
        "tenant-b retained reader connects clean"
    );
    subscribe_qos1(&mut b_ret, "sy02-b-ret", "sy02/retained").await;
    let (head, body) = recv_packet(&mut b_ret).await;
    assert_eq!(head & 0xF0, 0x30, "retained downlink is PUBLISH");
    let retained_b = sy02_parse_publish_classic(head, &body);
    assert_eq!(retained_b.topic, "sy02/retained");
    assert_eq!(
        retained_b.payload, b"b-ret",
        "tenant-b sees only its own retained message"
    );
    assert!(retained_b.retain, "retained replay carries retain");
    expect_silence(&mut b_ret, "tenant-b holds only its own retained message").await;

    // Offline leg: both subscribers drop; one publish per tenant while
    // detached; each reconnect (same username, so the same tenant)
    // replays exactly its own tenant's message.
    drop(a_sub);
    drop(b_sub);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    publish_qos1(&mut a_pub, "sy02/iso", 4, false, None, b"a-off").await;
    publish_qos1(&mut b_pub, "sy02/iso", 4, false, None, b"b-off").await;
    let mut a_re = dial(edge.host(), edge.mqtt_port).await;
    let mut b_re = dial(edge.host(), edge.mqtt_port).await;
    assert!(
        connect_tenant(&mut a_re, "sy02-a-sub", false, "user-a").await,
        "tenant-a resume reports session_present=true"
    );
    assert!(
        connect_tenant(&mut b_re, "sy02-b-sub", false, "user-b").await,
        "tenant-b resume reports session_present=true"
    );
    let (head, body) = recv_packet(&mut a_re).await;
    assert_eq!(head & 0xF0, 0x30, "replay is PUBLISH");
    let off_a = sy02_parse_publish_classic(head, &body);
    assert_eq!(off_a.topic, "sy02/iso");
    assert_eq!(off_a.payload, b"a-off");
    let (head, body) = recv_packet(&mut b_re).await;
    assert_eq!(head & 0xF0, 0x30, "replay is PUBLISH");
    let off_b = sy02_parse_publish_classic(head, &body);
    assert_eq!(off_b.topic, "sy02/iso");
    assert_eq!(off_b.payload, b"b-off");
    // Nothing crosses tenants: each reconnect holds exactly one frame.
    expect_silence(&mut a_re, "tenant-a holds only its own replay").await;
    expect_silence(&mut b_re, "tenant-b holds only its own replay").await;

    edge.finish().await;
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&scratch);
    let _ = std::fs::remove_dir_all(&config_dir);
}

/// MT-07: the same client id in two tenants holds two connections.
///
/// The kernel boots with one tenant rule from `indra.toml`. Two real
/// MQTT clients connect with the same client id but different
/// usernames. Both CONNACKs succeed and both sockets stay open. A
/// publish in each tenant reaches only its own tenant. The test uses
/// the file entry and client sockets only.
#[tokio::test]
async fn mt07_same_client_id_in_two_tenants_stays_connected_through_edge() {
    use tokio::io::AsyncWriteExt;
    let tag = format!(
        "mt07-dup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let scratch = std::env::temp_dir().join(format!("indramqtt-{tag}"));
    let config_dir = std::env::temp_dir().join(format!("indramqtt-{tag}-cfg"));
    std::fs::create_dir_all(&config_dir).expect("create temp config dir");
    std::fs::write(
        config_dir.join("indra.toml"),
        "[[tenants.rules]]\nexpression = \"t-${username}\"\n",
    )
    .expect("write indra.toml");
    let bl_port = shard_ephemeral_port();
    let config_arg = format!("--config-dir={}", config_dir.display());
    let (mut child, _addr) = shard_spawn_kernel(&[config_arg.as_str()], &scratch, bl_port).await;
    let edge = match sy02_spawn_edge(bl_port).await {
        Some(edge) => edge,
        None => {
            // SKIP already logged.
            let _ = child.kill().await;
            let _ = std::fs::remove_dir_all(&scratch);
            let _ = std::fs::remove_dir_all(&config_dir);
            return;
        }
    };
    sy02_mqtt_ready(edge.host(), edge.mqtt_port).await;

    // Two sockets share one client id. Each carries its own username,
    // so each lands in its own tenant.
    let mut a_sock = tokio::time::timeout(
        SHARD_E2E_STEP,
        tokio::net::TcpStream::connect((edge.host(), edge.mqtt_port)),
    )
    .await
    .expect("dial A in time")
    .expect("dial A");
    let mut b_sock = tokio::time::timeout(
        SHARD_E2E_STEP,
        tokio::net::TcpStream::connect((edge.host(), edge.mqtt_port)),
    )
    .await
    .expect("dial B in time")
    .expect("dial B");
    for (sock, user) in [(&mut a_sock, "alpha"), (&mut b_sock, "beta")] {
        let connect = sy02_connect311("mt07-dup", true, 60, Some((user, b"pw")));
        tokio::time::timeout(SHARD_E2E_STEP, sock.write_all(&connect))
            .await
            .expect("CONNECT in time")
            .expect("CONNECT send");
        let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(sock))
            .await
            .expect("CONNACK in time")
            .expect("CONNACK");
        assert_eq!(head, 0x20, "edge answers {user} with CONNACK");
        assert_eq!(
            sy02_parse_connack311(&body),
            (false, 0),
            "first CONNECT of {user} is accepted"
        );
    }
    // Both tenants subscribe to the same topic string.
    for sock in [&mut a_sock, &mut b_sock] {
        let subscribe = sy02_subscribe(1, &[("mt07/dup", 1)]);
        tokio::time::timeout(SHARD_E2E_STEP, sock.write_all(&subscribe))
            .await
            .expect("SUBSCRIBE in time")
            .expect("SUBSCRIBE send");
        let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(sock))
            .await
            .expect("SUBACK in time")
            .expect("SUBACK");
        assert_eq!(head, 0x90, "edge answers with SUBACK");
        assert_eq!(sy02_parse_suback(&body), (1, vec![1]));
    }
    // One publisher per tenant.
    let mut a_pub = tokio::time::timeout(
        SHARD_E2E_STEP,
        tokio::net::TcpStream::connect((edge.host(), edge.mqtt_port)),
    )
    .await
    .expect("dial A pub in time")
    .expect("dial A pub");
    let mut b_pub = tokio::time::timeout(
        SHARD_E2E_STEP,
        tokio::net::TcpStream::connect((edge.host(), edge.mqtt_port)),
    )
    .await
    .expect("dial B pub in time")
    .expect("dial B pub");
    for (sock, id, user) in [
        (&mut a_pub, "mt07-a-pub", "alpha"),
        (&mut b_pub, "mt07-b-pub", "beta"),
    ] {
        let connect = sy02_connect311(id, true, 60, Some((user, b"pw")));
        tokio::time::timeout(SHARD_E2E_STEP, sock.write_all(&connect))
            .await
            .expect("pub CONNECT in time")
            .expect("pub CONNECT send");
        let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(sock))
            .await
            .expect("pub CONNACK in time")
            .expect("pub CONNACK");
        assert_eq!(head, 0x20, "edge answers the publisher with CONNACK");
        assert_eq!(sy02_parse_connack311(&body), (false, 0));
    }
    // A publish in tenant A reaches A only. B stays silent.
    let publish = sy02_publish311("mt07/dup", 1, 1, false, b"from-a");
    tokio::time::timeout(SHARD_E2E_STEP, a_pub.write_all(&publish))
        .await
        .expect("publish in time")
        .expect("publish send");
    let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut a_pub))
        .await
        .expect("PUBACK in time")
        .expect("PUBACK");
    assert_eq!(head, 0x40, "publisher sees PUBACK");
    assert_eq!(body, vec![0, 1], "PUBACK mirrors its packet id");
    let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut a_sock))
        .await
        .expect("A downlink in time")
        .expect("A downlink");
    assert_eq!(head & 0xF0, 0x30, "downlink is PUBLISH");
    let downlink = sy02_parse_publish_classic(head, &body);
    assert_eq!(downlink.topic, "mt07/dup");
    assert_eq!(downlink.payload, b"from-a");
    tokio::time::timeout(
        SHARD_E2E_STEP,
        a_sock.write_all(&sy02_puback(downlink.packet_id)),
    )
    .await
    .expect("PUBACK in time")
    .expect("PUBACK send");
    let silent = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_mqtt_packet(&mut b_sock),
    )
    .await;
    assert!(silent.is_err(), "B holds none of A's publish");
    // A publish in tenant B reaches B only. A stays silent.
    let publish = sy02_publish311("mt07/dup", 2, 1, false, b"from-b");
    tokio::time::timeout(SHARD_E2E_STEP, b_pub.write_all(&publish))
        .await
        .expect("publish in time")
        .expect("publish send");
    let (head, _) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut b_pub))
        .await
        .expect("PUBACK in time")
        .expect("PUBACK");
    assert_eq!(head, 0x40, "publisher sees PUBACK");
    let (head, body) = tokio::time::timeout(SHARD_E2E_STEP, read_mqtt_packet(&mut b_sock))
        .await
        .expect("B downlink in time")
        .expect("B downlink");
    assert_eq!(head & 0xF0, 0x30, "downlink is PUBLISH");
    let downlink = sy02_parse_publish_classic(head, &body);
    assert_eq!(downlink.topic, "mt07/dup");
    assert_eq!(downlink.payload, b"from-b");
    tokio::time::timeout(
        SHARD_E2E_STEP,
        b_sock.write_all(&sy02_puback(downlink.packet_id)),
    )
    .await
    .expect("PUBACK in time")
    .expect("PUBACK send");
    let silent = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_mqtt_packet(&mut a_sock),
    )
    .await;
    assert!(silent.is_err(), "A holds none of B's publish");

    edge.finish().await;
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&scratch);
    let _ = std::fs::remove_dir_all(&config_dir);
}
