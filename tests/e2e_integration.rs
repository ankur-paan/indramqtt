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
/// `UserLen | Username | PassLen | Password` credentials section).
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
            return None;
        }
        let username = std::str::from_utf8(&rest[2..2 + user_len])
            .ok()?
            .to_string();
        let pass_len = u16::from_be_bytes([rest[2 + user_len], rest[3 + user_len]]) as usize;
        if rest.len() != 4 + user_len + pass_len {
            return None;
        }
        let password = rest[4 + user_len..].to_vec();
        (Some(username), Some(password))
    };
    Some((client_id, flags & 0x01 != 0, keepalive, username, password))
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
async fn e2e_edge_target(bl_port: u16) -> Option<(EdgeTarget, u16)> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebin = manifest.join("../../beam/ebin");
    let ebin = ebin.canonicalize().unwrap_or(ebin);
    if !ebin.join("indra_edge.app").is_file() {
        eprintln!(
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
        let args = vec![
            "-noshell".to_string(),
            "-pa".to_string(),
            ebin.to_string_lossy().into_owned(),
            "-indra_edge".to_string(),
            "mqtt_port".to_string(),
            mqtt_port.to_string(),
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
            eprintln!("SKIP kicked_mqtt_client_sees_disconnect: no `erl` on PATH and none in WSL");
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
        // Firewall proxy (see `E2E_PROXY_SCRIPT`): the edge dials the
        // proxy through the gateway; the proxy forwards to `bl_port`
        // on loopback. Without it the edge's SYNs never reach this
        // binary and the edge never gets past BrokerLink init.
        if !e2e_command_output("python", &["--version"], KICK_E2E_PROBE)
            .await
            .as_ref()
            .is_some_and(|out| out.status.success())
        {
            eprintln!(
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
        ));
    }
    eprintln!("SKIP kicked_mqtt_client_sees_disconnect: no `erl` on PATH");
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
    let (edge, mqtt_port) = match e2e_edge_target(bl_port).await {
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
                Ok(Some(frame)) => forwarder_conns.route(frame.header.conn_id, frame),
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
    assert_eq!(changed.status(), 200);
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

/// Decode `SessionBinding` metadata into `(session_id, present, rc)`.
fn shard_decode_binding(meta: &[u8]) -> (u64, bool, u8) {
    assert_eq!(meta.len(), 10, "SessionBinding meta must be 10 bytes");
    let session_id = u64::from_be_bytes(meta[0..8].try_into().unwrap());
    (session_id, meta[8] != 0, meta[9])
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
    let (session_id, present, rc) = shard_decode_binding(&reply.metadata);
    assert_eq!(rc, 0, "bind of {client_id} must be accepted");
    assert_ne!(session_id, 0);
    (session_id, present)
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
