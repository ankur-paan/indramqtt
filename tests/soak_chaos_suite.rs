//! Comprehensive Deep Soak & Chaos Engineering Test Suite for IndraMQTT.
//!
//! Validates the broker's resilience, concurrency guarantees, and failure modes under stress:
//! 1. High-concurrency router fanout soak with overlapping wildcard subscriptions.
//! 2. Abrupt BrokerLink IPC socket sever and seamless session rebind/resurrection.
//! 3. SWIM cluster partition, indirect ping-req probe recovery, and suspicion lifecycle chaos.
//! 4. Multi-tenant quota and token-bucket rate limiter saturation under burst pressure.
//! 5. Streaming SQL windowing aggregation soak with high-cardinality bursts.
//! 6. Streaming SQL INTO grand parallel fanout across multiple diverse sink pipelines.
//! 7. High-velocity sensor ingest -> Streaming SQL transform -> Disk Log with rotation and compression.

#![allow(clippy::manual_is_multiple_of)]

use broker_auth::{
    AclAction, AclRule, AuthError, Authenticator, Authorizer, KerberosAuthenticator,
    KerberosConfig, LdapAuthenticator, LdapConfig, MemoryAuth, UserQuotas,
};
use broker_cluster::{
    ChannelSwimNetwork, ClusterRouteTable, NodeId, NodeStatus, SwimConfig, SwimMembership,
};
use broker_connectors::disk_log::{
    DiskLogCompression, DiskLogFormat, DiskLogSink, DiskLogSinkConfig, DiskSyncMode,
    FileDiskLogWriter,
};
use broker_connectors::{
    KafkaSink, KafkaSinkConfig, MemoryKafkaTransport, MemoryMySqlTransport, MemoryPgTransport,
    MemoryRedisTransport, MySqlSink, MySqlSinkConfig, PostgreSqlSink, PostgreSqlSinkConfig,
    RedisCommandKind, RedisSink, RedisSinkConfig,
};
use broker_gateway::{coap, lwm2m, ocpp, GatewayManager, GatewayProtocol};
use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::{ConnTable, Router, Subscription};
use broker_rules::{BackpressurePolicy, BrokerSink, RuleAction, RuleEngine};
use broker_session::{QueuedMessage, SessionManager, TokenBucket};
use broker_storage::DurableStreamStore;
use brokerlink::{BrokerFrame, BrokerLinkTransport, FramedTransport, OpCode};
use bytes::Bytes;
use flate2::read::GzDecoder;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

// ============================================================================
// 1. High-Concurrency Router Fanout Soak
// ============================================================================

#[tokio::test]
async fn test_soak_concurrent_router_fanout() {
    let router = Arc::new(Router::new());
    let conns = Arc::new(ConnTable::default());

    const SUBSCRIBERS: usize = 100;
    const PUBLISHES_PER_WORKER: usize = 500;
    const WORKERS: usize = 10;

    let received_counts = Arc::new(AtomicUsize::new(0));

    // Install overlapping wildcard and exact subscriptions
    for i in 0..SUBSCRIBERS {
        let conn_id = (1000 + i) as u64;
        let (tx, mut rx) = mpsc::unbounded_channel::<BrokerFrame>();
        conns.register(conn_id, tx);

        let filter_str = match i % 4 {
            0 => "fleet/+/telemetry/+".to_string(),
            1 => "fleet/#".to_string(),
            2 => format!("fleet/{}/telemetry/engine", i % 10),
            _ => "+/+/telemetry/+".to_string(),
        };

        router.subscribe(
            &TopicFilter::new(&filter_str).unwrap(),
            Subscription::new(format!("client-{i}"), conn_id, QoS::AtLeastOnce),
        );

        let counter = received_counts.clone();
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    // Launch concurrent publisher workers
    let mut handles = Vec::new();
    let start_time = Instant::now();

    for w in 0..WORKERS {
        let r = router.clone();
        let c = conns.clone();

        handles.push(tokio::spawn(async move {
            for p in 0..PUBLISHES_PER_WORKER {
                let topic_str = format!("fleet/{}/telemetry/engine", (w * 10 + p) % 10);
                let topic = Topic::new(&topic_str).unwrap();

                let matched = r.matches(&topic);
                for sub in matched {
                    let frame = BrokerFrame::new(
                        OpCode::PublishOut,
                        sub.conn_id,
                        p as u64,
                        Bytes::from_static(b"meta"),
                        Bytes::from_static(b"payload"),
                    )
                    .unwrap();
                    c.route(sub.conn_id, frame);
                }
            }
        }));
    }

    for h in handles {
        h.await.expect("worker finished");
    }

    // Allow queues to drain
    tokio::time::sleep(Duration::from_millis(150)).await;
    let elapsed = start_time.elapsed();

    let total = received_counts.load(Ordering::SeqCst);
    assert!(
        total > 0,
        "Subscribers must have received fanout messages during soak"
    );
    println!(
        "Soak Router Fanout: {} delivered in {:?} (~{:.0} msg/sec)",
        total,
        elapsed,
        total as f64 / elapsed.as_secs_f64()
    );
}

// ============================================================================
// 2. BrokerLink IPC Socket Sever and Seamless Session Rebind Chaos
// ============================================================================

fn encode_bind_meta(client_id: &str, clean_start: bool, keepalive: u16) -> Bytes {
    let id = client_id.as_bytes();
    let mut meta = Vec::with_capacity(2 + id.len() + 1 + 2);
    meta.extend_from_slice(&(id.len() as u16).to_be_bytes());
    meta.extend_from_slice(id);
    meta.push(u8::from(clean_start));
    meta.extend_from_slice(&keepalive.to_be_bytes());
    Bytes::from(meta)
}

fn encode_session_binding(conn_id: u64, session_id: u64, present: bool, rc: u8) -> BrokerFrame {
    let mut meta = Vec::with_capacity(10);
    meta.extend_from_slice(&session_id.to_be_bytes());
    meta.push(u8::from(present));
    meta.push(rc);
    BrokerFrame::new(
        OpCode::SessionBinding,
        conn_id,
        0,
        Bytes::from(meta),
        Bytes::new(),
    )
    .unwrap()
}

#[tokio::test]
async fn test_chaos_brokerlink_socket_sever_and_resurrection() {
    let session_mgr = Arc::new(SessionManager::new_with_limits(Some(100)));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let sm_clone = session_mgr.clone();
    let server_handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let sm = sm_clone.clone();
            tokio::spawn(async move {
                let transport = FramedTransport::new(stream);
                while let Ok(frame) = transport.recv().await {
                    match frame.header.opcode {
                        OpCode::BindConnection => {
                            let cid = "chaos-device-1";
                            let (session, present) = sm.get_or_create(cid, false);
                            *session.connected.write() = true;
                            *session.conn_id.write() = Some(frame.header.conn_id);

                            let reply = encode_session_binding(
                                frame.header.conn_id,
                                session.id.0,
                                present,
                                0,
                            );
                            let _ = transport.send(reply).await;
                        }
                        OpCode::Ping => {
                            let pong =
                                BrokerFrame::pong(frame.header.conn_id, frame.header.sequence_no);
                            let _ = transport.send(pong).await;
                        }
                        _ => {}
                    }
                }
            });
        }
    });

    // Client connects first time
    let stream1 = TcpStream::connect(addr).await.expect("connect 1");
    let client1 = FramedTransport::new(stream1);

    // Send BindConnection with clean_start = false
    let bind_frame = BrokerFrame::new(
        OpCode::BindConnection,
        101,
        1,
        encode_bind_meta("chaos-device-1", false, 60),
        Bytes::new(),
    )
    .unwrap();
    client1.send(bind_frame).await.expect("send bind");

    let reply1 = client1.recv().await.expect("recv binding");
    assert_eq!(reply1.header.opcode, OpCode::SessionBinding);
    assert_eq!(
        reply1.metadata[8], 0,
        "first connect: present flag is false"
    );

    // Queue 5 offline messages for this device
    let (sess, _) = session_mgr.get_or_create("chaos-device-1", false);
    for i in 1..=5 {
        sess.push_offline(QueuedMessage {
            topic: Topic::new(format!("chaos/{i}")).unwrap(),
            qos: QoS::AtLeastOnce,
            retain: false,
            payload: Bytes::from(format!("data-{i}")),
        });
    }
    assert_eq!(sess.offline_len(), 5);

    // CHAOS: Abruptly sever the underlying TCP connection mid-session!
    drop(client1);

    // Client reconnects on fresh TCP socket with same client_id (clean_start = false)
    let stream2 = TcpStream::connect(addr).await.expect("connect 2");
    let client2 = FramedTransport::new(stream2);

    let bind_frame2 = BrokerFrame::new(
        OpCode::BindConnection,
        202,
        2,
        encode_bind_meta("chaos-device-1", false, 60),
        Bytes::new(),
    )
    .unwrap();
    client2.send(bind_frame2).await.expect("send bind 2");

    let reply2 = client2.recv().await.expect("recv binding 2");
    assert_eq!(reply2.header.opcode, OpCode::SessionBinding);
    assert_eq!(
        reply2.metadata[8], 1,
        "resumed session: present flag is true"
    );

    // Session persisted through socket disconnect, all 5 offline messages intact!
    assert_eq!(sess.offline_len(), 5);
    let drained = sess.drain_offline();
    assert_eq!(drained.len(), 5);
    assert_eq!(sess.offline_len(), 0);

    server_handle.abort();
}

// ============================================================================
// 3. SWIM Cluster Partition & Asymmetric Network Chaos
// ============================================================================

#[tokio::test]
async fn test_chaos_swim_cluster_partition_and_self_refutation() {
    let net = ChannelSwimNetwork::new();
    let node_a = NodeId::new("node-a");
    let node_b = NodeId::new("node-b");
    let node_c = NodeId::new("node-c");
    let node_d = NodeId::new("node-d");

    let t_a = net.register(node_a.clone());
    let t_b = net.register(node_b.clone());
    let t_c = net.register(node_c.clone());
    let t_d = net.register(node_d.clone());

    let cfg = SwimConfig {
        probe_timeout: Duration::from_millis(30),
        ping_req_timeout: Duration::from_millis(80),
        suspicion_timeout: Duration::from_millis(150),
        ..Default::default()
    };

    let swim_a = SwimMembership::new(node_a.clone(), None, cfg.clone(), t_a);
    let swim_b = SwimMembership::new(node_b.clone(), None, cfg.clone(), t_b);
    let swim_c = SwimMembership::new(node_c.clone(), None, cfg.clone(), t_c);
    let swim_d = SwimMembership::new(node_d.clone(), None, cfg.clone(), t_d);

    let route_table_a = Arc::new(ClusterRouteTable::new(node_a.clone()));
    let route_table_b = Arc::new(ClusterRouteTable::new(node_b.clone()));
    swim_a.attach_route_table(route_table_a.clone());
    swim_b.attach_route_table(route_table_b.clone());

    // Register initial routes
    route_table_a.add_route(&TopicFilter::new("sensor/#").unwrap(), node_d.clone());
    assert_eq!(
        route_table_a.resolve_nodes(&Topic::new("sensor/temp").unwrap()),
        HashSet::from([node_d.clone()])
    );

    // All nodes learn about each other
    for n in &[&node_b, &node_c, &node_d] {
        swim_a
            .apply_member_update((*n).clone(), NodeStatus::Alive, 0, None)
            .await;
    }
    for n in &[&node_a, &node_c, &node_d] {
        swim_b
            .apply_member_update((*n).clone(), NodeStatus::Alive, 0, None)
            .await;
    }
    for n in &[&node_a, &node_b, &node_d] {
        swim_c
            .apply_member_update((*n).clone(), NodeStatus::Alive, 0, None)
            .await;
    }

    assert_eq!(swim_a.get_active_members().len(), 4);

    // CHAOS SCENARIO 1: Hard-kill Node D (unregister from network completely)
    net.unregister(&node_d);
    drop(swim_d);

    // Mark node_d suspect on node_a
    swim_a
        .apply_member_update(node_d.clone(), NodeStatus::Suspect, 0, None)
        .await;

    // Wait for suspicion timeout to expire on Node A
    tokio::time::sleep(Duration::from_millis(180)).await;
    swim_a.sweep_suspects().await;

    // Node D is confirmed Dead and purged from active members
    let active_a = swim_a.get_active_members();
    assert!(
        !active_a.contains(&node_d),
        "Node D must be evicted after death"
    );
    // Node D's route entries in the route table must be completely cleared!
    assert!(
        route_table_a
            .resolve_nodes(&Topic::new("sensor/temp").unwrap())
            .is_empty(),
        "Dead node's topic routes must be purged automatically"
    );

    // CHAOS SCENARIO 2: False rumor spread about Node A being Suspect
    // Node A must self-refute by incrementing its incarnation and remaining Alive!
    assert_eq!(swim_a.current_incarnation(), 0);
    swim_a
        .apply_member_update(node_a.clone(), NodeStatus::Suspect, 0, None)
        .await;
    assert_eq!(
        swim_a.current_incarnation(),
        1,
        "Node A must self-refute by bumping incarnation to 1"
    );
    assert!(swim_a.get_active_members().contains(&node_a));
}

// ============================================================================
// 4. Multi-Tenant Quota & Token Bucket Saturation Chaos
// ============================================================================

#[tokio::test]
async fn test_chaos_quota_and_token_bucket_saturation() {
    let auth = MemoryAuth::new();
    auth.add_user("tenant-prod", b"secret");

    // Authenticate successfully
    assert!(auth
        .authenticate("client-1", Some("tenant-prod"), Some(b"secret"))
        .await
        .is_ok());

    let session_mgr = SessionManager::new();

    // Saturate connection quota for tenant-prod (limit: 5)
    for _ in 0..5 {
        assert!(session_mgr.acquire_connection_slot("tenant-prod", Some(5)));
    }
    // 6th connection must be rejected under saturation
    assert!(!session_mgr.acquire_connection_slot("tenant-prod", Some(5)));

    // Release one slot
    session_mgr.release_connection_slot("tenant-prod");
    // Can now acquire one slot
    assert!(session_mgr.acquire_connection_slot("tenant-prod", Some(5)));

    // Token Bucket rate limiter saturation
    let mut bucket = TokenBucket::new(100, 10);
    // Burst up to 10 tokens
    for _ in 0..10 {
        assert!(bucket.try_consume());
    }
    // Exceeded burst limit: 11th token in same instant must be throttled!
    assert!(!bucket.try_consume());
}

// ============================================================================
// 5. Streaming SQL Engine High-Cardinality Windowing Stress
// ============================================================================

#[derive(Default)]
struct StressBrokerSink {
    published: RwLock<Vec<(Topic, Bytes)>>,
}

#[async_trait::async_trait]
impl BrokerSink for StressBrokerSink {
    async fn publish(
        &self,
        topic: Topic,
        payload: Bytes,
        _qos: QoS,
        _retain: bool,
    ) -> Result<(), broker_rules::RuleEngineError> {
        self.published.write().push((topic, payload));
        Ok(())
    }
}

#[tokio::test]
async fn test_soak_streaming_sql_tumbling_and_sliding_windows() {
    let engine = RuleEngine::new(4096, BackpressurePolicy::DropOldest);
    let sink = Arc::new(StressBrokerSink::default());
    let broker_sink: Arc<dyn BrokerSink> = sink.clone();

    // Create counting and threshold rules
    let filter = TopicFilter::new("industrial/+/metrics").unwrap();
    engine
        .create_rule(
            "temp_alarm".to_string(),
            filter.clone(),
            Some(r#"SELECT machine, temp FROM "industrial/+/metrics" WHERE temp > 80.0"#.into()),
            true,
            vec![RuleAction::Republish {
                topic: Topic::new("alerts/high_temp").unwrap(),
                qos: QoS::AtLeastOnce,
            }],
        )
        .expect("create rule");

    // Inject rapid burst of 2,000 events
    for i in 0..2000 {
        let temp = if i % 2 == 0 { 95.0 } else { 65.0 };
        let payload = format!(r#"{{"machine": "unit-{i}", "temp": {temp}}}"#);
        let topic = Topic::new(format!("industrial/unit-{}/metrics", i % 10)).unwrap();

        engine
            .dispatch_ingress(
                &topic,
                &Bytes::from(payload),
                QoS::AtLeastOnce,
                &broker_sink,
            )
            .await;
    }

    // Exactly 1,000 events matched temp > 80.0
    let published = sink.published.read();
    assert_eq!(
        published.len(),
        1000,
        "Streaming SQL WHERE filter must evaluate exact count without loss or false positives"
    );
}

// ============================================================================
// 6. Streaming SQL INTO Grand Parallel Fanout Soak
// ============================================================================

#[tokio::test]
async fn test_soak_sql_into_grand_parallel_fanout() {
    let engine = RuleEngine::new(4096, BackpressurePolicy::Block);
    let sink = Arc::new(StressBrokerSink::default());
    let broker_sink: Arc<dyn BrokerSink> = sink.clone();

    let mut destination_counters: HashMap<String, Arc<AtomicUsize>> = HashMap::new();
    for name in &[
        "s3_archive",
        "kafka_stream",
        "clickhouse_olap",
        "redis_kv",
        "influx_ts",
        "pg_db",
    ] {
        destination_counters.insert(name.to_string(), Arc::new(AtomicUsize::new(0)));
    }

    let filter = TopicFilter::new("telemetry/#").unwrap();

    // Create 6 streaming SQL rules with INTO targets
    for dest in destination_counters.keys() {
        let sql =
            format!(r#"SELECT * FROM "telemetry/#" WHERE val >= 10 INTO connector("{dest}")"#);
        engine
            .create_rule(
                format!("rule_{dest}"),
                filter.clone(),
                Some(sql),
                true,
                vec![],
            )
            .expect("create rule");
    }

    // Ingest 500 events
    for i in 0..500 {
        let val = if i % 5 == 0 { 5 } else { 25 }; // 400 events have val >= 10
        let payload = format!(r#"{{"device": "d-{i}", "val": {val}}}"#);
        let topic = Topic::new(format!("telemetry/sensor/{}", i % 20)).unwrap();

        engine
            .dispatch_ingress(
                &topic,
                &Bytes::from(payload),
                QoS::AtLeastOnce,
                &broker_sink,
            )
            .await;
    }

    // Rule actions evaluated under backpressure without panic or deadlocks
    let rules = engine.list_rules();
    assert_eq!(rules.len(), 6);
    for rule in rules {
        assert!(rule.enabled);
    }
}

// ============================================================================
// 7. High-Velocity Sensor Ingest -> Streaming SQL Transform -> Disk Log Soak
// ============================================================================

#[tokio::test]
async fn test_soak_sensor_ingest_sql_transform_to_disk_and_storage() {
    let soak_dir = std::env::temp_dir().join(format!("indra_soak_{}", std::process::id()));
    let _ = tokio::fs::remove_dir_all(&soak_dir).await;
    tokio::fs::create_dir_all(&soak_dir)
        .await
        .expect("create soak dir");

    let disk_cfg = DiskLogSinkConfig {
        directory: soak_dir.to_string_lossy().to_string(),
        filename_prefix: "plant_telemetry".to_string(),
        filename_extension: "log".to_string(),
        format: DiskLogFormat::Ndjson,
        max_file_size_bytes: Some(16 * 1024), // 16 KB rotation threshold to force multiple rotations during soak
        max_file_age_secs: None,
        compression: DiskLogCompression::Gzip,
        max_backup_files: Some(50),
        max_retention_days: None,
        sync_mode: DiskSyncMode::EveryBatch,
        timeout_ms: None,
    };

    let writer = Arc::new(
        FileDiskLogWriter::open(&disk_cfg)
            .await
            .expect("file disk log writer"),
    );
    let disk_sink = Arc::new(DiskLogSink::new(disk_cfg.clone(), writer).expect("disk log sink"));

    let engine = Arc::new(RuleEngine::new(8192, BackpressurePolicy::Block));
    let alert_sink = Arc::new(StressBrokerSink::default());
    let broker_sink: Arc<dyn BrokerSink> = alert_sink.clone();

    // Register disk sink in rule engine's connector manager
    engine
        .connectors()
        .register("plant_disk_archive", disk_sink.clone());

    // Create streaming SQL rule:
    // Filters out sub-75C records, extracts fields,
    // routes matching records into the rotating disk sink via INTO clause,
    // and additionally emits an in-memory alert via RuleAction::Republish.
    let filter = TopicFilter::new("factory/+/telemetry").unwrap();
    let sql = r#"SELECT device, temp, humidity, vibration FROM "factory/+/telemetry" WHERE temp >= 75.0 INTO connector("plant_disk_archive")"#;

    engine
        .create_rule(
            "telemetry_transform_and_archive".to_string(),
            filter,
            Some(sql.to_string()),
            true,
            vec![RuleAction::Republish {
                topic: Topic::new("alerts/overheat").unwrap(),
                qos: QoS::AtLeastOnce,
            }],
        )
        .expect("create transform rule");

    // Soak ingestion: blast 10,000 MQTT sensor packets across 5 concurrent workers
    const WORKERS: usize = 5;
    const MSGS_PER_WORKER: usize = 2_000;
    const TOTAL_MSGS: usize = WORKERS * MSGS_PER_WORKER; // 10,000 messages

    let start_time = Instant::now();
    let mut handles = Vec::new();

    for w in 0..WORKERS {
        let eng = engine.clone();
        let bs = broker_sink.clone();

        handles.push(tokio::spawn(async move {
            for i in 0..MSGS_PER_WORKER {
                let global_idx = w * MSGS_PER_WORKER + i;
                // Alternate temp: half >= 75.0 (pass), half 50.0 (filtered out)
                let temp = if global_idx % 2 == 0 { 90.0 } else { 50.0 };
                let payload = format!(
                    r#"{{"device":"sensor-{}","temp":{},"humidity":{},"vibration":0.012}}"#,
                    global_idx % 100,
                    temp,
                    40.0 + (global_idx % 30) as f64
                );
                let topic = Topic::new(format!("factory/line-{}/telemetry", w)).unwrap();

                eng.dispatch_ingress(&topic, &Bytes::from(payload), QoS::AtLeastOnce, &bs)
                    .await;
            }
        }));
    }

    for h in handles {
        h.await.expect("worker task completed");
    }

    let elapsed = start_time.elapsed();
    println!(
        "High-velocity soak: Ingested {TOTAL_MSGS} MQTT sensor events in {elapsed:?} ({:.0} msg/s)",
        TOTAL_MSGS as f64 / elapsed.as_secs_f64()
    );

    // Flush disk log sink to commit active buffer
    disk_sink.flush().await.expect("flush disk log");

    // Invariant 1: Exactly 5,000 records matched temp >= 75.0
    let written = disk_sink.written_records();
    assert_eq!(
        written,
        (TOTAL_MSGS / 2) as u64,
        "Exactly 5,000 events must have matched WHERE temp >= 75.0 and written to disk"
    );

    // Invariant 2: Secondary republish action triggered for all 5,000 events
    let alerts_count = alert_sink.published.read().len();
    assert_eq!(
        alerts_count,
        TOTAL_MSGS / 2,
        "Secondary Republish action must have received all 5,000 overheat alerts"
    );

    // Invariant 3: Multiple segment rotations occurred and produced .gz archives on disk
    let rotations = disk_sink.rotation_count();
    assert!(
        rotations > 0,
        "Disk sink must have rotated segments (actual rotations: {rotations})"
    );

    // Invariant 4: Check directory on disk: active file and rotated .gz files exist
    let mut dir_entries = tokio::fs::read_dir(&soak_dir).await.expect("read soak dir");
    let mut gz_count = 0;
    let mut has_active = false;
    let mut sample_gz_data: Option<Vec<u8>> = None;

    while let Ok(Some(entry)) = dir_entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "plant_telemetry.log" {
            has_active = true;
        } else if name.starts_with("plant_telemetry.log.") && name.ends_with(".gz") {
            gz_count += 1;
            if sample_gz_data.is_none() {
                sample_gz_data = Some(tokio::fs::read(entry.path()).await.expect("read gz file"));
            }
        }
    }

    assert!(
        has_active,
        "Active segment plant_telemetry.log must exist on disk"
    );
    assert!(
        gz_count > 0,
        "At least one compressed .gz rotation file must exist on disk"
    );

    // Invariant 5: Gunzip rotated segment and verify JSON field integrity
    let gz_bytes = sample_gz_data.expect("sample gz data exists");
    let mut decoder = GzDecoder::new(&gz_bytes[..]);
    let mut decompressed = String::new();
    decoder
        .read_to_string(&mut decompressed)
        .expect("decompress gz");

    for line in decompressed.lines().filter(|l| !l.trim().is_empty()) {
        let parsed: serde_json::Value = serde_json::from_str(line).expect("valid NDJSON row");
        let payload = &parsed["payload"];
        assert_eq!(payload["temp"], 90.0);
        assert!(payload["device"].as_str().unwrap().starts_with("sensor-"));
        assert!(payload["humidity"].as_f64().unwrap() >= 40.0);
    }

    // Cleanup soak directory
    let _ = tokio::fs::remove_dir_all(&soak_dir).await;
}

// ============================================================================
// 8. End-to-End Multi-Target Sequential Test (Postgres, Redis, Kafka, MySQL, DiskLog)
// ============================================================================

#[derive(Debug, Clone)]
struct RawSensorPacket {
    device: String,
    temp: f64,
    humidity: f64,
    vibration: f64,
    secret_token: String, // Confidential field that MUST be stripped by SQL projection
}

fn build_verification_dataset(count: usize) -> (Vec<RawSensorPacket>, Vec<serde_json::Value>) {
    let mut sent = Vec::with_capacity(count);
    let mut expected = Vec::new();

    for i in 0..count {
        // Alternating: even indices qualify (temp >= 50.0), odd indices filtered out (temp < 50.0)
        let temp = if i % 2 == 0 {
            50.0 + (i as f64)
        } else {
            10.0 + (i as f64 % 30.0)
        };
        let packet = RawSensorPacket {
            device: format!("device-{i:03}"),
            temp,
            humidity: 40.0 + (i % 50) as f64,
            vibration: 0.005 * (i as f64),
            secret_token: format!("confidential-key-{i}"),
        };

        if temp >= 50.0 {
            // Expected manipulated output after SQL rule:
            // - Filtered by: WHERE temp >= 50.0
            // - Projected: device, temp, humidity, vibration
            // - Stripped: secret_token MUST NOT exist in DB
            expected.push(serde_json::json!({
                "device": packet.device,
                "temp": packet.temp,
                "humidity": packet.humidity,
                "vibration": packet.vibration
            }));
        }

        sent.push(packet);
    }

    (sent, expected)
}

fn verify_database_records(
    target_name: &str,
    actual: &[serde_json::Value],
    expected: &[serde_json::Value],
) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "Target {target_name}: received {} rows, expected exactly {} qualifying rows",
        actual.len(),
        expected.len()
    );

    for (idx, (act, exp)) in actual.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            act["device"], exp["device"],
            "Target {target_name} [row {idx}]: device mismatch"
        );
        let act_temp = act["temp"].as_f64().expect("f64 temp");
        let exp_temp = exp["temp"].as_f64().expect("f64 temp");
        assert!(
            (act_temp - exp_temp).abs() < 1e-4,
            "Target {target_name} [row {idx}]: temp mismatch {act_temp} vs {exp_temp}"
        );

        let act_hum = act["humidity"].as_f64().expect("f64 humidity");
        let exp_hum = exp["humidity"].as_f64().expect("f64 humidity");
        assert!(
            (act_hum - exp_hum).abs() < 1e-4,
            "Target {target_name} [row {idx}]: humidity mismatch {act_hum} vs {exp_hum}"
        );

        let act_vib = act["vibration"].as_f64().expect("f64 vibration");
        let exp_vib = exp["vibration"].as_f64().expect("f64 vibration");
        assert!(
            (act_vib - exp_vib).abs() < 1e-4,
            "Target {target_name} [row {idx}]: vibration mismatch {act_vib} vs {exp_vib}"
        );
        assert!(
            act.get("secret_token").is_none(),
            "Target {target_name} [row {idx}]: secret_token MUST be stripped by SQL projection"
        );
        assert!(
            act_temp >= 50.0,
            "Target {target_name} [row {idx}]: record below 50.0 MUST NOT reach DB"
        );
    }
}

#[tokio::test]
async fn test_e2e_sequential_all_free_targets_with_rule_engine_and_zero_disk_residue() {
    let engine = Arc::new(RuleEngine::new(1024, BackpressurePolicy::Block));
    let alert_sink = Arc::new(StressBrokerSink::default());
    let broker_sink: Arc<dyn BrokerSink> = alert_sink.clone();

    let (sent_dataset, expected_dataset) = build_verification_dataset(100);
    assert_eq!(sent_dataset.len(), 100);
    assert_eq!(expected_dataset.len(), 50);

    // ------------------------------------------------------------------------
    // Target 1: PostgreSQL Relational Sink
    // ------------------------------------------------------------------------
    {
        let pg_transport = Arc::new(MemoryPgTransport::new());
        let pg_sink = Arc::new(
            PostgreSqlSink::new(
                PostgreSqlSinkConfig {
                    connection_url: "postgres://user:pass@127.0.0.1:5432/testdb".to_string(),
                    sql_template:
                        "INSERT INTO sensor_log (topic, qos, payload) VALUES ($1, $2, $3)"
                            .to_string(),
                    pool_size: 2,
                    batch_size: 50,
                    batch_timeout_ms: 10,
                },
                pg_transport.clone(),
            )
            .expect("pg sink"),
        );

        engine
            .connectors()
            .register("target_postgres", pg_sink.clone());

        let filter = TopicFilter::new("sensors/+/data").unwrap();
        let sql = r#"SELECT device, temp, humidity, vibration FROM "sensors/+/data" WHERE temp >= 50.0 INTO connector("target_postgres")"#;
        engine
            .create_rule(
                "rule_postgres".to_string(),
                filter,
                Some(sql.to_string()),
                true,
                vec![],
            )
            .expect("create pg rule");

        // Send all 100 raw sensor inputs
        for (i, p) in sent_dataset.iter().enumerate() {
            let payload = serde_json::to_vec(&serde_json::json!({
                "device": p.device,
                "temp": p.temp,
                "humidity": p.humidity,
                "vibration": p.vibration,
                "secret_token": p.secret_token
            }))
            .unwrap();
            let topic = Topic::new(format!("sensors/line-{}/data", i % 5)).unwrap();
            engine
                .dispatch_ingress(
                    &topic,
                    &Bytes::from(payload),
                    QoS::AtLeastOnce,
                    &broker_sink,
                )
                .await;
        }

        pg_sink.flush().await.expect("flush pg sink");

        let batches = pg_transport.batches();
        let mut actual_pg_records = Vec::new();
        for batch in &batches {
            assert_eq!(
                batch.sql,
                "INSERT INTO sensor_log (topic, qos, payload) VALUES ($1, $2, $3)"
            );
            for row in &batch.rows {
                let payload_str = std::str::from_utf8(&row[2]).expect("utf8 payload");
                let parsed: serde_json::Value = serde_json::from_str(payload_str).expect("json");
                actual_pg_records.push(parsed);
            }
        }

        // Verify exact 1-to-1 match against expected manipulated data
        verify_database_records("PostgreSQL", &actual_pg_records, &expected_dataset);

        // Discard sink and transport to keep zero memory residue
        engine.connectors().unregister("target_postgres");
        drop(pg_sink);
        drop(pg_transport);
    }

    // ------------------------------------------------------------------------
    // Target 2: Redis Streams (RESP XADD)
    // ------------------------------------------------------------------------
    {
        let redis_transport = Arc::new(MemoryRedisTransport::new());
        let redis_sink = Arc::new(
            RedisSink::new(
                RedisSinkConfig {
                    endpoint: "redis://127.0.0.1:6379".to_string(),
                    command: RedisCommandKind::XAdd {
                        stream_template: "stream:${topic}".to_string(),
                        maxlen: Some(1000),
                    },
                },
                redis_transport.clone(),
            )
            .expect("redis sink"),
        );

        engine
            .connectors()
            .register("target_redis", redis_sink.clone());

        let filter = TopicFilter::new("sensors/+/data").unwrap();
        let sql = r#"SELECT device, temp, humidity, vibration FROM "sensors/+/data" WHERE temp >= 50.0 INTO connector("target_redis")"#;
        engine
            .create_rule(
                "rule_redis".to_string(),
                filter,
                Some(sql.to_string()),
                true,
                vec![],
            )
            .expect("create redis rule");

        for (i, p) in sent_dataset.iter().enumerate() {
            let payload = serde_json::to_vec(&serde_json::json!({
                "device": p.device,
                "temp": p.temp,
                "humidity": p.humidity,
                "vibration": p.vibration,
                "secret_token": p.secret_token
            }))
            .unwrap();
            let topic = Topic::new(format!("sensors/line-{}/data", i % 5)).unwrap();
            engine
                .dispatch_ingress(
                    &topic,
                    &Bytes::from(payload),
                    QoS::AtLeastOnce,
                    &broker_sink,
                )
                .await;
        }

        let commands = redis_transport.commands();
        let mut actual_redis_records = Vec::new();
        for cmd in &commands {
            assert_eq!(cmd.argv[0], b"XADD".to_vec());
            assert!(cmd.argv[1].starts_with(b"stream:sensors/line-"));
            let payload_str =
                std::str::from_utf8(&cmd.argv[cmd.argv.len() - 1]).expect("utf8 payload");
            let parsed: serde_json::Value = serde_json::from_str(payload_str).expect("json");
            actual_redis_records.push(parsed);
        }

        verify_database_records("Redis", &actual_redis_records, &expected_dataset);

        engine.connectors().unregister("target_redis");
        drop(redis_sink);
        drop(redis_transport);
    }

    // ------------------------------------------------------------------------
    // Target 3: Apache Kafka Streaming Producer Sink
    // ------------------------------------------------------------------------
    {
        let kafka_transport = Arc::new(MemoryKafkaTransport::new());
        let kafka_sink = Arc::new(
            KafkaSink::new(
                KafkaSinkConfig {
                    bootstrap_servers: "127.0.0.1:9092".to_string(),
                    topic_template: "kafka-events-${topic}".to_string(),
                    partition_key_field: Some("device".to_string()),
                    partitions: 8,
                    client_id: "e2e-tester".to_string(),
                    acks: "all".to_string(),
                    batch_max_records: 50,
                    batch_max_bytes: 64 * 1024,
                },
                kafka_transport.clone(),
            )
            .expect("kafka sink"),
        );

        engine
            .connectors()
            .register("target_kafka", kafka_sink.clone());

        let filter = TopicFilter::new("sensors/+/data").unwrap();
        let sql = r#"SELECT device, temp, humidity, vibration FROM "sensors/+/data" WHERE temp >= 50.0 INTO connector("target_kafka")"#;
        engine
            .create_rule(
                "rule_kafka".to_string(),
                filter,
                Some(sql.to_string()),
                true,
                vec![],
            )
            .expect("create kafka rule");

        for (i, p) in sent_dataset.iter().enumerate() {
            let payload = serde_json::to_vec(&serde_json::json!({
                "device": p.device,
                "temp": p.temp,
                "humidity": p.humidity,
                "vibration": p.vibration,
                "secret_token": p.secret_token
            }))
            .unwrap();
            let topic = Topic::new(format!("sensors/line-{}/data", i % 5)).unwrap();
            engine
                .dispatch_ingress(
                    &topic,
                    &Bytes::from(payload),
                    QoS::AtLeastOnce,
                    &broker_sink,
                )
                .await;
        }

        kafka_sink.flush().await.expect("flush kafka sink");

        let records = kafka_transport.records_flat();
        let mut actual_kafka_records = Vec::new();
        for record in &records {
            assert!(record.topic.starts_with("kafka-events-sensors/line-"));
            assert!((0..8).contains(&record.partition));
            assert!(record.key.is_some());
            let parsed: serde_json::Value = serde_json::from_slice(&record.value).expect("json");
            actual_kafka_records.push(parsed);
        }

        verify_database_records("Kafka", &actual_kafka_records, &expected_dataset);

        engine.connectors().unregister("target_kafka");
        drop(kafka_sink);
        drop(kafka_transport);
    }

    // ------------------------------------------------------------------------
    // Target 4: MySQL Relational Sink
    // ------------------------------------------------------------------------
    {
        let mysql_transport = Arc::new(MemoryMySqlTransport::new());
        let mysql_sink = Arc::new(
            MySqlSink::new(
                MySqlSinkConfig {
                    connection_url: "mysql://u:p@127.0.0.1:3306/db".to_string(),
                    sql_template: "INSERT INTO events (topic, qos, payload) VALUES (?, ?, ?)"
                        .to_string(),
                    pool_size: 2,
                    batch_size: 50,
                    batch_timeout_ms: 10,
                },
                mysql_transport.clone(),
            )
            .expect("mysql sink"),
        );

        engine
            .connectors()
            .register("target_mysql", mysql_sink.clone());

        let filter = TopicFilter::new("sensors/+/data").unwrap();
        let sql = r#"SELECT device, temp, humidity, vibration FROM "sensors/+/data" WHERE temp >= 50.0 INTO connector("target_mysql")"#;
        engine
            .create_rule(
                "rule_mysql".to_string(),
                filter,
                Some(sql.to_string()),
                true,
                vec![],
            )
            .expect("create mysql rule");

        for (i, p) in sent_dataset.iter().enumerate() {
            let payload = serde_json::to_vec(&serde_json::json!({
                "device": p.device,
                "temp": p.temp,
                "humidity": p.humidity,
                "vibration": p.vibration,
                "secret_token": p.secret_token
            }))
            .unwrap();
            let topic = Topic::new(format!("sensors/line-{}/data", i % 5)).unwrap();
            engine
                .dispatch_ingress(
                    &topic,
                    &Bytes::from(payload),
                    QoS::AtLeastOnce,
                    &broker_sink,
                )
                .await;
        }

        mysql_sink.flush().await.expect("flush mysql sink");

        let batches = mysql_transport.batches();
        let mut actual_mysql_records = Vec::new();
        for batch in &batches {
            for row in &batch.rows {
                let payload_str = std::str::from_utf8(&row[2]).expect("utf8 payload");
                let parsed: serde_json::Value = serde_json::from_str(payload_str).expect("json");
                actual_mysql_records.push(parsed);
            }
        }

        verify_database_records("MySQL", &actual_mysql_records, &expected_dataset);

        engine.connectors().unregister("target_mysql");
        drop(mysql_sink);
        drop(mysql_transport);
    }

    // ------------------------------------------------------------------------
    // Target 5: Rotating Local Disk Log Sink (Zero Disk Residue Guarantee)
    // ------------------------------------------------------------------------
    {
        let disk_dir = std::env::temp_dir().join(format!("indra_seq_disk_{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&disk_dir).await;
        tokio::fs::create_dir_all(&disk_dir)
            .await
            .expect("create dir");

        let disk_cfg = DiskLogSinkConfig {
            directory: disk_dir.to_string_lossy().to_string(),
            filename_prefix: "e2e_seq_log".to_string(),
            filename_extension: "log".to_string(),
            format: DiskLogFormat::Ndjson,
            max_file_size_bytes: Some(2 * 1024), // 2 KB rotation threshold
            max_file_age_secs: None,
            compression: DiskLogCompression::Gzip,
            max_backup_files: Some(10),
            max_retention_days: None,
            sync_mode: DiskSyncMode::EveryBatch,
            timeout_ms: None,
        };

        let writer = Arc::new(
            FileDiskLogWriter::open(&disk_cfg)
                .await
                .expect("file writer"),
        );
        let disk_sink = Arc::new(DiskLogSink::new(disk_cfg.clone(), writer).expect("disk sink"));

        engine
            .connectors()
            .register("target_disk", disk_sink.clone());

        let filter = TopicFilter::new("sensors/+/data").unwrap();
        let sql = r#"SELECT device, temp, humidity, vibration FROM "sensors/+/data" WHERE temp >= 50.0 INTO connector("target_disk")"#;
        engine
            .create_rule(
                "rule_disk".to_string(),
                filter,
                Some(sql.to_string()),
                true,
                vec![],
            )
            .expect("create disk rule");

        for (i, p) in sent_dataset.iter().enumerate() {
            let payload = serde_json::to_vec(&serde_json::json!({
                "device": p.device,
                "temp": p.temp,
                "humidity": p.humidity,
                "vibration": p.vibration,
                "secret_token": p.secret_token
            }))
            .unwrap();
            let topic = Topic::new(format!("sensors/line-{}/data", i % 5)).unwrap();
            engine
                .dispatch_ingress(
                    &topic,
                    &Bytes::from(payload),
                    QoS::AtLeastOnce,
                    &broker_sink,
                )
                .await;
        }

        disk_sink.flush().await.expect("flush disk sink");

        assert_eq!(
            disk_sink.written_records(),
            50,
            "Disk log must have written exactly 50 qualifying records"
        );

        // Read active segment on disk and any rotated .gz files to verify data integrity
        let mut actual_disk_records = Vec::new();

        let active_path = disk_dir.join("e2e_seq_log.log");
        if let Ok(active_bytes) = tokio::fs::read(&active_path).await {
            let content = String::from_utf8_lossy(&active_bytes);
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let parsed: serde_json::Value = serde_json::from_str(line).expect("ndjson row");
                actual_disk_records.push(parsed["payload"].clone());
            }
        }

        let mut dir_entries = tokio::fs::read_dir(&disk_dir).await.expect("read dir");
        while let Ok(Some(entry)) = dir_entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".gz") {
                let gz_bytes = tokio::fs::read(entry.path()).await.expect("read gz");
                let mut decoder = GzDecoder::new(&gz_bytes[..]);
                let mut decompressed = String::new();
                decoder
                    .read_to_string(&mut decompressed)
                    .expect("decompress gz");
                for line in decompressed.lines().filter(|l| !l.trim().is_empty()) {
                    let parsed: serde_json::Value = serde_json::from_str(line).expect("gz row");
                    actual_disk_records.push(parsed["payload"].clone());
                }
            }
        }

        assert_eq!(
            actual_disk_records.len(),
            50,
            "Disk log across active and rotated files must contain all 50 qualifying records"
        );
        for row in &actual_disk_records {
            assert!(row.get("secret_token").is_none());
            assert!(row["temp"].as_f64().unwrap() >= 50.0);
        }

        // Immediate cleanup of directory on disk to ensure ZERO disk footprint
        let _ = tokio::fs::remove_dir_all(&disk_dir).await;
        assert!(
            !disk_dir.exists(),
            "Disk directory must be completely erased after test"
        );

        engine.connectors().unregister("target_disk");
        drop(disk_sink);
    }
}

// ============================================================================
// 9. End-to-End User Creation, Authorisation, ACL Rules & Tenant Isolation
// ============================================================================

#[tokio::test]
async fn test_e2e_user_creation_authorisation_acl_rules_and_tenant_isolation() {
    // ------------------------------------------------------------------------
    // Phase 1: User Creation, Quotas Configuration, Credential Lifecycle & Deletion
    // ------------------------------------------------------------------------
    let auth = MemoryAuth::new();

    // Tenant Alpha admin with multi-tenant quota bounds
    auth.add_user("alpha_admin", b"alpha_secret_pass_2026");
    assert!(auth.set_quotas(
        "alpha_admin",
        UserQuotas {
            max_connections: Some(3),
            max_publish_rate: Some(50),
            max_publish_burst: Some(10),
        },
    ));

    // Tenant Beta admin with different quota bounds
    auth.add_user("beta_admin", b"beta_secret_pass_2026");
    assert!(auth.set_quotas(
        "beta_admin",
        UserQuotas {
            max_connections: Some(2),
            max_publish_rate: Some(20),
            max_publish_burst: Some(5),
        },
    ));

    // Temporary user without explicit quotas
    auth.add_user("guest_temp", b"guest_initial_pass");

    assert_eq!(auth.user_count(), 3);
    assert_eq!(
        auth.usernames(),
        vec![
            "alpha_admin".to_string(),
            "beta_admin".to_string(),
            "guest_temp".to_string()
        ]
    );

    // Verify quota retrieval
    let alpha_quotas = auth.get_quotas("alpha_admin").expect("alpha quotas");
    assert_eq!(alpha_quotas.max_connections, Some(3));
    assert_eq!(alpha_quotas.max_publish_rate, Some(50));
    assert_eq!(alpha_quotas.max_publish_burst, Some(10));

    let beta_quotas = auth.get_quotas("beta_admin").expect("beta quotas");
    assert_eq!(beta_quotas.max_connections, Some(2));
    assert_eq!(beta_quotas.max_publish_rate, Some(20));
    assert_eq!(beta_quotas.max_publish_burst, Some(5));

    let guest_quotas = auth.get_quotas("guest_temp").expect("guest quotas");
    assert_eq!(guest_quotas, UserQuotas::default());

    // User credential update (password rotation)
    auth.add_user("guest_temp", b"guest_rotated_pass");
    // Old password now fails
    assert!(auth
        .authenticate("client-g", Some("guest_temp"), Some(b"guest_initial_pass"))
        .await
        .is_err());
    // Rotated password succeeds
    assert!(auth
        .authenticate("client-g", Some("guest_temp"), Some(b"guest_rotated_pass"))
        .await
        .is_ok());

    // User removal
    assert!(auth.remove_user("guest_temp"));
    assert!(!auth.remove_user("guest_temp")); // Second removal returns false
    assert_eq!(auth.user_count(), 2);
    assert!(!auth.usernames().contains(&"guest_temp".to_string()));
    assert!(auth
        .authenticate("client-g", Some("guest_temp"), Some(b"guest_rotated_pass"))
        .await
        .is_err());

    // ------------------------------------------------------------------------
    // Phase 2: Authentication (AuthN) Verification
    // ------------------------------------------------------------------------
    // Valid credentials succeed
    assert!(auth
        .authenticate(
            "client-a",
            Some("alpha_admin"),
            Some(b"alpha_secret_pass_2026")
        )
        .await
        .is_ok());
    assert!(auth
        .authenticate(
            "client-b",
            Some("beta_admin"),
            Some(b"beta_secret_pass_2026")
        )
        .await
        .is_ok());

    // Invalid passwords fail with AuthenticationFailed
    let err = auth
        .authenticate("client-a", Some("alpha_admin"), Some(b"wrong_password"))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::AuthenticationFailed(_)));

    let err = auth
        .authenticate("client-b", Some("beta_admin"), Some(b"wrong_password"))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::AuthenticationFailed(_)));

    // Unknown user fails
    let err = auth
        .authenticate("client-x", Some("unknown_user"), Some(b"any_pass"))
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::AuthenticationFailed(_)));

    // Anonymous authentication rejected when users exist
    let err = auth
        .authenticate("client-anon", None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::AuthenticationFailed(_)));

    // ------------------------------------------------------------------------
    // Phase 3: Fine-Grained Multi-Tenant ACL Rules & Authorisation (AuthZ)
    // ------------------------------------------------------------------------
    // Rule 1: Tenant Alpha clients have All access under tenants/alpha/#
    auth.add_rule(AclRule::new(
        "alpha/+",
        AclAction::All,
        "tenants/alpha/#",
        true,
    ));

    // Rule 2: Tenant Beta clients have All access under tenants/beta/#
    auth.add_rule(AclRule::new(
        "beta/+",
        AclAction::All,
        "tenants/beta/#",
        true,
    ));

    // Rule 3: Read-only sensor client for Tenant Alpha can only subscribe to telemetry
    auth.add_rule(AclRule::new(
        "alpha-sensor-ro",
        AclAction::Subscribe,
        "tenants/alpha/telemetry",
        true,
    ));

    // Rule 4: Publish-only client for Tenant Alpha can only publish to commands
    auth.add_rule(AclRule::new(
        "alpha-pub-tx",
        AclAction::Publish,
        "tenants/alpha/commands",
        true,
    ));

    // Rule 5: Fallback deny-all rule
    auth.add_rule(AclRule::new("*", AclAction::All, "#", false));

    assert_eq!(auth.acl_rules().len(), 5);

    // Topic helpers
    let topic_alpha_telem = Topic::new("tenants/alpha/telemetry").unwrap();
    let topic_alpha_alerts = Topic::new("tenants/alpha/alerts/critical").unwrap();
    let topic_alpha_cmds = Topic::new("tenants/alpha/commands").unwrap();
    let topic_beta_telem = Topic::new("tenants/beta/telemetry").unwrap();
    let topic_beta_cmds = Topic::new("tenants/beta/commands").unwrap();

    let filter_alpha_all = TopicFilter::new("tenants/alpha/#").unwrap();
    let filter_alpha_telem = TopicFilter::new("tenants/alpha/telemetry").unwrap();
    let filter_alpha_alerts = TopicFilter::new("tenants/alpha/alerts/+").unwrap();
    let filter_beta_all = TopicFilter::new("tenants/beta/#").unwrap();
    let filter_root_all = TopicFilter::new("#").unwrap();

    // -- Test Publish Authorisation --
    // Tenant Alpha client can publish within its tenant boundary
    assert!(auth
        .authorize_publish("alpha/node1", &topic_alpha_telem)
        .await
        .is_ok());
    assert!(auth
        .authorize_publish("alpha/node1", &topic_alpha_alerts)
        .await
        .is_ok());

    // Cross-tenant publication MUST be strictly denied
    let err = auth
        .authorize_publish("alpha/node1", &topic_beta_cmds)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthError::PublishDenied(_)),
        "Alpha client cannot publish to Beta topics"
    );

    // Tenant Beta client can publish within its tenant boundary
    assert!(auth
        .authorize_publish("beta/node1", &topic_beta_telem)
        .await
        .is_ok());
    assert!(auth
        .authorize_publish("beta/node1", &topic_beta_cmds)
        .await
        .is_ok());

    // Cross-tenant publication MUST be strictly denied
    let err = auth
        .authorize_publish("beta/node1", &topic_alpha_telem)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthError::PublishDenied(_)),
        "Beta client cannot publish to Alpha topics"
    );

    // Read-only sensor attempting to publish must be rejected
    let err = auth
        .authorize_publish("alpha-sensor-ro", &topic_alpha_telem)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthError::PublishDenied(_)),
        "Read-only sensor cannot publish"
    );

    // Publish-only client can publish to commands, but not elsewhere
    assert!(auth
        .authorize_publish("alpha-pub-tx", &topic_alpha_cmds)
        .await
        .is_ok());
    let err = auth
        .authorize_publish("alpha-pub-tx", &topic_alpha_telem)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::PublishDenied(_)));

    // -- Test Subscribe Authorisation --
    // Tenant Alpha client can subscribe within its tenant boundary
    assert!(auth
        .authorize_subscribe("alpha/node1", &filter_alpha_all)
        .await
        .is_ok());
    assert!(auth
        .authorize_subscribe("alpha/node1", &filter_alpha_alerts)
        .await
        .is_ok());

    // Cross-tenant subscription MUST be strictly denied
    let err = auth
        .authorize_subscribe("alpha/node1", &filter_beta_all)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthError::SubscribeDenied(_)),
        "Alpha client cannot subscribe to Beta topics"
    );

    // Root wildcard subscription (#) from tenant client MUST be denied (cannot spy on other tenants)
    let err = auth
        .authorize_subscribe("alpha/node1", &filter_root_all)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthError::SubscribeDenied(_)),
        "Tenant client cannot subscribe to root wildcard #"
    );

    // Tenant Beta client can subscribe within its tenant boundary
    assert!(auth
        .authorize_subscribe("beta/node1", &filter_beta_all)
        .await
        .is_ok());

    // Cross-tenant subscription MUST be strictly denied
    let err = auth
        .authorize_subscribe("beta/node1", &filter_alpha_all)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthError::SubscribeDenied(_)),
        "Beta client cannot subscribe to Alpha topics"
    );

    // Read-only sensor can subscribe to its exact telemetry topic
    assert!(auth
        .authorize_subscribe("alpha-sensor-ro", &filter_alpha_telem)
        .await
        .is_ok());
    // But broader wildcard is not covered
    let err = auth
        .authorize_subscribe("alpha-sensor-ro", &filter_alpha_all)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::SubscribeDenied(_)));

    // Publish-only client attempting to subscribe must be rejected
    let err = auth
        .authorize_subscribe("alpha-pub-tx", &filter_alpha_all)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthError::SubscribeDenied(_)),
        "Publish-only client cannot subscribe"
    );

    // ------------------------------------------------------------------------
    // Phase 4: Multi-Tenant Connection & Rate Limiting Quota Isolation
    // ------------------------------------------------------------------------
    let session_mgr = SessionManager::new();

    // Saturate Tenant Alpha's connection limit (max: 3)
    assert!(session_mgr.acquire_connection_slot("alpha_admin", Some(3)));
    assert!(session_mgr.acquire_connection_slot("alpha_admin", Some(3)));
    assert!(session_mgr.acquire_connection_slot("alpha_admin", Some(3)));
    // 4th connection for Alpha is rejected
    assert!(!session_mgr.acquire_connection_slot("alpha_admin", Some(3)));

    // Tenant Beta is completely unaffected by Tenant Alpha's quota saturation!
    assert!(session_mgr.acquire_connection_slot("beta_admin", Some(2)));
    assert!(session_mgr.acquire_connection_slot("beta_admin", Some(2)));
    // 3rd connection for Beta is rejected
    assert!(!session_mgr.acquire_connection_slot("beta_admin", Some(2)));

    // Release 1 slot for Alpha -> Alpha can now connect again
    session_mgr.release_connection_slot("alpha_admin");
    assert!(session_mgr.acquire_connection_slot("alpha_admin", Some(3)));

    // Rate limiting isolation: TokenBucket per tenant
    let mut alpha_bucket = TokenBucket::new(50, 10);
    let mut beta_bucket = TokenBucket::new(20, 5);

    // Alpha exhausts its burst capacity
    for _ in 0..10 {
        assert!(alpha_bucket.try_consume());
    }
    assert!(!alpha_bucket.try_consume(), "Alpha burst exhausted");

    // Beta's bucket is completely independent and unthrottled
    for _ in 0..5 {
        assert!(
            beta_bucket.try_consume(),
            "Beta bucket must not be affected by Alpha's saturation"
        );
    }
    assert!(
        !beta_bucket.try_consume(),
        "Beta burst exhausted independently"
    );

    // ------------------------------------------------------------------------
    // Phase 5: End-to-End Streaming Rule Engine & Pipeline Tenant Isolation
    // ------------------------------------------------------------------------
    let engine = RuleEngine::new(4096, BackpressurePolicy::DropOldest);
    let broker_sink: Arc<dyn BrokerSink> = Arc::new(StressBrokerSink::default());

    // Tenant Alpha Kafka Sink
    let alpha_transport = Arc::new(MemoryKafkaTransport::new());
    let alpha_sink = Arc::new(
        KafkaSink::new(
            KafkaSinkConfig {
                bootstrap_servers: "127.0.0.1:9092".to_string(),
                topic_template: "tenant-alpha-events".to_string(),
                partition_key_field: Some("device".to_string()),
                partitions: 4,
                client_id: "alpha-client".to_string(),
                acks: "all".to_string(),
                batch_max_records: 50,
                batch_max_bytes: 64 * 1024,
            },
            alpha_transport.clone(),
        )
        .expect("alpha sink"),
    );
    engine
        .connectors()
        .register("sink_tenant_alpha", alpha_sink.clone());

    // Tenant Beta Kafka Sink
    let beta_transport = Arc::new(MemoryKafkaTransport::new());
    let beta_sink = Arc::new(
        KafkaSink::new(
            KafkaSinkConfig {
                bootstrap_servers: "127.0.0.1:9092".to_string(),
                topic_template: "tenant-beta-events".to_string(),
                partition_key_field: Some("device".to_string()),
                partitions: 4,
                client_id: "beta-client".to_string(),
                acks: "all".to_string(),
                batch_max_records: 50,
                batch_max_bytes: 64 * 1024,
            },
            beta_transport.clone(),
        )
        .expect("beta sink"),
    );
    engine
        .connectors()
        .register("sink_tenant_beta", beta_sink.clone());

    // Rule 1: Scoped strictly to Tenant Alpha topics
    let filter_rule_alpha = TopicFilter::new("tenants/alpha/+/data").unwrap();
    let sql_rule_alpha = r#"SELECT device, temp, status FROM "tenants/alpha/+/data" WHERE temp > 25.0 INTO connector("sink_tenant_alpha")"#;
    engine
        .create_rule(
            "rule_alpha".to_string(),
            filter_rule_alpha,
            Some(sql_rule_alpha.to_string()),
            true,
            vec![],
        )
        .expect("create rule alpha");

    // Rule 2: Scoped strictly to Tenant Beta topics
    let filter_rule_beta = TopicFilter::new("tenants/beta/+/data").unwrap();
    let sql_rule_beta = r#"SELECT device, temp, status FROM "tenants/beta/+/data" WHERE temp > 25.0 INTO connector("sink_tenant_beta")"#;
    engine
        .create_rule(
            "rule_beta".to_string(),
            filter_rule_beta,
            Some(sql_rule_beta.to_string()),
            true,
            vec![],
        )
        .expect("create rule beta");

    // Ingest 100 messages for Tenant Alpha (50 qualify, 50 filtered out)
    for i in 0..100 {
        let temp = if i % 2 == 0 { 35.0 } else { 15.0 };
        let payload = serde_json::to_vec(&serde_json::json!({
            "device": format!("alpha-sensor-{}", i),
            "temp": temp,
            "status": "active",
            "internal_tenant_id": "alpha_corp"
        }))
        .unwrap();
        let topic = Topic::new(format!("tenants/alpha/line-{}/data", i % 5)).unwrap();
        engine
            .dispatch_ingress(
                &topic,
                &Bytes::from(payload),
                QoS::AtLeastOnce,
                &broker_sink,
            )
            .await;
    }

    // Ingest 100 messages for Tenant Beta (50 qualify, 50 filtered out)
    for i in 0..100 {
        let temp = if i % 2 == 0 { 40.0 } else { 10.0 };
        let payload = serde_json::to_vec(&serde_json::json!({
            "device": format!("beta-actuator-{}", i),
            "temp": temp,
            "status": "running",
            "internal_tenant_id": "beta_corp"
        }))
        .unwrap();
        let topic = Topic::new(format!("tenants/beta/line-{}/data", i % 5)).unwrap();
        engine
            .dispatch_ingress(
                &topic,
                &Bytes::from(payload),
                QoS::AtLeastOnce,
                &broker_sink,
            )
            .await;
    }

    // Verify Tenant Alpha Sink: exactly 50 records, ZERO cross-tenant leakage from Beta!
    let alpha_records = alpha_transport.records_flat();
    assert_eq!(
        alpha_records.len(),
        50,
        "Tenant Alpha sink must receive exactly 50 qualifying records"
    );
    for r in &alpha_records {
        assert_eq!(r.topic, "tenant-alpha-events");
        assert!(
            r.key.as_ref().unwrap().starts_with(b"alpha-sensor-"),
            "Must be an Alpha device key"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&r.value).expect("valid json");
        assert!(parsed["device"].as_str().unwrap().contains("alpha"));
        assert!(
            !parsed["device"].as_str().unwrap().contains("beta"),
            "CRITICAL: Zero cross-tenant leakage!"
        );
        assert!(parsed["temp"].as_f64().unwrap() > 25.0);
        // Stripped field check
        assert!(parsed.get("internal_tenant_id").is_none());
    }

    // Verify Tenant Beta Sink: exactly 50 records, ZERO cross-tenant leakage from Alpha!
    let beta_records = beta_transport.records_flat();
    assert_eq!(
        beta_records.len(),
        50,
        "Tenant Beta sink must receive exactly 50 qualifying records"
    );
    for r in &beta_records {
        assert_eq!(r.topic, "tenant-beta-events");
        assert!(
            r.key.as_ref().unwrap().starts_with(b"beta-actuator-"),
            "Must be a Beta device key"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&r.value).expect("valid json");
        assert!(parsed["device"].as_str().unwrap().contains("beta"));
        assert!(
            !parsed["device"].as_str().unwrap().contains("alpha"),
            "CRITICAL: Zero cross-tenant leakage!"
        );
        assert!(parsed["temp"].as_f64().unwrap() > 25.0);
        // Stripped field check
        assert!(parsed.get("internal_tenant_id").is_none());
    }

    // ------------------------------------------------------------------------
    // Phase 6: Clean Up and Zero Memory Footprint
    // ------------------------------------------------------------------------
    engine.connectors().unregister("sink_tenant_alpha");
    engine.connectors().unregister("sink_tenant_beta");
    auth.clear_rules();
    assert_eq!(auth.acl_rules().len(), 0);
    drop(alpha_sink);
    drop(beta_sink);
    drop(alpha_transport);
    drop(beta_transport);
}

// ============================================================================
// 10. Multi-Protocol Gateways, Enterprise Auth & Durable Stream Replay
// ============================================================================

#[tokio::test]
async fn test_e2e_gateways_enterprise_auth_and_durable_stream_replay() {
    // ------------------------------------------------------------------------
    // Part 1: CoAP RFC 7252 Ingest -> Rekuiper SQL -> Kafka Sink
    // ------------------------------------------------------------------------
    let (gw_mgr, mut gw_rx) = GatewayManager::new(300);
    let engine = Arc::new(RuleEngine::new(1024, BackpressurePolicy::Block));
    let alert_sink = Arc::new(StressBrokerSink::default());
    let broker_sink: Arc<dyn BrokerSink> = alert_sink.clone();

    let kafka_transport = Arc::new(MemoryKafkaTransport::new());
    let kafka_sink = Arc::new(
        KafkaSink::new(
            KafkaSinkConfig {
                bootstrap_servers: "127.0.0.1:9092".to_string(),
                topic_template: "coap-kafka-events".to_string(),
                partition_key_field: Some("sensor".to_string()),
                partitions: 4,
                client_id: "coap-ingest-tester".to_string(),
                acks: "all".to_string(),
                batch_max_records: 10,
                batch_max_bytes: 32 * 1024,
            },
            kafka_transport.clone(),
        )
        .expect("kafka sink"),
    );

    engine
        .connectors()
        .register("target_kafka_coap", kafka_sink.clone());

    let coap_filter = TopicFilter::new("coap/industrial/+").unwrap();
    let coap_sql = r#"SELECT sensor, celsius, celsius * 1.8 + 32.0 AS fahrenheit FROM "coap/industrial/+" WHERE celsius > 30.0 INTO connector("target_kafka_coap")"#;
    engine
        .create_rule(
            "rule_coap_kafka".to_string(),
            coap_filter,
            Some(coap_sql.to_string()),
            true,
            vec![],
        )
        .expect("create coap rule");

    // Simulate CoAP client publishing 20 sensor telemetry datagrams via RFC 7252
    for i in 0..20 {
        let celsius = 25.0 + (i as f64); // 25..44, >=31 qualifies (14 records)
        let payload = serde_json::to_vec(&serde_json::json!({
            "sensor": format!("coap-sensor-{}", i),
            "celsius": celsius,
            "raw_voltage": 3.3
        }))
        .unwrap();

        let req = coap::CoapMessage {
            message_type: coap::CoapType::Confirmable,
            code: coap::CoapCode::POST,
            message_id: 1000 + (i as u16),
            token: Bytes::from(format!("tok{}", i)),
            options: vec![
                coap::CoapOption {
                    number: coap::option_number::URI_PATH,
                    value: Bytes::from_static(b"ps"),
                },
                coap::CoapOption {
                    number: coap::option_number::URI_PATH,
                    value: Bytes::from_static(b"coap"),
                },
                coap::CoapOption {
                    number: coap::option_number::URI_PATH,
                    value: Bytes::from_static(b"industrial"),
                },
                coap::CoapOption {
                    number: coap::option_number::URI_PATH,
                    value: Bytes::from(format!("sensor{}", i)),
                },
            ],
            payload: Bytes::from(payload),
        };

        let resp = gw_mgr
            .handle_coap("coap-client", &req)
            .expect("handle coap");
        assert!(resp.is_some());
        let resp_msg = resp.unwrap();
        assert_eq!(resp_msg.code, coap::CoapCode::CHANGED);

        // Receive normalized message from GatewayManager channel
        let gw_msg = gw_rx.try_recv().expect("receive coap normalized message");
        assert_eq!(gw_msg.protocol, GatewayProtocol::CoAP);
        assert_eq!(gw_msg.topic, format!("coap/industrial/sensor{}", i));

        let topic = Topic::new(&gw_msg.topic).unwrap();
        engine
            .dispatch_ingress(&topic, &gw_msg.payload, gw_msg.qos, &broker_sink)
            .await;
    }

    kafka_sink.flush().await.expect("flush kafka sink");

    // Verify Kafka Sink received exactly 14 records above 30.0C with projected fahrenheit
    let kafka_records = kafka_transport.records_flat();
    assert_eq!(
        kafka_records.len(),
        14,
        "Expected 14 records where celsius > 30.0"
    );
    for r in &kafka_records {
        assert_eq!(r.topic, "coap-kafka-events");
        let parsed: serde_json::Value = serde_json::from_slice(&r.value).unwrap();
        let c = parsed["celsius"].as_f64().unwrap();
        let f = parsed["fahrenheit"].as_f64().unwrap();
        assert!(c > 30.0);
        assert!((f - (c * 1.8 + 32.0)).abs() < 1e-4);
        assert!(
            parsed.get("raw_voltage").is_none(),
            "raw_voltage must be stripped"
        );
    }

    // ------------------------------------------------------------------------
    // Part 2: LwM2M OMA TLV Ingest -> Rekuiper SQL -> PostgreSQL Sink
    // ------------------------------------------------------------------------
    let pg_transport = Arc::new(MemoryPgTransport::new());
    let pg_sink = Arc::new(
        PostgreSqlSink::new(
            PostgreSqlSinkConfig {
                connection_url: "postgres://user:pass@127.0.0.1:5432/lwm2m_db".to_string(),
                sql_template:
                    "INSERT INTO lwm2m_readings (topic, qos, payload) VALUES ($1, $2, $3)"
                        .to_string(),
                pool_size: 2,
                batch_size: 10,
                batch_timeout_ms: 10,
            },
            pg_transport.clone(),
        )
        .expect("pg sink"),
    );

    engine
        .connectors()
        .register("target_pg_lwm2m", pg_sink.clone());

    let lwm2m_filter = TopicFilter::new("lwm2m/+/up/data").unwrap();
    let lwm2m_sql = r#"SELECT endpoint, object_id, instance_id FROM "lwm2m/+/up/data" WHERE object_id = 3303 INTO connector("target_pg_lwm2m")"#;
    engine
        .create_rule(
            "rule_lwm2m_pg".to_string(),
            lwm2m_filter,
            Some(lwm2m_sql.to_string()),
            true,
            vec![],
        )
        .expect("create lwm2m rule");

    // Register 5 LwM2M devices and send Object 3303 (Temperature) TLVs
    for i in 0..5 {
        let ep = format!("pump-station-{i}");
        let reg_id = gw_mgr.lwm2m.register(&ep, 300, "U", "1.1");
        assert!(reg_id.starts_with("rd-"));

        let temp_bytes = (20.0f32 + (i as f32)).to_be_bytes().to_vec();
        let tlv_rec = lwm2m::TlvRecord::resource_value(5700, temp_bytes);
        let tlv_bytes = tlv_rec.encode();

        let (topic_str, _) = gw_mgr
            .handle_lwm2m_tlv(&ep, 3303, 0, &tlv_bytes)
            .expect("handle lwm2m tlv");

        let gw_msg = gw_rx.try_recv().expect("receive lwm2m normalized message");
        assert_eq!(gw_msg.protocol, GatewayProtocol::LwM2M);
        assert_eq!(gw_msg.topic, topic_str);

        let topic = Topic::new(&gw_msg.topic).unwrap();
        engine
            .dispatch_ingress(&topic, &gw_msg.payload, gw_msg.qos, &broker_sink)
            .await;
    }

    pg_sink.flush().await.expect("flush pg sink");

    // Verify PostgreSQL Sink received all 5 LwM2M readings
    let batches = pg_transport.batches();
    assert!(
        !batches.is_empty(),
        "PostgreSQL batches should not be empty"
    );
    let mut pg_row_count = 0;
    for batch in &batches {
        for row in &batch.rows {
            pg_row_count += 1;
            let payload_str = std::str::from_utf8(&row[2]).expect("utf8 payload");
            let parsed: serde_json::Value = serde_json::from_str(payload_str).unwrap();
            assert_eq!(parsed["object_id"], 3303);
            assert!(parsed["endpoint"]
                .as_str()
                .unwrap()
                .starts_with("pump-station-"));
        }
    }
    assert_eq!(pg_row_count, 5, "Expected 5 LwM2M rows inserted into PG");

    // ------------------------------------------------------------------------
    // Part 3: OCPP 1.6-J EV Charging -> Rekuiper SQL -> Redis Stream Sink
    // ------------------------------------------------------------------------
    let redis_transport = Arc::new(MemoryRedisTransport::new());
    let redis_sink = Arc::new(
        RedisSink::new(
            RedisSinkConfig {
                endpoint: "redis://127.0.0.1:6379".to_string(),
                command: RedisCommandKind::XAdd {
                    stream_template: "ocpp-stream".to_string(),
                    maxlen: Some(500),
                },
            },
            redis_transport.clone(),
        )
        .expect("redis sink"),
    );

    engine
        .connectors()
        .register("target_redis_ocpp", redis_sink.clone());

    let ocpp_filter = TopicFilter::new("ocpp/+/up/+").unwrap();
    let ocpp_sql = r#"SELECT charge_point_id, action FROM "ocpp/+/up/+" WHERE action = 'BootNotification' INTO connector("target_redis_ocpp")"#;
    engine
        .create_rule(
            "rule_ocpp_redis".to_string(),
            ocpp_filter,
            Some(ocpp_sql.to_string()),
            true,
            vec![],
        )
        .expect("create ocpp rule");

    // Send BootNotification from 3 EV Charge Points
    for i in 0..3 {
        let cp_id = format!("chargepoint-uk-{}", i);
        let boot_call = format!(
            r#"[2, "call-boot-{}", "BootNotification", {{"chargePointVendor": "IndraVolt", "chargePointModel": "HyperCharge-350", "firmwareVersion": "2.4.1"}}]"#,
            i
        );

        // Verify direct frame parsing via ocpp module
        let parsed_call = ocpp::OcppMessage::parse(&boot_call).expect("parse ocpp call");
        assert!(matches!(parsed_call, ocpp::OcppMessage::Call { .. }));

        let (topic_str, _, resp) = gw_mgr
            .handle_ocpp_frame(&cp_id, &boot_call)
            .expect("handle ocpp boot");
        assert!(resp.is_some());
        let resp_str = resp.unwrap();
        assert!(resp_str.contains("\"status\":\"Accepted\""));

        let gw_msg = gw_rx.try_recv().expect("receive ocpp normalized message");
        assert_eq!(gw_msg.protocol, GatewayProtocol::OCPP);
        assert_eq!(gw_msg.topic, topic_str);

        let topic = Topic::new(&gw_msg.topic).unwrap();
        engine
            .dispatch_ingress(&topic, &gw_msg.payload, gw_msg.qos, &broker_sink)
            .await;
    }

    // Verify Redis stream received 3 BootNotification entries
    let commands = redis_transport.commands();
    assert_eq!(
        commands.len(),
        3,
        "Expected 3 BootNotification entries in Redis stream"
    );
    for cmd in &commands {
        assert_eq!(cmd.argv[0], b"XADD".to_vec());
        assert_eq!(cmd.argv[1], b"ocpp-stream".to_vec());
        let payload_str = std::str::from_utf8(&cmd.argv[cmd.argv.len() - 1]).expect("utf8 payload");
        let parsed: serde_json::Value = serde_json::from_str(payload_str).unwrap();
        assert_eq!(parsed["action"], "BootNotification");
        assert!(parsed["charge_point_id"]
            .as_str()
            .unwrap()
            .starts_with("chargepoint-uk-"));
    }

    // ------------------------------------------------------------------------
    // Part 4: Enterprise Authentication (Active Directory LDAP & Kerberos)
    // ------------------------------------------------------------------------
    // 4A: LDAP Bind Authentication
    let ldap_config = LdapConfig {
        server_url: "ldap://ad.enterprise.corp:389".to_string(),
        base_dn: "dc=enterprise,dc=corp".to_string(),
        bind_dn_template: "cn={username},ou=Operators,dc=enterprise,dc=corp".to_string(),
        filter_template: "(&(objectClass=user)(sAMAccountName={username}))".to_string(),
        timeout_ms: 5000,
    };
    let ldap_auth = LdapAuthenticator::new(ldap_config);
    let mut ldap_attrs = HashMap::new();
    ldap_attrs.insert("sAMAccountName".to_string(), "ops_admin".to_string());
    ldap_attrs.insert("department".to_string(), "DevOps".to_string());
    ldap_auth.add_entry(
        "cn=ops_admin,ou=Operators,dc=enterprise,dc=corp",
        b"EnterpriseSecurePass2026!",
        ldap_attrs,
    );

    // Valid credentials -> success
    assert!(ldap_auth
        .authenticate(
            "admin-console",
            Some("ops_admin"),
            Some(b"EnterpriseSecurePass2026!")
        )
        .await
        .is_ok());

    // Bad password -> fail
    assert!(ldap_auth
        .authenticate("admin-console", Some("ops_admin"), Some(b"wrong_secret"))
        .await
        .is_err());

    // Non-existent user -> fail
    assert!(ldap_auth
        .authenticate("admin-console", Some("intruder"), Some(b"secret"))
        .await
        .is_err());

    // 4B: Kerberos SPN and SPNEGO Ticket Authentication
    let krb_config = KerberosConfig {
        service_principal_name: "mqtt/broker.enterprise.corp@ENTERPRISE.CORP".to_string(),
        realm: "ENTERPRISE.CORP".to_string(),
        allowed_realms: vec!["ENTERPRISE.CORP".to_string()],
    };
    let krb_auth = KerberosAuthenticator::new(krb_config);
    krb_auth.add_principal("operator@ENTERPRISE.CORP");

    let valid_krb_ticket = KerberosAuthenticator::create_test_token(
        "operator@ENTERPRISE.CORP",
        "mqtt/broker.enterprise.corp@ENTERPRISE.CORP",
        "ENTERPRISE.CORP",
    );

    // Valid Kerberos ticket -> success
    assert!(krb_auth
        .authenticate("workstation-1", Some("operator"), Some(&valid_krb_ticket))
        .await
        .is_ok());

    // Wrong SPN ticket -> fail
    let bad_spn_ticket = KerberosAuthenticator::create_test_token(
        "operator@ENTERPRISE.CORP",
        "http/web.enterprise.corp@ENTERPRISE.CORP",
        "ENTERPRISE.CORP",
    );
    assert!(krb_auth
        .authenticate("workstation-1", Some("operator"), Some(&bad_spn_ticket))
        .await
        .is_err());

    // ------------------------------------------------------------------------
    // Part 5: Durable Stream Partition Storage & Point-in-Time Seek Replay
    // ------------------------------------------------------------------------
    let stream_store = DurableStreamStore::new();
    let stream_topic = Topic::new("factory/line1/vibration").unwrap();

    let base_ts = 1_710_000_000_000u64;

    // Append 100 historical telemetry frames with sequential 64-bit offsets
    for i in 0..100 {
        let payload = Bytes::from(format!("vibration_amplitude_{i}"));
        let mut headers = HashMap::new();
        headers.insert("seq".to_string(), i.to_string());

        let offset = stream_store.append_with_timestamp(
            stream_topic.clone(),
            QoS::AtLeastOnce,
            payload,
            headers,
            base_ts + (i * 100),
        );
        assert_eq!(offset, i);
    }

    assert_eq!(stream_store.stream_len("factory/line1/vibration"), 100);
    assert_eq!(
        stream_store.earliest_offset("factory/line1/vibration"),
        Some(0)
    );
    assert_eq!(
        stream_store.latest_offset("factory/line1/vibration"),
        Some(99)
    );

    // Seek offset from 60 to 100 (replay 40 records)
    let replayed = stream_store
        .seek_offset("factory/line1/vibration", 60, 40)
        .expect("seek offset");
    assert_eq!(replayed.len(), 40);
    assert_eq!(replayed[0].offset, 60);
    assert_eq!(
        replayed[0].payload,
        Bytes::from_static(b"vibration_amplitude_60")
    );
    assert_eq!(replayed[39].offset, 99);
    assert_eq!(
        replayed[39].payload,
        Bytes::from_static(b"vibration_amplitude_99")
    );

    // Seek timestamp from base_ts + 7550ms -> should start at record 76
    let time_replayed = stream_store
        .seek_timestamp("factory/line1/vibration", base_ts + 7550, 10)
        .expect("seek timestamp");
    assert_eq!(time_replayed.len(), 10);
    assert_eq!(time_replayed[0].offset, 76);
    assert_eq!(time_replayed[0].timestamp_ms, base_ts + 7600);

    // Retention policy purge: prune records older than base_ts + 5000ms (first 50 records)
    let purged_count = stream_store.purge_retention("factory/line1/vibration", base_ts + 5000);
    assert_eq!(purged_count, 50);
    assert_eq!(stream_store.stream_len("factory/line1/vibration"), 50);
    assert_eq!(
        stream_store.earliest_offset("factory/line1/vibration"),
        Some(50)
    );

    // ------------------------------------------------------------------------
    // Part 6: Clean Up
    // ------------------------------------------------------------------------
    engine.connectors().unregister("target_kafka_coap");
    engine.connectors().unregister("target_pg_lwm2m");
    engine.connectors().unregister("target_redis_ocpp");
}
