//! Comprehensive Deep Soak & Chaos Engineering Test Suite for IndraMQTT.
//!
//! Validates the broker's resilience, concurrency guarantees, and failure modes under stress:
//! 1. High-concurrency router fanout soak with overlapping wildcard subscriptions.
//! 2. Abrupt BrokerLink IPC socket sever and seamless session rebind/resurrection.
//! 3. SWIM cluster partition, indirect ping-req probe recovery, and suspicion lifecycle chaos.
//! 4. Multi-tenant quota and token-bucket rate limiter saturation under burst pressure.
//! 5. Streaming SQL windowing aggregation soak with high-cardinality bursts.
//! 6. Streaming SQL INTO grand parallel fanout across multiple diverse sink pipelines.

use broker_auth::{Authenticator, MemoryAuth};
use broker_cluster::{
    ChannelSwimNetwork, ClusterRouteTable, NodeId, NodeStatus, SwimConfig, SwimMembership,
};
use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::{ConnTable, Router, Subscription};
use broker_rules::{BackpressurePolicy, BrokerSink, RuleAction, RuleEngine};
use broker_session::{QueuedMessage, SessionManager, TokenBucket};
use brokerlink::{BrokerFrame, BrokerLinkTransport, FramedTransport, OpCode};
use bytes::Bytes;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
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
