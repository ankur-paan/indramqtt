//! Sparkplug B qualification path for the pre-split crate name.
//!
//! The real sink lives in `broker-connectors-enterprise` (`sparkplug_b`):
//! `SparkplugBSink` on the maintained `rumqttc` driver
//! (`RumqttcSparkplugTransport` with Tahu Protobuf framed through the
//! maintained `prost` driver). This module exists only so the task
//! spec's `QUAL-CMD`
//! (`-p broker-connectors --lib sparkplug_b::tests::test_qualify_birth_data_write_path`)
//! finds a test: the qualification below drives the enterprise sink
//! through the broker's rule path and asserts the same counts as the
//! enterprise qualification. Runtime code stays in the enterprise
//! crate; nothing here changes another sink, the `Sink` trait or the
//! management API shape.

#[cfg(test)]
mod tests {
    use crate::parse_bridge_address;
    use broker_connectors_enterprise::{decode_payload, decode_payload_prost, Sink as _};
    use broker_protocol::{QoS, Topic, TopicFilter};
    use broker_rules::{BackpressurePolicy, BrokerSink, RuleAction, RuleEngine, RuleEngineError};
    use bytes::Bytes;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    /// Collected Sparkplug frames seen by the qualification subscriber:
    /// topic, raw Protobuf payload and QoS. Factored out so the
    /// `Arc<Mutex<..>>` holder stays below the complexity lint.
    type CollectedFrames = Vec<(String, Vec<u8>, rumqttc::QoS)>;

    /// Discards unmatched egress for the rule-path qualification (the
    /// connector under test receives everything through its rule).
    struct NullBrokerSink;

    #[async_trait::async_trait]
    impl BrokerSink for NullBrokerSink {
        async fn publish(
            &self,
            _topic: Topic,
            _payload: Bytes,
            _qos: QoS,
            _retain: bool,
        ) -> std::result::Result<(), RuleEngineError> {
            Ok(())
        }
    }

    /// Qualification against a real MQTT server carrying Sparkplug B
    /// Protobuf through the maintained `rumqttc` driver write path
    /// (enterprise sink).
    ///
    /// Run with e.g.:
    /// `SPARKPLUG_MQTT_URL=mqtt://127.0.0.1:1883 SPARKPLUG_GROUP_ID=qual \
    ///  SPARKPLUG_NODE_ID=qual-b343 \
    ///  cargo test -p broker-connectors --lib sparkplug_b::tests::test_qualify_birth_data_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Publishes an NBIRTH/DBIRTH/DATA sequence plus a rebirth through
    /// the broker ([`RuleEngine::dispatch_ingress`] into a
    /// `SparkplugBSink` on `RumqttcSparkplugTransport`, never
    /// `sink.send` directly), and asserts the host subscriber decodes
    /// every metric with stable aliases and the rebirth arrives.
    /// Panics when its environment is missing (fail closed, never
    /// skips).
    #[tokio::test]
    #[ignore = "needs a real Sparkplug B MQTT server (see SPARKPLUG_* env)"]
    async fn test_qualify_birth_data_write_path() {
        use broker_connectors_enterprise::{
            RumqttcSparkplugTransport, SparkplugBSink, SparkplugSinkConfig, SparkplugStateMachine,
            SpbAnomaly,
        };

        const DATA_ROWS: usize = 5;

        let url = qual_env("SPARKPLUG_MQTT_URL").unwrap_or_else(|| {
            panic!(
                "SPARKPLUG_MQTT_URL must point at a real MQTT server carrying Sparkplug B for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. SPARKPLUG_MQTT_URL=mqtt://127.0.0.1:1883)"
            )
        });
        let group = qual_env("SPARKPLUG_GROUP_ID").unwrap_or_else(|| {
            panic!("SPARKPLUG_GROUP_ID must be set for qualification; failing closed")
        });
        let node = qual_env("SPARKPLUG_NODE_ID").unwrap_or_else(|| {
            panic!("SPARKPLUG_NODE_ID must be set for qualification; failing closed")
        });
        // Server version for the report comes from the qualification
        // image the gates start (eclipse-mosquitto:2.0.18); the driver
        // exposes no broker-version RPC here, so the endpoint line
        // below is the measured endpoint, never a substitute version
        // string.
        eprintln!(
            "qual server: image eclipse-mosquitto:2.0.18 url={url} group={group} node={node}"
        );
        let endpoint = parse_bridge_address(&url).expect("qual url parses");
        assert!(
            !endpoint.tls,
            "qual uses plaintext mqtt:// (mqtts fails closed in this build)"
        );

        let run_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // Unique device per run isolates concurrent gates sharing one
        // group/node; the node birth itself stays on the configured
        // node id.
        let device = format!("plc-{run_nanos}");
        let nbirth_topic = format!("spBv1.0/{group}/NBIRTH/{node}");
        let dbirth_topic = format!("spBv1.0/{group}/DBIRTH/{node}/{device}");
        let ddata_topic = format!("spBv1.0/{group}/DDATA/{node}/{device}");
        let watched: HashSet<String> = [
            nbirth_topic.clone(),
            dbirth_topic.clone(),
            ddata_topic.clone(),
        ]
        .into_iter()
        .collect();
        let subscribe_filter = format!("spBv1.0/{group}/#");
        let sub_id = format!("spb-qual-sub-{run_nanos}");
        let bridge_id = format!("spb-qual-{run_nanos}");

        // Subscriber first: with clean sessions a publish before the
        // SUBACK is lost, so the subscription must be active before
        // the sink sends anything.
        let mut sub_options =
            rumqttc::MqttOptions::new(sub_id.clone(), endpoint.host.clone(), endpoint.port);
        sub_options.set_keep_alive(Duration::from_secs(10));
        sub_options.set_clean_session(true);
        let (sub_client, mut sub_eventloop) = rumqttc::AsyncClient::new(sub_options, 100);
        sub_client
            .subscribe(subscribe_filter.clone(), rumqttc::QoS::AtLeastOnce)
            .await
            .expect("qual subscribe request");
        // 30s SUBACK wait: the protocol requirement is a bounded
        // handshake, not a specific value; 30s tolerates a slow
        // container start while failing fast on a dead server.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match sub_eventloop.poll().await {
                    Ok(rumqttc::Event::Incoming(rumqttc::Packet::SubAck(_))) => break,
                    Ok(_) => continue,
                    Err(e) => panic!("qual subscribe failed: {e:?}"),
                }
            }
        })
        .await
        .expect("qual suback timeout");
        eprintln!("qual subscribed: filter={subscribe_filter}");

        let expected_frames = DATA_ROWS + 3;
        let seen: Arc<parking_lot::Mutex<CollectedFrames>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        let collector_seen = seen.clone();
        let collector_watched = watched.clone();
        let collector = tokio::spawn(async move {
            loop {
                match sub_eventloop.poll().await {
                    Ok(rumqttc::Event::Incoming(rumqttc::Packet::Publish(publish))) => {
                        if !collector_watched.contains(&publish.topic) {
                            continue;
                        }
                        let mut guard = collector_seen.lock();
                        guard.push((publish.topic.clone(), publish.payload.to_vec(), publish.qos));
                        if guard.len() >= expected_frames {
                            break;
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        eprintln!("qual subscriber eventloop note: {e:?}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        let config = SparkplugSinkConfig {
            topic_prefix: None,
            tier: "enterprise".to_string(),
            batch_size: Some(100),
            linger_ms: Some(10),
            timeout_ms: None,
            mqtt_url: Some(url.clone()),
            client_id: Some(bridge_id.clone()),
            max_aliases: Some(10_000),
        };
        config.validate().expect("qual config validates");
        let transport = Arc::new(
            RumqttcSparkplugTransport::new(&url, Some(&bridge_id)).expect("qual transport"),
        );
        let sink = Arc::new(SparkplugBSink::new(config, transport).expect("qual sink"));
        assert_eq!(sink.kind(), "sparkplug_b");
        // The broker's path: a rule registered on the connector
        // manager, messages published through the rule engine, so the
        // qualification sends through it and never `sink.send`
        // directly.
        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        engine.connectors().register("qual-spb", sink.clone());
        engine
            .connectors()
            .register("sparkplug_b:qual-spb", sink.clone());
        engine
            .create_rule(
                "qual-spb-rule".to_string(),
                TopicFilter::new(&subscribe_filter).unwrap(),
                None,
                true,
                vec![RuleAction::ForwardConnector {
                    connector_id: "qual-spb".to_string(),
                }],
            )
            .expect("rule creates");
        let egress: Arc<dyn BrokerSink> = Arc::new(NullBrokerSink);

        let birth_doc = serde_json::json!({
            "timestamp": 1_726_145_890_000u64,
            "seq": 0u64,
            "metrics": {"Temperature": 82.5, "Running": true},
        });
        let birth_body = Bytes::from(serde_json::to_vec(&birth_doc).unwrap());
        engine
            .dispatch_ingress(
                &Topic::new(&nbirth_topic).unwrap(),
                &birth_body,
                QoS::AtLeastOnce,
                &egress,
            )
            .await;
        let dbirth_doc = serde_json::json!({
            "timestamp": 1_726_145_890_000u64,
            "seq": 0u64,
            "metrics": {"Pressure": 101.3},
        });
        engine
            .dispatch_ingress(
                &Topic::new(&dbirth_topic).unwrap(),
                &Bytes::from(serde_json::to_vec(&dbirth_doc).unwrap()),
                QoS::AtLeastOnce,
                &egress,
            )
            .await;
        for seq in 1..=DATA_ROWS as u64 {
            let data_doc = serde_json::json!({
                "timestamp": 1_726_145_890_000u64 + seq,
                "seq": seq,
                "metrics": {"Pressure": 101.3 + seq as f64},
            });
            engine
                .dispatch_ingress(
                    &Topic::new(&ddata_topic).unwrap(),
                    &Bytes::from(serde_json::to_vec(&data_doc).unwrap()),
                    QoS::AtLeastOnce,
                    &egress,
                )
                .await;
        }
        // Rebirth on state change: a fresh NBIRTH after data, as the
        // edge would emit when the host STATE flips.
        engine
            .dispatch_ingress(
                &Topic::new(&nbirth_topic).unwrap(),
                &birth_body,
                QoS::AtLeastOnce,
                &egress,
            )
            .await;
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), expected_frames as u64);
        eprintln!(
            "qual rows sent: records={} batches={}",
            sink.sent_records(),
            sink.sent_batches()
        );

        // 180s receive window: generous against the 1800s gate timeout
        // so a slow server still converges, while a stuck sink fails
        // instead of hanging the gate.
        tokio::time::timeout(Duration::from_secs(180), collector)
            .await
            .expect("qual receive timeout")
            .expect("qual collector task");
        let frames = seen.lock().clone();
        // At-least-once permits duplicates, never loss: every expected
        // topic and data sequence must be present, not an exact count.
        let mut nbirth_count = 0usize;
        let mut dbirth_count = 0usize;
        let mut data_seqs: HashSet<u64> = HashSet::new();
        let mut machine = SparkplugStateMachine::new();
        for (topic, payload, qos) in &frames {
            assert_eq!(
                *qos,
                rumqttc::QoS::AtLeastOnce,
                "qual QoS must be preserved as AtLeastOnce"
            );
            // Both codecs read the wire: the sink encodes through
            // `prost`, the host decodes here.
            let via_classic = decode_payload(payload).expect("qual payload decodes");
            let via_prost = decode_payload_prost(payload).expect("qual prost decodes");
            assert_eq!(via_classic, via_prost);
            assert!(!via_classic.metrics.is_empty(), "qual frame has metrics");
            for metric in &via_classic.metrics {
                assert!(metric.alias.is_some(), "qual metric needs an alias");
            }
            if *topic == nbirth_topic {
                nbirth_count += 1;
                let names: HashSet<&str> = via_classic
                    .metrics
                    .iter()
                    .filter_map(|metric| metric.name.as_deref())
                    .collect();
                assert!(names.contains("Temperature"));
                assert!(names.contains("Running"));
            } else if *topic == dbirth_topic {
                dbirth_count += 1;
            } else if *topic == ddata_topic {
                if let Some(seq) = via_classic.seq {
                    data_seqs.insert(seq);
                }
            }
            let outcome = machine
                .ingest(topic, payload)
                .unwrap_or_else(|e| panic!("qual host ingest failed for {topic}: {e:?}"));
            assert!(
                !outcome.anomalies.iter().any(|anomaly| matches!(
                    anomaly,
                    SpbAnomaly::UnknownAlias { .. } | SpbAnomaly::OfflineData
                )),
                "qual host anomalies on {topic}: {outcome:?}"
            );
        }
        assert!(
            nbirth_count >= 2,
            "qual rebirth must arrive (saw {nbirth_count} NBIRTH)"
        );
        assert!(dbirth_count >= 1, "qual DBIRTH must arrive");
        for seq in 1..=DATA_ROWS as u64 {
            assert!(data_seqs.contains(&seq), "qual missing DATA seq {seq}");
        }
        assert!(
            machine
                .node_state(&group, &node)
                .is_some_and(|state| state.online),
            "qual node must read online"
        );
        assert!(
            machine
                .device_state(&group, &node, &device)
                .is_some_and(|state| state.online),
            "qual device must read online"
        );
        let aliases = &machine.node_state(&group, &node).unwrap().aliases;
        assert!(
            aliases.values().any(|name| name == "Temperature"),
            "qual host must cache birth aliases"
        );
        eprintln!(
            "qual rows asserted: nbirth={nbirth_count} dbirth={dbirth_count} data_seqs={} rebirth=yes",
            data_seqs.len()
        );
        let _ = sub_client.disconnect().await;

        eprintln!("qual cleanup: disconnected subscriber {sub_id}, bridge {bridge_id}; no retained state (retain=false)");
    }
}
