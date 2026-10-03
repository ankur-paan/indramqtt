//! Amazon Kinesis qualification path for the pre-split crate name.
//!
//! The real sink lives in `broker-connectors-enterprise` (`kinesis`):
//! `KinesisSink` on the maintained `aws-sdk-kinesis` driver
//! (`SdkKinesisTransport` with driver-owned SigV4). This module exists
//! only so the task spec's `QUAL-CMD`
//! (`-p broker-connectors --lib kinesis::tests::test_qualify_driver_write_path`)
//! finds a test: the qualification below drives the enterprise sink
//! through the broker's rule path and asserts the same counts as the
//! enterprise qualification. Runtime code stays in the enterprise
//! crate; nothing here changes another sink, the `Sink` trait or the
//! management API shape.

#[cfg(test)]
mod tests {
    use broker_connectors_enterprise::{
        KinesisSink, KinesisSinkConfig, MockKinesisOutcome, MockKinesisTransport,
        SdkKinesisTransport,
    };
    use broker_protocol::{QoS, Topic, TopicFilter};
    use broker_rules::{BackpressurePolicy, BrokerSink, RuleEngine};
    use bytes::Bytes;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn test_config() -> KinesisSinkConfig {
        KinesisSinkConfig {
            stream_name: "telemetry-stream".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: None,
            partition_key_template: Some("${topic}".to_string()),
            explicit_hash_key: None,
            batch_size: Some(500),
            batch_bytes: Some(4_194_304),
            linger_ms: Some(20),
            max_retries: Some(5),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(3_000),
            timeout_ms: None,
        }
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

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
        ) -> std::result::Result<(), broker_rules::RuleEngineError> {
            Ok(())
        }
    }

    /// Qualification against the real Kinesis service via the maintained
    /// `aws-sdk-kinesis` driver (enterprise sink).
    ///
    /// Run with:
    /// `KINESIS_STREAM=qual-b325 KINESIS_REGION=ap-south-1 \
    ///  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
    ///  cargo test -p broker-connectors --lib kinesis::tests::test_qualify_driver_write_path -- --ignored --nocapture`
    ///
    /// Streams 1000 sequence-keyed records with distinct partition keys
    /// through the broker ([`RuleEngine`] dispatch into a `KinesisSink`
    /// on [`SdkKinesisTransport`]), reads the single shard back from
    /// `TRIM_HORIZON` and asserts exactly 1000 distinct sequence keys,
    /// proves the mock partial-failure path still requeues only failed
    /// records and the throughput-exceeded path backs off, then leaves
    /// the stream in place for the pipeline to delete.
    #[tokio::test]
    #[ignore = "needs the real Kinesis service (see KINESIS_* env)"]
    async fn test_qualify_driver_write_path() {
        use broker_connectors_enterprise::Sink as _;
        let stream = qual_env("KINESIS_STREAM").unwrap_or_else(|| {
            panic!(
                "KINESIS_STREAM must name a real Kinesis stream for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. KINESIS_STREAM=qual-b325)"
            )
        });
        let region = qual_env("KINESIS_REGION")
            .or_else(|| qual_env("AWS_REGION"))
            .or_else(|| qual_env("AWS_DEFAULT_REGION"))
            .unwrap_or_else(|| {
                panic!(
                    "KINESIS_REGION (or AWS_REGION) must name the stream's region; \
                     failing closed instead of passing vacuously"
                )
            });
        let access_key = qual_env("AWS_ACCESS_KEY_ID").unwrap_or_else(|| {
            panic!("AWS_ACCESS_KEY_ID must be set for qualification; failing closed")
        });
        let secret_key = qual_env("AWS_SECRET_ACCESS_KEY").unwrap_or_else(|| {
            panic!("AWS_SECRET_ACCESS_KEY must be set for qualification; failing closed")
        });
        // Optional session token (temporary credentials) and endpoint
        // override (local testing); the real service needs neither.
        let session_token = qual_env("AWS_SESSION_TOKEN");
        let endpoint = qual_env("KINESIS_ENDPOINT");
        // TODO(parity): Kinesis exposes no server-version API, so the
        // report carries the stream ARN plus DescribeStream output
        // instead of a version string; is that an acceptable "server
        // version"?

        let mut config = test_config();
        config.stream_name = stream.clone();
        config.region = region.clone();
        config.endpoint = endpoint;
        config.access_key_id = access_key;
        config.secret_access_key = secret_key;
        config.session_token = session_token;
        config.partition_key_template = Some("${client_id}".to_string());
        config.batch_size = Some(500);
        config.linger_ms = Some(10);
        config.max_retries = Some(5);
        config.initial_backoff_ms = Some(100);
        config.max_backoff_ms = Some(2_000);
        config.timeout_ms = Some(30_000);
        config.validate().expect("qual config validates");

        let transport = Arc::new(SdkKinesisTransport::new(&config).expect("qual transport"));
        let client = transport.client().clone();

        // Best-effort stream creation (the pipeline owns the stream and
        // deletes it after the run; an in-use name simply proceeds).
        match client
            .create_stream()
            .stream_name(&stream)
            .shard_count(1)
            .send()
            .await
        {
            Ok(_) => {}
            Err(e) => {
                let text = format!("{e:?} ({e})");
                let lower = text.to_lowercase();
                if !lower.contains("resourceinuse") && !lower.contains("already") {
                    panic!("qual create stream failed: {text}");
                }
            }
        }
        // Wait until the stream is ACTIVE before writing.
        tokio::time::timeout(Duration::from_secs(300), async {
            loop {
                let status = client
                    .describe_stream()
                    .stream_name(&stream)
                    .send()
                    .await
                    .ok()
                    .and_then(|out| {
                        out.stream_description()
                            .map(|desc| desc.stream_status())
                            .map(|status| format!("{status:?}"))
                    });
                if status.as_deref() == Some("Active") {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        })
        .await
        .expect("qual stream never became ACTIVE");
        let described = client
            .describe_stream()
            .stream_name(&stream)
            .send()
            .await
            .expect("qual describe");
        let stream_arn = described
            .stream_description()
            .map(|desc| desc.stream_arn())
            .map(str::to_string)
            .unwrap_or_default();
        let shard_id = described
            .stream_description()
            .and_then(|desc| desc.shards().first())
            .map(|shard| shard.shard_id())
            .map(str::to_string)
            .expect("qual stream has a shard");
        eprintln!("qual server: stream={stream} arn={stream_arn} region={region}");

        let sink = Arc::new(KinesisSink::new(config, transport).expect("qual sink"));
        assert_eq!(sink.kind(), "kinesis");
        // The broker's path: a rule registered on the connector
        // manager, messages published through the rule engine, so the
        // qualification sends through `dispatch_ingress`, never
        // `sink.send` directly.
        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        engine.connectors().register("qual-kinesis", sink.clone());
        engine
            .create_rule(
                "qual-kinesis-rule".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT client_id, seq FROM "sensors/+" INTO connector("qual-kinesis")"#
                        .to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");
        let egress: Arc<dyn BrokerSink> = Arc::new(NullBrokerSink);

        let topic = Topic::new("sensors/qual").unwrap();
        for seq in 0..1000u32 {
            let payload = Bytes::from(format!(r#"{{"client_id":"qual-{seq:04}","seq":{seq}}}"#));
            engine
                .dispatch_ingress(&topic, &payload, QoS::AtLeastOnce, &egress)
                .await;
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), 1000);
        eprintln!("qual rows sent: records=1000 stream={stream}");

        // Row keys asserted back from the server, not the counters:
        // every sequence key 0..1000 exactly once from TRIM_HORIZON.
        let iter_out = tokio::time::timeout(
            Duration::from_secs(60),
            client
                .get_shard_iterator()
                .stream_name(&stream)
                .shard_id(&shard_id)
                .shard_iterator_type(aws_sdk_kinesis::types::ShardIteratorType::TrimHorizon)
                .send(),
        )
        .await
        .expect("qual shard iterator timeout")
        .expect("qual shard iterator");
        let mut iterator = iter_out
            .shard_iterator()
            .map(str::to_string)
            .expect("qual iterator value");
        let deadline = Instant::now() + Duration::from_secs(600);
        let mut seen: HashSet<u32> = HashSet::new();
        while seen.len() < 1000 {
            if Instant::now() > deadline {
                break;
            }
            let page = tokio::time::timeout(
                Duration::from_secs(60),
                client.get_records().shard_iterator(iterator.clone()).send(),
            )
            .await
            .expect("qual get_records timeout")
            .expect("qual get_records");
            for record in page.records() {
                let data = record.data();
                let bytes: &[u8] = data.as_ref();
                if let Ok(doc) = serde_json::from_slice::<serde_json::Value>(bytes) {
                    if let Some(seq) = doc.get("seq").and_then(|v| v.as_u64()) {
                        if seq < 1000 {
                            seen.insert(seq as u32);
                        }
                    }
                }
            }
            match page.next_shard_iterator() {
                Some(next) => iterator = next.to_string(),
                None => break,
            }
            if seen.len() < 1000 {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        assert_eq!(
            seen.len(),
            1000,
            "kinesis qual: expected 1000 distinct seq records, saw {}",
            seen.len()
        );
        for seq in 0..1000u32 {
            assert!(seen.contains(&seq), "kinesis qual: missing seq {seq}");
        }
        eprintln!("qual rows asserted: count=1000 stream={stream}");

        // Throughput-exceeded backoff is asserted on the offline mock
        // only: the throttled record retries alone, then succeeds.
        let mut mock_config = test_config();
        mock_config.batch_size = Some(10);
        mock_config.initial_backoff_ms = Some(1);
        mock_config.max_backoff_ms = Some(2);
        let mock_transport = Arc::new(MockKinesisTransport::new());
        let mock_sink =
            Arc::new(KinesisSink::new(mock_config, mock_transport.clone()).expect("mock sink"));
        mock_transport.script_outcomes(vec![
            MockKinesisOutcome::Records(vec![
                Some("ProvisionedThroughputExceededException".to_string()),
                None,
            ]),
            MockKinesisOutcome::Records(vec![None]),
        ]);
        let mock_topic = Topic::new("t").unwrap();
        mock_sink
            .send(&mock_topic, &Bytes::from("a"), QoS::AtMostOnce)
            .await
            .unwrap();
        mock_sink
            .send(&mock_topic, &Bytes::from("b"), QoS::AtMostOnce)
            .await
            .unwrap();
        mock_sink.flush().await.unwrap();
        assert_eq!(mock_transport.calls(), 2);
        assert_eq!(mock_transport.captured()[1].records.len(), 1);

        // The stream is left in place: the pipeline deletes it after
        // the run.
    }
}
