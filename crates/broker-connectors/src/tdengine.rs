//! TDengine qualification path for the pre-split crate name.
//!
//! The real sink lives in `broker-connectors-enterprise` (`tdengine`):
//! `TdengineSink` on the maintained `reqwest` REST SQL driver
//! ([`DriverTdengineTransport`] posts the same `INSERT INTO ...
//! USING ... TAGS ...` text to `/rest/sql/{database}` with Basic auth).
//! This module exists
//! only so the task spec's `QUAL-CMD`
//! (`-p broker-connectors --lib tdengine::tests::test_qualify_driver_write_path`)
//! finds a test: the qualification below drives the enterprise sink
//! through the broker's rule path and asserts the same counts as the
//! enterprise qualification. Runtime code stays in the enterprise
//! crate; nothing here changes another sink, the `Sink` trait or the
//! management API shape.

#[cfg(test)]
mod tests {
    use broker_connectors_enterprise::{
        ConnectorError, DriverTdengineTransport, Sink as _, TdengineAuth, TdengineSink,
        TdengineSinkConfig, TdengineTransport,
    };
    use broker_protocol::{QoS, Topic, TopicFilter};
    use broker_rules::{BackpressurePolicy, RuleEngine};
    use bytes::Bytes;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    fn qual_require(name: &str) -> String {
        qual_env(name).unwrap_or_else(|| {
            panic!(
                "{name} must point at a real TDengine server for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. TDENGINE_URL=http://127.0.0.1:6041)"
            )
        })
    }

    fn qual_identifier(name: &str, value: &str) -> String {
        assert!(
            !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "qual {name} must match [A-Za-z0-9_]+, got {value:?} (failing closed)"
        );
        value.to_string()
    }

    /// Discards unmatched egress for the rule-path qualification (the
    /// connector under test receives everything through its rule).
    struct NullBrokerSink;

    #[async_trait::async_trait]
    impl broker_rules::BrokerSink for NullBrokerSink {
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

    #[derive(Debug, serde::Deserialize)]
    struct CountRow {
        n: i64,
    }

    #[derive(Debug, serde::Deserialize)]
    struct SumRow {
        s: i64,
    }

    #[derive(Debug, serde::Deserialize)]
    struct AvgRow {
        a: f64,
    }

    #[derive(Debug, serde::Deserialize)]
    struct SubtableRow {
        t: String,
        c: i64,
    }

    #[derive(Debug, serde::Deserialize)]
    struct VersionRow {
        v: String,
    }

    /// Qualification against a real TDengine server over the maintained
    /// `reqwest` REST SQL driver ([`DriverTdengineTransport`]).
    ///
    /// Run with e.g.:
    /// `TDENGINE_URL=http://127.0.0.1:6041 TDENGINE_USER=root \
    ///  TDENGINE_PASSWORD=taosdata TDENGINE_DATABASE=qual_b345 \
    ///  cargo test -p broker-connectors --lib tdengine::tests::test_qualify_driver_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Creates a super-table, proves a wrong password fails closed with
    /// an auth error, streams 2000 rows through the broker (a rule
    /// registered on the connector manager, messages published through
    /// the rule engine, never `sink.send` directly), asserts
    /// `COUNT(*)` / `SUM(seq)` / `AVG(val)` back from the server with
    /// every sub-table present exactly once, then drops the stable it
    /// created. Panics when its environment is missing (fail closed,
    /// never skips).
    #[tokio::test]
    #[ignore = "needs a real TDengine server (see TDENGINE_* env)"]
    async fn test_qualify_driver_write_path() {
        const ROWS: usize = 2000;
        const STABLE: &str = "qual_meters";

        let endpoint = qual_require("TDENGINE_URL");
        assert!(
            endpoint.starts_with("http://") || endpoint.starts_with("https://"),
            "qual TDENGINE_URL must be http(s), got {endpoint:?} (failing closed)"
        );
        let username = qual_require("TDENGINE_USER");
        let password = qual_require("TDENGINE_PASSWORD");
        let database = qual_identifier("database", &qual_require("TDENGINE_DATABASE"));

        let mut tags_template = HashMap::new();
        tags_template.insert("location".to_string(), "${payload.location}".to_string());
        tags_template.insert("groupid".to_string(), "${payload.groupid}".to_string());
        let mut metrics_template = HashMap::new();
        metrics_template.insert("seq".to_string(), "${payload.seq}".to_string());
        metrics_template.insert("val".to_string(), "${payload.val}".to_string());
        let sink_config = TdengineSinkConfig {
            endpoint: endpoint.clone(),
            database: database.clone(),
            stable_name: STABLE.to_string(),
            subtable_template: "d_${client_id}".to_string(),
            auth: TdengineAuth::Basic {
                username: username.clone(),
                password: password.clone(),
            },
            tags_template,
            metrics_template,
            batch_size: Some(500),
            batch_bytes: Some(4_194_304),
            linger_ms: Some(60_000), // explicit flushes only; keeps auto-batches exact
            buffer_capacity: Some(10_000),
            max_retries: Some(3),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_500),
            timeout_ms: Some(30_000), // container cold start + handshake
        };
        sink_config.validate().expect("qual config validates");
        // The qualified path rides the driver (Basic + plaintext); the
        // production wiring branches token/TLS configs to REST.
        assert!(
            sink_config.use_driver(),
            "qual config must ride the driver path"
        );
        let transport =
            Arc::new(DriverTdengineTransport::new(&sink_config).expect("qual transport"));

        // Server version for the report (connectivity is already proved
        // by the query itself; the version string is context).
        let versions: Vec<VersionRow> = transport
            .query_rows(Some(database.as_str()), "SELECT SERVER_VERSION() AS v")
            .await
            .expect("qual version query");
        let version = versions
            .first()
            .map(|row| row.v.clone())
            .unwrap_or_default();
        eprintln!("qual server: version={version} database={database}");

        transport
            .exec_admin(&format!("CREATE DATABASE IF NOT EXISTS {database}"))
            .await
            .expect("qual create database");
        transport
            .exec_admin(&format!("DROP STABLE IF EXISTS {database}.{STABLE}"))
            .await
            .expect("qual drop stale stable");
        transport
            .exec_admin(&format!(
                "CREATE STABLE IF NOT EXISTS {database}.{STABLE} \
                 (ts TIMESTAMP, seq BIGINT, val DOUBLE) \
                 TAGS (groupid INT, location BINARY(16))"
            ))
            .await
            .expect("qual create stable");
        eprintln!(
            "qual stable created: {database}.{STABLE} (TIMESTAMP/BIGINT/DOUBLE + INT/BINARY tags)"
        );

        // Wrong password fails closed with an auth error through the
        // same transport mapping production uses (Dispatch, never a
        // retryable silence, and nothing written).
        let bad_config = TdengineSinkConfig {
            auth: TdengineAuth::Basic {
                username: username.clone(),
                password: "wrongpass".to_string(),
            },
            ..sink_config.clone()
        };
        let bad_transport =
            Arc::new(DriverTdengineTransport::new(&bad_config).expect("qual bad transport"));
        let bad_err = bad_transport
            .execute_sql(
                &database,
                &format!(
                    "INSERT INTO d_qbad USING {STABLE} TAGS (1, 'room1') VALUES (1700000000000, -1, -1.0)"
                ),
                &bad_config.auth,
            )
            .await
            .expect_err("wrong password must fail");
        assert!(
            matches!(bad_err, ConnectorError::Dispatch(_)),
            "qual bad password must surface an auth error, got {bad_err:?}"
        );
        eprintln!("qual auth asserted: wrong password fails closed ({bad_err:?})");

        // The broker's path: a rule registered on the connector
        // manager, messages published through the rule engine, so the
        // qualification sends through `dispatch_ingress`, never
        // `sink.send` directly.
        let sink = Arc::new(TdengineSink::new(sink_config, transport.clone()).expect("qual sink"));
        assert_eq!(sink.kind(), "tdengine");
        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        engine.connectors().register("qual-tdengine", sink.clone());
        engine
            .create_rule(
                "qual-tdengine-rule".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT client_id, seq, val, location, groupid FROM "sensors/+" INTO connector("qual-tdengine")"#
                        .to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");
        let egress: Arc<dyn broker_rules::BrokerSink> = Arc::new(NullBrokerSink);

        let topic = Topic::new("sensors/qual").unwrap();
        for seq in 0..ROWS {
            let client_id = format!("q{seq:06}");
            let val = seq as f64 * 1.5;
            let payload = Bytes::from(format!(
                r#"{{"client_id":"{client_id}","seq":{seq},"val":{val},"location":"room1","groupid":{}}}"#,
                seq % 8,
            ));
            engine
                .dispatch_ingress(&topic, &payload, QoS::AtLeastOnce, &egress)
                .await;
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), ROWS as u64, "qual sent records");
        assert_eq!(sink.sent_batches(), 4, "qual sent batches");
        eprintln!("qual rows sent: records={ROWS} batches=4 stable={STABLE}");

        // Row count asserted back from the server, not the counters.
        let counts: Vec<CountRow> = transport
            .query_rows(
                Some(database.as_str()),
                &format!("SELECT COUNT(*) AS n FROM {STABLE}"),
            )
            .await
            .expect("qual count");
        assert_eq!(counts.len(), 1, "qual count row");
        assert_eq!(counts[0].n, ROWS as i64, "qual count mismatch");
        eprintln!("qual rows asserted: count={ROWS} stable={STABLE}");

        // Aggregation asserted back from the server: exact integer sum
        // plus the floating-point average (float division is the only
        // rounding step, hence the epsilon with this reason).
        let sums: Vec<SumRow> = transport
            .query_rows(
                Some(database.as_str()),
                &format!("SELECT SUM(seq) AS s FROM {STABLE}"),
            )
            .await
            .expect("qual sum");
        assert_eq!(sums.len(), 1, "qual sum row");
        assert_eq!(sums[0].s, 1_999_000, "qual sum mismatch");
        let avgs: Vec<AvgRow> = transport
            .query_rows(
                Some(database.as_str()),
                &format!("SELECT AVG(val) AS a FROM {STABLE}"),
            )
            .await
            .expect("qual avg");
        assert_eq!(avgs.len(), 1, "qual avg row");
        assert!(
            (avgs[0].a - 1499.25).abs() < 1e-9,
            "qual avg mismatch: got {}",
            avgs[0].a
        );
        eprintln!("qual aggregation asserted: sum=1999000 avg=1499.25");

        // Every key present exactly once (at-least-once permits
        // duplicates, never loss; here the count is already exact, so
        // one row per sub-table proves no duplication either).
        let tables: Vec<SubtableRow> = transport
            .query_rows(
                Some(database.as_str()),
                &format!("SELECT tbname AS t, COUNT(*) AS c FROM {STABLE} GROUP BY tbname"),
            )
            .await
            .expect("qual sub-tables");
        assert_eq!(tables.len(), ROWS, "qual sub-table count mismatch");
        let mut seen = HashSet::with_capacity(ROWS);
        for row in &tables {
            assert_eq!(row.c, 1, "qual duplicate in {}", row.t);
            assert!(seen.insert(row.t.clone()), "qual duplicate {}", row.t);
        }
        for seq in 0..ROWS {
            let key = format!("d_q{seq:06}");
            assert!(seen.contains(&key), "qual missing key {key}");
        }
        eprintln!("qual keys asserted: every sub-table present exactly once");

        // A syntax error surfaces as a terminal dispatch error (never a
        // silent drop, never a retry loop).
        let syntax_err = transport
            .execute_sql(
                &database,
                "THIS IS NOT VALID SQL __qual_syntax_probe__",
                &TdengineAuth::Basic {
                    username: username.clone(),
                    password: password.clone(),
                },
            )
            .await
            .expect_err("syntax error must fail");
        assert!(
            matches!(syntax_err, ConnectorError::Dispatch(_)),
            "syntax error must be terminal, got {syntax_err:?}"
        );
        eprintln!("qual syntax asserted: bad SQL fails closed ({syntax_err:?})");

        // Cleanup: drop the stable created for this run (best effort;
        // the next run drops stale stables first).
        match transport
            .exec_admin(&format!("DROP STABLE IF EXISTS {database}.{STABLE}"))
            .await
        {
            Ok(_) => eprintln!("qual cleanup: dropped stable {database}.{STABLE}"),
            Err(error) => {
                eprintln!("qual cleanup FAILED to drop {database}.{STABLE} (tolerated): {error}")
            }
        }
        eprintln!("qual done: rows={ROWS} stable={database}.{STABLE}");
    }
}
