//! Amazon Redshift qualification path for the pre-split crate name.
//!
//! The real sink lives in `broker-connectors-enterprise` (`redshift`):
//! `RedshiftSink` on the maintained `aws-sdk-redshiftdata` driver
//! (`SdkRedshiftTransport` with driver-owned SigV4 plus
//! `DescribeStatement` polling to FINISHED). This module exists
//! only so the task spec's `QUAL-CMD`
//! (`-p broker-connectors --lib redshift::tests::test_qualify_driver_write_path`)
//! finds a test: the qualification below drives the enterprise sink
//! through the broker's rule path and asserts the same counts as the
//! enterprise qualification. Runtime code stays in the enterprise
//! crate; nothing here changes another sink, the `Sink` trait or the
//! management API shape.

#[cfg(test)]
mod tests {
    use broker_connectors_enterprise::{
        ConnectorError, RedshiftBatchRequest, RedshiftSink, RedshiftSinkConfig, RedshiftTransport,
        SdkRedshiftTransport, Sink as _,
    };
    use broker_protocol::{QoS, Topic, TopicFilter};
    use broker_rules::{BackpressurePolicy, RuleEngine};
    use bytes::Bytes;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;

    fn test_config() -> RedshiftSinkConfig {
        RedshiftSinkConfig {
            database: "analytics".to_string(),
            table_template: "sensor_logs".to_string(),
            cluster_identifier: None,
            workgroup_name: Some("iot-workgroup".to_string()),
            region: "us-east-1".to_string(),
            endpoint: None,
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: None,
            db_user: None,
            sql_template: None,
            batch_size: Some(100),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_500),
            timeout_ms: None,
        }
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    fn qual_require(name: &str) -> String {
        qual_env(name).unwrap_or_else(|| {
            panic!(
                "{name} must name a real Amazon Redshift server for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. REDSHIFT_WORKGROUP=qual-wg)"
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

    fn field_to_string(field: &aws_sdk_redshiftdata::types::Field) -> String {
        use aws_sdk_redshiftdata::types::Field;
        match field {
            Field::StringValue(text) => text.clone(),
            Field::LongValue(n) => n.to_string(),
            Field::DoubleValue(d) => d.to_string(),
            Field::BooleanValue(b) => b.to_string(),
            Field::IsNull(_) => String::new(),
            _ => format!("{field:?}"),
        }
    }

    /// Run one SQL statement through the driver and poll
    /// `DescribeStatement` to FINISHED, returning the statement id.
    /// `FAILED` / `ABORTED` surface the server error plus the
    /// statement text as a terminal dispatch error.
    async fn qual_run_sql(
        client: &aws_sdk_redshiftdata::Client,
        database: &str,
        workgroup: Option<&str>,
        cluster: Option<&str>,
        db_user: Option<&str>,
        sql: &str,
        timeout: Duration,
    ) -> String {
        let mut builder = client
            .execute_statement()
            .set_database(Some(database.to_string()))
            .set_sql(Some(sql.to_string()));
        if let Some(cluster) = cluster {
            builder = builder.set_cluster_identifier(Some(cluster.to_string()));
        }
        if let Some(workgroup) = workgroup {
            builder = builder.set_workgroup_name(Some(workgroup.to_string()));
        }
        if let Some(user) = db_user {
            builder = builder.set_db_user(Some(user.to_string()));
        }
        let id = tokio::time::timeout(timeout, builder.send())
            .await
            .expect("qual execute timed out")
            .unwrap_or_else(|e| panic!("qual execute failed: {e:?} ({e})"))
            .id()
            .map(str::to_string)
            .expect("qual execute lacks Id");
        for _ in 0..300 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let described = tokio::time::timeout(
                timeout,
                client.describe_statement().set_id(Some(id.clone())).send(),
            )
            .await
            .expect("qual describe timed out")
            .unwrap_or_else(|e| panic!("qual describe failed: {e:?} ({e})"));
            let status = described.status().map(|s| s.as_str()).unwrap_or("");
            match status {
                "FINISHED" => return id,
                "FAILED" | "ABORTED" => {
                    let server_error = described.error().unwrap_or("unknown error");
                    let query = described.query_string().unwrap_or("");
                    panic!("qual statement {id} {status}: {server_error} :: {query}");
                }
                _ => {}
            }
        }
        panic!("qual statement {id} still pending after 300 polls");
    }

    /// Fetch every result row for a finished statement id,
    /// following pagination tokens to the end.
    async fn qual_fetch_all(
        client: &aws_sdk_redshiftdata::Client,
        id: &str,
        timeout: Duration,
    ) -> Vec<Vec<String>> {
        let mut rows = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut builder = client.get_statement_result().set_id(Some(id.to_string()));
            if let Some(token) = next {
                builder = builder.set_next_token(Some(token));
            }
            let page = tokio::time::timeout(timeout, builder.send())
                .await
                .expect("qual fetch timed out")
                .unwrap_or_else(|e| panic!("qual fetch failed: {e:?} ({e})"));
            for record in page.records() {
                rows.push(record.iter().map(field_to_string).collect());
            }
            match page.next_token() {
                Some(token) => next = Some(token.to_string()),
                None => break,
            }
        }
        rows
    }

    /// Qualification against a real Amazon Redshift Serverless
    /// workgroup through the Redshift Data API on the maintained
    /// `aws-sdk-redshiftdata` driver (enterprise sink).
    ///
    /// Run with:
    /// `REDSHIFT_WORKGROUP=qual-wg REDSHIFT_DATABASE=dev REDSHIFT_REGION=ap-south-1 \
    ///  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
    ///  cargo test -p broker-connectors --lib redshift::tests::test_qualify_driver_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Creates a table, streams 500 sequence-keyed rows through the
    /// broker ([`RuleEngine`] dispatch into a [`RedshiftSink`] on
    /// [`SdkRedshiftTransport`]), polls each statement to FINISHED,
    /// asserts `COUNT(*)` returns 500 with every key present, proves
    /// a syntax error surfaces the statement text, then drops the
    /// table it created.
    #[tokio::test]
    #[ignore = "needs a real Amazon Redshift server (see REDSHIFT_* env)"]
    async fn test_qualify_driver_write_path() {
        const ROWS: usize = 500;

        let workgroup = qual_require("REDSHIFT_WORKGROUP");
        let database = qual_require("REDSHIFT_DATABASE");
        let region = qual_require("REDSHIFT_REGION");
        let table = qual_identifier(
            "table",
            &qual_env("REDSHIFT_TABLE").unwrap_or_else(|| "qual_b338".to_string()),
        );
        let access_key = qual_env("AWS_ACCESS_KEY_ID").unwrap_or_else(|| {
            panic!("AWS_ACCESS_KEY_ID must be set for qualification; failing closed")
        });
        let secret_key = qual_env("AWS_SECRET_ACCESS_KEY").unwrap_or_else(|| {
            panic!("AWS_SECRET_ACCESS_KEY must be set for qualification; failing closed")
        });
        let session_token = qual_env("AWS_SESSION_TOKEN");
        let db_user = qual_env("REDSHIFT_DB_USER");
        // TODO(parity): the Data API exposes no dedicated server-version
        // call, so the report carries `SELECT version()` output plus the
        // workgroup/region instead of a version string; is that an
        // acceptable "server version"?

        let mut config = test_config();
        config.database = database.clone();
        config.table_template = table.clone();
        config.cluster_identifier = None;
        config.workgroup_name = Some(workgroup.clone());
        config.region = region.clone();
        config.endpoint = None;
        config.access_key_id = access_key;
        config.secret_access_key = secret_key;
        config.session_token = session_token;
        config.db_user = db_user.clone();
        config.sql_template = None;
        // Few billed statements: 500 rows in 5 batches of 100.
        config.batch_size = Some(100);
        config.batch_bytes = Some(1_048_576);
        config.linger_ms = Some(60_000);
        config.max_retries = Some(5);
        config.initial_backoff_ms = Some(100);
        config.max_backoff_ms = Some(2_500);
        config.timeout_ms = Some(30_000);
        config.validate().expect("qual config validates");

        let transport = Arc::new(
            SdkRedshiftTransport::with_polling(&config, Duration::from_secs(1), 300)
                .expect("qual transport"),
        );
        let client = transport.client().clone();
        let admin_timeout = Duration::from_secs(60);

        let version_id = qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            "SELECT version()",
            admin_timeout,
        )
        .await;
        let version_rows = qual_fetch_all(&client, &version_id, admin_timeout).await;
        let version = version_rows
            .first()
            .and_then(|row| row.first())
            .cloned()
            .unwrap_or_default();
        eprintln!("qual server: version={version} workgroup={workgroup} region={region}");

        qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            &format!("DROP TABLE IF EXISTS {table}"),
            admin_timeout,
        )
        .await;
        qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            &format!(
                "CREATE TABLE {table} (\
                 time_ms BIGINT NOT NULL, \
                 topic VARCHAR(256) NOT NULL, \
                 client_id VARCHAR(256) NOT NULL, \
                 qos INTEGER NOT NULL, \
                 payload VARCHAR(65535) NOT NULL)"
            ),
            admin_timeout,
        )
        .await;
        eprintln!("qual table created: {table} (BIGINT/VARCHAR/INTEGER)");

        // The broker's path: a rule registered on the connector
        // manager, messages published through the rule engine, so the
        // qualification sends through `dispatch_ingress`, never
        // `sink.send` directly.
        let sink = Arc::new(RedshiftSink::new(config, transport.clone()).expect("qual sink"));
        assert_eq!(sink.kind(), "redshift");
        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        engine.connectors().register("qual-redshift", sink.clone());
        engine
            .create_rule(
                "qual-redshift-rule".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT client_id, seq FROM "sensors/+" INTO connector("qual-redshift")"#
                        .to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");
        let egress: Arc<dyn broker_rules::BrokerSink> = Arc::new(NullBrokerSink);

        let topic = Topic::new("sensors/qual").unwrap();
        for seq in 0..ROWS {
            let payload = Bytes::from(format!(r#"{{"client_id":"qual-{seq:06}","seq":{seq}}}"#));
            engine
                .dispatch_ingress(&topic, &payload, QoS::AtLeastOnce, &egress)
                .await;
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), ROWS as u64, "qual sent records");
        eprintln!("qual rows sent: records={ROWS} table={table}");

        let count_id = qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            &format!("SELECT COUNT(*) FROM {table}"),
            admin_timeout,
        )
        .await;
        let count_rows = qual_fetch_all(&client, &count_id, admin_timeout).await;
        let count: i64 = count_rows
            .first()
            .and_then(|row| row.first())
            .and_then(|value| value.parse().ok())
            .expect("qual count value");
        assert_eq!(count, ROWS as i64, "qual count mismatch");
        eprintln!("qual rows asserted: count={ROWS} table={table}");

        let keys_id = qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            &format!("SELECT client_id FROM {table}"),
            admin_timeout,
        )
        .await;
        let key_rows = qual_fetch_all(&client, &keys_id, admin_timeout).await;
        let seen: HashSet<String> = key_rows
            .into_iter()
            .filter_map(|row| row.into_iter().next())
            .collect();
        assert_eq!(seen.len(), ROWS, "qual distinct keys mismatch");
        for seq in 0..ROWS {
            let key = format!("qual-{seq:06}");
            assert!(seen.contains(&key), "qual missing key {key}");
        }
        eprintln!("qual keys asserted: keys={ROWS} table={table}");

        // A syntax error surfaces the statement text (terminal
        // dispatch, never a silent drop).
        let probe = "THIS IS NOT VALID SQL __qual_syntax_probe__";
        let bad_request = RedshiftBatchRequest {
            database: database.clone(),
            cluster_identifier: None,
            workgroup_name: Some(workgroup.clone()),
            db_user: db_user.clone(),
            statements: vec![probe.to_string()],
        };
        let err = transport
            .execute_batch(&bad_request)
            .await
            .expect_err("syntax error must fail");
        assert!(
            matches!(err, ConnectorError::Dispatch(_)),
            "syntax error must be terminal, got {err:?}"
        );
        assert!(
            format!("{err}").contains("__qual_syntax_probe__"),
            "syntax error must surface the statement text, got {err:?}"
        );
        eprintln!("qual syntax asserted: statement text surfaces ({err})");

        qual_run_sql(
            &client,
            &database,
            Some(&workgroup),
            None,
            db_user.as_deref(),
            &format!("DROP TABLE IF EXISTS {table}"),
            admin_timeout,
        )
        .await;
        eprintln!("qual cleanup: dropped table {table}");
    }
}
