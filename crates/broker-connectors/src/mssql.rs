//! Microsoft SQL Server qualification path for the pre-split crate name.
//!
//! The real sink lives in `broker-connectors-enterprise` (`mssql`):
//! `MssqlSink` on the maintained `tiberius` driver
//! (`DriverMssqlTransport` speaking TDS PRELOGIN, LOGIN7,
//! `sp_executesql` with SQL auth and typed params). This module exists
//! only so the task spec's `QUAL-CMD`
//! (`-p broker-connectors --lib mssql::tests::test_qualify_driver_write_path`)
//! finds a test: the qualification below drives the enterprise sink
//! through the broker's path and asserts the same counts as the
//! enterprise qualification. Runtime code stays in the enterprise
//! crate; nothing here changes another sink, the `Sink` trait or the
//! management API shape.

#[cfg(test)]
mod tests {
    use broker_connectors_enterprise::{
        ConnectorError, DriverMssqlTransport, MssqlAuth, MssqlQueryMode, MssqlRowItem, MssqlSink,
        MssqlSinkConfig, MssqlTransport, Sink as _,
    };
    use broker_protocol::{QoS, Topic};
    use bytes::Bytes;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;

    fn now_millis() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
            .unwrap_or(0)
    }

    type DriverClient = tiberius::Client<tokio_util::compat::Compat<tokio::net::TcpStream>>;

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    fn qual_require(name: &str) -> String {
        qual_env(name).unwrap_or_else(|| {
            panic!(
                "{name} must point at a real Microsoft SQL Server server for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. MSSQL_HOST=127.0.0.1)"
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

    /// Open a bare driver session for setup and assertions (DDL,
    /// version, counts). Panics with context when unreachable: a
    /// qualification against a missing server must fail, never skip.
    async fn qual_admin_client(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
        database: &str,
    ) -> DriverClient {
        use tokio_util::compat::TokioAsyncWriteCompatExt;
        let mut config = tiberius::Config::new();
        config.host(host);
        config.port(port);
        config.database(database);
        config.authentication(tiberius::AuthMethod::sql_server(user, password));
        // Qualification runs against a container with a self-signed
        // certificate: trust it explicitly (production deployments
        // with a chained certificate leave this off via config).
        config.trust_cert();
        let tcp = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::net::TcpStream::connect(config.get_addr()),
        )
        .await
        .expect("qual connect timed out")
        .unwrap_or_else(|e| panic!("qual connect failed: {e:?}"));
        tcp.set_nodelay(true).expect("qual nodelay");
        tokio::time::timeout(
            Duration::from_secs(60),
            tiberius::Client::connect(config, tcp.compat_write()),
        )
        .await
        .expect("qual login timed out")
        .unwrap_or_else(|e| panic!("qual login failed: {e:?}"))
    }

    /// Qualification against a real Microsoft SQL Server server over
    /// the maintained `tiberius` driver
    /// ([`DriverMssqlTransport`]).
    ///
    /// Run with e.g.:
    /// `MSSQL_HOST=127.0.0.1 MSSQL_PORT=1433 MSSQL_DATABASE=qual_b328 \
    ///  MSSQL_TABLE=qual_rows MSSQL_USER=sa MSSQL_PASSWORD='Qualpass1!' \
    ///  cargo test -p broker-connectors --lib mssql::tests::test_qualify_driver_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Creates a table with `DATETIMEOFFSET` / `NVARCHAR` / `BIGINT`
    /// columns, proves a wrong password fails closed with an auth
    /// error, streams 1000 rows through the broker
    /// ([`crate::ConnectorManager`] -> [`MssqlSink`] on
    /// [`DriverMssqlTransport`], never `sink.send` directly), asserts
    /// `SELECT COUNT(*)` returns 1000 with every key present and the
    /// column types round-tripping, then drops the table it created.
    /// Panics when its environment is missing (fail closed, never
    /// skips).
    #[tokio::test]
    #[ignore = "needs a real Microsoft SQL Server server (see MSSQL_* env)"]
    async fn test_qualify_driver_write_path() {
        const ROWS: usize = 1000;

        let host = qual_require("MSSQL_HOST");
        let port: u16 = qual_require("MSSQL_PORT")
            .parse()
            .expect("qual MSSQL_PORT must be a port number");
        let database = qual_identifier("database", &qual_require("MSSQL_DATABASE"));
        let table = qual_identifier("table", &qual_require("MSSQL_TABLE"));
        let user = qual_require("MSSQL_USER");
        let password = qual_require("MSSQL_PASSWORD");

        let mut admin = qual_admin_client(&host, port, &user, &password, &database).await;

        // Server version for the report (connectivity is already
        // proved by the login above; the version string is context).
        let version_rows = admin
            .simple_query("SELECT @@VERSION AS version")
            .await
            .expect("qual version query")
            .into_first_result()
            .await
            .expect("qual version rows");
        let version: &str = version_rows
            .first()
            .expect("qual version row")
            .get(0)
            .expect("qual version value");
        eprintln!("qual server: version={version} host={host}:{port} database={database}");

        admin
            .simple_query(format!("DROP TABLE IF EXISTS [{table}]").as_str())
            .await
            .expect("qual drop stale table")
            .into_first_result()
            .await
            .expect("qual drop drained");
        admin
            .simple_query(
                format!(
                    "CREATE TABLE [{table}] (\
                     event_time DATETIMEOFFSET NOT NULL, \
                     topic NVARCHAR(256) NOT NULL, \
                     client_id NVARCHAR(256) NOT NULL, \
                     qos BIGINT NOT NULL, \
                     payload NVARCHAR(MAX) NOT NULL)"
                )
                .as_str(),
            )
            .await
            .expect("qual create table")
            .into_first_result()
            .await
            .expect("qual create drained");
        eprintln!("qual table created: {table} (DATETIMEOFFSET/NVARCHAR/BIGINT)");

        // Wrong password fails closed with an auth error through the
        // same transport mapping production uses (Dispatch, never a
        // retryable silence, and nothing written).
        let bad_row = MssqlRowItem {
            time_ms: now_millis(),
            topic: "sensors/qual".to_string(),
            client_id: "qual-bad".to_string(),
            qos: 1,
            payload_json: r#"{"client_id":"qual-bad","seq":-1}"#.to_string(),
        };
        let bad_config = MssqlSinkConfig {
            host: host.clone(),
            port: Some(port),
            database: database.clone(),
            table_template: table.clone(),
            auth: MssqlAuth::SqlPassword {
                username: user.clone(),
                password: "wrongpass".to_string(),
            },
            query_mode: MssqlQueryMode::InsertJson,
            trust_server_certificate: true,
            batch_size: Some(200),
            batch_bytes: Some(2_097_152),
            linger_ms: Some(60_000),
            max_retries: Some(3),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_500),
            timeout_ms: Some(15_000),
        };
        let bad_transport =
            Arc::new(DriverMssqlTransport::new(&bad_config).expect("qual bad transport"));
        let bad_err = bad_transport
            .execute_batch(&table, vec![bad_row])
            .await
            .expect_err("wrong password must fail");
        assert!(
            matches!(bad_err, ConnectorError::Dispatch(_)),
            "qual bad password must surface an auth error, got {bad_err:?}"
        );
        eprintln!("qual auth asserted: wrong password fails closed ({bad_err:?})");

        // The broker's path: rule actions deliver through the shared
        // connector manager (this is what `register_live_sink` fills
        // and what `ForwardConnector` sends through), so the
        // qualification sends through it and never `sink.send`.
        let sink_config = MssqlSinkConfig {
            host: host.clone(),
            port: Some(port),
            database: database.clone(),
            table_template: table.clone(),
            auth: MssqlAuth::SqlPassword {
                username: user.clone(),
                password: password.clone(),
            },
            query_mode: MssqlQueryMode::InsertJson,
            trust_server_certificate: true,
            batch_size: Some(200),
            batch_bytes: Some(2_097_152),
            linger_ms: Some(60_000), // explicit flushes only; keeps auto-batches exact
            max_retries: Some(3),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_500),
            timeout_ms: Some(30_000), // container cold start + TLS handshake
        };
        sink_config.validate().expect("qual config validates");
        let transport = Arc::new(DriverMssqlTransport::new(&sink_config).expect("qual transport"));
        let sink = Arc::new(MssqlSink::new(sink_config, transport).expect("qual sink"));
        assert_eq!(sink.kind(), "mssql");
        // Shared manager from the dependency instance (`broker-rules`
        // owns a `ConnectorManager` over the same `broker-connectors`
        // instance the enterprise sink implements `Sink` for). Using
        // `crate::ConnectorManager` here would mix the crate-under-test
        // instance with the dependency instance and fail to compile
        // ("multiple different versions of crate `broker_connectors`").
        let engine =
            broker_rules::RuleEngine::new(65_536, broker_rules::BackpressurePolicy::DropOldest);
        engine.connectors().register("qual-mssql", sink.clone());

        let topic = Topic::new("sensors/qual").unwrap();
        let window_start = now_millis();
        for seq in 0..ROWS {
            let payload = Bytes::from(format!(r#"{{"client_id":"qual-{seq:06}","seq":{seq}}}"#));
            engine
                .connectors()
                .send("qual-mssql", &topic, &payload, QoS::AtLeastOnce)
                .await
                .unwrap_or_else(|e| panic!("qual send seq={seq} failed: {e:?}"));
        }
        sink.flush().await.expect("qual flush");
        let window_end = now_millis();
        assert_eq!(sink.sent_records(), ROWS as u64, "qual sent records");
        assert_eq!(sink.sent_batches(), 5, "qual sent batches");
        eprintln!("qual rows sent: records={ROWS} batches=5 table={table}");

        // Row count asserted back from the server, not the counters.
        let count_rows = admin
            .simple_query(format!("SELECT COUNT(*) AS n FROM [{table}]").as_str())
            .await
            .expect("qual count")
            .into_first_result()
            .await
            .expect("qual count rows");
        let count: i32 = count_rows
            .first()
            .expect("qual count row")
            .get(0)
            .expect("qual count value");
        assert_eq!(count, ROWS as i32, "qual count mismatch");
        eprintln!("qual rows asserted: count={ROWS} table={table}");

        // Column types asserted back from the catalog: the params must
        // have landed as DATETIMEOFFSET / NVARCHAR / BIGINT.
        let schema_rows = admin
            .simple_query(
                format!(
                    "SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS \
                     WHERE TABLE_NAME = '{table}' ORDER BY ORDINAL_POSITION"
                )
                .as_str(),
            )
            .await
            .expect("qual schema")
            .into_first_result()
            .await
            .expect("qual schema rows");
        let schema: Vec<(String, String)> = schema_rows
            .iter()
            .map(|row| {
                let name: &str = row.get(0).expect("qual column name");
                let dtype: &str = row.get(1).expect("qual column type");
                (name.to_string(), dtype.to_string())
            })
            .collect();
        assert_eq!(
            schema,
            vec![
                ("event_time".to_string(), "datetimeoffset".to_string()),
                ("topic".to_string(), "nvarchar".to_string()),
                ("client_id".to_string(), "nvarchar".to_string()),
                ("qos".to_string(), "bigint".to_string()),
                ("payload".to_string(), "nvarchar".to_string()),
            ],
            "qual column types must round-trip"
        );
        eprintln!("qual types asserted: {schema:?}");

        // Every key present with exact values (at-least-once permits
        // duplicates, never loss; here the count is already exact).
        // Event times come back as epoch millis via DATEDIFF_BIG so
        // the assertion needs no client date library.
        let value_rows = admin
            .simple_query(
                format!(
                    "SELECT DATEDIFF_BIG(MILLISECOND, '1970-01-01T00:00:00+00:00', event_time), \
                     topic, client_id, qos, payload FROM [{table}]"
                )
                .as_str(),
            )
            .await
            .expect("qual values")
            .into_first_result()
            .await
            .expect("qual value rows");
        assert_eq!(value_rows.len(), ROWS, "qual value row count");
        let mut seen = HashSet::with_capacity(ROWS);
        for row in &value_rows {
            let event_ms: i64 = row.get(0).expect("qual event_time");
            let row_topic: &str = row.get(1).expect("qual topic");
            let row_client: &str = row.get(2).expect("qual client_id");
            let row_qos: i64 = row.get(3).expect("qual qos");
            let row_payload: &str = row.get(4).expect("qual payload");
            assert!(
                (window_start..=window_end).contains(&event_ms),
                "qual event_time {event_ms} outside send window"
            );
            assert_eq!(row_topic, "sensors/qual");
            assert_eq!(row_qos, 1);
            let value: serde_json::Value =
                serde_json::from_str(row_payload).expect("qual payload JSON");
            assert_eq!(
                value.get("client_id").and_then(|v| v.as_str()),
                Some(row_client)
            );
            assert!(
                seen.insert(row_client.to_string()),
                "qual duplicate {row_client}"
            );
        }
        for seq in 0..ROWS {
            assert!(
                seen.contains(&format!("qual-{seq:06}")),
                "qual missing key qual-{seq:06}"
            );
        }
        eprintln!("qual values asserted: every key present, types exact");

        // Cleanup: drop the table created for this run (best effort;
        // the next run drops stale tables first).
        match admin
            .simple_query(format!("DROP TABLE IF EXISTS [{table}]").as_str())
            .await
        {
            Ok(stream) => match stream.into_first_result().await {
                Ok(_) => eprintln!("qual cleanup: dropped table {table}"),
                Err(error) => {
                    eprintln!("qual cleanup FAILED to drop {table} (tolerated): {error}")
                }
            },
            Err(error) => {
                eprintln!("qual cleanup FAILED to drop {table} (tolerated): {error}")
            }
        }
        eprintln!("qual done: rows={ROWS} table={table} database={database}");
    }
}
