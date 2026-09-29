//! `indra ctl`: operator CLI for the session and messaging surface (M1-06).
//!
//! Decision record (spec allows `indra ctl` or an `indramqtt` subcommand;
//! decided once here): `indra` is a second binary in `broker-node` with a
//! `ctl` subcommand, so operators type `indra ctl status`,
//! `indra ctl clients list`, and so on. The kernel binary keeps its
//! flag-only boot shape; the CLI shares only the workspace HTTP and CLI
//! crates. Governance commands (rules, users, config, licence, backup)
//! extend the same `ctl` tree in M1-07.
//!
//! `ctl` holds no business logic and no local state beyond connection
//! options: every command maps 1:1 onto a management API call. Output is
//! human-readable tables by default with `--json` printing the management
//! API response body verbatim (stable keys) for scripts.
//!
//! Authentication: one operator API key, sent as
//! `Authorization: Bearer <key>` over whatever scheme the endpoint uses
//! (`http` for loopback, `https` for TLS-terminated endpoints; the client
//! never silently skips verification). The key is resolved
//! `--api-key` flag, then `--api-key-file`, then `INDRA_API_KEY`; a
//! missing key fails closed client-side before any request is sent. The
//! key never appears in output or logs ([`SecretString`] redacts it from
//! `Debug`/`Display`, and error paths never echo it).
//!
//! Exit codes (each tested):
//! - 0 success.
//! - 1 connection failure: unreachable host, refused port, timeout, TLS
//!   failure, or a response that is not valid JSON where JSON is required.
//! - 2 authentication failure: HTTP 401 or 403 (refused key, expired
//!   token, insufficient role).
//! - 3 not found: HTTP 404 (unknown client, topic, or route).
//! - 4 validation failure: bad CLI arguments, missing key, malformed
//!   endpoint URL, or HTTP 400/409/422 from the server.
//! - 5 server failure: HTTP 5xx or any other unexpected status.
//!
//!   A failed command prints the reason on stderr and nothing partial on
//!   stdout.
//!
//! Management-plane only: this binary never publishes or delivers MQTT
//! itself and takes no lock on the broker's message path; per-request
//! work is one HTTPS call plus rendering at most one bounded page.
//!
//! Governance surface (M1-07): `rules`, `connectors`, `users`,
//! `config validate|diff|explain|reload|history`, `licence` and `backup`
//! extend the same `ctl` tree with the same transport, auth and
//! human/`--json` contract. Each maps 1:1 onto a management API call
//! (`/api/v1/rules`, `/api/v5/connectors`, `/api/v1/auth/users`,
//! `/api/v1/config/*`, `/api/v1/licence/*`); `backup export` reads the
//! latest versioned config snapshot and `backup import` applies a snapshot
//! file through the config reload path, so no new server behaviour was
//! needed. Destructive commands (every `delete`, `config history
//! --restore`, `licence install`, `backup import`) require `--yes` or an
//! interactive confirm. Secrets stay references end to end: no command
//! prints, logs or exports a secret value (the server redacts `file:` /
//! `env:` references and the CLI never logs request bodies).

use clap::{Args, Parser, Subcommand};
use std::fmt;
use std::time::Duration;

/// Success.
const EXIT_OK: i32 = 0;
/// Unreachable host, refused port, timeout, TLS failure, or an
/// unparseable response body.
const EXIT_CONNECTION: i32 = 1;
/// HTTP 401/403: refused key or insufficient role.
const EXIT_AUTH: i32 = 2;
/// HTTP 404: unknown client, topic, or route.
const EXIT_NOT_FOUND: i32 = 3;
/// Bad arguments, missing key, malformed endpoint, or HTTP 400/409/422.
const EXIT_VALIDATION: i32 = 4;
/// HTTP 5xx or any other unexpected status.
const EXIT_SERVER: i32 = 5;

/// Default management endpoint: loopback API port the kernel binds by
/// default. Explicit `--endpoint` overrides it; loopback keeps test and
/// single-node setups working with no flags.
const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:18083";

/// Default request timeout in seconds. Reason: the management plane
/// answers loopback calls in milliseconds, so 10 s fails fast on
/// unreachable hosts without hanging scripts.
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Timeout clamp `1..=300`. Reason: below 1 s loopback TLS handshakes
/// flake; above 300 s a hung call outlives every operator script that
/// invokes it.
const MAX_TIMEOUT_SECS: u64 = 300;

/// Default list page: the first page, matching the server default.
const DEFAULT_PAGE: u32 = 1;
/// Default list limit: 100 rows, matching the server default page size.
const DEFAULT_LIMIT: u32 = 100;
/// Upper limit clamp: 1000 rows, matching the server-side clamp (larger
/// values are clamped, never rejected, on both sides).
const MAX_LIMIT: u32 = 1000;

/// Environment variable seeding the API key when no flag or file gives one.
const API_KEY_ENV: &str = "INDRA_API_KEY";

/// An API key that redacts itself from `Debug` and `Display` so the key
/// can never leak through a log line, a panic message, or an error that
/// formats its context.
#[derive(Clone)]
struct SecretString(String);

impl SecretString {
    fn new(secret: String) -> Self {
        Self(secret)
    }

    fn expose(&self) -> &str {
        &self.0
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([redacted])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Operator CLI entry point: `indra ctl ...`.
#[derive(Parser, Debug)]
#[command(
    name = "indra",
    version,
    about = "IndraMQTT operator CLI",
    after_help = "API key guidance: prefer INDRA_API_KEY or --api-key-file. A value passed with --api-key stays in shell history."
)]
struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand, Debug)]
enum TopCommand {
    /// Operator control surface (session and messaging in M1-06).
    Ctl(CtlArgs),
}

/// Connection options shared by every `ctl` command.
#[derive(Args, Debug)]
struct CtlArgs {
    /// Management API base URL (http for loopback, https for TLS endpoints).
    #[arg(long, default_value = DEFAULT_ENDPOINT)]
    endpoint: String,

    /// Operator API key. Prefer the environment or --api-key-file: a value
    /// passed here stays in shell history.
    #[arg(long)]
    api_key: Option<String>,

    /// File holding the operator API key (first line, trimmed). Used when
    /// --api-key is absent.
    #[arg(long)]
    api_key_file: Option<String>,

    /// Emit the management API response body as JSON for scripts.
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Per-request timeout in seconds (clamped 1..=300).
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,

    #[command(subcommand)]
    command: CtlCommand,
}

#[derive(Subcommand, Debug)]
enum CtlCommand {
    /// Show node status (reports whether the running node is up).
    Status,
    /// Client sessions: list, show, kick.
    Clients {
        #[command(subcommand)]
        command: ClientsCommand,
    },
    /// Global subscription list.
    Subscriptions {
        /// 1-based page number.
        #[arg(long, default_value_t = DEFAULT_PAGE)]
        page: u32,
        /// Rows per page (clamped 1..=1000).
        #[arg(long, default_value_t = DEFAULT_LIMIT)]
        limit: u32,
    },
    /// Known publish topics.
    Topics {
        /// 1-based page number.
        #[arg(long, default_value_t = DEFAULT_PAGE)]
        page: u32,
        /// Rows per page (clamped 1..=1000).
        #[arg(long, default_value_t = DEFAULT_LIMIT)]
        limit: u32,
    },
    /// Publish one message through the broker.
    Publish {
        /// Concrete topic to publish to.
        #[arg(long)]
        topic: String,
        /// Message payload (plain text, default empty).
        #[arg(long, default_value = "")]
        payload: String,
        /// QoS 0, 1 or 2 (default 0).
        #[arg(long, default_value_t = 0)]
        qos: u8,
        /// Retain the message.
        #[arg(long, default_value_t = false)]
        retain: bool,
    },
    /// Configured network listeners.
    Listeners,
    /// Routing rules: list, show, create, delete.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Data connectors: list, show, create, delete.
    Connectors {
        #[command(subcommand)]
        command: ConnectorsCommand,
    },
    /// Authentication users: list, show, create, delete.
    Users {
        #[command(subcommand)]
        command: UsersCommand,
    },
    /// Configuration: validate, diff, explain, reload, history.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Licence: current state (bare), request, install.
    Licence {
        #[command(subcommand)]
        command: Option<LicenceCommand>,
    },
    /// Backup: export a versioned config snapshot, import one back.
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
}

#[derive(Subcommand, Debug)]
enum ClientsCommand {
    /// List connected clients.
    List {
        /// 1-based page number.
        #[arg(long, default_value_t = DEFAULT_PAGE)]
        page: u32,
        /// Rows per page (clamped 1..=1000).
        #[arg(long, default_value_t = DEFAULT_LIMIT)]
        limit: u32,
    },
    /// Show one client session.
    Show {
        /// Client id.
        client_id: String,
    },
    /// Disconnect one client through the kernel-to-edge close path.
    Kick {
        /// Client id.
        client_id: String,
    },
}

/// Rule governance: every verb maps 1:1 onto `/api/v1/rules`.
#[derive(Subcommand, Debug)]
enum RulesCommand {
    /// List routing rules.
    List,
    /// Show one rule.
    Show {
        /// Rule id.
        id: String,
    },
    /// Create one rule. Actions come from `--actions` (a JSON array in the
    /// management API shape) or, exclusively, from the `--log`,
    /// `--forward` and `--republish` conveniences, which are appended in
    /// the order log, forwards, republishes.
    Create {
        /// Rule name (free-form).
        #[arg(long)]
        name: String,
        /// MQTT topic filter the rule matches.
        #[arg(long)]
        topic_filter: String,
        /// Optional streaming-SQL program (absent matches without SQL).
        #[arg(long)]
        sql: Option<String>,
        /// Create the rule disabled (enabled by default).
        #[arg(long, default_value_t = false)]
        disable: bool,
        /// JSON action array, e.g. '[{"type":"log"}]'.
        #[arg(long)]
        actions: Option<String>,
        /// Append a log action.
        #[arg(long, default_value_t = false)]
        log: bool,
        /// Append a forward-to-connector action (repeatable, one id each).
        #[arg(long)]
        forward: Vec<String>,
        /// Append a republish action as TOPIC:QOS (repeatable).
        #[arg(long)]
        republish: Vec<String>,
    },
    /// Delete one rule. Destructive: requires `--yes` or an interactive
    /// confirm.
    Delete {
        /// Rule id.
        id: String,
        /// Confirm without prompting. Required when stdin is not a terminal.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

/// Connector governance: every verb maps 1:1 onto `/api/v5/connectors`
/// (the persisted connector directory; reads redact secret references).
#[derive(Subcommand, Debug)]
enum ConnectorsCommand {
    /// List connectors.
    List,
    /// Show one connector.
    Show {
        /// Connector id.
        id: String,
    },
    /// Create one connector. Extra family fields come from `--params` (a
    /// JSON object) or `--params-file`; both are sent verbatim and the
    /// server validates them, naming the missing field.
    Create {
        /// Connector id.
        #[arg(long)]
        id: String,
        /// Connector type (e.g. `console`, `webhook`); `--kind` is an alias.
        #[arg(long, alias = "kind")]
        r#type: String,
        /// Extra family fields as a JSON object (default `{}`).
        #[arg(long)]
        params: Option<String>,
        /// File holding the extra family fields as JSON.
        #[arg(long)]
        params_file: Option<String>,
        /// Create the connector disabled (enabled by default).
        #[arg(long, default_value_t = false)]
        disable: bool,
    },
    /// Delete one connector. Destructive: requires `--yes` or an
    /// interactive confirm. The server answers success even for an unknown
    /// id, so the command is idempotent.
    Delete {
        /// Connector id.
        id: String,
        /// Confirm without prompting. Required when stdin is not a terminal.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

/// Authentication user governance: every verb maps 1:1 onto
/// `/api/v1/auth/users` (passwords are write-only and never listed).
#[derive(Subcommand, Debug)]
enum UsersCommand {
    /// List authentication users.
    List,
    /// Show one user.
    Show {
        /// Username.
        username: String,
    },
    /// Create one user. Prefer `--password-file`: a value passed with
    /// `--password` stays in shell history.
    Create {
        /// Username.
        #[arg(long)]
        username: String,
        /// Password (write-only; prefer the file form).
        #[arg(long)]
        password: Option<String>,
        /// File holding the password (first line, trimmed).
        #[arg(long)]
        password_file: Option<String>,
        /// Maximum concurrent connections (absent means unlimited).
        #[arg(long)]
        max_connections: Option<u32>,
        /// Maximum sustained publishes per second (absent means unlimited).
        #[arg(long)]
        max_publish_rate: Option<u32>,
        /// Burst allowance for the publish rate limiter.
        #[arg(long)]
        max_publish_burst: Option<u32>,
    },
    /// Delete one user. Destructive: requires `--yes` or an interactive
    /// confirm.
    Delete {
        /// Username.
        username: String,
        /// Confirm without prompting. Required when stdin is not a terminal.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

/// Configuration governance: every verb maps 1:1 onto `/api/v1/config/*`.
/// Snapshot documents are read from `--file` as JSON or TOML (tried in
/// that order) holding the full configuration (all roots).
#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Validate a snapshot document without changing any state.
    Validate {
        /// Snapshot document (JSON or TOML).
        #[arg(long)]
        file: String,
    },
    /// Show the diff a snapshot document would apply, without applying it.
    Diff {
        /// Snapshot document (JSON or TOML).
        #[arg(long)]
        file: String,
    },
    /// Preview the server diff, then apply the snapshot document and
    /// report the recorded version.
    Reload {
        /// Snapshot document (JSON or TOML).
        #[arg(long)]
        file: String,
        /// Who applies the change (recorded in the version history).
        #[arg(long, default_value = "ctl")]
        actor: String,
        /// Short human summary stored with the version.
        #[arg(long)]
        summary: Option<String>,
    },
    /// Explain one setting: its effective value and which layer set it.
    Explain {
        /// Setting key (schema key like `session.max_qos0_backlog`, or
        /// registry key like `mqtt_users.users.alice`).
        #[arg(long)]
        key: String,
    },
    /// List versions (no id), show one version (id), or restore one
    /// version (`--restore`; destructive: requires `--yes` or an
    /// interactive confirm).
    History {
        /// Version id (absent lists versions newest-first).
        id: Option<u64>,
        /// Restore this version through the same validate-whole path as a
        /// reload. Requires `id`.
        #[arg(long, default_value_t = false)]
        restore: bool,
        /// Confirm a restore without prompting. Required when stdin is not
        /// a terminal.
        #[arg(long, default_value_t = false)]
        yes: bool,
        /// Who applies the restore (recorded in the version history).
        #[arg(long, default_value = "ctl")]
        actor: String,
    },
}

/// Licence governance: every verb maps 1:1 onto `/api/v1/licence/*`. A
/// bare `licence` shows the current state.
#[derive(Subcommand, Debug)]
enum LicenceCommand {
    /// Show the current licence state (same as a bare `licence`).
    Status,
    /// Show the installation licence request (safe to send to sales).
    Request,
    /// Verify and atomically store the licence token. Overwrites the
    /// stored licence: requires `--yes` or an interactive confirm. A
    /// failed install leaves any previous licence in place.
    Install {
        /// The licence token text.
        #[arg(long)]
        token: Option<String>,
        /// File holding the licence token (whole file, trimmed).
        #[arg(long)]
        token_file: Option<String>,
        /// Confirm without prompting. Required when stdin is not a terminal.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

/// Backup governance through the versioned config snapshot: `export`
/// reads the latest recorded version, `import` applies a snapshot file
/// through the config reload path. No new server behaviour; both ends are
/// existing management API calls.
#[derive(Subcommand, Debug)]
enum BackupCommand {
    /// Export the latest versioned snapshot to a file (secret references
    /// stay redacted markers; secret values never appear).
    Export {
        /// Destination file.
        #[arg(long)]
        file: String,
        /// Output format: `toml` (default, matches the on-disk snapshot)
        /// or `json`.
        #[arg(long, default_value = "toml")]
        format: String,
    },
    /// Import a snapshot file through the config reload path. Destructive
    /// on the target node: requires `--yes` or an interactive confirm.
    Import {
        /// Snapshot file (JSON or TOML, tried in that order).
        #[arg(long)]
        file: String,
        /// Confirm without prompting. Required when stdin is not a terminal.
        #[arg(long, default_value_t = false)]
        yes: bool,
        /// Who applies the change (recorded in the version history).
        #[arg(long, default_value = "ctl")]
        actor: String,
    },
}

/// One failed `ctl` invocation: an exit code plus a stderr line that never
/// contains the API key.
#[derive(Debug)]
struct CtlError {
    code: i32,
    message: String,
}

impl CtlError {
    fn connection(detail: impl Into<String>) -> Self {
        Self {
            code: EXIT_CONNECTION,
            message: format!("error: connection failed: {}", detail.into()),
        }
    }

    fn auth(detail: impl Into<String>) -> Self {
        Self {
            code: EXIT_AUTH,
            message: format!("error: authentication failed: {}", detail.into()),
        }
    }

    fn not_found(detail: impl Into<String>) -> Self {
        Self {
            code: EXIT_NOT_FOUND,
            message: format!("error: not found: {}", detail.into()),
        }
    }

    fn validation(detail: impl Into<String>) -> Self {
        Self {
            code: EXIT_VALIDATION,
            message: format!("error: invalid request: {}", detail.into()),
        }
    }

    fn server(detail: impl Into<String>) -> Self {
        Self {
            code: EXIT_SERVER,
            message: format!("error: server failure: {}", detail.into()),
        }
    }
}

/// Resolve the API key: `--api-key`, then the first line of
/// `--api-key-file`, then `INDRA_API_KEY`. A missing key fails closed
/// before any request is sent.
fn resolve_api_key(args: &CtlArgs) -> Result<SecretString, CtlError> {
    if let Some(key) = args.api_key.as_deref().map(str::trim) {
        if !key.is_empty() {
            return Ok(SecretString::new(key.to_string()));
        }
    }
    if let Some(path) = args.api_key_file.as_deref() {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CtlError::validation(format!("cannot read key file: {e}")))?;
        let key = text.lines().next().unwrap_or("").trim();
        if !key.is_empty() {
            return Ok(SecretString::new(key.to_string()));
        }
    }
    match std::env::var(API_KEY_ENV).map(|v| v.trim().to_string()) {
        Ok(key) if !key.is_empty() => Ok(SecretString::new(key)),
        _ => Err(CtlError::validation(
            "missing API key: pass --api-key, --api-key-file, or set INDRA_API_KEY",
        )),
    }
}

/// Clamp a list page to `>= 1`, mirroring the server (never rejected).
fn clamp_page(page: u32) -> u32 {
    page.max(1)
}

/// Clamp a list limit to `1..=1000`, mirroring the server-side clamp.
fn clamp_limit(limit: u32) -> u32 {
    limit.clamp(1, MAX_LIMIT)
}

/// Clamp the request timeout to `1..=300` seconds.
fn clamp_timeout(timeout: u64) -> u64 {
    timeout.clamp(1, MAX_TIMEOUT_SECS)
}

/// One management API round-trip.
///
/// `body` is serialised as JSON for methods that carry one. Returns the
/// status plus the parsed body (`204 No Content` yields `Null`). Error
/// statuses map onto the documented exit codes; the API key is never part
/// of any error string.
async fn request(
    ctl: &CtlArgs,
    key: &SecretString,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<(reqwest::StatusCode, serde_json::Value), CtlError> {
    if key.is_empty() {
        return Err(CtlError::validation("missing API key"));
    }
    let base = ctl.endpoint.trim_end_matches('/');
    let url = format!("{base}{path}");
    let parsed = reqwest::Url::parse(&url)
        .map_err(|e| CtlError::validation(format!("malformed endpoint URL: {e}")))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(clamp_timeout(ctl.timeout)))
        .build()
        .map_err(|e| CtlError::connection(format!("cannot build HTTP client: {e}")))?;
    let mut call = client
        .request(method, parsed)
        .header("Authorization", format!("Bearer {}", key.expose()));
    if let Some(body) = body {
        call = call.json(&body);
    }
    let response = call
        .send()
        .await
        .map_err(|e| CtlError::connection(format!("{e}")))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| CtlError::connection(format!("cannot read response body: {e}")))?;
    let value: serde_json::Value = if text.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&text)
            .map_err(|e| CtlError::connection(format!("response is not valid JSON: {e}")))?
    };
    map_status(status, &value)?;
    Ok((status, value))
}

/// Map an HTTP error status onto its exit code, extracting the server's
/// `{code, message}` shape where one is present, else the native
/// `/api/v1` `{"error"}` shape. The API key is never part of any string.
fn map_status(status: reqwest::StatusCode, body: &serde_json::Value) -> Result<(), CtlError> {
    if status.is_success() {
        return Ok(());
    }
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");
    // Native `/api/v1` errors carry `{"error": "..."}` instead of the
    // `/api/v5` `{code, message}` shape; surface that text verbatim so a
    // rejected setting (which the server already names) reaches stderr.
    let detail = body
        .get("message")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("error").and_then(|v| v.as_str()))
        .unwrap_or("");
    let shaped = if detail.is_empty() {
        format!("{code} (HTTP {})", status.as_u16())
    } else {
        format!("{code}: {detail} (HTTP {})", status.as_u16())
    };
    match status.as_u16() {
        401 | 403 => Err(CtlError::auth(shaped)),
        404 => Err(CtlError::not_found(shaped)),
        400 | 409 | 422 => Err(CtlError::validation(shaped)),
        _ if status.is_server_error() => Err(CtlError::server(shaped)),
        _ => Err(CtlError::server(shaped)),
    }
}

/// Render a human table: headers plus rows, columns padded to the widest
/// cell. Pure formatting over one bounded page; no I/O.
fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }
    let mut out = String::new();
    for (i, header) in headers.iter().enumerate() {
        if i > 0 {
            out.push_str("  ");
        }
        out.push_str(&format!("{:width$}", header, width = widths[i]));
    }
    out.push('\n');
    for row in rows {
        for (i, _header) in headers.iter().enumerate() {
            if i > 0 {
                out.push_str("  ");
            }
            let cell = row.get(i).map(String::as_str).unwrap_or("");
            out.push_str(&format!("{:width$}", cell, width = widths[i]));
        }
        out.push('\n');
    }
    out
}

/// Short scalar rendering for human tables: strings verbatim, numbers and
/// booleans as-is, anything else compact JSON. Missing values render as
/// `-` (the broker omits what it does not track; tables never invent it).
fn cell(value: Option<&serde_json::Value>) -> String {
    match value {
        None => "-".to_string(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Null) => "-".to_string(),
        Some(other) => other.to_string(),
    }
}

/// Pretty JSON for `--json`: the management API response body verbatim.
fn render_json(value: &serde_json::Value) -> String {
    format!("{value:#}\n")
}

/// Confirm a destructive action: `--yes` proceeds silently, otherwise an
/// interactive terminal is asked (`y`/`yes` proceeds, anything else
/// cancels) and a non-interactive stdin fails closed demanding `--yes`.
/// The prompt never contains secret material: callers pass ids only.
fn confirm_destructive(yes: bool, prompt: &str) -> Result<(), CtlError> {
    if yes {
        return Ok(());
    }
    use std::io::{IsTerminal, Write as _};
    if !std::io::stdin().is_terminal() {
        return Err(CtlError::validation(
            "refusing a destructive action without --yes (stdin is not interactive)",
        ));
    }
    eprint!("{prompt} [y/N]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(_) => {
            let answer = line.trim().to_ascii_lowercase();
            if answer == "y" || answer == "yes" {
                Ok(())
            } else {
                Err(CtlError::validation("cancelled"))
            }
        }
        Err(e) => Err(CtlError::validation(format!("cannot read confirm: {e}"))),
    }
}

/// Read a secret from `--flag` or `--flag-file`. Passwords (`single_line`)
/// take the first line trimmed, so inner spaces survive; licence tokens
/// arrive as one pasted blob (possibly wrapped over lines), so all
/// whitespace is stripped. `what` names the secret (`password`, `licence
/// token`); the value never appears in any error string.
fn read_secret_arg(
    value: Option<&str>,
    file: Option<&str>,
    what: &str,
    flag_spelling: &str,
    single_line: bool,
) -> Result<String, CtlError> {
    if let Some(text) = value.map(str::trim) {
        if !text.is_empty() {
            return Ok(text.to_string());
        }
    }
    if let Some(path) = file {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CtlError::validation(format!("cannot read {what} file: {e}")))?;
        let secret: String = if single_line {
            text.lines().next().unwrap_or("").trim().to_string()
        } else {
            text.split_whitespace().collect()
        };
        if !secret.is_empty() {
            return Ok(secret);
        }
    }
    Err(CtlError::validation(format!(
        "missing {what}: pass {flag_spelling} or its --file form"
    )))
}

/// Load a full-configuration snapshot document: JSON first, then TOML.
/// A structural failure names the file; semantic failures (an empty rule
/// id, an unknown connector type) are reported by the server, which names
/// the setting.
fn load_snapshot_file(path: &str) -> Result<broker_config::FullSnapshot, CtlError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CtlError::validation(format!("cannot read snapshot file {path:?}: {e}")))?;
    if let Ok(snapshot) = serde_json::from_str::<broker_config::FullSnapshot>(&text) {
        return Ok(snapshot);
    }
    toml::from_str::<broker_config::FullSnapshot>(&text).map_err(|e| {
        CtlError::validation(format!(
            "cannot parse snapshot file {path:?} as JSON or TOML: {e}"
        ))
    })
}

/// Percent-encode one query value (the `explain` key): letters, digits
/// and `-_.~` pass through, everything else is `%HH`. Keys are dotted
/// paths, so this is almost a no-op, but a registry name with a space or
/// `&` must not split the query.
fn encode_query_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// One-line human summary of a rule action object from the API wire form.
fn describe_action(action: &serde_json::Value) -> String {
    let kind = action.get("type").and_then(|v| v.as_str()).unwrap_or("?");
    match kind {
        "log" => "log".to_string(),
        "republish" => format!(
            "republish:{}",
            action.get("topic").and_then(|v| v.as_str()).unwrap_or("?")
        ),
        "forwardconnector" => format!(
            "forward:{}",
            action
                .get("connector_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
        ),
        other => other.to_string(),
    }
}

async fn cmd_status(ctl: &CtlArgs, key: &SecretString) -> Result<String, CtlError> {
    let (_, body) = request(ctl, key, reqwest::Method::GET, "/api/v5/status", None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    Ok(format!("status: {}\n", cell(body.get("status"))))
}

async fn cmd_clients_list(
    ctl: &CtlArgs,
    key: &SecretString,
    page: u32,
    limit: u32,
) -> Result<String, CtlError> {
    let path = format!(
        "/api/v5/clients?page={}&limit={}",
        clamp_page(page),
        clamp_limit(limit)
    );
    let (_, body) = request(ctl, key, reqwest::Method::GET, &path, None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let data = body
        .get("data")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let rows: Vec<Vec<String>> = data
        .iter()
        .map(|row| {
            vec![
                cell(row.get("clientid")),
                cell(row.get("username")),
                cell(row.get("connected")),
                cell(row.get("keepalive")),
            ]
        })
        .collect();
    Ok(render_table(
        &["CLIENTID", "USERNAME", "CONNECTED", "KEEPALIVE"],
        &rows,
    ))
}

async fn cmd_clients_show(
    ctl: &CtlArgs,
    key: &SecretString,
    client_id: &str,
) -> Result<String, CtlError> {
    if client_id.trim().is_empty() {
        return Err(CtlError::validation("client id must not be empty"));
    }
    let path = format!("/api/v5/clients/{client_id}");
    let (_, body) = request(ctl, key, reqwest::Method::GET, &path, None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let object = body.as_object().cloned().unwrap_or_default();
    let mut out = String::new();
    for (name, value) in &object {
        out.push_str(&format!("{name}: {}\n", cell(Some(value))));
    }
    Ok(out)
}

async fn cmd_clients_kick(
    ctl: &CtlArgs,
    key: &SecretString,
    client_id: &str,
) -> Result<String, CtlError> {
    if client_id.trim().is_empty() {
        return Err(CtlError::validation("client id must not be empty"));
    }
    let path = format!("/api/v5/clients/{client_id}");
    request(ctl, key, reqwest::Method::DELETE, &path, None).await?;
    if ctl.json {
        let body = serde_json::json!({"clientid": client_id, "result": "kicked"});
        return Ok(render_json(&body));
    }
    Ok(format!("kicked {client_id}\n"))
}

async fn cmd_subscriptions(
    ctl: &CtlArgs,
    key: &SecretString,
    page: u32,
    limit: u32,
) -> Result<String, CtlError> {
    let path = format!(
        "/api/v5/subscriptions?page={}&limit={}",
        clamp_page(page),
        clamp_limit(limit)
    );
    let (_, body) = request(ctl, key, reqwest::Method::GET, &path, None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    // The global subscription list is a bare array (no data/meta envelope).
    let data = body.as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = data
        .iter()
        .map(|row| {
            vec![
                cell(row.get("clientid")),
                cell(row.get("topic")),
                cell(row.get("qos")),
            ]
        })
        .collect();
    Ok(render_table(&["CLIENTID", "TOPIC", "QOS"], &rows))
}

async fn cmd_topics(
    ctl: &CtlArgs,
    key: &SecretString,
    page: u32,
    limit: u32,
) -> Result<String, CtlError> {
    let path = format!(
        "/api/v5/topics?page={}&limit={}",
        clamp_page(page),
        clamp_limit(limit)
    );
    let (_, body) = request(ctl, key, reqwest::Method::GET, &path, None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let data = body
        .get("data")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let rows: Vec<Vec<String>> = data
        .iter()
        .map(|row| vec![cell(row.get("topic"))])
        .collect();
    Ok(render_table(&["TOPIC"], &rows))
}

async fn cmd_publish(
    ctl: &CtlArgs,
    key: &SecretString,
    topic: &str,
    payload: &str,
    qos: u8,
    retain: bool,
) -> Result<String, CtlError> {
    if topic.trim().is_empty() {
        return Err(CtlError::validation("topic must not be empty"));
    }
    if qos > 2 {
        return Err(CtlError::validation("qos must be 0, 1 or 2"));
    }
    let body = serde_json::json!({
        "topic": topic,
        "payload": payload,
        "payload_encoding": "plain",
        "qos": qos,
        "retain": retain,
    });
    let (_, response) = request(
        ctl,
        key,
        reqwest::Method::POST,
        "/api/v5/publish",
        Some(body),
    )
    .await?;
    if ctl.json {
        return Ok(render_json(&response));
    }
    Ok(format!("published {}\n", cell(response.get("id"))))
}

async fn cmd_listeners(ctl: &CtlArgs, key: &SecretString) -> Result<String, CtlError> {
    let (_, body) = request(ctl, key, reqwest::Method::GET, "/api/v5/listeners", None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let data = body.as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = data
        .iter()
        .map(|row| {
            vec![
                cell(row.get("id")),
                cell(row.get("protocol")),
                cell(row.get("bind")),
                cell(row.get("enabled")),
            ]
        })
        .collect();
    Ok(render_table(&["ID", "PROTOCOL", "BIND", "ENABLED"], &rows))
}

async fn cmd_rules_list(ctl: &CtlArgs, key: &SecretString) -> Result<String, CtlError> {
    let (_, body) = request(ctl, key, reqwest::Method::GET, "/api/v1/rules", None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let data = body.as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = data
        .iter()
        .map(|row| {
            let actions = row
                .get("actions")
                .and_then(|v| v.as_array())
                .map(|list| {
                    list.iter()
                        .map(describe_action)
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            vec![
                cell(row.get("id")),
                cell(row.get("name")),
                cell(row.get("topic_filter")),
                cell(row.get("enabled")),
                actions,
            ]
        })
        .collect();
    Ok(render_table(
        &["ID", "NAME", "FILTER", "ENABLED", "ACTIONS"],
        &rows,
    ))
}

async fn cmd_rules_show(ctl: &CtlArgs, key: &SecretString, id: &str) -> Result<String, CtlError> {
    if id.trim().is_empty() {
        return Err(CtlError::validation("rule id must not be empty"));
    }
    let path = format!("/api/v1/rules/{id}");
    let (_, body) = request(ctl, key, reqwest::Method::GET, &path, None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let object = body.as_object().cloned().unwrap_or_default();
    let mut out = String::new();
    for (name, value) in &object {
        if name == "actions" {
            let summary = value
                .as_array()
                .map(|list| {
                    list.iter()
                        .map(describe_action)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| cell(Some(value)));
            out.push_str(&format!("{name}: {summary}\n"));
        } else {
            out.push_str(&format!("{name}: {}\n", cell(Some(value))));
        }
    }
    Ok(out)
}

/// Parse one `--republish TOPIC:QOS` convenience into its API action form.
fn parse_republish_action(raw: &str) -> Result<serde_json::Value, CtlError> {
    let (topic, qos) = raw
        .rsplit_once(':')
        .ok_or_else(|| CtlError::validation("republish must be TOPIC:QOS, e.g. out/events:1"))?;
    if topic.trim().is_empty() {
        return Err(CtlError::validation("republish topic must not be empty"));
    }
    let qos: u8 = qos
        .trim()
        .parse()
        .map_err(|_| CtlError::validation("republish qos must be 0, 1 or 2"))?;
    if qos > 2 {
        return Err(CtlError::validation("republish qos must be 0, 1 or 2"));
    }
    Ok(serde_json::json!({"type": "republish", "topic": topic, "qos": qos}))
}

#[allow(clippy::too_many_arguments)]
async fn cmd_rules_create(
    ctl: &CtlArgs,
    key: &SecretString,
    name: &str,
    topic_filter: &str,
    sql: Option<&str>,
    disable: bool,
    actions_json: Option<&str>,
    log: bool,
    forwards: &[String],
    republishes: &[String],
) -> Result<String, CtlError> {
    if name.trim().is_empty() {
        return Err(CtlError::validation("rule name must not be empty"));
    }
    if topic_filter.trim().is_empty() {
        return Err(CtlError::validation("topic filter must not be empty"));
    }
    let actions = if let Some(raw) = actions_json {
        let parsed: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
            CtlError::validation(format!("cannot parse --actions as a JSON array: {e}"))
        })?;
        if !parsed.is_array() {
            return Err(CtlError::validation("--actions must be a JSON array"));
        }
        if log || !forwards.is_empty() || !republishes.is_empty() {
            return Err(CtlError::validation(
                "--actions cannot be combined with --log, --forward or --republish",
            ));
        }
        parsed
    } else {
        let mut list = Vec::new();
        if log {
            list.push(serde_json::json!({"type": "log"}));
        }
        for id in forwards {
            if id.trim().is_empty() {
                return Err(CtlError::validation(
                    "forward connector id must not be empty",
                ));
            }
            list.push(serde_json::json!({"type": "forwardconnector", "connector_id": id}));
        }
        for raw in republishes {
            list.push(parse_republish_action(raw)?);
        }
        serde_json::Value::Array(list)
    };
    let body = serde_json::json!({
        "name": name,
        "topic_filter": topic_filter,
        "sql_query": sql,
        "enabled": !disable,
        "actions": actions,
    });
    let (_, response) =
        request(ctl, key, reqwest::Method::POST, "/api/v1/rules", Some(body)).await?;
    if ctl.json {
        return Ok(render_json(&response));
    }
    Ok(format!("created {}\n", cell(response.get("id"))))
}

async fn cmd_rules_delete(
    ctl: &CtlArgs,
    key: &SecretString,
    id: &str,
    yes: bool,
) -> Result<String, CtlError> {
    if id.trim().is_empty() {
        return Err(CtlError::validation("rule id must not be empty"));
    }
    confirm_destructive(yes, &format!("Delete rule {id:?}?"))?;
    let path = format!("/api/v1/rules/{id}");
    request(ctl, key, reqwest::Method::DELETE, &path, None).await?;
    if ctl.json {
        let body = serde_json::json!({"id": id, "result": "deleted"});
        return Ok(render_json(&body));
    }
    Ok(format!("deleted {id}\n"))
}

async fn cmd_connectors_list(ctl: &CtlArgs, key: &SecretString) -> Result<String, CtlError> {
    let (_, body) = request(ctl, key, reqwest::Method::GET, "/api/v5/connectors", None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let data = body.as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = data
        .iter()
        .map(|row| {
            vec![
                cell(row.get("id")),
                cell(row.get("type")),
                cell(row.get("status")),
                cell(row.get("enable")),
            ]
        })
        .collect();
    Ok(render_table(&["ID", "TYPE", "STATUS", "ENABLED"], &rows))
}

async fn cmd_connectors_show(
    ctl: &CtlArgs,
    key: &SecretString,
    id: &str,
) -> Result<String, CtlError> {
    if id.trim().is_empty() {
        return Err(CtlError::validation("connector id must not be empty"));
    }
    let path = format!("/api/v5/connectors/{id}");
    let (_, body) = request(ctl, key, reqwest::Method::GET, &path, None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let object = body.as_object().cloned().unwrap_or_default();
    let mut out = String::new();
    for (name, value) in &object {
        out.push_str(&format!("{name}: {}\n", cell(Some(value))));
    }
    Ok(out)
}

async fn cmd_connectors_create(
    ctl: &CtlArgs,
    key: &SecretString,
    id: &str,
    kind: &str,
    params_json: Option<&str>,
    params_file: Option<&str>,
    disable: bool,
) -> Result<String, CtlError> {
    if id.trim().is_empty() {
        return Err(CtlError::validation("connector id must not be empty"));
    }
    if kind.trim().is_empty() {
        return Err(CtlError::validation("connector type must not be empty"));
    }
    if params_json.is_some() && params_file.is_some() {
        return Err(CtlError::validation(
            "--params cannot be combined with --params-file",
        ));
    }
    let mut params = if let Some(path) = params_file {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CtlError::validation(format!("cannot read params file: {e}")))?;
        serde_json::from_str::<serde_json::Value>(&text)
            .map_err(|e| CtlError::validation(format!("cannot parse params file as JSON: {e}")))?
    } else if let Some(raw) = params_json {
        serde_json::from_str::<serde_json::Value>(raw)
            .map_err(|e| CtlError::validation(format!("cannot parse --params as JSON: {e}")))?
    } else {
        serde_json::json!({})
    };
    if !params.is_object() {
        return Err(CtlError::validation("--params must be a JSON object"));
    }
    // The params object is sent verbatim (plus identity keys): secret
    // references inside it stay references, and the server validates the
    // family fields, naming the missing one.
    if let Some(obj) = params.as_object_mut() {
        obj.insert(
            "name".to_string(),
            serde_json::Value::String(id.to_string()),
        );
        obj.insert("id".to_string(), serde_json::Value::String(id.to_string()));
        obj.insert(
            "type".to_string(),
            serde_json::Value::String(kind.to_string()),
        );
        obj.insert("enable".to_string(), serde_json::Value::Bool(!disable));
    }
    let (_, response) = request(
        ctl,
        key,
        reqwest::Method::POST,
        "/api/v5/connectors",
        Some(params),
    )
    .await?;
    if ctl.json {
        return Ok(render_json(&response));
    }
    Ok(format!(
        "created {} ({})\n",
        cell(response.get("id")),
        cell(response.get("type"))
    ))
}

async fn cmd_connectors_delete(
    ctl: &CtlArgs,
    key: &SecretString,
    id: &str,
    yes: bool,
) -> Result<String, CtlError> {
    if id.trim().is_empty() {
        return Err(CtlError::validation("connector id must not be empty"));
    }
    confirm_destructive(yes, &format!("Delete connector {id:?}?"))?;
    let path = format!("/api/v5/connectors/{id}");
    request(ctl, key, reqwest::Method::DELETE, &path, None).await?;
    if ctl.json {
        let body = serde_json::json!({"id": id, "result": "deleted"});
        return Ok(render_json(&body));
    }
    Ok(format!("deleted {id}\n"))
}

async fn cmd_users_list(ctl: &CtlArgs, key: &SecretString) -> Result<String, CtlError> {
    let (_, body) = request(ctl, key, reqwest::Method::GET, "/api/v1/auth/users", None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let data = body.as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = data
        .iter()
        .map(|row| vec![cell(row.get("username")), cell(row.get("quotas"))])
        .collect();
    Ok(render_table(&["USERNAME", "QUOTAS"], &rows))
}

async fn cmd_users_show(
    ctl: &CtlArgs,
    key: &SecretString,
    username: &str,
) -> Result<String, CtlError> {
    if username.trim().is_empty() {
        return Err(CtlError::validation("username must not be empty"));
    }
    let (_, body) = request(ctl, key, reqwest::Method::GET, "/api/v1/auth/users", None).await?;
    let found = body
        .as_array()
        .and_then(|list| {
            list.iter()
                .find(|row| row.get("username").and_then(|v| v.as_str()) == Some(username))
        })
        .cloned();
    match found {
        Some(row) => {
            if ctl.json {
                return Ok(render_json(&row));
            }
            let object = row.as_object().cloned().unwrap_or_default();
            let mut out = String::new();
            for (name, value) in &object {
                out.push_str(&format!("{name}: {}\n", cell(Some(value))));
            }
            Ok(out)
        }
        None => Err(CtlError::not_found(format!("user not found: {username}"))),
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_users_create(
    ctl: &CtlArgs,
    key: &SecretString,
    username: &str,
    password: Option<&str>,
    password_file: Option<&str>,
    max_connections: Option<u32>,
    max_publish_rate: Option<u32>,
    max_publish_burst: Option<u32>,
) -> Result<String, CtlError> {
    if username.trim().is_empty() {
        return Err(CtlError::validation("username must not be empty"));
    }
    // The password travels once in the creation body (write-only on the
    // server) and is never printed, logged or listed back.
    let secret = read_secret_arg(password, password_file, "password", "--password", true)?;
    if secret.is_empty() {
        return Err(CtlError::validation("password must not be empty"));
    }
    let quotas =
        if max_connections.is_some() || max_publish_rate.is_some() || max_publish_burst.is_some() {
            Some(serde_json::json!({
                "max_connections": max_connections,
                "max_publish_rate": max_publish_rate,
                "max_publish_burst": max_publish_burst,
            }))
        } else {
            None
        };
    let body = serde_json::json!({
        "username": username,
        "password": secret,
        "quotas": quotas,
    });
    let (_, response) = request(
        ctl,
        key,
        reqwest::Method::POST,
        "/api/v1/auth/users",
        Some(body),
    )
    .await?;
    if ctl.json {
        return Ok(render_json(&response));
    }
    Ok(format!("created {}\n", cell(response.get("username"))))
}

async fn cmd_users_delete(
    ctl: &CtlArgs,
    key: &SecretString,
    username: &str,
    yes: bool,
) -> Result<String, CtlError> {
    if username.trim().is_empty() {
        return Err(CtlError::validation("username must not be empty"));
    }
    confirm_destructive(yes, &format!("Delete user {username:?}?"))?;
    let path = format!("/api/v1/auth/users/{username}");
    request(ctl, key, reqwest::Method::DELETE, &path, None).await?;
    if ctl.json {
        let body = serde_json::json!({"username": username, "result": "deleted"});
        return Ok(render_json(&body));
    }
    Ok(format!("deleted {username}\n"))
}

async fn cmd_config_validate(
    ctl: &CtlArgs,
    key: &SecretString,
    file: &str,
) -> Result<String, CtlError> {
    let snapshot = load_snapshot_file(file)?;
    let body = serde_json::json!({
        "snapshot": serde_json::to_value(&snapshot).unwrap_or(serde_json::Value::Null),
    });
    let (_, response) = request(
        ctl,
        key,
        reqwest::Method::POST,
        "/api/v1/config/validate",
        Some(body),
    )
    .await?;
    if ctl.json {
        return Ok(render_json(&response));
    }
    Ok("valid\n".to_string())
}

async fn cmd_config_diff(
    ctl: &CtlArgs,
    key: &SecretString,
    file: &str,
) -> Result<String, CtlError> {
    let snapshot = load_snapshot_file(file)?;
    let body = serde_json::json!({
        "snapshot": serde_json::to_value(&snapshot).unwrap_or(serde_json::Value::Null),
    });
    let (_, response) = request(
        ctl,
        key,
        reqwest::Method::POST,
        "/api/v1/config/diff",
        Some(body),
    )
    .await?;
    if ctl.json {
        return Ok(render_json(&response));
    }
    let diff = response
        .get("diff")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if diff.is_empty() {
        return Ok("(no changes)\n".to_string());
    }
    let rows: Vec<Vec<String>> = diff
        .iter()
        .map(|row| {
            vec![
                cell(row.get("setting")),
                cell(row.get("old_value")),
                cell(row.get("new_value")),
            ]
        })
        .collect();
    Ok(render_table(&["SETTING", "OLD_VALUE", "NEW_VALUE"], &rows))
}

async fn cmd_config_reload(
    ctl: &CtlArgs,
    key: &SecretString,
    file: &str,
    actor: &str,
    summary: Option<&str>,
) -> Result<String, CtlError> {
    let snapshot = load_snapshot_file(file)?;
    let value = serde_json::to_value(&snapshot).unwrap_or(serde_json::Value::Null);
    // Preview first: the server diff is printed before anything applies.
    // A 400 here names every offending setting and nothing is applied.
    let preview = serde_json::json!({ "snapshot": value.clone() });
    let (_, preview_response) = request(
        ctl,
        key,
        reqwest::Method::POST,
        "/api/v1/config/diff",
        Some(preview),
    )
    .await?;
    let mut body = serde_json::json!({
        "snapshot": value,
        "actor": actor,
    });
    if let Some(summary) = summary {
        body["summary"] = serde_json::Value::String(summary.to_string());
    }
    let (_, response) = request(
        ctl,
        key,
        reqwest::Method::POST,
        "/api/v1/config/reload",
        Some(body),
    )
    .await?;
    if ctl.json {
        return Ok(render_json(&response));
    }
    let mut out = String::new();
    let diff = preview_response
        .get("diff")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if diff.is_empty() {
        out.push_str("(no changes)\n");
    } else {
        let rows: Vec<Vec<String>> = diff
            .iter()
            .map(|row| {
                vec![
                    cell(row.get("setting")),
                    cell(row.get("old_value")),
                    cell(row.get("new_value")),
                ]
            })
            .collect();
        out.push_str(&render_table(&["SETTING", "OLD_VALUE", "NEW_VALUE"], &rows));
    }
    out.push_str(&format!(
        "applied version {}\n",
        cell(response.get("version"))
    ));
    Ok(out)
}

async fn cmd_config_explain(
    ctl: &CtlArgs,
    key: &SecretString,
    setting: &str,
) -> Result<String, CtlError> {
    if setting.trim().is_empty() {
        return Err(CtlError::validation("setting key must not be empty"));
    }
    let path = format!("/api/v1/config/explain?key={}", encode_query_value(setting));
    let (_, body) = request(ctl, key, reqwest::Method::GET, &path, None).await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    Ok(format!(
        "{} = {}\nlayer: {}\nsource: {}\n",
        cell(body.get("key")),
        cell(body.get("value")),
        cell(body.get("layer")),
        cell(body.get("source")),
    ))
}

async fn cmd_config_history(
    ctl: &CtlArgs,
    key: &SecretString,
    id: Option<u64>,
    restore: bool,
    yes: bool,
    actor: &str,
) -> Result<String, CtlError> {
    if restore {
        let id = id.ok_or_else(|| CtlError::validation("restore requires a version id"))?;
        confirm_destructive(yes, &format!("Restore config version {id}?"))?;
        let path = format!("/api/v1/config/history/{id}/restore");
        let body = serde_json::json!({ "actor": actor });
        let (_, response) = request(ctl, key, reqwest::Method::POST, &path, Some(body)).await?;
        if ctl.json {
            return Ok(render_json(&response));
        }
        return Ok(format!(
            "restored version {id} as version {}\n",
            cell(response.get("version"))
        ));
    }
    if let Some(id) = id {
        let path = format!("/api/v1/config/history/{id}");
        let (_, body) = request(ctl, key, reqwest::Method::GET, &path, None).await?;
        if ctl.json {
            return Ok(render_json(&body));
        }
        let mut out = String::new();
        out.push_str(&format!("version: {}\n", cell(body.get("id"))));
        out.push_str(&format!("actor: {}\n", cell(body.get("actor"))));
        out.push_str(&format!("summary: {}\n", cell(body.get("summary"))));
        let changes = body
            .get("changes")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if changes.is_empty() {
            out.push_str("(no changes)\n");
        } else {
            let rows: Vec<Vec<String>> = changes
                .iter()
                .map(|row| {
                    vec![
                        cell(row.get("setting")),
                        cell(row.get("old_value")),
                        cell(row.get("new_value")),
                    ]
                })
                .collect();
            out.push_str(&render_table(&["SETTING", "OLD_VALUE", "NEW_VALUE"], &rows));
        }
        return Ok(out);
    }
    let (_, body) = request(
        ctl,
        key,
        reqwest::Method::GET,
        "/api/v1/config/history",
        None,
    )
    .await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let versions = body
        .get("versions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let rows: Vec<Vec<String>> = versions
        .iter()
        .map(|row| {
            vec![
                cell(row.get("id")),
                cell(row.get("actor")),
                cell(row.get("timestamp_secs")),
                cell(row.get("summary")),
            ]
        })
        .collect();
    Ok(render_table(
        &["ID", "ACTOR", "TIMESTAMP", "SUMMARY"],
        &rows,
    ))
}

async fn cmd_licence_status(ctl: &CtlArgs, key: &SecretString) -> Result<String, CtlError> {
    let (_, body) = request(
        ctl,
        key,
        reqwest::Method::GET,
        "/api/v1/licence/status",
        None,
    )
    .await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let object = body.as_object().cloned().unwrap_or_default();
    let mut out = String::new();
    for (name, value) in &object {
        out.push_str(&format!("{name}: {}\n", cell(Some(value))));
    }
    Ok(out)
}

async fn cmd_licence_request(ctl: &CtlArgs, key: &SecretString) -> Result<String, CtlError> {
    let (_, body) = request(
        ctl,
        key,
        reqwest::Method::GET,
        "/api/v1/licence/request",
        None,
    )
    .await?;
    if ctl.json {
        return Ok(render_json(&body));
    }
    let object = body.as_object().cloned().unwrap_or_default();
    let mut out = String::new();
    for (name, value) in &object {
        out.push_str(&format!("{name}: {}\n", cell(Some(value))));
    }
    Ok(out)
}

async fn cmd_licence_install(
    ctl: &CtlArgs,
    key: &SecretString,
    token: Option<&str>,
    token_file: Option<&str>,
    yes: bool,
) -> Result<String, CtlError> {
    // The token travels once in the install body and is never printed,
    // logged or rendered back (the status route never echoes it).
    let secret = read_secret_arg(token, token_file, "licence token", "--token", false)?;
    if secret.is_empty() {
        return Err(CtlError::validation("licence token must not be empty"));
    }
    confirm_destructive(yes, "Install this licence token?")?;
    let body = serde_json::json!({ "token": secret });
    let (_, response) = request(
        ctl,
        key,
        reqwest::Method::POST,
        "/api/v1/licence/install",
        Some(body),
    )
    .await?;
    if ctl.json {
        return Ok(render_json(&response));
    }
    Ok(format!(
        "installed licence for {}\n",
        cell(response.get("customer"))
    ))
}

async fn cmd_backup_export(
    ctl: &CtlArgs,
    key: &SecretString,
    file: &str,
    format: &str,
) -> Result<String, CtlError> {
    if !matches!(format, "json" | "toml") {
        return Err(CtlError::validation("format must be json or toml"));
    }
    // The latest recorded version is the current configuration: every
    // applied change is versioned, so the newest version's snapshot is a
    // complete backup of the governance state.
    // TODO(parity): the backup contract's "clients' data paths" scope is
    // undecided (no dedicated backup endpoint exists; retained messages
    // and session state are not versioned). The conservative backup is the
    // versioned governance snapshot only, until decided.
    let (_, history) = request(
        ctl,
        key,
        reqwest::Method::GET,
        "/api/v1/config/history",
        None,
    )
    .await?;
    let latest = history
        .get("versions")
        .and_then(|v| v.as_array())
        .and_then(|versions| versions.first())
        .and_then(|row| row.get("id").and_then(|v| v.as_u64()))
        .ok_or_else(|| CtlError::server("config history has no versions"))?;
    let path = format!("/api/v1/config/history/{latest}");
    let (_, version) = request(ctl, key, reqwest::Method::GET, &path, None).await?;
    let snapshot = version
        .get("snapshot")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    // The server redacts secret references in this snapshot; the file
    // therefore holds references (restorable markers), never values.
    let text = if format == "json" {
        serde_json::to_string_pretty(&snapshot)
            .map_err(|e| CtlError::server(format!("cannot encode backup: {e}")))?
    } else {
        let parsed: broker_config::FullSnapshot = serde_json::from_value(snapshot.clone())
            .map_err(|e| CtlError::server(format!("cannot decode backup snapshot: {e}")))?;
        toml::to_string_pretty(&parsed)
            .map_err(|e| CtlError::server(format!("cannot encode backup: {e}")))?
    };
    std::fs::write(file, format!("{text}\n"))
        .map_err(|e| CtlError::validation(format!("cannot write backup file: {e}")))?;
    if ctl.json {
        let body = serde_json::json!({"version": latest, "file": file, "format": format});
        return Ok(render_json(&body));
    }
    Ok(format!("exported version {latest} to {file}\n"))
}

async fn cmd_backup_import(
    ctl: &CtlArgs,
    key: &SecretString,
    file: &str,
    yes: bool,
    actor: &str,
) -> Result<String, CtlError> {
    confirm_destructive(yes, &format!("Import backup {file:?} onto this node?"))?;
    let snapshot = load_snapshot_file(file)?;
    let value = serde_json::to_value(&snapshot).unwrap_or(serde_json::Value::Null);
    let body = serde_json::json!({
        "snapshot": value,
        "actor": actor,
        "summary": format!("backup import of {file}"),
    });
    let (_, response) = request(
        ctl,
        key,
        reqwest::Method::POST,
        "/api/v1/config/reload",
        Some(body),
    )
    .await?;
    if ctl.json {
        return Ok(render_json(&response));
    }
    Ok(format!(
        "imported {file} as version {}\n",
        cell(response.get("version"))
    ))
}

/// Run one parsed `ctl` invocation, returning stdout text or a [`CtlError`].
/// Errors carry only the stderr line; stdout stays empty so scripts never
/// see a partial table.
async fn run_ctl(ctl: &CtlArgs) -> Result<String, CtlError> {
    let key = resolve_api_key(ctl)?;
    match &ctl.command {
        CtlCommand::Status => cmd_status(ctl, &key).await,
        CtlCommand::Clients { command } => match command {
            ClientsCommand::List { page, limit } => {
                cmd_clients_list(ctl, &key, *page, *limit).await
            }
            ClientsCommand::Show { client_id } => cmd_clients_show(ctl, &key, client_id).await,
            ClientsCommand::Kick { client_id } => cmd_clients_kick(ctl, &key, client_id).await,
        },
        CtlCommand::Subscriptions { page, limit } => {
            cmd_subscriptions(ctl, &key, *page, *limit).await
        }
        CtlCommand::Topics { page, limit } => cmd_topics(ctl, &key, *page, *limit).await,
        CtlCommand::Publish {
            topic,
            payload,
            qos,
            retain,
        } => cmd_publish(ctl, &key, topic, payload, *qos, *retain).await,
        CtlCommand::Listeners => cmd_listeners(ctl, &key).await,
        CtlCommand::Rules { command } => match command {
            RulesCommand::List => cmd_rules_list(ctl, &key).await,
            RulesCommand::Show { id } => cmd_rules_show(ctl, &key, id).await,
            RulesCommand::Create {
                name,
                topic_filter,
                sql,
                disable,
                actions,
                log,
                forward,
                republish,
            } => {
                cmd_rules_create(
                    ctl,
                    &key,
                    name,
                    topic_filter,
                    sql.as_deref(),
                    *disable,
                    actions.as_deref(),
                    *log,
                    forward,
                    republish,
                )
                .await
            }
            RulesCommand::Delete { id, yes } => cmd_rules_delete(ctl, &key, id, *yes).await,
        },
        CtlCommand::Connectors { command } => match command {
            ConnectorsCommand::List => cmd_connectors_list(ctl, &key).await,
            ConnectorsCommand::Show { id } => cmd_connectors_show(ctl, &key, id).await,
            ConnectorsCommand::Create {
                id,
                r#type,
                params,
                params_file,
                disable,
            } => {
                cmd_connectors_create(
                    ctl,
                    &key,
                    id,
                    r#type,
                    params.as_deref(),
                    params_file.as_deref(),
                    *disable,
                )
                .await
            }
            ConnectorsCommand::Delete { id, yes } => {
                cmd_connectors_delete(ctl, &key, id, *yes).await
            }
        },
        CtlCommand::Users { command } => match command {
            UsersCommand::List => cmd_users_list(ctl, &key).await,
            UsersCommand::Show { username } => cmd_users_show(ctl, &key, username).await,
            UsersCommand::Create {
                username,
                password,
                password_file,
                max_connections,
                max_publish_rate,
                max_publish_burst,
            } => {
                cmd_users_create(
                    ctl,
                    &key,
                    username,
                    password.as_deref(),
                    password_file.as_deref(),
                    *max_connections,
                    *max_publish_rate,
                    *max_publish_burst,
                )
                .await
            }
            UsersCommand::Delete { username, yes } => {
                cmd_users_delete(ctl, &key, username, *yes).await
            }
        },
        CtlCommand::Config { command } => match command {
            ConfigCommand::Validate { file } => cmd_config_validate(ctl, &key, file).await,
            ConfigCommand::Diff { file } => cmd_config_diff(ctl, &key, file).await,
            ConfigCommand::Reload {
                file,
                actor,
                summary,
            } => cmd_config_reload(ctl, &key, file, actor, summary.as_deref()).await,
            ConfigCommand::Explain { key: setting } => cmd_config_explain(ctl, &key, setting).await,
            ConfigCommand::History {
                id,
                restore,
                yes,
                actor,
            } => cmd_config_history(ctl, &key, *id, *restore, *yes, actor).await,
        },
        CtlCommand::Licence { command } => match command {
            None | Some(LicenceCommand::Status) => cmd_licence_status(ctl, &key).await,
            Some(LicenceCommand::Request) => cmd_licence_request(ctl, &key).await,
            Some(LicenceCommand::Install {
                token,
                token_file,
                yes,
            }) => {
                cmd_licence_install(ctl, &key, token.as_deref(), token_file.as_deref(), *yes).await
            }
        },
        CtlCommand::Backup { command } => match command {
            BackupCommand::Export { file, format } => {
                cmd_backup_export(ctl, &key, file, format).await
            }
            BackupCommand::Import { file, yes, actor } => {
                cmd_backup_import(ctl, &key, file, *yes, actor).await
            }
        },
    }
}

#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // Clap usage errors exit 2 by default; remap to the validation
            // code so 2 keeps meaning authentication failure only.
            error.print().expect("clap error renders");
            std::process::exit(EXIT_VALIDATION);
        }
    };
    let TopCommand::Ctl(ctl) = cli.command;
    match run_ctl(&ctl).await {
        Ok(stdout) => {
            print!("{stdout}");
            std::process::exit(EXIT_OK);
        }
        Err(error) => {
            eprintln!("{}", error.message);
            std::process::exit(error.code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_protocol::{QoS, TopicFilter};
    use broker_router::Subscription;
    use std::sync::Arc;

    const TEST_KEY: &str = "ctl-test-key-1";

    /// Live management API over loopback backed by real broker state.
    ///
    /// The `ApiState` shares one `SessionManager`, subscription router and
    /// delivery directory exactly like the kernel's `serve_api` wiring, so
    /// every `ctl` call below exercises the real session list, the real
    /// kick close path and the real publish fan-out -- never a mock API.
    struct LiveApi {
        state: broker_api::ApiState,
        base: String,
        _task: tokio::task::JoinHandle<()>,
    }

    impl LiveApi {
        async fn start() -> Self {
            Self::start_with_listeners(None).await
        }

        /// Start the live API with a custom listener configuration.
        ///
        /// The configuration must be installed before the serving task
        /// clones the state: replacing the `Arc` afterwards would only
        /// touch the test handle, never the serving copy.
        async fn start_with_listeners(
            listeners: Option<broker_config::schema::ListenersConf>,
        ) -> Self {
            let engine = Arc::new(broker_rules::RuleEngine::new(
                16,
                broker_rules::BackpressurePolicy::DropOldest,
            ));
            let mut state = broker_api::ApiState::standalone(engine);
            // M1-07: attach the live rule engine and auth store to the test
            // registry, exactly like `ApiState::new` (and the kernel boot
            // path) does. Without this, rule/user creates through the API
            // would stay memory-only and the config history would never see
            // them, so governance round-trips (backup export/import) could
            // not be tested against this harness.
            state
                .engine
                .seed_from_registry(&state.config)
                .expect("empty snapshot seeds the test engine");
            state
                .auth
                .seed_from_registry(&state.config)
                .expect("empty snapshot seeds the test auth store");
            // M1-07: seed a cluster identity so the licence routes answer
            // like a booted node (trial state, generatable request) instead
            // of 503 with no identity loaded. The trial starts now so the
            // status reads `trial`, matching a fresh installation.
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(1_750_000_000);
            state
                .licence
                .set_identity_for_tests(broker_cluster::ClusterIdentity {
                    identity: "ctl-test-cluster".to_string(),
                    public_key_hex: "aa".to_string(),
                    private_key_hex: "bb".to_string(),
                    trial_started_at: now_secs,
                    highest_seen_secs: now_secs,
                });
            if let Some(listeners) = listeners {
                state.listeners = Arc::new(listeners);
            }
            state
                .api_keys
                .insert(TEST_KEY)
                .expect("test key inserts under the cap");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind live test API");
            let base = format!("http://{}", listener.local_addr().expect("addr"));
            let task = tokio::spawn({
                let state = state.clone();
                async move {
                    broker_api::serve(listener, state)
                        .await
                        .expect("serve live test API");
                }
            });
            Self {
                state,
                base,
                _task: task,
            }
        }

        /// Simulate a live edge connection the way the kernel bind path
        /// does: canonical session plus bound connection plus a registered
        /// delivery mailbox standing in for the edge task. Returns the
        /// mailbox receiver so tests observe close frames and deliveries.
        fn connect_client(
            &self,
            client_id: &str,
            conn_id: u64,
        ) -> tokio::sync::mpsc::UnboundedReceiver<brokerlink::BrokerFrame> {
            let (session, _) = self.state.sessions.get_or_create(client_id, true);
            self.state.sessions.bind_session(&session, conn_id);
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            self.state.conns.register(conn_id, tx);
            rx
        }

        fn subscribe(&self, client_id: &str, conn_id: u64, filter: &str) {
            let filter = TopicFilter::new(filter).expect("valid filter");
            // QoS 1 end to end: the management publish below uses QoS 1,
            // so the effective delivery QoS is 1 and the frame rides the
            // guaranteed mailbox path (`ConnTable::route`). QoS 0 would
            // ride the bounded per-subscriber backlog (`pop_qos0`), never
            // the mailbox, and a mailbox `recv` would hang forever.
            self.state.sessions.add_subscription_with_options(
                client_id,
                filter.clone(),
                QoS::AtLeastOnce,
                0,
                0,
                0,
            );
            self.state.router.subscribe(
                &filter,
                Subscription::new(client_id, conn_id, QoS::AtLeastOnce),
            );
        }

        fn ctl(&self, json: bool, command: CtlCommand) -> CtlArgs {
            CtlArgs {
                endpoint: self.base.clone(),
                api_key: Some(TEST_KEY.to_string()),
                api_key_file: None,
                json,
                timeout: 5,
                command,
            }
        }
    }

    #[tokio::test]
    async fn status_reports_running_node_in_both_forms() {
        let api = LiveApi::start().await;
        api.state.readiness.mark_ready();
        let human = run_ctl(&api.ctl(false, CtlCommand::Status))
            .await
            .expect("status succeeds");
        assert!(human.contains("up"), "human form reports up: {human}");
        let json = run_ctl(&api.ctl(true, CtlCommand::Status))
            .await
            .expect("status --json succeeds");
        let body: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        assert_eq!(body["status"], serde_json::json!("up"));
        assert!(
            human.contains("up") && body["status"] == serde_json::json!("up"),
            "both forms report the same running state"
        );
    }

    #[tokio::test]
    async fn clients_list_shows_two_connected_clients_in_both_forms() {
        let api = LiveApi::start().await;
        let _rx_a = api.connect_client("ctl-client-a", 7001);
        let _rx_b = api.connect_client("ctl-client-b", 7002);
        let human = run_ctl(&api.ctl(
            false,
            CtlCommand::Clients {
                command: ClientsCommand::List {
                    page: 1,
                    limit: 100,
                },
            },
        ))
        .await
        .expect("clients list succeeds");
        assert!(human.contains("ctl-client-a"), "human lists a: {human}");
        assert!(human.contains("ctl-client-b"), "human lists b: {human}");
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Clients {
                command: ClientsCommand::List {
                    page: 1,
                    limit: 100,
                },
            },
        ))
        .await
        .expect("clients list --json succeeds");
        let body: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        let ids: Vec<&str> = body["data"]
            .as_array()
            .expect("list envelope carries data")
            .iter()
            .map(|row| row["clientid"].as_str().expect("row carries clientid"))
            .collect();
        assert!(ids.contains(&"ctl-client-a"), "json lists a: {ids:?}");
        assert!(ids.contains(&"ctl-client-b"), "json lists b: {ids:?}");
    }

    #[tokio::test]
    async fn clients_show_matches_list_identities() {
        let api = LiveApi::start().await;
        let _rx = api.connect_client("ctl-client-show", 7011);
        let human = run_ctl(&api.ctl(
            false,
            CtlCommand::Clients {
                command: ClientsCommand::Show {
                    client_id: "ctl-client-show".to_string(),
                },
            },
        ))
        .await
        .expect("clients show succeeds");
        assert!(
            human.contains("ctl-client-show"),
            "human show names the client: {human}"
        );
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Clients {
                command: ClientsCommand::Show {
                    client_id: "ctl-client-show".to_string(),
                },
            },
        ))
        .await
        .expect("clients show --json succeeds");
        let body: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        assert_eq!(body["clientid"], serde_json::json!("ctl-client-show"));
    }

    #[tokio::test]
    async fn clients_kick_disconnects_one_through_edge_close_frame() {
        let api = LiveApi::start().await;
        let mut rx_a = api.connect_client("ctl-kick-a", 7021);
        let _rx_b = api.connect_client("ctl-kick-b", 7022);
        let out = run_ctl(&api.ctl(
            false,
            CtlCommand::Clients {
                command: ClientsCommand::Kick {
                    client_id: "ctl-kick-a".to_string(),
                },
            },
        ))
        .await
        .expect("kick succeeds");
        assert!(out.contains("ctl-kick-a"), "kick confirms the id: {out}");
        // The kick drives the kernel-to-edge close path, not a store flag:
        // the bound mailbox observes the close frame. Bounded wait so a
        // lost close fails the test instead of hanging the whole binary
        // (the gate kills a hung binary with SIGTERM).
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), rx_a.recv())
            .await
            .expect("edge sees the close frame in time")
            .expect("edge sees the close frame");
        assert_eq!(frame.header.opcode, brokerlink::OpCode::ConnClose);
        assert_eq!(frame.header.conn_id, 7021);
        // The next list shows one client: the kicked session is detached.
        let human = run_ctl(&api.ctl(
            false,
            CtlCommand::Clients {
                command: ClientsCommand::List {
                    page: 1,
                    limit: 100,
                },
            },
        ))
        .await
        .expect("list after kick succeeds");
        assert!(!human.contains("ctl-kick-a"), "kicked client gone: {human}");
        assert!(human.contains("ctl-kick-b"), "other client stays: {human}");
    }

    #[tokio::test]
    async fn kick_json_confirms_same_identity_as_human() {
        let api = LiveApi::start().await;
        let _rx = api.connect_client("ctl-kick-json", 7023);
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Clients {
                command: ClientsCommand::Kick {
                    client_id: "ctl-kick-json".to_string(),
                },
            },
        ))
        .await
        .expect("kick --json succeeds");
        let body: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        assert_eq!(body["clientid"], serde_json::json!("ctl-kick-json"));
        assert_eq!(body["result"], serde_json::json!("kicked"));
    }

    #[tokio::test]
    async fn unknown_kick_exits_not_found_with_error_shape() {
        let api = LiveApi::start().await;
        let error = run_ctl(&api.ctl(
            false,
            CtlCommand::Clients {
                command: ClientsCommand::Kick {
                    client_id: "no-such-client".to_string(),
                },
            },
        ))
        .await
        .expect_err("unknown kick fails");
        assert_eq!(error.code, EXIT_NOT_FOUND);
        assert!(
            error.message.contains("CLIENTID_NOT_FOUND"),
            "documented error shape: {}",
            error.message
        );
        // No stdout accompanies the failure: run_ctl returns Err, so the
        // caller prints only this stderr line.
    }

    #[tokio::test]
    async fn publish_is_delivered_to_subscribed_client() {
        let api = LiveApi::start().await;
        let mut rx_sub = api.connect_client("ctl-sub", 7031);
        api.subscribe("ctl-sub", 7031, "ctl/+/data");
        let out = run_ctl(&api.ctl(
            false,
            CtlCommand::Publish {
                topic: "ctl/sensor/data".to_string(),
                payload: "hello-ctl".to_string(),
                qos: 1,
                retain: false,
            },
        ))
        .await
        .expect("publish succeeds");
        assert!(out.contains("published"), "publish confirms: {out}");
        // Delivery rides the real management publish fan-out into the
        // subscriber mailbox (QoS 1: guaranteed path). Bounded wait so a
        // lost delivery fails this test instead of hanging the binary.
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), rx_sub.recv())
            .await
            .expect("subscriber is delivered in time")
            .expect("subscriber is delivered");
        assert_eq!(frame.header.opcode, brokerlink::OpCode::PublishOut);
        assert_eq!(frame.payload.to_vec(), b"hello-ctl".to_vec());
        // The publish also indexed the topic and the subscription rows
        // observe the same session state the human forms show.
        let subs = run_ctl(&api.ctl(
            true,
            CtlCommand::Subscriptions {
                page: 1,
                limit: 100,
            },
        ))
        .await
        .expect("subscriptions --json succeeds");
        let subs_body: serde_json::Value =
            serde_json::from_str(&subs).expect("subscriptions JSON parses");
        let rows = subs_body.as_array().expect("subscriptions is an array");
        assert!(
            rows.iter()
                .any(|r| r["clientid"] == serde_json::json!("ctl-sub")
                    && r["topic"] == serde_json::json!("ctl/+/data")),
            "subscription row visible: {rows:?}"
        );
        let topics = run_ctl(&api.ctl(
            true,
            CtlCommand::Topics {
                page: 1,
                limit: 100,
            },
        ))
        .await
        .expect("topics --json succeeds");
        let topics_body: serde_json::Value =
            serde_json::from_str(&topics).expect("topics JSON parses");
        let names: Vec<&str> = topics_body["data"]
            .as_array()
            .expect("topics envelope carries data")
            .iter()
            .map(|row| row["topic"].as_str().expect("row carries topic"))
            .collect();
        assert!(
            names.contains(&"ctl/sensor/data"),
            "published topic indexed: {names:?}"
        );
        // Same identities in the human forms: the default table output
        // shows the same subscription row and topic the --json bodies do.
        let subs_human = run_ctl(&api.ctl(
            false,
            CtlCommand::Subscriptions {
                page: 1,
                limit: 100,
            },
        ))
        .await
        .expect("subscriptions succeeds");
        assert!(
            subs_human.contains("ctl-sub"),
            "human subscriptions show the client: {subs_human}"
        );
        assert!(
            subs_human.contains("ctl/+/data"),
            "human subscriptions show the filter: {subs_human}"
        );
        let topics_human = run_ctl(&api.ctl(
            false,
            CtlCommand::Topics {
                page: 1,
                limit: 100,
            },
        ))
        .await
        .expect("topics succeeds");
        assert!(
            topics_human.contains("ctl/sensor/data"),
            "human topics show the published topic: {topics_human}"
        );
    }

    #[tokio::test]
    async fn publish_json_returns_stable_id_key() {
        let api = LiveApi::start().await;
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Publish {
                topic: "ctl/json/t".to_string(),
                payload: "p".to_string(),
                qos: 0,
                retain: false,
            },
        ))
        .await
        .expect("publish --json succeeds");
        let body: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        assert!(
            body.get("id").and_then(|v| v.as_str()).is_some(),
            "publish --json carries stable id key: {body}"
        );
    }

    #[tokio::test]
    async fn listeners_reflect_running_binds_in_both_forms() {
        // Installed before the serving task clones the state: replacing
        // the `Arc` afterwards would only touch the test handle.
        let mut listeners = broker_config::schema::ListenersConf::default();
        listeners.tcp.bind = "127.0.0.1:11883".to_string();
        listeners.ws.enabled = true;
        let api = LiveApi::start_with_listeners(Some(listeners)).await;
        let human = run_ctl(&api.ctl(false, CtlCommand::Listeners))
            .await
            .expect("listeners succeeds");
        assert!(
            human.contains("127.0.0.1:11883"),
            "human reflects the tcp bind: {human}"
        );
        assert!(human.contains("ws:default"), "human lists ws: {human}");
        let json = run_ctl(&api.ctl(true, CtlCommand::Listeners))
            .await
            .expect("listeners --json succeeds");
        let body: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        let rows = body.as_array().expect("listeners is an array");
        let by_id = |id: &str| rows.iter().find(|r| r["id"] == id).expect(id);
        assert_eq!(
            by_id("tcp:default")["bind"],
            serde_json::json!("127.0.0.1:11883")
        );
        assert_eq!(by_id("ws:default")["enabled"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn wrong_key_exits_auth_without_printing_key() {
        let api = LiveApi::start().await;
        let wrong = CtlArgs {
            endpoint: api.base.clone(),
            api_key: Some("wrong-key-value".to_string()),
            api_key_file: None,
            json: false,
            timeout: 5,
            command: CtlCommand::Status,
        };
        let error = run_ctl(&wrong).await.expect_err("wrong key fails");
        assert_eq!(error.code, EXIT_AUTH);
        assert!(
            error.message.contains("UNAUTHORIZED"),
            "reason on stderr: {}",
            error.message
        );
        assert!(
            !error.message.contains("wrong-key-value"),
            "key never appears in output: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn missing_key_fails_closed_before_any_request() {
        // No flag, no file, and (in CI) no INDRA_API_KEY in the
        // environment: ctl refuses before sending anything.
        if std::env::var(API_KEY_ENV).is_ok() {
            panic!(
                "{API_KEY_ENV} is set in this environment; refusing to assert the missing-key path"
            );
        }
        let ctl = CtlArgs {
            endpoint: "http://127.0.0.1:1".to_string(),
            api_key: None,
            api_key_file: None,
            json: false,
            timeout: 2,
            command: CtlCommand::Status,
        };
        let error = run_ctl(&ctl).await.expect_err("missing key fails");
        assert_eq!(error.code, EXIT_VALIDATION);
        assert!(
            error.message.contains("missing API key"),
            "{}",
            error.message
        );
    }

    #[tokio::test]
    async fn unreachable_endpoint_exits_connection() {
        let ctl = CtlArgs {
            endpoint: "http://127.0.0.1:1".to_string(),
            api_key: Some(TEST_KEY.to_string()),
            api_key_file: None,
            json: false,
            timeout: 2,
            command: CtlCommand::Status,
        };
        let error = run_ctl(&ctl).await.expect_err("refused port fails");
        assert_eq!(error.code, EXIT_CONNECTION);
    }

    #[tokio::test]
    async fn malformed_endpoint_is_validation_not_connection() {
        let ctl = CtlArgs {
            endpoint: "not a url".to_string(),
            api_key: Some(TEST_KEY.to_string()),
            api_key_file: None,
            json: false,
            timeout: 2,
            command: CtlCommand::Status,
        };
        let error = run_ctl(&ctl).await.expect_err("bad URL fails");
        assert_eq!(error.code, EXIT_VALIDATION);
    }

    #[test]
    fn exit_codes_are_distinct() {
        let codes = [
            EXIT_OK,
            EXIT_CONNECTION,
            EXIT_AUTH,
            EXIT_NOT_FOUND,
            EXIT_VALIDATION,
            EXIT_SERVER,
        ];
        assert_eq!(EXIT_OK, 0, "success is zero");
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "every failure is distinct");
    }

    #[test]
    fn secret_string_never_renders_the_key() {
        let key = SecretString::new("super-secret-value".to_string());
        assert!(!format!("{key:?}").contains("super-secret-value"));
        assert!(!format!("{key}").contains("super-secret-value"));
        assert!(!key.is_empty());
        assert!(SecretString::new(String::new()).is_empty());
    }

    #[test]
    fn api_key_flag_wins_without_touching_environment() {
        // Hermetic: a present non-blank flag resolves immediately, so the
        // result cannot depend on ambient environment or files.
        let ctl = CtlArgs {
            endpoint: DEFAULT_ENDPOINT.to_string(),
            api_key: Some("flag-key".to_string()),
            api_key_file: Some("/definitely/not/here".to_string()),
            json: false,
            timeout: 5,
            command: CtlCommand::Status,
        };
        assert_eq!(
            resolve_api_key(&ctl).expect("flag wins").expose(),
            "flag-key"
        );
    }

    #[test]
    fn api_key_file_is_used_when_no_flag_given() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("ctl.key");
        std::fs::write(&path, "file-key\n").expect("write key file");
        let ctl = CtlArgs {
            endpoint: DEFAULT_ENDPOINT.to_string(),
            api_key: None,
            api_key_file: Some(path.to_string_lossy().into_owned()),
            json: false,
            timeout: 5,
            command: CtlCommand::Status,
        };
        assert_eq!(
            resolve_api_key(&ctl).expect("file key").expose(),
            "file-key"
        );
    }

    #[test]
    fn status_mapping_covers_every_family() {
        let body = serde_json::json!({"code": "X", "message": "y"});
        let family = |n: u16| {
            map_status(
                reqwest::StatusCode::from_u16(n).expect("valid status"),
                &body,
            )
            .expect_err("error status maps to Err")
            .code
        };
        assert_eq!(family(401), EXIT_AUTH);
        assert_eq!(family(403), EXIT_AUTH);
        assert_eq!(family(404), EXIT_NOT_FOUND);
        assert_eq!(family(400), EXIT_VALIDATION);
        assert_eq!(family(422), EXIT_VALIDATION);
        assert_eq!(family(500), EXIT_SERVER);
        assert_eq!(family(503), EXIT_SERVER);
        assert!(
            map_status(reqwest::StatusCode::OK, &body).is_ok(),
            "2xx passes through"
        );
    }

    #[test]
    fn clamps_mirror_server_semantics() {
        assert_eq!(clamp_page(0), 1);
        assert_eq!(clamp_page(3), 3);
        assert_eq!(clamp_limit(0), 1);
        assert_eq!(clamp_limit(10_000), MAX_LIMIT);
        assert_eq!(clamp_timeout(0), 1);
        assert_eq!(clamp_timeout(10_000), MAX_TIMEOUT_SECS);
    }

    // M1-07 governance tests: every command runs against the live kernel
    // above (real session/auth/rule/connector state behind the management
    // API), never a mock.

    use std::sync::atomic::{AtomicU64, Ordering};

    /// Unique suffix so parallel tests never share a rule, connector or
    /// user identity (the v5 connector directory is process-global).
    static GOV_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn gov_id(prefix: &str) -> String {
        let n = GOV_COUNTER.fetch_add(1, Ordering::SeqCst);
        format!("{prefix}-{n}")
    }

    /// Null broker sink for rule-ingress assertions: proves the rule
    /// evaluates on the publish path, not only in the store list.
    struct GovNullSink;

    #[async_trait::async_trait]
    impl broker_rules::BrokerSink for GovNullSink {
        async fn publish(
            &self,
            _topic: broker_protocol::Topic,
            _payload: bytes::Bytes,
            _qos: broker_protocol::QoS,
            _retain: bool,
        ) -> Result<(), broker_rules::RuleEngineError> {
            Ok(())
        }
    }

    fn gov_sink() -> Arc<dyn broker_rules::BrokerSink> {
        Arc::new(GovNullSink)
    }

    fn write_temp_file(name: &str, contents: &str) -> std::path::PathBuf {
        // Plain temp-dir file with a unique name (no TempDir handle to
        // leak); every caller removes its file when done.
        let n = GOV_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("gov-{}-{n}-{name}", std::process::id()));
        std::fs::write(&path, contents).expect("write temp file");
        path
    }

    fn empty_snapshot_json() -> serde_json::Value {
        serde_json::json!({
            "admin_users": {"users": []},
            "mqtt_users": {"users": [], "acls": []},
            "rules": {"rules": []},
            "connectors": {"connectors": []},
        })
    }

    #[tokio::test]
    async fn rules_create_show_and_evaluate_through_broker() {
        let api = LiveApi::start().await;
        let name = gov_id("gov-rule");
        let filter = "gov/ctl/data";
        // Create through ctl, --json first to learn the server-assigned id.
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Rules {
                command: RulesCommand::Create {
                    name: name.clone(),
                    topic_filter: filter.to_string(),
                    sql: None,
                    disable: false,
                    actions: Some(r#"[{"type":"log"}]"#.to_string()),
                    log: false,
                    forward: Vec::new(),
                    republish: Vec::new(),
                },
            },
        ))
        .await
        .expect("rules create succeeds");
        let created: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        let id = created["id"]
            .as_str()
            .expect("create returns an id")
            .to_string();
        assert_eq!(created["name"], serde_json::json!(name));
        // Human show names the same rule.
        let human = run_ctl(&api.ctl(
            false,
            CtlCommand::Rules {
                command: RulesCommand::Show { id: id.clone() },
            },
        ))
        .await
        .expect("rules show succeeds");
        assert!(human.contains(&name), "human show names it: {human}");
        assert!(human.contains(filter), "human show shows filter: {human}");
        // Human list shows the same identity.
        let list = run_ctl(&api.ctl(
            false,
            CtlCommand::Rules {
                command: RulesCommand::List,
            },
        ))
        .await
        .expect("rules list succeeds");
        assert!(list.contains(&id), "list shows the id: {list}");
        assert!(list.contains(&name), "list shows the name: {list}");
        // Through the broker: a publish at ingress matches the new rule
        // (not only a store list).
        let sink = gov_sink();
        let matched = api
            .state
            .engine
            .dispatch_ingress(
                &broker_protocol::Topic::new(filter).expect("topic"),
                &bytes::Bytes::from_static(b"{}"),
                broker_protocol::QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(matched, 1, "ingress matches the ctl-created rule");
    }

    #[tokio::test]
    async fn rules_create_conveniences_and_delete_needs_confirm() {
        let api = LiveApi::start().await;
        let name = gov_id("gov-rule-conv");
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Rules {
                command: RulesCommand::Create {
                    name: name.clone(),
                    topic_filter: "gov/conv/#".to_string(),
                    sql: None,
                    disable: false,
                    actions: None,
                    log: true,
                    forward: Vec::new(),
                    republish: vec!["gov/out:1".to_string()],
                },
            },
        ))
        .await
        .expect("convenience create succeeds");
        let created: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        let id = created["id"].as_str().expect("id").to_string();
        assert_eq!(created["actions"].as_array().expect("actions").len(), 2);
        // Destructive without --yes on a non-interactive stdin fails closed.
        let error = run_ctl(&api.ctl(
            false,
            CtlCommand::Rules {
                command: RulesCommand::Delete {
                    id: id.clone(),
                    yes: false,
                },
            },
        ))
        .await
        .expect_err("delete without --yes fails");
        assert_eq!(error.code, EXIT_VALIDATION);
        // With --yes the rule is gone: the next show is 404.
        let out = run_ctl(&api.ctl(
            false,
            CtlCommand::Rules {
                command: RulesCommand::Delete {
                    id: id.clone(),
                    yes: true,
                },
            },
        ))
        .await
        .expect("delete with --yes succeeds");
        assert!(out.contains(&id), "delete confirms the id: {out}");
        let error = run_ctl(&api.ctl(
            true,
            CtlCommand::Rules {
                command: RulesCommand::Show { id: id.clone() },
            },
        ))
        .await
        .expect_err("show after delete fails");
        assert_eq!(error.code, EXIT_NOT_FOUND);
    }

    #[tokio::test]
    async fn connectors_create_show_and_live_sink() {
        let api = LiveApi::start().await;
        let id = gov_id("gov-conn");
        let human = run_ctl(&api.ctl(
            false,
            CtlCommand::Connectors {
                command: ConnectorsCommand::Create {
                    id: id.clone(),
                    r#type: "console".to_string(),
                    params: None,
                    params_file: None,
                    disable: false,
                },
            },
        ))
        .await
        .expect("connectors create succeeds");
        assert!(human.contains(&id), "human create confirms: {human}");
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Connectors {
                command: ConnectorsCommand::Show { id: id.clone() },
            },
        ))
        .await
        .expect("connectors show --json succeeds");
        let body: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        assert_eq!(body["id"], serde_json::json!(id));
        assert_eq!(body["type"], serde_json::json!("console"));
        // Through the broker: the live connector directory holds the sink
        // (created through the same probe-then-register path as the API).
        assert!(
            api.state.engine.connectors().get(&id).is_some(),
            "console sink is live on the engine"
        );
        let list = run_ctl(&api.ctl(
            true,
            CtlCommand::Connectors {
                command: ConnectorsCommand::List,
            },
        ))
        .await
        .expect("connectors list --json succeeds");
        let listed: serde_json::Value = serde_json::from_str(&list).expect("list JSON parses");
        assert!(
            listed
                .as_array()
                .expect("list is an array")
                .iter()
                .any(|row| row["id"] == serde_json::json!(id)),
            "list contains the new connector"
        );
    }

    #[tokio::test]
    async fn connectors_delete_removes_from_list() {
        let api = LiveApi::start().await;
        let id = gov_id("gov-conn-del");
        run_ctl(&api.ctl(
            false,
            CtlCommand::Connectors {
                command: ConnectorsCommand::Create {
                    id: id.clone(),
                    r#type: "console".to_string(),
                    params: None,
                    params_file: None,
                    disable: false,
                },
            },
        ))
        .await
        .expect("create succeeds");
        let error = run_ctl(&api.ctl(
            false,
            CtlCommand::Connectors {
                command: ConnectorsCommand::Delete {
                    id: id.clone(),
                    yes: false,
                },
            },
        ))
        .await
        .expect_err("delete without --yes fails");
        assert_eq!(error.code, EXIT_VALIDATION);
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Connectors {
                command: ConnectorsCommand::Delete {
                    id: id.clone(),
                    yes: true,
                },
            },
        ))
        .await
        .expect("delete with --yes succeeds");
        let body: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        assert_eq!(body["id"], serde_json::json!(id));
        assert_eq!(body["result"], serde_json::json!("deleted"));
        let list = run_ctl(&api.ctl(
            false,
            CtlCommand::Connectors {
                command: ConnectorsCommand::List,
            },
        ))
        .await
        .expect("list succeeds");
        assert!(!list.contains(&id), "deleted connector gone: {list}");
    }

    #[tokio::test]
    async fn users_create_list_and_authenticate_through_broker() {
        let api = LiveApi::start().await;
        let username = gov_id("gov-user");
        let human = run_ctl(&api.ctl(
            false,
            CtlCommand::Users {
                command: UsersCommand::Create {
                    username: username.clone(),
                    password: Some("gov-secret-pw".to_string()),
                    password_file: None,
                    max_connections: None,
                    max_publish_rate: None,
                    max_publish_burst: None,
                },
            },
        ))
        .await
        .expect("users create succeeds");
        assert!(human.contains(&username), "human confirms: {human}");
        // The password is write-only: no list or show output carries it.
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Users {
                command: UsersCommand::List,
            },
        ))
        .await
        .expect("users list --json succeeds");
        assert!(
            !json.contains("gov-secret-pw"),
            "list leaks the password: {json}"
        );
        let body: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        assert!(
            body.as_array()
                .expect("list is an array")
                .iter()
                .any(|row| row["username"] == serde_json::json!(username)),
            "list contains the new user"
        );
        let show = run_ctl(&api.ctl(
            true,
            CtlCommand::Users {
                command: UsersCommand::Show {
                    username: username.clone(),
                },
            },
        ))
        .await
        .expect("users show succeeds");
        let shown: serde_json::Value = serde_json::from_str(&show).expect("show JSON parses");
        assert_eq!(shown["username"], serde_json::json!(username));
        assert!(
            !show.contains("gov-secret-pw"),
            "show leaks the password: {show}"
        );
        // Through the broker: the CONNECT path accepts the new credential
        // and rejects a wrong one.
        use broker_auth::Authenticator as _;
        assert!(api
            .state
            .auth
            .authenticate("device-gov", Some(&username), Some(b"gov-secret-pw"))
            .await
            .is_ok());
        assert!(api
            .state
            .auth
            .authenticate("device-gov", Some(&username), Some(b"wrong"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn users_delete_needs_confirm_and_unknown_show_is_not_found() {
        let api = LiveApi::start().await;
        let username = gov_id("gov-user-del");
        run_ctl(&api.ctl(
            false,
            CtlCommand::Users {
                command: UsersCommand::Create {
                    username: username.clone(),
                    password: Some("pw".to_string()),
                    password_file: None,
                    max_connections: None,
                    max_publish_rate: None,
                    max_publish_burst: None,
                },
            },
        ))
        .await
        .expect("create succeeds");
        let error = run_ctl(&api.ctl(
            false,
            CtlCommand::Users {
                command: UsersCommand::Delete {
                    username: username.clone(),
                    yes: false,
                },
            },
        ))
        .await
        .expect_err("delete without --yes fails");
        assert_eq!(error.code, EXIT_VALIDATION);
        run_ctl(&api.ctl(
            false,
            CtlCommand::Users {
                command: UsersCommand::Delete {
                    username: username.clone(),
                    yes: true,
                },
            },
        ))
        .await
        .expect("delete with --yes succeeds");
        let error = run_ctl(&api.ctl(
            false,
            CtlCommand::Users {
                command: UsersCommand::Show {
                    username: username.clone(),
                },
            },
        ))
        .await
        .expect_err("show after delete fails");
        assert_eq!(error.code, EXIT_NOT_FOUND);
    }

    #[tokio::test]
    async fn config_validate_rejects_bad_document_naming_setting() {
        let api = LiveApi::start().await;
        let mut bad = empty_snapshot_json();
        bad["rules"]["rules"] = serde_json::json!([{
            "id": "",
            "name": "bad",
            "topic_filter": "a/#",
            "enabled": true,
            "actions": [],
        }]);
        let path = write_temp_file(
            "gov-bad.json",
            &serde_json::to_string_pretty(&bad).expect("encode"),
        );
        let error = run_ctl(&api.ctl(
            false,
            CtlCommand::Config {
                command: ConfigCommand::Validate {
                    file: path.to_string_lossy().into_owned(),
                },
            },
        ))
        .await
        .expect_err("bad document fails validation");
        assert_eq!(error.code, EXIT_VALIDATION);
        assert!(
            error.message.contains("rules.rules[0].id"),
            "server names the setting: {}",
            error.message
        );
        std::fs::remove_file(&path).ok();
        // A good document validates, and --json carries the server body.
        let good_path = write_temp_file(
            "gov-good.json",
            &serde_json::to_string_pretty(&empty_snapshot_json()).expect("encode"),
        );
        let human = run_ctl(&api.ctl(
            false,
            CtlCommand::Config {
                command: ConfigCommand::Validate {
                    file: good_path.to_string_lossy().into_owned(),
                },
            },
        ))
        .await
        .expect("good document validates");
        assert!(human.contains("valid"), "human confirms: {human}");
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Config {
                command: ConfigCommand::Validate {
                    file: good_path.to_string_lossy().into_owned(),
                },
            },
        ))
        .await
        .expect("validate --json succeeds");
        let body: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        assert_eq!(body["ok"], serde_json::json!(true));
        std::fs::remove_file(&good_path).ok();
    }

    #[tokio::test]
    async fn config_diff_reload_history_and_explain() {
        let api = LiveApi::start().await;
        let username = gov_id("gov-diff-user");
        // Pending change: the empty snapshot plus one user.
        let mut candidate = empty_snapshot_json();
        candidate["mqtt_users"]["users"] = serde_json::json!([{
            "username": username,
            "password_hash": "aa".repeat(32),
        }]);
        let path = write_temp_file(
            "gov-candidate.json",
            &serde_json::to_string_pretty(&candidate).expect("encode"),
        );
        let file = path.to_string_lossy().into_owned();
        let human = run_ctl(&api.ctl(
            false,
            CtlCommand::Config {
                command: ConfigCommand::Diff { file: file.clone() },
            },
        ))
        .await
        .expect("diff succeeds");
        assert!(
            human.contains(&format!("mqtt_users.users[{username}]")),
            "diff shows the pending change: {human}"
        );
        // Reload applies it and reports the version; --json is verbatim.
        let reloaded = run_ctl(&api.ctl(
            false,
            CtlCommand::Config {
                command: ConfigCommand::Reload {
                    file: file.clone(),
                    actor: "ctl-test".to_string(),
                    summary: Some("add diff user".to_string()),
                },
            },
        ))
        .await
        .expect("reload succeeds");
        assert!(
            reloaded.contains("applied version"),
            "reload reports the version: {reloaded}"
        );
        assert!(
            reloaded.contains(&format!("mqtt_users.users[{username}]")),
            "reload previews the diff first: {reloaded}"
        );
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Config {
                command: ConfigCommand::History {
                    id: None,
                    restore: false,
                    yes: false,
                    actor: "ctl".to_string(),
                },
            },
        ))
        .await
        .expect("history --json succeeds");
        let history: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        let versions = history["versions"].as_array().expect("versions");
        assert!(
            versions
                .iter()
                .any(|v| v["actor"] == serde_json::json!("ctl-test")),
            "history lists the reload: {versions:?}"
        );
        let human_history = run_ctl(&api.ctl(
            false,
            CtlCommand::Config {
                command: ConfigCommand::History {
                    id: None,
                    restore: false,
                    yes: false,
                    actor: "ctl".to_string(),
                },
            },
        ))
        .await
        .expect("history succeeds");
        assert!(
            human_history.contains("ctl-test"),
            "human history lists the actor: {human_history}"
        );
        // Explain names the setting layer: runtime for the reloaded user,
        // built-in defaults for an untouched schema key.
        let explain = run_ctl(&api.ctl(
            true,
            CtlCommand::Config {
                command: ConfigCommand::Explain {
                    key: format!("mqtt_users.users.{username}"),
                },
            },
        ))
        .await
        .expect("explain succeeds");
        let explained: serde_json::Value =
            serde_json::from_str(&explain).expect("explain JSON parses");
        assert!(
            explained["layer"]
                .as_str()
                .unwrap_or("")
                .contains("runtime"),
            "registry key reports its runtime layer: {explained}"
        );
        let schema = run_ctl(&api.ctl(
            false,
            CtlCommand::Config {
                command: ConfigCommand::Explain {
                    key: "node.id".to_string(),
                },
            },
        ))
        .await
        .expect("schema explain succeeds");
        assert!(
            schema.contains("built-in defaults"),
            "schema key reports its layer: {schema}"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn config_history_restore_needs_confirm_and_reversions() {
        let api = LiveApi::start().await;
        // Restoring the latest version is a no-op change set that still
        // exercises the whole restore path (validate, live apply, version,
        // persist) without disturbing sibling tests' connectors.
        let json = run_ctl(&api.ctl(
            true,
            CtlCommand::Config {
                command: ConfigCommand::History {
                    id: None,
                    restore: false,
                    yes: false,
                    actor: "ctl".to_string(),
                },
            },
        ))
        .await
        .expect("history succeeds");
        let history: serde_json::Value = serde_json::from_str(&json).expect("history JSON parses");
        let latest = history["versions"][0]["id"]
            .as_u64()
            .expect("at least the boot version");
        let error = run_ctl(&api.ctl(
            false,
            CtlCommand::Config {
                command: ConfigCommand::History {
                    id: Some(latest),
                    restore: true,
                    yes: false,
                    actor: "ctl".to_string(),
                },
            },
        ))
        .await
        .expect_err("restore without --yes fails");
        assert_eq!(error.code, EXIT_VALIDATION);
        let out = run_ctl(&api.ctl(
            false,
            CtlCommand::Config {
                command: ConfigCommand::History {
                    id: Some(latest),
                    restore: true,
                    yes: true,
                    actor: "ctl".to_string(),
                },
            },
        ))
        .await
        .expect("restore with --yes succeeds");
        assert!(
            out.contains(&format!("{latest}")),
            "restore names it: {out}"
        );
        // Restoring a missing version is not-found, not a 500.
        let error = run_ctl(&api.ctl(
            false,
            CtlCommand::Config {
                command: ConfigCommand::History {
                    id: Some(999_999_999),
                    restore: true,
                    yes: true,
                    actor: "ctl".to_string(),
                },
            },
        ))
        .await
        .expect_err("unknown restore fails");
        assert_eq!(error.code, EXIT_NOT_FOUND);
    }

    #[tokio::test]
    async fn licence_shows_state_and_rejects_bad_token() {
        let api = LiveApi::start().await;
        let human = run_ctl(&api.ctl(false, CtlCommand::Licence { command: None }))
            .await
            .expect("licence succeeds");
        assert!(human.contains("trial"), "human shows trial: {human}");
        let json = run_ctl(&api.ctl(true, CtlCommand::Licence { command: None }))
            .await
            .expect("licence --json succeeds");
        let body: serde_json::Value =
            serde_json::from_str(&json).expect("--json output parses as JSON");
        assert_eq!(body["state"], serde_json::json!("trial"));
        assert_eq!(
            body["entitlements_on"],
            serde_json::json!(true),
            "licence problems never stop serving: {body}"
        );
        let request = run_ctl(&api.ctl(
            true,
            CtlCommand::Licence {
                command: Some(LicenceCommand::Request),
            },
        ))
        .await
        .expect("licence request succeeds");
        let requested: serde_json::Value =
            serde_json::from_str(&request).expect("request JSON parses");
        assert!(
            requested.get("installation_identity").is_some() || requested.get("summary").is_some(),
            "request carries the identity: {requested}"
        );
        // A forged token is a validation failure naming the reason, never
        // a silent accept; the stored state is untouched afterwards.
        let error = run_ctl(&api.ctl(
            false,
            CtlCommand::Licence {
                command: Some(LicenceCommand::Install {
                    token: Some("NOT-A-TOKEN".to_string()),
                    token_file: None,
                    yes: true,
                }),
            },
        ))
        .await
        .expect_err("bad token fails");
        assert_eq!(error.code, EXIT_VALIDATION);
        let after = run_ctl(&api.ctl(true, CtlCommand::Licence { command: None }))
            .await
            .expect("status still succeeds");
        let status: serde_json::Value = serde_json::from_str(&after).expect("status JSON parses");
        assert_eq!(status["state"], serde_json::json!("trial"));
    }

    #[tokio::test]
    async fn backup_export_import_round_trip_to_scratch_node() {
        let api = LiveApi::start().await;
        let username = gov_id("gov-backup-user");
        let rule_name = gov_id("gov-backup-rule");
        let conn_id = gov_id("gov-backup-conn");
        run_ctl(&api.ctl(
            false,
            CtlCommand::Users {
                command: UsersCommand::Create {
                    username: username.clone(),
                    password: Some("backup-pw".to_string()),
                    password_file: None,
                    max_connections: None,
                    max_publish_rate: None,
                    max_publish_burst: None,
                },
            },
        ))
        .await
        .expect("user create succeeds");
        let rule_json = run_ctl(&api.ctl(
            true,
            CtlCommand::Rules {
                command: RulesCommand::Create {
                    name: rule_name.clone(),
                    topic_filter: "gov/backup/#".to_string(),
                    sql: None,
                    disable: false,
                    actions: Some(r#"[{"type":"log"}]"#.to_string()),
                    log: false,
                    forward: Vec::new(),
                    republish: Vec::new(),
                },
            },
        ))
        .await
        .expect("rule create succeeds");
        let rule_id: String = serde_json::from_str::<serde_json::Value>(&rule_json)
            .expect("rule JSON parses")["id"]
            .as_str()
            .expect("rule id")
            .to_string();
        run_ctl(&api.ctl(
            false,
            CtlCommand::Connectors {
                command: ConnectorsCommand::Create {
                    id: conn_id.clone(),
                    r#type: "console".to_string(),
                    params: None,
                    params_file: None,
                    disable: false,
                },
            },
        ))
        .await
        .expect("connector create succeeds");
        // Export to TOML (the on-disk snapshot shape).
        let dir = tempfile::tempdir().expect("scratch dir");
        let export_path = dir.path().join("gov-backup.toml");
        let export_file = export_path.to_string_lossy().into_owned();
        let out = run_ctl(&api.ctl(
            false,
            CtlCommand::Backup {
                command: BackupCommand::Export {
                    file: export_file.clone(),
                    format: "toml".to_string(),
                },
            },
        ))
        .await
        .expect("backup export succeeds");
        assert!(out.contains("exported version"), "export confirms: {out}");
        let text = std::fs::read_to_string(&export_path).expect("export file written");
        assert!(text.contains(&username), "export carries the user");
        assert!(text.contains(&rule_id), "export carries the rule");
        assert!(text.contains(&conn_id), "export carries the connector");
        // Import onto a scratch node restores every governance object.
        let scratch = LiveApi::start().await;
        let error = run_ctl(&scratch.ctl(
            false,
            CtlCommand::Backup {
                command: BackupCommand::Import {
                    file: export_file.clone(),
                    yes: false,
                    actor: "ctl".to_string(),
                },
            },
        ))
        .await
        .expect_err("import without --yes fails");
        assert_eq!(error.code, EXIT_VALIDATION);
        let imported = run_ctl(&scratch.ctl(
            true,
            CtlCommand::Backup {
                command: BackupCommand::Import {
                    file: export_file.clone(),
                    yes: true,
                    actor: "ctl".to_string(),
                },
            },
        ))
        .await
        .expect("backup import succeeds");
        let result: serde_json::Value =
            serde_json::from_str(&imported).expect("import --json parses");
        assert!(result["version"].is_number(), "import versions: {result}");
        // Read them back through ctl on the scratch node.
        let users = run_ctl(&scratch.ctl(
            false,
            CtlCommand::Users {
                command: UsersCommand::List,
            },
        ))
        .await
        .expect("scratch users list succeeds");
        assert!(users.contains(&username), "user restored: {users}");
        let rule = run_ctl(&scratch.ctl(
            false,
            CtlCommand::Rules {
                command: RulesCommand::Show {
                    id: rule_id.clone(),
                },
            },
        ))
        .await
        .expect("scratch rule show succeeds");
        assert!(rule.contains(&rule_name), "rule restored: {rule}");
        let conn = run_ctl(&scratch.ctl(
            false,
            CtlCommand::Connectors {
                command: ConnectorsCommand::Show {
                    id: conn_id.clone(),
                },
            },
        ))
        .await
        .expect("scratch connector show succeeds");
        assert!(conn.contains(&conn_id), "connector restored: {conn}");
        // Through the scratch broker: the credential authenticates and the
        // rule evaluates at ingress.
        use broker_auth::Authenticator as _;
        assert!(scratch
            .state
            .auth
            .authenticate("device-b", Some(&username), Some(b"backup-pw"))
            .await
            .is_ok());
        let sink = gov_sink();
        let matched = scratch
            .state
            .engine
            .dispatch_ingress(
                &broker_protocol::Topic::new("gov/backup/event").expect("topic"),
                &bytes::Bytes::from_static(b"{}"),
                broker_protocol::QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(matched, 1, "restored rule evaluates on the scratch node");
    }

    #[tokio::test]
    async fn secret_references_never_appear_in_outputs() {
        let api = LiveApi::start().await;
        let dir = tempfile::tempdir().expect("scratch dir");
        let secret_path = dir.path().join("gov-secret");
        // A distinctive value that must never surface in any output.
        std::fs::write(&secret_path, "gov-secret-value-9f31").expect("write secret");
        let conn_id = gov_id("gov-secret-conn");
        let params = serde_json::json!({
            "token": format!("file:{}", secret_path.to_string_lossy()),
            "note": "holds a reference",
        })
        .to_string();
        run_ctl(&api.ctl(
            false,
            CtlCommand::Connectors {
                command: ConnectorsCommand::Create {
                    id: conn_id.clone(),
                    r#type: "console".to_string(),
                    params: Some(params),
                    params_file: None,
                    disable: false,
                },
            },
        ))
        .await
        .expect("create with a secret reference succeeds");
        let show = run_ctl(&api.ctl(
            true,
            CtlCommand::Connectors {
                command: ConnectorsCommand::Show {
                    id: conn_id.clone(),
                },
            },
        ))
        .await
        .expect("show succeeds");
        assert!(
            !show.contains("gov-secret-value-9f31"),
            "show leaks the secret: {show}"
        );
        assert!(
            show.contains("<redacted:"),
            "show keeps the redacted reference: {show}"
        );
        let list = run_ctl(&api.ctl(
            true,
            CtlCommand::Connectors {
                command: ConnectorsCommand::List,
            },
        ))
        .await
        .expect("list succeeds");
        assert!(
            !list.contains("gov-secret-value-9f31"),
            "list leaks the secret"
        );
        // Backup export carries the reference, never the value.
        let export_path = dir.path().join("gov-secret-backup.json");
        let export_file = export_path.to_string_lossy().into_owned();
        run_ctl(&api.ctl(
            false,
            CtlCommand::Backup {
                command: BackupCommand::Export {
                    file: export_file.clone(),
                    format: "json".to_string(),
                },
            },
        ))
        .await
        .expect("export succeeds");
        let exported = std::fs::read_to_string(&export_path).expect("export written");
        assert!(
            !exported.contains("gov-secret-value-9f31"),
            "backup exports the secret value"
        );
    }

    #[test]
    fn snapshot_files_parse_as_json_or_toml() {
        let snapshot = serde_json::json!({
            "admin_users": {"users": []},
            "mqtt_users": {"users": [], "acls": []},
            "rules": {"rules": []},
            "connectors": {"connectors": []},
        });
        let json_path = write_temp_file(
            "gov-snap.json",
            &serde_json::to_string_pretty(&snapshot).expect("encode"),
        );
        let loaded = load_snapshot_file(&json_path.to_string_lossy()).expect("JSON snapshot loads");
        assert!(loaded.rules.rules.is_empty());
        let parsed: broker_config::FullSnapshot = serde_json::from_value(snapshot).expect("shape");
        let toml_text = toml::to_string_pretty(&parsed).expect("encode TOML");
        let toml_path = write_temp_file("gov-snap.toml", &toml_text);
        let reloaded =
            load_snapshot_file(&toml_path.to_string_lossy()).expect("TOML snapshot loads");
        assert_eq!(reloaded, parsed);
        let error = load_snapshot_file("/definitely/not/here.toml").expect_err("missing fails");
        assert_eq!(error.code, EXIT_VALIDATION);
        std::fs::remove_file(&json_path).ok();
        std::fs::remove_file(&toml_path).ok();
    }

    #[test]
    fn destructive_confirm_fails_closed_without_a_terminal() {
        use std::io::IsTerminal as _;
        // Cargo test stdin is not a terminal: without --yes this refuses
        // instead of blocking on a prompt no one can answer.
        if std::io::stdin().is_terminal() {
            panic!("refusing to assert the non-interactive path on a terminal");
        }
        let error = confirm_destructive(false, "Delete it?").expect_err("refuses");
        assert_eq!(error.code, EXIT_VALIDATION);
        assert!(confirm_destructive(true, "Delete it?").is_ok());
    }
}
