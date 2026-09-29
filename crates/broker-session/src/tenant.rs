//! Tenant assignment at connect (MT-01).
//!
//! Assigns one tenant id per connecting client from a configurable
//! per-listener rule list. Each rule renders an expression against the
//! connect context (client id, username, peer host, TLS certificate
//! fields, listener name) and stores the result as a named client
//! attribute; the attribute named [`TENANT_ATTRIBUTE_NAME`] becomes the
//! tenant id. An empty or unrenderable result means the default tenant,
//! and the default registry ships empty so a default install behaves
//! exactly as before (same session keys, same topic matching).
//!
//! The registry is consulted on the connect path only (`apply_bind` in
//! the kernel): it clones the capped list under a short read lock (a
//! read-optimised snapshot) and renders off the lock, so the publish
//! and deliver paths take no config lock. Later waves (router,
//! session, retained, auth, delivery enforcement) join this registry;
//! no second tenancy scheme may be invented.
//!
//! Bounds (all stated here and enforced below):
//! - at most [`MAX_TENANT_RULES`] rules per registry;
//! - one expression is at most [`MAX_TENANT_EXPRESSION_LEN`] chars;
//! - a rendered tenant id is at most [`MAX_TENANT_ID_LEN`] chars and
//!   must hold no control characters, else it is rejected to the
//!   default tenant (counted via [`TenantRegistry::fallback_count`] and
//!   logged once per rejection).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Tenant id for clients with no tenant attribute.
pub const DEFAULT_TENANT_ID: &str = "default";

/// Rule attribute name whose rendered value becomes the tenant id.
/// Rules with other attribute names are validated at write time and
/// kept for later waves (client attributes), but only this attribute
/// drives assignment in MT-01.
pub const TENANT_ATTRIBUTE_NAME: &str = "tenant";

/// Upper bound for stored tenant rules. Writes past this size are
/// rejected with the documented error shape instead of growing without
/// limit. Reason: the connect path scans the list once per bind, so 32
/// entries bound per-connect work to a small constant while covering
/// one rule set per listener family with headroom.
pub const MAX_TENANT_RULES: usize = 32;

/// Longest accepted rule expression. Reason: one expression is stored
/// per rule, so 1 KiB caps registry memory near 32 KiB worst case while
/// leaving room for multi-variable templates.
pub const MAX_TENANT_EXPRESSION_LEN: usize = 1024;

/// Longest accepted rendered tenant id. Reason: the tenant id joins
/// session keys and log lines, so 128 chars bounds key memory at the
/// scale of client ids while covering hierarchical names.
pub const MAX_TENANT_ID_LEN: usize = 128;

/// Longest accepted rule listener scope. Reason: listener names are
/// short labels, so 64 chars bounds the scope field while covering
/// qualified listener names.
pub const MAX_TENANT_LISTENER_LEN: usize = 64;

/// Longest accepted rule attribute name. Reason: attribute names are
/// short identifiers, so 64 chars bounds the field while covering
/// qualified attribute names.
pub const MAX_TENANT_ATTRIBUTE_LEN: usize = 64;

/// Connect-time inputs for tenant expression rendering.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectContext {
    /// MQTT client id.
    pub client_id: String,
    /// Authenticated username, if any.
    pub username: Option<String>,
    /// Peer IP literal the edge saw on the client socket, if forwarded.
    pub peer_host: Option<String>,
    /// Listener scope the connection arrived on (`""` = default).
    /// TODO(parity): the edge does not report listener names yet, so
    /// binds carry the default scope and per-listener rules match only
    /// the default or wildcard scopes until the name is plumbed.
    pub listener: String,
    /// TLS client-certificate common name, where TLS terminates.
    pub cert_cn: Option<String>,
    /// TLS client-certificate subject, where TLS terminates.
    pub cert_subject: Option<String>,
    /// TLS client-certificate subject-alt names, where TLS terminates.
    pub cert_sans: Vec<String>,
    /// MQTT 5 user properties as an opaque map.
    /// TODO(parity): the edge terminates CONNECT as 3.1.1 only with no
    /// property section, so user properties never reach the kernel yet;
    /// absent means the default tenant, never another tenant's
    /// (fail closed). The open question is the wire slot and merge rule
    /// once the codec can carry them.
    pub user_properties: Option<HashMap<String, String>>,
}

/// One tenant-assignment rule: render `expression` against the connect
/// context in the scope of `listener` and store the result as the named
/// client attribute. An empty `listener` (or `"*"`) applies to every
/// listener; otherwise it must equal the connection's listener scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRule {
    /// Listener scope (`""` or `"*"` = all listeners).
    pub listener: String,
    /// Client attribute name (`"tenant"` drives assignment).
    pub attribute: String,
    /// Expression template over the connect context.
    pub expression: String,
}

impl TenantRule {
    /// Create one rule without validation (validation happens in
    /// [`TenantRegistry::replace`] under validate-all-before-apply).
    pub fn new(
        listener: impl Into<String>,
        attribute: impl Into<String>,
        expression: impl Into<String>,
    ) -> Self {
        Self {
            listener: listener.into(),
            attribute: attribute.into(),
            expression: expression.into(),
        }
    }

    /// Validate one rule, naming the field on failure.
    pub fn validate(&self) -> Result<(), String> {
        if self.listener.len() > MAX_TENANT_LISTENER_LEN {
            return Err(format!(
                "field `listener` must not exceed {MAX_TENANT_LISTENER_LEN} chars"
            ));
        }
        if self.attribute.is_empty() {
            return Err("field `attribute` must not be empty".to_string());
        }
        if self.attribute.len() > MAX_TENANT_ATTRIBUTE_LEN {
            return Err(format!(
                "field `attribute` must not exceed {MAX_TENANT_ATTRIBUTE_LEN} chars"
            ));
        }
        if !self
            .attribute
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(
                "field `attribute` may only use letters, digits, underscore and dash".to_string(),
            );
        }
        if self.expression.len() > MAX_TENANT_EXPRESSION_LEN {
            return Err(format!(
                "field `expression` must not exceed {MAX_TENANT_EXPRESSION_LEN} chars"
            ));
        }
        Ok(())
    }
}

/// Bounded in-memory tenant rule list behind one short lock.
///
/// Every method finishes quickly and no publish or deliver path touches
/// it: the connect hook clones the capped list once per bind under a
/// short read and renders off the lock, so management writes never
/// block messaging.
pub struct TenantRegistry {
    inner: parking_lot::RwLock<Vec<TenantRule>>,
    /// Rendered ids rejected to the default tenant (overlong,
    /// control-character or otherwise invalid), counted exactly where
    /// the rejection happens.
    fallbacks: AtomicU64,
}

impl TenantRegistry {
    /// Empty registry: every connect lands in the default tenant.
    pub fn new() -> Self {
        Self {
            inner: parking_lot::RwLock::new(Vec::new()),
            fallbacks: AtomicU64::new(0),
        }
    }

    /// Number of stored rules.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// True when no rule is stored (the shipped default).
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Snapshot of the configured rules in stored order.
    pub fn list(&self) -> Vec<TenantRule> {
        self.inner.read().clone()
    }

    /// Rejections to the default tenant observed so far.
    pub fn fallback_count(&self) -> u64 {
        self.fallbacks.load(Ordering::SeqCst)
    }

    /// Replace the whole list after full validation of every entry.
    ///
    /// Validate-all-before-apply: a single bad entry rejects the entire
    /// write with an error naming the field and index, leaving the
    /// stored list untouched. Lists longer than [`MAX_TENANT_RULES`]
    /// are rejected with the documented `EXCEED_LIMIT`-style shape.
    pub fn replace(&self, next: Vec<TenantRule>) -> Result<(), String> {
        if next.len() > MAX_TENANT_RULES {
            return Err(format!(
                "field `tenants.rules` holds {} entries, at most {MAX_TENANT_RULES} (code EXCEED_LIMIT)",
                next.len()
            ));
        }
        for (index, rule) in next.iter().enumerate() {
            rule.validate()
                .map_err(|reason| format!("tenants.rules[{index}]: {reason}"))?;
        }
        *self.inner.write() = next;
        Ok(())
    }

    /// Assign the tenant id for one connect context.
    ///
    /// Scans the snapshot in order; the first rule scoped to this
    /// listener whose `attribute` is [`TENANT_ATTRIBUTE_NAME`] and whose
    /// expression renders non-empty wins when the rendered id is valid.
    /// Empty/unrenderable results fall through to the next rule and,
    /// when nothing renders, to [`DEFAULT_TENANT_ID`]. An overlong or
    /// control-character result is rejected to the default tenant
    /// (counted once and logged once per rejection, fail closed to the
    /// default, never to another tenant's).
    pub fn assign(&self, ctx: &ConnectContext) -> String {
        let snapshot = self.list();
        for rule in &snapshot {
            if rule.attribute != TENANT_ATTRIBUTE_NAME {
                continue;
            }
            if !(rule.listener.is_empty() || rule.listener == "*" || rule.listener == ctx.listener)
            {
                continue;
            }
            let Some(rendered) = render_expression(&rule.expression, ctx) else {
                continue;
            };
            if is_valid_tenant_id(&rendered) {
                return rendered;
            }
            self.fallbacks.fetch_add(1, Ordering::SeqCst);
            tracing::warn!(
                client_id = %ctx.client_id,
                rendered_len = rendered.len(),
                "Tenant render rejected: overlong or control-character id, using default tenant"
            );
            return DEFAULT_TENANT_ID.to_string();
        }
        DEFAULT_TENANT_ID.to_string()
    }
}

impl Default for TenantRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// True when the rendered id may become a tenant id: non-empty, at most
/// [`MAX_TENANT_ID_LEN`] chars and free of control characters.
pub fn is_valid_tenant_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_TENANT_ID_LEN && !id.chars().any(|c| c.is_control())
}

/// Render one expression template against the connect context.
///
/// Replaces the documented `${clientid}`/`${client_id}`, `${username}`,
/// `${peerhost}`/`${host}`, `${cert_cn}`, `${cert_subject}`,
/// `${cert_sans}` and `${listener}` placeholders. `None` means the
/// default tenant: the template was empty/whitespace-only, or it is
/// unrenderable (an unknown `${...}` variable remains after
/// substitution, so a future variable degrades to the default instead
/// of a silent empty id, or a referenced optional value is absent so
/// the expression cannot render for this client and fails closed to
/// the default, never to another tenant's). Absent user properties
/// render as unrenderable (see the fail-closed `TODO(parity)` on
/// [`ConnectContext::user_properties`]).
pub fn render_expression(template: &str, ctx: &ConnectContext) -> Option<String> {
    if template.trim().is_empty() {
        return None;
    }
    // Fail closed: a referenced optional input that is absent makes the
    // whole expression unrenderable (default tenant), never a partial id
    // such as `cn-` from `cn-${cert_cn}` with no certificate.
    fn missing(value: Option<&str>) -> bool {
        value.map(|s| s.is_empty()).unwrap_or(true)
    }
    if template.contains("${username}") && missing(ctx.username.as_deref()) {
        return None;
    }
    if (template.contains("${peerhost}") || template.contains("${host}"))
        && missing(ctx.peer_host.as_deref())
    {
        return None;
    }
    if template.contains("${cert_cn}") && missing(ctx.cert_cn.as_deref()) {
        return None;
    }
    if template.contains("${cert_subject}") && missing(ctx.cert_subject.as_deref()) {
        return None;
    }
    if template.contains("${cert_sans}") && ctx.cert_sans.is_empty() {
        return None;
    }
    let username = ctx.username.as_deref().unwrap_or("");
    let peerhost = ctx.peer_host.as_deref().unwrap_or("");
    let cert_cn = ctx.cert_cn.as_deref().unwrap_or("");
    let cert_subject = ctx.cert_subject.as_deref().unwrap_or("");
    let cert_sans = ctx.cert_sans.join(",");
    // One pass per variable; templates are short (<= 1 KiB) and the
    // hook runs once per connect, never per message.
    let rendered = template
        .replace("${clientid}", &ctx.client_id)
        .replace("${client_id}", &ctx.client_id)
        .replace("${username}", username)
        .replace("${peerhost}", peerhost)
        .replace("${host}", peerhost)
        .replace("${cert_cn}", cert_cn)
        .replace("${cert_subject}", cert_subject)
        .replace("${cert_sans}", &cert_sans)
        .replace("${listener}", &ctx.listener);
    if rendered.contains("${") {
        return None;
    }
    let trimmed = rendered.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(client_id: &str, username: Option<&str>) -> ConnectContext {
        ConnectContext {
            client_id: client_id.to_string(),
            username: username.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn renders_over_client_id_and_username() {
        let c = ctx("dev-1", Some("alice"));
        assert_eq!(
            render_expression("t-${clientid}", &c).as_deref(),
            Some("t-dev-1")
        );
        assert_eq!(
            render_expression("t-${username}", &c).as_deref(),
            Some("t-alice")
        );
        assert_eq!(
            render_expression("${clientid}/${username}", &c).as_deref(),
            Some("dev-1/alice")
        );
    }

    #[test]
    fn renders_cert_and_peer_inputs() {
        let c = ConnectContext {
            client_id: "dev-9".to_string(),
            peer_host: Some("192.0.2.7".to_string()),
            cert_cn: Some("sensor-9".to_string()),
            cert_subject: Some("CN=sensor-9".to_string()),
            cert_sans: vec!["dns:s9".to_string()],
            ..Default::default()
        };
        assert_eq!(
            render_expression("cn-${cert_cn}", &c).as_deref(),
            Some("cn-sensor-9")
        );
        assert_eq!(
            render_expression("host-${peerhost}", &c).as_deref(),
            Some("host-192.0.2.7")
        );
        assert_eq!(
            render_expression("sans-${cert_sans}", &c).as_deref(),
            Some("sans-dns:s9")
        );
    }

    #[test]
    fn empty_and_unrenderable_fall_back_to_default() {
        let registry = TenantRegistry::new();
        let c = ctx("dev-1", Some("alice"));
        // No rules: default tenant.
        assert_eq!(registry.assign(&c), DEFAULT_TENANT_ID);
        // Empty expression: default tenant.
        registry
            .replace(vec![TenantRule::new("", "tenant", "")])
            .expect("empty template stores");
        assert_eq!(registry.assign(&c), DEFAULT_TENANT_ID);
        // Unknown placeholder: unrenderable, default tenant.
        registry
            .replace(vec![TenantRule::new("", "tenant", "t-${unknown_var}")])
            .expect("future variable stores");
        assert_eq!(registry.assign(&c), DEFAULT_TENANT_ID);
        assert_eq!(registry.fallback_count(), 0);
    }

    #[test]
    fn render_failure_falls_through_to_next_rule() {
        let registry = TenantRegistry::new();
        registry
            .replace(vec![
                TenantRule::new("", "tenant", "t-${unknown_var}"),
                TenantRule::new("", "tenant", "t-${clientid}"),
            ])
            .expect("rules store");
        assert_eq!(registry.assign(&ctx("dev-3", None)), "t-dev-3");
    }

    #[test]
    fn overlong_or_control_results_rejected_with_counter() {
        let registry = TenantRegistry::new();
        // Overlong: a fixed template past the id bound.
        let long = "t-".to_string() + &"x".repeat(MAX_TENANT_ID_LEN);
        registry
            .replace(vec![TenantRule::new("", "tenant", long)])
            .expect("long template stores");
        assert_eq!(registry.assign(&ctx("dev-1", None)), DEFAULT_TENANT_ID);
        assert_eq!(registry.fallback_count(), 1);
        // Control characters: rejected the same way.
        registry
            .replace(vec![TenantRule::new("", "tenant", "bad-\u{0001}-id")])
            .expect("control template stores");
        assert_eq!(registry.assign(&ctx("dev-1", None)), DEFAULT_TENANT_ID);
        assert_eq!(registry.fallback_count(), 2);
    }

    #[test]
    fn overlong_lists_rejected_at_write_time() {
        let registry = TenantRegistry::new();
        let many: Vec<TenantRule> = (0..MAX_TENANT_RULES + 1)
            .map(|i| TenantRule::new("", "tenant", format!("t-{i}")))
            .collect();
        let err = registry.replace(many).expect_err("overlong list must fail");
        assert!(
            err.contains("tenants.rules"),
            "error must name the field, got: {err}"
        );
        assert!(
            err.contains("EXCEED_LIMIT"),
            "error must carry the documented shape, got: {err}"
        );
        assert!(registry.is_empty(), "failed write must not apply");
    }

    #[test]
    fn invalid_entries_rejected_without_applying() {
        let registry = TenantRegistry::new();
        registry
            .replace(vec![TenantRule::new("", "tenant", "t-ok")])
            .expect("seed stores");
        for bad in [
            TenantRule::new("", "", "t-empty-attr"),
            TenantRule::new("", "tenant", "x".repeat(MAX_TENANT_EXPRESSION_LEN + 1)),
            TenantRule::new("l".repeat(MAX_TENANT_LISTENER_LEN + 1), "tenant", "t-x"),
            TenantRule::new("", "bad attr!", "t-x"),
        ] {
            let err = registry
                .replace(vec![bad])
                .expect_err("bad entry must fail");
            assert!(
                err.contains("tenants.rules"),
                "error must name the list, got: {err}"
            );
        }
        assert_eq!(registry.len(), 1, "failed writes must not apply");
    }

    #[test]
    fn per_listener_scope_selects_matching_rule() {
        let registry = TenantRegistry::new();
        registry
            .replace(vec![
                TenantRule::new("tcp", "tenant", "t-tcp"),
                TenantRule::new("tls", "tenant", "t-tls"),
            ])
            .expect("scoped rules store");
        let mut tls_ctx = ctx("dev-1", None);
        tls_ctx.listener = "tls".to_string();
        assert_eq!(registry.assign(&tls_ctx), "t-tls");
        let mut other_ctx = ctx("dev-1", None);
        other_ctx.listener = "ws".to_string();
        assert_eq!(registry.assign(&other_ctx), DEFAULT_TENANT_ID);
    }

    #[test]
    fn non_tenant_attributes_do_not_drive_assignment() {
        let registry = TenantRegistry::new();
        registry
            .replace(vec![TenantRule::new("", "department", "eng-${clientid}")])
            .expect("non-tenant attribute stores");
        assert_eq!(registry.assign(&ctx("dev-1", None)), DEFAULT_TENANT_ID);
    }

    #[test]
    fn bounds_are_finite() {
        const {
            assert!(MAX_TENANT_RULES > 0 && MAX_TENANT_RULES <= 1024);
            assert!(MAX_TENANT_ID_LEN > 0 && MAX_TENANT_ID_LEN <= 1024);
            assert!(MAX_TENANT_EXPRESSION_LEN > 0);
        }
    }
}
