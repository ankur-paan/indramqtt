//! Management API authentication middleware (SEC-C1).
//!
//! Every route except the public ones (login endpoints, health checks,
//! static dashboard assets, MQTT-over-WebSocket) requires credentials.
//! The middleware resolves them, enforces the must-change-password gate
//! and the viewer read-only rule, and publishes the resolved
//! [`TokenInfo`] into request extensions for handlers.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::admin_users::AdminRole;
use crate::v5::auth::{authenticated_user, TokenInfo};
use crate::ApiState;

/// Credentials presented on a management API request.
///
/// EMQX 6.3 accepts `Authorization: Bearer <dashboard token>` and
/// `Authorization: Basic <api_key:api_secret>` on `/api/v5`. There is no
/// API key store yet, so Basic credentials never resolve; the single
/// [`resolve_credentials`] function stays the one place that changes when
/// the store lands.
#[derive(Debug)]
pub enum Credentials {
    Bearer(String),
    Basic { username: String, secret: String },
}

/// Parse the `Authorization` header into [`Credentials`].
/// Only the `Bearer` and `Basic` schemes (case-insensitive) are accepted;
/// anything else, including a bare token with no scheme, returns `None`.
pub fn parse_credentials(headers: &HeaderMap) -> Option<Credentials> {
    let value = headers.get("authorization")?.to_str().ok()?;
    if let Some(token) = strip_scheme(value, "Bearer") {
        if token.is_empty() {
            return None;
        }
        return Some(Credentials::Bearer(token.to_string()));
    }
    if let Some(decoded) = strip_scheme(value, "Basic") {
        let bytes = base64_decode(decoded)?;
        let text = String::from_utf8(bytes).ok()?;
        let (username, secret) = text.split_once(':')?;
        if username.is_empty() {
            return None;
        }
        return Some(Credentials::Basic {
            username: username.to_string(),
            secret: secret.to_string(),
        });
    }
    None
}

/// Resolve credentials to an authenticated identity.
///
/// Bearer tokens go through the token store (fresh roles, tokens of
/// deleted users revoked). Basic API keys have no store yet and always
/// resolve to unknown. Keep all credential resolution here so the API key
/// store plugs in later without touching routes or handlers.
pub fn resolve_credentials(state: &ApiState, headers: &HeaderMap) -> Option<TokenInfo> {
    authenticated_user(state, headers)
}

fn strip_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    if value.len() > scheme.len()
        && value[..scheme.len()].eq_ignore_ascii_case(scheme)
        && value[scheme.len()..].starts_with(' ')
    {
        Some(value[scheme.len() + 1..].trim())
    } else {
        None
    }
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    BASE64.decode(input.trim()).ok()
}

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "code": "UNAUTHORIZED", "message": message })),
    )
        .into_response()
}

fn password_change_required() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "code": "PASSWORD_CHANGE_REQUIRED",
            "message": "password change required before using the API"
        })),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "code": "FORBIDDEN",
            "message": "insufficient permissions"
        })),
    )
        .into_response()
}

/// Path of `PUT`/`POST /api/v5/users/<own username>/change_pwd`, the one
/// mutating route a must-change-password user may still call. The username
/// segment is percent-decoded before comparing; malformed encodings never
/// match.
pub(crate) fn is_own_change_pwd(method: &axum::http::Method, path: &str, username: &str) -> bool {
    if *method != axum::http::Method::PUT && *method != axum::http::Method::POST {
        return false;
    }
    let Some(rest) = path.strip_prefix("/api/v5/users/") else {
        return false;
    };
    let Some((name, tail)) = rest.split_once('/') else {
        return false;
    };
    if tail != "change_pwd" {
        return false;
    }
    let Some(decoded) = percent_decode(name) else {
        return false;
    };
    decoded == username
}

/// Tiny `%XX` percent-decoder for a single path segment. Returns `None`
/// on malformed encodings (`%` not followed by two hex digits, including
/// a truncated tail).
fn percent_decode(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_val(bytes[i + 1])?;
            let lo = hex_val(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Require authentication on every route behind this layer.
///
/// Exemptions are structural: public routes (login, health, dashboard
/// assets, `/ws/mqtt`) never pass through here. Inside, the only
/// exemptions are logout and current_user plus a user's own password
/// change while `must_change_password` is set, and GET-only access for
/// viewers.
pub async fn require_api_auth(State(state): State<ApiState>, req: Request, next: Next) -> Response {
    let Some(info) = resolve_credentials(&state, req.headers()) else {
        return unauthorized("missing or invalid credentials");
    };
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // `resolve_credentials` already loaded the user fresh from the store
    // (revoking tokens of deleted users), so `info` carries the current
    // role and `must_change_password` with no second `admin_users.get`.
    let must_change = info.must_change_password;

    let is_logout = method == axum::http::Method::POST && path == "/api/v5/logout";
    let is_current_user = method == axum::http::Method::GET && path == "/api/v5/current_user";
    let own_change = is_own_change_pwd(&method, &path, &info.username);

    if must_change && !(own_change || is_logout || is_current_user) {
        return password_change_required();
    }
    if info.role == AdminRole::Viewer
        && !(method == axum::http::Method::GET || is_logout || own_change)
    {
        return forbidden();
    }

    let mut req = req;
    req.extensions_mut().insert(info);
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", value.parse().expect("header value"));
        headers
    }

    #[test]
    fn parses_bearer_case_insensitively() {
        let creds = parse_credentials(&headers_with("Bearer abc123")).expect("bearer");
        assert!(matches!(creds, Credentials::Bearer(ref t) if t == "abc123"));
        let creds = parse_credentials(&headers_with("bearer abc123")).expect("lowercase");
        assert!(matches!(creds, Credentials::Bearer(ref t) if t == "abc123"));
    }

    #[test]
    fn parses_basic_credentials() {
        // "admin:secret" in base64.
        let creds = parse_credentials(&headers_with("Basic YWRtaW46c2VjcmV0")).expect("basic");
        match creds {
            Credentials::Basic { username, secret } => {
                assert_eq!(username, "admin");
                assert_eq!(secret, "secret");
            }
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_and_empty_credentials() {
        assert!(parse_credentials(&HeaderMap::new()).is_none());
        assert!(parse_credentials(&headers_with("Bearer ")).is_none());
        assert!(parse_credentials(&headers_with("Basic !!!not-base64!!!")).is_none());
    }

    #[test]
    fn matches_own_change_pwd_path() {
        let put = axum::http::Method::PUT;
        assert!(is_own_change_pwd(
            &put,
            "/api/v5/users/admin/change_pwd",
            "admin"
        ));
        assert!(!is_own_change_pwd(
            &put,
            "/api/v5/users/other/change_pwd",
            "admin"
        ));
        assert!(!is_own_change_pwd(
            &axum::http::Method::GET,
            "/api/v5/users/admin/change_pwd",
            "admin"
        ));
        assert!(!is_own_change_pwd(&put, "/api/v5/users/admin", "admin"));
    }
}
