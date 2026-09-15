//! SCRAM-SHA-256 and fallback authentication for EMQX v5 REST API.

use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use broker_auth::{AclAction, AclRule};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::admin_users::{AdminRole, AdminUserError};
use crate::ApiState;

/// Token lifetime: 60 minutes.
const TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
/// SCRAM challenge lifetime: 60 seconds.
const CHALLENGE_TTL: Duration = Duration::from_secs(60);
/// Upper bound on pending SCRAM challenges (flood cap).
pub(crate) const MAX_PENDING_CHALLENGES: usize = 10_000;

/// In-memory challenge state for pending SCRAM-SHA-256 handshakes.
#[derive(Clone)]
pub(crate) struct ScramChallengeState {
    username: String,
    client_nonce: String,
    _server_nonce: String,
    salt: Vec<u8>,
    iterations: u32,
    created_at: Instant,
}

#[cfg(test)]
impl ScramChallengeState {
    pub(crate) fn for_test(username: &str) -> Self {
        Self {
            username: username.to_string(),
            client_nonce: "test-client-nonce".to_string(),
            _server_nonce: "test-server-nonce".to_string(),
            salt: vec![0u8; 16],
            iterations: 4096,
            created_at: Instant::now(),
        }
    }
}

/// Authenticated identity resolved from a bearer token.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub username: String,
    pub role: AdminRole,
    pub expires_at: Instant,
    pub must_change_password: bool,
}

/// Per-`ApiState` token and SCRAM-challenge store. Lives in `ApiState`
/// (not in process globals) so tests are isolated.
pub struct ApiTokens {
    tokens: Mutex<HashMap<String, TokenInfo>>,
    challenges: Mutex<HashMap<String, ScramChallengeState>>,
}

impl ApiTokens {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a random 32-byte URL-safe token bound to `username`/`role`.
    pub fn issue(&self, username: &str, role: AdminRole) -> String {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = format!("indra_{}", URL_SAFE_NO_PAD.encode(token_bytes));
        let info = TokenInfo {
            username: username.to_string(),
            role,
            expires_at: Instant::now() + TOKEN_TTL,
            must_change_password: false,
        };
        let mut tokens = self.tokens.lock().unwrap();
        let now = Instant::now();
        tokens.retain(|_, v| v.expires_at > now);
        tokens.insert(token.clone(), info);
        token
    }

    /// Look up a token; unknown or expired tokens return `None`.
    /// Expired entries are removed.
    pub fn lookup(&self, token: &str) -> Option<TokenInfo> {
        let mut tokens = self.tokens.lock().unwrap();
        let info = tokens.get(token).cloned()?;
        if info.expires_at > Instant::now() {
            Some(info)
        } else {
            tokens.remove(token);
            None
        }
    }

    /// Revoke one token (logout).
    pub fn revoke(&self, token: &str) {
        self.tokens.lock().unwrap().remove(token);
    }

    /// Issue an already-expired token (tests only).
    #[cfg(test)]
    pub(crate) fn issue_expired(&self, username: &str, role: AdminRole) -> String {
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = format!("indra_{}", URL_SAFE_NO_PAD.encode(token_bytes));
        let info = TokenInfo {
            username: username.to_string(),
            role,
            expires_at: Instant::now() - Duration::from_secs(1),
            must_change_password: false,
        };
        self.tokens.lock().unwrap().insert(token.clone(), info);
        token
    }

    /// Revoke every token of `username` except `keep` (password change).
    pub fn revoke_user_except(&self, username: &str, keep: Option<&str>) {
        self.tokens
            .lock()
            .unwrap()
            .retain(|token, info| info.username != username || Some(token.as_str()) == keep);
    }

    pub(crate) fn insert_challenge(&self, id: String, state: ScramChallengeState) -> bool {
        let mut challenges = self.challenges.lock().unwrap();
        challenges.retain(|_, v| v.created_at.elapsed() < CHALLENGE_TTL);
        if challenges.len() >= MAX_PENDING_CHALLENGES {
            return false;
        }
        challenges.insert(id, state);
        true
    }

    pub(crate) fn take_challenge(&self, id: &str) -> Option<ScramChallengeState> {
        let mut challenges = self.challenges.lock().unwrap();
        let state = challenges.remove(id)?;
        if state.created_at.elapsed() < CHALLENGE_TTL {
            Some(state)
        } else {
            None
        }
    }
}

impl Default for ApiTokens {
    fn default() -> Self {
        Self::new()
    }
}

fn role_str(role: &AdminRole) -> &'static str {
    match role {
        AdminRole::Administrator => "administrator",
        AdminRole::Viewer => "viewer",
    }
}

fn parse_role(raw: &str) -> Option<AdminRole> {
    match raw.to_ascii_lowercase().as_str() {
        "administrator" | "admin" => Some(AdminRole::Administrator),
        "viewer" => Some(AdminRole::Viewer),
        _ => None,
    }
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "code": "FORBIDDEN" })),
    )
        .into_response()
}

fn name_pwd_error() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "code": "NAME_PWD_ERROR",
            "message": "Bad username or password"
        })),
    )
        .into_response()
}

/// Map an `AdminUsers` error onto its HTTP status.
fn admin_error(error: AdminUserError) -> Response {
    let (status, code) = match error {
        AdminUserError::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        AdminUserError::AlreadyExists => (StatusCode::CONFLICT, "ALREADY_EXISTS"),
        AdminUserError::InvalidUsername
        | AdminUserError::WeakPassword
        | AdminUserError::SameAsOld
        | AdminUserError::LastAdministrator => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
    };
    (
        status,
        Json(serde_json::json!({ "code": code, "message": error.to_string() })),
    )
        .into_response()
}

/// Resolve a bearer token through the token store: token lookup, then a
/// fresh load of the user from the store. Tokens of deleted users are
/// revoked and rejected. The returned [`TokenInfo`] carries the current
/// role and `must_change_password` so the middleware needs no second
/// `admin_users` lookup.
pub(crate) fn resolve_bearer(state: &ApiState, token: &str) -> Option<TokenInfo> {
    let info = state.tokens.lookup(token)?;
    let view = match state.admin_users.get(&info.username) {
        Some(view) => view,
        None => {
            state.tokens.revoke(token);
            return None;
        }
    };
    Some(TokenInfo {
        username: info.username,
        role: view.role,
        expires_at: info.expires_at,
        must_change_password: view.must_change_password,
    })
}

/// Resolve `Authorization: Bearer <token>` through the token store,
/// for reuse by SEC-C middleware. Roles are always read fresh from the
/// admin-user store; tokens of deleted users are revoked and rejected.
pub(crate) fn authenticated_user(state: &ApiState, headers: &HeaderMap) -> Option<TokenInfo> {
    match crate::api_auth::parse_credentials(headers)? {
        crate::api_auth::Credentials::Bearer(token) => resolve_bearer(state, &token),
        crate::api_auth::Credentials::Basic { .. } => None,
    }
}

/// Extract the bearer token from already-parsed credentials, if any.
pub(crate) fn bearer_token_from_credentials(headers: &HeaderMap) -> Option<String> {
    match crate::api_auth::parse_credentials(headers)? {
        crate::api_auth::Credentials::Bearer(token) => Some(token),
        crate::api_auth::Credentials::Basic { .. } => None,
    }
}

#[derive(Deserialize)]
pub struct ScramChallengeRequest {
    pub username: String,
    pub client_nonce: String,
}

#[derive(Serialize)]
pub struct ScramChallengeResponse {
    pub mechanism: &'static str,
    pub challenge_id: String,
    pub server_nonce: String,
    pub salt: String,
    pub iterations: u32,
}

pub async fn scram_challenge(
    State(state): State<ApiState>,
    Json(req): Json<ScramChallengeRequest>,
) -> Response {
    let mut rng = rand::thread_rng();
    let mut server_nonce_bytes = [0u8; 24];
    rng.fill_bytes(&mut server_nonce_bytes);
    let server_nonce = BASE64
        .encode(server_nonce_bytes)
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");

    // The stored salt (or a deterministic fake salt for unknown users so
    // names cannot be enumerated). Challenge id and server nonce stay
    // random per handshake.
    let (salt, iterations) = state.admin_users.scram_params(&req.username);
    let salt_b64 = BASE64.encode(&salt);

    let mut challenge_id_bytes = [0u8; 24];
    rng.fill_bytes(&mut challenge_id_bytes);
    let challenge_id = BASE64
        .encode(challenge_id_bytes)
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");

    let inserted = state.tokens.insert_challenge(
        challenge_id.clone(),
        ScramChallengeState {
            username: req.username.clone(),
            client_nonce: req.client_nonce,
            _server_nonce: server_nonce.clone(),
            salt,
            iterations,
            created_at: Instant::now(),
        },
    );
    if !inserted {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "code": "TOO_MANY_REQUESTS",
                "message": "too many pending login challenges"
            })),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(ScramChallengeResponse {
            mechanism: "SCRAM-SHA-256",
            challenge_id,
            server_nonce,
            salt: salt_b64,
            iterations,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct ScramVerifyRequest {
    pub challenge_id: String,
    pub combined_nonce: String,
    pub client_proof: String,
    #[serde(default)]
    pub mfa_token: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub server_signature: String,
    pub version: &'static str,
    pub role: String,
    pub must_change_password: bool,
    pub license: serde_json::Value,
}

pub async fn scram_verify(
    State(state): State<ApiState>,
    Json(req): Json<ScramVerifyRequest>,
) -> Response {
    let ch = {
        let challenge = state.tokens.take_challenge(&req.challenge_id);
        let Some(challenge) = challenge else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "SCRAM_CHALLENGE_INVALID",
                    "message": "Challenge expired or invalid"
                })),
            )
                .into_response();
        };
        challenge
    };

    let client_proof_bytes = match BASE64.decode(&req.client_proof) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "BAD_REQUEST",
                    "message": "Invalid client_proof encoding"
                })),
            )
                .into_response();
        }
    };

    let escaped_user = ch.username.replace('=', "=3D").replace(',', "=2C");
    let salt_b64 = BASE64.encode(&ch.salt);
    let auth_message = format!(
        "n={},r={},r={},s={},i={},c=biws,r={}",
        escaped_user,
        ch.client_nonce,
        req.combined_nonce,
        salt_b64,
        ch.iterations,
        req.combined_nonce
    );

    // Verify against the stored SCRAM credentials. Unknown users fail here:
    // `scram_verify` returns `None` when the user does not exist. Login
    // never creates or modifies users.
    let server_sig =
        match state
            .admin_users
            .scram_verify(&ch.username, &auth_message, &client_proof_bytes)
        {
            Some(sig) => sig,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "code": "NAME_PWD_ERROR",
                        "message": "Invalid credentials"
                    })),
                )
                    .into_response();
            }
        };
    let server_sig_b64 = BASE64.encode(server_sig);

    let Some(view) = state.admin_users.get(&ch.username) else {
        return name_pwd_error();
    };
    let role = view.role;
    let must_change_password = view.must_change_password;
    let token = state.tokens.issue(&ch.username, role);

    (
        StatusCode::OK,
        Json(LoginResponse {
            token,
            server_signature: server_sig_b64,
            version: "5.8.0",
            role: role_str(&role).to_string(),
            must_change_password,
            license: serde_json::json!({
                "edition": "enterprise",
                "valid": true,
                "customer_name": "IndraMQTT Core"
            }),
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct DirectLoginRequest {
    pub username: String,
    pub password: String,
}

pub async fn direct_login(
    State(state): State<ApiState>,
    Json(req): Json<DirectLoginRequest>,
) -> Response {
    // Only the admin-user store decides. The default `admin`/`public`
    // already lives there; there is no shortcut and no MQTT-store fallback.
    if !state
        .admin_users
        .verify_password(&req.username, &req.password)
    {
        return name_pwd_error();
    }

    let Some(view) = state.admin_users.get(&req.username) else {
        return name_pwd_error();
    };
    let role = view.role;
    let must_change_password = view.must_change_password;
    let token = state.tokens.issue(&req.username, role);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "token": token,
            "version": "5.8.0",
            "role": role_str(&role),
            "must_change_password": must_change_password,
            "license": {
                "edition": "enterprise",
                "valid": true,
                "customer_name": "IndraMQTT Core"
            }
        })),
    )
        .into_response()
}

pub async fn logout(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Some(token) = bearer_token_from_credentials(&headers) {
        state.tokens.revoke(&token);
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn current_user(
    State(state): State<ApiState>,
    Extension(info): Extension<TokenInfo>,
) -> Response {
    // The middleware guarantees a valid token; `info` already carries the
    // fresh role. Re-read the remaining profile fields.
    let Some(view) = state.admin_users.get(&info.username) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "code": "UNAUTHORIZED" })),
        )
            .into_response();
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "username": view.username,
            "role": role_str(&view.role).to_string(),
            "must_change_password": view.must_change_password,
        })),
    )
        .into_response()
}

pub async fn user_scopes() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "scopes": [
                "all",
                "user_management",
                "monitoring",
                "rules",
                "connectors",
                "clients",
                "subscriptions",
                "gateways",
                "listeners"
            ]
        })),
    )
        .into_response()
}

/// Dashboard/API users live in the admin-user store only. MQTT client
/// credentials stay in `MemoryAuth` behind the `/authentication/.../users`
/// and v1 `/auth/users` endpoints.
pub async fn list_users(State(state): State<ApiState>) -> Response {
    let users: Vec<_> = state
        .admin_users
        .list()
        .into_iter()
        .map(|u| {
            serde_json::json!({
                "username": u.username,
                "role": role_str(&u.role),
                "description": u.description,
            })
        })
        .collect();
    (StatusCode::OK, Json(users)).into_response()
}

#[derive(Deserialize)]
pub struct CreateUserReq {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

pub async fn create_user(
    State(state): State<ApiState>,
    Json(req): Json<CreateUserReq>,
) -> Response {
    // Authentication and the administrator role are enforced by the
    // middleware; the handler only validates the payload.
    let role = match req.role.as_deref() {
        None => AdminRole::Administrator,
        Some(raw) => match parse_role(raw) {
            Some(role) => role,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "code": "BAD_REQUEST",
                        "message": "role must be administrator or viewer"
                    })),
                )
                    .into_response();
            }
        },
    };
    let description = req.description.unwrap_or_default();
    if let Err(error) = state
        .admin_users
        .create(&req.username, &req.password, role, &description)
    {
        return admin_error(error);
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "username": req.username,
            "role": role_str(&role),
            "description": description
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct UpdateUserReq {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

pub async fn update_user(
    State(state): State<ApiState>,
    Path(username): Path<String>,
    Json(req): Json<UpdateUserReq>,
) -> Response {
    if let Some(raw) = req.role.as_deref() {
        let role = match parse_role(raw) {
            Some(role) => role,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "code": "BAD_REQUEST",
                        "message": "role must be administrator or viewer"
                    })),
                )
                    .into_response();
            }
        };
        if let Err(error) = state.admin_users.set_role(&username, role) {
            return admin_error(error);
        }
    }
    if let Some(description) = req.description.as_deref() {
        if let Err(error) = state.admin_users.set_description(&username, description) {
            return admin_error(error);
        }
    }
    match state.admin_users.get(&username) {
        Some(view) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "username": view.username,
                "role": role_str(&view.role),
                "description": view.description
            })),
        )
            .into_response(),
        None => admin_error(AdminUserError::NotFound),
    }
}

pub async fn delete_user(State(state): State<ApiState>, Path(username): Path<String>) -> Response {
    match state.admin_users.delete(&username) {
        Ok(()) => {
            state.tokens.revoke_user_except(&username, None);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => admin_error(error),
    }
}

#[derive(Deserialize)]
pub struct ChangePasswordReq {
    #[serde(default)]
    pub old_pwd: Option<String>,
    #[serde(default)]
    pub new_pwd: Option<String>,
}

/// `PUT /users/:username/change_pwd {old_pwd, new_pwd}` (EMQX-compatible).
/// Administrators may change any user's password; viewers only their own.
/// `old_pwd` is required when changing your own password. The middleware
/// guarantees a valid token; the self-or-administrator rule stays here.
pub async fn change_user_password(
    State(state): State<ApiState>,
    Extension(caller): Extension<TokenInfo>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(req): Json<ChangePasswordReq>,
) -> Response {
    let is_self = caller.username == username;
    if !is_self && caller.role != AdminRole::Administrator {
        return forbidden();
    }
    if state.admin_users.get(&username).is_none() {
        return admin_error(AdminUserError::NotFound);
    }
    if is_self {
        let Some(old_pwd) = req.old_pwd.as_deref() else {
            return name_pwd_error();
        };
        if !state.admin_users.verify_password(&username, old_pwd) {
            return name_pwd_error();
        }
    }
    let Some(new_pwd) = req.new_pwd.as_deref() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": "BAD_REQUEST",
                "message": "new_pwd must not be empty"
            })),
        )
            .into_response();
    };
    if let Err(error) = state.admin_users.change_password(&username, new_pwd) {
        return admin_error(error);
    }
    // Revoke that user's other tokens; the caller's token keeps working.
    state.tokens.revoke_user_except(
        &username,
        bearer_token_from_credentials(&headers).as_deref(),
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({ "username": username })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Authentication (AuthN) Provider Endpoints
// ---------------------------------------------------------------------------

pub async fn list_authentication() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!([
            {
                "id": "password_based:built_in_database",
                "mechanism": "password_based",
                "backend": "built_in_database",
                "user_id_type": "username",
                "enable": true,
                "status": "running"
            }
        ])),
    )
        .into_response()
}

pub async fn get_authentication(Path(id): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "mechanism": "password_based",
            "backend": "built_in_database",
            "user_id_type": "username",
            "enable": true,
            "status": "running"
        })),
    )
        .into_response()
}

pub async fn create_authentication(Json(body): Json<serde_json::Value>) -> Response {
    (StatusCode::CREATED, Json(body)).into_response()
}

pub async fn update_authentication(
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut resp = body;
    if let Some(obj) = resp.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(id));
    }
    (StatusCode::OK, Json(resp)).into_response()
}

pub async fn delete_authentication(Path(_id): Path<String>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn list_authn_users(State(state): State<ApiState>, Path(_id): Path<String>) -> Response {
    let names = state.auth.usernames();
    let data: Vec<_> = names
        .into_iter()
        .map(|name| {
            serde_json::json!({
                "user_id": name,
                "is_superuser": false,
                "created_at": "2026-09-13T21:00:00Z"
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": {
                "page": 1,
                "limit": 50,
                "count": data.len(),
                "hasnext": false
            }
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct CreateAuthnUserReq {
    pub user_id: String,
    pub password: String,
    #[serde(default)]
    pub is_superuser: bool,
}

pub async fn create_authn_user(
    State(state): State<ApiState>,
    Path(_id): Path<String>,
    Json(req): Json<CreateAuthnUserReq>,
) -> Response {
    state
        .auth
        .add_user(req.user_id.clone(), req.password.as_bytes());
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "user_id": req.user_id,
            "is_superuser": req.is_superuser
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct UpdateAuthnUserReq {
    pub password: String,
}

pub async fn update_authn_user(
    State(state): State<ApiState>,
    Path((_id, user_id)): Path<(String, String)>,
    Json(req): Json<UpdateAuthnUserReq>,
) -> Response {
    state
        .auth
        .add_user(user_id.clone(), req.password.as_bytes());
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "user_id": user_id
        })),
    )
        .into_response()
}

pub async fn delete_authn_user(
    State(state): State<ApiState>,
    Path((_id, user_id)): Path<(String, String)>,
) -> Response {
    state.auth.remove_user(&user_id);
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Authorization (AuthZ / ACL) Endpoints
// ---------------------------------------------------------------------------

pub async fn list_authorization_sources() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "sources": [
                {
                    "type": "built_in_database",
                    "enable": true,
                    "status": "running"
                }
            ]
        })),
    )
        .into_response()
}

pub async fn get_authorization_settings() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "no_match": "allow",
            "deny_action": "ignore",
            "cache": {
                "enable": true,
                "max_size": 32768,
                "ttl": "1m"
            }
        })),
    )
        .into_response()
}

pub async fn update_authorization_settings() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn clear_authorization_cache() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn list_authz_rules(
    State(state): State<ApiState>,
    Path(_type): Path<String>,
) -> Response {
    let rules = state.auth.acl_rules();
    let data: Vec<_> = rules
        .into_iter()
        .enumerate()
        .map(|(idx, r)| {
            serde_json::json!({
                "id": idx,
                "clientid": r.client_pattern,
                "action": match r.action {
                    AclAction::Publish => "publish",
                    AclAction::Subscribe => "subscribe",
                    AclAction::All => "all",
                },
                "topic": r.topic_pattern,
                "permission": if r.allow { "allow" } else { "deny" }
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": {
                "page": 1,
                "limit": 100,
                "count": data.len(),
                "hasnext": false
            }
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct CreateAuthzRuleReq {
    pub clientid: Option<String>,
    pub action: String,
    pub topic: String,
    pub permission: String,
}

pub async fn create_authz_rule(
    State(state): State<ApiState>,
    Path(_type): Path<String>,
    Json(req): Json<CreateAuthzRuleReq>,
) -> Response {
    let client_pattern = req.clientid.unwrap_or_else(|| "*".to_string());
    let action = match AclAction::parse(&req.action) {
        Some(a) => a,
        None => AclAction::All,
    };
    let allow = req.permission.to_lowercase() == "allow";

    state
        .auth
        .add_rule(AclRule::new(client_pattern, action, req.topic, allow));
    StatusCode::CREATED.into_response()
}

pub async fn delete_authz_rule(
    State(state): State<ApiState>,
    Path((_type, index)): Path<(String, usize)>,
) -> Response {
    if state.auth.remove_rule(index) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
