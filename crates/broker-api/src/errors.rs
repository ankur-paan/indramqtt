//! Shared EMQX error codes with `{code, message}` responses.
//!
//! Every management handler must reject with the EMQX error code name the
//! spec assigns to that failure (`CLIENTID_NOT_FOUND`, not `NOT_FOUND`,
//! for a missing client). Today each handler hand-rolls its own literals
//! and several use the wrong code; this module is the single place the
//! code names, their HTTP statuses, and the response shape live so future
//! callers cannot drift. No handler migrates to it yet (a later wave does
//! that); this task only adds the type and its tests.

use axum::{http::StatusCode, response::IntoResponse, Json};

/// One EMQX management error: a spec code name plus human detail.
///
/// Each variant carries the `message` string rendered alongside `code`;
/// use [`EmqxError::with_message`] to replace the detail while keeping
/// the variant (and therefore the code name and HTTP status).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmqxError {
    /// Generic resource miss (`GET /rules/:id`, connectors, schemas).
    NotFound(String),
    /// Malformed request body, query, or topic filter.
    BadRequest(String),
    /// `GET /clients/:clientid` for an unknown client id. Distinct from
    /// [`EmqxError::NotFound`]: the spec assigns this endpoint its own
    /// code name.
    ClientIdNotFound(String),
    /// Dashboard/API login with a wrong username or password.
    BadUsernameOrPwd(String),
    /// Legacy login failure code kept for the endpoints that already
    /// render it.
    NamePwdError(String),
    /// Login and SCRAM challenge rate limiting.
    TooManyRequests(String),
    /// Creating a user, rule, or connector that already exists.
    AlreadyExists(String),
    /// Authenticated caller lacking the required scope or role.
    NotAuthorized(String),
    /// Forbidden operation under the current licence or node role.
    Forbidden(String),
    /// Unknown listener id in listener-scoped routes.
    BadListenerId(String),
    /// Unknown node name in node-scoped routes.
    BadNode(String),
    /// Rule SQL dry-run (`POST /rules/test`) that does not match.
    TestFailed(String),
    /// Connector or action probe that could not connect to its target.
    ConnectionFailed(String),
    /// Missing, expired, or malformed bearer token / API key.
    Unauthorized(String),
}

impl EmqxError {
    /// The exact EMQX code name rendered as `code` in the response body.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "NOT_FOUND",
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::ClientIdNotFound(_) => "CLIENTID_NOT_FOUND",
            Self::BadUsernameOrPwd(_) => "BAD_USERNAME_OR_PWD",
            Self::NamePwdError(_) => "NAME_PWD_ERROR",
            Self::TooManyRequests(_) => "TOO_MANY_REQUESTS",
            Self::AlreadyExists(_) => "ALREADY_EXISTS",
            Self::NotAuthorized(_) => "NOT_AUTHORIZED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::BadListenerId(_) => "BAD_LISTENER_ID",
            Self::BadNode(_) => "BAD_NODE",
            Self::TestFailed(_) => "TEST_FAILED",
            Self::ConnectionFailed(_) => "CONNECTION_FAILED",
            Self::Unauthorized(_) => "UNAUTHORIZED",
        }
    }

    /// The human detail rendered as `message` in the response body.
    pub fn message(&self) -> &str {
        match self {
            Self::NotFound(message)
            | Self::BadRequest(message)
            | Self::ClientIdNotFound(message)
            | Self::BadUsernameOrPwd(message)
            | Self::NamePwdError(message)
            | Self::TooManyRequests(message)
            | Self::AlreadyExists(message)
            | Self::NotAuthorized(message)
            | Self::Forbidden(message)
            | Self::BadListenerId(message)
            | Self::BadNode(message)
            | Self::TestFailed(message)
            | Self::ConnectionFailed(message)
            | Self::Unauthorized(message) => message,
        }
    }

    /// The HTTP status the spec assigns to this code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound(_)
            | Self::ClientIdNotFound(_)
            | Self::BadListenerId(_)
            | Self::BadNode(_) => StatusCode::NOT_FOUND,
            Self::BadRequest(_)
            | Self::AlreadyExists(_)
            | Self::TestFailed(_)
            | Self::ConnectionFailed(_) => StatusCode::BAD_REQUEST,
            Self::BadUsernameOrPwd(_) | Self::NamePwdError(_) | Self::Unauthorized(_) => {
                StatusCode::UNAUTHORIZED
            }
            Self::NotAuthorized(_) | Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    /// Replace the detail string, keeping the variant (code and status).
    pub fn with_message(self, message: impl Into<String>) -> Self {
        let message = message.into();
        match self {
            Self::NotFound(_) => Self::NotFound(message),
            Self::BadRequest(_) => Self::BadRequest(message),
            Self::ClientIdNotFound(_) => Self::ClientIdNotFound(message),
            Self::BadUsernameOrPwd(_) => Self::BadUsernameOrPwd(message),
            Self::NamePwdError(_) => Self::NamePwdError(message),
            Self::TooManyRequests(_) => Self::TooManyRequests(message),
            Self::AlreadyExists(_) => Self::AlreadyExists(message),
            Self::NotAuthorized(_) => Self::NotAuthorized(message),
            Self::Forbidden(_) => Self::Forbidden(message),
            Self::BadListenerId(_) => Self::BadListenerId(message),
            Self::BadNode(_) => Self::BadNode(message),
            Self::TestFailed(_) => Self::TestFailed(message),
            Self::ConnectionFailed(_) => Self::ConnectionFailed(message),
            Self::Unauthorized(_) => Self::Unauthorized(message),
        }
    }
}

impl IntoResponse for EmqxError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status_code();
        let body = serde_json::json!({
            "code": self.code(),
            "message": self.message(),
        });
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::Response;

    /// Read a rendered error response back into status + JSON body.
    async fn response_parts(err: EmqxError) -> (StatusCode, serde_json::Value) {
        let response: Response = err.into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("error body is small and readable");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("error body is JSON");
        (status, body)
    }

    /// One instance of every variant, so table-driven tests cover the
    /// whole enum without a caller having to enumerate it again.
    fn every_variant() -> Vec<EmqxError> {
        vec![
            EmqxError::NotFound("missing".to_string()),
            EmqxError::BadRequest("bad input".to_string()),
            EmqxError::ClientIdNotFound("no such client".to_string()),
            EmqxError::BadUsernameOrPwd("wrong credentials".to_string()),
            EmqxError::NamePwdError("wrong credentials".to_string()),
            EmqxError::TooManyRequests("slow down".to_string()),
            EmqxError::AlreadyExists("duplicate".to_string()),
            EmqxError::NotAuthorized("no scope".to_string()),
            EmqxError::Forbidden("denied".to_string()),
            EmqxError::BadListenerId("no such listener".to_string()),
            EmqxError::BadNode("no such node".to_string()),
            EmqxError::TestFailed("rule did not match".to_string()),
            EmqxError::ConnectionFailed("target unreachable".to_string()),
            EmqxError::Unauthorized("no token".to_string()),
        ]
    }

    #[tokio::test]
    async fn each_code_renders_its_status_and_exact_shape() {
        let expected: Vec<(&str, StatusCode)> = vec![
            ("NOT_FOUND", StatusCode::NOT_FOUND),
            ("BAD_REQUEST", StatusCode::BAD_REQUEST),
            ("CLIENTID_NOT_FOUND", StatusCode::NOT_FOUND),
            ("BAD_USERNAME_OR_PWD", StatusCode::UNAUTHORIZED),
            ("NAME_PWD_ERROR", StatusCode::UNAUTHORIZED),
            ("TOO_MANY_REQUESTS", StatusCode::TOO_MANY_REQUESTS),
            ("ALREADY_EXISTS", StatusCode::BAD_REQUEST),
            ("NOT_AUTHORIZED", StatusCode::FORBIDDEN),
            ("FORBIDDEN", StatusCode::FORBIDDEN),
            ("BAD_LISTENER_ID", StatusCode::NOT_FOUND),
            ("BAD_NODE", StatusCode::NOT_FOUND),
            ("TEST_FAILED", StatusCode::BAD_REQUEST),
            ("CONNECTION_FAILED", StatusCode::BAD_REQUEST),
            ("UNAUTHORIZED", StatusCode::UNAUTHORIZED),
        ];
        let variants = every_variant();
        assert_eq!(variants.len(), expected.len());
        for (err, (code, status)) in variants.into_iter().zip(expected) {
            // `status_code()` agrees with the rendered HTTP status.
            assert_eq!(err.status_code(), status, "status for {code}");
            let message = err.message().to_string();
            let (rendered_status, body) = response_parts(err).await;
            assert_eq!(rendered_status, status, "HTTP status for {code}");
            assert_eq!(
                body,
                serde_json::json!({ "code": code, "message": message }),
                "exact body for {code}"
            );
        }
    }

    #[tokio::test]
    async fn not_found_and_clientid_not_found_are_distinct_codes() {
        let generic = EmqxError::NotFound("rule nope".to_string());
        let client = EmqxError::ClientIdNotFound("client nope".to_string());
        assert_ne!(generic.code(), client.code());
        assert_eq!(generic.code(), "NOT_FOUND");
        assert_eq!(client.code(), "CLIENTID_NOT_FOUND");
        // Both are 404s; only the code name differs.
        assert_eq!(generic.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(client.status_code(), StatusCode::NOT_FOUND);
        let (_, generic_body) = response_parts(generic).await;
        let (_, client_body) = response_parts(client).await;
        assert_eq!(generic_body["code"], serde_json::json!("NOT_FOUND"));
        assert_eq!(client_body["code"], serde_json::json!("CLIENTID_NOT_FOUND"));
    }

    #[tokio::test]
    async fn with_message_preserves_dynamic_detail() {
        let err =
            EmqxError::BadRequest("placeholder".to_string()).with_message("topic t/#/x bad: {e}");
        assert_eq!(err.code(), "BAD_REQUEST");
        assert_eq!(err.message(), "topic t/#/x bad: {e}");
        let (status, body) = response_parts(err).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], serde_json::json!("BAD_REQUEST"));
        assert_eq!(body["message"], serde_json::json!("topic t/#/x bad: {e}"));

        // `with_message` keeps the variant: code and status are unchanged.
        let renamed = EmqxError::NotFound("a".to_string()).with_message("b".to_string());
        assert_eq!(renamed.code(), "NOT_FOUND");
        assert_eq!(renamed.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(renamed.message(), "b");
    }

    #[test]
    fn error_body_has_exactly_code_and_message_keys() {
        // The shape is exactly `{code, message}`: no extra keys, no
        // nesting, no renamed fields.
        for err in every_variant() {
            let value = serde_json::json!({
                "code": err.code(),
                "message": err.message(),
            });
            let object = value.as_object().expect("error body is an object");
            assert_eq!(object.len(), 2);
            assert!(object.contains_key("code"));
            assert!(object.contains_key("message"));
        }
    }

    /// Exhaustive match over every variant with no wildcard arm: adding a
    /// variant breaks compilation here until its code name is pinned.
    fn code_by_match(err: &EmqxError) -> &'static str {
        match err {
            EmqxError::NotFound(_) => "NOT_FOUND",
            EmqxError::BadRequest(_) => "BAD_REQUEST",
            EmqxError::ClientIdNotFound(_) => "CLIENTID_NOT_FOUND",
            EmqxError::BadUsernameOrPwd(_) => "BAD_USERNAME_OR_PWD",
            EmqxError::NamePwdError(_) => "NAME_PWD_ERROR",
            EmqxError::TooManyRequests(_) => "TOO_MANY_REQUESTS",
            EmqxError::AlreadyExists(_) => "ALREADY_EXISTS",
            EmqxError::NotAuthorized(_) => "NOT_AUTHORIZED",
            EmqxError::Forbidden(_) => "FORBIDDEN",
            EmqxError::BadListenerId(_) => "BAD_LISTENER_ID",
            EmqxError::BadNode(_) => "BAD_NODE",
            EmqxError::TestFailed(_) => "TEST_FAILED",
            EmqxError::ConnectionFailed(_) => "CONNECTION_FAILED",
            EmqxError::Unauthorized(_) => "UNAUTHORIZED",
        }
    }

    #[test]
    fn every_variant_is_matched_exhaustively() {
        for err in every_variant() {
            assert_eq!(code_by_match(&err), err.code());
        }
    }
}
