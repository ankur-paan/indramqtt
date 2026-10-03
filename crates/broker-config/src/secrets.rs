//! Secret references for configuration values (M1-05).
//!
//! A secret is never stored inline: configuration holds a reference of the
//! form `file:/path` or `env:NAME`, resolved to bytes at the point of use
//! (authentication, connector construction). Every observable rendering
//! (logs, exports, `explain` output, API responses) shows a redacted marker
//! naming the reference, never the value. A missing or unreadable secret
//! fails closed with an error naming the reference, never the value.
//!
//! The `file:` form reads the file's bytes, stripping a single trailing
//! CR/LF pair so editor-terminated secret files compare equal without
//! changing interior bytes. The `env:` form reads the process environment.
//! TODO(parity): whether `file:` values should be re-read on every use or
//! cached per connection is undecided; resolving at each use is the
//! conservative choice (rotation takes effect immediately) until decided.

use crate::ConfigError;

/// Prefix for file-backed secret references.
pub const FILE_PREFIX: &str = "file:";
/// Prefix for environment-backed secret references.
pub const ENV_PREFIX: &str = "env:";

/// Returns true when `value` is a secret reference (`file:` or `env:`).
#[must_use]
pub fn is_secret_ref(value: &str) -> bool {
    value.starts_with(FILE_PREFIX) || value.starts_with(ENV_PREFIX)
}

/// Parsed form of a secret reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// Read the secret bytes from this filesystem path.
    File(String),
    /// Read the secret bytes from this environment variable.
    Env(String),
}

impl SecretRef {
    /// Parse a reference string. Returns `None` when it is not a reference.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        if let Some(path) = value.strip_prefix(FILE_PREFIX) {
            if path.is_empty() {
                return None;
            }
            Some(Self::File(path.to_string()))
        } else if let Some(name) = value.strip_prefix(ENV_PREFIX) {
            if name.is_empty() {
                return None;
            }
            Some(Self::Env(name.to_string()))
        } else {
            None
        }
    }

    /// The original reference string (`file:...` / `env:...`).
    #[must_use]
    pub fn reference(&self) -> String {
        match self {
            Self::File(path) => format!("{FILE_PREFIX}{path}"),
            Self::Env(name) => format!("{ENV_PREFIX}{name}"),
        }
    }

    /// Observable rendering: a marker naming the reference, never the value.
    #[must_use]
    pub fn redacted(&self) -> String {
        format!("<redacted:{}>", self.reference())
    }
}

/// Redact one configured value for any observable output.
///
/// References render as `<redacted:file:...>` / `<redacted:env:...>`; plain
/// values pass through unchanged (they are not secrets).
#[must_use]
pub fn redact_value(value: &str) -> String {
    match SecretRef::parse(value) {
        Some(reference) => reference.redacted(),
        None => value.to_string(),
    }
}

/// Resolve a reference to its secret bytes, failing closed.
///
/// Errors name the reference, never the value: a missing file, an
/// unreadable file or a missing variable denies the operation that needed
/// the secret. Non-reference input is a caller error naming the problem,
/// never the value.
pub fn resolve_secret(reference: &str) -> Result<Vec<u8>, ConfigError> {
    let parsed = SecretRef::parse(reference).ok_or_else(|| {
        ConfigError::Invalid(format!(
            "secret reference {reference:?} is invalid: must start with `file:` or `env:` (field `secret`)"
        ))
    })?;
    match parsed {
        SecretRef::File(path) => {
            let bytes = std::fs::read(&path).map_err(|err| {
                ConfigError::Invalid(format!(
                    "secret reference {reference:?} cannot be read: {err} (field `secret`)"
                ))
            })?;
            Ok(strip_single_trailing_newline(bytes))
        }
        SecretRef::Env(name) => {
            let value = std::env::var(&name).map_err(|_| {
                ConfigError::Invalid(format!(
                    "secret reference {reference:?} is not set (field `secret`)"
                ))
            })?;
            Ok(value.into_bytes())
        }
    }
}

/// Resolve when the value may be a reference, else return the raw bytes.
///
/// Plain values are returned as-is (backwards compatible with configs that
/// predate references); references go through [`resolve_secret`].
pub fn resolve_maybe_secret(value: &str) -> Result<Vec<u8>, ConfigError> {
    if is_secret_ref(value) {
        resolve_secret(value)
    } else {
        Ok(value.as_bytes().to_vec())
    }
}

/// Strip one trailing `\n` (plus a preceding `\r` when present) so files
/// written with a terminating newline still authenticate.
fn strip_single_trailing_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_both_forms_and_rejects_plain() {
        assert_eq!(
            SecretRef::parse("file:/run/secrets/pw"),
            Some(SecretRef::File("/run/secrets/pw".to_string()))
        );
        assert_eq!(
            SecretRef::parse("env:BROKER_PW"),
            Some(SecretRef::Env("BROKER_PW".to_string()))
        );
        assert_eq!(SecretRef::parse("plaintext"), None);
        assert_eq!(SecretRef::parse("file:"), None);
        assert_eq!(SecretRef::parse("env:"), None);
    }

    #[test]
    fn redacted_names_reference_never_value() {
        let marker = redact_value("env:SOME_VAR");
        assert!(
            marker.contains("env:SOME_VAR"),
            "marker names the reference"
        );
        assert!(!marker.contains("s3cret"), "marker never holds the value");
        assert_eq!(redact_value("plain"), "plain");
    }

    #[test]
    fn missing_secret_fails_closed_naming_reference() {
        let missing = "env:BROKER_CONFIG_TEST_DEFINITELY_UNSET_9F3A";
        let err = resolve_secret(missing).expect_err("unset variable must fail");
        assert!(err.to_string().contains(missing));
        let err = resolve_secret("file:/definitely/not/here-9f3a").expect_err("missing file fails");
        assert!(err.to_string().contains("file:/definitely/not/here-9f3a"));
    }

    #[test]
    fn env_secret_resolves_and_file_strips_newline() {
        std::env::set_var("BROKER_CONFIG_TEST_SECRET_RT", "s3cret-value");
        let bytes = resolve_secret("env:BROKER_CONFIG_TEST_SECRET_RT").expect("env resolves");
        assert_eq!(bytes, b"s3cret-value");
        std::env::remove_var("BROKER_CONFIG_TEST_SECRET_RT");

        let dir = std::env::temp_dir().join(format!("broker-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create dir");
        let path = dir.join("pw");
        std::fs::write(&path, b"file-secret\n").expect("write secret");
        let reference = format!("file:{}", path.display());
        let bytes = resolve_secret(&reference).expect("file resolves");
        assert_eq!(bytes, b"file-secret");
        std::fs::remove_dir_all(&dir).ok();
    }
}
