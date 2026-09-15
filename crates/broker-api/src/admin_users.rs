//! Management API users, separate from MQTT client credentials.
//!
//! Holds dashboard/API users with SCRAM-SHA-256 credentials (RFC 5802),
//! roles and the must-change-password flag. The MQTT `MemoryAuth` store
//! is untouched; this store is the only home for API users.

use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

/// Iterations for PBKDF2-HMAC-SHA-256 (`SCRAM-SHA-256` default).
const ITERATIONS: u32 = 4096;
/// Salt length for newly created credentials.
const SALT_LEN: usize = 16;
/// Minimum accepted password length.
const MIN_PASSWORD_LEN: usize = 8;

/// Role of a management API user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRole {
    Administrator,
    Viewer,
}

/// Public view of one admin user (no credential material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminUserView {
    pub username: String,
    pub role: AdminRole,
    pub description: String,
    pub must_change_password: bool,
}

/// Errors from [`AdminUsers`] mutations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminUserError {
    AlreadyExists,
    NotFound,
    WeakPassword,
    SameAsOld,
    LastAdministrator,
    InvalidUsername,
}

impl fmt::Display for AdminUserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => write!(f, "user already exists"),
            Self::NotFound => write!(f, "user not found"),
            Self::WeakPassword => write!(f, "password is too weak"),
            Self::SameAsOld => write!(f, "new password is the same as the old one"),
            Self::LastAdministrator => write!(f, "cannot remove the last administrator"),
            Self::InvalidUsername => write!(f, "invalid username"),
        }
    }
}

impl std::error::Error for AdminUserError {}

struct AdminUser {
    username: String,
    role: AdminRole,
    description: String,
    salt: Vec<u8>,
    iterations: u32,
    stored_key: [u8; 32],
    server_key: [u8; 32],
    must_change_password: bool,
}

/// Management API users with SCRAM-SHA-256 credentials.
pub struct AdminUsers {
    users: RwLock<HashMap<String, AdminUser>>,
    process_secret: [u8; 32],
}

impl AdminUsers {
    /// Store containing only `admin` / `public`, Administrator,
    /// `must_change_password = true`.
    pub fn with_default_admin() -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let store = Self {
            users: RwLock::new(HashMap::new()),
            process_secret: secret,
        };
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let (stored_key, server_key) = derive_keys(b"public", &salt, ITERATIONS);
        store.users.write().unwrap().insert(
            "admin".to_string(),
            AdminUser {
                username: "admin".to_string(),
                role: AdminRole::Administrator,
                description: "Default administrator".to_string(),
                salt: salt.to_vec(),
                iterations: ITERATIONS,
                stored_key,
                server_key,
                must_change_password: true,
            },
        );
        store
    }

    pub fn create(
        &self,
        username: &str,
        password: &str,
        role: AdminRole,
        description: &str,
    ) -> Result<(), AdminUserError> {
        if !is_valid_username(username) {
            return Err(AdminUserError::InvalidUsername);
        }
        if password.chars().count() < MIN_PASSWORD_LEN {
            return Err(AdminUserError::WeakPassword);
        }
        let mut users = self.users.write().unwrap();
        if users.contains_key(username) {
            return Err(AdminUserError::AlreadyExists);
        }
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let (stored_key, server_key) = derive_keys(password.as_bytes(), &salt, ITERATIONS);
        users.insert(
            username.to_string(),
            AdminUser {
                username: username.to_string(),
                role,
                description: description.to_string(),
                salt: salt.to_vec(),
                iterations: ITERATIONS,
                stored_key,
                server_key,
                must_change_password: false,
            },
        );
        Ok(())
    }

    pub fn delete(&self, username: &str) -> Result<(), AdminUserError> {
        let mut users = self.users.write().unwrap();
        let user = users.get(username).ok_or(AdminUserError::NotFound)?;
        if user.role == AdminRole::Administrator
            && users
                .values()
                .filter(|u| u.role == AdminRole::Administrator)
                .count()
                == 1
        {
            return Err(AdminUserError::LastAdministrator);
        }
        users.remove(username);
        Ok(())
    }

    pub fn set_role(&self, username: &str, role: AdminRole) -> Result<(), AdminUserError> {
        let mut users = self.users.write().unwrap();
        let current = users.get(username).ok_or(AdminUserError::NotFound)?;
        if current.role == AdminRole::Administrator
            && role == AdminRole::Viewer
            && users
                .values()
                .filter(|u| u.role == AdminRole::Administrator)
                .count()
                == 1
        {
            return Err(AdminUserError::LastAdministrator);
        }
        if let Some(user) = users.get_mut(username) {
            user.role = role;
        }
        Ok(())
    }

    pub fn set_description(&self, username: &str, description: &str) -> Result<(), AdminUserError> {
        let mut users = self.users.write().unwrap();
        let user = users.get_mut(username).ok_or(AdminUserError::NotFound)?;
        user.description = description.to_string();
        Ok(())
    }

    pub fn change_password(
        &self,
        username: &str,
        new_password: &str,
    ) -> Result<(), AdminUserError> {
        if new_password.chars().count() < MIN_PASSWORD_LEN {
            return Err(AdminUserError::WeakPassword);
        }
        let mut users = self.users.write().unwrap();
        let user = users.get(username).ok_or(AdminUserError::NotFound)?;
        let (candidate_stored, _) =
            derive_keys(new_password.as_bytes(), &user.salt, user.iterations);
        if constant_time_eq(&candidate_stored, &user.stored_key) {
            return Err(AdminUserError::SameAsOld);
        }
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let (stored_key, server_key) = derive_keys(new_password.as_bytes(), &salt, ITERATIONS);
        if let Some(user) = users.get_mut(username) {
            user.salt = salt.to_vec();
            user.iterations = ITERATIONS;
            user.stored_key = stored_key;
            user.server_key = server_key;
            user.must_change_password = false;
        }
        Ok(())
    }

    /// Constant-time check of `password` against the stored `StoredKey`.
    pub fn verify_password(&self, username: &str, password: &str) -> bool {
        let found: Option<(Vec<u8>, u32, [u8; 32])> = {
            let users = self.users.read().unwrap();
            users
                .get(username)
                .map(|user| (user.salt.clone(), user.iterations, user.stored_key))
        };
        match found {
            Some((salt, iterations, stored_key)) => {
                let (candidate_stored, _) = derive_keys(password.as_bytes(), &salt, iterations);
                constant_time_eq(&candidate_stored, &stored_key)
            }
            None => {
                let fake = self.fake_salt(username);
                let (candidate_stored, _) = derive_keys(password.as_bytes(), &fake, ITERATIONS);
                let dummy = [0u8; 32];
                let _ = constant_time_eq(&candidate_stored, &dummy);
                false
            }
        }
    }

    fn fake_salt(&self, username: &str) -> Vec<u8> {
        let full = hmac_sha256(&self.process_secret, username.as_bytes());
        full[..SALT_LEN].to_vec()
    }

    /// Stored salt + iterations, or a deterministic fake salt for unknown
    /// users so names cannot be enumerated.
    pub fn scram_params(&self, username: &str) -> (Vec<u8>, u32) {
        let users = self.users.read().unwrap();
        if let Some(user) = users.get(username) {
            return (user.salt.clone(), user.iterations);
        }
        (self.fake_salt(username), ITERATIONS)
    }

    /// Verify an RFC 5802 client proof against the stored `StoredKey`.
    /// Returns the server signature when valid.
    pub fn scram_verify(
        &self,
        username: &str,
        auth_message: &str,
        client_proof: &[u8],
    ) -> Option<[u8; 32]> {
        if client_proof.len() != 32 {
            return None;
        }
        let users = self.users.read().unwrap();
        let user = users.get(username)?;
        let client_signature = hmac_sha256(&user.stored_key, auth_message.as_bytes());
        let mut client_key = [0u8; 32];
        for i in 0..32 {
            client_key[i] = client_proof[i] ^ client_signature[i];
        }
        let candidate_stored: [u8; 32] = Sha256::digest(client_key).into();
        if !constant_time_eq(&candidate_stored, &user.stored_key) {
            return None;
        }
        Some(hmac_sha256(&user.server_key, auth_message.as_bytes()))
    }

    pub fn get(&self, username: &str) -> Option<AdminUserView> {
        let users = self.users.read().unwrap();
        users.get(username).map(|u| AdminUserView {
            username: u.username.clone(),
            role: u.role,
            description: u.description.clone(),
            must_change_password: u.must_change_password,
        })
    }

    pub fn list(&self) -> Vec<AdminUserView> {
        let users = self.users.read().unwrap();
        let mut out: Vec<AdminUserView> = users
            .values()
            .map(|u| AdminUserView {
                username: u.username.clone(),
                role: u.role,
                description: u.description.clone(),
                must_change_password: u.must_change_password,
            })
            .collect();
        out.sort_by(|a, b| a.username.cmp(&b.username));
        out
    }

    /// Test-only insert with a fixed salt/iterations (e.g. RFC vectors).
    #[cfg(test)]
    pub(crate) fn insert_with_salt(
        &self,
        username: &str,
        password: &str,
        salt: &[u8],
        iterations: u32,
        role: AdminRole,
        description: &str,
    ) {
        let (stored_key, server_key) = derive_keys(password.as_bytes(), salt, iterations);
        self.users.write().unwrap().insert(
            username.to_string(),
            AdminUser {
                username: username.to_string(),
                role,
                description: description.to_string(),
                salt: salt.to_vec(),
                iterations,
                stored_key,
                server_key,
                must_change_password: false,
            },
        );
    }
}

fn derive_keys(password: &[u8], salt: &[u8], iterations: u32) -> ([u8; 32], [u8; 32]) {
    let salted = pbkdf2_hmac_sha256(password, salt, iterations);
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key: [u8; 32] = Sha256::digest(client_key).into();
    let server_key = hmac_sha256(&salted, b"Server Key");
    (stored_key, server_key)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hash = Sha256::digest(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut salt_and_block = Vec::with_capacity(salt.len() + 4);
    salt_and_block.extend_from_slice(salt);
    salt_and_block.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac_sha256(password, &salt_and_block);
    let mut result = u;

    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for (r, v) in result.iter_mut().zip(u.iter()) {
            *r ^= *v;
        }
    }
    result
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn is_valid_username(username: &str) -> bool {
    if username.is_empty() || username.len() > 64 {
        return false;
    }
    username
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'@'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    #[test]
    fn default_admin_logs_in_and_must_change() {
        let store = AdminUsers::with_default_admin();
        assert!(store.verify_password("admin", "public"));
        let view = store.get("admin").expect("default admin exists");
        assert_eq!(view.role, AdminRole::Administrator);
        assert!(view.must_change_password);
    }

    #[test]
    fn change_password_clears_flag_and_old_password_fails() {
        let store = AdminUsers::with_default_admin();
        store
            .change_password("admin", "N3w-passw0rd")
            .expect("password change succeeds");
        assert!(!store.verify_password("admin", "public"));
        assert!(store.verify_password("admin", "N3w-passw0rd"));
        assert!(
            !store
                .get("admin")
                .expect("admin exists")
                .must_change_password
        );
        assert_eq!(
            store.change_password("admin", "N3w-passw0rd"),
            Err(AdminUserError::SameAsOld)
        );
        assert_eq!(
            store.change_password("admin", "short"),
            Err(AdminUserError::WeakPassword)
        );
    }

    #[test]
    fn scram_verify_rfc7677_vector() {
        let store = AdminUsers::with_default_admin();
        let salt = BASE64
            .decode("W22ZaJ0SNY7soEsUEjb6gQ==")
            .expect("valid salt");
        store.insert_with_salt(
            "user",
            "pencil",
            &salt,
            4096,
            AdminRole::Administrator,
            "rfc",
        );
        let auth_message = "n=user,r=rOprNGfwEbeRWgbNEkqO,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        let proof = BASE64
            .decode("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
            .expect("valid proof");
        let sig = store
            .scram_verify("user", auth_message, &proof)
            .expect("rfc proof verifies");
        assert_eq!(
            BASE64.encode(sig),
            "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
        );
        let mut bad = proof.clone();
        bad[0] ^= 1;
        assert!(store.scram_verify("user", auth_message, &bad).is_none());
    }

    #[test]
    fn unknown_user_gets_stable_fake_salt() {
        let store = AdminUsers::with_default_admin();
        let (first, _) = store.scram_params("ghost");
        let (second, _) = store.scram_params("ghost");
        assert_eq!(first, second);
        let (other, _) = store.scram_params("phantom");
        assert_ne!(first, other);
    }

    #[test]
    fn last_administrator_cannot_be_deleted_or_demoted() {
        let store = AdminUsers::with_default_admin();
        assert_eq!(
            store.delete("admin"),
            Err(AdminUserError::LastAdministrator)
        );
        assert_eq!(
            store.set_role("admin", AdminRole::Viewer),
            Err(AdminUserError::LastAdministrator)
        );
        store
            .create("admin2", "L0ng-passw0rd", AdminRole::Administrator, "")
            .expect("second admin");
        store
            .set_role("admin", AdminRole::Viewer)
            .expect("demote with backup admin");
        store.delete("admin").expect("delete demoted admin");
        assert_eq!(
            store.delete("admin2"),
            Err(AdminUserError::LastAdministrator)
        );
    }

    #[test]
    fn viewer_roles_and_listing() {
        let store = AdminUsers::with_default_admin();
        store
            .create("bob", "B0b-passw0rd", AdminRole::Viewer, "ro")
            .expect("create viewer");
        store
            .create("alice", "Al1ce-passw0rd", AdminRole::Administrator, "ops")
            .expect("create admin");
        let list = store.list();
        let names: Vec<&str> = list.iter().map(|u| u.username.as_str()).collect();
        assert_eq!(names, vec!["admin", "alice", "bob"]);
        let bob = list
            .iter()
            .find(|u| u.username == "bob")
            .expect("bob listed");
        assert_eq!(bob.role, AdminRole::Viewer);
        assert!(!bob.must_change_password);
        let alice = list
            .iter()
            .find(|u| u.username == "alice")
            .expect("alice listed");
        assert_eq!(alice.role, AdminRole::Administrator);
    }

    #[test]
    fn create_rejects_invalid_usernames() {
        let store = AdminUsers::with_default_admin();
        for name in ["", "a b", "x\n", &"a".repeat(65)] {
            assert_eq!(
                store.create(name, "L0ng-passw0rd", AdminRole::Viewer, ""),
                Err(AdminUserError::InvalidUsername),
                "name {name:?} must be rejected"
            );
        }
        store
            .create("ops.team-1@site", "L0ng-passw0rd", AdminRole::Viewer, "")
            .expect("valid username is accepted");
    }

    #[test]
    fn verify_password_unknown_user_is_false() {
        let store = AdminUsers::with_default_admin();
        assert!(!store.verify_password("ghost", "public"));
    }
}
