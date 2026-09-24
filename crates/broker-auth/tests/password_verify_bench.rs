//! Pipeline benchmark hook for B5-01 password hashing.
//!
//! Hot-path numbers are measured by the pipeline, never by an agent
//! (rulebook "Where do numbers come from?"): the gates run this file
//! three times on the base commit (with this file copied in) and three
//! times on the tree, and the numbers land in the gates log as lines
//! starting `BENCH <metric> <value> <unit>`.
//!
//! Base-commit compatibility: this file uses only broker-auth and
//! broker-config interfaces that exist on the base commit
//! (`MemoryAuth::new`, `MemoryAuth::from_snapshot`, `add_user`,
//! `authenticate`, `MqttUser`, `MqttUsersConf`). It deliberately does
//! not reference the task's new constructors (`add_user_with_algorithm`,
//! `PasswordHashPolicy`, `PasswordAlgorithm`, `verifier_string`), so the
//! same file compiles and runs on both sides. Per-algorithm entries are
//! seeded through `from_snapshot` as stored-verifier string literals:
//! on the tree each literal parses to its real verifier, while on the
//! base commit (SHA-256 only) the non-hex literals lock fail-closed and
//! the run measures the base `authenticate` path without the task's new
//! work. Outcomes per slot are printed as plain `outcome` lines so the
//! before/after logs stay interpretable; only `BENCH` lines carry
//! numbers.
//!
//! What each slot measures is the per-CONNECT verification cost the
//! slow verifiers sit next to: one `authenticate` round per attempt,
//! which is the cost every credentialed CONNECT pays through
//! `crates/broker-node/src/main.rs` (`shared.auth.authenticate`). The
//! expensive verifiers run in `spawn_blocking` off the accept path
//! while CONNECT still awaits the verdict, gated by a semaphore with
//! `MAX_CONCURRENT_VERIFICATIONS` permits (exhaustion fails closed);
//! the per-connection copy is bounded by `MAX_PASSWORD_BYTES` (8 KiB).
//!
//! Verifier literals and their parameters (fixed so CI stays fast; the
//! production default is measured separately through the migration and
//! default slots):
//! - sha256legacy: hex SHA-256 of `bench-secret` (legacy 64-hex form,
//!   verifies on both sides).
//! - bcrypt: cost-04 `$2a$` vector for password `password` (taken from
//!   the maintained bcrypt primitive's own test data for this exact
//!   crate generation, so it verifies on the tree).
//! - pbkdf2sha256: `$pbkdf2-sha256$1000$<salt-b64>$<key-b64>` for
//!   password `bench-pbkdf2-secret` (16-byte salt, 32-byte key,
//!   1,000 iterations; fast enough for CI while exercising the PBKDF2
//!   path end to end).
//! - argon2id: no literal. A second legacy entry migrates to the
//!   configured default on its first successful login, so the timed
//!   attempts after warm-up measure Argon2id at the production default
//!   parameters on the tree (19 MiB, 2 passes, 1 lane) and the legacy
//!   path on the base commit.
//! - connect_auth_per_sec: a user created with `add_user` (the tree
//!   default, i.e. production Argon2id; SHA-256 on the base commit),
//!   measuring sequential CONNECT-rate authentications per second.
//!
//! The sha256legacy slot times wrong-password attempts: a failed legacy
//! check performs the same digest plus constant-time compare as a
//! success but never triggers migration, so every timed attempt
//! measures the legacy verifier rather than the migrated one.

use broker_auth::{Authenticator, MemoryAuth};
use broker_config::{MqttUser, MqttUsersConf};
use std::hint::black_box;
use std::time::Instant;

/// Hex SHA-256 of `bench-secret` (the legacy stored form).
const LEGACY_HEX: &str = "0159438a9235d6abde38e49fb98944660d067d6b9b03d8a8f4ee4e522feb62cb";
/// Cost-04 bcrypt verifier for password `password`.
const BCRYPT_VERIFIER: &str = "$2a$04$UuTkLRZZ6QofpDOlMz32MuuxEHA43WOemOYHPz6.SjsVsyO1tDU96";
/// PBKDF2-SHA256 verifier (1,000 iterations) for `bench-pbkdf2-secret`.
const PBKDF2_VERIFIER: &str =
    "$pbkdf2-sha256$1000$ABEiM0RVZneImaq7zN3u/w==$NlGorl5w9qOObnVnV9pYN1b1lf2PMcz/T0DdAKD1IYc=";

fn snapshot_user(username: &str, password_hash: &str) -> MqttUser {
    MqttUser {
        username: username.to_string(),
        password_hash: password_hash.to_string(),
        max_connections: None,
        max_publish_rate: None,
        max_publish_burst: None,
    }
}

/// Time `iters` sequential `authenticate` rounds and return
/// (mean_us, max_us). `expect_ok` asserts success (only for slots that
/// verify on both sides); slots that lock fail-closed on the base
/// commit report their outcome without asserting.
async fn time_authenticates(
    auth: &MemoryAuth,
    username: &str,
    password: &[u8],
    iters: usize,
    expect_ok: bool,
) -> (f64, f64, bool) {
    let mut latencies_us: Vec<f64> = Vec::with_capacity(iters);
    let mut last_ok = false;
    for i in 0..iters {
        let start = Instant::now();
        let outcome = auth
            .authenticate("bench-conn", Some(username), Some(password))
            .await;
        black_box(&outcome);
        last_ok = outcome.is_ok();
        if expect_ok {
            assert!(last_ok, "attempt {i} for {username} must verify");
        }
        latencies_us.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    let mean_us = latencies_us.iter().sum::<f64>() / latencies_us.len() as f64;
    let max_us = latencies_us.iter().cloned().fold(0.0f64, f64::max);
    (mean_us, max_us, last_ok)
}

/// Pipeline benchmark hook (B5-01 connect path): per-attempt
/// `authenticate` cost per algorithm plus CONNECT throughput, printing
/// `BENCH` lines for the gates. `#[ignore]` so normal `cargo test`
/// runs skip it and the pipeline's bench runner picks it up
/// explicitly.
#[tokio::test]
#[ignore]
async fn password_verify_per_algorithm_bench() {
    let conf = MqttUsersConf {
        users: vec![
            snapshot_user("bench-sha256", LEGACY_HEX),
            snapshot_user("bench-bcrypt", BCRYPT_VERIFIER),
            snapshot_user("bench-pbkdf2", PBKDF2_VERIFIER),
            snapshot_user("bench-migrate", LEGACY_HEX),
        ],
        acls: vec![],
    };
    let auth = MemoryAuth::from_snapshot(&conf);

    // sha256legacy: wrong-password attempts measure the digest plus
    // constant-time compare without triggering migration. Fails on both
    // sides by construction.
    let (mean_us, max_us, _) =
        time_authenticates(&auth, "bench-sha256", b"wrong-secret", 20, false).await;
    println!("outcome sha256legacy ok=false (wrong-password probe, expected)");
    println!("BENCH verify_sha256legacy_mean_us {mean_us:.1} us");
    println!("BENCH verify_sha256legacy_max_us {max_us:.1} us");

    // bcrypt at cost 04 (fast CI vector; production uses cost 12).
    let (mean_us, max_us, ok) =
        time_authenticates(&auth, "bench-bcrypt", b"password", 10, false).await;
    println!("outcome bcrypt ok={ok} (ok on tree, fail-closed on base)");
    println!("BENCH verify_bcrypt_mean_us {mean_us:.1} us");
    println!("BENCH verify_bcrypt_max_us {max_us:.1} us");

    // PBKDF2-SHA256 at 1,000 iterations (fast CI vector; production
    // uses 600,000).
    let (mean_us, max_us, ok) =
        time_authenticates(&auth, "bench-pbkdf2", b"bench-pbkdf2-secret", 10, false).await;
    println!("outcome pbkdf2sha256 ok={ok} (ok on tree, fail-closed on base)");
    println!("BENCH verify_pbkdf2sha256_mean_us {mean_us:.1} us");
    println!("BENCH verify_pbkdf2sha256_max_us {max_us:.1} us");

    // argon2id at the production default via migration: the warm-up
    // login migrates the legacy entry (tree) and is excluded from the
    // window; the timed attempts measure the migrated verifier.
    let warmup = auth
        .authenticate("bench-conn", Some("bench-migrate"), Some(b"bench-secret"))
        .await;
    black_box(&warmup);
    assert!(warmup.is_ok(), "migration warm-up must verify");
    let (mean_us, max_us, ok) =
        time_authenticates(&auth, "bench-migrate", b"bench-secret", 5, true).await;
    println!("outcome argon2id ok={ok} (production default on tree, legacy on base)");
    println!("BENCH verify_argon2id_mean_us {mean_us:.1} us");
    println!("BENCH verify_argon2id_max_us {max_us:.1} us");

    // CONNECT throughput with the default-algorithm credential: what a
    // fresh deployment pays per CONNECT (production Argon2id on the
    // tree, SHA-256 on the base commit).
    let default_auth = MemoryAuth::new();
    default_auth
        .add_user("bench-default", b"bench-secret")
        .expect("memory-only persist cannot fail");
    let iters = 5usize;
    let start = Instant::now();
    for i in 0..iters {
        let outcome = default_auth
            .authenticate("bench-conn", Some("bench-default"), Some(b"bench-secret"))
            .await;
        black_box(&outcome);
        assert!(outcome.is_ok(), "default attempt {i} must verify");
    }
    let per_sec = iters as f64 / start.elapsed().as_secs_f64();
    println!("BENCH connect_auth_per_sec {per_sec:.1} per_sec");
}
