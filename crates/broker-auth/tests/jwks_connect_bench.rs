//! Pipeline benchmark hook for B5-02 JWKS refresh (T-95).
//!
//! Hot-path numbers are measured by the pipeline, never by an agent
//! (rulebook §2 "Where do numbers come from?"): the gates run this file
//! three times on the base commit (with this file copied in) and three
//! times on the tree, and the numbers land in the gates log as `BENCH`
//! lines. The spec needs a line
//! `BENCH: crates/broker-auth/tests/jwks_connect_bench.rs :: cargo test -p broker-auth --test jwks_connect_bench -- --ignored --nocapture --test-threads=1`
//! for the pipeline to pick it up.
//!
//! Base-commit compatibility: the gates copy only this file onto the base
//! commit, where the JWKS types do not exist yet, so the JWKS legs (cached
//! key hit, unknown-`kid` miss with one bounded HTTPS fetch) compile under
//! the `jwks-bench` feature (on by default on the tree). Without the
//! feature the same file falls back to the base CONNECT credential check
//! (`MemoryAuth::authenticate`, the only CONNECT authentication on the
//! base commit) under the same four `BENCH` metric names: the base run
//! measures that path without the task's new work, the tree run with it.
//! Outcomes per leg are printed as plain `outcome` lines so the
//! before/after logs stay interpretable; only `BENCH` lines carry
//! numbers.
//!
//! What the tree leg measures is the per-CONNECT `JwksAuthenticator::verify_token`
//! cost against a real loopback HTTPS JWKS endpoint: the hit leg pays one
//! cache read plus one RS256 verification with no fetch, the miss leg
//! (unknown `kid`) pays one bounded HTTPS fetch capped by
//! `fetch_timeout_ms` plus verification, then fails closed. Memory stays
//! flat: one cached key and no per-iteration allocation beyond the check
//! itself, so the measured cost is handling, not growth.
//!
//! The RSA keygen/HTTPS-server helpers are intentionally inline in this
//! one file (mirroring `crate::jwks_test_support`, which this file cannot
//! import): the pipeline copies only this file onto the base commit for
//! the before-numbers, so a shared import would not resolve there.

#[cfg(not(feature = "jwks-bench"))]
use broker_auth::{Authenticator, MemoryAuth};
#[cfg(feature = "jwks-bench")]
use broker_auth::{JwksAuthenticator, JwksConfig};
use std::hint::black_box;
#[cfg(feature = "jwks-bench")]
use std::sync::Arc;
use std::time::Instant;

/// Loopback HTTPS fixture certificate (same generation as the unit
/// fixtures: `openssl req -x509 -newkey rsa:2048 -days 3650
/// -subj /CN=localhost` plus `subjectAltName=IP:127.0.0.1,DNS:localhost`).
/// Test-only trust: the bench disables TLS verification on loopback.
/// Tree-only (`jwks-bench`): the base commit has no JWKS types.
#[cfg(feature = "jwks-bench")]
const BENCH_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIDJTCCAg2gAwIBAgIUHGyuPek7PZ/bqQKavEGif5TDKBwwDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkyNDAwMzAwNVoXDTM2MDky\nMTAwMzAwNVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAtdkihZVps667YXbUFntwwvjsoiWqrXqZmHuSh24KpDuu\nvvfzM+VuaO0O52OMJkDCbZE2GZz7mSQDaVNRfYG2z4MhQa95x4+AOBIA0f695Frh\n4plsm9zOnHdSCm/UD1UrkAvfwDuxC7vdEcsVtXAH024Y8O5+ogzcorjDwTB2BTLV\n6PLnPfwDgdsIkvH93dE2CNZ701fsxyepGa/hBEUx0IrYLroOxGZRXEs6fViGdVO4\nMffBZ9qFHJvRQNEf1UXscqkRPA5JkIQfbLw4xaGcbf1HB8ce42gD8GtMIS3czADi\nTzcbrd7SXq8alw73TW3DgLvuxypxDFvzI+59xLhqLQIDAQABo28wbTAdBgNVHQ4E\nFgQUrTQoqWVIzqrZqiKz6XbHAAx0eCowHwYDVR0jBBgwFoAUrTQoqWVIzqrZqiKz\n6XbHAAx0eCowDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARhwR/AAABgglsb2Nh\nbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAJPAiEsiOQylm9mooNhwchbZR60RLWM4\nHOQ2k1MEtX8BWpfHEFpgmlLKCDfaMlLSoTl5JHsZdinDAXoTexrN8ifMx9fOQttO\nQF50qYweJzkjOsmZmZd522t6covj7+odIG/FEqfXQHa9BisoFPox74B1GyDYd9K2\nBORFO61WQZhhtSltUSyhXAWLgxJTaqJWsSavf9qYWPs5oeOvs4aLvBzLhtx12NLI\nJL9Qi5rzXxzal7vqZYmiRMq8pH3Gi7DKpjScwRd/to07AetvvOGoyfdIcZS8vlF0\n16i1jz/RPXS8eTPl/XmQBz0bXYpTVJGkcx5lnGZLma7oNXCP+dp/v8s=\n-----END CERTIFICATE-----\n";
/// Tree-only (`jwks-bench`): the base commit has no JWKS types.
#[cfg(feature = "jwks-bench")]
const BENCH_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC12SKFlWmzrrth\ndtQWe3DC+OyiJaqtepmYe5KHbgqkO66+9/Mz5W5o7Q7nY4wmQMJtkTYZnPuZJANp\nU1F9gbbPgyFBr3nHj4A4EgDR/r3kWuHimWyb3M6cd1IKb9QPVSuQC9/AO7ELu90R\nyxW1cAfTbhjw7n6iDNyiuMPBMHYFMtXo8uc9/AOB2wiS8f3d0TYI1nvTV+zHJ6kZ\nr+EERTHQitguug7EZlFcSzp9WIZ1U7gx98Fn2oUcm9FA0R/VRexyqRE8DkmQhB9s\nvDjFoZxt/UcHxx7jaAPwa0whLdzMAOJPNxut3tJerxqXDvdNbcOAu+7HKnEMW/Mj\n7n3EuGotAgMBAAECggEAIsdSWOYIfzrtz2ggi+Qz3rYo26IEkIUgFw+bKJedJWfc\ntd1KACTjBuI/tXVOeopsJPReumtRmypOFLjAnxZN1kYn+B4NVmNVjGO1EHR98MyI\n4wOgx/Zk9XvEjwZwMjaBzFzZADTqWWomj56dmkPA22j1EC8svOVk1SItHiecisWp\noGSNJ/gDkAx0kK3c5YFobBAZZyP4nIIdpXBiAHypk4DT1cSIHEy4dFN9JVzLP/0k\nmD7jsovLvn4R8a6lSnMvescUoliHqE7kTOTd3OSLiXri+EjfvkS61zyjEB9DL+pH\ni4dVxWUJUBDnWUbNFqhYaJ03pXnXGkRbTlAJfe286QKBgQDdinXuCNHUTzQfDA5C\nkpnXndj1Sl+7f7aKSK1iLzf0Iy9X8AO9gamxNa68b3uY0dSnE1eICkOEqfcM64sI\nhV5wcR0tLER7fAIBkhzZZh3zlvYUn99WSb4QjR7oAUlLT0OSsoFidOaXXiTL1GQR\nndLplurj1mCZIu4KCpgFXNbhTwKBgQDSIiaWV71p0JLNUWjd592VnZdqCbztAsKR\n5ZjUrchJZb23F8aT6LrQFgceaNWvfdNd+AjB71la1y0xfIR9AOSLcprQDrPUBuT1\nYIrPYrunkrhZbvm3N1S3oGtESayzfYbJ6urh2i8JBXqC1s2SCdoFzmojmWHfBHEG\nFohZz4fFwwKBgQDYjEsRzVUtLe5ImsQllp8B/6zet0A0SnXnXXr9CiKrZOkWD+nY\nBzIToeGXF3G8wv4WAfYBZ+bveiOeYW6ZeaQCTM60JR0bhu9/EY9ZgVOtktYe+taX\nxaUfEJIxPXCjSGtIrWuDDbmII+Hby1O1VIuhAH/BDP+HMHl1Hz3RoBn6SQKBgErc\nh8q/72cnO2WSPz3vQO3weuT4GyqE9TRtC4mZb+VWLcRw3/oJy6QedOLMjnQ663Zq\nyxPsZXULe7pJlhnCm6liZu0Aj+hVnHQetNU1Y41LpAmYk7ZGLBRPPmfRp4k6iy6c\nVpmn1WHtZbv/MrV4dQfkhcOw/UEqn+l/VYxJdyFpAoGBAI+8qzjBnHSDUr3uDX7e\n21MBoYGPzGlYwom5zEhNM2xbHvZ6Dt+c5aB308q4Wq88At6eLFtFAaTJwNFEgz/3\n/yp8G6egdnUbScWzpG5qQQ4LiBjjzHrP7Y1LGWMBeDuaD74M2uByICuEyZmJUTTT\n2rpyA7NR3vcZpXi/ZeWghtZb\n-----END PRIVATE KEY-----\n";

/// One RSA-2048 signing key minted at bench start (real RSA, real RS256
/// via `jsonwebtoken`; nothing is mocked).
/// Tree-only (`jwks-bench`): the base commit has no JWKS types.
#[cfg(feature = "jwks-bench")]
struct BenchKey {
    kid: String,
    private_der: Vec<u8>,
    n_b64: String,
    e_b64: String,
}

#[cfg(feature = "jwks-bench")]
impl BenchKey {
    fn generate(kid: &str) -> Self {
        use rsa::pkcs1::EncodeRsaPrivateKey as _;
        use rsa::traits::PublicKeyParts as _;
        // `rsa` 0.9 expects `rand_core` 0.6 while the workspace uses `rand`
        // 0.10: bridge the two with a thin adapter over the workspace RNG
        // (a CSPRNG, so marking it `CryptoRng` is sound).
        struct CompatRng(rand::rngs::ThreadRng);
        impl rsa::rand_core::RngCore for CompatRng {
            fn next_u32(&mut self) -> u32 {
                rand::Rng::next_u32(&mut self.0)
            }
            fn next_u64(&mut self) -> u64 {
                rand::Rng::next_u64(&mut self.0)
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                rand::Rng::fill_bytes(&mut self.0, dest)
            }
            fn try_fill_bytes(
                &mut self,
                dest: &mut [u8],
            ) -> std::result::Result<(), rsa::rand_core::Error> {
                rand::Rng::fill_bytes(&mut self.0, dest);
                Ok(())
            }
        }
        impl rsa::rand_core::CryptoRng for CompatRng {}
        let mut rng = CompatRng(rand::rng());
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA key generates");
        let public = rsa::RsaPublicKey::from(&private);
        let der = private
            .to_pkcs1_der()
            .expect("private key encodes")
            .as_bytes()
            .to_vec();
        Self {
            kid: kid.to_string(),
            private_der: der,
            n_b64: bench_b64(public.n().to_bytes_be()),
            e_b64: bench_b64(public.e().to_bytes_be()),
        }
    }

    fn jwk_json(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": self.n_b64,
            "e": self.e_b64,
        })
    }

    fn mint(&self) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock reads")
            .as_secs() as i64;
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        let key = jsonwebtoken::EncodingKey::from_rsa_der(&self.private_der);
        let claims = serde_json::json!({
            "sub": "device-1",
            "iss": "https://issuer.example",
            "aud": "indra-mqtt",
            "iat": now,
            "exp": now + 3600,
        });
        jsonwebtoken::encode(&header, &claims, &key).expect("token mints")
    }
}

#[cfg(feature = "jwks-bench")]
fn bench_b64(bytes: Vec<u8>) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Minimal real HTTPS JWKS server on loopback serving one fixed key set
/// at `/jwks.json` (real TLS via `tokio-rustls`, real HTTP/1.1 framing).
/// Tree-only (`jwks-bench`): the base commit has no JWKS types.
#[cfg(feature = "jwks-bench")]
async fn start_bench_server(keys: Vec<serde_json::Value>) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let keys = Arc::new(parking_lot::RwLock::new(keys));
    let mut cert_reader = std::io::BufReader::new(BENCH_CERT_PEM.as_bytes());
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .expect("fixture cert reads")
            .into_iter()
            .map(rustls::pki_types::CertificateDer::from)
            .collect();
    assert!(!certs.is_empty(), "fixture holds a certificate");
    let mut key_reader = std::io::BufReader::new(BENCH_KEY_PEM.as_bytes());
    let mut private_key = None;
    while let Some(item) = rustls_pemfile::read_one(&mut key_reader).expect("fixture key reads") {
        if let rustls_pemfile::Item::PKCS8Key(key) = item {
            private_key = Some(rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()));
            break;
        }
    }
    let private_key = private_key.expect("fixture holds a private key");
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .expect("TLS config builds");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback binds");
    let addr = listener.local_addr().expect("addr reads");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let keys = Arc::clone(&keys);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let Ok(n) = tls.read(&mut buf).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&buf[..n]);
                let path = request
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let (status, body) = if path == "/jwks.json" {
                    let keys = keys.read();
                    ("200 OK", serde_json::json!({ "keys": *keys }).to_string())
                } else {
                    ("404 Not Found", String::new())
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(reply.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    format!("https://{addr}/jwks.json")
}

/// Pipeline benchmark hook (B5-02 CONNECT path): `verify_token` cache-hit
/// cost (hit leg) and unknown-`kid` miss cost with one bounded HTTPS fetch
/// per CONNECT (miss leg) through the real JWKS verifier, printing `BENCH`
/// lines for the gates. `#[ignore]` so normal `cargo test` runs skip it
/// and the pipeline's bench runner picks it up explicitly.
/// Tree-only (`jwks-bench`): the base commit runs the fallback below.
#[cfg(feature = "jwks-bench")]
#[tokio::test]
#[ignore]
async fn jwks_connect_auth_cost() {
    let signing = BenchKey::generate("bench-key-a");
    let url = start_bench_server(vec![signing.jwk_json()]).await;
    let auth = JwksAuthenticator::new(JwksConfig {
        jwks_url: url,
        issuer: "https://issuer.example".to_string(),
        audience: "indra-mqtt".to_string(),
        refresh_period_secs: 60,
        fetch_timeout_ms: 3_000,
        refresh_timeout_ms: 3_000,
        cache_max_keys: 32,
        cache_ttl_secs: 60,
        max_document_bytes: 64 * 1024,
        clock_skew_secs: 60,
        // Loopback fixture only: production endpoints keep TLS on.
        tls_verify: false,
        ca_cert_path: None,
    });
    let token = signing.mint();
    // Warm up: one fetch populates the cache, so the hit leg below pays
    // cache read plus verification with no network I/O.
    auth.verify_token("bench", &token)
        .await
        .expect("warmup verifies");
    assert_eq!(auth.refresh_count(), 1, "warmup fetches exactly once");
    // 200 rounds per leg: a sample size, not an SLO.
    let iters = 200u32;
    // Hit leg: every CONNECT verifies against the cached key.
    let mut hit_ok = 0u32;
    let mut hit_max_ns = 0u128;
    let hit_start = Instant::now();
    for _ in 0..iters {
        let op_start = Instant::now();
        let ok = black_box(auth.verify_token("bench", &token).await.is_ok());
        hit_ok += u32::from(ok);
        hit_max_ns = hit_max_ns.max(op_start.elapsed().as_nanos());
    }
    let hit_ms = hit_start.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);
    let hit_max_ms = hit_max_ns as f64 / 1_000_000.0;
    assert_eq!(hit_ok, iters, "every hit-leg verify must succeed");
    println!("BENCH jwks_verify_hit_ms {hit_ms:.4} ms");
    println!("BENCH jwks_verify_hit_max_ms {hit_max_ms:.4} ms");
    // Miss leg: one stranger key minted once and reused, so every CONNECT
    // names an unknown `kid`, pays one bounded HTTPS fetch, and is refused
    // fail-closed (exact counts: every refusal plus exactly one fetch each).
    let stranger = BenchKey::generate("bench-key-zzz");
    let unknown = stranger.mint();
    let fetches_before = auth.refresh_count();
    let mut miss_refused = 0u32;
    let mut miss_max_ns = 0u128;
    let miss_start = Instant::now();
    for _ in 0..iters {
        let op_start = Instant::now();
        let refused = black_box(auth.verify_token("bench", &unknown).await.is_err());
        miss_refused += u32::from(refused);
        miss_max_ns = miss_max_ns.max(op_start.elapsed().as_nanos());
    }
    let miss_ms = miss_start.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);
    let miss_max_ms = miss_max_ns as f64 / 1_000_000.0;
    assert_eq!(miss_refused, iters, "every miss-leg verify must be refused");
    assert_eq!(
        auth.refresh_count() - fetches_before,
        u64::from(iters),
        "every miss-leg CONNECT must pay exactly one bounded fetch"
    );
    println!("BENCH jwks_verify_miss_ms {miss_ms:.4} ms");
    println!("BENCH jwks_verify_miss_max_ms {miss_max_ms:.4} ms");
    // Summary re-print of the hit mean alongside the miss numbers, so the
    // pipeline-measured hit mean (spec: mean and worst case on hit and on
    // miss) is present at the end of the run as well as before the miss leg.
    println!("BENCH jwks_verify_hit_ms {hit_ms:.4} ms");
    // Flush stdout so all BENCH lines reach the gates log before exit.
    use std::io::Write as _;
    std::io::stdout().flush().ok();
}

/// Base-commit fallback for the same hook: the JWKS types do not exist on
/// the base commit, so the same four `BENCH` metric names measure the base
/// CONNECT credential check (`MemoryAuth::authenticate`) instead — the hit
/// leg verifies valid credentials, the miss leg (wrong password) is
/// refused fail-closed. `#[ignore]` like the tree leg; only one of the two
/// bodies compiles, selected by the `jwks-bench` feature (on by default on
/// the tree, absent on the base commit where only this file is copied in).
/// Uses only base-commit interfaces (`MemoryAuth::new`, `add_user`,
/// `authenticate`). Counts are a CI sample size, not an SLO.
#[cfg(not(feature = "jwks-bench"))]
#[tokio::test]
#[ignore]
async fn jwks_connect_auth_cost() {
    let auth = MemoryAuth::new();
    auth.add_user("bench-user", b"bench-secret")
        .expect("memory-only persist cannot fail");
    // 200 rounds per leg: a sample size, not an SLO.
    let iters = 200u32;
    // Hit leg: every CONNECT verifies against the stored verifier.
    let mut hit_ok = 0u32;
    let mut hit_max_ns = 0u128;
    let hit_start = Instant::now();
    for _ in 0..iters {
        let op_start = Instant::now();
        let ok = black_box(
            auth.authenticate("bench", Some("bench-user"), Some(b"bench-secret"))
                .await
                .is_ok(),
        );
        hit_ok += u32::from(ok);
        hit_max_ns = hit_max_ns.max(op_start.elapsed().as_nanos());
    }
    let hit_ms = hit_start.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);
    let hit_max_ms = hit_max_ns as f64 / 1_000_000.0;
    assert_eq!(hit_ok, iters, "every hit-leg authenticate must succeed");
    println!("outcome base_connect_hit ok=true (base credential check, no JWKS)");
    println!("BENCH jwks_verify_hit_ms {hit_ms:.4} ms");
    println!("BENCH jwks_verify_hit_max_ms {hit_max_ms:.4} ms");
    // Miss leg: wrong credentials are refused fail-closed with no fetch.
    let mut miss_refused = 0u32;
    let mut miss_max_ns = 0u128;
    let miss_start = Instant::now();
    for _ in 0..iters {
        let op_start = Instant::now();
        let refused = black_box(
            auth.authenticate("bench", Some("bench-user"), Some(b"wrong-secret"))
                .await
                .is_err(),
        );
        miss_refused += u32::from(refused);
        miss_max_ns = miss_max_ns.max(op_start.elapsed().as_nanos());
    }
    let miss_ms = miss_start.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);
    let miss_max_ms = miss_max_ns as f64 / 1_000_000.0;
    assert_eq!(
        miss_refused, iters,
        "every miss-leg authenticate must be refused"
    );
    println!("outcome base_connect_miss refused=true (fail-closed, no JWKS)");
    println!("BENCH jwks_verify_miss_ms {miss_ms:.4} ms");
    println!("BENCH jwks_verify_miss_max_ms {miss_max_ms:.4} ms");
}
