//! Shared JWKS test fixtures for B5-02 (T-95), single source.
//!
//! One RSA-2048 signing-key minter plus one minimal real HTTPS JWKS server
//! on loopback, used by the `broker-auth` authenticator tests and by the
//! `broker-node` CONNECT tests alike (the latter includes this file with
//! `#[path]`, so there is exactly one copy of the RSA/`CompatRng`/base64/
//! PEM/server logic). Test-only: never compiled into production binaries
//! (each user declares it under `#[cfg(test)]`).
//!
//! The server speaks real TLS via `tokio-rustls` and real HTTP/1.1 framing
//! at `/jwks.json` with generated key material; the key set is swappable
//! mid-test for rotation and the failing flag answers 500 to simulate an
//! outage on the same URL (a rebind would change the port).

use parking_lot::RwLock;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Loopback HTTPS fixture, generated for the test project with
/// `openssl req -x509 -newkey rsa:2048 -days 3650 -subj /CN=localhost`
/// plus `subjectAltName=IP:127.0.0.1,DNS:localhost` (valid to 2036).
/// Test-only trust: clients use `tls_verify = false` on loopback.
pub const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIDJTCCAg2gAwIBAgIUHGyuPek7PZ/bqQKavEGif5TDKBwwDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkyNDAwMzAwNVoXDTM2MDky\nMTAwMzAwNVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAtdkihZVps667YXbUFntwwvjsoiWqrXqZmHuSh24KpDuu\nvvfzM+VuaO0O52OMJkDCbZE2GZz7mSQDaVNRfYG2z4MhQa95x4+AOBIA0f695Frh\n4plsm9zOnHdSCm/UD1UrkAvfwDuxC7vdEcsVtXAH024Y8O5+ogzcorjDwTB2BTLV\n6PLnPfwDgdsIkvH93dE2CNZ701fsxyepGa/hBEUx0IrYLroOxGZRXEs6fViGdVO4\nMffBZ9qFHJvRQNEf1UXscqkRPA5JkIQfbLw4xaGcbf1HB8ce42gD8GtMIS3czADi\nTzcbrd7SXq8alw73TW3DgLvuxypxDFvzI+59xLhqLQIDAQABo28wbTAdBgNVHQ4E\nFgQUrTQoqWVIzqrZqiKz6XbHAAx0eCowHwYDVR0jBBgwFoAUrTQoqWVIzqrZqiKz\n6XbHAAx0eCowDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARhwR/AAABgglsb2Nh\nbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAJPAiEsiOQylm9mooNhwchbZR60RLWM4\nHOQ2k1MEtX8BWpfHEFpgmlLKCDfaMlLSoTl5JHsZdinDAXoTexrN8ifMx9fOQttO\nQF50qYweJzkjOsmZmZd522t6covj7+odIG/FEqfXQHa9BisoFPox74B1GyDYd9K2\nBORFO61WQZhhtSltUSyhXAWLgxJTaqJWsSavf9qYWPs5oeOvs4aLvBzLhtx12NLI\nJL9Qi5rzXxzal7vqZYmiRMq8pH3Gi7DKpjScwRd/to07AetvvOGoyfdIcZS8vlF0\n16i1jz/RPXS8eTPl/XmQBz0bXYpTVJGkcx5lnGZLma7oNXCP+dp/v8s=\n-----END CERTIFICATE-----\n";
pub const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC12SKFlWmzrrth\ndtQWe3DC+OyiJaqtepmYe5KHbgqkO66+9/Mz5W5o7Q7nY4wmQMJtkTYZnPuZJANp\nU1F9gbbPgyFBr3nHj4A4EgDR/r3kWuHimWyb3M6cd1IKb9QPVSuQC9/AO7ELu90R\nyxW1cAfTbhjw7n6iDNyiuMPBMHYFMtXo8uc9/AOB2wiS8f3d0TYI1nvTV+zHJ6kZ\nr+EERTHQitguug7EZlFcSzp9WIZ1U7gx98Fn2oUcm9FA0R/VRexyqRE8DkmQhB9s\nvDjFoZxt/UcHxx7jaAPwa0whLdzMAOJPNxut3tJerxqXDvdNbcOAu+7HKnEMW/Mj\n7n3EuGotAgMBAAECggEAIsdSWOYIfzrtz2ggi+Qz3rYo26IEkIUgFw+bKJedJWfc\ntd1KACTjBuI/tXVOeopsJPReumtRmypOFLjAnxZN1kYn+B4NVmNVjGO1EHR98MyI\n4wOgx/Zk9XvEjwZwMjaBzFzZADTqWWomj56dmkPA22j1EC8svOVk1SItHiecisWp\noGSNJ/gDkAx0kK3c5YFobBAZZyP4nIIdpXBiAHypk4DT1cSIHEy4dFN9JVzLP/0k\nmD7jsovLvn4R8a6lSnMvescUoliHqE7kTOTd3OSLiXri+EjfvkS61zyjEB9DL+pH\ni4dVxWUJUBDnWUbNFqhYaJ03pXnXGkRbTlAJfe286QKBgQDdinXuCNHUTzQfDA5C\nkpnXndj1Sl+7f7aKSK1iLzf0Iy9X8AO9gamxNa68b3uY0dSnE1eICkOEqfcM64sI\nhV5wcR0tLER7fAIBkhzZZh3zlvYUn99WSb4QjR7oAUlLT0OSsoFidOaXXiTL1GQR\nndLplurj1mCZIu4KCpgFXNbhTwKBgQDSIiaWV71p0JLNUWjd592VnZdqCbztAsKR\n5ZjUrchJZb23F8aT6LrQFgceaNWvfdNd+AjB71la1y0xfIR9AOSLcprQDrPUBuT1\nYIrPYrunkrhZbvm3N1S3oGtESayzfYbJ6urh2i8JBXqC1s2SCdoFzmojmWHfBHEG\nFohZz4fFwwKBgQDYjEsRzVUtLe5ImsQllp8B/6zet0A0SnXnXXr9CiKrZOkWD+nY\nBzIToeGXF3G8wv4WAfYBZ+bveiOeYW6ZeaQCTM60JR0bhu9/EY9ZgVOtktYe+taX\nxaUfEJIxPXCjSGtIrWuDDbmII+Hby1O1VIuhAH/BDP+HMHl1Hz3RoBn6SQKBgErc\nh8q/72cnO2WSPz3vQO3weuT4GyqE9TRtC4mZb+VWLcRw3/oJy6QedOLMjnQ663Zq\nyxPsZXULe7pJlhnCm6liZu0Aj+hVnHQetNU1Y41LpAmYk7ZGLBRPPmfRp4k6iy6c\nVpmn1WHtZbv/MrV4dQfkhcOw/UEqn+l/VYxJdyFpAoGBAI+8qzjBnHSDUr3uDX7e\n21MBoYGPzGlYwom5zEhNM2xbHvZ6Dt+c5aB308q4Wq88At6eLFtFAaTJwNFEgz/3\n/yp8G6egdnUbScWzpG5qQQ4LiBjjzHrP7Y1LGWMBeDuaD74M2uByICuEyZmJUTTT\n2rpyA7NR3vcZpXi/ZeWghtZb\n-----END PRIVATE KEY-----\n";

/// One RSA-2048 signing key minted at test start (real RSA, real PKCS#1
/// DER signing through `jsonwebtoken`; nothing is mocked).
pub struct TestSigningKey {
    pub kid: String,
    pub private_der: Vec<u8>,
    pub n_b64: String,
    pub e_b64: String,
}

impl TestSigningKey {
    pub fn generate(kid: &str) -> Self {
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
            n_b64: test_base64_url(public.n().to_bytes_be()),
            e_b64: test_base64_url(public.e().to_bytes_be()),
        }
    }

    pub fn jwk_json(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": self.n_b64,
            "e": self.e_b64,
        })
    }

    pub fn mint(&self, issuer: &str, audience: &str, exp_offset_secs: i64, tamper: bool) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock reads")
            .as_secs() as i64;
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        let key = jsonwebtoken::EncodingKey::from_rsa_der(&self.private_der);
        let claims = serde_json::json!({
            "sub": "device-1",
            "iss": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + exp_offset_secs,
        });
        let mut token = jsonwebtoken::encode(&header, &claims, &key).expect("token mints");
        if tamper {
            token.push('x');
        }
        token
    }
}

pub fn test_base64_url(bytes: Vec<u8>) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Minimal real HTTPS server on loopback serving the current key set at
/// `/jwks.json` (real TLS via `tokio-rustls`, real HTTP/1.1 framing,
/// generated key material). The key set is swappable mid-test for
/// rotation; the failing flag answers 500 to simulate an outage on the
/// same URL (a rebind would change the port).
pub struct TestJwksServer {
    pub addr: std::net::SocketAddr,
    pub keys: Arc<RwLock<Vec<serde_json::Value>>>,
    pub failing: Arc<AtomicBool>,
}

impl TestJwksServer {
    pub async fn start(initial: Vec<serde_json::Value>) -> Self {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let keys = Arc::new(RwLock::new(initial));
        let mut cert_reader = std::io::BufReader::new(TEST_CERT_PEM.as_bytes());
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader)
                .expect("fixture cert reads")
                .into_iter()
                .map(rustls::pki_types::CertificateDer::from)
                .collect();
        assert!(!certs.is_empty(), "fixture holds a certificate");
        let mut key_reader = std::io::BufReader::new(TEST_KEY_PEM.as_bytes());
        let mut private_key = None;
        while let Some(item) = rustls_pemfile::read_one(&mut key_reader).expect("fixture key reads")
        {
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
        let failing = Arc::new(AtomicBool::new(false));
        let serve_keys = Arc::clone(&keys);
        let serve_failing = Arc::clone(&failing);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let keys = Arc::clone(&serve_keys);
                let failing = Arc::clone(&serve_failing);
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
                    let (status, body) = if failing.load(Ordering::Relaxed) {
                        ("500 Internal Error", String::new())
                    } else if path == "/jwks.json" {
                        let keys = keys.read();
                        ("200 OK", serde_json::json!({ "keys": *keys }).to_string())
                    } else {
                        ("404 Not Found", String::new())
                    };
                    let content_len = body.len();
                    let reply = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {content_len}\r\nconnection: close\r\n\r\n{body}"
                    );
                    let _ = tls.write_all(reply.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self {
            addr,
            keys,
            failing,
        }
    }

    pub fn url(&self) -> String {
        format!("https://{}/jwks.json", self.addr)
    }

    pub fn rotate(&self, keys: Vec<serde_json::Value>) {
        *self.keys.write() = keys;
    }

    /// Flip the outage fault (the `broker-node` CONNECT tests simulate
    /// outage with a dead port instead, so this stays unused there;
    /// allowed rather than split into a second server).
    #[allow(dead_code)]
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::Relaxed);
    }
}
