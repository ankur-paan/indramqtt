//! Shared TLS + MQTT handshake helpers for the cloud sinks.
//!
//! Both the AWS IoT and Azure IoT transports dial TCP, upgrade to TLS
//! with server verification (plus client authentication where the
//! service requires it), then exchange MQTT CONNECT/CONNACK before any
//! PUBLISH. There is no plain-text path: a missing credential is a
//! dispatch error, never a fallback.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::{ConnectorError, Result};

/// Split `host[:port]`; bare hosts take `default_port`.
pub(crate) fn parse_host_port(input: &str, default_port: u16) -> Result<(String, u16)> {
    let rest = input.trim();
    if rest.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cloud endpoint must not be empty".to_string(),
        ));
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) if !port.contains('.') && !port.contains(']') => {
            let port: u16 = port.parse().map_err(|_| {
                ConnectorError::Dispatch(format!("cloud endpoint bad port in {rest:?}"))
            })?;
            (host, port)
        }
        _ => (rest, default_port),
    };
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if host.is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "cloud endpoint host must not be empty in {rest:?}"
        )));
    }
    if port == 0 {
        return Err(ConnectorError::Dispatch(format!(
            "cloud endpoint port must be 1..=65535 in {rest:?}"
        )));
    }
    Ok((host, port))
}

/// Server name for TLS verification (DNS or IP literal).
pub(crate) fn server_name_for_host(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string())
        .map_err(|_| ConnectorError::Dispatch(format!("cloud endpoint host invalid: {host:?}")))
}

/// All certificates in one PEM document.
pub(crate) fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|e| ConnectorError::Dispatch(format!("cloud PEM certificate read failed: {e}")))?;
    if certs.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cloud PEM has no certificate section".to_string(),
        ));
    }
    Ok(certs.into_iter().map(CertificateDer::from).collect())
}

/// First private key in one PEM document (PKCS#8, RSA or SEC1 EC).
pub(crate) fn private_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    loop {
        match rustls_pemfile::read_one(&mut reader)
            .map_err(|e| ConnectorError::Dispatch(format!("cloud PEM key read failed: {e}")))?
        {
            None => break,
            Some(rustls_pemfile::Item::PKCS8Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs8(key.into()));
            }
            Some(rustls_pemfile::Item::RSAKey(key)) => {
                return Ok(PrivateKeyDer::Pkcs1(key.into()));
            }
            Some(rustls_pemfile::Item::ECKey(key)) => {
                return Ok(PrivateKeyDer::Sec1(key.into()));
            }
            _ => {}
        }
    }
    Err(ConnectorError::Dispatch(
        "cloud PEM has no private key section".to_string(),
    ))
}

/// Root store: OS system trust store plus one optional extra bundle.
/// Falls back to bundled Mozilla roots when the OS store is empty or
/// unreadable so loopback/offline tests still build.
pub(crate) fn root_store_with(extra_pem: Option<&str>) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    let mut loaded = 0usize;
    for cert in native.certs {
        if store.add(cert).is_ok() {
            loaded += 1;
        }
    }
    if loaded == 0 {
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::pki_types::TrustAnchor {
                subject: ta.subject.to_vec().into(),
                subject_public_key_info: ta.spki.to_vec().into(),
                name_constraints: ta.name_constraints.map(|nc| nc.to_vec().into()),
            }
        }));
    }
    if let Some(pem) = extra_pem {
        if pem.trim().is_empty() {
            return Ok(store);
        }
        for cert in certs_from_pem(pem)? {
            store
                .add(cert)
                .map_err(|e| ConnectorError::Dispatch(format!("cloud CA bundle rejected: {e}")))?;
        }
    }
    Ok(store)
}

/// Client TLS config with optional mutual authentication and ALPN.
pub(crate) fn client_config(
    roots: RootCertStore,
    client_cert: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    alpn: &[String],
) -> Result<Arc<ClientConfig>> {
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let mut config = match client_cert {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).map_err(|e| {
            ConnectorError::Dispatch(format!("cloud client identity rejected: {e}"))
        })?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    Ok(Arc::new(config))
}

/// Dial TCP with a connect timeout, then complete the TLS handshake
/// with its own timeout. The TCP socket is never used for cleartext.
pub(crate) async fn tls_dial(
    host: &str,
    port: u16,
    config: Arc<ClientConfig>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    context: &str,
) -> Result<TlsStream<TcpStream>> {
    let addr = format!("{host}:{port}");
    let tcp = tokio::time::timeout(connect_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| ConnectorError::Connection(format!("{context} connect timeout: {addr}")))?
        .map_err(|e| ConnectorError::Connection(format!("{context} connect failed: {e}")))?;
    tcp.set_nodelay(true)
        .map_err(|e| ConnectorError::Connection(format!("{context} set_nodelay failed: {e}")))?;
    let server_name = server_name_for_host(host)?;
    tokio::time::timeout(
        handshake_timeout,
        TlsConnector::from(config).connect(server_name, tcp),
    )
    .await
    .map_err(|_| ConnectorError::Connection(format!("{context} TLS handshake timeout: {addr}")))?
    .map_err(|e| ConnectorError::Connection(format!("{context} TLS handshake failed: {e}")))
}

/// Encode one MQTT 3.1.1 CONNECT frame.
pub(crate) fn encode_mqtt_connect(
    client_id: &str,
    clean_start: bool,
    keep_alive_secs: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Vec<u8>> {
    if client_id.is_empty() || client_id.len() > u16::MAX as usize {
        return Err(ConnectorError::Dispatch(
            "cloud MQTT client_id must be 1..=65535 bytes".to_string(),
        ));
    }
    let mut body = Vec::new();
    body.extend_from_slice(&[0x00, 0x04]);
    body.extend_from_slice(b"MQTT");
    body.push(4);
    let mut flags: u8 = 0x02;
    if !clean_start {
        flags &= !0x02;
    }
    if username.is_some() {
        flags |= 0x80;
    }
    if password.is_some() {
        flags |= 0x40;
    }
    body.push(flags);
    body.extend_from_slice(&keep_alive_secs.to_be_bytes());
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    if let Some(username) = username {
        body.extend_from_slice(&(username.len() as u16).to_be_bytes());
        body.extend_from_slice(username.as_bytes());
    }
    if let Some(password) = password {
        body.extend_from_slice(&(password.len() as u16).to_be_bytes());
        body.extend_from_slice(password.as_bytes());
    }
    let mut frame = vec![0x10];
    super::mqtt_bridge::encode_remaining_length(body.len(), &mut frame)?;
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Write CONNECT and expect a `0x00` CONNACK over an established TLS stream.
pub(crate) async fn mqtt_connect_over_tls(
    stream: &mut TlsStream<TcpStream>,
    connect: &[u8],
    context: &str,
    io_timeout: Duration,
) -> Result<()> {
    tokio::time::timeout(io_timeout, stream.write_all(connect))
        .await
        .map_err(|_| ConnectorError::Connection(format!("{context} CONNECT write timeout")))?
        .map_err(|e| ConnectorError::Connection(format!("{context} CONNECT write failed: {e}")))?;
    let mut connack = [0u8; 4];
    tokio::time::timeout(io_timeout, stream.read_exact(&mut connack))
        .await
        .map_err(|_| ConnectorError::Connection(format!("{context} CONNACK read timeout")))?
        .map_err(|e| ConnectorError::Connection(format!("{context} CONNACK read failed: {e}")))?;
    if connack[0] != 0x20 || connack[1] != 0x02 {
        return Err(ConnectorError::Connection(format!(
            "{context} malformed CONNACK"
        )));
    }
    if connack[3] != 0x00 {
        return Err(ConnectorError::Dispatch(format!(
            "{context} connection refused: 0x{:02x}",
            connack[3]
        )));
    }
    Ok(())
}

/// Read one CONNECT from a server-side TLS stream (used by tests).
#[cfg(test)]
pub(crate) async fn read_client_connect<S>(
    stream: &mut S,
) -> Result<(String, Option<String>, Option<String>)>
where
    S: AsyncReadExt + Unpin,
{
    let mut head = [0u8; 1];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|e| ConnectorError::Connection(format!("test server CONNECT head failed: {e}")))?;
    if head[0] != 0x10 {
        return Err(ConnectorError::Connection(
            "test server expected CONNECT".to_string(),
        ));
    }
    let mut len_buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.map_err(|e| {
            ConnectorError::Connection(format!("test server CONNECT len failed: {e}"))
        })?;
        len_buf.push(byte[0]);
        if byte[0] & 0x80 == 0 {
            break;
        }
        if len_buf.len() >= 4 {
            return Err(ConnectorError::Connection(
                "test server CONNECT length overruns".to_string(),
            ));
        }
    }
    let (remaining, _) = super::mqtt_bridge::decode_remaining_length(&len_buf)?;
    let mut body = vec![0u8; remaining];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| ConnectorError::Connection(format!("test server CONNECT body failed: {e}")))?;
    // Minimal 3.1.1 parse: proto, flags, keepalive, client id, user, pass.
    if body.len() < 10 {
        return Err(ConnectorError::Connection(
            "test server CONNECT truncated".to_string(),
        ));
    }
    let flags = body[7];
    let mut cursor = &body[10..];
    let take_str = |cursor: &mut &[u8]| -> Result<String> {
        if cursor.len() < 2 {
            return Err(ConnectorError::Connection(
                "test server CONNECT field truncated".to_string(),
            ));
        }
        let len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
        *cursor = &cursor[2..];
        if cursor.len() < len {
            return Err(ConnectorError::Connection(
                "test server CONNECT field overruns".to_string(),
            ));
        }
        let value = std::str::from_utf8(&cursor[..len])
            .map_err(|_| {
                ConnectorError::Connection("test server CONNECT field not UTF-8".to_string())
            })?
            .to_string();
        *cursor = &cursor[len..];
        Ok(value)
    };
    let client_id = take_str(&mut cursor)?;
    let username = if flags & 0x80 != 0 {
        Some(take_str(&mut cursor)?)
    } else {
        None
    };
    let password = if flags & 0x40 != 0 {
        Some(take_str(&mut cursor)?)
    } else {
        None
    };
    Ok((client_id, username, password))
}

/// Minimal test CA + leaf certificate material (generated once with
/// openssl for loopback TLS tests; never deployed).
#[cfg(test)]
pub(crate) mod test_certs {
    /// Build a `ServerConfig` from PEM cert/key, optionally requiring
    /// a client certificate verified against `client_ca_pem`.
    pub(crate) fn server_config(
        cert_pem: &str,
        key_pem: &str,
        client_ca_pem: Option<&str>,
    ) -> std::result::Result<std::sync::Arc<rustls::ServerConfig>, String> {
        let certs = super::certs_from_pem(cert_pem).map_err(|e| e.to_string())?;
        let key = super::private_key_from_pem(key_pem).map_err(|e| e.to_string())?;
        let mut config = if let Some(ca_pem) = client_ca_pem {
            let mut roots = rustls::RootCertStore::empty();
            for cert in super::certs_from_pem(ca_pem).map_err(|e| e.to_string())? {
                roots.add(cert).map_err(|e| e.to_string())?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder(roots.into())
                .build()
                .map_err(|e| e.to_string())?;
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| e.to_string())?
        } else {
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| e.to_string())?
        };
        config.alpn_protocols = vec![b"mqtt".to_vec()];
        Ok(std::sync::Arc::new(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_defaults_and_errors() {
        assert_eq!(
            parse_host_port("example.com", 8883).unwrap(),
            ("example.com".to_string(), 8883)
        );
        assert_eq!(
            parse_host_port("example.com:443", 8883).unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("127.0.0.1:0", 8883)
                .unwrap_err()
                .to_string(),
            "Connector dispatch failure: cloud endpoint port must be 1..=65535 in \"127.0.0.1:0\""
        );
        assert!(parse_host_port("", 8883).is_err());
        assert!(parse_host_port("  ", 8883).is_err());
    }

    #[test]
    fn test_server_name_accepts_dns_and_ip() {
        assert!(server_name_for_host("example.com").is_ok());
        assert!(server_name_for_host("127.0.0.1").is_ok());
        assert!(server_name_for_host("").is_err());
    }

    #[test]
    fn test_pem_helpers_reject_empty() {
        assert!(certs_from_pem("nope").is_err());
        assert!(private_key_from_pem("nope").is_err());
        assert!(root_store_with(Some("nope")).is_err());
    }

    #[test]
    fn test_encode_connect_shape() {
        let frame = encode_mqtt_connect("device-1", true, 60, None, None).unwrap();
        assert_eq!(frame[0], 0x10);
        assert!(frame.windows(8).any(|w| w == b"device-1"));
        let with_auth =
            encode_mqtt_connect("device-1", true, 60, Some("user"), Some("pass")).unwrap();
        assert!(with_auth.len() > frame.len());
        assert!(encode_mqtt_connect("", true, 60, None, None).is_err());
    }
}
