//! Offline enterprise licence signer (ECDSA P-256, hardware-rooted).
//!
//! Outside the workspace default build: `cargo test --workspace` never builds
//! this binary.
//!
//! The tool never holds private key material on its production path. In the
//! default `--signer token` mode it builds the canonical payload, hashes it
//! with SHA-256, prints the digest for the ceremony record, and hands only
//! the digest to a hardware token through a helper process; the 64-byte raw
//! ECDSA signature comes back and is embedded in the licence. The private
//! key is generated on the device, is not importable or exportable, and the
//! device enforces PIN plus physical touch.
//!
//! `--signer software` is a test stand-in that signs with a key file so the
//! round trip can be exercised without a device. It must never issue a
//! production licence: test keys are ephemeral and untrusted.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

const TOKEN_PREFIX: &str = "INDRA-ENT-V2";

/// Canonical licence payload. Field order is the canonical order and must
/// match `crates/broker-cluster/src/license.rs` exactly: the signature
/// covers `serde_json::to_vec` of this struct with no whitespace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LicensePayload {
    customer: String,
    max_nodes: usize,
    issued_at: u64,
    expires_at: u64,
    #[serde(default)]
    features: Vec<String>,
    node_id: String,
    #[serde(default)]
    kid: String,
    /// Grace period in days past expiry. Must match the broker struct
    /// exactly (same field order): carried in the licence so a customer
    /// can be given longer without a new build; defaults to 90 days.
    #[serde(default = "default_grace_days")]
    grace_period_days: u64,
}

fn default_grace_days() -> u64 {
    90
}

/// Licence request produced by a customer installation (see B2-04). The
/// only field the signer trusts is `installation_identity`, which is copied
/// verbatim into the licence. Everything else is advisory; the operator
/// supplies the authoritative customer, entitlements and expiry on the
/// command line. Unknown fields are ignored so newer installations stay
/// readable by this tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LicenceRequest {
    installation_identity: String,
    #[serde(default)]
    product_version: String,
    #[serde(default)]
    requested_max_nodes: Option<usize>,
    #[serde(default)]
    requested_features: Vec<String>,
    #[serde(default)]
    customer_hint: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "license-signer",
    about = "Issue IndraMQTT enterprise licences from a hardware token"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show what a licence request contains, without signing anything.
    ShowRequest {
        /// Path to the request file from the customer installation.
        #[arg(long)]
        request: PathBuf,
    },
    /// Build the canonical payload from a request and sign its digest.
    Sign {
        /// Path to the request file from the customer installation.
        #[arg(long)]
        request: PathBuf,
        /// Key id to embed and select the token key (must match a trusted
        /// key id configured on the customer broker).
        #[arg(long)]
        kid: String,
        /// Customer name as on the purchase order.
        #[arg(long)]
        customer: String,
        /// Maximum cluster nodes the licence allows.
        #[arg(long)]
        max_nodes: usize,
        /// Licence start, unix epoch seconds.
        #[arg(long)]
        issued_at: u64,
        /// Licence end, unix epoch seconds.
        #[arg(long)]
        expires_at: u64,
        /// Optional comma-separated entitlement list.
        #[arg(long, default_value = "")]
        features: String,
        /// Grace period in days past expiry (default 90). Carried in the
        /// licence so a customer can be given longer without a new build.
        #[arg(long, default_value_t = 90)]
        grace_days: u64,
        /// Signing backend: `token` (hardware, default) or `software`
        /// (test stand-in only, needs `--software-key`).
        #[arg(long, default_value = "token")]
        signer: String,
        /// Test-only key file for `--signer software`: 64 hex chars
        /// holding a 32-byte P-256 private scalar. Never use for
        /// production licences.
        #[arg(long, default_value = "")]
        software_key: String,
        /// Helper that talks to the hardware token for `--signer token`.
        /// It receives the 64-char hex SHA-256 digest as its sole argument
        /// and prints the 128-char hex raw (r||s) signature. Defaults to a
        /// `yubico-piv-tool` invocation (see CEREMONY.md).
        #[arg(long, default_value = "")]
        token_helper: String,
        /// Slot on the device when using the default helper (for example
        /// `9c`). Passed through to the helper documentation; the tool
        /// itself never addresses the device directly.
        #[arg(long, default_value = "9c")]
        slot: String,
        /// Skip the interactive confirmation prompt. The ceremony forbids
        /// this for production; it exists for scripted tests only.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

fn decode_hex_bytes(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex string has odd length ({})", s.len());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| anyhow::anyhow!("invalid hex at offset {i}"))?;
        out.push(byte);
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_request(path: &std::path::Path) -> anyhow::Result<LicenceRequest> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read request {}: {e}", path.display()))?;
    let request: LicenceRequest = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("request {} is not valid JSON: {e}", path.display()))?;
    if request.installation_identity.trim().is_empty() {
        anyhow::bail!(
            "request {} carries no installation identity; refusing to invent one",
            path.display()
        );
    }
    Ok(request)
}

fn parse_features(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn build_payload(
    request: &LicenceRequest,
    kid: &str,
    customer: &str,
    max_nodes: usize,
    issued_at: u64,
    expires_at: u64,
    features: Vec<String>,
    grace_days: u64,
) -> anyhow::Result<LicensePayload> {
    if request.installation_identity.trim().is_empty() {
        anyhow::bail!("request carries no installation identity; refusing to invent one");
    }
    if kid.trim().is_empty() {
        anyhow::bail!("kid must not be empty");
    }
    if customer.trim().is_empty() {
        anyhow::bail!("customer must not be empty");
    }
    if expires_at <= issued_at {
        anyhow::bail!("expires_at must be after issued_at");
    }
    Ok(LicensePayload {
        customer: customer.trim().to_string(),
        max_nodes,
        issued_at,
        expires_at,
        features,
        // The binding comes from the request and is never invented here.
        node_id: request.installation_identity.trim().to_string(),
        kid: kid.trim().to_string(),
        grace_period_days: grace_days,
    })
}

/// Print the signing summary and wait for a deliberate confirmation.
/// Returns once the operator types `YES`. Anything else aborts.
fn confirm(summary: &str, skip: bool) -> anyhow::Result<()> {
    eprintln!("{summary}");
    if skip {
        eprintln!("confirmation skipped (--yes): test use only");
        return Ok(());
    }
    if std::io::stdin().is_terminal() {
        eprint!("Type YES to sign with the hardware token: ");
        std::io::stderr()
            .flush()
            .map_err(|e| anyhow::anyhow!("cannot write prompt: {e}"))?;
    } else {
        eprintln!("Type YES on stdin to sign with the hardware token:");
    }
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| anyhow::anyhow!("cannot read confirmation: {e}"))?;
    if line.trim() == "YES" {
        Ok(())
    } else {
        anyhow::bail!("aborted: confirmation was not YES");
    }
}

/// Test stand-in: sign the canonical bytes with a key file. Production
/// licences must use `--signer token`.
fn sign_software(canonical: &[u8], key_path: &std::path::Path) -> anyhow::Result<[u8; 64]> {
    use p256::ecdsa::signature::Signer as _;

    if key_path.as_os_str().is_empty() {
        anyhow::bail!("--signer software needs --software-key <hex file> (test use only)");
    }
    let raw = std::fs::read_to_string(key_path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", key_path.display()))?;
    let bytes = decode_hex_bytes(raw.trim())?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "software key must hold 32 bytes (64 hex chars), got {}",
            bytes.len()
        );
    }
    let field_bytes = p256::elliptic_curve::generic_array::GenericArray::clone_from_slice(&bytes);
    let signing = p256::ecdsa::SigningKey::from_bytes(&field_bytes)
        .map_err(|_| anyhow::anyhow!("software key is not a valid P-256 scalar"))?;
    let sig: p256::ecdsa::Signature = signing.sign(canonical);
    Ok(sig.to_bytes().into())
}

/// Hardware path: hand only the digest to the token helper and read back
/// the raw signature. The helper owns the device conversation (PIN, touch,
/// slot); this tool never sees key material.
fn sign_via_token_helper(
    digest: &[u8; 32],
    token_helper: &str,
    slot: &str,
) -> anyhow::Result<[u8; 64]> {
    if token_helper.trim().is_empty() {
        anyhow::bail!(
            "no token helper configured: pass --token-helper '<helper>' (see CEREMONY.md), \
             or use --signer software for the test stand-in"
        );
    }
    let digest_hex = encode_hex(digest);
    // The helper protocol is one argument in (digest hex), hex signature
    // on stdout. Split the configured string on whitespace; no shell.
    let mut words = token_helper.split_whitespace();
    let program = words
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty token helper"))?;
    let mut command = std::process::Command::new(program);
    for word in words {
        let word = word
            .replace("{digest}", &digest_hex)
            .replace("{slot}", slot);
        command.arg(word);
    }
    // Always pass the digest explicitly so helpers without placeholder
    // support still receive it as the final argument.
    if !token_helper.contains("{digest}") {
        command.arg(&digest_hex);
    }
    let output = command
        .output()
        .map_err(|e| anyhow::anyhow!("cannot run token helper: {e}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "token helper failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let sig_hex = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let sig_bytes = decode_hex_bytes(&sig_hex)?;
    if sig_bytes.len() != 64 {
        anyhow::bail!(
            "token helper must print 64 signature bytes (128 hex chars), got {}",
            sig_bytes.len()
        );
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    // The helper returns raw r||s; reject the degenerate all-zero answer
    // rather than emitting a licence that can never verify.
    if sig.iter().all(|b| *b == 0) {
        anyhow::bail!("token helper returned an all-zero signature");
    }
    Ok(sig)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ShowRequest { request } => {
            let req = read_request(&request)?;
            println!(
                "installation identity: {}",
                req.installation_identity.trim()
            );
            println!(
                "customer hint:         {}",
                if req.customer_hint.trim().is_empty() {
                    "(none)"
                } else {
                    req.customer_hint.trim()
                }
            );
            println!(
                "product version:       {}",
                if req.product_version.trim().is_empty() {
                    "(none)"
                } else {
                    req.product_version.trim()
                }
            );
            println!(
                "requested max nodes:   {}",
                req.requested_max_nodes
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "(none)".to_string())
            );
            println!(
                "requested features:    {}",
                if req.requested_features.is_empty() {
                    "(none)".to_string()
                } else {
                    req.requested_features.join(", ")
                }
            );
            Ok(())
        }
        Command::Sign {
            request,
            kid,
            customer,
            max_nodes,
            issued_at,
            expires_at,
            features,
            grace_days,
            signer,
            software_key,
            token_helper,
            slot,
            yes,
        } => {
            let req = read_request(&request)?;
            let payload = build_payload(
                &req,
                &kid,
                &customer,
                max_nodes,
                issued_at,
                expires_at,
                parse_features(&features),
                grace_days,
            )?;
            let canonical = serde_json::to_vec(&payload)?;
            let digest = Sha256::digest(&canonical);
            let digest_arr: [u8; 32] = digest.into();

            let summary = format!(
                "licence to sign\n  customer:   {}\n  identity:   {}\n  entitlements: max_nodes={} features=[{}]\n  expiry:     {} (issued {})\n  key id:     {}\n  digest:     sha256:{}\n  signer:     {}",
                payload.customer,
                payload.node_id,
                payload.max_nodes,
                payload.features.join(", "),
                payload.expires_at,
                payload.issued_at,
                payload.kid,
                encode_hex(&digest_arr),
                signer.trim(),
            );
            // Deliberate act: nothing touches the token before YES.
            confirm(&summary, yes)?;

            let backend = signer.trim().to_lowercase();
            let sig_bytes: [u8; 64] = match backend.as_str() {
                "token" => sign_via_token_helper(&digest_arr, &token_helper, &slot)?,
                "software" => {
                    eprintln!("WARNING: software stand-in signature; not a production licence");
                    sign_software(&canonical, std::path::Path::new(&software_key))?
                }
                other => anyhow::bail!(
                    "unknown --signer {other:?}: use 'token' (hardware) or 'software' (test stand-in)"
                ),
            };
            println!(
                "{}.{}.{}",
                TOKEN_PREFIX,
                URL_SAFE_NO_PAD.encode(&canonical),
                URL_SAFE_NO_PAD.encode(sig_bytes)
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> LicenceRequest {
        LicenceRequest {
            installation_identity: "cluster-7f3a".to_string(),
            product_version: "0.1.0".to_string(),
            requested_max_nodes: Some(10),
            requested_features: vec!["clustering".to_string()],
            customer_hint: "Acme".to_string(),
        }
    }

    #[test]
    fn identity_is_copied_never_invented() {
        let req = sample_request();
        let payload = build_payload(&req, "key-a", "Acme", 10, 1700000000, 2000000000, vec![], 90)
            .expect("builds");
        assert_eq!(payload.node_id, "cluster-7f3a");
        assert_eq!(payload.kid, "key-a");
    }

    #[test]
    fn empty_identity_is_refused() {
        let req = LicenceRequest {
            installation_identity: "   ".to_string(),
            ..sample_request()
        };
        assert!(build_payload(&req, "key-a", "Acme", 10, 1700000000, 2000000000, vec![], 90).is_err());
    }

    #[test]
    fn expiry_must_follow_issue() {
        let req = sample_request();
        assert!(build_payload(&req, "key-a", "Acme", 10, 2000000000, 1700000000, vec![], 90).is_err());
    }

    #[test]
    fn canonical_bytes_cover_every_field() {
        let req = sample_request();
        let payload = build_payload(
            &req,
            "key-a",
            "Acme",
            10,
            1700000000,
            2000000000,
            vec!["clustering".to_string()],
            90,
        )
        .expect("builds");
        let bytes = serde_json::to_vec(&payload).expect("json");
        let text = String::from_utf8(bytes).expect("utf-8");
        for fragment in [
            "\"customer\":\"Acme\"",
            "\"node_id\":\"cluster-7f3a\"",
            "\"kid\":\"key-a\"",
            "\"expires_at\":2000000000",
            "\"features\":[\"clustering\"]",
            "\"grace_period_days\":90",
        ] {
            assert!(text.contains(fragment), "missing {fragment} in {text}");
        }
    }

    #[test]
    fn software_round_trip_verifies_with_p256() {
        use p256::ecdsa::signature::{Signer, Verifier};

        let raw = [0x42u8; 32];
        let field_bytes = p256::elliptic_curve::generic_array::GenericArray::clone_from_slice(&raw);
        let signing = p256::ecdsa::SigningKey::from_bytes(&field_bytes).expect("scalar");
        let req = sample_request();
        let payload = build_payload(&req, "key-a", "Acme", 3, 1700000000, 1800000000, vec![], 90)
            .expect("builds");
        let canonical = serde_json::to_vec(&payload).expect("json");
        let sig: p256::ecdsa::Signature = signing.sign(&canonical);
        let verifying = p256::ecdsa::VerifyingKey::from(&signing);
        assert!(verifying.verify(&canonical, &sig).is_ok());
    }
}
