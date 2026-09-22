//! Offline enterprise licence signer.
//!
//! Outside the workspace default build: `cargo test --workspace` never builds
//! this binary. The Ed25519 private key is always read from a file path given
//! on the command line, never from a compiled-in constant.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LicensePayload {
    customer: String,
    max_nodes: usize,
    issued_at: u64,
    expires_at: u64,
    #[serde(default)]
    features: Vec<String>,
    node_id: String,
}

#[derive(Parser, Debug)]
#[command(
    name = "license-signer",
    about = "Mint IndraMQTT enterprise licences offline"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a fresh Ed25519 keypair. Writes hex files; the private file
    /// must stay offline and is never committed.
    Genkey {
        /// Where to write the 64-char hex private seed.
        #[arg(long)]
        private_out: PathBuf,
        /// Where to write the 64-char hex public key.
        #[arg(long)]
        public_out: PathBuf,
    },
    /// Sign a licence payload with the private key at `--private-key`.
    Sign {
        /// Path to a file holding the 64-char hex private seed.
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        customer: String,
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        max_nodes: usize,
        #[arg(long)]
        issued_at: u64,
        #[arg(long)]
        expires_at: u64,
        /// Optional comma-separated feature list.
        #[arg(long, default_value = "")]
        features: String,
    },
}

fn read_seed(path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    let hex = raw.trim();
    decode_hex(hex).map_err(|_| {
        anyhow::anyhow!(
            "private key file must hold 64 hex chars (32-byte seed), got {} chars",
            hex.len()
        )
    })
}

fn decode_hex(s: &str) -> Result<[u8; 32], ()> {
    if s.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| ())?;
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Genkey {
            private_out,
            public_out,
        } => {
            use rand::RngCore;
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let signing = SigningKey::from_bytes(&seed);
            std::fs::write(&private_out, format!("{}\n", encode_hex(&seed)))
                .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", private_out.display()))?;
            std::fs::write(
                &public_out,
                format!("{}\n", encode_hex(&signing.verifying_key().to_bytes())),
            )
            .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", public_out.display()))?;
            println!(
                "wrote {} and {}",
                private_out.display(),
                public_out.display()
            );
            Ok(())
        }
        Command::Sign {
            private_key,
            customer,
            node_id,
            max_nodes,
            issued_at,
            expires_at,
            features,
        } => {
            if node_id.trim().is_empty() {
                anyhow::bail!("node_id must not be empty");
            }
            if expires_at <= issued_at {
                anyhow::bail!("expires_at must be after issued_at");
            }
            let seed = read_seed(&private_key)?;
            let signing = SigningKey::from_bytes(&seed);
            let feature_list: Vec<String> = features
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
            let payload = LicensePayload {
                customer,
                max_nodes,
                issued_at,
                expires_at,
                features: feature_list,
                node_id,
            };
            let payload_json = serde_json::to_vec(&payload)?;
            let sig = signing.sign(&payload_json);
            println!(
                "INDRA-ENT-V1.{}.{}",
                URL_SAFE_NO_PAD.encode(&payload_json),
                URL_SAFE_NO_PAD.encode(sig.to_bytes())
            );
            Ok(())
        }
    }
}
