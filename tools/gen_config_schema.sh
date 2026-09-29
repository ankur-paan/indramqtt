#!/usr/bin/env bash
# Regenerate the derived configuration artefacts from the single schema
# source of truth (M1-03). Writes schemas/config-schema.json and
# docs/settings-reference.md. Run from anywhere inside the repository.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cargo run --manifest-path "$root/crates/broker-config/Cargo.toml" --example gen_config_schema
