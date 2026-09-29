//! Regenerate the derived configuration artefacts.
//!
//! Checked-in command (named in the M1-03 report):
//! `bash tools/gen_config_schema.sh`
//!
//! Writes `schemas/config-schema.json` and `docs/settings-reference.md`
//! from the single schema source of truth in `broker_config::schema`.

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|dir| dir.parent())
        .expect("crate lives under <root>/crates/<name>")
        .to_path_buf()
}

fn main() {
    let root = workspace_root();
    let schema = broker_config::schema::json_schema();
    let schema_text = serde_json::to_string_pretty(&schema).expect("schema serialises");
    let schema_path = root.join("schemas").join("config-schema.json");
    std::fs::create_dir_all(schema_path.parent().expect("schema dir")).expect("create schemas dir");
    std::fs::write(&schema_path, format!("{schema_text}\n")).expect("write schema");

    let reference = broker_config::schema::settings_reference_markdown();
    let reference_path = root.join("docs").join("settings-reference.md");
    std::fs::create_dir_all(reference_path.parent().expect("docs dir")).expect("create docs dir");
    std::fs::write(&reference_path, reference).expect("write reference");

    println!(
        "Wrote {} and {}",
        schema_path.display(),
        reference_path.display()
    );
}
