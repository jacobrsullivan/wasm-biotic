use std::path::PathBuf;
use wasm_biotic_independent_substrate::reproduce;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut arguments = std::env::args().skip(1);
    let mut release = None;
    let mut certifier_public_key_hex = None;
    let mut attestation = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--release" => release = arguments.next().map(PathBuf::from),
            "--certifier-public-key-hex" => certifier_public_key_hex = arguments.next(),
            "--attestation" => {
                attestation = Some(PathBuf::from(
                    arguments.next().ok_or("--attestation needs a path")?,
                ))
            }
            "--help" | "-h" => {
                println!(
                    "usage: wasm-biotic-independent-substrate --release PATH --certifier-public-key-hex HEX [--attestation PATH]"
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    let release = release.ok_or("--release is required")?;
    let attestation = match attestation {
        Some(path) => path,
        None => default_attestation_path(&release)?,
    };
    let digest = reproduce::run(
        &release,
        &certifier_public_key_hex.ok_or("--certifier-public-key-hex is required")?,
        &attestation,
    )?;
    println!("independent_attestation={digest}");
    println!("attestation_path={}", attestation.display());
    Ok(())
}

fn default_attestation_path(
    release: &std::path::Path,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(release.join("substrate-profile.json"))?)?;
    Ok(
        match profile.get("schema").and_then(serde_json::Value::as_str) {
            Some("wasm-biotic.factory-substrate-profile.v3") => PathBuf::from(
                "artifacts/component-complete/2026-08-03-r3-independent-substrate-reproduction.v2.json",
            ),
            Some("wasm-biotic.factory-substrate-profile.v2") => PathBuf::from(
                "artifacts/component-complete/2026-08-03-r2-independent-substrate-reproduction.v2.json",
            ),
            _ => PathBuf::from(
                "artifacts/component-complete/2026-08-03-r1-independent-substrate-reproduction.v1.json",
            ),
        },
    )
}
