use std::path::PathBuf;
use wasm_biotic_independent_substrate::shadow;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut arguments = std::env::args().skip(1);
    let mut incumbent = None;
    let mut candidate = None;
    let mut certifier_public_key_hex = None;
    let mut report = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--incumbent" => incumbent = arguments.next().map(PathBuf::from),
            "--candidate" => candidate = arguments.next().map(PathBuf::from),
            "--certifier-public-key-hex" => certifier_public_key_hex = arguments.next(),
            "--report" => {
                report = Some(PathBuf::from(
                    arguments.next().ok_or("--report needs a path")?,
                ))
            }
            "--help" | "-h" => {
                println!(
                    "usage: candidate-graph-shadow --incumbent PATH --candidate PATH --certifier-public-key-hex HEX [--report PATH]"
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    let incumbent = incumbent.ok_or("--incumbent is required")?;
    let candidate = candidate.ok_or("--candidate is required")?;
    let report = match report {
        Some(path) => path,
        None => default_report_path(&candidate)?,
    };
    let digest = shadow::run(
        &incumbent,
        &candidate,
        &certifier_public_key_hex.ok_or("--certifier-public-key-hex is required")?,
        &report,
    )?;
    println!("candidate_shadow_report={digest}");
    println!("report_path={}", report.display());
    Ok(())
}

fn default_report_path(
    candidate: &std::path::Path,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(candidate.join("substrate-profile.json"))?)?;
    Ok(
        match profile.get("schema").and_then(serde_json::Value::as_str) {
            Some("wasm-biotic.factory-substrate-profile.v3") => PathBuf::from(
                "artifacts/component-complete/2026-08-03-r3-candidate-graph-shadow.v3.json",
            ),
            Some("wasm-biotic.factory-substrate-profile.v2") => PathBuf::from(
                "artifacts/component-complete/2026-08-03-r2-candidate-graph-shadow.v3.json",
            ),
            _ => PathBuf::from(
                "artifacts/component-complete/2026-08-02-candidate-graph-shadow.v1.json",
            ),
        },
    )
}
