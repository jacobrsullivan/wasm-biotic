use std::path::PathBuf;
use wasm_biotic_independent_substrate::isolation;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut arguments = std::env::args().skip(1);
    let mut incumbent = None;
    let mut successor = None;
    let mut certifier_public_key_hex = None;
    let mut report = PathBuf::from(
        "artifacts/component-complete/2026-08-03-r2-independent-principal-isolation.v1.json",
    );
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--incumbent" | "--release" => incumbent = arguments.next().map(PathBuf::from),
            "--successor" => successor = arguments.next().map(PathBuf::from),
            "--certifier-public-key-hex" => certifier_public_key_hex = arguments.next(),
            "--report" => report = PathBuf::from(arguments.next().ok_or("--report needs a path")?),
            "--help" | "-h" => {
                println!(
                    "usage: principal-isolation --incumbent PATH --successor PATH --certifier-public-key-hex HEX [--report PATH]"
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    let digest = isolation::run(
        incumbent.ok_or("--incumbent is required")?,
        successor.ok_or("--successor is required")?,
        &certifier_public_key_hex.ok_or("--certifier-public-key-hex is required")?,
        &report,
    )?;
    println!("principal_isolation_report={digest}");
    println!("report_path={}", report.display());
    Ok(())
}
