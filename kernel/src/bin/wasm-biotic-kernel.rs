use std::error::Error;
use std::io::{self, BufRead};
use std::path::PathBuf;

use wasm_biotic_kernel::bindings::root::exports::wasm_biotic::factory::factory_api::IngressRequest;
use wasm_biotic_kernel::{
    LocalConfig, LocalMechanisms, OpaqueRootEngine, OpaqueRootManager, RootAdmission, Sha256Digest,
    TrustedCertifier,
};

fn usage(executable: &str) -> String {
    format!(
        "usage:\n  {executable} init <mechanism-state-directory> <trusted-manifest-sha256> <certifier-ed25519-public-key-hex> [operator-config.json]\n  {executable} <admit|serve> <graph-package-directory> <mechanism-state-directory> [http-material-directory]"
    )
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os();
    let executable = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "wasm-biotic-kernel".to_string());
    let command = arguments.next().ok_or_else(|| usage(&executable))?;
    let command = command.to_string_lossy();
    if command == "init" {
        let state = arguments.next().ok_or_else(|| usage(&executable))?;
        let trusted_manifest: Sha256Digest = arguments
            .next()
            .ok_or_else(|| usage(&executable))?
            .into_string()
            .map_err(|_| "trusted manifest digest must be UTF-8")?
            .parse()?;
        let trusted_certifier = TrustedCertifier::from_public_key_hex(
            &arguments
                .next()
                .ok_or_else(|| usage(&executable))?
                .into_string()
                .map_err(|_| "certifier public key must be UTF-8")?,
        )?;
        let certifier_key_id = trusted_certifier.key_id();
        let config = match arguments.next() {
            Some(path) => LocalConfig::from_canonical_json_file(path)?,
            None => LocalConfig::default(),
        };
        if arguments.next().is_some() {
            return Err(usage(&executable).into());
        }
        let state = PathBuf::from(state);
        LocalMechanisms::initialize(&state, config, trusted_manifest, trusted_certifier)?;
        eprintln!(
            "initialized operator capacity at {} trusted-bootstrap={trusted_manifest} trusted-certifier={certifier_key_id}",
            state.display()
        );
        return Ok(());
    }
    if command != "serve" && command != "admit" {
        return Err(format!("unknown command '{command}'; expected init, admit or serve").into());
    }

    let package = arguments.next().ok_or_else(|| usage(&executable))?;
    let state = arguments.next().ok_or_else(|| usage(&executable))?;
    let http_materials = arguments.next();
    if arguments.next().is_some() {
        return Err(usage(&executable).into());
    }
    let state = PathBuf::from(state);
    let mechanisms = match http_materials {
        Some(path) => LocalMechanisms::open_existing_with_http_materials(&state, path)?,
        None => LocalMechanisms::open_existing(&state)?,
    };
    let admission = RootAdmission::from_package_directory(package)?;
    let supplied_manifest = admission.manifest_digest;
    let operator_capacity = mechanisms.root_runtime_capacity();
    if command == "admit" {
        let limits = admission.bounded_root_limits(&operator_capacity)?;
        let engine = OpaqueRootEngine::load(admission, mechanisms, limits)?;
        eprintln!(
            "admitted manifest={} root={}",
            engine.binding().manifest_digest,
            engine.binding().composed_root_digest
        );
        return Ok(());
    }
    let active = mechanisms.active_manifest_reference()?;
    let mut manager = match active {
        None => OpaqueRootManager::bootstrap(admission, mechanisms, operator_capacity)?,
        Some(reference) => {
            let selected: Sha256Digest =
                format!("sha256:{}", reference.content_digest.hex).parse()?;
            if selected != supplied_manifest {
                return Err(format!(
                    "package manifest {supplied_manifest} is not the active manifest {selected}"
                )
                .into());
            }
            OpaqueRootManager::boot(mechanisms, operator_capacity)?
        }
    };

    eprintln!(
        "ready manifest={} root={}",
        manager.binding().manifest_digest,
        manager.binding().composed_root_digest
    );
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Err(error) = manager.reload_if_changed() {
            eprintln!("activation reload rejected; running verified fallback: {error}");
        }
        let request: IngressRequest = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(error) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": {
                            "code": "invalid-ingress",
                            "message": error.to_string(),
                        }
                    })
                );
                continue;
            }
        };
        match manager.root().handle(&request) {
            Ok(outcome) => println!("{}", serde_json::to_string(&outcome)?),
            Err(error) => println!(
                "{}",
                serde_json::json!({
                    "error": {
                        "code": "kernel-invocation-failed",
                        "message": error.to_string(),
                    }
                })
            ),
        }
    }
    Ok(())
}
