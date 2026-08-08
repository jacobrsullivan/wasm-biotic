use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use wasm_biotic_kernel::{HOST_INTERFACE_ALLOWLIST, LocalConfig, Sha256Digest};

fn crate_path(relative: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

#[test]
fn machine_inventory_is_closed_and_truthful_about_implemented_scope() {
    let inventory: Value = serde_json::from_slice(
        &fs::read(crate_path("native-tcb.json")).expect("read native inventory"),
    )
    .expect("native inventory must be JSON");

    let allowlisted = inventory["native_boundary"]["allowlisted_interfaces"]
        .as_array()
        .expect("allowlisted interface array")
        .iter()
        .map(|value| value.as_str().expect("interface name"))
        .collect::<Vec<_>>();
    assert_eq!(allowlisted, HOST_INTERFACE_ALLOWLIST);
    let implemented = inventory["native_boundary"]["implemented_interfaces"]
        .as_array()
        .expect("implemented interface array")
        .iter()
        .map(|value| value.as_str().expect("implemented interface name"))
        .collect::<Vec<_>>();
    assert_eq!(implemented, HOST_INTERFACE_ALLOWLIST);
    assert_eq!(
        inventory["native_boundary"]["interface_profiles"]["http-transport"]["mode"].as_str(),
        Some("bounded-external"),
        "the inventoried R3 adapter must declare its bounded external transport"
    );
    assert_eq!(
        inventory["conformance"]["component_complete_claim"].as_bool(),
        Some(true)
    );
    assert_eq!(
        inventory["conformance"]["status"].as_str(),
        Some("component-complete-bounded-external-release")
    );
    for field in [
        "native_program_execution_reachable",
        "ambient_file_system_exposed_to_components",
        "ambient_environment_exposed_to_components",
        "ambient_network_exposed_to_components",
        "native_domain_modules_reachable",
    ] {
        assert_eq!(
            inventory["negative_attestations"][field].as_bool(),
            Some(false),
            "negative attestation {field} must remain false"
        );
    }

    let substrate_wit = fs::read_to_string(crate_path("../wit/wasm-biotic/substrate.wit"))
        .expect("read normative substrate WIT");
    for interface in HOST_INTERFACE_ALLOWLIST {
        assert!(
            substrate_wit.contains(&format!("interface {interface} {{")),
            "allowlisted interface '{interface}' is not declared by normative WIT"
        );
    }

    let mut wit_paths = fs::read_dir(crate_path("../wit/wasm-biotic"))
        .expect("read normative WIT package")
        .map(|entry| entry.expect("read WIT entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "wit"))
        .collect::<Vec<_>>();
    wit_paths.sort();
    let wit_files = wit_paths
        .into_iter()
        .map(|path| {
            let content = fs::read_to_string(&path).expect("read WIT file");
            serde_json::json!({
                "content": content,
                "content_digest": Sha256Digest::from_bytes(content.as_bytes()),
                "path": format!(
                    "wit/wasm-biotic/{}",
                    path.file_name().expect("WIT file name").to_string_lossy()
                ),
            })
        })
        .collect::<Vec<_>>();
    let wit_package = serde_json::to_vec(&serde_json::json!({
        "files": wit_files,
        "package": "wasm-biotic:factory@0.1.0",
        "schema": "wasm-biotic.wit-package.v1",
    }))
    .expect("encode WIT package artifact");
    let expected_wit_digest = inventory["compiled_wit_package"]["sha256"]
        .as_str()
        .expect("compiled WIT package digest");
    assert_eq!(
        Sha256Digest::from_bytes(&wit_package).to_string(),
        expected_wit_digest,
        "normative WIT changed without updating the compiled package binding"
    );
    let runtime_source =
        fs::read_to_string(crate_path("src/root_runtime.rs")).expect("read root runtime source");
    assert!(runtime_source.contains(expected_wit_digest));

    let lock_path = inventory["dependency_lock"]["path"]
        .as_str()
        .expect("dependency lock path");
    let expected_lock_digest = inventory["dependency_lock"]["sha256"]
        .as_str()
        .expect("dependency lock digest");
    let lock_bytes = fs::read(crate_path(lock_path)).expect("read dependency lock");
    assert_eq!(
        Sha256Digest::from_bytes(&lock_bytes).to_string(),
        expected_lock_digest,
        "dependency lock changed without updating the native inventory"
    );

    for artifact in inventory["fixture_artifacts"]
        .as_array()
        .expect("fixture artifact array")
    {
        let path = artifact["path"].as_str().expect("fixture artifact path");
        let expected = artifact["sha256"]
            .as_str()
            .expect("fixture artifact digest");
        let bytes = fs::read(crate_path(path)).expect("read fixture artifact");
        assert_eq!(
            Sha256Digest::from_bytes(&bytes).to_string(),
            expected,
            "fixture artifact changed without updating the native inventory"
        );
    }

    let operator_example = &inventory["operator_capacity_example"];
    let operator_path = operator_example["path"]
        .as_str()
        .expect("operator capacity example path");
    let operator_bytes =
        fs::read(crate_path(operator_path)).expect("read operator capacity example");
    assert_eq!(
        Sha256Digest::from_bytes(&operator_bytes).to_string(),
        operator_example["sha256"]
            .as_str()
            .expect("operator capacity example digest"),
        "operator capacity example changed without updating the native inventory"
    );
    LocalConfig::from_canonical_json_file(crate_path(operator_path))
        .expect("operator capacity example must be canonical and match the closed schema");

    let http_operator_example = &inventory["http_operator_capacity_example"];
    let http_operator_path = http_operator_example["path"]
        .as_str()
        .expect("HTTP operator capacity example path");
    let http_operator_bytes =
        fs::read(crate_path(http_operator_path)).expect("read HTTP operator capacity example");
    assert_eq!(
        Sha256Digest::from_bytes(&http_operator_bytes).to_string(),
        http_operator_example["sha256"]
            .as_str()
            .expect("HTTP operator capacity example digest"),
        "HTTP operator capacity example changed without updating the native inventory"
    );
    LocalConfig::from_canonical_json_file(crate_path(http_operator_path))
        .expect("HTTP operator capacity example must be canonical and match the closed schema");

    let crate_manifest = fs::read_to_string(crate_path("Cargo.toml")).expect("read crate manifest");
    assert!(crate_manifest.contains("version = \"=43.0.1\""));
    assert!(crate_manifest.contains("default-features = false"));
    assert!(!crate_manifest.contains("aiaf-v1"));
    assert!(!crate_manifest.contains("path = \".."));
}

#[test]
fn reachable_native_source_has_no_domain_or_program_execution_escape_hatch() {
    let inventory: Value = serde_json::from_slice(
        &fs::read(crate_path("native-tcb.json")).expect("read native inventory"),
    )
    .expect("native inventory must be JSON");
    let modules = inventory["reachable_native_modules"]
        .as_array()
        .expect("reachable module array");

    let mut inventoried_paths = modules
        .iter()
        .map(|module| module["path"].as_str().expect("module path").to_string())
        .collect::<Vec<_>>();
    inventoried_paths.sort();
    let mut source_paths = fs::read_dir(crate_path("src"))
        .expect("read source directory")
        .map(|entry| entry.expect("read source entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .map(|path| {
            format!(
                "src/{}",
                path.file_name()
                    .expect("source file name")
                    .to_string_lossy()
            )
        })
        .collect::<Vec<_>>();
    source_paths.extend(
        fs::read_dir(crate_path("src/bin"))
            .expect("read binary source directory")
            .map(|entry| entry.expect("read binary source entry").path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
            .map(|path| {
                format!(
                    "src/bin/{}",
                    path.file_name()
                        .expect("binary source file name")
                        .to_string_lossy()
                )
            }),
    );
    source_paths.sort();
    assert_eq!(
        inventoried_paths, source_paths,
        "every native source module must be present in the machine inventory"
    );

    let forbidden_tokens = [
        "supervisor",
        "worker",
        "planner",
        "builder",
        "validator",
        "reviewer",
        "packager",
        "continuity",
        "milestone",
        "promotion",
        "closure",
        "northstar",
        "north_star",
        "commandexecute",
        "command_execute",
    ];
    let forbidden_fragments = [
        "std::process",
        "process::command",
        "command::new",
        "std::env",
        "/bin/sh",
        "/bin/bash",
        "powershell",
        "native-shell",
        "process-runner",
        "native_services",
        "workspace-open",
        "workspace-snapshot",
        "workspace-patch",
        "candidate-build",
        "command-execute",
        "package-publish",
        "package-verify",
        "validation-prove",
        "validation-compare",
        "review-candidate",
        "evidence-publish",
        "evidence-resolve",
        "schedule-job",
        "deployment-initialize",
        "deployment-activate",
        "deployment-observe",
        "deployment-rollback",
        "operations-inspect",
        "factory-execute",
        "factory-provider-proposal",
        "factory-shadow",
        "factory-initialize",
        "factory-state-migrate",
        "factory-activate",
        "factory-observe",
        "factory-rollback",
        "factory-inspect",
        "build-service",
        "packaging-service",
        "validation-service",
        "review-service",
        "continuity-service",
        "scheduling-service",
        "operations-service",
        "include!",
        "#[path",
    ];

    for module in modules {
        let relative = module["path"].as_str().expect("module path");
        let expected_digest = module["sha256"].as_str().expect("module digest");
        assert!(relative.starts_with("src/") && !relative.contains(".."));
        let source_bytes = fs::read(crate_path(relative)).expect("read reachable module");
        assert_eq!(
            Sha256Digest::from_bytes(&source_bytes).to_string(),
            expected_digest,
            "reachable native module changed without updating the machine inventory"
        );
        let source = String::from_utf8(source_bytes).expect("reachable module must be UTF-8");
        let normalized = source.to_ascii_lowercase();
        // `std::thread::Builder` is the fallible standard-library thread
        // constructor, not a factory role. Keep that one exact infrastructure
        // spelling out of the domain-vocabulary scan.
        let domain_vocabulary = normalized.replace(
            "std::thread::builder",
            "std::thread::fallible_thread_constructor",
        );
        let lexical_tokens = domain_vocabulary
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .filter(|token| !token.is_empty())
            .collect::<Vec<_>>();
        for token in forbidden_tokens {
            assert!(
                !lexical_tokens.contains(&token),
                "reachable module {relative} contains forbidden domain token '{token}'"
            );
        }
        for fragment in forbidden_fragments {
            if relative == "src/bin/wasm-biotic-kernel.rs" && fragment == "std::env" {
                continue;
            }
            assert!(
                !normalized.contains(fragment),
                "reachable module {relative} contains forbidden native import fragment '{fragment}'"
            );
        }
        if relative != "src/local.rs" && relative != "src/http_transport.rs" {
            assert!(
                !normalized.contains("std::fs"),
                "only the inventoried persistence and HTTP material adapters may access configured filesystem roots"
            );
        }
        if relative != "src/http_transport.rs" {
            assert!(
                !normalized.contains("std::net"),
                "only the inventoried bounded HTTP adapter may access native networking"
            );
        } else {
            assert!(normalized.contains("tcpstream"));
            assert!(normalized.contains("to_socket_addrs"));
            assert!(!normalized.contains("udp"));
        }
        if relative != "src/bin/wasm-biotic-kernel.rs" {
            assert!(
                !normalized.contains("std::env"),
                "only the generic launcher may read process arguments"
            );
        } else {
            assert!(normalized.contains("std::env::args_os"));
            assert!(!normalized.contains("std::env::vars"));
        }
    }

    let manifest = fs::read_to_string(crate_path("Cargo.toml")).expect("read crate manifest");
    assert!(
        !crate_path("build.rs").exists(),
        "build scripts are outside the inventoried source boundary"
    );
    for direct_dependency in [
        "duct =",
        "shell-words =",
        "command-group =",
        "subprocess =",
        "tokio =",
        "reqwest =",
        "hyper =",
    ] {
        assert!(
            !manifest.to_ascii_lowercase().contains(direct_dependency),
            "crate manifest contains forbidden direct dependency '{direct_dependency}'"
        );
    }
    for required_dependency in [
        "http = \"=1.4.0\"",
        "ipnet = \"=2.12.0\"",
        "rustls = { version = \"=0.23.38\"",
        "url = \"=2.5.8\"",
        "webpki-roots = \"=1.0.7\"",
    ] {
        assert!(
            manifest.contains(required_dependency),
            "bounded HTTP dependency is not exact: {required_dependency}"
        );
    }
}
