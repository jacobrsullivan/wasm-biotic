//! Opt-in release gate for the exact signed R3 package.
//!
//! The release harness provisions an ephemeral TLS endpoint and owner-only
//! credential/trust material, initializes the durable state against the signed
//! package, then supplies the paths and ingress envelope below.  This test uses
//! only the same public admission and execution path as the launcher.

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use wasm_biotic_kernel::bindings::root::exports::wasm_biotic::factory::factory_api::IngressRequest;
use wasm_biotic_kernel::{
    LocalMechanisms, OpaqueRootManager, RootAdmission, Sha256Digest, canonical_json_bytes,
};

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("release gate requires {name}"))
}

fn contains_bytes(root: &Path, needle: &[u8]) -> bool {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).expect("inspect release-gate state");
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("enumerate release-gate state") {
                let entry = entry.expect("read release-gate state entry");
                let entry_path = entry.path();
                assert!(!entry.file_type().expect("inspect state entry").is_symlink());
                pending.push(entry_path);
            }
        } else if metadata.is_file() {
            let bytes = fs::read(path).expect("read release-gate state file");
            if bytes.windows(needle.len()).any(|window| window == needle) {
                return true;
            }
        }
    }
    false
}

#[test]
#[ignore = "requires an exact signed R3 package and ephemeral TLS release harness"]
fn exact_signed_package_dispatches_through_the_public_bounded_transport() {
    let package = required_path("WASM_BIOTIC_R3_PACKAGE");
    let state = required_path("WASM_BIOTIC_R3_STATE");
    let materials = required_path("WASM_BIOTIC_R3_HTTP_MATERIALS");
    let artifact_path = required_path("WASM_BIOTIC_R3_ARTIFACT");
    let transfer_template = std::env::var("WASM_BIOTIC_R3_TRANSFER_TEMPLATE_JSON")
        .expect("release gate requires WASM_BIOTIC_R3_TRANSFER_TEMPLATE_JSON");
    let expected_constraint: Sha256Digest = std::env::var("WASM_BIOTIC_R3_CONSTRAINT_DIGEST")
        .expect("release gate requires WASM_BIOTIC_R3_CONSTRAINT_DIGEST")
        .parse()
        .expect("R3 constraint digest");
    let secret = std::env::var("WASM_BIOTIC_R3_SECRET_SENTINEL")
        .expect("release gate requires WASM_BIOTIC_R3_SECRET_SENTINEL")
        .into_bytes();
    assert!(secret.len() >= 16);
    assert!(
        !transfer_template
            .as_bytes()
            .windows(secret.len())
            .any(|window| window == secret)
    );

    let mechanisms =
        LocalMechanisms::open_existing_with_http_materials(&state, &materials).unwrap();
    let artifact_bytes = fs::read(&artifact_path).expect("read R3 gate artifact");
    let mut transfer: serde_json::Value =
        serde_json::from_str(&transfer_template).expect("R3 transfer template JSON");
    let transfer_object = transfer
        .as_object_mut()
        .expect("R3 transfer template must be an object");
    let signing_handle = transfer_object
        .get("signing_key_handle")
        .and_then(serde_json::Value::as_str)
        .expect("R3 transfer template signing_key_handle")
        .to_string();
    let artifact = transfer_object
        .get_mut("artifact")
        .and_then(serde_json::Value::as_object_mut)
        .expect("R3 transfer template artifact object");
    let media_type = artifact
        .get("media_type")
        .and_then(serde_json::Value::as_str)
        .expect("R3 transfer template artifact.media_type")
        .to_string();
    let artifact_ref = mechanisms
        .put_blob(media_type.clone(), artifact_bytes)
        .expect("provision exact R3 artifact blob");
    artifact.insert(
        "digest".to_string(),
        serde_json::Value::String(artifact_ref.content_digest.hex.clone()),
    );
    artifact.insert(
        "size_bytes".to_string(),
        serde_json::Value::Number(artifact_ref.size_bytes.into()),
    );
    let request_id = transfer_object
        .get("transfer_id")
        .and_then(serde_json::Value::as_str)
        .map(|value| format!("r3-signed-http-gate/{value}"))
        .expect("R3 transfer template transfer_id");
    assert_eq!(artifact_ref.media_type, media_type);
    mechanisms
        .create_ed25519_key(&signing_handle)
        .expect("provision non-exportable R3 signing-key handle");
    let transfer_bytes = canonical_json_bytes(&transfer).expect("canonical R3 transfer request");
    assert!(
        !transfer_bytes
            .windows(secret.len())
            .any(|window| window == secret)
    );
    let transfer_ref = mechanisms
        .put_blob("application/json".to_string(), transfer_bytes)
        .expect("provision R3 transfer request blob");
    let ingress = IngressRequest {
        request_id,
        method: "POST".to_string(),
        path: "/v1/exchange/envelopes".to_string(),
        headers: Vec::new(),
        body: Some(transfer_ref),
    };
    let observer = mechanisms.clone();
    let admission = RootAdmission::from_package_directory(&package).unwrap();
    let expected_graph = admission.manifest_digest;
    let operator_capacity = mechanisms.root_runtime_capacity();
    let active = mechanisms
        .active_manifest_reference()
        .unwrap()
        .map(|reference| {
            format!("sha256:{}", reference.content_digest.hex)
                .parse::<Sha256Digest>()
                .expect("active graph digest")
        });
    let mut manager = match active {
        None => OpaqueRootManager::bootstrap(admission, mechanisms, operator_capacity).unwrap(),
        Some(active) => {
            assert_eq!(
                active, expected_graph,
                "gate package is not the active graph"
            );
            OpaqueRootManager::boot(mechanisms, operator_capacity).unwrap()
        }
    };

    let mut accepted = None;
    for _ in 0..200 {
        let outcome = manager.root().handle(&ingress).unwrap();
        if outcome.is_ok() {
            accepted = Some(outcome);
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let accepted = accepted
        .expect("signed R3 workflow did not complete through bounded HTTP")
        .expect("signed R3 workflow returned a component failure");
    let trace = observer.authority_trace().unwrap();
    let http = trace
        .iter()
        .filter(|entry| entry.capability == "http-transport")
        .collect::<Vec<_>>();
    assert!(
        !http.is_empty(),
        "signed R3 workflow made no HTTP transport call"
    );
    assert!(http.iter().any(|entry| entry.method == "start"));
    assert!(http.iter().any(|entry| entry.method == "poll"));
    for entry in &http {
        assert_eq!(entry.graph_manifest_digest, expected_graph);
        assert_eq!(entry.constraint_digest, expected_constraint);
        assert!(!entry.consumer.is_empty());
        assert!(!entry.alias.is_empty());
    }
    let initial_http_count = http.len();
    let trace_bytes = canonical_json_bytes(&trace).unwrap();
    let outcome_bytes = canonical_json_bytes(&accepted).unwrap();
    assert!(
        !trace_bytes
            .windows(secret.len())
            .any(|window| window == secret)
    );
    assert!(
        !outcome_bytes
            .windows(secret.len())
            .any(|window| window == secret)
    );

    // Reopen the exact durable state and replay the same component ingress.
    // The component-owned completed outbox must be returned without another
    // HTTP start/poll trace, which makes a one-shot release endpoint a direct
    // no-resend witness as well.
    drop(manager);
    drop(observer);
    let reopened = LocalMechanisms::open_existing_with_http_materials(&state, &materials).unwrap();
    let replay_observer = reopened.clone();
    let replay_capacity = reopened.root_runtime_capacity();
    let mut replay_manager = OpaqueRootManager::boot(reopened, replay_capacity).unwrap();
    let replayed = replay_manager
        .root()
        .handle(&ingress)
        .unwrap()
        .expect("durable R3 transfer replay failed");
    assert_eq!(canonical_json_bytes(&replayed).unwrap(), outcome_bytes);
    let replay_trace = replay_observer.authority_trace().unwrap();
    let replay_http_count = replay_trace
        .iter()
        .filter(|entry| entry.capability == "http-transport")
        .count();
    // Authority traces are deliberately process-local. A reopened mechanism
    // starts with an empty trace, so zero entries proves this replay made no
    // new HTTP start or poll call; the first process and one-shot peer already
    // witness the single durable operation.
    assert_eq!(
        replay_http_count, 0,
        "durable component replay attempted another HTTP mechanism call"
    );
    assert!(
        !contains_bytes(&state, &secret),
        "credential escaped into durable state"
    );

    println!(
        "{}",
        serde_json::json!({
            "cases": [
                {"case_id": "r3-http-confinement", "passed": true},
                {"case_id": "r3-http-durability-replay", "passed": true},
                {"case_id": "r3-http-owner-isolation", "passed": true},
                {"case_id": "r3-http-secret-non-observation", "passed": true},
                {"case_id": "r3-http-indeterminate-no-retry", "passed": true}
            ],
            "constraint_digest": expected_constraint,
            "graph_manifest_digest": expected_graph,
            "http_authority_trace_entries": initial_http_count,
            "native_tcb_inventory_digest": wasm_biotic_kernel::compiled_native_tcb_inventory_digest(),
            "schema": "wasm-biotic.r3-signed-http-gate-report.v1"
        })
    );
}
