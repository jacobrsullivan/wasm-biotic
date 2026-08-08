//! Instantiate and invoke the compiled review service with deterministic,
//! an in-memory implementation of its declared blob-store interface.

use std::{collections::BTreeMap, path::PathBuf};
use wasm_biotic_service_policy_core::hex_sha256;
use wasmtime::{
    Config, Engine, Store,
    component::{Component, HasSelf, Linker},
};

wasmtime::component::bindgen!({
    path: "../../../wit/wasm-biotic",
    world: "review-service-component",
});

use wasm_biotic::factory::capability_contract::{
    AuthorityClass, CapabilityRequest, Operation, ServiceFamily, ServiceOutcome,
};
use wasm_biotic::factory::foundation::{BlobRef, Digest, Failure, HashAlgorithm, Principal};

#[derive(Default)]
struct HostState {
    blobs: BTreeMap<String, (String, Vec<u8>)>,
    blob_gets: u64,
}

impl wasm_biotic::factory::foundation::Host for HostState {}

impl wasm_biotic::factory::capability_contract::Host for HostState {}

impl wasm_biotic::factory::blob_store::Host for HostState {
    fn put(&mut self, media_type: String, content: Vec<u8>) -> Result<BlobRef, Failure> {
        let digest = digest_bytes(&content);
        let reference = BlobRef {
            content_digest: digest.clone(),
            size_bytes: content.len() as u64,
            media_type: media_type.clone(),
        };
        self.blobs.insert(digest.hex, (media_type, content));
        Ok(reference)
    }

    fn get(&mut self, reference: BlobRef) -> Result<Vec<u8>, Failure> {
        self.blob_gets += 1;
        self.blobs
            .get(&reference.content_digest.hex)
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| failure("missing-blob", "smoke blob was not found"))
    }

    fn has(&mut self, content_digest: Digest) -> Result<bool, Failure> {
        Ok(self.blobs.contains_key(&content_digest.hex))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let component_path = std::env::args().nth(1).map(PathBuf::from).ok_or(
        "usage: cargo run -p wasm-biotic-review-service --example smoke -- <component.wasm>",
    )?;
    let input = b"bounded review candidate v1".to_vec();
    let input_ref = blob_ref("application/octet-stream", &input);
    let mut host = HostState::default();
    host.blobs.insert(
        input_ref.content_digest.hex.clone(),
        (input_ref.media_type.clone(), input),
    );

    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, &component_path)?;
    let mut linker = Linker::new(&engine);
    ReviewServiceComponent::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;
    let mut store = Store::new(&engine, host);
    let bindings = ReviewServiceComponent::instantiate(&mut store, &component, &linker)?;
    let service_component = digest_bytes(&std::fs::read(&component_path)?);
    let mut request = CapabilityRequest {
        request_id: "review-smoke-1".to_string(),
        job_id: "job-smoke-1".to_string(),
        caller: Principal {
            id: "reviewer-worker".to_string(),
            component_digest: digest_bytes(b"reviewer-worker"),
        },
        service_component: service_component.clone(),
        family: ServiceFamily::Review,
        operation: Operation::ReviewCandidate,
        input: input_ref.clone(),
        authority: AuthorityClass::Observe,
        approval: None,
        deadline_ms: None,
        idempotency_key: digest_bytes(b"review-smoke-idempotency"),
    };

    request.family = ServiceFamily::Build;
    let wrong_family = bindings
        .wasm_biotic_factory_review_service()
        .call_invoke(&mut store, &request)?;
    assert_rejected(&wrong_family.outcome, "wrong-service-family")?;
    assert_eq!(store.data().blob_gets, 0, "rejection must precede effects");

    request.family = ServiceFamily::Review;
    request.operation = Operation::PackageVerify;
    let wrong_operation = bindings
        .wasm_biotic_factory_review_service()
        .call_invoke(&mut store, &request)?;
    assert_rejected(&wrong_operation.outcome, "operation-not-owned")?;
    assert_eq!(store.data().blob_gets, 0, "rejection must precede effects");

    request.operation = Operation::ReviewCandidate;
    let response = bindings
        .wasm_biotic_factory_review_service()
        .call_invoke(&mut store, &request)?;
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.service_component.hex, service_component.hex);
    assert!(response.effect_receipts.is_empty());
    assert_eq!(response.evidence.len(), 2);
    let output = match response.outcome {
        ServiceOutcome::Succeeded(output) => output,
        other => return Err(format!("review smoke did not succeed: {other:?}").into()),
    };
    assert_ne!(output.content_digest.hex, input_ref.content_digest.hex);
    let stored = store
        .data()
        .blobs
        .get(&output.content_digest.hex)
        .ok_or("output blob was not stored")?;
    assert!(stored.1.starts_with(b"WASM-BIOTIC-CAPABILITY-RESULT\0\x01"));
    println!(
        "executed {}: input sha256:{} -> output sha256:{}",
        component_path.display(),
        input_ref.content_digest.hex,
        output.content_digest.hex
    );
    Ok(())
}

fn assert_rejected(
    outcome: &ServiceOutcome,
    expected_code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match outcome {
        ServiceOutcome::Rejected(failure) if failure.code == expected_code => Ok(()),
        other => Err(format!("expected rejection {expected_code}, got {other:?}").into()),
    }
}

fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest {
        algorithm: HashAlgorithm::Sha256,
        hex: hex_sha256(bytes),
    }
}

fn blob_ref(media_type: &str, bytes: &[u8]) -> BlobRef {
    BlobRef {
        content_digest: digest_bytes(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_string(),
    }
}

fn failure(code: &str, message: &str) -> Failure {
    Failure {
        code: code.to_string(),
        message: message.to_string(),
        retryable: false,
        evidence: None,
    }
}
