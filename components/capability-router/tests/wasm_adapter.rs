//! Execute the compiled capability-router component against deterministic
//! cryptographic and durable-storage primitives. These host implementations
//! are policy-test fixtures, not candidate native implementations of routing,
//! approval, or service behavior.

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use std::{collections::BTreeMap, path::PathBuf};
use wasm_biotic_service_policy_core::{
    CapabilityDecisionMaterial, capability_decision_digest_hex, hex_sha256,
};
use wasmtime::{
    Config, Engine, Store,
    component::{Component, HasSelf, Linker},
};

wasmtime::component::bindgen!({
    path: "../../wit/wasm-biotic",
    world: "capability-router-component",
});

use wasm_biotic::factory::capability_contract::{
    CapabilityRequest, CapabilityResponse, Operation, ServiceFamily, ServiceOutcome,
};
use wasm_biotic::factory::foundation::{
    ApprovalProof, AuthorityClass, BlobRef, Digest, Failure, HashAlgorithm, Principal,
};
use wasm_biotic::factory::key_service::{Signature, SignatureAlgorithm};
use wasm_biotic::factory::transaction_store::{
    CommitReceipt, CommitRequest, Mutation, VersionedValue,
};

const APPROVAL_NAMESPACE: &str = "wasm-biotic.approvals.v1";
const APPROVAL_USE_MEDIA_TYPE: &str = "application/vnd.wasm-biotic.approval-use.v1+octet-stream";

#[derive(Default)]
struct HostState {
    blobs: BTreeMap<String, (String, Vec<u8>)>,
    records: BTreeMap<(String, String), (u64, BlobRef)>,
    public_keys: BTreeMap<String, Vec<u8>>,
    delegate_calls: u64,
    approval_reads: u64,
    approval_commits: u64,
    approval_blob_puts: u64,
}

impl wasm_biotic::factory::foundation::Host for HostState {}
impl wasm_biotic::factory::capability_contract::Host for HostState {}

impl wasm_biotic::factory::blob_store::Host for HostState {
    fn put(&mut self, media_type: String, content: Vec<u8>) -> Result<BlobRef, Failure> {
        if media_type == APPROVAL_USE_MEDIA_TYPE {
            self.approval_blob_puts += 1;
        }
        let reference = blob_ref(&media_type, &content);
        self.blobs
            .insert(reference.content_digest.hex.clone(), (media_type, content));
        Ok(reference)
    }

    fn get(&mut self, reference: BlobRef) -> Result<Vec<u8>, Failure> {
        self.blobs
            .get(&reference.content_digest.hex)
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| failure("missing-blob", "approval binding blob was not found"))
    }

    fn has(&mut self, content_digest: Digest) -> Result<bool, Failure> {
        Ok(self.blobs.contains_key(&content_digest.hex))
    }
}

impl wasm_biotic::factory::transaction_store::Host for HostState {
    fn read(&mut self, namespace: String, key: String) -> Result<Option<VersionedValue>, Failure> {
        if namespace != APPROVAL_NAMESPACE {
            return Err(failure(
                "out-of-scope",
                "approval fixture exposes only the declared approval namespace",
            ));
        }
        self.approval_reads += 1;
        Ok(self
            .records
            .get(&(namespace, key))
            .map(|(version, value)| VersionedValue {
                version: *version,
                value: value.clone(),
            }))
    }

    fn commit(&mut self, request: CommitRequest) -> Result<CommitReceipt, Failure> {
        if request
            .assertions
            .iter()
            .any(|assertion| assertion.namespace != APPROVAL_NAMESPACE)
        {
            return Err(failure(
                "out-of-scope",
                "approval fixture exposes only the declared approval namespace",
            ));
        }
        for assertion in &request.assertions {
            let actual = self
                .records
                .get(&(assertion.namespace.clone(), assertion.key.clone()))
                .map(|(version, _)| *version);
            if actual != assertion.expected_version {
                return Err(failure("cas-conflict", "approval assertion failed"));
            }
        }

        let mut commit_version = 0;
        let mut committed_value_digest = digest_bytes(b"empty-approval-commit");
        for mutation in request.mutations {
            match mutation {
                Mutation::Put((namespace, key, value)) => {
                    if namespace != APPROVAL_NAMESPACE {
                        return Err(failure(
                            "out-of-scope",
                            "approval fixture exposes only the declared approval namespace",
                        ));
                    }
                    let next = self
                        .records
                        .get(&(namespace.clone(), key.clone()))
                        .map_or(1, |(version, _)| version + 1);
                    commit_version = next;
                    committed_value_digest = value.content_digest.clone();
                    self.records.insert((namespace, key), (next, value));
                }
                Mutation::Delete((namespace, key)) => {
                    if namespace != APPROVAL_NAMESPACE {
                        return Err(failure(
                            "out-of-scope",
                            "approval fixture exposes only the declared approval namespace",
                        ));
                    }
                    self.records.remove(&(namespace, key));
                }
            }
        }
        self.approval_commits += 1;
        Ok(CommitReceipt {
            transaction_id: request.transaction_id,
            commit_version,
            committed_value_digest,
        })
    }
}

impl wasm_biotic::factory::key_service::Host for HostState {
    fn sign_digest(&mut self, _key_handle: String, _payload: Digest) -> Result<Signature, Failure> {
        Err(failure(
            "unsupported-test-operation",
            "the router must verify approvals, never sign them",
        ))
    }

    fn verify_digest(
        &mut self,
        key_id: String,
        payload: Digest,
        signature: Signature,
    ) -> Result<bool, Failure> {
        if signature.key_id != key_id
            || !matches!(payload.algorithm, HashAlgorithm::Sha256)
            || !matches!(signature.algorithm, SignatureAlgorithm::Ed25519)
        {
            return Ok(false);
        }
        let Some(public_key) = self.public_keys.get(&key_id) else {
            return Ok(false);
        };
        let Ok(payload_bytes) = decode_sha256_hex(&payload.hex) else {
            return Ok(false);
        };
        Ok(UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&payload_bytes, &signature.bytes)
            .is_ok())
    }

    fn random_bytes(&mut self, _length: u32) -> Result<Vec<u8>, Failure> {
        Err(failure(
            "unsupported-test-operation",
            "the router must not request entropy",
        ))
    }
}

macro_rules! delegate_service {
    ($module:ident) => {
        impl wasm_biotic::factory::$module::Host for HostState {
            fn invoke(&mut self, request: CapabilityRequest) -> CapabilityResponse {
                self.delegate_calls += 1;
                CapabilityResponse {
                    request_id: request.request_id,
                    service_component: request.service_component,
                    outcome: ServiceOutcome::Succeeded(request.input),
                    effect_receipts: Vec::new(),
                    evidence: Vec::new(),
                }
            }
        }
    };
}

delegate_service!(build_service);
delegate_service!(packaging_service);
delegate_service!(validation_service);
delegate_service!(review_service);
delegate_service!(continuity_service);
delegate_service!(scheduling_service);
delegate_service!(operations_service);

#[test]
fn compiled_router_authenticates_records_and_replay_binds_signed_approvals() {
    let component_path = component_path();
    let component_bytes = std::fs::read(&component_path).expect("read compiled router fixture");
    let signer = Ed25519KeyPair::from_seed_unchecked(&[0x42; 32]).expect("fixed Ed25519 seed");
    let signer_id = format!("sha256:{}", hex_sha256(signer.public_key().as_ref()));

    let mut host = HostState::default();
    host.public_keys
        .insert(signer_id.clone(), signer.public_key().as_ref().to_vec());

    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config).expect("create Wasmtime engine");
    let component = Component::new(&engine, component_bytes).expect("compile router component");
    let mut linker = Linker::new(&engine);
    CapabilityRouterComponent::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
        .expect("link router world");
    let mut store = Store::new(&engine, host);
    let bindings = CapabilityRouterComponent::instantiate(&mut store, &component, &linker)
        .expect("instantiate router component");

    let request = signed_request(
        "request-valid-1",
        "approval-1",
        1_754_000_000_000,
        &signer_id,
        &signer,
    );
    let first = route(&bindings, &mut store, &request);
    assert_succeeded(&first.outcome);
    assert_eq!(
        store.data().delegate_calls,
        1,
        "valid first use delegates once"
    );
    assert_eq!(store.data().approval_reads, 1);
    assert_eq!(store.data().approval_commits, 1);
    assert_eq!(store.data().approval_blob_puts, 1);
    assert_eq!(store.data().records.len(), 1);

    let replay = route(&bindings, &mut store, &request);
    assert_succeeded(&replay.outcome);
    assert_eq!(
        store.data().delegate_calls,
        2,
        "byte-exact replay remains idempotent and may repeat the same delegate call"
    );
    assert_eq!(store.data().approval_commits, 1, "replay must not recommit");
    assert_eq!(
        store.data().approval_blob_puts,
        1,
        "replay must not rewrite"
    );
    assert_eq!(store.data().records.len(), 1);
    assert_eq!(store.data().approval_reads, 2);

    let changed = signed_request(
        "request-changed-2",
        "approval-1",
        1_754_000_000_000,
        &signer_id,
        &signer,
    );
    let changed_response = route(&bindings, &mut store, &changed);
    assert_rejected(&changed_response.outcome, "approval-reused");
    assert_eq!(
        store.data().delegate_calls,
        2,
        "changed request with the same approval id must not reach a service"
    );
    assert_eq!(store.data().approval_commits, 1);
    assert_eq!(store.data().approval_blob_puts, 1);
    assert_eq!(store.data().approval_reads, 3);

    let mut forged_signer = request.clone();
    forged_signer.approval.as_mut().expect("approval").approver = "sha256:forged-signer".into();
    let forged_signer_response = route(&bindings, &mut store, &forged_signer);
    assert_rejected(
        &forged_signer_response.outcome,
        "invalid-approval-signature",
    );
    assert_eq!(
        store.data().delegate_calls,
        2,
        "forged signer must be rejected before service delegation"
    );
    assert_eq!(
        store.data().approval_reads,
        3,
        "signature rejection must precede durable replay lookup"
    );

    let mut forged_signature = request.clone();
    forged_signature
        .approval
        .as_mut()
        .expect("approval")
        .signature[0] ^= 0x80;
    let forged_signature_response = route(&bindings, &mut store, &forged_signature);
    assert_rejected(
        &forged_signature_response.outcome,
        "invalid-approval-signature",
    );
    assert_eq!(
        store.data().delegate_calls,
        2,
        "forged signature must be rejected before service delegation"
    );
    assert_eq!(store.data().approval_commits, 1);
    assert_eq!(store.data().approval_blob_puts, 1);
    assert_eq!(store.data().records.len(), 1);
    assert_eq!(
        store.data().approval_reads,
        3,
        "signature rejection must precede durable replay lookup"
    );
}

fn route(
    bindings: &CapabilityRouterComponent,
    store: &mut Store<HostState>,
    request: &CapabilityRequest,
) -> CapabilityResponse {
    bindings
        .wasm_biotic_factory_capability_router()
        .call_route(store, request)
        .expect("invoke compiled router component")
}

fn signed_request(
    request_id: &str,
    approval_id: &str,
    recorded_at_ms: u64,
    signer_id: &str,
    signer: &Ed25519KeyPair,
) -> CapabilityRequest {
    let caller = Principal {
        id: "operator-component".into(),
        component_digest: digest_bytes(b"operator-component"),
    };
    let service_component = digest_bytes(b"operations-service-component");
    let input = blob_ref("application/octet-stream", b"activate graph digest");
    let decision_hex = capability_decision_digest_hex(&CapabilityDecisionMaterial {
        request_id,
        job_id: "job-approval-1",
        caller_id: &caller.id,
        caller_component_hex: &caller.component_digest.hex,
        service_component_hex: &service_component.hex,
        family: "operations",
        operation: "factory-activate",
        input_digest_hex: &input.content_digest.hex,
        input_size: input.size_bytes,
        input_media_type: &input.media_type,
        authority: "promotion-control",
        deadline_ms: Some(1_754_000_001_000),
    });
    let decision_digest = Digest {
        algorithm: HashAlgorithm::Sha256,
        hex: decision_hex,
    };
    let signature = signer.sign(&decode_sha256_hex(&decision_digest.hex).expect("decision digest"));
    CapabilityRequest {
        request_id: request_id.into(),
        job_id: "job-approval-1".into(),
        caller,
        service_component,
        family: ServiceFamily::Operations,
        operation: Operation::FactoryActivate,
        input,
        authority: AuthorityClass::PromotionControl,
        approval: Some(ApprovalProof {
            approval_id: approval_id.into(),
            decision_digest: decision_digest.clone(),
            approver: signer_id.into(),
            recorded_at_ms,
            signature: signature.as_ref().to_vec(),
        }),
        deadline_ms: Some(1_754_000_001_000),
        idempotency_key: decision_digest,
    }
}

fn assert_succeeded(outcome: &ServiceOutcome) {
    assert!(
        matches!(outcome, ServiceOutcome::Succeeded(_)),
        "expected service success, got {outcome:?}"
    );
}

fn assert_rejected(outcome: &ServiceOutcome, expected_code: &str) {
    match outcome {
        ServiceOutcome::Rejected(failure) if failure.code == expected_code => {}
        other => panic!("expected rejection {expected_code}, got {other:?}"),
    }
}

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/artifacts/capability-router-component.wasm")
}

fn decode_sha256_hex(value: &str) -> Result<[u8; 32], ()> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    if value.len() != 64 {
        return Err(());
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16).map_err(|_| ())?;
    }
    Ok(bytes)
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
        media_type: media_type.into(),
    }
}

fn failure(code: &str, message: &str) -> Failure {
    Failure {
        code: code.into(),
        message: message.into(),
        retryable: false,
        evidence: None,
    }
}
