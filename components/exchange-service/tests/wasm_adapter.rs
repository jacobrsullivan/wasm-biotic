//! Executes the compiled exchange-service component against deterministic
//! byte-store, transaction, clock, key, and transport primitives. The fixture
//! primitives deliberately assign no exchange, retry, or HTTP-status meaning.

use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::PathBuf};
use wasm_biotic_exchange_service::{
    BlobPointer, JSON_MEDIA_TYPE, TRANSFER_SCHEMA, TRANSPORT_AUTHORIZATION_HEADER,
    TRANSPORT_AUTHORIZATION_PREFIX, TRANSPORT_TIMEOUT_MS, TransferRequest, TransportDisposition,
    TransportOutbox,
};
use wasmtime::{
    Config, Engine, Store,
    component::{Component, HasSelf, Linker},
};

wasmtime::component::bindgen!({
    path: "../../wit/wasm-biotic",
    world: "exchange-service-component",
});

use wasm_biotic::factory::foundation::{BlobRef, Digest, EffectReceipt, Failure, HashAlgorithm};
use wasm_biotic::factory::http_transport::{Header, Method, Request, Response};
use wasm_biotic::factory::key_service::{Signature, SignatureAlgorithm};
use wasm_biotic::factory::transaction_store::{
    CommitReceipt, CommitRequest, Mutation, VersionedValue,
};

const NOW_MS: u64 = 1_754_000_000_000;
const EXCHANGE_NAMESPACE: &str = "exchange-v1";
const SIGNING_HANDLE: &str = "exchange-signing-key";
const CREDENTIAL_HANDLE: &str = "exchange-bearer-token";

struct HostState {
    blobs: BTreeMap<String, (String, Vec<u8>)>,
    records: BTreeMap<(String, String), (u64, BlobRef)>,
    signer: Ed25519KeyPair,
    signer_id: String,
    now_ms: u64,
    clock_calls: u64,
    sign_calls: u64,
    start_calls: u64,
    poll_calls: u64,
    cancel_calls: u64,
    last_request: Option<Request>,
    polls_remaining: usize,
    response_status: u16,
    start_failure: Option<Failure>,
    poll_failure: Option<Failure>,
}

impl HostState {
    fn new(response_status: u16, polls_remaining: usize) -> Self {
        let signer = Ed25519KeyPair::from_seed_unchecked(&[0x73; 32])
            .expect("construct deterministic Ed25519 test key");
        let signer_id = format!("sha256:{}", hex_sha256(signer.public_key().as_ref()));
        Self {
            blobs: BTreeMap::new(),
            records: BTreeMap::new(),
            signer,
            signer_id,
            now_ms: NOW_MS,
            clock_calls: 0,
            sign_calls: 0,
            start_calls: 0,
            poll_calls: 0,
            cancel_calls: 0,
            last_request: None,
            polls_remaining,
            response_status,
            start_failure: None,
            poll_failure: None,
        }
    }

    fn advance_clock(&mut self, milliseconds: u64) {
        self.now_ms += milliseconds;
    }

    fn insert_blob(&mut self, media_type: &str, bytes: &[u8]) -> BlobRef {
        let reference = blob_ref(media_type, bytes);
        self.blobs.insert(
            reference.content_digest.hex.clone(),
            (media_type.to_string(), bytes.to_vec()),
        );
        reference
    }

    fn outbox(&self, transfer_id: &str) -> TransportOutbox {
        let (_, reference) = self
            .records
            .get(&(
                EXCHANGE_NAMESPACE.to_string(),
                format!("outbox/{transfer_id}"),
            ))
            .expect("component persisted transport outbox");
        let (_, bytes) = self
            .blobs
            .get(&reference.content_digest.hex)
            .expect("outbox blob exists");
        serde_json::from_slice(bytes).expect("decode component-owned outbox")
    }
}

impl wasm_biotic::factory::foundation::Host for HostState {}

impl wasm_biotic::factory::blob_store::Host for HostState {
    fn put(&mut self, media_type: String, content: Vec<u8>) -> Result<BlobRef, Failure> {
        Ok(self.insert_blob(&media_type, &content))
    }

    fn get(&mut self, reference: BlobRef) -> Result<Vec<u8>, Failure> {
        let Some((media_type, bytes)) = self.blobs.get(&reference.content_digest.hex) else {
            return Err(failure(
                "missing-blob",
                "content-addressed blob was not found",
            ));
        };
        if *media_type != reference.media_type
            || bytes.len() as u64 != reference.size_bytes
            || hex_sha256(bytes) != reference.content_digest.hex
        {
            return Err(failure(
                "blob-reference-mismatch",
                "blob bytes do not match the complete supplied reference",
            ));
        }
        Ok(bytes.clone())
    }

    fn has(&mut self, content_digest: Digest) -> Result<bool, Failure> {
        Ok(self.blobs.contains_key(&content_digest.hex))
    }
}

impl wasm_biotic::factory::transaction_store::Host for HostState {
    fn read(&mut self, namespace: String, key: String) -> Result<Option<VersionedValue>, Failure> {
        if namespace != EXCHANGE_NAMESPACE {
            return Err(failure(
                "out-of-scope",
                "fixture exposes only the exchange namespace",
            ));
        }
        Ok(self
            .records
            .get(&(namespace, key))
            .map(|(version, value)| VersionedValue {
                version: *version,
                value: value.clone(),
            }))
    }

    fn commit(&mut self, request: CommitRequest) -> Result<CommitReceipt, Failure> {
        for assertion in &request.assertions {
            if assertion.namespace != EXCHANGE_NAMESPACE {
                return Err(failure(
                    "out-of-scope",
                    "fixture exposes only the exchange namespace",
                ));
            }
            let actual = self
                .records
                .get(&(assertion.namespace.clone(), assertion.key.clone()))
                .map(|(version, _)| *version);
            if actual != assertion.expected_version {
                return Err(failure("cas-conflict", "transaction assertion failed"));
            }
        }

        let mut commit_version = 0;
        let mut committed_value_digest = digest_bytes(b"empty-exchange-commit");
        for mutation in request.mutations {
            match mutation {
                Mutation::Put((namespace, key, value)) => {
                    if namespace != EXCHANGE_NAMESPACE {
                        return Err(failure(
                            "out-of-scope",
                            "fixture exposes only the exchange namespace",
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
                    if namespace != EXCHANGE_NAMESPACE {
                        return Err(failure(
                            "out-of-scope",
                            "fixture exposes only the exchange namespace",
                        ));
                    }
                    self.records.remove(&(namespace, key));
                }
            }
        }
        Ok(CommitReceipt {
            transaction_id: request.transaction_id,
            commit_version,
            committed_value_digest,
        })
    }
}

impl wasm_biotic::factory::clock::Host for HostState {
    fn now_ms(&mut self) -> u64 {
        self.clock_calls += 1;
        self.now_ms
    }

    fn schedule_wake(
        &mut self,
        _request: wasm_biotic::factory::clock::WakeRequest,
    ) -> Result<u64, Failure> {
        Err(failure(
            "unsupported-test-operation",
            "exchange component must not schedule wakes",
        ))
    }

    fn poll_wake(
        &mut self,
        _wake_id: String,
    ) -> Result<Option<wasm_biotic::factory::clock::FiredWake>, Failure> {
        Err(failure(
            "unsupported-test-operation",
            "exchange component must not poll wakes",
        ))
    }

    fn cancel_wake(&mut self, _wake_id: String) -> Result<bool, Failure> {
        Err(failure(
            "unsupported-test-operation",
            "exchange component must not cancel wakes",
        ))
    }
}

impl wasm_biotic::factory::key_service::Host for HostState {
    fn sign_digest(&mut self, key_handle: String, payload: Digest) -> Result<Signature, Failure> {
        self.sign_calls += 1;
        if key_handle != SIGNING_HANDLE || !matches!(payload.algorithm, HashAlgorithm::Sha256) {
            return Err(failure(
                "unknown-key",
                "signing handle or algorithm is not admitted",
            ));
        }
        let payload = decode_sha256_hex(&payload.hex)
            .map_err(|()| failure("invalid-digest", "signing digest is not SHA-256"))?;
        Ok(Signature {
            key_id: self.signer_id.clone(),
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: self.signer.sign(&payload).as_ref().to_vec(),
        })
    }

    fn verify_digest(
        &mut self,
        key_id: String,
        payload: Digest,
        signature: Signature,
    ) -> Result<bool, Failure> {
        if key_id != self.signer_id
            || signature.key_id != key_id
            || !matches!(payload.algorithm, HashAlgorithm::Sha256)
            || !matches!(signature.algorithm, SignatureAlgorithm::Ed25519)
        {
            return Ok(false);
        }
        let Ok(payload) = decode_sha256_hex(&payload.hex) else {
            return Ok(false);
        };
        Ok(
            UnparsedPublicKey::new(&ED25519, self.signer.public_key().as_ref())
                .verify(&payload, &signature.bytes)
                .is_ok(),
        )
    }

    fn random_bytes(&mut self, _length: u32) -> Result<Vec<u8>, Failure> {
        Err(failure(
            "unsupported-test-operation",
            "exchange component must not request entropy",
        ))
    }
}

impl wasm_biotic::factory::http_transport::Host for HostState {
    fn start(&mut self, request: Request) -> Result<String, Failure> {
        self.start_calls += 1;
        self.last_request = Some(request);
        if let Some(error) = self.start_failure.take() {
            return Err(error);
        }
        Ok("opaque-operation-1".to_string())
    }

    fn poll(&mut self, operation_id: String) -> Result<Option<Response>, Failure> {
        self.poll_calls += 1;
        if operation_id != "opaque-operation-1" {
            return Err(failure("unknown-operation", "operation id was not issued"));
        }
        if let Some(error) = &self.poll_failure {
            return Err(error.clone());
        }
        if self.polls_remaining != 0 {
            self.polls_remaining -= 1;
            return Ok(None);
        }
        Ok(Some(Response {
            status: self.response_status,
            headers: vec![Header {
                name: "x-fixture".to_string(),
                value: b"opaque".to_vec(),
            }],
            body: None,
            receipt: EffectReceipt {
                receipt_id: "transport-receipt-1".to_string(),
                request_digest: digest_bytes(b"opaque-transport-request"),
                executor_digest: digest_bytes(b"bounded-http-substrate"),
                started_at_ms: NOW_MS,
                finished_at_ms: NOW_MS + 1,
                outcome_digest: digest_bytes(b"opaque-transport-response"),
                audit_sequence: 7,
            },
        }))
    }

    fn cancel(&mut self, operation_id: String) -> Result<bool, Failure> {
        self.cancel_calls += 1;
        Ok(operation_id == "opaque-operation-1")
    }
}

#[test]
fn compiled_component_owns_http_request_status_and_exact_replay_policy() {
    let (mut store, bindings) = instantiate(HostState::new(204, 0));
    let request_ref = seed_transfer(&mut store, "transfer-delivered", None);

    let envelope = create_envelope(&bindings, &mut store, &request_ref).expect("delivery succeeds");
    assert_eq!(store.data().start_calls, 1);
    assert_eq!(store.data().poll_calls, 1);
    assert_eq!(store.data().cancel_calls, 0);

    let http = store
        .data()
        .last_request
        .as_ref()
        .expect("transport request");
    assert!(matches!(http.method, Method::Post));
    assert_eq!(http.url, "http://127.0.0.1:9443/v1/envelopes");
    assert_eq!(http.request_id, "exchange-send/transfer-delivered");
    assert_eq!(http.timeout_ms, TRANSPORT_TIMEOUT_MS);
    assert_eq!(http.timeout_ms, 10_000);
    assert_eq!(http.credential_handle.as_deref(), Some(CREDENTIAL_HANDLE));
    assert_eq!(
        http.body
            .as_ref()
            .expect("envelope body")
            .content_digest
            .hex,
        envelope.content_digest.hex
    );
    assert_eq!(http.headers.len(), 2);
    assert_eq!(http.headers[0].name, "content-type");
    assert_eq!(http.headers[0].value, JSON_MEDIA_TYPE.as_bytes());
    assert_eq!(http.headers[1].name, TRANSPORT_AUTHORIZATION_HEADER);
    assert_eq!(http.headers[1].value, TRANSPORT_AUTHORIZATION_PREFIX);

    let outbox = store.data().outbox("transfer-delivered");
    assert_eq!(outbox.disposition, TransportDisposition::Delivered);
    assert_eq!(outbox.response_status, Some(204));
    assert_eq!(
        outbox.http_operation_id.as_deref(),
        Some("opaque-operation-1")
    );
    assert!(outbox.response_receipt_digest.is_some());

    let replay = create_envelope(&bindings, &mut store, &request_ref).expect("exact replay");
    assert_eq!(replay.content_digest.hex, envelope.content_digest.hex);
    assert_eq!(
        store.data().start_calls,
        1,
        "exact replay never starts again"
    );
    assert_eq!(
        store.data().poll_calls,
        1,
        "completed replay never polls again"
    );

    let changed_ref = seed_transfer(&mut store, "transfer-delivered", Some("factory-different"));
    let changed = create_envelope(&bindings, &mut store, &changed_ref).expect_err("changed replay");
    assert_eq!(changed.code, "transfer-request-conflict");
    assert_eq!(store.data().start_calls, 1);

    store.data_mut().records.remove(&(
        EXCHANGE_NAMESPACE.to_string(),
        "request/transfer-delivered".to_string(),
    ));
    let unverifiable =
        create_envelope(&bindings, &mut store, &request_ref).expect_err("legacy replay marker");
    assert_eq!(unverifiable.code, "unverifiable-transfer-replay");
    assert_eq!(store.data().start_calls, 1);
}

#[test]
fn compiled_component_assigns_rejection_meaning_to_opaque_http_status() {
    let (mut store, bindings) = instantiate(HostState::new(503, 0));
    let request_ref = seed_transfer(&mut store, "transfer-rejected", None);

    let rejected =
        create_envelope(&bindings, &mut store, &request_ref).expect_err("component rejects 503");
    assert_eq!(rejected.code, "exchange-send-rejected");
    assert_eq!(store.data().start_calls, 1);
    assert_eq!(store.data().poll_calls, 1);
    let outbox = store.data().outbox("transfer-rejected");
    assert_eq!(outbox.response_status, Some(503));
    assert_eq!(outbox.disposition, TransportDisposition::RejectedResponse);

    let replay =
        create_envelope(&bindings, &mut store, &request_ref).expect_err("durable rejection");
    assert_eq!(replay.code, "exchange-send-rejected");
    assert_eq!(store.data().start_calls, 1, "rejected replay never resends");
    assert_eq!(
        store.data().poll_calls,
        1,
        "rejected replay never polls again"
    );
}

#[test]
fn compiled_component_resumes_pre_start_outbox_without_resigning() {
    let mut host = HostState::new(204, 0);
    host.start_failure = Some(failure(
        "limit-exceeded",
        "fixture rejected the request before dispatch",
    ));
    let (mut store, bindings) = instantiate(host);
    let request_ref = seed_transfer(&mut store, "transfer-prepared", None);

    let rejected =
        create_envelope(&bindings, &mut store, &request_ref).expect_err("pre-start rejection");
    assert_eq!(rejected.code, "limit-exceeded");
    let prepared = store.data().outbox("transfer-prepared");
    assert_eq!(prepared.disposition, TransportDisposition::Prepared);
    assert!(prepared.http_operation_id.is_none());
    assert_eq!(store.data().clock_calls, 1);
    assert_eq!(store.data().sign_calls, 1);
    assert_eq!(store.data().start_calls, 1);
    assert_eq!(store.data().poll_calls, 0);

    store.data_mut().advance_clock(1_000);
    let changed_ref = seed_transfer(&mut store, "transfer-prepared", Some("factory-different"));
    let conflict = create_envelope(&bindings, &mut store, &changed_ref)
        .expect_err("changed prepared intent must conflict");
    assert_eq!(conflict.code, "transfer-request-conflict");
    assert_eq!(store.data().clock_calls, 2);
    assert_eq!(store.data().sign_calls, 1);
    assert_eq!(store.data().start_calls, 1);

    let resumed =
        create_envelope(&bindings, &mut store, &request_ref).expect("resume prepared intent");
    assert_eq!(resumed.content_digest.hex, prepared.envelope.digest);
    assert_eq!(
        store.data().clock_calls,
        3,
        "each invocation revalidates expiry against the component clock"
    );
    assert_eq!(store.data().sign_calls, 1, "resume does not sign again");
    assert_eq!(
        store.data().start_calls,
        2,
        "pre-start failure did not dispatch"
    );
    assert_eq!(store.data().poll_calls, 1);
    assert_eq!(
        store.data().outbox("transfer-prepared").disposition,
        TransportDisposition::Delivered
    );
}

#[test]
fn compiled_component_resumes_one_durable_operation_after_poll_budget() {
    let (mut store, bindings) = instantiate(HostState::new(202, 256));
    let request_ref = seed_transfer(&mut store, "transfer-pending", None);

    let pending =
        create_envelope(&bindings, &mut store, &request_ref).expect_err("bounded poll budget");
    assert_eq!(pending.code, "exchange-send-pending");
    assert!(
        pending.retryable,
        "pending resume is component-owned retry policy"
    );
    assert_eq!(store.data().start_calls, 1);
    assert_eq!(store.data().poll_calls, 256);
    assert_eq!(
        store.data().outbox("transfer-pending").disposition,
        TransportDisposition::Pending
    );
    let persisted_envelope = store.data().outbox("transfer-pending").envelope;
    assert_eq!(store.data().clock_calls, 1);
    assert_eq!(store.data().sign_calls, 1);

    store.data_mut().advance_clock(1_000);
    let changed_ref = seed_transfer(&mut store, "transfer-pending", Some("factory-different"));
    let conflict = create_envelope(&bindings, &mut store, &changed_ref)
        .expect_err("changed pending intent must conflict");
    assert_eq!(conflict.code, "transfer-request-conflict");
    assert_eq!(store.data().clock_calls, 2);
    assert_eq!(store.data().sign_calls, 1);
    assert_eq!(store.data().start_calls, 1);
    assert_eq!(store.data().poll_calls, 256);

    let resumed =
        create_envelope(&bindings, &mut store, &request_ref).expect("resume existing operation");
    assert_eq!(resumed.content_digest.hex, persisted_envelope.digest);
    assert_eq!(store.data().start_calls, 1, "resume must not resend");
    assert_eq!(store.data().poll_calls, 257);
    assert_eq!(
        store.data().clock_calls,
        3,
        "resume revalidates expiry against the component clock"
    );
    assert_eq!(store.data().sign_calls, 1, "resume does not sign again");
    assert_eq!(
        store.data().outbox("transfer-pending").disposition,
        TransportDisposition::Delivered
    );
    assert_eq!(store.data().cancel_calls, 0);
}

#[test]
fn compiled_component_rejects_expired_prepared_replay_without_resigning_or_resending() {
    let mut host = HostState::new(204, 0);
    host.start_failure = Some(failure(
        "limit-exceeded",
        "fixture rejected the request before dispatch",
    ));
    let (mut store, bindings) = instantiate(host);
    let request_ref = seed_transfer(&mut store, "transfer-expired-replay", None);

    let rejected =
        create_envelope(&bindings, &mut store, &request_ref).expect_err("pre-start rejection");
    assert_eq!(rejected.code, "limit-exceeded");
    assert_eq!(store.data().sign_calls, 1);
    assert_eq!(store.data().start_calls, 1);
    assert_eq!(
        store.data().outbox("transfer-expired-replay").disposition,
        TransportDisposition::Prepared
    );

    store.data_mut().advance_clock(60_000);
    let expired = create_envelope(&bindings, &mut store, &request_ref)
        .expect_err("expired prepared replay must remain subject to transfer policy");
    assert_eq!(expired.code, "transfer-expired");
    assert_eq!(store.data().clock_calls, 2);
    assert_eq!(
        store.data().sign_calls,
        1,
        "expiry rejection never re-signs"
    );
    assert_eq!(
        store.data().start_calls,
        1,
        "expiry rejection never resends"
    );
    assert_eq!(store.data().poll_calls, 0);

    let (mut pending_store, pending_bindings) = instantiate(HostState::new(204, 256));
    let pending_ref = seed_transfer(&mut pending_store, "transfer-expired-pending", None);
    let pending = create_envelope(&pending_bindings, &mut pending_store, &pending_ref)
        .expect_err("bounded poll budget");
    assert_eq!(pending.code, "exchange-send-pending");
    pending_store.data_mut().advance_clock(60_000);
    let expired_pending = create_envelope(&pending_bindings, &mut pending_store, &pending_ref)
        .expect_err("expired pending replay must fail before polling");
    assert_eq!(expired_pending.code, "transfer-expired");
    assert_eq!(pending_store.data().clock_calls, 2);
    assert_eq!(pending_store.data().sign_calls, 1);
    assert_eq!(pending_store.data().start_calls, 1);
    assert_eq!(pending_store.data().poll_calls, 256);

    let (mut delivered_store, delivered_bindings) = instantiate(HostState::new(204, 0));
    let delivered_ref = seed_transfer(&mut delivered_store, "transfer-expired-delivered", None);
    create_envelope(&delivered_bindings, &mut delivered_store, &delivered_ref)
        .expect("initial delivery");
    delivered_store.data_mut().advance_clock(60_000);
    let expired_delivered =
        create_envelope(&delivered_bindings, &mut delivered_store, &delivered_ref)
            .expect_err("expired terminal replay must fail before durable lookup");
    assert_eq!(expired_delivered.code, "transfer-expired");
    assert_eq!(delivered_store.data().clock_calls, 2);
    assert_eq!(delivered_store.data().sign_calls, 1);
    assert_eq!(delivered_store.data().start_calls, 1);
    assert_eq!(delivered_store.data().poll_calls, 1);
}

#[test]
fn compiled_component_latches_unknown_outcome_and_never_resends() {
    let mut host = HostState::new(204, 0);
    host.poll_failure = Some(failure(
        "transport-outcome-unknown",
        "connection failed after request dispatch",
    ));
    let (mut store, bindings) = instantiate(host);
    let request_ref = seed_transfer(&mut store, "transfer-unknown", None);

    let unknown =
        create_envelope(&bindings, &mut store, &request_ref).expect_err("unknown outcome");
    assert_eq!(unknown.code, "transport-outcome-unknown");
    assert_eq!(store.data().start_calls, 1);
    assert_eq!(store.data().poll_calls, 1);
    assert_eq!(
        store.data().outbox("transfer-unknown").disposition,
        TransportDisposition::OutcomeUnknown
    );

    let replay = create_envelope(&bindings, &mut store, &request_ref).expect_err("latched unknown");
    assert_eq!(replay.code, "transport-outcome-unknown");
    assert_eq!(store.data().start_calls, 1, "unknown outcome never resends");
    assert_eq!(
        store.data().poll_calls,
        1,
        "latched unknown never polls again"
    );
    assert_eq!(store.data().cancel_calls, 0);
}

fn instantiate(host: HostState) -> (Store<HostState>, ExchangeServiceComponent) {
    let component_bytes = std::fs::read(component_path()).expect("read compiled exchange fixture");
    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config).expect("create Wasmtime engine");
    let component = Component::new(&engine, component_bytes).expect("compile exchange component");
    let mut linker = Linker::new(&engine);
    ExchangeServiceComponent::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
        .expect("link exchange world");
    let mut store = Store::new(&engine, host);
    let bindings = ExchangeServiceComponent::instantiate(&mut store, &component, &linker)
        .expect("instantiate exchange component");
    (store, bindings)
}

fn create_envelope(
    bindings: &ExchangeServiceComponent,
    store: &mut Store<HostState>,
    request: &BlobRef,
) -> Result<BlobRef, Failure> {
    bindings
        .wasm_biotic_factory_exchange_service()
        .call_create_envelope(store, request)
        .expect("invoke compiled exchange component")
}

fn seed_transfer(
    store: &mut Store<HostState>,
    transfer_id: &str,
    receiver_override: Option<&str>,
) -> BlobRef {
    let artifact_bytes = format!("artifact:{transfer_id}").into_bytes();
    let artifact = store
        .data_mut()
        .insert_blob("application/wasm", &artifact_bytes);
    let request = TransferRequest {
        schema: TRANSFER_SCHEMA.to_string(),
        transfer_id: transfer_id.to_string(),
        sender: "factory-a".to_string(),
        receiver: receiver_override.unwrap_or("factory-b").to_string(),
        artifact: BlobPointer {
            digest: artifact.content_digest.hex,
            size_bytes: artifact.size_bytes,
            media_type: artifact.media_type,
        },
        expires_at_ms: NOW_MS + 60_000,
        signing_key_handle: SIGNING_HANDLE.to_string(),
        destination_url: Some("http://127.0.0.1:9443/v1/envelopes".to_string()),
        transport_credential_handle: Some(CREDENTIAL_HANDLE.to_string()),
        idempotency_key: hex_sha256(format!("idempotency:{transfer_id}").as_bytes()),
    };
    let bytes = serde_json::to_vec(&request).expect("serialize transfer request");
    store.data_mut().insert_blob(JSON_MEDIA_TYPE, &bytes)
}

fn component_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/artifacts/exchange-service-component.wasm")
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

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("write digest");
    }
    output
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
