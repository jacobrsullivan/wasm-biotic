use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde_json::Value;
use wasm_biotic_kernel::bindings::root::wasm_biotic::factory::{
    activation, clock, component_runner, foundation, http_transport, key_service, transaction_store,
};
use wasm_biotic_kernel::{KernelError, LocalConfig, LocalMechanisms, Sha256Digest, TimeSource};

const ECHO_TASK: &[u8] = include_bytes!("../fixtures/artifacts/task.wasm");
const ADVERSARIAL_TASK: &[u8] = include_bytes!("../fixtures/artifacts/adversarial-task.wasm");
const CAPABILITY_ROUTER: &[u8] = include_bytes!(
    "../../artifacts/fixtures/component-complete-history/capability-router-component.wasm"
);
const FIXED_TIME_MS: u64 = 1_787_000_123_456;
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wasm-biotic-adversarial-{name}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ManualTime(AtomicU64);

impl ManualTime {
    fn fixed() -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(FIXED_TIME_MS)))
    }
}

impl TimeSource for ManualTime {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn digest(bytes: &[u8]) -> foundation::Digest {
    digest_value(Sha256Digest::from_bytes(bytes))
}

fn digest_value(value: Sha256Digest) -> foundation::Digest {
    foundation::Digest {
        algorithm: foundation::HashAlgorithm::Sha256,
        hex: value.to_string().trim_start_matches("sha256:").to_string(),
    }
}

fn config() -> LocalConfig {
    LocalConfig::default()
        .allow_namespace("alpha")
        .allow_namespace("wasm-biotic.schedule.v1")
        .with_max_blob_bytes(1024 * 1024)
        .with_max_total_blob_bytes(16 * 1024 * 1024)
}

fn limits(fuel: u64, memory_bytes: u64, output_bytes: u64) -> foundation::ResourceLimits {
    foundation::ResourceLimits {
        fuel,
        memory_bytes,
        output_bytes,
        wall_time_ms: 5_000,
    }
}

fn grant(capability: &str, scope: &str) -> foundation::CapabilityGrant {
    foundation::CapabilityGrant {
        capability: capability.to_string(),
        scope: scope.to_string(),
        constraints: None,
    }
}

fn blob_grant() -> foundation::CapabilityGrant {
    grant("blob-store", "read-write")
}

fn run_request(
    mechanisms: &LocalMechanisms,
    component: &[u8],
    run_id: &str,
    payload: &[u8],
    grants: Vec<foundation::CapabilityGrant>,
    requested_limits: foundation::ResourceLimits,
) -> component_runner::RunRequest {
    let input = mechanisms
        .put_blob("application/octet-stream".to_string(), payload.to_vec())
        .unwrap();
    component_runner::RunRequest {
        run_id: run_id.to_string(),
        component_digest: digest(component),
        input,
        grants,
        limits: requested_limits,
        idempotency_key: digest(format!("adversarial-idempotency|{run_id}").as_bytes()),
    }
}

fn execute(
    mechanisms: &mut LocalMechanisms,
    request: component_runner::RunRequest,
) -> component_runner::RunCompletion {
    let operation = component_runner::Host::start(mechanisms, request).unwrap();
    component_runner::Host::poll(mechanisms, operation)
        .unwrap()
        .expect("the local runner completes synchronously")
}

fn outcome_code(outcome: &foundation::TerminalOutcome) -> (&'static str, Option<&str>) {
    match outcome {
        foundation::TerminalOutcome::Succeeded(_) => ("succeeded", None),
        foundation::TerminalOutcome::Rejected(failure) => ("rejected", Some(failure.code.as_str())),
        foundation::TerminalOutcome::Failed(failure) => ("failed", Some(failure.code.as_str())),
        foundation::TerminalOutcome::Cancelled => ("cancelled", None),
        foundation::TerminalOutcome::Exhausted(failure) => {
            ("exhausted", Some(failure.code.as_str()))
        }
    }
}

fn assert_truthful_completion(
    request: &component_runner::RunRequest,
    completion: &component_runner::RunCompletion,
) {
    assert_eq!(completion.run_id, request.run_id);
    assert_digest_eq(
        &completion.receipt.request_digest,
        &digest(&serde_json::to_vec(request).unwrap()),
    );
    assert_digest_eq(
        &completion.receipt.executor_digest,
        &request.component_digest,
    );
    assert_eq!(completion.receipt.started_at_ms, FIXED_TIME_MS);
    assert_eq!(completion.receipt.finished_at_ms, FIXED_TIME_MS);
    assert_digest_eq(
        &completion.receipt.outcome_digest,
        &digest(&serde_json::to_vec(&completion.outcome).unwrap()),
    );
    assert_eq!(completion.receipt.audit_sequence, 0);
}

fn assert_digest_eq(left: &foundation::Digest, right: &foundation::Digest) {
    assert!(matches!(left.algorithm, foundation::HashAlgorithm::Sha256));
    assert!(matches!(right.algorithm, foundation::HashAlgorithm::Sha256));
    assert_eq!(left.hex, right.hex);
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn replace_once(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), replacement.len());
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture contains the selected import name");
    let mut changed = bytes.to_vec();
    changed[offset..offset + needle.len()].copy_from_slice(replacement);
    changed
}

#[test]
fn arbitrary_domain_payloads_take_the_same_opaque_component_path() {
    let directory = TestDirectory::new("opaque-substitution");
    let time = ManualTime::fixed();
    let mut mechanisms = LocalMechanisms::open_with_time(directory.path(), config(), time).unwrap();
    mechanisms
        .admit_component(Sha256Digest::from_bytes(ECHO_TASK), ECHO_TASK)
        .unwrap();

    let payloads: [&[u8]; 7] = [
        b"",
        b"planner|promotion|closure|provider",
        br#"{"schema":"looks.like.factory.policy","decision":"allow"}"#,
        &[0x00, 0xff, 0x80, 0x01],
        b"../../escape\0SELECT * FROM secrets",
        &[0x5a; 257],
        b"not-json-at-all{",
    ];
    let mut executor = None::<String>;
    let mut provenance = None;
    for (index, payload) in payloads.into_iter().enumerate() {
        let request = run_request(
            &mechanisms,
            ECHO_TASK,
            &format!("opaque-{index}"),
            payload,
            vec![blob_grant()],
            limits(1_000_000, 8 * 1024 * 1024, 4096),
        );
        let completion = execute(&mut mechanisms, request.clone());
        assert_truthful_completion(&request, &completion);
        let output = match completion.outcome {
            foundation::TerminalOutcome::Succeeded(reference) => reference,
            other => panic!("opaque payload selected a different outcome: {other:?}"),
        };
        assert_eq!(mechanisms.get_blob(output).unwrap(), payload);
        assert_eq!(
            executor.get_or_insert(completion.receipt.executor_digest.hex.clone()),
            &completion.receipt.executor_digest.hex
        );
        let operation = format!("operation-{}", request.idempotency_key.hex);
        let observed = mechanisms
            .execution_provenance(&operation)
            .unwrap()
            .unwrap();
        assert_eq!(
            provenance.get_or_insert(observed.clone()),
            &observed,
            "payload bytes must not select a different executable mapping"
        );
    }

    let denied = run_request(
        &mechanisms,
        ECHO_TASK,
        "opaque-missing-grant",
        b"same opaque bytes",
        Vec::new(),
        limits(1_000_000, 8 * 1024 * 1024, 4096),
    );
    let denied_completion = execute(&mut mechanisms, denied.clone());
    assert_truthful_completion(&denied, &denied_completion);
    assert_eq!(
        outcome_code(&denied_completion.outcome),
        ("rejected", Some("not-granted"))
    );

    let good_input = mechanisms
        .put_blob(
            "application/octet-stream".to_string(),
            b"digest-bound".to_vec(),
        )
        .unwrap();
    let mut forged_input = good_input;
    forged_input.content_digest.hex = "00".repeat(32);
    let forged_request = component_runner::RunRequest {
        run_id: "opaque-forged-input".to_string(),
        component_digest: digest(ECHO_TASK),
        input: forged_input,
        grants: vec![blob_grant()],
        limits: limits(1_000_000, 8 * 1024 * 1024, 4096),
        idempotency_key: digest(b"opaque-forged-input-key"),
    };
    assert_eq!(
        component_runner::Host::start(&mut mechanisms, forged_request)
            .unwrap_err()
            .code,
        "not-found"
    );

    let quota_directory = TestDirectory::new("opaque-quota");
    let quota_config = LocalConfig::default()
        .with_max_blob_bytes(64)
        .with_max_total_blob_bytes(128);
    let quota = LocalMechanisms::open(quota_directory.path(), quota_config).unwrap();
    assert_eq!(
        quota
            .put_blob("application/octet-stream".to_string(), vec![0_u8; 65])
            .unwrap_err()
            .code,
        "quota-exceeded"
    );
}

#[test]
fn hostile_task_failures_are_bounded_receipted_and_never_become_success() {
    let directory = TestDirectory::new("hostile-tasks");
    let time = ManualTime::fixed();
    let mut mechanisms = LocalMechanisms::open_with_time(directory.path(), config(), time).unwrap();
    mechanisms
        .admit_component(Sha256Digest::from_bytes(ADVERSARIAL_TASK), ADVERSARIAL_TASK)
        .unwrap();

    let cases = [
        (
            "explicit-trap",
            b"T".as_slice(),
            limits(2_000_000, 8 * 1024 * 1024, 1024),
            ("failed", Some("component-failed")),
        ),
        (
            "infinite-loop",
            b"L".as_slice(),
            limits(100_000, 8 * 1024 * 1024, 1024),
            ("exhausted", Some("execution-exhausted")),
        ),
        (
            "over-memory",
            b"M".as_slice(),
            limits(5_000_000, 4 * 1024 * 1024, 1024),
            ("failed", Some("component-failed")),
        ),
        (
            "oversized-output",
            b"O".as_slice(),
            limits(5_000_000, 8 * 1024 * 1024, 128),
            ("exhausted", Some("limit-exceeded")),
        ),
        (
            "forged-output-digest",
            b"F".as_slice(),
            limits(2_000_000, 8 * 1024 * 1024, 1024),
            ("failed", Some("not-found")),
        ),
    ];
    for (run_id, payload, requested_limits, expected) in cases {
        let request = run_request(
            &mechanisms,
            ADVERSARIAL_TASK,
            run_id,
            payload,
            vec![blob_grant()],
            requested_limits,
        );
        let completion = execute(&mut mechanisms, request.clone());
        assert_truthful_completion(&request, &completion);
        assert_eq!(outcome_code(&completion.outcome), expected, "case {run_id}");
    }

    let malformed = run_request(
        &mechanisms,
        ADVERSARIAL_TASK,
        "malformed-domain-document",
        b"J",
        vec![blob_grant()],
        limits(2_000_000, 8 * 1024 * 1024, 1024),
    );
    let malformed_completion = execute(&mut mechanisms, malformed.clone());
    assert_truthful_completion(&malformed, &malformed_completion);
    let output = match malformed_completion.outcome {
        foundation::TerminalOutcome::Succeeded(reference) => reference,
        other => panic!("the substrate interpreted opaque document bytes: {other:?}"),
    };
    assert_eq!(
        mechanisms.get_blob(output).unwrap(),
        [0xff, 0x00, b'{', b'\n'],
        "domain-document validation must remain component policy"
    );

    let constraint = mechanisms
        .put_blob(
            "application/json".to_string(),
            br#"{"schema":"wasm-biotic.blob-grant.v1","max_put_bytes":64}"#.to_vec(),
        )
        .unwrap();
    let constrained = run_request(
        &mechanisms,
        ADVERSARIAL_TASK,
        "blob-run-grant-quota",
        b"B",
        vec![foundation::CapabilityGrant {
            capability: "blob-store".to_string(),
            scope: "read-write".to_string(),
            constraints: Some(constraint),
        }],
        limits(5_000_000, 8 * 1024 * 1024, 8192),
    );
    let constrained_completion = execute(&mut mechanisms, constrained.clone());
    assert_truthful_completion(&constrained, &constrained_completion);
    assert_eq!(
        outcome_code(&constrained_completion.outcome),
        ("rejected", Some("limit-exceeded"))
    );
}

#[test]
fn undeclared_imports_malformed_components_and_forged_admission_digests_fail_closed() {
    let directory = TestDirectory::new("invalid-components");
    let time = ManualTime::fixed();
    let mut mechanisms = LocalMechanisms::open_with_time(directory.path(), config(), time).unwrap();

    let malformed = b"not-a-component";
    assert!(matches!(
        mechanisms.admit_component(Sha256Digest::from_bytes(malformed), malformed),
        Err(KernelError::Compile { .. })
    ));
    assert!(matches!(
        mechanisms.admit_component(Sha256Digest::from_bytes(b"forged"), ECHO_TASK),
        Err(KernelError::ComponentDigestMismatch { .. })
    ));

    let undeclared = replace_once(
        ADVERSARIAL_TASK,
        b"wasm-biotic:factory/blob-store@0.1.0",
        b"wasm-biotic:factory/evil-store@0.1.0",
    );
    assert!(wasmparser::Parser::is_component(&undeclared));
    let undeclared_digest = Sha256Digest::from_bytes(&undeclared);
    mechanisms
        .admit_component(undeclared_digest, &undeclared)
        .unwrap();
    let request = run_request(
        &mechanisms,
        &undeclared,
        "undeclared-import",
        b"E",
        vec![blob_grant()],
        limits(2_000_000, 8 * 1024 * 1024, 1024),
    );
    let completion = execute(&mut mechanisms, request.clone());
    assert_truthful_completion(&request, &completion);
    assert_eq!(
        outcome_code(&completion.outcome),
        ("failed", Some("component-failed"))
    );
}

#[test]
fn primitive_scope_escapes_and_disabled_http_envelopes_fail_closed() {
    let directory = TestDirectory::new("scope-escapes");
    let time = ManualTime::fixed();
    let mut mechanisms = LocalMechanisms::open_with_time(directory.path(), config(), time).unwrap();
    mechanisms
        .admit_component(Sha256Digest::from_bytes(ADVERSARIAL_TASK), ADVERSARIAL_TASK)
        .unwrap();

    let transaction_escape = run_request(
        &mechanisms,
        ADVERSARIAL_TASK,
        "transaction-namespace-escape",
        b"X",
        vec![blob_grant(), grant("transaction-store", "alpha")],
        limits(5_000_000, 8 * 1024 * 1024, 1024),
    );
    let completion = execute(&mut mechanisms, transaction_escape.clone());
    assert_truthful_completion(&transaction_escape, &completion);
    assert_eq!(
        outcome_code(&completion.outcome),
        ("rejected", Some("not-granted"))
    );
    assert!(
        transaction_store::Host::read(
            &mut mechanisms,
            "alpha".to_string(),
            "opaque-key".to_string(),
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        transaction_store::Host::read(
            &mut mechanisms,
            "outside-grant".to_string(),
            "opaque-key".to_string(),
        )
        .unwrap_err()
        .code,
        "out-of-scope"
    );

    let wake_escape = run_request(
        &mechanisms,
        ADVERSARIAL_TASK,
        "wake-target-escape",
        b"W",
        vec![blob_grant(), grant("clock", "wake")],
        limits(5_000_000, 8 * 1024 * 1024, 1024),
    );
    let completion = execute(&mut mechanisms, wake_escape.clone());
    assert_truthful_completion(&wake_escape, &completion);
    assert_eq!(
        outcome_code(&completion.outcome),
        ("rejected", Some("not-admitted"))
    );
    assert!(
        clock::Host::poll_wake(&mut mechanisms, "adversarial-wake-target".to_string())
            .unwrap()
            .is_none()
    );

    let target_escape = run_request(
        &mechanisms,
        ADVERSARIAL_TASK,
        "component-target-escape",
        b"C",
        vec![blob_grant(), grant("component-runner", "run")],
        limits(5_000_000, 8 * 1024 * 1024, 1024),
    );
    let completion = execute(&mut mechanisms, target_escape.clone());
    assert_truthful_completion(&target_escape, &completion);
    assert_eq!(
        outcome_code(&completion.outcome),
        ("rejected", Some("not-admitted"))
    );

    let missing_runner_grant = run_request(
        &mechanisms,
        ADVERSARIAL_TASK,
        "component-runner-grant-escape",
        b"C",
        vec![blob_grant()],
        limits(5_000_000, 8 * 1024 * 1024, 1024),
    );
    let completion = execute(&mut mechanisms, missing_runner_grant.clone());
    assert_truthful_completion(&missing_runner_grant, &completion);
    assert_eq!(
        outcome_code(&completion.outcome),
        ("rejected", Some("not-granted"))
    );

    let missing_key_handle = run_request(
        &mechanisms,
        ADVERSARIAL_TASK,
        "key-handle-escape",
        b"K",
        vec![blob_grant(), grant("key-service", "use")],
        limits(5_000_000, 8 * 1024 * 1024, 1024),
    );
    let completion = execute(&mut mechanisms, missing_key_handle.clone());
    assert_truthful_completion(&missing_key_handle, &completion);
    assert_eq!(
        outcome_code(&completion.outcome),
        ("rejected", Some("not-found"))
    );

    let missing_http_grant = run_request(
        &mechanisms,
        ADVERSARIAL_TASK,
        "http-grant-escape",
        b"H",
        vec![blob_grant()],
        limits(5_000_000, 8 * 1024 * 1024, 1024),
    );
    let completion = execute(&mut mechanisms, missing_http_grant.clone());
    assert_truthful_completion(&missing_http_grant, &completion);
    assert_eq!(
        outcome_code(&completion.outcome),
        ("rejected", Some("not-granted"))
    );

    let disabled_http_grant = run_request(
        &mechanisms,
        ADVERSARIAL_TASK,
        "http-disabled-after-grant",
        b"H",
        vec![blob_grant(), grant("http-transport", "request")],
        limits(5_000_000, 8 * 1024 * 1024, 1024),
    );
    let completion = execute(&mut mechanisms, disabled_http_grant.clone());
    assert_truthful_completion(&disabled_http_grant, &completion);
    assert_eq!(
        outcome_code(&completion.outcome),
        ("rejected", Some("transport-disabled"))
    );

    let body = mechanisms
        .put_blob(
            "application/octet-stream".to_string(),
            b"HTTP body".to_vec(),
        )
        .unwrap();
    for (index, method) in [
        http_transport::Method::Get,
        http_transport::Method::Head,
        http_transport::Method::Post,
        http_transport::Method::Put,
        http_transport::Method::Patch,
        http_transport::Method::Delete,
    ]
    .into_iter()
    .enumerate()
    {
        let error = http_transport::Host::start(
            &mut mechanisms,
            http_transport::Request {
                request_id: format!("disabled-method-{index}"),
                method,
                url: "https://127.0.0.1:9/escape?destination=arbitrary".to_string(),
                headers: vec![http_transport::Header {
                    name: "x-opaque".to_string(),
                    value: vec![0x00, 0xff],
                }],
                body: Some(body.clone()),
                timeout_ms: 100,
                idempotency_key: digest(format!("disabled-method-{index}").as_bytes()),
                credential_handle: Some("credential-handle-only".to_string()),
            },
        )
        .unwrap_err();
        assert_eq!(error.code, "transport-disabled");
        assert!(!error.message.contains("credential-handle-only"));
    }

    for (request_id, timeout_ms) in [("timeout-zero", 0), ("timeout-over", 30_001)] {
        let error = http_transport::Host::start(
            &mut mechanisms,
            http_transport::Request {
                request_id: request_id.to_string(),
                method: http_transport::Method::Post,
                url: "https://example.invalid/".to_string(),
                headers: Vec::new(),
                body: Some(body.clone()),
                timeout_ms,
                idempotency_key: digest(request_id.as_bytes()),
                credential_handle: Some("credential-handle-only".to_string()),
            },
        )
        .unwrap_err();
        assert_eq!(error.code, "limit-exceeded");
    }
    let mut forged_body = body.clone();
    forged_body.content_digest.hex = "00".repeat(32);
    let disabled_forged_envelope = http_transport::Host::start(
        &mut mechanisms,
        http_transport::Request {
            request_id: "forged-disabled-envelope".to_string(),
            method: http_transport::Method::Post,
            url: "http://169.254.169.254/latest/meta-data/".to_string(),
            headers: vec![http_transport::Header {
                name: "authorization".to_string(),
                value: vec![0xff; 4096],
            }],
            body: Some(forged_body),
            timeout_ms: 100,
            idempotency_key: digest(b"forged-disabled-envelope"),
            credential_handle: Some("x".repeat(4096)),
        },
    )
    .unwrap_err();
    assert_eq!(disabled_forged_envelope.code, "transport-disabled");
    let destination_error = http_transport::Host::start(
        &mut mechanisms,
        http_transport::Request {
            request_id: "destination-overlong".to_string(),
            method: http_transport::Method::Get,
            url: "x".repeat(2049),
            headers: Vec::new(),
            body: Some(body),
            timeout_ms: 100,
            idempotency_key: digest(b"destination-overlong"),
            credential_handle: Some("credential-handle-only".to_string()),
        },
    )
    .unwrap_err();
    assert_eq!(destination_error.code, "limit-exceeded");
    assert!(
        http_transport::Host::poll(&mut mechanisms, "never-started".to_string())
            .unwrap()
            .is_none()
    );
}

#[test]
fn private_key_bytes_and_credentials_do_not_cross_the_component_boundary() {
    let substrate_wit = include_str!("../../wit/wasm-biotic/substrate.wit");
    assert!(substrate_wit.contains("credential-handle: option<string>"));
    assert!(!substrate_wit.contains("credential-bytes"));
    assert!(!substrate_wit.contains("export-private"));
    assert!(!substrate_wit.contains("export-key"));

    let directory = TestDirectory::new("secret-non-observation");
    let time = ManualTime::fixed();
    let mut mechanisms = LocalMechanisms::open_with_time(directory.path(), config(), time).unwrap();
    mechanisms
        .admit_component(Sha256Digest::from_bytes(ADVERSARIAL_TASK), ADVERSARIAL_TASK)
        .unwrap();
    let key_id = mechanisms.create_ed25519_key("adversarial-key").unwrap();

    let state_path = directory.path().join("mechanisms.json");
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
        0o600,
        "the native secret-bearing state file must be owner-only"
    );
    let state: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    let private_key = state["keys"]["adversarial-key"]["pkcs8"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as u8)
        .collect::<Vec<_>>();
    assert!(private_key.len() >= 64);

    let request = run_request(
        &mechanisms,
        ADVERSARIAL_TASK,
        "component-signature-only",
        b"K opaque payload",
        vec![blob_grant(), grant("key-service", "use")],
        limits(5_000_000, 8 * 1024 * 1024, 1024),
    );
    let completion = execute(&mut mechanisms, request.clone());
    assert_truthful_completion(&request, &completion);
    let component_visible_signature = match &completion.outcome {
        foundation::TerminalOutcome::Succeeded(reference) => {
            mechanisms.get_blob(reference.clone()).unwrap()
        }
        other => panic!("signature fixture did not succeed: {other:?}"),
    };
    assert_eq!(component_visible_signature.len(), 64);
    assert!(!find_subslice(&component_visible_signature, &private_key));

    let direct_signature = key_service::Host::sign_digest(
        &mut mechanisms,
        "adversarial-key".to_string(),
        request.input.content_digest.clone(),
    )
    .unwrap();
    assert_eq!(direct_signature.key_id, key_id);
    assert_eq!(direct_signature.bytes, component_visible_signature);
    assert!(
        key_service::Host::verify_digest(
            &mut mechanisms,
            key_id,
            request.input.content_digest.clone(),
            direct_signature.clone(),
        )
        .unwrap()
    );

    let visible_provenance = mechanisms
        .execution_provenance(&format!("operation-{}", request.idempotency_key.hex))
        .unwrap();
    let visible_active_manifest = activation::Host::active_manifest(&mut mechanisms).unwrap();
    let visible_json = serde_json::to_vec(&(
        &completion,
        &direct_signature,
        visible_provenance,
        visible_active_manifest,
    ))
    .unwrap();
    let private_key_json = serde_json::to_vec(&private_key).unwrap();
    assert!(!find_subslice(&visible_json, &private_key));
    assert!(!find_subslice(&visible_json, &private_key_json));

    let secret_sentinel = "raw-credential-secret-must-not-persist";
    let error = http_transport::Host::start(
        &mut mechanisms,
        http_transport::Request {
            request_id: "credential-non-observation".to_string(),
            method: http_transport::Method::Post,
            url: "https://example.invalid/".to_string(),
            headers: Vec::new(),
            body: None,
            timeout_ms: 100,
            idempotency_key: digest(b"credential-non-observation"),
            credential_handle: Some("opaque-credential-handle".to_string()),
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "transport-disabled");
    assert!(!error.message.contains("opaque-credential-handle"));
    assert!(!error.message.contains(secret_sentinel));
    let persisted_after_http = fs::read(&state_path).unwrap();
    assert!(!find_subslice(
        &persisted_after_http,
        b"opaque-credential-handle"
    ));
    assert!(!find_subslice(
        &persisted_after_http,
        secret_sentinel.as_bytes()
    ));
}

#[test]
fn historical_adversarial_report_is_closed_and_bound_to_its_certified_inventory() {
    let report_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../artifacts/fixtures/component-complete-history/2026-08-02-adversarial-isolation.v1.json",
    );
    let report: Value = serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
    assert_eq!(
        report["schema"].as_str(),
        Some("wasm-biotic.adversarial-isolation-report.v1")
    );
    assert_eq!(report["component_complete_claim"].as_bool(), Some(false));
    let certified_inventory_digest = report["native_tcb_inventory"]["sha256"].as_str().unwrap();
    let certified_inventory_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../artifacts/fixtures/component-complete-history")
        .join(format!(
            "{}.json",
            certified_inventory_digest.replace(':', "-")
        ));
    let certified_inventory = fs::read(certified_inventory_path).unwrap();
    assert_eq!(
        Sha256Digest::from_bytes(&certified_inventory).to_string(),
        certified_inventory_digest
    );
    assert_eq!(
        report["native_tcb_inventory"]["component_complete_claim"].as_bool(),
        Some(true)
    );
    let fixture_digest = Sha256Digest::from_bytes(ADVERSARIAL_TASK).to_string();
    assert_eq!(
        report["fixture"]["sha256"].as_str(),
        Some(fixture_digest.as_str())
    );
    let cases = report["cases"].as_array().unwrap();
    let ids = cases
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    for required in [
        "opaque-payload-substitution",
        "private-key-non-observation",
        "credential-non-observation",
        "explicit-trap",
        "infinite-loop",
        "over-memory",
        "oversized-output",
        "forged-output-digest",
        "undeclared-import",
        "unlisted-component-target",
        "transaction-namespace-escape",
        "blob-quota-escape",
        "wake-target-escape",
        "activation-expected-digest-escape",
        "http-envelope-disabled",
        "malformed-domain-document-opacity",
        "approval-valid-first-use",
        "approval-exact-replay",
        "approval-altered-request-reuse",
        "approval-forged-signer",
        "approval-forged-signature",
    ] {
        assert!(
            ids.contains(required),
            "report omits adversarial case {required}"
        );
    }
    let echo_digest = Sha256Digest::from_bytes(ECHO_TASK).to_string();
    let hostile_digest = Sha256Digest::from_bytes(ADVERSARIAL_TASK).to_string();
    let router_digest = Sha256Digest::from_bytes(CAPABILITY_ROUTER).to_string();
    let malformed_digest = Sha256Digest::from_bytes(b"not-a-component").to_string();
    let undeclared_digest = Sha256Digest::from_bytes(&replace_once(
        ADVERSARIAL_TASK,
        b"wasm-biotic:factory/blob-store@0.1.0",
        b"wasm-biotic:factory/evil-store@0.1.0",
    ))
    .to_string();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let expected_digest = match id {
            "opaque-payload-substitution"
            | "opaque-payload-size-rejection"
            | "opaque-payload-digest-rejection"
            | "opaque-payload-grant-rejection"
            | "forged-admission-digest" => echo_digest.as_str(),
            "malformed-component" => malformed_digest.as_str(),
            "undeclared-import" => undeclared_digest.as_str(),
            "approval-valid-first-use"
            | "approval-exact-replay"
            | "approval-altered-request-reuse"
            | "approval-forged-signer"
            | "approval-forged-signature" => router_digest.as_str(),
            _ => hostile_digest.as_str(),
        };
        assert_eq!(
            case["component_digest"].as_str(),
            Some(expected_digest),
            "case {id} is not bound to the exact exercised bytes"
        );
        let expected_executor = match id {
            "opaque-payload-size-rejection"
            | "opaque-payload-digest-rejection"
            | "malformed-component"
            | "forged-admission-digest"
            | "approval-valid-first-use"
            | "approval-exact-replay"
            | "approval-altered-request-reuse"
            | "approval-forged-signer"
            | "approval-forged-signature" => None,
            "opaque-payload-substitution"
            | "opaque-payload-grant-rejection"
            | "activation-expected-digest-escape" => Some(echo_digest.as_str()),
            "undeclared-import" => Some(undeclared_digest.as_str()),
            _ => Some(hostile_digest.as_str()),
        };
        assert_eq!(
            case["receipt_executor_digest"].as_str(),
            expected_executor,
            "case {id} records the wrong receipt executor identity"
        );
    }
    for case in cases {
        assert_eq!(case["result"], "pass");
        assert!(
            case["component_digest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71),
            "case {} lacks an exact component digest",
            case["id"]
        );
        for field in [
            "phase",
            "expected_terminal",
            "receipt_truth",
            "stimulus",
            "observed",
            "evidence_test",
        ] {
            assert!(
                case[field]
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty()),
                "case {} lacks field {field}",
                case["id"]
            );
        }
        assert!(
            case["expected_failure_code"].is_null() || case["expected_failure_code"].is_string()
        );
    }
}
