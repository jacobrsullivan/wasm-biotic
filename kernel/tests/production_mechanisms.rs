use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use wasm_biotic_kernel::bindings::root::wasm_biotic::factory::{
    activation, audit_log, clock, component_runner, foundation, http_transport, key_service,
    transaction_store,
};
use wasm_biotic_kernel::{LocalConfig, LocalMechanisms, Sha256Digest, TimeSource};

const TASK_COMPONENT: &[u8] = include_bytes!("../fixtures/artifacts/task.wasm");
const MECHANISM_TASK_COMPONENT: &[u8] = include_bytes!("../fixtures/artifacts/mechanism-task.wasm");
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wasm-biotic-kernel-{name}-{}-{}",
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
    fn new(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }

    fn set(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

impl TimeSource for ManualTime {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn digest(bytes: &[u8]) -> foundation::Digest {
    foundation::Digest {
        algorithm: foundation::HashAlgorithm::Sha256,
        hex: Sha256Digest::from_bytes(bytes)
            .to_string()
            .trim_start_matches("sha256:")
            .to_string(),
    }
}

fn component_digest() -> Sha256Digest {
    Sha256Digest::from_bytes(TASK_COMPONENT)
}

fn config() -> LocalConfig {
    LocalConfig::default()
        .allow_namespace("alpha")
        .allow_namespace("wasm-biotic.schedule.v1")
        .with_max_blob_bytes(1024 * 1024)
        .with_max_total_blob_bytes(8 * 1024 * 1024)
}

const CANONICAL_OPERATOR_CONFIG: &str = concat!(
    "{\"mechanisms\":{",
    "\"allowed_namespaces\":[\"alpha\",\"wasm-biotic.schedule.v1\"],",
    "\"max_blob_bytes\":1048576,",
    "\"max_component_fuel\":50000000,",
    "\"max_component_memory_bytes\":67108864,",
    "\"max_component_output_bytes\":16777216,",
    "\"max_component_wall_time_ms\":30000,",
    "\"max_http_timeout_ms\":30000,",
    "\"max_random_bytes\":4096,",
    "\"max_total_blob_bytes\":8388608,",
    "\"max_wake_delay_ms\":2592000000},",
    "\"schema\":\"wasm-biotic.operator-mechanism-capacity.v1\"}"
);

fn mechanism_component_digest() -> Sha256Digest {
    Sha256Digest::from_bytes(MECHANISM_TASK_COMPONENT)
}

#[test]
fn blob_and_transaction_state_survive_restart_and_fail_closed() {
    let directory = TestDirectory::new("persistence");
    let mut first = LocalMechanisms::open(directory.path(), config()).unwrap();
    let reference = first
        .put_blob(
            "application/octet-stream".to_string(),
            b"durable bytes".to_vec(),
        )
        .unwrap();
    assert_eq!(first.get_blob(reference.clone()).unwrap(), b"durable bytes");

    let request = transaction_store::CommitRequest {
        transaction_id: "tx-1".to_string(),
        assertions: vec![transaction_store::Assertion {
            namespace: "alpha".to_string(),
            key: "item".to_string(),
            expected_version: None,
        }],
        mutations: vec![transaction_store::Mutation::Put((
            "alpha".to_string(),
            "item".to_string(),
            reference.clone(),
        ))],
        idempotency_key: digest(b"tx-1-idempotency"),
    };
    let receipt = transaction_store::Host::commit(&mut first, request.clone()).unwrap();
    assert_eq!(receipt.commit_version, 1);
    let replay = transaction_store::Host::commit(&mut first, request).unwrap();
    assert_eq!(replay.commit_version, 1);
    drop(first);

    let mut reopened = LocalMechanisms::open(directory.path(), config()).unwrap();
    assert_eq!(
        reopened.get_blob(reference.clone()).unwrap(),
        b"durable bytes"
    );
    let value =
        transaction_store::Host::read(&mut reopened, "alpha".to_string(), "item".to_string())
            .unwrap()
            .unwrap();
    assert_eq!(value.version, 1);
    assert_eq!(value.value.content_digest.hex, reference.content_digest.hex);

    let out_of_scope = transaction_store::Host::read(
        &mut reopened,
        "../../escape".to_string(),
        "item".to_string(),
    )
    .unwrap_err();
    assert_eq!(out_of_scope.code, "out-of-scope");

    let blob_path = directory
        .path()
        .join("blobs")
        .join(&reference.content_digest.hex);
    fs::write(blob_path, b"tampered").unwrap();
    let integrity = reopened.get_blob(reference).unwrap_err();
    assert_eq!(integrity.code, "persistence-error");
}

#[test]
fn operator_capacity_document_is_canonical_closed_and_immutable() {
    let directory = TestDirectory::new("operator-capacity");
    let config_path = directory.path().join("operator-config.json");
    fs::write(&config_path, format!("{CANONICAL_OPERATOR_CONFIG}\n")).unwrap();
    let operator_config = LocalConfig::from_canonical_json_file(&config_path).unwrap();
    assert_eq!(operator_config, config());

    let state = directory.path().join("state");
    LocalMechanisms::open(&state, operator_config.clone()).unwrap();
    assert!(LocalMechanisms::open_existing(&state).is_ok());
    assert!(
        LocalMechanisms::open(
            &state,
            operator_config.clone().with_max_component_fuel(49_000_000),
        )
        .is_err()
    );

    fs::write(&config_path, format!(" {CANONICAL_OPERATOR_CONFIG}\n")).unwrap();
    assert!(LocalConfig::from_canonical_json_file(&config_path).is_err());

    let unknown = CANONICAL_OPERATOR_CONFIG.replacen("\"schema\"", "\"policy\":true,\"schema\"", 1);
    fs::write(&config_path, format!("{unknown}\n")).unwrap();
    assert!(LocalConfig::from_canonical_json_file(&config_path).is_err());

    let duplicate_namespace = CANONICAL_OPERATOR_CONFIG.replacen(
        "[\"alpha\",\"wasm-biotic.schedule.v1\"]",
        "[\"alpha\",\"alpha\",\"wasm-biotic.schedule.v1\"]",
        1,
    );
    fs::write(&config_path, format!("{duplicate_namespace}\n")).unwrap();
    assert!(LocalConfig::from_canonical_json_file(&config_path).is_err());

    let empty = directory.path().join("empty");
    fs::create_dir(&empty).unwrap();
    assert!(LocalMechanisms::open_existing(&empty).is_err());
    assert!(!empty.join("mechanisms.json").exists());
}

#[test]
fn http_operator_capacity_v2_is_canonical_closed_and_immutable() {
    let http_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("operator-config.http.example.json");
    let http = LocalConfig::from_canonical_json_file(&http_path).unwrap();
    let directory = TestDirectory::new("http-operator-v2");
    let state = directory.path().join("state");
    let first = LocalMechanisms::open(&state, http).unwrap();
    drop(first);
    LocalMechanisms::open_existing(&state).unwrap();
    assert!(
        LocalMechanisms::open(&state, LocalConfig::default()).is_err(),
        "HTTP capacity cannot be removed or changed after root initialization"
    );

    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&http_path).unwrap()).unwrap();
    value["mechanisms"]["http_transport"]["provider"] =
        serde_json::Value::String("forbidden-domain-policy".to_string());
    let rejected = directory.path().join("operator-http-extra.json");
    fs::write(&rejected, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(LocalConfig::from_canonical_json_file(&rejected).is_err());
}

#[test]
fn wakes_audit_keys_and_unverified_activation_are_fail_closed() {
    let directory = TestDirectory::new("mechanisms");
    let time = Arc::new(ManualTime::new(1_000));
    let mut mechanisms =
        LocalMechanisms::open_with_time(directory.path(), config(), time.clone()).unwrap();
    mechanisms
        .admit_component(component_digest(), TASK_COMPONENT)
        .unwrap();

    let wake = clock::WakeRequest {
        wake_id: "wake-1".to_string(),
        not_before_ms: 1_100,
        target_component: digest(TASK_COMPONENT),
        payload_digest: digest(b"payload"),
        idempotency_key: digest(b"wake-idempotency"),
    };
    assert_eq!(
        clock::Host::schedule_wake(&mut mechanisms, wake).unwrap(),
        1_100
    );
    assert!(
        clock::Host::poll_wake(&mut mechanisms, "wake-1".to_string())
            .unwrap()
            .is_none()
    );
    time.set(1_101);
    let fired = clock::Host::poll_wake(&mut mechanisms, "wake-1".to_string())
        .unwrap()
        .unwrap();
    assert_eq!(fired.fired_at_ms, 1_101);

    let payload = mechanisms
        .put_blob("application/json".to_string(), b"{}".to_vec())
        .unwrap();
    let actor_digest = digest(TASK_COMPONENT);
    let first_entry = audit_log::AuditEntry {
        event_id: "event-1".to_string(),
        actor: foundation::Principal {
            id: "component-1".to_string(),
            component_digest: actor_digest,
        },
        event_type: "opaque.type".to_string(),
        payload: payload.clone(),
        previous_entry: None,
        occurred_at_ms: 1_101,
        idempotency_key: digest(b"audit-1"),
    };
    let audit_receipt = audit_log::Host::append(&mut mechanisms, first_entry).unwrap();
    assert_eq!(audit_receipt.sequence, 1);

    let key_id = mechanisms.create_ed25519_key("signing-key").unwrap();
    let signature = key_service::Host::sign_digest(
        &mut mechanisms,
        "signing-key".to_string(),
        digest(b"signed payload"),
    )
    .unwrap();
    assert_eq!(signature.key_id, key_id);
    assert!(
        key_service::Host::verify_digest(
            &mut mechanisms,
            key_id,
            digest(b"signed payload"),
            signature,
        )
        .unwrap()
    );
    assert_eq!(
        key_service::Host::random_bytes(&mut mechanisms, 32)
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        key_service::Host::random_bytes(&mut mechanisms, 100_000)
            .unwrap_err()
            .code,
        "limit-exceeded"
    );

    let graph_one = mechanisms
        .put_blob("application/json".to_string(), b"graph-one".to_vec())
        .unwrap();
    mechanisms.admit_graph(&graph_one).unwrap();
    let unverified = activation::Host::stage(
        &mut mechanisms,
        activation::ActivationRequest {
            activation_id: "activation-1".to_string(),
            graph_manifest: graph_one.clone(),
            expected_active_graph: None,
            expected_active_state: None,
            state_migration: None,
            migrated_state: None,
            idempotency_key: digest(b"activation-1"),
        },
    )
    .unwrap_err();
    assert_eq!(unverified.code, "not-admitted");
    assert!(
        activation::Host::active_manifest(&mut mechanisms)
            .unwrap()
            .is_none()
    );

    let disabled = http_transport::Host::start(
        &mut mechanisms,
        http_transport::Request {
            request_id: "request-1".to_string(),
            method: http_transport::Method::Get,
            url: "https://example.invalid/".to_string(),
            headers: Vec::new(),
            body: None,
            timeout_ms: 100,
            idempotency_key: digest(b"http-1"),
            credential_handle: None,
        },
    )
    .unwrap_err();
    assert_eq!(disabled.code, "transport-disabled");

    drop(mechanisms);
    let mut reopened = LocalMechanisms::open_with_time(directory.path(), config(), time).unwrap();
    assert_eq!(
        clock::Host::poll_wake(&mut reopened, "wake-1".to_string())
            .unwrap()
            .unwrap()
            .fired_at_ms,
        1_101
    );
    assert!(
        audit_log::Host::resolve(&mut reopened, 1)
            .unwrap()
            .is_some()
    );
    assert!(
        activation::Host::active_manifest(&mut reopened)
            .unwrap()
            .is_none()
    );
}

#[test]
fn wake_observed_now_that_has_just_passed_is_immediately_due() {
    let directory = TestDirectory::new("wake-observed-now");
    let time = Arc::new(ManualTime::new(1_000));
    let observed_now = time.now_ms();
    time.set(1_001);

    let mut mechanisms =
        LocalMechanisms::open_with_time(directory.path(), config(), time.clone()).unwrap();
    mechanisms
        .admit_component(component_digest(), TASK_COMPONENT)
        .unwrap();

    let request = clock::WakeRequest {
        wake_id: "wake-observed-now".to_string(),
        not_before_ms: observed_now,
        target_component: digest(TASK_COMPONENT),
        payload_digest: digest(b"observed-now-payload"),
        idempotency_key: digest(b"observed-now-idempotency"),
    };

    assert_eq!(
        clock::Host::schedule_wake(&mut mechanisms, request.clone()).unwrap(),
        observed_now
    );
    let fired = clock::Host::poll_wake(&mut mechanisms, request.wake_id.clone())
        .unwrap()
        .unwrap();
    assert_eq!(fired.fired_at_ms, 1_001);

    assert_eq!(
        clock::Host::schedule_wake(&mut mechanisms, request.clone()).unwrap(),
        observed_now
    );
    let replayed_fire = clock::Host::poll_wake(&mut mechanisms, request.wake_id.clone())
        .unwrap()
        .unwrap();
    assert_eq!(replayed_fire.fired_at_ms, fired.fired_at_ms);

    let mut conflicting = request.clone();
    conflicting.payload_digest = digest(b"different-payload");
    let conflict = clock::Host::schedule_wake(&mut mechanisms, conflicting).unwrap_err();
    assert_eq!(conflict.code, "idempotency-conflict");

    let beyond_future_horizon = clock::WakeRequest {
        wake_id: "wake-too-far".to_string(),
        not_before_ms: u64::MAX,
        target_component: digest(TASK_COMPONENT),
        payload_digest: digest(b"future-payload"),
        idempotency_key: digest(b"future-idempotency"),
    };
    let limit = clock::Host::schedule_wake(&mut mechanisms, beyond_future_horizon).unwrap_err();
    assert_eq!(limit.code, "limit-exceeded");
}

#[test]
fn digest_selected_component_runner_enforces_grants_limits_and_restarts() {
    let directory = TestDirectory::new("runner");
    let time = Arc::new(ManualTime::new(2_000));
    let mut mechanisms =
        LocalMechanisms::open_with_time(directory.path(), config(), time.clone()).unwrap();
    mechanisms
        .admit_component(component_digest(), TASK_COMPONENT)
        .unwrap();
    let input = mechanisms
        .put_blob(
            "application/octet-stream".to_string(),
            b"component input".to_vec(),
        )
        .unwrap();
    let constraint = mechanisms
        .put_blob(
            "application/json".to_string(),
            br#"{"schema":"wasm-biotic.blob-grant.v1","max_put_bytes":1024}"#.to_vec(),
        )
        .unwrap();
    let request = component_runner::RunRequest {
        run_id: "run-1".to_string(),
        component_digest: digest(TASK_COMPONENT),
        input,
        grants: vec![foundation::CapabilityGrant {
            capability: "blob-store".to_string(),
            scope: "read-write".to_string(),
            constraints: Some(constraint),
        }],
        limits: foundation::ResourceLimits {
            fuel: 1_000_000,
            memory_bytes: 8 * 1024 * 1024,
            output_bytes: 1024,
            wall_time_ms: 1_000,
        },
        idempotency_key: digest(b"run-1-idempotency"),
    };
    let operation = component_runner::Host::start(&mut mechanisms, request.clone()).unwrap();
    let completion = component_runner::Host::poll(&mut mechanisms, operation.clone())
        .unwrap()
        .unwrap();
    let output = match completion.outcome {
        foundation::TerminalOutcome::Succeeded(reference) => reference,
        other => panic!("unexpected component outcome: {other:?}"),
    };
    assert_eq!(mechanisms.get_blob(output).unwrap(), b"component input");
    assert_eq!(
        component_runner::Host::start(&mut mechanisms, request).unwrap(),
        operation
    );

    let denied_request = component_runner::RunRequest {
        run_id: "run-2".to_string(),
        component_digest: digest(TASK_COMPONENT),
        input: mechanisms
            .put_blob("application/octet-stream".to_string(), b"denied".to_vec())
            .unwrap(),
        grants: Vec::new(),
        limits: foundation::ResourceLimits {
            fuel: 1_000_000,
            memory_bytes: 8 * 1024 * 1024,
            output_bytes: 1024,
            wall_time_ms: 1_000,
        },
        idempotency_key: digest(b"run-2-idempotency"),
    };
    let denied_operation = component_runner::Host::start(&mut mechanisms, denied_request).unwrap();
    let denied = component_runner::Host::poll(&mut mechanisms, denied_operation)
        .unwrap()
        .unwrap();
    assert!(matches!(
        denied.outcome,
        foundation::TerminalOutcome::Rejected(ref error) if error.code == "not-granted"
    ));

    drop(mechanisms);
    let mut reopened = LocalMechanisms::open_with_time(directory.path(), config(), time).unwrap();
    assert!(
        component_runner::Host::poll(&mut reopened, operation)
            .unwrap()
            .is_some()
    );
}

#[test]
fn dynamic_task_linker_gates_blob_transaction_and_clock_per_run() {
    let directory = TestDirectory::new("dynamic-grants");
    let time = Arc::new(ManualTime::new(3_000));
    let mut mechanisms = LocalMechanisms::open_with_time(directory.path(), config(), time).unwrap();
    mechanisms
        .admit_component(mechanism_component_digest(), MECHANISM_TASK_COMPONENT)
        .unwrap();
    let input = mechanisms
        .put_blob(
            "application/octet-stream".to_string(),
            b"grant input".to_vec(),
        )
        .unwrap();
    let grants = vec![
        foundation::CapabilityGrant {
            capability: "blob-store".to_string(),
            scope: "read-write".to_string(),
            constraints: None,
        },
        foundation::CapabilityGrant {
            capability: "transaction-store".to_string(),
            scope: "wasm-biotic.schedule.v1".to_string(),
            constraints: None,
        },
        foundation::CapabilityGrant {
            capability: "clock".to_string(),
            scope: "wake".to_string(),
            constraints: None,
        },
    ];
    let request = component_runner::RunRequest {
        run_id: "all-grants".to_string(),
        component_digest: digest(MECHANISM_TASK_COMPONENT),
        input: input.clone(),
        grants,
        limits: foundation::ResourceLimits {
            fuel: 1_000_000,
            memory_bytes: 8 * 1024 * 1024,
            output_bytes: 1024,
            wall_time_ms: 1_000,
        },
        idempotency_key: digest(b"all-grants-key"),
    };
    let operation = component_runner::Host::start(&mut mechanisms, request.clone()).unwrap();
    let completion = component_runner::Host::poll(&mut mechanisms, operation)
        .unwrap()
        .unwrap();
    assert!(matches!(
        completion.outcome,
        foundation::TerminalOutcome::Succeeded(_)
    ));
    assert!(
        transaction_store::Host::read(
            &mut mechanisms,
            "wasm-biotic.schedule.v1".to_string(),
            "last-input".to_string(),
        )
        .unwrap()
        .is_some()
    );

    for (run_id, omitted, expected_code) in [
        ("without-blob", "blob-store", "not-granted"),
        ("without-transaction", "transaction-store", "not-granted"),
        ("without-clock", "clock", "clock-not-granted"),
    ] {
        let mut denied = request.clone();
        denied.run_id = run_id.to_string();
        denied
            .grants
            .retain(|grant| grant.capability.as_str() != omitted);
        denied.idempotency_key = digest(run_id.as_bytes());
        let operation = component_runner::Host::start(&mut mechanisms, denied).unwrap();
        let completion = component_runner::Host::poll(&mut mechanisms, operation)
            .unwrap()
            .unwrap();
        assert!(matches!(
            completion.outcome,
            foundation::TerminalOutcome::Rejected(ref error) if error.code == expected_code
        ));
    }
}
