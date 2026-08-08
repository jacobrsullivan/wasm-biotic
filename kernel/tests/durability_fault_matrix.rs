use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use wasm_biotic_kernel::bindings::root::wasm_biotic::factory::{
    audit_log, component_runner, foundation, transaction_store,
};
use wasm_biotic_kernel::{
    DurabilityFaultController, DurabilityFaultPoint, LocalConfig, LocalMechanisms, Sha256Digest,
    TimeSource,
};

const TASK_COMPONENT: &[u8] = include_bytes!("../fixtures/artifacts/task.wasm");
const MECHANISM_TASK_COMPONENT: &[u8] = include_bytes!("../fixtures/artifacts/mechanism-task.wasm");
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wasm-biotic-durability-{name}-{}-{}",
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
}

impl TimeSource for ManualTime {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn config() -> LocalConfig {
    LocalConfig::default()
        .allow_namespace("alpha")
        .allow_namespace("wasm-biotic.schedule.v1")
        .with_max_blob_bytes(1024 * 1024)
        .with_max_total_blob_bytes(8 * 1024 * 1024)
}

fn digest(bytes: &[u8]) -> foundation::Digest {
    foundation::Digest {
        algorithm: foundation::HashAlgorithm::Sha256,
        hex: digest_hex(Sha256Digest::from_bytes(bytes)),
    }
}

fn digest_hex(digest: Sha256Digest) -> String {
    digest.to_string().trim_start_matches("sha256:").to_string()
}

fn atomic_points() -> [DurabilityFaultPoint; 8] {
    [
        DurabilityFaultPoint::BeforeTempWrite,
        DurabilityFaultPoint::AfterTempWrite,
        DurabilityFaultPoint::BeforeTempSync,
        DurabilityFaultPoint::AfterTempSync,
        DurabilityFaultPoint::BeforeRename,
        DurabilityFaultPoint::AfterRename,
        DurabilityFaultPoint::BeforeDirectorySync,
        DurabilityFaultPoint::AfterDirectorySync,
    ]
}

fn renamed(point: DurabilityFaultPoint) -> bool {
    matches!(
        point,
        DurabilityFaultPoint::AfterRename
            | DurabilityFaultPoint::BeforeDirectorySync
            | DurabilityFaultPoint::AfterDirectorySync
    )
}

fn open_faulted(path: &Path, controller: DurabilityFaultController) -> LocalMechanisms {
    LocalMechanisms::open_with_fault_injection(
        path,
        config(),
        Arc::new(ManualTime::new(1_000)),
        controller,
    )
    .unwrap()
}

fn commit_request(value: foundation::BlobRef) -> transaction_store::CommitRequest {
    transaction_store::CommitRequest {
        transaction_id: "durability-transaction".to_string(),
        assertions: vec![transaction_store::Assertion {
            namespace: "alpha".to_string(),
            key: "item".to_string(),
            expected_version: None,
        }],
        mutations: vec![transaction_store::Mutation::Put((
            "alpha".to_string(),
            "item".to_string(),
            value,
        ))],
        idempotency_key: digest(b"durability-transaction-idempotency"),
    }
}

#[test]
fn atomic_writer_faults_leave_blob_and_component_content_uncommitted_until_replay() {
    for point in atomic_points() {
        let directory = TestDirectory::new(&format!("blob-{point:?}"));
        LocalMechanisms::open(directory.path(), config()).unwrap();
        let controller = DurabilityFaultController::default();
        let mechanisms = open_faulted(directory.path(), controller.clone());
        let content = format!("blob-at-{point:?}").into_bytes();
        let expected = Sha256Digest::from_bytes(&content);
        controller.arm(point, "blob-content");
        let error = mechanisms
            .put_blob("application/octet-stream".to_string(), content.clone())
            .unwrap_err();
        assert_eq!(error.code, "persistence-error", "{point:?}");
        assert_eq!(controller.fired().len(), 1, "{point:?}");
        drop(mechanisms);

        let content_path = directory.path().join("blobs").join(digest_hex(expected));
        assert_eq!(content_path.exists(), renamed(point), "{point:?}");
        let reopened = LocalMechanisms::open(directory.path(), config()).unwrap();
        assert!(!reopened.has_blob(digest(&content)).unwrap(), "{point:?}");
        let reference = reopened
            .put_blob("application/octet-stream".to_string(), content.clone())
            .unwrap();
        assert_eq!(reopened.get_blob(reference).unwrap(), content, "{point:?}");
    }

    for point in atomic_points() {
        let directory = TestDirectory::new(&format!("component-{point:?}"));
        LocalMechanisms::open(directory.path(), config()).unwrap();
        let controller = DurabilityFaultController::default();
        let mechanisms = open_faulted(directory.path(), controller.clone());
        let expected = Sha256Digest::from_bytes(TASK_COMPONENT);
        controller.arm(point, "component-content");
        assert!(
            mechanisms
                .admit_component(expected, TASK_COMPONENT)
                .is_err(),
            "{point:?}"
        );
        assert_eq!(controller.fired().len(), 1, "{point:?}");
        drop(mechanisms);

        let content_path = directory
            .path()
            .join("components")
            .join(format!("{}.wasm", digest_hex(expected)));
        assert_eq!(content_path.exists(), renamed(point), "{point:?}");
        let reopened = LocalMechanisms::open(directory.path(), config()).unwrap();
        reopened.admit_component(expected, TASK_COMPONENT).unwrap();
    }
}

#[test]
fn mechanism_state_atomic_and_commit_faults_recover_old_or_new_and_replay_once() {
    let state_points = [
        DurabilityFaultPoint::BeforeStateChange,
        DurabilityFaultPoint::AfterStateChange,
        DurabilityFaultPoint::BeforeStateCommit,
        DurabilityFaultPoint::AfterStateCommit,
    ];
    for (point, operation, new_state_expected) in atomic_points()
        .into_iter()
        .map(|point| (point, "mechanism-state", renamed(point)))
        .chain(state_points.into_iter().map(|point| {
            (
                point,
                "transaction-commit",
                point == DurabilityFaultPoint::AfterStateCommit,
            )
        }))
    {
        let directory = TestDirectory::new(&format!("state-{point:?}"));
        let first = LocalMechanisms::open(directory.path(), config()).unwrap();
        let value = first
            .put_blob("application/octet-stream".to_string(), b"value".to_vec())
            .unwrap();
        drop(first);

        let controller = DurabilityFaultController::default();
        let mut faulted = open_faulted(directory.path(), controller.clone());
        let request = commit_request(value.clone());
        controller.arm(point, operation);
        let error = transaction_store::Host::commit(&mut faulted, request.clone()).unwrap_err();
        assert_eq!(error.code, "persistence-error", "{point:?}");
        assert_eq!(controller.fired().len(), 1, "{point:?}");
        drop(faulted);

        let mut reopened = LocalMechanisms::open(directory.path(), config()).unwrap();
        let recovered =
            transaction_store::Host::read(&mut reopened, "alpha".to_string(), "item".to_string())
                .unwrap();
        assert_eq!(recovered.is_some(), new_state_expected, "{point:?}");

        let receipt = transaction_store::Host::commit(&mut reopened, request.clone()).unwrap();
        assert_eq!(receipt.commit_version, 1, "{point:?}");
        let replay = transaction_store::Host::commit(&mut reopened, request).unwrap();
        assert_eq!(replay.transaction_id, receipt.transaction_id, "{point:?}");
        assert_eq!(replay.commit_version, receipt.commit_version, "{point:?}");
        assert_eq!(
            replay.committed_value_digest.hex, receipt.committed_value_digest.hex,
            "{point:?}"
        );

        let stale = transaction_store::CommitRequest {
            transaction_id: "stale-writer".to_string(),
            assertions: vec![transaction_store::Assertion {
                namespace: "alpha".to_string(),
                key: "item".to_string(),
                expected_version: None,
            }],
            mutations: Vec::new(),
            idempotency_key: digest(format!("stale-{point:?}").as_bytes()),
        };
        assert_eq!(
            transaction_store::Host::commit(&mut reopened, stale)
                .unwrap_err()
                .code,
            "conflict",
            "{point:?}"
        );
        drop(reopened);

        let mut restarted = LocalMechanisms::open(directory.path(), config()).unwrap();
        assert_eq!(
            transaction_store::Host::read(&mut restarted, "alpha".to_string(), "item".to_string(),)
                .unwrap()
                .unwrap()
                .version,
            1,
            "{point:?}"
        );
    }
}

#[test]
fn independently_opened_stale_writer_is_fenced_before_state_change() {
    let directory = TestDirectory::new("stale-generation");
    let first = LocalMechanisms::open(directory.path(), config()).unwrap();
    let value = first
        .put_blob("application/octet-stream".to_string(), b"value".to_vec())
        .unwrap();
    drop(first);

    let mut current = LocalMechanisms::open(directory.path(), config()).unwrap();
    let mut stale = LocalMechanisms::open(directory.path(), config()).unwrap();
    assert_eq!(
        transaction_store::Host::commit(&mut current, commit_request(value))
            .unwrap()
            .commit_version,
        1
    );
    let stale_attempt = transaction_store::CommitRequest {
        transaction_id: "independent-stale-writer".to_string(),
        assertions: Vec::new(),
        mutations: Vec::new(),
        idempotency_key: digest(b"independent-stale-writer"),
    };
    let error = transaction_store::Host::commit(&mut stale, stale_attempt).unwrap_err();
    assert_eq!(error.code, "persistence-error");
    assert!(error.message.contains("stale writer fenced"));

    drop(current);
    drop(stale);
    let mut restarted = LocalMechanisms::open(directory.path(), config()).unwrap();
    assert_eq!(
        transaction_store::Host::read(&mut restarted, "alpha".to_string(), "item".to_string(),)
            .unwrap()
            .unwrap()
            .version,
        1
    );
}

#[test]
fn audit_event_and_receipt_commit_are_atomic_and_idempotent_across_restart() {
    for point in [
        DurabilityFaultPoint::BeforeStateCommit,
        DurabilityFaultPoint::AfterStateCommit,
    ] {
        let directory = TestDirectory::new(&format!("audit-{point:?}"));
        let first = LocalMechanisms::open(directory.path(), config()).unwrap();
        let payload = first
            .put_blob("application/json".to_string(), b"{}".to_vec())
            .unwrap();
        drop(first);

        let entry = audit_log::AuditEntry {
            event_id: "durability-event".to_string(),
            actor: foundation::Principal {
                id: "opaque-component".to_string(),
                component_digest: digest(TASK_COMPONENT),
            },
            event_type: "opaque.event".to_string(),
            payload,
            previous_entry: None,
            occurred_at_ms: 1_000,
            idempotency_key: digest(b"durability-audit-idempotency"),
        };
        let controller = DurabilityFaultController::default();
        let mut faulted = open_faulted(directory.path(), controller.clone());
        controller.arm(point, "audit-append");
        let error = audit_log::Host::append(&mut faulted, entry.clone()).unwrap_err();
        assert_eq!(error.code, "persistence-error", "{point:?}");
        drop(faulted);

        let mut reopened = LocalMechanisms::open(directory.path(), config()).unwrap();
        assert_eq!(
            audit_log::Host::resolve(&mut reopened, 1)
                .unwrap()
                .is_some(),
            point == DurabilityFaultPoint::AfterStateCommit,
            "{point:?}"
        );
        let receipt = audit_log::Host::append(&mut reopened, entry.clone()).unwrap();
        let replay = audit_log::Host::append(&mut reopened, entry).unwrap();
        assert_eq!(receipt.sequence, 1, "{point:?}");
        assert_eq!(replay.sequence, receipt.sequence, "{point:?}");
        assert_eq!(
            replay.entry_digest.hex, receipt.entry_digest.hex,
            "{point:?}"
        );
        drop(reopened);

        let mut restarted = LocalMechanisms::open(directory.path(), config()).unwrap();
        assert!(
            audit_log::Host::resolve(&mut restarted, 1)
                .unwrap()
                .is_some(),
            "{point:?}"
        );
    }
}

fn run_request(input: foundation::BlobRef) -> component_runner::RunRequest {
    component_runner::RunRequest {
        run_id: "durable-component-run".to_string(),
        component_digest: digest(MECHANISM_TASK_COMPONENT),
        input,
        grants: vec![
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
        ],
        limits: foundation::ResourceLimits {
            fuel: 1_000_000,
            memory_bytes: 8 * 1024 * 1024,
            output_bytes: 1024,
            wall_time_ms: 1_000,
        },
        idempotency_key: digest(b"durable-component-run-idempotency"),
    }
}

#[test]
fn component_dispatch_completion_and_receipt_faults_resume_without_duplicate_effect() {
    for point in [
        DurabilityFaultPoint::BeforeComponentDispatch,
        DurabilityFaultPoint::AfterComponentDispatch,
        DurabilityFaultPoint::BeforeComponentCompletion,
        DurabilityFaultPoint::AfterComponentCompletion,
        DurabilityFaultPoint::BeforeRunReceiptCommit,
        DurabilityFaultPoint::AfterRunReceiptCommit,
    ] {
        let directory = TestDirectory::new(&format!("run-{point:?}"));
        let first = LocalMechanisms::open(directory.path(), config()).unwrap();
        first
            .admit_component(
                Sha256Digest::from_bytes(MECHANISM_TASK_COMPONENT),
                MECHANISM_TASK_COMPONENT,
            )
            .unwrap();
        let input = first
            .put_blob(
                "application/octet-stream".to_string(),
                format!("input-{point:?}").into_bytes(),
            )
            .unwrap();
        drop(first);

        let controller = DurabilityFaultController::default();
        let mut faulted = open_faulted(directory.path(), controller.clone());
        let request = run_request(input);
        controller.arm(point, "component-run");
        assert!(
            component_runner::Host::start(&mut faulted, request.clone()).is_err(),
            "{point:?}"
        );
        assert_eq!(controller.fired().len(), 1, "{point:?}");
        drop(faulted);

        let mut reopened = LocalMechanisms::open(directory.path(), config()).unwrap();
        let effect = transaction_store::Host::read(
            &mut reopened,
            "wasm-biotic.schedule.v1".to_string(),
            "last-input".to_string(),
        )
        .unwrap();
        assert_eq!(
            effect.is_some(),
            point != DurabilityFaultPoint::BeforeComponentDispatch,
            "{point:?}"
        );

        let operation = component_runner::Host::start(&mut reopened, request.clone()).unwrap();
        assert!(
            component_runner::Host::poll(&mut reopened, operation.clone())
                .unwrap()
                .is_some(),
            "{point:?}"
        );
        assert_eq!(
            component_runner::Host::start(&mut reopened, request).unwrap(),
            operation,
            "{point:?}"
        );
        assert_eq!(
            transaction_store::Host::read(
                &mut reopened,
                "wasm-biotic.schedule.v1".to_string(),
                "last-input".to_string(),
            )
            .unwrap()
            .unwrap()
            .version,
            1,
            "{point:?}"
        );

        let probe = transaction_store::CommitRequest {
            transaction_id: "version-probe".to_string(),
            assertions: vec![],
            mutations: vec![],
            idempotency_key: digest(format!("probe-{point:?}").as_bytes()),
        };
        assert_eq!(
            transaction_store::Host::commit(&mut reopened, probe)
                .unwrap()
                .commit_version,
            2,
            "the component's idempotent mechanism effect must commit exactly once at {point:?}"
        );
    }
}
