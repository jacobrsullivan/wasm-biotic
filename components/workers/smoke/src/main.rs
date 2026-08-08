//! Instantiate the compiled planner with an empty in-memory substrate plus its
//! two declared typed service imports, then execute its four-step workflow.

use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::PathBuf};
use wasm_biotic_worker_policy::{
    BlobPointer, DigestValue, PrincipalValue, Role as PolicyRole, ServiceBindingValue,
    ServiceFamily as PolicyServiceFamily, WorkerOutcomeValue, WorkerRequestValue,
    decode_task_response, encode_task_request,
};
use wasmtime::{
    Config, Engine, Store,
    component::{Component, HasSelf, Linker},
};

wasmtime::component::bindgen!({
    path: "../../../wit/wasm-biotic",
    world: "planner-worker-component",
});

use exports::wasm_biotic::factory::worker_workflow::{WorkerOutcome, WorkerRequest, WorkerRole};
use wasm_biotic::factory::capability_contract::{
    CapabilityRequest, CapabilityResponse, Operation, ServiceBinding, ServiceFamily, ServiceOutcome,
};
use wasm_biotic::factory::foundation::{BlobRef, Digest, Failure, HashAlgorithm, Principal};

#[derive(Default)]
struct HostState {
    calls: Vec<(ServiceFamily, Operation, String)>,
    blobs: BTreeMap<String, (String, Vec<u8>)>,
}

impl wasm_biotic::factory::foundation::Host for HostState {}

impl wasm_biotic::factory::capability_contract::Host for HostState {}

impl wasm_biotic::factory::blob_store::Host for HostState {
    fn put(&mut self, media_type: String, content: Vec<u8>) -> Result<BlobRef, Failure> {
        let reference = blob_ref(&media_type, &content);
        self.blobs
            .insert(reference.content_digest.hex.clone(), (media_type, content));
        Ok(reference)
    }

    fn get(&mut self, reference: BlobRef) -> Result<Vec<u8>, Failure> {
        self.blobs
            .get(&reference.content_digest.hex)
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| failure("missing-blob", "smoke blob was not found"))
    }

    fn has(&mut self, content_digest: Digest) -> Result<bool, Failure> {
        Ok(self.blobs.contains_key(&content_digest.hex))
    }
}

impl wasm_biotic::factory::build_service::Host for HostState {
    fn invoke(&mut self, request: CapabilityRequest) -> CapabilityResponse {
        self.calls.push((
            request.family,
            request.operation,
            request.service_component.hex.clone(),
        ));
        let (expected_input, output) = match request.operation {
            Operation::WorkspaceOpen => (blob('d'), blob('e')),
            Operation::WorkspaceSnapshot => (blob('e'), blob('f')),
            Operation::WorkspacePatch => (blob('f'), blob('0')),
            _ => return rejected_service(request, "invalid-build-operation"),
        };
        if request.family != ServiceFamily::Build
            || !digest_eq(&request.service_component, &repeated_digest('b'))
            || !blob_eq(&request.input, &expected_input)
        {
            return rejected_service(request, "invalid-build-request");
        }
        succeeded_service(request, output)
    }
}

impl wasm_biotic::factory::scheduling_service::Host for HostState {
    fn invoke(&mut self, request: CapabilityRequest) -> CapabilityResponse {
        self.calls.push((
            request.family,
            request.operation,
            request.service_component.hex.clone(),
        ));
        if request.family != ServiceFamily::Scheduling
            || request.operation != Operation::ScheduleJob
            || !digest_eq(&request.service_component, &repeated_digest('c'))
            || !blob_eq(&request.input, &blob('0'))
        {
            return rejected_service(request, "invalid-scheduling-request");
        }
        succeeded_service(request, blob('1'))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let component_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: cargo run -p wasm-biotic-worker-smoke -- <planner.wasm>")?;
    let component_bytes = std::fs::read(&component_path)?;
    let worker_digest = digest_bytes(&component_bytes);

    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_binary(&engine, &component_bytes)?;
    let mut linker = Linker::new(&engine);
    PlannerWorkerComponent::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;
    let task_request = policy_request(&worker_digest);
    let task_bytes = encode_task_request(task_request)
        .map_err(|failure| format!("task encode failed: {}: {}", failure.code, failure.message))?;
    let task_ref = blob_ref("application/json", &task_bytes);
    let mut host = HostState::default();
    host.blobs.insert(
        task_ref.content_digest.hex.clone(),
        (task_ref.media_type.clone(), task_bytes),
    );
    let mut store = Store::new(&engine, host);
    let bindings = PlannerWorkerComponent::instantiate(&mut store, &component, &linker)?;

    let request = WorkerRequest {
        execution_id: "planner-smoke-execution".to_string(),
        job_id: "planner-smoke-job".to_string(),
        role: WorkerRole::Planner,
        worker: Principal {
            id: "planner".to_string(),
            component_digest: worker_digest.clone(),
        },
        service_bindings: vec![
            ServiceBinding {
                family: ServiceFamily::Build,
                component_digest: repeated_digest('b'),
            },
            ServiceBinding {
                family: ServiceFamily::Scheduling,
                component_digest: repeated_digest('c'),
            },
        ],
        input: blob('d'),
        checkpoint: None,
        lease_digest: repeated_digest('a'),
        attempt: 1,
        deadline_ms: Some(10_000),
    };
    let response = bindings
        .wasm_biotic_factory_worker_workflow()
        .call_execute(&mut store, &request)?;
    assert_eq!(response.execution_id, request.execution_id);
    assert!(digest_eq(&response.worker_component, &worker_digest));
    assert!(
        matches!(response.outcome, WorkerOutcome::Completed(ref output) if blob_eq(output, &blob('1')))
    );
    assert_eq!(
        store.data().calls,
        vec![
            (
                ServiceFamily::Build,
                Operation::WorkspaceOpen,
                repeated_digest('b').hex,
            ),
            (
                ServiceFamily::Build,
                Operation::WorkspaceSnapshot,
                repeated_digest('b').hex,
            ),
            (
                ServiceFamily::Build,
                Operation::WorkspacePatch,
                repeated_digest('b').hex,
            ),
            (
                ServiceFamily::Scheduling,
                Operation::ScheduleJob,
                repeated_digest('c').hex,
            ),
        ]
    );
    store.data_mut().calls.clear();

    let response_ref = bindings
        .wasm_biotic_factory_component_task()
        .call_run(&mut store, &task_ref)?
        .map_err(|failure| {
            format!(
                "component-task failed: {}: {}",
                failure.code, failure.message
            )
        })?;
    let response_bytes = store
        .data()
        .blobs
        .get(&response_ref.content_digest.hex)
        .ok_or("component-task response blob was not persisted")?
        .1
        .clone();
    let task_response = decode_task_response(&response_bytes)
        .map_err(|failure| format!("task decode failed: {}: {}", failure.code, failure.message))?;
    assert_eq!(task_response.execution_id, "planner-task-execution");
    assert_eq!(task_response.worker_component.hex, worker_digest.hex);
    assert!(matches!(
        task_response.outcome,
        WorkerOutcomeValue::Completed(ref output) if output == &policy_blob('1')
    ));
    assert_eq!(store.data().calls.len(), 4);
    println!(
        "executed planner sha256:{} through typed workflow and component-task: build/workspace-open -> build/workspace-snapshot -> build/workspace-patch -> scheduling/schedule-job",
        worker_digest.hex
    );
    Ok(())
}

fn succeeded_service(request: CapabilityRequest, output: BlobRef) -> CapabilityResponse {
    CapabilityResponse {
        request_id: request.request_id,
        service_component: request.service_component,
        outcome: ServiceOutcome::Succeeded(output),
        effect_receipts: Vec::new(),
        evidence: Vec::new(),
    }
}

fn rejected_service(request: CapabilityRequest, code: &str) -> CapabilityResponse {
    CapabilityResponse {
        request_id: request.request_id,
        service_component: request.service_component,
        outcome: ServiceOutcome::Rejected(failure(code, "smoke host rejected request")),
        effect_receipts: Vec::new(),
        evidence: Vec::new(),
    }
}

fn blob(character: char) -> BlobRef {
    BlobRef {
        content_digest: repeated_digest(character),
        size_bytes: 8,
        media_type: "application/octet-stream".to_string(),
    }
}

fn blob_ref(media_type: &str, bytes: &[u8]) -> BlobRef {
    BlobRef {
        content_digest: digest_bytes(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_string(),
    }
}

fn repeated_digest(character: char) -> Digest {
    Digest {
        algorithm: HashAlgorithm::Sha256,
        hex: std::iter::repeat_n(character, 64).collect(),
    }
}

fn digest_bytes(bytes: &[u8]) -> Digest {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        hex.push(ALPHABET[(byte >> 4) as usize] as char);
        hex.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    Digest {
        algorithm: HashAlgorithm::Sha256,
        hex,
    }
}

fn digest_eq(left: &Digest, right: &Digest) -> bool {
    left.algorithm == right.algorithm && left.hex == right.hex
}

fn blob_eq(left: &BlobRef, right: &BlobRef) -> bool {
    digest_eq(&left.content_digest, &right.content_digest)
        && left.size_bytes == right.size_bytes
        && left.media_type == right.media_type
}

fn policy_request(worker_digest: &Digest) -> WorkerRequestValue {
    WorkerRequestValue {
        execution_id: "planner-task-execution".to_string(),
        job_id: "planner-smoke-job".to_string(),
        role: PolicyRole::Planner,
        worker: PrincipalValue {
            id: "planner".to_string(),
            component_digest: DigestValue {
                algorithm: "sha256".to_string(),
                hex: worker_digest.hex.clone(),
            },
        },
        service_bindings: vec![
            ServiceBindingValue {
                family: PolicyServiceFamily::Build,
                component_digest: policy_digest('b'),
            },
            ServiceBindingValue {
                family: PolicyServiceFamily::Scheduling,
                component_digest: policy_digest('c'),
            },
        ],
        input: policy_blob('d'),
        checkpoint: None,
        lease_digest: policy_digest('a'),
        attempt: 1,
        deadline_ms: Some(10_000),
    }
}

fn policy_blob(character: char) -> BlobPointer {
    BlobPointer {
        content_digest: policy_digest(character),
        size_bytes: 8,
        media_type: "application/octet-stream".to_string(),
    }
}

fn policy_digest(character: char) -> DigestValue {
    DigestValue {
        algorithm: "sha256".to_string(),
        hex: std::iter::repeat_n(character, 64).collect(),
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
