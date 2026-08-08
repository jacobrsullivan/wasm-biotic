//! Execute the compiled root through Wasmtime with deterministic in-memory
//! component-dependency stubs. Native stubs are test fixtures only; production
//! composition resolves these imports to graph-bound components.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use wasm_biotic_factory_control::policy::{
    BlobValue, ControlStatus, DigestValue, JSON_MEDIA_TYPE, JobResultV1, SUBMIT_SCHEMA,
    SUPERVISOR_STATE_SCHEMA, StateDocumentRef, SubmitEnvelopeV1, encode_json,
};
use wasmtime::{
    Config, Engine, Store,
    component::{Component, HasSelf, Linker},
};

wasmtime::component::bindgen!({
    path: "../../wit/wasm-biotic",
    world: "factory-control-component",
});

use exports::wasm_biotic::factory::factory_api::IngressRequest;
use wasm_biotic::factory::activation::{ActivationRequest, ActivationState, ActivationStatus};
use wasm_biotic::factory::audit_log::{AuditEntry, AuditReceipt};
use wasm_biotic::factory::capability_contract::{
    CapabilityRequest, CapabilityResponse, ServiceBinding, ServiceFamily, ServiceOutcome,
};
use wasm_biotic::factory::foundation::{
    BlobRef, Digest, Document, Failure, HashAlgorithm, Principal,
};
use wasm_biotic::factory::state_migration::StateMigrationRequest;
use wasm_biotic::factory::supervisor_reducer::{
    Reduction, ReductionRequest, SupervisorCommand, SupervisorEvent,
};
use wasm_biotic::factory::transaction_store::{
    CommitReceipt, CommitRequest, Mutation, VersionedValue,
};
use wasm_biotic::factory::worker_workflow::{
    WorkerOutcome, WorkerRequest, WorkerResponse, WorkerRole,
};

#[derive(Default)]
struct HostState {
    blobs: BTreeMap<String, (String, Vec<u8>)>,
    records: BTreeMap<(String, String), (u64, BlobRef)>,
    worker_roles: Vec<String>,
    active_manifest: Option<BlobRef>,
}

impl wasm_biotic::factory::foundation::Host for HostState {}
impl wasm_biotic::factory::capability_contract::Host for HostState {}
impl wasm_biotic::factory::worker_workflow::Host for HostState {
    fn execute(&mut self, request: WorkerRequest) -> WorkerResponse {
        dispatch_worker(self, request)
    }
}

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

impl wasm_biotic::factory::transaction_store::Host for HostState {
    fn read(&mut self, namespace: String, key: String) -> Result<Option<VersionedValue>, Failure> {
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
            let actual = self
                .records
                .get(&(assertion.namespace.clone(), assertion.key.clone()))
                .map(|(version, _)| *version);
            if actual != assertion.expected_version {
                return Err(failure(
                    "cas-conflict",
                    "smoke transaction assertion failed",
                ));
            }
        }
        let mut commit_version = 0;
        let mut committed = digest_bytes(b"empty-commit");
        for mutation in request.mutations {
            match mutation {
                Mutation::Put((namespace, key, value)) => {
                    let next = self
                        .records
                        .get(&(namespace.clone(), key.clone()))
                        .map_or(1, |(version, _)| version + 1);
                    committed = value.content_digest.clone();
                    commit_version = next;
                    self.records.insert((namespace, key), (next, value));
                }
                Mutation::Delete((namespace, key)) => {
                    self.records.remove(&(namespace, key));
                }
            }
        }
        Ok(CommitReceipt {
            transaction_id: request.transaction_id,
            commit_version,
            committed_value_digest: committed,
        })
    }
}

impl wasm_biotic::factory::supervisor_reducer::Host for HostState {
    fn reduce(&mut self, request: ReductionRequest) -> Result<Reduction, Failure> {
        let previous = digest_bytes(&request.state.body);
        let (job_id, input, command) = match request.event {
            SupervisorEvent::JobSubmitted(source) => {
                let job_id = format!("job-sha256-{}", source.content_digest.hex);
                let request = worker_request(&job_id, 0, source.clone());
                (job_id, source, SupervisorCommand::DispatchWorker(request))
            }
            SupervisorEvent::WorkerFinished(response) => {
                let finished = (request.event_sequence - 2) as usize;
                let expected = worker_digest(finished);
                if response.worker_component.hex != expected.hex {
                    return Err(failure(
                        "worker-component-mismatch",
                        "smoke reducer observed the wrong graph-bound worker",
                    ));
                }
                let output = match response.outcome {
                    WorkerOutcome::Completed(output) => output,
                    _ => {
                        return Err(failure(
                            "unexpected-worker-outcome",
                            "smoke expects completion",
                        ));
                    }
                };
                let job_id = response
                    .execution_id
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                if finished == 5 {
                    (
                        job_id,
                        output.clone(),
                        SupervisorCommand::EmitResponse(output),
                    )
                } else {
                    let next = worker_request(&job_id, finished + 1, output.clone());
                    (job_id, output, SupervisorCommand::DispatchWorker(next))
                }
            }
            _ => {
                return Err(failure(
                    "unsupported-smoke-event",
                    "smoke reducer supports job and worker events",
                ));
            }
        };
        let next_body = format!(
            "{{\"job_id\":\"{}\",\"event_sequence\":{},\"input\":\"{}\"}}",
            job_id, request.event_sequence, input.content_digest.hex,
        )
        .into_bytes();
        Ok(Reduction {
            previous_state_digest: previous,
            next_state: Document {
                schema: SUPERVISOR_STATE_SCHEMA.to_string(),
                media_type: JSON_MEDIA_TYPE.to_string(),
                body: next_body,
            },
            commands: vec![command],
            decision_digest: digest_bytes(
                format!("decision-{}", request.event_sequence).as_bytes(),
            ),
        })
    }
}

impl wasm_biotic::factory::worker_router::Host for HostState {
    fn dispatch(&mut self, request: WorkerRequest) -> WorkerResponse {
        dispatch_worker(self, request)
    }
}

impl wasm_biotic::factory::capability_router::Host for HostState {
    fn route(&mut self, request: CapabilityRequest) -> CapabilityResponse {
        CapabilityResponse {
            request_id: request.request_id,
            service_component: request.service_component,
            outcome: ServiceOutcome::Succeeded(request.input),
            effect_receipts: Vec::new(),
            evidence: Vec::new(),
        }
    }
}

impl wasm_biotic::factory::exchange_service::Host for HostState {
    fn create_envelope(&mut self, value: BlobRef) -> Result<BlobRef, Failure> {
        Ok(value)
    }
    fn receive_envelope(&mut self, value: BlobRef) -> Result<BlobRef, Failure> {
        Ok(value)
    }
    fn revoke_authority(&mut self, value: BlobRef) -> Result<BlobRef, Failure> {
        Ok(value)
    }
    fn inspect_transfer(&mut self, _id: String) -> Result<BlobRef, Failure> {
        Err(failure(
            "unused-smoke-route",
            "exchange inspect is not used",
        ))
    }
}

impl wasm_biotic::factory::factory_evolution::Host for HostState {
    fn propose(&mut self, value: BlobRef) -> Result<BlobRef, Failure> {
        Ok(value)
    }
    fn shadow(&mut self, value: BlobRef) -> Result<BlobRef, Failure> {
        Ok(value)
    }
    fn assess(&mut self, value: BlobRef) -> Result<BlobRef, Failure> {
        Ok(value)
    }
}

impl wasm_biotic::factory::state_migration::Host for HostState {
    fn migrate(&mut self, value: StateMigrationRequest) -> Result<Document, Failure> {
        Ok(value.previous_state)
    }
}

impl wasm_biotic::factory::closure_evaluator::Host for HostState {
    fn evaluate(&mut self, value: BlobRef) -> Result<BlobRef, Failure> {
        Ok(value)
    }
}

impl wasm_biotic::factory::activation::Host for HostState {
    fn active_manifest(&mut self) -> Result<Option<BlobRef>, Failure> {
        Ok(self.active_manifest.clone())
    }

    fn active_state(&mut self) -> Result<Option<BlobRef>, Failure> {
        Ok(None)
    }

    fn stage(&mut self, request: ActivationRequest) -> Result<ActivationStatus, Failure> {
        Ok(activation_status(
            request.activation_id,
            ActivationState::Staged,
        ))
    }
    fn commit(&mut self, id: String) -> Result<ActivationStatus, Failure> {
        Ok(activation_status(id, ActivationState::Active))
    }
    fn status(&mut self, id: String) -> Result<ActivationStatus, Failure> {
        Ok(activation_status(id, ActivationState::Active))
    }
    fn rollback(&mut self, id: String, graph: Digest) -> Result<ActivationStatus, Failure> {
        let mut status = activation_status(id, ActivationState::RolledBack);
        status.active_graph = Some(graph);
        Ok(status)
    }
}

impl wasm_biotic::factory::audit_log::Host for HostState {
    fn append(&mut self, entry: AuditEntry) -> Result<AuditReceipt, Failure> {
        Ok(AuditReceipt {
            sequence: 1,
            entry_digest: entry.idempotency_key,
        })
    }
    fn resolve(&mut self, _sequence: u64) -> Result<Option<AuditEntry>, Failure> {
        Ok(None)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let component_path = std::env::args().nth(1).map(PathBuf::from).ok_or(
        "usage: cargo run -p wasm-biotic-factory-control --example smoke -- <component.wasm>",
    )?;
    let mut host = HostState::default();
    let (manifest, worker_components, service_components) = active_factory_fixture();
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_ref = insert_blob(
        &mut host,
        "application/vnd.wasm-biotic.factory-graph.v1+json",
        manifest_bytes,
    );
    host.active_manifest = Some(manifest_ref.clone());
    let graph_digest = digest_value(&manifest_ref.content_digest);
    let source_bytes = b"bounded component-complete factory source".to_vec();
    let source = insert_blob(&mut host, "application/octet-stream", source_bytes);
    let initial_state_bytes = serde_json::to_vec(&json!({
        "active_executions": {},
        "completed_executions": {},
        "graph_digest": graph_digest,
        "jobs": {},
        "last_event_sequence": 0,
        "schema": SUPERVISOR_STATE_SCHEMA,
        "service_components": service_components,
        "worker_components": worker_components,
    }))?;
    let initial_state = insert_blob(&mut host, JSON_MEDIA_TYPE, initial_state_bytes);
    let submit = SubmitEnvelopeV1 {
        schema: SUBMIT_SCHEMA.to_string(),
        graph_digest,
        initial_state: StateDocumentRef {
            schema: SUPERVISOR_STATE_SCHEMA.to_string(),
            blob: blob_value(&initial_state),
        },
        source: blob_value(&source),
    };
    let submit_bytes = encode_json(&submit, "smoke-submit-encode")?;
    let submit_ref = insert_blob(&mut host, JSON_MEDIA_TYPE, submit_bytes);

    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, &component_path)?;
    let mut linker = Linker::new(&engine);
    FactoryControlComponent::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;
    let mut store = Store::new(&engine, host);
    let bindings = FactoryControlComponent::instantiate(&mut store, &component, &linker)?;

    let job_id = bindings
        .wasm_biotic_factory_factory_control()
        .call_submit(&mut store, &submit_ref)?
        .map_err(display_failure)?;
    let result_ref = bindings
        .wasm_biotic_factory_factory_control()
        .call_inspect(&mut store, &job_id)?
        .map_err(display_failure)?;
    let result_bytes = store
        .data()
        .blobs
        .get(&result_ref.content_digest.hex)
        .ok_or("result blob was not persisted")?
        .1
        .clone();
    let result: JobResultV1 = serde_json::from_slice(&result_bytes)?;
    assert_eq!(result.status, ControlStatus::Completed);
    assert!(result.output.is_some());
    assert_eq!(
        store.data().worker_roles,
        vec![
            "planner",
            "builder",
            "validator",
            "reviewer",
            "packager",
            "continuity-worker",
        ]
    );

    let probe = bindings
        .wasm_biotic_factory_factory_api()
        .call_handle(
            &mut store,
            &IngressRequest {
                request_id: "probe-1".to_string(),
                method: "GET".to_string(),
                path: "/__wasm-biotic/component-boundary-probe".to_string(),
                headers: Vec::new(),
                body: None,
            },
        )?
        .map_err(display_failure)?;
    assert_eq!(probe.status, 200);

    println!(
        "executed {}: {} completed through planner -> builder -> validator -> reviewer -> packager -> continuity-worker",
        component_path.display(),
        job_id,
    );
    Ok(())
}

fn worker_request(job_id: &str, index: usize, input: BlobRef) -> WorkerRequest {
    let roles = [
        WorkerRole::Planner,
        WorkerRole::Builder,
        WorkerRole::Validator,
        WorkerRole::Reviewer,
        WorkerRole::Packager,
        WorkerRole::ContinuityWorker,
    ];
    let role = roles[index];
    let service_bindings = match role {
        WorkerRole::Planner => vec![
            service_binding(ServiceFamily::Build, 'f'),
            service_binding(ServiceFamily::Scheduling, 'e'),
        ],
        WorkerRole::Builder => vec![service_binding(ServiceFamily::Build, 'f')],
        WorkerRole::Validator => vec![service_binding(ServiceFamily::Validation, 'd')],
        WorkerRole::Reviewer => vec![service_binding(ServiceFamily::Review, 'c')],
        WorkerRole::Packager => vec![service_binding(ServiceFamily::Packaging, 'b')],
        WorkerRole::ContinuityWorker => vec![service_binding(ServiceFamily::Continuity, 'a')],
    };
    WorkerRequest {
        execution_id: format!("{}:{}:1", job_id, role_name(role)),
        job_id: job_id.to_string(),
        role,
        worker: Principal {
            id: role_name(role).to_string(),
            component_digest: worker_digest(index),
        },
        service_bindings,
        input,
        checkpoint: None,
        lease_digest: digest_bytes(format!("lease-{index}").as_bytes()),
        attempt: 1,
        deadline_ms: None,
    }
}

fn dispatch_worker(host: &mut HostState, request: WorkerRequest) -> WorkerResponse {
    host.worker_roles.push(role_name(request.role).to_string());
    let bytes = format!("completed:{}", request.execution_id).into_bytes();
    let output = blob_ref("application/octet-stream", &bytes);
    host.blobs.insert(
        output.content_digest.hex.clone(),
        (output.media_type.clone(), bytes),
    );
    WorkerResponse {
        execution_id: request.execution_id,
        worker_component: request.worker.component_digest,
        outcome: WorkerOutcome::Completed(output),
        checkpoint: None,
        receipts: Vec::new(),
        evidence: Vec::new(),
    }
}

fn service_binding(family: ServiceFamily, character: char) -> ServiceBinding {
    ServiceBinding {
        family,
        component_digest: repeated_digest(character),
    }
}

fn role_name(role: WorkerRole) -> &'static str {
    match role {
        WorkerRole::Planner => "planner",
        WorkerRole::Builder => "builder",
        WorkerRole::Validator => "validator",
        WorkerRole::Reviewer => "reviewer",
        WorkerRole::Packager => "packager",
        WorkerRole::ContinuityWorker => "continuity-worker",
    }
}

fn worker_digest(index: usize) -> Digest {
    repeated_digest(char::from_digit(index as u32 + 1, 10).unwrap())
}

fn activation_status(id: String, state: ActivationState) -> ActivationStatus {
    ActivationStatus {
        activation_id: id,
        state,
        active_graph: None,
        active_state: None,
        receipt: None,
    }
}

fn insert_blob(host: &mut HostState, media_type: &str, bytes: Vec<u8>) -> BlobRef {
    let reference = blob_ref(media_type, &bytes);
    host.blobs.insert(
        reference.content_digest.hex.clone(),
        (media_type.to_string(), bytes),
    );
    reference
}

fn blob_ref(media_type: &str, bytes: &[u8]) -> BlobRef {
    BlobRef {
        content_digest: digest_bytes(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_string(),
    }
}

fn blob_value(reference: &BlobRef) -> BlobValue {
    BlobValue {
        content_digest: DigestValue {
            algorithm: "sha256".to_string(),
            hex: reference.content_digest.hex.clone(),
        },
        size_bytes: reference.size_bytes,
        media_type: reference.media_type.clone(),
    }
}

fn repeated_value_digest(character: char) -> DigestValue {
    DigestValue {
        algorithm: "sha256".to_string(),
        hex: std::iter::repeat_n(character, 64).collect(),
    }
}

fn digest_value(value: &Digest) -> DigestValue {
    DigestValue {
        algorithm: "sha256".to_string(),
        hex: value.hex.clone(),
    }
}

fn active_factory_fixture() -> (
    Value,
    BTreeMap<String, DigestValue>,
    BTreeMap<String, DigestValue>,
) {
    let workers = BTreeMap::from([
        ("planner".to_string(), digest_value(&worker_digest(0))),
        ("builder".to_string(), digest_value(&worker_digest(1))),
        ("validator".to_string(), digest_value(&worker_digest(2))),
        ("reviewer".to_string(), digest_value(&worker_digest(3))),
        ("packager".to_string(), digest_value(&worker_digest(4))),
        (
            "continuity-worker".to_string(),
            digest_value(&worker_digest(5)),
        ),
    ]);
    let services = BTreeMap::from([
        ("build".to_string(), repeated_value_digest('f')),
        ("packaging".to_string(), repeated_value_digest('b')),
        ("validation".to_string(), repeated_value_digest('d')),
        ("review".to_string(), repeated_value_digest('c')),
        ("continuity".to_string(), repeated_value_digest('a')),
        ("scheduling".to_string(), repeated_value_digest('e')),
        ("operations".to_string(), repeated_value_digest('9')),
    ]);
    let identities = [
        ("factory-control", "root", repeated_value_digest('8')),
        (
            "supervisor-reducer",
            "supervisor-reducer",
            repeated_value_digest('7'),
        ),
        ("worker-router", "worker-router", repeated_value_digest('6')),
        (
            "capability-router",
            "capability-router",
            repeated_value_digest('5'),
        ),
        (
            "planner-worker",
            "planner-worker",
            workers["planner"].clone(),
        ),
        (
            "builder-worker",
            "builder-worker",
            workers["builder"].clone(),
        ),
        (
            "validator-worker",
            "validator-worker",
            workers["validator"].clone(),
        ),
        (
            "reviewer-worker",
            "reviewer-worker",
            workers["reviewer"].clone(),
        ),
        (
            "packager-worker",
            "packager-worker",
            workers["packager"].clone(),
        ),
        (
            "continuity-worker",
            "continuity-worker",
            workers["continuity-worker"].clone(),
        ),
        ("build-service", "build-service", services["build"].clone()),
        (
            "packaging-service",
            "packaging-service",
            services["packaging"].clone(),
        ),
        (
            "validation-service",
            "validation-service",
            services["validation"].clone(),
        ),
        (
            "review-service",
            "review-service",
            services["review"].clone(),
        ),
        (
            "continuity-service",
            "continuity-service",
            services["continuity"].clone(),
        ),
        (
            "scheduling-service",
            "scheduling-service",
            services["scheduling"].clone(),
        ),
        (
            "operations-service",
            "operations-service",
            services["operations"].clone(),
        ),
        (
            "exchange-service",
            "exchange-service",
            repeated_value_digest('4'),
        ),
        (
            "factory-evolution",
            "factory-evolution",
            repeated_value_digest('3'),
        ),
        (
            "state-migration",
            "state-migration",
            repeated_value_digest('2'),
        ),
        (
            "closure-evaluator",
            "closure-evaluator",
            repeated_value_digest('1'),
        ),
    ];
    let nodes = identities
        .into_iter()
        .map(|(id, kind, digest)| {
            let mut node = json!({
                "component_digest": format!("sha256:{}", digest.hex),
                "exports": [format!("wasm-biotic:factory/{id}@0.1.0")],
                "grants": [],
                "id": id,
                "kind": kind,
                "world": format!("wasm-biotic:factory/{id}-component@0.1.0"),
            });
            if kind == "root" {
                node["state_schema"] = json!(SUPERVISOR_STATE_SCHEMA);
            }
            node
        })
        .collect::<Vec<_>>();
    (
        json!({
            "bindings": [],
            "invocations": [],
            "nodes": nodes,
            "root_node": "factory-control",
            "schema": "wasm-biotic.factory-graph.v1",
            "state_schema": SUPERVISOR_STATE_SCHEMA,
            "wit_package": "wasm-biotic:factory@0.1.0",
        }),
        workers,
        services,
    )
}

fn repeated_digest(character: char) -> Digest {
    Digest {
        algorithm: HashAlgorithm::Sha256,
        hex: std::iter::repeat_n(character, 64).collect(),
    }
}

fn digest_bytes(bytes: &[u8]) -> Digest {
    let value = DigestValue::sha256(bytes);
    Digest {
        algorithm: HashAlgorithm::Sha256,
        hex: value.hex,
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

fn display_failure(value: Failure) -> String {
    format!("{}: {}", value.code, value.message)
}
