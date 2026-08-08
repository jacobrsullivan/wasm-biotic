#![cfg_attr(not(test), no_std)]

//! Deterministic, effect-free policy for the bounded six-role worker ecology.
//!
//! Component adapters supply typed capability-service functions. This crate
//! validates graph bindings, constructs exact requests, and turns service
//! outcomes into truthful worker outcomes without a success fallback.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const TASK_REQUEST_SCHEMA: &str = "wasm-biotic.worker-task-request.v1";
pub const TASK_RESPONSE_SCHEMA: &str = "wasm-biotic.worker-task-response.v1";
pub const JSON_MEDIA_TYPE: &str = "application/json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Planner,
    Builder,
    Validator,
    Reviewer,
    Packager,
    ContinuityWorker,
}

impl Role {
    pub const ALL: [Self; 6] = [
        Self::Planner,
        Self::Builder,
        Self::Validator,
        Self::Reviewer,
        Self::Packager,
        Self::ContinuityWorker,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planner => "planner",
            Self::Builder => "builder",
            Self::Validator => "validator",
            Self::Reviewer => "reviewer",
            Self::Packager => "packager",
            Self::ContinuityWorker => "continuity-worker",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceFamily {
    Build,
    Packaging,
    Validation,
    Review,
    Continuity,
    Scheduling,
    Operations,
}

impl ServiceFamily {
    pub const ALL: [Self; 7] = [
        Self::Build,
        Self::Packaging,
        Self::Validation,
        Self::Review,
        Self::Continuity,
        Self::Scheduling,
        Self::Operations,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Packaging => "packaging",
            Self::Validation => "validation",
            Self::Review => "review",
            Self::Continuity => "continuity",
            Self::Scheduling => "scheduling",
            Self::Operations => "operations",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    WorkspaceOpen,
    WorkspaceSnapshot,
    WorkspacePatch,
    CandidateBuild,
    PackagePublish,
    PackageVerify,
    ValidationProve,
    FactoryProviderProposal,
    ReviewCandidate,
    EvidencePublish,
    EvidenceResolve,
    ScheduleJob,
}

impl Operation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceOpen => "workspace-open",
            Self::WorkspaceSnapshot => "workspace-snapshot",
            Self::WorkspacePatch => "workspace-patch",
            Self::CandidateBuild => "candidate-build",
            Self::PackagePublish => "package-publish",
            Self::PackageVerify => "package-verify",
            Self::ValidationProve => "validation-prove",
            Self::FactoryProviderProposal => "factory-provider-proposal",
            Self::ReviewCandidate => "review-candidate",
            Self::EvidencePublish => "evidence-publish",
            Self::EvidenceResolve => "evidence-resolve",
            Self::ScheduleJob => "schedule-job",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Authority {
    Observe,
    LocalMutate,
    AutomationControl,
    PromotionControl,
}

impl Authority {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::LocalMutate => "local-mutate",
            Self::AutomationControl => "automation-control",
            Self::PromotionControl => "promotion-control",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestValue {
    pub algorithm: String,
    pub hex: String,
}

impl DigestValue {
    pub fn sha256(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut hex = String::with_capacity(64);
        const ALPHABET: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            hex.push(ALPHABET[(byte >> 4) as usize] as char);
            hex.push(ALPHABET[(byte & 0x0f) as usize] as char);
        }
        Self {
            algorithm: "sha256".to_string(),
            hex,
        }
    }

    pub fn validate(&self, field: &str) -> Result<(), FailureValue> {
        if self.algorithm != "sha256"
            || self.hex.len() != 64
            || !self
                .hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(FailureValue::rejected(
                "invalid-digest",
                format!("{field} must be a lower-case SHA-256 digest"),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPointer {
    pub content_digest: DigestValue,
    pub size_bytes: u64,
    pub media_type: String,
}

impl BlobPointer {
    pub fn validate(&self, field: &str) -> Result<(), FailureValue> {
        self.content_digest
            .validate(&format!("{field}.content-digest"))?;
        if self.media_type.trim().is_empty() {
            return Err(FailureValue::rejected(
                "invalid-blob",
                format!("{field}.media-type must not be blank"),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalValue {
    pub id: String,
    pub component_digest: DigestValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBindingValue {
    pub family: ServiceFamily,
    pub component_digest: DigestValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequestValue {
    pub execution_id: String,
    pub job_id: String,
    pub role: Role,
    pub worker: PrincipalValue,
    pub service_bindings: Vec<ServiceBindingValue>,
    pub input: BlobPointer,
    pub checkpoint: Option<BlobPointer>,
    pub lease_digest: DigestValue,
    pub attempt: u32,
    pub deadline_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureValue {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub evidence: Option<BlobPointer>,
}

impl FailureValue {
    pub fn rejected(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: false,
            evidence: None,
        }
    }

    pub fn failed(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: false,
            evidence: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceiptValue {
    pub receipt_id: String,
    pub request_digest: DigestValue,
    pub executor_digest: DigestValue,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub outcome_digest: DigestValue,
    pub audit_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceOutcomeValue {
    Succeeded(BlobPointer),
    Rejected(FailureValue),
    Failed(FailureValue),
    Cancelled,
    Exhausted(FailureValue),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequestValue {
    pub request_id: String,
    pub job_id: String,
    pub caller: PrincipalValue,
    pub family: ServiceFamily,
    pub service_component: DigestValue,
    pub operation: Operation,
    pub input: BlobPointer,
    pub authority: Authority,
    pub deadline_ms: Option<u64>,
    pub idempotency_key: DigestValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityResponseValue {
    pub request_id: String,
    pub service_component: DigestValue,
    pub outcome: ServiceOutcomeValue,
    pub effect_receipts: Vec<EffectReceiptValue>,
    pub evidence: Vec<BlobPointer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerOutcomeValue {
    Completed(BlobPointer),
    Blocked(BlobPointer),
    Rejected(FailureValue),
    Failed(FailureValue),
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerResponseValue {
    pub execution_id: String,
    pub worker_component: DigestValue,
    pub outcome: WorkerOutcomeValue,
    pub checkpoint: Option<BlobPointer>,
    pub receipts: Vec<EffectReceiptValue>,
    pub evidence: Vec<BlobPointer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRequestEnvelope {
    pub schema: String,
    pub request: WorkerRequestValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskResponseEnvelope {
    pub schema: String,
    pub response: WorkerResponseValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StepSpec {
    family: ServiceFamily,
    operation: Operation,
    authority: Authority,
}

pub fn execute_worker<F>(
    expected_role: Role,
    request: WorkerRequestValue,
    mut invoke: F,
) -> WorkerResponseValue
where
    F: FnMut(ServiceFamily, CapabilityRequestValue) -> CapabilityResponseValue,
{
    let worker_component = request.worker.component_digest.clone();
    let execution_id = request.execution_id.clone();
    if let Err(failure) = validate_request(expected_role, &request) {
        return rejected_response(execution_id, worker_component, request.checkpoint, failure);
    }

    let bindings = request
        .service_bindings
        .iter()
        .map(|binding| (binding.family, binding.component_digest.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut current_input = request.input.clone();
    let mut receipts = Vec::new();
    let mut evidence = Vec::new();

    for (index, step) in steps(expected_role).iter().enumerate() {
        let target = bindings
            .get(&step.family)
            .expect("validated request contains every required service")
            .clone();
        let request_id = format!(
            "{}:{}:{}:{}",
            request.execution_id,
            index,
            step.family.as_str(),
            step.operation.as_str()
        );
        let idempotency_hex = wasm_biotic_service_policy_core::capability_decision_digest_hex(
            &wasm_biotic_service_policy_core::CapabilityDecisionMaterial {
                request_id: &request_id,
                job_id: &request.job_id,
                caller_id: &request.worker.id,
                caller_component_hex: &request.worker.component_digest.hex,
                service_component_hex: &target.hex,
                family: step.family.as_str(),
                operation: step.operation.as_str(),
                input_digest_hex: &current_input.content_digest.hex,
                input_size: current_input.size_bytes,
                input_media_type: &current_input.media_type,
                authority: step.authority.as_str(),
                deadline_ms: request.deadline_ms,
            },
        );
        let capability_request = CapabilityRequestValue {
            request_id: request_id.clone(),
            job_id: request.job_id.clone(),
            caller: request.worker.clone(),
            family: step.family,
            service_component: target.clone(),
            operation: step.operation,
            input: current_input.clone(),
            authority: step.authority,
            deadline_ms: request.deadline_ms,
            idempotency_key: DigestValue {
                algorithm: "sha256".to_string(),
                hex: idempotency_hex,
            },
        };
        let response = invoke(step.family, capability_request);
        receipts.extend(response.effect_receipts.clone());
        evidence.extend(response.evidence.clone());

        if response.request_id != request_id || response.service_component != target {
            return WorkerResponseValue {
                execution_id,
                worker_component,
                outcome: WorkerOutcomeValue::Failed(FailureValue::failed(
                    "service-protocol-violation",
                    "service response does not match the graph-bound request identity",
                )),
                checkpoint: request.checkpoint,
                receipts,
                evidence,
            };
        }

        match response.outcome {
            ServiceOutcomeValue::Succeeded(output) => {
                if let Err(failure) = output.validate("service.output") {
                    return WorkerResponseValue {
                        execution_id,
                        worker_component,
                        outcome: WorkerOutcomeValue::Failed(FailureValue::failed(
                            "invalid-service-output",
                            failure.message,
                        )),
                        checkpoint: request.checkpoint,
                        receipts,
                        evidence,
                    };
                }
                current_input = output;
            }
            ServiceOutcomeValue::Rejected(failure) => {
                return WorkerResponseValue {
                    execution_id,
                    worker_component,
                    outcome: WorkerOutcomeValue::Rejected(failure),
                    checkpoint: request.checkpoint,
                    receipts,
                    evidence,
                };
            }
            ServiceOutcomeValue::Failed(failure) | ServiceOutcomeValue::Exhausted(failure) => {
                return WorkerResponseValue {
                    execution_id,
                    worker_component,
                    outcome: WorkerOutcomeValue::Failed(failure),
                    checkpoint: request.checkpoint,
                    receipts,
                    evidence,
                };
            }
            ServiceOutcomeValue::Cancelled => {
                return WorkerResponseValue {
                    execution_id,
                    worker_component,
                    outcome: WorkerOutcomeValue::Cancelled,
                    checkpoint: request.checkpoint,
                    receipts,
                    evidence,
                };
            }
        }
    }

    WorkerResponseValue {
        execution_id,
        worker_component,
        outcome: WorkerOutcomeValue::Completed(current_input),
        checkpoint: request.checkpoint,
        receipts,
        evidence,
    }
}

pub fn decode_task_request(bytes: &[u8]) -> Result<WorkerRequestValue, FailureValue> {
    let envelope: TaskRequestEnvelope = serde_json::from_slice(bytes).map_err(|error| {
        FailureValue::rejected(
            "invalid-task-request-json",
            format!("could not decode worker task request: {error}"),
        )
    })?;
    if envelope.schema != TASK_REQUEST_SCHEMA {
        return Err(FailureValue::rejected(
            "unsupported-task-request-schema",
            format!("expected task request schema {TASK_REQUEST_SCHEMA}"),
        ));
    }
    Ok(envelope.request)
}

/// Encode the byte contract consumed by the uniform `component-task` adapter.
///
/// `serde_json` emits compact UTF-8 in declaration order for these structs.
/// The task ABI fixes that representation as part of schema v1 so a router can
/// content-address the exact bytes before passing the resulting blob reference
/// to `component-runner`.
pub fn encode_task_request(request: WorkerRequestValue) -> Result<Vec<u8>, FailureValue> {
    serde_json::to_vec(&TaskRequestEnvelope {
        schema: TASK_REQUEST_SCHEMA.to_string(),
        request,
    })
    .map_err(|error| {
        FailureValue::failed(
            "task-request-serialization-failed",
            format!("could not encode worker task request: {error}"),
        )
    })
}

pub fn encode_task_response(response: WorkerResponseValue) -> Result<Vec<u8>, FailureValue> {
    serde_json::to_vec(&TaskResponseEnvelope {
        schema: TASK_RESPONSE_SCHEMA.to_string(),
        response,
    })
    .map_err(|error| {
        FailureValue::failed(
            "task-response-serialization-failed",
            format!("could not encode worker task response: {error}"),
        )
    })
}

pub fn decode_task_response(bytes: &[u8]) -> Result<WorkerResponseValue, FailureValue> {
    let envelope: TaskResponseEnvelope = serde_json::from_slice(bytes).map_err(|error| {
        FailureValue::rejected(
            "invalid-task-response-json",
            format!("could not decode worker task response: {error}"),
        )
    })?;
    if envelope.schema != TASK_RESPONSE_SCHEMA {
        return Err(FailureValue::rejected(
            "unsupported-task-response-schema",
            format!("expected task response schema {TASK_RESPONSE_SCHEMA}"),
        ));
    }
    Ok(envelope.response)
}

fn validate_request(expected_role: Role, request: &WorkerRequestValue) -> Result<(), FailureValue> {
    if request.role != expected_role {
        return Err(FailureValue::rejected(
            "worker-role-mismatch",
            format!(
                "{} component cannot execute {} work",
                expected_role.as_str(),
                request.role.as_str()
            ),
        ));
    }
    if request.execution_id.trim().is_empty()
        || request.job_id.trim().is_empty()
        || request.worker.id.trim().is_empty()
        || request.attempt == 0
    {
        return Err(FailureValue::rejected(
            "invalid-worker-request",
            "execution, job, worker identifiers and non-zero attempt are required",
        ));
    }
    request
        .worker
        .component_digest
        .validate("worker.component-digest")?;
    request.input.validate("worker.input")?;
    request.lease_digest.validate("worker.lease-digest")?;
    if let Some(checkpoint) = &request.checkpoint {
        checkpoint.validate("worker.checkpoint")?;
    }

    let required = steps(expected_role)
        .iter()
        .map(|step| step.family)
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for binding in &request.service_bindings {
        binding
            .component_digest
            .validate(&format!("service-bindings.{}", binding.family.as_str()))?;
        if !actual.insert(binding.family) {
            return Err(FailureValue::rejected(
                "duplicate-service-binding",
                format!(
                    "{} service is bound more than once",
                    binding.family.as_str()
                ),
            ));
        }
    }
    if actual != required {
        return Err(FailureValue::rejected(
            "service-binding-mismatch",
            format!(
                "{} requires exactly its declared typed service families",
                expected_role.as_str()
            ),
        ));
    }
    Ok(())
}

fn steps(role: Role) -> &'static [StepSpec] {
    const PLANNER: &[StepSpec] = &[
        StepSpec {
            family: ServiceFamily::Build,
            operation: Operation::WorkspaceOpen,
            authority: Authority::Observe,
        },
        StepSpec {
            family: ServiceFamily::Build,
            operation: Operation::WorkspaceSnapshot,
            authority: Authority::Observe,
        },
        StepSpec {
            family: ServiceFamily::Build,
            operation: Operation::WorkspacePatch,
            authority: Authority::LocalMutate,
        },
        StepSpec {
            family: ServiceFamily::Scheduling,
            operation: Operation::ScheduleJob,
            authority: Authority::AutomationControl,
        },
    ];
    const BUILDER: &[StepSpec] = &[StepSpec {
        family: ServiceFamily::Build,
        operation: Operation::CandidateBuild,
        authority: Authority::LocalMutate,
    }];
    const VALIDATOR: &[StepSpec] = &[
        StepSpec {
            family: ServiceFamily::Validation,
            operation: Operation::FactoryProviderProposal,
            authority: Authority::LocalMutate,
        },
        StepSpec {
            family: ServiceFamily::Validation,
            operation: Operation::ValidationProve,
            authority: Authority::AutomationControl,
        },
    ];
    const REVIEWER: &[StepSpec] = &[StepSpec {
        family: ServiceFamily::Review,
        operation: Operation::ReviewCandidate,
        authority: Authority::Observe,
    }];
    const PACKAGER: &[StepSpec] = &[
        StepSpec {
            family: ServiceFamily::Packaging,
            operation: Operation::PackagePublish,
            authority: Authority::LocalMutate,
        },
        StepSpec {
            family: ServiceFamily::Packaging,
            operation: Operation::PackageVerify,
            authority: Authority::Observe,
        },
    ];
    const CONTINUITY: &[StepSpec] = &[
        StepSpec {
            family: ServiceFamily::Continuity,
            operation: Operation::EvidencePublish,
            authority: Authority::LocalMutate,
        },
        StepSpec {
            family: ServiceFamily::Continuity,
            operation: Operation::EvidenceResolve,
            authority: Authority::Observe,
        },
    ];
    match role {
        Role::Planner => PLANNER,
        Role::Builder => BUILDER,
        Role::Validator => VALIDATOR,
        Role::Reviewer => REVIEWER,
        Role::Packager => PACKAGER,
        Role::ContinuityWorker => CONTINUITY,
    }
}

fn rejected_response(
    execution_id: String,
    worker_component: DigestValue,
    checkpoint: Option<BlobPointer>,
    failure: FailureValue,
) -> WorkerResponseValue {
    WorkerResponseValue {
        execution_id,
        worker_component,
        outcome: WorkerOutcomeValue::Rejected(failure),
        checkpoint,
        receipts: Vec::new(),
        evidence: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(character: char) -> DigestValue {
        DigestValue {
            algorithm: "sha256".to_string(),
            hex: core::iter::repeat_n(character, 64).collect(),
        }
    }

    fn blob(character: char) -> BlobPointer {
        BlobPointer {
            content_digest: digest(character),
            size_bytes: 8,
            media_type: "application/octet-stream".to_string(),
        }
    }

    fn required(role: Role) -> Vec<ServiceBindingValue> {
        let families = steps(role)
            .iter()
            .map(|step| step.family)
            .collect::<BTreeSet<_>>();
        families
            .into_iter()
            .enumerate()
            .map(|(index, family)| ServiceBindingValue {
                family,
                component_digest: digest(char::from_digit(index as u32 + 1, 10).unwrap()),
            })
            .collect()
    }

    fn request(role: Role) -> WorkerRequestValue {
        WorkerRequestValue {
            execution_id: format!("execution-{}", role.as_str()),
            job_id: "job-1".to_string(),
            role,
            worker: PrincipalValue {
                id: role.as_str().to_string(),
                component_digest: digest('a'),
            },
            service_bindings: required(role),
            input: blob('b'),
            checkpoint: None,
            lease_digest: digest('c'),
            attempt: 1,
            deadline_ms: Some(1000),
        }
    }

    #[test]
    fn every_role_uses_only_its_declared_service_and_operation() {
        let expected = [
            (
                Role::Planner,
                vec![
                    (
                        ServiceFamily::Build,
                        Operation::WorkspaceOpen,
                        Authority::Observe,
                    ),
                    (
                        ServiceFamily::Build,
                        Operation::WorkspaceSnapshot,
                        Authority::Observe,
                    ),
                    (
                        ServiceFamily::Build,
                        Operation::WorkspacePatch,
                        Authority::LocalMutate,
                    ),
                    (
                        ServiceFamily::Scheduling,
                        Operation::ScheduleJob,
                        Authority::AutomationControl,
                    ),
                ],
            ),
            (
                Role::Builder,
                vec![(
                    ServiceFamily::Build,
                    Operation::CandidateBuild,
                    Authority::LocalMutate,
                )],
            ),
            (
                Role::Validator,
                vec![
                    (
                        ServiceFamily::Validation,
                        Operation::FactoryProviderProposal,
                        Authority::LocalMutate,
                    ),
                    (
                        ServiceFamily::Validation,
                        Operation::ValidationProve,
                        Authority::AutomationControl,
                    ),
                ],
            ),
            (
                Role::Reviewer,
                vec![(
                    ServiceFamily::Review,
                    Operation::ReviewCandidate,
                    Authority::Observe,
                )],
            ),
            (
                Role::Packager,
                vec![
                    (
                        ServiceFamily::Packaging,
                        Operation::PackagePublish,
                        Authority::LocalMutate,
                    ),
                    (
                        ServiceFamily::Packaging,
                        Operation::PackageVerify,
                        Authority::Observe,
                    ),
                ],
            ),
            (
                Role::ContinuityWorker,
                vec![
                    (
                        ServiceFamily::Continuity,
                        Operation::EvidencePublish,
                        Authority::LocalMutate,
                    ),
                    (
                        ServiceFamily::Continuity,
                        Operation::EvidenceResolve,
                        Authority::Observe,
                    ),
                ],
            ),
        ];
        for (role, expected_calls) in expected {
            let mut calls = Vec::new();
            let response = execute_worker(role, request(role), |family, request| {
                calls.push((family, request.operation, request.authority));
                CapabilityResponseValue {
                    request_id: request.request_id,
                    service_component: request.service_component,
                    outcome: ServiceOutcomeValue::Succeeded(blob('d')),
                    effect_receipts: Vec::new(),
                    evidence: Vec::new(),
                }
            });
            assert_eq!(calls, expected_calls);
            assert!(matches!(response.outcome, WorkerOutcomeValue::Completed(_)));
        }
    }

    #[test]
    fn expanded_workflow_requests_and_idempotency_material_are_replay_stable() {
        fn run(
            role: Role,
        ) -> (
            WorkerResponseValue,
            Vec<(String, Operation, String, DigestValue)>,
        ) {
            let mut trace = Vec::new();
            let response = execute_worker(role, request(role), |_, request| {
                trace.push((
                    request.request_id.clone(),
                    request.operation,
                    request.input.content_digest.hex.clone(),
                    request.idempotency_key.clone(),
                ));
                let output_bytes = request.request_id.as_bytes();
                let output_digest = DigestValue::sha256(output_bytes);
                let output_size = output_bytes.len() as u64;
                CapabilityResponseValue {
                    request_id: request.request_id,
                    service_component: request.service_component,
                    outcome: ServiceOutcomeValue::Succeeded(BlobPointer {
                        content_digest: output_digest,
                        size_bytes: output_size,
                        media_type: "application/vnd.wasm-biotic.test-step".to_string(),
                    }),
                    effect_receipts: Vec::new(),
                    evidence: Vec::new(),
                }
            });
            (response, trace)
        }

        let first = run(Role::Planner);
        let replay = run(Role::Planner);
        assert_eq!(first, replay);
        assert_eq!(
            first
                .1
                .iter()
                .map(|(request_id, operation, _, _)| (request_id.as_str(), *operation))
                .collect::<Vec<_>>(),
            vec![
                (
                    "execution-planner:0:build:workspace-open",
                    Operation::WorkspaceOpen,
                ),
                (
                    "execution-planner:1:build:workspace-snapshot",
                    Operation::WorkspaceSnapshot,
                ),
                (
                    "execution-planner:2:build:workspace-patch",
                    Operation::WorkspacePatch,
                ),
                (
                    "execution-planner:3:scheduling:schedule-job",
                    Operation::ScheduleJob,
                ),
            ]
        );
        assert!(
            first
                .1
                .windows(2)
                .all(|pair| pair[0].0 != pair[1].0 && pair[0].3 != pair[1].3)
        );
    }

    #[test]
    fn role_and_service_binding_mismatches_fail_before_invocation() {
        let mut wrong_role = request(Role::Builder);
        wrong_role.role = Role::Reviewer;
        let mut invoked = false;
        let response = execute_worker(Role::Builder, wrong_role, |_, _| {
            invoked = true;
            unreachable!()
        });
        assert!(!invoked);
        assert!(matches!(response.outcome, WorkerOutcomeValue::Rejected(_)));

        let mut extra = request(Role::Validator);
        extra.service_bindings.push(ServiceBindingValue {
            family: ServiceFamily::Operations,
            component_digest: digest('e'),
        });
        let response = execute_worker(Role::Validator, extra, |_, _| unreachable!());
        assert!(matches!(response.outcome, WorkerOutcomeValue::Rejected(_)));
    }

    #[test]
    fn service_failure_and_identity_violation_never_become_success() {
        let response = execute_worker(Role::Packager, request(Role::Packager), |_, request| {
            CapabilityResponseValue {
                request_id: request.request_id,
                service_component: request.service_component,
                outcome: ServiceOutcomeValue::Exhausted(FailureValue {
                    code: "quota-exhausted".to_string(),
                    message: "bounded quota exhausted".to_string(),
                    retryable: false,
                    evidence: None,
                }),
                effect_receipts: Vec::new(),
                evidence: Vec::new(),
            }
        });
        assert!(
            matches!(response.outcome, WorkerOutcomeValue::Failed(failure) if failure.code == "quota-exhausted")
        );

        let response = execute_worker(Role::Reviewer, request(Role::Reviewer), |_, request| {
            CapabilityResponseValue {
                request_id: request.request_id,
                service_component: digest('f'),
                outcome: ServiceOutcomeValue::Succeeded(blob('d')),
                effect_receipts: Vec::new(),
                evidence: Vec::new(),
            }
        });
        assert!(
            matches!(response.outcome, WorkerOutcomeValue::Failed(failure) if failure.code == "service-protocol-violation")
        );
    }

    #[test]
    fn task_blob_schema_is_versioned_compact_json_and_round_trips() {
        let request = request(Role::Builder);
        let encoded = encode_task_request(request.clone()).expect("encode task request");
        assert!(encoded.starts_with(
            br#"{"schema":"wasm-biotic.worker-task-request.v1","request":{"execution_id":"#
        ));
        assert!(!encoded.contains(&b'\n'));
        assert_eq!(decode_task_request(&encoded), Ok(request));

        let response = WorkerResponseValue {
            execution_id: "execution-builder".to_string(),
            worker_component: digest('a'),
            outcome: WorkerOutcomeValue::Completed(blob('d')),
            checkpoint: None,
            receipts: Vec::new(),
            evidence: Vec::new(),
        };
        let encoded = encode_task_response(response.clone()).expect("encode task response");
        assert!(encoded.starts_with(
            br#"{"schema":"wasm-biotic.worker-task-response.v1","response":{"execution_id":"#
        ));
        assert!(!encoded.contains(&b'\n'));
        assert_eq!(decode_task_response(&encoded), Ok(response));
    }
}
