//! Bounded M4 integration over the durable worker store and live M3 services.
//!
//! M2 deliberately accepts only the closed M1 lifecycle catalog. This module
//! does not smuggle a generic worker payload into that catalog. Worker
//! executions are durably owned by [`WorkerRuntime`]; the Planner's reference
//! workflow prerequisite is separately submitted through M3's real scheduling
//! service and therefore owned by M2. Every worker success is derived from one
//! or more durable M3 receipts and is rejected if the bridge cannot bind it to
//! the exact persisted worker result.

use crate::candidate::COMPONENT_WAT_PATH;
use crate::capability_services::{
    BuildCandidateRequest, CancellationToken as ServiceCancellationToken, CapabilityHostError,
    CapabilityInvocation, CapabilityOperation, CapabilityRequest, CapabilitySuccess,
    CompareProvingRequest, InvocationApproval, InvocationBudget, InvocationIdentity,
    InvocationOutcome, InvocationReceipt, OpenWorkspaceRequest, PatchWorkspaceRequest,
    ProvePackageRequest, PublishEvidenceRequest, PublishPackageRequest, ResolveEvidenceRequest,
    ScopedWorkspaceRef, ServiceInvocationAttestation, VerifyPackageRequest,
};
use crate::execution::artifact::{ContentDigest, digest_json_content};
use crate::execution::{
    ApprovalClass, AuthorityClass, CapabilityWorld, CapabilityWorldGrant, ComponentExecutionLimits,
    ComponentI32ExecutionTrace, execute_component_i32_export,
};
use crate::m1_validation::ValidationSuite;
use crate::m2_runtime::{M1LifecycleJob, OpenWorkspacePayload};
use crate::m3_runtime::{
    BUILD_SERVICE_ID, CONTINUITY_RESOLVE_SERVICE_ID, CONTINUITY_SERVICE_ID, M3CapabilityRuntime,
    M3RuntimeError, M3ScheduleRegistration, PACKAGING_SERVICE_ID, REVIEW_SERVICE_ID,
    SCHEDULING_SERVICE_ID, VALIDATION_SERVICE_ID,
};
use crate::supervisor::{DurableJob, JobPhase, RetryPolicy};
use crate::worker_runtime::{
    CancellationToken as WorkerCancellationToken, CapabilityInvocationReceipt,
    CapabilityInvocationRequest, CapabilityServiceFailure, CapabilityServiceInvoker,
    DispatchReport, DurableJobExecutor, ExecutableImplementation, ExecutableImplementationKind,
    ExecutorOutcome, ExecutorReconciliation, GovernedWorkerRole, JobStatus, PackageProvenance,
    PersistedWorkerResult, REFERENCE_SERVICE_SCHEMA, ReconciliationReport, ReferenceWorkerExecutor,
    ReferenceWorkflowEvidence, ReferenceWorkflowSpec, ReviewDecision, WorkBudget, WorkDeadline,
    WorkInput, WorkOutput, WorkerExecutionRecord, WorkerJobRequest, WorkerRuntime,
    WorkerRuntimeError, WorkspaceScope, governed_work_input_digest, reference_capability_envelope,
    reference_worker_registration,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BRIDGE_SCHEMA_VERSION: u32 = 5;
const EXECUTOR_SCHEMA_VERSION: u32 = 3;
const FLEET_SCHEMA_VERSION: u32 = 1;
const BRIDGE_STATE_FILE: &str = "m4-bridge-state.json";
const EXECUTOR_STATE_FILE: &str = "m4-executor-state.json";
const FLEET_STATE_FILE: &str = "m4-fleet-state.json";
const RUNTIME_IDENTITY_FILE: &str = "m4-runtime-identity.json";
const RUNTIME_OWNER_LOCK_FILE: &str = ".m4-runtime-owner.lock";
const WORKER_PACKAGE_DIRECTORY: &str = "packages";
const BRIDGE_WIRE_SCHEMA: &str = "wasm-biotic.m4-worker-bridge.v2";
const WORKER_PACKAGE_SCHEMA: &str = "wasm-biotic.m4-worker-package.v1";
const WORKER_PACKAGE_ENTRYPOINT: &str = "run";
const WORKER_PACKAGE_TOOLCHAIN_ID: &str = "wat:1.246.2";
const WORKER_PACKAGE_PRODUCER_REF: &str = "wasm-biotic:m4-reference-wat-builder:wat-1.246.2";
// The synchronous observer must be willing to wait for the same bounded
// interval that the durable M2 job is allowed to run. Keeping these values
// coupled avoids reporting a local timeout while the prerequisite still has
// valid execution time remaining under CPU or I/O contention.
const ANCHOR_LIFECYCLE_WINDOW_MS: u64 = 60_000;
const ANCHOR_WAIT_TIMEOUT: Duration = Duration::from_millis(ANCHOR_LIFECYCLE_WINDOW_MS);
const BRIDGE_CRASH_FAULT_DETAIL: &str =
    "injected crash after durable inner M3 receipt and before outer bridge receipt";

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

type BridgeCrashFaults = Arc<Mutex<BTreeMap<String, u32>>>;

/// One bounded worker factory backed by one fixed M3 scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M4RuntimeConfig {
    pub root: PathBuf,
    pub factory_id: String,
    pub worker_max_concurrency: usize,
}

impl M4RuntimeConfig {
    pub fn validate(&self) -> Result<(), M4RuntimeError> {
        if self.root.as_os_str().is_empty() {
            return Err(M4RuntimeError::InvalidConfig(
                "root must not be empty".to_string(),
            ));
        }
        validate_identifier("factory_id", &self.factory_id)?;
        if self.worker_max_concurrency == 0 {
            return Err(M4RuntimeError::InvalidConfig(
                "worker_max_concurrency must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Inputs for the closed six-role reference workflow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M4ReferenceWorkflowRequest {
    pub workflow_id: String,
    pub objective: String,
    pub governance_context_digest: ContentDigest,
    pub replacement_wat_bytes: Vec<u8>,
    pub validation_suite: ValidationSuite,
    pub budget: WorkBudget,
    pub deadline: WorkDeadline,
}

/// The real M2/M3 prerequisite bound before any worker is dispatched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M4LifecycleAnchor {
    pub schedule_id: String,
    pub m2_job_id: String,
    pub schedule_binding_digest: ContentDigest,
    pub schedule_attestation: ServiceInvocationAttestation,
    pub terminal_job: DurableJob,
    pub terminal_job_digest: ContentDigest,
}

/// A compact, reloadable account of the native effects behind one worker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M4ExecutionEvidence {
    pub execution_id: String,
    pub worker_result_digest: ContentDigest,
    pub role: GovernedWorkerRole,
    pub governance_context_digest: ContentDigest,
    pub actual: M4ActualOutput,
    pub service_attestations: Vec<ServiceInvocationAttestation>,
}

/// Durable, operator-visible progress at the M4-to-M3 effect boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M4BridgeExecutionProgress {
    pub execution_id: String,
    pub role: GovernedWorkerRole,
    pub governance_context_digest: ContentDigest,
    pub expected_inner_invocation_ids: Vec<String>,
    pub started_inner_invocation_ids: Vec<String>,
    pub recorded_inner_receipt_digests: BTreeMap<String, ContentDigest>,
    pub completed_inner_receipt_digests: BTreeMap<String, ContentDigest>,
    pub terminal_inner_invocation_ids: Vec<String>,
    pub outer_receipt_committed: bool,
}

/// Native artifacts actually returned by M3 for a worker result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum M4ActualOutput {
    Planner {
        workspace_tree_digest: ContentDigest,
        schedule_binding_digest: ContentDigest,
        plan_digest: ContentDigest,
    },
    Builder {
        before_digest: ContentDigest,
        candidate_wat_digest: ContentDigest,
        source_tree_digest: ContentDigest,
        package_digest: ContentDigest,
        package_record_digest: ContentDigest,
    },
    Validator {
        candidate_wat_digest: ContentDigest,
        package_digest: ContentDigest,
        proving_digest: ContentDigest,
        passed: bool,
    },
    Reviewer {
        comparison_digest: ContentDigest,
        review_digest: ContentDigest,
        approved: bool,
    },
    Packager {
        package_digest: ContentDigest,
        verification_digest: ContentDigest,
    },
    ContinuityWorker {
        evidence_id: String,
        content_digest: ContentDigest,
        record_digest: ContentDigest,
    },
}

impl M4ActualOutput {
    fn role(&self) -> GovernedWorkerRole {
        match self {
            Self::Planner { .. } => GovernedWorkerRole::Planner,
            Self::Builder { .. } => GovernedWorkerRole::Builder,
            Self::Validator { .. } => GovernedWorkerRole::Validator,
            Self::Reviewer { .. } => GovernedWorkerRole::Reviewer,
            Self::Packager { .. } => GovernedWorkerRole::Packager,
            Self::ContinuityWorker { .. } => GovernedWorkerRole::ContinuityWorker,
        }
    }
}

/// Durable proof that the exact registered worker package bytes were loaded
/// and invoked under Wasmtime before the role's capability service ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerPackageExecutionRecord {
    pub execution_id: String,
    pub worker_id: String,
    pub role: GovernedWorkerRole,
    pub governance_context_digest: ContentDigest,
    pub package_digest: ContentDigest,
    pub implementation_ref: String,
    pub source_digest: ContentDigest,
    pub build_record_digest: ContentDigest,
    pub input_digest: ContentDigest,
    pub component_trace_digest: ContentDigest,
    pub component_trace: ComponentI32ExecutionTrace,
    pub component_input: i32,
    pub component_output: i32,
    pub executed_at_tick: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WorkerPackageManifest {
    schema: String,
    worker_id: String,
    role: GovernedWorkerRole,
    source_digest: ContentDigest,
    executable: ExecutableImplementation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct M4RuntimeIdentity {
    schema_version: u32,
    factory_id: String,
    worker_max_concurrency: usize,
    m3_scope_id: String,
    m3_root: PathBuf,
    identity_digest: ContentDigest,
}

#[derive(Serialize)]
struct M4RuntimeIdentityMaterial<'a> {
    schema_version: u32,
    factory_id: &'a str,
    worker_max_concurrency: usize,
    m3_scope_id: &'a str,
    m3_root: &'a Path,
}

impl M4RuntimeIdentity {
    fn new(config: &M4RuntimeConfig, m3: &M3CapabilityRuntime) -> Result<Self, M4RuntimeError> {
        let material = M4RuntimeIdentityMaterial {
            schema_version: BRIDGE_SCHEMA_VERSION,
            factory_id: &config.factory_id,
            worker_max_concurrency: config.worker_max_concurrency,
            m3_scope_id: &m3.config().scope_id,
            m3_root: m3.root(),
        };
        let identity_digest = digest_json_content(&material)
            .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
        Ok(Self {
            schema_version: material.schema_version,
            factory_id: material.factory_id.to_string(),
            worker_max_concurrency: material.worker_max_concurrency,
            m3_scope_id: material.m3_scope_id.to_string(),
            m3_root: material.m3_root.to_path_buf(),
            identity_digest,
        })
    }

    fn validate(&self) -> Result<(), M4RuntimeError> {
        let expected = digest_json_content(&M4RuntimeIdentityMaterial {
            schema_version: self.schema_version,
            factory_id: &self.factory_id,
            worker_max_concurrency: self.worker_max_concurrency,
            m3_scope_id: &self.m3_scope_id,
            m3_root: &self.m3_root,
        })
        .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
        if self.schema_version != BRIDGE_SCHEMA_VERSION || self.identity_digest != expected {
            return Err(M4RuntimeError::Integrity(
                "M4 runtime identity does not match its persisted content".to_string(),
            ));
        }
        Ok(())
    }
}

/// Completion evidence for the integrated reference workflow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M4ReferenceWorkflowEvidence {
    pub governance_context_digest: ContentDigest,
    pub worker: ReferenceWorkflowEvidence,
    pub lifecycle_anchor: M4LifecycleAnchor,
    pub executions: Vec<M4ExecutionEvidence>,
    pub package_executions: Vec<WorkerPackageExecutionRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PreparedWorkflow {
    workflow_id: String,
    request_digest: ContentDigest,
    objective: String,
    governance_context_digest: ContentDigest,
    candidate_workspace_id: String,
    incumbent_workspace_id: String,
    resource_scope: String,
    baseline_digest: ContentDigest,
    expected_before_digest: ContentDigest,
    validation_suite: ValidationSuite,
    incumbent_package_digest: ContentDigest,
    incumbent_proving_digest: ContentDigest,
    replacement_wat_digest: ContentDigest,
    planner_evidence_id: String,
    planner_evidence_digest: ContentDigest,
    budget: WorkBudget,
    deadline: WorkDeadline,
    anchor: M4LifecycleAnchor,
    preflight_attestations: Vec<ServiceInvocationAttestation>,
}

impl PreparedWorkflow {
    fn specification(
        &self,
        workspace_root: &Path,
        factory_id: &str,
    ) -> Result<ReferenceWorkflowSpec, M4RuntimeError> {
        let workspace_scope = WorkspaceScope {
            scope_id: factory_id.to_string(),
            workspace_root: workspace_root.to_path_buf(),
            resource_scopes: vec![self.resource_scope.clone()],
        };
        let capability_envelopes = GovernedWorkerRole::ALL
            .into_iter()
            .map(|role| {
                let mut envelope = reference_capability_envelope(
                    format!("m4:{}:{}:{}", factory_id, self.workflow_id, role.as_str()),
                    format!("factory:{factory_id}:{}", role.as_str()),
                    role,
                    workspace_scope.resource_scopes.clone(),
                )?;
                if let Some(grant) = integration_dependency_grant(role) {
                    envelope.world_grants.push(grant);
                }
                Ok::<_, WorkerRuntimeError>((role, envelope))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(ReferenceWorkflowSpec {
            workflow_id: self.workflow_id.clone(),
            objective: self.objective.clone(),
            governance_context_digest: self.governance_context_digest.clone(),
            baseline_digest: self.baseline_digest.clone(),
            workspace_scope,
            target_relative_path: PathBuf::from(COMPONENT_WAT_PATH),
            expected_before_digest: self.expected_before_digest.clone(),
            replacement_bytes: Vec::new(),
            validation_suite_digest: self.validation_suite.suite_digest().map_err(|error| {
                M4RuntimeError::InvalidConfig(format!("invalid validation suite: {error}"))
            })?,
            budget: self.budget.clone(),
            deadline: self.deadline.clone(),
            capability_envelopes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PendingExecutionEvidence {
    role: GovernedWorkerRole,
    governance_context_digest: ContentDigest,
    worker_payload_digest: ContentDigest,
    acquired_at_tick: u64,
    effect_started_at_tick: u64,
    workspace_scope: WorkspaceScope,
    capability_envelope: crate::execution::CapabilityEnvelope,
    work_budget: WorkBudget,
    deadline: WorkDeadline,
    actual: M4ActualOutput,
    service_attestations: Vec<ServiceInvocationAttestation>,
    outer_receipt: CapabilityInvocationReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BridgeInnerInvocationProgress {
    origin_execution_id: String,
    invocation: CapabilityInvocation,
    receipt_digest: Option<ContentDigest>,
    #[serde(default)]
    terminal_failure: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BridgeExecutionIntent {
    request: CapabilityInvocationRequest,
    role: GovernedWorkerRole,
    governance_context_digest: ContentDigest,
    request_digest: ContentDigest,
    worker_payload_digest: ContentDigest,
    acquired_at_tick: u64,
    effect_started_at_tick: u64,
    workspace_scope: WorkspaceScope,
    capability_envelope: crate::execution::CapabilityEnvelope,
    work_budget: WorkBudget,
    deadline: WorkDeadline,
    invocation_base: String,
    expected_inner_invocation_ids: Vec<String>,
    inner_invocations: BTreeMap<String, BridgeInnerInvocationProgress>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BridgeInvocationMode {
    Live,
    RecoveryOnly,
    ValidationOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PreparationIntent {
    request_digest: ContentDigest,
    due_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BridgeState {
    schema_version: u32,
    configuration_digest: ContentDigest,
    preparations: BTreeMap<String, PreparationIntent>,
    workflows: BTreeMap<String, PreparedWorkflow>,
    #[serde(default)]
    execution_intents: BTreeMap<String, BridgeExecutionIntent>,
    executions: BTreeMap<String, PendingExecutionEvidence>,
    result_aliases: BTreeMap<String, String>,
}

impl BridgeState {
    fn new(configuration_digest: ContentDigest) -> Self {
        Self {
            schema_version: BRIDGE_SCHEMA_VERSION,
            configuration_digest,
            preparations: BTreeMap::new(),
            workflows: BTreeMap::new(),
            execution_intents: BTreeMap::new(),
            executions: BTreeMap::new(),
            result_aliases: BTreeMap::new(),
        }
    }
}

/// Worker capability boundary backed exclusively by the live M3 host.
struct M3WorkerCapabilityBridge {
    root: PathBuf,
    factory_id: String,
    scope_id: String,
    m3: Arc<M3CapabilityRuntime>,
    crash_faults: BridgeCrashFaults,
    effect_gates: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    state: Mutex<BridgeState>,
}

impl M3WorkerCapabilityBridge {
    pub fn open(
        root: impl AsRef<Path>,
        factory_id: impl Into<String>,
        m3: Arc<M3CapabilityRuntime>,
        configuration_digest: ContentDigest,
        crash_faults: BridgeCrashFaults,
    ) -> Result<Self, M4RuntimeError> {
        let factory_id = factory_id.into();
        validate_identifier("factory_id", &factory_id)?;
        let root = secure_create_root(root.as_ref())?;
        let state_path = root.join(BRIDGE_STATE_FILE);
        let state = if state_path.exists() {
            read_json(&state_path)?
        } else {
            let state = BridgeState::new(configuration_digest.clone());
            write_json_atomic(&root, &state_path, &state)?;
            state
        };
        validate_bridge_state(&state)?;
        if state.configuration_digest != configuration_digest {
            return Err(M4RuntimeError::Conflict(
                "M4 bridge store belongs to a different runtime identity".to_string(),
            ));
        }
        let bridge = Self {
            root,
            factory_id,
            scope_id: m3.config().scope_id.clone(),
            m3,
            crash_faults,
            effect_gates: Mutex::new(BTreeMap::new()),
            state: Mutex::new(state),
        };
        bridge.validate_persisted_evidence()?;
        Ok(bridge)
    }

    pub fn prepare_reference_workflow(
        &self,
        request: &M4ReferenceWorkflowRequest,
    ) -> Result<ReferenceWorkflowSpec, M4RuntimeError> {
        validate_reference_request(request)?;
        let request_digest = reference_workflow_request_digest(request)?;
        if let Some(existing) = self
            .lock_state()?
            .workflows
            .get(&request.workflow_id)
            .cloned()
        {
            if existing.request_digest != request_digest {
                return Err(M4RuntimeError::Conflict(format!(
                    "workflow '{}' was prepared with different immutable inputs",
                    request.workflow_id
                )));
            }
            self.validate_lifecycle_anchor(&existing.anchor)?;
            let mut spec = existing.specification(self.m3.root(), &self.factory_id)?;
            spec.replacement_bytes = request.replacement_wat_bytes.clone();
            return Ok(spec);
        }
        let due_at_ms = {
            let existing = self
                .lock_state()?
                .preparations
                .get(&request.workflow_id)
                .cloned();
            match existing {
                Some(intent) if intent.request_digest == request_digest => intent.due_at_ms,
                Some(_) => {
                    return Err(M4RuntimeError::Conflict(format!(
                        "workflow '{}' has a different durable preparation intent",
                        request.workflow_id
                    )));
                }
                None => {
                    let due_at_ms = now_ms()?;
                    self.transact(|state| {
                        state.preparations.insert(
                            request.workflow_id.clone(),
                            PreparationIntent {
                                request_digest: request_digest.clone(),
                                due_at_ms,
                            },
                        );
                        Ok(())
                    })?;
                    due_at_ms
                }
            }
        };

        let suffix = digest_suffix(&request_digest);
        let incumbent_workspace_id = format!("m4-{suffix}-incumbent");
        let candidate_workspace_id = format!("m4-{suffix}-candidate");
        let resource_scope = format!("workflow:{}", request.workflow_id);
        let mut attestations = Vec::new();

        let _incumbent_snapshot = match self.invoke_native(
            &format!("m4-{suffix}-preflight-open-incumbent"),
            BUILD_SERVICE_ID,
            AuthorityClass::LocalMutate,
            InvocationApproval::Automatic,
            CapabilityRequest::OpenWorkspace(OpenWorkspaceRequest {
                workspace: self.workspace(&incumbent_workspace_id),
            }),
        )? {
            (CapabilitySuccess::Workspace(snapshot), attestation) => {
                attestations.push(attestation);
                *snapshot
            }
            _ => {
                return Err(M4RuntimeError::Integrity(
                    "workspace open returned the wrong type".into(),
                ));
            }
        };
        let candidate_snapshot = match self.invoke_native(
            &format!("m4-{suffix}-preflight-open-candidate"),
            BUILD_SERVICE_ID,
            AuthorityClass::LocalMutate,
            InvocationApproval::Automatic,
            CapabilityRequest::OpenWorkspace(OpenWorkspaceRequest {
                workspace: self.workspace(&candidate_workspace_id),
            }),
        )? {
            (CapabilitySuccess::Workspace(snapshot), attestation) => {
                attestations.push(attestation);
                *snapshot
            }
            _ => {
                return Err(M4RuntimeError::Integrity(
                    "workspace open returned the wrong type".into(),
                ));
            }
        };
        let expected_before_digest = candidate_snapshot
            .entry(COMPONENT_WAT_PATH)
            .ok_or_else(|| {
                M4RuntimeError::Integrity(
                    "candidate snapshot lacks the bounded mutable WAT".to_string(),
                )
            })?
            .content_digest
            .clone();

        let incumbent_build = match self.invoke_native(
            &format!("m4-{suffix}-preflight-build-incumbent"),
            BUILD_SERVICE_ID,
            AuthorityClass::LocalMutate,
            InvocationApproval::Automatic,
            CapabilityRequest::BuildCandidate(BuildCandidateRequest {
                workspace: self.workspace(&incumbent_workspace_id),
            }),
        )? {
            (CapabilitySuccess::Build(build), attestation) => {
                attestations.push(attestation);
                *build
            }
            _ => {
                return Err(M4RuntimeError::Integrity(
                    "candidate build returned the wrong type".into(),
                ));
            }
        };
        let incumbent_package = match self.invoke_native(
            &format!("m4-{suffix}-preflight-package-incumbent"),
            PACKAGING_SERVICE_ID,
            AuthorityClass::LocalMutate,
            InvocationApproval::Automatic,
            CapabilityRequest::PublishPackage(PublishPackageRequest {
                workspace: self.workspace(&incumbent_workspace_id),
                expected_package_digest: incumbent_build.package_digest.clone(),
            }),
        )? {
            (CapabilitySuccess::Package(package), attestation) => {
                attestations.push(attestation);
                *package
            }
            _ => {
                return Err(M4RuntimeError::Integrity(
                    "package publish returned the wrong type".into(),
                ));
            }
        };
        let incumbent_proving = match self.invoke_native(
            &format!("m4-{suffix}-preflight-prove-incumbent"),
            VALIDATION_SERVICE_ID,
            AuthorityClass::Observe,
            InvocationApproval::Automatic,
            CapabilityRequest::ProvePackage(ProvePackageRequest {
                scope_id: self.scope_id.clone(),
                package_digest: incumbent_package.package_digest.clone(),
                suite: request.validation_suite.clone(),
            }),
        )? {
            (CapabilitySuccess::Proving(proving), attestation) => {
                attestations.push(attestation);
                *proving
            }
            _ => {
                return Err(M4RuntimeError::Integrity(
                    "proving returned the wrong type".into(),
                ));
            }
        };

        let schedule_id = format!("m4-{suffix}-anchor");
        let m2_job_id = format!("m4-{suffix}-open");
        let binding = self.m3.register_schedule(M3ScheduleRegistration {
            scope_id: self.scope_id.clone(),
            schedule_id: schedule_id.clone(),
            job_id: m2_job_id.clone(),
            idempotency_key: format!("m4-{suffix}-open-effect"),
            due_at_ms,
            deadline_at_ms: due_at_ms.saturating_add(ANCHOR_LIFECYCLE_WINDOW_MS),
            retry_policy: RetryPolicy::default(),
            lifecycle: M1LifecycleJob::OpenWorkspace(OpenWorkspacePayload {
                workspace_id: candidate_workspace_id.clone(),
            }),
        })?;
        let (_, schedule_attestation) = self.invoke_native(
            &format!("m4-{suffix}-schedule-anchor"),
            SCHEDULING_SERVICE_ID,
            AuthorityClass::AutomationControl,
            InvocationApproval::Granted {
                approval_ref: format!("m4:{suffix}:supervisor"),
                class: ApprovalClass::SupervisorAllowed,
            },
            CapabilityRequest::ScheduleJob(binding.capability_request()),
        )?;
        let terminal_job = self.await_schedule_success(&schedule_id)?;
        let terminal_job_digest = digest_json_content(&terminal_job)
            .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
        let anchor = M4LifecycleAnchor {
            schedule_id,
            m2_job_id,
            schedule_binding_digest: binding.binding_digest,
            schedule_attestation,
            terminal_job,
            terminal_job_digest,
        };
        let planner_payload = serde_json::to_vec(&(
            BRIDGE_WIRE_SCHEMA,
            &request.workflow_id,
            &request.governance_context_digest,
            &candidate_snapshot.tree_digest,
            &anchor.schedule_binding_digest,
        ))?;
        let planner_evidence_id = format!("m4-{suffix}-planner-context");
        let planner_evidence = match self.invoke_native(
            &format!("m4-{suffix}-publish-planner-context"),
            CONTINUITY_SERVICE_ID,
            AuthorityClass::LocalMutate,
            InvocationApproval::Automatic,
            CapabilityRequest::PublishEvidence(PublishEvidenceRequest {
                scope_id: self.scope_id.clone(),
                evidence_id: planner_evidence_id.clone(),
                media_type: "application/json".to_string(),
                subject_refs: vec![
                    format!("workflow:{}", request.workflow_id),
                    format!("governance:{}", request.governance_context_digest),
                    format!("schedule:{}", anchor.schedule_binding_digest),
                ],
                payload: planner_payload.clone(),
                expected_digest: Some(ContentDigest::from_bytes(&planner_payload)),
            }),
        )? {
            (CapabilitySuccess::EvidencePublished(evidence), attestation) => {
                attestations.push(attestation);
                *evidence
            }
            _ => {
                return Err(M4RuntimeError::Integrity(
                    "planner context publish returned the wrong type".into(),
                ));
            }
        };
        let prepared = PreparedWorkflow {
            workflow_id: request.workflow_id.clone(),
            request_digest,
            objective: request.objective.clone(),
            governance_context_digest: request.governance_context_digest.clone(),
            candidate_workspace_id,
            incumbent_workspace_id,
            resource_scope,
            baseline_digest: candidate_snapshot.tree_digest,
            expected_before_digest,
            validation_suite: request.validation_suite.clone(),
            incumbent_package_digest: incumbent_package.package_digest,
            incumbent_proving_digest: incumbent_proving.record_digest,
            replacement_wat_digest: ContentDigest::from_bytes(&request.replacement_wat_bytes),
            planner_evidence_id,
            planner_evidence_digest: planner_evidence.content_digest,
            budget: request.budget.clone(),
            deadline: request.deadline.clone(),
            anchor,
            preflight_attestations: attestations,
        };
        self.transact(|state| {
            state.preparations.remove(&request.workflow_id);
            state
                .workflows
                .insert(request.workflow_id.clone(), prepared.clone());
            Ok(())
        })?;
        let mut spec = prepared.specification(self.m3.root(), &self.factory_id)?;
        spec.replacement_bytes = request.replacement_wat_bytes.clone();
        Ok(spec)
    }

    pub fn lifecycle_anchor(&self, workflow_id: &str) -> Result<M4LifecycleAnchor, M4RuntimeError> {
        let anchor = self
            .lock_state()?
            .workflows
            .get(workflow_id)
            .map(|workflow| workflow.anchor.clone())
            .ok_or_else(|| M4RuntimeError::NotFound(format!("workflow '{workflow_id}'")))?;
        self.validate_lifecycle_anchor(&anchor)?;
        Ok(anchor)
    }

    fn await_schedule_success(&self, schedule_id: &str) -> Result<DurableJob, M4RuntimeError> {
        let started = Instant::now();
        loop {
            if let Some(job) = self.m3.scheduled_job(schedule_id)?
                && job.phase.is_terminal()
            {
                if job.phase == JobPhase::Succeeded && job.terminal_outcome.is_some() {
                    return Ok(job);
                }
                return Err(M4RuntimeError::CapabilityFailure(format!(
                    "M2 lifecycle prerequisite '{schedule_id}' terminated as {:?}",
                    job.phase
                )));
            }
            if started.elapsed() >= ANCHOR_WAIT_TIMEOUT {
                return Err(M4RuntimeError::CapabilityFailure(format!(
                    "M2 lifecycle prerequisite '{schedule_id}' did not reach terminal success within {} ms",
                    ANCHOR_WAIT_TIMEOUT.as_millis()
                )));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn validate_lifecycle_anchor(&self, anchor: &M4LifecycleAnchor) -> Result<(), M4RuntimeError> {
        let terminal_job_digest = digest_json_content(&anchor.terminal_job)
            .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
        let binding = self.m3.schedule_binding(&anchor.schedule_id)?;
        let current_job = self.m3.scheduled_job(&anchor.schedule_id)?.ok_or_else(|| {
            M4RuntimeError::Integrity(format!(
                "M2 lifecycle prerequisite '{}' disappeared",
                anchor.schedule_id
            ))
        })?;
        let canonical_attestation = self
            .m3
            .attestation(&anchor.schedule_attestation.invocation_id)?;
        if anchor.m2_job_id != anchor.terminal_job.job_id
            || anchor.terminal_job.phase != JobPhase::Succeeded
            || anchor.terminal_job.terminal_outcome.is_none()
            || terminal_job_digest != anchor.terminal_job_digest
            || binding.binding_digest != anchor.schedule_binding_digest
            || current_job != anchor.terminal_job
            || canonical_attestation != anchor.schedule_attestation
            || !anchor.schedule_attestation.terminal_success
        {
            return Err(M4RuntimeError::Integrity(format!(
                "M2 lifecycle prerequisite '{}' is not exact terminal-success evidence",
                anchor.schedule_id
            )));
        }
        Ok(())
    }

    fn prepared_workflow_for_scope(
        &self,
        scope: &WorkspaceScope,
    ) -> Result<PreparedWorkflow, M4RuntimeError> {
        if scope.scope_id != self.factory_id
            || scope.workspace_root != self.m3.root()
            || scope.resource_scopes.len() != 1
        {
            return Err(M4RuntimeError::Worker(WorkerRuntimeError::InvalidRequest(
                "workspace scope is not the exact prepared M4 factory root".to_string(),
            )));
        }
        let resource_scope = &scope.resource_scopes[0];
        if !resource_scope.starts_with("workflow:") {
            return Err(M4RuntimeError::Worker(WorkerRuntimeError::InvalidRequest(
                "workspace scope does not identify one prepared workflow".to_string(),
            )));
        }
        self.lock_state()?
            .workflows
            .values()
            .find(|workflow| &workflow.resource_scope == resource_scope)
            .cloned()
            .ok_or_else(|| {
                M4RuntimeError::Worker(WorkerRuntimeError::InvalidRequest(format!(
                    "workspace scope references unknown prepared resource '{resource_scope}'"
                )))
            })
    }

    fn validate_job_request(&self, request: &WorkerJobRequest) -> Result<(), M4RuntimeError> {
        let workflow = self.prepared_workflow_for_scope(&request.workspace_scope)?;
        let expected_spec = workflow.specification(self.m3.root(), &self.factory_id)?;
        let expected_envelope = expected_spec
            .capability_envelopes
            .get(&request.role)
            .ok_or_else(|| {
                M4RuntimeError::Integrity("prepared workflow lacks a role envelope".to_string())
            })?;
        request.budget.validate()?;
        request.deadline.validate()?;
        if request.role != request.input.role()
            || request.governance_context_digest != workflow.governance_context_digest
            || &request.capability_envelope != expected_envelope
            || request.fairness_key != self.factory_id
            || request.budget != workflow.budget
            || request.deadline != workflow.deadline
            || request.budget.max_capability_calls < role_inner_call_count(request.role)
        {
            return Err(M4RuntimeError::Worker(
                WorkerRuntimeError::CapabilityDenied(
                    "job changed its prepared role, governance context, envelope, factory, budget, or deadline".to_string(),
                ),
            ));
        }
        let encoded = serde_json::to_vec(&request.input)?;
        if encoded.len() as u64 > request.budget.max_input_bytes {
            return Err(M4RuntimeError::Worker(WorkerRuntimeError::BudgetExceeded(
                "typed worker input exceeds its prepared byte budget".to_string(),
            )));
        }
        self.validate_lifecycle_anchor(&workflow.anchor)
    }

    fn bind_result(
        &self,
        result: &PersistedWorkerResult,
    ) -> Result<M4ExecutionEvidence, M4RuntimeError> {
        self.validate_persisted_evidence()?;
        self.transact(|state| {
            let pending = state
                .executions
                .get(&result.execution_id)
                .cloned()
                .ok_or_else(|| {
                    M4RuntimeError::Integrity(format!(
                        "worker result '{}' has no M3 execution evidence",
                        result.result_digest
                    ))
                })?;
            let outer_receipt_digest = digest_json_content(&pending.outer_receipt)
                .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
            if pending.role != result.role
                || pending.governance_context_digest != result.governance_context_digest
                || pending.outer_receipt.governance_context_digest
                    != result.governance_context_digest
                || pending.actual.role() != result.role
                || !actual_matches_output(&pending.actual, &result.output)
                || result.capability_receipt_digests != vec![outer_receipt_digest]
                || pending.outer_receipt.execution_id != result.execution_id
                || pending.outer_receipt.worker_id != result.worker_id
                || pending.service_attestations.is_empty()
                || pending
                    .service_attestations
                    .iter()
                    .any(|attestation| !attestation.terminal_success)
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "worker result '{}' is not derived from its exact successful M3 artifacts",
                    result.result_digest
                )));
            }
            if let Some(existing) = state.result_aliases.get(result.result_digest.as_str())
                && existing != &result.execution_id
            {
                return Err(M4RuntimeError::Conflict(format!(
                    "result '{}' is already bound to another execution",
                    result.result_digest
                )));
            }
            state.result_aliases.insert(
                result.result_digest.to_string(),
                result.execution_id.clone(),
            );
            Ok(M4ExecutionEvidence {
                execution_id: result.execution_id.clone(),
                worker_result_digest: result.result_digest.clone(),
                role: result.role,
                governance_context_digest: result.governance_context_digest.clone(),
                actual: pending.actual,
                service_attestations: pending.service_attestations,
            })
        })
    }

    pub fn execution_evidence(
        &self,
        result_digest: &ContentDigest,
    ) -> Result<M4ExecutionEvidence, M4RuntimeError> {
        self.validate_persisted_evidence()?;
        let state = self.lock_state()?;
        let execution_id = state
            .result_aliases
            .get(result_digest.as_str())
            .ok_or_else(|| {
                M4RuntimeError::NotFound(format!("M3 evidence for worker result '{result_digest}'"))
            })?;
        let pending = state.executions.get(execution_id).ok_or_else(|| {
            M4RuntimeError::Integrity("result alias points to missing execution evidence".into())
        })?;
        Ok(M4ExecutionEvidence {
            execution_id: execution_id.clone(),
            worker_result_digest: result_digest.clone(),
            role: pending.role,
            governance_context_digest: pending.governance_context_digest.clone(),
            actual: pending.actual.clone(),
            service_attestations: pending.service_attestations.clone(),
        })
    }

    fn execution_progress(
        &self,
        execution_id: &str,
    ) -> Result<M4BridgeExecutionProgress, M4RuntimeError> {
        self.validate_persisted_evidence()?;
        let state = self.lock_state()?;
        if let Some(pending) = state.executions.get(execution_id) {
            let intent = state.execution_intents.get(execution_id).ok_or_else(|| {
                M4RuntimeError::Integrity(format!(
                    "committed execution '{execution_id}' lacks its exact inner intent"
                ))
            })?;
            let expected_inner_invocation_ids = intent.expected_inner_invocation_ids.clone();
            let completed_inner_receipt_digests: BTreeMap<String, ContentDigest> = pending
                .service_attestations
                .iter()
                .map(|attestation| {
                    (
                        attestation.invocation_id.clone(),
                        attestation.receipt_digest.clone(),
                    )
                })
                .collect();
            return Ok(M4BridgeExecutionProgress {
                execution_id: execution_id.to_string(),
                role: pending.role,
                governance_context_digest: pending.governance_context_digest.clone(),
                started_inner_invocation_ids: expected_inner_invocation_ids.clone(),
                expected_inner_invocation_ids,
                recorded_inner_receipt_digests: completed_inner_receipt_digests.clone(),
                completed_inner_receipt_digests,
                terminal_inner_invocation_ids: Vec::new(),
                outer_receipt_committed: true,
            });
        }
        if let Some(intent) = state.execution_intents.get(execution_id) {
            let started_inner_invocation_ids = intent
                .expected_inner_invocation_ids
                .iter()
                .filter(|invocation_id| intent.inner_invocations.contains_key(*invocation_id))
                .cloned()
                .collect();
            let recorded_inner_receipt_digests = intent
                .inner_invocations
                .iter()
                .filter_map(|(invocation_id, progress)| {
                    progress
                        .receipt_digest
                        .clone()
                        .map(|digest| (invocation_id.clone(), digest))
                })
                .collect();
            let completed_inner_receipt_digests = intent
                .inner_invocations
                .iter()
                .filter_map(|(invocation_id, progress)| {
                    progress
                        .receipt_digest
                        .clone()
                        .or_else(|| {
                            self.m3
                                .receipt(invocation_id)
                                .ok()
                                .map(|receipt| receipt.receipt_digest().clone())
                        })
                        .map(|digest| (invocation_id.clone(), digest))
                })
                .collect();
            return Ok(M4BridgeExecutionProgress {
                execution_id: execution_id.to_string(),
                role: intent.role,
                governance_context_digest: intent.governance_context_digest.clone(),
                expected_inner_invocation_ids: intent.expected_inner_invocation_ids.clone(),
                started_inner_invocation_ids,
                recorded_inner_receipt_digests,
                completed_inner_receipt_digests,
                terminal_inner_invocation_ids: intent
                    .expected_inner_invocation_ids
                    .iter()
                    .filter(|invocation_id| {
                        intent
                            .inner_invocations
                            .get(*invocation_id)
                            .is_some_and(|progress| {
                                progress.terminal_failure
                                    || self.m3.receipt(invocation_id).is_ok_and(|receipt| {
                                        matches!(
                                            receipt.outcome(),
                                            InvocationOutcome::Terminal { .. }
                                        )
                                    })
                            })
                    })
                    .cloned()
                    .collect(),
                outer_receipt_committed: false,
            });
        }
        Err(M4RuntimeError::NotFound(format!(
            "M4 bridge execution progress '{execution_id}'"
        )))
    }

    fn ensure_execution_intent(
        &self,
        request: &CapabilityInvocationRequest,
        invocation_base: &str,
    ) -> Result<(), CapabilityServiceFailure> {
        let request_digest = digest_json_content(request)
            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        let expected = BridgeExecutionIntent {
            request: request.clone(),
            role: request.role,
            governance_context_digest: request.governance_context_digest.clone(),
            request_digest,
            worker_payload_digest: ContentDigest::from_bytes(&request.payload),
            acquired_at_tick: request.acquired_at_tick,
            effect_started_at_tick: request.effect_started_at_tick,
            workspace_scope: request.workspace_scope.clone(),
            capability_envelope: request.capability_envelope.clone(),
            work_budget: request.work_budget.clone(),
            deadline: request.deadline.clone(),
            invocation_base: invocation_base.to_string(),
            expected_inner_invocation_ids: role_inner_invocation_ids(invocation_base, request.role),
            inner_invocations: BTreeMap::new(),
        };
        self.transact(|state| {
            if state.executions.contains_key(&request.execution_id) {
                return Err(M4RuntimeError::Conflict(format!(
                    "execution '{}' already has committed outer evidence",
                    request.execution_id
                )));
            }
            if let Some(existing) = state.execution_intents.get(&request.execution_id) {
                let mut identity = existing.clone();
                identity.inner_invocations.clear();
                if identity != expected {
                    return Err(M4RuntimeError::Conflict(format!(
                        "execution '{}' changed its durable bridge intent",
                        request.execution_id
                    )));
                }
                return Ok(());
            }
            state
                .execution_intents
                .insert(request.execution_id.clone(), expected);
            Ok(())
        })
        .map_err(capability_store_error)
    }

    fn persist_inner_invocation(
        &self,
        execution_id: &str,
        proposed: CapabilityInvocation,
    ) -> Result<CapabilityInvocation, CapabilityServiceFailure> {
        self.transact(|state| {
            let invocation_id = proposed.identity.invocation_id.clone();
            let mut shared_invocation: Option<(CapabilityInvocation, String)> = None;
            for (other_execution_id, other_intent) in &state.execution_intents {
                if other_execution_id == execution_id {
                    continue;
                }
                let Some(other) = other_intent.inner_invocations.get(&invocation_id) else {
                    continue;
                };
                if other.invocation.identity != proposed.identity
                    || other.invocation.request != proposed.request
                {
                    return Err(M4RuntimeError::Conflict(format!(
                        "logical inner invocation '{invocation_id}' changed across worker attempts"
                    )));
                }
                if shared_invocation
                    .as_ref()
                    .is_some_and(|(existing, origin_execution_id)| {
                        existing != &other.invocation
                            || origin_execution_id != &other.origin_execution_id
                    })
                {
                    return Err(M4RuntimeError::Integrity(format!(
                        "logical inner invocation '{invocation_id}' has conflicting durable origin or budget"
                    )));
                }
                shared_invocation = Some((
                    other.invocation.clone(),
                    other.origin_execution_id.clone(),
                ));
            }
            let (proposed, origin_execution_id) =
                shared_invocation.unwrap_or((proposed, execution_id.to_string()));
            let intent = state
                .execution_intents
                .get_mut(execution_id)
                .ok_or_else(|| {
                    M4RuntimeError::Integrity(format!(
                        "execution '{execution_id}' has no durable bridge intent"
                    ))
                })?;
            if !intent
                .expected_inner_invocation_ids
                .iter()
                .any(|expected| expected == &invocation_id)
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "inner invocation '{invocation_id}' is outside execution '{execution_id}'"
                )));
            }
            if let Some(existing) = intent.inner_invocations.get(&invocation_id) {
                if existing.invocation.identity != proposed.identity
                    || existing.invocation.request != proposed.request
                {
                    return Err(M4RuntimeError::Conflict(format!(
                        "inner invocation '{invocation_id}' changed its exact identity or request"
                    )));
                }
                return Ok(existing.invocation.clone());
            }
            intent.inner_invocations.insert(
                invocation_id,
                BridgeInnerInvocationProgress {
                    origin_execution_id,
                    invocation: proposed.clone(),
                    receipt_digest: None,
                    terminal_failure: false,
                },
            );
            Ok(proposed)
        })
        .map_err(capability_store_error)
    }

    fn record_inner_receipt(
        &self,
        execution_id: &str,
        invocation: &CapabilityInvocation,
        receipt: &InvocationReceipt,
    ) -> Result<(), CapabilityServiceFailure> {
        self.transact(|state| {
            let progress = state
                .execution_intents
                .get_mut(execution_id)
                .and_then(|intent| {
                    intent
                        .inner_invocations
                        .get_mut(&invocation.identity.invocation_id)
                })
                .ok_or_else(|| {
                    M4RuntimeError::Integrity(format!(
                        "inner invocation '{}' has no durable progress record",
                        invocation.identity.invocation_id
                    ))
                })?;
            if progress.invocation != *invocation
                || receipt.invocation_id() != invocation.identity.invocation_id
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "inner receipt '{}' changed its durable invocation",
                    receipt.invocation_id()
                )));
            }
            if let Some(existing) = &progress.receipt_digest
                && existing != receipt.receipt_digest()
            {
                return Err(M4RuntimeError::Conflict(format!(
                    "inner invocation '{}' has conflicting receipts",
                    receipt.invocation_id()
                )));
            }
            progress.receipt_digest = Some(receipt.receipt_digest().clone());
            progress.terminal_failure =
                matches!(receipt.outcome(), InvocationOutcome::Terminal { .. });
            Ok(())
        })
        .map_err(capability_store_error)
    }

    fn consume_bridge_crash_fault_after_receipt(
        &self,
        execution_id: &str,
    ) -> Result<(), CapabilityServiceFailure> {
        let durable_invocations = self
            .lock_state()
            .map_err(capability_store_error)?
            .execution_intents
            .get(execution_id)
            .map(|intent| intent.inner_invocations.len() as u32)
            .unwrap_or_default();
        let mut faults = self.crash_faults.lock().map_err(|_| {
            CapabilityServiceFailure::Unavailable(
                "M4 bridge crash-fault state lock is poisoned".to_string(),
            )
        })?;
        if faults
            .get(execution_id)
            .is_some_and(|threshold| durable_invocations >= *threshold)
        {
            faults.remove(execution_id);
            return Err(CapabilityServiceFailure::Unavailable(
                BRIDGE_CRASH_FAULT_DETAIL.to_string(),
            ));
        }
        Ok(())
    }

    fn effect_gate(
        &self,
        invocation_base: &str,
    ) -> Result<Arc<Mutex<()>>, CapabilityServiceFailure> {
        let mut gates = self.effect_gates.lock().map_err(|_| {
            CapabilityServiceFailure::Unavailable(
                "M4 logical-effect gate registry is poisoned".to_string(),
            )
        })?;
        Ok(Arc::clone(
            gates
                .entry(invocation_base.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        ))
    }

    fn invoke_worker(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<CapabilityInvocationReceipt, CapabilityServiceFailure> {
        let (service_request, workflow, invocation_base) = self.validate_worker_request(request)?;
        let effect_gate = self.effect_gate(&invocation_base)?;
        let _effect_guard = effect_gate.lock().map_err(|_| {
            CapabilityServiceFailure::Unavailable(format!(
                "M4 logical-effect gate '{invocation_base}' is poisoned"
            ))
        })?;
        if let Some(receipt) = self.committed_worker_receipt(request)? {
            return Ok(receipt);
        }
        let mut bridge_budget = BridgeCallBudget::new(
            request,
            request.payload.len() as u64,
            role_inner_call_count(request.role),
        )?;
        self.ensure_execution_intent(request, &invocation_base)?;
        let (response, actual, attestations) = self.execute_role(
            &workflow,
            request,
            &service_request.input,
            &invocation_base,
            BridgeInvocationMode::Live,
            &mut bridge_budget,
        )?;
        self.finish_worker_execution(request, response, actual, attestations, &mut bridge_budget)
    }

    fn validate_worker_request(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<
        (
            crate::worker_runtime::WorkerServiceRequest,
            PreparedWorkflow,
            String,
        ),
        CapabilityServiceFailure,
    > {
        let service_request =
            serde_json::from_slice::<crate::worker_runtime::WorkerServiceRequest>(&request.payload)
                .map_err(|error| {
                    CapabilityServiceFailure::Failed(format!("invalid M4 worker request: {error}"))
                })?;
        let expected_worker_id = format!("{}-{}", self.factory_id, request.role.as_str());
        if service_request.schema != REFERENCE_SERVICE_SCHEMA
            || service_request.execution_id != request.execution_id
            || service_request.role != request.role
            || service_request.input.role() != request.role
            || service_request.governance_context_digest != request.governance_context_digest
            || service_request.input_digest
                != governed_work_input_digest(
                    &service_request.governance_context_digest,
                    &service_request.input,
                )
                .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?
            || request.effect_started_at_tick < request.acquired_at_tick
            || request.effect_started_at_tick >= request.deadline.expires_at_tick
            || request.worker_id != expected_worker_id
            || request.service_family != request.role.service_family()
            || request.operation != request.role.operation()
            || request.world != request.role.required_world()
            || request.required_authority != request.role.required_authority()
        {
            return Err(CapabilityServiceFailure::Denied(
                "worker request is outside its exact M4 invocation boundary".to_string(),
            ));
        }
        let workflow = self
            .prepared_workflow_for_scope(&request.workspace_scope)
            .map_err(capability_scope_error)?;
        let expected_spec = workflow
            .specification(self.m3.root(), &self.factory_id)
            .map_err(capability_store_error)?;
        let expected_envelope = expected_spec
            .capability_envelopes
            .get(&request.role)
            .ok_or_else(|| {
                CapabilityServiceFailure::Denied(
                    "prepared workflow lacks the exact role envelope".to_string(),
                )
            })?;
        if &request.capability_envelope != expected_envelope
            || request.governance_context_digest != workflow.governance_context_digest
            || request.resource_scope != workflow.resource_scope
            || request.work_budget != workflow.budget
            || request.deadline != workflow.deadline
        {
            return Err(CapabilityServiceFailure::Denied(
                "worker request changed its prepared governance context, envelope, budget, deadline, or resource scope".to_string(),
            ));
        }
        let logical_effect_digest = digest_json_content(&(
            BRIDGE_WIRE_SCHEMA,
            &self.factory_id,
            &self.scope_id,
            &workflow.workflow_id,
            &workflow.governance_context_digest,
            request.role,
            &service_request.input_digest,
        ))
        .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        let invocation_base = format!(
            "m4-{}-{}",
            request.role.as_str(),
            digest_suffix(&logical_effect_digest)
        );
        Ok((service_request, workflow, invocation_base))
    }

    fn committed_worker_receipt(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<Option<CapabilityInvocationReceipt>, CapabilityServiceFailure> {
        let existing = self
            .lock_state()
            .map_err(capability_store_error)?
            .executions
            .get(&request.execution_id)
            .cloned();
        let Some(existing) = existing else {
            return Ok(None);
        };
        let envelope_digest = digest_json_content(&request.capability_envelope)
            .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))?;
        let budget_digest = digest_json_content(&request.work_budget)
            .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))?;
        let deadline_digest = digest_json_content(&request.deadline)
            .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))?;
        if existing.role != request.role
            || existing.governance_context_digest != request.governance_context_digest
            || existing.worker_payload_digest != ContentDigest::from_bytes(&request.payload)
            || existing.acquired_at_tick != request.acquired_at_tick
            || existing.effect_started_at_tick != request.effect_started_at_tick
            || existing.workspace_scope != request.workspace_scope
            || existing.capability_envelope != request.capability_envelope
            || existing.work_budget != request.work_budget
            || existing.deadline != request.deadline
            || existing.outer_receipt.worker_id != request.worker_id
            || existing.outer_receipt.service_family != request.service_family
            || existing.outer_receipt.operation != request.operation
            || existing.outer_receipt.governance_context_digest != request.governance_context_digest
            || existing.outer_receipt.effect_started_at_tick != request.effect_started_at_tick
            || existing.outer_receipt.capability_envelope_digest != envelope_digest
            || existing.outer_receipt.work_budget_digest != budget_digest
            || existing.outer_receipt.deadline_digest != deadline_digest
        {
            return Err(CapabilityServiceFailure::InvalidReceipt(
                "execution replay changed its exact durable bridge identity".to_string(),
            ));
        }
        existing.outer_receipt.validate_integrity()?;
        Ok(Some(existing.outer_receipt))
    }

    fn finish_worker_execution(
        &self,
        request: &CapabilityInvocationRequest,
        response: crate::worker_runtime::WorkerServiceResponse,
        actual: M4ActualOutput,
        attestations: Vec<ServiceInvocationAttestation>,
        bridge_budget: &mut BridgeCallBudget,
    ) -> Result<CapabilityInvocationReceipt, CapabilityServiceFailure> {
        if attestations.is_empty() || attestations.iter().any(|item| !item.terminal_success) {
            return Err(CapabilityServiceFailure::InvalidReceipt(
                "worker effect lacks successful M3 attestations".to_string(),
            ));
        }
        let output = serde_json::to_vec(&response)
            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        bridge_budget.charge_outer_output(output.len() as u64)?;
        let input_digest = ContentDigest::from_bytes(&request.payload);
        let output_digest = ContentDigest::from_bytes(&output);
        let capability_envelope_digest = digest_json_content(&request.capability_envelope)
            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        let work_budget_digest = digest_json_content(&request.work_budget)
            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        let deadline_digest = digest_json_content(&request.deadline)
            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        let implementation_digest = digest_json_content(&(
            BRIDGE_WIRE_SCHEMA,
            &self.factory_id,
            attestations
                .iter()
                .map(|item| &item.attestation_digest)
                .collect::<Vec<_>>(),
        ))
        .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        let completed_at_tick = self.completion_tick_from_inner_receipts(request, &attestations)?;
        let mut receipt = CapabilityInvocationReceipt {
            receipt_id: String::new(),
            execution_id: request.execution_id.clone(),
            worker_id: request.worker_id.clone(),
            service_family: request.service_family.clone(),
            operation: request.operation.clone(),
            governance_context_digest: request.governance_context_digest.clone(),
            implementation_ref: format!("m3-worker-bridge:{}", self.factory_id),
            implementation_digest,
            input_digest,
            capability_envelope_digest,
            work_budget_digest,
            deadline_digest,
            output,
            output_digest,
            effect_started_at_tick: request.effect_started_at_tick,
            completed_at_tick,
        };
        receipt.receipt_id = receipt.recompute_receipt_id()?;
        receipt.validate_integrity()?;
        self.transact(|state| {
            if let Some(existing) = state.executions.get(&request.execution_id) {
                if existing.outer_receipt == receipt {
                    return Ok(existing.outer_receipt.clone());
                }
                return Err(M4RuntimeError::Conflict(format!(
                    "execution '{}' already has conflicting outer evidence",
                    request.execution_id
                )));
            }
            let intent = state
                .execution_intents
                .get(&request.execution_id)
                .ok_or_else(|| {
                    M4RuntimeError::Integrity(format!(
                        "execution '{}' lost its durable bridge intent",
                        request.execution_id
                    ))
                })?;
            let attestation_ids = attestations
                .iter()
                .map(|attestation| attestation.invocation_id.clone())
                .collect::<Vec<_>>();
            if intent.expected_inner_invocation_ids != attestation_ids
                || intent.inner_invocations.len() != attestation_ids.len()
                || attestations.iter().any(|attestation| {
                    intent
                        .inner_invocations
                        .get(&attestation.invocation_id)
                        .and_then(|progress| progress.receipt_digest.as_ref())
                        != Some(&attestation.receipt_digest)
                })
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "execution '{}' cannot commit before all exact inner receipts",
                    request.execution_id
                )));
            }
            state.executions.insert(
                request.execution_id.clone(),
                PendingExecutionEvidence {
                    role: request.role,
                    governance_context_digest: request.governance_context_digest.clone(),
                    worker_payload_digest: ContentDigest::from_bytes(&request.payload),
                    acquired_at_tick: request.acquired_at_tick,
                    effect_started_at_tick: request.effect_started_at_tick,
                    workspace_scope: request.workspace_scope.clone(),
                    capability_envelope: request.capability_envelope.clone(),
                    work_budget: request.work_budget.clone(),
                    deadline: request.deadline.clone(),
                    actual,
                    service_attestations: attestations,
                    outer_receipt: receipt.clone(),
                },
            );
            Ok(receipt.clone())
        })
        .map_err(capability_store_error)
    }

    fn completion_tick_from_inner_receipts(
        &self,
        request: &CapabilityInvocationRequest,
        attestations: &[ServiceInvocationAttestation],
    ) -> Result<u64, CapabilityServiceFailure> {
        if attestations.is_empty() {
            return Err(CapabilityServiceFailure::InvalidReceipt(
                "worker completion has no inner receipt interval".to_string(),
            ));
        }
        let mut active_duration_ms = 0_u64;
        for attestation in attestations {
            let receipt = self
                .m3
                .receipt(&attestation.invocation_id)
                .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))?;
            if receipt.started_at_ms() > receipt.finished_at_ms() {
                return Err(CapabilityServiceFailure::InvalidReceipt(format!(
                    "inner receipt '{}' has an inverted time interval",
                    receipt.invocation_id()
                )));
            }
            let duration_ms = receipt.finished_at_ms() - receipt.started_at_ms();
            active_duration_ms = active_duration_ms.saturating_add(duration_ms);
        }
        let active_ticks = active_duration_ms
            .saturating_add(99)
            .checked_div(100)
            .unwrap_or(0);
        let completed_at_tick = request.effect_started_at_tick.saturating_add(active_ticks);
        if completed_at_tick >= request.deadline.expires_at_tick
            || completed_at_tick
                > request
                    .acquired_at_tick
                    .saturating_add(request.work_budget.max_runtime_ticks)
        {
            return Err(CapabilityServiceFailure::TimedOut(
                "inner M3 evidence completed outside the durable worker interval".to_string(),
            ));
        }
        Ok(completed_at_tick)
    }

    fn recover_worker(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<Option<CapabilityInvocationReceipt>, CapabilityServiceFailure> {
        self.validate_persisted_evidence()
            .map_err(capability_store_error)?;
        let persisted_effect_started_at_tick = {
            let state = self.lock_state().map_err(capability_store_error)?;
            state
                .executions
                .get(&request.execution_id)
                .map(|pending| pending.effect_started_at_tick)
                .or_else(|| {
                    state
                        .execution_intents
                        .get(&request.execution_id)
                        .map(|intent| intent.effect_started_at_tick)
                })
        };
        let Some(persisted_effect_started_at_tick) = persisted_effect_started_at_tick else {
            self.validate_worker_request(request)?;
            return Ok(None);
        };
        if request.effect_started_at_tick != request.acquired_at_tick
            && request.effect_started_at_tick != persisted_effect_started_at_tick
        {
            return Err(CapabilityServiceFailure::InvalidReceipt(
                "recovery caller changed the effect-start identity".to_string(),
            ));
        }
        let mut exact_request = request.clone();
        exact_request.effect_started_at_tick = persisted_effect_started_at_tick;
        let (service_request, workflow, invocation_base) =
            self.validate_worker_request(&exact_request)?;
        if let Some(receipt) = self.committed_worker_receipt(&exact_request)? {
            return Ok(Some(receipt));
        }
        let intent = self
            .lock_state()
            .map_err(capability_store_error)?
            .execution_intents
            .get(&exact_request.execution_id)
            .cloned();
        let Some(intent) = intent else {
            return Ok(None);
        };
        let request_digest = digest_json_content(&exact_request)
            .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))?;
        if intent.request_digest != request_digest
            || intent.invocation_base != invocation_base
            || intent.role != exact_request.role
            || intent.worker_payload_digest != ContentDigest::from_bytes(&exact_request.payload)
        {
            return Err(CapabilityServiceFailure::InvalidReceipt(
                "recovery request changed its durable bridge intent".to_string(),
            ));
        }
        if !self.recovery_receipts_are_complete(&exact_request.execution_id, &intent)? {
            return Ok(None);
        }
        let mut bridge_budget = BridgeCallBudget::for_recovery(
            &exact_request,
            exact_request.payload.len() as u64,
            role_inner_call_count(exact_request.role),
        )?;
        let (response, actual, attestations) = self.execute_role(
            &workflow,
            &exact_request,
            &service_request.input,
            &invocation_base,
            BridgeInvocationMode::RecoveryOnly,
            &mut bridge_budget,
        )?;
        self.finish_worker_execution(
            &exact_request,
            response,
            actual,
            attestations,
            &mut bridge_budget,
        )
        .map(Some)
    }

    fn recovery_receipts_are_complete(
        &self,
        execution_id: &str,
        intent: &BridgeExecutionIntent,
    ) -> Result<bool, CapabilityServiceFailure> {
        for invocation_id in &intent.expected_inner_invocation_ids {
            let Some(progress) = intent.inner_invocations.get(invocation_id) else {
                return Ok(false);
            };
            let receipt = match self.m3.receipt(invocation_id) {
                Ok(receipt) => receipt,
                Err(M3RuntimeError::Capability(CapabilityHostError::ReceiptNotFound {
                    ..
                })) => return Ok(false),
                Err(error) => {
                    return Err(CapabilityServiceFailure::InvalidReceipt(error.to_string()));
                }
            };
            let attestation =
                self.validate_native_receipt_evidence(&progress.invocation, &receipt)?;
            self.record_inner_receipt(execution_id, &progress.invocation, &receipt)?;
            if !matches!(receipt.outcome(), InvocationOutcome::Succeeded { .. })
                || !attestation.terminal_success
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn execute_role(
        &self,
        workflow: &PreparedWorkflow,
        request: &CapabilityInvocationRequest,
        input: &WorkInput,
        invocation_base: &str,
        mode: BridgeInvocationMode,
        budget: &mut BridgeCallBudget,
    ) -> Result<
        (
            crate::worker_runtime::WorkerServiceResponse,
            M4ActualOutput,
            Vec<ServiceInvocationAttestation>,
        ),
        CapabilityServiceFailure,
    > {
        let mut attestations = Vec::new();
        match input {
            WorkInput::Plan {
                objective,
                baseline_digest,
            } => {
                if objective != &workflow.objective || baseline_digest != &workflow.baseline_digest
                {
                    return Err(CapabilityServiceFailure::Denied(
                        "planner input differs from prepared workflow".to_string(),
                    ));
                }
                let resolved = match self.invoke_native_for_worker(
                    &request.execution_id,
                    mode,
                    budget,
                    &format!("{invocation_base}-resolve"),
                    CONTINUITY_RESOLVE_SERVICE_ID,
                    AuthorityClass::Observe,
                    CapabilityRequest::ResolveEvidence(ResolveEvidenceRequest {
                        scope_id: self.scope_id.clone(),
                        evidence_id: workflow.planner_evidence_id.clone(),
                        expected_digest: workflow.planner_evidence_digest.clone(),
                    }),
                )? {
                    (CapabilitySuccess::EvidenceResolved(resolved), attestation) => {
                        attestations.push(attestation);
                        *resolved
                    }
                    _ => return Err(wrong_native_type("planner context resolution")),
                };
                if resolved.record.content_digest != workflow.planner_evidence_digest {
                    return Err(CapabilityServiceFailure::InvalidReceipt(
                        "resolved planner context has the wrong content digest".to_string(),
                    ));
                }
                let plan_digest = digest_json_content(&(
                    BRIDGE_WIRE_SCHEMA,
                    &workflow.governance_context_digest,
                    objective,
                    baseline_digest,
                    &resolved.record.record_digest,
                    &workflow.anchor.schedule_binding_digest,
                ))
                .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
                Ok((
                    crate::worker_runtime::WorkerServiceResponse::Plan {
                        baseline_digest: baseline_digest.clone(),
                        plan_digest: plan_digest.clone(),
                    },
                    M4ActualOutput::Planner {
                        workspace_tree_digest: workflow.baseline_digest.clone(),
                        schedule_binding_digest: workflow.anchor.schedule_binding_digest.clone(),
                        plan_digest,
                    },
                    attestations,
                ))
            }
            WorkInput::Build {
                plan_result_digest,
                target_relative_path,
                expected_before_digest,
                replacement_bytes,
            } => {
                if target_relative_path != Path::new(COMPONENT_WAT_PATH)
                    || expected_before_digest != &workflow.expected_before_digest
                    || ContentDigest::from_bytes(replacement_bytes)
                        != workflow.replacement_wat_digest
                {
                    return Err(CapabilityServiceFailure::Denied(
                        "builder input exceeds the prepared candidate patch".to_string(),
                    ));
                }
                let patchset = match self.invoke_native_for_worker(
                    &request.execution_id,
                    mode,
                    budget,
                    &format!("{invocation_base}-patch"),
                    BUILD_SERVICE_ID,
                    AuthorityClass::LocalMutate,
                    CapabilityRequest::PatchWorkspace(PatchWorkspaceRequest {
                        workspace: self.workspace(&workflow.candidate_workspace_id),
                        expected_before_digest: expected_before_digest.clone(),
                        replacement_bytes: replacement_bytes.clone(),
                    }),
                )? {
                    (CapabilitySuccess::Patchset(patchset), attestation) => {
                        attestations.push(attestation);
                        *patchset
                    }
                    _ => return Err(wrong_native_type("workspace patch")),
                };
                let build = match self.invoke_native_for_worker(
                    &request.execution_id,
                    mode,
                    budget,
                    &format!("{invocation_base}-build"),
                    BUILD_SERVICE_ID,
                    AuthorityClass::LocalMutate,
                    CapabilityRequest::BuildCandidate(BuildCandidateRequest {
                        workspace: self.workspace(&workflow.candidate_workspace_id),
                    }),
                )? {
                    (CapabilitySuccess::Build(build), attestation) => {
                        attestations.push(attestation);
                        *build
                    }
                    _ => return Err(wrong_native_type("candidate build")),
                };
                let package = match self.invoke_native_for_worker(
                    &request.execution_id,
                    mode,
                    budget,
                    &format!("{invocation_base}-publish"),
                    PACKAGING_SERVICE_ID,
                    AuthorityClass::LocalMutate,
                    CapabilityRequest::PublishPackage(PublishPackageRequest {
                        workspace: self.workspace(&workflow.candidate_workspace_id),
                        expected_package_digest: build.package_digest.clone(),
                    }),
                )? {
                    (CapabilitySuccess::Package(package), attestation) => {
                        attestations.push(attestation);
                        *package
                    }
                    _ => return Err(wrong_native_type("candidate package")),
                };
                let before = patchset
                    .changes
                    .iter()
                    .find(|change| change.relative_path == COMPONENT_WAT_PATH)
                    .ok_or_else(|| {
                        CapabilityServiceFailure::InvalidReceipt(
                            "patchset lacks the exact WAT replacement".to_string(),
                        )
                    })?
                    .before_digest
                    .clone();
                Ok((
                    crate::worker_runtime::WorkerServiceResponse::Build {
                        plan_result_digest: plan_result_digest.clone(),
                        before_digest: before.clone(),
                        artifact_digest: workflow.replacement_wat_digest.clone(),
                    },
                    M4ActualOutput::Builder {
                        before_digest: before,
                        candidate_wat_digest: workflow.replacement_wat_digest.clone(),
                        source_tree_digest: package.source_tree_digest,
                        package_digest: package.package_digest,
                        package_record_digest: package.package_record_digest,
                    },
                    attestations,
                ))
            }
            WorkInput::Validate {
                plan_result_digest,
                build_result_digest,
                target_relative_path,
                expected_artifact_digest,
                suite_digest,
            } => {
                if target_relative_path != Path::new(COMPONENT_WAT_PATH)
                    || suite_digest
                        != &workflow
                            .validation_suite
                            .suite_digest()
                            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?
                {
                    return Err(CapabilityServiceFailure::Denied(
                        "validator input differs from the prepared proof scope".to_string(),
                    ));
                }
                let build =
                    self.resolve_actual(build_result_digest, GovernedWorkerRole::Builder)?;
                let (candidate_wat_digest, package_digest) = match build {
                    M4ActualOutput::Builder {
                        candidate_wat_digest,
                        package_digest,
                        ..
                    } => (candidate_wat_digest, package_digest),
                    _ => return Err(mismatched_result("builder")),
                };
                if &candidate_wat_digest != expected_artifact_digest {
                    return Err(mismatched_result("builder artifact"));
                }
                let proving = match self.invoke_native_for_worker(
                    &request.execution_id,
                    mode,
                    budget,
                    &format!("{invocation_base}-prove"),
                    VALIDATION_SERVICE_ID,
                    AuthorityClass::Observe,
                    CapabilityRequest::ProvePackage(ProvePackageRequest {
                        scope_id: self.scope_id.clone(),
                        package_digest: package_digest.clone(),
                        suite: workflow.validation_suite.clone(),
                    }),
                )? {
                    (CapabilitySuccess::Proving(proving), attestation) => {
                        attestations.push(attestation);
                        *proving
                    }
                    _ => return Err(wrong_native_type("candidate proving")),
                };
                let passed = proving.summary.all_satisfied;
                Ok((
                    crate::worker_runtime::WorkerServiceResponse::Validate {
                        plan_result_digest: plan_result_digest.clone(),
                        build_result_digest: build_result_digest.clone(),
                        artifact_digest: candidate_wat_digest.clone(),
                        proving_digest: proving.record_digest.clone(),
                        passed,
                    },
                    M4ActualOutput::Validator {
                        candidate_wat_digest,
                        package_digest,
                        proving_digest: proving.record_digest,
                        passed,
                    },
                    attestations,
                ))
            }
            WorkInput::Review {
                build_result_digest,
                validation_result_digest,
                ..
            } => {
                let validation =
                    self.resolve_actual(validation_result_digest, GovernedWorkerRole::Validator)?;
                let challenger_proving = match validation {
                    M4ActualOutput::Validator {
                        proving_digest,
                        passed: true,
                        ..
                    } => proving_digest,
                    _ => return Err(mismatched_result("passing validator")),
                };
                self.resolve_actual(build_result_digest, GovernedWorkerRole::Builder)?;
                let comparison = match self.invoke_native_for_worker(
                    &request.execution_id,
                    mode,
                    budget,
                    &format!("{invocation_base}-compare"),
                    VALIDATION_SERVICE_ID,
                    AuthorityClass::Observe,
                    CapabilityRequest::CompareProving(CompareProvingRequest {
                        scope_id: self.scope_id.clone(),
                        suite: workflow.validation_suite.clone(),
                        incumbent_proving_digest: workflow.incumbent_proving_digest.clone(),
                        challenger_proving_digest: challenger_proving,
                    }),
                )? {
                    (CapabilitySuccess::Comparison(comparison), attestation) => {
                        attestations.push(attestation);
                        *comparison
                    }
                    _ => return Err(wrong_native_type("proving comparison")),
                };
                let review = match self.invoke_native_for_worker(
                    &request.execution_id,
                    mode,
                    budget,
                    &format!("{invocation_base}-review"),
                    REVIEW_SERVICE_ID,
                    AuthorityClass::Observe,
                    CapabilityRequest::ReviewCandidate(
                        crate::capability_services::ReviewCandidateRequest {
                            scope_id: self.scope_id.clone(),
                            suite: workflow.validation_suite.clone(),
                            comparison_digest: comparison.record_digest.clone(),
                        },
                    ),
                )? {
                    (CapabilitySuccess::Review(review), attestation) => {
                        attestations.push(attestation);
                        *review
                    }
                    _ => return Err(wrong_native_type("candidate review")),
                };
                let approved = matches!(
                    review.decision,
                    crate::capability_services::ReviewDecision::Approved
                );
                Ok((
                    crate::worker_runtime::WorkerServiceResponse::Review {
                        build_result_digest: build_result_digest.clone(),
                        validation_result_digest: validation_result_digest.clone(),
                        decision: if approved {
                            ReviewDecision::Approve
                        } else {
                            ReviewDecision::Reject
                        },
                        review_digest: review.review_digest.clone(),
                    },
                    M4ActualOutput::Reviewer {
                        comparison_digest: comparison.record_digest,
                        review_digest: review.review_digest,
                        approved,
                    },
                    attestations,
                ))
            }
            WorkInput::Package {
                build_result_digest,
                validation_result_digest,
                review_result_digest,
            } => {
                let build =
                    self.resolve_actual(build_result_digest, GovernedWorkerRole::Builder)?;
                let package_digest = match build {
                    M4ActualOutput::Builder { package_digest, .. } => package_digest,
                    _ => return Err(mismatched_result("builder")),
                };
                self.resolve_actual(validation_result_digest, GovernedWorkerRole::Validator)?;
                let review =
                    self.resolve_actual(review_result_digest, GovernedWorkerRole::Reviewer)?;
                if !matches!(review, M4ActualOutput::Reviewer { approved: true, .. }) {
                    return Err(mismatched_result("approving reviewer"));
                }
                let verification = match self.invoke_native_for_worker(
                    &request.execution_id,
                    mode,
                    budget,
                    &format!("{invocation_base}-verify"),
                    PACKAGING_SERVICE_ID,
                    AuthorityClass::LocalMutate,
                    CapabilityRequest::VerifyPackage(VerifyPackageRequest {
                        scope_id: self.scope_id.clone(),
                        package_digest: package_digest.clone(),
                    }),
                )? {
                    (CapabilitySuccess::PackageVerification(verification), attestation) => {
                        attestations.push(attestation);
                        *verification
                    }
                    _ => return Err(wrong_native_type("package verification")),
                };
                if !verification.runnable_component || verification.package_digest != package_digest
                {
                    return Err(CapabilityServiceFailure::InvalidReceipt(
                        "package verification did not prove the cited component".to_string(),
                    ));
                }
                Ok((
                    crate::worker_runtime::WorkerServiceResponse::Package {
                        build_result_digest: build_result_digest.clone(),
                        validation_result_digest: validation_result_digest.clone(),
                        review_result_digest: review_result_digest.clone(),
                        package_digest: package_digest.clone(),
                    },
                    M4ActualOutput::Packager {
                        package_digest,
                        verification_digest: verification.verification_digest,
                    },
                    attestations,
                ))
            }
            WorkInput::Continue {
                package_result_digest,
                synthesis_seed_digest,
            } => {
                let package =
                    self.resolve_actual(package_result_digest, GovernedWorkerRole::Packager)?;
                let package_digest = match package {
                    M4ActualOutput::Packager { package_digest, .. } => package_digest,
                    _ => return Err(mismatched_result("packager")),
                };
                let payload = serde_json::to_vec(&(
                    BRIDGE_WIRE_SCHEMA,
                    &workflow.workflow_id,
                    &workflow.governance_context_digest,
                    package_result_digest,
                    synthesis_seed_digest,
                    &package_digest,
                ))
                .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
                let evidence_id =
                    format!("m4-{}", digest_suffix(&ContentDigest::from_bytes(&payload)));
                let evidence = match self.invoke_native_for_worker(
                    &request.execution_id,
                    mode,
                    budget,
                    &format!("{invocation_base}-publish"),
                    CONTINUITY_SERVICE_ID,
                    AuthorityClass::LocalMutate,
                    CapabilityRequest::PublishEvidence(PublishEvidenceRequest {
                        scope_id: self.scope_id.clone(),
                        evidence_id: evidence_id.clone(),
                        media_type: "application/json".to_string(),
                        subject_refs: vec![
                            format!("governance:{}", workflow.governance_context_digest),
                            format!("worker-result:{package_result_digest}"),
                            format!("package:{package_digest}"),
                        ],
                        expected_digest: Some(ContentDigest::from_bytes(&payload)),
                        payload,
                    }),
                )? {
                    (CapabilitySuccess::EvidencePublished(evidence), attestation) => {
                        attestations.push(attestation);
                        *evidence
                    }
                    _ => return Err(wrong_native_type("continuity evidence")),
                };
                Ok((
                    crate::worker_runtime::WorkerServiceResponse::Continue {
                        package_result_digest: package_result_digest.clone(),
                        checkpoint_digest: evidence.record_digest.clone(),
                    },
                    M4ActualOutput::ContinuityWorker {
                        evidence_id,
                        content_digest: evidence.content_digest,
                        record_digest: evidence.record_digest,
                    },
                    attestations,
                ))
            }
        }
    }

    fn resolve_actual(
        &self,
        result_digest: &ContentDigest,
        role: GovernedWorkerRole,
    ) -> Result<M4ActualOutput, CapabilityServiceFailure> {
        let state = self.lock_state().map_err(capability_store_error)?;
        let execution_id = state
            .result_aliases
            .get(result_digest.as_str())
            .ok_or_else(|| {
                CapabilityServiceFailure::Denied(format!(
                    "worker cited unknown result '{result_digest}'"
                ))
            })?;
        let evidence = state.executions.get(execution_id).ok_or_else(|| {
            CapabilityServiceFailure::InvalidReceipt(
                "worker result alias points to missing M3 evidence".to_string(),
            )
        })?;
        if evidence.role != role {
            return Err(mismatched_result(role.as_str()));
        }
        Ok(evidence.actual.clone())
    }

    fn workspace(&self, workspace_id: &str) -> ScopedWorkspaceRef {
        ScopedWorkspaceRef {
            scope_id: self.scope_id.clone(),
            workspace_id: workspace_id.to_string(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn invoke_native_for_worker(
        &self,
        execution_id: &str,
        mode: BridgeInvocationMode,
        budget: &mut BridgeCallBudget,
        invocation_id: &str,
        service_id: &str,
        authority: AuthorityClass,
        request: CapabilityRequest,
    ) -> Result<(CapabilitySuccess, ServiceInvocationAttestation), CapabilityServiceFailure> {
        let timeout_ms = budget.begin_call(&request)?;
        let proposed = CapabilityInvocation {
            identity: InvocationIdentity {
                invocation_id: invocation_id.to_string(),
                idempotency_key: format!("idempotency:{invocation_id}"),
                service_id: service_id.to_string(),
                scope_id: self.scope_id.clone(),
                caller_id: format!("m4-bridge:{}", self.factory_id),
                authority,
                approval: InvocationApproval::Automatic,
            },
            budget: InvocationBudget::bounded(timeout_ms.max(1)),
            request,
        };
        let (invocation, replaying_terminal_receipt) = match mode {
            BridgeInvocationMode::Live => {
                let (exact, replaying_terminal_receipt) = match self
                    .m3
                    .invocation_input(invocation_id)
                {
                    Ok(existing) => {
                        if existing.identity != proposed.identity
                            || existing.request != proposed.request
                        {
                            return Err(CapabilityServiceFailure::InvalidReceipt(format!(
                                "logical inner invocation '{invocation_id}' resolves to different durable work"
                            )));
                        }
                        (existing, true)
                    }
                    Err(M3RuntimeError::Capability(CapabilityHostError::ReceiptNotFound {
                        ..
                    })) => (proposed, false),
                    Err(error) => {
                        return Err(CapabilityServiceFailure::InvalidReceipt(error.to_string()));
                    }
                };
                (
                    self.persist_inner_invocation(execution_id, exact)?,
                    replaying_terminal_receipt,
                )
            }
            BridgeInvocationMode::RecoveryOnly | BridgeInvocationMode::ValidationOnly => {
                let state = self.lock_state().map_err(capability_store_error)?;
                let exact = state
                    .execution_intents
                    .get(execution_id)
                    .and_then(|intent| intent.inner_invocations.get(invocation_id))
                    .map(|progress| progress.invocation.clone())
                    .ok_or_else(|| {
                        CapabilityServiceFailure::InvalidReceipt(format!(
                            "recovery cannot start missing inner invocation '{invocation_id}'"
                        ))
                    })?;
                if exact.identity != proposed.identity || exact.request != proposed.request {
                    return Err(CapabilityServiceFailure::InvalidReceipt(format!(
                        "recovery changed inner invocation '{invocation_id}'"
                    )));
                }
                (exact, true)
            }
        };
        if mode == BridgeInvocationMode::Live
            && !replaying_terminal_receipt
            && invocation.budget.timeout_ms > timeout_ms
        {
            return Err(CapabilityServiceFailure::TimedOut(format!(
                "armed inner invocation '{invocation_id}' no longer fits the live effect window"
            )));
        }
        let receipt = match mode {
            BridgeInvocationMode::Live => self
                .m3
                .invoke(&invocation, ServiceCancellationToken::new())
                .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?,
            BridgeInvocationMode::RecoveryOnly | BridgeInvocationMode::ValidationOnly => self
                .m3
                .receipt(invocation_id)
                .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))?,
        };
        let attestation = self.validate_native_receipt_evidence(&invocation, &receipt)?;
        if mode == BridgeInvocationMode::Live {
            self.consume_bridge_crash_fault_after_receipt(execution_id)?;
        }
        if mode != BridgeInvocationMode::ValidationOnly {
            self.record_inner_receipt(execution_id, &invocation, &receipt)?;
        }
        let result = match receipt.outcome().clone() {
            InvocationOutcome::Succeeded { result } if attestation.terminal_success => {
                (result, attestation)
            }
            InvocationOutcome::Succeeded { .. } => {
                return Err(CapabilityServiceFailure::InvalidReceipt(format!(
                    "successful inner receipt '{}' has a non-success attestation",
                    receipt.invocation_id()
                )));
            }
            InvocationOutcome::Terminal { failure } => {
                return Err(CapabilityServiceFailure::Failed(failure.to_string()));
            }
        };
        budget.finish_call(&result)?;
        Ok(result)
    }

    fn validate_native_receipt_evidence(
        &self,
        invocation: &CapabilityInvocation,
        receipt: &InvocationReceipt,
    ) -> Result<ServiceInvocationAttestation, CapabilityServiceFailure> {
        receipt.verify_integrity().map_err(|error| {
            CapabilityServiceFailure::InvalidReceipt(format!(
                "M3 receipt failed integrity: {error}"
            ))
        })?;
        let persisted = self
            .m3
            .invocation_input(receipt.invocation_id())
            .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))?;
        if persisted != *invocation
            || receipt.invocation_id() != invocation.identity.invocation_id
            || receipt.service_id() != invocation.identity.service_id
            || receipt.scope_id() != self.scope_id
            || receipt.operation() != invocation.request.operation()
            || receipt.family() != invocation.request.operation().family()
        {
            return Err(CapabilityServiceFailure::InvalidReceipt(format!(
                "inner receipt '{}' does not bind its exact durable invocation",
                receipt.invocation_id()
            )));
        }
        let attestation = self
            .m3
            .attestation(receipt.invocation_id())
            .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))?;
        if attestation.invocation_id != invocation.identity.invocation_id
            || attestation.service_id != invocation.identity.service_id
            || attestation.family != receipt.family()
            || attestation.operation != receipt.operation()
            || attestation.scope_id != self.scope_id
            || attestation.receipt_digest != *receipt.receipt_digest()
            || attestation.input_digest != *receipt.input_digest()
            || attestation.output_digest != *receipt.output_digest()
            || attestation.provenance != *receipt.provenance()
        {
            return Err(CapabilityServiceFailure::InvalidReceipt(format!(
                "inner receipt '{}' lacks an exact canonical attestation",
                receipt.invocation_id()
            )));
        }
        Ok(attestation)
    }

    fn invoke_native(
        &self,
        invocation_id: &str,
        service_id: &str,
        authority: AuthorityClass,
        approval: InvocationApproval,
        request: CapabilityRequest,
    ) -> Result<(CapabilitySuccess, ServiceInvocationAttestation), M4RuntimeError> {
        self.invoke_native_with_timeout(
            invocation_id,
            service_id,
            authority,
            approval,
            request,
            30_000,
        )
    }

    fn invoke_native_with_timeout(
        &self,
        invocation_id: &str,
        service_id: &str,
        authority: AuthorityClass,
        approval: InvocationApproval,
        request: CapabilityRequest,
        timeout_ms: u64,
    ) -> Result<(CapabilitySuccess, ServiceInvocationAttestation), M4RuntimeError> {
        let invocation = CapabilityInvocation {
            identity: InvocationIdentity {
                invocation_id: invocation_id.to_string(),
                idempotency_key: format!("idempotency:{invocation_id}"),
                service_id: service_id.to_string(),
                scope_id: self.scope_id.clone(),
                caller_id: format!("m4-bridge:{}", self.factory_id),
                authority,
                approval,
            },
            budget: InvocationBudget::bounded(timeout_ms.max(1)),
            request,
        };
        let receipt = self
            .m3
            .invoke(&invocation, ServiceCancellationToken::new())?;
        receipt.verify_integrity().map_err(|error| {
            M4RuntimeError::Integrity(format!("M3 receipt failed integrity: {error}"))
        })?;
        let result = match receipt.outcome().clone() {
            InvocationOutcome::Succeeded { result } => result,
            InvocationOutcome::Terminal { failure } => {
                return Err(M4RuntimeError::CapabilityFailure(failure.to_string()));
            }
        };
        let attestation = self.m3.attestation(receipt.invocation_id())?;
        if !attestation.terminal_success
            || attestation.receipt_digest != *receipt.receipt_digest()
            || attestation.service_id != service_id
            || attestation.scope_id != self.scope_id
        {
            return Err(M4RuntimeError::Integrity(
                "M3 attestation does not bind the successful receipt".to_string(),
            ));
        }
        Ok((result, attestation))
    }

    fn validate_persisted_evidence(&self) -> Result<(), M4RuntimeError> {
        let state = self.lock_state()?.clone();
        for workflow in state.workflows.values() {
            if workflow.request_digest != prepared_workflow_request_digest(workflow)? {
                return Err(M4RuntimeError::Integrity(format!(
                    "prepared workflow '{}' changed its immutable governance-bound inputs",
                    workflow.workflow_id
                )));
            }
            self.validate_lifecycle_anchor(&workflow.anchor)?;
        }
        for (execution_id, intent) in &state.execution_intents {
            let workflow = self.prepared_workflow_for_scope(&intent.workspace_scope)?;
            let (_, validated_workflow, invocation_base) = self
                .validate_worker_request(&intent.request)
                .map_err(|error| M4RuntimeError::Integrity(error.to_string()))?;
            let expected_spec = workflow.specification(self.m3.root(), &self.factory_id)?;
            let expected_envelope = expected_spec
                .capability_envelopes
                .get(&intent.role)
                .ok_or_else(|| {
                    M4RuntimeError::Integrity(
                        "persisted workflow lacks its bridge-intent role envelope".to_string(),
                    )
                })?;
            if validated_workflow.workflow_id != workflow.workflow_id
                || intent.governance_context_digest != workflow.governance_context_digest
                || intent.governance_context_digest != intent.request.governance_context_digest
                || invocation_base != intent.invocation_base
                || &intent.capability_envelope != expected_envelope
                || intent.work_budget != workflow.budget
                || intent.deadline != workflow.deadline
                || intent
                    .workspace_scope
                    .resource_scopes
                    .first()
                    .is_none_or(|scope| scope != &workflow.resource_scope)
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "M4 bridge intent '{execution_id}' changed its prepared workflow boundary"
                )));
            }
            for (invocation_id, progress) in &intent.inner_invocations {
                if progress.invocation.identity.scope_id != self.scope_id
                    || progress.invocation.identity.caller_id
                        != format!("m4-bridge:{}", self.factory_id)
                    || progress.invocation.request.scope_id() != self.scope_id
                {
                    return Err(M4RuntimeError::Integrity(format!(
                        "M4 bridge intent '{execution_id}' changed inner invocation authority"
                    )));
                }
                match self.m3.receipt(invocation_id) {
                    Ok(receipt) => {
                        self.validate_native_receipt_evidence(&progress.invocation, &receipt)
                            .map_err(|error| M4RuntimeError::Integrity(error.to_string()))?;
                        if progress
                            .receipt_digest
                            .as_ref()
                            .is_some_and(|digest| digest != receipt.receipt_digest())
                            || progress.receipt_digest.is_some()
                                && progress.terminal_failure
                                    != matches!(
                                        receipt.outcome(),
                                        InvocationOutcome::Terminal { .. }
                                    )
                        {
                            return Err(M4RuntimeError::Integrity(format!(
                                "M4 bridge intent '{execution_id}' changed an inner receipt"
                            )));
                        }
                    }
                    Err(M3RuntimeError::Capability(CapabilityHostError::ReceiptNotFound {
                        ..
                    })) if progress.receipt_digest.is_none() => {}
                    Err(M3RuntimeError::Capability(CapabilityHostError::ReceiptNotFound {
                        ..
                    })) => {
                        return Err(M4RuntimeError::Integrity(format!(
                            "M4 bridge intent '{execution_id}' cites a missing inner receipt"
                        )));
                    }
                    Err(error) => return Err(M4RuntimeError::M3(error)),
                }
            }
        }
        for (execution_id, pending) in &state.executions {
            pending
                .outer_receipt
                .validate_integrity()
                .map_err(|error| M4RuntimeError::Integrity(error.to_string()))?;
            let response = serde_json::from_slice::<crate::worker_runtime::WorkerServiceResponse>(
                &pending.outer_receipt.output,
            )
            .map_err(|error| {
                M4RuntimeError::Integrity(format!(
                    "M4 bridge execution '{execution_id}' has invalid output: {error}"
                ))
            })?;
            let output: WorkOutput = response.into();
            let workflow = self.prepared_workflow_for_scope(&pending.workspace_scope)?;
            let expected_spec = workflow.specification(self.m3.root(), &self.factory_id)?;
            let expected_envelope = expected_spec
                .capability_envelopes
                .get(&pending.role)
                .ok_or_else(|| {
                    M4RuntimeError::Integrity(
                        "persisted workflow lacks its role envelope".to_string(),
                    )
                })?;
            let envelope_digest = digest_json_content(&pending.capability_envelope)
                .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
            let budget_digest = digest_json_content(&pending.work_budget)
                .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
            let deadline_digest = digest_json_content(&pending.deadline)
                .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
            if pending.role != pending.actual.role()
                || pending.governance_context_digest != workflow.governance_context_digest
                || pending.outer_receipt.governance_context_digest
                    != pending.governance_context_digest
                || pending.outer_receipt.execution_id != *execution_id
                || pending.outer_receipt.worker_id
                    != format!("{}-{}", self.factory_id, pending.role.as_str())
                || pending.outer_receipt.input_digest != pending.worker_payload_digest
                || pending.acquired_at_tick < pending.deadline.not_before_tick
                || pending.effect_started_at_tick < pending.acquired_at_tick
                || pending.effect_started_at_tick >= pending.deadline.expires_at_tick
                || pending.outer_receipt.effect_started_at_tick != pending.effect_started_at_tick
                || pending.outer_receipt.completed_at_tick < pending.effect_started_at_tick
                || pending.outer_receipt.completed_at_tick >= pending.deadline.expires_at_tick
                || pending.outer_receipt.completed_at_tick
                    > pending
                        .acquired_at_tick
                        .saturating_add(pending.work_budget.max_runtime_ticks)
                || &pending.capability_envelope != expected_envelope
                || pending.work_budget != workflow.budget
                || pending.deadline != workflow.deadline
                || pending.outer_receipt.capability_envelope_digest != envelope_digest
                || pending.outer_receipt.work_budget_digest != budget_digest
                || pending.outer_receipt.deadline_digest != deadline_digest
                || !actual_matches_output(&pending.actual, &output)
                || pending.service_attestations.is_empty()
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "M4 bridge execution '{execution_id}' is not internally cross-linked"
                )));
            }
            for attestation in &pending.service_attestations {
                let canonical = self.m3.attestation(&attestation.invocation_id)?;
                if &canonical != attestation || !attestation.terminal_success {
                    return Err(M4RuntimeError::Integrity(format!(
                        "M4 bridge execution '{execution_id}' contains altered M3 evidence"
                    )));
                }
            }
            let intent = state.execution_intents.get(execution_id).ok_or_else(|| {
                M4RuntimeError::Integrity(format!(
                    "M4 bridge execution '{execution_id}' lost its inner invocation plan"
                ))
            })?;
            let (service_request, derived_workflow, invocation_base) = self
                .validate_worker_request(&intent.request)
                .map_err(|error| M4RuntimeError::Integrity(error.to_string()))?;
            if invocation_base != intent.invocation_base
                || pending.governance_context_digest != intent.governance_context_digest
                || service_request.governance_context_digest != pending.governance_context_digest
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "M4 bridge execution '{execution_id}' changed its logical invocation identity"
                )));
            }
            let mut validation_budget = BridgeCallBudget::for_recovery(
                &intent.request,
                intent.request.payload.len() as u64,
                role_inner_call_count(intent.role),
            )
            .map_err(|error| M4RuntimeError::Integrity(error.to_string()))?;
            let (derived_response, derived_actual, derived_attestations) = self
                .execute_role(
                    &derived_workflow,
                    &intent.request,
                    &service_request.input,
                    &intent.invocation_base,
                    BridgeInvocationMode::ValidationOnly,
                    &mut validation_budget,
                )
                .map_err(|error| M4RuntimeError::Integrity(error.to_string()))?;
            let derived_output = serde_json::to_vec(&derived_response)?;
            validation_budget
                .charge_outer_output(derived_output.len() as u64)
                .map_err(|error| M4RuntimeError::Integrity(error.to_string()))?;
            if derived_actual != pending.actual
                || derived_attestations != pending.service_attestations
                || derived_output != pending.outer_receipt.output
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "M4 bridge execution '{execution_id}' is not derivable from its exact inner receipts"
                )));
            }
            let expected_implementation = digest_json_content(&(
                BRIDGE_WIRE_SCHEMA,
                &self.factory_id,
                pending
                    .service_attestations
                    .iter()
                    .map(|item| &item.attestation_digest)
                    .collect::<Vec<_>>(),
            ))
            .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
            if pending.outer_receipt.implementation_digest != expected_implementation {
                return Err(M4RuntimeError::Integrity(format!(
                    "M4 bridge execution '{execution_id}' has altered outer receipt identity"
                )));
            }
        }
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, BridgeState>, M4RuntimeError> {
        self.state.lock().map_err(|_| M4RuntimeError::LockPoisoned)
    }

    fn transact<R>(
        &self,
        operation: impl FnOnce(&mut BridgeState) -> Result<R, M4RuntimeError>,
    ) -> Result<R, M4RuntimeError> {
        let mut guard = self.lock_state()?;
        let mut next = guard.clone();
        let result = operation(&mut next)?;
        validate_bridge_state(&next)?;
        write_json_atomic(&self.root, &self.root.join(BRIDGE_STATE_FILE), &next)?;
        *guard = next;
        Ok(result)
    }
}

impl CapabilityServiceInvoker for M3WorkerCapabilityBridge {
    fn invoke(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<CapabilityInvocationReceipt, CapabilityServiceFailure> {
        self.invoke_worker(request)
    }

    fn recover(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<Option<CapabilityInvocationReceipt>, CapabilityServiceFailure> {
        self.recover_worker(request)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M4Fault {
    Hold,
    HoldThenBridgeCrashAfterInnerReceiptsOnce { completed_receipts: u32 },
    TrapOnce,
    CrashOnce,
    TimeoutOnce,
    ConflictingResultOnce,
    UnjournaledCompletionOnce,
    BridgeCrashAfterInnerReceiptsOnce { completed_receipts: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ExternalExecution {
    Held,
    HeldBridgeCrash { completed_receipts: u32 },
    Ready,
    ReadyBridgeCrash { completed_receipts: u32 },
    Lost,
    RecoverActual,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ExecutorState {
    schema_version: u32,
    faults: BTreeMap<String, M4Fault>,
    executions: BTreeMap<String, ExternalExecution>,
    package_executions: BTreeMap<String, WorkerPackageExecutionRecord>,
}

impl Default for ExecutorState {
    fn default() -> Self {
        Self {
            schema_version: EXECUTOR_SCHEMA_VERSION,
            faults: BTreeMap::new(),
            executions: BTreeMap::new(),
            package_executions: BTreeMap::new(),
        }
    }
}

/// Durable executor adapter with bounded operator fault injection.
///
/// Fault injection is part of the acceptance surface: it makes crash, timeout,
/// lost lease, cancellation, and conflicting-result recovery reproducible. With
/// no directive, it delegates directly to the package-backed reference
/// executor and therefore cannot complete without a capability receipt.
struct M4DurableWorkerExecutor {
    root: PathBuf,
    package_root: PathBuf,
    bridge_crash_faults: BridgeCrashFaults,
    state: Mutex<ExecutorState>,
}

impl M4DurableWorkerExecutor {
    fn open(
        root: impl AsRef<Path>,
        bridge_crash_faults: BridgeCrashFaults,
    ) -> Result<Self, M4RuntimeError> {
        let root = secure_create_root(root.as_ref())?;
        let path = root.join(EXECUTOR_STATE_FILE);
        let state = if path.exists() {
            read_json(&path)?
        } else {
            let state = ExecutorState::default();
            write_json_atomic(&root, &path, &state)?;
            state
        };
        if state.schema_version != EXECUTOR_SCHEMA_VERSION {
            return Err(M4RuntimeError::Integrity(
                "unsupported M4 executor state schema".to_string(),
            ));
        }
        let package_root = secure_create_root(&root.join(WORKER_PACKAGE_DIRECTORY))?;
        let executor = Self {
            root,
            package_root,
            bridge_crash_faults,
            state: Mutex::new(state),
        };
        executor.validate_persisted_state()?;
        Ok(executor)
    }

    fn validate_persisted_state(&self) -> Result<(), M4RuntimeError> {
        let state = self
            .state
            .lock()
            .map_err(|_| M4RuntimeError::LockPoisoned)?;
        for (execution_id, record) in &state.package_executions {
            if execution_id != &record.execution_id
                || record.worker_id.trim().is_empty()
                || record.component_input != digest_marker(&record.input_digest)
                || record.component_output != record.component_input ^ role_marker(record.role)
                || record.component_trace.component_digest != record.package_digest
                || record.component_trace.input != record.component_input
                || record.component_trace.output != Some(record.component_output)
                || record.component_trace.trapped
                || digest_json_content(&record.component_trace)
                    .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?
                    != record.component_trace_digest
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "worker package execution '{execution_id}' is corrupted"
                )));
            }
            let manifest_path = self
                .package_root
                .join(format!("{}.manifest.json", record.worker_id));
            let manifest: WorkerPackageManifest = read_json(&manifest_path)?;
            self.validate_package_manifest(&manifest, &record.worker_id, record.role)?;
            if manifest.source_digest != record.source_digest
                || manifest.executable.package_digest != record.package_digest
                || manifest.executable.implementation_ref != record.implementation_ref
                || manifest.executable.provenance.build_record_digest != record.build_record_digest
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "worker package execution '{execution_id}' no longer resolves its manifest"
                )));
            }
        }
        Ok(())
    }

    fn ensure_reference_package(
        &self,
        worker_id: &str,
        role: GovernedWorkerRole,
        built_at_tick: u64,
    ) -> Result<ExecutableImplementation, M4RuntimeError> {
        validate_identifier("worker_id", worker_id)?;
        let manifest_path = self.package_root.join(format!("{worker_id}.manifest.json"));
        if manifest_path.exists() {
            let manifest: WorkerPackageManifest = read_json(&manifest_path)?;
            self.validate_package_manifest(&manifest, worker_id, role)?;
            return Ok(manifest.executable);
        }
        let source = reference_worker_component_source(role);
        let component_bytes = wat::parse_str(&source)
            .map_err(|error| M4RuntimeError::Artifact(format!("worker WAT: {error}")))?;
        let source_digest = ContentDigest::from_bytes(source.as_bytes());
        let package_digest = ContentDigest::from_bytes(&component_bytes);
        let build_record_digest = digest_json_content(&(
            WORKER_PACKAGE_SCHEMA,
            worker_id,
            role,
            &source_digest,
            &package_digest,
            WORKER_PACKAGE_TOOLCHAIN_ID,
        ))
        .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
        let executable = ExecutableImplementation {
            kind: ExecutableImplementationKind::WasmComponent,
            package_digest: package_digest.clone(),
            implementation_ref: format!(
                "wasm-biotic:m4-worker-package:{worker_id}:{}",
                digest_suffix(&package_digest)
            ),
            entrypoint: WORKER_PACKAGE_ENTRYPOINT.to_string(),
            provider_profile_ref: None,
            provenance: PackageProvenance {
                source_digest: source_digest.clone(),
                build_record_digest,
                producer_ref: WORKER_PACKAGE_PRODUCER_REF.to_string(),
                built_at_tick,
                signature_or_attestation_ref: format!("sha256:{}", package_digest.as_str()),
            },
        };
        let trace = execute_component_i32_export(
            &component_bytes,
            WORKER_PACKAGE_ENTRYPOINT,
            0,
            &ComponentExecutionLimits::default(),
        )
        .map_err(|error| {
            M4RuntimeError::Artifact(format!("new worker component is not executable: {error}"))
        })?;
        if trace.trapped || trace.output != Some(role_marker(role)) {
            return Err(M4RuntimeError::Integrity(format!(
                "new '{}' worker component failed its build-time execution proof",
                role.as_str()
            )));
        }
        let package_path = self.package_path(&package_digest);
        write_bytes_atomic(&self.package_root, &package_path, &component_bytes)?;
        let manifest = WorkerPackageManifest {
            schema: WORKER_PACKAGE_SCHEMA.to_string(),
            worker_id: worker_id.to_string(),
            role,
            source_digest,
            executable: executable.clone(),
        };
        write_json_atomic(&self.package_root, &manifest_path, &manifest)?;
        self.validate_package_manifest(&manifest, worker_id, role)?;
        Ok(executable)
    }

    fn validate_package_manifest(
        &self,
        manifest: &WorkerPackageManifest,
        worker_id: &str,
        role: GovernedWorkerRole,
    ) -> Result<(), M4RuntimeError> {
        let expected_source = reference_worker_component_source(role);
        let expected_source_digest = ContentDigest::from_bytes(expected_source.as_bytes());
        let expected_build_record_digest = digest_json_content(&(
            WORKER_PACKAGE_SCHEMA,
            worker_id,
            role,
            &expected_source_digest,
            &manifest.executable.package_digest,
            WORKER_PACKAGE_TOOLCHAIN_ID,
        ))
        .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
        let expected_implementation_ref = format!(
            "wasm-biotic:m4-worker-package:{worker_id}:{}",
            digest_suffix(&manifest.executable.package_digest)
        );
        let expected_attestation_ref =
            format!("sha256:{}", manifest.executable.package_digest.as_str());
        if manifest.schema != WORKER_PACKAGE_SCHEMA
            || manifest.worker_id != worker_id
            || manifest.role != role
            || manifest.source_digest != expected_source_digest
            || manifest.executable.kind != ExecutableImplementationKind::WasmComponent
            || manifest.executable.implementation_ref != expected_implementation_ref
            || manifest.executable.entrypoint != WORKER_PACKAGE_ENTRYPOINT
            || manifest.executable.provider_profile_ref.is_some()
            || manifest.executable.provenance.source_digest != expected_source_digest
            || manifest.executable.provenance.build_record_digest != expected_build_record_digest
            || manifest.executable.provenance.producer_ref != WORKER_PACKAGE_PRODUCER_REF
            || manifest.executable.provenance.signature_or_attestation_ref
                != expected_attestation_ref
        {
            return Err(M4RuntimeError::Integrity(format!(
                "worker package manifest '{worker_id}' changed its executable identity"
            )));
        }
        let package_path = self.package_path(&manifest.executable.package_digest);
        let component_bytes = read_regular_bytes(&package_path)?;
        if ContentDigest::from_bytes(&component_bytes) != manifest.executable.package_digest {
            return Err(M4RuntimeError::Integrity(format!(
                "worker package bytes for '{worker_id}' do not match the registered digest"
            )));
        }
        let inspection = execute_component_i32_export(
            &component_bytes,
            &manifest.executable.entrypoint,
            0,
            &ComponentExecutionLimits::default(),
        )
        .map_err(|error| {
            M4RuntimeError::Integrity(format!(
                "worker package '{worker_id}' cannot execute: {error}"
            ))
        })?;
        if inspection.trapped || inspection.output != Some(role_marker(role)) {
            return Err(M4RuntimeError::Integrity(format!(
                "worker package '{worker_id}' no longer implements its role marker"
            )));
        }
        Ok(())
    }

    fn execute_registered_package(
        &self,
        invocation: &crate::worker_runtime::WorkerInvocation,
    ) -> Result<WorkerPackageExecutionRecord, M4RuntimeError> {
        let manifest_path = self.package_root.join(format!(
            "{}.manifest.json",
            invocation.registration.worker_id
        ));
        let manifest: WorkerPackageManifest = read_json(&manifest_path)?;
        self.validate_package_manifest(
            &manifest,
            &invocation.registration.worker_id,
            invocation.registration.role,
        )?;
        if manifest.executable != invocation.registration.executable {
            return Err(M4RuntimeError::Integrity(format!(
                "execution '{}' registration does not match its stored package manifest",
                invocation.execution_id
            )));
        }
        let component_bytes =
            read_regular_bytes(&self.package_path(&manifest.executable.package_digest))?;
        let input_digest = governed_work_input_digest(
            &invocation.request.governance_context_digest,
            &invocation.request.input,
        )?;
        let component_input = digest_marker(&input_digest);
        let limits = ComponentExecutionLimits {
            fuel: invocation
                .request
                .budget
                .max_runtime_ticks
                .saturating_mul(1_000)
                .clamp(1_000, 100_000),
            ..ComponentExecutionLimits::default()
        };
        let trace = execute_component_i32_export(
            &component_bytes,
            &manifest.executable.entrypoint,
            component_input,
            &limits,
        )
        .map_err(|error| {
            M4RuntimeError::Artifact(format!(
                "worker package '{}' could not run: {error}",
                manifest.worker_id
            ))
        })?;
        let component_output = trace.output.ok_or_else(|| {
            M4RuntimeError::CapabilityFailure(format!(
                "worker package '{}' trapped before producing its role marker",
                manifest.worker_id
            ))
        })?;
        if trace.trapped || component_output != component_input ^ role_marker(manifest.role) {
            return Err(M4RuntimeError::CapabilityFailure(format!(
                "worker package '{}' returned an invalid role-bound result",
                manifest.worker_id
            )));
        }
        let component_trace_digest = digest_json_content(&trace)
            .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
        let record = WorkerPackageExecutionRecord {
            execution_id: invocation.execution_id.clone(),
            worker_id: invocation.registration.worker_id.clone(),
            role: invocation.registration.role,
            governance_context_digest: invocation.request.governance_context_digest.clone(),
            package_digest: manifest.executable.package_digest,
            implementation_ref: manifest.executable.implementation_ref,
            source_digest: manifest.source_digest,
            build_record_digest: manifest.executable.provenance.build_record_digest,
            input_digest,
            component_trace_digest,
            component_trace: trace,
            component_input,
            component_output,
            executed_at_tick: invocation.acquired_at_tick,
        };
        self.transact(|state| {
            if let Some(existing) = state.package_executions.get(&record.execution_id) {
                if existing == &record {
                    return Ok(existing.clone());
                }
                return Err(M4RuntimeError::Conflict(format!(
                    "execution '{}' has conflicting worker package evidence",
                    record.execution_id
                )));
            }
            state
                .package_executions
                .insert(record.execution_id.clone(), record.clone());
            Ok(record.clone())
        })
    }

    pub fn package_execution(
        &self,
        execution_id: &str,
    ) -> Result<WorkerPackageExecutionRecord, M4RuntimeError> {
        self.state
            .lock()
            .map_err(|_| M4RuntimeError::LockPoisoned)?
            .package_executions
            .get(execution_id)
            .cloned()
            .ok_or_else(|| {
                M4RuntimeError::NotFound(format!("worker package execution '{execution_id}'"))
            })
    }

    fn package_path(&self, digest: &ContentDigest) -> PathBuf {
        self.package_root
            .join(format!("{}.wasm", digest.file_stem()))
    }

    pub fn inject(
        &self,
        request_id: impl Into<String>,
        fault: M4Fault,
    ) -> Result<(), M4RuntimeError> {
        let request_id = request_id.into();
        validate_identifier("request_id", &request_id)?;
        self.transact(|state| {
            state.faults.insert(request_id, fault);
            Ok(())
        })
    }

    pub fn release(&self, execution_id: &str) -> Result<(), M4RuntimeError> {
        self.transact(|state| {
            let execution = state.executions.get_mut(execution_id).ok_or_else(|| {
                M4RuntimeError::Conflict(format!("execution '{execution_id}' is not held"))
            })?;
            let next = match execution {
                ExternalExecution::Held => ExternalExecution::Ready,
                ExternalExecution::HeldBridgeCrash { completed_receipts } => {
                    ExternalExecution::ReadyBridgeCrash {
                        completed_receipts: *completed_receipts,
                    }
                }
                _ => {
                    return Err(M4RuntimeError::Conflict(format!(
                        "execution '{execution_id}' is not held"
                    )));
                }
            };
            *execution = next;
            Ok(())
        })
    }

    pub fn mark_lost(&self, execution_id: &str) -> Result<(), M4RuntimeError> {
        self.transact(|state| match state.executions.get_mut(execution_id) {
            Some(execution @ ExternalExecution::Held)
            | Some(execution @ ExternalExecution::Ready)
            | Some(execution @ ExternalExecution::HeldBridgeCrash { .. })
            | Some(execution @ ExternalExecution::ReadyBridgeCrash { .. }) => {
                *execution = ExternalExecution::Lost;
                Ok(())
            }
            _ => Err(M4RuntimeError::Conflict(format!(
                "execution '{execution_id}' cannot be marked lost"
            ))),
        })
    }

    fn acknowledge(&self, execution_id: &str) -> Result<(), M4RuntimeError> {
        self.transact(|state| {
            state.executions.remove(execution_id);
            Ok(())
        })
    }

    fn retain_recoverable(
        &self,
        execution_id: &str,
        outcome: &ExecutorOutcome,
    ) -> Result<(), M4RuntimeError> {
        if matches!(outcome, ExecutorOutcome::Completed { .. }) {
            self.transact(|state| {
                state
                    .executions
                    .insert(execution_id.to_string(), ExternalExecution::RecoverActual);
                Ok(())
            })?;
        }
        Ok(())
    }

    fn execute_with_bridge_crash(
        &self,
        invocation: &crate::worker_runtime::WorkerInvocation,
        capabilities: &dyn CapabilityServiceInvoker,
        completed_receipts: u32,
    ) -> ExecutorOutcome {
        if completed_receipts > role_inner_call_count(invocation.registration.role) {
            return ExecutorOutcome::Trapped {
                detail: format!(
                    "bridge crash threshold {completed_receipts} exceeds the '{}' role call count",
                    invocation.registration.role.as_str()
                ),
                failed_at_tick: invocation.acquired_at_tick,
            };
        }
        match self.bridge_crash_faults.lock() {
            Ok(mut faults) => {
                faults.insert(invocation.execution_id.clone(), completed_receipts);
            }
            Err(_) => {
                return ExecutorOutcome::Unavailable {
                    detail: "M4 bridge crash-fault state lock is poisoned".to_string(),
                    failed_at_tick: invocation.acquired_at_tick,
                };
            }
        }
        let outcome = ReferenceWorkerExecutor.dispatch(invocation, capabilities);
        let fault_was_consumed = match self.bridge_crash_faults.lock() {
            Ok(mut faults) => faults.remove(&invocation.execution_id).is_none(),
            Err(_) => {
                return ExecutorOutcome::Unavailable {
                    detail: "M4 bridge crash-fault state lock is poisoned".to_string(),
                    failed_at_tick: invocation.acquired_at_tick,
                };
            }
        };
        if fault_was_consumed
            && matches!(
                &outcome,
                ExecutorOutcome::Unavailable { detail, .. }
                    if detail == BRIDGE_CRASH_FAULT_DETAIL
            )
        {
            // Deliberately return an invalid running outcome so the
            // WorkerRuntime transaction cannot journal either a failure or a
            // retry. An empty executor handle is invalid at every tick,
            // including tick zero. The durable lease and bridge intent remain
            // exactly as they would after process death.
            ExecutorOutcome::Running {
                executor_handle: String::new(),
                heartbeat_tick: invocation.acquired_at_tick,
            }
        } else {
            outcome
        }
    }

    fn transact<R>(
        &self,
        operation: impl FnOnce(&mut ExecutorState) -> Result<R, M4RuntimeError>,
    ) -> Result<R, M4RuntimeError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| M4RuntimeError::LockPoisoned)?;
        let mut next = guard.clone();
        let result = operation(&mut next)?;
        write_json_atomic(&self.root, &self.root.join(EXECUTOR_STATE_FILE), &next)?;
        *guard = next;
        Ok(result)
    }

    fn unavailable(error: M4RuntimeError, tick: u64) -> ExecutorOutcome {
        ExecutorOutcome::Unavailable {
            detail: format!("M4 executor journal unavailable: {error}"),
            failed_at_tick: tick,
        }
    }
}

impl DurableJobExecutor for M4DurableWorkerExecutor {
    fn dispatch(
        &self,
        invocation: &crate::worker_runtime::WorkerInvocation,
        capabilities: &dyn CapabilityServiceInvoker,
    ) -> ExecutorOutcome {
        let fault =
            match self.transact(|state| Ok(state.faults.remove(&invocation.request.request_id))) {
                Ok(fault) => fault,
                Err(error) => {
                    return Self::unavailable(error, invocation.acquired_at_tick);
                }
            };
        match fault {
            Some(M4Fault::Hold) => {
                if let Err(error) = self.execute_registered_package(invocation) {
                    return ExecutorOutcome::Trapped {
                        detail: error.to_string(),
                        failed_at_tick: invocation.acquired_at_tick,
                    };
                }
                if let Err(error) = self.transact(|state| {
                    state
                        .executions
                        .insert(invocation.execution_id.clone(), ExternalExecution::Held);
                    Ok(())
                }) {
                    return Self::unavailable(error, invocation.acquired_at_tick);
                }
                ExecutorOutcome::Running {
                    executor_handle: format!("m4-held:{}", invocation.execution_id),
                    heartbeat_tick: invocation.acquired_at_tick,
                }
            }
            Some(M4Fault::TrapOnce) => ExecutorOutcome::Trapped {
                detail: "injected bounded worker trap".to_string(),
                failed_at_tick: invocation.acquired_at_tick,
            },
            Some(M4Fault::CrashOnce) => ExecutorOutcome::Crashed {
                detail: "injected bounded worker crash".to_string(),
                failed_at_tick: invocation.acquired_at_tick,
            },
            Some(M4Fault::TimeoutOnce) => ExecutorOutcome::TimedOut {
                detail: "injected bounded worker timeout".to_string(),
                failed_at_tick: invocation.acquired_at_tick,
            },
            Some(M4Fault::ConflictingResultOnce) => {
                if let Err(error) = self.execute_registered_package(invocation) {
                    return ExecutorOutcome::Trapped {
                        detail: error.to_string(),
                        failed_at_tick: invocation.acquired_at_tick,
                    };
                }
                let actual = ReferenceWorkerExecutor.dispatch(invocation, capabilities);
                if let Err(error) = self.transact(|state| {
                    state.executions.insert(
                        invocation.execution_id.clone(),
                        ExternalExecution::RecoverActual,
                    );
                    Ok(())
                }) {
                    return Self::unavailable(error, invocation.acquired_at_tick);
                }
                conflict_outcome(actual)
            }
            Some(M4Fault::UnjournaledCompletionOnce) => {
                if let Err(error) = self.execute_registered_package(invocation) {
                    return ExecutorOutcome::Trapped {
                        detail: error.to_string(),
                        failed_at_tick: invocation.acquired_at_tick,
                    };
                }
                // Persist the real capability receipt, then force the
                // WorkerRuntime transaction to reject the returned output
                // before either the result or RecoverActual journal marker is
                // committed. This deterministically models that crash window.
                conflict_outcome(ReferenceWorkerExecutor.dispatch(invocation, capabilities))
            }
            Some(M4Fault::BridgeCrashAfterInnerReceiptsOnce { completed_receipts }) => {
                if let Err(error) = self.execute_registered_package(invocation) {
                    return ExecutorOutcome::Trapped {
                        detail: error.to_string(),
                        failed_at_tick: invocation.acquired_at_tick,
                    };
                }
                self.execute_with_bridge_crash(invocation, capabilities, completed_receipts)
            }
            Some(M4Fault::HoldThenBridgeCrashAfterInnerReceiptsOnce { completed_receipts }) => {
                if completed_receipts > role_inner_call_count(invocation.registration.role) {
                    return ExecutorOutcome::Trapped {
                        detail: "bridge crash threshold exceeds the held role call count"
                            .to_string(),
                        failed_at_tick: invocation.acquired_at_tick,
                    };
                }
                if let Err(error) = self.execute_registered_package(invocation) {
                    return ExecutorOutcome::Trapped {
                        detail: error.to_string(),
                        failed_at_tick: invocation.acquired_at_tick,
                    };
                }
                if let Err(error) = self.transact(|state| {
                    state.executions.insert(
                        invocation.execution_id.clone(),
                        ExternalExecution::HeldBridgeCrash { completed_receipts },
                    );
                    Ok(())
                }) {
                    return Self::unavailable(error, invocation.acquired_at_tick);
                }
                ExecutorOutcome::Running {
                    executor_handle: format!("m4-held:{}", invocation.execution_id),
                    heartbeat_tick: invocation.acquired_at_tick,
                }
            }
            None => {
                if let Err(error) = self.execute_registered_package(invocation) {
                    return ExecutorOutcome::Trapped {
                        detail: error.to_string(),
                        failed_at_tick: invocation.acquired_at_tick,
                    };
                }
                let outcome = ReferenceWorkerExecutor.dispatch(invocation, capabilities);
                if let Err(error) = self.retain_recoverable(&invocation.execution_id, &outcome) {
                    return Self::unavailable(error, invocation.acquired_at_tick);
                }
                outcome
            }
        }
    }

    fn reconcile(
        &self,
        invocation: &crate::worker_runtime::WorkerInvocation,
        capabilities: &dyn CapabilityServiceInvoker,
    ) -> ExecutorReconciliation {
        let state = match self
            .state
            .lock()
            .map_err(|_| M4RuntimeError::LockPoisoned)
            .map(|state| state.executions.get(&invocation.execution_id).cloned())
        {
            Ok(state) => state,
            Err(error) => {
                return ExecutorReconciliation::Terminal(Self::unavailable(
                    error,
                    invocation.effect_started_at_tick,
                ));
            }
        };
        match state {
            Some(ExternalExecution::Held) | Some(ExternalExecution::HeldBridgeCrash { .. }) => {
                ExecutorReconciliation::StillRunning {
                    executor_handle: format!("m4-held:{}", invocation.execution_id),
                    heartbeat_tick: invocation.acquired_at_tick,
                }
            }
            Some(ExternalExecution::ReadyBridgeCrash { completed_receipts }) => {
                if let Err(error) = self.execute_registered_package(invocation) {
                    return ExecutorReconciliation::Terminal(ExecutorOutcome::Trapped {
                        detail: error.to_string(),
                        failed_at_tick: invocation.effect_started_at_tick,
                    });
                }
                let outcome =
                    self.execute_with_bridge_crash(invocation, capabilities, completed_receipts);
                if let Err(error) = self.retain_recoverable(&invocation.execution_id, &outcome) {
                    return ExecutorReconciliation::Terminal(Self::unavailable(
                        error,
                        invocation.effect_started_at_tick,
                    ));
                }
                ExecutorReconciliation::Terminal(outcome)
            }
            Some(ExternalExecution::Ready) | Some(ExternalExecution::RecoverActual) => {
                if let Err(error) = self.execute_registered_package(invocation) {
                    return ExecutorReconciliation::Terminal(ExecutorOutcome::Trapped {
                        detail: error.to_string(),
                        failed_at_tick: invocation.effect_started_at_tick,
                    });
                }
                let outcome = ReferenceWorkerExecutor.dispatch(invocation, capabilities);
                if let Err(error) = self.retain_recoverable(&invocation.execution_id, &outcome) {
                    return ExecutorReconciliation::Terminal(Self::unavailable(
                        error,
                        invocation.effect_started_at_tick,
                    ));
                }
                ExecutorReconciliation::Terminal(outcome)
            }
            Some(ExternalExecution::Lost) => ExecutorReconciliation::Unknown {
                detail: "durable executor journal marks the external execution lost".to_string(),
                observed_at_tick: invocation
                    .request
                    .deadline
                    .not_before_tick
                    .saturating_add(invocation.registration.policy.lease_duration_ticks)
                    .saturating_add(1),
            },
            Some(ExternalExecution::Cancelled) => {
                ExecutorReconciliation::Terminal(ExecutorOutcome::Cancelled {
                    detail: "durable executor journal records cancellation".to_string(),
                    failed_at_tick: invocation.effect_started_at_tick,
                })
            }
            None => ReferenceWorkerExecutor.reconcile(invocation, capabilities),
        }
    }

    fn recover_terminal(
        &self,
        invocation: &crate::worker_runtime::WorkerInvocation,
        capabilities: &dyn CapabilityServiceInvoker,
    ) -> Result<Option<ExecutorOutcome>, String> {
        let execution = self
            .state
            .lock()
            .map_err(|_| "M4 executor state lock is poisoned".to_string())?
            .executions
            .get(&invocation.execution_id)
            .cloned();
        match ReferenceWorkerExecutor.recover_terminal(invocation, capabilities)? {
            Some(outcome @ ExecutorOutcome::Completed { .. }) => Ok(Some(outcome)),
            Some(_) => Err(
                "M4 executor recovered non-completion from a committed capability receipt"
                    .to_string(),
            ),
            None if execution == Some(ExternalExecution::RecoverActual) => Err(format!(
                "M4 executor journal marks '{}' recoverable but no exact capability receipt exists",
                invocation.execution_id
            )),
            None => Ok(None),
        }
    }

    fn cancel(&self, execution_id: &str, _cancellation_token: &str) -> Result<(), String> {
        self.transact(|state| {
            if state.executions.get(execution_id) == Some(&ExternalExecution::RecoverActual) {
                return Err(M4RuntimeError::Conflict(format!(
                    "execution '{execution_id}' has durable completion evidence pending recovery"
                )));
            }
            state
                .executions
                .insert(execution_id.to_string(), ExternalExecution::Cancelled);
            Ok(())
        })
        .map_err(|error| error.to_string())
    }
}

pub struct M4Runtime {
    config: M4RuntimeConfig,
    _root: PathBuf,
    _identity: M4RuntimeIdentity,
    _owner_lock: File,
    bridge: Arc<M3WorkerCapabilityBridge>,
    executor: Arc<M4DurableWorkerExecutor>,
    workers: WorkerRuntime<M4DurableWorkerExecutor, M3WorkerCapabilityBridge>,
}

impl M4Runtime {
    pub fn open(
        config: M4RuntimeConfig,
        m3: Arc<M3CapabilityRuntime>,
    ) -> Result<Self, M4RuntimeError> {
        config.validate()?;
        let root = secure_create_root(&config.root)?;
        let owner_lock = acquire_owner_lock(&root, RUNTIME_OWNER_LOCK_FILE)?;
        let expected_identity = M4RuntimeIdentity::new(&config, &m3)?;
        let identity_path = root.join(RUNTIME_IDENTITY_FILE);
        let identity = if identity_path.exists() {
            let persisted: M4RuntimeIdentity = read_json(&identity_path)?;
            persisted.validate()?;
            if persisted != expected_identity {
                return Err(M4RuntimeError::Conflict(
                    "M4 root belongs to a different factory, M3 scope, or concurrency policy"
                        .to_string(),
                ));
            }
            persisted
        } else {
            write_json_atomic(&root, &identity_path, &expected_identity)?;
            expected_identity
        };
        let bridge_crash_faults = Arc::new(Mutex::new(BTreeMap::new()));
        let bridge = Arc::new(M3WorkerCapabilityBridge::open(
            root.join("bridge"),
            config.factory_id.clone(),
            m3,
            identity.identity_digest.clone(),
            Arc::clone(&bridge_crash_faults),
        )?);
        let executor = Arc::new(M4DurableWorkerExecutor::open(
            root.join("executor"),
            bridge_crash_faults,
        )?);
        let workers = WorkerRuntime::open_with_shared(
            root.join("workers"),
            Arc::clone(&executor),
            Arc::clone(&bridge),
        )?;
        let runtime = Self {
            config,
            _root: root,
            _identity: identity,
            _owner_lock: owner_lock,
            bridge,
            executor,
            workers,
        };
        runtime.repair_result_aliases()?;
        Ok(runtime)
    }

    pub fn config(&self) -> &M4RuntimeConfig {
        &self.config
    }

    pub fn inject_fault(
        &self,
        request_id: impl Into<String>,
        fault: M4Fault,
    ) -> Result<(), M4RuntimeError> {
        if let M4Fault::BridgeCrashAfterInnerReceiptsOnce { completed_receipts }
        | M4Fault::HoldThenBridgeCrashAfterInnerReceiptsOnce { completed_receipts } = fault
            && !(1..=3).contains(&completed_receipts)
        {
            return Err(M4RuntimeError::InvalidConfig(
                "bridge crash fault receipt threshold must be between one and three".to_string(),
            ));
        }
        self.executor.inject(request_id, fault)
    }

    pub fn release_execution(&self, execution_id: &str) -> Result<(), M4RuntimeError> {
        self.executor.release(execution_id)
    }

    pub fn heartbeat_execution(&self, execution_id: &str, tick: u64) -> Result<(), M4RuntimeError> {
        Ok(self.workers.heartbeat(execution_id, tick)?)
    }

    pub fn mark_execution_lost(&self, execution_id: &str) -> Result<(), M4RuntimeError> {
        self.executor.mark_lost(execution_id)
    }

    pub fn package_execution(
        &self,
        execution_id: &str,
    ) -> Result<WorkerPackageExecutionRecord, M4RuntimeError> {
        self.executor.package_execution(execution_id)
    }

    pub fn ensure_reference_workers(&self, tick: u64) -> Result<(), M4RuntimeError> {
        let existing = self.workers.registrations()?;
        if existing.len() > GovernedWorkerRole::ALL.len()
            || existing
                .iter()
                .map(|registration| registration.role)
                .collect::<BTreeSet<_>>()
                .len()
                != existing.len()
        {
            return Err(M4RuntimeError::Integrity(
                "M4 worker store contains duplicate or non-reference registrations".to_string(),
            ));
        }
        for (ordinal, role) in GovernedWorkerRole::ALL.into_iter().enumerate() {
            let worker_id = format!("{}-{}", self.config.factory_id, role.as_str());
            let executable = self.executor.ensure_reference_package(
                &worker_id,
                role,
                tick.saturating_add(ordinal as u64),
            )?;
            let mut registration = reference_worker_registration(
                worker_id,
                role,
                self.config.factory_id.clone(),
                executable.package_digest.as_str().as_bytes(),
                tick.saturating_add(ordinal as u64),
            )?;
            registration.executable = executable;
            registration.policy.max_concurrency = self.config.worker_max_concurrency;
            for dependency in integration_service_dependencies(role) {
                if !registration
                    .service_family_refs
                    .iter()
                    .any(|known| known == dependency)
                {
                    registration
                        .service_family_refs
                        .push((*dependency).to_string());
                }
            }
            if let Some(grant) = integration_dependency_grant(role)
                && !registration.allowed_worlds.contains(&grant.world)
            {
                registration.allowed_worlds.push(grant.world);
            }
            registration.validate()?;
            match existing.iter().find(|known| known.role == role) {
                Some(known) if known == &registration => {}
                Some(_) => {
                    return Err(M4RuntimeError::Integrity(format!(
                        "persisted '{}' worker registration differs from its exact package/configuration",
                        role.as_str()
                    )));
                }
                None => self
                    .workers
                    .register_worker(registration, tick.saturating_add(ordinal as u64))?,
            }
        }
        Ok(())
    }

    pub fn prepare_reference_workflow(
        &self,
        request: &M4ReferenceWorkflowRequest,
    ) -> Result<ReferenceWorkflowSpec, M4RuntimeError> {
        self.bridge.prepare_reference_workflow(request)
    }

    pub fn validate_reference_workflow_request(
        &self,
        request: &M4ReferenceWorkflowRequest,
    ) -> Result<(), M4RuntimeError> {
        validate_reference_request(request)
    }

    pub fn enqueue(&self, request: WorkerJobRequest, tick: u64) -> Result<String, M4RuntimeError> {
        self.bridge.validate_job_request(&request)?;
        Ok(self.workers.enqueue(request, tick)?)
    }

    pub fn dispatch_next(&self, tick: u64) -> Result<Option<DispatchReport>, M4RuntimeError> {
        let report = self.workers.dispatch_next(tick)?;
        if let Some(report) = &report {
            self.bind_dispatch_result(report)?;
        }
        Ok(report)
    }

    pub fn reconcile_in_flight(&self, tick: u64) -> Result<ReconciliationReport, M4RuntimeError> {
        let report = self.workers.reconcile_in_flight(tick)?;
        for digest in &report.recovered_result_digests {
            let result = self.workers.load_result(digest)?;
            self.validate_result_package_execution(&result)?;
            self.bridge.bind_result(&result)?;
            self.executor.acknowledge(&result.execution_id)?;
        }
        Ok(report)
    }

    pub fn cancel(
        &self,
        job_id: &str,
        cancellation_token: &str,
        tick: u64,
    ) -> Result<(), M4RuntimeError> {
        self.workers
            .request_cancellation(job_id, cancellation_token, tick)?;
        if let Some(result_digest) = self.workers.load_job(job_id)?.result_digest {
            let result = self.workers.load_result(&result_digest)?;
            self.validate_result_package_execution(&result)?;
            self.bridge.bind_result(&result)?;
            self.executor.acknowledge(&result.execution_id)?;
        }
        Ok(())
    }

    pub fn load_job(
        &self,
        job_id: &str,
    ) -> Result<crate::worker_runtime::StoredWorkerJob, M4RuntimeError> {
        Ok(self.workers.load_job(job_id)?)
    }

    pub fn jobs(&self) -> Result<Vec<crate::worker_runtime::StoredWorkerJob>, M4RuntimeError> {
        Ok(self.workers.jobs()?)
    }

    pub fn claim_tick(&self) -> Result<u64, M4RuntimeError> {
        Ok(self.workers.claim_tick()?)
    }

    pub fn claim_tick_span(&self, span: u64) -> Result<u64, M4RuntimeError> {
        Ok(self.workers.claim_tick_span(span)?)
    }

    pub fn claim_tick_span_at_or_after(
        &self,
        minimum_tick: u64,
        span: u64,
    ) -> Result<u64, M4RuntimeError> {
        Ok(self
            .workers
            .claim_tick_span_at_or_after(minimum_tick, span)?)
    }

    pub fn claim_tick_span_at_or_after_before(
        &self,
        minimum_tick: u64,
        span: u64,
        exclusive_upper_tick: u64,
    ) -> Result<u64, M4RuntimeError> {
        Ok(self.workers.claim_tick_span_at_or_after_before(
            minimum_tick,
            span,
            exclusive_upper_tick,
        )?)
    }

    pub fn lifecycle_anchor(&self, workflow_id: &str) -> Result<M4LifecycleAnchor, M4RuntimeError> {
        self.bridge.lifecycle_anchor(workflow_id)
    }

    pub fn execution_evidence(
        &self,
        result_digest: &ContentDigest,
    ) -> Result<M4ExecutionEvidence, M4RuntimeError> {
        self.bridge.execution_evidence(result_digest)
    }

    pub fn bridge_progress(
        &self,
        execution_id: &str,
    ) -> Result<M4BridgeExecutionProgress, M4RuntimeError> {
        self.bridge.execution_progress(execution_id)
    }

    pub fn load_execution(
        &self,
        execution_id: &str,
    ) -> Result<WorkerExecutionRecord, M4RuntimeError> {
        Ok(self.workers.load_execution(execution_id)?)
    }

    pub fn load_result(
        &self,
        result_digest: &ContentDigest,
    ) -> Result<PersistedWorkerResult, M4RuntimeError> {
        Ok(self.workers.load_result(result_digest)?)
    }

    pub fn active_count(&self) -> Result<usize, M4RuntimeError> {
        self.count_jobs(|status| matches!(status, JobStatus::Leased | JobStatus::Running))
    }

    pub fn pending_count(&self) -> Result<usize, M4RuntimeError> {
        self.count_jobs(|status| matches!(status, JobStatus::Pending | JobStatus::RetryPending))
    }

    pub fn registrations(
        &self,
    ) -> Result<Vec<crate::worker_runtime::WorkerRegistration>, M4RuntimeError> {
        Ok(self.workers.registrations()?)
    }

    pub fn events(&self) -> Result<Vec<crate::worker_runtime::RuntimeEvent>, M4RuntimeError> {
        Ok(self.workers.events()?)
    }

    pub fn run_reference_workflow(
        &self,
        spec: ReferenceWorkflowSpec,
        start_tick: u64,
    ) -> Result<M4ReferenceWorkflowEvidence, M4RuntimeError> {
        if start_tick < spec.deadline.not_before_tick
            || start_tick
                .checked_add(6)
                .is_none_or(|final_tick| final_tick >= spec.deadline.expires_at_tick)
        {
            return Err(M4RuntimeError::Worker(
                WorkerRuntimeError::DeadlineExceeded(
                    "reference workflow's seven logical ticks do not fit its exact deadline"
                        .to_string(),
                ),
            ));
        }
        let workflow_id = spec.workflow_id.clone();
        let mut job_ids = Vec::new();
        let mut execution_ids = Vec::new();
        let mut worker_ids = Vec::new();
        let mut result_digests = Vec::new();

        let plan = self.run_step(
            &spec,
            GovernedWorkerRole::Planner,
            WorkInput::Plan {
                objective: spec.objective.clone(),
                baseline_digest: spec.baseline_digest.clone(),
            },
            start_tick,
            0,
        )?;
        collect_integrated_step(
            &plan,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut result_digests,
        );
        let plan_digest = plan.2.result_digest.clone();

        let build = self.run_step(
            &spec,
            GovernedWorkerRole::Builder,
            WorkInput::Build {
                plan_result_digest: plan_digest.clone(),
                target_relative_path: spec.target_relative_path.clone(),
                expected_before_digest: spec.expected_before_digest.clone(),
                replacement_bytes: spec.replacement_bytes.clone(),
            },
            start_tick.saturating_add(1),
            1,
        )?;
        collect_integrated_step(
            &build,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut result_digests,
        );
        let build_digest = build.2.result_digest.clone();
        let artifact_digest = match &build.2.output {
            WorkOutput::Build {
                artifact_digest, ..
            } => artifact_digest.clone(),
            _ => {
                return Err(M4RuntimeError::Integrity(
                    "builder output changed role".into(),
                ));
            }
        };

        let validation = self.run_step(
            &spec,
            GovernedWorkerRole::Validator,
            WorkInput::Validate {
                plan_result_digest: plan_digest.clone(),
                build_result_digest: build_digest.clone(),
                target_relative_path: spec.target_relative_path.clone(),
                expected_artifact_digest: artifact_digest,
                suite_digest: spec.validation_suite_digest.clone(),
            },
            start_tick.saturating_add(2),
            2,
        )?;
        collect_integrated_step(
            &validation,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut result_digests,
        );
        let validation_digest = validation.2.result_digest.clone();
        if !matches!(
            validation.2.output,
            WorkOutput::Validate { passed: true, .. }
        ) {
            return Err(M4RuntimeError::CapabilityFailure(
                "validator rejected the M3 candidate package".to_string(),
            ));
        }

        let review = self.run_step(
            &spec,
            GovernedWorkerRole::Reviewer,
            WorkInput::Review {
                plan_result_digest: plan_digest,
                build_result_digest: build_digest.clone(),
                validation_result_digest: validation_digest.clone(),
            },
            start_tick.saturating_add(3),
            3,
        )?;
        collect_integrated_step(
            &review,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut result_digests,
        );
        let review_digest = review.2.result_digest.clone();

        let package = self.run_step(
            &spec,
            GovernedWorkerRole::Packager,
            WorkInput::Package {
                build_result_digest: build_digest,
                validation_result_digest: validation_digest,
                review_result_digest: review_digest,
            },
            start_tick.saturating_add(4),
            4,
        )?;
        collect_integrated_step(
            &package,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut result_digests,
        );
        let package_digest = package.2.result_digest.clone();
        let synthesis_seed_digest = digest_json_content(&result_digests)
            .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;

        let continuity = self.run_step(
            &spec,
            GovernedWorkerRole::ContinuityWorker,
            WorkInput::Continue {
                package_result_digest: package_digest,
                synthesis_seed_digest,
            },
            start_tick.saturating_add(5),
            5,
        )?;
        collect_integrated_step(
            &continuity,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut result_digests,
        );
        if execution_ids.iter().collect::<BTreeSet<_>>().len() != 6
            || worker_ids.iter().collect::<BTreeSet<_>>().len() != 6
        {
            return Err(M4RuntimeError::Integrity(
                "reference workflow did not use six distinct governed executions".to_string(),
            ));
        }
        let synthesis = self.workers.synthesize(
            format!("synthesis:{workflow_id}"),
            result_digests.clone(),
            start_tick.saturating_add(6),
        )?;
        for job_id in &job_ids {
            let job = self.workers.load_job(job_id)?;
            if job.request.governance_context_digest != spec.governance_context_digest {
                return Err(M4RuntimeError::Integrity(format!(
                    "durable job '{job_id}' escaped the workflow governance context"
                )));
            }
        }
        let worker = ReferenceWorkflowEvidence {
            workflow_id: workflow_id.clone(),
            governance_context_digest: spec.governance_context_digest.clone(),
            job_ids,
            execution_ids: execution_ids.clone(),
            worker_ids,
            result_digests: result_digests.clone(),
            synthesis,
        };
        let executions = result_digests
            .iter()
            .map(|digest| self.bridge.execution_evidence(digest))
            .collect::<Result<Vec<_>, _>>()?;
        let package_executions = execution_ids
            .iter()
            .map(|execution_id| self.executor.package_execution(execution_id))
            .collect::<Result<Vec<_>, _>>()?;
        if package_executions.len() != GovernedWorkerRole::ALL.len()
            || executions.iter().any(|execution| {
                execution.governance_context_digest != spec.governance_context_digest
            })
            || package_executions.iter().any(|execution| {
                execution.governance_context_digest != spec.governance_context_digest
            })
            || package_executions
                .iter()
                .map(|record| &record.package_digest)
                .collect::<BTreeSet<_>>()
                .len()
                != GovernedWorkerRole::ALL.len()
        {
            return Err(M4RuntimeError::Integrity(
                "reference workflow did not execute six distinct package byte identities"
                    .to_string(),
            ));
        }
        Ok(M4ReferenceWorkflowEvidence {
            governance_context_digest: spec.governance_context_digest,
            worker,
            lifecycle_anchor: self.bridge.lifecycle_anchor(&workflow_id)?,
            executions,
            package_executions,
        })
    }

    fn run_step(
        &self,
        spec: &ReferenceWorkflowSpec,
        role: GovernedWorkerRole,
        input: WorkInput,
        tick: u64,
        ordinal: usize,
    ) -> Result<(String, WorkerExecutionRecord, PersistedWorkerResult), M4RuntimeError> {
        let capability_envelope = spec
            .capability_envelopes
            .get(&role)
            .cloned()
            .ok_or_else(|| M4RuntimeError::InvalidConfig("missing role envelope".into()))?;
        let job_id = self.enqueue(
            WorkerJobRequest {
                request_id: format!("{}-{}-{ordinal}", spec.workflow_id, role.as_str()),
                role,
                governance_context_digest: spec.governance_context_digest.clone(),
                input,
                capability_envelope,
                workspace_scope: spec.workspace_scope.clone(),
                budget: spec.budget.clone(),
                deadline: spec.deadline.clone(),
                cancellation_token: WorkerCancellationToken::from_secret(&format!(
                    "cancel:{}:{}:{ordinal}",
                    spec.workflow_id,
                    role.as_str()
                )),
                fairness_key: self.config.factory_id.clone(),
                priority: 100,
            },
            tick,
        )?;
        let report = self.dispatch_next(tick)?.ok_or_else(|| {
            M4RuntimeError::Conflict(format!("worker scheduler did not dispatch '{job_id}'"))
        })?;
        if report.job_id != job_id || report.status != JobStatus::Completed {
            return Err(M4RuntimeError::CapabilityFailure(format!(
                "{} worker did not complete its isolated reference job: {:?}",
                role.as_str(),
                report.status
            )));
        }
        let result_digest = report.result_digest.ok_or_else(|| {
            M4RuntimeError::Integrity("completed worker has no result digest".into())
        })?;
        Ok((
            job_id,
            self.workers.load_execution(&report.execution_id)?,
            self.workers.load_result(&result_digest)?,
        ))
    }

    fn bind_dispatch_result(&self, report: &DispatchReport) -> Result<(), M4RuntimeError> {
        if let Some(digest) = &report.result_digest {
            let result = self.workers.load_result(digest)?;
            self.validate_result_package_execution(&result)?;
            self.bridge.bind_result(&result)?;
            self.executor.acknowledge(&result.execution_id)?;
        }
        Ok(())
    }

    fn repair_result_aliases(&self) -> Result<(), M4RuntimeError> {
        for job in self.workers.jobs()? {
            if let Some(digest) = job.result_digest {
                let result = self.workers.load_result(&digest)?;
                self.validate_result_package_execution(&result)?;
                self.bridge.bind_result(&result)?;
                self.executor.acknowledge(&result.execution_id)?;
            }
        }
        Ok(())
    }

    fn validate_result_package_execution(
        &self,
        result: &PersistedWorkerResult,
    ) -> Result<(), M4RuntimeError> {
        let package = self.executor.package_execution(&result.execution_id)?;
        let job = self.workers.load_job(&result.job_id)?;
        let execution = self.workers.load_execution(&result.execution_id)?;
        if package.worker_id != result.worker_id
            || package.role != result.role
            || package.governance_context_digest != result.governance_context_digest
            || package.governance_context_digest != job.request.governance_context_digest
            || package.governance_context_digest != execution.governance_context_digest
            || package.package_digest != result.implementation_package_digest
            || package.implementation_ref != result.implementation_ref
            || package.source_digest != result.provenance.source_digest
            || package.build_record_digest != result.provenance.build_record_digest
            || package.input_digest != job.input_digest
            || package.component_input != digest_marker(&job.input_digest)
            || package.executed_at_tick != execution.lease.acquired_at_tick
        {
            return Err(M4RuntimeError::Integrity(format!(
                "worker result '{}' is not bound to its executed package bytes",
                result.result_digest
            )));
        }
        Ok(())
    }

    fn count_jobs(&self, predicate: impl Fn(&JobStatus) -> bool) -> Result<usize, M4RuntimeError> {
        Ok(self
            .workers
            .jobs()?
            .iter()
            .filter(|job| predicate(&job.status))
            .count())
    }
}

fn collect_integrated_step(
    step: &(String, WorkerExecutionRecord, PersistedWorkerResult),
    job_ids: &mut Vec<String>,
    execution_ids: &mut Vec<String>,
    worker_ids: &mut Vec<String>,
    result_digests: &mut Vec<ContentDigest>,
) {
    job_ids.push(step.0.clone());
    execution_ids.push(step.1.execution_id.clone());
    worker_ids.push(step.1.worker_id.clone());
    result_digests.push(step.2.result_digest.clone());
}

fn integration_service_dependencies(role: GovernedWorkerRole) -> &'static [&'static str] {
    match role {
        GovernedWorkerRole::Planner => &["continuity"],
        GovernedWorkerRole::Builder => &["packaging"],
        GovernedWorkerRole::Reviewer => &["validation"],
        GovernedWorkerRole::Validator
        | GovernedWorkerRole::Packager
        | GovernedWorkerRole::ContinuityWorker => &[],
    }
}

fn integration_dependency_grant(role: GovernedWorkerRole) -> Option<CapabilityWorldGrant> {
    let (world, operation, authority) = match role {
        GovernedWorkerRole::Planner => (
            CapabilityWorld::MemoryAccess,
            "resolve_planner_context",
            AuthorityClass::Observe,
        ),
        GovernedWorkerRole::Builder => (
            CapabilityWorld::ServiceOrganelle,
            "publish_candidate_package",
            AuthorityClass::LocalMutate,
        ),
        GovernedWorkerRole::Reviewer => (
            CapabilityWorld::WorkspaceObserve,
            "compare_candidate_proving",
            AuthorityClass::Observe,
        ),
        GovernedWorkerRole::Validator
        | GovernedWorkerRole::Packager
        | GovernedWorkerRole::ContinuityWorker => return None,
    };
    Some(CapabilityWorldGrant {
        world,
        allowed_operations: vec![operation.to_string()],
        default_authority_class: authority,
        default_approval_class: ApprovalClass::AutoAllowed,
        operation_approval_overrides: Vec::new(),
    })
}

fn bridge_effect_safe_runtime_ticks(request: &CapabilityInvocationRequest) -> u64 {
    let deadline_runtime_ticks = request
        .deadline
        .expires_at_tick
        .saturating_sub(request.effect_started_at_tick)
        .saturating_sub(1);
    let execution_runtime_ticks = request
        .acquired_at_tick
        .saturating_add(request.work_budget.max_runtime_ticks)
        .saturating_sub(request.effect_started_at_tick);
    deadline_runtime_ticks.min(execution_runtime_ticks)
}

fn bridge_runtime_budget_ms(request: &CapabilityInvocationRequest) -> u64 {
    bridge_effect_safe_runtime_ticks(request)
        .saturating_mul(100)
        .clamp(1, 30_000)
}

fn bridge_per_call_timeout_cap_ms(
    request: &CapabilityInvocationRequest,
    required_calls: u32,
) -> u64 {
    bridge_runtime_budget_ms(request)
        .checked_div(u64::from(required_calls).saturating_add(1))
        .unwrap_or(1)
        .max(1)
}

struct BridgeCallBudget {
    started: Instant,
    max_calls: u32,
    required_calls: u32,
    calls: u32,
    max_input_bytes: u64,
    input_bytes: u64,
    max_output_bytes: u64,
    output_bytes: u64,
    max_runtime_ms: u64,
    per_call_timeout_ms: u64,
}

impl BridgeCallBudget {
    fn new(
        request: &CapabilityInvocationRequest,
        outer_input_bytes: u64,
        required_calls: u32,
    ) -> Result<Self, CapabilityServiceFailure> {
        let budget = &request.work_budget;
        if request.acquired_at_tick < request.deadline.not_before_tick
            || request.acquired_at_tick >= request.deadline.expires_at_tick
            || request.effect_started_at_tick < request.acquired_at_tick
            || request.effect_started_at_tick >= request.deadline.expires_at_tick
        {
            return Err(CapabilityServiceFailure::Denied(
                "worker capability invocation is outside its exact deadline".to_string(),
            ));
        }
        let max_runtime_ticks = bridge_effect_safe_runtime_ticks(request);
        if max_runtime_ticks == 0 {
            return Err(CapabilityServiceFailure::TimedOut(
                "worker capability invocation has no effect-safe time before its deadline"
                    .to_string(),
            ));
        }
        if budget.max_capability_calls < required_calls {
            return Err(CapabilityServiceFailure::Denied(format!(
                "role requires {required_calls} inner capability calls but budget permits {}",
                budget.max_capability_calls
            )));
        }
        if outer_input_bytes > budget.max_input_bytes {
            return Err(CapabilityServiceFailure::Denied(
                "outer worker payload exceeds its aggregate input budget".to_string(),
            ));
        }
        Ok(Self {
            started: Instant::now(),
            max_calls: budget.max_capability_calls,
            required_calls,
            calls: 0,
            max_input_bytes: budget.max_input_bytes,
            input_bytes: outer_input_bytes,
            max_output_bytes: budget.max_output_bytes,
            output_bytes: 0,
            max_runtime_ms: bridge_runtime_budget_ms(request),
            per_call_timeout_ms: bridge_per_call_timeout_cap_ms(request, required_calls),
        })
    }

    fn for_recovery(
        request: &CapabilityInvocationRequest,
        outer_input_bytes: u64,
        required_calls: u32,
    ) -> Result<Self, CapabilityServiceFailure> {
        let mut budget = Self::new(request, outer_input_bytes, required_calls)?;
        // Recovery performs bounded local reads only. Its authority comes from
        // the original durable interval, not from restart-time wall-clock
        // latency while integrity-checking those records.
        budget.max_runtime_ms = u64::MAX;
        Ok(budget)
    }

    fn begin_call(&mut self, request: &CapabilityRequest) -> Result<u64, CapabilityServiceFailure> {
        let encoded = serde_json::to_vec(request)
            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        let next_calls = self.calls.saturating_add(1);
        let next_input = self.input_bytes.saturating_add(encoded.len() as u64);
        if next_calls > self.max_calls || next_input > self.max_input_bytes {
            return Err(CapabilityServiceFailure::Denied(
                "inner M3 invocation would exceed the durable worker call/input budget".to_string(),
            ));
        }
        let elapsed = self.started.elapsed().as_millis() as u64;
        if elapsed >= self.max_runtime_ms {
            return Err(CapabilityServiceFailure::TimedOut(
                "aggregate worker capability runtime budget elapsed".to_string(),
            ));
        }
        self.calls = next_calls;
        self.input_bytes = next_input;
        let remaining_required_calls = u64::from(
            self.required_calls
                .saturating_sub(self.calls)
                .saturating_add(1),
        );
        Ok(self
            .per_call_timeout_ms
            .min(
                self.max_runtime_ms
                    .saturating_sub(elapsed)
                    .checked_div(remaining_required_calls.saturating_add(1))
                    .unwrap_or(1),
            )
            .max(1))
    }

    fn finish_call(
        &mut self,
        result: &(CapabilitySuccess, ServiceInvocationAttestation),
    ) -> Result<(), CapabilityServiceFailure> {
        let encoded = serde_json::to_vec(result)
            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        self.output_bytes = self.output_bytes.saturating_add(encoded.len() as u64);
        if self.output_bytes > self.max_output_bytes {
            return Err(CapabilityServiceFailure::Denied(
                "inner M3 response exceeds the durable worker output budget".to_string(),
            ));
        }
        if self.started.elapsed().as_millis() as u64 > self.max_runtime_ms {
            return Err(CapabilityServiceFailure::TimedOut(
                "aggregate worker capability runtime budget elapsed".to_string(),
            ));
        }
        Ok(())
    }

    fn charge_outer_output(&mut self, bytes: u64) -> Result<(), CapabilityServiceFailure> {
        self.output_bytes = self.output_bytes.saturating_add(bytes);
        if self.output_bytes > self.max_output_bytes {
            return Err(CapabilityServiceFailure::Denied(
                "outer worker response exceeds the aggregate output budget".to_string(),
            ));
        }
        if self.started.elapsed().as_millis() as u64 > self.max_runtime_ms {
            return Err(CapabilityServiceFailure::TimedOut(
                "aggregate worker capability runtime budget elapsed".to_string(),
            ));
        }
        Ok(())
    }
}

fn role_inner_call_count(role: GovernedWorkerRole) -> u32 {
    match role {
        GovernedWorkerRole::Planner
        | GovernedWorkerRole::Validator
        | GovernedWorkerRole::Packager
        | GovernedWorkerRole::ContinuityWorker => 1,
        GovernedWorkerRole::Reviewer => 2,
        GovernedWorkerRole::Builder => 3,
    }
}

fn role_inner_invocation_ids(invocation_base: &str, role: GovernedWorkerRole) -> Vec<String> {
    let suffixes: &[&str] = match role {
        GovernedWorkerRole::Planner => &["resolve"],
        GovernedWorkerRole::Builder => &["patch", "build", "publish"],
        GovernedWorkerRole::Validator => &["prove"],
        GovernedWorkerRole::Reviewer => &["compare", "review"],
        GovernedWorkerRole::Packager => &["verify"],
        GovernedWorkerRole::ContinuityWorker => &["publish"],
    };
    suffixes
        .iter()
        .map(|suffix| format!("{invocation_base}-{suffix}"))
        .collect()
}

fn role_inner_service_bindings(
    role: GovernedWorkerRole,
) -> Vec<(&'static str, AuthorityClass, CapabilityOperation)> {
    match role {
        GovernedWorkerRole::Planner => vec![(
            CONTINUITY_RESOLVE_SERVICE_ID,
            AuthorityClass::Observe,
            CapabilityOperation::EvidenceResolve,
        )],
        GovernedWorkerRole::Builder => vec![
            (
                BUILD_SERVICE_ID,
                AuthorityClass::LocalMutate,
                CapabilityOperation::WorkspacePatch,
            ),
            (
                BUILD_SERVICE_ID,
                AuthorityClass::LocalMutate,
                CapabilityOperation::CandidateBuild,
            ),
            (
                PACKAGING_SERVICE_ID,
                AuthorityClass::LocalMutate,
                CapabilityOperation::PackagePublish,
            ),
        ],
        GovernedWorkerRole::Validator => vec![(
            VALIDATION_SERVICE_ID,
            AuthorityClass::Observe,
            CapabilityOperation::ValidationProve,
        )],
        GovernedWorkerRole::Reviewer => vec![
            (
                VALIDATION_SERVICE_ID,
                AuthorityClass::Observe,
                CapabilityOperation::ValidationCompare,
            ),
            (
                REVIEW_SERVICE_ID,
                AuthorityClass::Observe,
                CapabilityOperation::ReviewCandidate,
            ),
        ],
        GovernedWorkerRole::Packager => vec![(
            PACKAGING_SERVICE_ID,
            AuthorityClass::LocalMutate,
            CapabilityOperation::PackageVerify,
        )],
        GovernedWorkerRole::ContinuityWorker => vec![(
            CONTINUITY_SERVICE_ID,
            AuthorityClass::LocalMutate,
            CapabilityOperation::EvidencePublish,
        )],
    }
}

fn immutable_reference_workflow_digest(
    workflow_id: &str,
    objective: &str,
    governance_context_digest: &ContentDigest,
    replacement_wat_digest: &ContentDigest,
    validation_suite: &ValidationSuite,
    budget: &WorkBudget,
    deadline: &WorkDeadline,
) -> Result<ContentDigest, M4RuntimeError> {
    digest_json_content(&(
        "wasm-biotic:m4-reference-request:v2",
        workflow_id,
        objective,
        governance_context_digest,
        replacement_wat_digest,
        validation_suite,
        budget,
        deadline,
    ))
    .map_err(|error| M4RuntimeError::Artifact(error.to_string()))
}

fn reference_workflow_request_digest(
    request: &M4ReferenceWorkflowRequest,
) -> Result<ContentDigest, M4RuntimeError> {
    immutable_reference_workflow_digest(
        &request.workflow_id,
        &request.objective,
        &request.governance_context_digest,
        &ContentDigest::from_bytes(&request.replacement_wat_bytes),
        &request.validation_suite,
        &request.budget,
        &request.deadline,
    )
}

fn prepared_workflow_request_digest(
    workflow: &PreparedWorkflow,
) -> Result<ContentDigest, M4RuntimeError> {
    immutable_reference_workflow_digest(
        &workflow.workflow_id,
        &workflow.objective,
        &workflow.governance_context_digest,
        &workflow.replacement_wat_digest,
        &workflow.validation_suite,
        &workflow.budget,
        &workflow.deadline,
    )
}

fn validate_reference_request(request: &M4ReferenceWorkflowRequest) -> Result<(), M4RuntimeError> {
    validate_identifier("workflow_id", &request.workflow_id)?;
    if request.objective.trim().is_empty() || request.replacement_wat_bytes.is_empty() {
        return Err(M4RuntimeError::InvalidConfig(
            "reference objective and replacement WAT must not be empty".to_string(),
        ));
    }
    validate_reference_request_budget(request)?;
    request.validation_suite.validate().map_err(|error| {
        M4RuntimeError::InvalidConfig(format!("invalid validation suite: {error}"))
    })?;
    let exclusive_end = request
        .deadline
        .not_before_tick
        .checked_add(7)
        .ok_or_else(|| {
            M4RuntimeError::Worker(WorkerRuntimeError::DeadlineExceeded(
                "reference workflow logical tick interval overflows".to_string(),
            ))
        })?;
    if exclusive_end > request.deadline.expires_at_tick {
        return Err(M4RuntimeError::Worker(
            WorkerRuntimeError::DeadlineExceeded(
                "reference workflow requires seven logical ticks before its deadline".to_string(),
            ),
        ));
    }
    Ok(())
}

fn validate_reference_request_budget(
    request: &M4ReferenceWorkflowRequest,
) -> Result<(), M4RuntimeError> {
    request.budget.validate()?;
    request.deadline.validate()?;
    if request.budget.max_capability_calls < role_inner_call_count(GovernedWorkerRole::Builder) {
        return Err(M4RuntimeError::Worker(WorkerRuntimeError::BudgetExceeded(
            "reference budget cannot fund the Builder's three exact M3 effects".to_string(),
        )));
    }
    let digest = ContentDigest::from_bytes(b"m4-budget-preflight");
    let inputs = [
        WorkInput::Plan {
            objective: request.objective.clone(),
            baseline_digest: digest.clone(),
        },
        WorkInput::Build {
            plan_result_digest: digest.clone(),
            target_relative_path: PathBuf::from(COMPONENT_WAT_PATH),
            expected_before_digest: digest.clone(),
            replacement_bytes: request.replacement_wat_bytes.clone(),
        },
        WorkInput::Validate {
            plan_result_digest: digest.clone(),
            build_result_digest: digest.clone(),
            target_relative_path: PathBuf::from(COMPONENT_WAT_PATH),
            expected_artifact_digest: digest.clone(),
            suite_digest: digest.clone(),
        },
        WorkInput::Review {
            plan_result_digest: digest.clone(),
            build_result_digest: digest.clone(),
            validation_result_digest: digest.clone(),
        },
        WorkInput::Package {
            build_result_digest: digest.clone(),
            validation_result_digest: digest.clone(),
            review_result_digest: digest.clone(),
        },
        WorkInput::Continue {
            package_result_digest: digest.clone(),
            synthesis_seed_digest: digest,
        },
    ];
    let largest_input = inputs
        .iter()
        .map(serde_json::to_vec)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|bytes| bytes.len() as u64)
        .max()
        .unwrap_or_default();
    if largest_input > request.budget.max_input_bytes {
        return Err(M4RuntimeError::Worker(WorkerRuntimeError::BudgetExceeded(
            "reference typed input cannot fit its declared byte budget".to_string(),
        )));
    }
    let suite_bytes = serde_json::to_vec(&request.validation_suite)?.len() as u64;
    let conservative_inner_input = largest_input
        .saturating_add(request.replacement_wat_bytes.len() as u64)
        .saturating_add(suite_bytes.saturating_mul(2))
        .saturating_add(262_144);
    let conservative_inner_output = suite_bytes
        .saturating_mul(4)
        .saturating_add(request.replacement_wat_bytes.len() as u64)
        .saturating_add(262_144);
    if conservative_inner_input > request.budget.max_input_bytes
        || conservative_inner_output > request.budget.max_output_bytes
    {
        return Err(M4RuntimeError::Worker(WorkerRuntimeError::BudgetExceeded(
            "reference budget cannot contain the complete bounded M3 request/response set"
                .to_string(),
        )));
    }
    Ok(())
}

/// Limits enforced above each factory's own worker and lease limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M4FleetLimits {
    pub global_max_active: usize,
    pub per_factory_max_active: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FleetState {
    schema_version: u32,
    configuration_digest: ContentDigest,
    last_factory_id: Option<String>,
}

impl FleetState {
    fn new(configuration_digest: ContentDigest) -> Self {
        Self {
            schema_version: FLEET_SCHEMA_VERSION,
            configuration_digest,
            last_factory_id: None,
        }
    }
}

/// Fair coordinator for multiple bounded local factories.
pub struct M4Fleet {
    root: PathBuf,
    _owner_lock: File,
    limits: M4FleetLimits,
    factories: BTreeMap<String, Arc<M4Runtime>>,
    state: Mutex<FleetState>,
    dispatch_gate: Mutex<()>,
}

impl M4Fleet {
    pub fn open(
        root: impl AsRef<Path>,
        limits: M4FleetLimits,
        factories: Vec<Arc<M4Runtime>>,
    ) -> Result<Self, M4RuntimeError> {
        if limits.global_max_active == 0 || limits.per_factory_max_active == 0 {
            return Err(M4RuntimeError::InvalidConfig(
                "fleet concurrency limits must be non-zero".to_string(),
            ));
        }
        let root = secure_create_root(root.as_ref())?;
        let mut map = BTreeMap::new();
        for factory in factories {
            let factory_id = factory.config.factory_id.clone();
            if map.insert(factory_id.clone(), factory).is_some() {
                return Err(M4RuntimeError::Conflict(format!(
                    "duplicate factory '{factory_id}'"
                )));
            }
        }
        if map.is_empty() {
            return Err(M4RuntimeError::InvalidConfig(
                "fleet requires at least one factory".to_string(),
            ));
        }
        let configuration_digest = digest_json_content(&(
            "wasm-biotic:m4-fleet-config:v1",
            limits,
            map.keys().collect::<Vec<_>>(),
        ))
        .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
        let owner_lock = acquire_owner_lock(&root, ".m4-fleet-owner.lock")?;
        let path = root.join(FLEET_STATE_FILE);
        let state = if path.exists() {
            read_json(&path)?
        } else {
            let state = FleetState::new(configuration_digest.clone());
            write_json_atomic(&root, &path, &state)?;
            state
        };
        if state.schema_version != FLEET_SCHEMA_VERSION
            || state.configuration_digest != configuration_digest
        {
            return Err(M4RuntimeError::Integrity(
                "fleet state belongs to a different factory set or concurrency policy".to_string(),
            ));
        }
        Ok(Self {
            root,
            _owner_lock: owner_lock,
            limits,
            factories: map,
            state: Mutex::new(state),
            dispatch_gate: Mutex::new(()),
        })
    }

    pub fn active_count(&self) -> Result<usize, M4RuntimeError> {
        self.factories.values().try_fold(0usize, |total, factory| {
            factory
                .active_count()
                .map(|count| total.saturating_add(count))
        })
    }

    pub fn dispatch_next(
        &self,
        tick: u64,
    ) -> Result<Option<(String, DispatchReport)>, M4RuntimeError> {
        let _dispatch = self
            .dispatch_gate
            .lock()
            .map_err(|_| M4RuntimeError::LockPoisoned)?;
        if self.active_count()? >= self.limits.global_max_active {
            return Ok(None);
        }
        let last = self
            .state
            .lock()
            .map_err(|_| M4RuntimeError::LockPoisoned)?
            .last_factory_id
            .clone();
        let mut eligible = Vec::new();
        for (factory_id, factory) in &self.factories {
            let active = factory.active_count()?;
            let pending = factory.pending_count()?;
            if active < self.limits.per_factory_max_active && pending > 0 {
                eligible.push(factory_id.clone());
            }
        }
        if let Some(last) = &last
            && !eligible.is_empty()
        {
            let successor = eligible
                .iter()
                .position(|factory| factory > last)
                .unwrap_or(0);
            eligible.rotate_left(successor);
        }
        for factory_id in eligible {
            // Reserve the fair turn before crossing into a separately durable
            // factory. A crash may consume one turn without dispatching, but
            // can never durably dispatch A while leaving the cursor at its
            // predecessor and selecting A again after restart.
            self.transact(|state| {
                state.last_factory_id = Some(factory_id.clone());
                Ok(())
            })?;
            let factory = self
                .factories
                .get(&factory_id)
                .ok_or_else(|| M4RuntimeError::Integrity("eligible factory vanished".into()))?;
            if let Some(report) = factory.dispatch_next(tick)? {
                return Ok(Some((factory_id, report)));
            }
        }
        Ok(None)
    }

    fn transact<R>(
        &self,
        operation: impl FnOnce(&mut FleetState) -> Result<R, M4RuntimeError>,
    ) -> Result<R, M4RuntimeError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| M4RuntimeError::LockPoisoned)?;
        let mut next = guard.clone();
        let result = operation(&mut next)?;
        write_json_atomic(&self.root, &self.root.join(FLEET_STATE_FILE), &next)?;
        *guard = next;
        Ok(result)
    }
}

#[derive(Debug)]
pub enum M4RuntimeError {
    InvalidConfig(String),
    NotFound(String),
    Conflict(String),
    Integrity(String),
    CapabilityFailure(String),
    Worker(WorkerRuntimeError),
    M3(M3RuntimeError),
    Artifact(String),
    Serialization(serde_json::Error),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    UnsafePath(PathBuf),
    LockPoisoned,
}

impl Display for M4RuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid M4 config: {message}"),
            Self::NotFound(message) => write!(formatter, "M4 record not found: {message}"),
            Self::Conflict(message) => write!(formatter, "M4 conflict: {message}"),
            Self::Integrity(message) => write!(formatter, "M4 integrity failure: {message}"),
            Self::CapabilityFailure(message) => {
                write!(formatter, "M4 capability failure: {message}")
            }
            Self::Worker(error) => write!(formatter, "M4 worker runtime: {error}"),
            Self::M3(error) => write!(formatter, "M4 M3 integration: {error}"),
            Self::Artifact(message) => write!(formatter, "M4 artifact failure: {message}"),
            Self::Serialization(error) => write!(formatter, "M4 serialization: {error}"),
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::UnsafePath(path) => write!(formatter, "unsafe M4 path: {}", path.display()),
            Self::LockPoisoned => write!(formatter, "M4 state lock poisoned"),
        }
    }
}

impl Error for M4RuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Worker(error) => Some(error),
            Self::M3(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<WorkerRuntimeError> for M4RuntimeError {
    fn from(value: WorkerRuntimeError) -> Self {
        Self::Worker(value)
    }
}

impl From<M3RuntimeError> for M4RuntimeError {
    fn from(value: M3RuntimeError) -> Self {
        Self::M3(value)
    }
}

impl From<serde_json::Error> for M4RuntimeError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

fn actual_matches_output(actual: &M4ActualOutput, output: &WorkOutput) -> bool {
    match (actual, output) {
        (
            M4ActualOutput::Planner { plan_digest, .. },
            WorkOutput::Plan {
                plan_digest: output_plan,
                ..
            },
        ) => plan_digest == output_plan,
        (
            M4ActualOutput::Builder {
                before_digest,
                candidate_wat_digest,
                ..
            },
            WorkOutput::Build {
                before_digest: output_before,
                artifact_digest,
                ..
            },
        ) => before_digest == output_before && candidate_wat_digest == artifact_digest,
        (
            M4ActualOutput::Validator {
                candidate_wat_digest,
                proving_digest,
                passed,
                ..
            },
            WorkOutput::Validate {
                artifact_digest,
                proving_digest: output_proving,
                passed: output_passed,
                ..
            },
        ) => {
            candidate_wat_digest == artifact_digest
                && proving_digest == output_proving
                && passed == output_passed
        }
        (
            M4ActualOutput::Reviewer {
                review_digest,
                approved,
                ..
            },
            WorkOutput::Review {
                decision,
                review_digest: output_review,
                ..
            },
        ) => {
            review_digest == output_review
                && *approved == matches!(decision, ReviewDecision::Approve)
        }
        (
            M4ActualOutput::Packager { package_digest, .. },
            WorkOutput::Package {
                package_digest: output_package,
                ..
            },
        ) => package_digest == output_package,
        (
            M4ActualOutput::ContinuityWorker { record_digest, .. },
            WorkOutput::Continue {
                checkpoint_digest, ..
            },
        ) => record_digest == checkpoint_digest,
        _ => false,
    }
}

fn conflict_outcome(outcome: ExecutorOutcome) -> ExecutorOutcome {
    match outcome {
        ExecutorOutcome::Completed {
            output,
            completed_at_tick,
        } => {
            let output = match output {
                WorkOutput::Plan { .. } => WorkOutput::Plan {
                    baseline_digest: ContentDigest::from_bytes(b"injected-conflicting-result"),
                    plan_digest: ContentDigest::from_bytes(b"injected-conflicting-result"),
                },
                WorkOutput::Build {
                    plan_result_digest,
                    before_digest,
                    ..
                } => WorkOutput::Build {
                    plan_result_digest,
                    before_digest,
                    artifact_digest: ContentDigest::from_bytes(b"injected-conflicting-result"),
                },
                WorkOutput::Validate {
                    plan_result_digest,
                    build_result_digest,
                    artifact_digest,
                    proving_digest,
                    passed,
                } => WorkOutput::Validate {
                    plan_result_digest,
                    build_result_digest,
                    artifact_digest,
                    proving_digest,
                    passed: !passed,
                },
                WorkOutput::Review {
                    build_result_digest,
                    validation_result_digest,
                    review_digest,
                    ..
                } => WorkOutput::Review {
                    build_result_digest,
                    validation_result_digest,
                    decision: ReviewDecision::Reject,
                    review_digest,
                },
                WorkOutput::Package {
                    build_result_digest,
                    validation_result_digest,
                    review_result_digest,
                    ..
                } => WorkOutput::Package {
                    build_result_digest,
                    validation_result_digest,
                    review_result_digest,
                    package_digest: ContentDigest::from_bytes(b"injected-conflicting-result"),
                },
                WorkOutput::Continue {
                    package_result_digest,
                    ..
                } => WorkOutput::Continue {
                    package_result_digest,
                    checkpoint_digest: ContentDigest::from_bytes(b"injected-conflicting-result"),
                },
            };
            ExecutorOutcome::Completed {
                output,
                completed_at_tick,
            }
        }
        other => other,
    }
}

fn validate_bridge_state(state: &BridgeState) -> Result<(), M4RuntimeError> {
    if state.schema_version != BRIDGE_SCHEMA_VERSION {
        return Err(M4RuntimeError::Integrity(
            "unsupported M4 bridge state schema".to_string(),
        ));
    }
    for (workflow_id, workflow) in &state.workflows {
        if workflow_id != &workflow.workflow_id
            || workflow.request_digest != prepared_workflow_request_digest(workflow)?
            || workflow.anchor.m2_job_id != workflow.anchor.terminal_job.job_id
            || workflow.anchor.terminal_job.phase != JobPhase::Succeeded
            || workflow.anchor.terminal_job.terminal_outcome.is_none()
            || digest_json_content(&workflow.anchor.terminal_job)
                .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?
                != workflow.anchor.terminal_job_digest
        {
            return Err(M4RuntimeError::Integrity(format!(
                "prepared workflow '{workflow_id}' has corrupted lifecycle evidence"
            )));
        }
    }
    let bounded_invocation = InvocationBudget::bounded(1);
    let mut logical_inner_invocations = BTreeMap::new();
    for (execution_id, intent) in &state.execution_intents {
        let expected_ids = role_inner_invocation_ids(&intent.invocation_base, intent.role);
        let bindings = role_inner_service_bindings(intent.role);
        let request_digest = digest_json_content(&intent.request)
            .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?;
        let safe_runtime_ticks = bridge_effect_safe_runtime_ticks(&intent.request);
        if intent.request.execution_id != *execution_id
            || intent.request_digest != request_digest
            || intent.role != intent.request.role
            || intent.governance_context_digest != intent.request.governance_context_digest
            || intent.worker_payload_digest != ContentDigest::from_bytes(&intent.request.payload)
            || intent.acquired_at_tick != intent.request.acquired_at_tick
            || intent.effect_started_at_tick != intent.request.effect_started_at_tick
            || intent.workspace_scope != intent.request.workspace_scope
            || intent.capability_envelope != intent.request.capability_envelope
            || intent.work_budget != intent.request.work_budget
            || intent.deadline != intent.request.deadline
            || intent.expected_inner_invocation_ids != expected_ids
            || expected_ids.len() != role_inner_call_count(intent.role) as usize
            || bindings.len() != expected_ids.len()
            || intent.acquired_at_tick < intent.deadline.not_before_tick
            || intent.acquired_at_tick >= intent.deadline.expires_at_tick
            || intent.effect_started_at_tick < intent.acquired_at_tick
            || intent.effect_started_at_tick >= intent.deadline.expires_at_tick
            || intent.effect_started_at_tick
                > intent
                    .acquired_at_tick
                    .saturating_add(intent.work_budget.max_runtime_ticks)
            || safe_runtime_ticks == 0
            || intent.inner_invocations.len() > expected_ids.len()
        {
            return Err(M4RuntimeError::Integrity(format!(
                "bridge intent '{execution_id}' is structurally corrupted"
            )));
        }
        let mut progress_closed = false;
        let mut timeout_budget_ms = 0_u64;
        let mut input_bytes = intent.request.payload.len() as u64;
        for (ordinal, invocation_id) in expected_ids.iter().enumerate() {
            let Some(progress) = intent.inner_invocations.get(invocation_id) else {
                progress_closed = true;
                continue;
            };
            let (service_id, authority, operation) = &bindings[ordinal];
            let invocation = &progress.invocation;
            let origin_intent = state
                .execution_intents
                .get(&progress.origin_execution_id)
                .ok_or_else(|| {
                    M4RuntimeError::Integrity(format!(
                        "bridge intent '{execution_id}' cites missing origin '{}' for inner invocation '{invocation_id}'",
                        progress.origin_execution_id
                    ))
                })?;
            let origin_progress = origin_intent
                .inner_invocations
                .get(invocation_id)
                .ok_or_else(|| {
                    M4RuntimeError::Integrity(format!(
                        "bridge intent '{execution_id}' cites an origin without inner invocation '{invocation_id}'"
                    ))
                })?;
            let origin_timeout_cap_ms = bridge_per_call_timeout_cap_ms(
                &origin_intent.request,
                role_inner_call_count(origin_intent.role),
            );
            if progress_closed
                || progress.origin_execution_id.trim().is_empty()
                || origin_progress.origin_execution_id != progress.origin_execution_id
                || origin_progress.invocation != *invocation
                || !origin_intent
                    .expected_inner_invocation_ids
                    .iter()
                    .any(|expected| expected == invocation_id)
                || bridge_effect_safe_runtime_ticks(&origin_intent.request) == 0
                || invocation.identity.invocation_id != *invocation_id
                || invocation.identity.idempotency_key != format!("idempotency:{invocation_id}")
                || invocation.identity.service_id != *service_id
                || invocation.identity.authority != *authority
                || invocation.identity.approval != InvocationApproval::Automatic
                || invocation.request.operation() != *operation
                || invocation.request.scope_id() != invocation.identity.scope_id
                || invocation.budget.timeout_ms == 0
                || invocation.budget.timeout_ms > origin_timeout_cap_ms
                || invocation.budget.max_request_bytes != bounded_invocation.max_request_bytes
                || progress.terminal_failure && progress.receipt_digest.is_none()
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "bridge intent '{execution_id}' has a malformed inner invocation"
                )));
            }
            timeout_budget_ms = timeout_budget_ms.saturating_add(invocation.budget.timeout_ms);
            input_bytes = input_bytes.saturating_add(
                serde_json::to_vec(&invocation.request)
                    .map_err(M4RuntimeError::Serialization)?
                    .len() as u64,
            );
            if logical_inner_invocations
                .insert(
                    invocation_id.clone(),
                    (invocation.clone(), progress.origin_execution_id.clone()),
                )
                .is_some_and(|(existing, origin_execution_id)| {
                    existing != *invocation || origin_execution_id != progress.origin_execution_id
                })
            {
                return Err(M4RuntimeError::Integrity(format!(
                    "logical inner invocation '{invocation_id}' differs in origin or content across worker attempts"
                )));
            }
            if progress.receipt_digest.is_none() || progress.terminal_failure {
                progress_closed = true;
            }
        }
        if timeout_budget_ms
            > intent
                .work_budget
                .max_runtime_ticks
                .saturating_mul(100)
                .clamp(1, 30_000)
            || input_bytes > intent.work_budget.max_input_bytes
            || intent.inner_invocations.len() as u32 > intent.work_budget.max_capability_calls
        {
            return Err(M4RuntimeError::Integrity(format!(
                "bridge intent '{execution_id}' exceeds its durable call, input, or timeout budget"
            )));
        }
        if intent
            .inner_invocations
            .keys()
            .any(|invocation_id| !expected_ids.contains(invocation_id))
        {
            return Err(M4RuntimeError::Integrity(format!(
                "bridge intent '{execution_id}' contains an unexpected inner invocation"
            )));
        }
    }
    for (execution_id, pending) in &state.executions {
        let intent = state.execution_intents.get(execution_id).ok_or_else(|| {
            M4RuntimeError::Integrity(format!(
                "bridge execution '{execution_id}' lacks its completed inner intent"
            ))
        })?;
        let attestation_ids = pending
            .service_attestations
            .iter()
            .map(|attestation| attestation.invocation_id.clone())
            .collect::<Vec<_>>();
        pending
            .outer_receipt
            .validate_integrity()
            .map_err(|error| M4RuntimeError::Integrity(error.to_string()))?;
        if execution_id != &pending.outer_receipt.execution_id
            || pending.role != pending.actual.role()
            || pending.role != intent.role
            || pending.governance_context_digest != intent.governance_context_digest
            || pending.governance_context_digest != intent.request.governance_context_digest
            || pending.governance_context_digest != pending.outer_receipt.governance_context_digest
            || pending.worker_payload_digest != ContentDigest::from_bytes(&intent.request.payload)
            || pending.acquired_at_tick != intent.request.acquired_at_tick
            || pending.effect_started_at_tick != intent.request.effect_started_at_tick
            || pending.workspace_scope != intent.request.workspace_scope
            || pending.capability_envelope != intent.request.capability_envelope
            || pending.work_budget != intent.request.work_budget
            || pending.deadline != intent.request.deadline
            || intent.expected_inner_invocation_ids != attestation_ids
            || intent.inner_invocations.len() != attestation_ids.len()
            || pending.service_attestations.iter().any(|attestation| {
                intent
                    .inner_invocations
                    .get(&attestation.invocation_id)
                    .is_none_or(|progress| {
                        progress.terminal_failure
                            || progress.receipt_digest.as_ref() != Some(&attestation.receipt_digest)
                    })
            })
            || pending.worker_payload_digest != pending.outer_receipt.input_digest
            || pending.acquired_at_tick < pending.deadline.not_before_tick
            || pending.effect_started_at_tick < pending.acquired_at_tick
            || pending.effect_started_at_tick >= pending.deadline.expires_at_tick
            || pending.outer_receipt.effect_started_at_tick != pending.effect_started_at_tick
            || pending.outer_receipt.completed_at_tick < pending.effect_started_at_tick
            || pending.outer_receipt.completed_at_tick >= pending.deadline.expires_at_tick
            || pending.outer_receipt.completed_at_tick
                > pending
                    .acquired_at_tick
                    .saturating_add(pending.work_budget.max_runtime_ticks)
            || digest_json_content(&pending.capability_envelope)
                .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?
                != pending.outer_receipt.capability_envelope_digest
            || digest_json_content(&pending.work_budget)
                .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?
                != pending.outer_receipt.work_budget_digest
            || digest_json_content(&pending.deadline)
                .map_err(|error| M4RuntimeError::Artifact(error.to_string()))?
                != pending.outer_receipt.deadline_digest
        {
            return Err(M4RuntimeError::Integrity(format!(
                "bridge execution '{execution_id}' is structurally corrupted"
            )));
        }
    }
    let mut aliased_executions = BTreeSet::new();
    for (digest, execution_id) in &state.result_aliases {
        if ContentDigest::new(digest.clone()).is_err()
            || !state.executions.contains_key(execution_id)
            || !aliased_executions.insert(execution_id)
        {
            return Err(M4RuntimeError::Integrity(
                "M4 result alias is malformed or dangling".to_string(),
            ));
        }
    }
    Ok(())
}

fn capability_store_error(error: M4RuntimeError) -> CapabilityServiceFailure {
    CapabilityServiceFailure::Unavailable(error.to_string())
}

fn capability_scope_error(error: M4RuntimeError) -> CapabilityServiceFailure {
    match error {
        M4RuntimeError::Worker(
            WorkerRuntimeError::InvalidRequest(message)
            | WorkerRuntimeError::CapabilityDenied(message),
        ) => CapabilityServiceFailure::Denied(message),
        other => capability_store_error(other),
    }
}

fn wrong_native_type(operation: &str) -> CapabilityServiceFailure {
    CapabilityServiceFailure::InvalidReceipt(format!(
        "M3 returned the wrong typed success for {operation}"
    ))
}

fn mismatched_result(subject: &str) -> CapabilityServiceFailure {
    CapabilityServiceFailure::Denied(format!(
        "worker result does not resolve to the required {subject} evidence"
    ))
}

fn digest_suffix(digest: &ContentDigest) -> &str {
    let value = digest.as_str();
    let start = value.len().saturating_sub(24);
    &value[start..]
}

fn now_ms() -> Result<u64, M4RuntimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| M4RuntimeError::InvalidConfig(format!("system clock: {error}")))?
        .as_millis()
        .try_into()
        .map_err(|_| M4RuntimeError::InvalidConfig("system time exceeds u64".to_string()))
}

fn validate_identifier(field: &str, value: &str) -> Result<(), M4RuntimeError> {
    let path = Path::new(value);
    let valid = !value.trim().is_empty()
        && value.len() <= 192
        && !path.is_absolute()
        && !value.contains('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if valid {
        Ok(())
    } else {
        Err(M4RuntimeError::InvalidConfig(format!(
            "{field} is not a safe bounded identifier"
        )))
    }
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M4RuntimeError> {
    reject_symlink(path)?;
    fs::create_dir_all(path).map_err(|source| M4RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| M4RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(M4RuntimeError::UnsafePath(path.to_path_buf()));
    }
    fs::canonicalize(path).map_err(|source| M4RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn acquire_owner_lock(root: &Path, file_name: &str) -> Result<File, M4RuntimeError> {
    let path = root.join(file_name);
    reject_symlink(&path)?;
    if path.exists() {
        let metadata = fs::symlink_metadata(&path).map_err(|source| M4RuntimeError::Io {
            path: path.clone(),
            source,
        })?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(M4RuntimeError::UnsafePath(path));
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| M4RuntimeError::Io {
            path: path.clone(),
            source,
        })?;
    file.try_lock().map_err(|source| match source {
        std::fs::TryLockError::WouldBlock => M4RuntimeError::Conflict(format!(
            "M4 runtime root '{}' already has a live owner",
            root.display()
        )),
        std::fs::TryLockError::Error(source) => M4RuntimeError::Io {
            path: path.clone(),
            source,
        },
    })?;
    Ok(file)
}

fn reject_symlink(path: &Path) -> Result<(), M4RuntimeError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(M4RuntimeError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn read_regular_bytes(path: &Path) -> Result<Vec<u8>, M4RuntimeError> {
    reject_symlink(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| M4RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(M4RuntimeError::UnsafePath(path.to_path_buf()));
    }
    fs::read(path).map_err(|source| M4RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_bytes_atomic(root: &Path, destination: &Path, bytes: &[u8]) -> Result<(), M4RuntimeError> {
    if destination.parent() != Some(root) {
        return Err(M4RuntimeError::UnsafePath(destination.to_path_buf()));
    }
    reject_symlink(destination)?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(
        ".m4-package.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|source| M4RuntimeError::Io {
                path: temporary.clone(),
                source,
            })?;
        file.write_all(bytes).map_err(|source| M4RuntimeError::Io {
            path: temporary.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| M4RuntimeError::Io {
            path: temporary.clone(),
            source,
        })?;
        fs::rename(&temporary, destination).map_err(|source| M4RuntimeError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| M4RuntimeError::Io {
                path: root.to_path_buf(),
                source,
            })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn reference_worker_component_source(role: GovernedWorkerRole) -> String {
    format!(
        r#"(component
  (core module $worker
    (func (export "run") (param i32) (result i32)
      local.get 0
      i32.const {}
      i32.xor))
  (core instance $worker-instance (instantiate $worker))
  (func $run (param "input" s32) (result s32)
    (canon lift (core func $worker-instance "run")))
  (export "run" (func $run)))
"#,
        role_marker(role)
    )
}

fn role_marker(role: GovernedWorkerRole) -> i32 {
    match role {
        GovernedWorkerRole::Planner => 0x11,
        GovernedWorkerRole::Builder => 0x22,
        GovernedWorkerRole::Validator => 0x33,
        GovernedWorkerRole::Reviewer => 0x44,
        GovernedWorkerRole::Packager => 0x55,
        GovernedWorkerRole::ContinuityWorker => 0x66,
    }
}

fn digest_marker(digest: &ContentDigest) -> i32 {
    digest
        .as_str()
        .as_bytes()
        .iter()
        .take(4)
        .fold(0_i32, |value, byte| value.rotate_left(5) ^ i32::from(*byte))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, M4RuntimeError> {
    reject_symlink(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| M4RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(M4RuntimeError::UnsafePath(path.to_path_buf()));
    }
    let mut file = File::open(path).map_err(|source| M4RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| M4RuntimeError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_json_atomic<T: Serialize>(
    root: &Path,
    destination: &Path,
    value: &T,
) -> Result<(), M4RuntimeError> {
    reject_symlink(destination)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(".m4-write-{}-{sequence}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|source| M4RuntimeError::Io {
                path: temporary.clone(),
                source,
            })?;
        file.write_all(&bytes)
            .map_err(|source| M4RuntimeError::Io {
                path: temporary.clone(),
                source,
            })?;
        file.sync_all().map_err(|source| M4RuntimeError::Io {
            path: temporary.clone(),
            source,
        })?;
        fs::rename(&temporary, destination).map_err(|source| M4RuntimeError::Io {
            path: destination.to_path_buf(),
            source,
        })?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| M4RuntimeError::Io {
                path: root.to_path_buf(),
                source,
            })
    })();
    let _ = fs::remove_file(&temporary);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::NativeServiceFamily;
    use crate::execution::component::ComponentExecutionLimits;
    use crate::m1_validation::ValidationCase;
    use crate::m2_runtime::{M2Runtime, M2RuntimeConfig};
    use crate::m3_runtime::M3RuntimeConfig;
    use crate::supervisor::JobPhase;
    use crate::worker_runtime::ExecutionStatus;
    use std::thread;
    use std::time::Duration;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestRoot {
        path: PathBuf,
    }

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m4-{label}-{}-{sequence}",
                std::process::id()
            ));
            if path.exists() {
                fs::remove_dir_all(&path).expect("remove stale M4 fixture");
            }
            fs::create_dir(&path).expect("create M4 fixture");
            Self { path }
        }

        fn template(&self, label: &str) -> PathBuf {
            let destination = self.path.join(format!("{label}-template"));
            fs::create_dir(&destination).expect("create isolated template");
            for file in ["component.wit", "component.wat"] {
                fs::copy(
                    fixture_root().join("template").join(file),
                    destination.join(file),
                )
                .expect("copy frozen reference template");
            }
            destination
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct Harness {
        m2_config: M2RuntimeConfig,
        m3_config: M3RuntimeConfig,
        m4_config: M4RuntimeConfig,
        m2: Arc<M2Runtime>,
        m3: Arc<M3CapabilityRuntime>,
        m4: Arc<M4Runtime>,
    }

    fn harness(test: &TestRoot, label: &str) -> Harness {
        let template = test.template(label);
        let scope_id = format!("scope-{label}");
        let m2_config = M2RuntimeConfig {
            supervisor_root: test.path.join(format!("{label}-m2-supervisor")),
            lifecycle_root: test.path.join(format!("{label}-m2-lifecycle")),
            template_root: template.clone(),
            owner_id: format!("m4-test-{label}"),
            max_idle_wait_ms: 10,
        };
        let m3_config = M3RuntimeConfig::new(
            test.path.join(format!("{label}-m3")),
            template,
            scope_id,
            format!("deployment-{label}"),
        );
        let m4_config = M4RuntimeConfig {
            root: test.path.join(format!("{label}-m4")),
            factory_id: format!("factory-{label}"),
            worker_max_concurrency: 2,
        };
        let m2 = Arc::new(M2Runtime::new(m2_config.clone()).expect("construct M2"));
        let m3 = Arc::new(
            M3CapabilityRuntime::open(m3_config.clone(), Arc::clone(&m2)).expect("open M3"),
        );
        let m4 = Arc::new(M4Runtime::open(m4_config.clone(), Arc::clone(&m3)).expect("open M4"));
        m4.ensure_reference_workers(1)
            .expect("register six package-backed workers");
        Harness {
            m2_config,
            m3_config,
            m4_config,
            m2,
            m3,
            m4,
        }
    }

    fn validation_suite(label: &str) -> ValidationSuite {
        ValidationSuite::new(
            format!("m4-{label}-increment-v1"),
            "transform",
            [(-1, 0), (0, 1), (41, 42)]
                .into_iter()
                .enumerate()
                .map(|(index, (input, output))| {
                    ValidationCase::returns(format!("case-{}", index + 1), input, output)
                })
                .collect(),
            ComponentExecutionLimits {
                fuel: 1_000_000,
                ..ComponentExecutionLimits::default()
            },
        )
        .expect("valid bounded suite")
    }

    fn budget() -> WorkBudget {
        WorkBudget {
            max_attempts: 3,
            max_capability_calls: 8,
            max_input_bytes: 1_048_576,
            max_output_bytes: 1_048_576,
            max_runtime_ticks: 100,
        }
    }

    fn workflow_request(label: &str, not_before_tick: u64) -> M4ReferenceWorkflowRequest {
        M4ReferenceWorkflowRequest {
            workflow_id: format!("workflow-{label}"),
            objective: "build the increment component and prove the exact package".to_string(),
            governance_context_digest: ContentDigest::from_bytes(
                format!("governance-{label}").as_bytes(),
            ),
            replacement_wat_bytes: fs::read(fixture_root().join("candidates/increment.wat"))
                .expect("read increment candidate"),
            validation_suite: validation_suite(label),
            budget: budget(),
            deadline: WorkDeadline {
                not_before_tick,
                expires_at_tick: not_before_tick.saturating_add(500),
            },
        }
    }

    fn plan_request(
        spec: &ReferenceWorkflowSpec,
        factory_id: &str,
        request_id: &str,
        _not_before_tick: u64,
    ) -> WorkerJobRequest {
        WorkerJobRequest {
            request_id: request_id.to_string(),
            role: GovernedWorkerRole::Planner,
            governance_context_digest: spec.governance_context_digest.clone(),
            input: WorkInput::Plan {
                objective: spec.objective.clone(),
                baseline_digest: spec.baseline_digest.clone(),
            },
            capability_envelope: spec
                .capability_envelopes
                .get(&GovernedWorkerRole::Planner)
                .expect("planner envelope")
                .clone(),
            workspace_scope: spec.workspace_scope.clone(),
            budget: spec.budget.clone(),
            deadline: spec.deadline.clone(),
            cancellation_token: WorkerCancellationToken::from_secret(&format!(
                "cancel-{request_id}"
            )),
            fairness_key: factory_id.to_string(),
            priority: 50,
        }
    }

    fn dispatch_retry_to_completion(
        runtime: &M4Runtime,
        job_id: &str,
        first_tick: u64,
    ) -> PersistedWorkerResult {
        let first = runtime
            .dispatch_next(first_tick)
            .expect("dispatch injected failure")
            .expect("failure report");
        assert_eq!(first.job_id, job_id);
        assert_eq!(first.status, JobStatus::RetryPending);
        let recovered = runtime
            .dispatch_next(first_tick.saturating_add(1))
            .expect("retry worker")
            .expect("retry report");
        assert_eq!(recovered.job_id, job_id);
        assert_eq!(recovered.status, JobStatus::Completed);
        runtime
            .load_result(
                recovered
                    .result_digest
                    .as_ref()
                    .expect("completed result digest"),
            )
            .expect("load recovered result")
    }

    fn wait_for_m2_success(m3: &M3CapabilityRuntime, schedule_id: &str) {
        for _ in 0..500 {
            let job = m3
                .scheduled_job(schedule_id)
                .expect("inspect scheduled M2 job")
                .expect("M2 job exists");
            if job.phase == JobPhase::Succeeded {
                return;
            }
            assert!(
                !job.phase.is_terminal(),
                "M2 anchor terminated unexpectedly: {:?}",
                job.phase
            );
            thread::sleep(Duration::from_millis(10));
        }
        panic!("M2 lifecycle anchor did not complete in the bounded wait");
    }

    #[test]
    fn governance_context_is_immutable_for_one_prepared_workflow_id() {
        let test = TestRoot::new("governance-context-conflict");
        let Harness { m2, m3, m4, .. } = harness(&test, "governance-context-conflict");
        let request = workflow_request("governance-context-conflict", 10);
        let first_spec = m4
            .prepare_reference_workflow(&request)
            .expect("prepare governance-bound workflow");
        assert_eq!(
            first_spec.governance_context_digest,
            request.governance_context_digest
        );
        let anchor = m4
            .lifecycle_anchor(&request.workflow_id)
            .expect("load governance-bound lifecycle anchor");
        let binding = m3
            .schedule_binding(&anchor.schedule_id)
            .expect("load immutable lifecycle schedule");
        assert_eq!(
            binding
                .registration
                .deadline_at_ms
                .saturating_sub(binding.registration.due_at_ms),
            ANCHOR_LIFECYCLE_WINDOW_MS
        );
        assert_eq!(
            ANCHOR_WAIT_TIMEOUT.as_millis(),
            u128::from(ANCHOR_LIFECYCLE_WINDOW_MS)
        );

        let mut changed = request;
        changed.governance_context_digest =
            ContentDigest::from_bytes(b"different-governance-context");
        assert!(matches!(
            m4.prepare_reference_workflow(&changed),
            Err(M4RuntimeError::Conflict(_))
        ));

        m2.stop().expect("stop context-conflict M2");
    }

    #[test]
    fn persisted_prepared_governance_context_tamper_is_rejected() {
        let test = TestRoot::new("governance-context-tamper");
        let Harness {
            m2,
            m3,
            m4_config,
            m4,
            ..
        } = harness(&test, "governance-context-tamper");
        let request = workflow_request("governance-context-tamper", 10);
        m4.prepare_reference_workflow(&request)
            .expect("prepare governance-bound workflow");
        let bridge_root = m4_config.root.join("bridge");
        let state_path = bridge_root.join(BRIDGE_STATE_FILE);
        drop(m4);

        let mut state: BridgeState = read_json(&state_path).expect("read bridge state");
        state
            .workflows
            .get_mut(&request.workflow_id)
            .expect("prepared workflow")
            .governance_context_digest = ContentDigest::from_bytes(b"tampered-governance-context");
        write_json_atomic(&bridge_root, &state_path, &state)
            .expect("persist governance-context tamper");

        assert!(matches!(
            M4Runtime::open(m4_config, Arc::clone(&m3)),
            Err(M4RuntimeError::Integrity(_))
        ));

        drop(m3);
        m2.stop().expect("stop context-tamper M2");
    }

    #[test]
    fn bridge_crash_fault_preserves_the_unjournaled_lease_at_tick_zero() {
        let test = TestRoot::new("bridge-crash-tick-zero");
        let Harness { m2, m3, m4, .. } = harness(&test, "bridge-crash-tick-zero");
        let spec = m4
            .prepare_reference_workflow(&workflow_request("bridge-crash-tick-zero", 0))
            .expect("prepare tick-zero crash workflow");
        let request_id = "bridge-crash-tick-zero";
        m4.inject_fault(
            request_id,
            M4Fault::BridgeCrashAfterInnerReceiptsOnce {
                completed_receipts: 1,
            },
        )
        .expect("arm tick-zero bridge crash");
        let job_id = m4
            .enqueue(
                plan_request(&spec, &m4.config().factory_id, request_id, 0),
                0,
            )
            .expect("enqueue tick-zero planner");

        let dispatch = m4.dispatch_next(0);
        assert!(
            matches!(
                dispatch,
                Err(M4RuntimeError::Worker(WorkerRuntimeError::InvalidRequest(
                    _
                )))
            ),
            "the crash seam must reject its deliberately invalid executor handle at tick zero: {dispatch:?}"
        );
        let job = m4.load_job(&job_id).expect("reload tick-zero job");
        assert_eq!(job.status, JobStatus::Leased);
        let execution_id = job
            .active_execution_id
            .expect("the unjournaled execution remains leased");
        let execution = m4
            .load_execution(&execution_id)
            .expect("reload tick-zero execution");
        assert_eq!(execution.status, ExecutionStatus::Leased);
        assert!(execution.capability_receipts.is_empty());
        let progress = m4
            .bridge_progress(&execution_id)
            .expect("inspect tick-zero bridge progress");
        assert_eq!(progress.completed_inner_receipt_digests.len(), 1);
        assert!(progress.recorded_inner_receipt_digests.is_empty());
        assert!(!progress.outer_receipt_committed);

        drop(m4);
        drop(m3);
        m2.stop().expect("stop tick-zero crash M2");
    }

    #[test]
    fn completed_outer_evidence_is_rederived_from_exact_inner_receipts_on_reopen() {
        let test = TestRoot::new("resealed-outer-tamper");
        let Harness {
            m2,
            m3,
            m4_config,
            m4,
            ..
        } = harness(&test, "resealed-outer-tamper");
        let spec = m4
            .prepare_reference_workflow(&workflow_request("resealed-outer-tamper", 10))
            .expect("prepare tamper workflow");
        let job_id = m4
            .enqueue(
                plan_request(&spec, &m4.config().factory_id, "resealed-outer-tamper", 20),
                20,
            )
            .expect("enqueue tamper planner");
        let report = m4
            .dispatch_next(20)
            .expect("dispatch tamper planner")
            .expect("tamper planner dispatch report");
        assert_eq!(report.job_id, job_id);
        assert_eq!(report.status, JobStatus::Completed);
        let execution_id = report.execution_id;
        let bridge_root = m4_config.root.join("bridge");
        let state_path = bridge_root.join(BRIDGE_STATE_FILE);
        drop(m4);

        let mut state: BridgeState = read_json(&state_path).expect("read bridge state");
        let pending = state
            .executions
            .get_mut(&execution_id)
            .expect("completed planner bridge evidence");
        let forged_plan_digest = ContentDigest::from_bytes(b"resealed-forged-plan");
        let M4ActualOutput::Planner { plan_digest, .. } = &mut pending.actual else {
            panic!("planner execution must retain planner actual evidence");
        };
        *plan_digest = forged_plan_digest.clone();
        let mut response: crate::worker_runtime::WorkerServiceResponse =
            serde_json::from_slice(&pending.outer_receipt.output)
                .expect("decode planner outer response");
        let crate::worker_runtime::WorkerServiceResponse::Plan { plan_digest, .. } = &mut response
        else {
            panic!("planner receipt must contain a planner response");
        };
        *plan_digest = forged_plan_digest;
        pending.outer_receipt.output =
            serde_json::to_vec(&response).expect("encode forged planner response");
        pending.outer_receipt.output_digest =
            ContentDigest::from_bytes(&pending.outer_receipt.output);
        pending.outer_receipt.receipt_id = pending
            .outer_receipt
            .recompute_receipt_id()
            .expect("reseal forged outer receipt");
        write_json_atomic(&bridge_root, &state_path, &state).expect("persist resealed tamper");

        match M4Runtime::open(m4_config, Arc::clone(&m3)) {
            Err(M4RuntimeError::Integrity(detail)) => assert!(
                detail.contains("not derivable from its exact inner receipts"),
                "unexpected integrity diagnosis: {detail}"
            ),
            Err(other) => panic!("unexpected reopen failure: {other}"),
            Ok(_) => panic!("reopening must reject resealed evidence not derived from M3"),
        }

        drop(m3);
        m2.stop().expect("stop resealed-tamper M2");
    }

    #[test]
    fn six_role_reference_run_uses_real_m3_artifacts_and_survives_restart() {
        let test = TestRoot::new("reference");
        let Harness {
            m2_config,
            m3_config,
            m4_config,
            m2,
            m3,
            m4,
        } = harness(&test, "reference");
        let request = workflow_request("reference", 10);
        let spec = m4
            .prepare_reference_workflow(&request)
            .expect("prepare real M2/M3 prerequisite");
        let evidence = m4
            .run_reference_workflow(spec, 10)
            .expect("run integrated six-role workflow");
        let governance_context_digest = request.governance_context_digest.clone();

        assert_eq!(evidence.worker.job_ids.len(), 6);
        assert_eq!(
            evidence.governance_context_digest,
            governance_context_digest
        );
        assert_eq!(
            evidence.worker.governance_context_digest,
            governance_context_digest
        );
        for (job_id, execution_id) in evidence
            .worker
            .job_ids
            .iter()
            .zip(&evidence.worker.execution_ids)
        {
            let job = m4.load_job(job_id).expect("reload governance-bound job");
            assert_eq!(
                job.request.governance_context_digest,
                governance_context_digest
            );
            let execution = m4
                .load_execution(execution_id)
                .expect("reload governance-bound execution");
            assert_eq!(execution.job_id, *job_id);
            assert_eq!(
                execution.governance_context_digest,
                governance_context_digest
            );
        }
        assert_eq!(
            evidence
                .worker
                .execution_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len(),
            6
        );
        assert_eq!(
            evidence
                .worker
                .worker_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len(),
            6
        );
        assert_eq!(
            evidence.worker.synthesis.cited_result_digests,
            evidence.worker.result_digests
        );
        assert_eq!(
            evidence.worker.synthesis.cited_roles,
            GovernedWorkerRole::ALL
        );
        assert_eq!(evidence.executions.len(), 6);
        assert!(
            evidence.executions.iter().all(|execution| {
                execution.governance_context_digest == governance_context_digest
            })
        );
        assert!(
            evidence.package_executions.iter().all(|execution| {
                execution.governance_context_digest == governance_context_digest
            })
        );
        assert_eq!(
            evidence
                .executions
                .iter()
                .map(|item| item.role)
                .collect::<Vec<_>>(),
            GovernedWorkerRole::ALL
        );

        let mut families = BTreeSet::new();
        for execution in &evidence.executions {
            assert!(
                !execution.service_attestations.is_empty(),
                "every worker cites at least one actual M3 invocation"
            );
            for attestation in &execution.service_attestations {
                assert!(attestation.terminal_success);
                assert_ne!(
                    attestation.attestation_digest,
                    ContentDigest::from_bytes(&[])
                );
                families.insert(attestation.family);
                assert!(
                    m3.root()
                        .join("host")
                        .join(&attestation.provenance.receipt_ref)
                        .is_file(),
                    "attestation cites a durable M3 receipt"
                );
            }
            let result = m4
                .load_result(&execution.worker_result_digest)
                .expect("reload exact worker result");
            assert_eq!(result.governance_context_digest, governance_context_digest);
            assert_eq!(
                result.recompute_digest().expect("recompute result"),
                execution.worker_result_digest
            );
            assert!(!result.capability_receipt_digests.is_empty());
        }
        assert!(families.contains(&NativeServiceFamily::Build));
        assert!(families.contains(&NativeServiceFamily::Validation));
        assert!(families.contains(&NativeServiceFamily::Review));
        assert!(families.contains(&NativeServiceFamily::Packaging));
        assert!(families.contains(&NativeServiceFamily::Continuity));
        assert!(matches!(
            evidence.executions[1].actual,
            M4ActualOutput::Builder { .. }
        ));
        assert!(matches!(
            evidence.executions[2].actual,
            M4ActualOutput::Validator { passed: true, .. }
        ));
        assert!(matches!(
            evidence.executions[3].actual,
            M4ActualOutput::Reviewer { approved: true, .. }
        ));
        wait_for_m2_success(&m3, &evidence.lifecycle_anchor.schedule_id);
        let anchor_job = m3
            .scheduled_job(&evidence.lifecycle_anchor.schedule_id)
            .expect("load M2 anchor")
            .expect("M2 anchor exists");
        assert_eq!(anchor_job.job_id, evidence.lifecycle_anchor.m2_job_id);
        assert_eq!(anchor_job.phase, JobPhase::Succeeded);

        let result_digests = evidence.worker.result_digests.clone();
        let expected_evidence = evidence.executions.clone();
        drop(m4);
        drop(m3);
        m2.stop().expect("stop first M2 owner");
        drop(m2);

        let restarted_m2 = Arc::new(M2Runtime::new(m2_config).expect("construct restarted M2"));
        let restarted_m3 = Arc::new(
            M3CapabilityRuntime::open(m3_config, Arc::clone(&restarted_m2)).expect("reopen M3"),
        );
        let restarted = M4Runtime::open(m4_config, Arc::clone(&restarted_m3)).expect("reopen M4");
        restarted
            .ensure_reference_workers(100)
            .expect("worker registrations are idempotently present");
        for (digest, expected) in result_digests.iter().zip(expected_evidence) {
            assert_eq!(
                restarted
                    .execution_evidence(digest)
                    .expect("reload M3 evidence after restart"),
                expected
            );
            restarted
                .load_result(digest)
                .expect("reload worker result after restart");
        }
        assert!(
            restarted
                .dispatch_next(200)
                .expect("no duplicate dispatch")
                .is_none()
        );
        restarted_m2.stop().expect("stop restarted M2");
    }

    #[test]
    fn trap_crash_timeout_conflict_stale_lease_and_cancellation_are_visible_and_recoverable() {
        let test = TestRoot::new("failures");
        let Harness {
            m2,
            m3: _m3,
            m4_config,
            m4,
            ..
        } = harness(&test, "failures");
        let spec = m4
            .prepare_reference_workflow(&workflow_request("failures", 10))
            .expect("prepare failure workflow");

        for (ordinal, fault, class) in [
            (0_u64, M4Fault::TrapOnce, "trap"),
            (2, M4Fault::CrashOnce, "crash"),
            (4, M4Fault::TimeoutOnce, "timeout"),
        ] {
            let request_id = format!("{class}-once");
            m4.inject_fault(&request_id, fault)
                .expect("inject bounded failure");
            let tick = 10 + ordinal;
            let job_id = m4
                .enqueue(
                    plan_request(&spec, &m4.config().factory_id, &request_id, tick),
                    tick,
                )
                .expect("enqueue failure probe");
            dispatch_retry_to_completion(&m4, &job_id, tick);
            let job = m4.load_job(&job_id).expect("load recovered job");
            assert_eq!(job.failures.len(), 1);
            assert_eq!(job.failures[0].class, class);
            assert!(job.failures[0].retry_scheduled);
        }

        let conflict_id = "conflicting-result";
        m4.inject_fault(conflict_id, M4Fault::ConflictingResultOnce)
            .expect("inject result conflict");
        let conflict_job = m4
            .enqueue(
                plan_request(&spec, &m4.config().factory_id, conflict_id, 20),
                20,
            )
            .expect("enqueue conflict");
        assert!(matches!(
            m4.dispatch_next(20),
            Err(M4RuntimeError::Worker(WorkerRuntimeError::Conflict(_)))
        ));
        let conflict_execution = m4
            .load_job(&conflict_job)
            .expect("conflict job remains durable")
            .active_execution_id
            .expect("conflict execution remains leased");
        let recovered = m4
            .reconcile_in_flight(21)
            .expect("reconcile exact conflicting execution");
        assert_eq!(recovered.recovered_result_digests.len(), 1);
        assert_eq!(
            m4.load_job(&conflict_job).expect("conflict job").status,
            JobStatus::Completed
        );
        assert_eq!(
            m4.load_execution(&conflict_execution)
                .expect("same conflict execution")
                .status,
            crate::worker_runtime::ExecutionStatus::Completed
        );
        let recovered_digest = recovered.recovered_result_digests[0].clone();
        let recovered_result = m4
            .load_result(&recovered_digest)
            .expect("load conflict-recovered result");
        let mut missing_evidence = recovered_result.clone();
        missing_evidence.execution_id = "invented-execution".to_string();
        missing_evidence.result_digest = missing_evidence
            .recompute_digest()
            .expect("digest invented missing-evidence result");
        assert!(matches!(
            m4.bridge.bind_result(&missing_evidence),
            Err(M4RuntimeError::Integrity(_))
        ));
        let mut fake_success = recovered_result;
        if let WorkOutput::Plan { plan_digest, .. } = &mut fake_success.output {
            *plan_digest = ContentDigest::from_bytes(b"caller-authored-plan");
        }
        fake_success.result_digest = fake_success
            .recompute_digest()
            .expect("digest caller-authored fake result");
        assert!(matches!(
            m4.bridge.bind_result(&fake_success),
            Err(M4RuntimeError::Integrity(_))
        ));

        let stale_id = "stale-lease";
        m4.inject_fault(stale_id, M4Fault::Hold)
            .expect("inject held execution");
        let stale_job = m4
            .enqueue(
                plan_request(&spec, &m4.config().factory_id, stale_id, 30),
                30,
            )
            .expect("enqueue held execution");
        let held = m4
            .dispatch_next(30)
            .expect("dispatch held worker")
            .expect("held report");
        assert_eq!(held.status, JobStatus::Running);
        m4.mark_execution_lost(&held.execution_id)
            .expect("mark external execution lost");
        drop(m4);

        let reopened =
            Arc::new(M4Runtime::open(m4_config, Arc::clone(&_m3)).expect("restart M4 after loss"));
        let reconciliation = reopened
            .reconcile_in_flight(42)
            .expect("reconcile stale lease after restart");
        assert_eq!(reconciliation.retried_job_ids, vec![stale_job.clone()]);
        let stale = reopened.load_job(&stale_job).expect("stale job");
        assert_eq!(stale.status, JobStatus::RetryPending);
        assert_eq!(
            stale.failures.last().expect("stale failure").class,
            "stale_lease"
        );
        let recovered_stale = reopened
            .dispatch_next(43)
            .expect("retry stale work")
            .expect("stale retry report");
        assert_eq!(recovered_stale.status, JobStatus::Completed);

        let cancellation_id = "cancel-held";
        reopened
            .inject_fault(cancellation_id, M4Fault::Hold)
            .expect("inject cancellable hold");
        let cancellation_request =
            plan_request(&spec, &reopened.config().factory_id, cancellation_id, 50);
        let cancellation_token = format!("cancel-{cancellation_id}");
        let cancellation_job = reopened
            .enqueue(cancellation_request, 50)
            .expect("enqueue cancellable job");
        let cancellation_execution = reopened
            .dispatch_next(50)
            .expect("dispatch cancellable worker")
            .expect("cancellable report");
        reopened
            .cancel(&cancellation_job, &cancellation_token, 51)
            .expect("cancel exact worker execution");
        assert_eq!(
            reopened
                .load_job(&cancellation_job)
                .expect("cancelled job")
                .status,
            JobStatus::Cancelled
        );
        assert_eq!(
            reopened
                .load_execution(&cancellation_execution.execution_id)
                .expect("cancelled execution")
                .status,
            crate::worker_runtime::ExecutionStatus::Cancelled
        );

        let invented = ContentDigest::from_bytes(b"invented-worker-result");
        let mut escaped = plan_request(&spec, &reopened.config().factory_id, "scope-escape", 60);
        escaped.role = GovernedWorkerRole::Builder;
        escaped.capability_envelope = spec
            .capability_envelopes
            .get(&GovernedWorkerRole::Builder)
            .expect("builder envelope")
            .clone();
        escaped.input = WorkInput::Build {
            plan_result_digest: invented,
            target_relative_path: PathBuf::from("../escape.wat"),
            expected_before_digest: spec.expected_before_digest.clone(),
            replacement_bytes: spec.replacement_bytes.clone(),
        };
        assert!(matches!(
            reopened.enqueue(escaped, 60),
            Err(M4RuntimeError::Worker(
                WorkerRuntimeError::InvalidRequest(_) | WorkerRuntimeError::NotFound(_)
            ))
        ));
        m2.stop().expect("stop failure-test M2");
    }

    #[test]
    fn fleet_enforces_global_and_per_factory_limits_with_fair_active_workers() {
        let test = TestRoot::new("fleet");
        let left = harness(&test, "fleet-left");
        let right = harness(&test, "fleet-right");
        let left_spec = left
            .m4
            .prepare_reference_workflow(&workflow_request("fleet-left", 10))
            .expect("prepare left workflow");
        let right_spec = right
            .m4
            .prepare_reference_workflow(&workflow_request("fleet-right", 10))
            .expect("prepare right workflow");

        for (runtime, spec, prefix) in [
            (&left.m4, &left_spec, "left"),
            (&right.m4, &right_spec, "right"),
        ] {
            for (ordinal, tick) in [(1, 10_u64), (2, 12_u64)] {
                let request_id = format!("{prefix}-hold-{ordinal}");
                runtime
                    .inject_fault(&request_id, M4Fault::Hold)
                    .expect("inject fleet hold");
                runtime
                    .enqueue(
                        plan_request(spec, &runtime.config().factory_id, &request_id, tick),
                        10,
                    )
                    .expect("enqueue fleet worker");
            }
        }

        let fleet = M4Fleet::open(
            test.path.join("fleet-coordinator"),
            M4FleetLimits {
                global_max_active: 2,
                per_factory_max_active: 1,
            },
            vec![Arc::clone(&left.m4), Arc::clone(&right.m4)],
        )
        .expect("open bounded fleet");
        let first = fleet
            .dispatch_next(10)
            .expect("first fleet dispatch")
            .expect("first report");
        let second = fleet
            .dispatch_next(10)
            .expect("second fleet dispatch")
            .expect("second report");
        assert_ne!(first.0, second.0);
        assert_eq!(fleet.active_count().expect("fleet active count"), 2);
        assert_eq!(left.m4.active_count().expect("left active"), 1);
        assert_eq!(right.m4.active_count().expect("right active"), 1);
        assert!(
            fleet
                .dispatch_next(10)
                .expect("global limit check")
                .is_none()
        );

        left.m4
            .release_execution(if first.0 == left.m4.config().factory_id {
                &first.1.execution_id
            } else {
                &second.1.execution_id
            })
            .expect("release left worker");
        right
            .m4
            .release_execution(if first.0 == right.m4.config().factory_id {
                &first.1.execution_id
            } else {
                &second.1.execution_id
            })
            .expect("release right worker");
        assert_eq!(
            left.m4
                .reconcile_in_flight(11)
                .expect("finish left")
                .recovered_result_digests
                .len(),
            1
        );
        assert_eq!(
            right
                .m4
                .reconcile_in_flight(11)
                .expect("finish right")
                .recovered_result_digests
                .len(),
            1
        );
        assert_eq!(fleet.active_count().expect("no active workers"), 0);

        let third = fleet
            .dispatch_next(12)
            .expect("third fleet dispatch")
            .expect("third report");
        let fourth = fleet
            .dispatch_next(12)
            .expect("fourth fleet dispatch")
            .expect("fourth report");
        assert_ne!(third.0, fourth.0);
        assert_eq!(third.0, first.0, "durable round-robin resumes fairly");
        assert_eq!(fleet.active_count().expect("second active pair"), 2);
        assert_eq!(left.m4.pending_count().expect("left pending"), 0);
        assert_eq!(right.m4.pending_count().expect("right pending"), 0);

        left.m2.stop().expect("stop left M2");
        right.m2.stop().expect("stop right M2");
    }

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts/fixtures/m1-reference-component")
    }
}
