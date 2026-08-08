//! Durable, governed worker execution for the bounded local worker ecology.
//!
//! This module deliberately does not make workers into threads or processes.
//! It makes the boundary that matters explicit: every worker has an executable
//! package identity, a separately leased execution, a capability membrane, a
//! typed result, and durable terminal evidence. An injected executor may use a
//! component host, provider driver, native process, or an in-process reference
//! adapter, but none of those implementations can manufacture a successful
//! result without going through the injected capability-service membrane.

use crate::execution::artifact::{ContentDigest, digest_json_content};
use crate::execution::{
    ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityWorld, IsolationProfile,
    WorkerRole, WorkerRoleKind,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const STATE_SCHEMA_VERSION: u32 = 2;
const STATE_FILE_NAME: &str = "worker-runtime-state.json";
const STORE_LOCK_FILE_NAME: &str = ".worker-runtime.lock";
const MAX_REQUESTED_FUTURE_TICK_DRIFT: u64 = 10_000;
pub(crate) const REFERENCE_SERVICE_SCHEMA: &str = "wasmbiotic.worker-service/v2";

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// The canonical M4 vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedWorkerRole {
    Planner,
    Builder,
    Validator,
    Reviewer,
    Packager,
    ContinuityWorker,
}

impl GovernedWorkerRole {
    pub const ALL: [Self; 6] = [
        Self::Planner,
        Self::Builder,
        Self::Validator,
        Self::Reviewer,
        Self::Packager,
        Self::ContinuityWorker,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planner => "planner",
            Self::Builder => "builder",
            Self::Validator => "validator",
            Self::Reviewer => "reviewer",
            Self::Packager => "packager",
            Self::ContinuityWorker => "continuity_worker",
        }
    }

    pub fn ecology_role(self) -> WorkerRoleKind {
        match self {
            Self::Planner => WorkerRoleKind::Planner,
            Self::Builder => WorkerRoleKind::Builder,
            Self::Validator => WorkerRoleKind::Validator,
            Self::Reviewer => WorkerRoleKind::Reviewer,
            Self::Packager => WorkerRoleKind::Packager,
            Self::ContinuityWorker => WorkerRoleKind::ContinuityWorker,
        }
    }

    pub fn legacy_role(self) -> WorkerRole {
        match self {
            Self::Planner => WorkerRole::ObserverWorker,
            Self::Builder => WorkerRole::MutatorWorker,
            Self::Validator => WorkerRole::EvaluatorWorker,
            Self::Reviewer => WorkerRole::ReviewerWorker,
            Self::Packager | Self::ContinuityWorker => WorkerRole::ConsolidatorWorker,
        }
    }

    pub fn legacy_qualifier(self) -> &'static str {
        match self {
            Self::Planner => "planning_and_observation",
            Self::Builder => "candidate_workspace_mutation",
            Self::Validator => "independent_proving_and_evaluation",
            Self::Reviewer => "governed_review",
            Self::Packager => "artifact_consolidation_and_packaging",
            Self::ContinuityWorker => "continuity_consolidation_and_checkpointing",
        }
    }

    pub fn required_world(self) -> CapabilityWorld {
        match self {
            Self::Planner => CapabilityWorld::WorkspaceObserve,
            Self::Builder => CapabilityWorld::WorkspaceMutate,
            Self::Validator => CapabilityWorld::WorkspaceObserve,
            Self::Reviewer => CapabilityWorld::ReviewPromotion,
            Self::Packager => CapabilityWorld::ServiceOrganelle,
            Self::ContinuityWorker => CapabilityWorld::MemoryAccess,
        }
    }

    pub fn required_authority(self) -> AuthorityClass {
        match self {
            Self::Planner | Self::Validator => AuthorityClass::Observe,
            Self::Builder | Self::Packager | Self::ContinuityWorker => AuthorityClass::LocalMutate,
            Self::Reviewer => AuthorityClass::PromotionControl,
        }
    }

    pub fn service_family(self) -> &'static str {
        match self {
            Self::Planner => "scheduling",
            Self::Builder => "build",
            Self::Validator => "validation",
            Self::Reviewer => "review",
            Self::Packager => "packaging",
            Self::ContinuityWorker => "continuity",
        }
    }

    pub fn operation(self) -> &'static str {
        match self {
            Self::Planner => "plan",
            Self::Builder => "apply_candidate",
            Self::Validator => "prove_candidate",
            Self::Reviewer => "review_candidate",
            Self::Packager => "package_candidate",
            Self::ContinuityWorker => "checkpoint",
        }
    }
}

impl From<WorkerRoleKind> for GovernedWorkerRole {
    fn from(value: WorkerRoleKind) -> Self {
        match value {
            WorkerRoleKind::Planner => Self::Planner,
            WorkerRoleKind::Builder => Self::Builder,
            WorkerRoleKind::Validator => Self::Validator,
            WorkerRoleKind::Reviewer => Self::Reviewer,
            WorkerRoleKind::Packager => Self::Packager,
            WorkerRoleKind::ContinuityWorker => Self::ContinuityWorker,
        }
    }
}

/// An explicit, reversible binding across both pre-M4 role vocabularies.
///
/// `WorkerRole::ConsolidatorWorker` is intentionally qualified. Without that
/// qualifier, Packager and Continuity Worker would collapse into the same
/// legacy value and the mapping would be lossy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleVocabularyBinding {
    pub canonical_role: GovernedWorkerRole,
    pub ecology_role: WorkerRoleKind,
    pub legacy_role: WorkerRole,
    pub legacy_qualifier: String,
}

impl RoleVocabularyBinding {
    pub fn for_role(role: GovernedWorkerRole) -> Self {
        Self {
            canonical_role: role,
            ecology_role: role.ecology_role(),
            legacy_role: role.legacy_role(),
            legacy_qualifier: role.legacy_qualifier().to_string(),
        }
    }

    pub fn validate(&self) -> Result<(), WorkerRuntimeError> {
        let expected = Self::for_role(self.canonical_role);
        if self != &expected {
            return Err(WorkerRuntimeError::InvalidRegistration(format!(
                "role binding for '{}' does not preserve both existing vocabularies",
                self.canonical_role.as_str()
            )));
        }
        Ok(())
    }
}

pub fn role_vocabulary_bindings() -> Vec<RoleVocabularyBinding> {
    GovernedWorkerRole::ALL
        .into_iter()
        .map(RoleVocabularyBinding::for_role)
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableImplementationKind {
    WasmComponent,
    ProviderProfile,
    NativeAdapter,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageProvenance {
    pub source_digest: ContentDigest,
    pub build_record_digest: ContentDigest,
    pub producer_ref: String,
    pub built_at_tick: u64,
    pub signature_or_attestation_ref: String,
}

impl PackageProvenance {
    fn validate(&self) -> Result<(), WorkerRuntimeError> {
        require_nonempty("producer_ref", &self.producer_ref)?;
        require_nonempty(
            "signature_or_attestation_ref",
            &self.signature_or_attestation_ref,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableImplementation {
    pub kind: ExecutableImplementationKind,
    pub package_digest: ContentDigest,
    pub implementation_ref: String,
    pub entrypoint: String,
    pub provider_profile_ref: Option<String>,
    pub provenance: PackageProvenance,
}

impl ExecutableImplementation {
    fn validate(&self) -> Result<(), WorkerRuntimeError> {
        require_nonempty("implementation_ref", &self.implementation_ref)?;
        require_nonempty("entrypoint", &self.entrypoint)?;
        if matches!(self.kind, ExecutableImplementationKind::ProviderProfile) {
            require_nonempty(
                "provider_profile_ref",
                self.provider_profile_ref.as_deref().unwrap_or_default(),
            )?;
        } else if self.provider_profile_ref.is_some() {
            return Err(WorkerRuntimeError::InvalidRegistration(
                "only provider implementations may name a provider profile".to_string(),
            ));
        }
        self.provenance.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerExecutionPolicy {
    pub max_concurrency: usize,
    pub max_attempts: u32,
    pub lease_duration_ticks: u64,
    pub heartbeat_grace_ticks: u64,
    pub retry_backoff_ticks: u64,
    pub degrade_after_attempt: u32,
    pub retry_timeouts: bool,
}

impl WorkerExecutionPolicy {
    fn validate(&self) -> Result<(), WorkerRuntimeError> {
        if self.max_concurrency == 0
            || self.max_attempts == 0
            || self.lease_duration_ticks == 0
            || self.heartbeat_grace_ticks == 0
            || self.degrade_after_attempt == 0
        {
            return Err(WorkerRuntimeError::InvalidRegistration(
                "worker policy limits must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRegistration {
    pub worker_id: String,
    pub specialization_card_ref: String,
    pub role: GovernedWorkerRole,
    pub vocabulary_binding: RoleVocabularyBinding,
    pub executable: ExecutableImplementation,
    pub allowed_worlds: Vec<CapabilityWorld>,
    pub service_family_refs: Vec<String>,
    pub allowed_workspace_scopes: Vec<String>,
    pub authority_ceiling: AuthorityClass,
    pub isolation_profile: IsolationProfile,
    pub policy: WorkerExecutionPolicy,
    pub enabled: bool,
}

impl WorkerRegistration {
    pub fn validate(&self) -> Result<(), WorkerRuntimeError> {
        require_nonempty("worker_id", &self.worker_id)?;
        require_nonempty("specialization_card_ref", &self.specialization_card_ref)?;
        self.vocabulary_binding.validate()?;
        if self.vocabulary_binding.canonical_role != self.role {
            return Err(WorkerRuntimeError::InvalidRegistration(
                "specialization role and vocabulary binding disagree".to_string(),
            ));
        }
        self.executable.validate()?;
        self.policy.validate()?;
        require_unique_nonempty("service_family_refs", &self.service_family_refs)?;
        require_unique_nonempty("allowed_workspace_scopes", &self.allowed_workspace_scopes)?;
        if !self
            .allowed_worlds
            .iter()
            .any(|world| world == &self.role.required_world())
        {
            return Err(WorkerRuntimeError::InvalidRegistration(format!(
                "worker '{}' lacks its role's required capability world",
                self.worker_id
            )));
        }
        if !self
            .service_family_refs
            .iter()
            .any(|family| family == self.role.service_family())
        {
            return Err(WorkerRuntimeError::InvalidRegistration(format!(
                "worker '{}' does not resolve required service family '{}'",
                self.worker_id,
                self.role.service_family()
            )));
        }
        if !self.authority_ceiling.ge(&self.role.required_authority()) {
            return Err(WorkerRuntimeError::InvalidRegistration(format!(
                "worker '{}' authority ceiling is below its role requirement",
                self.worker_id
            )));
        }
        Ok(())
    }

    fn permits_scope(&self, scope: &WorkspaceScope) -> bool {
        self.allowed_workspace_scopes
            .iter()
            .any(|allowed| allowed == "*" || allowed == &scope.scope_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceScope {
    pub scope_id: String,
    pub workspace_root: PathBuf,
    pub resource_scopes: Vec<String>,
}

impl WorkspaceScope {
    fn validate(&self) -> Result<(), WorkerRuntimeError> {
        require_nonempty("scope_id", &self.scope_id)?;
        if !self.workspace_root.is_absolute() {
            return Err(WorkerRuntimeError::InvalidRequest(
                "workspace_root must be absolute".to_string(),
            ));
        }
        require_unique_nonempty("resource_scopes", &self.resource_scopes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkBudget {
    pub max_attempts: u32,
    pub max_capability_calls: u32,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_runtime_ticks: u64,
}

impl WorkBudget {
    pub(crate) fn validate(&self) -> Result<(), WorkerRuntimeError> {
        if self.max_attempts == 0
            || self.max_capability_calls == 0
            || self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_runtime_ticks == 0
        {
            return Err(WorkerRuntimeError::InvalidRequest(
                "all work budget limits must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkDeadline {
    pub not_before_tick: u64,
    pub expires_at_tick: u64,
}

impl WorkDeadline {
    pub(crate) fn validate(&self) -> Result<(), WorkerRuntimeError> {
        if self.expires_at_tick <= self.not_before_tick {
            return Err(WorkerRuntimeError::InvalidRequest(
                "deadline must expire after its not-before tick".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationToken {
    pub credential_digest: ContentDigest,
}

impl CancellationToken {
    /// Derive the durable cancellation credential from a caller-held secret.
    ///
    /// The raw secret is intentionally neither retained nor serialised.
    pub fn from_secret(secret: &str) -> Self {
        Self {
            credential_digest: ContentDigest::from_bytes(secret.as_bytes()),
        }
    }

    fn matches_secret(&self, presented_secret: &str) -> bool {
        self.credential_digest == ContentDigest::from_bytes(presented_secret.as_bytes())
    }

    fn validate(&self) -> Result<(), WorkerRuntimeError> {
        if self.matches_secret("") {
            return Err(WorkerRuntimeError::InvalidRequest(
                "cancellation credential must be non-empty".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkInput {
    Plan {
        objective: String,
        baseline_digest: ContentDigest,
    },
    Build {
        plan_result_digest: ContentDigest,
        target_relative_path: PathBuf,
        expected_before_digest: ContentDigest,
        replacement_bytes: Vec<u8>,
    },
    Validate {
        plan_result_digest: ContentDigest,
        build_result_digest: ContentDigest,
        target_relative_path: PathBuf,
        expected_artifact_digest: ContentDigest,
        suite_digest: ContentDigest,
    },
    Review {
        plan_result_digest: ContentDigest,
        build_result_digest: ContentDigest,
        validation_result_digest: ContentDigest,
    },
    Package {
        build_result_digest: ContentDigest,
        validation_result_digest: ContentDigest,
        review_result_digest: ContentDigest,
    },
    Continue {
        package_result_digest: ContentDigest,
        synthesis_seed_digest: ContentDigest,
    },
}

impl WorkInput {
    pub fn role(&self) -> GovernedWorkerRole {
        match self {
            Self::Plan { .. } => GovernedWorkerRole::Planner,
            Self::Build { .. } => GovernedWorkerRole::Builder,
            Self::Validate { .. } => GovernedWorkerRole::Validator,
            Self::Review { .. } => GovernedWorkerRole::Reviewer,
            Self::Package { .. } => GovernedWorkerRole::Packager,
            Self::Continue { .. } => GovernedWorkerRole::ContinuityWorker,
        }
    }

    pub fn result_citations(&self) -> Vec<&ContentDigest> {
        match self {
            Self::Plan { .. } => Vec::new(),
            Self::Build {
                plan_result_digest, ..
            } => vec![plan_result_digest],
            Self::Validate {
                plan_result_digest,
                build_result_digest,
                ..
            } => vec![plan_result_digest, build_result_digest],
            Self::Review {
                plan_result_digest,
                build_result_digest,
                validation_result_digest,
            } => vec![
                plan_result_digest,
                build_result_digest,
                validation_result_digest,
            ],
            Self::Package {
                build_result_digest,
                validation_result_digest,
                review_result_digest,
            } => vec![
                build_result_digest,
                validation_result_digest,
                review_result_digest,
            ],
            Self::Continue {
                package_result_digest,
                ..
            } => vec![package_result_digest],
        }
    }

    fn validate(&self) -> Result<(), WorkerRuntimeError> {
        match self {
            Self::Plan { objective, .. } => require_nonempty("objective", objective),
            Self::Build {
                target_relative_path,
                replacement_bytes,
                ..
            } => {
                validate_relative_path(target_relative_path)?;
                if replacement_bytes.is_empty() {
                    return Err(WorkerRuntimeError::InvalidRequest(
                        "builder replacement bytes are empty".to_string(),
                    ));
                }
                Ok(())
            }
            Self::Validate {
                target_relative_path,
                ..
            } => validate_relative_path(target_relative_path),
            Self::Review { .. } | Self::Package { .. } | Self::Continue { .. } => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewDecision {
    Approve,
    Reject,
    Escalate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkOutput {
    Plan {
        baseline_digest: ContentDigest,
        plan_digest: ContentDigest,
    },
    Build {
        plan_result_digest: ContentDigest,
        before_digest: ContentDigest,
        artifact_digest: ContentDigest,
    },
    Validate {
        plan_result_digest: ContentDigest,
        build_result_digest: ContentDigest,
        artifact_digest: ContentDigest,
        proving_digest: ContentDigest,
        passed: bool,
    },
    Review {
        build_result_digest: ContentDigest,
        validation_result_digest: ContentDigest,
        decision: ReviewDecision,
        review_digest: ContentDigest,
    },
    Package {
        build_result_digest: ContentDigest,
        validation_result_digest: ContentDigest,
        review_result_digest: ContentDigest,
        package_digest: ContentDigest,
    },
    Continue {
        package_result_digest: ContentDigest,
        checkpoint_digest: ContentDigest,
    },
}

impl WorkOutput {
    pub fn role(&self) -> GovernedWorkerRole {
        match self {
            Self::Plan { .. } => GovernedWorkerRole::Planner,
            Self::Build { .. } => GovernedWorkerRole::Builder,
            Self::Validate { .. } => GovernedWorkerRole::Validator,
            Self::Review { .. } => GovernedWorkerRole::Reviewer,
            Self::Package { .. } => GovernedWorkerRole::Packager,
            Self::Continue { .. } => GovernedWorkerRole::ContinuityWorker,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerJobRequest {
    pub request_id: String,
    pub role: GovernedWorkerRole,
    pub governance_context_digest: ContentDigest,
    pub input: WorkInput,
    pub capability_envelope: CapabilityEnvelope,
    pub workspace_scope: WorkspaceScope,
    pub budget: WorkBudget,
    pub deadline: WorkDeadline,
    pub cancellation_token: CancellationToken,
    pub fairness_key: String,
    pub priority: u8,
}

impl WorkerJobRequest {
    fn validate(&self) -> Result<(), WorkerRuntimeError> {
        require_nonempty("request_id", &self.request_id)?;
        self.cancellation_token.validate()?;
        require_nonempty("fairness_key", &self.fairness_key)?;
        if self.role != self.input.role() {
            return Err(WorkerRuntimeError::InvalidRequest(
                "job role does not match its typed input".to_string(),
            ));
        }
        self.input.validate()?;
        self.workspace_scope.validate()?;
        self.budget.validate()?;
        self.deadline.validate()?;
        validate_envelope(self)?;
        let encoded = serde_json::to_vec(&self.input)
            .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
        if encoded.len() as u64 > self.budget.max_input_bytes {
            return Err(WorkerRuntimeError::BudgetExceeded(
                "typed input exceeds max_input_bytes".to_string(),
            ));
        }
        Ok(())
    }
}

/// Re-derive the exact durable input identity used by worker admission,
/// package execution, capability dispatch, retries, and terminal results.
///
/// The governance context is deliberately part of the input identity rather
/// than metadata beside it: changing the context changes the job, package
/// execution marker, capability request, and every downstream result digest.
pub fn governed_work_input_digest(
    governance_context_digest: &ContentDigest,
    input: &WorkInput,
) -> Result<ContentDigest, WorkerRuntimeError> {
    digest_json_content(&(
        "wasm-biotic:governed-worker-input:v2",
        governance_context_digest,
        input,
    ))
    .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityInvocationRequest {
    pub execution_id: String,
    pub acquired_at_tick: u64,
    pub effect_started_at_tick: u64,
    pub worker_id: String,
    pub role: GovernedWorkerRole,
    pub governance_context_digest: ContentDigest,
    pub service_family: String,
    pub world: CapabilityWorld,
    pub operation: String,
    pub required_authority: AuthorityClass,
    pub capability_envelope: CapabilityEnvelope,
    pub workspace_scope: WorkspaceScope,
    pub work_budget: WorkBudget,
    pub deadline: WorkDeadline,
    pub resource_scope: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityInvocationReceipt {
    pub receipt_id: String,
    pub execution_id: String,
    pub worker_id: String,
    pub service_family: String,
    pub operation: String,
    pub governance_context_digest: ContentDigest,
    pub implementation_ref: String,
    pub implementation_digest: ContentDigest,
    pub capability_envelope_digest: ContentDigest,
    pub work_budget_digest: ContentDigest,
    pub deadline_digest: ContentDigest,
    pub input_digest: ContentDigest,
    pub output: Vec<u8>,
    pub output_digest: ContentDigest,
    pub effect_started_at_tick: u64,
    pub completed_at_tick: u64,
}

impl CapabilityInvocationReceipt {
    fn expected_binding_digests(
        request: &CapabilityInvocationRequest,
    ) -> Result<(ContentDigest, ContentDigest, ContentDigest), CapabilityServiceFailure> {
        let envelope_digest = digest_json_content(&request.capability_envelope)
            .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))?;
        let budget_digest = digest_json_content(&request.work_budget)
            .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))?;
        let deadline_digest = digest_json_content(&request.deadline)
            .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))?;
        Ok((envelope_digest, budget_digest, deadline_digest))
    }

    pub(crate) fn recompute_receipt_id(&self) -> Result<String, CapabilityServiceFailure> {
        digest_json_content(&CapabilityReceiptMaterial {
            execution_id: &self.execution_id,
            worker_id: &self.worker_id,
            service_family: &self.service_family,
            operation: &self.operation,
            governance_context_digest: &self.governance_context_digest,
            implementation_ref: &self.implementation_ref,
            implementation_digest: &self.implementation_digest,
            capability_envelope_digest: &self.capability_envelope_digest,
            work_budget_digest: &self.work_budget_digest,
            deadline_digest: &self.deadline_digest,
            input_digest: &self.input_digest,
            output_digest: &self.output_digest,
            effect_started_at_tick: self.effect_started_at_tick,
            completed_at_tick: self.completed_at_tick,
        })
        .map(|digest| digest.to_string())
        .map_err(|error| CapabilityServiceFailure::InvalidReceipt(error.to_string()))
    }

    pub(crate) fn validate_integrity(&self) -> Result<(), CapabilityServiceFailure> {
        if self.receipt_id.trim().is_empty()
            || self.implementation_ref.trim().is_empty()
            || self.output_digest != ContentDigest::from_bytes(&self.output)
            || self.receipt_id != self.recompute_receipt_id()?
        {
            return Err(CapabilityServiceFailure::InvalidReceipt(
                "capability service receipt content or identity digest is invalid".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_for(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<(), CapabilityServiceFailure> {
        self.validate_bound_to(request, false)
    }

    fn validate_recovery_for(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<(), CapabilityServiceFailure> {
        self.validate_bound_to(request, true)
    }

    fn validate_bound_to(
        &self,
        request: &CapabilityInvocationRequest,
        recovering_prior_effect: bool,
    ) -> Result<(), CapabilityServiceFailure> {
        let (envelope_digest, budget_digest, deadline_digest) =
            Self::expected_binding_digests(request)?;
        self.validate_integrity()?;
        let runtime_limit = request
            .acquired_at_tick
            .saturating_add(request.work_budget.max_runtime_ticks);
        if self.receipt_id.trim().is_empty()
            || self.implementation_ref.trim().is_empty()
            || self.execution_id != request.execution_id
            || self.completed_at_tick < request.acquired_at_tick
            || self.effect_started_at_tick < request.acquired_at_tick
            || (!recovering_prior_effect
                && self.effect_started_at_tick > request.effect_started_at_tick)
            || self.completed_at_tick < self.effect_started_at_tick
            || self.effect_started_at_tick >= request.deadline.expires_at_tick
            || self.completed_at_tick >= request.deadline.expires_at_tick
            || self.effect_started_at_tick > runtime_limit
            || self.completed_at_tick > runtime_limit
            || self.worker_id != request.worker_id
            || self.service_family != request.service_family
            || self.operation != request.operation
            || self.governance_context_digest != request.governance_context_digest
            || self.capability_envelope_digest != envelope_digest
            || self.work_budget_digest != budget_digest
            || self.deadline_digest != deadline_digest
            || self.input_digest != ContentDigest::from_bytes(&request.payload)
        {
            return Err(CapabilityServiceFailure::InvalidReceipt(
                "capability service returned a mismatched or unverifiable receipt".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct CapabilityReceiptMaterial<'a> {
    execution_id: &'a str,
    worker_id: &'a str,
    service_family: &'a str,
    operation: &'a str,
    governance_context_digest: &'a ContentDigest,
    implementation_ref: &'a str,
    implementation_digest: &'a ContentDigest,
    capability_envelope_digest: &'a ContentDigest,
    work_budget_digest: &'a ContentDigest,
    deadline_digest: &'a ContentDigest,
    input_digest: &'a ContentDigest,
    output_digest: &'a ContentDigest,
    effect_started_at_tick: u64,
    completed_at_tick: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityServiceFailure {
    Denied(String),
    Unavailable(String),
    TimedOut(String),
    Failed(String),
    InvalidReceipt(String),
}

impl Display for CapabilityServiceFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(message) => write!(formatter, "capability denied: {message}"),
            Self::Unavailable(message) => write!(formatter, "capability unavailable: {message}"),
            Self::TimedOut(message) => write!(formatter, "capability timed out: {message}"),
            Self::Failed(message) => write!(formatter, "capability failed: {message}"),
            Self::InvalidReceipt(message) => {
                write!(formatter, "invalid capability receipt: {message}")
            }
        }
    }
}

impl Error for CapabilityServiceFailure {}

/// M3 implements this boundary. The runtime wraps it in a per-execution
/// membrane before exposing it to M2's executor.
pub trait CapabilityServiceInvoker: Send + Sync {
    fn invoke(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<CapabilityInvocationReceipt, CapabilityServiceFailure>;

    /// Return an already-durable receipt without beginning a new effect.
    ///
    /// Implementations must return `Ok(None)` when no exact prior receipt
    /// exists. Recovery is a read-only probe and must never fall through to
    /// ordinary invocation.
    fn recover(
        &self,
        _request: &CapabilityInvocationRequest,
    ) -> Result<Option<CapabilityInvocationReceipt>, CapabilityServiceFailure> {
        Ok(None)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerInvocation {
    pub job_id: String,
    pub execution_id: String,
    pub lease_id: String,
    pub attempt: u32,
    pub acquired_at_tick: u64,
    pub effect_started_at_tick: u64,
    pub registration: WorkerRegistration,
    pub request: WorkerJobRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutorOutcome {
    Running {
        executor_handle: String,
        heartbeat_tick: u64,
    },
    Completed {
        output: WorkOutput,
        completed_at_tick: u64,
    },
    Trapped {
        detail: String,
        failed_at_tick: u64,
    },
    Crashed {
        detail: String,
        failed_at_tick: u64,
    },
    TimedOut {
        detail: String,
        failed_at_tick: u64,
    },
    Cancelled {
        detail: String,
        failed_at_tick: u64,
    },
    Unavailable {
        detail: String,
        failed_at_tick: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutorReconciliation {
    StillRunning {
        executor_handle: String,
        heartbeat_tick: u64,
    },
    Terminal(ExecutorOutcome),
    Unknown {
        detail: String,
        observed_at_tick: u64,
    },
}

/// M2 implements this boundary. Implementations must use `capabilities` for
/// every effectful operation.
pub trait DurableJobExecutor: Send + Sync {
    fn dispatch(
        &self,
        invocation: &WorkerInvocation,
        capabilities: &dyn CapabilityServiceInvoker,
    ) -> ExecutorOutcome;

    fn reconcile(
        &self,
        invocation: &WorkerInvocation,
        capabilities: &dyn CapabilityServiceInvoker,
    ) -> ExecutorReconciliation;

    /// Recover an already-completed external effect without starting work.
    ///
    /// This probe runs before cancellation, deadline, and stale-lease fences.
    /// Implementations must return `Ok(None)` unless they can reconstruct
    /// terminal evidence from durable journals alone.
    fn recover_terminal(
        &self,
        _invocation: &WorkerInvocation,
        _capabilities: &dyn CapabilityServiceInvoker,
    ) -> Result<Option<ExecutorOutcome>, String> {
        Ok(None)
    }

    fn cancel(&self, execution_id: &str, cancellation_token: &str) -> Result<(), String>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerLease {
    pub lease_id: String,
    pub execution_id: String,
    pub worker_id: String,
    pub attempt: u32,
    pub acquired_at_tick: u64,
    pub expires_at_tick: u64,
    pub last_heartbeat_tick: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    RetryPending,
    Leased,
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl JobStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Leased,
    Running,
    Completed,
    Trapped,
    Crashed,
    TimedOut,
    Cancelled,
    Unavailable,
    Lost,
}

impl ExecutionStatus {
    fn is_active(&self) -> bool {
        matches!(self, Self::Leased | Self::Running)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureRecord {
    pub attempt: u32,
    pub worker_id: String,
    pub class: String,
    pub detail: String,
    pub observed_at_tick: u64,
    pub retry_scheduled: bool,
    pub degraded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWorkerJob {
    pub job_id: String,
    pub sequence: u64,
    pub request: WorkerJobRequest,
    pub input_digest: ContentDigest,
    pub status: JobStatus,
    pub attempts: u32,
    pub next_available_tick: u64,
    pub selected_worker_id: Option<String>,
    pub active_execution_id: Option<String>,
    pub result_digest: Option<ContentDigest>,
    pub failed_worker_ids: Vec<String>,
    pub failures: Vec<FailureRecord>,
    pub cancellation_requested_at_tick: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerExecutionRecord {
    pub execution_id: String,
    pub job_id: String,
    pub worker_id: String,
    pub role: GovernedWorkerRole,
    pub governance_context_digest: ContentDigest,
    pub implementation_package_digest: ContentDigest,
    pub implementation_ref: String,
    pub provenance: PackageProvenance,
    pub lease: WorkerLease,
    pub status: ExecutionStatus,
    pub executor_handle: Option<String>,
    pub capability_receipts: Vec<CapabilityInvocationReceipt>,
    pub result_digest: Option<ContentDigest>,
    pub terminal_detail: Option<String>,
    pub completed_at_tick: Option<u64>,
    pub last_reconciled_at_tick: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedWorkerResult {
    pub result_digest: ContentDigest,
    pub execution_id: String,
    pub job_id: String,
    pub worker_id: String,
    pub role: GovernedWorkerRole,
    pub governance_context_digest: ContentDigest,
    pub output: WorkOutput,
    pub capability_receipt_digests: Vec<ContentDigest>,
    pub implementation_package_digest: ContentDigest,
    pub implementation_ref: String,
    pub provenance: PackageProvenance,
    pub completed_at_tick: u64,
}

#[derive(Serialize)]
struct WorkerResultMaterial<'a> {
    execution_id: &'a str,
    job_id: &'a str,
    worker_id: &'a str,
    role: GovernedWorkerRole,
    governance_context_digest: &'a ContentDigest,
    output: &'a WorkOutput,
    capability_receipt_digests: &'a [ContentDigest],
    implementation_package_digest: &'a ContentDigest,
    implementation_ref: &'a str,
    provenance: &'a PackageProvenance,
    completed_at_tick: u64,
}

impl PersistedWorkerResult {
    pub fn recompute_digest(&self) -> Result<ContentDigest, WorkerRuntimeError> {
        digest_json_content(&WorkerResultMaterial {
            execution_id: &self.execution_id,
            job_id: &self.job_id,
            worker_id: &self.worker_id,
            role: self.role,
            governance_context_digest: &self.governance_context_digest,
            output: &self.output,
            capability_receipt_digests: &self.capability_receipt_digests,
            implementation_package_digest: &self.implementation_package_digest,
            implementation_ref: &self.implementation_ref,
            provenance: &self.provenance,
            completed_at_tick: self.completed_at_tick,
        })
        .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))
    }

    fn validate_digest(&self) -> Result<(), WorkerRuntimeError> {
        let actual = self.recompute_digest()?;
        if actual != self.result_digest {
            return Err(WorkerRuntimeError::Integrity(format!(
                "worker result '{}' does not match its persisted content",
                self.result_digest
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorSynthesis {
    pub synthesis_id: String,
    pub cited_result_digests: Vec<ContentDigest>,
    pub cited_execution_ids: Vec<String>,
    pub cited_roles: Vec<GovernedWorkerRole>,
    pub synthesis_digest: ContentDigest,
    pub created_at_tick: u64,
}

#[derive(Serialize)]
struct SynthesisMaterial<'a> {
    synthesis_id: &'a str,
    cited_result_digests: &'a [ContentDigest],
    cited_execution_ids: &'a [String],
    cited_roles: &'a [GovernedWorkerRole],
    created_at_tick: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub sequence: u64,
    pub tick: u64,
    pub class: String,
    pub job_id: Option<String>,
    pub execution_id: Option<String>,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WorkerRuntimeState {
    schema_version: u32,
    next_sequence: u64,
    #[serde(default = "default_next_logical_tick")]
    next_logical_tick: u64,
    registrations: BTreeMap<String, WorkerRegistration>,
    jobs: BTreeMap<String, StoredWorkerJob>,
    executions: BTreeMap<String, WorkerExecutionRecord>,
    results: BTreeMap<String, PersistedWorkerResult>,
    syntheses: BTreeMap<String, CoordinatorSynthesis>,
    events: Vec<RuntimeEvent>,
    last_fairness_key: Option<String>,
}

impl Default for WorkerRuntimeState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            next_sequence: 1,
            next_logical_tick: default_next_logical_tick(),
            registrations: BTreeMap::new(),
            jobs: BTreeMap::new(),
            executions: BTreeMap::new(),
            results: BTreeMap::new(),
            syntheses: BTreeMap::new(),
            events: Vec::new(),
            last_fairness_key: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerRuntimeError {
    InvalidRegistration(String),
    InvalidRequest(String),
    NotFound(String),
    Conflict(String),
    CapabilityDenied(String),
    BudgetExceeded(String),
    DeadlineExceeded(String),
    NoEligibleWorker(String),
    ExecutionFailed(String),
    Integrity(String),
    Serialization(String),
    Io { path: PathBuf, message: String },
    LockPoisoned,
}

impl WorkerRuntimeError {
    fn io(path: &Path, error: impl Display) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            message: error.to_string(),
        }
    }
}

impl Display for WorkerRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRegistration(message) => {
                write!(formatter, "invalid worker registration: {message}")
            }
            Self::InvalidRequest(message) => write!(formatter, "invalid worker request: {message}"),
            Self::NotFound(message) => write!(formatter, "not found: {message}"),
            Self::Conflict(message) => write!(formatter, "conflict: {message}"),
            Self::CapabilityDenied(message) => write!(formatter, "capability denied: {message}"),
            Self::BudgetExceeded(message) => write!(formatter, "budget exceeded: {message}"),
            Self::DeadlineExceeded(message) => write!(formatter, "deadline exceeded: {message}"),
            Self::NoEligibleWorker(message) => {
                write!(formatter, "no eligible worker: {message}")
            }
            Self::ExecutionFailed(message) => write!(formatter, "execution failed: {message}"),
            Self::Integrity(message) => write!(formatter, "integrity failure: {message}"),
            Self::Serialization(message) => write!(formatter, "serialization failure: {message}"),
            Self::Io { path, message } => {
                write!(formatter, "I/O failure at '{}': {message}", path.display())
            }
            Self::LockPoisoned => write!(formatter, "worker runtime state lock was poisoned"),
        }
    }
}

impl Error for WorkerRuntimeError {}

#[derive(Default)]
struct InvocationAudit {
    calls: u32,
    input_bytes: u64,
    output_bytes: u64,
    receipts: Vec<CapabilityInvocationReceipt>,
}

struct GovernedCapabilityMembrane<'a> {
    inner: &'a dyn CapabilityServiceInvoker,
    invocation: &'a WorkerInvocation,
    audit: Mutex<InvocationAudit>,
}

impl<'a> GovernedCapabilityMembrane<'a> {
    fn new(inner: &'a dyn CapabilityServiceInvoker, invocation: &'a WorkerInvocation) -> Self {
        Self {
            inner,
            invocation,
            audit: Mutex::new(InvocationAudit::default()),
        }
    }

    fn receipts(&self) -> Result<Vec<CapabilityInvocationReceipt>, WorkerRuntimeError> {
        self.audit
            .lock()
            .map(|audit| audit.receipts.clone())
            .map_err(|_| WorkerRuntimeError::LockPoisoned)
    }

    fn deny(&self, detail: impl Into<String>) -> CapabilityServiceFailure {
        CapabilityServiceFailure::Denied(detail.into())
    }

    fn authorize_and_charge(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<(), CapabilityServiceFailure> {
        let invocation = self.invocation;
        let registration = &invocation.registration;
        let job = &invocation.request;

        if request.execution_id != invocation.execution_id
            || request.acquired_at_tick != invocation.acquired_at_tick
            || request.effect_started_at_tick != invocation.effect_started_at_tick
            || request.effect_started_at_tick < request.acquired_at_tick
            || request.effect_started_at_tick >= request.deadline.expires_at_tick
            || request.worker_id != registration.worker_id
            || request.role != registration.role
        {
            return Err(self.deny(
                "worker attempted to invoke a capability for another execution or identity",
            ));
        }
        if request.workspace_scope != job.workspace_scope {
            return Err(self.deny("worker attempted to expand its workspace scope"));
        }
        if request.capability_envelope != job.capability_envelope
            || request.work_budget != job.budget
            || request.deadline != job.deadline
        {
            return Err(
                self.deny("worker attempted to replace its durable envelope, budget, or deadline")
            );
        }
        if request.service_family != registration.role.service_family()
            || !registration
                .service_family_refs
                .iter()
                .any(|family| family == &request.service_family)
        {
            return Err(self.deny("worker attempted to invoke an unregistered service family"));
        }
        if request.world != registration.role.required_world()
            || request.operation != registration.role.operation()
            || request.required_authority != registration.role.required_authority()
        {
            return Err(self.deny(
                "worker requested a world, operation, or authority outside its role contract",
            ));
        }
        if !registration
            .allowed_worlds
            .iter()
            .any(|world| world == &request.world)
            || !registration
                .authority_ceiling
                .ge(&request.required_authority)
        {
            return Err(self.deny("worker registration does not grant the requested capability"));
        }
        let envelope = &job.capability_envelope;
        if !envelope.grants_world(&request.world)
            || !envelope.allows_operation(&request.world, &request.operation)
            || !envelope.authority_allows(&request.required_authority)
            || !envelope.scope_allows(&request.resource_scope)
        {
            return Err(self.deny("capability envelope does not grant this invocation"));
        }
        match envelope.approval_for(&request.world, &request.operation) {
            Some(ApprovalClass::AutoAllowed) => {}
            Some(approval) => {
                return Err(self.deny(format!(
                    "operation requires an approval state not present in this execution: {approval:?}"
                )));
            }
            None => return Err(self.deny("capability operation has no approval rule")),
        }
        if !job
            .workspace_scope
            .resource_scopes
            .iter()
            .any(|scope| scope == &request.resource_scope)
        {
            return Err(self.deny("resource is outside the durable job scope"));
        }

        let mut audit = self
            .audit
            .lock()
            .map_err(|_| self.deny("capability accounting lock is poisoned"))?;
        let next_calls = audit.calls.saturating_add(1);
        let next_input = audit
            .input_bytes
            .saturating_add(request.payload.len() as u64);
        if next_calls > job.budget.max_capability_calls || next_input > job.budget.max_input_bytes {
            return Err(self.deny("capability invocation would exceed the job budget"));
        }
        audit.calls = next_calls;
        audit.input_bytes = next_input;
        Ok(())
    }

    fn record_receipt(
        &self,
        request: &CapabilityInvocationRequest,
        receipt: CapabilityInvocationReceipt,
        recovering_prior_effect: bool,
    ) -> Result<CapabilityInvocationReceipt, CapabilityServiceFailure> {
        if recovering_prior_effect {
            receipt.validate_recovery_for(request)?;
        } else {
            receipt.validate_for(request)?;
        }

        let mut audit = self
            .audit
            .lock()
            .map_err(|_| self.deny("capability accounting lock is poisoned"))?;
        if audit
            .receipts
            .iter()
            .any(|known| known.receipt_id == receipt.receipt_id)
        {
            return Err(self.deny("capability service returned a duplicate receipt id"));
        }
        let next_output = audit
            .output_bytes
            .saturating_add(receipt.output.len() as u64);
        if next_output > self.invocation.request.budget.max_output_bytes {
            return Err(self.deny("capability output exceeds the job budget"));
        }
        audit.output_bytes = next_output;
        audit.receipts.push(receipt.clone());
        Ok(receipt)
    }
}

impl CapabilityServiceInvoker for GovernedCapabilityMembrane<'_> {
    fn invoke(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<CapabilityInvocationReceipt, CapabilityServiceFailure> {
        self.authorize_and_charge(request)?;
        let receipt = self.inner.invoke(request)?;
        self.record_receipt(request, receipt, false)
    }

    fn recover(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<Option<CapabilityInvocationReceipt>, CapabilityServiceFailure> {
        self.authorize_and_charge(request)?;
        let Some(receipt) = self.inner.recover(request)? else {
            return Ok(None);
        };
        self.record_receipt(request, receipt, true).map(Some)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchReport {
    pub job_id: String,
    pub execution_id: String,
    pub worker_id: String,
    pub status: JobStatus,
    pub result_digest: Option<ContentDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReconciliationReport {
    pub inspected_execution_ids: Vec<String>,
    pub recovered_result_digests: Vec<ContentDigest>,
    pub retried_job_ids: Vec<String>,
    pub terminal_job_ids: Vec<String>,
}

/// Thread-safe coordinator over a single durable worker-runtime state file.
///
/// Runtime state is transactionally cloned and atomically replaced for every
/// mutation. The external executor is called only after a lease is durable,
/// and its result is committed in a second transaction.
pub struct WorkerRuntime<E, C>
where
    E: DurableJobExecutor,
    C: CapabilityServiceInvoker,
{
    root: PathBuf,
    executor: Arc<E>,
    capability_services: Arc<C>,
    state: Arc<Mutex<WorkerRuntimeState>>,
    _store_lock: Arc<File>,
    execution_gates: Arc<Mutex<BTreeMap<String, Arc<Mutex<()>>>>>,
    coordination_gate: Arc<Mutex<()>>,
}

impl<E, C> Clone for WorkerRuntime<E, C>
where
    E: DurableJobExecutor,
    C: CapabilityServiceInvoker,
{
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            executor: Arc::clone(&self.executor),
            capability_services: Arc::clone(&self.capability_services),
            state: Arc::clone(&self.state),
            _store_lock: Arc::clone(&self._store_lock),
            execution_gates: Arc::clone(&self.execution_gates),
            coordination_gate: Arc::clone(&self.coordination_gate),
        }
    }
}

impl<E, C> WorkerRuntime<E, C>
where
    E: DurableJobExecutor,
    C: CapabilityServiceInvoker,
{
    pub fn open(
        root: impl Into<PathBuf>,
        executor: E,
        capability_services: C,
    ) -> Result<Self, WorkerRuntimeError> {
        Self::open_with_shared(root, Arc::new(executor), Arc::new(capability_services))
    }

    pub fn open_with_shared(
        root: impl Into<PathBuf>,
        executor: Arc<E>,
        capability_services: Arc<C>,
    ) -> Result<Self, WorkerRuntimeError> {
        let root = root.into();
        prepare_store_root(&root)?;
        let store_lock = acquire_store_lock(&root)?;
        let path = root.join(STATE_FILE_NAME);
        let state = if path.exists() {
            read_state(&path)?
        } else {
            let state = WorkerRuntimeState::default();
            persist_state(&root, &state)?;
            state
        };
        validate_state_integrity(&state)?;
        Ok(Self {
            root,
            executor,
            capability_services,
            state: Arc::new(Mutex::new(state)),
            _store_lock: Arc::new(store_lock),
            execution_gates: Arc::new(Mutex::new(BTreeMap::new())),
            coordination_gate: Arc::new(Mutex::new(())),
        })
    }

    pub fn store_root(&self) -> &Path {
        &self.root
    }

    pub fn register_worker(
        &self,
        registration: WorkerRegistration,
        tick: u64,
    ) -> Result<(), WorkerRuntimeError> {
        registration.validate()?;
        self.transact(|state| {
            if state.registrations.contains_key(&registration.worker_id) {
                return Err(WorkerRuntimeError::Conflict(format!(
                    "worker id '{}' is already registered",
                    registration.worker_id
                )));
            }
            let worker_id = registration.worker_id.clone();
            state.registrations.insert(worker_id.clone(), registration);
            push_event(
                state,
                tick,
                "worker_registered",
                None,
                None,
                format!("registered executable worker '{worker_id}'"),
            );
            Ok(())
        })
    }

    pub fn enqueue(
        &self,
        request: WorkerJobRequest,
        tick: u64,
    ) -> Result<String, WorkerRuntimeError> {
        request.validate()?;
        self.transact(|state| {
            if state
                .jobs
                .values()
                .any(|job| job.request.request_id == request.request_id)
            {
                return Err(WorkerRuntimeError::Conflict(format!(
                    "request id '{}' is already durable",
                    request.request_id
                )));
            }
            validate_result_citations(state, &request.governance_context_digest, &request.input)?;
            if !state.registrations.values().any(|registration| {
                registration.enabled
                    && registration.role == request.role
                    && registration.permits_scope(&request.workspace_scope)
            }) {
                return Err(WorkerRuntimeError::NoEligibleWorker(format!(
                    "no enabled '{}' registration permits scope '{}'",
                    request.role.as_str(),
                    request.workspace_scope.scope_id
                )));
            }
            let sequence = take_sequence(state);
            let input_digest =
                governed_work_input_digest(&request.governance_context_digest, &request.input)?;
            let job_id =
                format!(
                    "job-{sequence}-{}",
                    digest_suffix(&digest_json_content(&request).map_err(|error| {
                        WorkerRuntimeError::Serialization(error.to_string())
                    })?)
                );
            state.jobs.insert(
                job_id.clone(),
                StoredWorkerJob {
                    job_id: job_id.clone(),
                    sequence,
                    request,
                    input_digest,
                    status: JobStatus::Pending,
                    attempts: 0,
                    next_available_tick: tick,
                    selected_worker_id: None,
                    active_execution_id: None,
                    result_digest: None,
                    failed_worker_ids: Vec::new(),
                    failures: Vec::new(),
                    cancellation_requested_at_tick: None,
                },
            );
            push_event(
                state,
                tick,
                "job_enqueued",
                Some(job_id.clone()),
                None,
                "typed worker request persisted before dispatch".to_string(),
            );
            Ok(job_id)
        })
    }

    pub fn dispatch_next(&self, tick: u64) -> Result<Option<DispatchReport>, WorkerRuntimeError> {
        let (invocation, execution_gate) = {
            let _coordination = self
                .coordination_gate
                .lock()
                .map_err(|_| WorkerRuntimeError::LockPoisoned)?;
            let invocation = self.transact(|state| lease_next_job(state, tick))?;
            let execution_gate = invocation
                .as_ref()
                .map(|leased| self.execution_gate(&leased.execution_id))
                .transpose()?;
            (invocation, execution_gate)
        };
        let Some(invocation) = invocation else {
            return Ok(None);
        };
        let execution_gate = execution_gate.ok_or_else(|| {
            WorkerRuntimeError::Integrity("leased execution has no safe-boundary gate".to_string())
        })?;
        let _safe_boundary = execution_gate
            .lock()
            .map_err(|_| WorkerRuntimeError::LockPoisoned)?;

        // Cancellation may have won the gate immediately after the lease was
        // persisted. Never enter the effectful executor with a stale lease.
        if !self.invocation_is_active(&invocation)? {
            return self
                .inspect(|state| dispatch_report(state, &invocation))
                .map(Some);
        }

        let membrane =
            GovernedCapabilityMembrane::new(self.capability_services.as_ref(), &invocation);
        let outcome = self.executor.dispatch(&invocation, &membrane);
        let receipts = membrane.receipts()?;
        let report =
            self.transact(|state| apply_outcome(state, &invocation, outcome, receipts, tick))?;
        Ok(Some(report))
    }

    pub fn heartbeat(&self, execution_id: &str, tick: u64) -> Result<(), WorkerRuntimeError> {
        self.transact(|state| {
            let (
                job_id,
                lease_duration,
                heartbeat_grace,
                acquired_at_tick,
                prior_expires_at_tick,
                prior_heartbeat_tick,
            ) = {
                let execution = state.executions.get(execution_id).ok_or_else(|| {
                    WorkerRuntimeError::NotFound(format!("execution '{execution_id}'"))
                })?;
                if !execution.status.is_active() {
                    return Err(WorkerRuntimeError::Conflict(format!(
                        "execution '{execution_id}' is not active"
                    )));
                }
                let registration =
                    state
                        .registrations
                        .get(&execution.worker_id)
                        .ok_or_else(|| {
                            WorkerRuntimeError::Integrity(
                                "active execution references a missing worker".to_string(),
                            )
                        })?;
                (
                    execution.job_id.clone(),
                    registration.policy.lease_duration_ticks,
                    registration.policy.heartbeat_grace_ticks,
                    execution.lease.acquired_at_tick,
                    execution.lease.expires_at_tick,
                    execution.lease.last_heartbeat_tick,
                )
            };
            let request = &state
                .jobs
                .get(&job_id)
                .ok_or_else(|| {
                    WorkerRuntimeError::Integrity("execution job is missing".to_string())
                })?
                .request;
            let deadline = request.deadline.expires_at_tick;
            let runtime_limit = acquired_at_tick.saturating_add(request.budget.max_runtime_ticks);
            if tick >= deadline {
                return Err(WorkerRuntimeError::DeadlineExceeded(format!(
                    "heartbeat for '{execution_id}' arrived after the job deadline"
                )));
            }
            if tick > runtime_limit {
                return Err(WorkerRuntimeError::BudgetExceeded(format!(
                    "heartbeat for '{execution_id}' exceeded max_runtime_ticks"
                )));
            }
            if tick > prior_expires_at_tick
                || tick.saturating_sub(prior_heartbeat_tick) > heartbeat_grace
            {
                return Err(WorkerRuntimeError::DeadlineExceeded(format!(
                    "heartbeat for '{execution_id}' cannot resurrect a stale durable lease"
                )));
            }
            let execution = state.executions.get_mut(execution_id).ok_or_else(|| {
                WorkerRuntimeError::Integrity("execution disappeared during heartbeat".to_string())
            })?;
            if tick < execution.lease.last_heartbeat_tick {
                return Err(WorkerRuntimeError::Conflict(
                    "heartbeat tick moved backwards".to_string(),
                ));
            }
            execution.lease.last_heartbeat_tick = tick;
            execution.lease.expires_at_tick = tick
                .saturating_add(lease_duration)
                .min(deadline)
                .min(runtime_limit);
            execution.status = ExecutionStatus::Running;
            push_event(
                state,
                tick,
                "worker_heartbeat",
                Some(job_id),
                Some(execution_id.to_string()),
                "worker lease renewed".to_string(),
            );
            Ok(())
        })
    }

    pub fn request_cancellation(
        &self,
        job_id: &str,
        presented_secret: &str,
        tick: u64,
    ) -> Result<(), WorkerRuntimeError> {
        loop {
            let active_and_gate = {
                let _coordination = self
                    .coordination_gate
                    .lock()
                    .map_err(|_| WorkerRuntimeError::LockPoisoned)?;
                let active = self.inspect(|state| {
                    let job = state
                        .jobs
                        .get(job_id)
                        .ok_or_else(|| WorkerRuntimeError::NotFound(format!("job '{job_id}'")))?;
                    if !job
                        .request
                        .cancellation_token
                        .matches_secret(presented_secret)
                    {
                        return Err(WorkerRuntimeError::CapabilityDenied(
                            "cancellation credential does not match the durable job".to_string(),
                        ));
                    }
                    if job.status.is_terminal() {
                        return Ok(None);
                    }
                    Ok(job.active_execution_id.clone())
                })?;
                match active {
                    Some(execution_id) => {
                        let gate = self.execution_gate(&execution_id)?;
                        Some((execution_id, gate))
                    }
                    None => {
                        self.transact(|state| {
                            let job = state.jobs.get_mut(job_id).ok_or_else(|| {
                                WorkerRuntimeError::NotFound(format!("job '{job_id}'"))
                            })?;
                            if !job
                                .request
                                .cancellation_token
                                .matches_secret(presented_secret)
                            {
                                return Err(WorkerRuntimeError::CapabilityDenied(
                                    "cancellation credential does not match the durable job"
                                        .to_string(),
                                ));
                            }
                            if !job.status.is_terminal() {
                                job.cancellation_requested_at_tick = Some(tick);
                                job.status = JobStatus::Cancelled;
                                push_event(
                                    state,
                                    tick,
                                    "cancellation_requested",
                                    Some(job_id.to_string()),
                                    None,
                                    "presented credential authorized durable cancellation"
                                        .to_string(),
                                );
                            }
                            Ok(())
                        })?;
                        None
                    }
                }
            };
            let Some((execution_id, execution_gate)) = active_and_gate else {
                return Ok(());
            };
            let _safe_boundary = execution_gate
                .lock()
                .map_err(|_| WorkerRuntimeError::LockPoisoned)?;
            let mut invocation = self.invocation_for(&execution_id)?;
            let cancellation_applies = {
                let _coordination = self
                    .coordination_gate
                    .lock()
                    .map_err(|_| WorkerRuntimeError::LockPoisoned)?;
                self.transact(|state| {
                    let job = state
                        .jobs
                        .get_mut(job_id)
                        .ok_or_else(|| WorkerRuntimeError::NotFound(format!("job '{job_id}'")))?;
                    if !job
                        .request
                        .cancellation_token
                        .matches_secret(presented_secret)
                    {
                        return Err(WorkerRuntimeError::CapabilityDenied(
                            "cancellation credential does not match the durable job".to_string(),
                        ));
                    }
                    if job.status.is_terminal() {
                        return Ok(false);
                    }
                    if job.active_execution_id.as_deref() != Some(&execution_id) {
                        return Ok(false);
                    }
                    if job.cancellation_requested_at_tick.is_none() {
                        job.cancellation_requested_at_tick = Some(tick);
                        push_event(
                            state,
                            tick,
                            "cancellation_requested",
                            Some(job_id.to_string()),
                            Some(execution_id.clone()),
                            "presented credential authorized durable cancellation".to_string(),
                        );
                    }
                    Ok(true)
                })?
            };
            if !cancellation_applies {
                if self.load_job(job_id)?.status.is_terminal() {
                    return Ok(());
                }
                continue;
            }
            if self.recover_terminal_completion(&mut invocation)?.is_some() {
                return Ok(());
            }
            self.executor
                .cancel(&execution_id, presented_secret)
                .map_err(WorkerRuntimeError::ExecutionFailed)?;
            self.transact(|state| {
                apply_outcome(
                    state,
                    &invocation,
                    ExecutorOutcome::Cancelled {
                        detail: "cancelled by durable token".to_string(),
                        failed_at_tick: tick,
                    },
                    Vec::new(),
                    tick,
                )
                .map(|_| ())
            })?;
            return Ok(());
        }
    }

    /// Reconcile every in-flight execution. Calling this immediately after
    /// `open` is the restart path; executor reconciliation must be idempotent.
    pub fn reconcile_in_flight(
        &self,
        tick: u64,
    ) -> Result<ReconciliationReport, WorkerRuntimeError> {
        let execution_ids = self.active_execution_ids()?;
        let mut report = ReconciliationReport::default();
        for execution_id in execution_ids {
            report.inspected_execution_ids.push(execution_id.clone());
            let execution_gate = {
                let _coordination = self
                    .coordination_gate
                    .lock()
                    .map_err(|_| WorkerRuntimeError::LockPoisoned)?;
                self.execution_gate(&execution_id)?
            };
            let _safe_boundary = execution_gate
                .lock()
                .map_err(|_| WorkerRuntimeError::LockPoisoned)?;
            let mut invocation = self.invocation_for(&execution_id)?;
            if !self.invocation_is_active(&invocation)? {
                continue;
            }
            let claimed = self.transact(|state| {
                let execution = state.executions.get_mut(&execution_id).ok_or_else(|| {
                    WorkerRuntimeError::Integrity(
                        "reconciled execution disappeared before its claim".to_string(),
                    )
                })?;
                if !execution.status.is_active()
                    || execution
                        .last_reconciled_at_tick
                        .is_some_and(|last_tick| last_tick >= tick)
                {
                    return Ok(false);
                }
                execution.last_reconciled_at_tick = Some(tick);
                push_event(
                    state,
                    tick,
                    "reconciliation_claimed",
                    Some(invocation.job_id.clone()),
                    Some(execution_id.clone()),
                    "one caller claimed the per-execution reconciliation boundary".to_string(),
                );
                Ok(true)
            })?;
            if !claimed {
                continue;
            }
            let job = self.load_job(&invocation.job_id)?;
            if let Some(dispatch) = self.recover_terminal_completion(&mut invocation)? {
                classify_reconciliation_dispatch(&dispatch, &mut report);
                continue;
            }

            if job.cancellation_requested_at_tick.is_some() {
                self.executor
                    .cancel(
                        &execution_id,
                        job.request.cancellation_token.credential_digest.as_str(),
                    )
                    .map_err(WorkerRuntimeError::ExecutionFailed)?;
                let dispatch = self.transact(|state| {
                    apply_outcome(
                        state,
                        &invocation,
                        ExecutorOutcome::Cancelled {
                            detail: "restart observed a durable cancellation request".to_string(),
                            failed_at_tick: tick,
                        },
                        Vec::new(),
                        tick,
                    )
                })?;
                report.terminal_job_ids.push(dispatch.job_id);
                continue;
            }
            let runtime_limit = invocation
                .acquired_at_tick
                .saturating_add(job.request.budget.max_runtime_ticks);
            if tick >= job.request.deadline.expires_at_tick || tick > runtime_limit {
                self.executor
                    .cancel(
                        &execution_id,
                        job.request.cancellation_token.credential_digest.as_str(),
                    )
                    .map_err(WorkerRuntimeError::ExecutionFailed)?;
                let dispatch = self.transact(|state| {
                    apply_outcome(
                        state,
                        &invocation,
                        ExecutorOutcome::TimedOut {
                            detail: if tick >= job.request.deadline.expires_at_tick {
                                "job deadline elapsed during restart reconciliation".to_string()
                            } else {
                                "max_runtime_ticks elapsed during restart reconciliation"
                                    .to_string()
                            },
                            failed_at_tick: tick,
                        },
                        Vec::new(),
                        tick,
                    )
                })?;
                classify_reconciliation_dispatch(&dispatch, &mut report);
                continue;
            }

            let stale = {
                let execution = self.load_execution(&execution_id)?;
                tick > execution.lease.expires_at_tick
                    || tick.saturating_sub(execution.lease.last_heartbeat_tick)
                        > invocation.registration.policy.heartbeat_grace_ticks
            };
            if stale {
                self.executor
                    .cancel(
                        &execution_id,
                        job.request.cancellation_token.credential_digest.as_str(),
                    )
                    .map_err(WorkerRuntimeError::ExecutionFailed)?;
                let dispatch = self.transact(|state| {
                    apply_failure(
                        state,
                        &invocation,
                        "stale_lease",
                        "durable lease or heartbeat grace elapsed before executor reconciliation"
                            .to_string(),
                        tick,
                        FailureDisposition::Retryable,
                    )
                })?;
                classify_reconciliation_dispatch(&dispatch, &mut report);
                continue;
            }

            invocation.effect_started_at_tick = tick;
            let membrane =
                GovernedCapabilityMembrane::new(self.capability_services.as_ref(), &invocation);
            let reconciliation = self.executor.reconcile(&invocation, &membrane);
            let receipts = membrane.receipts()?;
            match reconciliation {
                ExecutorReconciliation::StillRunning {
                    executor_handle,
                    heartbeat_tick,
                } => {
                    self.transact(|state| {
                        apply_running_reconciliation(
                            state,
                            &invocation,
                            executor_handle,
                            heartbeat_tick,
                            receipts,
                            tick,
                        )
                    })?;
                }
                ExecutorReconciliation::Terminal(outcome) => {
                    let dispatch = self.transact(|state| {
                        apply_outcome(state, &invocation, outcome, receipts, tick)
                    })?;
                    classify_reconciliation_dispatch(&dispatch, &mut report);
                }
                ExecutorReconciliation::Unknown {
                    detail,
                    observed_at_tick: _,
                } => {
                    self.transact(|state| {
                        push_event(
                            state,
                            tick,
                            "reconciliation_unknown",
                            Some(invocation.job_id.clone()),
                            Some(execution_id.clone()),
                            detail,
                        );
                        Ok(())
                    })?;
                }
            }
        }
        Ok(report)
    }

    pub fn synthesize(
        &self,
        synthesis_id: impl Into<String>,
        cited_result_digests: Vec<ContentDigest>,
        tick: u64,
    ) -> Result<CoordinatorSynthesis, WorkerRuntimeError> {
        let synthesis_id = synthesis_id.into();
        require_nonempty("synthesis_id", &synthesis_id)?;
        self.transact(|state| {
            if cited_result_digests.is_empty() {
                return Err(WorkerRuntimeError::InvalidRequest(
                    "coordinator synthesis requires persisted result citations".to_string(),
                ));
            }
            if state.syntheses.contains_key(&synthesis_id) {
                return Err(WorkerRuntimeError::Conflict(format!(
                    "synthesis id '{synthesis_id}' already exists"
                )));
            }
            let mut unique = BTreeSet::new();
            let mut execution_ids = Vec::new();
            let mut roles = Vec::new();
            for digest in &cited_result_digests {
                if !unique.insert(digest.clone()) {
                    return Err(WorkerRuntimeError::Conflict(format!(
                        "duplicate result citation '{digest}'"
                    )));
                }
                let result = state.results.get(digest.as_str()).ok_or_else(|| {
                    WorkerRuntimeError::NotFound(format!(
                        "persisted worker result digest '{digest}'"
                    ))
                })?;
                result.validate_digest()?;
                let execution = state.executions.get(&result.execution_id).ok_or_else(|| {
                    WorkerRuntimeError::Integrity(
                        "result citation references a missing execution".to_string(),
                    )
                })?;
                if execution.status != ExecutionStatus::Completed
                    || execution.result_digest.as_ref() != Some(digest)
                    || execution.worker_id != result.worker_id
                    || execution.role != result.role
                {
                    return Err(WorkerRuntimeError::Integrity(format!(
                        "result citation '{digest}' does not resolve to its exact terminal execution"
                    )));
                }
                if execution_ids.contains(&result.execution_id) {
                    return Err(WorkerRuntimeError::Conflict(
                        "coordinator cited conflicting results from one execution".to_string(),
                    ));
                }
                execution_ids.push(result.execution_id.clone());
                roles.push(result.role);
            }
            let synthesis_digest = digest_json_content(&SynthesisMaterial {
                synthesis_id: &synthesis_id,
                cited_result_digests: &cited_result_digests,
                cited_execution_ids: &execution_ids,
                cited_roles: &roles,
                created_at_tick: tick,
            })
            .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
            let synthesis = CoordinatorSynthesis {
                synthesis_id: synthesis_id.clone(),
                cited_result_digests,
                cited_execution_ids: execution_ids,
                cited_roles: roles,
                synthesis_digest,
                created_at_tick: tick,
            };
            state
                .syntheses
                .insert(synthesis_id.clone(), synthesis.clone());
            push_event(
                state,
                tick,
                "coordinator_synthesis",
                None,
                None,
                format!(
                    "synthesis '{}' loaded {} exact persisted worker results",
                    synthesis_id,
                    synthesis.cited_result_digests.len()
                ),
            );
            Ok(synthesis)
        })
    }

    pub fn load_job(&self, job_id: &str) -> Result<StoredWorkerJob, WorkerRuntimeError> {
        self.inspect(|state| {
            state
                .jobs
                .get(job_id)
                .cloned()
                .ok_or_else(|| WorkerRuntimeError::NotFound(format!("job '{job_id}'")))
        })
    }

    pub fn load_execution(
        &self,
        execution_id: &str,
    ) -> Result<WorkerExecutionRecord, WorkerRuntimeError> {
        self.inspect(|state| {
            state
                .executions
                .get(execution_id)
                .cloned()
                .ok_or_else(|| WorkerRuntimeError::NotFound(format!("execution '{execution_id}'")))
        })
    }

    pub fn load_result(
        &self,
        result_digest: &ContentDigest,
    ) -> Result<PersistedWorkerResult, WorkerRuntimeError> {
        self.inspect(|state| {
            let result = state
                .results
                .get(result_digest.as_str())
                .cloned()
                .ok_or_else(|| {
                    WorkerRuntimeError::NotFound(format!("worker result digest '{result_digest}'"))
                })?;
            result.validate_digest()?;
            Ok(result)
        })
    }

    pub fn events(&self) -> Result<Vec<RuntimeEvent>, WorkerRuntimeError> {
        self.inspect(|state| Ok(state.events.clone()))
    }

    pub fn registrations(&self) -> Result<Vec<WorkerRegistration>, WorkerRuntimeError> {
        self.inspect(|state| Ok(state.registrations.values().cloned().collect()))
    }

    pub fn jobs(&self) -> Result<Vec<StoredWorkerJob>, WorkerRuntimeError> {
        self.inspect(|state| {
            let mut jobs = state.jobs.values().cloned().collect::<Vec<_>>();
            jobs.sort_by_key(|job| job.sequence);
            Ok(jobs)
        })
    }

    /// Reserve a durable, non-overlapping span of logical ticks.
    ///
    /// The returned value is the first tick in the claimed half-open span.
    pub fn claim_tick_span(&self, span: u64) -> Result<u64, WorkerRuntimeError> {
        self.claim_tick_span_at_or_after(0, span)
    }

    /// Atomically reserve a durable tick span no earlier than `minimum_tick`.
    pub fn claim_tick_span_at_or_after(
        &self,
        minimum_tick: u64,
        span: u64,
    ) -> Result<u64, WorkerRuntimeError> {
        if span == 0 {
            return Err(WorkerRuntimeError::InvalidRequest(
                "logical tick span must be non-zero".to_string(),
            ));
        }
        self.transact(|state| {
            let first = state.next_logical_tick.max(minimum_tick);
            let next = first.checked_add(span).ok_or_else(|| {
                WorkerRuntimeError::Conflict("logical tick space is exhausted".to_string())
            })?;
            if next == u64::MAX {
                return Err(WorkerRuntimeError::Conflict(
                    "logical tick reservation would exhaust the final clock value".to_string(),
                ));
            }
            state.next_logical_tick = next;
            Ok(first)
        })
    }

    /// Atomically reserve a durable span whose final tick is strictly before
    /// `exclusive_upper_tick`. A rejected reservation does not advance the
    /// allocator.
    pub fn claim_tick_span_at_or_after_before(
        &self,
        minimum_tick: u64,
        span: u64,
        exclusive_upper_tick: u64,
    ) -> Result<u64, WorkerRuntimeError> {
        if span == 0 {
            return Err(WorkerRuntimeError::InvalidRequest(
                "logical tick span must be non-zero".to_string(),
            ));
        }
        self.transact(|state| {
            if minimum_tick
                > state
                    .next_logical_tick
                    .saturating_add(MAX_REQUESTED_FUTURE_TICK_DRIFT)
            {
                return Err(WorkerRuntimeError::InvalidRequest(format!(
                    "requested logical tick is more than {MAX_REQUESTED_FUTURE_TICK_DRIFT} ticks ahead of server time"
                )));
            }
            let first = state.next_logical_tick.max(minimum_tick);
            let next = first.checked_add(span).ok_or_else(|| {
                WorkerRuntimeError::Conflict("logical tick space is exhausted".to_string())
            })?;
            if next == u64::MAX {
                return Err(WorkerRuntimeError::Conflict(
                    "logical tick reservation would exhaust the final clock value".to_string(),
                ));
            }
            if next > exclusive_upper_tick {
                return Err(WorkerRuntimeError::DeadlineExceeded(format!(
                    "logical tick span [{first}, {next}) does not fit before exclusive deadline {exclusive_upper_tick}"
                )));
            }
            state.next_logical_tick = next;
            Ok(first)
        })
    }

    pub fn claim_tick(&self) -> Result<u64, WorkerRuntimeError> {
        self.claim_tick_span(1)
    }

    fn active_execution_ids(&self) -> Result<Vec<String>, WorkerRuntimeError> {
        self.inspect(|state| {
            Ok(state
                .executions
                .values()
                .filter(|execution| execution.status.is_active())
                .map(|execution| execution.execution_id.clone())
                .collect())
        })
    }

    fn invocation_for(&self, execution_id: &str) -> Result<WorkerInvocation, WorkerRuntimeError> {
        self.inspect(|state| {
            let execution = state.executions.get(execution_id).ok_or_else(|| {
                WorkerRuntimeError::NotFound(format!("execution '{execution_id}'"))
            })?;
            let job = state.jobs.get(&execution.job_id).ok_or_else(|| {
                WorkerRuntimeError::Integrity("execution references a missing job".to_string())
            })?;
            let registration = state
                .registrations
                .get(&execution.worker_id)
                .ok_or_else(|| {
                    WorkerRuntimeError::Integrity(
                        "execution references a missing registration".to_string(),
                    )
                })?;
            Ok(WorkerInvocation {
                job_id: job.job_id.clone(),
                execution_id: execution.execution_id.clone(),
                lease_id: execution.lease.lease_id.clone(),
                attempt: execution.lease.attempt,
                acquired_at_tick: execution.lease.acquired_at_tick,
                effect_started_at_tick: execution.lease.acquired_at_tick,
                registration: registration.clone(),
                request: job.request.clone(),
            })
        })
    }

    fn recover_terminal_completion(
        &self,
        invocation: &mut WorkerInvocation,
    ) -> Result<Option<DispatchReport>, WorkerRuntimeError> {
        let (outcome, receipts) = {
            let membrane =
                GovernedCapabilityMembrane::new(self.capability_services.as_ref(), invocation);
            let outcome = self
                .executor
                .recover_terminal(invocation, &membrane)
                .map_err(WorkerRuntimeError::ExecutionFailed)?;
            let receipts = membrane.receipts()?;
            (outcome, receipts)
        };
        let Some(outcome) = outcome else {
            if !receipts.is_empty() {
                return Err(WorkerRuntimeError::Integrity(
                    "executor recovery returned receipts without a terminal outcome".to_string(),
                ));
            }
            return Ok(None);
        };
        let recovered_at_tick = match &outcome {
            ExecutorOutcome::Completed {
                completed_at_tick, ..
            } if !receipts.is_empty()
                && receipts
                    .iter()
                    .any(|receipt| receipt.completed_at_tick == *completed_at_tick) =>
            {
                *completed_at_tick
            }
            _ => {
                return Err(WorkerRuntimeError::Integrity(
                    "terminal recovery must return a receipt-attested completed outcome"
                        .to_string(),
                ));
            }
        };
        invocation.effect_started_at_tick = receipts
            .iter()
            .map(|receipt| receipt.effect_started_at_tick)
            .max()
            .unwrap_or(invocation.acquired_at_tick);
        self.transact(|state| {
            apply_outcome(state, invocation, outcome, receipts, recovered_at_tick)
        })
        .map(Some)
    }

    fn execution_gate(&self, execution_id: &str) -> Result<Arc<Mutex<()>>, WorkerRuntimeError> {
        let mut gates = self
            .execution_gates
            .lock()
            .map_err(|_| WorkerRuntimeError::LockPoisoned)?;
        Ok(Arc::clone(
            gates
                .entry(execution_id.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        ))
    }

    fn invocation_is_active(
        &self,
        invocation: &WorkerInvocation,
    ) -> Result<bool, WorkerRuntimeError> {
        self.inspect(|state| Ok(verify_active_invocation(state, invocation).is_ok()))
    }

    fn inspect<R>(
        &self,
        operation: impl FnOnce(&WorkerRuntimeState) -> Result<R, WorkerRuntimeError>,
    ) -> Result<R, WorkerRuntimeError> {
        let state = self
            .state
            .lock()
            .map_err(|_| WorkerRuntimeError::LockPoisoned)?;
        operation(&state)
    }

    fn transact<R>(
        &self,
        operation: impl FnOnce(&mut WorkerRuntimeState) -> Result<R, WorkerRuntimeError>,
    ) -> Result<R, WorkerRuntimeError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WorkerRuntimeError::LockPoisoned)?;
        let mut candidate = guard.clone();
        let result = operation(&mut candidate)?;
        validate_state_integrity(&candidate)?;
        persist_state(&self.root, &candidate)?;
        *guard = candidate;
        Ok(result)
    }
}

fn lease_next_job(
    state: &mut WorkerRuntimeState,
    tick: u64,
) -> Result<Option<WorkerInvocation>, WorkerRuntimeError> {
    let expired_job_ids = state
        .jobs
        .values()
        .filter(|job| {
            matches!(job.status, JobStatus::Pending | JobStatus::RetryPending)
                && tick >= job.request.deadline.expires_at_tick
        })
        .map(|job| job.job_id.clone())
        .collect::<Vec<_>>();
    for job_id in expired_job_ids {
        if let Some(job) = state.jobs.get_mut(&job_id) {
            job.status = JobStatus::TimedOut;
        }
        push_event(
            state,
            tick,
            "job_deadline_elapsed",
            Some(job_id),
            None,
            "queued job reached its deadline without an execution lease".to_string(),
        );
    }

    let active_by_worker = state
        .executions
        .values()
        .filter(|execution| execution.status.is_active())
        .fold(BTreeMap::<String, usize>::new(), |mut counts, execution| {
            *counts.entry(execution.worker_id.clone()).or_default() += 1;
            counts
        });

    let mut candidates = state
        .jobs
        .values()
        .filter(|job| {
            matches!(job.status, JobStatus::Pending | JobStatus::RetryPending)
                && job.next_available_tick <= tick
                && job.request.deadline.not_before_tick <= tick
                && job.attempts < job.request.budget.max_attempts
        })
        .map(|job| job.job_id.clone())
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        let left_job = state.jobs.get(left).expect("candidate job exists");
        let right_job = state.jobs.get(right).expect("candidate job exists");
        right_job
            .request
            .priority
            .cmp(&left_job.request.priority)
            .then_with(|| left_job.sequence.cmp(&right_job.sequence))
    });
    if candidates.is_empty() {
        return Ok(None);
    }

    let highest_priority = state
        .jobs
        .get(&candidates[0])
        .map(|job| job.request.priority)
        .unwrap_or_default();
    let same_priority = candidates
        .iter()
        .filter(|job_id| {
            state
                .jobs
                .get(*job_id)
                .is_some_and(|job| job.request.priority == highest_priority)
        })
        .cloned()
        .collect::<Vec<_>>();
    if let Some(last_key) = &state.last_fairness_key
        && let Some(fair_job) = same_priority.iter().find(|job_id| {
            state
                .jobs
                .get(*job_id)
                .is_some_and(|job| &job.request.fairness_key != last_key)
        })
    {
        candidates.retain(|candidate| candidate != fair_job);
        candidates.insert(0, fair_job.clone());
    }

    let mut selection = None;
    for job_id in candidates {
        let job = state.jobs.get(&job_id).ok_or_else(|| {
            WorkerRuntimeError::Integrity("candidate job disappeared".to_string())
        })?;
        let mut registrations = state
            .registrations
            .values()
            .filter(|registration| {
                registration.enabled
                    && registration.role == job.request.role
                    && registration.permits_scope(&job.request.workspace_scope)
                    && registration
                        .isolation_profile
                        .satisfies(&job.request.capability_envelope.isolation_profile)
                    && active_by_worker
                        .get(&registration.worker_id)
                        .copied()
                        .unwrap_or_default()
                        < registration.policy.max_concurrency
                    && job.attempts
                        < job
                            .request
                            .budget
                            .max_attempts
                            .min(registration.policy.max_attempts)
            })
            .cloned()
            .collect::<Vec<_>>();
        registrations.sort_by(|left, right| left.worker_id.cmp(&right.worker_id));
        if let Some(registration) = registrations
            .iter()
            .find(|registration| !job.failed_worker_ids.contains(&registration.worker_id))
            .cloned()
            .or_else(|| registrations.into_iter().next())
        {
            selection = Some((job_id, registration));
            break;
        }
    }
    let Some((job_id, registration)) = selection else {
        return Ok(None);
    };

    let sequence = take_sequence(state);
    let (attempt, deadline, runtime_ticks, fairness_key, previous_worker) = {
        let job = state
            .jobs
            .get(&job_id)
            .ok_or_else(|| WorkerRuntimeError::Integrity("selected job disappeared".to_string()))?;
        (
            job.attempts.saturating_add(1),
            job.request.deadline.expires_at_tick,
            job.request.budget.max_runtime_ticks,
            job.request.fairness_key.clone(),
            job.selected_worker_id.clone(),
        )
    };
    let execution_id = format!("execution-{sequence}-{attempt}");
    let lease_id = format!("lease-{sequence}-{attempt}");
    let expires_at_tick = tick
        .saturating_add(registration.policy.lease_duration_ticks)
        .min(deadline)
        .min(tick.saturating_add(runtime_ticks));
    let lease = WorkerLease {
        lease_id: lease_id.clone(),
        execution_id: execution_id.clone(),
        worker_id: registration.worker_id.clone(),
        attempt,
        acquired_at_tick: tick,
        expires_at_tick,
        last_heartbeat_tick: tick,
    };

    let job = state
        .jobs
        .get_mut(&job_id)
        .ok_or_else(|| WorkerRuntimeError::Integrity("selected job disappeared".to_string()))?;
    job.status = JobStatus::Leased;
    job.attempts = attempt;
    job.selected_worker_id = Some(registration.worker_id.clone());
    job.active_execution_id = Some(execution_id.clone());
    let request = job.request.clone();
    state.last_fairness_key = Some(fairness_key);

    state.executions.insert(
        execution_id.clone(),
        WorkerExecutionRecord {
            execution_id: execution_id.clone(),
            job_id: job_id.clone(),
            worker_id: registration.worker_id.clone(),
            role: registration.role,
            governance_context_digest: request.governance_context_digest.clone(),
            implementation_package_digest: registration.executable.package_digest.clone(),
            implementation_ref: registration.executable.implementation_ref.clone(),
            provenance: registration.executable.provenance.clone(),
            lease,
            status: ExecutionStatus::Leased,
            executor_handle: None,
            capability_receipts: Vec::new(),
            result_digest: None,
            terminal_detail: None,
            completed_at_tick: None,
            last_reconciled_at_tick: None,
        },
    );
    let degraded = previous_worker
        .as_ref()
        .is_some_and(|worker| worker != &registration.worker_id);
    push_event(
        state,
        tick,
        if degraded {
            "worker_degraded_dispatch"
        } else {
            "worker_dispatched"
        },
        Some(job_id.clone()),
        Some(execution_id.clone()),
        format!(
            "attempt {attempt} leased to package-backed worker '{}'",
            registration.worker_id
        ),
    );
    Ok(Some(WorkerInvocation {
        job_id,
        execution_id,
        lease_id,
        attempt,
        acquired_at_tick: tick,
        effect_started_at_tick: tick,
        registration,
        request,
    }))
}

fn apply_outcome(
    state: &mut WorkerRuntimeState,
    invocation: &WorkerInvocation,
    outcome: ExecutorOutcome,
    receipts: Vec<CapabilityInvocationReceipt>,
    observed_at_tick: u64,
) -> Result<DispatchReport, WorkerRuntimeError> {
    verify_active_invocation(state, invocation)?;
    append_receipts(state, invocation, receipts)?;
    match outcome {
        ExecutorOutcome::Running {
            executor_handle,
            heartbeat_tick,
        } => {
            require_nonempty("executor_handle", &executor_handle)?;
            let execution = state
                .executions
                .get(&invocation.execution_id)
                .ok_or_else(|| {
                    WorkerRuntimeError::Integrity("active execution disappeared".to_string())
                })?;
            if heartbeat_tick < observed_at_tick
                || heartbeat_tick < execution.lease.last_heartbeat_tick
            {
                return Err(WorkerRuntimeError::Conflict(
                    "executor returned a non-monotonic heartbeat".to_string(),
                ));
            }
            let deadline = invocation.request.deadline.expires_at_tick;
            let runtime_limit = invocation
                .acquired_at_tick
                .saturating_add(invocation.request.budget.max_runtime_ticks);
            if heartbeat_tick >= deadline || heartbeat_tick > runtime_limit {
                return apply_failure(
                    state,
                    invocation,
                    "timeout",
                    "executor heartbeat exceeded the durable execution interval".to_string(),
                    observed_at_tick,
                    if invocation.registration.policy.retry_timeouts {
                        FailureDisposition::RetryableTimeout
                    } else {
                        FailureDisposition::TerminalTimeout
                    },
                );
            }
            let execution = state
                .executions
                .get_mut(&invocation.execution_id)
                .ok_or_else(|| {
                    WorkerRuntimeError::Integrity("active execution disappeared".to_string())
                })?;
            execution.status = ExecutionStatus::Running;
            execution.executor_handle = Some(executor_handle);
            execution.lease.last_heartbeat_tick = heartbeat_tick;
            execution.lease.expires_at_tick = heartbeat_tick
                .saturating_add(invocation.registration.policy.lease_duration_ticks)
                .min(deadline)
                .min(runtime_limit);
            let job = state.jobs.get_mut(&invocation.job_id).ok_or_else(|| {
                WorkerRuntimeError::Integrity("active job disappeared".to_string())
            })?;
            job.status = JobStatus::Running;
            push_event(
                state,
                observed_at_tick,
                "worker_running",
                Some(invocation.job_id.clone()),
                Some(invocation.execution_id.clone()),
                "executor retained the durable lease".to_string(),
            );
            dispatch_report(state, invocation)
        }
        ExecutorOutcome::Completed {
            output,
            completed_at_tick,
        } => finalize_result(
            state,
            invocation,
            output,
            completed_at_tick.max(observed_at_tick),
        ),
        ExecutorOutcome::Trapped {
            detail,
            failed_at_tick: _,
        } => apply_failure(
            state,
            invocation,
            "trap",
            detail,
            observed_at_tick,
            FailureDisposition::Retryable,
        ),
        ExecutorOutcome::Crashed {
            detail,
            failed_at_tick: _,
        } => apply_failure(
            state,
            invocation,
            "crash",
            detail,
            observed_at_tick,
            FailureDisposition::Retryable,
        ),
        ExecutorOutcome::TimedOut {
            detail,
            failed_at_tick: _,
        } => {
            let disposition = if invocation.registration.policy.retry_timeouts {
                FailureDisposition::RetryableTimeout
            } else {
                FailureDisposition::TerminalTimeout
            };
            apply_failure(
                state,
                invocation,
                "timeout",
                detail,
                observed_at_tick,
                disposition,
            )
        }
        ExecutorOutcome::Cancelled {
            detail,
            failed_at_tick: _,
        } => apply_failure(
            state,
            invocation,
            "cancelled",
            detail,
            observed_at_tick,
            FailureDisposition::TerminalCancellation,
        ),
        ExecutorOutcome::Unavailable {
            detail,
            failed_at_tick: _,
        } => apply_failure(
            state,
            invocation,
            "unavailable",
            detail,
            observed_at_tick,
            FailureDisposition::Retryable,
        ),
    }
}

fn apply_running_reconciliation(
    state: &mut WorkerRuntimeState,
    invocation: &WorkerInvocation,
    executor_handle: String,
    heartbeat_tick: u64,
    receipts: Vec<CapabilityInvocationReceipt>,
    observed_at_tick: u64,
) -> Result<(), WorkerRuntimeError> {
    verify_active_invocation(state, invocation)?;
    require_nonempty("executor_handle", &executor_handle)?;
    let execution = state
        .executions
        .get(&invocation.execution_id)
        .ok_or_else(|| WorkerRuntimeError::Integrity("execution disappeared".to_string()))?;
    let runtime_limit = invocation
        .acquired_at_tick
        .saturating_add(invocation.request.budget.max_runtime_ticks);
    if heartbeat_tick < invocation.acquired_at_tick
        || heartbeat_tick < execution.lease.last_heartbeat_tick
        || heartbeat_tick > observed_at_tick
    {
        return Err(WorkerRuntimeError::Conflict(
            "reconciled heartbeat is non-monotonic or outside the observable interval".to_string(),
        ));
    }
    if heartbeat_tick >= invocation.request.deadline.expires_at_tick
        || heartbeat_tick > runtime_limit
    {
        return apply_failure(
            state,
            invocation,
            "timeout",
            "reconciled heartbeat exceeded the durable execution interval".to_string(),
            observed_at_tick,
            if invocation.registration.policy.retry_timeouts {
                FailureDisposition::RetryableTimeout
            } else {
                FailureDisposition::TerminalTimeout
            },
        )
        .map(|_| ());
    }
    append_receipts(state, invocation, receipts)?;
    let execution = state
        .executions
        .get_mut(&invocation.execution_id)
        .ok_or_else(|| WorkerRuntimeError::Integrity("execution disappeared".to_string()))?;
    execution.status = ExecutionStatus::Running;
    execution.executor_handle = Some(executor_handle);
    execution.lease.last_heartbeat_tick = heartbeat_tick;
    execution.lease.expires_at_tick = heartbeat_tick
        .saturating_add(invocation.registration.policy.lease_duration_ticks)
        .min(invocation.request.deadline.expires_at_tick)
        .min(runtime_limit);
    state
        .jobs
        .get_mut(&invocation.job_id)
        .ok_or_else(|| WorkerRuntimeError::Integrity("job disappeared".to_string()))?
        .status = JobStatus::Running;
    push_event(
        state,
        observed_at_tick,
        "restart_reconciled_running",
        Some(invocation.job_id.clone()),
        Some(invocation.execution_id.clone()),
        "executor confirmed that the existing durable execution is still running".to_string(),
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum FailureDisposition {
    Retryable,
    RetryableTimeout,
    TerminalTimeout,
    TerminalCancellation,
}

fn apply_failure(
    state: &mut WorkerRuntimeState,
    invocation: &WorkerInvocation,
    class: &str,
    detail: String,
    observed_at_tick: u64,
    disposition: FailureDisposition,
) -> Result<DispatchReport, WorkerRuntimeError> {
    verify_active_invocation(state, invocation)?;
    require_nonempty("failure detail", &detail)?;
    let attempts = state
        .jobs
        .get(&invocation.job_id)
        .ok_or_else(|| WorkerRuntimeError::Integrity("failed job disappeared".to_string()))?
        .attempts;
    let attempt_limit = invocation
        .request
        .budget
        .max_attempts
        .min(invocation.registration.policy.max_attempts);
    let retryable = matches!(
        disposition,
        FailureDisposition::Retryable | FailureDisposition::RetryableTimeout
    ) && attempts < attempt_limit;
    let degraded = retryable && attempts >= invocation.registration.policy.degrade_after_attempt;

    {
        let execution = state
            .executions
            .get_mut(&invocation.execution_id)
            .ok_or_else(|| WorkerRuntimeError::Integrity("execution disappeared".to_string()))?;
        execution.status = match disposition {
            FailureDisposition::Retryable | FailureDisposition::RetryableTimeout => match class {
                "trap" => ExecutionStatus::Trapped,
                "crash" => ExecutionStatus::Crashed,
                "timeout" => ExecutionStatus::TimedOut,
                "unavailable" => ExecutionStatus::Unavailable,
                _ => ExecutionStatus::Lost,
            },
            FailureDisposition::TerminalTimeout => ExecutionStatus::TimedOut,
            FailureDisposition::TerminalCancellation => ExecutionStatus::Cancelled,
        };
        execution.terminal_detail = Some(detail.clone());
        execution.completed_at_tick = Some(observed_at_tick);
    }

    let job = state
        .jobs
        .get_mut(&invocation.job_id)
        .ok_or_else(|| WorkerRuntimeError::Integrity("job disappeared".to_string()))?;
    job.active_execution_id = None;
    if degraded
        && !job
            .failed_worker_ids
            .contains(&invocation.registration.worker_id)
    {
        job.failed_worker_ids
            .push(invocation.registration.worker_id.clone());
    }
    job.failures.push(FailureRecord {
        attempt: attempts,
        worker_id: invocation.registration.worker_id.clone(),
        class: class.to_string(),
        detail: detail.clone(),
        observed_at_tick,
        retry_scheduled: retryable,
        degraded,
    });
    job.status = if retryable {
        job.next_available_tick =
            observed_at_tick.saturating_add(invocation.registration.policy.retry_backoff_ticks);
        JobStatus::RetryPending
    } else {
        match disposition {
            FailureDisposition::TerminalCancellation => JobStatus::Cancelled,
            FailureDisposition::TerminalTimeout | FailureDisposition::RetryableTimeout => {
                JobStatus::TimedOut
            }
            FailureDisposition::Retryable => JobStatus::Failed,
        }
    };
    push_event(
        state,
        observed_at_tick,
        if retryable {
            if degraded {
                "worker_failure_degrading"
            } else {
                "worker_failure_retrying"
            }
        } else {
            "worker_failure_terminal"
        },
        Some(invocation.job_id.clone()),
        Some(invocation.execution_id.clone()),
        format!("{class}: {detail}"),
    );
    dispatch_report(state, invocation)
}

fn finalize_result(
    state: &mut WorkerRuntimeState,
    invocation: &WorkerInvocation,
    output: WorkOutput,
    completed_at_tick: u64,
) -> Result<DispatchReport, WorkerRuntimeError> {
    verify_active_invocation(state, invocation)?;
    if completed_at_tick >= invocation.request.deadline.expires_at_tick {
        return apply_failure(
            state,
            invocation,
            "timeout",
            "executor completion arrived at or after the durable deadline".to_string(),
            completed_at_tick,
            if invocation.registration.policy.retry_timeouts {
                FailureDisposition::RetryableTimeout
            } else {
                FailureDisposition::TerminalTimeout
            },
        );
    }
    if completed_at_tick.saturating_sub(
        state
            .executions
            .get(&invocation.execution_id)
            .ok_or_else(|| WorkerRuntimeError::Integrity("execution disappeared".to_string()))?
            .lease
            .acquired_at_tick,
    ) > invocation.request.budget.max_runtime_ticks
    {
        return apply_failure(
            state,
            invocation,
            "timeout",
            "executor completion exceeded max_runtime_ticks".to_string(),
            completed_at_tick,
            if invocation.registration.policy.retry_timeouts {
                FailureDisposition::RetryableTimeout
            } else {
                FailureDisposition::TerminalTimeout
            },
        );
    }
    validate_output_against_input(state, invocation, &output)?;
    let encoded_output = serde_json::to_vec(&output)
        .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
    if encoded_output.len() as u64 > invocation.request.budget.max_output_bytes {
        return apply_failure(
            state,
            invocation,
            "budget",
            "typed worker output exceeds max_output_bytes".to_string(),
            completed_at_tick,
            FailureDisposition::Retryable,
        );
    }
    let execution = state
        .executions
        .get(&invocation.execution_id)
        .ok_or_else(|| WorkerRuntimeError::Integrity("execution disappeared".to_string()))?;
    if execution.capability_receipts.is_empty()
        || !execution.capability_receipts.iter().any(|receipt| {
            receipt.service_family == invocation.registration.role.service_family()
                && receipt.operation == invocation.registration.role.operation()
        })
    {
        return apply_failure(
            state,
            invocation,
            "unattested_success",
            "executor claimed completion without a captured required-service receipt".to_string(),
            completed_at_tick,
            FailureDisposition::Retryable,
        );
    }
    let output_is_receipt_attested = execution.capability_receipts.iter().any(|receipt| {
        receipt.completed_at_tick == completed_at_tick
            && serde_json::from_slice::<WorkerServiceResponse>(&receipt.output)
                .map(WorkOutput::from)
                .is_ok_and(|attested| attested == output)
    });
    if !output_is_receipt_attested {
        return Err(WorkerRuntimeError::Conflict(
            "executor completion does not match its exact capability receipt".to_string(),
        ));
    }
    let receipt_digests = execution
        .capability_receipts
        .iter()
        .map(|receipt| {
            digest_json_content(receipt)
                .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let material = WorkerResultMaterial {
        execution_id: &invocation.execution_id,
        job_id: &invocation.job_id,
        worker_id: &invocation.registration.worker_id,
        role: invocation.registration.role,
        governance_context_digest: &invocation.request.governance_context_digest,
        output: &output,
        capability_receipt_digests: &receipt_digests,
        implementation_package_digest: &invocation.registration.executable.package_digest,
        implementation_ref: &invocation.registration.executable.implementation_ref,
        provenance: &invocation.registration.executable.provenance,
        completed_at_tick,
    };
    let result_digest = digest_json_content(&material)
        .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
    if let Some(existing_digest) = execution.result_digest.as_ref() {
        if existing_digest == &result_digest {
            return dispatch_report(state, invocation);
        }
        return Err(WorkerRuntimeError::Conflict(format!(
            "execution '{}' produced conflicting terminal results",
            invocation.execution_id
        )));
    }
    let result = PersistedWorkerResult {
        result_digest: result_digest.clone(),
        execution_id: invocation.execution_id.clone(),
        job_id: invocation.job_id.clone(),
        worker_id: invocation.registration.worker_id.clone(),
        role: invocation.registration.role,
        governance_context_digest: invocation.request.governance_context_digest.clone(),
        output,
        capability_receipt_digests: receipt_digests,
        implementation_package_digest: invocation.registration.executable.package_digest.clone(),
        implementation_ref: invocation
            .registration
            .executable
            .implementation_ref
            .clone(),
        provenance: invocation.registration.executable.provenance.clone(),
        completed_at_tick,
    };
    result.validate_digest()?;
    if let Some(existing) = state.results.get(result_digest.as_str())
        && existing != &result
    {
        return Err(WorkerRuntimeError::Conflict(format!(
            "result digest '{}' already identifies different content",
            result_digest
        )));
    }
    state.results.insert(result_digest.to_string(), result);
    {
        let execution = state
            .executions
            .get_mut(&invocation.execution_id)
            .ok_or_else(|| WorkerRuntimeError::Integrity("execution disappeared".to_string()))?;
        execution.status = ExecutionStatus::Completed;
        execution.result_digest = Some(result_digest.clone());
        execution.completed_at_tick = Some(completed_at_tick);
    }
    {
        let job = state
            .jobs
            .get_mut(&invocation.job_id)
            .ok_or_else(|| WorkerRuntimeError::Integrity("job disappeared".to_string()))?;
        if let Some(existing) = job.result_digest.as_ref()
            && existing != &result_digest
        {
            return Err(WorkerRuntimeError::Conflict(format!(
                "job '{}' received conflicting worker results",
                invocation.job_id
            )));
        }
        job.status = JobStatus::Completed;
        job.result_digest = Some(result_digest.clone());
        job.active_execution_id = None;
    }
    push_event(
        state,
        completed_at_tick,
        "worker_result_persisted",
        Some(invocation.job_id.clone()),
        Some(invocation.execution_id.clone()),
        format!("exact result digest '{result_digest}' committed"),
    );
    dispatch_report(state, invocation)
}

fn append_receipts(
    state: &mut WorkerRuntimeState,
    invocation: &WorkerInvocation,
    receipts: Vec<CapabilityInvocationReceipt>,
) -> Result<(), WorkerRuntimeError> {
    let envelope_digest = digest_json_content(&invocation.request.capability_envelope)
        .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
    let work_budget_digest = digest_json_content(&invocation.request.budget)
        .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
    let deadline_digest = digest_json_content(&invocation.request.deadline)
        .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
    let execution = state
        .executions
        .get_mut(&invocation.execution_id)
        .ok_or_else(|| WorkerRuntimeError::Integrity("execution disappeared".to_string()))?;
    for receipt in receipts {
        receipt.validate_integrity().map_err(|error| {
            WorkerRuntimeError::Integrity(format!(
                "captured capability receipt is invalid: {error}"
            ))
        })?;
        if receipt.execution_id != invocation.execution_id
            || receipt.worker_id != invocation.registration.worker_id
            || receipt.service_family != invocation.registration.role.service_family()
            || receipt.operation != invocation.registration.role.operation()
            || receipt.capability_envelope_digest != envelope_digest
            || receipt.work_budget_digest != work_budget_digest
            || receipt.deadline_digest != deadline_digest
            || receipt.effect_started_at_tick < invocation.acquired_at_tick
            || receipt.effect_started_at_tick > invocation.effect_started_at_tick
            || receipt.completed_at_tick < receipt.effect_started_at_tick
            || receipt.completed_at_tick < invocation.acquired_at_tick
            || receipt.completed_at_tick >= invocation.request.deadline.expires_at_tick
            || receipt.effect_started_at_tick >= invocation.request.deadline.expires_at_tick
            || receipt.completed_at_tick
                > invocation
                    .acquired_at_tick
                    .saturating_add(invocation.request.budget.max_runtime_ticks)
            || receipt.effect_started_at_tick
                > invocation
                    .acquired_at_tick
                    .saturating_add(invocation.request.budget.max_runtime_ticks)
        {
            return Err(WorkerRuntimeError::Integrity(
                "captured capability receipt escaped execution identity".to_string(),
            ));
        }
        if execution
            .capability_receipts
            .iter()
            .any(|known| known.receipt_id == receipt.receipt_id)
        {
            return Err(WorkerRuntimeError::Conflict(format!(
                "duplicate capability receipt '{}'",
                receipt.receipt_id
            )));
        }
        execution.capability_receipts.push(receipt);
    }
    Ok(())
}

fn verify_active_invocation(
    state: &WorkerRuntimeState,
    invocation: &WorkerInvocation,
) -> Result<(), WorkerRuntimeError> {
    let job = state.jobs.get(&invocation.job_id).ok_or_else(|| {
        WorkerRuntimeError::Integrity("executor outcome references a missing job".to_string())
    })?;
    let execution = state
        .executions
        .get(&invocation.execution_id)
        .ok_or_else(|| {
            WorkerRuntimeError::Integrity(
                "executor outcome references a missing execution".to_string(),
            )
        })?;
    if job.active_execution_id.as_deref() != Some(&invocation.execution_id)
        || !execution.status.is_active()
        || execution.lease.lease_id != invocation.lease_id
        || execution.worker_id != invocation.registration.worker_id
        || execution.lease.attempt != invocation.attempt
    {
        return Err(WorkerRuntimeError::Conflict(format!(
            "stale or mismatched executor outcome for '{}'",
            invocation.execution_id
        )));
    }
    Ok(())
}

fn dispatch_report(
    state: &WorkerRuntimeState,
    invocation: &WorkerInvocation,
) -> Result<DispatchReport, WorkerRuntimeError> {
    let job = state
        .jobs
        .get(&invocation.job_id)
        .ok_or_else(|| WorkerRuntimeError::Integrity("dispatch job disappeared".to_string()))?;
    Ok(DispatchReport {
        job_id: invocation.job_id.clone(),
        execution_id: invocation.execution_id.clone(),
        worker_id: invocation.registration.worker_id.clone(),
        status: job.status.clone(),
        result_digest: job.result_digest.clone(),
    })
}

fn classify_reconciliation_dispatch(dispatch: &DispatchReport, report: &mut ReconciliationReport) {
    if let Some(digest) = &dispatch.result_digest {
        report.recovered_result_digests.push(digest.clone());
    }
    if dispatch.status == JobStatus::RetryPending {
        report.retried_job_ids.push(dispatch.job_id.clone());
    } else if dispatch.status.is_terminal() {
        report.terminal_job_ids.push(dispatch.job_id.clone());
    }
}

fn validate_result_citations(
    state: &WorkerRuntimeState,
    governance_context_digest: &ContentDigest,
    input: &WorkInput,
) -> Result<(), WorkerRuntimeError> {
    let citations = input.result_citations();
    let mut unique = BTreeSet::new();
    for digest in &citations {
        if !unique.insert((*digest).clone()) {
            return Err(WorkerRuntimeError::Conflict(format!(
                "typed input contains duplicate result digest '{digest}'"
            )));
        }
    }
    let load = |digest: &ContentDigest,
                expected_role: GovernedWorkerRole|
     -> Result<&PersistedWorkerResult, WorkerRuntimeError> {
        let result = state.results.get(digest.as_str()).ok_or_else(|| {
            WorkerRuntimeError::NotFound(format!(
                "typed input invented or supplied unknown result digest '{digest}'"
            ))
        })?;
        result.validate_digest()?;
        if result.role != expected_role {
            return Err(WorkerRuntimeError::Conflict(format!(
                "result '{digest}' has role '{}' but '{}' was required",
                result.role.as_str(),
                expected_role.as_str()
            )));
        }
        if &result.governance_context_digest != governance_context_digest {
            return Err(WorkerRuntimeError::Conflict(format!(
                "result '{digest}' belongs to a different governance context"
            )));
        }
        let execution = state.executions.get(&result.execution_id).ok_or_else(|| {
            WorkerRuntimeError::Integrity("cited result execution is missing".to_string())
        })?;
        if execution.status != ExecutionStatus::Completed
            || execution.result_digest.as_ref() != Some(digest)
        {
            return Err(WorkerRuntimeError::Integrity(format!(
                "cited result '{digest}' is not the exact terminal execution result"
            )));
        }
        Ok(result)
    };

    match input {
        WorkInput::Plan { .. } => Ok(()),
        WorkInput::Build {
            plan_result_digest, ..
        } => load(plan_result_digest, GovernedWorkerRole::Planner).map(|_| ()),
        WorkInput::Validate {
            plan_result_digest,
            build_result_digest,
            expected_artifact_digest,
            ..
        } => {
            load(plan_result_digest, GovernedWorkerRole::Planner)?;
            let build = load(build_result_digest, GovernedWorkerRole::Builder)?;
            match &build.output {
                WorkOutput::Build {
                    plan_result_digest: actual_plan,
                    artifact_digest,
                    ..
                } if actual_plan == plan_result_digest
                    && artifact_digest == expected_artifact_digest =>
                {
                    Ok(())
                }
                _ => Err(WorkerRuntimeError::Conflict(
                    "validator input does not match the exact persisted builder result".to_string(),
                )),
            }
        }
        WorkInput::Review {
            plan_result_digest,
            build_result_digest,
            validation_result_digest,
        } => {
            load(plan_result_digest, GovernedWorkerRole::Planner)?;
            load(build_result_digest, GovernedWorkerRole::Builder)?;
            let validation = load(validation_result_digest, GovernedWorkerRole::Validator)?;
            match &validation.output {
                WorkOutput::Validate {
                    plan_result_digest: actual_plan,
                    build_result_digest: actual_build,
                    ..
                } if actual_plan == plan_result_digest && actual_build == build_result_digest => {
                    Ok(())
                }
                _ => Err(WorkerRuntimeError::Conflict(
                    "review input does not preserve the planner/builder/validator lineage"
                        .to_string(),
                )),
            }
        }
        WorkInput::Package {
            build_result_digest,
            validation_result_digest,
            review_result_digest,
        } => {
            load(build_result_digest, GovernedWorkerRole::Builder)?;
            let validation = load(validation_result_digest, GovernedWorkerRole::Validator)?;
            let review = load(review_result_digest, GovernedWorkerRole::Reviewer)?;
            if !matches!(
                validation.output,
                WorkOutput::Validate {
                    build_result_digest: ref actual_build,
                    passed: true,
                    ..
                } if actual_build == build_result_digest
            ) {
                return Err(WorkerRuntimeError::Conflict(
                    "packaging requires a passing validation of the cited build".to_string(),
                ));
            }
            match &review.output {
                WorkOutput::Review {
                    build_result_digest: actual_build,
                    validation_result_digest: actual_validation,
                    decision: ReviewDecision::Approve,
                    ..
                } if actual_build == build_result_digest
                    && actual_validation == validation_result_digest =>
                {
                    Ok(())
                }
                _ => Err(WorkerRuntimeError::Conflict(
                    "packaging requires an approving review of the cited build and validation"
                        .to_string(),
                )),
            }
        }
        WorkInput::Continue {
            package_result_digest,
            ..
        } => load(package_result_digest, GovernedWorkerRole::Packager).map(|_| ()),
    }
}

fn validate_output_against_input(
    state: &WorkerRuntimeState,
    invocation: &WorkerInvocation,
    output: &WorkOutput,
) -> Result<(), WorkerRuntimeError> {
    if output.role() != invocation.registration.role
        || output.role() != invocation.request.input.role()
    {
        return Err(WorkerRuntimeError::Conflict(
            "executor returned an output for a different worker role".to_string(),
        ));
    }
    match (&invocation.request.input, output) {
        (
            WorkInput::Plan {
                baseline_digest, ..
            },
            WorkOutput::Plan {
                baseline_digest: actual,
                ..
            },
        ) if actual == baseline_digest => Ok(()),
        (
            WorkInput::Build {
                plan_result_digest,
                expected_before_digest,
                replacement_bytes,
                ..
            },
            WorkOutput::Build {
                plan_result_digest: actual_plan,
                before_digest,
                artifact_digest,
            },
        ) if actual_plan == plan_result_digest
            && before_digest == expected_before_digest
            && artifact_digest == &ContentDigest::from_bytes(replacement_bytes) =>
        {
            Ok(())
        }
        (
            WorkInput::Validate {
                plan_result_digest,
                build_result_digest,
                expected_artifact_digest,
                ..
            },
            WorkOutput::Validate {
                plan_result_digest: actual_plan,
                build_result_digest: actual_build,
                artifact_digest,
                ..
            },
        ) if actual_plan == plan_result_digest
            && actual_build == build_result_digest
            && artifact_digest == expected_artifact_digest =>
        {
            let build = state
                .results
                .get(build_result_digest.as_str())
                .ok_or_else(|| {
                    WorkerRuntimeError::Integrity(
                        "validator's cited builder result disappeared".to_string(),
                    )
                })?;
            match &build.output {
                WorkOutput::Build {
                    artifact_digest: built,
                    ..
                } if built == artifact_digest => Ok(()),
                _ => Err(WorkerRuntimeError::Conflict(
                    "validator did not prove the exact persisted builder artifact".to_string(),
                )),
            }
        }
        (
            WorkInput::Review {
                build_result_digest,
                validation_result_digest,
                ..
            },
            WorkOutput::Review {
                build_result_digest: actual_build,
                validation_result_digest: actual_validation,
                ..
            },
        ) if actual_build == build_result_digest
            && actual_validation == validation_result_digest =>
        {
            Ok(())
        }
        (
            WorkInput::Package {
                build_result_digest,
                validation_result_digest,
                review_result_digest,
            },
            WorkOutput::Package {
                build_result_digest: actual_build,
                validation_result_digest: actual_validation,
                review_result_digest: actual_review,
                ..
            },
        ) if actual_build == build_result_digest
            && actual_validation == validation_result_digest
            && actual_review == review_result_digest =>
        {
            Ok(())
        }
        (
            WorkInput::Continue {
                package_result_digest,
                ..
            },
            WorkOutput::Continue {
                package_result_digest: actual,
                ..
            },
        ) if actual == package_result_digest => Ok(()),
        _ => Err(WorkerRuntimeError::Conflict(
            "worker output does not exactly match its persisted typed input".to_string(),
        )),
    }
}

fn validate_envelope(request: &WorkerJobRequest) -> Result<(), WorkerRuntimeError> {
    let envelope = &request.capability_envelope;
    require_nonempty("capability envelope id", &envelope.envelope_id)?;
    require_nonempty("capability actor_scope", &envelope.actor_scope)?;
    let world = request.role.required_world();
    let operation = request.role.operation();
    let authority = request.role.required_authority();
    if !envelope.grants_world(&world)
        || !envelope.allows_operation(&world, operation)
        || !envelope.authority_allows(&authority)
    {
        return Err(WorkerRuntimeError::CapabilityDenied(format!(
            "envelope '{}' does not grant '{}:{}' at required authority",
            envelope.envelope_id,
            request.role.as_str(),
            operation
        )));
    }
    if envelope.approval_for(&world, operation) != Some(ApprovalClass::AutoAllowed) {
        return Err(WorkerRuntimeError::CapabilityDenied(
            "worker request has no resolved auto-allowed approval state".to_string(),
        ));
    }
    for resource in &request.workspace_scope.resource_scopes {
        if !envelope.scope_allows(resource) {
            return Err(WorkerRuntimeError::CapabilityDenied(format!(
                "envelope '{}' does not grant resource scope '{resource}'",
                envelope.envelope_id
            )));
        }
    }
    Ok(())
}

fn validate_state_integrity(state: &WorkerRuntimeState) -> Result<(), WorkerRuntimeError> {
    if state.schema_version != STATE_SCHEMA_VERSION {
        return Err(WorkerRuntimeError::Integrity(format!(
            "unsupported worker runtime schema version {}",
            state.schema_version
        )));
    }
    if state.events.iter().any(|event| {
        if event.tick == u64::MAX {
            state.next_logical_tick != u64::MAX
        } else {
            state.next_logical_tick <= event.tick
        }
    }) {
        return Err(WorkerRuntimeError::Integrity(
            "logical tick allocator is behind a durable runtime event".to_string(),
        ));
    }
    if state
        .events
        .iter()
        .any(|event| event.sequence >= state.next_sequence)
        || state
            .events
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence || pair[0].tick > pair[1].tick)
    {
        return Err(WorkerRuntimeError::Integrity(
            "durable runtime events are not in strict sequence and monotonic tick order"
                .to_string(),
        ));
    }
    for (worker_id, registration) in &state.registrations {
        registration.validate()?;
        if worker_id != &registration.worker_id {
            return Err(WorkerRuntimeError::Integrity(
                "registration map key does not match worker id".to_string(),
            ));
        }
    }
    for (job_id, job) in &state.jobs {
        if job_id != &job.job_id {
            return Err(WorkerRuntimeError::Integrity(
                "job map key does not match durable job id".to_string(),
            ));
        }
        job.request.validate()?;
        let input_digest =
            governed_work_input_digest(&job.request.governance_context_digest, &job.request.input)?;
        if input_digest != job.input_digest {
            return Err(WorkerRuntimeError::Integrity(format!(
                "job '{job_id}' typed input digest is corrupted"
            )));
        }
        if matches!(job.status, JobStatus::Leased | JobStatus::Running)
            && job.active_execution_id.is_none()
        {
            return Err(WorkerRuntimeError::Integrity(format!(
                "active job '{job_id}' has no execution"
            )));
        }
        if job.status == JobStatus::Completed && job.result_digest.is_none() {
            return Err(WorkerRuntimeError::Integrity(format!(
                "completed job '{job_id}' has no result"
            )));
        }
        if !matches!(job.status, JobStatus::Leased | JobStatus::Running)
            && job.active_execution_id.is_some()
        {
            return Err(WorkerRuntimeError::Integrity(format!(
                "non-active job '{job_id}' retains an execution lease"
            )));
        }
        if job.status != JobStatus::Completed && job.result_digest.is_some() {
            return Err(WorkerRuntimeError::Integrity(format!(
                "non-completed job '{job_id}' retains a result digest"
            )));
        }
        if let Some(active_execution_id) = &job.active_execution_id {
            let execution = state.executions.get(active_execution_id).ok_or_else(|| {
                WorkerRuntimeError::Integrity(format!(
                    "active job '{job_id}' references a missing execution"
                ))
            })?;
            if execution.job_id != *job_id || !execution.status.is_active() {
                return Err(WorkerRuntimeError::Integrity(format!(
                    "active job '{job_id}' does not own one exact active execution"
                )));
            }
        }
        if let Some(result_digest) = &job.result_digest
            && !state.results.contains_key(result_digest.as_str())
        {
            return Err(WorkerRuntimeError::Integrity(format!(
                "job '{job_id}' references a missing result"
            )));
        }
    }
    for (execution_id, execution) in &state.executions {
        if execution_id != &execution.execution_id {
            return Err(WorkerRuntimeError::Integrity(
                "execution map key does not match execution id".to_string(),
            ));
        }
        let job = state.jobs.get(&execution.job_id).ok_or_else(|| {
            WorkerRuntimeError::Integrity(format!(
                "execution '{execution_id}' references a missing job"
            ))
        })?;
        if execution.role != job.request.role {
            return Err(WorkerRuntimeError::Integrity(format!(
                "execution '{execution_id}' role differs from its job"
            )));
        }
        if execution.governance_context_digest != job.request.governance_context_digest {
            return Err(WorkerRuntimeError::Integrity(format!(
                "execution '{execution_id}' governance context differs from its job"
            )));
        }
        let registration = state
            .registrations
            .get(&execution.worker_id)
            .ok_or_else(|| {
                WorkerRuntimeError::Integrity(format!(
                    "execution '{execution_id}' references a missing worker"
                ))
            })?;
        if registration.role != execution.role
            || registration.executable.package_digest != execution.implementation_package_digest
            || registration.executable.implementation_ref != execution.implementation_ref
            || registration.executable.provenance != execution.provenance
        {
            return Err(WorkerRuntimeError::Integrity(format!(
                "execution '{execution_id}' no longer resolves its exact registered package and provenance"
            )));
        }
        if execution.lease.execution_id != *execution_id
            || execution.lease.worker_id != execution.worker_id
            || execution.lease.attempt == 0
            || execution.lease.attempt > job.attempts
            || execution.lease.acquired_at_tick > execution.lease.last_heartbeat_tick
            || execution.lease.last_heartbeat_tick > execution.lease.expires_at_tick
            || execution.lease.expires_at_tick > job.request.deadline.expires_at_tick
            || execution.lease.expires_at_tick
                > execution
                    .lease
                    .acquired_at_tick
                    .saturating_add(job.request.budget.max_runtime_ticks)
        {
            return Err(WorkerRuntimeError::Integrity(format!(
                "execution '{execution_id}' contains a malformed or over-budget lease"
            )));
        }
        if execution.status.is_active() && job.active_execution_id.as_deref() != Some(execution_id)
        {
            return Err(WorkerRuntimeError::Integrity(format!(
                "active execution '{execution_id}' is not owned by its job"
            )));
        }
        if execution.status == ExecutionStatus::Completed
            && (execution.result_digest.is_none() || execution.completed_at_tick.is_none())
        {
            return Err(WorkerRuntimeError::Integrity(format!(
                "completed execution '{execution_id}' has no exact result or completion tick"
            )));
        }
        if execution.status != ExecutionStatus::Completed && execution.result_digest.is_some() {
            return Err(WorkerRuntimeError::Integrity(format!(
                "non-completed execution '{execution_id}' retains a result digest"
            )));
        }
        let envelope_digest = digest_json_content(&job.request.capability_envelope)
            .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
        let work_budget_digest = digest_json_content(&job.request.budget)
            .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
        let deadline_digest = digest_json_content(&job.request.deadline)
            .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
        let mut receipt_ids = BTreeSet::new();
        for receipt in &execution.capability_receipts {
            receipt.validate_integrity().map_err(|error| {
                WorkerRuntimeError::Integrity(format!(
                    "execution '{execution_id}' contains an invalid capability receipt: {error}"
                ))
            })?;
            if receipt.execution_id != *execution_id
                || receipt.worker_id != execution.worker_id
                || receipt.service_family != execution.role.service_family()
                || receipt.operation != execution.role.operation()
                || receipt.governance_context_digest != job.request.governance_context_digest
                || receipt.capability_envelope_digest != envelope_digest
                || receipt.work_budget_digest != work_budget_digest
                || receipt.deadline_digest != deadline_digest
                || receipt.effect_started_at_tick < execution.lease.acquired_at_tick
                || receipt.completed_at_tick < receipt.effect_started_at_tick
                || receipt.effect_started_at_tick >= job.request.deadline.expires_at_tick
                || receipt.completed_at_tick < execution.lease.acquired_at_tick
                || receipt.completed_at_tick >= job.request.deadline.expires_at_tick
                || receipt.effect_started_at_tick
                    > execution
                        .lease
                        .acquired_at_tick
                        .saturating_add(job.request.budget.max_runtime_ticks)
                || receipt.completed_at_tick
                    > execution
                        .lease
                        .acquired_at_tick
                        .saturating_add(job.request.budget.max_runtime_ticks)
                || !receipt_ids.insert(receipt.receipt_id.clone())
            {
                return Err(WorkerRuntimeError::Integrity(format!(
                    "execution '{execution_id}' contains an invalid capability receipt"
                )));
            }
        }
    }
    let mut result_jobs = BTreeSet::new();
    let mut result_executions = BTreeSet::new();
    for result in state.results.values() {
        if !result_jobs.insert(result.job_id.clone())
            || !result_executions.insert(result.execution_id.clone())
        {
            return Err(WorkerRuntimeError::Conflict(
                "durable state contains conflicting results for one job or execution".to_string(),
            ));
        }
    }
    for (digest_key, result) in &state.results {
        result.validate_digest()?;
        if digest_key != result.result_digest.as_str() {
            return Err(WorkerRuntimeError::Integrity(
                "result map key does not match result digest".to_string(),
            ));
        }
        let job = state.jobs.get(&result.job_id).ok_or_else(|| {
            WorkerRuntimeError::Integrity("result references a missing job".to_string())
        })?;
        let execution = state.executions.get(&result.execution_id).ok_or_else(|| {
            WorkerRuntimeError::Integrity("result references a missing execution".to_string())
        })?;
        let registration = state.registrations.get(&result.worker_id).ok_or_else(|| {
            WorkerRuntimeError::Integrity("result references a missing worker".to_string())
        })?;
        let receipt_digests = execution
            .capability_receipts
            .iter()
            .map(|receipt| {
                digest_json_content(receipt)
                    .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if job.result_digest.as_ref() != Some(&result.result_digest)
            || execution.result_digest.as_ref() != Some(&result.result_digest)
            || job.status != JobStatus::Completed
            || execution.status != ExecutionStatus::Completed
            || result.job_id != execution.job_id
            || result.worker_id != execution.worker_id
            || result.role != execution.role
            || result.governance_context_digest != execution.governance_context_digest
            || result.governance_context_digest != job.request.governance_context_digest
            || result.output.role() != result.role
            || result.capability_receipt_digests != receipt_digests
            || result.implementation_package_digest != execution.implementation_package_digest
            || result.implementation_ref != execution.implementation_ref
            || result.provenance != execution.provenance
            || result.completed_at_tick != execution.completed_at_tick.unwrap_or_default()
            || registration.executable.package_digest != result.implementation_package_digest
            || registration.executable.implementation_ref != result.implementation_ref
            || registration.executable.provenance != result.provenance
        {
            return Err(WorkerRuntimeError::Integrity(format!(
                "result '{}' is not linked to one exact completed job and execution",
                result.result_digest
            )));
        }
    }
    for (synthesis_id, synthesis) in &state.syntheses {
        if synthesis_id != &synthesis.synthesis_id {
            return Err(WorkerRuntimeError::Integrity(
                "synthesis map key does not match synthesis id".to_string(),
            ));
        }
        if synthesis.cited_result_digests.len() != synthesis.cited_execution_ids.len()
            || synthesis.cited_result_digests.len() != synthesis.cited_roles.len()
        {
            return Err(WorkerRuntimeError::Integrity(format!(
                "synthesis '{synthesis_id}' has misaligned citations"
            )));
        }
        let actual = digest_json_content(&SynthesisMaterial {
            synthesis_id,
            cited_result_digests: &synthesis.cited_result_digests,
            cited_execution_ids: &synthesis.cited_execution_ids,
            cited_roles: &synthesis.cited_roles,
            created_at_tick: synthesis.created_at_tick,
        })
        .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
        if actual != synthesis.synthesis_digest {
            return Err(WorkerRuntimeError::Integrity(format!(
                "synthesis '{synthesis_id}' digest is corrupted"
            )));
        }
        for digest in &synthesis.cited_result_digests {
            if !state.results.contains_key(digest.as_str()) {
                return Err(WorkerRuntimeError::Integrity(format!(
                    "synthesis '{synthesis_id}' cites a missing result"
                )));
            }
        }
    }
    Ok(())
}

fn prepare_store_root(root: &Path) -> Result<(), WorkerRuntimeError> {
    if root.exists() {
        let metadata =
            fs::symlink_metadata(root).map_err(|error| WorkerRuntimeError::io(root, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(WorkerRuntimeError::Integrity(format!(
                "worker runtime root '{}' must be a real directory",
                root.display()
            )));
        }
    } else {
        fs::create_dir_all(root).map_err(|error| WorkerRuntimeError::io(root, error))?;
    }
    let state_path = root.join(STATE_FILE_NAME);
    if state_path.exists() {
        let metadata = fs::symlink_metadata(&state_path)
            .map_err(|error| WorkerRuntimeError::io(&state_path, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(WorkerRuntimeError::Integrity(format!(
                "worker state '{}' must be a regular file",
                state_path.display()
            )));
        }
    }
    let lock_path = root.join(STORE_LOCK_FILE_NAME);
    if lock_path.exists() {
        let metadata = fs::symlink_metadata(&lock_path)
            .map_err(|error| WorkerRuntimeError::io(&lock_path, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(WorkerRuntimeError::Integrity(format!(
                "worker store lock '{}' must be a regular file",
                lock_path.display()
            )));
        }
    }
    Ok(())
}

fn acquire_store_lock(root: &Path) -> Result<File, WorkerRuntimeError> {
    let lock_path = root.join(STORE_LOCK_FILE_NAME);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| WorkerRuntimeError::io(&lock_path, error))?;
    file.try_lock().map_err(|error| {
        WorkerRuntimeError::Conflict(format!(
            "worker runtime store '{}' cannot acquire its exclusive lock: {error}",
            root.display()
        ))
    })?;
    Ok(file)
}

fn read_state(path: &Path) -> Result<WorkerRuntimeState, WorkerRuntimeError> {
    let mut file = File::open(path).map_err(|error| WorkerRuntimeError::io(path, error))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| WorkerRuntimeError::io(path, error))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))
}

fn persist_state(root: &Path, state: &WorkerRuntimeState) -> Result<(), WorkerRuntimeError> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;
    let target = root.join(STATE_FILE_NAME);
    if target.exists() {
        let metadata = fs::symlink_metadata(&target)
            .map_err(|error| WorkerRuntimeError::io(&target, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(WorkerRuntimeError::Integrity(format!(
                "refusing to replace non-regular state '{}'",
                target.display()
            )));
        }
    }
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(
        ".worker-runtime-state.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| WorkerRuntimeError::io(&temporary, error))?;
        file.write_all(&bytes)
            .map_err(|error| WorkerRuntimeError::io(&temporary, error))?;
        file.sync_all()
            .map_err(|error| WorkerRuntimeError::io(&temporary, error))?;
        fs::rename(&temporary, &target).map_err(|error| WorkerRuntimeError::io(&target, error))?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| WorkerRuntimeError::io(root, error))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn push_event(
    state: &mut WorkerRuntimeState,
    requested_tick: u64,
    class: &str,
    job_id: Option<String>,
    execution_id: Option<String>,
    detail: String,
) {
    let tick = state
        .events
        .last()
        .map_or(requested_tick, |event| event.tick.max(requested_tick));
    state.next_logical_tick = state.next_logical_tick.max(tick.saturating_add(1));
    let sequence = take_sequence(state);
    state.events.push(RuntimeEvent {
        sequence,
        tick,
        class: class.to_string(),
        job_id,
        execution_id,
        detail,
    });
}

const fn default_next_logical_tick() -> u64 {
    1
}

fn take_sequence(state: &mut WorkerRuntimeState) -> u64 {
    let sequence = state.next_sequence;
    state.next_sequence = state.next_sequence.saturating_add(1);
    sequence
}

fn digest_suffix(digest: &ContentDigest) -> &str {
    let value = digest.as_str();
    &value[value.len().saturating_sub(12)..]
}

fn require_nonempty(field: &str, value: &str) -> Result<(), WorkerRuntimeError> {
    if value.trim().is_empty() {
        return Err(WorkerRuntimeError::InvalidRequest(format!(
            "{field} is required"
        )));
    }
    Ok(())
}

fn require_unique_nonempty(field: &str, values: &[String]) -> Result<(), WorkerRuntimeError> {
    if values.is_empty() {
        return Err(WorkerRuntimeError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        require_nonempty(field, value)?;
        if !unique.insert(value) {
            return Err(WorkerRuntimeError::InvalidRequest(format!(
                "{field} contains duplicate value '{value}'"
            )));
        }
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), WorkerRuntimeError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(WorkerRuntimeError::InvalidRequest(
            "worker target path must be a non-empty relative path".to_string(),
        ));
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(WorkerRuntimeError::InvalidRequest(
                "worker target path may not traverse or escape its workspace".to_string(),
            ));
        }
    }
    Ok(())
}

/// Stable request schema used by the bounded reference executor adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerServiceRequest {
    pub schema: String,
    pub execution_id: String,
    pub role: GovernedWorkerRole,
    pub governance_context_digest: ContentDigest,
    pub input_digest: ContentDigest,
    pub input: WorkInput,
}

/// Stable response schema used by the bounded reference executor adapter.
///
/// M3 implementations can support this schema directly, or an M2 executor can
/// translate it to a component/provider-specific wire format. The runtime
/// still validates the resulting `WorkOutput` against durable inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkerServiceResponse {
    Plan {
        baseline_digest: ContentDigest,
        plan_digest: ContentDigest,
    },
    Build {
        plan_result_digest: ContentDigest,
        before_digest: ContentDigest,
        artifact_digest: ContentDigest,
    },
    Validate {
        plan_result_digest: ContentDigest,
        build_result_digest: ContentDigest,
        artifact_digest: ContentDigest,
        proving_digest: ContentDigest,
        passed: bool,
    },
    Review {
        build_result_digest: ContentDigest,
        validation_result_digest: ContentDigest,
        decision: ReviewDecision,
        review_digest: ContentDigest,
    },
    Package {
        build_result_digest: ContentDigest,
        validation_result_digest: ContentDigest,
        review_result_digest: ContentDigest,
        package_digest: ContentDigest,
    },
    Continue {
        package_result_digest: ContentDigest,
        checkpoint_digest: ContentDigest,
    },
}

impl From<WorkerServiceResponse> for WorkOutput {
    fn from(response: WorkerServiceResponse) -> Self {
        match response {
            WorkerServiceResponse::Plan {
                baseline_digest,
                plan_digest,
            } => Self::Plan {
                baseline_digest,
                plan_digest,
            },
            WorkerServiceResponse::Build {
                plan_result_digest,
                before_digest,
                artifact_digest,
            } => Self::Build {
                plan_result_digest,
                before_digest,
                artifact_digest,
            },
            WorkerServiceResponse::Validate {
                plan_result_digest,
                build_result_digest,
                artifact_digest,
                proving_digest,
                passed,
            } => Self::Validate {
                plan_result_digest,
                build_result_digest,
                artifact_digest,
                proving_digest,
                passed,
            },
            WorkerServiceResponse::Review {
                build_result_digest,
                validation_result_digest,
                decision,
                review_digest,
            } => Self::Review {
                build_result_digest,
                validation_result_digest,
                decision,
                review_digest,
            },
            WorkerServiceResponse::Package {
                build_result_digest,
                validation_result_digest,
                review_result_digest,
                package_digest,
            } => Self::Package {
                build_result_digest,
                validation_result_digest,
                review_result_digest,
                package_digest,
            },
            WorkerServiceResponse::Continue {
                package_result_digest,
                checkpoint_digest,
            } => Self::Continue {
                package_result_digest,
                checkpoint_digest,
            },
        }
    }
}

/// A concrete M2 adapter for the bounded worker-service schema.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReferenceWorkerExecutor;

impl ReferenceWorkerExecutor {
    fn capability_request(
        invocation: &WorkerInvocation,
    ) -> Result<CapabilityInvocationRequest, String> {
        let input_digest = governed_work_input_digest(
            &invocation.request.governance_context_digest,
            &invocation.request.input,
        )
        .map_err(|error| format!("cannot encode governed worker input: {error}"))?;
        let service_request = WorkerServiceRequest {
            schema: REFERENCE_SERVICE_SCHEMA.to_string(),
            execution_id: invocation.execution_id.clone(),
            role: invocation.registration.role,
            governance_context_digest: invocation.request.governance_context_digest.clone(),
            input_digest,
            input: invocation.request.input.clone(),
        };
        let payload = serde_json::to_vec(&service_request)
            .map_err(|error| format!("cannot serialize worker service request: {error}"))?;
        let resource_scope = invocation
            .request
            .workspace_scope
            .resource_scopes
            .first()
            .cloned()
            .ok_or_else(|| "worker has no resource scope".to_string())?;
        Ok(CapabilityInvocationRequest {
            execution_id: invocation.execution_id.clone(),
            acquired_at_tick: invocation.acquired_at_tick,
            effect_started_at_tick: invocation.effect_started_at_tick,
            worker_id: invocation.registration.worker_id.clone(),
            role: invocation.registration.role,
            governance_context_digest: invocation.request.governance_context_digest.clone(),
            service_family: invocation.registration.role.service_family().to_string(),
            world: invocation.registration.role.required_world(),
            operation: invocation.registration.role.operation().to_string(),
            required_authority: invocation.registration.role.required_authority(),
            capability_envelope: invocation.request.capability_envelope.clone(),
            workspace_scope: invocation.request.workspace_scope.clone(),
            work_budget: invocation.request.budget.clone(),
            deadline: invocation.request.deadline.clone(),
            resource_scope,
            payload,
        })
    }

    fn completed_outcome(receipt: CapabilityInvocationReceipt) -> Result<ExecutorOutcome, String> {
        let response =
            serde_json::from_slice::<WorkerServiceResponse>(&receipt.output).map_err(|error| {
                format!("capability service returned an invalid typed response: {error}")
            })?;
        Ok(ExecutorOutcome::Completed {
            output: response.into(),
            completed_at_tick: receipt.completed_at_tick,
        })
    }
}

impl DurableJobExecutor for ReferenceWorkerExecutor {
    fn dispatch(
        &self,
        invocation: &WorkerInvocation,
        capabilities: &dyn CapabilityServiceInvoker,
    ) -> ExecutorOutcome {
        let capability_request = match Self::capability_request(invocation) {
            Ok(request) => request,
            Err(detail) => {
                return ExecutorOutcome::Trapped {
                    detail,
                    failed_at_tick: invocation.effect_started_at_tick,
                };
            }
        };
        let receipt = match capabilities.invoke(&capability_request) {
            Ok(receipt) => receipt,
            Err(CapabilityServiceFailure::TimedOut(detail)) => {
                return ExecutorOutcome::TimedOut {
                    detail,
                    failed_at_tick: invocation.effect_started_at_tick,
                };
            }
            Err(CapabilityServiceFailure::Unavailable(detail)) => {
                return ExecutorOutcome::Unavailable {
                    detail,
                    failed_at_tick: invocation.effect_started_at_tick,
                };
            }
            Err(error) => {
                return ExecutorOutcome::Trapped {
                    detail: error.to_string(),
                    failed_at_tick: invocation.effect_started_at_tick,
                };
            }
        };
        let failed_at_tick = receipt.completed_at_tick;
        match Self::completed_outcome(receipt) {
            Ok(outcome) => outcome,
            Err(detail) => ExecutorOutcome::Trapped {
                detail,
                failed_at_tick,
            },
        }
    }

    fn reconcile(
        &self,
        invocation: &WorkerInvocation,
        _capabilities: &dyn CapabilityServiceInvoker,
    ) -> ExecutorReconciliation {
        ExecutorReconciliation::Unknown {
            detail: "stateless reference executor has no retained external handle".to_string(),
            observed_at_tick: invocation.effect_started_at_tick,
        }
    }

    fn recover_terminal(
        &self,
        invocation: &WorkerInvocation,
        capabilities: &dyn CapabilityServiceInvoker,
    ) -> Result<Option<ExecutorOutcome>, String> {
        let request = Self::capability_request(invocation)?;
        capabilities
            .recover(&request)
            .map_err(|error| error.to_string())?
            .map(Self::completed_outcome)
            .transpose()
    }

    fn cancel(&self, _execution_id: &str, _cancellation_token: &str) -> Result<(), String> {
        Ok(())
    }
}

/// A local M3 reference implementation with real, scope-checked filesystem
/// mutation and independent validation.
#[cfg(test)]
pub struct LocalReferenceCapabilityServices {
    allowed_roots: Vec<PathBuf>,
    implementation_ref: String,
    implementation_digest: ContentDigest,
    logical_clock: AtomicU64,
}

#[cfg(test)]
impl LocalReferenceCapabilityServices {
    pub fn new(
        allowed_roots: Vec<PathBuf>,
        implementation_ref: impl Into<String>,
        implementation_bytes: &[u8],
        first_tick: u64,
    ) -> Result<Self, WorkerRuntimeError> {
        if allowed_roots.is_empty() {
            return Err(WorkerRuntimeError::InvalidRegistration(
                "local capability services require at least one allowed root".to_string(),
            ));
        }
        let mut canonical_roots = Vec::new();
        for root in allowed_roots {
            let canonical =
                fs::canonicalize(&root).map_err(|error| WorkerRuntimeError::io(&root, error))?;
            if !canonical.is_dir() {
                return Err(WorkerRuntimeError::InvalidRegistration(format!(
                    "allowed service root '{}' is not a directory",
                    canonical.display()
                )));
            }
            canonical_roots.push(canonical);
        }
        let implementation_ref = implementation_ref.into();
        require_nonempty("implementation_ref", &implementation_ref)?;
        Ok(Self {
            allowed_roots: canonical_roots,
            implementation_ref,
            implementation_digest: ContentDigest::from_bytes(implementation_bytes),
            logical_clock: AtomicU64::new(first_tick),
        })
    }

    fn checked_root(&self, requested: &Path) -> Result<PathBuf, CapabilityServiceFailure> {
        let canonical = fs::canonicalize(requested).map_err(|error| {
            CapabilityServiceFailure::Denied(format!(
                "workspace root '{}' cannot be resolved: {error}",
                requested.display()
            ))
        })?;
        if !self.allowed_roots.iter().any(|root| root == &canonical) {
            return Err(CapabilityServiceFailure::Denied(format!(
                "workspace root '{}' is outside local service policy",
                canonical.display()
            )));
        }
        Ok(canonical)
    }

    fn execute(
        &self,
        request: &CapabilityInvocationRequest,
        service_request: &WorkerServiceRequest,
    ) -> Result<WorkerServiceResponse, CapabilityServiceFailure> {
        let root = self.checked_root(&request.workspace_scope.workspace_root)?;
        match &service_request.input {
            WorkInput::Plan {
                objective,
                baseline_digest,
            } => {
                #[derive(Serialize)]
                struct PlanMaterial<'a> {
                    objective: &'a str,
                    baseline_digest: &'a ContentDigest,
                }
                let plan_digest = digest_json_content(&PlanMaterial {
                    objective,
                    baseline_digest,
                })
                .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
                Ok(WorkerServiceResponse::Plan {
                    baseline_digest: baseline_digest.clone(),
                    plan_digest,
                })
            }
            WorkInput::Build {
                plan_result_digest,
                target_relative_path,
                expected_before_digest,
                replacement_bytes,
            } => {
                let target = checked_target(&root, target_relative_path)?;
                let before = read_optional_regular_file(&target)?;
                let actual_before = ContentDigest::from_bytes(&before);
                if &actual_before != expected_before_digest {
                    return Err(CapabilityServiceFailure::Failed(format!(
                        "candidate precondition mismatch: expected '{expected_before_digest}', got '{actual_before}'"
                    )));
                }
                atomic_replace_scoped(&target, replacement_bytes)?;
                let persisted = read_optional_regular_file(&target)?;
                if persisted != *replacement_bytes {
                    return Err(CapabilityServiceFailure::Failed(
                        "candidate workspace bytes differ after atomic mutation".to_string(),
                    ));
                }
                Ok(WorkerServiceResponse::Build {
                    plan_result_digest: plan_result_digest.clone(),
                    before_digest: actual_before,
                    artifact_digest: ContentDigest::from_bytes(&persisted),
                })
            }
            WorkInput::Validate {
                plan_result_digest,
                build_result_digest,
                target_relative_path,
                expected_artifact_digest,
                suite_digest,
            } => {
                let target = checked_target(&root, target_relative_path)?;
                let persisted = read_optional_regular_file(&target)?;
                let artifact_digest = ContentDigest::from_bytes(&persisted);
                #[derive(Serialize)]
                struct ProofMaterial<'a> {
                    suite_digest: &'a ContentDigest,
                    artifact_digest: &'a ContentDigest,
                    bytes: &'a [u8],
                }
                let proving_digest = digest_json_content(&ProofMaterial {
                    suite_digest,
                    artifact_digest: &artifact_digest,
                    bytes: &persisted,
                })
                .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
                Ok(WorkerServiceResponse::Validate {
                    plan_result_digest: plan_result_digest.clone(),
                    build_result_digest: build_result_digest.clone(),
                    passed: &artifact_digest == expected_artifact_digest,
                    artifact_digest,
                    proving_digest,
                })
            }
            WorkInput::Review {
                build_result_digest,
                validation_result_digest,
                ..
            } => {
                #[derive(Serialize)]
                struct ReviewMaterial<'a> {
                    build_result_digest: &'a ContentDigest,
                    validation_result_digest: &'a ContentDigest,
                    decision: &'static str,
                }
                let review_digest = digest_json_content(&ReviewMaterial {
                    build_result_digest,
                    validation_result_digest,
                    decision: "approve",
                })
                .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
                Ok(WorkerServiceResponse::Review {
                    build_result_digest: build_result_digest.clone(),
                    validation_result_digest: validation_result_digest.clone(),
                    decision: ReviewDecision::Approve,
                    review_digest,
                })
            }
            WorkInput::Package {
                build_result_digest,
                validation_result_digest,
                review_result_digest,
            } => {
                #[derive(Serialize)]
                struct PackageMaterial<'a> {
                    build_result_digest: &'a ContentDigest,
                    validation_result_digest: &'a ContentDigest,
                    review_result_digest: &'a ContentDigest,
                }
                let material = PackageMaterial {
                    build_result_digest,
                    validation_result_digest,
                    review_result_digest,
                };
                let package_digest = digest_json_content(&material)
                    .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
                let package_path = root
                    .join(".wasmbiotic")
                    .join("packages")
                    .join(format!("{}.json", package_digest.file_stem()));
                let bytes = serde_json::to_vec_pretty(&material)
                    .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
                atomic_replace_scoped(&package_path, &bytes)?;
                Ok(WorkerServiceResponse::Package {
                    build_result_digest: build_result_digest.clone(),
                    validation_result_digest: validation_result_digest.clone(),
                    review_result_digest: review_result_digest.clone(),
                    package_digest,
                })
            }
            WorkInput::Continue {
                package_result_digest,
                synthesis_seed_digest,
            } => {
                #[derive(Serialize)]
                struct CheckpointMaterial<'a> {
                    package_result_digest: &'a ContentDigest,
                    synthesis_seed_digest: &'a ContentDigest,
                    execution_id: &'a str,
                }
                let material = CheckpointMaterial {
                    package_result_digest,
                    synthesis_seed_digest,
                    execution_id: &request.execution_id,
                };
                let checkpoint_digest = digest_json_content(&material)
                    .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
                let checkpoint_path = root
                    .join(".wasmbiotic")
                    .join("continuity")
                    .join(format!("{}.json", checkpoint_digest.file_stem()));
                let bytes = serde_json::to_vec_pretty(&material)
                    .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
                atomic_replace_scoped(&checkpoint_path, &bytes)?;
                Ok(WorkerServiceResponse::Continue {
                    package_result_digest: package_result_digest.clone(),
                    checkpoint_digest,
                })
            }
        }
    }
}

#[cfg(test)]
impl CapabilityServiceInvoker for LocalReferenceCapabilityServices {
    fn invoke(
        &self,
        request: &CapabilityInvocationRequest,
    ) -> Result<CapabilityInvocationReceipt, CapabilityServiceFailure> {
        let service_request = serde_json::from_slice::<WorkerServiceRequest>(&request.payload)
            .map_err(|error| {
                CapabilityServiceFailure::Failed(format!("invalid worker service request: {error}"))
            })?;
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
            || request.service_family != request.role.service_family()
            || request.operation != request.role.operation()
        {
            return Err(CapabilityServiceFailure::Denied(
                "worker service request does not match its governed invocation".to_string(),
            ));
        }
        let response = self.execute(request, &service_request)?;
        let output = serde_json::to_vec(&response)
            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        let completed_at_tick = self
            .logical_clock
            .fetch_add(1, Ordering::SeqCst)
            .max(request.effect_started_at_tick);
        let _ = self
            .logical_clock
            .fetch_max(completed_at_tick.saturating_add(1), Ordering::SeqCst);
        let input_digest = ContentDigest::from_bytes(&request.payload);
        let output_digest = ContentDigest::from_bytes(&output);
        let capability_envelope_digest = digest_json_content(&request.capability_envelope)
            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        let work_budget_digest = digest_json_content(&request.work_budget)
            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        let deadline_digest = digest_json_content(&request.deadline)
            .map_err(|error| CapabilityServiceFailure::Failed(error.to_string()))?;
        let mut receipt = CapabilityInvocationReceipt {
            receipt_id: String::new(),
            execution_id: request.execution_id.clone(),
            worker_id: request.worker_id.clone(),
            service_family: request.service_family.clone(),
            operation: request.operation.clone(),
            governance_context_digest: request.governance_context_digest.clone(),
            implementation_ref: self.implementation_ref.clone(),
            implementation_digest: self.implementation_digest.clone(),
            capability_envelope_digest,
            work_budget_digest,
            deadline_digest,
            input_digest,
            output,
            output_digest,
            effect_started_at_tick: request.effect_started_at_tick,
            completed_at_tick,
        };
        receipt.receipt_id = receipt.recompute_receipt_id()?;
        receipt.validate_for(request)?;
        Ok(receipt)
    }
}

pub fn reference_isolation_profile(role: GovernedWorkerRole) -> IsolationProfile {
    match role {
        GovernedWorkerRole::Planner => IsolationProfile::ReadOnlyInspect,
        GovernedWorkerRole::Builder => IsolationProfile::DisposableWorktree,
        GovernedWorkerRole::Validator | GovernedWorkerRole::Reviewer => {
            IsolationProfile::ArtifactSandbox
        }
        GovernedWorkerRole::Packager => IsolationProfile::IsolatedServiceNamespace,
        GovernedWorkerRole::ContinuityWorker => IsolationProfile::IsolatedServiceNamespace,
    }
}

pub fn reference_worker_registration(
    worker_id: impl Into<String>,
    role: GovernedWorkerRole,
    workspace_scope_id: impl Into<String>,
    executable_package_bytes: &[u8],
    built_at_tick: u64,
) -> Result<WorkerRegistration, WorkerRuntimeError> {
    if executable_package_bytes.is_empty() {
        return Err(WorkerRuntimeError::InvalidRegistration(
            "reference worker package bytes must not be empty".to_string(),
        ));
    }
    let worker_id = worker_id.into();
    let workspace_scope_id = workspace_scope_id.into();
    let package_digest = ContentDigest::from_bytes(executable_package_bytes);
    let registration = WorkerRegistration {
        worker_id: worker_id.clone(),
        specialization_card_ref: format!("worker-card:{}:v1", role.as_str()),
        role,
        vocabulary_binding: RoleVocabularyBinding::for_role(role),
        executable: ExecutableImplementation {
            kind: ExecutableImplementationKind::NativeAdapter,
            package_digest: package_digest.clone(),
            implementation_ref: format!("reference-worker:{worker_id}:{}", role.as_str()),
            entrypoint: format!("worker/{}.run", role.as_str()),
            provider_profile_ref: None,
            provenance: PackageProvenance {
                source_digest: ContentDigest::from_bytes(
                    format!("source:{worker_id}:{}", role.as_str()).as_bytes(),
                ),
                build_record_digest: ContentDigest::from_bytes(
                    format!("build:{worker_id}:{package_digest}").as_bytes(),
                ),
                producer_ref: "wasmbiotic:m4-reference-worker-builder".to_string(),
                built_at_tick,
                signature_or_attestation_ref: format!(
                    "attestation:{}:{}",
                    role.as_str(),
                    digest_suffix(&package_digest)
                ),
            },
        },
        allowed_worlds: vec![role.required_world()],
        service_family_refs: vec![role.service_family().to_string()],
        allowed_workspace_scopes: vec![workspace_scope_id],
        authority_ceiling: role.required_authority(),
        isolation_profile: reference_isolation_profile(role),
        policy: WorkerExecutionPolicy {
            max_concurrency: 2,
            max_attempts: 3,
            lease_duration_ticks: 10,
            heartbeat_grace_ticks: 10,
            retry_backoff_ticks: 1,
            degrade_after_attempt: 1,
            retry_timeouts: true,
        },
        enabled: true,
    };
    registration.validate()?;
    Ok(registration)
}

pub fn reference_capability_envelope(
    envelope_id: impl Into<String>,
    actor_scope: impl Into<String>,
    role: GovernedWorkerRole,
    resource_scopes: Vec<String>,
) -> Result<CapabilityEnvelope, WorkerRuntimeError> {
    require_unique_nonempty("resource_scopes", &resource_scopes)?;
    Ok(CapabilityEnvelope {
        envelope_id: envelope_id.into(),
        actor_scope: actor_scope.into(),
        world_grants: vec![crate::execution::CapabilityWorldGrant {
            world: role.required_world(),
            allowed_operations: vec![role.operation().to_string()],
            default_authority_class: role.required_authority(),
            default_approval_class: ApprovalClass::AutoAllowed,
            operation_approval_overrides: Vec::new(),
        }],
        authority_ceiling: role.required_authority(),
        isolation_profile: reference_isolation_profile(role),
        allowed_resource_scopes: resource_scopes,
        approval_overrides: Vec::new(),
        quota_policy: Some("m4-reference-bounded".to_string()),
        campaign_scope: None,
        epoch_scope: None,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceWorkflowSpec {
    pub workflow_id: String,
    pub objective: String,
    pub governance_context_digest: ContentDigest,
    pub baseline_digest: ContentDigest,
    pub workspace_scope: WorkspaceScope,
    pub target_relative_path: PathBuf,
    pub expected_before_digest: ContentDigest,
    pub replacement_bytes: Vec<u8>,
    pub validation_suite_digest: ContentDigest,
    pub budget: WorkBudget,
    pub deadline: WorkDeadline,
    pub capability_envelopes: BTreeMap<GovernedWorkerRole, CapabilityEnvelope>,
}

impl ReferenceWorkflowSpec {
    fn validate(&self) -> Result<(), WorkerRuntimeError> {
        require_nonempty("workflow_id", &self.workflow_id)?;
        require_nonempty("objective", &self.objective)?;
        self.workspace_scope.validate()?;
        validate_relative_path(&self.target_relative_path)?;
        if self.replacement_bytes.is_empty() {
            return Err(WorkerRuntimeError::InvalidRequest(
                "reference workflow replacement bytes are empty".to_string(),
            ));
        }
        self.budget.validate()?;
        self.deadline.validate()?;
        for role in GovernedWorkerRole::ALL {
            if !self.capability_envelopes.contains_key(&role) {
                return Err(WorkerRuntimeError::InvalidRequest(format!(
                    "reference workflow lacks a '{}' capability envelope",
                    role.as_str()
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceWorkflowEvidence {
    pub workflow_id: String,
    pub governance_context_digest: ContentDigest,
    pub job_ids: Vec<String>,
    pub execution_ids: Vec<String>,
    pub worker_ids: Vec<String>,
    pub result_digests: Vec<ContentDigest>,
    pub synthesis: CoordinatorSynthesis,
}

impl<E, C> WorkerRuntime<E, C>
where
    E: DurableJobExecutor,
    C: CapabilityServiceInvoker,
{
    /// Run the bounded Planner → Builder → Validator → Reviewer → Packager →
    /// Continuity workflow. Each successor is constructed only from results
    /// reloaded by digest from this runtime's durable store.
    pub fn run_reference_workflow(
        &self,
        spec: ReferenceWorkflowSpec,
        start_tick: u64,
    ) -> Result<ReferenceWorkflowEvidence, WorkerRuntimeError> {
        spec.validate()?;
        if start_tick < spec.deadline.not_before_tick
            || start_tick.saturating_add(6) >= spec.deadline.expires_at_tick
        {
            return Err(WorkerRuntimeError::DeadlineExceeded(
                "reference workflow interval does not fit its durable deadline".to_string(),
            ));
        }
        let mut job_ids = Vec::new();
        let mut execution_ids = Vec::new();
        let mut worker_ids = Vec::new();
        let mut results = Vec::new();

        let plan = self.run_reference_step(
            &spec,
            GovernedWorkerRole::Planner,
            WorkInput::Plan {
                objective: spec.objective.clone(),
                baseline_digest: spec.baseline_digest.clone(),
            },
            start_tick,
            0,
        )?;
        collect_step(
            &plan,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut results,
        );
        let plan_digest = plan.result.result_digest.clone();

        let build = self.run_reference_step(
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
        collect_step(
            &build,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut results,
        );
        let build_digest = build.result.result_digest.clone();
        let artifact_digest = match &build.result.output {
            WorkOutput::Build {
                artifact_digest, ..
            } => artifact_digest.clone(),
            _ => {
                return Err(WorkerRuntimeError::Integrity(
                    "builder persisted a non-builder output".to_string(),
                ));
            }
        };

        let validation = self.run_reference_step(
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
        collect_step(
            &validation,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut results,
        );
        let validation_digest = validation.result.result_digest.clone();
        if !matches!(
            validation.result.output,
            WorkOutput::Validate { passed: true, .. }
        ) {
            return Err(WorkerRuntimeError::ExecutionFailed(
                "independent validator rejected the builder artifact".to_string(),
            ));
        }

        let review = self.run_reference_step(
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
        collect_step(
            &review,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut results,
        );
        let review_digest = review.result.result_digest.clone();

        let package = self.run_reference_step(
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
        collect_step(
            &package,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut results,
        );
        let package_digest = package.result.result_digest.clone();
        let synthesis_seed_digest = digest_json_content(&results)
            .map_err(|error| WorkerRuntimeError::Serialization(error.to_string()))?;

        let continuity = self.run_reference_step(
            &spec,
            GovernedWorkerRole::ContinuityWorker,
            WorkInput::Continue {
                package_result_digest: package_digest,
                synthesis_seed_digest,
            },
            start_tick.saturating_add(5),
            5,
        )?;
        collect_step(
            &continuity,
            &mut job_ids,
            &mut execution_ids,
            &mut worker_ids,
            &mut results,
        );

        if execution_ids.iter().collect::<BTreeSet<_>>().len() != GovernedWorkerRole::ALL.len()
            || worker_ids.iter().collect::<BTreeSet<_>>().len() != GovernedWorkerRole::ALL.len()
            || build.execution.worker_id == validation.execution.worker_id
            || build.execution.implementation_ref == validation.execution.implementation_ref
        {
            return Err(WorkerRuntimeError::Integrity(
                "reference workflow did not use six distinct executions and worker identities"
                    .to_string(),
            ));
        }
        let synthesis = self.synthesize(
            format!("synthesis:{}", spec.workflow_id),
            results.clone(),
            start_tick.saturating_add(6),
        )?;
        if synthesis.cited_roles != GovernedWorkerRole::ALL {
            return Err(WorkerRuntimeError::Integrity(
                "reference synthesis does not cite all six worker roles in causal order"
                    .to_string(),
            ));
        }
        Ok(ReferenceWorkflowEvidence {
            workflow_id: spec.workflow_id,
            governance_context_digest: spec.governance_context_digest,
            job_ids,
            execution_ids,
            worker_ids,
            result_digests: results,
            synthesis,
        })
    }

    fn run_reference_step(
        &self,
        spec: &ReferenceWorkflowSpec,
        role: GovernedWorkerRole,
        input: WorkInput,
        tick: u64,
        ordinal: usize,
    ) -> Result<ReferenceStep, WorkerRuntimeError> {
        let envelope = spec
            .capability_envelopes
            .get(&role)
            .cloned()
            .ok_or_else(|| {
                WorkerRuntimeError::InvalidRequest(format!(
                    "missing '{}' capability envelope",
                    role.as_str()
                ))
            })?;
        let job_id = self.enqueue(
            WorkerJobRequest {
                request_id: format!("{}:{}:{ordinal}", spec.workflow_id, role.as_str()),
                role,
                governance_context_digest: spec.governance_context_digest.clone(),
                input,
                capability_envelope: envelope,
                workspace_scope: spec.workspace_scope.clone(),
                budget: spec.budget.clone(),
                deadline: spec.deadline.clone(),
                cancellation_token: CancellationToken::from_secret(&format!(
                    "cancel:{}:{}:{ordinal}",
                    spec.workflow_id,
                    role.as_str()
                )),
                fairness_key: spec.workspace_scope.scope_id.clone(),
                priority: 100,
            },
            tick,
        )?;
        let dispatch = self.dispatch_next(tick)?.ok_or_else(|| {
            WorkerRuntimeError::ExecutionFailed(format!(
                "scheduler did not dispatch reference job '{job_id}'"
            ))
        })?;
        if dispatch.job_id != job_id {
            return Err(WorkerRuntimeError::Conflict(format!(
                "another queued job '{}' preceded isolated reference job '{job_id}'",
                dispatch.job_id
            )));
        }
        if dispatch.status != JobStatus::Completed {
            return Err(WorkerRuntimeError::ExecutionFailed(format!(
                "reference '{}' worker did not complete: {:?}",
                role.as_str(),
                dispatch.status
            )));
        }
        let result_digest = dispatch.result_digest.ok_or_else(|| {
            WorkerRuntimeError::Integrity(
                "completed reference job has no result digest".to_string(),
            )
        })?;
        let result = self.load_result(&result_digest)?;
        let execution = self.load_execution(&dispatch.execution_id)?;
        Ok(ReferenceStep {
            job_id,
            execution,
            result,
        })
    }
}

struct ReferenceStep {
    job_id: String,
    execution: WorkerExecutionRecord,
    result: PersistedWorkerResult,
}

fn collect_step(
    step: &ReferenceStep,
    job_ids: &mut Vec<String>,
    execution_ids: &mut Vec<String>,
    worker_ids: &mut Vec<String>,
    results: &mut Vec<ContentDigest>,
) {
    job_ids.push(step.job_id.clone());
    execution_ids.push(step.execution.execution_id.clone());
    worker_ids.push(step.execution.worker_id.clone());
    results.push(step.result.result_digest.clone());
}

#[cfg(test)]
fn checked_target(root: &Path, relative: &Path) -> Result<PathBuf, CapabilityServiceFailure> {
    validate_relative_path(relative)
        .map_err(|error| CapabilityServiceFailure::Denied(error.to_string()))?;
    let target = root.join(relative);
    ensure_no_symlink_ancestors(root, &target)?;
    if target.exists() {
        let metadata = fs::symlink_metadata(&target).map_err(|error| {
            CapabilityServiceFailure::Failed(format!(
                "cannot inspect '{}': {error}",
                target.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CapabilityServiceFailure::Denied(format!(
                "target '{}' is not a regular scoped file",
                target.display()
            )));
        }
    }
    Ok(target)
}

#[cfg(test)]
fn ensure_no_symlink_ancestors(root: &Path, target: &Path) -> Result<(), CapabilityServiceFailure> {
    if !target.starts_with(root) {
        return Err(CapabilityServiceFailure::Denied(
            "target escaped the canonical workspace root".to_string(),
        ));
    }
    let relative = target.strip_prefix(root).map_err(|error| {
        CapabilityServiceFailure::Denied(format!("cannot establish scoped target: {error}"))
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        if current == target {
            break;
        }
        if current.exists() {
            let metadata = fs::symlink_metadata(&current).map_err(|error| {
                CapabilityServiceFailure::Failed(format!(
                    "cannot inspect '{}': {error}",
                    current.display()
                ))
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CapabilityServiceFailure::Denied(format!(
                    "scoped path ancestor '{}' is not a real directory",
                    current.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn read_optional_regular_file(path: &Path) -> Result<Vec<u8>, CapabilityServiceFailure> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CapabilityServiceFailure::Failed(format!("cannot inspect '{}': {error}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CapabilityServiceFailure::Denied(format!(
            "'{}' is not a regular scoped file",
            path.display()
        )));
    }
    fs::read(path).map_err(|error| {
        CapabilityServiceFailure::Failed(format!("cannot read '{}': {error}", path.display()))
    })
}

#[cfg(test)]
fn atomic_replace_scoped(path: &Path, bytes: &[u8]) -> Result<(), CapabilityServiceFailure> {
    let parent = path.parent().ok_or_else(|| {
        CapabilityServiceFailure::Denied("scoped file has no parent directory".to_string())
    })?;
    create_scoped_directories(parent)?;
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            CapabilityServiceFailure::Failed(format!(
                "cannot inspect '{}': {error}",
                path.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CapabilityServiceFailure::Denied(format!(
                "refusing to replace non-regular file '{}'",
                path.display()
            )));
        }
    }
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".worker-effect.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| {
                CapabilityServiceFailure::Failed(format!(
                    "cannot create '{}': {error}",
                    temporary.display()
                ))
            })?;
        file.write_all(bytes).map_err(|error| {
            CapabilityServiceFailure::Failed(format!(
                "cannot write '{}': {error}",
                temporary.display()
            ))
        })?;
        file.sync_all().map_err(|error| {
            CapabilityServiceFailure::Failed(format!(
                "cannot sync '{}': {error}",
                temporary.display()
            ))
        })?;
        fs::rename(&temporary, path).map_err(|error| {
            CapabilityServiceFailure::Failed(format!(
                "cannot publish '{}': {error}",
                path.display()
            ))
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                CapabilityServiceFailure::Failed(format!(
                    "cannot sync '{}': {error}",
                    parent.display()
                ))
            })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
fn create_scoped_directories(path: &Path) -> Result<(), CapabilityServiceFailure> {
    let mut missing = Vec::new();
    let mut cursor = path;
    while !cursor.exists() {
        missing.push(cursor.to_path_buf());
        cursor = cursor.parent().ok_or_else(|| {
            CapabilityServiceFailure::Denied("cannot resolve scoped directory parent".to_string())
        })?;
    }
    let metadata = fs::symlink_metadata(cursor).map_err(|error| {
        CapabilityServiceFailure::Failed(format!("cannot inspect '{}': {error}", cursor.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CapabilityServiceFailure::Denied(format!(
            "scoped directory ancestor '{}' is unsafe",
            cursor.display()
        )));
    }
    for directory in missing.iter().rev() {
        fs::create_dir(directory).map_err(|error| {
            CapabilityServiceFailure::Failed(format!(
                "cannot create '{}': {error}",
                directory.display()
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicUsize;
    use std::thread;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn test_directory(label: &str) -> PathBuf {
        let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "wasmbiotic-worker-runtime-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create isolated test directory");
        path
    }

    fn scope(root: &Path, id: &str) -> WorkspaceScope {
        WorkspaceScope {
            scope_id: id.to_string(),
            workspace_root: root.to_path_buf(),
            resource_scopes: vec![format!("workspace:{id}")],
        }
    }

    fn budget() -> WorkBudget {
        WorkBudget {
            max_attempts: 3,
            max_capability_calls: 2,
            max_input_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_runtime_ticks: 50,
        }
    }

    fn deadline() -> WorkDeadline {
        WorkDeadline {
            not_before_tick: 10,
            expires_at_tick: 100,
        }
    }

    fn envelope(
        role: GovernedWorkerRole,
        scope: &WorkspaceScope,
        suffix: &str,
    ) -> CapabilityEnvelope {
        reference_capability_envelope(
            format!("envelope:{}:{suffix}", role.as_str()),
            format!("actor:{}:{suffix}", role.as_str()),
            role,
            scope.resource_scopes.clone(),
        )
        .expect("valid reference envelope")
    }

    fn plan_request(
        request_id: &str,
        workspace_scope: &WorkspaceScope,
        fairness_key: &str,
    ) -> WorkerJobRequest {
        WorkerJobRequest {
            request_id: request_id.to_string(),
            role: GovernedWorkerRole::Planner,
            governance_context_digest: ContentDigest::from_bytes(
                format!("governance:{request_id}").as_bytes(),
            ),
            input: WorkInput::Plan {
                objective: "make one bounded candidate safer".to_string(),
                baseline_digest: ContentDigest::from_bytes(b"baseline"),
            },
            capability_envelope: envelope(GovernedWorkerRole::Planner, workspace_scope, request_id),
            workspace_scope: workspace_scope.clone(),
            budget: budget(),
            deadline: deadline(),
            cancellation_token: CancellationToken::from_secret(&format!("cancel:{request_id}")),
            fairness_key: fairness_key.to_string(),
            priority: 10,
        }
    }

    fn registration(
        worker_id: &str,
        role: GovernedWorkerRole,
        scope_id: &str,
    ) -> WorkerRegistration {
        reference_worker_registration(
            worker_id,
            role,
            scope_id,
            format!("package:{worker_id}:{}", role.as_str()).as_bytes(),
            1,
        )
        .expect("valid reference worker registration")
    }

    fn register_all<E, C>(runtime: &WorkerRuntime<E, C>, scope_id: &str)
    where
        E: DurableJobExecutor,
        C: CapabilityServiceInvoker,
    {
        for (ordinal, role) in GovernedWorkerRole::ALL.into_iter().enumerate() {
            runtime
                .register_worker(
                    registration(
                        &format!("worker-{ordinal}-{}", role.as_str()),
                        role,
                        scope_id,
                    ),
                    ordinal as u64,
                )
                .expect("register reference worker");
        }
    }

    fn workflow_spec(root: &Path, target: &Path, scope_id: &str) -> ReferenceWorkflowSpec {
        let workspace_scope = scope(root, scope_id);
        let before = fs::read(target).expect("read candidate baseline");
        let capability_envelopes = GovernedWorkerRole::ALL
            .into_iter()
            .map(|role| (role, envelope(role, &workspace_scope, "workflow")))
            .collect();
        ReferenceWorkflowSpec {
            workflow_id: format!("workflow:{scope_id}"),
            objective: "replace the bounded candidate and prove the exact bytes".to_string(),
            governance_context_digest: ContentDigest::from_bytes(
                format!("governance:{scope_id}").as_bytes(),
            ),
            baseline_digest: ContentDigest::from_bytes(b"workspace-baseline"),
            workspace_scope,
            target_relative_path: target
                .strip_prefix(root)
                .expect("target inside root")
                .to_path_buf(),
            expected_before_digest: ContentDigest::from_bytes(&before),
            replacement_bytes: b"candidate-v2: governed and independently validated".to_vec(),
            validation_suite_digest: ContentDigest::from_bytes(b"suite:v1"),
            budget: budget(),
            deadline: WorkDeadline {
                not_before_tick: 10,
                expires_at_tick: 200,
            },
            capability_envelopes,
        }
    }

    #[derive(Clone)]
    enum DispatchAction {
        Return(ExecutorOutcome),
        RunReference,
    }

    #[derive(Clone)]
    enum ReconcileAction {
        Return(ExecutorReconciliation),
        RunReference,
    }

    #[derive(Default)]
    struct ScriptedExecutor {
        dispatch_actions: Mutex<VecDeque<DispatchAction>>,
        reconcile_actions: Mutex<VecDeque<ReconcileAction>>,
        cancellations: Mutex<Vec<String>>,
        cancel_failure: Mutex<Option<String>>,
    }

    impl ScriptedExecutor {
        fn with_dispatch(actions: Vec<DispatchAction>) -> Self {
            Self {
                dispatch_actions: Mutex::new(actions.into()),
                ..Self::default()
            }
        }

        fn push_reconciliation(&self, action: ReconcileAction) {
            self.reconcile_actions
                .lock()
                .expect("reconciliation script lock")
                .push_back(action);
        }

        fn fail_cancellation(&self, detail: &str) {
            *self.cancel_failure.lock().expect("cancel failure lock") = Some(detail.to_string());
        }
    }

    impl DurableJobExecutor for ScriptedExecutor {
        fn dispatch(
            &self,
            invocation: &WorkerInvocation,
            capabilities: &dyn CapabilityServiceInvoker,
        ) -> ExecutorOutcome {
            match self
                .dispatch_actions
                .lock()
                .expect("dispatch script lock")
                .pop_front()
                .unwrap_or(DispatchAction::RunReference)
            {
                DispatchAction::Return(outcome) => outcome,
                DispatchAction::RunReference => {
                    ReferenceWorkerExecutor.dispatch(invocation, capabilities)
                }
            }
        }

        fn reconcile(
            &self,
            invocation: &WorkerInvocation,
            capabilities: &dyn CapabilityServiceInvoker,
        ) -> ExecutorReconciliation {
            match self
                .reconcile_actions
                .lock()
                .expect("reconciliation script lock")
                .pop_front()
                .unwrap_or(ReconcileAction::Return(ExecutorReconciliation::Unknown {
                    detail: "script has no execution".to_string(),
                    observed_at_tick: invocation.lease_id.len() as u64,
                })) {
                ReconcileAction::Return(outcome) => outcome,
                ReconcileAction::RunReference => ExecutorReconciliation::Terminal(
                    ReferenceWorkerExecutor.dispatch(invocation, capabilities),
                ),
            }
        }

        fn cancel(&self, execution_id: &str, _cancellation_token: &str) -> Result<(), String> {
            if let Some(detail) = self
                .cancel_failure
                .lock()
                .map_err(|_| "cancel failure lock poisoned".to_string())?
                .clone()
            {
                return Err(detail);
            }
            self.cancellations
                .lock()
                .map_err(|_| "cancellation lock poisoned".to_string())?
                .push(execution_id.to_string());
            Ok(())
        }
    }

    struct DenyAllServices;

    impl CapabilityServiceInvoker for DenyAllServices {
        fn invoke(
            &self,
            _request: &CapabilityInvocationRequest,
        ) -> Result<CapabilityInvocationReceipt, CapabilityServiceFailure> {
            Err(CapabilityServiceFailure::Denied(
                "test service must not be reached".to_string(),
            ))
        }
    }

    struct BlockingCapabilityServices {
        inner: LocalReferenceCapabilityServices,
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    impl CapabilityServiceInvoker for BlockingCapabilityServices {
        fn invoke(
            &self,
            request: &CapabilityInvocationRequest,
        ) -> Result<CapabilityInvocationReceipt, CapabilityServiceFailure> {
            let _ = self.entered.wait();
            let _ = self.release.wait();
            self.inner.invoke(request)
        }
    }

    struct BlockingReconcileExecutor {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
        reconciliation_calls: Arc<AtomicUsize>,
    }

    impl DurableJobExecutor for BlockingReconcileExecutor {
        fn dispatch(
            &self,
            invocation: &WorkerInvocation,
            _capabilities: &dyn CapabilityServiceInvoker,
        ) -> ExecutorOutcome {
            running(invocation.acquired_at_tick, "blocking-reconcile")
        }

        fn reconcile(
            &self,
            invocation: &WorkerInvocation,
            _capabilities: &dyn CapabilityServiceInvoker,
        ) -> ExecutorReconciliation {
            self.reconciliation_calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.entered.wait();
            let _ = self.release.wait();
            ExecutorReconciliation::Terminal(ExecutorOutcome::Crashed {
                detail: "deterministic reconciliation crash".to_string(),
                failed_at_tick: invocation.acquired_at_tick,
            })
        }

        fn cancel(&self, _execution_id: &str, _cancellation_token: &str) -> Result<(), String> {
            Ok(())
        }
    }

    fn running(tick: u64, handle: &str) -> ExecutorOutcome {
        ExecutorOutcome::Running {
            executor_handle: handle.to_string(),
            heartbeat_tick: tick,
        }
    }

    #[test]
    fn role_mapping_is_explicit_and_lossless_across_both_vocabularies() {
        let bindings = role_vocabulary_bindings();
        assert_eq!(bindings.len(), 6);
        for binding in &bindings {
            binding.validate().expect("canonical binding validates");
            assert_eq!(
                GovernedWorkerRole::from(binding.ecology_role),
                binding.canonical_role
            );
        }
        let packager = RoleVocabularyBinding::for_role(GovernedWorkerRole::Packager);
        let continuity = RoleVocabularyBinding::for_role(GovernedWorkerRole::ContinuityWorker);
        assert_eq!(packager.legacy_role, continuity.legacy_role);
        assert_ne!(packager.legacy_qualifier, continuity.legacy_qualifier);

        let mut corrupted = packager;
        corrupted.ecology_role = WorkerRoleKind::Planner;
        assert!(matches!(
            corrupted.validate(),
            Err(WorkerRuntimeError::InvalidRegistration(_))
        ));
    }

    #[test]
    fn registration_requires_executable_package_provenance_and_exact_role_binding() {
        let mut worker = registration("builder", GovernedWorkerRole::Builder, "candidate-a");
        worker.executable.provenance.producer_ref.clear();
        assert!(matches!(
            worker.validate(),
            Err(WorkerRuntimeError::InvalidRequest(_))
        ));

        let mut worker = registration("validator", GovernedWorkerRole::Validator, "candidate-a");
        worker.vocabulary_binding = RoleVocabularyBinding::for_role(GovernedWorkerRole::Reviewer);
        assert!(matches!(
            worker.validate(),
            Err(WorkerRuntimeError::InvalidRegistration(_))
        ));
    }

    #[test]
    fn reference_workflow_runs_six_distinct_workers_and_cites_exact_results() {
        let workspace = test_directory("reference-workspace");
        let store = test_directory("reference-store");
        let target = workspace.join("candidate.txt");
        fs::write(&target, b"candidate-v1").expect("seed candidate");
        let services = LocalReferenceCapabilityServices::new(
            vec![workspace.clone()],
            "m3:local-reference",
            b"local-reference-capabilities-v1",
            10,
        )
        .expect("local services");
        let runtime =
            WorkerRuntime::open(&store, ReferenceWorkerExecutor, services).expect("runtime");
        register_all(&runtime, "candidate-a");

        let evidence = runtime
            .run_reference_workflow(workflow_spec(&workspace, &target, "candidate-a"), 10)
            .expect("bounded reference workflow");
        assert_eq!(evidence.job_ids.len(), 6);
        assert_eq!(
            evidence.execution_ids.iter().collect::<BTreeSet<_>>().len(),
            6
        );
        assert_eq!(evidence.worker_ids.iter().collect::<BTreeSet<_>>().len(), 6);
        assert_eq!(evidence.result_digests.len(), 6);
        assert_eq!(
            evidence.synthesis.cited_result_digests,
            evidence.result_digests
        );
        assert_eq!(
            fs::read(&target).expect("read mutated candidate"),
            b"candidate-v2: governed and independently validated"
        );
        assert!(workspace.join(".wasmbiotic/packages").is_dir());
        assert!(workspace.join(".wasmbiotic/continuity").is_dir());
        for digest in &evidence.result_digests {
            let result = runtime.load_result(digest).expect("exact result reload");
            assert_eq!(result.recompute_digest().expect("result digest"), *digest);
            assert!(!result.capability_receipt_digests.is_empty());
        }
        let builder = runtime
            .load_execution(&evidence.execution_ids[1])
            .expect("builder execution");
        let validator = runtime
            .load_execution(&evidence.execution_ids[2])
            .expect("validator execution");
        assert_ne!(builder.worker_id, validator.worker_id);
        assert_ne!(builder.implementation_ref, validator.implementation_ref);

        drop(runtime);
        let reopened = WorkerRuntime::open(
            &store,
            ReferenceWorkerExecutor,
            LocalReferenceCapabilityServices::new(
                vec![workspace.clone()],
                "m3:local-reference",
                b"local-reference-capabilities-v1",
                50,
            )
            .expect("reopened services"),
        )
        .expect("restart validates durable state");
        for digest in &evidence.result_digests {
            reopened
                .load_result(digest)
                .expect("result survives restart");
        }
    }

    #[test]
    fn executor_cannot_report_success_without_a_real_service_receipt() {
        let workspace = test_directory("unattested-workspace");
        let store = test_directory("unattested-store");
        let fake_output = WorkOutput::Plan {
            baseline_digest: ContentDigest::from_bytes(b"baseline"),
            plan_digest: ContentDigest::from_bytes(b"caller-authored-plan"),
        };
        let executor = ScriptedExecutor::with_dispatch(vec![DispatchAction::Return(
            ExecutorOutcome::Completed {
                output: fake_output,
                completed_at_tick: 10,
            },
        )]);
        let runtime = WorkerRuntime::open(&store, executor, DenyAllServices).expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("planner registration");
        let job_id = runtime
            .enqueue(
                plan_request("unattested", &scope(&workspace, "scope"), "scope"),
                10,
            )
            .expect("enqueue");
        let report = runtime
            .dispatch_next(10)
            .expect("dispatch")
            .expect("leased");
        assert_eq!(report.status, JobStatus::RetryPending);
        assert!(report.result_digest.is_none());
        let job = runtime.load_job(&job_id).expect("job");
        assert_eq!(job.failures[0].class, "unattested_success");
        assert!(
            runtime
                .events()
                .expect("events")
                .iter()
                .any(|event| event.class == "worker_failure_degrading")
        );
    }

    #[test]
    fn unknown_and_duplicate_result_references_fail_closed() {
        let workspace = test_directory("references-workspace");
        let store = test_directory("references-store");
        let runtime =
            WorkerRuntime::open(&store, ReferenceWorkerExecutor, DenyAllServices).expect("runtime");
        runtime
            .register_worker(
                registration("builder", GovernedWorkerRole::Builder, "scope"),
                1,
            )
            .expect("builder");
        let invented = ContentDigest::from_bytes(b"invented-result");
        let request = WorkerJobRequest {
            request_id: "invented-build".to_string(),
            role: GovernedWorkerRole::Builder,
            governance_context_digest: ContentDigest::from_bytes(b"governance:invented"),
            input: WorkInput::Build {
                plan_result_digest: invented.clone(),
                target_relative_path: PathBuf::from("candidate.txt"),
                expected_before_digest: ContentDigest::from_bytes(b"before"),
                replacement_bytes: b"after".to_vec(),
            },
            capability_envelope: envelope(
                GovernedWorkerRole::Builder,
                &scope(&workspace, "scope"),
                "invented",
            ),
            workspace_scope: scope(&workspace, "scope"),
            budget: budget(),
            deadline: deadline(),
            cancellation_token: CancellationToken::from_secret("cancel:invented"),
            fairness_key: "scope".to_string(),
            priority: 1,
        };
        assert!(matches!(
            runtime.enqueue(request, 10),
            Err(WorkerRuntimeError::NotFound(_))
        ));
        assert!(matches!(
            runtime.synthesize("invented-synthesis", vec![invented], 10),
            Err(WorkerRuntimeError::NotFound(_))
        ));
    }

    #[test]
    fn trap_retries_on_a_degraded_worker_and_crash_is_operator_visible() {
        let workspace = test_directory("degrade-workspace");
        let store = test_directory("degrade-store");
        let services = LocalReferenceCapabilityServices::new(
            vec![workspace.clone()],
            "m3:test",
            b"services",
            10,
        )
        .expect("services");
        let executor = ScriptedExecutor::with_dispatch(vec![
            DispatchAction::Return(ExecutorOutcome::Trapped {
                detail: "component trap".to_string(),
                failed_at_tick: 10,
            }),
            DispatchAction::RunReference,
            DispatchAction::Return(ExecutorOutcome::Crashed {
                detail: "worker process crashed".to_string(),
                failed_at_tick: 12,
            }),
            DispatchAction::RunReference,
        ]);
        let runtime = WorkerRuntime::open(&store, executor, services).expect("runtime");
        runtime
            .register_worker(
                registration("a-planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("primary planner");
        runtime
            .register_worker(
                registration("b-planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("fallback planner");

        let first_job = runtime
            .enqueue(
                plan_request("trap", &scope(&workspace, "scope"), "scope"),
                10,
            )
            .expect("trap job");
        let trapped = runtime
            .dispatch_next(10)
            .expect("trap dispatch")
            .expect("report");
        assert_eq!(trapped.worker_id, "a-planner");
        assert_eq!(trapped.status, JobStatus::RetryPending);
        let recovered = runtime.dispatch_next(11).expect("retry").expect("report");
        assert_eq!(recovered.worker_id, "b-planner");
        assert_eq!(recovered.status, JobStatus::Completed);
        assert_eq!(
            runtime.load_job(&first_job).expect("first job").failures[0].class,
            "trap"
        );

        let second_job = runtime
            .enqueue(
                plan_request("crash", &scope(&workspace, "scope"), "scope"),
                12,
            )
            .expect("crash job");
        let crashed = runtime
            .dispatch_next(12)
            .expect("crash dispatch")
            .expect("report");
        assert_eq!(crashed.status, JobStatus::RetryPending);
        let recovered = runtime.dispatch_next(13).expect("retry").expect("report");
        assert_eq!(recovered.status, JobStatus::Completed);
        assert_eq!(
            runtime.load_job(&second_job).expect("second job").failures[0].class,
            "crash"
        );
    }

    #[test]
    fn timeout_exhaustion_is_terminal_and_never_success_shaped() {
        let workspace = test_directory("timeout-workspace");
        let store = test_directory("timeout-store");
        let executor = ScriptedExecutor::with_dispatch(vec![DispatchAction::Return(
            ExecutorOutcome::TimedOut {
                detail: "component deadline".to_string(),
                failed_at_tick: 10,
            },
        )]);
        let runtime = WorkerRuntime::open(&store, executor, DenyAllServices).expect("runtime");
        let mut worker = registration("planner", GovernedWorkerRole::Planner, "scope");
        worker.policy.max_attempts = 1;
        runtime.register_worker(worker, 1).expect("planner");
        let mut request = plan_request("timeout", &scope(&workspace, "scope"), "scope");
        request.budget.max_attempts = 1;
        let job_id = runtime.enqueue(request, 10).expect("enqueue");
        let report = runtime
            .dispatch_next(10)
            .expect("dispatch")
            .expect("report");
        assert_eq!(report.status, JobStatus::TimedOut);
        assert!(report.result_digest.is_none());
        assert_eq!(
            runtime.load_job(&job_id).expect("job").failures[0].class,
            "timeout"
        );
    }

    #[test]
    fn restart_reconciles_in_flight_work_without_duplicate_dispatch() {
        let workspace = test_directory("restart-workspace");
        let store = test_directory("restart-store");
        let executor = Arc::new(ScriptedExecutor::with_dispatch(vec![
            DispatchAction::Return(running(10, "external-job-1")),
        ]));
        executor.push_reconciliation(ReconcileAction::RunReference);
        let services = Arc::new(
            LocalReferenceCapabilityServices::new(
                vec![workspace.clone()],
                "m3:test",
                b"services",
                10,
            )
            .expect("services"),
        );
        let runtime =
            WorkerRuntime::open_with_shared(&store, Arc::clone(&executor), Arc::clone(&services))
                .expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("planner");
        let job_id = runtime
            .enqueue(
                plan_request("restart", &scope(&workspace, "scope"), "scope"),
                10,
            )
            .expect("job");
        let initial = runtime
            .dispatch_next(10)
            .expect("dispatch")
            .expect("report");
        assert_eq!(initial.status, JobStatus::Running);
        let execution_id = initial.execution_id.clone();
        drop(runtime);

        let restarted =
            WorkerRuntime::open_with_shared(&store, executor, services).expect("restarted runtime");
        let report = restarted
            .reconcile_in_flight(11)
            .expect("restart reconciliation");
        assert_eq!(report.inspected_execution_ids, vec![execution_id.clone()]);
        assert_eq!(report.recovered_result_digests.len(), 1);
        assert_eq!(
            restarted.load_job(&job_id).expect("job").status,
            JobStatus::Completed
        );
        assert_eq!(
            restarted
                .load_execution(&execution_id)
                .expect("same execution")
                .status,
            ExecutionStatus::Completed
        );
        assert!(
            restarted
                .dispatch_next(12)
                .expect("no duplicate dispatch")
                .is_none()
        );
    }

    #[test]
    fn stale_unknown_lease_is_retried_and_remains_operator_visible() {
        let workspace = test_directory("stale-workspace");
        let store = test_directory("stale-store");
        let executor = Arc::new(ScriptedExecutor::with_dispatch(vec![
            DispatchAction::Return(running(10, "external-stale")),
        ]));
        executor.push_reconciliation(ReconcileAction::Return(ExecutorReconciliation::Unknown {
            detail: "external execution vanished".to_string(),
            observed_at_tick: 30,
        }));
        let runtime = WorkerRuntime::open_with_shared(
            &store,
            Arc::clone(&executor),
            Arc::new(DenyAllServices),
        )
        .expect("runtime");
        let mut worker = registration("planner", GovernedWorkerRole::Planner, "scope");
        worker.policy.lease_duration_ticks = 5;
        worker.policy.heartbeat_grace_ticks = 5;
        runtime.register_worker(worker, 1).expect("planner");
        let job_id = runtime
            .enqueue(
                plan_request("stale", &scope(&workspace, "scope"), "scope"),
                10,
            )
            .expect("job");
        runtime
            .dispatch_next(10)
            .expect("dispatch")
            .expect("report");
        let report = runtime.reconcile_in_flight(30).expect("reconcile");
        assert_eq!(report.retried_job_ids, vec![job_id.clone()]);
        let job = runtime.load_job(&job_id).expect("job");
        assert_eq!(job.status, JobStatus::RetryPending);
        assert_eq!(job.failures[0].class, "stale_lease");
    }

    #[test]
    fn durable_cancellation_stops_the_exact_active_execution() {
        let workspace = test_directory("cancel-workspace");
        let store = test_directory("cancel-store");
        let executor = Arc::new(ScriptedExecutor::with_dispatch(vec![
            DispatchAction::Return(running(10, "external-cancellable")),
        ]));
        let runtime = WorkerRuntime::open_with_shared(
            &store,
            Arc::clone(&executor),
            Arc::new(DenyAllServices),
        )
        .expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("planner");
        let request = plan_request("cancel-me", &scope(&workspace, "scope"), "scope");
        let token = "cancel:cancel-me".to_string();
        let job_id = runtime.enqueue(request, 10).expect("job");
        let running = runtime
            .dispatch_next(10)
            .expect("dispatch")
            .expect("report");
        runtime
            .request_cancellation(&job_id, &token, 11)
            .expect("cancel");
        assert_eq!(
            runtime.load_job(&job_id).expect("job").status,
            JobStatus::Cancelled
        );
        assert_eq!(
            *executor.cancellations.lock().expect("cancellations"),
            vec![running.execution_id]
        );
        assert!(
            matches!(
                runtime.request_cancellation(&job_id, "wrong-token", 12),
                Err(WorkerRuntimeError::CapabilityDenied(_))
            ) || runtime.load_job(&job_id).expect("terminal job").status == JobStatus::Cancelled
        );
    }

    #[test]
    fn failed_executor_fence_never_claims_terminal_cancellation_or_retry() {
        let workspace = test_directory("cancel-fence-workspace");
        let store = test_directory("cancel-fence-store");
        let executor = Arc::new(ScriptedExecutor::with_dispatch(vec![
            DispatchAction::Return(running(10, "external-unfenced")),
        ]));
        let runtime = WorkerRuntime::open_with_shared(
            &store,
            Arc::clone(&executor),
            Arc::new(DenyAllServices),
        )
        .expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("planner");
        let job_id = runtime
            .enqueue(
                plan_request("cancel-fence", &scope(&workspace, "scope"), "scope"),
                10,
            )
            .expect("job");
        runtime
            .dispatch_next(10)
            .expect("dispatch")
            .expect("running report");
        executor.fail_cancellation("external execution could not be fenced");

        assert!(matches!(
            runtime.request_cancellation(&job_id, "cancel:cancel-fence", 11),
            Err(WorkerRuntimeError::ExecutionFailed(_))
        ));
        let after_request = runtime
            .load_job(&job_id)
            .expect("durable cancellation intent");
        assert_eq!(after_request.status, JobStatus::Running);
        assert_eq!(after_request.cancellation_requested_at_tick, Some(11));

        assert!(matches!(
            runtime.reconcile_in_flight(12),
            Err(WorkerRuntimeError::ExecutionFailed(_))
        ));
        assert_eq!(
            runtime.load_job(&job_id).expect("still unfenced").status,
            JobStatus::Running,
            "a failed executor fence cannot authorize terminal cancellation or retry"
        );
    }

    #[test]
    fn two_scoped_workers_hold_concurrent_leases_without_state_collision() {
        let workspace_a = test_directory("scope-a-workspace");
        let workspace_b = test_directory("scope-b-workspace");
        let store = test_directory("concurrent-store");
        let executor = ScriptedExecutor::with_dispatch(vec![
            DispatchAction::Return(running(10, "external-a")),
            DispatchAction::Return(running(10, "external-b")),
        ]);
        let runtime = WorkerRuntime::open(&store, executor, DenyAllServices).expect("runtime");
        runtime
            .register_worker(
                registration("planner-a", GovernedWorkerRole::Planner, "scope-a"),
                1,
            )
            .expect("planner a");
        runtime
            .register_worker(
                registration("planner-b", GovernedWorkerRole::Planner, "scope-b"),
                1,
            )
            .expect("planner b");
        let job_a = runtime
            .enqueue(
                plan_request("scope-a", &scope(&workspace_a, "scope-a"), "scope-a"),
                10,
            )
            .expect("job a");
        let job_b = runtime
            .enqueue(
                plan_request("scope-b", &scope(&workspace_b, "scope-b"), "scope-b"),
                10,
            )
            .expect("job b");
        let first = runtime.dispatch_next(10).expect("first").expect("report");
        let second = runtime.dispatch_next(10).expect("second").expect("report");
        assert_ne!(first.execution_id, second.execution_id);
        assert_ne!(first.worker_id, second.worker_id);
        assert_eq!(
            runtime.load_job(&job_a).expect("job a").status,
            JobStatus::Running
        );
        assert_eq!(
            runtime.load_job(&job_b).expect("job b").status,
            JobStatus::Running
        );
        assert_eq!(runtime.active_execution_ids().expect("active").len(), 2);
    }

    #[test]
    fn fair_scheduler_rotates_scope_at_equal_priority() {
        let workspace_a = test_directory("fair-a");
        let workspace_b = test_directory("fair-b");
        let store = test_directory("fair-store");
        let executor = ScriptedExecutor::with_dispatch(vec![
            DispatchAction::Return(running(10, "one")),
            DispatchAction::Return(running(10, "two")),
            DispatchAction::Return(running(10, "three")),
        ]);
        let runtime = WorkerRuntime::open(&store, executor, DenyAllServices).expect("runtime");
        let mut worker = registration("shared-planner", GovernedWorkerRole::Planner, "*");
        worker.allowed_workspace_scopes = vec!["*".to_string()];
        worker.policy.max_concurrency = 3;
        runtime.register_worker(worker, 1).expect("shared planner");

        let a1 = runtime
            .enqueue(plan_request("a1", &scope(&workspace_a, "a"), "a"), 10)
            .expect("a1");
        let a2 = runtime
            .enqueue(plan_request("a2", &scope(&workspace_a, "a"), "a"), 10)
            .expect("a2");
        let b1 = runtime
            .enqueue(plan_request("b1", &scope(&workspace_b, "b"), "b"), 10)
            .expect("b1");
        assert_eq!(
            runtime
                .dispatch_next(10)
                .expect("first")
                .expect("report")
                .job_id,
            a1
        );
        assert_eq!(
            runtime
                .dispatch_next(10)
                .expect("second")
                .expect("report")
                .job_id,
            b1
        );
        assert_eq!(
            runtime
                .dispatch_next(10)
                .expect("third")
                .expect("report")
                .job_id,
            a2
        );
    }

    #[test]
    fn restart_rejects_mismatched_and_conflicting_result_state() {
        let workspace = test_directory("integrity-workspace");
        let store = test_directory("integrity-store");
        let conflict_store = test_directory("conflict-store");
        let target = workspace.join("candidate.txt");
        fs::write(&target, b"candidate-v1").expect("seed");
        let runtime = WorkerRuntime::open(
            &store,
            ReferenceWorkerExecutor,
            LocalReferenceCapabilityServices::new(
                vec![workspace.clone()],
                "m3:test",
                b"services",
                10,
            )
            .expect("services"),
        )
        .expect("runtime");
        register_all(&runtime, "candidate-a");
        let evidence = runtime
            .run_reference_workflow(workflow_spec(&workspace, &target, "candidate-a"), 10)
            .expect("workflow");
        let valid_state = runtime.state.lock().expect("state").clone();
        let mut state = valid_state.clone();
        let first_digest = evidence.result_digests[0].clone();
        let first = state
            .results
            .get_mut(first_digest.as_str())
            .expect("first result");
        first.output = WorkOutput::Plan {
            baseline_digest: ContentDigest::from_bytes(b"tampered-baseline"),
            plan_digest: ContentDigest::from_bytes(b"tampered-plan"),
        };
        persist_state(&store, &state).expect("persist deliberately corrupt fixture");
        drop(runtime);

        assert!(matches!(
            WorkerRuntime::open(
                &store,
                ReferenceWorkerExecutor,
                LocalReferenceCapabilityServices::new(
                    vec![workspace.clone()],
                    "m3:test",
                    b"services",
                    100,
                )
                .expect("services")
            ),
            Err(WorkerRuntimeError::Integrity(_))
        ));

        let mut conflicting_state = valid_state;
        let mut conflicting_result = conflicting_state
            .results
            .get(first_digest.as_str())
            .expect("first result")
            .clone();
        conflicting_result.completed_at_tick =
            conflicting_result.completed_at_tick.saturating_add(1);
        conflicting_result.result_digest = conflicting_result
            .recompute_digest()
            .expect("conflicting result digest");
        conflicting_state.results.insert(
            conflicting_result.result_digest.to_string(),
            conflicting_result,
        );
        persist_state(&conflict_store, &conflicting_state)
            .expect("persist deliberately conflicting fixture");
        assert!(matches!(
            WorkerRuntime::open(
                &conflict_store,
                ReferenceWorkerExecutor,
                LocalReferenceCapabilityServices::new(
                    vec![workspace],
                    "m3:test",
                    b"services",
                    100,
                )
                .expect("services")
            ),
            Err(WorkerRuntimeError::Conflict(_))
        ));
    }

    #[test]
    fn envelope_scope_and_authority_expansion_are_denied_before_dispatch() {
        let workspace = test_directory("envelope-workspace");
        let store = test_directory("envelope-store");
        let runtime =
            WorkerRuntime::open(&store, ReferenceWorkerExecutor, DenyAllServices).expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("planner");
        let mut request = plan_request("bad-scope", &scope(&workspace, "scope"), "scope");
        request.capability_envelope.allowed_resource_scopes =
            vec!["workspace:somewhere-else".to_string()];
        assert!(matches!(
            runtime.enqueue(request, 10),
            Err(WorkerRuntimeError::CapabilityDenied(_))
        ));

        let mut request = plan_request("approval", &scope(&workspace, "scope"), "scope");
        request.capability_envelope.world_grants[0].default_approval_class =
            ApprovalClass::HumanRequired;
        assert!(matches!(
            runtime.enqueue(request, 10),
            Err(WorkerRuntimeError::CapabilityDenied(_))
        ));
    }

    #[test]
    fn cancellation_secret_is_one_way_and_never_persisted() {
        let workspace = test_directory("secret-workspace");
        let store = test_directory("secret-store");
        let runtime =
            WorkerRuntime::open(&store, ReferenceWorkerExecutor, DenyAllServices).expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("planner");
        let secret = "correct-horse-battery-staple";
        let mut request = plan_request("secret", &scope(&workspace, "scope"), "scope");
        request.cancellation_token = CancellationToken::from_secret(secret);
        let job_id = runtime.enqueue(request, 10).expect("job");

        let persisted = fs::read_to_string(store.join(STATE_FILE_NAME)).expect("durable state");
        assert!(!persisted.contains(secret));
        assert!(
            persisted.contains(
                runtime
                    .load_job(&job_id)
                    .expect("job")
                    .request
                    .cancellation_token
                    .credential_digest
                    .as_str()
            )
        );
        assert!(matches!(
            runtime.request_cancellation(&job_id, "wrong-secret", 11),
            Err(WorkerRuntimeError::CapabilityDenied(_))
        ));
        runtime
            .request_cancellation(&job_id, secret, 11)
            .expect("matching secret");
        assert_eq!(
            runtime.load_job(&job_id).expect("cancelled job").status,
            JobStatus::Cancelled
        );
    }

    #[test]
    fn store_lock_rejects_duplicate_live_open_and_hands_off_after_drop() {
        let store = test_directory("store-lock");
        let first =
            WorkerRuntime::open(&store, ReferenceWorkerExecutor, DenyAllServices).expect("first");
        assert!(matches!(
            WorkerRuntime::open(&store, ReferenceWorkerExecutor, DenyAllServices),
            Err(WorkerRuntimeError::Conflict(_))
        ));
        let clone = first.clone();
        drop(first);
        assert!(matches!(
            WorkerRuntime::open(&store, ReferenceWorkerExecutor, DenyAllServices),
            Err(WorkerRuntimeError::Conflict(_))
        ));
        drop(clone);
        WorkerRuntime::open(&store, ReferenceWorkerExecutor, DenyAllServices)
            .expect("lock handoff after final clone");
    }

    #[test]
    fn logical_tick_claims_are_durable_and_jobs_are_sequence_sorted() {
        let workspace = test_directory("logical-tick-workspace");
        let store = test_directory("logical-tick-store");
        let runtime =
            WorkerRuntime::open(&store, ReferenceWorkerExecutor, DenyAllServices).expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                50,
            )
            .expect("planner");
        assert_eq!(runtime.claim_tick_span(3).expect("span"), 51);
        assert_eq!(runtime.claim_tick().expect("single tick"), 54);
        assert_eq!(
            runtime
                .claim_tick_span_at_or_after(60, 2)
                .expect("bounded span"),
            60
        );
        assert!(matches!(
            runtime.claim_tick_span(0),
            Err(WorkerRuntimeError::InvalidRequest(_))
        ));
        assert!(matches!(
            runtime.claim_tick_span_at_or_after_before(100, 7, 106),
            Err(WorkerRuntimeError::DeadlineExceeded(_))
        ));
        assert!(matches!(
            runtime.claim_tick_span_at_or_after_before(u64::MAX - 7, 7, u64::MAX),
            Err(WorkerRuntimeError::InvalidRequest(_))
        ));
        runtime
            .enqueue(
                plan_request("second", &scope(&workspace, "scope"), "scope"),
                56,
            )
            .expect("second");
        runtime
            .enqueue(
                plan_request("first", &scope(&workspace, "scope"), "scope"),
                55,
            )
            .expect("first");
        let jobs = runtime.jobs().expect("jobs");
        assert_eq!(jobs.len(), 2);
        assert!(jobs[0].sequence < jobs[1].sequence);
        drop(runtime);

        let reopened =
            WorkerRuntime::open(&store, ReferenceWorkerExecutor, DenyAllServices).expect("reopen");
        assert_eq!(
            reopened.claim_tick().expect("durable next tick"),
            62,
            "rejected deadline-bounded reservation does not advance the allocator"
        );
    }

    #[test]
    fn cancellation_waits_for_effect_safe_boundary_and_cannot_overwrite_success() {
        let workspace = test_directory("cancel-race-workspace");
        let store = test_directory("cancel-race-store");
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let services = Arc::new(BlockingCapabilityServices {
            inner: LocalReferenceCapabilityServices::new(
                vec![workspace.clone()],
                "m3:blocking",
                b"blocking-service",
                10,
            )
            .expect("services"),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let runtime =
            WorkerRuntime::open_with_shared(&store, Arc::new(ReferenceWorkerExecutor), services)
                .expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("planner");
        let job_id = runtime
            .enqueue(
                plan_request("cancel-race", &scope(&workspace, "scope"), "scope"),
                10,
            )
            .expect("job");

        let dispatch_runtime = runtime.clone();
        let dispatch = thread::spawn(move || dispatch_runtime.dispatch_next(10));
        let _ = entered.wait();

        let cancellation_started = Arc::new(Barrier::new(2));
        let cancellation_runtime = runtime.clone();
        let cancellation_job = job_id.clone();
        let cancellation_thread_started = Arc::clone(&cancellation_started);
        let cancellation = thread::spawn(move || {
            let _ = cancellation_thread_started.wait();
            cancellation_runtime.request_cancellation(&cancellation_job, "cancel:cancel-race", 11)
        });
        let _ = cancellation_started.wait();
        assert_ne!(
            runtime.load_job(&job_id).expect("in-flight job").status,
            JobStatus::Cancelled
        );

        let _ = release.wait();
        let dispatch = dispatch
            .join()
            .expect("dispatch thread")
            .expect("dispatch")
            .expect("report");
        cancellation
            .join()
            .expect("cancellation thread")
            .expect("cancellation");
        assert_eq!(dispatch.status, JobStatus::Completed);
        assert_eq!(
            runtime.load_job(&job_id).expect("terminal job").status,
            JobStatus::Completed
        );
    }

    #[test]
    fn concurrent_reconciliation_claims_one_execution_exactly_once() {
        let workspace = test_directory("reconcile-race-workspace");
        let store = test_directory("reconcile-race-store");
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let executor = Arc::new(BlockingReconcileExecutor {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            reconciliation_calls: Arc::clone(&calls),
        });
        let runtime = WorkerRuntime::open_with_shared(&store, executor, Arc::new(DenyAllServices))
            .expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("planner");
        let job_id = runtime
            .enqueue(
                plan_request("reconcile-race", &scope(&workspace, "scope"), "scope"),
                10,
            )
            .expect("job");
        runtime
            .dispatch_next(10)
            .expect("dispatch")
            .expect("running report");

        let first_runtime = runtime.clone();
        let first = thread::spawn(move || first_runtime.reconcile_in_flight(11));
        let _ = entered.wait();
        let second_started = Arc::new(Barrier::new(2));
        let second_thread_started = Arc::clone(&second_started);
        let second_runtime = runtime.clone();
        let second = thread::spawn(move || {
            let _ = second_thread_started.wait();
            second_runtime.reconcile_in_flight(11)
        });
        let _ = second_started.wait();
        let _ = release.wait();
        first
            .join()
            .expect("first thread")
            .expect("first reconcile");
        second
            .join()
            .expect("second thread")
            .expect("second reconcile");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let job = runtime.load_job(&job_id).expect("job");
        assert_eq!(job.status, JobStatus::RetryPending);
        assert_eq!(job.failures.len(), 1);
    }

    #[test]
    fn runtime_limit_caps_leases_heartbeats_and_reconciliation() {
        let workspace = test_directory("runtime-limit-workspace");
        let store = test_directory("runtime-limit-store");
        let executor = ScriptedExecutor::with_dispatch(vec![DispatchAction::Return(running(
            10,
            "runtime-limited",
        ))]);
        let runtime = WorkerRuntime::open(&store, executor, DenyAllServices).expect("runtime");
        let mut worker = registration("planner", GovernedWorkerRole::Planner, "scope");
        worker.policy.max_attempts = 1;
        worker.policy.lease_duration_ticks = 20;
        runtime.register_worker(worker, 1).expect("planner");
        let mut request = plan_request("runtime-limit", &scope(&workspace, "scope"), "scope");
        request.budget.max_attempts = 1;
        request.budget.max_runtime_ticks = 3;
        let job_id = runtime.enqueue(request, 10).expect("job");
        let dispatch = runtime
            .dispatch_next(10)
            .expect("dispatch")
            .expect("report");
        assert_eq!(
            runtime
                .load_execution(&dispatch.execution_id)
                .expect("execution")
                .lease
                .expires_at_tick,
            13
        );
        runtime
            .heartbeat(&dispatch.execution_id, 13)
            .expect("boundary heartbeat");
        assert!(matches!(
            runtime.heartbeat(&dispatch.execution_id, 14),
            Err(WorkerRuntimeError::BudgetExceeded(_))
        ));
        let report = runtime.reconcile_in_flight(14).expect("runtime expiry");
        assert_eq!(report.terminal_job_ids, vec![job_id.clone()]);
        assert_eq!(
            runtime.load_job(&job_id).expect("timed out").status,
            JobStatus::TimedOut
        );
    }

    #[test]
    fn reconciled_heartbeats_must_be_monotonic() {
        let workspace = test_directory("heartbeat-order-workspace");
        let store = test_directory("heartbeat-order-store");
        let executor = Arc::new(ScriptedExecutor::with_dispatch(vec![
            DispatchAction::Return(running(10, "heartbeat-order")),
        ]));
        executor.push_reconciliation(ReconcileAction::Return(
            ExecutorReconciliation::StillRunning {
                executor_handle: "heartbeat-order".to_string(),
                heartbeat_tick: 9,
            },
        ));
        let runtime = WorkerRuntime::open_with_shared(
            &store,
            Arc::clone(&executor),
            Arc::new(DenyAllServices),
        )
        .expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("planner");
        let job_id = runtime
            .enqueue(
                plan_request("heartbeat-order", &scope(&workspace, "scope"), "scope"),
                10,
            )
            .expect("job");
        runtime
            .dispatch_next(10)
            .expect("dispatch")
            .expect("report");
        assert!(matches!(
            runtime.reconcile_in_flight(11),
            Err(WorkerRuntimeError::Conflict(_))
        ));
        assert_eq!(
            runtime.load_job(&job_id).expect("still active").status,
            JobStatus::Running
        );
    }

    #[test]
    fn stale_lease_is_failed_before_executor_reconciliation_can_run() {
        let workspace = test_directory("stale-pre-effect-workspace");
        let store = test_directory("stale-pre-effect-store");
        let executor = Arc::new(ScriptedExecutor::with_dispatch(vec![
            DispatchAction::Return(running(10, "stale-pre-effect")),
        ]));
        executor.push_reconciliation(ReconcileAction::Return(
            ExecutorReconciliation::StillRunning {
                executor_handle: "must-not-run".to_string(),
                heartbeat_tick: 21,
            },
        ));
        let runtime = WorkerRuntime::open_with_shared(
            &store,
            Arc::clone(&executor),
            Arc::new(DenyAllServices),
        )
        .expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("planner");
        let job_id = runtime
            .enqueue(
                plan_request("stale-pre-effect", &scope(&workspace, "scope"), "scope"),
                10,
            )
            .expect("job");
        let execution_id = runtime
            .dispatch_next(10)
            .expect("dispatch")
            .expect("running report")
            .execution_id;

        assert!(matches!(
            runtime.heartbeat(&execution_id, 21),
            Err(WorkerRuntimeError::DeadlineExceeded(_))
        ));
        let report = runtime
            .reconcile_in_flight(21)
            .expect("stale reconciliation");
        assert_eq!(report.retried_job_ids, vec![job_id.clone()]);
        assert_eq!(
            runtime.load_job(&job_id).expect("stale job").status,
            JobStatus::RetryPending
        );
        assert_eq!(
            runtime
                .load_job(&job_id)
                .expect("stale failure")
                .failures
                .last()
                .expect("failure")
                .class,
            "stale_lease"
        );
        assert_eq!(
            executor
                .reconcile_actions
                .lock()
                .expect("script remains untouched")
                .len(),
            1,
            "stale reconciliation must not enter the executor"
        );
        assert_eq!(
            executor
                .cancellations
                .lock()
                .expect("cancellation journal")
                .as_slice(),
            &[execution_id]
        );
    }

    #[test]
    fn reopen_rejects_resealed_receipt_and_package_crosslink_tampering() {
        let workspace = test_directory("crosslink-workspace");
        let store = test_directory("receipt-crosslink-store");
        let package_store = test_directory("package-crosslink-store");
        let runtime = WorkerRuntime::open(
            &store,
            ReferenceWorkerExecutor,
            LocalReferenceCapabilityServices::new(
                vec![workspace.clone()],
                "m3:test",
                b"services",
                10,
            )
            .expect("services"),
        )
        .expect("runtime");
        runtime
            .register_worker(
                registration("planner", GovernedWorkerRole::Planner, "scope"),
                1,
            )
            .expect("planner");
        let job_id = runtime
            .enqueue(
                plan_request("crosslink", &scope(&workspace, "scope"), "scope"),
                10,
            )
            .expect("job");
        let dispatch = runtime
            .dispatch_next(10)
            .expect("dispatch")
            .expect("report");
        let valid_state = runtime.state.lock().expect("state").clone();
        drop(runtime);

        let mut receipt_state = valid_state.clone();
        let execution = receipt_state
            .executions
            .get_mut(&dispatch.execution_id)
            .expect("execution");
        let receipt = execution.capability_receipts.first_mut().expect("receipt");
        receipt.capability_envelope_digest = ContentDigest::from_bytes(b"forged-envelope");
        receipt.receipt_id = receipt.recompute_receipt_id().expect("reseal receipt");
        let receipt_digests = execution
            .capability_receipts
            .iter()
            .map(|receipt| digest_json_content(receipt).expect("receipt digest"))
            .collect::<Vec<_>>();
        let old_digest = dispatch.result_digest.clone().expect("result");
        let mut result = receipt_state
            .results
            .remove(old_digest.as_str())
            .expect("result");
        result.capability_receipt_digests = receipt_digests;
        result.result_digest = result.recompute_digest().expect("reseal result");
        let forged_result_digest = result.result_digest.clone();
        receipt_state
            .jobs
            .get_mut(&job_id)
            .expect("job")
            .result_digest = Some(forged_result_digest.clone());
        receipt_state
            .executions
            .get_mut(&dispatch.execution_id)
            .expect("execution")
            .result_digest = Some(forged_result_digest.clone());
        receipt_state
            .results
            .insert(forged_result_digest.to_string(), result);
        persist_state(&store, &receipt_state).expect("persist receipt tamper");
        assert!(matches!(
            WorkerRuntime::open(
                &store,
                ReferenceWorkerExecutor,
                LocalReferenceCapabilityServices::new(
                    vec![workspace.clone()],
                    "m3:test",
                    b"services",
                    20,
                )
                .expect("services")
            ),
            Err(WorkerRuntimeError::Integrity(_))
        ));

        let mut package_state = valid_state;
        let old_digest = dispatch.result_digest.expect("result");
        let execution = package_state
            .executions
            .get_mut(&dispatch.execution_id)
            .expect("execution");
        execution.implementation_ref = "forged-worker-implementation".to_string();
        let mut result = package_state
            .results
            .remove(old_digest.as_str())
            .expect("result");
        result.implementation_ref = execution.implementation_ref.clone();
        result.result_digest = result.recompute_digest().expect("reseal result");
        let forged_result_digest = result.result_digest.clone();
        execution.result_digest = Some(forged_result_digest.clone());
        package_state
            .jobs
            .get_mut(&job_id)
            .expect("job")
            .result_digest = Some(forged_result_digest.clone());
        package_state
            .results
            .insert(forged_result_digest.to_string(), result);
        persist_state(&package_store, &package_state).expect("persist package tamper");
        assert!(matches!(
            WorkerRuntime::open(
                &package_store,
                ReferenceWorkerExecutor,
                LocalReferenceCapabilityServices::new(vec![workspace], "m3:test", b"services", 20,)
                    .expect("services")
            ),
            Err(WorkerRuntimeError::Integrity(_))
        ));
    }
}
