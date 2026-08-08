//! Effect-owning, typed capability-service foundation for M3.
//!
//! The service host in this module records an invocation before dispatch,
//! routes it to an injected typed port, and commits one terminal receipt after
//! the port returns. A receipt can represent success, failure, timeout,
//! cancellation, unavailability, resource exhaustion, or unsupported work.
//! There is no success-shaped fallback.
//!
//! Concrete local adapters reuse the bounded M1 workspace, validation, and
//! deployment implementations. Scheduling is deliberately only a port here:
//! until an M2 executor is injected, scheduling returns `Unsupported`.

use crate::candidate::{
    COMPONENT_WAT_PATH, CandidateBuild, CandidateFileReplacement, CandidateWorkspaceService,
    CandidateWorkspaceSnapshot, MaterializedCandidatePatchset,
};
use crate::deployment::{
    ActivationRecord, ActivationRequest, ArtifactSnapshot, DeploymentState, InitializationRecord,
    LocalDeploymentService, ObservationOutcome, ObservationRecord, ObservationRequest,
    RollbackRecord, RollbackRequest,
};
use crate::execution::{
    ApprovalClass, AuthorityClass, ContentDigest, NativeServiceFamily, digest_json_content,
};
use crate::m1_validation::{
    ComparisonDecision, ComparisonRecord, ProvingRecord, ValidationSuite, compare_proving_records,
    prove_component_i32, validate_comparison_record, validate_proving_record,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const CAPABILITY_HOST_STATE_SCHEMA_VERSION: u32 = 1;
pub const CAPABILITY_RECEIPT_SCHEMA: &str = "wasm-biotic.capability-receipt.v1";
pub const CAPABILITY_ATTESTATION_SCHEMA: &str = "wasm-biotic.capability-attestation.v1";
pub const PACKAGE_ARTIFACT_SCHEMA: &str = "wasm-biotic.package-artifact.v1";
pub const EVIDENCE_RECORD_SCHEMA: &str = "wasm-biotic.evidence-record.v1";
pub const REVIEW_RECORD_SCHEMA: &str = "wasm-biotic.review-record.v1";

const HOST_STATE_FILE: &str = "capability-services-state.json";
const HOST_INPUT_DIRECTORY: &str = "invocation-inputs";
const HOST_OUTPUT_DIRECTORY: &str = "invocation-outputs";
const HOST_RECEIPT_DIRECTORY: &str = "invocation-receipts";
const MAX_INVOCATION_INPUT_BYTES: usize = 4 * 1_048_576;
const MAX_INVOCATION_JOURNAL_ENTRIES: usize = 10_000;
const MAX_INVOCATION_TIMEOUT_MS: u64 = 300_000;
const MAX_PACKAGE_BYTES: usize = 16 * 1_048_576;
const MAX_EVIDENCE_BYTES: usize = 4 * 1_048_576;
const MAX_EXECUTABLE_IDENTITY_BYTES: u64 = 256 * 1_048_576;
pub const MAX_FACTORY_EFFECT_REQUEST_BYTES: usize = 4 * 1_048_576;
pub const MAX_FACTORY_EFFECT_RESPONSE_BYTES: usize = 4 * 1_048_576;
const MAX_FACTORY_EFFECT_ID_BYTES: usize = 1_024;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityOperation {
    WorkspaceOpen,
    WorkspaceSnapshot,
    WorkspacePatch,
    CandidateBuild,
    CommandExecute,
    PackagePublish,
    PackageVerify,
    ValidationProve,
    ValidationCompare,
    ReviewCandidate,
    EvidencePublish,
    EvidenceResolve,
    ScheduleJob,
    DeploymentInitialize,
    DeploymentActivate,
    DeploymentObserve,
    DeploymentRollback,
    OperationsInspect,
    FactoryExecute,
    FactoryProviderProposal,
    FactoryShadow,
    FactoryInitialize,
    FactoryStateMigrate,
    FactoryActivate,
    FactoryObserve,
    FactoryRollback,
    FactoryInspect,
}

impl CapabilityOperation {
    pub fn family(self) -> NativeServiceFamily {
        match self {
            Self::WorkspaceOpen
            | Self::WorkspaceSnapshot
            | Self::WorkspacePatch
            | Self::CandidateBuild
            | Self::CommandExecute => NativeServiceFamily::Build,
            Self::PackagePublish | Self::PackageVerify => NativeServiceFamily::Packaging,
            Self::ValidationProve
            | Self::ValidationCompare
            | Self::FactoryExecute
            | Self::FactoryProviderProposal
            | Self::FactoryShadow => NativeServiceFamily::Validation,
            Self::ReviewCandidate => NativeServiceFamily::Review,
            Self::EvidencePublish | Self::EvidenceResolve => NativeServiceFamily::Continuity,
            Self::ScheduleJob => NativeServiceFamily::Scheduling,
            Self::DeploymentInitialize
            | Self::DeploymentActivate
            | Self::DeploymentObserve
            | Self::DeploymentRollback
            | Self::OperationsInspect
            | Self::FactoryInitialize
            | Self::FactoryStateMigrate
            | Self::FactoryActivate
            | Self::FactoryObserve
            | Self::FactoryRollback
            | Self::FactoryInspect => NativeServiceFamily::Operations,
        }
    }

    pub fn minimum_authority(self) -> AuthorityClass {
        match self {
            Self::WorkspaceSnapshot
            | Self::PackageVerify
            | Self::ValidationProve
            | Self::ValidationCompare
            | Self::ReviewCandidate
            | Self::EvidenceResolve
            | Self::OperationsInspect
            | Self::FactoryExecute
            | Self::FactoryProviderProposal
            | Self::FactoryShadow
            | Self::FactoryInspect => AuthorityClass::Observe,
            Self::WorkspaceOpen
            | Self::WorkspacePatch
            | Self::CandidateBuild
            | Self::CommandExecute
            | Self::PackagePublish
            | Self::EvidencePublish => AuthorityClass::LocalMutate,
            Self::ScheduleJob => AuthorityClass::AutomationControl,
            Self::DeploymentInitialize
            | Self::DeploymentActivate
            | Self::DeploymentObserve
            | Self::DeploymentRollback
            | Self::FactoryInitialize
            | Self::FactoryStateMigrate
            | Self::FactoryActivate
            | Self::FactoryObserve
            | Self::FactoryRollback => AuthorityClass::PromotionControl,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyContract {
    SingleAttemptNoAutomaticRetry,
    IdempotentAtLeastOnce,
    ReadOnlyReplayable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutBehavior {
    Enforced,
    Cooperative,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityServiceDescriptor {
    service_id: String,
    family: NativeServiceFamily,
    scope_id: String,
    required_authority: AuthorityClass,
    required_approval: ApprovalClass,
    supported_operations: BTreeSet<CapabilityOperation>,
    idempotency_contract: IdempotencyContract,
    timeout_behavior: TimeoutBehavior,
    implementation_id: String,
    implementation_digest: ContentDigest,
}

impl CapabilityServiceDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service_id: impl Into<String>,
        family: NativeServiceFamily,
        scope_id: impl Into<String>,
        required_authority: AuthorityClass,
        required_approval: ApprovalClass,
        supported_operations: impl IntoIterator<Item = CapabilityOperation>,
        idempotency_contract: IdempotencyContract,
        timeout_behavior: TimeoutBehavior,
        implementation_id: impl Into<String>,
    ) -> Result<Self, CapabilityHostError> {
        let service_id = service_id.into();
        let scope_id = scope_id.into();
        let implementation_id = implementation_id.into();
        validate_nonblank("service_id", &service_id)?;
        validate_nonblank("scope_id", &scope_id)?;
        validate_nonblank("implementation_id", &implementation_id)?;
        if required_approval == ApprovalClass::Forbidden {
            return Err(CapabilityHostError::InvalidConfiguration(
                "a service descriptor cannot advertise effects with Forbidden approval".to_string(),
            ));
        }
        let supported_operations = supported_operations.into_iter().collect::<BTreeSet<_>>();
        if supported_operations.is_empty() {
            return Err(CapabilityHostError::InvalidConfiguration(format!(
                "service '{service_id}' must declare at least one operation"
            )));
        }
        for operation in &supported_operations {
            if operation.family() != family {
                return Err(CapabilityHostError::InvalidConfiguration(format!(
                    "operation '{operation:?}' belongs to '{:?}', not descriptor family '{family:?}'",
                    operation.family()
                )));
            }
            if required_authority < operation.minimum_authority() {
                return Err(CapabilityHostError::InvalidConfiguration(format!(
                    "service '{service_id}' authority '{required_authority:?}' is below operation '{operation:?}' minimum '{:?}'",
                    operation.minimum_authority()
                )));
            }
        }
        let implementation_digest = digest_json_content(&(
            "wasm-biotic:capability-service-implementation:v1",
            &service_id,
            family,
            &scope_id,
            &required_authority,
            &required_approval,
            &supported_operations,
            idempotency_contract,
            timeout_behavior,
            &implementation_id,
        ))
        .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
        Ok(Self {
            service_id,
            family,
            scope_id,
            required_authority,
            required_approval,
            supported_operations,
            idempotency_contract,
            timeout_behavior,
            implementation_id,
            implementation_digest,
        })
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn family(&self) -> NativeServiceFamily {
        self.family
    }

    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    pub fn supported_operations(&self) -> &BTreeSet<CapabilityOperation> {
        &self.supported_operations
    }

    pub fn implementation_digest(&self) -> &ContentDigest {
        &self.implementation_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum InvocationApproval {
    Automatic,
    Granted {
        approval_ref: String,
        class: ApprovalClass,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationIdentity {
    pub invocation_id: String,
    pub idempotency_key: String,
    pub service_id: String,
    pub scope_id: String,
    pub caller_id: String,
    pub authority: AuthorityClass,
    pub approval: InvocationApproval,
}

impl InvocationIdentity {
    fn validate(&self) -> Result<(), CapabilityHostError> {
        validate_nonblank("invocation_id", &self.invocation_id)?;
        validate_nonblank("idempotency_key", &self.idempotency_key)?;
        validate_nonblank("service_id", &self.service_id)?;
        validate_nonblank("scope_id", &self.scope_id)?;
        validate_nonblank("caller_id", &self.caller_id)?;
        if let InvocationApproval::Granted { approval_ref, .. } = &self.approval {
            validate_nonblank("approval_ref", approval_ref)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationBudget {
    pub timeout_ms: u64,
    pub max_request_bytes: usize,
}

impl InvocationBudget {
    pub fn bounded(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            max_request_bytes: MAX_INVOCATION_INPUT_BYTES,
        }
    }

    fn validate(&self) -> Result<(), CapabilityHostError> {
        if self.timeout_ms == 0 || self.timeout_ms > MAX_INVOCATION_TIMEOUT_MS {
            return Err(CapabilityHostError::InvalidRequest(format!(
                "timeout_ms must be between 1 and {MAX_INVOCATION_TIMEOUT_MS}"
            )));
        }
        if self.max_request_bytes == 0 || self.max_request_bytes > MAX_INVOCATION_INPUT_BYTES {
            return Err(CapabilityHostError::InvalidRequest(format!(
                "max_request_bytes must be between 1 and {MAX_INVOCATION_INPUT_BYTES}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedWorkspaceRef {
    pub scope_id: String,
    pub workspace_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedDeploymentRef {
    pub scope_id: String,
    pub deployment_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenWorkspaceRequest {
    pub workspace: ScopedWorkspaceRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotWorkspaceRequest {
    pub workspace: ScopedWorkspaceRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchWorkspaceRequest {
    pub workspace: ScopedWorkspaceRef,
    pub expected_before_digest: ContentDigest,
    pub replacement_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildCandidateRequest {
    pub workspace: ScopedWorkspaceRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishPackageRequest {
    pub workspace: ScopedWorkspaceRef,
    pub expected_package_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyPackageRequest {
    pub scope_id: String,
    pub package_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvePackageRequest {
    pub scope_id: String,
    pub package_digest: ContentDigest,
    pub suite: ValidationSuite,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompareProvingRequest {
    pub scope_id: String,
    pub suite: ValidationSuite,
    pub incumbent_proving_digest: ContentDigest,
    pub challenger_proving_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewCandidateRequest {
    pub scope_id: String,
    pub suite: ValidationSuite,
    pub comparison_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitializeDeploymentRequest {
    pub deployment: ScopedDeploymentRef,
    pub operation_id: String,
    pub incumbent_package_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivateDeploymentRequest {
    pub deployment: ScopedDeploymentRef,
    pub operation_id: String,
    pub package_digest: ContentDigest,
    pub expected_active_digest: ContentDigest,
    pub approval_ref: String,
    pub comparison_ref: String,
    pub observation_window_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserveDeploymentRequest {
    pub deployment: ScopedDeploymentRef,
    pub observation_id: String,
    pub activation_id: String,
    pub expected_active_digest: ContentDigest,
    pub outcome: ObservationOutcome,
    pub summary: String,
    pub evidence_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackDeploymentRequest {
    pub deployment: ScopedDeploymentRef,
    pub operation_id: String,
    pub activation_id: String,
    pub reason_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectOperationsRequest {
    pub deployment: ScopedDeploymentRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishEvidenceRequest {
    pub scope_id: String,
    pub evidence_id: String,
    pub media_type: String,
    pub subject_refs: Vec<String>,
    pub payload: Vec<u8>,
    pub expected_digest: Option<ContentDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveEvidenceRequest {
    pub scope_id: String,
    pub evidence_id: String,
    pub expected_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleJobRequest {
    pub scope_id: String,
    pub schedule_id: String,
    pub due_at_ms: u64,
    pub payload_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteCommandRequest {
    pub workspace: ScopedWorkspaceRef,
    pub command_id: String,
    pub arguments: Vec<String>,
    pub relative_working_directory: PathBuf,
    pub limits: CommandLimits,
}

/// Opaque, digest-bound request carried across the M3 factory-effect boundary.
///
/// M3 deliberately does not interpret `exact_request_bytes`. The injected
/// effect owner is responsible for the domain schema, while the host enforces
/// scope, size, identity, digest, authority, approval, and durable receipt
/// semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryEffectRequest {
    pub scope_id: String,
    pub factory_id: String,
    pub logical_effect_id: String,
    pub exact_request_digest: ContentDigest,
    pub exact_request_bytes: Vec<u8>,
}

impl FactoryEffectRequest {
    pub fn new(
        scope_id: impl Into<String>,
        factory_id: impl Into<String>,
        logical_effect_id: impl Into<String>,
        exact_request_bytes: Vec<u8>,
    ) -> Self {
        Self {
            scope_id: scope_id.into(),
            factory_id: factory_id.into(),
            logical_effect_id: logical_effect_id.into(),
            exact_request_digest: ContentDigest::from_bytes(&exact_request_bytes),
            exact_request_bytes,
        }
    }
}

/// Opaque, digest-bound result returned by an injected factory effect owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryEffectResult {
    pub logical_effect_id: String,
    pub exact_request_digest: ContentDigest,
    pub exact_response_digest: ContentDigest,
    pub exact_response_bytes: Vec<u8>,
}

impl FactoryEffectResult {
    pub fn new(request: &FactoryEffectRequest, exact_response_bytes: Vec<u8>) -> Self {
        Self {
            logical_effect_id: request.logical_effect_id.clone(),
            exact_request_digest: request.exact_request_digest.clone(),
            exact_response_digest: ContentDigest::from_bytes(&exact_response_bytes),
            exact_response_bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "request")]
pub enum CapabilityRequest {
    OpenWorkspace(OpenWorkspaceRequest),
    SnapshotWorkspace(SnapshotWorkspaceRequest),
    PatchWorkspace(PatchWorkspaceRequest),
    BuildCandidate(BuildCandidateRequest),
    ExecuteCommand(ExecuteCommandRequest),
    PublishPackage(PublishPackageRequest),
    VerifyPackage(VerifyPackageRequest),
    ProvePackage(ProvePackageRequest),
    CompareProving(CompareProvingRequest),
    ReviewCandidate(ReviewCandidateRequest),
    PublishEvidence(PublishEvidenceRequest),
    ResolveEvidence(ResolveEvidenceRequest),
    ScheduleJob(ScheduleJobRequest),
    InitializeDeployment(InitializeDeploymentRequest),
    ActivateDeployment(ActivateDeploymentRequest),
    ObserveDeployment(ObserveDeploymentRequest),
    RollbackDeployment(RollbackDeploymentRequest),
    InspectOperations(InspectOperationsRequest),
    FactoryExecute(FactoryEffectRequest),
    FactoryProviderProposal(FactoryEffectRequest),
    FactoryShadow(FactoryEffectRequest),
    FactoryInitialize(FactoryEffectRequest),
    FactoryStateMigrate(FactoryEffectRequest),
    FactoryActivate(FactoryEffectRequest),
    FactoryObserve(FactoryEffectRequest),
    FactoryRollback(FactoryEffectRequest),
    FactoryInspect(FactoryEffectRequest),
}

impl CapabilityRequest {
    pub fn operation(&self) -> CapabilityOperation {
        match self {
            Self::OpenWorkspace(_) => CapabilityOperation::WorkspaceOpen,
            Self::SnapshotWorkspace(_) => CapabilityOperation::WorkspaceSnapshot,
            Self::PatchWorkspace(_) => CapabilityOperation::WorkspacePatch,
            Self::BuildCandidate(_) => CapabilityOperation::CandidateBuild,
            Self::ExecuteCommand(_) => CapabilityOperation::CommandExecute,
            Self::PublishPackage(_) => CapabilityOperation::PackagePublish,
            Self::VerifyPackage(_) => CapabilityOperation::PackageVerify,
            Self::ProvePackage(_) => CapabilityOperation::ValidationProve,
            Self::CompareProving(_) => CapabilityOperation::ValidationCompare,
            Self::ReviewCandidate(_) => CapabilityOperation::ReviewCandidate,
            Self::PublishEvidence(_) => CapabilityOperation::EvidencePublish,
            Self::ResolveEvidence(_) => CapabilityOperation::EvidenceResolve,
            Self::ScheduleJob(_) => CapabilityOperation::ScheduleJob,
            Self::InitializeDeployment(_) => CapabilityOperation::DeploymentInitialize,
            Self::ActivateDeployment(_) => CapabilityOperation::DeploymentActivate,
            Self::ObserveDeployment(_) => CapabilityOperation::DeploymentObserve,
            Self::RollbackDeployment(_) => CapabilityOperation::DeploymentRollback,
            Self::InspectOperations(_) => CapabilityOperation::OperationsInspect,
            Self::FactoryExecute(_) => CapabilityOperation::FactoryExecute,
            Self::FactoryProviderProposal(_) => CapabilityOperation::FactoryProviderProposal,
            Self::FactoryShadow(_) => CapabilityOperation::FactoryShadow,
            Self::FactoryInitialize(_) => CapabilityOperation::FactoryInitialize,
            Self::FactoryStateMigrate(_) => CapabilityOperation::FactoryStateMigrate,
            Self::FactoryActivate(_) => CapabilityOperation::FactoryActivate,
            Self::FactoryObserve(_) => CapabilityOperation::FactoryObserve,
            Self::FactoryRollback(_) => CapabilityOperation::FactoryRollback,
            Self::FactoryInspect(_) => CapabilityOperation::FactoryInspect,
        }
    }

    pub fn scope_id(&self) -> &str {
        match self {
            Self::OpenWorkspace(request) => &request.workspace.scope_id,
            Self::SnapshotWorkspace(request) => &request.workspace.scope_id,
            Self::PatchWorkspace(request) => &request.workspace.scope_id,
            Self::BuildCandidate(request) => &request.workspace.scope_id,
            Self::ExecuteCommand(request) => &request.workspace.scope_id,
            Self::PublishPackage(request) => &request.workspace.scope_id,
            Self::VerifyPackage(request) => &request.scope_id,
            Self::ProvePackage(request) => &request.scope_id,
            Self::CompareProving(request) => &request.scope_id,
            Self::ReviewCandidate(request) => &request.scope_id,
            Self::PublishEvidence(request) => &request.scope_id,
            Self::ResolveEvidence(request) => &request.scope_id,
            Self::ScheduleJob(request) => &request.scope_id,
            Self::InitializeDeployment(request) => &request.deployment.scope_id,
            Self::ActivateDeployment(request) => &request.deployment.scope_id,
            Self::ObserveDeployment(request) => &request.deployment.scope_id,
            Self::RollbackDeployment(request) => &request.deployment.scope_id,
            Self::InspectOperations(request) => &request.deployment.scope_id,
            Self::FactoryExecute(request)
            | Self::FactoryProviderProposal(request)
            | Self::FactoryShadow(request)
            | Self::FactoryInitialize(request)
            | Self::FactoryStateMigrate(request)
            | Self::FactoryActivate(request)
            | Self::FactoryObserve(request)
            | Self::FactoryRollback(request)
            | Self::FactoryInspect(request) => &request.scope_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityInvocation {
    pub identity: InvocationIdentity,
    pub budget: InvocationBudget,
    pub request: CapabilityRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageArtifact {
    pub schema: String,
    pub scope_id: String,
    pub package_digest: ContentDigest,
    pub source_tree_digest: ContentDigest,
    pub byte_len: u64,
    pub artifact_relative_path: PathBuf,
    pub build_id: String,
    pub package_record_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageVerification {
    pub package_digest: ContentDigest,
    pub byte_len: u64,
    pub runnable_component: bool,
    pub verification_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Approved,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateReviewRecord {
    pub schema: String,
    pub scope_id: String,
    pub comparison_digest: ContentDigest,
    pub incumbent_proving_digest: ContentDigest,
    pub challenger_proving_digest: ContentDigest,
    pub decision: ReviewDecision,
    pub rationale: String,
    pub review_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub schema: String,
    pub scope_id: String,
    pub evidence_id: String,
    pub media_type: String,
    pub subject_refs: Vec<String>,
    pub content_digest: ContentDigest,
    pub byte_len: u64,
    pub record_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEvidence {
    pub record: EvidenceRecord,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleReceipt {
    pub schedule_id: String,
    pub due_at_ms: u64,
    pub payload_digest: ContentDigest,
    pub scheduler_receipt_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationsSnapshot {
    pub deployment_id: String,
    pub active_artifact: Option<ArtifactSnapshot>,
    pub activation_count: usize,
    pub observation_count: usize,
    pub rollback_count: usize,
    pub in_flight: bool,
    pub state_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum CapabilitySuccess {
    Workspace(Box<CandidateWorkspaceSnapshot>),
    Patchset(Box<MaterializedCandidatePatchset>),
    Build(Box<CandidateBuild>),
    Command(Box<BoundedCommandReceipt>),
    Package(Box<PackageArtifact>),
    PackageVerification(Box<PackageVerification>),
    Proving(Box<ProvingRecord>),
    Comparison(Box<ComparisonRecord>),
    Review(Box<CandidateReviewRecord>),
    EvidencePublished(Box<EvidenceRecord>),
    EvidenceResolved(Box<ResolvedEvidence>),
    Scheduled(Box<ScheduleReceipt>),
    DeploymentInitialized(Box<InitializationRecord>),
    DeploymentActivated(Box<ActivationRecord>),
    DeploymentObserved(Box<ObservationRecord>),
    DeploymentRolledBack(Box<RollbackRecord>),
    Operations(Box<OperationsSnapshot>),
    FactoryEffect(Box<FactoryEffectResult>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceFailureKind {
    Failed,
    TimedOut,
    Cancelled,
    Unavailable,
    Unsupported,
    ResourceExhausted,
    ScopeDenied,
    ApprovalBlocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "evidence")]
pub enum FailureEvidence {
    Command(Box<BoundedCommandReceipt>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceFailure {
    pub kind: ServiceFailureKind,
    pub code: String,
    pub message: String,
    pub evidence: Option<FailureEvidence>,
}

impl ServiceFailure {
    pub fn failed(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ServiceFailureKind::Failed, code, message)
    }

    pub fn timed_out(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ServiceFailureKind::TimedOut, code, message)
    }

    pub fn cancelled(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ServiceFailureKind::Cancelled, code, message)
    }

    pub fn unavailable(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ServiceFailureKind::Unavailable, code, message)
    }

    pub fn unsupported(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ServiceFailureKind::Unsupported, code, message)
    }

    pub fn resource_exhausted(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ServiceFailureKind::ResourceExhausted, code, message)
    }

    fn new(kind: ServiceFailureKind, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            code: code.into(),
            message: message.into(),
            evidence: None,
        }
    }

    fn with_evidence(mut self, evidence: FailureEvidence) -> Self {
        self.evidence = Some(evidence);
        self
    }
}

impl Display for ServiceFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?} {}: {}", self.kind, self.code, self.message)
    }
}

impl Error for ServiceFailure {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum InvocationOutcome {
    Succeeded { result: CapabilitySuccess },
    Terminal { failure: ServiceFailure },
}

impl InvocationOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Succeeded { .. })
    }

    pub fn failure_kind(&self) -> Option<ServiceFailureKind> {
        match self {
            Self::Succeeded { .. } => None,
            Self::Terminal { failure } => Some(failure.kind),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationProvenance {
    pub input_ref: String,
    pub output_ref: String,
    pub receipt_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationReceipt {
    schema: String,
    invocation_id: String,
    idempotency_key: String,
    service_id: String,
    family: NativeServiceFamily,
    operation: CapabilityOperation,
    scope_id: String,
    implementation_id: String,
    implementation_digest: ContentDigest,
    input_digest: ContentDigest,
    output_digest: ContentDigest,
    started_at_ms: u64,
    finished_at_ms: u64,
    outcome: InvocationOutcome,
    provenance: InvocationProvenance,
    receipt_digest: ContentDigest,
}

impl InvocationReceipt {
    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn family(&self) -> NativeServiceFamily {
        self.family
    }

    pub fn operation(&self) -> CapabilityOperation {
        self.operation
    }

    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    pub fn input_digest(&self) -> &ContentDigest {
        &self.input_digest
    }

    pub fn output_digest(&self) -> &ContentDigest {
        &self.output_digest
    }

    pub fn started_at_ms(&self) -> u64 {
        self.started_at_ms
    }

    pub fn finished_at_ms(&self) -> u64 {
        self.finished_at_ms
    }

    pub fn outcome(&self) -> &InvocationOutcome {
        &self.outcome
    }

    pub fn receipt_digest(&self) -> &ContentDigest {
        &self.receipt_digest
    }

    pub fn provenance(&self) -> &InvocationProvenance {
        &self.provenance
    }

    pub fn verify_integrity(&self) -> Result<(), CapabilityHostError> {
        if self.schema != CAPABILITY_RECEIPT_SCHEMA {
            return Err(CapabilityHostError::CorruptState(
                "unexpected invocation receipt schema".to_string(),
            ));
        }
        let expected_output = digest_json_content(&self.outcome)
            .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
        if self.output_digest != expected_output {
            return Err(CapabilityHostError::CorruptState(format!(
                "receipt '{}' output digest does not match its typed outcome",
                self.invocation_id
            )));
        }
        let expected_receipt = receipt_digest(self)?;
        if self.receipt_digest != expected_receipt {
            return Err(CapabilityHostError::CorruptState(format!(
                "receipt '{}' digest does not match its fields",
                self.invocation_id
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInvocationAttestation {
    pub schema: String,
    pub attestation_id: String,
    pub invocation_id: String,
    pub service_id: String,
    pub family: NativeServiceFamily,
    pub operation: CapabilityOperation,
    pub scope_id: String,
    pub implementation_digest: ContentDigest,
    pub input_digest: ContentDigest,
    pub output_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
    pub terminal_success: bool,
    pub failure_kind: Option<ServiceFailureKind>,
    pub provenance: InvocationProvenance,
    pub attestation_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceLifecycleState {
    Registered,
    Ready,
    Invoking,
    Degraded,
    Unavailable,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAvailability {
    Available,
    Degraded,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub service_id: String,
    pub family: NativeServiceFamily,
    pub scope_id: String,
    pub lifecycle: ServiceLifecycleState,
    pub availability: ServiceAvailability,
    pub successful_invocations: u64,
    pub failed_invocations: u64,
    pub last_invocation_id: Option<String>,
    pub last_failure: Option<ServiceFailure>,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DurableInvocation {
    identity: InvocationIdentity,
    family: NativeServiceFamily,
    operation: CapabilityOperation,
    input_digest: ContentDigest,
    started_at_ms: u64,
    receipt: Option<InvocationReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CapabilityHostState {
    schema_version: u32,
    configuration_digest: ContentDigest,
    health: BTreeMap<String, ServiceHealth>,
    invocations: Vec<DurableInvocation>,
}

#[derive(Clone, Debug)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub trait ClockPort: Send + Sync {
    fn now_ms(&self) -> u64;
}

#[derive(Clone, Debug, Default)]
pub struct SystemClock;

impl ClockPort for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

#[derive(Clone)]
pub struct InvocationControl {
    started_at_ms: u64,
    deadline_at_ms: u64,
    clock: Arc<dyn ClockPort>,
    cancellation: CancellationToken,
}

impl InvocationControl {
    fn new(
        started_at_ms: u64,
        timeout_ms: u64,
        clock: Arc<dyn ClockPort>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            started_at_ms,
            deadline_at_ms: started_at_ms.saturating_add(timeout_ms),
            clock,
            cancellation,
        }
    }

    pub fn started_at_ms(&self) -> u64 {
        self.started_at_ms
    }

    pub fn deadline_at_ms(&self) -> u64 {
        self.deadline_at_ms
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn check(&self) -> Result<(), ServiceFailure> {
        if self.is_cancelled() {
            return Err(ServiceFailure::cancelled(
                "invocation_cancelled",
                "the invocation was cancelled before the effect boundary",
            ));
        }
        if self.clock.now_ms() >= self.deadline_at_ms {
            return Err(ServiceFailure::timed_out(
                "invocation_deadline_elapsed",
                "the invocation deadline elapsed before the effect boundary",
            ));
        }
        Ok(())
    }
}

pub trait CandidateWorkspacePort: Send + Sync {
    fn open_workspace(
        &self,
        request: &OpenWorkspaceRequest,
        control: &InvocationControl,
    ) -> Result<CandidateWorkspaceSnapshot, ServiceFailure>;

    fn snapshot_workspace(
        &self,
        request: &SnapshotWorkspaceRequest,
        control: &InvocationControl,
    ) -> Result<CandidateWorkspaceSnapshot, ServiceFailure>;

    fn patch_workspace(
        &self,
        request: &PatchWorkspaceRequest,
        control: &InvocationControl,
    ) -> Result<MaterializedCandidatePatchset, ServiceFailure>;
}

pub trait BuildPackagingPort: Send + Sync {
    fn build_candidate(
        &self,
        request: &BuildCandidateRequest,
        control: &InvocationControl,
    ) -> Result<CandidateBuild, ServiceFailure>;

    fn publish_package(
        &self,
        request: &PublishPackageRequest,
        control: &InvocationControl,
    ) -> Result<PackageArtifact, ServiceFailure>;

    fn verify_package(
        &self,
        request: &VerifyPackageRequest,
        control: &InvocationControl,
    ) -> Result<PackageVerification, ServiceFailure>;

    fn load_package_bytes(
        &self,
        scope_id: &str,
        package_digest: &ContentDigest,
        control: &InvocationControl,
    ) -> Result<Vec<u8>, ServiceFailure>;
}

pub trait ValidationReviewPort: Send + Sync {
    fn prove_package(
        &self,
        request: &ProvePackageRequest,
        control: &InvocationControl,
    ) -> Result<ProvingRecord, ServiceFailure>;

    fn compare_proving(
        &self,
        request: &CompareProvingRequest,
        control: &InvocationControl,
    ) -> Result<ComparisonRecord, ServiceFailure>;

    fn review_candidate(
        &self,
        request: &ReviewCandidateRequest,
        control: &InvocationControl,
    ) -> Result<CandidateReviewRecord, ServiceFailure>;
}

pub trait DeploymentRollbackPort: Send + Sync {
    fn initialize(
        &self,
        request: &InitializeDeploymentRequest,
        control: &InvocationControl,
    ) -> Result<InitializationRecord, ServiceFailure>;

    fn activate(
        &self,
        request: &ActivateDeploymentRequest,
        control: &InvocationControl,
    ) -> Result<ActivationRecord, ServiceFailure>;

    fn observe(
        &self,
        request: &ObserveDeploymentRequest,
        control: &InvocationControl,
    ) -> Result<ObservationRecord, ServiceFailure>;

    fn rollback(
        &self,
        request: &RollbackDeploymentRequest,
        control: &InvocationControl,
    ) -> Result<RollbackRecord, ServiceFailure>;

    fn inspect(
        &self,
        request: &InspectOperationsRequest,
        control: &InvocationControl,
    ) -> Result<OperationsSnapshot, ServiceFailure>;
}

pub trait EvidencePublicationPort: Send + Sync {
    fn publish(
        &self,
        request: &PublishEvidenceRequest,
        control: &InvocationControl,
    ) -> Result<EvidenceRecord, ServiceFailure>;

    fn resolve(
        &self,
        request: &ResolveEvidenceRequest,
        control: &InvocationControl,
    ) -> Result<ResolvedEvidence, ServiceFailure>;
}

pub trait BoundedCommandPort: Send + Sync {
    fn execute(
        &self,
        request: &ExecuteCommandRequest,
        control: &InvocationControl,
    ) -> Result<BoundedCommandReceipt, ServiceFailure>;
}

pub trait SchedulingPort: Send + Sync {
    fn schedule(
        &self,
        request: &ScheduleJobRequest,
        control: &InvocationControl,
    ) -> Result<ScheduleReceipt, ServiceFailure>;
}

/// Effect owner for the generic, opaque factory-evolution boundary.
///
/// The operation is explicit so one backend can enforce domain-specific
/// semantics without widening M3's wire schema. M3 validates the digest-bound
/// request and result before committing a successful receipt.
pub trait FactoryEvolutionPort: Send + Sync {
    fn apply_factory_effect(
        &self,
        operation: CapabilityOperation,
        request: &FactoryEffectRequest,
        control: &InvocationControl,
    ) -> Result<FactoryEffectResult, ServiceFailure>;
}

pub struct CapabilityServiceDependencies {
    pub workspace: Option<Arc<dyn CandidateWorkspacePort>>,
    pub build_packaging: Option<Arc<dyn BuildPackagingPort>>,
    pub validation_review: Option<Arc<dyn ValidationReviewPort>>,
    pub deployment: Option<Arc<dyn DeploymentRollbackPort>>,
    pub evidence: Option<Arc<dyn EvidencePublicationPort>>,
    pub command: Option<Arc<dyn BoundedCommandPort>>,
    pub scheduling: Option<Arc<dyn SchedulingPort>>,
    pub factory_evolution: Option<Arc<dyn FactoryEvolutionPort>>,
    /// Explicit operational outages. Descriptors remain registered so callers
    /// receive durable `Unavailable` receipts instead of an unknown-service
    /// transport error or a success-shaped fallback.
    pub unavailable_service_ids: BTreeSet<String>,
    pub clock: Arc<dyn ClockPort>,
}

impl CapabilityServiceDependencies {
    pub fn empty() -> Self {
        Self {
            workspace: None,
            build_packaging: None,
            validation_review: None,
            deployment: None,
            evidence: None,
            command: None,
            scheduling: None,
            factory_evolution: None,
            unavailable_service_ids: BTreeSet::new(),
            clock: Arc::new(SystemClock),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandLimits {
    pub timeout_ms: u64,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub max_argument_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandPolicy {
    pub max_timeout_ms: u64,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub max_argument_bytes: usize,
    pub max_arguments: usize,
    pub poll_interval_ms: u64,
}

impl Default for CommandPolicy {
    fn default() -> Self {
        Self {
            max_timeout_ms: 30_000,
            max_stdout_bytes: 256 * 1024,
            max_stderr_bytes: 256 * 1024,
            max_argument_bytes: 64 * 1024,
            max_arguments: 128,
            poll_interval_ms: 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedCommand {
    pub command_id: String,
    pub executable: PathBuf,
    pub executable_digest: ContentDigest,
    pub fixed_arguments: Vec<String>,
    pub accepts_request_arguments: bool,
}

impl AllowedCommand {
    pub fn inspect(
        command_id: impl Into<String>,
        executable: impl AsRef<Path>,
        fixed_arguments: Vec<String>,
        accepts_request_arguments: bool,
    ) -> Result<Self, CapabilityHostError> {
        let command_id = command_id.into();
        validate_nonblank("command_id", &command_id)?;
        let executable = executable.as_ref();
        if !executable.is_absolute() {
            return Err(CapabilityHostError::InvalidConfiguration(format!(
                "allowlisted executable '{}' must be absolute",
                executable.display()
            )));
        }
        let metadata = fs::symlink_metadata(executable)
            .map_err(|source| CapabilityHostError::io(executable, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CapabilityHostError::UnsafePath {
                path: executable.to_path_buf(),
                reason: "allowlisted executable must be a regular non-symlink file",
            });
        }
        if metadata.len() > MAX_EXECUTABLE_IDENTITY_BYTES {
            return Err(CapabilityHostError::InvalidConfiguration(format!(
                "allowlisted executable '{}' exceeds the {} byte identity limit",
                executable.display(),
                MAX_EXECUTABLE_IDENTITY_BYTES
            )));
        }
        let canonical = fs::canonicalize(executable)
            .map_err(|source| CapabilityHostError::io(executable, source))?;
        let executable_digest = digest_file_streaming(&canonical)?;
        Ok(Self {
            command_id,
            executable: canonical,
            executable_digest,
            fixed_arguments,
            accepts_request_arguments,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandTerminalStatus {
    ExitedZero,
    ExitedNonzero,
    TimedOut,
    Cancelled,
    OutputLimitExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedCommandStream {
    pub captured_bytes: Vec<u8>,
    pub captured_digest: ContentDigest,
    pub total_bytes: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedCommandReceipt {
    pub command_id: String,
    pub executable_digest: ContentDigest,
    pub arguments_digest: ContentDigest,
    pub working_directory_ref: String,
    pub status: CommandTerminalStatus,
    pub exit_code: Option<i32>,
    pub stdout: CapturedCommandStream,
    pub stderr: CapturedCommandStream,
    pub elapsed_ms: u64,
    pub receipt_digest: ContentDigest,
}

#[derive(Debug)]
pub struct LocalBoundedCommandExecutor {
    scope_id: String,
    workspaces_root: PathBuf,
    allowlist: BTreeMap<String, AllowedCommand>,
    policy: CommandPolicy,
}

impl LocalBoundedCommandExecutor {
    pub fn new(
        scope_id: impl Into<String>,
        workspaces_root: impl AsRef<Path>,
        commands: impl IntoIterator<Item = AllowedCommand>,
        policy: CommandPolicy,
    ) -> Result<Self, CapabilityHostError> {
        let scope_id = scope_id.into();
        validate_nonblank("scope_id", &scope_id)?;
        validate_command_policy(&policy)?;
        let workspaces_root = secure_existing_directory(workspaces_root.as_ref())?;
        let mut allowlist = BTreeMap::new();
        for command in commands {
            let fixed_argument_bytes = command
                .fixed_arguments
                .iter()
                .map(String::len)
                .try_fold(0usize, |total, length| total.checked_add(length))
                .ok_or_else(|| {
                    CapabilityHostError::InvalidConfiguration(
                        "fixed command argument byte count overflowed".to_string(),
                    )
                })?;
            if command.fixed_arguments.len() > policy.max_arguments
                || fixed_argument_bytes > policy.max_argument_bytes
            {
                return Err(CapabilityHostError::InvalidConfiguration(format!(
                    "allowlisted command '{}' fixed arguments exceed command policy",
                    command.command_id
                )));
            }
            if allowlist
                .insert(command.command_id.clone(), command)
                .is_some()
            {
                return Err(CapabilityHostError::InvalidConfiguration(
                    "duplicate allowlisted command id".to_string(),
                ));
            }
        }
        if allowlist.is_empty() {
            return Err(CapabilityHostError::InvalidConfiguration(
                "bounded command executor requires a nonempty allowlist".to_string(),
            ));
        }
        Ok(Self {
            scope_id,
            workspaces_root,
            allowlist,
            policy,
        })
    }

    fn resolve_working_directory(
        &self,
        request: &ExecuteCommandRequest,
    ) -> Result<PathBuf, ServiceFailure> {
        require_scope(&self.scope_id, &request.workspace.scope_id)?;
        validate_safe_component("workspace_id", &request.workspace.workspace_id)
            .map_err(host_error_as_failure)?;
        let mut path = self.workspaces_root.join(&request.workspace.workspace_id);
        for component in request.relative_working_directory.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(segment) if segment.to_str().is_some() => path.push(segment),
                _ => {
                    return Err(ServiceFailure::failed(
                        "unsafe_working_directory",
                        "command working directory contains traversal, a prefix, or non-UTF-8 data",
                    ));
                }
            }
        }
        let mut inspected = self.workspaces_root.clone();
        let relative = path.strip_prefix(&self.workspaces_root).map_err(|_| {
            ServiceFailure::failed(
                "working_directory_escape",
                "command working directory escapes the configured workspace root",
            )
        })?;
        for component in relative.components() {
            let Component::Normal(segment) = component else {
                continue;
            };
            inspected.push(segment);
            let metadata = fs::symlink_metadata(&inspected).map_err(|source| {
                ServiceFailure::failed(
                    "working_directory_unavailable",
                    format!("cannot inspect '{}': {source}", inspected.display()),
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(ServiceFailure::failed(
                    "working_directory_symlink",
                    format!(
                        "working directory traverses symlink '{}'",
                        inspected.display()
                    ),
                ));
            }
        }
        let canonical = fs::canonicalize(&path).map_err(|source| {
            ServiceFailure::failed(
                "working_directory_unavailable",
                format!("cannot canonicalize '{}': {source}", path.display()),
            )
        })?;
        if !canonical.starts_with(&self.workspaces_root) {
            return Err(ServiceFailure::failed(
                "working_directory_escape",
                "command working directory escapes the configured workspace root",
            ));
        }
        Ok(canonical)
    }
}

impl BoundedCommandPort for LocalBoundedCommandExecutor {
    fn execute(
        &self,
        request: &ExecuteCommandRequest,
        control: &InvocationControl,
    ) -> Result<BoundedCommandReceipt, ServiceFailure> {
        control.check()?;
        validate_command_limits(&request.limits, &self.policy)?;
        let descriptor = self.allowlist.get(&request.command_id).ok_or_else(|| {
            ServiceFailure::unsupported(
                "command_not_allowlisted",
                format!("command '{}' is not allowlisted", request.command_id),
            )
        })?;
        let executable_metadata =
            fs::symlink_metadata(&descriptor.executable).map_err(|source| {
                ServiceFailure::unavailable(
                    "command_executable_unavailable",
                    format!(
                        "cannot inspect allowlisted executable '{}': {source}",
                        descriptor.executable.display()
                    ),
                )
            })?;
        if executable_metadata.file_type().is_symlink() || !executable_metadata.is_file() {
            return Err(ServiceFailure::unavailable(
                "command_executable_replaced",
                "allowlisted executable is no longer a regular non-symlink file",
            ));
        }
        let actual_executable_digest =
            digest_file_streaming(&descriptor.executable).map_err(host_error_as_failure)?;
        if actual_executable_digest != descriptor.executable_digest {
            return Err(ServiceFailure::unavailable(
                "command_executable_identity_changed",
                format!(
                    "allowlisted executable identity changed from {} to {}",
                    descriptor.executable_digest, actual_executable_digest
                ),
            ));
        }
        if !descriptor.accepts_request_arguments && !request.arguments.is_empty() {
            return Err(ServiceFailure::unsupported(
                "command_arguments_unsupported",
                format!(
                    "allowlisted command '{}' does not accept request arguments",
                    request.command_id
                ),
            ));
        }
        if request.arguments.len() > self.policy.max_arguments {
            return Err(ServiceFailure::resource_exhausted(
                "argument_count_exceeded",
                format!(
                    "command supplied {} arguments; limit is {}",
                    request.arguments.len(),
                    self.policy.max_arguments
                ),
            ));
        }
        let argument_bytes = descriptor
            .fixed_arguments
            .iter()
            .chain(&request.arguments)
            .map(|argument| argument.len())
            .try_fold(0usize, |total, length| total.checked_add(length))
            .ok_or_else(|| {
                ServiceFailure::resource_exhausted(
                    "argument_bytes_overflow",
                    "command argument byte count overflowed",
                )
            })?;
        if argument_bytes > request.limits.max_argument_bytes {
            return Err(ServiceFailure::resource_exhausted(
                "argument_bytes_exceeded",
                format!(
                    "command arguments use {argument_bytes} bytes; request limit is {}",
                    request.limits.max_argument_bytes
                ),
            ));
        }
        let working_directory = self.resolve_working_directory(request)?;
        let arguments = descriptor
            .fixed_arguments
            .iter()
            .chain(&request.arguments)
            .cloned()
            .collect::<Vec<_>>();
        let arguments_digest = digest_json_content(&arguments).map_err(|error| {
            ServiceFailure::failed("arguments_digest_failed", error.to_string())
        })?;

        let mut command = Command::new(&descriptor.executable);
        command
            .args(&arguments)
            .current_dir(&working_directory)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let mut child = command.spawn().map_err(|source| {
            ServiceFailure::unavailable(
                "command_spawn_failed",
                format!(
                    "failed to spawn allowlisted executable '{}': {source}",
                    descriptor.executable.display()
                ),
            )
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ServiceFailure::failed(
                "stdout_pipe_missing",
                "spawned command did not provide a stdout pipe",
            )
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            ServiceFailure::failed(
                "stderr_pipe_missing",
                "spawned command did not provide a stderr pipe",
            )
        })?;
        let stdout_limit = request.limits.max_stdout_bytes;
        let stderr_limit = request.limits.max_stderr_bytes;
        let stdout_reader = thread::spawn(move || capture_stream(stdout, stdout_limit));
        let stderr_reader = thread::spawn(move || capture_stream(stderr, stderr_limit));

        let timeout = Duration::from_millis(request.limits.timeout_ms);
        let poll = Duration::from_millis(self.policy.poll_interval_ms);
        let mut terminal = None;
        while terminal.is_none() {
            if control.is_cancelled() {
                let _ = child.kill();
                let status = child.wait().ok();
                terminal = Some((CommandTerminalStatus::Cancelled, status));
                break;
            }
            if started.elapsed() >= timeout || control.clock.now_ms() >= control.deadline_at_ms {
                let _ = child.kill();
                let status = child.wait().ok();
                terminal = Some((CommandTerminalStatus::TimedOut, status));
                break;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    terminal = Some((
                        if status.success() {
                            CommandTerminalStatus::ExitedZero
                        } else {
                            CommandTerminalStatus::ExitedNonzero
                        },
                        Some(status),
                    ));
                }
                Ok(None) => thread::sleep(poll),
                Err(source) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ServiceFailure::failed(
                        "command_wait_failed",
                        format!("failed while waiting for command: {source}"),
                    ));
                }
            }
        }
        let (mut status, exit_status) = terminal.expect("terminal command status");
        let stdout = join_capture(stdout_reader, "stdout")?;
        let stderr = join_capture(stderr_reader, "stderr")?;
        if matches!(
            status,
            CommandTerminalStatus::ExitedZero | CommandTerminalStatus::ExitedNonzero
        ) && (stdout.truncated || stderr.truncated)
        {
            status = CommandTerminalStatus::OutputLimitExceeded;
        }
        let elapsed_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let mut receipt = BoundedCommandReceipt {
            command_id: request.command_id.clone(),
            executable_digest: descriptor.executable_digest.clone(),
            arguments_digest,
            working_directory_ref: format!(
                "{}/{}",
                request.workspace.workspace_id,
                request.relative_working_directory.display()
            ),
            status,
            exit_code: exit_status.and_then(exit_code),
            stdout,
            stderr,
            elapsed_ms,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.receipt_digest = command_receipt_digest(&receipt)?;
        Ok(receipt)
    }
}

#[derive(Clone, Debug, Default)]
pub struct UnsupportedSchedulingPort;

impl SchedulingPort for UnsupportedSchedulingPort {
    fn schedule(
        &self,
        _request: &ScheduleJobRequest,
        _control: &InvocationControl,
    ) -> Result<ScheduleReceipt, ServiceFailure> {
        Err(ServiceFailure::unsupported(
            "m2_scheduler_not_injected",
            "scheduling requires an injected M2 durable executor",
        ))
    }
}

pub struct CapabilityServiceHost {
    root: PathBuf,
    descriptors: BTreeMap<String, CapabilityServiceDescriptor>,
    dependencies: CapabilityServiceDependencies,
    state: Mutex<CapabilityHostState>,
}

impl CapabilityServiceHost {
    pub fn open(
        root: impl AsRef<Path>,
        descriptors: impl IntoIterator<Item = CapabilityServiceDescriptor>,
        dependencies: CapabilityServiceDependencies,
    ) -> Result<Self, CapabilityHostError> {
        let root = secure_create_root(root.as_ref())?;
        ensure_owned_directory(&root, HOST_INPUT_DIRECTORY)?;
        ensure_owned_directory(&root, HOST_OUTPUT_DIRECTORY)?;
        ensure_owned_directory(&root, HOST_RECEIPT_DIRECTORY)?;
        let state_path = root.join(HOST_STATE_FILE);
        reject_symlink_if_present(&state_path)?;

        let mut descriptor_map = BTreeMap::new();
        for descriptor in descriptors {
            if descriptor_map
                .insert(descriptor.service_id.clone(), descriptor)
                .is_some()
            {
                return Err(CapabilityHostError::InvalidConfiguration(
                    "duplicate capability service id".to_string(),
                ));
            }
        }
        if descriptor_map.is_empty() {
            return Err(CapabilityHostError::InvalidConfiguration(
                "capability host requires at least one service descriptor".to_string(),
            ));
        }
        let configuration_digest = digest_json_content(&descriptor_map)
            .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
        let now = dependencies.clock.now_ms();
        let mut state = if state_path.exists() {
            let state = read_json::<CapabilityHostState>(&state_path)?;
            validate_host_state(&state)?;
            if state.configuration_digest != configuration_digest {
                return Err(CapabilityHostError::ConfigurationMismatch {
                    expected: state.configuration_digest,
                    actual: configuration_digest,
                });
            }
            state
        } else {
            CapabilityHostState {
                schema_version: CAPABILITY_HOST_STATE_SCHEMA_VERSION,
                configuration_digest: configuration_digest.clone(),
                health: descriptor_map
                    .values()
                    .map(|descriptor| {
                        (
                            descriptor.service_id.clone(),
                            initial_health(descriptor, &dependencies, now),
                        )
                    })
                    .collect(),
                invocations: Vec::new(),
            }
        };
        for descriptor in descriptor_map.values() {
            let availability = descriptor_availability(descriptor, &dependencies);
            let health = state
                .health
                .entry(descriptor.service_id.clone())
                .or_insert_with(|| initial_health(descriptor, &dependencies, now));
            health.availability = availability;
            if health.lifecycle != ServiceLifecycleState::Invoking {
                health.lifecycle = match availability {
                    ServiceAvailability::Available => ServiceLifecycleState::Ready,
                    ServiceAvailability::Degraded => ServiceLifecycleState::Degraded,
                    ServiceAvailability::Unavailable => ServiceLifecycleState::Unavailable,
                };
            }
            health.updated_at_ms = now;
        }
        let host = Self {
            root,
            descriptors: descriptor_map,
            dependencies,
            state: Mutex::new(state),
        };
        host.reconcile_interrupted_invocations()?;
        host.persist_state()?;
        let receipts = host
            .lock_state()?
            .invocations
            .iter()
            .filter_map(|entry| entry.receipt.clone())
            .collect::<Vec<_>>();
        for receipt in &receipts {
            host.verify_durable_receipt(receipt)?;
        }
        Ok(host)
    }

    pub fn invoke(
        &self,
        invocation: &CapabilityInvocation,
        cancellation: CancellationToken,
    ) -> Result<InvocationReceipt, CapabilityHostError> {
        invocation.identity.validate()?;
        invocation.budget.validate()?;
        let descriptor = self
            .descriptors
            .get(&invocation.identity.service_id)
            .ok_or_else(|| CapabilityHostError::UnknownService {
                service_id: invocation.identity.service_id.clone(),
            })?
            .clone();
        let input_bytes = serde_json::to_vec(invocation)
            .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
        if input_bytes.len() > invocation.budget.max_request_bytes
            || input_bytes.len() > MAX_INVOCATION_INPUT_BYTES
        {
            return Err(CapabilityHostError::RequestTooLarge {
                actual: input_bytes.len(),
                limit: invocation
                    .budget
                    .max_request_bytes
                    .min(MAX_INVOCATION_INPUT_BYTES),
            });
        }
        let input_digest = ContentDigest::from_bytes(&input_bytes);
        // Publish immutable input bytes before the journal claims an in-flight
        // invocation. A crash may leave an unreferenced blob, but never a
        // journal entry whose provenance was never durable.
        self.persist_content(HOST_INPUT_DIRECTORY, &input_digest, &input_bytes)?;

        {
            let mut state = self.lock_state()?;
            if let Some(existing) = state.invocations.iter().find(|entry| {
                entry.identity.service_id == invocation.identity.service_id
                    && entry.identity.idempotency_key == invocation.identity.idempotency_key
            }) {
                if existing.input_digest != input_digest {
                    return Err(CapabilityHostError::IdempotencyConflict {
                        service_id: invocation.identity.service_id.clone(),
                        idempotency_key: invocation.identity.idempotency_key.clone(),
                    });
                }
                let receipt = existing.receipt.clone().ok_or_else(|| {
                    CapabilityHostError::InvocationInFlight {
                        invocation_id: existing.identity.invocation_id.clone(),
                    }
                })?;
                drop(state);
                self.verify_durable_receipt(&receipt)?;
                return Ok(receipt);
            }
            if state.invocations.len() >= MAX_INVOCATION_JOURNAL_ENTRIES {
                return Err(CapabilityHostError::JournalFull {
                    limit: MAX_INVOCATION_JOURNAL_ENTRIES,
                });
            }
            if state
                .invocations
                .iter()
                .any(|entry| entry.identity.invocation_id == invocation.identity.invocation_id)
            {
                return Err(CapabilityHostError::InvocationIdConflict {
                    invocation_id: invocation.identity.invocation_id.clone(),
                });
            }
            let started_at_ms = self.dependencies.clock.now_ms();
            state.invocations.push(DurableInvocation {
                identity: invocation.identity.clone(),
                family: descriptor.family,
                operation: invocation.request.operation(),
                input_digest: input_digest.clone(),
                started_at_ms,
                receipt: None,
            });
            let health = state
                .health
                .get_mut(&descriptor.service_id)
                .ok_or_else(|| {
                    CapabilityHostError::CorruptState(format!(
                        "missing health record for service '{}'",
                        descriptor.service_id
                    ))
                })?;
            health.lifecycle = ServiceLifecycleState::Invoking;
            health.last_invocation_id = Some(invocation.identity.invocation_id.clone());
            health.updated_at_ms = started_at_ms;
            write_host_state(&self.root, &state)?;
        }

        let started_at_ms = {
            let state = self.lock_state()?;
            state
                .invocations
                .iter()
                .find(|entry| entry.identity.invocation_id == invocation.identity.invocation_id)
                .map(|entry| entry.started_at_ms)
                .ok_or_else(|| {
                    CapabilityHostError::CorruptState(
                        "started invocation disappeared from the journal".to_string(),
                    )
                })?
        };
        let control = InvocationControl::new(
            started_at_ms,
            invocation.budget.timeout_ms,
            self.dependencies.clock.clone(),
            cancellation,
        );
        let outcome = match self.authorize_and_route(&descriptor, invocation, &control) {
            Ok(result) => InvocationOutcome::Succeeded { result },
            Err(failure) => InvocationOutcome::Terminal { failure },
        };
        let finished_at_ms = self.dependencies.clock.now_ms();
        let output_bytes = serde_json::to_vec(&outcome)
            .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
        let output_digest = ContentDigest::from_bytes(&output_bytes);
        self.persist_content(HOST_OUTPUT_DIRECTORY, &output_digest, &output_bytes)?;
        let provenance = InvocationProvenance {
            input_ref: content_ref(HOST_INPUT_DIRECTORY, &input_digest, "json"),
            output_ref: content_ref(HOST_OUTPUT_DIRECTORY, &output_digest, "json"),
            receipt_ref: String::new(),
        };
        let mut receipt = InvocationReceipt {
            schema: CAPABILITY_RECEIPT_SCHEMA.to_string(),
            invocation_id: invocation.identity.invocation_id.clone(),
            idempotency_key: invocation.identity.idempotency_key.clone(),
            service_id: descriptor.service_id.clone(),
            family: descriptor.family,
            operation: invocation.request.operation(),
            scope_id: invocation.identity.scope_id.clone(),
            implementation_id: descriptor.implementation_id.clone(),
            implementation_digest: descriptor.implementation_digest.clone(),
            input_digest,
            output_digest,
            started_at_ms,
            finished_at_ms,
            outcome,
            provenance,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt_digest(&receipt)?;
        receipt.provenance.receipt_ref =
            content_ref(HOST_RECEIPT_DIRECTORY, &receipt.receipt_digest, "json");
        // The receipt reference is excluded from the digest because its file
        // name is itself the digest. Re-derive after setting it to prove that
        // this intentional exclusion remains stable.
        receipt.receipt_digest = receipt_digest(&receipt)?;
        let receipt_bytes = serde_json::to_vec_pretty(&receipt)
            .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
        self.persist_named_content(
            HOST_RECEIPT_DIRECTORY,
            &receipt.receipt_digest,
            &receipt_bytes,
        )?;

        {
            let mut state = self.lock_state()?;
            let entry = state
                .invocations
                .iter_mut()
                .find(|entry| entry.identity.invocation_id == invocation.identity.invocation_id)
                .ok_or_else(|| {
                    CapabilityHostError::CorruptState(
                        "started invocation disappeared before commit".to_string(),
                    )
                })?;
            entry.receipt = Some(receipt.clone());
            update_health_after_receipt(&mut state, &descriptor, &receipt, finished_at_ms)?;
            write_host_state(&self.root, &state)?;
        }
        self.verify_durable_receipt(&receipt)?;
        Ok(receipt)
    }

    pub fn health(&self, service_id: &str) -> Result<ServiceHealth, CapabilityHostError> {
        self.lock_state()?
            .health
            .get(service_id)
            .cloned()
            .ok_or_else(|| CapabilityHostError::UnknownService {
                service_id: service_id.to_string(),
            })
    }

    pub fn receipt(&self, invocation_id: &str) -> Result<InvocationReceipt, CapabilityHostError> {
        let receipt = self
            .lock_state()?
            .invocations
            .iter()
            .find(|entry| entry.identity.invocation_id == invocation_id)
            .and_then(|entry| entry.receipt.clone())
            .ok_or_else(|| CapabilityHostError::ReceiptNotFound {
                invocation_id: invocation_id.to_string(),
            })?;
        self.verify_durable_receipt(&receipt)?;
        Ok(receipt)
    }

    /// Reload the exact typed input for one terminal invocation.
    ///
    /// Recovery is deliberately receipt-led: an in-flight journal entry is
    /// not sufficient authority to replay work. The content-addressed bytes
    /// must still match the terminal receipt, deserialize to the canonical
    /// invocation encoding, and agree with every receipt identity that can be
    /// derived from the input.
    pub fn invocation_input(
        &self,
        invocation_id: &str,
    ) -> Result<CapabilityInvocation, CapabilityHostError> {
        let receipt = self.receipt(invocation_id)?;
        let input_path = self.root.join(&receipt.provenance.input_ref);
        let input_bytes = read_regular_file(&input_path)?;
        let actual_digest = ContentDigest::from_bytes(&input_bytes);
        if actual_digest != receipt.input_digest {
            return Err(CapabilityHostError::CorruptState(format!(
                "invocation '{}' input bytes are {actual_digest}, expected {}",
                receipt.invocation_id, receipt.input_digest
            )));
        }
        if input_bytes.len() > MAX_INVOCATION_INPUT_BYTES {
            return Err(CapabilityHostError::CorruptState(format!(
                "invocation '{}' input exceeds the durable request bound",
                receipt.invocation_id
            )));
        }
        let invocation = serde_json::from_slice::<CapabilityInvocation>(&input_bytes)
            .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
        invocation.identity.validate()?;
        invocation.budget.validate()?;
        let canonical_bytes = serde_json::to_vec(&invocation)
            .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
        if canonical_bytes != input_bytes {
            return Err(CapabilityHostError::CorruptState(format!(
                "invocation '{}' input bytes are not the canonical persisted encoding",
                receipt.invocation_id
            )));
        }
        if invocation.identity.invocation_id != receipt.invocation_id
            || invocation.identity.idempotency_key != receipt.idempotency_key
            || invocation.identity.service_id != receipt.service_id
            || invocation.identity.scope_id != receipt.scope_id
            || invocation.request.scope_id() != receipt.scope_id
            || invocation.request.operation() != receipt.operation
            || invocation.request.operation().family() != receipt.family
        {
            return Err(CapabilityHostError::CorruptState(format!(
                "invocation '{}' input does not match its terminal receipt",
                receipt.invocation_id
            )));
        }
        Ok(invocation)
    }

    pub fn attest(
        &self,
        invocation_id: &str,
    ) -> Result<ServiceInvocationAttestation, CapabilityHostError> {
        let receipt = self.receipt(invocation_id)?;
        let attestation_id = format!("attestation:{}", receipt.receipt_digest.file_stem());
        let mut attestation = ServiceInvocationAttestation {
            schema: CAPABILITY_ATTESTATION_SCHEMA.to_string(),
            attestation_id,
            invocation_id: receipt.invocation_id.clone(),
            service_id: receipt.service_id.clone(),
            family: receipt.family,
            operation: receipt.operation,
            scope_id: receipt.scope_id.clone(),
            implementation_digest: receipt.implementation_digest.clone(),
            input_digest: receipt.input_digest.clone(),
            output_digest: receipt.output_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            terminal_success: receipt.outcome.is_success(),
            failure_kind: receipt.outcome.failure_kind(),
            provenance: receipt.provenance.clone(),
            attestation_digest: ContentDigest::from_bytes(&[]),
        };
        attestation.attestation_digest =
            digest_json_content(&AttestationDigestMaterial::from(&attestation))
                .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
        Ok(attestation)
    }

    pub fn stop(&self) -> Result<(), CapabilityHostError> {
        let now = self.dependencies.clock.now_ms();
        let mut state = self.lock_state()?;
        for health in state.health.values_mut() {
            health.lifecycle = ServiceLifecycleState::Stopped;
            health.updated_at_ms = now;
        }
        write_host_state(&self.root, &state)
    }

    fn authorize_and_route(
        &self,
        descriptor: &CapabilityServiceDescriptor,
        invocation: &CapabilityInvocation,
        control: &InvocationControl,
    ) -> Result<CapabilitySuccess, ServiceFailure> {
        control.check()?;
        if self
            .dependencies
            .unavailable_service_ids
            .contains(descriptor.service_id())
        {
            return Err(ServiceFailure::unavailable(
                "service_configured_unavailable",
                format!(
                    "service '{}' is registered but its effect owner is unavailable",
                    descriptor.service_id()
                ),
            ));
        }
        let operation = invocation.request.operation();
        if invocation.identity.scope_id != descriptor.scope_id
            || invocation.request.scope_id() != descriptor.scope_id
            || invocation.identity.scope_id != invocation.request.scope_id()
        {
            return Err(ServiceFailure::new(
                ServiceFailureKind::ScopeDenied,
                "capability_scope_mismatch",
                format!(
                    "service scope '{}', invocation scope '{}', and request scope '{}' must match",
                    descriptor.scope_id,
                    invocation.identity.scope_id,
                    invocation.request.scope_id()
                ),
            ));
        }
        if operation.family() != descriptor.family {
            return Err(ServiceFailure::unsupported(
                "service_family_mismatch",
                format!(
                    "operation '{operation:?}' belongs to '{:?}', not service family '{:?}'",
                    operation.family(),
                    descriptor.family
                ),
            ));
        }
        if invocation.identity.authority < descriptor.required_authority
            || invocation.identity.authority < operation.minimum_authority()
        {
            return Err(ServiceFailure::new(
                ServiceFailureKind::ScopeDenied,
                "authority_insufficient",
                format!(
                    "authority '{:?}' is below service or operation requirement",
                    invocation.identity.authority
                ),
            ));
        }
        if !approval_satisfies(&invocation.identity.approval, &descriptor.required_approval) {
            return Err(ServiceFailure::new(
                ServiceFailureKind::ApprovalBlocked,
                "approval_not_satisfied",
                format!(
                    "operation requires '{:?}' approval",
                    descriptor.required_approval
                ),
            ));
        }
        if !descriptor.supported_operations.contains(&operation) {
            return Err(ServiceFailure::unsupported(
                "operation_not_advertised",
                format!(
                    "service '{}' does not advertise operation '{operation:?}'",
                    descriptor.service_id
                ),
            ));
        }
        self.route_request(&invocation.request, control)
    }

    fn route_request(
        &self,
        request: &CapabilityRequest,
        control: &InvocationControl,
    ) -> Result<CapabilitySuccess, ServiceFailure> {
        match request {
            CapabilityRequest::OpenWorkspace(request) => self
                .dependencies
                .workspace
                .as_ref()
                .ok_or_else(|| missing_dependency("candidate workspace"))?
                .open_workspace(request, control)
                .map(|result| CapabilitySuccess::Workspace(Box::new(result))),
            CapabilityRequest::SnapshotWorkspace(request) => self
                .dependencies
                .workspace
                .as_ref()
                .ok_or_else(|| missing_dependency("candidate workspace"))?
                .snapshot_workspace(request, control)
                .map(|result| CapabilitySuccess::Workspace(Box::new(result))),
            CapabilityRequest::PatchWorkspace(request) => self
                .dependencies
                .workspace
                .as_ref()
                .ok_or_else(|| missing_dependency("candidate workspace"))?
                .patch_workspace(request, control)
                .map(|result| CapabilitySuccess::Patchset(Box::new(result))),
            CapabilityRequest::BuildCandidate(request) => self
                .dependencies
                .build_packaging
                .as_ref()
                .ok_or_else(|| missing_dependency("build and packaging"))?
                .build_candidate(request, control)
                .map(|result| CapabilitySuccess::Build(Box::new(result))),
            CapabilityRequest::ExecuteCommand(request) => {
                let receipt = self
                    .dependencies
                    .command
                    .as_ref()
                    .ok_or_else(|| missing_dependency("bounded command"))?
                    .execute(request, control)?;
                command_success_or_failure(receipt)
            }
            CapabilityRequest::PublishPackage(request) => self
                .dependencies
                .build_packaging
                .as_ref()
                .ok_or_else(|| missing_dependency("build and packaging"))?
                .publish_package(request, control)
                .map(|result| CapabilitySuccess::Package(Box::new(result))),
            CapabilityRequest::VerifyPackage(request) => self
                .dependencies
                .build_packaging
                .as_ref()
                .ok_or_else(|| missing_dependency("build and packaging"))?
                .verify_package(request, control)
                .map(|result| CapabilitySuccess::PackageVerification(Box::new(result))),
            CapabilityRequest::ProvePackage(request) => self
                .dependencies
                .validation_review
                .as_ref()
                .ok_or_else(|| missing_dependency("validation and review"))?
                .prove_package(request, control)
                .map(|result| CapabilitySuccess::Proving(Box::new(result))),
            CapabilityRequest::CompareProving(request) => self
                .dependencies
                .validation_review
                .as_ref()
                .ok_or_else(|| missing_dependency("validation and review"))?
                .compare_proving(request, control)
                .map(|result| CapabilitySuccess::Comparison(Box::new(result))),
            CapabilityRequest::ReviewCandidate(request) => self
                .dependencies
                .validation_review
                .as_ref()
                .ok_or_else(|| missing_dependency("validation and review"))?
                .review_candidate(request, control)
                .map(|result| CapabilitySuccess::Review(Box::new(result))),
            CapabilityRequest::PublishEvidence(request) => self
                .dependencies
                .evidence
                .as_ref()
                .ok_or_else(|| missing_dependency("evidence publication"))?
                .publish(request, control)
                .map(|result| CapabilitySuccess::EvidencePublished(Box::new(result))),
            CapabilityRequest::ResolveEvidence(request) => self
                .dependencies
                .evidence
                .as_ref()
                .ok_or_else(|| missing_dependency("evidence publication"))?
                .resolve(request, control)
                .map(|result| CapabilitySuccess::EvidenceResolved(Box::new(result))),
            CapabilityRequest::ScheduleJob(request) => self
                .dependencies
                .scheduling
                .as_ref()
                .ok_or_else(|| missing_dependency("scheduling"))?
                .schedule(request, control)
                .map(|result| CapabilitySuccess::Scheduled(Box::new(result))),
            CapabilityRequest::InitializeDeployment(request) => self
                .dependencies
                .deployment
                .as_ref()
                .ok_or_else(|| missing_dependency("deployment and rollback"))?
                .initialize(request, control)
                .map(|result| CapabilitySuccess::DeploymentInitialized(Box::new(result))),
            CapabilityRequest::ActivateDeployment(request) => self
                .dependencies
                .deployment
                .as_ref()
                .ok_or_else(|| missing_dependency("deployment and rollback"))?
                .activate(request, control)
                .map(|result| CapabilitySuccess::DeploymentActivated(Box::new(result))),
            CapabilityRequest::ObserveDeployment(request) => self
                .dependencies
                .deployment
                .as_ref()
                .ok_or_else(|| missing_dependency("deployment and rollback"))?
                .observe(request, control)
                .map(|result| CapabilitySuccess::DeploymentObserved(Box::new(result))),
            CapabilityRequest::RollbackDeployment(request) => self
                .dependencies
                .deployment
                .as_ref()
                .ok_or_else(|| missing_dependency("deployment and rollback"))?
                .rollback(request, control)
                .map(|result| CapabilitySuccess::DeploymentRolledBack(Box::new(result))),
            CapabilityRequest::InspectOperations(request) => self
                .dependencies
                .deployment
                .as_ref()
                .ok_or_else(|| missing_dependency("deployment and rollback"))?
                .inspect(request, control)
                .map(|result| CapabilitySuccess::Operations(Box::new(result))),
            CapabilityRequest::FactoryExecute(effect_request)
            | CapabilityRequest::FactoryProviderProposal(effect_request)
            | CapabilityRequest::FactoryShadow(effect_request)
            | CapabilityRequest::FactoryInitialize(effect_request)
            | CapabilityRequest::FactoryStateMigrate(effect_request)
            | CapabilityRequest::FactoryActivate(effect_request)
            | CapabilityRequest::FactoryObserve(effect_request)
            | CapabilityRequest::FactoryRollback(effect_request)
            | CapabilityRequest::FactoryInspect(effect_request) => {
                self.route_factory_effect(request.operation(), effect_request, control)
            }
        }
    }

    fn route_factory_effect(
        &self,
        operation: CapabilityOperation,
        request: &FactoryEffectRequest,
        control: &InvocationControl,
    ) -> Result<CapabilitySuccess, ServiceFailure> {
        validate_factory_effect_request(request)?;
        let result = self
            .dependencies
            .factory_evolution
            .as_ref()
            .ok_or_else(|| missing_dependency("factory evolution"))?
            .apply_factory_effect(operation, request, control)?;
        validate_factory_effect_result(request, &result)?;
        Ok(CapabilitySuccess::FactoryEffect(Box::new(result)))
    }

    fn persist_content(
        &self,
        directory: &str,
        digest: &ContentDigest,
        bytes: &[u8],
    ) -> Result<(), CapabilityHostError> {
        verify_directory_anchor(&self.root.join(directory))?;
        let path = self
            .root
            .join(directory)
            .join(format!("{}.json", digest.file_stem()));
        persist_immutable(&path, bytes, digest)
    }

    fn persist_named_content(
        &self,
        directory: &str,
        digest: &ContentDigest,
        bytes: &[u8],
    ) -> Result<(), CapabilityHostError> {
        verify_directory_anchor(&self.root.join(directory))?;
        let path = self
            .root
            .join(directory)
            .join(format!("{}.json", digest.file_stem()));
        persist_named_immutable(&path, bytes)
    }

    fn verify_durable_receipt(
        &self,
        receipt: &InvocationReceipt,
    ) -> Result<(), CapabilityHostError> {
        receipt.verify_integrity()?;
        let expected_input_ref = content_ref(HOST_INPUT_DIRECTORY, &receipt.input_digest, "json");
        let expected_output_ref =
            content_ref(HOST_OUTPUT_DIRECTORY, &receipt.output_digest, "json");
        let expected_receipt_ref =
            content_ref(HOST_RECEIPT_DIRECTORY, &receipt.receipt_digest, "json");
        if receipt.provenance.input_ref != expected_input_ref
            || receipt.provenance.output_ref != expected_output_ref
            || receipt.provenance.receipt_ref != expected_receipt_ref
        {
            return Err(CapabilityHostError::CorruptState(format!(
                "receipt '{}' contains noncanonical provenance paths",
                receipt.invocation_id
            )));
        }
        let input_path = self.root.join(&receipt.provenance.input_ref);
        let output_path = self.root.join(&receipt.provenance.output_ref);
        let receipt_path = self.root.join(&receipt.provenance.receipt_ref);
        verify_content_file(&input_path, &receipt.input_digest)?;
        verify_content_file(&output_path, &receipt.output_digest)?;
        let receipt_bytes = read_regular_file(&receipt_path)?;
        let stored = serde_json::from_slice::<InvocationReceipt>(&receipt_bytes)
            .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
        if stored != *receipt {
            return Err(CapabilityHostError::CorruptState(format!(
                "receipt file for '{}' differs from journal state",
                receipt.invocation_id
            )));
        }
        Ok(())
    }

    fn reconcile_interrupted_invocations(&self) -> Result<(), CapabilityHostError> {
        let now = self.dependencies.clock.now_ms();
        let interrupted = {
            let state = self.lock_state()?;
            state
                .invocations
                .iter()
                .filter(|entry| entry.receipt.is_none())
                .map(|entry| {
                    (
                        entry.identity.invocation_id.clone(),
                        entry.identity.clone(),
                        entry.family,
                        entry.operation,
                        entry.input_digest.clone(),
                        entry.started_at_ms,
                    )
                })
                .collect::<Vec<_>>()
        };
        for (invocation_id, identity, family, operation, input_digest, started_at_ms) in interrupted
        {
            let descriptor = self.descriptors.get(&identity.service_id).ok_or_else(|| {
                CapabilityHostError::CorruptState(format!(
                    "interrupted invocation '{invocation_id}' names missing service '{}'",
                    identity.service_id
                ))
            })?;
            let outcome = InvocationOutcome::Terminal {
                failure: ServiceFailure::failed(
                    "interrupted_by_restart",
                    "the process restarted before the invocation committed a terminal result",
                ),
            };
            let output_bytes = serde_json::to_vec(&outcome)
                .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
            let output_digest = ContentDigest::from_bytes(&output_bytes);
            self.persist_content(HOST_OUTPUT_DIRECTORY, &output_digest, &output_bytes)?;
            let mut receipt = InvocationReceipt {
                schema: CAPABILITY_RECEIPT_SCHEMA.to_string(),
                invocation_id: invocation_id.clone(),
                idempotency_key: identity.idempotency_key.clone(),
                service_id: identity.service_id.clone(),
                family,
                operation,
                scope_id: identity.scope_id,
                implementation_id: descriptor.implementation_id.clone(),
                implementation_digest: descriptor.implementation_digest.clone(),
                input_digest: input_digest.clone(),
                output_digest: output_digest.clone(),
                started_at_ms,
                finished_at_ms: now,
                outcome,
                provenance: InvocationProvenance {
                    input_ref: content_ref(HOST_INPUT_DIRECTORY, &input_digest, "json"),
                    output_ref: content_ref(HOST_OUTPUT_DIRECTORY, &output_digest, "json"),
                    receipt_ref: String::new(),
                },
                receipt_digest: ContentDigest::from_bytes(&[]),
            };
            receipt.receipt_digest = receipt_digest(&receipt)?;
            receipt.provenance.receipt_ref =
                content_ref(HOST_RECEIPT_DIRECTORY, &receipt.receipt_digest, "json");
            receipt.receipt_digest = receipt_digest(&receipt)?;
            let receipt_bytes = serde_json::to_vec_pretty(&receipt)
                .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
            self.persist_named_content(
                HOST_RECEIPT_DIRECTORY,
                &receipt.receipt_digest,
                &receipt_bytes,
            )?;

            let mut state = self.lock_state()?;
            let entry = state
                .invocations
                .iter_mut()
                .find(|entry| entry.identity.invocation_id == invocation_id)
                .ok_or_else(|| {
                    CapabilityHostError::CorruptState(
                        "interrupted invocation disappeared during reconciliation".to_string(),
                    )
                })?;
            entry.receipt = Some(receipt.clone());
            update_health_after_receipt(&mut state, descriptor, &receipt, now)?;
            write_host_state(&self.root, &state)?;
        }
        Ok(())
    }

    fn persist_state(&self) -> Result<(), CapabilityHostError> {
        let state = self.lock_state()?;
        write_host_state(&self.root, &state)
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, CapabilityHostState>, CapabilityHostError> {
        self.state
            .lock()
            .map_err(|_| CapabilityHostError::StateLockPoisoned)
    }
}

#[derive(Debug)]
pub struct M1CandidateWorkspaceAdapter {
    scope_id: String,
    template_root: PathBuf,
    service: Arc<CandidateWorkspaceService>,
}

impl M1CandidateWorkspaceAdapter {
    pub fn new(
        scope_id: impl Into<String>,
        template_root: impl AsRef<Path>,
        service: Arc<CandidateWorkspaceService>,
    ) -> Result<Self, CapabilityHostError> {
        let scope_id = scope_id.into();
        validate_nonblank("scope_id", &scope_id)?;
        let template_root = secure_existing_directory(template_root.as_ref())?;
        Ok(Self {
            scope_id,
            template_root,
            service,
        })
    }
}

impl CandidateWorkspacePort for M1CandidateWorkspaceAdapter {
    fn open_workspace(
        &self,
        request: &OpenWorkspaceRequest,
        control: &InvocationControl,
    ) -> Result<CandidateWorkspaceSnapshot, ServiceFailure> {
        control.check()?;
        require_workspace_scope(&self.scope_id, &request.workspace)?;
        self.service
            .open_workspace(&request.workspace.workspace_id, &self.template_root)
            .map_err(|error| ServiceFailure::failed("workspace_open_failed", error.to_string()))
    }

    fn snapshot_workspace(
        &self,
        request: &SnapshotWorkspaceRequest,
        control: &InvocationControl,
    ) -> Result<CandidateWorkspaceSnapshot, ServiceFailure> {
        control.check()?;
        require_workspace_scope(&self.scope_id, &request.workspace)?;
        self.service
            .snapshot(&request.workspace.workspace_id)
            .map_err(|error| ServiceFailure::failed("workspace_snapshot_failed", error.to_string()))
    }

    fn patch_workspace(
        &self,
        request: &PatchWorkspaceRequest,
        control: &InvocationControl,
    ) -> Result<MaterializedCandidatePatchset, ServiceFailure> {
        control.check()?;
        require_workspace_scope(&self.scope_id, &request.workspace)?;
        let replacement = CandidateFileReplacement::new(
            COMPONENT_WAT_PATH,
            request.expected_before_digest.clone(),
            request.replacement_bytes.clone(),
        );
        self.service
            .materialize_patchset(&request.workspace.workspace_id, &[replacement])
            .map_err(|error| ServiceFailure::failed("workspace_patch_failed", error.to_string()))
    }
}

#[derive(Debug)]
pub struct LocalBuildPackagingService {
    scope_id: String,
    root: PathBuf,
    package_directory: PathBuf,
    record_directory: PathBuf,
    workspace_service: Arc<CandidateWorkspaceService>,
}

impl LocalBuildPackagingService {
    pub fn open(
        scope_id: impl Into<String>,
        root: impl AsRef<Path>,
        workspace_service: Arc<CandidateWorkspaceService>,
    ) -> Result<Self, CapabilityHostError> {
        let scope_id = scope_id.into();
        validate_nonblank("scope_id", &scope_id)?;
        let root = secure_create_root(root.as_ref())?;
        let package_directory = ensure_owned_directory(&root, "packages")?;
        let record_directory = ensure_owned_directory(&root, "package-records")?;
        Ok(Self {
            scope_id,
            root,
            package_directory,
            record_directory,
            workspace_service,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn package_path(&self, digest: &ContentDigest) -> PathBuf {
        self.package_directory
            .join(format!("{}.component", digest.file_stem()))
    }

    fn record_path(&self, digest: &ContentDigest) -> PathBuf {
        self.record_directory
            .join(format!("{}.json", digest.file_stem()))
    }

    fn load_artifact(&self, digest: &ContentDigest) -> Result<PackageArtifact, ServiceFailure> {
        verify_directory_anchor(&self.record_directory).map_err(host_error_as_failure)?;
        let path = self.record_path(digest);
        let artifact = read_json::<PackageArtifact>(&path).map_err(host_error_as_failure)?;
        if artifact.schema != PACKAGE_ARTIFACT_SCHEMA
            || artifact.scope_id != self.scope_id
            || artifact.package_digest != *digest
        {
            return Err(ServiceFailure::failed(
                "package_record_invalid",
                "stored package record is not bound to the requested scope and digest",
            ));
        }
        let expected_record_digest = package_record_digest(&artifact)?;
        if artifact.package_record_digest != expected_record_digest {
            return Err(ServiceFailure::failed(
                "package_record_corrupt",
                "stored package record digest does not match its fields",
            ));
        }
        Ok(artifact)
    }
}

impl BuildPackagingPort for LocalBuildPackagingService {
    fn build_candidate(
        &self,
        request: &BuildCandidateRequest,
        control: &InvocationControl,
    ) -> Result<CandidateBuild, ServiceFailure> {
        control.check()?;
        require_workspace_scope(&self.scope_id, &request.workspace)?;
        self.workspace_service
            .build_candidate(&request.workspace.workspace_id)
            .map_err(|error| ServiceFailure::failed("candidate_build_failed", error.to_string()))
    }

    fn publish_package(
        &self,
        request: &PublishPackageRequest,
        control: &InvocationControl,
    ) -> Result<PackageArtifact, ServiceFailure> {
        control.check()?;
        require_workspace_scope(&self.scope_id, &request.workspace)?;
        let build = self
            .workspace_service
            .build_candidate(&request.workspace.workspace_id)
            .map_err(|error| ServiceFailure::failed("candidate_build_failed", error.to_string()))?;
        if build.package_digest != request.expected_package_digest {
            return Err(ServiceFailure::failed(
                "package_digest_mismatch",
                format!(
                    "rebuilt candidate digest is {}, expected {}",
                    build.package_digest, request.expected_package_digest
                ),
            ));
        }
        if build.component.component_bytes.len() > MAX_PACKAGE_BYTES {
            return Err(ServiceFailure::resource_exhausted(
                "package_size_exceeded",
                format!(
                    "package is {} bytes; limit is {MAX_PACKAGE_BYTES}",
                    build.component.component_bytes.len()
                ),
            ));
        }
        verify_directory_anchor(&self.package_directory).map_err(host_error_as_failure)?;
        verify_directory_anchor(&self.record_directory).map_err(host_error_as_failure)?;
        let artifact_path = self.package_path(&build.package_digest);
        persist_immutable(
            &artifact_path,
            &build.component.component_bytes,
            &build.package_digest,
        )
        .map_err(host_error_as_failure)?;
        let relative_path = artifact_path
            .strip_prefix(&self.root)
            .map_err(|_| {
                ServiceFailure::failed(
                    "package_path_escape",
                    "package path escaped the configured package root",
                )
            })?
            .to_path_buf();
        let mut artifact = PackageArtifact {
            schema: PACKAGE_ARTIFACT_SCHEMA.to_string(),
            scope_id: self.scope_id.clone(),
            package_digest: build.package_digest,
            source_tree_digest: build.source_tree_digest,
            byte_len: build.component.component_bytes.len() as u64,
            artifact_relative_path: relative_path,
            build_id: build.component.build_id,
            package_record_digest: ContentDigest::from_bytes(&[]),
        };
        artifact.package_record_digest = package_record_digest(&artifact)?;
        let record_bytes = serde_json::to_vec_pretty(&artifact).map_err(|error| {
            ServiceFailure::failed("package_record_serialize_failed", error.to_string())
        })?;
        persist_named_immutable(&self.record_path(&artifact.package_digest), &record_bytes)
            .map_err(host_error_as_failure)?;
        let loaded = self.load_artifact(&artifact.package_digest)?;
        if loaded != artifact {
            return Err(ServiceFailure::failed(
                "package_record_conflict",
                "existing package record differs from reproducible package output",
            ));
        }
        Ok(artifact)
    }

    fn verify_package(
        &self,
        request: &VerifyPackageRequest,
        control: &InvocationControl,
    ) -> Result<PackageVerification, ServiceFailure> {
        control.check()?;
        require_scope(&self.scope_id, &request.scope_id)?;
        let artifact = self.load_artifact(&request.package_digest)?;
        let bytes = self.load_package_bytes(&request.scope_id, &request.package_digest, control)?;
        let engine = wasmtime::Engine::default();
        wasmtime::component::Component::new(&engine, &bytes).map_err(|error| {
            ServiceFailure::failed(
                "package_not_runnable",
                format!("stored package does not compile as a Wasmtime component: {error}"),
            )
        })?;
        let verification_digest = digest_json_content(&(
            "wasm-biotic:package-verification:v1",
            &artifact.package_digest,
            artifact.byte_len,
            true,
        ))
        .map_err(|error| {
            ServiceFailure::failed("package_verification_digest_failed", error.to_string())
        })?;
        Ok(PackageVerification {
            package_digest: artifact.package_digest,
            byte_len: artifact.byte_len,
            runnable_component: true,
            verification_digest,
        })
    }

    fn load_package_bytes(
        &self,
        scope_id: &str,
        package_digest: &ContentDigest,
        control: &InvocationControl,
    ) -> Result<Vec<u8>, ServiceFailure> {
        control.check()?;
        require_scope(&self.scope_id, scope_id)?;
        let artifact = self.load_artifact(package_digest)?;
        let path = resolve_regular_descendant(&self.root, &artifact.artifact_relative_path)
            .map_err(host_error_as_failure)?;
        let bytes = read_regular_file(&path).map_err(host_error_as_failure)?;
        let actual = ContentDigest::from_bytes(&bytes);
        if actual != *package_digest || bytes.len() as u64 != artifact.byte_len {
            return Err(ServiceFailure::failed(
                "package_content_corrupt",
                format!(
                    "stored package content is {actual} with {} bytes; expected {} with {} bytes",
                    bytes.len(),
                    package_digest,
                    artifact.byte_len
                ),
            ));
        }
        Ok(bytes)
    }
}

pub struct LocalValidationReviewService {
    scope_id: String,
    root: PathBuf,
    proving_directory: PathBuf,
    comparison_directory: PathBuf,
    review_directory: PathBuf,
    packages: Arc<dyn BuildPackagingPort>,
}

impl LocalValidationReviewService {
    pub fn open(
        scope_id: impl Into<String>,
        root: impl AsRef<Path>,
        packages: Arc<dyn BuildPackagingPort>,
    ) -> Result<Self, CapabilityHostError> {
        let scope_id = scope_id.into();
        validate_nonblank("scope_id", &scope_id)?;
        let root = secure_create_root(root.as_ref())?;
        let proving_directory = ensure_owned_directory(&root, "proving-records")?;
        let comparison_directory = ensure_owned_directory(&root, "comparison-records")?;
        let review_directory = ensure_owned_directory(&root, "review-records")?;
        Ok(Self {
            scope_id,
            root,
            proving_directory,
            comparison_directory,
            review_directory,
            packages,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn proving_path(&self, digest: &ContentDigest) -> PathBuf {
        self.proving_directory
            .join(format!("{}.json", digest.file_stem()))
    }

    fn comparison_path(&self, digest: &ContentDigest) -> PathBuf {
        self.comparison_directory
            .join(format!("{}.json", digest.file_stem()))
    }

    fn review_path(&self, digest: &ContentDigest) -> PathBuf {
        self.review_directory
            .join(format!("{}.json", digest.file_stem()))
    }

    fn load_proving(
        &self,
        suite: &ValidationSuite,
        digest: &ContentDigest,
    ) -> Result<ProvingRecord, ServiceFailure> {
        verify_directory_anchor(&self.proving_directory).map_err(host_error_as_failure)?;
        let record = read_json::<ProvingRecord>(&self.proving_path(digest))
            .map_err(host_error_as_failure)?;
        validate_proving_record(suite, &record)
            .map_err(|error| ServiceFailure::failed("proving_record_invalid", error.to_string()))?;
        if record.record_digest != *digest {
            return Err(ServiceFailure::failed(
                "proving_digest_mismatch",
                "stored proving record does not match the requested digest",
            ));
        }
        Ok(record)
    }

    fn load_comparison(&self, digest: &ContentDigest) -> Result<ComparisonRecord, ServiceFailure> {
        verify_directory_anchor(&self.comparison_directory).map_err(host_error_as_failure)?;
        let record = read_json::<ComparisonRecord>(&self.comparison_path(digest))
            .map_err(host_error_as_failure)?;
        if record.record_digest != *digest {
            return Err(ServiceFailure::failed(
                "comparison_digest_mismatch",
                "stored comparison does not match the requested digest",
            ));
        }
        Ok(record)
    }
}

impl ValidationReviewPort for LocalValidationReviewService {
    fn prove_package(
        &self,
        request: &ProvePackageRequest,
        control: &InvocationControl,
    ) -> Result<ProvingRecord, ServiceFailure> {
        control.check()?;
        require_scope(&self.scope_id, &request.scope_id)?;
        request.suite.validate().map_err(|error| {
            ServiceFailure::failed("validation_suite_invalid", error.to_string())
        })?;
        let bytes = self.packages.load_package_bytes(
            &request.scope_id,
            &request.package_digest,
            control,
        )?;
        let record = prove_component_i32(&request.suite, &bytes)
            .map_err(|error| ServiceFailure::failed("proving_failed", error.to_string()))?;
        if record.component_digest != request.package_digest {
            return Err(ServiceFailure::failed(
                "proving_package_digest_mismatch",
                "proving record is not bound to the requested package bytes",
            ));
        }
        verify_directory_anchor(&self.proving_directory).map_err(host_error_as_failure)?;
        let record_bytes = serde_json::to_vec_pretty(&record).map_err(|error| {
            ServiceFailure::failed("proving_record_serialize_failed", error.to_string())
        })?;
        persist_named_immutable(&self.proving_path(&record.record_digest), &record_bytes)
            .map_err(host_error_as_failure)?;
        let loaded = self.load_proving(&request.suite, &record.record_digest)?;
        if loaded != record {
            return Err(ServiceFailure::failed(
                "proving_record_conflict",
                "existing proving record differs from the derived record",
            ));
        }
        Ok(record)
    }

    fn compare_proving(
        &self,
        request: &CompareProvingRequest,
        control: &InvocationControl,
    ) -> Result<ComparisonRecord, ServiceFailure> {
        control.check()?;
        require_scope(&self.scope_id, &request.scope_id)?;
        let incumbent = self.load_proving(&request.suite, &request.incumbent_proving_digest)?;
        let challenger = self.load_proving(&request.suite, &request.challenger_proving_digest)?;
        let comparison = compare_proving_records(&request.suite, &incumbent, &challenger)
            .map_err(|error| ServiceFailure::failed("comparison_failed", error.to_string()))?;
        verify_directory_anchor(&self.comparison_directory).map_err(host_error_as_failure)?;
        let bytes = serde_json::to_vec_pretty(&comparison).map_err(|error| {
            ServiceFailure::failed("comparison_record_serialize_failed", error.to_string())
        })?;
        persist_named_immutable(&self.comparison_path(&comparison.record_digest), &bytes)
            .map_err(host_error_as_failure)?;
        let loaded = self.load_comparison(&comparison.record_digest)?;
        validate_comparison_record(&request.suite, &incumbent, &challenger, &loaded).map_err(
            |error| ServiceFailure::failed("comparison_record_invalid", error.to_string()),
        )?;
        if loaded != comparison {
            return Err(ServiceFailure::failed(
                "comparison_record_conflict",
                "existing comparison differs from the derived comparison",
            ));
        }
        Ok(comparison)
    }

    fn review_candidate(
        &self,
        request: &ReviewCandidateRequest,
        control: &InvocationControl,
    ) -> Result<CandidateReviewRecord, ServiceFailure> {
        control.check()?;
        require_scope(&self.scope_id, &request.scope_id)?;
        let comparison = self.load_comparison(&request.comparison_digest)?;
        let incumbent = self.load_proving(&request.suite, &comparison.incumbent_proving_digest)?;
        let challenger =
            self.load_proving(&request.suite, &comparison.challenger_proving_digest)?;
        validate_comparison_record(&request.suite, &incumbent, &challenger, &comparison).map_err(
            |error| ServiceFailure::failed("review_comparison_invalid", error.to_string()),
        )?;
        let approved = comparison.eligible_for_activation
            && comparison.decision == ComparisonDecision::ChallengerPreferred
            && challenger.summary.all_satisfied
            && comparison.summary.regressed_count == 0;
        let decision = if approved {
            ReviewDecision::Approved
        } else {
            ReviewDecision::Rejected
        };
        let rationale = if approved {
            format!(
                "independent review revalidated comparison {} and all {} challenger cases",
                comparison.record_digest, challenger.summary.case_count
            )
        } else {
            format!(
                "independent review rejected comparison {}: decision {:?}, eligible {}, regressions {}",
                comparison.record_digest,
                comparison.decision,
                comparison.eligible_for_activation,
                comparison.summary.regressed_count
            )
        };
        let mut review = CandidateReviewRecord {
            schema: REVIEW_RECORD_SCHEMA.to_string(),
            scope_id: self.scope_id.clone(),
            comparison_digest: comparison.record_digest,
            incumbent_proving_digest: incumbent.record_digest,
            challenger_proving_digest: challenger.record_digest,
            decision,
            rationale,
            review_digest: ContentDigest::from_bytes(&[]),
        };
        review.review_digest = review_record_digest(&review)?;
        verify_directory_anchor(&self.review_directory).map_err(host_error_as_failure)?;
        let bytes = serde_json::to_vec_pretty(&review).map_err(|error| {
            ServiceFailure::failed("review_record_serialize_failed", error.to_string())
        })?;
        persist_named_immutable(&self.review_path(&review.review_digest), &bytes)
            .map_err(host_error_as_failure)?;
        let loaded = read_json::<CandidateReviewRecord>(&self.review_path(&review.review_digest))
            .map_err(host_error_as_failure)?;
        if loaded != review || review_record_digest(&loaded)? != loaded.review_digest {
            return Err(ServiceFailure::failed(
                "review_record_conflict",
                "stored review differs from the independently derived review",
            ));
        }
        Ok(review)
    }
}

pub struct LocalDeploymentRollbackAdapter {
    scope_id: String,
    deployment_id: String,
    deployment: Arc<LocalDeploymentService>,
    packages: Arc<dyn BuildPackagingPort>,
    staging_directory: PathBuf,
}

impl LocalDeploymentRollbackAdapter {
    pub fn open(
        scope_id: impl Into<String>,
        deployment_id: impl Into<String>,
        deployment: Arc<LocalDeploymentService>,
        packages: Arc<dyn BuildPackagingPort>,
    ) -> Result<Self, CapabilityHostError> {
        let scope_id = scope_id.into();
        let deployment_id = deployment_id.into();
        validate_nonblank("scope_id", &scope_id)?;
        validate_safe_component("deployment_id", &deployment_id)?;
        let candidate_root = secure_existing_directory(deployment.candidate_root())?;
        let staging_directory = ensure_owned_directory(&candidate_root, "capability-packages")?;
        Ok(Self {
            scope_id,
            deployment_id,
            deployment,
            packages,
            staging_directory,
        })
    }

    fn require_deployment(&self, deployment: &ScopedDeploymentRef) -> Result<(), ServiceFailure> {
        require_scope(&self.scope_id, &deployment.scope_id)?;
        if deployment.deployment_id != self.deployment_id {
            return Err(ServiceFailure::new(
                ServiceFailureKind::ScopeDenied,
                "deployment_identity_mismatch",
                format!(
                    "deployment '{}' is outside service-owned deployment '{}'",
                    deployment.deployment_id, self.deployment_id
                ),
            ));
        }
        Ok(())
    }

    fn stage_package(
        &self,
        package_digest: &ContentDigest,
        control: &InvocationControl,
    ) -> Result<PathBuf, ServiceFailure> {
        verify_directory_anchor(&self.staging_directory).map_err(host_error_as_failure)?;
        let bytes = self
            .packages
            .load_package_bytes(&self.scope_id, package_digest, control)?;
        let path = self
            .staging_directory
            .join(format!("{}.component", package_digest.file_stem()));
        persist_immutable(&path, &bytes, package_digest).map_err(host_error_as_failure)?;
        path.strip_prefix(self.deployment.candidate_root())
            .map(Path::to_path_buf)
            .map_err(|_| {
                ServiceFailure::failed(
                    "deployment_stage_escape",
                    "staged package escaped the deployment candidate root",
                )
            })
    }
}

impl DeploymentRollbackPort for LocalDeploymentRollbackAdapter {
    fn initialize(
        &self,
        request: &InitializeDeploymentRequest,
        control: &InvocationControl,
    ) -> Result<InitializationRecord, ServiceFailure> {
        control.check()?;
        self.require_deployment(&request.deployment)?;
        let bytes = self.packages.load_package_bytes(
            &self.scope_id,
            &request.incumbent_package_digest,
            control,
        )?;
        self.deployment
            .initialize_active(&request.operation_id, &bytes)
            .map_err(|error| {
                ServiceFailure::failed("deployment_initialize_failed", error.to_string())
            })
    }

    fn activate(
        &self,
        request: &ActivateDeploymentRequest,
        control: &InvocationControl,
    ) -> Result<ActivationRecord, ServiceFailure> {
        control.check()?;
        self.require_deployment(&request.deployment)?;
        let relative = self.stage_package(&request.package_digest, control)?;
        self.deployment
            .activate(&ActivationRequest {
                operation_id: request.operation_id.clone(),
                candidate_path: relative,
                expected_candidate_digest: request.package_digest.clone(),
                expected_active_digest: request.expected_active_digest.clone(),
                approval_ref: request.approval_ref.clone(),
                comparison_ref: request.comparison_ref.clone(),
                observation_window_ref: request.observation_window_ref.clone(),
            })
            .map_err(|error| {
                ServiceFailure::failed("deployment_activation_failed", error.to_string())
            })
    }

    fn observe(
        &self,
        request: &ObserveDeploymentRequest,
        control: &InvocationControl,
    ) -> Result<ObservationRecord, ServiceFailure> {
        control.check()?;
        self.require_deployment(&request.deployment)?;
        if request.evidence_bytes.is_empty() || request.evidence_bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(ServiceFailure::resource_exhausted(
                "observation_evidence_size_invalid",
                format!("observation evidence must contain 1..={MAX_EVIDENCE_BYTES} bytes"),
            ));
        }
        self.deployment
            .record_observation(
                &ObservationRequest {
                    observation_id: request.observation_id.clone(),
                    activation_id: request.activation_id.clone(),
                    expected_active_digest: request.expected_active_digest.clone(),
                    outcome: request.outcome,
                    summary: request.summary.clone(),
                },
                &request.evidence_bytes,
            )
            .map_err(|error| {
                ServiceFailure::failed("deployment_observation_failed", error.to_string())
            })
    }

    fn rollback(
        &self,
        request: &RollbackDeploymentRequest,
        control: &InvocationControl,
    ) -> Result<RollbackRecord, ServiceFailure> {
        control.check()?;
        self.require_deployment(&request.deployment)?;
        self.deployment
            .rollback(&RollbackRequest {
                operation_id: request.operation_id.clone(),
                activation_id: request.activation_id.clone(),
                reason_ref: request.reason_ref.clone(),
            })
            .map_err(|error| {
                ServiceFailure::failed("deployment_rollback_failed", error.to_string())
            })
    }

    fn inspect(
        &self,
        request: &InspectOperationsRequest,
        control: &InvocationControl,
    ) -> Result<OperationsSnapshot, ServiceFailure> {
        control.check()?;
        self.require_deployment(&request.deployment)?;
        let state = self.deployment.state().map_err(|error| {
            ServiceFailure::failed("deployment_inspection_failed", error.to_string())
        })?;
        operations_snapshot(&self.deployment_id, &state)
    }
}

#[derive(Debug)]
pub struct LocalEvidenceStore {
    scope_id: String,
    root: PathBuf,
    payload_directory: PathBuf,
    record_directory: PathBuf,
}

impl LocalEvidenceStore {
    pub fn open(
        scope_id: impl Into<String>,
        root: impl AsRef<Path>,
    ) -> Result<Self, CapabilityHostError> {
        let scope_id = scope_id.into();
        validate_nonblank("scope_id", &scope_id)?;
        let root = secure_create_root(root.as_ref())?;
        let payload_directory = ensure_owned_directory(&root, "payloads")?;
        let record_directory = ensure_owned_directory(&root, "records")?;
        Ok(Self {
            scope_id,
            root,
            payload_directory,
            record_directory,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn record_path(&self, evidence_id: &str) -> PathBuf {
        let digest = ContentDigest::from_bytes(evidence_id.as_bytes());
        self.record_directory
            .join(format!("{}.json", digest.file_stem()))
    }

    fn payload_path(&self, digest: &ContentDigest) -> PathBuf {
        self.payload_directory
            .join(format!("{}.evidence", digest.file_stem()))
    }

    fn load_record(&self, evidence_id: &str) -> Result<EvidenceRecord, ServiceFailure> {
        verify_directory_anchor(&self.record_directory).map_err(host_error_as_failure)?;
        let record = read_json::<EvidenceRecord>(&self.record_path(evidence_id))
            .map_err(host_error_as_failure)?;
        if record.schema != EVIDENCE_RECORD_SCHEMA
            || record.scope_id != self.scope_id
            || record.evidence_id != evidence_id
            || evidence_record_digest(&record)? != record.record_digest
        {
            return Err(ServiceFailure::failed(
                "evidence_record_invalid",
                "stored evidence record is not valid for the requested identity and scope",
            ));
        }
        Ok(record)
    }
}

impl EvidencePublicationPort for LocalEvidenceStore {
    fn publish(
        &self,
        request: &PublishEvidenceRequest,
        control: &InvocationControl,
    ) -> Result<EvidenceRecord, ServiceFailure> {
        control.check()?;
        require_scope(&self.scope_id, &request.scope_id)?;
        validate_safe_identifier("evidence_id", &request.evidence_id)
            .map_err(host_error_as_failure)?;
        validate_nonblank("media_type", &request.media_type).map_err(host_error_as_failure)?;
        if request.subject_refs.is_empty()
            || request
                .subject_refs
                .iter()
                .any(|value| value.trim().is_empty())
        {
            return Err(ServiceFailure::failed(
                "evidence_subjects_invalid",
                "evidence must name at least one nonblank subject reference",
            ));
        }
        if request.payload.is_empty() || request.payload.len() > MAX_EVIDENCE_BYTES {
            return Err(ServiceFailure::resource_exhausted(
                "evidence_size_invalid",
                format!("evidence payload must contain 1..={MAX_EVIDENCE_BYTES} bytes"),
            ));
        }
        let content_digest = ContentDigest::from_bytes(&request.payload);
        if let Some(expected) = &request.expected_digest
            && expected != &content_digest
        {
            return Err(ServiceFailure::failed(
                "evidence_digest_mismatch",
                format!("evidence content is {content_digest}, expected {expected}"),
            ));
        }
        verify_directory_anchor(&self.payload_directory).map_err(host_error_as_failure)?;
        verify_directory_anchor(&self.record_directory).map_err(host_error_as_failure)?;
        persist_immutable(
            &self.payload_path(&content_digest),
            &request.payload,
            &content_digest,
        )
        .map_err(host_error_as_failure)?;
        let mut record = EvidenceRecord {
            schema: EVIDENCE_RECORD_SCHEMA.to_string(),
            scope_id: self.scope_id.clone(),
            evidence_id: request.evidence_id.clone(),
            media_type: request.media_type.clone(),
            subject_refs: request.subject_refs.clone(),
            content_digest,
            byte_len: request.payload.len() as u64,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        record.record_digest = evidence_record_digest(&record)?;
        let record_bytes = serde_json::to_vec_pretty(&record).map_err(|error| {
            ServiceFailure::failed("evidence_record_serialize_failed", error.to_string())
        })?;
        persist_named_immutable(&self.record_path(&record.evidence_id), &record_bytes)
            .map_err(host_error_as_failure)?;
        let loaded = self.load_record(&record.evidence_id)?;
        if loaded != record {
            return Err(ServiceFailure::failed(
                "evidence_identity_conflict",
                "evidence id already resolves to different immutable content",
            ));
        }
        Ok(record)
    }

    fn resolve(
        &self,
        request: &ResolveEvidenceRequest,
        control: &InvocationControl,
    ) -> Result<ResolvedEvidence, ServiceFailure> {
        control.check()?;
        require_scope(&self.scope_id, &request.scope_id)?;
        validate_safe_identifier("evidence_id", &request.evidence_id)
            .map_err(host_error_as_failure)?;
        let record = self.load_record(&request.evidence_id)?;
        if record.content_digest != request.expected_digest {
            return Err(ServiceFailure::failed(
                "evidence_digest_mismatch",
                format!(
                    "evidence id resolves to {}, expected {}",
                    record.content_digest, request.expected_digest
                ),
            ));
        }
        verify_directory_anchor(&self.payload_directory).map_err(host_error_as_failure)?;
        let payload = read_regular_file(&self.payload_path(&record.content_digest))
            .map_err(host_error_as_failure)?;
        let actual = ContentDigest::from_bytes(&payload);
        if actual != record.content_digest || payload.len() as u64 != record.byte_len {
            return Err(ServiceFailure::failed(
                "evidence_payload_corrupt",
                "evidence payload bytes do not match their durable record",
            ));
        }
        Ok(ResolvedEvidence { record, payload })
    }
}

#[derive(Debug)]
pub enum CapabilityHostError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Serialization(String),
    InvalidConfiguration(String),
    InvalidRequest(String),
    InvalidField {
        field: &'static str,
    },
    UnsafePath {
        path: PathBuf,
        reason: &'static str,
    },
    UnknownService {
        service_id: String,
    },
    ConfigurationMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    IdempotencyConflict {
        service_id: String,
        idempotency_key: String,
    },
    InvocationIdConflict {
        invocation_id: String,
    },
    InvocationInFlight {
        invocation_id: String,
    },
    RequestTooLarge {
        actual: usize,
        limit: usize,
    },
    JournalFull {
        limit: usize,
    },
    ReceiptNotFound {
        invocation_id: String,
    },
    CorruptState(String),
    StateLockPoisoned,
}

impl CapabilityHostError {
    fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }
}

impl Display for CapabilityHostError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(
                formatter,
                "capability service I/O error at '{}': {source}",
                path.display()
            ),
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "capability service serialization error: {message}"
                )
            }
            Self::InvalidConfiguration(message) => {
                write!(
                    formatter,
                    "invalid capability service configuration: {message}"
                )
            }
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid capability invocation: {message}")
            }
            Self::InvalidField { field } => {
                write!(formatter, "capability field '{field}' must not be blank")
            }
            Self::UnsafePath { path, reason } => {
                write!(
                    formatter,
                    "unsafe capability path '{}': {reason}",
                    path.display()
                )
            }
            Self::UnknownService { service_id } => {
                write!(formatter, "unknown capability service '{service_id}'")
            }
            Self::ConfigurationMismatch { expected, actual } => write!(
                formatter,
                "capability host configuration changed across restart: stored {expected}, configured {actual}"
            ),
            Self::IdempotencyConflict {
                service_id,
                idempotency_key,
            } => write!(
                formatter,
                "service '{service_id}' idempotency key '{idempotency_key}' was reused with different input"
            ),
            Self::InvocationIdConflict { invocation_id } => write!(
                formatter,
                "invocation id '{invocation_id}' was already used"
            ),
            Self::InvocationInFlight { invocation_id } => {
                write!(
                    formatter,
                    "invocation '{invocation_id}' is already in flight"
                )
            }
            Self::RequestTooLarge { actual, limit } => write!(
                formatter,
                "serialized invocation is {actual} bytes; limit is {limit}"
            ),
            Self::JournalFull { limit } => {
                write!(
                    formatter,
                    "capability invocation journal reached limit {limit}"
                )
            }
            Self::ReceiptNotFound { invocation_id } => {
                write!(
                    formatter,
                    "no terminal receipt for invocation '{invocation_id}'"
                )
            }
            Self::CorruptState(message) => {
                write!(formatter, "corrupt capability service state: {message}")
            }
            Self::StateLockPoisoned => {
                write!(formatter, "capability service state lock is poisoned")
            }
        }
    }
}

impl Error for CapabilityHostError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct ReceiptDigestMaterial<'a> {
    schema: &'a str,
    invocation_id: &'a str,
    idempotency_key: &'a str,
    service_id: &'a str,
    family: NativeServiceFamily,
    operation: CapabilityOperation,
    scope_id: &'a str,
    implementation_id: &'a str,
    implementation_digest: &'a ContentDigest,
    input_digest: &'a ContentDigest,
    output_digest: &'a ContentDigest,
    started_at_ms: u64,
    finished_at_ms: u64,
    outcome: &'a InvocationOutcome,
    input_ref: &'a str,
    output_ref: &'a str,
}

fn receipt_digest(receipt: &InvocationReceipt) -> Result<ContentDigest, CapabilityHostError> {
    digest_json_content(&ReceiptDigestMaterial {
        schema: &receipt.schema,
        invocation_id: &receipt.invocation_id,
        idempotency_key: &receipt.idempotency_key,
        service_id: &receipt.service_id,
        family: receipt.family,
        operation: receipt.operation,
        scope_id: &receipt.scope_id,
        implementation_id: &receipt.implementation_id,
        implementation_digest: &receipt.implementation_digest,
        input_digest: &receipt.input_digest,
        output_digest: &receipt.output_digest,
        started_at_ms: receipt.started_at_ms,
        finished_at_ms: receipt.finished_at_ms,
        outcome: &receipt.outcome,
        input_ref: &receipt.provenance.input_ref,
        output_ref: &receipt.provenance.output_ref,
    })
    .map_err(|error| CapabilityHostError::Serialization(error.to_string()))
}

#[derive(Serialize)]
struct AttestationDigestMaterial<'a> {
    schema: &'a str,
    attestation_id: &'a str,
    invocation_id: &'a str,
    service_id: &'a str,
    family: NativeServiceFamily,
    operation: CapabilityOperation,
    scope_id: &'a str,
    implementation_digest: &'a ContentDigest,
    input_digest: &'a ContentDigest,
    output_digest: &'a ContentDigest,
    receipt_digest: &'a ContentDigest,
    terminal_success: bool,
    failure_kind: Option<ServiceFailureKind>,
    provenance: &'a InvocationProvenance,
}

impl<'a> From<&'a ServiceInvocationAttestation> for AttestationDigestMaterial<'a> {
    fn from(attestation: &'a ServiceInvocationAttestation) -> Self {
        Self {
            schema: &attestation.schema,
            attestation_id: &attestation.attestation_id,
            invocation_id: &attestation.invocation_id,
            service_id: &attestation.service_id,
            family: attestation.family,
            operation: attestation.operation,
            scope_id: &attestation.scope_id,
            implementation_digest: &attestation.implementation_digest,
            input_digest: &attestation.input_digest,
            output_digest: &attestation.output_digest,
            receipt_digest: &attestation.receipt_digest,
            terminal_success: attestation.terminal_success,
            failure_kind: attestation.failure_kind,
            provenance: &attestation.provenance,
        }
    }
}

#[derive(Serialize)]
struct PackageRecordDigestMaterial<'a> {
    schema: &'a str,
    scope_id: &'a str,
    package_digest: &'a ContentDigest,
    source_tree_digest: &'a ContentDigest,
    byte_len: u64,
    artifact_relative_path: &'a Path,
    build_id: &'a str,
}

fn package_record_digest(artifact: &PackageArtifact) -> Result<ContentDigest, ServiceFailure> {
    digest_json_content(&PackageRecordDigestMaterial {
        schema: &artifact.schema,
        scope_id: &artifact.scope_id,
        package_digest: &artifact.package_digest,
        source_tree_digest: &artifact.source_tree_digest,
        byte_len: artifact.byte_len,
        artifact_relative_path: &artifact.artifact_relative_path,
        build_id: &artifact.build_id,
    })
    .map_err(|error| ServiceFailure::failed("package_record_digest_failed", error.to_string()))
}

#[derive(Serialize)]
struct ReviewRecordDigestMaterial<'a> {
    schema: &'a str,
    scope_id: &'a str,
    comparison_digest: &'a ContentDigest,
    incumbent_proving_digest: &'a ContentDigest,
    challenger_proving_digest: &'a ContentDigest,
    decision: ReviewDecision,
    rationale: &'a str,
}

fn review_record_digest(record: &CandidateReviewRecord) -> Result<ContentDigest, ServiceFailure> {
    digest_json_content(&ReviewRecordDigestMaterial {
        schema: &record.schema,
        scope_id: &record.scope_id,
        comparison_digest: &record.comparison_digest,
        incumbent_proving_digest: &record.incumbent_proving_digest,
        challenger_proving_digest: &record.challenger_proving_digest,
        decision: record.decision,
        rationale: &record.rationale,
    })
    .map_err(|error| ServiceFailure::failed("review_record_digest_failed", error.to_string()))
}

#[derive(Serialize)]
struct EvidenceRecordDigestMaterial<'a> {
    schema: &'a str,
    scope_id: &'a str,
    evidence_id: &'a str,
    media_type: &'a str,
    subject_refs: &'a [String],
    content_digest: &'a ContentDigest,
    byte_len: u64,
}

fn evidence_record_digest(record: &EvidenceRecord) -> Result<ContentDigest, ServiceFailure> {
    digest_json_content(&EvidenceRecordDigestMaterial {
        schema: &record.schema,
        scope_id: &record.scope_id,
        evidence_id: &record.evidence_id,
        media_type: &record.media_type,
        subject_refs: &record.subject_refs,
        content_digest: &record.content_digest,
        byte_len: record.byte_len,
    })
    .map_err(|error| ServiceFailure::failed("evidence_record_digest_failed", error.to_string()))
}

fn operations_snapshot(
    deployment_id: &str,
    state: &DeploymentState,
) -> Result<OperationsSnapshot, ServiceFailure> {
    let state_digest =
        digest_json_content(&("wasm-biotic:operations-snapshot:v1", deployment_id, state))
            .map_err(|error| {
                ServiceFailure::failed("operations_snapshot_digest_failed", error.to_string())
            })?;
    Ok(OperationsSnapshot {
        deployment_id: deployment_id.to_string(),
        active_artifact: state.active_artifact.clone(),
        activation_count: state.activations.len(),
        observation_count: state.observations.len(),
        rollback_count: state.rollbacks.len(),
        in_flight: state.in_flight.is_some(),
        state_digest,
    })
}

fn approval_satisfies(actual: &InvocationApproval, required: &ApprovalClass) -> bool {
    match (actual, required) {
        (InvocationApproval::Automatic, ApprovalClass::AutoAllowed) => true,
        (
            InvocationApproval::Granted { class, .. },
            ApprovalClass::SupervisorAllowed
            | ApprovalClass::HumanRequired
            | ApprovalClass::QuarantineOnExpand,
        ) => class == required,
        _ => false,
    }
}

fn missing_dependency(name: &str) -> ServiceFailure {
    ServiceFailure::unavailable(
        "service_dependency_unavailable",
        format!("required {name} implementation is not configured"),
    )
}

fn validate_factory_effect_request(request: &FactoryEffectRequest) -> Result<(), ServiceFailure> {
    validate_factory_effect_id("scope_id", &request.scope_id)?;
    validate_factory_effect_id("factory_id", &request.factory_id)?;
    validate_factory_effect_id("logical_effect_id", &request.logical_effect_id)?;
    if request.exact_request_bytes.len() > MAX_FACTORY_EFFECT_REQUEST_BYTES {
        return Err(ServiceFailure::resource_exhausted(
            "factory_request_too_large",
            format!(
                "factory request contains {} bytes, limit is {MAX_FACTORY_EFFECT_REQUEST_BYTES}",
                request.exact_request_bytes.len()
            ),
        ));
    }
    let actual = ContentDigest::from_bytes(&request.exact_request_bytes);
    if actual != request.exact_request_digest {
        return Err(ServiceFailure::failed(
            "factory_request_digest_mismatch",
            format!(
                "factory request bytes digest to {actual}, declared {}",
                request.exact_request_digest
            ),
        ));
    }
    Ok(())
}

fn validate_factory_effect_result(
    request: &FactoryEffectRequest,
    result: &FactoryEffectResult,
) -> Result<(), ServiceFailure> {
    if result.logical_effect_id != request.logical_effect_id
        || result.exact_request_digest != request.exact_request_digest
    {
        return Err(ServiceFailure::failed(
            "factory_result_identity_mismatch",
            "factory result does not bind the exact logical effect and request digest",
        ));
    }
    if result.exact_response_bytes.len() > MAX_FACTORY_EFFECT_RESPONSE_BYTES {
        return Err(ServiceFailure::resource_exhausted(
            "factory_response_too_large",
            format!(
                "factory response contains {} bytes, limit is {MAX_FACTORY_EFFECT_RESPONSE_BYTES}",
                result.exact_response_bytes.len()
            ),
        ));
    }
    let actual = ContentDigest::from_bytes(&result.exact_response_bytes);
    if actual != result.exact_response_digest {
        return Err(ServiceFailure::failed(
            "factory_response_digest_mismatch",
            format!(
                "factory response bytes digest to {actual}, declared {}",
                result.exact_response_digest
            ),
        ));
    }
    Ok(())
}

fn validate_factory_effect_id(field: &str, value: &str) -> Result<(), ServiceFailure> {
    if value.trim().is_empty() || value.len() > MAX_FACTORY_EFFECT_ID_BYTES {
        return Err(ServiceFailure::failed(
            "factory_effect_identity_invalid",
            format!("{field} must contain 1..={MAX_FACTORY_EFFECT_ID_BYTES} nonblank bytes"),
        ));
    }
    Ok(())
}

fn command_success_or_failure(
    receipt: BoundedCommandReceipt,
) -> Result<CapabilitySuccess, ServiceFailure> {
    match receipt.status {
        CommandTerminalStatus::ExitedZero => Ok(CapabilitySuccess::Command(Box::new(receipt))),
        CommandTerminalStatus::ExitedNonzero => Err(ServiceFailure::failed(
            "command_exited_nonzero",
            format!(
                "allowlisted command exited with code {:?}",
                receipt.exit_code
            ),
        )
        .with_evidence(FailureEvidence::Command(Box::new(receipt)))),
        CommandTerminalStatus::TimedOut => Err(ServiceFailure::timed_out(
            "command_timed_out",
            "allowlisted command exceeded its wall-time bound",
        )
        .with_evidence(FailureEvidence::Command(Box::new(receipt)))),
        CommandTerminalStatus::Cancelled => Err(ServiceFailure::cancelled(
            "command_cancelled",
            "allowlisted command was killed after cancellation",
        )
        .with_evidence(FailureEvidence::Command(Box::new(receipt)))),
        CommandTerminalStatus::OutputLimitExceeded => Err(ServiceFailure::resource_exhausted(
            "command_output_limit_exceeded",
            "allowlisted command exceeded a captured-output bound",
        )
        .with_evidence(FailureEvidence::Command(Box::new(receipt)))),
    }
}

fn descriptor_availability(
    descriptor: &CapabilityServiceDescriptor,
    dependencies: &CapabilityServiceDependencies,
) -> ServiceAvailability {
    if dependencies
        .unavailable_service_ids
        .contains(descriptor.service_id())
    {
        return ServiceAvailability::Unavailable;
    }
    let available = descriptor
        .supported_operations
        .iter()
        .filter(|operation| dependency_for_operation(**operation, dependencies))
        .count();
    if available == descriptor.supported_operations.len() {
        ServiceAvailability::Available
    } else if available == 0 {
        ServiceAvailability::Unavailable
    } else {
        ServiceAvailability::Degraded
    }
}

fn dependency_for_operation(
    operation: CapabilityOperation,
    dependencies: &CapabilityServiceDependencies,
) -> bool {
    match operation {
        CapabilityOperation::WorkspaceOpen
        | CapabilityOperation::WorkspaceSnapshot
        | CapabilityOperation::WorkspacePatch => dependencies.workspace.is_some(),
        CapabilityOperation::CandidateBuild
        | CapabilityOperation::PackagePublish
        | CapabilityOperation::PackageVerify => dependencies.build_packaging.is_some(),
        CapabilityOperation::CommandExecute => dependencies.command.is_some(),
        CapabilityOperation::ValidationProve
        | CapabilityOperation::ValidationCompare
        | CapabilityOperation::ReviewCandidate => dependencies.validation_review.is_some(),
        CapabilityOperation::EvidencePublish | CapabilityOperation::EvidenceResolve => {
            dependencies.evidence.is_some()
        }
        CapabilityOperation::ScheduleJob => dependencies.scheduling.is_some(),
        CapabilityOperation::DeploymentInitialize
        | CapabilityOperation::DeploymentActivate
        | CapabilityOperation::DeploymentObserve
        | CapabilityOperation::DeploymentRollback
        | CapabilityOperation::OperationsInspect => dependencies.deployment.is_some(),
        CapabilityOperation::FactoryExecute
        | CapabilityOperation::FactoryProviderProposal
        | CapabilityOperation::FactoryShadow
        | CapabilityOperation::FactoryInitialize
        | CapabilityOperation::FactoryStateMigrate
        | CapabilityOperation::FactoryActivate
        | CapabilityOperation::FactoryObserve
        | CapabilityOperation::FactoryRollback
        | CapabilityOperation::FactoryInspect => dependencies.factory_evolution.is_some(),
    }
}

fn initial_health(
    descriptor: &CapabilityServiceDescriptor,
    dependencies: &CapabilityServiceDependencies,
    now: u64,
) -> ServiceHealth {
    let availability = descriptor_availability(descriptor, dependencies);
    ServiceHealth {
        service_id: descriptor.service_id.clone(),
        family: descriptor.family,
        scope_id: descriptor.scope_id.clone(),
        lifecycle: match availability {
            ServiceAvailability::Available => ServiceLifecycleState::Ready,
            ServiceAvailability::Degraded => ServiceLifecycleState::Degraded,
            ServiceAvailability::Unavailable => ServiceLifecycleState::Unavailable,
        },
        availability,
        successful_invocations: 0,
        failed_invocations: 0,
        last_invocation_id: None,
        last_failure: None,
        updated_at_ms: now,
    }
}

fn update_health_after_receipt(
    state: &mut CapabilityHostState,
    descriptor: &CapabilityServiceDescriptor,
    receipt: &InvocationReceipt,
    now: u64,
) -> Result<(), CapabilityHostError> {
    let health = state
        .health
        .get_mut(&descriptor.service_id)
        .ok_or_else(|| {
            CapabilityHostError::CorruptState(format!(
                "missing health record for service '{}'",
                descriptor.service_id
            ))
        })?;
    health.last_invocation_id = Some(receipt.invocation_id.clone());
    health.updated_at_ms = now;
    match &receipt.outcome {
        InvocationOutcome::Succeeded { .. } => {
            health.successful_invocations = health.successful_invocations.saturating_add(1);
            health.lifecycle = ServiceLifecycleState::Ready;
            health.availability = ServiceAvailability::Available;
            health.last_failure = None;
        }
        InvocationOutcome::Terminal { failure } => {
            health.failed_invocations = health.failed_invocations.saturating_add(1);
            health.lifecycle = match failure.kind {
                ServiceFailureKind::Unavailable => ServiceLifecycleState::Unavailable,
                _ => ServiceLifecycleState::Degraded,
            };
            health.availability = match failure.kind {
                ServiceFailureKind::Unavailable => ServiceAvailability::Unavailable,
                _ => ServiceAvailability::Degraded,
            };
            health.last_failure = Some(failure.clone());
        }
    }
    Ok(())
}

fn validate_host_state(state: &CapabilityHostState) -> Result<(), CapabilityHostError> {
    if state.schema_version != CAPABILITY_HOST_STATE_SCHEMA_VERSION {
        return Err(CapabilityHostError::CorruptState(format!(
            "unsupported state schema {}; expected {}",
            state.schema_version, CAPABILITY_HOST_STATE_SCHEMA_VERSION
        )));
    }
    if state.invocations.len() > MAX_INVOCATION_JOURNAL_ENTRIES {
        return Err(CapabilityHostError::CorruptState(
            "invocation journal exceeds its configured bound".to_string(),
        ));
    }
    let mut invocation_ids = BTreeSet::new();
    let mut idempotency_keys = BTreeSet::new();
    for entry in &state.invocations {
        entry.identity.validate()?;
        if !invocation_ids.insert(entry.identity.invocation_id.clone()) {
            return Err(CapabilityHostError::CorruptState(format!(
                "duplicate invocation id '{}'",
                entry.identity.invocation_id
            )));
        }
        if !idempotency_keys.insert((
            entry.identity.service_id.clone(),
            entry.identity.idempotency_key.clone(),
        )) {
            return Err(CapabilityHostError::CorruptState(format!(
                "duplicate idempotency key '{}' for service '{}'",
                entry.identity.idempotency_key, entry.identity.service_id
            )));
        }
        if let Some(receipt) = &entry.receipt {
            receipt.verify_integrity()?;
            if receipt.invocation_id != entry.identity.invocation_id
                || receipt.service_id != entry.identity.service_id
                || receipt.input_digest != entry.input_digest
                || receipt.family != entry.family
                || receipt.operation != entry.operation
            {
                return Err(CapabilityHostError::CorruptState(format!(
                    "receipt '{}' does not match its journal entry",
                    receipt.invocation_id
                )));
            }
        }
    }
    for (service_id, health) in &state.health {
        if service_id != &health.service_id {
            return Err(CapabilityHostError::CorruptState(format!(
                "health map key '{service_id}' does not match record '{}'",
                health.service_id
            )));
        }
    }
    Ok(())
}

fn write_host_state(root: &Path, state: &CapabilityHostState) -> Result<(), CapabilityHostError> {
    validate_host_state(state)?;
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|error| CapabilityHostError::Serialization(error.to_string()))?;
    atomic_replace(&root.join(HOST_STATE_FILE), &bytes)
}

fn validate_nonblank(field: &'static str, value: &str) -> Result<(), CapabilityHostError> {
    if value.trim().is_empty() {
        Err(CapabilityHostError::InvalidField { field })
    } else {
        Ok(())
    }
}

fn validate_safe_identifier(field: &'static str, value: &str) -> Result<(), CapabilityHostError> {
    validate_nonblank(field, value)?;
    if value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
    {
        return Err(CapabilityHostError::InvalidRequest(format!(
            "{field} contains unsupported characters or exceeds 256 bytes"
        )));
    }
    Ok(())
}

fn validate_safe_component(field: &'static str, value: &str) -> Result<(), CapabilityHostError> {
    validate_nonblank(field, value)?;
    if value.len() > 128
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(CapabilityHostError::InvalidRequest(format!(
            "{field} must be one safe ASCII path component"
        )));
    }
    Ok(())
}

fn require_scope(expected: &str, actual: &str) -> Result<(), ServiceFailure> {
    if expected == actual {
        Ok(())
    } else {
        Err(ServiceFailure::new(
            ServiceFailureKind::ScopeDenied,
            "port_scope_mismatch",
            format!("port owns scope '{expected}', request names '{actual}'"),
        ))
    }
}

fn require_workspace_scope(
    expected: &str,
    workspace: &ScopedWorkspaceRef,
) -> Result<(), ServiceFailure> {
    require_scope(expected, &workspace.scope_id)?;
    validate_safe_component("workspace_id", &workspace.workspace_id).map_err(host_error_as_failure)
}

fn host_error_as_failure(error: CapabilityHostError) -> ServiceFailure {
    match error {
        CapabilityHostError::UnsafePath { .. } => {
            ServiceFailure::failed("unsafe_path", error.to_string())
        }
        CapabilityHostError::Io { .. } => {
            ServiceFailure::failed("local_io_failed", error.to_string())
        }
        _ => ServiceFailure::failed("service_invariant_failed", error.to_string()),
    }
}

fn validate_command_policy(policy: &CommandPolicy) -> Result<(), CapabilityHostError> {
    if policy.max_timeout_ms == 0
        || policy.max_timeout_ms > MAX_INVOCATION_TIMEOUT_MS
        || policy.max_stdout_bytes == 0
        || policy.max_stderr_bytes == 0
        || policy.max_argument_bytes == 0
        || policy.max_arguments == 0
        || policy.poll_interval_ms == 0
        || policy.poll_interval_ms > policy.max_timeout_ms
    {
        return Err(CapabilityHostError::InvalidConfiguration(
            "command policy bounds must be nonzero, internally consistent, and within the host timeout maximum"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_command_limits(
    limits: &CommandLimits,
    policy: &CommandPolicy,
) -> Result<(), ServiceFailure> {
    if limits.timeout_ms == 0
        || limits.timeout_ms > policy.max_timeout_ms
        || limits.max_stdout_bytes == 0
        || limits.max_stdout_bytes > policy.max_stdout_bytes
        || limits.max_stderr_bytes == 0
        || limits.max_stderr_bytes > policy.max_stderr_bytes
        || limits.max_argument_bytes == 0
        || limits.max_argument_bytes > policy.max_argument_bytes
    {
        return Err(ServiceFailure::resource_exhausted(
            "command_limits_outside_policy",
            "requested command bounds are zero or exceed the configured command policy",
        ));
    }
    Ok(())
}

fn capture_stream<R: Read>(
    mut reader: R,
    limit: usize,
) -> Result<CapturedCommandStream, std::io::Error> {
    let mut captured = Vec::with_capacity(limit.min(16 * 1024));
    let mut buffer = [0u8; 8 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        let remaining = limit.saturating_sub(captured.len());
        if remaining > 0 {
            captured.extend_from_slice(&buffer[..read.min(remaining)]);
        }
    }
    Ok(CapturedCommandStream {
        captured_digest: ContentDigest::from_bytes(&captured),
        truncated: total > captured.len() as u64,
        captured_bytes: captured,
        total_bytes: total,
    })
}

fn join_capture(
    handle: thread::JoinHandle<Result<CapturedCommandStream, std::io::Error>>,
    stream: &'static str,
) -> Result<CapturedCommandStream, ServiceFailure> {
    handle
        .join()
        .map_err(|_| {
            ServiceFailure::failed(
                "command_capture_panicked",
                format!("{stream} capture thread panicked"),
            )
        })?
        .map_err(|source| {
            ServiceFailure::failed(
                "command_capture_failed",
                format!("failed to read command {stream}: {source}"),
            )
        })
}

fn exit_code(status: ExitStatus) -> Option<i32> {
    status.code()
}

#[derive(Serialize)]
struct CommandReceiptDigestMaterial<'a> {
    command_id: &'a str,
    executable_digest: &'a ContentDigest,
    arguments_digest: &'a ContentDigest,
    working_directory_ref: &'a str,
    status: CommandTerminalStatus,
    exit_code: Option<i32>,
    stdout: &'a CapturedCommandStream,
    stderr: &'a CapturedCommandStream,
    elapsed_ms: u64,
}

fn command_receipt_digest(
    receipt: &BoundedCommandReceipt,
) -> Result<ContentDigest, ServiceFailure> {
    digest_json_content(&CommandReceiptDigestMaterial {
        command_id: &receipt.command_id,
        executable_digest: &receipt.executable_digest,
        arguments_digest: &receipt.arguments_digest,
        working_directory_ref: &receipt.working_directory_ref,
        status: receipt.status,
        exit_code: receipt.exit_code,
        stdout: &receipt.stdout,
        stderr: &receipt.stderr,
        elapsed_ms: receipt.elapsed_ms,
    })
    .map_err(|error| ServiceFailure::failed("command_receipt_digest_failed", error.to_string()))
}

fn secure_create_root(path: &Path) -> Result<PathBuf, CapabilityHostError> {
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| CapabilityHostError::io(path, source))?;
    secure_existing_directory(path)
}

fn secure_existing_directory(path: &Path) -> Result<PathBuf, CapabilityHostError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| CapabilityHostError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CapabilityHostError::UnsafePath {
            path: path.to_path_buf(),
            reason: "configured root must be a non-symlink directory",
        });
    }
    fs::canonicalize(path).map_err(|source| CapabilityHostError::io(path, source))
}

fn verify_directory_anchor(path: &Path) -> Result<(), CapabilityHostError> {
    let canonical = secure_existing_directory(path)?;
    if canonical != path {
        return Err(CapabilityHostError::UnsafePath {
            path: path.to_path_buf(),
            reason: "service-owned directory anchor changed after startup",
        });
    }
    Ok(())
}

fn resolve_regular_descendant(
    root: &Path,
    relative: &Path,
) -> Result<PathBuf, CapabilityHostError> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(CapabilityHostError::UnsafePath {
            path: relative.to_path_buf(),
            reason: "stored artifact path must be a nonempty relative path",
        });
    }
    let mut path = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(CapabilityHostError::UnsafePath {
                path: relative.to_path_buf(),
                reason: "stored artifact path contains traversal or a platform prefix",
            });
        };
        if segment.to_str().is_none() {
            return Err(CapabilityHostError::UnsafePath {
                path: relative.to_path_buf(),
                reason: "stored artifact path contains a non-UTF-8 component",
            });
        }
        path.push(segment);
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| CapabilityHostError::io(&path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(CapabilityHostError::UnsafePath {
                path: relative.to_path_buf(),
                reason: "stored artifact path traverses a symbolic link",
            });
        }
    }
    let metadata =
        fs::symlink_metadata(&path).map_err(|source| CapabilityHostError::io(&path, source))?;
    if !metadata.is_file() {
        return Err(CapabilityHostError::UnsafePath {
            path: relative.to_path_buf(),
            reason: "stored artifact path must resolve to a regular file",
        });
    }
    let canonical =
        fs::canonicalize(&path).map_err(|source| CapabilityHostError::io(&path, source))?;
    if !canonical.starts_with(root) {
        return Err(CapabilityHostError::UnsafePath {
            path: relative.to_path_buf(),
            reason: "stored artifact path escapes its canonical root",
        });
    }
    Ok(canonical)
}

fn ensure_owned_directory(root: &Path, name: &'static str) -> Result<PathBuf, CapabilityHostError> {
    let path = root.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(CapabilityHostError::UnsafePath {
                path,
                reason: "service-owned path must be a non-symlink directory",
            });
        }
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&path).map_err(|source| CapabilityHostError::io(&path, source))?;
        }
        Err(source) => return Err(CapabilityHostError::io(&path, source)),
    }
    let canonical =
        fs::canonicalize(&path).map_err(|source| CapabilityHostError::io(&path, source))?;
    if canonical.parent() != Some(root) {
        return Err(CapabilityHostError::UnsafePath {
            path,
            reason: "service-owned directory is not directly beneath its canonical root",
        });
    }
    Ok(canonical)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), CapabilityHostError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CapabilityHostError::UnsafePath {
            path: path.to_path_buf(),
            reason: "service-owned path must not be a symbolic link",
        }),
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CapabilityHostError::io(path, source)),
    }
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, CapabilityHostError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| CapabilityHostError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CapabilityHostError::UnsafePath {
            path: path.to_path_buf(),
            reason: "service-owned file must be a regular non-symlink file",
        });
    }
    let mut file = File::open(path).map_err(|source| CapabilityHostError::io(path, source))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| CapabilityHostError::io(path, source))?;
    Ok(bytes)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, CapabilityHostError> {
    let bytes = read_regular_file(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| CapabilityHostError::Serialization(error.to_string()))
}

fn verify_content_file(path: &Path, expected: &ContentDigest) -> Result<(), CapabilityHostError> {
    let bytes = read_regular_file(path)?;
    let actual = ContentDigest::from_bytes(&bytes);
    if &actual != expected {
        return Err(CapabilityHostError::CorruptState(format!(
            "content file '{}' is {actual}, expected {expected}",
            path.display()
        )));
    }
    Ok(())
}

fn persist_immutable(
    path: &Path,
    bytes: &[u8],
    expected_digest: &ContentDigest,
) -> Result<(), CapabilityHostError> {
    let actual = ContentDigest::from_bytes(bytes);
    if &actual != expected_digest {
        return Err(CapabilityHostError::CorruptState(format!(
            "refusing to store bytes {actual} under identity {expected_digest}"
        )));
    }
    persist_named_immutable(path, bytes)
}

fn persist_named_immutable(path: &Path, bytes: &[u8]) -> Result<(), CapabilityHostError> {
    reject_symlink_if_present(path)?;
    if path.exists() {
        let existing = read_regular_file(path)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(CapabilityHostError::CorruptState(format!(
            "immutable path '{}' already contains different bytes",
            path.display()
        )));
    }
    let temporary = unique_temporary_path(path)?;
    let result = write_and_sync_new(&temporary, bytes).and_then(|()| {
        match fs::hard_link(&temporary, path) {
            Ok(()) => {
                fs::remove_file(&temporary)
                    .map_err(|source| CapabilityHostError::io(&temporary, source))?;
                sync_parent(path)
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temporary)
                    .map_err(|source| CapabilityHostError::io(&temporary, source))?;
                let existing = read_regular_file(path)?;
                if existing == bytes {
                    Ok(())
                } else {
                    Err(CapabilityHostError::CorruptState(format!(
                        "immutable path '{}' won a race with different bytes",
                        path.display()
                    )))
                }
            }
            Err(source) => Err(CapabilityHostError::io(path, source)),
        }
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), CapabilityHostError> {
    reject_symlink_if_present(path)?;
    let temporary = unique_temporary_path(path)?;
    let result = write_and_sync_new(&temporary, bytes).and_then(|()| {
        fs::rename(&temporary, path).map_err(|source| CapabilityHostError::io(path, source))?;
        sync_parent(path)
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_and_sync_new(path: &Path, bytes: &[u8]) -> Result<(), CapabilityHostError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|source| CapabilityHostError::io(path, source))?;
    file.write_all(bytes)
        .map_err(|source| CapabilityHostError::io(path, source))?;
    file.sync_all()
        .map_err(|source| CapabilityHostError::io(path, source))
}

fn unique_temporary_path(path: &Path) -> Result<PathBuf, CapabilityHostError> {
    let parent = path.parent().ok_or_else(|| {
        CapabilityHostError::InvalidConfiguration(format!(
            "path '{}' has no parent",
            path.display()
        ))
    })?;
    let file_name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
        CapabilityHostError::InvalidConfiguration(format!(
            "path '{}' has no UTF-8 file name",
            path.display()
        ))
    })?;
    for _ in 0..128 {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            sequence
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(CapabilityHostError::InvalidConfiguration(format!(
        "could not allocate temporary file beside '{}'",
        path.display()
    )))
}

fn sync_parent(path: &Path) -> Result<(), CapabilityHostError> {
    let parent = path.parent().ok_or_else(|| {
        CapabilityHostError::InvalidConfiguration(format!(
            "path '{}' has no parent",
            path.display()
        ))
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| CapabilityHostError::io(parent, source))
}

fn content_ref(directory: &str, digest: &ContentDigest, extension: &str) -> String {
    format!("{directory}/{}.{extension}", digest.file_stem())
}

fn digest_file_streaming(path: &Path) -> Result<ContentDigest, CapabilityHostError> {
    let mut file = File::open(path).map_err(|source| CapabilityHostError::io(path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| CapabilityHostError::io(path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    ContentDigest::new(format!("sha256:{:x}", hasher.finalize()))
        .map_err(|error| CapabilityHostError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::ComponentExecutionLimits;
    use crate::m1_validation::ValidationCase;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "wasm-biotic-capability-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create isolated test root");
            Self { root }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Default)]
    struct ManualClock {
        now: AtomicU64,
    }

    impl ManualClock {
        fn at(now: u64) -> Self {
            Self {
                now: AtomicU64::new(now),
            }
        }
    }

    impl ClockPort for ManualClock {
        fn now_ms(&self) -> u64 {
            self.now.load(Ordering::Acquire)
        }
    }

    struct CountingWorkspacePort {
        calls: Arc<AtomicUsize>,
        failure: Option<ServiceFailure>,
    }

    impl CandidateWorkspacePort for CountingWorkspacePort {
        fn open_workspace(
            &self,
            request: &OpenWorkspaceRequest,
            _control: &InvocationControl,
        ) -> Result<CandidateWorkspaceSnapshot, ServiceFailure> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if let Some(failure) = &self.failure {
                return Err(failure.clone());
            }
            Ok(test_workspace_snapshot(&request.workspace))
        }

        fn snapshot_workspace(
            &self,
            request: &SnapshotWorkspaceRequest,
            _control: &InvocationControl,
        ) -> Result<CandidateWorkspaceSnapshot, ServiceFailure> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if let Some(failure) = &self.failure {
                return Err(failure.clone());
            }
            Ok(test_workspace_snapshot(&request.workspace))
        }

        fn patch_workspace(
            &self,
            _request: &PatchWorkspaceRequest,
            _control: &InvocationControl,
        ) -> Result<MaterializedCandidatePatchset, ServiceFailure> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(ServiceFailure::unsupported(
                "test_patch_unsupported",
                "test port does not implement patching",
            ))
        }
    }

    #[derive(Default)]
    struct FixtureFactoryEvolutionPort {
        calls: Mutex<Vec<(CapabilityOperation, FactoryEffectRequest)>>,
    }

    impl FactoryEvolutionPort for FixtureFactoryEvolutionPort {
        fn apply_factory_effect(
            &self,
            operation: CapabilityOperation,
            request: &FactoryEffectRequest,
            _control: &InvocationControl,
        ) -> Result<FactoryEffectResult, ServiceFailure> {
            self.calls
                .lock()
                .expect("lock fixture factory calls")
                .push((operation, request.clone()));
            Ok(FactoryEffectResult::new(
                request,
                [
                    b"fixture-response:".as_slice(),
                    request.exact_request_bytes.as_slice(),
                ]
                .concat(),
            ))
        }
    }

    fn test_workspace_snapshot(workspace: &ScopedWorkspaceRef) -> CandidateWorkspaceSnapshot {
        CandidateWorkspaceSnapshot {
            workspace_id: workspace.workspace_id.clone(),
            workspace_ref: format!("workspace:{}", workspace.workspace_id),
            mutable_paths: vec![COMPONENT_WAT_PATH.to_string()],
            immutable_paths: vec!["component.wit".to_string()],
            entries: Vec::new(),
            total_source_bytes: 0,
            tree_digest: ContentDigest::from_bytes(workspace.workspace_id.as_bytes()),
        }
    }

    fn descriptor(
        service_id: &str,
        family: NativeServiceFamily,
        authority: AuthorityClass,
        operations: impl IntoIterator<Item = CapabilityOperation>,
    ) -> CapabilityServiceDescriptor {
        CapabilityServiceDescriptor::new(
            service_id,
            family,
            "scope-a",
            authority,
            ApprovalClass::AutoAllowed,
            operations,
            IdempotencyContract::SingleAttemptNoAutomaticRetry,
            TimeoutBehavior::Cooperative,
            format!("test-implementation:{service_id}"),
        )
        .expect("valid descriptor")
    }

    fn identity(service_id: &str, invocation_id: &str) -> InvocationIdentity {
        InvocationIdentity {
            invocation_id: invocation_id.to_string(),
            idempotency_key: format!("key:{invocation_id}"),
            service_id: service_id.to_string(),
            scope_id: "scope-a".to_string(),
            caller_id: "test-caller".to_string(),
            authority: AuthorityClass::LocalMutate,
            approval: InvocationApproval::Automatic,
        }
    }

    fn snapshot_invocation(
        service_id: &str,
        invocation_id: &str,
        identity_scope: &str,
        request_scope: &str,
    ) -> CapabilityInvocation {
        let mut identity = identity(service_id, invocation_id);
        identity.scope_id = identity_scope.to_string();
        CapabilityInvocation {
            identity,
            budget: InvocationBudget::bounded(1_000),
            request: CapabilityRequest::SnapshotWorkspace(SnapshotWorkspaceRequest {
                workspace: ScopedWorkspaceRef {
                    scope_id: request_scope.to_string(),
                    workspace_id: "workspace-1".to_string(),
                },
            }),
        }
    }

    fn dependencies_with_workspace(
        workspace: Option<Arc<dyn CandidateWorkspacePort>>,
        clock: Arc<dyn ClockPort>,
    ) -> CapabilityServiceDependencies {
        let mut dependencies = CapabilityServiceDependencies::empty();
        dependencies.workspace = workspace;
        dependencies.clock = clock;
        dependencies
    }

    #[test]
    fn host_rejects_out_of_scope_identity_without_calling_the_port() {
        let test = TestDirectory::new("scope-rejection");
        let calls = Arc::new(AtomicUsize::new(0));
        let port = Arc::new(CountingWorkspacePort {
            calls: calls.clone(),
            failure: None,
        });
        let host = CapabilityServiceHost::open(
            test.root.join("host"),
            [descriptor(
                "build-service",
                NativeServiceFamily::Build,
                AuthorityClass::LocalMutate,
                [CapabilityOperation::WorkspaceSnapshot],
            )],
            dependencies_with_workspace(Some(port), Arc::new(ManualClock::at(100))),
        )
        .expect("open host");
        let invocation = snapshot_invocation("build-service", "scope-denied", "scope-a", "scope-b");
        let receipt = host
            .invoke(&invocation, CancellationToken::new())
            .expect("terminal receipt");

        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            receipt.outcome().failure_kind(),
            Some(ServiceFailureKind::ScopeDenied)
        );
        assert!(!receipt.outcome().is_success());
        let attestation = host.attest("scope-denied").expect("derive attestation");
        assert!(!attestation.terminal_success);
        assert_eq!(
            attestation.failure_kind,
            Some(ServiceFailureKind::ScopeDenied)
        );
    }

    #[test]
    fn missing_dependency_and_unadvertised_operation_never_fall_through_to_success() {
        let test = TestDirectory::new("no-fallthrough");
        let descriptor = descriptor(
            "build-service",
            NativeServiceFamily::Build,
            AuthorityClass::LocalMutate,
            [CapabilityOperation::WorkspaceSnapshot],
        );
        let mut dependencies = CapabilityServiceDependencies::empty();
        dependencies.clock = Arc::new(ManualClock::at(100));
        let host = CapabilityServiceHost::open(test.root.join("host"), [descriptor], dependencies)
            .expect("open host");

        let missing = host
            .invoke(
                &snapshot_invocation("build-service", "missing-dependency", "scope-a", "scope-a"),
                CancellationToken::new(),
            )
            .expect("unavailable receipt");
        assert_eq!(
            missing.outcome().failure_kind(),
            Some(ServiceFailureKind::Unavailable)
        );

        let mut open_identity = identity("build-service", "not-advertised");
        open_identity.authority = AuthorityClass::LocalMutate;
        let unsupported = host
            .invoke(
                &CapabilityInvocation {
                    identity: open_identity,
                    budget: InvocationBudget::bounded(1_000),
                    request: CapabilityRequest::OpenWorkspace(OpenWorkspaceRequest {
                        workspace: ScopedWorkspaceRef {
                            scope_id: "scope-a".to_string(),
                            workspace_id: "workspace-2".to_string(),
                        },
                    }),
                },
                CancellationToken::new(),
            )
            .expect("unsupported receipt");
        assert_eq!(
            unsupported.outcome().failure_kind(),
            Some(ServiceFailureKind::Unsupported)
        );
    }

    #[test]
    fn factory_boundary_preserves_exact_bytes_and_blocks_unapproved_promotion() {
        let test = TestDirectory::new("factory-boundary");
        let backend = Arc::new(FixtureFactoryEvolutionPort::default());
        let descriptors = [
            CapabilityServiceDescriptor::new(
                "factory-execution",
                NativeServiceFamily::Validation,
                "scope-a",
                AuthorityClass::Observe,
                ApprovalClass::AutoAllowed,
                [
                    CapabilityOperation::FactoryExecute,
                    CapabilityOperation::FactoryProviderProposal,
                    CapabilityOperation::FactoryShadow,
                ],
                IdempotencyContract::IdempotentAtLeastOnce,
                TimeoutBehavior::Cooperative,
                "test-implementation:factory-execution",
            )
            .expect("valid factory execution descriptor"),
            CapabilityServiceDescriptor::new(
                "factory-promotion",
                NativeServiceFamily::Operations,
                "scope-a",
                AuthorityClass::PromotionControl,
                ApprovalClass::HumanRequired,
                [CapabilityOperation::FactoryActivate],
                IdempotencyContract::IdempotentAtLeastOnce,
                TimeoutBehavior::Cooperative,
                "test-implementation:factory-promotion",
            )
            .expect("valid factory promotion descriptor"),
        ];
        let mut dependencies = CapabilityServiceDependencies::empty();
        dependencies.factory_evolution = Some(backend.clone());
        dependencies.clock = Arc::new(ManualClock::at(100));
        let host = CapabilityServiceHost::open(test.root.join("host"), descriptors, dependencies)
            .expect("open factory host");
        let exact_request_bytes = b"\0opaque\nfactory-request\xff".to_vec();
        let request = FactoryEffectRequest::new(
            "scope-a",
            "factory-a",
            "effect:shadow:1",
            exact_request_bytes.clone(),
        );
        let shadow = CapabilityInvocation {
            identity: InvocationIdentity {
                invocation_id: "factory-shadow".to_string(),
                idempotency_key: "factory-shadow-key".to_string(),
                service_id: "factory-execution".to_string(),
                scope_id: "scope-a".to_string(),
                caller_id: "test-caller".to_string(),
                authority: AuthorityClass::Observe,
                approval: InvocationApproval::Automatic,
            },
            budget: InvocationBudget::bounded(1_000),
            request: CapabilityRequest::FactoryShadow(request.clone()),
        };
        let receipt = host
            .invoke(&shadow, CancellationToken::new())
            .expect("invoke factory shadow");
        assert!(matches!(
            receipt.outcome(),
            InvocationOutcome::Succeeded {
                result: CapabilitySuccess::FactoryEffect(result)
            } if result.logical_effect_id == request.logical_effect_id
                && result.exact_request_digest == request.exact_request_digest
        ));
        assert_eq!(
            backend
                .calls
                .lock()
                .expect("read fixture factory calls")
                .as_slice(),
            &[(CapabilityOperation::FactoryShadow, request.clone())]
        );
        assert_eq!(
            backend.calls.lock().unwrap()[0].1.exact_request_bytes,
            exact_request_bytes
        );

        let mut digest_mismatch_request = FactoryEffectRequest::new(
            "scope-a",
            "factory-a",
            "effect:shadow:digest-mismatch",
            b"original".to_vec(),
        );
        digest_mismatch_request.exact_request_bytes = b"altered".to_vec();
        let digest_mismatch = CapabilityInvocation {
            identity: InvocationIdentity {
                invocation_id: "factory-shadow-digest-mismatch".to_string(),
                idempotency_key: "factory-shadow-digest-mismatch-key".to_string(),
                service_id: "factory-execution".to_string(),
                scope_id: "scope-a".to_string(),
                caller_id: "test-caller".to_string(),
                authority: AuthorityClass::Observe,
                approval: InvocationApproval::Automatic,
            },
            budget: InvocationBudget::bounded(1_000),
            request: CapabilityRequest::FactoryShadow(digest_mismatch_request),
        };
        let mismatch_receipt = host
            .invoke(&digest_mismatch, CancellationToken::new())
            .expect("digest mismatch is a terminal receipt");
        assert_eq!(
            mismatch_receipt.outcome().failure_kind(),
            Some(ServiceFailureKind::Failed)
        );
        assert_eq!(backend.calls.lock().unwrap().len(), 1);

        let blocked = CapabilityInvocation {
            identity: InvocationIdentity {
                invocation_id: "factory-activate-blocked".to_string(),
                idempotency_key: "factory-activate-blocked-key".to_string(),
                service_id: "factory-promotion".to_string(),
                scope_id: "scope-a".to_string(),
                caller_id: "test-caller".to_string(),
                authority: AuthorityClass::PromotionControl,
                approval: InvocationApproval::Automatic,
            },
            budget: InvocationBudget::bounded(1_000),
            request: CapabilityRequest::FactoryActivate(FactoryEffectRequest::new(
                "scope-a",
                "factory-a",
                "effect:activate:1",
                b"activate".to_vec(),
            )),
        };
        let blocked_receipt = host
            .invoke(&blocked, CancellationToken::new())
            .expect("approval block is a terminal receipt");
        assert_eq!(
            blocked_receipt.outcome().failure_kind(),
            Some(ServiceFailureKind::ApprovalBlocked)
        );
        assert_eq!(backend.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn explicitly_unavailable_registered_service_never_calls_its_effect_owner() {
        let test = TestDirectory::new("configured-unavailable");
        let calls = Arc::new(AtomicUsize::new(0));
        let port = Arc::new(CountingWorkspacePort {
            calls: Arc::clone(&calls),
            failure: None,
        });
        let mut dependencies =
            dependencies_with_workspace(Some(port), Arc::new(ManualClock::at(100)));
        dependencies
            .unavailable_service_ids
            .insert("build-service".to_string());
        let host = CapabilityServiceHost::open(
            test.root.join("host"),
            [descriptor(
                "build-service",
                NativeServiceFamily::Build,
                AuthorityClass::LocalMutate,
                [CapabilityOperation::WorkspaceSnapshot],
            )],
            dependencies,
        )
        .expect("open host with unavailable registered service");

        assert_eq!(
            host.health("build-service").unwrap().availability,
            ServiceAvailability::Unavailable
        );
        let receipt = host
            .invoke(
                &snapshot_invocation(
                    "build-service",
                    "configured-unavailable",
                    "scope-a",
                    "scope-a",
                ),
                CancellationToken::new(),
            )
            .expect("unavailability is a durable terminal receipt");
        assert_eq!(
            receipt.outcome().failure_kind(),
            Some(ServiceFailureKind::Unavailable)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn explicitly_unsupported_port_result_is_terminal_not_success_shaped() {
        let test = TestDirectory::new("explicit-unsupported");
        let calls = Arc::new(AtomicUsize::new(0));
        let port = Arc::new(CountingWorkspacePort {
            calls: calls.clone(),
            failure: Some(ServiceFailure::unsupported(
                "backend_unsupported",
                "configured backend cannot execute this operation",
            )),
        });
        let host = CapabilityServiceHost::open(
            test.root.join("host"),
            [descriptor(
                "build-service",
                NativeServiceFamily::Build,
                AuthorityClass::LocalMutate,
                [CapabilityOperation::WorkspaceSnapshot],
            )],
            dependencies_with_workspace(Some(port), Arc::new(ManualClock::at(100))),
        )
        .expect("open host");
        let receipt = host
            .invoke(
                &snapshot_invocation("build-service", "unsupported", "scope-a", "scope-a"),
                CancellationToken::new(),
            )
            .expect("terminal receipt");

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            receipt.outcome().failure_kind(),
            Some(ServiceFailureKind::Unsupported)
        );
    }

    #[test]
    fn cancellation_and_missing_approval_are_terminal_before_port_effects() {
        let test = TestDirectory::new("cancel-approval");
        let calls = Arc::new(AtomicUsize::new(0));
        let port = Arc::new(CountingWorkspacePort {
            calls: calls.clone(),
            failure: None,
        });
        let descriptor = CapabilityServiceDescriptor::new(
            "build-service",
            NativeServiceFamily::Build,
            "scope-a",
            AuthorityClass::LocalMutate,
            ApprovalClass::SupervisorAllowed,
            [CapabilityOperation::WorkspaceSnapshot],
            IdempotencyContract::SingleAttemptNoAutomaticRetry,
            TimeoutBehavior::Cooperative,
            "test-implementation:build-service",
        )
        .unwrap();
        let host = CapabilityServiceHost::open(
            test.root.join("host"),
            [descriptor],
            dependencies_with_workspace(Some(port), Arc::new(ManualClock::at(100))),
        )
        .unwrap();

        let no_approval = host
            .invoke(
                &snapshot_invocation("build-service", "approval-blocked", "scope-a", "scope-a"),
                CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            no_approval.outcome().failure_kind(),
            Some(ServiceFailureKind::ApprovalBlocked)
        );

        let mut approved = snapshot_invocation("build-service", "cancelled", "scope-a", "scope-a");
        approved.identity.approval = InvocationApproval::Granted {
            approval_ref: "approval:1".to_string(),
            class: ApprovalClass::SupervisorAllowed,
        };
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = host.invoke(&approved, cancellation).unwrap();
        assert_eq!(
            cancelled.outcome().failure_kind(),
            Some(ServiceFailureKind::Cancelled)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn idempotency_and_restart_return_the_same_durable_receipt() {
        let test = TestDirectory::new("idempotency-restart");
        let host_root = test.root.join("host");
        let evidence_root = test.root.join("evidence");
        let descriptor = descriptor(
            "continuity-service",
            NativeServiceFamily::Continuity,
            AuthorityClass::LocalMutate,
            [CapabilityOperation::EvidencePublish],
        );
        let evidence = Arc::new(
            LocalEvidenceStore::open("scope-a", &evidence_root).expect("open evidence store"),
        );
        let invocation = CapabilityInvocation {
            identity: identity("continuity-service", "publish-1"),
            budget: InvocationBudget::bounded(1_000),
            request: CapabilityRequest::PublishEvidence(PublishEvidenceRequest {
                scope_id: "scope-a".to_string(),
                evidence_id: "evidence-1".to_string(),
                media_type: "application/json".to_string(),
                subject_refs: vec!["subject:1".to_string()],
                payload: br#"{"passed":true}"#.to_vec(),
                expected_digest: None,
            }),
        };
        let mut dependencies = CapabilityServiceDependencies::empty();
        dependencies.evidence = Some(evidence.clone());
        dependencies.clock = Arc::new(ManualClock::at(100));
        let host = CapabilityServiceHost::open(&host_root, [descriptor.clone()], dependencies)
            .expect("open host");
        let first = host
            .invoke(&invocation, CancellationToken::new())
            .expect("publish evidence");
        let repeated = host
            .invoke(&invocation, CancellationToken::new())
            .expect("idempotent retry");
        assert_eq!(repeated, first);
        let health = host.health("continuity-service").unwrap();
        assert_eq!(health.successful_invocations, 1);
        assert_eq!(health.failed_invocations, 0);
        assert_eq!(health.lifecycle, ServiceLifecycleState::Ready);

        let mut conflicting = invocation.clone();
        if let CapabilityRequest::PublishEvidence(request) = &mut conflicting.request {
            request.payload = b"different".to_vec();
        }
        assert!(matches!(
            host.invoke(&conflicting, CancellationToken::new()),
            Err(CapabilityHostError::IdempotencyConflict { .. })
        ));
        drop(host);

        let mut restarted_dependencies = CapabilityServiceDependencies::empty();
        restarted_dependencies.evidence = Some(evidence);
        restarted_dependencies.clock = Arc::new(ManualClock::at(200));
        let restarted =
            CapabilityServiceHost::open(&host_root, [descriptor], restarted_dependencies)
                .expect("reopen host");
        assert_eq!(restarted.receipt("publish-1").unwrap(), first);
        assert_eq!(
            restarted
                .health("continuity-service")
                .unwrap()
                .successful_invocations,
            1
        );
        assert_eq!(
            restarted
                .invoke(&invocation, CancellationToken::new())
                .unwrap(),
            first
        );
    }

    #[test]
    fn terminal_invocation_input_reloads_exactly_across_restart() {
        let test = TestDirectory::new("invocation-input-restart");
        let host_root = test.root.join("host");
        let service = descriptor(
            "build-service",
            NativeServiceFamily::Build,
            AuthorityClass::LocalMutate,
            [CapabilityOperation::WorkspaceSnapshot],
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let port = Arc::new(CountingWorkspacePort {
            calls,
            failure: None,
        });
        let invocation =
            snapshot_invocation("build-service", "recover-input", "scope-a", "scope-a");
        let host = CapabilityServiceHost::open(
            &host_root,
            [service.clone()],
            dependencies_with_workspace(Some(port.clone()), Arc::new(ManualClock::at(100))),
        )
        .expect("open host");
        let receipt = host
            .invoke(&invocation, CancellationToken::new())
            .expect("persist terminal invocation");
        let input_bytes = read_regular_file(&host.root.join(&receipt.provenance().input_ref))
            .expect("read exact persisted input bytes");
        assert_eq!(
            input_bytes,
            serde_json::to_vec(&invocation).expect("encode invocation")
        );
        assert_eq!(
            ContentDigest::from_bytes(&input_bytes),
            *receipt.input_digest()
        );
        assert_eq!(
            host.invocation_input("recover-input")
                .expect("reload terminal invocation input"),
            invocation
        );
        drop(host);

        let restarted = CapabilityServiceHost::open(
            &host_root,
            [service],
            dependencies_with_workspace(Some(port), Arc::new(ManualClock::at(200))),
        )
        .expect("restart host");
        assert_eq!(
            restarted
                .invocation_input("recover-input")
                .expect("reload exact input after restart"),
            invocation
        );
    }

    #[test]
    fn invocation_input_requires_a_terminal_invocation_id() {
        let test = TestDirectory::new("invocation-input-missing");
        let host = CapabilityServiceHost::open(
            test.root.join("host"),
            [descriptor(
                "build-service",
                NativeServiceFamily::Build,
                AuthorityClass::LocalMutate,
                [CapabilityOperation::WorkspaceSnapshot],
            )],
            dependencies_with_workspace(None, Arc::new(ManualClock::at(100))),
        )
        .expect("open host");

        assert!(matches!(
            host.invocation_input("missing"),
            Err(CapabilityHostError::ReceiptNotFound { invocation_id })
                if invocation_id == "missing"
        ));
    }

    #[test]
    fn invocation_input_rejects_tampered_persisted_bytes() {
        let test = TestDirectory::new("invocation-input-tamper");
        let calls = Arc::new(AtomicUsize::new(0));
        let port = Arc::new(CountingWorkspacePort {
            calls,
            failure: None,
        });
        let host = CapabilityServiceHost::open(
            test.root.join("host"),
            [descriptor(
                "build-service",
                NativeServiceFamily::Build,
                AuthorityClass::LocalMutate,
                [CapabilityOperation::WorkspaceSnapshot],
            )],
            dependencies_with_workspace(Some(port), Arc::new(ManualClock::at(100))),
        )
        .expect("open host");
        let invocation = snapshot_invocation("build-service", "tamper-input", "scope-a", "scope-a");
        let receipt = host
            .invoke(&invocation, CancellationToken::new())
            .expect("persist terminal invocation");
        let mut altered = invocation;
        if let CapabilityRequest::SnapshotWorkspace(request) = &mut altered.request {
            request.workspace.workspace_id = "different-workspace".to_string();
        }
        fs::write(
            host.root.join(&receipt.provenance().input_ref),
            serde_json::to_vec(&altered).expect("encode altered invocation"),
        )
        .expect("tamper input blob");

        assert!(matches!(
            host.invocation_input("tamper-input"),
            Err(CapabilityHostError::CorruptState(_))
        ));
    }

    #[test]
    fn receipt_attestation_fails_if_durable_receipt_bytes_are_tampered() {
        let test = TestDirectory::new("receipt-tamper");
        let calls = Arc::new(AtomicUsize::new(0));
        let port = Arc::new(CountingWorkspacePort {
            calls,
            failure: None,
        });
        let host = CapabilityServiceHost::open(
            test.root.join("host"),
            [descriptor(
                "build-service",
                NativeServiceFamily::Build,
                AuthorityClass::LocalMutate,
                [CapabilityOperation::WorkspaceSnapshot],
            )],
            dependencies_with_workspace(Some(port), Arc::new(ManualClock::at(100))),
        )
        .unwrap();
        let receipt = host
            .invoke(
                &snapshot_invocation("build-service", "tamper-me", "scope-a", "scope-a"),
                CancellationToken::new(),
            )
            .unwrap();
        fs::write(
            host.root.join(&receipt.provenance().receipt_ref),
            b"{\"tampered\":true}",
        )
        .unwrap();

        assert!(host.receipt("tamper-me").is_err());
        assert!(host.attest("tamper-me").is_err());
    }

    #[test]
    fn evidence_store_publishes_resolves_and_reloads_exact_bytes() {
        let test = TestDirectory::new("evidence");
        let root = test.root.join("store");
        let clock: Arc<dyn ClockPort> = Arc::new(ManualClock::at(10));
        let control = InvocationControl::new(10, 1_000, clock, CancellationToken::new());
        let store = LocalEvidenceStore::open("scope-a", &root).unwrap();
        let payload = b"actual validation evidence".to_vec();
        let request = PublishEvidenceRequest {
            scope_id: "scope-a".to_string(),
            evidence_id: "validation-1".to_string(),
            media_type: "application/octet-stream".to_string(),
            subject_refs: vec!["package:1".to_string()],
            expected_digest: Some(ContentDigest::from_bytes(&payload)),
            payload: payload.clone(),
        };
        let record = store.publish(&request, &control).unwrap();
        drop(store);

        let reopened = LocalEvidenceStore::open("scope-a", &root).unwrap();
        let resolved = reopened
            .resolve(
                &ResolveEvidenceRequest {
                    scope_id: "scope-a".to_string(),
                    evidence_id: record.evidence_id.clone(),
                    expected_digest: record.content_digest.clone(),
                },
                &control,
            )
            .unwrap();
        assert_eq!(resolved.payload, payload);
        assert_eq!(resolved.record, record);
        assert!(matches!(
            reopened.resolve(
                &ResolveEvidenceRequest {
                    scope_id: "scope-b".to_string(),
                    evidence_id: "validation-1".to_string(),
                    expected_digest: ContentDigest::from_bytes(&payload),
                },
                &control,
            ),
            Err(ServiceFailure {
                kind: ServiceFailureKind::ScopeDenied,
                ..
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_executor_enforces_allowlist_timeout_and_output_limits() {
        let test = TestDirectory::new("commands");
        let workspaces = test.root.join("workspaces");
        fs::create_dir(&workspaces).unwrap();
        fs::create_dir(workspaces.join("workspace-1")).unwrap();
        let commands = [
            AllowedCommand::inspect("printf", "/usr/bin/printf", Vec::new(), true).unwrap(),
            AllowedCommand::inspect("sleep", "/bin/sleep", Vec::new(), true).unwrap(),
            AllowedCommand::inspect("false", "/usr/bin/false", Vec::new(), false).unwrap(),
        ];
        let executor = LocalBoundedCommandExecutor::new(
            "scope-a",
            &workspaces,
            commands,
            CommandPolicy {
                max_timeout_ms: 2_000,
                max_stdout_bytes: 1_024,
                max_stderr_bytes: 1_024,
                max_argument_bytes: 1_024,
                max_arguments: 8,
                poll_interval_ms: 2,
            },
        )
        .unwrap();
        let control = InvocationControl::new(
            SystemClock.now_ms(),
            2_000,
            Arc::new(SystemClock),
            CancellationToken::new(),
        );
        let base = ExecuteCommandRequest {
            workspace: ScopedWorkspaceRef {
                scope_id: "scope-a".to_string(),
                workspace_id: "workspace-1".to_string(),
            },
            command_id: "printf".to_string(),
            arguments: vec!["hello".to_string()],
            relative_working_directory: PathBuf::new(),
            limits: CommandLimits {
                timeout_ms: 1_000,
                max_stdout_bytes: 64,
                max_stderr_bytes: 64,
                max_argument_bytes: 64,
            },
        };
        let success = executor.execute(&base, &control).unwrap();
        assert_eq!(success.status, CommandTerminalStatus::ExitedZero);
        assert_eq!(success.stdout.captured_bytes, b"hello");

        let mut not_allowlisted = base.clone();
        not_allowlisted.command_id = "shell".to_string();
        assert!(matches!(
            executor.execute(&not_allowlisted, &control),
            Err(ServiceFailure {
                kind: ServiceFailureKind::Unsupported,
                ..
            })
        ));

        let mut output_limited = base.clone();
        output_limited.arguments = vec!["0123456789".to_string()];
        output_limited.limits.max_stdout_bytes = 4;
        let limited = executor.execute(&output_limited, &control).unwrap();
        assert_eq!(limited.status, CommandTerminalStatus::OutputLimitExceeded);
        assert!(limited.stdout.truncated);
        assert_eq!(limited.stdout.captured_bytes, b"0123");

        let mut timed_out = base.clone();
        timed_out.command_id = "sleep".to_string();
        timed_out.arguments = vec!["1".to_string()];
        timed_out.limits.timeout_ms = 20;
        let timeout = executor.execute(&timed_out, &control).unwrap();
        assert_eq!(timeout.status, CommandTerminalStatus::TimedOut);

        let mut nonzero = base;
        nonzero.command_id = "false".to_string();
        nonzero.arguments.clear();
        let failed = executor.execute(&nonzero, &control).unwrap();
        assert_eq!(failed.status, CommandTerminalStatus::ExitedNonzero);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_executor_rejects_symlink_workspace_escape() {
        use std::os::unix::fs::symlink;

        let test = TestDirectory::new("command-symlink");
        let workspaces = test.root.join("workspaces");
        fs::create_dir(&workspaces).unwrap();
        let outside = test.root.join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, workspaces.join("workspace-1")).unwrap();
        let executor = LocalBoundedCommandExecutor::new(
            "scope-a",
            &workspaces,
            [AllowedCommand::inspect("printf", "/usr/bin/printf", Vec::new(), true).unwrap()],
            CommandPolicy::default(),
        )
        .unwrap();
        let control = InvocationControl::new(
            SystemClock.now_ms(),
            1_000,
            Arc::new(SystemClock),
            CancellationToken::new(),
        );
        let result = executor.execute(
            &ExecuteCommandRequest {
                workspace: ScopedWorkspaceRef {
                    scope_id: "scope-a".to_string(),
                    workspace_id: "workspace-1".to_string(),
                },
                command_id: "printf".to_string(),
                arguments: vec!["unsafe".to_string()],
                relative_working_directory: PathBuf::new(),
                limits: CommandLimits {
                    timeout_ms: 500,
                    max_stdout_bytes: 64,
                    max_stderr_bytes: 64,
                    max_argument_bytes: 64,
                },
            },
            &control,
        );
        assert!(matches!(
            result,
            Err(ServiceFailure {
                code,
                ..
            }) if code == "working_directory_symlink"
        ));
        assert!(fs::read_dir(outside).unwrap().next().is_none());
    }

    #[test]
    fn scheduling_is_explicitly_unsupported_without_m2_executor() {
        let control = InvocationControl::new(
            10,
            1_000,
            Arc::new(ManualClock::at(10)),
            CancellationToken::new(),
        );
        let result = UnsupportedSchedulingPort.schedule(
            &ScheduleJobRequest {
                scope_id: "scope-a".to_string(),
                schedule_id: "schedule-1".to_string(),
                due_at_ms: 20,
                payload_digest: ContentDigest::from_bytes(b"payload"),
            },
            &control,
        );
        assert!(matches!(
            result,
            Err(ServiceFailure {
                kind: ServiceFailureKind::Unsupported,
                ..
            })
        ));
    }

    #[test]
    fn restart_reconciles_in_flight_invocation_to_explicit_failure() {
        let test = TestDirectory::new("interrupted");
        let host_root = test.root.join("host");
        let service_descriptor = descriptor(
            "build-service",
            NativeServiceFamily::Build,
            AuthorityClass::LocalMutate,
            [CapabilityOperation::WorkspaceSnapshot],
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let port = Arc::new(CountingWorkspacePort {
            calls,
            failure: None,
        });
        let host = CapabilityServiceHost::open(
            &host_root,
            [service_descriptor.clone()],
            dependencies_with_workspace(Some(port.clone()), Arc::new(ManualClock::at(100))),
        )
        .unwrap();
        let invocation = snapshot_invocation("build-service", "interrupted", "scope-a", "scope-a");
        let bytes = serde_json::to_vec(&invocation).unwrap();
        let input_digest = ContentDigest::from_bytes(&bytes);
        host.persist_content(HOST_INPUT_DIRECTORY, &input_digest, &bytes)
            .unwrap();
        {
            let mut state = host.lock_state().unwrap();
            state.invocations.push(DurableInvocation {
                identity: invocation.identity.clone(),
                family: NativeServiceFamily::Build,
                operation: CapabilityOperation::WorkspaceSnapshot,
                input_digest,
                started_at_ms: 100,
                receipt: None,
            });
            write_host_state(&host.root, &state).unwrap();
        }
        drop(host);

        let restarted = CapabilityServiceHost::open(
            &host_root,
            [service_descriptor],
            dependencies_with_workspace(Some(port), Arc::new(ManualClock::at(200))),
        )
        .unwrap();
        let receipt = restarted.receipt("interrupted").unwrap();
        assert_eq!(
            receipt.outcome().failure_kind(),
            Some(ServiceFailureKind::Failed)
        );
        let InvocationOutcome::Terminal { failure } = receipt.outcome() else {
            panic!("interrupted invocation must be terminal");
        };
        assert_eq!(failure.code, "interrupted_by_restart");
    }

    #[test]
    fn real_m1_adapters_build_prove_review_deploy_observe_and_rollback() {
        let test = TestDirectory::new("real-adapters");
        let fixture = fixture_root();
        let candidate_service = Arc::new(
            CandidateWorkspaceService::bootstrap(test.root.join("candidate-service")).unwrap(),
        );
        let workspace_adapter = M1CandidateWorkspaceAdapter::new(
            "scope-a",
            fixture.join("template"),
            candidate_service.clone(),
        )
        .unwrap();
        let clock: Arc<dyn ClockPort> = Arc::new(SystemClock);
        let control =
            InvocationControl::new(clock.now_ms(), 30_000, clock, CancellationToken::new());
        for workspace_id in ["incumbent", "challenger"] {
            workspace_adapter
                .open_workspace(
                    &OpenWorkspaceRequest {
                        workspace: ScopedWorkspaceRef {
                            scope_id: "scope-a".to_string(),
                            workspace_id: workspace_id.to_string(),
                        },
                    },
                    &control,
                )
                .unwrap();
        }
        let challenger_snapshot = candidate_service.snapshot("challenger").unwrap();
        workspace_adapter
            .patch_workspace(
                &PatchWorkspaceRequest {
                    workspace: ScopedWorkspaceRef {
                        scope_id: "scope-a".to_string(),
                        workspace_id: "challenger".to_string(),
                    },
                    expected_before_digest: challenger_snapshot
                        .entry(COMPONENT_WAT_PATH)
                        .unwrap()
                        .content_digest
                        .clone(),
                    replacement_bytes: fs::read(fixture.join("candidates/increment.wat")).unwrap(),
                },
                &control,
            )
            .unwrap();

        let packages = Arc::new(
            LocalBuildPackagingService::open(
                "scope-a",
                test.root.join("packages"),
                candidate_service.clone(),
            )
            .unwrap(),
        );
        let incumbent_build = packages
            .build_candidate(
                &BuildCandidateRequest {
                    workspace: ScopedWorkspaceRef {
                        scope_id: "scope-a".to_string(),
                        workspace_id: "incumbent".to_string(),
                    },
                },
                &control,
            )
            .unwrap();
        let challenger_build = packages
            .build_candidate(
                &BuildCandidateRequest {
                    workspace: ScopedWorkspaceRef {
                        scope_id: "scope-a".to_string(),
                        workspace_id: "challenger".to_string(),
                    },
                },
                &control,
            )
            .unwrap();
        let incumbent_package = packages
            .publish_package(
                &PublishPackageRequest {
                    workspace: ScopedWorkspaceRef {
                        scope_id: "scope-a".to_string(),
                        workspace_id: "incumbent".to_string(),
                    },
                    expected_package_digest: incumbent_build.package_digest.clone(),
                },
                &control,
            )
            .unwrap();
        let challenger_package = packages
            .publish_package(
                &PublishPackageRequest {
                    workspace: ScopedWorkspaceRef {
                        scope_id: "scope-a".to_string(),
                        workspace_id: "challenger".to_string(),
                    },
                    expected_package_digest: challenger_build.package_digest.clone(),
                },
                &control,
            )
            .unwrap();
        assert!(
            packages
                .verify_package(
                    &VerifyPackageRequest {
                        scope_id: "scope-a".to_string(),
                        package_digest: challenger_package.package_digest.clone(),
                    },
                    &control,
                )
                .unwrap()
                .runnable_component
        );

        let validation = LocalValidationReviewService::open(
            "scope-a",
            test.root.join("validation"),
            packages.clone(),
        )
        .unwrap();
        let suite = increment_suite();
        let incumbent_proving = validation
            .prove_package(
                &ProvePackageRequest {
                    scope_id: "scope-a".to_string(),
                    package_digest: incumbent_package.package_digest.clone(),
                    suite: suite.clone(),
                },
                &control,
            )
            .unwrap();
        let challenger_proving = validation
            .prove_package(
                &ProvePackageRequest {
                    scope_id: "scope-a".to_string(),
                    package_digest: challenger_package.package_digest.clone(),
                    suite: suite.clone(),
                },
                &control,
            )
            .unwrap();
        assert!(!incumbent_proving.summary.all_satisfied);
        assert!(challenger_proving.summary.all_satisfied);
        let comparison = validation
            .compare_proving(
                &CompareProvingRequest {
                    scope_id: "scope-a".to_string(),
                    suite: suite.clone(),
                    incumbent_proving_digest: incumbent_proving.record_digest.clone(),
                    challenger_proving_digest: challenger_proving.record_digest.clone(),
                },
                &control,
            )
            .unwrap();
        let review = validation
            .review_candidate(
                &ReviewCandidateRequest {
                    scope_id: "scope-a".to_string(),
                    suite,
                    comparison_digest: comparison.record_digest.clone(),
                },
                &control,
            )
            .unwrap();
        assert_eq!(review.decision, ReviewDecision::Approved);

        let deployment_candidates = test.root.join("deployment-candidates");
        fs::create_dir(&deployment_candidates).unwrap();
        let deployment = Arc::new(
            LocalDeploymentService::open(test.root.join("deployment"), &deployment_candidates)
                .unwrap(),
        );
        let deployment_adapter = LocalDeploymentRollbackAdapter::open(
            "scope-a",
            "reference-task",
            deployment.clone(),
            packages,
        )
        .unwrap();
        let deployment_ref = ScopedDeploymentRef {
            scope_id: "scope-a".to_string(),
            deployment_id: "reference-task".to_string(),
        };
        deployment_adapter
            .initialize(
                &InitializeDeploymentRequest {
                    deployment: deployment_ref.clone(),
                    operation_id: "initialize-1".to_string(),
                    incumbent_package_digest: incumbent_package.package_digest.clone(),
                },
                &control,
            )
            .unwrap();
        let activation = deployment_adapter
            .activate(
                &ActivateDeploymentRequest {
                    deployment: deployment_ref.clone(),
                    operation_id: "activation-1".to_string(),
                    package_digest: challenger_package.package_digest.clone(),
                    expected_active_digest: incumbent_package.package_digest.clone(),
                    approval_ref: format!("review:{}", review.review_digest),
                    comparison_ref: comparison.record_digest.to_string(),
                    observation_window_ref: "window:1".to_string(),
                },
                &control,
            )
            .unwrap();
        assert_eq!(
            ContentDigest::from_bytes(&deployment.read_active_bytes().unwrap()),
            challenger_package.package_digest
        );
        deployment_adapter
            .observe(
                &ObserveDeploymentRequest {
                    deployment: deployment_ref.clone(),
                    observation_id: "observation-1".to_string(),
                    activation_id: activation.operation_id.clone(),
                    expected_active_digest: challenger_package.package_digest,
                    outcome: ObservationOutcome::Healthy,
                    summary: "real reference execution remained healthy".to_string(),
                    evidence_bytes: br#"{"input":41,"output":42}"#.to_vec(),
                },
                &control,
            )
            .unwrap();
        deployment_adapter
            .rollback(
                &RollbackDeploymentRequest {
                    deployment: deployment_ref.clone(),
                    operation_id: "rollback-1".to_string(),
                    activation_id: activation.operation_id,
                    reason_ref: "operator:bounded-test".to_string(),
                },
                &control,
            )
            .unwrap();
        assert_eq!(
            ContentDigest::from_bytes(&deployment.read_active_bytes().unwrap()),
            incumbent_package.package_digest
        );
        let operations = deployment_adapter
            .inspect(
                &InspectOperationsRequest {
                    deployment: deployment_ref,
                },
                &control,
            )
            .unwrap();
        assert_eq!(operations.activation_count, 1);
        assert_eq!(operations.observation_count, 1);
        assert_eq!(operations.rollback_count, 1);
    }

    fn fixture_root() -> PathBuf {
        let source = PathBuf::from(file!());
        let absolute = if source.is_absolute() {
            source
        } else {
            std::env::current_dir().unwrap().join(source)
        };
        absolute
            .parent()
            .and_then(Path::parent)
            .expect("source file is beneath repository src")
            .join("artifacts/fixtures/m1-reference-component")
    }

    fn increment_suite() -> ValidationSuite {
        ValidationSuite::new(
            "m3-reference-transform-v1",
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
        .unwrap()
    }
}
