use crate::execution::artifact::{
    ArtifactDigest, GenerationArtifactBundle, validate_generation_artifact_bundle,
};
use crate::execution::closure_review::{
    AdversarialReviewRecord, ClaimBoundaryReviewPacket, ClosureCriteriaMatrix,
    ClosureDecisionRecord, ClosureDossier, EvidenceInventoryPacket, PublicationPolicyRecord,
    ResidualRiskRecord,
};
use crate::execution::component::ComponentBuildOutput;
use crate::execution::continuity_grounding::{
    ContradictionCarryForwardRecord, ModelContinuityBundle, OpenQuestionLedger,
    TurnGroundingPacket, VerifiedTurnMemoryUpdate,
};
use crate::execution::ecosystem::{
    CrossFactoryAdoptionDossier, EcosystemAdmissionProfile, EcosystemAdmissionRecord,
    EcosystemCompatibilityPersistenceRecord, EcosystemContinuityWindowRecord,
    EcosystemExchangeRouteLedger, EcosystemHealthLedger, EcosystemHealthSnapshot,
    EcosystemRollbackChoreographyRecord, EcosystemRollbackSymmetryRecord,
    EcosystemWorkspaceSnapshot, ExchangeRouteRecord, RouteCompatibilityCycle,
    RouteExchangeHistoryRecord, TrustProfile,
};
use crate::execution::factory::{
    FactoryActivationBundle, FactoryComparisonRecord, FactoryEvidencePacket, FactoryGenomeArtifact,
    FactoryLineageRecord, FactoryPhenotypeArtifact,
};
use crate::execution::factory_exchange::{
    CrossFactoryLineageImportRecord, FactoryCompatibilityDecision, FactoryExchangeEnvelope,
    FactoryIdentityManifest, ImportDispositionRecord, ImportedArtifactQuarantinePacket,
    MemoryExchangePacket, QuarantineFirstImportStateRecord,
};
use crate::execution::factory_program::{
    AdoptionWindowRecord, FactoryImprovementProgram, LaterFactoryCycleDossier,
    LaterFactoryGenerationAgenda, LineageHealthDossier, LineageHealthLedger,
    LongitudinalLineageDossier, ProgramBudgetHistoryRecord, ProgramContinuityWindowRecord,
    ProgramPolicyComplianceRecord, RecurringFactoryProgramRecord, RecursionBudgetRecord,
    RegressionReviewPacket, StopConditionRecord,
};
use crate::execution::factory_replication::{
    ChildFactoryDispositionRecord, ChildFactoryObservationWindowRecord,
    ChildFactoryQuarantineProtocolRecord, FactoryProvingRunRecord, FactoryReplicationCampaign,
    FactoryReplicationDecision, FactoryReplicationEvidencePacket, LaterFactoryCandidate,
};
use crate::execution::factory_runtime::{
    ActiveFactoryState, FactoryGovernanceTransitionRecord, FactoryQuarantineRecord,
    FactoryRollbackEnvelope,
};
use crate::execution::factory_validation::{
    FactoryValidationEvidence, FactoryValidationProfile, FactoryValidationRecord,
};
use crate::execution::governance::{
    V3SubstrateCompletionGate, V4SupervisoryShellCompletionGate,
    evaluate_v4_supervisory_shell_completion_gate,
};
use crate::execution::inference::{
    InferenceAttemptRecord, InferenceGenerationPolicy, InferenceParsedOutputRecord,
    InferenceProviderOutcomeRecord, InferenceProviderRegistryEntry, InferenceRawOutputRecord,
    InferenceRenderedPromptRecord, InferenceRequestBodyRecord,
    InferenceResponseSchemaPayloadRecord, InferenceToolCatalogPayloadRecord, InferenceTurnRequest,
    InferenceTurnResult, InferenceUsageRecord, ProviderDegradationRecord,
};
use crate::execution::launch::{
    AcceptanceTruthMatrix, CampaignAdmissionRecord, LaunchRefusalRecord, MigrationGateRecord,
    PathRetirementRecord, PathSupportClassification, ProgramToShellMapping, ResumeChainRecord,
    ShellDerivedExportBundle, ShellEvidenceSummary, TransitionalAdapterManifest,
    TransitionalTruthAnnotation, UnifiedLifecycleTransitionRecord, UniversalShellLaunchAssembly,
};
use crate::execution::memory_protocol::MemoryRetrievalTrace;
use crate::execution::native_services::{
    ServiceAttestationBundle, ServiceClosureDossier, ServiceFamilyManifest, ServiceHandleLease,
    WorkflowServiceClosureDossier, WorkflowSufficiencyRecord,
};
use crate::execution::operations::{
    ApprovalInboxRecord, ConsolidationJobRecord, ContinuityJobClassification, ContinuityJobRecord,
    DeferredDecisionBundle, LeaseExpiryRecord, PersistentJobLease, PersistentShellAuditPacket,
    PersistentShellOperationsDossier, ScheduledWakeRecord, SchedulerTickRecord,
    ShellEscalationRecord,
};
use crate::execution::phase02::{
    EcologyClosureWorkspacePacket, Phase02AcceptancePacket, ServiceClosureWorkspacePacket,
};
use crate::execution::phase03::{
    EcosystemClosureWorkspacePacket, Phase03ClosureReviewPacket, RecurringFactoryWorkspacePacket,
};
use crate::execution::recursive_factory_interface::{
    ArchitecturalDependencyStatement, InterfaceNativeRecursionClosureDossier,
    LlmFactoryProgramProfile, ModelDrivenFactoryCycleRecord, RecursiveLineageExecutionRecord,
};
use crate::execution::runtime_adapter::ActiveGenerationState;
use crate::execution::self_production::{SelfProductionCampaign, SuccessorProductionRecord};
use crate::execution::shell::ShellSessionBundle;
use crate::execution::shell_evidence::ShellEvidencePacket;
use crate::execution::tool_membrane::{
    ModelToolDefinition, OperatorOnlySurfaceRecord, ParsedTurnToolExecutionReceipt,
    ToolArgumentSchemaRecord, ToolCallLegalityRecord, ToolCatalogRecord,
    ToolExecutionContextRecord, ToolExecutionRecord, ToolExposureDecisionRecord,
    ToolResultSchemaRecord,
};
use crate::execution::turn_governance::{
    ModelApprovalRequestRecord, ModelAuthorityDecision, ModelDelegationPolicyRecord,
    ModelOutputQuarantineRecord, PendingGovernedTurnActionRecord, TurnCheckpointRecord,
};
use crate::execution::turn_package::{
    ContextBudgetRecord, ContextTruncationRecord, ParseRepairRecord, ParsedApprovalRequestRecord,
    ParsedProposalRecord, ParsedToolCallIntentRecord, ParsedTurnResult, PromptLayerRecord,
    PromptRenderingRecord, TurnPackage, TurnResponseSchemaRecord,
};
use crate::execution::validation::{ExecutionBackedValidationRecord, ExecutionComparisonBundle};
use crate::execution::worker_ecology::{
    CoordinatorPlanningRecord, EcologyHealthRecord, EcologyRecoveryRecord, EcologySnapshot,
    RoutingPacketRecord, SynthesisDossier, WorkLease, WorkerSpecializationCard,
};
use crate::execution::{
    AgendaStatus, AuditRecordClass, ChallengerEvaluationSession, ClosureInventory,
    CycleClosureDecision, EpochAdoptionRecord, EventFamily, ExecutionEvent, ExecutionSession,
    GenerationComparisonRecord, GenomeArtifact, MemoryArtifactPayload, MemoryStore,
    NativeSufficiencyEvidence, NativeSufficiencyGate, OwnershipMode, PhenotypeArtifact,
    PromotionAct, PromotionReadinessDecision, ReversalWindow, RollbackHandle, RunCheckpoint,
    SemanticValidationRecord, ShadowCampaign, TaskArtifact, TaskGraph, TopicBundleClass,
    V1CompletionGate, V1CompletionStatus, closure_inventory_is_complete,
    evaluate_native_sufficiency_with_evidence,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayableRuntimeState {
    pub session: ExecutionSession,
    pub root_task: TaskArtifact,
    pub task_graph: TaskGraph,
    pub memory_store: MemoryStore,
    pub latest_checkpoint: Option<RunCheckpoint>,
    pub event_log: Vec<ExecutionEvent>,
}

impl ReplayableRuntimeState {
    pub fn new(
        session: ExecutionSession,
        root_task: TaskArtifact,
        task_graph: TaskGraph,
        memory_store: MemoryStore,
        latest_checkpoint: Option<RunCheckpoint>,
        event_log: Vec<ExecutionEvent>,
    ) -> Self {
        Self {
            session,
            root_task,
            task_graph,
            memory_store,
            latest_checkpoint,
            event_log,
        }
    }

    pub fn validate_replayability(&self) -> Result<(), RuntimeStateValidationError> {
        if let Some(active_task_id) = &self.session.active_task_id {
            if active_task_id != &self.root_task.task_id {
                return Err(RuntimeStateValidationError::ActiveTaskMismatch {
                    session_task_id: active_task_id.clone(),
                    root_task_id: self.root_task.task_id.clone(),
                });
            }
        }

        match self.session.state {
            crate::execution::ExecutionSessionState::AwaitingApproval
                if self.session.pending_approval_refs.is_empty() =>
            {
                return Err(RuntimeStateValidationError::AwaitingApprovalWithoutPendingApproval);
            }
            crate::execution::ExecutionSessionState::AwaitingWorkerResult
                if self.session.outstanding_worker_refs.is_empty() =>
            {
                return Err(RuntimeStateValidationError::AwaitingWorkerWithoutOutstandingWorker);
            }
            crate::execution::ExecutionSessionState::AwaitingApproval
            | crate::execution::ExecutionSessionState::AwaitingWorkerResult
            | crate::execution::ExecutionSessionState::Blocked
                if self.session.blocked_reason.is_none() =>
            {
                return Err(RuntimeStateValidationError::BlockedStateWithoutReason {
                    state: format!("{:?}", self.session.state),
                });
            }
            _ => {}
        }

        if !self.session.pending_approval_refs.is_empty()
            && self.session.state != crate::execution::ExecutionSessionState::AwaitingApproval
        {
            return Err(
                RuntimeStateValidationError::PendingApprovalsOutsideAwaitingApproval {
                    state: format!("{:?}", self.session.state),
                },
            );
        }

        if !self.session.outstanding_worker_refs.is_empty()
            && self.session.state != crate::execution::ExecutionSessionState::AwaitingWorkerResult
        {
            return Err(
                RuntimeStateValidationError::OutstandingWorkersOutsideAwaitingWorkerResult {
                    state: format!("{:?}", self.session.state),
                },
            );
        }

        if let Some(checkpoint) = &self.latest_checkpoint {
            let Some(session_checkpoint_ref) = &self.session.latest_checkpoint_ref else {
                return Err(RuntimeStateValidationError::MissingLatestCheckpointRef);
            };

            if session_checkpoint_ref != &checkpoint.checkpoint_id {
                return Err(RuntimeStateValidationError::LatestCheckpointRefMismatch {
                    session_checkpoint_ref: session_checkpoint_ref.clone(),
                    checkpoint_id: checkpoint.checkpoint_id.clone(),
                });
            }

            if !checkpoint.matches_session(&self.session) {
                return Err(RuntimeStateValidationError::CheckpointHeaderMismatch {
                    checkpoint_id: checkpoint.checkpoint_id.clone(),
                });
            }

            if let Some(checkpoint_task_id) = checkpoint.active_task_refs.first() {
                if checkpoint_task_id != &self.root_task.task_id {
                    return Err(RuntimeStateValidationError::CheckpointTaskMismatch {
                        checkpoint_id: checkpoint.checkpoint_id.clone(),
                        checkpoint_task_id: checkpoint_task_id.clone(),
                        root_task_id: self.root_task.task_id.clone(),
                    });
                }
            }

            for approval_request_id in &self.session.pending_approval_refs {
                if !checkpoint.tracks_approval(approval_request_id) {
                    return Err(
                        RuntimeStateValidationError::PendingApprovalNotCheckpointed {
                            approval_request_id: approval_request_id.clone(),
                            checkpoint_id: checkpoint.checkpoint_id.clone(),
                        },
                    );
                }
            }

            for worker_id in &self.session.outstanding_worker_refs {
                if !checkpoint.tracks_worker(worker_id) {
                    return Err(
                        RuntimeStateValidationError::OutstandingWorkerNotCheckpointed {
                            worker_id: worker_id.clone(),
                            checkpoint_id: checkpoint.checkpoint_id.clone(),
                        },
                    );
                }
            }
        } else if self.session.latest_checkpoint_ref.is_some() {
            return Err(RuntimeStateValidationError::MissingLatestCheckpointRef);
        }

        for event in &self.event_log {
            if !event.matches_scope(
                &self.session.header.campaign_id,
                &self.session.header.epoch_id,
                &self.session.header.session_id,
            ) {
                return Err(RuntimeStateValidationError::EventScopeMismatch {
                    event_id: event.event_id.clone(),
                });
            }
        }

        Ok(())
    }

    pub fn events_for_task(&self, task_id: &str) -> Vec<&ExecutionEvent> {
        self.event_log
            .iter()
            .filter(|event| event.references_task(task_id))
            .collect()
    }

    pub fn count_events_in_family(&self, family: EventFamily) -> usize {
        self.event_log
            .iter()
            .filter(|event| event.family == family)
            .count()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowEvaluationBundle {
    pub shadow_campaign: ShadowCampaign,
    pub challenger_evaluation_session: ChallengerEvaluationSession,
    pub incumbent_runtime_state: ReplayableRuntimeState,
    pub challenger_runtime_state: ReplayableRuntimeState,
    pub comparison_record: GenerationComparisonRecord,
    pub sufficiency_evidence: NativeSufficiencyEvidence,
    pub promotion_readiness_decision: PromotionReadinessDecision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionActivationBundle {
    pub shadow_evaluation_bundle: ShadowEvaluationBundle,
    pub promotion_act: PromotionAct,
    pub epoch_adoption_record: EpochAdoptionRecord,
    pub reversal_window: ReversalWindow,
    pub promoted_runtime_state: ReplayableRuntimeState,
    pub successor_loop_comparison: GenerationComparisonRecord,
    pub successor_loop_evidence: NativeSufficiencyEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1CompletionBundle {
    pub promotion_activation_bundle: PromotionActivationBundle,
    pub closure_inventory: ClosureInventory,
    pub successor_genome: GenomeArtifact,
    pub successor_phenotype: PhenotypeArtifact,
    pub semantic_validation_record: SemanticValidationRecord,
    pub second_cycle_comparison: GenerationComparisonRecord,
    pub second_cycle_evidence: NativeSufficiencyEvidence,
    pub second_cycle_readiness: PromotionReadinessDecision,
    pub second_cycle_decision: CycleClosureDecision,
    pub second_cycle_promotion_act: Option<PromotionAct>,
    pub v1_completion_gate: V1CompletionGate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V4ShellEvidenceBundle {
    pub shell_session_bundle: ShellSessionBundle,
    pub shell_evidence_packet: ShellEvidencePacket,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V4SupervisoryShellBundle {
    pub shell_session_bundle: ShellSessionBundle,
    pub shell_evidence_packet: ShellEvidencePacket,
    pub completion_gate: V4SupervisoryShellCompletionGate,
}

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Serde(serde_json::Error),
    Validation(RuntimeStateValidationError),
}

impl Display for StorageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "storage I/O error: {error}"),
            Self::Serde(error) => write!(f, "storage serialization error: {error}"),
            Self::Validation(error) => write!(f, "storage validation error: {error}"),
        }
    }
}

impl Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(value)
    }
}

impl From<RuntimeStateValidationError> for StorageError {
    fn from(value: RuntimeStateValidationError) -> Self {
        Self::Validation(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeStateValidationError {
    MissingLatestCheckpointRef,
    LatestCheckpointRefMismatch {
        session_checkpoint_ref: String,
        checkpoint_id: String,
    },
    CheckpointHeaderMismatch {
        checkpoint_id: String,
    },
    ActiveTaskMismatch {
        session_task_id: String,
        root_task_id: String,
    },
    CheckpointTaskMismatch {
        checkpoint_id: String,
        checkpoint_task_id: String,
        root_task_id: String,
    },
    PendingApprovalNotCheckpointed {
        approval_request_id: String,
        checkpoint_id: String,
    },
    OutstandingWorkerNotCheckpointed {
        worker_id: String,
        checkpoint_id: String,
    },
    AwaitingApprovalWithoutPendingApproval,
    AwaitingWorkerWithoutOutstandingWorker,
    PendingApprovalsOutsideAwaitingApproval {
        state: String,
    },
    OutstandingWorkersOutsideAwaitingWorkerResult {
        state: String,
    },
    BlockedStateWithoutReason {
        state: String,
    },
    EventScopeMismatch {
        event_id: String,
    },
}

impl Display for RuntimeStateValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingLatestCheckpointRef => {
                write!(f, "runtime state is missing a latest checkpoint reference")
            }
            Self::LatestCheckpointRefMismatch {
                session_checkpoint_ref,
                checkpoint_id,
            } => write!(
                f,
                "runtime state checkpoint ref '{}' does not match checkpoint '{}'",
                session_checkpoint_ref, checkpoint_id
            ),
            Self::CheckpointHeaderMismatch { checkpoint_id } => write!(
                f,
                "checkpoint '{}' does not match the session header scope",
                checkpoint_id
            ),
            Self::ActiveTaskMismatch {
                session_task_id,
                root_task_id,
            } => write!(
                f,
                "runtime state active task '{}' does not match root task '{}'",
                session_task_id, root_task_id
            ),
            Self::CheckpointTaskMismatch {
                checkpoint_id,
                checkpoint_task_id,
                root_task_id,
            } => write!(
                f,
                "checkpoint '{}' tracks task '{}' instead of root task '{}'",
                checkpoint_id, checkpoint_task_id, root_task_id
            ),
            Self::PendingApprovalNotCheckpointed {
                approval_request_id,
                checkpoint_id,
            } => write!(
                f,
                "pending approval '{}' is missing from checkpoint '{}'",
                approval_request_id, checkpoint_id
            ),
            Self::OutstandingWorkerNotCheckpointed {
                worker_id,
                checkpoint_id,
            } => write!(
                f,
                "outstanding worker '{}' is missing from checkpoint '{}'",
                worker_id, checkpoint_id
            ),
            Self::AwaitingApprovalWithoutPendingApproval => write!(
                f,
                "runtime state cannot await approval without a pending approval ref"
            ),
            Self::AwaitingWorkerWithoutOutstandingWorker => write!(
                f,
                "runtime state cannot await a worker without an outstanding worker ref"
            ),
            Self::PendingApprovalsOutsideAwaitingApproval { state } => write!(
                f,
                "runtime state '{}' cannot retain pending approvals outside approval wait",
                state
            ),
            Self::OutstandingWorkersOutsideAwaitingWorkerResult { state } => write!(
                f,
                "runtime state '{}' cannot retain outstanding workers outside worker wait",
                state
            ),
            Self::BlockedStateWithoutReason { state } => {
                write!(f, "runtime state '{}' must include a blocked reason", state)
            }
            Self::EventScopeMismatch { event_id } => write!(
                f,
                "event '{}' does not match the runtime session scope",
                event_id
            ),
        }
    }
}

impl Error for RuntimeStateValidationError {}

#[derive(Debug, PartialEq, Eq)]
pub enum RollbackExecutionError {
    Storage(String),
    ApprovalRequired { rollback_handle_id: String },
}

impl Display for RollbackExecutionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "rollback storage error: {error}"),
            Self::ApprovalRequired { rollback_handle_id } => write!(
                f,
                "rollback '{}' requires explicit approval before execution",
                rollback_handle_id
            ),
        }
    }
}

impl Error for RollbackExecutionError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableArtifactStore {
    pub root: PathBuf,
}

impl DurableArtifactStore {
    pub fn bootstrap(root: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let root = root.into();
        fs::create_dir_all(root.join("checkpoints"))?;
        fs::create_dir_all(root.join("snapshots/by-checkpoint"))?;
        fs::create_dir_all(root.join("shadow-evaluations"))?;
        fs::create_dir_all(root.join("promotion-activations"))?;
        fs::create_dir_all(root.join("v1-completion"))?;
        fs::create_dir_all(root.join("v3-substrate").join("generation-artifacts"))?;
        fs::create_dir_all(root.join("v3-substrate").join("component-builds"))?;
        fs::create_dir_all(root.join("v3-substrate").join("validation-traces"))?;
        fs::create_dir_all(root.join("v3-substrate").join("comparisons"))?;
        fs::create_dir_all(root.join("v3-substrate").join("active-generations"))?;
        fs::create_dir_all(root.join("v3-substrate").join("self-production"))?;
        fs::create_dir_all(root.join("v3-substrate").join("completion-gates"))?;
        fs::create_dir_all(root.join("v4-shell").join("sessions"))?;
        fs::create_dir_all(root.join("v4-shell").join("evidence-packets"))?;
        fs::create_dir_all(root.join("v4-shell").join("completion-gates"))?;
        fs::create_dir_all(root.join("factories").join("genomes"))?;
        fs::create_dir_all(root.join("factories").join("phenotypes"))?;
        fs::create_dir_all(root.join("factories").join("lineage"))?;
        fs::create_dir_all(root.join("factories").join("validation-profiles"))?;
        fs::create_dir_all(root.join("factories").join("validation-evidence"))?;
        fs::create_dir_all(root.join("factories").join("validation-records"))?;
        fs::create_dir_all(root.join("factories").join("comparisons"))?;
        fs::create_dir_all(root.join("factories").join("activations"))?;
        fs::create_dir_all(root.join("factories").join("states"))?;
        fs::create_dir_all(root.join("factories").join("governance-transitions"))?;
        fs::create_dir_all(root.join("factories").join("rollback-envelopes"))?;
        fs::create_dir_all(root.join("factories").join("quarantine-records"))?;
        fs::create_dir_all(root.join("factories").join("evidence-packets"))?;
        fs::create_dir_all(root.join("factory-replication").join("campaigns"))?;
        fs::create_dir_all(root.join("factory-replication").join("candidates"))?;
        fs::create_dir_all(root.join("factory-replication").join("proving-runs"))?;
        fs::create_dir_all(root.join("factory-replication").join("observation-windows"))?;
        fs::create_dir_all(
            root.join("factory-replication")
                .join("quarantine-protocols"),
        )?;
        fs::create_dir_all(root.join("factory-replication").join("dispositions"))?;
        fs::create_dir_all(root.join("factory-replication").join("decisions"))?;
        fs::create_dir_all(root.join("factory-replication").join("evidence-packets"))?;
        fs::create_dir_all(root.join("factory-exchange").join("identities"))?;
        fs::create_dir_all(root.join("factory-exchange").join("envelopes"))?;
        fs::create_dir_all(
            root.join("factory-exchange")
                .join("compatibility-decisions"),
        )?;
        fs::create_dir_all(root.join("factory-exchange").join("quarantine-packets"))?;
        fs::create_dir_all(root.join("factory-exchange").join("import-states"))?;
        fs::create_dir_all(root.join("factory-exchange").join("dispositions"))?;
        fs::create_dir_all(root.join("factory-exchange").join("lineage-imports"))?;
        fs::create_dir_all(root.join("factory-exchange").join("memory-packets"))?;
        fs::create_dir_all(root.join("northstar-01").join("support-classifications"))?;
        fs::create_dir_all(root.join("northstar-01").join("launch-assemblies"))?;
        fs::create_dir_all(root.join("northstar-01").join("campaign-admissions"))?;
        fs::create_dir_all(root.join("northstar-01").join("launch-refusals"))?;
        fs::create_dir_all(root.join("northstar-01").join("program-mappings"))?;
        fs::create_dir_all(root.join("northstar-01").join("lifecycle-transitions"))?;
        fs::create_dir_all(root.join("northstar-01").join("resume-chains"))?;
        fs::create_dir_all(root.join("northstar-01").join("evidence-summaries"))?;
        fs::create_dir_all(root.join("northstar-01").join("export-bundles"))?;
        fs::create_dir_all(root.join("northstar-01").join("truth-annotations"))?;
        fs::create_dir_all(root.join("northstar-01").join("adapter-manifests"))?;
        fs::create_dir_all(root.join("northstar-01").join("migration-gates"))?;
        fs::create_dir_all(root.join("northstar-01").join("retirements"))?;
        fs::create_dir_all(root.join("northstar-01").join("acceptance-truth"))?;
        fs::create_dir_all(root.join("northstar-02").join("scheduler-ticks"))?;
        fs::create_dir_all(root.join("northstar-02").join("scheduled-wakes"))?;
        fs::create_dir_all(root.join("northstar-02").join("persistent-job-leases"))?;
        fs::create_dir_all(root.join("northstar-02").join("approval-inbox"))?;
        fs::create_dir_all(root.join("northstar-02").join("deferred-decision-bundles"))?;
        fs::create_dir_all(root.join("northstar-02").join("lease-expiries"))?;
        fs::create_dir_all(root.join("northstar-02").join("shell-escalations"))?;
        fs::create_dir_all(root.join("northstar-02").join("consolidation-jobs"))?;
        fs::create_dir_all(root.join("northstar-02").join("continuity-job-classes"))?;
        fs::create_dir_all(root.join("northstar-02").join("continuity-jobs"))?;
        fs::create_dir_all(root.join("northstar-02").join("audit-packets"))?;
        fs::create_dir_all(root.join("northstar-02").join("operations-dossiers"))?;
        fs::create_dir_all(root.join("northstar-03").join("service-manifests"))?;
        fs::create_dir_all(root.join("northstar-03").join("service-handles"))?;
        fs::create_dir_all(root.join("northstar-03").join("service-attestations"))?;
        fs::create_dir_all(root.join("northstar-03").join("service-closure-dossiers"))?;
        fs::create_dir_all(root.join("northstar-03").join("workflow-sufficiency"))?;
        fs::create_dir_all(root.join("northstar-03").join("workflow-closure-dossiers"))?;
        fs::create_dir_all(root.join("northstar-04").join("worker-cards"))?;
        fs::create_dir_all(root.join("northstar-04").join("ecology-snapshots"))?;
        fs::create_dir_all(root.join("northstar-04").join("planning-records"))?;
        fs::create_dir_all(root.join("northstar-04").join("work-leases"))?;
        fs::create_dir_all(root.join("northstar-04").join("synthesis-dossiers"))?;
        fs::create_dir_all(root.join("northstar-04").join("health-records"))?;
        fs::create_dir_all(root.join("northstar-04").join("routing-packets"))?;
        fs::create_dir_all(root.join("northstar-04").join("recovery-records"))?;
        fs::create_dir_all(root.join("remediation-phase-02").join("service-workspaces"))?;
        fs::create_dir_all(root.join("remediation-phase-02").join("ecology-workspaces"))?;
        fs::create_dir_all(root.join("remediation-phase-02").join("acceptance-packets"))?;
        fs::create_dir_all(root.join("northstar-05").join("programs"))?;
        fs::create_dir_all(root.join("northstar-05").join("recursion-budgets"))?;
        fs::create_dir_all(root.join("northstar-05").join("generation-agendas"))?;
        fs::create_dir_all(root.join("northstar-05").join("adoption-windows"))?;
        fs::create_dir_all(root.join("northstar-05").join("lineage-health"))?;
        fs::create_dir_all(root.join("northstar-05").join("stop-conditions"))?;
        fs::create_dir_all(root.join("northstar-05").join("recurring-programs"))?;
        fs::create_dir_all(root.join("northstar-05").join("cycle-dossiers"))?;
        fs::create_dir_all(root.join("northstar-05").join("lineage-ledgers"))?;
        fs::create_dir_all(root.join("northstar-05").join("regression-packets"))?;
        fs::create_dir_all(
            root.join("northstar-05")
                .join("longitudinal-lineage-dossiers"),
        )?;
        fs::create_dir_all(root.join("northstar-06").join("trust-profiles"))?;
        fs::create_dir_all(root.join("northstar-06").join("admissions"))?;
        fs::create_dir_all(root.join("northstar-06").join("routes"))?;
        fs::create_dir_all(root.join("northstar-06").join("route-cycles"))?;
        fs::create_dir_all(root.join("northstar-06").join("adoption-dossiers"))?;
        fs::create_dir_all(root.join("northstar-06").join("rollback-choreography"))?;
        fs::create_dir_all(root.join("northstar-06").join("workspace-snapshots"))?;
        fs::create_dir_all(root.join("northstar-06").join("health-snapshots"))?;
        fs::create_dir_all(root.join("northstar-06").join("admission-profiles"))?;
        fs::create_dir_all(root.join("northstar-06").join("route-history-records"))?;
        fs::create_dir_all(root.join("northstar-06").join("route-ledgers"))?;
        fs::create_dir_all(root.join("northstar-06").join("continuity-windows"))?;
        fs::create_dir_all(root.join("northstar-06").join("rollback-symmetry-records"))?;
        fs::create_dir_all(
            root.join("northstar-06")
                .join("compatibility-persistence-records"),
        )?;
        fs::create_dir_all(root.join("northstar-06").join("health-ledgers"))?;
        fs::create_dir_all(root.join("remediation-phase-03").join("factory-workspaces"))?;
        fs::create_dir_all(
            root.join("remediation-phase-03")
                .join("ecosystem-workspaces"),
        )?;
        fs::create_dir_all(
            root.join("remediation-phase-03")
                .join("closure-review-packets"),
        )?;
        fs::create_dir_all(root.join("northstar-07").join("criteria-matrices"))?;
        fs::create_dir_all(root.join("northstar-07").join("evidence-inventories"))?;
        fs::create_dir_all(root.join("northstar-07").join("adversarial-reviews"))?;
        fs::create_dir_all(root.join("northstar-07").join("residual-risks"))?;
        fs::create_dir_all(root.join("northstar-07").join("closure-dossiers"))?;
        fs::create_dir_all(root.join("northstar-07").join("claim-reviews"))?;
        fs::create_dir_all(root.join("northstar-07").join("publication-policies"))?;
        fs::create_dir_all(root.join("northstar-07").join("closure-decisions"))?;
        fs::create_dir_all(root.join("llm-interface").join("providers"))?;
        fs::create_dir_all(root.join("llm-interface").join("generation-policies"))?;
        fs::create_dir_all(root.join("llm-interface").join("turn-requests"))?;
        fs::create_dir_all(root.join("llm-interface").join("rendered-prompts"))?;
        fs::create_dir_all(root.join("llm-interface").join("tool-catalogs"))?;
        fs::create_dir_all(root.join("llm-interface").join("response-schemas"))?;
        fs::create_dir_all(root.join("llm-interface").join("request-bodies"))?;
        fs::create_dir_all(root.join("llm-interface").join("attempts"))?;
        fs::create_dir_all(root.join("llm-interface").join("raw-outputs"))?;
        fs::create_dir_all(root.join("llm-interface").join("usage-records"))?;
        fs::create_dir_all(root.join("llm-interface").join("provider-outcomes"))?;
        fs::create_dir_all(root.join("llm-interface").join("parsed-outputs"))?;
        fs::create_dir_all(root.join("llm-interface").join("turn-results"))?;
        fs::create_dir_all(root.join("llm-interface").join("degradation-records"))?;
        fs::create_dir_all(root.join("llm-interface").join("turn-packages"))?;
        fs::create_dir_all(root.join("llm-interface").join("continuity-bundles"))?;
        fs::create_dir_all(root.join("llm-interface").join("turn-groundings"))?;
        fs::create_dir_all(
            root.join("llm-interface")
                .join("continuity-retrieval-traces"),
        )?;
        fs::create_dir_all(root.join("llm-interface").join("open-question-ledgers"))?;
        fs::create_dir_all(
            root.join("llm-interface")
                .join("contradiction-carry-forwards"),
        )?;
        fs::create_dir_all(root.join("llm-interface").join("turn-memory-updates"))?;
        fs::create_dir_all(root.join("llm-interface").join("context-budgets"))?;
        fs::create_dir_all(root.join("llm-interface").join("context-truncations"))?;
        fs::create_dir_all(root.join("llm-interface").join("prompt-layers"))?;
        fs::create_dir_all(root.join("llm-interface").join("prompt-renderings"))?;
        fs::create_dir_all(root.join("llm-interface").join("turn-response-schemas"))?;
        fs::create_dir_all(root.join("llm-interface").join("parsed-tool-intents"))?;
        fs::create_dir_all(root.join("llm-interface").join("parsed-proposals"))?;
        fs::create_dir_all(root.join("llm-interface").join("parsed-approval-requests"))?;
        fs::create_dir_all(root.join("llm-interface").join("parsed-turn-results"))?;
        fs::create_dir_all(root.join("llm-interface").join("parse-repairs"))?;
        fs::create_dir_all(root.join("llm-interface").join("delegation-policies"))?;
        fs::create_dir_all(root.join("llm-interface").join("authority-decisions"))?;
        fs::create_dir_all(root.join("llm-interface").join("model-approval-requests"))?;
        fs::create_dir_all(root.join("llm-interface").join("model-quarantines"))?;
        fs::create_dir_all(root.join("llm-interface").join("turn-checkpoints"))?;
        fs::create_dir_all(root.join("llm-interface").join("pending-turn-actions"))?;
        fs::create_dir_all(root.join("llm-interface").join("tool-definitions"))?;
        fs::create_dir_all(root.join("llm-interface").join("tool-argument-schemas"))?;
        fs::create_dir_all(root.join("llm-interface").join("tool-result-schemas"))?;
        fs::create_dir_all(root.join("llm-interface").join("tool-execution-contexts"))?;
        fs::create_dir_all(root.join("llm-interface").join("tool-exposure-decisions"))?;
        fs::create_dir_all(root.join("llm-interface").join("tool-legality-decisions"))?;
        fs::create_dir_all(root.join("llm-interface").join("tool-executions"))?;
        fs::create_dir_all(root.join("llm-interface").join("tool-execution-receipts"))?;
        fs::create_dir_all(root.join("llm-interface").join("operator-only-surfaces"))?;
        Ok(Self { root })
    }

    pub fn persist_runtime_state(
        &self,
        state: &ReplayableRuntimeState,
    ) -> Result<(), StorageError> {
        state.validate_replayability()?;
        self.write_json(self.root.join("runtime-state.json"), state)?;

        if let Some(checkpoint) = &state.latest_checkpoint {
            self.persist_checkpoint(checkpoint)?;
            let snapshot_path = self.snapshot_path(&checkpoint.checkpoint_id);
            if !snapshot_path.exists() {
                self.write_json(snapshot_path, state)?;
            }
        }

        Ok(())
    }

    pub fn load_runtime_state(&self) -> Result<ReplayableRuntimeState, StorageError> {
        let state: ReplayableRuntimeState = self.read_json(self.root.join("runtime-state.json"))?;
        state.validate_replayability()?;
        Ok(state)
    }

    pub fn persist_checkpoint(&self, checkpoint: &RunCheckpoint) -> Result<(), StorageError> {
        self.write_json(
            self.root
                .join("checkpoints")
                .join(format!("{}.json", checkpoint.checkpoint_id)),
            checkpoint,
        )
    }

    pub fn load_checkpoint(&self, checkpoint_id: &str) -> Result<RunCheckpoint, StorageError> {
        self.read_json(
            self.root
                .join("checkpoints")
                .join(format!("{}.json", checkpoint_id)),
        )
    }

    pub fn load_runtime_state_for_checkpoint(
        &self,
        checkpoint_id: &str,
    ) -> Result<ReplayableRuntimeState, StorageError> {
        let state: ReplayableRuntimeState = self.read_json(self.snapshot_path(checkpoint_id))?;
        state.validate_replayability()?;
        Ok(state)
    }

    pub fn artifact_ids(&self) -> Result<Vec<String>, StorageError> {
        Ok(self
            .load_runtime_state()?
            .memory_store
            .artifacts
            .into_iter()
            .map(|artifact| artifact.artifact_id)
            .collect())
    }

    pub fn persist_shadow_evaluation_bundle(
        &self,
        bundle: &ShadowEvaluationBundle,
    ) -> Result<(), StorageError> {
        validate_shadow_evaluation_bundle(bundle)?;
        self.write_json(
            self.shadow_bundle_path(&bundle.shadow_campaign.shadow_campaign_id),
            bundle,
        )
    }

    pub fn load_shadow_evaluation_bundle(
        &self,
        shadow_campaign_id: &str,
    ) -> Result<ShadowEvaluationBundle, StorageError> {
        let bundle: ShadowEvaluationBundle =
            self.read_json(self.shadow_bundle_path(shadow_campaign_id))?;
        validate_shadow_evaluation_bundle(&bundle)?;
        Ok(bundle)
    }

    pub fn persist_promotion_activation_bundle(
        &self,
        bundle: &PromotionActivationBundle,
    ) -> Result<(), StorageError> {
        validate_promotion_activation_bundle(bundle)?;
        self.write_json(
            self.promotion_bundle_path(&bundle.promotion_act.promotion_act_id),
            bundle,
        )
    }

    pub fn load_promotion_activation_bundle(
        &self,
        promotion_act_id: &str,
    ) -> Result<PromotionActivationBundle, StorageError> {
        let bundle: PromotionActivationBundle =
            self.read_json(self.promotion_bundle_path(promotion_act_id))?;
        validate_promotion_activation_bundle(&bundle)?;
        Ok(bundle)
    }

    pub fn persist_v1_completion_bundle(
        &self,
        bundle: &V1CompletionBundle,
    ) -> Result<(), StorageError> {
        validate_v1_completion_bundle(bundle)?;
        self.write_json(
            self.v1_completion_path(&bundle.v1_completion_gate.gate_id),
            bundle,
        )
    }

    pub fn load_v1_completion_bundle(
        &self,
        gate_id: &str,
    ) -> Result<V1CompletionBundle, StorageError> {
        let bundle: V1CompletionBundle = self.read_json(self.v1_completion_path(gate_id))?;
        validate_v1_completion_bundle(&bundle)?;
        Ok(bundle)
    }

    pub fn persist_generation_artifact_bundle(
        &self,
        bundle: &GenerationArtifactBundle,
    ) -> Result<(), StorageError> {
        validate_generation_artifact_bundle(bundle).map_err(|error| {
            storage_integrity_error(format!("v3 generation artifact validation failed: {error}"))
        })?;
        self.write_json(
            self.v3_generation_artifact_path(bundle.package_digest()),
            bundle,
        )
    }

    pub fn load_generation_artifact_bundle(
        &self,
        package_digest: &ArtifactDigest,
    ) -> Result<GenerationArtifactBundle, StorageError> {
        let bundle: GenerationArtifactBundle =
            self.read_json(self.v3_generation_artifact_path(package_digest))?;
        validate_generation_artifact_bundle(&bundle).map_err(|error| {
            storage_integrity_error(format!("v3 generation artifact validation failed: {error}"))
        })?;
        Ok(bundle)
    }

    pub fn persist_component_build_output(
        &self,
        output: &ComponentBuildOutput,
    ) -> Result<(), StorageError> {
        validate_component_build_output(output)?;
        self.write_json(self.v3_component_build_path(&output.build_id), output)
    }

    pub fn load_component_build_output(
        &self,
        build_id: &str,
    ) -> Result<ComponentBuildOutput, StorageError> {
        let output: ComponentBuildOutput =
            self.read_json(self.v3_component_build_path(build_id))?;
        validate_component_build_output(&output)?;
        Ok(output)
    }

    pub fn persist_execution_validation_record(
        &self,
        record: &ExecutionBackedValidationRecord,
    ) -> Result<(), StorageError> {
        validate_execution_validation_record(record)?;
        self.write_json(self.v3_validation_trace_path(&record.trace_ref), record)
    }

    pub fn load_execution_validation_record(
        &self,
        trace_ref: &str,
    ) -> Result<ExecutionBackedValidationRecord, StorageError> {
        let record: ExecutionBackedValidationRecord =
            self.read_json(self.v3_validation_trace_path(trace_ref))?;
        validate_execution_validation_record(&record)?;
        Ok(record)
    }

    pub fn persist_execution_comparison_bundle(
        &self,
        bundle: &ExecutionComparisonBundle,
    ) -> Result<(), StorageError> {
        validate_comparison_dimensions(&bundle.comparison_record)?;
        if bundle.incumbent_trace.trace_ref.trim().is_empty()
            || bundle.challenger_trace.trace_ref.trim().is_empty()
            || !bundle.incumbent_trace.passed
            || !bundle.challenger_trace.passed
        {
            return Err(storage_integrity_error(
                "v3 execution comparison requires passing incumbent and challenger traces",
            ));
        }
        self.write_json(
            self.v3_comparison_path(&bundle.comparison_record.comparison_id),
            bundle,
        )
    }

    pub fn load_execution_comparison_bundle(
        &self,
        comparison_id: &str,
    ) -> Result<ExecutionComparisonBundle, StorageError> {
        let bundle: ExecutionComparisonBundle =
            self.read_json(self.v3_comparison_path(comparison_id))?;
        validate_comparison_dimensions(&bundle.comparison_record)?;
        Ok(bundle)
    }

    pub fn persist_active_generation_state(
        &self,
        state: &ActiveGenerationState,
    ) -> Result<(), StorageError> {
        if state.state_id.trim().is_empty() {
            return Err(storage_integrity_error(
                "v3 active generation state requires a state id",
            ));
        }
        self.write_json(self.v3_active_generation_state_path(&state.state_id), state)
    }

    pub fn load_active_generation_state(
        &self,
        state_id: &str,
    ) -> Result<ActiveGenerationState, StorageError> {
        self.read_json(self.v3_active_generation_state_path(state_id))
    }

    pub fn persist_self_production_campaign(
        &self,
        campaign: &SelfProductionCampaign,
    ) -> Result<(), StorageError> {
        if campaign.campaign_id.trim().is_empty() {
            return Err(storage_integrity_error(
                "v3 self-production campaign requires a campaign id",
            ));
        }
        self.write_json(
            self.v3_self_production_campaign_path(&campaign.campaign_id),
            campaign,
        )
    }

    pub fn load_self_production_campaign(
        &self,
        campaign_id: &str,
    ) -> Result<SelfProductionCampaign, StorageError> {
        self.read_json(self.v3_self_production_campaign_path(campaign_id))
    }

    pub fn persist_successor_production_record(
        &self,
        record: &SuccessorProductionRecord,
    ) -> Result<(), StorageError> {
        if record.record_id.trim().is_empty() || !record.complete {
            return Err(storage_integrity_error(
                "v3 successor production record requires a complete record id",
            ));
        }
        self.write_json(
            self.v3_successor_production_record_path(&record.record_id),
            record,
        )
    }

    pub fn load_successor_production_record(
        &self,
        record_id: &str,
    ) -> Result<SuccessorProductionRecord, StorageError> {
        self.read_json(self.v3_successor_production_record_path(record_id))
    }

    pub fn persist_v3_substrate_completion_gate(
        &self,
        gate: &V3SubstrateCompletionGate,
    ) -> Result<(), StorageError> {
        if gate.gate_id.trim().is_empty() {
            return Err(storage_integrity_error(
                "v3 substrate completion gate requires a gate id",
            ));
        }
        self.write_json(self.v3_completion_gate_path(&gate.gate_id), gate)
    }

    pub fn load_v3_substrate_completion_gate(
        &self,
        gate_id: &str,
    ) -> Result<V3SubstrateCompletionGate, StorageError> {
        self.read_json(self.v3_completion_gate_path(gate_id))
    }

    pub fn persist_shell_session_bundle(
        &self,
        bundle: &ShellSessionBundle,
    ) -> Result<(), StorageError> {
        validate_shell_session_bundle(bundle)?;
        self.write_json(
            self.v4_shell_session_bundle_path(&bundle.shell_session.shell_session_id),
            bundle,
        )
    }

    pub fn load_shell_session_bundle(
        &self,
        shell_session_id: &str,
    ) -> Result<ShellSessionBundle, StorageError> {
        let bundle: ShellSessionBundle =
            self.read_json(self.v4_shell_session_bundle_path(shell_session_id))?;
        validate_shell_session_bundle(&bundle)?;
        Ok(bundle)
    }

    pub fn persist_v4_shell_evidence_bundle(
        &self,
        bundle: &V4ShellEvidenceBundle,
    ) -> Result<(), StorageError> {
        validate_shell_session_bundle(&bundle.shell_session_bundle)?;
        validate_shell_evidence_packet(
            &bundle.shell_evidence_packet,
            Some(&bundle.shell_session_bundle),
        )?;
        self.write_json(
            self.v4_shell_evidence_packet_path(&bundle.shell_evidence_packet.packet_id),
            bundle,
        )
    }

    pub fn load_v4_shell_evidence_bundle(
        &self,
        packet_id: &str,
    ) -> Result<V4ShellEvidenceBundle, StorageError> {
        let bundle: V4ShellEvidenceBundle =
            self.read_json(self.v4_shell_evidence_packet_path(packet_id))?;
        validate_shell_session_bundle(&bundle.shell_session_bundle)?;
        validate_shell_evidence_packet(
            &bundle.shell_evidence_packet,
            Some(&bundle.shell_session_bundle),
        )?;
        Ok(bundle)
    }

    pub fn persist_v4_supervisory_shell_bundle(
        &self,
        bundle: &V4SupervisoryShellBundle,
    ) -> Result<(), StorageError> {
        validate_shell_session_bundle(&bundle.shell_session_bundle)?;
        validate_shell_evidence_packet(
            &bundle.shell_evidence_packet,
            Some(&bundle.shell_session_bundle),
        )?;
        validate_v4_supervisory_shell_completion_gate(&bundle.completion_gate)?;
        self.write_json(
            self.v4_completion_gate_path(&bundle.completion_gate.gate_id),
            bundle,
        )
    }

    pub fn load_v4_supervisory_shell_bundle(
        &self,
        gate_id: &str,
    ) -> Result<V4SupervisoryShellBundle, StorageError> {
        let bundle: V4SupervisoryShellBundle =
            self.read_json(self.v4_completion_gate_path(gate_id))?;
        validate_shell_session_bundle(&bundle.shell_session_bundle)?;
        validate_shell_evidence_packet(
            &bundle.shell_evidence_packet,
            Some(&bundle.shell_session_bundle),
        )?;
        validate_v4_supervisory_shell_completion_gate(&bundle.completion_gate)?;
        Ok(bundle)
    }

    pub fn persist_factory_genome_artifact(
        &self,
        artifact: &FactoryGenomeArtifact,
    ) -> Result<(), StorageError> {
        artifact.validate().map_err(|error| {
            storage_integrity_error(format!("factory genome validation failed: {error}"))
        })?;
        self.write_json(
            self.factory_genome_path(&artifact.factory_genome_id),
            artifact,
        )
    }

    pub fn load_factory_genome_artifact(
        &self,
        factory_genome_id: &str,
    ) -> Result<FactoryGenomeArtifact, StorageError> {
        let artifact: FactoryGenomeArtifact =
            self.read_json(self.factory_genome_path(factory_genome_id))?;
        artifact.validate().map_err(|error| {
            storage_integrity_error(format!("factory genome validation failed: {error}"))
        })?;
        Ok(artifact)
    }

    pub fn persist_factory_phenotype_artifact(
        &self,
        artifact: &FactoryPhenotypeArtifact,
    ) -> Result<(), StorageError> {
        artifact.validate().map_err(|error| {
            storage_integrity_error(format!("factory phenotype validation failed: {error}"))
        })?;
        self.write_json(
            self.factory_phenotype_path(&artifact.factory_phenotype_id),
            artifact,
        )
    }

    pub fn load_factory_phenotype_artifact(
        &self,
        factory_phenotype_id: &str,
    ) -> Result<FactoryPhenotypeArtifact, StorageError> {
        let artifact: FactoryPhenotypeArtifact =
            self.read_json(self.factory_phenotype_path(factory_phenotype_id))?;
        artifact.validate().map_err(|error| {
            storage_integrity_error(format!("factory phenotype validation failed: {error}"))
        })?;
        Ok(artifact)
    }

    pub fn persist_factory_lineage_record(
        &self,
        record: &FactoryLineageRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("factory lineage validation failed: {error}"))
        })?;
        self.write_json(self.factory_lineage_path(&record.lineage_id), record)
    }

    pub fn load_factory_lineage_record(
        &self,
        lineage_id: &str,
    ) -> Result<FactoryLineageRecord, StorageError> {
        let record: FactoryLineageRecord = self.read_json(self.factory_lineage_path(lineage_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("factory lineage validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_factory_validation_profile(
        &self,
        profile: &FactoryValidationProfile,
    ) -> Result<(), StorageError> {
        profile.validate().map_err(|error| {
            storage_integrity_error(format!("factory validation profile failed: {error}"))
        })?;
        self.write_json(
            self.factory_validation_profile_path(&profile.validation_profile_id),
            profile,
        )
    }

    pub fn load_factory_validation_profile(
        &self,
        validation_profile_id: &str,
    ) -> Result<FactoryValidationProfile, StorageError> {
        let profile: FactoryValidationProfile =
            self.read_json(self.factory_validation_profile_path(validation_profile_id))?;
        profile.validate().map_err(|error| {
            storage_integrity_error(format!("factory validation profile failed: {error}"))
        })?;
        Ok(profile)
    }

    pub fn persist_factory_validation_evidence(
        &self,
        evidence: &FactoryValidationEvidence,
    ) -> Result<(), StorageError> {
        evidence.validate().map_err(|error| {
            storage_integrity_error(format!("factory validation evidence failed: {error}"))
        })?;
        self.write_json(
            self.factory_validation_evidence_path(&evidence.evidence_id),
            evidence,
        )
    }

    pub fn load_factory_validation_evidence(
        &self,
        evidence_id: &str,
    ) -> Result<FactoryValidationEvidence, StorageError> {
        let evidence: FactoryValidationEvidence =
            self.read_json(self.factory_validation_evidence_path(evidence_id))?;
        evidence.validate().map_err(|error| {
            storage_integrity_error(format!("factory validation evidence failed: {error}"))
        })?;
        Ok(evidence)
    }

    pub fn persist_factory_validation_record(
        &self,
        record: &FactoryValidationRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("factory validation record failed: {error}"))
        })?;
        self.write_json(
            self.factory_validation_record_path(&record.validation_id),
            record,
        )
    }

    pub fn load_factory_validation_record(
        &self,
        validation_id: &str,
    ) -> Result<FactoryValidationRecord, StorageError> {
        let record: FactoryValidationRecord =
            self.read_json(self.factory_validation_record_path(validation_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("factory validation record failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_factory_comparison_record(
        &self,
        record: &FactoryComparisonRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("factory comparison validation failed: {error}"))
        })?;
        self.write_json(self.factory_comparison_path(&record.comparison_id), record)
    }

    pub fn load_factory_comparison_record(
        &self,
        comparison_id: &str,
    ) -> Result<FactoryComparisonRecord, StorageError> {
        let record: FactoryComparisonRecord =
            self.read_json(self.factory_comparison_path(comparison_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("factory comparison validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_factory_activation_bundle(
        &self,
        bundle: &FactoryActivationBundle,
    ) -> Result<(), StorageError> {
        bundle.validate().map_err(|error| {
            storage_integrity_error(format!("factory activation validation failed: {error}"))
        })?;
        self.write_json(self.factory_activation_path(&bundle.activation_id), bundle)
    }

    pub fn load_factory_activation_bundle(
        &self,
        activation_id: &str,
    ) -> Result<FactoryActivationBundle, StorageError> {
        let bundle: FactoryActivationBundle =
            self.read_json(self.factory_activation_path(activation_id))?;
        bundle.validate().map_err(|error| {
            storage_integrity_error(format!("factory activation validation failed: {error}"))
        })?;
        Ok(bundle)
    }

    pub fn persist_active_factory_state(
        &self,
        state: &ActiveFactoryState,
    ) -> Result<(), StorageError> {
        validate_active_factory_state(state)?;
        self.write_json(self.factory_state_path(&state.state_id), state)
    }

    pub fn load_active_factory_state(
        &self,
        state_id: &str,
    ) -> Result<ActiveFactoryState, StorageError> {
        let state: ActiveFactoryState = self.read_json(self.factory_state_path(state_id))?;
        validate_active_factory_state(&state)?;
        Ok(state)
    }

    pub fn persist_factory_governance_transition(
        &self,
        record: &FactoryGovernanceTransitionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory governance transition validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.factory_governance_transition_path(&record.transition_id),
            record,
        )
    }

    pub fn load_factory_governance_transition(
        &self,
        transition_id: &str,
    ) -> Result<FactoryGovernanceTransitionRecord, StorageError> {
        let record: FactoryGovernanceTransitionRecord =
            self.read_json(self.factory_governance_transition_path(transition_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory governance transition validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_factory_rollback_envelope(
        &self,
        envelope: &FactoryRollbackEnvelope,
    ) -> Result<(), StorageError> {
        envelope.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory rollback envelope validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.factory_rollback_envelope_path(&envelope.rollback_id),
            envelope,
        )
    }

    pub fn load_factory_rollback_envelope(
        &self,
        rollback_id: &str,
    ) -> Result<FactoryRollbackEnvelope, StorageError> {
        let envelope: FactoryRollbackEnvelope =
            self.read_json(self.factory_rollback_envelope_path(rollback_id))?;
        envelope.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory rollback envelope validation failed: {error}"
            ))
        })?;
        Ok(envelope)
    }

    pub fn persist_factory_quarantine_record(
        &self,
        record: &FactoryQuarantineRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("factory quarantine validation failed: {error}"))
        })?;
        self.write_json(
            self.factory_quarantine_record_path(&record.quarantine_id),
            record,
        )
    }

    pub fn load_factory_quarantine_record(
        &self,
        quarantine_id: &str,
    ) -> Result<FactoryQuarantineRecord, StorageError> {
        let record: FactoryQuarantineRecord =
            self.read_json(self.factory_quarantine_record_path(quarantine_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("factory quarantine validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_factory_evidence_packet(
        &self,
        packet: &FactoryEvidencePacket,
    ) -> Result<(), StorageError> {
        packet.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory evidence packet validation failed: {error}"
            ))
        })?;
        self.write_json(self.factory_evidence_packet_path(&packet.packet_id), packet)
    }

    pub fn load_factory_evidence_packet(
        &self,
        packet_id: &str,
    ) -> Result<FactoryEvidencePacket, StorageError> {
        let packet: FactoryEvidencePacket =
            self.read_json(self.factory_evidence_packet_path(packet_id))?;
        packet.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory evidence packet validation failed: {error}"
            ))
        })?;
        Ok(packet)
    }

    pub fn persist_factory_replication_campaign(
        &self,
        campaign: &FactoryReplicationCampaign,
    ) -> Result<(), StorageError> {
        campaign.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory replication campaign validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.factory_replication_campaign_path(&campaign.replication_campaign_id),
            campaign,
        )
    }

    pub fn load_factory_replication_campaign(
        &self,
        replication_campaign_id: &str,
    ) -> Result<FactoryReplicationCampaign, StorageError> {
        let campaign: FactoryReplicationCampaign =
            self.read_json(self.factory_replication_campaign_path(replication_campaign_id))?;
        campaign.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory replication campaign validation failed: {error}"
            ))
        })?;
        Ok(campaign)
    }

    pub fn persist_later_factory_candidate(
        &self,
        candidate: &LaterFactoryCandidate,
    ) -> Result<(), StorageError> {
        candidate.validate().map_err(|error| {
            storage_integrity_error(format!(
                "later-factory candidate validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.later_factory_candidate_path(&candidate.later_factory_candidate_id),
            candidate,
        )
    }

    pub fn load_later_factory_candidate(
        &self,
        later_factory_candidate_id: &str,
    ) -> Result<LaterFactoryCandidate, StorageError> {
        let candidate: LaterFactoryCandidate =
            self.read_json(self.later_factory_candidate_path(later_factory_candidate_id))?;
        candidate.validate().map_err(|error| {
            storage_integrity_error(format!(
                "later-factory candidate validation failed: {error}"
            ))
        })?;
        Ok(candidate)
    }

    pub fn persist_factory_proving_run_record(
        &self,
        record: &FactoryProvingRunRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("factory proving run validation failed: {error}"))
        })?;
        self.write_json(
            self.factory_proving_run_path(&record.proving_run_id),
            record,
        )
    }

    pub fn load_factory_proving_run_record(
        &self,
        proving_run_id: &str,
    ) -> Result<FactoryProvingRunRecord, StorageError> {
        let record: FactoryProvingRunRecord =
            self.read_json(self.factory_proving_run_path(proving_run_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("factory proving run validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_child_factory_observation_window(
        &self,
        record: &ChildFactoryObservationWindowRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "child-factory observation validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.child_factory_observation_window_path(&record.observation_window_id),
            record,
        )
    }

    pub fn load_child_factory_observation_window(
        &self,
        observation_window_id: &str,
    ) -> Result<ChildFactoryObservationWindowRecord, StorageError> {
        let record: ChildFactoryObservationWindowRecord =
            self.read_json(self.child_factory_observation_window_path(observation_window_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "child-factory observation validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_child_factory_quarantine_protocol(
        &self,
        record: &ChildFactoryQuarantineProtocolRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "child-factory quarantine protocol validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.child_factory_quarantine_protocol_path(&record.protocol_id),
            record,
        )
    }

    pub fn load_child_factory_quarantine_protocol(
        &self,
        protocol_id: &str,
    ) -> Result<ChildFactoryQuarantineProtocolRecord, StorageError> {
        let record: ChildFactoryQuarantineProtocolRecord =
            self.read_json(self.child_factory_quarantine_protocol_path(protocol_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "child-factory quarantine protocol validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_child_factory_disposition(
        &self,
        record: &ChildFactoryDispositionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "child-factory disposition validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.child_factory_disposition_path(&record.disposition_id),
            record,
        )
    }

    pub fn load_child_factory_disposition(
        &self,
        disposition_id: &str,
    ) -> Result<ChildFactoryDispositionRecord, StorageError> {
        let record: ChildFactoryDispositionRecord =
            self.read_json(self.child_factory_disposition_path(disposition_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "child-factory disposition validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_factory_replication_decision(
        &self,
        decision: &FactoryReplicationDecision,
    ) -> Result<(), StorageError> {
        decision.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory replication decision validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.factory_replication_decision_path(&decision.decision_id),
            decision,
        )
    }

    pub fn load_factory_replication_decision(
        &self,
        decision_id: &str,
    ) -> Result<FactoryReplicationDecision, StorageError> {
        let decision: FactoryReplicationDecision =
            self.read_json(self.factory_replication_decision_path(decision_id))?;
        decision.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory replication decision validation failed: {error}"
            ))
        })?;
        Ok(decision)
    }

    pub fn persist_factory_replication_evidence_packet(
        &self,
        packet: &FactoryReplicationEvidencePacket,
    ) -> Result<(), StorageError> {
        packet.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory replication evidence packet validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.factory_replication_evidence_packet_path(&packet.packet_id),
            packet,
        )
    }

    pub fn load_factory_replication_evidence_packet(
        &self,
        packet_id: &str,
    ) -> Result<FactoryReplicationEvidencePacket, StorageError> {
        let packet: FactoryReplicationEvidencePacket =
            self.read_json(self.factory_replication_evidence_packet_path(packet_id))?;
        packet.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory replication evidence packet validation failed: {error}"
            ))
        })?;
        Ok(packet)
    }

    pub fn persist_factory_identity_manifest(
        &self,
        manifest: &FactoryIdentityManifest,
    ) -> Result<(), StorageError> {
        manifest.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory identity manifest validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.factory_identity_manifest_path(&manifest.factory_identity_id),
            manifest,
        )
    }

    pub fn load_factory_identity_manifest(
        &self,
        factory_identity_id: &str,
    ) -> Result<FactoryIdentityManifest, StorageError> {
        let manifest: FactoryIdentityManifest =
            self.read_json(self.factory_identity_manifest_path(factory_identity_id))?;
        manifest.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory identity manifest validation failed: {error}"
            ))
        })?;
        Ok(manifest)
    }

    pub fn persist_factory_exchange_envelope(
        &self,
        envelope: &FactoryExchangeEnvelope,
    ) -> Result<(), StorageError> {
        envelope.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory exchange envelope validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.factory_exchange_envelope_path(&envelope.exchange_id),
            envelope,
        )
    }

    pub fn load_factory_exchange_envelope(
        &self,
        exchange_id: &str,
    ) -> Result<FactoryExchangeEnvelope, StorageError> {
        let envelope: FactoryExchangeEnvelope =
            self.read_json(self.factory_exchange_envelope_path(exchange_id))?;
        envelope.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory exchange envelope validation failed: {error}"
            ))
        })?;
        Ok(envelope)
    }

    pub fn persist_factory_compatibility_decision(
        &self,
        decision: &FactoryCompatibilityDecision,
    ) -> Result<(), StorageError> {
        decision.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory compatibility decision validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.factory_compatibility_decision_path(&decision.decision_id),
            decision,
        )
    }

    pub fn load_factory_compatibility_decision(
        &self,
        decision_id: &str,
    ) -> Result<FactoryCompatibilityDecision, StorageError> {
        let decision: FactoryCompatibilityDecision =
            self.read_json(self.factory_compatibility_decision_path(decision_id))?;
        decision.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory compatibility decision validation failed: {error}"
            ))
        })?;
        Ok(decision)
    }

    pub fn persist_imported_artifact_quarantine_packet(
        &self,
        packet: &ImportedArtifactQuarantinePacket,
    ) -> Result<(), StorageError> {
        packet.validate().map_err(|error| {
            storage_integrity_error(format!(
                "import quarantine packet validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.imported_artifact_quarantine_packet_path(&packet.quarantine_packet_id),
            packet,
        )
    }

    pub fn load_imported_artifact_quarantine_packet(
        &self,
        quarantine_packet_id: &str,
    ) -> Result<ImportedArtifactQuarantinePacket, StorageError> {
        let packet: ImportedArtifactQuarantinePacket =
            self.read_json(self.imported_artifact_quarantine_packet_path(quarantine_packet_id))?;
        packet.validate().map_err(|error| {
            storage_integrity_error(format!(
                "import quarantine packet validation failed: {error}"
            ))
        })?;
        Ok(packet)
    }

    pub fn persist_quarantine_first_import_state(
        &self,
        record: &QuarantineFirstImportStateRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "quarantine-first import state validation failed: {error}"
            ))
        })?;
        self.write_json(self.import_state_path(&record.import_state_id), record)
    }

    pub fn load_quarantine_first_import_state(
        &self,
        import_state_id: &str,
    ) -> Result<QuarantineFirstImportStateRecord, StorageError> {
        let record: QuarantineFirstImportStateRecord =
            self.read_json(self.import_state_path(import_state_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "quarantine-first import state validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_import_disposition(
        &self,
        record: &ImportDispositionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("import disposition validation failed: {error}"))
        })?;
        self.write_json(self.import_disposition_path(&record.disposition_id), record)
    }

    pub fn load_import_disposition(
        &self,
        disposition_id: &str,
    ) -> Result<ImportDispositionRecord, StorageError> {
        let record: ImportDispositionRecord =
            self.read_json(self.import_disposition_path(disposition_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("import disposition validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_cross_factory_lineage_import_record(
        &self,
        record: &CrossFactoryLineageImportRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "cross-factory lineage import validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.cross_factory_lineage_import_path(&record.lineage_import_id),
            record,
        )
    }

    pub fn load_cross_factory_lineage_import_record(
        &self,
        lineage_import_id: &str,
    ) -> Result<CrossFactoryLineageImportRecord, StorageError> {
        let record: CrossFactoryLineageImportRecord =
            self.read_json(self.cross_factory_lineage_import_path(lineage_import_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "cross-factory lineage import validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_memory_exchange_packet(
        &self,
        packet: &MemoryExchangePacket,
    ) -> Result<(), StorageError> {
        packet.validate().map_err(|error| {
            storage_integrity_error(format!("memory exchange packet validation failed: {error}"))
        })?;
        self.write_json(
            self.memory_exchange_packet_path(&packet.memory_exchange_id),
            packet,
        )
    }

    pub fn load_memory_exchange_packet(
        &self,
        memory_exchange_id: &str,
    ) -> Result<MemoryExchangePacket, StorageError> {
        let packet: MemoryExchangePacket =
            self.read_json(self.memory_exchange_packet_path(memory_exchange_id))?;
        packet.validate().map_err(|error| {
            storage_integrity_error(format!("memory exchange packet validation failed: {error}"))
        })?;
        Ok(packet)
    }

    pub fn persist_path_support_classification(
        &self,
        record: &PathSupportClassification,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "path support classification validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.path_support_classification_path(&record.path_ref),
            record,
        )
    }

    pub fn load_path_support_classification(
        &self,
        path_ref: &str,
    ) -> Result<PathSupportClassification, StorageError> {
        let record: PathSupportClassification =
            self.read_json(self.path_support_classification_path(path_ref))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "path support classification validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_universal_shell_launch_assembly(
        &self,
        record: &UniversalShellLaunchAssembly,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("universal shell launch validation failed: {error}"))
        })?;
        self.write_json(self.universal_shell_launch_path(&record.launch_id), record)
    }

    pub fn load_universal_shell_launch_assembly(
        &self,
        launch_id: &str,
    ) -> Result<UniversalShellLaunchAssembly, StorageError> {
        let record: UniversalShellLaunchAssembly =
            self.read_json(self.universal_shell_launch_path(launch_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("universal shell launch validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_campaign_admission_record(
        &self,
        record: &CampaignAdmissionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("campaign admission validation failed: {error}"))
        })?;
        self.write_json(
            self.campaign_admission_record_path(&record.admission_id),
            record,
        )
    }

    pub fn load_campaign_admission_record(
        &self,
        admission_id: &str,
    ) -> Result<CampaignAdmissionRecord, StorageError> {
        let record: CampaignAdmissionRecord =
            self.read_json(self.campaign_admission_record_path(admission_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("campaign admission validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_launch_refusal_record(
        &self,
        record: &LaunchRefusalRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("launch refusal validation failed: {error}"))
        })?;
        self.write_json(self.launch_refusal_record_path(&record.refusal_id), record)
    }

    pub fn load_launch_refusal_record(
        &self,
        refusal_id: &str,
    ) -> Result<LaunchRefusalRecord, StorageError> {
        let record: LaunchRefusalRecord =
            self.read_json(self.launch_refusal_record_path(refusal_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("launch refusal validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_program_to_shell_mapping(
        &self,
        record: &ProgramToShellMapping,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "program-to-shell mapping validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.program_to_shell_mapping_path(&record.mapping_id),
            record,
        )
    }

    pub fn load_program_to_shell_mapping(
        &self,
        mapping_id: &str,
    ) -> Result<ProgramToShellMapping, StorageError> {
        let record: ProgramToShellMapping =
            self.read_json(self.program_to_shell_mapping_path(mapping_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "program-to-shell mapping validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_unified_lifecycle_transition_record(
        &self,
        record: &UnifiedLifecycleTransitionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("lifecycle transition validation failed: {error}"))
        })?;
        self.write_json(
            self.lifecycle_transition_record_path(&record.transition_id),
            record,
        )
    }

    pub fn load_unified_lifecycle_transition_record(
        &self,
        transition_id: &str,
    ) -> Result<UnifiedLifecycleTransitionRecord, StorageError> {
        let record: UnifiedLifecycleTransitionRecord =
            self.read_json(self.lifecycle_transition_record_path(transition_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("lifecycle transition validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_resume_chain_record(
        &self,
        record: &ResumeChainRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("resume chain validation failed: {error}"))
        })?;
        self.write_json(
            self.resume_chain_record_path(&record.resume_chain_id),
            record,
        )
    }

    pub fn load_resume_chain_record(
        &self,
        resume_chain_id: &str,
    ) -> Result<ResumeChainRecord, StorageError> {
        let record: ResumeChainRecord =
            self.read_json(self.resume_chain_record_path(resume_chain_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("resume chain validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_shell_evidence_summary(
        &self,
        record: &ShellEvidenceSummary,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("shell evidence summary validation failed: {error}"))
        })?;
        self.write_json(self.shell_evidence_summary_path(&record.summary_id), record)
    }

    pub fn load_shell_evidence_summary(
        &self,
        summary_id: &str,
    ) -> Result<ShellEvidenceSummary, StorageError> {
        let record: ShellEvidenceSummary =
            self.read_json(self.shell_evidence_summary_path(summary_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("shell evidence summary validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_shell_derived_export_bundle(
        &self,
        record: &ShellDerivedExportBundle,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("shell-derived export validation failed: {error}"))
        })?;
        self.write_json(
            self.shell_derived_export_bundle_path(&record.export_id),
            record,
        )
    }

    pub fn load_shell_derived_export_bundle(
        &self,
        export_id: &str,
    ) -> Result<ShellDerivedExportBundle, StorageError> {
        let record: ShellDerivedExportBundle =
            self.read_json(self.shell_derived_export_bundle_path(export_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("shell-derived export validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_transitional_truth_annotation(
        &self,
        record: &TransitionalTruthAnnotation,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "transitional truth annotation validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.transitional_truth_annotation_path(&record.annotation_id),
            record,
        )
    }

    pub fn load_transitional_truth_annotation(
        &self,
        annotation_id: &str,
    ) -> Result<TransitionalTruthAnnotation, StorageError> {
        let record: TransitionalTruthAnnotation =
            self.read_json(self.transitional_truth_annotation_path(annotation_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "transitional truth annotation validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_transitional_adapter_manifest(
        &self,
        record: &TransitionalAdapterManifest,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "transitional adapter manifest validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.transitional_adapter_manifest_path(&record.adapter_id),
            record,
        )
    }

    pub fn load_transitional_adapter_manifest(
        &self,
        adapter_id: &str,
    ) -> Result<TransitionalAdapterManifest, StorageError> {
        let record: TransitionalAdapterManifest =
            self.read_json(self.transitional_adapter_manifest_path(adapter_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "transitional adapter manifest validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_migration_gate_record(
        &self,
        record: &MigrationGateRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("migration gate validation failed: {error}"))
        })?;
        self.write_json(self.migration_gate_record_path(&record.gate_id), record)
    }

    pub fn load_migration_gate_record(
        &self,
        gate_id: &str,
    ) -> Result<MigrationGateRecord, StorageError> {
        let record: MigrationGateRecord =
            self.read_json(self.migration_gate_record_path(gate_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("migration gate validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_path_retirement_record(
        &self,
        record: &PathRetirementRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("path retirement validation failed: {error}"))
        })?;
        self.write_json(
            self.path_retirement_record_path(&record.retirement_id),
            record,
        )
    }

    pub fn load_path_retirement_record(
        &self,
        retirement_id: &str,
    ) -> Result<PathRetirementRecord, StorageError> {
        let record: PathRetirementRecord =
            self.read_json(self.path_retirement_record_path(retirement_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("path retirement validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_acceptance_truth_matrix(
        &self,
        record: &AcceptanceTruthMatrix,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "acceptance truth matrix validation failed: {error}"
            ))
        })?;
        self.write_json(self.acceptance_truth_matrix_path(&record.matrix_id), record)
    }

    pub fn load_acceptance_truth_matrix(
        &self,
        matrix_id: &str,
    ) -> Result<AcceptanceTruthMatrix, StorageError> {
        let record: AcceptanceTruthMatrix =
            self.read_json(self.acceptance_truth_matrix_path(matrix_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "acceptance truth matrix validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_scheduler_tick_record(
        &self,
        record: &SchedulerTickRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("scheduler tick validation failed: {error}"))
        })?;
        self.write_json(self.scheduler_tick_record_path(&record.tick_id), record)
    }

    pub fn load_scheduler_tick_record(
        &self,
        tick_id: &str,
    ) -> Result<SchedulerTickRecord, StorageError> {
        let record: SchedulerTickRecord =
            self.read_json(self.scheduler_tick_record_path(tick_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("scheduler tick validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_scheduled_wake_record(
        &self,
        record: &ScheduledWakeRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("scheduled wake validation failed: {error}"))
        })?;
        self.write_json(
            self.scheduled_wake_record_path(&record.wake_record_id),
            record,
        )
    }

    pub fn load_scheduled_wake_record(
        &self,
        wake_record_id: &str,
    ) -> Result<ScheduledWakeRecord, StorageError> {
        let record: ScheduledWakeRecord =
            self.read_json(self.scheduled_wake_record_path(wake_record_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("scheduled wake validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_persistent_job_lease(
        &self,
        record: &PersistentJobLease,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("persistent job lease validation failed: {error}"))
        })?;
        self.write_json(self.persistent_job_lease_path(&record.lease_id), record)
    }

    pub fn load_persistent_job_lease(
        &self,
        lease_id: &str,
    ) -> Result<PersistentJobLease, StorageError> {
        let record: PersistentJobLease =
            self.read_json(self.persistent_job_lease_path(lease_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("persistent job lease validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_approval_inbox_record(
        &self,
        record: &ApprovalInboxRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("approval inbox validation failed: {error}"))
        })?;
        self.write_json(
            self.approval_inbox_record_path(&record.approval_inbox_id),
            record,
        )
    }

    pub fn load_approval_inbox_record(
        &self,
        approval_inbox_id: &str,
    ) -> Result<ApprovalInboxRecord, StorageError> {
        let record: ApprovalInboxRecord =
            self.read_json(self.approval_inbox_record_path(approval_inbox_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("approval inbox validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_deferred_decision_bundle(
        &self,
        record: &DeferredDecisionBundle,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "deferred decision bundle validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.deferred_decision_bundle_path(&record.decision_bundle_id),
            record,
        )
    }

    pub fn load_deferred_decision_bundle(
        &self,
        decision_bundle_id: &str,
    ) -> Result<DeferredDecisionBundle, StorageError> {
        let record: DeferredDecisionBundle =
            self.read_json(self.deferred_decision_bundle_path(decision_bundle_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "deferred decision bundle validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_lease_expiry_record(
        &self,
        record: &LeaseExpiryRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("lease expiry validation failed: {error}"))
        })?;
        self.write_json(self.lease_expiry_record_path(&record.expiry_id), record)
    }

    pub fn load_lease_expiry_record(
        &self,
        expiry_id: &str,
    ) -> Result<LeaseExpiryRecord, StorageError> {
        let record: LeaseExpiryRecord = self.read_json(self.lease_expiry_record_path(expiry_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("lease expiry validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_shell_escalation_record(
        &self,
        record: &ShellEscalationRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("shell escalation validation failed: {error}"))
        })?;
        self.write_json(
            self.shell_escalation_record_path(&record.escalation_id),
            record,
        )
    }

    pub fn load_shell_escalation_record(
        &self,
        escalation_id: &str,
    ) -> Result<ShellEscalationRecord, StorageError> {
        let record: ShellEscalationRecord =
            self.read_json(self.shell_escalation_record_path(escalation_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("shell escalation validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_consolidation_job_record(
        &self,
        record: &ConsolidationJobRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "consolidation job record validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.consolidation_job_record_path(&record.consolidation_id),
            record,
        )
    }

    pub fn load_consolidation_job_record(
        &self,
        consolidation_id: &str,
    ) -> Result<ConsolidationJobRecord, StorageError> {
        let record: ConsolidationJobRecord =
            self.read_json(self.consolidation_job_record_path(consolidation_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "consolidation job record validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_continuity_job_classification(
        &self,
        record: &ContinuityJobClassification,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("continuity job class validation failed: {error}"))
        })?;
        self.write_json(
            self.continuity_job_classification_path(&record.job_class_id),
            record,
        )
    }

    pub fn load_continuity_job_classification(
        &self,
        job_class_id: &str,
    ) -> Result<ContinuityJobClassification, StorageError> {
        let record: ContinuityJobClassification =
            self.read_json(self.continuity_job_classification_path(job_class_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("continuity job class validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_continuity_job_record(
        &self,
        record: &ContinuityJobRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("continuity job validation failed: {error}"))
        })?;
        self.write_json(
            self.continuity_job_record_path(&record.job_record_id),
            record,
        )
    }

    pub fn load_continuity_job_record(
        &self,
        job_record_id: &str,
    ) -> Result<ContinuityJobRecord, StorageError> {
        let record: ContinuityJobRecord =
            self.read_json(self.continuity_job_record_path(job_record_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("continuity job validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_persistent_shell_audit_packet(
        &self,
        record: &PersistentShellAuditPacket,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "persistent shell audit packet validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.persistent_shell_audit_packet_path(&record.audit_packet_id),
            record,
        )
    }

    pub fn load_persistent_shell_audit_packet(
        &self,
        audit_packet_id: &str,
    ) -> Result<PersistentShellAuditPacket, StorageError> {
        let record: PersistentShellAuditPacket =
            self.read_json(self.persistent_shell_audit_packet_path(audit_packet_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "persistent shell audit packet validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_persistent_shell_operations_dossier(
        &self,
        record: &PersistentShellOperationsDossier,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "persistent shell operations dossier validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.persistent_shell_operations_dossier_path(&record.operations_dossier_id),
            record,
        )
    }

    pub fn load_persistent_shell_operations_dossier(
        &self,
        operations_dossier_id: &str,
    ) -> Result<PersistentShellOperationsDossier, StorageError> {
        let record: PersistentShellOperationsDossier =
            self.read_json(self.persistent_shell_operations_dossier_path(operations_dossier_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "persistent shell operations dossier validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_service_family_manifest(
        &self,
        record: &ServiceFamilyManifest,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("service manifest validation failed: {error}"))
        })?;
        self.write_json(
            self.service_family_manifest_path(&record.service_manifest_id),
            record,
        )
    }

    pub fn load_service_family_manifest(
        &self,
        service_manifest_id: &str,
    ) -> Result<ServiceFamilyManifest, StorageError> {
        let record: ServiceFamilyManifest =
            self.read_json(self.service_family_manifest_path(service_manifest_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("service manifest validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_service_handle_lease(
        &self,
        record: &ServiceHandleLease,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("service handle validation failed: {error}"))
        })?;
        self.write_json(
            self.service_handle_lease_path(&record.service_handle_id),
            record,
        )
    }

    pub fn load_service_handle_lease(
        &self,
        service_handle_id: &str,
    ) -> Result<ServiceHandleLease, StorageError> {
        let record: ServiceHandleLease =
            self.read_json(self.service_handle_lease_path(service_handle_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("service handle validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_service_attestation_bundle(
        &self,
        record: &ServiceAttestationBundle,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("service attestation validation failed: {error}"))
        })?;
        self.write_json(
            self.service_attestation_bundle_path(&record.attestation_id),
            record,
        )
    }

    pub fn load_service_attestation_bundle(
        &self,
        attestation_id: &str,
    ) -> Result<ServiceAttestationBundle, StorageError> {
        let record: ServiceAttestationBundle =
            self.read_json(self.service_attestation_bundle_path(attestation_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("service attestation validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_service_closure_dossier(
        &self,
        record: &ServiceClosureDossier,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "service closure dossier validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.service_closure_dossier_path(&record.closure_dossier_id),
            record,
        )
    }

    pub fn load_service_closure_dossier(
        &self,
        closure_dossier_id: &str,
    ) -> Result<ServiceClosureDossier, StorageError> {
        let record: ServiceClosureDossier =
            self.read_json(self.service_closure_dossier_path(closure_dossier_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "service closure dossier validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_workflow_sufficiency_record(
        &self,
        record: &WorkflowSufficiencyRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("workflow sufficiency validation failed: {error}"))
        })?;
        self.write_json(
            self.workflow_sufficiency_record_path(&record.workflow_sufficiency_id),
            record,
        )
    }

    pub fn load_workflow_sufficiency_record(
        &self,
        workflow_sufficiency_id: &str,
    ) -> Result<WorkflowSufficiencyRecord, StorageError> {
        let record: WorkflowSufficiencyRecord =
            self.read_json(self.workflow_sufficiency_record_path(workflow_sufficiency_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("workflow sufficiency validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_workflow_service_closure_dossier(
        &self,
        record: &WorkflowServiceClosureDossier,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "workflow service closure dossier validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.workflow_service_closure_dossier_path(&record.workflow_dossier_id),
            record,
        )
    }

    pub fn load_workflow_service_closure_dossier(
        &self,
        workflow_dossier_id: &str,
    ) -> Result<WorkflowServiceClosureDossier, StorageError> {
        let record: WorkflowServiceClosureDossier =
            self.read_json(self.workflow_service_closure_dossier_path(workflow_dossier_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "workflow service closure dossier validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_worker_specialization_card(
        &self,
        record: &WorkerSpecializationCard,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("worker specialization validation failed: {error}"))
        })?;
        self.write_json(
            self.worker_specialization_card_path(&record.worker_card_id),
            record,
        )
    }

    pub fn load_worker_specialization_card(
        &self,
        worker_card_id: &str,
    ) -> Result<WorkerSpecializationCard, StorageError> {
        let record: WorkerSpecializationCard =
            self.read_json(self.worker_specialization_card_path(worker_card_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("worker specialization validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_worker_specialization_cards(
        &self,
    ) -> Result<Vec<WorkerSpecializationCard>, StorageError> {
        self.list_json_records(self.root.join("northstar-04").join("worker-cards"))
    }

    pub fn persist_ecology_snapshot(&self, record: &EcologySnapshot) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecology snapshot validation failed: {error}"))
        })?;
        self.write_json(
            self.ecology_snapshot_path(&record.ecology_snapshot_id),
            record,
        )
    }

    pub fn load_ecology_snapshot(
        &self,
        ecology_snapshot_id: &str,
    ) -> Result<EcologySnapshot, StorageError> {
        let record: EcologySnapshot =
            self.read_json(self.ecology_snapshot_path(ecology_snapshot_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecology snapshot validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_coordinator_planning_record(
        &self,
        record: &CoordinatorPlanningRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("coordinator planning validation failed: {error}"))
        })?;
        self.write_json(
            self.coordinator_planning_record_path(&record.planning_id),
            record,
        )
    }

    pub fn load_coordinator_planning_record(
        &self,
        planning_id: &str,
    ) -> Result<CoordinatorPlanningRecord, StorageError> {
        let record: CoordinatorPlanningRecord =
            self.read_json(self.coordinator_planning_record_path(planning_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("coordinator planning validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_work_lease(&self, record: &WorkLease) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("work lease validation failed: {error}"))
        })?;
        self.write_json(self.work_lease_path(&record.work_lease_id), record)
    }

    pub fn load_work_lease(&self, work_lease_id: &str) -> Result<WorkLease, StorageError> {
        let record: WorkLease = self.read_json(self.work_lease_path(work_lease_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("work lease validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_synthesis_dossier(&self, record: &SynthesisDossier) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("synthesis dossier validation failed: {error}"))
        })?;
        self.write_json(self.synthesis_dossier_path(&record.synthesis_id), record)
    }

    pub fn load_synthesis_dossier(
        &self,
        synthesis_id: &str,
    ) -> Result<SynthesisDossier, StorageError> {
        let record: SynthesisDossier = self.read_json(self.synthesis_dossier_path(synthesis_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("synthesis dossier validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_ecology_health_record(
        &self,
        record: &EcologyHealthRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecology health validation failed: {error}"))
        })?;
        self.write_json(
            self.ecology_health_record_path(&record.health_record_id),
            record,
        )
    }

    pub fn load_ecology_health_record(
        &self,
        health_record_id: &str,
    ) -> Result<EcologyHealthRecord, StorageError> {
        let record: EcologyHealthRecord =
            self.read_json(self.ecology_health_record_path(health_record_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecology health validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_routing_packet_record(
        &self,
        record: &RoutingPacketRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("routing packet validation failed: {error}"))
        })?;
        self.write_json(
            self.routing_packet_record_path(&record.routing_packet_id),
            record,
        )
    }

    pub fn load_routing_packet_record(
        &self,
        routing_packet_id: &str,
    ) -> Result<RoutingPacketRecord, StorageError> {
        let record: RoutingPacketRecord =
            self.read_json(self.routing_packet_record_path(routing_packet_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("routing packet validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_ecology_recovery_record(
        &self,
        record: &EcologyRecoveryRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecology recovery validation failed: {error}"))
        })?;
        self.write_json(
            self.ecology_recovery_record_path(&record.recovery_id),
            record,
        )
    }

    pub fn load_ecology_recovery_record(
        &self,
        recovery_id: &str,
    ) -> Result<EcologyRecoveryRecord, StorageError> {
        let record: EcologyRecoveryRecord =
            self.read_json(self.ecology_recovery_record_path(recovery_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecology recovery validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_service_closure_workspace_packet(
        &self,
        record: &ServiceClosureWorkspacePacket,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "service closure workspace validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.service_closure_workspace_packet_path(&record.service_workspace_id),
            record,
        )
    }

    pub fn load_service_closure_workspace_packet(
        &self,
        service_workspace_id: &str,
    ) -> Result<ServiceClosureWorkspacePacket, StorageError> {
        let record: ServiceClosureWorkspacePacket =
            self.read_json(self.service_closure_workspace_packet_path(service_workspace_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "service closure workspace validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_ecology_closure_workspace_packet(
        &self,
        record: &EcologyClosureWorkspacePacket,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecology closure workspace validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.ecology_closure_workspace_packet_path(&record.ecology_workspace_id),
            record,
        )
    }

    pub fn load_ecology_closure_workspace_packet(
        &self,
        ecology_workspace_id: &str,
    ) -> Result<EcologyClosureWorkspacePacket, StorageError> {
        let record: EcologyClosureWorkspacePacket =
            self.read_json(self.ecology_closure_workspace_packet_path(ecology_workspace_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecology closure workspace validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_phase02_acceptance_packet(
        &self,
        record: &Phase02AcceptancePacket,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("phase 02 acceptance validation failed: {error}"))
        })?;
        self.write_json(
            self.phase02_acceptance_packet_path(&record.acceptance_packet_id),
            record,
        )
    }

    pub fn load_phase02_acceptance_packet(
        &self,
        acceptance_packet_id: &str,
    ) -> Result<Phase02AcceptancePacket, StorageError> {
        let record: Phase02AcceptancePacket =
            self.read_json(self.phase02_acceptance_packet_path(acceptance_packet_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("phase 02 acceptance validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_factory_improvement_program(
        &self,
        record: &FactoryImprovementProgram,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory improvement program validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.factory_improvement_program_path(&record.improvement_program_id),
            record,
        )
    }

    pub fn load_factory_improvement_program(
        &self,
        improvement_program_id: &str,
    ) -> Result<FactoryImprovementProgram, StorageError> {
        let record: FactoryImprovementProgram =
            self.read_json(self.factory_improvement_program_path(improvement_program_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "factory improvement program validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_recursion_budget_record(
        &self,
        record: &RecursionBudgetRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("recursion budget validation failed: {error}"))
        })?;
        self.write_json(
            self.recursion_budget_record_path(&record.recursion_budget_id),
            record,
        )
    }

    pub fn load_recursion_budget_record(
        &self,
        recursion_budget_id: &str,
    ) -> Result<RecursionBudgetRecord, StorageError> {
        let record: RecursionBudgetRecord =
            self.read_json(self.recursion_budget_record_path(recursion_budget_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("recursion budget validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_later_factory_generation_agenda(
        &self,
        record: &LaterFactoryGenerationAgenda,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("generation agenda validation failed: {error}"))
        })?;
        self.write_json(
            self.later_factory_generation_agenda_path(&record.generation_agenda_id),
            record,
        )
    }

    pub fn load_later_factory_generation_agenda(
        &self,
        generation_agenda_id: &str,
    ) -> Result<LaterFactoryGenerationAgenda, StorageError> {
        let record: LaterFactoryGenerationAgenda =
            self.read_json(self.later_factory_generation_agenda_path(generation_agenda_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("generation agenda validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_adoption_window_record(
        &self,
        record: &AdoptionWindowRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("adoption window validation failed: {error}"))
        })?;
        self.write_json(
            self.adoption_window_record_path(&record.adoption_window_id),
            record,
        )
    }

    pub fn load_adoption_window_record(
        &self,
        adoption_window_id: &str,
    ) -> Result<AdoptionWindowRecord, StorageError> {
        let record: AdoptionWindowRecord =
            self.read_json(self.adoption_window_record_path(adoption_window_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("adoption window validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_lineage_health_dossier(
        &self,
        record: &LineageHealthDossier,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("lineage health validation failed: {error}"))
        })?;
        self.write_json(
            self.lineage_health_dossier_path(&record.lineage_health_id),
            record,
        )
    }

    pub fn load_lineage_health_dossier(
        &self,
        lineage_health_id: &str,
    ) -> Result<LineageHealthDossier, StorageError> {
        let record: LineageHealthDossier =
            self.read_json(self.lineage_health_dossier_path(lineage_health_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("lineage health validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_stop_condition_record(
        &self,
        record: &StopConditionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("stop condition validation failed: {error}"))
        })?;
        self.write_json(
            self.stop_condition_record_path(&record.stop_condition_id),
            record,
        )
    }

    pub fn load_stop_condition_record(
        &self,
        stop_condition_id: &str,
    ) -> Result<StopConditionRecord, StorageError> {
        let record: StopConditionRecord =
            self.read_json(self.stop_condition_record_path(stop_condition_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("stop condition validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_recurring_factory_program_record(
        &self,
        record: &RecurringFactoryProgramRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "recurring factory program validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.recurring_factory_program_record_path(&record.factory_program_id),
            record,
        )
    }

    pub fn load_recurring_factory_program_record(
        &self,
        factory_program_id: &str,
    ) -> Result<RecurringFactoryProgramRecord, StorageError> {
        let record: RecurringFactoryProgramRecord =
            self.read_json(self.recurring_factory_program_record_path(factory_program_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "recurring factory program validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_program_continuity_window_record(
        &self,
        record: &ProgramContinuityWindowRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "program continuity window validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.program_continuity_window_record_path(&record.continuity_window_id),
            record,
        )
    }

    pub fn load_program_continuity_window_record(
        &self,
        continuity_window_id: &str,
    ) -> Result<ProgramContinuityWindowRecord, StorageError> {
        let record: ProgramContinuityWindowRecord =
            self.read_json(self.program_continuity_window_record_path(continuity_window_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "program continuity window validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_program_budget_history_record(
        &self,
        record: &ProgramBudgetHistoryRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("program budget history validation failed: {error}"))
        })?;
        self.write_json(
            self.program_budget_history_record_path(&record.budget_history_id),
            record,
        )
    }

    pub fn load_program_budget_history_record(
        &self,
        budget_history_id: &str,
    ) -> Result<ProgramBudgetHistoryRecord, StorageError> {
        let record: ProgramBudgetHistoryRecord =
            self.read_json(self.program_budget_history_record_path(budget_history_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("program budget history validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_program_policy_compliance_record(
        &self,
        record: &ProgramPolicyComplianceRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "program policy compliance validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.program_policy_compliance_record_path(&record.policy_compliance_id),
            record,
        )
    }

    pub fn load_program_policy_compliance_record(
        &self,
        policy_compliance_id: &str,
    ) -> Result<ProgramPolicyComplianceRecord, StorageError> {
        let record: ProgramPolicyComplianceRecord =
            self.read_json(self.program_policy_compliance_record_path(policy_compliance_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "program policy compliance validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_later_factory_cycle_dossier(
        &self,
        record: &LaterFactoryCycleDossier,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "later-factory cycle dossier validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.later_factory_cycle_dossier_path(&record.cycle_dossier_id),
            record,
        )
    }

    pub fn load_later_factory_cycle_dossier(
        &self,
        cycle_dossier_id: &str,
    ) -> Result<LaterFactoryCycleDossier, StorageError> {
        let record: LaterFactoryCycleDossier =
            self.read_json(self.later_factory_cycle_dossier_path(cycle_dossier_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "later-factory cycle dossier validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_lineage_health_ledger(
        &self,
        record: &LineageHealthLedger,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("lineage health ledger validation failed: {error}"))
        })?;
        self.write_json(
            self.lineage_health_ledger_path(&record.lineage_ledger_id),
            record,
        )
    }

    pub fn load_lineage_health_ledger(
        &self,
        lineage_ledger_id: &str,
    ) -> Result<LineageHealthLedger, StorageError> {
        let record: LineageHealthLedger =
            self.read_json(self.lineage_health_ledger_path(lineage_ledger_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("lineage health ledger validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_regression_review_packet(
        &self,
        record: &RegressionReviewPacket,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "regression review packet validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.regression_review_packet_path(&record.regression_packet_id),
            record,
        )
    }

    pub fn load_regression_review_packet(
        &self,
        regression_packet_id: &str,
    ) -> Result<RegressionReviewPacket, StorageError> {
        let record: RegressionReviewPacket =
            self.read_json(self.regression_review_packet_path(regression_packet_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "regression review packet validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_longitudinal_lineage_dossier(
        &self,
        record: &LongitudinalLineageDossier,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "longitudinal lineage dossier validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.longitudinal_lineage_dossier_path(&record.lineage_dossier_id),
            record,
        )
    }

    pub fn load_longitudinal_lineage_dossier(
        &self,
        lineage_dossier_id: &str,
    ) -> Result<LongitudinalLineageDossier, StorageError> {
        let record: LongitudinalLineageDossier =
            self.read_json(self.longitudinal_lineage_dossier_path(lineage_dossier_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "longitudinal lineage dossier validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_trust_profile(&self, record: &TrustProfile) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("trust profile validation failed: {error}"))
        })?;
        self.write_json(self.trust_profile_path(&record.trust_profile_id), record)
    }

    pub fn load_trust_profile(&self, trust_profile_id: &str) -> Result<TrustProfile, StorageError> {
        let record: TrustProfile = self.read_json(self.trust_profile_path(trust_profile_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("trust profile validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_ecosystem_admission_record(
        &self,
        record: &EcosystemAdmissionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecosystem admission validation failed: {error}"))
        })?;
        self.write_json(
            self.ecosystem_admission_record_path(&record.admission_id),
            record,
        )
    }

    pub fn load_ecosystem_admission_record(
        &self,
        admission_id: &str,
    ) -> Result<EcosystemAdmissionRecord, StorageError> {
        let record: EcosystemAdmissionRecord =
            self.read_json(self.ecosystem_admission_record_path(admission_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecosystem admission validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_exchange_route_record(
        &self,
        record: &ExchangeRouteRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("exchange route validation failed: {error}"))
        })?;
        self.write_json(self.exchange_route_record_path(&record.route_id), record)
    }

    pub fn load_exchange_route_record(
        &self,
        route_id: &str,
    ) -> Result<ExchangeRouteRecord, StorageError> {
        let record: ExchangeRouteRecord =
            self.read_json(self.exchange_route_record_path(route_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("exchange route validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_route_compatibility_cycle(
        &self,
        record: &RouteCompatibilityCycle,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "route compatibility cycle validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.route_compatibility_cycle_path(&record.compatibility_cycle_id),
            record,
        )
    }

    pub fn load_route_compatibility_cycle(
        &self,
        compatibility_cycle_id: &str,
    ) -> Result<RouteCompatibilityCycle, StorageError> {
        let record: RouteCompatibilityCycle =
            self.read_json(self.route_compatibility_cycle_path(compatibility_cycle_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "route compatibility cycle validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_cross_factory_adoption_dossier(
        &self,
        record: &CrossFactoryAdoptionDossier,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("cross-factory adoption validation failed: {error}"))
        })?;
        self.write_json(
            self.cross_factory_adoption_dossier_path(&record.adoption_dossier_id),
            record,
        )
    }

    pub fn load_cross_factory_adoption_dossier(
        &self,
        adoption_dossier_id: &str,
    ) -> Result<CrossFactoryAdoptionDossier, StorageError> {
        let record: CrossFactoryAdoptionDossier =
            self.read_json(self.cross_factory_adoption_dossier_path(adoption_dossier_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("cross-factory adoption validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_ecosystem_rollback_choreography_record(
        &self,
        record: &EcosystemRollbackChoreographyRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem rollback choreography validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.ecosystem_rollback_choreography_record_path(&record.rollback_choreography_id),
            record,
        )
    }

    pub fn load_ecosystem_rollback_choreography_record(
        &self,
        rollback_choreography_id: &str,
    ) -> Result<EcosystemRollbackChoreographyRecord, StorageError> {
        let record: EcosystemRollbackChoreographyRecord = self.read_json(
            self.ecosystem_rollback_choreography_record_path(rollback_choreography_id),
        )?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem rollback choreography validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_ecosystem_workspace_snapshot(
        &self,
        record: &EcosystemWorkspaceSnapshot,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecosystem workspace validation failed: {error}"))
        })?;
        self.write_json(
            self.ecosystem_workspace_snapshot_path(&record.workspace_id),
            record,
        )
    }

    pub fn load_ecosystem_workspace_snapshot(
        &self,
        workspace_id: &str,
    ) -> Result<EcosystemWorkspaceSnapshot, StorageError> {
        let record: EcosystemWorkspaceSnapshot =
            self.read_json(self.ecosystem_workspace_snapshot_path(workspace_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecosystem workspace validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_ecosystem_health_snapshot(
        &self,
        record: &EcosystemHealthSnapshot,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecosystem health validation failed: {error}"))
        })?;
        self.write_json(
            self.ecosystem_health_snapshot_path(&record.ecosystem_snapshot_id),
            record,
        )
    }

    pub fn load_ecosystem_health_snapshot(
        &self,
        ecosystem_snapshot_id: &str,
    ) -> Result<EcosystemHealthSnapshot, StorageError> {
        let record: EcosystemHealthSnapshot =
            self.read_json(self.ecosystem_health_snapshot_path(ecosystem_snapshot_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecosystem health validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_ecosystem_admission_profile(
        &self,
        record: &EcosystemAdmissionProfile,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem admission profile validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.ecosystem_admission_profile_path(&record.admission_profile_id),
            record,
        )
    }

    pub fn load_ecosystem_admission_profile(
        &self,
        admission_profile_id: &str,
    ) -> Result<EcosystemAdmissionProfile, StorageError> {
        let record: EcosystemAdmissionProfile =
            self.read_json(self.ecosystem_admission_profile_path(admission_profile_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem admission profile validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_route_exchange_history_record(
        &self,
        record: &RouteExchangeHistoryRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem route history validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.route_exchange_history_record_path(&record.route_history_id),
            record,
        )
    }

    pub fn load_route_exchange_history_record(
        &self,
        route_history_id: &str,
    ) -> Result<RouteExchangeHistoryRecord, StorageError> {
        let record: RouteExchangeHistoryRecord =
            self.read_json(self.route_exchange_history_record_path(route_history_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem route history validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_ecosystem_exchange_route_ledger(
        &self,
        record: &EcosystemExchangeRouteLedger,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecosystem route ledger validation failed: {error}"))
        })?;
        self.write_json(
            self.ecosystem_exchange_route_ledger_path(&record.exchange_route_ledger_id),
            record,
        )
    }

    pub fn load_ecosystem_exchange_route_ledger(
        &self,
        exchange_route_ledger_id: &str,
    ) -> Result<EcosystemExchangeRouteLedger, StorageError> {
        let record: EcosystemExchangeRouteLedger =
            self.read_json(self.ecosystem_exchange_route_ledger_path(exchange_route_ledger_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("ecosystem route ledger validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_ecosystem_continuity_window(
        &self,
        record: &EcosystemContinuityWindowRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem continuity window validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.ecosystem_continuity_window_path(&record.continuity_window_id),
            record,
        )
    }

    pub fn load_ecosystem_continuity_window(
        &self,
        continuity_window_id: &str,
    ) -> Result<EcosystemContinuityWindowRecord, StorageError> {
        let record: EcosystemContinuityWindowRecord =
            self.read_json(self.ecosystem_continuity_window_path(continuity_window_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem continuity window validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_ecosystem_rollback_symmetry_record(
        &self,
        record: &EcosystemRollbackSymmetryRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem rollback symmetry validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.ecosystem_rollback_symmetry_record_path(&record.rollback_symmetry_id),
            record,
        )
    }

    pub fn load_ecosystem_rollback_symmetry_record(
        &self,
        rollback_symmetry_id: &str,
    ) -> Result<EcosystemRollbackSymmetryRecord, StorageError> {
        let record: EcosystemRollbackSymmetryRecord =
            self.read_json(self.ecosystem_rollback_symmetry_record_path(rollback_symmetry_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem rollback symmetry validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_ecosystem_compatibility_persistence_record(
        &self,
        record: &EcosystemCompatibilityPersistenceRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem compatibility persistence validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.ecosystem_compatibility_persistence_record_path(
                &record.compatibility_persistence_id,
            ),
            record,
        )
    }

    pub fn load_ecosystem_compatibility_persistence_record(
        &self,
        compatibility_persistence_id: &str,
    ) -> Result<EcosystemCompatibilityPersistenceRecord, StorageError> {
        let record: EcosystemCompatibilityPersistenceRecord = self.read_json(
            self.ecosystem_compatibility_persistence_record_path(compatibility_persistence_id),
        )?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem compatibility persistence validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_ecosystem_health_ledger(
        &self,
        record: &EcosystemHealthLedger,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem health ledger validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.ecosystem_health_ledger_path(&record.ecosystem_health_id),
            record,
        )
    }

    pub fn load_ecosystem_health_ledger(
        &self,
        ecosystem_health_id: &str,
    ) -> Result<EcosystemHealthLedger, StorageError> {
        let record: EcosystemHealthLedger =
            self.read_json(self.ecosystem_health_ledger_path(ecosystem_health_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem health ledger validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_recurring_factory_workspace_packet(
        &self,
        record: &RecurringFactoryWorkspacePacket,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "recurring factory workspace validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.recurring_factory_workspace_packet_path(&record.factory_workspace_id),
            record,
        )
    }

    pub fn load_recurring_factory_workspace_packet(
        &self,
        factory_workspace_id: &str,
    ) -> Result<RecurringFactoryWorkspacePacket, StorageError> {
        let record: RecurringFactoryWorkspacePacket =
            self.read_json(self.recurring_factory_workspace_packet_path(factory_workspace_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "recurring factory workspace validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_ecosystem_closure_workspace_packet(
        &self,
        record: &EcosystemClosureWorkspacePacket,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem closure workspace validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.ecosystem_closure_workspace_packet_path(&record.ecosystem_workspace_id),
            record,
        )
    }

    pub fn load_ecosystem_closure_workspace_packet(
        &self,
        ecosystem_workspace_id: &str,
    ) -> Result<EcosystemClosureWorkspacePacket, StorageError> {
        let record: EcosystemClosureWorkspacePacket =
            self.read_json(self.ecosystem_closure_workspace_packet_path(ecosystem_workspace_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "ecosystem closure workspace validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_phase03_closure_review_packet(
        &self,
        record: &Phase03ClosureReviewPacket,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "phase03 closure review packet validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.phase03_closure_review_packet_path(&record.closure_review_packet_id),
            record,
        )
    }

    pub fn load_phase03_closure_review_packet(
        &self,
        closure_review_packet_id: &str,
    ) -> Result<Phase03ClosureReviewPacket, StorageError> {
        let record: Phase03ClosureReviewPacket =
            self.read_json(self.phase03_closure_review_packet_path(closure_review_packet_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "phase03 closure review packet validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_closure_criteria_matrix(
        &self,
        record: &ClosureCriteriaMatrix,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "closure criteria matrix validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.closure_criteria_matrix_path(&record.criteria_matrix_id),
            record,
        )
    }

    pub fn load_closure_criteria_matrix(
        &self,
        criteria_matrix_id: &str,
    ) -> Result<ClosureCriteriaMatrix, StorageError> {
        let record: ClosureCriteriaMatrix =
            self.read_json(self.closure_criteria_matrix_path(criteria_matrix_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "closure criteria matrix validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_evidence_inventory_packet(
        &self,
        record: &EvidenceInventoryPacket,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("evidence inventory validation failed: {error}"))
        })?;
        self.write_json(
            self.evidence_inventory_packet_path(&record.inventory_packet_id),
            record,
        )
    }

    pub fn load_evidence_inventory_packet(
        &self,
        inventory_packet_id: &str,
    ) -> Result<EvidenceInventoryPacket, StorageError> {
        let record: EvidenceInventoryPacket =
            self.read_json(self.evidence_inventory_packet_path(inventory_packet_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("evidence inventory validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_adversarial_review_record(
        &self,
        record: &AdversarialReviewRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("adversarial review validation failed: {error}"))
        })?;
        self.write_json(
            self.adversarial_review_record_path(&record.adversarial_review_id),
            record,
        )
    }

    pub fn load_adversarial_review_record(
        &self,
        adversarial_review_id: &str,
    ) -> Result<AdversarialReviewRecord, StorageError> {
        let record: AdversarialReviewRecord =
            self.read_json(self.adversarial_review_record_path(adversarial_review_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("adversarial review validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_residual_risk_record(
        &self,
        record: &ResidualRiskRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("residual risk validation failed: {error}"))
        })?;
        self.write_json(
            self.residual_risk_record_path(&record.risk_record_id),
            record,
        )
    }

    pub fn load_residual_risk_record(
        &self,
        risk_record_id: &str,
    ) -> Result<ResidualRiskRecord, StorageError> {
        let record: ResidualRiskRecord =
            self.read_json(self.residual_risk_record_path(risk_record_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("residual risk validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_closure_dossier(&self, record: &ClosureDossier) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("closure dossier validation failed: {error}"))
        })?;
        self.write_json(
            self.closure_dossier_path(&record.closure_dossier_id),
            record,
        )
    }

    pub fn load_closure_dossier(
        &self,
        closure_dossier_id: &str,
    ) -> Result<ClosureDossier, StorageError> {
        let record: ClosureDossier =
            self.read_json(self.closure_dossier_path(closure_dossier_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("closure dossier validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_claim_boundary_review_packet(
        &self,
        record: &ClaimBoundaryReviewPacket,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("claim-boundary packet validation failed: {error}"))
        })?;
        self.write_json(
            self.claim_boundary_review_packet_path(&record.claim_review_id),
            record,
        )
    }

    pub fn load_claim_boundary_review_packet(
        &self,
        claim_review_id: &str,
    ) -> Result<ClaimBoundaryReviewPacket, StorageError> {
        let record: ClaimBoundaryReviewPacket =
            self.read_json(self.claim_boundary_review_packet_path(claim_review_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("claim-boundary packet validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_closure_decision_record(
        &self,
        record: &ClosureDecisionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("closure decision validation failed: {error}"))
        })?;
        self.write_json(
            self.closure_decision_record_path(&record.closure_decision_id),
            record,
        )
    }

    pub fn load_closure_decision_record(
        &self,
        closure_decision_id: &str,
    ) -> Result<ClosureDecisionRecord, StorageError> {
        let record: ClosureDecisionRecord =
            self.read_json(self.closure_decision_record_path(closure_decision_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("closure decision validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_publication_policy_record(
        &self,
        record: &PublicationPolicyRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("publication policy validation failed: {error}"))
        })?;
        self.write_json(
            self.publication_policy_record_path(&record.publication_policy_id),
            record,
        )
    }

    pub fn load_publication_policy_record(
        &self,
        publication_policy_id: &str,
    ) -> Result<PublicationPolicyRecord, StorageError> {
        let record: PublicationPolicyRecord =
            self.read_json(self.publication_policy_record_path(publication_policy_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("publication policy validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_inference_provider_registry_entry(
        &self,
        record: &InferenceProviderRegistryEntry,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference provider validation failed: {error}"))
        })?;
        self.write_json(
            self.inference_provider_registry_entry_path(&record.provider_id),
            record,
        )
    }

    pub fn load_inference_provider_registry_entry(
        &self,
        provider_id: &str,
    ) -> Result<InferenceProviderRegistryEntry, StorageError> {
        let record: InferenceProviderRegistryEntry =
            self.read_json(self.inference_provider_registry_entry_path(provider_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference provider validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_inference_provider_registry_entries(
        &self,
    ) -> Result<Vec<InferenceProviderRegistryEntry>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("providers"))
    }

    pub fn persist_inference_generation_policy(
        &self,
        record: &InferenceGenerationPolicy,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "inference generation policy validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.inference_generation_policy_path(&record.generation_policy_id),
            record,
        )
    }

    pub fn load_inference_generation_policy(
        &self,
        generation_policy_id: &str,
    ) -> Result<InferenceGenerationPolicy, StorageError> {
        let record: InferenceGenerationPolicy =
            self.read_json(self.inference_generation_policy_path(generation_policy_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "inference generation policy validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_inference_turn_request(
        &self,
        record: &InferenceTurnRequest,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference turn request validation failed: {error}"))
        })?;
        self.write_json(
            self.inference_turn_request_path(&record.turn_request_id),
            record,
        )
    }

    pub fn load_inference_turn_request(
        &self,
        turn_request_id: &str,
    ) -> Result<InferenceTurnRequest, StorageError> {
        let record: InferenceTurnRequest =
            self.read_json(self.inference_turn_request_path(turn_request_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference turn request validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_inference_rendered_prompt_record(
        &self,
        record: &InferenceRenderedPromptRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "inference rendered prompt validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.inference_rendered_prompt_record_path(&record.rendered_prompt_id),
            record,
        )
    }

    pub fn load_inference_rendered_prompt_record(
        &self,
        rendered_prompt_id: &str,
    ) -> Result<InferenceRenderedPromptRecord, StorageError> {
        let record: InferenceRenderedPromptRecord =
            self.read_json(self.inference_rendered_prompt_record_path(rendered_prompt_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "inference rendered prompt validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_inference_tool_catalog_payload_record(
        &self,
        record: &InferenceToolCatalogPayloadRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference tool catalog validation failed: {error}"))
        })?;
        self.write_json(
            self.inference_tool_catalog_payload_record_path(&record.tool_catalog_id),
            record,
        )
    }

    pub fn load_inference_tool_catalog_payload_record(
        &self,
        tool_catalog_id: &str,
    ) -> Result<InferenceToolCatalogPayloadRecord, StorageError> {
        let record: InferenceToolCatalogPayloadRecord =
            self.read_json(self.inference_tool_catalog_payload_record_path(tool_catalog_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference tool catalog validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_inference_response_schema_payload_record(
        &self,
        record: &InferenceResponseSchemaPayloadRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "inference response schema validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.inference_response_schema_payload_record_path(&record.response_schema_id),
            record,
        )
    }

    pub fn load_inference_response_schema_payload_record(
        &self,
        response_schema_id: &str,
    ) -> Result<InferenceResponseSchemaPayloadRecord, StorageError> {
        let record: InferenceResponseSchemaPayloadRecord =
            self.read_json(self.inference_response_schema_payload_record_path(response_schema_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "inference response schema validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_inference_request_body_record(
        &self,
        record: &InferenceRequestBodyRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference request body validation failed: {error}"))
        })?;
        self.write_json(
            self.inference_request_body_record_path(&record.request_body_id),
            record,
        )
    }

    pub fn load_inference_request_body_record(
        &self,
        request_body_id: &str,
    ) -> Result<InferenceRequestBodyRecord, StorageError> {
        let record: InferenceRequestBodyRecord =
            self.read_json(self.inference_request_body_record_path(request_body_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference request body validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_inference_raw_output_record(
        &self,
        record: &InferenceRawOutputRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference raw output validation failed: {error}"))
        })?;
        self.write_json(
            self.inference_raw_output_record_path(&record.raw_output_id),
            record,
        )
    }

    pub fn load_inference_raw_output_record(
        &self,
        raw_output_id: &str,
    ) -> Result<InferenceRawOutputRecord, StorageError> {
        let record: InferenceRawOutputRecord =
            self.read_json(self.inference_raw_output_record_path(raw_output_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference raw output validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_inference_attempt_record(
        &self,
        record: &InferenceAttemptRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference attempt validation failed: {error}"))
        })?;
        self.write_json(
            self.inference_attempt_record_path(&record.attempt_id),
            record,
        )
    }

    pub fn load_inference_attempt_record(
        &self,
        attempt_id: &str,
    ) -> Result<InferenceAttemptRecord, StorageError> {
        let record: InferenceAttemptRecord =
            self.read_json(self.inference_attempt_record_path(attempt_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference attempt validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_inference_usage_record(
        &self,
        record: &InferenceUsageRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference usage validation failed: {error}"))
        })?;
        self.write_json(
            self.inference_usage_record_path(&record.usage_record_id),
            record,
        )
    }

    pub fn load_inference_usage_record(
        &self,
        usage_record_id: &str,
    ) -> Result<InferenceUsageRecord, StorageError> {
        let record: InferenceUsageRecord =
            self.read_json(self.inference_usage_record_path(usage_record_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference usage validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_inference_provider_outcome_record(
        &self,
        record: &InferenceProviderOutcomeRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "inference provider outcome validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.inference_provider_outcome_record_path(&record.provider_outcome_id),
            record,
        )
    }

    pub fn load_inference_provider_outcome_record(
        &self,
        provider_outcome_id: &str,
    ) -> Result<InferenceProviderOutcomeRecord, StorageError> {
        let record: InferenceProviderOutcomeRecord =
            self.read_json(self.inference_provider_outcome_record_path(provider_outcome_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "inference provider outcome validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_inference_parsed_output_record(
        &self,
        record: &InferenceParsedOutputRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "inference parsed output validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.inference_parsed_output_record_path(&record.parsed_output_id),
            record,
        )
    }

    pub fn load_inference_parsed_output_record(
        &self,
        parsed_output_id: &str,
    ) -> Result<InferenceParsedOutputRecord, StorageError> {
        let record: InferenceParsedOutputRecord =
            self.read_json(self.inference_parsed_output_record_path(parsed_output_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "inference parsed output validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn persist_inference_turn_result(
        &self,
        record: &InferenceTurnResult,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference turn result validation failed: {error}"))
        })?;
        self.write_json(
            self.inference_turn_result_path(&record.turn_result_id),
            record,
        )
    }

    pub fn load_inference_turn_result(
        &self,
        turn_result_id: &str,
    ) -> Result<InferenceTurnResult, StorageError> {
        let record: InferenceTurnResult =
            self.read_json(self.inference_turn_result_path(turn_result_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("inference turn result validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_inference_turn_results(&self) -> Result<Vec<InferenceTurnResult>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("turn-results"))
    }

    pub fn persist_provider_degradation_record(
        &self,
        record: &ProviderDegradationRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("provider degradation validation failed: {error}"))
        })?;
        self.write_json(
            self.provider_degradation_record_path(&record.degradation_id),
            record,
        )
    }

    pub fn load_provider_degradation_record(
        &self,
        degradation_id: &str,
    ) -> Result<ProviderDegradationRecord, StorageError> {
        let record: ProviderDegradationRecord =
            self.read_json(self.provider_degradation_record_path(degradation_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("provider degradation validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_turn_package(&self, record: &TurnPackage) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("turn package validation failed: {error}"))
        })?;
        self.write_json(self.turn_package_path(&record.turn_package_id), record)
    }

    pub fn load_turn_package(&self, turn_package_id: &str) -> Result<TurnPackage, StorageError> {
        let record: TurnPackage = self.read_json(self.turn_package_path(turn_package_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("turn package validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_turn_packages(&self) -> Result<Vec<TurnPackage>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("turn-packages"))
    }

    pub fn persist_model_continuity_bundle(
        &self,
        bundle: &ModelContinuityBundle,
    ) -> Result<(), StorageError> {
        bundle.validate().map_err(|error| {
            storage_integrity_error(format!(
                "model continuity bundle validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.continuity_bundle_path(&bundle.continuity_bundle_id),
            bundle,
        )
    }

    pub fn load_model_continuity_bundle(
        &self,
        continuity_bundle_id: &str,
    ) -> Result<ModelContinuityBundle, StorageError> {
        let bundle: ModelContinuityBundle =
            self.read_json(self.continuity_bundle_path(continuity_bundle_id))?;
        bundle.validate().map_err(|error| {
            storage_integrity_error(format!(
                "model continuity bundle validation failed: {error}"
            ))
        })?;
        Ok(bundle)
    }

    pub fn list_model_continuity_bundles(
        &self,
    ) -> Result<Vec<ModelContinuityBundle>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("continuity-bundles"))
    }

    pub fn persist_turn_grounding_packet(
        &self,
        packet: &TurnGroundingPacket,
    ) -> Result<(), StorageError> {
        packet.validate().map_err(|error| {
            storage_integrity_error(format!("turn grounding packet validation failed: {error}"))
        })?;
        self.write_json(
            self.turn_grounding_packet_path(&packet.turn_grounding_packet_id),
            packet,
        )
    }

    pub fn load_turn_grounding_packet(
        &self,
        turn_grounding_packet_id: &str,
    ) -> Result<TurnGroundingPacket, StorageError> {
        let packet: TurnGroundingPacket =
            self.read_json(self.turn_grounding_packet_path(turn_grounding_packet_id))?;
        packet.validate().map_err(|error| {
            storage_integrity_error(format!("turn grounding packet validation failed: {error}"))
        })?;
        Ok(packet)
    }

    pub fn list_turn_grounding_packets(&self) -> Result<Vec<TurnGroundingPacket>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("turn-groundings"))
    }

    pub fn persist_memory_retrieval_trace(
        &self,
        trace: &MemoryRetrievalTrace,
    ) -> Result<(), StorageError> {
        trace.validate().map_err(|error| {
            storage_integrity_error(format!(
                "continuity retrieval trace validation failed: {error}"
            ))
        })?;
        self.write_json(self.continuity_retrieval_trace_path(&trace.trace_id), trace)
    }

    pub fn load_memory_retrieval_trace(
        &self,
        trace_id: &str,
    ) -> Result<MemoryRetrievalTrace, StorageError> {
        let trace: MemoryRetrievalTrace =
            self.read_json(self.continuity_retrieval_trace_path(trace_id))?;
        trace.validate().map_err(|error| {
            storage_integrity_error(format!(
                "continuity retrieval trace validation failed: {error}"
            ))
        })?;
        Ok(trace)
    }

    pub fn list_memory_retrieval_traces(&self) -> Result<Vec<MemoryRetrievalTrace>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("continuity-retrieval-traces"),
        )
    }

    pub fn persist_open_question_ledger(
        &self,
        ledger: &OpenQuestionLedger,
    ) -> Result<(), StorageError> {
        ledger.validate().map_err(|error| {
            storage_integrity_error(format!("open question ledger validation failed: {error}"))
        })?;
        self.write_json(
            self.open_question_ledger_path(&ledger.open_question_ledger_id),
            ledger,
        )
    }

    pub fn load_open_question_ledger(
        &self,
        open_question_ledger_id: &str,
    ) -> Result<OpenQuestionLedger, StorageError> {
        let ledger: OpenQuestionLedger =
            self.read_json(self.open_question_ledger_path(open_question_ledger_id))?;
        ledger.validate().map_err(|error| {
            storage_integrity_error(format!("open question ledger validation failed: {error}"))
        })?;
        Ok(ledger)
    }

    pub fn list_open_question_ledgers(&self) -> Result<Vec<OpenQuestionLedger>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("open-question-ledgers"),
        )
    }

    pub fn persist_contradiction_carry_forward(
        &self,
        record: &ContradictionCarryForwardRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "contradiction carry-forward validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.contradiction_carry_forward_path(&record.contradiction_carry_forward_id),
            record,
        )
    }

    pub fn load_contradiction_carry_forward(
        &self,
        contradiction_carry_forward_id: &str,
    ) -> Result<ContradictionCarryForwardRecord, StorageError> {
        let record: ContradictionCarryForwardRecord =
            self.read_json(self.contradiction_carry_forward_path(contradiction_carry_forward_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "contradiction carry-forward validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn list_contradiction_carry_forwards(
        &self,
    ) -> Result<Vec<ContradictionCarryForwardRecord>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("contradiction-carry-forwards"),
        )
    }

    pub fn persist_verified_turn_memory_update(
        &self,
        update: &VerifiedTurnMemoryUpdate,
    ) -> Result<(), StorageError> {
        update.validate().map_err(|error| {
            storage_integrity_error(format!(
                "verified turn memory update validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.turn_memory_update_path(&update.turn_memory_update_id),
            update,
        )
    }

    pub fn load_verified_turn_memory_update(
        &self,
        turn_memory_update_id: &str,
    ) -> Result<VerifiedTurnMemoryUpdate, StorageError> {
        let update: VerifiedTurnMemoryUpdate =
            self.read_json(self.turn_memory_update_path(turn_memory_update_id))?;
        update.validate().map_err(|error| {
            storage_integrity_error(format!(
                "verified turn memory update validation failed: {error}"
            ))
        })?;
        Ok(update)
    }

    pub fn list_verified_turn_memory_updates(
        &self,
    ) -> Result<Vec<VerifiedTurnMemoryUpdate>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("turn-memory-updates"))
    }

    pub fn persist_context_budget_record(
        &self,
        record: &ContextBudgetRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("context budget validation failed: {error}"))
        })?;
        self.write_json(
            self.context_budget_record_path(&record.context_budget_id),
            record,
        )
    }

    pub fn load_context_budget_record(
        &self,
        context_budget_id: &str,
    ) -> Result<ContextBudgetRecord, StorageError> {
        let record: ContextBudgetRecord =
            self.read_json(self.context_budget_record_path(context_budget_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("context budget validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_context_truncation_record(
        &self,
        record: &ContextTruncationRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("context truncation validation failed: {error}"))
        })?;
        self.write_json(
            self.context_truncation_record_path(&record.context_truncation_id),
            record,
        )
    }

    pub fn load_context_truncation_record(
        &self,
        context_truncation_id: &str,
    ) -> Result<ContextTruncationRecord, StorageError> {
        let record: ContextTruncationRecord =
            self.read_json(self.context_truncation_record_path(context_truncation_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("context truncation validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_context_truncation_records(
        &self,
    ) -> Result<Vec<ContextTruncationRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("context-truncations"))
    }

    pub fn persist_prompt_layer_record(
        &self,
        record: &PromptLayerRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("prompt layer validation failed: {error}"))
        })?;
        self.write_json(
            self.prompt_layer_record_path(&record.prompt_layer_id),
            record,
        )
    }

    pub fn load_prompt_layer_record(
        &self,
        prompt_layer_id: &str,
    ) -> Result<PromptLayerRecord, StorageError> {
        let record: PromptLayerRecord =
            self.read_json(self.prompt_layer_record_path(prompt_layer_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("prompt layer validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_prompt_layer_records(&self) -> Result<Vec<PromptLayerRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("prompt-layers"))
    }

    pub fn persist_prompt_rendering_record(
        &self,
        record: &PromptRenderingRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("prompt rendering validation failed: {error}"))
        })?;
        self.write_json(
            self.prompt_rendering_record_path(&record.prompt_rendering_id),
            record,
        )
    }

    pub fn load_prompt_rendering_record(
        &self,
        prompt_rendering_id: &str,
    ) -> Result<PromptRenderingRecord, StorageError> {
        let record: PromptRenderingRecord =
            self.read_json(self.prompt_rendering_record_path(prompt_rendering_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("prompt rendering validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_prompt_rendering_records(
        &self,
    ) -> Result<Vec<PromptRenderingRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("prompt-renderings"))
    }

    pub fn persist_turn_response_schema_record(
        &self,
        record: &TurnResponseSchemaRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("turn response schema validation failed: {error}"))
        })?;
        self.write_json(
            self.turn_response_schema_record_path(&record.turn_response_schema_id),
            record,
        )
    }

    pub fn load_turn_response_schema_record(
        &self,
        turn_response_schema_id: &str,
    ) -> Result<TurnResponseSchemaRecord, StorageError> {
        let record: TurnResponseSchemaRecord =
            self.read_json(self.turn_response_schema_record_path(turn_response_schema_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("turn response schema validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_turn_response_schema_records(
        &self,
    ) -> Result<Vec<TurnResponseSchemaRecord>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("turn-response-schemas"),
        )
    }

    pub fn persist_parsed_tool_call_intent_record(
        &self,
        record: &ParsedToolCallIntentRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "parsed tool call intent validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.parsed_tool_call_intent_record_path(&record.parsed_tool_call_intent_id),
            record,
        )
    }

    pub fn load_parsed_tool_call_intent_record(
        &self,
        parsed_tool_call_intent_id: &str,
    ) -> Result<ParsedToolCallIntentRecord, StorageError> {
        let record: ParsedToolCallIntentRecord =
            self.read_json(self.parsed_tool_call_intent_record_path(parsed_tool_call_intent_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "parsed tool call intent validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn list_parsed_tool_call_intent_records(
        &self,
    ) -> Result<Vec<ParsedToolCallIntentRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("parsed-tool-intents"))
    }

    pub fn persist_parsed_proposal_record(
        &self,
        record: &ParsedProposalRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("parsed proposal validation failed: {error}"))
        })?;
        self.write_json(
            self.parsed_proposal_record_path(&record.parsed_proposal_id),
            record,
        )
    }

    pub fn load_parsed_proposal_record(
        &self,
        parsed_proposal_id: &str,
    ) -> Result<ParsedProposalRecord, StorageError> {
        let record: ParsedProposalRecord =
            self.read_json(self.parsed_proposal_record_path(parsed_proposal_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("parsed proposal validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_parsed_proposal_records(&self) -> Result<Vec<ParsedProposalRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("parsed-proposals"))
    }

    pub fn persist_parsed_approval_request_record(
        &self,
        record: &ParsedApprovalRequestRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "parsed approval request validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.parsed_approval_request_record_path(&record.parsed_approval_request_id),
            record,
        )
    }

    pub fn load_parsed_approval_request_record(
        &self,
        parsed_approval_request_id: &str,
    ) -> Result<ParsedApprovalRequestRecord, StorageError> {
        let record: ParsedApprovalRequestRecord =
            self.read_json(self.parsed_approval_request_record_path(parsed_approval_request_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "parsed approval request validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn list_parsed_approval_request_records(
        &self,
    ) -> Result<Vec<ParsedApprovalRequestRecord>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("parsed-approval-requests"),
        )
    }

    pub fn persist_parse_repair_record(
        &self,
        record: &ParseRepairRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("parse repair validation failed: {error}"))
        })?;
        self.write_json(
            self.parse_repair_record_path(&record.parse_repair_id),
            record,
        )
    }

    pub fn load_parse_repair_record(
        &self,
        parse_repair_id: &str,
    ) -> Result<ParseRepairRecord, StorageError> {
        let record: ParseRepairRecord =
            self.read_json(self.parse_repair_record_path(parse_repair_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("parse repair validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_parse_repair_records(&self) -> Result<Vec<ParseRepairRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("parse-repairs"))
    }

    pub fn persist_parsed_turn_result(
        &self,
        record: &ParsedTurnResult,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("parsed turn result validation failed: {error}"))
        })?;
        self.write_json(
            self.parsed_turn_result_path(&record.parsed_turn_result_id),
            record,
        )
    }

    pub fn load_parsed_turn_result(
        &self,
        parsed_turn_result_id: &str,
    ) -> Result<ParsedTurnResult, StorageError> {
        let record: ParsedTurnResult =
            self.read_json(self.parsed_turn_result_path(parsed_turn_result_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("parsed turn result validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_parsed_turn_results(&self) -> Result<Vec<ParsedTurnResult>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("parsed-turn-results"))
    }

    pub fn persist_model_delegation_policy_record(
        &self,
        record: &ModelDelegationPolicyRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "model delegation policy validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.model_delegation_policy_path(&record.delegation_policy_id),
            record,
        )
    }

    pub fn load_model_delegation_policy_record(
        &self,
        delegation_policy_id: &str,
    ) -> Result<ModelDelegationPolicyRecord, StorageError> {
        let record: ModelDelegationPolicyRecord =
            self.read_json(self.model_delegation_policy_path(delegation_policy_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "model delegation policy validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn list_model_delegation_policy_records(
        &self,
    ) -> Result<Vec<ModelDelegationPolicyRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("delegation-policies"))
    }

    pub fn persist_model_authority_decision(
        &self,
        record: &ModelAuthorityDecision,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "model authority decision validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.model_authority_decision_path(&record.authority_decision_id),
            record,
        )
    }

    pub fn load_model_authority_decision(
        &self,
        authority_decision_id: &str,
    ) -> Result<ModelAuthorityDecision, StorageError> {
        let record: ModelAuthorityDecision =
            self.read_json(self.model_authority_decision_path(authority_decision_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "model authority decision validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn list_model_authority_decisions(
        &self,
    ) -> Result<Vec<ModelAuthorityDecision>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("authority-decisions"))
    }

    pub fn persist_model_approval_request_record(
        &self,
        record: &ModelApprovalRequestRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("model approval request validation failed: {error}"))
        })?;
        self.write_json(
            self.model_approval_request_record_path(&record.model_approval_request_id),
            record,
        )
    }

    pub fn load_model_approval_request_record(
        &self,
        model_approval_request_id: &str,
    ) -> Result<ModelApprovalRequestRecord, StorageError> {
        let record: ModelApprovalRequestRecord =
            self.read_json(self.model_approval_request_record_path(model_approval_request_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("model approval request validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_model_approval_request_records(
        &self,
    ) -> Result<Vec<ModelApprovalRequestRecord>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("model-approval-requests"),
        )
    }

    pub fn persist_model_output_quarantine_record(
        &self,
        record: &ModelOutputQuarantineRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("model quarantine validation failed: {error}"))
        })?;
        self.write_json(
            self.model_output_quarantine_record_path(&record.model_quarantine_id),
            record,
        )
    }

    pub fn load_model_output_quarantine_record(
        &self,
        model_quarantine_id: &str,
    ) -> Result<ModelOutputQuarantineRecord, StorageError> {
        let record: ModelOutputQuarantineRecord =
            self.read_json(self.model_output_quarantine_record_path(model_quarantine_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("model quarantine validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_model_output_quarantine_records(
        &self,
    ) -> Result<Vec<ModelOutputQuarantineRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("model-quarantines"))
    }

    pub fn persist_turn_checkpoint_record(
        &self,
        record: &TurnCheckpointRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("turn checkpoint validation failed: {error}"))
        })?;
        self.write_json(
            self.turn_checkpoint_record_path(&record.turn_checkpoint_id),
            record,
        )
    }

    pub fn load_turn_checkpoint_record(
        &self,
        turn_checkpoint_id: &str,
    ) -> Result<TurnCheckpointRecord, StorageError> {
        let record: TurnCheckpointRecord =
            self.read_json(self.turn_checkpoint_record_path(turn_checkpoint_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("turn checkpoint validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_turn_checkpoint_records(&self) -> Result<Vec<TurnCheckpointRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("turn-checkpoints"))
    }

    pub fn persist_pending_governed_turn_action_record(
        &self,
        record: &PendingGovernedTurnActionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "pending governed turn action validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.pending_governed_turn_action_record_path(&record.pending_governed_turn_action_id),
            record,
        )
    }

    pub fn load_pending_governed_turn_action_record(
        &self,
        pending_governed_turn_action_id: &str,
    ) -> Result<PendingGovernedTurnActionRecord, StorageError> {
        let record: PendingGovernedTurnActionRecord = self.read_json(
            self.pending_governed_turn_action_record_path(pending_governed_turn_action_id),
        )?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "pending governed turn action validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn list_pending_governed_turn_action_records(
        &self,
    ) -> Result<Vec<PendingGovernedTurnActionRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("pending-turn-actions"))
    }

    pub fn persist_llm_factory_program_profile(
        &self,
        record: &LlmFactoryProgramProfile,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "llm factory program profile validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.llm_factory_program_profile_path(&record.llm_factory_program_profile_id),
            record,
        )
    }

    pub fn load_llm_factory_program_profile(
        &self,
        profile_id: &str,
    ) -> Result<LlmFactoryProgramProfile, StorageError> {
        let record: LlmFactoryProgramProfile =
            self.read_json(self.llm_factory_program_profile_path(profile_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "llm factory program profile validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn list_llm_factory_program_profiles(
        &self,
    ) -> Result<Vec<LlmFactoryProgramProfile>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("llm-driver-profiles"))
    }

    pub fn persist_model_driven_factory_cycle_record(
        &self,
        record: &ModelDrivenFactoryCycleRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "model-driven factory cycle validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.model_driven_factory_cycle_path(&record.model_factory_cycle_id),
            record,
        )
    }

    pub fn load_model_driven_factory_cycle_record(
        &self,
        cycle_id: &str,
    ) -> Result<ModelDrivenFactoryCycleRecord, StorageError> {
        let record: ModelDrivenFactoryCycleRecord =
            self.read_json(self.model_driven_factory_cycle_path(cycle_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "model-driven factory cycle validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn list_model_driven_factory_cycle_records(
        &self,
    ) -> Result<Vec<ModelDrivenFactoryCycleRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("model-factory-cycles"))
    }

    pub fn persist_recursive_lineage_execution_record(
        &self,
        record: &RecursiveLineageExecutionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "recursive lineage execution validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.recursive_lineage_execution_path(&record.recursive_lineage_execution_id),
            record,
        )
    }

    pub fn load_recursive_lineage_execution_record(
        &self,
        lineage_id: &str,
    ) -> Result<RecursiveLineageExecutionRecord, StorageError> {
        let record: RecursiveLineageExecutionRecord =
            self.read_json(self.recursive_lineage_execution_path(lineage_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "recursive lineage execution validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn list_recursive_lineage_execution_records(
        &self,
    ) -> Result<Vec<RecursiveLineageExecutionRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("recursive-lineages"))
    }

    pub fn persist_architectural_dependency_statement(
        &self,
        record: &ArchitecturalDependencyStatement,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "architectural dependency statement validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.architectural_dependency_statement_path(
                &record.architectural_dependency_statement_id,
            ),
            record,
        )
    }

    pub fn load_architectural_dependency_statement(
        &self,
        statement_id: &str,
    ) -> Result<ArchitecturalDependencyStatement, StorageError> {
        let record: ArchitecturalDependencyStatement =
            self.read_json(self.architectural_dependency_statement_path(statement_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "architectural dependency statement validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn list_architectural_dependency_statements(
        &self,
    ) -> Result<Vec<ArchitecturalDependencyStatement>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("architectural-dependencies"),
        )
    }

    pub fn persist_interface_native_recursion_closure_dossier(
        &self,
        record: &InterfaceNativeRecursionClosureDossier,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "recursion closure dossier validation failed: {error}"
            ))
        })?;
        self.write_json(
            self.interface_native_recursion_closure_dossier_path(
                &record.recursion_closure_dossier_id,
            ),
            record,
        )
    }

    pub fn load_interface_native_recursion_closure_dossier(
        &self,
        dossier_id: &str,
    ) -> Result<InterfaceNativeRecursionClosureDossier, StorageError> {
        let record: InterfaceNativeRecursionClosureDossier =
            self.read_json(self.interface_native_recursion_closure_dossier_path(dossier_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!(
                "recursion closure dossier validation failed: {error}"
            ))
        })?;
        Ok(record)
    }

    pub fn list_interface_native_recursion_closure_dossiers(
        &self,
    ) -> Result<Vec<InterfaceNativeRecursionClosureDossier>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("recursion-closure-dossiers"),
        )
    }

    pub fn persist_tool_catalog_record(
        &self,
        record: &ToolCatalogRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool catalog validation failed: {error}"))
        })?;
        self.write_json(
            self.tool_catalog_record_path(&record.tool_catalog_id),
            record,
        )
    }

    pub fn load_tool_catalog_record(
        &self,
        tool_catalog_id: &str,
    ) -> Result<ToolCatalogRecord, StorageError> {
        let record: ToolCatalogRecord =
            self.read_json(self.tool_catalog_record_path(tool_catalog_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool catalog validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_model_tool_definition(
        &self,
        record: &ModelToolDefinition,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool definition validation failed: {error}"))
        })?;
        self.write_json(self.model_tool_definition_path(&record.tool_id), record)
    }

    pub fn load_model_tool_definition(
        &self,
        tool_id: &str,
    ) -> Result<ModelToolDefinition, StorageError> {
        let record: ModelToolDefinition =
            self.read_json(self.model_tool_definition_path(tool_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool definition validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_tool_argument_schema_record(
        &self,
        record: &ToolArgumentSchemaRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool argument schema validation failed: {error}"))
        })?;
        self.write_json(
            self.tool_argument_schema_record_path(&record.tool_argument_schema_id),
            record,
        )
    }

    pub fn load_tool_argument_schema_record(
        &self,
        tool_argument_schema_id: &str,
    ) -> Result<ToolArgumentSchemaRecord, StorageError> {
        let record: ToolArgumentSchemaRecord =
            self.read_json(self.tool_argument_schema_record_path(tool_argument_schema_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool argument schema validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_tool_result_schema_record(
        &self,
        record: &ToolResultSchemaRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool result schema validation failed: {error}"))
        })?;
        self.write_json(
            self.tool_result_schema_record_path(&record.tool_result_schema_id),
            record,
        )
    }

    pub fn load_tool_result_schema_record(
        &self,
        tool_result_schema_id: &str,
    ) -> Result<ToolResultSchemaRecord, StorageError> {
        let record: ToolResultSchemaRecord =
            self.read_json(self.tool_result_schema_record_path(tool_result_schema_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool result schema validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_tool_execution_context_record(
        &self,
        record: &ToolExecutionContextRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool execution context validation failed: {error}"))
        })?;
        self.write_json(
            self.tool_execution_context_record_path(&record.tool_execution_context_id),
            record,
        )
    }

    pub fn load_tool_execution_context_record(
        &self,
        tool_execution_context_id: &str,
    ) -> Result<ToolExecutionContextRecord, StorageError> {
        let record: ToolExecutionContextRecord =
            self.read_json(self.tool_execution_context_record_path(tool_execution_context_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool execution context validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_tool_execution_context_records(
        &self,
    ) -> Result<Vec<ToolExecutionContextRecord>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("tool-execution-contexts"),
        )
    }

    pub fn persist_tool_exposure_decision_record(
        &self,
        record: &ToolExposureDecisionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool exposure validation failed: {error}"))
        })?;
        self.write_json(
            self.tool_exposure_decision_record_path(&record.tool_exposure_decision_id),
            record,
        )
    }

    pub fn load_tool_exposure_decision_record(
        &self,
        tool_exposure_decision_id: &str,
    ) -> Result<ToolExposureDecisionRecord, StorageError> {
        let record: ToolExposureDecisionRecord =
            self.read_json(self.tool_exposure_decision_record_path(tool_exposure_decision_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool exposure validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn persist_tool_call_legality_record(
        &self,
        record: &ToolCallLegalityRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool legality validation failed: {error}"))
        })?;
        self.write_json(
            self.tool_call_legality_record_path(&record.tool_legality_id),
            record,
        )
    }

    pub fn load_tool_call_legality_record(
        &self,
        tool_legality_id: &str,
    ) -> Result<ToolCallLegalityRecord, StorageError> {
        let record: ToolCallLegalityRecord =
            self.read_json(self.tool_call_legality_record_path(tool_legality_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool legality validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_tool_call_legality_records(
        &self,
    ) -> Result<Vec<ToolCallLegalityRecord>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("tool-legality-decisions"),
        )
    }

    pub fn persist_tool_execution_record(
        &self,
        record: &ToolExecutionRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool execution validation failed: {error}"))
        })?;
        self.write_json(
            self.tool_execution_record_path(&record.tool_execution_id),
            record,
        )
    }

    pub fn load_tool_execution_record(
        &self,
        tool_execution_id: &str,
    ) -> Result<ToolExecutionRecord, StorageError> {
        let record: ToolExecutionRecord =
            self.read_json(self.tool_execution_record_path(tool_execution_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool execution validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_tool_execution_records(&self) -> Result<Vec<ToolExecutionRecord>, StorageError> {
        self.list_json_records(self.root.join("llm-interface").join("tool-executions"))
    }

    pub fn persist_parsed_turn_tool_execution_receipt(
        &self,
        record: &ParsedTurnToolExecutionReceipt,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool execution receipt validation failed: {error}"))
        })?;
        self.write_json(
            self.parsed_turn_tool_execution_receipt_path(
                &record.parsed_turn_tool_execution_receipt_id,
            ),
            record,
        )
    }

    pub fn load_parsed_turn_tool_execution_receipt(
        &self,
        parsed_turn_tool_execution_receipt_id: &str,
    ) -> Result<ParsedTurnToolExecutionReceipt, StorageError> {
        let record: ParsedTurnToolExecutionReceipt = self.read_json(
            self.parsed_turn_tool_execution_receipt_path(parsed_turn_tool_execution_receipt_id),
        )?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("tool execution receipt validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_parsed_turn_tool_execution_receipts(
        &self,
    ) -> Result<Vec<ParsedTurnToolExecutionReceipt>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("tool-execution-receipts"),
        )
    }

    pub fn persist_operator_only_surface_record(
        &self,
        record: &OperatorOnlySurfaceRecord,
    ) -> Result<(), StorageError> {
        record.validate().map_err(|error| {
            storage_integrity_error(format!("operator-only surface validation failed: {error}"))
        })?;
        self.write_json(
            self.operator_only_surface_record_path(&record.operator_only_surface_id),
            record,
        )
    }

    pub fn load_operator_only_surface_record(
        &self,
        operator_only_surface_id: &str,
    ) -> Result<OperatorOnlySurfaceRecord, StorageError> {
        let record: OperatorOnlySurfaceRecord =
            self.read_json(self.operator_only_surface_record_path(operator_only_surface_id))?;
        record.validate().map_err(|error| {
            storage_integrity_error(format!("operator-only surface validation failed: {error}"))
        })?;
        Ok(record)
    }

    pub fn list_operator_only_surface_records(
        &self,
    ) -> Result<Vec<OperatorOnlySurfaceRecord>, StorageError> {
        self.list_json_records(
            self.root
                .join("llm-interface")
                .join("operator-only-surfaces"),
        )
    }

    fn path_support_classification_path(&self, path_ref: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("support-classifications")
            .join(format!("{}.json", safe_file_stem(path_ref)))
    }

    fn inference_provider_registry_entry_path(&self, provider_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("providers")
            .join(format!("{}.json", safe_file_stem(provider_id)))
    }

    fn inference_generation_policy_path(&self, generation_policy_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("generation-policies")
            .join(format!("{}.json", safe_file_stem(generation_policy_id)))
    }

    fn inference_turn_request_path(&self, turn_request_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("turn-requests")
            .join(format!("{}.json", safe_file_stem(turn_request_id)))
    }

    fn inference_rendered_prompt_record_path(&self, rendered_prompt_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("rendered-prompts")
            .join(format!("{}.json", safe_file_stem(rendered_prompt_id)))
    }

    fn inference_tool_catalog_payload_record_path(&self, tool_catalog_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("tool-catalogs")
            .join(format!("{}.json", safe_file_stem(tool_catalog_id)))
    }

    fn inference_response_schema_payload_record_path(&self, response_schema_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("response-schemas")
            .join(format!("{}.json", safe_file_stem(response_schema_id)))
    }

    fn inference_request_body_record_path(&self, request_body_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("request-bodies")
            .join(format!("{}.json", safe_file_stem(request_body_id)))
    }

    fn inference_raw_output_record_path(&self, raw_output_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("raw-outputs")
            .join(format!("{}.json", safe_file_stem(raw_output_id)))
    }

    fn inference_attempt_record_path(&self, attempt_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("attempts")
            .join(format!("{}.json", safe_file_stem(attempt_id)))
    }

    fn inference_usage_record_path(&self, usage_record_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("usage-records")
            .join(format!("{}.json", safe_file_stem(usage_record_id)))
    }

    fn inference_provider_outcome_record_path(&self, provider_outcome_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("provider-outcomes")
            .join(format!("{}.json", safe_file_stem(provider_outcome_id)))
    }

    fn inference_parsed_output_record_path(&self, parsed_output_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("parsed-outputs")
            .join(format!("{}.json", safe_file_stem(parsed_output_id)))
    }

    fn inference_turn_result_path(&self, turn_result_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("turn-results")
            .join(format!("{}.json", safe_file_stem(turn_result_id)))
    }

    fn provider_degradation_record_path(&self, degradation_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("degradation-records")
            .join(format!("{}.json", safe_file_stem(degradation_id)))
    }

    fn turn_package_path(&self, turn_package_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("turn-packages")
            .join(format!("{}.json", safe_file_stem(turn_package_id)))
    }

    fn continuity_bundle_path(&self, continuity_bundle_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("continuity-bundles")
            .join(format!("{}.json", safe_file_stem(continuity_bundle_id)))
    }

    fn turn_grounding_packet_path(&self, turn_grounding_packet_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("turn-groundings")
            .join(format!("{}.json", safe_file_stem(turn_grounding_packet_id)))
    }

    fn continuity_retrieval_trace_path(&self, trace_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("continuity-retrieval-traces")
            .join(format!("{}.json", safe_file_stem(trace_id)))
    }

    fn open_question_ledger_path(&self, open_question_ledger_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("open-question-ledgers")
            .join(format!("{}.json", safe_file_stem(open_question_ledger_id)))
    }

    fn contradiction_carry_forward_path(&self, contradiction_carry_forward_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("contradiction-carry-forwards")
            .join(format!(
                "{}.json",
                safe_file_stem(contradiction_carry_forward_id)
            ))
    }

    fn turn_memory_update_path(&self, turn_memory_update_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("turn-memory-updates")
            .join(format!("{}.json", safe_file_stem(turn_memory_update_id)))
    }

    fn context_budget_record_path(&self, context_budget_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("context-budgets")
            .join(format!("{}.json", safe_file_stem(context_budget_id)))
    }

    fn context_truncation_record_path(&self, context_truncation_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("context-truncations")
            .join(format!("{}.json", safe_file_stem(context_truncation_id)))
    }

    fn prompt_layer_record_path(&self, prompt_layer_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("prompt-layers")
            .join(format!("{}.json", safe_file_stem(prompt_layer_id)))
    }

    fn prompt_rendering_record_path(&self, prompt_rendering_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("prompt-renderings")
            .join(format!("{}.json", safe_file_stem(prompt_rendering_id)))
    }

    fn turn_response_schema_record_path(&self, turn_response_schema_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("turn-response-schemas")
            .join(format!("{}.json", safe_file_stem(turn_response_schema_id)))
    }

    fn parsed_tool_call_intent_record_path(&self, parsed_tool_call_intent_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("parsed-tool-intents")
            .join(format!(
                "{}.json",
                safe_file_stem(parsed_tool_call_intent_id)
            ))
    }

    fn parsed_proposal_record_path(&self, parsed_proposal_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("parsed-proposals")
            .join(format!("{}.json", safe_file_stem(parsed_proposal_id)))
    }

    fn parsed_approval_request_record_path(&self, parsed_approval_request_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("parsed-approval-requests")
            .join(format!(
                "{}.json",
                safe_file_stem(parsed_approval_request_id)
            ))
    }

    fn parsed_turn_result_path(&self, parsed_turn_result_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("parsed-turn-results")
            .join(format!("{}.json", safe_file_stem(parsed_turn_result_id)))
    }

    fn parse_repair_record_path(&self, parse_repair_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("parse-repairs")
            .join(format!("{}.json", safe_file_stem(parse_repair_id)))
    }

    fn model_delegation_policy_path(&self, delegation_policy_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("delegation-policies")
            .join(format!("{}.json", safe_file_stem(delegation_policy_id)))
    }

    fn model_authority_decision_path(&self, authority_decision_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("authority-decisions")
            .join(format!("{}.json", safe_file_stem(authority_decision_id)))
    }

    fn model_approval_request_record_path(&self, model_approval_request_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("model-approval-requests")
            .join(format!(
                "{}.json",
                safe_file_stem(model_approval_request_id)
            ))
    }

    fn model_output_quarantine_record_path(&self, model_quarantine_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("model-quarantines")
            .join(format!("{}.json", safe_file_stem(model_quarantine_id)))
    }

    fn turn_checkpoint_record_path(&self, turn_checkpoint_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("turn-checkpoints")
            .join(format!("{}.json", safe_file_stem(turn_checkpoint_id)))
    }

    fn pending_governed_turn_action_record_path(
        &self,
        pending_governed_turn_action_id: &str,
    ) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("pending-turn-actions")
            .join(format!(
                "{}.json",
                safe_file_stem(pending_governed_turn_action_id)
            ))
    }

    fn llm_factory_program_profile_path(&self, profile_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("llm-driver-profiles")
            .join(format!("{}.json", safe_file_stem(profile_id)))
    }

    fn model_driven_factory_cycle_path(&self, cycle_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("model-factory-cycles")
            .join(format!("{}.json", safe_file_stem(cycle_id)))
    }

    fn recursive_lineage_execution_path(&self, lineage_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("recursive-lineages")
            .join(format!("{}.json", safe_file_stem(lineage_id)))
    }

    fn architectural_dependency_statement_path(&self, statement_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("architectural-dependencies")
            .join(format!("{}.json", safe_file_stem(statement_id)))
    }

    fn interface_native_recursion_closure_dossier_path(&self, dossier_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("recursion-closure-dossiers")
            .join(format!("{}.json", safe_file_stem(dossier_id)))
    }

    fn tool_catalog_record_path(&self, tool_catalog_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("tool-catalogs")
            .join(format!("{}.json", safe_file_stem(tool_catalog_id)))
    }

    fn model_tool_definition_path(&self, tool_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("tool-definitions")
            .join(format!("{}.json", safe_file_stem(tool_id)))
    }

    fn tool_argument_schema_record_path(&self, tool_argument_schema_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("tool-argument-schemas")
            .join(format!("{}.json", safe_file_stem(tool_argument_schema_id)))
    }

    fn tool_result_schema_record_path(&self, tool_result_schema_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("tool-result-schemas")
            .join(format!("{}.json", safe_file_stem(tool_result_schema_id)))
    }

    fn tool_execution_context_record_path(&self, tool_execution_context_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("tool-execution-contexts")
            .join(format!(
                "{}.json",
                safe_file_stem(tool_execution_context_id)
            ))
    }

    fn tool_exposure_decision_record_path(&self, tool_exposure_decision_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("tool-exposure-decisions")
            .join(format!(
                "{}.json",
                safe_file_stem(tool_exposure_decision_id)
            ))
    }

    fn tool_call_legality_record_path(&self, tool_legality_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("tool-legality-decisions")
            .join(format!("{}.json", safe_file_stem(tool_legality_id)))
    }

    fn tool_execution_record_path(&self, tool_execution_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("tool-executions")
            .join(format!("{}.json", safe_file_stem(tool_execution_id)))
    }

    fn parsed_turn_tool_execution_receipt_path(
        &self,
        parsed_turn_tool_execution_receipt_id: &str,
    ) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("tool-execution-receipts")
            .join(format!(
                "{}.json",
                safe_file_stem(parsed_turn_tool_execution_receipt_id)
            ))
    }

    fn operator_only_surface_record_path(&self, operator_only_surface_id: &str) -> PathBuf {
        self.root
            .join("llm-interface")
            .join("operator-only-surfaces")
            .join(format!("{}.json", safe_file_stem(operator_only_surface_id)))
    }

    fn universal_shell_launch_path(&self, launch_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("launch-assemblies")
            .join(format!("{}.json", safe_file_stem(launch_id)))
    }

    fn campaign_admission_record_path(&self, admission_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("campaign-admissions")
            .join(format!("{}.json", safe_file_stem(admission_id)))
    }

    fn launch_refusal_record_path(&self, refusal_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("launch-refusals")
            .join(format!("{}.json", safe_file_stem(refusal_id)))
    }

    fn program_to_shell_mapping_path(&self, mapping_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("program-mappings")
            .join(format!("{}.json", safe_file_stem(mapping_id)))
    }

    fn lifecycle_transition_record_path(&self, transition_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("lifecycle-transitions")
            .join(format!("{}.json", safe_file_stem(transition_id)))
    }

    fn resume_chain_record_path(&self, resume_chain_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("resume-chains")
            .join(format!("{}.json", safe_file_stem(resume_chain_id)))
    }

    fn shell_evidence_summary_path(&self, summary_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("evidence-summaries")
            .join(format!("{}.json", safe_file_stem(summary_id)))
    }

    fn shell_derived_export_bundle_path(&self, export_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("export-bundles")
            .join(format!("{}.json", safe_file_stem(export_id)))
    }

    fn transitional_truth_annotation_path(&self, annotation_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("truth-annotations")
            .join(format!("{}.json", safe_file_stem(annotation_id)))
    }

    fn transitional_adapter_manifest_path(&self, adapter_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("adapter-manifests")
            .join(format!("{}.json", safe_file_stem(adapter_id)))
    }

    fn migration_gate_record_path(&self, gate_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("migration-gates")
            .join(format!("{}.json", safe_file_stem(gate_id)))
    }

    fn path_retirement_record_path(&self, retirement_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("retirements")
            .join(format!("{}.json", safe_file_stem(retirement_id)))
    }

    fn acceptance_truth_matrix_path(&self, matrix_id: &str) -> PathBuf {
        self.root
            .join("northstar-01")
            .join("acceptance-truth")
            .join(format!("{}.json", safe_file_stem(matrix_id)))
    }

    fn scheduler_tick_record_path(&self, tick_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("scheduler-ticks")
            .join(format!("{}.json", safe_file_stem(tick_id)))
    }

    fn scheduled_wake_record_path(&self, wake_record_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("scheduled-wakes")
            .join(format!("{}.json", safe_file_stem(wake_record_id)))
    }

    fn persistent_job_lease_path(&self, lease_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("persistent-job-leases")
            .join(format!("{}.json", safe_file_stem(lease_id)))
    }

    fn approval_inbox_record_path(&self, approval_inbox_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("approval-inbox")
            .join(format!("{}.json", safe_file_stem(approval_inbox_id)))
    }

    fn deferred_decision_bundle_path(&self, decision_bundle_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("deferred-decision-bundles")
            .join(format!("{}.json", safe_file_stem(decision_bundle_id)))
    }

    fn lease_expiry_record_path(&self, expiry_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("lease-expiries")
            .join(format!("{}.json", safe_file_stem(expiry_id)))
    }

    fn shell_escalation_record_path(&self, escalation_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("shell-escalations")
            .join(format!("{}.json", safe_file_stem(escalation_id)))
    }

    fn consolidation_job_record_path(&self, consolidation_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("consolidation-jobs")
            .join(format!("{}.json", safe_file_stem(consolidation_id)))
    }

    fn continuity_job_classification_path(&self, job_class_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("continuity-job-classes")
            .join(format!("{}.json", safe_file_stem(job_class_id)))
    }

    fn continuity_job_record_path(&self, job_record_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("continuity-jobs")
            .join(format!("{}.json", safe_file_stem(job_record_id)))
    }

    fn persistent_shell_audit_packet_path(&self, audit_packet_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("audit-packets")
            .join(format!("{}.json", safe_file_stem(audit_packet_id)))
    }

    fn persistent_shell_operations_dossier_path(&self, operations_dossier_id: &str) -> PathBuf {
        self.root
            .join("northstar-02")
            .join("operations-dossiers")
            .join(format!("{}.json", safe_file_stem(operations_dossier_id)))
    }

    fn service_family_manifest_path(&self, service_manifest_id: &str) -> PathBuf {
        self.root
            .join("northstar-03")
            .join("service-manifests")
            .join(format!("{}.json", safe_file_stem(service_manifest_id)))
    }

    fn service_handle_lease_path(&self, service_handle_id: &str) -> PathBuf {
        self.root
            .join("northstar-03")
            .join("service-handles")
            .join(format!("{}.json", safe_file_stem(service_handle_id)))
    }

    fn service_attestation_bundle_path(&self, attestation_id: &str) -> PathBuf {
        self.root
            .join("northstar-03")
            .join("service-attestations")
            .join(format!("{}.json", safe_file_stem(attestation_id)))
    }

    fn service_closure_dossier_path(&self, closure_dossier_id: &str) -> PathBuf {
        self.root
            .join("northstar-03")
            .join("service-closure-dossiers")
            .join(format!("{}.json", safe_file_stem(closure_dossier_id)))
    }

    fn workflow_sufficiency_record_path(&self, workflow_sufficiency_id: &str) -> PathBuf {
        self.root
            .join("northstar-03")
            .join("workflow-sufficiency")
            .join(format!("{}.json", safe_file_stem(workflow_sufficiency_id)))
    }

    fn workflow_service_closure_dossier_path(&self, workflow_dossier_id: &str) -> PathBuf {
        self.root
            .join("northstar-03")
            .join("workflow-closure-dossiers")
            .join(format!("{}.json", safe_file_stem(workflow_dossier_id)))
    }

    fn worker_specialization_card_path(&self, worker_card_id: &str) -> PathBuf {
        self.root
            .join("northstar-04")
            .join("worker-cards")
            .join(format!("{}.json", safe_file_stem(worker_card_id)))
    }

    fn ecology_snapshot_path(&self, ecology_snapshot_id: &str) -> PathBuf {
        self.root
            .join("northstar-04")
            .join("ecology-snapshots")
            .join(format!("{}.json", safe_file_stem(ecology_snapshot_id)))
    }

    fn coordinator_planning_record_path(&self, planning_id: &str) -> PathBuf {
        self.root
            .join("northstar-04")
            .join("planning-records")
            .join(format!("{}.json", safe_file_stem(planning_id)))
    }

    fn work_lease_path(&self, work_lease_id: &str) -> PathBuf {
        self.root
            .join("northstar-04")
            .join("work-leases")
            .join(format!("{}.json", safe_file_stem(work_lease_id)))
    }

    fn synthesis_dossier_path(&self, synthesis_id: &str) -> PathBuf {
        self.root
            .join("northstar-04")
            .join("synthesis-dossiers")
            .join(format!("{}.json", safe_file_stem(synthesis_id)))
    }

    fn ecology_health_record_path(&self, health_record_id: &str) -> PathBuf {
        self.root
            .join("northstar-04")
            .join("health-records")
            .join(format!("{}.json", safe_file_stem(health_record_id)))
    }

    fn routing_packet_record_path(&self, routing_packet_id: &str) -> PathBuf {
        self.root
            .join("northstar-04")
            .join("routing-packets")
            .join(format!("{}.json", safe_file_stem(routing_packet_id)))
    }

    fn ecology_recovery_record_path(&self, recovery_id: &str) -> PathBuf {
        self.root
            .join("northstar-04")
            .join("recovery-records")
            .join(format!("{}.json", safe_file_stem(recovery_id)))
    }

    fn service_closure_workspace_packet_path(&self, service_workspace_id: &str) -> PathBuf {
        self.root
            .join("remediation-phase-02")
            .join("service-workspaces")
            .join(format!("{}.json", safe_file_stem(service_workspace_id)))
    }

    fn ecology_closure_workspace_packet_path(&self, ecology_workspace_id: &str) -> PathBuf {
        self.root
            .join("remediation-phase-02")
            .join("ecology-workspaces")
            .join(format!("{}.json", safe_file_stem(ecology_workspace_id)))
    }

    fn phase02_acceptance_packet_path(&self, acceptance_packet_id: &str) -> PathBuf {
        self.root
            .join("remediation-phase-02")
            .join("acceptance-packets")
            .join(format!("{}.json", safe_file_stem(acceptance_packet_id)))
    }

    fn factory_improvement_program_path(&self, improvement_program_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("programs")
            .join(format!("{}.json", safe_file_stem(improvement_program_id)))
    }

    fn recursion_budget_record_path(&self, recursion_budget_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("recursion-budgets")
            .join(format!("{}.json", safe_file_stem(recursion_budget_id)))
    }

    fn later_factory_generation_agenda_path(&self, generation_agenda_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("generation-agendas")
            .join(format!("{}.json", safe_file_stem(generation_agenda_id)))
    }

    fn adoption_window_record_path(&self, adoption_window_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("adoption-windows")
            .join(format!("{}.json", safe_file_stem(adoption_window_id)))
    }

    fn lineage_health_dossier_path(&self, lineage_health_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("lineage-health")
            .join(format!("{}.json", safe_file_stem(lineage_health_id)))
    }

    fn stop_condition_record_path(&self, stop_condition_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("stop-conditions")
            .join(format!("{}.json", safe_file_stem(stop_condition_id)))
    }

    fn recurring_factory_program_record_path(&self, factory_program_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("recurring-programs")
            .join(format!("{}.json", safe_file_stem(factory_program_id)))
    }

    fn program_continuity_window_record_path(&self, continuity_window_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("continuity-windows")
            .join(format!("{}.json", safe_file_stem(continuity_window_id)))
    }

    fn program_budget_history_record_path(&self, budget_history_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("budget-histories")
            .join(format!("{}.json", safe_file_stem(budget_history_id)))
    }

    fn program_policy_compliance_record_path(&self, policy_compliance_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("policy-compliance-records")
            .join(format!("{}.json", safe_file_stem(policy_compliance_id)))
    }

    fn later_factory_cycle_dossier_path(&self, cycle_dossier_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("cycle-dossiers")
            .join(format!("{}.json", safe_file_stem(cycle_dossier_id)))
    }

    fn lineage_health_ledger_path(&self, lineage_ledger_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("lineage-ledgers")
            .join(format!("{}.json", safe_file_stem(lineage_ledger_id)))
    }

    fn regression_review_packet_path(&self, regression_packet_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("regression-packets")
            .join(format!("{}.json", safe_file_stem(regression_packet_id)))
    }

    fn longitudinal_lineage_dossier_path(&self, lineage_dossier_id: &str) -> PathBuf {
        self.root
            .join("northstar-05")
            .join("longitudinal-lineage-dossiers")
            .join(format!("{}.json", safe_file_stem(lineage_dossier_id)))
    }

    fn trust_profile_path(&self, trust_profile_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("trust-profiles")
            .join(format!("{}.json", safe_file_stem(trust_profile_id)))
    }

    fn ecosystem_admission_record_path(&self, admission_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("admissions")
            .join(format!("{}.json", safe_file_stem(admission_id)))
    }

    fn exchange_route_record_path(&self, route_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("routes")
            .join(format!("{}.json", safe_file_stem(route_id)))
    }

    fn route_compatibility_cycle_path(&self, compatibility_cycle_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("route-cycles")
            .join(format!("{}.json", safe_file_stem(compatibility_cycle_id)))
    }

    fn cross_factory_adoption_dossier_path(&self, adoption_dossier_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("adoption-dossiers")
            .join(format!("{}.json", safe_file_stem(adoption_dossier_id)))
    }

    fn ecosystem_rollback_choreography_record_path(
        &self,
        rollback_choreography_id: &str,
    ) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("rollback-choreography")
            .join(format!("{}.json", safe_file_stem(rollback_choreography_id)))
    }

    fn ecosystem_workspace_snapshot_path(&self, workspace_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("workspace-snapshots")
            .join(format!("{}.json", safe_file_stem(workspace_id)))
    }

    fn ecosystem_health_snapshot_path(&self, ecosystem_snapshot_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("health-snapshots")
            .join(format!("{}.json", safe_file_stem(ecosystem_snapshot_id)))
    }

    fn ecosystem_admission_profile_path(&self, admission_profile_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("admission-profiles")
            .join(format!("{}.json", safe_file_stem(admission_profile_id)))
    }

    fn route_exchange_history_record_path(&self, route_history_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("route-history-records")
            .join(format!("{}.json", safe_file_stem(route_history_id)))
    }

    fn ecosystem_exchange_route_ledger_path(&self, exchange_route_ledger_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("route-ledgers")
            .join(format!("{}.json", safe_file_stem(exchange_route_ledger_id)))
    }

    fn ecosystem_continuity_window_path(&self, continuity_window_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("continuity-windows")
            .join(format!("{}.json", safe_file_stem(continuity_window_id)))
    }

    fn ecosystem_rollback_symmetry_record_path(&self, rollback_symmetry_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("rollback-symmetry-records")
            .join(format!("{}.json", safe_file_stem(rollback_symmetry_id)))
    }

    fn ecosystem_compatibility_persistence_record_path(
        &self,
        compatibility_persistence_id: &str,
    ) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("compatibility-persistence-records")
            .join(format!(
                "{}.json",
                safe_file_stem(compatibility_persistence_id)
            ))
    }

    fn ecosystem_health_ledger_path(&self, ecosystem_health_id: &str) -> PathBuf {
        self.root
            .join("northstar-06")
            .join("health-ledgers")
            .join(format!("{}.json", safe_file_stem(ecosystem_health_id)))
    }

    fn recurring_factory_workspace_packet_path(&self, factory_workspace_id: &str) -> PathBuf {
        self.root
            .join("remediation-phase-03")
            .join("factory-workspaces")
            .join(format!("{}.json", safe_file_stem(factory_workspace_id)))
    }

    fn ecosystem_closure_workspace_packet_path(&self, ecosystem_workspace_id: &str) -> PathBuf {
        self.root
            .join("remediation-phase-03")
            .join("ecosystem-workspaces")
            .join(format!("{}.json", safe_file_stem(ecosystem_workspace_id)))
    }

    fn phase03_closure_review_packet_path(&self, closure_review_packet_id: &str) -> PathBuf {
        self.root
            .join("remediation-phase-03")
            .join("closure-review-packets")
            .join(format!("{}.json", safe_file_stem(closure_review_packet_id)))
    }

    fn closure_criteria_matrix_path(&self, criteria_matrix_id: &str) -> PathBuf {
        self.root
            .join("northstar-07")
            .join("criteria-matrices")
            .join(format!("{}.json", safe_file_stem(criteria_matrix_id)))
    }

    fn evidence_inventory_packet_path(&self, inventory_packet_id: &str) -> PathBuf {
        self.root
            .join("northstar-07")
            .join("evidence-inventories")
            .join(format!("{}.json", safe_file_stem(inventory_packet_id)))
    }

    fn adversarial_review_record_path(&self, adversarial_review_id: &str) -> PathBuf {
        self.root
            .join("northstar-07")
            .join("adversarial-reviews")
            .join(format!("{}.json", safe_file_stem(adversarial_review_id)))
    }

    fn residual_risk_record_path(&self, risk_record_id: &str) -> PathBuf {
        self.root
            .join("northstar-07")
            .join("residual-risks")
            .join(format!("{}.json", safe_file_stem(risk_record_id)))
    }

    fn closure_dossier_path(&self, closure_dossier_id: &str) -> PathBuf {
        self.root
            .join("northstar-07")
            .join("closure-dossiers")
            .join(format!("{}.json", safe_file_stem(closure_dossier_id)))
    }

    fn claim_boundary_review_packet_path(&self, claim_review_id: &str) -> PathBuf {
        self.root
            .join("northstar-07")
            .join("claim-reviews")
            .join(format!("{}.json", safe_file_stem(claim_review_id)))
    }

    fn closure_decision_record_path(&self, closure_decision_id: &str) -> PathBuf {
        self.root
            .join("northstar-07")
            .join("closure-decisions")
            .join(format!("{}.json", safe_file_stem(closure_decision_id)))
    }

    fn publication_policy_record_path(&self, publication_policy_id: &str) -> PathBuf {
        self.root
            .join("northstar-07")
            .join("publication-policies")
            .join(format!("{}.json", safe_file_stem(publication_policy_id)))
    }

    fn write_json<T: Serialize>(
        &self,
        path: impl AsRef<Path>,
        value: &T,
    ) -> Result<(), StorageError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(value)?;
        fs::write(path, bytes)?;
        Ok(())
    }

    fn list_json_records<T>(&self, dir: impl AsRef<Path>) -> Result<Vec<T>, StorageError>
    where
        T: for<'de> Deserialize<'de> + ValidateRecord,
    {
        let dir = dir.as_ref();
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut records = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let record: T = self.read_json(&path)?;
            record.validate_record().map_err(|error| {
                storage_integrity_error(format!("listed record validation failed: {error}"))
            })?;
            records.push(record);
        }
        Ok(records)
    }

    fn snapshot_path(&self, checkpoint_id: &str) -> PathBuf {
        self.root
            .join("snapshots/by-checkpoint")
            .join(format!("{}.json", checkpoint_id))
    }

    fn shadow_bundle_path(&self, shadow_campaign_id: &str) -> PathBuf {
        self.root
            .join("shadow-evaluations")
            .join(format!("{}.json", shadow_campaign_id))
    }

    fn promotion_bundle_path(&self, promotion_act_id: &str) -> PathBuf {
        self.root
            .join("promotion-activations")
            .join(format!("{}.json", promotion_act_id))
    }

    fn v1_completion_path(&self, gate_id: &str) -> PathBuf {
        self.root
            .join("v1-completion")
            .join(format!("{}.json", gate_id))
    }

    fn v3_generation_artifact_path(&self, package_digest: &ArtifactDigest) -> PathBuf {
        self.root
            .join("v3-substrate")
            .join("generation-artifacts")
            .join(format!("{}.json", package_digest.file_stem()))
    }

    fn v3_component_build_path(&self, build_id: &str) -> PathBuf {
        self.root
            .join("v3-substrate")
            .join("component-builds")
            .join(format!("{}.json", safe_file_stem(build_id)))
    }

    fn v3_validation_trace_path(&self, trace_ref: &str) -> PathBuf {
        self.root
            .join("v3-substrate")
            .join("validation-traces")
            .join(format!("{}.json", safe_file_stem(trace_ref)))
    }

    fn v3_comparison_path(&self, comparison_id: &str) -> PathBuf {
        self.root
            .join("v3-substrate")
            .join("comparisons")
            .join(format!("{}.json", safe_file_stem(comparison_id)))
    }

    fn v3_active_generation_state_path(&self, state_id: &str) -> PathBuf {
        self.root
            .join("v3-substrate")
            .join("active-generations")
            .join(format!("{}.json", safe_file_stem(state_id)))
    }

    fn v3_self_production_campaign_path(&self, campaign_id: &str) -> PathBuf {
        self.root
            .join("v3-substrate")
            .join("self-production")
            .join(format!("campaign-{}.json", safe_file_stem(campaign_id)))
    }

    fn v3_successor_production_record_path(&self, record_id: &str) -> PathBuf {
        self.root
            .join("v3-substrate")
            .join("self-production")
            .join(format!("record-{}.json", safe_file_stem(record_id)))
    }

    fn v3_completion_gate_path(&self, gate_id: &str) -> PathBuf {
        self.root
            .join("v3-substrate")
            .join("completion-gates")
            .join(format!("{}.json", safe_file_stem(gate_id)))
    }

    fn v4_shell_session_bundle_path(&self, shell_session_id: &str) -> PathBuf {
        self.root
            .join("v4-shell")
            .join("sessions")
            .join(format!("{}.json", safe_file_stem(shell_session_id)))
    }

    fn v4_shell_evidence_packet_path(&self, packet_id: &str) -> PathBuf {
        self.root
            .join("v4-shell")
            .join("evidence-packets")
            .join(format!("{}.json", safe_file_stem(packet_id)))
    }

    fn v4_completion_gate_path(&self, gate_id: &str) -> PathBuf {
        self.root
            .join("v4-shell")
            .join("completion-gates")
            .join(format!("{}.json", safe_file_stem(gate_id)))
    }

    fn factory_genome_path(&self, factory_genome_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("genomes")
            .join(format!("{}.json", safe_file_stem(factory_genome_id)))
    }

    fn factory_phenotype_path(&self, factory_phenotype_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("phenotypes")
            .join(format!("{}.json", safe_file_stem(factory_phenotype_id)))
    }

    fn factory_lineage_path(&self, lineage_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("lineage")
            .join(format!("{}.json", safe_file_stem(lineage_id)))
    }

    fn factory_validation_profile_path(&self, validation_profile_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("validation-profiles")
            .join(format!("{}.json", safe_file_stem(validation_profile_id)))
    }

    fn factory_validation_evidence_path(&self, evidence_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("validation-evidence")
            .join(format!("{}.json", safe_file_stem(evidence_id)))
    }

    fn factory_validation_record_path(&self, validation_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("validation-records")
            .join(format!("{}.json", safe_file_stem(validation_id)))
    }

    fn factory_comparison_path(&self, comparison_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("comparisons")
            .join(format!("{}.json", safe_file_stem(comparison_id)))
    }

    fn factory_activation_path(&self, activation_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("activations")
            .join(format!("{}.json", safe_file_stem(activation_id)))
    }

    fn factory_state_path(&self, state_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("states")
            .join(format!("{}.json", safe_file_stem(state_id)))
    }

    fn factory_governance_transition_path(&self, transition_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("governance-transitions")
            .join(format!("{}.json", safe_file_stem(transition_id)))
    }

    fn factory_rollback_envelope_path(&self, rollback_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("rollback-envelopes")
            .join(format!("{}.json", safe_file_stem(rollback_id)))
    }

    fn factory_quarantine_record_path(&self, quarantine_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("quarantine-records")
            .join(format!("{}.json", safe_file_stem(quarantine_id)))
    }

    fn factory_evidence_packet_path(&self, packet_id: &str) -> PathBuf {
        self.root
            .join("factories")
            .join("evidence-packets")
            .join(format!("{}.json", safe_file_stem(packet_id)))
    }

    fn factory_replication_campaign_path(&self, replication_campaign_id: &str) -> PathBuf {
        self.root
            .join("factory-replication")
            .join("campaigns")
            .join(format!("{}.json", safe_file_stem(replication_campaign_id)))
    }

    fn later_factory_candidate_path(&self, later_factory_candidate_id: &str) -> PathBuf {
        self.root
            .join("factory-replication")
            .join("candidates")
            .join(format!(
                "{}.json",
                safe_file_stem(later_factory_candidate_id)
            ))
    }

    fn factory_proving_run_path(&self, proving_run_id: &str) -> PathBuf {
        self.root
            .join("factory-replication")
            .join("proving-runs")
            .join(format!("{}.json", safe_file_stem(proving_run_id)))
    }

    fn child_factory_observation_window_path(&self, observation_window_id: &str) -> PathBuf {
        self.root
            .join("factory-replication")
            .join("observation-windows")
            .join(format!("{}.json", safe_file_stem(observation_window_id)))
    }

    fn child_factory_quarantine_protocol_path(&self, protocol_id: &str) -> PathBuf {
        self.root
            .join("factory-replication")
            .join("quarantine-protocols")
            .join(format!("{}.json", safe_file_stem(protocol_id)))
    }

    fn child_factory_disposition_path(&self, disposition_id: &str) -> PathBuf {
        self.root
            .join("factory-replication")
            .join("dispositions")
            .join(format!("{}.json", safe_file_stem(disposition_id)))
    }

    fn factory_replication_decision_path(&self, decision_id: &str) -> PathBuf {
        self.root
            .join("factory-replication")
            .join("decisions")
            .join(format!("{}.json", safe_file_stem(decision_id)))
    }

    fn factory_replication_evidence_packet_path(&self, packet_id: &str) -> PathBuf {
        self.root
            .join("factory-replication")
            .join("evidence-packets")
            .join(format!("{}.json", safe_file_stem(packet_id)))
    }

    fn factory_identity_manifest_path(&self, factory_identity_id: &str) -> PathBuf {
        self.root
            .join("factory-exchange")
            .join("identities")
            .join(format!("{}.json", safe_file_stem(factory_identity_id)))
    }

    fn factory_exchange_envelope_path(&self, exchange_id: &str) -> PathBuf {
        self.root
            .join("factory-exchange")
            .join("envelopes")
            .join(format!("{}.json", safe_file_stem(exchange_id)))
    }

    fn factory_compatibility_decision_path(&self, decision_id: &str) -> PathBuf {
        self.root
            .join("factory-exchange")
            .join("compatibility-decisions")
            .join(format!("{}.json", safe_file_stem(decision_id)))
    }

    fn imported_artifact_quarantine_packet_path(&self, quarantine_packet_id: &str) -> PathBuf {
        self.root
            .join("factory-exchange")
            .join("quarantine-packets")
            .join(format!("{}.json", safe_file_stem(quarantine_packet_id)))
    }

    fn import_state_path(&self, import_state_id: &str) -> PathBuf {
        self.root
            .join("factory-exchange")
            .join("import-states")
            .join(format!("{}.json", safe_file_stem(import_state_id)))
    }

    fn import_disposition_path(&self, disposition_id: &str) -> PathBuf {
        self.root
            .join("factory-exchange")
            .join("dispositions")
            .join(format!("{}.json", safe_file_stem(disposition_id)))
    }

    fn cross_factory_lineage_import_path(&self, lineage_import_id: &str) -> PathBuf {
        self.root
            .join("factory-exchange")
            .join("lineage-imports")
            .join(format!("{}.json", safe_file_stem(lineage_import_id)))
    }

    fn memory_exchange_packet_path(&self, memory_exchange_id: &str) -> PathBuf {
        self.root
            .join("factory-exchange")
            .join("memory-packets")
            .join(format!("{}.json", safe_file_stem(memory_exchange_id)))
    }

    fn read_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<T, StorageError> {
        let raw = fs::read(path)?;
        Ok(serde_json::from_slice(&raw)?)
    }
}

trait ValidateRecord {
    fn validate_record(&self) -> Result<(), String>;
}

macro_rules! impl_validate_record {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl ValidateRecord for $ty {
                fn validate_record(&self) -> Result<(), String> {
                    self.validate().map_err(|error| error.to_string())
                }
            }
        )+
    };
}

impl_validate_record!(
    InferenceProviderRegistryEntry,
    InferenceTurnResult,
    TurnPackage,
    WorkerSpecializationCard,
    ModelContinuityBundle,
    TurnGroundingPacket,
    OpenQuestionLedger,
    ContradictionCarryForwardRecord,
    VerifiedTurnMemoryUpdate,
    ContextTruncationRecord,
    PromptLayerRecord,
    PromptRenderingRecord,
    TurnResponseSchemaRecord,
    ParsedToolCallIntentRecord,
    ParsedProposalRecord,
    ParsedApprovalRequestRecord,
    ParseRepairRecord,
    ParsedTurnResult,
    ToolExecutionContextRecord,
    ToolCallLegalityRecord,
    ToolExecutionRecord,
    ParsedTurnToolExecutionReceipt,
    OperatorOnlySurfaceRecord,
    ModelDelegationPolicyRecord,
    ModelAuthorityDecision,
    ModelApprovalRequestRecord,
    ModelOutputQuarantineRecord,
    TurnCheckpointRecord,
    PendingGovernedTurnActionRecord,
    LlmFactoryProgramProfile,
    ModelDrivenFactoryCycleRecord,
    RecursiveLineageExecutionRecord,
    ArchitecturalDependencyStatement,
    InterfaceNativeRecursionClosureDossier,
);

impl ValidateRecord for MemoryRetrievalTrace {
    fn validate_record(&self) -> Result<(), String> {
        self.validate()
    }
}

fn validate_shadow_evaluation_bundle(bundle: &ShadowEvaluationBundle) -> Result<(), StorageError> {
    bundle.incumbent_runtime_state.validate_replayability()?;
    bundle.challenger_runtime_state.validate_replayability()?;

    if bundle.challenger_evaluation_session.shadow_campaign_id
        != bundle.shadow_campaign.shadow_campaign_id
    {
        return Err(storage_integrity_error(
            "shadow evaluation session must remain attached to the same shadow campaign",
        ));
    }

    if !sorted_refs(&bundle.shadow_campaign.shared_input_refs).eq(&sorted_refs(
        &bundle.challenger_evaluation_session.shared_input_refs,
    )) || !sorted_refs(&bundle.shadow_campaign.shared_input_refs)
        .eq(&sorted_refs(&bundle.comparison_record.shared_input_refs))
    {
        return Err(storage_integrity_error(
            "shadow campaign, challenger evaluation session, and comparison must share the same input refs",
        ));
    }

    if bundle.comparison_record.comparison_id != bundle.promotion_readiness_decision.comparison_id
        || bundle.comparison_record.challenger_ref
            != bundle.promotion_readiness_decision.challenger_ref
    {
        return Err(storage_integrity_error(
            "promotion readiness must remain aligned to the shadow comparison record",
        ));
    }

    validate_comparison_dimensions(&bundle.comparison_record)?;
    validate_native_sufficiency(
        &bundle.comparison_record,
        &bundle.sufficiency_evidence,
        crate::execution::NativeReplacementTier::NativeSupervisorChallengers,
        "shadow evaluation",
    )?;
    validate_checkpoint_lineage(
        &bundle.challenger_runtime_state.memory_store,
        bundle
            .challenger_evaluation_session
            .latest_challenger_checkpoint_ref
            .as_deref()
            .or(bundle
                .challenger_runtime_state
                .session
                .latest_checkpoint_ref
                .as_deref())
            .or(bundle
                .challenger_runtime_state
                .latest_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.checkpoint_id.as_str())),
        "shadow evaluation",
    )?;
    validate_control_audits(
        &bundle.challenger_runtime_state.memory_store,
        &[
            bundle.comparison_record.comparison_id.as_str(),
            bundle.sufficiency_evidence.evidence_id.as_str(),
        ],
        "shadow evaluation",
    )?;
    validate_review_artifact_refs(
        &bundle.challenger_runtime_state.memory_store,
        &bundle.promotion_readiness_decision.review_artifact_refs,
        "shadow evaluation",
    )?;
    validate_audit_refs_exist(
        &bundle.challenger_runtime_state.memory_store,
        &bundle.sufficiency_evidence.audit_refs,
        "shadow evaluation",
    )?;

    Ok(())
}

fn validate_promotion_activation_bundle(
    bundle: &PromotionActivationBundle,
) -> Result<(), StorageError> {
    validate_shadow_evaluation_bundle(&bundle.shadow_evaluation_bundle)?;
    bundle.promoted_runtime_state.validate_replayability()?;

    if bundle.promotion_act.comparison_id
        != bundle
            .shadow_evaluation_bundle
            .comparison_record
            .comparison_id
    {
        return Err(storage_integrity_error(
            "promotion act must remain anchored to the shadow comparison record",
        ));
    }

    if bundle.epoch_adoption_record.promotion_act_id != bundle.promotion_act.promotion_act_id
        || bundle.reversal_window.promotion_act_id != bundle.promotion_act.promotion_act_id
    {
        return Err(storage_integrity_error(
            "epoch adoption and reversal window must remain anchored to the same promotion act",
        ));
    }

    validate_comparison_dimensions(&bundle.successor_loop_comparison)?;
    validate_native_sufficiency(
        &bundle.successor_loop_comparison,
        &bundle.successor_loop_evidence,
        crate::execution::NativeReplacementTier::BoundedSelfHostingLoop,
        "promotion activation",
    )?;
    validate_checkpoint_lineage(
        &bundle.promoted_runtime_state.memory_store,
        bundle
            .promoted_runtime_state
            .session
            .latest_checkpoint_ref
            .as_deref()
            .or(bundle
                .promoted_runtime_state
                .latest_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.checkpoint_id.as_str())),
        "promotion activation",
    )?;
    validate_control_audits(
        &bundle.promoted_runtime_state.memory_store,
        &[
            bundle.promotion_act.promotion_act_id.as_str(),
            bundle.epoch_adoption_record.adoption_id.as_str(),
            bundle.reversal_window.reversal_window_id.as_str(),
            bundle.successor_loop_comparison.comparison_id.as_str(),
            bundle.successor_loop_evidence.evidence_id.as_str(),
        ],
        "promotion activation",
    )?;
    validate_review_artifact_refs(
        &bundle.promoted_runtime_state.memory_store,
        &bundle.promotion_act.review_artifact_refs,
        "promotion activation",
    )?;
    validate_review_artifact_refs(
        &bundle.promoted_runtime_state.memory_store,
        &bundle.epoch_adoption_record.carried_artifact_refs,
        "promotion activation epoch handoff",
    )?;
    validate_campaign_portfolio_budget_evidence(
        &bundle.promoted_runtime_state.memory_store,
        "promotion activation",
    )?;
    validate_review_canary_release_evidence(
        &bundle.promoted_runtime_state.memory_store,
        &bundle.promotion_act.review_artifact_refs,
        "promotion activation",
    )?;
    validate_contention_control_evidence(
        &bundle.promoted_runtime_state.memory_store,
        &bundle.promoted_runtime_state.task_graph,
        "promotion activation",
    )?;
    validate_operator_steering_evidence(
        &bundle.promoted_runtime_state.memory_store,
        "promotion activation",
    )?;
    validate_audit_refs_exist(
        &bundle.promoted_runtime_state.memory_store,
        &bundle.successor_loop_evidence.audit_refs,
        "promotion activation",
    )?;
    validate_epoch_handoff_service_continuity(bundle)?;

    Ok(())
}

fn validate_v1_completion_bundle(bundle: &V1CompletionBundle) -> Result<(), StorageError> {
    validate_promotion_activation_bundle(&bundle.promotion_activation_bundle)?;

    if !closure_inventory_is_complete(&bundle.closure_inventory) {
        return Err(storage_integrity_error(
            "v1 completion requires a fully covered closure inventory with explicit audit-backed entries",
        ));
    }

    if bundle.semantic_validation_record.genome_ref != bundle.successor_genome.genome_id
        || bundle.semantic_validation_record.phenotype_ref != bundle.successor_phenotype.artifact_id
        || bundle.successor_phenotype.genome_ref != bundle.successor_genome.genome_id
        || !bundle.semantic_validation_record.passed
    {
        return Err(storage_integrity_error(
            "v1 completion requires aligned genome, phenotype, and semantic validation records",
        ));
    }

    validate_comparison_dimensions(&bundle.second_cycle_comparison)?;
    validate_native_sufficiency(
        &bundle.second_cycle_comparison,
        &bundle.second_cycle_evidence,
        crate::execution::NativeReplacementTier::BoundedSelfHostingLoop,
        "v1 completion",
    )?;

    if bundle.second_cycle_readiness.comparison_id != bundle.second_cycle_comparison.comparison_id
        || bundle.second_cycle_readiness.challenger_ref
            != bundle.second_cycle_comparison.challenger_ref
        || bundle.second_cycle_decision.comparison_id
            != bundle.second_cycle_comparison.comparison_id
        || bundle.second_cycle_decision.promotion_readiness_ref
            != bundle.second_cycle_readiness.decision_id
    {
        return Err(storage_integrity_error(
            "v1 completion must keep second-cycle comparison, readiness, and closure decisions aligned",
        ));
    }

    if bundle.v1_completion_gate.closure_inventory_ref != bundle.closure_inventory.inventory_id
        || bundle.v1_completion_gate.cycle_closure_decision_ref
            != bundle.second_cycle_decision.decision_id
    {
        return Err(storage_integrity_error(
            "v1 completion gate must remain anchored to the active closure inventory and cycle decision",
        ));
    }

    if bundle.v1_completion_gate.status == V1CompletionStatus::Satisfied
        && bundle.second_cycle_decision.status
            != crate::execution::CycleClosureDecisionStatus::Promote
        && bundle.second_cycle_decision.status
            != crate::execution::CycleClosureDecisionStatus::Retain
    {
        return Err(storage_integrity_error(
            "a satisfied v1 completion gate requires a promotable or retained second-cycle decision",
        ));
    }

    validate_inventory_audit_coverage(
        &bundle
            .promotion_activation_bundle
            .promoted_runtime_state
            .memory_store,
        &bundle.closure_inventory,
        "v1 completion",
    )?;
    validate_review_artifact_refs(
        &bundle
            .promotion_activation_bundle
            .promoted_runtime_state
            .memory_store,
        &bundle.second_cycle_readiness.review_artifact_refs,
        "v1 completion",
    )?;
    validate_review_artifact_refs(
        &bundle
            .promotion_activation_bundle
            .promoted_runtime_state
            .memory_store,
        &bundle.second_cycle_decision.review_artifact_refs,
        "v1 completion",
    )?;
    validate_background_program_memory_continuity(
        &bundle
            .promotion_activation_bundle
            .promoted_runtime_state
            .memory_store,
        "v1 completion",
    )?;
    validate_audit_refs_exist(
        &bundle
            .promotion_activation_bundle
            .promoted_runtime_state
            .memory_store,
        &bundle.second_cycle_evidence.audit_refs,
        "v1 completion",
    )?;

    Ok(())
}

fn validate_shell_session_bundle(bundle: &ShellSessionBundle) -> Result<(), StorageError> {
    bundle.runtime_state.validate_replayability()?;

    if bundle.shell_session.shell_session_id.trim().is_empty()
        || bundle.shell_session.execution_session_ref.trim().is_empty()
        || bundle.shell_session.task_id.trim().is_empty()
        || bundle
            .shell_session
            .capability_envelope_ref
            .trim()
            .is_empty()
    {
        return Err(storage_integrity_error(
            "v4 shell session bundle requires shell, session, task, and capability refs",
        ));
    }

    if bundle.shell_session.execution_session_ref != bundle.runtime_state.session.header.session_id
        || bundle.shell_session.task_id != bundle.runtime_state.root_task.task_id
        || bundle.shell_session.capability_envelope_ref
            != bundle.runtime_state.session.header.capability_envelope_ref
    {
        return Err(storage_integrity_error(
            "v4 shell session bundle must remain aligned with the replayable runtime state",
        ));
    }

    if bundle
        .shell_session
        .latest_turn_ref
        .as_ref()
        .is_some_and(|turn_ref| {
            !bundle
                .shell_turns
                .iter()
                .any(|turn| &turn.shell_turn_id == turn_ref)
        })
    {
        return Err(storage_integrity_error(
            "v4 shell session bundle latest turn ref must resolve to a stored turn",
        ));
    }

    if bundle
        .shell_session
        .latest_checkpoint_ref
        .as_ref()
        .is_some_and(|checkpoint_ref| {
            !bundle
                .shell_checkpoints
                .iter()
                .any(|checkpoint| &checkpoint.runtime_checkpoint_ref == checkpoint_ref)
        })
    {
        return Err(storage_integrity_error(
            "v4 shell session bundle latest checkpoint ref must resolve to a stored shell checkpoint",
        ));
    }

    if bundle
        .shell_session
        .latest_resume_anchor_ref
        .as_ref()
        .is_some_and(|anchor_ref| {
            !bundle
                .resume_anchors
                .iter()
                .any(|anchor| &anchor.resume_anchor_id == anchor_ref)
        })
    {
        return Err(storage_integrity_error(
            "v4 shell session bundle latest resume anchor ref must resolve to a stored anchor",
        ));
    }

    for turn in &bundle.shell_turns {
        if turn.shell_session_id != bundle.shell_session.shell_session_id {
            return Err(storage_integrity_error(
                "v4 shell turn must remain attached to the same shell session",
            ));
        }
        for action_trace_ref in &turn.action_trace_refs {
            if !bundle
                .action_traces
                .iter()
                .any(|trace| &trace.request.action_id == action_trace_ref)
            {
                return Err(storage_integrity_error(format!(
                    "v4 shell turn '{}' references missing action trace '{}'",
                    turn.shell_turn_id, action_trace_ref
                )));
            }
        }
    }

    for action_trace in &bundle.action_traces {
        if action_trace.request.shell_session_id != bundle.shell_session.shell_session_id {
            return Err(storage_integrity_error(
                "v4 worker action trace must remain attached to the same shell session",
            ));
        }
        if !bundle
            .action_decisions
            .iter()
            .any(|decision| decision.decision_id == action_trace.decision.decision_id)
        {
            return Err(storage_integrity_error(format!(
                "v4 worker action trace '{}' is missing its persisted decision",
                action_trace.request.action_id
            )));
        }
    }

    if let Some(continuity_bundle) = &bundle.continuity_bundle {
        if continuity_bundle.shell_session_id != bundle.shell_session.shell_session_id {
            return Err(storage_integrity_error(
                "v4 continuity bundle must remain attached to the same shell session",
            ));
        }
        if continuity_bundle
            .retrieval_trace_refs
            .iter()
            .any(|trace_ref| {
                !bundle
                    .memory_retrieval_traces
                    .iter()
                    .any(|trace| &trace.trace_id == trace_ref)
            })
        {
            return Err(storage_integrity_error(
                "v4 continuity bundle references missing retrieval traces",
            ));
        }
        if continuity_bundle
            .verified_memory_refs
            .iter()
            .any(|record_ref| {
                !bundle
                    .verified_memory_updates
                    .iter()
                    .any(|record| &record.record_id == record_ref)
            })
        {
            return Err(storage_integrity_error(
                "v4 continuity bundle references missing verified memory updates",
            ));
        }
    }

    Ok(())
}

fn validate_shell_evidence_packet(
    packet: &ShellEvidencePacket,
    bundle: Option<&ShellSessionBundle>,
) -> Result<(), StorageError> {
    if packet.packet_id.trim().is_empty()
        || packet.shell_session_ref.trim().is_empty()
        || packet.shell_session_bundle_ref.trim().is_empty()
    {
        return Err(storage_integrity_error(
            "v4 shell evidence packet requires packet, shell session, and bundle refs",
        ));
    }

    if let Some(bundle) = bundle {
        if packet.shell_session_ref != bundle.shell_session.shell_session_id {
            return Err(storage_integrity_error(
                "v4 shell evidence packet must remain aligned to the shell session bundle",
            ));
        }
    }

    Ok(())
}

fn validate_v4_supervisory_shell_completion_gate(
    gate: &V4SupervisoryShellCompletionGate,
) -> Result<(), StorageError> {
    if gate.gate_id.trim().is_empty() {
        return Err(storage_integrity_error(
            "v4 supervisory shell completion gate requires a gate id",
        ));
    }
    let expected =
        evaluate_v4_supervisory_shell_completion_gate(gate.gate_id.clone(), gate.evidence.clone());
    if gate.status != expected.status
        || gate.missing_evidence_refs != expected.missing_evidence_refs
    {
        return Err(storage_integrity_error(
            "v4 supervisory shell completion gate must match deterministic evaluation",
        ));
    }
    Ok(())
}

fn validate_active_factory_state(state: &ActiveFactoryState) -> Result<(), StorageError> {
    if state.state_id.trim().is_empty() {
        return Err(storage_integrity_error("factory state requires a state id"));
    }
    if state.active_factory_ref.trim().is_empty() {
        return Err(storage_integrity_error(
            "factory state requires an active factory ref",
        ));
    }
    if state
        .retained_incumbent_ref
        .as_ref()
        .is_some_and(|reference| reference.trim().is_empty())
    {
        return Err(storage_integrity_error(
            "factory state retained incumbent ref cannot be blank",
        ));
    }

    for activation in &state.activation_history {
        if activation.activation_id.trim().is_empty()
            || activation.from_factory_ref.trim().is_empty()
            || activation.to_factory_ref.trim().is_empty()
            || activation.comparison_ref.trim().is_empty()
            || activation.observation_window_ref.trim().is_empty()
            || activation.rollback_handle_ref.trim().is_empty()
            || activation.retained_incumbent_ref.trim().is_empty()
        {
            return Err(storage_integrity_error(
                "factory state activation history must keep explicit factory, comparison, observation, and rollback refs",
            ));
        }
    }

    for rollback in &state.rollback_history {
        if rollback.rollback_id.trim().is_empty()
            || rollback.from_factory_ref.trim().is_empty()
            || rollback.restored_factory_ref.trim().is_empty()
            || rollback.activation_ref.trim().is_empty()
            || rollback.rollback_handle_ref.trim().is_empty()
        {
            return Err(storage_integrity_error(
                "factory state rollback history must keep explicit activation and rollback refs",
            ));
        }
    }

    Ok(())
}

fn storage_integrity_error(message: impl Into<String>) -> StorageError {
    StorageError::Io(std::io::Error::other(message.into()))
}

fn sorted_refs(refs: &[String]) -> BTreeSet<&str> {
    refs.iter().map(String::as_str).collect()
}

fn safe_file_stem(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn validate_component_build_output(output: &ComponentBuildOutput) -> Result<(), StorageError> {
    if output.build_id.trim().is_empty() {
        return Err(storage_integrity_error(
            "v3 component build output requires a build id",
        ));
    }
    if output.component_digest != output.inspection.component_digest
        || output.component_digest != output.build_closure.output_digest
        || output.component_digest != output.package_manifest.component_digest
    {
        return Err(storage_integrity_error(
            "v3 component build output must keep component digests aligned",
        ));
    }
    if !output.inspection.executable || output.component_bytes.len() < 4 {
        return Err(storage_integrity_error(
            "v3 component build output must be executable and carry component bytes",
        ));
    }
    output.package_manifest.validate().map_err(|error| {
        storage_integrity_error(format!("v3 package manifest validation failed: {error}"))
    })?;
    Ok(())
}

fn validate_execution_validation_record(
    record: &ExecutionBackedValidationRecord,
) -> Result<(), StorageError> {
    if record.validation_id.trim().is_empty()
        || record.trace_ref.trim().is_empty()
        || record.scenario_refs.is_empty()
        || record.output_refs.is_empty()
        || record.event_refs.is_empty()
    {
        return Err(storage_integrity_error(
            "v3 execution validation record is missing trace evidence",
        ));
    }
    Ok(())
}

fn validate_comparison_dimensions(
    comparison: &GenerationComparisonRecord,
) -> Result<(), StorageError> {
    for dimension in [
        crate::execution::EvaluationDimension::SemanticCorrectness,
        crate::execution::EvaluationDimension::GovernanceFidelity,
        crate::execution::EvaluationDimension::Replayability,
        crate::execution::EvaluationDimension::OperatorBurden,
        crate::execution::EvaluationDimension::BoundaryCost,
        crate::execution::EvaluationDimension::ReplacementSafety,
    ] {
        if !comparison
            .dimension_scores
            .iter()
            .any(|score| score.dimension == dimension)
        {
            return Err(storage_integrity_error(format!(
                "comparison '{}' is missing required {:?} evidence",
                comparison.comparison_id, dimension
            )));
        }
    }

    Ok(())
}

fn validate_native_sufficiency(
    comparison: &GenerationComparisonRecord,
    evidence: &NativeSufficiencyEvidence,
    required_tier: crate::execution::NativeReplacementTier,
    label: &str,
) -> Result<(), StorageError> {
    let gate = NativeSufficiencyGate {
        target: comparison.target,
        required_tier,
        requires_exact_match: true,
    };

    if !evaluate_native_sufficiency_with_evidence(&gate, comparison, evidence) {
        return Err(storage_integrity_error(format!(
            "{label} requires exact native-sufficiency evidence for comparison '{}'",
            comparison.comparison_id
        )));
    }

    Ok(())
}

fn validate_checkpoint_lineage(
    memory_store: &MemoryStore,
    checkpoint_id: Option<&str>,
    label: &str,
) -> Result<(), StorageError> {
    let Some(checkpoint_id) = checkpoint_id else {
        return Err(storage_integrity_error(format!(
            "{label} requires a replayable checkpoint reference"
        )));
    };

    let checkpoint_lineage = memory_store.checkpoint_lineage(checkpoint_id);
    let has_checkpoint_artifact = checkpoint_lineage
        .iter()
        .any(|artifact| matches!(artifact.payload, MemoryArtifactPayload::Checkpoint(_)));
    let has_checkpoint_audit = checkpoint_lineage.iter().any(|artifact| {
        matches!(
            artifact.payload,
            MemoryArtifactPayload::AuditRecord(ref audit_record)
                if matches!(
                    audit_record.class,
                    AuditRecordClass::ExecutionAuditRecord
                        | AuditRecordClass::GovernanceAuditRecord
                        | AuditRecordClass::PromotionAuditRecord
                        | AuditRecordClass::ApprovalAuditRecord
                )
        )
    });

    if !has_checkpoint_artifact || !has_checkpoint_audit {
        return Err(storage_integrity_error(format!(
            "{label} requires checkpoint lineage with both checkpoint and audit artifacts for '{checkpoint_id}'"
        )));
    }

    Ok(())
}

fn validate_control_audits(
    memory_store: &MemoryStore,
    related_refs: &[&str],
    label: &str,
) -> Result<(), StorageError> {
    for related_ref in related_refs {
        let has_audit = memory_store
            .artifacts_for_related_ref(related_ref)
            .iter()
            .any(|artifact| matches!(artifact.payload, MemoryArtifactPayload::AuditRecord(_)));
        if !has_audit {
            return Err(storage_integrity_error(format!(
                "{label} requires an audit-backed native control record for '{related_ref}'"
            )));
        }
    }

    Ok(())
}

fn validate_inventory_audit_coverage(
    memory_store: &MemoryStore,
    inventory: &ClosureInventory,
    label: &str,
) -> Result<(), StorageError> {
    for entry in &inventory.entries {
        let Some(audit_ref) = entry.audit_ref.as_deref() else {
            return Err(storage_integrity_error(format!(
                "{label} requires explicit service audit coverage for '{:?}'",
                entry.target
            )));
        };

        if !has_audit_ref(memory_store, audit_ref) {
            return Err(storage_integrity_error(format!(
                "{label} requires persisted service audit coverage for inventory audit ref '{audit_ref}'"
            )));
        }
    }

    Ok(())
}

fn validate_review_artifact_refs(
    memory_store: &MemoryStore,
    review_artifact_refs: &[String],
    label: &str,
) -> Result<(), StorageError> {
    for review_artifact_ref in review_artifact_refs {
        if !has_supporting_ref(memory_store, review_artifact_ref) {
            return Err(storage_integrity_error(format!(
                "{label} requires persisted operator review support for '{review_artifact_ref}'"
            )));
        }
    }

    Ok(())
}

fn validate_campaign_portfolio_budget_evidence(
    memory_store: &MemoryStore,
    label: &str,
) -> Result<(), StorageError> {
    let prefixes = ["portfolio:", "budget:", "intervention:"];
    if !memory_store
        .has_bundle_with_evidence_prefixes(TopicBundleClass::CampaignOperatingNotes, &prefixes)
    {
        return Err(storage_integrity_error(format!(
            "{label} requires a campaign-operating bundle with portfolio, budget, and intervention evidence"
        )));
    }

    for prefix in prefixes {
        if !memory_store.has_ref_prefix(prefix) {
            return Err(storage_integrity_error(format!(
                "{label} requires persisted portfolio evidence for prefix '{prefix}'"
            )));
        }
    }

    Ok(())
}

fn validate_review_canary_release_evidence(
    memory_store: &MemoryStore,
    review_artifact_refs: &[String],
    label: &str,
) -> Result<(), StorageError> {
    let has_bundle = memory_store.topic_bundles.iter().any(|bundle| {
        bundle.bundle_class == TopicBundleClass::GovernanceNotes
            && review_artifact_refs.iter().any(|review_artifact_ref| {
                bundle
                    .evidence_refs
                    .iter()
                    .any(|evidence_ref| evidence_ref == review_artifact_ref)
            })
            && ["canary:", "release:", "rejection:"].iter().all(|prefix| {
                bundle
                    .evidence_refs
                    .iter()
                    .any(|evidence_ref| evidence_ref.starts_with(prefix))
            })
    });

    if !has_bundle {
        return Err(storage_integrity_error(format!(
            "{label} requires a governance review bundle with canary, release, and rejection evidence"
        )));
    }

    for prefix in ["canary:", "release:", "rejection:"] {
        if !memory_store.has_ref_prefix(prefix) {
            return Err(storage_integrity_error(format!(
                "{label} requires persisted review evidence for prefix '{prefix}'"
            )));
        }
    }

    Ok(())
}

fn validate_operator_steering_evidence(
    memory_store: &MemoryStore,
    label: &str,
) -> Result<(), StorageError> {
    let has_bundle = memory_store.topic_bundles.iter().any(|bundle| {
        matches!(
            bundle.bundle_class,
            TopicBundleClass::ArchitectureDecision | TopicBundleClass::GovernanceNotes
        ) && ["steering:", "rollback-rehearsal:", "adoption-safety:"]
            .iter()
            .all(|prefix| {
                bundle.bundle_id.starts_with(prefix)
                    || bundle
                        .evidence_refs
                        .iter()
                        .any(|evidence_ref| evidence_ref.starts_with(prefix))
            })
    });

    if !has_bundle {
        return Err(storage_integrity_error(format!(
            "{label} requires operator steering evidence with steering, rollback rehearsal, and adoption-safety refs"
        )));
    }

    for prefix in ["steering:", "rollback-rehearsal:", "adoption-safety:"] {
        if !memory_store.has_ref_prefix(prefix) {
            return Err(storage_integrity_error(format!(
                "{label} requires persisted operator steering evidence for prefix '{prefix}'"
            )));
        }
    }

    Ok(())
}

fn validate_background_program_memory_continuity(
    memory_store: &MemoryStore,
    label: &str,
) -> Result<(), StorageError> {
    let prefixes = [
        "program-memory:",
        "plan-carry-forward:",
        "reprioritization:",
    ];
    if !memory_store
        .has_bundle_with_evidence_prefixes(TopicBundleClass::CampaignOperatingNotes, &prefixes)
    {
        return Err(storage_integrity_error(format!(
            "{label} requires a campaign-operating bundle with program-memory carry-forward evidence"
        )));
    }

    if !memory_store
        .has_transcript_references_with_prefixes(&["plan-carry-forward:", "reprioritization:"])
    {
        return Err(storage_integrity_error(format!(
            "{label} requires transcript-backed plan carry-forward and reprioritization evidence"
        )));
    }

    if !memory_store.has_resolved_contradiction() {
        return Err(storage_integrity_error(format!(
            "{label} requires at least one resolved contradiction record for long-horizon continuity"
        )));
    }

    for prefix in prefixes {
        if !memory_store.has_ref_prefix(prefix) {
            return Err(storage_integrity_error(format!(
                "{label} requires persisted background-program evidence for prefix '{prefix}'"
            )));
        }
    }

    Ok(())
}

fn validate_contention_control_evidence(
    memory_store: &MemoryStore,
    task_graph: &TaskGraph,
    label: &str,
) -> Result<(), StorageError> {
    if !memory_store.has_bundle_with_evidence_prefixes(
        TopicBundleClass::CampaignOperatingNotes,
        &["contention:", "fairness:"],
    ) {
        return Err(storage_integrity_error(format!(
            "{label} requires campaign-operating evidence for contention and fairness control"
        )));
    }

    for prefix in ["contention:", "fairness:"] {
        if !memory_store.has_ref_prefix(prefix) {
            return Err(storage_integrity_error(format!(
                "{label} requires persisted contention evidence for prefix '{prefix}'"
            )));
        }
    }

    validate_active_ownership_contention(task_graph, label)
}

fn validate_active_ownership_contention(
    task_graph: &TaskGraph,
    label: &str,
) -> Result<(), StorageError> {
    let active_items: Vec<_> = task_graph
        .agenda_items
        .iter()
        .filter(|agenda_item| {
            matches!(
                agenda_item.status,
                AgendaStatus::Ready | AgendaStatus::Dispatched | AgendaStatus::AwaitingSynthesis
            )
        })
        .collect();

    for (index, left) in active_items.iter().enumerate() {
        for right in active_items.iter().skip(index + 1) {
            let same_scope =
                left.ownership_boundary.resource_scope == right.ownership_boundary.resource_scope;
            let same_owner =
                left.ownership_boundary.owner_actor_ref == right.ownership_boundary.owner_actor_ref;
            let both_read_only = left.ownership_boundary.mode == OwnershipMode::ReadOnlyFanOut
                && right.ownership_boundary.mode == OwnershipMode::ReadOnlyFanOut;

            if same_scope && !same_owner && !both_read_only {
                return Err(storage_integrity_error(format!(
                    "{label} requires bounded contention control for scope '{}' between '{}' and '{}'",
                    left.ownership_boundary.resource_scope, left.task_id, right.task_id
                )));
            }
        }
    }

    Ok(())
}

fn validate_audit_refs_exist(
    memory_store: &MemoryStore,
    audit_refs: &[String],
    label: &str,
) -> Result<(), StorageError> {
    for audit_ref in audit_refs {
        if !has_audit_ref(memory_store, audit_ref) {
            return Err(storage_integrity_error(format!(
                "{label} requires persisted audit evidence for '{audit_ref}'"
            )));
        }
    }

    Ok(())
}

fn validate_epoch_handoff_service_continuity(
    bundle: &PromotionActivationBundle,
) -> Result<(), StorageError> {
    if bundle.epoch_adoption_record.status == crate::execution::EpochAdoptionStatus::Active {
        validate_checkpoint_lineage(
            &bundle.promoted_runtime_state.memory_store,
            bundle
                .epoch_adoption_record
                .activation_checkpoint_ref
                .as_deref(),
            "promotion activation epoch handoff",
        )?;
    }

    Ok(())
}

fn has_supporting_ref(memory_store: &MemoryStore, reference: &str) -> bool {
    memory_store
        .artifacts
        .iter()
        .any(|artifact| artifact.artifact_id == reference || artifact.related_ref == reference)
        || memory_store
            .topic_bundles
            .iter()
            .any(|topic_bundle| topic_bundle.bundle_id == reference)
        || memory_store
            .transcript_slices
            .iter()
            .any(|transcript_slice| transcript_slice.slice_id == reference)
        || has_audit_ref(memory_store, reference)
}

fn has_audit_ref(memory_store: &MemoryStore, reference: &str) -> bool {
    memory_store.artifacts.iter().any(|artifact| {
        matches!(
            artifact.payload,
            MemoryArtifactPayload::AuditRecord(ref audit_record)
                if audit_record.audit_record_id == reference || audit_record.related_ref == reference
        )
    })
}

pub fn execute_rollback(
    rollback_handle: &RollbackHandle,
    store: &DurableArtifactStore,
) -> Result<ReplayableRuntimeState, RollbackExecutionError> {
    if !rollback_handle.approval_requirements.is_empty() {
        return Err(RollbackExecutionError::ApprovalRequired {
            rollback_handle_id: rollback_handle.rollback_handle_id.clone(),
        });
    }

    let runtime_state = store
        .load_runtime_state_for_checkpoint(&rollback_handle.safe_state_ref)
        .map_err(|error| RollbackExecutionError::Storage(error.to_string()))?;
    validate_rollback_evidence(rollback_handle, &runtime_state)?;

    Ok(runtime_state)
}

fn validate_rollback_evidence(
    rollback_handle: &RollbackHandle,
    runtime_state: &ReplayableRuntimeState,
) -> Result<(), RollbackExecutionError> {
    let checkpoint_lineage = runtime_state
        .memory_store
        .checkpoint_lineage(&rollback_handle.safe_state_ref);
    let has_checkpoint_artifact = checkpoint_lineage.iter().any(|artifact| {
        artifact.class == crate::execution::MemoryArtifactClass::CheckpointArtifact
    });
    let has_checkpoint_audit = checkpoint_lineage.iter().any(|artifact| {
        artifact.class == crate::execution::MemoryArtifactClass::AuditRecordArtifact
    });
    let has_governance_or_promotion_audit = runtime_state
        .memory_store
        .artifacts_for_related_ref(&rollback_handle.rollback_handle_id)
        .iter()
        .chain(
            runtime_state
                .memory_store
                .artifacts_for_related_ref(&rollback_handle.safe_state_ref)
                .iter(),
        )
        .any(|artifact| {
            matches!(
                artifact.payload,
                crate::execution::MemoryArtifactPayload::AuditRecord(ref audit_record)
                    if matches!(
                        audit_record.class,
                        crate::execution::AuditRecordClass::GovernanceAuditRecord
                            | crate::execution::AuditRecordClass::PromotionAuditRecord
                    )
            )
        });

    if !has_checkpoint_artifact || !has_checkpoint_audit || !has_governance_or_promotion_audit {
        return Err(RollbackExecutionError::Storage(format!(
            "rollback '{}' is missing checkpoint or governance evidence for '{}'",
            rollback_handle.rollback_handle_id, rollback_handle.safe_state_ref
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::execution::events::{EventFamily, ExecutionEvent};
    use crate::execution::failure_budget::FailureBudget;
    use crate::execution::governance::{
        AuditRecord, AuditRecordClass, CycleClosureDecision, CycleClosureDecisionStatus,
        EpochAdoptionRecord, EpochAdoptionStatus, PromotionAct, PromotionActStatus,
        PromotionReadinessDecision, PromotionReadinessStatus, ReversalWindow, ReversalWindowStatus,
        V1CompletionGate, V1CompletionStatus,
    };
    use crate::execution::memory::{
        MemoryScope, PointerIndex, TopicBundle, TopicBundleClass, TranscriptSlice,
    };
    use crate::execution::orchestration::{
        AgendaItem, OwnershipBoundary, OwnershipMode, TaskGraph,
    };
    use crate::execution::replacement::{
        CapabilityClosureEntry, CapabilityClosureStatus, CapabilityDependencyMode,
        ChallengerEvaluationSession, ClosureInventory, DimensionVerdict, EvaluationDimension,
        EvaluationDimensionScore, GenerationComparisonRecord, GenomeArtifact,
        NativeReplacementTier, NativeSufficiencyEvidence, PhenotypeArtifact,
        SemanticValidationRecord, ShadowCampaign, ShadowCampaignStatus,
    };
    use crate::execution::session::{ActorKind, ExecutionSession, ExecutionSessionHeader};
    use crate::execution::task::TaskArtifact;
    use crate::execution::turn_package::{
        ContextBudgetRecord, ContinuityEntryPriority, TurnContinuityEntry, TurnPackage,
        TurnPackageRole, TurnResponseSchemaFamily, parse_turn_package_output, render_turn_package,
    };
    use crate::execution::{
        CapabilityImportTarget, FixtureInferenceResponse, InferenceFinishReason,
        InferenceGenerationPolicy, InferenceProviderMode, InferenceProviderModelEntry,
        InferenceProviderRegistryEntry, InferenceRenderedPromptRecord,
        InferenceResponseSchemaPayloadRecord, InferenceToolCatalogPayloadRecord,
        InferenceTurnRequest, MemoryArtifact, MemoryStore, ProviderDegradationReasonClass,
        create_rollback_handle, execute_inference_turn_with_fixture,
    };
    use serde::Deserialize;
    use std::env;
    use std::fs;
    use std::process;

    use super::{
        DurableArtifactStore, PromotionActivationBundle, ReplayableRuntimeState,
        RollbackExecutionError, RuntimeStateValidationError, ShadowEvaluationBundle, StorageError,
        V1CompletionBundle, execute_rollback,
    };

    #[derive(Deserialize)]
    struct Rc01PointerIndexFixture {
        artifact_id: String,
        critical_refs: Vec<String>,
        governance_constraints: Vec<String>,
    }

    fn temp_store_root(name: &str) -> std::path::PathBuf {
        env::temp_dir().join(format!("rc02-aiaf-{name}-{}", process::id()))
    }

    fn copy_dir_all(source: &std::path::Path, target: &std::path::Path) -> std::io::Result<()> {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let entry_type = entry.file_type()?;
            let target_path = target.join(entry.file_name());
            if entry_type.is_dir() {
                copy_dir_all(&entry.path(), &target_path)?;
            } else {
                fs::copy(entry.path(), target_path)?;
            }
        }
        Ok(())
    }

    fn runtime_state() -> ReplayableRuntimeState {
        let mut session = ExecutionSession::new(ExecutionSessionHeader {
            session_id: "session-1".to_string(),
            actor_kind: ActorKind::Supervisor,
            actor_id: "supervisor-alpha".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            capability_envelope_ref: "envelope-1".to_string(),
            parent_session_id: None,
        });
        let root_task = TaskArtifact::new("task-root", "Bounded replayable RC03 flow");
        let task_graph = TaskGraph::new(
            "task-root",
            vec![AgendaItem::new(
                "agenda-root",
                "task-root",
                "bounded-analysis",
                Vec::new(),
                OwnershipBoundary {
                    boundary_id: "boundary-root".to_string(),
                    resource_scope: "workspace-root".to_string(),
                    mode: OwnershipMode::ExclusiveMutable,
                    owner_actor_ref: "supervisor-alpha".to_string(),
                },
            )],
        );
        let mut memory_store = MemoryStore::default();
        memory_store.insert_pointer_index(PointerIndex {
            index_id: "pointer-index-1".to_string(),
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            entry_refs: vec!["task-root".to_string()],
            contested_refs: Vec::new(),
            critical_refs: vec!["task-root".to_string()],
            governance_constraints: vec!["human approval required".to_string()],
            open_task_refs: vec!["task-root".to_string()],
            updated_at: "t0".to_string(),
        });
        let checkpoint = crate::execution::RunCheckpoint::capture(
            "checkpoint-1",
            &session,
            Some(&root_task),
            Vec::new(),
            vec!["pointer-index-1".to_string()],
            FailureBudget::default().snapshot(),
            Vec::new(),
        );
        session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());
        ReplayableRuntimeState::new(
            session,
            root_task,
            task_graph,
            memory_store,
            Some(checkpoint),
            vec![ExecutionEvent::new(
                "event-1",
                EventFamily::CheckpointEvent,
                "campaign-1",
                "epoch-1",
                "session-1",
                None,
                None,
                "checkpoint captured",
            )],
        )
    }

    fn inference_provider() -> InferenceProviderRegistryEntry {
        InferenceProviderRegistryEntry {
            provider_id: "provider:fixture".to_string(),
            provider_mode: InferenceProviderMode::DeterministicFixture,
            models: vec![InferenceProviderModelEntry {
                model_ref: "model:test".to_string(),
                input_cost_per_million_microunits: 0,
                output_cost_per_million_microunits: 0,
                supports_json_schema: true,
                supports_function_tools: true,
            }],
            capability_summary: "deterministic fixture provider".to_string(),
            policy_summary: "kernel-only workstream-a boundary".to_string(),
            active: true,
            api_base_url: String::new(),
            api_key_env_var: String::new(),
            organization_env_var: None,
            project_env_var: None,
            request_timeout_ms: 50,
        }
    }

    fn inference_generation_policy() -> InferenceGenerationPolicy {
        InferenceGenerationPolicy {
            generation_policy_id: "policy:bounded-generation".to_string(),
            max_output_tokens: 256,
            max_retries: 0,
            summary: "bounded deterministic generation policy".to_string(),
        }
    }

    fn inference_turn_request() -> InferenceTurnRequest {
        InferenceTurnRequest {
            turn_request_id: "turn:storage".to_string(),
            provider_ref: "provider:fixture".to_string(),
            model_ref: "model:test".to_string(),
            rendered_prompt_ref: "prompt:storage".to_string(),
            tool_catalog_ref: "tools:storage".to_string(),
            response_schema_ref: "schema:storage".to_string(),
            generation_policy_ref: "policy:bounded-generation".to_string(),
        }
    }

    fn inference_rendered_prompt() -> InferenceRenderedPromptRecord {
        InferenceRenderedPromptRecord {
            rendered_prompt_id: "prompt:storage".to_string(),
            turn_request_ref: "turn:storage".to_string(),
            prompt_text: "You are a bounded Wasm-Biotic runtime.".to_string(),
            created_at: "1".to_string(),
        }
    }

    fn inference_tool_catalog() -> InferenceToolCatalogPayloadRecord {
        InferenceToolCatalogPayloadRecord {
            tool_catalog_id: "tools:storage".to_string(),
            turn_request_ref: "turn:storage".to_string(),
            tool_catalog_json: r#"[{"type":"function","name":"continuity.retrieve","description":"retrieve continuity","parameters":{"type":"object","properties":{},"additionalProperties":false}}]"#.to_string(),
            created_at: "1".to_string(),
        }
    }

    fn inference_response_schema() -> InferenceResponseSchemaPayloadRecord {
        InferenceResponseSchemaPayloadRecord {
            response_schema_id: "schema:storage".to_string(),
            turn_request_ref: "turn:storage".to_string(),
            response_schema_json: r#"{"type":"json_schema","name":"turn_result","strict":true,"schema":{"type":"object","properties":{"turn_outcome":{"type":"string"}},"required":["turn_outcome"],"additionalProperties":false}}"#.to_string(),
            created_at: "1".to_string(),
        }
    }

    fn supervisor_turn_package() -> TurnPackage {
        TurnPackage {
            turn_package_id: "turn-package:storage".to_string(),
            program_ref: "program:storage".to_string(),
            session_ref: "session:storage".to_string(),
            turn_ref: "turn:storage".to_string(),
            envelope_ref: "envelope:storage".to_string(),
            role: TurnPackageRole::Supervisor,
            system_frame_ref: "system:storage".to_string(),
            system_frame_text: "You are the bounded Wasm-Biotic supervisor.".to_string(),
            program_frame_ref: "program-frame:storage".to_string(),
            program_frame_text: "Advance the bounded lineage program.".to_string(),
            capability_frame_ref: "capability-frame:storage".to_string(),
            capability_frame_text: "Do not exceed the active capability envelope.".to_string(),
            agenda_ref: "agenda:storage".to_string(),
            agenda_text: "Evaluate the next bounded turn.".to_string(),
            continuity_entries: vec![
                TurnContinuityEntry {
                    entry_ref: "continuity:critical".to_string(),
                    text: "Critical continuity evidence.".to_string(),
                    priority: ContinuityEntryPriority::Critical,
                },
                TurnContinuityEntry {
                    entry_ref: "continuity:supporting".to_string(),
                    text: "Supporting continuity evidence.".to_string(),
                    priority: ContinuityEntryPriority::Supporting,
                },
            ],
            tool_catalog_ref: "tool-catalog:canonical:v1".to_string(),
            tool_execution_context_ref: "tool-context:storage".to_string(),
            response_schema_family: TurnResponseSchemaFamily::SupervisorTurnV1,
            context_budget: ContextBudgetRecord {
                context_budget_id: "context-budget:storage".to_string(),
                turn_package_ref: "turn-package:storage".to_string(),
                max_rendered_prompt_chars: 5_000,
                max_continuity_entries: 1,
                created_at: "1".to_string(),
            },
            created_at: "1".to_string(),
        }
    }

    fn completed_inference_fixture() -> FixtureInferenceResponse {
        FixtureInferenceResponse {
            fixture_response_id: "fixture:storage-completed".to_string(),
            finish_reason: InferenceFinishReason::Completed,
            http_status: Some(200),
            raw_output_payload: "{\"summary\":\"storage-ok\"}".to_string(),
            parsed_output_json: Some("{\"turn_outcome\":\"storage-ok\"}".to_string()),
            refusal_summary: None,
            provider_response_id: Some("resp-storage".to_string()),
            provider_request_id: Some("req-storage".to_string()),
            provider_metadata_refs: vec![
                "provider-metadata:fixture".to_string(),
                "provider-metadata:model:test".to_string(),
            ],
            input_tokens: 19,
            output_tokens: 7,
            degraded: false,
            degradation_reason: None,
            degradation_summary: None,
            recovery_attempt_refs: Vec::new(),
            transport_error_summary: None,
            latency_ms: 13,
        }
    }

    fn degraded_inference_fixture() -> FixtureInferenceResponse {
        FixtureInferenceResponse {
            fixture_response_id: "fixture:storage-timeout".to_string(),
            finish_reason: InferenceFinishReason::TimedOut,
            http_status: None,
            raw_output_payload: "timeout while waiting for deterministic provider".to_string(),
            parsed_output_json: None,
            refusal_summary: None,
            provider_response_id: None,
            provider_request_id: None,
            provider_metadata_refs: vec![
                "provider-metadata:fixture".to_string(),
                "provider-metadata:model:test".to_string(),
            ],
            input_tokens: 21,
            output_tokens: 0,
            degraded: true,
            degradation_reason: Some(ProviderDegradationReasonClass::Timeout),
            degradation_summary: Some("deterministic provider timed out".to_string()),
            recovery_attempt_refs: vec!["recovery-attempt:timeout-1".to_string()],
            transport_error_summary: Some("timeout".to_string()),
            latency_ms: 25,
        }
    }

    #[test]
    fn llm_interface_bootstrap_creates_directories() {
        let root = temp_store_root("llm-interface-bootstrap");
        let _ = fs::remove_dir_all(&root);
        let _store = DurableArtifactStore::bootstrap(root.clone()).unwrap();

        for relative in [
            "llm-interface/providers",
            "llm-interface/generation-policies",
            "llm-interface/turn-requests",
            "llm-interface/rendered-prompts",
            "llm-interface/tool-catalogs",
            "llm-interface/response-schemas",
            "llm-interface/request-bodies",
            "llm-interface/raw-outputs",
            "llm-interface/usage-records",
            "llm-interface/attempts",
            "llm-interface/provider-outcomes",
            "llm-interface/parsed-outputs",
            "llm-interface/turn-results",
            "llm-interface/degradation-records",
            "llm-interface/turn-packages",
            "llm-interface/context-budgets",
            "llm-interface/context-truncations",
            "llm-interface/prompt-layers",
            "llm-interface/prompt-renderings",
            "llm-interface/turn-response-schemas",
            "llm-interface/parsed-tool-intents",
            "llm-interface/parsed-proposals",
            "llm-interface/parsed-approval-requests",
            "llm-interface/parsed-turn-results",
            "llm-interface/parse-repairs",
        ] {
            assert!(
                root.join(relative).exists(),
                "missing bootstrap directory {relative}"
            );
        }

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn llm_interface_artifacts_round_trip() {
        let root = temp_store_root("llm-interface-round-trip");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(root.clone()).unwrap();

        let provider = inference_provider();
        let policy = inference_generation_policy();
        let request = inference_turn_request();
        let rendered_prompt = inference_rendered_prompt();
        let tool_catalog = inference_tool_catalog();
        let response_schema = inference_response_schema();
        let bundle = execute_inference_turn_with_fixture(
            &provider,
            &policy,
            &request,
            &rendered_prompt,
            &tool_catalog,
            &response_schema,
            &completed_inference_fixture(),
        )
        .await
        .unwrap();

        store
            .persist_inference_provider_registry_entry(&provider)
            .unwrap();
        store.persist_inference_generation_policy(&policy).unwrap();
        store
            .persist_inference_turn_request(&bundle.turn_request)
            .unwrap();
        store
            .persist_inference_rendered_prompt_record(&bundle.rendered_prompt)
            .unwrap();
        store
            .persist_inference_tool_catalog_payload_record(&bundle.tool_catalog)
            .unwrap();
        store
            .persist_inference_response_schema_payload_record(&bundle.response_schema)
            .unwrap();
        for request_body in &bundle.request_body_records {
            store
                .persist_inference_request_body_record(request_body)
                .unwrap();
        }
        for attempt in &bundle.attempts {
            store.persist_inference_attempt_record(attempt).unwrap();
        }
        store
            .persist_inference_raw_output_record(&bundle.raw_output_records[0])
            .unwrap();
        store
            .persist_inference_usage_record(&bundle.usage_record)
            .unwrap();
        store
            .persist_inference_provider_outcome_record(&bundle.provider_outcome)
            .unwrap();
        store
            .persist_inference_parsed_output_record(
                bundle
                    .parsed_output
                    .as_ref()
                    .expect("completed bundle has parsed output"),
            )
            .unwrap();
        store
            .persist_inference_turn_result(&bundle.turn_result)
            .unwrap();

        assert_eq!(
            store
                .load_inference_provider_registry_entry(&provider.provider_id)
                .unwrap(),
            provider
        );
        assert_eq!(
            store
                .load_inference_generation_policy(&policy.generation_policy_id)
                .unwrap(),
            policy
        );
        assert_eq!(
            store
                .load_inference_turn_request(&bundle.turn_request.turn_request_id)
                .unwrap(),
            bundle.turn_request.clone()
        );
        assert_eq!(
            store
                .load_inference_rendered_prompt_record(&bundle.rendered_prompt.rendered_prompt_id)
                .unwrap(),
            bundle.rendered_prompt.clone()
        );
        assert_eq!(
            store
                .load_inference_tool_catalog_payload_record(&bundle.tool_catalog.tool_catalog_id)
                .unwrap(),
            bundle.tool_catalog.clone()
        );
        assert_eq!(
            store
                .load_inference_response_schema_payload_record(
                    &bundle.response_schema.response_schema_id,
                )
                .unwrap(),
            bundle.response_schema.clone()
        );
        assert_eq!(
            store
                .load_inference_request_body_record(&bundle.request_body_records[0].request_body_id)
                .unwrap(),
            bundle.request_body_records[0].clone()
        );
        assert_eq!(
            store
                .load_inference_attempt_record(&bundle.attempts[0].attempt_id)
                .unwrap(),
            bundle.attempts[0].clone()
        );
        assert_eq!(
            store
                .load_inference_raw_output_record(&bundle.raw_output_records[0].raw_output_id)
                .unwrap(),
            bundle.raw_output_records[0].clone()
        );
        assert_eq!(
            store
                .load_inference_usage_record(&bundle.usage_record.usage_record_id)
                .unwrap(),
            bundle.usage_record.clone()
        );
        assert_eq!(
            store
                .load_inference_provider_outcome_record(
                    &bundle.provider_outcome.provider_outcome_id,
                )
                .unwrap(),
            bundle.provider_outcome.clone()
        );
        assert_eq!(
            store
                .load_inference_parsed_output_record(
                    &bundle
                        .parsed_output
                        .as_ref()
                        .expect("completed bundle has parsed output")
                        .parsed_output_id,
                )
                .unwrap(),
            bundle.parsed_output.clone().unwrap()
        );
        assert_eq!(
            store
                .load_inference_turn_result(&bundle.turn_result.turn_result_id)
                .unwrap(),
            bundle.turn_result.clone()
        );
        assert_eq!(
            store.list_inference_provider_registry_entries().unwrap(),
            vec![provider]
        );
        assert_eq!(
            store.list_inference_turn_results().unwrap(),
            vec![bundle.turn_result.clone()]
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn llm_interface_degraded_artifacts_round_trip() {
        let root = temp_store_root("llm-interface-degraded-round-trip");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(root.clone()).unwrap();

        let provider = inference_provider();
        let policy = inference_generation_policy();
        let request = inference_turn_request();
        let rendered_prompt = inference_rendered_prompt();
        let tool_catalog = inference_tool_catalog();
        let response_schema = inference_response_schema();
        let bundle = execute_inference_turn_with_fixture(
            &provider,
            &policy,
            &request,
            &rendered_prompt,
            &tool_catalog,
            &response_schema,
            &degraded_inference_fixture(),
        )
        .await
        .unwrap();

        store
            .persist_inference_provider_registry_entry(&provider)
            .unwrap();
        store.persist_inference_generation_policy(&policy).unwrap();
        store
            .persist_inference_turn_request(&bundle.turn_request)
            .unwrap();
        store
            .persist_inference_rendered_prompt_record(&bundle.rendered_prompt)
            .unwrap();
        store
            .persist_inference_tool_catalog_payload_record(&bundle.tool_catalog)
            .unwrap();
        store
            .persist_inference_response_schema_payload_record(&bundle.response_schema)
            .unwrap();
        for request_body in &bundle.request_body_records {
            store
                .persist_inference_request_body_record(request_body)
                .unwrap();
        }
        for attempt in &bundle.attempts {
            store.persist_inference_attempt_record(attempt).unwrap();
        }
        store
            .persist_inference_raw_output_record(&bundle.raw_output_records[0])
            .unwrap();
        store
            .persist_inference_usage_record(&bundle.usage_record)
            .unwrap();
        store
            .persist_inference_provider_outcome_record(&bundle.provider_outcome)
            .unwrap();
        store
            .persist_inference_turn_result(&bundle.turn_result)
            .unwrap();
        store
            .persist_provider_degradation_record(
                bundle
                    .degradation_record
                    .as_ref()
                    .expect("expected degradation record"),
            )
            .unwrap();

        assert_eq!(
            store
                .load_inference_turn_result(&bundle.turn_result.turn_result_id)
                .unwrap(),
            bundle.turn_result.clone()
        );
        assert_eq!(
            store
                .load_inference_request_body_record(&bundle.request_body_records[0].request_body_id)
                .unwrap(),
            bundle.request_body_records[0].clone()
        );
        assert_eq!(
            store
                .load_inference_attempt_record(&bundle.attempts[0].attempt_id)
                .unwrap(),
            bundle.attempts[0].clone()
        );
        assert_eq!(
            store
                .load_inference_provider_outcome_record(
                    &bundle.provider_outcome.provider_outcome_id,
                )
                .unwrap(),
            bundle.provider_outcome.clone()
        );
        assert_eq!(
            store
                .load_provider_degradation_record(
                    &bundle.degradation_record.as_ref().unwrap().degradation_id,
                )
                .unwrap(),
            bundle.degradation_record.unwrap()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn llm_interface_turn_package_artifacts_round_trip() {
        let root = temp_store_root("llm-interface-turn-package-round-trip");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(root.clone()).unwrap();

        let turn_package = supervisor_turn_package();
        let render_bundle = render_turn_package(&turn_package).unwrap();
        let provider = inference_provider();
        let policy = inference_generation_policy();
        let request = inference_turn_request();
        let rendered_prompt = inference_rendered_prompt();
        let tool_catalog = inference_tool_catalog();
        let response_schema = inference_response_schema();
        let completed_fixture = FixtureInferenceResponse {
            fixture_response_id: "fixture:turn-package".to_string(),
            finish_reason: InferenceFinishReason::Completed,
            http_status: Some(200),
            raw_output_payload: serde_json::json!({
                "output_parsed": {
                    "summary": "bounded supervisor result",
                    "proposals": [
                        {
                            "proposal_family": "task_update",
                            "summary": "advance the bounded task"
                        }
                    ],
                    "stop_recommendation": "continue"
                },
                "usage": {"input_tokens": 12, "output_tokens": 8, "total_tokens": 20}
            })
            .to_string(),
            parsed_output_json: Some(
                serde_json::json!({
                    "summary": "bounded supervisor result",
                    "proposals": [
                        {
                            "proposal_family": "task_update",
                            "summary": "advance the bounded task"
                        }
                    ],
                    "stop_recommendation": "continue"
                })
                .to_string(),
            ),
            refusal_summary: None,
            provider_response_id: Some("provider-response:1".to_string()),
            provider_request_id: Some("provider-request:1".to_string()),
            provider_metadata_refs: vec!["provider-metadata:fixture".to_string()],
            input_tokens: 12,
            output_tokens: 8,
            degraded: false,
            degradation_reason: None,
            degradation_summary: None,
            recovery_attempt_refs: Vec::new(),
            transport_error_summary: None,
            latency_ms: 18,
        };
        let inference_bundle = execute_inference_turn_with_fixture(
            &provider,
            &policy,
            &request,
            &rendered_prompt,
            &tool_catalog,
            &response_schema,
            &completed_fixture,
        )
        .await
        .unwrap();
        let parsed_bundle = parse_turn_package_output(
            &turn_package,
            &inference_bundle.turn_result,
            inference_bundle.parsed_output.as_ref(),
        )
        .unwrap();

        store.persist_turn_package(&turn_package).unwrap();
        store
            .persist_context_budget_record(&turn_package.context_budget)
            .unwrap();
        store
            .persist_context_truncation_record(&render_bundle.truncation)
            .unwrap();
        for layer in &render_bundle.prompt_layers {
            store.persist_prompt_layer_record(layer).unwrap();
        }
        store
            .persist_turn_response_schema_record(&render_bundle.response_schema)
            .unwrap();
        store
            .persist_prompt_rendering_record(&render_bundle.rendering)
            .unwrap();

        store
            .persist_inference_provider_registry_entry(&provider)
            .unwrap();
        store.persist_inference_generation_policy(&policy).unwrap();
        store
            .persist_inference_turn_request(&inference_bundle.turn_request)
            .unwrap();
        store
            .persist_inference_rendered_prompt_record(&inference_bundle.rendered_prompt)
            .unwrap();
        store
            .persist_inference_tool_catalog_payload_record(&inference_bundle.tool_catalog)
            .unwrap();
        store
            .persist_inference_response_schema_payload_record(&inference_bundle.response_schema)
            .unwrap();
        for request_body in &inference_bundle.request_body_records {
            store
                .persist_inference_request_body_record(request_body)
                .unwrap();
        }
        for raw_output in &inference_bundle.raw_output_records {
            store
                .persist_inference_raw_output_record(raw_output)
                .unwrap();
        }
        for attempt in &inference_bundle.attempts {
            store.persist_inference_attempt_record(attempt).unwrap();
        }
        store
            .persist_inference_usage_record(&inference_bundle.usage_record)
            .unwrap();
        store
            .persist_inference_provider_outcome_record(&inference_bundle.provider_outcome)
            .unwrap();
        store
            .persist_inference_parsed_output_record(
                inference_bundle.parsed_output.as_ref().unwrap(),
            )
            .unwrap();
        store
            .persist_inference_turn_result(&inference_bundle.turn_result)
            .unwrap();

        for record in &parsed_bundle.parsed_tool_call_intents {
            store
                .persist_parsed_tool_call_intent_record(record)
                .unwrap();
        }
        for record in &parsed_bundle.parsed_proposals {
            store.persist_parsed_proposal_record(record).unwrap();
        }
        if let Some(record) = &parsed_bundle.parsed_approval_request {
            store
                .persist_parsed_approval_request_record(record)
                .unwrap();
        }
        for record in &parsed_bundle.repair_records {
            store.persist_parse_repair_record(record).unwrap();
        }
        store
            .persist_parsed_turn_result(&parsed_bundle.parsed_result)
            .unwrap();

        assert_eq!(
            store
                .load_turn_package(&turn_package.turn_package_id)
                .unwrap(),
            turn_package
        );
        assert_eq!(
            store
                .load_prompt_rendering_record(&render_bundle.rendering.prompt_rendering_id)
                .unwrap(),
            render_bundle.rendering
        );
        assert_eq!(
            store
                .load_parsed_turn_result(&parsed_bundle.parsed_result.parsed_turn_result_id)
                .unwrap(),
            parsed_bundle.parsed_result
        );
        assert_eq!(store.list_turn_packages().unwrap().len(), 1);
        assert_eq!(store.list_parsed_turn_results().unwrap().len(), 1);

        let copied = temp_store_root("llm-interface-turn-package-round-trip-reload");
        let _ = fs::remove_dir_all(&copied);
        copy_dir_all(&root, &copied).unwrap();
        let reloaded = DurableArtifactStore::bootstrap(copied.clone()).unwrap();
        assert_eq!(reloaded.list_turn_packages().unwrap().len(), 1);
        assert_eq!(reloaded.list_parsed_turn_results().unwrap().len(), 1);

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(copied);
    }

    #[tokio::test]
    async fn llm_interface_rejected_contract_artifacts_round_trip() {
        let root = temp_store_root("llm-interface-rejected-contract-round-trip");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(root.clone()).unwrap();

        let turn_package = supervisor_turn_package();
        let render_bundle = render_turn_package(&turn_package).unwrap();
        let provider = inference_provider();
        let policy = inference_generation_policy();
        let request = inference_turn_request();
        let rendered_prompt = inference_rendered_prompt();
        let tool_catalog = inference_tool_catalog();
        let response_schema = inference_response_schema();
        let rejected_fixture = FixtureInferenceResponse {
            fixture_response_id: "fixture:rejected-contract".to_string(),
            finish_reason: InferenceFinishReason::Completed,
            http_status: Some(200),
            raw_output_payload: serde_json::json!({
                "output_parsed": {"summary": "missing required supervisor fields"},
                "usage": {"input_tokens": 4, "output_tokens": 2, "total_tokens": 6}
            })
            .to_string(),
            parsed_output_json: Some(
                serde_json::json!({
                    "summary": "missing required supervisor fields"
                })
                .to_string(),
            ),
            refusal_summary: None,
            provider_response_id: Some("provider-response:2".to_string()),
            provider_request_id: Some("provider-request:2".to_string()),
            provider_metadata_refs: vec!["provider-metadata:fixture".to_string()],
            input_tokens: 4,
            output_tokens: 2,
            degraded: false,
            degradation_reason: None,
            degradation_summary: None,
            recovery_attempt_refs: Vec::new(),
            transport_error_summary: None,
            latency_ms: 9,
        };
        let inference_bundle = execute_inference_turn_with_fixture(
            &provider,
            &policy,
            &request,
            &rendered_prompt,
            &tool_catalog,
            &response_schema,
            &rejected_fixture,
        )
        .await
        .unwrap();
        let parsed_bundle = parse_turn_package_output(
            &turn_package,
            &inference_bundle.turn_result,
            inference_bundle.parsed_output.as_ref(),
        )
        .unwrap();

        store.persist_turn_package(&turn_package).unwrap();
        store
            .persist_context_budget_record(&turn_package.context_budget)
            .unwrap();
        store
            .persist_context_truncation_record(&render_bundle.truncation)
            .unwrap();
        for layer in &render_bundle.prompt_layers {
            store.persist_prompt_layer_record(layer).unwrap();
        }
        store
            .persist_turn_response_schema_record(&render_bundle.response_schema)
            .unwrap();
        store
            .persist_prompt_rendering_record(&render_bundle.rendering)
            .unwrap();
        store
            .persist_inference_provider_registry_entry(&provider)
            .unwrap();
        store.persist_inference_generation_policy(&policy).unwrap();
        store
            .persist_inference_turn_request(&inference_bundle.turn_request)
            .unwrap();
        store
            .persist_inference_rendered_prompt_record(&inference_bundle.rendered_prompt)
            .unwrap();
        store
            .persist_inference_tool_catalog_payload_record(&inference_bundle.tool_catalog)
            .unwrap();
        store
            .persist_inference_response_schema_payload_record(&inference_bundle.response_schema)
            .unwrap();
        for request_body in &inference_bundle.request_body_records {
            store
                .persist_inference_request_body_record(request_body)
                .unwrap();
        }
        for raw_output in &inference_bundle.raw_output_records {
            store
                .persist_inference_raw_output_record(raw_output)
                .unwrap();
        }
        for attempt in &inference_bundle.attempts {
            store.persist_inference_attempt_record(attempt).unwrap();
        }
        store
            .persist_inference_usage_record(&inference_bundle.usage_record)
            .unwrap();
        store
            .persist_inference_provider_outcome_record(&inference_bundle.provider_outcome)
            .unwrap();
        store
            .persist_inference_parsed_output_record(
                inference_bundle.parsed_output.as_ref().unwrap(),
            )
            .unwrap();
        store
            .persist_inference_turn_result(&inference_bundle.turn_result)
            .unwrap();
        for record in &parsed_bundle.repair_records {
            store.persist_parse_repair_record(record).unwrap();
        }
        store
            .persist_parsed_turn_result(&parsed_bundle.parsed_result)
            .unwrap();

        let loaded = store
            .load_parsed_turn_result(&parsed_bundle.parsed_result.parsed_turn_result_id)
            .unwrap();
        assert_eq!(
            loaded.status,
            crate::execution::ParsedTurnResultStatus::RejectedContract
        );
        assert!(loaded.parsed_proposal_refs.is_empty());
        assert!(loaded.stop_recommendation.is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn northstar_02_expiry_and_escalation_records_round_trip() {
        let root = temp_store_root("northstar-02-expiry-escalation");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(root.clone()).unwrap();

        let expiry = crate::execution::LeaseExpiryRecord {
            expiry_id: "expiry-1".to_string(),
            lease_ref: "lease-1".to_string(),
            continuity_ref: "continuity-1".to_string(),
            tick_ref: "tick-1".to_string(),
            expiry_policy_ref: "policy:expiry".to_string(),
            outcome_ref: "outcome:expired".to_string(),
            summary: "approval lease expired under bounded shell policy".to_string(),
        };
        let escalation = crate::execution::ShellEscalationRecord {
            escalation_id: "escalation-1".to_string(),
            source_ref: "approval-1".to_string(),
            campaign_ref: "campaign-1".to_string(),
            policy_ref: "policy:authority-escalation".to_string(),
            trigger_ref: "trigger:approval-timeout".to_string(),
            outcome_ref: "outcome:paused".to_string(),
            summary: "approval escalation paused the shell-owned program".to_string(),
        };

        store.persist_lease_expiry_record(&expiry).unwrap();
        store.persist_shell_escalation_record(&escalation).unwrap();

        assert_eq!(
            store.load_lease_expiry_record(&expiry.expiry_id).unwrap(),
            expiry
        );
        assert_eq!(
            store
                .load_shell_escalation_record(&escalation.escalation_id)
                .unwrap(),
            escalation
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn northstar_03_04_and_phase02_closure_records_round_trip() {
        let root = temp_store_root("northstar-03-04-phase02");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(root.clone()).unwrap();

        let sufficiency = crate::execution::WorkflowSufficiencyRecord {
            workflow_sufficiency_id: "workflow-sufficiency-build".to_string(),
            workflow_kind: crate::execution::NativeWorkflowKind::Build,
            required_service_refs: vec!["manifest:build".to_string()],
            present_service_refs: vec!["manifest:build".to_string()],
            transitional_gap_refs: Vec::new(),
            closure_status: crate::execution::WorkflowClosureStatus::ClosureGrade,
            supporting_run_refs: vec!["run:phase-b".to_string()],
            summary: "build workflow closed".to_string(),
        };
        let workflow_dossier = crate::execution::WorkflowServiceClosureDossier {
            workflow_dossier_id: "workflow-dossier-build".to_string(),
            workflow_kind: crate::execution::NativeWorkflowKind::Build,
            required_service_refs: vec!["manifest:build".to_string()],
            service_handle_refs: vec!["handle:build".to_string()],
            attestation_refs: vec!["attestation:build".to_string()],
            transitional_gap_refs: Vec::new(),
            closure_status: crate::execution::WorkflowClosureStatus::ClosureGrade,
            claim_boundary: "bounded build workflow closure".to_string(),
            summary: "build workflow dossier".to_string(),
        };
        let routing = crate::execution::RoutingPacketRecord {
            routing_packet_id: "routing-packet-1".to_string(),
            agenda_ref: "agenda:1".to_string(),
            worker_selection_refs: vec!["worker:planner".to_string()],
            synthesis_ref: "synthesis:1".to_string(),
            quality_ref: "quality:accepted".to_string(),
            fallback_ref: "fallback:reviewer".to_string(),
            summary: "routing explicit".to_string(),
        };
        let recovery = crate::execution::EcologyRecoveryRecord {
            recovery_id: "recovery-1".to_string(),
            ecology_snapshot_ref: "snapshot:1".to_string(),
            trigger_refs: vec!["trigger:degradation".to_string()],
            reroute_refs: vec!["reroute:validator".to_string()],
            rollback_refs: vec!["rollback:1".to_string()],
            outcome_ref: "outcome:stable".to_string(),
            summary: "recovery explicit".to_string(),
        };
        let service_workspace = crate::execution::ServiceClosureWorkspacePacket {
            service_workspace_id: "service-workspace-1".to_string(),
            workflow_sufficiency_refs: vec![sufficiency.workflow_sufficiency_id.clone()],
            workflow_dossier_refs: vec![workflow_dossier.workflow_dossier_id.clone()],
            attestation_refs: vec!["attestation:build".to_string()],
            transitional_gap_refs: Vec::new(),
            operator_summary_ref: "operator:phase02:service".to_string(),
        };
        let ecology_workspace = crate::execution::EcologyClosureWorkspacePacket {
            ecology_workspace_id: "ecology-workspace-1".to_string(),
            worker_card_refs: vec!["worker:planner".to_string()],
            ecology_ledger_refs: vec!["health:1".to_string(), "synthesis:1".to_string()],
            routing_packet_refs: vec![routing.routing_packet_id.clone()],
            degradation_refs: vec!["degradation:none".to_string()],
            operator_summary_ref: "operator:phase02:ecology".to_string(),
        };
        let acceptance = crate::execution::Phase02AcceptancePacket {
            acceptance_packet_id: "phase02-acceptance-1".to_string(),
            workflow_refs: vec![sufficiency.workflow_sufficiency_id.clone()],
            closure_refs: vec![
                workflow_dossier.workflow_dossier_id.clone(),
                service_workspace.service_workspace_id.clone(),
            ],
            ecology_refs: vec![
                routing.routing_packet_id.clone(),
                recovery.recovery_id.clone(),
                ecology_workspace.ecology_workspace_id.clone(),
            ],
            attestation_refs: vec!["attestation:build".to_string()],
            summary: "phase 02 accepted".to_string(),
        };

        store
            .persist_workflow_sufficiency_record(&sufficiency)
            .unwrap();
        store
            .persist_workflow_service_closure_dossier(&workflow_dossier)
            .unwrap();
        store.persist_routing_packet_record(&routing).unwrap();
        store.persist_ecology_recovery_record(&recovery).unwrap();
        store
            .persist_service_closure_workspace_packet(&service_workspace)
            .unwrap();
        store
            .persist_ecology_closure_workspace_packet(&ecology_workspace)
            .unwrap();
        store
            .persist_phase02_acceptance_packet(&acceptance)
            .unwrap();

        assert_eq!(
            store
                .load_workflow_sufficiency_record(&sufficiency.workflow_sufficiency_id)
                .unwrap(),
            sufficiency
        );
        assert_eq!(
            store
                .load_workflow_service_closure_dossier(&workflow_dossier.workflow_dossier_id)
                .unwrap(),
            workflow_dossier
        );
        assert_eq!(
            store
                .load_routing_packet_record(&routing.routing_packet_id)
                .unwrap(),
            routing
        );
        assert_eq!(
            store
                .load_ecology_recovery_record(&recovery.recovery_id)
                .unwrap(),
            recovery
        );
        assert_eq!(
            store
                .load_service_closure_workspace_packet(&service_workspace.service_workspace_id)
                .unwrap(),
            service_workspace
        );
        assert_eq!(
            store
                .load_ecology_closure_workspace_packet(&ecology_workspace.ecology_workspace_id)
                .unwrap(),
            ecology_workspace
        );
        assert_eq!(
            store
                .load_phase02_acceptance_packet(&acceptance.acceptance_packet_id)
                .unwrap(),
            acceptance
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn northstar_05_06_and_phase03_closure_records_round_trip() {
        let root = temp_store_root("northstar-05-06-phase03");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(root.clone()).unwrap();

        let recurring = crate::execution::RecurringFactoryProgramRecord {
            factory_program_id: "recurring-program-1".to_string(),
            bounded_program_refs: vec!["program:bounded".to_string()],
            incumbent_factory_ref: "factory:incumbent".to_string(),
            cycle_refs: vec!["cycle:a".to_string(), "cycle:b".to_string()],
            continuity_window_refs: vec![
                "continuity-window:a".to_string(),
                "continuity-window:b".to_string(),
            ],
            budget_ref: "budget:1".to_string(),
            budget_history_ref: "budget-history:1".to_string(),
            policy_ref: "policy:stop".to_string(),
            policy_compliance_ref: "policy-compliance:1".to_string(),
            restart_resume_refs: vec![
                "resume-chain:cycle:a".to_string(),
                "resume-chain:cycle:b".to_string(),
            ],
            summary_ref: "summary:phase03".to_string(),
        };
        let continuity = crate::execution::ProgramContinuityWindowRecord {
            continuity_window_id: "continuity-window:a".to_string(),
            program_ref: recurring.factory_program_id.clone(),
            preceding_ref: "anchor:program".to_string(),
            succeeding_ref: "cycle:a".to_string(),
            carry_forward_refs: vec!["carry:a".to_string()],
            restart_resume_refs: vec!["resume-chain:cycle:a".to_string()],
            summary: "continuity".to_string(),
        };
        let budget_history = crate::execution::ProgramBudgetHistoryRecord {
            budget_history_id: recurring.budget_history_ref.clone(),
            program_ref: recurring.factory_program_id.clone(),
            budget_ref: recurring.budget_ref.clone(),
            cycle_refs: recurring.cycle_refs.clone(),
            consumption_refs: vec![
                "budget-consumption:a".to_string(),
                "budget-consumption:b".to_string(),
            ],
            exhaustion_posture_ref: "budget-posture:headroom".to_string(),
            summary: "budget history".to_string(),
        };
        let policy_compliance = crate::execution::ProgramPolicyComplianceRecord {
            policy_compliance_id: recurring.policy_compliance_ref.clone(),
            program_ref: recurring.factory_program_id.clone(),
            policy_ref: recurring.policy_ref.clone(),
            cycle_refs: recurring.cycle_refs.clone(),
            compliance_refs: vec![
                "policy-compliance:a".to_string(),
                "policy-compliance:b".to_string(),
            ],
            variance_refs: vec!["variance:none".to_string()],
            summary: "policy compliance".to_string(),
        };
        let cycle = crate::execution::LaterFactoryCycleDossier {
            cycle_dossier_id: "cycle:a".to_string(),
            program_ref: recurring.factory_program_id.clone(),
            generation_agenda_ref: "agenda:a".to_string(),
            adoption_window_ref: "window:a".to_string(),
            candidate_factory_ref: "factory:candidate".to_string(),
            proving_refs: vec!["proving:a".to_string()],
            observation_refs: vec!["observation:a".to_string()],
            rollback_posture_refs: vec!["rollback:a".to_string()],
            continuity_ref: continuity.continuity_window_id.clone(),
            disposition_ref: "disposition:a".to_string(),
            lineage_delta_ref: "lineage-delta:a".to_string(),
        };
        let ledger = crate::execution::LineageHealthLedger {
            lineage_ledger_id: "lineage-ledger-1".to_string(),
            program_ref: recurring.factory_program_id.clone(),
            generation_refs: vec!["agenda:a".to_string(), "agenda:b".to_string()],
            cycle_result_refs: vec!["disposition:a".to_string(), "disposition:b".to_string()],
            continuity_refs: recurring.continuity_window_refs.clone(),
            regression_refs: vec!["trigger:drift".to_string()],
            rollback_refs: vec!["rollback:a".to_string()],
        };
        let regression = crate::execution::RegressionReviewPacket {
            regression_packet_id: "regression-1".to_string(),
            lineage_ledger_ref: ledger.lineage_ledger_id.clone(),
            threshold_refs: vec!["threshold:1".to_string()],
            trigger_refs: vec!["trigger:drift".to_string()],
            mitigation_refs: vec!["rollback:a".to_string()],
            summary: "phase03 regression review".to_string(),
        };
        let longitudinal = crate::execution::LongitudinalLineageDossier {
            lineage_dossier_id: "longitudinal-1".to_string(),
            program_ref: recurring.factory_program_id.clone(),
            health_ref: ledger.lineage_ledger_id.clone(),
            cycle_refs: vec!["cycle:a".to_string(), "cycle:b".to_string()],
            continuity_window_refs: recurring.continuity_window_refs.clone(),
            regression_packet_refs: vec![regression.regression_packet_id.clone()],
            stability_refs: vec![
                budget_history.budget_history_id.clone(),
                policy_compliance.policy_compliance_id.clone(),
            ],
            closure_posture: "closure_grade".to_string(),
        };
        let admission = crate::execution::EcosystemAdmissionProfile {
            admission_profile_id: "admission-profile-1".to_string(),
            factory_ref: "factory:sender".to_string(),
            identity_ref: "identity:sender".to_string(),
            compatibility_ref: "compat:sender".to_string(),
            rollback_obligation_ref: "rollback-obligation:sender".to_string(),
            admission_status: crate::execution::EcosystemAdmissionDecision::Admitted,
        };
        let route = crate::execution::EcosystemExchangeRouteLedger {
            exchange_route_ledger_id: "route-ledger-1".to_string(),
            source_factory_ref: "factory:sender".to_string(),
            target_factory_ref: "factory:receiver".to_string(),
            route_ref: "route:a".to_string(),
            admission_refs: vec![admission.admission_profile_id.clone()],
            exchange_packet_refs: vec!["packet:a".to_string(), "packet:b".to_string()],
            route_history_refs: vec!["route-history-1".to_string(), "route-history-2".to_string()],
            continuity_window_refs: vec!["ecosystem-continuity-1".to_string()],
            adoption_refs: vec!["adoption:a".to_string()],
            quarantine_refs: vec!["quarantine:a".to_string()],
            rollback_refs: vec!["rollback:a".to_string()],
        };
        let route_history_1 = crate::execution::RouteExchangeHistoryRecord {
            route_history_id: "route-history-1".to_string(),
            route_ref: route.route_ref.clone(),
            admission_ref: admission.admission_profile_id.clone(),
            exchange_packet_ref: "packet:a".to_string(),
            adoption_ref: "adoption:a".to_string(),
            quarantine_ref: "quarantine:a".to_string(),
            rollback_ref: "rollback:a".to_string(),
            outcome_ref: "outcome:a".to_string(),
            continuity_ref: "ecosystem-continuity-1".to_string(),
        };
        let route_history_2 = crate::execution::RouteExchangeHistoryRecord {
            route_history_id: "route-history-2".to_string(),
            route_ref: route.route_ref.clone(),
            admission_ref: admission.admission_profile_id.clone(),
            exchange_packet_ref: "packet:b".to_string(),
            adoption_ref: "adoption:b".to_string(),
            quarantine_ref: "quarantine:b".to_string(),
            rollback_ref: "rollback:b".to_string(),
            outcome_ref: "outcome:b".to_string(),
            continuity_ref: "ecosystem-continuity-1".to_string(),
        };
        let ecosystem_continuity = crate::execution::EcosystemContinuityWindowRecord {
            continuity_window_id: "ecosystem-continuity-1".to_string(),
            health_ref: "ecosystem-health-1".to_string(),
            preceding_route_history_ref: route_history_1.route_history_id.clone(),
            succeeding_route_history_ref: route_history_2.route_history_id.clone(),
            carry_forward_refs: vec!["carry-forward:a".to_string()],
            degraded_state_refs: vec!["degraded:a".to_string()],
            resumed_state_refs: vec!["resumed:a".to_string()],
            summary: "ecosystem continuity".to_string(),
        };
        let rollback_symmetry = crate::execution::EcosystemRollbackSymmetryRecord {
            rollback_symmetry_id: "rollback-symmetry-1".to_string(),
            route_ledger_ref: route.exchange_route_ledger_id.clone(),
            adoption_refs: route.adoption_refs.clone(),
            quarantine_refs: route.quarantine_refs.clone(),
            rollback_refs: route.rollback_refs.clone(),
            recovery_refs: vec!["recovery:a".to_string()],
            summary: "rollback symmetry".to_string(),
        };
        let compatibility_persistence = crate::execution::EcosystemCompatibilityPersistenceRecord {
            compatibility_persistence_id: "compatibility-persistence-1".to_string(),
            trust_profile_refs: vec!["trust:a".to_string()],
            route_cycle_refs: vec!["route-cycle:a".to_string()],
            profile_refs: vec!["compatibility:a".to_string()],
            persistence_refs: vec!["persistence:a".to_string()],
            variance_refs: vec!["variance:none".to_string()],
            summary: "compatibility persistence".to_string(),
        };
        let ecosystem_health = crate::execution::EcosystemHealthLedger {
            ecosystem_health_id: "ecosystem-health-1".to_string(),
            admission_refs: vec![admission.admission_profile_id.clone()],
            route_refs: vec![route.exchange_route_ledger_id.clone()],
            continuity_refs: vec![ecosystem_continuity.continuity_window_id.clone()],
            failure_refs: vec!["failure:a".to_string()],
            recovery_refs: vec!["rollback:a".to_string()],
            rollback_symmetry_refs: vec![rollback_symmetry.rollback_symmetry_id.clone()],
            compatibility_persistence_refs: vec![
                compatibility_persistence
                    .compatibility_persistence_id
                    .clone(),
            ],
        };
        let factory_workspace = crate::execution::RecurringFactoryWorkspacePacket {
            factory_workspace_id: "phase03-factory-workspace".to_string(),
            program_ref: recurring.factory_program_id.clone(),
            cycle_refs: recurring.cycle_refs.clone(),
            lineage_refs: vec![
                ledger.lineage_ledger_id.clone(),
                longitudinal.lineage_dossier_id.clone(),
            ],
            budget_ref: recurring.budget_ref.clone(),
            continuity_refs: vec![
                continuity.continuity_window_id.clone(),
                budget_history.budget_history_id.clone(),
                policy_compliance.policy_compliance_id.clone(),
            ],
            stability_refs: vec![
                budget_history.budget_history_id.clone(),
                policy_compliance.policy_compliance_id.clone(),
            ],
            claim_boundary_ref: "claim:phase03:bounded-recurring-factory-program".to_string(),
        };
        let ecosystem_workspace = crate::execution::EcosystemClosureWorkspacePacket {
            ecosystem_workspace_id: "phase03-ecosystem-workspace".to_string(),
            admission_refs: vec![admission.admission_profile_id.clone()],
            route_refs: vec![route.exchange_route_ledger_id.clone()],
            health_refs: vec![ecosystem_health.ecosystem_health_id.clone()],
            rollback_refs: route.rollback_refs.clone(),
            continuity_refs: vec![ecosystem_continuity.continuity_window_id.clone()],
            stability_refs: vec![
                rollback_symmetry.rollback_symmetry_id.clone(),
                compatibility_persistence
                    .compatibility_persistence_id
                    .clone(),
            ],
            claim_boundary_ref: "claim:phase03:bounded-ecosystem".to_string(),
        };
        let review = crate::execution::Phase03ClosureReviewPacket {
            closure_review_packet_id: "phase03-review".to_string(),
            factory_program_refs: vec![recurring.factory_program_id.clone()],
            lineage_refs: vec![longitudinal.lineage_dossier_id.clone()],
            continuity_refs: factory_workspace.continuity_refs.clone(),
            ecosystem_refs: vec![ecosystem_health.ecosystem_health_id.clone()],
            acceptable_caveat_refs: vec![
                "risk:phase03:recurring-program-publication-caveat".to_string(),
                "risk:phase03:bounded-ecosystem-publication-caveat".to_string(),
            ],
            blocking_risk_refs: Vec::new(),
            risk_refs: vec![
                "risk:phase03:recurring-program-publication-caveat".to_string(),
                "risk:phase03:bounded-ecosystem-publication-caveat".to_string(),
            ],
            summary: "phase03 closure review".to_string(),
        };

        store
            .persist_recurring_factory_program_record(&recurring)
            .unwrap();
        store
            .persist_program_continuity_window_record(&continuity)
            .unwrap();
        store
            .persist_program_budget_history_record(&budget_history)
            .unwrap();
        store
            .persist_program_policy_compliance_record(&policy_compliance)
            .unwrap();
        store.persist_later_factory_cycle_dossier(&cycle).unwrap();
        store.persist_lineage_health_ledger(&ledger).unwrap();
        store.persist_regression_review_packet(&regression).unwrap();
        store
            .persist_longitudinal_lineage_dossier(&longitudinal)
            .unwrap();
        store
            .persist_ecosystem_admission_profile(&admission)
            .unwrap();
        store
            .persist_route_exchange_history_record(&route_history_1)
            .unwrap();
        store
            .persist_route_exchange_history_record(&route_history_2)
            .unwrap();
        store
            .persist_ecosystem_exchange_route_ledger(&route)
            .unwrap();
        store
            .persist_ecosystem_continuity_window(&ecosystem_continuity)
            .unwrap();
        store
            .persist_ecosystem_rollback_symmetry_record(&rollback_symmetry)
            .unwrap();
        store
            .persist_ecosystem_compatibility_persistence_record(&compatibility_persistence)
            .unwrap();
        store
            .persist_ecosystem_health_ledger(&ecosystem_health)
            .unwrap();
        store
            .persist_recurring_factory_workspace_packet(&factory_workspace)
            .unwrap();
        store
            .persist_ecosystem_closure_workspace_packet(&ecosystem_workspace)
            .unwrap();
        store
            .persist_phase03_closure_review_packet(&review)
            .unwrap();

        let imported_root = temp_store_root("remediation-phase03-imported");
        let _ = fs::remove_dir_all(&imported_root);
        copy_dir_all(&root, &imported_root).unwrap();
        let imported_store = DurableArtifactStore::bootstrap(imported_root.clone()).unwrap();

        assert_eq!(
            imported_store
                .load_recurring_factory_program_record(&recurring.factory_program_id)
                .unwrap(),
            recurring
        );
        assert_eq!(
            imported_store
                .load_program_continuity_window_record(&continuity.continuity_window_id)
                .unwrap(),
            continuity
        );
        assert_eq!(
            imported_store
                .load_program_budget_history_record(&budget_history.budget_history_id)
                .unwrap(),
            budget_history
        );
        assert_eq!(
            imported_store
                .load_program_policy_compliance_record(&policy_compliance.policy_compliance_id)
                .unwrap(),
            policy_compliance
        );
        assert_eq!(
            imported_store
                .load_later_factory_cycle_dossier(&cycle.cycle_dossier_id)
                .unwrap(),
            cycle
        );
        assert_eq!(
            imported_store
                .load_lineage_health_ledger(&ledger.lineage_ledger_id)
                .unwrap(),
            ledger
        );
        assert_eq!(
            imported_store
                .load_regression_review_packet(&regression.regression_packet_id)
                .unwrap(),
            regression
        );
        assert_eq!(
            imported_store
                .load_longitudinal_lineage_dossier(&longitudinal.lineage_dossier_id)
                .unwrap(),
            longitudinal
        );
        assert_eq!(
            imported_store
                .load_ecosystem_admission_profile(&admission.admission_profile_id)
                .unwrap(),
            admission
        );
        assert_eq!(
            imported_store
                .load_ecosystem_exchange_route_ledger(&route.exchange_route_ledger_id)
                .unwrap(),
            route
        );
        assert_eq!(
            imported_store
                .load_route_exchange_history_record(&route_history_1.route_history_id)
                .unwrap(),
            route_history_1
        );
        assert_eq!(
            imported_store
                .load_route_exchange_history_record(&route_history_2.route_history_id)
                .unwrap(),
            route_history_2
        );
        assert_eq!(
            imported_store
                .load_ecosystem_continuity_window(&ecosystem_continuity.continuity_window_id)
                .unwrap(),
            ecosystem_continuity
        );
        assert_eq!(
            imported_store
                .load_ecosystem_rollback_symmetry_record(&rollback_symmetry.rollback_symmetry_id,)
                .unwrap(),
            rollback_symmetry
        );
        assert_eq!(
            imported_store
                .load_ecosystem_compatibility_persistence_record(
                    &compatibility_persistence.compatibility_persistence_id,
                )
                .unwrap(),
            compatibility_persistence
        );
        assert_eq!(
            imported_store
                .load_ecosystem_health_ledger(&ecosystem_health.ecosystem_health_id)
                .unwrap(),
            ecosystem_health
        );
        assert_eq!(
            imported_store
                .load_recurring_factory_workspace_packet(&factory_workspace.factory_workspace_id)
                .unwrap(),
            factory_workspace
        );
        assert_eq!(
            imported_store
                .load_ecosystem_closure_workspace_packet(
                    &ecosystem_workspace.ecosystem_workspace_id,
                )
                .unwrap(),
            ecosystem_workspace
        );
        assert_eq!(
            imported_store
                .load_phase03_closure_review_packet(&review.closure_review_packet_id)
                .unwrap(),
            review
        );

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(imported_root);
    }

    #[test]
    fn remediated_phase04_closure_review_records_round_trip() {
        let root = temp_store_root("remediation-phase04");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(root.clone()).unwrap();

        let matrix = crate::execution::ClosureCriteriaMatrix {
            criteria_matrix_id: "remediation-phase-04-criteria-matrix".to_string(),
            criterion_refs: vec!["northstar-07-criterion-final-claim".to_string()],
            status: crate::execution::ClosureCriterionStatus::Passed,
            evidence_refs: vec!["evidence:bounded-local-first-positive-closure".to_string()],
            phase_evidence_refs: vec!["phase03:closure".to_string()],
            delta_crosswalk_refs: vec!["delta:final-claim".to_string()],
            gap_refs: Vec::new(),
            review_status: "remediated_current_review".to_string(),
        };
        let inventory = crate::execution::EvidenceInventoryPacket {
            inventory_packet_id: "remediation-phase-04-evidence-inventory".to_string(),
            northstar_refs: vec!["northstar:bounded".to_string()],
            operator_refs: vec!["operator:post-v4".to_string()],
            risk_refs: vec![
                "remediation-phase-04-risk-final-claim-boundedness".to_string(),
                "remediation-phase-04-risk-publication-overclaim".to_string(),
            ],
            phase_01_refs: vec!["phase01:closure".to_string()],
            phase_02_refs: vec!["phase02:closure".to_string()],
            phase_03_refs: vec!["phase03:closure".to_string()],
            phase_04_refs: vec!["phase04:decision".to_string()],
            summary: "phase04 evidence inventory".to_string(),
        };
        let adversarial = crate::execution::AdversarialReviewRecord {
            adversarial_review_id: "remediation-phase-04-adversarial-review".to_string(),
            scenario_refs: vec!["scenario:phase04".to_string()],
            criterion_refs: vec!["northstar-07-criterion-final-claim".to_string()],
            criteria_matrix_ref: matrix.criteria_matrix_id.clone(),
            failure_refs: vec!["risk:phase03:bounded-ecosystem-publication-caveat".to_string()],
            counter_evidence_refs: vec!["counter:bounded-local-first-closure".to_string()],
            risk_refs: inventory.risk_refs.clone(),
            challenge_outcome_refs: vec!["remediation-phase-04-final-decision".to_string()],
            recommendation_ref: "remediation-phase-04-final-decision".to_string(),
            summary: "phase04 adversarial rereview".to_string(),
        };
        let claim_catalog = crate::execution::ActiveTruthClaimCatalogV1::bounded_local_first()
            .expect("active truth claim catalog");
        let claim_boundary = crate::execution::ClaimBoundaryReviewPacket {
            claim_review_id: "remediation-phase-04-claim-boundary".to_string(),
            claim_catalog: claim_catalog.clone(),
            allowed_claims: claim_catalog.allowed_claim_statements(),
            forbidden_claims: claim_catalog.forbidden_claim_statements(),
            caveat_refs: Vec::new(),
            supporting_refs: vec![matrix.criteria_matrix_id.clone()],
            supporting_evidence_refs: vec![
                "evidence:bounded-local-first-positive-closure".to_string(),
            ],
            counter_evidence_refs: adversarial.counter_evidence_refs.clone(),
            publication_risk_refs: vec![
                "remediation-phase-04-risk-publication-overclaim".to_string(),
            ],
        };
        let dossier = crate::execution::ClosureDossier {
            closure_dossier_id: "remediation-phase-04-closure-dossier".to_string(),
            criteria_matrix_ref: matrix.criteria_matrix_id.clone(),
            inventory_ref: inventory.inventory_packet_id.clone(),
            adversarial_review_ref: adversarial.adversarial_review_id.clone(),
            claim_boundary_ref: claim_boundary.claim_review_id.clone(),
            risk_refs: inventory.risk_refs.clone(),
            recommendation_ref: "remediation-phase-04-final-decision".to_string(),
        };
        let policy = crate::execution::PublicationPolicyRecord {
            publication_policy_id: "remediation-phase-04-publication-policy".to_string(),
            claim_catalog: claim_catalog.clone(),
            publication_controls: crate::execution::active_truth_publication_controls(),
            allowed_claims: claim_boundary.allowed_claims.clone(),
            required_caveats: crate::execution::active_truth_required_publication_caveats()
                .into_iter()
                .collect(),
            forbidden_claims: claim_boundary.forbidden_claims.clone(),
            source_refs: vec![
                matrix.criteria_matrix_id.clone(),
                dossier.closure_dossier_id.clone(),
            ],
            audience_note: "Public reporting may state only that the archived Phase 04 record-completeness lineage decision is Closed. It must separately report the current operational North Star decision as NotYet and retain every bounded/local-first caveat."
                .to_string(),
        };
        let decision = crate::execution::ClosureDecisionRecord {
            closure_decision_id: "remediation-phase-04-final-decision".to_string(),
            decision: crate::execution::NorthStarClosureDecision::Closed,
            rationale: "The faithful historical record-completeness rereview supports an archived Closed lineage decision; it is not a current operational North Star closure, which remains NotYet."
                .to_string(),
            required_followups: vec![
                "followup:keep-phase04-closed-labelled-historical-lineage".to_string(),
                "followup:retain-operational-not-yet-until-m7-evidence-closes".to_string(),
            ],
            publication_policy_ref: policy.publication_policy_id.clone(),
            supersedes_ref: "northstar-07-closure-decision".to_string(),
        };

        store.persist_closure_criteria_matrix(&matrix).unwrap();
        store.persist_evidence_inventory_packet(&inventory).unwrap();
        store
            .persist_adversarial_review_record(&adversarial)
            .unwrap();
        store
            .persist_claim_boundary_review_packet(&claim_boundary)
            .unwrap();
        store.persist_closure_dossier(&dossier).unwrap();
        store.persist_publication_policy_record(&policy).unwrap();
        store.persist_closure_decision_record(&decision).unwrap();

        let imported_root = temp_store_root("remediation-phase04-imported");
        let _ = fs::remove_dir_all(&imported_root);
        copy_dir_all(&root, &imported_root).unwrap();
        let imported_store = DurableArtifactStore::bootstrap(imported_root.clone()).unwrap();

        assert_eq!(
            imported_store
                .load_closure_criteria_matrix(&matrix.criteria_matrix_id)
                .unwrap(),
            matrix
        );
        assert_eq!(
            imported_store
                .load_evidence_inventory_packet(&inventory.inventory_packet_id)
                .unwrap(),
            inventory
        );
        assert_eq!(
            imported_store
                .load_adversarial_review_record(&adversarial.adversarial_review_id)
                .unwrap(),
            adversarial
        );
        assert_eq!(
            imported_store
                .load_claim_boundary_review_packet(&claim_boundary.claim_review_id)
                .unwrap(),
            claim_boundary
        );
        assert_eq!(
            imported_store
                .load_closure_dossier(&dossier.closure_dossier_id)
                .unwrap(),
            dossier
        );
        assert_eq!(
            imported_store
                .load_publication_policy_record(&policy.publication_policy_id)
                .unwrap(),
            policy
        );
        assert_eq!(
            imported_store
                .load_closure_decision_record(&decision.closure_decision_id)
                .unwrap(),
            decision
        );

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(imported_root);
    }

    fn runtime_state_with_rollback_evidence() -> ReplayableRuntimeState {
        let mut runtime_state = runtime_state();
        let checkpoint = runtime_state
            .latest_checkpoint
            .clone()
            .expect("runtime_state should include a checkpoint");
        runtime_state.memory_store.persist_checkpoint_artifact(
            "memory-checkpoint-1",
            checkpoint.clone(),
            "checkpoint persisted for rollback reconstruction",
        );
        runtime_state
            .memory_store
            .append(MemoryArtifact::audit_record(
                "memory-audit-checkpoint-1",
                AuditRecord::new(
                    "audit-checkpoint-1",
                    AuditRecordClass::GovernanceAuditRecord,
                    checkpoint.session_header.campaign_id.clone(),
                    checkpoint.session_header.epoch_id.clone(),
                    checkpoint.session_header.session_id.clone(),
                    checkpoint.active_task_refs.first().cloned(),
                    checkpoint.checkpoint_id.clone(),
                    "checkpoint lineage recorded for rollback",
                ),
            ));
        runtime_state
            .memory_store
            .append(MemoryArtifact::audit_record(
                "memory-audit-rollback-1",
                AuditRecord::new(
                    "audit-rollback-1",
                    AuditRecordClass::PromotionAuditRecord,
                    checkpoint.session_header.campaign_id.clone(),
                    checkpoint.session_header.epoch_id.clone(),
                    checkpoint.session_header.session_id.clone(),
                    checkpoint.active_task_refs.first().cloned(),
                    "rollback-1",
                    "rollback handle remained reconstructable",
                ),
            ));
        runtime_state
    }

    fn sanitize_id(value: &str) -> String {
        value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character
                } else {
                    '-'
                }
            })
            .collect()
    }

    fn append_control_audit(
        runtime_state: &mut ReplayableRuntimeState,
        related_ref: &str,
        class: AuditRecordClass,
        summary: &str,
    ) {
        let artifact_id = format!("memory-audit-{}", sanitize_id(related_ref));
        let audit_record_id = format!("audit-{}", sanitize_id(related_ref));
        runtime_state
            .memory_store
            .append(MemoryArtifact::audit_record(
                artifact_id,
                AuditRecord::new(
                    audit_record_id,
                    class,
                    runtime_state.session.header.campaign_id.clone(),
                    runtime_state.session.header.epoch_id.clone(),
                    runtime_state.session.header.session_id.clone(),
                    runtime_state.session.active_task_id.clone(),
                    related_ref.to_string(),
                    summary.to_string(),
                ),
            ));
    }

    fn append_review_artifact(runtime_state: &mut ReplayableRuntimeState, review_ref: &str) {
        append_control_audit(
            runtime_state,
            review_ref,
            AuditRecordClass::GovernanceAuditRecord,
            "operator review bundle remained reconstructable",
        );
    }

    fn append_v14_program_evidence(
        runtime_state: &mut ReplayableRuntimeState,
        label: &str,
        review_artifact_refs: &[String],
    ) {
        let campaign_id = runtime_state.session.header.campaign_id.clone();
        let epoch_id = runtime_state.session.header.epoch_id.clone();
        let session_id = runtime_state.session.header.session_id.clone();
        let task_id = runtime_state.root_task.task_id.clone();

        let portfolio_ref = format!("portfolio:{label}");
        let budget_ref = format!("budget:{label}");
        let intervention_ref = format!("intervention:{label}");
        runtime_state.memory_store.add_topic_bundle(TopicBundle {
            bundle_id: portfolio_ref.clone(),
            bundle_class: TopicBundleClass::CampaignOperatingNotes,
            scope: MemoryScope::Campaign(campaign_id.clone()),
            summary: "campaign portfolio and budget continuity remained reconstructable"
                .to_string(),
            evidence_refs: vec![
                portfolio_ref.clone(),
                budget_ref.clone(),
                intervention_ref.clone(),
            ],
            freshness_policy: "retain-until-program-close".to_string(),
        });

        let review_bundle_ref = format!("review:{label}");
        let canary_ref = format!("canary:{label}");
        let release_ref = format!("release:{label}");
        let rejection_ref = format!("rejection:{label}");
        let mut review_evidence_refs = review_artifact_refs.to_vec();
        review_evidence_refs.extend([
            review_bundle_ref.clone(),
            canary_ref.clone(),
            release_ref.clone(),
            rejection_ref.clone(),
        ]);
        runtime_state.memory_store.add_topic_bundle(TopicBundle {
            bundle_id: review_bundle_ref.clone(),
            bundle_class: TopicBundleClass::GovernanceNotes,
            scope: MemoryScope::Campaign(campaign_id.clone()),
            summary: "review, canary, release, and rejection evidence remained reconstructable"
                .to_string(),
            evidence_refs: review_evidence_refs,
            freshness_policy: "retain-until-adoption-close".to_string(),
        });

        let program_memory_ref = format!("program-memory:{label}");
        let plan_ref = format!("plan-carry-forward:{label}");
        let reprioritization_ref = format!("reprioritization:{label}");
        runtime_state.memory_store.add_topic_bundle(TopicBundle {
            bundle_id: program_memory_ref.clone(),
            bundle_class: TopicBundleClass::CampaignOperatingNotes,
            scope: MemoryScope::Campaign(campaign_id.clone()),
            summary: "program memory continuity remained reconstructable".to_string(),
            evidence_refs: vec![
                program_memory_ref.clone(),
                plan_ref.clone(),
                reprioritization_ref.clone(),
            ],
            freshness_policy: "carry-forward-across-cycles".to_string(),
        });
        runtime_state
            .memory_store
            .add_transcript_slice(TranscriptSlice {
                slice_id: format!("program-transcript:{label}"),
                campaign_id: campaign_id.clone(),
                epoch_id: epoch_id.clone(),
                session_id: Some(session_id.clone()),
                task_id: Some(task_id.clone()),
                referenced_artifacts: vec![
                    review_bundle_ref.clone(),
                    plan_ref.clone(),
                    reprioritization_ref.clone(),
                ],
                summary: "carry-forward and reprioritization remained transcript-backed"
                    .to_string(),
                excerpts: vec!["reprioritized under bounded review load".to_string()],
            });

        let contention_ref = format!("contention:{label}");
        let fairness_ref = format!("fairness:{label}");
        runtime_state.memory_store.add_topic_bundle(TopicBundle {
            bundle_id: contention_ref.clone(),
            bundle_class: TopicBundleClass::CampaignOperatingNotes,
            scope: MemoryScope::Campaign(campaign_id.clone()),
            summary: "contention and fairness control remained reconstructable".to_string(),
            evidence_refs: vec![contention_ref.clone(), fairness_ref.clone()],
            freshness_policy: "retain-until-contention-cleared".to_string(),
        });

        let steering_ref = format!("steering:{label}");
        let rollback_rehearsal_ref = format!("rollback-rehearsal:{label}");
        let adoption_safety_ref = format!("adoption-safety:{label}");
        runtime_state.memory_store.add_topic_bundle(TopicBundle {
            bundle_id: steering_ref.clone(),
            bundle_class: TopicBundleClass::ArchitectureDecision,
            scope: MemoryScope::Campaign(campaign_id.clone()),
            summary: "operator steering and adoption safety remained reconstructable".to_string(),
            evidence_refs: vec![
                steering_ref.clone(),
                rollback_rehearsal_ref.clone(),
                adoption_safety_ref.clone(),
            ],
            freshness_policy: "retain-through-reversal-window".to_string(),
        });

        let pointer_index_ref = runtime_state
            .memory_store
            .pointer_indexes
            .first()
            .map(|pointer_index| pointer_index.index_id.clone());
        let contradiction_ref = format!("contradiction:{label}");
        runtime_state.memory_store.register_contradiction(
            contradiction_ref.clone(),
            vec![plan_ref.clone(), reprioritization_ref.clone()],
            "reconcile plan carry-forward with reprioritized work",
            pointer_index_ref.as_deref(),
        );
        runtime_state
            .memory_store
            .resolve_contradiction(&contradiction_ref, pointer_index_ref.as_deref());

        for (related_ref, class, summary) in [
            (
                portfolio_ref.as_str(),
                AuditRecordClass::GovernanceAuditRecord,
                "campaign portfolio remained reconstructable",
            ),
            (
                budget_ref.as_str(),
                AuditRecordClass::GovernanceAuditRecord,
                "budget continuity remained reconstructable",
            ),
            (
                intervention_ref.as_str(),
                AuditRecordClass::GovernanceAuditRecord,
                "intervention evidence remained reconstructable",
            ),
            (
                canary_ref.as_str(),
                AuditRecordClass::PromotionAuditRecord,
                "canary evidence remained reconstructable",
            ),
            (
                release_ref.as_str(),
                AuditRecordClass::PromotionAuditRecord,
                "release evidence remained reconstructable",
            ),
            (
                rejection_ref.as_str(),
                AuditRecordClass::GovernanceAuditRecord,
                "rejection evidence remained reconstructable",
            ),
            (
                program_memory_ref.as_str(),
                AuditRecordClass::GovernanceAuditRecord,
                "program memory evidence remained reconstructable",
            ),
            (
                plan_ref.as_str(),
                AuditRecordClass::GovernanceAuditRecord,
                "plan carry-forward remained reconstructable",
            ),
            (
                reprioritization_ref.as_str(),
                AuditRecordClass::GovernanceAuditRecord,
                "reprioritization remained reconstructable",
            ),
            (
                contention_ref.as_str(),
                AuditRecordClass::GovernanceAuditRecord,
                "contention evidence remained reconstructable",
            ),
            (
                fairness_ref.as_str(),
                AuditRecordClass::GovernanceAuditRecord,
                "fairness evidence remained reconstructable",
            ),
            (
                steering_ref.as_str(),
                AuditRecordClass::GovernanceAuditRecord,
                "operator steering remained reconstructable",
            ),
            (
                rollback_rehearsal_ref.as_str(),
                AuditRecordClass::PromotionAuditRecord,
                "rollback rehearsal remained reconstructable",
            ),
            (
                adoption_safety_ref.as_str(),
                AuditRecordClass::PromotionAuditRecord,
                "adoption safety remained reconstructable",
            ),
        ] {
            append_control_audit(runtime_state, related_ref, class, summary);
        }
    }

    fn append_inventory_service_audits(
        runtime_state: &mut ReplayableRuntimeState,
        inventory: &ClosureInventory,
    ) {
        for entry in &inventory.entries {
            if let Some(audit_ref) = entry.audit_ref.as_deref() {
                append_control_audit(
                    runtime_state,
                    audit_ref,
                    AuditRecordClass::GovernanceAuditRecord,
                    "service inventory audit remained reconstructable",
                );
            }
        }
    }

    fn append_checkpoint_lineage(
        runtime_state: &mut ReplayableRuntimeState,
        artifact_prefix: &str,
    ) {
        let checkpoint = runtime_state
            .latest_checkpoint
            .clone()
            .expect("runtime state should include a checkpoint");
        runtime_state.memory_store.persist_checkpoint_artifact(
            format!("memory-checkpoint-{artifact_prefix}"),
            checkpoint.clone(),
            format!("checkpoint {} persisted", checkpoint.checkpoint_id),
        );
        runtime_state
            .memory_store
            .append(MemoryArtifact::audit_record(
                format!("memory-audit-checkpoint-{artifact_prefix}"),
                AuditRecord::new(
                    format!("audit-checkpoint-{artifact_prefix}"),
                    AuditRecordClass::GovernanceAuditRecord,
                    checkpoint.session_header.campaign_id.clone(),
                    checkpoint.session_header.epoch_id.clone(),
                    checkpoint.session_header.session_id.clone(),
                    checkpoint.active_task_refs.first().cloned(),
                    checkpoint.checkpoint_id.clone(),
                    format!(
                        "checkpoint {} remained reconstructable",
                        checkpoint.checkpoint_id
                    ),
                ),
            ));
    }

    fn supervisor_dimension_scores(
        incumbent_prefix: &str,
        challenger_prefix: &str,
    ) -> Vec<EvaluationDimensionScore> {
        vec![
            EvaluationDimensionScore {
                dimension: EvaluationDimension::SemanticCorrectness,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: format!("{incumbent_prefix} remained semantically correct"),
                challenger_summary: format!("{challenger_prefix} remained semantically correct"),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::GovernanceFidelity,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: format!("{incumbent_prefix} remained governed"),
                challenger_summary: format!("{challenger_prefix} remained governed"),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::Replayability,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: format!("{incumbent_prefix} remained replayable"),
                challenger_summary: format!("{challenger_prefix} remained replayable"),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::OperatorBurden,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: format!("{incumbent_prefix} kept operator review bounded"),
                challenger_summary: format!("{challenger_prefix} kept operator review bounded"),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::BoundaryCost,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: format!("{incumbent_prefix} preserved boundary cost"),
                challenger_summary: format!("{challenger_prefix} preserved boundary cost"),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::ReplacementSafety,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: format!("{incumbent_prefix} remained reversible"),
                challenger_summary: format!("{challenger_prefix} remained reversible"),
            },
        ]
    }

    fn shadow_bundle() -> ShadowEvaluationBundle {
        let incumbent_runtime_state = runtime_state();
        let mut challenger_runtime_state = runtime_state();
        append_checkpoint_lineage(&mut challenger_runtime_state, "shadow-challenger");
        append_control_audit(
            &mut challenger_runtime_state,
            "comparison-1",
            AuditRecordClass::GovernanceAuditRecord,
            "shadow comparison remained reconstructable",
        );
        append_control_audit(
            &mut challenger_runtime_state,
            "evidence-1",
            AuditRecordClass::PromotionAuditRecord,
            "shadow sufficiency evidence remained reconstructable",
        );
        append_review_artifact(&mut challenger_runtime_state, "review-artifact-1");

        ShadowEvaluationBundle {
            shadow_campaign: ShadowCampaign {
                shadow_campaign_id: "shadow-campaign-1".to_string(),
                campaign_id: "campaign-1".to_string(),
                incumbent_session_ref: "session-incumbent".to_string(),
                challenger_session_ref: "session-challenger".to_string(),
                shared_input_refs: vec!["campaign-input-1".to_string()],
                incumbent_checkpoint_ref: Some("checkpoint-1".to_string()),
                challenger_checkpoint_ref: Some("checkpoint-1".to_string()),
                allowed_tick_sources: vec![crate::execution::TickSource::ApprovalResponse],
                native_control_targets: vec![
                    CapabilityImportTarget::CampaignControl,
                    CapabilityImportTarget::ApprovalGateway,
                    CapabilityImportTarget::ReviewPromotion,
                ],
                no_live_mutation: true,
                rollback_handle_ref: "rollback-1".to_string(),
                status: ShadowCampaignStatus::DecisionReady,
            },
            challenger_evaluation_session: ChallengerEvaluationSession {
                evaluation_session_id: "evaluation-1".to_string(),
                shadow_campaign_id: "shadow-campaign-1".to_string(),
                incumbent_session_ref: "session-incumbent".to_string(),
                challenger_session_ref: "session-challenger".to_string(),
                shared_input_refs: vec!["campaign-input-1".to_string()],
                challenger_capability_envelope_refs: vec![
                    "envelope-campaign-control".to_string(),
                    "envelope-review-promotion".to_string(),
                ],
                latest_challenger_checkpoint_ref: Some("checkpoint-1".to_string()),
                no_live_mutation: true,
            },
            incumbent_runtime_state,
            challenger_runtime_state,
            comparison_record: GenerationComparisonRecord {
                comparison_id: "comparison-1".to_string(),
                target: CapabilityImportTarget::NativeSupervisorChallenger,
                replacement_tier: NativeReplacementTier::NativeSupervisorChallengers,
                incumbent_ref: "session-incumbent".to_string(),
                challenger_ref: "session-challenger".to_string(),
                shared_input_refs: vec!["campaign-input-1".to_string()],
                imported_provider: crate::execution::ProviderKind::Imported,
                native_provider: crate::execution::ProviderKind::Native,
                imported_output_refs: vec!["incumbent-output-1".to_string()],
                native_output_refs: vec!["challenger-output-1".to_string()],
                dimension_scores: supervisor_dimension_scores("incumbent baseline", "challenger"),
                matched: true,
                summary: "challenger remained bounded and comparable".to_string(),
            },
            sufficiency_evidence: NativeSufficiencyEvidence {
                evidence_id: "evidence-1".to_string(),
                target: CapabilityImportTarget::NativeSupervisorChallenger,
                achieved_tier: NativeReplacementTier::NativeSupervisorChallengers,
                artifact_refs: vec!["review-artifact-1".to_string()],
                checkpoint_refs: vec!["checkpoint-1".to_string(), "checkpoint-2".to_string()],
                audit_refs: vec!["audit-evidence-1".to_string()],
                summary: "native challenger evidence bundle".to_string(),
                complete: true,
            },
            promotion_readiness_decision: PromotionReadinessDecision {
                decision_id: "promotion-readiness-1".to_string(),
                comparison_id: "comparison-1".to_string(),
                challenger_ref: "session-challenger".to_string(),
                status: PromotionReadinessStatus::Promotable,
                rationale: "bounded challenger is promotion-ready without live adoption"
                    .to_string(),
                required_preconditions: Vec::new(),
                rollback_handle_refs: vec!["rollback-1".to_string()],
                review_artifact_refs: vec!["review-artifact-1".to_string()],
                quarantine_refs: Vec::new(),
            },
        }
    }

    fn promotion_bundle() -> PromotionActivationBundle {
        let mut promoted_runtime_state = runtime_state();
        append_checkpoint_lineage(&mut promoted_runtime_state, "promotion");
        for (related_ref, class, summary) in [
            (
                "promotion-act-1",
                AuditRecordClass::PromotionAuditRecord,
                "promotion act remained reconstructable",
            ),
            (
                "adoption-1",
                AuditRecordClass::PromotionAuditRecord,
                "epoch adoption remained reconstructable",
            ),
            (
                "reversal-window-1",
                AuditRecordClass::GovernanceAuditRecord,
                "reversal window remained reconstructable",
            ),
            (
                "comparison-loop-1",
                AuditRecordClass::GovernanceAuditRecord,
                "successor loop comparison remained reconstructable",
            ),
            (
                "evidence-loop-1",
                AuditRecordClass::PromotionAuditRecord,
                "successor loop evidence remained reconstructable",
            ),
        ] {
            append_control_audit(&mut promoted_runtime_state, related_ref, class, summary);
        }
        append_review_artifact(&mut promoted_runtime_state, "review-artifact-1");
        append_v14_program_evidence(
            &mut promoted_runtime_state,
            "promotion-activation-1",
            &["review-artifact-1".to_string()],
        );

        PromotionActivationBundle {
            shadow_evaluation_bundle: shadow_bundle(),
            promotion_act: PromotionAct {
                promotion_act_id: "promotion-act-1".to_string(),
                comparison_id: "comparison-1".to_string(),
                challenger_ref: "session-challenger".to_string(),
                prior_epoch_id: "epoch-1".to_string(),
                promoted_epoch_id: "epoch-2".to_string(),
                successor_campaign_id: "campaign-successor-1".to_string(),
                review_artifact_refs: vec!["review-artifact-1".to_string()],
                rollback_handle_refs: vec!["rollback-1".to_string()],
                lineage_refs: vec!["comparison-1".to_string()],
                status: PromotionActStatus::Activated,
                rationale: "bounded promotion act".to_string(),
            },
            epoch_adoption_record: EpochAdoptionRecord {
                adoption_id: "adoption-1".to_string(),
                promotion_act_id: "promotion-act-1".to_string(),
                prior_epoch_id: "epoch-1".to_string(),
                promoted_epoch_id: "epoch-2".to_string(),
                prior_incumbent_ref: "session-incumbent".to_string(),
                promoted_incumbent_ref: "session-challenger".to_string(),
                activated_session_id: "session-activated".to_string(),
                successor_campaign_id: "campaign-successor-1".to_string(),
                carried_artifact_refs: vec!["review-artifact-1".to_string()],
                activation_checkpoint_ref: Some("checkpoint-1".to_string()),
                status: EpochAdoptionStatus::Active,
                summary: "epoch adoption active".to_string(),
            },
            reversal_window: ReversalWindow {
                reversal_window_id: "reversal-window-1".to_string(),
                promotion_act_id: "promotion-act-1".to_string(),
                promoted_epoch_id: "epoch-2".to_string(),
                rollback_handle_refs: vec!["rollback-1".to_string()],
                quarantine_refs: Vec::new(),
                status: ReversalWindowStatus::Open,
                summary: "reversal window open".to_string(),
            },
            promoted_runtime_state,
            successor_loop_comparison: GenerationComparisonRecord {
                comparison_id: "comparison-loop-1".to_string(),
                target: CapabilityImportTarget::NativeSupervisorChallenger,
                replacement_tier: NativeReplacementTier::BoundedSelfHostingLoop,
                incumbent_ref: "session-challenger".to_string(),
                challenger_ref: "successor-candidate-1".to_string(),
                shared_input_refs: vec!["campaign-input-1".to_string()],
                imported_provider: crate::execution::ProviderKind::Native,
                native_provider: crate::execution::ProviderKind::Native,
                imported_output_refs: vec!["promoted-output-1".to_string()],
                native_output_refs: vec!["successor-output-1".to_string()],
                dimension_scores: supervisor_dimension_scores(
                    "promoted incumbent",
                    "successor candidate",
                ),
                matched: true,
                summary: "loop entry comparison".to_string(),
            },
            successor_loop_evidence: NativeSufficiencyEvidence {
                evidence_id: "evidence-loop-1".to_string(),
                target: CapabilityImportTarget::NativeSupervisorChallenger,
                achieved_tier: NativeReplacementTier::BoundedSelfHostingLoop,
                artifact_refs: vec!["successor-output-1".to_string()],
                checkpoint_refs: vec!["checkpoint-epoch-handoff-1".to_string()],
                audit_refs: vec!["audit-evidence-loop-1".to_string()],
                summary: "bounded self-hosting loop evidence".to_string(),
                complete: true,
            },
        }
    }

    fn v1_completion_bundle() -> V1CompletionBundle {
        let mut promotion_activation_bundle = promotion_bundle();
        let closure_inventory = ClosureInventory {
            inventory_id: "closure-1".to_string(),
            entries: vec![
                CapabilityClosureEntry {
                    target: CapabilityImportTarget::TranscriptRetrieval,
                    current_mode: CapabilityDependencyMode::Native,
                    closure_status: CapabilityClosureStatus::NativeClosed,
                    capability_world_ref: Some("world:memory-access".to_string()),
                    audit_ref: Some("audit-memory-access".to_string()),
                    rationale: "skeptical transcript retrieval is native".to_string(),
                },
                CapabilityClosureEntry {
                    target: CapabilityImportTarget::CampaignControl,
                    current_mode: CapabilityDependencyMode::Native,
                    closure_status: CapabilityClosureStatus::NativeClosed,
                    capability_world_ref: Some("world:campaign-control".to_string()),
                    audit_ref: Some("audit-campaign-control".to_string()),
                    rationale: "campaign control is native".to_string(),
                },
                CapabilityClosureEntry {
                    target: CapabilityImportTarget::ApprovalGateway,
                    current_mode: CapabilityDependencyMode::Native,
                    closure_status: CapabilityClosureStatus::NativeClosed,
                    capability_world_ref: Some("world:approval-gateway".to_string()),
                    audit_ref: Some("audit-approval-gateway".to_string()),
                    rationale: "approval gateway is native".to_string(),
                },
                CapabilityClosureEntry {
                    target: CapabilityImportTarget::ReviewPromotion,
                    current_mode: CapabilityDependencyMode::Native,
                    closure_status: CapabilityClosureStatus::NativeClosed,
                    capability_world_ref: Some("world:review-promotion".to_string()),
                    audit_ref: Some("audit-review-promotion".to_string()),
                    rationale: "review and promotion flow is native".to_string(),
                },
                CapabilityClosureEntry {
                    target: CapabilityImportTarget::ScheduleTick,
                    current_mode: CapabilityDependencyMode::Native,
                    closure_status: CapabilityClosureStatus::NativeClosed,
                    capability_world_ref: Some("world:schedule-tick".to_string()),
                    audit_ref: Some("audit-schedule-tick".to_string()),
                    rationale: "schedule tick handling is native".to_string(),
                },
                CapabilityClosureEntry {
                    target: CapabilityImportTarget::ModelHosting,
                    current_mode: CapabilityDependencyMode::ImportedBaseline,
                    closure_status: CapabilityClosureStatus::CarriedImportApproved,
                    capability_world_ref: Some("world:model-hosting-adapter".to_string()),
                    audit_ref: Some("audit-model-hosting".to_string()),
                    rationale: "model hosting remains explicit and governed".to_string(),
                },
                CapabilityClosureEntry {
                    target: CapabilityImportTarget::WorktreeHostAdapter,
                    current_mode: CapabilityDependencyMode::ImportedBaseline,
                    closure_status: CapabilityClosureStatus::CarriedImportApproved,
                    capability_world_ref: Some("world:worktree-host-adapter".to_string()),
                    audit_ref: Some("audit-worktree-host-adapter".to_string()),
                    rationale: "worktree host access remains an explicit carried import"
                        .to_string(),
                },
                CapabilityClosureEntry {
                    target: CapabilityImportTarget::EnvironmentBridge,
                    current_mode: CapabilityDependencyMode::ImportedBaseline,
                    closure_status: CapabilityClosureStatus::CarriedImportApproved,
                    capability_world_ref: Some("world:environment-bridge".to_string()),
                    audit_ref: Some("audit-environment-bridge".to_string()),
                    rationale: "environment bridging remains an explicit carried import"
                        .to_string(),
                },
                CapabilityClosureEntry {
                    target: CapabilityImportTarget::SemanticValidation,
                    current_mode: CapabilityDependencyMode::Native,
                    closure_status: CapabilityClosureStatus::NativeClosed,
                    capability_world_ref: Some("world:semantic-validation".to_string()),
                    audit_ref: Some("audit-semantic-validation".to_string()),
                    rationale: "semantic validation is native".to_string(),
                },
                CapabilityClosureEntry {
                    target: CapabilityImportTarget::ArtifactPackaging,
                    current_mode: CapabilityDependencyMode::Native,
                    closure_status: CapabilityClosureStatus::NativeClosed,
                    capability_world_ref: Some("world:artifact-packaging".to_string()),
                    audit_ref: Some("audit-artifact-packaging".to_string()),
                    rationale: "artifact packaging remains inside the bounded substrate"
                        .to_string(),
                },
                CapabilityClosureEntry {
                    target: CapabilityImportTarget::NativeSupervisorChallenger,
                    current_mode: CapabilityDependencyMode::Native,
                    closure_status: CapabilityClosureStatus::NativeClosed,
                    capability_world_ref: Some("world:native-supervisor-challenger".to_string()),
                    audit_ref: Some("audit-native-supervisor-challenger".to_string()),
                    rationale:
                        "native supervisor challenger evaluation is closed in the bounded loop"
                            .to_string(),
                },
            ],
            remaining_gap_refs: Vec::new(),
            summary: "bounded v1 closure inventory".to_string(),
        };
        append_inventory_service_audits(
            &mut promotion_activation_bundle.promoted_runtime_state,
            &closure_inventory,
        );
        append_review_artifact(
            &mut promotion_activation_bundle.promoted_runtime_state,
            "review-artifact-2",
        );
        append_control_audit(
            &mut promotion_activation_bundle.promoted_runtime_state,
            "evidence-cycle-2",
            AuditRecordClass::PromotionAuditRecord,
            "second-cycle evidence remained reconstructable",
        );
        append_v14_program_evidence(
            &mut promotion_activation_bundle.promoted_runtime_state,
            "v1-completion-1",
            &[
                "review-artifact-1".to_string(),
                "review-artifact-2".to_string(),
            ],
        );

        V1CompletionBundle {
            promotion_activation_bundle,
            closure_inventory,
            successor_genome: GenomeArtifact {
                genome_id: "genome-1".to_string(),
                parent_ref: "session-challenger".to_string(),
                stable_interface_ref: "package:aiaf/supervisor@v1".to_string(),
                typed_graph_ref: "typed-dag:successor-1".to_string(),
                policy_refs: vec!["policy:bounded".to_string()],
                summary: "second-cycle successor genome".to_string(),
            },
            successor_phenotype: PhenotypeArtifact {
                artifact_id: "artifact-1".to_string(),
                genome_ref: "genome-1".to_string(),
                stable_interface_ref: "package:aiaf/supervisor@v1".to_string(),
                package_ref: "component:artifact-1".to_string(),
                boundary_refs: vec!["wit:supervisor".to_string()],
                output_refs: vec!["artifact-output-1".to_string()],
                summary: "second-cycle successor phenotype".to_string(),
            },
            semantic_validation_record: SemanticValidationRecord {
                validation_id: "validation-1".to_string(),
                genome_ref: "genome-1".to_string(),
                phenotype_ref: "artifact-1".to_string(),
                stable_interface_ref: "package:aiaf/supervisor@v1".to_string(),
                validator_refs: vec!["validator:semantic-check".to_string()],
                evidence_refs: vec!["evidence:semantic-check-1".to_string()],
                passed: true,
                summary: "semantic validation passed".to_string(),
            },
            second_cycle_comparison: GenerationComparisonRecord {
                comparison_id: "comparison-cycle-2".to_string(),
                target: CapabilityImportTarget::NativeSupervisorChallenger,
                replacement_tier: NativeReplacementTier::BoundedSelfHostingLoop,
                incumbent_ref: "session-challenger".to_string(),
                challenger_ref: "successor-candidate-2".to_string(),
                shared_input_refs: vec!["campaign-input-1".to_string()],
                imported_provider: crate::execution::ProviderKind::Native,
                native_provider: crate::execution::ProviderKind::Native,
                imported_output_refs: vec!["promoted-output-1".to_string()],
                native_output_refs: vec!["successor-output-2".to_string()],
                dimension_scores: supervisor_dimension_scores("incumbent", "successor"),
                matched: true,
                summary: "second-cycle bounded comparison".to_string(),
            },
            second_cycle_evidence: NativeSufficiencyEvidence {
                evidence_id: "evidence-cycle-2".to_string(),
                target: CapabilityImportTarget::NativeSupervisorChallenger,
                achieved_tier: NativeReplacementTier::BoundedSelfHostingLoop,
                artifact_refs: vec!["artifact-1".to_string()],
                checkpoint_refs: vec!["checkpoint-epoch-handoff-1".to_string()],
                audit_refs: vec!["audit-evidence-cycle-2".to_string()],
                summary: "second-cycle evidence bundle".to_string(),
                complete: true,
            },
            second_cycle_readiness: PromotionReadinessDecision {
                decision_id: "promotion-readiness-2".to_string(),
                comparison_id: "comparison-cycle-2".to_string(),
                challenger_ref: "successor-candidate-2".to_string(),
                status: PromotionReadinessStatus::Promotable,
                rationale: "second-cycle successor is promotable".to_string(),
                required_preconditions: Vec::new(),
                rollback_handle_refs: vec!["rollback-1".to_string()],
                review_artifact_refs: vec!["review-artifact-2".to_string()],
                quarantine_refs: Vec::new(),
            },
            second_cycle_decision: CycleClosureDecision {
                decision_id: "cycle-closure-2".to_string(),
                comparison_id: "comparison-cycle-2".to_string(),
                promotion_readiness_ref: "promotion-readiness-2".to_string(),
                successor_candidate_ref: "successor-candidate-2".to_string(),
                status: CycleClosureDecisionStatus::Promote,
                rationale: "second-cycle successor can be promoted".to_string(),
                review_artifact_refs: vec!["review-artifact-2".to_string()],
                rollback_handle_refs: vec!["rollback-1".to_string()],
                quarantine_refs: Vec::new(),
            },
            second_cycle_promotion_act: Some(PromotionAct {
                promotion_act_id: "promotion-act-2".to_string(),
                comparison_id: "comparison-cycle-2".to_string(),
                challenger_ref: "successor-candidate-2".to_string(),
                prior_epoch_id: "epoch-2".to_string(),
                promoted_epoch_id: "epoch-3".to_string(),
                successor_campaign_id: "campaign-successor-2".to_string(),
                review_artifact_refs: vec!["review-artifact-2".to_string()],
                rollback_handle_refs: vec!["rollback-1".to_string()],
                lineage_refs: vec!["comparison-cycle-2".to_string()],
                status: PromotionActStatus::Approved,
                rationale: "bounded second-cycle promotion act".to_string(),
            }),
            v1_completion_gate: V1CompletionGate {
                gate_id: "v1-gate-1".to_string(),
                closure_inventory_ref: "closure-1".to_string(),
                cycle_closure_decision_ref: "cycle-closure-2".to_string(),
                carried_import_refs: vec!["ModelHosting".to_string()],
                remaining_gap_refs: Vec::new(),
                status: V1CompletionStatus::Satisfied,
                rationale: "bounded v1 completion satisfied".to_string(),
            },
        }
    }

    #[test]
    fn runtime_state_persists_and_reloads() {
        let root = temp_store_root("persist-reload");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let state = runtime_state();

        store.persist_runtime_state(&state).unwrap();
        let reloaded = store.load_runtime_state().unwrap();

        assert_eq!(reloaded.session.header.session_id, "session-1");
        assert_eq!(reloaded.root_task.task_id, "task-root");
        assert_eq!(
            reloaded.latest_checkpoint.unwrap().checkpoint_id,
            "checkpoint-1"
        );
        assert_eq!(store.artifact_ids().unwrap().len(), 0);
    }

    #[test]
    fn runtime_state_exposes_task_scoped_events_and_family_counts() {
        let mut state = runtime_state();
        state.event_log.push(ExecutionEvent::new(
            "event-task-root",
            EventFamily::WorkerDispatchEvent,
            "campaign-1",
            "epoch-1",
            "session-1",
            None,
            Some("task-root".to_string()),
            "worker dispatch tracked for root task",
        ));

        assert_eq!(
            state.count_events_in_family(EventFamily::CheckpointEvent),
            1
        );
        assert_eq!(
            state.count_events_in_family(EventFamily::WorkerDispatchEvent),
            1
        );
        assert_eq!(state.events_for_task("task-root").len(), 1);
        state.validate_replayability().unwrap();
    }

    #[test]
    fn invalid_runtime_state_is_rejected_on_persist() {
        let root = temp_store_root("invalid-runtime-state");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let mut state = runtime_state();
        state.session.latest_checkpoint_ref = None;

        let error = store.persist_runtime_state(&state).unwrap_err();

        assert!(matches!(
            error,
            StorageError::Validation(RuntimeStateValidationError::MissingLatestCheckpointRef)
        ));
    }

    #[test]
    fn runtime_state_rejects_pending_approvals_outside_approval_wait() {
        let mut state = runtime_state();
        state
            .session
            .pending_approval_refs
            .push("approval-1".to_string());

        let error = state.validate_replayability().unwrap_err();

        assert_eq!(
            error,
            RuntimeStateValidationError::PendingApprovalsOutsideAwaitingApproval {
                state: "Initialized".to_string(),
            }
        );
    }

    #[test]
    fn runtime_state_rejects_outstanding_workers_outside_worker_wait() {
        let mut state = runtime_state();
        state
            .session
            .outstanding_worker_refs
            .push("worker-1".to_string());

        let error = state.validate_replayability().unwrap_err();

        assert_eq!(
            error,
            RuntimeStateValidationError::OutstandingWorkersOutsideAwaitingWorkerResult {
                state: "Initialized".to_string(),
            }
        );
    }

    #[test]
    fn rollback_restores_checkpoint_snapshot() {
        let root = temp_store_root("rollback");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let state = runtime_state_with_rollback_evidence();
        store.persist_runtime_state(&state).unwrap();

        let mut updated_state = state.clone();
        updated_state.root_task.summary = "Updated after checkpoint".to_string();
        store.persist_runtime_state(&updated_state).unwrap();

        let rollback_handle = create_rollback_handle(
            "rollback-1",
            "task",
            "checkpoint-1",
            vec!["restore checkpoint-1".to_string()],
            Vec::new(),
        );
        let restored = execute_rollback(&rollback_handle, &store).unwrap();

        assert_eq!(
            restored.latest_checkpoint.unwrap().checkpoint_id,
            "checkpoint-1"
        );
        assert_eq!(restored.root_task.summary, "Bounded replayable RC03 flow");
        assert_eq!(
            store.load_runtime_state().unwrap().root_task.summary,
            "Updated after checkpoint"
        );
    }

    #[test]
    fn rollback_requires_explicit_approval_when_declared() {
        let root = temp_store_root("rollback-approval");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        store
            .persist_runtime_state(&runtime_state_with_rollback_evidence())
            .unwrap();

        let rollback_handle = create_rollback_handle(
            "rollback-1",
            "task",
            "checkpoint-1",
            vec!["restore checkpoint-1".to_string()],
            vec!["operator-confirm".to_string()],
        );
        let error = execute_rollback(&rollback_handle, &store).unwrap_err();

        assert_eq!(
            error,
            RollbackExecutionError::ApprovalRequired {
                rollback_handle_id: "rollback-1".to_string()
            }
        );
    }

    #[test]
    fn rollback_rejects_missing_governance_evidence() {
        let root = temp_store_root("rollback-missing-evidence");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        store.persist_runtime_state(&runtime_state()).unwrap();

        let rollback_handle = create_rollback_handle(
            "rollback-1",
            "task",
            "checkpoint-1",
            vec!["restore checkpoint-1".to_string()],
            Vec::new(),
        );
        let error = execute_rollback(&rollback_handle, &store).unwrap_err();

        assert_eq!(
            error,
            RollbackExecutionError::Storage(
                "rollback 'rollback-1' is missing checkpoint or governance evidence for 'checkpoint-1'"
                    .to_string()
            )
        );
    }

    #[test]
    fn rc01_pointer_index_fixture_is_compatible_with_rc02_seed_loading() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "artifacts/fixtures/supervisor-approval-resume-worker-complete/pointer-index.json",
        );
        let raw = fs::read_to_string(path).unwrap();
        let fixture: Rc01PointerIndexFixture = serde_json::from_str(&raw).unwrap();

        let seeded_pointer_index = PointerIndex {
            index_id: fixture.artifact_id,
            scope: MemoryScope::Campaign("campaign-rc01".to_string()),
            entry_refs: fixture.critical_refs.clone(),
            contested_refs: Vec::new(),
            critical_refs: fixture.critical_refs,
            governance_constraints: fixture.governance_constraints,
            open_task_refs: vec!["task-approve-worker-complete".to_string()],
            updated_at: "fixture-seed".to_string(),
        };

        assert!(
            seeded_pointer_index
                .governance_constraints
                .iter()
                .any(|constraint| constraint.contains("human approval"))
        );
    }

    #[test]
    fn shadow_evaluation_bundle_persists_and_reloads() {
        let root = temp_store_root("shadow-evaluation");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let bundle = shadow_bundle();

        store.persist_shadow_evaluation_bundle(&bundle).unwrap();
        let reloaded = store
            .load_shadow_evaluation_bundle(&bundle.shadow_campaign.shadow_campaign_id)
            .unwrap();

        assert_eq!(reloaded, bundle);
    }

    #[test]
    fn promotion_activation_bundle_persists_and_reloads() {
        let root = temp_store_root("promotion-activation");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let bundle = promotion_bundle();

        store.persist_promotion_activation_bundle(&bundle).unwrap();
        let reloaded = store
            .load_promotion_activation_bundle(&bundle.promotion_act.promotion_act_id)
            .unwrap();

        assert_eq!(reloaded, bundle);
    }

    #[test]
    fn v1_completion_bundle_persists_and_reloads() {
        let root = temp_store_root("v1-completion");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let bundle = v1_completion_bundle();

        store.persist_v1_completion_bundle(&bundle).unwrap();
        let reloaded = store
            .load_v1_completion_bundle(&bundle.v1_completion_gate.gate_id)
            .unwrap();

        assert_eq!(reloaded, bundle);
    }

    #[test]
    fn shadow_evaluation_bundle_requires_review_artifact_support() {
        let root = temp_store_root("shadow-evaluation-review-support");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let mut bundle = shadow_bundle();
        bundle
            .challenger_runtime_state
            .memory_store
            .artifacts
            .retain(|artifact| artifact.related_ref != "review-artifact-1");

        let error = store
            .persist_shadow_evaluation_bundle(&bundle)
            .expect_err("shadow bundle should fail without review artifact backing");

        assert!(
            error
                .to_string()
                .contains("requires persisted operator review support")
        );
    }

    #[test]
    fn promotion_activation_bundle_requires_epoch_handoff_checkpoint_lineage() {
        let root = temp_store_root("promotion-activation-epoch-handoff");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let mut bundle = promotion_bundle();
        bundle.epoch_adoption_record.activation_checkpoint_ref =
            Some("checkpoint-missing".to_string());

        let error = store
            .persist_promotion_activation_bundle(&bundle)
            .expect_err("promotion bundle should fail without epoch handoff checkpoint lineage");

        assert!(
            error
                .to_string()
                .contains("promotion activation epoch handoff requires checkpoint lineage")
        );
    }

    #[test]
    fn v1_completion_bundle_requires_inventory_audit_coverage() {
        let root = temp_store_root("v1-completion-inventory-audits");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let mut bundle = v1_completion_bundle();
        bundle
            .promotion_activation_bundle
            .promoted_runtime_state
            .memory_store
            .artifacts
            .retain(|artifact| artifact.related_ref != "audit-memory-access");

        let error = store
            .persist_v1_completion_bundle(&bundle)
            .expect_err("v1 completion should fail without service inventory audit coverage");

        assert!(
            error
                .to_string()
                .contains("requires persisted service audit coverage")
        );
    }

    #[test]
    fn promotion_activation_bundle_requires_v14_portfolio_and_release_evidence() {
        let root = temp_store_root("promotion-activation-v14-evidence");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let mut bundle = promotion_bundle();
        bundle
            .promoted_runtime_state
            .memory_store
            .artifacts
            .retain(|artifact| !artifact.related_ref.starts_with("budget:"));
        for topic_bundle in &mut bundle.promoted_runtime_state.memory_store.topic_bundles {
            topic_bundle
                .evidence_refs
                .retain(|reference| !reference.starts_with("budget:"));
        }

        let error = store
            .persist_promotion_activation_bundle(&bundle)
            .expect_err("promotion bundle should fail without v1.4 budget evidence");

        assert!(error.to_string().contains(
            "requires a campaign-operating bundle with portfolio, budget, and intervention evidence"
        ));
    }

    #[test]
    fn promotion_activation_bundle_rejects_unbounded_contention() {
        let root = temp_store_root("promotion-activation-contention");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let mut bundle = promotion_bundle();
        bundle.promoted_runtime_state.task_graph = TaskGraph::new(
            "task-root",
            vec![
                AgendaItem::new(
                    "agenda-one",
                    "task-one",
                    "bounded-analysis",
                    Vec::new(),
                    OwnershipBoundary {
                        boundary_id: "boundary-one".to_string(),
                        resource_scope: "shared-workspace".to_string(),
                        mode: OwnershipMode::ExclusiveMutable,
                        owner_actor_ref: "campaign-one".to_string(),
                    },
                ),
                AgendaItem::new(
                    "agenda-two",
                    "task-two",
                    "bounded-analysis",
                    Vec::new(),
                    OwnershipBoundary {
                        boundary_id: "boundary-two".to_string(),
                        resource_scope: "shared-workspace".to_string(),
                        mode: OwnershipMode::MergeRequired,
                        owner_actor_ref: "campaign-two".to_string(),
                    },
                ),
            ],
        );

        let error = store
            .persist_promotion_activation_bundle(&bundle)
            .expect_err("promotion bundle should fail when active contention is unbounded");

        assert!(
            error
                .to_string()
                .contains("requires bounded contention control for scope 'shared-workspace'")
        );
    }

    #[test]
    fn v1_completion_bundle_requires_background_program_memory_continuity() {
        let root = temp_store_root("v1-completion-program-memory");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();
        let mut bundle = v1_completion_bundle();
        bundle
            .promotion_activation_bundle
            .promoted_runtime_state
            .memory_store
            .contradiction_records
            .clear();

        let error = store
            .persist_v1_completion_bundle(&bundle)
            .expect_err("v1 completion should fail without resolved contradiction continuity");

        assert!(
            error
                .to_string()
                .contains("requires at least one resolved contradiction record")
        );
    }
}
