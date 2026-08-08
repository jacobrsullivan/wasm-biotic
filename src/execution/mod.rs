//! Execution-kernel module tree for standalone AIAF v1.

use serde::{Deserialize, Serialize};

pub mod artifact;
pub mod capability;
pub mod checkpoint;
pub mod closure_review;
pub mod component;
pub mod continuity_grounding;
pub mod ecosystem;
pub mod events;
pub mod factory;
pub mod factory_exchange;
pub mod factory_program;
pub mod factory_replication;
pub mod factory_runtime;
pub mod factory_validation;
pub mod failure_budget;
pub mod governance;
pub mod inference;
pub mod launch;
pub mod memory;
pub mod memory_protocol;
pub mod native_services;
pub mod operations;
pub mod orchestration;
pub mod phase02;
pub mod phase03;
pub mod proposals;
pub mod recursive_factory_interface;
pub mod replacement;
pub mod runtime_adapter;
pub mod self_production;
pub mod session;
pub mod shell;
pub mod shell_evidence;
pub mod storage;
pub mod task;
pub mod tool_membrane;
pub mod transition;
pub mod turn_governance;
pub mod turn_package;
pub mod validation;
pub mod worker;
pub mod worker_ecology;
pub mod worker_world;

pub type ActorId = String;
pub type AgendaItemId = String;
pub type ApprovalRequestId = String;
pub type AuditRecordId = String;
pub type BackgroundCampaignId = String;
pub type CampaignId = String;
pub type CapabilityEnvelopeId = String;
pub type CheckpointId = String;
pub type ContradictionId = String;
pub type EpochId = String;
pub type EventId = String;
pub type HandoffId = String;
pub type MemoryArtifactId = String;
pub type MemoryUpdateProposalId = String;
pub type MessageId = String;
pub type PointerIndexId = String;
pub type QuarantineId = String;
pub type RollbackHandleId = String;
pub type SessionId = String;
pub type ShellEvidencePacketId = String;
pub type ShellSessionId = String;
pub type ShellTurnId = String;
pub type TaskId = String;
pub type TopicBundleId = String;
pub type TranscriptSliceId = String;
pub type TurnId = String;
pub type WorkerDispatchId = String;
pub type WorkerId = String;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockedReasonKind {
    Capability,
    Worker,
    Approval,
    Governance,
    Pause,
    NoProgress,
    FailureBudget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedReason {
    pub kind: BlockedReasonKind,
    pub detail: String,
}

impl BlockedReason {
    pub fn new(kind: BlockedReasonKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

pub use artifact::{
    ActivationEnvelope, ArtifactDigest, ArtifactError, ArtifactLineageRecord, BuildClosureManifest,
    ContentDigest, ContentDigestError, GenerationArtifactBundle, GenerationArtifactId,
    GenerationManifest, PackageBundleManifest, digest_json, digest_json_content,
    validate_generation_artifact_bundle,
};
pub use capability::{
    ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityOperationApproval,
    CapabilityWorld, CapabilityWorldGrant, IsolationProfile,
};
pub use checkpoint::RunCheckpoint;
pub use closure_review::{
    ACTIVE_TRUTH_CLAIM_CATALOG_SCHEMA, ACTIVE_TRUTH_CLAIM_CATALOG_VERSION,
    ActiveTruthClaimCatalogV1, ActiveTruthClaimIdV1, ActiveTruthClaimStatementV1,
    ActiveTruthPublicationControlV1, AdversarialReviewRecord, ClaimBoundaryReviewPacket,
    ClosureCriteriaMatrix, ClosureCriterionRecord, ClosureCriterionStatus, ClosureDecisionRecord,
    ClosureDossier, ClosureEffect, ClosureReviewError, EvidenceInventoryPacket,
    NorthStarClosureDecision, PublicationPolicyRecord, ResidualRiskClass, ResidualRiskRecord,
    RiskSeverity, active_truth_allowed_claims, active_truth_forbidden_claims,
    active_truth_publication_controls, active_truth_required_publication_caveats,
};
pub use component::{
    ComponentBuildError, ComponentBuildOutput, ComponentBuildRequest, ComponentExecutionContext,
    ComponentExecutionFailurePhase, ComponentExecutionLimitKind, ComponentExecutionLimits,
    ComponentExecutionTrace, ComponentI32ExecutionTrace, ComponentImportBinding,
    ComponentImportLinkAudit, ComponentInspection, build_component_package,
    component_failure_result_ref, component_success_result_ref, execute_component_export,
    execute_component_export_with_context, execute_component_i32_export,
    execute_component_i32_export_with_context, inspect_component_bytes,
};
pub use continuity_grounding::{
    ContinuityGroundingBundle, ContinuityGroundingError, ContradictionCarryForwardRecord,
    ModelContinuityBundle, OpenQuestionLedger, TurnGroundingPacket, VerifiedTurnMemoryUpdate,
};
pub use ecosystem::{
    CrossFactoryAdoptionDossier, CrossFactoryAdoptionResult, EcosystemAdmissionDecision,
    EcosystemAdmissionProfile, EcosystemAdmissionRecord, EcosystemCompatibilityPersistenceRecord,
    EcosystemContinuityWindowRecord, EcosystemError, EcosystemExchangeRouteLedger,
    EcosystemHealthLedger, EcosystemHealthSnapshot, EcosystemRollbackChoreographyRecord,
    EcosystemRollbackSymmetryRecord, EcosystemWorkspaceSnapshot, ExchangeRouteRecord,
    RouteCompatibilityCycle, RouteDeliveryResult, RouteExchangeHistoryRecord, TrustProfile,
};
pub use events::{EventFamily, ExecutionEvent};
pub use factory::{
    FactoryActivationBundle, FactoryArtifactError, FactoryComparisonDimension,
    FactoryComparisonOutcome, FactoryComparisonRecord, FactoryDimensionScore,
    FactoryDimensionVerdict, FactoryEvidencePacket, FactoryGenomeArtifact, FactoryLineageRecord,
    FactoryPhenotypeArtifact,
};
pub use factory_exchange::{
    CrossFactoryLineageImportRecord, FactoryCompatibilityDecision, FactoryCompatibilityVerdict,
    FactoryExchangeDecisionKind, FactoryExchangeEnvelope, FactoryExchangeError,
    FactoryExchangePacketClass, FactoryIdentityManifest, ImportDispositionKind,
    ImportDispositionRecord, ImportedArtifactQuarantinePacket, MemoryExchangePacket,
    QuarantineFirstImportStateKind, QuarantineFirstImportStateRecord,
    evaluate_factory_exchange_compatibility, issue_import_quarantine_packet,
    record_cross_factory_lineage_import, record_import_disposition,
    record_quarantine_first_import_state,
};
pub use factory_program::{
    AdoptionWindowRecord, AdoptionWindowResult, FactoryImprovementProgram, FactoryProgramError,
    FactoryProgramInstance, FactoryProgramSpec, FactoryProgramState, FactoryProgramTickReceipt,
    FactoryProgramTickRequest, LaterFactoryCycleDossier, LaterFactoryGenerationAgenda,
    LineageHealthDossier, LineageHealthLedger, LongitudinalLineageDossier,
    ProgramBudgetHistoryRecord, ProgramContinuityWindowRecord, ProgramPolicyComplianceRecord,
    RecurringFactoryProgramRecord, RecursionBudgetRecord, RegressionReviewPacket,
    StopConditionDecision, StopConditionRecord,
};
pub use factory_replication::{
    ChildFactoryDispositionKind, ChildFactoryDispositionRecord, ChildFactoryObservationStatus,
    ChildFactoryObservationWindowRecord, ChildFactoryQuarantineProtocolRecord,
    FactoryProvingRunRecord, FactoryReplicationCampaign, FactoryReplicationDecision,
    FactoryReplicationDecisionKind, FactoryReplicationError, FactoryReplicationEvidencePacket,
    FactoryReplicationStage, LaterFactoryCandidate, assemble_factory_replication_evidence_packet,
    finalize_factory_replication_decision, issue_child_factory_disposition,
    issue_child_factory_quarantine_protocol, materialize_later_factory_candidate,
    open_child_factory_observation_window, record_factory_proving_run,
    start_factory_replication_campaign,
};
pub use factory_runtime::{
    ActiveFactoryState, FactoryActivationRecord, FactoryGovernanceState,
    FactoryGovernanceTransitionRecord, FactoryObservationWindowReport, FactoryQuarantineRecord,
    FactoryRollbackEnvelope, FactoryRollbackRecord, FactoryRuntimeError, activate_factory,
    build_factory_rollback_envelope, observe_active_factory, quarantine_factory_candidate,
    record_factory_governance_transition, rollback_factory,
};
pub use factory_validation::{
    FactoryValidationError, FactoryValidationEvidence, FactoryValidationProfile,
    FactoryValidationRecord, FactoryValidationStatus, evaluate_factory_candidate,
};
pub use failure_budget::{FailureBudget, FailureBudgetSnapshot, RetryClass, StopCondition};
pub use failure_budget::{ShellRetryRecord, apply_shell_retry};
pub use governance::{
    ApprovalDecision, ApprovalDecisionMemoryWrite, ApprovalDecisionStatus, ApprovalRequest,
    ApprovalRequestMemoryWrite, AuditRecord, AuditRecordClass, BackgroundCampaign,
    CycleClosureDecision, CycleClosureDecisionStatus, EpochAdoptionRecord, EpochAdoptionStatus,
    GovernanceError, GovernancePolicyClass, PromotionAct, PromotionActStatus, PromotionError,
    PromotionReadinessDecision, PromotionReadinessStatus, QuarantineReasonClass, QuarantineRecord,
    QuarantineResolutionState, ReversalAction, ReversalWindow, ReversalWindowStatus,
    RollbackHandle, ShellActionDecision, ShellActionDecisionStatus, ShellApprovalPauseRecord,
    ShellDenialPacket, TickSource, V1CompletionGate, V1CompletionStatus,
    V3SubstrateCompletionEvidence, V3SubstrateCompletionGate, V3SubstrateCompletionStatus,
    V4SupervisoryShellCompletionEvidence, V4SupervisoryShellCompletionGate,
    V4SupervisoryShellCompletionStatus, create_quarantine_record, create_rollback_handle,
    decide_cycle_closure, decide_promotion_readiness, evaluate_reversal_window,
    evaluate_v1_completion_gate, evaluate_v3_substrate_completion_gate,
    evaluate_v4_supervisory_shell_completion_gate, mark_epoch_adoption_active,
    mark_epoch_adoption_reversed, mark_promotion_activated, mark_promotion_reversed,
    mark_reversal_window_reversed, open_promotion_act, open_reversal_window,
    persist_approval_decision_bundle, persist_approval_request_bundle, plan_epoch_adoption,
    validate_background_resume, validate_background_resume_with_runtime_state,
};
pub use inference::{
    FixtureInferenceResponse, InferenceAdapterError, InferenceAttemptRecord, InferenceFinishReason,
    InferenceGenerationPolicy, InferenceParsedOutputRecord, InferenceProviderMode,
    InferenceProviderModelEntry, InferenceProviderOutcomeRecord, InferenceProviderRegistryEntry,
    InferenceRawOutputRecord, InferenceRenderedPromptRecord, InferenceRequestBodyRecord,
    InferenceResponseSchemaPayloadRecord, InferenceRetryClassification,
    InferenceToolCatalogPayloadRecord, InferenceTurnBundle, InferenceTurnRequest,
    InferenceTurnResult, InferenceUsageRecord, ProviderDegradationReasonClass,
    ProviderDegradationRecord, execute_inference_turn, execute_inference_turn_with_fixture,
};
pub use launch::{
    AcceptanceTruthMatrix, CampaignAdmissionRecord, LaunchAdmissionState, LaunchError,
    LaunchRefusalClass, LaunchRefusalRecord, MigrationGateRecord, MigrationGateResult, PathKind,
    PathRetirementRecord, PathSupportClass, PathSupportClassification, ProgramToShellMapping,
    ResumeChainRecord, ShellDerivedExportBundle, ShellEvidenceSummary, TransitionalAdapterManifest,
    TransitionalTruthAnnotation, UnifiedLifecycleTransitionRecord, UniversalShellLaunchAssembly,
};
pub use memory::{
    CompactionStage, ConsolidationJob, ConsolidationJobStatus, ContradictionRecord,
    ContradictionResolutionState, MemoryArtifact, MemoryArtifactClass, MemoryArtifactPayload,
    MemoryScope, MemoryStore, MemoryUpdateProposal, MemoryUpdateStatus, MemoryWriteError,
    PointerIndex, TopicBundle, TopicBundleClass, TranscriptSlice, TranscriptSliceQuery,
};
pub use memory_protocol::{
    MemoryProtocolError, MemoryRetrievalRequest, MemoryRetrievalTrace, ShellContinuityBundle,
    VerifiedMemoryUpdateRecord, build_shell_continuity_bundle, execute_memory_retrieval_protocol,
    memory_retrieval_request_from_action, record_verified_memory_update,
};
pub use native_services::{
    NativeServiceFamily, NativeServicesError, NativeWorkflowKind, ServiceAttestationBundle,
    ServiceAttestationDecision, ServiceClosureDossier, ServiceClosureState,
    ServiceFamilyClassification, ServiceFamilyManifest, ServiceHandleLease, WorkflowClosureStatus,
    WorkflowServiceClosureDossier, WorkflowSufficiencyRecord,
};
pub use operations::{
    ApprovalInboxRecord, ConsolidationJobRecord, ContinuityJobClassification, ContinuityJobRecord,
    DeferredDecisionBundle, LeaseExpiryRecord, OperationsError, PersistentJobLease,
    PersistentShellAuditPacket, PersistentShellOperationsDossier, ScheduledWakeRecord,
    SchedulerTickClass, SchedulerTickRecord, SchedulerTickResult, ShellEscalationRecord,
};
pub use orchestration::{
    AgendaItem, AgendaStatus, OrchestrationError, OwnershipBoundary, OwnershipMode,
    RoutingDecision, ShellOrchestrationRecord, TaskGraph, WorkerRegistry,
    complete_shell_session_agenda_item, dispatch_shell_session_to_agenda_item,
    validate_ownership_boundary,
};
pub use phase02::{
    EcologyClosureWorkspacePacket, Phase02AcceptancePacket, Phase02PacketError,
    ServiceClosureWorkspacePacket,
};
pub use phase03::{
    EcosystemClosureWorkspacePacket, Phase03ClosureReviewPacket, Phase03PacketError,
    RecurringFactoryWorkspacePacket,
};
pub use proposals::{NormalizedProposal, ProposalFamily, ProposalValidationError};
pub use recursive_factory_interface::{
    ArchitecturalDependencyStatement, InterfaceNativeRecursionClosureDossier,
    LlmFactoryProgramProfile, ModelDrivenFactoryCycleRecord, RecursionClaimPosture,
    RecursiveCycleOutcome, RecursiveFactoryInterfaceError, RecursiveLineageExecutionRecord,
    WorkerAgentProductionMode, claim_boundary_statement, derive_recursion_claim_posture,
    infer_worker_role_kind, recursive_cycle_outcome_from_adoption_result,
};
pub use replacement::{
    ArtifactFlowError, CapabilityClosureEntry, CapabilityClosureStatus, CapabilityDependencyMode,
    CapabilityImportTarget, ChallengerEvaluationSession, ClosureInventory, DimensionVerdict,
    EvaluationDimension, EvaluationDimensionScore, GenerationComparisonRecord, GenomeArtifact,
    NativeReplacementTier, NativeSufficiencyEvidence, NativeSufficiencyGate, PhenotypeArtifact,
    ProviderKind, SemanticValidationRecord, ShadowCampaign, ShadowCampaignStatus,
    ShadowEvaluationError, build_closure_inventory, build_native_sufficiency_evidence,
    build_successor_genome, carried_import_targets, closure_inventory_has_hidden_imports,
    closure_inventory_is_complete, compare_challenger_outputs, compare_successor_loop_outputs,
    compare_transcript_retrieval, evaluate_native_sufficiency,
    evaluate_native_sufficiency_with_evidence, imported_transcript_retrieval_from_store,
    materialize_successor_phenotype, native_transcript_retrieval_from_memory,
    open_challenger_evaluation_session, open_shadow_campaign, validate_semantic_phenotype,
    validate_shadow_dispatch,
};
pub use runtime_adapter::{
    ActiveGenerationState, GenerationActivationRecord, GenerationObservationWindowReport,
    GenerationRollbackRecord, RuntimeAdapterError, activate_generation, observe_active_generation,
    rollback_generation,
};
pub use self_production::{
    SelfProductionCampaign, SelfProductionCampaignStatus, SelfProductionError,
    SuccessorProductionRecord, record_successor_production, start_adopted_generation_campaign,
};
pub use session::{
    ActorKind, ExecutionSession, ExecutionSessionHeader, ExecutionSessionState, TurnOutcome,
    TurnRecord,
};
pub use shell::{
    ShellCheckpointRecord, ShellResumeAnchor, ShellRuntimeError, ShellSessionBundle,
    ShellSessionRecord, ShellSessionState, ShellTaskState, ShellTurnRecord, ShellTurnState,
    approval_request_ids, complete_shell_orchestration, dispatch_shell_session,
    execute_active_shell_turn, finalize_shell_continuity_bundle, open_shell_session_bundle,
    record_shell_verified_memory_update, resume_shell_session_from_approval,
    shell_state_from_execution, shell_task_state_from_task, start_shell_turn,
};
pub use shell_evidence::{
    ShellEvidenceCompletenessStatus, ShellEvidencePacket, ShellWorkspaceView,
    assemble_shell_evidence_packet, build_shell_workspace_view,
};
pub use storage::{
    DurableArtifactStore, PromotionActivationBundle, ReplayableRuntimeState,
    RollbackExecutionError, ShadowEvaluationBundle, StorageError, V1CompletionBundle,
    V4ShellEvidenceBundle, V4SupervisoryShellBundle, execute_rollback,
};
pub use task::{TaskArtifact, TaskState};
pub use tool_membrane::{
    CanonicalToolCatalogBundle, ModelToolDefinition, ModelToolFamily, OperatorOnlySurfaceRecord,
    ParsedTurnToolExecutionBatch, ParsedTurnToolExecutionReceipt, ToolArgumentSchemaRecord,
    ToolCallLegalityRecord, ToolCatalogRecord, ToolContextField, ToolExecutionBundle,
    ToolExecutionContextRecord, ToolExecutionDecision, ToolExecutionRecord,
    ToolExposureDecisionRecord, ToolMembraneError, ToolResultSchemaRecord,
    ToolServiceExecutionOutcome, build_canonical_tool_catalog, evaluate_tool_call_legality,
    execute_parsed_tool_intent, execute_parsed_turn_tool_intents,
    render_tool_catalog_json_for_role,
};
pub use transition::{
    TransitionError, accept_worker_result, activate_promoted_incumbent, apply_approval_decision,
    bind_session_ready, block_on_approval, checkpointed_block_on_approval,
    checkpointed_dispatch_to_worker, complete_task, conclude_turn_ready, dispatch_to_worker,
    fail_task, resume_from_approval, start_turn,
};
pub use turn_governance::{
    ModelApprovalRequestRecord, ModelApprovalResolutionAction, ModelAuthorityDecision,
    ModelAuthorityDecisionKind, ModelDelegationPolicyRecord, ModelDelegationPosture,
    ModelOutputQuarantineReasonClass, ModelOutputQuarantineRecord, PendingGovernedTurnActionRecord,
    PendingGovernedTurnActionStatus, TurnCheckpointRecord, TurnGovernanceBundle,
    TurnGovernanceError,
};
pub use turn_package::{
    ContextBudgetRecord, ContextTruncationRecord, ContinuityEntryPriority, ParseRepairClass,
    ParseRepairRecord, ParsedApprovalRequestRecord, ParsedProposalRecord,
    ParsedToolCallIntentRecord, ParsedTurnBundle, ParsedTurnResult, ParsedTurnResultStatus,
    PromptLayerKind, PromptLayerRecord, PromptRenderingRecord, TurnContinuityEntry,
    TurnContractError, TurnPackage, TurnPackageRole, TurnRenderBundle, TurnResponseSchemaFamily,
    TurnResponseSchemaRecord, parse_turn_package_output, render_turn_package,
};
pub use validation::{
    ExecutionBackedValidationRecord, ExecutionComparisonBundle, ValidationHarnessError,
    ValidationScenario, compare_packages_with_execution, compare_packages_with_execution_context,
    execute_validation_plan, execute_validation_plan_with_context, expected_execution_result_ref,
    expected_output_ref,
};
pub use worker::{
    CapabilityOperationRequest, MessageArtifact, MessageArtifactClass, MessageArtifactStatus,
    ShellWorkerDispatch, ShellWorkerResult, SynthesisClosureDecision, SynthesisHandoff, WorkerCard,
    WorkerDispatch, WorkerDispatchCheckpointOutcome, WorkerDispatchOutcome, WorkerResult,
    WorkerRole,
};
pub use worker_ecology::{
    CoordinatorPlanningRecord, EcologyHealthRecord, EcologyRecoveryRecord, EcologySnapshot,
    RoutingPacketRecord, SynthesisDossier, WorkLease, WorkerEcologyError, WorkerRoleKind,
    WorkerSpecializationCard,
};
pub use worker_world::{
    WorkerActionRequest, WorkerActionTrace, WorkerTurnExecution, WorkerWorldError, WorkerWorldKind,
    decide_worker_action, denial_from_component_error, execute_worker_turn,
    world_kind_for_capability,
};
