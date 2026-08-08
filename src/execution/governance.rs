use crate::execution::artifact::ArtifactDigest;
use crate::execution::checkpoint::RunCheckpoint;
use crate::execution::memory::{
    MemoryArtifact, MemoryArtifactClass, MemoryArtifactPayload, MemoryStore,
};
use crate::execution::replacement::{
    ClosureInventory, DimensionVerdict, EvaluationDimension, GenerationComparisonRecord,
    NativeSufficiencyEvidence, NativeSufficiencyGate, SemanticValidationRecord,
    carried_import_targets, closure_inventory_has_hidden_imports, closure_inventory_is_complete,
    evaluate_native_sufficiency_with_evidence,
};
use crate::execution::storage::ReplayableRuntimeState;
use crate::execution::{
    ApprovalClass, ApprovalRequestId, AuditRecordId, AuthorityClass, CampaignId, EpochId,
    MemoryArtifactId, QuarantineId, RollbackHandleId, SessionId, StopCondition, TaskId, TurnId,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub approval_request_id: ApprovalRequestId,
    pub campaign_id: CampaignId,
    pub epoch_id: EpochId,
    pub session_id: SessionId,
    pub task_id: TaskId,
    pub action_ref: String,
    pub scope_ref: String,
    pub requested_authority_class: AuthorityClass,
    pub status: ApprovalDecisionStatus,
}

impl ApprovalRequest {
    pub fn requested(
        approval_request_id: impl Into<ApprovalRequestId>,
        campaign_id: impl Into<CampaignId>,
        epoch_id: impl Into<EpochId>,
        session_id: impl Into<SessionId>,
        task_id: impl Into<TaskId>,
        action_ref: impl Into<String>,
        scope_ref: impl Into<String>,
        requested_authority_class: AuthorityClass,
    ) -> Self {
        Self {
            approval_request_id: approval_request_id.into(),
            campaign_id: campaign_id.into(),
            epoch_id: epoch_id.into(),
            session_id: session_id.into(),
            task_id: task_id.into(),
            action_ref: action_ref.into(),
            scope_ref: scope_ref.into(),
            requested_authority_class,
            status: ApprovalDecisionStatus::Requested,
        }
    }

    pub fn matches_decision(&self, decision: &ApprovalDecision) -> bool {
        self.approval_request_id == decision.approval_request_id
            && self.campaign_id == decision.campaign_id
            && self.epoch_id == decision.epoch_id
            && self.session_id == decision.session_id
            && self.task_id == decision.task_id
            && self.action_ref == decision.action_ref
            && self.scope_ref == decision.scope_ref
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecisionStatus {
    Requested,
    Pending,
    Granted,
    Denied,
    Expired,
    Superseded,
    Consumed,
}

impl ApprovalDecisionStatus {
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub approval_request_id: ApprovalRequestId,
    pub campaign_id: CampaignId,
    pub epoch_id: EpochId,
    pub session_id: SessionId,
    pub task_id: TaskId,
    pub action_ref: String,
    pub decision: ApprovalDecisionStatus,
    pub decided_by: String,
    pub scope_ref: String,
    pub notes: Option<String>,
}

impl ApprovalDecision {
    pub fn granted(
        approval_request_id: impl Into<ApprovalRequestId>,
        campaign_id: impl Into<CampaignId>,
        epoch_id: impl Into<EpochId>,
        session_id: impl Into<SessionId>,
        task_id: impl Into<TaskId>,
        action_ref: impl Into<String>,
        decided_by: impl Into<String>,
        scope_ref: impl Into<String>,
        notes: Option<String>,
    ) -> Self {
        Self {
            approval_request_id: approval_request_id.into(),
            campaign_id: campaign_id.into(),
            epoch_id: epoch_id.into(),
            session_id: session_id.into(),
            task_id: task_id.into(),
            action_ref: action_ref.into(),
            decision: ApprovalDecisionStatus::Granted,
            decided_by: decided_by.into(),
            scope_ref: scope_ref.into(),
            notes,
        }
    }

    pub fn matches_request(&self, request: &ApprovalRequest) -> bool {
        request.matches_decision(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TickSource {
    ManualResume,
    ScheduledTimer,
    QueueOrWebhookArrival,
    ApprovalResponse,
    EpochTransition,
    ConsolidationTrigger,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernancePolicyClass {
    ExecutionSafetyPolicy,
    AuthorityEscalationPolicy,
    BackgroundAutonomyPolicy,
    MemoryIntegrityPolicy,
    PromotionGovernancePolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundCampaign {
    pub campaign_id: CampaignId,
    pub objective: String,
    pub authority_ceiling: AuthorityClass,
    pub allowed_tick_sources: Vec<TickSource>,
    pub max_concurrent_sessions: usize,
    pub stop_conditions: Vec<StopCondition>,
    pub approval_policy: GovernancePolicyClass,
    pub audit_policy: GovernancePolicyClass,
}

impl BackgroundCampaign {
    pub fn allows_tick_source(&self, tick_source: &TickSource) -> bool {
        self.allowed_tick_sources
            .iter()
            .any(|allowed| allowed == tick_source)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineReasonClass {
    AuthorityExpansion,
    PolicyViolation,
    PostApprovalAnomaly,
    EvaluationMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineResolutionState {
    Open,
    Reviewing,
    Resolved,
    Retired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackHandle {
    pub rollback_handle_id: RollbackHandleId,
    pub target_scope: String,
    pub safe_state_ref: String,
    pub required_steps: Vec<String>,
    pub approval_requirements: Vec<String>,
}

pub fn create_rollback_handle(
    rollback_handle_id: impl Into<RollbackHandleId>,
    target_scope: impl Into<String>,
    safe_state_ref: impl Into<String>,
    required_steps: Vec<String>,
    approval_requirements: Vec<String>,
) -> RollbackHandle {
    RollbackHandle {
        rollback_handle_id: rollback_handle_id.into(),
        target_scope: target_scope.into(),
        safe_state_ref: safe_state_ref.into(),
        required_steps,
        approval_requirements,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub quarantine_id: QuarantineId,
    pub reason_class: QuarantineReasonClass,
    pub affected_refs: Vec<String>,
    pub rollback_handle_ref: Option<RollbackHandleId>,
    pub resolution_state: QuarantineResolutionState,
}

impl QuarantineRecord {
    pub fn blocks_ref(&self, affected_ref: &str) -> bool {
        matches!(
            self.resolution_state,
            QuarantineResolutionState::Open | QuarantineResolutionState::Reviewing
        ) && self
            .affected_refs
            .iter()
            .any(|candidate| candidate == affected_ref)
    }
}

pub fn create_quarantine_record(
    quarantine_id: impl Into<QuarantineId>,
    reason_class: QuarantineReasonClass,
    affected_refs: Vec<String>,
    rollback_handle_ref: Option<RollbackHandleId>,
) -> QuarantineRecord {
    QuarantineRecord {
        quarantine_id: quarantine_id.into(),
        reason_class,
        affected_refs,
        rollback_handle_ref,
        resolution_state: QuarantineResolutionState::Open,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GovernanceError {
    TickSourceNotAllowed {
        campaign_id: CampaignId,
        tick_source: TickSource,
    },
    MissingCheckpointForBackgroundResume {
        campaign_id: CampaignId,
    },
    InvalidApprovalsForBackgroundResume {
        campaign_id: CampaignId,
    },
    InvalidCapabilityEnvelopeForBackgroundResume {
        campaign_id: CampaignId,
    },
    InvalidRuntimeStateForBackgroundResume {
        campaign_id: CampaignId,
        reason: String,
    },
    QuarantineBlocksAction {
        quarantine_id: QuarantineId,
        affected_ref: String,
    },
}

impl Display for GovernanceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TickSourceNotAllowed {
                campaign_id,
                tick_source,
            } => write!(
                f,
                "tick source {:?} is not allowed for background campaign '{}'",
                tick_source, campaign_id
            ),
            Self::MissingCheckpointForBackgroundResume { campaign_id } => write!(
                f,
                "background campaign '{}' cannot resume without a checkpoint",
                campaign_id
            ),
            Self::InvalidApprovalsForBackgroundResume { campaign_id } => write!(
                f,
                "background campaign '{}' cannot resume with invalid approvals",
                campaign_id
            ),
            Self::InvalidCapabilityEnvelopeForBackgroundResume { campaign_id } => write!(
                f,
                "background campaign '{}' cannot resume with an invalid capability envelope",
                campaign_id
            ),
            Self::InvalidRuntimeStateForBackgroundResume {
                campaign_id,
                reason,
            } => write!(
                f,
                "background campaign '{}' cannot resume from invalid runtime state: {}",
                campaign_id, reason
            ),
            Self::QuarantineBlocksAction {
                quarantine_id,
                affected_ref,
            } => write!(
                f,
                "quarantine '{}' blocks affected ref '{}'",
                quarantine_id, affected_ref
            ),
        }
    }
}

impl Error for GovernanceError {}

pub fn validate_background_resume(
    background_campaign: &BackgroundCampaign,
    tick_source: &TickSource,
    checkpoint_ref: Option<&str>,
    approvals_valid: bool,
    envelope_valid: bool,
    quarantine_records: &[QuarantineRecord],
    affected_ref: &str,
) -> Result<(), GovernanceError> {
    if !background_campaign.allows_tick_source(tick_source) {
        return Err(GovernanceError::TickSourceNotAllowed {
            campaign_id: background_campaign.campaign_id.clone(),
            tick_source: *tick_source,
        });
    }

    if checkpoint_ref.is_none() {
        return Err(GovernanceError::MissingCheckpointForBackgroundResume {
            campaign_id: background_campaign.campaign_id.clone(),
        });
    }

    if !approvals_valid {
        return Err(GovernanceError::InvalidApprovalsForBackgroundResume {
            campaign_id: background_campaign.campaign_id.clone(),
        });
    }

    if !envelope_valid {
        return Err(
            GovernanceError::InvalidCapabilityEnvelopeForBackgroundResume {
                campaign_id: background_campaign.campaign_id.clone(),
            },
        );
    }

    if let Some(quarantine_record) = quarantine_records
        .iter()
        .find(|quarantine_record| quarantine_record.blocks_ref(affected_ref))
    {
        return Err(GovernanceError::QuarantineBlocksAction {
            quarantine_id: quarantine_record.quarantine_id.clone(),
            affected_ref: affected_ref.to_string(),
        });
    }

    Ok(())
}

pub fn validate_background_resume_with_runtime_state(
    background_campaign: &BackgroundCampaign,
    tick_source: &TickSource,
    runtime_state: &ReplayableRuntimeState,
    approval_decisions: &[ApprovalDecision],
    quarantine_records: &[QuarantineRecord],
    affected_ref: &str,
) -> Result<(), GovernanceError> {
    if runtime_state.session.header.campaign_id != background_campaign.campaign_id {
        return Err(GovernanceError::InvalidRuntimeStateForBackgroundResume {
            campaign_id: background_campaign.campaign_id.clone(),
            reason: format!(
                "runtime state campaign '{}' does not match '{}'",
                runtime_state.session.header.campaign_id, background_campaign.campaign_id
            ),
        });
    }

    runtime_state.validate_replayability().map_err(|error| {
        GovernanceError::InvalidRuntimeStateForBackgroundResume {
            campaign_id: background_campaign.campaign_id.clone(),
            reason: error.to_string(),
        }
    })?;

    let approvals_valid =
        approvals_support_background_resume(runtime_state, tick_source, approval_decisions);
    let envelope_valid = !runtime_state
        .session
        .header
        .capability_envelope_ref
        .trim()
        .is_empty();

    validate_background_resume(
        background_campaign,
        tick_source,
        runtime_state.session.latest_checkpoint_ref.as_deref(),
        approvals_valid,
        envelope_valid,
        quarantine_records,
        affected_ref,
    )
}

#[allow(dead_code)]
fn capability_envelope_related_ref(envelope_id: &str) -> String {
    format!("capability-envelope:{envelope_id}")
}

fn capability_related_ref(
    dispatch_id: &str,
    world: &str,
    operation: &str,
    resource_scope: &str,
) -> String {
    format!("capability:{dispatch_id}:{world}:{operation}:{resource_scope}")
}

fn approval_transport_related_ref(approval_request_id: &str) -> String {
    format!("approval-transport:{approval_request_id}")
}

#[allow(dead_code)]
fn background_related_ref(
    campaign_id: &str,
    tick_source: &TickSource,
    checkpoint_id: &str,
) -> String {
    format!("background:{campaign_id}:{tick_source:?}:{checkpoint_id}")
}

fn capability_related_ref_from_action(action_ref: &str, scope_ref: &str) -> Option<String> {
    let mut parts = action_ref.splitn(4, ':');
    let action_kind = parts.next()?;
    let dispatch_id = parts.next()?;
    let world = parts.next()?;
    let operation = parts.next()?;

    if action_kind != "dispatch" {
        return None;
    }

    Some(capability_related_ref(
        dispatch_id,
        world,
        operation,
        scope_ref,
    ))
}

fn append_audit_record(
    memory_store: &mut MemoryStore,
    audit_record: AuditRecord,
) -> MemoryArtifactId {
    let artifact_id = format!("memory-audit-{}", audit_record.audit_record_id);
    memory_store.append(MemoryArtifact::audit_record(
        artifact_id.clone(),
        audit_record,
    ));
    artifact_id
}

fn append_capability_audit_for_request(
    memory_store: &mut MemoryStore,
    approval_request: &ApprovalRequest,
) -> Option<MemoryArtifactId> {
    let capability_related_ref = capability_related_ref_from_action(
        &approval_request.action_ref,
        &approval_request.scope_ref,
    )?;
    let audit_record = AuditRecord::new(
        format!(
            "audit-capability-request-{}",
            approval_request.approval_request_id
        ),
        AuditRecordClass::CapabilityAuditRecord,
        approval_request.campaign_id.clone(),
        approval_request.epoch_id.clone(),
        approval_request.session_id.clone(),
        Some(approval_request.task_id.clone()),
        capability_related_ref,
        format!(
            "capability request {} is awaiting approval for {}",
            approval_request.approval_request_id, approval_request.scope_ref
        ),
    );
    Some(append_audit_record(memory_store, audit_record))
}

fn append_capability_audit_for_decision(
    memory_store: &mut MemoryStore,
    approval_decision: &ApprovalDecision,
) -> Option<MemoryArtifactId> {
    let capability_related_ref = capability_related_ref_from_action(
        &approval_decision.action_ref,
        &approval_decision.scope_ref,
    )?;
    let audit_record = AuditRecord::new(
        format!(
            "audit-capability-decision-{}",
            approval_decision.approval_request_id
        ),
        AuditRecordClass::CapabilityAuditRecord,
        approval_decision.campaign_id.clone(),
        approval_decision.epoch_id.clone(),
        approval_decision.session_id.clone(),
        Some(approval_decision.task_id.clone()),
        capability_related_ref,
        format!(
            "capability decision {} recorded as {:?} for {}",
            approval_decision.approval_request_id,
            approval_decision.decision,
            approval_decision.scope_ref
        ),
    );
    Some(append_audit_record(memory_store, audit_record))
}

#[allow(dead_code)]
fn append_background_resume_audit(
    memory_store: &mut MemoryStore,
    background_campaign: &BackgroundCampaign,
    tick_source: &TickSource,
    runtime_state: &ReplayableRuntimeState,
    affected_ref: &str,
) -> Option<MemoryArtifactId> {
    let checkpoint_id = runtime_state.session.latest_checkpoint_ref.as_deref()?;
    let audit_record = AuditRecord::new(
        format!(
            "audit-background-resume-{}-{:?}",
            background_campaign.campaign_id, tick_source
        ),
        AuditRecordClass::GovernanceAuditRecord,
        background_campaign.campaign_id.clone(),
        runtime_state.session.header.epoch_id.clone(),
        runtime_state.session.header.session_id.clone(),
        Some(affected_ref.to_string()),
        background_related_ref(&background_campaign.campaign_id, tick_source, checkpoint_id),
        format!(
            "background resume {:?} validated against checkpoint {}",
            tick_source, checkpoint_id
        ),
    );
    Some(append_audit_record(memory_store, audit_record))
}

#[allow(dead_code)]
fn append_quarantine_transition_audit(
    memory_store: &mut MemoryStore,
    quarantine_record: &QuarantineRecord,
    campaign_id: &str,
    epoch_id: &str,
    session_id: &str,
    task_id: Option<TaskId>,
    summary: impl Into<String>,
) -> MemoryArtifactId {
    let audit_record = AuditRecord::new(
        format!("audit-quarantine-{}", quarantine_record.quarantine_id),
        AuditRecordClass::GovernanceAuditRecord,
        campaign_id.to_string(),
        epoch_id.to_string(),
        session_id.to_string(),
        task_id,
        quarantine_record.quarantine_id.clone(),
        summary,
    );
    append_audit_record(memory_store, audit_record)
}

#[allow(dead_code)]
fn append_rollback_execution_audit(
    memory_store: &mut MemoryStore,
    rollback_handle: &RollbackHandle,
    runtime_state: &ReplayableRuntimeState,
) -> MemoryArtifactId {
    let audit_record = AuditRecord::new(
        format!("audit-rollback-{}", rollback_handle.rollback_handle_id),
        AuditRecordClass::PromotionAuditRecord,
        runtime_state.session.header.campaign_id.clone(),
        runtime_state.session.header.epoch_id.clone(),
        runtime_state.session.header.session_id.clone(),
        runtime_state.session.active_task_id.clone(),
        rollback_handle.rollback_handle_id.clone(),
        format!(
            "rollback {} restored checkpoint {}",
            rollback_handle.rollback_handle_id, rollback_handle.safe_state_ref
        ),
    );
    append_audit_record(memory_store, audit_record)
}

fn approvals_support_background_resume(
    runtime_state: &ReplayableRuntimeState,
    tick_source: &TickSource,
    approval_decisions: &[ApprovalDecision],
) -> bool {
    let pending_approval_refs = &runtime_state.session.pending_approval_refs;
    if pending_approval_refs.is_empty() {
        return !matches!(tick_source, TickSource::ApprovalResponse)
            && approval_decisions.is_empty();
    }

    if !matches!(tick_source, TickSource::ApprovalResponse) {
        return false;
    }

    let checkpoint_has_audit = runtime_state
        .session
        .latest_checkpoint_ref
        .as_deref()
        .is_some_and(|checkpoint_id| {
            runtime_state
                .memory_store
                .checkpoint_lineage(checkpoint_id)
                .iter()
                .any(|artifact| artifact.class == MemoryArtifactClass::AuditRecordArtifact)
        });

    pending_approval_refs.iter().all(|approval_request_id| {
        let lineage = runtime_state
            .memory_store
            .approval_lineage(approval_request_id);
        let request = lineage.iter().find_map(|artifact| match &artifact.payload {
            MemoryArtifactPayload::ApprovalRequest(request) => Some(request),
            _ => None,
        });

        request.is_some_and(|request| {
            checkpoint_has_audit
                && approval_decisions.iter().any(|decision| {
                    decision.matches_request(request) && decision.decision.is_granted()
                })
        })
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequestMemoryWrite {
    pub approval_request_artifact_id: MemoryArtifactId,
    pub audit_artifact_id: MemoryArtifactId,
    pub audit_record: AuditRecord,
}

pub fn persist_approval_request_bundle(
    memory_store: &mut MemoryStore,
    approval_request: &ApprovalRequest,
    checkpoint: &RunCheckpoint,
) -> ApprovalRequestMemoryWrite {
    let approval_request_artifact_id = format!(
        "memory-approval-request-{}",
        approval_request.approval_request_id
    );
    memory_store.append(MemoryArtifact::approval_request(
        approval_request_artifact_id.clone(),
        approval_request.clone(),
        format!(
            "approval request {} persisted for {}",
            approval_request.approval_request_id, approval_request.action_ref
        ),
    ));

    let audit_record = AuditRecord::new(
        format!(
            "audit-approval-request-{}",
            approval_request.approval_request_id
        ),
        AuditRecordClass::ApprovalAuditRecord,
        approval_request.campaign_id.clone(),
        approval_request.epoch_id.clone(),
        approval_request.session_id.clone(),
        Some(approval_request.task_id.clone()),
        checkpoint.checkpoint_id.clone(),
        format!(
            "approval request {} persisted at checkpoint {}",
            approval_request.approval_request_id, checkpoint.checkpoint_id
        ),
    );
    let audit_artifact_id = format!("memory-audit-{}", audit_record.audit_record_id);
    memory_store.append(MemoryArtifact::audit_record(
        audit_artifact_id.clone(),
        audit_record.clone(),
    ));
    append_audit_record(
        memory_store,
        AuditRecord::new(
            format!(
                "audit-approval-transport-request-{}",
                approval_request.approval_request_id
            ),
            AuditRecordClass::GovernanceAuditRecord,
            approval_request.campaign_id.clone(),
            approval_request.epoch_id.clone(),
            approval_request.session_id.clone(),
            Some(approval_request.task_id.clone()),
            approval_transport_related_ref(&approval_request.approval_request_id),
            format!(
                "approval request {} entered the native approval transport",
                approval_request.approval_request_id
            ),
        ),
    );
    let _ = append_capability_audit_for_request(memory_store, approval_request);

    ApprovalRequestMemoryWrite {
        approval_request_artifact_id,
        audit_artifact_id,
        audit_record,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditRecordClass {
    ExecutionAuditRecord,
    CapabilityAuditRecord,
    ApprovalAuditRecord,
    GovernanceAuditRecord,
    PromotionAuditRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub audit_record_id: AuditRecordId,
    pub class: AuditRecordClass,
    pub campaign_id: CampaignId,
    pub epoch_id: EpochId,
    pub session_id: SessionId,
    pub task_id: Option<TaskId>,
    pub related_ref: String,
    pub summary: String,
}

impl AuditRecord {
    pub fn new(
        audit_record_id: impl Into<AuditRecordId>,
        class: AuditRecordClass,
        campaign_id: impl Into<CampaignId>,
        epoch_id: impl Into<EpochId>,
        session_id: impl Into<SessionId>,
        task_id: Option<TaskId>,
        related_ref: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            audit_record_id: audit_record_id.into(),
            class,
            campaign_id: campaign_id.into(),
            epoch_id: epoch_id.into(),
            session_id: session_id.into(),
            task_id,
            related_ref: related_ref.into(),
            summary: summary.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionReadinessStatus {
    Reject,
    Retain,
    Promotable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionReadinessDecision {
    pub decision_id: String,
    pub comparison_id: String,
    pub challenger_ref: String,
    pub status: PromotionReadinessStatus,
    pub rationale: String,
    pub required_preconditions: Vec<String>,
    pub rollback_handle_refs: Vec<RollbackHandleId>,
    pub review_artifact_refs: Vec<String>,
    pub quarantine_refs: Vec<QuarantineId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CycleClosureDecisionStatus {
    Promote,
    Retain,
    Contain,
    Reverse,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CycleClosureDecision {
    pub decision_id: String,
    pub comparison_id: String,
    pub promotion_readiness_ref: String,
    pub successor_candidate_ref: String,
    pub status: CycleClosureDecisionStatus,
    pub rationale: String,
    pub review_artifact_refs: Vec<String>,
    pub rollback_handle_refs: Vec<RollbackHandleId>,
    pub quarantine_refs: Vec<QuarantineId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum V1CompletionStatus {
    Satisfied,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1CompletionGate {
    pub gate_id: String,
    pub closure_inventory_ref: String,
    pub cycle_closure_decision_ref: String,
    pub carried_import_refs: Vec<String>,
    pub remaining_gap_refs: Vec<String>,
    pub status: V1CompletionStatus,
    pub rationale: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionActStatus {
    Approved,
    Activated,
    Reversed,
    Contained,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionAct {
    pub promotion_act_id: String,
    pub comparison_id: String,
    pub challenger_ref: String,
    pub prior_epoch_id: EpochId,
    pub promoted_epoch_id: EpochId,
    pub successor_campaign_id: CampaignId,
    pub review_artifact_refs: Vec<String>,
    pub rollback_handle_refs: Vec<RollbackHandleId>,
    pub lineage_refs: Vec<String>,
    pub status: PromotionActStatus,
    pub rationale: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpochAdoptionStatus {
    Planned,
    Active,
    Reversed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochAdoptionRecord {
    pub adoption_id: String,
    pub promotion_act_id: String,
    pub prior_epoch_id: EpochId,
    pub promoted_epoch_id: EpochId,
    pub prior_incumbent_ref: String,
    pub promoted_incumbent_ref: String,
    pub activated_session_id: SessionId,
    pub successor_campaign_id: CampaignId,
    pub carried_artifact_refs: Vec<String>,
    pub activation_checkpoint_ref: Option<String>,
    pub status: EpochAdoptionStatus,
    pub summary: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReversalWindowStatus {
    Open,
    Reversed,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReversalWindow {
    pub reversal_window_id: String,
    pub promotion_act_id: String,
    pub promoted_epoch_id: EpochId,
    pub rollback_handle_refs: Vec<RollbackHandleId>,
    pub quarantine_refs: Vec<QuarantineId>,
    pub status: ReversalWindowStatus,
    pub summary: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReversalAction {
    KeepActive,
    ReverseToCheckpoint,
    QuarantinePromotedIncumbent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromotionError {
    NotPromotable { decision_id: String },
    MissingRollbackHandle,
    MissingReviewArtifacts,
    OpenQuarantine { quarantine_id: QuarantineId },
    InvalidEpochBoundary,
    InvalidSuccessorCampaign,
    ReversalWindowClosed { reversal_window_id: String },
}

impl Display for PromotionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPromotable { decision_id } => {
                write!(
                    f,
                    "promotion readiness decision '{decision_id}' is not promotable"
                )
            }
            Self::MissingRollbackHandle => {
                write!(f, "promotion act requires at least one rollback handle")
            }
            Self::MissingReviewArtifacts => {
                write!(
                    f,
                    "promotion act requires at least one review artifact reference"
                )
            }
            Self::OpenQuarantine { quarantine_id } => {
                write!(f, "open quarantine '{quarantine_id}' blocks promotion")
            }
            Self::InvalidEpochBoundary => {
                write!(
                    f,
                    "promotion act requires distinct prior and promoted epochs"
                )
            }
            Self::InvalidSuccessorCampaign => {
                write!(
                    f,
                    "promotion act requires a non-empty successor campaign id"
                )
            }
            Self::ReversalWindowClosed { reversal_window_id } => write!(
                f,
                "reversal window '{}' is no longer open",
                reversal_window_id
            ),
        }
    }
}

impl Error for PromotionError {}

pub fn open_promotion_act(
    promotion_act_id: impl Into<String>,
    decision: &PromotionReadinessDecision,
    comparison: &GenerationComparisonRecord,
    prior_epoch_id: impl Into<EpochId>,
    promoted_epoch_id: impl Into<EpochId>,
    successor_campaign_id: impl Into<CampaignId>,
    lineage_refs: Vec<String>,
) -> Result<PromotionAct, PromotionError> {
    if decision.status != PromotionReadinessStatus::Promotable {
        return Err(PromotionError::NotPromotable {
            decision_id: decision.decision_id.clone(),
        });
    }
    if decision.rollback_handle_refs.is_empty() {
        return Err(PromotionError::MissingRollbackHandle);
    }
    if decision.review_artifact_refs.is_empty() {
        return Err(PromotionError::MissingReviewArtifacts);
    }
    if let Some(quarantine_id) = decision.quarantine_refs.first() {
        return Err(PromotionError::OpenQuarantine {
            quarantine_id: quarantine_id.clone(),
        });
    }

    let prior_epoch_id = prior_epoch_id.into();
    let promoted_epoch_id = promoted_epoch_id.into();
    if prior_epoch_id == promoted_epoch_id {
        return Err(PromotionError::InvalidEpochBoundary);
    }

    let successor_campaign_id = successor_campaign_id.into();
    if successor_campaign_id.trim().is_empty() {
        return Err(PromotionError::InvalidSuccessorCampaign);
    }

    Ok(PromotionAct {
        promotion_act_id: promotion_act_id.into(),
        comparison_id: comparison.comparison_id.clone(),
        challenger_ref: decision.challenger_ref.clone(),
        prior_epoch_id,
        promoted_epoch_id,
        successor_campaign_id,
        review_artifact_refs: decision.review_artifact_refs.clone(),
        rollback_handle_refs: decision.rollback_handle_refs.clone(),
        lineage_refs,
        status: PromotionActStatus::Approved,
        rationale: format!(
            "promotion act opened from promotable challenger {}",
            decision.challenger_ref
        ),
    })
}

pub fn plan_epoch_adoption(
    adoption_id: impl Into<String>,
    promotion_act: &PromotionAct,
    prior_incumbent_ref: impl Into<String>,
    promoted_incumbent_ref: impl Into<String>,
    activated_session_id: impl Into<SessionId>,
    carried_artifact_refs: Vec<String>,
    summary: impl Into<String>,
) -> EpochAdoptionRecord {
    EpochAdoptionRecord {
        adoption_id: adoption_id.into(),
        promotion_act_id: promotion_act.promotion_act_id.clone(),
        prior_epoch_id: promotion_act.prior_epoch_id.clone(),
        promoted_epoch_id: promotion_act.promoted_epoch_id.clone(),
        prior_incumbent_ref: prior_incumbent_ref.into(),
        promoted_incumbent_ref: promoted_incumbent_ref.into(),
        activated_session_id: activated_session_id.into(),
        successor_campaign_id: promotion_act.successor_campaign_id.clone(),
        carried_artifact_refs,
        activation_checkpoint_ref: None,
        status: EpochAdoptionStatus::Planned,
        summary: summary.into(),
    }
}

pub fn mark_epoch_adoption_active(
    adoption_record: &mut EpochAdoptionRecord,
    activation_checkpoint_ref: impl Into<String>,
) {
    adoption_record.activation_checkpoint_ref = Some(activation_checkpoint_ref.into());
    adoption_record.status = EpochAdoptionStatus::Active;
}

pub fn mark_epoch_adoption_reversed(adoption_record: &mut EpochAdoptionRecord) {
    adoption_record.status = EpochAdoptionStatus::Reversed;
}

pub fn open_reversal_window(
    reversal_window_id: impl Into<String>,
    promotion_act: &PromotionAct,
    rollback_handles: &[RollbackHandle],
    quarantine_records: &[QuarantineRecord],
    summary: impl Into<String>,
) -> Result<ReversalWindow, PromotionError> {
    if rollback_handles.is_empty() {
        return Err(PromotionError::MissingRollbackHandle);
    }

    Ok(ReversalWindow {
        reversal_window_id: reversal_window_id.into(),
        promotion_act_id: promotion_act.promotion_act_id.clone(),
        promoted_epoch_id: promotion_act.promoted_epoch_id.clone(),
        rollback_handle_refs: rollback_handles
            .iter()
            .map(|handle| handle.rollback_handle_id.clone())
            .collect(),
        quarantine_refs: quarantine_records
            .iter()
            .filter(|record| {
                matches!(
                    record.resolution_state,
                    QuarantineResolutionState::Open | QuarantineResolutionState::Reviewing
                )
            })
            .map(|record| record.quarantine_id.clone())
            .collect(),
        status: ReversalWindowStatus::Open,
        summary: summary.into(),
    })
}

pub fn evaluate_reversal_window(
    reversal_window: &ReversalWindow,
    quarantine_records: &[QuarantineRecord],
    affected_ref: &str,
) -> Result<ReversalAction, PromotionError> {
    if reversal_window.status != ReversalWindowStatus::Open {
        return Err(PromotionError::ReversalWindowClosed {
            reversal_window_id: reversal_window.reversal_window_id.clone(),
        });
    }

    if quarantine_records
        .iter()
        .any(|record| record.blocks_ref(affected_ref))
    {
        if reversal_window.rollback_handle_refs.is_empty() {
            return Ok(ReversalAction::QuarantinePromotedIncumbent);
        }
        return Ok(ReversalAction::ReverseToCheckpoint);
    }

    Ok(ReversalAction::KeepActive)
}

pub fn mark_promotion_activated(promotion_act: &mut PromotionAct) {
    promotion_act.status = PromotionActStatus::Activated;
}

pub fn mark_promotion_reversed(promotion_act: &mut PromotionAct) {
    promotion_act.status = PromotionActStatus::Reversed;
}

pub fn mark_reversal_window_reversed(reversal_window: &mut ReversalWindow) {
    reversal_window.status = ReversalWindowStatus::Reversed;
}

pub fn decide_promotion_readiness(
    decision_id: impl Into<String>,
    comparison: &GenerationComparisonRecord,
    sufficiency_gate: &NativeSufficiencyGate,
    sufficiency_evidence: &NativeSufficiencyEvidence,
    rollback_handles: &[RollbackHandle],
    review_artifact_refs: &[String],
    quarantine_records: &[QuarantineRecord],
) -> PromotionReadinessDecision {
    let quarantine_refs = quarantine_records
        .iter()
        .filter(|record| {
            matches!(
                record.resolution_state,
                QuarantineResolutionState::Open | QuarantineResolutionState::Reviewing
            ) && (record.blocks_ref(&comparison.challenger_ref)
                || record.blocks_ref(&comparison.comparison_id))
        })
        .map(|record| record.quarantine_id.clone())
        .collect::<Vec<_>>();

    let critical_failure = comparison.dimension_scores.iter().any(|score| {
        matches!(
            score.dimension,
            EvaluationDimension::SemanticCorrectness
                | EvaluationDimension::GovernanceFidelity
                | EvaluationDimension::Replayability
                | EvaluationDimension::ReplacementSafety
        ) && matches!(
            score.verdict,
            DimensionVerdict::ChallengerWorse | DimensionVerdict::InsufficientEvidence
        )
    });

    let evidence_ok = evaluate_native_sufficiency_with_evidence(
        sufficiency_gate,
        comparison,
        sufficiency_evidence,
    );
    let rollback_handle_refs = rollback_handles
        .iter()
        .map(|handle| handle.rollback_handle_id.clone())
        .collect::<Vec<_>>();

    let mut required_preconditions = Vec::new();
    if !evidence_ok {
        required_preconditions.push("complete native-sufficiency evidence".to_string());
    }
    if rollback_handle_refs.is_empty() {
        required_preconditions.push("attach rollback handle".to_string());
    }
    if review_artifact_refs.is_empty() {
        required_preconditions.push("attach review or promotion artifact refs".to_string());
    }
    if !quarantine_refs.is_empty() {
        required_preconditions.push("resolve challenger quarantine records".to_string());
    }

    let (status, rationale) = if !quarantine_refs.is_empty() || critical_failure {
        (
            PromotionReadinessStatus::Reject,
            "challenger evaluation failed governance or critical comparison checks".to_string(),
        )
    } else if !required_preconditions.is_empty() {
        (
            PromotionReadinessStatus::Retain,
            "challenger retained pending evidence, review, or rollback completeness".to_string(),
        )
    } else {
        (
            PromotionReadinessStatus::Promotable,
            "challenger is promotion-ready but live promotion remains deferred".to_string(),
        )
    };

    PromotionReadinessDecision {
        decision_id: decision_id.into(),
        comparison_id: comparison.comparison_id.clone(),
        challenger_ref: comparison.challenger_ref.clone(),
        status,
        rationale,
        required_preconditions,
        rollback_handle_refs,
        review_artifact_refs: review_artifact_refs.to_vec(),
        quarantine_refs,
    }
}

pub fn decide_cycle_closure(
    decision_id: impl Into<String>,
    promotion_readiness: &PromotionReadinessDecision,
    comparison: &GenerationComparisonRecord,
    rollback_handles: &[RollbackHandle],
    quarantine_records: &[QuarantineRecord],
) -> CycleClosureDecision {
    let quarantine_refs = quarantine_records
        .iter()
        .filter(|record| {
            matches!(
                record.resolution_state,
                QuarantineResolutionState::Open | QuarantineResolutionState::Reviewing
            ) && (record.blocks_ref(&comparison.challenger_ref)
                || record.blocks_ref(&comparison.comparison_id))
        })
        .map(|record| record.quarantine_id.clone())
        .collect::<Vec<_>>();

    let status = if !quarantine_refs.is_empty() {
        CycleClosureDecisionStatus::Contain
    } else {
        match promotion_readiness.status {
            PromotionReadinessStatus::Promotable => CycleClosureDecisionStatus::Promote,
            PromotionReadinessStatus::Retain => CycleClosureDecisionStatus::Retain,
            PromotionReadinessStatus::Reject => {
                if rollback_handles.is_empty() {
                    CycleClosureDecisionStatus::Contain
                } else {
                    CycleClosureDecisionStatus::Reverse
                }
            }
        }
    };

    let rationale = match status {
        CycleClosureDecisionStatus::Promote => format!(
            "successor {} is promotable under bounded second-cycle governance",
            promotion_readiness.challenger_ref
        ),
        CycleClosureDecisionStatus::Retain => format!(
            "successor {} is retained with sufficient evidence for bounded v1 closure",
            promotion_readiness.challenger_ref
        ),
        CycleClosureDecisionStatus::Contain => format!(
            "successor {} remains contained due to quarantine or incomplete safety evidence",
            promotion_readiness.challenger_ref
        ),
        CycleClosureDecisionStatus::Reverse => format!(
            "successor {} must be reversed under bounded second-cycle rollback rules",
            promotion_readiness.challenger_ref
        ),
    };

    CycleClosureDecision {
        decision_id: decision_id.into(),
        comparison_id: comparison.comparison_id.clone(),
        promotion_readiness_ref: promotion_readiness.decision_id.clone(),
        successor_candidate_ref: promotion_readiness.challenger_ref.clone(),
        status,
        rationale,
        review_artifact_refs: promotion_readiness.review_artifact_refs.clone(),
        rollback_handle_refs: rollback_handles
            .iter()
            .map(|handle| handle.rollback_handle_id.clone())
            .collect(),
        quarantine_refs,
    }
}

pub fn evaluate_v1_completion_gate(
    gate_id: impl Into<String>,
    closure_inventory: &ClosureInventory,
    semantic_validation_record: &SemanticValidationRecord,
    cycle_closure_decision: &CycleClosureDecision,
) -> V1CompletionGate {
    let status = if closure_inventory_is_complete(closure_inventory)
        && !closure_inventory_has_hidden_imports(closure_inventory)
        && semantic_validation_record.passed
        && matches!(
            cycle_closure_decision.status,
            CycleClosureDecisionStatus::Promote | CycleClosureDecisionStatus::Retain
        ) {
        V1CompletionStatus::Satisfied
    } else {
        V1CompletionStatus::Incomplete
    };

    let rationale = match status {
        V1CompletionStatus::Satisfied => format!(
            "bounded v1 completion gate satisfied by {} with explicit carried imports {:?}",
            cycle_closure_decision.successor_candidate_ref,
            carried_import_targets(closure_inventory)
        ),
        V1CompletionStatus::Incomplete => format!(
            "bounded v1 completion gate remains incomplete for {}",
            cycle_closure_decision.successor_candidate_ref
        ),
    };

    V1CompletionGate {
        gate_id: gate_id.into(),
        closure_inventory_ref: closure_inventory.inventory_id.clone(),
        cycle_closure_decision_ref: cycle_closure_decision.decision_id.clone(),
        carried_import_refs: carried_import_targets(closure_inventory),
        remaining_gap_refs: closure_inventory.remaining_gap_refs.clone(),
        status,
        rationale,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecisionMemoryWrite {
    pub approval_decision_artifact_id: MemoryArtifactId,
    pub audit_artifact_ids: Vec<MemoryArtifactId>,
}

pub fn persist_approval_decision_bundle(
    memory_store: &mut MemoryStore,
    approval_decision: &ApprovalDecision,
    audit_records: &[AuditRecord],
) -> ApprovalDecisionMemoryWrite {
    let approval_decision_artifact_id = format!(
        "memory-approval-decision-{}",
        approval_decision.approval_request_id
    );
    memory_store.append(MemoryArtifact::approval_decision(
        approval_decision_artifact_id.clone(),
        approval_decision.clone(),
        format!(
            "approval decision {} recorded as {:?}",
            approval_decision.approval_request_id, approval_decision.decision
        ),
    ));

    let mut audit_artifact_ids = Vec::with_capacity(audit_records.len());
    for audit_record in audit_records {
        let artifact_id = append_audit_record(memory_store, audit_record.clone());
        audit_artifact_ids.push(artifact_id);
    }
    audit_artifact_ids.push(append_audit_record(
        memory_store,
        AuditRecord::new(
            format!(
                "audit-approval-transport-decision-{}",
                approval_decision.approval_request_id
            ),
            AuditRecordClass::GovernanceAuditRecord,
            approval_decision.campaign_id.clone(),
            approval_decision.epoch_id.clone(),
            approval_decision.session_id.clone(),
            Some(approval_decision.task_id.clone()),
            approval_transport_related_ref(&approval_decision.approval_request_id),
            format!(
                "approval decision {} moved through the native approval transport as {:?}",
                approval_decision.approval_request_id, approval_decision.decision
            ),
        ),
    ));
    if let Some(capability_audit_id) =
        append_capability_audit_for_decision(memory_store, approval_decision)
    {
        audit_artifact_ids.push(capability_audit_id);
    }

    ApprovalDecisionMemoryWrite {
        approval_decision_artifact_id,
        audit_artifact_ids,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum V3SubstrateCompletionStatus {
    Satisfied,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V3SubstrateCompletionEvidence {
    pub artifact_digest: ArtifactDigest,
    pub package_digest: ArtifactDigest,
    pub component_build_ref: String,
    pub validation_trace_ref: String,
    pub comparison_ref: String,
    pub activation_ref: String,
    pub rollback_ref: String,
    pub successor_campaign_ref: String,
    pub successor_digest: ArtifactDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V3SubstrateCompletionGate {
    pub gate_id: String,
    pub evidence: V3SubstrateCompletionEvidence,
    pub status: V3SubstrateCompletionStatus,
    pub missing_evidence_refs: Vec<String>,
    pub claim: String,
    pub anti_overclaim_boundary: String,
}

pub fn evaluate_v3_substrate_completion_gate(
    gate_id: impl Into<String>,
    evidence: V3SubstrateCompletionEvidence,
) -> V3SubstrateCompletionGate {
    let mut missing_evidence_refs = Vec::new();
    for (label, value) in [
        ("component-build", evidence.component_build_ref.as_str()),
        ("validation-trace", evidence.validation_trace_ref.as_str()),
        ("comparison", evidence.comparison_ref.as_str()),
        ("activation", evidence.activation_ref.as_str()),
        ("rollback", evidence.rollback_ref.as_str()),
        (
            "successor-campaign",
            evidence.successor_campaign_ref.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            missing_evidence_refs.push(label.to_string());
        }
    }

    let status = if missing_evidence_refs.is_empty()
        && evidence.artifact_digest.as_str() != evidence.package_digest.as_str()
        && evidence.package_digest.as_str() != evidence.successor_digest.as_str()
    {
        V3SubstrateCompletionStatus::Satisfied
    } else {
        if evidence.artifact_digest.as_str() == evidence.package_digest.as_str() {
            missing_evidence_refs.push("distinct-package-digest".to_string());
        }
        if evidence.package_digest.as_str() == evidence.successor_digest.as_str() {
            missing_evidence_refs.push("distinct-successor-digest".to_string());
        }
        V3SubstrateCompletionStatus::Blocked
    };

    V3SubstrateCompletionGate {
        gate_id: gate_id.into(),
        evidence,
        status,
        missing_evidence_refs,
        claim: match status {
            V3SubstrateCompletionStatus::Satisfied => {
                "bounded single-factory v3 substrate complete".to_string()
            }
            V3SubstrateCompletionStatus::Blocked => {
                "bounded single-factory v3 substrate incomplete".to_string()
            }
        },
        anti_overclaim_boundary:
            "does not claim federation, hosted autonomy, or cross-repository replacement"
                .to_string(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellActionDecisionStatus {
    Allowed,
    ApprovalRequired,
    Denied,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellActionDecision {
    pub decision_id: String,
    pub shell_session_id: String,
    pub shell_turn_id: TurnId,
    pub action_ref: String,
    pub status: ShellActionDecisionStatus,
    pub approval_class: Option<ApprovalClass>,
    pub rationale: String,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellApprovalPauseRecord {
    pub pause_id: String,
    pub shell_session_id: String,
    pub shell_turn_id: TurnId,
    pub approval_request_ref: ApprovalRequestId,
    pub checkpoint_ref: String,
    pub rationale: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellDenialPacket {
    pub denial_id: String,
    pub shell_session_id: String,
    pub shell_turn_id: TurnId,
    pub action_ref: String,
    pub status: ShellActionDecisionStatus,
    pub rationale: String,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum V4SupervisoryShellCompletionStatus {
    Satisfied,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V4SupervisoryShellCompletionEvidence {
    pub shell_session_bundle_ref: String,
    pub shell_evidence_packet_ref: String,
    pub shell_session_ref: String,
    pub pause_resume_refs: Vec<String>,
    pub membrane_trace_refs: Vec<String>,
    pub memory_trace_refs: Vec<String>,
    pub verified_memory_refs: Vec<String>,
    pub orchestration_trace_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V4SupervisoryShellCompletionGate {
    pub gate_id: String,
    pub evidence: V4SupervisoryShellCompletionEvidence,
    pub status: V4SupervisoryShellCompletionStatus,
    pub missing_evidence_refs: Vec<String>,
    pub claim: String,
    pub anti_overclaim_boundary: String,
}

pub fn evaluate_v4_supervisory_shell_completion_gate(
    gate_id: impl Into<String>,
    evidence: V4SupervisoryShellCompletionEvidence,
) -> V4SupervisoryShellCompletionGate {
    let mut missing_evidence_refs = Vec::new();

    for (label, value) in [
        (
            "shell-session-bundle",
            evidence.shell_session_bundle_ref.as_str(),
        ),
        (
            "shell-evidence-packet",
            evidence.shell_evidence_packet_ref.as_str(),
        ),
        ("shell-session", evidence.shell_session_ref.as_str()),
    ] {
        if value.trim().is_empty() {
            missing_evidence_refs.push(label.to_string());
        }
    }

    for (label, refs) in [
        ("pause-resume", &evidence.pause_resume_refs),
        ("membrane-traces", &evidence.membrane_trace_refs),
        ("memory-traces", &evidence.memory_trace_refs),
        ("verified-memory", &evidence.verified_memory_refs),
        ("orchestration-traces", &evidence.orchestration_trace_refs),
    ] {
        if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
            missing_evidence_refs.push(label.to_string());
        }
    }

    let status = if missing_evidence_refs.is_empty() {
        V4SupervisoryShellCompletionStatus::Satisfied
    } else {
        V4SupervisoryShellCompletionStatus::Blocked
    };

    V4SupervisoryShellCompletionGate {
        gate_id: gate_id.into(),
        evidence,
        status,
        missing_evidence_refs,
        claim: match status {
            V4SupervisoryShellCompletionStatus::Satisfied => {
                "bounded single-factory component-native v4 supervisory shell complete"
                    .to_string()
            }
            V4SupervisoryShellCompletionStatus::Blocked => {
                "bounded single-factory component-native v4 supervisory shell incomplete"
                    .to_string()
            }
        },
        anti_overclaim_boundary:
            "does not claim richer tool worlds, hosted autonomy, persistent daemon operation, or federation"
                .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use crate::execution::checkpoint::RunCheckpoint;
    use crate::execution::events::{EventFamily, ExecutionEvent};
    use crate::execution::failure_budget::FailureBudget;
    use crate::execution::memory::{MemoryArtifactClass, MemoryArtifactPayload, MemoryStore};
    use crate::execution::orchestration::TaskGraph;
    use crate::execution::replacement::{
        CapabilityClosureEntry, CapabilityClosureStatus, CapabilityDependencyMode,
        CapabilityImportTarget, DimensionVerdict, EvaluationDimension, EvaluationDimensionScore,
        GenerationComparisonRecord, NativeReplacementTier, NativeSufficiencyEvidence,
        NativeSufficiencyGate, build_closure_inventory, build_successor_genome,
        materialize_successor_phenotype, validate_semantic_phenotype,
    };
    use crate::execution::session::{
        ActorKind, ExecutionSession, ExecutionSessionHeader, ExecutionSessionState,
    };
    use crate::execution::storage::ReplayableRuntimeState;
    use crate::execution::task::{TaskArtifact, TaskState};
    use crate::execution::{BlockedReason, BlockedReasonKind};

    use super::{
        ApprovalDecision, ApprovalDecisionStatus, ApprovalRequest, AuditRecord, AuditRecordClass,
        BackgroundCampaign, CycleClosureDecisionStatus, EpochAdoptionStatus, GovernanceError,
        GovernancePolicyClass, PromotionActStatus, PromotionError, PromotionReadinessStatus,
        QuarantineReasonClass, QuarantineResolutionState, ReversalAction, ReversalWindowStatus,
        TickSource, V1CompletionStatus, append_background_resume_audit,
        append_quarantine_transition_audit, append_rollback_execution_audit,
        create_quarantine_record, create_rollback_handle, decide_cycle_closure,
        decide_promotion_readiness, evaluate_reversal_window, evaluate_v1_completion_gate,
        mark_epoch_adoption_active, mark_epoch_adoption_reversed, mark_promotion_activated,
        mark_promotion_reversed, mark_reversal_window_reversed, open_promotion_act,
        open_reversal_window, persist_approval_decision_bundle, persist_approval_request_bundle,
        plan_epoch_adoption, validate_background_resume,
        validate_background_resume_with_runtime_state,
    };

    fn checkpoint(session_id: &str) -> RunCheckpoint {
        let session = ExecutionSession::new(ExecutionSessionHeader {
            session_id: session_id.to_string(),
            actor_kind: ActorKind::Supervisor,
            actor_id: "supervisor-alpha".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            capability_envelope_ref: "envelope-1".to_string(),
            parent_session_id: None,
        });

        RunCheckpoint::capture(
            "checkpoint-1",
            &session,
            None,
            Vec::new(),
            vec!["pointer-index".to_string()],
            FailureBudget::default().snapshot(),
            Vec::new(),
        )
    }

    fn approval_blocked_runtime_state(memory_store: MemoryStore) -> ReplayableRuntimeState {
        let mut session = ExecutionSession::new(ExecutionSessionHeader {
            session_id: "session-1".to_string(),
            actor_kind: ActorKind::Supervisor,
            actor_id: "supervisor-alpha".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            capability_envelope_ref: "envelope-1".to_string(),
            parent_session_id: None,
        });
        session.state = ExecutionSessionState::AwaitingApproval;
        session.active_task_id = Some("task-1".to_string());
        session.pending_approval_refs.push("approval-1".to_string());
        session.blocked_reason = Some(BlockedReason::new(
            BlockedReasonKind::Approval,
            "approval required for bounded continuation",
        ));

        let mut root_task = TaskArtifact::new("task-1", "Bounded background resume flow");
        root_task.state = TaskState::BlockedOnApproval;
        root_task.owner_session_id = Some(session.header.session_id.clone());
        root_task.blocked_reason = session.blocked_reason.clone();

        let checkpoint = RunCheckpoint::capture(
            "checkpoint-1",
            &session,
            Some(&root_task),
            Vec::new(),
            vec!["pointer-index".to_string()],
            FailureBudget::default().snapshot(),
            vec!["approval-1".to_string()],
        );
        session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());

        ReplayableRuntimeState::new(
            session,
            root_task,
            TaskGraph::new("task-1", Vec::new()),
            memory_store,
            Some(checkpoint),
            vec![ExecutionEvent::new(
                "event-checkpoint-1",
                EventFamily::CheckpointEvent,
                "campaign-1",
                "epoch-1",
                "session-1",
                None,
                Some("task-1".to_string()),
                "approval checkpoint captured",
            )],
        )
    }

    fn challenger_comparison(verdict: DimensionVerdict) -> GenerationComparisonRecord {
        GenerationComparisonRecord {
            comparison_id: "comparison-1".to_string(),
            target: CapabilityImportTarget::NativeSupervisorChallenger,
            replacement_tier: NativeReplacementTier::NativeSupervisorChallengers,
            incumbent_ref: "session-incumbent".to_string(),
            challenger_ref: "session-challenger".to_string(),
            shared_input_refs: vec!["shared-input-1".to_string()],
            imported_provider: crate::execution::ProviderKind::Imported,
            native_provider: crate::execution::ProviderKind::Native,
            imported_output_refs: vec!["incumbent-output-1".to_string()],
            native_output_refs: vec!["challenger-output-1".to_string()],
            dimension_scores: vec![
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::SemanticCorrectness,
                    verdict,
                    incumbent_summary: "incumbent semantic baseline".to_string(),
                    challenger_summary: "challenger semantic result".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::GovernanceFidelity,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "incumbent governance baseline".to_string(),
                    challenger_summary: "challenger governance result".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::Replayability,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "incumbent replay baseline".to_string(),
                    challenger_summary: "challenger replay result".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::OperatorBurden,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "incumbent operator burden baseline".to_string(),
                    challenger_summary: "challenger operator burden result".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::BoundaryCost,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "incumbent boundary cost baseline".to_string(),
                    challenger_summary: "challenger boundary cost result".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::ReplacementSafety,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "incumbent rollback baseline".to_string(),
                    challenger_summary: "challenger rollback result".to_string(),
                },
            ],
            matched: !matches!(
                verdict,
                DimensionVerdict::ChallengerWorse | DimensionVerdict::InsufficientEvidence
            ),
            summary: "challenger comparison".to_string(),
        }
    }

    fn sufficiency_gate() -> NativeSufficiencyGate {
        NativeSufficiencyGate {
            target: CapabilityImportTarget::NativeSupervisorChallenger,
            required_tier: NativeReplacementTier::NativeSupervisorChallengers,
            requires_exact_match: true,
        }
    }

    fn sufficiency_evidence(complete: bool) -> NativeSufficiencyEvidence {
        NativeSufficiencyEvidence {
            evidence_id: "evidence-1".to_string(),
            target: CapabilityImportTarget::NativeSupervisorChallenger,
            achieved_tier: NativeReplacementTier::NativeSupervisorChallengers,
            artifact_refs: vec!["review-artifact-1".to_string()],
            checkpoint_refs: vec!["checkpoint-1".to_string()],
            audit_refs: vec!["audit-1".to_string()],
            summary: "challenger evidence".to_string(),
            complete,
        }
    }

    fn full_closure_inventory_entries() -> Vec<CapabilityClosureEntry> {
        vec![
            CapabilityClosureEntry {
                target: CapabilityImportTarget::TranscriptRetrieval,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:memory-access".to_string()),
                audit_ref: Some("audit-memory-access".to_string()),
                rationale: "transcript retrieval is native".to_string(),
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
                rationale: "model hosting remains a governed carried import".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::WorktreeHostAdapter,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:worktree-host-adapter".to_string()),
                audit_ref: Some("audit-worktree-host-adapter".to_string()),
                rationale: "worktree host adapter is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::EnvironmentBridge,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:environment-bridge".to_string()),
                audit_ref: Some("audit-environment-bridge".to_string()),
                rationale: "environment bridge is native".to_string(),
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
                rationale: "artifact packaging is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::NativeSupervisorChallenger,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:native-supervisor-challenger".to_string()),
                audit_ref: Some("audit-native-supervisor-challenger".to_string()),
                rationale: "native supervisor challenger evaluation is closed".to_string(),
            },
        ]
    }

    fn promotable_decision() -> crate::execution::PromotionReadinessDecision {
        decide_promotion_readiness(
            "promotion-readiness-1",
            &challenger_comparison(DimensionVerdict::Equivalent),
            &sufficiency_gate(),
            &sufficiency_evidence(true),
            &[create_rollback_handle(
                "rollback-1",
                "shadow-campaign",
                "checkpoint-incumbent-1",
                vec!["restore checkpoint".to_string()],
                Vec::new(),
            )],
            &["review-artifact-1".to_string()],
            &[],
        )
    }

    #[test]
    fn approval_request_bundle_persists_request_and_audit_artifacts() {
        let mut memory_store = MemoryStore::default();
        let approval_request = ApprovalRequest::requested(
            "approval-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "dispatch:dispatch-1:WorkspaceObserve:search",
            "workspace-root",
            crate::execution::AuthorityClass::Observe,
        );

        let write = persist_approval_request_bundle(
            &mut memory_store,
            &approval_request,
            &checkpoint("session-1"),
        );

        assert_eq!(memory_store.artifacts.len(), 4);
        assert_eq!(
            memory_store
                .get(&write.approval_request_artifact_id)
                .expect("approval request artifact should be persisted")
                .class,
            MemoryArtifactClass::ApprovalRequestArtifact
        );
        assert_eq!(
            memory_store
                .get(&write.audit_artifact_id)
                .expect("approval audit artifact should be persisted")
                .class,
            MemoryArtifactClass::AuditRecordArtifact
        );
        assert_eq!(
            write.audit_record.class,
            AuditRecordClass::ApprovalAuditRecord
        );
        assert!(
            memory_store
                .artifacts_for_related_ref(
                    "capability:dispatch-1:WorkspaceObserve:search:workspace-root"
                )
                .iter()
                .any(|artifact| matches!(
                    artifact.payload,
                    MemoryArtifactPayload::AuditRecord(ref audit_record)
                        if audit_record.class == AuditRecordClass::CapabilityAuditRecord
                ))
        );
        assert!(
            memory_store
                .artifacts_for_related_ref("approval-transport:approval-1")
                .iter()
                .any(|artifact| matches!(
                    artifact.payload,
                    MemoryArtifactPayload::AuditRecord(ref audit_record)
                        if audit_record.class == AuditRecordClass::GovernanceAuditRecord
                ))
        );
    }

    #[test]
    fn approval_decision_bundle_persists_decision_and_audits() {
        let mut memory_store = MemoryStore::default();
        let approval_decision = ApprovalDecision::granted(
            "approval-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "workspace-root",
            "operator-1",
            "workspace-root",
            Some("approved".to_string()),
        );
        let audit_records = vec![
            AuditRecord::new(
                "audit-approval-1",
                AuditRecordClass::ApprovalAuditRecord,
                "campaign-1",
                "epoch-1",
                "session-1",
                Some("task-1".to_string()),
                "approval-1",
                "approval granted",
            ),
            AuditRecord::new(
                "audit-governance-1",
                AuditRecordClass::GovernanceAuditRecord,
                "campaign-1",
                "epoch-1",
                "session-1",
                Some("task-1".to_string()),
                "workspace-root",
                "governance recorded",
            ),
        ];

        let write =
            persist_approval_decision_bundle(&mut memory_store, &approval_decision, &audit_records);

        assert_eq!(memory_store.artifacts.len(), 4);
        assert_eq!(
            memory_store
                .get(&write.approval_decision_artifact_id)
                .expect("approval decision artifact should be persisted")
                .class,
            MemoryArtifactClass::ApprovalDecisionArtifact
        );
        assert_eq!(write.audit_artifact_ids.len(), 3);
        assert!(write.audit_artifact_ids.iter().all(|artifact_id| matches!(
                memory_store
                    .get(artifact_id)
                    .expect("audit artifact should be persisted")
                    .class,
                MemoryArtifactClass::AuditRecordArtifact
            )));
        assert_eq!(approval_decision.decision, ApprovalDecisionStatus::Granted);
        assert!(
            memory_store
                .artifacts_for_related_ref("approval-transport:approval-1")
                .iter()
                .any(|artifact| matches!(
                    artifact.payload,
                    MemoryArtifactPayload::AuditRecord(ref audit_record)
                        if audit_record.class == AuditRecordClass::GovernanceAuditRecord
                ))
        );
    }

    #[test]
    fn approval_decision_bundle_persists_capability_audit_for_dispatch_action() {
        let mut memory_store = MemoryStore::default();
        let approval_decision = ApprovalDecision::granted(
            "approval-dispatch-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "dispatch:dispatch-1:WorkspaceObserve:search",
            "operator-1",
            "workspace-root",
            Some("approved".to_string()),
        );

        let write = persist_approval_decision_bundle(&mut memory_store, &approval_decision, &[]);

        assert_eq!(write.audit_artifact_ids.len(), 2);
        assert!(
            memory_store
                .artifacts_for_related_ref(
                    "capability:dispatch-1:WorkspaceObserve:search:workspace-root"
                )
                .iter()
                .any(|artifact| matches!(
                    artifact.payload,
                    MemoryArtifactPayload::AuditRecord(ref audit_record)
                        if audit_record.class == AuditRecordClass::CapabilityAuditRecord
                ))
        );
        assert!(
            memory_store
                .artifacts_for_related_ref("approval-transport:approval-dispatch-1")
                .iter()
                .any(|artifact| matches!(
                    artifact.payload,
                    MemoryArtifactPayload::AuditRecord(ref audit_record)
                        if audit_record.class == AuditRecordClass::GovernanceAuditRecord
                ))
        );
    }

    #[test]
    fn background_resume_accepts_approval_response_tick_when_state_is_valid() {
        let background_campaign = BackgroundCampaign {
            campaign_id: "campaign-1".to_string(),
            objective: "resume approval-blocked bounded flow".to_string(),
            authority_ceiling: crate::execution::AuthorityClass::Observe,
            allowed_tick_sources: vec![TickSource::ApprovalResponse],
            max_concurrent_sessions: 1,
            stop_conditions: vec![crate::execution::StopCondition::ExplicitTaskCompletion],
            approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
            audit_policy: GovernancePolicyClass::ExecutionSafetyPolicy,
        };

        validate_background_resume(
            &background_campaign,
            &TickSource::ApprovalResponse,
            Some("checkpoint-1"),
            true,
            true,
            &[],
            "task-1",
        )
        .unwrap();
    }

    #[test]
    fn background_resume_with_runtime_state_accepts_matching_lineage_and_decision() {
        let background_campaign = BackgroundCampaign {
            campaign_id: "campaign-1".to_string(),
            objective: "resume approval-blocked bounded flow".to_string(),
            authority_ceiling: crate::execution::AuthorityClass::Observe,
            allowed_tick_sources: vec![TickSource::ApprovalResponse],
            max_concurrent_sessions: 1,
            stop_conditions: vec![crate::execution::StopCondition::ExplicitTaskCompletion],
            approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
            audit_policy: GovernancePolicyClass::ExecutionSafetyPolicy,
        };
        let approval_request = ApprovalRequest::requested(
            "approval-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "workspace-root",
            "workspace-root",
            crate::execution::AuthorityClass::Observe,
        );
        let mut memory_store = MemoryStore::default();
        let request_checkpoint = checkpoint("session-1");
        persist_approval_request_bundle(&mut memory_store, &approval_request, &request_checkpoint);
        let runtime_state = approval_blocked_runtime_state(memory_store);
        let approval_decision = ApprovalDecision::granted(
            "approval-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "workspace-root",
            "operator-1",
            "workspace-root",
            Some("approved for bounded continuation".to_string()),
        );

        validate_background_resume_with_runtime_state(
            &background_campaign,
            &TickSource::ApprovalResponse,
            &runtime_state,
            &[approval_decision],
            &[],
            "task-1",
        )
        .unwrap();
    }

    #[test]
    fn background_resume_audit_uses_deterministic_related_ref() {
        let background_campaign = BackgroundCampaign {
            campaign_id: "campaign-1".to_string(),
            objective: "resume approval-blocked bounded flow".to_string(),
            authority_ceiling: crate::execution::AuthorityClass::Observe,
            allowed_tick_sources: vec![TickSource::ApprovalResponse],
            max_concurrent_sessions: 1,
            stop_conditions: vec![crate::execution::StopCondition::ExplicitTaskCompletion],
            approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
            audit_policy: GovernancePolicyClass::ExecutionSafetyPolicy,
        };
        let approval_request = ApprovalRequest::requested(
            "approval-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "dispatch:dispatch-1:WorkspaceObserve:search",
            "workspace-root",
            crate::execution::AuthorityClass::Observe,
        );
        let mut memory_store = MemoryStore::default();
        let request_checkpoint = checkpoint("session-1");
        persist_approval_request_bundle(&mut memory_store, &approval_request, &request_checkpoint);
        let runtime_state = approval_blocked_runtime_state(memory_store.clone());

        let artifact_id = append_background_resume_audit(
            &mut memory_store,
            &background_campaign,
            &TickSource::ApprovalResponse,
            &runtime_state,
            "task-1",
        )
        .expect("background audit should be created");

        let audit_artifact = memory_store
            .get(&artifact_id)
            .expect("background audit should be persisted");
        assert_eq!(
            audit_artifact.related_ref,
            "background:campaign-1:ApprovalResponse:checkpoint-1"
        );
    }

    #[test]
    fn quarantine_and_rollback_audits_use_stable_related_refs() {
        let mut memory_store = MemoryStore::default();
        let quarantine_record = create_quarantine_record(
            "quarantine-1",
            QuarantineReasonClass::PostApprovalAnomaly,
            vec!["task-1".to_string()],
            Some("rollback-1".to_string()),
        );
        let quarantine_artifact_id = append_quarantine_transition_audit(
            &mut memory_store,
            &quarantine_record,
            "campaign-1",
            "epoch-1",
            "session-1",
            Some("task-1".to_string()),
            "quarantine opened for bounded rollback review",
        );
        let rollback_handle = create_rollback_handle(
            "rollback-1",
            "task",
            "checkpoint-1",
            vec!["restore checkpoint-1".to_string()],
            Vec::new(),
        );
        let runtime_state = approval_blocked_runtime_state(memory_store.clone());
        let rollback_artifact_id =
            append_rollback_execution_audit(&mut memory_store, &rollback_handle, &runtime_state);

        assert_eq!(
            memory_store
                .get(&quarantine_artifact_id)
                .expect("quarantine audit should exist")
                .related_ref,
            "quarantine-1"
        );
        assert_eq!(
            memory_store
                .get(&rollback_artifact_id)
                .expect("rollback audit should exist")
                .related_ref,
            "rollback-1"
        );
        assert!(
            memory_store
                .artifacts_for_related_ref("rollback-1")
                .iter()
                .any(|artifact| artifact.artifact_id == rollback_artifact_id)
        );
    }

    #[test]
    fn background_resume_with_runtime_state_rejects_pending_approval_without_granted_decision() {
        let background_campaign = BackgroundCampaign {
            campaign_id: "campaign-1".to_string(),
            objective: "resume approval-blocked bounded flow".to_string(),
            authority_ceiling: crate::execution::AuthorityClass::Observe,
            allowed_tick_sources: vec![TickSource::ApprovalResponse],
            max_concurrent_sessions: 1,
            stop_conditions: vec![crate::execution::StopCondition::ExplicitTaskCompletion],
            approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
            audit_policy: GovernancePolicyClass::ExecutionSafetyPolicy,
        };
        let approval_request = ApprovalRequest::requested(
            "approval-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "workspace-root",
            "workspace-root",
            crate::execution::AuthorityClass::Observe,
        );
        let mut memory_store = MemoryStore::default();
        let request_checkpoint = checkpoint("session-1");
        persist_approval_request_bundle(&mut memory_store, &approval_request, &request_checkpoint);
        let runtime_state = approval_blocked_runtime_state(memory_store);

        let error = validate_background_resume_with_runtime_state(
            &background_campaign,
            &TickSource::ApprovalResponse,
            &runtime_state,
            &[],
            &[],
            "task-1",
        )
        .unwrap_err();

        assert_eq!(
            error,
            GovernanceError::InvalidApprovalsForBackgroundResume {
                campaign_id: "campaign-1".to_string(),
            }
        );
    }

    #[test]
    fn background_resume_with_runtime_state_rejects_replayability_violation() {
        let background_campaign = BackgroundCampaign {
            campaign_id: "campaign-1".to_string(),
            objective: "resume approval-blocked bounded flow".to_string(),
            authority_ceiling: crate::execution::AuthorityClass::Observe,
            allowed_tick_sources: vec![TickSource::ApprovalResponse],
            max_concurrent_sessions: 1,
            stop_conditions: vec![crate::execution::StopCondition::ExplicitTaskCompletion],
            approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
            audit_policy: GovernancePolicyClass::ExecutionSafetyPolicy,
        };
        let approval_request = ApprovalRequest::requested(
            "approval-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "workspace-root",
            "workspace-root",
            crate::execution::AuthorityClass::Observe,
        );
        let mut memory_store = MemoryStore::default();
        let request_checkpoint = checkpoint("session-1");
        persist_approval_request_bundle(&mut memory_store, &approval_request, &request_checkpoint);
        let mut runtime_state = approval_blocked_runtime_state(memory_store);
        runtime_state.session.state = ExecutionSessionState::Ready;

        let error = validate_background_resume_with_runtime_state(
            &background_campaign,
            &TickSource::ApprovalResponse,
            &runtime_state,
            &[],
            &[],
            "task-1",
        )
        .unwrap_err();

        assert_eq!(
            error,
            GovernanceError::InvalidRuntimeStateForBackgroundResume {
                campaign_id: "campaign-1".to_string(),
                reason:
                    "runtime state 'Ready' cannot retain pending approvals outside approval wait"
                        .to_string(),
            }
        );
    }

    #[test]
    fn background_resume_rejects_disallowed_tick_source() {
        let background_campaign = BackgroundCampaign {
            campaign_id: "campaign-1".to_string(),
            objective: "resume approval-blocked bounded flow".to_string(),
            authority_ceiling: crate::execution::AuthorityClass::Observe,
            allowed_tick_sources: vec![TickSource::ApprovalResponse],
            max_concurrent_sessions: 1,
            stop_conditions: vec![crate::execution::StopCondition::ExplicitTaskCompletion],
            approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
            audit_policy: GovernancePolicyClass::ExecutionSafetyPolicy,
        };

        let error = validate_background_resume(
            &background_campaign,
            &TickSource::ScheduledTimer,
            Some("checkpoint-1"),
            true,
            true,
            &[],
            "task-1",
        )
        .unwrap_err();

        assert_eq!(
            error,
            GovernanceError::TickSourceNotAllowed {
                campaign_id: "campaign-1".to_string(),
                tick_source: TickSource::ScheduledTimer,
            }
        );
    }

    #[test]
    fn quarantine_blocks_affected_action_until_resolved() {
        let background_campaign = BackgroundCampaign {
            campaign_id: "campaign-1".to_string(),
            objective: "resume approval-blocked bounded flow".to_string(),
            authority_ceiling: crate::execution::AuthorityClass::Observe,
            allowed_tick_sources: vec![TickSource::ApprovalResponse],
            max_concurrent_sessions: 1,
            stop_conditions: vec![crate::execution::StopCondition::ExplicitTaskCompletion],
            approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
            audit_policy: GovernancePolicyClass::ExecutionSafetyPolicy,
        };
        let rollback_handle = create_rollback_handle(
            "rollback-1",
            "task",
            "checkpoint-1",
            vec!["restore checkpoint-1".to_string()],
            vec!["operator-confirm".to_string()],
        );
        let quarantine_record = create_quarantine_record(
            "quarantine-1",
            QuarantineReasonClass::PostApprovalAnomaly,
            vec!["task-1".to_string()],
            Some(rollback_handle.rollback_handle_id.clone()),
        );

        let error = validate_background_resume(
            &background_campaign,
            &TickSource::ApprovalResponse,
            Some("checkpoint-1"),
            true,
            true,
            &[quarantine_record],
            "task-1",
        )
        .unwrap_err();

        assert_eq!(
            error,
            GovernanceError::QuarantineBlocksAction {
                quarantine_id: "quarantine-1".to_string(),
                affected_ref: "task-1".to_string(),
            }
        );
    }

    #[test]
    fn rollback_handle_can_be_attached_to_quarantine() {
        let rollback_handle = create_rollback_handle(
            "rollback-1",
            "task",
            "checkpoint-1",
            vec!["restore checkpoint-1".to_string()],
            vec!["operator-confirm".to_string()],
        );
        let quarantine_record = create_quarantine_record(
            "quarantine-1",
            QuarantineReasonClass::PolicyViolation,
            vec!["task-1".to_string()],
            Some(rollback_handle.rollback_handle_id.clone()),
        );

        assert_eq!(
            quarantine_record.rollback_handle_ref,
            Some("rollback-1".to_string())
        );
    }

    #[test]
    fn promotion_readiness_is_promotable_when_evidence_and_safety_are_complete() {
        let decision = decide_promotion_readiness(
            "promotion-readiness-1",
            &challenger_comparison(DimensionVerdict::Equivalent),
            &sufficiency_gate(),
            &sufficiency_evidence(true),
            &[create_rollback_handle(
                "rollback-1",
                "shadow-campaign",
                "checkpoint-1",
                vec!["restore checkpoint".to_string()],
                Vec::new(),
            )],
            &["review-artifact-1".to_string()],
            &[],
        );

        assert_eq!(decision.status, PromotionReadinessStatus::Promotable);
        assert!(decision.required_preconditions.is_empty());
    }

    #[test]
    fn promotion_readiness_is_retained_when_supporting_artifacts_are_incomplete() {
        let decision = decide_promotion_readiness(
            "promotion-readiness-1",
            &challenger_comparison(DimensionVerdict::Equivalent),
            &sufficiency_gate(),
            &sufficiency_evidence(false),
            &[],
            &[],
            &[],
        );

        assert_eq!(decision.status, PromotionReadinessStatus::Retain);
        assert!(
            decision
                .required_preconditions
                .iter()
                .any(|item| item.contains("complete native-sufficiency evidence"))
        );
        assert!(
            decision
                .required_preconditions
                .iter()
                .any(|item| item.contains("rollback handle"))
        );
        assert!(
            decision
                .required_preconditions
                .iter()
                .any(|item| item.contains("review or promotion artifact refs"))
        );
    }

    #[test]
    fn promotion_readiness_is_rejected_when_quarantine_or_critical_failure_exists() {
        let mut quarantine = create_quarantine_record(
            "quarantine-1",
            QuarantineReasonClass::EvaluationMismatch,
            vec!["session-challenger".to_string()],
            Some("rollback-1".to_string()),
        );
        quarantine.resolution_state = QuarantineResolutionState::Open;

        let decision = decide_promotion_readiness(
            "promotion-readiness-1",
            &challenger_comparison(DimensionVerdict::ChallengerWorse),
            &sufficiency_gate(),
            &sufficiency_evidence(true),
            &[create_rollback_handle(
                "rollback-1",
                "shadow-campaign",
                "checkpoint-1",
                vec!["restore checkpoint".to_string()],
                Vec::new(),
            )],
            &["review-artifact-1".to_string()],
            &[quarantine],
        );

        assert_eq!(decision.status, PromotionReadinessStatus::Reject);
        assert_eq!(decision.quarantine_refs, vec!["quarantine-1".to_string()]);
    }

    #[test]
    fn promotion_act_requires_promotable_decision_and_artifacts() {
        let act = open_promotion_act(
            "promotion-act-1",
            &promotable_decision(),
            &challenger_comparison(DimensionVerdict::Equivalent),
            "epoch-1",
            "epoch-2",
            "campaign-successor-1",
            vec!["comparison-1".to_string()],
        )
        .unwrap();

        assert_eq!(act.status, PromotionActStatus::Approved);
        assert_eq!(act.promoted_epoch_id, "epoch-2");
        assert_eq!(act.successor_campaign_id, "campaign-successor-1");
    }

    #[test]
    fn promotion_act_rejects_open_quarantine() {
        let mut decision = promotable_decision();
        decision.quarantine_refs.push("quarantine-1".to_string());

        let error = open_promotion_act(
            "promotion-act-1",
            &decision,
            &challenger_comparison(DimensionVerdict::Equivalent),
            "epoch-1",
            "epoch-2",
            "campaign-successor-1",
            vec!["comparison-1".to_string()],
        )
        .unwrap_err();

        assert_eq!(
            error,
            PromotionError::OpenQuarantine {
                quarantine_id: "quarantine-1".to_string()
            }
        );
    }

    #[test]
    fn epoch_adoption_and_reversal_window_progress_through_states() {
        let mut promotion_act = open_promotion_act(
            "promotion-act-1",
            &promotable_decision(),
            &challenger_comparison(DimensionVerdict::Equivalent),
            "epoch-1",
            "epoch-2",
            "campaign-successor-1",
            vec!["comparison-1".to_string()],
        )
        .unwrap();
        let rollback_handle = create_rollback_handle(
            "rollback-1",
            "promotion-act",
            "checkpoint-incumbent-1",
            vec!["restore checkpoint".to_string()],
            Vec::new(),
        );
        let quarantine = create_quarantine_record(
            "quarantine-1",
            QuarantineReasonClass::PostApprovalAnomaly,
            vec!["session-promoted-1".to_string()],
            Some(rollback_handle.rollback_handle_id.clone()),
        );

        let mut adoption = plan_epoch_adoption(
            "adoption-1",
            &promotion_act,
            "session-incumbent-1",
            "session-promoted-1",
            "session-activated-1",
            vec!["review-artifact-1".to_string()],
            "promotion adoption planned",
        );
        assert_eq!(adoption.status, EpochAdoptionStatus::Planned);

        mark_promotion_activated(&mut promotion_act);
        mark_epoch_adoption_active(&mut adoption, "checkpoint-epoch-handoff-1");
        assert_eq!(promotion_act.status, PromotionActStatus::Activated);
        assert_eq!(adoption.status, EpochAdoptionStatus::Active);
        assert_eq!(
            adoption.activation_checkpoint_ref.as_deref(),
            Some("checkpoint-epoch-handoff-1")
        );

        let mut reversal_window = open_reversal_window(
            "reversal-window-1",
            &promotion_act,
            std::slice::from_ref(&rollback_handle),
            std::slice::from_ref(&quarantine),
            "open reversal window",
        )
        .unwrap();
        assert_eq!(reversal_window.status, ReversalWindowStatus::Open);

        let action = evaluate_reversal_window(
            &reversal_window,
            std::slice::from_ref(&quarantine),
            "session-promoted-1",
        )
        .unwrap();
        assert_eq!(action, ReversalAction::ReverseToCheckpoint);

        mark_reversal_window_reversed(&mut reversal_window);
        mark_promotion_reversed(&mut promotion_act);
        mark_epoch_adoption_reversed(&mut adoption);

        assert_eq!(reversal_window.status, ReversalWindowStatus::Reversed);
        assert_eq!(promotion_act.status, PromotionActStatus::Reversed);
        assert_eq!(adoption.status, EpochAdoptionStatus::Reversed);
    }

    #[test]
    fn cycle_closure_promotes_promotable_second_cycle_candidate() {
        let comparison = challenger_comparison(DimensionVerdict::Equivalent);
        let rollback_handle = create_rollback_handle(
            "rollback-1",
            "successor-cycle",
            "checkpoint-1",
            vec!["restore checkpoint-1".to_string()],
            Vec::new(),
        );
        let readiness = decide_promotion_readiness(
            "readiness-1",
            &comparison,
            &sufficiency_gate(),
            &sufficiency_evidence(true),
            std::slice::from_ref(&rollback_handle),
            &["review-artifact-1".to_string()],
            &[],
        );

        let closure = decide_cycle_closure(
            "cycle-closure-1",
            &readiness,
            &comparison,
            std::slice::from_ref(&rollback_handle),
            &[],
        );

        assert_eq!(closure.status, CycleClosureDecisionStatus::Promote);
        assert_eq!(closure.successor_candidate_ref, "session-challenger");
    }

    #[test]
    fn v1_completion_gate_accepts_explicit_carried_imports_when_validation_passes() {
        let closure_inventory = build_closure_inventory(
            "closure-1",
            full_closure_inventory_entries(),
            Vec::new(),
            "bounded v1 closure inventory",
        );
        let genome = build_successor_genome(
            "genome-1",
            "session-promoted-incumbent",
            "package:aiaf/supervisor@v1",
            "typed-dag:successor-1",
            vec!["policy:bounded".to_string()],
            "successor genome",
        )
        .unwrap();
        let phenotype = materialize_successor_phenotype(
            "artifact-1",
            &genome,
            "package:aiaf/supervisor@v1",
            "component:artifact-1",
            vec!["wit:supervisor".to_string()],
            vec!["artifact-output-1".to_string()],
            "successor phenotype",
        )
        .unwrap();
        let validation = validate_semantic_phenotype(
            "validation-1",
            &genome,
            &phenotype,
            vec!["validator:semantic-check".to_string()],
            vec!["evidence:semantic-check-1".to_string()],
            "validation passed",
        )
        .unwrap();
        let rollback_handle = create_rollback_handle(
            "rollback-1",
            "successor-cycle",
            "checkpoint-1",
            vec!["restore checkpoint-1".to_string()],
            Vec::new(),
        );
        let comparison = challenger_comparison(DimensionVerdict::Equivalent);
        let readiness = decide_promotion_readiness(
            "readiness-1",
            &comparison,
            &sufficiency_gate(),
            &sufficiency_evidence(true),
            std::slice::from_ref(&rollback_handle),
            &["review-artifact-1".to_string()],
            &[],
        );
        let cycle_closure = decide_cycle_closure(
            "cycle-closure-1",
            &readiness,
            &comparison,
            std::slice::from_ref(&rollback_handle),
            &[],
        );

        let gate = evaluate_v1_completion_gate(
            "v1-gate-1",
            &closure_inventory,
            &validation,
            &cycle_closure,
        );

        assert_eq!(gate.status, V1CompletionStatus::Satisfied);
        assert_eq!(gate.carried_import_refs, vec!["ModelHosting".to_string()]);
    }
}
