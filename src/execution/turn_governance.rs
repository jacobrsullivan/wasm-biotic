use crate::execution::checkpoint::RunCheckpoint;
use crate::execution::governance::{ApprovalDecision, ApprovalRequest, QuarantineRecord};
use crate::execution::operations::{ApprovalInboxRecord, DeferredDecisionBundle};
use crate::execution::tool_membrane::ModelToolFamily;
use crate::execution::turn_package::{ParsedApprovalRequestRecord, TurnPackageRole};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelDelegationPosture {
    ReadHeavy,
    BoundedMutation,
    CandidateConstruction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAuthorityDecisionKind {
    Allow,
    ApprovalBlock,
    Deny,
    Quarantine,
    Fail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelOutputQuarantineReasonClass {
    AuthorityExpansion,
    PolicyViolation,
    MalformedOutput,
    UngroundedClaim,
    InconsistentLineageAction,
    OperatorOnlySurface,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelApprovalResolutionAction {
    Grant,
    Deny,
    Expire,
    Escalate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingGovernedTurnActionStatus {
    PendingApproval,
    GrantedExecuted,
    Denied,
    Expired,
    Escalated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelDelegationPolicyRecord {
    pub delegation_policy_id: String,
    pub turn_package_ref: String,
    pub posture: ModelDelegationPosture,
    pub turn_role: TurnPackageRole,
    pub exposed_tool_families: Vec<ModelToolFamily>,
    pub approval_evidence_refs: Vec<String>,
    pub rationale: String,
    pub created_at: String,
}

impl ModelDelegationPolicyRecord {
    pub fn validate(&self) -> Result<(), TurnGovernanceError> {
        require_nonempty(
            &self.delegation_policy_id,
            TurnGovernanceError::MissingDelegationPolicyId,
        )?;
        require_nonempty(
            &self.turn_package_ref,
            TurnGovernanceError::MissingTurnPackageRef,
        )?;
        validate_required_string_list(
            &self.approval_evidence_refs,
            TurnGovernanceError::MissingApprovalEvidenceRefs,
        )?;
        require_nonempty(&self.rationale, TurnGovernanceError::MissingRationale)?;
        require_nonempty(&self.created_at, TurnGovernanceError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAuthorityDecision {
    pub authority_decision_id: String,
    pub turn_result_ref: String,
    pub delegation_policy_ref: String,
    pub decision: ModelAuthorityDecisionKind,
    pub reason_refs: Vec<String>,
    pub reason_summary: String,
    pub created_at: String,
}

impl ModelAuthorityDecision {
    pub fn validate(&self) -> Result<(), TurnGovernanceError> {
        require_nonempty(
            &self.authority_decision_id,
            TurnGovernanceError::MissingAuthorityDecisionId,
        )?;
        require_nonempty(
            &self.turn_result_ref,
            TurnGovernanceError::MissingTurnResultRef,
        )?;
        require_nonempty(
            &self.delegation_policy_ref,
            TurnGovernanceError::MissingDelegationPolicyRef,
        )?;
        validate_required_string_list(&self.reason_refs, TurnGovernanceError::MissingReasonRefs)?;
        require_nonempty(
            &self.reason_summary,
            TurnGovernanceError::MissingReasonSummary,
        )?;
        require_nonempty(&self.created_at, TurnGovernanceError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelApprovalRequestRecord {
    pub model_approval_request_id: String,
    pub turn_result_ref: String,
    pub authority_decision_ref: String,
    pub parsed_approval_request_ref: Option<String>,
    pub approval_request: ApprovalRequest,
    pub approval_inbox: ApprovalInboxRecord,
    pub deferred_decision_bundle: DeferredDecisionBundle,
    pub pending_action_ref: Option<String>,
    pub resolution_action: Option<ModelApprovalResolutionAction>,
    pub latest_decision: Option<ApprovalDecision>,
    pub notes: Vec<String>,
    pub created_at: String,
}

impl ModelApprovalRequestRecord {
    pub fn validate(&self) -> Result<(), TurnGovernanceError> {
        require_nonempty(
            &self.model_approval_request_id,
            TurnGovernanceError::MissingModelApprovalRequestId,
        )?;
        require_nonempty(
            &self.turn_result_ref,
            TurnGovernanceError::MissingTurnResultRef,
        )?;
        require_nonempty(
            &self.authority_decision_ref,
            TurnGovernanceError::MissingAuthorityDecisionRef,
        )?;
        if let Some(reference) = &self.parsed_approval_request_ref {
            require_nonempty(
                reference,
                TurnGovernanceError::MissingParsedApprovalRequestRef,
            )?;
        }
        self.approval_inbox.validate().map_err(|reason| {
            TurnGovernanceError::InvalidNestedRecord {
                record: "approval_inbox",
                reason: reason.to_string(),
            }
        })?;
        self.deferred_decision_bundle.validate().map_err(|reason| {
            TurnGovernanceError::InvalidNestedRecord {
                record: "deferred_decision_bundle",
                reason: reason.to_string(),
            }
        })?;
        if let Some(reference) = &self.pending_action_ref {
            require_nonempty(reference, TurnGovernanceError::MissingPendingActionRef)?;
        }
        if self.notes.iter().any(|note| note.trim().is_empty()) {
            return Err(TurnGovernanceError::MissingNote);
        }
        require_nonempty(&self.created_at, TurnGovernanceError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelOutputQuarantineRecord {
    pub model_quarantine_id: String,
    pub affected_turn_result_ref: String,
    pub authority_decision_ref: String,
    pub quarantine_record: QuarantineRecord,
    pub reason_class: ModelOutputQuarantineReasonClass,
    pub rollback_or_pause_refs: Vec<String>,
    pub notes: Vec<String>,
    pub created_at: String,
}

impl ModelOutputQuarantineRecord {
    pub fn validate(&self) -> Result<(), TurnGovernanceError> {
        require_nonempty(
            &self.model_quarantine_id,
            TurnGovernanceError::MissingModelQuarantineId,
        )?;
        require_nonempty(
            &self.affected_turn_result_ref,
            TurnGovernanceError::MissingTurnResultRef,
        )?;
        require_nonempty(
            &self.authority_decision_ref,
            TurnGovernanceError::MissingAuthorityDecisionRef,
        )?;
        validate_required_string_list(
            &self.rollback_or_pause_refs,
            TurnGovernanceError::MissingRollbackOrPauseRefs,
        )?;
        if self.notes.iter().any(|note| note.trim().is_empty()) {
            return Err(TurnGovernanceError::MissingNote);
        }
        require_nonempty(&self.created_at, TurnGovernanceError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnCheckpointRecord {
    pub turn_checkpoint_id: String,
    pub turn_result_ref: String,
    pub authority_decision_ref: String,
    pub runtime_checkpoint: Option<RunCheckpoint>,
    pub resumable: bool,
    pub terminal: bool,
    pub pending_approval_refs: Vec<String>,
    pub summary: String,
    pub created_at: String,
}

impl TurnCheckpointRecord {
    pub fn validate(&self) -> Result<(), TurnGovernanceError> {
        require_nonempty(
            &self.turn_checkpoint_id,
            TurnGovernanceError::MissingTurnCheckpointId,
        )?;
        require_nonempty(
            &self.turn_result_ref,
            TurnGovernanceError::MissingTurnResultRef,
        )?;
        require_nonempty(
            &self.authority_decision_ref,
            TurnGovernanceError::MissingAuthorityDecisionRef,
        )?;
        validate_optional_string_list(
            &self.pending_approval_refs,
            TurnGovernanceError::InvalidPendingApprovalRefs,
        )?;
        require_nonempty(&self.summary, TurnGovernanceError::MissingSummary)?;
        require_nonempty(&self.created_at, TurnGovernanceError::MissingCreatedAt)?;
        if self.resumable && self.terminal {
            return Err(TurnGovernanceError::CheckpointCannotBeResumableAndTerminal);
        }
        if !self.resumable && !self.terminal {
            return Err(TurnGovernanceError::CheckpointMustDeclareDisposition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGovernedTurnActionRecord {
    pub pending_governed_turn_action_id: String,
    pub turn_result_ref: String,
    pub authority_decision_ref: String,
    pub checkpoint_ref: String,
    pub model_approval_request_ref: String,
    pub stored_tool_intent_refs: Vec<String>,
    pub resolution_status: PendingGovernedTurnActionStatus,
    pub execution_receipt_ref: Option<String>,
    pub resolved_at: Option<String>,
    pub notes: Vec<String>,
    pub created_at: String,
}

impl PendingGovernedTurnActionRecord {
    pub fn validate(&self) -> Result<(), TurnGovernanceError> {
        require_nonempty(
            &self.pending_governed_turn_action_id,
            TurnGovernanceError::MissingPendingActionId,
        )?;
        require_nonempty(
            &self.turn_result_ref,
            TurnGovernanceError::MissingTurnResultRef,
        )?;
        require_nonempty(
            &self.authority_decision_ref,
            TurnGovernanceError::MissingAuthorityDecisionRef,
        )?;
        require_nonempty(
            &self.checkpoint_ref,
            TurnGovernanceError::MissingCheckpointRef,
        )?;
        require_nonempty(
            &self.model_approval_request_ref,
            TurnGovernanceError::MissingModelApprovalRequestRef,
        )?;
        validate_required_string_list(
            &self.stored_tool_intent_refs,
            TurnGovernanceError::MissingStoredToolIntentRefs,
        )?;
        if let Some(reference) = &self.execution_receipt_ref {
            require_nonempty(reference, TurnGovernanceError::MissingExecutionReceiptRef)?;
        }
        if let Some(resolved_at) = &self.resolved_at {
            require_nonempty(resolved_at, TurnGovernanceError::MissingResolvedAt)?;
        }
        if self.notes.iter().any(|note| note.trim().is_empty()) {
            return Err(TurnGovernanceError::MissingNote);
        }
        require_nonempty(&self.created_at, TurnGovernanceError::MissingCreatedAt)?;
        match self.resolution_status {
            PendingGovernedTurnActionStatus::PendingApproval => {
                if self.execution_receipt_ref.is_some() || self.resolved_at.is_some() {
                    return Err(TurnGovernanceError::PendingActionResolutionMismatch);
                }
            }
            PendingGovernedTurnActionStatus::GrantedExecuted => {
                if self.execution_receipt_ref.is_none() || self.resolved_at.is_none() {
                    return Err(TurnGovernanceError::PendingActionResolutionMismatch);
                }
            }
            PendingGovernedTurnActionStatus::Denied
            | PendingGovernedTurnActionStatus::Expired
            | PendingGovernedTurnActionStatus::Escalated => {
                if self.resolved_at.is_none() {
                    return Err(TurnGovernanceError::PendingActionResolutionMismatch);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnGovernanceBundle {
    pub delegation_policy: ModelDelegationPolicyRecord,
    pub authority_decision: ModelAuthorityDecision,
    pub approvals: Vec<ModelApprovalRequestRecord>,
    pub quarantines: Vec<ModelOutputQuarantineRecord>,
    pub checkpoints: Vec<TurnCheckpointRecord>,
    pub pending_actions: Vec<PendingGovernedTurnActionRecord>,
    pub parsed_approval_request: Option<ParsedApprovalRequestRecord>,
}

impl TurnGovernanceBundle {
    pub fn validate(&self) -> Result<(), TurnGovernanceError> {
        self.delegation_policy.validate()?;
        self.authority_decision.validate()?;
        if self.authority_decision.delegation_policy_ref
            != self.delegation_policy.delegation_policy_id
        {
            return Err(TurnGovernanceError::ReferenceMismatch {
                left_field: "authority_decision.delegation_policy_ref",
                right_field: "delegation_policy.delegation_policy_id",
            });
        }
        for approval in &self.approvals {
            approval.validate()?;
            if approval.turn_result_ref != self.authority_decision.turn_result_ref {
                return Err(TurnGovernanceError::ReferenceMismatch {
                    left_field: "approval.turn_result_ref",
                    right_field: "authority_decision.turn_result_ref",
                });
            }
            if approval.authority_decision_ref != self.authority_decision.authority_decision_id {
                return Err(TurnGovernanceError::ReferenceMismatch {
                    left_field: "approval.authority_decision_ref",
                    right_field: "authority_decision.authority_decision_id",
                });
            }
        }
        for quarantine in &self.quarantines {
            quarantine.validate()?;
            if quarantine.affected_turn_result_ref != self.authority_decision.turn_result_ref {
                return Err(TurnGovernanceError::ReferenceMismatch {
                    left_field: "quarantine.affected_turn_result_ref",
                    right_field: "authority_decision.turn_result_ref",
                });
            }
            if quarantine.authority_decision_ref != self.authority_decision.authority_decision_id {
                return Err(TurnGovernanceError::ReferenceMismatch {
                    left_field: "quarantine.authority_decision_ref",
                    right_field: "authority_decision.authority_decision_id",
                });
            }
        }
        for checkpoint in &self.checkpoints {
            checkpoint.validate()?;
            if checkpoint.turn_result_ref != self.authority_decision.turn_result_ref {
                return Err(TurnGovernanceError::ReferenceMismatch {
                    left_field: "checkpoint.turn_result_ref",
                    right_field: "authority_decision.turn_result_ref",
                });
            }
            if checkpoint.authority_decision_ref != self.authority_decision.authority_decision_id {
                return Err(TurnGovernanceError::ReferenceMismatch {
                    left_field: "checkpoint.authority_decision_ref",
                    right_field: "authority_decision.authority_decision_id",
                });
            }
        }
        for action in &self.pending_actions {
            action.validate()?;
            if action.turn_result_ref != self.authority_decision.turn_result_ref {
                return Err(TurnGovernanceError::ReferenceMismatch {
                    left_field: "pending_action.turn_result_ref",
                    right_field: "authority_decision.turn_result_ref",
                });
            }
            if action.authority_decision_ref != self.authority_decision.authority_decision_id {
                return Err(TurnGovernanceError::ReferenceMismatch {
                    left_field: "pending_action.authority_decision_ref",
                    right_field: "authority_decision.authority_decision_id",
                });
            }
        }
        if let Some(parsed_approval_request) = &self.parsed_approval_request {
            parsed_approval_request.validate().map_err(|reason| {
                TurnGovernanceError::InvalidNestedRecord {
                    record: "parsed_approval_request",
                    reason: reason.to_string(),
                }
            })?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TurnGovernanceError {
    MissingDelegationPolicyId,
    MissingAuthorityDecisionId,
    MissingDelegationPolicyRef,
    MissingModelApprovalRequestId,
    MissingModelQuarantineId,
    MissingTurnCheckpointId,
    MissingPendingActionId,
    MissingTurnPackageRef,
    MissingTurnResultRef,
    MissingAuthorityDecisionRef,
    MissingParsedApprovalRequestRef,
    MissingPendingActionRef,
    MissingModelApprovalRequestRef,
    MissingCheckpointRef,
    MissingExecutionReceiptRef,
    MissingStoredToolIntentRefs,
    MissingApprovalEvidenceRefs,
    MissingRollbackOrPauseRefs,
    InvalidPendingApprovalRefs,
    MissingReasonRefs,
    MissingReasonSummary,
    MissingRationale,
    MissingSummary,
    MissingCreatedAt,
    MissingResolvedAt,
    MissingNote,
    CheckpointCannotBeResumableAndTerminal,
    CheckpointMustDeclareDisposition,
    PendingActionResolutionMismatch,
    ReferenceMismatch {
        left_field: &'static str,
        right_field: &'static str,
    },
    InvalidNestedRecord {
        record: &'static str,
        reason: String,
    },
}

impl Display for TurnGovernanceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDelegationPolicyId => write!(f, "model delegation policy id is required"),
            Self::MissingAuthorityDecisionId => {
                write!(f, "model authority decision id is required")
            }
            Self::MissingDelegationPolicyRef => {
                write!(
                    f,
                    "model authority decision must reference a delegation policy"
                )
            }
            Self::MissingModelApprovalRequestId => {
                write!(f, "model approval request id is required")
            }
            Self::MissingModelQuarantineId => write!(f, "model quarantine id is required"),
            Self::MissingTurnCheckpointId => write!(f, "turn checkpoint id is required"),
            Self::MissingPendingActionId => {
                write!(f, "pending governed turn action id is required")
            }
            Self::MissingTurnPackageRef => write!(f, "turn package ref is required"),
            Self::MissingTurnResultRef => write!(f, "turn result ref is required"),
            Self::MissingAuthorityDecisionRef => {
                write!(
                    f,
                    "governance artifact must reference an authority decision"
                )
            }
            Self::MissingParsedApprovalRequestRef => {
                write!(f, "parsed approval request ref cannot be blank")
            }
            Self::MissingPendingActionRef => write!(f, "pending action ref cannot be blank"),
            Self::MissingModelApprovalRequestRef => {
                write!(f, "pending action must reference a model approval request")
            }
            Self::MissingCheckpointRef => write!(f, "pending action must reference a checkpoint"),
            Self::MissingExecutionReceiptRef => {
                write!(f, "execution receipt ref cannot be blank")
            }
            Self::MissingStoredToolIntentRefs => {
                write!(f, "pending action must store at least one tool intent ref")
            }
            Self::MissingApprovalEvidenceRefs => {
                write!(f, "delegation policy must include approval evidence refs")
            }
            Self::MissingRollbackOrPauseRefs => {
                write!(f, "model quarantine must include rollback or pause refs")
            }
            Self::InvalidPendingApprovalRefs => {
                write!(
                    f,
                    "checkpoint pending approval refs cannot contain blank values"
                )
            }
            Self::MissingReasonRefs => write!(f, "authority decision reason refs are required"),
            Self::MissingReasonSummary => {
                write!(f, "authority decision reason summary is required")
            }
            Self::MissingRationale => write!(f, "governance rationale is required"),
            Self::MissingSummary => write!(f, "governance summary is required"),
            Self::MissingCreatedAt => write!(f, "created_at is required"),
            Self::MissingResolvedAt => write!(f, "resolved_at cannot be blank"),
            Self::MissingNote => write!(f, "governance notes cannot contain blank values"),
            Self::CheckpointCannotBeResumableAndTerminal => write!(
                f,
                "turn checkpoint cannot be resumable and terminal at the same time"
            ),
            Self::CheckpointMustDeclareDisposition => {
                write!(f, "turn checkpoint must be resumable or terminal")
            }
            Self::PendingActionResolutionMismatch => write!(
                f,
                "pending governed action resolution fields do not match the declared status"
            ),
            Self::ReferenceMismatch {
                left_field,
                right_field,
            } => write!(
                f,
                "record field '{}' must match '{}'",
                left_field, right_field
            ),
            Self::InvalidNestedRecord { record, reason } => {
                write!(f, "nested {} record is invalid: {}", record, reason)
            }
        }
    }
}

impl Error for TurnGovernanceError {}

fn require_nonempty(value: &str, error: TurnGovernanceError) -> Result<(), TurnGovernanceError> {
    if value.trim().is_empty() {
        Err(error)
    } else {
        Ok(())
    }
}

fn validate_required_string_list(
    values: &[String],
    error: TurnGovernanceError,
) -> Result<(), TurnGovernanceError> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        Err(error)
    } else {
        Ok(())
    }
}

fn validate_optional_string_list(
    values: &[String],
    error: TurnGovernanceError,
) -> Result<(), TurnGovernanceError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::{
        ApprovalDecisionStatus, ApprovalInboxRecord, ApprovalRequest, AuthorityClass,
        DeferredDecisionBundle, QuarantineReasonClass, create_quarantine_record,
    };

    fn approval_request() -> ApprovalRequest {
        ApprovalRequest::requested(
            "approval-request-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "action:1",
            "scope:1",
            AuthorityClass::PromotionControl,
        )
    }

    fn approval_inbox() -> ApprovalInboxRecord {
        ApprovalInboxRecord {
            approval_inbox_id: "inbox-1".to_string(),
            pause_ref: "turn-checkpoint-1".to_string(),
            approval_refs: vec!["approval-request-1".to_string()],
            decision_authority_refs: vec!["authority:human".to_string()],
            deadline_policy_ref: "policy:deadline".to_string(),
            escalation_policy_ref: "policy:escalate".to_string(),
            response_ref: "response:1".to_string(),
            resume_ref: "resume:1".to_string(),
            audit_summary_ref: "audit:1".to_string(),
            campaign_refs: vec!["campaign-1".to_string()],
        }
    }

    fn decision_bundle() -> DeferredDecisionBundle {
        DeferredDecisionBundle {
            decision_bundle_id: "decision-bundle-1".to_string(),
            approval_ref: "approval-request-1".to_string(),
            grant_resume_refs: vec!["resume:1".to_string()],
            deny_outcome_refs: vec!["deny:1".to_string()],
            expired_outcome_refs: vec!["expire:1".to_string()],
            escalation_outcome_refs: vec!["escalate:1".to_string()],
            risk_refs: vec!["risk:1".to_string()],
            summary: "bounded decision bundle".to_string(),
        }
    }

    #[test]
    fn pending_action_requires_resolution_fields_to_match_status() {
        let error = PendingGovernedTurnActionRecord {
            pending_governed_turn_action_id: "pending-action-1".to_string(),
            turn_result_ref: "parsed-turn-result-1".to_string(),
            authority_decision_ref: "authority-decision-1".to_string(),
            checkpoint_ref: "turn-checkpoint-1".to_string(),
            model_approval_request_ref: "model-approval-request-1".to_string(),
            stored_tool_intent_refs: vec!["intent:1".to_string()],
            resolution_status: PendingGovernedTurnActionStatus::GrantedExecuted,
            execution_receipt_ref: None,
            resolved_at: Some("2026-04-18T12:00:00Z".to_string()),
            notes: vec!["approval granted".to_string()],
            created_at: "2026-04-18T12:00:00Z".to_string(),
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            error,
            TurnGovernanceError::PendingActionResolutionMismatch
        ));
    }

    #[test]
    fn governance_bundle_rejects_cross_record_mismatches() {
        let bundle = TurnGovernanceBundle {
            delegation_policy: ModelDelegationPolicyRecord {
                delegation_policy_id: "delegation-policy-1".to_string(),
                turn_package_ref: "turn-package-1".to_string(),
                posture: ModelDelegationPosture::BoundedMutation,
                turn_role: TurnPackageRole::Supervisor,
                exposed_tool_families: vec![ModelToolFamily::Program],
                approval_evidence_refs: vec!["family:program".to_string()],
                rationale: "program mutation remains bounded".to_string(),
                created_at: "2026-04-18T12:00:00Z".to_string(),
            },
            authority_decision: ModelAuthorityDecision {
                authority_decision_id: "authority-decision-1".to_string(),
                turn_result_ref: "parsed-turn-result-1".to_string(),
                delegation_policy_ref: "delegation-policy-1".to_string(),
                decision: ModelAuthorityDecisionKind::Quarantine,
                reason_refs: vec!["tool-legality:intent-1".to_string()],
                reason_summary: "operator-only surface was requested".to_string(),
                created_at: "2026-04-18T12:00:00Z".to_string(),
            },
            approvals: Vec::new(),
            quarantines: vec![ModelOutputQuarantineRecord {
                model_quarantine_id: "model-quarantine-1".to_string(),
                affected_turn_result_ref: "parsed-turn-result-2".to_string(),
                authority_decision_ref: "authority-decision-1".to_string(),
                quarantine_record: create_quarantine_record(
                    "quarantine-1",
                    QuarantineReasonClass::PolicyViolation,
                    vec!["parsed-turn-result-1".to_string()],
                    None,
                ),
                reason_class: ModelOutputQuarantineReasonClass::PolicyViolation,
                rollback_or_pause_refs: vec!["turn-checkpoint-1".to_string()],
                notes: vec!["operator-only surface attempt".to_string()],
                created_at: "2026-04-18T12:00:00Z".to_string(),
            }],
            checkpoints: Vec::new(),
            pending_actions: Vec::new(),
            parsed_approval_request: None,
        };
        let error = bundle.validate().unwrap_err();
        assert!(matches!(
            error,
            TurnGovernanceError::ReferenceMismatch {
                left_field: "quarantine.affected_turn_result_ref",
                right_field: "authority_decision.turn_result_ref",
            }
        ));
    }

    #[test]
    fn model_approval_record_accepts_nested_runtime_artifacts() {
        let mut approval_request = approval_request();
        approval_request.status = ApprovalDecisionStatus::Requested;
        ModelApprovalRequestRecord {
            model_approval_request_id: "model-approval-request-1".to_string(),
            turn_result_ref: "parsed-turn-result-1".to_string(),
            authority_decision_ref: "authority-decision-1".to_string(),
            parsed_approval_request_ref: Some("parsed-approval-request-1".to_string()),
            approval_request,
            approval_inbox: approval_inbox(),
            deferred_decision_bundle: decision_bundle(),
            pending_action_ref: Some("pending-action-1".to_string()),
            resolution_action: None,
            latest_decision: None,
            notes: vec!["awaiting operator review".to_string()],
            created_at: "2026-04-18T12:00:00Z".to_string(),
        }
        .validate()
        .unwrap();
    }
}
