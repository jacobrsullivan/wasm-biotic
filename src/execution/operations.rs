use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerTickClass {
    Time,
    Approval,
    Operator,
    Policy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerTickResult {
    Resumed,
    Deferred,
    Refused,
    Exhausted,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerTickRecord {
    pub tick_id: String,
    pub tick_class: SchedulerTickClass,
    pub target_ref: String,
    pub lease_ref: String,
    pub result: SchedulerTickResult,
    pub summary: String,
}

impl SchedulerTickRecord {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.tick_id.trim().is_empty() {
            return Err(OperationsError::MissingTickId);
        }
        if self.target_ref.trim().is_empty() {
            return Err(OperationsError::MissingTargetRef);
        }
        if self.lease_ref.trim().is_empty() {
            return Err(OperationsError::MissingLeaseRef);
        }
        if self.summary.trim().is_empty() {
            return Err(OperationsError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledWakeRecord {
    pub wake_record_id: String,
    pub continuity_ref: String,
    pub lease_ref: String,
    pub tick_ref: String,
    pub scheduled_at: String,
    pub executed_at: String,
    pub result_ref: String,
}

impl ScheduledWakeRecord {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.wake_record_id.trim().is_empty() {
            return Err(OperationsError::MissingWakeRecordId);
        }
        if self.continuity_ref.trim().is_empty() {
            return Err(OperationsError::MissingContinuityRef);
        }
        if self.lease_ref.trim().is_empty() {
            return Err(OperationsError::MissingLeaseRef);
        }
        if self.tick_ref.trim().is_empty() {
            return Err(OperationsError::MissingTickRef);
        }
        if self.scheduled_at.trim().is_empty() {
            return Err(OperationsError::MissingScheduledAt);
        }
        if self.executed_at.trim().is_empty() {
            return Err(OperationsError::MissingExecutedAt);
        }
        if self.result_ref.trim().is_empty() {
            return Err(OperationsError::MissingResultRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentJobLease {
    pub lease_id: String,
    pub job_class: String,
    pub owner_ref: String,
    pub scope_ref: String,
    pub campaign_ref: String,
    pub authority_ref: String,
    pub wake_policy_ref: String,
    pub renewal_policy_ref: String,
    pub interruption_policy_ref: String,
    pub termination_policy_ref: String,
    pub lease_state: String,
}

impl PersistentJobLease {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.lease_id.trim().is_empty() {
            return Err(OperationsError::MissingLeaseId);
        }
        if self.job_class.trim().is_empty() {
            return Err(OperationsError::MissingJobClass);
        }
        if self.owner_ref.trim().is_empty() {
            return Err(OperationsError::MissingOwnerRef);
        }
        if self.scope_ref.trim().is_empty() {
            return Err(OperationsError::MissingScopeRef);
        }
        if self.campaign_ref.trim().is_empty() {
            return Err(OperationsError::MissingCampaignRef);
        }
        if self.authority_ref.trim().is_empty() {
            return Err(OperationsError::MissingAuthorityRef);
        }
        if self.wake_policy_ref.trim().is_empty() {
            return Err(OperationsError::MissingWakePolicyRef);
        }
        if self.renewal_policy_ref.trim().is_empty() {
            return Err(OperationsError::MissingRenewalPolicyRef);
        }
        if self.interruption_policy_ref.trim().is_empty() {
            return Err(OperationsError::MissingInterruptionPolicyRef);
        }
        if self.termination_policy_ref.trim().is_empty() {
            return Err(OperationsError::MissingTerminationPolicyRef);
        }
        if self.lease_state.trim().is_empty() {
            return Err(OperationsError::MissingLeaseState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentShellOperationsDossier {
    pub operations_dossier_id: String,
    pub continuity_ref: String,
    pub tick_refs: Vec<String>,
    pub wake_refs: Vec<String>,
    pub lease_refs: Vec<String>,
    pub approval_inbox_refs: Vec<String>,
    pub decision_bundle_refs: Vec<String>,
    pub continuity_job_refs: Vec<String>,
    pub expiry_refs: Vec<String>,
    pub escalation_refs: Vec<String>,
    pub quarantine_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub audit_refs: Vec<String>,
    pub operator_summary_ref: String,
}

impl PersistentShellOperationsDossier {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.operations_dossier_id.trim().is_empty() {
            return Err(OperationsError::MissingOperationsDossierId);
        }
        if self.continuity_ref.trim().is_empty() {
            return Err(OperationsError::MissingContinuityRef);
        }
        validate_ref_list(&self.tick_refs, OperationsError::MissingTickRefs)?;
        validate_ref_list(&self.wake_refs, OperationsError::MissingWakeRefs)?;
        validate_ref_list(&self.lease_refs, OperationsError::MissingLeaseRefs)?;
        validate_optional_ref_list(
            &self.approval_inbox_refs,
            OperationsError::MissingApprovalInboxRefs,
        )?;
        validate_optional_ref_list(
            &self.decision_bundle_refs,
            OperationsError::MissingDecisionBundleRefs,
        )?;
        validate_ref_list(
            &self.continuity_job_refs,
            OperationsError::MissingContinuityJobRefs,
        )?;
        validate_optional_ref_list(&self.expiry_refs, OperationsError::InvalidExpiryRefs)?;
        validate_optional_ref_list(
            &self.escalation_refs,
            OperationsError::InvalidEscalationRefs,
        )?;
        validate_optional_ref_list(
            &self.quarantine_refs,
            OperationsError::InvalidQuarantineRefs,
        )?;
        validate_optional_ref_list(&self.rollback_refs, OperationsError::InvalidRollbackRefs)?;
        validate_ref_list(&self.audit_refs, OperationsError::MissingAuditRefs)?;
        if self.operator_summary_ref.trim().is_empty() {
            return Err(OperationsError::MissingOperatorSummaryRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityJobRecord {
    pub job_record_id: String,
    pub job_kind: String,
    pub continuity_ref: String,
    pub lease_ref: String,
    pub budget_ref: String,
    pub result_ref: String,
    pub evidence_refs: Vec<String>,
    pub checkpoint_refs: Vec<String>,
}

impl ContinuityJobRecord {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.job_record_id.trim().is_empty() {
            return Err(OperationsError::MissingJobRecordId);
        }
        if self.job_kind.trim().is_empty() {
            return Err(OperationsError::MissingJobKind);
        }
        if self.continuity_ref.trim().is_empty() {
            return Err(OperationsError::MissingContinuityRef);
        }
        if self.lease_ref.trim().is_empty() {
            return Err(OperationsError::MissingLeaseRef);
        }
        if self.budget_ref.trim().is_empty() {
            return Err(OperationsError::MissingBudgetRef);
        }
        if self.result_ref.trim().is_empty() {
            return Err(OperationsError::MissingResultRef);
        }
        validate_ref_list(&self.evidence_refs, OperationsError::MissingEvidenceRefs)?;
        validate_ref_list(
            &self.checkpoint_refs,
            OperationsError::MissingCheckpointRefs,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentShellAuditPacket {
    pub audit_packet_id: String,
    pub continuity_ref: String,
    pub tick_refs: Vec<String>,
    pub wake_refs: Vec<String>,
    pub lease_refs: Vec<String>,
    pub approval_inbox_refs: Vec<String>,
    pub decision_bundle_refs: Vec<String>,
    pub job_refs: Vec<String>,
    pub expiry_refs: Vec<String>,
    pub escalation_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub operator_summary: String,
}

impl PersistentShellAuditPacket {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.audit_packet_id.trim().is_empty() {
            return Err(OperationsError::MissingAuditPacketId);
        }
        if self.continuity_ref.trim().is_empty() {
            return Err(OperationsError::MissingContinuityRef);
        }
        validate_ref_list(&self.tick_refs, OperationsError::MissingTickRefs)?;
        validate_ref_list(&self.wake_refs, OperationsError::MissingWakeRefs)?;
        validate_ref_list(&self.lease_refs, OperationsError::MissingLeaseRefs)?;
        validate_optional_ref_list(
            &self.approval_inbox_refs,
            OperationsError::MissingApprovalInboxRefs,
        )?;
        validate_optional_ref_list(
            &self.decision_bundle_refs,
            OperationsError::MissingDecisionBundleRefs,
        )?;
        validate_ref_list(&self.job_refs, OperationsError::MissingContinuityJobRefs)?;
        validate_optional_ref_list(&self.expiry_refs, OperationsError::InvalidExpiryRefs)?;
        validate_optional_ref_list(
            &self.escalation_refs,
            OperationsError::InvalidEscalationRefs,
        )?;
        validate_ref_list(&self.evidence_refs, OperationsError::MissingEvidenceRefs)?;
        if self.operator_summary.trim().is_empty() {
            return Err(OperationsError::MissingOperatorSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalInboxRecord {
    pub approval_inbox_id: String,
    pub pause_ref: String,
    pub approval_refs: Vec<String>,
    pub decision_authority_refs: Vec<String>,
    pub deadline_policy_ref: String,
    pub escalation_policy_ref: String,
    pub response_ref: String,
    pub resume_ref: String,
    pub audit_summary_ref: String,
    pub campaign_refs: Vec<String>,
}

impl ApprovalInboxRecord {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.approval_inbox_id.trim().is_empty() {
            return Err(OperationsError::MissingApprovalInboxId);
        }
        if self.pause_ref.trim().is_empty() {
            return Err(OperationsError::MissingPauseRef);
        }
        validate_ref_list(&self.approval_refs, OperationsError::MissingApprovalRefs)?;
        validate_ref_list(
            &self.decision_authority_refs,
            OperationsError::MissingDecisionAuthorityRefs,
        )?;
        if self.deadline_policy_ref.trim().is_empty() {
            return Err(OperationsError::MissingDeadlinePolicyRef);
        }
        if self.escalation_policy_ref.trim().is_empty() {
            return Err(OperationsError::MissingEscalationPolicyRef);
        }
        if self.response_ref.trim().is_empty() {
            return Err(OperationsError::MissingResponseRef);
        }
        if self.resume_ref.trim().is_empty() {
            return Err(OperationsError::MissingResumeRef);
        }
        if self.audit_summary_ref.trim().is_empty() {
            return Err(OperationsError::MissingAuditSummaryRef);
        }
        validate_ref_list(&self.campaign_refs, OperationsError::MissingCampaignRefs)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredDecisionBundle {
    pub decision_bundle_id: String,
    pub approval_ref: String,
    pub grant_resume_refs: Vec<String>,
    pub deny_outcome_refs: Vec<String>,
    pub expired_outcome_refs: Vec<String>,
    pub escalation_outcome_refs: Vec<String>,
    pub risk_refs: Vec<String>,
    pub summary: String,
}

impl DeferredDecisionBundle {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.decision_bundle_id.trim().is_empty() {
            return Err(OperationsError::MissingDecisionBundleId);
        }
        if self.approval_ref.trim().is_empty() {
            return Err(OperationsError::MissingApprovalRef);
        }
        validate_ref_list(
            &self.grant_resume_refs,
            OperationsError::MissingGrantResumeRefs,
        )?;
        validate_ref_list(
            &self.deny_outcome_refs,
            OperationsError::MissingDenyOutcomeRefs,
        )?;
        validate_optional_ref_list(
            &self.expired_outcome_refs,
            OperationsError::InvalidExpiredOutcomeRefs,
        )?;
        validate_optional_ref_list(
            &self.escalation_outcome_refs,
            OperationsError::InvalidEscalationOutcomeRefs,
        )?;
        validate_ref_list(&self.risk_refs, OperationsError::MissingRiskRefs)?;
        if self.summary.trim().is_empty() {
            return Err(OperationsError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsolidationJobRecord {
    pub consolidation_id: String,
    pub lease_ref: String,
    pub input_refs: Vec<String>,
    pub verification_policy_ref: String,
    pub output_refs: Vec<String>,
    pub checkpoint_refs: Vec<String>,
}

impl ConsolidationJobRecord {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.consolidation_id.trim().is_empty() {
            return Err(OperationsError::MissingConsolidationId);
        }
        if self.lease_ref.trim().is_empty() {
            return Err(OperationsError::MissingLeaseRef);
        }
        validate_ref_list(&self.input_refs, OperationsError::MissingInputRefs)?;
        if self.verification_policy_ref.trim().is_empty() {
            return Err(OperationsError::MissingVerificationPolicyRef);
        }
        validate_ref_list(&self.output_refs, OperationsError::MissingOutputRefs)?;
        validate_ref_list(
            &self.checkpoint_refs,
            OperationsError::MissingCheckpointRefs,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityJobClassification {
    pub job_class_id: String,
    pub job_class: String,
    pub allowed_actions: Vec<String>,
    pub forbidden_actions: Vec<String>,
    pub claim_boundary: String,
}

impl ContinuityJobClassification {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.job_class_id.trim().is_empty() {
            return Err(OperationsError::MissingJobClassId);
        }
        if self.job_class.trim().is_empty() {
            return Err(OperationsError::MissingJobClass);
        }
        validate_ref_list(
            &self.allowed_actions,
            OperationsError::MissingAllowedActions,
        )?;
        validate_ref_list(
            &self.forbidden_actions,
            OperationsError::MissingForbiddenActions,
        )?;
        if self.claim_boundary.trim().is_empty() {
            return Err(OperationsError::MissingClaimBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseExpiryRecord {
    pub expiry_id: String,
    pub lease_ref: String,
    pub continuity_ref: String,
    pub tick_ref: String,
    pub expiry_policy_ref: String,
    pub outcome_ref: String,
    pub summary: String,
}

impl LeaseExpiryRecord {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.expiry_id.trim().is_empty() {
            return Err(OperationsError::MissingExpiryId);
        }
        if self.lease_ref.trim().is_empty() {
            return Err(OperationsError::MissingLeaseRef);
        }
        if self.continuity_ref.trim().is_empty() {
            return Err(OperationsError::MissingContinuityRef);
        }
        if self.tick_ref.trim().is_empty() {
            return Err(OperationsError::MissingTickRef);
        }
        if self.expiry_policy_ref.trim().is_empty() {
            return Err(OperationsError::MissingExpiryPolicyRef);
        }
        if self.outcome_ref.trim().is_empty() {
            return Err(OperationsError::MissingOutcomeRef);
        }
        if self.summary.trim().is_empty() {
            return Err(OperationsError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellEscalationRecord {
    pub escalation_id: String,
    pub source_ref: String,
    pub campaign_ref: String,
    pub policy_ref: String,
    pub trigger_ref: String,
    pub outcome_ref: String,
    pub summary: String,
}

impl ShellEscalationRecord {
    pub fn validate(&self) -> Result<(), OperationsError> {
        if self.escalation_id.trim().is_empty() {
            return Err(OperationsError::MissingEscalationId);
        }
        if self.source_ref.trim().is_empty() {
            return Err(OperationsError::MissingSourceRef);
        }
        if self.campaign_ref.trim().is_empty() {
            return Err(OperationsError::MissingCampaignRef);
        }
        if self.policy_ref.trim().is_empty() {
            return Err(OperationsError::MissingPolicyRef);
        }
        if self.trigger_ref.trim().is_empty() {
            return Err(OperationsError::MissingTriggerRef);
        }
        if self.outcome_ref.trim().is_empty() {
            return Err(OperationsError::MissingOutcomeRef);
        }
        if self.summary.trim().is_empty() {
            return Err(OperationsError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationsError {
    MissingTickId,
    MissingWakeRecordId,
    MissingTargetRef,
    MissingLeaseRef,
    MissingContinuityRef,
    MissingSummary,
    MissingScheduledAt,
    MissingExecutedAt,
    MissingResultRef,
    MissingTickRef,
    MissingLeaseId,
    MissingJobClass,
    MissingOwnerRef,
    MissingScopeRef,
    MissingCampaignRef,
    MissingAuthorityRef,
    MissingWakePolicyRef,
    MissingRenewalPolicyRef,
    MissingInterruptionPolicyRef,
    MissingTerminationPolicyRef,
    MissingLeaseState,
    MissingOperationsDossierId,
    MissingJobRecordId,
    MissingJobKind,
    MissingBudgetRef,
    MissingEvidenceRefs,
    MissingAuditPacketId,
    MissingTickRefs,
    MissingWakeRefs,
    MissingLeaseRefs,
    MissingApprovalInboxRefs,
    MissingDecisionBundleRefs,
    MissingContinuityJobRefs,
    MissingAuditRefs,
    MissingOperatorSummaryRef,
    MissingOperatorSummary,
    InvalidExpiryRefs,
    InvalidEscalationRefs,
    InvalidQuarantineRefs,
    InvalidRollbackRefs,
    MissingApprovalInboxId,
    MissingPauseRef,
    MissingApprovalRefs,
    MissingDecisionAuthorityRefs,
    MissingDeadlinePolicyRef,
    MissingEscalationPolicyRef,
    MissingResponseRef,
    MissingResumeRef,
    MissingAuditSummaryRef,
    MissingCampaignRefs,
    MissingDecisionBundleId,
    MissingApprovalRef,
    MissingGrantResumeRefs,
    MissingDenyOutcomeRefs,
    InvalidExpiredOutcomeRefs,
    InvalidEscalationOutcomeRefs,
    MissingRiskRefs,
    MissingConsolidationId,
    MissingInputRefs,
    MissingVerificationPolicyRef,
    MissingOutputRefs,
    MissingCheckpointRefs,
    MissingJobClassId,
    MissingAllowedActions,
    MissingForbiddenActions,
    MissingClaimBoundary,
    MissingExpiryId,
    MissingExpiryPolicyRef,
    MissingOutcomeRef,
    MissingEscalationId,
    MissingSourceRef,
    MissingPolicyRef,
    MissingTriggerRef,
}

impl Display for OperationsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for OperationsError {}

fn validate_ref_list(refs: &[String], error: OperationsError) -> Result<(), OperationsError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

fn validate_optional_ref_list(
    refs: &[String],
    error: OperationsError,
) -> Result<(), OperationsError> {
    if refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalInboxRecord, DeferredDecisionBundle, LeaseExpiryRecord, PersistentJobLease,
        PersistentShellAuditPacket, PersistentShellOperationsDossier, ScheduledWakeRecord,
        ShellEscalationRecord,
    };

    #[test]
    fn lease_expiry_record_validation_accepts_complete_record() {
        let record = LeaseExpiryRecord {
            expiry_id: "expiry-1".to_string(),
            lease_ref: "lease-1".to_string(),
            continuity_ref: "continuity-1".to_string(),
            tick_ref: "tick-1".to_string(),
            expiry_policy_ref: "policy:expiry".to_string(),
            outcome_ref: "outcome:expired".to_string(),
            summary: "lease expired under bounded shell policy".to_string(),
        };

        assert!(record.validate().is_ok());
    }

    #[test]
    fn shell_escalation_record_validation_accepts_complete_record() {
        let record = ShellEscalationRecord {
            escalation_id: "escalation-1".to_string(),
            source_ref: "approval-1".to_string(),
            campaign_ref: "campaign-1".to_string(),
            policy_ref: "policy:authority-escalation".to_string(),
            trigger_ref: "trigger:approval-timeout".to_string(),
            outcome_ref: "outcome:paused".to_string(),
            summary: "shell escalation paused the campaign under explicit policy".to_string(),
        };

        assert!(record.validate().is_ok());
    }

    #[test]
    fn extended_operation_records_validate_new_fields() {
        let wake = ScheduledWakeRecord {
            wake_record_id: "wake-1".to_string(),
            continuity_ref: "continuity-1".to_string(),
            lease_ref: "lease-1".to_string(),
            tick_ref: "tick-1".to_string(),
            scheduled_at: "scheduled".to_string(),
            executed_at: "executed".to_string(),
            result_ref: "result".to_string(),
        };
        let lease = PersistentJobLease {
            lease_id: "lease-1".to_string(),
            job_class: "repair".to_string(),
            owner_ref: "program-1".to_string(),
            scope_ref: "scope:campaign-1".to_string(),
            campaign_ref: "campaign-1".to_string(),
            authority_ref: "authority:campaign-control".to_string(),
            wake_policy_ref: "policy:wake".to_string(),
            renewal_policy_ref: "policy:renew".to_string(),
            interruption_policy_ref: "policy:interrupt".to_string(),
            termination_policy_ref: "policy:terminate".to_string(),
            lease_state: "active".to_string(),
        };
        let inbox = ApprovalInboxRecord {
            approval_inbox_id: "inbox-1".to_string(),
            pause_ref: "pause-1".to_string(),
            approval_refs: vec!["approval-1".to_string()],
            decision_authority_refs: vec!["operator".to_string()],
            deadline_policy_ref: "policy:deadline".to_string(),
            escalation_policy_ref: "policy:escalate".to_string(),
            response_ref: "response:pending".to_string(),
            resume_ref: "resume:pending".to_string(),
            audit_summary_ref: "audit:summary".to_string(),
            campaign_refs: vec!["campaign-1".to_string()],
        };
        let bundle = DeferredDecisionBundle {
            decision_bundle_id: "bundle-1".to_string(),
            approval_ref: "approval-1".to_string(),
            grant_resume_refs: vec!["resume:granted".to_string()],
            deny_outcome_refs: vec!["outcome:denied".to_string()],
            expired_outcome_refs: vec!["outcome:expired".to_string()],
            escalation_outcome_refs: vec!["outcome:escalated".to_string()],
            risk_refs: vec!["risk:timeout".to_string()],
            summary: "all bounded approval outcomes stay explicit".to_string(),
        };
        let audit = PersistentShellAuditPacket {
            audit_packet_id: "audit-1".to_string(),
            continuity_ref: "continuity-1".to_string(),
            tick_refs: vec!["tick-1".to_string()],
            wake_refs: vec!["wake-1".to_string()],
            lease_refs: vec!["lease-1".to_string()],
            approval_inbox_refs: vec!["inbox-1".to_string()],
            decision_bundle_refs: vec!["bundle-1".to_string()],
            job_refs: vec!["job-1".to_string()],
            expiry_refs: vec!["expiry-1".to_string()],
            escalation_refs: vec!["escalation-1".to_string()],
            evidence_refs: vec!["evidence-1".to_string()],
            operator_summary: "audit trail".to_string(),
        };
        let dossier = PersistentShellOperationsDossier {
            operations_dossier_id: "dossier-1".to_string(),
            continuity_ref: "continuity-1".to_string(),
            tick_refs: vec!["tick-1".to_string()],
            wake_refs: vec!["wake-1".to_string()],
            lease_refs: vec!["lease-1".to_string()],
            approval_inbox_refs: vec!["inbox-1".to_string()],
            decision_bundle_refs: vec!["bundle-1".to_string()],
            continuity_job_refs: vec!["job-1".to_string()],
            expiry_refs: vec!["expiry-1".to_string()],
            escalation_refs: vec!["escalation-1".to_string()],
            quarantine_refs: vec!["quarantine-1".to_string()],
            rollback_refs: vec!["rollback-1".to_string()],
            audit_refs: vec!["audit-1".to_string()],
            operator_summary_ref: "operator:summary".to_string(),
        };

        assert!(wake.validate().is_ok());
        assert!(lease.validate().is_ok());
        assert!(inbox.validate().is_ok());
        assert!(bundle.validate().is_ok());
        assert!(audit.validate().is_ok());
        assert!(dossier.validate().is_ok());
    }
}
