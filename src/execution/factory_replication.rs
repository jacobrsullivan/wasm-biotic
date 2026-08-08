use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryReplicationStage {
    Define,
    Produce,
    Validate,
    Prove,
    Observe,
    Decide,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryReplicationDecisionKind {
    RetainParent,
    RejectChild,
    AdoptChildForObservation,
    QuarantineChild,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryReplicationCampaign {
    pub replication_campaign_id: String,
    pub adopted_factory_ref: String,
    pub later_factory_request_ref: String,
    pub runtime_stage: FactoryReplicationStage,
    pub governance_refs: Vec<String>,
    pub replay_refs: Vec<String>,
}

impl FactoryReplicationCampaign {
    pub fn validate(&self) -> Result<(), FactoryReplicationError> {
        if self.replication_campaign_id.trim().is_empty() {
            return Err(FactoryReplicationError::MissingReplicationCampaignId);
        }
        if self.adopted_factory_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingAdoptedFactoryRef);
        }
        if self.later_factory_request_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingLaterFactoryRequestRef);
        }
        validate_ref_list(
            &self.governance_refs,
            FactoryReplicationError::MissingGovernanceRefs,
        )?;
        validate_ref_list(
            &self.replay_refs,
            FactoryReplicationError::MissingReplayRefs,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaterFactoryCandidate {
    pub later_factory_candidate_id: String,
    pub parent_factory_ref: String,
    pub production_trace_refs: Vec<String>,
    pub factory_genome_ref: String,
    pub factory_phenotype_ref: String,
    pub bounded_scope: String,
    pub summary: String,
}

impl LaterFactoryCandidate {
    pub fn validate(&self) -> Result<(), FactoryReplicationError> {
        if self.later_factory_candidate_id.trim().is_empty() {
            return Err(FactoryReplicationError::MissingLaterFactoryCandidateId);
        }
        if self.parent_factory_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingParentFactoryRef);
        }
        validate_ref_list(
            &self.production_trace_refs,
            FactoryReplicationError::MissingProductionTraceRefs,
        )?;
        if self.factory_genome_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingFactoryGenomeRef);
        }
        if self.factory_phenotype_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingFactoryPhenotypeRef);
        }
        if self.bounded_scope.trim().is_empty() {
            return Err(FactoryReplicationError::MissingBoundedScope);
        }
        if self.summary.trim().is_empty() {
            return Err(FactoryReplicationError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryProvingRunRecord {
    pub proving_run_id: String,
    pub factory_candidate_ref: String,
    pub scenario_refs: Vec<String>,
    pub shell_evidence_refs: Vec<String>,
    pub governance_refs: Vec<String>,
    pub passed: bool,
    pub result_summary: String,
}

impl FactoryProvingRunRecord {
    pub fn validate(&self) -> Result<(), FactoryReplicationError> {
        if self.proving_run_id.trim().is_empty() {
            return Err(FactoryReplicationError::MissingProvingRunId);
        }
        if self.factory_candidate_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingFactoryCandidateRef);
        }
        validate_ref_list(
            &self.scenario_refs,
            FactoryReplicationError::MissingScenarioRefs,
        )?;
        validate_ref_list(
            &self.shell_evidence_refs,
            FactoryReplicationError::MissingShellEvidenceRefs,
        )?;
        validate_ref_list(
            &self.governance_refs,
            FactoryReplicationError::MissingGovernanceRefs,
        )?;
        if self.result_summary.trim().is_empty() {
            return Err(FactoryReplicationError::MissingResultSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryReplicationDecision {
    pub decision_id: String,
    pub replication_campaign_ref: String,
    pub factory_candidate_ref: String,
    pub decision: FactoryReplicationDecisionKind,
    pub rollback_refs: Vec<String>,
    pub summary: String,
}

impl FactoryReplicationDecision {
    pub fn validate(&self) -> Result<(), FactoryReplicationError> {
        if self.decision_id.trim().is_empty() {
            return Err(FactoryReplicationError::MissingDecisionId);
        }
        if self.replication_campaign_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingReplicationCampaignRef);
        }
        if self.factory_candidate_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingFactoryCandidateRef);
        }
        validate_ref_list(
            &self.rollback_refs,
            FactoryReplicationError::MissingRollbackRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryReplicationError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryReplicationEvidencePacket {
    pub packet_id: String,
    pub parent_factory_ref: String,
    pub child_factory_ref: String,
    pub production_refs: Vec<String>,
    pub proving_refs: Vec<String>,
    pub governance_refs: Vec<String>,
    pub claim_boundary: String,
}

impl FactoryReplicationEvidencePacket {
    pub fn validate(&self) -> Result<(), FactoryReplicationError> {
        if self.packet_id.trim().is_empty() {
            return Err(FactoryReplicationError::MissingPacketId);
        }
        if self.parent_factory_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingParentFactoryRef);
        }
        if self.child_factory_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingFactoryCandidateRef);
        }
        validate_ref_list(
            &self.production_refs,
            FactoryReplicationError::MissingProductionTraceRefs,
        )?;
        validate_ref_list(
            &self.proving_refs,
            FactoryReplicationError::MissingProvingRefs,
        )?;
        validate_ref_list(
            &self.governance_refs,
            FactoryReplicationError::MissingGovernanceRefs,
        )?;
        if self.claim_boundary.trim().is_empty() {
            return Err(FactoryReplicationError::MissingClaimBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildFactoryObservationStatus {
    Active,
    Passed,
    QuarantineReady,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildFactoryObservationWindowRecord {
    pub observation_window_id: String,
    pub replication_campaign_ref: String,
    pub child_factory_ref: String,
    pub observation_event_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub status: ChildFactoryObservationStatus,
    pub summary: String,
}

impl ChildFactoryObservationWindowRecord {
    pub fn validate(&self) -> Result<(), FactoryReplicationError> {
        if self.observation_window_id.trim().is_empty() {
            return Err(FactoryReplicationError::MissingObservationWindowId);
        }
        if self.replication_campaign_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingReplicationCampaignRef);
        }
        if self.child_factory_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingFactoryCandidateRef);
        }
        validate_ref_list(
            &self.observation_event_refs,
            FactoryReplicationError::MissingObservationEventRefs,
        )?;
        validate_ref_list(
            &self.rollback_refs,
            FactoryReplicationError::MissingRollbackRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryReplicationError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildFactoryQuarantineProtocolRecord {
    pub protocol_id: String,
    pub observation_window_ref: String,
    pub child_factory_ref: String,
    pub trigger_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub summary: String,
}

impl ChildFactoryQuarantineProtocolRecord {
    pub fn validate(&self) -> Result<(), FactoryReplicationError> {
        if self.protocol_id.trim().is_empty() {
            return Err(FactoryReplicationError::MissingQuarantineProtocolId);
        }
        if self.observation_window_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingObservationWindowRef);
        }
        if self.child_factory_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingFactoryCandidateRef);
        }
        validate_ref_list(
            &self.trigger_refs,
            FactoryReplicationError::MissingQuarantineTriggerRefs,
        )?;
        validate_ref_list(
            &self.rollback_refs,
            FactoryReplicationError::MissingRollbackRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryReplicationError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildFactoryDispositionKind {
    Rollback,
    Discard,
    RetainForReview,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildFactoryDispositionRecord {
    pub disposition_id: String,
    pub child_factory_ref: String,
    pub decision_ref: String,
    pub disposition: ChildFactoryDispositionKind,
    pub rollback_refs: Vec<String>,
    pub summary: String,
}

impl ChildFactoryDispositionRecord {
    pub fn validate(&self) -> Result<(), FactoryReplicationError> {
        if self.disposition_id.trim().is_empty() {
            return Err(FactoryReplicationError::MissingDispositionId);
        }
        if self.child_factory_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingFactoryCandidateRef);
        }
        if self.decision_ref.trim().is_empty() {
            return Err(FactoryReplicationError::MissingDecisionRef);
        }
        validate_ref_list(
            &self.rollback_refs,
            FactoryReplicationError::MissingRollbackRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryReplicationError::MissingSummary);
        }
        Ok(())
    }
}

pub fn start_factory_replication_campaign(
    replication_campaign_id: impl Into<String>,
    adopted_factory_ref: impl Into<String>,
    later_factory_request_ref: impl Into<String>,
    governance_refs: Vec<String>,
    replay_refs: Vec<String>,
) -> Result<FactoryReplicationCampaign, FactoryReplicationError> {
    let campaign = FactoryReplicationCampaign {
        replication_campaign_id: replication_campaign_id.into(),
        adopted_factory_ref: adopted_factory_ref.into(),
        later_factory_request_ref: later_factory_request_ref.into(),
        runtime_stage: FactoryReplicationStage::Define,
        governance_refs,
        replay_refs,
    };
    campaign.validate()?;
    Ok(campaign)
}

pub fn materialize_later_factory_candidate(
    campaign: &mut FactoryReplicationCampaign,
    later_factory_candidate_id: impl Into<String>,
    production_trace_refs: Vec<String>,
    factory_genome_ref: impl Into<String>,
    factory_phenotype_ref: impl Into<String>,
    bounded_scope: impl Into<String>,
    summary: impl Into<String>,
) -> Result<LaterFactoryCandidate, FactoryReplicationError> {
    campaign.validate()?;
    if campaign.runtime_stage == FactoryReplicationStage::Decide {
        return Err(FactoryReplicationError::ReplicationCampaignAlreadyDecided);
    }

    let candidate = LaterFactoryCandidate {
        later_factory_candidate_id: later_factory_candidate_id.into(),
        parent_factory_ref: campaign.adopted_factory_ref.clone(),
        production_trace_refs,
        factory_genome_ref: factory_genome_ref.into(),
        factory_phenotype_ref: factory_phenotype_ref.into(),
        bounded_scope: bounded_scope.into(),
        summary: summary.into(),
    };
    candidate.validate()?;
    campaign.runtime_stage = FactoryReplicationStage::Produce;
    Ok(candidate)
}

pub fn record_factory_proving_run(
    campaign: &mut FactoryReplicationCampaign,
    proving_run_id: impl Into<String>,
    candidate: &LaterFactoryCandidate,
    scenario_refs: Vec<String>,
    shell_evidence_refs: Vec<String>,
    governance_refs: Vec<String>,
    passed: bool,
    result_summary: impl Into<String>,
) -> Result<FactoryProvingRunRecord, FactoryReplicationError> {
    campaign.validate()?;
    candidate.validate()?;
    if candidate.parent_factory_ref != campaign.adopted_factory_ref {
        return Err(FactoryReplicationError::ParentFactoryMismatch {
            expected: campaign.adopted_factory_ref.clone(),
            actual: candidate.parent_factory_ref.clone(),
        });
    }

    let record = FactoryProvingRunRecord {
        proving_run_id: proving_run_id.into(),
        factory_candidate_ref: candidate.later_factory_candidate_id.clone(),
        scenario_refs,
        shell_evidence_refs,
        governance_refs,
        passed,
        result_summary: result_summary.into(),
    };
    record.validate()?;
    campaign.runtime_stage = FactoryReplicationStage::Prove;
    Ok(record)
}

pub fn finalize_factory_replication_decision(
    campaign: &mut FactoryReplicationCampaign,
    decision_id: impl Into<String>,
    candidate: &LaterFactoryCandidate,
    proving_run: &FactoryProvingRunRecord,
    decision: FactoryReplicationDecisionKind,
    rollback_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<FactoryReplicationDecision, FactoryReplicationError> {
    campaign.validate()?;
    candidate.validate()?;
    proving_run.validate()?;
    if candidate.parent_factory_ref != campaign.adopted_factory_ref {
        return Err(FactoryReplicationError::ParentFactoryMismatch {
            expected: campaign.adopted_factory_ref.clone(),
            actual: candidate.parent_factory_ref.clone(),
        });
    }
    if proving_run.factory_candidate_ref != candidate.later_factory_candidate_id {
        return Err(FactoryReplicationError::CandidateMismatch {
            expected: candidate.later_factory_candidate_id.clone(),
            actual: proving_run.factory_candidate_ref.clone(),
        });
    }
    if decision == FactoryReplicationDecisionKind::AdoptChildForObservation && !proving_run.passed {
        return Err(FactoryReplicationError::CannotAdoptWithoutPassingProvingRun);
    }

    let record = FactoryReplicationDecision {
        decision_id: decision_id.into(),
        replication_campaign_ref: campaign.replication_campaign_id.clone(),
        factory_candidate_ref: candidate.later_factory_candidate_id.clone(),
        decision,
        rollback_refs,
        summary: summary.into(),
    };
    record.validate()?;
    campaign.runtime_stage = FactoryReplicationStage::Decide;
    Ok(record)
}

pub fn assemble_factory_replication_evidence_packet(
    packet_id: impl Into<String>,
    campaign: &FactoryReplicationCampaign,
    candidate: &LaterFactoryCandidate,
    proving_run: &FactoryProvingRunRecord,
    decision: &FactoryReplicationDecision,
    claim_boundary: impl Into<String>,
) -> Result<FactoryReplicationEvidencePacket, FactoryReplicationError> {
    campaign.validate()?;
    candidate.validate()?;
    proving_run.validate()?;
    decision.validate()?;
    if candidate.parent_factory_ref != campaign.adopted_factory_ref {
        return Err(FactoryReplicationError::ParentFactoryMismatch {
            expected: campaign.adopted_factory_ref.clone(),
            actual: candidate.parent_factory_ref.clone(),
        });
    }
    if proving_run.factory_candidate_ref != candidate.later_factory_candidate_id
        || decision.factory_candidate_ref != candidate.later_factory_candidate_id
        || decision.replication_campaign_ref != campaign.replication_campaign_id
    {
        return Err(FactoryReplicationError::ReplicationEvidenceAlignmentFailed);
    }

    let packet = FactoryReplicationEvidencePacket {
        packet_id: packet_id.into(),
        parent_factory_ref: campaign.adopted_factory_ref.clone(),
        child_factory_ref: candidate.later_factory_candidate_id.clone(),
        production_refs: candidate.production_trace_refs.clone(),
        proving_refs: vec![proving_run.proving_run_id.clone()],
        governance_refs: vec![decision.decision_id.clone()],
        claim_boundary: claim_boundary.into(),
    };
    packet.validate()?;
    Ok(packet)
}

pub fn open_child_factory_observation_window(
    campaign: &FactoryReplicationCampaign,
    candidate: &LaterFactoryCandidate,
    decision: &FactoryReplicationDecision,
    observation_window_id: impl Into<String>,
    observation_event_refs: Vec<String>,
    rollback_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<ChildFactoryObservationWindowRecord, FactoryReplicationError> {
    campaign.validate()?;
    candidate.validate()?;
    decision.validate()?;
    if decision.replication_campaign_ref != campaign.replication_campaign_id
        || decision.factory_candidate_ref != candidate.later_factory_candidate_id
    {
        return Err(FactoryReplicationError::ReplicationEvidenceAlignmentFailed);
    }

    let status = match decision.decision {
        FactoryReplicationDecisionKind::AdoptChildForObservation => {
            ChildFactoryObservationStatus::Active
        }
        FactoryReplicationDecisionKind::QuarantineChild => {
            ChildFactoryObservationStatus::QuarantineReady
        }
        FactoryReplicationDecisionKind::RetainParent
        | FactoryReplicationDecisionKind::RejectChild => {
            return Err(FactoryReplicationError::ObservationRequiresObservationDecision);
        }
    };

    let record = ChildFactoryObservationWindowRecord {
        observation_window_id: observation_window_id.into(),
        replication_campaign_ref: campaign.replication_campaign_id.clone(),
        child_factory_ref: candidate.later_factory_candidate_id.clone(),
        observation_event_refs,
        rollback_refs,
        status,
        summary: summary.into(),
    };
    record.validate()?;
    Ok(record)
}

pub fn issue_child_factory_quarantine_protocol(
    observation: &ChildFactoryObservationWindowRecord,
    protocol_id: impl Into<String>,
    trigger_refs: Vec<String>,
    rollback_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<ChildFactoryQuarantineProtocolRecord, FactoryReplicationError> {
    observation.validate()?;
    let protocol = ChildFactoryQuarantineProtocolRecord {
        protocol_id: protocol_id.into(),
        observation_window_ref: observation.observation_window_id.clone(),
        child_factory_ref: observation.child_factory_ref.clone(),
        trigger_refs,
        rollback_refs,
        summary: summary.into(),
    };
    protocol.validate()?;
    Ok(protocol)
}

pub fn issue_child_factory_disposition(
    decision: &FactoryReplicationDecision,
    child_factory_ref: impl Into<String>,
    disposition_id: impl Into<String>,
    disposition: ChildFactoryDispositionKind,
    rollback_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<ChildFactoryDispositionRecord, FactoryReplicationError> {
    decision.validate()?;
    let record = ChildFactoryDispositionRecord {
        disposition_id: disposition_id.into(),
        child_factory_ref: child_factory_ref.into(),
        decision_ref: decision.decision_id.clone(),
        disposition,
        rollback_refs,
        summary: summary.into(),
    };
    record.validate()?;
    Ok(record)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactoryReplicationError {
    MissingReplicationCampaignId,
    MissingAdoptedFactoryRef,
    MissingLaterFactoryRequestRef,
    MissingLaterFactoryCandidateId,
    MissingParentFactoryRef,
    MissingFactoryGenomeRef,
    MissingFactoryPhenotypeRef,
    MissingProvingRunId,
    MissingDecisionId,
    MissingReplicationCampaignRef,
    MissingPacketId,
    MissingObservationWindowId,
    MissingObservationWindowRef,
    MissingQuarantineProtocolId,
    MissingDispositionId,
    MissingGovernanceRefs,
    MissingReplayRefs,
    MissingProductionTraceRefs,
    MissingScenarioRefs,
    MissingShellEvidenceRefs,
    MissingRollbackRefs,
    MissingProvingRefs,
    MissingObservationEventRefs,
    MissingQuarantineTriggerRefs,
    MissingDecisionRef,
    MissingBoundedScope,
    MissingClaimBoundary,
    MissingSummary,
    MissingResultSummary,
    MissingFactoryCandidateRef,
    ReplicationCampaignAlreadyDecided,
    ObservationRequiresObservationDecision,
    ParentFactoryMismatch { expected: String, actual: String },
    CandidateMismatch { expected: String, actual: String },
    CannotAdoptWithoutPassingProvingRun,
    ReplicationEvidenceAlignmentFailed,
}

impl Display for FactoryReplicationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingReplicationCampaignId => {
                write!(f, "factory replication campaign requires a campaign id")
            }
            Self::MissingAdoptedFactoryRef => {
                write!(
                    f,
                    "factory replication campaign requires an adopted factory ref"
                )
            }
            Self::MissingLaterFactoryRequestRef => {
                write!(
                    f,
                    "factory replication campaign requires a later-factory request ref"
                )
            }
            Self::MissingLaterFactoryCandidateId => {
                write!(f, "later-factory candidate requires a candidate id")
            }
            Self::MissingParentFactoryRef => {
                write!(f, "later-factory candidate requires a parent factory ref")
            }
            Self::MissingFactoryGenomeRef => {
                write!(f, "later-factory candidate requires a factory genome ref")
            }
            Self::MissingFactoryPhenotypeRef => {
                write!(
                    f,
                    "later-factory candidate requires a factory phenotype ref"
                )
            }
            Self::MissingProvingRunId => write!(f, "factory proving run requires an id"),
            Self::MissingDecisionId => {
                write!(f, "factory replication decision requires an id")
            }
            Self::MissingReplicationCampaignRef => {
                write!(f, "factory replication decision requires a campaign ref")
            }
            Self::MissingPacketId => {
                write!(f, "factory replication evidence packet requires an id")
            }
            Self::MissingObservationWindowId => {
                write!(f, "child-factory observation requires a window id")
            }
            Self::MissingObservationWindowRef => {
                write!(
                    f,
                    "child-factory quarantine protocol requires an observation window ref"
                )
            }
            Self::MissingQuarantineProtocolId => {
                write!(f, "child-factory quarantine protocol requires an id")
            }
            Self::MissingDispositionId => {
                write!(f, "child-factory disposition requires an id")
            }
            Self::MissingGovernanceRefs => {
                write!(f, "factory replication requires governance refs")
            }
            Self::MissingReplayRefs => write!(f, "factory replication requires replay refs"),
            Self::MissingProductionTraceRefs => {
                write!(f, "later-factory candidate requires production trace refs")
            }
            Self::MissingScenarioRefs => write!(f, "factory proving run requires scenario refs"),
            Self::MissingShellEvidenceRefs => {
                write!(f, "factory proving run requires shell evidence refs")
            }
            Self::MissingRollbackRefs => {
                write!(f, "factory replication decision requires rollback refs")
            }
            Self::MissingProvingRefs => {
                write!(
                    f,
                    "factory replication evidence packet requires proving refs"
                )
            }
            Self::MissingObservationEventRefs => {
                write!(f, "child-factory observation requires event refs")
            }
            Self::MissingQuarantineTriggerRefs => {
                write!(f, "child-factory quarantine protocol requires trigger refs")
            }
            Self::MissingDecisionRef => {
                write!(f, "child-factory disposition requires a decision ref")
            }
            Self::MissingBoundedScope => {
                write!(
                    f,
                    "later-factory candidate requires a bounded scope statement"
                )
            }
            Self::MissingClaimBoundary => {
                write!(
                    f,
                    "factory replication evidence packet requires a claim boundary"
                )
            }
            Self::MissingSummary => write!(f, "factory replication record requires a summary"),
            Self::MissingResultSummary => {
                write!(f, "factory proving run requires a result summary")
            }
            Self::MissingFactoryCandidateRef => {
                write!(
                    f,
                    "factory replication record requires a factory candidate ref"
                )
            }
            Self::ReplicationCampaignAlreadyDecided => {
                write!(
                    f,
                    "factory replication campaign is already in the decided stage"
                )
            }
            Self::ObservationRequiresObservationDecision => write!(
                f,
                "child-factory observation requires an observe or quarantine decision"
            ),
            Self::ParentFactoryMismatch { expected, actual } => write!(
                f,
                "factory replication expected parent factory '{}', got '{}'",
                expected, actual
            ),
            Self::CandidateMismatch { expected, actual } => write!(
                f,
                "factory replication expected candidate '{}', got '{}'",
                expected, actual
            ),
            Self::CannotAdoptWithoutPassingProvingRun => write!(
                f,
                "factory replication cannot adopt a child without a passing proving run"
            ),
            Self::ReplicationEvidenceAlignmentFailed => write!(
                f,
                "factory replication evidence packet inputs must remain aligned"
            ),
        }
    }
}

impl Error for FactoryReplicationError {}

fn validate_ref_list(
    refs: &[String],
    error: FactoryReplicationError,
) -> Result<(), FactoryReplicationError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replication_requires_passing_proving_run_for_adoption() {
        let mut campaign = start_factory_replication_campaign(
            "replication-1",
            "factory-parent",
            "later-request-1",
            vec!["governance:adoption".to_string()],
            vec!["replay:checkpoint".to_string()],
        )
        .unwrap();
        let candidate = materialize_later_factory_candidate(
            &mut campaign,
            "candidate-1",
            vec!["production:trace-1".to_string()],
            "factory-genome-child",
            "factory-phenotype-child",
            "bounded single-factory child candidate",
            "child factory candidate",
        )
        .unwrap();
        let proving = record_factory_proving_run(
            &mut campaign,
            "proving-1",
            &candidate,
            vec!["scenario:bounded-proof".to_string()],
            vec!["shell:evidence-1".to_string()],
            vec!["governance:proof-1".to_string()],
            false,
            "proving run failed",
        )
        .unwrap();

        let error = finalize_factory_replication_decision(
            &mut campaign,
            "decision-1",
            &candidate,
            &proving,
            FactoryReplicationDecisionKind::AdoptChildForObservation,
            vec!["rollback:child-1".to_string()],
            "attempted adoption",
        )
        .unwrap_err();
        assert_eq!(
            error,
            FactoryReplicationError::CannotAdoptWithoutPassingProvingRun
        );
    }

    #[test]
    fn child_observation_and_quarantine_protocol_roundtrip() {
        let mut campaign = start_factory_replication_campaign(
            "replication-2",
            "factory-parent",
            "later-request-2",
            vec!["governance:adoption".to_string()],
            vec!["replay:checkpoint".to_string()],
        )
        .unwrap();
        let candidate = materialize_later_factory_candidate(
            &mut campaign,
            "candidate-2",
            vec!["production:trace-2".to_string()],
            "factory-genome-child",
            "factory-phenotype-child",
            "bounded single-factory child candidate",
            "child factory candidate",
        )
        .unwrap();
        let proving = record_factory_proving_run(
            &mut campaign,
            "proving-2",
            &candidate,
            vec!["scenario:bounded-proof".to_string()],
            vec!["shell:evidence-2".to_string()],
            vec!["governance:proof-2".to_string()],
            true,
            "proving run passed",
        )
        .unwrap();
        let decision = finalize_factory_replication_decision(
            &mut campaign,
            "decision-2",
            &candidate,
            &proving,
            FactoryReplicationDecisionKind::AdoptChildForObservation,
            vec!["rollback:child-2".to_string()],
            "child enters bounded observation",
        )
        .unwrap();

        let observation = open_child_factory_observation_window(
            &campaign,
            &candidate,
            &decision,
            "observation-2",
            vec![
                "event:child-started".to_string(),
                "event:child-replayed".to_string(),
            ],
            vec!["rollback:child-2".to_string()],
            "child factory remains under bounded observation",
        )
        .unwrap();
        assert_eq!(observation.status, ChildFactoryObservationStatus::Active);

        let quarantine = issue_child_factory_quarantine_protocol(
            &observation,
            "quarantine-protocol-2",
            vec![
                "trigger:regression".to_string(),
                "trigger:governance-drift".to_string(),
            ],
            vec!["rollback:child-2".to_string()],
            "quarantine the child if bounded observation regresses",
        )
        .unwrap();
        assert_eq!(
            quarantine.observation_window_ref,
            observation.observation_window_id
        );

        let disposition = issue_child_factory_disposition(
            &decision,
            candidate.later_factory_candidate_id.clone(),
            "disposition-2",
            ChildFactoryDispositionKind::Rollback,
            vec!["rollback:child-2".to_string()],
            "rollback the child if observation regresses",
        )
        .unwrap();
        assert_eq!(disposition.decision_ref, decision.decision_id);
    }
}
