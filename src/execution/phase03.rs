use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecurringFactoryWorkspacePacket {
    pub factory_workspace_id: String,
    pub program_ref: String,
    pub cycle_refs: Vec<String>,
    pub lineage_refs: Vec<String>,
    pub budget_ref: String,
    pub continuity_refs: Vec<String>,
    pub stability_refs: Vec<String>,
    pub claim_boundary_ref: String,
}

impl RecurringFactoryWorkspacePacket {
    pub fn validate(&self) -> Result<(), Phase03PacketError> {
        if self.factory_workspace_id.trim().is_empty() {
            return Err(Phase03PacketError::MissingWorkspaceId);
        }
        if self.program_ref.trim().is_empty() {
            return Err(Phase03PacketError::MissingProgramRef);
        }
        validate_ref_list(&self.cycle_refs, Phase03PacketError::MissingCycleRefs)?;
        validate_ref_list(&self.lineage_refs, Phase03PacketError::MissingLineageRefs)?;
        if self.budget_ref.trim().is_empty() {
            return Err(Phase03PacketError::MissingBudgetRef);
        }
        validate_ref_list(
            &self.continuity_refs,
            Phase03PacketError::MissingContinuityRefs,
        )?;
        validate_ref_list(
            &self.stability_refs,
            Phase03PacketError::MissingStabilityRefs,
        )?;
        if self.claim_boundary_ref.trim().is_empty() {
            return Err(Phase03PacketError::MissingClaimBoundaryRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemClosureWorkspacePacket {
    pub ecosystem_workspace_id: String,
    pub admission_refs: Vec<String>,
    pub route_refs: Vec<String>,
    pub health_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub continuity_refs: Vec<String>,
    pub stability_refs: Vec<String>,
    pub claim_boundary_ref: String,
}

impl EcosystemClosureWorkspacePacket {
    pub fn validate(&self) -> Result<(), Phase03PacketError> {
        if self.ecosystem_workspace_id.trim().is_empty() {
            return Err(Phase03PacketError::MissingWorkspaceId);
        }
        validate_ref_list(
            &self.admission_refs,
            Phase03PacketError::MissingAdmissionRefs,
        )?;
        validate_ref_list(&self.route_refs, Phase03PacketError::MissingRouteRefs)?;
        validate_ref_list(&self.health_refs, Phase03PacketError::MissingHealthRefs)?;
        validate_ref_list(&self.rollback_refs, Phase03PacketError::MissingRollbackRefs)?;
        validate_ref_list(
            &self.continuity_refs,
            Phase03PacketError::MissingContinuityRefs,
        )?;
        validate_ref_list(
            &self.stability_refs,
            Phase03PacketError::MissingStabilityRefs,
        )?;
        if self.claim_boundary_ref.trim().is_empty() {
            return Err(Phase03PacketError::MissingClaimBoundaryRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase03ClosureReviewPacket {
    pub closure_review_packet_id: String,
    pub factory_program_refs: Vec<String>,
    pub lineage_refs: Vec<String>,
    pub continuity_refs: Vec<String>,
    pub ecosystem_refs: Vec<String>,
    pub acceptable_caveat_refs: Vec<String>,
    pub blocking_risk_refs: Vec<String>,
    pub risk_refs: Vec<String>,
    pub summary: String,
}

impl Phase03ClosureReviewPacket {
    pub fn validate(&self) -> Result<(), Phase03PacketError> {
        if self.closure_review_packet_id.trim().is_empty() {
            return Err(Phase03PacketError::MissingClosureReviewPacketId);
        }
        validate_ref_list(
            &self.factory_program_refs,
            Phase03PacketError::MissingFactoryProgramRefs,
        )?;
        validate_ref_list(&self.lineage_refs, Phase03PacketError::MissingLineageRefs)?;
        validate_ref_list(
            &self.continuity_refs,
            Phase03PacketError::MissingContinuityRefs,
        )?;
        validate_ref_list(
            &self.ecosystem_refs,
            Phase03PacketError::MissingEcosystemRefs,
        )?;
        validate_ref_list(&self.risk_refs, Phase03PacketError::MissingRiskRefs)?;
        validate_optional_ref_list(
            &self.acceptable_caveat_refs,
            Phase03PacketError::InvalidAcceptableCaveatRefs,
        )?;
        validate_optional_ref_list(
            &self.blocking_risk_refs,
            Phase03PacketError::InvalidBlockingRiskRefs,
        )?;
        if self.acceptable_caveat_refs.is_empty() && self.blocking_risk_refs.is_empty() {
            return Err(Phase03PacketError::MissingRiskClassificationRefs);
        }
        let acceptable = self
            .acceptable_caveat_refs
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let blocking = self
            .blocking_risk_refs
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if !acceptable.is_disjoint(&blocking) {
            return Err(Phase03PacketError::OverlappingRiskClassificationRefs);
        }
        let aggregate = self.risk_refs.iter().cloned().collect::<BTreeSet<_>>();
        let classified = acceptable
            .union(&blocking)
            .cloned()
            .collect::<BTreeSet<_>>();
        if aggregate != classified {
            return Err(Phase03PacketError::RiskRefsDoNotMatchClassification);
        }
        if self.summary.trim().is_empty() {
            return Err(Phase03PacketError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase03PacketError {
    MissingWorkspaceId,
    MissingProgramRef,
    MissingCycleRefs,
    MissingLineageRefs,
    MissingBudgetRef,
    MissingContinuityRefs,
    MissingStabilityRefs,
    MissingClaimBoundaryRef,
    MissingAdmissionRefs,
    MissingRouteRefs,
    MissingHealthRefs,
    MissingRollbackRefs,
    MissingClosureReviewPacketId,
    MissingFactoryProgramRefs,
    MissingEcosystemRefs,
    MissingRiskRefs,
    InvalidAcceptableCaveatRefs,
    InvalidBlockingRiskRefs,
    MissingRiskClassificationRefs,
    OverlappingRiskClassificationRefs,
    RiskRefsDoNotMatchClassification,
    MissingSummary,
}

impl Display for Phase03PacketError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for Phase03PacketError {}

fn validate_ref_list(refs: &[String], error: Phase03PacketError) -> Result<(), Phase03PacketError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

fn validate_optional_ref_list(
    refs: &[String],
    error: Phase03PacketError,
) -> Result<(), Phase03PacketError> {
    if refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase03_workspace_packets_validate() {
        let factory = RecurringFactoryWorkspacePacket {
            factory_workspace_id: "phase03-factory-workspace".to_string(),
            program_ref: "phase03-program".to_string(),
            cycle_refs: vec!["cycle:a".to_string(), "cycle:b".to_string()],
            lineage_refs: vec!["lineage:dossier".to_string()],
            budget_ref: "budget:a".to_string(),
            continuity_refs: vec!["continuity:a".to_string()],
            stability_refs: vec!["stability:a".to_string()],
            claim_boundary_ref: "claim:bounded-recursion".to_string(),
        };
        factory.validate().unwrap();

        let ecosystem = EcosystemClosureWorkspacePacket {
            ecosystem_workspace_id: "phase03-ecosystem-workspace".to_string(),
            admission_refs: vec!["admission:a".to_string(), "admission:b".to_string()],
            route_refs: vec!["route-ledger:a".to_string()],
            health_refs: vec!["health-ledger:a".to_string()],
            rollback_refs: vec!["rollback:a".to_string()],
            continuity_refs: vec!["continuity-window:a".to_string()],
            stability_refs: vec!["rollback-symmetry:a".to_string()],
            claim_boundary_ref: "claim:bounded-ecosystem".to_string(),
        };
        ecosystem.validate().unwrap();

        let packet = Phase03ClosureReviewPacket {
            closure_review_packet_id: "phase03-closure-review".to_string(),
            factory_program_refs: vec!["phase03-program".to_string()],
            lineage_refs: vec!["lineage:dossier".to_string()],
            continuity_refs: vec!["continuity:a".to_string()],
            ecosystem_refs: vec!["health-ledger:a".to_string()],
            acceptable_caveat_refs: vec!["risk:bounded".to_string()],
            blocking_risk_refs: Vec::new(),
            risk_refs: vec!["risk:bounded".to_string()],
            summary: "phase 03 closure packet".to_string(),
        };
        packet.validate().unwrap();
    }

    #[test]
    fn phase03_closure_packet_rejects_misaligned_risk_classification() {
        let packet = Phase03ClosureReviewPacket {
            closure_review_packet_id: "phase03-closure-review".to_string(),
            factory_program_refs: vec!["phase03-program".to_string()],
            lineage_refs: vec!["lineage:dossier".to_string()],
            continuity_refs: vec!["continuity:a".to_string()],
            ecosystem_refs: vec!["health-ledger:a".to_string()],
            acceptable_caveat_refs: vec!["risk:caveat".to_string()],
            blocking_risk_refs: vec!["risk:blocking".to_string()],
            risk_refs: vec!["risk:caveat".to_string()],
            summary: "phase 03 closure packet".to_string(),
        };
        assert_eq!(
            packet.validate().unwrap_err(),
            Phase03PacketError::RiskRefsDoNotMatchClassification
        );
    }

    #[test]
    fn phase03_closure_packet_rejects_overlapping_risk_classification() {
        let packet = Phase03ClosureReviewPacket {
            closure_review_packet_id: "phase03-closure-review".to_string(),
            factory_program_refs: vec!["phase03-program".to_string()],
            lineage_refs: vec!["lineage:dossier".to_string()],
            continuity_refs: vec!["continuity:a".to_string()],
            ecosystem_refs: vec!["health-ledger:a".to_string()],
            acceptable_caveat_refs: vec!["risk:shared".to_string()],
            blocking_risk_refs: vec!["risk:shared".to_string()],
            risk_refs: vec!["risk:shared".to_string()],
            summary: "phase 03 closure packet".to_string(),
        };
        assert_eq!(
            packet.validate().unwrap_err(),
            Phase03PacketError::OverlappingRiskClassificationRefs
        );
    }
}
