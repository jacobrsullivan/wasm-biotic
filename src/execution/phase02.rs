use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceClosureWorkspacePacket {
    pub service_workspace_id: String,
    pub workflow_sufficiency_refs: Vec<String>,
    pub workflow_dossier_refs: Vec<String>,
    pub attestation_refs: Vec<String>,
    pub transitional_gap_refs: Vec<String>,
    pub operator_summary_ref: String,
}

impl ServiceClosureWorkspacePacket {
    pub fn validate(&self) -> Result<(), Phase02PacketError> {
        if self.service_workspace_id.trim().is_empty() {
            return Err(Phase02PacketError::MissingWorkspaceId);
        }
        validate_ref_list(
            &self.workflow_sufficiency_refs,
            Phase02PacketError::MissingWorkflowSufficiencyRefs,
        )?;
        validate_ref_list(
            &self.workflow_dossier_refs,
            Phase02PacketError::MissingWorkflowDossierRefs,
        )?;
        validate_ref_list(
            &self.attestation_refs,
            Phase02PacketError::MissingAttestationRefs,
        )?;
        if self.operator_summary_ref.trim().is_empty() {
            return Err(Phase02PacketError::MissingOperatorSummaryRef);
        }
        if self
            .transitional_gap_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(Phase02PacketError::InvalidTransitionalGapRefs);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcologyClosureWorkspacePacket {
    pub ecology_workspace_id: String,
    pub worker_card_refs: Vec<String>,
    pub ecology_ledger_refs: Vec<String>,
    pub routing_packet_refs: Vec<String>,
    pub degradation_refs: Vec<String>,
    pub operator_summary_ref: String,
}

impl EcologyClosureWorkspacePacket {
    pub fn validate(&self) -> Result<(), Phase02PacketError> {
        if self.ecology_workspace_id.trim().is_empty() {
            return Err(Phase02PacketError::MissingWorkspaceId);
        }
        validate_ref_list(
            &self.worker_card_refs,
            Phase02PacketError::MissingWorkerCardRefs,
        )?;
        validate_ref_list(
            &self.ecology_ledger_refs,
            Phase02PacketError::MissingEcologyLedgerRefs,
        )?;
        validate_ref_list(
            &self.routing_packet_refs,
            Phase02PacketError::MissingRoutingPacketRefs,
        )?;
        validate_ref_list(
            &self.degradation_refs,
            Phase02PacketError::MissingDegradationRefs,
        )?;
        if self.operator_summary_ref.trim().is_empty() {
            return Err(Phase02PacketError::MissingOperatorSummaryRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase02AcceptancePacket {
    pub acceptance_packet_id: String,
    pub workflow_refs: Vec<String>,
    pub closure_refs: Vec<String>,
    pub ecology_refs: Vec<String>,
    pub attestation_refs: Vec<String>,
    pub summary: String,
}

impl Phase02AcceptancePacket {
    pub fn validate(&self) -> Result<(), Phase02PacketError> {
        if self.acceptance_packet_id.trim().is_empty() {
            return Err(Phase02PacketError::MissingAcceptancePacketId);
        }
        validate_ref_list(&self.workflow_refs, Phase02PacketError::MissingWorkflowRefs)?;
        validate_ref_list(&self.closure_refs, Phase02PacketError::MissingClosureRefs)?;
        validate_ref_list(&self.ecology_refs, Phase02PacketError::MissingEcologyRefs)?;
        validate_ref_list(
            &self.attestation_refs,
            Phase02PacketError::MissingAttestationRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(Phase02PacketError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase02PacketError {
    MissingWorkspaceId,
    MissingWorkflowSufficiencyRefs,
    MissingWorkflowDossierRefs,
    MissingAttestationRefs,
    MissingOperatorSummaryRef,
    InvalidTransitionalGapRefs,
    MissingWorkerCardRefs,
    MissingEcologyLedgerRefs,
    MissingRoutingPacketRefs,
    MissingDegradationRefs,
    MissingAcceptancePacketId,
    MissingWorkflowRefs,
    MissingClosureRefs,
    MissingEcologyRefs,
    MissingSummary,
}

impl Display for Phase02PacketError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for Phase02PacketError {}

fn validate_ref_list(refs: &[String], error: Phase02PacketError) -> Result<(), Phase02PacketError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}
