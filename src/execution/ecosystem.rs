use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::execution::factory_exchange::FactoryExchangePacketClass;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcosystemAdmissionDecision {
    Admitted,
    Constrained,
    Quarantined,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteDeliveryResult {
    Delivered,
    Paused,
    Quarantined,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossFactoryAdoptionResult {
    Adopted,
    Quarantined,
    RolledBack,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustProfile {
    pub trust_profile_id: String,
    pub factory_identity_ref: String,
    pub allowed_exchange_classes: Vec<FactoryExchangePacketClass>,
    pub adoption_scope: String,
    pub review_requirements: Vec<String>,
    pub revocation_policy_ref: String,
}

impl TrustProfile {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.trust_profile_id.trim().is_empty() {
            return Err(EcosystemError::MissingTrustProfileId);
        }
        if self.factory_identity_ref.trim().is_empty() {
            return Err(EcosystemError::MissingFactoryIdentityRef);
        }
        if self.allowed_exchange_classes.is_empty() {
            return Err(EcosystemError::MissingAllowedExchangeClasses);
        }
        if self.adoption_scope.trim().is_empty() {
            return Err(EcosystemError::MissingAdoptionScope);
        }
        validate_ref_list(
            &self.review_requirements,
            EcosystemError::MissingReviewRequirements,
        )?;
        if self.revocation_policy_ref.trim().is_empty() {
            return Err(EcosystemError::MissingRevocationPolicyRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemAdmissionRecord {
    pub admission_id: String,
    pub factory_identity_ref: String,
    pub trust_profile_ref: String,
    pub compatibility_profile_ref: String,
    pub decision: EcosystemAdmissionDecision,
    pub summary: String,
}

impl EcosystemAdmissionRecord {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.admission_id.trim().is_empty() {
            return Err(EcosystemError::MissingAdmissionId);
        }
        if self.factory_identity_ref.trim().is_empty() {
            return Err(EcosystemError::MissingFactoryIdentityRef);
        }
        if self.trust_profile_ref.trim().is_empty() {
            return Err(EcosystemError::MissingTrustProfileRef);
        }
        if self.compatibility_profile_ref.trim().is_empty() {
            return Err(EcosystemError::MissingCompatibilityProfileRef);
        }
        if self.summary.trim().is_empty() {
            return Err(EcosystemError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeRouteRecord {
    pub route_id: String,
    pub sender_factory_ref: String,
    pub receiver_factory_ref: String,
    pub packet_refs: Vec<String>,
    pub compatibility_refs: Vec<String>,
    pub delivery_result_ref: String,
}

impl ExchangeRouteRecord {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.route_id.trim().is_empty() {
            return Err(EcosystemError::MissingRouteId);
        }
        if self.sender_factory_ref.trim().is_empty() {
            return Err(EcosystemError::MissingSenderFactoryRef);
        }
        if self.receiver_factory_ref.trim().is_empty() {
            return Err(EcosystemError::MissingReceiverFactoryRef);
        }
        validate_ref_list(&self.packet_refs, EcosystemError::MissingPacketRefs)?;
        validate_ref_list(
            &self.compatibility_refs,
            EcosystemError::MissingCompatibilityRefs,
        )?;
        if self.delivery_result_ref.trim().is_empty() {
            return Err(EcosystemError::MissingDeliveryResultRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteCompatibilityCycle {
    pub compatibility_cycle_id: String,
    pub route_ref: String,
    pub profile_refs: Vec<String>,
    pub pressure_refs: Vec<String>,
    pub decision_ref: String,
}

impl RouteCompatibilityCycle {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.compatibility_cycle_id.trim().is_empty() {
            return Err(EcosystemError::MissingCompatibilityCycleId);
        }
        if self.route_ref.trim().is_empty() {
            return Err(EcosystemError::MissingRouteRef);
        }
        validate_ref_list(&self.profile_refs, EcosystemError::MissingProfileRefs)?;
        validate_ref_list(&self.pressure_refs, EcosystemError::MissingPressureRefs)?;
        if self.decision_ref.trim().is_empty() {
            return Err(EcosystemError::MissingDecisionRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossFactoryAdoptionDossier {
    pub adoption_dossier_id: String,
    pub receiver_factory_ref: String,
    pub route_ref: String,
    pub import_refs: Vec<String>,
    pub review_refs: Vec<String>,
    pub result: CrossFactoryAdoptionResult,
}

impl CrossFactoryAdoptionDossier {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.adoption_dossier_id.trim().is_empty() {
            return Err(EcosystemError::MissingAdoptionDossierId);
        }
        if self.receiver_factory_ref.trim().is_empty() {
            return Err(EcosystemError::MissingReceiverFactoryRef);
        }
        if self.route_ref.trim().is_empty() {
            return Err(EcosystemError::MissingRouteRef);
        }
        validate_ref_list(&self.import_refs, EcosystemError::MissingImportRefs)?;
        validate_ref_list(&self.review_refs, EcosystemError::MissingReviewRefs)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemRollbackChoreographyRecord {
    pub rollback_choreography_id: String,
    pub affected_factory_refs: Vec<String>,
    pub adoption_refs: Vec<String>,
    pub rollback_steps: Vec<String>,
    pub quarantine_refs: Vec<String>,
    pub completion_ref: String,
}

impl EcosystemRollbackChoreographyRecord {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.rollback_choreography_id.trim().is_empty() {
            return Err(EcosystemError::MissingRollbackChoreographyId);
        }
        validate_ref_list(
            &self.affected_factory_refs,
            EcosystemError::MissingAffectedFactoryRefs,
        )?;
        validate_ref_list(&self.adoption_refs, EcosystemError::MissingAdoptionRefs)?;
        validate_ref_list(&self.rollback_steps, EcosystemError::MissingRollbackSteps)?;
        validate_ref_list(&self.quarantine_refs, EcosystemError::MissingQuarantineRefs)?;
        if self.completion_ref.trim().is_empty() {
            return Err(EcosystemError::MissingCompletionRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemWorkspaceSnapshot {
    pub workspace_id: String,
    pub factory_refs: Vec<String>,
    pub trust_refs: Vec<String>,
    pub route_refs: Vec<String>,
    pub adoption_refs: Vec<String>,
    pub health_refs: Vec<String>,
}

impl EcosystemWorkspaceSnapshot {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.workspace_id.trim().is_empty() {
            return Err(EcosystemError::MissingWorkspaceId);
        }
        validate_ref_list(&self.factory_refs, EcosystemError::MissingFactoryRefs)?;
        validate_ref_list(&self.trust_refs, EcosystemError::MissingTrustRefs)?;
        validate_ref_list(&self.route_refs, EcosystemError::MissingRouteRefs)?;
        validate_ref_list(&self.adoption_refs, EcosystemError::MissingAdoptionRefs)?;
        validate_ref_list(&self.health_refs, EcosystemError::MissingHealthRefs)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemHealthSnapshot {
    pub ecosystem_snapshot_id: String,
    pub route_pressure_refs: Vec<String>,
    pub adoption_stability_refs: Vec<String>,
    pub quarantine_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub claim_boundary: String,
}

impl EcosystemHealthSnapshot {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.ecosystem_snapshot_id.trim().is_empty() {
            return Err(EcosystemError::MissingEcosystemSnapshotId);
        }
        validate_ref_list(
            &self.route_pressure_refs,
            EcosystemError::MissingRoutePressureRefs,
        )?;
        validate_ref_list(
            &self.adoption_stability_refs,
            EcosystemError::MissingAdoptionStabilityRefs,
        )?;
        validate_ref_list(&self.quarantine_refs, EcosystemError::MissingQuarantineRefs)?;
        validate_ref_list(&self.rollback_refs, EcosystemError::MissingRollbackRefs)?;
        if self.claim_boundary.trim().is_empty() {
            return Err(EcosystemError::MissingClaimBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemAdmissionProfile {
    pub admission_profile_id: String,
    pub factory_ref: String,
    pub identity_ref: String,
    pub compatibility_ref: String,
    pub rollback_obligation_ref: String,
    pub admission_status: EcosystemAdmissionDecision,
}

impl EcosystemAdmissionProfile {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.admission_profile_id.trim().is_empty() {
            return Err(EcosystemError::MissingAdmissionProfileId);
        }
        if self.factory_ref.trim().is_empty() {
            return Err(EcosystemError::MissingFactoryRef);
        }
        if self.identity_ref.trim().is_empty() {
            return Err(EcosystemError::MissingIdentityRef);
        }
        if self.compatibility_ref.trim().is_empty() {
            return Err(EcosystemError::MissingCompatibilityRef);
        }
        if self.rollback_obligation_ref.trim().is_empty() {
            return Err(EcosystemError::MissingRollbackObligationRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemExchangeRouteLedger {
    pub exchange_route_ledger_id: String,
    pub source_factory_ref: String,
    pub target_factory_ref: String,
    pub route_ref: String,
    pub admission_refs: Vec<String>,
    pub exchange_packet_refs: Vec<String>,
    pub route_history_refs: Vec<String>,
    pub continuity_window_refs: Vec<String>,
    pub adoption_refs: Vec<String>,
    pub quarantine_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
}

impl EcosystemExchangeRouteLedger {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.exchange_route_ledger_id.trim().is_empty() {
            return Err(EcosystemError::MissingExchangeRouteLedgerId);
        }
        if self.source_factory_ref.trim().is_empty() {
            return Err(EcosystemError::MissingSenderFactoryRef);
        }
        if self.target_factory_ref.trim().is_empty() {
            return Err(EcosystemError::MissingReceiverFactoryRef);
        }
        if self.route_ref.trim().is_empty() {
            return Err(EcosystemError::MissingRouteRef);
        }
        validate_ref_list(&self.admission_refs, EcosystemError::MissingAdmissionRefs)?;
        validate_ref_list(
            &self.exchange_packet_refs,
            EcosystemError::MissingPacketRefs,
        )?;
        validate_ref_list(
            &self.route_history_refs,
            EcosystemError::MissingRouteHistoryRefs,
        )?;
        validate_ref_list(
            &self.continuity_window_refs,
            EcosystemError::MissingContinuityWindowRefs,
        )?;
        validate_ref_list(&self.adoption_refs, EcosystemError::MissingAdoptionRefs)?;
        validate_ref_list(&self.quarantine_refs, EcosystemError::MissingQuarantineRefs)?;
        validate_ref_list(&self.rollback_refs, EcosystemError::MissingRollbackRefs)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemHealthLedger {
    pub ecosystem_health_id: String,
    pub admission_refs: Vec<String>,
    pub route_refs: Vec<String>,
    pub continuity_refs: Vec<String>,
    pub failure_refs: Vec<String>,
    pub recovery_refs: Vec<String>,
    pub rollback_symmetry_refs: Vec<String>,
    pub compatibility_persistence_refs: Vec<String>,
}

impl EcosystemHealthLedger {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.ecosystem_health_id.trim().is_empty() {
            return Err(EcosystemError::MissingEcosystemHealthLedgerId);
        }
        validate_ref_list(&self.admission_refs, EcosystemError::MissingAdmissionRefs)?;
        validate_ref_list(&self.route_refs, EcosystemError::MissingRouteRefs)?;
        validate_ref_list(&self.continuity_refs, EcosystemError::MissingContinuityRefs)?;
        validate_ref_list(&self.failure_refs, EcosystemError::MissingFailureRefs)?;
        validate_ref_list(&self.recovery_refs, EcosystemError::MissingRecoveryRefs)?;
        validate_ref_list(
            &self.rollback_symmetry_refs,
            EcosystemError::MissingRollbackSymmetryRefs,
        )?;
        validate_ref_list(
            &self.compatibility_persistence_refs,
            EcosystemError::MissingCompatibilityPersistenceRefs,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteExchangeHistoryRecord {
    pub route_history_id: String,
    pub route_ref: String,
    pub admission_ref: String,
    pub exchange_packet_ref: String,
    pub adoption_ref: String,
    pub quarantine_ref: String,
    pub rollback_ref: String,
    pub outcome_ref: String,
    pub continuity_ref: String,
}

impl RouteExchangeHistoryRecord {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.route_history_id.trim().is_empty() {
            return Err(EcosystemError::MissingRouteHistoryId);
        }
        if self.route_ref.trim().is_empty() {
            return Err(EcosystemError::MissingRouteRef);
        }
        if self.admission_ref.trim().is_empty() {
            return Err(EcosystemError::MissingAdmissionRef);
        }
        if self.exchange_packet_ref.trim().is_empty() {
            return Err(EcosystemError::MissingExchangePacketRef);
        }
        if self.adoption_ref.trim().is_empty() {
            return Err(EcosystemError::MissingAdoptionRef);
        }
        if self.quarantine_ref.trim().is_empty() {
            return Err(EcosystemError::MissingQuarantineRef);
        }
        if self.rollback_ref.trim().is_empty() {
            return Err(EcosystemError::MissingRollbackRef);
        }
        if self.outcome_ref.trim().is_empty() {
            return Err(EcosystemError::MissingOutcomeRef);
        }
        if self.continuity_ref.trim().is_empty() {
            return Err(EcosystemError::MissingContinuityRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemContinuityWindowRecord {
    pub continuity_window_id: String,
    pub health_ref: String,
    pub preceding_route_history_ref: String,
    pub succeeding_route_history_ref: String,
    pub carry_forward_refs: Vec<String>,
    pub degraded_state_refs: Vec<String>,
    pub resumed_state_refs: Vec<String>,
    pub summary: String,
}

impl EcosystemContinuityWindowRecord {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.continuity_window_id.trim().is_empty() {
            return Err(EcosystemError::MissingContinuityWindowId);
        }
        if self.health_ref.trim().is_empty() {
            return Err(EcosystemError::MissingHealthRef);
        }
        if self.preceding_route_history_ref.trim().is_empty() {
            return Err(EcosystemError::MissingPrecedingRouteHistoryRef);
        }
        if self.succeeding_route_history_ref.trim().is_empty() {
            return Err(EcosystemError::MissingSucceedingRouteHistoryRef);
        }
        validate_ref_list(
            &self.carry_forward_refs,
            EcosystemError::MissingCarryForwardRefs,
        )?;
        validate_ref_list(
            &self.degraded_state_refs,
            EcosystemError::MissingDegradedStateRefs,
        )?;
        validate_ref_list(
            &self.resumed_state_refs,
            EcosystemError::MissingResumedStateRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(EcosystemError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemRollbackSymmetryRecord {
    pub rollback_symmetry_id: String,
    pub route_ledger_ref: String,
    pub adoption_refs: Vec<String>,
    pub quarantine_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub recovery_refs: Vec<String>,
    pub summary: String,
}

impl EcosystemRollbackSymmetryRecord {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.rollback_symmetry_id.trim().is_empty() {
            return Err(EcosystemError::MissingRollbackSymmetryId);
        }
        if self.route_ledger_ref.trim().is_empty() {
            return Err(EcosystemError::MissingRouteLedgerRef);
        }
        validate_ref_list(&self.adoption_refs, EcosystemError::MissingAdoptionRefs)?;
        validate_ref_list(&self.quarantine_refs, EcosystemError::MissingQuarantineRefs)?;
        validate_ref_list(&self.rollback_refs, EcosystemError::MissingRollbackRefs)?;
        validate_ref_list(&self.recovery_refs, EcosystemError::MissingRecoveryRefs)?;
        if self.summary.trim().is_empty() {
            return Err(EcosystemError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemCompatibilityPersistenceRecord {
    pub compatibility_persistence_id: String,
    pub trust_profile_refs: Vec<String>,
    pub route_cycle_refs: Vec<String>,
    pub profile_refs: Vec<String>,
    pub persistence_refs: Vec<String>,
    pub variance_refs: Vec<String>,
    pub summary: String,
}

impl EcosystemCompatibilityPersistenceRecord {
    pub fn validate(&self) -> Result<(), EcosystemError> {
        if self.compatibility_persistence_id.trim().is_empty() {
            return Err(EcosystemError::MissingCompatibilityPersistenceId);
        }
        validate_ref_list(
            &self.trust_profile_refs,
            EcosystemError::MissingTrustProfileRefs,
        )?;
        validate_ref_list(
            &self.route_cycle_refs,
            EcosystemError::MissingRouteCycleRefs,
        )?;
        validate_ref_list(&self.profile_refs, EcosystemError::MissingProfileRefs)?;
        validate_ref_list(
            &self.persistence_refs,
            EcosystemError::MissingPersistenceRefs,
        )?;
        validate_ref_list(&self.variance_refs, EcosystemError::MissingVarianceRefs)?;
        if self.summary.trim().is_empty() {
            return Err(EcosystemError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcosystemError {
    MissingTrustProfileId,
    MissingFactoryIdentityRef,
    MissingAllowedExchangeClasses,
    MissingAdoptionScope,
    MissingReviewRequirements,
    MissingRevocationPolicyRef,
    MissingAdmissionId,
    MissingTrustProfileRef,
    MissingCompatibilityProfileRef,
    MissingSummary,
    MissingRouteId,
    MissingSenderFactoryRef,
    MissingReceiverFactoryRef,
    MissingPacketRefs,
    MissingCompatibilityRefs,
    MissingDeliveryResultRef,
    MissingCompatibilityCycleId,
    MissingRouteRef,
    MissingProfileRefs,
    MissingPressureRefs,
    MissingDecisionRef,
    MissingAdoptionDossierId,
    MissingImportRefs,
    MissingReviewRefs,
    MissingRollbackChoreographyId,
    MissingAffectedFactoryRefs,
    MissingAdoptionRefs,
    MissingRollbackSteps,
    MissingQuarantineRefs,
    MissingCompletionRef,
    MissingWorkspaceId,
    MissingFactoryRefs,
    MissingTrustRefs,
    MissingRouteRefs,
    MissingHealthRefs,
    MissingEcosystemSnapshotId,
    MissingRoutePressureRefs,
    MissingAdoptionStabilityRefs,
    MissingRollbackRefs,
    MissingClaimBoundary,
    MissingAdmissionRefs,
    MissingAdmissionProfileId,
    MissingFactoryRef,
    MissingIdentityRef,
    MissingCompatibilityRef,
    MissingRollbackObligationRef,
    MissingExchangeRouteLedgerId,
    MissingRouteHistoryId,
    MissingAdmissionRef,
    MissingExchangePacketRef,
    MissingAdoptionRef,
    MissingQuarantineRef,
    MissingRollbackRef,
    MissingOutcomeRef,
    MissingContinuityRef,
    MissingContinuityWindowId,
    MissingHealthRef,
    MissingPrecedingRouteHistoryRef,
    MissingSucceedingRouteHistoryRef,
    MissingCarryForwardRefs,
    MissingDegradedStateRefs,
    MissingResumedStateRefs,
    MissingRollbackSymmetryId,
    MissingRouteLedgerRef,
    MissingCompatibilityPersistenceId,
    MissingTrustProfileRefs,
    MissingRouteCycleRefs,
    MissingPersistenceRefs,
    MissingVarianceRefs,
    MissingRouteHistoryRefs,
    MissingContinuityWindowRefs,
    MissingContinuityRefs,
    MissingFailureRefs,
    MissingRecoveryRefs,
    MissingRollbackSymmetryRefs,
    MissingCompatibilityPersistenceRefs,
    MissingEcosystemHealthLedgerId,
}

impl Display for EcosystemError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for EcosystemError {}

fn validate_ref_list(refs: &[String], error: EcosystemError) -> Result<(), EcosystemError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase03_ecosystem_records_validate() {
        let profile = EcosystemAdmissionProfile {
            admission_profile_id: "phase03-admission-profile".to_string(),
            factory_ref: "factory:sender".to_string(),
            identity_ref: "identity:sender".to_string(),
            compatibility_ref: "compatibility:sender".to_string(),
            rollback_obligation_ref: "rollback:sender".to_string(),
            admission_status: EcosystemAdmissionDecision::Admitted,
        };
        profile.validate().unwrap();

        let route_ledger = EcosystemExchangeRouteLedger {
            exchange_route_ledger_id: "phase03-route-ledger".to_string(),
            source_factory_ref: "factory:sender".to_string(),
            target_factory_ref: "factory:receiver".to_string(),
            route_ref: "northstar-06-route-a".to_string(),
            admission_refs: vec!["admission-profile:a".to_string()],
            exchange_packet_refs: vec!["packet:a".to_string(), "packet:b".to_string()],
            route_history_refs: vec!["route-history:a".to_string(), "route-history:b".to_string()],
            continuity_window_refs: vec!["continuity-window:a".to_string()],
            adoption_refs: vec!["adoption:a".to_string()],
            quarantine_refs: vec!["quarantine:a".to_string()],
            rollback_refs: vec!["rollback:a".to_string()],
        };
        route_ledger.validate().unwrap();

        let health = EcosystemHealthLedger {
            ecosystem_health_id: "phase03-ecosystem-health".to_string(),
            admission_refs: vec![profile.admission_profile_id],
            route_refs: vec![route_ledger.exchange_route_ledger_id],
            continuity_refs: vec!["continuity:a".to_string()],
            failure_refs: vec!["failure:a".to_string()],
            recovery_refs: vec!["recovery:a".to_string()],
            rollback_symmetry_refs: vec!["rollback-symmetry:a".to_string()],
            compatibility_persistence_refs: vec!["compatibility-persistence:a".to_string()],
        };
        health.validate().unwrap();

        let route_history = RouteExchangeHistoryRecord {
            route_history_id: "route-history:a".to_string(),
            route_ref: "northstar-06-route-a".to_string(),
            admission_ref: "admission-profile:a".to_string(),
            exchange_packet_ref: "packet:a".to_string(),
            adoption_ref: "adoption:a".to_string(),
            quarantine_ref: "quarantine:a".to_string(),
            rollback_ref: "rollback:a".to_string(),
            outcome_ref: "outcome:a".to_string(),
            continuity_ref: "continuity-window:a".to_string(),
        };
        route_history.validate().unwrap();

        let continuity = EcosystemContinuityWindowRecord {
            continuity_window_id: "continuity-window:a".to_string(),
            health_ref: "phase03-ecosystem-health".to_string(),
            preceding_route_history_ref: "route-history:a".to_string(),
            succeeding_route_history_ref: "route-history:b".to_string(),
            carry_forward_refs: vec!["carry:a".to_string()],
            degraded_state_refs: vec!["degraded:a".to_string()],
            resumed_state_refs: vec!["resumed:a".to_string()],
            summary: "bounded ecosystem continuity".to_string(),
        };
        continuity.validate().unwrap();

        let rollback_symmetry = EcosystemRollbackSymmetryRecord {
            rollback_symmetry_id: "rollback-symmetry:a".to_string(),
            route_ledger_ref: "phase03-route-ledger".to_string(),
            adoption_refs: vec!["adoption:a".to_string()],
            quarantine_refs: vec!["quarantine:a".to_string()],
            rollback_refs: vec!["rollback:a".to_string()],
            recovery_refs: vec!["recovery:a".to_string()],
            summary: "rollback symmetry".to_string(),
        };
        rollback_symmetry.validate().unwrap();

        let compatibility = EcosystemCompatibilityPersistenceRecord {
            compatibility_persistence_id: "compatibility-persistence:a".to_string(),
            trust_profile_refs: vec!["trust:a".to_string()],
            route_cycle_refs: vec!["route-cycle:a".to_string()],
            profile_refs: vec!["compatibility:a".to_string()],
            persistence_refs: vec!["persistence:a".to_string()],
            variance_refs: vec!["variance:none".to_string()],
            summary: "compatibility persistence".to_string(),
        };
        compatibility.validate().unwrap();
    }
}
