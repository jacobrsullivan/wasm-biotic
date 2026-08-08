use crate::execution::recursive_factory_interface::WorkerAgentProductionMode;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerRoleKind {
    Planner,
    Builder,
    Validator,
    Reviewer,
    Packager,
    ContinuityWorker,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerSpecializationCard {
    pub worker_card_id: String,
    pub role_kind: WorkerRoleKind,
    pub world_refs: Vec<String>,
    pub capability_ref: String,
    pub service_dependency_refs: Vec<String>,
    pub preferred_work_refs: Vec<String>,
    pub ownership_scope: String,
    pub responsibility_boundary: String,
    pub routing_requirements: Vec<String>,
    pub failure_budget_ref: String,
    #[serde(default)]
    pub production_mode: Option<WorkerAgentProductionMode>,
    #[serde(default)]
    pub production_program_instance_ref: Option<String>,
    #[serde(default)]
    pub production_turn_package_ref: Option<String>,
    #[serde(default)]
    pub production_parsed_turn_result_ref: Option<String>,
    #[serde(default)]
    pub production_cycle_ref: Option<String>,
    #[serde(default)]
    pub lineage_ref: Option<String>,
    #[serde(default)]
    pub production_summary: Option<String>,
}

impl WorkerSpecializationCard {
    pub fn validate(&self) -> Result<(), WorkerEcologyError> {
        if self.worker_card_id.trim().is_empty() {
            return Err(WorkerEcologyError::MissingWorkerCardId);
        }
        validate_ref_list(&self.world_refs, WorkerEcologyError::MissingWorldRefs)?;
        if self.capability_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingCapabilityRef);
        }
        validate_ref_list(
            &self.service_dependency_refs,
            WorkerEcologyError::MissingServiceDependencyRefs,
        )?;
        validate_ref_list(
            &self.preferred_work_refs,
            WorkerEcologyError::MissingPreferredWorkRefs,
        )?;
        if self.ownership_scope.trim().is_empty() {
            return Err(WorkerEcologyError::MissingOwnershipScope);
        }
        if self.responsibility_boundary.trim().is_empty() {
            return Err(WorkerEcologyError::MissingResponsibilityBoundary);
        }
        validate_ref_list(
            &self.routing_requirements,
            WorkerEcologyError::MissingRoutingRequirements,
        )?;
        if self.failure_budget_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingFailureBudgetRef);
        }
        for value in [
            self.production_program_instance_ref.as_ref(),
            self.production_turn_package_ref.as_ref(),
            self.production_parsed_turn_result_ref.as_ref(),
            self.production_cycle_ref.as_ref(),
            self.lineage_ref.as_ref(),
            self.production_summary.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.trim().is_empty() {
                return Err(WorkerEcologyError::MissingProducedAgentMetadata);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcologySnapshot {
    pub ecology_snapshot_id: String,
    pub worker_card_refs: Vec<String>,
    pub capability_mix_refs: Vec<String>,
    pub lease_refs: Vec<String>,
    pub performance_refs: Vec<String>,
    pub drift_refs: Vec<String>,
    pub summary: String,
}

impl EcologySnapshot {
    pub fn validate(&self) -> Result<(), WorkerEcologyError> {
        if self.ecology_snapshot_id.trim().is_empty() {
            return Err(WorkerEcologyError::MissingEcologySnapshotId);
        }
        validate_ref_list(
            &self.worker_card_refs,
            WorkerEcologyError::MissingWorkerCardRefs,
        )?;
        validate_ref_list(
            &self.capability_mix_refs,
            WorkerEcologyError::MissingCapabilityMixRefs,
        )?;
        validate_ref_list(&self.lease_refs, WorkerEcologyError::MissingLeaseRefs)?;
        validate_ref_list(
            &self.performance_refs,
            WorkerEcologyError::MissingPerformanceRefs,
        )?;
        validate_ref_list(&self.drift_refs, WorkerEcologyError::MissingDriftRefs)?;
        if self.summary.trim().is_empty() {
            return Err(WorkerEcologyError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinatorPlanningRecord {
    pub planning_id: String,
    pub campaign_ref: String,
    pub agenda_refs: Vec<String>,
    pub routing_refs: Vec<String>,
    pub synthesis_target_ref: String,
    pub summary: String,
}

impl CoordinatorPlanningRecord {
    pub fn validate(&self) -> Result<(), WorkerEcologyError> {
        if self.planning_id.trim().is_empty() {
            return Err(WorkerEcologyError::MissingPlanningId);
        }
        if self.campaign_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingCampaignRef);
        }
        validate_ref_list(&self.agenda_refs, WorkerEcologyError::MissingAgendaRefs)?;
        validate_ref_list(&self.routing_refs, WorkerEcologyError::MissingRoutingRefs)?;
        if self.synthesis_target_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingSynthesisTargetRef);
        }
        if self.summary.trim().is_empty() {
            return Err(WorkerEcologyError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkLease {
    pub work_lease_id: String,
    pub campaign_ref: String,
    pub task_ref: String,
    pub worker_card_ref: String,
    pub lease_budget_ref: String,
    pub output_requirements: Vec<String>,
    pub handoff_refs: Vec<String>,
}

impl WorkLease {
    pub fn validate(&self) -> Result<(), WorkerEcologyError> {
        if self.work_lease_id.trim().is_empty() {
            return Err(WorkerEcologyError::MissingWorkLeaseId);
        }
        if self.campaign_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingCampaignRef);
        }
        if self.task_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingTaskRef);
        }
        if self.worker_card_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingWorkerCardRef);
        }
        if self.lease_budget_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingLeaseBudgetRef);
        }
        validate_ref_list(
            &self.output_requirements,
            WorkerEcologyError::MissingOutputRequirements,
        )?;
        validate_ref_list(&self.handoff_refs, WorkerEcologyError::MissingHandoffRefs)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisDossier {
    pub synthesis_id: String,
    pub input_refs: Vec<String>,
    pub conflict_refs: Vec<String>,
    pub coordinator_ref: String,
    pub decision_ref: String,
    pub summary: String,
}

impl SynthesisDossier {
    pub fn validate(&self) -> Result<(), WorkerEcologyError> {
        if self.synthesis_id.trim().is_empty() {
            return Err(WorkerEcologyError::MissingSynthesisId);
        }
        validate_ref_list(&self.input_refs, WorkerEcologyError::MissingInputRefs)?;
        if self.coordinator_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingCoordinatorRef);
        }
        if self.decision_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingDecisionRef);
        }
        if self.summary.trim().is_empty() {
            return Err(WorkerEcologyError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcologyHealthRecord {
    pub health_record_id: String,
    pub ecology_snapshot_ref: String,
    pub lease_failure_refs: Vec<String>,
    pub bottleneck_refs: Vec<String>,
    pub drift_refs: Vec<String>,
    pub load_refs: Vec<String>,
    pub fairness_refs: Vec<String>,
    pub degradation_refs: Vec<String>,
    pub recovery_refs: Vec<String>,
    pub recommendation_ref: String,
}

impl EcologyHealthRecord {
    pub fn validate(&self) -> Result<(), WorkerEcologyError> {
        if self.health_record_id.trim().is_empty() {
            return Err(WorkerEcologyError::MissingHealthRecordId);
        }
        if self.ecology_snapshot_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingEcologySnapshotRef);
        }
        validate_ref_list(
            &self.lease_failure_refs,
            WorkerEcologyError::MissingLeaseFailureRefs,
        )?;
        validate_ref_list(
            &self.bottleneck_refs,
            WorkerEcologyError::MissingBottleneckRefs,
        )?;
        validate_ref_list(&self.drift_refs, WorkerEcologyError::MissingDriftRefs)?;
        validate_ref_list(&self.load_refs, WorkerEcologyError::MissingLoadRefs)?;
        validate_ref_list(&self.fairness_refs, WorkerEcologyError::MissingFairnessRefs)?;
        validate_ref_list(
            &self.degradation_refs,
            WorkerEcologyError::MissingDegradationRefs,
        )?;
        validate_ref_list(&self.recovery_refs, WorkerEcologyError::MissingRecoveryRefs)?;
        if self.recommendation_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingRecommendationRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingPacketRecord {
    pub routing_packet_id: String,
    pub agenda_ref: String,
    pub worker_selection_refs: Vec<String>,
    pub synthesis_ref: String,
    pub quality_ref: String,
    pub fallback_ref: String,
    pub summary: String,
}

impl RoutingPacketRecord {
    pub fn validate(&self) -> Result<(), WorkerEcologyError> {
        if self.routing_packet_id.trim().is_empty() {
            return Err(WorkerEcologyError::MissingRoutingPacketId);
        }
        if self.agenda_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingAgendaRef);
        }
        validate_ref_list(
            &self.worker_selection_refs,
            WorkerEcologyError::MissingWorkerSelectionRefs,
        )?;
        if self.synthesis_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingSynthesisRef);
        }
        if self.quality_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingQualityRef);
        }
        if self.fallback_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingFallbackRef);
        }
        if self.summary.trim().is_empty() {
            return Err(WorkerEcologyError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcologyRecoveryRecord {
    pub recovery_id: String,
    pub ecology_snapshot_ref: String,
    pub trigger_refs: Vec<String>,
    pub reroute_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub outcome_ref: String,
    pub summary: String,
}

impl EcologyRecoveryRecord {
    pub fn validate(&self) -> Result<(), WorkerEcologyError> {
        if self.recovery_id.trim().is_empty() {
            return Err(WorkerEcologyError::MissingRecoveryId);
        }
        if self.ecology_snapshot_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingEcologySnapshotRef);
        }
        validate_ref_list(&self.trigger_refs, WorkerEcologyError::MissingTriggerRefs)?;
        validate_ref_list(&self.reroute_refs, WorkerEcologyError::MissingRerouteRefs)?;
        validate_ref_list(&self.rollback_refs, WorkerEcologyError::MissingRollbackRefs)?;
        if self.outcome_ref.trim().is_empty() {
            return Err(WorkerEcologyError::MissingOutcomeRef);
        }
        if self.summary.trim().is_empty() {
            return Err(WorkerEcologyError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerEcologyError {
    MissingWorkerCardId,
    MissingWorldRefs,
    MissingCapabilityRef,
    MissingServiceDependencyRefs,
    MissingPreferredWorkRefs,
    MissingOwnershipScope,
    MissingResponsibilityBoundary,
    MissingRoutingRequirements,
    MissingFailureBudgetRef,
    MissingProducedAgentMetadata,
    MissingEcologySnapshotId,
    MissingWorkerCardRefs,
    MissingCapabilityMixRefs,
    MissingLeaseRefs,
    MissingPerformanceRefs,
    MissingSummary,
    MissingPlanningId,
    MissingCampaignRef,
    MissingAgendaRefs,
    MissingRoutingRefs,
    MissingSynthesisTargetRef,
    MissingWorkLeaseId,
    MissingTaskRef,
    MissingWorkerCardRef,
    MissingLeaseBudgetRef,
    MissingOutputRequirements,
    MissingHandoffRefs,
    MissingSynthesisId,
    MissingInputRefs,
    MissingCoordinatorRef,
    MissingDecisionRef,
    MissingHealthRecordId,
    MissingEcologySnapshotRef,
    MissingLeaseFailureRefs,
    MissingBottleneckRefs,
    MissingDriftRefs,
    MissingLoadRefs,
    MissingFairnessRefs,
    MissingDegradationRefs,
    MissingRecoveryRefs,
    MissingRecommendationRef,
    MissingRoutingPacketId,
    MissingAgendaRef,
    MissingWorkerSelectionRefs,
    MissingSynthesisRef,
    MissingQualityRef,
    MissingFallbackRef,
    MissingRecoveryId,
    MissingTriggerRefs,
    MissingRerouteRefs,
    MissingRollbackRefs,
    MissingOutcomeRef,
}

impl Display for WorkerEcologyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for WorkerEcologyError {}

fn validate_ref_list(refs: &[String], error: WorkerEcologyError) -> Result<(), WorkerEcologyError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CoordinatorPlanningRecord, EcologyHealthRecord, EcologyRecoveryRecord, EcologySnapshot,
        RoutingPacketRecord, SynthesisDossier, WorkLease, WorkerRoleKind, WorkerSpecializationCard,
    };

    #[test]
    fn ecology_records_validate() {
        let planner = WorkerSpecializationCard {
            worker_card_id: "worker-planner".to_string(),
            role_kind: WorkerRoleKind::Planner,
            world_refs: vec!["world:planner".to_string()],
            capability_ref: "capability:planning".to_string(),
            service_dependency_refs: vec!["service:scheduling".to_string()],
            preferred_work_refs: vec!["workflow:planning".to_string()],
            ownership_scope: "scope:campaign".to_string(),
            responsibility_boundary: "planner owns agenda assembly".to_string(),
            routing_requirements: vec!["route:planner-eligible".to_string()],
            failure_budget_ref: "failure-budget:planner".to_string(),
            production_mode: None,
            production_program_instance_ref: None,
            production_turn_package_ref: None,
            production_parsed_turn_result_ref: None,
            production_cycle_ref: None,
            lineage_ref: None,
            production_summary: None,
        };
        planner.validate().unwrap();

        let lease = WorkLease {
            work_lease_id: "lease-build".to_string(),
            campaign_ref: "campaign:phase-c".to_string(),
            task_ref: "task:build".to_string(),
            worker_card_ref: planner.worker_card_id.clone(),
            lease_budget_ref: "budget:build".to_string(),
            output_requirements: vec!["deliverable:plan".to_string()],
            handoff_refs: vec!["handoff:planner-builder".to_string()],
        };
        lease.validate().unwrap();

        let snapshot = EcologySnapshot {
            ecology_snapshot_id: "snapshot-1".to_string(),
            worker_card_refs: vec![planner.worker_card_id.clone()],
            capability_mix_refs: vec!["capability:planning".to_string()],
            lease_refs: vec![lease.work_lease_id.clone()],
            performance_refs: vec!["performance:stable".to_string()],
            drift_refs: vec!["drift:none".to_string()],
            summary: "ecology stayed explicit".to_string(),
        };
        snapshot.validate().unwrap();

        let planning = CoordinatorPlanningRecord {
            planning_id: "planning-1".to_string(),
            campaign_ref: "campaign:phase-c".to_string(),
            agenda_refs: vec!["agenda:1".to_string()],
            routing_refs: vec!["routing:1".to_string()],
            synthesis_target_ref: "synthesis-target:1".to_string(),
            summary: "planning closed".to_string(),
        };
        planning.validate().unwrap();

        let synthesis = SynthesisDossier {
            synthesis_id: "synthesis-1".to_string(),
            input_refs: vec![lease.work_lease_id.clone()],
            conflict_refs: vec!["conflict:none".to_string()],
            coordinator_ref: planning.planning_id.clone(),
            decision_ref: "decision:synthesis".to_string(),
            summary: "synthesis closed".to_string(),
        };
        synthesis.validate().unwrap();

        let health = EcologyHealthRecord {
            health_record_id: "health-1".to_string(),
            ecology_snapshot_ref: snapshot.ecology_snapshot_id.clone(),
            lease_failure_refs: vec!["lease-failure:none".to_string()],
            bottleneck_refs: vec!["bottleneck:review".to_string()],
            drift_refs: vec!["drift:none".to_string()],
            load_refs: vec!["load:balanced".to_string()],
            fairness_refs: vec!["fairness:balanced".to_string()],
            degradation_refs: vec!["degradation:none".to_string()],
            recovery_refs: vec!["recovery:available".to_string()],
            recommendation_ref: "recommendation:continue".to_string(),
        };
        health.validate().unwrap();

        let routing = RoutingPacketRecord {
            routing_packet_id: "routing-1".to_string(),
            agenda_ref: "agenda:1".to_string(),
            worker_selection_refs: vec![planner.worker_card_id],
            synthesis_ref: synthesis.synthesis_id.clone(),
            quality_ref: "quality:accepted".to_string(),
            fallback_ref: "fallback:reviewer".to_string(),
            summary: "routing remained explicit".to_string(),
        };
        routing.validate().unwrap();

        let recovery = EcologyRecoveryRecord {
            recovery_id: "recovery-1".to_string(),
            ecology_snapshot_ref: snapshot.ecology_snapshot_id,
            trigger_refs: vec!["trigger:degradation".to_string()],
            reroute_refs: vec!["reroute:validator-reviewer".to_string()],
            rollback_refs: vec!["rollback:phase-c".to_string()],
            outcome_ref: "outcome:stable".to_string(),
            summary: "recovery remained explicit".to_string(),
        };
        recovery.validate().unwrap();
    }
}
