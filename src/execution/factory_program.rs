use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactoryProgramState {
    Preparing,
    Producing,
    Proving,
    Observing,
    Paused,
    Stopped,
    Completed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionWindowResult {
    Adopted,
    Refused,
    RolledBack,
    Paused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopConditionDecision {
    Continue,
    Constrain,
    Pause,
    Stop,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryImprovementProgram {
    pub improvement_program_id: String,
    pub root_factory_ref: String,
    pub goal_refs: Vec<String>,
    pub recursion_budget_ref: String,
    pub program_state: FactoryProgramState,
    pub lineage_refs: Vec<String>,
}

impl FactoryImprovementProgram {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.improvement_program_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingImprovementProgramId);
        }
        if self.root_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingRootFactoryRef);
        }
        validate_ref_list(&self.goal_refs, FactoryProgramError::MissingGoalRefs)?;
        if self.recursion_budget_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingRecursionBudgetRef);
        }
        validate_ref_list(&self.lineage_refs, FactoryProgramError::MissingLineageRefs)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursionBudgetRecord {
    pub recursion_budget_id: String,
    pub max_depth: usize,
    pub max_campaigns: usize,
    pub risk_threshold_refs: Vec<String>,
    pub exhaustion_policy: String,
}

impl RecursionBudgetRecord {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.recursion_budget_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingRecursionBudgetId);
        }
        if self.max_depth == 0 {
            return Err(FactoryProgramError::InvalidMaxDepth);
        }
        if self.max_campaigns == 0 {
            return Err(FactoryProgramError::InvalidMaxCampaigns);
        }
        validate_ref_list(
            &self.risk_threshold_refs,
            FactoryProgramError::MissingRiskThresholdRefs,
        )?;
        if self.exhaustion_policy.trim().is_empty() {
            return Err(FactoryProgramError::MissingExhaustionPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaterFactoryGenerationAgenda {
    pub generation_agenda_id: String,
    pub parent_factory_ref: String,
    pub candidate_factory_ref: String,
    pub proving_refs: Vec<String>,
    pub observation_refs: Vec<String>,
    pub decision_refs: Vec<String>,
}

impl LaterFactoryGenerationAgenda {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.generation_agenda_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingGenerationAgendaId);
        }
        if self.parent_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingParentFactoryRef);
        }
        if self.candidate_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingCandidateFactoryRef);
        }
        validate_ref_list(&self.proving_refs, FactoryProgramError::MissingProvingRefs)?;
        validate_ref_list(
            &self.observation_refs,
            FactoryProgramError::MissingObservationRefs,
        )?;
        validate_ref_list(
            &self.decision_refs,
            FactoryProgramError::MissingDecisionRefs,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdoptionWindowRecord {
    pub adoption_window_id: String,
    pub candidate_factory_ref: String,
    pub observation_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub result: AdoptionWindowResult,
}

impl AdoptionWindowRecord {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.adoption_window_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingAdoptionWindowId);
        }
        if self.candidate_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingCandidateFactoryRef);
        }
        validate_ref_list(
            &self.observation_refs,
            FactoryProgramError::MissingObservationRefs,
        )?;
        validate_ref_list(
            &self.rollback_refs,
            FactoryProgramError::MissingRollbackRefs,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageHealthDossier {
    pub lineage_health_id: String,
    pub lineage_refs: Vec<String>,
    pub comparison_refs: Vec<String>,
    pub risk_refs: Vec<String>,
    pub trend_refs: Vec<String>,
    pub recommendation_ref: String,
}

impl LineageHealthDossier {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.lineage_health_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingLineageHealthId);
        }
        validate_ref_list(&self.lineage_refs, FactoryProgramError::MissingLineageRefs)?;
        validate_ref_list(
            &self.comparison_refs,
            FactoryProgramError::MissingComparisonRefs,
        )?;
        validate_ref_list(&self.risk_refs, FactoryProgramError::MissingRiskRefs)?;
        validate_ref_list(&self.trend_refs, FactoryProgramError::MissingTrendRefs)?;
        if self.recommendation_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingRecommendationRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopConditionRecord {
    pub stop_condition_id: String,
    pub program_ref: String,
    pub trigger_refs: Vec<String>,
    pub decision: StopConditionDecision,
    pub operator_guidance: String,
}

impl StopConditionRecord {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.stop_condition_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingStopConditionId);
        }
        if self.program_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingProgramRef);
        }
        validate_ref_list(&self.trigger_refs, FactoryProgramError::MissingTriggerRefs)?;
        if self.operator_guidance.trim().is_empty() {
            return Err(FactoryProgramError::MissingOperatorGuidance);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryProgramSpec {
    pub spec_id: String,
    pub title: String,
    pub root_factory_ref: String,
    pub stable_interface_ref: String,
    pub goal_refs: Vec<String>,
    pub workload_refs: Vec<String>,
    pub utility_metric_refs: Vec<String>,
    pub mutation_scope_refs: Vec<String>,
    pub promotion_gate_refs: Vec<String>,
    pub rollback_gate_refs: Vec<String>,
    pub recursion_budget: RecursionBudgetRecord,
    pub policy_ref: String,
    #[serde(default)]
    pub llm_driver_profile_ref: Option<String>,
}

impl FactoryProgramSpec {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.spec_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingFactoryProgramSpecId);
        }
        if self.title.trim().is_empty() {
            return Err(FactoryProgramError::MissingFactoryProgramTitle);
        }
        if self.root_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingRootFactoryRef);
        }
        if self.stable_interface_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingStableInterfaceRef);
        }
        validate_ref_list(&self.goal_refs, FactoryProgramError::MissingGoalRefs)?;
        validate_ref_list(
            &self.workload_refs,
            FactoryProgramError::MissingWorkloadRefs,
        )?;
        validate_ref_list(
            &self.utility_metric_refs,
            FactoryProgramError::MissingUtilityMetricRefs,
        )?;
        validate_ref_list(
            &self.mutation_scope_refs,
            FactoryProgramError::MissingMutationScopeRefs,
        )?;
        validate_ref_list(
            &self.promotion_gate_refs,
            FactoryProgramError::MissingPromotionGateRefs,
        )?;
        validate_ref_list(
            &self.rollback_gate_refs,
            FactoryProgramError::MissingRollbackGateRefs,
        )?;
        self.recursion_budget.validate()?;
        if self.policy_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingPolicyRef);
        }
        if self
            .llm_driver_profile_ref
            .as_ref()
            .is_some_and(|reference| reference.trim().is_empty())
        {
            return Err(FactoryProgramError::MissingLlmDriverProfileRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryProgramInstance {
    pub instance_id: String,
    pub spec_id: String,
    pub recurring_program_ref: String,
    pub current_factory_ref: String,
    pub program_state: FactoryProgramState,
    pub generation_depth: usize,
    pub campaign_count: usize,
    pub cycle_refs: Vec<String>,
    pub continuity_window_refs: Vec<String>,
    pub adopted_factory_refs: Vec<String>,
    pub restart_resume_refs: Vec<String>,
    pub latest_tick_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl FactoryProgramInstance {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.instance_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingFactoryProgramInstanceId);
        }
        if self.spec_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingFactoryProgramSpecId);
        }
        if self.recurring_program_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingRecurringFactoryProgramId);
        }
        if self.current_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingIncumbentFactoryRef);
        }
        if self.created_at.trim().is_empty() || self.updated_at.trim().is_empty() {
            return Err(FactoryProgramError::MissingTimestamp);
        }
        validate_ref_list(
            &self.adopted_factory_refs,
            FactoryProgramError::MissingLineageRefs,
        )?;
        if self
            .cycle_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(FactoryProgramError::MissingCycleRefs);
        }
        if self
            .continuity_window_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(FactoryProgramError::MissingContinuityWindowRefs);
        }
        if self
            .restart_resume_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(FactoryProgramError::MissingRestartResumeRefs);
        }
        if self
            .latest_tick_id
            .as_ref()
            .is_some_and(|reference| reference.trim().is_empty())
        {
            return Err(FactoryProgramError::MissingFactoryProgramTickId);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryProgramTickRequest {
    pub candidate_factory_ref: String,
    pub proving_refs: Vec<String>,
    pub observation_refs: Vec<String>,
    pub comparison_refs: Vec<String>,
    pub risk_refs: Vec<String>,
    pub trend_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub adoption_result: AdoptionWindowResult,
    pub operator_note: Option<String>,
}

impl FactoryProgramTickRequest {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.candidate_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingCandidateFactoryRef);
        }
        validate_ref_list(&self.proving_refs, FactoryProgramError::MissingProvingRefs)?;
        validate_ref_list(
            &self.observation_refs,
            FactoryProgramError::MissingObservationRefs,
        )?;
        validate_ref_list(
            &self.comparison_refs,
            FactoryProgramError::MissingComparisonRefs,
        )?;
        validate_ref_list(&self.risk_refs, FactoryProgramError::MissingRiskRefs)?;
        validate_ref_list(&self.trend_refs, FactoryProgramError::MissingTrendRefs)?;
        validate_ref_list(
            &self.rollback_refs,
            FactoryProgramError::MissingRollbackRefs,
        )?;
        if self
            .operator_note
            .as_ref()
            .is_some_and(|note| note.trim().is_empty())
        {
            return Err(FactoryProgramError::MissingOperatorGuidance);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryProgramTickReceipt {
    pub tick_id: String,
    pub instance_id: String,
    pub parent_factory_ref: String,
    pub candidate_factory_ref: String,
    pub resulting_factory_ref: String,
    pub generation_depth: usize,
    pub campaign_count: usize,
    pub created_at: String,
    pub recurring_program: RecurringFactoryProgramRecord,
    pub generation_agenda: LaterFactoryGenerationAgenda,
    pub adoption_window: AdoptionWindowRecord,
    pub continuity_window: ProgramContinuityWindowRecord,
    pub budget_history: ProgramBudgetHistoryRecord,
    pub policy_compliance: ProgramPolicyComplianceRecord,
    pub cycle_dossier: LaterFactoryCycleDossier,
    pub lineage_health: LineageHealthDossier,
    pub stop_condition: StopConditionRecord,
    pub operator_note: Option<String>,
}

impl FactoryProgramTickReceipt {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.tick_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingFactoryProgramTickId);
        }
        if self.instance_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingFactoryProgramInstanceId);
        }
        if self.parent_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingParentFactoryRef);
        }
        if self.candidate_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingCandidateFactoryRef);
        }
        if self.resulting_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingResultingFactoryRef);
        }
        if self.created_at.trim().is_empty() {
            return Err(FactoryProgramError::MissingTimestamp);
        }
        self.recurring_program.validate()?;
        self.generation_agenda.validate()?;
        self.adoption_window.validate()?;
        self.continuity_window.validate()?;
        self.budget_history.validate()?;
        self.policy_compliance.validate()?;
        self.cycle_dossier.validate()?;
        self.lineage_health.validate()?;
        self.stop_condition.validate()?;
        if self
            .operator_note
            .as_ref()
            .is_some_and(|note| note.trim().is_empty())
        {
            return Err(FactoryProgramError::MissingOperatorGuidance);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecurringFactoryProgramRecord {
    pub factory_program_id: String,
    pub bounded_program_refs: Vec<String>,
    pub incumbent_factory_ref: String,
    pub cycle_refs: Vec<String>,
    pub continuity_window_refs: Vec<String>,
    pub budget_ref: String,
    pub budget_history_ref: String,
    pub policy_ref: String,
    pub policy_compliance_ref: String,
    pub restart_resume_refs: Vec<String>,
    pub summary_ref: String,
}

impl RecurringFactoryProgramRecord {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.factory_program_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingRecurringFactoryProgramId);
        }
        validate_ref_list(
            &self.bounded_program_refs,
            FactoryProgramError::MissingBoundedProgramRefs,
        )?;
        if self.incumbent_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingIncumbentFactoryRef);
        }
        validate_ref_list(&self.cycle_refs, FactoryProgramError::MissingCycleRefs)?;
        validate_ref_list(
            &self.continuity_window_refs,
            FactoryProgramError::MissingContinuityWindowRefs,
        )?;
        if self.budget_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingBudgetRef);
        }
        if self.budget_history_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingBudgetHistoryRef);
        }
        if self.policy_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingPolicyRef);
        }
        if self.policy_compliance_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingPolicyComplianceRef);
        }
        validate_ref_list(
            &self.restart_resume_refs,
            FactoryProgramError::MissingRestartResumeRefs,
        )?;
        if self.summary_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingSummaryRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramContinuityWindowRecord {
    pub continuity_window_id: String,
    pub program_ref: String,
    pub preceding_ref: String,
    pub succeeding_ref: String,
    pub carry_forward_refs: Vec<String>,
    pub restart_resume_refs: Vec<String>,
    pub summary: String,
}

impl ProgramContinuityWindowRecord {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.continuity_window_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingContinuityWindowId);
        }
        if self.program_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingProgramRef);
        }
        if self.preceding_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingPrecedingRef);
        }
        if self.succeeding_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingSucceedingRef);
        }
        validate_ref_list(
            &self.carry_forward_refs,
            FactoryProgramError::MissingCarryForwardRefs,
        )?;
        validate_ref_list(
            &self.restart_resume_refs,
            FactoryProgramError::MissingRestartResumeRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryProgramError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramBudgetHistoryRecord {
    pub budget_history_id: String,
    pub program_ref: String,
    pub budget_ref: String,
    pub cycle_refs: Vec<String>,
    pub consumption_refs: Vec<String>,
    pub exhaustion_posture_ref: String,
    pub summary: String,
}

impl ProgramBudgetHistoryRecord {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.budget_history_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingBudgetHistoryId);
        }
        if self.program_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingProgramRef);
        }
        if self.budget_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingBudgetRef);
        }
        validate_ref_list(&self.cycle_refs, FactoryProgramError::MissingCycleRefs)?;
        validate_ref_list(
            &self.consumption_refs,
            FactoryProgramError::MissingConsumptionRefs,
        )?;
        if self.exhaustion_posture_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingExhaustionPostureRef);
        }
        if self.summary.trim().is_empty() {
            return Err(FactoryProgramError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramPolicyComplianceRecord {
    pub policy_compliance_id: String,
    pub program_ref: String,
    pub policy_ref: String,
    pub cycle_refs: Vec<String>,
    pub compliance_refs: Vec<String>,
    pub variance_refs: Vec<String>,
    pub summary: String,
}

impl ProgramPolicyComplianceRecord {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.policy_compliance_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingPolicyComplianceRecordId);
        }
        if self.program_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingProgramRef);
        }
        if self.policy_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingPolicyRef);
        }
        validate_ref_list(&self.cycle_refs, FactoryProgramError::MissingCycleRefs)?;
        validate_ref_list(
            &self.compliance_refs,
            FactoryProgramError::MissingComplianceRefs,
        )?;
        validate_ref_list(
            &self.variance_refs,
            FactoryProgramError::MissingVarianceRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryProgramError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaterFactoryCycleDossier {
    pub cycle_dossier_id: String,
    pub program_ref: String,
    pub generation_agenda_ref: String,
    pub adoption_window_ref: String,
    pub candidate_factory_ref: String,
    pub proving_refs: Vec<String>,
    pub observation_refs: Vec<String>,
    pub rollback_posture_refs: Vec<String>,
    pub continuity_ref: String,
    pub disposition_ref: String,
    pub lineage_delta_ref: String,
}

impl LaterFactoryCycleDossier {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.cycle_dossier_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingCycleDossierId);
        }
        if self.program_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingProgramRef);
        }
        if self.generation_agenda_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingGenerationAgendaRef);
        }
        if self.adoption_window_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingAdoptionWindowRef);
        }
        if self.candidate_factory_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingCandidateFactoryRef);
        }
        validate_ref_list(&self.proving_refs, FactoryProgramError::MissingProvingRefs)?;
        validate_ref_list(
            &self.observation_refs,
            FactoryProgramError::MissingObservationRefs,
        )?;
        validate_ref_list(
            &self.rollback_posture_refs,
            FactoryProgramError::MissingRollbackPostureRefs,
        )?;
        if self.continuity_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingContinuityRef);
        }
        if self.disposition_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingDispositionRef);
        }
        if self.lineage_delta_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingLineageDeltaRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageHealthLedger {
    pub lineage_ledger_id: String,
    pub program_ref: String,
    pub generation_refs: Vec<String>,
    pub cycle_result_refs: Vec<String>,
    pub continuity_refs: Vec<String>,
    pub regression_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
}

impl LineageHealthLedger {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.lineage_ledger_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingLineageLedgerId);
        }
        if self.program_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingProgramRef);
        }
        validate_ref_list(
            &self.generation_refs,
            FactoryProgramError::MissingGenerationRefs,
        )?;
        validate_ref_list(
            &self.cycle_result_refs,
            FactoryProgramError::MissingCycleResultRefs,
        )?;
        validate_ref_list(
            &self.continuity_refs,
            FactoryProgramError::MissingContinuityRefs,
        )?;
        validate_ref_list(
            &self.regression_refs,
            FactoryProgramError::MissingRegressionRefs,
        )?;
        validate_ref_list(
            &self.rollback_refs,
            FactoryProgramError::MissingRollbackRefs,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionReviewPacket {
    pub regression_packet_id: String,
    pub lineage_ledger_ref: String,
    pub threshold_refs: Vec<String>,
    pub trigger_refs: Vec<String>,
    pub mitigation_refs: Vec<String>,
    pub summary: String,
}

impl RegressionReviewPacket {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.regression_packet_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingRegressionPacketId);
        }
        if self.lineage_ledger_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingLineageLedgerRef);
        }
        validate_ref_list(
            &self.threshold_refs,
            FactoryProgramError::MissingThresholdRefs,
        )?;
        validate_ref_list(&self.trigger_refs, FactoryProgramError::MissingTriggerRefs)?;
        validate_ref_list(
            &self.mitigation_refs,
            FactoryProgramError::MissingMitigationRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryProgramError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongitudinalLineageDossier {
    pub lineage_dossier_id: String,
    pub program_ref: String,
    pub health_ref: String,
    pub cycle_refs: Vec<String>,
    pub continuity_window_refs: Vec<String>,
    pub regression_packet_refs: Vec<String>,
    pub stability_refs: Vec<String>,
    pub closure_posture: String,
}

impl LongitudinalLineageDossier {
    pub fn validate(&self) -> Result<(), FactoryProgramError> {
        if self.lineage_dossier_id.trim().is_empty() {
            return Err(FactoryProgramError::MissingLongitudinalLineageDossierId);
        }
        if self.program_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingProgramRef);
        }
        if self.health_ref.trim().is_empty() {
            return Err(FactoryProgramError::MissingHealthRef);
        }
        validate_ref_list(&self.cycle_refs, FactoryProgramError::MissingCycleRefs)?;
        validate_ref_list(
            &self.continuity_window_refs,
            FactoryProgramError::MissingContinuityWindowRefs,
        )?;
        validate_ref_list(
            &self.regression_packet_refs,
            FactoryProgramError::MissingRegressionPacketRefs,
        )?;
        validate_ref_list(
            &self.stability_refs,
            FactoryProgramError::MissingStabilityRefs,
        )?;
        if self.closure_posture.trim().is_empty() {
            return Err(FactoryProgramError::MissingClosurePosture);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactoryProgramError {
    MissingImprovementProgramId,
    MissingFactoryProgramSpecId,
    MissingFactoryProgramTitle,
    MissingFactoryProgramInstanceId,
    MissingFactoryProgramTickId,
    MissingRootFactoryRef,
    MissingStableInterfaceRef,
    MissingGoalRefs,
    MissingWorkloadRefs,
    MissingUtilityMetricRefs,
    MissingMutationScopeRefs,
    MissingPromotionGateRefs,
    MissingRollbackGateRefs,
    MissingRecursionBudgetRef,
    MissingLineageRefs,
    MissingRecursionBudgetId,
    InvalidMaxDepth,
    InvalidMaxCampaigns,
    MissingRiskThresholdRefs,
    MissingExhaustionPolicy,
    MissingGenerationAgendaId,
    MissingParentFactoryRef,
    MissingCandidateFactoryRef,
    MissingProvingRefs,
    MissingObservationRefs,
    MissingDecisionRefs,
    MissingAdoptionWindowId,
    MissingRollbackRefs,
    MissingLineageHealthId,
    MissingComparisonRefs,
    MissingRiskRefs,
    MissingTrendRefs,
    MissingRecommendationRef,
    MissingStopConditionId,
    MissingProgramRef,
    MissingTriggerRefs,
    MissingOperatorGuidance,
    MissingRecurringFactoryProgramId,
    MissingBoundedProgramRefs,
    MissingIncumbentFactoryRef,
    MissingCycleRefs,
    MissingContinuityWindowRefs,
    MissingBudgetRef,
    MissingBudgetHistoryRef,
    MissingPolicyRef,
    MissingLlmDriverProfileRef,
    MissingPolicyComplianceRef,
    MissingRestartResumeRefs,
    MissingSummaryRef,
    MissingContinuityWindowId,
    MissingPrecedingRef,
    MissingSucceedingRef,
    MissingCarryForwardRefs,
    MissingBudgetHistoryId,
    MissingConsumptionRefs,
    MissingExhaustionPostureRef,
    MissingPolicyComplianceRecordId,
    MissingComplianceRefs,
    MissingVarianceRefs,
    MissingCycleDossierId,
    MissingGenerationAgendaRef,
    MissingAdoptionWindowRef,
    MissingRollbackPostureRefs,
    MissingContinuityRef,
    MissingDispositionRef,
    MissingLineageDeltaRef,
    MissingLineageLedgerId,
    MissingGenerationRefs,
    MissingCycleResultRefs,
    MissingContinuityRefs,
    MissingRegressionRefs,
    MissingRegressionPacketId,
    MissingLineageLedgerRef,
    MissingThresholdRefs,
    MissingMitigationRefs,
    MissingSummary,
    MissingLongitudinalLineageDossierId,
    MissingHealthRef,
    MissingRegressionPacketRefs,
    MissingStabilityRefs,
    MissingClosurePosture,
    MissingResultingFactoryRef,
    MissingTimestamp,
}

impl Display for FactoryProgramError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for FactoryProgramError {}

fn validate_ref_list(
    refs: &[String],
    error: FactoryProgramError,
) -> Result<(), FactoryProgramError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase03_factory_program_records_validate() {
        let recurring = RecurringFactoryProgramRecord {
            factory_program_id: "phase03-program".to_string(),
            bounded_program_refs: vec!["northstar-05-program-a".to_string()],
            incumbent_factory_ref: "factory:incumbent".to_string(),
            cycle_refs: vec!["phase03-cycle-a".to_string(), "phase03-cycle-b".to_string()],
            continuity_window_refs: vec![
                "phase03-continuity-bootstrap".to_string(),
                "phase03-continuity-cycle-b".to_string(),
            ],
            budget_ref: "northstar-05-budget-a".to_string(),
            budget_history_ref: "phase03-budget-history".to_string(),
            policy_ref: "policy:bounded-recursion".to_string(),
            policy_compliance_ref: "phase03-policy-compliance".to_string(),
            restart_resume_refs: vec![
                "resume:phase03-cycle-a".to_string(),
                "resume:phase03-cycle-b".to_string(),
            ],
            summary_ref: "summary:phase03-program".to_string(),
        };
        recurring.validate().unwrap();

        let continuity = ProgramContinuityWindowRecord {
            continuity_window_id: "phase03-continuity-bootstrap".to_string(),
            program_ref: recurring.factory_program_id.clone(),
            preceding_ref: "anchor:phase03-program".to_string(),
            succeeding_ref: "phase03-cycle-a".to_string(),
            carry_forward_refs: vec!["carry-forward:a".to_string()],
            restart_resume_refs: vec!["resume:phase03-cycle-a".to_string()],
            summary: "phase03 continuity anchor".to_string(),
        };
        continuity.validate().unwrap();

        let budget_history = ProgramBudgetHistoryRecord {
            budget_history_id: recurring.budget_history_ref.clone(),
            program_ref: recurring.factory_program_id.clone(),
            budget_ref: recurring.budget_ref.clone(),
            cycle_refs: recurring.cycle_refs.clone(),
            consumption_refs: vec![
                "budget-consumption:a".to_string(),
                "budget-consumption:b".to_string(),
            ],
            exhaustion_posture_ref: "budget-posture:within-bounds".to_string(),
            summary: "phase03 budget history".to_string(),
        };
        budget_history.validate().unwrap();

        let policy_compliance = ProgramPolicyComplianceRecord {
            policy_compliance_id: recurring.policy_compliance_ref.clone(),
            program_ref: recurring.factory_program_id.clone(),
            policy_ref: recurring.policy_ref.clone(),
            cycle_refs: recurring.cycle_refs.clone(),
            compliance_refs: vec![
                "policy-compliance:a".to_string(),
                "policy-compliance:b".to_string(),
            ],
            variance_refs: vec!["variance:none".to_string()],
            summary: "phase03 policy compliance".to_string(),
        };
        policy_compliance.validate().unwrap();

        let cycle = LaterFactoryCycleDossier {
            cycle_dossier_id: "phase03-cycle-a".to_string(),
            program_ref: recurring.factory_program_id.clone(),
            generation_agenda_ref: "northstar-05-generation-agenda-a".to_string(),
            adoption_window_ref: "northstar-05-adoption-window-a".to_string(),
            candidate_factory_ref: "factory:candidate".to_string(),
            proving_refs: vec!["proving:a".to_string()],
            observation_refs: vec!["observation:a".to_string()],
            rollback_posture_refs: vec!["rollback:a".to_string()],
            continuity_ref: continuity.continuity_window_id.clone(),
            disposition_ref: "decision:a".to_string(),
            lineage_delta_ref: "lineage-delta:a".to_string(),
        };
        cycle.validate().unwrap();

        let ledger = LineageHealthLedger {
            lineage_ledger_id: "phase03-lineage-ledger".to_string(),
            program_ref: recurring.factory_program_id.clone(),
            generation_refs: vec!["generation:a".to_string(), "generation:b".to_string()],
            cycle_result_refs: vec![cycle.cycle_dossier_id.clone()],
            continuity_refs: recurring.continuity_window_refs.clone(),
            regression_refs: vec!["phase03-regression".to_string()],
            rollback_refs: vec!["rollback:a".to_string()],
        };
        ledger.validate().unwrap();

        let packet = RegressionReviewPacket {
            regression_packet_id: "phase03-regression".to_string(),
            lineage_ledger_ref: ledger.lineage_ledger_id.clone(),
            threshold_refs: vec!["threshold:drift".to_string()],
            trigger_refs: vec!["trigger:budget-review".to_string()],
            mitigation_refs: vec!["mitigation:pause".to_string()],
            summary: "lineage review remained bounded".to_string(),
        };
        packet.validate().unwrap();

        let dossier = LongitudinalLineageDossier {
            lineage_dossier_id: "phase03-lineage-dossier".to_string(),
            program_ref: recurring.factory_program_id,
            health_ref: ledger.lineage_ledger_id,
            cycle_refs: vec![cycle.cycle_dossier_id],
            continuity_window_refs: vec![continuity.continuity_window_id],
            regression_packet_refs: vec![packet.regression_packet_id],
            stability_refs: vec![
                budget_history.budget_history_id,
                policy_compliance.policy_compliance_id,
            ],
            closure_posture: "healthy_bounded".to_string(),
        };
        dossier.validate().unwrap();
    }

    #[test]
    fn northstar_factory_program_spec_and_tick_validate() {
        let spec = FactoryProgramSpec {
            spec_id: "northstar-program".to_string(),
            title: "NorthStar governed recursion".to_string(),
            root_factory_ref: "factory:root".to_string(),
            stable_interface_ref: "contract:rc01".to_string(),
            goal_refs: vec!["goal:deepen-shell-universality".to_string()],
            workload_refs: vec!["workload:factory-self-improvement".to_string()],
            utility_metric_refs: vec!["metric:approval-burden".to_string()],
            mutation_scope_refs: vec!["scope:worker-routing".to_string()],
            promotion_gate_refs: vec!["gate:promotion".to_string()],
            rollback_gate_refs: vec!["gate:rollback".to_string()],
            recursion_budget: RecursionBudgetRecord {
                recursion_budget_id: "budget:northstar".to_string(),
                max_depth: 3,
                max_campaigns: 4,
                risk_threshold_refs: vec!["risk:drift".to_string()],
                exhaustion_policy: "pause_and_preserve_best_lineage".to_string(),
            },
            policy_ref: "policy:bounded-recursion".to_string(),
            llm_driver_profile_ref: None,
        };
        spec.validate().unwrap();

        let instance = FactoryProgramInstance {
            instance_id: "program-instance:1".to_string(),
            spec_id: spec.spec_id.clone(),
            recurring_program_ref: "recurring-program:1".to_string(),
            current_factory_ref: spec.root_factory_ref.clone(),
            program_state: FactoryProgramState::Preparing,
            generation_depth: 0,
            campaign_count: 0,
            cycle_refs: Vec::new(),
            continuity_window_refs: Vec::new(),
            adopted_factory_refs: vec![spec.root_factory_ref.clone()],
            restart_resume_refs: Vec::new(),
            latest_tick_id: None,
            created_at: "1".to_string(),
            updated_at: "1".to_string(),
        };
        instance.validate().unwrap();

        let request = FactoryProgramTickRequest {
            candidate_factory_ref: "factory:candidate".to_string(),
            proving_refs: vec!["proving:1".to_string()],
            observation_refs: vec!["observation:1".to_string()],
            comparison_refs: vec!["comparison:1".to_string()],
            risk_refs: vec!["risk:bounded".to_string()],
            trend_refs: vec!["trend:improving".to_string()],
            rollback_refs: vec!["rollback:1".to_string()],
            adoption_result: AdoptionWindowResult::Adopted,
            operator_note: Some("advance one governed generation".to_string()),
        };
        request.validate().unwrap();

        let receipt = FactoryProgramTickReceipt {
            tick_id: "tick:1".to_string(),
            instance_id: instance.instance_id,
            parent_factory_ref: "factory:root".to_string(),
            candidate_factory_ref: request.candidate_factory_ref.clone(),
            resulting_factory_ref: request.candidate_factory_ref,
            generation_depth: 1,
            campaign_count: 1,
            created_at: "2".to_string(),
            recurring_program: RecurringFactoryProgramRecord {
                factory_program_id: "recurring-program:1".to_string(),
                bounded_program_refs: vec![spec.spec_id],
                incumbent_factory_ref: "factory:candidate".to_string(),
                cycle_refs: vec!["cycle:1".to_string()],
                continuity_window_refs: vec!["continuity:1".to_string()],
                budget_ref: "budget:northstar".to_string(),
                budget_history_ref: "budget-history:1".to_string(),
                policy_ref: "policy:bounded-recursion".to_string(),
                policy_compliance_ref: "policy-compliance:1".to_string(),
                restart_resume_refs: vec!["resume:1".to_string()],
                summary_ref: "summary:1".to_string(),
            },
            generation_agenda: LaterFactoryGenerationAgenda {
                generation_agenda_id: "agenda:1".to_string(),
                parent_factory_ref: "factory:root".to_string(),
                candidate_factory_ref: "factory:candidate".to_string(),
                proving_refs: vec!["proving:1".to_string()],
                observation_refs: vec!["observation:1".to_string()],
                decision_refs: vec!["decision:1".to_string()],
            },
            adoption_window: AdoptionWindowRecord {
                adoption_window_id: "adoption-window:1".to_string(),
                candidate_factory_ref: "factory:candidate".to_string(),
                observation_refs: vec!["observation:1".to_string()],
                rollback_refs: vec!["rollback:1".to_string()],
                result: AdoptionWindowResult::Adopted,
            },
            continuity_window: ProgramContinuityWindowRecord {
                continuity_window_id: "continuity:1".to_string(),
                program_ref: "recurring-program:1".to_string(),
                preceding_ref: "factory:root".to_string(),
                succeeding_ref: "cycle:1".to_string(),
                carry_forward_refs: vec!["observation:1".to_string()],
                restart_resume_refs: vec!["resume:1".to_string()],
                summary: "carry governed state into cycle 1".to_string(),
            },
            budget_history: ProgramBudgetHistoryRecord {
                budget_history_id: "budget-history:1".to_string(),
                program_ref: "recurring-program:1".to_string(),
                budget_ref: "budget:northstar".to_string(),
                cycle_refs: vec!["cycle:1".to_string()],
                consumption_refs: vec!["budget-consumption:1".to_string()],
                exhaustion_posture_ref: "budget-posture:within-bounds".to_string(),
                summary: "campaign 1 remained within budget".to_string(),
            },
            policy_compliance: ProgramPolicyComplianceRecord {
                policy_compliance_id: "policy-compliance:1".to_string(),
                program_ref: "recurring-program:1".to_string(),
                policy_ref: "policy:bounded-recursion".to_string(),
                cycle_refs: vec!["cycle:1".to_string()],
                compliance_refs: vec!["policy-compliance:1".to_string()],
                variance_refs: vec!["variance:none".to_string()],
                summary: "cycle 1 remained inside the mutation boundary".to_string(),
            },
            cycle_dossier: LaterFactoryCycleDossier {
                cycle_dossier_id: "cycle:1".to_string(),
                program_ref: "recurring-program:1".to_string(),
                generation_agenda_ref: "agenda:1".to_string(),
                adoption_window_ref: "adoption-window:1".to_string(),
                candidate_factory_ref: "factory:candidate".to_string(),
                proving_refs: vec!["proving:1".to_string()],
                observation_refs: vec!["observation:1".to_string()],
                rollback_posture_refs: vec!["rollback:1".to_string()],
                continuity_ref: "continuity:1".to_string(),
                disposition_ref: "disposition:adopted".to_string(),
                lineage_delta_ref: "lineage-delta:1".to_string(),
            },
            lineage_health: LineageHealthDossier {
                lineage_health_id: "lineage-health:1".to_string(),
                lineage_refs: vec!["factory:root".to_string(), "factory:candidate".to_string()],
                comparison_refs: vec!["comparison:1".to_string()],
                risk_refs: vec!["risk:bounded".to_string()],
                trend_refs: vec!["trend:improving".to_string()],
                recommendation_ref: "recommendation:continue".to_string(),
            },
            stop_condition: StopConditionRecord {
                stop_condition_id: "stop-condition:1".to_string(),
                program_ref: "recurring-program:1".to_string(),
                trigger_refs: vec!["budget:northstar".to_string()],
                decision: StopConditionDecision::Continue,
                operator_guidance: "continue to the next governed generation".to_string(),
            },
            operator_note: Some("advance one governed generation".to_string()),
        };
        receipt.validate().unwrap();
    }
}
