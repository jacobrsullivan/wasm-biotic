use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Scenario,
    Program,
    Rerun,
    OperatorResume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathSupportClass {
    ShellFirst,
    Transitional,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchAdmissionState {
    Created,
    Running,
    Paused,
    Completed,
    Denied,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchRefusalClass {
    Unsupported,
    Denied,
    TransitionalBlock,
    GovernanceBlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationGateResult {
    Passed,
    Transitional,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathSupportClassification {
    pub path_ref: String,
    pub path_kind: PathKind,
    pub support_class: PathSupportClass,
    pub required_world_refs: Vec<String>,
    pub adapter_refs: Vec<String>,
    pub claim_boundary: String,
}

impl PathSupportClassification {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.path_ref.trim().is_empty() {
            return Err(LaunchError::MissingPathRef);
        }
        validate_ref_list(
            &self.required_world_refs,
            LaunchError::MissingRequiredWorldRefs,
        )?;
        if self.claim_boundary.trim().is_empty() {
            return Err(LaunchError::MissingClaimBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalShellLaunchAssembly {
    pub launch_id: String,
    pub path_ref: String,
    pub support_class_ref: String,
    pub campaign_ref: String,
    pub agenda_ref: String,
    pub worker_binding_ref: String,
    pub capability_context_ref: String,
    pub bootstrap_refs: Vec<String>,
}

impl UniversalShellLaunchAssembly {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.launch_id.trim().is_empty() {
            return Err(LaunchError::MissingLaunchId);
        }
        if self.path_ref.trim().is_empty() {
            return Err(LaunchError::MissingPathRef);
        }
        if self.support_class_ref.trim().is_empty() {
            return Err(LaunchError::MissingSupportClassRef);
        }
        if self.campaign_ref.trim().is_empty() {
            return Err(LaunchError::MissingCampaignRef);
        }
        if self.agenda_ref.trim().is_empty() {
            return Err(LaunchError::MissingAgendaRef);
        }
        if self.worker_binding_ref.trim().is_empty() {
            return Err(LaunchError::MissingWorkerBindingRef);
        }
        if self.capability_context_ref.trim().is_empty() {
            return Err(LaunchError::MissingCapabilityContextRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignAdmissionRecord {
    pub admission_id: String,
    pub launch_ref: String,
    pub session_refs: Vec<String>,
    pub task_refs: Vec<String>,
    pub initial_state: LaunchAdmissionState,
    pub summary: String,
}

impl CampaignAdmissionRecord {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.admission_id.trim().is_empty() {
            return Err(LaunchError::MissingAdmissionId);
        }
        if self.launch_ref.trim().is_empty() {
            return Err(LaunchError::MissingLaunchRef);
        }
        validate_ref_list(&self.session_refs, LaunchError::MissingSessionRefs)?;
        validate_ref_list(&self.task_refs, LaunchError::MissingTaskRefs)?;
        if self.summary.trim().is_empty() {
            return Err(LaunchError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchRefusalRecord {
    pub refusal_id: String,
    pub launch_ref: String,
    pub refusal_class: LaunchRefusalClass,
    pub blocking_refs: Vec<String>,
    pub operator_guidance: String,
}

impl LaunchRefusalRecord {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.refusal_id.trim().is_empty() {
            return Err(LaunchError::MissingRefusalId);
        }
        if self.launch_ref.trim().is_empty() {
            return Err(LaunchError::MissingLaunchRef);
        }
        validate_ref_list(&self.blocking_refs, LaunchError::MissingBlockingRefs)?;
        if self.operator_guidance.trim().is_empty() {
            return Err(LaunchError::MissingOperatorGuidance);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramToShellMapping {
    pub mapping_id: String,
    pub program_ref: String,
    pub campaign_refs: Vec<String>,
    pub step_refs: Vec<String>,
    pub budget_ref: String,
    pub summary: String,
}

impl ProgramToShellMapping {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.mapping_id.trim().is_empty() {
            return Err(LaunchError::MissingMappingId);
        }
        if self.program_ref.trim().is_empty() {
            return Err(LaunchError::MissingProgramRef);
        }
        validate_ref_list(&self.campaign_refs, LaunchError::MissingCampaignRefs)?;
        validate_ref_list(&self.step_refs, LaunchError::MissingStepRefs)?;
        if self.budget_ref.trim().is_empty() {
            return Err(LaunchError::MissingBudgetRef);
        }
        if self.summary.trim().is_empty() {
            return Err(LaunchError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedLifecycleTransitionRecord {
    pub transition_id: String,
    pub campaign_ref: String,
    pub from_state: String,
    pub to_state: String,
    pub turn_ref: String,
    pub decision_refs: Vec<String>,
}

impl UnifiedLifecycleTransitionRecord {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.transition_id.trim().is_empty() {
            return Err(LaunchError::MissingTransitionId);
        }
        if self.campaign_ref.trim().is_empty() {
            return Err(LaunchError::MissingCampaignRef);
        }
        if self.from_state.trim().is_empty() {
            return Err(LaunchError::MissingFromState);
        }
        if self.to_state.trim().is_empty() {
            return Err(LaunchError::MissingToState);
        }
        if self.turn_ref.trim().is_empty() {
            return Err(LaunchError::MissingTurnRef);
        }
        validate_ref_list(&self.decision_refs, LaunchError::MissingDecisionRefs)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeChainRecord {
    pub resume_chain_id: String,
    pub checkpoint_refs: Vec<String>,
    pub resume_trigger_ref: String,
    pub campaign_ref: String,
    pub outcome_ref: String,
}

impl ResumeChainRecord {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.resume_chain_id.trim().is_empty() {
            return Err(LaunchError::MissingResumeChainId);
        }
        validate_ref_list(&self.checkpoint_refs, LaunchError::MissingCheckpointRefs)?;
        if self.resume_trigger_ref.trim().is_empty() {
            return Err(LaunchError::MissingResumeTriggerRef);
        }
        if self.campaign_ref.trim().is_empty() {
            return Err(LaunchError::MissingCampaignRef);
        }
        if self.outcome_ref.trim().is_empty() {
            return Err(LaunchError::MissingOutcomeRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellEvidenceSummary {
    pub summary_id: String,
    pub launch_ref: String,
    pub campaign_ref: String,
    pub continuity_ref: String,
    pub decision_refs: Vec<String>,
    pub claim_boundary: String,
}

impl ShellEvidenceSummary {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.summary_id.trim().is_empty() {
            return Err(LaunchError::MissingSummaryId);
        }
        if self.launch_ref.trim().is_empty() {
            return Err(LaunchError::MissingLaunchRef);
        }
        if self.campaign_ref.trim().is_empty() {
            return Err(LaunchError::MissingCampaignRef);
        }
        if self.continuity_ref.trim().is_empty() {
            return Err(LaunchError::MissingContinuityRef);
        }
        validate_ref_list(&self.decision_refs, LaunchError::MissingDecisionRefs)?;
        if self.claim_boundary.trim().is_empty() {
            return Err(LaunchError::MissingClaimBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellDerivedExportBundle {
    pub export_id: String,
    pub summary_ref: String,
    pub session_refs: Vec<String>,
    pub checkpoint_refs: Vec<String>,
    pub memory_refs: Vec<String>,
    pub workspace_refs: Vec<String>,
}

impl ShellDerivedExportBundle {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.export_id.trim().is_empty() {
            return Err(LaunchError::MissingExportId);
        }
        if self.summary_ref.trim().is_empty() {
            return Err(LaunchError::MissingSummaryRef);
        }
        validate_ref_list(&self.session_refs, LaunchError::MissingSessionRefs)?;
        validate_ref_list(&self.checkpoint_refs, LaunchError::MissingCheckpointRefs)?;
        validate_ref_list(&self.memory_refs, LaunchError::MissingMemoryRefs)?;
        validate_ref_list(&self.workspace_refs, LaunchError::MissingWorkspaceRefs)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionalTruthAnnotation {
    pub annotation_id: String,
    pub surface_ref: String,
    pub shell_truth_refs: Vec<String>,
    pub adapter_refs: Vec<String>,
    pub operator_warning: String,
}

impl TransitionalTruthAnnotation {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.annotation_id.trim().is_empty() {
            return Err(LaunchError::MissingAnnotationId);
        }
        if self.surface_ref.trim().is_empty() {
            return Err(LaunchError::MissingSurfaceRef);
        }
        validate_ref_list(&self.shell_truth_refs, LaunchError::MissingShellTruthRefs)?;
        validate_ref_list(&self.adapter_refs, LaunchError::MissingAdapterRefs)?;
        if self.operator_warning.trim().is_empty() {
            return Err(LaunchError::MissingOperatorWarning);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionalAdapterManifest {
    pub adapter_id: String,
    pub path_refs: Vec<String>,
    pub reason: String,
    pub shell_gap_refs: Vec<String>,
    pub retirement_gate_ref: String,
}

impl TransitionalAdapterManifest {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.adapter_id.trim().is_empty() {
            return Err(LaunchError::MissingAdapterId);
        }
        validate_ref_list(&self.path_refs, LaunchError::MissingPathRefs)?;
        if self.reason.trim().is_empty() {
            return Err(LaunchError::MissingReason);
        }
        validate_ref_list(&self.shell_gap_refs, LaunchError::MissingShellGapRefs)?;
        if self.retirement_gate_ref.trim().is_empty() {
            return Err(LaunchError::MissingRetirementGateRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationGateRecord {
    pub gate_id: String,
    pub path_ref: String,
    pub required_refs: Vec<String>,
    pub result: MigrationGateResult,
    pub failure_refs: Vec<String>,
}

impl MigrationGateRecord {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.gate_id.trim().is_empty() {
            return Err(LaunchError::MissingGateId);
        }
        if self.path_ref.trim().is_empty() {
            return Err(LaunchError::MissingPathRef);
        }
        validate_ref_list(&self.required_refs, LaunchError::MissingRequiredRefs)?;
        if matches!(self.result, MigrationGateResult::Passed) && !self.failure_refs.is_empty() {
            return Err(LaunchError::PassedGateCannotCarryFailures);
        }
        if !matches!(self.result, MigrationGateResult::Passed) {
            validate_ref_list(&self.failure_refs, LaunchError::MissingFailureRefs)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRetirementRecord {
    pub retirement_id: String,
    pub path_ref: String,
    pub retired_refs: Vec<String>,
    pub replacement_refs: Vec<String>,
    pub summary: String,
}

impl PathRetirementRecord {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.retirement_id.trim().is_empty() {
            return Err(LaunchError::MissingRetirementId);
        }
        if self.path_ref.trim().is_empty() {
            return Err(LaunchError::MissingPathRef);
        }
        validate_ref_list(&self.retired_refs, LaunchError::MissingRetiredRefs)?;
        validate_ref_list(&self.replacement_refs, LaunchError::MissingReplacementRefs)?;
        if self.summary.trim().is_empty() {
            return Err(LaunchError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceTruthMatrix {
    pub matrix_id: String,
    pub path_refs: Vec<String>,
    pub support_expectations: Vec<String>,
    pub provenance_expectations: Vec<String>,
    pub deprecation_expectations: Vec<String>,
}

impl AcceptanceTruthMatrix {
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.matrix_id.trim().is_empty() {
            return Err(LaunchError::MissingMatrixId);
        }
        validate_ref_list(&self.path_refs, LaunchError::MissingPathRefs)?;
        validate_ref_list(
            &self.support_expectations,
            LaunchError::MissingSupportExpectations,
        )?;
        validate_ref_list(
            &self.provenance_expectations,
            LaunchError::MissingProvenanceExpectations,
        )?;
        validate_ref_list(
            &self.deprecation_expectations,
            LaunchError::MissingDeprecationExpectations,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchError {
    MissingPathRef,
    MissingPathRefs,
    MissingRequiredWorldRefs,
    MissingClaimBoundary,
    MissingLaunchId,
    MissingSupportClassRef,
    MissingCampaignRef,
    MissingAgendaRef,
    MissingWorkerBindingRef,
    MissingCapabilityContextRef,
    MissingAdmissionId,
    MissingLaunchRef,
    MissingSessionRefs,
    MissingTaskRefs,
    MissingSummary,
    MissingRefusalId,
    MissingBlockingRefs,
    MissingOperatorGuidance,
    MissingMappingId,
    MissingProgramRef,
    MissingCampaignRefs,
    MissingStepRefs,
    MissingBudgetRef,
    MissingTransitionId,
    MissingFromState,
    MissingToState,
    MissingTurnRef,
    MissingDecisionRefs,
    MissingResumeChainId,
    MissingCheckpointRefs,
    MissingResumeTriggerRef,
    MissingOutcomeRef,
    MissingSummaryId,
    MissingContinuityRef,
    MissingExportId,
    MissingSummaryRef,
    MissingMemoryRefs,
    MissingWorkspaceRefs,
    MissingAnnotationId,
    MissingSurfaceRef,
    MissingShellTruthRefs,
    MissingAdapterRefs,
    MissingOperatorWarning,
    MissingAdapterId,
    MissingReason,
    MissingShellGapRefs,
    MissingRetirementGateRef,
    MissingGateId,
    MissingRequiredRefs,
    MissingFailureRefs,
    PassedGateCannotCarryFailures,
    MissingRetirementId,
    MissingRetiredRefs,
    MissingReplacementRefs,
    MissingMatrixId,
    MissingSupportExpectations,
    MissingProvenanceExpectations,
    MissingDeprecationExpectations,
}

impl Display for LaunchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for LaunchError {}

fn validate_ref_list(refs: &[String], error: LaunchError) -> Result<(), LaunchError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}
