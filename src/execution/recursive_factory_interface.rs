use crate::execution::capability::{CapabilityEnvelope, CapabilityWorld};
use crate::execution::factory_program::AdoptionWindowResult;
use crate::execution::turn_package::TurnResponseSchemaFamily;
use crate::execution::worker_ecology::WorkerRoleKind;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerAgentProductionMode {
    ModelProduced,
    ModelReused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveCycleOutcome {
    ApprovalBlocked,
    Denied,
    Quarantined,
    Failed,
    WorkerDispatched,
    CycleRecorded,
    Adopted,
    Refused,
    RolledBack,
    Paused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursionClaimPosture {
    InsufficientEvidence,
    GovernedBounded,
    GovernedBoundedOnHold,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmFactoryProgramProfile {
    pub llm_factory_program_profile_id: String,
    pub title: String,
    pub system_frame_text: String,
    pub program_frame_template: String,
    pub capability_frame_text: String,
    pub agenda_template: String,
    pub response_schema_family: TurnResponseSchemaFamily,
    pub max_rendered_prompt_chars: usize,
    pub max_continuity_entries: usize,
    pub capability_envelope: CapabilityEnvelope,
    #[serde(default)]
    pub tool_catalog_ref: Option<String>,
    pub default_pointer_index_ref: Option<String>,
    pub default_ecology_snapshot_ref: Option<String>,
    pub default_workspace_scope_ref: Option<String>,
    pub default_campaign_ref: Option<String>,
    pub default_epoch_ref: Option<String>,
    pub created_at: String,
}

impl LlmFactoryProgramProfile {
    pub fn validate(&self) -> Result<(), RecursiveFactoryInterfaceError> {
        require_nonempty(
            &self.llm_factory_program_profile_id,
            RecursiveFactoryInterfaceError::MissingProfileId,
        )?;
        require_nonempty(&self.title, RecursiveFactoryInterfaceError::MissingTitle)?;
        require_nonempty(
            &self.system_frame_text,
            RecursiveFactoryInterfaceError::MissingSystemFrameText,
        )?;
        require_nonempty(
            &self.program_frame_template,
            RecursiveFactoryInterfaceError::MissingProgramFrameTemplate,
        )?;
        require_nonempty(
            &self.capability_frame_text,
            RecursiveFactoryInterfaceError::MissingCapabilityFrameText,
        )?;
        require_nonempty(
            &self.agenda_template,
            RecursiveFactoryInterfaceError::MissingAgendaTemplate,
        )?;
        if self.max_rendered_prompt_chars == 0 {
            return Err(RecursiveFactoryInterfaceError::InvalidMaxRenderedPromptChars);
        }
        if self.max_continuity_entries == 0 {
            return Err(RecursiveFactoryInterfaceError::InvalidMaxContinuityEntries);
        }
        require_nonempty(
            &self.capability_envelope.envelope_id,
            RecursiveFactoryInterfaceError::MissingCapabilityEnvelopeId,
        )?;
        require_nonempty(
            &self.capability_envelope.actor_scope,
            RecursiveFactoryInterfaceError::MissingActorScope,
        )?;
        if self.capability_envelope.world_grants.is_empty() {
            return Err(RecursiveFactoryInterfaceError::MissingWorldGrants);
        }
        validate_optional_string(
            self.tool_catalog_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidDefaultContextRef,
        )?;
        validate_optional_string(
            self.default_pointer_index_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidDefaultContextRef,
        )?;
        validate_optional_string(
            self.default_ecology_snapshot_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidDefaultContextRef,
        )?;
        validate_optional_string(
            self.default_workspace_scope_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidDefaultContextRef,
        )?;
        validate_optional_string(
            self.default_campaign_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidDefaultContextRef,
        )?;
        validate_optional_string(
            self.default_epoch_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidDefaultContextRef,
        )?;
        require_nonempty(
            &self.created_at,
            RecursiveFactoryInterfaceError::MissingCreatedAt,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelDrivenFactoryCycleRecord {
    pub model_factory_cycle_id: String,
    pub program_instance_ref: String,
    pub campaign_number: usize,
    pub turn_package_ref: String,
    pub parsed_turn_result_ref: String,
    pub inference_turn_result_ref: String,
    pub authority_decision_ref: String,
    pub continuity_bundle_ref: Option<String>,
    pub turn_grounding_ref: Option<String>,
    pub tool_execution_receipt_refs: Vec<String>,
    pub tool_execution_refs: Vec<String>,
    pub worker_card_refs: Vec<String>,
    pub worker_dispatch_refs: Vec<String>,
    pub worker_result_refs: Vec<String>,
    pub proving_refs: Vec<String>,
    pub observation_refs: Vec<String>,
    pub comparison_refs: Vec<String>,
    pub tick_receipt_ref: Option<String>,
    pub candidate_factory_ref: Option<String>,
    pub resulting_factory_ref: Option<String>,
    pub approval_request_refs: Vec<String>,
    pub quarantine_refs: Vec<String>,
    pub checkpoint_refs: Vec<String>,
    pub pending_action_refs: Vec<String>,
    pub outcome: RecursiveCycleOutcome,
    pub created_at: String,
}

impl ModelDrivenFactoryCycleRecord {
    pub fn validate(&self) -> Result<(), RecursiveFactoryInterfaceError> {
        require_nonempty(
            &self.model_factory_cycle_id,
            RecursiveFactoryInterfaceError::MissingCycleId,
        )?;
        require_nonempty(
            &self.program_instance_ref,
            RecursiveFactoryInterfaceError::MissingProgramInstanceRef,
        )?;
        if self.campaign_number == 0 {
            return Err(RecursiveFactoryInterfaceError::InvalidCampaignNumber);
        }
        require_nonempty(
            &self.turn_package_ref,
            RecursiveFactoryInterfaceError::MissingTurnPackageRef,
        )?;
        require_nonempty(
            &self.parsed_turn_result_ref,
            RecursiveFactoryInterfaceError::MissingParsedTurnResultRef,
        )?;
        require_nonempty(
            &self.inference_turn_result_ref,
            RecursiveFactoryInterfaceError::MissingInferenceTurnResultRef,
        )?;
        require_nonempty(
            &self.authority_decision_ref,
            RecursiveFactoryInterfaceError::MissingAuthorityDecisionRef,
        )?;
        validate_optional_string(
            self.continuity_bundle_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidReference,
        )?;
        validate_optional_string(
            self.turn_grounding_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidReference,
        )?;
        validate_optional_string(
            self.tick_receipt_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidReference,
        )?;
        validate_optional_string(
            self.candidate_factory_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidReference,
        )?;
        validate_optional_string(
            self.resulting_factory_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidReference,
        )?;
        for refs in [
            &self.tool_execution_receipt_refs,
            &self.tool_execution_refs,
            &self.worker_card_refs,
            &self.worker_dispatch_refs,
            &self.worker_result_refs,
            &self.proving_refs,
            &self.observation_refs,
            &self.comparison_refs,
            &self.approval_request_refs,
            &self.quarantine_refs,
            &self.checkpoint_refs,
            &self.pending_action_refs,
        ] {
            validate_optional_string_list(refs, RecursiveFactoryInterfaceError::InvalidReference)?;
        }
        require_nonempty(
            &self.created_at,
            RecursiveFactoryInterfaceError::MissingCreatedAt,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveLineageExecutionRecord {
    pub recursive_lineage_execution_id: String,
    pub program_instance_ref: String,
    pub cycle_refs: Vec<String>,
    pub model_turn_refs: Vec<String>,
    pub produced_worker_refs: Vec<String>,
    pub adopted_factory_refs: Vec<String>,
    pub continuity_refs: Vec<String>,
    pub governance_refs: Vec<String>,
    pub latest_tick_ref: Option<String>,
    pub current_depth: usize,
    pub campaign_count: usize,
    pub claim_posture: RecursionClaimPosture,
    pub created_at: String,
    pub updated_at: String,
}

impl RecursiveLineageExecutionRecord {
    pub fn validate(&self) -> Result<(), RecursiveFactoryInterfaceError> {
        require_nonempty(
            &self.recursive_lineage_execution_id,
            RecursiveFactoryInterfaceError::MissingLineageId,
        )?;
        require_nonempty(
            &self.program_instance_ref,
            RecursiveFactoryInterfaceError::MissingProgramInstanceRef,
        )?;
        validate_required_string_list(
            &self.cycle_refs,
            RecursiveFactoryInterfaceError::MissingCycleRefs,
        )?;
        validate_required_string_list(
            &self.model_turn_refs,
            RecursiveFactoryInterfaceError::MissingTurnRefs,
        )?;
        for refs in [
            &self.produced_worker_refs,
            &self.adopted_factory_refs,
            &self.continuity_refs,
            &self.governance_refs,
        ] {
            validate_optional_string_list(refs, RecursiveFactoryInterfaceError::InvalidReference)?;
        }
        validate_optional_string(
            self.latest_tick_ref.as_deref(),
            RecursiveFactoryInterfaceError::InvalidReference,
        )?;
        if self.campaign_count == 0 {
            return Err(RecursiveFactoryInterfaceError::InvalidCampaignNumber);
        }
        require_nonempty(
            &self.created_at,
            RecursiveFactoryInterfaceError::MissingCreatedAt,
        )?;
        require_nonempty(
            &self.updated_at,
            RecursiveFactoryInterfaceError::MissingUpdatedAt,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchitecturalDependencyStatement {
    pub architectural_dependency_statement_id: String,
    pub lineage_ref: String,
    pub inference_provider_refs: Vec<String>,
    pub turn_refs: Vec<String>,
    pub tool_membrane_refs: Vec<String>,
    pub continuity_refs: Vec<String>,
    pub governance_refs: Vec<String>,
    pub operator_boundary_refs: Vec<String>,
    pub claim_posture: RecursionClaimPosture,
    pub claim_boundary_statement: String,
    pub created_at: String,
}

impl ArchitecturalDependencyStatement {
    pub fn validate(&self) -> Result<(), RecursiveFactoryInterfaceError> {
        require_nonempty(
            &self.architectural_dependency_statement_id,
            RecursiveFactoryInterfaceError::MissingDependencyStatementId,
        )?;
        require_nonempty(
            &self.lineage_ref,
            RecursiveFactoryInterfaceError::MissingLineageRef,
        )?;
        validate_required_string_list(
            &self.inference_provider_refs,
            RecursiveFactoryInterfaceError::MissingInferenceProviderRefs,
        )?;
        validate_required_string_list(
            &self.turn_refs,
            RecursiveFactoryInterfaceError::MissingTurnRefs,
        )?;
        validate_required_string_list(
            &self.tool_membrane_refs,
            RecursiveFactoryInterfaceError::MissingToolMembraneRefs,
        )?;
        validate_required_string_list(
            &self.operator_boundary_refs,
            RecursiveFactoryInterfaceError::MissingOperatorBoundaryRefs,
        )?;
        validate_optional_string_list(
            &self.continuity_refs,
            RecursiveFactoryInterfaceError::InvalidReference,
        )?;
        validate_optional_string_list(
            &self.governance_refs,
            RecursiveFactoryInterfaceError::InvalidReference,
        )?;
        require_nonempty(
            &self.claim_boundary_statement,
            RecursiveFactoryInterfaceError::MissingClaimBoundaryStatement,
        )?;
        require_nonempty(
            &self.created_at,
            RecursiveFactoryInterfaceError::MissingCreatedAt,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceNativeRecursionClosureDossier {
    pub recursion_closure_dossier_id: String,
    pub lineage_ref: String,
    pub cycle_refs: Vec<String>,
    pub produced_worker_refs: Vec<String>,
    pub proving_refs: Vec<String>,
    pub observation_refs: Vec<String>,
    pub comparison_refs: Vec<String>,
    pub continuity_refs: Vec<String>,
    pub governance_refs: Vec<String>,
    pub dependency_statement_ref: String,
    pub claim_posture: RecursionClaimPosture,
    pub claim_boundary_statement: String,
    pub created_at: String,
}

impl InterfaceNativeRecursionClosureDossier {
    pub fn validate(&self) -> Result<(), RecursiveFactoryInterfaceError> {
        require_nonempty(
            &self.recursion_closure_dossier_id,
            RecursiveFactoryInterfaceError::MissingClosureDossierId,
        )?;
        require_nonempty(
            &self.lineage_ref,
            RecursiveFactoryInterfaceError::MissingLineageRef,
        )?;
        validate_required_string_list(
            &self.cycle_refs,
            RecursiveFactoryInterfaceError::MissingCycleRefs,
        )?;
        for refs in [
            &self.produced_worker_refs,
            &self.proving_refs,
            &self.observation_refs,
            &self.comparison_refs,
            &self.continuity_refs,
            &self.governance_refs,
        ] {
            validate_optional_string_list(refs, RecursiveFactoryInterfaceError::InvalidReference)?;
        }
        require_nonempty(
            &self.dependency_statement_ref,
            RecursiveFactoryInterfaceError::MissingDependencyStatementRef,
        )?;
        require_nonempty(
            &self.claim_boundary_statement,
            RecursiveFactoryInterfaceError::MissingClaimBoundaryStatement,
        )?;
        require_nonempty(
            &self.created_at,
            RecursiveFactoryInterfaceError::MissingCreatedAt,
        )
    }
}

pub fn claim_boundary_statement(posture: RecursionClaimPosture) -> &'static str {
    match posture {
        RecursionClaimPosture::InsufficientEvidence => {
            "No completed tick-linked model cycle exists yet, so recursive factory claims remain insufficiently evidenced."
        }
        RecursionClaimPosture::GovernedBounded => {
            "Recursive factory execution is evidenced only as a governed, bounded supervisor line with no unresolved governance incidents."
        }
        RecursionClaimPosture::GovernedBoundedOnHold => {
            "Recursive factory execution is evidenced as governed and bounded, but unresolved governance incidents keep the recursive claim on hold."
        }
    }
}

pub fn derive_recursion_claim_posture(
    cycles: &[ModelDrivenFactoryCycleRecord],
) -> RecursionClaimPosture {
    let has_completed_cycle = cycles.iter().any(|cycle| cycle.tick_receipt_ref.is_some());
    if !has_completed_cycle {
        return RecursionClaimPosture::InsufficientEvidence;
    }
    let has_governance_hold = cycles.iter().any(|cycle| {
        matches!(
            cycle.outcome,
            RecursiveCycleOutcome::ApprovalBlocked
                | RecursiveCycleOutcome::Denied
                | RecursiveCycleOutcome::Quarantined
                | RecursiveCycleOutcome::Failed
        )
    });
    if has_governance_hold {
        RecursionClaimPosture::GovernedBoundedOnHold
    } else {
        RecursionClaimPosture::GovernedBounded
    }
}

pub fn recursive_cycle_outcome_from_adoption_result(
    result: AdoptionWindowResult,
) -> RecursiveCycleOutcome {
    match result {
        AdoptionWindowResult::Adopted => RecursiveCycleOutcome::Adopted,
        AdoptionWindowResult::Refused => RecursiveCycleOutcome::Refused,
        AdoptionWindowResult::RolledBack => RecursiveCycleOutcome::RolledBack,
        AdoptionWindowResult::Paused => RecursiveCycleOutcome::Paused,
    }
}

pub fn infer_worker_role_kind(
    task_kind: Option<&str>,
    capability_worlds: &[CapabilityWorld],
) -> WorkerRoleKind {
    let task_kind = task_kind.unwrap_or_default().to_ascii_lowercase();
    if task_kind.contains("continuity") {
        return WorkerRoleKind::ContinuityWorker;
    }
    if ["validate", "prove", "compare"]
        .iter()
        .any(|term| task_kind.contains(term))
    {
        return WorkerRoleKind::Validator;
    }
    if task_kind.contains("review") {
        return WorkerRoleKind::Reviewer;
    }
    if task_kind.contains("package") {
        return WorkerRoleKind::Packager;
    }
    if ["build", "patch", "mutate", "write"]
        .iter()
        .any(|term| task_kind.contains(term))
    {
        return WorkerRoleKind::Builder;
    }
    if ["plan", "observe", "inspect"]
        .iter()
        .any(|term| task_kind.contains(term))
    {
        return WorkerRoleKind::Planner;
    }
    if capability_worlds.contains(&CapabilityWorld::MemoryAccess) {
        return WorkerRoleKind::ContinuityWorker;
    }
    if capability_worlds.contains(&CapabilityWorld::ReviewPromotion) {
        return WorkerRoleKind::Validator;
    }
    if capability_worlds.contains(&CapabilityWorld::WorkspaceMutate) {
        return WorkerRoleKind::Builder;
    }
    if capability_worlds.contains(&CapabilityWorld::WorkspaceObserve) {
        return WorkerRoleKind::Planner;
    }
    WorkerRoleKind::Planner
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecursiveFactoryInterfaceError {
    MissingProfileId,
    MissingTitle,
    MissingSystemFrameText,
    MissingProgramFrameTemplate,
    MissingCapabilityFrameText,
    MissingAgendaTemplate,
    InvalidMaxRenderedPromptChars,
    InvalidMaxContinuityEntries,
    MissingCapabilityEnvelopeId,
    MissingActorScope,
    MissingWorldGrants,
    MissingCycleId,
    MissingLineageId,
    MissingDependencyStatementId,
    MissingClosureDossierId,
    MissingProgramInstanceRef,
    InvalidCampaignNumber,
    MissingTurnPackageRef,
    MissingParsedTurnResultRef,
    MissingInferenceTurnResultRef,
    MissingAuthorityDecisionRef,
    MissingCycleRefs,
    MissingTurnRefs,
    MissingDependencyStatementRef,
    MissingLineageRef,
    MissingInferenceProviderRefs,
    MissingToolMembraneRefs,
    MissingOperatorBoundaryRefs,
    MissingClaimBoundaryStatement,
    InvalidDefaultContextRef,
    InvalidReference,
    MissingCreatedAt,
    MissingUpdatedAt,
}

impl Display for RecursiveFactoryInterfaceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingProfileId => write!(f, "llm factory program profile id is required"),
            Self::MissingTitle => write!(f, "title is required"),
            Self::MissingSystemFrameText => write!(f, "system frame text is required"),
            Self::MissingProgramFrameTemplate => write!(f, "program frame template is required"),
            Self::MissingCapabilityFrameText => write!(f, "capability frame text is required"),
            Self::MissingAgendaTemplate => write!(f, "agenda template is required"),
            Self::InvalidMaxRenderedPromptChars => {
                write!(f, "max rendered prompt chars must be greater than zero")
            }
            Self::InvalidMaxContinuityEntries => {
                write!(f, "max continuity entries must be greater than zero")
            }
            Self::MissingCapabilityEnvelopeId => {
                write!(f, "capability envelope id is required")
            }
            Self::MissingActorScope => write!(f, "capability actor scope is required"),
            Self::MissingWorldGrants => {
                write!(f, "capability envelope must grant at least one world")
            }
            Self::MissingCycleId => write!(f, "model factory cycle id is required"),
            Self::MissingLineageId => write!(f, "recursive lineage execution id is required"),
            Self::MissingDependencyStatementId => {
                write!(f, "architectural dependency statement id is required")
            }
            Self::MissingClosureDossierId => {
                write!(f, "recursion closure dossier id is required")
            }
            Self::MissingProgramInstanceRef => write!(f, "program instance ref is required"),
            Self::InvalidCampaignNumber => write!(f, "campaign number must be greater than zero"),
            Self::MissingTurnPackageRef => write!(f, "turn package ref is required"),
            Self::MissingParsedTurnResultRef => write!(f, "parsed turn result ref is required"),
            Self::MissingInferenceTurnResultRef => {
                write!(f, "inference turn result ref is required")
            }
            Self::MissingAuthorityDecisionRef => write!(f, "authority decision ref is required"),
            Self::MissingCycleRefs => write!(f, "at least one cycle ref is required"),
            Self::MissingTurnRefs => write!(f, "at least one turn ref is required"),
            Self::MissingDependencyStatementRef => {
                write!(f, "dependency statement ref is required")
            }
            Self::MissingLineageRef => write!(f, "lineage ref is required"),
            Self::MissingInferenceProviderRefs => {
                write!(f, "at least one inference provider ref is required")
            }
            Self::MissingToolMembraneRefs => {
                write!(f, "at least one tool membrane ref is required")
            }
            Self::MissingOperatorBoundaryRefs => {
                write!(f, "at least one operator boundary ref is required")
            }
            Self::MissingClaimBoundaryStatement => {
                write!(f, "claim boundary statement is required")
            }
            Self::InvalidDefaultContextRef => write!(f, "default context refs cannot be blank"),
            Self::InvalidReference => write!(f, "record references cannot be blank"),
            Self::MissingCreatedAt => write!(f, "created_at is required"),
            Self::MissingUpdatedAt => write!(f, "updated_at is required"),
        }
    }
}

impl Error for RecursiveFactoryInterfaceError {}

fn require_nonempty(
    value: &str,
    error: RecursiveFactoryInterfaceError,
) -> Result<(), RecursiveFactoryInterfaceError> {
    if value.trim().is_empty() {
        Err(error)
    } else {
        Ok(())
    }
}

fn validate_required_string_list(
    values: &[String],
    error: RecursiveFactoryInterfaceError,
) -> Result<(), RecursiveFactoryInterfaceError> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        Err(error)
    } else {
        Ok(())
    }
}

fn validate_optional_string_list(
    values: &[String],
    error: RecursiveFactoryInterfaceError,
) -> Result<(), RecursiveFactoryInterfaceError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        Err(error)
    } else {
        Ok(())
    }
}

fn validate_optional_string(
    value: Option<&str>,
    error: RecursiveFactoryInterfaceError,
) -> Result<(), RecursiveFactoryInterfaceError> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LlmFactoryProgramProfile, ModelDrivenFactoryCycleRecord, RecursionClaimPosture,
        RecursiveCycleOutcome, WorkerAgentProductionMode, claim_boundary_statement,
        derive_recursion_claim_posture, infer_worker_role_kind,
    };
    use crate::execution::{
        ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityWorld, CapabilityWorldGrant,
        IsolationProfile, TurnResponseSchemaFamily, WorkerRoleKind,
    };

    fn profile() -> LlmFactoryProgramProfile {
        LlmFactoryProgramProfile {
            llm_factory_program_profile_id: "profile-1".to_string(),
            title: "Supervisor recursive driver".to_string(),
            system_frame_text: "bounded system".to_string(),
            program_frame_template: "program {{program_instance_ref}}".to_string(),
            capability_frame_text: "stay bounded".to_string(),
            agenda_template: "advance {{current_factory_ref}}".to_string(),
            response_schema_family: TurnResponseSchemaFamily::SupervisorTurnV1,
            max_rendered_prompt_chars: 4_000,
            max_continuity_entries: 4,
            capability_envelope: CapabilityEnvelope {
                envelope_id: "envelope:profile".to_string(),
                actor_scope: "llm-turn".to_string(),
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::CampaignControl,
                    allowed_operations: vec!["program.submit_cycle_decision".to_string()],
                    default_authority_class: AuthorityClass::PromotionControl,
                    default_approval_class: ApprovalClass::SupervisorAllowed,
                    operation_approval_overrides: Vec::new(),
                }],
                authority_ceiling: AuthorityClass::PromotionControl,
                isolation_profile: IsolationProfile::SupervisorExclusive,
                allowed_resource_scopes: vec!["scope:program".to_string()],
                approval_overrides: Vec::new(),
                quota_policy: None,
                campaign_scope: Some("campaign:profile".to_string()),
                epoch_scope: Some("epoch:profile".to_string()),
            },
            tool_catalog_ref: None,
            default_pointer_index_ref: Some("pointer-index:1".to_string()),
            default_ecology_snapshot_ref: Some("ecology-snapshot:1".to_string()),
            default_workspace_scope_ref: Some("scope:workspace".to_string()),
            default_campaign_ref: Some("campaign:profile".to_string()),
            default_epoch_ref: Some("epoch:profile".to_string()),
            created_at: "2026-04-18T12:00:00Z".to_string(),
        }
    }

    fn cycle(
        outcome: RecursiveCycleOutcome,
        tick_receipt_ref: Option<&str>,
    ) -> ModelDrivenFactoryCycleRecord {
        ModelDrivenFactoryCycleRecord {
            model_factory_cycle_id: format!("cycle-{outcome:?}"),
            program_instance_ref: "instance-1".to_string(),
            campaign_number: 1,
            turn_package_ref: "turn-package-1".to_string(),
            parsed_turn_result_ref: "parsed-turn-1".to_string(),
            inference_turn_result_ref: "inference-turn-1".to_string(),
            authority_decision_ref: "authority-1".to_string(),
            continuity_bundle_ref: Some("continuity-1".to_string()),
            turn_grounding_ref: Some("grounding-1".to_string()),
            tool_execution_receipt_refs: vec!["receipt-1".to_string()],
            tool_execution_refs: vec!["execution-1".to_string()],
            worker_card_refs: vec!["worker-card-1".to_string()],
            worker_dispatch_refs: vec!["dispatch-1".to_string()],
            worker_result_refs: vec!["result-1".to_string()],
            proving_refs: vec!["proof-1".to_string()],
            observation_refs: vec!["observation-1".to_string()],
            comparison_refs: vec!["comparison-1".to_string()],
            tick_receipt_ref: tick_receipt_ref.map(str::to_string),
            candidate_factory_ref: Some("factory:candidate".to_string()),
            resulting_factory_ref: Some("factory:result".to_string()),
            approval_request_refs: Vec::new(),
            quarantine_refs: Vec::new(),
            checkpoint_refs: vec!["checkpoint-1".to_string()],
            pending_action_refs: Vec::new(),
            outcome,
            created_at: "2026-04-18T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn profile_and_cycle_records_validate() {
        assert!(profile().validate().is_ok());
        assert!(
            cycle(RecursiveCycleOutcome::Adopted, Some("tick-1"))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn claim_posture_requires_tick_and_honors_governance_hold() {
        let insufficient =
            derive_recursion_claim_posture(&[cycle(RecursiveCycleOutcome::WorkerDispatched, None)]);
        assert_eq!(insufficient, RecursionClaimPosture::InsufficientEvidence);

        let governed = derive_recursion_claim_posture(&[cycle(
            RecursiveCycleOutcome::Adopted,
            Some("tick-1"),
        )]);
        assert_eq!(governed, RecursionClaimPosture::GovernedBounded);

        let on_hold = derive_recursion_claim_posture(&[
            cycle(RecursiveCycleOutcome::Adopted, Some("tick-1")),
            cycle(RecursiveCycleOutcome::Denied, None),
        ]);
        assert_eq!(on_hold, RecursionClaimPosture::GovernedBoundedOnHold);
        assert!(claim_boundary_statement(on_hold).contains("on hold"));
    }

    #[test]
    fn worker_role_inference_respects_fixed_precedence() {
        assert_eq!(
            infer_worker_role_kind(
                Some("continuity-audit"),
                &[CapabilityWorld::WorkspaceObserve]
            ),
            WorkerRoleKind::ContinuityWorker
        );
        assert_eq!(
            infer_worker_role_kind(
                Some("compare candidate"),
                &[CapabilityWorld::WorkspaceObserve]
            ),
            WorkerRoleKind::Validator
        );
        assert_eq!(
            infer_worker_role_kind(None, &[CapabilityWorld::WorkspaceMutate]),
            WorkerRoleKind::Builder
        );
        assert_eq!(
            infer_worker_role_kind(None, &[CapabilityWorld::WorkspaceObserve]),
            WorkerRoleKind::Planner
        );
        let _ = WorkerAgentProductionMode::ModelProduced;
    }
}
