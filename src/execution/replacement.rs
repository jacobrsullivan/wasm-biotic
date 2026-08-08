use crate::execution::capability::{CapabilityEnvelope, CapabilityWorld};
use crate::execution::governance::TickSource;
use crate::execution::memory::{MemoryStore, TranscriptSlice, TranscriptSliceQuery};
use crate::execution::storage::DurableArtifactStore;
use crate::execution::worker::WorkerDispatch;
use crate::execution::{CampaignId, CapabilityEnvelopeId, CheckpointId, SessionId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityImportTarget {
    TranscriptRetrieval,
    CampaignControl,
    ApprovalGateway,
    ReviewPromotion,
    ScheduleTick,
    ModelHosting,
    WorktreeHostAdapter,
    EnvironmentBridge,
    SemanticValidation,
    ArtifactPackaging,
    NativeSupervisorChallenger,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderKind {
    Imported,
    Native,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NativeReplacementTier {
    ImportedBaseline,
    NativeControlArtifacts,
    NativeCapabilitySurfaces,
    NativeSupervisorChallengers,
    BoundedSelfHostingLoop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvaluationDimension {
    SemanticCorrectness,
    GovernanceFidelity,
    Replayability,
    OperatorBurden,
    BoundaryCost,
    ReplacementSafety,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DimensionVerdict {
    ChallengerBetter,
    Equivalent,
    ChallengerWorse,
    InsufficientEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationDimensionScore {
    pub dimension: EvaluationDimension,
    pub verdict: DimensionVerdict,
    pub incumbent_summary: String,
    pub challenger_summary: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowCampaignStatus {
    Prepared,
    Running,
    Compared,
    DecisionReady,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowCampaign {
    pub shadow_campaign_id: String,
    pub campaign_id: CampaignId,
    pub incumbent_session_ref: SessionId,
    pub challenger_session_ref: SessionId,
    pub shared_input_refs: Vec<String>,
    pub incumbent_checkpoint_ref: Option<CheckpointId>,
    pub challenger_checkpoint_ref: Option<CheckpointId>,
    pub allowed_tick_sources: Vec<TickSource>,
    pub native_control_targets: Vec<CapabilityImportTarget>,
    pub no_live_mutation: bool,
    pub rollback_handle_ref: String,
    pub status: ShadowCampaignStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengerEvaluationSession {
    pub evaluation_session_id: String,
    pub shadow_campaign_id: String,
    pub incumbent_session_ref: SessionId,
    pub challenger_session_ref: SessionId,
    pub shared_input_refs: Vec<String>,
    pub challenger_capability_envelope_refs: Vec<CapabilityEnvelopeId>,
    pub latest_challenger_checkpoint_ref: Option<CheckpointId>,
    pub no_live_mutation: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationComparisonRecord {
    pub comparison_id: String,
    pub target: CapabilityImportTarget,
    pub replacement_tier: NativeReplacementTier,
    pub incumbent_ref: String,
    pub challenger_ref: String,
    pub shared_input_refs: Vec<String>,
    pub imported_provider: ProviderKind,
    pub native_provider: ProviderKind,
    pub imported_output_refs: Vec<String>,
    pub native_output_refs: Vec<String>,
    pub dimension_scores: Vec<EvaluationDimensionScore>,
    pub matched: bool,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSufficiencyGate {
    pub target: CapabilityImportTarget,
    pub required_tier: NativeReplacementTier,
    pub requires_exact_match: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSufficiencyEvidence {
    pub evidence_id: String,
    pub target: CapabilityImportTarget,
    pub achieved_tier: NativeReplacementTier,
    pub artifact_refs: Vec<String>,
    pub checkpoint_refs: Vec<String>,
    pub audit_refs: Vec<String>,
    pub summary: String,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityDependencyMode {
    ImportedBaseline,
    HybridControl,
    CarriedImport,
    Native,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityClosureStatus {
    NativeClosed,
    CarriedImportApproved,
    DeferredPostV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityClosureEntry {
    pub target: CapabilityImportTarget,
    pub current_mode: CapabilityDependencyMode,
    pub closure_status: CapabilityClosureStatus,
    pub capability_world_ref: Option<String>,
    pub audit_ref: Option<String>,
    pub rationale: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureInventory {
    pub inventory_id: String,
    pub entries: Vec<CapabilityClosureEntry>,
    pub remaining_gap_refs: Vec<String>,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenomeArtifact {
    pub genome_id: String,
    pub parent_ref: String,
    pub stable_interface_ref: String,
    pub typed_graph_ref: String,
    pub policy_refs: Vec<String>,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhenotypeArtifact {
    pub artifact_id: String,
    pub genome_ref: String,
    pub stable_interface_ref: String,
    pub package_ref: String,
    pub boundary_refs: Vec<String>,
    pub output_refs: Vec<String>,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticValidationRecord {
    pub validation_id: String,
    pub genome_ref: String,
    pub phenotype_ref: String,
    pub stable_interface_ref: String,
    pub validator_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub passed: bool,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactFlowError {
    MissingStableInterface,
    MissingTypedGraph,
    MissingPackageRef,
    MissingValidationEvidence,
    InterfaceMismatch { expected: String, actual: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShadowEvaluationError {
    MissingSharedInputs,
    SharedInputMismatch {
        incumbent_only_refs: Vec<String>,
        challenger_only_refs: Vec<String>,
    },
    MissingNativeControlTarget {
        target: CapabilityImportTarget,
    },
    MissingCapabilityEnvelopeRefs,
    MissingCriticalDimension {
        dimension: EvaluationDimension,
    },
    LiveMutationForbidden {
        operation: String,
    },
}

pub fn build_closure_inventory(
    inventory_id: impl Into<String>,
    entries: Vec<CapabilityClosureEntry>,
    remaining_gap_refs: Vec<String>,
    summary: impl Into<String>,
) -> ClosureInventory {
    ClosureInventory {
        inventory_id: inventory_id.into(),
        entries,
        remaining_gap_refs,
        summary: summary.into(),
    }
}

pub fn closure_inventory_has_hidden_imports(inventory: &ClosureInventory) -> bool {
    inventory.entries.iter().any(|entry| {
        matches!(
            entry.current_mode,
            CapabilityDependencyMode::ImportedBaseline | CapabilityDependencyMode::CarriedImport
        ) && entry.capability_world_ref.is_none()
    })
}

pub fn closure_inventory_is_complete(inventory: &ClosureInventory) -> bool {
    let mut audit_refs = BTreeSet::new();
    let has_complete_target_coverage = all_capability_import_targets().iter().all(|target| {
        inventory
            .entries
            .iter()
            .filter(|entry| entry.target == *target)
            .count()
            == 1
    });

    inventory.remaining_gap_refs.is_empty()
        && has_complete_target_coverage
        && !closure_inventory_has_hidden_imports(inventory)
        && inventory.entries.iter().all(|entry| {
            let mode_matches_closure = match entry.current_mode {
                CapabilityDependencyMode::ImportedBaseline
                | CapabilityDependencyMode::CarriedImport => {
                    entry.closure_status == CapabilityClosureStatus::CarriedImportApproved
                }
                CapabilityDependencyMode::Native => {
                    entry.closure_status == CapabilityClosureStatus::NativeClosed
                }
                CapabilityDependencyMode::HybridControl => matches!(
                    entry.closure_status,
                    CapabilityClosureStatus::NativeClosed
                        | CapabilityClosureStatus::CarriedImportApproved
                ),
            };
            let audit_ref = entry.audit_ref.as_ref();
            let audit_ref_is_unique =
                audit_ref.is_some_and(|audit_ref| audit_refs.insert(audit_ref.as_str()));
            !entry.rationale.trim().is_empty()
                && entry
                    .capability_world_ref
                    .as_ref()
                    .is_some_and(|world_ref| !world_ref.trim().is_empty())
                && audit_ref.is_some_and(|audit_ref| !audit_ref.trim().is_empty())
                && audit_ref_is_unique
                && mode_matches_closure
        })
}

pub fn carried_import_targets(inventory: &ClosureInventory) -> Vec<String> {
    inventory
        .entries
        .iter()
        .filter(|entry| entry.closure_status == CapabilityClosureStatus::CarriedImportApproved)
        .map(|entry| format!("{:?}", entry.target))
        .collect()
}

pub fn build_successor_genome(
    genome_id: impl Into<String>,
    parent_ref: impl Into<String>,
    stable_interface_ref: impl Into<String>,
    typed_graph_ref: impl Into<String>,
    policy_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<GenomeArtifact, ArtifactFlowError> {
    let stable_interface_ref = stable_interface_ref.into();
    if stable_interface_ref.trim().is_empty() {
        return Err(ArtifactFlowError::MissingStableInterface);
    }

    let typed_graph_ref = typed_graph_ref.into();
    if typed_graph_ref.trim().is_empty() {
        return Err(ArtifactFlowError::MissingTypedGraph);
    }

    Ok(GenomeArtifact {
        genome_id: genome_id.into(),
        parent_ref: parent_ref.into(),
        stable_interface_ref,
        typed_graph_ref,
        policy_refs,
        summary: summary.into(),
    })
}

pub fn materialize_successor_phenotype(
    artifact_id: impl Into<String>,
    genome: &GenomeArtifact,
    stable_interface_ref: impl Into<String>,
    package_ref: impl Into<String>,
    boundary_refs: Vec<String>,
    output_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<PhenotypeArtifact, ArtifactFlowError> {
    let stable_interface_ref = stable_interface_ref.into();
    if stable_interface_ref.trim().is_empty() {
        return Err(ArtifactFlowError::MissingStableInterface);
    }

    if stable_interface_ref != genome.stable_interface_ref {
        return Err(ArtifactFlowError::InterfaceMismatch {
            expected: genome.stable_interface_ref.clone(),
            actual: stable_interface_ref,
        });
    }

    let package_ref = package_ref.into();
    if package_ref.trim().is_empty() {
        return Err(ArtifactFlowError::MissingPackageRef);
    }

    Ok(PhenotypeArtifact {
        artifact_id: artifact_id.into(),
        genome_ref: genome.genome_id.clone(),
        stable_interface_ref: genome.stable_interface_ref.clone(),
        package_ref,
        boundary_refs,
        output_refs,
        summary: summary.into(),
    })
}

pub fn validate_semantic_phenotype(
    validation_id: impl Into<String>,
    genome: &GenomeArtifact,
    phenotype: &PhenotypeArtifact,
    validator_refs: Vec<String>,
    evidence_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<SemanticValidationRecord, ArtifactFlowError> {
    if phenotype.stable_interface_ref != genome.stable_interface_ref {
        return Err(ArtifactFlowError::InterfaceMismatch {
            expected: genome.stable_interface_ref.clone(),
            actual: phenotype.stable_interface_ref.clone(),
        });
    }

    if evidence_refs.is_empty() {
        return Err(ArtifactFlowError::MissingValidationEvidence);
    }

    Ok(SemanticValidationRecord {
        validation_id: validation_id.into(),
        genome_ref: genome.genome_id.clone(),
        phenotype_ref: phenotype.artifact_id.clone(),
        stable_interface_ref: phenotype.stable_interface_ref.clone(),
        validator_refs,
        evidence_refs,
        passed: true,
        summary: summary.into(),
    })
}

fn required_evaluation_dimensions() -> [EvaluationDimension; 6] {
    [
        EvaluationDimension::SemanticCorrectness,
        EvaluationDimension::GovernanceFidelity,
        EvaluationDimension::Replayability,
        EvaluationDimension::OperatorBurden,
        EvaluationDimension::BoundaryCost,
        EvaluationDimension::ReplacementSafety,
    ]
}

fn verdict_blocks_promotion(verdict: DimensionVerdict) -> bool {
    matches!(
        verdict,
        DimensionVerdict::ChallengerWorse | DimensionVerdict::InsufficientEvidence
    )
}

fn set_diff(left: &[String], right: &[String]) -> Vec<String> {
    let left_set = left.iter().cloned().collect::<BTreeSet<_>>();
    let right_set = right.iter().cloned().collect::<BTreeSet<_>>();
    left_set.difference(&right_set).cloned().collect()
}

fn all_capability_import_targets() -> [CapabilityImportTarget; 11] {
    [
        CapabilityImportTarget::TranscriptRetrieval,
        CapabilityImportTarget::CampaignControl,
        CapabilityImportTarget::ApprovalGateway,
        CapabilityImportTarget::ReviewPromotion,
        CapabilityImportTarget::ScheduleTick,
        CapabilityImportTarget::ModelHosting,
        CapabilityImportTarget::WorktreeHostAdapter,
        CapabilityImportTarget::EnvironmentBridge,
        CapabilityImportTarget::SemanticValidation,
        CapabilityImportTarget::ArtifactPackaging,
        CapabilityImportTarget::NativeSupervisorChallenger,
    ]
}

fn ensure_critical_dimensions(
    dimension_scores: &[EvaluationDimensionScore],
) -> Result<(), ShadowEvaluationError> {
    for required in required_evaluation_dimensions() {
        if !dimension_scores
            .iter()
            .any(|score| score.dimension == required)
        {
            return Err(ShadowEvaluationError::MissingCriticalDimension {
                dimension: required,
            });
        }
    }

    Ok(())
}

pub fn open_shadow_campaign(
    shadow_campaign_id: impl Into<String>,
    campaign_id: impl Into<CampaignId>,
    incumbent_session_ref: impl Into<SessionId>,
    challenger_session_ref: impl Into<SessionId>,
    shared_input_refs: Vec<String>,
    allowed_tick_sources: Vec<TickSource>,
    native_control_targets: Vec<CapabilityImportTarget>,
    no_live_mutation: bool,
    rollback_handle_ref: impl Into<String>,
) -> Result<ShadowCampaign, ShadowEvaluationError> {
    if shared_input_refs.is_empty() {
        return Err(ShadowEvaluationError::MissingSharedInputs);
    }

    for required_target in [
        CapabilityImportTarget::CampaignControl,
        CapabilityImportTarget::ApprovalGateway,
        CapabilityImportTarget::ReviewPromotion,
    ] {
        if !native_control_targets.contains(&required_target) {
            return Err(ShadowEvaluationError::MissingNativeControlTarget {
                target: required_target,
            });
        }
    }

    Ok(ShadowCampaign {
        shadow_campaign_id: shadow_campaign_id.into(),
        campaign_id: campaign_id.into(),
        incumbent_session_ref: incumbent_session_ref.into(),
        challenger_session_ref: challenger_session_ref.into(),
        shared_input_refs,
        incumbent_checkpoint_ref: None,
        challenger_checkpoint_ref: None,
        allowed_tick_sources,
        native_control_targets,
        no_live_mutation,
        rollback_handle_ref: rollback_handle_ref.into(),
        status: ShadowCampaignStatus::Prepared,
    })
}

pub fn open_challenger_evaluation_session(
    evaluation_session_id: impl Into<String>,
    shadow_campaign: &ShadowCampaign,
    incumbent_input_refs: &[String],
    challenger_input_refs: &[String],
    challenger_capability_envelope_refs: Vec<CapabilityEnvelopeId>,
) -> Result<ChallengerEvaluationSession, ShadowEvaluationError> {
    if challenger_capability_envelope_refs.is_empty() {
        return Err(ShadowEvaluationError::MissingCapabilityEnvelopeRefs);
    }

    let incumbent_only_refs = set_diff(incumbent_input_refs, challenger_input_refs);
    let challenger_only_refs = set_diff(challenger_input_refs, incumbent_input_refs);
    if !incumbent_only_refs.is_empty() || !challenger_only_refs.is_empty() {
        return Err(ShadowEvaluationError::SharedInputMismatch {
            incumbent_only_refs,
            challenger_only_refs,
        });
    }

    Ok(ChallengerEvaluationSession {
        evaluation_session_id: evaluation_session_id.into(),
        shadow_campaign_id: shadow_campaign.shadow_campaign_id.clone(),
        incumbent_session_ref: shadow_campaign.incumbent_session_ref.clone(),
        challenger_session_ref: shadow_campaign.challenger_session_ref.clone(),
        shared_input_refs: challenger_input_refs.to_vec(),
        challenger_capability_envelope_refs,
        latest_challenger_checkpoint_ref: shadow_campaign.challenger_checkpoint_ref.clone(),
        no_live_mutation: shadow_campaign.no_live_mutation,
    })
}

pub fn validate_shadow_dispatch(
    evaluation_session: &ChallengerEvaluationSession,
    dispatch: &WorkerDispatch,
    capability_envelope: &CapabilityEnvelope,
) -> Result<(), ShadowEvaluationError> {
    if !evaluation_session.no_live_mutation {
        return Ok(());
    }

    if capability_envelope.grants_world(&CapabilityWorld::WorkspaceMutate) {
        return Err(ShadowEvaluationError::LiveMutationForbidden {
            operation: "workspace-mutate world is not allowed in shadow evaluation".to_string(),
        });
    }

    if let Some(request) = dispatch
        .requested_capabilities
        .iter()
        .find(|request| request.world == CapabilityWorld::WorkspaceMutate)
    {
        return Err(ShadowEvaluationError::LiveMutationForbidden {
            operation: request.operation.clone(),
        });
    }

    Ok(())
}

pub fn build_native_sufficiency_evidence(
    evidence_id: impl Into<String>,
    target: CapabilityImportTarget,
    achieved_tier: NativeReplacementTier,
    artifact_refs: Vec<String>,
    checkpoint_refs: Vec<String>,
    audit_refs: Vec<String>,
    summary: impl Into<String>,
    complete: bool,
) -> NativeSufficiencyEvidence {
    NativeSufficiencyEvidence {
        evidence_id: evidence_id.into(),
        target,
        achieved_tier,
        artifact_refs,
        checkpoint_refs,
        audit_refs,
        summary: summary.into(),
        complete,
    }
}

pub fn compare_challenger_outputs(
    comparison_id: impl Into<String>,
    incumbent_ref: impl Into<String>,
    challenger_ref: impl Into<String>,
    shared_input_refs: Vec<String>,
    incumbent_output_refs: Vec<String>,
    challenger_output_refs: Vec<String>,
    dimension_scores: Vec<EvaluationDimensionScore>,
    summary: impl Into<String>,
) -> Result<GenerationComparisonRecord, ShadowEvaluationError> {
    if shared_input_refs.is_empty() {
        return Err(ShadowEvaluationError::MissingSharedInputs);
    }
    ensure_critical_dimensions(&dimension_scores)?;

    let matched = !dimension_scores.iter().any(|score| {
        required_evaluation_dimensions().contains(&score.dimension)
            && verdict_blocks_promotion(score.verdict)
    });

    Ok(GenerationComparisonRecord {
        comparison_id: comparison_id.into(),
        target: CapabilityImportTarget::NativeSupervisorChallenger,
        replacement_tier: NativeReplacementTier::NativeSupervisorChallengers,
        incumbent_ref: incumbent_ref.into(),
        challenger_ref: challenger_ref.into(),
        shared_input_refs,
        imported_provider: ProviderKind::Imported,
        native_provider: ProviderKind::Native,
        imported_output_refs: incumbent_output_refs,
        native_output_refs: challenger_output_refs,
        dimension_scores,
        matched,
        summary: summary.into(),
    })
}

pub fn compare_successor_loop_outputs(
    comparison_id: impl Into<String>,
    promoted_incumbent_ref: impl Into<String>,
    successor_candidate_ref: impl Into<String>,
    shared_input_refs: Vec<String>,
    promoted_output_refs: Vec<String>,
    successor_output_refs: Vec<String>,
    dimension_scores: Vec<EvaluationDimensionScore>,
    summary: impl Into<String>,
) -> Result<GenerationComparisonRecord, ShadowEvaluationError> {
    if shared_input_refs.is_empty() {
        return Err(ShadowEvaluationError::MissingSharedInputs);
    }
    ensure_critical_dimensions(&dimension_scores)?;

    let matched = !dimension_scores.iter().any(|score| {
        required_evaluation_dimensions().contains(&score.dimension)
            && verdict_blocks_promotion(score.verdict)
    });

    Ok(GenerationComparisonRecord {
        comparison_id: comparison_id.into(),
        target: CapabilityImportTarget::NativeSupervisorChallenger,
        replacement_tier: NativeReplacementTier::BoundedSelfHostingLoop,
        incumbent_ref: promoted_incumbent_ref.into(),
        challenger_ref: successor_candidate_ref.into(),
        shared_input_refs,
        imported_provider: ProviderKind::Native,
        native_provider: ProviderKind::Native,
        imported_output_refs: promoted_output_refs,
        native_output_refs: successor_output_refs,
        dimension_scores,
        matched,
        summary: summary.into(),
    })
}

pub fn imported_transcript_retrieval_from_store(
    store: &DurableArtifactStore,
    query: &TranscriptSliceQuery,
) -> Result<Vec<TranscriptSlice>, String> {
    let runtime_state = store
        .load_runtime_state()
        .map_err(|error| error.to_string())?;
    Ok(runtime_state
        .memory_store
        .retrieve_transcript_slices(query)
        .into_iter()
        .cloned()
        .collect())
}

pub fn native_transcript_retrieval_from_memory(
    memory_store: &MemoryStore,
    query: &TranscriptSliceQuery,
) -> Vec<TranscriptSlice> {
    memory_store
        .retrieve_transcript_slices(query)
        .into_iter()
        .cloned()
        .collect()
}

pub fn compare_transcript_retrieval(
    imported: &[TranscriptSlice],
    native: &[TranscriptSlice],
) -> GenerationComparisonRecord {
    let imported_output_refs = imported
        .iter()
        .map(|slice| slice.slice_id.clone())
        .collect::<Vec<_>>();
    let native_output_refs = native
        .iter()
        .map(|slice| slice.slice_id.clone())
        .collect::<Vec<_>>();
    let matched = imported_output_refs == native_output_refs;

    GenerationComparisonRecord {
        comparison_id: "comparison-transcript-retrieval".to_string(),
        target: CapabilityImportTarget::TranscriptRetrieval,
        replacement_tier: NativeReplacementTier::NativeCapabilitySurfaces,
        incumbent_ref: "imported-transcript-retrieval".to_string(),
        challenger_ref: "native-transcript-retrieval".to_string(),
        shared_input_refs: Vec::new(),
        imported_provider: ProviderKind::Imported,
        native_provider: ProviderKind::Native,
        imported_output_refs,
        native_output_refs,
        dimension_scores: vec![EvaluationDimensionScore {
            dimension: EvaluationDimension::Replayability,
            verdict: if matched {
                DimensionVerdict::Equivalent
            } else {
                DimensionVerdict::ChallengerWorse
            },
            incumbent_summary: "imported transcript retrieval results".to_string(),
            challenger_summary: "native transcript retrieval results".to_string(),
        }],
        matched,
        summary: if matched {
            "native transcript retrieval matched imported retrieval".to_string()
        } else {
            "native transcript retrieval diverged from imported retrieval".to_string()
        },
    }
}

pub fn evaluate_native_sufficiency(
    gate: &NativeSufficiencyGate,
    comparison: &GenerationComparisonRecord,
) -> bool {
    gate.target == comparison.target
        && comparison.replacement_tier >= gate.required_tier
        && (!gate.requires_exact_match || comparison.matched)
}

pub fn evaluate_native_sufficiency_with_evidence(
    gate: &NativeSufficiencyGate,
    comparison: &GenerationComparisonRecord,
    evidence: &NativeSufficiencyEvidence,
) -> bool {
    gate.target == comparison.target
        && gate.target == evidence.target
        && evidence.complete
        && !evidence.artifact_refs.is_empty()
        && !evidence.checkpoint_refs.is_empty()
        && !evidence.audit_refs.is_empty()
        && evidence.achieved_tier >= gate.required_tier
        && (!gate.requires_exact_match || comparison.matched)
}

#[cfg(test)]
mod tests {
    use crate::execution::capability::{
        ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityWorld, CapabilityWorldGrant,
        IsolationProfile,
    };
    use crate::execution::memory::{
        MemoryScope, MemoryStore, PointerIndex, TranscriptSlice, TranscriptSliceQuery,
    };
    use crate::execution::storage::{DurableArtifactStore, ReplayableRuntimeState};
    use crate::execution::worker::{
        CapabilityOperationRequest, MessageArtifact, MessageArtifactClass, MessageArtifactStatus,
        WorkerDispatch,
    };
    use crate::execution::{
        ActorKind, ExecutionSession, ExecutionSessionHeader, TaskArtifact, TaskGraph, TickSource,
    };
    use serde_json::json;
    use std::env;
    use std::fs;
    use std::process;

    use super::{
        ArtifactFlowError, CapabilityClosureEntry, CapabilityClosureStatus,
        CapabilityDependencyMode, CapabilityImportTarget, ChallengerEvaluationSession,
        DimensionVerdict, EvaluationDimension, EvaluationDimensionScore, NativeReplacementTier,
        NativeSufficiencyGate, ProviderKind, ShadowCampaign, ShadowCampaignStatus,
        ShadowEvaluationError, build_closure_inventory, build_native_sufficiency_evidence,
        build_successor_genome, closure_inventory_has_hidden_imports,
        closure_inventory_is_complete, compare_challenger_outputs, compare_successor_loop_outputs,
        compare_transcript_retrieval, evaluate_native_sufficiency,
        evaluate_native_sufficiency_with_evidence, imported_transcript_retrieval_from_store,
        materialize_successor_phenotype, native_transcript_retrieval_from_memory,
        open_challenger_evaluation_session, open_shadow_campaign, validate_semantic_phenotype,
        validate_shadow_dispatch,
    };

    fn temp_store_root(name: &str) -> std::path::PathBuf {
        env::temp_dir().join(format!("rc03-aiaf-replacement-{name}-{}", process::id()))
    }

    fn full_closure_inventory_entries() -> Vec<CapabilityClosureEntry> {
        vec![
            CapabilityClosureEntry {
                target: CapabilityImportTarget::TranscriptRetrieval,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:memory-access".to_string()),
                audit_ref: Some("audit-memory-access".to_string()),
                rationale: "skeptical transcript retrieval is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::CampaignControl,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:campaign-control".to_string()),
                audit_ref: Some("audit-campaign-control".to_string()),
                rationale: "campaign control is native in v1.2".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ApprovalGateway,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:approval-gateway".to_string()),
                audit_ref: Some("audit-approval-gateway".to_string()),
                rationale: "approval gateway is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ReviewPromotion,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:review-promotion".to_string()),
                audit_ref: Some("audit-review-promotion".to_string()),
                rationale: "review and promotion flow is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ScheduleTick,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:schedule-tick".to_string()),
                audit_ref: Some("audit-schedule-tick".to_string()),
                rationale: "schedule tick handling is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ModelHosting,
                current_mode: CapabilityDependencyMode::ImportedBaseline,
                closure_status: CapabilityClosureStatus::CarriedImportApproved,
                capability_world_ref: Some("world:model-hosting-adapter".to_string()),
                audit_ref: Some("audit-model-hosting".to_string()),
                rationale: "model hosting remains explicit and governed in v1.2".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::WorktreeHostAdapter,
                current_mode: CapabilityDependencyMode::ImportedBaseline,
                closure_status: CapabilityClosureStatus::CarriedImportApproved,
                capability_world_ref: Some("world:worktree-host-adapter".to_string()),
                audit_ref: Some("audit-worktree-host-adapter".to_string()),
                rationale: "worktree host access remains an explicit carried import".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::EnvironmentBridge,
                current_mode: CapabilityDependencyMode::ImportedBaseline,
                closure_status: CapabilityClosureStatus::CarriedImportApproved,
                capability_world_ref: Some("world:environment-bridge".to_string()),
                audit_ref: Some("audit-environment-bridge".to_string()),
                rationale: "environment bridging remains explicit and governed".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::SemanticValidation,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:semantic-validation".to_string()),
                audit_ref: Some("audit-semantic-validation".to_string()),
                rationale: "semantic validation is native and replayable".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ArtifactPackaging,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:artifact-packaging".to_string()),
                audit_ref: Some("audit-artifact-packaging".to_string()),
                rationale: "artifact packaging remains inside the bounded substrate".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::NativeSupervisorChallenger,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:native-supervisor-challenger".to_string()),
                audit_ref: Some("audit-native-supervisor-challenger".to_string()),
                rationale: "native supervisor challenger evaluation is closed".to_string(),
            },
        ]
    }

    #[test]
    fn native_replacement_sufficiency_accepts_matching_results() {
        let imported = vec![TranscriptSlice {
            slice_id: "slice-1".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            session_id: Some("session-1".to_string()),
            task_id: Some("task-1".to_string()),
            referenced_artifacts: vec!["artifact-1".to_string()],
            summary: "slice".to_string(),
            excerpts: vec!["line".to_string()],
        }];
        let native = imported.clone();

        let comparison = compare_transcript_retrieval(&imported, &native);
        let gate = NativeSufficiencyGate {
            target: CapabilityImportTarget::TranscriptRetrieval,
            required_tier: NativeReplacementTier::NativeCapabilitySurfaces,
            requires_exact_match: true,
        };
        let evidence = build_native_sufficiency_evidence(
            "evidence-1",
            CapabilityImportTarget::TranscriptRetrieval,
            NativeReplacementTier::NativeCapabilitySurfaces,
            vec!["slice-1".to_string()],
            vec!["checkpoint-1".to_string()],
            vec!["audit-1".to_string()],
            "transcript retrieval parity evidence",
            true,
        );

        assert!(comparison.matched);
        assert!(evaluate_native_sufficiency(&gate, &comparison));
        assert!(evaluate_native_sufficiency_with_evidence(
            &gate,
            &comparison,
            &evidence
        ));

        let evidence_without_audits = build_native_sufficiency_evidence(
            "evidence-2",
            CapabilityImportTarget::TranscriptRetrieval,
            NativeReplacementTier::NativeCapabilitySurfaces,
            vec!["slice-1".to_string()],
            vec!["checkpoint-1".to_string()],
            Vec::new(),
            "transcript retrieval evidence without audit support",
            true,
        );

        assert!(!evaluate_native_sufficiency_with_evidence(
            &gate,
            &comparison,
            &evidence_without_audits
        ));
    }

    #[test]
    fn imported_and_native_transcript_retrieval_can_be_compared_from_durable_state() {
        let root = temp_store_root("compare");
        let _ = fs::remove_dir_all(&root);
        let store = DurableArtifactStore::bootstrap(&root).unwrap();

        let session = ExecutionSession::new(ExecutionSessionHeader {
            session_id: "session-1".to_string(),
            actor_kind: ActorKind::Supervisor,
            actor_id: "supervisor-alpha".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            capability_envelope_ref: "envelope-1".to_string(),
            parent_session_id: None,
        });
        let task = TaskArtifact::new("task-1", "Compare imported and native transcript retrieval");
        let task_graph = TaskGraph::new("task-1", Vec::new());
        let mut memory_store = MemoryStore::default();
        memory_store.insert_pointer_index(PointerIndex {
            index_id: "pointer-index-1".to_string(),
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            entry_refs: vec!["slice-1".to_string()],
            contested_refs: Vec::new(),
            critical_refs: vec!["slice-1".to_string()],
            governance_constraints: vec!["bounded replay".to_string()],
            open_task_refs: vec!["task-1".to_string()],
            updated_at: "t0".to_string(),
        });
        memory_store.add_transcript_slice(TranscriptSlice {
            slice_id: "slice-1".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            session_id: Some("session-1".to_string()),
            task_id: Some("task-1".to_string()),
            referenced_artifacts: vec!["artifact-1".to_string()],
            summary: "slice".to_string(),
            excerpts: vec!["line".to_string()],
        });
        store
            .persist_runtime_state(&ReplayableRuntimeState::new(
                session,
                task,
                task_graph,
                memory_store.clone(),
                None,
                Vec::new(),
            ))
            .unwrap();

        let query = TranscriptSliceQuery {
            campaign_id: Some("campaign-1".to_string()),
            task_id: Some("task-1".to_string()),
            ..TranscriptSliceQuery::default()
        };

        let imported = imported_transcript_retrieval_from_store(&store, &query).unwrap();
        let native = native_transcript_retrieval_from_memory(&memory_store, &query);
        let comparison = compare_transcript_retrieval(&imported, &native);

        assert!(comparison.matched, "{}", json!(comparison).to_string());
    }

    #[test]
    fn shadow_campaign_requires_same_inputs() {
        let shadow_campaign = open_shadow_campaign(
            "shadow-1",
            "campaign-1",
            "session-incumbent",
            "session-challenger",
            vec!["input-a".to_string()],
            vec![TickSource::ScheduledTimer],
            vec![
                CapabilityImportTarget::CampaignControl,
                CapabilityImportTarget::ApprovalGateway,
                CapabilityImportTarget::ReviewPromotion,
            ],
            true,
            "rollback-1",
        )
        .unwrap();

        let error = open_challenger_evaluation_session(
            "evaluation-1",
            &shadow_campaign,
            &["input-a".to_string()],
            &["input-b".to_string()],
            vec!["envelope-1".to_string()],
        )
        .unwrap_err();

        assert_eq!(
            error,
            ShadowEvaluationError::SharedInputMismatch {
                incumbent_only_refs: vec!["input-a".to_string()],
                challenger_only_refs: vec!["input-b".to_string()],
            }
        );
    }

    #[test]
    fn shadow_dispatch_forbids_workspace_mutation() {
        let shadow_campaign = ShadowCampaign {
            shadow_campaign_id: "shadow-1".to_string(),
            campaign_id: "campaign-1".to_string(),
            incumbent_session_ref: "session-incumbent".to_string(),
            challenger_session_ref: "session-challenger".to_string(),
            shared_input_refs: vec!["input-a".to_string()],
            incumbent_checkpoint_ref: None,
            challenger_checkpoint_ref: None,
            allowed_tick_sources: vec![TickSource::ScheduledTimer],
            native_control_targets: vec![
                CapabilityImportTarget::CampaignControl,
                CapabilityImportTarget::ApprovalGateway,
                CapabilityImportTarget::ReviewPromotion,
            ],
            no_live_mutation: true,
            rollback_handle_ref: "rollback-1".to_string(),
            status: ShadowCampaignStatus::Prepared,
        };
        let evaluation_session = ChallengerEvaluationSession {
            evaluation_session_id: "evaluation-1".to_string(),
            shadow_campaign_id: shadow_campaign.shadow_campaign_id.clone(),
            incumbent_session_ref: shadow_campaign.incumbent_session_ref.clone(),
            challenger_session_ref: shadow_campaign.challenger_session_ref.clone(),
            shared_input_refs: shadow_campaign.shared_input_refs.clone(),
            challenger_capability_envelope_refs: vec!["envelope-1".to_string()],
            latest_challenger_checkpoint_ref: None,
            no_live_mutation: true,
        };
        let dispatch = WorkerDispatch {
            dispatch_id: "dispatch-1".to_string(),
            task_id: "task-1".to_string(),
            parent_session_id: "session-challenger".to_string(),
            worker_id: "worker-1".to_string(),
            worker_task_ref: "worker-task-1".to_string(),
            capability_envelope_ref: "envelope-1".to_string(),
            requested_capabilities: vec![CapabilityOperationRequest {
                world: CapabilityWorld::WorkspaceMutate,
                operation: "write-file".to_string(),
                resource_scope: "workspace-root".to_string(),
            }],
            dispatch_message: MessageArtifact {
                message_id: "message-1".to_string(),
                campaign_id: "campaign-1".to_string(),
                epoch_id: "epoch-1".to_string(),
                task_id: "task-1".to_string(),
                sender_actor_ref: "session-challenger".to_string(),
                receiver_actor_ref: "worker-1".to_string(),
                message_class: MessageArtifactClass::DispatchMessage,
                payload_summary: "mutate workspace".to_string(),
                referenced_artifacts: vec!["input-a".to_string()],
                status: MessageArtifactStatus::Sent,
            },
        };
        let envelope = CapabilityEnvelope {
            envelope_id: "envelope-1".to_string(),
            actor_scope: "worker-1".to_string(),
            world_grants: vec![CapabilityWorldGrant {
                world: CapabilityWorld::WorkspaceObserve,
                allowed_operations: vec!["search".to_string()],
                default_authority_class: AuthorityClass::Observe,
                default_approval_class: ApprovalClass::AutoAllowed,
                operation_approval_overrides: Vec::new(),
            }],
            authority_ceiling: AuthorityClass::Observe,
            isolation_profile: IsolationProfile::ReadOnlyInspect,
            allowed_resource_scopes: vec!["workspace-root".to_string()],
            approval_overrides: Vec::new(),
            quota_policy: None,
            campaign_scope: Some("campaign-1".to_string()),
            epoch_scope: Some("epoch-1".to_string()),
        };

        let error =
            validate_shadow_dispatch(&evaluation_session, &dispatch, &envelope).unwrap_err();
        assert_eq!(
            error,
            ShadowEvaluationError::LiveMutationForbidden {
                operation: "write-file".to_string()
            }
        );
    }

    #[test]
    fn challenger_comparison_requires_critical_dimensions() {
        let error = compare_challenger_outputs(
            "comparison-1",
            "incumbent",
            "challenger",
            vec!["input-a".to_string()],
            vec!["inc-output".to_string()],
            vec!["challenger-output".to_string()],
            vec![EvaluationDimensionScore {
                dimension: EvaluationDimension::OperatorBurden,
                verdict: DimensionVerdict::ChallengerBetter,
                incumbent_summary: "manual stitching".to_string(),
                challenger_summary: "native coordination".to_string(),
            }],
            "insufficient comparison",
        )
        .unwrap_err();

        assert_eq!(
            error,
            ShadowEvaluationError::MissingCriticalDimension {
                dimension: EvaluationDimension::SemanticCorrectness
            }
        );
    }

    #[test]
    fn successor_loop_comparison_reaches_bounded_self_hosting_tier() {
        let comparison = compare_successor_loop_outputs(
            "comparison-loop-1",
            "session-promoted-incumbent",
            "successor-candidate-1",
            vec!["shared-input-1".to_string()],
            vec!["promoted-output-1".to_string()],
            vec!["successor-output-1".to_string()],
            vec![
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::SemanticCorrectness,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "promoted incumbent remained correct".to_string(),
                    challenger_summary: "successor candidate remained correct".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::GovernanceFidelity,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "promoted incumbent stayed governed".to_string(),
                    challenger_summary: "successor candidate stayed governed".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::Replayability,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "promoted incumbent replayed".to_string(),
                    challenger_summary: "successor candidate replayed".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::OperatorBurden,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "operator review stayed bounded".to_string(),
                    challenger_summary: "operator review stayed bounded".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::BoundaryCost,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "worker boundary cost stayed bounded".to_string(),
                    challenger_summary: "worker boundary cost stayed bounded".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::ReplacementSafety,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "promotion remained reversible".to_string(),
                    challenger_summary: "successor remained bounded".to_string(),
                },
            ],
            "bounded self-hosting loop entry comparison",
        )
        .unwrap();

        assert_eq!(
            comparison.replacement_tier,
            NativeReplacementTier::BoundedSelfHostingLoop
        );
        assert_eq!(comparison.imported_provider, ProviderKind::Native);
        assert_eq!(comparison.native_provider, ProviderKind::Native);
    }

    #[test]
    fn closure_inventory_allows_explicit_carried_imports_without_hidden_deps() {
        let inventory = build_closure_inventory(
            "closure-1",
            full_closure_inventory_entries(),
            Vec::new(),
            "bounded v1 closure inventory",
        );

        assert!(!closure_inventory_has_hidden_imports(&inventory));
        assert!(closure_inventory_is_complete(&inventory));
    }

    #[test]
    fn closure_inventory_rejects_duplicate_audit_refs() {
        let mut entries = full_closure_inventory_entries();
        entries[0].audit_ref = Some("audit-shared".to_string());
        entries[1].audit_ref = Some("audit-shared".to_string());

        let inventory = build_closure_inventory(
            "closure-duplicate-audits",
            entries,
            Vec::new(),
            "duplicate audit refs should fail explicit service accounting",
        );

        assert!(!closure_inventory_is_complete(&inventory));
    }

    #[test]
    fn successor_artifact_flow_requires_stable_interface_alignment() {
        let genome = build_successor_genome(
            "genome-1",
            "session-promoted-incumbent",
            "package:aiaf/supervisor@v1",
            "typed-dag:successor-1",
            vec!["policy:bounded".to_string()],
            "second-cycle successor genome",
        )
        .unwrap();

        let phenotype = materialize_successor_phenotype(
            "artifact-1",
            &genome,
            "package:aiaf/supervisor@v1",
            "component:artifact-1",
            vec!["wit:supervisor".to_string()],
            vec!["artifact-output-1".to_string()],
            "second-cycle successor phenotype",
        )
        .unwrap();

        let validation = validate_semantic_phenotype(
            "validation-1",
            &genome,
            &phenotype,
            vec!["validator:semantic-check".to_string()],
            vec!["evidence:semantic-check-1".to_string()],
            "semantic validation passed",
        )
        .unwrap();

        assert!(validation.passed);
        assert_eq!(
            validation.stable_interface_ref,
            "package:aiaf/supervisor@v1"
        );

        let error = materialize_successor_phenotype(
            "artifact-bad",
            &genome,
            "package:aiaf/supervisor@v2",
            "component:artifact-bad",
            vec!["wit:supervisor".to_string()],
            vec!["artifact-output-bad".to_string()],
            "bad phenotype",
        )
        .unwrap_err();

        assert_eq!(
            error,
            ArtifactFlowError::InterfaceMismatch {
                expected: "package:aiaf/supervisor@v1".to_string(),
                actual: "package:aiaf/supervisor@v2".to_string(),
            }
        );
    }
}
