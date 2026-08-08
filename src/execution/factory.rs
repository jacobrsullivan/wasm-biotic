use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryComparisonDimension {
    SemanticCorrectness,
    ShellFidelity,
    GovernanceFidelity,
    Replayability,
    OperatorBurden,
    ContinuityQuality,
    ServiceClosureQuality,
    ReplacementSafety,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryDimensionVerdict {
    ChallengerBetter,
    Equivalent,
    ChallengerWorse,
    RequiresReview,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryComparisonOutcome {
    RetainIncumbent,
    AdoptChallenger,
    RequiresReview,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryGenomeArtifact {
    pub factory_genome_id: String,
    pub parent_factory_ref: Option<String>,
    pub stable_contract_refs: Vec<String>,
    pub worker_topology_refs: Vec<String>,
    pub service_closure_refs: Vec<String>,
    pub governance_policy_refs: Vec<String>,
    pub shell_profile_refs: Vec<String>,
    pub summary: String,
}

impl FactoryGenomeArtifact {
    pub fn validate(&self) -> Result<(), FactoryArtifactError> {
        if self.factory_genome_id.trim().is_empty() {
            return Err(FactoryArtifactError::MissingFactoryGenomeId);
        }
        validate_ref_list(
            &self.stable_contract_refs,
            FactoryArtifactError::MissingStableContractRefs,
        )?;
        validate_ref_list(
            &self.worker_topology_refs,
            FactoryArtifactError::MissingWorkerTopologyRefs,
        )?;
        validate_ref_list(
            &self.service_closure_refs,
            FactoryArtifactError::MissingServiceClosureRefs,
        )?;
        validate_ref_list(
            &self.governance_policy_refs,
            FactoryArtifactError::MissingGovernancePolicyRefs,
        )?;
        validate_ref_list(
            &self.shell_profile_refs,
            FactoryArtifactError::MissingShellProfileRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryArtifactError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryPhenotypeArtifact {
    pub factory_phenotype_id: String,
    pub factory_genome_ref: String,
    pub package_refs: Vec<String>,
    pub entrypoint_refs: Vec<String>,
    pub boundary_refs: Vec<String>,
    pub validation_profile_refs: Vec<String>,
    pub summary: String,
}

impl FactoryPhenotypeArtifact {
    pub fn validate(&self) -> Result<(), FactoryArtifactError> {
        if self.factory_phenotype_id.trim().is_empty() {
            return Err(FactoryArtifactError::MissingFactoryPhenotypeId);
        }
        if self.factory_genome_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingFactoryGenomeRef);
        }
        validate_ref_list(&self.package_refs, FactoryArtifactError::MissingPackageRefs)?;
        validate_ref_list(
            &self.entrypoint_refs,
            FactoryArtifactError::MissingEntrypointRefs,
        )?;
        validate_ref_list(
            &self.boundary_refs,
            FactoryArtifactError::MissingBoundaryRefs,
        )?;
        validate_ref_list(
            &self.validation_profile_refs,
            FactoryArtifactError::MissingValidationProfileRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryArtifactError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryLineageRecord {
    pub lineage_id: String,
    pub factory_genome_ref: String,
    pub ancestor_refs: Vec<String>,
    pub preserved_constraint_refs: Vec<String>,
    pub claim_boundary: String,
}

impl FactoryLineageRecord {
    pub fn validate(&self) -> Result<(), FactoryArtifactError> {
        if self.lineage_id.trim().is_empty() {
            return Err(FactoryArtifactError::MissingLineageId);
        }
        if self.factory_genome_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingFactoryGenomeRef);
        }
        validate_ref_list(
            &self.ancestor_refs,
            FactoryArtifactError::MissingAncestorRefs,
        )?;
        validate_ref_list(
            &self.preserved_constraint_refs,
            FactoryArtifactError::MissingPreservedConstraintRefs,
        )?;
        if self.claim_boundary.trim().is_empty() {
            return Err(FactoryArtifactError::MissingClaimBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryDimensionScore {
    pub dimension: FactoryComparisonDimension,
    pub verdict: FactoryDimensionVerdict,
    pub incumbent_summary: String,
    pub challenger_summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryComparisonRecord {
    pub comparison_id: String,
    pub incumbent_factory_ref: String,
    pub challenger_factory_ref: String,
    pub dimension_scores: Vec<FactoryDimensionScore>,
    pub shared_input_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub outcome: FactoryComparisonOutcome,
    pub summary: String,
}

impl FactoryComparisonRecord {
    pub fn validate(&self) -> Result<(), FactoryArtifactError> {
        if self.comparison_id.trim().is_empty() {
            return Err(FactoryArtifactError::MissingComparisonId);
        }
        if self.incumbent_factory_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingIncumbentFactoryRef);
        }
        if self.challenger_factory_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingChallengerFactoryRef);
        }
        if self.incumbent_factory_ref == self.challenger_factory_ref {
            return Err(FactoryArtifactError::FactoryComparisonRequiresDistinctFactories);
        }
        if self.dimension_scores.is_empty() {
            return Err(FactoryArtifactError::MissingComparisonDimensions);
        }
        validate_ref_list(
            &self.shared_input_refs,
            FactoryArtifactError::MissingSharedInputRefs,
        )?;
        validate_ref_list(
            &self.evidence_refs,
            FactoryArtifactError::MissingEvidenceRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryArtifactError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryActivationBundle {
    pub activation_id: String,
    pub comparison_ref: String,
    pub adopted_factory_ref: String,
    pub retained_incumbent_ref: String,
    pub observation_window_ref: String,
    pub rollback_handle_ref: String,
}

impl FactoryActivationBundle {
    pub fn validate(&self) -> Result<(), FactoryArtifactError> {
        if self.activation_id.trim().is_empty() {
            return Err(FactoryArtifactError::MissingActivationId);
        }
        if self.comparison_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingComparisonRef);
        }
        if self.adopted_factory_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingAdoptedFactoryRef);
        }
        if self.retained_incumbent_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingRetainedIncumbentRef);
        }
        if self.adopted_factory_ref == self.retained_incumbent_ref {
            return Err(FactoryArtifactError::ActivationRequiresDistinctFactories);
        }
        if self.observation_window_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingObservationWindowRef);
        }
        if self.rollback_handle_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingRollbackHandleRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryEvidencePacket {
    pub packet_id: String,
    pub genome_ref: String,
    pub phenotype_ref: String,
    pub lineage_ref: String,
    pub comparison_ref: String,
    pub activation_ref: String,
    pub rollback_ref: String,
    pub claim_boundary: String,
}

impl FactoryEvidencePacket {
    pub fn validate(&self) -> Result<(), FactoryArtifactError> {
        if self.packet_id.trim().is_empty() {
            return Err(FactoryArtifactError::MissingPacketId);
        }
        if self.genome_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingFactoryGenomeRef);
        }
        if self.phenotype_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingFactoryPhenotypeRef);
        }
        if self.lineage_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingLineageRef);
        }
        if self.comparison_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingComparisonRef);
        }
        if self.activation_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingActivationRef);
        }
        if self.rollback_ref.trim().is_empty() {
            return Err(FactoryArtifactError::MissingRollbackRef);
        }
        if self.claim_boundary.trim().is_empty() {
            return Err(FactoryArtifactError::MissingClaimBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactoryArtifactError {
    MissingFactoryGenomeId,
    MissingFactoryPhenotypeId,
    MissingLineageId,
    MissingPacketId,
    MissingComparisonId,
    MissingActivationId,
    MissingFactoryGenomeRef,
    MissingFactoryPhenotypeRef,
    MissingLineageRef,
    MissingComparisonRef,
    MissingActivationRef,
    MissingRollbackRef,
    MissingAdoptedFactoryRef,
    MissingRetainedIncumbentRef,
    MissingIncumbentFactoryRef,
    MissingChallengerFactoryRef,
    MissingStableContractRefs,
    MissingWorkerTopologyRefs,
    MissingServiceClosureRefs,
    MissingGovernancePolicyRefs,
    MissingShellProfileRefs,
    MissingPackageRefs,
    MissingEntrypointRefs,
    MissingBoundaryRefs,
    MissingValidationProfileRefs,
    MissingAncestorRefs,
    MissingPreservedConstraintRefs,
    MissingComparisonDimensions,
    MissingSharedInputRefs,
    MissingEvidenceRefs,
    MissingObservationWindowRef,
    MissingRollbackHandleRef,
    MissingClaimBoundary,
    MissingSummary,
    FactoryComparisonRequiresDistinctFactories,
    ActivationRequiresDistinctFactories,
}

impl Display for FactoryArtifactError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingFactoryGenomeId => write!(f, "factory genome requires a genome id"),
            Self::MissingFactoryPhenotypeId => {
                write!(f, "factory phenotype requires a phenotype id")
            }
            Self::MissingLineageId => write!(f, "factory lineage requires a lineage id"),
            Self::MissingPacketId => write!(f, "factory evidence packet requires a packet id"),
            Self::MissingComparisonId => write!(f, "factory comparison requires a comparison id"),
            Self::MissingActivationId => write!(f, "factory activation requires an activation id"),
            Self::MissingFactoryGenomeRef => write!(f, "factory artifact requires a genome ref"),
            Self::MissingFactoryPhenotypeRef => {
                write!(f, "factory evidence packet requires a phenotype ref")
            }
            Self::MissingLineageRef => write!(f, "factory evidence packet requires a lineage ref"),
            Self::MissingComparisonRef => {
                write!(f, "factory artifact requires a comparison ref")
            }
            Self::MissingActivationRef => {
                write!(f, "factory evidence packet requires an activation ref")
            }
            Self::MissingRollbackRef => {
                write!(f, "factory evidence packet requires a rollback ref")
            }
            Self::MissingAdoptedFactoryRef => {
                write!(f, "factory activation requires an adopted factory ref")
            }
            Self::MissingRetainedIncumbentRef => {
                write!(f, "factory activation requires a retained incumbent ref")
            }
            Self::MissingIncumbentFactoryRef => {
                write!(f, "factory comparison requires an incumbent factory ref")
            }
            Self::MissingChallengerFactoryRef => {
                write!(f, "factory comparison requires a challenger factory ref")
            }
            Self::MissingStableContractRefs => {
                write!(f, "factory genome requires stable contract refs")
            }
            Self::MissingWorkerTopologyRefs => {
                write!(f, "factory genome requires worker topology refs")
            }
            Self::MissingServiceClosureRefs => {
                write!(f, "factory genome requires service closure refs")
            }
            Self::MissingGovernancePolicyRefs => {
                write!(f, "factory genome requires governance policy refs")
            }
            Self::MissingShellProfileRefs => {
                write!(f, "factory genome requires shell profile refs")
            }
            Self::MissingPackageRefs => write!(f, "factory phenotype requires package refs"),
            Self::MissingEntrypointRefs => {
                write!(f, "factory phenotype requires entrypoint refs")
            }
            Self::MissingBoundaryRefs => write!(f, "factory phenotype requires boundary refs"),
            Self::MissingValidationProfileRefs => {
                write!(f, "factory phenotype requires validation profile refs")
            }
            Self::MissingAncestorRefs => write!(f, "factory lineage requires ancestor refs"),
            Self::MissingPreservedConstraintRefs => {
                write!(f, "factory lineage requires preserved constraint refs")
            }
            Self::MissingComparisonDimensions => {
                write!(f, "factory comparison requires dimension scores")
            }
            Self::MissingSharedInputRefs => {
                write!(f, "factory comparison requires shared input refs")
            }
            Self::MissingEvidenceRefs => write!(f, "factory artifact requires evidence refs"),
            Self::MissingObservationWindowRef => {
                write!(f, "factory activation requires an observation window ref")
            }
            Self::MissingRollbackHandleRef => {
                write!(f, "factory activation requires a rollback handle ref")
            }
            Self::MissingClaimBoundary => write!(f, "factory artifact requires a claim boundary"),
            Self::MissingSummary => write!(f, "factory artifact requires a summary"),
            Self::FactoryComparisonRequiresDistinctFactories => write!(
                f,
                "factory comparison requires distinct incumbent and challenger refs"
            ),
            Self::ActivationRequiresDistinctFactories => {
                write!(
                    f,
                    "factory activation requires distinct adopted and retained factory refs"
                )
            }
        }
    }
}

impl Error for FactoryArtifactError {}

fn validate_ref_list(
    refs: &[String],
    error: FactoryArtifactError,
) -> Result<(), FactoryArtifactError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_artifacts_require_explicit_refs() {
        let genome = FactoryGenomeArtifact {
            factory_genome_id: "factory-genome-1".to_string(),
            parent_factory_ref: None,
            stable_contract_refs: vec!["contract:v1".to_string()],
            worker_topology_refs: vec!["worker:supervisor".to_string()],
            service_closure_refs: vec!["service:memory".to_string()],
            governance_policy_refs: vec!["policy:rollback".to_string()],
            shell_profile_refs: vec!["shell:v4".to_string()],
            summary: "factory genome".to_string(),
        };
        genome.validate().unwrap();

        let mut invalid = genome.clone();
        invalid.shell_profile_refs.clear();
        assert_eq!(
            invalid.validate().unwrap_err(),
            FactoryArtifactError::MissingShellProfileRefs
        );
    }

    #[test]
    fn factory_activation_requires_distinct_factory_refs() {
        let activation = FactoryActivationBundle {
            activation_id: "activation-1".to_string(),
            comparison_ref: "comparison-1".to_string(),
            adopted_factory_ref: "factory-1".to_string(),
            retained_incumbent_ref: "factory-1".to_string(),
            observation_window_ref: "window-1".to_string(),
            rollback_handle_ref: "rollback-1".to_string(),
        };
        assert_eq!(
            activation.validate().unwrap_err(),
            FactoryArtifactError::ActivationRequiresDistinctFactories
        );
    }
}
