use crate::execution::factory::{FactoryArtifactError, FactoryComparisonDimension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryValidationStatus {
    Passed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryValidationProfile {
    pub validation_profile_id: String,
    pub factory_candidate_ref: String,
    pub scenario_refs: Vec<String>,
    pub required_dimension_refs: Vec<FactoryComparisonDimension>,
    pub required_evidence_refs: Vec<String>,
    pub failure_policy_refs: Vec<String>,
}

impl FactoryValidationProfile {
    pub fn validate(&self) -> Result<(), FactoryValidationError> {
        if self.validation_profile_id.trim().is_empty() {
            return Err(FactoryValidationError::MissingValidationProfileId);
        }
        if self.factory_candidate_ref.trim().is_empty() {
            return Err(FactoryValidationError::MissingFactoryCandidateRef);
        }
        if self.scenario_refs.is_empty()
            || self
                .scenario_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Err(FactoryValidationError::MissingScenarioRefs);
        }
        if self.required_dimension_refs.is_empty() {
            return Err(FactoryValidationError::MissingRequiredDimensions);
        }
        if self
            .required_evidence_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(FactoryValidationError::MissingRequiredEvidenceRefs);
        }
        if self
            .failure_policy_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(FactoryValidationError::MissingFailurePolicyRefs);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryValidationEvidence {
    pub evidence_id: String,
    pub factory_candidate_ref: String,
    pub shell_evidence_refs: Vec<String>,
    pub governance_refs: Vec<String>,
    pub continuity_refs: Vec<String>,
    pub replay_refs: Vec<String>,
    pub operator_review_refs: Vec<String>,
    pub failure_refs: Vec<String>,
    pub summary: String,
}

impl FactoryValidationEvidence {
    pub fn validate(&self) -> Result<(), FactoryValidationError> {
        if self.evidence_id.trim().is_empty() {
            return Err(FactoryValidationError::MissingEvidenceId);
        }
        if self.factory_candidate_ref.trim().is_empty() {
            return Err(FactoryValidationError::MissingFactoryCandidateRef);
        }
        validate_ref_list(
            &self.shell_evidence_refs,
            FactoryValidationError::MissingShellEvidenceRefs,
        )?;
        validate_ref_list(
            &self.governance_refs,
            FactoryValidationError::MissingGovernanceEvidenceRefs,
        )?;
        validate_ref_list(
            &self.continuity_refs,
            FactoryValidationError::MissingContinuityEvidenceRefs,
        )?;
        validate_ref_list(
            &self.replay_refs,
            FactoryValidationError::MissingReplayEvidenceRefs,
        )?;
        if self
            .operator_review_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(FactoryValidationError::MissingOperatorReviewRefs);
        }
        if self.summary.trim().is_empty() {
            return Err(FactoryValidationError::MissingSummary);
        }
        Ok(())
    }

    pub fn all_evidence_refs(&self) -> Vec<String> {
        let mut refs = self
            .shell_evidence_refs
            .iter()
            .chain(&self.governance_refs)
            .chain(&self.continuity_refs)
            .chain(&self.replay_refs)
            .chain(&self.operator_review_refs)
            .chain(&self.failure_refs)
            .cloned()
            .collect::<Vec<_>>();
        refs.sort();
        refs.dedup();
        refs
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryValidationRecord {
    pub validation_id: String,
    pub profile_ref: String,
    pub factory_candidate_ref: String,
    pub covered_dimensions: Vec<FactoryComparisonDimension>,
    pub evidence_refs: Vec<String>,
    pub status: FactoryValidationStatus,
    pub summary: String,
}

impl FactoryValidationRecord {
    pub fn validate(&self) -> Result<(), FactoryValidationError> {
        if self.validation_id.trim().is_empty() {
            return Err(FactoryValidationError::MissingValidationId);
        }
        if self.profile_ref.trim().is_empty() {
            return Err(FactoryValidationError::MissingValidationProfileRef);
        }
        if self.factory_candidate_ref.trim().is_empty() {
            return Err(FactoryValidationError::MissingFactoryCandidateRef);
        }
        if self.covered_dimensions.is_empty() {
            return Err(FactoryValidationError::MissingRequiredDimensions);
        }
        validate_ref_list(
            &self.evidence_refs,
            FactoryValidationError::MissingRequiredEvidenceRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryValidationError::MissingSummary);
        }
        Ok(())
    }
}

pub fn evaluate_factory_candidate(
    validation_id: impl Into<String>,
    profile: &FactoryValidationProfile,
    evidence: &FactoryValidationEvidence,
    summary: impl Into<String>,
) -> Result<FactoryValidationRecord, FactoryValidationError> {
    profile.validate()?;
    evidence.validate()?;

    if profile.factory_candidate_ref != evidence.factory_candidate_ref {
        return Err(FactoryValidationError::CandidateMismatch {
            profile_ref: profile.factory_candidate_ref.clone(),
            evidence_ref: evidence.factory_candidate_ref.clone(),
        });
    }

    let available_evidence = evidence
        .all_evidence_refs()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let missing_required_evidence = profile
        .required_evidence_refs
        .iter()
        .filter(|reference| !available_evidence.contains(*reference))
        .cloned()
        .collect::<Vec<_>>();
    if !missing_required_evidence.is_empty() {
        return Err(FactoryValidationError::MissingRequiredEvidence {
            missing_refs: missing_required_evidence,
        });
    }

    let status = if evidence.failure_refs.is_empty() {
        FactoryValidationStatus::Passed
    } else {
        FactoryValidationStatus::Failed
    };

    let record = FactoryValidationRecord {
        validation_id: validation_id.into(),
        profile_ref: profile.validation_profile_id.clone(),
        factory_candidate_ref: profile.factory_candidate_ref.clone(),
        covered_dimensions: profile.required_dimension_refs.clone(),
        evidence_refs: available_evidence.into_iter().collect(),
        status,
        summary: summary.into(),
    };
    record.validate()?;
    Ok(record)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactoryValidationError {
    MissingValidationProfileId,
    MissingValidationId,
    MissingValidationProfileRef,
    MissingEvidenceId,
    MissingFactoryCandidateRef,
    MissingScenarioRefs,
    MissingRequiredDimensions,
    MissingRequiredEvidenceRefs,
    MissingFailurePolicyRefs,
    MissingShellEvidenceRefs,
    MissingGovernanceEvidenceRefs,
    MissingContinuityEvidenceRefs,
    MissingReplayEvidenceRefs,
    MissingOperatorReviewRefs,
    MissingSummary,
    CandidateMismatch {
        profile_ref: String,
        evidence_ref: String,
    },
    MissingRequiredEvidence {
        missing_refs: Vec<String>,
    },
    Artifact(FactoryArtifactError),
}

impl Display for FactoryValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingValidationProfileId => {
                write!(f, "factory validation profile requires an id")
            }
            Self::MissingValidationId => write!(f, "factory validation record requires an id"),
            Self::MissingValidationProfileRef => {
                write!(f, "factory validation record requires a profile ref")
            }
            Self::MissingEvidenceId => write!(f, "factory validation evidence requires an id"),
            Self::MissingFactoryCandidateRef => {
                write!(f, "factory validation requires a factory candidate ref")
            }
            Self::MissingScenarioRefs => {
                write!(f, "factory validation profile requires scenario refs")
            }
            Self::MissingRequiredDimensions => {
                write!(f, "factory validation requires dimension coverage")
            }
            Self::MissingRequiredEvidenceRefs => {
                write!(f, "factory validation requires evidence refs")
            }
            Self::MissingFailurePolicyRefs => {
                write!(
                    f,
                    "factory validation failure policy refs must be non-empty when present"
                )
            }
            Self::MissingShellEvidenceRefs => {
                write!(f, "factory validation evidence requires shell refs")
            }
            Self::MissingGovernanceEvidenceRefs => {
                write!(f, "factory validation evidence requires governance refs")
            }
            Self::MissingContinuityEvidenceRefs => {
                write!(f, "factory validation evidence requires continuity refs")
            }
            Self::MissingReplayEvidenceRefs => {
                write!(f, "factory validation evidence requires replay refs")
            }
            Self::MissingOperatorReviewRefs => {
                write!(
                    f,
                    "factory validation operator review refs must be non-empty when present"
                )
            }
            Self::MissingSummary => write!(f, "factory validation requires a summary"),
            Self::CandidateMismatch {
                profile_ref,
                evidence_ref,
            } => write!(
                f,
                "factory validation profile candidate '{}' does not match evidence candidate '{}'",
                profile_ref, evidence_ref
            ),
            Self::MissingRequiredEvidence { missing_refs } => write!(
                f,
                "factory validation is missing required evidence refs: {}",
                missing_refs.join(", ")
            ),
            Self::Artifact(error) => write!(f, "{error}"),
        }
    }
}

impl Error for FactoryValidationError {}

impl From<FactoryArtifactError> for FactoryValidationError {
    fn from(value: FactoryArtifactError) -> Self {
        Self::Artifact(value)
    }
}

fn validate_ref_list(
    refs: &[String],
    error: FactoryValidationError,
) -> Result<(), FactoryValidationError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluation_requires_matching_candidate_refs() {
        let profile = FactoryValidationProfile {
            validation_profile_id: "profile-1".to_string(),
            factory_candidate_ref: "factory-1".to_string(),
            scenario_refs: vec!["scenario:a".to_string()],
            required_dimension_refs: vec![FactoryComparisonDimension::ShellFidelity],
            required_evidence_refs: vec!["shell:packet".to_string()],
            failure_policy_refs: vec!["policy:fail".to_string()],
        };
        let evidence = FactoryValidationEvidence {
            evidence_id: "evidence-1".to_string(),
            factory_candidate_ref: "factory-2".to_string(),
            shell_evidence_refs: vec!["shell:packet".to_string()],
            governance_refs: vec!["governance:1".to_string()],
            continuity_refs: vec!["continuity:1".to_string()],
            replay_refs: vec!["replay:1".to_string()],
            operator_review_refs: Vec::new(),
            failure_refs: Vec::new(),
            summary: "evidence".to_string(),
        };

        assert!(matches!(
            evaluate_factory_candidate("validation-1", &profile, &evidence, "summary").unwrap_err(),
            FactoryValidationError::CandidateMismatch { .. }
        ));
    }

    #[test]
    fn evaluation_marks_failure_when_failure_refs_exist() {
        let profile = FactoryValidationProfile {
            validation_profile_id: "profile-1".to_string(),
            factory_candidate_ref: "factory-1".to_string(),
            scenario_refs: vec!["scenario:a".to_string()],
            required_dimension_refs: vec![FactoryComparisonDimension::ShellFidelity],
            required_evidence_refs: vec!["shell:packet".to_string()],
            failure_policy_refs: vec!["policy:fail".to_string()],
        };
        let evidence = FactoryValidationEvidence {
            evidence_id: "evidence-1".to_string(),
            factory_candidate_ref: "factory-1".to_string(),
            shell_evidence_refs: vec!["shell:packet".to_string()],
            governance_refs: vec!["governance:1".to_string()],
            continuity_refs: vec!["continuity:1".to_string()],
            replay_refs: vec!["replay:1".to_string()],
            operator_review_refs: Vec::new(),
            failure_refs: vec!["failure:1".to_string()],
            summary: "evidence".to_string(),
        };

        let record =
            evaluate_factory_candidate("validation-1", &profile, &evidence, "summary").unwrap();
        assert_eq!(record.status, FactoryValidationStatus::Failed);
    }
}
