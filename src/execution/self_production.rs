use crate::execution::artifact::{ArtifactDigest, GenerationArtifactBundle};
use crate::execution::runtime_adapter::ActiveGenerationState;
use crate::execution::validation::ExecutionBackedValidationRecord;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelfProductionCampaignStatus {
    Planned,
    Running,
    SuccessorProduced,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfProductionCampaign {
    pub campaign_id: String,
    pub adopted_generation_digest: ArtifactDigest,
    pub successor_request_ref: String,
    pub status: SelfProductionCampaignStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessorProductionRecord {
    pub record_id: String,
    pub campaign_id: String,
    pub producer_generation_digest: ArtifactDigest,
    pub successor_generation_digest: ArtifactDigest,
    pub successor_package_digest: ArtifactDigest,
    pub validation_trace_ref: String,
    pub lineage_ref: String,
    pub complete: bool,
}

pub fn start_adopted_generation_campaign(
    campaign_id: impl Into<String>,
    state: &ActiveGenerationState,
    successor_request_ref: impl Into<String>,
) -> Result<SelfProductionCampaign, SelfProductionError> {
    let campaign_id = campaign_id.into();
    let successor_request_ref = successor_request_ref.into();
    if campaign_id.trim().is_empty() {
        return Err(SelfProductionError::MissingCampaignId);
    }
    if successor_request_ref.trim().is_empty() {
        return Err(SelfProductionError::MissingSuccessorRequest);
    }

    Ok(SelfProductionCampaign {
        campaign_id,
        adopted_generation_digest: state.active_generation_digest.clone(),
        successor_request_ref,
        status: SelfProductionCampaignStatus::Planned,
    })
}

pub fn record_successor_production(
    record_id: impl Into<String>,
    campaign: &mut SelfProductionCampaign,
    successor_bundle: &GenerationArtifactBundle,
    validation: &ExecutionBackedValidationRecord,
) -> Result<SuccessorProductionRecord, SelfProductionError> {
    let record_id = record_id.into();
    if record_id.trim().is_empty() {
        return Err(SelfProductionError::MissingRecordId);
    }
    if successor_bundle.manifest.parent_digest.as_ref() != Some(&campaign.adopted_generation_digest)
    {
        return Err(SelfProductionError::SuccessorParentMismatch);
    }
    if successor_bundle
        .lineage
        .produced_by_generation_digest
        .as_ref()
        != Some(&campaign.adopted_generation_digest)
    {
        return Err(SelfProductionError::ProducerMismatch);
    }
    if validation.package_digest != successor_bundle.package.bundle_digest || !validation.passed {
        return Err(SelfProductionError::MissingValidationProof);
    }

    campaign.status = SelfProductionCampaignStatus::SuccessorProduced;
    Ok(SuccessorProductionRecord {
        record_id,
        campaign_id: campaign.campaign_id.clone(),
        producer_generation_digest: campaign.adopted_generation_digest.clone(),
        successor_generation_digest: successor_bundle.lineage.generation_digest.clone(),
        successor_package_digest: successor_bundle.package.bundle_digest.clone(),
        validation_trace_ref: validation.trace_ref.clone(),
        lineage_ref: successor_bundle.lineage.lineage_id.clone(),
        complete: true,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelfProductionError {
    MissingCampaignId,
    MissingSuccessorRequest,
    MissingRecordId,
    SuccessorParentMismatch,
    ProducerMismatch,
    MissingValidationProof,
}

impl Display for SelfProductionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCampaignId => write!(f, "self-production campaign requires a campaign id"),
            Self::MissingSuccessorRequest => {
                write!(f, "self-production campaign requires a successor request")
            }
            Self::MissingRecordId => write!(f, "successor production requires a record id"),
            Self::SuccessorParentMismatch => {
                write!(f, "successor parent does not match adopted generation")
            }
            Self::ProducerMismatch => {
                write!(f, "successor lineage producer does not match campaign")
            }
            Self::MissingValidationProof => {
                write!(
                    f,
                    "successor production requires a passing validation proof"
                )
            }
        }
    }
}

impl Error for SelfProductionError {}
