use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalFamily {
    TaskComplete,
    TaskUpdate,
    CapabilityCallRequest,
    WorkerSpawnRequest,
    MemoryFetchRequest,
    MemoryWriteRequest,
    ApprovalRequest,
    SynthesisSummary,
    HaltOrEscalate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedProposal {
    pub family: ProposalFamily,
    pub summary: String,
    pub target_ref: Option<String>,
}

impl NormalizedProposal {
    pub fn new(
        family: ProposalFamily,
        summary: impl Into<String>,
        target_ref: Option<String>,
    ) -> Result<Self, ProposalValidationError> {
        let proposal = Self {
            family,
            summary: summary.into(),
            target_ref,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn validate(&self) -> Result<(), ProposalValidationError> {
        if self.summary.trim().is_empty() {
            return Err(ProposalValidationError::MissingSummary);
        }

        match self.family {
            ProposalFamily::CapabilityCallRequest
            | ProposalFamily::WorkerSpawnRequest
            | ProposalFamily::MemoryFetchRequest
            | ProposalFamily::MemoryWriteRequest => {
                if self.target_ref.is_none() {
                    return Err(ProposalValidationError::MissingTargetRef(
                        self.family.clone(),
                    ));
                }
            }
            ProposalFamily::ApprovalRequest
            | ProposalFamily::TaskComplete
            | ProposalFamily::TaskUpdate
            | ProposalFamily::SynthesisSummary
            | ProposalFamily::HaltOrEscalate => {}
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalValidationError {
    MissingSummary,
    MissingTargetRef(ProposalFamily),
}

impl Display for ProposalValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSummary => write!(f, "proposal summary must not be empty"),
            Self::MissingTargetRef(family) => {
                write!(f, "proposal family {family:?} requires a target reference")
            }
        }
    }
}

impl Error for ProposalValidationError {}

#[cfg(test)]
mod tests {
    use super::{NormalizedProposal, ProposalFamily, ProposalValidationError};

    #[test]
    fn capability_request_requires_target() {
        let error = NormalizedProposal::new(
            ProposalFamily::CapabilityCallRequest,
            "call workspace capability",
            None,
        )
        .unwrap_err();

        assert_eq!(
            error,
            ProposalValidationError::MissingTargetRef(ProposalFamily::CapabilityCallRequest)
        );
    }

    #[test]
    fn summary_must_not_be_blank() {
        let error = NormalizedProposal::new(ProposalFamily::TaskUpdate, "   ", None).unwrap_err();
        assert_eq!(error, ProposalValidationError::MissingSummary);
    }

    #[test]
    fn approval_request_can_omit_target_ref() {
        let proposal = NormalizedProposal::new(
            ProposalFamily::ApprovalRequest,
            "request bounded approval",
            None,
        )
        .unwrap();

        assert_eq!(proposal.family, ProposalFamily::ApprovalRequest);
        assert!(proposal.target_ref.is_none());
    }
}
