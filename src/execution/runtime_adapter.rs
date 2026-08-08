use crate::execution::artifact::{ActivationEnvelope, ArtifactDigest, PackageBundleManifest};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveGenerationState {
    pub state_id: String,
    pub active_generation_digest: ArtifactDigest,
    pub retained_incumbent_digest: Option<ArtifactDigest>,
    pub activation_history: Vec<GenerationActivationRecord>,
    pub rollback_history: Vec<GenerationRollbackRecord>,
}

impl ActiveGenerationState {
    pub fn initial(
        state_id: impl Into<String>,
        active_generation_digest: ArtifactDigest,
    ) -> Result<Self, RuntimeAdapterError> {
        let state_id = state_id.into();
        if state_id.trim().is_empty() {
            return Err(RuntimeAdapterError::MissingStateId);
        }
        Ok(Self {
            state_id,
            active_generation_digest,
            retained_incumbent_digest: None,
            activation_history: Vec::new(),
            rollback_history: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationActivationRecord {
    pub activation_id: String,
    pub from_generation_digest: ArtifactDigest,
    pub to_generation_digest: ArtifactDigest,
    pub observation_window_ref: String,
    pub retained_incumbent_digest: ArtifactDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationRollbackRecord {
    pub rollback_id: String,
    pub from_generation_digest: ArtifactDigest,
    pub restored_generation_digest: ArtifactDigest,
    pub activation_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationObservationWindowReport {
    pub observation_window_ref: String,
    pub active_generation_digest: ArtifactDigest,
    pub event_refs: Vec<String>,
    pub passed: bool,
    pub summary: String,
}

pub fn activate_generation(
    state: &mut ActiveGenerationState,
    activation: &ActivationEnvelope,
    package: &PackageBundleManifest,
) -> Result<GenerationActivationRecord, RuntimeAdapterError> {
    if !activation.approved {
        return Err(RuntimeAdapterError::ActivationNotApproved {
            activation_id: activation.activation_id.clone(),
        });
    }
    if activation.package_digest != package.bundle_digest {
        return Err(RuntimeAdapterError::PackageDigestMismatch {
            expected: activation.package_digest.clone(),
            actual: package.bundle_digest.clone(),
        });
    }

    let retained_incumbent_digest = state.active_generation_digest.clone();
    let record = GenerationActivationRecord {
        activation_id: activation.activation_id.clone(),
        from_generation_digest: retained_incumbent_digest.clone(),
        to_generation_digest: package.bundle_digest.clone(),
        observation_window_ref: activation.observation_window_ref.clone(),
        retained_incumbent_digest: retained_incumbent_digest.clone(),
    };
    state.active_generation_digest = package.bundle_digest.clone();
    state.retained_incumbent_digest = Some(retained_incumbent_digest);
    state.activation_history.push(record.clone());
    Ok(record)
}

pub fn rollback_generation(
    state: &mut ActiveGenerationState,
    rollback_id: impl Into<String>,
) -> Result<GenerationRollbackRecord, RuntimeAdapterError> {
    let rollback_id = rollback_id.into();
    if rollback_id.trim().is_empty() {
        return Err(RuntimeAdapterError::MissingRollbackId);
    }
    let retained = state
        .retained_incumbent_digest
        .clone()
        .ok_or(RuntimeAdapterError::MissingRetainedIncumbent)?;
    let activation_ref = state
        .activation_history
        .last()
        .map(|record| record.activation_id.clone())
        .ok_or(RuntimeAdapterError::MissingActivationHistory)?;
    let record = GenerationRollbackRecord {
        rollback_id,
        from_generation_digest: state.active_generation_digest.clone(),
        restored_generation_digest: retained.clone(),
        activation_ref,
    };
    state.active_generation_digest = retained;
    state.rollback_history.push(record.clone());
    Ok(record)
}

pub fn observe_active_generation(
    observation_window_ref: impl Into<String>,
    state: &ActiveGenerationState,
    event_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<GenerationObservationWindowReport, RuntimeAdapterError> {
    let observation_window_ref = observation_window_ref.into();
    if observation_window_ref.trim().is_empty() {
        return Err(RuntimeAdapterError::MissingObservationWindow);
    }
    if event_refs.is_empty() {
        return Err(RuntimeAdapterError::MissingObservationEvents);
    }
    Ok(GenerationObservationWindowReport {
        observation_window_ref,
        active_generation_digest: state.active_generation_digest.clone(),
        event_refs,
        passed: true,
        summary: summary.into(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeAdapterError {
    MissingStateId,
    MissingRollbackId,
    MissingObservationWindow,
    MissingObservationEvents,
    ActivationNotApproved {
        activation_id: String,
    },
    PackageDigestMismatch {
        expected: ArtifactDigest,
        actual: ArtifactDigest,
    },
    MissingRetainedIncumbent,
    MissingActivationHistory,
}

impl Display for RuntimeAdapterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingStateId => write!(f, "active generation state requires a state id"),
            Self::MissingRollbackId => write!(f, "rollback requires a rollback id"),
            Self::MissingObservationWindow => write!(f, "observation requires a window ref"),
            Self::MissingObservationEvents => write!(f, "observation requires event refs"),
            Self::ActivationNotApproved { activation_id } => {
                write!(f, "activation '{activation_id}' is not approved")
            }
            Self::PackageDigestMismatch { expected, actual } => {
                write!(f, "activation expected package {expected}, got {actual}")
            }
            Self::MissingRetainedIncumbent => write!(f, "rollback requires a retained incumbent"),
            Self::MissingActivationHistory => write!(f, "rollback requires activation history"),
        }
    }
}

impl Error for RuntimeAdapterError {}
