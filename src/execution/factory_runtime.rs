use crate::execution::factory::FactoryActivationBundle;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryGovernanceState {
    CandidatePrepared,
    CandidateValidated,
    Adopted,
    UnderObservation,
    RolledBack,
    Quarantined,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveFactoryState {
    pub state_id: String,
    pub active_factory_ref: String,
    pub retained_incumbent_ref: Option<String>,
    pub activation_history: Vec<FactoryActivationRecord>,
    pub rollback_history: Vec<FactoryRollbackRecord>,
}

impl ActiveFactoryState {
    pub fn initial(
        state_id: impl Into<String>,
        active_factory_ref: impl Into<String>,
    ) -> Result<Self, FactoryRuntimeError> {
        let state_id = state_id.into();
        let active_factory_ref = active_factory_ref.into();
        if state_id.trim().is_empty() {
            return Err(FactoryRuntimeError::MissingStateId);
        }
        if active_factory_ref.trim().is_empty() {
            return Err(FactoryRuntimeError::MissingActiveFactoryRef);
        }
        Ok(Self {
            state_id,
            active_factory_ref,
            retained_incumbent_ref: None,
            activation_history: Vec::new(),
            rollback_history: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryActivationRecord {
    pub activation_id: String,
    pub from_factory_ref: String,
    pub to_factory_ref: String,
    pub comparison_ref: String,
    pub observation_window_ref: String,
    pub rollback_handle_ref: String,
    pub retained_incumbent_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryRollbackRecord {
    pub rollback_id: String,
    pub from_factory_ref: String,
    pub restored_factory_ref: String,
    pub activation_ref: String,
    pub rollback_handle_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryObservationWindowReport {
    pub observation_window_ref: String,
    pub active_factory_ref: String,
    pub event_refs: Vec<String>,
    pub passed: bool,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryGovernanceTransitionRecord {
    pub transition_id: String,
    pub factory_ref: String,
    pub previous_state: FactoryGovernanceState,
    pub next_state: FactoryGovernanceState,
    pub authorizing_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
}

impl FactoryGovernanceTransitionRecord {
    pub fn validate(&self) -> Result<(), FactoryRuntimeError> {
        if self.transition_id.trim().is_empty() {
            return Err(FactoryRuntimeError::MissingTransitionId);
        }
        if self.factory_ref.trim().is_empty() {
            return Err(FactoryRuntimeError::MissingFactoryRef);
        }
        validate_ref_list(
            &self.authorizing_refs,
            FactoryRuntimeError::MissingAuthorizingRefs,
        )?;
        validate_ref_list(
            &self.rollback_refs,
            FactoryRuntimeError::MissingRollbackRefs,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryRollbackEnvelope {
    pub rollback_id: String,
    pub active_factory_ref: String,
    pub restore_factory_ref: String,
    pub runtime_restore_refs: Vec<String>,
    pub evidence_restore_refs: Vec<String>,
    pub summary: String,
}

impl FactoryRollbackEnvelope {
    pub fn validate(&self) -> Result<(), FactoryRuntimeError> {
        if self.rollback_id.trim().is_empty() {
            return Err(FactoryRuntimeError::MissingRollbackId);
        }
        if self.active_factory_ref.trim().is_empty() {
            return Err(FactoryRuntimeError::MissingActiveFactoryRef);
        }
        if self.restore_factory_ref.trim().is_empty() {
            return Err(FactoryRuntimeError::MissingRestoreFactoryRef);
        }
        validate_ref_list(
            &self.runtime_restore_refs,
            FactoryRuntimeError::MissingRuntimeRestoreRefs,
        )?;
        validate_ref_list(
            &self.evidence_restore_refs,
            FactoryRuntimeError::MissingEvidenceRestoreRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryRuntimeError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryQuarantineRecord {
    pub quarantine_id: String,
    pub factory_ref: String,
    pub trigger_refs: Vec<String>,
    pub retained_lineage_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub summary: String,
}

impl FactoryQuarantineRecord {
    pub fn validate(&self) -> Result<(), FactoryRuntimeError> {
        if self.quarantine_id.trim().is_empty() {
            return Err(FactoryRuntimeError::MissingQuarantineId);
        }
        if self.factory_ref.trim().is_empty() {
            return Err(FactoryRuntimeError::MissingFactoryRef);
        }
        validate_ref_list(&self.trigger_refs, FactoryRuntimeError::MissingTriggerRefs)?;
        validate_ref_list(
            &self.retained_lineage_refs,
            FactoryRuntimeError::MissingRetainedLineageRefs,
        )?;
        validate_ref_list(
            &self.rollback_refs,
            FactoryRuntimeError::MissingRollbackRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryRuntimeError::MissingSummary);
        }
        Ok(())
    }
}

pub fn activate_factory(
    state: &mut ActiveFactoryState,
    activation: &FactoryActivationBundle,
) -> Result<FactoryActivationRecord, FactoryRuntimeError> {
    activation
        .validate()
        .map_err(FactoryRuntimeError::InvalidActivationBundle)?;
    if state.active_factory_ref != activation.retained_incumbent_ref {
        return Err(FactoryRuntimeError::RetainedIncumbentMismatch {
            expected: state.active_factory_ref.clone(),
            actual: activation.retained_incumbent_ref.clone(),
        });
    }

    let retained_incumbent_ref = state.active_factory_ref.clone();
    let record = FactoryActivationRecord {
        activation_id: activation.activation_id.clone(),
        from_factory_ref: retained_incumbent_ref.clone(),
        to_factory_ref: activation.adopted_factory_ref.clone(),
        comparison_ref: activation.comparison_ref.clone(),
        observation_window_ref: activation.observation_window_ref.clone(),
        rollback_handle_ref: activation.rollback_handle_ref.clone(),
        retained_incumbent_ref: retained_incumbent_ref.clone(),
    };
    state.active_factory_ref = activation.adopted_factory_ref.clone();
    state.retained_incumbent_ref = Some(retained_incumbent_ref);
    state.activation_history.push(record.clone());
    Ok(record)
}

pub fn rollback_factory(
    state: &mut ActiveFactoryState,
    rollback_id: impl Into<String>,
) -> Result<FactoryRollbackRecord, FactoryRuntimeError> {
    let rollback_id = rollback_id.into();
    if rollback_id.trim().is_empty() {
        return Err(FactoryRuntimeError::MissingRollbackId);
    }
    let retained = state
        .retained_incumbent_ref
        .clone()
        .ok_or(FactoryRuntimeError::MissingRetainedIncumbent)?;
    let activation = state
        .activation_history
        .last()
        .ok_or(FactoryRuntimeError::MissingActivationHistory)?;
    let record = FactoryRollbackRecord {
        rollback_id,
        from_factory_ref: state.active_factory_ref.clone(),
        restored_factory_ref: retained.clone(),
        activation_ref: activation.activation_id.clone(),
        rollback_handle_ref: activation.rollback_handle_ref.clone(),
    };
    state.active_factory_ref = retained;
    state.rollback_history.push(record.clone());
    Ok(record)
}

pub fn observe_active_factory(
    observation_window_ref: impl Into<String>,
    state: &ActiveFactoryState,
    event_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<FactoryObservationWindowReport, FactoryRuntimeError> {
    let observation_window_ref = observation_window_ref.into();
    if observation_window_ref.trim().is_empty() {
        return Err(FactoryRuntimeError::MissingObservationWindowRef);
    }
    if event_refs.is_empty()
        || event_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
    {
        return Err(FactoryRuntimeError::MissingObservationEvents);
    }
    Ok(FactoryObservationWindowReport {
        observation_window_ref,
        active_factory_ref: state.active_factory_ref.clone(),
        event_refs,
        passed: true,
        summary: summary.into(),
    })
}

pub fn record_factory_governance_transition(
    transition_id: impl Into<String>,
    factory_ref: impl Into<String>,
    previous_state: FactoryGovernanceState,
    next_state: FactoryGovernanceState,
    authorizing_refs: Vec<String>,
    rollback_refs: Vec<String>,
) -> Result<FactoryGovernanceTransitionRecord, FactoryRuntimeError> {
    let record = FactoryGovernanceTransitionRecord {
        transition_id: transition_id.into(),
        factory_ref: factory_ref.into(),
        previous_state,
        next_state,
        authorizing_refs,
        rollback_refs,
    };
    record.validate()?;
    Ok(record)
}

pub fn build_factory_rollback_envelope(
    rollback_id: impl Into<String>,
    rollback: &FactoryRollbackRecord,
    runtime_restore_refs: Vec<String>,
    evidence_restore_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<FactoryRollbackEnvelope, FactoryRuntimeError> {
    let envelope = FactoryRollbackEnvelope {
        rollback_id: rollback_id.into(),
        active_factory_ref: rollback.from_factory_ref.clone(),
        restore_factory_ref: rollback.restored_factory_ref.clone(),
        runtime_restore_refs,
        evidence_restore_refs,
        summary: summary.into(),
    };
    envelope.validate()?;
    Ok(envelope)
}

pub fn quarantine_factory_candidate(
    quarantine_id: impl Into<String>,
    factory_ref: impl Into<String>,
    trigger_refs: Vec<String>,
    retained_lineage_refs: Vec<String>,
    rollback_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<FactoryQuarantineRecord, FactoryRuntimeError> {
    let record = FactoryQuarantineRecord {
        quarantine_id: quarantine_id.into(),
        factory_ref: factory_ref.into(),
        trigger_refs,
        retained_lineage_refs,
        rollback_refs,
        summary: summary.into(),
    };
    record.validate()?;
    Ok(record)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactoryRuntimeError {
    MissingStateId,
    MissingTransitionId,
    MissingQuarantineId,
    MissingFactoryRef,
    MissingActiveFactoryRef,
    MissingRollbackId,
    MissingObservationWindowRef,
    MissingObservationEvents,
    MissingRetainedIncumbent,
    MissingActivationHistory,
    MissingAuthorizingRefs,
    MissingTriggerRefs,
    MissingRetainedLineageRefs,
    MissingRestoreFactoryRef,
    MissingRuntimeRestoreRefs,
    MissingEvidenceRestoreRefs,
    MissingRollbackRefs,
    MissingSummary,
    RetainedIncumbentMismatch { expected: String, actual: String },
    InvalidActivationBundle(crate::execution::factory::FactoryArtifactError),
}

impl Display for FactoryRuntimeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingStateId => write!(f, "active factory state requires a state id"),
            Self::MissingTransitionId => {
                write!(f, "factory governance transition requires a transition id")
            }
            Self::MissingQuarantineId => write!(f, "factory quarantine requires an id"),
            Self::MissingFactoryRef => write!(f, "factory runtime record requires a factory ref"),
            Self::MissingActiveFactoryRef => {
                write!(f, "active factory state requires an active factory ref")
            }
            Self::MissingRollbackId => write!(f, "factory rollback requires a rollback id"),
            Self::MissingObservationWindowRef => {
                write!(f, "factory observation requires a window ref")
            }
            Self::MissingObservationEvents => {
                write!(f, "factory observation requires event refs")
            }
            Self::MissingRetainedIncumbent => {
                write!(f, "factory rollback requires a retained incumbent")
            }
            Self::MissingActivationHistory => {
                write!(f, "factory rollback requires activation history")
            }
            Self::MissingAuthorizingRefs => {
                write!(f, "factory governance transition requires authorizing refs")
            }
            Self::MissingTriggerRefs => {
                write!(f, "factory quarantine requires trigger refs")
            }
            Self::MissingRetainedLineageRefs => {
                write!(f, "factory quarantine requires retained lineage refs")
            }
            Self::MissingRestoreFactoryRef => {
                write!(
                    f,
                    "factory rollback envelope requires a restore factory ref"
                )
            }
            Self::MissingRuntimeRestoreRefs => {
                write!(f, "factory rollback envelope requires runtime restore refs")
            }
            Self::MissingEvidenceRestoreRefs => {
                write!(
                    f,
                    "factory rollback envelope requires evidence restore refs"
                )
            }
            Self::MissingRollbackRefs => {
                write!(f, "factory runtime record requires rollback refs")
            }
            Self::MissingSummary => write!(f, "factory runtime record requires a summary"),
            Self::RetainedIncumbentMismatch { expected, actual } => write!(
                f,
                "factory activation expected retained incumbent '{}', got '{}'",
                expected, actual
            ),
            Self::InvalidActivationBundle(error) => write!(f, "{error}"),
        }
    }
}

impl Error for FactoryRuntimeError {}

fn validate_ref_list(
    refs: &[String],
    error: FactoryRuntimeError,
) -> Result<(), FactoryRuntimeError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::factory::FactoryActivationBundle;

    #[test]
    fn factory_activation_and_rollback_roundtrip() {
        let mut state = ActiveFactoryState::initial("state-1", "factory-incumbent").unwrap();
        let activation = FactoryActivationBundle {
            activation_id: "activation-1".to_string(),
            comparison_ref: "comparison-1".to_string(),
            adopted_factory_ref: "factory-challenger".to_string(),
            retained_incumbent_ref: "factory-incumbent".to_string(),
            observation_window_ref: "window-1".to_string(),
            rollback_handle_ref: "rollback-handle-1".to_string(),
        };

        let record = activate_factory(&mut state, &activation).unwrap();
        assert_eq!(record.to_factory_ref, "factory-challenger");
        assert_eq!(state.active_factory_ref, "factory-challenger");

        let rollback = rollback_factory(&mut state, "rollback-1").unwrap();
        assert_eq!(rollback.restored_factory_ref, "factory-incumbent");
        assert_eq!(state.active_factory_ref, "factory-incumbent");
    }

    #[test]
    fn factory_governance_and_quarantine_records_validate() {
        let transition = record_factory_governance_transition(
            "transition-1",
            "factory-challenger",
            FactoryGovernanceState::CandidateValidated,
            FactoryGovernanceState::Adopted,
            vec!["comparison-1".to_string()],
            vec!["rollback-handle-1".to_string()],
        )
        .unwrap();
        assert_eq!(transition.next_state, FactoryGovernanceState::Adopted);

        let rollback = FactoryRollbackRecord {
            rollback_id: "rollback-1".to_string(),
            from_factory_ref: "factory-challenger".to_string(),
            restored_factory_ref: "factory-incumbent".to_string(),
            activation_ref: "activation-1".to_string(),
            rollback_handle_ref: "rollback-handle-1".to_string(),
        };
        let envelope = build_factory_rollback_envelope(
            "rollback-envelope-1",
            &rollback,
            vec!["runtime:restore".to_string()],
            vec!["evidence:restore".to_string()],
            "rollback envelope",
        )
        .unwrap();
        assert_eq!(envelope.restore_factory_ref, "factory-incumbent");

        let quarantine = quarantine_factory_candidate(
            "quarantine-1",
            "factory-challenger",
            vec!["trigger:regression".to_string()],
            vec!["lineage-1".to_string()],
            vec!["rollback-handle-1".to_string()],
            "quarantine challenger",
        )
        .unwrap();
        assert_eq!(quarantine.factory_ref, "factory-challenger");
    }
}
