use crate::execution::memory::ContradictionResolutionState;
use crate::execution::memory_protocol::MemoryRetrievalTrace;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelContinuityBundle {
    pub continuity_bundle_id: String,
    pub turn_package_ref: String,
    pub session_ref: String,
    pub agenda_ref: String,
    pub pointer_index_refs: Vec<String>,
    pub transcript_slice_refs: Vec<String>,
    pub lineage_receipt_refs: Vec<String>,
    pub contradiction_refs: Vec<String>,
    pub open_question_refs: Vec<String>,
    pub created_at: String,
}

impl ModelContinuityBundle {
    pub fn validate(&self) -> Result<(), ContinuityGroundingError> {
        require_nonempty(&self.continuity_bundle_id, "continuity_bundle_id")?;
        require_nonempty(&self.turn_package_ref, "turn_package_ref")?;
        require_nonempty(&self.session_ref, "session_ref")?;
        require_nonempty(&self.agenda_ref, "agenda_ref")?;
        validate_optional_string_list(&self.pointer_index_refs, "pointer_index_refs")?;
        validate_optional_string_list(&self.transcript_slice_refs, "transcript_slice_refs")?;
        validate_optional_string_list(&self.lineage_receipt_refs, "lineage_receipt_refs")?;
        validate_optional_string_list(&self.contradiction_refs, "contradiction_refs")?;
        validate_optional_string_list(&self.open_question_refs, "open_question_refs")?;
        require_nonempty(&self.created_at, "created_at")?;
        if self.pointer_index_refs.is_empty()
            && self.transcript_slice_refs.is_empty()
            && self.lineage_receipt_refs.is_empty()
            && self.contradiction_refs.is_empty()
            && self.open_question_refs.is_empty()
        {
            return Err(ContinuityGroundingError::MissingContent {
                field: "continuity_bundle_contents",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnGroundingPacket {
    pub turn_grounding_packet_id: String,
    pub turn_package_ref: String,
    pub continuity_bundle_ref: String,
    pub open_question_ledger_ref: Option<String>,
    pub contradiction_carry_forward_refs: Vec<String>,
    pub retrieval_trace_refs: Vec<String>,
    pub lineage_receipt_refs: Vec<String>,
    pub selection_diagnostics: Vec<String>,
    pub created_at: String,
}

impl TurnGroundingPacket {
    pub fn validate(&self) -> Result<(), ContinuityGroundingError> {
        require_nonempty(&self.turn_grounding_packet_id, "turn_grounding_packet_id")?;
        require_nonempty(&self.turn_package_ref, "turn_package_ref")?;
        require_nonempty(&self.continuity_bundle_ref, "continuity_bundle_ref")?;
        if let Some(open_question_ledger_ref) = &self.open_question_ledger_ref {
            require_nonempty(open_question_ledger_ref, "open_question_ledger_ref")?;
        }
        validate_optional_string_list(
            &self.contradiction_carry_forward_refs,
            "contradiction_carry_forward_refs",
        )?;
        validate_optional_string_list(&self.retrieval_trace_refs, "retrieval_trace_refs")?;
        validate_optional_string_list(&self.lineage_receipt_refs, "lineage_receipt_refs")?;
        validate_required_string_list(&self.selection_diagnostics, "selection_diagnostics")?;
        require_nonempty(&self.created_at, "created_at")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenQuestionLedger {
    pub open_question_ledger_id: String,
    pub turn_package_ref: String,
    pub open_question_refs: Vec<String>,
    pub missing_evidence_refs: Vec<String>,
    pub notes: Vec<String>,
    pub created_at: String,
}

impl OpenQuestionLedger {
    pub fn validate(&self) -> Result<(), ContinuityGroundingError> {
        require_nonempty(&self.open_question_ledger_id, "open_question_ledger_id")?;
        require_nonempty(&self.turn_package_ref, "turn_package_ref")?;
        validate_required_string_list(&self.open_question_refs, "open_question_refs")?;
        validate_optional_string_list(&self.missing_evidence_refs, "missing_evidence_refs")?;
        validate_required_string_list(&self.notes, "notes")?;
        require_nonempty(&self.created_at, "created_at")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContradictionCarryForwardRecord {
    pub contradiction_carry_forward_id: String,
    pub turn_package_ref: String,
    pub contradiction_ref: String,
    pub claim_refs: Vec<String>,
    pub resolution_state: ContradictionResolutionState,
    pub resolution_path: String,
    pub created_at: String,
}

impl ContradictionCarryForwardRecord {
    pub fn validate(&self) -> Result<(), ContinuityGroundingError> {
        require_nonempty(
            &self.contradiction_carry_forward_id,
            "contradiction_carry_forward_id",
        )?;
        require_nonempty(&self.turn_package_ref, "turn_package_ref")?;
        require_nonempty(&self.contradiction_ref, "contradiction_ref")?;
        validate_required_string_list(&self.claim_refs, "claim_refs")?;
        require_nonempty(&self.resolution_path, "resolution_path")?;
        require_nonempty(&self.created_at, "created_at")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedTurnMemoryUpdate {
    pub turn_memory_update_id: String,
    pub turn_result_ref: String,
    pub tool_execution_ref: String,
    pub verified_memory_record_ref: String,
    pub pointer_index_ref: String,
    pub proposed_summary: String,
    pub evidence_refs: Vec<String>,
    pub verification_refs: Vec<String>,
    pub output_bundle_ref: String,
    pub created_at: String,
}

impl VerifiedTurnMemoryUpdate {
    pub fn validate(&self) -> Result<(), ContinuityGroundingError> {
        require_nonempty(&self.turn_memory_update_id, "turn_memory_update_id")?;
        require_nonempty(&self.turn_result_ref, "turn_result_ref")?;
        require_nonempty(&self.tool_execution_ref, "tool_execution_ref")?;
        require_nonempty(
            &self.verified_memory_record_ref,
            "verified_memory_record_ref",
        )?;
        require_nonempty(&self.pointer_index_ref, "pointer_index_ref")?;
        require_nonempty(&self.proposed_summary, "proposed_summary")?;
        validate_required_string_list(&self.evidence_refs, "evidence_refs")?;
        validate_required_string_list(&self.verification_refs, "verification_refs")?;
        require_nonempty(&self.output_bundle_ref, "output_bundle_ref")?;
        require_nonempty(&self.created_at, "created_at")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinuityGroundingBundle {
    pub continuity_bundle: ModelContinuityBundle,
    pub turn_grounding_packet: TurnGroundingPacket,
    pub retrieval_traces: Vec<MemoryRetrievalTrace>,
    pub open_question_ledger: Option<OpenQuestionLedger>,
    pub contradiction_carry_forwards: Vec<ContradictionCarryForwardRecord>,
}

impl ContinuityGroundingBundle {
    pub fn validate(&self) -> Result<(), ContinuityGroundingError> {
        self.continuity_bundle.validate()?;
        self.turn_grounding_packet.validate()?;

        if self.turn_grounding_packet.turn_package_ref != self.continuity_bundle.turn_package_ref {
            return Err(ContinuityGroundingError::ReferenceMismatch {
                left_field: "turn_grounding_packet.turn_package_ref",
                right_field: "continuity_bundle.turn_package_ref",
            });
        }
        if self.turn_grounding_packet.continuity_bundle_ref
            != self.continuity_bundle.continuity_bundle_id
        {
            return Err(ContinuityGroundingError::ReferenceMismatch {
                left_field: "turn_grounding_packet.continuity_bundle_ref",
                right_field: "continuity_bundle.continuity_bundle_id",
            });
        }

        for trace in &self.retrieval_traces {
            trace
                .validate()
                .map_err(|reason| ContinuityGroundingError::InvalidNestedRecord {
                    record: "retrieval_trace",
                    reason,
                })?;
        }
        let retrieval_trace_refs = self
            .retrieval_traces
            .iter()
            .map(|trace| trace.trace_id.clone())
            .collect::<Vec<_>>();
        if sorted_refs(&retrieval_trace_refs)
            != sorted_refs(&self.turn_grounding_packet.retrieval_trace_refs)
        {
            return Err(ContinuityGroundingError::ReferenceMismatch {
                left_field: "turn_grounding_packet.retrieval_trace_refs",
                right_field: "retrieval_traces",
            });
        }

        for carry_forward in &self.contradiction_carry_forwards {
            carry_forward.validate()?;
            if carry_forward.turn_package_ref != self.continuity_bundle.turn_package_ref {
                return Err(ContinuityGroundingError::ReferenceMismatch {
                    left_field: "contradiction_carry_forwards.turn_package_ref",
                    right_field: "continuity_bundle.turn_package_ref",
                });
            }
        }
        let contradiction_carry_forward_refs = self
            .contradiction_carry_forwards
            .iter()
            .map(|record| record.contradiction_carry_forward_id.clone())
            .collect::<Vec<_>>();
        if sorted_refs(&contradiction_carry_forward_refs)
            != sorted_refs(&self.turn_grounding_packet.contradiction_carry_forward_refs)
        {
            return Err(ContinuityGroundingError::ReferenceMismatch {
                left_field: "turn_grounding_packet.contradiction_carry_forward_refs",
                right_field: "contradiction_carry_forwards",
            });
        }
        let contradiction_refs = self
            .contradiction_carry_forwards
            .iter()
            .map(|record| record.contradiction_ref.clone())
            .collect::<Vec<_>>();
        if sorted_refs(&contradiction_refs)
            != sorted_refs(&self.continuity_bundle.contradiction_refs)
        {
            return Err(ContinuityGroundingError::ReferenceMismatch {
                left_field: "continuity_bundle.contradiction_refs",
                right_field: "contradiction_carry_forwards.contradiction_ref",
            });
        }

        if let Some(open_question_ledger) = &self.open_question_ledger {
            open_question_ledger.validate()?;
            if open_question_ledger.turn_package_ref != self.continuity_bundle.turn_package_ref {
                return Err(ContinuityGroundingError::ReferenceMismatch {
                    left_field: "open_question_ledger.turn_package_ref",
                    right_field: "continuity_bundle.turn_package_ref",
                });
            }
            if self
                .turn_grounding_packet
                .open_question_ledger_ref
                .as_deref()
                != Some(open_question_ledger.open_question_ledger_id.as_str())
            {
                return Err(ContinuityGroundingError::ReferenceMismatch {
                    left_field: "turn_grounding_packet.open_question_ledger_ref",
                    right_field: "open_question_ledger.open_question_ledger_id",
                });
            }
            if sorted_refs(&open_question_ledger.open_question_refs)
                != sorted_refs(&self.continuity_bundle.open_question_refs)
            {
                return Err(ContinuityGroundingError::ReferenceMismatch {
                    left_field: "continuity_bundle.open_question_refs",
                    right_field: "open_question_ledger.open_question_refs",
                });
            }
        } else if self
            .turn_grounding_packet
            .open_question_ledger_ref
            .is_some()
            || !self.continuity_bundle.open_question_refs.is_empty()
        {
            return Err(ContinuityGroundingError::ReferenceMismatch {
                left_field: "continuity_bundle.open_question_refs",
                right_field: "open_question_ledger",
            });
        }

        let traced_pointer_index_refs = self
            .retrieval_traces
            .iter()
            .map(|trace| trace.request.pointer_index_ref.clone())
            .collect::<Vec<_>>();
        if !traced_pointer_index_refs.is_empty()
            && sorted_refs(&traced_pointer_index_refs)
                != sorted_refs(&self.continuity_bundle.pointer_index_refs)
        {
            return Err(ContinuityGroundingError::ReferenceMismatch {
                left_field: "continuity_bundle.pointer_index_refs",
                right_field: "retrieval_traces.request.pointer_index_ref",
            });
        }
        let traced_transcript_slice_refs = self
            .retrieval_traces
            .iter()
            .flat_map(|trace| trace.transcript_slice_refs.iter().cloned())
            .collect::<Vec<_>>();
        if !traced_transcript_slice_refs.is_empty()
            && sorted_refs(&traced_transcript_slice_refs)
                != sorted_refs(&self.continuity_bundle.transcript_slice_refs)
        {
            return Err(ContinuityGroundingError::ReferenceMismatch {
                left_field: "continuity_bundle.transcript_slice_refs",
                right_field: "retrieval_traces.transcript_slice_refs",
            });
        }
        if sorted_refs(&self.turn_grounding_packet.lineage_receipt_refs)
            != sorted_refs(&self.continuity_bundle.lineage_receipt_refs)
        {
            return Err(ContinuityGroundingError::ReferenceMismatch {
                left_field: "turn_grounding_packet.lineage_receipt_refs",
                right_field: "continuity_bundle.lineage_receipt_refs",
            });
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContinuityGroundingError {
    MissingField {
        field: &'static str,
    },
    MissingContent {
        field: &'static str,
    },
    ReferenceMismatch {
        left_field: &'static str,
        right_field: &'static str,
    },
    InvalidNestedRecord {
        record: &'static str,
        reason: String,
    },
}

impl Display for ContinuityGroundingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField { field } => {
                write!(f, "missing continuity grounding field: {field}")
            }
            Self::MissingContent { field } => {
                write!(
                    f,
                    "continuity grounding artifact is missing content: {field}"
                )
            }
            Self::ReferenceMismatch {
                left_field,
                right_field,
            } => write!(
                f,
                "continuity grounding reference mismatch between {left_field} and {right_field}"
            ),
            Self::InvalidNestedRecord { record, reason } => {
                write!(
                    f,
                    "invalid nested continuity grounding record {record}: {reason}"
                )
            }
        }
    }
}

impl Error for ContinuityGroundingError {}

fn require_nonempty(value: &str, field: &'static str) -> Result<(), ContinuityGroundingError> {
    if value.trim().is_empty() {
        return Err(ContinuityGroundingError::MissingField { field });
    }
    Ok(())
}

fn validate_required_string_list(
    values: &[String],
    field: &'static str,
) -> Result<(), ContinuityGroundingError> {
    if values.is_empty() {
        return Err(ContinuityGroundingError::MissingContent { field });
    }
    validate_optional_string_list(values, field)
}

fn validate_optional_string_list(
    values: &[String],
    field: &'static str,
) -> Result<(), ContinuityGroundingError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(ContinuityGroundingError::MissingField { field });
    }
    Ok(())
}

fn sorted_refs(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    values
}
