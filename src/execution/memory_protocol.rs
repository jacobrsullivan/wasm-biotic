use crate::execution::memory::{
    MemoryScope, MemoryStore, MemoryUpdateProposal, MemoryUpdateStatus, PointerIndex,
    TopicBundleClass, TranscriptSliceQuery,
};
use crate::execution::worker_world::{WorkerActionRequest, WorkerWorldKind};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRetrievalRequest {
    pub retrieval_request_id: String,
    pub shell_session_id: String,
    pub shell_turn_id: String,
    pub pointer_index_ref: String,
    pub bundle_class: TopicBundleClass,
    pub transcript_query: TranscriptSliceQuery,
    pub max_bundle_refs: usize,
}

impl MemoryRetrievalRequest {
    pub fn validate(&self) -> Result<(), String> {
        require_nonempty(&self.retrieval_request_id, "retrieval_request_id")?;
        require_nonempty(&self.shell_session_id, "shell_session_id")?;
        require_nonempty(&self.shell_turn_id, "shell_turn_id")?;
        require_nonempty(&self.pointer_index_ref, "pointer_index_ref")?;
        if self.max_bundle_refs == 0 {
            return Err("max_bundle_refs must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRetrievalTrace {
    pub trace_id: String,
    pub request: MemoryRetrievalRequest,
    pub bundle_refs: Vec<String>,
    pub transcript_slice_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub diagnostics: Vec<String>,
}

impl MemoryRetrievalTrace {
    pub fn validate(&self) -> Result<(), String> {
        require_nonempty(&self.trace_id, "trace_id")?;
        self.request.validate()?;
        validate_string_list(&self.bundle_refs, "bundle_refs")?;
        validate_string_list(&self.transcript_slice_refs, "transcript_slice_refs")?;
        validate_string_list(&self.evidence_refs, "evidence_refs")?;
        validate_string_list(&self.diagnostics, "diagnostics")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedMemoryUpdateRecord {
    pub record_id: String,
    pub shell_session_id: String,
    pub shell_turn_id: String,
    pub proposal_id: String,
    pub output_bundle_id: String,
    pub pointer_index_ref: String,
    pub evidence_refs: Vec<String>,
    pub verification_refs: Vec<String>,
}

impl VerifiedMemoryUpdateRecord {
    pub fn validate(&self) -> Result<(), String> {
        require_nonempty(&self.record_id, "record_id")?;
        require_nonempty(&self.shell_session_id, "shell_session_id")?;
        require_nonempty(&self.shell_turn_id, "shell_turn_id")?;
        require_nonempty(&self.proposal_id, "proposal_id")?;
        require_nonempty(&self.output_bundle_id, "output_bundle_id")?;
        require_nonempty(&self.pointer_index_ref, "pointer_index_ref")?;
        validate_string_list(&self.evidence_refs, "evidence_refs")?;
        validate_string_list(&self.verification_refs, "verification_refs")?;
        if self.verification_refs.is_empty() {
            return Err("verified memory update requires verification refs".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellContinuityBundle {
    pub continuity_id: String,
    pub shell_session_id: String,
    pub pointer_index_ref: String,
    pub retrieval_trace_refs: Vec<String>,
    pub verified_memory_refs: Vec<String>,
    pub contradiction_refs: Vec<String>,
}

impl ShellContinuityBundle {
    pub fn validate(&self) -> Result<(), String> {
        require_nonempty(&self.continuity_id, "continuity_id")?;
        require_nonempty(&self.shell_session_id, "shell_session_id")?;
        require_nonempty(&self.pointer_index_ref, "pointer_index_ref")?;
        validate_string_list(&self.retrieval_trace_refs, "retrieval_trace_refs")?;
        validate_string_list(&self.verified_memory_refs, "verified_memory_refs")?;
        validate_string_list(&self.contradiction_refs, "contradiction_refs")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoryProtocolError {
    ActionIsNotMemoryRetrieval { action_id: String },
    PointerIndexNotFound { pointer_index_ref: String },
    InvalidMaxBundleRefs,
    MemoryWrite(String),
}

impl Display for MemoryProtocolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActionIsNotMemoryRetrieval { action_id } => {
                write!(
                    f,
                    "worker action is not a memory retrieval action: {action_id}"
                )
            }
            Self::PointerIndexNotFound { pointer_index_ref } => {
                write!(f, "pointer index not found: {pointer_index_ref}")
            }
            Self::InvalidMaxBundleRefs => {
                write!(f, "memory retrieval requires a positive bundle cap")
            }
            Self::MemoryWrite(error) => write!(f, "memory protocol write failed: {error}"),
        }
    }
}

impl Error for MemoryProtocolError {}

fn require_nonempty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("missing memory protocol field: {field}"));
    }
    Ok(())
}

fn validate_string_list(values: &[String], field: &str) -> Result<(), String> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!(
            "memory protocol field {field} contains an empty ref"
        ));
    }
    Ok(())
}

pub fn memory_retrieval_request_from_action(
    action: &WorkerActionRequest,
    retrieval_request_id: impl Into<String>,
    bundle_class: TopicBundleClass,
    transcript_query: TranscriptSliceQuery,
    max_bundle_refs: usize,
) -> Result<MemoryRetrievalRequest, MemoryProtocolError> {
    if action.world_kind != WorkerWorldKind::MemoryRetrieval {
        return Err(MemoryProtocolError::ActionIsNotMemoryRetrieval {
            action_id: action.action_id.clone(),
        });
    }
    if max_bundle_refs == 0 {
        return Err(MemoryProtocolError::InvalidMaxBundleRefs);
    }

    Ok(MemoryRetrievalRequest {
        retrieval_request_id: retrieval_request_id.into(),
        shell_session_id: action.shell_session_id.clone(),
        shell_turn_id: action.shell_turn_id.clone(),
        pointer_index_ref: action.resource_scope.clone(),
        bundle_class,
        transcript_query,
        max_bundle_refs,
    })
}

pub fn execute_memory_retrieval_protocol(
    memory_store: &MemoryStore,
    request: &MemoryRetrievalRequest,
) -> Result<MemoryRetrievalTrace, MemoryProtocolError> {
    let pointer_index = memory_store
        .load_pointer_index(&request.pointer_index_ref)
        .ok_or_else(|| MemoryProtocolError::PointerIndexNotFound {
            pointer_index_ref: request.pointer_index_ref.clone(),
        })?;

    let bundle_refs = pointer_index
        .entry_refs
        .iter()
        .filter(|entry_ref| {
            memory_store
                .topic_bundle(entry_ref)
                .is_some_and(|bundle| bundle.bundle_class == request.bundle_class)
        })
        .take(request.max_bundle_refs)
        .cloned()
        .collect::<Vec<_>>();
    let transcript_slice_refs = memory_store
        .retrieve_transcript_slices(&request.transcript_query)
        .into_iter()
        .map(|slice| slice.slice_id.clone())
        .collect::<Vec<_>>();
    let mut evidence_refs = bundle_refs.clone();
    evidence_refs.extend(transcript_slice_refs.clone());

    Ok(MemoryRetrievalTrace {
        trace_id: format!("memory-trace-{}", request.retrieval_request_id),
        request: request.clone(),
        bundle_refs,
        transcript_slice_refs,
        evidence_refs,
        diagnostics: vec![format!(
            "retrieved memory from pointer index {}",
            pointer_index.index_id
        )],
    })
}

pub fn record_verified_memory_update(
    memory_store: &mut MemoryStore,
    record_id: impl Into<String>,
    shell_session_id: impl Into<String>,
    shell_turn_id: impl Into<String>,
    pointer_index_ref: impl Into<String>,
    bundle_class: TopicBundleClass,
    summary: impl Into<String>,
    evidence_refs: Vec<String>,
    verification_refs: Vec<String>,
) -> Result<VerifiedMemoryUpdateRecord, MemoryProtocolError> {
    let record_id = record_id.into();
    let shell_session_id = shell_session_id.into();
    let shell_turn_id = shell_turn_id.into();
    let pointer_index_ref = pointer_index_ref.into();
    let proposal_id = format!("memory-update-{record_id}");
    let output_bundle_id = format!("memory-bundle-{record_id}");
    let proposal = MemoryUpdateProposal {
        proposal_id: proposal_id.clone(),
        pointer_index_ref: Some(pointer_index_ref.clone()),
        bundle_class,
        scope: MemoryScope::Session(shell_session_id.clone()),
        proposed_summary: summary.into(),
        evidence_refs: evidence_refs.clone(),
        verification_refs: verification_refs.clone(),
        status: MemoryUpdateStatus::Proposed,
    };
    memory_store.propose_memory_update(proposal);
    memory_store
        .accept_memory_update(
            &proposal_id,
            output_bundle_id.clone(),
            format!("verified-shell-outcome:{shell_turn_id}"),
        )
        .map_err(|error| MemoryProtocolError::MemoryWrite(format!("{error:?}")))?;

    Ok(VerifiedMemoryUpdateRecord {
        record_id,
        shell_session_id,
        shell_turn_id,
        proposal_id,
        output_bundle_id,
        pointer_index_ref,
        evidence_refs,
        verification_refs,
    })
}

pub fn build_shell_continuity_bundle(
    continuity_id: impl Into<String>,
    shell_session_id: impl Into<String>,
    pointer_index: &PointerIndex,
    retrieval_traces: &[MemoryRetrievalTrace],
    verified_memory_updates: &[VerifiedMemoryUpdateRecord],
    contradiction_refs: Vec<String>,
) -> ShellContinuityBundle {
    ShellContinuityBundle {
        continuity_id: continuity_id.into(),
        shell_session_id: shell_session_id.into(),
        pointer_index_ref: pointer_index.index_id.clone(),
        retrieval_trace_refs: retrieval_traces
            .iter()
            .map(|trace| trace.trace_id.clone())
            .collect(),
        verified_memory_refs: verified_memory_updates
            .iter()
            .map(|record| record.record_id.clone())
            .collect(),
        contradiction_refs,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MemoryProtocolError, build_shell_continuity_bundle, execute_memory_retrieval_protocol,
        memory_retrieval_request_from_action, record_verified_memory_update,
    };
    use crate::execution::memory::{
        MemoryScope, MemoryStore, PointerIndex, TopicBundle, TopicBundleClass, TranscriptSlice,
        TranscriptSliceQuery,
    };
    use crate::execution::worker_world::{WorkerActionRequest, WorkerWorldKind};
    use crate::execution::{AuthorityClass, CapabilityWorld};

    fn memory_action() -> WorkerActionRequest {
        WorkerActionRequest {
            action_id: "action-1".to_string(),
            shell_session_id: "shell-session-1".to_string(),
            shell_turn_id: "shell-turn-1".to_string(),
            import_name: "memory-fetch".to_string(),
            world_kind: WorkerWorldKind::MemoryRetrieval,
            capability_world: CapabilityWorld::MemoryAccess,
            operation: "retrieve-topic".to_string(),
            resource_scope: "pointer-index-1".to_string(),
            required_authority_class: AuthorityClass::Observe,
        }
    }

    fn memory_store() -> MemoryStore {
        let mut memory_store = MemoryStore::default();
        memory_store.insert_pointer_index(PointerIndex {
            index_id: "pointer-index-1".to_string(),
            scope: MemoryScope::Session("shell-session-1".to_string()),
            entry_refs: vec!["bundle-1".to_string()],
            contested_refs: Vec::new(),
            critical_refs: vec!["bundle-1".to_string()],
            governance_constraints: vec!["skeptical".to_string()],
            open_task_refs: Vec::new(),
            updated_at: "now".to_string(),
        });
        memory_store.add_topic_bundle(TopicBundle {
            bundle_id: "bundle-1".to_string(),
            bundle_class: TopicBundleClass::WorkspaceMap,
            scope: MemoryScope::Session("shell-session-1".to_string()),
            summary: "workspace".to_string(),
            evidence_refs: vec!["evidence-1".to_string()],
            freshness_policy: "fresh".to_string(),
        });
        memory_store.add_transcript_slice(TranscriptSlice {
            slice_id: "slice-1".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            session_id: Some("shell-session-1".to_string()),
            task_id: Some("task-1".to_string()),
            referenced_artifacts: vec!["bundle-1".to_string()],
            summary: "retrieval".to_string(),
            excerpts: vec!["excerpt".to_string()],
        });
        memory_store
    }

    #[test]
    fn retrieval_request_must_be_memory_action() {
        let mut action = memory_action();
        action.world_kind = WorkerWorldKind::TaskControl;
        let error = memory_retrieval_request_from_action(
            &action,
            "request-1",
            TopicBundleClass::WorkspaceMap,
            TranscriptSliceQuery::default(),
            1,
        )
        .unwrap_err();

        assert_eq!(
            error,
            MemoryProtocolError::ActionIsNotMemoryRetrieval {
                action_id: "action-1".to_string()
            }
        );
    }

    #[test]
    fn retrieval_protocol_uses_pointer_index_and_transcript_query() {
        let memory_store = memory_store();
        let request = memory_retrieval_request_from_action(
            &memory_action(),
            "request-1",
            TopicBundleClass::WorkspaceMap,
            TranscriptSliceQuery {
                session_id: Some("shell-session-1".to_string()),
                ..TranscriptSliceQuery::default()
            },
            1,
        )
        .unwrap();

        let trace = execute_memory_retrieval_protocol(&memory_store, &request).unwrap();
        assert_eq!(trace.bundle_refs, vec!["bundle-1".to_string()]);
        assert_eq!(trace.transcript_slice_refs, vec!["slice-1".to_string()]);
    }

    #[test]
    fn verified_update_round_trips_into_pointer_index_bundle() {
        let mut memory_store = memory_store();
        let record = record_verified_memory_update(
            &mut memory_store,
            "record-1",
            "shell-session-1",
            "shell-turn-3",
            "pointer-index-1",
            TopicBundleClass::GovernanceNotes,
            "verified shell outcome",
            vec!["bundle-1".to_string()],
            vec!["task-output-1".to_string()],
        )
        .unwrap();

        assert_eq!(record.output_bundle_id, "memory-bundle-record-1");
        assert!(
            memory_store
                .topic_bundle(&record.output_bundle_id)
                .is_some()
        );
        let continuity = build_shell_continuity_bundle(
            "continuity-1",
            "shell-session-1",
            memory_store.load_pointer_index("pointer-index-1").unwrap(),
            &[],
            &[record],
            vec!["contradiction-1".to_string()],
        );
        assert_eq!(
            continuity.verified_memory_refs,
            vec!["record-1".to_string()]
        );
        assert_eq!(
            continuity.contradiction_refs,
            vec!["contradiction-1".to_string()]
        );
    }
}
