use crate::execution::governance::ShellActionDecisionStatus;
use crate::execution::shell::{ShellSessionBundle, ShellSessionState};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellEvidenceCompletenessStatus {
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellEvidencePacket {
    pub packet_id: String,
    pub shell_session_ref: String,
    pub shell_session_bundle_ref: String,
    pub turn_refs: Vec<String>,
    pub pause_resume_refs: Vec<String>,
    pub membrane_trace_refs: Vec<String>,
    pub memory_trace_refs: Vec<String>,
    pub verified_memory_refs: Vec<String>,
    pub orchestration_trace_refs: Vec<String>,
    pub denial_refs: Vec<String>,
    pub completeness_status: ShellEvidenceCompletenessStatus,
    pub claim: String,
    pub bounded_scope_statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellWorkspaceView {
    pub packet_id: String,
    pub shell_session_id: String,
    pub session_state: String,
    pub turn_count: usize,
    pub approval_pause_count: usize,
    pub membrane_decision_count: usize,
    pub memory_trace_count: usize,
    pub verified_memory_count: usize,
    pub orchestration_count: usize,
    pub denial_count: usize,
    pub claim: String,
}

pub fn assemble_shell_evidence_packet(
    packet_id: impl Into<String>,
    shell_session_bundle_ref: impl Into<String>,
    bundle: &ShellSessionBundle,
) -> ShellEvidencePacket {
    let packet_id = packet_id.into();
    let shell_session_bundle_ref = shell_session_bundle_ref.into();
    let pause_resume_refs = bundle
        .approval_pause_records
        .iter()
        .map(|record| record.pause_id.clone())
        .chain(
            bundle
                .resume_anchors
                .iter()
                .filter(|anchor| !anchor.active)
                .map(|anchor| anchor.resume_anchor_id.clone()),
        )
        .collect::<Vec<_>>();
    let membrane_trace_refs = bundle
        .action_traces
        .iter()
        .map(|trace| trace.request.action_id.clone())
        .collect::<Vec<_>>();
    let memory_trace_refs = bundle
        .memory_retrieval_traces
        .iter()
        .map(|trace| trace.trace_id.clone())
        .collect::<Vec<_>>();
    let verified_memory_refs = bundle
        .verified_memory_updates
        .iter()
        .map(|record| record.record_id.clone())
        .collect::<Vec<_>>();
    let orchestration_trace_refs = bundle
        .orchestration_records
        .iter()
        .map(|record| record.orchestration_id.clone())
        .collect::<Vec<_>>();
    let denial_refs = bundle
        .denial_packets
        .iter()
        .map(|packet| packet.denial_id.clone())
        .collect::<Vec<_>>();
    let has_completed_session = bundle.shell_session.state == ShellSessionState::Completed;
    let has_pause_and_resume = !bundle.approval_pause_records.is_empty()
        && bundle.resume_anchors.iter().any(|anchor| !anchor.active);
    let has_membrane = !membrane_trace_refs.is_empty()
        && bundle
            .action_traces
            .iter()
            .any(|trace| trace.decision.status == ShellActionDecisionStatus::Allowed);
    let has_memory = !memory_trace_refs.is_empty() && !verified_memory_refs.is_empty();
    let has_orchestration = !orchestration_trace_refs.is_empty();
    let completeness_status = if has_completed_session
        && has_pause_and_resume
        && has_membrane
        && has_memory
        && has_orchestration
        && bundle.continuity_bundle.is_some()
    {
        ShellEvidenceCompletenessStatus::Complete
    } else {
        ShellEvidenceCompletenessStatus::Incomplete
    };

    ShellEvidencePacket {
        packet_id,
        shell_session_ref: bundle.shell_session.shell_session_id.clone(),
        shell_session_bundle_ref,
        turn_refs: bundle
            .shell_turns
            .iter()
            .map(|turn| turn.shell_turn_id.clone())
            .collect(),
        pause_resume_refs,
        membrane_trace_refs,
        memory_trace_refs,
        verified_memory_refs,
        orchestration_trace_refs,
        denial_refs,
        completeness_status,
        claim: match completeness_status {
            ShellEvidenceCompletenessStatus::Complete => {
                "bounded component-native supervisory shell evidence packet complete".to_string()
            }
            ShellEvidenceCompletenessStatus::Incomplete => {
                "bounded component-native supervisory shell evidence packet incomplete"
                    .to_string()
            }
        },
        bounded_scope_statement:
            "covers a single-factory bounded worker shell and does not imply hosted autonomy, rich tool worlds, or federation"
                .to_string(),
    }
}

pub fn build_shell_workspace_view(
    packet: &ShellEvidencePacket,
    bundle: &ShellSessionBundle,
) -> ShellWorkspaceView {
    ShellWorkspaceView {
        packet_id: packet.packet_id.clone(),
        shell_session_id: bundle.shell_session.shell_session_id.clone(),
        session_state: format!("{:?}", bundle.shell_session.state),
        turn_count: bundle.shell_turns.len(),
        approval_pause_count: bundle.approval_pause_records.len(),
        membrane_decision_count: bundle.action_decisions.len(),
        memory_trace_count: bundle.memory_retrieval_traces.len(),
        verified_memory_count: bundle.verified_memory_updates.len(),
        orchestration_count: bundle.orchestration_records.len(),
        denial_count: bundle.denial_packets.len(),
        claim: packet.claim.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ShellEvidenceCompletenessStatus, assemble_shell_evidence_packet, build_shell_workspace_view,
    };
    use crate::execution::events::{EventFamily, ExecutionEvent};
    use crate::execution::failure_budget::FailureBudget;
    use crate::execution::memory::MemoryStore;
    use crate::execution::orchestration::TaskGraph;
    use crate::execution::session::{ActorKind, ExecutionSession, ExecutionSessionHeader};
    use crate::execution::shell::{ShellSessionBundle, ShellSessionRecord, ShellSessionState};
    use crate::execution::storage::ReplayableRuntimeState;
    use crate::execution::task::{TaskArtifact, TaskState};

    fn empty_bundle() -> ShellSessionBundle {
        let session = ExecutionSession::new(ExecutionSessionHeader {
            session_id: "session-1".to_string(),
            actor_kind: ActorKind::Worker,
            actor_id: "worker-1".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            capability_envelope_ref: "envelope-1".to_string(),
            parent_session_id: None,
        });
        let runtime_state = ReplayableRuntimeState::new(
            session,
            TaskArtifact {
                state: TaskState::Ready,
                ..TaskArtifact::new("task-1", "root")
            },
            TaskGraph::new("task-1", Vec::new()),
            MemoryStore::default(),
            None,
            vec![ExecutionEvent::new(
                "event-1",
                EventFamily::ShellSessionEvent,
                "campaign-1",
                "epoch-1",
                "session-1",
                None,
                Some("task-1".to_string()),
                "shell session opened",
            )],
        );

        ShellSessionBundle {
            shell_session: ShellSessionRecord {
                shell_session_id: "shell-session-1".to_string(),
                execution_session_ref: "session-1".to_string(),
                worker_id: "worker-1".to_string(),
                task_id: "task-1".to_string(),
                capability_envelope_ref: "envelope-1".to_string(),
                agenda_item_ref: None,
                state: ShellSessionState::Ready,
                latest_turn_ref: None,
                latest_checkpoint_ref: None,
                latest_resume_anchor_ref: None,
                retry_budget: FailureBudget::default().snapshot(),
            },
            shell_turns: Vec::new(),
            shell_checkpoints: Vec::new(),
            resume_anchors: Vec::new(),
            action_decisions: Vec::new(),
            action_traces: Vec::new(),
            approval_pause_records: Vec::new(),
            denial_packets: Vec::new(),
            memory_retrieval_traces: Vec::new(),
            verified_memory_updates: Vec::new(),
            continuity_bundle: None,
            orchestration_records: Vec::new(),
            retry_records: Vec::new(),
            runtime_state,
        }
    }

    #[test]
    fn incomplete_packet_is_marked_incomplete() {
        let bundle = empty_bundle();
        let packet = assemble_shell_evidence_packet("packet-1", "bundle-1", &bundle);
        assert_eq!(
            packet.completeness_status,
            ShellEvidenceCompletenessStatus::Incomplete
        );
    }

    #[test]
    fn workspace_view_uses_kernel_owned_packet_data() {
        let bundle = empty_bundle();
        let packet = assemble_shell_evidence_packet("packet-1", "bundle-1", &bundle);
        let workspace = build_shell_workspace_view(&packet, &bundle);
        assert_eq!(workspace.packet_id, "packet-1");
        assert_eq!(workspace.shell_session_id, "shell-session-1");
    }
}
