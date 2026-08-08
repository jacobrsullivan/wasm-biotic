use crate::execution::failure_budget::FailureBudgetSnapshot;
use crate::execution::proposals::NormalizedProposal;
use crate::execution::session::{ExecutionSession, ExecutionSessionHeader, ExecutionSessionState};
use crate::execution::task::TaskArtifact;
use crate::execution::{
    ApprovalRequestId, BlockedReason, CheckpointId, MemoryArtifactId, TaskId, WorkerId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunCheckpoint {
    pub checkpoint_id: CheckpointId,
    pub session_header: ExecutionSessionHeader,
    pub session_state: ExecutionSessionState,
    pub active_task_refs: Vec<TaskId>,
    pub outstanding_proposals: Vec<NormalizedProposal>,
    pub blocked_reason: Option<BlockedReason>,
    pub outstanding_worker_refs: Vec<WorkerId>,
    pub pending_approval_refs: Vec<ApprovalRequestId>,
    pub memory_artifact_refs: Vec<MemoryArtifactId>,
    pub failure_budget: FailureBudgetSnapshot,
    pub idempotency_markers: Vec<String>,
}

impl RunCheckpoint {
    pub fn capture(
        checkpoint_id: impl Into<CheckpointId>,
        session: &ExecutionSession,
        task: Option<&TaskArtifact>,
        outstanding_proposals: Vec<NormalizedProposal>,
        memory_artifact_refs: Vec<MemoryArtifactId>,
        failure_budget: FailureBudgetSnapshot,
        idempotency_markers: Vec<String>,
    ) -> Self {
        let active_task_refs = task
            .map(|task| vec![task.task_id.clone()])
            .unwrap_or_default();

        Self {
            checkpoint_id: checkpoint_id.into(),
            session_header: session.header.clone(),
            session_state: session.state.clone(),
            active_task_refs,
            outstanding_proposals,
            blocked_reason: session.blocked_reason.clone(),
            outstanding_worker_refs: session.outstanding_worker_refs.clone(),
            pending_approval_refs: session.pending_approval_refs.clone(),
            memory_artifact_refs,
            failure_budget,
            idempotency_markers,
        }
    }

    pub fn matches_session(&self, session: &ExecutionSession) -> bool {
        self.session_header.session_id == session.header.session_id
            && self.session_header.campaign_id == session.header.campaign_id
            && self.session_header.epoch_id == session.header.epoch_id
    }

    pub fn references_task(&self, task_id: &str) -> bool {
        self.active_task_refs
            .iter()
            .any(|candidate| candidate == task_id)
    }

    pub fn tracks_approval(&self, approval_request_id: &str) -> bool {
        self.pending_approval_refs
            .iter()
            .any(|candidate| candidate == approval_request_id)
    }

    pub fn tracks_worker(&self, worker_id: &str) -> bool {
        self.outstanding_worker_refs
            .iter()
            .any(|candidate| candidate == worker_id)
    }
}
