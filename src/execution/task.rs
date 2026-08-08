use crate::execution::{BlockedReason, SessionId, TaskId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Created,
    Ready,
    Running,
    BlockedOnCapability,
    BlockedOnWorker,
    BlockedOnApproval,
    Paused,
    Completed,
    Failed,
    Canceled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskArtifact {
    pub task_id: TaskId,
    pub state: TaskState,
    pub owner_session_id: Option<SessionId>,
    pub blocked_reason: Option<BlockedReason>,
    pub summary: String,
    pub output_refs: Vec<String>,
}

impl TaskArtifact {
    pub fn new(task_id: impl Into<TaskId>, summary: impl Into<String>) -> Self {
        Self {
            task_id: task_id.into(),
            state: TaskState::Created,
            owner_session_id: None,
            blocked_reason: None,
            summary: summary.into(),
            output_refs: Vec::new(),
        }
    }

    pub fn record_output_ref(&mut self, output_ref: impl Into<String>) {
        self.output_refs.push(output_ref.into());
    }
}
