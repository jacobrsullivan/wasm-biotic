use crate::execution::{CampaignId, EpochId, EventId, SessionId, TaskId, TurnId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventFamily {
    SessionLifecycleEvent,
    TurnLifecycleEvent,
    TaskLifecycleEvent,
    ActionProposalEvent,
    CapabilityDispatchEvent,
    WorkerDispatchEvent,
    ApprovalStateEvent,
    MemoryInteractionEvent,
    GovernanceDecisionEvent,
    CheckpointEvent,
    ComponentBuildEvent,
    ValidationExecutionEvent,
    ComparisonExecutionEvent,
    GenerationActivationEvent,
    SelfProductionEvent,
    ShellSessionEvent,
    ShellMembraneEvent,
    ShellMemoryEvent,
    ShellEvidenceEvent,
    ShellCompletionGateEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEvent {
    pub event_id: EventId,
    pub family: EventFamily,
    pub campaign_id: CampaignId,
    pub epoch_id: EpochId,
    pub session_id: SessionId,
    pub turn_id: Option<TurnId>,
    pub task_id: Option<TaskId>,
    pub detail: String,
}

impl ExecutionEvent {
    pub fn new(
        event_id: impl Into<EventId>,
        family: EventFamily,
        campaign_id: impl Into<CampaignId>,
        epoch_id: impl Into<EpochId>,
        session_id: impl Into<SessionId>,
        turn_id: Option<TurnId>,
        task_id: Option<TaskId>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            family,
            campaign_id: campaign_id.into(),
            epoch_id: epoch_id.into(),
            session_id: session_id.into(),
            turn_id,
            task_id,
            detail: detail.into(),
        }
    }

    pub fn matches_scope(&self, campaign_id: &str, epoch_id: &str, session_id: &str) -> bool {
        self.campaign_id == campaign_id
            && self.epoch_id == epoch_id
            && self.session_id == session_id
    }

    pub fn references_task(&self, task_id: &str) -> bool {
        self.task_id.as_deref() == Some(task_id)
    }
}
