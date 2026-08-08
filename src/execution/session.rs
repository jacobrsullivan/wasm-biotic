use crate::execution::proposals::ProposalFamily;
use crate::execution::{
    ActorId, ApprovalRequestId, BlockedReason, CampaignId, CapabilityEnvelopeId, CheckpointId,
    EpochId, SessionId, TaskId, TurnId, WorkerId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorKind {
    Supervisor,
    Worker,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionSessionState {
    Initialized,
    Ready,
    ExecutingTurn,
    AwaitingCapabilityResult,
    AwaitingWorkerResult,
    AwaitingApproval,
    Paused,
    Blocked,
    Completed,
    Failed,
    Terminated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TurnOutcome {
    Open,
    AwaitingCapabilityResult,
    AwaitingWorkerResult,
    AwaitingApproval,
    Paused,
    Blocked,
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnRecord {
    pub turn_id: TurnId,
    pub session_id: SessionId,
    pub turn_index: usize,
    pub proposal_families: Vec<ProposalFamily>,
    pub outcome: TurnOutcome,
}

impl TurnRecord {
    pub fn open(
        turn_id: impl Into<TurnId>,
        session_id: impl Into<SessionId>,
        turn_index: usize,
    ) -> Self {
        Self {
            turn_id: turn_id.into(),
            session_id: session_id.into(),
            turn_index,
            proposal_families: Vec::new(),
            outcome: TurnOutcome::Open,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSessionHeader {
    pub session_id: SessionId,
    pub actor_kind: ActorKind,
    pub actor_id: ActorId,
    pub campaign_id: CampaignId,
    pub epoch_id: EpochId,
    pub capability_envelope_ref: CapabilityEnvelopeId,
    pub parent_session_id: Option<SessionId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSession {
    pub header: ExecutionSessionHeader,
    pub state: ExecutionSessionState,
    pub active_task_id: Option<TaskId>,
    pub latest_checkpoint_ref: Option<CheckpointId>,
    pub blocked_reason: Option<BlockedReason>,
    pub outstanding_worker_refs: Vec<WorkerId>,
    pub pending_approval_refs: Vec<ApprovalRequestId>,
    pub current_turn: Option<TurnRecord>,
    pub turn_counter: usize,
}

impl ExecutionSession {
    pub fn new(header: ExecutionSessionHeader) -> Self {
        Self {
            header,
            state: ExecutionSessionState::Initialized,
            active_task_id: None,
            latest_checkpoint_ref: None,
            blocked_reason: None,
            outstanding_worker_refs: Vec::new(),
            pending_approval_refs: Vec::new(),
            current_turn: None,
            turn_counter: 0,
        }
    }
}
