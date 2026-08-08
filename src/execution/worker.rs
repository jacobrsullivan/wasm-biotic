use crate::execution::{
    ApprovalRequest, AuthorityClass, CampaignId, CapabilityEnvelopeId, CapabilityWorld, EpochId,
    HandoffId, IsolationProfile, MessageId, SessionId, TaskId, WorkerDispatchId, WorkerId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerRole {
    ObserverWorker,
    MutatorWorker,
    EvaluatorWorker,
    ReviewerWorker,
    ConsolidatorWorker,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageArtifactClass {
    DispatchMessage,
    ProgressMessage,
    RiskMessage,
    ResultMessage,
    ExceptionMessage,
    SynthesisRequestMessage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageArtifactStatus {
    Prepared,
    Sent,
    Received,
    Consumed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageArtifact {
    pub message_id: MessageId,
    pub campaign_id: CampaignId,
    pub epoch_id: EpochId,
    pub task_id: TaskId,
    pub sender_actor_ref: String,
    pub receiver_actor_ref: String,
    pub message_class: MessageArtifactClass,
    pub payload_summary: String,
    pub referenced_artifacts: Vec<String>,
    pub status: MessageArtifactStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityOperationRequest {
    pub world: CapabilityWorld,
    pub operation: String,
    pub resource_scope: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCard {
    pub worker_id: WorkerId,
    pub worker_role: WorkerRole,
    pub supported_task_kinds: Vec<String>,
    pub required_worlds: Vec<CapabilityWorld>,
    pub authority_ceiling: AuthorityClass,
    pub isolation_profile: IsolationProfile,
    pub result_contract: String,
    pub max_concurrency: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerDispatch {
    pub dispatch_id: WorkerDispatchId,
    pub task_id: TaskId,
    pub parent_session_id: SessionId,
    pub worker_id: WorkerId,
    pub worker_task_ref: String,
    pub capability_envelope_ref: CapabilityEnvelopeId,
    pub requested_capabilities: Vec<CapabilityOperationRequest>,
    pub dispatch_message: MessageArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellWorkerDispatch {
    pub shell_session_id: String,
    pub shell_turn_id: String,
    pub export_name: String,
    pub component_build_ref: String,
    pub dispatch: WorkerDispatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerDispatchOutcome {
    Dispatched,
    ApprovalRequired(ApprovalRequest),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerDispatchCheckpointOutcome {
    Dispatched(crate::execution::RunCheckpoint),
    ApprovalBlocked {
        approval_request: ApprovalRequest,
        checkpoint: crate::execution::RunCheckpoint,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerResult {
    pub dispatch_id: WorkerDispatchId,
    pub worker_id: WorkerId,
    pub worker_task_ref: String,
    pub result_ref: String,
    pub summary: String,
    pub result_message: MessageArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellWorkerResult {
    pub shell_session_id: String,
    pub shell_turn_id: String,
    pub worker_result: WorkerResult,
    pub action_trace_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SynthesisClosureDecision {
    Continue,
    Escalate,
    Complete,
    Fail,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisHandoff {
    pub handoff_id: HandoffId,
    pub task_id: TaskId,
    pub worker_output_refs: Vec<String>,
    pub supervisor_summary: String,
    pub next_action: String,
    pub closure_decision: SynthesisClosureDecision,
}
