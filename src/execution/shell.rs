use crate::execution::component::ComponentExecutionContext;
use crate::execution::events::{EventFamily, ExecutionEvent};
use crate::execution::failure_budget::{
    FailureBudget, FailureBudgetSnapshot, RetryClass, ShellRetryRecord, apply_shell_retry,
};
use crate::execution::governance::{
    ApprovalDecision, ApprovalRequest, ShellActionDecision, ShellApprovalPauseRecord,
    ShellDenialPacket, persist_approval_decision_bundle, persist_approval_request_bundle,
};
use crate::execution::memory::{MemoryArtifactPayload, TopicBundleClass};
use crate::execution::memory_protocol::{
    MemoryProtocolError, MemoryRetrievalTrace, ShellContinuityBundle, VerifiedMemoryUpdateRecord,
    build_shell_continuity_bundle, execute_memory_retrieval_protocol,
    memory_retrieval_request_from_action, record_verified_memory_update,
};
use crate::execution::orchestration::{
    OrchestrationError, ShellOrchestrationRecord, complete_shell_session_agenda_item,
    dispatch_shell_session_to_agenda_item,
};
use crate::execution::storage::ReplayableRuntimeState;
use crate::execution::task::TaskState;
use crate::execution::transition::{
    TransitionError, apply_approval_decision, checkpointed_block_on_approval, complete_task,
    conclude_turn_ready, fail_task, start_turn,
};
use crate::execution::worker::{SynthesisClosureDecision, SynthesisHandoff};
use crate::execution::worker_world::{
    WorkerActionTrace, WorkerTurnExecution, WorkerWorldError, WorkerWorldKind, execute_worker_turn,
};
use crate::execution::{
    AgendaItemId, BlockedReason, CheckpointId, ExecutionSessionState, TurnId, bind_session_ready,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellSessionState {
    Created,
    Ready,
    RunningTurn,
    PausedForApproval,
    Denied,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellTurnState {
    Planned,
    Running,
    AwaitingApproval,
    Resumed,
    Denied,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellTaskState {
    Planned,
    Ready,
    Running,
    AwaitingApproval,
    Denied,
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellSessionRecord {
    pub shell_session_id: String,
    pub execution_session_ref: String,
    pub worker_id: String,
    pub task_id: String,
    pub capability_envelope_ref: String,
    pub agenda_item_ref: Option<AgendaItemId>,
    pub state: ShellSessionState,
    pub latest_turn_ref: Option<TurnId>,
    pub latest_checkpoint_ref: Option<CheckpointId>,
    pub latest_resume_anchor_ref: Option<String>,
    pub retry_budget: FailureBudgetSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellTurnRecord {
    pub shell_turn_id: String,
    pub shell_session_id: String,
    pub turn_index: usize,
    pub export_name: String,
    pub state: ShellTurnState,
    pub component_result_ref: Option<String>,
    pub invoked_imports: Vec<String>,
    pub import_link_audits: Vec<crate::execution::ComponentImportLinkAudit>,
    pub action_trace_refs: Vec<String>,
    pub checkpoint_ref: Option<String>,
    pub denial_ref: Option<String>,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellCheckpointRecord {
    pub shell_checkpoint_id: String,
    pub shell_session_id: String,
    pub shell_turn_id: String,
    pub runtime_checkpoint_ref: String,
    pub session_state: ExecutionSessionState,
    pub task_state: TaskState,
    pub blocked_reason: Option<BlockedReason>,
    pub failure_budget: FailureBudgetSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellResumeAnchor {
    pub resume_anchor_id: String,
    pub shell_session_id: String,
    pub shell_turn_id: String,
    pub checkpoint_ref: String,
    pub approval_request_ref: String,
    pub active: bool,
    pub resumed_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellSessionBundle {
    pub shell_session: ShellSessionRecord,
    pub shell_turns: Vec<ShellTurnRecord>,
    pub shell_checkpoints: Vec<ShellCheckpointRecord>,
    pub resume_anchors: Vec<ShellResumeAnchor>,
    pub action_decisions: Vec<ShellActionDecision>,
    pub action_traces: Vec<WorkerActionTrace>,
    pub approval_pause_records: Vec<ShellApprovalPauseRecord>,
    pub denial_packets: Vec<ShellDenialPacket>,
    pub memory_retrieval_traces: Vec<MemoryRetrievalTrace>,
    pub verified_memory_updates: Vec<VerifiedMemoryUpdateRecord>,
    pub continuity_bundle: Option<ShellContinuityBundle>,
    pub orchestration_records: Vec<ShellOrchestrationRecord>,
    pub retry_records: Vec<ShellRetryRecord>,
    pub runtime_state: ReplayableRuntimeState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellRuntimeError {
    InvalidShellState(String),
    MissingActiveTurn,
    MissingResumeAnchor { approval_request_ref: String },
    MissingPointerIndex { pointer_index_ref: String },
    Transition(TransitionError),
    WorkerWorld(WorkerWorldError),
    MemoryProtocol(MemoryProtocolError),
    Orchestration(OrchestrationError),
}

impl From<TransitionError> for ShellRuntimeError {
    fn from(value: TransitionError) -> Self {
        Self::Transition(value)
    }
}

impl From<WorkerWorldError> for ShellRuntimeError {
    fn from(value: WorkerWorldError) -> Self {
        Self::WorkerWorld(value)
    }
}

impl From<MemoryProtocolError> for ShellRuntimeError {
    fn from(value: MemoryProtocolError) -> Self {
        Self::MemoryProtocol(value)
    }
}

impl From<OrchestrationError> for ShellRuntimeError {
    fn from(value: OrchestrationError) -> Self {
        Self::Orchestration(value)
    }
}

impl Display for ShellRuntimeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidShellState(message) => write!(f, "invalid shell state: {message}"),
            Self::MissingActiveTurn => write!(f, "shell runtime requires an active turn"),
            Self::MissingResumeAnchor {
                approval_request_ref,
            } => write!(
                f,
                "shell runtime could not locate a resume anchor for approval request {approval_request_ref}"
            ),
            Self::MissingPointerIndex { pointer_index_ref } => {
                write!(
                    f,
                    "pointer index is missing from shell memory: {pointer_index_ref}"
                )
            }
            Self::Transition(error) => write!(f, "{error}"),
            Self::WorkerWorld(error) => write!(f, "{error}"),
            Self::MemoryProtocol(error) => write!(f, "{error}"),
            Self::Orchestration(error) => write!(f, "{error:?}"),
        }
    }
}

impl Error for ShellRuntimeError {}

pub fn open_shell_session_bundle(
    shell_session_id: impl Into<String>,
    worker_id: impl Into<String>,
    agenda_item_ref: Option<AgendaItemId>,
    mut runtime_state: ReplayableRuntimeState,
    failure_budget: &FailureBudget,
) -> Result<ShellSessionBundle, ShellRuntimeError> {
    if runtime_state.session.state == ExecutionSessionState::Initialized {
        bind_session_ready(&mut runtime_state.session)?;
        runtime_state.root_task.state = TaskState::Ready;
    }
    runtime_state.validate_replayability().map_err(|error| {
        ShellRuntimeError::InvalidShellState(format!("runtime state is not replayable: {error}"))
    })?;

    let shell_session = ShellSessionRecord {
        shell_session_id: shell_session_id.into(),
        execution_session_ref: runtime_state.session.header.session_id.clone(),
        worker_id: worker_id.into(),
        task_id: runtime_state.root_task.task_id.clone(),
        capability_envelope_ref: runtime_state.session.header.capability_envelope_ref.clone(),
        agenda_item_ref,
        state: shell_state_from_execution(&runtime_state.session.state),
        latest_turn_ref: None,
        latest_checkpoint_ref: runtime_state.session.latest_checkpoint_ref.clone(),
        latest_resume_anchor_ref: None,
        retry_budget: failure_budget.snapshot(),
    };

    runtime_state.event_log.push(ExecutionEvent::new(
        format!(
            "event-shell-session-open-{}",
            shell_session.shell_session_id
        ),
        EventFamily::ShellSessionEvent,
        runtime_state.session.header.campaign_id.clone(),
        runtime_state.session.header.epoch_id.clone(),
        runtime_state.session.header.session_id.clone(),
        None,
        Some(runtime_state.root_task.task_id.clone()),
        format!("shell session {} opened", shell_session.shell_session_id),
    ));

    Ok(ShellSessionBundle {
        shell_session,
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
    })
}

pub fn dispatch_shell_session(
    bundle: &mut ShellSessionBundle,
    agenda_item_id: &str,
) -> Result<ShellOrchestrationRecord, ShellRuntimeError> {
    let record = dispatch_shell_session_to_agenda_item(
        &mut bundle.runtime_state.task_graph,
        agenda_item_id,
        bundle.shell_session.shell_session_id.clone(),
        bundle.shell_session.worker_id.clone(),
        bundle.shell_session.retry_budget.clone(),
    )?;
    bundle.shell_session.agenda_item_ref = Some(agenda_item_id.to_string());
    bundle.orchestration_records.push(record.clone());
    Ok(record)
}

pub fn start_shell_turn(
    bundle: &mut ShellSessionBundle,
    shell_turn_id: impl Into<String>,
    export_name: impl Into<String>,
) -> Result<ShellTurnRecord, ShellRuntimeError> {
    if bundle.shell_session.state != ShellSessionState::Ready {
        return Err(ShellRuntimeError::InvalidShellState(format!(
            "shell session must be ready to start a turn, got {:?}",
            bundle.shell_session.state
        )));
    }

    let shell_turn_id = shell_turn_id.into();
    let export_name = export_name.into();
    start_turn(
        &mut bundle.runtime_state.session,
        &mut bundle.runtime_state.root_task,
        shell_turn_id.clone(),
    )?;
    let turn_record = ShellTurnRecord {
        shell_turn_id: shell_turn_id.clone(),
        shell_session_id: bundle.shell_session.shell_session_id.clone(),
        turn_index: bundle.runtime_state.session.turn_counter,
        export_name: export_name.clone(),
        state: ShellTurnState::Running,
        component_result_ref: None,
        invoked_imports: Vec::new(),
        import_link_audits: Vec::new(),
        action_trace_refs: Vec::new(),
        checkpoint_ref: None,
        denial_ref: None,
        diagnostics: Vec::new(),
    };
    bundle.shell_session.state = ShellSessionState::RunningTurn;
    bundle.shell_session.latest_turn_ref = Some(shell_turn_id.clone());
    bundle.runtime_state.event_log.push(ExecutionEvent::new(
        format!("event-shell-turn-start-{shell_turn_id}"),
        EventFamily::TurnLifecycleEvent,
        bundle.runtime_state.session.header.campaign_id.clone(),
        bundle.runtime_state.session.header.epoch_id.clone(),
        bundle.runtime_state.session.header.session_id.clone(),
        Some(shell_turn_id.clone()),
        Some(bundle.runtime_state.root_task.task_id.clone()),
        format!("shell turn {shell_turn_id} started export {export_name}"),
    ));
    bundle.shell_turns.push(turn_record.clone());
    Ok(turn_record)
}

pub fn execute_active_shell_turn(
    bundle: &mut ShellSessionBundle,
    component_bytes: &[u8],
    context: &ComponentExecutionContext,
    failure_budget: &mut FailureBudget,
) -> Result<WorkerTurnExecution, ShellRuntimeError> {
    let turn = bundle
        .shell_turns
        .last_mut()
        .ok_or(ShellRuntimeError::MissingActiveTurn)?;
    if turn.state != ShellTurnState::Running {
        return Err(ShellRuntimeError::InvalidShellState(format!(
            "shell turn must be running to execute, got {:?}",
            turn.state
        )));
    }

    let execution = execute_worker_turn(
        bundle.shell_session.shell_session_id.clone(),
        turn.shell_turn_id.clone(),
        bundle.runtime_state.session.header.campaign_id.clone(),
        bundle.runtime_state.session.header.epoch_id.clone(),
        bundle.runtime_state.session.header.session_id.clone(),
        bundle.runtime_state.root_task.task_id.clone(),
        component_bytes,
        turn.export_name.clone(),
        context,
    )?;

    let turn_id_for_events = turn.shell_turn_id.clone();
    if let Some(component_trace) = &execution.component_trace {
        turn.component_result_ref = Some(component_trace.result_ref.clone());
        turn.invoked_imports = component_trace.invoked_imports.clone();
        turn.import_link_audits = component_trace.import_link_audits.clone();
        turn.diagnostics.extend(component_trace.diagnostics.clone());
    }

    let action_trace_refs = execution
        .action_traces
        .iter()
        .map(|trace| trace.request.action_id.clone())
        .collect::<Vec<_>>();
    turn.action_trace_refs.extend(action_trace_refs);
    let component_result_ref = turn.component_result_ref.clone();
    let _ = turn;

    for action_trace in &execution.action_traces {
        bundle.action_decisions.push(action_trace.decision.clone());
        bundle.action_traces.push(action_trace.clone());
        bundle.runtime_state.event_log.push(ExecutionEvent::new(
            format!("event-shell-action-{}", action_trace.request.action_id),
            EventFamily::ShellMembraneEvent,
            bundle.runtime_state.session.header.campaign_id.clone(),
            bundle.runtime_state.session.header.epoch_id.clone(),
            bundle.runtime_state.session.header.session_id.clone(),
            Some(turn_id_for_events.clone()),
            Some(bundle.runtime_state.root_task.task_id.clone()),
            format!(
                "worker action {} resolved as {:?}",
                action_trace.request.action_id, action_trace.decision.status
            ),
        ));
    }

    if let Some(approval_request) = &execution.approval_request {
        pause_shell_turn_for_approval(bundle, failure_budget.snapshot(), approval_request)?;
        if let Some(turn) = bundle.shell_turns.last_mut() {
            turn.state = ShellTurnState::AwaitingApproval;
        }
        bundle.shell_session.state = ShellSessionState::PausedForApproval;
        return Ok(execution);
    }

    if let Some(denial_packet) = &execution.denial_packet {
        record_shell_denial(bundle, failure_budget, denial_packet.clone())?;
        if let Some(turn) = bundle.shell_turns.last_mut() {
            turn.state = ShellTurnState::Denied;
            turn.denial_ref = Some(denial_packet.denial_id.clone());
        }
        bundle.shell_session.state = ShellSessionState::Denied;
        return Ok(execution);
    }

    for action_trace in &execution.action_traces {
        if action_trace.request.world_kind == WorkerWorldKind::MemoryRetrieval
            && action_trace.decision.status
                == crate::execution::governance::ShellActionDecisionStatus::Allowed
        {
            let retrieval_request = memory_retrieval_request_from_action(
                &action_trace.request,
                format!("retrieval-{}", action_trace.request.action_id),
                TopicBundleClass::WorkspaceMap,
                Default::default(),
                8,
            )?;
            let trace = execute_memory_retrieval_protocol(
                &bundle.runtime_state.memory_store,
                &retrieval_request,
            )?;
            bundle.runtime_state.event_log.push(ExecutionEvent::new(
                format!("event-shell-memory-{}", trace.trace_id),
                EventFamily::ShellMemoryEvent,
                bundle.runtime_state.session.header.campaign_id.clone(),
                bundle.runtime_state.session.header.epoch_id.clone(),
                bundle.runtime_state.session.header.session_id.clone(),
                Some(turn_id_for_events.clone()),
                Some(bundle.runtime_state.root_task.task_id.clone()),
                format!("memory retrieval {} completed", trace.trace_id),
            ));
            bundle.memory_retrieval_traces.push(trace);
        }
    }

    if execution.completed_task {
        if let Some(result_ref) = component_result_ref {
            bundle
                .runtime_state
                .root_task
                .record_output_ref(result_ref.clone());
        }
        complete_task(
            &mut bundle.runtime_state.session,
            &mut bundle.runtime_state.root_task,
        )?;
        if let Some(turn) = bundle.shell_turns.last_mut() {
            turn.state = ShellTurnState::Completed;
        }
        bundle.shell_session.state = ShellSessionState::Completed;
    } else {
        conclude_turn_ready(
            &mut bundle.runtime_state.session,
            &mut bundle.runtime_state.root_task,
        )?;
        if let Some(turn) = bundle.shell_turns.last_mut() {
            turn.state = ShellTurnState::Completed;
        }
        bundle.shell_session.state = ShellSessionState::Ready;
    }

    Ok(execution)
}

fn pause_shell_turn_for_approval(
    bundle: &mut ShellSessionBundle,
    failure_budget: FailureBudgetSnapshot,
    approval_request: &ApprovalRequest,
) -> Result<(), ShellRuntimeError> {
    let turn = bundle
        .shell_turns
        .last_mut()
        .ok_or(ShellRuntimeError::MissingActiveTurn)?;
    let checkpoint_id = format!("shell-checkpoint-{}", turn.shell_turn_id);
    let checkpoint = checkpointed_block_on_approval(
        &mut bundle.runtime_state.session,
        &mut bundle.runtime_state.root_task,
        approval_request.approval_request_id.clone(),
        format!("approval requested by shell turn {}", turn.shell_turn_id),
        checkpoint_id.clone(),
        Vec::new(),
        Vec::new(),
        failure_budget.clone(),
        vec![format!("shell-turn:{}", turn.shell_turn_id)],
    )?;
    bundle.runtime_state.latest_checkpoint = Some(checkpoint.clone());
    bundle
        .runtime_state
        .memory_store
        .persist_checkpoint_artifact(
            format!("memory-checkpoint-{}", checkpoint.checkpoint_id),
            checkpoint.clone(),
            format!("shell checkpoint {} persisted", checkpoint.checkpoint_id),
        );
    let _ = persist_approval_request_bundle(
        &mut bundle.runtime_state.memory_store,
        approval_request,
        &checkpoint,
    );

    let shell_checkpoint = ShellCheckpointRecord {
        shell_checkpoint_id: checkpoint_id.clone(),
        shell_session_id: bundle.shell_session.shell_session_id.clone(),
        shell_turn_id: turn.shell_turn_id.clone(),
        runtime_checkpoint_ref: checkpoint.checkpoint_id.clone(),
        session_state: bundle.runtime_state.session.state.clone(),
        task_state: bundle.runtime_state.root_task.state.clone(),
        blocked_reason: bundle.runtime_state.session.blocked_reason.clone(),
        failure_budget,
    };
    let anchor = ShellResumeAnchor {
        resume_anchor_id: format!("shell-resume-anchor-{}", turn.shell_turn_id),
        shell_session_id: bundle.shell_session.shell_session_id.clone(),
        shell_turn_id: turn.shell_turn_id.clone(),
        checkpoint_ref: checkpoint.checkpoint_id.clone(),
        approval_request_ref: approval_request.approval_request_id.clone(),
        active: true,
        resumed_by: None,
    };
    let pause_record = ShellApprovalPauseRecord {
        pause_id: format!("shell-pause-{}", turn.shell_turn_id),
        shell_session_id: bundle.shell_session.shell_session_id.clone(),
        shell_turn_id: turn.shell_turn_id.clone(),
        approval_request_ref: approval_request.approval_request_id.clone(),
        checkpoint_ref: checkpoint.checkpoint_id.clone(),
        rationale: "worker requested approval through the bounded shell membrane".to_string(),
    };

    turn.checkpoint_ref = Some(checkpoint.checkpoint_id.clone());
    bundle.shell_session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());
    bundle.shell_session.latest_resume_anchor_ref = Some(anchor.resume_anchor_id.clone());
    bundle.shell_checkpoints.push(shell_checkpoint);
    bundle.resume_anchors.push(anchor);
    bundle.approval_pause_records.push(pause_record);
    bundle.runtime_state.event_log.push(ExecutionEvent::new(
        format!("event-shell-pause-{}", turn.shell_turn_id),
        EventFamily::ApprovalStateEvent,
        bundle.runtime_state.session.header.campaign_id.clone(),
        bundle.runtime_state.session.header.epoch_id.clone(),
        bundle.runtime_state.session.header.session_id.clone(),
        Some(turn.shell_turn_id.clone()),
        Some(bundle.runtime_state.root_task.task_id.clone()),
        format!(
            "shell turn {} paused on approval {}",
            turn.shell_turn_id, approval_request.approval_request_id
        ),
    ));
    Ok(())
}

fn record_shell_denial(
    bundle: &mut ShellSessionBundle,
    failure_budget: &mut FailureBudget,
    denial_packet: ShellDenialPacket,
) -> Result<(), ShellRuntimeError> {
    let turn = bundle
        .shell_turns
        .last()
        .ok_or(ShellRuntimeError::MissingActiveTurn)?;
    fail_task(
        &mut bundle.runtime_state.session,
        &mut bundle.runtime_state.root_task,
    )?;
    bundle.retry_records.push(apply_shell_retry(
        failure_budget,
        bundle.shell_session.shell_session_id.clone(),
        turn.shell_turn_id.clone(),
        RetryClass::PolicyNonRetryable,
    ));
    bundle.runtime_state.event_log.push(ExecutionEvent::new(
        format!("event-shell-denial-{}", denial_packet.denial_id),
        EventFamily::GovernanceDecisionEvent,
        bundle.runtime_state.session.header.campaign_id.clone(),
        bundle.runtime_state.session.header.epoch_id.clone(),
        bundle.runtime_state.session.header.session_id.clone(),
        Some(turn.shell_turn_id.clone()),
        Some(bundle.runtime_state.root_task.task_id.clone()),
        format!("shell denial {} recorded", denial_packet.denial_id),
    ));
    bundle.denial_packets.push(denial_packet);
    Ok(())
}

pub fn resume_shell_session_from_approval(
    bundle: &mut ShellSessionBundle,
    approval_decision: &ApprovalDecision,
    resumed_by: impl Into<String>,
) -> Result<(), ShellRuntimeError> {
    apply_approval_decision(
        &mut bundle.runtime_state.session,
        &mut bundle.runtime_state.root_task,
        approval_decision,
    )?;
    let anchor = bundle
        .resume_anchors
        .iter_mut()
        .find(|anchor| {
            anchor.approval_request_ref == approval_decision.approval_request_id && anchor.active
        })
        .ok_or_else(|| ShellRuntimeError::MissingResumeAnchor {
            approval_request_ref: approval_decision.approval_request_id.clone(),
        })?;
    anchor.active = false;
    anchor.resumed_by = Some(resumed_by.into());
    if let Some(turn) = bundle
        .shell_turns
        .iter_mut()
        .find(|turn| turn.shell_turn_id == anchor.shell_turn_id)
    {
        turn.state = ShellTurnState::Resumed;
    }
    let _ = persist_approval_decision_bundle(
        &mut bundle.runtime_state.memory_store,
        approval_decision,
        &[],
    );
    bundle.shell_session.state = ShellSessionState::Ready;
    bundle.runtime_state.event_log.push(ExecutionEvent::new(
        format!(
            "event-shell-resume-{}",
            approval_decision.approval_request_id
        ),
        EventFamily::ApprovalStateEvent,
        bundle.runtime_state.session.header.campaign_id.clone(),
        bundle.runtime_state.session.header.epoch_id.clone(),
        bundle.runtime_state.session.header.session_id.clone(),
        Some(anchor.shell_turn_id.clone()),
        Some(bundle.runtime_state.root_task.task_id.clone()),
        format!(
            "shell session resumed from approval {}",
            approval_decision.approval_request_id
        ),
    ));
    Ok(())
}

pub fn record_shell_verified_memory_update(
    bundle: &mut ShellSessionBundle,
    record_id: impl Into<String>,
    pointer_index_ref: &str,
    bundle_class: TopicBundleClass,
    summary: impl Into<String>,
    evidence_refs: Vec<String>,
    verification_refs: Vec<String>,
) -> Result<VerifiedMemoryUpdateRecord, ShellRuntimeError> {
    let turn = bundle
        .shell_turns
        .last()
        .ok_or(ShellRuntimeError::MissingActiveTurn)?;
    if bundle
        .runtime_state
        .memory_store
        .load_pointer_index(pointer_index_ref)
        .is_none()
    {
        return Err(ShellRuntimeError::MissingPointerIndex {
            pointer_index_ref: pointer_index_ref.to_string(),
        });
    }
    let record = record_verified_memory_update(
        &mut bundle.runtime_state.memory_store,
        record_id,
        bundle.shell_session.shell_session_id.clone(),
        turn.shell_turn_id.clone(),
        pointer_index_ref.to_string(),
        bundle_class,
        summary,
        evidence_refs,
        verification_refs,
    )?;
    bundle.verified_memory_updates.push(record.clone());
    Ok(record)
}

pub fn finalize_shell_continuity_bundle(
    bundle: &mut ShellSessionBundle,
    continuity_id: impl Into<String>,
    pointer_index_ref: &str,
    contradiction_refs: Vec<String>,
) -> Result<ShellContinuityBundle, ShellRuntimeError> {
    let pointer_index = bundle
        .runtime_state
        .memory_store
        .load_pointer_index(pointer_index_ref)
        .ok_or_else(|| ShellRuntimeError::MissingPointerIndex {
            pointer_index_ref: pointer_index_ref.to_string(),
        })?;
    let continuity_bundle = build_shell_continuity_bundle(
        continuity_id,
        bundle.shell_session.shell_session_id.clone(),
        pointer_index,
        &bundle.memory_retrieval_traces,
        &bundle.verified_memory_updates,
        contradiction_refs,
    );
    bundle.continuity_bundle = Some(continuity_bundle.clone());
    Ok(continuity_bundle)
}

pub fn complete_shell_orchestration(
    bundle: &mut ShellSessionBundle,
    agenda_item_id: &str,
) -> Result<ShellOrchestrationRecord, ShellRuntimeError> {
    let turn = bundle
        .shell_turns
        .last()
        .ok_or(ShellRuntimeError::MissingActiveTurn)?;
    let handoff = SynthesisHandoff {
        handoff_id: format!("shell-handoff-{}", turn.shell_turn_id),
        task_id: bundle.runtime_state.root_task.task_id.clone(),
        worker_output_refs: bundle.runtime_state.root_task.output_refs.clone(),
        supervisor_summary: format!(
            "shell session {} completed",
            bundle.shell_session.shell_session_id
        ),
        next_action: "record-evidence".to_string(),
        closure_decision: SynthesisClosureDecision::Complete,
    };
    let record = complete_shell_session_agenda_item(
        &mut bundle.runtime_state.task_graph,
        agenda_item_id,
        bundle.shell_session.shell_session_id.clone(),
        bundle.shell_session.worker_id.clone(),
        bundle.shell_session.retry_budget.clone(),
        &handoff,
    )?;
    bundle.orchestration_records.push(record.clone());
    Ok(record)
}

pub fn shell_state_from_execution(state: &ExecutionSessionState) -> ShellSessionState {
    match state {
        ExecutionSessionState::Initialized => ShellSessionState::Created,
        ExecutionSessionState::Ready => ShellSessionState::Ready,
        ExecutionSessionState::ExecutingTurn => ShellSessionState::RunningTurn,
        ExecutionSessionState::AwaitingApproval | ExecutionSessionState::Paused => {
            ShellSessionState::PausedForApproval
        }
        ExecutionSessionState::Completed => ShellSessionState::Completed,
        ExecutionSessionState::Failed | ExecutionSessionState::Terminated => {
            ShellSessionState::Failed
        }
        ExecutionSessionState::AwaitingCapabilityResult
        | ExecutionSessionState::AwaitingWorkerResult
        | ExecutionSessionState::Blocked => ShellSessionState::Failed,
    }
}

pub fn shell_task_state_from_task(state: &TaskState) -> ShellTaskState {
    match state {
        TaskState::Created => ShellTaskState::Planned,
        TaskState::Ready => ShellTaskState::Ready,
        TaskState::Running => ShellTaskState::Running,
        TaskState::BlockedOnApproval | TaskState::Paused => ShellTaskState::AwaitingApproval,
        TaskState::Completed => ShellTaskState::Completed,
        TaskState::Failed | TaskState::Canceled => ShellTaskState::Failed,
        TaskState::BlockedOnCapability | TaskState::BlockedOnWorker => ShellTaskState::Denied,
    }
}

pub fn approval_request_ids(bundle: &ShellSessionBundle) -> Vec<String> {
    bundle
        .runtime_state
        .memory_store
        .artifacts
        .iter()
        .filter_map(|artifact| match &artifact.payload {
            MemoryArtifactPayload::ApprovalRequest(request) => {
                Some(request.approval_request_id.clone())
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ShellRuntimeError, ShellSessionState, approval_request_ids, execute_active_shell_turn,
        finalize_shell_continuity_bundle, open_shell_session_bundle,
        record_shell_verified_memory_update, resume_shell_session_from_approval, start_shell_turn,
    };
    use crate::execution::artifact::GenerationManifest;
    use crate::execution::capability::{
        ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityWorld, CapabilityWorldGrant,
        IsolationProfile,
    };
    use crate::execution::component::{
        ComponentBuildRequest, ComponentExecutionContext, ComponentImportBinding,
        build_component_package,
    };
    use crate::execution::failure_budget::FailureBudget;
    use crate::execution::memory::{MemoryScope, MemoryStore, PointerIndex, TopicBundleClass};
    use crate::execution::orchestration::{
        AgendaItem, OwnershipBoundary, OwnershipMode, TaskGraph,
    };
    use crate::execution::session::{ActorKind, ExecutionSession, ExecutionSessionHeader};
    use crate::execution::storage::ReplayableRuntimeState;
    use crate::execution::task::{TaskArtifact, TaskState};
    use crate::execution::{ApprovalDecision, bind_session_ready};

    fn runtime_state() -> ReplayableRuntimeState {
        let mut session = ExecutionSession::new(ExecutionSessionHeader {
            session_id: "session-1".to_string(),
            actor_kind: ActorKind::Worker,
            actor_id: "worker-component".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            capability_envelope_ref: "envelope-1".to_string(),
            parent_session_id: None,
        });
        bind_session_ready(&mut session).unwrap();
        let task = TaskArtifact {
            state: TaskState::Ready,
            ..TaskArtifact::new("task-1", "root task")
        };
        let agenda_item = AgendaItem::new(
            "agenda-1",
            "task-1",
            "shell-task",
            Vec::new(),
            OwnershipBoundary {
                boundary_id: "boundary-1".to_string(),
                resource_scope: "scope:shell".to_string(),
                mode: OwnershipMode::ExclusiveMutable,
                owner_actor_ref: "worker-component".to_string(),
            },
        );
        let mut memory_store = MemoryStore::default();
        memory_store.insert_pointer_index(PointerIndex {
            index_id: "pointer-index-1".to_string(),
            scope: MemoryScope::Session("shell-session-1".to_string()),
            entry_refs: Vec::new(),
            contested_refs: Vec::new(),
            critical_refs: Vec::new(),
            governance_constraints: vec!["skeptical".to_string()],
            open_task_refs: vec!["task-1".to_string()],
            updated_at: "now".to_string(),
        });
        ReplayableRuntimeState::new(
            session,
            task,
            TaskGraph::new("task-1", vec![agenda_item]),
            memory_store,
            None,
            Vec::new(),
        )
    }

    fn approval_component_context() -> (Vec<u8>, ComponentExecutionContext) {
        let output = build_component_package(ComponentBuildRequest {
            build_id: "build-shell-approval".to_string(),
            manifest: GenerationManifest::new(
                "generation-shell-test",
                None,
                "package:aiaf/supervisor@test",
                "aiaf-supervisor-v4",
                vec!["src:test".to_string()],
                vec!["policy:test".to_string()],
                vec!["input:test".to_string()],
                "test manifest",
            )
            .unwrap(),
            wit_source:
                "world aiaf-supervisor-v4 { import approval-request: func(); export request-approval: func(); }"
                    .to_string(),
            component_source: r#"
                (component
                    (import "approval-request" (func $approval))
                    (core func $approval-core (canon lower (func $approval)))
                    (core module $m
                        (import "" "approval-request" (func $approval))
                        (func (export "request-approval")
                            call $approval))
                    (core instance $i (instantiate $m
                        (with "" (instance
                            (export "approval-request" (func $approval-core))))))
                    (func $request-approval (canon lift (core func $i "request-approval")))
                    (export "request-approval" (func $request-approval)))
            "#
            .to_string(),
            required_capability_world_refs: vec!["world:test".to_string()],
        })
        .unwrap();
        let context = ComponentExecutionContext {
            capability_envelope: CapabilityEnvelope {
                envelope_id: "envelope-shell-test".to_string(),
                actor_scope: "worker-shell-test".to_string(),
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::ApprovalGateway,
                    allowed_operations: vec!["request-approval".to_string()],
                    default_authority_class: AuthorityClass::CampaignControl,
                    default_approval_class: ApprovalClass::AutoAllowed,
                    operation_approval_overrides: Vec::new(),
                }],
                authority_ceiling: AuthorityClass::CampaignControl,
                isolation_profile: IsolationProfile::ArtifactSandbox,
                allowed_resource_scopes: vec!["scope:approval".to_string()],
                approval_overrides: Vec::new(),
                quota_policy: None,
                campaign_scope: None,
                epoch_scope: None,
            },
            import_bindings: vec![ComponentImportBinding {
                import_name: "approval-request".to_string(),
                world: CapabilityWorld::ApprovalGateway,
                operation: "request-approval".to_string(),
                resource_scope: "scope:approval".to_string(),
                required_authority_class: AuthorityClass::CampaignControl,
            }],
        };
        (output.component_bytes, context)
    }

    #[test]
    fn approval_pause_creates_resume_anchor_and_memory_lineage() {
        let (bytes, context) = approval_component_context();
        let mut bundle = open_shell_session_bundle(
            "shell-session-1",
            "worker-1",
            Some("agenda-1".to_string()),
            runtime_state(),
            &FailureBudget::default(),
        )
        .unwrap();
        start_shell_turn(&mut bundle, "shell-turn-1", "request-approval").unwrap();
        let mut failure_budget = FailureBudget::default();
        let execution =
            execute_active_shell_turn(&mut bundle, &bytes, &context, &mut failure_budget).unwrap();

        assert!(execution.approval_request.is_some());
        assert_eq!(
            bundle.shell_session.state,
            ShellSessionState::PausedForApproval
        );
        assert_eq!(bundle.resume_anchors.len(), 1);
        assert_eq!(bundle.shell_checkpoints.len(), 1);
        assert_eq!(approval_request_ids(&bundle).len(), 1);
    }

    #[test]
    fn resume_and_continuity_follow_verified_memory_update() {
        let (bytes, context) = approval_component_context();
        let mut bundle = open_shell_session_bundle(
            "shell-session-1",
            "worker-1",
            Some("agenda-1".to_string()),
            runtime_state(),
            &FailureBudget::default(),
        )
        .unwrap();
        start_shell_turn(&mut bundle, "shell-turn-1", "request-approval").unwrap();
        let mut failure_budget = FailureBudget::default();
        let execution =
            execute_active_shell_turn(&mut bundle, &bytes, &context, &mut failure_budget).unwrap();
        let request = execution.approval_request.unwrap();

        resume_shell_session_from_approval(
            &mut bundle,
            &ApprovalDecision::granted(
                request.approval_request_id.clone(),
                "campaign-1",
                "epoch-1",
                "session-1",
                "task-1",
                request.action_ref.clone(),
                "operator-1",
                request.scope_ref.clone(),
                Some("resume".to_string()),
            ),
            "operator-1",
        )
        .unwrap();
        start_shell_turn(&mut bundle, "shell-turn-2", "request-approval").unwrap();
        record_shell_verified_memory_update(
            &mut bundle,
            "record-1",
            "pointer-index-1",
            TopicBundleClass::GovernanceNotes,
            "verified",
            vec!["evidence-1".to_string()],
            vec!["verification-1".to_string()],
        )
        .unwrap();
        let continuity = finalize_shell_continuity_bundle(
            &mut bundle,
            "continuity-1",
            "pointer-index-1",
            vec!["contradiction-1".to_string()],
        )
        .unwrap();
        assert_eq!(
            continuity.verified_memory_refs,
            vec!["record-1".to_string()]
        );
    }

    #[test]
    fn missing_pointer_index_blocks_verified_memory_update() {
        let mut bundle = open_shell_session_bundle(
            "shell-session-1",
            "worker-1",
            Some("agenda-1".to_string()),
            runtime_state(),
            &FailureBudget::default(),
        )
        .unwrap();
        start_shell_turn(&mut bundle, "shell-turn-1", "noop").unwrap();
        let error = record_shell_verified_memory_update(
            &mut bundle,
            "record-1",
            "missing-pointer",
            TopicBundleClass::GovernanceNotes,
            "verified",
            vec![],
            vec!["verification-1".to_string()],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ShellRuntimeError::MissingPointerIndex { .. }
        ));
    }
}
