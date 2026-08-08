use crate::execution::capability::CapabilityEnvelope;
use crate::execution::checkpoint::RunCheckpoint;
use crate::execution::failure_budget::FailureBudgetSnapshot;
use crate::execution::governance::{
    ApprovalDecision, ApprovalDecisionStatus, ApprovalRequest, EpochAdoptionRecord,
    EpochAdoptionStatus, PromotionAct, PromotionActStatus,
};
use crate::execution::proposals::NormalizedProposal;
use crate::execution::worker::{
    WorkerCard, WorkerDispatch, WorkerDispatchCheckpointOutcome, WorkerDispatchOutcome,
    WorkerResult,
};
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::execution::session::{
    ExecutionSession, ExecutionSessionHeader, ExecutionSessionState, TurnOutcome, TurnRecord,
};
use crate::execution::task::{TaskArtifact, TaskState};
use crate::execution::{
    ApprovalRequestId, BlockedReason, BlockedReasonKind, CheckpointId, MemoryArtifactId, SessionId,
    TurnId, WorkerId,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    IllegalSessionTransition {
        from: ExecutionSessionState,
        to: ExecutionSessionState,
    },
    IllegalTaskTransition {
        from: TaskState,
        to: TaskState,
    },
    MissingCapabilityEnvelope,
    TaskAlreadyOwned {
        task_id: String,
        owner_session_id: SessionId,
    },
    MissingApproval {
        approval_request_id: ApprovalRequestId,
    },
    ApprovalDecisionNotGranted {
        approval_request_id: ApprovalRequestId,
        status: ApprovalDecisionStatus,
    },
    CapabilityWorldMissing {
        world: String,
        envelope_id: String,
    },
    AuthorityExceedsEnvelope {
        required: String,
        envelope_ceiling: String,
    },
    IsolationProfileInsufficient {
        required: String,
        available: String,
    },
    WorkerCardMismatch {
        worker_id: WorkerId,
        dispatch_worker_id: WorkerId,
    },
    DispatchSessionMismatch {
        dispatch_session_id: SessionId,
        session_id: SessionId,
    },
    DispatchEnvelopeMismatch {
        dispatch_envelope_id: String,
        envelope_id: String,
    },
    EnvelopeCampaignScopeMismatch {
        envelope_id: String,
        envelope_campaign_id: String,
        session_campaign_id: String,
    },
    EnvelopeEpochScopeMismatch {
        envelope_id: String,
        envelope_epoch_id: String,
        session_epoch_id: String,
    },
    ResourceScopeNotAllowed {
        resource_scope: String,
        envelope_id: String,
    },
    OperationNotAllowed {
        world: String,
        operation: String,
        envelope_id: String,
    },
    ApprovalClassBlocksOperation {
        world: String,
        operation: String,
        approval_class: String,
    },
    WorkerConcurrencyExceeded {
        worker_id: WorkerId,
        max_concurrency: usize,
        outstanding_dispatches: usize,
    },
    MissingWorkerDispatch {
        worker_id: WorkerId,
    },
    MissingCheckpoint,
    PromotionActNotApproved {
        promotion_act_id: String,
        status: String,
    },
    EpochAdoptionNotPlanned {
        adoption_id: String,
        status: String,
    },
    EpochHandoffMismatch {
        expected_epoch_id: String,
        actual_epoch_id: String,
    },
}

impl Display for TransitionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IllegalSessionTransition { from, to } => {
                write!(f, "illegal session transition: {from:?} -> {to:?}")
            }
            Self::IllegalTaskTransition { from, to } => {
                write!(f, "illegal task transition: {from:?} -> {to:?}")
            }
            Self::MissingCapabilityEnvelope => {
                write!(f, "session is missing a capability envelope")
            }
            Self::TaskAlreadyOwned {
                task_id,
                owner_session_id,
            } => write!(
                f,
                "task '{task_id}' is already owned by session '{owner_session_id}'"
            ),
            Self::MissingApproval {
                approval_request_id,
            } => {
                write!(
                    f,
                    "missing valid approval '{approval_request_id}' for resume"
                )
            }
            Self::ApprovalDecisionNotGranted {
                approval_request_id,
                status,
            } => write!(
                f,
                "approval decision '{approval_request_id}' is not granted: {status:?}"
            ),
            Self::CapabilityWorldMissing { world, envelope_id } => write!(
                f,
                "capability world '{world}' is missing from envelope '{envelope_id}'"
            ),
            Self::AuthorityExceedsEnvelope {
                required,
                envelope_ceiling,
            } => write!(
                f,
                "required authority '{required}' exceeds envelope ceiling '{envelope_ceiling}'"
            ),
            Self::IsolationProfileInsufficient {
                required,
                available,
            } => write!(
                f,
                "required isolation '{required}' is not satisfied by '{available}'"
            ),
            Self::WorkerCardMismatch {
                worker_id,
                dispatch_worker_id,
            } => write!(
                f,
                "worker card '{worker_id}' does not match dispatch worker '{dispatch_worker_id}'"
            ),
            Self::DispatchSessionMismatch {
                dispatch_session_id,
                session_id,
            } => write!(
                f,
                "dispatch session '{}' does not match active session '{}'",
                dispatch_session_id, session_id
            ),
            Self::DispatchEnvelopeMismatch {
                dispatch_envelope_id,
                envelope_id,
            } => write!(
                f,
                "dispatch envelope '{dispatch_envelope_id}' does not match provided envelope '{envelope_id}'"
            ),
            Self::EnvelopeCampaignScopeMismatch {
                envelope_id,
                envelope_campaign_id,
                session_campaign_id,
            } => write!(
                f,
                "envelope '{}' is scoped to campaign '{}' instead of '{}'",
                envelope_id, envelope_campaign_id, session_campaign_id
            ),
            Self::EnvelopeEpochScopeMismatch {
                envelope_id,
                envelope_epoch_id,
                session_epoch_id,
            } => write!(
                f,
                "envelope '{}' is scoped to epoch '{}' instead of '{}'",
                envelope_id, envelope_epoch_id, session_epoch_id
            ),
            Self::ResourceScopeNotAllowed {
                resource_scope,
                envelope_id,
            } => write!(
                f,
                "resource scope '{resource_scope}' is not allowed by envelope '{envelope_id}'"
            ),
            Self::OperationNotAllowed {
                world,
                operation,
                envelope_id,
            } => write!(
                f,
                "operation '{operation}' in world '{world}' is not allowed by envelope '{envelope_id}'"
            ),
            Self::ApprovalClassBlocksOperation {
                world,
                operation,
                approval_class,
            } => write!(
                f,
                "operation '{operation}' in world '{world}' is blocked by approval class '{approval_class}'"
            ),
            Self::WorkerConcurrencyExceeded {
                worker_id,
                max_concurrency,
                outstanding_dispatches,
            } => write!(
                f,
                "worker '{}' already has {} outstanding dispatches and exceeds concurrency limit {}",
                worker_id, outstanding_dispatches, max_concurrency
            ),
            Self::MissingWorkerDispatch { worker_id } => {
                write!(
                    f,
                    "missing valid outstanding worker dispatch for '{worker_id}'"
                )
            }
            Self::MissingCheckpoint => write!(f, "resume requires a valid latest checkpoint"),
            Self::PromotionActNotApproved {
                promotion_act_id,
                status,
            } => write!(
                f,
                "promotion act '{}' is not approved for activation: {}",
                promotion_act_id, status
            ),
            Self::EpochAdoptionNotPlanned {
                adoption_id,
                status,
            } => write!(
                f,
                "epoch adoption '{}' is not planned for activation: {}",
                adoption_id, status
            ),
            Self::EpochHandoffMismatch {
                expected_epoch_id,
                actual_epoch_id,
            } => write!(
                f,
                "epoch handoff expected prior epoch '{}' but session is in '{}'",
                expected_epoch_id, actual_epoch_id
            ),
        }
    }
}

impl Error for TransitionError {}

pub fn bind_session_ready(session: &mut ExecutionSession) -> Result<(), TransitionError> {
    if session.header.capability_envelope_ref.trim().is_empty() {
        return Err(TransitionError::MissingCapabilityEnvelope);
    }

    if session.state != ExecutionSessionState::Initialized {
        return Err(TransitionError::IllegalSessionTransition {
            from: session.state.clone(),
            to: ExecutionSessionState::Ready,
        });
    }

    session.state = ExecutionSessionState::Ready;
    Ok(())
}

pub fn activate_promoted_incumbent(
    prior_session: &ExecutionSession,
    promotion_act: &PromotionAct,
    adoption_record: &EpochAdoptionRecord,
    capability_envelope_ref: impl Into<String>,
    root_task: Option<&TaskArtifact>,
    checkpoint_id: impl Into<CheckpointId>,
    outstanding_proposals: Vec<NormalizedProposal>,
    memory_artifact_refs: Vec<MemoryArtifactId>,
    failure_budget: FailureBudgetSnapshot,
    idempotency_markers: Vec<String>,
) -> Result<(ExecutionSession, RunCheckpoint), TransitionError> {
    if promotion_act.status != PromotionActStatus::Approved {
        return Err(TransitionError::PromotionActNotApproved {
            promotion_act_id: promotion_act.promotion_act_id.clone(),
            status: format!("{:?}", promotion_act.status),
        });
    }

    if adoption_record.status != EpochAdoptionStatus::Planned {
        return Err(TransitionError::EpochAdoptionNotPlanned {
            adoption_id: adoption_record.adoption_id.clone(),
            status: format!("{:?}", adoption_record.status),
        });
    }

    if prior_session.header.epoch_id != adoption_record.prior_epoch_id {
        return Err(TransitionError::EpochHandoffMismatch {
            expected_epoch_id: adoption_record.prior_epoch_id.clone(),
            actual_epoch_id: prior_session.header.epoch_id.clone(),
        });
    }

    let mut promoted_session = ExecutionSession::new(ExecutionSessionHeader {
        session_id: adoption_record.activated_session_id.clone(),
        actor_kind: crate::execution::ActorKind::Supervisor,
        actor_id: adoption_record.promoted_incumbent_ref.clone(),
        campaign_id: adoption_record.successor_campaign_id.clone(),
        epoch_id: adoption_record.promoted_epoch_id.clone(),
        capability_envelope_ref: capability_envelope_ref.into(),
        parent_session_id: Some(prior_session.header.session_id.clone()),
    });
    bind_session_ready(&mut promoted_session)?;

    let checkpoint = RunCheckpoint::capture(
        checkpoint_id,
        &promoted_session,
        root_task,
        outstanding_proposals,
        memory_artifact_refs,
        failure_budget,
        idempotency_markers,
    );
    promoted_session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());

    Ok((promoted_session, checkpoint))
}

pub fn start_turn(
    session: &mut ExecutionSession,
    task: &mut TaskArtifact,
    turn_id: impl Into<TurnId>,
) -> Result<TurnRecord, TransitionError> {
    if session.state != ExecutionSessionState::Ready {
        return Err(TransitionError::IllegalSessionTransition {
            from: session.state.clone(),
            to: ExecutionSessionState::ExecutingTurn,
        });
    }

    if let Some(owner_session_id) = &task.owner_session_id {
        if owner_session_id != &session.header.session_id {
            return Err(TransitionError::TaskAlreadyOwned {
                task_id: task.task_id.clone(),
                owner_session_id: owner_session_id.clone(),
            });
        }
    }

    if !matches!(task.state, TaskState::Created | TaskState::Ready) {
        return Err(TransitionError::IllegalTaskTransition {
            from: task.state.clone(),
            to: TaskState::Running,
        });
    }

    session.state = ExecutionSessionState::ExecutingTurn;
    session.turn_counter += 1;
    session.active_task_id = Some(task.task_id.clone());

    task.state = TaskState::Running;
    task.owner_session_id = Some(session.header.session_id.clone());
    task.blocked_reason = None;

    let turn = TurnRecord::open(
        turn_id,
        session.header.session_id.clone(),
        session.turn_counter,
    );
    session.current_turn = Some(turn.clone());

    Ok(turn)
}

pub fn block_on_approval(
    session: &mut ExecutionSession,
    task: &mut TaskArtifact,
    approval_request_id: impl Into<ApprovalRequestId>,
    detail: impl Into<String>,
) -> Result<(), TransitionError> {
    if session.state != ExecutionSessionState::ExecutingTurn {
        return Err(TransitionError::IllegalSessionTransition {
            from: session.state.clone(),
            to: ExecutionSessionState::AwaitingApproval,
        });
    }

    if task.state != TaskState::Running {
        return Err(TransitionError::IllegalTaskTransition {
            from: task.state.clone(),
            to: TaskState::BlockedOnApproval,
        });
    }

    let approval_request_id = approval_request_id.into();
    let blocked_reason = BlockedReason::new(BlockedReasonKind::Approval, detail);

    session.pending_approval_refs.push(approval_request_id);
    session.blocked_reason = Some(blocked_reason.clone());
    session.state = ExecutionSessionState::AwaitingApproval;

    if let Some(turn) = &mut session.current_turn {
        turn.outcome = TurnOutcome::AwaitingApproval;
    }

    task.state = TaskState::BlockedOnApproval;
    task.blocked_reason = Some(blocked_reason);

    Ok(())
}

pub fn checkpointed_block_on_approval(
    session: &mut ExecutionSession,
    task: &mut TaskArtifact,
    approval_request_id: impl Into<ApprovalRequestId>,
    detail: impl Into<String>,
    checkpoint_id: impl Into<CheckpointId>,
    outstanding_proposals: Vec<NormalizedProposal>,
    memory_artifact_refs: Vec<MemoryArtifactId>,
    failure_budget: FailureBudgetSnapshot,
    idempotency_markers: Vec<String>,
) -> Result<RunCheckpoint, TransitionError> {
    let approval_request_id = approval_request_id.into();
    let detail = detail.into();

    let mut projected_session = session.clone();
    let mut projected_task = task.clone();

    block_on_approval(
        &mut projected_session,
        &mut projected_task,
        approval_request_id.clone(),
        detail.clone(),
    )?;

    let checkpoint = RunCheckpoint::capture(
        checkpoint_id,
        &projected_session,
        Some(&projected_task),
        outstanding_proposals,
        memory_artifact_refs,
        failure_budget,
        idempotency_markers,
    );

    block_on_approval(session, task, approval_request_id, detail)?;
    session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());

    Ok(checkpoint)
}

pub fn resume_from_approval(
    session: &mut ExecutionSession,
    task: &mut TaskArtifact,
    approval_request_id: &str,
) -> Result<(), TransitionError> {
    if session.state != ExecutionSessionState::AwaitingApproval {
        return Err(TransitionError::IllegalSessionTransition {
            from: session.state.clone(),
            to: ExecutionSessionState::Ready,
        });
    }

    if session.latest_checkpoint_ref.is_none() {
        return Err(TransitionError::MissingCheckpoint);
    }

    if !session
        .pending_approval_refs
        .iter()
        .any(|candidate| candidate == approval_request_id)
    {
        return Err(TransitionError::MissingApproval {
            approval_request_id: approval_request_id.to_string(),
        });
    }

    session
        .pending_approval_refs
        .retain(|candidate| candidate != approval_request_id);
    session.blocked_reason = None;
    session.state = ExecutionSessionState::Ready;

    task.blocked_reason = None;
    task.state = TaskState::Ready;

    Ok(())
}

pub fn apply_approval_decision(
    session: &mut ExecutionSession,
    task: &mut TaskArtifact,
    decision: &ApprovalDecision,
) -> Result<(), TransitionError> {
    if decision.campaign_id != session.header.campaign_id
        || decision.epoch_id != session.header.epoch_id
        || decision.session_id != session.header.session_id
        || decision.task_id != task.task_id
    {
        return Err(TransitionError::MissingApproval {
            approval_request_id: decision.approval_request_id.clone(),
        });
    }

    if !decision.decision.is_granted() {
        return Err(TransitionError::ApprovalDecisionNotGranted {
            approval_request_id: decision.approval_request_id.clone(),
            status: decision.decision.clone(),
        });
    }

    resume_from_approval(session, task, &decision.approval_request_id)
}

pub fn dispatch_to_worker(
    session: &mut ExecutionSession,
    task: &mut TaskArtifact,
    worker_card: &WorkerCard,
    capability_envelope: &CapabilityEnvelope,
    dispatch: &WorkerDispatch,
) -> Result<WorkerDispatchOutcome, TransitionError> {
    if session.state != ExecutionSessionState::ExecutingTurn {
        return Err(TransitionError::IllegalSessionTransition {
            from: session.state.clone(),
            to: ExecutionSessionState::AwaitingWorkerResult,
        });
    }

    if task.state != TaskState::Running {
        return Err(TransitionError::IllegalTaskTransition {
            from: task.state.clone(),
            to: TaskState::BlockedOnWorker,
        });
    }

    if dispatch.worker_id != worker_card.worker_id {
        return Err(TransitionError::WorkerCardMismatch {
            worker_id: worker_card.worker_id.clone(),
            dispatch_worker_id: dispatch.worker_id.clone(),
        });
    }

    if dispatch.parent_session_id != session.header.session_id {
        return Err(TransitionError::DispatchSessionMismatch {
            dispatch_session_id: dispatch.parent_session_id.clone(),
            session_id: session.header.session_id.clone(),
        });
    }

    if dispatch.capability_envelope_ref != capability_envelope.envelope_id {
        return Err(TransitionError::DispatchEnvelopeMismatch {
            dispatch_envelope_id: dispatch.capability_envelope_ref.clone(),
            envelope_id: capability_envelope.envelope_id.clone(),
        });
    }

    if let Some(envelope_campaign_id) = &capability_envelope.campaign_scope {
        if envelope_campaign_id != &session.header.campaign_id {
            return Err(TransitionError::EnvelopeCampaignScopeMismatch {
                envelope_id: capability_envelope.envelope_id.clone(),
                envelope_campaign_id: envelope_campaign_id.clone(),
                session_campaign_id: session.header.campaign_id.clone(),
            });
        }
    }

    if let Some(envelope_epoch_id) = &capability_envelope.epoch_scope {
        if envelope_epoch_id != &session.header.epoch_id {
            return Err(TransitionError::EnvelopeEpochScopeMismatch {
                envelope_id: capability_envelope.envelope_id.clone(),
                envelope_epoch_id: envelope_epoch_id.clone(),
                session_epoch_id: session.header.epoch_id.clone(),
            });
        }
    }

    for world in &worker_card.required_worlds {
        if !capability_envelope.grants_world(world) {
            return Err(TransitionError::CapabilityWorldMissing {
                world: format!("{world:?}"),
                envelope_id: capability_envelope.envelope_id.clone(),
            });
        }
    }

    if !capability_envelope.grants_world(&crate::execution::CapabilityWorld::WorkerMessaging) {
        return Err(TransitionError::CapabilityWorldMissing {
            world: "WorkerMessaging".to_string(),
            envelope_id: capability_envelope.envelope_id.clone(),
        });
    }

    if !capability_envelope.authority_allows(&worker_card.authority_ceiling) {
        return Err(TransitionError::AuthorityExceedsEnvelope {
            required: format!("{:?}", worker_card.authority_ceiling),
            envelope_ceiling: format!("{:?}", capability_envelope.authority_ceiling),
        });
    }

    if !capability_envelope.isolation_allows(&worker_card.isolation_profile) {
        return Err(TransitionError::IsolationProfileInsufficient {
            required: format!("{:?}", worker_card.isolation_profile),
            available: format!("{:?}", capability_envelope.isolation_profile),
        });
    }

    let outstanding_dispatches = session
        .outstanding_worker_refs
        .iter()
        .filter(|candidate| *candidate == &worker_card.worker_id)
        .count();
    if outstanding_dispatches >= worker_card.max_concurrency {
        return Err(TransitionError::WorkerConcurrencyExceeded {
            worker_id: worker_card.worker_id.clone(),
            max_concurrency: worker_card.max_concurrency,
            outstanding_dispatches,
        });
    }

    for request in &dispatch.requested_capabilities {
        if !capability_envelope.grants_world(&request.world) {
            return Err(TransitionError::CapabilityWorldMissing {
                world: format!("{:?}", request.world),
                envelope_id: capability_envelope.envelope_id.clone(),
            });
        }

        if !capability_envelope.scope_allows(&request.resource_scope) {
            return Err(TransitionError::ResourceScopeNotAllowed {
                resource_scope: request.resource_scope.clone(),
                envelope_id: capability_envelope.envelope_id.clone(),
            });
        }

        if !capability_envelope.allows_operation(&request.world, &request.operation) {
            return Err(TransitionError::OperationNotAllowed {
                world: format!("{:?}", request.world),
                operation: request.operation.clone(),
                envelope_id: capability_envelope.envelope_id.clone(),
            });
        }

        let approval_class = capability_envelope
            .approval_for(&request.world, &request.operation)
            .expect("allowed operation must have an approval class");
        match approval_class {
            crate::execution::ApprovalClass::AutoAllowed
            | crate::execution::ApprovalClass::SupervisorAllowed => {}
            crate::execution::ApprovalClass::HumanRequired => {
                return Ok(WorkerDispatchOutcome::ApprovalRequired(
                    ApprovalRequest::requested(
                        format!("approval-{}", dispatch.dispatch_id),
                        session.header.campaign_id.clone(),
                        session.header.epoch_id.clone(),
                        session.header.session_id.clone(),
                        task.task_id.clone(),
                        format!(
                            "dispatch:{}:{}:{}",
                            dispatch.dispatch_id,
                            format!("{:?}", request.world),
                            request.operation
                        ),
                        request.resource_scope.clone(),
                        worker_card.authority_ceiling.clone(),
                    ),
                ));
            }
            crate::execution::ApprovalClass::QuarantineOnExpand
            | crate::execution::ApprovalClass::Forbidden => {
                return Err(TransitionError::ApprovalClassBlocksOperation {
                    world: format!("{:?}", request.world),
                    operation: request.operation.clone(),
                    approval_class: format!("{approval_class:?}"),
                });
            }
        }
    }

    let blocked_reason = BlockedReason::new(
        BlockedReasonKind::Worker,
        format!(
            "awaiting worker {} result for {}",
            dispatch.worker_id, dispatch.worker_task_ref
        ),
    );

    session
        .outstanding_worker_refs
        .push(dispatch.worker_id.clone());
    session.blocked_reason = Some(blocked_reason.clone());
    session.state = ExecutionSessionState::AwaitingWorkerResult;

    if let Some(turn) = &mut session.current_turn {
        turn.outcome = TurnOutcome::AwaitingWorkerResult;
    }

    task.state = TaskState::BlockedOnWorker;
    task.blocked_reason = Some(blocked_reason);

    Ok(WorkerDispatchOutcome::Dispatched)
}

pub fn checkpointed_dispatch_to_worker(
    session: &mut ExecutionSession,
    task: &mut TaskArtifact,
    worker_card: &WorkerCard,
    capability_envelope: &CapabilityEnvelope,
    dispatch: &WorkerDispatch,
    checkpoint_id: impl Into<CheckpointId>,
    outstanding_proposals: Vec<NormalizedProposal>,
    memory_artifact_refs: Vec<MemoryArtifactId>,
    failure_budget: FailureBudgetSnapshot,
    idempotency_markers: Vec<String>,
) -> Result<WorkerDispatchCheckpointOutcome, TransitionError> {
    let mut projected_session = session.clone();
    let mut projected_task = task.clone();

    let projected_outcome = dispatch_to_worker(
        &mut projected_session,
        &mut projected_task,
        worker_card,
        capability_envelope,
        dispatch,
    )?;
    if let WorkerDispatchOutcome::ApprovalRequired(request) = projected_outcome {
        let approval_proposal = NormalizedProposal::new(
            crate::execution::ProposalFamily::ApprovalRequest,
            format!(
                "Approve worker dispatch {} for {}",
                dispatch.dispatch_id, request.scope_ref
            ),
            Some(request.scope_ref.clone()),
        )
        .expect("approval proposal summary and target should be valid");
        let checkpoint = checkpointed_block_on_approval(
            session,
            task,
            request.approval_request_id.clone(),
            format!(
                "worker dispatch {} requires approval for {}",
                dispatch.dispatch_id, request.scope_ref
            ),
            checkpoint_id,
            vec![approval_proposal],
            memory_artifact_refs,
            failure_budget,
            idempotency_markers,
        )?;
        return Ok(WorkerDispatchCheckpointOutcome::ApprovalBlocked {
            approval_request: request,
            checkpoint,
        });
    }

    let checkpoint = RunCheckpoint::capture(
        checkpoint_id,
        &projected_session,
        Some(&projected_task),
        outstanding_proposals,
        memory_artifact_refs,
        failure_budget,
        idempotency_markers,
    );

    let live_outcome =
        dispatch_to_worker(session, task, worker_card, capability_envelope, dispatch)?;
    debug_assert!(matches!(live_outcome, WorkerDispatchOutcome::Dispatched));
    session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());

    Ok(WorkerDispatchCheckpointOutcome::Dispatched(checkpoint))
}

pub fn accept_worker_result(
    session: &mut ExecutionSession,
    task: &mut TaskArtifact,
    result: &WorkerResult,
) -> Result<(), TransitionError> {
    if session.state != ExecutionSessionState::AwaitingWorkerResult {
        return Err(TransitionError::IllegalSessionTransition {
            from: session.state.clone(),
            to: ExecutionSessionState::Ready,
        });
    }

    if task.state != TaskState::BlockedOnWorker {
        return Err(TransitionError::IllegalTaskTransition {
            from: task.state.clone(),
            to: TaskState::Ready,
        });
    }

    if session.latest_checkpoint_ref.is_none() {
        return Err(TransitionError::MissingCheckpoint);
    }

    if !session
        .outstanding_worker_refs
        .iter()
        .any(|candidate| candidate == &result.worker_id)
    {
        return Err(TransitionError::MissingWorkerDispatch {
            worker_id: result.worker_id.clone(),
        });
    }

    session
        .outstanding_worker_refs
        .retain(|candidate| candidate != &result.worker_id);
    session.blocked_reason = None;
    session.state = ExecutionSessionState::Ready;

    task.blocked_reason = None;
    task.state = TaskState::Ready;

    Ok(())
}

pub fn conclude_turn_ready(
    session: &mut ExecutionSession,
    task: &mut TaskArtifact,
) -> Result<(), TransitionError> {
    if session.state != ExecutionSessionState::ExecutingTurn {
        return Err(TransitionError::IllegalSessionTransition {
            from: session.state.clone(),
            to: ExecutionSessionState::Ready,
        });
    }

    if task.state != TaskState::Running {
        return Err(TransitionError::IllegalTaskTransition {
            from: task.state.clone(),
            to: TaskState::Ready,
        });
    }

    session.state = ExecutionSessionState::Ready;
    session.blocked_reason = None;
    session.active_task_id = Some(task.task_id.clone());

    if let Some(turn) = &mut session.current_turn {
        turn.outcome = TurnOutcome::Completed;
    }

    task.state = TaskState::Ready;
    task.blocked_reason = None;

    Ok(())
}

pub fn complete_task(
    session: &mut ExecutionSession,
    task: &mut TaskArtifact,
) -> Result<(), TransitionError> {
    if session.state != ExecutionSessionState::ExecutingTurn {
        return Err(TransitionError::IllegalSessionTransition {
            from: session.state.clone(),
            to: ExecutionSessionState::Completed,
        });
    }

    if task.state != TaskState::Running {
        return Err(TransitionError::IllegalTaskTransition {
            from: task.state.clone(),
            to: TaskState::Completed,
        });
    }

    session.state = ExecutionSessionState::Completed;
    session.active_task_id = Some(task.task_id.clone());

    if let Some(turn) = &mut session.current_turn {
        turn.outcome = TurnOutcome::Completed;
    }

    task.state = TaskState::Completed;
    Ok(())
}

pub fn fail_task(
    session: &mut ExecutionSession,
    task: &mut TaskArtifact,
) -> Result<(), TransitionError> {
    if !matches!(
        session.state,
        ExecutionSessionState::ExecutingTurn
            | ExecutionSessionState::AwaitingApproval
            | ExecutionSessionState::Blocked
    ) {
        return Err(TransitionError::IllegalSessionTransition {
            from: session.state.clone(),
            to: ExecutionSessionState::Failed,
        });
    }

    if !matches!(
        task.state,
        TaskState::Running | TaskState::BlockedOnApproval
    ) {
        return Err(TransitionError::IllegalTaskTransition {
            from: task.state.clone(),
            to: TaskState::Failed,
        });
    }

    session.state = ExecutionSessionState::Failed;

    if let Some(turn) = &mut session.current_turn {
        turn.outcome = TurnOutcome::Failed;
    }

    task.state = TaskState::Failed;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::execution::capability::{
        ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityOperationApproval,
        CapabilityWorld, CapabilityWorldGrant, IsolationProfile,
    };
    use crate::execution::failure_budget::FailureBudget;
    use crate::execution::governance::{
        ApprovalDecision, ApprovalDecisionStatus, open_promotion_act, plan_epoch_adoption,
    };
    use crate::execution::memory::{MemoryArtifactClass, MemoryStore};
    use crate::execution::proposals::{NormalizedProposal, ProposalFamily};
    use crate::execution::replacement::{
        CapabilityImportTarget, DimensionVerdict, EvaluationDimension, EvaluationDimensionScore,
        GenerationComparisonRecord, NativeReplacementTier,
    };
    use crate::execution::session::{
        ActorKind, ExecutionSession, ExecutionSessionHeader, ExecutionSessionState, TurnOutcome,
    };
    use crate::execution::task::{TaskArtifact, TaskState};
    use crate::execution::worker::{
        CapabilityOperationRequest, MessageArtifact, MessageArtifactClass, MessageArtifactStatus,
        WorkerCard, WorkerDispatch, WorkerDispatchCheckpointOutcome, WorkerDispatchOutcome,
        WorkerResult, WorkerRole,
    };

    use super::{
        TransitionError, accept_worker_result, activate_promoted_incumbent,
        apply_approval_decision, bind_session_ready, block_on_approval,
        checkpointed_block_on_approval, checkpointed_dispatch_to_worker, complete_task,
        conclude_turn_ready, dispatch_to_worker, resume_from_approval, start_turn,
    };

    fn supervisor_session() -> ExecutionSession {
        ExecutionSession::new(ExecutionSessionHeader {
            session_id: "session-1".to_string(),
            actor_kind: ActorKind::Supervisor,
            actor_id: "supervisor-alpha".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            capability_envelope_ref: "envelope-1".to_string(),
            parent_session_id: None,
        })
    }

    fn task() -> TaskArtifact {
        TaskArtifact::new("task-1", "Complete the first bounded supervisor flow.")
    }

    fn worker_envelope() -> CapabilityEnvelope {
        CapabilityEnvelope {
            envelope_id: "envelope-worker-1".to_string(),
            actor_scope: "worker-1".to_string(),
            world_grants: vec![
                CapabilityWorldGrant {
                    world: CapabilityWorld::WorkerMessaging,
                    allowed_operations: vec!["dispatch".to_string(), "result".to_string()],
                    default_authority_class: AuthorityClass::Observe,
                    default_approval_class: ApprovalClass::AutoAllowed,
                    operation_approval_overrides: Vec::new(),
                },
                CapabilityWorldGrant {
                    world: CapabilityWorld::WorkspaceObserve,
                    allowed_operations: vec!["read-file".to_string(), "search".to_string()],
                    default_authority_class: AuthorityClass::Observe,
                    default_approval_class: ApprovalClass::AutoAllowed,
                    operation_approval_overrides: Vec::new(),
                },
                CapabilityWorldGrant {
                    world: CapabilityWorld::MemoryAccess,
                    allowed_operations: vec!["read-pointer-index".to_string()],
                    default_authority_class: AuthorityClass::Observe,
                    default_approval_class: ApprovalClass::AutoAllowed,
                    operation_approval_overrides: Vec::new(),
                },
            ],
            authority_ceiling: AuthorityClass::Observe,
            isolation_profile: IsolationProfile::ArtifactSandbox,
            allowed_resource_scopes: vec![
                "worker-channel".to_string(),
                "workspace-root".to_string(),
                "pointer-index".to_string(),
            ],
            approval_overrides: Vec::new(),
            quota_policy: None,
            campaign_scope: Some("campaign-1".to_string()),
            epoch_scope: Some("epoch-1".to_string()),
        }
    }

    fn worker_card() -> WorkerCard {
        WorkerCard {
            worker_id: "worker-1".to_string(),
            worker_role: WorkerRole::EvaluatorWorker,
            supported_task_kinds: vec!["bounded-analysis".to_string()],
            required_worlds: vec![
                CapabilityWorld::WorkspaceObserve,
                CapabilityWorld::MemoryAccess,
            ],
            authority_ceiling: AuthorityClass::Observe,
            isolation_profile: IsolationProfile::ArtifactSandbox,
            result_contract: "bounded-evaluation-result".to_string(),
            max_concurrency: 1,
        }
    }

    fn worker_dispatch(session_id: &str, task_id: &str) -> WorkerDispatch {
        WorkerDispatch {
            dispatch_id: "dispatch-1".to_string(),
            task_id: task_id.to_string(),
            parent_session_id: session_id.to_string(),
            worker_id: "worker-1".to_string(),
            worker_task_ref: "worker-task-1".to_string(),
            capability_envelope_ref: "envelope-worker-1".to_string(),
            requested_capabilities: vec![
                CapabilityOperationRequest {
                    world: CapabilityWorld::WorkerMessaging,
                    operation: "dispatch".to_string(),
                    resource_scope: "worker-channel".to_string(),
                },
                CapabilityOperationRequest {
                    world: CapabilityWorld::WorkspaceObserve,
                    operation: "search".to_string(),
                    resource_scope: "workspace-root".to_string(),
                },
                CapabilityOperationRequest {
                    world: CapabilityWorld::MemoryAccess,
                    operation: "read-pointer-index".to_string(),
                    resource_scope: "pointer-index".to_string(),
                },
            ],
            dispatch_message: MessageArtifact {
                message_id: "message-dispatch-1".to_string(),
                campaign_id: "campaign-1".to_string(),
                epoch_id: "epoch-1".to_string(),
                task_id: task_id.to_string(),
                sender_actor_ref: session_id.to_string(),
                receiver_actor_ref: "worker-1".to_string(),
                message_class: MessageArtifactClass::DispatchMessage,
                payload_summary: "dispatch worker for bounded evaluation".to_string(),
                referenced_artifacts: vec![task_id.to_string()],
                status: MessageArtifactStatus::Sent,
            },
        }
    }

    #[test]
    fn supervisor_can_conclude_turn_and_keep_task_ready() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();

        conclude_turn_ready(&mut session, &mut task).unwrap();

        assert_eq!(session.state, ExecutionSessionState::Ready);
        assert_eq!(task.state, TaskState::Ready);
        assert_eq!(
            session.current_turn.as_ref().map(|turn| &turn.outcome),
            Some(&TurnOutcome::Completed)
        );
    }

    fn worker_result(dispatch: &WorkerDispatch) -> WorkerResult {
        WorkerResult {
            dispatch_id: dispatch.dispatch_id.clone(),
            worker_id: dispatch.worker_id.clone(),
            worker_task_ref: dispatch.worker_task_ref.clone(),
            result_ref: "worker-result-1".to_string(),
            summary: "worker completed bounded evaluation".to_string(),
            result_message: MessageArtifact {
                message_id: "message-result-1".to_string(),
                campaign_id: "campaign-1".to_string(),
                epoch_id: "epoch-1".to_string(),
                task_id: dispatch.task_id.clone(),
                sender_actor_ref: dispatch.worker_id.clone(),
                receiver_actor_ref: dispatch.parent_session_id.clone(),
                message_class: MessageArtifactClass::ResultMessage,
                payload_summary: "bounded result available".to_string(),
                referenced_artifacts: vec!["worker-result-1".to_string()],
                status: MessageArtifactStatus::Received,
            },
        }
    }

    fn promotable_comparison() -> GenerationComparisonRecord {
        GenerationComparisonRecord {
            comparison_id: "comparison-1".to_string(),
            target: CapabilityImportTarget::NativeSupervisorChallenger,
            replacement_tier: NativeReplacementTier::NativeSupervisorChallengers,
            incumbent_ref: "session-incumbent-1".to_string(),
            challenger_ref: "session-challenger-1".to_string(),
            shared_input_refs: vec!["shared-input-1".to_string()],
            imported_provider: crate::execution::ProviderKind::Imported,
            native_provider: crate::execution::ProviderKind::Native,
            imported_output_refs: vec!["incumbent-output-1".to_string()],
            native_output_refs: vec!["challenger-output-1".to_string()],
            dimension_scores: vec![
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::SemanticCorrectness,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "incumbent correct".to_string(),
                    challenger_summary: "challenger correct".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::GovernanceFidelity,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "incumbent governed".to_string(),
                    challenger_summary: "challenger governed".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::Replayability,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "incumbent replayable".to_string(),
                    challenger_summary: "challenger replayable".to_string(),
                },
                EvaluationDimensionScore {
                    dimension: EvaluationDimension::ReplacementSafety,
                    verdict: DimensionVerdict::Equivalent,
                    incumbent_summary: "incumbent reversible".to_string(),
                    challenger_summary: "challenger reversible".to_string(),
                },
            ],
            matched: true,
            summary: "promotable challenger comparison".to_string(),
        }
    }

    #[test]
    fn supervisor_can_block_on_approval_and_resume() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        assert_eq!(session.state, ExecutionSessionState::Ready);

        let turn = start_turn(&mut session, &mut task, "turn-1").unwrap();
        assert_eq!(turn.turn_index, 1);
        assert_eq!(task.state, TaskState::Running);

        let proposal = NormalizedProposal::new(
            ProposalFamily::ApprovalRequest,
            "Request approval for workspace mutation",
            Some("workspace-root".to_string()),
        )
        .unwrap();

        let checkpoint = checkpointed_block_on_approval(
            &mut session,
            &mut task,
            "approval-1",
            "workspace mutation requires human approval",
            "checkpoint-1",
            vec![proposal],
            vec!["pointer-index".to_string()],
            FailureBudget::default().snapshot(),
            vec!["action-1".to_string()],
        )
        .unwrap();

        assert_eq!(session.state, ExecutionSessionState::AwaitingApproval);
        assert_eq!(task.state, TaskState::BlockedOnApproval);
        assert_eq!(
            checkpoint.pending_approval_refs,
            vec!["approval-1".to_string()]
        );

        let approval = ApprovalDecision::granted(
            "approval-1",
            "campaign-1",
            "epoch-1",
            session.header.session_id.clone(),
            task.task_id.clone(),
            "workspace-root",
            "operator-1",
            "workspace-root",
            Some("Approved for bounded continuation".to_string()),
        );

        apply_approval_decision(&mut session, &mut task, &approval).unwrap();
        assert_eq!(session.state, ExecutionSessionState::Ready);
        assert_eq!(task.state, TaskState::Ready);

        start_turn(&mut session, &mut task, "turn-2").unwrap();
        complete_task(&mut session, &mut task).unwrap();

        assert_eq!(session.state, ExecutionSessionState::Completed);
        assert_eq!(task.state, TaskState::Completed);
    }

    #[test]
    fn resume_requires_checkpoint() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();
        block_on_approval(
            &mut session,
            &mut task,
            "approval-1",
            "workspace mutation requires human approval",
        )
        .unwrap();

        let error = resume_from_approval(&mut session, &mut task, "approval-1").unwrap_err();
        assert_eq!(error, TransitionError::MissingCheckpoint);
    }

    #[test]
    fn worker_dispatch_and_result_resume_correctly() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();

        let dispatch = worker_dispatch(&session.header.session_id, &task.task_id);
        let worker_card = worker_card();
        let envelope = worker_envelope();
        let outcome = checkpointed_dispatch_to_worker(
            &mut session,
            &mut task,
            &worker_card,
            &envelope,
            &dispatch,
            "checkpoint-worker-1",
            Vec::new(),
            vec!["pointer-index".to_string()],
            FailureBudget::default().snapshot(),
            vec![dispatch.dispatch_id.clone()],
        )
        .unwrap();
        let WorkerDispatchCheckpointOutcome::Dispatched(checkpoint) = outcome else {
            panic!("expected worker dispatch to proceed without approval");
        };

        assert_eq!(session.state, ExecutionSessionState::AwaitingWorkerResult);
        assert_eq!(task.state, TaskState::BlockedOnWorker);
        assert_eq!(
            checkpoint.outstanding_worker_refs,
            vec![dispatch.worker_id.clone()]
        );

        let result = worker_result(&dispatch);
        accept_worker_result(&mut session, &mut task, &result).unwrap();

        assert_eq!(session.state, ExecutionSessionState::Ready);
        assert_eq!(task.state, TaskState::Ready);
        assert!(session.outstanding_worker_refs.is_empty());
    }

    #[test]
    fn worker_dispatch_rejects_missing_required_world() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();

        let dispatch = worker_dispatch(&session.header.session_id, &task.task_id);
        let worker_card = worker_card();
        let mut envelope = worker_envelope();
        envelope
            .world_grants
            .retain(|grant| grant.world != CapabilityWorld::MemoryAccess);

        let error = dispatch_to_worker(&mut session, &mut task, &worker_card, &envelope, &dispatch)
            .unwrap_err();

        assert_eq!(
            error,
            TransitionError::CapabilityWorldMissing {
                world: "MemoryAccess".to_string(),
                envelope_id: envelope.envelope_id,
            }
        );
    }

    #[test]
    fn worker_dispatch_rejects_missing_operation() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();

        let mut dispatch = worker_dispatch(&session.header.session_id, &task.task_id);
        dispatch
            .requested_capabilities
            .push(CapabilityOperationRequest {
                world: CapabilityWorld::WorkspaceObserve,
                operation: "open-worktree".to_string(),
                resource_scope: "workspace-root".to_string(),
            });
        let worker_card = worker_card();
        let envelope = worker_envelope();

        let error = dispatch_to_worker(&mut session, &mut task, &worker_card, &envelope, &dispatch)
            .unwrap_err();

        assert_eq!(
            error,
            TransitionError::OperationNotAllowed {
                world: "WorkspaceObserve".to_string(),
                operation: "open-worktree".to_string(),
                envelope_id: envelope.envelope_id,
            }
        );
    }

    #[test]
    fn worker_dispatch_rejects_forbidden_operation() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();

        let dispatch = worker_dispatch(&session.header.session_id, &task.task_id);
        let worker_card = worker_card();
        let mut envelope = worker_envelope();
        envelope.world_grants[1]
            .operation_approval_overrides
            .push(CapabilityOperationApproval {
                operation: "search".to_string(),
                approval_class: ApprovalClass::Forbidden,
            });

        let error = dispatch_to_worker(&mut session, &mut task, &worker_card, &envelope, &dispatch)
            .unwrap_err();

        assert_eq!(
            error,
            TransitionError::ApprovalClassBlocksOperation {
                world: "WorkspaceObserve".to_string(),
                operation: "search".to_string(),
                approval_class: "Forbidden".to_string(),
            }
        );
    }

    #[test]
    fn worker_dispatch_generates_approval_request_for_human_required_operation() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();

        let dispatch = worker_dispatch(&session.header.session_id, &task.task_id);
        let worker_card = worker_card();
        let mut envelope = worker_envelope();
        envelope.world_grants[1]
            .operation_approval_overrides
            .push(CapabilityOperationApproval {
                operation: "search".to_string(),
                approval_class: ApprovalClass::HumanRequired,
            });

        let outcome =
            dispatch_to_worker(&mut session, &mut task, &worker_card, &envelope, &dispatch)
                .unwrap();

        let WorkerDispatchOutcome::ApprovalRequired(request) = outcome else {
            panic!("expected approval request instead of immediate dispatch");
        };

        assert_eq!(request.approval_request_id, "approval-dispatch-1");
        assert_eq!(request.scope_ref, "workspace-root");
        assert_eq!(request.requested_authority_class, AuthorityClass::Observe);
        assert_eq!(request.status, ApprovalDecisionStatus::Requested);
        assert_eq!(session.state, ExecutionSessionState::ExecutingTurn);
        assert_eq!(task.state, TaskState::Running);
    }

    #[test]
    fn checkpointed_worker_dispatch_blocks_on_human_required_operation() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();

        let dispatch = worker_dispatch(&session.header.session_id, &task.task_id);
        let worker_card = worker_card();
        let mut envelope = worker_envelope();
        envelope.world_grants[1]
            .operation_approval_overrides
            .push(CapabilityOperationApproval {
                operation: "search".to_string(),
                approval_class: ApprovalClass::HumanRequired,
            });

        let outcome = checkpointed_dispatch_to_worker(
            &mut session,
            &mut task,
            &worker_card,
            &envelope,
            &dispatch,
            "checkpoint-approval-worker-1",
            Vec::new(),
            vec!["pointer-index".to_string()],
            FailureBudget::default().snapshot(),
            vec![dispatch.dispatch_id.clone()],
        )
        .unwrap();

        let WorkerDispatchCheckpointOutcome::ApprovalBlocked {
            approval_request,
            checkpoint,
        } = outcome
        else {
            panic!("expected checkpointed worker dispatch to block on approval");
        };

        assert_eq!(approval_request.approval_request_id, "approval-dispatch-1");
        assert_eq!(
            approval_request.action_ref,
            "dispatch:dispatch-1:WorkspaceObserve:search"
        );
        assert_eq!(approval_request.scope_ref, "workspace-root");
        assert_eq!(
            checkpoint.pending_approval_refs,
            vec!["approval-dispatch-1".to_string()]
        );
        assert_eq!(
            checkpoint
                .blocked_reason
                .as_ref()
                .map(|blocked_reason| blocked_reason.detail.as_str()),
            Some("worker dispatch dispatch-1 requires approval for workspace-root")
        );
        assert_eq!(session.state, ExecutionSessionState::AwaitingApproval);
        assert_eq!(task.state, TaskState::BlockedOnApproval);
        assert!(session.outstanding_worker_refs.is_empty());

        let mut memory_store = MemoryStore::default();
        let memory_write = crate::execution::persist_approval_request_bundle(
            &mut memory_store,
            &approval_request,
            &checkpoint,
        );
        assert_eq!(memory_store.artifacts.len(), 4);
        assert_eq!(
            memory_store
                .get(&memory_write.approval_request_artifact_id)
                .expect("approval request artifact should exist")
                .class,
            MemoryArtifactClass::ApprovalRequestArtifact
        );
        assert_eq!(
            memory_store
                .get(&memory_write.audit_artifact_id)
                .expect("approval audit artifact should exist")
                .class,
            MemoryArtifactClass::AuditRecordArtifact
        );
        assert!(
            memory_store
                .artifacts_for_related_ref(
                    "capability:dispatch-1:WorkspaceObserve:search:workspace-root"
                )
                .iter()
                .any(|artifact| artifact.class == MemoryArtifactClass::AuditRecordArtifact)
        );
        assert!(
            memory_store
                .artifacts_for_related_ref("approval-transport:approval-dispatch-1")
                .iter()
                .any(|artifact| artifact.class == MemoryArtifactClass::AuditRecordArtifact)
        );
    }

    #[test]
    fn worker_dispatch_rejects_missing_resource_scope() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();

        let dispatch = worker_dispatch(&session.header.session_id, &task.task_id);
        let worker_card = worker_card();
        let mut envelope = worker_envelope();
        envelope
            .allowed_resource_scopes
            .retain(|scope| scope != "workspace-root");

        let error = dispatch_to_worker(&mut session, &mut task, &worker_card, &envelope, &dispatch)
            .unwrap_err();

        assert_eq!(
            error,
            TransitionError::ResourceScopeNotAllowed {
                resource_scope: "workspace-root".to_string(),
                envelope_id: envelope.envelope_id,
            }
        );
    }

    #[test]
    fn worker_dispatch_rejects_mismatched_parent_session() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();

        let mut dispatch = worker_dispatch(&session.header.session_id, &task.task_id);
        dispatch.parent_session_id = "session-other".to_string();
        let worker_card = worker_card();
        let envelope = worker_envelope();

        let error = dispatch_to_worker(&mut session, &mut task, &worker_card, &envelope, &dispatch)
            .unwrap_err();

        assert_eq!(
            error,
            TransitionError::DispatchSessionMismatch {
                dispatch_session_id: "session-other".to_string(),
                session_id: session.header.session_id.clone(),
            }
        );
    }

    #[test]
    fn worker_dispatch_rejects_mismatched_campaign_scope() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();

        let dispatch = worker_dispatch(&session.header.session_id, &task.task_id);
        let worker_card = worker_card();
        let mut envelope = worker_envelope();
        envelope.campaign_scope = Some("campaign-other".to_string());

        let error = dispatch_to_worker(&mut session, &mut task, &worker_card, &envelope, &dispatch)
            .unwrap_err();

        assert_eq!(
            error,
            TransitionError::EnvelopeCampaignScopeMismatch {
                envelope_id: envelope.envelope_id,
                envelope_campaign_id: "campaign-other".to_string(),
                session_campaign_id: session.header.campaign_id.clone(),
            }
        );
    }

    #[test]
    fn worker_dispatch_rejects_per_worker_concurrency_overrun() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();
        session.outstanding_worker_refs.push("worker-1".to_string());

        let dispatch = worker_dispatch(&session.header.session_id, &task.task_id);
        let worker_card = worker_card();
        let envelope = worker_envelope();

        let error = dispatch_to_worker(&mut session, &mut task, &worker_card, &envelope, &dispatch)
            .unwrap_err();

        assert_eq!(
            error,
            TransitionError::WorkerConcurrencyExceeded {
                worker_id: "worker-1".to_string(),
                max_concurrency: 1,
                outstanding_dispatches: 1,
            }
        );
    }

    #[test]
    fn denied_approval_cannot_resume() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();
        block_on_approval(
            &mut session,
            &mut task,
            "approval-1",
            "workspace mutation requires human approval",
        )
        .unwrap();
        session.latest_checkpoint_ref = Some("checkpoint-1".to_string());

        let denied = ApprovalDecision {
            approval_request_id: "approval-1".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            session_id: session.header.session_id.clone(),
            task_id: task.task_id.clone(),
            action_ref: "workspace-root".to_string(),
            decision: ApprovalDecisionStatus::Denied,
            decided_by: "operator-1".to_string(),
            scope_ref: "workspace-root".to_string(),
            notes: Some("Denied for safety".to_string()),
        };

        let error = apply_approval_decision(&mut session, &mut task, &denied).unwrap_err();
        assert_eq!(
            error,
            TransitionError::ApprovalDecisionNotGranted {
                approval_request_id: "approval-1".to_string(),
                status: ApprovalDecisionStatus::Denied,
            }
        );
    }

    #[test]
    fn approval_decision_must_match_active_session_and_task_context() {
        let mut session = supervisor_session();
        let mut task = task();

        bind_session_ready(&mut session).unwrap();
        start_turn(&mut session, &mut task, "turn-1").unwrap();
        block_on_approval(
            &mut session,
            &mut task,
            "approval-1",
            "workspace mutation requires human approval",
        )
        .unwrap();
        session.latest_checkpoint_ref = Some("checkpoint-1".to_string());

        let mismatched_decision = ApprovalDecision::granted(
            "approval-1",
            "campaign-1",
            "epoch-1",
            "other-session",
            task.task_id.clone(),
            "workspace-root",
            "operator-1",
            "workspace-root",
            None,
        );

        let error =
            apply_approval_decision(&mut session, &mut task, &mismatched_decision).unwrap_err();

        assert_eq!(
            error,
            TransitionError::MissingApproval {
                approval_request_id: "approval-1".to_string(),
            }
        );
        assert_eq!(session.state, ExecutionSessionState::AwaitingApproval);
        assert_eq!(task.state, TaskState::BlockedOnApproval);
    }

    #[test]
    fn promoted_incumbent_activation_creates_next_epoch_ready_session() {
        let prior_session = supervisor_session();
        let promotion_readiness = crate::execution::PromotionReadinessDecision {
            decision_id: "promotion-readiness-1".to_string(),
            comparison_id: "comparison-1".to_string(),
            challenger_ref: "session-challenger-1".to_string(),
            status: crate::execution::PromotionReadinessStatus::Promotable,
            rationale: "challenger is promotion-ready".to_string(),
            required_preconditions: Vec::new(),
            rollback_handle_refs: vec!["rollback-1".to_string()],
            review_artifact_refs: vec!["review-artifact-1".to_string()],
            quarantine_refs: Vec::new(),
        };
        let promotion_act = open_promotion_act(
            "promotion-act-1",
            &promotion_readiness,
            &promotable_comparison(),
            "epoch-1",
            "epoch-2",
            "campaign-successor-1",
            vec!["comparison-1".to_string()],
        )
        .unwrap();
        let adoption = plan_epoch_adoption(
            "adoption-1",
            &promotion_act,
            "session-incumbent-1",
            "session-challenger-1",
            "session-activated-1",
            vec!["review-artifact-1".to_string()],
            "adoption planned",
        );
        let root_task = TaskArtifact::new("task-successor-root", "Bounded successor campaign");

        let (activated_session, checkpoint) = activate_promoted_incumbent(
            &prior_session,
            &promotion_act,
            &adoption,
            "envelope-promoted-native",
            Some(&root_task),
            "checkpoint-epoch-handoff-1",
            Vec::new(),
            vec!["review-artifact-1".to_string()],
            FailureBudget::default().snapshot(),
            vec!["epoch-handoff-once".to_string()],
        )
        .unwrap();

        assert_eq!(activated_session.state, ExecutionSessionState::Ready);
        assert_eq!(activated_session.header.epoch_id, "epoch-2");
        assert_eq!(activated_session.header.campaign_id, "campaign-successor-1");
        assert_eq!(
            activated_session.header.parent_session_id.as_deref(),
            Some("session-1")
        );
        assert_eq!(checkpoint.checkpoint_id, "checkpoint-epoch-handoff-1");
        assert_eq!(
            checkpoint.active_task_refs,
            vec!["task-successor-root".to_string()]
        );
    }
}
