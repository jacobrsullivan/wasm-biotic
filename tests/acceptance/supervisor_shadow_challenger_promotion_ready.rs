use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use crate::hardening_support::append_named_related_audit;
use aiaf_v1::execution::{
    ActorKind, AgendaItem, AgendaStatus, ApprovalClass, AuditRecord, AuditRecordClass,
    AuthorityClass, BackgroundCampaign, CapabilityEnvelope, CapabilityImportTarget,
    CapabilityOperationRequest, CapabilityWorld, CapabilityWorldGrant, DimensionVerdict,
    DurableArtifactStore, EvaluationDimension, EvaluationDimensionScore, EventFamily,
    ExecutionEvent, ExecutionSession, ExecutionSessionHeader, ExecutionSessionState, FailureBudget,
    GovernancePolicyClass, IsolationProfile, MemoryArtifact, MemoryScope, MemoryStore,
    NativeReplacementTier, NativeSufficiencyGate, OwnershipBoundary, OwnershipMode, PointerIndex,
    PromotionReadinessStatus, ProviderKind, ReplayableRuntimeState, ShadowCampaignStatus,
    ShadowEvaluationBundle, StopCondition, SynthesisClosureDecision, SynthesisHandoff,
    TaskArtifact, TaskGraph, TaskState, TickSource, WorkerCard, WorkerDispatch,
    WorkerDispatchCheckpointOutcome, WorkerRegistry, WorkerResult, WorkerRole,
    accept_worker_result, bind_session_ready, build_native_sufficiency_evidence,
    checkpointed_dispatch_to_worker, compare_challenger_outputs, complete_task,
    create_rollback_handle, decide_promotion_readiness, execute_rollback,
    open_challenger_evaluation_session, open_shadow_campaign, start_turn,
    validate_background_resume_with_runtime_state, validate_shadow_dispatch,
};

fn temp_store_root(name: &str) -> PathBuf {
    env::temp_dir().join(format!("rc03-aiaf-acceptance-{name}-{}", process::id()))
}

fn execution_event(
    event_id: &str,
    family: EventFamily,
    session: &ExecutionSession,
    task_id: Option<&str>,
    detail: &str,
) -> ExecutionEvent {
    ExecutionEvent::new(
        event_id,
        family,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        session
            .current_turn
            .as_ref()
            .map(|turn| turn.turn_id.clone()),
        task_id.map(str::to_string),
        detail.to_string(),
    )
}

fn world_grant(
    world: CapabilityWorld,
    authority: AuthorityClass,
    operations: Vec<&str>,
) -> CapabilityWorldGrant {
    CapabilityWorldGrant {
        world,
        allowed_operations: operations.into_iter().map(str::to_string).collect(),
        default_authority_class: authority,
        default_approval_class: ApprovalClass::AutoAllowed,
        operation_approval_overrides: Vec::new(),
    }
}

fn capability_envelope(
    envelope_id: &str,
    actor_scope: &str,
    authority_ceiling: AuthorityClass,
    world_grants: Vec<CapabilityWorldGrant>,
    allowed_resource_scopes: Vec<&str>,
) -> CapabilityEnvelope {
    CapabilityEnvelope {
        envelope_id: envelope_id.to_string(),
        actor_scope: actor_scope.to_string(),
        world_grants,
        authority_ceiling,
        isolation_profile: IsolationProfile::ArtifactSandbox,
        allowed_resource_scopes: allowed_resource_scopes
            .into_iter()
            .map(str::to_string)
            .collect(),
        approval_overrides: Vec::new(),
        quota_policy: None,
        campaign_scope: Some("campaign-rc03".to_string()),
        epoch_scope: Some("epoch-1".to_string()),
    }
}

fn worker_card(
    worker_id: &str,
    worker_role: WorkerRole,
    task_kind: &str,
    required_worlds: Vec<CapabilityWorld>,
    authority_ceiling: AuthorityClass,
    result_contract: &str,
) -> WorkerCard {
    WorkerCard {
        worker_id: worker_id.to_string(),
        worker_role,
        supported_task_kinds: vec![task_kind.to_string()],
        required_worlds,
        authority_ceiling,
        isolation_profile: IsolationProfile::ArtifactSandbox,
        result_contract: result_contract.to_string(),
        max_concurrency: 1,
    }
}

fn worker_dispatch(
    session: &ExecutionSession,
    task_id: &str,
    worker_card: &WorkerCard,
    capability_envelope_ref: &str,
    dispatch_id: &str,
    worker_task_ref: &str,
    payload_summary: &str,
    requested_capabilities: Vec<CapabilityOperationRequest>,
    referenced_artifacts: Vec<String>,
) -> WorkerDispatch {
    WorkerDispatch {
        dispatch_id: dispatch_id.to_string(),
        task_id: task_id.to_string(),
        parent_session_id: session.header.session_id.clone(),
        worker_id: worker_card.worker_id.clone(),
        worker_task_ref: worker_task_ref.to_string(),
        capability_envelope_ref: capability_envelope_ref.to_string(),
        requested_capabilities,
        dispatch_message: aiaf_v1::execution::MessageArtifact {
            message_id: format!("message-{dispatch_id}"),
            campaign_id: session.header.campaign_id.clone(),
            epoch_id: session.header.epoch_id.clone(),
            task_id: task_id.to_string(),
            sender_actor_ref: session.header.session_id.clone(),
            receiver_actor_ref: worker_card.worker_id.clone(),
            message_class: aiaf_v1::execution::MessageArtifactClass::DispatchMessage,
            payload_summary: payload_summary.to_string(),
            referenced_artifacts,
            status: aiaf_v1::execution::MessageArtifactStatus::Sent,
        },
    }
}

fn worker_result(
    session: &ExecutionSession,
    task_id: &str,
    worker_card: &WorkerCard,
    dispatch: &WorkerDispatch,
    result_ref: &str,
    summary: &str,
) -> WorkerResult {
    WorkerResult {
        dispatch_id: dispatch.dispatch_id.clone(),
        worker_id: worker_card.worker_id.clone(),
        worker_task_ref: dispatch.worker_task_ref.clone(),
        result_ref: result_ref.to_string(),
        summary: summary.to_string(),
        result_message: aiaf_v1::execution::MessageArtifact {
            message_id: format!("message-result-{result_ref}"),
            campaign_id: session.header.campaign_id.clone(),
            epoch_id: session.header.epoch_id.clone(),
            task_id: task_id.to_string(),
            sender_actor_ref: worker_card.worker_id.clone(),
            receiver_actor_ref: session.header.session_id.clone(),
            message_class: aiaf_v1::execution::MessageArtifactClass::ResultMessage,
            payload_summary: summary.to_string(),
            referenced_artifacts: vec![result_ref.to_string()],
            status: aiaf_v1::execution::MessageArtifactStatus::Received,
        },
    }
}

fn incumbent_runtime_state(shared_input_refs: &[String]) -> ReplayableRuntimeState {
    let mut session = ExecutionSession::new(ExecutionSessionHeader {
        session_id: "session-incumbent-1".to_string(),
        actor_kind: ActorKind::Supervisor,
        actor_id: "supervisor-incumbent".to_string(),
        campaign_id: "campaign-rc03".to_string(),
        epoch_id: "epoch-1".to_string(),
        capability_envelope_ref: "envelope-supervisor-incumbent".to_string(),
        parent_session_id: None,
    });
    bind_session_ready(&mut session).unwrap();
    session.state = ExecutionSessionState::Completed;

    let mut root_task = TaskArtifact::new(
        "task-root-rc03",
        "Incumbent supervisor baseline for bounded RC03 comparison",
    );
    root_task.state = TaskState::Completed;
    root_task.owner_session_id = Some(session.header.session_id.clone());
    root_task.output_refs = vec!["incumbent-output-shadow-review".to_string()];

    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(PointerIndex {
        index_id: "pointer-index-rc03".to_string(),
        scope: MemoryScope::Campaign("campaign-rc03".to_string()),
        entry_refs: shared_input_refs.to_vec(),
        contested_refs: Vec::new(),
        critical_refs: shared_input_refs.to_vec(),
        governance_constraints: vec![
            "challenger and incumbent must use the same shared inputs".to_string(),
            "challenger promotion remains deferred in rc03".to_string(),
        ],
        open_task_refs: vec!["task-root-rc03".to_string()],
        updated_at: "incumbent-baseline".to_string(),
    });

    let checkpoint = aiaf_v1::execution::RunCheckpoint::capture(
        "checkpoint-incumbent-1",
        &session,
        Some(&root_task),
        Vec::new(),
        Vec::new(),
        FailureBudget::default().snapshot(),
        vec!["same-input-shadow-evaluation".to_string()],
    );
    session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());

    ReplayableRuntimeState::new(
        session.clone(),
        root_task,
        TaskGraph::new("task-root-rc03", Vec::new()),
        memory_store,
        Some(checkpoint),
        vec![execution_event(
            "event-incumbent-baseline",
            EventFamily::GovernanceDecisionEvent,
            &session,
            Some("task-root-rc03"),
            "incumbent supervisor baseline available for RC03 comparison",
        )],
    )
}

#[test]
fn supervisor_shadow_challenger_promotion_ready_acceptance() {
    let root = temp_store_root("shadow-challenger");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let shared_input_refs = vec![
        "campaign-brief-shadow-1".to_string(),
        "pointer-index-rc03".to_string(),
    ];
    let root_task_id = "task-root-rc03";
    let evaluate_task_id = "task-shadow-evaluate";
    let review_task_id = "task-shadow-review";

    let mut challenger_memory = MemoryStore::default();
    challenger_memory.insert_pointer_index(PointerIndex {
        index_id: "pointer-index-rc03".to_string(),
        scope: MemoryScope::Campaign("campaign-rc03".to_string()),
        entry_refs: shared_input_refs.clone(),
        contested_refs: Vec::new(),
        critical_refs: shared_input_refs.clone(),
        governance_constraints: vec![
            "same-input challenger evaluation required".to_string(),
            "promotion readiness must preserve rollback".to_string(),
        ],
        open_task_refs: vec![root_task_id.to_string()],
        updated_at: "seed-load".to_string(),
    });

    let mut session = ExecutionSession::new(ExecutionSessionHeader {
        session_id: "session-challenger-1".to_string(),
        actor_kind: ActorKind::Supervisor,
        actor_id: "supervisor-native-challenger".to_string(),
        campaign_id: "campaign-rc03".to_string(),
        epoch_id: "epoch-1".to_string(),
        capability_envelope_ref: "envelope-supervisor-native".to_string(),
        parent_session_id: Some("session-incumbent-1".to_string()),
    });
    bind_session_ready(&mut session).unwrap();

    let mut root_task = TaskArtifact::new(
        root_task_id,
        "Bounded native challenger shadow campaign for RC03",
    );
    let mut task_graph = TaskGraph::new(
        root_task_id,
        vec![
            AgendaItem::new(
                "agenda-shadow-evaluate",
                evaluate_task_id,
                "shadow-evaluate",
                Vec::new(),
                OwnershipBoundary {
                    boundary_id: "boundary-shadow-evaluate".to_string(),
                    resource_scope: "campaign-shadow".to_string(),
                    mode: OwnershipMode::ReadOnlyFanOut,
                    owner_actor_ref: session.header.session_id.clone(),
                },
            ),
            AgendaItem::new(
                "agenda-shadow-review",
                review_task_id,
                "shadow-review",
                vec![evaluate_task_id.to_string()],
                OwnershipBoundary {
                    boundary_id: "boundary-shadow-review".to_string(),
                    resource_scope: "promotion-review".to_string(),
                    mode: OwnershipMode::MergeRequired,
                    owner_actor_ref: session.header.session_id.clone(),
                },
            ),
        ],
    );

    let evaluator_worker = worker_card(
        "worker-shadow-evaluator-1",
        WorkerRole::EvaluatorWorker,
        "shadow-evaluate",
        vec![
            CapabilityWorld::WorkerMessaging,
            CapabilityWorld::CampaignControl,
            CapabilityWorld::MemoryAccess,
        ],
        AuthorityClass::CampaignControl,
        "shadow-evaluation-result",
    );
    let reviewer_worker = worker_card(
        "worker-shadow-reviewer-1",
        WorkerRole::ReviewerWorker,
        "shadow-review",
        vec![
            CapabilityWorld::WorkerMessaging,
            CapabilityWorld::ApprovalGateway,
            CapabilityWorld::ReviewPromotion,
            CapabilityWorld::ScheduleTick,
            CapabilityWorld::MemoryAccess,
        ],
        AuthorityClass::PromotionControl,
        "promotion-readiness-result",
    );

    let evaluator_envelope = capability_envelope(
        "envelope-shadow-evaluator",
        &evaluator_worker.worker_id,
        AuthorityClass::CampaignControl,
        vec![
            world_grant(
                CapabilityWorld::WorkerMessaging,
                AuthorityClass::Observe,
                vec!["dispatch", "result"],
            ),
            world_grant(
                CapabilityWorld::CampaignControl,
                AuthorityClass::CampaignControl,
                vec!["shadow-plan-step"],
            ),
            world_grant(
                CapabilityWorld::MemoryAccess,
                AuthorityClass::Observe,
                vec!["read-pointer-index", "read-transcript-slice"],
            ),
        ],
        vec!["worker-channel", "campaign-shadow", "pointer-index-store"],
    );
    let reviewer_envelope = capability_envelope(
        "envelope-shadow-reviewer",
        &reviewer_worker.worker_id,
        AuthorityClass::PromotionControl,
        vec![
            world_grant(
                CapabilityWorld::WorkerMessaging,
                AuthorityClass::Observe,
                vec!["dispatch", "result"],
            ),
            world_grant(
                CapabilityWorld::ApprovalGateway,
                AuthorityClass::PromotionControl,
                vec!["stage-decision"],
            ),
            world_grant(
                CapabilityWorld::ReviewPromotion,
                AuthorityClass::PromotionControl,
                vec!["draft-promotion-readiness"],
            ),
            world_grant(
                CapabilityWorld::ScheduleTick,
                AuthorityClass::AutomationControl,
                vec!["register-shadow-tick"],
            ),
            world_grant(
                CapabilityWorld::MemoryAccess,
                AuthorityClass::Observe,
                vec![
                    "read-pointer-index",
                    "read-transcript-slice",
                    "append-audit-record",
                ],
            ),
        ],
        vec![
            "worker-channel",
            "approval-gateway",
            "promotion-review",
            "pointer-index-store",
            "shadow-tick",
        ],
    );

    let rollback_handle = create_rollback_handle(
        "rollback-shadow-challenger-1",
        "shadow-campaign",
        "checkpoint-shadow-evaluate-1",
        vec!["restore checkpoint-shadow-evaluate-1".to_string()],
        Vec::new(),
    );
    let mut shadow_campaign = open_shadow_campaign(
        "shadow-campaign-1",
        session.header.campaign_id.clone(),
        "session-incumbent-1",
        session.header.session_id.clone(),
        shared_input_refs.clone(),
        vec![TickSource::ScheduledTimer, TickSource::ApprovalResponse],
        vec![
            CapabilityImportTarget::CampaignControl,
            CapabilityImportTarget::ApprovalGateway,
            CapabilityImportTarget::ReviewPromotion,
            CapabilityImportTarget::ScheduleTick,
        ],
        true,
        rollback_handle.rollback_handle_id.clone(),
    )
    .unwrap();
    let mut challenger_evaluation_session = open_challenger_evaluation_session(
        "evaluation-session-1",
        &shadow_campaign,
        &shared_input_refs,
        &shared_input_refs,
        vec![
            evaluator_envelope.envelope_id.clone(),
            reviewer_envelope.envelope_id.clone(),
        ],
    )
    .unwrap();

    let mut worker_registry = WorkerRegistry::default();
    worker_registry.register(evaluator_worker.clone());
    worker_registry.register(reviewer_worker.clone());

    let mut event_log = vec![execution_event(
        "event-shadow-ready",
        EventFamily::SessionLifecycleEvent,
        &session,
        Some(root_task_id),
        "challenger supervisor bound to ready state for RC03 shadow campaign",
    )];

    let evaluator_routing = worker_registry
        .select_worker(
            "shadow-evaluate",
            &[
                CapabilityWorld::WorkerMessaging,
                CapabilityWorld::CampaignControl,
                CapabilityWorld::MemoryAccess,
            ],
            &AuthorityClass::CampaignControl,
            &IsolationProfile::ArtifactSandbox,
        )
        .unwrap();
    assert_eq!(evaluator_routing.worker_id, evaluator_worker.worker_id);
    task_graph
        .mark_dispatched(
            "agenda-shadow-evaluate",
            evaluator_routing.worker_id.clone(),
        )
        .unwrap();

    start_turn(&mut session, &mut root_task, "turn-shadow-evaluate").unwrap();
    shadow_campaign.status = ShadowCampaignStatus::Running;

    let evaluator_dispatch = worker_dispatch(
        &session,
        root_task_id,
        &evaluator_worker,
        &evaluator_envelope.envelope_id,
        "dispatch-shadow-evaluate-1",
        "shadow-evaluate-task-1",
        "evaluate native challenger against incumbent campaign inputs",
        vec![
            CapabilityOperationRequest {
                world: CapabilityWorld::WorkerMessaging,
                operation: "dispatch".to_string(),
                resource_scope: "worker-channel".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::CampaignControl,
                operation: "shadow-plan-step".to_string(),
                resource_scope: "campaign-shadow".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::MemoryAccess,
                operation: "read-pointer-index".to_string(),
                resource_scope: "pointer-index-store".to_string(),
            },
        ],
        shared_input_refs.clone(),
    );
    validate_shadow_dispatch(
        &challenger_evaluation_session,
        &evaluator_dispatch,
        &evaluator_envelope,
    )
    .unwrap();

    let WorkerDispatchCheckpointOutcome::Dispatched(evaluator_checkpoint) =
        checkpointed_dispatch_to_worker(
            &mut session,
            &mut root_task,
            &evaluator_worker,
            &evaluator_envelope,
            &evaluator_dispatch,
            "checkpoint-shadow-evaluate-1",
            vec![
                aiaf_v1::execution::NormalizedProposal::new(
                    aiaf_v1::execution::ProposalFamily::CapabilityCallRequest,
                    "dispatch bounded shadow evaluation worker",
                    Some("campaign-shadow".to_string()),
                )
                .unwrap(),
            ],
            Vec::new(),
            FailureBudget::default().snapshot(),
            vec!["shadow-evaluate-once".to_string()],
        )
        .unwrap()
    else {
        panic!("shadow evaluator dispatch should not require extra approval");
    };
    shadow_campaign.challenger_checkpoint_ref = Some(evaluator_checkpoint.checkpoint_id.clone());
    challenger_evaluation_session.latest_challenger_checkpoint_ref =
        Some(evaluator_checkpoint.checkpoint_id.clone());

    let checkpoint_artifact_id = challenger_memory.append(MemoryArtifact::checkpoint(
        "memory-checkpoint-shadow-evaluate-1",
        evaluator_checkpoint.clone(),
        "challenger evaluation checkpoint persisted",
    ));
    event_log.push(execution_event(
        "event-shadow-checkpoint-1",
        EventFamily::CheckpointEvent,
        &session,
        Some(root_task_id),
        "shadow evaluator dispatch checkpoint persisted",
    ));
    challenger_memory.append(MemoryArtifact::audit_record(
        "memory-audit-shadow-checkpoint-rollback",
        AuditRecord::new(
            "audit-shadow-checkpoint-rollback",
            AuditRecordClass::GovernanceAuditRecord,
            session.header.campaign_id.clone(),
            session.header.epoch_id.clone(),
            session.header.session_id.clone(),
            Some(root_task_id.to_string()),
            evaluator_checkpoint.checkpoint_id.clone(),
            "shadow checkpoint retained for governed rollback reconstruction",
        ),
    ));
    challenger_memory.append(MemoryArtifact::audit_record(
        "memory-audit-shadow-rollback-handle",
        AuditRecord::new(
            "audit-shadow-rollback-handle",
            AuditRecordClass::PromotionAuditRecord,
            session.header.campaign_id.clone(),
            session.header.epoch_id.clone(),
            session.header.session_id.clone(),
            Some(root_task_id.to_string()),
            rollback_handle.rollback_handle_id.clone(),
            "shadow rollback handle retained for challenger recovery",
        ),
    ));

    let scheduled_runtime_state = ReplayableRuntimeState::new(
        session.clone(),
        root_task.clone(),
        task_graph.clone(),
        challenger_memory.clone(),
        Some(evaluator_checkpoint.clone()),
        event_log.clone(),
    );
    store
        .persist_runtime_state(&scheduled_runtime_state)
        .unwrap();

    let background_campaign = BackgroundCampaign {
        campaign_id: session.header.campaign_id.clone(),
        objective: "continue challenger shadow campaign from durable checkpoint".to_string(),
        authority_ceiling: AuthorityClass::CampaignControl,
        allowed_tick_sources: vec![TickSource::ScheduledTimer, TickSource::ApprovalResponse],
        max_concurrent_sessions: 1,
        stop_conditions: vec![StopCondition::ExplicitTaskCompletion],
        approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
        audit_policy: GovernancePolicyClass::PromotionGovernancePolicy,
    };
    validate_background_resume_with_runtime_state(
        &background_campaign,
        &TickSource::ScheduledTimer,
        &scheduled_runtime_state,
        &[],
        &[],
        &shadow_campaign.shadow_campaign_id,
    )
    .unwrap();

    let evaluator_result = worker_result(
        &session,
        root_task_id,
        &evaluator_worker,
        &evaluator_dispatch,
        "challenger-evaluation-output-1",
        "challenger matched incumbent control behavior under the same campaign inputs",
    );
    accept_worker_result(&mut session, &mut root_task, &evaluator_result).unwrap();
    root_task.record_output_ref(evaluator_result.result_ref.clone());
    task_graph
        .apply_synthesis_handoff(
            "agenda-shadow-evaluate",
            &SynthesisHandoff {
                handoff_id: "handoff-shadow-evaluate-1".to_string(),
                task_id: evaluate_task_id.to_string(),
                worker_output_refs: vec![evaluator_result.result_ref.clone()],
                supervisor_summary: "bounded shadow evaluation is complete".to_string(),
                next_action: "run promotion-readiness review".to_string(),
                closure_decision: SynthesisClosureDecision::Complete,
            },
        )
        .unwrap();
    task_graph.refresh_ready_states(&[evaluate_task_id.to_string()]);
    assert_eq!(
        task_graph
            .agenda_item("agenda-shadow-review")
            .unwrap()
            .status,
        AgendaStatus::Ready
    );

    challenger_memory.add_transcript_slice(aiaf_v1::execution::TranscriptSlice {
        slice_id: "slice-shadow-evaluate-1".to_string(),
        campaign_id: session.header.campaign_id.clone(),
        epoch_id: session.header.epoch_id.clone(),
        session_id: Some(session.header.session_id.clone()),
        task_id: Some(evaluate_task_id.to_string()),
        referenced_artifacts: vec![evaluator_result.result_ref.clone()],
        summary: "challenger evaluation transcript slice".to_string(),
        excerpts: vec![
            "challenger stayed within campaign-control and memory-access bounds".to_string(),
        ],
    });
    let evaluator_audit = AuditRecord::new(
        "audit-shadow-evaluate-1",
        AuditRecordClass::GovernanceAuditRecord,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(evaluate_task_id.to_string()),
        evaluator_checkpoint.checkpoint_id.clone(),
        "shadow evaluation checkpoint is replayable and side-effect bounded",
    );
    let evaluator_audit_artifact_id = challenger_memory.append(MemoryArtifact::audit_record(
        "memory-audit-shadow-evaluate-1",
        evaluator_audit,
    ));

    let reviewer_routing = worker_registry
        .select_worker(
            "shadow-review",
            &[
                CapabilityWorld::WorkerMessaging,
                CapabilityWorld::ApprovalGateway,
                CapabilityWorld::ReviewPromotion,
                CapabilityWorld::ScheduleTick,
                CapabilityWorld::MemoryAccess,
            ],
            &AuthorityClass::PromotionControl,
            &IsolationProfile::ArtifactSandbox,
        )
        .unwrap();
    assert_eq!(reviewer_routing.worker_id, reviewer_worker.worker_id);
    task_graph
        .mark_dispatched("agenda-shadow-review", reviewer_routing.worker_id.clone())
        .unwrap();

    start_turn(&mut session, &mut root_task, "turn-shadow-review").unwrap();
    let reviewer_dispatch = worker_dispatch(
        &session,
        root_task_id,
        &reviewer_worker,
        &reviewer_envelope.envelope_id,
        "dispatch-shadow-review-1",
        "shadow-review-task-1",
        "prepare promotion-readiness review for the challenger supervisor",
        vec![
            CapabilityOperationRequest {
                world: CapabilityWorld::WorkerMessaging,
                operation: "dispatch".to_string(),
                resource_scope: "worker-channel".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::ApprovalGateway,
                operation: "stage-decision".to_string(),
                resource_scope: "approval-gateway".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::ReviewPromotion,
                operation: "draft-promotion-readiness".to_string(),
                resource_scope: "promotion-review".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::ScheduleTick,
                operation: "register-shadow-tick".to_string(),
                resource_scope: "shadow-tick".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::MemoryAccess,
                operation: "read-transcript-slice".to_string(),
                resource_scope: "pointer-index-store".to_string(),
            },
        ],
        vec![
            evaluator_result.result_ref.clone(),
            "slice-shadow-evaluate-1".to_string(),
        ],
    );
    validate_shadow_dispatch(
        &challenger_evaluation_session,
        &reviewer_dispatch,
        &reviewer_envelope,
    )
    .unwrap();

    let WorkerDispatchCheckpointOutcome::Dispatched(reviewer_checkpoint) =
        checkpointed_dispatch_to_worker(
            &mut session,
            &mut root_task,
            &reviewer_worker,
            &reviewer_envelope,
            &reviewer_dispatch,
            "checkpoint-shadow-review-1",
            vec![
                aiaf_v1::execution::NormalizedProposal::new(
                    aiaf_v1::execution::ProposalFamily::CapabilityCallRequest,
                    "dispatch promotion-readiness reviewer",
                    Some("promotion-review".to_string()),
                )
                .unwrap(),
            ],
            vec![
                checkpoint_artifact_id.clone(),
                evaluator_audit_artifact_id.clone(),
            ],
            FailureBudget::default().snapshot(),
            vec!["shadow-review-once".to_string()],
        )
        .unwrap()
    else {
        panic!("shadow reviewer dispatch should not require extra approval");
    };
    shadow_campaign.challenger_checkpoint_ref = Some(reviewer_checkpoint.checkpoint_id.clone());
    challenger_evaluation_session.latest_challenger_checkpoint_ref =
        Some(reviewer_checkpoint.checkpoint_id.clone());
    let review_checkpoint_artifact_id = challenger_memory.append(MemoryArtifact::checkpoint(
        "memory-checkpoint-shadow-review-1",
        reviewer_checkpoint.clone(),
        "challenger review checkpoint persisted",
    ));
    challenger_memory.append(MemoryArtifact::audit_record(
        "memory-audit-checkpoint-shadow-review-1",
        AuditRecord::new(
            "audit-checkpoint-shadow-review-1",
            AuditRecordClass::GovernanceAuditRecord,
            session.header.campaign_id.clone(),
            session.header.epoch_id.clone(),
            session.header.session_id.clone(),
            Some(root_task_id.to_string()),
            reviewer_checkpoint.checkpoint_id.clone(),
            "challenger review checkpoint remained reconstructable",
        ),
    ));
    event_log.push(execution_event(
        "event-shadow-checkpoint-2",
        EventFamily::CheckpointEvent,
        &session,
        Some(root_task_id),
        "shadow reviewer dispatch checkpoint persisted",
    ));

    store
        .persist_runtime_state(&ReplayableRuntimeState::new(
            session.clone(),
            root_task.clone(),
            task_graph.clone(),
            challenger_memory.clone(),
            Some(reviewer_checkpoint.clone()),
            event_log.clone(),
        ))
        .unwrap();

    let reviewer_result = worker_result(
        &session,
        root_task_id,
        &reviewer_worker,
        &reviewer_dispatch,
        "challenger-review-output-1",
        "challenger is promotable after governed comparison, but live replacement remains deferred",
    );
    accept_worker_result(&mut session, &mut root_task, &reviewer_result).unwrap();
    root_task.record_output_ref(reviewer_result.result_ref.clone());
    let review_artifact_ref = "review-artifact-shadow-1".to_string();
    root_task.record_output_ref(review_artifact_ref.clone());
    task_graph
        .apply_synthesis_handoff(
            "agenda-shadow-review",
            &SynthesisHandoff {
                handoff_id: "handoff-shadow-review-1".to_string(),
                task_id: review_task_id.to_string(),
                worker_output_refs: vec![
                    reviewer_result.result_ref.clone(),
                    review_artifact_ref.clone(),
                ],
                supervisor_summary: "promotion-readiness review completed without live promotion"
                    .to_string(),
                next_action: "finalize challenger comparison and decision bundle".to_string(),
                closure_decision: SynthesisClosureDecision::Complete,
            },
        )
        .unwrap();

    start_turn(&mut session, &mut root_task, "turn-shadow-complete").unwrap();
    complete_task(&mut session, &mut root_task).unwrap();
    assert_eq!(session.state, ExecutionSessionState::Completed);
    assert_eq!(root_task.state, TaskState::Completed);

    let comparison = compare_challenger_outputs(
        "comparison-shadow-1",
        "session-incumbent-1",
        session.header.session_id.clone(),
        shared_input_refs.clone(),
        vec!["incumbent-output-shadow-review".to_string()],
        vec![
            evaluator_result.result_ref.clone(),
            reviewer_result.result_ref.clone(),
        ],
        vec![
            EvaluationDimensionScore {
                dimension: EvaluationDimension::SemanticCorrectness,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "incumbent supervisor completed the bounded campaign"
                    .to_string(),
                challenger_summary: "challenger supervisor completed the same bounded campaign"
                    .to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::GovernanceFidelity,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "incumbent respected approval and rollback boundaries"
                    .to_string(),
                challenger_summary: "challenger respected approval and rollback boundaries"
                    .to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::Replayability,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "incumbent baseline was replayable".to_string(),
                challenger_summary: "challenger generated replayable checkpoints".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::OperatorBurden,
                verdict: DimensionVerdict::ChallengerBetter,
                incumbent_summary: "incumbent required more manual review stitching".to_string(),
                challenger_summary: "challenger packaged a tighter decision bundle".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::BoundaryCost,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "incumbent used bounded worker boundaries".to_string(),
                challenger_summary: "challenger used bounded worker boundaries".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::ReplacementSafety,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "incumbent retained rollback coverage".to_string(),
                challenger_summary: "challenger retained rollback coverage".to_string(),
            },
        ],
        "native challenger completed a governed same-input shadow campaign",
    )
    .unwrap();
    assert_eq!(
        comparison.target,
        CapabilityImportTarget::NativeSupervisorChallenger
    );
    assert_eq!(
        comparison.replacement_tier,
        NativeReplacementTier::NativeSupervisorChallengers
    );
    assert_eq!(comparison.imported_provider, ProviderKind::Imported);
    assert_eq!(comparison.native_provider, ProviderKind::Native);
    assert_eq!(comparison.shared_input_refs, shared_input_refs);
    assert!(comparison.matched);

    shadow_campaign.status = ShadowCampaignStatus::Compared;
    let review_audit = AuditRecord::new(
        "audit-shadow-review-1",
        AuditRecordClass::PromotionAuditRecord,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(review_task_id.to_string()),
        comparison.comparison_id.clone(),
        "shadow review completed with promotion-readiness only",
    );
    let _review_audit_artifact_id = challenger_memory.append(MemoryArtifact::audit_record(
        "memory-audit-shadow-review-1",
        review_audit,
    ));
    let sufficiency_evidence = build_native_sufficiency_evidence(
        "evidence-shadow-1",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::NativeSupervisorChallengers,
        vec![
            checkpoint_artifact_id.clone(),
            review_checkpoint_artifact_id.clone(),
            review_artifact_ref.clone(),
        ],
        vec![
            evaluator_checkpoint.checkpoint_id.clone(),
            reviewer_checkpoint.checkpoint_id.clone(),
        ],
        vec![
            "audit-shadow-evaluate-1".to_string(),
            "audit-shadow-review-1".to_string(),
        ],
        "challenger completed native control-plane evaluation with artifact-backed continuity",
        true,
    );
    let evidence_audit_artifact_id = challenger_memory.append(MemoryArtifact::audit_record(
        "memory-audit-shadow-evidence-1",
        AuditRecord::new(
            "audit-shadow-evidence-1",
            AuditRecordClass::PromotionAuditRecord,
            session.header.campaign_id.clone(),
            session.header.epoch_id.clone(),
            session.header.session_id.clone(),
            Some(review_task_id.to_string()),
            sufficiency_evidence.evidence_id.clone(),
            "shadow sufficiency evidence remained reconstructable",
        ),
    ));
    assert!(
        challenger_memory
            .artifacts_for_related_ref(&sufficiency_evidence.evidence_id)
            .iter()
            .any(|artifact| artifact.artifact_id == evidence_audit_artifact_id)
    );
    append_named_related_audit(
        &mut challenger_memory,
        &session,
        Some(root_task_id),
        &review_artifact_ref,
        "audit-review-artifact-shadow-1",
        AuditRecordClass::GovernanceAuditRecord,
        "shadow review artifact remained reconstructable",
    );
    let promotion_gate = NativeSufficiencyGate {
        target: CapabilityImportTarget::NativeSupervisorChallenger,
        required_tier: NativeReplacementTier::NativeSupervisorChallengers,
        requires_exact_match: true,
    };
    let promotion_readiness = decide_promotion_readiness(
        "promotion-readiness-1",
        &comparison,
        &promotion_gate,
        &sufficiency_evidence,
        &[rollback_handle.clone()],
        std::slice::from_ref(&review_artifact_ref),
        &[],
    );
    assert_eq!(
        promotion_readiness.status,
        PromotionReadinessStatus::Promotable
    );
    assert!(promotion_readiness.required_preconditions.is_empty());
    shadow_campaign.status = ShadowCampaignStatus::DecisionReady;

    let challenger_state = ReplayableRuntimeState::new(
        session.clone(),
        root_task.clone(),
        task_graph.clone(),
        challenger_memory.clone(),
        Some(reviewer_checkpoint.clone()),
        event_log.clone(),
    );
    store.persist_runtime_state(&challenger_state).unwrap();

    let shadow_bundle = ShadowEvaluationBundle {
        shadow_campaign: shadow_campaign.clone(),
        challenger_evaluation_session: challenger_evaluation_session.clone(),
        incumbent_runtime_state: incumbent_runtime_state(&shared_input_refs),
        challenger_runtime_state: challenger_state.clone(),
        comparison_record: comparison.clone(),
        sufficiency_evidence: sufficiency_evidence.clone(),
        promotion_readiness_decision: promotion_readiness.clone(),
    };
    store
        .persist_shadow_evaluation_bundle(&shadow_bundle)
        .unwrap();
    let reloaded_shadow_bundle = store
        .load_shadow_evaluation_bundle(&shadow_campaign.shadow_campaign_id)
        .unwrap();
    assert_eq!(reloaded_shadow_bundle, shadow_bundle);

    let rolled_back = execute_rollback(&rollback_handle, &store).unwrap();
    assert_eq!(
        rolled_back.latest_checkpoint.unwrap().checkpoint_id,
        evaluator_checkpoint.checkpoint_id
    );
    assert_eq!(
        rolled_back.session.state,
        ExecutionSessionState::AwaitingWorkerResult
    );
    assert_eq!(rolled_back.root_task.state, TaskState::BlockedOnWorker);
    assert_eq!(shadow_campaign.status, ShadowCampaignStatus::DecisionReady);
}
