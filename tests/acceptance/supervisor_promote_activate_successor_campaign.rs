use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use crate::hardening_support::{append_named_related_audit, append_v14_program_evidence};
use aiaf_v1::execution::{
    ActorKind, AgendaItem, AgendaStatus, ApprovalClass, AuditRecord, AuditRecordClass,
    AuthorityClass, BackgroundCampaign, CapabilityEnvelope, CapabilityImportTarget,
    CapabilityOperationRequest, CapabilityWorld, CapabilityWorldGrant, DimensionVerdict,
    DurableArtifactStore, EpochAdoptionStatus, EvaluationDimension, EvaluationDimensionScore,
    EventFamily, ExecutionEvent, ExecutionSession, ExecutionSessionHeader, ExecutionSessionState,
    FailureBudget, GovernancePolicyClass, IsolationProfile, MemoryArtifact, MemoryScope,
    MemoryStore, NativeReplacementTier, NativeSufficiencyGate, OwnershipBoundary, OwnershipMode,
    PointerIndex, PromotionActStatus, PromotionActivationBundle, PromotionReadinessStatus,
    ProviderKind, ReplayableRuntimeState, ReversalAction, ReversalWindowStatus,
    ShadowCampaignStatus, ShadowEvaluationBundle, StopCondition, SynthesisClosureDecision,
    SynthesisHandoff, TaskArtifact, TaskGraph, TaskState, TickSource, WorkerCard, WorkerDispatch,
    WorkerDispatchCheckpointOutcome, WorkerRegistry, WorkerResult, WorkerRole,
    accept_worker_result, activate_promoted_incumbent, bind_session_ready,
    build_native_sufficiency_evidence, checkpointed_dispatch_to_worker, compare_challenger_outputs,
    compare_successor_loop_outputs, complete_task, create_quarantine_record,
    create_rollback_handle, decide_promotion_readiness, evaluate_native_sufficiency_with_evidence,
    evaluate_reversal_window, execute_rollback, mark_epoch_adoption_active,
    mark_epoch_adoption_reversed, mark_promotion_activated, mark_promotion_reversed,
    mark_reversal_window_reversed, open_challenger_evaluation_session, open_promotion_act,
    open_reversal_window, open_shadow_campaign, plan_epoch_adoption, start_turn,
    validate_background_resume_with_runtime_state,
};

fn temp_store_root(name: &str) -> PathBuf {
    env::temp_dir().join(format!("rc04-aiaf-acceptance-{name}-{}", process::id()))
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
    campaign_scope: &str,
    epoch_scope: &str,
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
        campaign_scope: Some(campaign_scope.to_string()),
        epoch_scope: Some(epoch_scope.to_string()),
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

fn completed_runtime_state(
    session_id: &str,
    actor_id: &str,
    campaign_id: &str,
    epoch_id: &str,
    root_task_id: &str,
    summary: &str,
    checkpoint_id: &str,
    shared_input_refs: &[String],
    output_refs: Vec<String>,
) -> ReplayableRuntimeState {
    let mut session = ExecutionSession::new(ExecutionSessionHeader {
        session_id: session_id.to_string(),
        actor_kind: ActorKind::Supervisor,
        actor_id: actor_id.to_string(),
        campaign_id: campaign_id.to_string(),
        epoch_id: epoch_id.to_string(),
        capability_envelope_ref: "envelope-supervisor-root".to_string(),
        parent_session_id: None,
    });
    bind_session_ready(&mut session).unwrap();
    session.state = ExecutionSessionState::Completed;

    let mut root_task = TaskArtifact::new(root_task_id, summary);
    root_task.state = TaskState::Completed;
    root_task.owner_session_id = Some(session.header.session_id.clone());
    root_task.output_refs = output_refs;

    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(PointerIndex {
        index_id: "pointer-index-shadow".to_string(),
        scope: MemoryScope::Campaign(campaign_id.to_string()),
        entry_refs: shared_input_refs.to_vec(),
        contested_refs: Vec::new(),
        critical_refs: shared_input_refs.to_vec(),
        governance_constraints: vec![
            "bounded promotion must preserve rollback".to_string(),
            "same shared inputs must remain explicit".to_string(),
        ],
        open_task_refs: vec![root_task_id.to_string()],
        updated_at: "seed-load".to_string(),
    });

    let checkpoint = aiaf_v1::execution::RunCheckpoint::capture(
        checkpoint_id,
        &session,
        Some(&root_task),
        Vec::new(),
        Vec::new(),
        FailureBudget::default().snapshot(),
        vec!["completed-runtime-state".to_string()],
    );
    session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());
    memory_store.persist_checkpoint_artifact(
        format!("memory-{checkpoint_id}"),
        checkpoint.clone(),
        "checkpoint retained for promotion rollback reconstruction",
    );
    memory_store.append(MemoryArtifact::audit_record(
        format!("memory-audit-{checkpoint_id}"),
        AuditRecord::new(
            format!("audit-{checkpoint_id}"),
            AuditRecordClass::GovernanceAuditRecord,
            campaign_id,
            epoch_id,
            session_id,
            Some(root_task_id.to_string()),
            checkpoint.checkpoint_id.clone(),
            "completed runtime checkpoint retained for governed rollback",
        ),
    ));

    ReplayableRuntimeState::new(
        session.clone(),
        root_task,
        TaskGraph::new(root_task_id, Vec::new()),
        memory_store,
        Some(checkpoint),
        vec![execution_event(
            &format!("event-{session_id}"),
            EventFamily::CheckpointEvent,
            &session,
            Some(root_task_id),
            summary,
        )],
    )
}

#[test]
fn supervisor_promote_activate_successor_campaign_acceptance() {
    let root = temp_store_root("promote-activate-successor");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let shared_input_refs = vec![
        "campaign-brief-1".to_string(),
        "pointer-index-shadow".to_string(),
    ];

    let incumbent_runtime_state = completed_runtime_state(
        "session-incumbent-1",
        "supervisor-incumbent",
        "campaign-shadow",
        "epoch-1",
        "task-root-incumbent",
        "Stable incumbent baseline before promotion",
        "checkpoint-incumbent-stable-1",
        &shared_input_refs,
        vec!["incumbent-output-1".to_string()],
    );
    store
        .persist_runtime_state(&incumbent_runtime_state)
        .unwrap();

    let mut challenger_runtime_state = completed_runtime_state(
        "session-challenger-1",
        "supervisor-challenger",
        "campaign-shadow",
        "epoch-1",
        "task-root-challenger",
        "Native challenger completed bounded shadow evaluation",
        "checkpoint-challenger-ready-1",
        &shared_input_refs,
        vec!["challenger-output-1".to_string()],
    );
    let rollback_handle = create_rollback_handle(
        "rollback-pre-promotion-1",
        "promotion-act",
        "checkpoint-incumbent-stable-1",
        vec!["restore checkpoint-incumbent-stable-1".to_string()],
        Vec::new(),
    );

    let shadow_campaign = open_shadow_campaign(
        "shadow-campaign-1",
        "campaign-shadow",
        incumbent_runtime_state.session.header.session_id.clone(),
        challenger_runtime_state.session.header.session_id.clone(),
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
    let challenger_evaluation_session = open_challenger_evaluation_session(
        "evaluation-session-1",
        &shadow_campaign,
        &shared_input_refs,
        &shared_input_refs,
        vec![
            "envelope-successor-designer".to_string(),
            "envelope-successor-reviewer".to_string(),
        ],
    )
    .unwrap();

    let comparison = compare_challenger_outputs(
        "comparison-shadow-1",
        incumbent_runtime_state.session.header.session_id.clone(),
        challenger_runtime_state.session.header.session_id.clone(),
        shared_input_refs.clone(),
        vec!["incumbent-output-1".to_string()],
        vec!["challenger-output-1".to_string()],
        vec![
            EvaluationDimensionScore {
                dimension: EvaluationDimension::SemanticCorrectness,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "incumbent stayed semantically correct".to_string(),
                challenger_summary: "challenger stayed semantically correct".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::GovernanceFidelity,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "incumbent remained governed".to_string(),
                challenger_summary: "challenger remained governed".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::Replayability,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "incumbent replay remained available".to_string(),
                challenger_summary: "challenger replay remained available".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::OperatorBurden,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "incumbent review burden remained bounded".to_string(),
                challenger_summary: "challenger review burden remained bounded".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::BoundaryCost,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "incumbent boundary cost remained bounded".to_string(),
                challenger_summary: "challenger boundary cost remained bounded".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::ReplacementSafety,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "incumbent could be restored".to_string(),
                challenger_summary: "challenger could be restored".to_string(),
            },
        ],
        "bounded challenger remained promotion-ready under same-input evaluation",
    )
    .unwrap();
    let shadow_evidence = build_native_sufficiency_evidence(
        "evidence-shadow-1",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::NativeSupervisorChallengers,
        vec!["review-artifact-shadow-1".to_string()],
        vec!["checkpoint-challenger-ready-1".to_string()],
        vec!["audit-shadow-comparison-1".to_string()],
        "native challenger evidence bundle",
        true,
    );
    challenger_runtime_state
        .memory_store
        .append(MemoryArtifact::audit_record(
            "memory-audit-shadow-comparison-1",
            AuditRecord::new(
                "audit-shadow-comparison-1",
                AuditRecordClass::GovernanceAuditRecord,
                challenger_runtime_state.session.header.campaign_id.clone(),
                challenger_runtime_state.session.header.epoch_id.clone(),
                challenger_runtime_state.session.header.session_id.clone(),
                Some(challenger_runtime_state.root_task.task_id.clone()),
                comparison.comparison_id.clone(),
                "shadow comparison remained reconstructable",
            ),
        ));
    challenger_runtime_state
        .memory_store
        .append(MemoryArtifact::audit_record(
            "memory-audit-shadow-evidence-1",
            AuditRecord::new(
                "audit-shadow-evidence-1",
                AuditRecordClass::PromotionAuditRecord,
                challenger_runtime_state.session.header.campaign_id.clone(),
                challenger_runtime_state.session.header.epoch_id.clone(),
                challenger_runtime_state.session.header.session_id.clone(),
                Some(challenger_runtime_state.root_task.task_id.clone()),
                shadow_evidence.evidence_id.clone(),
                "shadow sufficiency evidence remained reconstructable",
            ),
        ));
    append_named_related_audit(
        &mut challenger_runtime_state.memory_store,
        &challenger_runtime_state.session,
        Some(&challenger_runtime_state.root_task.task_id),
        "review-artifact-shadow-1",
        "audit-review-artifact-shadow-1",
        AuditRecordClass::GovernanceAuditRecord,
        "shadow review artifact remained reconstructable",
    );
    store
        .persist_runtime_state(&challenger_runtime_state)
        .unwrap();
    let shadow_gate = NativeSufficiencyGate {
        target: CapabilityImportTarget::NativeSupervisorChallenger,
        required_tier: NativeReplacementTier::NativeSupervisorChallengers,
        requires_exact_match: true,
    };
    let promotion_readiness = decide_promotion_readiness(
        "promotion-readiness-1",
        &comparison,
        &shadow_gate,
        &shadow_evidence,
        std::slice::from_ref(&rollback_handle),
        &["review-artifact-shadow-1".to_string()],
        &[],
    );
    assert_eq!(
        promotion_readiness.status,
        PromotionReadinessStatus::Promotable
    );

    let shadow_bundle = ShadowEvaluationBundle {
        shadow_campaign,
        challenger_evaluation_session,
        incumbent_runtime_state: incumbent_runtime_state.clone(),
        challenger_runtime_state: challenger_runtime_state.clone(),
        comparison_record: comparison.clone(),
        sufficiency_evidence: shadow_evidence.clone(),
        promotion_readiness_decision: promotion_readiness.clone(),
    };
    store
        .persist_shadow_evaluation_bundle(&shadow_bundle)
        .unwrap();

    let mut promotion_act = open_promotion_act(
        "promotion-act-1",
        &promotion_readiness,
        &comparison,
        "epoch-1",
        "epoch-2",
        "campaign-successor",
        vec![
            comparison.comparison_id.clone(),
            shadow_bundle.shadow_campaign.shadow_campaign_id.clone(),
        ],
    )
    .unwrap();
    assert_eq!(promotion_act.status, PromotionActStatus::Approved);

    let mut adoption = plan_epoch_adoption(
        "adoption-1",
        &promotion_act,
        incumbent_runtime_state.session.header.session_id.clone(),
        challenger_runtime_state.session.header.session_id.clone(),
        "session-promoted-incumbent-1",
        vec![
            "review-artifact-shadow-1".to_string(),
            comparison.comparison_id.clone(),
        ],
        "bounded epoch adoption planned",
    );
    assert_eq!(adoption.status, EpochAdoptionStatus::Planned);

    let mut reversal_window = open_reversal_window(
        "reversal-window-1",
        &promotion_act,
        std::slice::from_ref(&rollback_handle),
        &[],
        "bounded reversal window opened",
    )
    .unwrap();
    assert_eq!(reversal_window.status, ReversalWindowStatus::Open);

    let mut promoted_memory = challenger_runtime_state.memory_store.clone();
    let successor_root_task_id = "task-root-successor";
    promoted_memory.insert_pointer_index(PointerIndex {
        index_id: "pointer-index-successor".to_string(),
        scope: MemoryScope::Campaign("campaign-successor".to_string()),
        entry_refs: adoption.carried_artifact_refs.clone(),
        contested_refs: Vec::new(),
        critical_refs: adoption.carried_artifact_refs.clone(),
        governance_constraints: vec![
            "promoted incumbent must remain reversible".to_string(),
            "successor shaping remains bounded to one campaign".to_string(),
        ],
        open_task_refs: vec![successor_root_task_id.to_string()],
        updated_at: "promotion-adoption".to_string(),
    });

    let successor_root_task =
        TaskArtifact::new(successor_root_task_id, "Bounded successor-shaping campaign");
    let (mut promoted_session, epoch_handoff_checkpoint) = activate_promoted_incumbent(
        &challenger_runtime_state.session,
        &promotion_act,
        &adoption,
        "envelope-promoted-supervisor",
        Some(&successor_root_task),
        "checkpoint-epoch-handoff-1",
        Vec::new(),
        adoption.carried_artifact_refs.clone(),
        FailureBudget::default().snapshot(),
        vec!["epoch-handoff-once".to_string()],
    )
    .unwrap();
    mark_promotion_activated(&mut promotion_act);
    mark_epoch_adoption_active(
        &mut adoption,
        epoch_handoff_checkpoint.checkpoint_id.clone(),
    );

    let epoch_handoff_artifact_id = promoted_memory.persist_checkpoint_artifact(
        "memory-checkpoint-epoch-handoff-1",
        epoch_handoff_checkpoint.clone(),
        "epoch handoff checkpoint persisted",
    );
    promoted_memory.append(MemoryArtifact::audit_record(
        "memory-audit-checkpoint-epoch-handoff-1",
        AuditRecord::new(
            "audit-checkpoint-epoch-handoff-1",
            AuditRecordClass::GovernanceAuditRecord,
            promoted_session.header.campaign_id.clone(),
            promoted_session.header.epoch_id.clone(),
            promoted_session.header.session_id.clone(),
            Some(successor_root_task_id.to_string()),
            epoch_handoff_checkpoint.checkpoint_id.clone(),
            "epoch handoff checkpoint remained reconstructable",
        ),
    ));
    append_v14_program_evidence(
        &mut promoted_memory,
        &promoted_session,
        Some(successor_root_task_id),
        "successor-campaign",
        &promotion_act.review_artifact_refs,
    );

    let background_campaign = BackgroundCampaign {
        campaign_id: promoted_session.header.campaign_id.clone(),
        objective: "start bounded successor-shaping campaign after promotion".to_string(),
        authority_ceiling: AuthorityClass::PromotionControl,
        allowed_tick_sources: vec![TickSource::EpochTransition],
        max_concurrent_sessions: 1,
        stop_conditions: vec![StopCondition::ExplicitTaskCompletion],
        approval_policy: GovernancePolicyClass::PromotionGovernancePolicy,
        audit_policy: GovernancePolicyClass::PromotionGovernancePolicy,
    };
    let successor_runtime_state = ReplayableRuntimeState::new(
        promoted_session.clone(),
        successor_root_task.clone(),
        TaskGraph::new(successor_root_task_id, Vec::new()),
        promoted_memory.clone(),
        Some(epoch_handoff_checkpoint.clone()),
        Vec::new(),
    );
    validate_background_resume_with_runtime_state(
        &background_campaign,
        &TickSource::EpochTransition,
        &successor_runtime_state,
        &[],
        &[],
        &promoted_session.header.session_id,
    )
    .unwrap();

    let mut root_task = successor_root_task;
    let design_task_id = "task-successor-design".to_string();
    let review_task_id = "task-successor-review".to_string();
    let mut task_graph = TaskGraph::new(
        successor_root_task_id,
        vec![
            AgendaItem::new(
                "agenda-successor-design",
                design_task_id.clone(),
                "successor-design",
                Vec::new(),
                OwnershipBoundary {
                    boundary_id: "boundary-successor-design".to_string(),
                    resource_scope: "successor-control".to_string(),
                    mode: OwnershipMode::ReadOnlyFanOut,
                    owner_actor_ref: promoted_session.header.session_id.clone(),
                },
            ),
            AgendaItem::new(
                "agenda-successor-review",
                review_task_id.clone(),
                "successor-review",
                vec![design_task_id.clone()],
                OwnershipBoundary {
                    boundary_id: "boundary-successor-review".to_string(),
                    resource_scope: "promotion-review".to_string(),
                    mode: OwnershipMode::MergeRequired,
                    owner_actor_ref: promoted_session.header.session_id.clone(),
                },
            ),
        ],
    );

    let designer_worker = worker_card(
        "worker-successor-designer-1",
        WorkerRole::MutatorWorker,
        "successor-design",
        vec![
            CapabilityWorld::WorkerMessaging,
            CapabilityWorld::CampaignControl,
            CapabilityWorld::MemoryAccess,
        ],
        AuthorityClass::CampaignControl,
        "successor-candidate-result",
    );
    let reviewer_worker = worker_card(
        "worker-successor-reviewer-1",
        WorkerRole::ReviewerWorker,
        "successor-review",
        vec![
            CapabilityWorld::WorkerMessaging,
            CapabilityWorld::ReviewPromotion,
            CapabilityWorld::ScheduleTick,
            CapabilityWorld::MemoryAccess,
        ],
        AuthorityClass::PromotionControl,
        "successor-review-result",
    );
    let designer_envelope = capability_envelope(
        "envelope-successor-designer",
        &designer_worker.worker_id,
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
                vec!["plan-successor-trial"],
            ),
            world_grant(
                CapabilityWorld::MemoryAccess,
                AuthorityClass::Observe,
                vec!["read-pointer-index"],
            ),
        ],
        vec!["worker-channel", "successor-control", "pointer-index-store"],
        "campaign-successor",
        "epoch-2",
    );
    let reviewer_envelope = capability_envelope(
        "envelope-successor-reviewer",
        &reviewer_worker.worker_id,
        AuthorityClass::PromotionControl,
        vec![
            world_grant(
                CapabilityWorld::WorkerMessaging,
                AuthorityClass::Observe,
                vec!["dispatch", "result"],
            ),
            world_grant(
                CapabilityWorld::ReviewPromotion,
                AuthorityClass::PromotionControl,
                vec!["draft-successor-candidate"],
            ),
            world_grant(
                CapabilityWorld::ScheduleTick,
                AuthorityClass::AutomationControl,
                vec!["register-reversal-window-monitor"],
            ),
            world_grant(
                CapabilityWorld::MemoryAccess,
                AuthorityClass::Observe,
                vec!["read-transcript-slice", "append-audit-record"],
            ),
        ],
        vec![
            "worker-channel",
            "promotion-review",
            "reversal-window",
            "pointer-index-store",
        ],
        "campaign-successor",
        "epoch-2",
    );

    let mut registry = WorkerRegistry::default();
    registry.register(designer_worker.clone());
    registry.register(reviewer_worker.clone());

    let mut event_log = vec![execution_event(
        "event-epoch-handoff-1",
        EventFamily::SessionLifecycleEvent,
        &promoted_session,
        Some(successor_root_task_id),
        "promoted incumbent activated for bounded successor campaign",
    )];

    let design_route = registry
        .select_worker(
            "successor-design",
            &[
                CapabilityWorld::WorkerMessaging,
                CapabilityWorld::CampaignControl,
                CapabilityWorld::MemoryAccess,
            ],
            &AuthorityClass::CampaignControl,
            &IsolationProfile::ArtifactSandbox,
        )
        .unwrap();
    assert_eq!(design_route.worker_id, designer_worker.worker_id);
    task_graph
        .mark_dispatched("agenda-successor-design", design_route.worker_id.clone())
        .unwrap();

    start_turn(
        &mut promoted_session,
        &mut root_task,
        "turn-successor-design",
    )
    .unwrap();
    let design_dispatch = worker_dispatch(
        &promoted_session,
        successor_root_task_id,
        &designer_worker,
        &designer_envelope.envelope_id,
        "dispatch-successor-design-1",
        "successor-design-task-1",
        "shape one bounded successor candidate artifact",
        vec![
            CapabilityOperationRequest {
                world: CapabilityWorld::WorkerMessaging,
                operation: "dispatch".to_string(),
                resource_scope: "worker-channel".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::CampaignControl,
                operation: "plan-successor-trial".to_string(),
                resource_scope: "successor-control".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::MemoryAccess,
                operation: "read-pointer-index".to_string(),
                resource_scope: "pointer-index-store".to_string(),
            },
        ],
        adoption.carried_artifact_refs.clone(),
    );
    let WorkerDispatchCheckpointOutcome::Dispatched(design_checkpoint) =
        checkpointed_dispatch_to_worker(
            &mut promoted_session,
            &mut root_task,
            &designer_worker,
            &designer_envelope,
            &design_dispatch,
            "checkpoint-successor-design-1",
            Vec::new(),
            vec![epoch_handoff_artifact_id.clone()],
            FailureBudget::default().snapshot(),
            vec!["successor-design-once".to_string()],
        )
        .unwrap()
    else {
        panic!("successor designer dispatch should proceed without extra approval");
    };
    let design_result = worker_result(
        &promoted_session,
        successor_root_task_id,
        &designer_worker,
        &design_dispatch,
        "successor-candidate-1",
        "bounded successor candidate artifact drafted",
    );
    accept_worker_result(&mut promoted_session, &mut root_task, &design_result).unwrap();
    root_task.record_output_ref(design_result.result_ref.clone());
    task_graph
        .apply_synthesis_handoff(
            "agenda-successor-design",
            &SynthesisHandoff {
                handoff_id: "handoff-successor-design-1".to_string(),
                task_id: design_task_id.clone(),
                worker_output_refs: vec![design_result.result_ref.clone()],
                supervisor_summary: "successor candidate drafted under promoted incumbent"
                    .to_string(),
                next_action: "review bounded successor candidate".to_string(),
                closure_decision: SynthesisClosureDecision::Complete,
            },
        )
        .unwrap();
    task_graph.refresh_ready_states(std::slice::from_ref(&design_task_id));
    assert_eq!(
        task_graph
            .agenda_item("agenda-successor-review")
            .unwrap()
            .status,
        AgendaStatus::Ready
    );

    promoted_memory.add_transcript_slice(aiaf_v1::execution::TranscriptSlice {
        slice_id: "slice-successor-design-1".to_string(),
        campaign_id: promoted_session.header.campaign_id.clone(),
        epoch_id: promoted_session.header.epoch_id.clone(),
        session_id: Some(promoted_session.header.session_id.clone()),
        task_id: Some(design_task_id.clone()),
        referenced_artifacts: vec![design_result.result_ref.clone()],
        summary: "successor candidate transcript".to_string(),
        excerpts: vec![
            "promoted incumbent coordinated one bounded successor design step".to_string(),
        ],
    });

    let review_route = registry
        .select_worker(
            "successor-review",
            &[
                CapabilityWorld::WorkerMessaging,
                CapabilityWorld::ReviewPromotion,
                CapabilityWorld::ScheduleTick,
                CapabilityWorld::MemoryAccess,
            ],
            &AuthorityClass::PromotionControl,
            &IsolationProfile::ArtifactSandbox,
        )
        .unwrap();
    assert_eq!(review_route.worker_id, reviewer_worker.worker_id);
    task_graph
        .mark_dispatched("agenda-successor-review", review_route.worker_id.clone())
        .unwrap();

    start_turn(
        &mut promoted_session,
        &mut root_task,
        "turn-successor-review",
    )
    .unwrap();
    let review_dispatch = worker_dispatch(
        &promoted_session,
        successor_root_task_id,
        &reviewer_worker,
        &reviewer_envelope.envelope_id,
        "dispatch-successor-review-1",
        "successor-review-task-1",
        "review the bounded successor candidate and register reversal monitoring",
        vec![
            CapabilityOperationRequest {
                world: CapabilityWorld::WorkerMessaging,
                operation: "dispatch".to_string(),
                resource_scope: "worker-channel".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::ReviewPromotion,
                operation: "draft-successor-candidate".to_string(),
                resource_scope: "promotion-review".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::ScheduleTick,
                operation: "register-reversal-window-monitor".to_string(),
                resource_scope: "reversal-window".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::MemoryAccess,
                operation: "read-transcript-slice".to_string(),
                resource_scope: "pointer-index-store".to_string(),
            },
        ],
        vec![
            design_result.result_ref.clone(),
            "slice-successor-design-1".to_string(),
        ],
    );
    let WorkerDispatchCheckpointOutcome::Dispatched(review_checkpoint) =
        checkpointed_dispatch_to_worker(
            &mut promoted_session,
            &mut root_task,
            &reviewer_worker,
            &reviewer_envelope,
            &review_dispatch,
            "checkpoint-successor-review-1",
            Vec::new(),
            vec![epoch_handoff_artifact_id.clone()],
            FailureBudget::default().snapshot(),
            vec!["successor-review-once".to_string()],
        )
        .unwrap()
    else {
        panic!("successor reviewer dispatch should proceed without extra approval");
    };
    let review_result = worker_result(
        &promoted_session,
        successor_root_task_id,
        &reviewer_worker,
        &review_dispatch,
        "successor-review-1",
        "bounded successor candidate reviewed and contained",
    );
    accept_worker_result(&mut promoted_session, &mut root_task, &review_result).unwrap();
    root_task.record_output_ref(review_result.result_ref.clone());
    task_graph
        .apply_synthesis_handoff(
            "agenda-successor-review",
            &SynthesisHandoff {
                handoff_id: "handoff-successor-review-1".to_string(),
                task_id: review_task_id.clone(),
                worker_output_refs: vec![review_result.result_ref.clone()],
                supervisor_summary: "bounded successor campaign completed".to_string(),
                next_action: "close successor-shaping campaign".to_string(),
                closure_decision: SynthesisClosureDecision::Complete,
            },
        )
        .unwrap();

    start_turn(
        &mut promoted_session,
        &mut root_task,
        "turn-successor-complete",
    )
    .unwrap();
    complete_task(&mut promoted_session, &mut root_task).unwrap();
    assert_eq!(promoted_session.state, ExecutionSessionState::Completed);
    assert_eq!(root_task.state, TaskState::Completed);

    let promotion_audit_artifact_id = promoted_memory.append(MemoryArtifact::audit_record(
        "memory-audit-promotion-1",
        AuditRecord::new(
            "audit-promotion-1",
            AuditRecordClass::PromotionAuditRecord,
            promoted_session.header.campaign_id.clone(),
            promoted_session.header.epoch_id.clone(),
            promoted_session.header.session_id.clone(),
            Some(successor_root_task_id.to_string()),
            promotion_act.promotion_act_id.clone(),
            "bounded promotion and epoch handoff completed",
        ),
    ));
    let adoption_audit_artifact_id = promoted_memory.append(MemoryArtifact::audit_record(
        "memory-audit-adoption-1",
        AuditRecord::new(
            "audit-adoption-1",
            AuditRecordClass::PromotionAuditRecord,
            promoted_session.header.campaign_id.clone(),
            promoted_session.header.epoch_id.clone(),
            promoted_session.header.session_id.clone(),
            Some(successor_root_task_id.to_string()),
            adoption.adoption_id.clone(),
            "epoch adoption remained reconstructable",
        ),
    ));
    let reversal_window_audit_artifact_id = promoted_memory.append(MemoryArtifact::audit_record(
        "memory-audit-reversal-window-1",
        AuditRecord::new(
            "audit-reversal-window-1",
            AuditRecordClass::GovernanceAuditRecord,
            promoted_session.header.campaign_id.clone(),
            promoted_session.header.epoch_id.clone(),
            promoted_session.header.session_id.clone(),
            Some(successor_root_task_id.to_string()),
            reversal_window.reversal_window_id.clone(),
            "reversal window remained reconstructable",
        ),
    ));
    let successor_review_artifact_id = promoted_memory.append(MemoryArtifact::audit_record(
        "memory-audit-successor-review-1",
        AuditRecord::new(
            "audit-successor-review-1",
            AuditRecordClass::GovernanceAuditRecord,
            promoted_session.header.campaign_id.clone(),
            promoted_session.header.epoch_id.clone(),
            promoted_session.header.session_id.clone(),
            Some(successor_root_task_id.to_string()),
            review_result.result_ref.clone(),
            "successor candidate remained bounded and review-complete",
        ),
    ));
    event_log.push(execution_event(
        "event-successor-complete-1",
        EventFamily::GovernanceDecisionEvent,
        &promoted_session,
        Some(successor_root_task_id),
        "promoted incumbent completed one bounded successor-shaping campaign",
    ));

    let successor_loop_comparison = compare_successor_loop_outputs(
        "comparison-loop-1",
        promoted_session.header.session_id.clone(),
        design_result.result_ref.clone(),
        shared_input_refs.clone(),
        vec![
            promotion_act.promotion_act_id.clone(),
            adoption.adoption_id.clone(),
        ],
        vec![
            design_result.result_ref.clone(),
            review_result.result_ref.clone(),
        ],
        vec![
            EvaluationDimensionScore {
                dimension: EvaluationDimension::SemanticCorrectness,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promoted incumbent preserved bounded semantics".to_string(),
                challenger_summary: "successor candidate remained bounded".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::GovernanceFidelity,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promotion stayed governed".to_string(),
                challenger_summary: "successor candidate stayed governed".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::Replayability,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promoted incumbent remained replayable".to_string(),
                challenger_summary: "successor candidate remained replayable".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::OperatorBurden,
                verdict: DimensionVerdict::ChallengerBetter,
                incumbent_summary: "manual successor planning would cost more operator effort"
                    .to_string(),
                challenger_summary: "bounded successor shaping packaged artifacts directly"
                    .to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::BoundaryCost,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "bounded worker boundaries were preserved".to_string(),
                challenger_summary: "bounded worker boundaries were preserved".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::ReplacementSafety,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promotion remained reversible".to_string(),
                challenger_summary: "successor candidate remained non-live".to_string(),
            },
        ],
        "promoted incumbent completed one bounded successor-shaping campaign",
    )
    .unwrap();
    assert_eq!(
        successor_loop_comparison.replacement_tier,
        NativeReplacementTier::BoundedSelfHostingLoop
    );
    assert_eq!(
        successor_loop_comparison.imported_provider,
        ProviderKind::Native
    );
    assert_eq!(
        successor_loop_comparison.native_provider,
        ProviderKind::Native
    );

    let successor_loop_evidence = build_native_sufficiency_evidence(
        "evidence-loop-1",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::BoundedSelfHostingLoop,
        vec![
            design_result.result_ref.clone(),
            review_result.result_ref.clone(),
            promotion_act.promotion_act_id.clone(),
        ],
        vec![
            epoch_handoff_checkpoint.checkpoint_id.clone(),
            design_checkpoint.checkpoint_id.clone(),
            review_checkpoint.checkpoint_id.clone(),
        ],
        vec![
            "audit-promotion-1".to_string(),
            "audit-successor-review-1".to_string(),
        ],
        "bounded self-hosting loop entry evidence",
        true,
    );
    let successor_loop_gate = NativeSufficiencyGate {
        target: CapabilityImportTarget::NativeSupervisorChallenger,
        required_tier: NativeReplacementTier::BoundedSelfHostingLoop,
        requires_exact_match: true,
    };
    assert!(evaluate_native_sufficiency_with_evidence(
        &successor_loop_gate,
        &successor_loop_comparison,
        &successor_loop_evidence
    ));

    let final_checkpoint = aiaf_v1::execution::RunCheckpoint::capture(
        "checkpoint-successor-complete-1",
        &promoted_session,
        Some(&root_task),
        Vec::new(),
        vec![
            epoch_handoff_artifact_id.clone(),
            promotion_audit_artifact_id.clone(),
            successor_review_artifact_id.clone(),
        ],
        FailureBudget::default().snapshot(),
        vec!["successor-campaign-complete".to_string()],
    );
    promoted_session.latest_checkpoint_ref = Some(final_checkpoint.checkpoint_id.clone());
    let final_checkpoint_artifact_id = promoted_memory.persist_checkpoint_artifact(
        "memory-checkpoint-successor-complete-1",
        final_checkpoint.clone(),
        "successor campaign completion checkpoint persisted",
    );
    promoted_memory.append(MemoryArtifact::audit_record(
        "memory-audit-checkpoint-successor-complete-1",
        AuditRecord::new(
            "audit-checkpoint-successor-complete-1",
            AuditRecordClass::GovernanceAuditRecord,
            promoted_session.header.campaign_id.clone(),
            promoted_session.header.epoch_id.clone(),
            promoted_session.header.session_id.clone(),
            Some(successor_root_task_id.to_string()),
            final_checkpoint.checkpoint_id.clone(),
            "successor completion checkpoint remained reconstructable",
        ),
    ));
    root_task.record_output_ref(final_checkpoint_artifact_id.clone());
    promoted_memory.append(MemoryArtifact::audit_record(
        "memory-audit-successor-loop-comparison-1",
        AuditRecord::new(
            "audit-successor-loop-comparison-1",
            AuditRecordClass::GovernanceAuditRecord,
            promoted_session.header.campaign_id.clone(),
            promoted_session.header.epoch_id.clone(),
            promoted_session.header.session_id.clone(),
            Some(successor_root_task_id.to_string()),
            successor_loop_comparison.comparison_id.clone(),
            "successor loop comparison remained reconstructable",
        ),
    ));
    promoted_memory.append(MemoryArtifact::audit_record(
        "memory-audit-successor-loop-evidence-1",
        AuditRecord::new(
            "audit-successor-loop-evidence-1",
            AuditRecordClass::PromotionAuditRecord,
            promoted_session.header.campaign_id.clone(),
            promoted_session.header.epoch_id.clone(),
            promoted_session.header.session_id.clone(),
            Some(successor_root_task_id.to_string()),
            successor_loop_evidence.evidence_id.clone(),
            "successor loop evidence remained reconstructable",
        ),
    ));

    let promoted_runtime_state = ReplayableRuntimeState::new(
        promoted_session.clone(),
        root_task.clone(),
        task_graph.clone(),
        promoted_memory.clone(),
        Some(final_checkpoint.clone()),
        event_log.clone(),
    );
    store
        .persist_runtime_state(&promoted_runtime_state)
        .unwrap();

    let promotion_bundle = PromotionActivationBundle {
        shadow_evaluation_bundle: shadow_bundle.clone(),
        promotion_act: promotion_act.clone(),
        epoch_adoption_record: adoption.clone(),
        reversal_window: reversal_window.clone(),
        promoted_runtime_state: promoted_runtime_state.clone(),
        successor_loop_comparison: successor_loop_comparison.clone(),
        successor_loop_evidence: successor_loop_evidence.clone(),
    };
    store
        .persist_promotion_activation_bundle(&promotion_bundle)
        .unwrap();
    let reloaded_bundle = store
        .load_promotion_activation_bundle(&promotion_act.promotion_act_id)
        .unwrap();
    assert_eq!(reloaded_bundle, promotion_bundle);
    assert!(
        promoted_memory
            .artifacts_for_related_ref(&adoption.adoption_id)
            .iter()
            .any(|artifact| artifact.artifact_id == adoption_audit_artifact_id)
    );
    assert!(
        promoted_memory
            .artifacts_for_related_ref(&reversal_window.reversal_window_id)
            .iter()
            .any(|artifact| artifact.artifact_id == reversal_window_audit_artifact_id)
    );

    let quarantine = create_quarantine_record(
        "quarantine-post-adoption-1",
        aiaf_v1::execution::QuarantineReasonClass::PostApprovalAnomaly,
        vec![promoted_session.header.session_id.clone()],
        Some(rollback_handle.rollback_handle_id.clone()),
    );
    let reversal_action = evaluate_reversal_window(
        &reversal_window,
        std::slice::from_ref(&quarantine),
        &promoted_session.header.session_id,
    )
    .unwrap();
    assert_eq!(reversal_action, ReversalAction::ReverseToCheckpoint);

    let rolled_back = execute_rollback(&rollback_handle, &store).unwrap();
    assert_eq!(
        rolled_back.session.header.session_id,
        incumbent_runtime_state.session.header.session_id
    );
    assert_eq!(
        rolled_back.session.header.epoch_id,
        incumbent_runtime_state.session.header.epoch_id
    );
    assert_eq!(
        rolled_back.root_task.summary,
        incumbent_runtime_state.root_task.summary
    );

    mark_reversal_window_reversed(&mut reversal_window);
    mark_promotion_reversed(&mut promotion_act);
    mark_epoch_adoption_reversed(&mut adoption);
    assert_eq!(reversal_window.status, ReversalWindowStatus::Reversed);
    assert_eq!(promotion_act.status, PromotionActStatus::Reversed);
    assert_eq!(adoption.status, EpochAdoptionStatus::Reversed);
    assert_eq!(
        shadow_bundle.promotion_readiness_decision.status,
        PromotionReadinessStatus::Promotable
    );
    assert_eq!(
        shadow_bundle.shadow_campaign.status,
        ShadowCampaignStatus::Prepared
    );
}
