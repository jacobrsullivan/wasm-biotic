use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use crate::hardening_support::{append_named_related_audit, append_v14_program_evidence};
use aiaf_v1::execution::{
    ActorKind, AgendaItem, AgendaStatus, ApprovalClass, AuditRecord, AuditRecordClass,
    AuthorityClass, CapabilityClosureEntry, CapabilityClosureStatus, CapabilityDependencyMode,
    CapabilityEnvelope, CapabilityImportTarget, CapabilityOperationRequest, CapabilityWorld,
    CapabilityWorldGrant, CycleClosureDecisionStatus, DimensionVerdict, DurableArtifactStore,
    EpochAdoptionStatus, EvaluationDimension, EvaluationDimensionScore, EventFamily,
    ExecutionEvent, ExecutionSession, ExecutionSessionHeader, ExecutionSessionState, FailureBudget,
    GenomeArtifact, GovernancePolicyClass, IsolationProfile, MemoryArtifact, MemoryScope,
    MemoryStore, MemoryUpdateProposal, MemoryUpdateStatus, NativeReplacementTier,
    NativeSufficiencyGate, OwnershipBoundary, OwnershipMode, PhenotypeArtifact, PointerIndex,
    PromotionAct, PromotionActStatus, PromotionActivationBundle, PromotionReadinessStatus,
    ReplayableRuntimeState, ReversalWindowStatus, RunCheckpoint, SemanticValidationRecord,
    ShadowEvaluationBundle, StopCondition, SynthesisClosureDecision, SynthesisHandoff,
    TaskArtifact, TaskGraph, TaskState, TickSource, TopicBundleClass, TranscriptSlice,
    TranscriptSliceQuery, V1CompletionBundle, V1CompletionStatus, WorkerCard, WorkerDispatch,
    WorkerDispatchCheckpointOutcome, WorkerRegistry, WorkerResult, WorkerRole,
    accept_worker_result, bind_session_ready, build_closure_inventory,
    build_native_sufficiency_evidence, build_successor_genome, checkpointed_dispatch_to_worker,
    closure_inventory_has_hidden_imports, compare_challenger_outputs,
    compare_successor_loop_outputs, complete_task, create_rollback_handle, decide_cycle_closure,
    decide_promotion_readiness, evaluate_native_sufficiency_with_evidence,
    evaluate_v1_completion_gate, materialize_successor_phenotype,
    native_transcript_retrieval_from_memory, open_challenger_evaluation_session,
    open_promotion_act, open_reversal_window, open_shadow_campaign, plan_epoch_adoption,
    start_turn, validate_background_resume_with_runtime_state, validate_semantic_phenotype,
};

fn temp_store_root(name: &str) -> PathBuf {
    env::temp_dir().join(format!("rc05-aiaf-acceptance-{name}-{}", process::id()))
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

fn runtime_state(
    session_id: &str,
    actor_id: &str,
    campaign_id: &str,
    epoch_id: &str,
    root_task_id: &str,
    summary: &str,
    checkpoint_id: &str,
    shared_input_refs: &[String],
    output_refs: Vec<String>,
    session_state: ExecutionSessionState,
    task_state: TaskState,
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
    session.state = session_state;

    let mut root_task = TaskArtifact::new(root_task_id, summary);
    root_task.state = task_state;
    root_task.owner_session_id = Some(session.header.session_id.clone());
    root_task.output_refs = output_refs;

    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(PointerIndex {
        index_id: "pointer-index-successor".to_string(),
        scope: MemoryScope::Campaign(campaign_id.to_string()),
        entry_refs: shared_input_refs.to_vec(),
        contested_refs: Vec::new(),
        critical_refs: shared_input_refs.to_vec(),
        governance_constraints: vec![
            "fixed interface must remain stable".to_string(),
            "bounded self-hosting loop must remain replayable".to_string(),
        ],
        open_task_refs: vec![root_task_id.to_string()],
        updated_at: "seed-load".to_string(),
    });
    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: format!("slice-{session_id}"),
        campaign_id: campaign_id.to_string(),
        epoch_id: epoch_id.to_string(),
        session_id: Some(session_id.to_string()),
        task_id: Some(root_task_id.to_string()),
        referenced_artifacts: shared_input_refs.to_vec(),
        summary: summary.to_string(),
        excerpts: vec!["bounded self-hosting baseline".to_string()],
    });

    let checkpoint = RunCheckpoint::capture(
        checkpoint_id,
        &session,
        Some(&root_task),
        Vec::new(),
        vec!["pointer-index-successor".to_string()],
        FailureBudget::default().snapshot(),
        vec!["seed-runtime-state".to_string()],
    );
    memory_store.persist_checkpoint_artifact(
        format!("memory-checkpoint-{checkpoint_id}"),
        checkpoint.clone(),
        format!("checkpoint {checkpoint_id} persisted"),
    );
    memory_store.append(MemoryArtifact::audit_record(
        format!("memory-audit-{checkpoint_id}"),
        AuditRecord::new(
            format!("audit-{checkpoint_id}"),
            AuditRecordClass::GovernanceAuditRecord,
            campaign_id.to_string(),
            epoch_id.to_string(),
            session_id.to_string(),
            Some(root_task_id.to_string()),
            checkpoint.checkpoint_id.clone(),
            "runtime-state checkpoint remained reconstructable",
        ),
    ));
    session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());

    let mut state = ReplayableRuntimeState::new(
        session,
        root_task,
        TaskGraph::new(root_task_id, Vec::new()),
        memory_store,
        Some(checkpoint),
        Vec::new(),
    );
    state.event_log.push(execution_event(
        &format!("event-{session_id}"),
        EventFamily::CheckpointEvent,
        &state.session,
        Some(root_task_id),
        summary,
    ));
    state
}

#[test]
fn supervisor_second_cycle_v1_completion_acceptance() {
    let root = temp_store_root("second-cycle-v1");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let shared_input_refs = vec![
        "campaign-brief-2".to_string(),
        "pointer-index-successor".to_string(),
        "review-artifact-shadow-1".to_string(),
    ];

    let incumbent_runtime_state = runtime_state(
        "session-incumbent-1",
        "supervisor-incumbent",
        "campaign-shadow",
        "epoch-1",
        "task-root-incumbent",
        "Stable incumbent baseline before first promotion",
        "checkpoint-incumbent-stable-1",
        &shared_input_refs,
        vec!["incumbent-output-1".to_string()],
        ExecutionSessionState::Completed,
        TaskState::Completed,
    );
    let mut challenger_runtime_state = runtime_state(
        "session-challenger-1",
        "supervisor-challenger",
        "campaign-shadow",
        "epoch-1",
        "task-root-challenger",
        "Native challenger completed bounded shadow evaluation",
        "checkpoint-challenger-ready-1",
        &shared_input_refs,
        vec!["challenger-output-1".to_string()],
        ExecutionSessionState::Completed,
        TaskState::Completed,
    );
    let mut promoted_runtime_state = runtime_state(
        "session-promoted-incumbent-1",
        "supervisor-promoted",
        "campaign-successor-1",
        "epoch-2",
        "task-root-promoted",
        "Promoted incumbent ready for bounded second cycle",
        "checkpoint-promoted-ready-1",
        &shared_input_refs,
        vec!["promoted-output-1".to_string()],
        ExecutionSessionState::Ready,
        TaskState::Ready,
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
        "rollback-1",
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
    let shadow_comparison = compare_challenger_outputs(
        "comparison-shadow-1",
        incumbent_runtime_state.session.header.session_id.clone(),
        challenger_runtime_state.session.header.session_id.clone(),
        shared_input_refs.clone(),
        incumbent_runtime_state.root_task.output_refs.clone(),
        challenger_runtime_state.root_task.output_refs.clone(),
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
                incumbent_summary: "incumbent stayed governed".to_string(),
                challenger_summary: "challenger stayed governed".to_string(),
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
                incumbent_summary: "incumbent remained reversible".to_string(),
                challenger_summary: "challenger remained reversible".to_string(),
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
        vec!["checkpoint-incumbent-stable-1".to_string()],
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
                shadow_comparison.comparison_id.clone(),
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
    let shadow_gate = NativeSufficiencyGate {
        target: CapabilityImportTarget::NativeSupervisorChallenger,
        required_tier: NativeReplacementTier::NativeSupervisorChallengers,
        requires_exact_match: true,
    };
    let shadow_readiness = decide_promotion_readiness(
        "promotion-readiness-1",
        &shadow_comparison,
        &shadow_gate,
        &shadow_evidence,
        &[create_rollback_handle(
            "rollback-1",
            "shadow-campaign-1",
            "checkpoint-incumbent-stable-1",
            vec!["restore checkpoint-incumbent-stable-1".to_string()],
            Vec::new(),
        )],
        &["review-artifact-shadow-1".to_string()],
        &[],
    );
    assert_eq!(
        shadow_readiness.status,
        PromotionReadinessStatus::Promotable
    );

    let shadow_bundle = ShadowEvaluationBundle {
        shadow_campaign,
        challenger_evaluation_session,
        incumbent_runtime_state: incumbent_runtime_state.clone(),
        challenger_runtime_state: challenger_runtime_state.clone(),
        comparison_record: shadow_comparison.clone(),
        sufficiency_evidence: shadow_evidence.clone(),
        promotion_readiness_decision: shadow_readiness.clone(),
    };

    let promotion_act = open_promotion_act(
        "promotion-act-1",
        &shadow_readiness,
        &shadow_comparison,
        "epoch-1",
        "epoch-2",
        "campaign-successor-1",
        vec!["comparison-shadow-1".to_string()],
    )
    .unwrap();
    let adoption = plan_epoch_adoption(
        "adoption-1",
        &promotion_act,
        "session-incumbent-1",
        "supervisor-promoted",
        "session-promoted-incumbent-1",
        vec!["review-artifact-shadow-1".to_string()],
        "epoch adoption planned",
    );
    assert_eq!(adoption.status, EpochAdoptionStatus::Planned);
    let reversal_window = open_reversal_window(
        "reversal-window-1",
        &promotion_act,
        &[create_rollback_handle(
            "rollback-1",
            "shadow-campaign-1",
            "checkpoint-incumbent-stable-1",
            vec!["restore checkpoint-incumbent-stable-1".to_string()],
            Vec::new(),
        )],
        &[],
        "reversal window open",
    )
    .unwrap();
    assert_eq!(reversal_window.status, ReversalWindowStatus::Open);
    append_named_related_audit(
        &mut promoted_runtime_state.memory_store,
        &promoted_runtime_state.session,
        Some(&promoted_runtime_state.root_task.task_id),
        "review-artifact-shadow-1",
        "audit-review-artifact-shadow-promoted-1",
        AuditRecordClass::GovernanceAuditRecord,
        "shadow review artifact remained reconstructable through epoch handoff",
    );
    append_v14_program_evidence(
        &mut promoted_runtime_state.memory_store,
        &promoted_runtime_state.session,
        Some(&promoted_runtime_state.root_task.task_id),
        "second-cycle",
        &promotion_act.review_artifact_refs,
    );

    let first_loop_comparison = compare_successor_loop_outputs(
        "comparison-loop-1",
        promoted_runtime_state.session.header.session_id.clone(),
        "successor-candidate-1",
        shared_input_refs.clone(),
        promoted_runtime_state.root_task.output_refs.clone(),
        vec!["successor-output-1".to_string()],
        vec![
            EvaluationDimensionScore {
                dimension: EvaluationDimension::SemanticCorrectness,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promoted incumbent remained correct".to_string(),
                challenger_summary: "successor candidate remained correct".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::GovernanceFidelity,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promoted incumbent remained governed".to_string(),
                challenger_summary: "successor candidate remained governed".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::Replayability,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promoted incumbent remained replayable".to_string(),
                challenger_summary: "successor candidate remained replayable".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::OperatorBurden,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "operator review burden remained bounded".to_string(),
                challenger_summary: "operator review burden remained bounded".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::BoundaryCost,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "worker boundary cost remained bounded".to_string(),
                challenger_summary: "worker boundary cost remained bounded".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::ReplacementSafety,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promotion remained reversible".to_string(),
                challenger_summary: "successor remained bounded".to_string(),
            },
        ],
        "first bounded self-hosting loop entry comparison",
    )
    .unwrap();
    let first_loop_evidence = build_native_sufficiency_evidence(
        "evidence-loop-1",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::BoundedSelfHostingLoop,
        vec!["successor-output-1".to_string()],
        vec!["checkpoint-promoted-ready-1".to_string()],
        vec!["audit-loop-1".to_string()],
        "bounded self-hosting loop evidence",
        true,
    );
    append_named_related_audit(
        &mut promoted_runtime_state.memory_store,
        &promoted_runtime_state.session,
        Some(&promoted_runtime_state.root_task.task_id),
        &first_loop_evidence.evidence_id,
        "audit-loop-1",
        AuditRecordClass::PromotionAuditRecord,
        "first loop audit evidence remained reconstructable",
    );
    for (related_ref, class, summary) in [
        (
            promotion_act.promotion_act_id.clone(),
            AuditRecordClass::PromotionAuditRecord,
            "promotion act remained reconstructable",
        ),
        (
            adoption.adoption_id.clone(),
            AuditRecordClass::PromotionAuditRecord,
            "epoch adoption remained reconstructable",
        ),
        (
            reversal_window.reversal_window_id.clone(),
            AuditRecordClass::GovernanceAuditRecord,
            "reversal window remained reconstructable",
        ),
        (
            "comparison-loop-1".to_string(),
            AuditRecordClass::GovernanceAuditRecord,
            "first loop comparison remained reconstructable",
        ),
        (
            first_loop_evidence.evidence_id.clone(),
            AuditRecordClass::PromotionAuditRecord,
            "first loop evidence remained reconstructable",
        ),
    ] {
        promoted_runtime_state
            .memory_store
            .append(MemoryArtifact::audit_record(
                format!("memory-audit-{}", related_ref.replace(':', "-")),
                AuditRecord::new(
                    format!("audit-{}", related_ref.replace(':', "-")),
                    class,
                    promoted_runtime_state.session.header.campaign_id.clone(),
                    promoted_runtime_state.session.header.epoch_id.clone(),
                    promoted_runtime_state.session.header.session_id.clone(),
                    Some(promoted_runtime_state.root_task.task_id.clone()),
                    related_ref,
                    summary,
                ),
            ));
    }
    for audit_ref in [
        "audit-campaign-control",
        "audit-approval-gateway",
        "audit-review-promotion",
        "audit-schedule-tick",
        "audit-memory-access",
        "audit-semantic-validation",
        "audit-artifact-packaging",
        "audit-model-hosting",
        "audit-environment-bridge",
        "audit-worktree-host-adapter",
        "audit-native-supervisor-challenger",
    ] {
        append_named_related_audit(
            &mut promoted_runtime_state.memory_store,
            &promoted_runtime_state.session,
            Some(&promoted_runtime_state.root_task.task_id),
            audit_ref,
            audit_ref,
            AuditRecordClass::GovernanceAuditRecord,
            "service inventory audit remained reconstructable",
        );
    }

    let mut live_session = promoted_runtime_state.session.clone();
    let mut root_task = TaskArtifact::new(
        "task-root-v1-completion",
        "Second bounded cycle for v1 completion",
    );
    let design_task_id = "task-successor-design-2".to_string();
    let review_task_id = "task-semantic-validation-2".to_string();
    let mut task_graph = TaskGraph::new(
        "task-root-v1-completion",
        vec![
            AgendaItem::new(
                "agenda-successor-design-2",
                design_task_id.clone(),
                "successor-design",
                Vec::new(),
                OwnershipBoundary {
                    boundary_id: "boundary-successor-design-2".to_string(),
                    resource_scope: "successor-control".to_string(),
                    mode: OwnershipMode::ExclusiveMutable,
                    owner_actor_ref: live_session.header.actor_id.clone(),
                },
            ),
            AgendaItem::new(
                "agenda-semantic-validation-2",
                review_task_id.clone(),
                "semantic-validation",
                vec![design_task_id.clone()],
                OwnershipBoundary {
                    boundary_id: "boundary-semantic-validation-2".to_string(),
                    resource_scope: "successor-review".to_string(),
                    mode: OwnershipMode::MergeRequired,
                    owner_actor_ref: live_session.header.actor_id.clone(),
                },
            ),
        ],
    );
    let mut memory_store = promoted_runtime_state.memory_store.clone();
    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: "slice-second-cycle".to_string(),
        campaign_id: live_session.header.campaign_id.clone(),
        epoch_id: live_session.header.epoch_id.clone(),
        session_id: Some(live_session.header.session_id.clone()),
        task_id: Some(root_task.task_id.clone()),
        referenced_artifacts: shared_input_refs.clone(),
        summary: "second-cycle kickoff context".to_string(),
        excerpts: vec!["promoted incumbent is beginning bounded v1 closure cycle".to_string()],
    });
    let retrieved_slices = native_transcript_retrieval_from_memory(
        &memory_store,
        &TranscriptSliceQuery {
            campaign_id: Some(live_session.header.campaign_id.clone()),
            ..TranscriptSliceQuery::default()
        },
    );
    assert!(
        !retrieved_slices.is_empty(),
        "skeptical memory should return second-cycle context"
    );

    let design_worker = worker_card(
        "worker-successor-designer-2",
        WorkerRole::MutatorWorker,
        "successor-design",
        vec![CapabilityWorld::MemoryAccess],
        AuthorityClass::Observe,
        "successor-genome-result",
    );
    let review_worker = worker_card(
        "worker-successor-reviewer-2",
        WorkerRole::ReviewerWorker,
        "semantic-validation",
        vec![
            CapabilityWorld::MemoryAccess,
            CapabilityWorld::ReviewPromotion,
        ],
        AuthorityClass::PromotionControl,
        "semantic-validation-result",
    );
    let mut worker_registry = WorkerRegistry::default();
    worker_registry.register(design_worker.clone());
    worker_registry.register(review_worker.clone());

    let design_envelope = capability_envelope(
        "envelope-successor-designer-2",
        &design_worker.worker_id,
        AuthorityClass::Observe,
        vec![
            world_grant(
                CapabilityWorld::WorkerMessaging,
                AuthorityClass::Observe,
                vec!["dispatch", "result"],
            ),
            world_grant(
                CapabilityWorld::MemoryAccess,
                AuthorityClass::Observe,
                vec!["search-bundle", "record-genome"],
            ),
        ],
        vec!["successor-memory"],
        &live_session.header.campaign_id,
        &live_session.header.epoch_id,
    );
    let review_envelope = capability_envelope(
        "envelope-successor-reviewer-2",
        &review_worker.worker_id,
        AuthorityClass::PromotionControl,
        vec![
            world_grant(
                CapabilityWorld::WorkerMessaging,
                AuthorityClass::Observe,
                vec!["dispatch", "result"],
            ),
            world_grant(
                CapabilityWorld::MemoryAccess,
                AuthorityClass::Observe,
                vec!["search-bundle", "record-validation"],
            ),
            world_grant(
                CapabilityWorld::ReviewPromotion,
                AuthorityClass::PromotionControl,
                vec!["record-review", "record-decision"],
            ),
        ],
        vec!["successor-memory", "successor-review"],
        &live_session.header.campaign_id,
        &live_session.header.epoch_id,
    );

    let background_campaign = aiaf_v1::execution::BackgroundCampaign {
        campaign_id: live_session.header.campaign_id.clone(),
        objective: "bounded second cycle for v1 completion".to_string(),
        authority_ceiling: AuthorityClass::PromotionControl,
        allowed_tick_sources: vec![TickSource::EpochTransition],
        max_concurrent_sessions: 1,
        stop_conditions: vec![StopCondition::ExplicitTaskCompletion],
        approval_policy: GovernancePolicyClass::PromotionGovernancePolicy,
        audit_policy: GovernancePolicyClass::PromotionGovernancePolicy,
    };
    let second_cycle_runtime_state = promoted_runtime_state.clone();
    validate_background_resume_with_runtime_state(
        &background_campaign,
        &TickSource::EpochTransition,
        &second_cycle_runtime_state,
        &[],
        &[],
        &live_session.header.session_id,
    )
    .unwrap();

    start_turn(
        &mut live_session,
        &mut root_task,
        "turn-second-cycle-design",
    )
    .unwrap();
    let design_routing = worker_registry
        .select_worker(
            "successor-design",
            &[CapabilityWorld::MemoryAccess],
            &AuthorityClass::Observe,
            &IsolationProfile::ArtifactSandbox,
        )
        .unwrap();
    task_graph
        .mark_dispatched(
            "agenda-successor-design-2",
            design_routing.worker_id.clone(),
        )
        .unwrap();
    assert_eq!(
        task_graph
            .agenda_item("agenda-successor-design-2")
            .unwrap()
            .status,
        AgendaStatus::Dispatched
    );
    let design_dispatch = worker_dispatch(
        &live_session,
        &root_task.task_id,
        &design_worker,
        &design_envelope.envelope_id,
        "dispatch-successor-design-2",
        "worker-task-successor-design-2",
        "design successor genome for second bounded cycle",
        vec![CapabilityOperationRequest {
            world: CapabilityWorld::MemoryAccess,
            operation: "record-genome".to_string(),
            resource_scope: "successor-memory".to_string(),
        }],
        shared_input_refs.clone(),
    );
    let WorkerDispatchCheckpointOutcome::Dispatched(design_checkpoint) =
        checkpointed_dispatch_to_worker(
            &mut live_session,
            &mut root_task,
            &design_worker,
            &design_envelope,
            &design_dispatch,
            "checkpoint-second-cycle-design-1",
            Vec::new(),
            vec!["pointer-index-successor".to_string()],
            FailureBudget::default().snapshot(),
            vec!["design-dispatch-once".to_string()],
        )
        .unwrap()
    else {
        panic!("design dispatch should not require extra approval");
    };
    let design_result = worker_result(
        &live_session,
        &root_task.task_id,
        &design_worker,
        &design_dispatch,
        "result-successor-design-2",
        "successor genome candidate prepared",
    );
    accept_worker_result(&mut live_session, &mut root_task, &design_result).unwrap();

    let successor_genome: GenomeArtifact = build_successor_genome(
        "genome-successor-2",
        live_session.header.actor_id.clone(),
        "package:aiaf/supervisor@v1",
        "typed-dag:successor-2",
        vec![
            "policy:bounded".to_string(),
            "policy:stable-interface".to_string(),
        ],
        "second-cycle successor genome",
    )
    .unwrap();
    task_graph
        .apply_synthesis_handoff(
            "agenda-successor-design-2",
            &SynthesisHandoff {
                handoff_id: "handoff-successor-design-2".to_string(),
                task_id: design_task_id.clone(),
                worker_output_refs: vec![successor_genome.genome_id.clone()],
                supervisor_summary: "successor genome accepted for semantic validation".to_string(),
                next_action: "dispatch semantic validation".to_string(),
                closure_decision: SynthesisClosureDecision::Complete,
            },
        )
        .unwrap();
    task_graph.refresh_ready_states(std::slice::from_ref(&design_task_id));
    root_task.record_output_ref(successor_genome.genome_id.clone());

    start_turn(
        &mut live_session,
        &mut root_task,
        "turn-second-cycle-review",
    )
    .unwrap();
    let review_routing = worker_registry
        .select_worker(
            "semantic-validation",
            &[
                CapabilityWorld::MemoryAccess,
                CapabilityWorld::ReviewPromotion,
            ],
            &AuthorityClass::PromotionControl,
            &IsolationProfile::ArtifactSandbox,
        )
        .unwrap();
    task_graph
        .mark_dispatched(
            "agenda-semantic-validation-2",
            review_routing.worker_id.clone(),
        )
        .unwrap();
    let review_dispatch = worker_dispatch(
        &live_session,
        &root_task.task_id,
        &review_worker,
        &review_envelope.envelope_id,
        "dispatch-semantic-validation-2",
        "worker-task-semantic-validation-2",
        "validate successor phenotype for second bounded cycle",
        vec![
            CapabilityOperationRequest {
                world: CapabilityWorld::MemoryAccess,
                operation: "record-validation".to_string(),
                resource_scope: "successor-memory".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::ReviewPromotion,
                operation: "record-review".to_string(),
                resource_scope: "successor-review".to_string(),
            },
        ],
        vec![successor_genome.genome_id.clone()],
    );
    let WorkerDispatchCheckpointOutcome::Dispatched(review_checkpoint) =
        checkpointed_dispatch_to_worker(
            &mut live_session,
            &mut root_task,
            &review_worker,
            &review_envelope,
            &review_dispatch,
            "checkpoint-second-cycle-review-1",
            Vec::new(),
            vec!["pointer-index-successor".to_string()],
            FailureBudget::default().snapshot(),
            vec!["review-dispatch-once".to_string()],
        )
        .unwrap()
    else {
        panic!("review dispatch should not require extra approval");
    };
    let review_result = worker_result(
        &live_session,
        &root_task.task_id,
        &review_worker,
        &review_dispatch,
        "result-semantic-validation-2",
        "semantic validation artifacts prepared",
    );
    accept_worker_result(&mut live_session, &mut root_task, &review_result).unwrap();

    let successor_phenotype: PhenotypeArtifact = materialize_successor_phenotype(
        "artifact-successor-2",
        &successor_genome,
        "package:aiaf/supervisor@v1",
        "component:successor-2",
        vec!["wit:supervisor".to_string()],
        vec!["successor-output-2".to_string()],
        "second-cycle successor phenotype",
    )
    .unwrap();
    let semantic_validation_record: SemanticValidationRecord = validate_semantic_phenotype(
        "validation-successor-2",
        &successor_genome,
        &successor_phenotype,
        vec!["validator:semantic-check".to_string()],
        vec![
            design_result.result_ref.clone(),
            review_result.result_ref.clone(),
            successor_phenotype.artifact_id.clone(),
        ],
        "second-cycle semantic validation passed",
    )
    .unwrap();
    let review_artifact_ref = "review-artifact-2".to_string();
    let memory_update = MemoryUpdateProposal {
        proposal_id: "memory-update-second-cycle-1".to_string(),
        pointer_index_ref: Some("pointer-index-successor".to_string()),
        bundle_class: TopicBundleClass::ArchitectureDecision,
        scope: MemoryScope::Campaign(live_session.header.campaign_id.clone()),
        proposed_summary: "second-cycle successor validation accepted".to_string(),
        evidence_refs: vec![
            semantic_validation_record.validation_id.clone(),
            review_artifact_ref.clone(),
        ],
        verification_refs: vec![review_artifact_ref.clone()],
        status: MemoryUpdateStatus::Proposed,
    };
    memory_store.propose_memory_update(memory_update);
    let closure_topic_bundle_id = memory_store
        .accept_memory_update(
            "memory-update-second-cycle-1",
            "topic-bundle-second-cycle-1",
            "verified",
        )
        .unwrap();
    task_graph
        .apply_synthesis_handoff(
            "agenda-semantic-validation-2",
            &SynthesisHandoff {
                handoff_id: "handoff-semantic-validation-2".to_string(),
                task_id: review_task_id.clone(),
                worker_output_refs: vec![
                    successor_phenotype.artifact_id.clone(),
                    semantic_validation_record.validation_id.clone(),
                    review_artifact_ref.clone(),
                    closure_topic_bundle_id.clone(),
                ],
                supervisor_summary: "successor phenotype passed semantic validation".to_string(),
                next_action: "prepare second-cycle governance decision".to_string(),
                closure_decision: SynthesisClosureDecision::Complete,
            },
        )
        .unwrap();
    root_task.record_output_ref(successor_phenotype.artifact_id.clone());
    root_task.record_output_ref(semantic_validation_record.validation_id.clone());
    root_task.record_output_ref(closure_topic_bundle_id.clone());

    let second_cycle_comparison = compare_successor_loop_outputs(
        "comparison-cycle-2",
        live_session.header.session_id.clone(),
        successor_phenotype.artifact_id.clone(),
        shared_input_refs.clone(),
        promoted_runtime_state.root_task.output_refs.clone(),
        successor_phenotype.output_refs.clone(),
        vec![
            EvaluationDimensionScore {
                dimension: EvaluationDimension::SemanticCorrectness,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promoted incumbent remained correct".to_string(),
                challenger_summary: "successor phenotype remained correct".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::GovernanceFidelity,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promoted incumbent remained governed".to_string(),
                challenger_summary: "successor phenotype remained governed".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::Replayability,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promoted incumbent remained replayable".to_string(),
                challenger_summary: "successor phenotype remained replayable".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::OperatorBurden,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "operator review burden remained bounded".to_string(),
                challenger_summary: "operator review burden remained bounded".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::BoundaryCost,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "worker boundary cost remained bounded".to_string(),
                challenger_summary: "worker boundary cost remained bounded".to_string(),
            },
            EvaluationDimensionScore {
                dimension: EvaluationDimension::ReplacementSafety,
                verdict: DimensionVerdict::Equivalent,
                incumbent_summary: "promoted incumbent remained reversible".to_string(),
                challenger_summary: "successor phenotype remained reversible".to_string(),
            },
        ],
        "second bounded cycle comparison",
    )
    .unwrap();
    let second_cycle_evidence = build_native_sufficiency_evidence(
        "evidence-cycle-2",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::BoundedSelfHostingLoop,
        vec![
            successor_genome.genome_id.clone(),
            successor_phenotype.artifact_id.clone(),
            semantic_validation_record.validation_id.clone(),
            closure_topic_bundle_id.clone(),
        ],
        vec![
            design_checkpoint.checkpoint_id.clone(),
            review_checkpoint.checkpoint_id.clone(),
        ],
        vec!["audit-cycle-2".to_string()],
        "second-cycle bounded evidence bundle",
        true,
    );
    append_named_related_audit(
        &mut promoted_runtime_state.memory_store,
        &promoted_runtime_state.session,
        Some(&promoted_runtime_state.root_task.task_id),
        &second_cycle_evidence.evidence_id,
        "audit-cycle-2",
        AuditRecordClass::PromotionAuditRecord,
        "second-cycle audit evidence remained reconstructable",
    );
    append_named_related_audit(
        &mut promoted_runtime_state.memory_store,
        &promoted_runtime_state.session,
        Some(&promoted_runtime_state.root_task.task_id),
        &review_artifact_ref,
        "audit-review-artifact-2",
        AuditRecordClass::GovernanceAuditRecord,
        "second-cycle review artifact remained reconstructable",
    );
    append_named_related_audit(
        &mut promoted_runtime_state.memory_store,
        &promoted_runtime_state.session,
        Some(&promoted_runtime_state.root_task.task_id),
        &closure_topic_bundle_id,
        "audit-topic-bundle-second-cycle-1",
        AuditRecordClass::GovernanceAuditRecord,
        "second-cycle topic bundle remained reconstructable",
    );
    let second_cycle_gate = NativeSufficiencyGate {
        target: CapabilityImportTarget::NativeSupervisorChallenger,
        required_tier: NativeReplacementTier::BoundedSelfHostingLoop,
        requires_exact_match: true,
    };
    assert!(evaluate_native_sufficiency_with_evidence(
        &second_cycle_gate,
        &second_cycle_comparison,
        &second_cycle_evidence
    ));

    let second_cycle_rollback = create_rollback_handle(
        "rollback-second-cycle-1",
        "epoch-2",
        promoted_runtime_state
            .latest_checkpoint
            .as_ref()
            .unwrap()
            .checkpoint_id
            .clone(),
        vec!["restore checkpoint-promoted-ready-1".to_string()],
        Vec::new(),
    );
    let second_cycle_readiness = decide_promotion_readiness(
        "promotion-readiness-2",
        &second_cycle_comparison,
        &second_cycle_gate,
        &second_cycle_evidence,
        std::slice::from_ref(&second_cycle_rollback),
        &[review_artifact_ref.clone(), closure_topic_bundle_id.clone()],
        &[],
    );
    assert_eq!(
        second_cycle_readiness.status,
        PromotionReadinessStatus::Promotable
    );
    let second_cycle_decision = decide_cycle_closure(
        "cycle-closure-2",
        &second_cycle_readiness,
        &second_cycle_comparison,
        std::slice::from_ref(&second_cycle_rollback),
        &[],
    );
    assert_eq!(
        second_cycle_decision.status,
        CycleClosureDecisionStatus::Promote
    );

    let second_cycle_promotion_act: PromotionAct = open_promotion_act(
        "promotion-act-2",
        &second_cycle_readiness,
        &second_cycle_comparison,
        "epoch-2",
        "epoch-3",
        "campaign-successor-2",
        vec![
            second_cycle_comparison.comparison_id.clone(),
            successor_genome.genome_id.clone(),
            successor_phenotype.artifact_id.clone(),
            semantic_validation_record.validation_id.clone(),
            closure_topic_bundle_id.clone(),
        ],
    )
    .unwrap();
    assert_eq!(
        second_cycle_promotion_act.status,
        PromotionActStatus::Approved
    );

    let closure_inventory = build_closure_inventory(
        "closure-1",
        vec![
            CapabilityClosureEntry {
                target: CapabilityImportTarget::CampaignControl,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:campaign-control".to_string()),
                audit_ref: Some("audit-campaign-control".to_string()),
                rationale: "campaign control is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ApprovalGateway,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:approval-gateway".to_string()),
                audit_ref: Some("audit-approval-gateway".to_string()),
                rationale: "approval gateway is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ReviewPromotion,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:review-promotion".to_string()),
                audit_ref: Some("audit-review-promotion".to_string()),
                rationale: "review and promotion flow is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ScheduleTick,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:schedule-tick".to_string()),
                audit_ref: Some("audit-schedule-tick".to_string()),
                rationale: "schedule tick handling is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::TranscriptRetrieval,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:memory-access".to_string()),
                audit_ref: Some("audit-memory-access".to_string()),
                rationale: "skeptical memory retrieval is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::SemanticValidation,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:semantic-validation".to_string()),
                audit_ref: Some("audit-semantic-validation".to_string()),
                rationale: "semantic validation is native and replayable".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ArtifactPackaging,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:artifact-packaging".to_string()),
                audit_ref: Some("audit-artifact-packaging".to_string()),
                rationale: "artifact packaging remains inside the bounded substrate".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ModelHosting,
                current_mode: CapabilityDependencyMode::ImportedBaseline,
                closure_status: CapabilityClosureStatus::CarriedImportApproved,
                capability_world_ref: Some("world:model-hosting-adapter".to_string()),
                audit_ref: Some("audit-model-hosting".to_string()),
                rationale: "model hosting remains an explicit carried import in v1".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::EnvironmentBridge,
                current_mode: CapabilityDependencyMode::ImportedBaseline,
                closure_status: CapabilityClosureStatus::CarriedImportApproved,
                capability_world_ref: Some("world:environment-bridge".to_string()),
                audit_ref: Some("audit-environment-bridge".to_string()),
                rationale: "environment bridge remains an explicit carried import in v1"
                    .to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::WorktreeHostAdapter,
                current_mode: CapabilityDependencyMode::ImportedBaseline,
                closure_status: CapabilityClosureStatus::CarriedImportApproved,
                capability_world_ref: Some("world:worktree-host-adapter".to_string()),
                audit_ref: Some("audit-worktree-host-adapter".to_string()),
                rationale: "worktree host adapter remains an explicit carried import in v1"
                    .to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::NativeSupervisorChallenger,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:native-supervisor-challenger".to_string()),
                audit_ref: Some("audit-native-supervisor-challenger".to_string()),
                rationale: "native supervisor challenger evaluation is closed in the bounded loop"
                    .to_string(),
            },
        ],
        Vec::new(),
        "bounded v1 closure inventory",
    );
    assert!(!closure_inventory_has_hidden_imports(&closure_inventory));
    let v1_completion_gate = evaluate_v1_completion_gate(
        "v1-gate-1",
        &closure_inventory,
        &semantic_validation_record,
        &second_cycle_decision,
    );
    assert_eq!(v1_completion_gate.status, V1CompletionStatus::Satisfied);

    start_turn(
        &mut live_session,
        &mut root_task,
        "turn-second-cycle-complete",
    )
    .unwrap();
    complete_task(&mut live_session, &mut root_task).unwrap();
    assert_eq!(live_session.state, ExecutionSessionState::Completed);
    assert_eq!(root_task.state, TaskState::Completed);

    let final_runtime_state = ReplayableRuntimeState::new(
        live_session.clone(),
        root_task.clone(),
        task_graph.clone(),
        memory_store.clone(),
        Some(review_checkpoint.clone()),
        vec![
            execution_event(
                "event-second-cycle-design",
                EventFamily::WorkerDispatchEvent,
                &live_session,
                Some(&root_task.task_id),
                "successor design dispatched",
            ),
            execution_event(
                "event-second-cycle-review",
                EventFamily::MemoryInteractionEvent,
                &live_session,
                Some(&root_task.task_id),
                "semantic validation completed",
            ),
        ],
    );
    store.persist_runtime_state(&final_runtime_state).unwrap();

    let prior_promotion_bundle = PromotionActivationBundle {
        shadow_evaluation_bundle: shadow_bundle,
        promotion_act,
        epoch_adoption_record: adoption,
        reversal_window,
        promoted_runtime_state: promoted_runtime_state.clone(),
        successor_loop_comparison: first_loop_comparison,
        successor_loop_evidence: first_loop_evidence,
    };
    store
        .persist_promotion_activation_bundle(&prior_promotion_bundle)
        .unwrap();

    let v1_completion_bundle = V1CompletionBundle {
        promotion_activation_bundle: prior_promotion_bundle,
        closure_inventory,
        successor_genome: successor_genome.clone(),
        successor_phenotype: successor_phenotype.clone(),
        semantic_validation_record: semantic_validation_record.clone(),
        second_cycle_comparison: second_cycle_comparison.clone(),
        second_cycle_evidence: second_cycle_evidence.clone(),
        second_cycle_readiness: second_cycle_readiness.clone(),
        second_cycle_decision: second_cycle_decision.clone(),
        second_cycle_promotion_act: Some(second_cycle_promotion_act.clone()),
        v1_completion_gate: v1_completion_gate.clone(),
    };
    store
        .persist_v1_completion_bundle(&v1_completion_bundle)
        .unwrap();
    let reloaded = store
        .load_v1_completion_bundle(&v1_completion_bundle.v1_completion_gate.gate_id)
        .unwrap();

    assert_eq!(reloaded, v1_completion_bundle);
    assert_eq!(
        reloaded.second_cycle_promotion_act.as_ref().unwrap().status,
        PromotionActStatus::Approved
    );
    assert_eq!(
        reloaded.v1_completion_gate.carried_import_refs,
        vec![
            "ModelHosting".to_string(),
            "EnvironmentBridge".to_string(),
            "WorktreeHostAdapter".to_string(),
        ]
    );
    assert!(
        memory_store
            .pointer_indexes
            .iter()
            .find(|pointer_index| pointer_index.index_id == "pointer-index-successor")
            .unwrap()
            .entry_refs
            .iter()
            .any(|entry| entry == &closure_topic_bundle_id)
    );
}
