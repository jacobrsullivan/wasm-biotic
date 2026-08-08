use std::fs;

use aiaf_v1::execution::{
    AuthorityClass, BackgroundCampaign, CapabilityImportTarget, DurableArtifactStore,
    FailureBudget, GovernancePolicyClass, NativeReplacementTier, NativeSufficiencyGate,
    PromotionReadinessStatus, ReplayableRuntimeState, RunCheckpoint, StopCondition, TaskArtifact,
    TaskGraph, TickSource, activate_promoted_incumbent, build_native_sufficiency_evidence,
    compare_challenger_outputs, create_rollback_handle, decide_promotion_readiness,
    open_promotion_act, plan_epoch_adoption, validate_background_resume_with_runtime_state,
};

use crate::hardening_support::{
    append_named_related_audit, completed_runtime_state, persist_checkpoint_lineage,
    supervisor_dimension_scores, temp_store_root,
};

#[test]
fn supervisor_service_backed_multi_epoch_background_continuity_acceptance() {
    let root = temp_store_root("service-backed-multi-epoch-background-continuity");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let shared_input_refs = vec![
        "service:scheduler".to_string(),
        "service:queue".to_string(),
        "service:memory".to_string(),
    ];
    let incumbent_state = completed_runtime_state(
        "session-background-incumbent",
        "campaign-background",
        "epoch-1",
        "task-background-incumbent",
        "checkpoint-background-incumbent",
        vec!["incumbent-output-background".to_string()],
        "incumbent background checkpoint captured",
    );
    let mut challenger_state = completed_runtime_state(
        "session-background-challenger",
        "campaign-background",
        "epoch-1",
        "task-background-challenger",
        "checkpoint-background-challenger",
        vec!["challenger-output-background".to_string()],
        "challenger background checkpoint captured",
    );
    let comparison = compare_challenger_outputs(
        "comparison-background-1",
        incumbent_state.session.header.session_id.clone(),
        challenger_state.session.header.session_id.clone(),
        shared_input_refs.clone(),
        incumbent_state.root_task.output_refs.clone(),
        challenger_state.root_task.output_refs.clone(),
        supervisor_dimension_scores("incumbent background", "challenger background"),
        "multi-epoch background continuity remained promotable",
    )
    .unwrap();
    append_named_related_audit(
        &mut challenger_state.memory_store,
        &challenger_state.session,
        Some(&challenger_state.root_task.task_id),
        &comparison.comparison_id,
        "audit-background-comparison-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "background comparison remained reconstructable",
    );
    append_named_related_audit(
        &mut challenger_state.memory_store,
        &challenger_state.session,
        Some(&challenger_state.root_task.task_id),
        "review-artifact-background-1",
        "audit-review-artifact-background-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "background review artifact remained reconstructable",
    );
    let evidence = build_native_sufficiency_evidence(
        "evidence-background-1",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::NativeSupervisorChallengers,
        vec!["review-artifact-background-1".to_string()],
        vec!["checkpoint-background-challenger".to_string()],
        vec!["audit-background-comparison-1".to_string()],
        "background continuity evidence remained explicit",
        true,
    );
    let rollback_handle = create_rollback_handle(
        "rollback-background-1",
        "campaign-background",
        "checkpoint-background-incumbent",
        vec!["restore checkpoint-background-incumbent".to_string()],
        Vec::new(),
    );
    let readiness = decide_promotion_readiness(
        "promotion-readiness-background-1",
        &comparison,
        &NativeSufficiencyGate {
            target: CapabilityImportTarget::NativeSupervisorChallenger,
            required_tier: NativeReplacementTier::NativeSupervisorChallengers,
            requires_exact_match: true,
        },
        &evidence,
        std::slice::from_ref(&rollback_handle),
        &["review-artifact-background-1".to_string()],
        &[],
    );
    assert_eq!(readiness.status, PromotionReadinessStatus::Promotable);

    let promotion_act = open_promotion_act(
        "promotion-act-background-1",
        &readiness,
        &comparison,
        "epoch-1",
        "epoch-2",
        "campaign-background-successor",
        vec![comparison.comparison_id.clone()],
    )
    .unwrap();
    let adoption = plan_epoch_adoption(
        "adoption-background-1",
        &promotion_act,
        incumbent_state.session.header.session_id.clone(),
        challenger_state.session.header.session_id.clone(),
        "session-background-successor",
        vec!["review-artifact-background-1".to_string()],
        "background epoch handoff planned",
    );
    let successor_root_task_id = "task-background-successor";
    let successor_root_task = TaskArtifact::new(
        successor_root_task_id,
        "service-backed successor background loop",
    );
    let mut promoted_memory = challenger_state.memory_store.clone();
    let (mut promoted_session, epoch_handoff_checkpoint) = activate_promoted_incumbent(
        &challenger_state.session,
        &promotion_act,
        &adoption,
        "envelope-background-successor",
        Some(&successor_root_task),
        "checkpoint-background-epoch-2",
        Vec::new(),
        adoption.carried_artifact_refs.clone(),
        FailureBudget::default().snapshot(),
        vec!["epoch-transition-once".to_string()],
    )
    .unwrap();
    promoted_memory.persist_checkpoint_artifact(
        "memory-checkpoint-background-epoch-2",
        epoch_handoff_checkpoint.clone(),
        "epoch handoff checkpoint persisted",
    );
    append_named_related_audit(
        &mut promoted_memory,
        &promoted_session,
        Some(successor_root_task_id),
        &epoch_handoff_checkpoint.checkpoint_id,
        "audit-checkpoint-background-epoch-2",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "epoch handoff checkpoint remained reconstructable",
    );

    let mut promoted_state = ReplayableRuntimeState::new(
        promoted_session.clone(),
        successor_root_task,
        TaskGraph::new(successor_root_task_id, Vec::new()),
        promoted_memory,
        Some(epoch_handoff_checkpoint.clone()),
        Vec::new(),
    );
    let background_campaign = BackgroundCampaign {
        campaign_id: promoted_state.session.header.campaign_id.clone(),
        objective: "continue bounded service-backed background loop".to_string(),
        authority_ceiling: AuthorityClass::Observe,
        allowed_tick_sources: vec![TickSource::EpochTransition, TickSource::ScheduledTimer],
        max_concurrent_sessions: 1,
        stop_conditions: vec![StopCondition::ExplicitTaskCompletion],
        approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
        audit_policy: GovernancePolicyClass::PromotionGovernancePolicy,
    };
    validate_background_resume_with_runtime_state(
        &background_campaign,
        &TickSource::EpochTransition,
        &promoted_state,
        &[],
        &[],
        &promotion_act.promotion_act_id,
    )
    .unwrap();

    let follow_up_checkpoint = RunCheckpoint::capture(
        "checkpoint-background-epoch-2-followup",
        &promoted_state.session,
        Some(&promoted_state.root_task),
        Vec::new(),
        vec!["review-artifact-background-1".to_string()],
        FailureBudget::default().snapshot(),
        vec!["background-tick-2".to_string()],
    );
    promoted_session.latest_checkpoint_ref = Some(follow_up_checkpoint.checkpoint_id.clone());
    persist_checkpoint_lineage(
        &mut promoted_state.memory_store,
        &follow_up_checkpoint,
        "background-follow-up",
        "follow-up background checkpoint remained reconstructable",
    );
    promoted_state.session = promoted_session;
    promoted_state.latest_checkpoint = Some(follow_up_checkpoint.clone());
    validate_background_resume_with_runtime_state(
        &background_campaign,
        &TickSource::ScheduledTimer,
        &promoted_state,
        &[],
        &[],
        &promotion_act.promotion_act_id,
    )
    .unwrap();

    store.persist_runtime_state(&promoted_state).unwrap();
    let reloaded = store
        .load_runtime_state_for_checkpoint("checkpoint-background-epoch-2-followup")
        .unwrap();

    assert_eq!(reloaded.session.header.epoch_id, "epoch-2");
    assert!(
        reloaded
            .memory_store
            .checkpoint_lineage("checkpoint-background-epoch-2-followup")
            .len()
            >= 2
    );
}
