use std::fs;

use aiaf_v1::execution::{
    AuthorityClass, BackgroundCampaign, BlockedReason, BlockedReasonKind, DurableArtifactStore,
    ExecutionSessionState, GovernancePolicyClass, MemoryScope, MemoryStore, QuarantineReasonClass,
    QuarantineResolutionState, StopCondition, TaskGraph, TaskState, TickSource, TopicBundle,
    TopicBundleClass, TranscriptSlice, create_quarantine_record, create_rollback_handle,
    execute_rollback, persist_approval_decision_bundle, persist_approval_request_bundle,
    validate_background_resume_with_runtime_state,
};

use crate::hardening_support::{
    append_named_related_audit, checkpoint, granted_dispatch_decision, persist_checkpoint_lineage,
    ready_session, request_for_dispatch, root_pointer_index, root_task,
    runtime_state_with_checkpoint, temp_store_root,
};

#[test]
fn supervisor_native_memory_governance_service_continuity_acceptance() {
    let root = temp_store_root("native-memory-governance-service-continuity");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let mut session = ready_session(
        "session-memory-service",
        "campaign-memory-service",
        "epoch-1",
        "envelope-memory-service",
    );
    session.state = ExecutionSessionState::AwaitingApproval;
    session.active_task_id = Some("task-memory-service".to_string());
    session.pending_approval_refs = vec!["approval-memory-service-1".to_string()];
    session.blocked_reason = Some(BlockedReason::new(
        BlockedReasonKind::Approval,
        "approval required before governed memory service resume",
    ));

    let mut task = root_task(
        "task-memory-service",
        "native memory and governance continuity",
    );
    task.state = TaskState::BlockedOnApproval;
    task.owner_session_id = Some(session.header.session_id.clone());
    task.blocked_reason = session.blocked_reason.clone();

    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(root_pointer_index(
        "pointer-index-memory-service",
        &session.header.campaign_id,
        &task.task_id,
    ));
    memory_store.add_topic_bundle(TopicBundle {
        bundle_id: "review-bundle-memory-1".to_string(),
        bundle_class: TopicBundleClass::GovernanceNotes,
        scope: MemoryScope::Campaign(session.header.campaign_id.clone()),
        summary: "operator review bundle for native memory and governance services".to_string(),
        evidence_refs: vec!["approval-memory-service-1".to_string()],
        freshness_policy: "retain-until-epoch-close".to_string(),
    });
    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: "transcript-memory-service-1".to_string(),
        campaign_id: session.header.campaign_id.clone(),
        epoch_id: session.header.epoch_id.clone(),
        session_id: Some(session.header.session_id.clone()),
        task_id: Some(task.task_id.clone()),
        referenced_artifacts: vec!["review-bundle-memory-1".to_string()],
        summary: "native memory and governance service review transcript".to_string(),
        excerpts: vec![
            "approval and rollback evidence remained available to the operator".to_string(),
        ],
    });

    let checkpoint = checkpoint(
        "checkpoint-memory-service-1",
        &session,
        Some(&task),
        vec!["pointer-index-memory-service".to_string()],
        vec!["approval-memory-service-1".to_string()],
    );
    persist_checkpoint_lineage(
        &mut memory_store,
        &checkpoint,
        "memory-service",
        "memory service checkpoint remained reconstructable",
    );
    let rollback_handle = create_rollback_handle(
        "rollback-memory-service-1",
        "campaign-memory-service",
        checkpoint.checkpoint_id.clone(),
        vec!["restore checkpoint-memory-service-1".to_string()],
        Vec::new(),
    );
    append_named_related_audit(
        &mut memory_store,
        &session,
        Some(&task.task_id),
        &rollback_handle.rollback_handle_id,
        "audit-rollback-memory-service-1",
        aiaf_v1::execution::AuditRecordClass::PromotionAuditRecord,
        "rollback handle remained reconstructable",
    );
    append_named_related_audit(
        &mut memory_store,
        &session,
        Some(&task.task_id),
        "review-bundle-memory-1",
        "audit-review-bundle-memory-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "operator review bundle remained reconstructable",
    );

    let mut runtime_state = runtime_state_with_checkpoint(
        session,
        task,
        TaskGraph::new("task-memory-service", Vec::new()),
        memory_store,
        checkpoint,
        "event-memory-service-checkpoint",
        "memory service checkpoint captured",
    );
    let approval_request = request_for_dispatch(
        "approval-memory-service-1",
        &runtime_state.session,
        &runtime_state.root_task.task_id,
    );
    persist_approval_request_bundle(
        &mut runtime_state.memory_store,
        &approval_request,
        runtime_state.latest_checkpoint.as_ref().unwrap(),
    );
    let approval_decision = granted_dispatch_decision(
        "approval-memory-service-1",
        &runtime_state.session,
        &runtime_state.root_task.task_id,
    );
    persist_approval_decision_bundle(&mut runtime_state.memory_store, &approval_decision, &[]);

    let background_campaign = BackgroundCampaign {
        campaign_id: runtime_state.session.header.campaign_id.clone(),
        objective: "resume governed memory service flow".to_string(),
        authority_ceiling: AuthorityClass::Observe,
        allowed_tick_sources: vec![TickSource::ApprovalResponse, TickSource::ScheduledTimer],
        max_concurrent_sessions: 1,
        stop_conditions: vec![StopCondition::ExplicitTaskCompletion],
        approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
        audit_policy: GovernancePolicyClass::MemoryIntegrityPolicy,
    };
    let quarantine = create_quarantine_record(
        "quarantine-memory-service-1",
        QuarantineReasonClass::PolicyViolation,
        vec![approval_request.approval_request_id.clone()],
        Some(rollback_handle.rollback_handle_id.clone()),
    );
    let blocked = validate_background_resume_with_runtime_state(
        &background_campaign,
        &TickSource::ApprovalResponse,
        &runtime_state,
        std::slice::from_ref(&approval_decision),
        std::slice::from_ref(&quarantine),
        &approval_request.approval_request_id,
    );
    assert!(blocked.is_err());

    let mut resolved_quarantine = quarantine.clone();
    resolved_quarantine.resolution_state = QuarantineResolutionState::Resolved;
    validate_background_resume_with_runtime_state(
        &background_campaign,
        &TickSource::ApprovalResponse,
        &runtime_state,
        std::slice::from_ref(&approval_decision),
        std::slice::from_ref(&resolved_quarantine),
        &approval_request.approval_request_id,
    )
    .unwrap();

    store.persist_runtime_state(&runtime_state).unwrap();
    let restored = execute_rollback(&rollback_handle, &store).unwrap();

    assert_eq!(
        restored.latest_checkpoint.unwrap().checkpoint_id,
        "checkpoint-memory-service-1"
    );
    assert!(
        restored
            .memory_store
            .topic_bundles
            .iter()
            .any(|bundle| bundle.bundle_id == "review-bundle-memory-1")
    );
    assert!(
        restored
            .memory_store
            .approval_lineage("approval-memory-service-1")
            .len()
            >= 2
    );
    assert!(
        restored
            .memory_store
            .approval_lineage("approval-memory-service-1")
            .iter()
            .any(|artifact| {
                artifact.class == aiaf_v1::execution::MemoryArtifactClass::ApprovalRequestArtifact
            })
    );
    assert!(
        restored
            .memory_store
            .approval_lineage("approval-memory-service-1")
            .iter()
            .any(|artifact| {
                artifact.class == aiaf_v1::execution::MemoryArtifactClass::ApprovalDecisionArtifact
            })
    );
    assert!(
        restored
            .memory_store
            .artifacts_for_related_ref("approval-transport:approval-memory-service-1")
            .len()
            >= 2
    );
}
