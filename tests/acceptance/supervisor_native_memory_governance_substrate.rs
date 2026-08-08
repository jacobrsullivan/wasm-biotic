use std::fs;

use aiaf_v1::execution::{
    AuditRecordClass, DurableArtifactStore, GovernanceError, MemoryScope, MemoryUpdateProposal,
    MemoryUpdateStatus, StopCondition, TopicBundleClass, create_quarantine_record,
    create_rollback_handle, execute_rollback, persist_approval_decision_bundle,
    persist_approval_request_bundle, validate_background_resume_with_runtime_state,
};

use crate::hardening_support::{
    append_audit, approval_blocked_runtime_state, background_campaign, checkpoint,
    granted_dispatch_decision, ready_session, request_for_dispatch, root_pointer_index, root_task,
    temp_store_root,
};

#[test]
fn supervisor_native_memory_governance_substrate_acceptance() {
    let root = temp_store_root("native-memory-governance-substrate");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let session = ready_session("session-1", "campaign-1", "epoch-1", "envelope-1");
    let task = root_task("task-1", "preserve native memory and governance continuity");
    let checkpoint = checkpoint(
        "checkpoint-memory-governance-1",
        &session,
        Some(&task),
        vec!["pointer-index-1".to_string()],
        Vec::new(),
    );

    let mut memory_store = aiaf_v1::execution::MemoryStore::default();
    memory_store.insert_pointer_index(root_pointer_index(
        "pointer-index-1",
        &session.header.campaign_id,
        &task.task_id,
    ));
    memory_store.persist_checkpoint_artifact(
        "memory-checkpoint-memory-governance-1",
        checkpoint.clone(),
        "native memory/governance checkpoint persisted",
    );
    append_audit(
        &mut memory_store,
        "memory-audit-checkpoint-memory-governance-1",
        "audit-checkpoint-memory-governance-1",
        AuditRecordClass::GovernanceAuditRecord,
        &session,
        Some(&task.task_id),
        &checkpoint.checkpoint_id,
        "native memory/governance checkpoint remained reconstructable",
    );

    let approval_request = request_for_dispatch("approval-memory-1", &session, &task.task_id);
    persist_approval_request_bundle(&mut memory_store, &approval_request, &checkpoint);
    let granted_decision = granted_dispatch_decision("approval-memory-1", &session, &task.task_id);
    persist_approval_decision_bundle(&mut memory_store, &granted_decision, &[]);

    memory_store.propose_memory_update(MemoryUpdateProposal {
        proposal_id: "memory-proposal-1".to_string(),
        pointer_index_ref: Some("pointer-index-1".to_string()),
        bundle_class: TopicBundleClass::GovernanceNotes,
        scope: MemoryScope::Task(task.task_id.clone()),
        proposed_summary: "approval and rollback review bundle accepted".to_string(),
        evidence_refs: vec![
            approval_request.approval_request_id.clone(),
            granted_decision.approval_request_id.clone(),
        ],
        verification_refs: vec![checkpoint.checkpoint_id.clone()],
        status: MemoryUpdateStatus::Proposed,
    });
    let review_bundle_id = memory_store
        .accept_memory_update(
            "memory-proposal-1",
            "bundle-memory-governance-review",
            "verified-by-checkpoint",
        )
        .unwrap();

    let rollback_handle = create_rollback_handle(
        "rollback-memory-governance-1",
        "task",
        checkpoint.checkpoint_id.clone(),
        vec!["restore checkpoint-memory-governance-1".to_string()],
        Vec::new(),
    );
    append_audit(
        &mut memory_store,
        "memory-audit-rollback-memory-governance-1",
        "audit-rollback-memory-governance-1",
        AuditRecordClass::PromotionAuditRecord,
        &session,
        Some(&task.task_id),
        &rollback_handle.rollback_handle_id,
        "rollback handle remained reconstructable",
    );

    let runtime_state = approval_blocked_runtime_state(
        memory_store.clone(),
        &approval_request.approval_request_id,
        &checkpoint.checkpoint_id,
        &task.task_id,
    );

    let mut quarantine = create_quarantine_record(
        "quarantine-memory-governance-1",
        aiaf_v1::execution::QuarantineReasonClass::PostApprovalAnomaly,
        vec![task.task_id.clone()],
        Some(rollback_handle.rollback_handle_id.clone()),
    );
    let blocked = validate_background_resume_with_runtime_state(
        &background_campaign("campaign-1"),
        &aiaf_v1::execution::TickSource::ApprovalResponse,
        &runtime_state,
        std::slice::from_ref(&granted_decision),
        std::slice::from_ref(&quarantine),
        &task.task_id,
    )
    .unwrap_err();
    assert_eq!(
        blocked,
        GovernanceError::QuarantineBlocksAction {
            quarantine_id: "quarantine-memory-governance-1".to_string(),
            affected_ref: "task-1".to_string(),
        }
    );
    quarantine.resolution_state = aiaf_v1::execution::QuarantineResolutionState::Resolved;
    validate_background_resume_with_runtime_state(
        &background_campaign("campaign-1"),
        &aiaf_v1::execution::TickSource::ApprovalResponse,
        &runtime_state,
        std::slice::from_ref(&granted_decision),
        std::slice::from_ref(&quarantine),
        &task.task_id,
    )
    .unwrap();

    store.persist_runtime_state(&runtime_state).unwrap();
    let rolled_back = execute_rollback(&rollback_handle, &store).unwrap();

    let approval_lineage = rolled_back
        .memory_store
        .approval_lineage(&approval_request.approval_request_id);
    assert!(approval_lineage.iter().any(|artifact| {
        artifact.class == aiaf_v1::execution::MemoryArtifactClass::ApprovalRequestArtifact
    }));
    assert!(approval_lineage.iter().any(|artifact| {
        artifact.class == aiaf_v1::execution::MemoryArtifactClass::ApprovalDecisionArtifact
    }));
    assert!(
        rolled_back
            .memory_store
            .topic_bundle(&review_bundle_id)
            .expect("review bundle should exist")
            .evidence_refs
            .iter()
            .any(|evidence_ref| evidence_ref == &checkpoint.checkpoint_id)
    );
    assert!(
        background_campaign("campaign-1")
            .stop_conditions
            .contains(&StopCondition::ExplicitTaskCompletion)
    );
}
