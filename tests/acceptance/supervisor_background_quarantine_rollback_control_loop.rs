use std::fs;

use aiaf_v1::execution::{
    AuditRecordClass, DurableArtifactStore, GovernanceError, QuarantineResolutionState,
    RollbackExecutionError, create_quarantine_record, create_rollback_handle, execute_rollback,
    persist_approval_decision_bundle, persist_approval_request_bundle,
    validate_background_resume_with_runtime_state,
};

use crate::hardening_support::{
    append_audit, approval_blocked_runtime_state, background_campaign, checkpoint,
    granted_dispatch_decision, persist_checkpoint_lineage, ready_session, request_for_dispatch,
    root_pointer_index, root_task, temp_store_root,
};

#[test]
fn supervisor_background_quarantine_rollback_control_loop_acceptance() {
    let session = ready_session("session-1", "campaign-1", "epoch-1", "envelope-1");
    let task = root_task(
        "task-1",
        "exercise governed background, quarantine, and rollback",
    );
    let checkpoint = checkpoint(
        "checkpoint-1",
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
    persist_checkpoint_lineage(
        &mut memory_store,
        &checkpoint,
        "background",
        "background checkpoint lineage remained reconstructable",
    );

    let approval_request = request_for_dispatch("approval-1", &session, &task.task_id);
    persist_approval_request_bundle(&mut memory_store, &approval_request, &checkpoint);
    let granted = granted_dispatch_decision("approval-1", &session, &task.task_id);
    persist_approval_decision_bundle(&mut memory_store, &granted, &[]);
    append_audit(
        &mut memory_store,
        "memory-audit-background-1",
        "audit-background-1",
        AuditRecordClass::GovernanceAuditRecord,
        &session,
        Some(&task.task_id),
        "background:campaign-1:ApprovalResponse:checkpoint-1",
        "background resume approval response was recorded deterministically",
    );

    let runtime_state = approval_blocked_runtime_state(
        memory_store.clone(),
        &approval_request.approval_request_id,
        &checkpoint.checkpoint_id,
        &task.task_id,
    );
    validate_background_resume_with_runtime_state(
        &background_campaign("campaign-1"),
        &aiaf_v1::execution::TickSource::ApprovalResponse,
        &runtime_state,
        std::slice::from_ref(&granted),
        &[],
        &task.task_id,
    )
    .unwrap();

    let mut quarantine = create_quarantine_record(
        "quarantine-1",
        aiaf_v1::execution::QuarantineReasonClass::PostApprovalAnomaly,
        vec![task.task_id.clone()],
        Some("rollback-1".to_string()),
    );
    append_audit(
        &mut memory_store,
        "memory-audit-quarantine-loop-1",
        "audit-quarantine-loop-1",
        AuditRecordClass::GovernanceAuditRecord,
        &session,
        Some(&task.task_id),
        "quarantine-1",
        "quarantine opened and blocked the affected task",
    );

    let runtime_state = approval_blocked_runtime_state(
        memory_store.clone(),
        &approval_request.approval_request_id,
        &checkpoint.checkpoint_id,
        &task.task_id,
    );
    let quarantine_error = validate_background_resume_with_runtime_state(
        &background_campaign("campaign-1"),
        &aiaf_v1::execution::TickSource::ApprovalResponse,
        &runtime_state,
        std::slice::from_ref(&granted),
        std::slice::from_ref(&quarantine),
        &task.task_id,
    )
    .unwrap_err();
    assert_eq!(
        quarantine_error,
        GovernanceError::QuarantineBlocksAction {
            quarantine_id: "quarantine-1".to_string(),
            affected_ref: "task-1".to_string(),
        }
    );

    quarantine.resolution_state = QuarantineResolutionState::Resolved;
    validate_background_resume_with_runtime_state(
        &background_campaign("campaign-1"),
        &aiaf_v1::execution::TickSource::ApprovalResponse,
        &runtime_state,
        std::slice::from_ref(&granted),
        std::slice::from_ref(&quarantine),
        &task.task_id,
    )
    .unwrap();

    let rollback_handle = create_rollback_handle(
        "rollback-1",
        "task",
        "checkpoint-1",
        vec!["restore checkpoint-1".to_string()],
        Vec::new(),
    );
    append_audit(
        &mut memory_store,
        "memory-audit-rollback-loop-1",
        "audit-rollback-loop-1",
        AuditRecordClass::PromotionAuditRecord,
        &session,
        Some(&task.task_id),
        "rollback-1",
        "rollback execution remained reconstructable",
    );

    let root = temp_store_root("background-quarantine-rollback");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();
    let runtime_state = approval_blocked_runtime_state(
        memory_store.clone(),
        &approval_request.approval_request_id,
        &checkpoint.checkpoint_id,
        &task.task_id,
    );
    store.persist_runtime_state(&runtime_state).unwrap();

    let restored = execute_rollback(&rollback_handle, &store).unwrap();
    assert_eq!(
        restored
            .session
            .latest_checkpoint_ref
            .as_deref()
            .expect("checkpoint should survive rollback"),
        "checkpoint-1"
    );
    assert!(
        restored
            .memory_store
            .artifacts_for_related_ref("background:campaign-1:ApprovalResponse:checkpoint-1")
            .iter()
            .any(|artifact| artifact.class
                == aiaf_v1::execution::MemoryArtifactClass::AuditRecordArtifact)
    );

    let approval_required_handle = create_rollback_handle(
        "rollback-2",
        "task",
        "checkpoint-1",
        vec!["restore checkpoint-1".to_string()],
        vec!["operator-approval".to_string()],
    );
    assert_eq!(
        execute_rollback(&approval_required_handle, &store).unwrap_err(),
        RollbackExecutionError::ApprovalRequired {
            rollback_handle_id: "rollback-2".to_string(),
        }
    );
}
