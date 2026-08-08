use std::fs;

use aiaf_v1::execution::{
    ContradictionResolutionState, DurableArtifactStore, persist_approval_decision_bundle,
    persist_approval_request_bundle, validate_background_resume_with_runtime_state,
};

use crate::hardening_support::{
    append_named_related_audit, append_v14_program_evidence, approval_blocked_runtime_state,
    background_campaign, checkpoint, granted_dispatch_decision, persist_checkpoint_lineage,
    ready_session, request_for_dispatch, root_pointer_index, root_task, temp_store_root,
};

#[test]
fn supervisor_continuous_background_program_memory_acceptance() {
    let session = ready_session("session-1", "campaign-1", "epoch-1", "envelope-1");
    let task = root_task("task-1", "exercise repeated background program continuity");
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
        "continuous-background-program",
        "continuous background program checkpoint remained reconstructable",
    );

    let review_artifact_ref = "review-artifact-background-program-1".to_string();
    append_named_related_audit(
        &mut memory_store,
        &session,
        Some(&task.task_id),
        &review_artifact_ref,
        "audit-review-artifact-background-program-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "background program review artifact remained reconstructable",
    );
    append_v14_program_evidence(
        &mut memory_store,
        &session,
        Some(&task.task_id),
        "background-program-1",
        std::slice::from_ref(&review_artifact_ref),
    );

    let approval_request = request_for_dispatch("approval-1", &session, &task.task_id);
    persist_approval_request_bundle(&mut memory_store, &approval_request, &checkpoint);
    let granted = granted_dispatch_decision("approval-1", &session, &task.task_id);
    persist_approval_decision_bundle(&mut memory_store, &granted, &[]);

    let runtime_state = approval_blocked_runtime_state(
        memory_store,
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

    let root = temp_store_root("continuous-background-program-memory");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();
    store.persist_runtime_state(&runtime_state).unwrap();
    let reloaded = store.load_runtime_state().unwrap();

    assert!(
        reloaded
            .memory_store
            .topic_bundles
            .iter()
            .any(|bundle| bundle.bundle_id == "program-memory:background-program-1")
    );
    assert!(reloaded.memory_store.transcript_slices.iter().any(|slice| {
        slice
            .referenced_artifacts
            .iter()
            .any(|reference| reference == "plan-carry-forward:background-program-1")
            && slice
                .referenced_artifacts
                .iter()
                .any(|reference| reference == "reprioritization:background-program-1")
    }));
    assert!(
        reloaded
            .memory_store
            .contradiction_records
            .iter()
            .any(|record| {
                record.contradiction_id == "contradiction:background-program-1"
                    && record.resolution_state == ContradictionResolutionState::Resolved
            })
    );
    assert!(reloaded.memory_store.approval_lineage("approval-1").len() >= 2);
}
