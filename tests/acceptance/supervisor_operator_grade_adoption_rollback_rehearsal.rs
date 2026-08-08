use std::fs;

use aiaf_v1::execution::{
    AuditRecordClass, DurableArtifactStore, create_rollback_handle, execute_rollback,
};

use crate::hardening_support::{
    append_named_related_audit, append_v14_program_evidence, completed_runtime_state,
    temp_store_root,
};

#[test]
fn supervisor_operator_grade_adoption_rollback_rehearsal_acceptance() {
    let root = temp_store_root("operator-grade-adoption-rollback-rehearsal");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let mut runtime_state = completed_runtime_state(
        "session-operator-steering",
        "campaign-operator-steering",
        "epoch-3",
        "task-operator-steering",
        "checkpoint-operator-steering-1",
        vec!["operator-steering-output-1".to_string()],
        "operator steering checkpoint captured",
    );
    let rollback_handle = create_rollback_handle(
        "rollback-operator-steering-1",
        "campaign-operator-steering",
        "checkpoint-operator-steering-1",
        vec!["restore checkpoint-operator-steering-1".to_string()],
        Vec::new(),
    );
    let review_artifact_ref = "review-artifact-operator-steering-1".to_string();
    append_named_related_audit(
        &mut runtime_state.memory_store,
        &runtime_state.session,
        Some(&runtime_state.root_task.task_id),
        &review_artifact_ref,
        "audit-review-artifact-operator-steering-1",
        AuditRecordClass::GovernanceAuditRecord,
        "operator steering review artifact remained reconstructable",
    );
    append_named_related_audit(
        &mut runtime_state.memory_store,
        &runtime_state.session,
        Some(&runtime_state.root_task.task_id),
        &rollback_handle.rollback_handle_id,
        "audit-rollback-operator-steering-1",
        AuditRecordClass::PromotionAuditRecord,
        "rollback handle remained reconstructable",
    );
    append_v14_program_evidence(
        &mut runtime_state.memory_store,
        &runtime_state.session,
        Some(&runtime_state.root_task.task_id),
        "operator-steering-1",
        std::slice::from_ref(&review_artifact_ref),
    );

    store.persist_runtime_state(&runtime_state).unwrap();
    let restored = execute_rollback(&rollback_handle, &store).unwrap();

    assert_eq!(
        restored.latest_checkpoint.unwrap().checkpoint_id,
        "checkpoint-operator-steering-1"
    );
    assert!(
        restored
            .memory_store
            .topic_bundles
            .iter()
            .any(|bundle| bundle.bundle_id == "steering:operator-steering-1")
    );
    assert!(
        restored
            .memory_store
            .artifacts
            .iter()
            .any(|artifact| artifact.related_ref == "rollback-rehearsal:operator-steering-1")
    );
}
