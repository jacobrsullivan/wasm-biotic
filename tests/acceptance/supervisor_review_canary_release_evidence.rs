use std::fs;

use aiaf_v1::execution::DurableArtifactStore;

use crate::hardening_support::{
    append_named_related_audit, append_v14_program_evidence, completed_runtime_state,
    temp_store_root,
};

#[test]
fn supervisor_review_canary_release_evidence_acceptance() {
    let root = temp_store_root("review-canary-release-evidence");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let mut runtime_state = completed_runtime_state(
        "session-review-release",
        "campaign-review-release",
        "epoch-2",
        "task-review-release",
        "checkpoint-review-release-1",
        vec!["review-release-output-1".to_string()],
        "review release checkpoint captured",
    );
    let review_artifact_ref = "review-artifact-release-1".to_string();
    append_named_related_audit(
        &mut runtime_state.memory_store,
        &runtime_state.session,
        Some(&runtime_state.root_task.task_id),
        &review_artifact_ref,
        "audit-review-artifact-release-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "review artifact remained reconstructable",
    );
    append_v14_program_evidence(
        &mut runtime_state.memory_store,
        &runtime_state.session,
        Some(&runtime_state.root_task.task_id),
        "review-release-1",
        std::slice::from_ref(&review_artifact_ref),
    );

    store.persist_runtime_state(&runtime_state).unwrap();
    let reloaded = store.load_runtime_state().unwrap();

    let governance_bundle = reloaded
        .memory_store
        .topic_bundles
        .iter()
        .find(|bundle| bundle.bundle_id == "review:review-release-1")
        .expect("review governance bundle should exist");
    assert!(
        governance_bundle
            .evidence_refs
            .iter()
            .any(|reference| reference == &review_artifact_ref)
    );
    assert!(
        governance_bundle
            .evidence_refs
            .iter()
            .any(|reference| reference == "canary:review-release-1")
    );
    assert!(
        governance_bundle
            .evidence_refs
            .iter()
            .any(|reference| reference == "release:review-release-1")
    );
    assert!(
        governance_bundle
            .evidence_refs
            .iter()
            .any(|reference| reference == "rejection:review-release-1")
    );
    assert!(
        reloaded
            .memory_store
            .artifacts
            .iter()
            .any(|artifact| artifact.related_ref == "canary:review-release-1")
    );
}
