use std::fs;

use aiaf_v1::execution::DurableArtifactStore;

use crate::hardening_support::{
    append_named_related_audit, append_v14_program_evidence, completed_runtime_state,
    temp_store_root,
};

#[test]
fn supervisor_campaign_portfolio_budget_continuity_acceptance() {
    let root = temp_store_root("campaign-portfolio-budget-continuity");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let mut runtime_state = completed_runtime_state(
        "session-portfolio-budget",
        "campaign-portfolio-budget",
        "epoch-1",
        "task-portfolio-budget",
        "checkpoint-portfolio-budget-1",
        vec!["portfolio-output-1".to_string()],
        "campaign portfolio checkpoint captured",
    );
    let review_artifact_ref = "review-artifact-portfolio-budget-1".to_string();
    append_named_related_audit(
        &mut runtime_state.memory_store,
        &runtime_state.session,
        Some(&runtime_state.root_task.task_id),
        &review_artifact_ref,
        "audit-review-artifact-portfolio-budget-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "portfolio review artifact remained reconstructable",
    );
    append_v14_program_evidence(
        &mut runtime_state.memory_store,
        &runtime_state.session,
        Some(&runtime_state.root_task.task_id),
        "portfolio-budget-1",
        std::slice::from_ref(&review_artifact_ref),
    );

    store.persist_runtime_state(&runtime_state).unwrap();
    let reloaded = store.load_runtime_state().unwrap();

    let portfolio_bundle = reloaded
        .memory_store
        .topic_bundles
        .iter()
        .find(|bundle| bundle.bundle_id == "portfolio:portfolio-budget-1")
        .expect("portfolio bundle should exist");
    assert!(
        portfolio_bundle
            .evidence_refs
            .iter()
            .any(|reference| reference == "budget:portfolio-budget-1")
    );
    assert!(
        portfolio_bundle
            .evidence_refs
            .iter()
            .any(|reference| reference == "intervention:portfolio-budget-1")
    );
    assert!(
        reloaded
            .memory_store
            .artifacts
            .iter()
            .any(|artifact| artifact.related_ref == "budget:portfolio-budget-1")
    );
    assert!(reloaded.memory_store.transcript_slices.iter().any(|slice| {
        slice
            .referenced_artifacts
            .iter()
            .any(|reference| reference == "plan-carry-forward:portfolio-budget-1")
    }));
}
