use aiaf_v1::local_runtime::V2BoundaryCandidateInventoryView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_contract_pressure_normalization_acceptance() {
    let service = service("v20-pressure-normalization").await;
    let _ = service
        .start_run("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    let _ = service
        .start_run("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();

    let router = router(service.clone());
    let inventory: V2BoundaryCandidateInventoryView =
        get_json(&router, "/api/v2/contracts/candidates").await;

    assert!(inventory.summary.contains("candidate"));
    assert_eq!(
        inventory.baseline_anchor,
        "v1.9 convergence dossier and transition workspace"
    );
    assert!(inventory.candidates.len() >= 6);
    assert!(
        inventory
            .candidates
            .iter()
            .all(|candidate| !candidate.source_pressure_id.trim().is_empty())
    );
    assert!(
        inventory
            .candidates
            .iter()
            .all(|candidate| !candidate.evidence_refs.is_empty())
    );
}
