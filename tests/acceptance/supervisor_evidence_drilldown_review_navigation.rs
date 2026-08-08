use aiaf_v1::local_runtime::EvidenceDrilldownView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_evidence_drilldown_review_navigation_acceptance() {
    let service = service("evidence-drilldown").await;
    let run = service
        .start_run("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();

    let router = router(service.clone());
    let evidence: EvidenceDrilldownView = get_json(
        &router,
        &format!("/api/runs/{}/evidence", run.summary.run_id),
    )
    .await;

    assert_eq!(evidence.run_id, run.summary.run_id);
    assert!(evidence.review_bundle_refs.contains(&run.summary.run_id));
    assert!(
        evidence
            .sections
            .iter()
            .any(|section| section.section_id == "approvals")
    );
    assert!(
        evidence
            .sections
            .iter()
            .any(|section| section.section_id == "checkpoints")
    );
    assert!(
        evidence
            .sections
            .iter()
            .any(|section| section.section_id == "audit-and-promotion")
    );
}
