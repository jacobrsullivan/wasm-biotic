use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2ServiceClosureEvidenceReviewView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_service_closure_evidence_review_acceptance() {
    let service = service("v26-evidence-review").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-approval-resume-worker-complete" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-promote-activate-successor-campaign" }),
    )
    .await;

    let review: V2ServiceClosureEvidenceReviewView =
        get_json(&router, "/api/v2/service-generation/evidence-review").await;

    assert!(review.summary.contains("service-evidence layer"));
    assert!(!review.items.is_empty());
    assert!(!review.operator_review_notes.is_empty());
}
