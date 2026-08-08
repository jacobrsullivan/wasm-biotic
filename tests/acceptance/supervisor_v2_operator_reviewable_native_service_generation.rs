use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2OperatorReviewableNativeServiceGenerationView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_operator_reviewable_native_service_generation_acceptance() {
    let service = service("v26-reviewable-generation").await;
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
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program" }),
    )
    .await;

    let review: V2OperatorReviewableNativeServiceGenerationView =
        get_json(&router, "/api/v2/service-generation/review").await;

    assert!(
        review
            .summary
            .contains("operator-reviewable service generation")
    );
    assert!(
        review
            .maturity_signal
            .contains("bounded service-generation review")
    );
    assert!(!review.review_dimensions.is_empty());
    assert!(!review.evidence_refs.is_empty());
}
