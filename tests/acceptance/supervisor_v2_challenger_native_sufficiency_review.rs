use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2ChallengerNativeSufficiencyReviewView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_challenger_native_sufficiency_review_acceptance() {
    let service = service("v28-sufficiency-review").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-promote-activate-successor-campaign" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program" }),
    )
    .await;

    let review: V2ChallengerNativeSufficiencyReviewView =
        get_json(&router, "/api/v2/self-hosting/sufficiency").await;

    assert!(review.summary.contains("challenger review"));
    assert!(review.sufficiency_summary.contains("operator-reviewable"));
    assert!(!review.guardrails.is_empty());
}
