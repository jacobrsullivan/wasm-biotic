use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2CrossWorkstreamCompatibilityView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_cross_workstream_compatibility_rehearsal_acceptance() {
    let service = service("v25-generation-compatibility").await;
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

    let compatibility: V2CrossWorkstreamCompatibilityView =
        get_json(&router, "/api/v2/generation/compatibility").await;

    assert!(compatibility.summary.contains("compatibility rehearsal"));
    assert_eq!(compatibility.checks.len(), 5);
    assert!(!compatibility.coexistence_rules.is_empty());
}
