use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2IntegratedMultiCampaignFactoryOperationsView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_integrated_multicampaign_factory_operations_acceptance() {
    let service = service("v27-integrated-operations").await;
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
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;

    let suite: V2IntegratedMultiCampaignFactoryOperationsView =
        get_json(&router, "/api/v2/operations/suite").await;

    assert!(suite.summary.contains("integrated operations suite"));
    assert!(!suite.operational_story.is_empty());
    assert!(!suite.evidence_refs.is_empty());
}
