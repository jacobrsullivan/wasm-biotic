use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2MultiCampaignPortfolioTopologyView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_multicampaign_portfolio_topology_acceptance() {
    let service = service("v27-portfolio-topology").await;
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

    let topology: V2MultiCampaignPortfolioTopologyView =
        get_json(&router, "/api/v2/operations/portfolio").await;

    assert!(topology.summary.contains("bounded campaign"));
    assert_eq!(topology.campaigns.len(), 3);
    assert!(topology.concurrency_rule.contains("bounded"));
}
