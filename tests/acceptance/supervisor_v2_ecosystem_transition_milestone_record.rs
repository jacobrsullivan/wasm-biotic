use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2EcosystemTransitionMilestoneRecordView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_ecosystem_transition_milestone_record_acceptance() {
    let service = service("v28-milestone").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-self-hosting-loop" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program" }),
    )
    .await;

    let milestone: V2EcosystemTransitionMilestoneRecordView =
        get_json(&router, "/api/v2/self-hosting/milestone").await;

    assert!(milestone.summary.contains("ecosystem-transition milestone"));
    assert!(milestone.phase_label.contains("single-factory"));
    assert!(!milestone.non_goals.is_empty());
}
