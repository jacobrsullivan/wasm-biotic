use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2QueueFairnessSchedulerContentionView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_queue_fairness_scheduler_contention_acceptance() {
    let service = service("v27-fairness-contention").await;
    let router = router(service.clone());

    let approval: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-approval-resume-worker-complete" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-promote-activate-successor-campaign" }),
    )
    .await;

    let fairness: V2QueueFairnessSchedulerContentionView =
        get_json(&router, "/api/v2/operations/fairness").await;

    assert!(fairness.summary.contains("scheduler lane"));
    assert!(fairness.lanes.len() >= 2);
    assert!(
        fairness
            .lanes
            .iter()
            .any(|lane| lane.run_refs.contains(&approval.summary.run_id))
    );
}
