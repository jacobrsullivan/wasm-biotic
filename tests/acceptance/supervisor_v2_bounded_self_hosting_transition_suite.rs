use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2BoundedSelfHostingTransitionSuiteView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_bounded_self_hosting_transition_suite_acceptance() {
    let service = service("v28-suite").await;
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
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;

    let suite: V2BoundedSelfHostingTransitionSuiteView =
        get_json(&router, "/api/v2/self-hosting/suite").await;

    assert!(suite.summary.contains("distinct v2 self-hosting proof"));
    assert!(!suite.evidence_refs.is_empty());
}
