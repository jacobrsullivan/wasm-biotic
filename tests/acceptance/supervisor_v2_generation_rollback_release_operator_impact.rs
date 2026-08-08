use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2GenerationOperationalImpactView};

use crate::local_runtime_support::{get_json, post_empty, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_generation_rollback_release_operator_impact_acceptance() {
    let service = service("v25-generation-operational").await;
    let router = router(service.clone());

    let approval: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-approval-resume-worker-complete" }),
    )
    .await;
    let _: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/approval/grant", approval.summary.run_id),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;

    let operational: V2GenerationOperationalImpactView =
        get_json(&router, "/api/v2/generation/operational").await;

    assert!(
        operational
            .summary
            .contains("release, rollback, and operator story")
    );
    assert!(operational.release_posture.contains("release law"));
    assert!(operational.rollback_posture.contains("rollback"));
    assert!(!operational.operator_impact.is_empty());
}
