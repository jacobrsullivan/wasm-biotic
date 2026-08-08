use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2RecoveryInterventionSharedResourcesView};

use crate::local_runtime_support::{get_json, post_empty, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_recovery_intervention_shared_resources_acceptance() {
    let service = service("v27-recovery-intervention").await;
    let router = router(service.clone());

    let approval: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-approval-resume-worker-complete" }),
    )
    .await;
    let _: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/approval/deny", approval.summary.run_id),
    )
    .await;

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;

    let recovery: V2RecoveryInterventionSharedResourcesView =
        get_json(&router, "/api/v2/operations/recovery").await;

    assert!(recovery.summary.contains("recovery or intervention"));
    assert!(!recovery.entries.is_empty());
    assert!(
        recovery.operator_context.contains("denied")
            || recovery.operator_context.contains("rollback")
    );
}
