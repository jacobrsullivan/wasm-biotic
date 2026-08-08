use serde_json::json;

use aiaf_v1::local_runtime::{LocalRunStatus, RunViewModel};

use crate::local_runtime_support::{post_empty, post_json, router, service};

#[tokio::test]
async fn supervisor_rollback_via_operator_surface_acceptance() {
    let service = service("rollback-operator-surface").await;
    let router = router(service);

    let created: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-background-quarantine-rollback-control-loop"
        }),
    )
    .await;
    assert_eq!(created.summary.status, LocalRunStatus::AwaitingRollback);
    assert!(created.summary.rollback_available);
    assert_eq!(created.quarantines.len(), 1);

    let rolled_back: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/rollback", created.summary.run_id),
    )
    .await;
    assert_eq!(rolled_back.summary.status, LocalRunStatus::RolledBack);
    assert!(rolled_back.quarantines.is_empty());
    assert!(
        rolled_back
            .events
            .iter()
            .any(|event| event.detail.contains("rollback"))
    );
}
