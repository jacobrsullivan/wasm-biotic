use serde_json::json;

use aiaf_v1::local_runtime::{OperatorRunbookView, RunViewModel};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_operator_runbook_steering_context_acceptance() {
    let service = service("operator-runbook").await;
    let router = router(service.clone());

    let created: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-approval-resume-worker-complete"
        }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        &format!("/api/runs/{}/approval/grant", created.summary.run_id),
        &json!({}),
    )
    .await;

    let runbook: OperatorRunbookView = get_json(&router, "/api/operator/runbook").await;

    assert!(runbook.entries.len() >= 2);
    assert_eq!(runbook.entries[0].title, "Approval granted");
    assert!(runbook.steering_context.contains("Latest operator action"));
    assert_eq!(runbook.last_action.as_deref(), Some("Approval granted"));
}
