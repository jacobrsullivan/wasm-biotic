use serde_json::json;

use aiaf_v1::local_runtime::{LocalRunStatus, RunViewModel};

use crate::local_runtime_support::{post_empty, post_json, router, service};

#[tokio::test]
async fn supervisor_approval_resume_via_operator_surface_acceptance() {
    let service = service("approval-operator-surface").await;
    let router = router(service);

    let created: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-approval-resume-worker-complete"
        }),
    )
    .await;
    assert_eq!(created.summary.status, LocalRunStatus::AwaitingApproval);
    assert_eq!(created.summary.pending_approval_count, 1);

    let resumed: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/approval/grant", created.summary.run_id),
    )
    .await;
    assert_eq!(resumed.summary.status, LocalRunStatus::Completed);
    assert!(
        resumed.approvals.iter().any(|approval| approval.decision
            == Some(aiaf_v1::execution::ApprovalDecisionStatus::Granted))
    );
    assert!(
        resumed
            .events
            .iter()
            .any(|event| event.detail.contains("granted approval"))
    );
}
