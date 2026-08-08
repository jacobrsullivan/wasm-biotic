use std::fs;

use serde_json::json;

use aiaf_v1::local_runtime::{LocalRunStatus, RunViewModel};

use crate::local_runtime_support::{post_empty, post_json, router, service};

#[tokio::test]
async fn supervisor_runnable_local_continuous_factory_program_acceptance() {
    let service = service("runnable-continuous-program").await;
    let router = router(service.clone());

    let created: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program"
        }),
    )
    .await;
    assert_eq!(created.summary.status, LocalRunStatus::AwaitingApproval);
    assert_eq!(created.summary.pending_approval_count, 1);

    let completed: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/approval/grant", created.summary.run_id),
    )
    .await;
    assert_eq!(completed.summary.status, LocalRunStatus::Completed);
    assert!(completed.approvals.iter().any(|approval| {
        approval.decision == Some(aiaf_v1::execution::ApprovalDecisionStatus::Granted)
    }));
    assert!(
        completed
            .summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("northstar-01-program-mapping:"))
    );

    let export_root = service.export_run(&completed.summary.run_id).await.unwrap();
    let report = fs::read_to_string(export_root.join("report.html")).unwrap();
    assert!(report.contains("Continuous Self-Hosting Program"));
}
