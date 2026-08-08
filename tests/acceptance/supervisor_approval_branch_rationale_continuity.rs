use aiaf_v1::local_runtime::{ReplayWorkspaceView, RunViewModel};
use serde_json::json;

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_approval_branch_rationale_continuity_acceptance() {
    let service = service("approval-branch-rationale").await;
    let router = router(service.clone());

    let run: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-approval-resume-worker-complete",
            "composition_id": "composition-factory-approval-baseline",
            "run_set_id": "runset-factory-governed-upgrade",
            "hypothesis_id": "hypothesis-approval-lineage"
        }),
    )
    .await;

    let replay: ReplayWorkspaceView =
        get_json(&router, &format!("/api/runs/{}/replay", run.summary.run_id)).await;
    let approval_branch = replay
        .branch_points
        .iter()
        .find(|branch| branch.branch_kind == "approval")
        .expect("expected approval branch");

    assert!(approval_branch.parent_point_id.is_some());
    assert!(approval_branch.rationale.contains("Approval branches"));
    assert!(!approval_branch.expected_evidence_refs.is_empty());
}
