use aiaf_v1::local_runtime::{ReplayWorkspaceView, RunViewModel};
use serde_json::json;

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_replay_branch_hypothesis_lineage_acceptance() {
    let service = service("replay-hypothesis").await;
    let router = router(service.clone());

    let run: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-approval-resume-worker-complete",
            "composition_id": "composition-factory-approval-baseline",
            "run_set_id": "runset-factory-governed-upgrade",
            "hypothesis_id": "hypothesis-factory-approval-branch"
        }),
    )
    .await;

    let replay: ReplayWorkspaceView =
        get_json(&router, &format!("/api/runs/{}/replay", run.summary.run_id)).await;

    assert!(!replay.hypotheses.is_empty());
    assert!(
        replay
            .hypotheses
            .iter()
            .any(|hypothesis| hypothesis.hypothesis_id == "hypothesis-factory-approval-branch")
    );
    assert!(replay.branch_points.iter().any(
        |branch| branch.hypothesis_id.as_deref() == Some("hypothesis-factory-approval-branch")
    ));
}
