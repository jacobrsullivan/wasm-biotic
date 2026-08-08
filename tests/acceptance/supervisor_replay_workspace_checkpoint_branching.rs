use aiaf_v1::local_runtime::ReplayWorkspaceView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_replay_workspace_checkpoint_branching_acceptance() {
    let service = service("replay-workspace").await;
    let run = service
        .start_run("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();

    let router = router(service.clone());
    let replay: ReplayWorkspaceView =
        get_json(&router, &format!("/api/runs/{}/replay", run.summary.run_id)).await;

    assert!(replay.replay_summary.contains("checkpoint"));
    assert!(
        replay
            .replay_points
            .iter()
            .any(|point| point.kind == "checkpoint")
    );
    assert!(
        replay
            .replay_points
            .iter()
            .any(|point| point.kind == "approval")
    );
    assert!(
        replay
            .branch_points
            .iter()
            .any(|branch| branch.title.contains("Approval"))
    );
    assert!(!replay.guardrails.is_empty());
}
