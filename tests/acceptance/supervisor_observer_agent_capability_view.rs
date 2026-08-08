use aiaf_v1::local_runtime::AgentView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_observer_agent_capability_view_acceptance() {
    let service = service("observer-agent-view").await;
    let run = service
        .start_run("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    let router = router(service.clone());

    let agents: AgentView =
        get_json(&router, &format!("/api/runs/{}/agents", run.summary.run_id)).await;

    assert_eq!(agents.run_id, run.summary.run_id);
    assert_eq!(agents.pending_approval_count, 1);
    assert!(agents.blocked_agent_count >= 1);
    assert_eq!(agents.supervisor.role_kind, "Supervisor");
    assert!(
        agents
            .supervisor
            .capability_summary
            .iter()
            .any(|entry| entry.contains("governed session control"))
    );
    assert!(agents.supervisor.approval_state.contains("1 approval"));
    assert!(!agents.workers.is_empty());
    assert_eq!(agents.workers[0].role_kind, "Worker");
    assert!(
        agents.workers[0]
            .capability_summary
            .iter()
            .any(|entry| entry.contains("ownership:"))
    );
    assert!(
        agents.workers[0]
            .approval_state
            .contains("pending approval")
    );
}
