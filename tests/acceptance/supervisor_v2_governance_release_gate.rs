use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2GovernanceReleaseClosureView, serve_local_console};

use crate::local_runtime_support::{
    free_socket_addr, get_json, post_empty, post_json, router, service, wait_for_http,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_v2_governance_release_gate_acceptance() {
    let service = service("v24-governance-closure").await;
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
        &json!({ "scenario_id": "supervisor-promote-activate-successor-campaign" }),
    )
    .await;
    let awaiting_approval: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program" }),
    )
    .await;
    let _: RunViewModel = post_empty(
        &router,
        &format!(
            "/api/runs/{}/approval/grant",
            awaiting_approval.summary.run_id
        ),
    )
    .await;

    let closure: V2GovernanceReleaseClosureView =
        get_json(&router, "/api/v2/governance/closure").await;
    assert!(closure.summary.contains("governance law"));
    assert!(closure.next_line.contains("v2.5"));
    assert!(!closure.guardrails.is_empty());

    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));
    let html = wait_for_http(address, "/console");
    assert!(html.contains("v2 Governance"));
    assert!(html.contains("Governance Protocol Summary"));
    assert!(html.contains("Governance-Release Closure"));
    server.abort();
    let _ = server.await;
}
