use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2SelfHostingTransitionGateView, serve_local_console};

use crate::local_runtime_support::{
    free_socket_addr, get_json, post_json, router, service, wait_for_http,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_v2_self_hosting_transition_gate_acceptance() {
    let service = service("v28-closure").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-approval-resume-worker-complete" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program" }),
    )
    .await;

    let closure: V2SelfHostingTransitionGateView =
        get_json(&router, "/api/v2/self-hosting/closure").await;
    assert!(
        closure
            .summary
            .contains("distinct v2 self-hosting milestone")
    );
    assert!(closure.next_line.contains("v2.9"));
    assert!(!closure.guardrails.is_empty());

    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));
    let html = wait_for_http(address, "/console");
    assert!(html.contains("v2 Self-Hosting"));
    assert!(html.contains("Self-Hosting Transition Summary"));
    assert!(html.contains("Self-Hosting Transition Gate"));
    server.abort();
    let _ = server.await;
}
