use serde_json::json;

use aiaf_v1::local_runtime::{
    RunViewModel, V2BoundedFactoryOperationsGateView, serve_local_console,
};

use crate::local_runtime_support::{
    free_socket_addr, get_json, post_json, router, service, wait_for_http,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_v2_bounded_factory_operations_gate_acceptance() {
    let service = service("v27-operations-closure").await;
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
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;

    let closure: V2BoundedFactoryOperationsGateView =
        get_json(&router, "/api/v2/operations/closure").await;
    assert!(closure.summary.contains("bounded factory"));
    assert!(closure.next_line.contains("v2.8"));
    assert!(!closure.guardrails.is_empty());

    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));
    let html = wait_for_http(address, "/console");
    assert!(html.contains("v2 Operations"));
    assert!(html.contains("Bounded Operations Summary"));
    assert!(html.contains("Bounded Operations Closure"));
    server.abort();
    let _ = server.await;
}
