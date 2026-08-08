use serde_json::json;

use aiaf_v1::local_runtime::{
    RunViewModel, V2NativeServiceGenerationAdoptionGateView, serve_local_console,
};

use crate::local_runtime_support::{
    free_socket_addr, get_json, post_json, router, service, wait_for_http,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_v2_native_service_generation_adoption_gate_acceptance() {
    let service = service("v26-service-closure").await;
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

    let closure: V2NativeServiceGenerationAdoptionGateView =
        get_json(&router, "/api/v2/service-generation/closure").await;
    assert!(closure.summary.contains("service-generation maturity"));
    assert!(closure.next_line.contains("v2.7"));
    assert!(!closure.guardrails.is_empty());

    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));
    let html = wait_for_http(address, "/console");
    assert!(html.contains("v2 Service Generation"));
    assert!(html.contains("Service Generation Summary"));
    assert!(html.contains("Service Generation Closure"));
    server.abort();
    let _ = server.await;
}
