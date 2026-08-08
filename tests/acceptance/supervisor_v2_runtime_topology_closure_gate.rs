use aiaf_v1::local_runtime::{V2RuntimeTopologyClosureView, serve_local_console};

use crate::local_runtime_support::{free_socket_addr, get_json, router, service, wait_for_http};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_v2_runtime_topology_closure_gate_acceptance() {
    let service = service("v23-closure-gate").await;
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let closure: V2RuntimeTopologyClosureView = get_json(&router, "/api/v2/topology/closure").await;
    assert!(closure.summary.contains("runtime topology"));
    assert!(closure.next_line.contains("v2.4"));
    assert!(!closure.guardrails.is_empty());

    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));
    let html = wait_for_http(address, "/console");
    assert!(html.contains("v2 Topology"));
    assert!(html.contains("Coordination Domains"));
    assert!(html.contains("Runtime-Coordination Closure"));
    server.abort();
    let _ = server.await;
}
