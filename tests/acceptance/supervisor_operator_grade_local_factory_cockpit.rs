use aiaf_v1::local_runtime::serve_local_console;

use crate::local_runtime_support::{free_socket_addr, service, wait_for_http};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_operator_grade_local_factory_cockpit_acceptance() {
    let service = service("operator-cockpit").await;
    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));

    let html = wait_for_http(address, "/console");
    assert!(html.contains("AIAF v1.9 Final Convergence"));
    assert!(html.contains("System Overview"));
    assert!(html.contains("Scenario Studio"));
    assert!(html.contains("Programs"));
    assert!(html.contains("Convergence"));
    assert!(html.contains("Transition"));
    assert!(html.contains("Replay"));
    assert!(html.contains("Analytics"));
    assert!(html.contains("History"));
    assert!(html.contains("Portfolio"));
    assert!(html.contains("Evidence"));
    assert!(html.contains("Operator"));
    assert!(html.contains("Review"));
    assert!(html.contains("Factory"));
    assert!(html.contains("Agent"));
    assert!(html.contains("Run Evidence"));

    server.abort();
    let _ = server.await;
}
