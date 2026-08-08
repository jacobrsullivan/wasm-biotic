use aiaf_v1::local_runtime::serve_local_console;

use crate::local_runtime_support::{free_socket_addr, service, wait_for_http};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_scenario_studio_replay_analytics_workspace_acceptance() {
    let service = service("scenario-studio-workspace").await;
    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));

    let html = wait_for_http(address, "/console");
    assert!(html.contains("AIAF v1.9 Final Convergence"));
    assert!(html.contains("Scenario Studio"));
    assert!(html.contains("Programs"));
    assert!(html.contains("Convergence"));
    assert!(html.contains("Transition"));
    assert!(html.contains("Replay"));
    assert!(html.contains("Analytics"));
    assert!(html.contains("Context Packages"));
    assert!(html.contains("Review"));
    assert!(html.contains("Factory"));
    assert!(html.contains("Agent"));

    server.abort();
    let _ = server.await;
}
