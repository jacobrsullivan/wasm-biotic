use aiaf_v1::local_runtime::{RunSummary, serve_local_console};

use crate::local_runtime_support::{free_socket_addr, get_json, router, service, wait_for_http};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_observer_console_run_summary_acceptance() {
    let service = service("observer-console").await;
    let run = service
        .start_run("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();

    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));
    let html = wait_for_http(address, "/console");
    assert!(html.contains("AIAF v1.9 Final Convergence"));
    assert!(html.contains("Scenario Studio"));
    assert!(html.contains("Convergence"));
    assert!(html.contains("Transition"));
    assert!(html.contains("Replay"));
    assert!(html.contains("Analytics"));
    assert!(html.contains("History"));
    assert!(html.contains("Portfolio"));
    assert!(html.contains("Operator"));
    assert!(html.contains("Run Evidence"));
    assert!(html.contains("Factory"));
    assert!(html.contains("Agent"));

    let router = router(service.clone());
    let summary: RunSummary = get_json(
        &router,
        &format!("/api/runs/{}/summary", run.summary.run_id),
    )
    .await;
    assert_eq!(summary.run_id, run.summary.run_id);
    assert_eq!(
        summary.status,
        aiaf_v1::local_runtime::LocalRunStatus::Completed
    );

    server.abort();
    let _ = server.await;
}
