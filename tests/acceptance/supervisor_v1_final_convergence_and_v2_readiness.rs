use aiaf_v1::local_runtime::{
    V2TransitionPacket, V2TransitionPacketExportRequest, V2TransitionWorkspaceView,
    serve_local_console,
};

use crate::local_runtime_support::{
    free_socket_addr, get_json, post_json, router, service, wait_for_http,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_v1_final_convergence_and_v2_readiness_acceptance() {
    let service = service("v1-final-convergence").await;
    let self_hosting = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();

    let router = router(service.clone());
    let _: V2TransitionPacket = post_json(
        &router,
        "/api/transition/v2/export",
        &V2TransitionPacketExportRequest {
            run_ids: vec![self_hosting.summary.run_id.clone()],
            title: Some("final v1 readiness".to_string()),
            summary: None,
            next_v2_questions: Vec::new(),
        },
    )
    .await;

    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));

    let html = wait_for_http(address, "/console");
    assert!(html.contains("AIAF v1.9 Final Convergence"));
    assert!(html.contains("Convergence"));
    assert!(html.contains("Transition"));
    assert!(html.contains("Release Train"));
    assert!(html.contains("Contract Pressure"));
    assert!(html.contains("Latest v2 Transition Packet"));

    let workspace: V2TransitionWorkspaceView = get_json(&router, "/api/transition/v2").await;
    assert!(workspace.final_v1_readiness.contains("v1"));
    assert!(workspace.final_v1_readiness.contains("v2"));

    server.abort();
    let _ = server.await;
}
