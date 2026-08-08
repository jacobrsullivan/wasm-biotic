use aiaf_v1::local_runtime::{
    V2ConvergenceTransitionWorkspaceView, V2NextLineHandoffPacket,
    V2NextLineHandoffPacketExportRequest, V2TransitionPacket, V2TransitionPacketExportRequest,
    serve_local_console,
};

use crate::local_runtime_support::{
    free_socket_addr, get_json, post_json, router, service, wait_for_http,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_v2_convergence_transition_workspace_acceptance() {
    let service = service("v29-workspace").await;
    let self_hosting = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();
    let router = router(service.clone());

    let transition: V2TransitionPacket = post_json(
        &router,
        "/api/transition/v2/export",
        &V2TransitionPacketExportRequest {
            run_ids: vec![self_hosting.summary.run_id.clone()],
            title: Some("v29 workspace transition".to_string()),
            summary: None,
            next_v2_questions: Vec::new(),
        },
    )
    .await;
    let handoff: V2NextLineHandoffPacket = post_json(
        &router,
        "/api/v2/convergence/handoff/export",
        &V2NextLineHandoffPacketExportRequest {
            run_ids: vec![self_hosting.summary.run_id.clone()],
            title: Some("v29 workspace handoff".to_string()),
            summary: None,
            next_line_focus: Vec::new(),
        },
    )
    .await;

    let workspace: V2ConvergenceTransitionWorkspaceView =
        get_json(&router, "/api/v2/convergence/workspace").await;
    assert_eq!(
        workspace
            .latest_handoff_packet
            .as_ref()
            .map(|item| item.packet_id.as_str()),
        Some(handoff.packet_id.as_str())
    );
    assert_eq!(
        workspace.transition_anchor.as_deref(),
        Some(transition.packet_id.as_str())
    );
    assert!(!workspace.workspace_checks.is_empty());
    assert!(!workspace.guardrails.is_empty());

    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));
    let html = wait_for_http(address, "/console");
    assert!(html.contains("v2 Convergence"));
    assert!(html.contains("Next-Line Handoff Packet"));
    assert!(html.contains("Next-Line Readiness Gate"));
    server.abort();
    let _ = server.await;
}
