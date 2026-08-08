use aiaf_v1::local_runtime::{
    V2ContractFoundationView, V2TransitionPacket, V2TransitionPacketExportRequest,
    serve_local_console,
};

use crate::local_runtime_support::{
    free_socket_addr, get_json, post_json, router, service, wait_for_http,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_v2_contract_foundation_gate_acceptance() {
    let service = service("v20-foundation-gate").await;
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
            title: Some("v20 contract foundation gate".to_string()),
            summary: None,
            next_v2_questions: Vec::new(),
        },
    )
    .await;

    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));

    let html = wait_for_http(address, "/console");
    assert!(html.contains("v2 Contracts"));
    assert!(html.contains("Contract Foundation Summary"));

    let foundation: V2ContractFoundationView =
        get_json(&router, "/api/v2/contracts/foundation").await;
    assert!(foundation.summary.contains("contract"));
    assert!(foundation.readiness_statement.contains("v2"));
    assert!(
        foundation
            .next_lines
            .iter()
            .any(|line| line.contains("v2.1"))
    );
    assert_eq!(foundation.map.entries.len(), 6);

    server.abort();
    let _ = server.await;
}
