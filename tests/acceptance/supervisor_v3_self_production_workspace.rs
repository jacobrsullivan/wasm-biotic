use aiaf_v1::local_runtime::{
    V3GenerationArtifact, V3GenerationArtifactExportRequest, V3SelfProductionEvidencePacket,
    V3SelfProductionEvidencePacketExportRequest, V3SelfProductionWorkspaceView,
    serve_local_console,
};

use crate::local_runtime_support::{
    free_socket_addr, get_json, post_json, router, service, wait_for_http,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_v3_self_production_workspace_acceptance() {
    let service = service("v30-workspace").await;
    let approval = service
        .run_headless("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    let self_hosting = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();
    let second_cycle = service
        .run_headless("supervisor-second-cycle-v1-completion")
        .await
        .unwrap();
    let router = router(service.clone());

    let artifact: V3GenerationArtifact = post_json(
        &router,
        "/api/v3/generation/artifact/export",
        &V3GenerationArtifactExportRequest {
            run_ids: vec![
                approval.summary.run_id.clone(),
                self_hosting.summary.run_id.clone(),
                second_cycle.summary.run_id.clone(),
            ],
            title: Some("v30 workspace artifact".to_string()),
            summary: None,
            coexistence_mode: None,
            operator_constraints: Vec::new(),
        },
    )
    .await;
    let packet: V3SelfProductionEvidencePacket = post_json(
        &router,
        "/api/v3/workspace/evidence/export",
        &V3SelfProductionEvidencePacketExportRequest {
            run_ids: vec![
                approval.summary.run_id.clone(),
                self_hosting.summary.run_id.clone(),
                second_cycle.summary.run_id.clone(),
            ],
            title: Some("v30 workspace packet".to_string()),
            summary: None,
            claim_boundary: None,
        },
    )
    .await;

    let workspace: V3SelfProductionWorkspaceView = get_json(&router, "/api/v3/workspace").await;
    assert_eq!(workspace.artifact_ref, artifact.generation_id);
    assert_eq!(
        workspace
            .latest_evidence_packet
            .as_ref()
            .map(|item| item.packet_id.as_str()),
        Some(packet.packet_id.as_str())
    );
    assert!(!workspace.milestone_checks.is_empty());

    let address = free_socket_addr();
    let server = tokio::spawn(serve_local_console(service.clone(), address));
    let html = wait_for_http(address, "/console");
    assert!(html.contains("v3 Self-Production"));
    assert!(html.contains("Generation Artifact"));
    assert!(html.contains("Self-Production Evidence Packet"));
    server.abort();
    let _ = server.await;
}
