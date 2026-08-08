use aiaf_v1::local_runtime::{
    V2TransitionPacket, V2TransitionPacketExportRequest, V2TransitionWorkspaceView,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_transition_workspace_export_packet_acceptance() {
    let service = service("v2-transition-workspace").await;
    let self_hosting = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let packet: V2TransitionPacket = post_json(
        &router,
        "/api/transition/v2/export",
        &V2TransitionPacketExportRequest {
            run_ids: vec![self_hosting.summary.run_id.clone()],
            title: Some("v2 readiness packet".to_string()),
            summary: Some("Exported from the final v1 convergence cockpit.".to_string()),
            next_v2_questions: vec![
                "Which boundary should become explicit first in v2?".to_string(),
            ],
        },
    )
    .await;

    assert!(packet.exported);
    assert!(!packet.pressure_ids.is_empty());
    assert!(!packet.scorecard_ids.is_empty());

    let workspace: V2TransitionWorkspaceView = get_json(&router, "/api/transition/v2").await;
    assert_eq!(
        workspace
            .latest_packet
            .as_ref()
            .map(|item| item.packet_id.as_str()),
        Some(packet.packet_id.as_str())
    );
    assert!(!workspace.pending_questions.is_empty());
    assert!(workspace.final_v1_readiness.contains("v1"));
}
