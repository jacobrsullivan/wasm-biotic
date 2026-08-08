use aiaf_v1::local_runtime::{
    V2NextLineHandoffPacket, V2NextLineHandoffPacketExportRequest, V2TransitionPacket,
    V2TransitionPacketExportRequest,
};

use crate::local_runtime_support::{post_json, router, service};

#[tokio::test]
async fn supervisor_v2_next_line_handoff_packet_acceptance() {
    let service = service("v29-handoff").await;
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
            title: Some("v29 readiness packet".to_string()),
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
            title: Some("v29 next-line packet".to_string()),
            summary: None,
            next_line_focus: Vec::new(),
        },
    )
    .await;

    assert!(handoff.exported);
    assert_eq!(
        handoff.source_transition_packet_id.as_deref(),
        Some(transition.packet_id.as_str())
    );
    assert!(!handoff.unresolved_pressure_ids.is_empty());
    assert!(!handoff.scorecard_ids.is_empty());
    assert!(!handoff.next_line_focus.is_empty());
}
