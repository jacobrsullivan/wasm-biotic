use aiaf_v1::local_runtime::{
    V2FinalConvergenceNextLineReadinessView, V2NextLineHandoffPacketExportRequest,
    V2TransitionPacketExportRequest,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_final_convergence_next_line_readiness_acceptance() {
    let service = service("v29-closure").await;
    let self_hosting = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();
    let router = router(service.clone());

    let _: serde_json::Value = post_json(
        &router,
        "/api/transition/v2/export",
        &V2TransitionPacketExportRequest {
            run_ids: vec![self_hosting.summary.run_id.clone()],
            title: Some("v29 closure transition".to_string()),
            summary: None,
            next_v2_questions: Vec::new(),
        },
    )
    .await;
    let _: serde_json::Value = post_json(
        &router,
        "/api/v2/convergence/handoff/export",
        &V2NextLineHandoffPacketExportRequest {
            run_ids: vec![self_hosting.summary.run_id.clone()],
            title: Some("v29 closure handoff".to_string()),
            summary: None,
            next_line_focus: Vec::new(),
        },
    )
    .await;

    let closure: V2FinalConvergenceNextLineReadinessView =
        get_json(&router, "/api/v2/convergence/closure").await;
    assert!(closure.summary.contains("first v2 phase"));
    assert!(closure.handoff_summary.contains("handoff packet"));
    assert!(closure.next_line.contains("v3"));
    assert!(!closure.guardrails.is_empty());
}
