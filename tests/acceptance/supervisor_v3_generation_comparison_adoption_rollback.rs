use aiaf_v1::local_runtime::{
    V3GenerationArtifact, V3GenerationArtifactExportRequest,
    V3GenerationComparisonAdoptionRollbackView,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v3_generation_comparison_adoption_rollback_acceptance() {
    let service = service("v30-adoption").await;
    let approval = service
        .run_headless("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    let self_hosting = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();
    let rollback = service
        .run_headless("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();
    let router = router(service.clone());

    let _: V3GenerationArtifact = post_json(
        &router,
        "/api/v3/generation/artifact/export",
        &V3GenerationArtifactExportRequest {
            run_ids: vec![
                approval.summary.run_id.clone(),
                self_hosting.summary.run_id.clone(),
                rollback.summary.run_id.clone(),
            ],
            title: Some("v30 adoption artifact".to_string()),
            summary: None,
            coexistence_mode: Some("bounded-adopt".to_string()),
            operator_constraints: Vec::new(),
        },
    )
    .await;

    let adoption: V3GenerationComparisonAdoptionRollbackView =
        get_json(&router, "/api/v3/adoption/decision").await;
    assert!(adoption.summary.contains("adopt"));
    assert!(adoption.decision.decision.contains("adopt"));
    assert!(!adoption.decision.rollback_refs.is_empty());
    assert!(!adoption.observation_window.findings.is_empty());
    assert!(!adoption.release_evidence.evidence_refs.is_empty());
    assert!(!adoption.guardrails.is_empty());
}
