use aiaf_v1::local_runtime::{
    V3AdoptedGenerationSuccessorProductionView, V3GenerationArtifact,
    V3GenerationArtifactExportRequest,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v3_adopted_generation_successor_production_acceptance() {
    let service = service("v30-successor").await;
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

    let _: V3GenerationArtifact = post_json(
        &router,
        "/api/v3/generation/artifact/export",
        &V3GenerationArtifactExportRequest {
            run_ids: vec![
                approval.summary.run_id.clone(),
                self_hosting.summary.run_id.clone(),
                second_cycle.summary.run_id.clone(),
            ],
            title: Some("v30 successor artifact".to_string()),
            summary: None,
            coexistence_mode: None,
            operator_constraints: Vec::new(),
        },
    )
    .await;

    let successor: V3AdoptedGenerationSuccessorProductionView =
        get_json(&router, "/api/v3/runtime/successor").await;
    assert!(successor.summary.contains("adopted generation"));
    assert!(successor.successor_run.is_some());
    assert!(
        successor
            .successor_run
            .as_ref()
            .unwrap()
            .produced_generation_ref
            .contains("generation:successor")
    );
    assert!(!successor.runtime_stage_story.is_empty());
    assert!(!successor.guardrails.is_empty());
}
