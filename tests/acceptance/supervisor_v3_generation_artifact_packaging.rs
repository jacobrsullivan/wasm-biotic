use aiaf_v1::local_runtime::{
    V3GenerationArtifact, V3GenerationArtifactExportRequest, V3GenerationArtifactPackagingView,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v3_generation_artifact_packaging_acceptance() {
    let service = service("v30-generation-artifact").await;
    let approval = service
        .run_headless("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    let self_hosting = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
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
            ],
            title: Some("v30 generation artifact".to_string()),
            summary: None,
            coexistence_mode: None,
            operator_constraints: Vec::new(),
        },
    )
    .await;

    let view: V3GenerationArtifactPackagingView =
        get_json(&router, "/api/v3/generation/artifact").await;
    assert!(artifact.exported);
    assert_eq!(view.artifact.generation_id, artifact.generation_id);
    assert!(view.artifact.package_bundle.activation_ready);
    assert!(!view.artifact.validation_refs.is_empty());
    assert!(!view.artifact.lineage_refs.is_empty());
    assert!(!view.guardrails.is_empty());
}
