use aiaf_v1::local_runtime::{
    V3GenerationArtifact, V3GenerationArtifactExportRequest, V3NativeServiceValidationClosureView,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v3_native_service_validation_closure_acceptance() {
    let service = service("v30-service-closure").await;
    let approval = service
        .run_headless("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    let self_hosting = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
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
            ],
            title: Some("v30 service closure artifact".to_string()),
            summary: None,
            coexistence_mode: None,
            operator_constraints: Vec::new(),
        },
    )
    .await;

    let closure: V3NativeServiceValidationClosureView =
        get_json(&router, "/api/v3/services/closure").await;
    let families = closure
        .service_maturity
        .iter()
        .map(|record| record.family.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(closure.summary.contains("self-production loop"));
    assert!(closure.closure_state.contains("explicit"));
    assert!(families.contains("build"));
    assert!(families.contains("validation"));
    assert!(families.contains("review"));
    assert!(families.contains("storage"));
    assert!(families.contains("approval"));
    assert!(families.contains("packaging"));
    assert!(!closure.validation_bundle.decision_summary.is_empty());
}
