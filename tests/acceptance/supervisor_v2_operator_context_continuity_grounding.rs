use aiaf_v1::local_runtime::{
    OperatorContextPackage, OperatorContextPackageExportRequest, V2OperatorContextContinuityView,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_operator_context_continuity_grounding_acceptance() {
    let service = service("v22-context-grounding").await;
    let run = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();

    let router = router(service.clone());
    let package: OperatorContextPackage = post_json(
        &router,
        "/api/operator/context-packages/export",
        &OperatorContextPackageExportRequest {
            run_id: Some(run.summary.run_id.clone()),
            title: Some("v22 grounded context".to_string()),
            note: Some("Context package grounded in local run evidence.".to_string()),
        },
    )
    .await;

    let context: V2OperatorContextContinuityView =
        get_json(&router, "/api/v2/continuity/context").await;
    assert!(context.summary.contains("operator-context continuity"));
    assert!(
        context
            .grounded_packages
            .iter()
            .any(|item| item.package_id == package.package_id)
    );
    assert!(
        context
            .grounded_packages
            .iter()
            .any(|item| !item.evidence_refs.is_empty())
    );
}
