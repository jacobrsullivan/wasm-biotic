use aiaf_v1::local_runtime::{
    OperatorContextPackage, OperatorContextPackageExportRequest, OperatorContextPackageView,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_operator_context_package_export_import_acceptance() {
    let service = service("context-packages").await;
    let run = service
        .run_headless("supervisor-durable-fixed-interface-self-hosting-loop")
        .await
        .unwrap();

    let router = router(service.clone());
    let exported: OperatorContextPackage = post_json(
        &router,
        "/api/operator/context-packages/export",
        &OperatorContextPackageExportRequest {
            run_id: Some(run.summary.run_id.clone()),
            title: Some("Self-hosting review package".to_string()),
            note: Some("Carry forward replay and comparison context.".to_string()),
        },
    )
    .await;

    assert_eq!(
        exported.source_run_id.as_deref(),
        Some(run.summary.run_id.as_str())
    );
    let mut imported = exported.clone();
    imported.package_id = "context-package:imported:acceptance".to_string();
    imported.title = "Imported rehearsal package".to_string();

    let imported_response: OperatorContextPackage =
        post_json(&router, "/api/operator/context-packages/import", &imported).await;
    assert!(imported_response.imported);

    let packages: OperatorContextPackageView =
        get_json(&router, "/api/operator/context-packages").await;
    assert!(packages.summary.contains("package"));
    assert!(packages.packages.len() >= 2);
    assert!(packages.packages.iter().any(|package| package.imported));
}
