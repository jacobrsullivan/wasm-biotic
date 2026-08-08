use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2IntegratedGenerationDossierView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_integrated_generation_dossier_acceptance() {
    let service = service("v25-generation-dossier").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-promote-activate-successor-campaign" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;

    let dossier: V2IntegratedGenerationDossierView =
        get_json(&router, "/api/v2/generation/dossier").await;

    assert!(dossier.summary.contains("operator-readable"));
    assert!(dossier.assembly_summary.contains("generation candidate"));
    assert!(!dossier.unresolved_edges.is_empty());
}
