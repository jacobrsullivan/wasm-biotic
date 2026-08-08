use aiaf_v1::local_runtime::{RunViewModel, ScenarioStudioView};
use serde_json::json;

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_scenario_studio_catalog_governance_acceptance() {
    let service = service("scenario-studio").await;
    let router = router(service.clone());

    let studio: ScenarioStudioView = get_json(&router, "/api/studio/scenarios").await;
    assert!(studio.registry_summary.contains("governed scenarios"));
    assert!(!studio.templates.is_empty());
    assert!(!studio.rehearsal_packs.is_empty());
    assert!(
        studio
            .governance_rules
            .iter()
            .any(|rule| rule.contains("approval") || rule.contains("evidence"))
    );

    let run: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-promote-activate-successor-campaign",
            "template_id": "template-factory-promotion-lane",
            "pack_id": "pack-factory-governance-basics",
            "operator_goal": "Rehearse a bounded factory promotion path"
        }),
    )
    .await;
    assert_eq!(
        run.summary.scenario_id,
        "supervisor-promote-activate-successor-campaign"
    );
}
