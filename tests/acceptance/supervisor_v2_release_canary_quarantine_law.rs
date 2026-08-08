use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2ReleaseLawView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_release_canary_quarantine_law_acceptance() {
    let service = service("v24-governance-release").await;
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

    let release: V2ReleaseLawView = get_json(&router, "/api/v2/governance/release").await;

    assert!(release.summary.contains("release law"));
    assert!(
        release
            .stages
            .iter()
            .any(|stage| stage.stage_kind == "canary")
    );
    assert!(
        release
            .stages
            .iter()
            .any(|stage| stage.stage_kind == "quarantine")
    );
    assert!(!release.quarantine_rules.is_empty());
}
