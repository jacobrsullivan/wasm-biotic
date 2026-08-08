use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2NativeSufficiencyServiceGateView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_native_sufficiency_service_gate_acceptance() {
    let service = service("v26-sufficiency-gate").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-approval-resume-worker-complete" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-promote-activate-successor-campaign" }),
    )
    .await;

    let gate: V2NativeSufficiencyServiceGateView =
        get_json(&router, "/api/v2/service-generation/sufficiency").await;

    assert!(gate.summary.contains("native-sufficiency gate"));
    assert_eq!(gate.criteria.len(), 4);
    assert!(!gate.guardrails.is_empty());
}
