use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2RollbackSafetyEnvelopeView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_rollback_safety_envelope_closure_acceptance() {
    let service = service("v24-governance-rollback").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;

    let rollback: V2RollbackSafetyEnvelopeView =
        get_json(&router, "/api/v2/governance/rollback").await;

    assert!(rollback.summary.contains("rollback/safety"));
    assert!(!rollback.envelopes.is_empty());
    assert!(!rollback.envelopes[0].safety_requirements.is_empty());
    assert!(!rollback.rejection_paths.is_empty());
}
