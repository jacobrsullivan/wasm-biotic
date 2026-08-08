use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2GenerationAdoptionQuarantineRollbackView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_generation_adoption_quarantine_rollback_acceptance() {
    let service = service("v28-transition-rehearsal").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program" }),
    )
    .await;

    let transition: V2GenerationAdoptionQuarantineRollbackView =
        get_json(&router, "/api/v2/self-hosting/transition").await;

    assert!(
        transition
            .summary
            .contains("adoption, quarantine, and rollback")
    );
    assert!(transition.rollback_posture.contains("rollback"));
    assert!(!transition.guardrails.is_empty());
}
