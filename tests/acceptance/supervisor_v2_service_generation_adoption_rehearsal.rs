use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2ServiceGenerationAdoptionRehearsalView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_service_generation_adoption_rehearsal_acceptance() {
    let service = service("v26-adoption-rehearsal").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program" }),
    )
    .await;

    let rehearsal: V2ServiceGenerationAdoptionRehearsalView =
        get_json(&router, "/api/v2/service-generation/adoption").await;

    assert!(rehearsal.summary.contains("adoption rehearsal"));
    assert_eq!(rehearsal.steps.len(), 3);
    assert!(rehearsal.rollback_rule.contains("rollback"));
}
