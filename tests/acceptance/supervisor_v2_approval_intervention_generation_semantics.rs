use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2ApprovalInterventionSemanticView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_approval_intervention_generation_semantics_acceptance() {
    let service = service("v24-governance-semantics").await;
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
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program" }),
    )
    .await;

    let semantics: V2ApprovalInterventionSemanticView =
        get_json(&router, "/api/v2/governance/semantics").await;

    assert!(
        semantics
            .summary
            .contains("grant, deny, hold, resume, and intervene")
    );
    assert_eq!(semantics.semantics.len(), 5);
    assert!(
        semantics
            .semantics
            .iter()
            .any(|entry| entry.action == "hold" && entry.current_signal.contains("paused"))
    );
    assert!(
        semantics
            .semantics
            .iter()
            .any(|entry| entry.action == "intervene")
    );
}
