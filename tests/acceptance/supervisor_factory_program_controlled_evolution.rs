use aiaf_v1::execution::{FactoryProgramState, FactoryProgramTickReceipt, StopConditionDecision};
use aiaf_v1::local_runtime::{FactoryProgramLedgerView, FactoryProgramView};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use tower::util::ServiceExt;

use crate::local_runtime_support::{
    get_json, post_json, reloaded_service_from_existing_workspace, router, service,
};

#[tokio::test]
async fn supervisor_factory_program_controlled_evolution_acceptance() {
    let service = service("factory-program-controlled-evolution").await;
    let app = router(service.clone());

    let created: FactoryProgramView = post_json(
        &app,
        "/api/programs",
        &json!({
            "spec_id": "northstar-controlled-lineage",
            "title": "NorthStar Controlled Lineage",
            "root_factory_ref": "factory:root",
            "stable_interface_ref": "contract:rc-01",
            "goal_refs": ["goal:self-hosting-lineage"],
            "workload_refs": ["workload:factory-self-improvement"],
            "utility_metric_refs": ["metric:bounded-upgrade-readiness"],
            "mutation_scope_refs": ["scope:worker-routing-policy"],
            "promotion_gate_refs": ["gate:promotion:challenger-outperforms-incumbent"],
            "rollback_gate_refs": ["gate:rollback:restore-incumbent"],
            "recursion_budget": {
                "recursion_budget_id": "budget:northstar-controlled-lineage",
                "max_depth": 2,
                "max_campaigns": 3,
                "risk_threshold_refs": ["risk-threshold:bounded-recursion"],
                "exhaustion_policy": "stop"
            },
            "policy_ref": "policy:bounded-recursion"
        }),
    )
    .await;

    assert_eq!(
        created.instance.program_state,
        FactoryProgramState::Preparing
    );
    assert_eq!(created.instance.generation_depth, 0);
    assert_eq!(created.instance.campaign_count, 0);
    assert_eq!(
        created.instance.adopted_factory_refs,
        vec!["factory:root".to_string()]
    );
    assert!(created.receipts.is_empty());

    let instance_id = created.instance.instance_id.clone();

    let tick1: FactoryProgramTickReceipt = post_json(
        &app,
        &format!("/api/programs/{instance_id}/tick"),
        &json!({
            "candidate_factory_ref": "factory:g1",
            "proving_refs": ["proof:g1:validation"],
            "observation_refs": ["observation:g1:stability"],
            "comparison_refs": ["comparison:g1-vs-root"],
            "risk_refs": ["risk:g1:bounded"],
            "trend_refs": ["trend:g1:upward"],
            "rollback_refs": ["rollback:g1:ready"],
            "adoption_result": "adopted",
            "operator_note": "promote g1 under bounded observation"
        }),
    )
    .await;

    assert_eq!(tick1.resulting_factory_ref, "factory:g1");
    assert_eq!(tick1.generation_depth, 1);
    assert_eq!(tick1.campaign_count, 1);
    assert_eq!(
        tick1.stop_condition.decision,
        StopConditionDecision::Continue
    );

    let tick2: FactoryProgramTickReceipt = post_json(
        &app,
        &format!("/api/programs/{instance_id}/tick"),
        &json!({
            "candidate_factory_ref": "factory:g2-unsafe",
            "proving_refs": ["proof:g2-unsafe:validation"],
            "observation_refs": ["observation:g2-unsafe:regression"],
            "comparison_refs": ["comparison:g2-unsafe-vs-g1"],
            "risk_refs": ["risk:g2-unsafe:regression"],
            "trend_refs": ["trend:g2-unsafe:unstable"],
            "rollback_refs": ["rollback:g2-unsafe:engaged"],
            "adoption_result": "rolled_back",
            "operator_note": "reject the unsafe successor"
        }),
    )
    .await;

    assert_eq!(tick2.resulting_factory_ref, "factory:g1");
    assert_eq!(tick2.generation_depth, 1);
    assert_eq!(tick2.campaign_count, 2);
    assert_eq!(
        tick2.stop_condition.decision,
        StopConditionDecision::Constrain
    );

    let tick3: FactoryProgramTickReceipt = post_json(
        &app,
        &format!("/api/programs/{instance_id}/tick"),
        &json!({
            "candidate_factory_ref": "factory:g2",
            "proving_refs": ["proof:g2:validation"],
            "observation_refs": ["observation:g2:stability"],
            "comparison_refs": ["comparison:g2-vs-g1"],
            "risk_refs": ["risk:g2:bounded"],
            "trend_refs": ["trend:g2:upward"],
            "rollback_refs": ["rollback:g2:ready"],
            "adoption_result": "adopted",
            "operator_note": "close the bounded lineage at g2"
        }),
    )
    .await;

    assert_eq!(tick3.resulting_factory_ref, "factory:g2");
    assert_eq!(tick3.generation_depth, 2);
    assert_eq!(tick3.campaign_count, 3);
    assert_eq!(tick3.stop_condition.decision, StopConditionDecision::Stop);
    assert_eq!(tick3.recurring_program.cycle_refs.len(), 3);
    assert_eq!(tick3.recurring_program.continuity_window_refs.len(), 3);

    let program: FactoryProgramView = get_json(&app, &format!("/api/programs/{instance_id}")).await;
    assert_eq!(program.instance.current_factory_ref, "factory:g2");
    assert_eq!(program.instance.generation_depth, 2);
    assert_eq!(program.instance.campaign_count, 3);
    assert_eq!(
        program.instance.program_state,
        FactoryProgramState::Completed
    );
    assert_eq!(program.receipts.len(), 3);
    assert!(program.recurring_program.is_some());
    assert!(program.lineage_ledger.is_some());
    assert!(program.regression_packet.is_some());
    assert!(program.longitudinal_lineage_dossier.is_some());
    assert_eq!(
        program
            .longitudinal_lineage_dossier
            .as_ref()
            .unwrap()
            .cycle_refs
            .len(),
        3
    );

    let ledger: FactoryProgramLedgerView = get_json(&app, "/api/programs").await;
    assert_eq!(ledger.programs.len(), 1);
    assert_eq!(ledger.programs[0].instance.instance_id, instance_id);

    let exhausted = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/programs/{instance_id}/tick"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "candidate_factory_ref": "factory:g3",
                        "proving_refs": ["proof:g3:validation"],
                        "observation_refs": ["observation:g3:stability"],
                        "comparison_refs": ["comparison:g3-vs-g2"],
                        "risk_refs": ["risk:g3:bounded"],
                        "trend_refs": ["trend:g3:upward"],
                        "rollback_refs": ["rollback:g3:ready"],
                        "adoption_result": "adopted"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exhausted.status(), StatusCode::BAD_REQUEST);
    let exhausted_body = to_bytes(exhausted.into_body(), usize::MAX).await.unwrap();
    assert!(
        String::from_utf8_lossy(&exhausted_body).contains("terminal state"),
        "unexpected error body: {}",
        String::from_utf8_lossy(&exhausted_body)
    );

    let reloaded_service = reloaded_service_from_existing_workspace(
        &service,
        "factory-program-controlled-evolution-reloaded",
    )
    .await;
    let reloaded_router = router(reloaded_service);
    let reloaded: FactoryProgramView =
        get_json(&reloaded_router, &format!("/api/programs/{instance_id}")).await;

    assert_eq!(reloaded.instance, program.instance);
    assert_eq!(reloaded.recurring_program, program.recurring_program);
    assert_eq!(reloaded.lineage_ledger, program.lineage_ledger);
    assert_eq!(reloaded.regression_packet, program.regression_packet);
    assert_eq!(
        reloaded.longitudinal_lineage_dossier,
        program.longitudinal_lineage_dossier
    );
    assert_eq!(reloaded.receipts.len(), program.receipts.len());
}
