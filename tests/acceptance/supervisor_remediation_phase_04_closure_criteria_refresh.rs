use serde_json::json;

use aiaf_v1::local_runtime::{LocalRunStatus, RunViewModel};

use crate::local_runtime_support::{get_json, post_empty, post_json, router, service};

async fn seed_northstar_runtime(
    service: &aiaf_v1::local_runtime::LocalRuntimeService,
    router: &axum::Router,
) {
    for scenario_id in [
        "supervisor-v4-live-shell-runner-path",
        "supervisor-northstar-live-persistent-shell-program",
        "supervisor-phase-b-live-factory-artifact-family",
        "supervisor-phase-c-live-bounded-factory-replication",
        "supervisor-phase-d-live-prefederation-exchange-contracts",
    ] {
        let _ = service.run_headless(scenario_id).await.unwrap();
    }

    let expired: RunViewModel = post_json(
        router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program"
        }),
    )
    .await;
    assert_eq!(expired.summary.status, LocalRunStatus::AwaitingApproval);
    let expired: RunViewModel = post_empty(
        router,
        &format!("/api/runs/{}/approval/expire", expired.summary.run_id),
    )
    .await;
    assert_eq!(expired.summary.status, LocalRunStatus::Failed);

    let escalated: RunViewModel = post_json(
        router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program"
        }),
    )
    .await;
    assert_eq!(escalated.summary.status, LocalRunStatus::AwaitingApproval);
    let escalated: RunViewModel = post_empty(
        router,
        &format!("/api/runs/{}/approval/escalate", escalated.summary.run_id),
    )
    .await;
    assert_eq!(escalated.summary.status, LocalRunStatus::Paused);

    let rollback_ready: RunViewModel = post_json(
        router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-background-quarantine-rollback-control-loop"
        }),
    )
    .await;
    assert_eq!(
        rollback_ready.summary.status,
        LocalRunStatus::AwaitingRollback
    );
}

#[tokio::test]
async fn supervisor_remediation_phase_04_closure_criteria_refresh_acceptance() {
    let service = service("remediation-phase-04-criteria-refresh").await;
    let router = router(service.clone());
    seed_northstar_runtime(&service, &router).await;

    let matrix: aiaf_v1::execution::ClosureCriteriaMatrix =
        get_json(&router, "/api/remediation/phase-04/criteria-matrix").await;
    let inventory: aiaf_v1::execution::EvidenceInventoryPacket =
        get_json(&router, "/api/remediation/phase-04/evidence-inventory").await;

    assert_eq!(
        matrix.criteria_matrix_id,
        "remediation-phase-04-criteria-matrix"
    );
    assert_eq!(matrix.review_status, "remediated_current_review");
    assert!(!matrix.criterion_refs.is_empty());
    assert!(!matrix.phase_evidence_refs.is_empty());
    assert!(!matrix.delta_crosswalk_refs.is_empty());

    assert_eq!(
        inventory.inventory_packet_id,
        "remediation-phase-04-evidence-inventory"
    );
    assert!(!inventory.phase_01_refs.is_empty());
    assert!(!inventory.phase_02_refs.is_empty());
    assert!(!inventory.phase_03_refs.is_empty());
    assert!(!inventory.phase_04_refs.is_empty());
    assert!(
        inventory
            .phase_04_refs
            .iter()
            .any(|reference| reference == "remediation-phase-04-final-decision")
    );
}
