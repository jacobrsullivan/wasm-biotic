use serde_json::json;

use aiaf_v1::local_runtime::{
    LocalRunStatus, RemediationPhase01LifecycleClosureView,
    RemediationPhase02ServiceEcologyClosureView,
    RemediationPhase03ReproductionEcosystemClosureView, RemediationPhase04FinalClosureRereviewView,
    RunViewModel,
};

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
async fn supervisor_remediation_phase_operator_views_acceptance() {
    let service = service("remediation-phase-operator-views").await;
    let router = router(service.clone());
    seed_northstar_runtime(&service, &router).await;

    let phase01: RemediationPhase01LifecycleClosureView =
        get_json(&router, "/api/remediation/phase-01/lifecycle-closure").await;
    assert!(phase01.summary.contains("Remediation Phase 01"));
    assert_eq!(phase01.phase_status, "closure_grade");
    assert_eq!(phase01.workstreams.len(), 4);
    assert!(
        phase01
            .shell_first_paths
            .iter()
            .any(|path| path == "supervisor-northstar-live-persistent-shell-program")
    );
    assert!(!phase01.reference_demo_paths.is_empty());
    assert!(phase01.remaining_blockers.is_empty());
    assert!(phase01.workstreams.iter().any(
        |item| item.workstream_id == "phase-01-workstream-c" && item.status == "closure_grade"
    ));

    let phase02: RemediationPhase02ServiceEcologyClosureView =
        get_json(&router, "/api/remediation/phase-02/service-ecology-closure").await;
    assert!(phase02.summary.contains("Remediation Phase 02"));
    assert_eq!(phase02.phase_status, "closure_grade");
    assert_eq!(phase02.workstreams.len(), 4);
    assert!(!phase02.service_manifest_refs.is_empty());
    assert!(!phase02.worker_card_refs.is_empty());
    assert!(!phase02.closure_grade_workflow_refs.is_empty());
    assert!(!phase02.service_workspace_refs.is_empty());
    assert!(!phase02.ecology_workspace_refs.is_empty());
    assert!(!phase02.acceptance_packet_refs.is_empty());
    assert!(phase02.remaining_blockers.is_empty());

    let phase03: RemediationPhase03ReproductionEcosystemClosureView = get_json(
        &router,
        "/api/remediation/phase-03/reproduction-ecosystem-closure",
    )
    .await;
    assert!(phase03.summary.contains("Remediation Phase 03"));
    assert_eq!(phase03.phase_status, "closure_grade");
    assert_eq!(phase03.workstreams.len(), 4);
    assert!(!phase03.factory_program_refs.is_empty());
    assert!(!phase03.ecosystem_route_refs.is_empty());
    assert!(!phase03.closure_grade_program_refs.is_empty());
    assert!(!phase03.closure_grade_ecosystem_refs.is_empty());
    assert!(!phase03.factory_workspace_refs.is_empty());
    assert!(!phase03.ecosystem_workspace_refs.is_empty());
    assert!(!phase03.closure_review_packet_refs.is_empty());
    assert!(phase03.remaining_blockers.is_empty());

    let phase04: RemediationPhase04FinalClosureRereviewView =
        get_json(&router, "/api/remediation/phase-04/final-closure-rereview").await;
    assert!(phase04.summary.contains("Remediation Phase 04"));
    assert_eq!(phase04.phase_status, "closure_grade");
    assert_eq!(phase04.workstreams.len(), 3);
    assert_eq!(phase04.decision_posture, "Closed");
    assert!(!phase04.criteria_refs.is_empty());
    assert!(!phase04.criteria_matrix_refs.is_empty());
    assert!(!phase04.evidence_inventory_refs.is_empty());
    assert!(!phase04.adversarial_review_refs.is_empty());
    assert!(!phase04.claim_boundary_refs.is_empty());
    assert!(!phase04.closure_dossier_refs.is_empty());
    assert!(!phase04.publication_policy_refs.is_empty());
    assert!(!phase04.final_decision_refs.is_empty());
    assert!(!phase04.forbidden_claims.is_empty());
    assert!(phase04.remaining_blockers.is_empty());
    assert!(
        phase04
            .workstreams
            .iter()
            .all(|item| item.status == "closure_grade")
    );
}
