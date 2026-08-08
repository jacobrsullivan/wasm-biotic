use serde_json::json;

use aiaf_v1::execution::{ClosureCriterionStatus, NorthStarClosureDecision};
use aiaf_v1::local_runtime::{
    LocalRunStatus, NorthStar07ClosureReviewView,
    RemediationPhase03ReproductionEcosystemClosureView, RunViewModel,
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
async fn supervisor_remediation_phase_03_operator_truth_acceptance() {
    let service = service("remediation-phase-03-operator-truth").await;
    let router = router(service.clone());
    seed_northstar_runtime(&service, &router).await;

    let factory_workspace: aiaf_v1::execution::RecurringFactoryWorkspacePacket =
        get_json(&router, "/api/remediation/phase-03/factory-workspace").await;
    let ecosystem_workspace: aiaf_v1::execution::EcosystemClosureWorkspacePacket =
        get_json(&router, "/api/remediation/phase-03/ecosystem-workspace").await;
    let closure_packet: aiaf_v1::execution::Phase03ClosureReviewPacket =
        get_json(&router, "/api/remediation/phase-03/closure-review-packet").await;
    let phase03: RemediationPhase03ReproductionEcosystemClosureView = get_json(
        &router,
        "/api/remediation/phase-03/reproduction-ecosystem-closure",
    )
    .await;
    let review: NorthStar07ClosureReviewView =
        get_json(&router, "/api/northstar/07/closure-review").await;

    assert_eq!(phase03.phase_status, "closure_grade");
    assert!(phase03.remaining_blockers.is_empty());
    assert!(!phase03.closure_grade_program_refs.is_empty());
    assert!(!phase03.closure_grade_ecosystem_refs.is_empty());
    assert_eq!(
        phase03.acceptable_caveat_refs,
        vec![
            "risk:phase03:recurring-program-publication-caveat".to_string(),
            "risk:phase03:bounded-ecosystem-publication-caveat".to_string(),
        ]
    );
    assert!(phase03.blocking_claim_risk_refs.is_empty());
    assert!(
        phase03
            .workstreams
            .iter()
            .all(|item| item.status == "closure_grade")
    );
    assert_eq!(
        factory_workspace.factory_workspace_id,
        "remediation-phase-03-factory-workspace"
    );
    assert_eq!(
        ecosystem_workspace.ecosystem_workspace_id,
        "remediation-phase-03-ecosystem-workspace"
    );
    assert_eq!(
        closure_packet.closure_review_packet_id,
        "remediation-phase-03-closure-review-packet"
    );
    assert!(!factory_workspace.continuity_refs.is_empty());
    assert!(!factory_workspace.stability_refs.is_empty());
    assert!(!ecosystem_workspace.continuity_refs.is_empty());
    assert!(!ecosystem_workspace.stability_refs.is_empty());
    assert!(
        closure_packet
            .factory_program_refs
            .contains(&factory_workspace.program_ref)
    );
    assert!(
        closure_packet
            .continuity_refs
            .iter()
            .all(|reference| factory_workspace.continuity_refs.contains(reference))
    );
    assert!(
        ecosystem_workspace
            .route_refs
            .iter()
            .all(|reference| closure_packet.ecosystem_refs.contains(reference))
    );
    assert!(
        ecosystem_workspace
            .health_refs
            .iter()
            .all(|reference| closure_packet.ecosystem_refs.contains(reference))
    );
    assert!(
        ecosystem_workspace
            .continuity_refs
            .iter()
            .all(|reference| closure_packet.ecosystem_refs.contains(reference))
    );
    assert!(
        ecosystem_workspace
            .stability_refs
            .iter()
            .all(|reference| closure_packet.ecosystem_refs.contains(reference))
    );
    assert!(
        closure_packet
            .acceptable_caveat_refs
            .contains(&"risk:phase03:recurring-program-publication-caveat".to_string())
    );
    assert!(
        closure_packet
            .acceptable_caveat_refs
            .contains(&"risk:phase03:bounded-ecosystem-publication-caveat".to_string())
    );
    assert!(closure_packet.blocking_risk_refs.is_empty());
    assert!(
        closure_packet
            .risk_refs
            .contains(&"risk:phase03:recurring-program-publication-caveat".to_string())
    );
    assert!(
        closure_packet
            .risk_refs
            .contains(&"risk:phase03:bounded-ecosystem-publication-caveat".to_string())
    );
    assert!(
        !closure_packet
            .risk_refs
            .contains(&"risk:phase03:bounded-ecosystem".to_string())
    );
    assert!(
        !closure_packet
            .risk_refs
            .contains(&"risk:phase03:final-claim-remains-not-yet".to_string())
    );

    assert!(review.criteria.iter().any(|criterion| {
        criterion.criterion_id == "northstar-07-criterion-factory-programs"
            && criterion.status == ClosureCriterionStatus::Passed
    }));
    assert!(review.criteria.iter().any(|criterion| {
        criterion.criterion_id == "northstar-07-criterion-ecosystem"
            && criterion.status == ClosureCriterionStatus::Passed
    }));
    assert!(review.criteria.iter().any(|criterion| {
        criterion.criterion_id == "northstar-07-criterion-final-claim"
            && !criterion
                .gap_refs
                .contains(&"risk:phase03:final-claim-remains-not-yet".to_string())
    }));
    assert_eq!(review.decision.decision, NorthStarClosureDecision::Closed);

    let phase_d_run = service
        .run_headless("supervisor-phase-d-live-prefederation-exchange-contracts")
        .await
        .unwrap();
    let export_root = service
        .export_run(&phase_d_run.summary.run_id)
        .await
        .unwrap();
    for path in [
        "snapshots/northstar-05-recurring-programs.json",
        "snapshots/northstar-05-continuity-windows.json",
        "snapshots/northstar-05-budget-histories.json",
        "snapshots/northstar-05-policy-compliance-records.json",
        "snapshots/northstar-05-cycle-dossiers.json",
        "snapshots/northstar-05-lineage-ledgers.json",
        "snapshots/northstar-05-regression-packets.json",
        "snapshots/northstar-05-longitudinal-lineage-dossiers.json",
        "snapshots/northstar-06-admission-profiles.json",
        "snapshots/northstar-06-route-history-records.json",
        "snapshots/northstar-06-route-ledgers.json",
        "snapshots/northstar-06-continuity-windows.json",
        "snapshots/northstar-06-rollback-symmetry-records.json",
        "snapshots/northstar-06-compatibility-persistence-records.json",
        "snapshots/northstar-06-health-ledgers.json",
        "snapshots/remediation-phase-03-factory-workspaces.json",
        "snapshots/remediation-phase-03-ecosystem-workspaces.json",
        "snapshots/remediation-phase-03-closure-review-packets.json",
    ] {
        assert!(export_root.join(path).exists(), "missing snapshot {path}");
    }
}
