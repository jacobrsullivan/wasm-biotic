use serde_json::json;

use aiaf_v1::execution::NorthStarClosureDecision;
use aiaf_v1::local_runtime::{
    LocalRunStatus, NorthStar07ClosureReviewView, RemediationPhase04FinalClosureRereviewView,
    RunViewModel,
};

use crate::local_runtime_support::{get_json, post_empty, post_json, router, service};

async fn seed_northstar_runtime(
    service: &aiaf_v1::local_runtime::LocalRuntimeService,
    router: &axum::Router,
) -> String {
    for scenario_id in [
        "supervisor-v4-live-shell-runner-path",
        "supervisor-northstar-live-persistent-shell-program",
        "supervisor-phase-b-live-factory-artifact-family",
        "supervisor-phase-c-live-bounded-factory-replication",
    ] {
        let _ = service.run_headless(scenario_id).await.unwrap();
    }

    let phase_d_run = service
        .run_headless("supervisor-phase-d-live-prefederation-exchange-contracts")
        .await
        .unwrap();

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

    phase_d_run.summary.run_id
}

#[tokio::test]
async fn supervisor_remediation_phase_04_operator_truth_acceptance() {
    let service = service("remediation-phase-04-operator-truth").await;
    let router = router(service.clone());
    let export_run_id = seed_northstar_runtime(&service, &router).await;

    let phase04: RemediationPhase04FinalClosureRereviewView =
        get_json(&router, "/api/remediation/phase-04/final-closure-rereview").await;
    let criteria_matrix: aiaf_v1::execution::ClosureCriteriaMatrix =
        get_json(&router, "/api/remediation/phase-04/criteria-matrix").await;
    let evidence_inventory: aiaf_v1::execution::EvidenceInventoryPacket =
        get_json(&router, "/api/remediation/phase-04/evidence-inventory").await;
    let adversarial: aiaf_v1::execution::AdversarialReviewRecord =
        get_json(&router, "/api/remediation/phase-04/adversarial-review").await;
    let claim_boundary: aiaf_v1::execution::ClaimBoundaryReviewPacket =
        get_json(&router, "/api/remediation/phase-04/claim-boundary").await;
    let closure_dossier: aiaf_v1::execution::ClosureDossier =
        get_json(&router, "/api/remediation/phase-04/closure-dossier").await;
    let publication_policy: aiaf_v1::execution::PublicationPolicyRecord =
        get_json(&router, "/api/remediation/phase-04/publication-policy").await;
    let final_decision: aiaf_v1::execution::ClosureDecisionRecord =
        get_json(&router, "/api/remediation/phase-04/final-decision").await;
    let northstar07: NorthStar07ClosureReviewView =
        get_json(&router, "/api/northstar/07/closure-review").await;

    assert_eq!(phase04.phase_status, "closure_grade");
    assert_eq!(phase04.decision_posture, "Closed");
    assert!(phase04.remaining_blockers.is_empty());
    assert!(
        phase04
            .workstreams
            .iter()
            .all(|item| item.status == "closure_grade")
    );
    assert_eq!(
        phase04.criteria_matrix_refs,
        vec![criteria_matrix.criteria_matrix_id.clone()]
    );
    assert_eq!(
        phase04.evidence_inventory_refs,
        vec![evidence_inventory.inventory_packet_id.clone()]
    );
    assert_eq!(
        phase04.adversarial_review_refs,
        vec![adversarial.adversarial_review_id.clone()]
    );
    assert_eq!(
        phase04.claim_boundary_refs,
        vec![claim_boundary.claim_review_id.clone()]
    );
    assert_eq!(
        phase04.closure_dossier_refs,
        vec![closure_dossier.closure_dossier_id.clone()]
    );
    assert_eq!(
        phase04.publication_policy_refs,
        vec![publication_policy.publication_policy_id.clone()]
    );
    assert_eq!(
        phase04.final_decision_refs,
        vec![final_decision.closure_decision_id.clone()]
    );

    assert!(northstar07.is_remediated_current_review);
    assert_eq!(
        northstar07.decision.decision,
        NorthStarClosureDecision::Closed
    );
    assert_eq!(
        northstar07.decision.supersedes_ref,
        "northstar-07-closure-decision"
    );
    assert!(northstar07.criteria.iter().any(|criterion| {
        criterion.criterion_id == "northstar-07-criterion-final-claim"
            && !criterion
                .gap_refs
                .contains(&"risk:phase03:final-claim-remains-not-yet".to_string())
    }));
    assert!(northstar07.residual_risks.iter().all(|risk| {
        !risk
            .supporting_refs
            .contains(&"risk:phase03:final-claim-remains-not-yet".to_string())
    }));
    assert!(northstar07.criteria.iter().all(|criterion| {
        criterion.status != aiaf_v1::execution::ClosureCriterionStatus::Failed
    }));
    assert!(
        northstar07.residual_risks.iter().all(|risk| {
            risk.closure_effect != aiaf_v1::execution::ClosureEffect::BlocksClosure
        })
    );
    assert!(
        northstar07
            .residual_risks
            .iter()
            .all(|risk| { risk.closure_effect != aiaf_v1::execution::ClosureEffect::Caveated })
    );
    assert!(publication_policy.required_caveats.is_empty());

    let export_root = service.export_run(&export_run_id).await.unwrap();
    for path in [
        "snapshots/remediation-phase-04-criteria-matrices.json",
        "snapshots/remediation-phase-04-evidence-inventories.json",
        "snapshots/remediation-phase-04-adversarial-reviews.json",
        "snapshots/remediation-phase-04-claim-boundaries.json",
        "snapshots/remediation-phase-04-closure-dossiers.json",
        "snapshots/remediation-phase-04-publication-policies.json",
        "snapshots/remediation-phase-04-final-decisions.json",
    ] {
        assert!(export_root.join(path).exists(), "missing snapshot {path}");
    }
}
