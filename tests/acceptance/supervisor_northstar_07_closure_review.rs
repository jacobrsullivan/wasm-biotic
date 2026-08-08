use aiaf_v1::execution::{
    ClosureCriterionStatus, ClosureEffect, DurableArtifactStore, NorthStarClosureDecision,
};
use aiaf_v1::local_runtime::{LocalRunStatus, NorthStar07ClosureReviewView, RunViewModel};

use crate::local_runtime_support::{get_json, post_empty, post_json, router, service};

async fn seed_northstar_01_06(
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
        &serde_json::json!({
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
        &serde_json::json!({
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
        &serde_json::json!({
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
async fn supervisor_northstar_07_closure_dossier_integrity_acceptance() {
    let service = service("northstar-07-closure-dossier").await;
    let router = router(service.clone());
    seed_northstar_01_06(&service, &router).await;
    let review: NorthStar07ClosureReviewView =
        get_json(&router, "/api/northstar/07/closure-review").await;

    assert!(review.summary.contains("NorthStar 07 closure review"));
    assert!(review.is_remediated_current_review);
    assert_eq!(
        review.criteria_matrix.status,
        ClosureCriterionStatus::Passed
    );
    assert!(!review.criteria.is_empty());
    assert!(!review.evidence_inventory.northstar_refs.is_empty());
    assert!(!review.evidence_inventory.operator_refs.is_empty());
    assert!(!review.evidence_inventory.phase_01_refs.is_empty());
    assert!(!review.evidence_inventory.phase_02_refs.is_empty());
    assert!(!review.evidence_inventory.phase_03_refs.is_empty());
    assert!(!review.evidence_inventory.phase_04_refs.is_empty());
    assert!(!review.residual_risks.is_empty());
    assert_eq!(
        review.closure_dossier.criteria_matrix_ref,
        review.criteria_matrix.criteria_matrix_id
    );
    assert_eq!(
        review.closure_dossier.inventory_ref,
        review.evidence_inventory.inventory_packet_id
    );
    assert_eq!(
        review.closure_dossier.adversarial_review_ref,
        review.adversarial_review.adversarial_review_id
    );
    assert_eq!(
        review.closure_dossier.claim_boundary_ref,
        review.claim_boundary.claim_review_id
    );
    assert_eq!(
        review.closure_dossier.recommendation_ref,
        review.decision.closure_decision_id
    );
    assert_eq!(
        review.decision.publication_policy_ref,
        review.publication_policy.publication_policy_id
    );
}

#[tokio::test]
async fn supervisor_northstar_07_claim_boundary_review_acceptance() {
    let service = service("northstar-07-claim-boundary").await;
    let router = router(service.clone());
    seed_northstar_01_06(&service, &router).await;
    let review: NorthStar07ClosureReviewView =
        get_json(&router, "/api/northstar/07/closure-review").await;

    assert!(!review.claim_boundary.allowed_claims.is_empty());
    assert!(!review.claim_boundary.forbidden_claims.is_empty());
    assert!(
        review
            .claim_boundary
            .allowed_claims
            .iter()
            .any(|claim| claim.contains("North Star has been reached"))
    );
    assert!(
        review
            .claim_boundary
            .allowed_claims
            .iter()
            .any(|claim| claim.contains("self-sustaining Wasm-Biotic world"))
    );
    assert!(
        review
            .claim_boundary
            .forbidden_claims
            .iter()
            .all(|claim| !claim.contains("North Star has been reached"))
    );
    assert!(
        review
            .claim_boundary
            .forbidden_claims
            .iter()
            .all(|claim| !claim.contains("self-sustaining Wasm-Biotic world"))
    );
    assert!(
        review
            .claim_boundary
            .allowed_claims
            .iter()
            .any(|claim| claim.contains("Closed."))
    );
    assert!(
        review
            .residual_risks
            .iter()
            .all(|risk| { risk.closure_effect != ClosureEffect::BlocksClosure })
    );
    assert!(
        review
            .residual_risks
            .iter()
            .all(|risk| { risk.closure_effect != ClosureEffect::Caveated })
    );
    assert!(review.publication_policy.required_caveats.is_empty());
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
    assert!(
        review
            .criteria
            .iter()
            .all(|criterion| { criterion.status != ClosureCriterionStatus::Failed })
    );
    assert!(
        review
            .criteria
            .iter()
            .all(|criterion| { criterion.status != ClosureCriterionStatus::Caveated })
    );
    assert!(review.residual_risks.iter().all(|risk| {
        !risk
            .supporting_refs
            .contains(&"risk:phase03:final-claim-remains-not-yet".to_string())
    }));
}

#[tokio::test]
async fn supervisor_northstar_07_final_decision_record_acceptance() {
    let service = service("northstar-07-final-decision").await;
    let router = router(service.clone());
    seed_northstar_01_06(&service, &router).await;
    let review: NorthStar07ClosureReviewView =
        get_json(&router, "/api/northstar/07/closure-review").await;

    assert_eq!(review.decision.decision, NorthStarClosureDecision::Closed);
    assert!(
        review
            .decision
            .rationale
            .contains("uncaveated current NorthStar closure")
    );
    assert!(!review.decision.required_followups.is_empty());
    assert_eq!(
        review.decision.supersedes_ref,
        "northstar-07-closure-decision"
    );
    assert_eq!(
        review.adversarial_review.recommendation_ref,
        review.decision.closure_decision_id
    );

    let phase04_store = DurableArtifactStore::bootstrap(
        service
            .workspace()
            .root()
            .join("remediation-phase-04-store"),
    )
    .unwrap();
    let precursor_store =
        DurableArtifactStore::bootstrap(service.workspace().root().join("northstar-07-store"))
            .unwrap();
    let matrix = phase04_store
        .load_closure_criteria_matrix(&review.criteria_matrix.criteria_matrix_id)
        .unwrap();
    let inventory = phase04_store
        .load_evidence_inventory_packet(&review.evidence_inventory.inventory_packet_id)
        .unwrap();
    let dossier = phase04_store
        .load_closure_dossier(&review.closure_dossier.closure_dossier_id)
        .unwrap();
    let claim_boundary = phase04_store
        .load_claim_boundary_review_packet(&review.claim_boundary.claim_review_id)
        .unwrap();
    let publication_policy = phase04_store
        .load_publication_policy_record(&review.publication_policy.publication_policy_id)
        .unwrap();
    let decision = phase04_store
        .load_closure_decision_record(&review.decision.closure_decision_id)
        .unwrap();
    let precursor_decision = precursor_store
        .load_closure_decision_record(&review.decision.supersedes_ref)
        .unwrap();

    assert_eq!(matrix.status, ClosureCriterionStatus::Passed);
    assert_eq!(
        inventory.inventory_packet_id,
        review.evidence_inventory.inventory_packet_id
    );
    assert_eq!(
        dossier.closure_dossier_id,
        review.closure_dossier.closure_dossier_id
    );
    assert_eq!(
        claim_boundary.claim_review_id,
        review.claim_boundary.claim_review_id
    );
    assert_eq!(
        publication_policy.publication_policy_id,
        review.publication_policy.publication_policy_id
    );
    assert_eq!(decision.decision, NorthStarClosureDecision::Closed);
    assert_eq!(
        precursor_decision.closure_decision_id,
        review.decision.supersedes_ref
    );
}
