use aiaf_v1::execution::{ClosureEffect, NorthStarClosureDecision};
use aiaf_v1::local_runtime::NorthStar07ClosureReviewView;

use crate::local_runtime_support::{
    get_json, reloaded_service_from_existing_workspace, router, seed_positive_closure_corpus,
    service,
};

#[tokio::test]
async fn supervisor_remediation_phase_04_positive_closure_with_caveats_acceptance() {
    let service = service("remediation-phase-04-positive-closure-with-caveats").await;
    let app = router(service.clone());
    let seeded = seed_positive_closure_corpus(&service, &app).await;

    let review: NorthStar07ClosureReviewView =
        get_json(&app, "/api/northstar/07/closure-review").await;

    assert_eq!(review.decision.decision, NorthStarClosureDecision::Closed);
    assert!(review.publication_policy.required_caveats.is_empty());
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
    assert!(
        review
            .claim_boundary
            .allowed_claims
            .iter()
            .any(|claim| { claim.contains("self-sustaining Wasm-Biotic world") })
    );

    let _ = service.export_run(&seeded.phase_d_run_id).await.unwrap();
    let reloaded_service = reloaded_service_from_existing_workspace(
        &service,
        "remediation-phase-04-positive-closure-with-caveats-reloaded",
    )
    .await;
    let reloaded_router = router(reloaded_service);
    let reloaded_review: NorthStar07ClosureReviewView =
        get_json(&reloaded_router, "/api/northstar/07/closure-review").await;

    assert_eq!(
        reloaded_review.decision.decision,
        NorthStarClosureDecision::Closed
    );
    assert_eq!(
        reloaded_review.publication_policy.required_caveats,
        review.publication_policy.required_caveats
    );
    assert_eq!(
        reloaded_review.claim_boundary.forbidden_claims,
        review.claim_boundary.forbidden_claims
    );
    assert!(
        reloaded_review
            .residual_risks
            .iter()
            .all(|risk| { risk.closure_effect != ClosureEffect::BlocksClosure })
    );
    assert!(
        reloaded_review
            .residual_risks
            .iter()
            .all(|risk| { risk.closure_effect != ClosureEffect::Caveated })
    );
}
