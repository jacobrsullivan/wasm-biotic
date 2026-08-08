use aiaf_v1::execution::{
    ClaimBoundaryReviewPacket, ClosureCriterionStatus, ClosureDecisionRecord, ClosureEffect,
    NorthStarClosureDecision, Phase03ClosureReviewPacket, PublicationPolicyRecord,
};
use aiaf_v1::local_runtime::NorthStar07ClosureReviewView;

use crate::local_runtime_support::{
    fetch_positive_closure_truth, read_snapshot_json, reloaded_service_from_existing_workspace,
    router, seed_positive_closure_corpus, service,
};

fn criterion_statuses(
    review: &NorthStar07ClosureReviewView,
) -> Vec<(String, ClosureCriterionStatus)> {
    review
        .criteria
        .iter()
        .map(|criterion| (criterion.criterion_id.clone(), criterion.status))
        .collect()
}

fn residual_risk_effects(review: &NorthStar07ClosureReviewView) -> Vec<(String, ClosureEffect)> {
    review
        .residual_risks
        .iter()
        .map(|risk| (risk.risk_record_id.clone(), risk.closure_effect))
        .collect()
}

#[tokio::test]
async fn supervisor_remediation_positive_closure_snapshot_truth_acceptance() {
    let service = service("remediation-positive-closure-snapshot-truth").await;
    let app = router(service.clone());
    let seeded = seed_positive_closure_corpus(&service, &app).await;

    let live = fetch_positive_closure_truth(&app).await;

    assert_eq!(live.phase03.phase_status, "closure_grade");
    assert_eq!(live.phase04.phase_status, "closure_grade");
    assert_eq!(
        live.northstar07.decision.decision,
        NorthStarClosureDecision::Closed
    );
    assert!(
        live.northstar07
            .criteria
            .iter()
            .all(|criterion| criterion.status != ClosureCriterionStatus::Failed)
    );
    assert!(
        live.northstar07
            .residual_risks
            .iter()
            .all(|risk| risk.closure_effect != ClosureEffect::BlocksClosure)
    );
    assert!(
        live.northstar07
            .residual_risks
            .iter()
            .all(|risk| risk.closure_effect != ClosureEffect::Caveated)
    );

    let export_root = service.export_run(&seeded.phase_d_run_id).await.unwrap();
    let exported_phase03_packets: Vec<Phase03ClosureReviewPacket> = read_snapshot_json(
        &export_root,
        "snapshots/remediation-phase-03-closure-review-packets.json",
    );
    let exported_phase03_packet = exported_phase03_packets
        .into_iter()
        .find(|packet| {
            packet.closure_review_packet_id == live.phase03_packet.closure_review_packet_id
        })
        .unwrap();
    assert_eq!(
        exported_phase03_packet.acceptable_caveat_refs,
        live.phase03_packet.acceptable_caveat_refs
    );
    assert_eq!(
        exported_phase03_packet.blocking_risk_refs,
        live.phase03_packet.blocking_risk_refs
    );
    assert_eq!(
        exported_phase03_packet.risk_refs,
        live.phase03_packet.risk_refs
    );

    let exported_claim_boundaries: Vec<ClaimBoundaryReviewPacket> = read_snapshot_json(
        &export_root,
        "snapshots/remediation-phase-04-claim-boundaries.json",
    );
    let exported_claim_boundary = exported_claim_boundaries
        .into_iter()
        .find(|packet| packet.claim_review_id == live.northstar07.claim_boundary.claim_review_id)
        .unwrap();
    assert_eq!(
        exported_claim_boundary.allowed_claims,
        live.northstar07.claim_boundary.allowed_claims
    );
    assert_eq!(
        exported_claim_boundary.forbidden_claims,
        live.northstar07.claim_boundary.forbidden_claims
    );

    let exported_publication_policies: Vec<PublicationPolicyRecord> = read_snapshot_json(
        &export_root,
        "snapshots/remediation-phase-04-publication-policies.json",
    );
    let exported_publication_policy = exported_publication_policies
        .into_iter()
        .find(|policy| {
            policy.publication_policy_id
                == live.northstar07.publication_policy.publication_policy_id
        })
        .unwrap();
    assert_eq!(
        exported_publication_policy.required_caveats,
        live.northstar07.publication_policy.required_caveats
    );
    assert_eq!(
        exported_publication_policy.forbidden_claims,
        live.northstar07.publication_policy.forbidden_claims
    );

    let exported_final_decisions: Vec<ClosureDecisionRecord> = read_snapshot_json(
        &export_root,
        "snapshots/remediation-phase-04-final-decisions.json",
    );
    let exported_final_decision = exported_final_decisions
        .into_iter()
        .find(|decision| {
            decision.closure_decision_id == live.northstar07.decision.closure_decision_id
        })
        .unwrap();
    assert_eq!(
        exported_final_decision.decision,
        live.northstar07.decision.decision
    );
    assert_eq!(
        exported_final_decision.supersedes_ref,
        live.northstar07.decision.supersedes_ref
    );

    let reloaded_service = reloaded_service_from_existing_workspace(
        &service,
        "remediation-positive-closure-snapshot-truth-reloaded",
    )
    .await;
    let reloaded_router = router(reloaded_service);
    let reloaded = fetch_positive_closure_truth(&reloaded_router).await;

    assert_eq!(reloaded.phase03.phase_status, live.phase03.phase_status);
    assert_eq!(
        reloaded.phase03.acceptable_caveat_refs,
        live.phase03.acceptable_caveat_refs
    );
    assert_eq!(
        reloaded.phase03.blocking_claim_risk_refs,
        live.phase03.blocking_claim_risk_refs
    );
    assert_eq!(
        reloaded.phase03_packet.acceptable_caveat_refs,
        live.phase03_packet.acceptable_caveat_refs
    );
    assert_eq!(
        reloaded.phase03_packet.blocking_risk_refs,
        live.phase03_packet.blocking_risk_refs
    );
    assert_eq!(
        reloaded.phase03_packet.risk_refs,
        live.phase03_packet.risk_refs
    );

    assert_eq!(reloaded.phase04.phase_status, live.phase04.phase_status);
    assert_eq!(
        reloaded.phase04.decision_posture,
        live.phase04.decision_posture
    );

    assert_eq!(
        reloaded.northstar07.decision.decision,
        NorthStarClosureDecision::Closed
    );
    assert_eq!(
        reloaded.northstar07.decision.decision,
        live.northstar07.decision.decision
    );
    assert_eq!(
        reloaded.northstar07.decision.supersedes_ref,
        live.northstar07.decision.supersedes_ref
    );
    assert_eq!(
        criterion_statuses(&reloaded.northstar07),
        criterion_statuses(&live.northstar07)
    );
    assert_eq!(
        residual_risk_effects(&reloaded.northstar07),
        residual_risk_effects(&live.northstar07)
    );
    assert_eq!(
        reloaded.northstar07.claim_boundary.allowed_claims,
        live.northstar07.claim_boundary.allowed_claims
    );
    assert_eq!(
        reloaded.northstar07.claim_boundary.forbidden_claims,
        live.northstar07.claim_boundary.forbidden_claims
    );
    assert_eq!(
        reloaded.northstar07.publication_policy.required_caveats,
        live.northstar07.publication_policy.required_caveats
    );
    assert_eq!(
        reloaded.northstar07.publication_policy.forbidden_claims,
        live.northstar07.publication_policy.forbidden_claims
    );
}
