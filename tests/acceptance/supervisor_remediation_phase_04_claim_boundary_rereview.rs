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
async fn supervisor_remediation_phase_04_claim_boundary_rereview_acceptance() {
    let service = service("remediation-phase-04-claim-boundary").await;
    let router = router(service.clone());
    seed_northstar_runtime(&service, &router).await;

    let adversarial: aiaf_v1::execution::AdversarialReviewRecord =
        get_json(&router, "/api/remediation/phase-04/adversarial-review").await;
    let claim_boundary: aiaf_v1::execution::ClaimBoundaryReviewPacket =
        get_json(&router, "/api/remediation/phase-04/claim-boundary").await;
    let publication_policy: aiaf_v1::execution::PublicationPolicyRecord =
        get_json(&router, "/api/remediation/phase-04/publication-policy").await;

    assert_eq!(
        adversarial.adversarial_review_id,
        "remediation-phase-04-adversarial-review"
    );
    assert_eq!(
        adversarial.criteria_matrix_ref,
        "remediation-phase-04-criteria-matrix"
    );
    assert!(!adversarial.counter_evidence_refs.is_empty());
    assert!(!adversarial.risk_refs.is_empty());
    assert!(!adversarial.challenge_outcome_refs.is_empty());

    assert_eq!(
        claim_boundary.claim_review_id,
        "remediation-phase-04-claim-boundary"
    );
    assert!(!claim_boundary.allowed_claims.is_empty());
    assert!(!claim_boundary.forbidden_claims.is_empty());
    assert!(!claim_boundary.counter_evidence_refs.is_empty());
    assert!(!claim_boundary.publication_risk_refs.is_empty());

    assert_eq!(
        publication_policy.publication_policy_id,
        "remediation-phase-04-publication-policy"
    );
    assert!(publication_policy.required_caveats.is_empty());
    assert!(!publication_policy.forbidden_claims.is_empty());
    assert!(
        publication_policy
            .allowed_claims
            .iter()
            .any(|claim| claim.contains("North Star has been reached"))
    );
    assert!(
        publication_policy
            .allowed_claims
            .iter()
            .any(|claim| claim.contains("self-sustaining Wasm-Biotic world"))
    );
    assert!(
        publication_policy
            .forbidden_claims
            .iter()
            .all(|claim| !claim.contains("self-sustaining Wasm-Biotic world"))
    );
    assert!(
        publication_policy
            .forbidden_claims
            .iter()
            .any(|claim| claim.contains("open-ended autonomous multi-factory federation"))
    );
}
