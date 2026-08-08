use serde_json::json;

use aiaf_v1::execution::{DurableArtifactStore, NorthStarClosureDecision};
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
async fn supervisor_remediation_phase_04_final_decision_record_acceptance() {
    let service = service("remediation-phase-04-final-decision").await;
    let router = router(service.clone());
    seed_northstar_runtime(&service, &router).await;

    let dossier: aiaf_v1::execution::ClosureDossier =
        get_json(&router, "/api/remediation/phase-04/closure-dossier").await;
    let publication_policy: aiaf_v1::execution::PublicationPolicyRecord =
        get_json(&router, "/api/remediation/phase-04/publication-policy").await;
    let decision: aiaf_v1::execution::ClosureDecisionRecord =
        get_json(&router, "/api/remediation/phase-04/final-decision").await;

    assert_eq!(
        dossier.closure_dossier_id,
        "remediation-phase-04-closure-dossier"
    );
    assert_eq!(
        publication_policy.publication_policy_id,
        "remediation-phase-04-publication-policy"
    );
    assert_eq!(
        decision.closure_decision_id,
        "remediation-phase-04-final-decision"
    );
    assert_eq!(decision.decision, NorthStarClosureDecision::Closed);
    assert_eq!(decision.supersedes_ref, "northstar-07-closure-decision");

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

    let stored_decision = phase04_store
        .load_closure_decision_record(&decision.closure_decision_id)
        .unwrap();
    let precursor_decision = precursor_store
        .load_closure_decision_record(&decision.supersedes_ref)
        .unwrap();

    assert_eq!(stored_decision, decision);
    assert_eq!(
        precursor_decision.closure_decision_id,
        "northstar-07-closure-decision"
    );
}
