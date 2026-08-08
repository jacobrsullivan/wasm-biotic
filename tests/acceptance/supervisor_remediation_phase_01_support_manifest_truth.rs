use serde_json::json;

use aiaf_v1::execution::{ClosureCriterionStatus, PathSupportClass};
use aiaf_v1::local_runtime::{
    LocalRunStatus, NorthStar01UniversalShellView, NorthStar07ClosureReviewView, RunViewModel,
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
async fn supervisor_remediation_phase_01_support_manifest_truth_acceptance() {
    let service = service("remediation-phase-01-support-manifest").await;
    let router = router(service.clone());
    seed_northstar_runtime(&service, &router).await;

    let northstar01: NorthStar01UniversalShellView =
        get_json(&router, "/api/northstar/01/universal-shell").await;
    for scenario_id in [
        "supervisor-v4-live-shell-runner-path",
        "supervisor-northstar-live-persistent-shell-program",
        "supervisor-durable-fixed-interface-continuous-self-hosting-program",
        "supervisor-background-quarantine-rollback-control-loop",
        "supervisor-phase-b-live-factory-artifact-family",
        "supervisor-phase-c-live-bounded-factory-replication",
        "supervisor-phase-d-live-prefederation-exchange-contracts",
    ] {
        assert!(northstar01.support.iter().any(|item| {
            item.path_ref == scenario_id && item.support_class == PathSupportClass::ShellFirst
        }));
    }
    for scenario_id in [
        "supervisor-approval-resume-worker-complete",
        "supervisor-promote-activate-successor-campaign",
        "supervisor-second-cycle-v1-completion",
        "supervisor-durable-fixed-interface-self-hosting-loop",
    ] {
        assert!(northstar01.support.iter().any(|item| {
            item.path_ref == scenario_id && item.support_class == PathSupportClass::Unsupported
        }));
    }

    let northstar07: NorthStar07ClosureReviewView =
        get_json(&router, "/api/northstar/07/closure-review").await;
    let universal_shell = northstar07
        .criteria
        .iter()
        .find(|item| item.criterion_id == "northstar-07-criterion-universal-shell")
        .expect("northstar 07 universal shell criterion should exist");
    assert_eq!(universal_shell.status, ClosureCriterionStatus::Passed);
    let persistent_shell = northstar07
        .criteria
        .iter()
        .find(|item| item.criterion_id == "northstar-07-criterion-persistent-shell")
        .expect("northstar 07 persistent shell criterion should exist");
    assert_eq!(persistent_shell.status, ClosureCriterionStatus::Passed);
    assert!(
        northstar07
            .claim_boundary
            .allowed_claims
            .iter()
            .any(|claim| claim.contains("supported live path"))
    );
    assert!(
        northstar07
            .claim_boundary
            .forbidden_claims
            .iter()
            .any(|claim| claim.contains("curated path"))
    );
}
