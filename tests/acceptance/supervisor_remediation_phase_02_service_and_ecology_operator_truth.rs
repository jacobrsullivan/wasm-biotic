use serde_json::json;

use aiaf_v1::execution::{ClosureCriterionStatus, NorthStarClosureDecision};
use aiaf_v1::local_runtime::{
    LocalRunStatus, NorthStar07ClosureReviewView, RemediationPhase02ServiceEcologyClosureView,
    RunViewModel,
};

use crate::local_runtime_support::{get_json, post_empty, post_json, router, service};

#[tokio::test]
async fn supervisor_remediation_phase_02_service_and_ecology_operator_truth_acceptance() {
    let service = service("remediation-phase-02-operator-truth").await;
    let router = router(service.clone());

    let _ = service
        .run_headless("supervisor-v4-live-shell-runner-path")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-phase-b-live-factory-artifact-family")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-phase-c-live-bounded-factory-replication")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-northstar-live-persistent-shell-program")
        .await
        .unwrap();

    let awaiting: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program"
        }),
    )
    .await;
    assert_eq!(awaiting.summary.status, LocalRunStatus::AwaitingApproval);
    let _expired: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/approval/expire", awaiting.summary.run_id),
    )
    .await;

    let _ = service
        .run_headless("supervisor-phase-d-live-prefederation-exchange-contracts")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();

    let service_workspace: aiaf_v1::execution::ServiceClosureWorkspacePacket =
        get_json(&router, "/api/remediation/phase-02/service-workspace").await;
    let ecology_workspace: aiaf_v1::execution::EcologyClosureWorkspacePacket =
        get_json(&router, "/api/remediation/phase-02/ecology-workspace").await;
    let acceptance_packet: aiaf_v1::execution::Phase02AcceptancePacket =
        get_json(&router, "/api/remediation/phase-02/acceptance-packet").await;
    assert!(!service_workspace.workflow_sufficiency_refs.is_empty());
    assert!(!ecology_workspace.routing_packet_refs.is_empty());
    assert!(!acceptance_packet.workflow_refs.is_empty());

    let phase02: RemediationPhase02ServiceEcologyClosureView =
        get_json(&router, "/api/remediation/phase-02/service-ecology-closure").await;
    assert_eq!(phase02.phase_status, "closure_grade");

    let northstar07: NorthStar07ClosureReviewView =
        get_json(&router, "/api/northstar/07/closure-review").await;
    let native_services = northstar07
        .criteria
        .iter()
        .find(|item| item.criterion_id == "northstar-07-criterion-native-services")
        .unwrap();
    let worker_ecology = northstar07
        .criteria
        .iter()
        .find(|item| item.criterion_id == "northstar-07-criterion-worker-ecology")
        .unwrap();
    assert_eq!(native_services.status, ClosureCriterionStatus::Passed);
    assert_eq!(worker_ecology.status, ClosureCriterionStatus::Passed);
    assert!(native_services.gap_refs.is_empty());
    assert!(worker_ecology.gap_refs.is_empty());
    assert_eq!(
        northstar07.decision.decision,
        NorthStarClosureDecision::Closed
    );
}
