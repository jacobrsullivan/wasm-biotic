use std::collections::BTreeSet;

use aiaf_v1::execution::WorkerRoleKind;
use aiaf_v1::local_runtime::{
    NorthStar04WorkerEcologyView, RemediationPhase02ServiceEcologyClosureView,
};

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_remediation_phase_02_worker_ecology_closure_acceptance() {
    let service = service("remediation-phase-02-worker-ecology").await;
    let router = router(service.clone());

    let _ = service
        .run_headless("supervisor-phase-c-live-bounded-factory-replication")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-phase-b-live-factory-artifact-family")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();

    let northstar04: NorthStar04WorkerEcologyView =
        get_json(&router, "/api/northstar/04/worker-ecology").await;
    let roles = northstar04
        .worker_cards
        .iter()
        .map(|item| item.role_kind)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        roles,
        [
            WorkerRoleKind::Planner,
            WorkerRoleKind::Builder,
            WorkerRoleKind::Validator,
            WorkerRoleKind::Reviewer,
            WorkerRoleKind::Packager,
            WorkerRoleKind::ContinuityWorker,
        ]
        .into_iter()
        .collect()
    );
    assert!(!northstar04.routing_packets.is_empty());
    assert!(!northstar04.recovery_records.is_empty());
    assert!(northstar04.health_records.iter().all(|item| {
        !item.load_refs.is_empty()
            && !item.fairness_refs.is_empty()
            && !item.degradation_refs.is_empty()
            && !item.recovery_refs.is_empty()
    }));

    let workspace: aiaf_v1::execution::EcologyClosureWorkspacePacket =
        get_json(&router, "/api/remediation/phase-02/ecology-workspace").await;
    assert!(!workspace.worker_card_refs.is_empty());
    assert!(!workspace.routing_packet_refs.is_empty());
    assert!(!workspace.degradation_refs.is_empty());

    let phase02: RemediationPhase02ServiceEcologyClosureView =
        get_json(&router, "/api/remediation/phase-02/service-ecology-closure").await;
    assert!(phase02.workstreams.iter().any(
        |item| item.workstream_id == "phase-02-workstream-c" && item.status == "closure_grade"
    ));
}
