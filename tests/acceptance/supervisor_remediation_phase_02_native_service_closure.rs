use std::collections::BTreeSet;

use aiaf_v1::execution::WorkflowClosureStatus;
use aiaf_v1::local_runtime::NorthStar03NativeServicesView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_remediation_phase_02_native_service_closure_acceptance() {
    let service = service("remediation-phase-02-native-services").await;
    let router = router(service.clone());

    let _ = service
        .run_headless("supervisor-phase-b-live-factory-artifact-family")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-northstar-live-persistent-shell-program")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();

    let northstar03: NorthStar03NativeServicesView =
        get_json(&router, "/api/northstar/03/native-services").await;
    let workflow_kinds = northstar03
        .workflow_sufficiency_records
        .iter()
        .filter(|item| item.closure_status == WorkflowClosureStatus::ClosureGrade)
        .map(|item| item.workflow_kind)
        .collect::<BTreeSet<_>>();
    assert_eq!(workflow_kinds.len(), 7);
    assert!(northstar03.bounded_workflow_refs.is_empty());
    assert!(
        northstar03
            .workflow_sufficiency_records
            .iter()
            .filter(|item| item.closure_status == WorkflowClosureStatus::ClosureGrade)
            .count()
            >= 7
    );
    assert!(
        northstar03
            .workflow_closure_dossiers
            .iter()
            .filter(|item| item.closure_status == WorkflowClosureStatus::ClosureGrade)
            .count()
            >= 7
    );

    let workspace: aiaf_v1::execution::ServiceClosureWorkspacePacket =
        get_json(&router, "/api/remediation/phase-02/service-workspace").await;
    assert_eq!(workspace.workflow_sufficiency_refs.len(), 7);
    assert_eq!(workspace.workflow_dossier_refs.len(), 7);
    assert!(workspace.transitional_gap_refs.is_empty());
}
