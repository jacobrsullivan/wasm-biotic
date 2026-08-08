use aiaf_v1::local_runtime::{
    PhaseALaunchTruthView, PhaseBFactoryAdoptionWorkspaceView, PhaseCObservationWorkspaceView,
    PhaseDImportWorkspaceView, ScenarioSupportClass,
};

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_phase_a_launch_truth_acceptance() {
    let service = service("phase-a-launch-truth").await;
    let _ = service
        .run_headless("supervisor-v4-live-shell-runner-path")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-phase-b-live-factory-artifact-family")
        .await
        .unwrap();

    let router = router(service.clone());
    let truth: PhaseALaunchTruthView = get_json(&router, "/api/phase-a/launch-truth").await;

    assert!(truth.summary.contains("launch truth"));
    assert!(truth.scenario_support.iter().any(|item| {
        item.scenario_ref == "supervisor-v4-live-shell-runner-path"
            && item.support_class == ScenarioSupportClass::ShellBacked
    }));
    assert!(truth.scenario_support.iter().any(|item| {
        item.scenario_ref == "supervisor-phase-b-live-factory-artifact-family"
            && item.support_class == ScenarioSupportClass::ShellBacked
    }));
    assert!(!truth.launches.is_empty());
    assert!(!truth.admissions.is_empty());
}

#[tokio::test]
async fn supervisor_phase_b_adoption_workspace_acceptance() {
    let service = service("phase-b-adoption-workspace").await;
    let _ = service
        .run_headless("supervisor-phase-b-live-factory-artifact-family")
        .await
        .unwrap();

    let router = router(service.clone());
    let workspace: PhaseBFactoryAdoptionWorkspaceView =
        get_json(&router, "/api/phase-b/factory/adoption-workspace").await;

    assert!(workspace.summary.contains("adoption workspace"));
    assert!(!workspace.run_refs.is_empty());
    assert!(!workspace.comparison_refs.is_empty());
    assert!(!workspace.activation_refs.is_empty());
    assert!(!workspace.governance_transition_refs.is_empty());
    assert!(!workspace.retained_incumbent_refs.is_empty());
    assert!(!workspace.observation_window_refs.is_empty());
    assert!(!workspace.rollback_handle_refs.is_empty());
    assert!(!workspace.quarantine_refs.is_empty());
    assert!(workspace.boundary_statement.contains("single-factory"));
}

#[tokio::test]
async fn supervisor_phase_c_observation_workspace_acceptance() {
    let service = service("phase-c-observation-workspace").await;
    let _ = service
        .run_headless("supervisor-phase-c-live-bounded-factory-replication")
        .await
        .unwrap();

    let router = router(service.clone());
    let workspace: PhaseCObservationWorkspaceView =
        get_json(&router, "/api/phase-c/replication/observation-workspace").await;

    assert!(workspace.summary.contains("observation workspace"));
    assert!(!workspace.run_refs.is_empty());
    assert!(!workspace.campaign_refs.is_empty());
    assert!(!workspace.child_factory_refs.is_empty());
    assert!(!workspace.observation_window_refs.is_empty());
    assert!(!workspace.quarantine_protocol_refs.is_empty());
    assert!(!workspace.decision_refs.is_empty());
    assert!(!workspace.disposition_refs.is_empty());
    assert!(!workspace.rollback_refs.is_empty());
    assert!(workspace.boundary_statement.contains("bounded"));
}

#[tokio::test]
async fn supervisor_phase_d_import_workspace_acceptance() {
    let service = service("phase-d-import-workspace").await;
    let _ = service
        .run_headless("supervisor-phase-d-live-prefederation-exchange-contracts")
        .await
        .unwrap();
    let router = router(service.clone());
    let workspace: PhaseDImportWorkspaceView =
        get_json(&router, "/api/phase-d/exchange/import-workspace").await;

    assert!(workspace.summary.contains("import workspace"));
    assert!(!workspace.run_refs.is_empty());
    assert!(!workspace.sender_identity_refs.is_empty());
    assert!(!workspace.exchange_refs.is_empty());
    assert!(!workspace.compatibility_refs.is_empty());
    assert!(!workspace.quarantine_refs.is_empty());
    assert!(!workspace.import_state_refs.is_empty());
    assert!(!workspace.import_disposition_refs.is_empty());
    assert!(!workspace.imported_content_refs.is_empty());
    assert!(workspace.boundary_statement.contains("pre-federation"));
}
