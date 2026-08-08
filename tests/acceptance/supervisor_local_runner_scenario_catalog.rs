use aiaf_v1::local_runtime::ScenarioDefinition;

use crate::local_runtime_support::service;

#[tokio::test]
async fn supervisor_local_runner_scenario_catalog_acceptance() {
    let service = service("scenario-catalog").await;
    let scenarios: Vec<ScenarioDefinition> = service.list_scenarios().await;
    let ids = scenarios
        .into_iter()
        .map(|definition| definition.scenario_id)
        .collect::<Vec<_>>();

    assert_eq!(
        ids,
        vec![
            "supervisor-approval-resume-worker-complete",
            "supervisor-background-quarantine-rollback-control-loop",
            "supervisor-promote-activate-successor-campaign",
            "supervisor-second-cycle-v1-completion",
            "supervisor-durable-fixed-interface-self-hosting-loop",
            "supervisor-durable-fixed-interface-continuous-self-hosting-program",
            "supervisor-v4-live-shell-runner-path",
            "supervisor-northstar-live-persistent-shell-program",
            "supervisor-phase-b-live-factory-artifact-family",
            "supervisor-phase-c-live-bounded-factory-replication",
            "supervisor-phase-d-live-prefederation-exchange-contracts",
        ]
    );
}
