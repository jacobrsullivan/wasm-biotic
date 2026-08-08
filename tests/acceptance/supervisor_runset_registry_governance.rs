use aiaf_v1::local_runtime::{ExperimentProgramView, RunViewModel};
use serde_json::json;

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_runset_registry_governance_acceptance() {
    let service = service("runset-registry").await;
    let router = router(service.clone());

    let programs: ExperimentProgramView = get_json(&router, "/api/studio/experiment-program").await;
    assert!(!programs.run_sets.is_empty());
    assert!(
        programs
            .governance_rules
            .iter()
            .any(|rule| rule.contains("bounded") || rule.contains("evidence"))
    );

    let run: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-approval-resume-worker-complete",
            "composition_id": "composition-factory-approval-baseline",
            "run_set_id": "runset-factory-governed-upgrade",
            "operator_goal": "Validate the governed upgrade baseline"
        }),
    )
    .await;

    assert_eq!(
        run.summary.composition_id.as_deref(),
        Some("composition-factory-approval-baseline")
    );
    assert_eq!(
        run.summary.run_set_id.as_deref(),
        Some("runset-factory-governed-upgrade")
    );
}
