use aiaf_v1::local_runtime::{OperatorRunbookView, RunViewModel, UseCaseStudioView};
use serde_json::json;

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_factory_agent_usecase_studio_rehearsal_acceptance() {
    let service = service("usecase-studio").await;
    let router = router(service.clone());

    let usecases: UseCaseStudioView = get_json(&router, "/api/studio/usecases").await;
    assert!(usecases.summary.contains("Factory and Agent"));
    assert!(
        usecases
            .use_cases
            .iter()
            .any(|usecase| usecase.kind == "Factory")
    );
    assert!(
        usecases
            .use_cases
            .iter()
            .any(|usecase| usecase.kind == "Agent")
    );

    let run: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program",
            "template_id": "template-agent-continuous-program-lane",
            "pack_id": "pack-agent-self-hosting",
            "operator_goal": "Rehearse the agent continuous review path"
        }),
    )
    .await;
    assert_eq!(
        run.summary.scenario_id,
        "supervisor-durable-fixed-interface-continuous-self-hosting-program"
    );

    let runbook: OperatorRunbookView = get_json(&router, "/api/operator/runbook").await;
    assert!(
        runbook
            .entries
            .first()
            .map(|entry| entry
                .detail
                .contains("template-agent-continuous-program-lane"))
            .unwrap_or(false)
    );
}
