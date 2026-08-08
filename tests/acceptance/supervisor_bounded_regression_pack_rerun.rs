use aiaf_v1::local_runtime::RunViewModel;
use serde_json::json;

use crate::local_runtime_support::{post_json, router, service};

#[tokio::test]
async fn supervisor_bounded_regression_pack_rerun_acceptance() {
    let service = service("regression-pack-rerun").await;
    let router = router(service.clone());

    let run: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-self-hosting-loop",
            "composition_id": "composition-agent-self-hosting-baseline",
            "run_set_id": "runset-agent-self-hosting-program",
            "regression_pack_id": "regression-pack-agent-self-hosting-core",
            "operator_goal": "Rerun the bounded self-hosting baseline"
        }),
    )
    .await;

    assert_eq!(
        run.summary.regression_pack_id.as_deref(),
        Some("regression-pack-agent-self-hosting-core")
    );
    assert_eq!(
        run.summary.run_set_id.as_deref(),
        Some("runset-agent-self-hosting-program")
    );
}
