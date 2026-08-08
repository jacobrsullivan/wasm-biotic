use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2ChallengerIncumbentGenerationComparisonView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_challenger_incumbent_generation_comparison_acceptance() {
    let service = service("v28-comparison").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-approval-resume-worker-complete" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program" }),
    )
    .await;

    let comparison: V2ChallengerIncumbentGenerationComparisonView =
        get_json(&router, "/api/v2/self-hosting/comparison").await;

    assert!(comparison.summary.contains("challenger/incumbent"));
    assert_ne!(comparison.challenger_ref, comparison.incumbent_ref);
    assert!(!comparison.evidence_refs.is_empty());
}
