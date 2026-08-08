use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2ContractGenerationComparisonRecordView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_contract_generation_comparison_record_acceptance() {
    let service = service("v25-generation-comparison").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-promote-activate-successor-campaign" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program" }),
    )
    .await;

    let comparison: V2ContractGenerationComparisonRecordView =
        get_json(&router, "/api/v2/generation/comparison").await;

    assert!(comparison.summary.contains("formal subject"));
    assert_eq!(
        comparison.record_id,
        "generation-comparison:v2-candidate-01"
    );
    assert_eq!(comparison.dimensions.len(), 5);
}
