use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2GenerationCandidateAssemblyView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_generation_candidate_assembly_acceptance() {
    let service = service("v25-generation-assembly").await;
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

    let assembly: V2GenerationCandidateAssemblyView =
        get_json(&router, "/api/v2/generation/assembly").await;

    assert!(assembly.summary.contains("generation candidate"));
    assert_eq!(assembly.candidate_id, "v2-generation:candidate-01");
    assert_eq!(assembly.integrated_lines.len(), 5);
}
