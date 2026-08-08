use aiaf_v1::local_runtime::V2RuntimeCoordinationGenerationView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_runtime_coordination_generation_candidate_acceptance() {
    let service = service("v23-generation").await;
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let generation: V2RuntimeCoordinationGenerationView =
        get_json(&router, "/api/v2/topology/generation").await;

    assert!(
        generation
            .summary
            .contains("runtime-coordination generation")
    );
    assert!(generation.generation_status.contains("candidate"));
    assert!(!generation.unresolved_edges.is_empty());
}
