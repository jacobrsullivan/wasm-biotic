use aiaf_v1::local_runtime::V2CapabilityServiceGenerationView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_capability_service_generation_candidate_acceptance() {
    let service = service("v21-service-generation").await;
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let generation: V2CapabilityServiceGenerationView =
        get_json(&router, "/api/v2/services/generation").await;

    assert!(generation.summary.contains("capability-service generation"));
    assert!(generation.generation_status.contains("candidate"));
    assert!(generation.strongest_world_family.is_some());
    assert!(!generation.unresolved_edges.is_empty());
}
