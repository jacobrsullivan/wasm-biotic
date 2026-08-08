use aiaf_v1::local_runtime::V2CapabilityWorldTaxonomyView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_world_family_brokerage_taxonomy_acceptance() {
    let service = service("v21-world-taxonomy").await;
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let taxonomy: V2CapabilityWorldTaxonomyView =
        get_json(&router, "/api/v2/services/worlds").await;

    assert!(taxonomy.summary.contains("taxonomy"));
    assert!(!taxonomy.world_families.is_empty());
    assert!(
        taxonomy
            .world_families
            .iter()
            .any(|family| family.family_id == "world-family:execution-control")
    );
    assert!(!taxonomy.brokerage_boundary.is_empty());
}
