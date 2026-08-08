use aiaf_v1::local_runtime::V2ContractMapView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_contract_map_dossier_acceptance() {
    let service = service("v20-contract-map").await;
    let _ = service
        .run_headless("supervisor-second-cycle-v1-completion")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let map: V2ContractMapView = get_json(&router, "/api/v2/contracts/map").await;

    assert!(map.summary.contains("contract map"));
    assert_eq!(
        map.baseline_anchor,
        "v1.9 convergence dossier -> v2.0 contract-foundation baseline"
    );
    assert_eq!(map.entries.len(), 6);
    assert!(!map.preserved_invariants.is_empty());
    assert!(!map.deferred_boundaries.is_empty());
}
