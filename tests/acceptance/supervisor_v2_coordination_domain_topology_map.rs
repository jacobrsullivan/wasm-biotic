use aiaf_v1::local_runtime::V2CoordinationTopologyMapView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_coordination_domain_topology_map_acceptance() {
    let service = service("v23-topology-domains").await;
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let topology: V2CoordinationTopologyMapView =
        get_json(&router, "/api/v2/topology/domains").await;

    assert!(topology.summary.contains("coordination domain"));
    assert_eq!(topology.domains.len(), 6);
    assert!(
        topology
            .domains
            .iter()
            .any(|domain| domain.domain_id == "coordination-domain:campaign")
    );
    assert!(
        topology
            .domains
            .iter()
            .any(|domain| domain.domain_id == "coordination-domain:replay-recovery")
    );
}
