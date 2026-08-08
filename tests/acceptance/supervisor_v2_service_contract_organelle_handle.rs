use aiaf_v1::local_runtime::V2ServiceContractHandleView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_service_contract_organelle_handle_acceptance() {
    let service = service("v21-service-contracts").await;
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let contracts: V2ServiceContractHandleView =
        get_json(&router, "/api/v2/services/contracts").await;

    assert!(contracts.summary.contains("service/handle model"));
    assert!(!contracts.services.is_empty());
    assert!(
        contracts
            .services
            .iter()
            .all(|service| service.handle_model.starts_with("organelle-handle:"))
    );
    assert!(!contracts.handle_rules.is_empty());
}
