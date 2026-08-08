use aiaf_v1::local_runtime::V2ContractClassificationView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_contract_change_classification_acceptance() {
    let service = service("v20-change-classification").await;
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let classification: V2ContractClassificationView =
        get_json(&router, "/api/v2/contracts/classification").await;

    assert!(classification.summary.contains("preserve"));
    assert!(
        classification
            .allowed_change_classes
            .contains(&"replace".to_string())
    );
    assert!(
        classification
            .allowed_change_classes
            .contains(&"defer".to_string())
    );
    assert!(
        classification
            .decisions
            .iter()
            .any(|decision| decision.change_class == "replace")
    );
    assert!(
        classification
            .decisions
            .iter()
            .any(|decision| decision.change_class == "defer")
    );
}
