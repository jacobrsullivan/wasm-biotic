use aiaf_v1::local_runtime::V2ServiceAttestationLedgerView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_native_carried_service_attestation_acceptance() {
    let service = service("v21-service-attestation").await;
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let attestation: V2ServiceAttestationLedgerView =
        get_json(&router, "/api/v2/services/attestation").await;

    assert!(attestation.summary.contains("attestation ledger"));
    assert!(!attestation.attestations.is_empty());
    assert!(
        attestation
            .closure_classes
            .iter()
            .any(|item| item == "imported")
    );
    assert!(
        attestation
            .closure_classes
            .iter()
            .any(|item| item == "carried")
    );
    assert!(
        attestation
            .closure_classes
            .iter()
            .any(|item| item == "hybrid")
    );
    assert!(
        attestation
            .closure_classes
            .iter()
            .any(|item| item == "native-enough")
    );
}
