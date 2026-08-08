use aiaf_v1::local_runtime::V2CompatibilityWorkspaceView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_compatibility_envelope_coexistence_acceptance() {
    let service = service("v20-compatibility").await;
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-self-hosting-loop")
        .await
        .unwrap();

    let router = router(service.clone());
    let compatibility: V2CompatibilityWorkspaceView =
        get_json(&router, "/api/v2/contracts/compatibility").await;

    assert!(compatibility.summary.contains("Compatibility"));
    assert!(!compatibility.envelopes.is_empty());
    assert!(
        compatibility
            .envelopes
            .iter()
            .all(|envelope| !envelope.coexistence_rules.is_empty())
    );
    assert!(compatibility.envelopes.iter().any(|envelope| {
        envelope
            .preserved_v1_surfaces
            .iter()
            .any(|surface| surface.contains("execution"))
    }));
    assert!(!compatibility.deferred_candidates.is_empty());
}
