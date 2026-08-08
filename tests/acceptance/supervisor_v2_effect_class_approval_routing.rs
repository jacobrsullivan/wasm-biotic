use aiaf_v1::local_runtime::V2EffectRoutingView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_effect_class_approval_routing_acceptance() {
    let service = service("v21-effect-routing").await;
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let effects: V2EffectRoutingView = get_json(&router, "/api/v2/services/effects").await;

    assert!(effects.summary.contains("effect-routing"));
    assert!(!effects.effect_classes.is_empty());
    assert!(
        effects
            .effect_classes
            .iter()
            .any(|effect| effect.approval_requirement.contains("Approval-gated"))
    );
    assert!(
        effects
            .effect_classes
            .iter()
            .any(|effect| effect.release_or_rollback_sensitivity == "release-or-rollback-sensitive")
    );
}
