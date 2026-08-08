use aiaf_v1::local_runtime::V2SelfHostingPhaseDeclarationView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_self_hosting_phase_declaration_acceptance() {
    let service = service("v29-phase").await;
    service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service);
    let phase: V2SelfHostingPhaseDeclarationView =
        get_json(&router, "/api/v2/convergence/phase").await;

    assert!(phase.phase_label.contains("first bounded v2"));
    assert!(phase.scope_statement.contains("single-factory"));
    assert!(!phase.achieved_capabilities.is_empty());
    assert!(
        phase
            .explicit_non_goals
            .iter()
            .any(|item| item.to_lowercase().contains("federation"))
    );
}
