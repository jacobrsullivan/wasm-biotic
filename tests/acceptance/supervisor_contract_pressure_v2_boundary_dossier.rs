use aiaf_v1::local_runtime::ContractPressureDossierView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_contract_pressure_v2_boundary_dossier_acceptance() {
    let service = service("contract-pressure-dossier").await;
    let _ = service
        .start_run("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    let _ = service
        .start_run("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();

    let router = router(service.clone());
    let dossier: ContractPressureDossierView =
        get_json(&router, "/api/convergence/contract-pressure").await;

    assert!(dossier.summary.contains("pressure"));
    assert!(
        dossier
            .pressures
            .iter()
            .any(|item| item.pressure_kind == "capability")
    );
    assert!(
        dossier
            .pressures
            .iter()
            .any(|item| item.pressure_kind == "orchestration")
    );
    assert!(
        dossier
            .pressures
            .iter()
            .all(|item| !item.v2_implication.trim().is_empty())
    );
    assert!(!dossier.guardrails.is_empty());
}
