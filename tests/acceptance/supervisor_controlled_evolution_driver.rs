use aiaf_v1::execution::{AdoptionWindowResult, FactoryProgramState};
use aiaf_v1::local_runtime::{FactoryProgramLedgerView, FactoryProgramView};

use crate::local_runtime_support::{
    get_json, post_empty, reloaded_service_from_existing_workspace, router, service,
};

#[tokio::test]
async fn supervisor_controlled_evolution_driver_acceptance() {
    let service = service("controlled-evolution-driver").await;
    let app = router(service.clone());

    let program: FactoryProgramView =
        post_empty(&app, "/api/programs/controlled-evolution/drive").await;

    assert_eq!(
        program.instance.program_state,
        FactoryProgramState::Completed
    );
    assert_eq!(program.instance.generation_depth, 2);
    assert_eq!(program.instance.campaign_count, 3);
    assert_eq!(program.instance.current_factory_ref, "factory:g2");
    assert_eq!(program.receipts.len(), 3);
    assert_eq!(
        program.receipts[0].adoption_window.result,
        AdoptionWindowResult::Adopted
    );
    assert_eq!(
        program.receipts[1].adoption_window.result,
        AdoptionWindowResult::RolledBack
    );
    assert_eq!(
        program.receipts[2].adoption_window.result,
        AdoptionWindowResult::Adopted
    );
    assert!(program.lineage_ledger.is_some());
    assert!(program.regression_packet.is_some());
    assert!(program.longitudinal_lineage_dossier.is_some());

    let ledger: FactoryProgramLedgerView = get_json(&app, "/api/programs").await;
    assert_eq!(ledger.programs.len(), 1);
    assert_eq!(
        ledger.programs[0].instance.instance_id,
        program.instance.instance_id
    );

    let reloaded_service =
        reloaded_service_from_existing_workspace(&service, "controlled-evolution-driver-reloaded")
            .await;
    let reloaded_router = router(reloaded_service);
    let reloaded_program: FactoryProgramView = get_json(
        &reloaded_router,
        &format!("/api/programs/{}", program.instance.instance_id),
    )
    .await;

    assert_eq!(reloaded_program.instance, program.instance);
    assert_eq!(reloaded_program.receipts, program.receipts);
    assert_eq!(reloaded_program.lineage_ledger, program.lineage_ledger);
    assert_eq!(
        reloaded_program.regression_packet,
        program.regression_packet
    );
    assert_eq!(
        reloaded_program.longitudinal_lineage_dossier,
        program.longitudinal_lineage_dossier
    );
}
