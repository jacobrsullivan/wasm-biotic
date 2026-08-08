use aiaf_v1::local_runtime::NorthStar05FactoryProgramsView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_remediation_phase_03_longitudinal_lineage_health_acceptance() {
    let service = service("remediation-phase-03-longitudinal-lineage-health").await;
    let router = router(service.clone());

    let _ = service
        .run_headless("supervisor-phase-b-live-factory-artifact-family")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-phase-c-live-bounded-factory-replication")
        .await
        .unwrap();

    let northstar05: NorthStar05FactoryProgramsView =
        get_json(&router, "/api/northstar/05/factory-programs").await;
    let recurring = northstar05
        .recurring_factory_programs
        .iter()
        .find(|item| {
            northstar05
                .closure_grade_program_refs
                .contains(&item.factory_program_id)
        })
        .unwrap();
    let ledger = northstar05
        .lineage_ledgers
        .iter()
        .find(|item| item.program_ref == recurring.factory_program_id)
        .unwrap();
    let regression = northstar05
        .regression_packets
        .iter()
        .find(|item| item.lineage_ledger_ref == ledger.lineage_ledger_id)
        .unwrap();
    let dossier = northstar05
        .longitudinal_lineage_dossiers
        .iter()
        .find(|item| {
            item.program_ref == recurring.factory_program_id
                && item.health_ref == ledger.lineage_ledger_id
        })
        .unwrap();

    assert!(!ledger.rollback_refs.is_empty());
    assert!(!ledger.regression_refs.is_empty());
    assert!(!regression.threshold_refs.is_empty());
    assert!(!regression.trigger_refs.is_empty());
    assert!(!regression.mitigation_refs.is_empty());
    assert!(
        dossier
            .regression_packet_refs
            .contains(&regression.regression_packet_id)
    );
    assert!(
        recurring
            .cycle_refs
            .iter()
            .all(|reference| dossier.cycle_refs.contains(reference))
    );
}
