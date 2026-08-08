use aiaf_v1::local_runtime::PhaseBFactoryDossierView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_phase_b_factory_dossier_acceptance() {
    let service = service("phase-b-dossier").await;
    let _ = service
        .run_headless("supervisor-phase-b-live-factory-artifact-family")
        .await
        .unwrap();

    let router = router(service.clone());
    let dossier: PhaseBFactoryDossierView = get_json(&router, "/api/phase-b/factory/dossier").await;

    assert!(dossier.summary.contains("factory dossier"));
    assert!(!dossier.run_refs.is_empty());
    assert!(!dossier.incumbent_factory_refs.is_empty());
    assert!(!dossier.challenger_factory_refs.is_empty());
    assert!(!dossier.genomes.is_empty());
    assert!(!dossier.phenotypes.is_empty());
    assert!(!dossier.lineage_records.is_empty());
    assert!(!dossier.validation_profiles.is_empty());
    assert!(!dossier.validation_evidence.is_empty());
    assert!(!dossier.validation_records.is_empty());
    assert!(!dossier.comparisons.is_empty());
    assert!(!dossier.activations.is_empty());
    assert!(!dossier.active_states.is_empty());
    assert!(!dossier.governance_transitions.is_empty());
    assert!(!dossier.rollback_envelopes.is_empty());
    assert!(!dossier.quarantine_records.is_empty());
    assert!(!dossier.evidence_packets.is_empty());
    assert!(dossier.boundary_statement.contains("single-factory"));
}
