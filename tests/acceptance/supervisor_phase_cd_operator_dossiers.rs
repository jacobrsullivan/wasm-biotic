use aiaf_v1::local_runtime::{PhaseCReplicationDossierView, PhaseDExchangeReviewDossierView};

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_phase_c_replication_dossier_acceptance() {
    let service = service("phase-c-dossier").await;
    let _ = service
        .run_headless("supervisor-phase-c-live-bounded-factory-replication")
        .await
        .unwrap();

    let router = router(service.clone());
    let dossier: PhaseCReplicationDossierView =
        get_json(&router, "/api/phase-c/replication/dossier").await;

    assert!(dossier.summary.contains("replication dossier"));
    assert!(!dossier.run_refs.is_empty());
    assert!(!dossier.campaigns.is_empty());
    assert!(!dossier.candidates.is_empty());
    assert!(!dossier.proving_runs.is_empty());
    assert!(!dossier.observation_windows.is_empty());
    assert!(!dossier.quarantine_protocols.is_empty());
    assert!(!dossier.dispositions.is_empty());
    assert!(!dossier.decisions.is_empty());
    assert!(!dossier.evidence_packets.is_empty());
    assert!(dossier.boundary_statement.contains("bounded"));
}

#[tokio::test]
async fn supervisor_phase_d_exchange_review_dossier_acceptance() {
    let service = service("phase-d-dossier").await;
    let _ = service
        .run_headless("supervisor-phase-d-live-prefederation-exchange-contracts")
        .await
        .unwrap();

    let router = router(service.clone());
    let dossier: PhaseDExchangeReviewDossierView =
        get_json(&router, "/api/phase-d/exchange/dossier").await;

    assert!(dossier.summary.contains("exchange dossier"));
    assert!(!dossier.run_refs.is_empty());
    assert!(!dossier.identities.is_empty());
    assert!(!dossier.envelopes.is_empty());
    assert!(!dossier.compatibility_decisions.is_empty());
    assert!(!dossier.quarantine_packets.is_empty());
    assert!(!dossier.import_states.is_empty());
    assert!(!dossier.import_dispositions.is_empty());
    assert!(!dossier.lineage_imports.is_empty());
    assert!(!dossier.memory_packets.is_empty());
    assert!(
        dossier
            .contract_anchor_refs
            .iter()
            .any(|reference| reference.contains("PD-01-phase-d-anchor-family"))
    );
    assert!(
        dossier
            .boundary_statement
            .contains("does not prove federation")
    );
}
