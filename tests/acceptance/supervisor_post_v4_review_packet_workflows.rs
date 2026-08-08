use aiaf_v1::local_runtime::{
    PhaseBFactoryPacketLedgerView, PhaseBFactoryReviewPacket, PhaseCReplicationPacketLedgerView,
    PhaseCReplicationReviewPacket, PhaseDContractManifest, PhaseDContractManifestLedgerView,
    PhaseDExchangePacketLedgerView, PhaseDExchangeReviewPacket,
};
use serde_json::json;

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_phase_b_review_packet_export_import_acceptance() {
    let service = service("phase-b-packets").await;
    let run = service
        .run_headless("supervisor-phase-b-live-factory-artifact-family")
        .await
        .unwrap();
    let router = router(service.clone());

    let exported: PhaseBFactoryReviewPacket = post_json(
        &router,
        "/api/phase-b/factory/packets/export",
        &json!({ "run_ids": [run.summary.run_id] }),
    )
    .await;
    assert!(exported.summary.contains("Phase B review packet"));
    assert!(!exported.comparison_refs.is_empty());
    assert!(!exported.activation_refs.is_empty());
    assert!(!exported.governance_refs.is_empty());
    assert!(exported.claim_boundary.contains("single-factory"));

    let ledger: PhaseBFactoryPacketLedgerView =
        get_json(&router, "/api/phase-b/factory/packets").await;
    assert!(
        ledger
            .packets
            .iter()
            .any(|packet| packet.packet_id == exported.packet_id)
    );

    let imported: PhaseBFactoryReviewPacket =
        post_json(&router, "/api/phase-b/factory/packets/import", &exported).await;
    assert!(imported.imported);

    let ledger: PhaseBFactoryPacketLedgerView =
        get_json(&router, "/api/phase-b/factory/packets").await;
    assert!(
        ledger
            .packets
            .iter()
            .any(|packet| packet.packet_id == imported.packet_id && packet.imported)
    );
}

#[tokio::test]
async fn supervisor_phase_c_review_packet_export_import_acceptance() {
    let service = service("phase-c-packets").await;
    let run = service
        .run_headless("supervisor-phase-c-live-bounded-factory-replication")
        .await
        .unwrap();
    let router = router(service.clone());

    let exported: PhaseCReplicationReviewPacket = post_json(
        &router,
        "/api/phase-c/replication/packets/export",
        &json!({ "run_ids": [run.summary.run_id] }),
    )
    .await;
    assert!(exported.summary.contains("Phase C review packet"));
    assert!(!exported.campaign_refs.is_empty());
    assert!(!exported.proving_refs.is_empty());
    assert!(!exported.observation_refs.is_empty());
    assert!(!exported.quarantine_refs.is_empty());
    assert!(!exported.decision_refs.is_empty());
    assert!(!exported.disposition_refs.is_empty());
    assert!(exported.claim_boundary.contains("bounded"));

    let ledger: PhaseCReplicationPacketLedgerView =
        get_json(&router, "/api/phase-c/replication/packets").await;
    assert!(
        ledger
            .packets
            .iter()
            .any(|packet| packet.packet_id == exported.packet_id)
    );

    let imported: PhaseCReplicationReviewPacket = post_json(
        &router,
        "/api/phase-c/replication/packets/import",
        &exported,
    )
    .await;
    assert!(imported.imported);

    let ledger: PhaseCReplicationPacketLedgerView =
        get_json(&router, "/api/phase-c/replication/packets").await;
    assert!(
        ledger
            .packets
            .iter()
            .any(|packet| packet.packet_id == imported.packet_id && packet.imported)
    );
}

#[tokio::test]
async fn supervisor_phase_d_review_packet_export_import_acceptance() {
    let service = service("phase-d-packets").await;
    let run = service
        .run_headless("supervisor-phase-d-live-prefederation-exchange-contracts")
        .await
        .unwrap();
    let router = router(service.clone());

    let exported: PhaseDExchangeReviewPacket = post_json(
        &router,
        "/api/phase-d/exchange/packets/export",
        &json!({ "run_ids": [run.summary.run_id] }),
    )
    .await;
    assert!(exported.summary.contains("Phase D review packet"));
    assert!(!exported.envelope_refs.is_empty());
    assert!(!exported.compatibility_refs.is_empty());
    assert!(!exported.quarantine_refs.is_empty());
    assert!(!exported.import_state_refs.is_empty());
    assert!(!exported.import_disposition_refs.is_empty());
    assert!(
        exported
            .contract_anchor_refs
            .iter()
            .any(|reference| reference.contains("PD-01-phase-d-anchor-family"))
    );

    let ledger: PhaseDExchangePacketLedgerView =
        get_json(&router, "/api/phase-d/exchange/packets").await;
    assert!(
        ledger
            .packets
            .iter()
            .any(|packet| packet.packet_id == exported.packet_id)
    );

    let imported: PhaseDExchangeReviewPacket =
        post_json(&router, "/api/phase-d/exchange/packets/import", &exported).await;
    assert!(imported.imported);

    let ledger: PhaseDExchangePacketLedgerView =
        get_json(&router, "/api/phase-d/exchange/packets").await;
    assert!(
        ledger
            .packets
            .iter()
            .any(|packet| packet.packet_id == imported.packet_id && packet.imported)
    );
}

#[tokio::test]
async fn supervisor_phase_d_contract_manifest_export_import_acceptance() {
    let service = service("phase-d-manifests").await;
    let run = service
        .run_headless("supervisor-phase-d-live-prefederation-exchange-contracts")
        .await
        .unwrap();
    let router = router(service.clone());

    let exported: PhaseDContractManifest = post_json(
        &router,
        "/api/phase-d/contracts/manifests/export",
        &json!({ "run_ids": [run.summary.run_id] }),
    )
    .await;
    assert!(
        exported
            .summary
            .contains("Concrete Phase D contract manifest")
    );
    assert_eq!(
        exported.anchor_family_ref,
        "contracts/PD-01-phase-d-anchor-family.json"
    );
    assert_eq!(
        exported.manifest_schema_ref,
        "contracts/PD-02-phase-d-contract-manifest-anchor.json"
    );
    assert!(!exported.sender_identity_refs.is_empty());
    assert!(!exported.envelope_refs.is_empty());
    assert!(!exported.compatibility_refs.is_empty());
    assert!(!exported.quarantine_refs.is_empty());
    assert!(!exported.import_state_refs.is_empty());
    assert!(!exported.import_disposition_refs.is_empty());

    let ledger: PhaseDContractManifestLedgerView =
        get_json(&router, "/api/phase-d/contracts/manifests").await;
    assert!(
        ledger
            .manifests
            .iter()
            .any(|manifest| manifest.manifest_id == exported.manifest_id)
    );

    let imported: PhaseDContractManifest = post_json(
        &router,
        "/api/phase-d/contracts/manifests/import",
        &exported,
    )
    .await;
    assert!(imported.imported);

    let ledger: PhaseDContractManifestLedgerView =
        get_json(&router, "/api/phase-d/contracts/manifests").await;
    assert!(
        ledger
            .manifests
            .iter()
            .any(|manifest| manifest.manifest_id == imported.manifest_id && manifest.imported)
    );
}
