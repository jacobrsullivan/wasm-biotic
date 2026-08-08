use aiaf_v1::execution::{
    DurableArtifactStore, FactoryCompatibilityVerdict, FactoryExchangeDecisionKind,
    FactoryExchangeEnvelope, FactoryExchangePacketClass, FactoryIdentityManifest,
    ImportDispositionKind, MemoryExchangePacket, QuarantineFirstImportStateKind,
    evaluate_factory_exchange_compatibility, issue_import_quarantine_packet,
    record_cross_factory_lineage_import, record_import_disposition,
    record_quarantine_first_import_state,
};
use std::env;
use std::fs;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_store_root(name: &str) -> std::path::PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should remain after unix epoch")
        .as_nanos();
    env::temp_dir().join(format!("aiaf-phase-d-{name}-{}-{timestamp}", process::id()))
}

#[test]
fn supervisor_phase_d_prefederation_exchange_contracts_acceptance() {
    let root = temp_store_root("prefederation-exchange");
    let store = DurableArtifactStore::bootstrap(root.join("store")).unwrap();

    let sender_identity = FactoryIdentityManifest {
        factory_identity_id: "factory-identity-sender".to_string(),
        factory_ref: "factory-phenotype-child".to_string(),
        contract_refs: vec!["contract:v1".to_string()],
        service_closure_refs: vec!["service:v4-shell".to_string()],
        governance_policy_refs: vec!["governance:bounded-adoption".to_string()],
        lineage_root_ref: "lineage-root:sender".to_string(),
        claim_boundary: "bounded local-first ecosystem participant only".to_string(),
        summary: "sending factory identity manifest".to_string(),
    };
    let receiver_identity = FactoryIdentityManifest {
        factory_identity_id: "factory-identity-receiver".to_string(),
        factory_ref: "factory-phenotype-receiver".to_string(),
        contract_refs: vec!["contract:v1".to_string()],
        service_closure_refs: vec!["service:v4-shell".to_string()],
        governance_policy_refs: vec!["governance:bounded-adoption".to_string()],
        lineage_root_ref: "lineage-root:receiver".to_string(),
        claim_boundary: "bounded local-first ecosystem participant only".to_string(),
        summary: "receiving factory identity manifest".to_string(),
    };

    let exchange_envelope = FactoryExchangeEnvelope {
        exchange_id: "factory-exchange-1".to_string(),
        sender_factory_ref: sender_identity.factory_ref.clone(),
        receiver_scope_ref: receiver_identity.factory_ref.clone(),
        packet_class: FactoryExchangePacketClass::LineageImport,
        payload_refs: vec![
            "payload:lineage-1".to_string(),
            "payload:evidence-1".to_string(),
        ],
        trust_requirements: vec![
            "trust:local-review".to_string(),
            "trust:compatibility-gate".to_string(),
        ],
        rollback_requirements: vec!["rollback:discard-import".to_string()],
    };

    let compatibility_decision = evaluate_factory_exchange_compatibility(
        "factory-compatibility-decision-1",
        &exchange_envelope,
        FactoryCompatibilityVerdict::Compatible,
        FactoryCompatibilityVerdict::Compatible,
        FactoryCompatibilityVerdict::RequiresReview,
        FactoryExchangeDecisionKind::AcceptToQuarantine,
        "incoming packet is compatible enough to enter quarantine-first review",
    )
    .unwrap();
    let quarantine_packet = issue_import_quarantine_packet(
        "factory-quarantine-packet-1",
        &exchange_envelope,
        vec![
            "payload:lineage-1".to_string(),
            "payload:evidence-1".to_string(),
        ],
        vec![
            "review:operator-approval".to_string(),
            "review:compatibility-confirmation".to_string(),
        ],
        vec!["rollback:discard-import".to_string()],
        "incoming packet is quarantined until explicit review completes",
    )
    .unwrap();
    let import_state = record_quarantine_first_import_state(
        "factory-import-state-1",
        &exchange_envelope,
        QuarantineFirstImportStateKind::Admitted,
        vec![
            compatibility_decision.decision_id.clone(),
            quarantine_packet.quarantine_packet_id.clone(),
        ],
        vec!["rollback:discard-import".to_string()],
        "incoming packet remained quarantine-first until bounded review admitted it local-only",
    )
    .unwrap();
    let import_disposition = record_import_disposition(
        "factory-import-disposition-1",
        &exchange_envelope,
        &import_state,
        ImportDispositionKind::AdmitLocalOnly,
        vec!["rollback:discard-import".to_string()],
        "incoming packet was admitted for bounded local-only use after quarantine-first review",
    )
    .unwrap();
    let lineage_import = record_cross_factory_lineage_import(
        "factory-lineage-import-1",
        sender_identity.factory_ref.clone(),
        receiver_identity.factory_ref.clone(),
        vec!["payload:lineage-1".to_string()],
        compatibility_decision.decision_id.clone(),
        "receiver imported lineage under an explicit compatibility decision",
    )
    .unwrap();
    let memory_packet = MemoryExchangePacket {
        memory_exchange_id: "factory-memory-packet-1".to_string(),
        sender_factory_ref: sender_identity.factory_ref.clone(),
        pointer_refs: vec!["pointer:topic-1".to_string(), "pointer:topic-2".to_string()],
        contradiction_refs: vec!["contradiction:shared-1".to_string()],
        freshness_policy: "bounded-review-window".to_string(),
        summary: "compact pointer-driven memory exchange".to_string(),
    };

    store
        .persist_factory_identity_manifest(&sender_identity)
        .unwrap();
    store
        .persist_factory_identity_manifest(&receiver_identity)
        .unwrap();
    store
        .persist_factory_exchange_envelope(&exchange_envelope)
        .unwrap();
    store
        .persist_factory_compatibility_decision(&compatibility_decision)
        .unwrap();
    store
        .persist_imported_artifact_quarantine_packet(&quarantine_packet)
        .unwrap();
    store
        .persist_quarantine_first_import_state(&import_state)
        .unwrap();
    store
        .persist_import_disposition(&import_disposition)
        .unwrap();
    store
        .persist_cross_factory_lineage_import_record(&lineage_import)
        .unwrap();
    store
        .persist_memory_exchange_packet(&memory_packet)
        .unwrap();

    assert_eq!(
        compatibility_decision.decision,
        FactoryExchangeDecisionKind::AcceptToQuarantine
    );
    assert_eq!(
        quarantine_packet.exchange_ref,
        exchange_envelope.exchange_id
    );
    assert_eq!(import_state.exchange_ref, exchange_envelope.exchange_id);
    assert_eq!(
        import_disposition.import_state_ref,
        import_state.import_state_id
    );
    assert_eq!(
        lineage_import.receiver_factory_ref,
        receiver_identity.factory_ref
    );
    assert_eq!(
        memory_packet.sender_factory_ref,
        sender_identity.factory_ref
    );

    assert_eq!(
        store
            .load_factory_identity_manifest(&sender_identity.factory_identity_id)
            .unwrap(),
        sender_identity
    );
    assert_eq!(
        store
            .load_factory_exchange_envelope(&exchange_envelope.exchange_id)
            .unwrap(),
        exchange_envelope
    );
    assert_eq!(
        store
            .load_factory_compatibility_decision(&compatibility_decision.decision_id)
            .unwrap(),
        compatibility_decision
    );
    assert_eq!(
        store
            .load_imported_artifact_quarantine_packet(&quarantine_packet.quarantine_packet_id)
            .unwrap(),
        quarantine_packet
    );
    assert_eq!(
        store
            .load_quarantine_first_import_state(&import_state.import_state_id)
            .unwrap(),
        import_state
    );
    assert_eq!(
        store
            .load_import_disposition(&import_disposition.disposition_id)
            .unwrap(),
        import_disposition
    );
    assert_eq!(
        store
            .load_cross_factory_lineage_import_record(&lineage_import.lineage_import_id)
            .unwrap(),
        lineage_import
    );
    assert_eq!(
        store
            .load_memory_exchange_packet(&memory_packet.memory_exchange_id)
            .unwrap(),
        memory_packet
    );

    fs::remove_dir_all(root).unwrap();
}
