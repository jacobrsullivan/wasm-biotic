use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn contract_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("contracts")
        .join(path)
}

#[test]
fn phase_d_anchor_family_is_present_and_versioned() {
    let readme = fs::read_to_string(contract_path("README.md")).unwrap();
    assert!(readme.contains("PD-01-phase-d-anchor-family.md"));
    assert!(readme.contains("PD-01-exchange-envelope-anchor.md"));

    let manifest_raw =
        fs::read_to_string(contract_path("PD-01-phase-d-anchor-family.json")).unwrap();
    let manifest: Value = serde_json::from_str(&manifest_raw).unwrap();

    assert_eq!(
        manifest["anchor_family_id"].as_str(),
        Some("pd-01-phase-d-anchor-family")
    );
    assert_eq!(
        manifest["identity_anchor_ref"].as_str(),
        Some("PD-01-factory-identity-manifest-anchor.md")
    );
    assert_eq!(
        manifest["exchange_anchor_ref"].as_str(),
        Some("PD-01-exchange-envelope-anchor.md")
    );
    assert_eq!(
        manifest["compatibility_anchor_ref"].as_str(),
        Some("PD-01-compatibility-decision-anchor.md")
    );
    assert_eq!(
        manifest["quarantine_anchor_ref"].as_str(),
        Some("PD-01-import-quarantine-anchor.md")
    );

    let version_refs = manifest["version_refs"]
        .as_array()
        .expect("version_refs should be an array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(version_refs.contains(&"phase-d-local-first"));
    assert!(version_refs.contains(&"phase-d-pre-federation"));
    assert!(version_refs.contains(&"phase-d-quarantine-first"));
    assert!(version_refs.contains(&"phase-d-bounded-memory-exchange"));

    let boundary_statement = manifest["boundary_statement"]
        .as_str()
        .expect("boundary statement should be present");
    assert!(boundary_statement.contains("quarantine-capable packets"));
    assert!(boundary_statement.contains("does not prove federation"));
}

#[test]
fn phase_d_anchor_files_freeze_required_semantics() {
    let identity =
        fs::read_to_string(contract_path("PD-01-factory-identity-manifest-anchor.md")).unwrap();
    assert!(identity.contains("factory_identity_id"));
    assert!(identity.contains("claim_boundary"));
    assert!(identity.contains("local-first ecosystem participant only"));

    let exchange = fs::read_to_string(contract_path("PD-01-exchange-envelope-anchor.md")).unwrap();
    assert!(exchange.contains("sender_identity_ref"));
    assert!(exchange.contains("receiver_scope_ref"));
    assert!(exchange.contains("rollback_requirements"));

    let compatibility =
        fs::read_to_string(contract_path("PD-01-compatibility-decision-anchor.md")).unwrap();
    assert!(compatibility.contains("contract_compatibility"));
    assert!(compatibility.contains("service_compatibility"));
    assert!(compatibility.contains("governance_compatibility"));

    let quarantine =
        fs::read_to_string(contract_path("PD-01-import-quarantine-anchor.md")).unwrap();
    assert!(quarantine.contains("quarantine_packet_id"));
    assert!(quarantine.contains("review_requirements"));
    assert!(quarantine.contains("rollback_refs"));
}
