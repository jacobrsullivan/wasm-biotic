use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn contract_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("contracts")
        .join(path)
}

#[test]
fn phase_d_contract_manifest_anchor_is_present_and_cites_pd01() {
    let readme = fs::read_to_string(contract_path("README.md")).unwrap();
    assert!(readme.contains("PD-02-phase-d-contract-manifest-anchor.md"));
    assert!(readme.contains("PD-02-phase-d-contract-manifest-anchor.json"));

    let manifest_raw =
        fs::read_to_string(contract_path("PD-02-phase-d-contract-manifest-anchor.json")).unwrap();
    let manifest: Value = serde_json::from_str(&manifest_raw).unwrap();

    assert_eq!(
        manifest["anchor_id"].as_str(),
        Some("pd-02-phase-d-contract-manifest-anchor")
    );
    assert_eq!(
        manifest["anchor_family_ref"].as_str(),
        Some("PD-01-phase-d-anchor-family.json")
    );
    assert_eq!(
        manifest["schema_kind"].as_str(),
        Some("phase-d-contract-manifest")
    );

    let required_fields = manifest["required_fields"]
        .as_array()
        .expect("required_fields should be an array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(required_fields.contains(&"manifest_id"));
    assert!(required_fields.contains(&"anchor_family_ref"));
    assert!(required_fields.contains(&"claim_boundary"));
}

#[test]
fn phase_d_contract_manifest_anchor_freezes_manifest_semantics() {
    let anchor =
        fs::read_to_string(contract_path("PD-02-phase-d-contract-manifest-anchor.md")).unwrap();
    assert!(anchor.contains("anchor_family_ref"));
    assert!(anchor.contains("manifest_schema_ref"));
    assert!(anchor.contains("sender_identity_refs"));
    assert!(anchor.contains("claim_boundary"));
    assert!(anchor.contains("does not prove federation"));
}
