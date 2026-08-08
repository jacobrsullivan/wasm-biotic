use std::collections::BTreeMap;

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use wasm_biotic_kernel::{
    RELEASE_CERTIFICATION_STATEMENT_SCHEMA, ReleaseCertificationStatement, Sha256Digest,
    SignedReleaseCertification, TrustedCertifier, canonical_json_bytes,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn statement() -> ReleaseCertificationStatement {
    ReleaseCertificationStatement {
        schema: RELEASE_CERTIFICATION_STATEMENT_SCHEMA.to_string(),
        graph_manifest_digest: Sha256Digest::from_bytes(b"manifest"),
        native_tcb_inventory_digest: Sha256Digest::from_bytes(b"native-tcb"),
        wit_package_digest: Sha256Digest::from_bytes(b"wit-package"),
        metadata_digest: Sha256Digest::from_bytes(b"metadata"),
        raw_artifacts: BTreeMap::from([(
            "opaque-node".to_string(),
            Sha256Digest::from_bytes(b"raw"),
        )]),
        derived_artifacts: BTreeMap::from([(
            "opaque-authority".to_string(),
            Sha256Digest::from_bytes(b"derived"),
        )]),
        derivation_descriptor_digest: Sha256Digest::from_bytes(b"descriptor"),
        substrate_profile_digest: Sha256Digest::from_bytes(b"profile"),
        wit_world_digests: BTreeMap::from([(
            "opaque-world".to_string(),
            Sha256Digest::from_bytes(b"world"),
        )]),
        composition_configuration_digests: vec![Sha256Digest::from_bytes(b"configuration")],
        constraint_digests: vec![Sha256Digest::from_bytes(b"constraint")],
        validation_report_digest: Sha256Digest::from_bytes(b"strict-report"),
        validator_identity: "offline-strict-validator".to_string(),
        validator_version: "1.0.0".to_string(),
    }
}

fn signed(
    key_pair: &Ed25519KeyPair,
    statement: ReleaseCertificationStatement,
) -> SignedReleaseCertification {
    let key_id = Sha256Digest::from_bytes(key_pair.public_key().as_ref());
    let payload = SignedReleaseCertification::signing_payload_bytes(&statement, key_id).unwrap();
    SignedReleaseCertification::assemble(key_id, statement, hex(key_pair.sign(&payload).as_ref()))
        .unwrap()
}

#[test]
fn canonical_certificate_verifies_only_for_exact_statement_and_operator_key() {
    let random = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let trust =
        TrustedCertifier::from_public_key_hex(&hex(key_pair.public_key().as_ref())).unwrap();
    let certificate = signed(&key_pair, statement());
    let bytes = certificate.canonical_bytes().unwrap();
    let parsed = SignedReleaseCertification::from_canonical_bytes(&bytes).unwrap();
    parsed.verify_signature(&trust).unwrap();

    let other_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let other = Ed25519KeyPair::from_pkcs8(other_pkcs8.as_ref()).unwrap();
    let wrong_trust =
        TrustedCertifier::from_public_key_hex(&hex(other.public_key().as_ref())).unwrap();
    assert!(parsed.verify_signature(&wrong_trust).is_err());

    let mut substituted = parsed.clone();
    substituted.statement.graph_manifest_digest = Sha256Digest::from_bytes(b"substitution");
    assert!(substituted.verify_signature(&trust).is_err());
}

#[test]
fn noncanonical_extended_and_malformed_certificates_fail_closed() {
    let random = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let certificate = signed(&key_pair, statement());
    let mut bytes = certificate.canonical_bytes().unwrap();
    bytes.push(b'\n');
    assert!(SignedReleaseCertification::from_canonical_bytes(&bytes).is_err());

    let mut extended = serde_json::to_value(&certificate).unwrap();
    extended
        .as_object_mut()
        .unwrap()
        .insert("policy".to_string(), serde_json::Value::Bool(true));
    let extended = canonical_json_bytes(&extended).unwrap();
    assert!(SignedReleaseCertification::from_canonical_bytes(&extended).is_err());

    let mut missing_configuration = certificate;
    missing_configuration
        .statement
        .composition_configuration_digests
        .clear();
    assert!(missing_configuration.canonical_bytes().is_err());
}
