//! Canonical, policy-neutral release-certification envelopes.
//!
//! The native substrate verifies only one exact artifact set, an Ed25519
//! signature and an independently persisted certifier key. It does not parse
//! the semantic validation report whose digest is carried by the statement.

use crate::{KernelError, Sha256Digest};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Canonical envelope schema accepted by this kernel release.
pub const RELEASE_CERTIFICATION_SCHEMA: &str = "wasm-biotic.release-certification.v1";
/// Canonical signed statement schema accepted by this kernel release.
pub const RELEASE_CERTIFICATION_STATEMENT_SCHEMA: &str =
    "wasm-biotic.release-certification-statement.v1";
const RELEASE_CERTIFICATION_PAYLOAD_SCHEMA: &str =
    "wasm-biotic.release-certification-signing-payload.v1";
const ED25519_ALGORITHM: &str = "ed25519";
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const MAX_OPAQUE_IDENTITY_BYTES: usize = 512;

/// Digest of the machine inventory compiled alongside this kernel source.
#[must_use]
pub fn compiled_native_tcb_inventory_digest() -> Sha256Digest {
    Sha256Digest::from_bytes(include_bytes!("../native-tcb.json"))
}

/// Operator-selected Ed25519 certifier identity persisted outside packages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedCertifier {
    key_id: Sha256Digest,
    public_key_hex: String,
}

impl TrustedCertifier {
    /// Constructs trust from one canonical lowercase raw Ed25519 public key.
    pub fn from_public_key_hex(public_key_hex: &str) -> Result<Self, KernelError> {
        let public_key = decode_lower_hex(
            public_key_hex,
            ED25519_PUBLIC_KEY_BYTES,
            "certifier public key",
        )?;
        Ok(Self {
            key_id: Sha256Digest::from_bytes(&public_key),
            public_key_hex: public_key_hex.to_string(),
        })
    }

    /// SHA-256 identity of the raw public-key bytes.
    #[must_use]
    pub const fn key_id(&self) -> Sha256Digest {
        self.key_id
    }

    fn public_key_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let bytes = decode_lower_hex(
            &self.public_key_hex,
            ED25519_PUBLIC_KEY_BYTES,
            "persisted certifier public key",
        )?;
        if Sha256Digest::from_bytes(&bytes) != self.key_id {
            return Err(KernelError::InvalidConfiguration(
                "persisted certifier key identity does not match its bytes".to_string(),
            ));
        }
        Ok(bytes)
    }
}

/// Exact release artifact set certified by an offline strict checker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseCertificationStatement {
    /// Closed statement schema identifier.
    pub schema: String,
    /// Exact authoritative graph manifest digest.
    pub graph_manifest_digest: Sha256Digest,
    /// Exact native inventory compiled into the admitting kernel.
    pub native_tcb_inventory_digest: Sha256Digest,
    /// Exact WIT package evidence digest.
    pub wit_package_digest: Sha256Digest,
    /// Exact manifest-selected metadata digest.
    pub metadata_digest: Sha256Digest,
    /// Raw component digest keyed by opaque graph node identifier.
    pub raw_artifacts: BTreeMap<String, Sha256Digest>,
    /// Instantiated artifact digest keyed by opaque authority identifier.
    pub derived_artifacts: BTreeMap<String, Sha256Digest>,
    /// Exact derivation descriptor digest.
    pub derivation_descriptor_digest: Sha256Digest,
    /// Exact substrate profile digest.
    pub substrate_profile_digest: Sha256Digest,
    /// Exact WIT world evidence digests keyed by opaque world identifier.
    pub wit_world_digests: BTreeMap<String, Sha256Digest>,
    /// Sorted unique exact composition-configuration digests.
    pub composition_configuration_digests: Vec<Sha256Digest>,
    /// Sorted unique exact immutable-constraint digests.
    pub constraint_digests: Vec<Sha256Digest>,
    /// Exact canonical offline validation-report digest.
    pub validation_report_digest: Sha256Digest,
    /// Opaque identity of the offline certifier.
    pub validator_identity: String,
    /// Opaque version of the offline certifier.
    pub validator_version: String,
}

/// Detached Ed25519 signature over a canonical certification payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseCertificationSignature {
    /// Closed signature algorithm identifier.
    pub algorithm: String,
    /// Canonical lowercase detached signature bytes.
    pub signature_hex: String,
}

/// Canonical signed certificate carried by a graph package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseCertification {
    /// Closed certificate envelope schema identifier.
    pub schema: String,
    /// SHA-256 identity of the raw operator-pinned public key.
    pub certifier_key_id: Sha256Digest,
    /// Exact content-set statement covered by the signature.
    pub statement: ReleaseCertificationStatement,
    /// Detached signature metadata and bytes.
    pub signature: ReleaseCertificationSignature,
}

#[derive(Serialize)]
struct SigningPayload<'a> {
    certifier_key_id: Sha256Digest,
    schema: &'static str,
    statement: &'a ReleaseCertificationStatement,
}

impl SignedReleaseCertification {
    /// Builds a certificate from an externally produced signature.
    pub fn assemble(
        certifier_key_id: Sha256Digest,
        statement: ReleaseCertificationStatement,
        signature_hex: String,
    ) -> Result<Self, KernelError> {
        let certificate = Self {
            schema: RELEASE_CERTIFICATION_SCHEMA.to_string(),
            certifier_key_id,
            statement,
            signature: ReleaseCertificationSignature {
                algorithm: ED25519_ALGORITHM.to_string(),
                signature_hex,
            },
        };
        certificate.validate_shape()?;
        Ok(certificate)
    }

    /// Canonical bytes signed by the certifier.
    pub fn signing_payload_bytes(
        statement: &ReleaseCertificationStatement,
        certifier_key_id: Sha256Digest,
    ) -> Result<Vec<u8>, KernelError> {
        validate_statement(statement)?;
        canonical_json_bytes(&SigningPayload {
            certifier_key_id,
            schema: RELEASE_CERTIFICATION_PAYLOAD_SCHEMA,
            statement,
        })
    }

    /// Parses exact canonical certificate bytes and rejects every extension.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, KernelError> {
        let certificate: Self = parse_canonical_json(bytes, "release certification")?;
        certificate.validate_shape()?;
        Ok(certificate)
    }

    /// Returns exact canonical certificate bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        self.validate_shape()?;
        canonical_json_bytes(self)
    }

    /// Verifies the key identity and detached Ed25519 signature only.
    pub fn verify_signature(&self, trust: &TrustedCertifier) -> Result<(), KernelError> {
        self.validate_shape()?;
        if self.certifier_key_id != trust.key_id() {
            return Err(KernelError::InvalidConfiguration(
                "release certification signer does not match operator trust".to_string(),
            ));
        }
        let public_key = trust.public_key_bytes()?;
        let signature = decode_lower_hex(
            &self.signature.signature_hex,
            ED25519_SIGNATURE_BYTES,
            "release certification signature",
        )?;
        let payload = Self::signing_payload_bytes(&self.statement, self.certifier_key_id)?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&payload, &signature)
            .map_err(|_| {
                KernelError::InvalidConfiguration(
                    "release certification signature verification failed".to_string(),
                )
            })
    }

    fn validate_shape(&self) -> Result<(), KernelError> {
        if self.schema != RELEASE_CERTIFICATION_SCHEMA
            || self.signature.algorithm != ED25519_ALGORITHM
        {
            return Err(KernelError::InvalidConfiguration(
                "release certification schema or signature algorithm is unsupported".to_string(),
            ));
        }
        validate_statement(&self.statement)?;
        decode_lower_hex(
            &self.signature.signature_hex,
            ED25519_SIGNATURE_BYTES,
            "release certification signature",
        )?;
        Ok(())
    }
}

/// Canonical JSON used by both offline evidence emission and native checking.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, KernelError> {
    let value = serde_json::to_value(value)
        .map_err(|error| KernelError::ManifestDecode(error.to_string()))?;
    let mut bytes = Vec::new();
    write_canonical_value(&value, &mut bytes)?;
    Ok(bytes)
}

fn validate_statement(value: &ReleaseCertificationStatement) -> Result<(), KernelError> {
    if value.schema != RELEASE_CERTIFICATION_STATEMENT_SCHEMA
        || value.raw_artifacts.is_empty()
        || value.derived_artifacts.is_empty()
        || value.wit_world_digests.is_empty()
        || value.composition_configuration_digests.is_empty()
        || value.constraint_digests.is_empty()
        || !strictly_sorted(&value.composition_configuration_digests)
        || !strictly_sorted(&value.constraint_digests)
        || !valid_opaque_identity(&value.validator_identity)
        || !valid_opaque_identity(&value.validator_version)
        || value
            .raw_artifacts
            .keys()
            .any(|key| !valid_opaque_identity(key))
        || value
            .derived_artifacts
            .keys()
            .any(|key| !valid_opaque_identity(key))
        || value
            .wit_world_digests
            .keys()
            .any(|key| !valid_opaque_identity(key))
    {
        return Err(KernelError::InvalidConfiguration(
            "release certification statement is empty, non-canonical or out of bounds".to_string(),
        ));
    }
    Ok(())
}

fn valid_opaque_identity(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_OPAQUE_IDENTITY_BYTES
        && !value.chars().any(char::is_control)
}

fn strictly_sorted(values: &[Sha256Digest]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn parse_canonical_json<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    subject: &str,
) -> Result<T, KernelError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| KernelError::ManifestDecode(format!("{subject}: {error}")))?;
    let mut canonical = Vec::new();
    write_canonical_value(&value, &mut canonical)?;
    if canonical != bytes {
        return Err(KernelError::ManifestDecode(format!(
            "{subject} is not canonical JSON"
        )));
    }
    let parsed: T = serde_json::from_value(value)
        .map_err(|error| KernelError::ManifestDecode(format!("{subject}: {error}")))?;
    if canonical_json_bytes(&parsed)? != bytes {
        return Err(KernelError::ManifestDecode(format!(
            "{subject} is not the canonical closed-schema representation"
        )));
    }
    Ok(parsed)
}

fn write_canonical_value(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), KernelError> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" });
        }
        serde_json::Value::Number(number) => {
            if number.is_f64() {
                return Err(KernelError::ManifestDecode(
                    "floating-point values are outside the certification domain".to_string(),
                ));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        serde_json::Value::String(value) => output.extend_from_slice(
            &serde_json::to_vec(value)
                .map_err(|error| KernelError::ManifestDecode(error.to_string()))?,
        ),
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(&serde_json::Value::String(key.clone()), output)?;
                output.push(b':');
                write_canonical_value(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn decode_lower_hex(value: &str, bytes: usize, subject: &str) -> Result<Vec<u8>, KernelError> {
    if value.len() != bytes * 2
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(KernelError::InvalidConfiguration(format!(
            "{subject} is not canonical lowercase hexadecimal"
        )));
    }
    (0..bytes)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
                KernelError::InvalidConfiguration(format!("{subject} contains invalid hexadecimal"))
            })
        })
        .collect()
}
