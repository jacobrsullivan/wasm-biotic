use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArtifactDigest(pub String);

impl ArtifactDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, ArtifactError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ArtifactError::MissingDigest);
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hash = 0xcbf29ce484222325u64;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        Self(format!("aiaf-digest-{hash:016x}-{:016x}", bytes.len()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn file_stem(&self) -> String {
        self.0
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                    character
                } else {
                    '-'
                }
            })
            .collect()
    }
}

impl Display for ArtifactDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// A cryptographic identity for exact content bytes.
///
/// `ArtifactDigest` remains the compatibility identifier used by the existing
/// artifact model. New code that needs collision-resistant content identity
/// should use this type instead.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ContentDigest(String);

impl ContentDigest {
    const PREFIX: &'static str = "sha256:";
    const HEX_LENGTH: usize = 64;

    pub fn new(value: impl Into<String>) -> Result<Self, ContentDigestError> {
        let value = value.into();
        if !Self::has_valid_format(&value) {
            return Err(ContentDigestError::InvalidFormat);
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let hash = Sha256::digest(bytes);
        Self(format!("{}{:x}", Self::PREFIX, hash))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn file_stem(&self) -> String {
        format!("sha256-{}", &self.0[Self::PREFIX.len()..])
    }

    fn has_valid_format(value: &str) -> bool {
        value.len() == Self::PREFIX.len() + Self::HEX_LENGTH
            && value.starts_with(Self::PREFIX)
            && value.as_bytes()[Self::PREFIX.len()..]
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    }
}

impl Display for ContentDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ContentDigest {
    type Err = ContentDigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for ContentDigest {
    type Error = ContentDigestError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentDigestError {
    InvalidFormat,
}

impl Display for ContentDigestError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(
                f,
                "content digest must match sha256:<64 lowercase hexadecimal characters>"
            ),
        }
    }
}

impl Error for ContentDigestError {}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GenerationArtifactId(pub String);

impl GenerationArtifactId {
    pub fn new(value: impl Into<String>) -> Result<Self, ArtifactError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ArtifactError::MissingGenerationId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Display for GenerationArtifactId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationManifest {
    pub artifact_id: GenerationArtifactId,
    pub parent_digest: Option<ArtifactDigest>,
    pub stable_interface_ref: String,
    pub wit_world: String,
    pub source_refs: Vec<String>,
    pub policy_refs: Vec<String>,
    pub build_input_refs: Vec<String>,
    pub summary: String,
}

impl GenerationManifest {
    pub fn new(
        artifact_id: impl Into<String>,
        parent_digest: Option<ArtifactDigest>,
        stable_interface_ref: impl Into<String>,
        wit_world: impl Into<String>,
        source_refs: Vec<String>,
        policy_refs: Vec<String>,
        build_input_refs: Vec<String>,
        summary: impl Into<String>,
    ) -> Result<Self, ArtifactError> {
        let manifest = Self {
            artifact_id: GenerationArtifactId::new(artifact_id)?,
            parent_digest,
            stable_interface_ref: stable_interface_ref.into(),
            wit_world: wit_world.into(),
            source_refs,
            policy_refs,
            build_input_refs,
            summary: summary.into(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.stable_interface_ref.trim().is_empty() {
            return Err(ArtifactError::MissingStableInterface);
        }
        if self.wit_world.trim().is_empty() {
            return Err(ArtifactError::MissingWitWorld);
        }
        if self.source_refs.is_empty() {
            return Err(ArtifactError::MissingSourceRefs);
        }
        if self.build_input_refs.is_empty() {
            return Err(ArtifactError::MissingBuildInputs);
        }
        Ok(())
    }

    pub fn manifest_digest(&self) -> Result<ArtifactDigest, ArtifactError> {
        digest_json(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildClosureManifest {
    pub build_id: String,
    pub generation_id: GenerationArtifactId,
    pub toolchain_ref: String,
    pub input_digests: Vec<ArtifactDigest>,
    pub output_digest: ArtifactDigest,
    pub diagnostics: Vec<String>,
}

impl BuildClosureManifest {
    pub fn new(
        build_id: impl Into<String>,
        generation_id: GenerationArtifactId,
        toolchain_ref: impl Into<String>,
        input_digests: Vec<ArtifactDigest>,
        output_digest: ArtifactDigest,
        diagnostics: Vec<String>,
    ) -> Result<Self, ArtifactError> {
        let build = Self {
            build_id: build_id.into(),
            generation_id,
            toolchain_ref: toolchain_ref.into(),
            input_digests,
            output_digest,
            diagnostics,
        };
        build.validate()?;
        Ok(build)
    }

    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.build_id.trim().is_empty() {
            return Err(ArtifactError::MissingBuildId);
        }
        if self.toolchain_ref.trim().is_empty() {
            return Err(ArtifactError::MissingToolchainRef);
        }
        if self.input_digests.is_empty() {
            return Err(ArtifactError::MissingBuildInputs);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageBundleManifest {
    pub package_id: String,
    pub generation_id: GenerationArtifactId,
    pub artifact_digest: ArtifactDigest,
    pub component_digest: ArtifactDigest,
    pub interface_exports: Vec<String>,
    pub interface_imports: Vec<String>,
    pub capability_world_refs: Vec<String>,
    pub bundle_digest: ArtifactDigest,
}

impl PackageBundleManifest {
    pub fn new(
        package_id: impl Into<String>,
        generation_id: GenerationArtifactId,
        artifact_digest: ArtifactDigest,
        component_digest: ArtifactDigest,
        interface_exports: Vec<String>,
        interface_imports: Vec<String>,
        capability_world_refs: Vec<String>,
    ) -> Result<Self, ArtifactError> {
        let package_id = package_id.into();
        if package_id.trim().is_empty() {
            return Err(ArtifactError::MissingPackageId);
        }
        if interface_exports.is_empty() {
            return Err(ArtifactError::MissingInterfaceExports);
        }
        if capability_world_refs.is_empty() {
            return Err(ArtifactError::MissingCapabilityWorldRefs);
        }

        let bundle_digest = digest_json(&PackageBundleDigestInput {
            package_id: package_id.clone(),
            generation_id: generation_id.clone(),
            artifact_digest: artifact_digest.clone(),
            component_digest: component_digest.clone(),
            interface_exports: interface_exports.clone(),
            interface_imports: interface_imports.clone(),
            capability_world_refs: capability_world_refs.clone(),
        })?;

        Ok(Self {
            package_id,
            generation_id,
            artifact_digest,
            component_digest,
            interface_exports,
            interface_imports,
            capability_world_refs,
            bundle_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ArtifactError> {
        let expected = digest_json(&PackageBundleDigestInput {
            package_id: self.package_id.clone(),
            generation_id: self.generation_id.clone(),
            artifact_digest: self.artifact_digest.clone(),
            component_digest: self.component_digest.clone(),
            interface_exports: self.interface_exports.clone(),
            interface_imports: self.interface_imports.clone(),
            capability_world_refs: self.capability_world_refs.clone(),
        })?;
        if expected != self.bundle_digest {
            return Err(ArtifactError::DigestMismatch {
                expected,
                actual: self.bundle_digest.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct PackageBundleDigestInput {
    package_id: String,
    generation_id: GenerationArtifactId,
    artifact_digest: ArtifactDigest,
    component_digest: ArtifactDigest,
    interface_exports: Vec<String>,
    interface_imports: Vec<String>,
    capability_world_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationEnvelope {
    pub activation_id: String,
    pub generation_id: GenerationArtifactId,
    pub package_digest: ArtifactDigest,
    pub required_capability_world_refs: Vec<String>,
    pub rollback_package_digest: Option<ArtifactDigest>,
    pub observation_window_ref: String,
    pub approved: bool,
}

impl ActivationEnvelope {
    pub fn new(
        activation_id: impl Into<String>,
        generation_id: GenerationArtifactId,
        package_digest: ArtifactDigest,
        required_capability_world_refs: Vec<String>,
        rollback_package_digest: Option<ArtifactDigest>,
        observation_window_ref: impl Into<String>,
        approved: bool,
    ) -> Result<Self, ArtifactError> {
        let envelope = Self {
            activation_id: activation_id.into(),
            generation_id,
            package_digest,
            required_capability_world_refs,
            rollback_package_digest,
            observation_window_ref: observation_window_ref.into(),
            approved,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.activation_id.trim().is_empty() {
            return Err(ArtifactError::MissingActivationId);
        }
        if self.required_capability_world_refs.is_empty() {
            return Err(ArtifactError::MissingCapabilityWorldRefs);
        }
        if self.observation_window_ref.trim().is_empty() {
            return Err(ArtifactError::MissingObservationWindow);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactLineageRecord {
    pub lineage_id: String,
    pub generation_id: GenerationArtifactId,
    pub parent_digest: Option<ArtifactDigest>,
    pub generation_digest: ArtifactDigest,
    pub package_digest: ArtifactDigest,
    pub produced_by_generation_digest: Option<ArtifactDigest>,
    pub evidence_refs: Vec<String>,
}

impl ArtifactLineageRecord {
    pub fn new(
        lineage_id: impl Into<String>,
        generation_id: GenerationArtifactId,
        parent_digest: Option<ArtifactDigest>,
        generation_digest: ArtifactDigest,
        package_digest: ArtifactDigest,
        produced_by_generation_digest: Option<ArtifactDigest>,
        evidence_refs: Vec<String>,
    ) -> Result<Self, ArtifactError> {
        let lineage = Self {
            lineage_id: lineage_id.into(),
            generation_id,
            parent_digest,
            generation_digest,
            package_digest,
            produced_by_generation_digest,
            evidence_refs,
        };
        lineage.validate()?;
        Ok(lineage)
    }

    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.lineage_id.trim().is_empty() {
            return Err(ArtifactError::MissingLineageId);
        }
        if self.evidence_refs.is_empty() {
            return Err(ArtifactError::MissingLineageEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationArtifactBundle {
    pub manifest: GenerationManifest,
    pub build: BuildClosureManifest,
    pub package: PackageBundleManifest,
    pub activation: ActivationEnvelope,
    pub lineage: ArtifactLineageRecord,
}

impl GenerationArtifactBundle {
    pub fn new(
        manifest: GenerationManifest,
        build: BuildClosureManifest,
        package: PackageBundleManifest,
        activation: ActivationEnvelope,
        lineage: ArtifactLineageRecord,
    ) -> Result<Self, ArtifactError> {
        let bundle = Self {
            manifest,
            build,
            package,
            activation,
            lineage,
        };
        validate_generation_artifact_bundle(&bundle)?;
        Ok(bundle)
    }

    pub fn package_digest(&self) -> &ArtifactDigest {
        &self.package.bundle_digest
    }
}

pub fn digest_json<T: Serialize>(value: &T) -> Result<ArtifactDigest, ArtifactError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ArtifactError::Serialization(error.to_string()))?;
    Ok(ArtifactDigest::from_bytes(&bytes))
}

pub fn digest_json_content<T: Serialize>(value: &T) -> Result<ContentDigest, ArtifactError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ArtifactError::Serialization(error.to_string()))?;
    Ok(ContentDigest::from_bytes(&bytes))
}

pub fn validate_generation_artifact_bundle(
    bundle: &GenerationArtifactBundle,
) -> Result<(), ArtifactError> {
    bundle.manifest.validate()?;
    bundle.build.validate()?;
    bundle.package.validate()?;
    bundle.activation.validate()?;
    bundle.lineage.validate()?;

    let manifest_digest = bundle.manifest.manifest_digest()?;
    if !bundle
        .build
        .input_digests
        .iter()
        .any(|digest| digest == &manifest_digest)
    {
        return Err(ArtifactError::MissingManifestDigestInBuild { manifest_digest });
    }
    if bundle.build.generation_id != bundle.manifest.artifact_id
        || bundle.package.generation_id != bundle.manifest.artifact_id
        || bundle.activation.generation_id != bundle.manifest.artifact_id
        || bundle.lineage.generation_id != bundle.manifest.artifact_id
    {
        return Err(ArtifactError::GenerationIdMismatch);
    }
    if bundle.package.artifact_digest != manifest_digest {
        return Err(ArtifactError::DigestMismatch {
            expected: manifest_digest,
            actual: bundle.package.artifact_digest.clone(),
        });
    }
    if bundle.package.component_digest != bundle.build.output_digest {
        return Err(ArtifactError::DigestMismatch {
            expected: bundle.build.output_digest.clone(),
            actual: bundle.package.component_digest.clone(),
        });
    }
    if bundle.activation.package_digest != bundle.package.bundle_digest {
        return Err(ArtifactError::DigestMismatch {
            expected: bundle.package.bundle_digest.clone(),
            actual: bundle.activation.package_digest.clone(),
        });
    }
    if bundle.lineage.parent_digest != bundle.manifest.parent_digest {
        return Err(ArtifactError::LineageParentMismatch);
    }
    if bundle.lineage.package_digest != bundle.package.bundle_digest {
        return Err(ArtifactError::DigestMismatch {
            expected: bundle.package.bundle_digest.clone(),
            actual: bundle.lineage.package_digest.clone(),
        });
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactError {
    MissingDigest,
    MissingGenerationId,
    MissingStableInterface,
    MissingWitWorld,
    MissingSourceRefs,
    MissingBuildInputs,
    MissingBuildId,
    MissingToolchainRef,
    MissingPackageId,
    MissingInterfaceExports,
    MissingCapabilityWorldRefs,
    MissingActivationId,
    MissingObservationWindow,
    MissingLineageId,
    MissingLineageEvidence,
    MissingManifestDigestInBuild {
        manifest_digest: ArtifactDigest,
    },
    GenerationIdMismatch,
    LineageParentMismatch,
    DigestMismatch {
        expected: ArtifactDigest,
        actual: ArtifactDigest,
    },
    Serialization(String),
}

impl Display for ArtifactError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDigest => write!(f, "artifact digest cannot be empty"),
            Self::MissingGenerationId => write!(f, "generation artifact id cannot be empty"),
            Self::MissingStableInterface => {
                write!(f, "generation artifact requires a stable interface ref")
            }
            Self::MissingWitWorld => write!(f, "generation artifact requires a WIT world ref"),
            Self::MissingSourceRefs => write!(f, "generation artifact requires source refs"),
            Self::MissingBuildInputs => write!(f, "generation artifact requires build inputs"),
            Self::MissingBuildId => write!(f, "build closure requires a build id"),
            Self::MissingToolchainRef => write!(f, "build closure requires a toolchain ref"),
            Self::MissingPackageId => write!(f, "package bundle requires a package id"),
            Self::MissingInterfaceExports => write!(f, "package bundle requires interface exports"),
            Self::MissingCapabilityWorldRefs => {
                write!(f, "package bundle requires capability world refs")
            }
            Self::MissingActivationId => write!(f, "activation envelope requires an activation id"),
            Self::MissingObservationWindow => {
                write!(f, "activation envelope requires an observation window ref")
            }
            Self::MissingLineageId => write!(f, "artifact lineage requires a lineage id"),
            Self::MissingLineageEvidence => write!(f, "artifact lineage requires evidence refs"),
            Self::MissingManifestDigestInBuild { manifest_digest } => write!(
                f,
                "build closure does not cite manifest digest {manifest_digest}"
            ),
            Self::GenerationIdMismatch => write!(f, "generation artifact ids do not align"),
            Self::LineageParentMismatch => write!(
                f,
                "lineage parent digest does not match manifest parent digest"
            ),
            Self::DigestMismatch { expected, actual } => {
                write!(
                    f,
                    "artifact digest mismatch: expected {expected}, got {actual}"
                )
            }
            Self::Serialization(error) => write!(f, "artifact serialization error: {error}"),
        }
    }
}

impl Error for ArtifactError {}

#[cfg(test)]
mod tests {
    use super::{ArtifactDigest, ContentDigest, ContentDigestError, digest_json_content};
    use serde::Serialize;

    #[test]
    fn legacy_artifact_digest_vectors_remain_byte_for_byte_compatible() {
        assert_eq!(
            ArtifactDigest::from_bytes(b"").as_str(),
            "aiaf-digest-cbf29ce484222325-0000000000000000"
        );
        assert_eq!(
            ArtifactDigest::from_bytes(b"abc").as_str(),
            "aiaf-digest-e71fa2190541574b-0000000000000003"
        );
    }

    #[test]
    fn content_digest_uses_sha256_test_vectors() {
        assert_eq!(
            ContentDigest::from_bytes(b"").as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            ContentDigest::from_bytes(b"abc").as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn content_digest_parsing_is_strict_and_file_safe() {
        let encoded = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let digest: ContentDigest = encoded.parse().expect("valid digest");

        assert_eq!(digest.as_str(), encoded);
        assert_eq!(digest.to_string(), encoded);
        assert_eq!(
            digest.file_stem(),
            "sha256-ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(ContentDigest::try_from(encoded), Ok(digest));
    }

    #[test]
    fn content_digest_rejects_noncanonical_encodings() {
        let invalid = [
            "",
            "sha256:",
            "SHA256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015a",
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015add",
            "sha256:ga7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            " sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ];

        for value in invalid {
            assert_eq!(
                ContentDigest::new(value),
                Err(ContentDigestError::InvalidFormat),
                "{value:?} must be rejected"
            );
        }
    }

    #[test]
    fn content_digest_serde_round_trip_enforces_the_invariant() {
        let digest = ContentDigest::from_bytes(b"candidate component");
        let encoded = serde_json::to_string(&digest).expect("serialize digest");

        assert_eq!(
            serde_json::from_str::<ContentDigest>(&encoded).expect("deserialize digest"),
            digest
        );
        assert!(
            serde_json::from_str::<ContentDigest>(
                "\"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\""
            )
            .is_err()
        );
    }

    #[derive(Serialize)]
    struct JsonFixture<'a> {
        name: &'a str,
        generation: u8,
    }

    #[test]
    fn json_content_digest_hashes_the_exact_serialized_bytes() {
        let fixture = JsonFixture {
            name: "candidate",
            generation: 1,
        };
        let serialized = serde_json::to_vec(&fixture).expect("serialize fixture");

        assert_eq!(
            digest_json_content(&fixture).expect("digest fixture"),
            ContentDigest::from_bytes(&serialized)
        );
    }
}
