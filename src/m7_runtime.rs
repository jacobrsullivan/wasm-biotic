//! Bounded, local-first persistence for an operational M7 closure dossier.
//!
//! This runtime owns only the evidence boundary. It never runs a milestone,
//! invents evidence, calls a provider, or chooses a closure outcome. Exact
//! canonical artifacts are frozen into a content-addressed store and the pure
//! [`crate::m7_closure::evaluate_m7_closure`] evaluator remains the sole source
//! of the resulting decision.

use crate::execution::{ContentDigest, digest_json_content};
use crate::m7_closure::{
    EvidenceResolveError, EvidenceResolver, IndependentReviewerEvidence, M7ClosureDecision,
    M7DerivedEvidenceV2, M7Evaluation, M7EvidenceArtifact, M7EvidenceKind, M7EvidenceLink,
    M7EvidencePayload, M7ExternalEd25519IdentityV1, M7FinalBundle, M7FoundationError,
    M7IndependentReviewSourceV2, M7ProofRunManifest, M7SourceCaptureAttestationV2, M7SourceInputV2,
    M7SourceLinkV2, M7SourceRoleV2, evaluate_m7_closure, mandatory_evidence_kinds,
    reviewed_evidence_set_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const M7_REVIEW_REQUEST_SCHEMA: &str = "wasm-biotic.m7-independent-review-request.v5";
const M7_STORED_EVIDENCE_INDEX_SCHEMA: &str = "wasm-biotic.m7-stored-evidence-index.v5";

const REVIEW_REQUEST_DOMAIN: &str = "wasm-biotic:m7-independent-review-request:v5";
const OWNER_LOCK_FILE: &str = ".m7-dossier.lock";
const MANIFEST_FILE: &str = "proof-run-manifest.json";
const REVIEW_REQUEST_FILE: &str = "independent-review-request.json";
const FINAL_BUNDLE_FILE: &str = "final-bundle.json";
const EVIDENCE_DIRECTORY: &str = "evidence";
const LINKS_DIRECTORY: &str = "links";
const STAGING_DIRECTORY: &str = "staging";
const MAX_MANIFEST_BYTES: usize = 2 * 1_048_576;
const MAX_EVIDENCE_BYTES: usize = 256 * 1_048_576;
const MAX_ARTIFACT_BYTES: usize = 32 * 1_048_576;
const MAX_LINK_BYTES: usize = 256 * 1_024;
const MAX_CONTROL_BYTES: usize = 4 * 1_048_576;
const MAX_STORED_ARTIFACTS: usize = 128;
const MAX_TOTAL_EVIDENCE_BYTES: u64 = 384 * 1_048_576;
const MAX_IDENTIFIER_BYTES: usize = 512;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7IndependentReviewRequest {
    schema: String,
    proof_run_id: String,
    manifest_digest: ContentDigest,
    reviewer_identity: M7ExternalEd25519IdentityV1,
    reviewed_evidence_links: Vec<M7EvidenceLink>,
    live_provider_link: Option<M7EvidenceLink>,
    source_links: Vec<M7SourceLinkV2>,
    reviewed_evidence_set_digest: ContentDigest,
    request_digest: ContentDigest,
}

#[derive(Serialize)]
struct ReviewRequestDigestMaterial<'a> {
    domain: &'static str,
    proof_run_id: &'a str,
    manifest_digest: &'a ContentDigest,
    reviewer_identity: &'a M7ExternalEd25519IdentityV1,
    reviewed_evidence_links: &'a [M7EvidenceLink],
    live_provider_link: &'a Option<M7EvidenceLink>,
    source_links: &'a [M7SourceLinkV2],
    reviewed_evidence_set_digest: &'a ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct M7StoredEvidenceIndexV2 {
    schema: String,
    evidence_link: M7EvidenceLink,
    source_links: Vec<M7SourceLinkV2>,
}

impl M7IndependentReviewRequest {
    fn new(
        manifest: &M7ProofRunManifest,
        mut reviewed_evidence_links: Vec<M7EvidenceLink>,
        live_provider_link: Option<M7EvidenceLink>,
        mut source_links: Vec<M7SourceLinkV2>,
    ) -> Result<Self, M7DossierError> {
        reviewed_evidence_links
            .sort_by(|left, right| (left.kind, &left.digest).cmp(&(right.kind, &right.digest)));
        source_links.sort_by(|left, right| {
            (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
        });
        let set_digest = reviewed_evidence_set_digest(
            manifest,
            &reviewed_evidence_links,
            live_provider_link.as_ref(),
            &source_links,
        )
        .map_err(M7DossierError::foundation)?;
        let mut request = Self {
            schema: M7_REVIEW_REQUEST_SCHEMA.to_string(),
            proof_run_id: manifest.proof_run_id().to_string(),
            manifest_digest: manifest.manifest_digest().clone(),
            reviewer_identity: manifest.reviewer_identity().clone(),
            reviewed_evidence_links,
            live_provider_link,
            source_links,
            reviewed_evidence_set_digest: set_digest,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = request.expected_digest()?;
        request.validate(manifest)?;
        Ok(request)
    }

    pub fn reviewer_id(&self) -> &str {
        self.reviewer_identity.principal_id()
    }

    pub fn reviewer_identity_digest(&self) -> &ContentDigest {
        self.reviewer_identity.identity_digest()
    }

    pub fn reviewer_identity(&self) -> &M7ExternalEd25519IdentityV1 {
        &self.reviewer_identity
    }

    pub fn reviewed_evidence_set_digest(&self) -> &ContentDigest {
        &self.reviewed_evidence_set_digest
    }

    pub fn request_digest(&self) -> &ContentDigest {
        &self.request_digest
    }

    pub fn reviewed_evidence_links(&self) -> &[M7EvidenceLink] {
        &self.reviewed_evidence_links
    }

    pub fn live_provider_link(&self) -> Option<&M7EvidenceLink> {
        self.live_provider_link.as_ref()
    }

    pub fn source_links(&self) -> &[M7SourceLinkV2] {
        &self.source_links
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7DossierError> {
        self.validate_fields()?;
        canonical_json(self)
    }

    fn from_canonical_bytes(
        bytes: &[u8],
        manifest: &M7ProofRunManifest,
    ) -> Result<Self, M7DossierError> {
        if bytes.is_empty() || bytes.len() > MAX_CONTROL_BYTES {
            return Err(M7DossierError::ResourceExhausted(
                "review request exceeds its byte budget".to_string(),
            ));
        }
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|error| M7DossierError::Serialization(error.to_string()))?;
        if canonical_json(&request)? != bytes {
            return Err(M7DossierError::Integrity(
                "review request is not canonical JSON".to_string(),
            ));
        }
        request.validate(manifest)?;
        Ok(request)
    }

    fn validate(&self, manifest: &M7ProofRunManifest) -> Result<(), M7DossierError> {
        self.validate_fields()?;
        if self.proof_run_id != manifest.proof_run_id()
            || &self.manifest_digest != manifest.manifest_digest()
            || &self.reviewer_identity != manifest.reviewer_identity()
        {
            return Err(M7DossierError::Integrity(
                "review request is bound to another proof run or manifest".to_string(),
            ));
        }
        if manifest
            .implementation_principal_ids()
            .contains(self.reviewer_identity.principal_id())
            || manifest
                .implementation_identity_digests()
                .contains(self.reviewer_identity.identity_digest())
            || manifest
                .implementation_identity_digests()
                .contains(self.reviewer_identity.public_key_digest())
        {
            return Err(M7DossierError::ReviewerNotIndependent);
        }
        let expected = reviewed_evidence_set_digest(
            manifest,
            &self.reviewed_evidence_links,
            self.live_provider_link.as_ref(),
            &self.source_links,
        )
        .map_err(M7DossierError::foundation)?;
        if expected != self.reviewed_evidence_set_digest {
            return Err(M7DossierError::Integrity(
                "reviewed evidence-set digest does not match the frozen links".to_string(),
            ));
        }
        if self.expected_digest()? != self.request_digest {
            return Err(M7DossierError::Integrity(
                "review request digest mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), M7DossierError> {
        if self.schema != M7_REVIEW_REQUEST_SCHEMA {
            return Err(M7DossierError::Integrity(
                "unsupported review-request schema".to_string(),
            ));
        }
        validate_identifier("review proof_run_id", &self.proof_run_id)?;
        self.reviewer_identity
            .validate()
            .map_err(M7DossierError::foundation)?;
        let expected = mandatory_non_review_kinds();
        let actual: BTreeSet<_> = self
            .reviewed_evidence_links
            .iter()
            .map(|link| link.kind)
            .collect();
        if actual != expected
            || self.reviewed_evidence_links.len() != expected.len()
            || self.reviewed_evidence_links.iter().any(|link| {
                link.kind == M7EvidenceKind::IndependentReviewerRecommendation
                    || link.kind == M7EvidenceKind::LiveProviderQualification
            })
        {
            return Err(M7DossierError::ReviewNotReady(
                "review request must freeze exactly every mandatory non-review artifact"
                    .to_string(),
            ));
        }
        let mut ordered = self.reviewed_evidence_links.clone();
        ordered.sort_by(|left, right| (left.kind, &left.digest).cmp(&(right.kind, &right.digest)));
        if ordered != self.reviewed_evidence_links {
            return Err(M7DossierError::Integrity(
                "review request evidence links are not canonically ordered".to_string(),
            ));
        }
        if self
            .live_provider_link
            .as_ref()
            .is_some_and(|link| link.kind != M7EvidenceKind::LiveProviderQualification)
        {
            return Err(M7DossierError::ProviderScopeMismatch);
        }
        let mut roles = BTreeSet::new();
        let mut ordered_sources = self.source_links.clone();
        ordered_sources.sort_by(|left, right| {
            (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
        });
        if ordered_sources != self.source_links
            || self.source_links.iter().any(|link| {
                link.semantic_role == M7SourceRoleV2::IndependentReview
                    || !roles.insert(link.semantic_role)
            })
        {
            return Err(M7DossierError::Integrity(
                "review request source closure is duplicated, includes review output, or is not canonical"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7DossierError> {
        digest_json_content(&ReviewRequestDigestMaterial {
            domain: REVIEW_REQUEST_DOMAIN,
            proof_run_id: &self.proof_run_id,
            manifest_digest: &self.manifest_digest,
            reviewer_identity: &self.reviewer_identity,
            reviewed_evidence_links: &self.reviewed_evidence_links,
            live_provider_link: &self.live_provider_link,
            source_links: &self.source_links,
            reviewed_evidence_set_digest: &self.reviewed_evidence_set_digest,
        })
        .map_err(|error| M7DossierError::Serialization(error.to_string()))
    }
}

/// Read-only resolver over the dossier's content-addressed evidence directory.
#[derive(Clone, Debug)]
pub struct M7FileEvidenceResolver {
    evidence_root: PathBuf,
}

impl EvidenceResolver for M7FileEvidenceResolver {
    fn resolve(&self, digest: &ContentDigest) -> Result<Option<Vec<u8>>, EvidenceResolveError> {
        let path = evidence_path(&self.evidence_root, digest);
        if !path.exists() {
            return Ok(None);
        }
        read_regular_bounded(&path, MAX_EVIDENCE_BYTES)
            .map(Some)
            .map_err(|error| EvidenceResolveError {
                message: error.to_string(),
            })
    }
}

/// A single-owner writer and read-only evaluator for one frozen proof run.
///
/// `_owner_lock` is deliberately last, so all in-memory state is dropped
/// before another process may acquire ownership.
pub struct M7DossierRuntime {
    root: PathBuf,
    evidence_root: PathBuf,
    links_root: PathBuf,
    staging_root: PathBuf,
    manifest: M7ProofRunManifest,
    links: BTreeMap<M7EvidenceKind, M7EvidenceLink>,
    artifact_sources: BTreeMap<M7EvidenceKind, Vec<M7SourceLinkV2>>,
    review_request: Option<M7IndependentReviewRequest>,
    final_bundle: Option<M7FinalBundle>,
    _owner_lock: File,
}

impl M7DossierRuntime {
    /// Create or idempotently reopen a dossier for this exact manifest.
    pub fn open(
        root: impl AsRef<Path>,
        manifest: M7ProofRunManifest,
    ) -> Result<Self, M7DossierError> {
        let manifest_bytes = manifest
            .canonical_bytes()
            .map_err(M7DossierError::foundation)?;
        let root = secure_create_root(root.as_ref())?;
        let owner_lock = acquire_owner_lock(&root)?;
        validate_root_entries(&root)?;
        let evidence_root = secure_child_directory(&root, EVIDENCE_DIRECTORY)?;
        let links_root = secure_child_directory(&root, LINKS_DIRECTORY)?;
        let staging_root = secure_child_directory(&root, STAGING_DIRECTORY)?;
        recover_staging(&staging_root)?;

        let manifest_path = root.join(MANIFEST_FILE);
        persist_immutable(
            &staging_root,
            &manifest_path,
            &manifest_bytes,
            MAX_MANIFEST_BYTES,
        )?;
        let stored_manifest_bytes = read_regular_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
        let stored_manifest = M7ProofRunManifest::from_canonical_bytes(&stored_manifest_bytes)
            .map_err(M7DossierError::foundation)?;
        if stored_manifest != manifest {
            return Err(M7DossierError::Conflict(
                "dossier already belongs to a different proof-run manifest".to_string(),
            ));
        }
        Self::finish_open(
            root,
            evidence_root,
            links_root,
            staging_root,
            stored_manifest,
            owner_lock,
        )
    }

    /// Reopen an existing dossier using only its immutable manifest.
    pub fn reopen(root: impl AsRef<Path>) -> Result<Self, M7DossierError> {
        let root = secure_existing_root(root.as_ref())?;
        let owner_lock = acquire_owner_lock(&root)?;
        validate_root_entries(&root)?;
        let evidence_root = secure_existing_child_directory(&root, EVIDENCE_DIRECTORY)?;
        let links_root = secure_existing_child_directory(&root, LINKS_DIRECTORY)?;
        let staging_root = secure_existing_child_directory(&root, STAGING_DIRECTORY)?;
        recover_staging(&staging_root)?;
        let manifest_bytes = read_regular_bounded(&root.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
        let manifest = M7ProofRunManifest::from_canonical_bytes(&manifest_bytes)
            .map_err(M7DossierError::foundation)?;
        Self::finish_open(
            root,
            evidence_root,
            links_root,
            staging_root,
            manifest,
            owner_lock,
        )
    }

    fn finish_open(
        root: PathBuf,
        evidence_root: PathBuf,
        links_root: PathBuf,
        staging_root: PathBuf,
        manifest: M7ProofRunManifest,
        owner_lock: File,
    ) -> Result<Self, M7DossierError> {
        validate_evidence_directory(&evidence_root)?;
        let (links, artifact_sources) = load_links(&links_root, &manifest)?;
        let review_request = load_optional_review_request(&root, &manifest)?;
        if let Some(request) = &review_request {
            validate_review_request_against_links(request, &links, &artifact_sources)?;
        } else if links.contains_key(&M7EvidenceKind::IndependentReviewerRecommendation) {
            return Err(M7DossierError::Integrity(
                "reviewer evidence exists without a durable review request".to_string(),
            ));
        }
        let final_bundle = load_optional_final_bundle(&root)?;
        if let Some(bundle) = &final_bundle {
            validate_final_bundle_against_state(
                bundle,
                &manifest,
                review_request.as_ref(),
                &links,
                &artifact_sources,
            )?;
        }
        Ok(Self {
            root,
            evidence_root,
            links_root,
            staging_root,
            manifest,
            links,
            artifact_sources,
            review_request,
            final_bundle,
            _owner_lock: owner_lock,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest(&self) -> &M7ProofRunManifest {
        &self.manifest
    }

    pub fn evidence_links(&self) -> &BTreeMap<M7EvidenceKind, M7EvidenceLink> {
        &self.links
    }

    pub fn source_links(&self) -> &BTreeMap<M7EvidenceKind, Vec<M7SourceLinkV2>> {
        &self.artifact_sources
    }

    /// Build the exact pre-review inventory that an external source custodian
    /// must inspect and sign.
    ///
    /// Every non-transcript role comes from evidence already admitted to this
    /// dossier. The Cargo transcript is supplied separately because its
    /// evidence artifact cannot be derived until the resulting detached
    /// source-capture signature exists.
    pub fn source_capture_inventory(
        &self,
        transcript_bytes: &[u8],
    ) -> Result<Vec<M7SourceLinkV2>, M7DossierError> {
        if self.review_request.is_some() || self.final_bundle.is_some() {
            return Err(M7DossierError::Conflict(
                "source capture must finish before independent review begins".to_string(),
            ));
        }
        if self
            .links
            .contains_key(&M7EvidenceKind::DeterministicTestTranscript)
            || self
                .links
                .contains_key(&M7EvidenceKind::IndependentReviewerRecommendation)
        {
            return Err(M7DossierError::Conflict(
                "source-capture inventory cannot be rebuilt after capture or review evidence is admitted"
                    .to_string(),
            ));
        }

        let mut expected = mandatory_non_review_kinds();
        expected.remove(&M7EvidenceKind::DeterministicTestTranscript);
        let actual = self
            .links
            .keys()
            .copied()
            .filter(|kind| *kind != M7EvidenceKind::LiveProviderQualification)
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(M7DossierError::ReviewNotReady(
                "source capture requires every mandatory non-transcript artifact first".to_string(),
            ));
        }
        match (
            self.manifest.live_provider_scope().is_some(),
            self.links
                .contains_key(&M7EvidenceKind::LiveProviderQualification),
        ) {
            (true, false) => {
                return Err(M7DossierError::ReviewNotReady(
                    "the manifest-scoped live-provider artifact is absent".to_string(),
                ));
            }
            (false, true) => return Err(M7DossierError::ProviderScopeMismatch),
            _ => {}
        }

        let transcript_input = M7SourceInputV2::new(
            M7SourceRoleV2::CargoTestTranscript,
            transcript_bytes.to_vec(),
        );
        let transcript_subject = M7EvidenceArtifact::derive_causal_subject_from_sources(
            &self.manifest,
            M7EvidenceKind::DeterministicTestTranscript,
            std::slice::from_ref(&transcript_input),
        )
        .map_err(M7DossierError::foundation)?;
        let mut inventory = canonical_source_union(&self.artifact_sources, false)?;
        inventory.push(
            M7SourceLinkV2::from_source_bytes(
                &self.manifest,
                transcript_subject,
                M7SourceRoleV2::CargoTestTranscript,
                transcript_bytes,
            )
            .map_err(M7DossierError::foundation)?,
        );
        inventory.sort_by(|left, right| {
            (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
        });
        let validation_time = self
            .manifest
            .run_started_at_ms()
            .checked_add(1)
            .ok_or_else(|| {
                M7DossierError::Integrity(
                    "proof-run start time leaves no valid source-capture timestamp".to_string(),
                )
            })?;
        M7SourceCaptureAttestationV2::signing_preimage(&self.manifest, &inventory, validation_time)
            .map_err(M7DossierError::foundation)?;
        Ok(inventory)
    }

    /// Export the detached source-capture signing bytes without ever handling
    /// the custodian's private key.
    pub fn source_capture_signing_preimage(
        &self,
        transcript_bytes: &[u8],
        captured_at_ms: u64,
    ) -> Result<Vec<u8>, M7DossierError> {
        let inventory = self.source_capture_inventory(transcript_bytes)?;
        M7SourceCaptureAttestationV2::signing_preimage(&self.manifest, &inventory, captured_at_ms)
            .map_err(M7DossierError::foundation)
    }

    /// Verify an externally supplied source-custodian signature and admit the
    /// resulting deterministic-test artifact plus both exact source records.
    pub fn admit_source_capture_signature(
        &mut self,
        transcript_bytes: &[u8],
        captured_at_ms: u64,
        signature: &[u8],
    ) -> Result<M7EvidenceLink, M7DossierError> {
        let inventory = self.source_capture_inventory(transcript_bytes)?;
        let attestation = M7SourceCaptureAttestationV2::from_external_signature(
            &self.manifest,
            &inventory,
            captured_at_ms,
            signature,
        )
        .map_err(M7DossierError::foundation)?;
        let attestation_bytes = attestation
            .canonical_bytes(&self.manifest)
            .map_err(M7DossierError::foundation)?;
        let derived = M7EvidenceArtifact::derive_from_sources(
            &self.manifest,
            M7EvidenceKind::DeterministicTestTranscript,
            vec![
                M7SourceInputV2::new(
                    M7SourceRoleV2::CargoTestTranscript,
                    transcript_bytes.to_vec(),
                ),
                M7SourceInputV2::new(M7SourceRoleV2::SourceCaptureAttestation, attestation_bytes),
            ],
        )
        .map_err(M7DossierError::foundation)?;
        self.admit_derived_evidence(&derived)
    }

    pub fn review_request(&self) -> Option<&M7IndependentReviewRequest> {
        self.review_request.as_ref()
    }

    pub fn final_bundle(&self) -> Option<&M7FinalBundle> {
        self.final_bundle.as_ref()
    }

    pub fn resolver(&self) -> M7FileEvidenceResolver {
        M7FileEvidenceResolver {
            evidence_root: self.evidence_root.clone(),
        }
    }

    /// Persist a typed derived artifact and its exact authoritative source
    /// closure. Source bytes are content-addressed before the evidence index;
    /// an interruption can therefore leave only harmless unreferenced bytes.
    pub fn admit_derived_evidence(
        &mut self,
        derived: &M7DerivedEvidenceV2,
    ) -> Result<M7EvidenceLink, M7DossierError> {
        let artifact = derived.artifact();
        let kind = artifact.kind();
        if self.final_bundle.is_some()
            || (self.review_request.is_some()
                && kind != M7EvidenceKind::IndependentReviewerRecommendation
                && !self.links.contains_key(&kind))
        {
            return Err(M7DossierError::Conflict(
                "dossier evidence boundary is already frozen".to_string(),
            ));
        }
        if artifact.source_links().len() != derived.source_blobs().len()
            || artifact.source_links().iter().any(|link| {
                !derived.source_blobs().iter().any(|blob| {
                    blob.link() == link
                        && ContentDigest::from_bytes(blob.bytes()) == link.digest
                        && blob.bytes().len() as u64 == link.byte_length
                })
            })
        {
            return Err(M7DossierError::InvalidEvidence(
                "derived artifact and supplied source blobs disagree".to_string(),
            ));
        }
        for blob in derived.source_blobs() {
            let destination = evidence_path(&self.evidence_root, &blob.link().digest);
            ensure_evidence_capacity(&self.evidence_root, &destination, blob.bytes().len())?;
            persist_immutable(
                &self.staging_root,
                &destination,
                blob.bytes(),
                MAX_EVIDENCE_BYTES,
            )?;
        }
        self.admit_evidence_bytes(
            &derived
                .artifact_bytes()
                .map_err(M7DossierError::foundation)?,
        )
    }

    /// Admit exact canonical evidence. Independent review is admitted only
    /// through a previously frozen review request.
    pub fn admit_evidence_bytes(&mut self, bytes: &[u8]) -> Result<M7EvidenceLink, M7DossierError> {
        if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(M7DossierError::ResourceExhausted(format!(
                "evidence bytes must be in 1..={MAX_ARTIFACT_BYTES}"
            )));
        }
        let artifact: M7EvidenceArtifact = serde_json::from_slice(bytes)
            .map_err(|error| M7DossierError::InvalidEvidence(error.to_string()))?;
        let canonical = artifact
            .canonical_bytes()
            .map_err(M7DossierError::foundation)?;
        if canonical != bytes {
            return Err(M7DossierError::InvalidEvidence(
                "artifact is not canonical JSON".to_string(),
            ));
        }
        let link = artifact
            .evidence_link()
            .map_err(M7DossierError::foundation)?;
        self.validate_artifact_binding(&artifact, &link)?;
        self.validate_artifact_sources_available(&artifact, &link)?;

        if let Some(existing) = self.links.get(&link.kind) {
            if existing != &link {
                return Err(M7DossierError::Conflict(format!(
                    "evidence kind {:?} is already frozen to different bytes",
                    link.kind
                )));
            }
            let existing_bytes = read_regular_bounded(
                &evidence_path(&self.evidence_root, &link.digest),
                MAX_ARTIFACT_BYTES,
            )?;
            if existing_bytes != bytes {
                return Err(M7DossierError::Integrity(format!(
                    "content-addressed evidence {} is missing or corrupt",
                    link.digest
                )));
            }
            return Ok(link);
        }

        if self.final_bundle.is_some() {
            return Err(M7DossierError::Conflict(
                "final dossier is immutable".to_string(),
            ));
        }
        match link.kind {
            M7EvidenceKind::IndependentReviewerRecommendation => {
                self.validate_reviewer_artifact(&artifact)?;
            }
            _ => {
                if self.review_request.is_some() {
                    return Err(M7DossierError::Conflict(
                        "non-review evidence is frozen once review is requested".to_string(),
                    ));
                }
                self.validate_non_reviewer_artifact(&artifact)?;
            }
        }
        if self.links.len() >= MAX_STORED_ARTIFACTS {
            return Err(M7DossierError::ResourceExhausted(
                "dossier evidence-count budget exhausted".to_string(),
            ));
        }
        let destination = evidence_path(&self.evidence_root, &link.digest);
        ensure_evidence_capacity(&self.evidence_root, &destination, bytes.len())?;
        persist_immutable(&self.staging_root, &destination, bytes, MAX_ARTIFACT_BYTES)?;
        let index = M7StoredEvidenceIndexV2 {
            schema: M7_STORED_EVIDENCE_INDEX_SCHEMA.to_string(),
            evidence_link: link.clone(),
            source_links: artifact.source_links().to_vec(),
        };
        let link_bytes = canonical_json(&index)?;
        persist_immutable(
            &self.staging_root,
            &link_path(&self.links_root, link.kind),
            &link_bytes,
            MAX_LINK_BYTES,
        )?;
        self.links.insert(link.kind, link.clone());
        self.artifact_sources
            .insert(link.kind, artifact.source_links().to_vec());
        Ok(link)
    }

    /// Freeze the complete non-review evidence set before independent review.
    pub fn begin_independent_review(
        &mut self,
    ) -> Result<M7IndependentReviewRequest, M7DossierError> {
        if self.final_bundle.is_some() {
            return Err(M7DossierError::Conflict(
                "final dossier is immutable".to_string(),
            ));
        }
        let non_review = self.mandatory_non_review_links()?;
        let provider = self
            .links
            .get(&M7EvidenceKind::LiveProviderQualification)
            .cloned();
        let source_links = canonical_source_union(&self.artifact_sources, false)?;
        let request =
            M7IndependentReviewRequest::new(&self.manifest, non_review, provider, source_links)?;
        if let Some(existing) = &self.review_request {
            return if existing == &request {
                Ok(existing.clone())
            } else {
                Err(M7DossierError::Conflict(
                    "independent review was already requested with different scope or identity"
                        .to_string(),
                ))
            };
        }
        let bytes = request.canonical_bytes()?;
        persist_immutable(
            &self.staging_root,
            &self.root.join(REVIEW_REQUEST_FILE),
            &bytes,
            MAX_CONTROL_BYTES,
        )?;
        self.review_request = Some(request.clone());
        Ok(request)
    }

    /// Export the exact bytes the pre-pinned independent reviewer must sign.
    /// Rationale and independence statement contents stay with the reviewer;
    /// their exact SHA-256 identities are signed and admitted into the dossier.
    pub fn independent_review_signing_preimage(
        &self,
        recommendation: M7ClosureDecision,
        rationale_digest: ContentDigest,
        independence_statement_digest: ContentDigest,
    ) -> Result<Vec<u8>, M7DossierError> {
        if self.final_bundle.is_some()
            || self
                .links
                .contains_key(&M7EvidenceKind::IndependentReviewerRecommendation)
        {
            return Err(M7DossierError::Conflict(
                "independent review is already admitted or finalized".to_string(),
            ));
        }
        let request = self.review_request.as_ref().ok_or_else(|| {
            M7DossierError::ReviewNotReady("independent review has not been requested".to_string())
        })?;
        M7IndependentReviewSourceV2::signing_preimage(
            request.reviewer_identity(),
            self.manifest.manifest_digest().clone(),
            request.reviewed_evidence_set_digest().clone(),
            recommendation,
            rationale_digest,
            independence_statement_digest,
        )
        .map_err(M7DossierError::foundation)
    }

    /// Verify the detached reviewer signature against the immutable review
    /// request, then admit the exact independent-review source and artifact.
    pub fn admit_independent_review_signature(
        &mut self,
        recommendation: M7ClosureDecision,
        rationale_digest: ContentDigest,
        independence_statement_digest: ContentDigest,
        signature: &[u8],
    ) -> Result<M7EvidenceLink, M7DossierError> {
        if self.final_bundle.is_some()
            || self
                .links
                .contains_key(&M7EvidenceKind::IndependentReviewerRecommendation)
        {
            return Err(M7DossierError::Conflict(
                "independent review is already admitted or finalized".to_string(),
            ));
        }
        let request = self.review_request.clone().ok_or_else(|| {
            M7DossierError::ReviewNotReady("independent review has not been requested".to_string())
        })?;
        let source = M7IndependentReviewSourceV2::from_external_signature(
            request.reviewer_identity().clone(),
            self.manifest.manifest_digest().clone(),
            request.reviewed_evidence_set_digest().clone(),
            recommendation,
            rationale_digest,
            independence_statement_digest,
            signature,
        )
        .map_err(M7DossierError::foundation)?;
        let source_bytes = source
            .canonical_bytes()
            .map_err(M7DossierError::foundation)?;
        let derived = M7EvidenceArtifact::derive_from_sources(
            &self.manifest,
            M7EvidenceKind::IndependentReviewerRecommendation,
            vec![M7SourceInputV2::new(
                M7SourceRoleV2::IndependentReview,
                source_bytes,
            )],
        )
        .map_err(M7DossierError::foundation)?;
        self.admit_derived_evidence(&derived)
    }

    /// Seal an immutable final bundle. This operation never evaluates it.
    pub fn finalize(&mut self) -> Result<M7FinalBundle, M7DossierError> {
        if let Some(existing) = &self.final_bundle {
            return Ok(existing.clone());
        }
        let request = self.review_request.as_ref().ok_or_else(|| {
            M7DossierError::ReviewNotReady("independent review has not been requested".to_string())
        })?;
        validate_review_request_against_links(request, &self.links, &self.artifact_sources)?;
        if !self
            .links
            .contains_key(&M7EvidenceKind::IndependentReviewerRecommendation)
        {
            return Err(M7DossierError::ReviewNotReady(
                "independent reviewer artifact is absent".to_string(),
            ));
        }
        let release_links = mandatory_evidence_kinds()
            .into_iter()
            .map(|kind| {
                self.links.get(&kind).cloned().ok_or_else(|| {
                    M7DossierError::ReviewNotReady(format!("mandatory evidence {kind:?} is absent"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let provider = self
            .links
            .get(&M7EvidenceKind::LiveProviderQualification)
            .cloned();
        let source_links = canonical_source_union(&self.artifact_sources, true)?;
        let bundle =
            M7FinalBundle::new(self.manifest.clone(), release_links, provider, source_links)
                .map_err(M7DossierError::foundation)?;
        let bytes = bundle
            .canonical_bytes()
            .map_err(M7DossierError::foundation)?;
        persist_immutable(
            &self.staging_root,
            &self.root.join(FINAL_BUNDLE_FILE),
            &bytes,
            MAX_CONTROL_BYTES,
        )?;
        self.final_bundle = Some(bundle.clone());
        Ok(bundle)
    }

    /// Evaluate the immutable final bundle through the filesystem resolver.
    ///
    /// Missing, corrupt, or semantically failing evidence is reported by the
    /// pure evaluator as `NotYet`; this method never repairs or rewrites it.
    pub fn evaluate_final(&self) -> Result<M7Evaluation, M7DossierError> {
        let bundle = self.final_bundle.as_ref().ok_or_else(|| {
            M7DossierError::ReviewNotReady("final bundle has not been sealed".to_string())
        })?;
        Ok(evaluate_m7_closure(bundle, &self.resolver()))
    }

    fn validate_artifact_binding(
        &self,
        artifact: &M7EvidenceArtifact,
        link: &M7EvidenceLink,
    ) -> Result<(), M7DossierError> {
        if link.proof_run_id != self.manifest.proof_run_id() {
            return Err(M7DossierError::WrongProofRun);
        }
        if artifact.manifest_digest() != self.manifest.manifest_digest() {
            return Err(M7DossierError::StaleManifest);
        }
        if link.causal_subject.proof_chain_digest != *self.manifest.causal_chain_digest() {
            return Err(M7DossierError::CausalMismatch);
        }
        if link.owner_milestone != link.kind.owner_milestone()
            || link.causal_subject.kind != link.kind.expected_causal_kind()
        {
            return Err(M7DossierError::InvalidEvidence(
                "evidence kind, owner, and causal subject disagree".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_artifact_sources_available(
        &self,
        artifact: &M7EvidenceArtifact,
        link: &M7EvidenceLink,
    ) -> Result<(), M7DossierError> {
        if artifact.kind() == M7EvidenceKind::M6FactoryExchange
            && artifact.source_links().is_empty()
        {
            let expected = M7EvidenceArtifact::unresolved_m6(
                &self.manifest,
                link.causal_subject.subject_digest.clone(),
            )
            .map_err(M7DossierError::foundation)?;
            if artifact != &expected {
                return Err(M7DossierError::InvalidEvidence(
                    "source-less M6 evidence must be the exact unresolved artifact".to_string(),
                ));
            }
            return Ok(());
        }
        if artifact.source_links().is_empty() {
            return Err(M7DossierError::InvalidEvidence(
                "source-v2 evidence has no authoritative sources".to_string(),
            ));
        }
        let mut inputs = Vec::with_capacity(artifact.source_links().len());
        for source in artifact.source_links() {
            let bytes = read_regular_bounded(
                &evidence_path(&self.evidence_root, &source.digest),
                MAX_EVIDENCE_BYTES,
            )?;
            if bytes.len() as u64 != source.byte_length
                || ContentDigest::from_bytes(&bytes) != source.digest
            {
                return Err(M7DossierError::Integrity(format!(
                    "authoritative source {:?} is missing, truncated, or corrupt",
                    source.semantic_role
                )));
            }
            inputs.push(M7SourceInputV2::new(source.semantic_role, bytes));
        }
        let derived =
            M7EvidenceArtifact::derive_from_sources(&self.manifest, artifact.kind(), inputs)
                .map_err(M7DossierError::foundation)?;
        if derived.artifact() != artifact {
            return Err(M7DossierError::InvalidEvidence(
                "artifact payload was not exactly rederived from its source bytes".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_non_reviewer_artifact(
        &self,
        artifact: &M7EvidenceArtifact,
    ) -> Result<(), M7DossierError> {
        match artifact.payload() {
            M7EvidencePayload::IndependentReviewerRecommendation(_) => {
                Err(M7DossierError::ReviewNotReady(
                    "reviewer evidence requires a frozen review request".to_string(),
                ))
            }
            M7EvidencePayload::LiveProviderQualification(provider) => {
                let expected = self
                    .manifest
                    .live_provider_scope()
                    .ok_or(M7DossierError::ProviderScopeMismatch)?;
                if &provider.scope_digest != expected.scope_digest() {
                    return Err(M7DossierError::ProviderScopeMismatch);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn validate_reviewer_artifact(
        &self,
        artifact: &M7EvidenceArtifact,
    ) -> Result<(), M7DossierError> {
        let request = self.review_request.as_ref().ok_or_else(|| {
            M7DossierError::ReviewNotReady(
                "reviewer evidence arrived before a durable review request".to_string(),
            )
        })?;
        let review = match artifact.payload() {
            M7EvidencePayload::IndependentReviewerRecommendation(review) => review,
            _ => {
                return Err(M7DossierError::ReviewerScopeMismatch);
            }
        };
        validate_reviewer_payload(review, request, &self.manifest)
    }

    fn mandatory_non_review_links(&self) -> Result<Vec<M7EvidenceLink>, M7DossierError> {
        mandatory_non_review_kinds()
            .into_iter()
            .map(|kind| {
                self.links.get(&kind).cloned().ok_or_else(|| {
                    M7DossierError::ReviewNotReady(format!(
                        "mandatory non-review evidence {kind:?} is absent"
                    ))
                })
            })
            .collect()
    }
}

fn validate_reviewer_payload(
    review: &IndependentReviewerEvidence,
    request: &M7IndependentReviewRequest,
    manifest: &M7ProofRunManifest,
) -> Result<(), M7DossierError> {
    if manifest
        .implementation_principal_ids()
        .contains(&review.reviewer_id)
        || manifest
            .implementation_identity_digests()
            .contains(&review.reviewer_identity_digest)
        || manifest
            .implementation_identity_digests()
            .contains(&review.reviewer_public_key_digest)
    {
        return Err(M7DossierError::ReviewerNotIndependent);
    }
    if review.reviewer_id != request.reviewer_id()
        || &review.reviewer_identity_digest != request.reviewer_identity_digest()
        || review.reviewer_public_key_digest != *request.reviewer_identity().public_key_digest()
        || review.reviewed_manifest_digest != *manifest.manifest_digest()
        || review.reviewed_evidence_set_digest != request.reviewed_evidence_set_digest
    {
        return Err(M7DossierError::ReviewerScopeMismatch);
    }
    Ok(())
}

fn mandatory_non_review_kinds() -> BTreeSet<M7EvidenceKind> {
    mandatory_evidence_kinds()
        .into_iter()
        .filter(|kind| *kind != M7EvidenceKind::IndependentReviewerRecommendation)
        .collect()
}

fn canonical_source_union(
    artifact_sources: &BTreeMap<M7EvidenceKind, Vec<M7SourceLinkV2>>,
    include_review: bool,
) -> Result<Vec<M7SourceLinkV2>, M7DossierError> {
    let mut links = artifact_sources
        .iter()
        .filter(|(kind, _)| {
            include_review || **kind != M7EvidenceKind::IndependentReviewerRecommendation
        })
        .flat_map(|(_, links)| links.iter().cloned())
        .collect::<Vec<_>>();
    links.sort_by(|left, right| {
        (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
    });
    let mut roles = BTreeSet::new();
    if links.iter().any(|link| !roles.insert(link.semantic_role)) {
        return Err(M7DossierError::Integrity(
            "dossier repeats a semantic source role".to_string(),
        ));
    }
    Ok(links)
}

fn validate_review_request_against_links(
    request: &M7IndependentReviewRequest,
    links: &BTreeMap<M7EvidenceKind, M7EvidenceLink>,
    artifact_sources: &BTreeMap<M7EvidenceKind, Vec<M7SourceLinkV2>>,
) -> Result<(), M7DossierError> {
    let frozen = mandatory_non_review_kinds()
        .into_iter()
        .map(|kind| {
            links.get(&kind).cloned().ok_or_else(|| {
                M7DossierError::Integrity(format!(
                    "frozen review scope lost mandatory link {kind:?}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut frozen = frozen;
    frozen.sort_by(|left, right| (left.kind, &left.digest).cmp(&(right.kind, &right.digest)));
    if frozen != request.reviewed_evidence_links {
        return Err(M7DossierError::Integrity(
            "durable non-review links differ from the frozen review scope".to_string(),
        ));
    }
    let provider = links
        .get(&M7EvidenceKind::LiveProviderQualification)
        .cloned();
    if provider != request.live_provider_link {
        return Err(M7DossierError::Integrity(
            "durable provider link differs from the frozen review scope".to_string(),
        ));
    }
    if canonical_source_union(artifact_sources, false)? != request.source_links {
        return Err(M7DossierError::Integrity(
            "durable source closure differs from the frozen review scope".to_string(),
        ));
    }
    Ok(())
}

fn validate_final_bundle_against_state(
    bundle: &M7FinalBundle,
    manifest: &M7ProofRunManifest,
    review_request: Option<&M7IndependentReviewRequest>,
    links: &BTreeMap<M7EvidenceKind, M7EvidenceLink>,
    artifact_sources: &BTreeMap<M7EvidenceKind, Vec<M7SourceLinkV2>>,
) -> Result<(), M7DossierError> {
    if bundle.manifest() != manifest {
        return Err(M7DossierError::Integrity(
            "final bundle manifest differs from the dossier manifest".to_string(),
        ));
    }
    let review_request = review_request.ok_or_else(|| {
        M7DossierError::Integrity(
            "final bundle exists without its immutable independent-review request".to_string(),
        )
    })?;
    if bundle.reviewer_identity() != review_request.reviewer_identity() {
        return Err(M7DossierError::Integrity(
            "final bundle reviewer identity differs from the pre-review public-key pin".to_string(),
        ));
    }
    let expected: BTreeMap<_, _> = bundle
        .evidence_links()
        .iter()
        .cloned()
        .chain(bundle.live_provider_link().cloned())
        .map(|link| (link.kind, link))
        .collect();
    if &expected != links {
        return Err(M7DossierError::Integrity(
            "final bundle links differ from the immutable dossier catalog".to_string(),
        ));
    }
    if bundle.source_links() != canonical_source_union(artifact_sources, true)? {
        return Err(M7DossierError::Integrity(
            "final bundle sources differ from the immutable dossier catalog".to_string(),
        ));
    }
    Ok(())
}

fn load_links(
    links_root: &Path,
    manifest: &M7ProofRunManifest,
) -> Result<
    (
        BTreeMap<M7EvidenceKind, M7EvidenceLink>,
        BTreeMap<M7EvidenceKind, Vec<M7SourceLinkV2>>,
    ),
    M7DossierError,
> {
    let mut links = BTreeMap::new();
    let mut artifact_sources = BTreeMap::new();
    let entries =
        fs::read_dir(links_root).map_err(|source| M7DossierError::io(links_root, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| M7DossierError::io(links_root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let metadata = fs::metadata(&path).map_err(|source| M7DossierError::io(&path, source))?;
        if !metadata.is_file() {
            return Err(M7DossierError::UnsafePath(path));
        }
        if links.len() >= MAX_STORED_ARTIFACTS {
            return Err(M7DossierError::ResourceExhausted(
                "stored link-count budget exhausted".to_string(),
            ));
        }
        let bytes = read_regular_bounded(&path, MAX_LINK_BYTES)?;
        let index: M7StoredEvidenceIndexV2 = serde_json::from_slice(&bytes)
            .map_err(|error| M7DossierError::Serialization(error.to_string()))?;
        let link = &index.evidence_link;
        if index.schema != M7_STORED_EVIDENCE_INDEX_SCHEMA
            || canonical_json(&index)? != bytes
            || path.file_name().and_then(|name| name.to_str()) != Some(kind_file_name(link.kind))
        {
            return Err(M7DossierError::Integrity(format!(
                "link record '{}' is non-canonical or misnamed",
                path.display()
            )));
        }
        validate_loaded_link(&link, manifest)?;
        let mut roles = BTreeSet::new();
        if index.source_links.iter().any(|source| {
            source
                .validate_for(manifest, link.kind, &link.causal_subject)
                .is_err()
                || !roles.insert(source.semantic_role)
        }) {
            return Err(M7DossierError::Integrity(
                "stored evidence index contains invalid or duplicate source roles".to_string(),
            ));
        }
        if links.insert(link.kind, link.clone()).is_some()
            || artifact_sources
                .insert(link.kind, index.source_links)
                .is_some()
        {
            return Err(M7DossierError::Integrity(
                "duplicate evidence-kind link".to_string(),
            ));
        }
    }
    Ok((links, artifact_sources))
}

fn validate_loaded_link(
    link: &M7EvidenceLink,
    manifest: &M7ProofRunManifest,
) -> Result<(), M7DossierError> {
    if link.proof_run_id != manifest.proof_run_id() {
        return Err(M7DossierError::WrongProofRun);
    }
    if link.owner_milestone != link.kind.owner_milestone()
        || link.causal_subject.kind != link.kind.expected_causal_kind()
        || link.causal_subject.proof_chain_digest != *manifest.causal_chain_digest()
        || link.byte_length == 0
        || link.byte_length > MAX_ARTIFACT_BYTES as u64
    {
        return Err(M7DossierError::Integrity(
            "stored evidence link has invalid owner, causal chain, or size".to_string(),
        ));
    }
    Ok(())
}

fn load_optional_review_request(
    root: &Path,
    manifest: &M7ProofRunManifest,
) -> Result<Option<M7IndependentReviewRequest>, M7DossierError> {
    let path = root.join(REVIEW_REQUEST_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = read_regular_bounded(&path, MAX_CONTROL_BYTES)?;
    M7IndependentReviewRequest::from_canonical_bytes(&bytes, manifest).map(Some)
}

fn load_optional_final_bundle(root: &Path) -> Result<Option<M7FinalBundle>, M7DossierError> {
    let path = root.join(FINAL_BUNDLE_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = read_regular_bounded(&path, MAX_CONTROL_BYTES)?;
    M7FinalBundle::from_canonical_bytes(&bytes)
        .map(Some)
        .map_err(M7DossierError::foundation)
}

fn evidence_path(root: &Path, digest: &ContentDigest) -> PathBuf {
    root.join(format!("{}.json", digest.file_stem()))
}

fn link_path(root: &Path, kind: M7EvidenceKind) -> PathBuf {
    root.join(kind_file_name(kind))
}

fn kind_file_name(kind: M7EvidenceKind) -> &'static str {
    match kind {
        M7EvidenceKind::M0TruthBaseline => "m0-truth-baseline.json",
        M7EvidenceKind::M1CandidateLifecycle => "m1-candidate-lifecycle.json",
        M7EvidenceKind::M2SchedulerWakeRestart => "m2-scheduler-wake-restart.json",
        M7EvidenceKind::M3CapabilityEffects => "m3-capability-effects.json",
        M7EvidenceKind::M4WorkerEcology => "m4-worker-ecology.json",
        M7EvidenceKind::M5ActivationRollback => "m5-activation-rollback.json",
        M7EvidenceKind::M6FactoryExchange => "m6-factory-exchange.json",
        M7EvidenceKind::DeterministicTestTranscript => "deterministic-test-transcript.json",
        M7EvidenceKind::ClaimBoundary => "claim-boundary.json",
        M7EvidenceKind::PublicationPolicy => "publication-policy.json",
        M7EvidenceKind::IndependentReviewerRecommendation => {
            "independent-reviewer-recommendation.json"
        }
        M7EvidenceKind::LiveProviderQualification => "live-provider-qualification.json",
    }
}

fn persist_immutable(
    staging_root: &Path,
    destination: &Path,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), M7DossierError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(M7DossierError::ResourceExhausted(format!(
            "record '{}' exceeds its byte budget",
            destination.display()
        )));
    }
    if path_entry_exists(destination)? {
        reject_symlink(destination)?;
        let existing = read_regular_bounded(destination, maximum)?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(M7DossierError::Conflict(format!(
                "immutable record '{}' contains different bytes",
                destination.display()
            )))
        };
    }
    let parent = destination
        .parent()
        .ok_or_else(|| M7DossierError::UnsafePath(destination.to_path_buf()))?;
    let temporary = staging_root.join(format!(
        ".building-{}-{}-{}",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("record"),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|source| M7DossierError::io(&temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| M7DossierError::io(&temporary, source))?;
        file.sync_all()
            .map_err(|source| M7DossierError::io(&temporary, source))?;
        fs::rename(&temporary, destination)
            .map_err(|source| M7DossierError::io(destination, source))?;
        sync_directory(parent)?;
        sync_directory(staging_root)
    })();
    if result.is_err() && temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_regular_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, M7DossierError> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|source| M7DossierError::io(path, source))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(M7DossierError::ResourceExhausted(format!(
            "'{}' is not a regular file or exceeds {maximum} bytes",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| file.take(maximum as u64 + 1).read_to_end(&mut bytes))
        .map_err(|source| M7DossierError::io(path, source))?;
    if bytes.len() > maximum {
        return Err(M7DossierError::ResourceExhausted(format!(
            "'{}' exceeds {maximum} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M7DossierError> {
    reject_unsafe_components(path)?;
    if path_entry_exists(path)? {
        reject_symlink(path)?;
    }
    fs::create_dir_all(path).map_err(|source| M7DossierError::io(path, source))?;
    secure_existing_root(path)
}

fn secure_existing_root(path: &Path) -> Result<PathBuf, M7DossierError> {
    reject_unsafe_components(path)?;
    reject_symlink(path)?;
    let canonical = fs::canonicalize(path).map_err(|source| M7DossierError::io(path, source))?;
    let metadata =
        fs::metadata(&canonical).map_err(|source| M7DossierError::io(&canonical, source))?;
    if !metadata.is_dir() {
        return Err(M7DossierError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M7DossierError> {
    let path = root.join(name);
    if path_entry_exists(&path)? {
        reject_symlink(&path)?;
    }
    fs::create_dir_all(&path).map_err(|source| M7DossierError::io(&path, source))?;
    secure_existing_child_directory(root, name)
}

fn secure_existing_child_directory(root: &Path, name: &str) -> Result<PathBuf, M7DossierError> {
    let path = root.join(name);
    reject_symlink(&path)?;
    let canonical = fs::canonicalize(&path).map_err(|source| M7DossierError::io(&path, source))?;
    if canonical.parent() != Some(root)
        || !fs::metadata(&canonical)
            .map_err(|source| M7DossierError::io(&canonical, source))?
            .is_dir()
    {
        return Err(M7DossierError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn validate_root_entries(root: &Path) -> Result<(), M7DossierError> {
    let allowed = BTreeSet::from([
        OWNER_LOCK_FILE,
        MANIFEST_FILE,
        REVIEW_REQUEST_FILE,
        FINAL_BUNDLE_FILE,
        EVIDENCE_DIRECTORY,
        LINKS_DIRECTORY,
        STAGING_DIRECTORY,
    ]);
    for entry in fs::read_dir(root).map_err(|source| M7DossierError::io(root, source))? {
        let entry = entry.map_err(|source| M7DossierError::io(root, source))?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| M7DossierError::UnsafePath(entry.path()))?;
        if !allowed.contains(name) {
            return Err(M7DossierError::UnsafePath(entry.path()));
        }
        reject_symlink(&entry.path())?;
    }
    Ok(())
}

fn validate_evidence_directory(root: &Path) -> Result<(), M7DossierError> {
    let mut count = 0usize;
    let mut total = 0u64;
    for entry in fs::read_dir(root).map_err(|source| M7DossierError::io(root, source))? {
        let entry = entry.map_err(|source| M7DossierError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let metadata = fs::metadata(&path).map_err(|source| M7DossierError::io(&path, source))?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| M7DossierError::UnsafePath(path.clone()))?
            .to_string();
        if !metadata.is_file()
            || !valid_evidence_file_name(&name)
            || metadata.len() == 0
            || metadata.len() > MAX_EVIDENCE_BYTES as u64
        {
            return Err(M7DossierError::Integrity(format!(
                "invalid content-addressed evidence entry '{}'",
                path.display()
            )));
        }
        count += 1;
        total = total.checked_add(metadata.len()).ok_or_else(|| {
            M7DossierError::ResourceExhausted("stored evidence-size budget overflow".to_string())
        })?;
        if count > MAX_STORED_ARTIFACTS || total > MAX_TOTAL_EVIDENCE_BYTES {
            return Err(M7DossierError::ResourceExhausted(
                "stored evidence exceeds dossier budgets".to_string(),
            ));
        }
    }
    Ok(())
}

fn ensure_evidence_capacity(
    root: &Path,
    destination: &Path,
    incoming_bytes: usize,
) -> Result<(), M7DossierError> {
    validate_evidence_directory(root)?;
    if path_entry_exists(destination)? {
        return Ok(());
    }
    let mut count = 0usize;
    let mut total = 0u64;
    for entry in fs::read_dir(root).map_err(|source| M7DossierError::io(root, source))? {
        let entry = entry.map_err(|source| M7DossierError::io(root, source))?;
        let path = entry.path();
        let metadata = fs::metadata(&path).map_err(|source| M7DossierError::io(&path, source))?;
        count = count.saturating_add(1);
        total = total.checked_add(metadata.len()).ok_or_else(|| {
            M7DossierError::ResourceExhausted("stored evidence-size budget overflow".to_string())
        })?;
    }
    let projected_total = total
        .checked_add(u64::try_from(incoming_bytes).unwrap_or(u64::MAX))
        .ok_or_else(|| {
            M7DossierError::ResourceExhausted("stored evidence-size budget overflow".to_string())
        })?;
    if count >= MAX_STORED_ARTIFACTS || projected_total > MAX_TOTAL_EVIDENCE_BYTES {
        return Err(M7DossierError::ResourceExhausted(
            "storing this evidence would exceed dossier count or byte budgets".to_string(),
        ));
    }
    Ok(())
}

fn valid_evidence_file_name(name: &str) -> bool {
    name.len() == "sha256-".len() + 64 + ".json".len()
        && name.starts_with("sha256-")
        && name.ends_with(".json")
        && name.as_bytes()["sha256-".len()..("sha256-".len() + 64)]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn acquire_owner_lock(root: &Path) -> Result<File, M7DossierError> {
    let path = root.join(OWNER_LOCK_FILE);
    let existed = path_entry_exists(&path)?;
    if existed {
        reject_symlink(&path)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| M7DossierError::io(&path, source))?;
    file.try_lock()
        .map_err(|_| M7DossierError::AlreadyOwned(root.to_path_buf()))?;
    if !existed {
        sync_directory(root)?;
    }
    Ok(file)
}

fn recover_staging(root: &Path) -> Result<(), M7DossierError> {
    let mut changed = false;
    for entry in fs::read_dir(root).map_err(|source| M7DossierError::io(root, source))? {
        let entry = entry.map_err(|source| M7DossierError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let metadata = fs::metadata(&path).map_err(|source| M7DossierError::io(&path, source))?;
        if !metadata.is_file()
            || !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".building-"))
        {
            return Err(M7DossierError::UnsafePath(path));
        }
        fs::remove_file(&path).map_err(|source| M7DossierError::io(&path, source))?;
        changed = true;
    }
    if changed {
        sync_directory(root)?;
    }
    Ok(())
}

fn reject_unsafe_components(path: &Path) -> Result<(), M7DossierError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(M7DossierError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), M7DossierError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| M7DossierError::io(path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(M7DossierError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn path_entry_exists(path: &Path) -> Result<bool, M7DossierError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(M7DossierError::io(path, source)),
    }
}

fn sync_directory(path: &Path) -> Result<(), M7DossierError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| M7DossierError::io(path, source))
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), M7DossierError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('\\')
        || value == "."
        || value == ".."
    {
        return Err(M7DossierError::InvalidIdentifier {
            field,
            limit: MAX_IDENTIFIER_BYTES,
        });
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, M7DossierError> {
    serde_json::to_vec_pretty(value)
        .map_err(|error| M7DossierError::Serialization(error.to_string()))
}

#[derive(Debug)]
pub enum M7DossierError {
    InvalidIdentifier {
        field: &'static str,
        limit: usize,
    },
    InvalidEvidence(String),
    WrongProofRun,
    StaleManifest,
    CausalMismatch,
    ProviderScopeMismatch,
    ReviewerNotIndependent,
    ReviewerScopeMismatch,
    ReviewNotReady(String),
    Conflict(String),
    ResourceExhausted(String),
    Integrity(String),
    AlreadyOwned(PathBuf),
    UnsafePath(PathBuf),
    Foundation(String),
    Serialization(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl M7DossierError {
    fn foundation(error: M7FoundationError) -> Self {
        Self::Foundation(error.to_string())
    }

    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl Display for M7DossierError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIdentifier { field, limit } => write!(
                formatter,
                "{field} must contain 1..={limit} safe non-control bytes"
            ),
            Self::InvalidEvidence(message) => {
                write!(formatter, "invalid M7 evidence: {message}")
            }
            Self::WrongProofRun => formatter.write_str("evidence belongs to another proof run"),
            Self::StaleManifest => {
                formatter.write_str("evidence names a stale or foreign manifest")
            }
            Self::CausalMismatch => {
                formatter.write_str("evidence is outside the proof-run causal chain")
            }
            Self::ProviderScopeMismatch => {
                formatter.write_str("live-provider evidence scope mismatch")
            }
            Self::ReviewerNotIndependent => {
                formatter.write_str("reviewer is not independent of implementation")
            }
            Self::ReviewerScopeMismatch => {
                formatter.write_str("reviewer artifact does not match the frozen review request")
            }
            Self::ReviewNotReady(message) => {
                write!(formatter, "M7 review is not ready: {message}")
            }
            Self::Conflict(message) => write!(formatter, "M7 immutable conflict: {message}"),
            Self::ResourceExhausted(message) => {
                write!(formatter, "M7 dossier resource exhausted: {message}")
            }
            Self::Integrity(message) => {
                write!(formatter, "M7 dossier integrity failure: {message}")
            }
            Self::AlreadyOwned(path) => write!(
                formatter,
                "M7 dossier '{}' already has a live owner",
                path.display()
            ),
            Self::UnsafePath(path) => {
                write!(formatter, "unsafe M7 dossier path '{}'", path.display())
            }
            Self::Foundation(message) => {
                write!(formatter, "M7 closure foundation rejected input: {message}")
            }
            Self::Serialization(message) => {
                write!(formatter, "M7 dossier serialization failed: {message}")
            }
            Self::Io { path, source } => write!(
                formatter,
                "M7 dossier I/O failure at '{}': {source}",
                path.display()
            ),
        }
    }
}

impl Error for M7DossierError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m7_closure::{
        ClaimBoundaryEvidence, DeterministicTestTranscriptEvidence, FrozenClosureCriteria,
        LiveProviderQualificationScope, M0TruthEvidence, M1CandidateLifecycleEvidence,
        M2SchedulerWakeRestartEvidence, M3CapabilityEffectsEvidence, M4WorkerEcologyEvidence,
        M5ActivationRollbackEvidence, M6FactoryExchangeEvidence, M7_CLAIM_CATALOG_VERSION,
        M7Blocker, M7CargoTestTranscriptV2, M7CausalSubjectKind, M7ClaimBoundarySourceV3,
        M7ClosureDecision, M7Criterion, M7EvidenceFamily, M7IndependentReviewSourceV2,
        M7PublicationPolicySourceV3, M7SourceCaptureAttestationV2, M7SourceIdentity,
        M7SourceRootProvenanceV1, M7TruthBoundarySourceV3, M7WorkerRole, PublicationPolicyEvidence,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::Value;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const CAPTURE_ATTESTOR_SEED: [u8; 32] = [0x71; 32];
    const REVIEWER_ATTESTOR_SEED: [u8; 32] = [0x72; 32];
    const IMPLEMENTER_IDENTITY_SEED: [u8; 32] = [0x63; 32];

    fn test_attestor(seed: [u8; 32]) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&seed).expect("test Ed25519 attestor")
    }

    fn test_identity(principal_id: &str, seed: [u8; 32]) -> M7ExternalEd25519IdentityV1 {
        let key = test_attestor(seed);
        M7ExternalEd25519IdentityV1::new(principal_id, key.public_key().as_ref())
            .expect("test external identity")
    }

    fn capture_identity() -> M7ExternalEd25519IdentityV1 {
        test_identity("attestor:source-capture", CAPTURE_ATTESTOR_SEED)
    }

    fn reviewer_identity() -> M7ExternalEd25519IdentityV1 {
        test_identity("reviewer:independent", REVIEWER_ATTESTOR_SEED)
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m7-runtime-{label}-{}-{}",
                std::process::id(),
                TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("create test directory");
            Self { path }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    enum FixtureEvidence {
        Derived(M7DerivedEvidenceV2),
        Unresolved(Vec<u8>),
    }

    impl FixtureEvidence {
        fn bytes(&self) -> Vec<u8> {
            match self {
                Self::Derived(derived) => derived.artifact_bytes().expect("derived artifact bytes"),
                Self::Unresolved(bytes) => bytes.clone(),
            }
        }
    }

    struct Fixture {
        directory: TestDirectory,
        manifest: M7ProofRunManifest,
        artifacts: BTreeMap<M7EvidenceKind, FixtureEvidence>,
    }

    impl Fixture {
        fn new(provider_scope: Option<LiveProviderQualificationScope>) -> Self {
            let directory = TestDirectory::new("fixture");
            let manifest = manifest("proof-run:m7:runtime", provider_scope);
            let artifacts = source_bound_non_review_evidence(&manifest);
            Self {
                directory,
                manifest,
                artifacts,
            }
        }

        fn open(&self) -> M7DossierRuntime {
            M7DossierRuntime::open(&self.directory.path, self.manifest.clone())
                .expect("open dossier")
        }

        fn admit_non_review(
            &self,
            runtime: &mut M7DossierRuntime,
        ) -> BTreeMap<M7EvidenceKind, M7EvidenceLink> {
            self.artifacts
                .iter()
                .map(|(kind, evidence)| {
                    let link = match evidence {
                        FixtureEvidence::Derived(derived) => runtime
                            .admit_derived_evidence(derived)
                            .expect("admit derived evidence"),
                        FixtureEvidence::Unresolved(bytes) => runtime
                            .admit_evidence_bytes(bytes)
                            .expect("admit unresolved evidence"),
                    };
                    (*kind, link)
                })
                .collect()
        }

        fn evidence(&self, kind: M7EvidenceKind) -> &FixtureEvidence {
            self.artifacts.get(&kind).expect("fixture evidence")
        }

        fn bytes(&self, kind: M7EvidenceKind) -> Vec<u8> {
            self.evidence(kind).bytes()
        }

        fn seal(
            &self,
            runtime: &mut M7DossierRuntime,
            recommendation: M7ClosureDecision,
        ) -> M7FinalBundle {
            self.admit_non_review(runtime);
            let request = runtime.begin_independent_review().expect("begin review");
            let reviewer = reviewer_evidence(
                &self.manifest,
                &request,
                recommendation,
                REVIEWER_ATTESTOR_SEED,
            )
            .expect("derive reviewer evidence");
            runtime
                .admit_derived_evidence(&reviewer)
                .expect("admit reviewer");
            runtime.finalize().expect("finalize dossier")
        }
    }

    fn content(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(label.as_bytes())
    }

    fn criteria() -> FrozenClosureCriteria {
        let families = [
            M7EvidenceFamily::M0TruthBaseline,
            M7EvidenceFamily::M1CandidateLifecycle,
            M7EvidenceFamily::M2SchedulerWakeRestart,
            M7EvidenceFamily::M3CapabilityEffects,
            M7EvidenceFamily::M4WorkerEcology,
            M7EvidenceFamily::M5ActivationRollback,
            M7EvidenceFamily::M6FactoryExchange,
        ];
        FrozenClosureCriteria::new(
            "m7-operational-closure",
            "1.0.0",
            100,
            families
                .into_iter()
                .enumerate()
                .map(|(index, family)| {
                    let statement = format!(
                        "M{index} must be proven from its exact bounded authoritative sources."
                    );
                    M7Criterion {
                        criterion_id: format!("criterion:m{index}"),
                        statement_digest: ContentDigest::from_bytes(statement.as_bytes()),
                        statement,
                        required_families: BTreeSet::from([family]),
                    }
                })
                .collect(),
        )
        .expect("frozen criteria")
    }

    fn manifest(
        proof_run_id: &str,
        provider_scope: Option<LiveProviderQualificationScope>,
    ) -> M7ProofRunManifest {
        M7ProofRunManifest::new(
            proof_run_id,
            200,
            criteria(),
            M7SourceIdentity {
                commit_oid: "0123456789abcdef0123456789abcdef01234567".to_string(),
                commit_object_digest: content("commit-object"),
                tree_oid: "89abcdef0123456789abcdef0123456789abcdef".to_string(),
                tree_digest: content("tree-object"),
                checkout_root_digest: content("checkout-root"),
                toolchain_digest: content("rust-toolchain"),
                lockfile_digest: content("cargo-lock"),
                root_provenance: M7SourceRootProvenanceV1::FreshCleanCheckout,
            },
            capture_identity(),
            reviewer_identity(),
            content("m7-causal-chain"),
            BTreeSet::from(["implementer:one".to_string(), "implementer:two".to_string()]),
            BTreeSet::from([
                content("implementer-one-identity"),
                content("implementer-two-identity"),
            ]),
            provider_scope,
        )
        .expect("proof-run manifest")
    }

    fn derive_evidence(
        manifest: &M7ProofRunManifest,
        kind: M7EvidenceKind,
        inputs: Vec<M7SourceInputV2>,
    ) -> M7DerivedEvidenceV2 {
        M7EvidenceArtifact::derive_from_sources(manifest, kind, inputs)
            .expect("derive source-bound evidence")
    }

    fn source_bound_non_review_evidence(
        manifest: &M7ProofRunManifest,
    ) -> BTreeMap<M7EvidenceKind, FixtureEvidence> {
        let (export_bytes, probe_bytes, supervisor_before, supervisor_after) =
            crate::m7_closure::tests::exact_manifest_bound_m5_m2_source_bytes(
                manifest.manifest_digest(),
            );
        let active_surfaces = crate::m7_closure::tests::exact_active_surface_snapshot();
        let truth = M7TruthBoundarySourceV3::new(active_surfaces.clone())
            .expect("truth source")
            .canonical_bytes()
            .expect("truth source bytes");
        let transcript = M7CargoTestTranscriptV2::new(
            vec![
                "cargo".to_string(),
                "test".to_string(),
                "--locked".to_string(),
                "--all-targets".to_string(),
            ],
            manifest.manifest_digest().clone(),
            "test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n"
                .to_string(),
            String::new(),
            0,
        )
        .expect("test transcript source")
        .canonical_bytes()
        .expect("test transcript bytes");
        let capture_inventory = crate::m7_closure::tests::synthetic_capture_inventory_for_fixture(
            manifest,
            &transcript,
        );
        let capture_key = test_attestor(CAPTURE_ATTESTOR_SEED);
        let capture_preimage =
            M7SourceCaptureAttestationV2::signing_preimage(manifest, &capture_inventory, 300)
                .expect("source-capture signing preimage");
        let capture_signature = capture_key.sign(&capture_preimage);
        let capture_attestation = M7SourceCaptureAttestationV2::from_external_signature(
            manifest,
            &capture_inventory,
            300,
            capture_signature.as_ref(),
        )
        .expect("source-capture attestation");
        let capture_attestation = capture_attestation
            .canonical_bytes(manifest)
            .expect("source-capture attestation bytes");
        let claims = M7ClaimBoundarySourceV3::new(active_surfaces.clone())
            .expect("claim source")
            .canonical_bytes()
            .expect("claim source bytes");
        let publication = M7PublicationPolicySourceV3::new(active_surfaces)
            .expect("publication source")
            .canonical_bytes()
            .expect("publication source bytes");

        let mut artifacts = BTreeMap::new();
        for (kind, inputs) in [
            (
                M7EvidenceKind::M0TruthBaseline,
                vec![M7SourceInputV2::new(M7SourceRoleV2::M0TruthBoundary, truth)],
            ),
            (
                M7EvidenceKind::M1CandidateLifecycle,
                vec![M7SourceInputV2::new(
                    M7SourceRoleV2::M5ExportM1,
                    export_bytes.clone(),
                )],
            ),
            (
                M7EvidenceKind::M2SchedulerWakeRestart,
                vec![
                    M7SourceInputV2::new(M7SourceRoleV2::SupervisorPreRestart, supervisor_before),
                    M7SourceInputV2::new(M7SourceRoleV2::SupervisorPostRestart, supervisor_after),
                ],
            ),
            (
                M7EvidenceKind::M3CapabilityEffects,
                vec![M7SourceInputV2::new(
                    M7SourceRoleV2::M5ExportM3,
                    export_bytes.clone(),
                )],
            ),
            (
                M7EvidenceKind::M4WorkerEcology,
                vec![M7SourceInputV2::new(
                    M7SourceRoleV2::M5ExportM4,
                    export_bytes.clone(),
                )],
            ),
            (
                M7EvidenceKind::M5ActivationRollback,
                vec![
                    M7SourceInputV2::new(M7SourceRoleV2::M5ExportRollback, export_bytes),
                    M7SourceInputV2::new(M7SourceRoleV2::M5FinalPostRollbackProbe, probe_bytes),
                ],
            ),
            (
                M7EvidenceKind::DeterministicTestTranscript,
                vec![
                    M7SourceInputV2::new(M7SourceRoleV2::CargoTestTranscript, transcript),
                    M7SourceInputV2::new(
                        M7SourceRoleV2::SourceCaptureAttestation,
                        capture_attestation,
                    ),
                ],
            ),
            (
                M7EvidenceKind::ClaimBoundary,
                vec![M7SourceInputV2::new(M7SourceRoleV2::ClaimBoundary, claims)],
            ),
            (
                M7EvidenceKind::PublicationPolicy,
                vec![M7SourceInputV2::new(
                    M7SourceRoleV2::PublicationPolicy,
                    publication,
                )],
            ),
        ] {
            artifacts.insert(
                kind,
                FixtureEvidence::Derived(derive_evidence(manifest, kind, inputs)),
            );
        }
        let unresolved = M7EvidenceArtifact::unresolved_m6(
            manifest,
            content("subject:M6FactoryExchange:unresolved"),
        )
        .expect("unresolved M6")
        .canonical_bytes()
        .expect("unresolved M6 bytes");
        artifacts.insert(
            M7EvidenceKind::M6FactoryExchange,
            FixtureEvidence::Unresolved(unresolved),
        );
        artifacts
    }

    fn artifact(manifest: &M7ProofRunManifest, payload: M7EvidencePayload) -> M7EvidenceArtifact {
        M7EvidenceArtifact::new(
            manifest,
            content(&format!("subject:{:?}", payload.kind())),
            payload,
        )
        .expect("evidence artifact")
    }

    fn required_payloads_without_reviewer() -> Vec<M7EvidencePayload> {
        vec![
            M7EvidencePayload::M0TruthBaseline(M0TruthEvidence {
                active_surface_snapshot_digest: content("active-surface-snapshot"),
                active_truth_digest: content("active-truth"),
                legacy_phase04_historical_only: true,
                seeded_status_used_as_proof: false,
                pre_run_operational_decision: M7ClosureDecision::NotYet,
            }),
            M7EvidencePayload::M1CandidateLifecycle(M1CandidateLifecycleEvidence {
                incumbent_package_digest: content("incumbent-package"),
                candidate_package_digest: content("candidate-package"),
                candidate_component_digest: content("candidate-component"),
                mutation_changed_candidate_bytes: true,
                build_succeeded: true,
                tests_succeeded: true,
                proving_succeeded: true,
                package_resolved: true,
            }),
            M7EvidencePayload::M2SchedulerWakeRestart(M2SchedulerWakeRestartEvidence {
                manifest_digest: content("fixture-manifest"),
                challenge_job_id: "job:m7-post-export-challenge".to_string(),
                challenge_digest: content("m2-post-export-challenge"),
                m5_export_bundle_content_digest: content("m5-export-bundle-content"),
                m6_completion_bundle_content_digest: content("m6-completion-bundle-content"),
                m4_lifecycle_job_id: "job:m4-lifecycle-anchor".to_string(),
                m4_lifecycle_terminal_job_digest: content("m4-lifecycle-anchor"),
                scheduled_job_digest: content("scheduled-job"),
                completed_job_digest: content("completed-job"),
                effect_receipt_digest: content("effect-receipt"),
                wake_record_digest: content("wake-record"),
                restart_capture_digest: content("restart-capture"),
                future_wake_observed: true,
                process_restart_observed: true,
                restart_reconstructed: true,
                missed_wake_count: 0,
            }),
            M7EvidencePayload::M3CapabilityEffects(M3CapabilityEffectsEvidence {
                required_capability_count: 9,
                successful_receipt_count: 9,
                all_receipts_resolved: true,
                all_attestations_valid: true,
                generic_bypass_count: 0,
            }),
            M7EvidencePayload::M4WorkerEcology(M4WorkerEcologyEvidence {
                factory_id: "factory:m7-fixture".to_string(),
                scope_id: "scope:m7-fixture".to_string(),
                lifecycle_terminal_job_digests: BTreeMap::from([(
                    "job:m4-lifecycle-anchor".to_string(),
                    content("m4-lifecycle-anchor"),
                )]),
                required_roles: BTreeSet::from([
                    M7WorkerRole::Planner,
                    M7WorkerRole::Researcher,
                    M7WorkerRole::Builder,
                    M7WorkerRole::Tester,
                    M7WorkerRole::Reviewer,
                    M7WorkerRole::Operator,
                ]),
                terminal_worker_result_count: 6,
                receipt_backed_result_count: 6,
                invented_worker_result_count: 0,
                synthesis_resolved: true,
            }),
            M7EvidencePayload::M5ActivationRollback(M5ActivationRollbackEvidence {
                manifest_digest: content("fixture-manifest"),
                m5_export_bundle_content_digest: content("m5-export-bundle-content"),
                m6_completion_bundle_content_digest: content("m6-completion-bundle-content"),
                m2_restart_capture_digest: content("restart-capture"),
                final_probe_causal_execution_context_digest: content(
                    "final-probe-causal-execution-context",
                ),
                final_post_rollback_probe_content_digest: content(
                    "final-post-rollback-probe-content",
                ),
                final_post_rollback_probe_record_digest: content(
                    "final-post-rollback-probe-record",
                ),
                active_cycle_id: "cycle:m7-active".to_string(),
                active_cycle_record_digest: content("active-cycle-record"),
                active_parent_package_digest: content("incumbent-package"),
                active_package_digest: content("candidate-package"),
                active_release_gate_digest: content("release-gate"),
                active_operator_context_digest: content("fixture-manifest"),
                rollback_cycle_id: "cycle:m7-rollback".to_string(),
                rollback_cycle_record_digest: content("rollback-cycle-record"),
                rollback_release_gate_digest: content("release-gate"),
                rollback_operator_context_digest: content("fixture-manifest"),
                provider_qualification_record_digests_by_target: BTreeMap::new(),
                incumbent_package_digest: content("incumbent-package"),
                successor_package_digest: content("successor-package"),
                restored_package_digest: content("incumbent-package"),
                restored_snapshot_digest: content("incumbent-snapshot"),
                activation_receipt_digest: content("activation-receipt"),
                observation_evidence_digest: content("observation-evidence"),
                recovery_receipt_digest: content("recovery-receipt"),
                successor_activated: true,
                real_failure_observed: true,
                rollback_intent_durable: true,
                rollback_completed: true,
                state_reference_restored: true,
                runtime_behavior_restored: true,
                incomplete_mutation: false,
            }),
            M7EvidencePayload::M6FactoryExchange(M6FactoryExchangeEvidence {
                completion_bundle_content_digest: content("m6-completion-bundle-content"),
                sender_m5_export_bundle_content_digest: content("m5-export-bundle-content"),
                accepted_exchange_digest: content("accepted-exchange"),
                rejected_or_rolled_back_exchange_digest: content("rejected-exchange"),
                accepted_exchange_count: 1,
                rejected_or_rolled_back_count: 1,
                exact_bytes_verified: true,
                sender_lineage_resolved: true,
                receiver_proving_resolved: true,
                negative_control_suite_passed: true,
                replay_rejection_control_passed: true,
                revocation_control_passed: true,
                unresolved_quarantine_count: 0,
                receiver_rollback_complete: true,
                sender_unchanged: true,
                both_factories_restarted: true,
                acknowledgement_used_as_adoption_evidence: false,
            }),
            M7EvidencePayload::DeterministicTestTranscript(DeterministicTestTranscriptEvidence {
                command_digest: content("test-command"),
                transcript_digest: content("test-transcript"),
                required_test_count: 100,
                executed_test_count: 100,
                failed_test_count: 0,
                clean_root: true,
            }),
            M7EvidencePayload::ClaimBoundary(ClaimBoundaryEvidence {
                active_surface_snapshot_digest: content("active-surface-snapshot"),
                claim_catalog_digest: content("claim-catalog"),
                claim_catalog_version: M7_CLAIM_CATALOG_VERSION.to_string(),
                allowed_claims_digest: content("allowed-claims"),
                forbidden_claims_digest: content("forbidden-claims"),
                forbidden_claim_count: 4,
                active_surfaces_aligned: true,
                public_federation_claimed: false,
            }),
            M7EvidencePayload::PublicationPolicy(PublicationPolicyEvidence {
                active_surface_snapshot_digest: content("active-surface-snapshot"),
                publication_controls_digest: content("publication-controls"),
                publication_policy_digest: content("publication-policy"),
                secrets_redacted: true,
                legacy_phase04_labeled_historical: true,
                outcome_neutral: true,
                bounded_local_first_preserved: true,
            }),
        ]
    }

    fn reviewer_evidence(
        manifest: &M7ProofRunManifest,
        request: &M7IndependentReviewRequest,
        recommendation: M7ClosureDecision,
        signing_seed: [u8; 32],
    ) -> Result<M7DerivedEvidenceV2, M7FoundationError> {
        reviewer_evidence_for_identity(
            manifest,
            request,
            recommendation,
            request.reviewer_identity().clone(),
            signing_seed,
        )
    }

    fn reviewer_evidence_for_identity(
        manifest: &M7ProofRunManifest,
        request: &M7IndependentReviewRequest,
        recommendation: M7ClosureDecision,
        reviewer_identity: M7ExternalEd25519IdentityV1,
        signing_seed: [u8; 32],
    ) -> Result<M7DerivedEvidenceV2, M7FoundationError> {
        let rationale_digest = content("reviewer-rationale");
        let independence_statement_digest = content("reviewer-independence-statement");
        let preimage = M7IndependentReviewSourceV2::signing_preimage(
            &reviewer_identity,
            manifest.manifest_digest().clone(),
            request.reviewed_evidence_set_digest().clone(),
            recommendation,
            rationale_digest.clone(),
            independence_statement_digest.clone(),
        )?;
        let signer = test_attestor(signing_seed);
        let signature = signer.sign(&preimage);
        let source = M7IndependentReviewSourceV2::from_external_signature(
            reviewer_identity,
            manifest.manifest_digest().clone(),
            request.reviewed_evidence_set_digest().clone(),
            recommendation,
            rationale_digest,
            independence_statement_digest,
            signature.as_ref(),
        )?;
        M7EvidenceArtifact::derive_from_sources(
            manifest,
            M7EvidenceKind::IndependentReviewerRecommendation,
            vec![M7SourceInputV2::new(
                M7SourceRoleV2::IndependentReview,
                source.canonical_bytes()?,
            )],
        )
    }

    fn rewrite_json_field(bytes: &[u8], path: &[&str], replacement: Value) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(bytes).expect("parse JSON");
        let mut cursor = &mut value;
        for name in &path[..path.len() - 1] {
            cursor = cursor.get_mut(*name).expect("JSON field on rewrite path");
        }
        cursor[path[path.len() - 1]] = replacement;
        serde_json::to_vec_pretty(&value).expect("canonical value bytes")
    }

    fn replace_digest_bytes(
        bytes: &[u8],
        old: &ContentDigest,
        replacement: &ContentDigest,
    ) -> Vec<u8> {
        let text = String::from_utf8(bytes.to_vec()).expect("UTF-8 evidence");
        assert!(text.contains(old.as_str()), "old digest occurs in evidence");
        text.replacen(old.as_str(), replacement.as_str(), 1)
            .into_bytes()
    }

    #[test]
    fn complete_evidence_neutral_dossier_preserves_not_yet_recommendation() {
        let fixture = Fixture::new(None);
        let mut runtime = fixture.open();
        fixture.seal(&mut runtime, M7ClosureDecision::NotYet);
        let evaluation = runtime.evaluate_final().expect("evaluate");

        assert!(!evaluation.evidence_complete);
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert_eq!(
            evaluation.reviewer_recommendation,
            Some(M7ClosureDecision::NotYet)
        );
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::MissingAuthoritativeSource(
                    M7EvidenceKind::M6FactoryExchange
                ))
        );
    }

    #[test]
    fn every_mandatory_evidence_deletion_and_corruption_evaluates_not_yet() {
        let fixture = Fixture::new(None);
        let mut runtime = fixture.open();
        let bundle = fixture.seal(&mut runtime, M7ClosureDecision::Closed);
        assert_eq!(
            runtime.evaluate_final().expect("baseline").decision,
            M7ClosureDecision::NotYet
        );

        for link in bundle.evidence_links() {
            let path = evidence_path(&runtime.evidence_root, &link.digest);
            let original = fs::read(&path).expect("original evidence");

            fs::remove_file(&path).expect("delete evidence");
            let missing = runtime.evaluate_final().expect("missing evaluation");
            assert_eq!(
                missing.decision,
                M7ClosureDecision::NotYet,
                "deletion of {:?}",
                link.kind
            );
            assert!(
                missing
                    .blockers
                    .contains(&M7Blocker::MissingEvidenceBytes(link.kind))
            );

            fs::write(&path, b"{}").expect("restore corrupt evidence");
            let corrupt = runtime.evaluate_final().expect("corrupt evaluation");
            assert_eq!(
                corrupt.decision,
                M7ClosureDecision::NotYet,
                "corruption of {:?}",
                link.kind
            );
            assert!(corrupt.blockers.iter().any(|blocker| matches!(
                blocker,
                M7Blocker::LengthMismatch(kind)
                    | M7Blocker::DigestMismatch(kind)
                    | M7Blocker::MalformedEvidence(kind)
                    if *kind == link.kind
            )));
            fs::write(&path, &original).expect("restore exact evidence");
        }
        assert_eq!(
            runtime.evaluate_final().expect("restored").decision,
            M7ClosureDecision::NotYet
        );
    }

    #[test]
    fn missing_wrong_run_stale_manifest_and_wrong_causal_evidence_fail_closed() {
        let fixture = Fixture::new(None);
        let mut runtime = fixture.open();
        let error = runtime
            .begin_independent_review()
            .expect_err("missing evidence");
        assert!(matches!(error, M7DossierError::ReviewNotReady(_)));

        let payload = required_payloads_without_reviewer().remove(0);
        let foreign = manifest("proof-run:foreign", None);
        let foreign_bytes = artifact(&foreign, payload.clone())
            .canonical_bytes()
            .expect("foreign bytes");
        assert!(matches!(
            runtime.admit_evidence_bytes(&foreign_bytes),
            Err(M7DossierError::WrongProofRun)
        ));

        let valid = artifact(&fixture.manifest, payload)
            .canonical_bytes()
            .expect("valid bytes");
        let stale = replace_digest_bytes(
            &valid,
            fixture.manifest.manifest_digest(),
            &content("stale-manifest"),
        );
        assert!(matches!(
            runtime.admit_evidence_bytes(&stale),
            Err(M7DossierError::StaleManifest)
        ));

        let wrong_causal = replace_digest_bytes(
            &valid,
            fixture.manifest.causal_chain_digest(),
            &content("wrong-causal"),
        );
        assert!(matches!(
            runtime.admit_evidence_bytes(&wrong_causal),
            Err(M7DossierError::CausalMismatch)
        ));
        assert!(runtime.evidence_links().is_empty());
    }

    #[test]
    fn exact_retry_is_idempotent_and_cannot_be_relabelled() {
        let fixture = Fixture::new(None);
        let mut runtime = fixture.open();
        let FixtureEvidence::Derived(m0) = fixture.evidence(M7EvidenceKind::M0TruthBaseline) else {
            panic!("M0 must be derived")
        };
        let first = runtime
            .admit_derived_evidence(m0)
            .expect("first derived admit");
        let second = runtime
            .admit_derived_evidence(m0)
            .expect("exact derived retry");
        assert_eq!(first, second);

        let independently_rederived = M7EvidenceArtifact::derive_from_sources(
            &fixture.manifest,
            M7EvidenceKind::M0TruthBaseline,
            vec![M7SourceInputV2::new(
                M7SourceRoleV2::M0TruthBoundary,
                m0.source_blobs()[0].bytes().to_vec(),
            )],
        )
        .expect("independently rederived artifact");
        assert!(
            &independently_rederived == m0,
            "independently rederived M0 evidence differed from the exact source-bound artifact"
        );
        assert_eq!(
            runtime
                .admit_derived_evidence(&independently_rederived)
                .expect("source-equivalent retry"),
            first
        );
        assert_eq!(runtime.evidence_links().len(), 1);
    }

    #[test]
    fn review_boundary_rejects_a_signature_from_the_wrong_key() {
        let fixture = Fixture::new(None);
        let mut runtime = fixture.open();
        fixture.admit_non_review(&mut runtime);

        let request = runtime
            .begin_independent_review()
            .expect("external request");
        assert!(matches!(
            reviewer_evidence(
                &fixture.manifest,
                &request,
                M7ClosureDecision::Closed,
                IMPLEMENTER_IDENTITY_SEED,
            ),
            Err(M7FoundationError::InvalidSource(_))
        ));
        assert!(
            !runtime
                .evidence_links()
                .contains_key(&M7EvidenceKind::IndependentReviewerRecommendation)
        );
    }

    #[test]
    fn detached_reviewer_handoff_survives_finalize_and_reopen() {
        let fixture = Fixture::new(None);
        let rationale_digest = content("operator-review-rationale");
        let independence_digest = content("operator-review-independence");
        let recommendation = M7ClosureDecision::ClosedWithCaveats;
        {
            let mut runtime = fixture.open();
            fixture.admit_non_review(&mut runtime);
            runtime
                .begin_independent_review()
                .expect("freeze review request");
            let preimage = runtime
                .independent_review_signing_preimage(
                    recommendation,
                    rationale_digest.clone(),
                    independence_digest.clone(),
                )
                .expect("export reviewer signing preimage");
            let signature = test_attestor(REVIEWER_ATTESTOR_SEED).sign(&preimage);
            runtime
                .admit_independent_review_signature(
                    recommendation,
                    rationale_digest,
                    independence_digest,
                    signature.as_ref(),
                )
                .expect("admit detached reviewer signature");
            runtime.finalize().expect("finalize dossier");
        }

        let reopened = M7DossierRuntime::reopen(&fixture.directory.path).expect("reopen dossier");
        assert!(
            reopened
                .evidence_links()
                .contains_key(&M7EvidenceKind::IndependentReviewerRecommendation)
        );
        assert!(reopened.final_bundle().is_some());
        let evaluation = reopened
            .evaluate_final()
            .expect("evaluate reopened dossier");
        assert_eq!(
            evaluation.reviewer_recommendation,
            Some(M7ClosureDecision::ClosedWithCaveats)
        );
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
    }

    #[test]
    fn source_capture_rejects_an_unresolved_source_less_m6_artifact() {
        let fixture = Fixture::new(None);
        let mut runtime = fixture.open();
        for (kind, evidence) in &fixture.artifacts {
            if *kind == M7EvidenceKind::DeterministicTestTranscript {
                continue;
            }
            match evidence {
                FixtureEvidence::Derived(derived) => {
                    runtime
                        .admit_derived_evidence(derived)
                        .expect("admit derived source evidence");
                }
                FixtureEvidence::Unresolved(bytes) => {
                    runtime
                        .admit_evidence_bytes(bytes)
                        .expect("admit unresolved artifact");
                }
            }
        }

        let error = runtime
            .source_capture_inventory(b"test result: ok. 1 passed; 0 failed\n")
            .expect_err("source-less M6 must prevent source capture");
        assert!(
            matches!(
                error,
                M7DossierError::Foundation(_) | M7DossierError::Integrity(_)
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn restart_reconstructs_frozen_scope_bundle_and_pure_evaluation() {
        let fixture = Fixture::new(None);
        let expected_digest;
        {
            let mut runtime = fixture.open();
            let bundle = fixture.seal(&mut runtime, M7ClosureDecision::ClosedWithCaveats);
            expected_digest = bundle.bundle_digest().clone();
        }

        let reopened = M7DossierRuntime::reopen(&fixture.directory.path).expect("reopen");
        assert_eq!(
            reopened
                .review_request()
                .expect("review request")
                .reviewer_id(),
            "reviewer:independent"
        );
        assert_eq!(
            reopened
                .final_bundle()
                .expect("final bundle")
                .bundle_digest(),
            &expected_digest
        );
        let evaluation = reopened.evaluate_final().expect("evaluate reopen");
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert!(!evaluation.evidence_complete);
    }

    #[test]
    fn restart_recovers_staging_and_exact_orphan_after_evidence_first_crash() {
        let fixture = Fixture::new(None);
        {
            let _runtime = fixture.open();
        }
        let FixtureEvidence::Derived(m0) = fixture.evidence(M7EvidenceKind::M0TruthBaseline) else {
            panic!("M0 must be derived")
        };
        let bytes = m0.artifact_bytes().expect("M0 bytes");
        let artifact: M7EvidenceArtifact = serde_json::from_slice(&bytes).expect("M0 artifact");
        let link = artifact.evidence_link().expect("M0 link");
        for blob in m0.source_blobs() {
            fs::write(
                fixture
                    .directory
                    .path
                    .join(EVIDENCE_DIRECTORY)
                    .join(format!("{}.json", blob.link().digest.file_stem())),
                blob.bytes(),
            )
            .expect("simulate source-first crash");
        }
        fs::write(
            fixture
                .directory
                .path
                .join(EVIDENCE_DIRECTORY)
                .join(format!("{}.json", link.digest.file_stem())),
            &bytes,
        )
        .expect("simulate evidence-first crash");
        fs::write(
            fixture
                .directory
                .path
                .join(STAGING_DIRECTORY)
                .join(".building-interrupted"),
            b"partial",
        )
        .expect("simulate interrupted staging file");

        let mut reopened = M7DossierRuntime::reopen(&fixture.directory.path).expect("reopen");
        assert_eq!(
            fs::read_dir(fixture.directory.path.join(STAGING_DIRECTORY))
                .expect("staging directory")
                .count(),
            0
        );
        assert!(reopened.evidence_links().is_empty());
        assert_eq!(
            reopened
                .admit_evidence_bytes(&bytes)
                .expect("finish exact admission"),
            link
        );
    }

    #[test]
    fn provider_binding_is_separate_required_and_exactly_scoped() {
        let source =
            crate::m7_closure::tests::live_provider_source_fixture("proof-run:m7:runtime", 150);
        let completed = source
            .completed_invocation()
            .expect("completed provider invocation");
        let scope = LiveProviderQualificationScope::from_prepared(completed.prepared_seed())
            .expect("provider scope");
        let fixture = Fixture::new(Some(scope));
        assert_eq!(
            &completed.execution_receipt().manifest_digest,
            fixture.manifest.manifest_digest(),
            "provider fixture completion must be receipt-bound to this exact dossier manifest"
        );
        let mut runtime = fixture.open();
        let mismatched_source =
            crate::m7_closure::tests::live_provider_source_fixture("proof-run:m7:runtime", 151);
        let mismatched_completed = mismatched_source
            .completed_invocation()
            .expect("mismatched completed invocation");
        let mismatched_scope =
            LiveProviderQualificationScope::from_prepared(mismatched_completed.prepared_seed())
                .expect("mismatched provider scope");

        assert!(matches!(
            M7EvidenceArtifact::derive_from_sources(
                &Fixture::new(Some(mismatched_scope)).manifest,
                M7EvidenceKind::LiveProviderQualification,
                vec![M7SourceInputV2::new(
                    M7SourceRoleV2::LiveProviderQualification,
                    source
                        .canonical_bytes()
                        .expect("live-provider source bytes"),
                )],
            ),
            Err(M7FoundationError::InvalidSource(_))
        ));

        let provider = M7EvidenceArtifact::derive_from_sources(
            &fixture.manifest,
            M7EvidenceKind::LiveProviderQualification,
            vec![M7SourceInputV2::new(
                M7SourceRoleV2::LiveProviderQualification,
                source
                    .canonical_bytes()
                    .expect("live-provider source bytes"),
            )],
        )
        .expect("provider evidence");
        let link = runtime
            .admit_derived_evidence(&provider)
            .expect("admit provider");
        assert_eq!(link.kind, M7EvidenceKind::LiveProviderQualification);

        fixture.seal(&mut runtime, M7ClosureDecision::Closed);
        let bundle = runtime.final_bundle().expect("bundle");
        assert!(
            bundle
                .evidence_links()
                .iter()
                .all(|link| link.kind != M7EvidenceKind::LiveProviderQualification)
        );
        assert_eq!(
            bundle.live_provider_link().map(|link| link.kind),
            Some(M7EvidenceKind::LiveProviderQualification)
        );
        assert_eq!(
            runtime.evaluate_final().expect("evaluate").decision,
            M7ClosureDecision::NotYet
        );
        assert_eq!(
            runtime
                .evaluate_final()
                .expect("provider evaluation")
                .live_provider_status,
            crate::m7_closure::LiveProviderQualificationStatus::Invalid
        );
    }

    #[test]
    fn duplicate_owner_is_rejected_before_state_changes() {
        let fixture = Fixture::new(None);
        let owner = fixture.open();
        let before = fs::read(owner.root.join(MANIFEST_FILE)).expect("manifest");
        assert!(matches!(
            M7DossierRuntime::reopen(&fixture.directory.path),
            Err(M7DossierError::AlreadyOwned(_))
        ));
        assert_eq!(
            fs::read(owner.root.join(MANIFEST_FILE)).expect("manifest after"),
            before
        );
    }

    #[test]
    fn corrupt_control_state_fails_reopen_without_upgrading_outcome() {
        let fixture = Fixture::new(None);
        {
            let mut runtime = fixture.open();
            fixture.admit_non_review(&mut runtime);
            runtime.begin_independent_review().expect("review request");
        }
        fs::write(
            fixture.directory.path.join(REVIEW_REQUEST_FILE),
            b"{\"tampered\":true}",
        )
        .expect("tamper review request");
        assert!(matches!(
            M7DossierRuntime::reopen(&fixture.directory.path),
            Err(M7DossierError::Serialization(_)) | Err(M7DossierError::Integrity(_))
        ));
    }

    #[test]
    fn reviewer_scope_is_bound_to_frozen_evidence_set() {
        let fixture = Fixture::new(None);
        let mut runtime = fixture.open();
        fixture.admit_non_review(&mut runtime);
        let request = runtime.begin_independent_review().expect("review request");
        let wrong = reviewer_evidence_for_identity(
            &fixture.manifest,
            &request,
            M7ClosureDecision::Closed,
            test_identity("reviewer:different", [0x64; 32]),
            [0x64; 32],
        )
        .expect("wrong reviewer evidence");
        assert!(matches!(
            runtime.admit_derived_evidence(&wrong),
            Err(M7DossierError::ReviewerScopeMismatch)
        ));
    }

    #[test]
    fn malformed_and_schema_mismatched_artifacts_are_never_persisted() {
        let fixture = Fixture::new(None);
        let mut runtime = fixture.open();
        assert!(matches!(
            runtime.admit_evidence_bytes(b"not json"),
            Err(M7DossierError::InvalidEvidence(_))
        ));
        let valid = fixture.bytes(M7EvidenceKind::M0TruthBaseline);
        let wrong_schema = rewrite_json_field(
            &valid,
            &["schema"],
            Value::String("wasm-biotic.m7-evidence.unknown.v1".to_string()),
        );
        assert!(runtime.admit_evidence_bytes(&wrong_schema).is_err());
        assert!(runtime.evidence_links().is_empty());
    }

    #[test]
    fn causal_subject_kind_is_rejected_even_with_canonical_bytes() {
        let fixture = Fixture::new(None);
        let mut runtime = fixture.open();
        let valid = fixture.bytes(M7EvidenceKind::M0TruthBaseline);
        let wrong_kind = rewrite_json_field(
            &valid,
            &["causal_subject", "kind"],
            serde_json::to_value(M7CausalSubjectKind::Candidate).expect("causal kind"),
        );
        assert!(runtime.admit_evidence_bytes(&wrong_kind).is_err());
        assert!(runtime.evidence_links().is_empty());
    }
}
