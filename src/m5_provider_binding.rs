//! Durable binding between qualified provider intent and one exact M5 seed target.
//!
//! A live provider is allowed to propose only the bounded
//! `candidate.materialize_patchset` operation. This module turns that proposal
//! into a local, content-addressed record before any candidate work begins. It
//! deliberately has no network surface: qualification evidence is supplied by
//! the caller, revalidated, and bound to exact deterministic M5 inputs.

use crate::execution::{ContentDigest, digest_json_content};
use crate::factory_reproduction::{
    FactoryPackage, LIVE_PROVIDER_QUALIFICATION_SCHEMA, LiveProviderQualificationRecord,
    M5_PROVIDER_INTENT_SCHEMA, MutableFactoryPolicy, MutableGenome, ParsedProviderIntent,
    ProviderQualificationStatus, ProviderReplayRequest, StateCompatibility, StateMigrationPlan,
    unbound_provider_invocation_challenge_digest,
};
use crate::m5_effect_port::M5M3EffectReference;
use crate::m5_effect_store::{
    FactoryProviderProposalRequest, FactoryProviderProposalResult, StateMigrationArtifactBundle,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const PROVIDER_CANDIDATE_TARGET_SCHEMA: &str = "wasm-biotic.provider-candidate-target.v1";
pub const PROVIDER_CANDIDATE_BINDING_SCHEMA: &str = "wasm-biotic.provider-candidate-binding.v5";
pub const PROVIDER_PROPOSAL_EVIDENCE_SCHEMA: &str = "wasm-biotic.provider-proposal-evidence.v4";
pub const PROVIDER_CANDIDATE_INTENT_SCHEMA: &str = M5_PROVIDER_INTENT_SCHEMA;
pub const PROVIDER_CANDIDATE_OPERATION: &str = "candidate.materialize_patchset";

const OWNER_LOCK_FILE: &str = ".provider-candidate-binding.lock";
const BINDING_DIRECTORY: &str = "bindings";
const MAX_WAT_BYTES: usize = 256 * 1_024;
const MAX_BINDING_BYTES: usize = 4 * 1_048_576;
const MAX_BINDINGS: usize = 128;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_TRANSCRIPT_BYTES: usize = 256 * 1_024;
const MAX_MIGRATION_STATE_BYTES: u64 = 4 * 1_048_576;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// One exact, deterministic seed target accepted from a provider proposal.
///
/// The WAT source is retained because it is the M5 recipe input. Validation
/// always recompiles it and reconstructs the [`MutableGenome`]; neither the
/// stored WAT digest nor the stored target-genome digest is trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCandidateTarget {
    pub schema: String,
    pub cycle_id: String,
    pub incumbent_package_digest: ContentDigest,
    pub incumbent_package_bytes: Vec<u8>,
    pub incumbent_package_bytes_digest: ContentDigest,
    pub candidate_package_digest: ContentDigest,
    pub candidate_package_bytes: Vec<u8>,
    pub candidate_package_bytes_digest: ContentDigest,
    pub candidate_component_digest: ContentDigest,
    pub release_gate_digest: ContentDigest,
    pub challenger_wat_bytes: Vec<u8>,
    pub challenger_wat_digest: ContentDigest,
    pub challenger_policy: MutableFactoryPolicy,
    pub challenger_policy_digest: ContentDigest,
    pub state_compatibility: StateCompatibility,
    pub migration_plan: Option<StateMigrationPlan>,
    pub migration_artifacts: Option<StateMigrationArtifactBundle>,
    pub operator_context_digest: ContentDigest,
    pub target_genome_digest: ContentDigest,
    pub target_digest: ContentDigest,
}

impl ProviderCandidateTarget {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cycle_id: impl Into<String>,
        incumbent: &FactoryPackage,
        candidate: &FactoryPackage,
        release_gate_digest: ContentDigest,
        challenger_wat_bytes: Vec<u8>,
        challenger_policy: MutableFactoryPolicy,
        state_compatibility: StateCompatibility,
        migration_plan: Option<StateMigrationPlan>,
        migration_artifacts: Option<StateMigrationArtifactBundle>,
        operator_context_digest: ContentDigest,
    ) -> Result<Self, ProviderBindingError> {
        let cycle_id = cycle_id.into();
        validate_identifier("cycle_id", &cycle_id)?;
        validate_wat_bounds(&challenger_wat_bytes)?;
        let challenger_wat_digest = ContentDigest::from_bytes(&challenger_wat_bytes);
        let challenger_policy_digest = challenger_policy.policy_digest().map_err(|error| {
            ProviderBindingError::InvalidTarget(format!("challenger policy is invalid: {error}"))
        })?;
        incumbent.validate().map_err(|error| {
            ProviderBindingError::InvalidTarget(format!("incumbent package is invalid: {error}"))
        })?;
        candidate.validate().map_err(|error| {
            ProviderBindingError::InvalidTarget(format!("candidate package is invalid: {error}"))
        })?;
        let incumbent_package_bytes = incumbent.canonical_bytes().map_err(|error| {
            ProviderBindingError::InvalidTarget(format!(
                "incumbent package bytes cannot be rendered: {error}"
            ))
        })?;
        let candidate_package_bytes = candidate.canonical_bytes().map_err(|error| {
            ProviderBindingError::InvalidTarget(format!(
                "candidate package bytes cannot be rendered: {error}"
            ))
        })?;
        let component_bytes = compile_wat(&challenger_wat_bytes)?;
        let genome = MutableGenome::new(
            Some(incumbent.package_digest.clone()),
            component_bytes,
            challenger_policy.clone(),
        )
        .map_err(|error| {
            ProviderBindingError::InvalidTarget(format!(
                "challenger genome cannot be reconstructed: {error}"
            ))
        })?;
        let mut target = Self {
            schema: PROVIDER_CANDIDATE_TARGET_SCHEMA.to_string(),
            cycle_id,
            incumbent_package_digest: incumbent.package_digest.clone(),
            incumbent_package_bytes_digest: ContentDigest::from_bytes(&incumbent_package_bytes),
            incumbent_package_bytes,
            candidate_package_digest: candidate.package_digest.clone(),
            candidate_package_bytes_digest: ContentDigest::from_bytes(&candidate_package_bytes),
            candidate_package_bytes,
            candidate_component_digest: candidate.payload.genome.component_digest.clone(),
            release_gate_digest,
            challenger_wat_bytes,
            challenger_wat_digest,
            challenger_policy,
            challenger_policy_digest,
            state_compatibility,
            migration_plan,
            migration_artifacts,
            operator_context_digest,
            target_genome_digest: genome.genome_digest,
            target_digest: ContentDigest::from_bytes(&[]),
        };
        target.validate_fields()?;
        target.target_digest = target.expected_digest()?;
        Ok(target)
    }

    /// Recompile the retained WAT and reconstruct its exact seed genome.
    pub fn materialized_genome(&self) -> Result<MutableGenome, ProviderBindingError> {
        validate_wat_bounds(&self.challenger_wat_bytes)?;
        let component_bytes = compile_wat(&self.challenger_wat_bytes)?;
        let genome = MutableGenome::new(
            Some(self.incumbent_package_digest.clone()),
            component_bytes,
            self.challenger_policy.clone(),
        )
        .map_err(|error| {
            ProviderBindingError::InvalidTarget(format!(
                "challenger genome cannot be reconstructed: {error}"
            ))
        })?;
        genome.validate().map_err(|error| {
            ProviderBindingError::InvalidTarget(format!(
                "reconstructed challenger genome is invalid: {error}"
            ))
        })?;
        Ok(genome)
    }

    pub fn validate(&self) -> Result<(), ProviderBindingError> {
        self.validate_fields()?;
        require_digest(
            "provider candidate target",
            &self.target_digest,
            &self.expected_digest()?,
            ProviderBindingError::InvalidTarget,
        )
    }

    fn validate_fields(&self) -> Result<(), ProviderBindingError> {
        if self.schema != PROVIDER_CANDIDATE_TARGET_SCHEMA {
            return Err(ProviderBindingError::InvalidTarget(
                "unsupported provider candidate target schema".to_string(),
            ));
        }
        validate_identifier("cycle_id", &self.cycle_id)?;
        let incumbent = FactoryPackage::from_canonical_bytes(&self.incumbent_package_bytes)
            .map_err(|error| {
                ProviderBindingError::InvalidTarget(format!(
                    "incumbent package bytes are invalid: {error}"
                ))
            })?;
        let candidate = FactoryPackage::from_canonical_bytes(&self.candidate_package_bytes)
            .map_err(|error| {
                ProviderBindingError::InvalidTarget(format!(
                    "candidate package bytes are invalid: {error}"
                ))
            })?;
        require_digest(
            "incumbent package",
            &self.incumbent_package_digest,
            &incumbent.package_digest,
            ProviderBindingError::InvalidTarget,
        )?;
        require_digest(
            "incumbent package bytes",
            &self.incumbent_package_bytes_digest,
            &ContentDigest::from_bytes(&self.incumbent_package_bytes),
            ProviderBindingError::InvalidTarget,
        )?;
        require_digest(
            "candidate package",
            &self.candidate_package_digest,
            &candidate.package_digest,
            ProviderBindingError::InvalidTarget,
        )?;
        require_digest(
            "candidate package bytes",
            &self.candidate_package_bytes_digest,
            &ContentDigest::from_bytes(&self.candidate_package_bytes),
            ProviderBindingError::InvalidTarget,
        )?;
        require_digest(
            "candidate component",
            &self.candidate_component_digest,
            &candidate.payload.genome.component_digest,
            ProviderBindingError::InvalidTarget,
        )?;
        if candidate.payload.factory_id != incumbent.payload.factory_id
            || candidate.payload.generation
                != incumbent.payload.generation.checked_add(1).ok_or_else(|| {
                    ProviderBindingError::InvalidTarget(
                        "incumbent generation cannot advance".to_string(),
                    )
                })?
            || candidate.payload.parent_package_digest != Some(incumbent.package_digest.clone())
            || candidate.payload.stable_interface != incumbent.payload.stable_interface
            || candidate.payload.worker_catalog != incumbent.payload.worker_catalog
            || candidate.payload.service_dependencies != incumbent.payload.service_dependencies
            || candidate.payload.genome.policy != self.challenger_policy
            || candidate.payload.boot_manifest.state_compatibility != self.state_compatibility
        {
            return Err(ProviderBindingError::InvalidTarget(
                "candidate package is not the exact one-step bounded successor of the retained incumbent"
                    .to_string(),
            ));
        }
        validate_wat_bounds(&self.challenger_wat_bytes)?;
        require_digest(
            "challenger WAT",
            &self.challenger_wat_digest,
            &ContentDigest::from_bytes(&self.challenger_wat_bytes),
            ProviderBindingError::InvalidTarget,
        )?;
        self.challenger_policy.validate().map_err(|error| {
            ProviderBindingError::InvalidTarget(format!("challenger policy is invalid: {error}"))
        })?;
        require_digest(
            "challenger policy",
            &self.challenger_policy_digest,
            &self.challenger_policy.policy_digest().map_err(|error| {
                ProviderBindingError::InvalidTarget(format!(
                    "challenger policy digest cannot be derived: {error}"
                ))
            })?,
            ProviderBindingError::InvalidTarget,
        )?;
        self.state_compatibility.validate().map_err(|error| {
            ProviderBindingError::InvalidTarget(format!("state compatibility is invalid: {error}"))
        })?;
        validate_migration(
            &self.state_compatibility,
            self.migration_plan.as_ref(),
            self.migration_artifacts.as_ref(),
        )?;
        let genome = self.materialized_genome()?;
        if candidate.payload.genome != genome {
            return Err(ProviderBindingError::InvalidTarget(
                "candidate package genome differs from the independently reconstructed WAT and policy"
                    .to_string(),
            ));
        }
        require_digest(
            "target genome",
            &self.target_genome_digest,
            &genome.genome_digest,
            ProviderBindingError::InvalidTarget,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, ProviderBindingError> {
        digest(&(
            PROVIDER_CANDIDATE_TARGET_SCHEMA,
            &self.cycle_id,
            &self.incumbent_package_digest,
            &self.incumbent_package_bytes_digest,
            &self.candidate_package_digest,
            &self.candidate_package_bytes_digest,
            &self.candidate_component_digest,
            &self.release_gate_digest,
            &self.challenger_wat_digest,
            &self.challenger_policy_digest,
            &self.state_compatibility,
            self.migration_plan.as_ref().map(|plan| &plan.plan_digest),
            self.migration_artifacts
                .as_ref()
                .map(|artifacts| &artifacts.bundle_digest),
            &self.operator_context_digest,
            &self.target_genome_digest,
        ))
    }
}

/// Exact provider-proposal material and the external M3/backend proof
/// references returned when that material was admitted.
///
/// This record is a content-addressed copy of evidence owned by the M3 ledger
/// and factory-effect backend. It deliberately has no method that can create,
/// mutate, or certify those external facts. [`crate::m5_runtime::M5Runtime`]
/// re-resolves every reference against both owners whenever the runtime opens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProposalEvidence {
    pub schema: String,
    pub request: FactoryProviderProposalRequest,
    pub result: FactoryProviderProposalResult,
    pub m3_reference: M5M3EffectReference,
    pub evidence_digest: ContentDigest,
}

impl ProviderProposalEvidence {
    pub fn new(
        request: FactoryProviderProposalRequest,
        result: FactoryProviderProposalResult,
        m3_reference: M5M3EffectReference,
    ) -> Result<Self, ProviderBindingError> {
        let mut evidence = Self {
            schema: PROVIDER_PROPOSAL_EVIDENCE_SCHEMA.to_string(),
            request,
            result,
            m3_reference,
            evidence_digest: ContentDigest::from_bytes(&[]),
        };
        evidence.validate_fields()?;
        evidence.evidence_digest = evidence.expected_digest()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), ProviderBindingError> {
        self.validate_fields()?;
        require_digest(
            "provider proposal evidence",
            &self.evidence_digest,
            &self.expected_digest()?,
            ProviderBindingError::InvalidBinding,
        )
    }

    fn validate_fields(&self) -> Result<(), ProviderBindingError> {
        if self.schema != PROVIDER_PROPOSAL_EVIDENCE_SCHEMA {
            return Err(ProviderBindingError::InvalidBinding(
                "unsupported provider proposal evidence schema".to_string(),
            ));
        }
        self.request.validate().map_err(|error| {
            ProviderBindingError::InvalidBinding(format!(
                "provider proposal request is invalid: {error}"
            ))
        })?;
        self.result.validate_for(&self.request).map_err(|error| {
            ProviderBindingError::InvalidBinding(format!(
                "provider proposal result is invalid: {error}"
            ))
        })?;
        let expected_logical_effect_id = format!(
            "m5-provider-proposal:{}",
            self.request.request_digest.file_stem()
        );
        if self.m3_reference.logical_effect_id != expected_logical_effect_id
            || self.m3_reference.invocation_id.trim().is_empty()
        {
            return Err(ProviderBindingError::InvalidBinding(
                "provider proposal M3 reference does not name the canonical exact effect"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, ProviderBindingError> {
        digest(&(
            PROVIDER_PROPOSAL_EVIDENCE_SCHEMA,
            &self.request,
            &self.result,
            &self.m3_reference,
        ))
    }
}

/// Exact qualification evidence and intent sealed against one candidate target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCandidateBinding {
    pub schema: String,
    pub target: ProviderCandidateTarget,
    pub qualification: LiveProviderQualificationRecord,
    pub qualification_record_digest: ContentDigest,
    pub parsed_intent: ParsedProviderIntent,
    pub intent_digest: ContentDigest,
    pub proposal_evidence: ProviderProposalEvidence,
    pub binding_digest: ContentDigest,
}

impl ProviderCandidateBinding {
    pub fn new(
        target: ProviderCandidateTarget,
        qualification: LiveProviderQualificationRecord,
        parsed_intent: ParsedProviderIntent,
        proposal_evidence: ProviderProposalEvidence,
    ) -> Result<Self, ProviderBindingError> {
        target.validate()?;
        validate_exact_intent(&target, &parsed_intent)?;
        validate_qualification(&target, &parsed_intent, &qualification)?;
        validate_proposal_evidence(&target, &qualification, &parsed_intent, &proposal_evidence)?;
        let qualification_record_digest = qualification.record_digest.clone();
        let intent_digest = parsed_intent.intent_digest().map_err(|error| {
            ProviderBindingError::InvalidBinding(format!(
                "provider intent digest cannot be derived: {error}"
            ))
        })?;
        let mut binding = Self {
            schema: PROVIDER_CANDIDATE_BINDING_SCHEMA.to_string(),
            target,
            qualification,
            qualification_record_digest,
            parsed_intent,
            intent_digest,
            proposal_evidence,
            binding_digest: ContentDigest::from_bytes(&[]),
        };
        binding.binding_digest = binding.expected_digest()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), ProviderBindingError> {
        self.validate_with_qualification(None)
    }

    /// Bounded canonical representation used by detached closure evidence.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProviderBindingError> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| ProviderBindingError::Serialization(error.to_string()))?;
        enforce_byte_bound("provider candidate binding", bytes.len(), MAX_BINDING_BYTES)?;
        Ok(bytes)
    }

    /// Parse and fully revalidate one exact detached provider binding.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProviderBindingError> {
        enforce_byte_bound("provider candidate binding", bytes.len(), MAX_BINDING_BYTES)?;
        if bytes.is_empty() {
            return Err(ProviderBindingError::InvalidBinding(
                "provider candidate binding bytes are empty".to_string(),
            ));
        }
        let binding: Self = serde_json::from_slice(bytes)
            .map_err(|error| ProviderBindingError::Serialization(error.to_string()))?;
        let canonical = serde_json::to_vec_pretty(&binding)
            .map_err(|error| ProviderBindingError::Serialization(error.to_string()))?;
        if canonical != bytes {
            return Err(ProviderBindingError::InvalidBinding(
                "provider candidate binding is not in its exact canonical encoding".to_string(),
            ));
        }
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate_with_qualification(
        &self,
        supplied_qualification: Option<&LiveProviderQualificationRecord>,
    ) -> Result<(), ProviderBindingError> {
        if self.schema != PROVIDER_CANDIDATE_BINDING_SCHEMA {
            return Err(ProviderBindingError::InvalidBinding(
                "unsupported provider candidate binding schema".to_string(),
            ));
        }
        self.target.validate()?;
        validate_exact_intent(&self.target, &self.parsed_intent)?;
        validate_qualification(&self.target, &self.parsed_intent, &self.qualification)?;
        validate_proposal_evidence(
            &self.target,
            &self.qualification,
            &self.parsed_intent,
            &self.proposal_evidence,
        )?;
        require_digest(
            "bound qualification record",
            &self.qualification_record_digest,
            &self.qualification.record_digest,
            ProviderBindingError::InvalidBinding,
        )?;
        let expected_intent_digest = self.parsed_intent.intent_digest().map_err(|error| {
            ProviderBindingError::InvalidBinding(format!(
                "provider intent digest cannot be rederived: {error}"
            ))
        })?;
        require_digest(
            "bound provider intent",
            &self.intent_digest,
            &expected_intent_digest,
            ProviderBindingError::InvalidBinding,
        )?;
        require_digest(
            "provider candidate binding",
            &self.binding_digest,
            &self.expected_digest()?,
            ProviderBindingError::InvalidBinding,
        )?;
        if let Some(supplied) = supplied_qualification {
            validate_qualification(&self.target, &self.parsed_intent, supplied)?;
            if supplied != &self.qualification {
                return Err(ProviderBindingError::QualificationMismatch {
                    expected: self.qualification.record_digest.clone(),
                    supplied: supplied.record_digest.clone(),
                });
            }
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, ProviderBindingError> {
        digest(&(
            PROVIDER_CANDIDATE_BINDING_SCHEMA,
            &self.target.target_digest,
            &self.qualification_record_digest,
            &self.intent_digest,
            &self.proposal_evidence.evidence_digest,
        ))
    }
}

/// Sole-writer, append-only store for provider candidate bindings.
///
/// Opening the store acquires an operating-system file lock and validates every
/// retained binding. Publication uses an atomic no-clobber hard link, so an
/// existing digest name is never replaced.
pub struct ProviderCandidateBindingStore {
    root: PathBuf,
    bindings_root: PathBuf,
    _owner_lock: File,
}

impl ProviderCandidateBindingStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ProviderBindingError> {
        let root = secure_create_root(root.as_ref())?;
        let owner_lock = acquire_owner_lock(&root)?;
        let bindings_root = secure_child_directory(&root, BINDING_DIRECTORY)?;
        let store = Self {
            root,
            bindings_root,
            _owner_lock: owner_lock,
        };
        store.validate_all()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn bindings_root(&self) -> &Path {
        &self.bindings_root
    }

    pub fn bind_and_publish(
        &self,
        target: ProviderCandidateTarget,
        qualification: LiveProviderQualificationRecord,
        parsed_intent: ParsedProviderIntent,
        proposal_evidence: ProviderProposalEvidence,
    ) -> Result<ProviderCandidateBinding, ProviderBindingError> {
        self.publish(ProviderCandidateBinding::new(
            target,
            qualification,
            parsed_intent,
            proposal_evidence,
        )?)
    }

    pub fn publish(
        &self,
        binding: ProviderCandidateBinding,
    ) -> Result<ProviderCandidateBinding, ProviderBindingError> {
        binding.validate()?;
        enforce_item_bound(
            "provider candidate bindings",
            directory_entry_count(&self.bindings_root)?.saturating_add(1),
            MAX_BINDINGS,
        )?;
        let bytes = serde_json::to_vec_pretty(&binding)
            .map_err(|error| ProviderBindingError::Serialization(error.to_string()))?;
        enforce_byte_bound("provider candidate binding", bytes.len(), MAX_BINDING_BYTES)?;
        let destination = self.binding_path(&binding.binding_digest);
        persist_immutable_named(&self.bindings_root, &destination, &bytes)?;
        Ok(binding)
    }

    /// Load and fully revalidate a binding, optionally cross-checking the
    /// independently supplied qualification record used as its trust anchor.
    pub fn load(
        &self,
        binding_digest: &ContentDigest,
        supplied_qualification: Option<&LiveProviderQualificationRecord>,
    ) -> Result<ProviderCandidateBinding, ProviderBindingError> {
        let path = self.binding_path(binding_digest);
        if !path.exists() {
            return Err(ProviderBindingError::NotFound(binding_digest.clone()));
        }
        let binding = self.load_path(&path, supplied_qualification)?;
        require_digest(
            "requested provider candidate binding",
            &binding.binding_digest,
            binding_digest,
            ProviderBindingError::InvalidBinding,
        )?;
        Ok(binding)
    }

    /// Revalidate every durable record and return them in digest-name order.
    pub fn validate_all(&self) -> Result<Vec<ProviderCandidateBinding>, ProviderBindingError> {
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.bindings_root)
            .map_err(|source| ProviderBindingError::io(&self.bindings_root, source))?
        {
            let entry =
                entry.map_err(|source| ProviderBindingError::io(&self.bindings_root, source))?;
            paths.push(entry.path());
            enforce_item_bound("provider candidate bindings", paths.len(), MAX_BINDINGS)?;
        }
        paths.sort();
        paths
            .iter()
            .map(|path| self.load_path(path, None))
            .collect()
    }

    fn binding_path(&self, binding_digest: &ContentDigest) -> PathBuf {
        self.bindings_root
            .join(format!("{}.json", binding_digest.file_stem()))
    }

    fn load_path(
        &self,
        path: &Path,
        supplied_qualification: Option<&LiveProviderQualificationRecord>,
    ) -> Result<ProviderCandidateBinding, ProviderBindingError> {
        if path.parent() != Some(self.bindings_root.as_path()) {
            return Err(ProviderBindingError::UnsafePath(path.to_path_buf()));
        }
        let bytes = read_regular_file_bounded(path, MAX_BINDING_BYTES)?;
        let binding: ProviderCandidateBinding = serde_json::from_slice(&bytes)
            .map_err(|error| ProviderBindingError::Serialization(error.to_string()))?;
        let canonical = serde_json::to_vec_pretty(&binding)
            .map_err(|error| ProviderBindingError::Serialization(error.to_string()))?;
        if canonical != bytes {
            return Err(ProviderBindingError::InvalidBinding(format!(
                "binding file '{}' is not the exact canonical encoding",
                path.display()
            )));
        }
        binding.validate_with_qualification(supplied_qualification)?;
        let expected_path = self.binding_path(&binding.binding_digest);
        if expected_path != path {
            return Err(ProviderBindingError::InvalidBinding(format!(
                "binding file '{}' does not match its content digest",
                path.display()
            )));
        }
        Ok(binding)
    }
}

fn validate_exact_intent(
    target: &ProviderCandidateTarget,
    intent: &ParsedProviderIntent,
) -> Result<(), ProviderBindingError> {
    intent.intent_digest().map_err(|error| {
        ProviderBindingError::InvalidBinding(format!("provider intent is invalid: {error}"))
    })?;
    if intent.intent_schema != PROVIDER_CANDIDATE_INTENT_SCHEMA {
        return Err(ProviderBindingError::InvalidBinding(
            "provider intent uses an unsupported schema".to_string(),
        ));
    }
    if intent.operation != PROVIDER_CANDIDATE_OPERATION {
        return Err(ProviderBindingError::InvalidBinding(format!(
            "provider intent must request exactly '{PROVIDER_CANDIDATE_OPERATION}'"
        )));
    }
    let expected_arguments = BTreeMap::from([
        ("cycle_id".to_string(), target.cycle_id.clone()),
        (
            "challenger_wat_digest".to_string(),
            target.challenger_wat_digest.as_str().to_string(),
        ),
        (
            "policy_digest".to_string(),
            target.challenger_policy_digest.as_str().to_string(),
        ),
        (
            "invocation_challenge_digest".to_string(),
            intent
                .arguments
                .get("invocation_challenge_digest")
                .and_then(|value| ContentDigest::new(value.clone()).ok())
                .ok_or_else(|| {
                    ProviderBindingError::InvalidBinding(
                        "provider intent invocation challenge is not a valid SHA-256 digest"
                            .to_string(),
                    )
                })?
                .as_str()
                .to_string(),
        ),
    ]);
    if intent.arguments != expected_arguments {
        return Err(ProviderBindingError::InvalidBinding(
            "provider intent arguments must be exactly cycle_id, challenger_wat_digest, policy_digest, and one valid invocation challenge with target-matching values"
                .to_string(),
        ));
    }
    require_digest(
        "provider intent target genome",
        &intent.target_genome_digest,
        &target.materialized_genome()?.genome_digest,
        ProviderBindingError::InvalidBinding,
    )
}

fn validate_proposal_evidence(
    target: &ProviderCandidateTarget,
    qualification: &LiveProviderQualificationRecord,
    intent: &ParsedProviderIntent,
    evidence: &ProviderProposalEvidence,
) -> Result<(), ProviderBindingError> {
    evidence.validate()?;
    let request = &evidence.request;
    let frozen = &request.qualification_request;
    let result = &evidence.result;
    let turn = qualification.live_turn.as_ref().ok_or_else(|| {
        ProviderBindingError::InvalidBinding(
            "provider proposal has no exact qualified live turn".to_string(),
        )
    })?;
    let replay = qualification.replay.as_ref().ok_or_else(|| {
        ProviderBindingError::InvalidBinding(
            "provider proposal has no exact qualified offline replay".to_string(),
        )
    })?;
    let expected_replay_request = ProviderReplayRequest::new(frozen, turn).map_err(|error| {
        ProviderBindingError::InvalidBinding(format!(
            "provider proposal offline replay request cannot be rederived: {error}"
        ))
    })?;
    let expected_invocation_challenge = frozen
        .invocation_challenge_digest
        .clone()
        .unwrap_or_else(unbound_provider_invocation_challenge_digest);
    if frozen.qualification_id != qualification.qualification_id
        || frozen.package_digest != qualification.package_digest
        || frozen.target_digest != qualification.target_digest
        || frozen.target_digest != target.target_digest
        || frozen.request_digest != qualification.request_digest
        || frozen.replay_capsule.capsule_digest != qualification.replay_capsule_digest
        || frozen.configuration.fingerprint().map_err(|error| {
            ProviderBindingError::InvalidBinding(format!(
                "provider proposal configuration cannot be fingerprinted: {error}"
            ))
        })? != qualification.configuration_fingerprint
        || turn.request_digest != frozen.request_digest
        || turn.replay_capsule_digest != frozen.replay_capsule.capsule_digest
        || turn.configuration_fingerprint != qualification.configuration_fingerprint
        || turn.transcript.raw_prompt_digest != ContentDigest::from_bytes(&frozen.prompt_bytes)
        || request.normalized_parser_input_bytes != turn.normalized_parser_input_bytes
        || turn.provider_accounting.provider_id != frozen.configuration.provider_id
        || turn.provider_accounting.model_id != frozen.configuration.model_id
        || turn.provider_accounting.provider_profile != frozen.configuration.provider_profile
        || turn.provider_accounting.generation_policy_id
            != frozen.configuration.generation_policy_id
        || turn.provider_accounting.maximum_retries != frozen.configuration.maximum_retries
        || turn.provider_accounting.maximum_output_tokens
            != frozen.configuration.maximum_output_tokens
        || turn.provider_accounting.input_cost_per_million_microunits
            != frozen.configuration.input_cost_per_million_microunits
        || turn.provider_accounting.output_cost_per_million_microunits
            != frozen.configuration.output_cost_per_million_microunits
        || turn.provider_accounting.currency != frozen.configuration.cost_currency
        || turn.provider_accounting.response_schema_digest
            != frozen.configuration.response_schema_digest
        || turn.provider_accounting.generation_policy_digest
            != frozen.configuration.generation_policy_digest
        || intent
            .arguments
            .get("invocation_challenge_digest")
            .map(String::as_str)
            != Some(expected_invocation_challenge.as_str())
    {
        return Err(ProviderBindingError::InvalidBinding(
            "provider proposal request is cross-linked from a different qualification, capsule, target, prompt, or parser input"
                .to_string(),
        ));
    }
    if replay.request_digest != expected_replay_request.request_digest
        || replay.parser_digest != frozen.configuration.parser_digest
    {
        return Err(ProviderBindingError::InvalidBinding(
            "provider proposal offline replay does not bind the exact frozen request and parser"
                .to_string(),
        ));
    }
    let intent_digest = intent.intent_digest().map_err(|error| {
        ProviderBindingError::InvalidBinding(format!(
            "bound provider proposal intent cannot be digested: {error}"
        ))
    })?;
    if result.qualification_request_digest != frozen.request_digest
        || result.replay_capsule_digest != frozen.replay_capsule.capsule_digest
        || result.target_digest != target.target_digest
        || result.proposed_target_genome_digest != target.target_genome_digest
        || result.intent_digest != intent_digest
        || ContentDigest::from_bytes(&request.normalized_parser_input_bytes)
            != result.normalized_parser_input_digest
    {
        return Err(ProviderBindingError::InvalidBinding(
            "provider proposal result does not bind the exact qualification, target, capsule, normalized parser input, and parsed intent"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_qualification(
    target: &ProviderCandidateTarget,
    intent: &ParsedProviderIntent,
    qualification: &LiveProviderQualificationRecord,
) -> Result<(), ProviderBindingError> {
    if qualification.schema != LIVE_PROVIDER_QUALIFICATION_SCHEMA {
        return Err(ProviderBindingError::InvalidQualification(
            "unsupported live-provider qualification schema".to_string(),
        ));
    }
    validate_identifier("qualification_id", &qualification.qualification_id)
        .map_err(|error| ProviderBindingError::InvalidQualification(error.to_string()))?;
    require_digest(
        "qualified incumbent package",
        &qualification.package_digest,
        &target.incumbent_package_digest,
        ProviderBindingError::InvalidQualification,
    )?;
    require_digest(
        "qualified provider target",
        &qualification.target_digest,
        &target.target_digest,
        ProviderBindingError::InvalidQualification,
    )?;
    if qualification.status != ProviderQualificationStatus::Qualified {
        return Err(ProviderBindingError::InvalidQualification(
            "provider qualification is not qualified".to_string(),
        ));
    }
    if qualification.failure.is_some() {
        return Err(ProviderBindingError::InvalidQualification(
            "qualified provider record carries a failure".to_string(),
        ));
    }
    let turn = qualification.live_turn.as_ref().ok_or_else(|| {
        ProviderBindingError::InvalidQualification(
            "qualified provider record has no live turn".to_string(),
        )
    })?;
    let replay = qualification.replay.as_ref().ok_or_else(|| {
        ProviderBindingError::InvalidQualification(
            "qualified provider record has no offline replay".to_string(),
        )
    })?;
    validate_identifier("external_turn_id", &turn.external_turn_id)
        .map_err(|error| ProviderBindingError::InvalidQualification(error.to_string()))?;
    if turn.request_digest != qualification.request_digest
        || turn.configuration_fingerprint != qualification.configuration_fingerprint
        || turn.replay_capsule_digest != qualification.replay_capsule_digest
        || turn.transcript.request_digest != qualification.request_digest
        || turn.normalized_parser_input_bytes != turn.transcript.redacted_response.as_bytes()
    {
        return Err(ProviderBindingError::InvalidQualification(
            "live-turn request or configuration identity differs from its qualification"
                .to_string(),
        ));
    }
    validate_redacted_transcript(
        &turn.transcript.redacted_prompt,
        &turn.transcript.redacted_response,
        turn.transcript.redaction_applied,
    )?;
    let expected_turn = turn.clone().seal().map_err(|error| {
        ProviderBindingError::InvalidQualification(format!(
            "live-provider turn digest cannot be rederived: {error}"
        ))
    })?;
    if &expected_turn != turn {
        return Err(ProviderBindingError::InvalidQualification(
            "live-provider turn digest does not match its exact evidence".to_string(),
        ));
    }
    if replay.network_used {
        return Err(ProviderBindingError::InvalidQualification(
            "offline provider replay used network access".to_string(),
        ));
    }
    let expected_replay = replay.clone().seal().map_err(|error| {
        ProviderBindingError::InvalidQualification(format!(
            "provider replay digest cannot be rederived: {error}"
        ))
    })?;
    if &expected_replay != replay {
        return Err(ProviderBindingError::InvalidQualification(
            "provider replay digest does not match its exact evidence".to_string(),
        ));
    }
    if &turn.parsed_intent != intent || &replay.parsed_intent != intent {
        return Err(ProviderBindingError::InvalidQualification(
            "live and offline qualification evidence do not contain the exact bound intent"
                .to_string(),
        ));
    }
    validate_exact_intent(target, &turn.parsed_intent)?;
    let expected_record_digest = digest(&(
        LIVE_PROVIDER_QUALIFICATION_SCHEMA,
        &qualification.qualification_id,
        &qualification.package_digest,
        &qualification.target_digest,
        &qualification.replay_capsule_digest,
        &qualification.configuration_fingerprint,
        &qualification.request_digest,
        qualification.status,
        &qualification.live_turn,
        &qualification.replay,
        &qualification.failure,
    ))?;
    require_digest(
        "live-provider qualification record",
        &qualification.record_digest,
        &expected_record_digest,
        ProviderBindingError::InvalidQualification,
    )
}

fn validate_redacted_transcript(
    prompt: &str,
    response: &str,
    redaction_applied: bool,
) -> Result<(), ProviderBindingError> {
    if !redaction_applied || prompt.trim().is_empty() || response.trim().is_empty() {
        return Err(ProviderBindingError::InvalidQualification(
            "provider transcript is absent or was not redacted".to_string(),
        ));
    }
    let byte_len = prompt.len().saturating_add(response.len());
    if byte_len > MAX_TRANSCRIPT_BYTES {
        return Err(ProviderBindingError::ResourceBoundExceeded {
            resource: "redacted provider transcript",
            actual: byte_len,
            limit: MAX_TRANSCRIPT_BYTES,
        });
    }
    if contains_obvious_secret(prompt) || contains_obvious_secret(response) {
        return Err(ProviderBindingError::InvalidQualification(
            "redacted transcript contains an obvious credential-shaped token".to_string(),
        ));
    }
    Ok(())
}

fn contains_obvious_secret(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.contains("authorization: bearer ")
        || lowercase.contains("api_key=")
        || lowercase.contains("apikey=")
        || lowercase.contains("sk-proj-")
}

fn validate_migration(
    compatibility: &StateCompatibility,
    plan: Option<&StateMigrationPlan>,
    artifacts: Option<&StateMigrationArtifactBundle>,
) -> Result<(), ProviderBindingError> {
    match (plan, artifacts) {
        (None, None) => Ok(()),
        (Some(_), None) => Err(ProviderBindingError::InvalidTarget(
            "migration plan requires exact executable forward and rollback artifacts".to_string(),
        )),
        (None, Some(_)) => Err(ProviderBindingError::InvalidTarget(
            "migration artifacts must not be supplied without a migration plan".to_string(),
        )),
        (Some(plan), Some(artifacts)) => {
            plan.validate().map_err(|error| {
                ProviderBindingError::InvalidTarget(format!(
                    "state migration plan is invalid: {error}"
                ))
            })?;
            artifacts.validate().map_err(|error| {
                ProviderBindingError::InvalidTarget(format!(
                    "state migration artifacts are invalid: {error}"
                ))
            })?;
            if plan.migration_program_digest != artifacts.bundle_digest {
                return Err(ProviderBindingError::InvalidTarget(
                    "migration plan does not bind the supplied artifact bundle".to_string(),
                ));
            }
            if plan.from_schema != artifacts.forward.from_schema
                || plan.to_schema != artifacts.forward.to_schema
                || plan.rollback_schema != artifacts.rollback.to_schema
                || plan.rollback_schema != plan.from_schema
                || compatibility.written_schema != plan.to_schema
                || plan.from_schema < compatibility.readable_schema_min
                || plan.from_schema > compatibility.readable_schema_max
            {
                return Err(ProviderBindingError::InvalidTarget(
                    "migration schemas do not match the challenger compatibility and exact forward/rollback edges"
                        .to_string(),
                ));
            }
            if plan.maximum_state_bytes > MAX_MIGRATION_STATE_BYTES {
                return Err(ProviderBindingError::InvalidTarget(format!(
                    "migration state budget exceeds {MAX_MIGRATION_STATE_BYTES} bytes"
                )));
            }
            Ok(())
        }
    }
}

fn compile_wat(wat_bytes: &[u8]) -> Result<Vec<u8>, ProviderBindingError> {
    validate_wat_bounds(wat_bytes)?;
    wat::parse_bytes(wat_bytes)
        .map(|bytes| bytes.into_owned())
        .map_err(|error| {
            ProviderBindingError::InvalidTarget(format!("challenger WAT did not compile: {error}"))
        })
}

fn validate_wat_bounds(wat_bytes: &[u8]) -> Result<(), ProviderBindingError> {
    if wat_bytes.is_empty() || wat_bytes.len() > MAX_WAT_BYTES {
        return Err(ProviderBindingError::ResourceBoundExceeded {
            resource: "challenger WAT",
            actual: wat_bytes.len(),
            limit: MAX_WAT_BYTES,
        });
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ProviderBindingError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ProviderBindingError::InvalidTarget(format!(
            "{field} must contain 1..={MAX_IDENTIFIER_BYTES} non-control characters"
        )));
    }
    Ok(())
}

fn digest<T: Serialize>(value: &T) -> Result<ContentDigest, ProviderBindingError> {
    digest_json_content(value)
        .map_err(|error| ProviderBindingError::Serialization(error.to_string()))
}

fn require_digest<F>(
    subject: &str,
    actual: &ContentDigest,
    expected: &ContentDigest,
    error: F,
) -> Result<(), ProviderBindingError>
where
    F: FnOnce(String) -> ProviderBindingError,
{
    if actual == expected {
        Ok(())
    } else {
        Err(error(format!(
            "{subject} digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

fn secure_create_root(path: &Path) -> Result<PathBuf, ProviderBindingError> {
    if path.as_os_str().is_empty() {
        return Err(ProviderBindingError::InvalidStore(
            "binding-store root must not be empty".to_string(),
        ));
    }
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| ProviderBindingError::io(path, source))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| ProviderBindingError::io(path, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ProviderBindingError::UnsafePath(path.to_path_buf()));
    }
    fs::canonicalize(path).map_err(|source| ProviderBindingError::io(path, source))
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, ProviderBindingError> {
    let path = root.join(name);
    reject_symlink_if_present(&path)?;
    fs::create_dir_all(&path).map_err(|source| ProviderBindingError::io(&path, source))?;
    let canonical =
        fs::canonicalize(&path).map_err(|source| ProviderBindingError::io(&path, source))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|source| ProviderBindingError::io(&canonical, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || canonical.parent() != Some(root) {
        return Err(ProviderBindingError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn acquire_owner_lock(root: &Path) -> Result<File, ProviderBindingError> {
    let path = root.join(OWNER_LOCK_FILE);
    reject_symlink_if_present(&path)?;
    if path.exists() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| ProviderBindingError::io(&path, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(ProviderBindingError::UnsafePath(path));
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| ProviderBindingError::io(&path, source))?;
    file.try_lock().map_err(|source| match source {
        std::fs::TryLockError::WouldBlock => ProviderBindingError::Conflict(format!(
            "provider candidate binding root '{}' already has a live owner",
            root.display()
        )),
        std::fs::TryLockError::Error(source) => ProviderBindingError::io(&path, source),
    })?;
    Ok(file)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), ProviderBindingError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ProviderBindingError::UnsafePath(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ProviderBindingError::io(path, source)),
    }
}

fn read_regular_file_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ProviderBindingError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| ProviderBindingError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ProviderBindingError::UnsafePath(path.to_path_buf()));
    }
    let byte_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    enforce_byte_bound("durable provider binding", byte_len, limit)?;
    let mut bytes = Vec::with_capacity(byte_len);
    File::open(path)
        .map_err(|source| ProviderBindingError::io(path, source))?
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ProviderBindingError::io(path, source))?;
    enforce_byte_bound("durable provider binding", bytes.len(), limit)?;
    Ok(bytes)
}

fn directory_entry_count(directory: &Path) -> Result<usize, ProviderBindingError> {
    let mut count = 0usize;
    for entry in
        fs::read_dir(directory).map_err(|source| ProviderBindingError::io(directory, source))?
    {
        entry.map_err(|source| ProviderBindingError::io(directory, source))?;
        count = count.saturating_add(1);
        enforce_item_bound("provider candidate bindings", count, MAX_BINDINGS)?;
    }
    Ok(count)
}

/// Atomically publish immutable bytes without replacing an existing name.
fn persist_immutable_named(
    directory: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), ProviderBindingError> {
    if destination.parent() != Some(directory) {
        return Err(ProviderBindingError::UnsafePath(destination.to_path_buf()));
    }
    reject_symlink_if_present(destination)?;
    if destination.exists() {
        let existing = read_regular_file_bounded(destination, MAX_BINDING_BYTES)?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(ProviderBindingError::ImmutableConflict(
                destination.to_path_buf(),
            ))
        };
    }
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(
        ".provider-binding-{}-{sequence}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| ProviderBindingError::io(&temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| ProviderBindingError::io(&temporary, source))?;
        file.sync_all()
            .map_err(|source| ProviderBindingError::io(&temporary, source))?;
        match fs::hard_link(&temporary, destination) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_regular_file_bounded(destination, MAX_BINDING_BYTES)?;
                if existing != bytes {
                    return Err(ProviderBindingError::ImmutableConflict(
                        destination.to_path_buf(),
                    ));
                }
            }
            Err(source) => return Err(ProviderBindingError::io(destination, source)),
        }
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ProviderBindingError::io(directory, source))
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn enforce_byte_bound(
    resource: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), ProviderBindingError> {
    if actual > limit {
        Err(ProviderBindingError::ResourceBoundExceeded {
            resource,
            actual,
            limit,
        })
    } else {
        Ok(())
    }
}

fn enforce_item_bound(
    resource: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), ProviderBindingError> {
    if actual > limit {
        Err(ProviderBindingError::ResourceBoundExceeded {
            resource,
            actual,
            limit,
        })
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum ProviderBindingError {
    InvalidStore(String),
    InvalidTarget(String),
    InvalidQualification(String),
    InvalidBinding(String),
    QualificationMismatch {
        expected: ContentDigest,
        supplied: ContentDigest,
    },
    NotFound(ContentDigest),
    Conflict(String),
    ImmutableConflict(PathBuf),
    UnsafePath(PathBuf),
    ResourceBoundExceeded {
        resource: &'static str,
        actual: usize,
        limit: usize,
    },
    Serialization(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl ProviderBindingError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl Display for ProviderBindingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStore(message) => write!(formatter, "invalid binding store: {message}"),
            Self::InvalidTarget(message) => {
                write!(formatter, "invalid candidate target: {message}")
            }
            Self::InvalidQualification(message) => {
                write!(formatter, "invalid provider qualification: {message}")
            }
            Self::InvalidBinding(message) => {
                write!(formatter, "invalid provider candidate binding: {message}")
            }
            Self::QualificationMismatch { expected, supplied } => write!(
                formatter,
                "supplied qualification {supplied} does not match bound qualification {expected}"
            ),
            Self::NotFound(digest) => write!(formatter, "provider binding {digest} was not found"),
            Self::Conflict(message) => write!(formatter, "binding-store conflict: {message}"),
            Self::ImmutableConflict(path) => write!(
                formatter,
                "immutable provider binding conflicts with '{}'",
                path.display()
            ),
            Self::UnsafePath(path) => {
                write!(
                    formatter,
                    "unsafe provider-binding path '{}'",
                    path.display()
                )
            }
            Self::ResourceBoundExceeded {
                resource,
                actual,
                limit,
            } => write!(
                formatter,
                "{resource} exceeds its bound: {actual} > {limit}"
            ),
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "provider-binding serialization failed: {message}"
                )
            }
            Self::Io { path, source } => {
                write!(formatter, "I/O at '{}': {source}", path.display())
            }
        }
    }
}

impl Error for ProviderBindingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::execution::inference::{InferenceFinishReason, InferenceRetryClassification};
    use crate::factory_reproduction::{
        LiveProviderTurn, M5ProviderAccountingSummaryV1, M5ProviderAttemptSummaryV1,
        M5ProviderProfileV1, ProviderConfiguration, ProviderQualificationRequest,
        ProviderReplayCapsule, ProviderReplayRecord, ProviderTransport, RedactedTranscript,
        ServiceDependencyCatalog, StableInterfaceContract, WorkerCatalog,
    };
    use crate::m5_effect_store::{
        StateTransformArtifact, StateTransformDirection, StateTransformProgram,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-provider-binding-{label}-{}-{nonce}",
                std::process::id()
            ));
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn component_wat() -> Vec<u8> {
        br#"(component
  (core module $candidate
    (func (export "transform") (param i32) (result i32)
      local.get 0
      i32.const 1
      i32.add))
  (core instance $candidate-instance (instantiate $candidate))
  (func $transform (param "input" s32) (result s32)
    (canon lift (core func $candidate-instance "transform")))
  (export "transform" (func $transform)))"#
            .to_vec()
    }

    fn incumbent_wat() -> Vec<u8> {
        br#"(component
  (core module $incumbent
    (func (export "transform") (param i32) (result i32)
      local.get 0))
  (core instance $incumbent-instance (instantiate $incumbent))
  (func $transform (param "input" s32) (result s32)
    (canon lift (core func $incumbent-instance "transform")))
  (export "transform" (func $transform)))"#
            .to_vec()
    }

    fn compatibility(schema: u32) -> StateCompatibility {
        StateCompatibility {
            readable_schema_min: 1,
            readable_schema_max: schema,
            written_schema: schema,
            incumbent_rollback_readable_through: schema,
        }
    }

    fn packages(
        policy: MutableFactoryPolicy,
        candidate_compatibility: StateCompatibility,
    ) -> (FactoryPackage, FactoryPackage) {
        let incumbent = FactoryPackage::build(
            "factory:provider-binding-test",
            0,
            MutableGenome::new(
                None,
                compile_wat(&incumbent_wat()).expect("compile incumbent"),
                MutableFactoryPolicy::terminal(1, 4),
            )
            .expect("incumbent genome"),
            StableInterfaceContract::reference(),
            WorkerCatalog::reference().expect("worker catalog"),
            ServiceDependencyCatalog::reference().expect("service catalog"),
            compatibility(1),
        )
        .expect("incumbent package");
        let candidate = FactoryPackage::build(
            "factory:provider-binding-test",
            1,
            MutableGenome::new(
                Some(incumbent.package_digest.clone()),
                compile_wat(&component_wat()).expect("compile candidate"),
                policy,
            )
            .expect("candidate genome"),
            incumbent.payload.stable_interface.clone(),
            incumbent.payload.worker_catalog.clone(),
            incumbent.payload.service_dependencies.clone(),
            candidate_compatibility,
        )
        .expect("candidate package");
        (incumbent, candidate)
    }

    fn target() -> ProviderCandidateTarget {
        let policy = MutableFactoryPolicy::terminal(1, 4);
        let (incumbent, candidate) = packages(policy.clone(), compatibility(1));
        ProviderCandidateTarget::new(
            "cycle-provider-1",
            &incumbent,
            &candidate,
            ContentDigest::from_bytes(b"release-gate"),
            component_wat(),
            policy,
            compatibility(1),
            None,
            None,
            ContentDigest::from_bytes(b"operator-context"),
        )
        .expect("candidate target")
    }

    fn intent_for(target: &ProviderCandidateTarget) -> ParsedProviderIntent {
        ParsedProviderIntent {
            intent_schema: PROVIDER_CANDIDATE_INTENT_SCHEMA.to_string(),
            operation: PROVIDER_CANDIDATE_OPERATION.to_string(),
            target_genome_digest: target.target_genome_digest.clone(),
            arguments: BTreeMap::from([
                ("cycle_id".to_string(), target.cycle_id.clone()),
                (
                    "challenger_wat_digest".to_string(),
                    target.challenger_wat_digest.as_str().to_string(),
                ),
                (
                    "policy_digest".to_string(),
                    target.challenger_policy_digest.as_str().to_string(),
                ),
                (
                    "invocation_challenge_digest".to_string(),
                    unbound_provider_invocation_challenge_digest()
                        .as_str()
                        .to_string(),
                ),
            ]),
        }
    }

    fn qualification_for(
        target: &ProviderCandidateTarget,
        intent: &ParsedProviderIntent,
        qualification_id: &str,
    ) -> (
        ProviderQualificationRequest,
        LiveProviderQualificationRecord,
    ) {
        let argument_schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": [
                "cycle_id",
                "challenger_wat_digest",
                "policy_digest",
                "invocation_challenge_digest"
            ],
            "properties": {
                "cycle_id": {"type": "string"},
                "challenger_wat_digest": {"type": "string"},
                "policy_digest": {"type": "string"},
                "invocation_challenge_digest": {"type": "string"}
            }
        });
        let selected_tool = serde_json::json!({
            "type": "function",
            "name": PROVIDER_CANDIDATE_OPERATION,
            "parameters": argument_schema
        });
        let tool_catalog_bytes =
            serde_json::to_vec(&vec![selected_tool.clone()]).expect("tool catalog");
        let selected_tool_bytes =
            serde_json::to_vec(&selected_tool).expect("selected provider tool");
        let argument_schema_bytes =
            serde_json::to_vec(&argument_schema).expect("provider argument schema");
        let response_schema_bytes = serde_json::to_vec(&serde_json::json!({
            "type": "object"
        }))
        .expect("provider response schema");
        let configuration = ProviderConfiguration {
            provider_id: "provider:test".to_string(),
            model_id: "model:test".to_string(),
            provider_profile: M5ProviderProfileV1::OpenAiResponses,
            api_base_url: "https://provider.example.test/v1/".to_string(),
            endpoint_class: crate::factory_reproduction::M5ProviderEndpointClassV1::ExternalHttps,
            driver_profile_digest: ContentDigest::from_bytes(b"driver-profile"),
            generation_policy_id: "fixture-generation-policy".to_string(),
            generation_policy_digest: ContentDigest::from_bytes(b"generation-policy"),
            maximum_retries: 0,
            maximum_output_tokens: 512,
            input_cost_per_million_microunits: 100_000,
            output_cost_per_million_microunits: 0,
            cost_currency: "usd".to_string(),
            parser_digest: ContentDigest::from_bytes(b"provider-parser"),
            response_schema_digest: ContentDigest::from_bytes(&response_schema_bytes),
            prompt_renderer_digest: ContentDigest::from_bytes(b"prompt-renderer"),
            tool_catalog_digest: ContentDigest::from_bytes(&tool_catalog_bytes),
        };
        let prompt_bytes = serde_json::to_vec(&serde_json::json!({
            "qualification_id": qualification_id,
            "required_response": {
                "operation": &intent.operation,
                "target_genome_digest": &intent.target_genome_digest,
                "arguments": &intent.arguments,
            }
        }))
        .expect("frozen provider prompt");
        let replay_capsule = ProviderReplayCapsule::new(
            &configuration,
            prompt_bytes.clone(),
            tool_catalog_bytes,
            selected_tool_bytes,
            argument_schema_bytes,
            response_schema_bytes,
        )
        .expect("provider replay capsule");
        let request = ProviderQualificationRequest::new(
            qualification_id,
            target.incumbent_package_digest.clone(),
            target.target_digest.clone(),
            configuration,
            prompt_bytes,
            replay_capsule,
        )
        .expect("provider qualification request");
        let configuration_fingerprint = request
            .configuration
            .fingerprint()
            .expect("configuration fingerprint");
        let replay_capsule_digest = request.replay_capsule.capsule_digest.clone();
        let normalized_parser_input_bytes =
            serde_json::to_vec(&intent.arguments).expect("normalized proposal input");
        let transcript = RedactedTranscript {
            request_digest: request.request_digest.clone(),
            redacted_prompt: "[REDACTED PROMPT]".to_string(),
            redacted_response: String::from_utf8(normalized_parser_input_bytes.clone())
                .expect("normalized proposal is UTF-8"),
            raw_prompt_digest: ContentDigest::from_bytes(&request.prompt_bytes),
            raw_response_digest: ContentDigest::from_bytes(b"raw-response"),
            redaction_applied: true,
        };
        let provider_accounting = M5ProviderAccountingSummaryV1::new(
            request.configuration.provider_id.clone(),
            request.configuration.model_id.clone(),
            request.configuration.provider_profile,
            request.configuration.response_schema_digest.clone(),
            request.configuration.generation_policy_id.clone(),
            request.configuration.generation_policy_digest.clone(),
            request.configuration.maximum_retries,
            request.configuration.maximum_output_tokens,
            request.configuration.input_cost_per_million_microunits,
            request.configuration.output_cost_per_million_microunits,
            InferenceFinishReason::Completed,
            10,
            5,
            15,
            1,
            request.configuration.cost_currency.clone(),
            7,
            vec![M5ProviderAttemptSummaryV1 {
                attempt_number: 1,
                http_status: Some(200),
                latency_ms: 7,
                retry_classification: InferenceRetryClassification::NoRetryNeeded,
                request_body_digest: request.request_digest.clone(),
                raw_response_digest: transcript.raw_response_digest.clone(),
            }],
            &transcript,
        )
        .expect("provider accounting summary");
        let turn = LiveProviderTurn {
            request_digest: request.request_digest.clone(),
            configuration_fingerprint: configuration_fingerprint.clone(),
            replay_capsule_digest: replay_capsule_digest.clone(),
            transport: ProviderTransport::LiveProviderApi,
            external_turn_id: format!("turn-{qualification_id}"),
            provider_receipt_digest: provider_accounting.accounting_digest.clone(),
            provider_accounting,
            transcript,
            normalized_parser_input_bytes,
            parsed_intent: intent.clone(),
            turn_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .expect("seal live turn");
        let replay_request =
            ProviderReplayRequest::new(&request, &turn).expect("derive offline replay request");
        let replay = ProviderReplayRecord {
            request_digest: replay_request.request_digest,
            network_used: false,
            parsed_intent: intent.clone(),
            parser_digest: request.configuration.parser_digest.clone(),
            replay_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .expect("seal offline replay");
        let mut record = LiveProviderQualificationRecord {
            schema: LIVE_PROVIDER_QUALIFICATION_SCHEMA.to_string(),
            qualification_id: qualification_id.to_string(),
            package_digest: target.incumbent_package_digest.clone(),
            target_digest: target.target_digest.clone(),
            replay_capsule_digest,
            configuration_fingerprint,
            request_digest: request.request_digest.clone(),
            status: ProviderQualificationStatus::Qualified,
            live_turn: Some(turn),
            replay: Some(replay),
            failure: None,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        record.record_digest = digest(&(
            LIVE_PROVIDER_QUALIFICATION_SCHEMA,
            &record.qualification_id,
            &record.package_digest,
            &record.target_digest,
            &record.replay_capsule_digest,
            &record.configuration_fingerprint,
            &record.request_digest,
            record.status,
            &record.live_turn,
            &record.replay,
            &record.failure,
        ))
        .expect("qualification digest");
        (request, record)
    }

    fn proposal_evidence_for(
        request: ProviderQualificationRequest,
        qualification: &LiveProviderQualificationRecord,
    ) -> ProviderProposalEvidence {
        let proposal_request = FactoryProviderProposalRequest::new(
            request,
            qualification
                .live_turn
                .as_ref()
                .expect("qualified live turn")
                .normalized_parser_input_bytes
                .clone(),
        )
        .expect("provider proposal request");
        let proposal_result = FactoryProviderProposalResult::from_request(&proposal_request)
            .expect("provider proposal result");
        let m3_reference = M5M3EffectReference {
            logical_effect_id: format!(
                "m5-provider-proposal:{}",
                proposal_request.request_digest.file_stem()
            ),
            invocation_id: format!("invocation:{}", proposal_request.request_digest.file_stem()),
            receipt_digest: ContentDigest::from_bytes(b"m3-receipt"),
            attestation_digest: ContentDigest::from_bytes(b"m3-attestation"),
            proof_digest: ContentDigest::from_bytes(b"m3-proof"),
            backend_fact_digest: ContentDigest::from_bytes(b"backend-fact"),
        };
        ProviderProposalEvidence::new(proposal_request, proposal_result, m3_reference)
            .expect("provider proposal evidence")
    }

    pub(crate) fn binding() -> ProviderCandidateBinding {
        let target = target();
        let intent = intent_for(&target);
        let (request, qualification) = qualification_for(&target, &intent, "qualification-1");
        let proposal_evidence = proposal_evidence_for(request, &qualification);
        ProviderCandidateBinding::new(target, qualification, intent, proposal_evidence)
            .expect("candidate binding")
    }

    fn reseal_binding_qualification(binding: &mut ProviderCandidateBinding) {
        binding.qualification.record_digest = digest(&(
            LIVE_PROVIDER_QUALIFICATION_SCHEMA,
            &binding.qualification.qualification_id,
            &binding.qualification.package_digest,
            &binding.qualification.target_digest,
            &binding.qualification.replay_capsule_digest,
            &binding.qualification.configuration_fingerprint,
            &binding.qualification.request_digest,
            binding.qualification.status,
            &binding.qualification.live_turn,
            &binding.qualification.replay,
            &binding.qualification.failure,
        ))
        .expect("reseal qualification record");
        binding.qualification_record_digest = binding.qualification.record_digest.clone();
        binding.binding_digest = binding.expected_digest().expect("reseal binding");
    }

    #[test]
    fn publishes_reopens_and_cross_checks_exact_qualification() {
        let root = TestRoot::new("roundtrip");
        let binding = binding();
        let digest = binding.binding_digest.clone();
        let qualification = binding.qualification.clone();
        {
            let store = ProviderCandidateBindingStore::open(&root.0).expect("open store");
            let published = store.publish(binding.clone()).expect("publish binding");
            assert!(
                published == binding,
                "published provider binding differed from the exact candidate binding"
            );
            let loaded = store
                .load(&digest, Some(&qualification))
                .expect("load exact binding");
            assert!(
                loaded == binding,
                "loaded provider binding differed from the exact candidate binding"
            );
            let validated = store.validate_all().expect("validate store");
            assert!(
                validated == vec![binding.clone()],
                "provider binding store differed from the exact singleton (actual_count={})",
                validated.len()
            );
            assert!(matches!(
                ProviderCandidateBindingStore::open(&root.0),
                Err(ProviderBindingError::Conflict(_))
            ));
        }
        let reopened = ProviderCandidateBindingStore::open(&root.0).expect("reopen store");
        let reopened_binding = reopened.load(&digest, None).expect("load after reopen");
        assert!(
            reopened_binding == binding,
            "reopened provider binding differed from the exact candidate binding"
        );
    }

    #[test]
    fn rejects_extra_or_target_mismatched_intent_material() {
        let target = target();
        let valid_intent = intent_for(&target);
        let (request, qualification) =
            qualification_for(&target, &valid_intent, "qualification-extra");
        let proposal_evidence = proposal_evidence_for(request, &qualification);
        let mut extra = valid_intent;
        extra
            .arguments
            .insert("unapproved".to_string(), "true".to_string());
        assert!(matches!(
            ProviderCandidateBinding::new(target.clone(), qualification, extra, proposal_evidence,),
            Err(ProviderBindingError::InvalidBinding(_))
        ));

        let mut wrong_target = intent_for(&target);
        wrong_target.target_genome_digest = ContentDigest::from_bytes(b"wrong-genome");
        let (request, qualification) =
            qualification_for(&target, &wrong_target, "qualification-wrong-target");
        let proposal_evidence = proposal_evidence_for(request, &qualification);
        assert!(matches!(
            ProviderCandidateBinding::new(target, qualification, wrong_target, proposal_evidence,),
            Err(ProviderBindingError::InvalidBinding(_))
        ));
    }

    #[test]
    fn rejects_cross_linked_provider_proposal_evidence() {
        let target = target();
        let intent = intent_for(&target);
        let (_, qualification) = qualification_for(&target, &intent, "qualification:binding-a");
        let (other_request, other_qualification) =
            qualification_for(&target, &intent, "qualification:binding-b");
        let cross_linked = proposal_evidence_for(other_request, &other_qualification);
        assert!(matches!(
            ProviderCandidateBinding::new(target, qualification, intent, cross_linked,),
            Err(ProviderBindingError::InvalidBinding(_))
        ));
    }

    #[test]
    fn rejects_resealed_provider_accounting_for_a_different_frozen_provider() {
        let mut binding = binding();
        let turn = binding
            .qualification
            .live_turn
            .as_mut()
            .expect("qualified live turn");
        turn.provider_accounting.provider_id = "provider:tampered".to_string();
        *turn = turn
            .clone()
            .seal()
            .expect("internally reseal tampered turn");

        reseal_binding_qualification(&mut binding);

        assert!(matches!(
            binding.validate(),
            Err(ProviderBindingError::InvalidBinding(message))
                if message.contains("cross-linked")
        ));
    }

    #[test]
    fn rejects_resealed_offline_replay_for_a_different_request_or_parser() {
        let mut wrong_request = binding();
        let replay = wrong_request
            .qualification
            .replay
            .as_mut()
            .expect("qualified offline replay");
        replay.request_digest = ContentDigest::from_bytes(b"different-offline-replay-request");
        *replay = replay.clone().seal().expect("reseal wrong replay request");
        reseal_binding_qualification(&mut wrong_request);
        assert!(matches!(
            wrong_request.validate(),
            Err(ProviderBindingError::InvalidBinding(message))
                if message.contains("offline replay")
        ));

        let mut wrong_parser = binding();
        let replay = wrong_parser
            .qualification
            .replay
            .as_mut()
            .expect("qualified offline replay");
        replay.parser_digest = ContentDigest::from_bytes(b"different-offline-parser");
        *replay = replay.clone().seal().expect("reseal wrong replay parser");
        reseal_binding_qualification(&mut wrong_parser);
        assert!(matches!(
            wrong_parser.validate(),
            Err(ProviderBindingError::InvalidBinding(message))
                if message.contains("offline replay")
        ));
    }

    #[test]
    fn validates_exact_migration_plan_and_artifact_edges() {
        let proving = ContentDigest::from_bytes(b"migration-proof");
        let prefix = b"schema-2:".to_vec();
        let forward = StateTransformArtifact::new(
            StateTransformDirection::Forward,
            1,
            2,
            StateTransformProgram::Prepend {
                prefix: prefix.clone(),
            },
            proving.clone(),
        )
        .expect("forward artifact");
        let rollback = StateTransformArtifact::new(
            StateTransformDirection::Rollback,
            2,
            1,
            StateTransformProgram::RemovePrefix { prefix },
            proving,
        )
        .expect("rollback artifact");
        let artifacts =
            StateMigrationArtifactBundle::new(forward, rollback).expect("artifact bundle");
        let plan = StateMigrationPlan::new(
            "migration-1-to-2",
            1,
            2,
            1,
            artifacts.bundle_digest.clone(),
            1_024,
        )
        .expect("migration plan");
        let policy = MutableFactoryPolicy::terminal(1, 4);
        let (incumbent, candidate) = packages(policy.clone(), compatibility(2));
        ProviderCandidateTarget::new(
            "cycle-provider-migration",
            &incumbent,
            &candidate,
            ContentDigest::from_bytes(b"release-gate"),
            component_wat(),
            policy,
            compatibility(2),
            Some(plan),
            Some(artifacts.clone()),
            ContentDigest::from_bytes(b"operator-context"),
        )
        .expect("migration-bound target");

        let mismatched = StateMigrationPlan::new(
            "migration-mismatch",
            1,
            2,
            1,
            ContentDigest::from_bytes(b"different-bundle"),
            1_024,
        )
        .expect("mismatched plan");
        let bad_policy = MutableFactoryPolicy::terminal(1, 4);
        let (bad_incumbent, bad_candidate) = packages(bad_policy.clone(), compatibility(2));
        assert!(matches!(
            ProviderCandidateTarget::new(
                "cycle-provider-migration-bad",
                &bad_incumbent,
                &bad_candidate,
                ContentDigest::from_bytes(b"release-gate"),
                component_wat(),
                bad_policy,
                compatibility(2),
                Some(mismatched),
                Some(artifacts),
                ContentDigest::from_bytes(b"operator-context"),
            ),
            Err(ProviderBindingError::InvalidTarget(_))
        ));
    }

    #[test]
    fn load_and_open_reject_tampered_durable_content() {
        let root = TestRoot::new("tamper");
        let binding = binding();
        let digest = binding.binding_digest.clone();
        let store = ProviderCandidateBindingStore::open(&root.0).expect("open store");
        store.publish(binding).expect("publish binding");
        let path = store.binding_path(&digest);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read binding")).expect("parse binding");
        value["target"]["target_genome_digest"] =
            serde_json::to_value(ContentDigest::from_bytes(b"tampered-genome"))
                .expect("serialize digest");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&value).expect("encode tampered binding"),
        )
        .expect("tamper durable file");
        assert!(store.load(&digest, None).is_err());
        drop(store);
        assert!(ProviderCandidateBindingStore::open(&root.0).is_err());
    }

    #[test]
    fn supplied_qualification_must_be_the_exact_bound_record() {
        let root = TestRoot::new("cross-check");
        let binding = binding();
        let digest = binding.binding_digest.clone();
        let (_, mut other) = qualification_for(
            &binding.target,
            &binding.parsed_intent,
            "qualification-other",
        );
        assert_ne!(other.record_digest, binding.qualification.record_digest);
        let store = ProviderCandidateBindingStore::open(&root.0).expect("open store");
        store.publish(binding).expect("publish binding");
        assert!(matches!(
            store.load(&digest, Some(&other)),
            Err(ProviderBindingError::QualificationMismatch { .. })
        ));

        other.record_digest = ContentDigest::from_bytes(b"tampered-record");
        assert!(matches!(
            store.load(&digest, Some(&other)),
            Err(ProviderBindingError::InvalidQualification(_))
        ));
    }

    #[test]
    fn detached_binding_codec_revalidates_exact_canonical_bytes() {
        let binding = binding();
        let bytes = binding.canonical_bytes().expect("canonical binding");
        let detached =
            ProviderCandidateBinding::from_canonical_bytes(&bytes).expect("detached binding");
        assert!(
            detached == binding,
            "detached provider binding differed from its canonical source"
        );

        let mut noncanonical = bytes.clone();
        noncanonical.push(b'\n');
        assert!(ProviderCandidateBinding::from_canonical_bytes(&noncanonical).is_err());

        let mut tampered: serde_json::Value =
            serde_json::from_slice(&bytes).expect("binding value");
        tampered["qualification"]["record_digest"] =
            serde_json::to_value(ContentDigest::from_bytes(b"forged-qualification"))
                .expect("digest value");
        let tampered = serde_json::to_vec_pretty(&tampered).expect("tampered bytes");
        assert!(ProviderCandidateBinding::from_canonical_bytes(&tampered).is_err());
    }
}
