//! Operational M7 closure evaluation over exact, immutable evidence bytes.
//!
//! Legacy NorthStar 07 and Remediation Phase 04 records remain historical
//! inputs outside this module. This foundation never upgrades their seeded
//! statuses or reference strings into operational proof.
//!
//! Evaluation is deliberately pure: callers supply a finalized bundle and an
//! [`EvidenceResolver`], and the evaluator performs only reads. It does not
//! create evidence, repair records, consult ambient time, call a provider, or
//! mutate runtime state. Any unresolved, malformed, stale, cross-run,
//! causally inconsistent, or semantically failed required input yields
//! [`M7ClosureDecision::NotYet`].
//!
//! Clean-checkout/test capture and independent-review claims are accepted only
//! through detached Ed25519 attestations. Both public identities are frozen in
//! the pre-run manifest, and the reviewer pin is repeated by the durable review
//! request before review evidence is admitted. This module owns verification
//! only and never handles either private key.

use crate::capability_services::{
    CAPABILITY_ATTESTATION_SCHEMA, CapabilityOperation, InvocationOutcome, InvocationProvenance,
    InvocationReceipt, ServiceFailureKind, ServiceInvocationAttestation,
};
use crate::execution::NativeServiceFamily;
use crate::execution::inference::normalize_safe_provider_api_base_url;
pub use crate::execution::{
    ActiveTruthClaimCatalogV1 as M7ClaimCatalogV1, ActiveTruthClaimIdV1 as M7ClaimIdV1,
    ActiveTruthPublicationControlV1 as M7PublicationControlV1,
};
use crate::execution::{
    ContentDigest, NorthStarClosureDecision, PublicationPolicyRecord, digest_json_content,
};
use crate::factory_reproduction::{
    CycleStatus, ExecutionTerminal, FactoryPackage, HealthStatus, LineageDisposition,
    M5ProviderEndpointClassV1, WorkerRole, WorkerTerminalStatus,
};
use crate::local_runtime::{
    GeneralAudienceHomeView, NorthStar07ClosureReviewView, OperatorTruthSurfaceAuthorityView,
    RemediationPhase04FinalClosureRereviewView, SystemOverviewView,
};
use crate::m1_reference::ChallengerWorkspaceLineage;
use crate::m2_runtime::{M1_OPEN_WORKSPACE_JOB_KIND, M1LifecycleJob};
use crate::m5_effect_port::M5EffectAuditKind;
use crate::m5_export::{M5_EXPORT_BUNDLE_SCHEMA, M5ExportBundleV1};
use crate::m5_provider_execution::{M5CompletedProviderInvocationV1, M5ProviderTerminalOutcomeV1};
use crate::m5_runtime::{
    M5_FINAL_POST_ROLLBACK_PROBE_SCHEMA, M5FinalPostRollbackProbeV1, M5M2PostExportJobBindingV2,
    M5M2PostExportRestartCaptureV2, M5PreparedProviderSeedV1,
};
use crate::m6_completion::{M6_COMPLETION_BUNDLE_SCHEMA, M6CompletionBundleV1};
use crate::supervisor::{
    AttemptOutcome, DurableJob, EffectReceiptStatus, JobPhase, JobTerminalOutcome, SupervisorState,
    WakeKind,
};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::path::{Component, Path};

pub const M7_CRITERIA_SCHEMA: &str = "wasm-biotic.m7-frozen-criteria.v3";
pub const M7_PROOF_RUN_MANIFEST_SCHEMA: &str = "wasm-biotic.m7-proof-run-manifest.v5";
pub const M7_FINAL_BUNDLE_SCHEMA: &str = "wasm-biotic.m7-final-bundle.v7";
pub const M7_SOURCE_LINK_SCHEMA: &str = "wasm-biotic.m7-source-link.v4";
pub const M7_CARGO_TEST_TRANSCRIPT_SCHEMA: &str = "wasm-biotic.m7-source.cargo-test-transcript.v2";
pub const M7_SOURCE_CAPTURE_ATTESTATION_SCHEMA: &str =
    "wasm-biotic.m7-source.source-capture-attestation.v4";
pub const M7_TRUTH_BOUNDARY_SOURCE_SCHEMA: &str = "wasm-biotic.m7-source.truth-boundary.v4";
pub const M7_CLAIM_BOUNDARY_SOURCE_SCHEMA: &str = "wasm-biotic.m7-source.claim-boundary.v4";
pub const M7_PUBLICATION_POLICY_SOURCE_SCHEMA: &str = "wasm-biotic.m7-source.publication-policy.v4";
pub const M7_ACTIVE_SURFACE_SNAPSHOT_SCHEMA: &str = "wasm-biotic.m7-active-surface-snapshot.v2";
pub const M7_ACTIVE_SURFACE_CAPTURE_SCHEMA: &str = "wasm-biotic.m7-active-surface-capture.v2";
pub const M7_ACTIVE_SURFACE_OBSERVATION_SCHEMA: &str =
    "wasm-biotic.m7-active-surface-observation.v1";
pub const M7_ACTIVE_SURFACE_CAPTURE_POLICY_SCHEMA: &str =
    "wasm-biotic.m7-active-surface-capture-policy.v1";
pub const M7_ACTIVE_TRUTH_SCHEMA: &str = "wasm-biotic.active-truth.v1";
pub const M7_CLAIM_CATALOG_SCHEMA: &str = crate::execution::ACTIVE_TRUTH_CLAIM_CATALOG_SCHEMA;
pub const M7_CLAIM_CATALOG_VERSION: &str = crate::execution::ACTIVE_TRUTH_CLAIM_CATALOG_VERSION;
pub const M7_ACTIVE_SURFACE_SECRET_SCAN_SCHEMA: &str =
    "wasm-biotic.m7-active-surface-secret-scan.v2";
pub const M7_ACTIVE_SURFACE_SECRET_RULE_SET_SCHEMA: &str =
    "wasm-biotic.m7-active-surface-secret-rules.v2";
pub const M7_ACTIVE_TRUTH_BLOCK_BEGIN: &str = "<!-- wasm-biotic.active-truth.v1:begin -->";
pub const M7_ACTIVE_TRUTH_BLOCK_END: &str = "<!-- wasm-biotic.active-truth.v1:end -->";
pub const M7_INDEPENDENT_REVIEW_SOURCE_SCHEMA: &str =
    "wasm-biotic.m7-source.independent-review-attestation.v4";
pub const M7_LIVE_PROVIDER_SOURCE_SCHEMA: &str =
    "wasm-biotic.m7-source.live-provider-qualification.v4";
pub const M7_SUPERVISOR_STATE_SOURCE_SCHEMA: &str = "wasm-biotic.supervisor-state.v2";

const CRITERIA_DOMAIN: &str = "wasm-biotic:m7-frozen-criteria:v3";
const MANIFEST_DOMAIN: &str = "wasm-biotic:m7-proof-run-manifest:v5";
const LIVE_PROVIDER_SCOPE_DOMAIN: &str = "wasm-biotic:m7-live-provider-scope:v3";
const LIVE_PROVIDER_SOURCE_DOMAIN: &str = "wasm-biotic:m7-live-provider-source:v4";
const EVIDENCE_SET_DOMAIN: &str = "wasm-biotic:m7-reviewed-evidence-set:v4";
const FINAL_BUNDLE_DOMAIN: &str = "wasm-biotic:m7-final-bundle:v7";
const SOURCE_RECORD_DOMAIN: &str = "wasm-biotic:m7-source-record:v2";
const CAUSAL_SUBJECT_FROM_SOURCES_DOMAIN: &str = "wasm-biotic:m7-causal-subject-from-sources:v2";
const EXTERNAL_IDENTITY_DOMAIN: &str = "wasm-biotic:m7-external-ed25519-identity:v1";
const SOURCE_CAPTURE_ATTESTATION_DOMAIN: &str = "wasm-biotic:m7-source-capture-attestation:v4";
const SOURCE_CAPTURE_INVENTORY_DOMAIN: &str = "wasm-biotic:m7-source-capture-inventory:v4";
const SOURCE_CAPTURE_SIGNATURE_DOMAIN: &[u8] = b"wasm-biotic:m7-source-capture-signature:v4\0";
const REVIEWER_ATTESTATION_DOMAIN: &str = "wasm-biotic:m7-reviewer-attestation:v2";
const REVIEWER_ATTESTATION_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m7-reviewer-attestation-signature:v2\0";
const ACTIVE_SURFACE_CAPTURE_DOMAIN: &str = "wasm-biotic:m7-active-surface-capture:v2";
const ACTIVE_SURFACE_SNAPSHOT_DOMAIN: &str = "wasm-biotic:m7-active-surface-snapshot:v2";
const ACTIVE_SURFACE_OBSERVATION_DOMAIN: &str = "wasm-biotic:m7-active-surface-observation:v1";
const ACTIVE_SURFACE_CAPTURE_POLICY_DOMAIN: &str =
    "wasm-biotic:m7-active-surface-capture-policy:v1";
const OBSERVED_SERVICE_SURFACE_DOMAIN: &str = "wasm-biotic:m7-observed-service-surfaces:v1";
const PUBLICATION_CONTROLS_DOMAIN: &str = "wasm-biotic:m7-publication-controls:v1";
const ACTIVE_SURFACE_SECRET_RULE_SET_DOMAIN: &str = "wasm-biotic:m7-active-surface-secret-rules:v2";
const ACTIVE_SURFACE_SECRET_SCAN_DOMAIN: &str = "wasm-biotic:m7-active-surface-secret-scan:v2";

pub const M7_ACTIVE_SURFACE_CONNECT_TIMEOUT_MS: u64 = 2_000;
pub const M7_ACTIVE_SURFACE_REQUEST_TIMEOUT_MS: u64 = 10_000;
pub const M7_ACTIVE_SURFACE_READ_TIMEOUT_MS: u64 = 5_000;

const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_CRITERIA: usize = 128;
const MAX_CRITERION_STATEMENT_BYTES: usize = 64 * 1_024;
const MAX_EVIDENCE_LINKS: usize = 128;
const MAX_EVIDENCE_BYTES: usize = 32 * 1_048_576;
const MAX_SOURCE_BYTES: usize = 256 * 1_048_576;
const MAX_SOURCE_LINKS: usize = 128;
pub(crate) const M7_MAX_TRANSCRIPT_CONTENT_BYTES: usize = 32 * 1_048_576;
const MAX_ACTIVE_SURFACE_BYTES: usize = 16 * 1_048_576;
const MAX_ACTIVE_SURFACE_SNAPSHOT_BYTES: usize = 64 * 1_048_576;
// The completed invocation is itself bounded at 8 MiB, but this source stores
// those canonical JSON bytes as a JSON string. In the worst case every quote
// or backslash is escaped again, so allow the full 2x expansion plus envelope.
const MAX_LIVE_PROVIDER_SOURCE_BYTES: usize = 32 * 1_048_576;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const M7_DETERMINISTIC_CARGO_TEST_COMMAND: [&str; 4] =
    ["cargo", "test", "--locked", "--all-targets"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7ClosureDecision {
    Closed,
    ClosedWithCaveats,
    NotYet,
}

/// Stable, machine-readable qualifications on an otherwise valid evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7EvaluationCaveatV1 {
    /// The frozen active public/operator surfaces still truthfully publish the
    /// pre-run `not_yet` decision and require a separate post-proof update.
    PublicationPendingActiveSurfacesNotYet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7Milestone {
    M0,
    M1,
    M2,
    M3,
    M4,
    M5,
    M6,
    M7,
    Supplemental,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7EvidenceFamily {
    M0TruthBaseline,
    M1CandidateLifecycle,
    M2SchedulerWakeRestart,
    M3CapabilityEffects,
    M4WorkerEcology,
    M5ActivationRollback,
    M6FactoryExchange,
    DeterministicValidation,
    ClaimBoundary,
    PublicationPolicy,
    IndependentReview,
    LiveProviderQualification,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7EvidenceKind {
    M0TruthBaseline,
    M1CandidateLifecycle,
    M2SchedulerWakeRestart,
    M3CapabilityEffects,
    M4WorkerEcology,
    M5ActivationRollback,
    M6FactoryExchange,
    DeterministicTestTranscript,
    ClaimBoundary,
    PublicationPolicy,
    IndependentReviewerRecommendation,
    LiveProviderQualification,
}

impl M7EvidenceKind {
    pub fn family(self) -> M7EvidenceFamily {
        match self {
            Self::M0TruthBaseline => M7EvidenceFamily::M0TruthBaseline,
            Self::M1CandidateLifecycle => M7EvidenceFamily::M1CandidateLifecycle,
            Self::M2SchedulerWakeRestart => M7EvidenceFamily::M2SchedulerWakeRestart,
            Self::M3CapabilityEffects => M7EvidenceFamily::M3CapabilityEffects,
            Self::M4WorkerEcology => M7EvidenceFamily::M4WorkerEcology,
            Self::M5ActivationRollback => M7EvidenceFamily::M5ActivationRollback,
            Self::M6FactoryExchange => M7EvidenceFamily::M6FactoryExchange,
            Self::DeterministicTestTranscript => M7EvidenceFamily::DeterministicValidation,
            Self::ClaimBoundary => M7EvidenceFamily::ClaimBoundary,
            Self::PublicationPolicy => M7EvidenceFamily::PublicationPolicy,
            Self::IndependentReviewerRecommendation => M7EvidenceFamily::IndependentReview,
            Self::LiveProviderQualification => M7EvidenceFamily::LiveProviderQualification,
        }
    }

    pub fn owner_milestone(self) -> M7Milestone {
        match self {
            Self::M0TruthBaseline => M7Milestone::M0,
            Self::M1CandidateLifecycle => M7Milestone::M1,
            Self::M2SchedulerWakeRestart => M7Milestone::M2,
            Self::M3CapabilityEffects => M7Milestone::M3,
            Self::M4WorkerEcology => M7Milestone::M4,
            Self::M5ActivationRollback => M7Milestone::M5,
            Self::M6FactoryExchange => M7Milestone::M6,
            Self::DeterministicTestTranscript
            | Self::ClaimBoundary
            | Self::PublicationPolicy
            | Self::IndependentReviewerRecommendation => M7Milestone::M7,
            Self::LiveProviderQualification => M7Milestone::Supplemental,
        }
    }

    pub fn schema(self) -> &'static str {
        match self {
            Self::M0TruthBaseline => "wasm-biotic.m7-evidence.m0-truth.v5",
            Self::M1CandidateLifecycle => "wasm-biotic.m7-evidence.m1-candidate-lifecycle.v4",
            Self::M2SchedulerWakeRestart => "wasm-biotic.m7-evidence.m2-scheduler-wake-restart.v5",
            Self::M3CapabilityEffects => "wasm-biotic.m7-evidence.m3-capability-effects.v4",
            Self::M4WorkerEcology => "wasm-biotic.m7-evidence.m4-worker-ecology.v5",
            Self::M5ActivationRollback => "wasm-biotic.m7-evidence.m5-activation-rollback.v5",
            Self::M6FactoryExchange => "wasm-biotic.m7-evidence.m6-factory-exchange.v6",
            Self::DeterministicTestTranscript => "wasm-biotic.m7-evidence.test-transcript.v4",
            Self::ClaimBoundary => "wasm-biotic.m7-evidence.claim-boundary.v5",
            Self::PublicationPolicy => "wasm-biotic.m7-evidence.publication-policy.v5",
            Self::IndependentReviewerRecommendation => {
                "wasm-biotic.m7-evidence.independent-review.v4"
            }
            Self::LiveProviderQualification => {
                "wasm-biotic.m7-evidence.live-provider-qualification.v8"
            }
        }
    }

    pub fn expected_causal_kind(self) -> M7CausalSubjectKind {
        match self {
            Self::M0TruthBaseline => M7CausalSubjectKind::ProofRun,
            Self::M1CandidateLifecycle => M7CausalSubjectKind::Candidate,
            Self::M2SchedulerWakeRestart => M7CausalSubjectKind::SchedulerRun,
            Self::M3CapabilityEffects => M7CausalSubjectKind::CapabilityRun,
            Self::M4WorkerEcology => M7CausalSubjectKind::WorkerWorkflow,
            Self::M5ActivationRollback => M7CausalSubjectKind::FactoryCycle,
            Self::M6FactoryExchange => M7CausalSubjectKind::ExchangeRoute,
            Self::DeterministicTestTranscript => M7CausalSubjectKind::TestRun,
            Self::ClaimBoundary
            | Self::PublicationPolicy
            | Self::IndependentReviewerRecommendation => M7CausalSubjectKind::ClosureReview,
            Self::LiveProviderQualification => M7CausalSubjectKind::ProviderQualification,
        }
    }
}

pub fn mandatory_evidence_kinds() -> BTreeSet<M7EvidenceKind> {
    BTreeSet::from([
        M7EvidenceKind::M0TruthBaseline,
        M7EvidenceKind::M1CandidateLifecycle,
        M7EvidenceKind::M2SchedulerWakeRestart,
        M7EvidenceKind::M3CapabilityEffects,
        M7EvidenceKind::M4WorkerEcology,
        M7EvidenceKind::M5ActivationRollback,
        M7EvidenceKind::M6FactoryExchange,
        M7EvidenceKind::DeterministicTestTranscript,
        M7EvidenceKind::ClaimBoundary,
        M7EvidenceKind::PublicationPolicy,
        M7EvidenceKind::IndependentReviewerRecommendation,
    ])
}

fn primary_milestone_families() -> BTreeSet<M7EvidenceFamily> {
    BTreeSet::from([
        M7EvidenceFamily::M0TruthBaseline,
        M7EvidenceFamily::M1CandidateLifecycle,
        M7EvidenceFamily::M2SchedulerWakeRestart,
        M7EvidenceFamily::M3CapabilityEffects,
        M7EvidenceFamily::M4WorkerEcology,
        M7EvidenceFamily::M5ActivationRollback,
        M7EvidenceFamily::M6FactoryExchange,
    ])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7Criterion {
    pub criterion_id: String,
    pub statement: String,
    pub statement_digest: ContentDigest,
    pub required_families: BTreeSet<M7EvidenceFamily>,
}

impl M7Criterion {
    fn validate(&self) -> Result<(), M7FoundationError> {
        validate_identifier("criterion_id", &self.criterion_id)?;
        if self.statement.trim().is_empty()
            || self.statement.len() > MAX_CRITERION_STATEMENT_BYTES
            || self.statement.chars().any(char::is_control)
        {
            return Err(M7FoundationError::InvalidCriteria(format!(
                "criterion statement must contain 1..={MAX_CRITERION_STATEMENT_BYTES} UTF-8 bytes and no control characters"
            )));
        }
        if self.statement_digest != ContentDigest::from_bytes(self.statement.as_bytes()) {
            return Err(M7FoundationError::InvalidCriteria(
                "criterion statement digest does not bind its exact UTF-8 bytes".to_string(),
            ));
        }
        if self.required_families.is_empty()
            || self
                .required_families
                .contains(&M7EvidenceFamily::LiveProviderQualification)
        {
            return Err(M7FoundationError::InvalidCriteria(
                "a frozen criterion must require operational evidence and cannot make the separate provider qualification release-authoritative"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenClosureCriteria {
    schema: String,
    criteria_id: String,
    criteria_version: String,
    frozen_at_ms: u64,
    criteria: Vec<M7Criterion>,
    required_evidence_kinds: BTreeSet<M7EvidenceKind>,
    criteria_digest: ContentDigest,
}

#[derive(Serialize)]
struct CriteriaDigestMaterial<'a> {
    domain: &'static str,
    criteria_id: &'a str,
    criteria_version: &'a str,
    frozen_at_ms: u64,
    criteria: &'a [M7Criterion],
    required_evidence_kinds: &'a BTreeSet<M7EvidenceKind>,
}

impl FrozenClosureCriteria {
    pub fn new(
        criteria_id: impl Into<String>,
        criteria_version: impl Into<String>,
        frozen_at_ms: u64,
        criteria: Vec<M7Criterion>,
    ) -> Result<Self, M7FoundationError> {
        let mut frozen = Self {
            schema: M7_CRITERIA_SCHEMA.to_string(),
            criteria_id: criteria_id.into(),
            criteria_version: criteria_version.into(),
            frozen_at_ms,
            criteria,
            required_evidence_kinds: mandatory_evidence_kinds(),
            criteria_digest: ContentDigest::from_bytes(&[]),
        };
        frozen.validate_fields()?;
        frozen.criteria_digest = frozen.expected_digest()?;
        Ok(frozen)
    }

    pub fn criteria_id(&self) -> &str {
        &self.criteria_id
    }

    pub fn criteria_version(&self) -> &str {
        &self.criteria_version
    }

    pub fn frozen_at_ms(&self) -> u64 {
        self.frozen_at_ms
    }

    pub fn criteria(&self) -> &[M7Criterion] {
        &self.criteria
    }

    pub fn required_evidence_kinds(&self) -> &BTreeSet<M7EvidenceKind> {
        &self.required_evidence_kinds
    }

    pub fn criteria_digest(&self) -> &ContentDigest {
        &self.criteria_digest
    }

    fn validate(&self) -> Result<(), M7FoundationError> {
        self.validate_fields()?;
        require_digest(
            "frozen closure criteria",
            &self.criteria_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M7FoundationError> {
        if self.schema != M7_CRITERIA_SCHEMA {
            return Err(M7FoundationError::InvalidCriteria(
                "unsupported frozen-criteria schema".to_string(),
            ));
        }
        validate_identifier("criteria_id", &self.criteria_id)?;
        validate_identifier("criteria_version", &self.criteria_version)?;
        if self.frozen_at_ms == 0 || self.criteria.is_empty() || self.criteria.len() > MAX_CRITERIA
        {
            return Err(M7FoundationError::InvalidCriteria(format!(
                "criteria must contain 1..={MAX_CRITERIA} entries and a nonzero freeze time"
            )));
        }
        let mut ids = BTreeSet::new();
        let mut covered_families = BTreeSet::new();
        for criterion in &self.criteria {
            criterion.validate()?;
            if !ids.insert(criterion.criterion_id.clone()) {
                return Err(M7FoundationError::InvalidCriteria(
                    "criterion identifiers must be unique".to_string(),
                ));
            }
            covered_families.extend(criterion.required_families.iter().copied());
        }
        if !primary_milestone_families().is_subset(&covered_families) {
            return Err(M7FoundationError::InvalidCriteria(
                "frozen criteria do not cover every M0-M6 evidence family".to_string(),
            ));
        }
        if self.required_evidence_kinds != mandatory_evidence_kinds() {
            return Err(M7FoundationError::InvalidCriteria(
                "required evidence kinds differ from the M7 operational minimum".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&CriteriaDigestMaterial {
            domain: CRITERIA_DOMAIN,
            criteria_id: &self.criteria_id,
            criteria_version: &self.criteria_version,
            frozen_at_ms: self.frozen_at_ms,
            criteria: &self.criteria,
            required_evidence_kinds: &self.required_evidence_kinds,
        })
    }
}

/// Public identity of an external attestor. The runtime stores and verifies
/// this pin; it never accepts or persists the corresponding private key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ExternalEd25519IdentityV1 {
    principal_id: String,
    public_key_hex: String,
    public_key_digest: ContentDigest,
    identity_digest: ContentDigest,
}

impl M7ExternalEd25519IdentityV1 {
    pub fn new(
        principal_id: impl Into<String>,
        public_key: &[u8],
    ) -> Result<Self, M7FoundationError> {
        if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(M7FoundationError::InvalidManifest(
                "external Ed25519 public key must contain exactly 32 bytes".to_string(),
            ));
        }
        let mut identity = Self {
            principal_id: principal_id.into(),
            public_key_hex: hex_encode(public_key),
            public_key_digest: ContentDigest::from_bytes(public_key),
            identity_digest: ContentDigest::from_bytes(&[]),
        };
        identity.validate_fields()?;
        identity.identity_digest = identity.expected_digest()?;
        Ok(identity)
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub fn public_key_digest(&self) -> &ContentDigest {
        &self.public_key_digest
    }

    pub fn identity_digest(&self) -> &ContentDigest {
        &self.identity_digest
    }

    fn public_key_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        let bytes = hex_decode(&self.public_key_hex).map_err(M7FoundationError::InvalidSource)?;
        if bytes.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(M7FoundationError::InvalidSource(
                "external Ed25519 public key has the wrong length".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), M7FoundationError> {
        self.validate_fields()?;
        let public_key = self.public_key_bytes()?;
        if self.public_key_digest != ContentDigest::from_bytes(&public_key)
            || self.identity_digest != self.expected_digest()?
        {
            return Err(M7FoundationError::InvalidSource(
                "external Ed25519 identity digest differs from its pinned public key".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), M7FoundationError> {
        validate_identifier("external attestor principal_id", &self.principal_id)
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            EXTERNAL_IDENTITY_DOMAIN,
            &self.principal_id,
            &self.public_key_hex,
            &self.public_key_digest,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7SourceRootProvenanceV1 {
    FreshCleanCheckout,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7SourceIdentity {
    pub commit_oid: String,
    pub commit_object_digest: ContentDigest,
    pub tree_oid: String,
    pub tree_digest: ContentDigest,
    pub checkout_root_digest: ContentDigest,
    pub toolchain_digest: ContentDigest,
    pub lockfile_digest: ContentDigest,
    pub root_provenance: M7SourceRootProvenanceV1,
}

impl M7SourceIdentity {
    fn validate(&self) -> Result<(), M7FoundationError> {
        validate_identifier("commit_oid", &self.commit_oid)?;
        validate_identifier("tree_oid", &self.tree_oid)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7LiveProviderSourceV1 {
    schema: String,
    completed_invocation_json: String,
    source_digest: ContentDigest,
}

impl M7LiveProviderSourceV1 {
    /// Wrap the sole opaque output of M5's manifest-bound provider invocation.
    /// The exact completed-invocation bytes remain embedded unchanged so M7
    /// never reassembles authority from separable prepared/binding/receipt
    /// records.
    pub fn from_completed_invocation(
        completed_invocation: M5CompletedProviderInvocationV1,
    ) -> Result<Self, M7FoundationError> {
        let completed_invocation_json =
            String::from_utf8(completed_invocation.canonical_bytes().map_err(|error| {
                M7FoundationError::InvalidSource(format!(
                    "completed provider invocation is invalid: {error}"
                ))
            })?)
            .map_err(|_| {
                M7FoundationError::InvalidSource(
                    "completed provider invocation is not canonical UTF-8 JSON".to_string(),
                )
            })?;
        let mut source = Self {
            schema: M7_LIVE_PROVIDER_SOURCE_SCHEMA.to_string(),
            completed_invocation_json,
            source_digest: ContentDigest::from_bytes(&[]),
        };
        source.completed_invocation()?;
        source.source_digest = source.expected_digest()?;
        source.validate()?;
        Ok(source)
    }

    pub fn completed_invocation(
        &self,
    ) -> Result<M5CompletedProviderInvocationV1, M7FoundationError> {
        M5CompletedProviderInvocationV1::from_canonical_bytes(
            self.completed_invocation_json.as_bytes(),
        )
        .map_err(|error| {
            M7FoundationError::InvalidSource(format!(
                "completed provider invocation is invalid: {error}"
            ))
        })
    }

    pub fn source_digest(&self) -> &ContentDigest {
        &self.source_digest
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        enforce_live_provider_source_bound(bytes.len())?;
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M7FoundationError> {
        enforce_live_provider_source_bound(bytes.len())?;
        if bytes.is_empty() {
            return Err(M7FoundationError::InvalidSource(
                "live-provider source bytes are empty".to_string(),
            ));
        }
        let source: Self = serde_json::from_slice(bytes)
            .map_err(|error| M7FoundationError::Serialization(error.to_string()))?;
        source.validate()?;
        if canonical_json(&source)? != bytes {
            return Err(M7FoundationError::InvalidSource(
                "live-provider source is not canonical JSON".to_string(),
            ));
        }
        Ok(source)
    }

    pub fn validate(&self) -> Result<(), M7FoundationError> {
        if self.schema != M7_LIVE_PROVIDER_SOURCE_SCHEMA {
            return Err(M7FoundationError::InvalidSource(
                "unsupported M7 live-provider source schema".to_string(),
            ));
        }
        self.completed_invocation()?;
        require_digest(
            "M7 live-provider source",
            &self.source_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        let completed = self.completed_invocation()?;
        digest(&(
            LIVE_PROVIDER_SOURCE_DOMAIN,
            ContentDigest::from_bytes(self.completed_invocation_json.as_bytes()),
            completed.completed_invocation_digest(),
        ))
    }
}

fn enforce_live_provider_source_bound(length: usize) -> Result<(), M7FoundationError> {
    if length > MAX_LIVE_PROVIDER_SOURCE_BYTES {
        return Err(M7FoundationError::InvalidSource(format!(
            "live-provider source exceeds {MAX_LIVE_PROVIDER_SOURCE_BYTES} bytes"
        )));
    }
    Ok(())
}

fn is_external_https_provider_endpoint(
    api_base_url: &str,
    endpoint_class: M5ProviderEndpointClassV1,
) -> bool {
    endpoint_class == M5ProviderEndpointClassV1::ExternalHttps
        && matches!(
            normalize_safe_provider_api_base_url(api_base_url),
            Ok((normalized, false)) if normalized == api_base_url
        )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderQualificationScope {
    proof_run_id: String,
    prepared_at_ms: u64,
    provider_id: String,
    model_id: String,
    api_base_url: String,
    endpoint_class: M5ProviderEndpointClassV1,
    qualification_run_id: String,
    precommit_digest: ContentDigest,
    request_digest: ContentDigest,
    target_digest: ContentDigest,
    driver_profile_digest: ContentDigest,
    configuration_fingerprint: ContentDigest,
    response_schema_digest: ContentDigest,
    prompt_renderer_digest: ContentDigest,
    tool_catalog_digest: ContentDigest,
    target_package_digest: ContentDigest,
    scope_digest: ContentDigest,
}

impl LiveProviderQualificationScope {
    pub fn from_prepared(prepared: &M5PreparedProviderSeedV1) -> Result<Self, M7FoundationError> {
        prepared.validate().map_err(|error| {
            M7FoundationError::InvalidSource(format!("prepared provider seed is invalid: {error}"))
        })?;
        let configuration = &prepared.qualification_request.configuration;
        let mut scope = Self {
            proof_run_id: prepared.precommit.proof_run_id.clone(),
            prepared_at_ms: prepared.precommit.prepared_at_ms,
            provider_id: configuration.provider_id.clone(),
            model_id: configuration.model_id.clone(),
            api_base_url: configuration.api_base_url.clone(),
            endpoint_class: configuration.endpoint_class,
            qualification_run_id: prepared.qualification_request.qualification_id.clone(),
            precommit_digest: prepared.precommit.precommit_digest.clone(),
            request_digest: prepared.qualification_request.request_digest.clone(),
            target_digest: prepared.target.target_digest.clone(),
            driver_profile_digest: configuration.driver_profile_digest.clone(),
            configuration_fingerprint: configuration.fingerprint().map_err(|error| {
                M7FoundationError::InvalidSource(format!(
                    "prepared provider configuration cannot be fingerprinted: {error}"
                ))
            })?,
            response_schema_digest: configuration.response_schema_digest.clone(),
            prompt_renderer_digest: configuration.prompt_renderer_digest.clone(),
            tool_catalog_digest: configuration.tool_catalog_digest.clone(),
            target_package_digest: prepared.target.candidate_package_digest.clone(),
            scope_digest: ContentDigest::from_bytes(&[]),
        };
        scope.validate_fields()?;
        scope.scope_digest = scope.expected_digest()?;
        Ok(scope)
    }

    pub fn proof_run_id(&self) -> &str {
        &self.proof_run_id
    }

    pub fn prepared_at_ms(&self) -> u64 {
        self.prepared_at_ms
    }

    pub fn scope_digest(&self) -> &ContentDigest {
        &self.scope_digest
    }

    pub fn api_base_url(&self) -> &str {
        &self.api_base_url
    }

    pub fn endpoint_class(&self) -> M5ProviderEndpointClassV1 {
        self.endpoint_class
    }

    pub fn validate_post_call_source(
        &self,
        source: &M7LiveProviderSourceV1,
    ) -> Result<(), M7FoundationError> {
        self.validate()?;
        source.validate()?;
        let completed = source.completed_invocation()?;
        let observed = Self::from_prepared(completed.prepared_seed())?;
        if &observed != self {
            return Err(M7FoundationError::InvalidSource(
                "live-provider source differs from the exact frozen pre-call qualification scope"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), M7FoundationError> {
        self.validate_fields()?;
        require_digest(
            "live-provider qualification scope",
            &self.scope_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M7FoundationError> {
        validate_identifier("live-provider proof_run_id", &self.proof_run_id)?;
        if self.prepared_at_ms == 0 {
            return Err(M7FoundationError::InvalidSource(
                "live-provider precommit time must be nonzero".to_string(),
            ));
        }
        validate_identifier("provider_id", &self.provider_id)?;
        validate_identifier("model_id", &self.model_id)?;
        validate_identifier("qualification_run_id", &self.qualification_run_id)?;
        let (normalized_api_base_url, loopback) =
            normalize_safe_provider_api_base_url(&self.api_base_url).map_err(|error| {
                M7FoundationError::InvalidSource(format!(
                    "live-provider API base URL is invalid: {error}"
                ))
            })?;
        let expected_endpoint_class = if loopback {
            M5ProviderEndpointClassV1::LoopbackTest
        } else {
            M5ProviderEndpointClassV1::ExternalHttps
        };
        if normalized_api_base_url != self.api_base_url
            || self.endpoint_class != expected_endpoint_class
        {
            return Err(M7FoundationError::InvalidSource(
                "live-provider API base URL and endpoint class are not the exact normalized safe endpoint"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            LIVE_PROVIDER_SCOPE_DOMAIN,
            &self.proof_run_id,
            self.prepared_at_ms,
            &self.provider_id,
            &self.model_id,
            (&self.api_base_url, self.endpoint_class),
            &self.qualification_run_id,
            &self.precommit_digest,
            &self.request_digest,
            &self.target_digest,
            &self.driver_profile_digest,
            &self.configuration_fingerprint,
            &self.response_schema_digest,
            &self.prompt_renderer_digest,
            &self.tool_catalog_digest,
            &self.target_package_digest,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ProofRunManifest {
    schema: String,
    proof_run_id: String,
    run_started_at_ms: u64,
    frozen_criteria: FrozenClosureCriteria,
    source_identity: M7SourceIdentity,
    source_capture_identity: M7ExternalEd25519IdentityV1,
    reviewer_identity: M7ExternalEd25519IdentityV1,
    causal_chain_digest: ContentDigest,
    implementation_principal_ids: BTreeSet<String>,
    implementation_identity_digests: BTreeSet<ContentDigest>,
    live_provider_scope: Option<LiveProviderQualificationScope>,
    manifest_digest: ContentDigest,
}

#[derive(Serialize)]
struct ManifestDigestMaterial<'a> {
    domain: &'static str,
    proof_run_id: &'a str,
    run_started_at_ms: u64,
    frozen_criteria: &'a FrozenClosureCriteria,
    source_identity: &'a M7SourceIdentity,
    source_capture_identity: &'a M7ExternalEd25519IdentityV1,
    reviewer_identity: &'a M7ExternalEd25519IdentityV1,
    causal_chain_digest: &'a ContentDigest,
    implementation_principal_ids: &'a BTreeSet<String>,
    implementation_identity_digests: &'a BTreeSet<ContentDigest>,
    live_provider_scope: &'a Option<LiveProviderQualificationScope>,
}

impl M7ProofRunManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proof_run_id: impl Into<String>,
        run_started_at_ms: u64,
        frozen_criteria: FrozenClosureCriteria,
        source_identity: M7SourceIdentity,
        source_capture_identity: M7ExternalEd25519IdentityV1,
        reviewer_identity: M7ExternalEd25519IdentityV1,
        causal_chain_digest: ContentDigest,
        implementation_principal_ids: BTreeSet<String>,
        implementation_identity_digests: BTreeSet<ContentDigest>,
        live_provider_scope: Option<LiveProviderQualificationScope>,
    ) -> Result<Self, M7FoundationError> {
        let mut manifest = Self {
            schema: M7_PROOF_RUN_MANIFEST_SCHEMA.to_string(),
            proof_run_id: proof_run_id.into(),
            run_started_at_ms,
            frozen_criteria,
            source_identity,
            source_capture_identity,
            reviewer_identity,
            causal_chain_digest,
            implementation_principal_ids,
            implementation_identity_digests,
            live_provider_scope,
            manifest_digest: ContentDigest::from_bytes(&[]),
        };
        manifest.validate_fields()?;
        manifest.manifest_digest = manifest.expected_digest()?;
        Ok(manifest)
    }

    pub fn proof_run_id(&self) -> &str {
        &self.proof_run_id
    }

    pub fn frozen_criteria(&self) -> &FrozenClosureCriteria {
        &self.frozen_criteria
    }

    pub fn source_identity(&self) -> &M7SourceIdentity {
        &self.source_identity
    }

    pub fn source_capture_identity(&self) -> &M7ExternalEd25519IdentityV1 {
        &self.source_capture_identity
    }

    pub fn reviewer_identity(&self) -> &M7ExternalEd25519IdentityV1 {
        &self.reviewer_identity
    }

    pub fn run_started_at_ms(&self) -> u64 {
        self.run_started_at_ms
    }

    pub fn causal_chain_digest(&self) -> &ContentDigest {
        &self.causal_chain_digest
    }

    pub fn live_provider_scope(&self) -> Option<&LiveProviderQualificationScope> {
        self.live_provider_scope.as_ref()
    }

    pub fn manifest_digest(&self) -> &ContentDigest {
        &self.manifest_digest
    }

    pub fn implementation_principal_ids(&self) -> &BTreeSet<String> {
        &self.implementation_principal_ids
    }

    pub fn implementation_identity_digests(&self) -> &BTreeSet<ContentDigest> {
        &self.implementation_identity_digests
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M7FoundationError> {
        if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(M7FoundationError::InvalidManifest(format!(
                "M7 proof-run manifest byte length must be in 1..={MAX_EVIDENCE_BYTES}"
            )));
        }
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| M7FoundationError::Serialization(error.to_string()))?;
        manifest.validate()?;
        if canonical_json(&manifest)? != bytes {
            return Err(M7FoundationError::InvalidManifest(
                "M7 proof-run manifest bytes are not canonical".to_string(),
            ));
        }
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), M7FoundationError> {
        self.validate_fields()?;
        require_digest(
            "M7 proof-run manifest",
            &self.manifest_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M7FoundationError> {
        if self.schema != M7_PROOF_RUN_MANIFEST_SCHEMA {
            return Err(M7FoundationError::InvalidManifest(
                "unsupported M7 proof-run manifest schema".to_string(),
            ));
        }
        validate_identifier("proof_run_id", &self.proof_run_id)?;
        self.frozen_criteria.validate()?;
        self.source_identity.validate()?;
        self.source_capture_identity.validate()?;
        self.reviewer_identity.validate()?;
        if self.run_started_at_ms <= self.frozen_criteria.frozen_at_ms {
            return Err(M7FoundationError::InvalidManifest(
                "closure criteria were not frozen before the proof run".to_string(),
            ));
        }
        if self.implementation_principal_ids.is_empty()
            || self.implementation_identity_digests.is_empty()
        {
            return Err(M7FoundationError::InvalidManifest(
                "proof run must identify its implementation principals".to_string(),
            ));
        }
        for principal in &self.implementation_principal_ids {
            validate_identifier("implementation_principal_id", principal)?;
        }
        if identity_reuses_implementation_path(
            &self.source_capture_identity,
            &self.implementation_principal_ids,
            &self.implementation_identity_digests,
        ) {
            return Err(M7FoundationError::InvalidManifest(
                "source-capture identity reuses an implementation-path identity".to_string(),
            ));
        }
        if identity_reuses_implementation_path(
            &self.reviewer_identity,
            &self.implementation_principal_ids,
            &self.implementation_identity_digests,
        ) {
            return Err(M7FoundationError::InvalidManifest(
                "reviewer identity reuses an implementation-path identity".to_string(),
            ));
        }
        if external_identities_reuse_key(&self.source_capture_identity, &self.reviewer_identity) {
            return Err(M7FoundationError::InvalidManifest(
                "source-capture and reviewer identities must be distinct external keys".to_string(),
            ));
        }
        if let Some(scope) = &self.live_provider_scope {
            scope.validate()?;
            if scope.proof_run_id != self.proof_run_id {
                return Err(M7FoundationError::InvalidManifest(
                    "live-provider precommit belongs to a different proof run".to_string(),
                ));
            }
            if scope.prepared_at_ms <= self.frozen_criteria.frozen_at_ms {
                return Err(M7FoundationError::InvalidManifest(
                    "live-provider precommit must be created after closure criteria are frozen"
                        .to_string(),
                ));
            }
            if scope.prepared_at_ms >= self.run_started_at_ms {
                return Err(M7FoundationError::InvalidManifest(
                    "live-provider precommit must be created strictly before the proof run starts"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&ManifestDigestMaterial {
            domain: MANIFEST_DOMAIN,
            proof_run_id: &self.proof_run_id,
            run_started_at_ms: self.run_started_at_ms,
            frozen_criteria: &self.frozen_criteria,
            source_identity: &self.source_identity,
            source_capture_identity: &self.source_capture_identity,
            reviewer_identity: &self.reviewer_identity,
            causal_chain_digest: &self.causal_chain_digest,
            implementation_principal_ids: &self.implementation_principal_ids,
            implementation_identity_digests: &self.implementation_identity_digests,
            live_provider_scope: &self.live_provider_scope,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7CausalSubjectKind {
    ProofRun,
    Candidate,
    SchedulerRun,
    CapabilityRun,
    WorkerWorkflow,
    FactoryCycle,
    ExchangeRoute,
    TestRun,
    ClosureReview,
    ProviderQualification,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7CausalSubject {
    pub kind: M7CausalSubjectKind,
    pub subject_digest: ContentDigest,
    pub proof_chain_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct M7CausalSourceDescriptorV1 {
    semantic_role: M7SourceRoleV2,
    source_schema: String,
    digest: ContentDigest,
    byte_length: u64,
}

#[derive(Serialize)]
struct M7CausalSubjectDigestMaterial<'a> {
    domain: &'static str,
    proof_run_id: &'a str,
    manifest_digest: &'a ContentDigest,
    proof_chain_digest: &'a ContentDigest,
    evidence_kind: M7EvidenceKind,
    source_closure: &'a [M7CausalSourceDescriptorV1],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7SourceKindV2 {
    M5ExportBundle,
    M5FinalPostRollbackProbe,
    SupervisorState,
    CargoTestTranscript,
    SourceCaptureAttestation,
    TruthBoundary,
    ClaimBoundary,
    PublicationPolicy,
    IndependentReview,
    LiveProviderQualification,
    M6CompletionBundle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7SourceRoleV2 {
    M0TruthBoundary,
    M5ExportM1,
    SupervisorPreRestart,
    SupervisorPostRestart,
    M5ExportM3,
    M5ExportM4,
    M5ExportRollback,
    M5FinalPostRollbackProbe,
    M6Completion,
    CargoTestTranscript,
    SourceCaptureAttestation,
    ClaimBoundary,
    PublicationPolicy,
    IndependentReview,
    LiveProviderQualification,
}

impl M7SourceRoleV2 {
    pub fn source_kind(self) -> M7SourceKindV2 {
        match self {
            Self::M0TruthBoundary => M7SourceKindV2::TruthBoundary,
            Self::M5ExportM1 | Self::M5ExportM3 | Self::M5ExportM4 | Self::M5ExportRollback => {
                M7SourceKindV2::M5ExportBundle
            }
            Self::M5FinalPostRollbackProbe => M7SourceKindV2::M5FinalPostRollbackProbe,
            Self::SupervisorPreRestart | Self::SupervisorPostRestart => {
                M7SourceKindV2::SupervisorState
            }
            Self::M6Completion => M7SourceKindV2::M6CompletionBundle,
            Self::CargoTestTranscript => M7SourceKindV2::CargoTestTranscript,
            Self::SourceCaptureAttestation => M7SourceKindV2::SourceCaptureAttestation,
            Self::ClaimBoundary => M7SourceKindV2::ClaimBoundary,
            Self::PublicationPolicy => M7SourceKindV2::PublicationPolicy,
            Self::IndependentReview => M7SourceKindV2::IndependentReview,
            Self::LiveProviderQualification => M7SourceKindV2::LiveProviderQualification,
        }
    }

    pub fn source_schema(self) -> &'static str {
        match self.source_kind() {
            M7SourceKindV2::M5ExportBundle => M5_EXPORT_BUNDLE_SCHEMA,
            M7SourceKindV2::M5FinalPostRollbackProbe => M5_FINAL_POST_ROLLBACK_PROBE_SCHEMA,
            M7SourceKindV2::SupervisorState => M7_SUPERVISOR_STATE_SOURCE_SCHEMA,
            M7SourceKindV2::CargoTestTranscript => M7_CARGO_TEST_TRANSCRIPT_SCHEMA,
            M7SourceKindV2::SourceCaptureAttestation => M7_SOURCE_CAPTURE_ATTESTATION_SCHEMA,
            M7SourceKindV2::TruthBoundary => M7_TRUTH_BOUNDARY_SOURCE_SCHEMA,
            M7SourceKindV2::ClaimBoundary => M7_CLAIM_BOUNDARY_SOURCE_SCHEMA,
            M7SourceKindV2::PublicationPolicy => M7_PUBLICATION_POLICY_SOURCE_SCHEMA,
            M7SourceKindV2::IndependentReview => M7_INDEPENDENT_REVIEW_SOURCE_SCHEMA,
            M7SourceKindV2::LiveProviderQualification => M7_LIVE_PROVIDER_SOURCE_SCHEMA,
            M7SourceKindV2::M6CompletionBundle => M6_COMPLETION_BUNDLE_SCHEMA,
        }
    }

    pub fn evidence_kind(self) -> M7EvidenceKind {
        match self {
            Self::M0TruthBoundary => M7EvidenceKind::M0TruthBaseline,
            Self::M5ExportM1 => M7EvidenceKind::M1CandidateLifecycle,
            Self::SupervisorPreRestart | Self::SupervisorPostRestart => {
                M7EvidenceKind::M2SchedulerWakeRestart
            }
            Self::M5ExportM3 => M7EvidenceKind::M3CapabilityEffects,
            Self::M5ExportM4 => M7EvidenceKind::M4WorkerEcology,
            Self::M5ExportRollback | Self::M5FinalPostRollbackProbe => {
                M7EvidenceKind::M5ActivationRollback
            }
            Self::M6Completion => M7EvidenceKind::M6FactoryExchange,
            Self::CargoTestTranscript => M7EvidenceKind::DeterministicTestTranscript,
            Self::SourceCaptureAttestation => M7EvidenceKind::DeterministicTestTranscript,
            Self::ClaimBoundary => M7EvidenceKind::ClaimBoundary,
            Self::PublicationPolicy => M7EvidenceKind::PublicationPolicy,
            Self::IndependentReview => M7EvidenceKind::IndependentReviewerRecommendation,
            Self::LiveProviderQualification => M7EvidenceKind::LiveProviderQualification,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7SourceLinkV2 {
    schema: String,
    pub semantic_role: M7SourceRoleV2,
    pub source_kind: M7SourceKindV2,
    pub source_schema: String,
    pub proof_run_id: String,
    pub manifest_digest: ContentDigest,
    pub causal_subject: M7CausalSubject,
    pub digest: ContentDigest,
    pub byte_length: u64,
}

impl M7SourceLinkV2 {
    /// Construct the immutable link for exact source bytes before those bytes
    /// are placed in a resolver.
    ///
    /// Source-capture callers use this constructor to build the inventory that
    /// an external custodian signs. It deliberately seals every routing field,
    /// rather than accepting a caller-supplied digest detached from its run,
    /// manifest, schema, semantic role, or causal subject.
    pub fn from_source_bytes(
        manifest: &M7ProofRunManifest,
        causal_subject: M7CausalSubject,
        semantic_role: M7SourceRoleV2,
        bytes: &[u8],
    ) -> Result<Self, M7FoundationError> {
        manifest.validate()?;
        if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
            return Err(M7FoundationError::InvalidSource(
                "source bytes are empty or outside the source bound".to_string(),
            ));
        }
        validate_source_bytes(semantic_role, bytes)?;
        let evidence_kind = semantic_role.evidence_kind();
        let link = Self {
            schema: M7_SOURCE_LINK_SCHEMA.to_string(),
            semantic_role,
            source_kind: semantic_role.source_kind(),
            source_schema: semantic_role.source_schema().to_string(),
            proof_run_id: manifest.proof_run_id.clone(),
            manifest_digest: manifest.manifest_digest.clone(),
            causal_subject,
            digest: ContentDigest::from_bytes(bytes),
            byte_length: bytes.len() as u64,
        };
        link.validate_for(manifest, evidence_kind, &link.causal_subject)?;
        Ok(link)
    }

    pub fn validate_for(
        &self,
        manifest: &M7ProofRunManifest,
        evidence_kind: M7EvidenceKind,
        causal_subject: &M7CausalSubject,
    ) -> Result<(), M7FoundationError> {
        if self.schema != M7_SOURCE_LINK_SCHEMA
            || self.source_kind != self.semantic_role.source_kind()
            || self.source_schema != self.semantic_role.source_schema()
            || self.semantic_role.evidence_kind() != evidence_kind
        {
            return Err(M7FoundationError::InvalidSource(
                "source-link role, kind, schema, and evidence family disagree".to_string(),
            ));
        }
        validate_identifier("source proof_run_id", &self.proof_run_id)?;
        if self.proof_run_id != manifest.proof_run_id
            || self.manifest_digest != manifest.manifest_digest
        {
            return Err(M7FoundationError::InvalidSource(
                "source link is cross-run or names a stale manifest".to_string(),
            ));
        }
        if self.causal_subject.kind != evidence_kind.expected_causal_kind()
            || &self.causal_subject != causal_subject
            || self.causal_subject.proof_chain_digest != manifest.causal_chain_digest
        {
            return Err(M7FoundationError::InvalidSource(
                "source link is outside the evidence causal subject".to_string(),
            ));
        }
        let length = usize::try_from(self.byte_length).unwrap_or(usize::MAX);
        if length == 0 || length > MAX_SOURCE_BYTES {
            return Err(M7FoundationError::InvalidSource(format!(
                "source byte length must be in 1..={MAX_SOURCE_BYTES}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M7SourceInputV2 {
    pub semantic_role: M7SourceRoleV2,
    pub bytes: Vec<u8>,
}

impl M7SourceInputV2 {
    pub fn new(semantic_role: M7SourceRoleV2, bytes: Vec<u8>) -> Self {
        Self {
            semantic_role,
            bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M7SourceBlobV2 {
    link: M7SourceLinkV2,
    bytes: Vec<u8>,
}

impl M7SourceBlobV2 {
    pub fn link(&self) -> &M7SourceLinkV2 {
        &self.link
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M7DerivedEvidenceV2 {
    artifact: M7EvidenceArtifact,
    source_blobs: Vec<M7SourceBlobV2>,
}

impl M7DerivedEvidenceV2 {
    pub fn artifact(&self) -> &M7EvidenceArtifact {
        &self.artifact
    }

    pub fn source_blobs(&self) -> &[M7SourceBlobV2] {
        &self.source_blobs
    }

    pub fn artifact_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        self.artifact.canonical_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7EvidenceLink {
    pub kind: M7EvidenceKind,
    pub owner_milestone: M7Milestone,
    pub proof_run_id: String,
    pub causal_subject: M7CausalSubject,
    pub digest: ContentDigest,
    pub byte_length: u64,
}

impl M7EvidenceLink {
    fn validate(&self) -> Result<(), M7FoundationError> {
        validate_identifier("evidence proof_run_id", &self.proof_run_id)?;
        if self.owner_milestone != self.kind.owner_milestone() {
            return Err(M7FoundationError::InvalidEvidenceLink(
                "evidence owner milestone does not match its kind".to_string(),
            ));
        }
        if self.causal_subject.kind != self.kind.expected_causal_kind() {
            return Err(M7FoundationError::InvalidEvidenceLink(
                "evidence causal-subject kind does not match its evidence kind".to_string(),
            ));
        }
        let byte_length = usize::try_from(self.byte_length).unwrap_or(usize::MAX);
        if byte_length == 0 || byte_length > MAX_EVIDENCE_BYTES {
            return Err(M7FoundationError::InvalidEvidenceLink(format!(
                "evidence byte length must be in 1..={MAX_EVIDENCE_BYTES}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7WorkerRole {
    Planner,
    Researcher,
    Builder,
    Tester,
    Reviewer,
    Operator,
}

fn mandatory_worker_roles() -> BTreeSet<M7WorkerRole> {
    BTreeSet::from([
        M7WorkerRole::Planner,
        M7WorkerRole::Researcher,
        M7WorkerRole::Builder,
        M7WorkerRole::Tester,
        M7WorkerRole::Reviewer,
        M7WorkerRole::Operator,
    ])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M0TruthEvidence {
    pub active_surface_snapshot_digest: ContentDigest,
    pub active_truth_digest: ContentDigest,
    pub legacy_phase04_historical_only: bool,
    pub seeded_status_used_as_proof: bool,
    pub pre_run_operational_decision: M7ClosureDecision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M1CandidateLifecycleEvidence {
    pub incumbent_package_digest: ContentDigest,
    pub candidate_package_digest: ContentDigest,
    pub candidate_component_digest: ContentDigest,
    pub mutation_changed_candidate_bytes: bool,
    pub build_succeeded: bool,
    pub tests_succeeded: bool,
    pub proving_succeeded: bool,
    pub package_resolved: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M2SchedulerWakeRestartEvidence {
    pub manifest_digest: ContentDigest,
    pub challenge_job_id: String,
    pub challenge_digest: ContentDigest,
    pub m5_export_bundle_content_digest: ContentDigest,
    /// Content digest of the exact canonical M6 completion bytes that existed
    /// before this future M2 job was submitted.
    pub m6_completion_bundle_content_digest: ContentDigest,
    pub m4_lifecycle_job_id: String,
    pub m4_lifecycle_terminal_job_digest: ContentDigest,
    pub scheduled_job_digest: ContentDigest,
    pub completed_job_digest: ContentDigest,
    pub effect_receipt_digest: ContentDigest,
    pub wake_record_digest: ContentDigest,
    /// Seal over the exact before/after supervisor bytes and every recovered
    /// manifest, M5, M6, M4, and challenge-job identity.
    pub restart_capture_digest: ContentDigest,
    pub future_wake_observed: bool,
    pub process_restart_observed: bool,
    pub restart_reconstructed: bool,
    pub missed_wake_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3CapabilityEffectsEvidence {
    pub required_capability_count: u32,
    pub successful_receipt_count: u32,
    pub all_receipts_resolved: bool,
    pub all_attestations_valid: bool,
    pub generic_bypass_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M4WorkerEcologyEvidence {
    pub factory_id: String,
    pub scope_id: String,
    pub lifecycle_terminal_job_digests: BTreeMap<String, ContentDigest>,
    pub required_roles: BTreeSet<M7WorkerRole>,
    pub terminal_worker_result_count: u32,
    pub receipt_backed_result_count: u32,
    pub invented_worker_result_count: u32,
    pub synthesis_resolved: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ActivationRollbackEvidence {
    /// Exact proof-run chronology identities carried by the final, M3-backed
    /// post-rollback probe. They are rejoined against the manifest and the M2
    /// and M6 artifacts by the pure evaluator.
    pub manifest_digest: ContentDigest,
    pub m5_export_bundle_content_digest: ContentDigest,
    pub m6_completion_bundle_content_digest: ContentDigest,
    pub m2_restart_capture_digest: ContentDigest,
    pub final_probe_causal_execution_context_digest: ContentDigest,
    pub final_post_rollback_probe_content_digest: ContentDigest,
    pub final_post_rollback_probe_record_digest: ContentDigest,
    pub active_cycle_id: String,
    pub active_cycle_record_digest: ContentDigest,
    pub active_parent_package_digest: ContentDigest,
    pub active_package_digest: ContentDigest,
    pub active_release_gate_digest: ContentDigest,
    pub active_operator_context_digest: ContentDigest,
    pub rollback_cycle_id: String,
    pub rollback_cycle_record_digest: ContentDigest,
    pub rollback_release_gate_digest: ContentDigest,
    pub rollback_operator_context_digest: ContentDigest,
    pub provider_qualification_record_digests_by_target:
        BTreeMap<ContentDigest, BTreeSet<ContentDigest>>,
    pub incumbent_package_digest: ContentDigest,
    pub successor_package_digest: ContentDigest,
    pub restored_package_digest: ContentDigest,
    pub restored_snapshot_digest: ContentDigest,
    pub activation_receipt_digest: ContentDigest,
    pub observation_evidence_digest: ContentDigest,
    pub recovery_receipt_digest: ContentDigest,
    pub successor_activated: bool,
    pub real_failure_observed: bool,
    pub rollback_intent_durable: bool,
    pub rollback_completed: bool,
    pub state_reference_restored: bool,
    pub runtime_behavior_restored: bool,
    pub incomplete_mutation: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M6FactoryExchangeEvidence {
    /// Content digest of the exact canonical completion source bytes. This is
    /// deliberately distinct from the completion bundle's internal seal.
    pub completion_bundle_content_digest: ContentDigest,
    /// Content digest of the exact canonical M5 export bytes embedded by the
    /// M6 sender. The evaluator requires this identity to equal every M5
    /// export source used for M1, M3, M4, and M5.
    pub sender_m5_export_bundle_content_digest: ContentDigest,
    pub accepted_exchange_digest: ContentDigest,
    pub rejected_or_rolled_back_exchange_digest: ContentDigest,
    pub accepted_exchange_count: u32,
    pub rejected_or_rolled_back_count: u32,
    pub exact_bytes_verified: bool,
    pub sender_lineage_resolved: bool,
    pub receiver_proving_resolved: bool,
    pub negative_control_suite_passed: bool,
    pub replay_rejection_control_passed: bool,
    pub revocation_control_passed: bool,
    pub unresolved_quarantine_count: u32,
    pub receiver_rollback_complete: bool,
    pub sender_unchanged: bool,
    pub both_factories_restarted: bool,
    pub acknowledgement_used_as_adoption_evidence: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicTestTranscriptEvidence {
    pub command_digest: ContentDigest,
    pub transcript_digest: ContentDigest,
    pub required_test_count: u32,
    pub executed_test_count: u32,
    pub failed_test_count: u32,
    pub clean_root: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimBoundaryEvidence {
    pub active_surface_snapshot_digest: ContentDigest,
    pub claim_catalog_digest: ContentDigest,
    pub claim_catalog_version: String,
    pub allowed_claims_digest: ContentDigest,
    pub forbidden_claims_digest: ContentDigest,
    pub forbidden_claim_count: u32,
    pub active_surfaces_aligned: bool,
    pub public_federation_claimed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationPolicyEvidence {
    pub active_surface_snapshot_digest: ContentDigest,
    pub publication_controls_digest: ContentDigest,
    pub publication_policy_digest: ContentDigest,
    pub secrets_redacted: bool,
    pub legacy_phase04_labeled_historical: bool,
    pub outcome_neutral: bool,
    pub bounded_local_first_preserved: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentReviewerEvidence {
    pub reviewer_id: String,
    pub reviewer_identity_digest: ContentDigest,
    pub reviewer_public_key_digest: ContentDigest,
    pub reviewed_manifest_digest: ContentDigest,
    pub reviewed_evidence_set_digest: ContentDigest,
    pub recommendation: M7ClosureDecision,
    pub rationale_digest: ContentDigest,
    pub independence_statement_digest: ContentDigest,
    pub participation_declaration: M7ReviewerParticipationDeclarationV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderQualificationEvidence {
    pub scope_digest: ContentDigest,
    pub proof_run_id: String,
    pub prepared_at_ms: u64,
    pub execution_manifest_digest: ContentDigest,
    pub precommit_digest: ContentDigest,
    pub prepared_digest: ContentDigest,
    pub binding_digest: ContentDigest,
    pub execution_receipt_digest: ContentDigest,
    pub qualification_record_digest: ContentDigest,
    pub provider_id: String,
    pub model_id: String,
    pub api_base_url: String,
    pub endpoint_class: M5ProviderEndpointClassV1,
    pub qualification_run_id: String,
    pub driver_profile_digest: ContentDigest,
    pub configuration_fingerprint: ContentDigest,
    pub response_schema_digest: ContentDigest,
    pub prompt_renderer_digest: ContentDigest,
    pub tool_catalog_digest: ContentDigest,
    pub cycle_id: String,
    pub release_gate_digest: ContentDigest,
    pub operator_context_digest: ContentDigest,
    pub incumbent_package_digest: ContentDigest,
    pub target_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub challenged_seed_digest: ContentDigest,
    pub invocation_challenge_digest: ContentDigest,
    pub wire_request_digest: ContentDigest,
    pub request_body_digest: ContentDigest,
    pub completed_invocation_digest: ContentDigest,
    pub target_package_digest: ContentDigest,
    pub qualified: bool,
    pub transcript_redacted: bool,
    /// Narrow statement about the exact scanned source wrapper only.
    pub credential_material_in_source: bool,
    pub terminal_outcome_adopted: bool,
    pub terminal_cycle_record_digest: Option<ContentDigest>,
    pub terminal_outcome_digest: ContentDigest,
    pub manifest_run_started_at_ms: u64,
    pub manifest_validated_at_ms: u64,
    pub call_started_at_ms: u64,
    pub call_completed_at_ms: u64,
    pub run_nonce_digest: ContentDigest,
    pub deterministic_replay_digest: ContentDigest,
    pub parsed_intent_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "payload_kind", content = "payload", rename_all = "snake_case")]
pub enum M7EvidencePayload {
    M0TruthBaseline(M0TruthEvidence),
    M1CandidateLifecycle(M1CandidateLifecycleEvidence),
    M2SchedulerWakeRestart(M2SchedulerWakeRestartEvidence),
    M3CapabilityEffects(M3CapabilityEffectsEvidence),
    M4WorkerEcology(M4WorkerEcologyEvidence),
    M5ActivationRollback(M5ActivationRollbackEvidence),
    M6FactoryExchange(M6FactoryExchangeEvidence),
    DeterministicTestTranscript(DeterministicTestTranscriptEvidence),
    ClaimBoundary(ClaimBoundaryEvidence),
    PublicationPolicy(PublicationPolicyEvidence),
    IndependentReviewerRecommendation(IndependentReviewerEvidence),
    LiveProviderQualification(LiveProviderQualificationEvidence),
}

fn required_publication_controls() -> BTreeSet<M7PublicationControlV1> {
    crate::execution::active_truth_publication_controls()
}

fn bounded_claim_catalog() -> Result<M7ClaimCatalogV1, M7FoundationError> {
    M7ClaimCatalogV1::bounded_local_first().map_err(|error| {
        M7FoundationError::InvalidSource(format!(
            "bounded local-first claim catalog is invalid: {error}"
        ))
    })
}

fn validate_claim_catalog(catalog: &M7ClaimCatalogV1) -> Result<(), M7FoundationError> {
    catalog.validate().map_err(|error| {
        M7FoundationError::InvalidSource(format!("active claim catalog is invalid: {error}"))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7HistoricalPhase04ScopeV1 {
    #[serde(rename = "historical_record_completeness_only")]
    HistoricalRecordCompletenessOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7FederationPostureV1 {
    #[serde(rename = "bounded_local_first_no_public_federation")]
    BoundedLocalFirstNoPublicFederation,
}

/// Canonical structured truth embedded verbatim in both authoritative
/// Markdown surfaces and re-derived from the typed HTTP projections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ActiveTruthV1 {
    schema: String,
    pub operational_decision: M7ClosureDecision,
    pub historical_phase04_scope: M7HistoricalPhase04ScopeV1,
    pub historical_lineage_decision: NorthStarClosureDecision,
    pub federation_posture: M7FederationPostureV1,
    pub roadmap_status_authority: String,
    pub claim_catalog_version: String,
    pub claim_catalog_digest: ContentDigest,
}

impl M7ActiveTruthV1 {
    pub fn bounded_local_first(catalog: &M7ClaimCatalogV1) -> Result<Self, M7FoundationError> {
        validate_claim_catalog(catalog)?;
        let value = Self {
            schema: M7_ACTIVE_TRUTH_SCHEMA.to_string(),
            operational_decision: M7ClosureDecision::NotYet,
            historical_phase04_scope: M7HistoricalPhase04ScopeV1::HistoricalRecordCompletenessOnly,
            historical_lineage_decision: NorthStarClosureDecision::Closed,
            federation_posture: M7FederationPostureV1::BoundedLocalFirstNoPublicFederation,
            roadmap_status_authority: "notes/ROADMAP.md".to_string(),
            claim_catalog_version: catalog.catalog_version.clone(),
            claim_catalog_digest: catalog.catalog_digest.clone(),
        };
        value.validate(catalog)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        compact_json(self)
    }

    pub fn digest(&self) -> Result<ContentDigest, M7FoundationError> {
        Ok(ContentDigest::from_bytes(&self.canonical_bytes()?))
    }

    fn from_canonical_bytes(
        bytes: &[u8],
        catalog: &M7ClaimCatalogV1,
    ) -> Result<Self, M7FoundationError> {
        parse_compact_json(bytes, "active-truth block", |value: &Self| {
            value.validate(catalog)
        })
    }

    fn validate(&self, catalog: &M7ClaimCatalogV1) -> Result<(), M7FoundationError> {
        if self.schema != M7_ACTIVE_TRUTH_SCHEMA
            || self.operational_decision != M7ClosureDecision::NotYet
            || self.historical_phase04_scope
                != M7HistoricalPhase04ScopeV1::HistoricalRecordCompletenessOnly
            || self.historical_lineage_decision != NorthStarClosureDecision::Closed
            || self.federation_posture != M7FederationPostureV1::BoundedLocalFirstNoPublicFederation
            || self.roadmap_status_authority != "notes/ROADMAP.md"
            || self.claim_catalog_version != catalog.catalog_version
            || self.claim_catalog_digest != catalog.catalog_digest
        {
            return Err(M7FoundationError::InvalidSource(
                "active-truth block disagrees with the bounded local-first claim catalog"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7ActiveSurfaceRoleV1 {
    #[serde(rename = "root_readme")]
    RootReadme,
    #[serde(rename = "roadmap")]
    Roadmap,
    #[serde(rename = "system_overview")]
    SystemOverview,
    #[serde(rename = "general_audience_home")]
    GeneralAudienceHome,
    #[serde(rename = "north_star_07_closure_review")]
    NorthStar07ClosureReview,
    #[serde(rename = "remediation_phase_04_final_closure_rereview")]
    RemediationPhase04FinalClosureRereview,
    #[serde(rename = "remediation_phase_04_publication_policy")]
    RemediationPhase04PublicationPolicy,
}

impl M7ActiveSurfaceRoleV1 {
    pub fn observation_sequence(self) -> u8 {
        match self {
            Self::RootReadme => 1,
            Self::Roadmap => 2,
            Self::SystemOverview => 3,
            Self::GeneralAudienceHome => 4,
            Self::NorthStar07ClosureReview => 5,
            Self::RemediationPhase04FinalClosureRereview => 6,
            Self::RemediationPhase04PublicationPolicy => 7,
        }
    }

    pub fn is_http_surface(self) -> bool {
        !matches!(self, Self::RootReadme | Self::Roadmap)
    }

    pub fn path(self) -> &'static str {
        match self {
            Self::RootReadme => "README.md",
            Self::Roadmap => "notes/ROADMAP.md",
            Self::SystemOverview => "/api/system/overview",
            Self::GeneralAudienceHome => "/api/home/general-audience",
            Self::NorthStar07ClosureReview => "/api/northstar/07/closure-review",
            Self::RemediationPhase04FinalClosureRereview => {
                "/api/remediation/phase-04/final-closure-rereview"
            }
            Self::RemediationPhase04PublicationPolicy => {
                "/api/remediation/phase-04/publication-policy"
            }
        }
    }

    pub fn media_type(self) -> &'static str {
        match self {
            Self::RootReadme | Self::Roadmap => "text/markdown; charset=utf-8",
            _ => "application/json",
        }
    }

    pub fn content_schema(self) -> &'static str {
        match self {
            Self::RootReadme | Self::Roadmap => "wasm-biotic.markdown.active-truth.v1",
            Self::SystemOverview => "wasm-biotic.api.system-overview.v1",
            Self::GeneralAudienceHome => "wasm-biotic.api.general-audience-home.v1",
            Self::NorthStar07ClosureReview => "wasm-biotic.api.north-star-07-closure-review.v1",
            Self::RemediationPhase04FinalClosureRereview => {
                "wasm-biotic.api.remediation-phase-04-final-closure-rereview.v1"
            }
            Self::RemediationPhase04PublicationPolicy => {
                "wasm-biotic.api.remediation-phase-04-publication-policy.v1"
            }
        }
    }
}

fn required_active_surface_roles() -> BTreeSet<M7ActiveSurfaceRoleV1> {
    BTreeSet::from([
        M7ActiveSurfaceRoleV1::RootReadme,
        M7ActiveSurfaceRoleV1::Roadmap,
        M7ActiveSurfaceRoleV1::SystemOverview,
        M7ActiveSurfaceRoleV1::GeneralAudienceHome,
        M7ActiveSurfaceRoleV1::NorthStar07ClosureReview,
        M7ActiveSurfaceRoleV1::RemediationPhase04FinalClosureRereview,
        M7ActiveSurfaceRoleV1::RemediationPhase04PublicationPolicy,
    ])
}

/// Fixture-only owned bytes for deterministic in-crate and acceptance tests.
/// Production callers must use the operator's loopback HTTP capture boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct M7ActiveSurfaceInputBytesV1 {
    pub root_readme: Vec<u8>,
    pub roadmap: Vec<u8>,
    pub system_overview: Vec<u8>,
    pub general_audience_home: Vec<u8>,
    pub northstar_07_closure_review: Vec<u8>,
    pub remediation_phase_04_final_closure_rereview: Vec<u8>,
    pub remediation_phase_04_publication_policy: Vec<u8>,
}

#[cfg(test)]
impl M7ActiveSurfaceInputBytesV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root_readme: Vec<u8>,
        roadmap: Vec<u8>,
        system_overview: Vec<u8>,
        general_audience_home: Vec<u8>,
        northstar_07_closure_review: Vec<u8>,
        remediation_phase_04_final_closure_rereview: Vec<u8>,
        remediation_phase_04_publication_policy: Vec<u8>,
    ) -> Self {
        Self {
            root_readme,
            roadmap,
            system_overview,
            general_audience_home,
            northstar_07_closure_review,
            remediation_phase_04_final_closure_rereview,
            remediation_phase_04_publication_policy,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum M7ActiveSurfaceObservationSourceV1 {
    LocalAuthority {
        authority_ref: String,
        canonical_path: String,
    },
    Http {
        method: String,
        origin: String,
        request_path: String,
        status_code: u16,
        media_type: String,
        peer_addr: String,
        http_version: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ActiveSurfaceObservationV1 {
    schema: String,
    sequence: u8,
    observed_started_at_ms: u64,
    observed_completed_at_ms: u64,
    source: M7ActiveSurfaceObservationSourceV1,
    content_length: u64,
    content_digest: ContentDigest,
    observation_digest: ContentDigest,
}

impl M7ActiveSurfaceObservationV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn local_authority(
        role: M7ActiveSurfaceRoleV1,
        canonical_path: String,
        observed_started_at_ms: u64,
        observed_completed_at_ms: u64,
        bytes: &[u8],
    ) -> Result<Self, M7FoundationError> {
        Self::new(
            role,
            observed_started_at_ms,
            observed_completed_at_ms,
            M7ActiveSurfaceObservationSourceV1::LocalAuthority {
                authority_ref: role.path().to_string(),
                canonical_path,
            },
            bytes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn http_get(
        role: M7ActiveSurfaceRoleV1,
        origin: String,
        peer_addr: String,
        http_version: String,
        observed_started_at_ms: u64,
        observed_completed_at_ms: u64,
        bytes: &[u8],
    ) -> Result<Self, M7FoundationError> {
        Self::new(
            role,
            observed_started_at_ms,
            observed_completed_at_ms,
            M7ActiveSurfaceObservationSourceV1::Http {
                method: "GET".to_string(),
                origin,
                request_path: role.path().to_string(),
                status_code: 200,
                media_type: "application/json".to_string(),
                peer_addr,
                http_version,
            },
            bytes,
        )
    }

    fn new(
        role: M7ActiveSurfaceRoleV1,
        observed_started_at_ms: u64,
        observed_completed_at_ms: u64,
        source: M7ActiveSurfaceObservationSourceV1,
        bytes: &[u8],
    ) -> Result<Self, M7FoundationError> {
        let mut value = Self {
            schema: M7_ACTIVE_SURFACE_OBSERVATION_SCHEMA.to_string(),
            sequence: role.observation_sequence(),
            observed_started_at_ms,
            observed_completed_at_ms,
            source,
            content_length: bytes.len() as u64,
            content_digest: ContentDigest::from_bytes(bytes),
            observation_digest: ContentDigest::from_bytes(&[]),
        };
        value.observation_digest = value.expected_digest()?;
        value.validate_for_role(role)?;
        Ok(value)
    }

    pub fn sequence(&self) -> u8 {
        self.sequence
    }

    pub fn observed_started_at_ms(&self) -> u64 {
        self.observed_started_at_ms
    }

    pub fn observed_completed_at_ms(&self) -> u64 {
        self.observed_completed_at_ms
    }

    pub fn source(&self) -> &M7ActiveSurfaceObservationSourceV1 {
        &self.source
    }

    pub fn observation_digest(&self) -> &ContentDigest {
        &self.observation_digest
    }

    fn validate_for_role(&self, role: M7ActiveSurfaceRoleV1) -> Result<(), M7FoundationError> {
        let source_valid = match &self.source {
            M7ActiveSurfaceObservationSourceV1::LocalAuthority {
                authority_ref,
                canonical_path,
            } => {
                !role.is_http_surface()
                    && authority_ref == role.path()
                    && valid_canonical_authority_path(role, canonical_path)
            }
            M7ActiveSurfaceObservationSourceV1::Http {
                method,
                origin,
                request_path,
                status_code,
                media_type,
                peer_addr,
                http_version,
            } => {
                role.is_http_surface()
                    && method == "GET"
                    && valid_loopback_http_origin(origin)
                    && request_path == role.path()
                    && *status_code == 200
                    && media_type == "application/json"
                    && valid_observed_http_peer(origin, peer_addr)
                    && http_version == "HTTP/1.1"
            }
        };
        if self.schema != M7_ACTIVE_SURFACE_OBSERVATION_SCHEMA
            || self.sequence != role.observation_sequence()
            || self.observed_started_at_ms == 0
            || self.observed_completed_at_ms < self.observed_started_at_ms
            || self.content_length == 0
            || self.content_length > MAX_ACTIVE_SURFACE_BYTES as u64
            || !source_valid
            || self.observation_digest != self.expected_digest()?
        {
            return Err(M7FoundationError::InvalidSource(format!(
                "active surface {role:?} has invalid observation provenance"
            )));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            ACTIVE_SURFACE_OBSERVATION_DOMAIN,
            M7_ACTIVE_SURFACE_OBSERVATION_SCHEMA,
            self.sequence,
            self.observed_started_at_ms,
            self.observed_completed_at_ms,
            &self.source,
            self.content_length,
            &self.content_digest,
        ))
    }
}

fn valid_canonical_authority_path(role: M7ActiveSurfaceRoleV1, value: &str) -> bool {
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return false;
    }
    match role {
        M7ActiveSurfaceRoleV1::RootReadme => {
            path.file_name().is_some_and(|name| name == "README.md")
        }
        M7ActiveSurfaceRoleV1::Roadmap => {
            path.file_name().is_some_and(|name| name == "ROADMAP.md")
                && path
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == "notes")
        }
        _ => false,
    }
}

fn valid_loopback_http_origin(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(&format!("{value}/")) else {
        return false;
    };
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_none_or(|port| port == 80)
        || url.origin().ascii_serialization() != value
    {
        return false;
    }
    matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
    )
}

fn valid_observed_http_peer(origin: &str, peer: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(&format!("{origin}/")) else {
        return false;
    };
    let Ok(peer) = peer.parse::<SocketAddr>() else {
        return false;
    };
    if url.port() != Some(peer.port()) || !peer.ip().is_loopback() {
        return false;
    }
    match url.host_str() {
        Some("localhost") => true,
        Some("127.0.0.1") => peer.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        Some("::1" | "[::1]") => peer.ip() == std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        _ => false,
    }
}

pub fn m7_active_surface_capture_policy_digest() -> Result<ContentDigest, M7FoundationError> {
    digest(&(
        ACTIVE_SURFACE_CAPTURE_POLICY_DOMAIN,
        M7_ACTIVE_SURFACE_CAPTURE_POLICY_SCHEMA,
        "sequential-readme-roadmap-then-five-exact-http-get-paths",
        ["localhost", "127.0.0.1", "::1"],
        "explicit-non-default-port",
        "http1.1-only-no-redirect-no-proxy-no-retry-no-referer-no-pool-reuse",
        "status-200-content-type-application-json-no-content-encoding",
        "final-url-exact-no-location-no-cookie-no-auth-response-headers",
        "strict-content-length-bounded-streaming-body-and-total",
        "loopback-remote-peer-required",
        M7_ACTIVE_SURFACE_CONNECT_TIMEOUT_MS,
        M7_ACTIVE_SURFACE_REQUEST_TIMEOUT_MS,
        M7_ACTIVE_SURFACE_READ_TIMEOUT_MS,
        MAX_ACTIVE_SURFACE_BYTES,
        MAX_ACTIVE_SURFACE_SNAPSHOT_BYTES,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ActiveSurfaceCaptureV1 {
    schema: String,
    role: M7ActiveSurfaceRoleV1,
    path: String,
    media_type: String,
    content_schema: String,
    observation: M7ActiveSurfaceObservationV1,
    byte_length: u64,
    content_digest: ContentDigest,
    content: String,
    capture_digest: ContentDigest,
}

impl M7ActiveSurfaceCaptureV1 {
    pub(crate) fn from_observation(
        role: M7ActiveSurfaceRoleV1,
        bytes: Vec<u8>,
        observation: M7ActiveSurfaceObservationV1,
    ) -> Result<Self, M7FoundationError> {
        if bytes.is_empty() || bytes.len() > MAX_ACTIVE_SURFACE_BYTES {
            return Err(M7FoundationError::InvalidSource(format!(
                "active surface {:?} is empty or exceeds {MAX_ACTIVE_SURFACE_BYTES} bytes",
                role
            )));
        }
        let content = String::from_utf8(bytes).map_err(|_| {
            M7FoundationError::InvalidSource(format!(
                "active surface {:?} is not exact UTF-8",
                role
            ))
        })?;
        let mut value = Self {
            schema: M7_ACTIVE_SURFACE_CAPTURE_SCHEMA.to_string(),
            role,
            path: role.path().to_string(),
            media_type: role.media_type().to_string(),
            content_schema: role.content_schema().to_string(),
            observation,
            byte_length: content.len() as u64,
            content_digest: ContentDigest::from_bytes(content.as_bytes()),
            content,
            capture_digest: ContentDigest::from_bytes(&[]),
        };
        value.capture_digest = value.expected_digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn role(&self) -> M7ActiveSurfaceRoleV1 {
        self.role
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    pub fn content_schema(&self) -> &str {
        &self.content_schema
    }

    pub fn observation(&self) -> &M7ActiveSurfaceObservationV1 {
        &self.observation
    }

    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }

    pub fn content_bytes(&self) -> &[u8] {
        self.content.as_bytes()
    }

    pub fn capture_digest(&self) -> &ContentDigest {
        &self.capture_digest
    }

    fn validate(&self) -> Result<(), M7FoundationError> {
        if self.schema != M7_ACTIVE_SURFACE_CAPTURE_SCHEMA
            || self.path != self.role.path()
            || self.media_type != self.role.media_type()
            || self.content_schema != self.role.content_schema()
            || self.observation.content_length != self.byte_length
            || self.observation.content_digest != self.content_digest
            || self.observation.validate_for_role(self.role).is_err()
            || self.content.is_empty()
            || self.content.len() > MAX_ACTIVE_SURFACE_BYTES
            || self.byte_length != self.content.len() as u64
            || self.content_digest != ContentDigest::from_bytes(self.content.as_bytes())
            || self.capture_digest != self.expected_digest()?
        {
            return Err(M7FoundationError::InvalidSource(format!(
                "active surface {:?} has invalid metadata, bytes, or digest",
                self.role
            )));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            ACTIVE_SURFACE_CAPTURE_DOMAIN,
            M7_ACTIVE_SURFACE_CAPTURE_SCHEMA,
            self.role,
            &self.path,
            &self.media_type,
            &self.content_schema,
            &self.observation,
            self.byte_length,
            &self.content_digest,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7ActiveSurfaceSecretRuleV1 {
    PrivateKeyHeader,
    AuthorizationCredential,
    UriAuthorityUserinfo,
    SecretBearingAssignment,
    ProviderCloudTokenPrefix,
    CompactJwt,
}

fn active_surface_secret_rules() -> BTreeSet<M7ActiveSurfaceSecretRuleV1> {
    BTreeSet::from([
        M7ActiveSurfaceSecretRuleV1::PrivateKeyHeader,
        M7ActiveSurfaceSecretRuleV1::AuthorizationCredential,
        M7ActiveSurfaceSecretRuleV1::UriAuthorityUserinfo,
        M7ActiveSurfaceSecretRuleV1::SecretBearingAssignment,
        M7ActiveSurfaceSecretRuleV1::ProviderCloudTokenPrefix,
        M7ActiveSurfaceSecretRuleV1::CompactJwt,
    ])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7SecretScannedSurfaceV1 {
    pub role: M7ActiveSurfaceRoleV1,
    pub content_digest: ContentDigest,
    pub byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ActiveSurfaceSecretScanV1 {
    schema: String,
    rule_set_schema: String,
    rule_set_digest: ContentDigest,
    scanned_surfaces: Vec<M7SecretScannedSurfaceV1>,
    finding_count: u32,
    scan_digest: ContentDigest,
}

impl M7ActiveSurfaceSecretScanV1 {
    fn scan(surfaces: &[M7ActiveSurfaceCaptureV1]) -> Result<Self, M7FoundationError> {
        let rules = active_surface_secret_rules();
        let rule_set_digest = digest(&(
            ACTIVE_SURFACE_SECRET_RULE_SET_DOMAIN,
            M7_ACTIVE_SURFACE_SECRET_RULE_SET_SCHEMA,
            &rules,
        ))?;
        let mut finding_count = 0_u32;
        let scanned_surfaces = surfaces
            .iter()
            .map(|surface| {
                finding_count = finding_count.saturating_add(
                    u32::try_from(
                        detect_active_surface_secret_rules(surface.content_bytes()).len(),
                    )
                    .unwrap_or(u32::MAX),
                );
                M7SecretScannedSurfaceV1 {
                    role: surface.role,
                    content_digest: surface.content_digest.clone(),
                    byte_length: surface.byte_length,
                }
            })
            .collect::<Vec<_>>();
        let mut value = Self {
            schema: M7_ACTIVE_SURFACE_SECRET_SCAN_SCHEMA.to_string(),
            rule_set_schema: M7_ACTIVE_SURFACE_SECRET_RULE_SET_SCHEMA.to_string(),
            rule_set_digest,
            scanned_surfaces,
            finding_count,
            scan_digest: ContentDigest::from_bytes(&[]),
        };
        value.scan_digest = value.expected_digest()?;
        Ok(value)
    }

    pub fn rule_set_digest(&self) -> &ContentDigest {
        &self.rule_set_digest
    }

    pub fn scanned_surfaces(&self) -> &[M7SecretScannedSurfaceV1] {
        &self.scanned_surfaces
    }

    pub fn finding_count(&self) -> u32 {
        self.finding_count
    }

    pub fn scan_digest(&self) -> &ContentDigest {
        &self.scan_digest
    }

    fn validate(&self, surfaces: &[M7ActiveSurfaceCaptureV1]) -> Result<(), M7FoundationError> {
        let expected = Self::scan(surfaces)?;
        if self.schema != M7_ACTIVE_SURFACE_SECRET_SCAN_SCHEMA
            || self.rule_set_schema != M7_ACTIVE_SURFACE_SECRET_RULE_SET_SCHEMA
            || self != &expected
        {
            return Err(M7FoundationError::InvalidSource(
                "active-surface secret scan is stale, incomplete, or uses another rule set"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            ACTIVE_SURFACE_SECRET_SCAN_DOMAIN,
            M7_ACTIVE_SURFACE_SECRET_SCAN_SCHEMA,
            &self.rule_set_schema,
            &self.rule_set_digest,
            &self.scanned_surfaces,
            self.finding_count,
        ))
    }
}

fn secret_scan_is_placeholder(value: &[u8]) -> bool {
    let text = String::from_utf8_lossy(value);
    let value = text.trim_matches(|character: char| {
        character.is_ascii_whitespace() || matches!(character, '"' | '\'' | '`' | ',' | ';')
    });
    if value.is_empty()
        || (value.starts_with('<') && value.ends_with('>'))
        || (value.starts_with("${") && value.ends_with('}'))
        || value
            .bytes()
            .all(|byte| matches!(byte, b'*' | b'x' | b'X' | b'.' | b'-' | b'_'))
    {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("replace_with_")
        || lower.starts_with("replace-with-")
        || lower.starts_with("replace_me_")
        || lower.starts_with("replace-me-")
        || lower.starts_with("example_")
        || lower.starts_with("example-")
        || lower.starts_with("sample_")
        || lower.starts_with("sample-")
    {
        return true;
    }
    let compact = lower
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>();
    matches!(
        compact.as_str(),
        "redacted"
            | "masked"
            | "placeholder"
            | "example"
            | "sample"
            | "changeme"
            | "replaceme"
            | "unset"
            | "notset"
            | "none"
            | "null"
            | "false"
            | "true"
            | "omitted"
            | "removed"
            | "yourapikey"
            | "yourtoken"
            | "yoursecret"
            | "yourpassword"
    )
}

fn secret_scan_is_digest_value(value: &str) -> bool {
    [
        ("sha256:", 64_usize),
        ("sha512:", 128_usize),
        ("blake3:", 64_usize),
    ]
    .into_iter()
    .any(|(prefix, expected_length)| {
        value.strip_prefix(prefix).is_some_and(|digest| {
            digest.len() == expected_length && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    })
}

fn secret_scan_normalized_assignment_key_is_sensitive(key: &str) -> bool {
    let mut normalized = String::new();
    let mut previous_was_lower_or_digit = false;
    let mut last_was_separator = false;
    for character in key.chars() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase() && previous_was_lower_or_digit && !last_was_separator
            {
                normalized.push('_');
            }
            normalized.push(character.to_ascii_lowercase());
            previous_was_lower_or_digit =
                character.is_ascii_lowercase() || character.is_ascii_digit();
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            previous_was_lower_or_digit = false;
            last_was_separator = true;
        }
    }
    let normalized = normalized.trim_matches('_');
    if ["not_", "no_", "non_", "without_"]
        .into_iter()
        .any(|prefix| normalized.starts_with(prefix))
    {
        return false;
    }
    [
        "password",
        "passwd",
        "passphrase",
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "secretkey",
        "client_secret",
        "clientsecret",
        "private_key",
        "privatekey",
        "access_token",
        "accesstoken",
        "refresh_token",
        "refreshtoken",
        "session_token",
        "sessiontoken",
        "auth_token",
        "authtoken",
        "bearer_token",
        "bearertoken",
        "secret_access_key",
        "secretaccesskey",
    ]
    .into_iter()
    .any(|suffix| {
        normalized == suffix
            || normalized
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('_'))
    })
}

fn secret_scan_assignment_key(left: &str) -> bool {
    // Inspect the identifier immediately to the left of the delimiter. Source
    // records can embed captured output inside a JSON string, so using the
    // whole physical line would miss `... OPENAI_API_KEY=value` after the
    // enclosing JSON field name.
    let quoted_left = left;
    let left = left.trim_end_matches(|character: char| {
        !character.is_ascii_alphanumeric() && !matches!(character, '_' | '-' | '.')
    });
    let key = left
        .rsplit(|character: char| {
            !character.is_ascii_alphanumeric() && !matches!(character, '_' | '-' | '.')
        })
        .next()
        .unwrap_or(left);
    if secret_scan_normalized_assignment_key_is_sensitive(key) {
        return true;
    }

    // Quoted JSON/YAML keys may deliberately contain a space. Restrict this
    // broader candidate to an actual trailing quote so prose before an
    // assignment delimiter does not become a key.
    let quoted = quoted_left
        .trim_end()
        .strip_suffix(|character| matches!(character, '"' | '\'' | '`'))
        .and_then(|without_close| {
            without_close
                .rfind(|character| matches!(character, '"' | '\'' | '`'))
                .map(|open| &without_close[open + 1..])
        });
    quoted.is_some_and(secret_scan_normalized_assignment_key_is_sensitive)
}

fn secret_scan_assignment_value(right: &str) -> Option<&str> {
    let right = right.trim_start();
    if let Some(variable) = right.strip_prefix("${") {
        let close = variable.find('}')? + 2;
        let remainder = right[close + 1..].trim_start();
        if remainder.is_empty()
            || remainder.starts_with('#')
            || remainder.starts_with("//")
            || matches!(
                remainder.as_bytes().first(),
                Some(b',' | b';' | b'}' | b']')
            )
        {
            return Some(&right[..=close]);
        }
        return None;
    }
    let first = right.as_bytes().first().copied()?;
    if matches!(first, b'"' | b'\'' | b'`') {
        let mut escaped = false;
        for (offset, byte) in right.as_bytes()[1..].iter().copied().enumerate() {
            if byte == first && !escaped {
                return Some(&right[1..offset + 1]);
            }
            escaped = byte == b'\\' && !escaped;
            if byte != b'\\' {
                escaped = false;
            }
        }
        return None;
    }
    let end = right
        .char_indices()
        .find_map(|(index, character)| {
            (character.is_ascii_whitespace() || matches!(character, ',' | ';' | '}' | ']' | '#'))
                .then_some(index)
        })
        .unwrap_or(right.len());
    Some(&right[..end])
}

fn secret_scan_value_looks_secret(value: &str) -> bool {
    let value = value.trim();
    value.len() >= 8
        && !secret_scan_is_placeholder(value.as_bytes())
        && !secret_scan_is_digest_value(&value.to_ascii_lowercase())
}

fn secret_scan_contains_assignment(content: &str) -> bool {
    let lines = content.lines().collect::<Vec<_>>();
    lines.iter().enumerate().any(|(line_index, line)| {
        line.char_indices().any(|(index, delimiter)| {
            if !matches!(delimiter, ':' | '=') || !secret_scan_assignment_key(&line[..index]) {
                return false;
            }
            let right = &line[index + delimiter.len_utf8()..];
            if secret_scan_assignment_value(right).is_some_and(secret_scan_value_looks_secret) {
                return true;
            }
            if !matches!(right.trim(), "|" | ">" | "|-" | ">-" | "|+" | ">+") {
                return false;
            }
            lines[line_index + 1..]
                .iter()
                .take_while(|next| {
                    next.trim().is_empty() || next.starts_with(' ') || next.starts_with('\t')
                })
                .map(|next| next.trim())
                .find(|next| !next.is_empty() && !next.starts_with('#'))
                .is_some_and(secret_scan_value_looks_secret)
        })
    })
}

fn secret_scan_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn secret_scan_authorization_token_byte(byte: u8) -> bool {
    !byte.is_ascii_whitespace() && !matches!(byte, b'"' | b'\'' | b',' | b';' | b'}' | b']')
}

fn secret_scan_contains_authorization_credential(bytes: &[u8]) -> bool {
    let lower = bytes
        .iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let needle = b"authorization";
    let mut start = 0_usize;
    while start + needle.len() <= lower.len() {
        let Some(relative) = lower[start..]
            .windows(needle.len())
            .position(|window| window == needle)
        else {
            break;
        };
        let index = start + relative;
        start = index + needle.len();
        if (index > 0 && secret_scan_key_byte(lower[index - 1]))
            || lower
                .get(start)
                .is_some_and(|byte| secret_scan_key_byte(*byte))
        {
            continue;
        }
        let mut cursor = start;
        while lower
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\''))
        {
            cursor += 1;
        }
        if !matches!(lower.get(cursor), Some(b':' | b'=')) {
            continue;
        }
        cursor += 1;
        while lower
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\''))
        {
            cursor += 1;
        }
        let (scheme_length, minimum_token_length, basic) = if lower[cursor..].starts_with(b"bearer")
        {
            (6_usize, 12_usize, false)
        } else if lower[cursor..].starts_with(b"basic") {
            (5_usize, 12_usize, true)
        } else {
            continue;
        };
        cursor += scheme_length;
        if !lower
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            continue;
        }
        while lower
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            cursor += 1;
        }
        let token_start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| secret_scan_authorization_token_byte(*byte))
        {
            cursor += 1;
        }
        let token = &bytes[token_start..cursor];
        let valid_shape = token.len() >= minimum_token_length
            && if basic {
                token.len() % 4 == 0
                    && token.iter().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
                    })
            } else {
                token.iter().all(|byte| byte.is_ascii_graphic())
            };
        if valid_shape && !secret_scan_is_placeholder(token) {
            return true;
        }
    }
    false
}

fn secret_scan_uri_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

fn secret_scan_uri_authority_terminator(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>' | b'{' | b'}'
        )
}

fn secret_scan_contains_uri_userinfo(bytes: &[u8]) -> bool {
    for separator in 1..bytes.len().saturating_sub(2) {
        if &bytes[separator..separator + 3] != b"://" {
            continue;
        }
        let mut scheme_start = separator;
        while scheme_start > 0 && secret_scan_uri_scheme_byte(bytes[scheme_start - 1]) {
            scheme_start -= 1;
        }
        if scheme_start == separator || !bytes[scheme_start].is_ascii_alphabetic() {
            continue;
        }
        let authority_start = separator + 3;
        let authority_end = bytes[authority_start..]
            .iter()
            .position(|byte| secret_scan_uri_authority_terminator(*byte))
            .map(|offset| authority_start + offset)
            .unwrap_or(bytes.len());
        let authority = &bytes[authority_start..authority_end];
        let Some(at) = authority.iter().position(|byte| *byte == b'@') else {
            continue;
        };
        let userinfo = &authority[..at];
        if userinfo.is_empty() {
            continue;
        }
        let secret_part = userinfo
            .iter()
            .rposition(|byte| *byte == b':')
            .map(|colon| &userinfo[colon + 1..])
            .unwrap_or(userinfo);
        if secret_part.len() >= 3 && !secret_scan_is_placeholder(secret_part) {
            return true;
        }
    }
    false
}

fn secret_scan_provider_token_byte(byte: u8, allow_separators: bool) -> bool {
    byte.is_ascii_alphanumeric() || (allow_separators && matches!(byte, b'_' | b'-' | b'.'))
}

fn secret_scan_contains_prefixed_token(
    bytes: &[u8],
    prefix: &[u8],
    minimum_suffix_length: usize,
    allow_separators: bool,
) -> bool {
    bytes
        .windows(prefix.len())
        .enumerate()
        .any(|(index, window)| {
            if window != prefix
                || (index > 0
                    && secret_scan_provider_token_byte(bytes[index - 1], allow_separators))
            {
                return false;
            }
            let mut end = index + prefix.len();
            while bytes
                .get(end)
                .is_some_and(|byte| secret_scan_provider_token_byte(*byte, allow_separators))
            {
                end += 1;
            }
            end - index - prefix.len() >= minimum_suffix_length
                && !secret_scan_is_placeholder(&bytes[index..end])
        })
}

fn secret_scan_contains_aws_access_key(bytes: &[u8]) -> bool {
    [b"AKIA".as_slice(), b"ASIA".as_slice()]
        .into_iter()
        .any(|prefix| {
            bytes
                .windows(prefix.len())
                .enumerate()
                .any(|(index, window)| {
                    if window != prefix
                        || (index > 0
                            && (bytes[index - 1].is_ascii_uppercase()
                                || bytes[index - 1].is_ascii_digit()))
                    {
                        return false;
                    }
                    let mut end = index + prefix.len();
                    while bytes
                        .get(end)
                        .is_some_and(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                    {
                        end += 1;
                    }
                    end - index - prefix.len() >= 16
                        && !secret_scan_is_placeholder(&bytes[index..end])
                })
        })
}

fn secret_scan_contains_provider_cloud_token(bytes: &[u8]) -> bool {
    [
        (&b"sk-proj-"[..], 20_usize, true),
        (&b"sk-svcacct-"[..], 20_usize, true),
        (&b"sk-or-v1-"[..], 20_usize, true),
        (&b"sk-ant-"[..], 20_usize, true),
        (&b"sk-"[..], 32_usize, false),
        (&b"ghp_"[..], 20_usize, true),
        (&b"gho_"[..], 20_usize, true),
        (&b"ghu_"[..], 20_usize, true),
        (&b"ghs_"[..], 20_usize, true),
        (&b"ghr_"[..], 20_usize, true),
        (&b"github_pat_"[..], 20_usize, true),
        (&b"glpat-"[..], 20_usize, true),
        (&b"xoxb-"[..], 20_usize, true),
        (&b"xoxp-"[..], 20_usize, true),
        (&b"xoxa-"[..], 20_usize, true),
        (&b"xoxr-"[..], 20_usize, true),
        (&b"xoxs-"[..], 20_usize, true),
        (&b"xapp-"[..], 20_usize, true),
        (&b"AIza"[..], 30_usize, true),
        (&b"GOCSPX-"[..], 20_usize, true),
        (&b"ya29."[..], 20_usize, true),
        (&b"hf_"[..], 20_usize, true),
        (&b"sk_live_"[..], 16_usize, true),
        (&b"rk_live_"[..], 16_usize, true),
    ]
    .into_iter()
    .any(|(prefix, minimum_suffix_length, allow_separators)| {
        secret_scan_contains_prefixed_token(bytes, prefix, minimum_suffix_length, allow_separators)
    }) || secret_scan_contains_aws_access_key(bytes)
}

fn secret_scan_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn secret_scan_contains_compact_jwt(bytes: &[u8]) -> bool {
    for start in 0..bytes.len().saturating_sub(3) {
        if !bytes[start..].starts_with(b"eyJ")
            || (start > 0
                && (secret_scan_base64url_byte(bytes[start - 1]) || bytes[start - 1] == b'.'))
        {
            continue;
        }
        let mut first_end = start;
        while bytes
            .get(first_end)
            .is_some_and(|byte| secret_scan_base64url_byte(*byte))
        {
            first_end += 1;
        }
        if first_end - start < 8 || !matches!(bytes.get(first_end), Some(b'.')) {
            continue;
        }
        let second_start = first_end + 1;
        if !bytes[second_start..].starts_with(b"eyJ") {
            continue;
        }
        let mut second_end = second_start;
        while bytes
            .get(second_end)
            .is_some_and(|byte| secret_scan_base64url_byte(*byte))
        {
            second_end += 1;
        }
        if second_end - second_start < 8 || !matches!(bytes.get(second_end), Some(b'.')) {
            continue;
        }
        let third_start = second_end + 1;
        let mut third_end = third_start;
        while bytes
            .get(third_end)
            .is_some_and(|byte| secret_scan_base64url_byte(*byte))
        {
            third_end += 1;
        }
        if third_end - third_start >= 16
            && !bytes
                .get(third_end)
                .is_some_and(|byte| secret_scan_base64url_byte(*byte) || *byte == b'.')
            && !secret_scan_is_placeholder(&bytes[start..third_end])
        {
            return true;
        }
    }
    false
}

fn detect_active_surface_secret_rules(bytes: &[u8]) -> BTreeSet<M7ActiveSurfaceSecretRuleV1> {
    let content = String::from_utf8_lossy(bytes);
    let lower = content.to_ascii_lowercase();
    let mut findings = BTreeSet::new();
    if [
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "-----begin ec private key-----",
        "-----begin openssh private key-----",
        "-----begin encrypted private key-----",
        "-----begin dsa private key-----",
        "-----begin pgp private key block-----",
    ]
    .into_iter()
    .any(|header| lower.contains(header))
    {
        findings.insert(M7ActiveSurfaceSecretRuleV1::PrivateKeyHeader);
    }
    if secret_scan_contains_authorization_credential(bytes) {
        findings.insert(M7ActiveSurfaceSecretRuleV1::AuthorizationCredential);
    }
    if secret_scan_contains_uri_userinfo(bytes) {
        findings.insert(M7ActiveSurfaceSecretRuleV1::UriAuthorityUserinfo);
    }
    if secret_scan_contains_assignment(&content) {
        findings.insert(M7ActiveSurfaceSecretRuleV1::SecretBearingAssignment);
    }
    if secret_scan_contains_provider_cloud_token(bytes) {
        findings.insert(M7ActiveSurfaceSecretRuleV1::ProviderCloudTokenPrefix);
    }
    if secret_scan_contains_compact_jwt(bytes) {
        findings.insert(M7ActiveSurfaceSecretRuleV1::CompactJwt);
    }
    findings
}

fn derive_publication_controls(
    active_truth: &M7ActiveTruthV1,
    claim_catalog: &M7ClaimCatalogV1,
    secret_scan: &M7ActiveSurfaceSecretScanV1,
    publication_policy: &PublicationPolicyRecord,
) -> BTreeSet<M7PublicationControlV1> {
    let caveats = publication_policy
        .required_caveats
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut controls = BTreeSet::new();
    if secret_scan.finding_count() == 0 && caveats.contains("secrets:redacted") {
        controls.insert(M7PublicationControlV1::RedactSecrets);
    }
    if active_truth.historical_phase04_scope
        == M7HistoricalPhase04ScopeV1::HistoricalRecordCompletenessOnly
        && active_truth.historical_lineage_decision == NorthStarClosureDecision::Closed
        && caveats.contains("scope:historical-record-completeness-only")
        && caveats.contains("status-authority:notes/ROADMAP.md")
        && caveats.contains("m7-authority:notes/M7-CLOSURE-OPERATIONS.md")
        && caveats.contains("phase04-is-not-current-m7-source-capture-or-independent-review")
    {
        controls.insert(M7PublicationControlV1::LabelHistoricalPhase04);
    }
    if active_truth.operational_decision == M7ClosureDecision::NotYet
        && caveats.contains("operational-decision:NotYet")
    {
        controls.insert(M7PublicationControlV1::OutcomeNeutralBeforeClosure);
    }
    if active_truth.federation_posture == M7FederationPostureV1::BoundedLocalFirstNoPublicFederation
        && claim_catalog
            .forbidden_claim_ids()
            .contains(&M7ClaimIdV1::PublicFederation)
        && !claim_catalog
            .allowed_claim_ids()
            .contains(&M7ClaimIdV1::PublicFederation)
        && caveats.contains("scope:bounded-local-first-no-public-federation")
    {
        controls.insert(M7PublicationControlV1::PreserveBoundedLocalFirstScope);
    }
    controls
}

#[cfg(test)]
fn fixture_active_surface_capture(
    role: M7ActiveSurfaceRoleV1,
    bytes: Vec<u8>,
) -> Result<M7ActiveSurfaceCaptureV1, M7FoundationError> {
    let sequence = role.observation_sequence() as u64;
    let observation = if role.is_http_surface() {
        M7ActiveSurfaceObservationV1::http_get(
            role,
            "http://127.0.0.1:65535".to_string(),
            "127.0.0.1:65535".to_string(),
            "HTTP/1.1".to_string(),
            sequence,
            sequence,
            &bytes,
        )?
    } else {
        let canonical_path = match role {
            M7ActiveSurfaceRoleV1::RootReadme => "/wasm-biotic-fixture/README.md",
            M7ActiveSurfaceRoleV1::Roadmap => "/wasm-biotic-fixture/notes/ROADMAP.md",
            _ => unreachable!("HTTP roles were handled above"),
        };
        M7ActiveSurfaceObservationV1::local_authority(
            role,
            canonical_path.to_string(),
            sequence,
            sequence,
            &bytes,
        )?
    };
    M7ActiveSurfaceCaptureV1::from_observation(role, bytes, observation)
}

fn observed_service_surface_digest(
    surfaces: &[M7ActiveSurfaceCaptureV1],
) -> Result<ContentDigest, M7FoundationError> {
    let observations = surfaces
        .iter()
        .filter(|surface| surface.role.is_http_surface())
        .map(|surface| {
            (
                surface.role,
                surface.observation.sequence,
                surface.observation.observed_started_at_ms,
                surface.observation.observed_completed_at_ms,
                surface.observation.observation_digest.clone(),
                surface.content_digest.clone(),
                surface.byte_length,
            )
        })
        .collect::<Vec<_>>();
    if observations.len() != 5 {
        return Err(M7FoundationError::InvalidSource(
            "active-surface snapshot must bind exactly five HTTP observations".to_string(),
        ));
    }
    digest(&(OBSERVED_SERVICE_SURFACE_DOMAIN, observations))
}

/// One exact, self-contained snapshot of every active operator truth surface.
/// The same canonical snapshot is embedded in M0, ClaimBoundary, and
/// PublicationPolicy sources, and the evaluator requires their digests to
/// agree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ActiveSurfaceSnapshotV1 {
    schema: String,
    surfaces: Vec<M7ActiveSurfaceCaptureV1>,
    capture_policy_digest: ContentDigest,
    observed_service_surface_digest: ContentDigest,
    active_truth: M7ActiveTruthV1,
    claim_catalog: M7ClaimCatalogV1,
    secret_scan: M7ActiveSurfaceSecretScanV1,
    publication_controls: BTreeSet<M7PublicationControlV1>,
    publication_controls_digest: ContentDigest,
    snapshot_digest: ContentDigest,
}

impl M7ActiveSurfaceSnapshotV1 {
    /// Deterministic fixture constructor. Production capture is exclusively
    /// the operator's `active-surfaces capture` loopback transport boundary.
    #[cfg(test)]
    pub(crate) fn from_fixture_surface_bytes(
        input: M7ActiveSurfaceInputBytesV1,
    ) -> Result<Self, M7FoundationError> {
        let surfaces = vec![
            fixture_active_surface_capture(M7ActiveSurfaceRoleV1::RootReadme, input.root_readme)?,
            fixture_active_surface_capture(M7ActiveSurfaceRoleV1::Roadmap, input.roadmap)?,
            fixture_active_surface_capture(
                M7ActiveSurfaceRoleV1::SystemOverview,
                input.system_overview,
            )?,
            fixture_active_surface_capture(
                M7ActiveSurfaceRoleV1::GeneralAudienceHome,
                input.general_audience_home,
            )?,
            fixture_active_surface_capture(
                M7ActiveSurfaceRoleV1::NorthStar07ClosureReview,
                input.northstar_07_closure_review,
            )?,
            fixture_active_surface_capture(
                M7ActiveSurfaceRoleV1::RemediationPhase04FinalClosureRereview,
                input.remediation_phase_04_final_closure_rereview,
            )?,
            fixture_active_surface_capture(
                M7ActiveSurfaceRoleV1::RemediationPhase04PublicationPolicy,
                input.remediation_phase_04_publication_policy,
            )?,
        ];
        Self::from_observed_surfaces(surfaces)
    }

    pub(crate) fn from_observed_surfaces(
        mut surfaces: Vec<M7ActiveSurfaceCaptureV1>,
    ) -> Result<Self, M7FoundationError> {
        let claim_catalog = bounded_claim_catalog()?;
        let publication_controls = required_publication_controls();
        let publication_controls_digest =
            digest(&(PUBLICATION_CONTROLS_DOMAIN, &publication_controls))?;
        surfaces.sort_by_key(|capture| capture.role);
        let capture_policy_digest = m7_active_surface_capture_policy_digest()?;
        let observed_service_surface_digest = observed_service_surface_digest(&surfaces)?;
        let secret_scan = M7ActiveSurfaceSecretScanV1::scan(&surfaces)?;
        if secret_scan.finding_count() != 0 {
            return Err(M7FoundationError::InvalidSource(format!(
                "active-surface secret scan found {} credential-bearing rule match(es)",
                secret_scan.finding_count()
            )));
        }
        let readme = surfaces
            .iter()
            .find(|capture| capture.role == M7ActiveSurfaceRoleV1::RootReadme)
            .ok_or_else(|| {
                M7FoundationError::InvalidSource(
                    "active surface snapshot is missing README.md".to_string(),
                )
            })?;
        let active_truth = extract_active_truth_block(readme.content_bytes(), &claim_catalog)?;
        let mut value = Self {
            schema: M7_ACTIVE_SURFACE_SNAPSHOT_SCHEMA.to_string(),
            surfaces,
            capture_policy_digest,
            observed_service_surface_digest,
            active_truth,
            claim_catalog,
            secret_scan,
            publication_controls,
            publication_controls_digest,
            snapshot_digest: ContentDigest::from_bytes(&[]),
        };
        value.validate_fields()?;
        value.snapshot_digest = value.expected_digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M7FoundationError> {
        parse_source_record(bytes, |value: &Self| value.validate())
    }

    pub fn snapshot_digest(&self) -> &ContentDigest {
        &self.snapshot_digest
    }

    pub fn capture_policy_digest(&self) -> &ContentDigest {
        &self.capture_policy_digest
    }

    /// Integrity digest over the five sequential HTTP observations. This
    /// binds what the operator observed; it is not a server-identity proof.
    pub fn observed_service_surface_digest(&self) -> &ContentDigest {
        &self.observed_service_surface_digest
    }

    pub fn active_truth(&self) -> &M7ActiveTruthV1 {
        &self.active_truth
    }

    pub fn claim_catalog(&self) -> &M7ClaimCatalogV1 {
        &self.claim_catalog
    }

    pub fn publication_controls(&self) -> &BTreeSet<M7PublicationControlV1> {
        &self.publication_controls
    }

    pub fn secret_scan(&self) -> &M7ActiveSurfaceSecretScanV1 {
        &self.secret_scan
    }

    pub fn publication_controls_digest(&self) -> &ContentDigest {
        &self.publication_controls_digest
    }

    pub fn surfaces(&self) -> &[M7ActiveSurfaceCaptureV1] {
        &self.surfaces
    }

    pub fn surface(&self, role: M7ActiveSurfaceRoleV1) -> Option<&M7ActiveSurfaceCaptureV1> {
        self.surfaces.iter().find(|surface| surface.role == role)
    }

    fn validate(&self) -> Result<(), M7FoundationError> {
        self.validate_fields()?;
        require_digest(
            "M7 active-surface snapshot",
            &self.snapshot_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M7FoundationError> {
        if self.schema != M7_ACTIVE_SURFACE_SNAPSHOT_SCHEMA
            || self.surfaces.is_empty()
            || self
                .surfaces
                .iter()
                .map(|surface| surface.content.len())
                .sum::<usize>()
                > MAX_ACTIVE_SURFACE_SNAPSHOT_BYTES
            || self.capture_policy_digest != m7_active_surface_capture_policy_digest()?
            || self.observed_service_surface_digest
                != observed_service_surface_digest(&self.surfaces)?
            || self.publication_controls != required_publication_controls()
            || self.publication_controls_digest
                != digest(&(PUBLICATION_CONTROLS_DOMAIN, &self.publication_controls))?
        {
            return Err(M7FoundationError::InvalidSource(
                "active-surface snapshot schema, bounds, or publication controls are invalid"
                    .to_string(),
            ));
        }
        validate_claim_catalog(&self.claim_catalog)?;
        self.active_truth.validate(&self.claim_catalog)?;
        self.secret_scan.validate(&self.surfaces)?;
        if self.secret_scan.finding_count() != 0 {
            return Err(M7FoundationError::InvalidSource(
                "active-surface snapshot contains a secret-scan finding".to_string(),
            ));
        }

        let mut roles = BTreeSet::new();
        let mut previous = None;
        let mut previous_completed_at_ms = 0;
        for surface in &self.surfaces {
            surface.validate()?;
            if !roles.insert(surface.role)
                || previous.is_some_and(|role| role > surface.role)
                || surface.observation.sequence != surface.role.observation_sequence()
                || surface.observation.observed_started_at_ms < previous_completed_at_ms
            {
                return Err(M7FoundationError::InvalidSource(
                    "active-surface captures are duplicated, noncanonical, or not sequentially observed"
                        .to_string(),
                ));
            }
            previous = Some(surface.role);
            previous_completed_at_ms = surface.observation.observed_completed_at_ms;
        }
        if roles != required_active_surface_roles() {
            return Err(M7FoundationError::InvalidSource(
                "active-surface snapshot does not contain the exact required role set".to_string(),
            ));
        }

        let readme_truth = extract_active_truth_block(
            self.required_surface(M7ActiveSurfaceRoleV1::RootReadme)?
                .content_bytes(),
            &self.claim_catalog,
        )?;
        let roadmap_truth = extract_active_truth_block(
            self.required_surface(M7ActiveSurfaceRoleV1::Roadmap)?
                .content_bytes(),
            &self.claim_catalog,
        )?;
        if readme_truth != roadmap_truth || readme_truth != self.active_truth {
            return Err(M7FoundationError::InvalidSource(
                "README and ROADMAP active-truth blocks are absent, noncanonical, or different"
                    .to_string(),
            ));
        }
        self.validate_operator_projections()
    }

    fn required_surface(
        &self,
        role: M7ActiveSurfaceRoleV1,
    ) -> Result<&M7ActiveSurfaceCaptureV1, M7FoundationError> {
        self.surface(role).ok_or_else(|| {
            M7FoundationError::InvalidSource(format!("active-surface snapshot is missing {role:?}"))
        })
    }

    fn validate_operator_projections(&self) -> Result<(), M7FoundationError> {
        let overview: SystemOverviewView =
            parse_exact_http_json(self.required_surface(M7ActiveSurfaceRoleV1::SystemOverview)?)?;
        let home: GeneralAudienceHomeView = parse_exact_http_json(
            self.required_surface(M7ActiveSurfaceRoleV1::GeneralAudienceHome)?,
        )?;
        let northstar: NorthStar07ClosureReviewView = parse_exact_http_json(
            self.required_surface(M7ActiveSurfaceRoleV1::NorthStar07ClosureReview)?,
        )?;
        let phase04: RemediationPhase04FinalClosureRereviewView = parse_exact_http_json(
            self.required_surface(M7ActiveSurfaceRoleV1::RemediationPhase04FinalClosureRereview)?,
        )?;
        let publication_policy: PublicationPolicyRecord = parse_exact_http_json(
            self.required_surface(M7ActiveSurfaceRoleV1::RemediationPhase04PublicationPolicy)?,
        )?;
        northstar.claim_boundary.validate().map_err(|error| {
            M7FoundationError::InvalidSource(format!(
                "active NorthStar07 claim boundary is invalid: {error}"
            ))
        })?;
        northstar.publication_policy.validate().map_err(|error| {
            M7FoundationError::InvalidSource(format!(
                "active NorthStar07 publication policy is invalid: {error}"
            ))
        })?;
        publication_policy.validate().map_err(|error| {
            M7FoundationError::InvalidSource(format!(
                "active Phase04 publication policy is invalid: {error}"
            ))
        })?;

        let readme = self.required_surface(M7ActiveSurfaceRoleV1::RootReadme)?;
        let roadmap = self.required_surface(M7ActiveSurfaceRoleV1::Roadmap)?;
        for authority in [
            &overview.operator_truth_surfaces,
            &home.operator_truth_surfaces,
            &northstar.operator_truth_surfaces,
            &phase04.operator_truth_surfaces,
        ] {
            validate_operator_truth_authority(authority, readme, roadmap, &self.claim_catalog)?;
        }
        if [
            overview.status_authority_ref.as_str(),
            home.status_authority_ref.as_str(),
            northstar.status_authority_ref.as_str(),
            phase04.status_authority_ref.as_str(),
        ]
        .into_iter()
        .any(|authority| authority != self.active_truth.roadmap_status_authority)
        {
            return Err(M7FoundationError::InvalidSource(
                "active operator projections disagree on the ROADMAP status authority".to_string(),
            ));
        }
        if [
            overview.operational_north_star_decision,
            home.operational_north_star_decision,
            northstar.operational_decision,
            phase04.operational_decision,
        ]
        .into_iter()
        .any(|decision| decision != NorthStarClosureDecision::NotYet)
            || self.active_truth.operational_decision != M7ClosureDecision::NotYet
            || self.active_truth.historical_lineage_decision != NorthStarClosureDecision::Closed
            || phase04.historical_lineage_decision != self.active_truth.historical_lineage_decision
            || northstar.decision.decision != self.active_truth.historical_lineage_decision
            || northstar.review_scope != "historical_record_completeness"
            || phase04.review_scope != "historical_record_completeness"
            || phase04.decision_posture != "HistoricalClosed"
            || northstar.is_remediated_current_review
            || phase04.northstar07 != northstar
        {
            return Err(M7FoundationError::InvalidSource(
                "active operator projections do not preserve the typed historical Closed/current NotYet boundary"
                    .to_string(),
            ));
        }

        let allowed_claims = &northstar.claim_boundary.allowed_claims;
        let forbidden_claims = &northstar.claim_boundary.forbidden_claims;
        if allowed_claims.is_empty()
            || forbidden_claims.is_empty()
            || northstar.claim_boundary.claim_catalog != self.claim_catalog
            || northstar.publication_policy.claim_catalog != self.claim_catalog
            || publication_policy.claim_catalog != self.claim_catalog
            || phase04.claim_catalog != self.claim_catalog
            || northstar.publication_policy != publication_policy
            || phase04.northstar07.publication_policy != publication_policy
            || northstar.publication_policy.publication_controls != self.publication_controls
            || publication_policy.publication_controls != self.publication_controls
            || phase04.publication_controls != self.publication_controls
            || &northstar.publication_policy.allowed_claims != allowed_claims
            || &northstar.publication_policy.forbidden_claims != forbidden_claims
            || &phase04.allowed_claims != allowed_claims
            || &phase04.forbidden_claims != forbidden_claims
        {
            return Err(M7FoundationError::InvalidSource(
                "claim-boundary and publication-policy projections are not exact crosslinks"
                    .to_string(),
            ));
        }
        let derived_controls = derive_publication_controls(
            &self.active_truth,
            &self.claim_catalog,
            &self.secret_scan,
            &publication_policy,
        );
        if derived_controls != self.publication_controls {
            return Err(M7FoundationError::InvalidSource(
                "publication controls are not derived from the exact policy caveats, active truth, typed claims, and secret scan"
                    .to_string(),
            ));
        }

        let expected_truth = M7ActiveTruthV1::bounded_local_first(&self.claim_catalog)?;
        if self.active_truth != expected_truth
            || self
                .claim_catalog
                .allowed_claim_ids()
                .contains(&M7ClaimIdV1::PublicFederation)
            || !self
                .claim_catalog
                .forbidden_claim_ids()
                .contains(&M7ClaimIdV1::PublicFederation)
        {
            return Err(M7FoundationError::InvalidSource(
                "active truth or typed claim catalog permits a public-federation claim".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            ACTIVE_SURFACE_SNAPSHOT_DOMAIN,
            M7_ACTIVE_SURFACE_SNAPSHOT_SCHEMA,
            &self.surfaces,
            &self.capture_policy_digest,
            &self.observed_service_surface_digest,
            &self.active_truth,
            &self.claim_catalog,
            &self.secret_scan,
            &self.publication_controls,
            &self.publication_controls_digest,
        ))
    }
}

fn extract_active_truth_block(
    markdown_bytes: &[u8],
    catalog: &M7ClaimCatalogV1,
) -> Result<M7ActiveTruthV1, M7FoundationError> {
    let markdown = std::str::from_utf8(markdown_bytes).map_err(|_| {
        M7FoundationError::InvalidSource(
            "active-truth Markdown surface is not exact UTF-8".to_string(),
        )
    })?;
    let begin_positions = markdown
        .match_indices(M7_ACTIVE_TRUTH_BLOCK_BEGIN)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let end_positions = markdown
        .match_indices(M7_ACTIVE_TRUTH_BLOCK_END)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if begin_positions.len() != 1 || end_positions.len() != 1 {
        return Err(M7FoundationError::InvalidSource(
            "Markdown authority must contain exactly one delimited active-truth block".to_string(),
        ));
    }
    let content_start = begin_positions[0] + M7_ACTIVE_TRUTH_BLOCK_BEGIN.len();
    let content_end = end_positions[0];
    if content_start >= content_end {
        return Err(M7FoundationError::InvalidSource(
            "active-truth block delimiters are reversed or empty".to_string(),
        ));
    }
    let delimited = &markdown.as_bytes()[content_start..content_end];
    let json_bytes = delimited
        .strip_prefix(b"\n")
        .and_then(|bytes| bytes.strip_suffix(b"\n"))
        .ok_or_else(|| {
            M7FoundationError::InvalidSource(
                "active-truth JSON must be separated from both delimiters by exactly one LF"
                    .to_string(),
            )
        })?;
    if json_bytes.contains(&b'\n') || json_bytes.contains(&b'\r') {
        return Err(M7FoundationError::InvalidSource(
            "active-truth JSON must be one compact canonical line".to_string(),
        ));
    }
    M7ActiveTruthV1::from_canonical_bytes(json_bytes, catalog)
}

fn parse_exact_http_json<T>(capture: &M7ActiveSurfaceCaptureV1) -> Result<T, M7FoundationError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_slice(capture.content_bytes()).map_err(|error| {
        M7FoundationError::InvalidSource(format!(
            "active HTTP surface {:?} is malformed: {error}",
            capture.role
        ))
    })?;
    if compact_json(&value)? != capture.content_bytes() {
        return Err(M7FoundationError::InvalidSource(format!(
            "active HTTP surface {:?} is not its exact canonical response bytes",
            capture.role
        )));
    }
    Ok(value)
}

fn validate_operator_truth_authority(
    authority: &OperatorTruthSurfaceAuthorityView,
    readme: &M7ActiveSurfaceCaptureV1,
    roadmap: &M7ActiveSurfaceCaptureV1,
    claim_catalog: &M7ClaimCatalogV1,
) -> Result<(), M7FoundationError> {
    if authority.root_readme_ref != readme.path
        || authority.root_readme_digest != readme.content_digest
        || authority.roadmap_ref != roadmap.path
        || authority.roadmap_digest != roadmap.content_digest
        || &authority.claim_catalog != claim_catalog
    {
        return Err(M7FoundationError::InvalidSource(
            "operator projection is not bound to the exact README, ROADMAP, and typed claim catalog"
                .to_string(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7TruthBoundarySourceV3 {
    schema: String,
    active_surface_snapshot: M7ActiveSurfaceSnapshotV1,
    record_digest: ContentDigest,
}

impl M7TruthBoundarySourceV3 {
    pub fn new(
        active_surface_snapshot: M7ActiveSurfaceSnapshotV1,
    ) -> Result<Self, M7FoundationError> {
        let mut value = Self {
            schema: M7_TRUTH_BOUNDARY_SOURCE_SCHEMA.to_string(),
            active_surface_snapshot,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        value.record_digest = value.expected_digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        self.validate()?;
        canonical_json(self)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M7FoundationError> {
        parse_source_record(bytes, |value: &Self| value.validate())
    }

    pub fn active_surface_snapshot(&self) -> &M7ActiveSurfaceSnapshotV1 {
        &self.active_surface_snapshot
    }

    fn validate(&self) -> Result<(), M7FoundationError> {
        self.active_surface_snapshot.validate()?;
        if self.schema != M7_TRUTH_BOUNDARY_SOURCE_SCHEMA
            || self.record_digest != self.expected_digest()?
        {
            return Err(M7FoundationError::InvalidSource(
                "truth-boundary source does not bind the exact active-surface snapshot".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            SOURCE_RECORD_DOMAIN,
            M7_TRUTH_BOUNDARY_SOURCE_SCHEMA,
            &self.active_surface_snapshot,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ClaimBoundarySourceV3 {
    schema: String,
    active_surface_snapshot: M7ActiveSurfaceSnapshotV1,
    record_digest: ContentDigest,
}

impl M7ClaimBoundarySourceV3 {
    pub fn new(
        active_surface_snapshot: M7ActiveSurfaceSnapshotV1,
    ) -> Result<Self, M7FoundationError> {
        let mut value = Self {
            schema: M7_CLAIM_BOUNDARY_SOURCE_SCHEMA.to_string(),
            active_surface_snapshot,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        value.record_digest = value.expected_digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        self.validate()?;
        canonical_json(self)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M7FoundationError> {
        parse_source_record(bytes, |value: &Self| value.validate())
    }

    pub fn active_surface_snapshot(&self) -> &M7ActiveSurfaceSnapshotV1 {
        &self.active_surface_snapshot
    }

    fn validate(&self) -> Result<(), M7FoundationError> {
        self.active_surface_snapshot.validate()?;
        if self.schema != M7_CLAIM_BOUNDARY_SOURCE_SCHEMA
            || self.record_digest != self.expected_digest()?
        {
            return Err(M7FoundationError::InvalidSource(
                "claim-boundary source does not bind the exact active-surface snapshot".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            SOURCE_RECORD_DOMAIN,
            M7_CLAIM_BOUNDARY_SOURCE_SCHEMA,
            &self.active_surface_snapshot,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7PublicationPolicySourceV3 {
    schema: String,
    active_surface_snapshot: M7ActiveSurfaceSnapshotV1,
    record_digest: ContentDigest,
}

impl M7PublicationPolicySourceV3 {
    pub fn new(
        active_surface_snapshot: M7ActiveSurfaceSnapshotV1,
    ) -> Result<Self, M7FoundationError> {
        let mut value = Self {
            schema: M7_PUBLICATION_POLICY_SOURCE_SCHEMA.to_string(),
            active_surface_snapshot,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        value.record_digest = value.expected_digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        self.validate()?;
        canonical_json(self)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M7FoundationError> {
        parse_source_record(bytes, |value: &Self| value.validate())
    }

    pub fn active_surface_snapshot(&self) -> &M7ActiveSurfaceSnapshotV1 {
        &self.active_surface_snapshot
    }

    fn validate(&self) -> Result<(), M7FoundationError> {
        self.active_surface_snapshot.validate()?;
        if self.schema != M7_PUBLICATION_POLICY_SOURCE_SCHEMA
            || self.record_digest != self.expected_digest()?
        {
            return Err(M7FoundationError::InvalidSource(
                "publication-policy source does not bind the exact active-surface snapshot"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            SOURCE_RECORD_DOMAIN,
            M7_PUBLICATION_POLICY_SOURCE_SCHEMA,
            &self.active_surface_snapshot,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7CargoTestTranscriptV2 {
    schema: String,
    pub command: Vec<String>,
    pub source_manifest_digest: ContentDigest,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    record_digest: ContentDigest,
}

impl M7CargoTestTranscriptV2 {
    pub fn new(
        command: Vec<String>,
        source_manifest_digest: ContentDigest,
        stdout: String,
        stderr: String,
        exit_code: i32,
    ) -> Result<Self, M7FoundationError> {
        let mut value = Self {
            schema: M7_CARGO_TEST_TRANSCRIPT_SCHEMA.to_string(),
            command,
            source_manifest_digest,
            stdout,
            stderr,
            exit_code,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        value.record_digest = value.expected_digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        self.validate()?;
        canonical_json(self)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M7FoundationError> {
        parse_source_record(bytes, |value: &Self| value.validate())
    }

    fn validate(&self) -> Result<(), M7FoundationError> {
        let total = self.stdout.len().saturating_add(self.stderr.len());
        if self.schema != M7_CARGO_TEST_TRANSCRIPT_SCHEMA
            || !self
                .command
                .iter()
                .map(String::as_str)
                .eq(M7_DETERMINISTIC_CARGO_TEST_COMMAND.iter().copied())
            || total == 0
            || total > M7_MAX_TRANSCRIPT_CONTENT_BYTES
            || self.record_digest != self.expected_digest()?
        {
            return Err(M7FoundationError::InvalidSource(
                "cargo test transcript must use exactly `cargo test --locked --all-targets` and preserve its bounded content seal"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            SOURCE_RECORD_DOMAIN,
            M7_CARGO_TEST_TRANSCRIPT_SCHEMA,
            &self.command,
            &self.source_manifest_digest,
            &self.stdout,
            &self.stderr,
            self.exit_code,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7SourceCaptureScopeV2 {
    FreshCleanRootPinnedToolchainExactSourceInventory,
}

/// Typed reason that the source custodian's signed inventory is not the exact
/// inventory permitted by the frozen proof-run manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum M7SourceCaptureInventoryFailure {
    MissingRole(M7SourceRoleV2),
    UnexpectedRole(M7SourceRoleV2),
    ForbiddenRole(M7SourceRoleV2),
    DuplicateRole(M7SourceRoleV2),
    NonCanonicalOrder,
    RelabeledRole(M7SourceRoleV2),
    CrossRunRole(M7SourceRoleV2),
    StaleManifestRole(M7SourceRoleV2),
    CausalMismatch(M7SourceRoleV2),
    InvalidLink(M7SourceRoleV2),
    LinkMismatch(M7SourceRoleV2),
    AttestationUnavailable,
    AttestationInvalid,
}

fn required_source_capture_roles(manifest: &M7ProofRunManifest) -> BTreeSet<M7SourceRoleV2> {
    let mut roles = BTreeSet::from([
        M7SourceRoleV2::M0TruthBoundary,
        M7SourceRoleV2::M5ExportM1,
        M7SourceRoleV2::SupervisorPreRestart,
        M7SourceRoleV2::SupervisorPostRestart,
        M7SourceRoleV2::M5ExportM3,
        M7SourceRoleV2::M5ExportM4,
        M7SourceRoleV2::M5ExportRollback,
        M7SourceRoleV2::M5FinalPostRollbackProbe,
        M7SourceRoleV2::M6Completion,
        M7SourceRoleV2::CargoTestTranscript,
        M7SourceRoleV2::ClaimBoundary,
        M7SourceRoleV2::PublicationPolicy,
    ]);
    if manifest.live_provider_scope.is_some() {
        roles.insert(M7SourceRoleV2::LiveProviderQualification);
    }
    roles
}

fn source_capture_inventory_failure(
    manifest: &M7ProofRunManifest,
    links: &[M7SourceLinkV2],
) -> Option<M7SourceCaptureInventoryFailure> {
    if links.len() > MAX_SOURCE_LINKS {
        return Some(M7SourceCaptureInventoryFailure::NonCanonicalOrder);
    }
    let expected_roles = required_source_capture_roles(manifest);
    let mut seen = BTreeSet::new();
    let mut previous: Option<(M7SourceRoleV2, ContentDigest)> = None;
    for link in links {
        let role = link.semantic_role;
        if matches!(
            role,
            M7SourceRoleV2::SourceCaptureAttestation | M7SourceRoleV2::IndependentReview
        ) {
            return Some(M7SourceCaptureInventoryFailure::ForbiddenRole(role));
        }
        if !seen.insert(role) {
            return Some(M7SourceCaptureInventoryFailure::DuplicateRole(role));
        }
        let current = (role, link.digest.clone());
        if previous.as_ref().is_some_and(|value| value > &current) {
            return Some(M7SourceCaptureInventoryFailure::NonCanonicalOrder);
        }
        previous = Some(current);
        if !expected_roles.contains(&role) {
            return Some(M7SourceCaptureInventoryFailure::UnexpectedRole(role));
        }
        if link.schema != M7_SOURCE_LINK_SCHEMA
            || link.source_kind != role.source_kind()
            || link.source_schema != role.source_schema()
            || role.evidence_kind().expected_causal_kind() != link.causal_subject.kind
        {
            return Some(M7SourceCaptureInventoryFailure::RelabeledRole(role));
        }
        if link.proof_run_id != manifest.proof_run_id {
            return Some(M7SourceCaptureInventoryFailure::CrossRunRole(role));
        }
        if link.manifest_digest != manifest.manifest_digest {
            return Some(M7SourceCaptureInventoryFailure::StaleManifestRole(role));
        }
        if link.causal_subject.proof_chain_digest != manifest.causal_chain_digest {
            return Some(M7SourceCaptureInventoryFailure::CausalMismatch(role));
        }
        let length = usize::try_from(link.byte_length).unwrap_or(usize::MAX);
        if length == 0 || length > MAX_SOURCE_BYTES {
            return Some(M7SourceCaptureInventoryFailure::InvalidLink(role));
        }
    }
    for role in expected_roles {
        if !seen.contains(&role) {
            return Some(M7SourceCaptureInventoryFailure::MissingRole(role));
        }
    }
    None
}

fn canonical_source_capture_inventory(
    manifest: &M7ProofRunManifest,
    links: &[M7SourceLinkV2],
) -> Result<Vec<M7SourceLinkV2>, M7FoundationError> {
    manifest.validate()?;
    let mut canonical = links.to_vec();
    canonical.sort_by(|left, right| {
        (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
    });
    if let Some(failure) = source_capture_inventory_failure(manifest, &canonical) {
        return Err(M7FoundationError::InvalidSource(format!(
            "source-capture inventory is invalid: {failure:?}"
        )));
    }
    Ok(canonical)
}

fn source_capture_inventory_digest(
    links: &[M7SourceLinkV2],
) -> Result<ContentDigest, M7FoundationError> {
    digest(&(SOURCE_CAPTURE_INVENTORY_DOMAIN, links))
}

/// External signature over the exact canonical source-link inventory used for
/// this proof run.
///
/// The inventory is the twelve bounded local-first sources, plus the live
/// provider binding exactly when the manifest freezes that scope. The capture
/// attestation and independent review are deliberately excluded because they
/// are produced after the captured sources and would otherwise be circular.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7SourceCaptureAttestationV2 {
    schema: String,
    proof_run_id: String,
    manifest_digest: ContentDigest,
    capture_identity_digest: ContentDigest,
    source_identity_digest: ContentDigest,
    toolchain_digest: ContentDigest,
    lockfile_digest: ContentDigest,
    scope: M7SourceCaptureScopeV2,
    captured_source_links: Vec<M7SourceLinkV2>,
    source_inventory_digest: ContentDigest,
    captured_at_ms: u64,
    attestation_digest: ContentDigest,
    signature_hex: String,
}

impl M7SourceCaptureAttestationV2 {
    pub fn signing_preimage(
        manifest: &M7ProofRunManifest,
        captured_source_links: &[M7SourceLinkV2],
        captured_at_ms: u64,
    ) -> Result<Vec<u8>, M7FoundationError> {
        let inventory = canonical_source_capture_inventory(manifest, captured_source_links)?;
        let digest = Self::expected_digest_for(manifest, &inventory, captured_at_ms)?;
        Ok(signature_preimage(SOURCE_CAPTURE_SIGNATURE_DOMAIN, &digest))
    }

    pub fn from_external_signature(
        manifest: &M7ProofRunManifest,
        captured_source_links: &[M7SourceLinkV2],
        captured_at_ms: u64,
        signature: &[u8],
    ) -> Result<Self, M7FoundationError> {
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(M7FoundationError::InvalidSource(
                "source-capture Ed25519 signature must contain exactly 64 bytes".to_string(),
            ));
        }
        let inventory = canonical_source_capture_inventory(manifest, captured_source_links)?;
        let mut attestation = Self {
            schema: M7_SOURCE_CAPTURE_ATTESTATION_SCHEMA.to_string(),
            proof_run_id: manifest.proof_run_id.clone(),
            manifest_digest: manifest.manifest_digest.clone(),
            capture_identity_digest: manifest.source_capture_identity.identity_digest.clone(),
            source_identity_digest: digest(&manifest.source_identity)?,
            toolchain_digest: manifest.source_identity.toolchain_digest.clone(),
            lockfile_digest: manifest.source_identity.lockfile_digest.clone(),
            scope: M7SourceCaptureScopeV2::FreshCleanRootPinnedToolchainExactSourceInventory,
            source_inventory_digest: source_capture_inventory_digest(&inventory)?,
            captured_source_links: inventory,
            captured_at_ms,
            attestation_digest: ContentDigest::from_bytes(&[]),
            signature_hex: hex_encode(signature),
        };
        attestation.attestation_digest = Self::expected_digest_for(
            manifest,
            &attestation.captured_source_links,
            captured_at_ms,
        )?;
        attestation.validate_for(manifest)?;
        Ok(attestation)
    }

    pub fn captured_source_links(&self) -> &[M7SourceLinkV2] {
        &self.captured_source_links
    }

    pub fn canonical_bytes(
        &self,
        manifest: &M7ProofRunManifest,
    ) -> Result<Vec<u8>, M7FoundationError> {
        self.validate_for(manifest)?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes_detached(
        bytes: &[u8],
        manifest: &M7ProofRunManifest,
    ) -> Result<Self, M7FoundationError> {
        let value: Self = parse_source_record(bytes, |value: &Self| value.validate_fields())?;
        value.validate_for(manifest)?;
        Ok(value)
    }

    fn from_canonical_bytes_unbound(bytes: &[u8]) -> Result<Self, M7FoundationError> {
        parse_source_record(bytes, |value: &Self| value.validate_fields())
    }

    fn validate_fields(&self) -> Result<(), M7FoundationError> {
        validate_identifier("source-capture proof_run_id", &self.proof_run_id)?;
        let signature =
            hex_decode(&self.signature_hex).map_err(M7FoundationError::InvalidSource)?;
        let mut ordered = self.captured_source_links.clone();
        ordered.sort_by(|left, right| {
            (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
        });
        if self.schema != M7_SOURCE_CAPTURE_ATTESTATION_SCHEMA
            || self.captured_at_ms == 0
            || signature.len() != ED25519_SIGNATURE_BYTES
            || self.captured_source_links.is_empty()
            || self.captured_source_links.len() > MAX_SOURCE_LINKS
            || ordered != self.captured_source_links
            || self.source_inventory_digest
                != source_capture_inventory_digest(&self.captured_source_links)?
        {
            return Err(M7FoundationError::InvalidSource(
                "source-capture attestation has an invalid schema, time, signature, or canonical inventory"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_for(&self, manifest: &M7ProofRunManifest) -> Result<(), M7FoundationError> {
        self.validate_fields()?;
        let inventory = canonical_source_capture_inventory(manifest, &self.captured_source_links)?;
        let expected_digest = Self::expected_digest_for(manifest, &inventory, self.captured_at_ms)?;
        if inventory != self.captured_source_links
            || self.proof_run_id != manifest.proof_run_id
            || self.manifest_digest != manifest.manifest_digest
            || self.capture_identity_digest != manifest.source_capture_identity.identity_digest
            || self.source_identity_digest != digest(&manifest.source_identity)?
            || self.toolchain_digest != manifest.source_identity.toolchain_digest
            || self.lockfile_digest != manifest.source_identity.lockfile_digest
            || self.captured_at_ms <= manifest.run_started_at_ms
            || self.attestation_digest != expected_digest
        {
            return Err(M7FoundationError::InvalidSource(
                "source-capture attestation is stale, unpinned, or outside its exact source-inventory scope"
                    .to_string(),
            ));
        }
        verify_external_signature(
            &manifest.source_capture_identity,
            &signature_preimage(SOURCE_CAPTURE_SIGNATURE_DOMAIN, &self.attestation_digest),
            &self.signature_hex,
            "source-capture",
        )
    }

    fn expected_digest_for(
        manifest: &M7ProofRunManifest,
        captured_source_links: &[M7SourceLinkV2],
        captured_at_ms: u64,
    ) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            SOURCE_CAPTURE_ATTESTATION_DOMAIN,
            &manifest.proof_run_id,
            &manifest.manifest_digest,
            &manifest.source_capture_identity.identity_digest,
            &manifest.source_identity,
            &manifest.source_identity.toolchain_digest,
            &manifest.source_identity.lockfile_digest,
            M7SourceCaptureScopeV2::FreshCleanRootPinnedToolchainExactSourceInventory,
            source_capture_inventory_digest(captured_source_links)?,
            captured_source_links,
            captured_at_ms,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7ReviewerParticipationDeclarationV1 {
    NoImplementationParticipation,
    ImplementationParticipant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7IndependentReviewSourceV2 {
    schema: String,
    pub reviewer_identity: M7ExternalEd25519IdentityV1,
    pub reviewed_manifest_digest: ContentDigest,
    pub reviewed_evidence_set_digest: ContentDigest,
    pub recommendation: M7ClosureDecision,
    pub rationale_digest: ContentDigest,
    pub independence_statement_digest: ContentDigest,
    pub participation_declaration: M7ReviewerParticipationDeclarationV1,
    attestation_digest: ContentDigest,
    signature_hex: String,
}

impl M7IndependentReviewSourceV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn signing_preimage(
        reviewer_identity: &M7ExternalEd25519IdentityV1,
        reviewed_manifest_digest: ContentDigest,
        reviewed_evidence_set_digest: ContentDigest,
        recommendation: M7ClosureDecision,
        rationale_digest: ContentDigest,
        independence_statement_digest: ContentDigest,
    ) -> Result<Vec<u8>, M7FoundationError> {
        reviewer_identity.validate()?;
        let attestation_digest = Self::expected_digest_for(
            reviewer_identity,
            &reviewed_manifest_digest,
            &reviewed_evidence_set_digest,
            recommendation,
            &rationale_digest,
            &independence_statement_digest,
        )?;
        Ok(signature_preimage(
            REVIEWER_ATTESTATION_SIGNATURE_DOMAIN,
            &attestation_digest,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_external_signature(
        reviewer_identity: M7ExternalEd25519IdentityV1,
        reviewed_manifest_digest: ContentDigest,
        reviewed_evidence_set_digest: ContentDigest,
        recommendation: M7ClosureDecision,
        rationale_digest: ContentDigest,
        independence_statement_digest: ContentDigest,
        signature: &[u8],
    ) -> Result<Self, M7FoundationError> {
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(M7FoundationError::InvalidSource(
                "reviewer Ed25519 signature must contain exactly 64 bytes".to_string(),
            ));
        }
        let mut value = Self {
            schema: M7_INDEPENDENT_REVIEW_SOURCE_SCHEMA.to_string(),
            reviewer_identity,
            reviewed_manifest_digest,
            reviewed_evidence_set_digest,
            recommendation,
            rationale_digest,
            independence_statement_digest,
            participation_declaration:
                M7ReviewerParticipationDeclarationV1::NoImplementationParticipation,
            attestation_digest: ContentDigest::from_bytes(&[]),
            signature_hex: hex_encode(signature),
        };
        value.attestation_digest = value.expected_digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes_detached(bytes: &[u8]) -> Result<Self, M7FoundationError> {
        parse_source_record(bytes, |value: &Self| value.validate())
    }

    fn validate(&self) -> Result<(), M7FoundationError> {
        self.reviewer_identity.validate()?;
        let signature =
            hex_decode(&self.signature_hex).map_err(M7FoundationError::InvalidSource)?;
        if self.schema != M7_INDEPENDENT_REVIEW_SOURCE_SCHEMA
            || signature.len() != ED25519_SIGNATURE_BYTES
            || self.participation_declaration
                != M7ReviewerParticipationDeclarationV1::NoImplementationParticipation
            || self.attestation_digest != self.expected_digest()?
        {
            return Err(M7FoundationError::InvalidSource(
                "independent-review attestation has an invalid schema, digest, or signature encoding"
                    .to_string(),
            ));
        }
        verify_external_signature(
            &self.reviewer_identity,
            &signature_preimage(
                REVIEWER_ATTESTATION_SIGNATURE_DOMAIN,
                &self.attestation_digest,
            ),
            &self.signature_hex,
            "reviewer",
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        Self::expected_digest_for(
            &self.reviewer_identity,
            &self.reviewed_manifest_digest,
            &self.reviewed_evidence_set_digest,
            self.recommendation,
            &self.rationale_digest,
            &self.independence_statement_digest,
        )
    }

    fn expected_digest_for(
        reviewer_identity: &M7ExternalEd25519IdentityV1,
        reviewed_manifest_digest: &ContentDigest,
        reviewed_evidence_set_digest: &ContentDigest,
        recommendation: M7ClosureDecision,
        rationale_digest: &ContentDigest,
        independence_statement_digest: &ContentDigest,
    ) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            REVIEWER_ATTESTATION_DOMAIN,
            reviewer_identity,
            reviewed_manifest_digest,
            reviewed_evidence_set_digest,
            recommendation,
            rationale_digest,
            independence_statement_digest,
            M7ReviewerParticipationDeclarationV1::NoImplementationParticipation,
        ))
    }
}

impl M7EvidencePayload {
    pub fn kind(&self) -> M7EvidenceKind {
        match self {
            Self::M0TruthBaseline(_) => M7EvidenceKind::M0TruthBaseline,
            Self::M1CandidateLifecycle(_) => M7EvidenceKind::M1CandidateLifecycle,
            Self::M2SchedulerWakeRestart(_) => M7EvidenceKind::M2SchedulerWakeRestart,
            Self::M3CapabilityEffects(_) => M7EvidenceKind::M3CapabilityEffects,
            Self::M4WorkerEcology(_) => M7EvidenceKind::M4WorkerEcology,
            Self::M5ActivationRollback(_) => M7EvidenceKind::M5ActivationRollback,
            Self::M6FactoryExchange(_) => M7EvidenceKind::M6FactoryExchange,
            Self::DeterministicTestTranscript(_) => M7EvidenceKind::DeterministicTestTranscript,
            Self::ClaimBoundary(_) => M7EvidenceKind::ClaimBoundary,
            Self::PublicationPolicy(_) => M7EvidenceKind::PublicationPolicy,
            Self::IndependentReviewerRecommendation(_) => {
                M7EvidenceKind::IndependentReviewerRecommendation
            }
            Self::LiveProviderQualification(_) => M7EvidenceKind::LiveProviderQualification,
        }
    }

    fn semantic_failure(&self) -> Option<M7SemanticFailure> {
        match self {
            Self::M0TruthBaseline(value)
                if !value.legacy_phase04_historical_only
                    || value.seeded_status_used_as_proof
                    || value.pre_run_operational_decision != M7ClosureDecision::NotYet =>
            {
                Some(M7SemanticFailure::HistoricalTruthUsedAsOperationalProof)
            }
            Self::M1CandidateLifecycle(value)
                if value.incumbent_package_digest == value.candidate_package_digest
                    || !value.mutation_changed_candidate_bytes
                    || !value.build_succeeded
                    || !value.tests_succeeded
                    || !value.proving_succeeded
                    || !value.package_resolved =>
            {
                Some(M7SemanticFailure::CandidateLifecycleIncomplete)
            }
            Self::M2SchedulerWakeRestart(value)
                if !value.future_wake_observed
                    || !value.process_restart_observed
                    || !value.restart_reconstructed
                    || value.missed_wake_count != 0 =>
            {
                Some(M7SemanticFailure::MissedWakeOrRestart)
            }
            Self::M3CapabilityEffects(value)
                if value.required_capability_count == 0
                    || value.successful_receipt_count != value.required_capability_count
                    || !value.all_receipts_resolved
                    || !value.all_attestations_valid
                    || value.generic_bypass_count != 0 =>
            {
                Some(M7SemanticFailure::CapabilityEffectsIncomplete)
            }
            Self::M4WorkerEcology(value)
                if value.required_roles != mandatory_worker_roles()
                    || value.terminal_worker_result_count != value.required_roles.len() as u32
                    || value.receipt_backed_result_count != value.terminal_worker_result_count
                    || value.invented_worker_result_count != 0
                    || !value.synthesis_resolved =>
            {
                Some(M7SemanticFailure::InventedOrIncompleteWorkerResult)
            }
            Self::M5ActivationRollback(value)
                if !value.successor_activated
                    || !value.real_failure_observed
                    || !value.rollback_intent_durable
                    || !value.rollback_completed
                    || !value.state_reference_restored
                    || !value.runtime_behavior_restored
                    || value.incomplete_mutation
                    || value.restored_package_digest != value.incumbent_package_digest
                    || value.successor_package_digest == value.incumbent_package_digest =>
            {
                Some(M7SemanticFailure::RollbackIncomplete)
            }
            Self::M6FactoryExchange(value)
                if value.accepted_exchange_count == 0
                    || value.rejected_or_rolled_back_count == 0
                    || value.accepted_exchange_digest
                        == value.rejected_or_rolled_back_exchange_digest
                    || !value.exact_bytes_verified
                    || !value.sender_lineage_resolved
                    || !value.receiver_proving_resolved
                    || !value.negative_control_suite_passed
                    || !value.replay_rejection_control_passed
                    || !value.revocation_control_passed
                    || !value.receiver_rollback_complete
                    || !value.sender_unchanged
                    || !value.both_factories_restarted
                    || value.acknowledgement_used_as_adoption_evidence =>
            {
                Some(M7SemanticFailure::ExchangeTamperedOrIncomplete)
            }
            Self::M6FactoryExchange(value) if value.unresolved_quarantine_count != 0 => {
                Some(M7SemanticFailure::UnresolvedQuarantine)
            }
            Self::DeterministicTestTranscript(value)
                if !value.clean_root
                    || value.required_test_count == 0
                    || value.executed_test_count == 0
                    || value.executed_test_count != value.required_test_count
                    || value.failed_test_count != 0 =>
            {
                Some(M7SemanticFailure::FailedTests)
            }
            Self::ClaimBoundary(value)
                if value.forbidden_claim_count == 0
                    || value.claim_catalog_version != M7_CLAIM_CATALOG_VERSION
                    || value.allowed_claims_digest == value.forbidden_claims_digest
                    || !value.active_surfaces_aligned
                    || value.public_federation_claimed =>
            {
                Some(M7SemanticFailure::ClaimBoundaryIncomplete)
            }
            Self::PublicationPolicy(value)
                if !value.secrets_redacted
                    || !value.legacy_phase04_labeled_historical
                    || !value.outcome_neutral
                    || !value.bounded_local_first_preserved =>
            {
                Some(M7SemanticFailure::PublicationPolicyUnsafe)
            }
            Self::LiveProviderQualification(value)
                if !value.qualified
                    || !value.transcript_redacted
                    || value.credential_material_in_source
                    || !is_external_https_provider_endpoint(
                        &value.api_base_url,
                        value.endpoint_class,
                    )
                    || !value.terminal_outcome_adopted
                    || value.manifest_validated_at_ms < value.manifest_run_started_at_ms
                    || value.manifest_validated_at_ms >= value.call_started_at_ms
                    || value.call_started_at_ms > value.call_completed_at_ms =>
            {
                Some(M7SemanticFailure::LiveProviderEvidenceUnsafe)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7EvidenceArtifact {
    schema: String,
    kind: M7EvidenceKind,
    owner_milestone: M7Milestone,
    proof_run_id: String,
    manifest_digest: ContentDigest,
    causal_subject: M7CausalSubject,
    source_links: Vec<M7SourceLinkV2>,
    payload: M7EvidencePayload,
}

impl M7EvidenceArtifact {
    /// Internal compatibility seam for negative controls and legacy decoding.
    ///
    /// Artifacts created here contain no authoritative sources and therefore
    /// can never satisfy the source-bound evaluator. Public callers must use
    /// [`Self::derive_from_sources`] or [`Self::unresolved_m6`].
    pub(crate) fn new(
        manifest: &M7ProofRunManifest,
        subject_digest: ContentDigest,
        payload: M7EvidencePayload,
    ) -> Result<Self, M7FoundationError> {
        manifest.validate()?;
        let kind = payload.kind();
        let artifact = Self {
            schema: kind.schema().to_string(),
            kind,
            owner_milestone: kind.owner_milestone(),
            proof_run_id: manifest.proof_run_id.clone(),
            manifest_digest: manifest.manifest_digest.clone(),
            causal_subject: M7CausalSubject {
                kind: kind.expected_causal_kind(),
                subject_digest,
                proof_chain_digest: manifest.causal_chain_digest.clone(),
            },
            source_links: Vec::new(),
            payload,
        };
        artifact.validate_structure()?;
        Ok(artifact)
    }

    /// Derive the one causal subject allowed for an evidence kind and exact
    /// canonical source closure.
    ///
    /// The deterministic-test subject deliberately excludes the later
    /// source-capture attestation. Its subject is therefore independently
    /// available from the exact Cargo transcript before the custodian signs,
    /// while the final artifact still requires and binds that attestation.
    pub fn derive_causal_subject_from_sources(
        manifest: &M7ProofRunManifest,
        kind: M7EvidenceKind,
        inputs: &[M7SourceInputV2],
    ) -> Result<M7CausalSubject, M7FoundationError> {
        manifest.validate()?;
        if inputs.is_empty() || inputs.len() > MAX_SOURCE_LINKS {
            return Err(M7FoundationError::InvalidSource(format!(
                "causal-subject derivation requires 1..={MAX_SOURCE_LINKS} exact sources"
            )));
        }
        let mut roles = BTreeSet::new();
        for input in inputs {
            if input.semantic_role.evidence_kind() != kind || !roles.insert(input.semantic_role) {
                return Err(M7FoundationError::InvalidSource(
                    "source roles are duplicated or belong to another evidence family".to_string(),
                ));
            }
            if input.bytes.is_empty() || input.bytes.len() > MAX_SOURCE_BYTES {
                return Err(M7FoundationError::InvalidSource(
                    "source bytes are empty or outside the source bound".to_string(),
                ));
            }
            if !detect_active_surface_secret_rules(&input.bytes).is_empty() {
                return Err(M7FoundationError::InvalidSource(
                    "source bytes contain credential-shaped material and cannot enter immutable M7 evidence"
                        .to_string(),
                ));
            }
            validate_source_bytes(input.semantic_role, &input.bytes)?;
        }
        let required_roles = causal_subject_source_roles(kind);
        let actual_roles = roles
            .iter()
            .copied()
            .filter(|role| {
                !(kind == M7EvidenceKind::DeterministicTestTranscript
                    && *role == M7SourceRoleV2::SourceCaptureAttestation)
            })
            .collect::<BTreeSet<_>>();
        if actual_roles != required_roles {
            return Err(M7FoundationError::InvalidSource(format!(
                "{kind:?} causal subject requires exact source roles {required_roles:?}, got {actual_roles:?}"
            )));
        }
        let mut source_closure = inputs
            .iter()
            .filter(|input| {
                !(kind == M7EvidenceKind::DeterministicTestTranscript
                    && input.semantic_role == M7SourceRoleV2::SourceCaptureAttestation)
            })
            .map(|input| M7CausalSourceDescriptorV1 {
                semantic_role: input.semantic_role,
                source_schema: input.semantic_role.source_schema().to_string(),
                digest: ContentDigest::from_bytes(&input.bytes),
                byte_length: input.bytes.len() as u64,
            })
            .collect::<Vec<_>>();
        source_closure.sort();
        let subject_digest = digest(&M7CausalSubjectDigestMaterial {
            domain: CAUSAL_SUBJECT_FROM_SOURCES_DOMAIN,
            proof_run_id: &manifest.proof_run_id,
            manifest_digest: &manifest.manifest_digest,
            proof_chain_digest: &manifest.causal_chain_digest,
            evidence_kind: kind,
            source_closure: &source_closure,
        })?;
        Ok(M7CausalSubject {
            kind: kind.expected_causal_kind(),
            subject_digest,
            proof_chain_digest: manifest.causal_chain_digest.clone(),
        })
    }

    pub fn derive_from_sources(
        manifest: &M7ProofRunManifest,
        kind: M7EvidenceKind,
        inputs: Vec<M7SourceInputV2>,
    ) -> Result<M7DerivedEvidenceV2, M7FoundationError> {
        let causal_subject = Self::derive_causal_subject_from_sources(manifest, kind, &inputs)?;
        let mut blobs = Vec::with_capacity(inputs.len());
        let mut resolved = BTreeMap::new();
        for input in inputs {
            let link = M7SourceLinkV2::from_source_bytes(
                manifest,
                causal_subject.clone(),
                input.semantic_role,
                &input.bytes,
            )?;
            resolved.insert(input.semantic_role, input.bytes.clone());
            blobs.push(M7SourceBlobV2 {
                link,
                bytes: input.bytes,
            });
        }
        blobs.sort_by(|left, right| {
            (left.link.semantic_role, &left.link.digest)
                .cmp(&(right.link.semantic_role, &right.link.digest))
        });
        let payload = derive_payload(kind, manifest, &causal_subject, &resolved)?;
        let artifact = Self {
            schema: kind.schema().to_string(),
            kind,
            owner_milestone: kind.owner_milestone(),
            proof_run_id: manifest.proof_run_id.clone(),
            manifest_digest: manifest.manifest_digest.clone(),
            causal_subject,
            source_links: blobs.iter().map(|blob| blob.link.clone()).collect(),
            payload,
        };
        artifact.validate_structure()?;
        Ok(M7DerivedEvidenceV2 {
            artifact,
            source_blobs: blobs,
        })
    }

    /// Explicit unresolved M6 placeholder. It is portable but permanently
    /// evaluates `NotYet`; source-bound M6 evidence must instead be derived
    /// from an exact [`M6CompletionBundleV1`].
    pub fn unresolved_m6(
        manifest: &M7ProofRunManifest,
        subject_digest: ContentDigest,
    ) -> Result<Self, M7FoundationError> {
        Self::new(
            manifest,
            subject_digest,
            M7EvidencePayload::M6FactoryExchange(M6FactoryExchangeEvidence {
                completion_bundle_content_digest: ContentDigest::from_bytes(
                    b"m6-unresolved-completion-bundle",
                ),
                sender_m5_export_bundle_content_digest: ContentDigest::from_bytes(
                    b"m6-unresolved-sender-m5-export",
                ),
                accepted_exchange_digest: ContentDigest::from_bytes(b"m6-unresolved-accepted"),
                rejected_or_rolled_back_exchange_digest: ContentDigest::from_bytes(
                    b"m6-unresolved-rejected",
                ),
                accepted_exchange_count: 0,
                rejected_or_rolled_back_count: 0,
                exact_bytes_verified: false,
                sender_lineage_resolved: false,
                receiver_proving_resolved: false,
                negative_control_suite_passed: false,
                replay_rejection_control_passed: false,
                revocation_control_passed: false,
                unresolved_quarantine_count: 1,
                receiver_rollback_complete: false,
                sender_unchanged: false,
                both_factories_restarted: false,
                acknowledgement_used_as_adoption_evidence: false,
            }),
        )
    }

    pub fn kind(&self) -> M7EvidenceKind {
        self.kind
    }

    pub fn payload(&self) -> &M7EvidencePayload {
        &self.payload
    }

    pub fn manifest_digest(&self) -> &ContentDigest {
        &self.manifest_digest
    }

    pub fn source_links(&self) -> &[M7SourceLinkV2] {
        &self.source_links
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        canonical_json(self)
    }

    pub fn evidence_link(&self) -> Result<M7EvidenceLink, M7FoundationError> {
        self.validate_structure()?;
        let bytes = self.canonical_bytes()?;
        Ok(M7EvidenceLink {
            kind: self.kind,
            owner_milestone: self.owner_milestone,
            proof_run_id: self.proof_run_id.clone(),
            causal_subject: self.causal_subject.clone(),
            digest: ContentDigest::from_bytes(&bytes),
            byte_length: bytes.len() as u64,
        })
    }

    fn validate_structure(&self) -> Result<(), M7FoundationError> {
        if self.schema != self.kind.schema()
            || self.kind != self.payload.kind()
            || self.owner_milestone != self.kind.owner_milestone()
            || self.causal_subject.kind != self.kind.expected_causal_kind()
        {
            return Err(M7FoundationError::InvalidEvidence(
                "evidence schema, kind, owner, causal subject, and payload disagree".to_string(),
            ));
        }
        validate_identifier("evidence proof_run_id", &self.proof_run_id)?;
        if self.source_links.len() > MAX_SOURCE_LINKS {
            return Err(M7FoundationError::InvalidEvidence(
                "evidence exceeds its source-link bound".to_string(),
            ));
        }
        let mut roles = BTreeSet::new();
        let mut previous: Option<(M7SourceRoleV2, ContentDigest)> = None;
        for link in &self.source_links {
            if link.semantic_role.evidence_kind() != self.kind
                || link.causal_subject != self.causal_subject
                || !roles.insert(link.semantic_role)
            {
                return Err(M7FoundationError::InvalidEvidence(
                    "evidence source roles are duplicated, cross-family, or cross-causal"
                        .to_string(),
                ));
            }
            let current = (link.semantic_role, link.digest.clone());
            if previous.as_ref().is_some_and(|value| value > &current) {
                return Err(M7FoundationError::InvalidEvidence(
                    "evidence source links are not canonically ordered".to_string(),
                ));
            }
            previous = Some(current);
        }
        Ok(())
    }
}

fn validate_source_bytes(role: M7SourceRoleV2, bytes: &[u8]) -> Result<(), M7FoundationError> {
    match role {
        M7SourceRoleV2::M0TruthBoundary => {
            M7TruthBoundarySourceV3::from_canonical_bytes(bytes).map(|_| ())
        }
        M7SourceRoleV2::M5ExportM1
        | M7SourceRoleV2::M5ExportM3
        | M7SourceRoleV2::M5ExportM4
        | M7SourceRoleV2::M5ExportRollback => M5ExportBundleV1::from_canonical_bytes(bytes)
            .map(|_| ())
            .map_err(|error| {
                M7FoundationError::InvalidSource(format!("M5 export source is invalid: {error}"))
            }),
        M7SourceRoleV2::M5FinalPostRollbackProbe => {
            M5FinalPostRollbackProbeV1::from_canonical_bytes(bytes)
                .map(|_| ())
                .map_err(|error| {
                    M7FoundationError::InvalidSource(format!(
                        "M5 final post-rollback probe source is invalid: {error}"
                    ))
                })
        }
        M7SourceRoleV2::SupervisorPreRestart | M7SourceRoleV2::SupervisorPostRestart => {
            parse_supervisor_state(bytes).map(|_| ())
        }
        M7SourceRoleV2::M6Completion => M6CompletionBundleV1::from_canonical_bytes(bytes)
            .map(|_| ())
            .map_err(|error| {
                M7FoundationError::InvalidSource(format!(
                    "M6 completion source is invalid: {error}"
                ))
            }),
        M7SourceRoleV2::CargoTestTranscript => {
            let transcript = M7CargoTestTranscriptV2::from_canonical_bytes(bytes)?;
            if !detect_active_surface_secret_rules(transcript.stdout.as_bytes()).is_empty()
                || !detect_active_surface_secret_rules(transcript.stderr.as_bytes()).is_empty()
            {
                return Err(M7FoundationError::InvalidSource(
                    "decoded cargo test transcript contains credential-shaped material".to_string(),
                ));
            }
            Ok(())
        }
        M7SourceRoleV2::SourceCaptureAttestation => {
            M7SourceCaptureAttestationV2::from_canonical_bytes_unbound(bytes).map(|_| ())
        }
        M7SourceRoleV2::ClaimBoundary => {
            M7ClaimBoundarySourceV3::from_canonical_bytes(bytes).map(|_| ())
        }
        M7SourceRoleV2::PublicationPolicy => {
            M7PublicationPolicySourceV3::from_canonical_bytes(bytes).map(|_| ())
        }
        M7SourceRoleV2::IndependentReview => {
            M7IndependentReviewSourceV2::from_canonical_bytes_detached(bytes).map(|_| ())
        }
        M7SourceRoleV2::LiveProviderQualification => {
            M7LiveProviderSourceV1::from_canonical_bytes(bytes)
                .map(|_| ())
                .map_err(|error| {
                    M7FoundationError::InvalidSource(format!(
                        "M7 live-provider source is invalid: {error}"
                    ))
                })
        }
    }
}

fn derive_payload(
    kind: M7EvidenceKind,
    manifest: &M7ProofRunManifest,
    causal_subject: &M7CausalSubject,
    sources: &BTreeMap<M7SourceRoleV2, Vec<u8>>,
) -> Result<M7EvidencePayload, M7FoundationError> {
    let exact_roles: BTreeSet<_> = sources.keys().copied().collect();
    let expected_roles = expected_source_roles(kind);
    if exact_roles != expected_roles {
        return Err(M7FoundationError::InvalidSource(format!(
            "{kind:?} requires exact source roles {expected_roles:?}, got {exact_roles:?}"
        )));
    }
    match kind {
        M7EvidenceKind::M0TruthBaseline => {
            let source = M7TruthBoundarySourceV3::from_canonical_bytes(source_bytes(
                sources,
                M7SourceRoleV2::M0TruthBoundary,
            )?)?;
            let snapshot = source.active_surface_snapshot();
            Ok(M7EvidencePayload::M0TruthBaseline(M0TruthEvidence {
                active_surface_snapshot_digest: snapshot.snapshot_digest().clone(),
                active_truth_digest: snapshot.active_truth().digest()?,
                legacy_phase04_historical_only: snapshot.active_truth().historical_phase04_scope
                    == M7HistoricalPhase04ScopeV1::HistoricalRecordCompletenessOnly,
                seeded_status_used_as_proof: snapshot.active_truth().operational_decision
                    != M7ClosureDecision::NotYet,
                pre_run_operational_decision: snapshot.active_truth().operational_decision,
            }))
        }
        M7EvidenceKind::M1CandidateLifecycle => {
            derive_m1_from_export(source_bytes(sources, M7SourceRoleV2::M5ExportM1)?)
        }
        M7EvidenceKind::M2SchedulerWakeRestart => derive_m2_from_states(
            manifest,
            source_bytes(sources, M7SourceRoleV2::SupervisorPreRestart)?,
            source_bytes(sources, M7SourceRoleV2::SupervisorPostRestart)?,
        ),
        M7EvidenceKind::M3CapabilityEffects => {
            derive_m3_from_export(source_bytes(sources, M7SourceRoleV2::M5ExportM3)?)
        }
        M7EvidenceKind::M4WorkerEcology => {
            derive_m4_from_export(source_bytes(sources, M7SourceRoleV2::M5ExportM4)?)
        }
        M7EvidenceKind::M5ActivationRollback => derive_m5_from_export_and_probe(
            manifest,
            source_bytes(sources, M7SourceRoleV2::M5ExportRollback)?,
            source_bytes(sources, M7SourceRoleV2::M5FinalPostRollbackProbe)?,
        ),
        M7EvidenceKind::M6FactoryExchange => {
            let completion_bytes = source_bytes(sources, M7SourceRoleV2::M6Completion)?;
            let bundle =
                M6CompletionBundleV1::from_canonical_bytes(completion_bytes).map_err(|error| {
                    M7FoundationError::InvalidSource(format!(
                        "M6 completion source is invalid: {error}"
                    ))
                })?;
            let facts = bundle.derived();
            let sender_m5_export_bundle_content_digest = bundle
                .sender_m5_export_bundle_content_digest()
                .map_err(|error| {
                    M7FoundationError::InvalidSource(format!(
                        "M6 sender M5 export identity is invalid: {error}"
                    ))
                })?;
            Ok(M7EvidencePayload::M6FactoryExchange(
                M6FactoryExchangeEvidence {
                    completion_bundle_content_digest: ContentDigest::from_bytes(completion_bytes),
                    sender_m5_export_bundle_content_digest,
                    accepted_exchange_digest: facts.accepted_exchange_digest().clone(),
                    rejected_or_rolled_back_exchange_digest: facts
                        .rejected_or_rolled_back_exchange_digest()
                        .clone(),
                    accepted_exchange_count: facts.accepted_exchange_count(),
                    rejected_or_rolled_back_count: facts.rejected_or_rolled_back_count(),
                    exact_bytes_verified: facts.exact_bytes_verified(),
                    sender_lineage_resolved: facts.sender_lineage_resolved(),
                    receiver_proving_resolved: facts.receiver_proving_resolved(),
                    negative_control_suite_passed: facts.negative_control_suite_passed(),
                    replay_rejection_control_passed: facts.replay_rejection_control_passed(),
                    revocation_control_passed: facts.revocation_control_passed(),
                    unresolved_quarantine_count: facts.unresolved_quarantine_count(),
                    receiver_rollback_complete: facts.receiver_rejection_or_rollback_complete(),
                    sender_unchanged: facts.sender_unchanged(),
                    both_factories_restarted: facts.both_factories_restarted(),
                    acknowledgement_used_as_adoption_evidence: facts
                        .acknowledgement_used_as_adoption_evidence(),
                },
            ))
        }
        M7EvidenceKind::DeterministicTestTranscript => derive_test_transcript(
            manifest,
            causal_subject,
            source_bytes(sources, M7SourceRoleV2::CargoTestTranscript)?,
            source_bytes(sources, M7SourceRoleV2::SourceCaptureAttestation)?,
        ),
        M7EvidenceKind::ClaimBoundary => {
            let source = M7ClaimBoundarySourceV3::from_canonical_bytes(source_bytes(
                sources,
                M7SourceRoleV2::ClaimBoundary,
            )?)?;
            let snapshot = source.active_surface_snapshot();
            let catalog = snapshot.claim_catalog();
            Ok(M7EvidencePayload::ClaimBoundary(ClaimBoundaryEvidence {
                active_surface_snapshot_digest: snapshot.snapshot_digest().clone(),
                claim_catalog_digest: catalog.catalog_digest.clone(),
                claim_catalog_version: catalog.catalog_version.clone(),
                allowed_claims_digest: catalog.allowed_claims_digest().map_err(|error| {
                    M7FoundationError::InvalidSource(format!(
                        "allowed claim catalog digest failed: {error}"
                    ))
                })?,
                forbidden_claims_digest: catalog.forbidden_claims_digest().map_err(|error| {
                    M7FoundationError::InvalidSource(format!(
                        "forbidden claim catalog digest failed: {error}"
                    ))
                })?,
                forbidden_claim_count: u32::try_from(catalog.forbidden_claim_ids().len()).map_err(
                    |_| {
                        M7FoundationError::InvalidSource(
                            "forbidden claim catalog exceeds u32".to_string(),
                        )
                    },
                )?,
                active_surfaces_aligned: snapshot.validate_operator_projections().is_ok(),
                public_federation_claimed: catalog
                    .allowed_claim_ids()
                    .contains(&M7ClaimIdV1::PublicFederation),
            }))
        }
        M7EvidenceKind::PublicationPolicy => {
            let source = M7PublicationPolicySourceV3::from_canonical_bytes(source_bytes(
                sources,
                M7SourceRoleV2::PublicationPolicy,
            )?)?;
            let snapshot = source.active_surface_snapshot();
            let publication_policy_digest = snapshot
                .required_surface(M7ActiveSurfaceRoleV1::RemediationPhase04PublicationPolicy)?
                .content_digest()
                .clone();
            Ok(M7EvidencePayload::PublicationPolicy(
                PublicationPolicyEvidence {
                    active_surface_snapshot_digest: snapshot.snapshot_digest().clone(),
                    publication_controls_digest: snapshot.publication_controls_digest().clone(),
                    publication_policy_digest,
                    secrets_redacted: snapshot
                        .publication_controls()
                        .contains(&M7PublicationControlV1::RedactSecrets)
                        && snapshot.secret_scan().finding_count() == 0,
                    legacy_phase04_labeled_historical: snapshot
                        .publication_controls()
                        .contains(&M7PublicationControlV1::LabelHistoricalPhase04)
                        && snapshot.active_truth().historical_phase04_scope
                            == M7HistoricalPhase04ScopeV1::HistoricalRecordCompletenessOnly
                        && snapshot.active_truth().historical_lineage_decision
                            == NorthStarClosureDecision::Closed,
                    outcome_neutral: snapshot
                        .publication_controls()
                        .contains(&M7PublicationControlV1::OutcomeNeutralBeforeClosure)
                        && snapshot.active_truth().operational_decision
                            == M7ClosureDecision::NotYet,
                    bounded_local_first_preserved: snapshot
                        .publication_controls()
                        .contains(&M7PublicationControlV1::PreserveBoundedLocalFirstScope)
                        && snapshot.active_truth().federation_posture
                            == M7FederationPostureV1::BoundedLocalFirstNoPublicFederation
                        && snapshot
                            .claim_catalog()
                            .forbidden_claim_ids()
                            .contains(&M7ClaimIdV1::PublicFederation)
                        && !snapshot
                            .claim_catalog()
                            .allowed_claim_ids()
                            .contains(&M7ClaimIdV1::PublicFederation),
                },
            ))
        }
        M7EvidenceKind::IndependentReviewerRecommendation => {
            let source = M7IndependentReviewSourceV2::from_canonical_bytes_detached(source_bytes(
                sources,
                M7SourceRoleV2::IndependentReview,
            )?)?;
            Ok(M7EvidencePayload::IndependentReviewerRecommendation(
                IndependentReviewerEvidence {
                    reviewer_id: source.reviewer_identity.principal_id,
                    reviewer_identity_digest: source.reviewer_identity.identity_digest,
                    reviewer_public_key_digest: source.reviewer_identity.public_key_digest,
                    reviewed_manifest_digest: source.reviewed_manifest_digest,
                    reviewed_evidence_set_digest: source.reviewed_evidence_set_digest,
                    recommendation: source.recommendation,
                    rationale_digest: source.rationale_digest,
                    independence_statement_digest: source.independence_statement_digest,
                    participation_declaration: source.participation_declaration,
                },
            ))
        }
        M7EvidenceKind::LiveProviderQualification => {
            let source = M7LiveProviderSourceV1::from_canonical_bytes(source_bytes(
                sources,
                M7SourceRoleV2::LiveProviderQualification,
            )?)
            .map_err(|error| {
                M7FoundationError::InvalidSource(format!(
                    "M7 live-provider source is invalid: {error}"
                ))
            })?;
            let frozen_scope = manifest.live_provider_scope.as_ref().ok_or_else(|| {
                M7FoundationError::InvalidSource(
                    "live-provider source has no separately frozen qualification scope".to_string(),
                )
            })?;
            frozen_scope.validate_post_call_source(&source)?;
            let completed = source.completed_invocation()?;
            completed
                .execution_receipt()
                .validate_for_manifest(
                    manifest,
                    completed.prepared_seed(),
                    completed.challenged_seed(),
                    completed.provider_binding(),
                )
                .map_err(|error| {
                    M7FoundationError::InvalidSource(format!(
                        "provider execution receipt does not prove this manifest-bound call: {error}"
                    ))
                })?;
            let observed_scope =
                LiveProviderQualificationScope::from_prepared(completed.prepared_seed())?;
            let challenged = completed.challenged_seed();
            let binding = completed.provider_binding();
            let execution = completed.execution_receipt();
            let request = challenged.qualification_request();
            let configuration = &request.configuration;
            let turn = binding.qualification.live_turn.as_ref().ok_or_else(|| {
                M7FoundationError::InvalidSource(
                    "qualified provider binding has no exact live turn".to_string(),
                )
            })?;
            let replay = binding.qualification.replay.as_ref().ok_or_else(|| {
                M7FoundationError::InvalidSource(
                    "qualified provider binding has no exact deterministic replay".to_string(),
                )
            })?;
            let terminal_cycle_record_digest = match completed.terminal_outcome() {
                M5ProviderTerminalOutcomeV1::Adopted {
                    cycle_record_digest,
                    ..
                } => Some(cycle_record_digest.clone()),
                _ => None,
            };
            Ok(M7EvidencePayload::LiveProviderQualification(
                LiveProviderQualificationEvidence {
                    scope_digest: observed_scope.scope_digest,
                    proof_run_id: completed.prepared_seed().precommit.proof_run_id.clone(),
                    prepared_at_ms: completed.prepared_seed().precommit.prepared_at_ms,
                    execution_manifest_digest: execution.manifest_digest.clone(),
                    precommit_digest: completed.prepared_seed().precommit.precommit_digest.clone(),
                    prepared_digest: completed.prepared_seed().prepared_digest.clone(),
                    binding_digest: binding.binding_digest.clone(),
                    execution_receipt_digest: execution.receipt_digest.clone(),
                    qualification_record_digest: binding.qualification_record_digest.clone(),
                    provider_id: configuration.provider_id.clone(),
                    model_id: configuration.model_id.clone(),
                    api_base_url: configuration.api_base_url.clone(),
                    endpoint_class: configuration.endpoint_class,
                    qualification_run_id: binding.qualification.qualification_id.clone(),
                    driver_profile_digest: configuration.driver_profile_digest.clone(),
                    configuration_fingerprint: configuration.fingerprint().map_err(|error| {
                        M7FoundationError::InvalidSource(format!(
                            "provider configuration cannot be fingerprinted: {error}"
                        ))
                    })?,
                    response_schema_digest: configuration.response_schema_digest.clone(),
                    prompt_renderer_digest: configuration.prompt_renderer_digest.clone(),
                    tool_catalog_digest: configuration.tool_catalog_digest.clone(),
                    cycle_id: binding.target.cycle_id.clone(),
                    release_gate_digest: binding.target.release_gate_digest.clone(),
                    operator_context_digest: binding.target.operator_context_digest.clone(),
                    incumbent_package_digest: binding.target.incumbent_package_digest.clone(),
                    target_digest: binding.target.target_digest.clone(),
                    request_digest: request.request_digest.clone(),
                    challenged_seed_digest: challenged.challenged_digest().clone(),
                    invocation_challenge_digest: challenged
                        .challenge()
                        .invocation_challenge_digest()
                        .clone(),
                    wire_request_digest: challenged
                        .provider_wire_request()
                        .wire_request_digest()
                        .clone(),
                    request_body_digest: challenged
                        .provider_wire_request()
                        .request_body_digest()
                        .clone(),
                    completed_invocation_digest: completed.completed_invocation_digest().clone(),
                    target_package_digest: binding.target.candidate_package_digest.clone(),
                    qualified: true,
                    transcript_redacted: turn.transcript.redaction_applied,
                    // Every exact source passed the generic credential-shaped
                    // material scan before payload derivation. This claim is
                    // intentionally scoped to the canonical wrapper bytes.
                    credential_material_in_source: false,
                    terminal_outcome_adopted: completed
                        .terminal_outcome()
                        .non_adopted_status()
                        .is_none(),
                    terminal_cycle_record_digest,
                    terminal_outcome_digest: execution.terminal_outcome_digest.clone(),
                    manifest_run_started_at_ms: execution.manifest_run_started_at_ms,
                    manifest_validated_at_ms: execution.manifest_validated_at_ms,
                    call_started_at_ms: execution.call_started_at_ms,
                    call_completed_at_ms: execution.call_completed_at_ms,
                    run_nonce_digest: execution.run_nonce_digest.clone(),
                    deterministic_replay_digest: replay.replay_digest.clone(),
                    parsed_intent_digest: binding.intent_digest.clone(),
                },
            ))
        }
    }
}

fn expected_source_roles(kind: M7EvidenceKind) -> BTreeSet<M7SourceRoleV2> {
    match kind {
        M7EvidenceKind::M0TruthBaseline => BTreeSet::from([M7SourceRoleV2::M0TruthBoundary]),
        M7EvidenceKind::M1CandidateLifecycle => BTreeSet::from([M7SourceRoleV2::M5ExportM1]),
        M7EvidenceKind::M2SchedulerWakeRestart => BTreeSet::from([
            M7SourceRoleV2::SupervisorPreRestart,
            M7SourceRoleV2::SupervisorPostRestart,
        ]),
        M7EvidenceKind::M3CapabilityEffects => BTreeSet::from([M7SourceRoleV2::M5ExportM3]),
        M7EvidenceKind::M4WorkerEcology => BTreeSet::from([M7SourceRoleV2::M5ExportM4]),
        M7EvidenceKind::M5ActivationRollback => BTreeSet::from([
            M7SourceRoleV2::M5ExportRollback,
            M7SourceRoleV2::M5FinalPostRollbackProbe,
        ]),
        M7EvidenceKind::M6FactoryExchange => BTreeSet::from([M7SourceRoleV2::M6Completion]),
        M7EvidenceKind::DeterministicTestTranscript => BTreeSet::from([
            M7SourceRoleV2::CargoTestTranscript,
            M7SourceRoleV2::SourceCaptureAttestation,
        ]),
        M7EvidenceKind::ClaimBoundary => BTreeSet::from([M7SourceRoleV2::ClaimBoundary]),
        M7EvidenceKind::PublicationPolicy => BTreeSet::from([M7SourceRoleV2::PublicationPolicy]),
        M7EvidenceKind::IndependentReviewerRecommendation => {
            BTreeSet::from([M7SourceRoleV2::IndependentReview])
        }
        M7EvidenceKind::LiveProviderQualification => {
            BTreeSet::from([M7SourceRoleV2::LiveProviderQualification])
        }
    }
}

fn causal_subject_source_roles(kind: M7EvidenceKind) -> BTreeSet<M7SourceRoleV2> {
    let mut roles = expected_source_roles(kind);
    if kind == M7EvidenceKind::DeterministicTestTranscript {
        roles.remove(&M7SourceRoleV2::SourceCaptureAttestation);
    }
    roles
}

fn source_bytes(
    sources: &BTreeMap<M7SourceRoleV2, Vec<u8>>,
    role: M7SourceRoleV2,
) -> Result<&[u8], M7FoundationError> {
    sources.get(&role).map(Vec::as_slice).ok_or_else(|| {
        M7FoundationError::InvalidSource(format!("missing exact source role {role:?}"))
    })
}

fn derive_m1_from_export(bytes: &[u8]) -> Result<M7EvidencePayload, M7FoundationError> {
    let bundle = parse_m5_export(bytes)?;
    let cycle = bundle.active_cycle();
    let package =
        FactoryPackage::from_canonical_bytes(bundle.active_package().canonical_package_bytes())
            .map_err(|error| {
                M7FoundationError::InvalidSource(format!(
                    "M5 active package cannot be parsed: {error}"
                ))
            })?;
    let proving = cycle.m1_proving_record();
    if !proving.summary.all_satisfied
        || proving.summary.case_count == 0
        || proving.summary.case_count != proving.summary.satisfied_count
        || proving.component_digest != package.payload.genome.component_digest
        || cycle.m1_evidence().proving_record_digest != proving.record_digest
        || cycle.record().parent_package_digest == package.package_digest
    {
        return Err(M7FoundationError::InvalidSource(
            "M5 export does not prove an exact changed and fully passing M1 candidate".to_string(),
        ));
    }
    Ok(M7EvidencePayload::M1CandidateLifecycle(
        M1CandidateLifecycleEvidence {
            incumbent_package_digest: cycle.record().parent_package_digest.clone(),
            candidate_package_digest: package.package_digest,
            candidate_component_digest: proving.component_digest.clone(),
            mutation_changed_candidate_bytes: true,
            build_succeeded: true,
            tests_succeeded: true,
            proving_succeeded: true,
            package_resolved: true,
        },
    ))
}

fn derive_m3_from_export(bytes: &[u8]) -> Result<M7EvidencePayload, M7FoundationError> {
    let bundle = parse_m5_export(bytes)?;
    let workflows = bundle.active_cycle().m4_workflows();
    let evidence = derive_m3_from_service_evidence(
        workflows
            .iter()
            .map(|workflow| (workflow.service_receipts(), workflow.service_attestations())),
    )?;
    Ok(M7EvidencePayload::M3CapabilityEffects(evidence))
}

fn required_native_service_families() -> BTreeSet<NativeServiceFamily> {
    BTreeSet::from([
        NativeServiceFamily::Build,
        NativeServiceFamily::Validation,
        NativeServiceFamily::Review,
        NativeServiceFamily::Packaging,
        NativeServiceFamily::Continuity,
        NativeServiceFamily::Scheduling,
        NativeServiceFamily::Operations,
    ])
}

#[derive(Serialize)]
struct M7AttestationDigestMaterial<'a> {
    schema: &'a str,
    attestation_id: &'a str,
    invocation_id: &'a str,
    service_id: &'a str,
    family: NativeServiceFamily,
    operation: CapabilityOperation,
    scope_id: &'a str,
    implementation_digest: &'a ContentDigest,
    input_digest: &'a ContentDigest,
    output_digest: &'a ContentDigest,
    receipt_digest: &'a ContentDigest,
    terminal_success: bool,
    failure_kind: Option<ServiceFailureKind>,
    provenance: &'a InvocationProvenance,
}

fn receipt_implementation_digest(
    receipt: &InvocationReceipt,
) -> Result<ContentDigest, M7FoundationError> {
    let value = serde_json::to_value(receipt)
        .map_err(|error| M7FoundationError::Serialization(error.to_string()))?;
    serde_json::from_value(value.get("implementation_digest").cloned().ok_or_else(|| {
        M7FoundationError::InvalidSource(
            "M3 invocation receipt omits its implementation digest".to_string(),
        )
    })?)
    .map_err(|error| M7FoundationError::InvalidSource(error.to_string()))
}

fn validate_m3_attestation(
    attestation: &ServiceInvocationAttestation,
) -> Result<(), M7FoundationError> {
    if attestation.schema != CAPABILITY_ATTESTATION_SCHEMA
        || attestation.attestation_id.trim().is_empty()
        || attestation.invocation_id.trim().is_empty()
        || attestation.service_id.trim().is_empty()
        || attestation.scope_id.trim().is_empty()
        || attestation.operation.family() != attestation.family
        || !attestation.terminal_success
        || attestation.failure_kind.is_some()
        || attestation.provenance.input_ref.trim().is_empty()
        || attestation.provenance.output_ref.trim().is_empty()
        || attestation.provenance.receipt_ref.trim().is_empty()
        || attestation.attestation_id
            != format!("attestation:{}", attestation.receipt_digest.file_stem())
    {
        return Err(M7FoundationError::InvalidSource(
            "M3 service attestation is failed, malformed, or relabeled".to_string(),
        ));
    }
    let expected = digest(&M7AttestationDigestMaterial {
        schema: &attestation.schema,
        attestation_id: &attestation.attestation_id,
        invocation_id: &attestation.invocation_id,
        service_id: &attestation.service_id,
        family: attestation.family,
        operation: attestation.operation,
        scope_id: &attestation.scope_id,
        implementation_digest: &attestation.implementation_digest,
        input_digest: &attestation.input_digest,
        output_digest: &attestation.output_digest,
        receipt_digest: &attestation.receipt_digest,
        terminal_success: attestation.terminal_success,
        failure_kind: attestation.failure_kind,
        provenance: &attestation.provenance,
    })?;
    require_digest(
        "M3 service attestation",
        &attestation.attestation_digest,
        &expected,
    )
}

fn derive_m3_from_service_evidence<'a, I>(
    workflows: I,
) -> Result<M3CapabilityEffectsEvidence, M7FoundationError>
where
    I: IntoIterator<Item = (&'a [InvocationReceipt], &'a [ServiceInvocationAttestation])>,
{
    let required_families = required_native_service_families();
    let mut observed_families = BTreeSet::new();
    let mut invocation_ids = BTreeSet::new();
    let mut receipt_digests = BTreeSet::new();
    let mut attestation_ids = BTreeSet::new();
    let mut attestation_digests = BTreeSet::new();
    let mut workflow_count = 0_usize;
    let mut receipt_count = 0_usize;
    let mut resolved_pair_count = 0_usize;
    let mut validated_attestation_count = 0_usize;
    let mut generic_bypass_count = 0_usize;

    for (receipts, attestations) in workflows {
        workflow_count = workflow_count.saturating_add(1);
        if receipts.is_empty() || receipts.len() != attestations.len() {
            return Err(M7FoundationError::InvalidSource(
                "M3 workflow receipts and attestations are empty or not one-to-one".to_string(),
            ));
        }
        let mut attestations_by_invocation = BTreeMap::new();
        for attestation in attestations {
            validate_m3_attestation(attestation)?;
            if attestations_by_invocation
                .insert(attestation.invocation_id.as_str(), attestation)
                .is_some()
                || !attestation_ids.insert(attestation.attestation_id.clone())
                || !attestation_digests.insert(attestation.attestation_digest.clone())
            {
                return Err(M7FoundationError::InvalidSource(
                    "M3 workflow reuses an attestation, invocation, or attestation digest"
                        .to_string(),
                ));
            }
            validated_attestation_count = validated_attestation_count.saturating_add(1);
        }
        for receipt in receipts {
            receipt.verify_integrity().map_err(|error| {
                M7FoundationError::InvalidSource(format!(
                    "M3 invocation receipt '{}' is corrupt: {error}",
                    receipt.invocation_id()
                ))
            })?;
            if !matches!(receipt.outcome(), InvocationOutcome::Succeeded { .. }) {
                return Err(M7FoundationError::InvalidSource(format!(
                    "M3 invocation receipt '{}' is not successful",
                    receipt.invocation_id()
                )));
            }
            if !invocation_ids.insert(receipt.invocation_id().to_string())
                || !receipt_digests.insert(receipt.receipt_digest().clone())
            {
                return Err(M7FoundationError::InvalidSource(
                    "M3 workflow reuses an invocation or receipt identity".to_string(),
                ));
            }
            let family = receipt.family();
            observed_families.insert(family);
            if !required_families.contains(&family) {
                generic_bypass_count = generic_bypass_count.saturating_add(1);
            }
            let attestation = attestations_by_invocation
                .remove(receipt.invocation_id())
                .ok_or_else(|| {
                    M7FoundationError::InvalidSource(format!(
                        "M3 invocation receipt '{}' has no exact attestation",
                        receipt.invocation_id()
                    ))
                })?;
            if attestation.service_id != receipt.service_id()
                || attestation.family != family
                || attestation.operation != receipt.operation()
                || attestation.scope_id != receipt.scope_id()
                || attestation.implementation_digest != receipt_implementation_digest(receipt)?
                || &attestation.input_digest != receipt.input_digest()
                || &attestation.output_digest != receipt.output_digest()
                || &attestation.receipt_digest != receipt.receipt_digest()
                || &attestation.provenance != receipt.provenance()
            {
                return Err(M7FoundationError::InvalidSource(format!(
                    "M3 receipt and attestation '{}' are cross-linked",
                    receipt.invocation_id()
                )));
            }
            receipt_count = receipt_count.saturating_add(1);
            resolved_pair_count = resolved_pair_count.saturating_add(1);
        }
        if !attestations_by_invocation.is_empty() {
            return Err(M7FoundationError::InvalidSource(
                "M3 workflow contains an unattached service attestation".to_string(),
            ));
        }
    }

    let all_receipts_resolved = workflow_count > 0
        && receipt_count > 0
        && resolved_pair_count == receipt_count
        && invocation_ids.len() == receipt_count
        && receipt_digests.len() == receipt_count;
    let all_attestations_valid = validated_attestation_count == receipt_count
        && attestation_ids.len() == receipt_count
        && attestation_digests.len() == receipt_count;
    if observed_families != required_families
        || !all_receipts_resolved
        || !all_attestations_valid
        || generic_bypass_count != 0
    {
        let missing_families = required_families
            .difference(&observed_families)
            .copied()
            .collect::<BTreeSet<_>>();
        let unexpected_families = observed_families
            .difference(&required_families)
            .copied()
            .collect::<BTreeSet<_>>();
        return Err(M7FoundationError::InvalidSource(format!(
            "M3 service evidence does not close the exact seven-family typed capability set: observed={observed_families:?}, missing={missing_families:?}, unexpected={unexpected_families:?}, workflows={workflow_count}, receipts={receipt_count}, resolved_pairs={resolved_pair_count}, validated_attestations={validated_attestation_count}, generic_bypasses={generic_bypass_count}"
        )));
    }
    let pair_count = u32::try_from(resolved_pair_count).map_err(|_| {
        M7FoundationError::InvalidSource(
            "M3 resolved service-pair count exceeds the evidence bound".to_string(),
        )
    })?;
    Ok(M3CapabilityEffectsEvidence {
        required_capability_count: pair_count,
        successful_receipt_count: pair_count,
        all_receipts_resolved,
        all_attestations_valid,
        generic_bypass_count: u32::try_from(generic_bypass_count).unwrap_or(u32::MAX),
    })
}

fn derive_m4_from_export(bytes: &[u8]) -> Result<M7EvidencePayload, M7FoundationError> {
    let bundle = parse_m5_export(bytes)?;
    let receipts = &bundle.active_cycle().m4_worker_evidence().receipts;
    let workflows = bundle.active_cycle().m4_workflows();
    let mapped: BTreeSet<_> = receipts
        .iter()
        .map(|receipt| match receipt.role {
            WorkerRole::Planner => M7WorkerRole::Planner,
            WorkerRole::Builder => M7WorkerRole::Builder,
            WorkerRole::Validator => M7WorkerRole::Tester,
            WorkerRole::Reviewer => M7WorkerRole::Reviewer,
            WorkerRole::Packager => M7WorkerRole::Operator,
            WorkerRole::Continuity => M7WorkerRole::Researcher,
        })
        .collect();
    let required = mandatory_worker_roles();
    let successful = receipts
        .iter()
        .filter(|receipt| {
            receipt.terminal_status == WorkerTerminalStatus::Succeeded
                && receipt.output_digest.is_some()
        })
        .count();
    if mapped != required
        || receipts.len() != required.len()
        || successful != receipts.len()
        || workflows.is_empty()
    {
        return Err(M7FoundationError::InvalidSource(
            "M5 export lacks the exact complete six-role M4 workflow closure".to_string(),
        ));
    }
    let mut lifecycle_terminal_job_digests = BTreeMap::new();
    let mut scope_id = None;
    for workflow in workflows {
        let anchor = &workflow.workflow().lifecycle_anchor;
        if lifecycle_terminal_job_digests
            .insert(anchor.m2_job_id.clone(), anchor.terminal_job_digest.clone())
            .is_some()
        {
            return Err(M7FoundationError::InvalidSource(
                "M5 export reuses an M4 lifecycle terminal job identity".to_string(),
            ));
        }
        match &scope_id {
            Some(existing) if existing != &anchor.schedule_attestation.scope_id => {
                return Err(M7FoundationError::InvalidSource(
                    "M5 export M4 lifecycle anchors span different capability scopes".to_string(),
                ));
            }
            None => scope_id = Some(anchor.schedule_attestation.scope_id.clone()),
            Some(_) => {}
        }
    }
    Ok(M7EvidencePayload::M4WorkerEcology(
        M4WorkerEcologyEvidence {
            factory_id: bundle.reproduction_state().factory_id.clone(),
            scope_id: scope_id.expect("non-empty validated M4 workflow set has one scope"),
            lifecycle_terminal_job_digests,
            required_roles: required,
            terminal_worker_result_count: receipts.len() as u32,
            receipt_backed_result_count: successful as u32,
            invented_worker_result_count: 0,
            synthesis_resolved: true,
        },
    ))
}

fn derive_m5_from_export_and_probe(
    manifest: &M7ProofRunManifest,
    export_bytes: &[u8],
    probe_bytes: &[u8],
) -> Result<M7EvidencePayload, M7FoundationError> {
    let bundle = parse_m5_export(export_bytes)?;
    let final_probe =
        M5FinalPostRollbackProbeV1::from_canonical_bytes(probe_bytes).map_err(|error| {
            M7FoundationError::InvalidSource(format!(
                "M5 final post-rollback probe source is invalid: {error}"
            ))
        })?;
    if final_probe.proof_run_manifest_digest() != &manifest.manifest_digest
        || final_probe.m5_export_bundle_content_digest() != &ContentDigest::from_bytes(export_bytes)
    {
        return Err(M7FoundationError::InvalidSource(
            "M5 final post-rollback probe is not bound to this manifest and exact export"
                .to_string(),
        ));
    }
    let probe = final_probe.probe();
    let state = bundle.reproduction_state();
    let snapshot = bundle.active_runtime_snapshot();
    let audit = bundle.effect_audit();
    let cycle = state
        .cycles
        .iter()
        .find(|cycle| {
            cycle.cycle_id == probe.cycle_id()
                && cycle.record_digest == *probe.cycle_record_digest()
                && cycle.recovery_receipt.as_ref().is_some_and(|receipt| {
                    receipt.receipt_digest == *probe.recovery_receipt_digest()
                })
                && matches!(
                    cycle.status,
                    CycleStatus::QuarantinedAndRolledBack | CycleStatus::RecoveredToIncumbent
                )
                && cycle.parent_package_digest == state.active_package_digest
                && cycle.parent_package_digest == snapshot.package_digest
        })
        .ok_or_else(|| {
            M7FoundationError::InvalidSource(
                "M5 export contains no rollback restored to the authoritative active snapshot"
                    .to_string(),
            )
        })?;
    let activation = cycle.activation_receipt.as_ref().ok_or_else(|| {
        M7FoundationError::InvalidSource("rolled-back cycle has no activation receipt".to_string())
    })?;
    let observation = cycle.observation_evidence.as_ref().ok_or_else(|| {
        M7FoundationError::InvalidSource(
            "rolled-back cycle has no observation evidence".to_string(),
        )
    })?;
    let recovery = cycle.recovery_receipt.as_ref().ok_or_else(|| {
        M7FoundationError::InvalidSource("rolled-back cycle has no recovery receipt".to_string())
    })?;
    let real_failure = observation.health_observations.iter().any(|item| {
        matches!(
            item.status,
            HealthStatus::Degraded | HealthStatus::Unhealthy
        )
    }) || observation.task_observations.iter().any(|item| {
        item.terminal != ExecutionTerminal::Succeeded || item.health != HealthStatus::Healthy
    });
    let quarantine = state.quarantines.iter().any(|item| {
        item.cycle_id == cycle.cycle_id
            && item.package_digest == cycle.challenger_package_digest
            && item.recovery_receipt_digest == recovery.receipt_digest
            && item.observation_evidence_digest.as_ref() == Some(&observation.evidence_digest)
    });
    let lineage = state.lineage.iter().any(|item| {
        item.cycle_record_digest.as_ref() == Some(&cycle.record_digest)
            && matches!(
                item.disposition,
                LineageDisposition::RecoveryRollback | LineageDisposition::Quarantined
            )
    });
    let recovery_response_digest = ContentDigest::from_bytes(
        &serde_json::to_vec(recovery)
            .map_err(|error| M7FoundationError::Serialization(error.to_string()))?,
    );
    let recovery_effect = audit.entries.iter().any(|entry| {
        entry.kind == M5EffectAuditKind::Recovery
            && entry.domain_request_digest == recovery.request_digest
            && entry.backend_response_digest == recovery_response_digest
    });
    let active_package =
        FactoryPackage::from_canonical_bytes(bundle.active_package().canonical_package_bytes())
            .map_err(|error| {
                M7FoundationError::InvalidSource(format!(
                    "restored active package is invalid: {error}"
                ))
            })?;
    let execution = probe.execution();
    let prior_audit = probe.prior_effect_audit();
    let post_audit = probe.effect_audit();
    let audit_delta: Vec<_> = post_audit
        .entries
        .iter()
        .filter(|entry| !prior_audit.entries.contains(entry))
        .collect();
    let execution_effect = audit_delta.first().is_some_and(|entry| {
        audit_delta.len() == 1
            && entry.kind == M5EffectAuditKind::ActiveExecution
            && entry.evidence_id == format!("active-execution:{}", execution.execution_digest)
            && entry.invocation_id == execution.m3_invocation_id
            && entry.receipt_digest == execution.m3_receipt_digest
            && entry.attestation_digest == execution.m3_attestation_digest
            && entry.proof_digest == execution.m3_proof_digest
    });
    let exact_audit_delta = post_audit.entries.len() == prior_audit.entries.len().saturating_add(1)
        && prior_audit
            .entries
            .iter()
            .all(|entry| post_audit.entries.contains(entry))
        && !prior_audit.entries.iter().any(|entry| {
            entry.invocation_id == execution.m3_invocation_id
                || entry.proof_digest == execution.m3_proof_digest
        })
        && audit
            .entries
            .iter()
            .all(|entry| prior_audit.entries.contains(entry));
    let post_rollback_behavior = probe.reproduction_state_digest() == &state.state_digest
        && probe.active_snapshot_digest() == &snapshot.snapshot_digest
        && probe.restored_package_digest() == &recovery.restored_package_digest
        && execution.package_digest == snapshot.package_digest
        && execution.package_bytes_digest == snapshot.package_bytes_digest
        && execution.component_digest == snapshot.component_digest
        && execution.package_digest == active_package.package_digest
        && execution.package_bytes_digest
            == ContentDigest::from_bytes(bundle.active_package().canonical_package_bytes())
        && execution.component_digest == active_package.payload.genome.component_digest
        && prior_audit.reproduction_state_digest == state.state_digest
        && prior_audit.backend_snapshot_digest == snapshot.snapshot_digest
        && post_audit.reproduction_state_digest == state.state_digest
        && post_audit.backend_snapshot_digest == snapshot.snapshot_digest
        && exact_audit_delta
        && execution_effect;
    if activation.previous_package_digest != cycle.parent_package_digest
        || activation.active_package_digest != cycle.challenger_package_digest
        || recovery.restored_package_digest != cycle.parent_package_digest
        || !recovery.state_readable
        || !real_failure
        || !quarantine
        || !lineage
        || !recovery_effect
        || !post_rollback_behavior
        || state.in_flight.is_some()
    {
        return Err(M7FoundationError::InvalidSource(
            "M5 rollback/recovery/audit/snapshot closure is incomplete".to_string(),
        ));
    }
    let active_cycle = bundle.active_cycle();
    let rollback_intent = state
        .cycle_intents
        .iter()
        .find(|intent| intent.cycle_id == cycle.cycle_id)
        .ok_or_else(|| {
            M7FoundationError::InvalidSource(
                "M5 rollback cycle omits its immutable cycle intent".to_string(),
            )
        })?;
    let mut provider_qualification_record_digests_by_target = BTreeMap::new();
    for qualification in &state.provider_qualifications {
        provider_qualification_record_digests_by_target
            .entry(qualification.target_digest.clone())
            .or_insert_with(BTreeSet::new)
            .insert(qualification.record_digest.clone());
    }
    Ok(M7EvidencePayload::M5ActivationRollback(
        M5ActivationRollbackEvidence {
            manifest_digest: final_probe.proof_run_manifest_digest().clone(),
            m5_export_bundle_content_digest: final_probe.m5_export_bundle_content_digest().clone(),
            m6_completion_bundle_content_digest: final_probe
                .m6_completion_bundle_content_digest()
                .clone(),
            m2_restart_capture_digest: final_probe.m2_restart_capture_digest().clone(),
            final_probe_causal_execution_context_digest: final_probe
                .causal_execution_context_digest()
                .clone(),
            final_post_rollback_probe_content_digest: ContentDigest::from_bytes(probe_bytes),
            final_post_rollback_probe_record_digest: final_probe.final_probe_digest().clone(),
            active_cycle_id: active_cycle.record().cycle_id.clone(),
            active_cycle_record_digest: active_cycle.record().record_digest.clone(),
            active_parent_package_digest: active_cycle.record().parent_package_digest.clone(),
            active_package_digest: state.active_package_digest.clone(),
            active_release_gate_digest: active_cycle.intent().expected_gate_digest.clone(),
            active_operator_context_digest: active_cycle.intent().operator_context_digest.clone(),
            rollback_cycle_id: cycle.cycle_id.clone(),
            rollback_cycle_record_digest: cycle.record_digest.clone(),
            rollback_release_gate_digest: rollback_intent.expected_gate_digest.clone(),
            rollback_operator_context_digest: rollback_intent.operator_context_digest.clone(),
            provider_qualification_record_digests_by_target,
            incumbent_package_digest: cycle.parent_package_digest.clone(),
            successor_package_digest: cycle.challenger_package_digest.clone(),
            restored_package_digest: recovery.restored_package_digest.clone(),
            restored_snapshot_digest: snapshot.snapshot_digest.clone(),
            activation_receipt_digest: activation.receipt_digest.clone(),
            observation_evidence_digest: observation.evidence_digest.clone(),
            recovery_receipt_digest: recovery.receipt_digest.clone(),
            successor_activated: true,
            real_failure_observed: true,
            rollback_intent_durable: true,
            rollback_completed: true,
            state_reference_restored: true,
            runtime_behavior_restored: true,
            incomplete_mutation: false,
        },
    ))
}

fn job_immutable_identity_preserved(before: &DurableJob, after: &DurableJob) -> bool {
    before.job_id == after.job_id
        && before.job_kind == after.job_kind
        && before.payload_json == after.payload_json
        && before.payload_digest == after.payload_digest
        && before.request_fingerprint == after.request_fingerprint
        && before.idempotency_key == after.idempotency_key
        && before.effect_receipt_id == after.effect_receipt_id
        && before.created_at_ms == after.created_at_ms
        && before.not_before_ms == after.not_before_ms
        && before.deadline_at_ms == after.deadline_at_ms
        && before.retry_policy == after.retry_policy
        && before.approval_request_id == after.approval_request_id
}

fn supervisor_state_preserved_across_restart(
    before: &SupervisorState,
    after: &SupervisorState,
) -> bool {
    if before.schema_name != after.schema_name
        || before.schema_version != after.schema_version
        || before.created_at_ms != after.created_at_ms
        || !after.shutdowns.starts_with(&before.shutdowns)
        || !after.migrations.starts_with(&before.migrations)
        || !before
            .idempotency_index
            .iter()
            .all(|(key, job_id)| after.idempotency_index.get(key) == Some(job_id))
        || !before
            .approval_resolutions
            .iter()
            .all(|(key, resolution)| after.approval_resolutions.get(key) == Some(resolution))
    {
        return false;
    }
    for (job_id, before_job) in &before.jobs {
        let Some(after_job) = after.jobs.get(job_id) else {
            return false;
        };
        if !job_immutable_identity_preserved(before_job, after_job)
            || !after_job.attempts.starts_with(&before_job.attempts)
            || before_job
                .cancellation
                .as_ref()
                .is_some_and(|cancellation| after_job.cancellation.as_ref() != Some(cancellation))
            || (before_job.phase.is_terminal() && after_job != before_job)
        {
            return false;
        }
    }
    if before.effect_receipts.iter().any(|(receipt_id, receipt)| {
        receipt.status == EffectReceiptStatus::Committed
            && after.effect_receipts.get(receipt_id) != Some(receipt)
    }) {
        return false;
    }

    let mut after_wakes = BTreeMap::new();
    for wake in &after.wakes {
        if after_wakes.insert(wake.wake_id.as_str(), wake).is_some() {
            return false;
        }
    }
    let mut before_wake_ids = BTreeSet::new();
    before.wakes.iter().all(|before_wake| {
        if !before_wake_ids.insert(before_wake.wake_id.as_str()) {
            return false;
        }
        let Some(after_wake) = after_wakes.get(before_wake.wake_id.as_str()) else {
            return false;
        };
        let identity_preserved = before_wake.wake_id == after_wake.wake_id
            && before_wake.job_id == after_wake.job_id
            && before_wake.kind == after_wake.kind
            && before_wake.scheduled_at_ms == after_wake.scheduled_at_ms
            && before_wake.recorded_at_ms == after_wake.recorded_at_ms;
        let consumption_non_regressing =
            match (before_wake.consumed_at_ms, after_wake.consumed_at_ms) {
                (Some(before_time), Some(after_time)) => {
                    before_time == after_time
                        && before_time <= before.updated_at_ms
                        && after_time <= after.updated_at_ms
                }
                (None, None) => true,
                (None, Some(after_time)) => {
                    after_time >= after_wake.scheduled_at_ms
                        && after_time >= after_wake.recorded_at_ms
                        && after_time <= after.updated_at_ms
                }
                (Some(_), None) => false,
            };
        identity_preserved && consumption_non_regressing
    })
}

fn exact_future_completion_after_restart(
    before: &SupervisorState,
    after: &SupervisorState,
    before_job: &DurableJob,
    after_job: &DurableJob,
) -> bool {
    let Some(before_receipt) = before.effect_receipts.get(&before_job.effect_receipt_id) else {
        return false;
    };
    let Some(after_receipt) = after.effect_receipts.get(&after_job.effect_receipt_id) else {
        return false;
    };
    let Some(JobTerminalOutcome::EffectCommitted {
        effect_receipt_id,
        effect_id,
        result_digest,
        completed_at_ms,
    }) = after_job.terminal_outcome.as_ref()
    else {
        return false;
    };
    let Some(commit) = after_receipt.commit.as_ref() else {
        return false;
    };
    before_receipt.status != EffectReceiptStatus::Committed
        && after_job.phase == JobPhase::Succeeded
        && effect_receipt_id == &after_job.effect_receipt_id
        && after_receipt.status == EffectReceiptStatus::Committed
        && after_receipt.committed_at_ms == Some(*completed_at_ms)
        && after_receipt.delivery_count > before_receipt.delivery_count
        && &commit.effect_id == effect_id
        && &commit.result_digest == result_digest
        && *completed_at_ms >= before_job.not_before_ms
        && *completed_at_ms >= after.heartbeat.started_at_ms
        && after_job.attempts.iter().any(|attempt| {
            attempt.ended_at_ms.is_some_and(|ended| {
                ended >= after.heartbeat.started_at_ms
                    && matches!(
                        &attempt.outcome,
                        Some(AttemptOutcome::EffectCommitted {
                            effect_receipt_id: attempt_receipt,
                            result_digest: attempt_result,
                        }) if attempt_receipt == effect_receipt_id
                            && attempt_result == result_digest
                    )
            })
        })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct M2OpenWorkspaceEffectEnvelopeV1 {
    schema: String,
    job_kind: String,
    record: ChallengerWorkspaceLineage,
}

fn validate_m2_open_workspace_commit(
    result_json: &str,
    workspace_id: &str,
) -> Result<(), M7FoundationError> {
    let value: M2OpenWorkspaceEffectEnvelopeV1 = serde_json::from_str(result_json)
        .map_err(|error| M7FoundationError::InvalidSource(error.to_string()))?;
    if value.schema != "wasm-biotic.m2-lifecycle-effect.v1"
        || value.job_kind != M1_OPEN_WORKSPACE_JOB_KIND
        || value.record.snapshot.workspace_id != workspace_id
    {
        return Err(M7FoundationError::InvalidSource(
            "M2 post-restart result is not the exact ordinary OpenWorkspace lifecycle effect"
                .to_string(),
        ));
    }
    Ok(())
}

fn derive_m2_from_states(
    manifest: &M7ProofRunManifest,
    before_bytes: &[u8],
    after_bytes: &[u8],
) -> Result<M7EvidencePayload, M7FoundationError> {
    let before = parse_supervisor_state(before_bytes)?;
    let after = parse_supervisor_state(after_bytes)?;
    let process_restart_observed = after.revision > before.revision
        && after.updated_at_ms > before.updated_at_ms
        && after.heartbeat.started_at_ms > before.heartbeat.started_at_ms
        && !before.heartbeat.owner_id.trim().is_empty()
        && !after.heartbeat.owner_id.trim().is_empty()
        && before.heartbeat.owner_id != after.heartbeat.owner_id;
    if !process_restart_observed {
        return Err(M7FoundationError::InvalidSource(
            "supervisor sources do not prove a later distinct-owner restart epoch".to_string(),
        ));
    }

    let state_preserved = supervisor_state_preserved_across_restart(&before, &after);
    let shutdown_reopen = before.shutdowns.iter().any(|shutdown| {
        shutdown.owner_id == before.heartbeat.owner_id
            && shutdown.requested_at_ms <= shutdown.completed_at_ms
            && shutdown.completed_at_ms <= after.heartbeat.started_at_ms
    });
    let startup_reconciliation = after.wakes.iter().any(|wake| {
        wake.kind == WakeKind::StartupLeaseReconciliation
            && wake.consumed_at_ms.is_some_and(|consumed| {
                consumed >= after.heartbeat.started_at_ms
                    && consumed >= wake.scheduled_at_ms
                    && consumed >= wake.recorded_at_ms
            })
    });
    let restart_reconstructed =
        process_restart_observed && state_preserved && (shutdown_reopen || startup_reconciliation);
    if !restart_reconstructed {
        return Err(M7FoundationError::InvalidSource(
            "supervisor restart lost or rewrote pre-restart durable state".to_string(),
        ));
    }

    let mut candidates = Vec::new();
    for before_job in before.jobs.values().filter(|job| {
        job.not_before_ms > before.updated_at_ms
            && !job.phase.is_terminal()
            && job.next_wake_at_ms == Some(job.not_before_ms)
            && job.job_kind == M1_OPEN_WORKSPACE_JOB_KIND
    }) {
        let binding = match M5M2PostExportJobBindingV2::from_job_identity(
            &before_job.job_id,
            &before_job.idempotency_key,
        ) {
            Ok(binding) => binding,
            Err(_) => continue,
        };
        if binding.manifest_digest() != &manifest.manifest_digest {
            continue;
        }
        let M1LifecycleJob::OpenWorkspace(challenge_payload) =
            serde_json::from_str::<M1LifecycleJob>(&before_job.payload_json)
                .map_err(|error| M7FoundationError::InvalidSource(error.to_string()))?
        else {
            continue;
        };
        let mut anchors = before
            .jobs
            .values()
            .filter(|job| {
                job.phase == JobPhase::Succeeded
                    && job.job_kind == M1_OPEN_WORKSPACE_JOB_KIND
                    && job.terminal_outcome.is_some()
                    && job.updated_at_ms <= before_job.created_at_ms
                    && digest(*job).ok().as_ref()
                        == Some(binding.m4_lifecycle_terminal_job_digest())
            })
            .collect::<Vec<_>>();
        if anchors.len() != 1 {
            return Err(M7FoundationError::InvalidSource(format!(
                "M2 post-export job requires exactly one prior terminal M4 anchor in the same state, found {}",
                anchors.len()
            )));
        }
        let anchor_job = anchors.pop().expect("one checked M4 anchor");
        let M1LifecycleJob::OpenWorkspace(anchor_payload) =
            serde_json::from_str::<M1LifecycleJob>(&anchor_job.payload_json)
                .map_err(|error| M7FoundationError::InvalidSource(error.to_string()))?
        else {
            return Err(M7FoundationError::InvalidSource(
                "M2 lifecycle anchor is not an ordinary OpenWorkspace job".to_string(),
            ));
        };
        if challenge_payload.workspace_id != anchor_payload.workspace_id {
            return Err(M7FoundationError::InvalidSource(
                "M2 post-export job did not idempotently reopen the anchor workspace".to_string(),
            ));
        }
        let after_job = after.jobs.get(&before_job.job_id).ok_or_else(|| {
            M7FoundationError::InvalidSource(
                "M2 post-restart state omits its exact challenge job".to_string(),
            )
        })?;
        if !exact_future_completion_after_restart(&before, &after, before_job, after_job) {
            continue;
        }
        let before_wake = before
            .wakes
            .iter()
            .find(|wake| {
                wake.job_id == before_job.job_id
                    && wake.scheduled_at_ms == before_job.not_before_ms
                    && wake.consumed_at_ms.is_none()
                    && matches!(
                        &wake.kind,
                        WakeKind::Submission | WakeKind::Retry | WakeKind::ApprovalGranted
                    )
            })
            .ok_or_else(|| {
                M7FoundationError::InvalidSource(
                    "M2 challenge has no exact unconsumed pre-restart wake".to_string(),
                )
            })?;
        let after_wake = after
            .wakes
            .iter()
            .find(|wake| wake.wake_id == before_wake.wake_id)
            .ok_or_else(|| {
                M7FoundationError::InvalidSource(
                    "M2 challenge wake disappeared after restart".to_string(),
                )
            })?;
        if !after_wake.consumed_at_ms.is_some_and(|consumed| {
            consumed >= before_wake.scheduled_at_ms && consumed >= after.heartbeat.started_at_ms
        }) {
            continue;
        }
        let after_receipt = after
            .effect_receipts
            .get(&after_job.effect_receipt_id)
            .ok_or_else(|| {
                M7FoundationError::InvalidSource(
                    "M2 completed challenge omits its effect receipt".to_string(),
                )
            })?;
        let commit = after_receipt.commit.as_ref().ok_or_else(|| {
            M7FoundationError::InvalidSource(
                "M2 completed challenge receipt omits its commit".to_string(),
            )
        })?;
        let anchor_receipt = before
            .effect_receipts
            .get(&anchor_job.effect_receipt_id)
            .and_then(|receipt| receipt.commit.as_ref())
            .ok_or_else(|| {
                M7FoundationError::InvalidSource(
                    "M2 lifecycle anchor omits its committed ordinary effect".to_string(),
                )
            })?;
        if commit != anchor_receipt {
            return Err(M7FoundationError::InvalidSource(
                "post-restart OpenWorkspace did not replay the exact idempotent anchor effect"
                    .to_string(),
            ));
        }
        validate_m2_open_workspace_commit(&commit.result_json, &anchor_payload.workspace_id)?;
        let challenge_digest = binding
            .challenge_digest(&anchor_job.job_id, &anchor_payload.workspace_id)
            .map_err(|error| M7FoundationError::InvalidSource(error.to_string()))?;
        candidates.push((
            before_job,
            after_job,
            after_wake,
            after_receipt,
            binding,
            anchor_job.job_id.clone(),
            challenge_digest,
        ));
    }
    if candidates.len() != 1 {
        return Err(M7FoundationError::InvalidSource(format!(
            "supervisor sources require exactly one manifest-bound post-export challenge completed after restart, found {}",
            candidates.len()
        )));
    }
    let (before_job, after_job, wake, after_receipt, binding, anchor_job_id, challenge_digest) =
        candidates.pop().expect("one checked M2 candidate");
    let restart_capture = M5M2PostExportRestartCaptureV2::from_canonical_state_bytes(
        binding.clone(),
        anchor_job_id.clone(),
        before_bytes.to_vec(),
        after_bytes.to_vec(),
    )
    .map_err(|error| {
        M7FoundationError::InvalidSource(format!(
            "M2 restart sources do not form the exact sealed capture: {error}"
        ))
    })?;
    let future_wake_observed = wake.consumed_at_ms.is_some_and(|consumed| {
        wake.scheduled_at_ms == before_job.not_before_ms
            && consumed >= wake.scheduled_at_ms
            && consumed >= after.heartbeat.started_at_ms
    });
    let missed_wake_count = u32::try_from(
        after
            .jobs
            .values()
            .filter(|job| {
                matches!(job.phase, JobPhase::Queued | JobPhase::RetryScheduled)
                    && job
                        .next_wake_at_ms
                        .is_some_and(|scheduled| scheduled <= after.updated_at_ms)
            })
            .count(),
    )
    .unwrap_or(u32::MAX);
    Ok(M7EvidencePayload::M2SchedulerWakeRestart(
        M2SchedulerWakeRestartEvidence {
            manifest_digest: manifest.manifest_digest.clone(),
            challenge_job_id: before_job.job_id.clone(),
            challenge_digest,
            m5_export_bundle_content_digest: binding.m5_export_bundle_content_digest().clone(),
            m6_completion_bundle_content_digest: binding
                .m6_completion_bundle_content_digest()
                .clone(),
            m4_lifecycle_job_id: anchor_job_id,
            m4_lifecycle_terminal_job_digest: binding.m4_lifecycle_terminal_job_digest().clone(),
            scheduled_job_digest: digest(before_job)?,
            completed_job_digest: digest(after_job)?,
            effect_receipt_digest: digest(after_receipt)?,
            wake_record_digest: digest(wake)?,
            restart_capture_digest: restart_capture.capture_digest().clone(),
            future_wake_observed,
            process_restart_observed,
            restart_reconstructed,
            missed_wake_count,
        },
    ))
}

fn derive_test_transcript(
    manifest: &M7ProofRunManifest,
    causal_subject: &M7CausalSubject,
    bytes: &[u8],
    capture_attestation_bytes: &[u8],
) -> Result<M7EvidencePayload, M7FoundationError> {
    let transcript = M7CargoTestTranscriptV2::from_canonical_bytes(bytes)?;
    let capture = M7SourceCaptureAttestationV2::from_canonical_bytes_detached(
        capture_attestation_bytes,
        manifest,
    )?;
    let transcript_link = M7SourceLinkV2::from_source_bytes(
        manifest,
        causal_subject.clone(),
        M7SourceRoleV2::CargoTestTranscript,
        bytes,
    )?;
    if !capture
        .captured_source_links
        .iter()
        .any(|link| link == &transcript_link)
    {
        return Err(M7FoundationError::InvalidSource(
            "source-capture inventory does not bind the exact cargo transcript source link"
                .to_string(),
        ));
    }
    if transcript.source_manifest_digest != manifest.manifest_digest || transcript.exit_code != 0 {
        return Err(M7FoundationError::InvalidSource(
            "test transcript names another manifest or a nonzero exit".to_string(),
        ));
    }
    let combined = format!("{}\n{}", transcript.stdout, transcript.stderr);
    let mut passed = 0_u32;
    let mut failed = 0_u32;
    let mut result_lines = 0_u32;
    for line in combined.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("test result: ") {
            let ok = rest.starts_with("ok.");
            let failure = rest.starts_with("FAILED.");
            if !ok && !failure {
                return Err(M7FoundationError::InvalidSource(
                    "cargo transcript contains an unrecognized result line".to_string(),
                ));
            }
            let fields: Vec<_> = rest.split(';').collect();
            if fields.len() < 2 {
                return Err(M7FoundationError::InvalidSource(
                    "cargo result line is incomplete".to_string(),
                ));
            }
            passed = passed.saturating_add(parse_result_count(
                fields[0],
                if ok { "ok. " } else { "FAILED. " },
                " passed",
            )?);
            failed = failed.saturating_add(parse_result_count(fields[1], "", " failed")?);
            result_lines = result_lines.saturating_add(1);
        }
    }
    if result_lines == 0 || passed == 0 || failed != 0 {
        return Err(M7FoundationError::InvalidSource(
            "cargo transcript has no nonempty all-passing result set".to_string(),
        ));
    }
    Ok(M7EvidencePayload::DeterministicTestTranscript(
        DeterministicTestTranscriptEvidence {
            command_digest: digest(&transcript.command)?,
            transcript_digest: ContentDigest::from_bytes(bytes),
            required_test_count: passed,
            executed_test_count: passed,
            failed_test_count: failed,
            clean_root: true,
        },
    ))
}

fn parse_result_count(field: &str, prefix: &str, suffix: &str) -> Result<u32, M7FoundationError> {
    field
        .trim()
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .and_then(|value| value.trim().parse().ok())
        .ok_or_else(|| {
            M7FoundationError::InvalidSource(format!(
                "cannot parse cargo test count from '{field}'"
            ))
        })
}

fn parse_m5_export(bytes: &[u8]) -> Result<M5ExportBundleV1, M7FoundationError> {
    M5ExportBundleV1::from_canonical_bytes(bytes).map_err(|error| {
        M7FoundationError::InvalidSource(format!("M5 export source is invalid: {error}"))
    })
}

fn parse_supervisor_state(bytes: &[u8]) -> Result<SupervisorState, M7FoundationError> {
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
        return Err(M7FoundationError::InvalidSource(
            "supervisor source is outside bounds".to_string(),
        ));
    }
    let state: SupervisorState = serde_json::from_slice(bytes)
        .map_err(|error| M7FoundationError::Serialization(error.to_string()))?;
    if canonical_json(&state)? != bytes {
        return Err(M7FoundationError::InvalidSource(
            "supervisor source is not canonical JSON".to_string(),
        ));
    }
    state.validate().map_err(|error| {
        M7FoundationError::InvalidSource(format!("supervisor source is invalid: {error}"))
    })?;
    Ok(state)
}

pub trait EvidenceResolver {
    /// Resolve immutable bytes by cryptographic content identity.
    ///
    /// Implementations must not synthesize a success record for a missing
    /// digest. The evaluator treats both `Ok(None)` and errors as `NotYet`.
    fn resolve(&self, digest: &ContentDigest) -> Result<Option<Vec<u8>>, EvidenceResolveError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceResolveError {
    pub message: String,
}

impl Display for EvidenceResolveError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for EvidenceResolveError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7FinalBundle {
    schema: String,
    manifest: M7ProofRunManifest,
    reviewer_identity: M7ExternalEd25519IdentityV1,
    evidence_links: Vec<M7EvidenceLink>,
    live_provider_link: Option<M7EvidenceLink>,
    source_links: Vec<M7SourceLinkV2>,
    bundle_digest: ContentDigest,
}

impl M7FinalBundle {
    pub fn new(
        manifest: M7ProofRunManifest,
        mut evidence_links: Vec<M7EvidenceLink>,
        live_provider_link: Option<M7EvidenceLink>,
        mut source_links: Vec<M7SourceLinkV2>,
    ) -> Result<Self, M7FoundationError> {
        evidence_links
            .sort_by(|left, right| (left.kind, &left.digest).cmp(&(right.kind, &right.digest)));
        source_links.sort_by(|left, right| {
            (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
        });
        let reviewer_identity = manifest.reviewer_identity.clone();
        let mut bundle = Self {
            schema: M7_FINAL_BUNDLE_SCHEMA.to_string(),
            manifest,
            reviewer_identity,
            evidence_links,
            live_provider_link,
            source_links,
            bundle_digest: ContentDigest::from_bytes(&[]),
        };
        bundle.validate_fields()?;
        bundle.bundle_digest = bundle.expected_digest()?;
        Ok(bundle)
    }

    pub fn manifest(&self) -> &M7ProofRunManifest {
        &self.manifest
    }

    pub fn evidence_links(&self) -> &[M7EvidenceLink] {
        &self.evidence_links
    }

    pub fn reviewer_identity(&self) -> &M7ExternalEd25519IdentityV1 {
        &self.reviewer_identity
    }

    pub fn live_provider_link(&self) -> Option<&M7EvidenceLink> {
        self.live_provider_link.as_ref()
    }

    pub fn source_links(&self) -> &[M7SourceLinkV2] {
        &self.source_links
    }

    pub fn bundle_digest(&self) -> &ContentDigest {
        &self.bundle_digest
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7FoundationError> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M7FoundationError> {
        let bundle: Self = serde_json::from_slice(bytes)
            .map_err(|error| M7FoundationError::Serialization(error.to_string()))?;
        if canonical_json(&bundle)? != bytes {
            return Err(M7FoundationError::InvalidBundle(
                "final bundle is not canonical JSON".to_string(),
            ));
        }
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn reviewed_evidence_set_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        reviewed_evidence_set_digest(
            &self.manifest,
            &self.evidence_links,
            self.live_provider_link.as_ref(),
            &self.source_links,
        )
    }

    fn validate(&self) -> Result<(), M7FoundationError> {
        self.validate_fields()?;
        require_digest(
            "M7 final bundle",
            &self.bundle_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M7FoundationError> {
        if self.schema != M7_FINAL_BUNDLE_SCHEMA {
            return Err(M7FoundationError::InvalidBundle(
                "unsupported M7 final-bundle schema".to_string(),
            ));
        }
        self.manifest.validate()?;
        self.reviewer_identity.validate()?;
        if self.reviewer_identity != self.manifest.reviewer_identity {
            return Err(M7FoundationError::InvalidBundle(
                "final-bundle reviewer identity differs from the pre-run manifest pin".to_string(),
            ));
        }
        if self.evidence_links.len() > MAX_EVIDENCE_LINKS {
            return Err(M7FoundationError::InvalidBundle(format!(
                "final bundle exceeds {MAX_EVIDENCE_LINKS} evidence links"
            )));
        }
        let mut kinds = BTreeSet::new();
        let mut previous: Option<(M7EvidenceKind, ContentDigest)> = None;
        for link in &self.evidence_links {
            link.validate()?;
            if link.kind == M7EvidenceKind::LiveProviderQualification {
                return Err(M7FoundationError::InvalidBundle(
                    "live-provider evidence must use its separate qualification slot".to_string(),
                ));
            }
            if link.proof_run_id != self.manifest.proof_run_id
                || link.causal_subject.proof_chain_digest != self.manifest.causal_chain_digest
            {
                return Err(M7FoundationError::InvalidBundle(
                    "evidence link is cross-run or outside the manifest causal chain".to_string(),
                ));
            }
            if !kinds.insert(link.kind) {
                return Err(M7FoundationError::DuplicateEvidenceKind(link.kind));
            }
            let current = (link.kind, link.digest.clone());
            if previous.as_ref().is_some_and(|value| value > &current) {
                return Err(M7FoundationError::InvalidBundle(
                    "evidence links are not in canonical order".to_string(),
                ));
            }
            previous = Some(current);
        }
        for required in self.manifest.frozen_criteria.required_evidence_kinds() {
            if !kinds.contains(required) {
                return Err(M7FoundationError::MissingRequiredEvidence(*required));
            }
        }
        if &kinds != self.manifest.frozen_criteria.required_evidence_kinds() {
            return Err(M7FoundationError::InvalidBundle(
                "final bundle contains undeclared release-authoritative evidence kinds".to_string(),
            ));
        }
        match (&self.manifest.live_provider_scope, &self.live_provider_link) {
            (None, None) | (Some(_), None) => {}
            (Some(_), Some(link)) => {
                link.validate()?;
                if link.kind != M7EvidenceKind::LiveProviderQualification
                    || link.proof_run_id != self.manifest.proof_run_id
                    || link.causal_subject.proof_chain_digest != self.manifest.causal_chain_digest
                {
                    return Err(M7FoundationError::InvalidBundle(
                        "provider qualification evidence has the wrong kind or proof-run scope"
                            .to_string(),
                    ));
                }
            }
            (None, Some(_)) => {
                return Err(M7FoundationError::InvalidBundle(
                    "provider evidence is present without a separately frozen provider scope"
                        .to_string(),
                ));
            }
        }
        if self.source_links.len() > MAX_SOURCE_LINKS {
            return Err(M7FoundationError::InvalidBundle(format!(
                "final bundle exceeds {MAX_SOURCE_LINKS} source links"
            )));
        }
        let mut roles = BTreeSet::new();
        let mut previous_source: Option<(M7SourceRoleV2, ContentDigest)> = None;
        for link in &self.source_links {
            link.validate_for(
                &self.manifest,
                link.semantic_role.evidence_kind(),
                &link.causal_subject,
            )?;
            if !roles.insert(link.semantic_role) {
                return Err(M7FoundationError::InvalidBundle(
                    "final bundle repeats a semantic source role".to_string(),
                ));
            }
            let current = (link.semantic_role, link.digest.clone());
            if previous_source
                .as_ref()
                .is_some_and(|value| value > &current)
            {
                return Err(M7FoundationError::InvalidBundle(
                    "final bundle source links are not canonically ordered".to_string(),
                ));
            }
            previous_source = Some(current);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7FoundationError> {
        digest(&(
            FINAL_BUNDLE_DOMAIN,
            &self.manifest,
            &self.reviewer_identity,
            &self.evidence_links,
            &self.live_provider_link,
            &self.source_links,
        ))
    }
}

pub fn reviewed_evidence_set_digest(
    manifest: &M7ProofRunManifest,
    evidence_links: &[M7EvidenceLink],
    live_provider_link: Option<&M7EvidenceLink>,
    source_links: &[M7SourceLinkV2],
) -> Result<ContentDigest, M7FoundationError> {
    let mut reviewed: Vec<_> = evidence_links
        .iter()
        .filter(|link| link.kind != M7EvidenceKind::IndependentReviewerRecommendation)
        .cloned()
        .collect();
    if let Some(link) = live_provider_link {
        reviewed.push(link.clone());
    }
    reviewed.sort_by(|left, right| (left.kind, &left.digest).cmp(&(right.kind, &right.digest)));
    let mut sources = source_links
        .iter()
        .filter(|link| link.semantic_role != M7SourceRoleV2::IndependentReview)
        .cloned()
        .collect::<Vec<_>>();
    sources.sort_by(|left, right| {
        (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
    });
    digest(&(
        EVIDENCE_SET_DOMAIN,
        &manifest.manifest_digest,
        &reviewed,
        &sources,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7SemanticFailure {
    HistoricalTruthUsedAsOperationalProof,
    CandidateLifecycleIncomplete,
    MissedWakeOrRestart,
    CapabilityEffectsIncomplete,
    InventedOrIncompleteWorkerResult,
    RollbackIncomplete,
    ExchangeTamperedOrIncomplete,
    UnresolvedQuarantine,
    FailedTests,
    ClaimBoundaryIncomplete,
    PublicationPolicyUnsafe,
    ReviewerNotIndependent,
    LiveProviderEvidenceUnsafe,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum M7Blocker {
    InvalidBundle(String),
    MissingEvidenceLink(M7EvidenceKind),
    MissingEvidenceBytes(M7EvidenceKind),
    ResolverFailure(M7EvidenceKind),
    LengthMismatch(M7EvidenceKind),
    DigestMismatch(M7EvidenceKind),
    MalformedEvidence(M7EvidenceKind),
    NonCanonicalEvidence(M7EvidenceKind),
    SchemaMismatch(M7EvidenceKind),
    OwnerMismatch(M7EvidenceKind),
    CrossRunEvidence(M7EvidenceKind),
    StaleManifestEvidence(M7EvidenceKind),
    CausalMismatch(M7EvidenceKind),
    MissingAuthoritativeSource(M7EvidenceKind),
    MissingSourceBytes {
        kind: M7EvidenceKind,
        role: M7SourceRoleV2,
    },
    SourceResolverFailure {
        kind: M7EvidenceKind,
        role: M7SourceRoleV2,
    },
    SourceLengthMismatch {
        kind: M7EvidenceKind,
        role: M7SourceRoleV2,
    },
    SourceDigestMismatch {
        kind: M7EvidenceKind,
        role: M7SourceRoleV2,
    },
    InvalidAuthoritativeSource {
        kind: M7EvidenceKind,
        role: Option<M7SourceRoleV2>,
    },
    SourcePayloadMismatch(M7EvidenceKind),
    ActiveSurfaceSnapshotMismatch,
    M5ExportLineageMismatch,
    M2M4LineageMismatch,
    ClosureChronologyMismatch,
    SourceClosureMismatch,
    SourceSelfReference(M7EvidenceKind),
    SemanticFailure {
        kind: M7EvidenceKind,
        failure: M7SemanticFailure,
    },
    ReviewerAbsent,
    ReviewerNotIndependent,
    ReviewerScopeMismatch,
    LiveProviderScopeMismatch,
    LiveProviderCandidateIdentityMismatch {
        m1_incumbent_package_digest: Option<ContentDigest>,
        m1_candidate_package_digest: Option<ContentDigest>,
        provider_incumbent_package_digest: ContentDigest,
        provider_target_package_digest: ContentDigest,
    },
    LiveProviderQualificationIncomplete(LiveProviderQualificationStatus),
    SourceCaptureAttestationAbsent,
    SourceCaptureInventoryFailure(M7SourceCaptureInventoryFailure),
    SourceCaptureIdentityNotIndependent,
    ReviewerCryptographicAttestationAbsent,
    ReviewerCryptographicAttestationInvalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveProviderQualificationStatus {
    NotScoped,
    ScopedButNotProvided,
    Qualified,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M7Evaluation {
    pub decision: M7ClosureDecision,
    pub evidence_complete: bool,
    pub reviewer_recommendation: Option<M7ClosureDecision>,
    pub caveats: BTreeSet<M7EvaluationCaveatV1>,
    pub verified_kinds: BTreeSet<M7EvidenceKind>,
    pub blockers: Vec<M7Blocker>,
    pub bundle_digest: ContentDigest,
    pub live_provider_status: LiveProviderQualificationStatus,
}

fn artifact_source_content_digest(
    artifacts: &BTreeMap<M7EvidenceKind, M7EvidenceArtifact>,
    kind: M7EvidenceKind,
    role: M7SourceRoleV2,
) -> Option<&ContentDigest> {
    artifacts
        .get(&kind)?
        .source_links
        .iter()
        .find(|link| link.semantic_role == role)
        .map(|link| &link.digest)
}

/// Detect substitution of individually valid milestone evidence from another
/// M5 export. Canonical M5 sources are byte-normalized before admission, so
/// their source-link digest is the exact export identity. M6 repeats that same
/// identity from its validated sender completion source.
fn m5_export_lineage_mismatch(artifacts: &BTreeMap<M7EvidenceKind, M7EvidenceArtifact>) -> bool {
    let identities = [
        artifacts
            .get(&M7EvidenceKind::M2SchedulerWakeRestart)
            .and_then(|artifact| match &artifact.payload {
                M7EvidencePayload::M2SchedulerWakeRestart(restart) => {
                    Some(&restart.m5_export_bundle_content_digest)
                }
                _ => None,
            }),
        artifact_source_content_digest(
            artifacts,
            M7EvidenceKind::M1CandidateLifecycle,
            M7SourceRoleV2::M5ExportM1,
        ),
        artifact_source_content_digest(
            artifacts,
            M7EvidenceKind::M3CapabilityEffects,
            M7SourceRoleV2::M5ExportM3,
        ),
        artifact_source_content_digest(
            artifacts,
            M7EvidenceKind::M4WorkerEcology,
            M7SourceRoleV2::M5ExportM4,
        ),
        artifact_source_content_digest(
            artifacts,
            M7EvidenceKind::M5ActivationRollback,
            M7SourceRoleV2::M5ExportRollback,
        ),
        artifacts
            .get(&M7EvidenceKind::M6FactoryExchange)
            .and_then(|artifact| match &artifact.payload {
                M7EvidencePayload::M6FactoryExchange(exchange) => {
                    Some(&exchange.sender_m5_export_bundle_content_digest)
                }
                _ => None,
            }),
    ];
    let mut present = identities.into_iter().flatten();
    let Some(canonical) = present.next() else {
        return false;
    };
    present.any(|identity| identity != canonical)
}

/// Cross-check the post-export M2 restart challenge against the exact M4
/// lifecycle anchor carried by the canonical M5 export. This proves that the
/// restart happened on a supervisor root from the same factory/workflow
/// lineage, rather than on an unrelated but individually valid supervisor.
fn m2_m4_lineage_mismatch(artifacts: &BTreeMap<M7EvidenceKind, M7EvidenceArtifact>) -> bool {
    let Some(M7EvidenceArtifact {
        payload: M7EvidencePayload::M2SchedulerWakeRestart(m2),
        ..
    }) = artifacts.get(&M7EvidenceKind::M2SchedulerWakeRestart)
    else {
        return false;
    };
    let Some(M7EvidenceArtifact {
        payload: M7EvidencePayload::M4WorkerEcology(m4),
        ..
    }) = artifacts.get(&M7EvidenceKind::M4WorkerEcology)
    else {
        return false;
    };
    m4.lifecycle_terminal_job_digests
        .get(&m2.m4_lifecycle_job_id)
        != Some(&m2.m4_lifecycle_terminal_job_digest)
}

/// Prove the manifest -> export -> M6 completion -> M2 restart -> final M5
/// probe chain from independently re-derived identities. In particular, the
/// M6 identity is the content digest of the exact authoritative source bytes,
/// not the bundle's caller-visible internal seal.
fn closure_chronology_mismatch(
    manifest: &M7ProofRunManifest,
    artifacts: &BTreeMap<M7EvidenceKind, M7EvidenceArtifact>,
) -> bool {
    let Some(M7EvidenceArtifact {
        payload: M7EvidencePayload::M2SchedulerWakeRestart(m2),
        ..
    }) = artifacts.get(&M7EvidenceKind::M2SchedulerWakeRestart)
    else {
        return false;
    };
    let Some(
        m5_artifact @ M7EvidenceArtifact {
            payload: M7EvidencePayload::M5ActivationRollback(m5),
            ..
        },
    ) = artifacts.get(&M7EvidenceKind::M5ActivationRollback)
    else {
        return false;
    };
    let Some(
        m6_artifact @ M7EvidenceArtifact {
            payload: M7EvidencePayload::M6FactoryExchange(m6),
            ..
        },
    ) = artifacts.get(&M7EvidenceKind::M6FactoryExchange)
    else {
        return false;
    };
    let Some(m6_source_content_digest) = m6_artifact
        .source_links
        .iter()
        .find(|link| link.semantic_role == M7SourceRoleV2::M6Completion)
        .map(|link| &link.digest)
    else {
        // Source absence has its own fail-closed blocker.
        return false;
    };
    let Some(final_probe_source_content_digest) = m5_artifact
        .source_links
        .iter()
        .find(|link| link.semantic_role == M7SourceRoleV2::M5FinalPostRollbackProbe)
        .map(|link| &link.digest)
    else {
        return false;
    };
    let expected_causal_execution_context =
        M5FinalPostRollbackProbeV1::expected_causal_execution_context_digest(
            &m5.manifest_digest,
            &m5.m5_export_bundle_content_digest,
            &m5.m6_completion_bundle_content_digest,
            &m5.m2_restart_capture_digest,
            &m5.rollback_cycle_id,
            &m5.rollback_cycle_record_digest,
            &m5.recovery_receipt_digest,
        )
        .ok();

    expected_causal_execution_context.as_ref()
        != Some(&m5.final_probe_causal_execution_context_digest)
        || m2.manifest_digest != manifest.manifest_digest
        || m5.manifest_digest != manifest.manifest_digest
        || m5.m5_export_bundle_content_digest != m2.m5_export_bundle_content_digest
        || m5.m5_export_bundle_content_digest != m6.sender_m5_export_bundle_content_digest
        || m2.m6_completion_bundle_content_digest != *m6_source_content_digest
        || m6.completion_bundle_content_digest != *m6_source_content_digest
        || m5.m6_completion_bundle_content_digest != *m6_source_content_digest
        || m5.m2_restart_capture_digest != m2.restart_capture_digest
        || m5.final_post_rollback_probe_content_digest != *final_probe_source_content_digest
}

fn m5_current_run_lineage_mismatch(
    manifest: &M7ProofRunManifest,
    artifacts: &BTreeMap<M7EvidenceKind, M7EvidenceArtifact>,
    provider: Option<&LiveProviderQualificationEvidence>,
) -> bool {
    let Some(M7EvidenceArtifact {
        payload: M7EvidencePayload::M5ActivationRollback(m5),
        ..
    }) = artifacts.get(&M7EvidenceKind::M5ActivationRollback)
    else {
        return false;
    };
    if m5.active_cycle_id == m5.rollback_cycle_id
        || m5.active_release_gate_digest != m5.rollback_release_gate_digest
        || m5.rollback_operator_context_digest != manifest.manifest_digest
    {
        return true;
    }
    match (&manifest.live_provider_scope, provider) {
        (None, _) => m5.active_operator_context_digest != manifest.manifest_digest,
        (Some(_), None) => false,
        (Some(scope), Some(provider)) => {
            provider.api_base_url != scope.api_base_url
                || provider.endpoint_class != scope.endpoint_class
                || !is_external_https_provider_endpoint(
                    &provider.api_base_url,
                    provider.endpoint_class,
                )
                || provider.cycle_id != m5.active_cycle_id
                || provider.terminal_cycle_record_digest.as_ref()
                    != Some(&m5.active_cycle_record_digest)
                || provider.incumbent_package_digest != m5.active_parent_package_digest
                || provider.target_package_digest != m5.active_package_digest
                || provider.release_gate_digest != m5.active_release_gate_digest
                || provider.operator_context_digest != provider.precommit_digest
                || m5.active_operator_context_digest != provider.precommit_digest
                || m5
                    .provider_qualification_record_digests_by_target
                    .get(&provider.target_digest)
                    .map(|record_digests| {
                        record_digests.len() != 1
                            || !record_digests.contains(&provider.qualification_record_digest)
                    })
                    .unwrap_or(true)
        }
    }
}

/// Pure, fail-closed evaluation of a finalized content-addressed bundle.
pub fn evaluate_m7_closure<R: EvidenceResolver>(
    bundle: &M7FinalBundle,
    resolver: &R,
) -> M7Evaluation {
    let mut blockers = Vec::new();
    let mut verified_kinds = BTreeSet::new();
    let mut artifacts = BTreeMap::new();
    let mut declared_source_links = Vec::new();
    let mut reviewer_recommendation = None;
    let mut live_provider_evidence = None;
    let mut live_provider_status = if bundle.manifest.live_provider_scope.is_some() {
        LiveProviderQualificationStatus::ScopedButNotProvided
    } else {
        LiveProviderQualificationStatus::NotScoped
    };

    if identity_reuses_implementation_path(
        &bundle.manifest.source_capture_identity,
        &bundle.manifest.implementation_principal_ids,
        &bundle.manifest.implementation_identity_digests,
    ) {
        blockers.push(M7Blocker::SourceCaptureIdentityNotIndependent);
    }
    if identity_reuses_implementation_path(
        &bundle.reviewer_identity,
        &bundle.manifest.implementation_principal_ids,
        &bundle.manifest.implementation_identity_digests,
    ) {
        blockers.push(M7Blocker::ReviewerNotIndependent);
    }

    if let Err(error) = bundle.validate() {
        match error {
            M7FoundationError::MissingRequiredEvidence(
                M7EvidenceKind::IndependentReviewerRecommendation,
            ) => blockers.push(M7Blocker::ReviewerAbsent),
            M7FoundationError::MissingRequiredEvidence(kind) => {
                blockers.push(M7Blocker::MissingEvidenceLink(kind))
            }
            other => blockers.push(M7Blocker::InvalidBundle(other.to_string())),
        }
    }

    for required in mandatory_evidence_kinds() {
        if !bundle
            .evidence_links
            .iter()
            .any(|link| link.kind == required)
        {
            if required == M7EvidenceKind::IndependentReviewerRecommendation {
                if !blockers.contains(&M7Blocker::ReviewerAbsent) {
                    blockers.push(M7Blocker::ReviewerAbsent);
                }
            } else if !blockers.contains(&M7Blocker::MissingEvidenceLink(required)) {
                blockers.push(M7Blocker::MissingEvidenceLink(required));
            }
        }
    }

    for link in &bundle.evidence_links {
        match resolve_artifact(&bundle.manifest, link, resolver) {
            Ok(artifact) => {
                declared_source_links.extend(artifact.source_links.iter().cloned());
                match verify_artifact_sources(&bundle.manifest, link, &artifact, resolver) {
                    Ok(()) => {
                        if let Some(failure) = artifact.payload.semantic_failure() {
                            blockers.push(M7Blocker::SemanticFailure {
                                kind: link.kind,
                                failure,
                            });
                        } else {
                            verified_kinds.insert(link.kind);
                        }
                    }
                    Err(blocker) => blockers.push(blocker),
                }
                artifacts.insert(link.kind, artifact);
            }
            Err(blocker) => blockers.push(blocker),
        }
    }

    let active_surface_bindings = [
        artifacts
            .get(&M7EvidenceKind::M0TruthBaseline)
            .and_then(|artifact| match &artifact.payload {
                M7EvidencePayload::M0TruthBaseline(value) => {
                    Some(&value.active_surface_snapshot_digest)
                }
                _ => None,
            }),
        artifacts
            .get(&M7EvidenceKind::ClaimBoundary)
            .and_then(|artifact| match &artifact.payload {
                M7EvidencePayload::ClaimBoundary(value) => {
                    Some(&value.active_surface_snapshot_digest)
                }
                _ => None,
            }),
        artifacts
            .get(&M7EvidenceKind::PublicationPolicy)
            .and_then(|artifact| match &artifact.payload {
                M7EvidencePayload::PublicationPolicy(value) => {
                    Some(&value.active_surface_snapshot_digest)
                }
                _ => None,
            }),
    ];
    if let [Some(m0), Some(claims), Some(publication)] = active_surface_bindings
        && (m0 != claims || claims != publication)
    {
        blockers.push(M7Blocker::ActiveSurfaceSnapshotMismatch);
        verified_kinds.remove(&M7EvidenceKind::M0TruthBaseline);
        verified_kinds.remove(&M7EvidenceKind::ClaimBoundary);
        verified_kinds.remove(&M7EvidenceKind::PublicationPolicy);
    }

    if m5_export_lineage_mismatch(&artifacts) {
        blockers.push(M7Blocker::M5ExportLineageMismatch);
        for kind in [
            M7EvidenceKind::M1CandidateLifecycle,
            M7EvidenceKind::M2SchedulerWakeRestart,
            M7EvidenceKind::M3CapabilityEffects,
            M7EvidenceKind::M4WorkerEcology,
            M7EvidenceKind::M5ActivationRollback,
            M7EvidenceKind::M6FactoryExchange,
        ] {
            verified_kinds.remove(&kind);
        }
    }

    if m2_m4_lineage_mismatch(&artifacts) {
        blockers.push(M7Blocker::M2M4LineageMismatch);
        verified_kinds.remove(&M7EvidenceKind::M2SchedulerWakeRestart);
        verified_kinds.remove(&M7EvidenceKind::M4WorkerEcology);
    }

    if closure_chronology_mismatch(&bundle.manifest, &artifacts) {
        blockers.push(M7Blocker::ClosureChronologyMismatch);
        verified_kinds.remove(&M7EvidenceKind::M2SchedulerWakeRestart);
        verified_kinds.remove(&M7EvidenceKind::M5ActivationRollback);
        verified_kinds.remove(&M7EvidenceKind::M6FactoryExchange);
    }

    let capture_attestation_present = artifacts
        .get(&M7EvidenceKind::DeterministicTestTranscript)
        .is_some_and(|artifact| {
            artifact
                .source_links
                .iter()
                .any(|link| link.semantic_role == M7SourceRoleV2::SourceCaptureAttestation)
        });
    if !capture_attestation_present {
        blockers.push(M7Blocker::SourceCaptureAttestationAbsent);
    }
    let reviewer_attestation_present = artifacts
        .get(&M7EvidenceKind::IndependentReviewerRecommendation)
        .is_some_and(|artifact| {
            artifact
                .source_links
                .iter()
                .any(|link| link.semantic_role == M7SourceRoleV2::IndependentReview)
        });
    if !reviewer_attestation_present {
        blockers.push(M7Blocker::ReviewerCryptographicAttestationAbsent);
    }

    let expected_reviewed_set = bundle.reviewed_evidence_set_digest().ok();
    match artifacts.get(&M7EvidenceKind::IndependentReviewerRecommendation) {
        Some(M7EvidenceArtifact {
            payload: M7EvidencePayload::IndependentReviewerRecommendation(review),
            ..
        }) => {
            reviewer_recommendation = Some(review.recommendation);
            let identity_is_implementation = bundle
                .manifest
                .implementation_principal_ids
                .contains(&review.reviewer_id)
                || bundle
                    .manifest
                    .implementation_identity_digests
                    .contains(&review.reviewer_identity_digest)
                || bundle
                    .manifest
                    .implementation_identity_digests
                    .contains(&review.reviewer_public_key_digest);
            if identity_is_implementation {
                blockers.push(M7Blocker::ReviewerNotIndependent);
            }
            if review.reviewer_id != bundle.reviewer_identity.principal_id
                || review.reviewer_identity_digest != bundle.reviewer_identity.identity_digest
                || review.reviewer_public_key_digest != bundle.reviewer_identity.public_key_digest
            {
                blockers.push(M7Blocker::ReviewerCryptographicAttestationInvalid);
            }
            if review.reviewed_manifest_digest != bundle.manifest.manifest_digest
                || expected_reviewed_set.as_ref() != Some(&review.reviewed_evidence_set_digest)
            {
                blockers.push(M7Blocker::ReviewerScopeMismatch);
            }
        }
        Some(_) => blockers.push(M7Blocker::ReviewerScopeMismatch),
        None => {
            if !blockers.contains(&M7Blocker::ReviewerAbsent) {
                blockers.push(M7Blocker::ReviewerAbsent);
            }
        }
    }

    if let Some(link) = &bundle.live_provider_link {
        match resolve_artifact(&bundle.manifest, link, resolver) {
            Ok(
                ref artifact @ M7EvidenceArtifact {
                    payload: M7EvidencePayload::LiveProviderQualification(ref provider),
                    ..
                },
            ) => {
                declared_source_links.extend(artifact.source_links.iter().cloned());
                let source_valid =
                    match verify_artifact_sources(&bundle.manifest, link, &artifact, resolver) {
                        Ok(()) => true,
                        Err(blocker) => {
                            blockers.push(blocker);
                            live_provider_status = LiveProviderQualificationStatus::Invalid;
                            false
                        }
                    };
                if source_valid {
                    live_provider_evidence = Some(provider.clone());
                }
                let scope_matches = source_valid
                    && bundle
                        .manifest
                        .live_provider_scope
                        .as_ref()
                        .is_some_and(|scope| scope.scope_digest == provider.scope_digest);
                let m1_package_digests = artifacts
                    .get(&M7EvidenceKind::M1CandidateLifecycle)
                    .and_then(|artifact| match &artifact.payload {
                        M7EvidencePayload::M1CandidateLifecycle(candidate) => Some((
                            candidate.incumbent_package_digest.clone(),
                            candidate.candidate_package_digest.clone(),
                        )),
                        _ => None,
                    });
                let candidate_identity_matches =
                    m1_package_digests
                        .as_ref()
                        .is_some_and(|(incumbent, candidate)| {
                            incumbent == &provider.incumbent_package_digest
                                && candidate == &provider.target_package_digest
                        });
                if source_valid && !scope_matches {
                    blockers.push(M7Blocker::LiveProviderScopeMismatch);
                    live_provider_status = LiveProviderQualificationStatus::Invalid;
                } else if source_valid && !candidate_identity_matches {
                    blockers.push(M7Blocker::LiveProviderCandidateIdentityMismatch {
                        m1_incumbent_package_digest: m1_package_digests
                            .as_ref()
                            .map(|(incumbent, _)| incumbent.clone()),
                        m1_candidate_package_digest: m1_package_digests
                            .as_ref()
                            .map(|(_, candidate)| candidate.clone()),
                        provider_incumbent_package_digest: provider
                            .incumbent_package_digest
                            .clone(),
                        provider_target_package_digest: provider.target_package_digest.clone(),
                    });
                    live_provider_status = LiveProviderQualificationStatus::Invalid;
                } else if source_valid
                    && let Some(failure) =
                        M7EvidencePayload::LiveProviderQualification(provider.clone())
                            .semantic_failure()
                {
                    blockers.push(M7Blocker::SemanticFailure {
                        kind: M7EvidenceKind::LiveProviderQualification,
                        failure,
                    });
                    live_provider_status = LiveProviderQualificationStatus::Invalid;
                } else if source_valid {
                    live_provider_status = LiveProviderQualificationStatus::Qualified;
                    verified_kinds.insert(M7EvidenceKind::LiveProviderQualification);
                }
            }
            Ok(_) => {
                blockers.push(M7Blocker::LiveProviderScopeMismatch);
                live_provider_status = LiveProviderQualificationStatus::Invalid;
            }
            Err(blocker) => {
                blockers.push(blocker);
                live_provider_status = LiveProviderQualificationStatus::Invalid;
            }
        }
    }
    if live_provider_status != LiveProviderQualificationStatus::Qualified {
        blockers.push(M7Blocker::LiveProviderQualificationIncomplete(
            live_provider_status,
        ));
    }

    if m5_current_run_lineage_mismatch(
        &bundle.manifest,
        &artifacts,
        live_provider_evidence.as_ref(),
    ) {
        if !blockers.contains(&M7Blocker::M5ExportLineageMismatch) {
            blockers.push(M7Blocker::M5ExportLineageMismatch);
        }
        for kind in [
            M7EvidenceKind::M1CandidateLifecycle,
            M7EvidenceKind::M2SchedulerWakeRestart,
            M7EvidenceKind::M3CapabilityEffects,
            M7EvidenceKind::M4WorkerEcology,
            M7EvidenceKind::M5ActivationRollback,
            M7EvidenceKind::M6FactoryExchange,
            M7EvidenceKind::LiveProviderQualification,
        ] {
            verified_kinds.remove(&kind);
        }
        if bundle.manifest.live_provider_scope.is_some() {
            live_provider_status = LiveProviderQualificationStatus::Invalid;
        }
    }

    if let Err(failure) = verify_source_capture_inventory(
        &bundle.manifest,
        &artifacts,
        &declared_source_links,
        resolver,
    ) {
        blockers.push(M7Blocker::SourceCaptureInventoryFailure(failure));
    }

    declared_source_links.sort_by(|left, right| {
        (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
    });
    declared_source_links.dedup();
    if declared_source_links != bundle.source_links {
        blockers.push(M7Blocker::SourceClosureMismatch);
    }

    let evidence_complete = blockers.is_empty();
    let publication_pending = verified_kinds.contains(&M7EvidenceKind::M0TruthBaseline)
        && artifacts
            .get(&M7EvidenceKind::M0TruthBaseline)
            .is_some_and(|artifact| {
                matches!(
                    &artifact.payload,
                    M7EvidencePayload::M0TruthBaseline(M0TruthEvidence {
                        pre_run_operational_decision: M7ClosureDecision::NotYet,
                        ..
                    })
                )
            });
    let (decision, caveats) = decision_with_publication_state(
        evidence_complete,
        reviewer_recommendation,
        publication_pending,
    );
    M7Evaluation {
        decision,
        evidence_complete,
        reviewer_recommendation,
        caveats,
        verified_kinds,
        blockers,
        bundle_digest: bundle.bundle_digest.clone(),
        live_provider_status,
    }
}

fn decision_with_publication_state(
    evidence_complete: bool,
    reviewer_recommendation: Option<M7ClosureDecision>,
    publication_pending: bool,
) -> (M7ClosureDecision, BTreeSet<M7EvaluationCaveatV1>) {
    let reviewer_decision = reviewer_recommendation.unwrap_or(M7ClosureDecision::NotYet);
    if !evidence_complete {
        return (M7ClosureDecision::NotYet, BTreeSet::new());
    }
    let caveats = if publication_pending && reviewer_decision != M7ClosureDecision::NotYet {
        BTreeSet::from([M7EvaluationCaveatV1::PublicationPendingActiveSurfacesNotYet])
    } else {
        BTreeSet::new()
    };
    let decision = if publication_pending && reviewer_decision == M7ClosureDecision::Closed {
        M7ClosureDecision::ClosedWithCaveats
    } else {
        reviewer_decision
    };
    (decision, caveats)
}

fn resolve_artifact<R: EvidenceResolver>(
    manifest: &M7ProofRunManifest,
    link: &M7EvidenceLink,
    resolver: &R,
) -> Result<M7EvidenceArtifact, M7Blocker> {
    let bytes = match resolver.resolve(&link.digest) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Err(M7Blocker::MissingEvidenceBytes(link.kind)),
        Err(_) => return Err(M7Blocker::ResolverFailure(link.kind)),
    };
    if bytes.len() as u64 != link.byte_length {
        return Err(M7Blocker::LengthMismatch(link.kind));
    }
    if ContentDigest::from_bytes(&bytes) != link.digest {
        return Err(M7Blocker::DigestMismatch(link.kind));
    }
    let artifact: M7EvidenceArtifact =
        serde_json::from_slice(&bytes).map_err(|_| M7Blocker::MalformedEvidence(link.kind))?;
    let canonical =
        canonical_json(&artifact).map_err(|_| M7Blocker::MalformedEvidence(link.kind))?;
    if canonical != bytes {
        return Err(M7Blocker::NonCanonicalEvidence(link.kind));
    }
    artifact
        .validate_structure()
        .map_err(|_| M7Blocker::SchemaMismatch(link.kind))?;
    if artifact.kind != link.kind || artifact.schema != link.kind.schema() {
        return Err(M7Blocker::SchemaMismatch(link.kind));
    }
    if artifact.owner_milestone != link.owner_milestone {
        return Err(M7Blocker::OwnerMismatch(link.kind));
    }
    if artifact.proof_run_id != link.proof_run_id || artifact.proof_run_id != manifest.proof_run_id
    {
        return Err(M7Blocker::CrossRunEvidence(link.kind));
    }
    if artifact.manifest_digest != manifest.manifest_digest {
        return Err(M7Blocker::StaleManifestEvidence(link.kind));
    }
    if artifact.causal_subject != link.causal_subject
        || artifact.causal_subject.proof_chain_digest != manifest.causal_chain_digest
    {
        return Err(M7Blocker::CausalMismatch(link.kind));
    }
    Ok(artifact)
}

fn verify_source_capture_inventory<R: EvidenceResolver>(
    manifest: &M7ProofRunManifest,
    artifacts: &BTreeMap<M7EvidenceKind, M7EvidenceArtifact>,
    declared_source_links: &[M7SourceLinkV2],
    resolver: &R,
) -> Result<(), M7SourceCaptureInventoryFailure> {
    let capture_link = artifacts
        .get(&M7EvidenceKind::DeterministicTestTranscript)
        .and_then(|artifact| {
            artifact
                .source_links
                .iter()
                .find(|link| link.semantic_role == M7SourceRoleV2::SourceCaptureAttestation)
        })
        .ok_or(M7SourceCaptureInventoryFailure::AttestationUnavailable)?;
    let bytes = resolver
        .resolve(&capture_link.digest)
        .map_err(|_| M7SourceCaptureInventoryFailure::AttestationUnavailable)?
        .ok_or(M7SourceCaptureInventoryFailure::AttestationUnavailable)?;
    if bytes.len() as u64 != capture_link.byte_length
        || ContentDigest::from_bytes(&bytes) != capture_link.digest
    {
        return Err(M7SourceCaptureInventoryFailure::AttestationInvalid);
    }
    let capture = M7SourceCaptureAttestationV2::from_canonical_bytes_unbound(&bytes)
        .map_err(|_| M7SourceCaptureInventoryFailure::AttestationInvalid)?;
    if let Some(failure) =
        source_capture_inventory_failure(manifest, &capture.captured_source_links)
    {
        return Err(failure);
    }
    capture
        .validate_for(manifest)
        .map_err(|_| M7SourceCaptureInventoryFailure::AttestationInvalid)?;

    compare_source_capture_inventory(&capture.captured_source_links, declared_source_links)
}

fn compare_source_capture_inventory(
    signed_source_links: &[M7SourceLinkV2],
    declared_source_links: &[M7SourceLinkV2],
) -> Result<(), M7SourceCaptureInventoryFailure> {
    let mut actual = declared_source_links
        .iter()
        .filter(|link| {
            !matches!(
                link.semantic_role,
                M7SourceRoleV2::SourceCaptureAttestation | M7SourceRoleV2::IndependentReview
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    actual.sort_by(|left, right| {
        (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
    });
    let mut actual_by_role = BTreeMap::new();
    for link in actual {
        let role = link.semantic_role;
        if actual_by_role.insert(role, link).is_some() {
            return Err(M7SourceCaptureInventoryFailure::LinkMismatch(role));
        }
    }
    for signed in signed_source_links {
        match actual_by_role.remove(&signed.semantic_role) {
            Some(declared) if declared == *signed => {}
            _ => {
                return Err(M7SourceCaptureInventoryFailure::LinkMismatch(
                    signed.semantic_role,
                ));
            }
        }
    }
    if let Some(role) = actual_by_role.into_keys().next() {
        return Err(M7SourceCaptureInventoryFailure::LinkMismatch(role));
    }
    Ok(())
}

fn verify_artifact_sources<R: EvidenceResolver>(
    manifest: &M7ProofRunManifest,
    evidence_link: &M7EvidenceLink,
    artifact: &M7EvidenceArtifact,
    resolver: &R,
) -> Result<(), M7Blocker> {
    if artifact.source_links.is_empty() {
        return Err(M7Blocker::MissingAuthoritativeSource(artifact.kind));
    }
    let actual_roles: BTreeSet<_> = artifact
        .source_links
        .iter()
        .map(|link| link.semantic_role)
        .collect();
    if actual_roles != expected_source_roles(artifact.kind) {
        return Err(M7Blocker::MissingAuthoritativeSource(artifact.kind));
    }
    let mut sources = BTreeMap::new();
    for link in &artifact.source_links {
        if link.digest == evidence_link.digest {
            return Err(M7Blocker::SourceSelfReference(artifact.kind));
        }
        if link
            .validate_for(manifest, artifact.kind, &artifact.causal_subject)
            .is_err()
        {
            return Err(M7Blocker::InvalidAuthoritativeSource {
                kind: artifact.kind,
                role: Some(link.semantic_role),
            });
        }
        let bytes = match resolver.resolve(&link.digest) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return Err(M7Blocker::MissingSourceBytes {
                    kind: artifact.kind,
                    role: link.semantic_role,
                });
            }
            Err(_) => {
                return Err(M7Blocker::SourceResolverFailure {
                    kind: artifact.kind,
                    role: link.semantic_role,
                });
            }
        };
        if bytes.len() as u64 != link.byte_length {
            return Err(M7Blocker::SourceLengthMismatch {
                kind: artifact.kind,
                role: link.semantic_role,
            });
        }
        if ContentDigest::from_bytes(&bytes) != link.digest {
            return Err(M7Blocker::SourceDigestMismatch {
                kind: artifact.kind,
                role: link.semantic_role,
            });
        }
        if !detect_active_surface_secret_rules(&bytes).is_empty()
            || validate_source_bytes(link.semantic_role, &bytes).is_err()
        {
            return Err(M7Blocker::InvalidAuthoritativeSource {
                kind: artifact.kind,
                role: Some(link.semantic_role),
            });
        }
        if sources.insert(link.semantic_role, bytes).is_some() {
            return Err(M7Blocker::InvalidAuthoritativeSource {
                kind: artifact.kind,
                role: Some(link.semantic_role),
            });
        }
    }
    let subject_inputs = sources
        .iter()
        .map(|(role, bytes)| M7SourceInputV2::new(*role, bytes.clone()))
        .collect::<Vec<_>>();
    let expected_subject = M7EvidenceArtifact::derive_causal_subject_from_sources(
        manifest,
        artifact.kind,
        &subject_inputs,
    )
    .map_err(|_| M7Blocker::InvalidAuthoritativeSource {
        kind: artifact.kind,
        role: None,
    })?;
    if artifact.causal_subject != expected_subject {
        return Err(M7Blocker::CausalMismatch(artifact.kind));
    }
    let expected = derive_payload(artifact.kind, manifest, &artifact.causal_subject, &sources)
        .map_err(|_| M7Blocker::InvalidAuthoritativeSource {
            kind: artifact.kind,
            role: None,
        })?;
    if expected != artifact.payload {
        return Err(M7Blocker::SourcePayloadMismatch(artifact.kind));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), M7FoundationError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(M7FoundationError::InvalidIdentifier {
            field,
            limit: MAX_IDENTIFIER_BYTES,
        });
    }
    Ok(())
}

fn identity_reuses_implementation_path(
    identity: &M7ExternalEd25519IdentityV1,
    implementation_principal_ids: &BTreeSet<String>,
    implementation_identity_digests: &BTreeSet<ContentDigest>,
) -> bool {
    implementation_principal_ids.contains(identity.principal_id())
        || implementation_identity_digests.contains(identity.identity_digest())
        || implementation_identity_digests.contains(identity.public_key_digest())
}

fn external_identities_reuse_key(
    left: &M7ExternalEd25519IdentityV1,
    right: &M7ExternalEd25519IdentityV1,
) -> bool {
    left.principal_id == right.principal_id
        || left.identity_digest == right.identity_digest
        || left.public_key_digest == right.public_key_digest
}

fn signature_preimage(domain: &[u8], digest: &ContentDigest) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(domain.len() + digest.as_str().len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(digest.as_str().as_bytes());
    preimage
}

fn verify_external_signature(
    identity: &M7ExternalEd25519IdentityV1,
    preimage: &[u8],
    signature_hex: &str,
    subject: &str,
) -> Result<(), M7FoundationError> {
    identity.validate()?;
    let public_key = identity.public_key_bytes()?;
    let signature = hex_decode(signature_hex).map_err(M7FoundationError::InvalidSource)?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(M7FoundationError::InvalidSource(format!(
            "{subject} Ed25519 signature has the wrong length"
        )));
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(preimage, &signature)
        .map_err(|_| {
            M7FoundationError::InvalidSource(format!(
                "{subject} Ed25519 signature verification failed"
            ))
        })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex value has an odd length".to_string());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("hex value contains a non-hexadecimal character".to_string()),
    }
}

fn parse_source_record<T, F>(bytes: &[u8], validate: F) -> Result<T, M7FoundationError>
where
    T: for<'de> Deserialize<'de> + Serialize,
    F: FnOnce(&T) -> Result<(), M7FoundationError>,
{
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
        return Err(M7FoundationError::InvalidSource(
            "source record is empty or outside bounds".to_string(),
        ));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| M7FoundationError::Serialization(error.to_string()))?;
    if canonical_json(&value)? != bytes {
        return Err(M7FoundationError::InvalidSource(
            "source record is not canonical JSON".to_string(),
        ));
    }
    validate(&value)?;
    Ok(value)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, M7FoundationError> {
    serde_json::to_vec_pretty(value)
        .map_err(|error| M7FoundationError::Serialization(error.to_string()))
}

fn compact_json<T: Serialize>(value: &T) -> Result<Vec<u8>, M7FoundationError> {
    serde_json::to_vec(value).map_err(|error| M7FoundationError::Serialization(error.to_string()))
}

fn parse_compact_json<T, F>(
    bytes: &[u8],
    subject: &str,
    validate: F,
) -> Result<T, M7FoundationError>
where
    T: for<'de> Deserialize<'de> + Serialize,
    F: FnOnce(&T) -> Result<(), M7FoundationError>,
{
    if bytes.is_empty() || bytes.len() > MAX_ACTIVE_SURFACE_BYTES {
        return Err(M7FoundationError::InvalidSource(format!(
            "{subject} is empty or outside its byte bound"
        )));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| M7FoundationError::Serialization(error.to_string()))?;
    if compact_json(&value)? != bytes {
        return Err(M7FoundationError::InvalidSource(format!(
            "{subject} is not compact canonical JSON"
        )));
    }
    validate(&value)?;
    Ok(value)
}

fn digest<T: Serialize>(value: &T) -> Result<ContentDigest, M7FoundationError> {
    digest_json_content(value).map_err(|error| M7FoundationError::Serialization(error.to_string()))
}

fn require_digest(
    subject: &str,
    actual: &ContentDigest,
    expected: &ContentDigest,
) -> Result<(), M7FoundationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(M7FoundationError::Integrity(format!(
            "{subject} digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

#[derive(Debug)]
pub enum M7FoundationError {
    InvalidIdentifier { field: &'static str, limit: usize },
    InvalidCriteria(String),
    InvalidManifest(String),
    InvalidEvidenceLink(String),
    InvalidEvidence(String),
    InvalidSource(String),
    UnsupportedSource(String),
    InvalidBundle(String),
    MissingRequiredEvidence(M7EvidenceKind),
    DuplicateEvidenceKind(M7EvidenceKind),
    Integrity(String),
    Serialization(String),
}

impl Display for M7FoundationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIdentifier { field, limit } => write!(
                formatter,
                "{field} must contain 1..={limit} non-control bytes"
            ),
            Self::InvalidCriteria(message) => {
                write!(formatter, "invalid M7 frozen criteria: {message}")
            }
            Self::InvalidManifest(message) => {
                write!(formatter, "invalid M7 proof-run manifest: {message}")
            }
            Self::InvalidEvidenceLink(message) => {
                write!(formatter, "invalid M7 evidence link: {message}")
            }
            Self::InvalidEvidence(message) => {
                write!(formatter, "invalid M7 evidence: {message}")
            }
            Self::InvalidSource(message) => {
                write!(formatter, "invalid M7 authoritative source: {message}")
            }
            Self::UnsupportedSource(message) => {
                write!(formatter, "unsupported M7 authoritative source: {message}")
            }
            Self::InvalidBundle(message) => {
                write!(formatter, "invalid M7 final bundle: {message}")
            }
            Self::MissingRequiredEvidence(kind) => {
                write!(formatter, "M7 bundle is missing required evidence {kind:?}")
            }
            Self::DuplicateEvidenceKind(kind) => {
                write!(formatter, "M7 bundle repeats evidence kind {kind:?}")
            }
            Self::Integrity(message) => {
                write!(formatter, "M7 evidence integrity failure: {message}")
            }
            Self::Serialization(message) => {
                write!(formatter, "M7 serialization failed: {message}")
            }
        }
    }
}

impl Error for M7FoundationError {}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::execution::component::ComponentExecutionLimits;
    use crate::execution::inference::{
        InferenceFinishReason, InferenceGenerationPolicy, InferenceProviderMode,
        InferenceProviderModelEntry, InferenceProviderRegistryEntry, InferenceRetryClassification,
    };
    use crate::factory_reproduction::{
        ApprovalDecision, BenchmarkSpec, CycleOutcome, InvariantKind, InvariantSpec,
        LIVE_PROVIDER_QUALIFICATION_SCHEMA, LiveProviderQualificationRecord, LiveProviderTurn,
        M5ProviderAccountingSummaryV1, M5ProviderAttemptSummaryV1, MutableFactoryPolicy,
        ParsedProviderIntent, ProviderQualificationStatus, ProviderReplayRecord,
        ProviderReplayRequest, ProviderTransport, RecursionBudgets, RedactedTranscript,
        ReleaseGate, ReleaseThresholds, StateCompatibility,
    };
    use crate::local_runtime::{
        LocalRunStatus, LocalRuntimeService, LocalRuntimeWorkspace, build_router,
    };
    use crate::m1_validation::{ValidationCase, ValidationSuite};
    use crate::m5_effect_port::M5M3EffectReference;
    use crate::m5_effect_store::{FactoryProviderProposalRequest, FactoryProviderProposalResult};
    use crate::m5_provider_binding::{
        PROVIDER_CANDIDATE_INTENT_SCHEMA, PROVIDER_CANDIDATE_OPERATION, ProviderCandidateBinding,
        ProviderProposalEvidence,
    };
    use crate::m5_provider_execution::M5ProviderExecutionReceiptV1;
    use crate::m5_runtime::{
        GovernedLiveProviderConfig, GovernedLiveProviderPort, M5ChallengedProviderSeedV1,
        M5InitializationAuthority, M5Runtime, M5RuntimeConfig, M5SeedCyclePlan,
    };
    use crate::supervisor::{
        ApprovalResolutionKind, ApprovalResolutionRecord, EffectCommit, JobExecutionResult,
        LocalDurableSupervisor, RetryPolicy, SubmitJobRequest, SupervisorClock,
    };
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header::CONTENT_TYPE};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, OnceLock};
    use tower::ServiceExt;

    static M5_TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    static ACTIVE_SURFACE_TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const CAPTURE_ATTESTOR_SEED: [u8; 32] = [0x71; 32];
    const REVIEWER_ATTESTOR_SEED: [u8; 32] = [0x72; 32];

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

    async fn exact_json_router_body(router: &axum::Router, path: &str) -> Vec<u8> {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("active-surface HTTP request"),
            )
            .await
            .expect("active-surface HTTP response");
        let status = response.status();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = to_bytes(response.into_body(), MAX_ACTIVE_SURFACE_BYTES)
            .await
            .expect("bounded active-surface HTTP body");
        assert_eq!(
            status,
            StatusCode::OK,
            "{path} must be an actual successful router response; body_bytes={}",
            body.len()
        );
        assert_eq!(
            content_type.as_deref(),
            Some("application/json"),
            "{path} must be the actual JSON router representation; body_bytes={}",
            body.len()
        );
        body.to_vec()
    }

    async fn seed_historical_phase04_closure_corpus(service: &LocalRuntimeService) {
        // Materialize the same persisted corpus exercised by the public Phase
        // 04 acceptance path. The capture must observe the real router over
        // real runtime records; a constructed Closed response would make the
        // historical/current truth boundary circular.
        for scenario_id in [
            "supervisor-v4-live-shell-runner-path",
            "supervisor-northstar-live-persistent-shell-program",
            "supervisor-phase-b-live-factory-artifact-family",
            "supervisor-phase-c-live-bounded-factory-replication",
            "supervisor-phase-d-live-prefederation-exchange-contracts",
        ] {
            service
                .run_headless(scenario_id)
                .await
                .unwrap_or_else(|error| {
                    panic!("seed historical Phase 04 completed scenario `{scenario_id}`: {error}")
                });
        }

        let expired = service
            .start_run("supervisor-durable-fixed-interface-continuous-self-hosting-program")
            .await
            .expect("seed historical Phase 04 approval-expiry run");
        assert_eq!(expired.summary.status, LocalRunStatus::AwaitingApproval);
        let expired = service
            .expire_approval(&expired.summary.run_id)
            .await
            .expect("materialize historical Phase 04 approval-expiry outcome");
        assert_eq!(expired.summary.status, LocalRunStatus::Failed);

        let escalated = service
            .start_run("supervisor-durable-fixed-interface-continuous-self-hosting-program")
            .await
            .expect("seed historical Phase 04 approval-escalation run");
        assert_eq!(escalated.summary.status, LocalRunStatus::AwaitingApproval);
        let escalated = service
            .escalate_approval(&escalated.summary.run_id)
            .await
            .expect("materialize historical Phase 04 approval-escalation outcome");
        assert_eq!(escalated.summary.status, LocalRunStatus::Paused);

        let rollback_ready = service
            .start_run("supervisor-background-quarantine-rollback-control-loop")
            .await
            .expect("seed historical Phase 04 rollback-ready run");
        assert_eq!(
            rollback_ready.summary.status,
            LocalRunStatus::AwaitingRollback
        );
    }

    pub(crate) fn exact_active_surface_snapshot() -> M7ActiveSurfaceSnapshotV1 {
        static SNAPSHOT: OnceLock<M7ActiveSurfaceSnapshotV1> = OnceLock::new();
        SNAPSHOT
            .get_or_init(|| {
                let root = std::env::temp_dir().join(format!(
                    "wasm-biotic-m7-active-surfaces-{}-{}",
                    std::process::id(),
                    ACTIVE_SURFACE_TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir(&root).expect("create active-surface test root");
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("active-surface test runtime");
                let snapshot = runtime.block_on(async {
                    let workspace = LocalRuntimeWorkspace::bootstrap(&root)
                        .expect("active-surface test workspace");
                    let service = LocalRuntimeService::new(workspace)
                        .await
                        .expect("active-surface test service");
                    seed_historical_phase04_closure_corpus(&service).await;
                    let router = build_router(Arc::new(service));
                    M7ActiveSurfaceSnapshotV1::from_fixture_surface_bytes(
                        M7ActiveSurfaceInputBytesV1::new(
                            include_bytes!("../README.md").to_vec(),
                            include_bytes!("../notes/ROADMAP.md").to_vec(),
                            exact_json_router_body(&router, "/api/system/overview").await,
                            exact_json_router_body(&router, "/api/home/general-audience").await,
                            exact_json_router_body(&router, "/api/northstar/07/closure-review")
                                .await,
                            exact_json_router_body(
                                &router,
                                "/api/remediation/phase-04/final-closure-rereview",
                            )
                            .await,
                            exact_json_router_body(
                                &router,
                                "/api/remediation/phase-04/publication-policy",
                            )
                            .await,
                        ),
                    )
                    .expect("exact active-surface snapshot")
                });
                drop(runtime);
                let _ = std::fs::remove_dir_all(&root);
                snapshot
            })
            .clone()
    }

    fn synthetic_inventory_link(
        manifest: &M7ProofRunManifest,
        role: M7SourceRoleV2,
    ) -> M7SourceLinkV2 {
        M7SourceLinkV2 {
            schema: M7_SOURCE_LINK_SCHEMA.to_string(),
            semantic_role: role,
            source_kind: role.source_kind(),
            source_schema: role.source_schema().to_string(),
            proof_run_id: manifest.proof_run_id.clone(),
            manifest_digest: manifest.manifest_digest.clone(),
            causal_subject: M7CausalSubject {
                kind: role.evidence_kind().expected_causal_kind(),
                subject_digest: content(&format!("inventory-subject:{role:?}")),
                proof_chain_digest: manifest.causal_chain_digest.clone(),
            },
            digest: content(&format!("inventory-bytes:{role:?}")),
            byte_length: 1,
        }
    }

    pub(crate) fn synthetic_capture_inventory_for_fixture(
        manifest: &M7ProofRunManifest,
        transcript: &[u8],
    ) -> Vec<M7SourceLinkV2> {
        let mut inventory = required_source_capture_roles(manifest)
            .into_iter()
            .map(|role| synthetic_inventory_link(manifest, role))
            .collect::<Vec<_>>();
        let transcript_input =
            M7SourceInputV2::new(M7SourceRoleV2::CargoTestTranscript, transcript.to_vec());
        let transcript_subject = M7EvidenceArtifact::derive_causal_subject_from_sources(
            manifest,
            M7EvidenceKind::DeterministicTestTranscript,
            std::slice::from_ref(&transcript_input),
        )
        .expect("transcript causal subject");
        let transcript_link = M7SourceLinkV2::from_source_bytes(
            manifest,
            transcript_subject,
            M7SourceRoleV2::CargoTestTranscript,
            transcript,
        )
        .expect("transcript inventory link");
        *inventory
            .iter_mut()
            .find(|link| link.semantic_role == M7SourceRoleV2::CargoTestTranscript)
            .expect("transcript inventory role") = transcript_link;
        inventory.sort_by(|left, right| {
            (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
        });
        inventory
    }

    fn signed_capture_for_transcript(
        manifest: &M7ProofRunManifest,
        transcript: &[u8],
    ) -> M7SourceCaptureAttestationV2 {
        let inventory = synthetic_capture_inventory_for_fixture(manifest, transcript);
        let key = test_attestor(CAPTURE_ATTESTOR_SEED);
        let preimage = M7SourceCaptureAttestationV2::signing_preimage(manifest, &inventory, 300)
            .expect("capture preimage");
        let signature = key.sign(&preimage);
        M7SourceCaptureAttestationV2::from_external_signature(
            manifest,
            &inventory,
            300,
            signature.as_ref(),
        )
        .expect("signed capture attestation")
    }

    fn signed_capture_sources(
        manifest: &M7ProofRunManifest,
    ) -> (Vec<u8>, M7SourceCaptureAttestationV2) {
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
        .expect("capture transcript")
        .canonical_bytes()
        .expect("capture transcript bytes");
        let attestation = signed_capture_for_transcript(manifest, &transcript);
        (transcript, attestation)
    }

    fn signed_capture_evidence(manifest: &M7ProofRunManifest) -> M7DerivedEvidenceV2 {
        let (transcript, attestation) = signed_capture_sources(manifest);
        let attestation_bytes = attestation
            .canonical_bytes(manifest)
            .expect("capture attestation bytes");
        M7EvidenceArtifact::derive_from_sources(
            manifest,
            M7EvidenceKind::DeterministicTestTranscript,
            vec![
                M7SourceInputV2::new(M7SourceRoleV2::CargoTestTranscript, transcript),
                M7SourceInputV2::new(M7SourceRoleV2::SourceCaptureAttestation, attestation_bytes),
            ],
        )
        .expect("signed capture evidence")
    }

    #[test]
    fn causal_subject_derivation_is_canonical_and_matches_source_capture() {
        let manifest = manifest(None);
        let (before, after) = exact_m2_supervisor_states();
        let inputs = vec![
            M7SourceInputV2::new(
                M7SourceRoleV2::SupervisorPreRestart,
                supervisor_state_bytes(&before),
            ),
            M7SourceInputV2::new(
                M7SourceRoleV2::SupervisorPostRestart,
                supervisor_state_bytes(&after),
            ),
        ];
        let mut reversed = inputs.clone();
        reversed.reverse();
        let canonical = M7EvidenceArtifact::derive_causal_subject_from_sources(
            &manifest,
            M7EvidenceKind::M2SchedulerWakeRestart,
            &inputs,
        )
        .expect("derive canonical causal subject");
        assert_eq!(
            canonical,
            M7EvidenceArtifact::derive_causal_subject_from_sources(
                &manifest,
                M7EvidenceKind::M2SchedulerWakeRestart,
                &reversed,
            )
            .expect("derive order-independent causal subject")
        );
        let derived = M7EvidenceArtifact::derive_from_sources(
            &manifest,
            M7EvidenceKind::M2SchedulerWakeRestart,
            inputs,
        )
        .expect("derive M2 artifact");
        assert_eq!(
            derived
                .artifact()
                .evidence_link()
                .expect("M2 evidence link")
                .causal_subject,
            canonical
        );

        let (transcript, capture) = signed_capture_sources(&manifest);
        let pre_capture = M7EvidenceArtifact::derive_causal_subject_from_sources(
            &manifest,
            M7EvidenceKind::DeterministicTestTranscript,
            &[M7SourceInputV2::new(
                M7SourceRoleV2::CargoTestTranscript,
                transcript.clone(),
            )],
        )
        .expect("derive pre-capture transcript subject");
        let final_evidence = M7EvidenceArtifact::derive_from_sources(
            &manifest,
            M7EvidenceKind::DeterministicTestTranscript,
            vec![
                M7SourceInputV2::new(M7SourceRoleV2::CargoTestTranscript, transcript),
                M7SourceInputV2::new(
                    M7SourceRoleV2::SourceCaptureAttestation,
                    capture
                        .canonical_bytes(&manifest)
                        .expect("capture attestation bytes"),
                ),
            ],
        )
        .expect("derive post-capture transcript evidence");
        assert_eq!(
            final_evidence
                .artifact()
                .evidence_link()
                .expect("transcript evidence link")
                .causal_subject,
            pre_capture
        );
    }

    #[test]
    fn causal_subject_changes_with_source_role_kind_run_and_exact_bytes() {
        let manifest = manifest(None);
        let transcript = |passed: u32| {
            M7CargoTestTranscriptV2::new(
                M7_DETERMINISTIC_CARGO_TEST_COMMAND
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                manifest.manifest_digest().clone(),
                format!(
                    "test result: ok. {passed} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n"
                ),
                String::new(),
                0,
            )
            .expect("Cargo transcript")
            .canonical_bytes()
            .expect("Cargo transcript bytes")
        };
        let transcript_subject = |bytes: Vec<u8>| {
            M7EvidenceArtifact::derive_causal_subject_from_sources(
                &manifest,
                M7EvidenceKind::DeterministicTestTranscript,
                &[M7SourceInputV2::new(
                    M7SourceRoleV2::CargoTestTranscript,
                    bytes,
                )],
            )
            .expect("transcript causal subject")
        };
        assert_ne!(
            transcript_subject(transcript(12)).subject_digest,
            transcript_subject(transcript(13)).subject_digest,
            "one valid source-byte change must change the causal subject"
        );

        let (before, after) = exact_m2_supervisor_states();
        let before_bytes = supervisor_state_bytes(&before);
        let after_bytes = supervisor_state_bytes(&after);
        let role_order = |pre: Vec<u8>, post: Vec<u8>| {
            M7EvidenceArtifact::derive_causal_subject_from_sources(
                &manifest,
                M7EvidenceKind::M2SchedulerWakeRestart,
                &[
                    M7SourceInputV2::new(M7SourceRoleV2::SupervisorPreRestart, pre),
                    M7SourceInputV2::new(M7SourceRoleV2::SupervisorPostRestart, post),
                ],
            )
            .expect("M2 causal subject")
        };
        let canonical_role_subject = role_order(before_bytes.clone(), after_bytes.clone());
        assert_ne!(
            canonical_role_subject.subject_digest,
            role_order(after_bytes.clone(), before_bytes.clone()).subject_digest,
            "relabeling valid bytes under the opposite semantic roles must change the subject"
        );

        let (m5_export, _) = exact_m5_source_bytes();
        let m1_subject = M7EvidenceArtifact::derive_causal_subject_from_sources(
            &manifest,
            M7EvidenceKind::M1CandidateLifecycle,
            &[M7SourceInputV2::new(
                M7SourceRoleV2::M5ExportM1,
                m5_export.clone(),
            )],
        )
        .expect("M1 causal subject");
        let m3_subject = M7EvidenceArtifact::derive_causal_subject_from_sources(
            &manifest,
            M7EvidenceKind::M3CapabilityEffects,
            &[M7SourceInputV2::new(
                M7SourceRoleV2::M5ExportM3,
                m5_export.clone(),
            )],
        )
        .expect("M3 causal subject");
        assert_ne!(m1_subject.subject_digest, m3_subject.subject_digest);
        assert!(
            M7EvidenceArtifact::derive_causal_subject_from_sources(
                &manifest,
                M7EvidenceKind::M3CapabilityEffects,
                &[M7SourceInputV2::new(M7SourceRoleV2::M5ExportM1, m5_export)],
            )
            .is_err(),
            "a source role cannot be replayed under another evidence kind"
        );

        let mut other_manifest = manifest.clone();
        other_manifest.proof_run_id = "proof-run:m7:replay".to_string();
        other_manifest.manifest_digest = other_manifest
            .expected_digest()
            .expect("other manifest digest");
        other_manifest.validate().expect("other manifest");
        let other_run_subject = M7EvidenceArtifact::derive_causal_subject_from_sources(
            &other_manifest,
            M7EvidenceKind::M2SchedulerWakeRestart,
            &[
                M7SourceInputV2::new(M7SourceRoleV2::SupervisorPreRestart, before_bytes),
                M7SourceInputV2::new(M7SourceRoleV2::SupervisorPostRestart, after_bytes),
            ],
        )
        .expect("same sources under another valid proof run");
        assert_ne!(
            canonical_role_subject.subject_digest, other_run_subject.subject_digest,
            "the proof-run manifest is part of the causal-subject domain"
        );
        let source = transcript(12);
        let original = transcript_subject(source.clone());
        let replayed = M7EvidenceArtifact::derive_causal_subject_from_sources(
            &other_manifest,
            M7EvidenceKind::DeterministicTestTranscript,
            &[M7SourceInputV2::new(
                M7SourceRoleV2::CargoTestTranscript,
                source,
            )],
        )
        .expect("derive the same exact transcript under another manifest domain");
        assert_ne!(
            original.subject_digest, replayed.subject_digest,
            "the same exact transcript cannot retain its causal subject across proof runs"
        );
        assert_eq!(original.proof_chain_digest, manifest.causal_chain_digest);
    }

    #[test]
    fn caller_relabelled_subject_is_rejected_when_exact_sources_are_replayed() {
        let manifest = manifest(None);
        let (before, after) = exact_m2_supervisor_states();
        let derived = M7EvidenceArtifact::derive_from_sources(
            &manifest,
            M7EvidenceKind::M2SchedulerWakeRestart,
            vec![
                M7SourceInputV2::new(
                    M7SourceRoleV2::SupervisorPreRestart,
                    supervisor_state_bytes(&before),
                ),
                M7SourceInputV2::new(
                    M7SourceRoleV2::SupervisorPostRestart,
                    supervisor_state_bytes(&after),
                ),
            ],
        )
        .expect("derive M2 evidence");
        let mut relabelled = derived.artifact().clone();
        let forged = content("caller-supplied-relabel");
        relabelled.causal_subject.subject_digest = forged.clone();
        for link in &mut relabelled.source_links {
            link.causal_subject.subject_digest = forged.clone();
        }
        relabelled
            .validate_structure()
            .expect("the old structural check alone cannot detect a consistent relabel");
        let evidence_link = relabelled
            .evidence_link()
            .expect("relabelled evidence link");
        let mut resolver = MapResolver::default();
        for blob in derived.source_blobs() {
            resolver
                .bytes
                .insert(blob.link().digest.clone(), blob.bytes().to_vec());
        }
        assert_eq!(
            verify_artifact_sources(&manifest, &evidence_link, &relabelled, &resolver),
            Err(M7Blocker::CausalMismatch(
                M7EvidenceKind::M2SchedulerWakeRestart
            ))
        );
    }

    fn signed_reviewer_evidence(
        manifest: &M7ProofRunManifest,
        reviewed_set: ContentDigest,
        recommendation: M7ClosureDecision,
        identity: M7ExternalEd25519IdentityV1,
        seed: [u8; 32],
    ) -> M7DerivedEvidenceV2 {
        let rationale = content("reviewer-rationale");
        let independence = content("reviewer-independence-statement");
        let preimage = M7IndependentReviewSourceV2::signing_preimage(
            &identity,
            manifest.manifest_digest().clone(),
            reviewed_set.clone(),
            recommendation,
            rationale.clone(),
            independence.clone(),
        )
        .expect("reviewer preimage");
        let signature = test_attestor(seed).sign(&preimage);
        let source = M7IndependentReviewSourceV2::from_external_signature(
            identity,
            manifest.manifest_digest().clone(),
            reviewed_set,
            recommendation,
            rationale,
            independence,
            signature.as_ref(),
        )
        .expect("signed reviewer source");
        M7EvidenceArtifact::derive_from_sources(
            manifest,
            M7EvidenceKind::IndependentReviewerRecommendation,
            vec![M7SourceInputV2::new(
                M7SourceRoleV2::IndependentReview,
                source.canonical_bytes().expect("reviewer source bytes"),
            )],
        )
        .expect("signed reviewer evidence")
    }

    #[derive(Clone, Default)]
    struct MapResolver {
        bytes: BTreeMap<ContentDigest, Vec<u8>>,
        failures: BTreeSet<ContentDigest>,
    }

    impl EvidenceResolver for MapResolver {
        fn resolve(&self, digest: &ContentDigest) -> Result<Option<Vec<u8>>, EvidenceResolveError> {
            if self.failures.contains(digest) {
                return Err(EvidenceResolveError {
                    message: "injected resolver failure".to_string(),
                });
            }
            Ok(self.bytes.get(digest).cloned())
        }
    }

    struct Fixture {
        bundle: M7FinalBundle,
        resolver: MapResolver,
    }

    impl Fixture {
        fn new(recommendation: M7ClosureDecision) -> Self {
            Self::new_with_provider(recommendation, None)
        }

        fn new_with_provider(
            recommendation: M7ClosureDecision,
            provider_qualified: Option<bool>,
        ) -> Self {
            Self::new_with_provider_source(
                recommendation,
                provider_qualified.map(|_| live_provider_source_fixture("proof-run:m7:1", 150)),
                provider_qualified,
            )
        }

        fn new_with_provider_source(
            recommendation: M7ClosureDecision,
            provider_source: Option<M7LiveProviderSourceV1>,
            provider_qualified: Option<bool>,
        ) -> Self {
            assert_eq!(
                provider_source.is_some(),
                provider_qualified.is_some(),
                "provider source and qualification disposition must be supplied together"
            );
            let provider_scope = provider_source
                .as_ref()
                .map(|source| {
                    let completed = source.completed_invocation()?;
                    LiveProviderQualificationScope::from_prepared(completed.prepared_seed())
                })
                .transpose()
                .expect("provider scope");
            let manifest = manifest(provider_scope.clone());
            let mut resolver = MapResolver::default();
            let mut links = Vec::new();
            let mut source_links = Vec::new();
            let mut required_payloads = required_payloads_without_reviewer();
            for payload in &mut required_payloads {
                match payload {
                    M7EvidencePayload::M2SchedulerWakeRestart(restart) => {
                        restart.manifest_digest = manifest.manifest_digest.clone();
                    }
                    M7EvidencePayload::M5ActivationRollback(m5) => {
                        m5.rollback_operator_context_digest = manifest.manifest_digest.clone();
                        if provider_source.is_none() {
                            m5.active_operator_context_digest = manifest.manifest_digest.clone();
                        }
                    }
                    _ => {}
                }
            }
            if let Some(source) = &provider_source {
                let completed = source
                    .completed_invocation()
                    .expect("opaque completed provider fixture");
                let binding = completed.provider_binding();
                let m1 = required_payloads
                    .iter_mut()
                    .find_map(|payload| match payload {
                        M7EvidencePayload::M1CandidateLifecycle(candidate) => Some(candidate),
                        _ => None,
                    })
                    .expect("M1 candidate payload");
                m1.incumbent_package_digest = binding.target.incumbent_package_digest.clone();
                m1.candidate_package_digest = binding.target.candidate_package_digest.clone();
                let m5 = required_payloads
                    .iter_mut()
                    .find_map(|payload| match payload {
                        M7EvidencePayload::M5ActivationRollback(m5) => Some(m5),
                        _ => None,
                    })
                    .expect("M5 lineage payload");
                let target = &binding.target;
                let M5ProviderTerminalOutcomeV1::Adopted {
                    cycle_record_digest,
                    ..
                } = completed.terminal_outcome()
                else {
                    panic!("qualified fixture provider outcome must be adopted")
                };
                m5.active_cycle_id = target.cycle_id.clone();
                m5.active_cycle_record_digest = cycle_record_digest.clone();
                m5.active_parent_package_digest = target.incumbent_package_digest.clone();
                m5.active_package_digest = target.candidate_package_digest.clone();
                m5.active_release_gate_digest = target.release_gate_digest.clone();
                m5.rollback_release_gate_digest = target.release_gate_digest.clone();
                m5.active_operator_context_digest = target.operator_context_digest.clone();
                m5.provider_qualification_record_digests_by_target = BTreeMap::from([(
                    target.target_digest.clone(),
                    BTreeSet::from([binding.qualification_record_digest.clone()]),
                )]);
            }
            for payload in required_payloads {
                let artifact = M7EvidenceArtifact::new(
                    &manifest,
                    content(&format!("subject:{:?}", payload.kind())),
                    payload,
                )
                .expect("evidence artifact");
                let bytes = artifact.canonical_bytes().expect("evidence bytes");
                let link = artifact.evidence_link().expect("evidence link");
                resolver.bytes.insert(link.digest.clone(), bytes);
                links.push(link);
            }

            let live_provider_link = provider_source.as_ref().map(|source| {
                let derived = M7EvidenceArtifact::derive_from_sources(
                    &manifest,
                    M7EvidenceKind::LiveProviderQualification,
                    vec![M7SourceInputV2::new(
                        M7SourceRoleV2::LiveProviderQualification,
                        source
                            .canonical_bytes()
                            .expect("live-provider source bytes"),
                    )],
                )
                .expect("derived provider artifact");
                let artifact = if provider_qualified == Some(true) {
                    for blob in derived.source_blobs() {
                        resolver
                            .bytes
                            .insert(blob.link().digest.clone(), blob.bytes().to_vec());
                        source_links.push(blob.link().clone());
                    }
                    derived.artifact().clone()
                } else {
                    let M7EvidencePayload::LiveProviderQualification(mut payload) =
                        derived.artifact().payload().clone()
                    else {
                        panic!("provider payload")
                    };
                    payload.qualified = false;
                    M7EvidenceArtifact::new(
                        &manifest,
                        content("subject:provider"),
                        M7EvidencePayload::LiveProviderQualification(payload),
                    )
                    .expect("unqualified compatibility artifact")
                };
                let bytes = artifact.canonical_bytes().expect("provider bytes");
                let link = artifact.evidence_link().expect("provider link");
                resolver.bytes.insert(link.digest.clone(), bytes);
                link
            });

            let reviewed_set = reviewed_evidence_set_digest(
                &manifest,
                &links,
                live_provider_link.as_ref(),
                &source_links,
            )
            .expect("reviewed evidence set");
            let pinned_reviewer = reviewer_identity();
            let reviewer = reviewer_artifact(
                &manifest,
                reviewed_set,
                recommendation,
                pinned_reviewer.principal_id(),
                pinned_reviewer.identity_digest().clone(),
                pinned_reviewer.public_key_digest().clone(),
            );
            let reviewer_bytes = reviewer.canonical_bytes().expect("reviewer bytes");
            let reviewer_link = reviewer.evidence_link().expect("reviewer link");
            resolver
                .bytes
                .insert(reviewer_link.digest.clone(), reviewer_bytes);
            links.push(reviewer_link);
            let bundle = M7FinalBundle::new(manifest, links, live_provider_link, source_links)
                .expect("final bundle");
            Self { bundle, resolver }
        }

        fn artifact(&self, kind: M7EvidenceKind) -> M7EvidenceArtifact {
            let link = self
                .bundle
                .evidence_links
                .iter()
                .find(|link| link.kind == kind)
                .or_else(|| {
                    self.bundle
                        .live_provider_link
                        .as_ref()
                        .filter(|link| link.kind == kind)
                })
                .expect("artifact link");
            serde_json::from_slice(
                self.resolver
                    .bytes
                    .get(&link.digest)
                    .expect("artifact bytes"),
            )
            .expect("artifact parse")
        }

        fn replace_artifact(&mut self, artifact: M7EvidenceArtifact) {
            let kind = artifact.kind;
            assert_ne!(
                kind,
                M7EvidenceKind::IndependentReviewerRecommendation,
                "use replace_reviewer for reviewer evidence"
            );
            let bytes = artifact.canonical_bytes().expect("replacement bytes");
            let replacement = artifact.evidence_link().expect("replacement link");
            let link = self
                .bundle
                .evidence_links
                .iter_mut()
                .find(|link| link.kind == kind)
                .expect("replacement target");
            self.resolver.bytes.remove(&link.digest);
            *link = replacement.clone();
            self.resolver.bytes.insert(replacement.digest, bytes);
            self.reseal_reviewer();
        }

        fn replace_with_derived(&mut self, derived: M7DerivedEvidenceV2) {
            let kind = derived.artifact().kind();
            let bytes = derived.artifact_bytes().expect("derived artifact bytes");
            let replacement = derived
                .artifact()
                .evidence_link()
                .expect("derived artifact link");
            let link = self
                .bundle
                .evidence_links
                .iter_mut()
                .find(|link| link.kind == kind)
                .expect("derived replacement target");
            self.resolver.bytes.remove(&link.digest);
            *link = replacement.clone();
            self.resolver.bytes.insert(replacement.digest, bytes);
            self.bundle
                .source_links
                .retain(|link| link.semantic_role.evidence_kind() != kind);
            for blob in derived.source_blobs() {
                self.resolver
                    .bytes
                    .insert(blob.link().digest.clone(), blob.bytes().to_vec());
                self.bundle.source_links.push(blob.link().clone());
            }
            self.reseal_reviewer();
        }

        fn replace_with_signed_reviewer(&mut self, derived: M7DerivedEvidenceV2) {
            assert_eq!(
                derived.artifact().kind(),
                M7EvidenceKind::IndependentReviewerRecommendation
            );
            let old_link = self
                .bundle
                .evidence_links
                .iter()
                .find(|link| link.kind == M7EvidenceKind::IndependentReviewerRecommendation)
                .expect("reviewer link")
                .clone();
            self.resolver.bytes.remove(&old_link.digest);
            self.bundle
                .evidence_links
                .retain(|link| link.kind != M7EvidenceKind::IndependentReviewerRecommendation);
            self.bundle
                .source_links
                .retain(|link| link.semantic_role != M7SourceRoleV2::IndependentReview);
            let bytes = derived.artifact_bytes().expect("signed reviewer bytes");
            let link = derived
                .artifact()
                .evidence_link()
                .expect("signed reviewer link");
            self.resolver.bytes.insert(link.digest.clone(), bytes);
            self.bundle.evidence_links.push(link);
            for blob in derived.source_blobs() {
                self.resolver
                    .bytes
                    .insert(blob.link().digest.clone(), blob.bytes().to_vec());
                self.bundle.source_links.push(blob.link().clone());
            }
            self.rebuild_bundle();
        }

        fn replace_artifact_bytes_but_keep_link_scope(
            &mut self,
            kind: M7EvidenceKind,
            bytes: Vec<u8>,
        ) {
            let link = self
                .bundle
                .evidence_links
                .iter_mut()
                .find(|link| link.kind == kind)
                .expect("raw replacement target");
            self.resolver.bytes.remove(&link.digest);
            link.digest = ContentDigest::from_bytes(&bytes);
            link.byte_length = bytes.len() as u64;
            self.resolver.bytes.insert(link.digest.clone(), bytes);
            self.reseal_reviewer();
        }

        fn replace_reviewer(&mut self, reviewer_id: &str, reviewer_identity_digest: ContentDigest) {
            let recommendation = self.reviewer_payload().recommendation;
            let old_link = self
                .bundle
                .evidence_links
                .iter()
                .find(|link| link.kind == M7EvidenceKind::IndependentReviewerRecommendation)
                .expect("reviewer link")
                .clone();
            self.resolver.bytes.remove(&old_link.digest);
            self.bundle
                .evidence_links
                .retain(|link| link.kind != M7EvidenceKind::IndependentReviewerRecommendation);
            let reviewed_set = reviewed_evidence_set_digest(
                &self.bundle.manifest,
                &self.bundle.evidence_links,
                self.bundle.live_provider_link.as_ref(),
                &self.bundle.source_links,
            )
            .expect("review set");
            let reviewer = reviewer_artifact(
                &self.bundle.manifest,
                reviewed_set,
                recommendation,
                reviewer_id,
                reviewer_identity_digest,
                self.bundle.reviewer_identity.public_key_digest.clone(),
            );
            let bytes = reviewer.canonical_bytes().expect("reviewer bytes");
            let link = reviewer.evidence_link().expect("reviewer link");
            self.resolver.bytes.insert(link.digest.clone(), bytes);
            self.bundle.evidence_links.push(link);
            self.rebuild_bundle();
        }

        fn reseal_reviewer(&mut self) {
            let reviewer = self.reviewer_payload();
            let old_link = self
                .bundle
                .evidence_links
                .iter()
                .find(|link| link.kind == M7EvidenceKind::IndependentReviewerRecommendation)
                .expect("reviewer link")
                .clone();
            self.resolver.bytes.remove(&old_link.digest);
            self.bundle
                .evidence_links
                .retain(|link| link.kind != M7EvidenceKind::IndependentReviewerRecommendation);
            let reviewed_set = reviewed_evidence_set_digest(
                &self.bundle.manifest,
                &self.bundle.evidence_links,
                self.bundle.live_provider_link.as_ref(),
                &self.bundle.source_links,
            )
            .expect("review set");
            let replacement = reviewer_artifact(
                &self.bundle.manifest,
                reviewed_set,
                reviewer.recommendation,
                &reviewer.reviewer_id,
                reviewer.reviewer_identity_digest,
                reviewer.reviewer_public_key_digest,
            );
            let bytes = replacement
                .canonical_bytes()
                .expect("replacement reviewer bytes");
            let link = replacement
                .evidence_link()
                .expect("replacement reviewer link");
            self.resolver.bytes.insert(link.digest.clone(), bytes);
            self.bundle.evidence_links.push(link);
            self.rebuild_bundle();
        }

        fn reviewer_payload(&self) -> IndependentReviewerEvidence {
            match self
                .artifact(M7EvidenceKind::IndependentReviewerRecommendation)
                .payload
            {
                M7EvidencePayload::IndependentReviewerRecommendation(value) => value,
                _ => panic!("wrong reviewer payload"),
            }
        }

        fn rebuild_bundle(&mut self) {
            self.bundle = M7FinalBundle::new(
                self.bundle.manifest.clone(),
                self.bundle.evidence_links.clone(),
                self.bundle.live_provider_link.clone(),
                self.bundle.source_links.clone(),
            )
            .expect("rebuild bundle");
        }
    }

    fn content(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(label.as_bytes())
    }

    fn provider_fixture_config(
        api_base_url: &str,
        changed_marker: Option<&str>,
    ) -> GovernedLiveProviderConfig {
        GovernedLiveProviderConfig {
            provider: InferenceProviderRegistryEntry {
                provider_id: "provider:m7-fixture".to_string(),
                provider_mode: InferenceProviderMode::OpenAiResponses,
                models: vec![InferenceProviderModelEntry {
                    model_ref: "model:m7-fixture".to_string(),
                    input_cost_per_million_microunits: 100_000,
                    output_cost_per_million_microunits: 0,
                    supports_json_schema: true,
                    supports_function_tools: true,
                }],
                capability_summary: "bounded M7 provider fixture".to_string(),
                policy_summary: "no credential or network call is used by this fixture".to_string(),
                active: true,
                api_base_url: api_base_url.to_string(),
                api_key_env_var: "WASM_BIOTIC_M7_FIXTURE_KEY_MUST_NOT_EXIST".to_string(),
                organization_env_var: None,
                project_env_var: None,
                request_timeout_ms: 100,
            },
            generation_policy: InferenceGenerationPolicy {
                generation_policy_id: "policy:m7-provider-fixture".to_string(),
                max_output_tokens: 128,
                max_retries: 0,
                summary: changed_marker
                    .map(|marker| format!("bounded M7 provider fixture: {marker}"))
                    .unwrap_or_else(|| "bounded M7 provider fixture".to_string()),
            },
        }
    }

    pub(crate) fn live_provider_source_fixture(
        proof_run_id: &str,
        prepared_at_ms: u64,
    ) -> M7LiveProviderSourceV1 {
        live_provider_source_fixture_with_endpoint(
            proof_run_id,
            prepared_at_ms,
            None,
            "https://api.openai.com/v1/",
        )
    }

    fn live_provider_source_fixture_with_prompt(
        proof_run_id: &str,
        prepared_at_ms: u64,
        changed_prompt: Option<&str>,
    ) -> M7LiveProviderSourceV1 {
        live_provider_source_fixture_with_endpoint(
            proof_run_id,
            prepared_at_ms,
            changed_prompt,
            "https://api.openai.com/v1/",
        )
    }

    fn live_provider_source_fixture_with_endpoint(
        proof_run_id: &str,
        prepared_at_ms: u64,
        changed_marker: Option<&str>,
        api_base_url: &str,
    ) -> M7LiveProviderSourceV1 {
        let directory = M5TestDirectory::new();
        let runtime = m5_runtime(&directory);
        let provider =
            GovernedLiveProviderPort::new(provider_fixture_config(api_base_url, changed_marker))
                .expect("construct governed provider fixture without calling it");
        let mut plan = m5_seed("cycle:m7-provider-fixture", 2);
        if let Some(marker) = changed_marker {
            plan.approval_rationale = format!("provider fixture drift marker: {marker}");
        }
        let prepared = runtime
            .prepare_provider_backed_seed_cycle(
                proof_run_id,
                "qualification:m7-provider-fixture",
                prepared_at_ms,
                &provider,
                plan,
            )
            .expect("prepare exact provider fixture");
        let scope = LiveProviderQualificationScope::from_prepared(&prepared)
            .expect("fixture live-provider scope");
        let receipt_manifest = manifest_for_proof_run(proof_run_id, Some(scope.clone()));
        let challenged = M5ChallengedProviderSeedV1::derive(
            &prepared,
            receipt_manifest.manifest_digest().clone(),
            scope.scope_digest().clone(),
            [0x5a; 32],
        )
        .expect("derive exact manifest-bound provider challenge");
        let request = challenged.qualification_request().clone();
        let target = prepared.target.clone();
        let intent = ParsedProviderIntent {
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
                    challenged
                        .challenge()
                        .invocation_challenge_digest()
                        .as_str()
                        .to_string(),
                ),
            ]),
        };
        // The provider adapter exposes only the selected function call's
        // normalized argument object. Preserve those exact bytes for both the
        // live turn and offline replay; operation and target identity come
        // exclusively from the frozen qualification boundary.
        let normalized_parser_input_bytes = serde_json::to_vec(&intent.arguments)
            .expect("canonical normalized provider tool arguments");
        let configuration_fingerprint = request
            .configuration
            .fingerprint()
            .expect("provider configuration fingerprint");
        let transcript = RedactedTranscript {
            request_digest: request.request_digest.clone(),
            redacted_prompt: "[REDACTED PROVIDER PROMPT]".to_string(),
            redacted_response: String::from_utf8(normalized_parser_input_bytes.clone())
                .expect("provider fixture response UTF-8"),
            raw_prompt_digest: ContentDigest::from_bytes(&request.prompt_bytes),
            raw_response_digest: ContentDigest::from_bytes(&normalized_parser_input_bytes),
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
                request_body_digest: challenged
                    .provider_wire_request()
                    .request_body_digest()
                    .clone(),
                raw_response_digest: transcript.raw_response_digest.clone(),
            }],
            &transcript,
        )
        .expect("provider accounting fixture");
        let turn = LiveProviderTurn {
            request_digest: request.request_digest.clone(),
            configuration_fingerprint: configuration_fingerprint.clone(),
            replay_capsule_digest: request.replay_capsule.capsule_digest.clone(),
            transport: ProviderTransport::LiveProviderApi,
            external_turn_id: "turn:m7-provider-fixture".to_string(),
            provider_receipt_digest: provider_accounting.accounting_digest.clone(),
            provider_accounting,
            transcript,
            normalized_parser_input_bytes: normalized_parser_input_bytes.clone(),
            parsed_intent: intent.clone(),
            turn_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .expect("seal provider live-turn fixture");
        let replay_request = ProviderReplayRequest::new(&request, &turn)
            .expect("derive provider fixture replay request");
        let replay = ProviderReplayRecord {
            request_digest: replay_request.request_digest,
            network_used: false,
            parsed_intent: intent.clone(),
            parser_digest: request.configuration.parser_digest.clone(),
            replay_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .expect("seal provider replay fixture");
        let mut qualification = LiveProviderQualificationRecord {
            schema: LIVE_PROVIDER_QUALIFICATION_SCHEMA.to_string(),
            qualification_id: request.qualification_id.clone(),
            package_digest: request.package_digest.clone(),
            target_digest: request.target_digest.clone(),
            replay_capsule_digest: request.replay_capsule.capsule_digest.clone(),
            configuration_fingerprint,
            request_digest: request.request_digest.clone(),
            status: ProviderQualificationStatus::Qualified,
            live_turn: Some(turn),
            replay: Some(replay),
            failure: None,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        qualification.record_digest = digest(&(
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
        ))
        .expect("provider qualification fixture digest");
        let proposal_request =
            FactoryProviderProposalRequest::new(request, normalized_parser_input_bytes)
                .expect("provider proposal fixture request");
        let proposal_result = FactoryProviderProposalResult::from_request(&proposal_request)
            .expect("provider proposal fixture result");
        let m3_reference = M5M3EffectReference {
            logical_effect_id: format!(
                "m5-provider-proposal:{}",
                proposal_request.request_digest.file_stem()
            ),
            invocation_id: format!("invocation:{}", proposal_request.request_digest.file_stem()),
            receipt_digest: content("fixture-provider-receipt"),
            attestation_digest: content("fixture-provider-attestation"),
            proof_digest: content("fixture-provider-proof"),
            backend_fact_digest: content("fixture-provider-backend-fact"),
        };
        let proposal_evidence =
            ProviderProposalEvidence::new(proposal_request, proposal_result, m3_reference)
                .expect("provider proposal fixture evidence");
        let binding =
            ProviderCandidateBinding::new(target, qualification, intent, proposal_evidence)
                .expect("provider candidate fixture binding");
        let outcome = CycleOutcome::Adopted {
            package_digest: prepared.target.candidate_package_digest.clone(),
            cycle_record_digest: content("fixture-provider-cycle-record"),
        };
        let execution_receipt = M5ProviderExecutionReceiptV1::new(
            &receipt_manifest,
            &prepared,
            &challenged,
            &binding,
            &outcome,
            201,
            202,
            209,
        )
        .expect("seal provider execution fixture");
        let completed = M5CompletedProviderInvocationV1::seal(
            prepared,
            challenged,
            binding,
            outcome,
            execution_receipt,
        )
        .expect("seal opaque completed provider fixture");
        M7LiveProviderSourceV1::from_completed_invocation(completed)
            .expect("fixture M7 live-provider source")
    }

    struct M5TestDirectory(PathBuf);

    impl M5TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m7-m5-source-{}-{}",
                std::process::id(),
                M5_TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("create M5 source test directory");
            Self(path)
        }
    }

    impl Drop for M5TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone)]
    struct M2ManualClock {
        now_ms: Arc<AtomicU64>,
    }

    impl M2ManualClock {
        fn new(now_ms: u64) -> Arc<Self> {
            Arc::new(Self {
                now_ms: Arc::new(AtomicU64::new(now_ms)),
            })
        }

        fn set(&self, now_ms: u64) {
            self.now_ms.store(now_ms, Ordering::Release);
        }
    }

    impl SupervisorClock for M2ManualClock {
        fn now_ms(&self) -> u64 {
            self.now_ms.load(Ordering::Acquire)
        }
    }

    fn m2_submit_request(
        job_id: &str,
        idempotency_key: &str,
        not_before_ms: u64,
        approval_request_id: Option<&str>,
    ) -> SubmitJobRequest {
        SubmitJobRequest {
            job_id: job_id.to_string(),
            job_kind: "reference-effect".to_string(),
            payload_json: serde_json::json!({"job": job_id}).to_string(),
            idempotency_key: idempotency_key.to_string(),
            not_before_ms,
            deadline_at_ms: 1_000,
            retry_policy: RetryPolicy {
                max_attempts: 3,
                initial_backoff_ms: 10,
                max_backoff_ms: 100,
                lease_duration_ms: 20,
                attempt_timeout_ms: 50,
            },
            approval_request_id: approval_request_id.map(str::to_string),
        }
    }

    fn m2_open_workspace_request(
        job_id: &str,
        idempotency_key: &str,
        not_before_ms: u64,
        workspace_id: &str,
    ) -> SubmitJobRequest {
        let mut request = m2_submit_request(job_id, idempotency_key, not_before_ms, None);
        request.job_kind = M1_OPEN_WORKSPACE_JOB_KIND.to_string();
        request.payload_json = serde_json::to_string(&M1LifecycleJob::OpenWorkspace(
            crate::m2_runtime::OpenWorkspacePayload {
                workspace_id: workspace_id.to_string(),
            },
        ))
        .expect("typed OpenWorkspace payload");
        request
    }

    fn m2_open_workspace_commit(workspace_id: &str) -> EffectCommit {
        EffectCommit::from_json(
            "m1.open_workspace:fixture",
            &serde_json::json!({
                "schema": "wasm-biotic.m2-lifecycle-effect.v1",
                "job_kind": M1_OPEN_WORKSPACE_JOB_KIND,
                "record": {
                    "snapshot": {
                        "workspace_id": workspace_id,
                        "workspace_ref": "workspace:fixture",
                        "mutable_paths": ["component.wat"],
                        "immutable_paths": ["component.wit"],
                        "entries": [],
                        "total_source_bytes": 0,
                        "tree_digest": content("fixture-workspace-tree"),
                    },
                    "snapshot_digest": content("fixture-workspace-snapshot"),
                },
            }),
        )
        .expect("ordinary OpenWorkspace effect")
    }

    fn exact_m2_supervisor_states() -> (SupervisorState, SupervisorState) {
        exact_m2_supervisor_states_for_exports(
            &[content("m5-export-bundle-content")],
            content("m6-completion-bundle-content"),
        )
    }

    fn exact_m2_supervisor_states_for_exports(
        export_digests: &[ContentDigest],
        m6_completion_bundle_content_digest: ContentDigest,
    ) -> (SupervisorState, SupervisorState) {
        assert!(!export_digests.is_empty());
        let directory = M5TestDirectory::new();
        let proof_manifest = manifest(None);
        let clock = M2ManualClock::new(200);
        let mut supervisor =
            LocalDurableSupervisor::open(&directory.0, "owner:m7-before", clock.clone())
                .expect("open pre-restart supervisor");

        supervisor
            .submit_job(m2_open_workspace_request(
                "job:m7-terminal",
                "effect-key:m7-terminal",
                200,
                "workspace:m7-anchor",
            ))
            .expect("submit pre-restart terminal job");
        let terminal_dispatch = supervisor
            .claim_due_job()
            .expect("claim terminal job")
            .expect("terminal dispatch");
        supervisor
            .complete_dispatch(
                &terminal_dispatch,
                JobExecutionResult::EffectCommitted(m2_open_workspace_commit(
                    "workspace:m7-anchor",
                )),
            )
            .expect("complete pre-restart terminal job");

        supervisor
            .submit_job(m2_submit_request(
                "job:m7-approval",
                "effect-key:m7-approval",
                200,
                Some("approval:m7-granted"),
            ))
            .expect("submit pre-restart approval job");
        supervisor
            .resolve_approval(ApprovalResolutionRecord {
                approval_request_id: "approval:m7-granted".to_string(),
                resolution: ApprovalResolutionKind::Granted,
                evidence_ref: "evidence:m7-grant".to_string(),
                resolved_at_ms: 200,
            })
            .expect("resolve pre-restart approval");
        let approval_dispatch = supervisor
            .claim_due_job()
            .expect("claim approved job")
            .expect("approved dispatch");
        assert_eq!(approval_dispatch.job_id, "job:m7-approval");
        supervisor
            .complete_dispatch(
                &approval_dispatch,
                JobExecutionResult::EffectCommitted(
                    EffectCommit::from_json(
                        "effect:m7-approval",
                        &serde_json::json!({"effect": "m7-approval"}),
                    )
                    .expect("approval effect commit"),
                ),
            )
            .expect("complete approved pre-restart job");

        let terminal_job = supervisor
            .state()
            .jobs
            .get("job:m7-terminal")
            .expect("terminal lifecycle anchor");
        let terminal_job_digest = digest(terminal_job).expect("terminal lifecycle anchor digest");
        let mut challenge_job_ids = Vec::new();
        for export_digest in export_digests {
            let binding = M5M2PostExportJobBindingV2::new(
                proof_manifest.manifest_digest.clone(),
                export_digest.clone(),
                m6_completion_bundle_content_digest.clone(),
                "job:m7-terminal",
                terminal_job_digest.clone(),
            )
            .expect("post-export restart binding");
            let challenge_job_id = binding.job_id();
            let future_request = m2_open_workspace_request(
                &challenge_job_id,
                &binding.idempotency_key(),
                300,
                "workspace:m7-anchor",
            );
            supervisor
                .submit_job(future_request)
                .expect("submit future job");
            challenge_job_ids.push(challenge_job_id);
        }
        supervisor
            .graceful_shutdown()
            .expect("durable pre-restart shutdown");
        let before = supervisor.state().clone();
        drop(supervisor);

        clock.set(300);
        let mut reopened =
            LocalDurableSupervisor::open(&directory.0, "owner:m7-after", clock.clone())
                .expect("open post-restart supervisor");
        let mut completed_job_ids = BTreeSet::new();
        while let Some(future_dispatch) = reopened.claim_due_job().expect("claim future job") {
            assert!(challenge_job_ids.contains(&future_dispatch.job_id));
            completed_job_ids.insert(future_dispatch.job_id.clone());
            reopened
                .complete_dispatch(
                    &future_dispatch,
                    JobExecutionResult::EffectCommitted(m2_open_workspace_commit(
                        "workspace:m7-anchor",
                    )),
                )
                .expect("complete post-restart future job");
        }
        assert_eq!(completed_job_ids.len(), challenge_job_ids.len());
        let after = reopened.state().clone();
        (before, after)
    }

    fn supervisor_state_bytes(state: &SupervisorState) -> Vec<u8> {
        canonical_json(state).expect("canonical supervisor state")
    }

    fn m2_post_export_job_id(state: &SupervisorState) -> String {
        let matches = state
            .jobs
            .values()
            .filter(|job| {
                M5M2PostExportJobBindingV2::from_job_identity(&job.job_id, &job.idempotency_key)
                    .is_ok()
            })
            .map(|job| job.job_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "one post-export job fixture");
        matches[0].clone()
    }

    fn m5_component_wat(body: &str) -> Vec<u8> {
        format!(
            r#"(component
                (core module $implementation
                    (func (export "transform") (param i32) (result i32)
                        {body}))
                (core instance $instance (instantiate $implementation))
                (func (export "transform") (param "input" s32) (result s32)
                    (canon lift (core func $instance "transform"))))"#
        )
        .into_bytes()
    }

    fn m5_incumbent_wat() -> Vec<u8> {
        m5_component_wat("local.get 0")
    }

    fn m5_successor_wat() -> Vec<u8> {
        m5_component_wat(
            r#"local.get 0
               i32.const -2147483648
               i32.eq
               if (result i32)
                   i32.const 1
               else
                   local.get 0
                   i32.const 1
                   i32.add
               end"#,
        )
    }

    fn m5_equivalent_successor_wat() -> Vec<u8> {
        m5_component_wat(
            r#"local.get 0
               i32.const -2147483648
               i32.eq
               if (result i32)
                   i32.const 1
               else
                   local.get 0
                   i32.const 1
                   i32.add
               end
               i32.const 0
               i32.add"#,
        )
    }

    fn m5_validation_suite() -> ValidationSuite {
        ValidationSuite::new(
            "m7-m5-source-suite",
            "transform",
            vec![
                ValidationCase::returns("case:one", 1, 2),
                ValidationCase::returns("case:seven", 7, 8),
            ],
            ComponentExecutionLimits::default(),
        )
        .expect("M5 source validation suite")
    }

    fn m5_release_gate() -> ReleaseGate {
        let benchmarks = [(1_i32, 2_i32), (7_i32, 8_i32)]
            .into_iter()
            .enumerate()
            .map(|(index, (input, output))| BenchmarkSpec {
                benchmark_id: format!("benchmark:m7:{index}"),
                request_bytes: input.to_le_bytes().to_vec(),
                expected_output_digest: ContentDigest::from_bytes(&output.to_le_bytes()),
                max_duration_ms: 10_000,
                required: true,
            })
            .collect();
        let invariants = [
            InvariantKind::StableInterface,
            InvariantKind::RunnableComponent,
            InvariantKind::ExactPackageIdentity,
            InvariantKind::BoundedCapabilities,
            InvariantKind::DurableRollback,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| InvariantSpec {
            invariant_id: format!("invariant:m7:{index}"),
            kind,
            required: true,
        })
        .collect();
        ReleaseGate::new(
            "m7-m5-source-gate",
            benchmarks,
            invariants,
            RecursionBudgets {
                max_generation_depth: 4,
                max_total_cycles: 8,
                max_shadow_tasks: 4,
                max_component_bytes: 1_048_576,
                max_state_bytes: 4_096,
                max_provider_turns: 4,
            },
            ReleaseThresholds {
                minimum_passed_benchmarks: 2,
                minimum_success_basis_points: 10_000,
                maximum_regressions: 0,
                require_all_required_invariants: true,
                minimum_post_activation_successes: 2,
            },
        )
        .expect("M5 source release gate")
    }

    fn m5_runtime(directory: &M5TestDirectory) -> M5Runtime {
        M5Runtime::initialize(
            M5RuntimeConfig {
                root: directory.0.clone(),
                factory_id: "factory:m7-m5-source".to_string(),
                scope_id: "scope:m7-m5-source".to_string(),
                deployment_id: "deployment-m7-m5-source".to_string(),
                worker_max_concurrency: 1,
            },
            m5_incumbent_wat(),
            m5_validation_suite(),
            m5_release_gate(),
            1,
            M5InitializationAuthority {
                operator_ref: "operator:m7-m5-source-bootstrap".to_string(),
                rationale: "authorize exact M5 sources for M7 derivation".to_string(),
            },
            None,
        )
        .expect("initialize M5 source runtime")
    }

    fn m5_seed(cycle_id: &str, policy_revision: u32) -> M5SeedCyclePlan {
        M5SeedCyclePlan {
            cycle_id: cycle_id.to_string(),
            challenger_wat_bytes: if policy_revision == 2 {
                m5_successor_wat()
            } else {
                m5_equivalent_successor_wat()
            },
            challenger_policy: MutableFactoryPolicy::terminal(policy_revision, 2),
            state_compatibility: StateCompatibility {
                readable_schema_min: 1,
                readable_schema_max: 2,
                written_schema: 1,
                incumbent_rollback_readable_through: 2,
            },
            migration_plan: None,
            migration_artifacts: None,
            operator_context_digest: content(&format!("operator-context:{cycle_id}")),
            approval_decision: ApprovalDecision::Approved,
            approver_ref: "operator:m7-m5-source".to_string(),
            approval_rationale: "approve exact local source fixture".to_string(),
        }
    }

    pub(crate) fn exact_m5_source_bytes() -> (Vec<u8>, Vec<u8>) {
        static SOURCES: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        SOURCES
            .get_or_init(|| {
                let proof_manifest = manifest(None);
                let directory = M5TestDirectory::new();
                let runtime = m5_runtime(&directory);
                assert!(matches!(
                    runtime
                        .run_seeded_cycle(m5_seed("cycle:m7-adopted-n1", 2))
                        .expect("adopt exact N+1"),
                    CycleOutcome::Adopted { .. }
                ));
                runtime
                    .induce_next_health_regression()
                    .expect("arm real post-activation failure");
                let rollback_cycle_id = "cycle:m7-rollback-n2";
                assert!(matches!(
                    runtime
                        .run_seeded_cycle(m5_seed(rollback_cycle_id, 3))
                        .expect("run rollback cycle"),
                    CycleOutcome::QuarantinedAndRolledBack { .. }
                ));
                let export_bytes = runtime
                    .export_active_adopted_bundle()
                    .expect("export restored adopted package")
                    .canonical_bytes()
                    .expect("canonical M5 export");
                let export = M5ExportBundleV1::from_canonical_bytes(&export_bytes)
                    .expect("reparse exact M5 export");
                let lifecycle_anchor = &export
                    .active_cycle()
                    .m4_workflows()
                    .first()
                    .expect("exact active cycle has an M4 workflow")
                    .workflow()
                    .lifecycle_anchor;
                let export_digest = ContentDigest::from_bytes(&export_bytes);
                let m6_completion_digest = content("m6-completion-bundle-content");
                let restart_capture = runtime
                    .capture_post_export_m2_restart_with_completion_digest_for_test(
                        proof_manifest.manifest_digest.clone(),
                        export_digest.clone(),
                        m6_completion_digest.clone(),
                        &lifecycle_anchor.m2_job_id,
                        lifecycle_anchor.terminal_job_digest.clone(),
                    )
                    .expect("capture exact M2 restart before final M5 probe");
                let probe_bytes = runtime
                    .capture_final_post_rollback_probe_with_completion_digest_for_test(
                        rollback_cycle_id,
                        23,
                        proof_manifest.manifest_digest.clone(),
                        export_digest,
                        m6_completion_digest,
                        &restart_capture,
                    )
                    .expect("fresh chronology-bound post-rollback execution")
                    .canonical_bytes()
                    .expect("canonical final post-rollback probe");
                (export_bytes, probe_bytes)
            })
            .clone()
    }

    fn exact_ordinary_m5_probe_bytes() -> Vec<u8> {
        static PROBE: OnceLock<Vec<u8>> = OnceLock::new();
        PROBE
            .get_or_init(|| {
                let directory = M5TestDirectory::new();
                let runtime = m5_runtime(&directory);
                assert!(matches!(
                    runtime
                        .run_seeded_cycle(m5_seed("cycle:m7-ordinary-adopted-n1", 2))
                        .expect("adopt ordinary-probe N+1"),
                    CycleOutcome::Adopted { .. }
                ));
                runtime
                    .induce_next_health_regression()
                    .expect("arm ordinary-probe failure");
                let rollback_cycle_id = "cycle:m7-ordinary-rollback-n2";
                assert!(matches!(
                    runtime
                        .run_seeded_cycle(m5_seed(rollback_cycle_id, 3))
                        .expect("run ordinary-probe rollback"),
                    CycleOutcome::QuarantinedAndRolledBack { .. }
                ));
                runtime
                    .capture_post_rollback_probe(rollback_cycle_id, 23)
                    .expect("capture valid ordinary M6-compatible probe")
                    .canonical_bytes()
                    .expect("canonical ordinary M6-compatible probe")
            })
            .clone()
    }

    pub(crate) fn exact_manifest_bound_m5_m2_source_bytes(
        manifest_digest: &ContentDigest,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let directory = M5TestDirectory::new();
        let runtime = m5_runtime(&directory);
        let mut adoption_seed = m5_seed("cycle:m7-manifest-adopted-n1", 2);
        adoption_seed.operator_context_digest = manifest_digest.clone();
        assert!(matches!(
            runtime
                .run_seeded_cycle(adoption_seed)
                .expect("adopt exact manifest-bound N+1"),
            CycleOutcome::Adopted { .. }
        ));
        runtime
            .induce_next_health_regression()
            .expect("arm manifest-bound post-activation failure");
        let rollback_cycle_id = "cycle:m7-manifest-rollback-n2";
        let mut rollback_seed = m5_seed(rollback_cycle_id, 3);
        rollback_seed.operator_context_digest = manifest_digest.clone();
        assert!(matches!(
            runtime
                .run_seeded_cycle(rollback_seed)
                .expect("run manifest-bound rollback cycle"),
            CycleOutcome::QuarantinedAndRolledBack { .. }
        ));
        let export_bytes = runtime
            .export_active_adopted_bundle()
            .expect("export manifest-bound restored package")
            .canonical_bytes()
            .expect("canonical manifest-bound M5 export");
        let export = M5ExportBundleV1::from_canonical_bytes(&export_bytes)
            .expect("reparse manifest-bound M5 export");
        let lifecycle_anchor = &export
            .active_cycle()
            .m4_workflows()
            .first()
            .expect("manifest-bound active cycle has an M4 workflow")
            .workflow()
            .lifecycle_anchor;
        let restart_capture = runtime
            .capture_post_export_m2_restart_with_completion_digest_for_test(
                manifest_digest.clone(),
                ContentDigest::from_bytes(&export_bytes),
                content("m6-completion-bundle-content"),
                &lifecycle_anchor.m2_job_id,
                lifecycle_anchor.terminal_job_digest.clone(),
            )
            .expect("capture exact post-export M2 restart seam");
        let probe_bytes = runtime
            .capture_final_post_rollback_probe_with_completion_digest_for_test(
                rollback_cycle_id,
                23,
                manifest_digest.clone(),
                ContentDigest::from_bytes(&export_bytes),
                content("m6-completion-bundle-content"),
                &restart_capture,
            )
            .expect("capture final manifest-bound post-rollback execution")
            .canonical_bytes()
            .expect("canonical manifest-bound M5 probe");
        (
            export_bytes,
            probe_bytes,
            restart_capture
                .pre_restart_supervisor_state_bytes()
                .to_vec(),
            restart_capture
                .post_restart_supervisor_state_bytes()
                .to_vec(),
        )
    }

    fn alternate_valid_m5_export_bytes() -> Vec<u8> {
        let directory = M5TestDirectory::new();
        let runtime = M5Runtime::initialize(
            M5RuntimeConfig {
                root: directory.0.clone(),
                factory_id: "factory:m7-m5-alternate".to_string(),
                scope_id: "scope:m7-m5-alternate".to_string(),
                deployment_id: "deployment-m7-m5-alternate".to_string(),
                worker_max_concurrency: 1,
            },
            m5_incumbent_wat(),
            m5_validation_suite(),
            m5_release_gate(),
            1,
            M5InitializationAuthority {
                operator_ref: "operator:m7-m5-alternate-bootstrap".to_string(),
                rationale: "construct independently valid M5 substitution control".to_string(),
            },
            None,
        )
        .expect("initialize alternate M5 source runtime");
        assert!(matches!(
            runtime
                .run_seeded_cycle(m5_seed("cycle:m7-alternate-adopted", 2))
                .expect("adopt alternate M5 source"),
            CycleOutcome::Adopted { .. }
        ));
        runtime
            .export_active_adopted_bundle()
            .expect("export alternate adopted M5 bundle")
            .canonical_bytes()
            .expect("canonical alternate M5 export")
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

    #[test]
    fn frozen_criterion_text_round_trips_and_statement_or_digest_tamper_fails() {
        let manifest = manifest(None);
        let bytes = manifest.canonical_bytes().expect("canonical manifest");
        let reopened = M7ProofRunManifest::from_canonical_bytes(&bytes)
            .expect("manifest with exact criterion text round trips");
        assert!(
            reopened == manifest,
            "reopened proof-run manifest differed from its canonical source"
        );
        for criterion in reopened.frozen_criteria().criteria() {
            assert!(!criterion.statement.is_empty());
            assert_eq!(
                criterion.statement_digest,
                ContentDigest::from_bytes(criterion.statement.as_bytes())
            );
        }

        let mut changed_statement = manifest.frozen_criteria.clone();
        changed_statement.criteria[0]
            .statement
            .push_str(" Altered after the freeze.");
        assert!(matches!(
            changed_statement.validate(),
            Err(M7FoundationError::InvalidCriteria(_))
        ));

        let mut changed_digest = manifest.frozen_criteria.clone();
        changed_digest.criteria[0].statement_digest = content("forged-statement-digest");
        assert!(matches!(
            changed_digest.validate(),
            Err(M7FoundationError::InvalidCriteria(_))
        ));

        for invalid_statement in [
            String::new(),
            "contains\na control character".to_string(),
            "x".repeat(MAX_CRITERION_STATEMENT_BYTES + 1),
        ] {
            let mut invalid = manifest.frozen_criteria.criteria[0].clone();
            invalid.statement = invalid_statement;
            invalid.statement_digest = ContentDigest::from_bytes(invalid.statement.as_bytes());
            assert!(matches!(
                invalid.validate(),
                Err(M7FoundationError::InvalidCriteria(_))
            ));
        }
    }

    fn manifest(provider_scope: Option<LiveProviderQualificationScope>) -> M7ProofRunManifest {
        manifest_for_proof_run("proof-run:m7:1", provider_scope)
    }

    pub(crate) fn manifest_for_proof_run(
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
                required_roles: mandatory_worker_roles(),
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

    fn reviewer_artifact(
        manifest: &M7ProofRunManifest,
        reviewed_evidence_set_digest: ContentDigest,
        recommendation: M7ClosureDecision,
        reviewer_id: &str,
        reviewer_identity_digest: ContentDigest,
        reviewer_public_key_digest: ContentDigest,
    ) -> M7EvidenceArtifact {
        M7EvidenceArtifact::new(
            manifest,
            content("subject:independent-review"),
            M7EvidencePayload::IndependentReviewerRecommendation(IndependentReviewerEvidence {
                reviewer_id: reviewer_id.to_string(),
                reviewer_identity_digest,
                reviewer_public_key_digest,
                reviewed_manifest_digest: manifest.manifest_digest.clone(),
                reviewed_evidence_set_digest,
                recommendation,
                rationale_digest: content("reviewer-rationale"),
                independence_statement_digest: content("reviewer-independence-statement"),
                participation_declaration:
                    M7ReviewerParticipationDeclarationV1::NoImplementationParticipation,
            }),
        )
        .expect("reviewer artifact")
    }

    fn assert_family_fails_closed(
        evaluation: &M7Evaluation,
        kind: M7EvidenceKind,
        failure: M7SemanticFailure,
    ) {
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert!(!evaluation.evidence_complete);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::SemanticFailure { kind, failure })
                || evaluation
                    .blockers
                    .contains(&M7Blocker::MissingAuthoritativeSource(kind))
        );
    }

    fn active_surface_inputs(snapshot: &M7ActiveSurfaceSnapshotV1) -> M7ActiveSurfaceInputBytesV1 {
        let bytes = |role| {
            snapshot
                .surface(role)
                .expect("active surface")
                .content_bytes()
                .to_vec()
        };
        M7ActiveSurfaceInputBytesV1::new(
            bytes(M7ActiveSurfaceRoleV1::RootReadme),
            bytes(M7ActiveSurfaceRoleV1::Roadmap),
            bytes(M7ActiveSurfaceRoleV1::SystemOverview),
            bytes(M7ActiveSurfaceRoleV1::GeneralAudienceHome),
            bytes(M7ActiveSurfaceRoleV1::NorthStar07ClosureReview),
            bytes(M7ActiveSurfaceRoleV1::RemediationPhase04FinalClosureRereview),
            bytes(M7ActiveSurfaceRoleV1::RemediationPhase04PublicationPolicy),
        )
    }

    #[test]
    fn active_surface_secret_rule_set_v2_detects_each_category_without_material() {
        assert_eq!(
            active_surface_secret_rules(),
            BTreeSet::from([
                M7ActiveSurfaceSecretRuleV1::PrivateKeyHeader,
                M7ActiveSurfaceSecretRuleV1::AuthorizationCredential,
                M7ActiveSurfaceSecretRuleV1::UriAuthorityUserinfo,
                M7ActiveSurfaceSecretRuleV1::SecretBearingAssignment,
                M7ActiveSurfaceSecretRuleV1::ProviderCloudTokenPrefix,
                M7ActiveSurfaceSecretRuleV1::CompactJwt,
            ])
        );

        let cases: &[(&[u8], M7ActiveSurfaceSecretRuleV1)] = &[
            (
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
                M7ActiveSurfaceSecretRuleV1::PrivateKeyHeader,
            ),
            (
                b"Authorization: Bearer syntheticBearerCredential1234",
                M7ActiveSurfaceSecretRuleV1::AuthorizationCredential,
            ),
            (
                b"Authorization=Basic dXNlcjpwYXNzd29yZA==",
                M7ActiveSurfaceSecretRuleV1::AuthorizationCredential,
            ),
            (
                b"postgresql://worker:local-fixture-password@example.invalid/db",
                M7ActiveSurfaceSecretRuleV1::UriAuthorityUserinfo,
            ),
            (
                b"OPENAI_API_KEY=must_not_enter_evidence_1234",
                M7ActiveSurfaceSecretRuleV1::SecretBearingAssignment,
            ),
            (
                b"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA",
                M7ActiveSurfaceSecretRuleV1::ProviderCloudTokenPrefix,
            ),
            (
                b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJlLWJ5dGVz",
                M7ActiveSurfaceSecretRuleV1::CompactJwt,
            ),
        ];
        for (bytes, expected) in cases {
            assert_eq!(
                detect_active_surface_secret_rules(bytes),
                BTreeSet::from([*expected]),
                "secret scan category drift"
            );
        }
    }

    #[test]
    fn active_surface_secret_rule_set_v2_covers_key_and_provider_families() {
        for header in [
            b"-----BEGIN PRIVATE KEY-----".as_slice(),
            b"-----BEGIN RSA PRIVATE KEY-----".as_slice(),
            b"-----BEGIN EC PRIVATE KEY-----".as_slice(),
            b"-----BEGIN OPENSSH PRIVATE KEY-----".as_slice(),
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----".as_slice(),
            b"-----BEGIN DSA PRIVATE KEY-----".as_slice(),
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----".as_slice(),
        ] {
            assert_eq!(
                detect_active_surface_secret_rules(header),
                BTreeSet::from([M7ActiveSurfaceSecretRuleV1::PrivateKeyHeader])
            );
        }

        for assignment in [
            b"password=local-fixture-password".as_slice(),
            b"client-secret: local-fixture-client-secret".as_slice(),
            b"{\"refresh_token\":\"local-fixture-refresh-token\"}".as_slice(),
            b"export AWS_SECRET_ACCESS_KEY=LOCALFIXTURESECRETACCESSKEY".as_slice(),
            b"clientSecret=localFixtureCredential1234".as_slice(),
            b"accessToken=localFixtureCredential1234".as_slice(),
            b"privateKey=localFixtureCredential1234".as_slice(),
            b"{\"access token\":\"local-fixture-credential-1234\"}".as_slice(),
            b"OPENAI_API_KEY=live-redacted-but-real-credential".as_slice(),
            b"OPENAI_API_KEY=localFixtureCredential1234 /usr/bin/true".as_slice(),
            b"password: |\n  local-fixture-credential-1234".as_slice(),
            br#"{"stdout":"test result: ok\nOPENAI_API_KEY=must_not_enter_evidence_1234\n"}"#
                .as_slice(),
        ] {
            assert_eq!(
                detect_active_surface_secret_rules(assignment),
                BTreeSet::from([M7ActiveSurfaceSecretRuleV1::SecretBearingAssignment])
            );
        }

        for token in [
            b"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA".as_slice(),
            b"sk-or-v1-BBBBBBBBBBBBBBBBBBBBBBBB".as_slice(),
            b"sk-ant-api03-CCCCCCCCCCCCCCCCCCCCCCCC".as_slice(),
            b"github_pat_DDDDDDDDDDDDDDDDDDDDDDDD".as_slice(),
            b"glpat-EEEEEEEEEEEEEEEEEEEEEEEE".as_slice(),
            b"xoxb-111111111111-222222222222".as_slice(),
            b"AIzaFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".as_slice(),
            b"GOCSPX-GGGGGGGGGGGGGGGGGGGGGGGG".as_slice(),
            b"ya29.HHHHHHHHHHHHHHHHHHHHHHHH".as_slice(),
            b"hf_IIIIIIIIIIIIIIIIIIIIIIII".as_slice(),
            b"AKIA1234567890ABCDEF".as_slice(),
            b"ASIAABCDEF1234567890".as_slice(),
            b"sk_live_JJJJJJJJJJJJJJJJJJJJJJJJ".as_slice(),
        ] {
            assert_eq!(
                detect_active_surface_secret_rules(token),
                BTreeSet::from([M7ActiveSurfaceSecretRuleV1::ProviderCloudTokenPrefix])
            );
        }
    }

    #[test]
    fn active_surface_secret_rule_set_v2_ignores_benign_documentation_and_placeholders() {
        let digest = "a".repeat(64);
        let digest_assignment = format!("secret=sha256:{digest}");
        let benign: &[&[u8]] = &[
            b"Authorization Bearer and Basic credential values must be redacted.",
            b"The password: should never be written into evidence.",
            b"https://example.invalid/docs/user@example.org",
            b"postgresql://worker:replace_with_password@example.invalid/db",
            b"OPENAI_API_KEY=replace_with_openai_api_key",
            b"ANTHROPIC_API_KEY=replace-with-anthropic-api-key",
            b"Authorization: Bearer replace_with_token",
            b"client_secret=${CLIENT_SECRET}",
            b"password=<redacted>",
            b"credential_material_in_source=false",
            b"not_secret: feature-disabled",
            b"no_password=authentication-disabled",
            b"without_access_token: external-auth-disabled",
            b"Example prefixes: sk-proj-short, ghp_short, and AKIAEXAMPLE.",
            b"JWT shape: eyJ...eyJ...signature",
            digest_assignment.as_bytes(),
        ];
        for (case_index, bytes) in benign.iter().enumerate() {
            assert!(
                detect_active_surface_secret_rules(bytes).is_empty(),
                "benign secret-scan fixture {case_index} produced a finding"
            );
        }
    }

    #[test]
    fn active_surface_snapshot_binds_structured_markdown_and_exact_http_projections() {
        let snapshot = exact_active_surface_snapshot();
        assert_eq!(
            snapshot.active_truth().claim_catalog_digest,
            snapshot.claim_catalog().catalog_digest
        );
        assert_eq!(
            snapshot.active_truth().historical_lineage_decision,
            NorthStarClosureDecision::Closed
        );
        assert_eq!(
            snapshot.active_truth().operational_decision,
            M7ClosureDecision::NotYet
        );
        assert_eq!(
            snapshot
                .surfaces()
                .iter()
                .map(M7ActiveSurfaceCaptureV1::role)
                .collect::<BTreeSet<_>>(),
            required_active_surface_roles()
        );
        let reopened_snapshot = M7ActiveSurfaceSnapshotV1::from_canonical_bytes(
            &snapshot.canonical_bytes().expect("snapshot bytes"),
        )
        .expect("snapshot round trip");
        assert!(
            reopened_snapshot == snapshot,
            "active-surface snapshot round trip differed from the captured snapshot"
        );
        for source_digest in [
            M7TruthBoundarySourceV3::new(snapshot.clone())
                .expect("M0 source")
                .active_surface_snapshot()
                .snapshot_digest()
                .clone(),
            M7ClaimBoundarySourceV3::new(snapshot.clone())
                .expect("claim source")
                .active_surface_snapshot()
                .snapshot_digest()
                .clone(),
            M7PublicationPolicySourceV3::new(snapshot.clone())
                .expect("publication source")
                .active_surface_snapshot()
                .snapshot_digest()
                .clone(),
        ] {
            assert_eq!(&source_digest, snapshot.snapshot_digest());
        }

        let mut markdown_relabel = active_surface_inputs(&snapshot);
        let readme = String::from_utf8(markdown_relabel.root_readme)
            .expect("README UTF-8")
            .replacen(
                "\"operational_decision\":\"not_yet\"",
                "\"operational_decision\":\"closed\"",
                1,
            );
        markdown_relabel.root_readme = readme.into_bytes();
        assert!(M7ActiveSurfaceSnapshotV1::from_fixture_surface_bytes(markdown_relabel).is_err());

        let mut operator_relabel = active_surface_inputs(&snapshot);
        let mut overview: SystemOverviewView =
            serde_json::from_slice(&operator_relabel.system_overview).expect("overview JSON");
        overview.operational_north_star_decision = NorthStarClosureDecision::Closed;
        operator_relabel.system_overview =
            serde_json::to_vec(&overview).expect("relabeled overview");
        assert!(M7ActiveSurfaceSnapshotV1::from_fixture_surface_bytes(operator_relabel).is_err());

        let mut historical_relabel = active_surface_inputs(&snapshot);
        let mut phase04: RemediationPhase04FinalClosureRereviewView =
            serde_json::from_slice(&historical_relabel.remediation_phase_04_final_closure_rereview)
                .expect("Phase04 JSON");
        phase04.historical_lineage_decision = NorthStarClosureDecision::NotYet;
        historical_relabel.remediation_phase_04_final_closure_rereview =
            serde_json::to_vec(&phase04).expect("relabeled historical decision");
        assert!(M7ActiveSurfaceSnapshotV1::from_fixture_surface_bytes(historical_relabel).is_err());

        let mut claim_substitution = active_surface_inputs(&snapshot);
        let mut northstar: NorthStar07ClosureReviewView =
            serde_json::from_slice(&claim_substitution.northstar_07_closure_review)
                .expect("NorthStar07 JSON");
        northstar
            .claim_boundary
            .allowed_claims
            .push("caller substituted claim".to_string());
        claim_substitution.northstar_07_closure_review =
            serde_json::to_vec(&northstar).expect("substituted NorthStar07");
        assert!(M7ActiveSurfaceSnapshotV1::from_fixture_surface_bytes(claim_substitution).is_err());

        let mut secret_injection = active_surface_inputs(&snapshot);
        secret_injection
            .root_readme
            .extend_from_slice(b"\naccidental-token=ghp_0123456789abcdefghijklmnopqrstuv\n");
        assert!(M7ActiveSurfaceSnapshotV1::from_fixture_surface_bytes(secret_injection).is_err());

        let mut federation_relabel =
            M7ClaimCatalogV1::bounded_local_first().expect("claim catalog");
        let federation = federation_relabel
            .forbidden_claims
            .pop()
            .expect("public-federation claim");
        assert_eq!(federation.claim_id, M7ClaimIdV1::PublicFederation);
        federation_relabel.allowed_claims.push(federation);
        federation_relabel.catalog_digest = federation_relabel
            .expected_digest()
            .expect("relabeled digest");
        assert!(federation_relabel.validate().is_err());
    }

    #[test]
    fn evaluator_requires_one_snapshot_digest_across_m0_claims_and_publication() {
        let mut fixture = Fixture::new(M7ClosureDecision::Closed);
        let existing = fixture.artifact(M7EvidenceKind::ClaimBoundary);
        let M7EvidencePayload::ClaimBoundary(mut claim) = existing.payload.clone() else {
            panic!("claim-boundary payload");
        };
        claim.active_surface_snapshot_digest = content("substituted-active-surface-snapshot");
        let replacement = M7EvidenceArtifact::new(
            &fixture.bundle.manifest,
            existing.causal_subject.subject_digest,
            M7EvidencePayload::ClaimBoundary(claim),
        )
        .expect("cross-snapshot claim artifact");
        fixture.replace_artifact(replacement);
        let evaluation = evaluate_m7_closure(&fixture.bundle, &fixture.resolver);
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::ActiveSurfaceSnapshotMismatch)
        );
    }

    #[test]
    fn frozen_not_yet_surfaces_temper_positive_review_until_publication() {
        let pending =
            BTreeSet::from([M7EvaluationCaveatV1::PublicationPendingActiveSurfacesNotYet]);
        assert_eq!(
            decision_with_publication_state(true, Some(M7ClosureDecision::Closed), true),
            (M7ClosureDecision::ClosedWithCaveats, pending.clone())
        );
        assert_eq!(
            decision_with_publication_state(true, Some(M7ClosureDecision::ClosedWithCaveats), true,),
            (M7ClosureDecision::ClosedWithCaveats, pending)
        );
        assert_eq!(
            decision_with_publication_state(true, Some(M7ClosureDecision::NotYet), true),
            (M7ClosureDecision::NotYet, BTreeSet::new())
        );
        assert_eq!(
            decision_with_publication_state(false, Some(M7ClosureDecision::Closed), true),
            (M7ClosureDecision::NotYet, BTreeSet::new()),
            "blocked evaluations must not carry an otherwise-valid publication caveat"
        );
        assert_eq!(
            decision_with_publication_state(true, Some(M7ClosureDecision::Closed), false),
            (M7ClosureDecision::Closed, BTreeSet::new())
        );
    }

    #[test]
    fn deterministic_transcript_requires_exact_command_and_nonzero_counts() {
        let manifest = manifest(None);
        let exact_command = M7_DETERMINISTIC_CARGO_TEST_COMMAND
            .iter()
            .map(|part| (*part).to_string())
            .collect::<Vec<_>>();
        let passing_output = "test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n";

        let exact = M7CargoTestTranscriptV2::new(
            exact_command.clone(),
            manifest.manifest_digest().clone(),
            passing_output.to_string(),
            String::new(),
            0,
        )
        .expect("exact deterministic command");
        assert_eq!(
            exact.command.iter().map(String::as_str).collect::<Vec<_>>(),
            M7_DETERMINISTIC_CARGO_TEST_COMMAND
        );

        for invalid_command in [
            vec!["cargo", "test", "--all-targets"],
            vec!["cargo", "test", "--locked", "--workspace"],
            vec!["cargo", "test", "--all-targets", "--locked"],
            vec!["cargo", "test", "--locked", "--all-targets", "--quiet"],
            vec!["/usr/bin/cargo", "test", "--locked", "--all-targets"],
        ] {
            assert!(
                M7CargoTestTranscriptV2::new(
                    invalid_command.into_iter().map(str::to_string).collect(),
                    manifest.manifest_digest().clone(),
                    passing_output.to_string(),
                    String::new(),
                    0,
                )
                .is_err(),
                "invalid command vector must be rejected"
            );
        }

        let credential_bearing = M7CargoTestTranscriptV2::new(
            exact_command.clone(),
            manifest.manifest_digest().clone(),
            format!("{passing_output}OPENAI_API_KEY=must-not-enter-evidence\n"),
            String::new(),
            0,
        )
        .expect("structurally valid credential-bearing transcript")
        .canonical_bytes()
        .expect("credential-bearing transcript bytes");
        assert!(matches!(
            M7EvidenceArtifact::derive_causal_subject_from_sources(
                &manifest,
                M7EvidenceKind::DeterministicTestTranscript,
                &[M7SourceInputV2::new(
                    M7SourceRoleV2::CargoTestTranscript,
                    credential_bearing,
                )],
            ),
            Err(M7FoundationError::InvalidSource(_))
        ));

        let derived = signed_capture_evidence(&manifest);
        let M7EvidencePayload::DeterministicTestTranscript(counts) = derived.artifact().payload()
        else {
            panic!("deterministic transcript payload")
        };
        assert_eq!(counts.required_test_count, 12);
        assert_eq!(counts.executed_test_count, 12);
        assert_ne!(counts.required_test_count, 0);
        assert_ne!(counts.executed_test_count, 0);

        let empty_result = M7CargoTestTranscriptV2::new(
            exact_command,
            manifest.manifest_digest().clone(),
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n"
                .to_string(),
            String::new(),
            0,
        )
        .expect("structurally valid zero-count transcript")
        .canonical_bytes()
        .expect("zero-count transcript bytes");
        let capture = signed_capture_for_transcript(&manifest, &empty_result)
            .canonical_bytes(&manifest)
            .expect("zero-count capture bytes");
        assert!(matches!(
            M7EvidenceArtifact::derive_from_sources(
                &manifest,
                M7EvidenceKind::DeterministicTestTranscript,
                vec![
                    M7SourceInputV2::new(M7SourceRoleV2::CargoTestTranscript, empty_result,),
                    M7SourceInputV2::new(M7SourceRoleV2::SourceCaptureAttestation, capture),
                ],
            ),
            Err(M7FoundationError::InvalidSource(_))
        ));
    }

    #[test]
    fn fabricated_all_true_summaries_never_force_positive_closure() {
        for recommendation in [
            M7ClosureDecision::Closed,
            M7ClosureDecision::ClosedWithCaveats,
            M7ClosureDecision::NotYet,
        ] {
            let fixture = Fixture::new(recommendation);
            let evaluation = evaluate_m7_closure(&fixture.bundle, &fixture.resolver);
            assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
            assert_eq!(evaluation.reviewer_recommendation, Some(recommendation));
            assert!(!evaluation.evidence_complete);
            assert!(
                evaluation
                    .blockers
                    .contains(&M7Blocker::SourceCaptureAttestationAbsent)
            );
            assert!(
                evaluation
                    .blockers
                    .contains(&M7Blocker::ReviewerCryptographicAttestationAbsent)
            );
            assert!(evaluation.verified_kinds.is_empty());
            for kind in mandatory_evidence_kinds() {
                assert!(
                    evaluation
                        .blockers
                        .contains(&M7Blocker::MissingAuthoritativeSource(kind)),
                    "raw {kind:?} summary must not count as source-bound evidence"
                );
            }
        }
    }

    #[test]
    fn valid_external_attestations_clear_only_the_capture_and_reviewer_blockers() {
        let mut fixture =
            Fixture::new_with_provider(M7ClosureDecision::ClosedWithCaveats, Some(true));
        let capture = signed_capture_evidence(&fixture.bundle.manifest);
        fixture.replace_with_derived(capture);
        let reviewed_set = reviewed_evidence_set_digest(
            &fixture.bundle.manifest,
            &fixture.bundle.evidence_links,
            fixture.bundle.live_provider_link.as_ref(),
            &fixture.bundle.source_links,
        )
        .expect("reviewed evidence set");
        let reviewer = signed_reviewer_evidence(
            &fixture.bundle.manifest,
            reviewed_set,
            M7ClosureDecision::ClosedWithCaveats,
            reviewer_identity(),
            REVIEWER_ATTESTOR_SEED,
        );
        fixture.replace_with_signed_reviewer(reviewer);

        let evaluation = evaluate_m7_closure(&fixture.bundle, &fixture.resolver);
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert!(
            !evaluation
                .blockers
                .contains(&M7Blocker::SourceCaptureAttestationAbsent)
        );
        assert!(
            !evaluation
                .blockers
                .contains(&M7Blocker::ReviewerCryptographicAttestationAbsent)
        );
        assert!(
            !evaluation
                .blockers
                .contains(&M7Blocker::ReviewerCryptographicAttestationInvalid)
        );
        assert!(
            evaluation
                .verified_kinds
                .contains(&M7EvidenceKind::DeterministicTestTranscript)
        );
        assert!(
            evaluation
                .verified_kinds
                .contains(&M7EvidenceKind::IndependentReviewerRecommendation)
        );
    }

    #[test]
    fn source_capture_inventory_is_exact_typed_and_provider_conditional() {
        let manifest = manifest(None);
        let (_, capture) = signed_capture_sources(&manifest);
        let base = capture.captured_source_links().to_vec();
        assert_eq!(base.len(), 12);
        assert_eq!(source_capture_inventory_failure(&manifest, &base), None);
        assert!(!base.iter().any(|link| matches!(
            link.semantic_role,
            M7SourceRoleV2::SourceCaptureAttestation
                | M7SourceRoleV2::IndependentReview
                | M7SourceRoleV2::LiveProviderQualification
        )));

        let mut omitted = base.clone();
        omitted.retain(|link| link.semantic_role != M7SourceRoleV2::M0TruthBoundary);
        assert_eq!(
            source_capture_inventory_failure(&manifest, &omitted),
            Some(M7SourceCaptureInventoryFailure::MissingRole(
                M7SourceRoleV2::M0TruthBoundary,
            ))
        );

        for forbidden_role in [
            M7SourceRoleV2::SourceCaptureAttestation,
            M7SourceRoleV2::IndependentReview,
        ] {
            let mut forbidden = base.clone();
            forbidden.push(synthetic_inventory_link(&manifest, forbidden_role));
            forbidden.sort_by(|left, right| {
                (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
            });
            assert_eq!(
                source_capture_inventory_failure(&manifest, &forbidden),
                Some(M7SourceCaptureInventoryFailure::ForbiddenRole(
                    forbidden_role,
                ))
            );
        }

        let mut relabeled = base.clone();
        relabeled[0].source_kind = M7SourceKindV2::ClaimBoundary;
        assert!(matches!(
            source_capture_inventory_failure(&manifest, &relabeled),
            Some(M7SourceCaptureInventoryFailure::RelabeledRole(_))
        ));

        let mut cross_run = base.clone();
        cross_run[0].proof_run_id = "proof-run:inventory-substitution".to_string();
        assert!(matches!(
            source_capture_inventory_failure(&manifest, &cross_run),
            Some(M7SourceCaptureInventoryFailure::CrossRunRole(_))
        ));

        let mut stale_manifest = base.clone();
        stale_manifest[0].manifest_digest = content("stale-inventory-manifest");
        assert!(matches!(
            source_capture_inventory_failure(&manifest, &stale_manifest),
            Some(M7SourceCaptureInventoryFailure::StaleManifestRole(_))
        ));

        let mut causal_relabel = base.clone();
        causal_relabel[0].causal_subject.proof_chain_digest = content("other-proof-chain");
        assert!(matches!(
            source_capture_inventory_failure(&manifest, &causal_relabel),
            Some(M7SourceCaptureInventoryFailure::CausalMismatch(_))
        ));

        for substitute in [
            {
                let mut links = base.clone();
                links[0].digest = content("substituted-source-bytes");
                links
            },
            {
                let mut links = base.clone();
                links[0].byte_length += 1;
                links
            },
            {
                let mut links = base.clone();
                links[0].causal_subject.subject_digest = content("reassigned-causal-subject");
                links
            },
        ] {
            let failure =
                compare_source_capture_inventory(&substitute, &base).expect_err("substitution");
            assert!(matches!(
                M7Blocker::SourceCaptureInventoryFailure(failure),
                M7Blocker::SourceCaptureInventoryFailure(
                    M7SourceCaptureInventoryFailure::LinkMismatch(_)
                )
            ));
        }

        let mut unexpected_provider = base.clone();
        unexpected_provider.push(synthetic_inventory_link(
            &manifest,
            M7SourceRoleV2::LiveProviderQualification,
        ));
        unexpected_provider.sort_by(|left, right| {
            (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
        });
        assert_eq!(
            source_capture_inventory_failure(&manifest, &unexpected_provider),
            Some(M7SourceCaptureInventoryFailure::UnexpectedRole(
                M7SourceRoleV2::LiveProviderQualification,
            ))
        );

        let provider_source = live_provider_source_fixture("proof-run:m7:1", 150);
        let provider_completed = provider_source
            .completed_invocation()
            .expect("completed provider invocation");
        let provider_scope =
            LiveProviderQualificationScope::from_prepared(provider_completed.prepared_seed())
                .expect("provider scope");
        let scoped_manifest = self::manifest(Some(provider_scope));
        let (_, scoped_capture) = signed_capture_sources(&scoped_manifest);
        assert_eq!(scoped_capture.captured_source_links().len(), 13);
        assert!(
            scoped_capture
                .captured_source_links()
                .iter()
                .any(|link| { link.semantic_role == M7SourceRoleV2::LiveProviderQualification })
        );
        let mut scoped_omission = scoped_capture.captured_source_links().to_vec();
        scoped_omission
            .retain(|link| link.semantic_role != M7SourceRoleV2::LiveProviderQualification);
        assert_eq!(
            source_capture_inventory_failure(&scoped_manifest, &scoped_omission),
            Some(M7SourceCaptureInventoryFailure::MissingRole(
                M7SourceRoleV2::LiveProviderQualification,
            ))
        );
    }

    #[test]
    fn detached_attestation_signature_and_scope_tamper_matrix_fails_closed() {
        let manifest = manifest(None);
        let (transcript, capture) = signed_capture_sources(&manifest);
        let derive_capture = |capture: M7SourceCaptureAttestationV2| {
            M7EvidenceArtifact::derive_from_sources(
                &manifest,
                M7EvidenceKind::DeterministicTestTranscript,
                vec![
                    M7SourceInputV2::new(M7SourceRoleV2::CargoTestTranscript, transcript.clone()),
                    M7SourceInputV2::new(
                        M7SourceRoleV2::SourceCaptureAttestation,
                        canonical_json(&capture).expect("capture bytes"),
                    ),
                ],
            )
        };

        let mut bad_signature = capture.clone();
        bad_signature.signature_hex = hex_encode(&[0x00; ED25519_SIGNATURE_BYTES]);
        assert!(derive_capture(bad_signature).is_err());

        let wrong_capture_key = test_attestor([0x73; 32]);
        let capture_preimage = M7SourceCaptureAttestationV2::signing_preimage(
            &manifest,
            capture.captured_source_links(),
            300,
        )
        .expect("capture preimage");
        assert!(
            M7SourceCaptureAttestationV2::from_external_signature(
                &manifest,
                capture.captured_source_links(),
                300,
                wrong_capture_key.sign(&capture_preimage).as_ref(),
            )
            .is_err()
        );

        let mut source_digest_tamper = capture.clone();
        source_digest_tamper
            .captured_source_links
            .iter_mut()
            .find(|link| link.semantic_role == M7SourceRoleV2::CargoTestTranscript)
            .expect("transcript source link")
            .digest = content("wrong-transcript");
        assert!(derive_capture(source_digest_tamper).is_err());

        let mut capture_manifest_tamper = capture;
        capture_manifest_tamper.manifest_digest = content("wrong-manifest");
        assert!(derive_capture(capture_manifest_tamper).is_err());

        let reviewed_set = content("reviewed-set");
        let identity = reviewer_identity();
        let rationale = content("reviewer-rationale");
        let independence = content("reviewer-independence-statement");
        let reviewer_preimage = M7IndependentReviewSourceV2::signing_preimage(
            &identity,
            manifest.manifest_digest().clone(),
            reviewed_set.clone(),
            M7ClosureDecision::Closed,
            rationale.clone(),
            independence.clone(),
        )
        .expect("reviewer preimage");
        let reviewer = M7IndependentReviewSourceV2::from_external_signature(
            identity.clone(),
            manifest.manifest_digest().clone(),
            reviewed_set,
            M7ClosureDecision::Closed,
            rationale,
            independence,
            test_attestor(REVIEWER_ATTESTOR_SEED)
                .sign(&reviewer_preimage)
                .as_ref(),
        )
        .expect("reviewer attestation");
        let derive_reviewer = |reviewer: M7IndependentReviewSourceV2| {
            M7EvidenceArtifact::derive_from_sources(
                &manifest,
                M7EvidenceKind::IndependentReviewerRecommendation,
                vec![M7SourceInputV2::new(
                    M7SourceRoleV2::IndependentReview,
                    canonical_json(&reviewer).expect("reviewer bytes"),
                )],
            )
        };

        let mut bad_reviewer_signature = reviewer.clone();
        bad_reviewer_signature.signature_hex = hex_encode(&[0x00; ED25519_SIGNATURE_BYTES]);
        assert!(derive_reviewer(bad_reviewer_signature).is_err());
        let mut reviewed_manifest_tamper = reviewer.clone();
        reviewed_manifest_tamper.reviewed_manifest_digest = content("wrong-reviewed-manifest");
        assert!(derive_reviewer(reviewed_manifest_tamper).is_err());
        let mut evidence_set_tamper = reviewer.clone();
        evidence_set_tamper.reviewed_evidence_set_digest = content("wrong-evidence-set");
        assert!(derive_reviewer(evidence_set_tamper).is_err());
        let mut recommendation_tamper = reviewer.clone();
        recommendation_tamper.recommendation = M7ClosureDecision::NotYet;
        assert!(derive_reviewer(recommendation_tamper).is_err());
        let mut participant = reviewer;
        participant.participation_declaration =
            M7ReviewerParticipationDeclarationV1::ImplementationParticipant;
        assert!(derive_reviewer(participant).is_err());
    }

    #[test]
    fn attestor_identity_reuse_and_late_reviewer_substitution_fail_closed() {
        let mut capture_reuses_implementation = manifest(None);
        capture_reuses_implementation.source_capture_identity =
            test_identity("implementer:one", [0x73; 32]);
        assert!(capture_reuses_implementation.validate().is_err());

        let mut reviewer_reuses_implementation = manifest(None);
        reviewer_reuses_implementation.reviewer_identity =
            test_identity("implementer:one", [0x74; 32]);
        assert!(reviewer_reuses_implementation.validate().is_err());

        let mut unpinned = Fixture::new_with_provider(M7ClosureDecision::Closed, Some(true));
        let capture = signed_capture_evidence(&unpinned.bundle.manifest);
        unpinned.replace_with_derived(capture);
        let reviewed_set = reviewed_evidence_set_digest(
            &unpinned.bundle.manifest,
            &unpinned.bundle.evidence_links,
            unpinned.bundle.live_provider_link.as_ref(),
            &unpinned.bundle.source_links,
        )
        .expect("reviewed evidence set");
        let alternate = test_identity("reviewer:unpinned", [0x75; 32]);
        let reviewer = signed_reviewer_evidence(
            &unpinned.bundle.manifest,
            reviewed_set,
            M7ClosureDecision::Closed,
            alternate,
            [0x75; 32],
        );
        unpinned.replace_with_signed_reviewer(reviewer);
        let evaluation = evaluate_m7_closure(&unpinned.bundle, &unpinned.resolver);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::ReviewerCryptographicAttestationInvalid)
        );

        let fixture = Fixture::new(M7ClosureDecision::Closed);
        let mut substituted = fixture.bundle.clone();
        substituted.reviewer_identity = test_identity("reviewer:substituted", [0x75; 32]);
        assert!(substituted.validate().is_err());
    }

    #[test]
    fn deletion_and_corruption_of_every_required_family_fail_closed() {
        for kind in mandatory_evidence_kinds() {
            let fixture = Fixture::new(M7ClosureDecision::Closed);
            let link = fixture
                .bundle
                .evidence_links
                .iter()
                .find(|link| link.kind == kind)
                .expect("required link");

            let mut deleted = fixture.resolver.clone();
            deleted.bytes.remove(&link.digest);
            let evaluation = evaluate_m7_closure(&fixture.bundle, &deleted);
            assert_eq!(
                evaluation.decision,
                M7ClosureDecision::NotYet,
                "deletion must fail for {kind:?}"
            );
            assert!(!evaluation.evidence_complete);

            let mut corrupted = fixture.resolver.clone();
            corrupted
                .bytes
                .get_mut(&link.digest)
                .expect("corruption target")
                .push(0xff);
            let evaluation = evaluate_m7_closure(&fixture.bundle, &corrupted);
            assert_eq!(
                evaluation.decision,
                M7ClosureDecision::NotYet,
                "corruption must fail for {kind:?}"
            );
            assert!(!evaluation.evidence_complete);
        }
    }

    #[test]
    fn listed_operational_negative_controls_all_return_not_yet() {
        let mut failed_tests = Fixture::new(M7ClosureDecision::Closed);
        let mut artifact = failed_tests.artifact(M7EvidenceKind::DeterministicTestTranscript);
        let M7EvidencePayload::DeterministicTestTranscript(payload) = &mut artifact.payload else {
            panic!("test payload");
        };
        payload.failed_test_count = 1;
        failed_tests.replace_artifact(artifact);
        assert_family_fails_closed(
            &evaluate_m7_closure(&failed_tests.bundle, &failed_tests.resolver),
            M7EvidenceKind::DeterministicTestTranscript,
            M7SemanticFailure::FailedTests,
        );

        let mut invented_worker = Fixture::new(M7ClosureDecision::Closed);
        let mut artifact = invented_worker.artifact(M7EvidenceKind::M4WorkerEcology);
        let M7EvidencePayload::M4WorkerEcology(payload) = &mut artifact.payload else {
            panic!("worker payload");
        };
        payload.invented_worker_result_count = 1;
        invented_worker.replace_artifact(artifact);
        assert_family_fails_closed(
            &evaluate_m7_closure(&invented_worker.bundle, &invented_worker.resolver),
            M7EvidenceKind::M4WorkerEcology,
            M7SemanticFailure::InventedOrIncompleteWorkerResult,
        );

        let mut missed_wake = Fixture::new(M7ClosureDecision::Closed);
        let mut artifact = missed_wake.artifact(M7EvidenceKind::M2SchedulerWakeRestart);
        let M7EvidencePayload::M2SchedulerWakeRestart(payload) = &mut artifact.payload else {
            panic!("scheduler payload");
        };
        payload.future_wake_observed = false;
        payload.missed_wake_count = 1;
        missed_wake.replace_artifact(artifact);
        assert_family_fails_closed(
            &evaluate_m7_closure(&missed_wake.bundle, &missed_wake.resolver),
            M7EvidenceKind::M2SchedulerWakeRestart,
            M7SemanticFailure::MissedWakeOrRestart,
        );

        let mut incomplete_rollback = Fixture::new(M7ClosureDecision::Closed);
        let mut artifact = incomplete_rollback.artifact(M7EvidenceKind::M5ActivationRollback);
        let M7EvidencePayload::M5ActivationRollback(payload) = &mut artifact.payload else {
            panic!("rollback payload");
        };
        payload.rollback_completed = false;
        payload.runtime_behavior_restored = false;
        incomplete_rollback.replace_artifact(artifact);
        assert_family_fails_closed(
            &evaluate_m7_closure(&incomplete_rollback.bundle, &incomplete_rollback.resolver),
            M7EvidenceKind::M5ActivationRollback,
            M7SemanticFailure::RollbackIncomplete,
        );

        let mut tampered_exchange = Fixture::new(M7ClosureDecision::Closed);
        let mut artifact = tampered_exchange.artifact(M7EvidenceKind::M6FactoryExchange);
        let M7EvidencePayload::M6FactoryExchange(payload) = &mut artifact.payload else {
            panic!("exchange payload");
        };
        payload.negative_control_suite_passed = false;
        tampered_exchange.replace_artifact(artifact);
        assert_family_fails_closed(
            &evaluate_m7_closure(&tampered_exchange.bundle, &tampered_exchange.resolver),
            M7EvidenceKind::M6FactoryExchange,
            M7SemanticFailure::ExchangeTamperedOrIncomplete,
        );

        let mut acknowledgement_overreach = Fixture::new(M7ClosureDecision::Closed);
        let mut artifact = acknowledgement_overreach.artifact(M7EvidenceKind::M6FactoryExchange);
        let M7EvidencePayload::M6FactoryExchange(payload) = &mut artifact.payload else {
            panic!("exchange payload");
        };
        payload.acknowledgement_used_as_adoption_evidence = true;
        acknowledgement_overreach.replace_artifact(artifact);
        assert_family_fails_closed(
            &evaluate_m7_closure(
                &acknowledgement_overreach.bundle,
                &acknowledgement_overreach.resolver,
            ),
            M7EvidenceKind::M6FactoryExchange,
            M7SemanticFailure::ExchangeTamperedOrIncomplete,
        );

        let mut unresolved_quarantine = Fixture::new(M7ClosureDecision::Closed);
        let mut artifact = unresolved_quarantine.artifact(M7EvidenceKind::M6FactoryExchange);
        let M7EvidencePayload::M6FactoryExchange(payload) = &mut artifact.payload else {
            panic!("exchange payload");
        };
        payload.unresolved_quarantine_count = 1;
        unresolved_quarantine.replace_artifact(artifact);
        assert_family_fails_closed(
            &evaluate_m7_closure(
                &unresolved_quarantine.bundle,
                &unresolved_quarantine.resolver,
            ),
            M7EvidenceKind::M6FactoryExchange,
            M7SemanticFailure::UnresolvedQuarantine,
        );

        let reviewer_absent = Fixture::new(M7ClosureDecision::Closed);
        let reviewer_link = reviewer_absent
            .bundle
            .evidence_links
            .iter()
            .find(|link| link.kind == M7EvidenceKind::IndependentReviewerRecommendation)
            .expect("reviewer link");
        let mut resolver = reviewer_absent.resolver.clone();
        resolver.bytes.remove(&reviewer_link.digest);
        let evaluation = evaluate_m7_closure(&reviewer_absent.bundle, &resolver);
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert!(evaluation.blockers.contains(&M7Blocker::ReviewerAbsent));
    }

    #[test]
    fn malformed_stale_cross_run_and_resolver_failures_return_not_yet() {
        let mut malformed = Fixture::new(M7ClosureDecision::Closed);
        malformed.replace_artifact_bytes_but_keep_link_scope(
            M7EvidenceKind::M3CapabilityEffects,
            b"{not-json".to_vec(),
        );
        let evaluation = evaluate_m7_closure(&malformed.bundle, &malformed.resolver);
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert!(evaluation.blockers.contains(&M7Blocker::MalformedEvidence(
            M7EvidenceKind::M3CapabilityEffects
        )));

        let mut stale = Fixture::new(M7ClosureDecision::Closed);
        let mut artifact = stale.artifact(M7EvidenceKind::M1CandidateLifecycle);
        artifact.manifest_digest = content("stale-manifest");
        stale.replace_artifact_bytes_but_keep_link_scope(
            M7EvidenceKind::M1CandidateLifecycle,
            artifact.canonical_bytes().expect("stale bytes"),
        );
        let evaluation = evaluate_m7_closure(&stale.bundle, &stale.resolver);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::StaleManifestEvidence(
                    M7EvidenceKind::M1CandidateLifecycle
                ))
        );

        let mut cross_run = Fixture::new(M7ClosureDecision::Closed);
        let mut artifact = cross_run.artifact(M7EvidenceKind::M2SchedulerWakeRestart);
        artifact.proof_run_id = "proof-run:other".to_string();
        cross_run.replace_artifact_bytes_but_keep_link_scope(
            M7EvidenceKind::M2SchedulerWakeRestart,
            artifact.canonical_bytes().expect("cross-run bytes"),
        );
        let evaluation = evaluate_m7_closure(&cross_run.bundle, &cross_run.resolver);
        assert!(evaluation.blockers.contains(&M7Blocker::CrossRunEvidence(
            M7EvidenceKind::M2SchedulerWakeRestart
        )));

        let resolver_failure = Fixture::new(M7ClosureDecision::Closed);
        let target = resolver_failure
            .bundle
            .evidence_links
            .iter()
            .find(|link| link.kind == M7EvidenceKind::M0TruthBaseline)
            .expect("resolver target");
        let mut resolver = resolver_failure.resolver.clone();
        resolver.failures.insert(target.digest.clone());
        let evaluation = evaluate_m7_closure(&resolver_failure.bundle, &resolver);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::ResolverFailure(M7EvidenceKind::M0TruthBaseline))
        );
    }

    #[test]
    fn exact_source_bytes_are_rederived_and_tampering_fails_closed() {
        let mut fixture = Fixture::new(M7ClosureDecision::Closed);
        let snapshot = exact_active_surface_snapshot();
        let truth_source_bytes = M7TruthBoundarySourceV3::new(snapshot.clone())
            .expect("truth-boundary source")
            .canonical_bytes()
            .expect("truth source bytes");
        let claim_source_bytes = M7ClaimBoundarySourceV3::new(snapshot.clone())
            .expect("claim-boundary source")
            .canonical_bytes()
            .expect("claim source bytes");
        let publication_source_bytes = M7PublicationPolicySourceV3::new(snapshot)
            .expect("publication-policy source")
            .canonical_bytes()
            .expect("publication source bytes");
        assert!(matches!(
            M7EvidenceArtifact::derive_from_sources(
                &fixture.bundle.manifest,
                M7EvidenceKind::M0TruthBaseline,
                vec![
                    M7SourceInputV2::new(
                        M7SourceRoleV2::M0TruthBoundary,
                        truth_source_bytes.clone(),
                    ),
                    M7SourceInputV2::new(
                        M7SourceRoleV2::M0TruthBoundary,
                        truth_source_bytes.clone(),
                    ),
                ],
            ),
            Err(M7FoundationError::InvalidSource(_))
        ));
        for (kind, role, source_bytes) in [
            (
                M7EvidenceKind::M0TruthBaseline,
                M7SourceRoleV2::M0TruthBoundary,
                truth_source_bytes,
            ),
            (
                M7EvidenceKind::ClaimBoundary,
                M7SourceRoleV2::ClaimBoundary,
                claim_source_bytes,
            ),
            (
                M7EvidenceKind::PublicationPolicy,
                M7SourceRoleV2::PublicationPolicy,
                publication_source_bytes,
            ),
        ] {
            let derived = M7EvidenceArtifact::derive_from_sources(
                &fixture.bundle.manifest,
                kind,
                vec![M7SourceInputV2::new(role, source_bytes)],
            )
            .unwrap_or_else(|error| panic!("derive exact {kind:?} evidence: {error}"));
            fixture.replace_with_derived(derived);
        }

        let evaluation = evaluate_m7_closure(&fixture.bundle, &fixture.resolver);
        for kind in [
            M7EvidenceKind::M0TruthBaseline,
            M7EvidenceKind::ClaimBoundary,
            M7EvidenceKind::PublicationPolicy,
        ] {
            assert!(evaluation.verified_kinds.contains(&kind));
        }
        assert!(
            !evaluation
                .blockers
                .contains(&M7Blocker::MissingAuthoritativeSource(
                    M7EvidenceKind::M0TruthBaseline
                ))
        );
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);

        let source_link = fixture
            .bundle
            .source_links
            .iter()
            .find(|link| link.semantic_role == M7SourceRoleV2::M0TruthBoundary)
            .expect("M0 source link")
            .clone();
        let mut missing = fixture.resolver.clone();
        missing.bytes.remove(&source_link.digest);
        let evaluation = evaluate_m7_closure(&fixture.bundle, &missing);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::MissingSourceBytes {
                    kind: M7EvidenceKind::M0TruthBaseline,
                    role: M7SourceRoleV2::M0TruthBoundary,
                })
        );

        let mut corrupted = fixture.resolver.clone();
        let bytes = corrupted
            .bytes
            .get_mut(&source_link.digest)
            .expect("source corruption target");
        bytes[0] ^= 1;
        let evaluation = evaluate_m7_closure(&fixture.bundle, &corrupted);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::SourceDigestMismatch {
                    kind: M7EvidenceKind::M0TruthBaseline,
                    role: M7SourceRoleV2::M0TruthBoundary,
                })
        );

        let mut artifact = fixture.artifact(M7EvidenceKind::M0TruthBaseline);
        let M7EvidencePayload::M0TruthBaseline(payload) = &mut artifact.payload else {
            panic!("M0 payload")
        };
        payload.seeded_status_used_as_proof = true;
        fixture.replace_artifact(artifact);
        let evaluation = evaluate_m7_closure(&fixture.bundle, &fixture.resolver);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::SourcePayloadMismatch(
                    M7EvidenceKind::M0TruthBaseline
                ))
        );
    }

    #[test]
    fn m2_restart_evidence_is_derived_from_preserved_state_and_due_wakes() {
        let (before, after) = exact_m2_supervisor_states();
        let payload = derive_m2_from_states(
            &manifest(None),
            &supervisor_state_bytes(&before),
            &supervisor_state_bytes(&after),
        )
        .expect("derive exact restart evidence");
        let M7EvidencePayload::M2SchedulerWakeRestart(evidence) = payload else {
            panic!("M2 restart payload")
        };
        assert!(evidence.future_wake_observed);
        assert!(evidence.process_restart_observed);
        assert!(evidence.restart_reconstructed);
        assert_eq!(evidence.missed_wake_count, 0);

        let mut with_missed_due_wake = after.clone();
        let post_export_job_id = m2_post_export_job_id(&before);
        let mut missed_job = before
            .jobs
            .get(&post_export_job_id)
            .expect("future job fixture")
            .clone();
        let before_receipt = before
            .effect_receipts
            .get(&missed_job.effect_receipt_id)
            .expect("future receipt fixture")
            .clone();
        missed_job.job_id = "job:m7-intentionally-missed".to_string();
        missed_job.idempotency_key = "effect-key:m7-intentionally-missed".to_string();
        missed_job.effect_receipt_id = "receipt:m7-intentionally-missed".to_string();
        missed_job.next_wake_at_ms = Some(with_missed_due_wake.updated_at_ms);
        let mut missed_receipt = before_receipt;
        missed_receipt.effect_receipt_id = missed_job.effect_receipt_id.clone();
        missed_receipt.job_id = missed_job.job_id.clone();
        missed_receipt.idempotency_key = missed_job.idempotency_key.clone();
        with_missed_due_wake.idempotency_index.insert(
            missed_job.idempotency_key.clone(),
            missed_job.job_id.clone(),
        );
        with_missed_due_wake
            .effect_receipts
            .insert(missed_receipt.effect_receipt_id.clone(), missed_receipt);
        with_missed_due_wake
            .jobs
            .insert(missed_job.job_id.clone(), missed_job);
        let payload = derive_m2_from_states(
            &manifest(None),
            &supervisor_state_bytes(&before),
            &supervisor_state_bytes(&with_missed_due_wake),
        )
        .expect("derive explicit missed-wake count");
        let M7EvidencePayload::M2SchedulerWakeRestart(evidence) = payload else {
            panic!("M2 missed-wake payload")
        };
        assert_eq!(evidence.missed_wake_count, 1);
        assert!(matches!(
            M7EvidencePayload::M2SchedulerWakeRestart(evidence).semantic_failure(),
            Some(M7SemanticFailure::MissedWakeOrRestart)
        ));
    }

    #[test]
    fn m2_restart_rejects_two_individually_valid_post_export_candidates() {
        let (before, after) = exact_m2_supervisor_states_for_exports(
            &[
                content("m5-export-candidate-one"),
                content("m5-export-candidate-two"),
            ],
            content("m6-completion-bundle-content"),
        );
        let error = derive_m2_from_states(
            &manifest(None),
            &supervisor_state_bytes(&before),
            &supervisor_state_bytes(&after),
        )
        .expect_err("two valid post-export candidates must fail closed");
        assert!(matches!(
            error,
            M7FoundationError::InvalidSource(message)
                if message.contains("found 2")
        ));
    }

    #[test]
    fn m2_restart_rejects_dropped_changed_or_regressed_pre_restart_state() {
        let (before, after) = exact_m2_supervisor_states();
        let before_bytes = supervisor_state_bytes(&before);
        let mut adversarial = Vec::new();

        let mut same_owner = after.clone();
        same_owner.heartbeat.owner_id = before.heartbeat.owner_id.clone();
        adversarial.push(("same owner epoch", same_owner));

        let mut changed_job_identity = after.clone();
        let post_export_job_id = m2_post_export_job_id(&before);
        changed_job_identity
            .jobs
            .get_mut(&post_export_job_id)
            .expect("future job")
            .created_at_ms += 1;
        adversarial.push(("changed immutable job identity", changed_job_identity));

        let mut dropped_terminal = after.clone();
        let terminal = dropped_terminal
            .jobs
            .remove("job:m7-terminal")
            .expect("terminal job");
        dropped_terminal
            .idempotency_index
            .remove(&terminal.idempotency_key);
        dropped_terminal
            .effect_receipts
            .remove(&terminal.effect_receipt_id);
        adversarial.push(("dropped terminal job and indexes", dropped_terminal));

        let mut changed_committed_receipt = after.clone();
        let terminal_receipt_id = before
            .jobs
            .get("job:m7-terminal")
            .expect("terminal job")
            .effect_receipt_id
            .clone();
        changed_committed_receipt
            .effect_receipts
            .get_mut(&terminal_receipt_id)
            .expect("terminal receipt")
            .delivery_count += 1;
        adversarial.push(("changed committed receipt", changed_committed_receipt));

        let mut changed_approval = after.clone();
        changed_approval
            .approval_resolutions
            .get_mut("approval:m7-granted")
            .expect("approval resolution")
            .evidence_ref = "evidence:rewritten-grant".to_string();
        adversarial.push(("changed approval resolution", changed_approval));

        let mut dropped_shutdown = after.clone();
        dropped_shutdown.shutdowns.clear();
        adversarial.push(("dropped shutdown history", dropped_shutdown));

        let preserved_wake = before.wakes.first().expect("pre-restart wake");
        let mut changed_wake_identity = after.clone();
        changed_wake_identity
            .wakes
            .iter_mut()
            .find(|wake| wake.wake_id == preserved_wake.wake_id)
            .expect("preserved wake")
            .scheduled_at_ms += 1;
        adversarial.push(("changed wake identity", changed_wake_identity));

        let consumed_before = before
            .wakes
            .iter()
            .find(|wake| wake.consumed_at_ms.is_some())
            .expect("pre-restart consumed wake");
        let mut regressed_consumption = after;
        regressed_consumption
            .wakes
            .iter_mut()
            .find(|wake| wake.wake_id == consumed_before.wake_id)
            .expect("preserved consumed wake")
            .consumed_at_ms = None;
        adversarial.push(("regressed wake consumption", regressed_consumption));

        for (label, changed_after) in adversarial {
            assert!(
                derive_m2_from_states(
                    &manifest(None),
                    &before_bytes,
                    &supervisor_state_bytes(&changed_after),
                )
                .is_err(),
                "{label} must fail restart derivation"
            );
        }
    }

    #[test]
    fn m3_requires_exact_unique_successful_receipt_attestation_pairs_and_families() {
        let (export_bytes, _) = exact_m5_source_bytes();
        let bundle = parse_m5_export(&export_bytes).expect("exact M5 export");
        let service_evidence = bundle
            .active_cycle()
            .m4_workflows()
            .iter()
            .map(|workflow| {
                (
                    workflow.service_receipts().to_vec(),
                    workflow.service_attestations().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        let derive =
            |evidence: &[(Vec<InvocationReceipt>, Vec<ServiceInvocationAttestation>)]| {
                derive_m3_from_service_evidence(
                    evidence.iter().map(|(receipts, attestations)| {
                        (receipts.as_slice(), attestations.as_slice())
                    }),
                )
            };
        let exact = derive(&service_evidence).expect("exact typed M3 service evidence");
        let expected_pairs = service_evidence
            .iter()
            .map(|(receipts, _)| receipts.len())
            .sum::<usize>() as u32;
        assert_eq!(exact.required_capability_count, expected_pairs);
        assert_eq!(exact.successful_receipt_count, expected_pairs);
        assert!(exact.all_receipts_resolved);
        assert!(exact.all_attestations_valid);
        assert_eq!(exact.generic_bypass_count, 0);

        let mut dropped_attestation = service_evidence.clone();
        dropped_attestation[0].1.pop();
        assert!(derive(&dropped_attestation).is_err());

        let mut corrupt_receipt = service_evidence.clone();
        let mut receipt_value =
            serde_json::to_value(&corrupt_receipt[0].0[0]).expect("receipt value");
        receipt_value["output_digest"] =
            serde_json::to_value(content("corrupt-M3-output")).expect("digest value");
        corrupt_receipt[0].0[0] =
            serde_json::from_value(receipt_value).expect("corrupt receipt shape");
        assert!(derive(&corrupt_receipt).is_err());

        let mut cross_linked_attestation = service_evidence.clone();
        cross_linked_attestation[0].1[0].receipt_digest = content("other-M3-receipt");
        assert!(derive(&cross_linked_attestation).is_err());

        let mut family_relabel = service_evidence.clone();
        family_relabel[0].1[0].family = match family_relabel[0].1[0].family {
            NativeServiceFamily::Build => NativeServiceFamily::Validation,
            _ => NativeServiceFamily::Build,
        };
        assert!(derive(&family_relabel).is_err());

        let mut duplicate_pair = service_evidence.clone();
        let duplicate_receipt = duplicate_pair[0].0[0].clone();
        let duplicate_attestation = duplicate_pair[0].1[0].clone();
        duplicate_pair[0].0.push(duplicate_receipt);
        duplicate_pair[0].1.push(duplicate_attestation);
        assert!(derive(&duplicate_pair).is_err());

        let without_operations = service_evidence
            .iter()
            .map(|(receipts, attestations)| {
                let attestations_by_invocation = attestations
                    .iter()
                    .map(|attestation| (attestation.invocation_id.as_str(), attestation))
                    .collect::<BTreeMap<_, _>>();
                let filtered_receipts = receipts
                    .iter()
                    .filter(|receipt| receipt.family() != NativeServiceFamily::Operations)
                    .cloned()
                    .collect::<Vec<_>>();
                let filtered_attestations = filtered_receipts
                    .iter()
                    .map(|receipt| {
                        (**attestations_by_invocation
                            .get(receipt.invocation_id())
                            .expect("paired attestation"))
                        .clone()
                    })
                    .collect::<Vec<_>>();
                (filtered_receipts, filtered_attestations)
            })
            .collect::<Vec<_>>();
        assert!(derive(&without_operations).is_err());
    }

    #[test]
    fn m5_success_requires_exact_export_and_final_chronology_bound_probe() {
        // The helper completes M6 and the M2 restart before the final probe;
        // its new M3 request is sealed to that exact chronology.
        let (export_bytes, probe_bytes) = exact_m5_source_bytes();
        let manifest = manifest(None);

        for (kind, role) in [
            (
                M7EvidenceKind::M1CandidateLifecycle,
                M7SourceRoleV2::M5ExportM1,
            ),
            (
                M7EvidenceKind::M3CapabilityEffects,
                M7SourceRoleV2::M5ExportM3,
            ),
            (M7EvidenceKind::M4WorkerEcology, M7SourceRoleV2::M5ExportM4),
        ] {
            let derived = M7EvidenceArtifact::derive_from_sources(
                &manifest,
                kind,
                vec![M7SourceInputV2::new(role, export_bytes.clone())],
            )
            .expect("exact M5 export derives its proven family");
            assert_eq!(derived.artifact().kind(), kind);
            assert_eq!(derived.source_blobs().len(), 1);
        }

        assert!(matches!(
            M7EvidenceArtifact::derive_from_sources(
                &manifest,
                M7EvidenceKind::M5ActivationRollback,
                vec![M7SourceInputV2::new(
                    M7SourceRoleV2::M5ExportRollback,
                    export_bytes.clone(),
                )],
            ),
            Err(M7FoundationError::InvalidSource(_))
        ));
        let rollback = M7EvidenceArtifact::derive_from_sources(
            &manifest,
            M7EvidenceKind::M5ActivationRollback,
            vec![
                M7SourceInputV2::new(M7SourceRoleV2::M5ExportRollback, export_bytes.clone()),
                M7SourceInputV2::new(
                    M7SourceRoleV2::M5FinalPostRollbackProbe,
                    probe_bytes.clone(),
                ),
            ],
        )
        .expect("derive rollback only from the export plus fresh execution probe");
        let M7EvidencePayload::M5ActivationRollback(payload) = rollback.artifact().payload() else {
            panic!("M5 rollback payload")
        };
        assert!(payload.successor_activated);
        assert!(payload.real_failure_observed);
        assert!(payload.rollback_completed);
        assert!(payload.state_reference_restored);
        assert!(payload.runtime_behavior_restored);
        assert!(!payload.incomplete_mutation);

        let ordinary_probe_bytes = exact_ordinary_m5_probe_bytes();
        assert!(
            M7EvidenceArtifact::derive_from_sources(
                &manifest,
                M7EvidenceKind::M5ActivationRollback,
                vec![
                    M7SourceInputV2::new(M7SourceRoleV2::M5ExportRollback, export_bytes.clone(),),
                    M7SourceInputV2::new(
                        M7SourceRoleV2::M5FinalPostRollbackProbe,
                        ordinary_probe_bytes,
                    ),
                ],
            )
            .is_err(),
            "the valid ordinary V1 probe used inside M6 must never satisfy M7's final source role"
        );

        let mut corrupted_probe = probe_bytes;
        corrupted_probe[0] ^= 1;
        assert!(
            M7EvidenceArtifact::derive_from_sources(
                &manifest,
                M7EvidenceKind::M5ActivationRollback,
                vec![
                    M7SourceInputV2::new(M7SourceRoleV2::M5ExportRollback, export_bytes,),
                    M7SourceInputV2::new(
                        M7SourceRoleV2::M5FinalPostRollbackProbe,
                        corrupted_probe,
                    ),
                ],
            )
            .is_err()
        );
        assert!(matches!(
            M7EvidenceArtifact::derive_from_sources(
                &manifest,
                M7EvidenceKind::M6FactoryExchange,
                vec![M7SourceInputV2::new(
                    M7SourceRoleV2::M6Completion,
                    b"caller-authored-M6-success".to_vec(),
                )],
            ),
            Err(M7FoundationError::InvalidSource(_))
        ));
    }

    #[test]
    fn evaluator_rejects_fresh_manifest_challenge_over_old_valid_m5_lineage() {
        let mut fixture = Fixture::new(M7ClosureDecision::Closed);
        let mut artifact = fixture.artifact(M7EvidenceKind::M5ActivationRollback);
        let M7EvidencePayload::M5ActivationRollback(m5) = &mut artifact.payload else {
            panic!("M5 payload")
        };
        let old_manifest_digest = content("old-proof-run-manifest");
        assert_ne!(old_manifest_digest, fixture.bundle.manifest.manifest_digest);
        m5.active_operator_context_digest = old_manifest_digest.clone();
        m5.rollback_operator_context_digest = old_manifest_digest;
        fixture.replace_artifact(artifact);

        let evaluation = evaluate_m7_closure(&fixture.bundle, &fixture.resolver);
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::M5ExportLineageMismatch)
        );
        assert!(
            !evaluation
                .verified_kinds
                .contains(&M7EvidenceKind::M5ActivationRollback)
        );
    }

    #[test]
    fn legacy_m5_v3_artifact_is_not_current_lineage_evidence() {
        let fixture = Fixture::new(M7ClosureDecision::Closed);
        let mut artifact = fixture.artifact(M7EvidenceKind::M5ActivationRollback);
        assert_eq!(
            artifact.schema,
            "wasm-biotic.m7-evidence.m5-activation-rollback.v5"
        );
        artifact.schema = "wasm-biotic.m7-evidence.m5-activation-rollback.v4".to_string();
        assert!(matches!(
            artifact.validate_structure(),
            Err(M7FoundationError::InvalidEvidence(_))
        ));
    }

    #[test]
    fn current_m5_m7_lineage_schema_matrix_is_pinned() {
        assert_eq!(
            crate::factory_reproduction::REPRODUCTION_STATE_SCHEMA_VERSION,
            6
        );
        assert_eq!(
            crate::factory_reproduction::LIVE_PROVIDER_QUALIFICATION_SCHEMA,
            "wasm-biotic.live-provider-qualification.v4"
        );
        assert_eq!(
            crate::factory_reproduction::M5_PROVIDER_ACCOUNTING_SCHEMA,
            "wasm-biotic.m5-provider-accounting-summary.v3"
        );
        assert_eq!(
            crate::factory_reproduction::M5_PROVIDER_INTENT_SCHEMA,
            "wasm-biotic.m5-provider-intent.v2"
        );
        assert_eq!(
            crate::factory_reproduction::PROVIDER_REPLAY_CAPSULE_SCHEMA,
            "wasm-biotic.provider-replay-capsule.v2"
        );
        assert_eq!(
            crate::m5_provider_binding::PROVIDER_CANDIDATE_BINDING_SCHEMA,
            "wasm-biotic.provider-candidate-binding.v5"
        );
        assert_eq!(
            crate::m5_provider_binding::PROVIDER_PROPOSAL_EVIDENCE_SCHEMA,
            "wasm-biotic.provider-proposal-evidence.v4"
        );
        assert_eq!(
            crate::m5_runtime::M5_PREPARED_PROVIDER_SEED_SCHEMA,
            "wasm-biotic.m5-prepared-provider-seed.v3"
        );
        assert_eq!(
            crate::m5_provider_execution::M5_PROVIDER_EXECUTION_RECEIPT_SCHEMA,
            "wasm-biotic.m5-provider-execution-receipt.v2"
        );
        assert_eq!(
            crate::m5_provider_execution::M5_COMPLETED_PROVIDER_INVOCATION_SCHEMA,
            "wasm-biotic.m5-completed-provider-invocation.v1"
        );
        assert_eq!(M5_EXPORT_BUNDLE_SCHEMA, "wasm-biotic.m5-export-bundle.v2");
        assert_eq!(
            crate::m5_runtime::M5_FINAL_POST_ROLLBACK_PROBE_SCHEMA,
            "wasm-biotic.m5-final-post-rollback-probe.v1"
        );
        assert_eq!(
            crate::m5_runtime::M5_CAUSALLY_BOUND_POST_ROLLBACK_PROBE_SCHEMA,
            "wasm-biotic.m5-causally-bound-post-rollback-probe.v1"
        );
        assert_eq!(
            M7_PROOF_RUN_MANIFEST_SCHEMA,
            "wasm-biotic.m7-proof-run-manifest.v5"
        );
        assert_eq!(
            M7_LIVE_PROVIDER_SOURCE_SCHEMA,
            "wasm-biotic.m7-source.live-provider-qualification.v4"
        );
        assert_eq!(
            M7_INDEPENDENT_REVIEW_SOURCE_SCHEMA,
            "wasm-biotic.m7-source.independent-review-attestation.v4"
        );
        assert_eq!(M7_FINAL_BUNDLE_SCHEMA, "wasm-biotic.m7-final-bundle.v7");
        assert_eq!(M7_SOURCE_LINK_SCHEMA, "wasm-biotic.m7-source-link.v4");
        assert_eq!(
            M7_SOURCE_CAPTURE_ATTESTATION_SCHEMA,
            "wasm-biotic.m7-source.source-capture-attestation.v4"
        );
        assert_eq!(
            M7EvidenceKind::M2SchedulerWakeRestart.schema(),
            "wasm-biotic.m7-evidence.m2-scheduler-wake-restart.v5"
        );
        assert_eq!(
            M7EvidenceKind::M4WorkerEcology.schema(),
            "wasm-biotic.m7-evidence.m4-worker-ecology.v5"
        );
        assert_eq!(
            M7EvidenceKind::M5ActivationRollback.schema(),
            "wasm-biotic.m7-evidence.m5-activation-rollback.v5"
        );
        assert_eq!(
            M7EvidenceKind::M6FactoryExchange.schema(),
            "wasm-biotic.m7-evidence.m6-factory-exchange.v6"
        );
        assert_eq!(
            M7EvidenceKind::LiveProviderQualification.schema(),
            "wasm-biotic.m7-evidence.live-provider-qualification.v8"
        );
        assert_eq!(
            crate::m7_runtime::M7_REVIEW_REQUEST_SCHEMA,
            "wasm-biotic.m7-independent-review-request.v5"
        );
        assert_eq!(
            crate::m7_operator::M7_MANIFEST_CREATE_REQUEST_SCHEMA,
            "wasm-biotic.m7-manifest-create-request.v3"
        );
        assert_eq!(
            crate::m7_operator::M7_EXACT_SOURCE_ADMISSION_REQUEST_SCHEMA,
            "wasm-biotic.m7-exact-source-admission-request.v3"
        );
        assert_eq!(
            crate::m7_operator::M7_SOURCE_CAPTURE_SIGNING_REQUEST_SCHEMA,
            "wasm-biotic.m7-source-capture-signing-request.v3"
        );
        assert_eq!(
            crate::m7_operator::M7_EVALUATION_REPORT_SCHEMA,
            "wasm-biotic.m7-evaluation-report.v6"
        );
    }

    #[test]
    fn m5_export_lineage_crosscheck_accepts_one_export_and_rejects_valid_substitution() {
        let manifest = manifest(None);
        let (export_bytes, probe_bytes) = exact_m5_source_bytes();
        let export_content_digest = ContentDigest::from_bytes(&export_bytes);
        let mut artifacts = BTreeMap::new();
        for (kind, inputs) in [
            (
                M7EvidenceKind::M1CandidateLifecycle,
                vec![M7SourceInputV2::new(
                    M7SourceRoleV2::M5ExportM1,
                    export_bytes.clone(),
                )],
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
                    M7SourceInputV2::new(M7SourceRoleV2::M5ExportRollback, export_bytes.clone()),
                    M7SourceInputV2::new(M7SourceRoleV2::M5FinalPostRollbackProbe, probe_bytes),
                ],
            ),
        ] {
            let derived = M7EvidenceArtifact::derive_from_sources(&manifest, kind, inputs)
                .unwrap_or_else(|error| panic!("derive same-export {kind:?} evidence: {error}"));
            artifacts.insert(kind, derived.artifact().clone());
        }
        let mut m6_exchange = required_payloads_without_reviewer()
            .into_iter()
            .find_map(|payload| match payload {
                M7EvidencePayload::M6FactoryExchange(exchange) => Some(exchange),
                _ => None,
            })
            .expect("fixture M6 exchange payload");
        m6_exchange.sender_m5_export_bundle_content_digest = export_content_digest.clone();
        let m6_artifact = M7EvidenceArtifact::new(
            &manifest,
            content("subject:m6-lineage-control"),
            M7EvidencePayload::M6FactoryExchange(m6_exchange),
        )
        .expect("M6 lineage control artifact");
        artifacts.insert(M7EvidenceKind::M6FactoryExchange, m6_artifact);
        assert!(
            !m5_export_lineage_mismatch(&artifacts),
            "the exact same canonical M5 export across M1/M3/M4/M5 and M6 must be accepted"
        );

        let alternate_export = alternate_valid_m5_export_bytes();
        assert_ne!(
            ContentDigest::from_bytes(&alternate_export),
            export_content_digest,
            "the substitution control must be a distinct valid M5 export"
        );
        let substituted = M7EvidenceArtifact::derive_from_sources(
            &manifest,
            M7EvidenceKind::M3CapabilityEffects,
            vec![M7SourceInputV2::new(
                M7SourceRoleV2::M5ExportM3,
                alternate_export,
            )],
        )
        .expect("derive independently valid substituted M3 evidence");
        let mut resolver = MapResolver::default();
        for blob in substituted.source_blobs() {
            resolver
                .bytes
                .insert(blob.link().digest.clone(), blob.bytes().to_vec());
        }
        let substituted_link = substituted
            .artifact()
            .evidence_link()
            .expect("substituted M3 evidence link");
        assert_eq!(
            verify_artifact_sources(
                &manifest,
                &substituted_link,
                substituted.artifact(),
                &resolver,
            ),
            Ok(()),
            "the negative control must be individually valid before the cross-milestone check"
        );
        artifacts.insert(
            M7EvidenceKind::M3CapabilityEffects,
            substituted.artifact().clone(),
        );
        assert!(
            m5_export_lineage_mismatch(&artifacts),
            "an independently valid M3 export from another factory must not splice into the dossier"
        );
    }

    #[test]
    fn chronology_join_rejects_source_valid_m2_splice_and_stale_final_probe() {
        let manifest = manifest(None);
        let (export_bytes, final_probe_bytes, before_bytes, after_bytes) =
            exact_manifest_bound_m5_m2_source_bytes(&manifest.manifest_digest);
        let export_digest = ContentDigest::from_bytes(&export_bytes);
        let m6_content_digest = content("m6-completion-bundle-content");

        let derive = |kind, inputs| {
            let derived = M7EvidenceArtifact::derive_from_sources(&manifest, kind, inputs)
                .unwrap_or_else(|error| panic!("derive chronology {kind:?}: {error}"));
            let mut resolver = MapResolver::default();
            for blob in derived.source_blobs() {
                resolver
                    .bytes
                    .insert(blob.link().digest.clone(), blob.bytes().to_vec());
            }
            let link = derived
                .artifact()
                .evidence_link()
                .expect("chronology evidence link");
            assert_eq!(
                verify_artifact_sources(&manifest, &link, derived.artifact(), &resolver),
                Ok(()),
                "the chronology control must be individually source-valid"
            );
            derived.artifact().clone()
        };
        let m2 = derive(
            M7EvidenceKind::M2SchedulerWakeRestart,
            vec![
                M7SourceInputV2::new(M7SourceRoleV2::SupervisorPreRestart, before_bytes),
                M7SourceInputV2::new(M7SourceRoleV2::SupervisorPostRestart, after_bytes),
            ],
        );
        let m5 = derive(
            M7EvidenceKind::M5ActivationRollback,
            vec![
                M7SourceInputV2::new(M7SourceRoleV2::M5ExportRollback, export_bytes.clone()),
                M7SourceInputV2::new(M7SourceRoleV2::M5FinalPostRollbackProbe, final_probe_bytes),
            ],
        );

        // The M6 source itself is exercised by the public M6->M7 acceptance
        // path. This structural link isolates the cross-artifact chronology
        // join while retaining the exact source-content identity.
        let mut m6_payload = required_payloads_without_reviewer()
            .into_iter()
            .find_map(|payload| match payload {
                M7EvidencePayload::M6FactoryExchange(exchange) => Some(exchange),
                _ => None,
            })
            .expect("M6 chronology payload");
        m6_payload.completion_bundle_content_digest = m6_content_digest.clone();
        m6_payload.sender_m5_export_bundle_content_digest = export_digest.clone();
        let mut m6 = M7EvidenceArtifact::new(
            &manifest,
            content("subject:m6-chronology-control"),
            M7EvidencePayload::M6FactoryExchange(m6_payload),
        )
        .expect("M6 chronology artifact");
        m6.source_links = vec![M7SourceLinkV2 {
            schema: M7_SOURCE_LINK_SCHEMA.to_string(),
            semantic_role: M7SourceRoleV2::M6Completion,
            source_kind: M7SourceKindV2::M6CompletionBundle,
            source_schema: M6_COMPLETION_BUNDLE_SCHEMA.to_string(),
            proof_run_id: manifest.proof_run_id.clone(),
            manifest_digest: manifest.manifest_digest.clone(),
            causal_subject: m6.causal_subject.clone(),
            digest: m6_content_digest.clone(),
            byte_length: 1,
        }];
        m6.validate_structure().expect("M6 chronology structure");

        let mut artifacts = BTreeMap::from([
            (M7EvidenceKind::M2SchedulerWakeRestart, m2.clone()),
            (M7EvidenceKind::M5ActivationRollback, m5.clone()),
            (M7EvidenceKind::M6FactoryExchange, m6),
        ]);
        assert!(
            !closure_chronology_mismatch(&manifest, &artifacts),
            "one exact M6 -> M2 -> final-probe chain must join"
        );

        let (spliced_before, spliced_after) = exact_m2_supervisor_states_for_exports(
            std::slice::from_ref(&export_digest),
            content("different-valid-m6-completion"),
        );
        let spliced_m2 = derive(
            M7EvidenceKind::M2SchedulerWakeRestart,
            vec![
                M7SourceInputV2::new(
                    M7SourceRoleV2::SupervisorPreRestart,
                    supervisor_state_bytes(&spliced_before),
                ),
                M7SourceInputV2::new(
                    M7SourceRoleV2::SupervisorPostRestart,
                    supervisor_state_bytes(&spliced_after),
                ),
            ],
        );
        artifacts.insert(M7EvidenceKind::M2SchedulerWakeRestart, spliced_m2);
        assert!(
            closure_chronology_mismatch(&manifest, &artifacts),
            "an individually source-valid M2 artifact bound to another M6 completion must fail"
        );

        artifacts.insert(M7EvidenceKind::M2SchedulerWakeRestart, m2);
        let (stale_export, stale_probe) = exact_m5_source_bytes();
        let stale_m5 = derive(
            M7EvidenceKind::M5ActivationRollback,
            vec![
                M7SourceInputV2::new(M7SourceRoleV2::M5ExportRollback, stale_export),
                M7SourceInputV2::new(M7SourceRoleV2::M5FinalPostRollbackProbe, stale_probe),
            ],
        );
        artifacts.insert(M7EvidenceKind::M5ActivationRollback, stale_m5);
        assert!(
            closure_chronology_mismatch(&manifest, &artifacts),
            "an individually source-valid final probe from an earlier chronology must fail"
        );
    }

    #[test]
    fn evaluator_blocks_cross_factory_m5_export_splicing() {
        let mut fixture = Fixture::new(M7ClosureDecision::Closed);
        let manifest = fixture.bundle.manifest.clone();
        let (export_bytes, probe_bytes) = exact_m5_source_bytes();
        let export_content_digest = ContentDigest::from_bytes(&export_bytes);
        let install = |fixture: &mut Fixture, derived: M7DerivedEvidenceV2| {
            for blob in derived.source_blobs() {
                fixture
                    .resolver
                    .bytes
                    .insert(blob.link().digest.clone(), blob.bytes().to_vec());
            }
            fixture.replace_artifact(derived.artifact().clone());
        };
        for (kind, inputs) in [
            (
                M7EvidenceKind::M1CandidateLifecycle,
                vec![M7SourceInputV2::new(
                    M7SourceRoleV2::M5ExportM1,
                    export_bytes.clone(),
                )],
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
        ] {
            install(
                &mut fixture,
                M7EvidenceArtifact::derive_from_sources(&manifest, kind, inputs)
                    .unwrap_or_else(|error| panic!("derive evaluator {kind:?} source: {error}")),
            );
        }
        let exact_m4 = fixture.artifact(M7EvidenceKind::M4WorkerEcology);
        let M7EvidencePayload::M4WorkerEcology(exact_m4) = exact_m4.payload else {
            panic!("derived M4 payload")
        };
        let (lifecycle_job_id, lifecycle_terminal_digest) = exact_m4
            .lifecycle_terminal_job_digests
            .first_key_value()
            .expect("derived M4 evidence has one lifecycle anchor");
        let mut m2 = fixture.artifact(M7EvidenceKind::M2SchedulerWakeRestart);
        let M7EvidencePayload::M2SchedulerWakeRestart(m2_payload) = &mut m2.payload else {
            panic!("fixture M2 payload")
        };
        m2_payload.m5_export_bundle_content_digest = export_content_digest.clone();
        m2_payload.m4_lifecycle_job_id = lifecycle_job_id.clone();
        m2_payload.m4_lifecycle_terminal_job_digest = lifecycle_terminal_digest.clone();
        fixture.replace_artifact(m2);
        let mut m5 = fixture.artifact(M7EvidenceKind::M5ActivationRollback);
        let M7EvidencePayload::M5ActivationRollback(m5_payload) = &mut m5.payload else {
            panic!("derived M5 payload")
        };
        m5_payload.active_operator_context_digest = manifest.manifest_digest.clone();
        m5_payload.rollback_operator_context_digest = manifest.manifest_digest.clone();
        fixture.replace_artifact(m5);
        let mut m6 = fixture.artifact(M7EvidenceKind::M6FactoryExchange);
        let M7EvidencePayload::M6FactoryExchange(exchange) = &mut m6.payload else {
            panic!("fixture M6 payload")
        };
        exchange.sender_m5_export_bundle_content_digest = export_content_digest;
        fixture.replace_artifact(m6);
        let same_export = evaluate_m7_closure(&fixture.bundle, &fixture.resolver);
        assert!(
            !same_export
                .blockers
                .contains(&M7Blocker::M5ExportLineageMismatch),
            "one exact M5 export must not trip the anti-splicing blocker"
        );

        let substituted = M7EvidenceArtifact::derive_from_sources(
            &manifest,
            M7EvidenceKind::M3CapabilityEffects,
            vec![M7SourceInputV2::new(
                M7SourceRoleV2::M5ExportM3,
                alternate_valid_m5_export_bytes(),
            )],
        )
        .expect("derive valid cross-factory M3 substitution");
        install(&mut fixture, substituted);
        let evaluation = evaluate_m7_closure(&fixture.bundle, &fixture.resolver);
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::M5ExportLineageMismatch)
        );
        for kind in [
            M7EvidenceKind::M1CandidateLifecycle,
            M7EvidenceKind::M3CapabilityEffects,
            M7EvidenceKind::M4WorkerEcology,
            M7EvidenceKind::M5ActivationRollback,
            M7EvidenceKind::M6FactoryExchange,
        ] {
            assert!(
                !evaluation.verified_kinds.contains(&kind),
                "spliced lineage must invalidate {kind:?}"
            );
        }
    }

    #[test]
    fn reviewer_identity_must_be_independent_from_implementation_path() {
        let mut by_principal = Fixture::new(M7ClosureDecision::Closed);
        by_principal.replace_reviewer("implementer:one", content("reviewer-independent-identity"));
        let evaluation = evaluate_m7_closure(&by_principal.bundle, &by_principal.resolver);
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::ReviewerNotIndependent)
        );

        let mut by_identity = Fixture::new(M7ClosureDecision::Closed);
        by_identity.replace_reviewer("reviewer:other", content("implementer-one-identity"));
        let evaluation = evaluate_m7_closure(&by_identity.bundle, &by_identity.resolver);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::ReviewerNotIndependent)
        );
    }

    #[test]
    fn live_provider_source_round_trips_and_rejects_cross_run_or_stale_precommit() {
        let source = live_provider_source_fixture("proof-run:m7:1", 150);
        let bytes = source.canonical_bytes().expect("canonical provider source");
        let reopened =
            M7LiveProviderSourceV1::from_canonical_bytes(&bytes).expect("reopen provider source");
        assert!(
            reopened == source,
            "reopened live-provider source differed from its canonical source"
        );
        let mut noncanonical = bytes;
        noncanonical.push(b'\n');
        assert!(M7LiveProviderSourceV1::from_canonical_bytes(&noncanonical).is_err());
        let mut source_digest_tamper = source.clone();
        source_digest_tamper.source_digest = content("forged-live-provider-source");
        assert!(source_digest_tamper.validate().is_err());

        let cross_run_source = live_provider_source_fixture("proof-run:m7:other", 150);
        let cross_run_completed = cross_run_source
            .completed_invocation()
            .expect("cross-run completed invocation");
        let cross_run_scope =
            LiveProviderQualificationScope::from_prepared(cross_run_completed.prepared_seed())
                .expect("cross-run scope");
        let mut cross_run_manifest = manifest(None);
        cross_run_manifest.live_provider_scope = Some(cross_run_scope);
        cross_run_manifest.manifest_digest = cross_run_manifest
            .expected_digest()
            .expect("cross-run manifest digest");
        assert!(matches!(
            cross_run_manifest.validate(),
            Err(M7FoundationError::InvalidManifest(message))
                if message == "live-provider precommit belongs to a different proof run"
        ));

        let source_completed = source
            .completed_invocation()
            .expect("exact completed invocation");
        let exact_scope =
            LiveProviderQualificationScope::from_prepared(source_completed.prepared_seed())
                .expect("exact source scope");

        let mut at_freeze_boundary = manifest(None);
        at_freeze_boundary.frozen_criteria.frozen_at_ms = exact_scope.prepared_at_ms;
        at_freeze_boundary.frozen_criteria.criteria_digest = at_freeze_boundary
            .frozen_criteria
            .expected_digest()
            .expect("freeze-boundary criteria digest");
        at_freeze_boundary.live_provider_scope = Some(exact_scope.clone());
        at_freeze_boundary.manifest_digest = at_freeze_boundary
            .expected_digest()
            .expect("freeze-boundary manifest digest");
        assert!(matches!(
            at_freeze_boundary.validate(),
            Err(M7FoundationError::InvalidManifest(message))
                if message == "live-provider precommit must be created after closure criteria are frozen"
        ));

        let mut at_run_boundary = manifest(None);
        at_run_boundary.run_started_at_ms = exact_scope.prepared_at_ms;
        at_run_boundary.live_provider_scope = Some(exact_scope);
        at_run_boundary.manifest_digest = at_run_boundary
            .expected_digest()
            .expect("run-boundary manifest digest");
        assert!(matches!(
            at_run_boundary.validate(),
            Err(M7FoundationError::InvalidManifest(message))
                if message
                    == "live-provider precommit must be created strictly before the proof run starts"
        ));

        let mut tampered = source;
        let mut completed_value: serde_json::Value =
            serde_json::from_str(&tampered.completed_invocation_json)
                .expect("completed invocation JSON");
        completed_value["prepared_seed"]["precommit"]["prepared_at_ms"] = serde_json::json!(151);
        tampered.completed_invocation_json =
            serde_json::to_string_pretty(&completed_value).expect("tampered completed JSON");
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn live_provider_source_rejects_request_and_target_drift_between_valid_records() {
        let exact = live_provider_source_fixture("proof-run:m7:1", 150);
        let request_drift = live_provider_source_fixture_with_prompt(
            "proof-run:m7:1",
            150,
            Some("changed but independently valid frozen provider prompt"),
        );
        let exact_completed = exact
            .completed_invocation()
            .expect("exact completed invocation");
        let request_drift_completed = request_drift
            .completed_invocation()
            .expect("request-drift completed invocation");
        assert!(
            exact_completed.prepared_seed().target
                != request_drift_completed.prepared_seed().target,
            "changed pre-call material must change the sealed provider target"
        );
        let mut spliced_value: serde_json::Value =
            serde_json::from_str(&exact.completed_invocation_json)
                .expect("exact completed invocation JSON");
        let request_drift_value: serde_json::Value =
            serde_json::from_str(&request_drift.completed_invocation_json)
                .expect("request-drift completed invocation JSON");
        spliced_value["provider_binding"] = request_drift_value["provider_binding"].clone();
        let mut spliced = exact.clone();
        spliced.completed_invocation_json =
            serde_json::to_string_pretty(&spliced_value).expect("spliced completed JSON");
        assert!(spliced.validate().is_err());

        let target_drift = live_provider_source_fixture("proof-run:m7:1", 151);
        let target_drift_completed = target_drift
            .completed_invocation()
            .expect("target-drift completed invocation");
        assert!(
            exact_completed.prepared_seed().target != target_drift_completed.prepared_seed().target,
            "live-provider target drift preserved the exact provider target"
        );
        let mut target_splice_value: serde_json::Value =
            serde_json::from_str(&exact.completed_invocation_json)
                .expect("exact completed invocation JSON");
        let target_drift_value: serde_json::Value =
            serde_json::from_str(&target_drift.completed_invocation_json)
                .expect("target-drift completed invocation JSON");
        target_splice_value["prepared_seed"] = target_drift_value["prepared_seed"].clone();
        let mut target_splice = exact;
        target_splice.completed_invocation_json =
            serde_json::to_string_pretty(&target_splice_value).expect("target-spliced JSON");
        assert!(target_splice.validate().is_err());
    }

    #[test]
    fn live_provider_source_requires_an_exact_current_call_receipt() {
        let exact = live_provider_source_fixture("proof-run:m7:1", 150);
        let completed = exact
            .completed_invocation()
            .expect("exact completed invocation");
        let separable_records = serde_json::to_vec_pretty(&(
            completed.prepared_seed(),
            completed.provider_binding(),
            completed.execution_receipt(),
        ))
        .expect("separable provider records");
        assert!(
            M5CompletedProviderInvocationV1::from_canonical_bytes(&separable_records).is_err(),
            "separable provider records must never parse as the opaque completion"
        );

        let mut nonce_tamper = exact.clone();
        let mut nonce_value: serde_json::Value =
            serde_json::from_str(&nonce_tamper.completed_invocation_json)
                .expect("completed invocation JSON");
        nonce_value["execution_receipt"]["run_nonce_hex"] = serde_json::json!("00".repeat(32));
        nonce_tamper.completed_invocation_json =
            serde_json::to_string_pretty(&nonce_value).expect("nonce-tampered completed JSON");
        assert!(nonce_tamper.validate().is_err());

        let mut manifest_tamper = exact;
        let mut manifest_value: serde_json::Value =
            serde_json::from_str(&manifest_tamper.completed_invocation_json)
                .expect("completed invocation JSON");
        manifest_value["execution_receipt"]["manifest_digest"] =
            serde_json::to_value(content("another-manifest")).expect("manifest digest JSON");
        manifest_tamper.completed_invocation_json =
            serde_json::to_string_pretty(&manifest_value).expect("manifest-tampered JSON");
        assert!(manifest_tamper.validate().is_err());
    }

    #[test]
    fn openai_loopback_provider_never_qualifies_m7() {
        let loopback_source = live_provider_source_fixture_with_endpoint(
            "proof-run:m7:1",
            150,
            None,
            "http://127.0.0.1:45123/v1/",
        );
        let completed = loopback_source
            .completed_invocation()
            .expect("loopback completed provider invocation");
        assert_eq!(
            completed.endpoint_class(),
            M5ProviderEndpointClassV1::LoopbackTest
        );
        let fixture = Fixture::new_with_provider_source(
            M7ClosureDecision::Closed,
            Some(loopback_source),
            Some(true),
        );
        let evaluation = evaluate_m7_closure(&fixture.bundle, &fixture.resolver);
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert_eq!(
            evaluation.live_provider_status,
            LiveProviderQualificationStatus::Invalid
        );
        assert!(evaluation.blockers.iter().any(|blocker| matches!(
            blocker,
            M7Blocker::SemanticFailure {
                kind: M7EvidenceKind::LiveProviderQualification,
                failure: M7SemanticFailure::LiveProviderEvidenceUnsafe,
            }
        )));
    }

    #[test]
    fn https_ipv4_mapped_ipv6_loopback_provider_never_qualifies_m7() {
        let loopback_source = live_provider_source_fixture_with_endpoint(
            "proof-run:m7:1",
            150,
            None,
            "https://[::ffff:127.0.0.2]/v1/",
        );
        let completed = loopback_source
            .completed_invocation()
            .expect("mapped-loopback completed provider invocation");
        assert_eq!(
            completed.endpoint_class(),
            M5ProviderEndpointClassV1::LoopbackTest
        );
        let fixture = Fixture::new_with_provider_source(
            M7ClosureDecision::Closed,
            Some(loopback_source),
            Some(true),
        );
        let evaluation = evaluate_m7_closure(&fixture.bundle, &fixture.resolver);
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert_eq!(
            evaluation.live_provider_status,
            LiveProviderQualificationStatus::Invalid
        );
        assert!(evaluation.blockers.iter().any(|blocker| matches!(
            blocker,
            M7Blocker::SemanticFailure {
                kind: M7EvidenceKind::LiveProviderQualification,
                failure: M7SemanticFailure::LiveProviderEvidenceUnsafe,
            }
        )));
        assert!(
            !evaluation
                .verified_kinds
                .contains(&M7EvidenceKind::LiveProviderQualification)
        );
    }

    #[test]
    fn provider_scope_rejects_external_url_labeled_as_loopback_class() {
        let source = live_provider_source_fixture("proof-run:m7:1", 150);
        let completed = source
            .completed_invocation()
            .expect("completed provider invocation");
        let mut scope = LiveProviderQualificationScope::from_prepared(completed.prepared_seed())
            .expect("external provider scope");
        scope.endpoint_class = M5ProviderEndpointClassV1::LoopbackTest;
        scope.scope_digest = scope.expected_digest().expect("forged scope digest");
        assert!(scope.validate().is_err());
    }

    #[test]
    fn qualified_provider_target_must_match_the_same_dossier_m1_candidate() {
        let matched = Fixture::new_with_provider(M7ClosureDecision::NotYet, Some(true));
        let provider_target_package_digest = matched
            .artifact(M7EvidenceKind::LiveProviderQualification)
            .payload()
            .clone();
        let M7EvidencePayload::LiveProviderQualification(provider) = provider_target_package_digest
        else {
            panic!("live-provider payload")
        };
        let evaluation = evaluate_m7_closure(&matched.bundle, &matched.resolver);
        assert_eq!(
            evaluation.live_provider_status,
            LiveProviderQualificationStatus::Qualified
        );
        assert!(!evaluation.blockers.iter().any(|blocker| matches!(
            blocker,
            M7Blocker::LiveProviderCandidateIdentityMismatch { .. }
        )));

        let mut substituted = matched;
        let mut m1 = substituted.artifact(M7EvidenceKind::M1CandidateLifecycle);
        let M7EvidencePayload::M1CandidateLifecycle(candidate) = &mut m1.payload else {
            panic!("M1 candidate payload")
        };
        let substituted_candidate_package_digest = content("substituted-m1-candidate-package");
        candidate.candidate_package_digest = substituted_candidate_package_digest.clone();
        substituted.replace_artifact(m1);

        let evaluation = evaluate_m7_closure(&substituted.bundle, &substituted.resolver);
        assert_eq!(
            evaluation.live_provider_status,
            LiveProviderQualificationStatus::Invalid
        );
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::LiveProviderCandidateIdentityMismatch {
                    m1_incumbent_package_digest: Some(provider.incumbent_package_digest.clone(),),
                    m1_candidate_package_digest: Some(substituted_candidate_package_digest),
                    provider_incumbent_package_digest: provider.incumbent_package_digest,
                    provider_target_package_digest: provider.target_package_digest,
                })
        );
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::LiveProviderQualificationIncomplete(
                    LiveProviderQualificationStatus::Invalid,
                ))
        );

        let mut wrong_incumbent = Fixture::new_with_provider(M7ClosureDecision::NotYet, Some(true));
        let provider = match wrong_incumbent
            .artifact(M7EvidenceKind::LiveProviderQualification)
            .payload
        {
            M7EvidencePayload::LiveProviderQualification(provider) => provider,
            _ => panic!("live-provider payload"),
        };
        let mut m1 = wrong_incumbent.artifact(M7EvidenceKind::M1CandidateLifecycle);
        let M7EvidencePayload::M1CandidateLifecycle(candidate) = &mut m1.payload else {
            panic!("M1 candidate payload")
        };
        let substituted_incumbent = content("substituted-m1-incumbent-package");
        candidate.incumbent_package_digest = substituted_incumbent.clone();
        let expected_candidate = candidate.candidate_package_digest.clone();
        wrong_incumbent.replace_artifact(m1);
        let evaluation = evaluate_m7_closure(&wrong_incumbent.bundle, &wrong_incumbent.resolver);
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::LiveProviderCandidateIdentityMismatch {
                    m1_incumbent_package_digest: Some(substituted_incumbent),
                    m1_candidate_package_digest: Some(expected_candidate),
                    provider_incumbent_package_digest: provider.incumbent_package_digest,
                    provider_target_package_digest: provider.target_package_digest,
                })
        );
    }

    #[test]
    fn live_provider_qualification_is_a_separate_required_completion_gate() {
        let absent = Fixture::new(M7ClosureDecision::ClosedWithCaveats);
        let evaluation = evaluate_m7_closure(&absent.bundle, &absent.resolver);
        assert_eq!(
            evaluation.live_provider_status,
            LiveProviderQualificationStatus::NotScoped
        );
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::LiveProviderQualificationIncomplete(
                    LiveProviderQualificationStatus::NotScoped,
                ),)
        );
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert!(!evaluation.evidence_complete);

        let mut scoped_but_missing =
            Fixture::new_with_provider(M7ClosureDecision::ClosedWithCaveats, Some(true));
        let provider_link = scoped_but_missing
            .bundle
            .live_provider_link
            .take()
            .expect("provider link");
        scoped_but_missing
            .resolver
            .bytes
            .remove(&provider_link.digest);
        scoped_but_missing
            .bundle
            .source_links
            .retain(|link| link.semantic_role != M7SourceRoleV2::LiveProviderQualification);
        scoped_but_missing.reseal_reviewer();
        let evaluation =
            evaluate_m7_closure(&scoped_but_missing.bundle, &scoped_but_missing.resolver);
        assert_eq!(
            evaluation.live_provider_status,
            LiveProviderQualificationStatus::ScopedButNotProvided
        );
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::LiveProviderQualificationIncomplete(
                    LiveProviderQualificationStatus::ScopedButNotProvided,
                ),)
        );
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);

        let unqualified =
            Fixture::new_with_provider(M7ClosureDecision::ClosedWithCaveats, Some(false));
        let evaluation = evaluate_m7_closure(&unqualified.bundle, &unqualified.resolver);
        assert!(!evaluation.evidence_complete);
        assert_eq!(
            evaluation.live_provider_status,
            LiveProviderQualificationStatus::Invalid
        );
        assert!(
            evaluation
                .blockers
                .contains(&M7Blocker::LiveProviderQualificationIncomplete(
                    LiveProviderQualificationStatus::Invalid,
                ),)
        );
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);

        let qualified = Fixture::new_with_provider(M7ClosureDecision::NotYet, Some(true));
        let evaluation = evaluate_m7_closure(&qualified.bundle, &qualified.resolver);
        assert!(!evaluation.evidence_complete);
        assert_eq!(
            evaluation.live_provider_status,
            LiveProviderQualificationStatus::Qualified
        );
        assert!(
            !evaluation.blockers.iter().any(|blocker| matches!(
                blocker,
                M7Blocker::LiveProviderQualificationIncomplete(_)
            ))
        );
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
    }

    #[test]
    fn final_bundle_reconstructs_after_restart_from_finalized_artifacts_only() {
        let fixture = Fixture::new(M7ClosureDecision::ClosedWithCaveats);
        let bundle_bytes = fixture.bundle.canonical_bytes().expect("bundle bytes");
        let persisted_evidence = fixture.resolver.bytes.clone();
        let expected_bundle_digest = fixture.bundle.bundle_digest().clone();
        drop(fixture);

        let restarted_bundle =
            M7FinalBundle::from_canonical_bytes(&bundle_bytes).expect("restart bundle");
        let restarted_resolver = MapResolver {
            bytes: persisted_evidence,
            failures: BTreeSet::new(),
        };
        let evaluation = evaluate_m7_closure(&restarted_bundle, &restarted_resolver);
        assert!(!evaluation.evidence_complete);
        assert_eq!(evaluation.decision, M7ClosureDecision::NotYet);
        assert_eq!(evaluation.bundle_digest, expected_bundle_digest);
    }
}
