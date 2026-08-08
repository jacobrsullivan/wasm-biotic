//! Production integration for one bounded, local M5 factory reproduction loop.
//!
//! [`FactoryReproductionEngine`] owns the reproduction law.  This module binds
//! its four required ports to the operational M1--M4 implementations:
//!
//! - M1 proving executes the exact component bytes under Wasmtime and persists
//!   the complete proving record by content digest;
//! - M2 approval is an explicit, exact-package authorization recorded in the
//!   durable supervisor store;
//! - M3 shadowing, activation, recovery, and inspection execute through the
//!   receipt-backed M5 capability port over exact canonical factory-package bytes; and
//! - M4 runs the six-role durable worker workflow for every candidate and for
//!   the material generation instruction performed by an adopted successor.
//!
//! The mutable genome remains deliberately small: one reference-task WebAssembly
//! component plus its bounded generation policy.  WAT source is registered
//! before a cycle and is accepted only when compiling it produces the exact
//! component digest already named by the immutable factory package.
//!
//! Live-provider qualification is optional and separate from the deterministic
//! release gate.  [`GovernedLiveProviderPort`] reads a configured credential
//! environment variable only inside the live call, uses the repository's
//! inference adapter and canonical tool catalog, persists only redacted output
//! through the reproduction engine, and never becomes acceptance authority.

use crate::capability_services::{
    CancellationToken as ServiceCancellationToken, CapabilityInvocation, CapabilityRequest,
    InspectOperationsRequest, InvocationApproval, InvocationBudget, InvocationIdentity,
    ScopedDeploymentRef,
};
use crate::execution::AuthorityClass;
use crate::execution::artifact::{ContentDigest, digest_json_content};
use crate::execution::inference::{
    InferenceFinishReason, InferenceGenerationPolicy, InferenceProviderMode,
    InferenceProviderRegistryEntry, InferenceRenderedPromptRecord,
    InferenceResponseSchemaPayloadRecord, InferenceToolCatalogPayloadRecord, InferenceTurnBundle,
    InferenceTurnRequest, build_required_function_request_body_json_from_frozen_inputs,
    execute_inference_turn_requiring_function_tool, normalize_safe_provider_api_base_url,
};
use crate::factory_reproduction::{
    AdoptedSuccessorRequest, ApprovalDecision, CycleIntent, CycleOutcome, CycleRecord,
    FactoryPackage, FactoryReproductionEngine, GenerationMaterializationEvidence,
    GenerationMaterializationRequest, LiveProviderQualificationPort,
    LiveProviderQualificationRecord, LiveProviderTurn, M1BuildEvidence, M1BuildRequest,
    M1CandidatePort, M4WorkerPort, M5_PROVIDER_INTENT_SCHEMA, M5ProviderAccountingSummaryV1,
    M5ProviderAttemptSummaryV1, M5ProviderEndpointClassV1, M5ProviderProfileV1,
    MAX_M5_PROVIDER_OUTPUT_TOKENS, MAX_M5_PROVIDER_RETRIES, MutableFactoryPolicy, MutableGenome,
    ParsedProviderIntent, PortFailure, PrepareSuccessorOutcome, ProviderConfiguration,
    ProviderQualificationRequest, ProviderQualificationStatus, ProviderReplayCapsule,
    ProviderReplayRecord, ProviderReplayRequest, ProviderTransport, RedactedTranscript,
    ReleaseGate, ReproductionError, ReproductionPorts, ReproductionState, SeedCycleRequest,
    ServiceDependencyCatalog, StableInterfaceContract, StateCompatibility, StateMigrationPlan,
    WorkerCatalog, WorkerReceipt, WorkerRole, WorkerTerminalStatus, WorkerWorkflowEvidence,
    WorkerWorkflowRequest, render_reference_delta_v1, unbound_provider_invocation_challenge_digest,
};
use crate::m1_validation::{
    ProvingRecord, ValidationSuite, prove_component_i32, validate_proving_record,
};
use crate::m2_runtime::{
    M1_OPEN_WORKSPACE_JOB_KIND, M1LifecycleJob, M2Runtime, M2RuntimeConfig, M2SubmitJobRequest,
    OpenWorkspacePayload,
};
use crate::m3_runtime::{M3CapabilityRuntime, M3RuntimeConfig, OPERATIONS_INSPECT_SERVICE_ID};
use crate::m4_runtime::{M4ReferenceWorkflowRequest, M4Runtime, M4RuntimeConfig};
use crate::m5_effect_port::{
    M5ActiveExecutionAuditRecord, M5EffectAuditKind, M5EffectAuditReport, M5EffectCapabilityPort,
};
use crate::m5_effect_store::{
    FactoryEffectStore, FactoryExecuteRequest, FactoryInitializeRequest,
    FactoryProviderProposalRequest, FactoryRuntimeSnapshot, StateMigrationArtifactBundle,
};
use crate::m5_export::{
    M5ExportBundleV1, M5ExportPackageV1, M5StoredM4WorkflowEvidenceV1,
    MAX_STORED_M4_WORKFLOW_BYTES, active_evidence_references,
};
use crate::m5_m3_adapter::{M5M3AdapterConfig, M5M3InvocationProofLedger};
use crate::m5_provider_binding::{
    PROVIDER_CANDIDATE_OPERATION, ProviderCandidateBinding, ProviderCandidateBindingStore,
    ProviderCandidateTarget, ProviderProposalEvidence,
};
use crate::m5_provider_execution::{
    M5CompletedProviderInvocationV1, M5ProviderExecutionReceiptV1, fresh_provider_run_nonce,
};
use crate::m5_provider_precommit::M5ProviderPrecommitV1;
use crate::m5_supervisor_adapter::{
    M5InitializationAuthorizationRequest, M5InitializationExecutionRequest,
    M5OperatorRollbackAuthorizationRequest, M5OperatorRollbackExecutionRequest,
    M5PackageAuthorizationRecord, M5PackageAuthorizationRequest, M5SupervisorAdapter,
};
use crate::m6_completion::M6CompletionBundleV1;
use crate::m7_closure::{LiveProviderQualificationScope, M7ProofRunManifest};
use crate::supervisor::{JobPhase, RetryPolicy, SupervisorClock, SupervisorState};
use crate::worker_runtime::{GovernedWorkerRole, WorkBudget, WorkDeadline};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const M5_MANIFEST_SCHEMA: &str = "wasm-biotic.m5-runtime-manifest.v1";
const M5_INITIALIZATION_JOURNAL_SCHEMA: &str = "wasm-biotic.m5-initialization-journal.v2";
const M5_PROVIDER_PROMPT_SCHEMA: &str = "wasm-biotic.m5-provider-prompt.v2";
pub const M5_PREPARED_PROVIDER_SEED_SCHEMA: &str = "wasm-biotic.m5-prepared-provider-seed.v3";
pub const M5_PROVIDER_WIRE_REQUEST_SCHEMA: &str = "wasm-biotic.m5-provider-wire-request.v1";
pub const M5_PROVIDER_INVOCATION_CHALLENGE_SCHEMA: &str =
    "wasm-biotic.m5-provider-invocation-challenge.v1";
pub const M5_CHALLENGED_PROVIDER_SEED_SCHEMA: &str = "wasm-biotic.m5-challenged-provider-seed.v1";
const M5_PROVIDER_PARSER_DOMAIN: &[u8] = b"wasm-biotic:m5-provider-parser:v2";
const M5_PROMPT_RENDERER_DOMAIN: &[u8] = b"wasm-biotic:m5-prompt-renderer:v2";
pub const M5_PROVIDER_INVOCATION_CHALLENGE_DOMAIN: &str =
    "wasm-biotic:m5-provider-invocation-challenge:v1";
const M5_PROVIDER_WIRE_REQUEST_DOMAIN: &str = "wasm-biotic:m5-provider-wire-request:v1";
const M5_CHALLENGED_PROVIDER_SEED_DOMAIN: &str = "wasm-biotic:m5-challenged-provider-seed:v1";
const M5_REQUIRED_FUNCTION_DRIVER_PROFILE: &str = "wasm-biotic:m5-required-function-driver:v2";
const M5_EXACT_CANDIDATE_CONTEXT_DOMAIN: &str = "wasm-biotic:m5-exact-candidate-cycle-context:v1";
const M5_FACTORY_SNAPSHOT_SCHEMA: &str = "wasm-biotic.m5-factory-snapshot.v1";
pub const M5_POST_ROLLBACK_PROBE_SCHEMA: &str = "wasm-biotic.m5-post-rollback-probe.v1";
const M5_POST_ROLLBACK_PROBE_DOMAIN: &str = "wasm-biotic:m5-post-rollback-probe:v1";
pub const M5_CAUSALLY_BOUND_POST_ROLLBACK_PROBE_SCHEMA: &str =
    "wasm-biotic.m5-causally-bound-post-rollback-probe.v1";
const M5_CAUSALLY_BOUND_POST_ROLLBACK_PROBE_DOMAIN: &str =
    "wasm-biotic:m5-causally-bound-post-rollback-probe:v1";
pub const M5_FINAL_POST_ROLLBACK_PROBE_SCHEMA: &str = "wasm-biotic.m5-final-post-rollback-probe.v1";
const M5_FINAL_POST_ROLLBACK_PROBE_DOMAIN: &str = "wasm-biotic:m5-final-post-rollback-probe:v1";
pub const M5_M2_POST_EXPORT_RESTART_CAPTURE_SCHEMA: &str =
    "wasm-biotic.m5-m2-post-export-restart-capture.v2";
const M5_M2_POST_EXPORT_BINDING_DOMAIN: &str = "wasm-biotic:m5-m2-post-export-binding:v2";
const M5_M2_POST_EXPORT_CAPTURE_DOMAIN: &str = "wasm-biotic:m5-m2-post-export-capture:v2";
const M5_M2_POST_EXPORT_JOB_PREFIX: &str = "m7-m2-open-v2.";
const M5_M2_POST_EXPORT_EFFECT_PREFIX: &str = "m7-m2-open-effect-v2.";
const MAX_POST_ROLLBACK_PROBE_BYTES: usize = 64 * 1_048_576;
const MAX_M5_M2_POST_EXPORT_CAPTURE_BYTES: usize = 40 * 1_048_576;
const MAX_M5_M4_WORKFLOW_RUNS: usize = 256;
const MANIFEST_FILE: &str = "m5-runtime-manifest.json";
const INITIALIZATION_JOURNAL_FILE: &str = "m5-initialization-journal.json";
const M5_RUNTIME_OWNER_LOCK_FILE: &str = ".m5-runtime-owner.lock";
const TEMPLATE_DIRECTORY: &str = "frozen-template";
const TEMPLATE_WAT_FILE: &str = "component.wat";

#[cfg(test)]
#[derive(Clone)]
struct ProviderInvocationPreflightTestHook {
    cycle_id: String,
    reached: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[cfg(test)]
static PROVIDER_INVOCATION_PREFLIGHT_TEST_HOOK: Mutex<Option<ProviderInvocationPreflightTestHook>> =
    Mutex::new(None);

#[cfg(test)]
fn pause_after_provider_invocation_preflight_for_test(cycle_id: &str) {
    let hook = PROVIDER_INVOCATION_PREFLIGHT_TEST_HOOK
        .lock()
        .expect("lock provider invocation preflight test hook")
        .clone();
    if let Some(hook) = hook.filter(|hook| hook.cycle_id == cycle_id) {
        hook.reached.wait();
        hook.release.wait();
    }
}
const TEMPLATE_WIT_FILE: &str = "component.wit";
const ENGINE_DIRECTORY: &str = "reproduction";
const APPROVAL_DIRECTORY: &str = "approval-supervisor";
const PROVING_DIRECTORY: &str = "m1-proving";
const CAPABILITY_DIRECTORY: &str = "m3-factory-effects";
const CAPABILITY_PORT_DIRECTORY: &str = "m5-capability-port";
const M3_PROOF_DIRECTORY: &str = "m5-m3-proof-ledger";
const PROVIDER_BINDINGS_DIRECTORY: &str = "provider-candidate-bindings";
const RECIPES_DIRECTORY: &str = "m4-recipes";
const MAX_RUNTIME_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECIPE_BYTES: usize = 256 * 1024;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 256 * 1024;
/// M5's billed live-qualification generation ceiling. This is deliberately
/// narrower than the generic inference transport's representable range.
pub const M5_LIVE_PROVIDER_MAX_OUTPUT_TOKENS: usize = MAX_M5_PROVIDER_OUTPUT_TOKENS as usize;
/// Maximum wall-clock wait for one M5 provider attempt. Together with the
/// retry ceiling this prevents an accepted configuration from making one
/// qualification effectively unbounded.
pub const M5_LIVE_PROVIDER_MAX_REQUEST_TIMEOUT_MS: u64 = 120_000;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn m5_provider_driver_transport_semantics(mode: InferenceProviderMode) -> &'static str {
    match mode {
        InferenceProviderMode::OpenAiResponses => {
            "openai-responses:one-exact-function-call:no-structured-fallback:redirect-none:no-system-proxy"
        }
        InferenceProviderMode::OpenRouterChatCompletions => {
            "openrouter-chat-completions:one-exact-tool-call:finish-tool-calls:parallel-false:no-legacy-fallback:redirect-none:no-system-proxy"
        }
        InferenceProviderMode::DeterministicFixture | InferenceProviderMode::Disabled => {
            "unsupported-for-live-m5-qualification"
        }
    }
}

/// Exact current-run identities encoded into an ordinary, idempotent M1
/// `OpenWorkspace` job submitted to an already-used M4 workflow supervisor.
///
/// The closed M1 lifecycle payload remains unchanged. The full manifest and
/// M5-export digests are recoverable from `job_id`; the exact M6 completion,
/// M4 terminal-job digest, and a digest binding all four identities are
/// recoverable from the idempotency key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5M2PostExportJobBindingV2 {
    manifest_digest: ContentDigest,
    m5_export_bundle_content_digest: ContentDigest,
    m6_completion_bundle_content_digest: ContentDigest,
    m4_lifecycle_terminal_job_digest: ContentDigest,
    binding_context_digest: ContentDigest,
}

impl M5M2PostExportJobBindingV2 {
    pub fn new(
        manifest_digest: ContentDigest,
        m5_export_bundle_content_digest: ContentDigest,
        m6_completion_bundle_content_digest: ContentDigest,
        m4_lifecycle_job_id: &str,
        m4_lifecycle_terminal_job_digest: ContentDigest,
    ) -> Result<Self, M5RuntimeError> {
        validate_identifier("M4 lifecycle job_id", m4_lifecycle_job_id)?;
        let mut value = Self {
            manifest_digest,
            m5_export_bundle_content_digest,
            m6_completion_bundle_content_digest,
            m4_lifecycle_terminal_job_digest,
            binding_context_digest: ContentDigest::from_bytes(&[]),
        };
        value.binding_context_digest = value.expected_binding_context_digest()?;
        Ok(value)
    }

    pub fn from_job_identity(job_id: &str, idempotency_key: &str) -> Result<Self, M5RuntimeError> {
        let job_parts = parse_post_export_identity(M5_M2_POST_EXPORT_JOB_PREFIX, job_id)?;
        let effect_parts = parse_post_export_effect_identity(idempotency_key)?;
        let value = Self {
            manifest_digest: job_parts.0,
            m5_export_bundle_content_digest: job_parts.1,
            m4_lifecycle_terminal_job_digest: effect_parts.0,
            m6_completion_bundle_content_digest: effect_parts.1,
            binding_context_digest: effect_parts.2,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), M5RuntimeError> {
        require_digest(
            "post-export M2 binding context",
            &self.binding_context_digest,
            &self.expected_binding_context_digest()?,
        )
    }

    pub fn manifest_digest(&self) -> &ContentDigest {
        &self.manifest_digest
    }

    pub fn m5_export_bundle_content_digest(&self) -> &ContentDigest {
        &self.m5_export_bundle_content_digest
    }

    pub fn m6_completion_bundle_content_digest(&self) -> &ContentDigest {
        &self.m6_completion_bundle_content_digest
    }

    pub fn m4_lifecycle_terminal_job_digest(&self) -> &ContentDigest {
        &self.m4_lifecycle_terminal_job_digest
    }

    pub fn job_id(&self) -> String {
        encode_post_export_identity(
            M5_M2_POST_EXPORT_JOB_PREFIX,
            &self.manifest_digest,
            &self.m5_export_bundle_content_digest,
        )
    }

    pub fn idempotency_key(&self) -> String {
        encode_post_export_effect_identity(
            M5_M2_POST_EXPORT_EFFECT_PREFIX,
            &self.m4_lifecycle_terminal_job_digest,
            &self.m6_completion_bundle_content_digest,
            &self.binding_context_digest,
        )
    }

    pub fn challenge_digest(
        &self,
        m4_lifecycle_job_id: &str,
        workspace_id: &str,
    ) -> Result<ContentDigest, M5RuntimeError> {
        validate_identifier("M4 lifecycle job_id", m4_lifecycle_job_id)?;
        validate_identifier("post-export workspace_id", workspace_id)?;
        Ok(digest_json_content(&(
            M5_M2_POST_EXPORT_BINDING_DOMAIN,
            &self.manifest_digest,
            &self.m5_export_bundle_content_digest,
            &self.m6_completion_bundle_content_digest,
            m4_lifecycle_job_id,
            &self.m4_lifecycle_terminal_job_digest,
            workspace_id,
            self.job_id(),
            self.idempotency_key(),
        ))?)
    }

    fn expected_binding_context_digest(&self) -> Result<ContentDigest, M5RuntimeError> {
        Ok(digest_json_content(&(
            M5_M2_POST_EXPORT_BINDING_DOMAIN,
            "identity",
            &self.manifest_digest,
            &self.m5_export_bundle_content_digest,
            &self.m6_completion_bundle_content_digest,
            &self.m4_lifecycle_terminal_job_digest,
        ))?)
    }
}

/// Exact pre/post supervisor bytes captured by the production M5 runtime on
/// the isolated M4 workflow root that contains the exported lifecycle anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5M2PostExportRestartCaptureV2 {
    schema: String,
    binding: M5M2PostExportJobBindingV2,
    m4_lifecycle_job_id: String,
    pre_restart_supervisor_state_bytes: Vec<u8>,
    post_restart_supervisor_state_bytes: Vec<u8>,
    capture_digest: ContentDigest,
}

impl M5M2PostExportRestartCaptureV2 {
    /// Reconstruct the exact capture identity from the two canonical state
    /// sources retained by M7. This is also the only production constructor.
    pub fn from_canonical_state_bytes(
        binding: M5M2PostExportJobBindingV2,
        m4_lifecycle_job_id: impl Into<String>,
        pre_restart_supervisor_state_bytes: Vec<u8>,
        post_restart_supervisor_state_bytes: Vec<u8>,
    ) -> Result<Self, M5RuntimeError> {
        let mut value = Self {
            schema: M5_M2_POST_EXPORT_RESTART_CAPTURE_SCHEMA.to_string(),
            binding,
            m4_lifecycle_job_id: m4_lifecycle_job_id.into(),
            pre_restart_supervisor_state_bytes,
            post_restart_supervisor_state_bytes,
            capture_digest: ContentDigest::from_bytes(&[]),
        };
        value.validate_fields()?;
        value.capture_digest = value.expected_capture_digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn binding(&self) -> &M5M2PostExportJobBindingV2 {
        &self.binding
    }

    pub fn m4_lifecycle_job_id(&self) -> &str {
        &self.m4_lifecycle_job_id
    }

    pub fn pre_restart_supervisor_state_bytes(&self) -> &[u8] {
        &self.pre_restart_supervisor_state_bytes
    }

    pub fn post_restart_supervisor_state_bytes(&self) -> &[u8] {
        &self.post_restart_supervisor_state_bytes
    }

    pub fn capture_digest(&self) -> &ContentDigest {
        &self.capture_digest
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M5RuntimeError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_M5_M2_POST_EXPORT_CAPTURE_BYTES {
            return Err(M5RuntimeError::ResourceBound(
                "post-export restart capture exceeds its canonical byte bound".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M5RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_M5_M2_POST_EXPORT_CAPTURE_BYTES {
            return Err(M5RuntimeError::ResourceBound(
                "post-export restart capture bytes are empty or exceed bounds".to_string(),
            ));
        }
        let value: Self = serde_json::from_slice(bytes)?;
        if serde_json::to_vec(&value)? != bytes {
            return Err(M5RuntimeError::Integrity(
                "post-export restart capture is not canonical JSON".to_string(),
            ));
        }
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), M5RuntimeError> {
        self.validate_fields()?;
        require_digest(
            "post-export restart capture",
            &self.capture_digest,
            &self.expected_capture_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M5RuntimeError> {
        if self.schema != M5_M2_POST_EXPORT_RESTART_CAPTURE_SCHEMA {
            return Err(M5RuntimeError::Integrity(
                "post-export restart capture uses the wrong schema".to_string(),
            ));
        }
        if serde_json::to_vec(self)?.len() > MAX_M5_M2_POST_EXPORT_CAPTURE_BYTES {
            return Err(M5RuntimeError::ResourceBound(
                "post-export restart capture exceeds its canonical byte bound".to_string(),
            ));
        }
        self.binding.validate()?;
        validate_identifier("M4 lifecycle job_id", &self.m4_lifecycle_job_id)?;
        let before: SupervisorState = canonical_supervisor_state(
            "pre-restart supervisor state",
            &self.pre_restart_supervisor_state_bytes,
        )?;
        let after: SupervisorState = canonical_supervisor_state(
            "post-restart supervisor state",
            &self.post_restart_supervisor_state_bytes,
        )?;
        let job_id = self.binding.job_id();
        let before_job = before.jobs.get(&job_id).ok_or_else(|| {
            M5RuntimeError::Integrity(
                "pre-restart supervisor state omits the exact challenge job".to_string(),
            )
        })?;
        let after_job = after.jobs.get(&job_id).ok_or_else(|| {
            M5RuntimeError::Integrity(
                "post-restart supervisor state omits the exact challenge job".to_string(),
            )
        })?;
        let before_anchor = before.jobs.get(&self.m4_lifecycle_job_id).ok_or_else(|| {
            M5RuntimeError::Integrity(
                "pre-restart supervisor state omits the exact M4 lifecycle anchor".to_string(),
            )
        })?;
        let after_anchor = after.jobs.get(&self.m4_lifecycle_job_id).ok_or_else(|| {
            M5RuntimeError::Integrity(
                "post-restart supervisor state omits the exact M4 lifecycle anchor".to_string(),
            )
        })?;
        if before_job.idempotency_key != self.binding.idempotency_key()
            || after_job.idempotency_key != self.binding.idempotency_key()
            || before_job.phase.is_terminal()
            || after_job.phase != JobPhase::Succeeded
            || after_job.terminal_outcome.is_none()
            || before_anchor != after_anchor
            || digest_json_content(before_anchor)?
                != *self.binding.m4_lifecycle_terminal_job_digest()
            || before.heartbeat.owner_id == after.heartbeat.owner_id
        {
            return Err(M5RuntimeError::Integrity(
                "post-export restart capture is not the exact future job, terminal M4 anchor, and distinct-owner completion"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_capture_digest(&self) -> Result<ContentDigest, M5RuntimeError> {
        Ok(digest_json_content(&(
            M5_M2_POST_EXPORT_CAPTURE_DOMAIN,
            &self.schema,
            &self.binding,
            &self.m4_lifecycle_job_id,
            self.pre_restart_supervisor_state_bytes.len(),
            ContentDigest::from_bytes(&self.pre_restart_supervisor_state_bytes),
            self.post_restart_supervisor_state_bytes.len(),
            ContentDigest::from_bytes(&self.post_restart_supervisor_state_bytes),
        ))?)
    }
}

fn canonical_supervisor_state(
    label: &str,
    bytes: &[u8],
) -> Result<SupervisorState, M5RuntimeError> {
    if bytes.is_empty() || bytes.len() > MAX_RUNTIME_STATE_BYTES {
        return Err(M5RuntimeError::ResourceBound(format!(
            "{label} bytes are empty or exceed bounds"
        )));
    }
    let state: SupervisorState = serde_json::from_slice(bytes)?;
    if serde_json::to_vec_pretty(&state)? != bytes {
        return Err(M5RuntimeError::Integrity(format!(
            "{label} is not canonical JSON"
        )));
    }
    state.validate().map_err(|error| {
        M5RuntimeError::Integrity(format!("{label} is not a valid supervisor state: {error}"))
    })?;
    Ok(state)
}

fn encode_post_export_identity(
    prefix: &str,
    first: &ContentDigest,
    second: &ContentDigest,
) -> String {
    format!(
        "{prefix}{}.{}",
        &first.as_str()["sha256:".len()..],
        &second.as_str()["sha256:".len()..]
    )
}

fn encode_post_export_effect_identity(
    prefix: &str,
    first: &ContentDigest,
    second: &ContentDigest,
    third: &ContentDigest,
) -> String {
    format!(
        "{prefix}{}.{}.{}",
        &first.as_str()["sha256:".len()..],
        &second.as_str()["sha256:".len()..],
        &third.as_str()["sha256:".len()..]
    )
}

fn parse_post_export_identity(
    prefix: &str,
    value: &str,
) -> Result<(ContentDigest, ContentDigest), M5RuntimeError> {
    let suffix = value.strip_prefix(prefix).ok_or_else(|| {
        M5RuntimeError::Integrity("post-export M2 job identity has the wrong prefix".to_string())
    })?;
    let (first, second) = suffix.split_once('.').ok_or_else(|| {
        M5RuntimeError::Integrity("post-export M2 job identity is malformed".to_string())
    })?;
    if first.len() != 64
        || second.len() != 64
        || second.contains('.')
        || !first
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !second
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(M5RuntimeError::Integrity(
            "post-export M2 job identity contains a non-canonical digest".to_string(),
        ));
    }
    Ok((
        ContentDigest::new(format!("sha256:{first}"))
            .map_err(|error| M5RuntimeError::Integrity(error.to_string()))?,
        ContentDigest::new(format!("sha256:{second}"))
            .map_err(|error| M5RuntimeError::Integrity(error.to_string()))?,
    ))
}

fn parse_post_export_effect_identity(
    value: &str,
) -> Result<(ContentDigest, ContentDigest, ContentDigest), M5RuntimeError> {
    let suffix = value
        .strip_prefix(M5_M2_POST_EXPORT_EFFECT_PREFIX)
        .ok_or_else(|| {
            M5RuntimeError::Integrity(
                "post-export M2 effect identity has the wrong prefix".to_string(),
            )
        })?;
    let parts = suffix.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.len() != 64
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    {
        return Err(M5RuntimeError::Integrity(
            "post-export M2 effect identity contains a non-canonical digest".to_string(),
        ));
    }
    let parse = |part: &str| {
        ContentDigest::new(format!("sha256:{part}"))
            .map_err(|error| M5RuntimeError::Integrity(error.to_string()))
    };
    Ok((parse(parts[0])?, parse(parts[1])?, parse(parts[2])?))
}

/// Explicit roots and identities for one local reproduction namespace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5RuntimeConfig {
    pub root: PathBuf,
    pub factory_id: String,
    pub scope_id: String,
    pub deployment_id: String,
    pub worker_max_concurrency: usize,
}

impl M5RuntimeConfig {
    pub fn validate(&self) -> Result<(), M5RuntimeError> {
        if self.root.as_os_str().is_empty() {
            return Err(M5RuntimeError::InvalidConfig(
                "root must not be empty".to_string(),
            ));
        }
        for (field, value) in [
            ("factory_id", self.factory_id.as_str()),
            ("scope_id", self.scope_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        validate_safe_component("deployment_id", &self.deployment_id)?;
        if self.worker_max_concurrency == 0 {
            return Err(M5RuntimeError::InvalidConfig(
                "worker_max_concurrency must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Immutable inputs required to reopen the exact same local factory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct M5RuntimeManifest {
    pub(crate) schema: String,
    pub(crate) config: M5RuntimeConfig,
    pub(crate) validation_suite: ValidationSuite,
    pub(crate) release_gate: ReleaseGate,
    pub(crate) incumbent_wat_digest: ContentDigest,
    pub(crate) manifest_digest: ContentDigest,
}

impl M5RuntimeManifest {
    fn new(
        config: M5RuntimeConfig,
        validation_suite: ValidationSuite,
        release_gate: ReleaseGate,
        incumbent_wat: &[u8],
    ) -> Result<Self, M5RuntimeError> {
        let mut manifest = Self {
            schema: M5_MANIFEST_SCHEMA.to_string(),
            config,
            validation_suite,
            release_gate,
            incumbent_wat_digest: ContentDigest::from_bytes(incumbent_wat),
            manifest_digest: ContentDigest::from_bytes(&[]),
        };
        manifest.validate_fields()?;
        manifest.manifest_digest = manifest.expected_digest()?;
        Ok(manifest)
    }

    /// Validate the exact immutable identity used to open this M5 runtime.
    pub(crate) fn validate(&self) -> Result<(), M5RuntimeError> {
        self.validate_fields()?;
        require_digest(
            "M5 runtime manifest",
            &self.manifest_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M5RuntimeError> {
        if self.schema != M5_MANIFEST_SCHEMA {
            return Err(M5RuntimeError::Integrity(
                "unsupported M5 runtime manifest schema".to_string(),
            ));
        }
        self.config.validate()?;
        self.validation_suite
            .validate()
            .map_err(|error| M5RuntimeError::InvalidConfig(error.to_string()))?;
        self.release_gate.validate()?;
        validate_suite_matches_gate(&self.validation_suite, &self.release_gate)
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5RuntimeError> {
        Ok(digest_json_content(&(
            M5_MANIFEST_SCHEMA,
            &self.config,
            &self.validation_suite,
            &self.release_gate,
            &self.incumbent_wat_digest,
        ))?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum M5InitializationPhase {
    IntentRecorded,
    ComponentsReconciled,
    Complete,
}

/// Exact restart input retained before any mutable child runtime is opened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct M5InitializationJournal {
    schema: String,
    manifest: M5RuntimeManifest,
    incumbent: FactoryPackage,
    initial_state_bytes: Vec<u8>,
    initialization_authority: M5InitializationAuthority,
    phase: M5InitializationPhase,
    journal_digest: ContentDigest,
}

impl M5InitializationJournal {
    fn new(
        manifest: M5RuntimeManifest,
        incumbent: FactoryPackage,
        initialization_authority: M5InitializationAuthority,
    ) -> Result<Self, M5RuntimeError> {
        let initial_state_bytes = serde_json::to_vec(&json!({
            "schema": incumbent.payload.boot_manifest.state_compatibility.written_schema,
            "factory_id": incumbent.payload.factory_id,
            "generation": incumbent.payload.generation,
        }))?;
        let mut journal = Self {
            schema: M5_INITIALIZATION_JOURNAL_SCHEMA.to_string(),
            manifest,
            incumbent,
            initial_state_bytes,
            initialization_authority,
            phase: M5InitializationPhase::IntentRecorded,
            journal_digest: ContentDigest::from_bytes(&[]),
        };
        journal.validate_fields()?;
        journal.journal_digest = journal.expected_digest()?;
        Ok(journal)
    }

    fn advance(&mut self, phase: M5InitializationPhase) -> Result<(), M5RuntimeError> {
        if (phase as u8) < (self.phase as u8) {
            return Ok(());
        }
        self.phase = phase;
        self.journal_digest = self.expected_digest()?;
        Ok(())
    }

    fn validate(&self) -> Result<(), M5RuntimeError> {
        self.validate_fields()?;
        require_digest(
            "M5 initialization journal",
            &self.journal_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M5RuntimeError> {
        if self.schema != M5_INITIALIZATION_JOURNAL_SCHEMA
            || self.initial_state_bytes.is_empty()
            || self.initial_state_bytes.len() > MAX_RUNTIME_STATE_BYTES
        {
            return Err(M5RuntimeError::Integrity(
                "M5 initialization journal is outside its bounded schema".to_string(),
            ));
        }
        self.manifest.validate()?;
        self.incumbent.validate()?;
        self.initialization_authority.validate()?;
        if self.incumbent.payload.factory_id != self.manifest.config.factory_id
            || self.incumbent.payload.generation != 0
            || self.incumbent.payload.parent_package_digest.is_some()
            || self.initial_state_bytes
                != serde_json::to_vec(&json!({
                    "schema": self.incumbent.payload.boot_manifest.state_compatibility.written_schema,
                    "factory_id": self.incumbent.payload.factory_id,
                    "generation": self.incumbent.payload.generation,
                }))?
        {
            return Err(M5RuntimeError::Integrity(
                "M5 initialization journal does not describe one exact generation-zero package"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5RuntimeError> {
        Ok(digest_json_content(&(
            M5_INITIALIZATION_JOURNAL_SCHEMA,
            &self.manifest,
            &self.incumbent,
            &self.initial_state_bytes,
            &self.initialization_authority,
            self.phase,
        ))?)
    }
}

/// Explicit local operator authority for generation-zero initialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5InitializationAuthority {
    pub operator_ref: String,
    pub rationale: String,
}

impl M5InitializationAuthority {
    pub fn validate(&self) -> Result<(), M5RuntimeError> {
        validate_identifier("M5 initialization operator ref", &self.operator_ref)?;
        if self.rationale.trim().is_empty() || self.rationale.len() > 4_096 {
            return Err(M5RuntimeError::InvalidConfig(
                "M5 initialization rationale must contain 1..=4096 bytes".to_string(),
            ));
        }
        Ok(())
    }
}

/// Inputs for the first, externally seeded bounded cycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5SeedCyclePlan {
    pub cycle_id: String,
    pub challenger_wat_bytes: Vec<u8>,
    pub challenger_policy: MutableFactoryPolicy,
    pub state_compatibility: StateCompatibility,
    pub migration_plan: Option<StateMigrationPlan>,
    /// Exact executable forward/rollback artifacts required when a migration
    /// plan changes the written state schema.
    pub migration_artifacts: Option<StateMigrationArtifactBundle>,
    pub operator_context_digest: ContentDigest,
    pub approval_decision: ApprovalDecision,
    pub approver_ref: String,
    pub approval_rationale: String,
}

/// Inputs for the cycle materially initiated by the active successor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M5AdoptedCyclePlan {
    pub cycle_id: String,
    pub migration_plan: Option<StateMigrationPlan>,
    pub migration_artifacts: Option<StateMigrationArtifactBundle>,
    pub operator_context_digest: ContentDigest,
    pub approval_decision: ApprovalDecision,
    pub approver_ref: String,
    pub approval_rationale: String,
}

/// Exact receiver-local package input for one ordinary seeded M5 cycle.
///
/// `cycle_id` is the durable idempotency identity. The expected active
/// package, authoritative snapshot, and release gate make the caller's current
/// view explicit. V1 intentionally has no migration input: the candidate must
/// read and continue writing the current state schema.
///
/// The runtime folds every field, including the exact package and WAT byte
/// digests and the explicit approval disposition, into a domain-separated
/// operator-context digest before recording the normal seeded-cycle intent.
/// This lets an M6 coordinator supply its own context digest without coupling
/// M5 to any M6 type while ensuring that any changed replay conflicts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M5ExactCandidateCyclePlan {
    pub cycle_id: String,
    pub expected_active_package_digest: ContentDigest,
    pub expected_active_snapshot_digest: ContentDigest,
    pub expected_release_gate_digest: ContentDigest,
    pub candidate_package_bytes: Vec<u8>,
    pub candidate_wat_bytes: Vec<u8>,
    pub operator_context_digest: ContentDigest,
    pub approval_decision: ApprovalDecision,
    pub approver_ref: String,
    pub approval_rationale: String,
}

/// Self-contained result of the exact-package adoption seam.
///
/// The cycle record carries M1 proving, the six-role M4 evidence, M3 shadow
/// evidence, the release decision, supervisor decision, and any
/// activation/observation/recovery receipts. `effect_audit` adds the exact M3
/// receipt/attestation/proof and backend-fact crosswalk. The final snapshot and
/// complete reproduction state make adoption and rollback outcomes
/// independently cross-checkable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M5ExactCandidateCycleResult {
    pub cycle_id: String,
    pub expected_active_package_digest: ContentDigest,
    pub expected_active_snapshot_digest: ContentDigest,
    pub expected_release_gate_digest: ContentDigest,
    pub incumbent_package: FactoryPackage,
    pub candidate_package: FactoryPackage,
    pub candidate_package_bytes_digest: ContentDigest,
    pub candidate_wat_digest: ContentDigest,
    pub supplied_operator_context_digest: ContentDigest,
    pub bound_operator_context_digest: ContentDigest,
    pub approval_decision: ApprovalDecision,
    pub approver_ref: String,
    pub approval_rationale: String,
    pub intent: CycleIntent,
    pub package_authorization: M5PackageAuthorizationRecord,
    pub cycle_record: CycleRecord,
    pub outcome: CycleOutcome,
    pub reproduction_state: ReproductionState,
    pub active_snapshot: FactoryRuntimeSnapshot,
    pub effect_audit: M5EffectAuditReport,
}

impl M5ExactCandidateCycleResult {
    /// Validate the returned terminal result without reopening its runtime.
    pub fn validate(&self) -> Result<(), M5RuntimeError> {
        validate_exact_candidate_result(self)
    }
}

/// Observable execution through the currently routed exact factory package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ActiveExecution {
    pub package_digest: ContentDigest,
    pub package_bytes_digest: ContentDigest,
    pub component_digest: ContentDigest,
    pub input: i32,
    pub output: i32,
    pub m3_invocation_id: String,
    pub m3_receipt_digest: ContentDigest,
    pub m3_attestation_digest: ContentDigest,
    pub m3_proof_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_context_digest: Option<ContentDigest>,
    pub execution_digest: ContentDigest,
}

/// Portable proof that a named rolled-back cycle was followed by a real
/// execution through the restored active route.
///
/// The effect audit is regenerated with this exact execution classified as an
/// `ActiveExecution`. Detached consumers can therefore cross-check the
/// recovery cycle, restored package, M3 receipt/attestation/proof, backend
/// response and fact, reproduction-state root, and active-snapshot root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5PostRollbackProbeV1 {
    schema: String,
    cycle_id: String,
    cycle_record_digest: ContentDigest,
    recovery_receipt_digest: ContentDigest,
    restored_package_digest: ContentDigest,
    execution: M5ActiveExecution,
    reproduction_state_digest: ContentDigest,
    active_snapshot_digest: ContentDigest,
    prior_effect_audit: M5EffectAuditReport,
    effect_audit: M5EffectAuditReport,
    probe_digest: ContentDigest,
}

impl M5PostRollbackProbeV1 {
    pub fn cycle_id(&self) -> &str {
        &self.cycle_id
    }

    pub fn cycle_record_digest(&self) -> &ContentDigest {
        &self.cycle_record_digest
    }

    pub fn recovery_receipt_digest(&self) -> &ContentDigest {
        &self.recovery_receipt_digest
    }

    pub fn restored_package_digest(&self) -> &ContentDigest {
        &self.restored_package_digest
    }

    pub fn execution(&self) -> &M5ActiveExecution {
        &self.execution
    }

    pub fn reproduction_state_digest(&self) -> &ContentDigest {
        &self.reproduction_state_digest
    }

    pub fn active_snapshot_digest(&self) -> &ContentDigest {
        &self.active_snapshot_digest
    }

    pub fn prior_effect_audit(&self) -> &M5EffectAuditReport {
        &self.prior_effect_audit
    }

    pub fn effect_audit(&self) -> &M5EffectAuditReport {
        &self.effect_audit
    }

    pub fn probe_digest(&self) -> &ContentDigest {
        &self.probe_digest
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M5RuntimeError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(M5RuntimeError::from)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M5RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_POST_ROLLBACK_PROBE_BYTES {
            return Err(M5RuntimeError::ResourceBound(
                "post-rollback probe bytes are empty or exceed the portable bound".to_string(),
            ));
        }
        let value: Self = serde_json::from_slice(bytes)?;
        if serde_json::to_vec(&value)? != bytes {
            return Err(M5RuntimeError::Integrity(
                "post-rollback probe is not canonical JSON".to_string(),
            ));
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), M5RuntimeError> {
        validate_identifier("M5 post-rollback probe cycle id", &self.cycle_id)?;
        self.prior_effect_audit.validate()?;
        self.effect_audit.validate()?;
        if self.schema != M5_POST_ROLLBACK_PROBE_SCHEMA
            || self.execution.causal_context_digest.is_some()
            || self.restored_package_digest != self.execution.package_digest
            || self.reproduction_state_digest != self.effect_audit.reproduction_state_digest
            || self.active_snapshot_digest != self.effect_audit.backend_snapshot_digest
            || self.prior_effect_audit.reproduction_state_digest != self.reproduction_state_digest
            || self.prior_effect_audit.backend_snapshot_digest != self.active_snapshot_digest
        {
            return Err(M5RuntimeError::Integrity(
                "post-rollback probe roots, restored package, or schema disagree".to_string(),
            ));
        }
        let matching = self
            .effect_audit
            .entries
            .iter()
            .filter(|entry| {
                entry.kind == M5EffectAuditKind::ActiveExecution
                    && !self.prior_effect_audit.entries.contains(entry)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(M5RuntimeError::Integrity(
                "post-rollback probe must add exactly one active-execution audit entry".to_string(),
            ));
        }
        let entry = matching[0];
        if entry.evidence_id != format!("active-execution:{}", self.execution.execution_digest)
            || entry.invocation_id != self.execution.m3_invocation_id
            || entry.receipt_digest != self.execution.m3_receipt_digest
            || entry.attestation_digest != self.execution.m3_attestation_digest
            || entry.proof_digest != self.execution.m3_proof_digest
        {
            return Err(M5RuntimeError::Integrity(
                "post-rollback execution differs from its exact M3 audit entry".to_string(),
            ));
        }
        if self.prior_effect_audit.entries.iter().any(|prior| {
            prior.invocation_id == self.execution.m3_invocation_id
                || prior.proof_digest == self.execution.m3_proof_digest
        }) || self.effect_audit.entries.len()
            != self.prior_effect_audit.entries.len().saturating_add(1)
            || self
                .prior_effect_audit
                .entries
                .iter()
                .any(|prior| !self.effect_audit.entries.contains(prior))
        {
            return Err(M5RuntimeError::Integrity(
                "post-rollback probe is not an exact one-execution audit delta".to_string(),
            ));
        }
        require_digest(
            "M5 post-rollback probe",
            &self.probe_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5RuntimeError> {
        Ok(digest_json_content(&(
            M5_POST_ROLLBACK_PROBE_DOMAIN,
            &self.schema,
            &self.cycle_id,
            &self.cycle_record_digest,
            &self.recovery_receipt_digest,
            &self.restored_package_digest,
            &self.execution,
            &self.reproduction_state_digest,
            &self.active_snapshot_digest,
            &self.prior_effect_audit,
            &self.effect_audit,
        ))?)
    }
}

/// Exact rollback probe whose fresh execution request is durably challenged
/// by a caller-supplied causal context before M3 invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5CausallyBoundPostRollbackProbeV1 {
    schema: String,
    causal_execution_context_digest: ContentDigest,
    cycle_id: String,
    cycle_record_digest: ContentDigest,
    recovery_receipt_digest: ContentDigest,
    restored_package_digest: ContentDigest,
    execution: M5ActiveExecution,
    reproduction_state_digest: ContentDigest,
    active_snapshot_digest: ContentDigest,
    prior_effect_audit: M5EffectAuditReport,
    effect_audit: M5EffectAuditReport,
    probe_digest: ContentDigest,
}

impl M5CausallyBoundPostRollbackProbeV1 {
    pub fn causal_execution_context_digest(&self) -> &ContentDigest {
        &self.causal_execution_context_digest
    }

    pub fn cycle_id(&self) -> &str {
        &self.cycle_id
    }

    pub fn cycle_record_digest(&self) -> &ContentDigest {
        &self.cycle_record_digest
    }

    pub fn recovery_receipt_digest(&self) -> &ContentDigest {
        &self.recovery_receipt_digest
    }

    pub fn restored_package_digest(&self) -> &ContentDigest {
        &self.restored_package_digest
    }

    pub fn execution(&self) -> &M5ActiveExecution {
        &self.execution
    }

    pub fn reproduction_state_digest(&self) -> &ContentDigest {
        &self.reproduction_state_digest
    }

    pub fn active_snapshot_digest(&self) -> &ContentDigest {
        &self.active_snapshot_digest
    }

    pub fn prior_effect_audit(&self) -> &M5EffectAuditReport {
        &self.prior_effect_audit
    }

    pub fn effect_audit(&self) -> &M5EffectAuditReport {
        &self.effect_audit
    }

    pub fn probe_digest(&self) -> &ContentDigest {
        &self.probe_digest
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M5RuntimeError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_POST_ROLLBACK_PROBE_BYTES {
            return Err(M5RuntimeError::ResourceBound(
                "causally bound post-rollback probe exceeds its portable byte bound".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M5RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_POST_ROLLBACK_PROBE_BYTES {
            return Err(M5RuntimeError::ResourceBound(
                "causally bound post-rollback probe bytes are empty or exceed bounds".to_string(),
            ));
        }
        let value: Self = serde_json::from_slice(bytes)?;
        if serde_json::to_vec(&value)? != bytes {
            return Err(M5RuntimeError::Integrity(
                "causally bound post-rollback probe is not canonical JSON".to_string(),
            ));
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), M5RuntimeError> {
        validate_identifier("M5 causally bound post-rollback cycle id", &self.cycle_id)?;
        self.prior_effect_audit.validate()?;
        self.effect_audit.validate()?;
        if self.schema != M5_CAUSALLY_BOUND_POST_ROLLBACK_PROBE_SCHEMA
            || self.execution.causal_context_digest.as_ref()
                != Some(&self.causal_execution_context_digest)
            || self.restored_package_digest != self.execution.package_digest
            || self.reproduction_state_digest != self.effect_audit.reproduction_state_digest
            || self.active_snapshot_digest != self.effect_audit.backend_snapshot_digest
            || self.prior_effect_audit.reproduction_state_digest != self.reproduction_state_digest
            || self.prior_effect_audit.backend_snapshot_digest != self.active_snapshot_digest
        {
            return Err(M5RuntimeError::Integrity(
                "causally bound post-rollback probe roots, context, package, or schema disagree"
                    .to_string(),
            ));
        }
        let exact_request = FactoryExecuteRequest::new_with_causal_context(
            self.execution.package_digest.clone(),
            self.execution.input,
            self.causal_execution_context_digest.clone(),
        )?;
        let matching = self
            .effect_audit
            .entries
            .iter()
            .filter(|entry| {
                entry.kind == M5EffectAuditKind::ActiveExecution
                    && !self.prior_effect_audit.entries.contains(entry)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(M5RuntimeError::Integrity(
                "causally bound post-rollback probe must add one active execution".to_string(),
            ));
        }
        let entry = matching[0];
        if entry.evidence_id != format!("active-execution:{}", self.execution.execution_digest)
            || entry.logical_effect_id
                != format!("m5-execute:{}", exact_request.request_digest.file_stem())
            || entry.domain_request_digest != exact_request.request_digest
            || entry.invocation_id != self.execution.m3_invocation_id
            || entry.receipt_digest != self.execution.m3_receipt_digest
            || entry.attestation_digest != self.execution.m3_attestation_digest
            || entry.proof_digest != self.execution.m3_proof_digest
            || self.prior_effect_audit.entries.iter().any(|prior| {
                prior.invocation_id == self.execution.m3_invocation_id
                    || prior.proof_digest == self.execution.m3_proof_digest
            })
            || self.effect_audit.entries.len()
                != self.prior_effect_audit.entries.len().saturating_add(1)
            || self
                .prior_effect_audit
                .entries
                .iter()
                .any(|prior| !self.effect_audit.entries.contains(prior))
        {
            return Err(M5RuntimeError::Integrity(
                "causally bound post-rollback execution differs from its exact M3 audit delta"
                    .to_string(),
            ));
        }
        require_digest(
            "M5 causally bound post-rollback probe",
            &self.probe_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5RuntimeError> {
        Ok(digest_json_content(&(
            M5_CAUSALLY_BOUND_POST_ROLLBACK_PROBE_DOMAIN,
            &self.schema,
            &self.causal_execution_context_digest,
            &self.cycle_id,
            &self.cycle_record_digest,
            &self.recovery_receipt_digest,
            &self.restored_package_digest,
            &self.execution,
            &self.reproduction_state_digest,
            &self.active_snapshot_digest,
            &self.prior_effect_audit,
            &self.effect_audit,
        ))?)
    }
}

/// Final proof-run rollback probe whose fresh M3 execution is causally bound
/// to the exact manifest, export, M6 completion, and terminal M2 restart that
/// existed before invocation.
///
/// This is deliberately separate from [`M5PostRollbackProbeV1`], which remains
/// usable inside M6 while the completion bundle is still being assembled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5FinalPostRollbackProbeV1 {
    schema: String,
    proof_run_manifest_digest: ContentDigest,
    m5_export_bundle_content_digest: ContentDigest,
    m6_completion_bundle_content_digest: ContentDigest,
    m2_restart_capture_digest: ContentDigest,
    causal_execution_context_digest: ContentDigest,
    probe: M5CausallyBoundPostRollbackProbeV1,
    final_probe_digest: ContentDigest,
}

struct CapturedPostRollbackProbeParts {
    cycle_id: String,
    cycle_record_digest: ContentDigest,
    recovery_receipt_digest: ContentDigest,
    restored_package_digest: ContentDigest,
    execution: M5ActiveExecution,
    reproduction_state_digest: ContentDigest,
    active_snapshot_digest: ContentDigest,
    prior_effect_audit: M5EffectAuditReport,
    effect_audit: M5EffectAuditReport,
}

impl M5FinalPostRollbackProbeV1 {
    pub fn proof_run_manifest_digest(&self) -> &ContentDigest {
        &self.proof_run_manifest_digest
    }

    pub fn m5_export_bundle_content_digest(&self) -> &ContentDigest {
        &self.m5_export_bundle_content_digest
    }

    pub fn m6_completion_bundle_content_digest(&self) -> &ContentDigest {
        &self.m6_completion_bundle_content_digest
    }

    pub fn m2_restart_capture_digest(&self) -> &ContentDigest {
        &self.m2_restart_capture_digest
    }

    pub fn causal_execution_context_digest(&self) -> &ContentDigest {
        &self.causal_execution_context_digest
    }

    pub fn probe(&self) -> &M5CausallyBoundPostRollbackProbeV1 {
        &self.probe
    }

    pub fn final_probe_digest(&self) -> &ContentDigest {
        &self.final_probe_digest
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M5RuntimeError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_POST_ROLLBACK_PROBE_BYTES {
            return Err(M5RuntimeError::ResourceBound(
                "final post-rollback probe exceeds its portable byte bound".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M5RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_POST_ROLLBACK_PROBE_BYTES {
            return Err(M5RuntimeError::ResourceBound(
                "final post-rollback probe bytes are empty or exceed bounds".to_string(),
            ));
        }
        let value: Self = serde_json::from_slice(bytes)?;
        if serde_json::to_vec(&value)? != bytes {
            return Err(M5RuntimeError::Integrity(
                "final post-rollback probe is not canonical JSON".to_string(),
            ));
        }
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), M5RuntimeError> {
        self.probe.validate()?;
        if self.schema != M5_FINAL_POST_ROLLBACK_PROBE_SCHEMA {
            return Err(M5RuntimeError::Integrity(
                "final post-rollback probe uses the wrong schema".to_string(),
            ));
        }
        require_digest(
            "final post-rollback causal execution context",
            &self.causal_execution_context_digest,
            &Self::expected_causal_execution_context_digest(
                &self.proof_run_manifest_digest,
                &self.m5_export_bundle_content_digest,
                &self.m6_completion_bundle_content_digest,
                &self.m2_restart_capture_digest,
                self.probe.cycle_id(),
                self.probe.cycle_record_digest(),
                self.probe.recovery_receipt_digest(),
            )?,
        )?;
        if self.probe.execution().causal_context_digest.as_ref()
            != Some(&self.causal_execution_context_digest)
        {
            return Err(M5RuntimeError::Integrity(
                "final post-rollback execution omits its pre-invocation causal context".to_string(),
            ));
        }
        let exact_request = FactoryExecuteRequest::new_with_causal_context(
            self.probe.execution().package_digest.clone(),
            self.probe.execution().input,
            self.causal_execution_context_digest.clone(),
        )?;
        let matching = self
            .probe
            .effect_audit()
            .entries
            .iter()
            .filter(|entry| {
                entry.kind == M5EffectAuditKind::ActiveExecution
                    && entry.invocation_id == self.probe.execution().m3_invocation_id
                    && entry.proof_digest == self.probe.execution().m3_proof_digest
                    && !self.probe.prior_effect_audit().entries.contains(entry)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1
            || matching[0].domain_request_digest != exact_request.request_digest
            || matching[0].logical_effect_id
                != format!("m5-execute:{}", exact_request.request_digest.file_stem())
        {
            return Err(M5RuntimeError::Integrity(
                "final post-rollback execution audit is not the exact challenged M3 request"
                    .to_string(),
            ));
        }
        require_digest(
            "final post-rollback probe",
            &self.final_probe_digest,
            &self.expected_final_probe_digest()?,
        )
    }

    pub fn expected_causal_execution_context_digest(
        proof_run_manifest_digest: &ContentDigest,
        m5_export_bundle_content_digest: &ContentDigest,
        m6_completion_bundle_content_digest: &ContentDigest,
        m2_restart_capture_digest: &ContentDigest,
        cycle_id: &str,
        cycle_record_digest: &ContentDigest,
        recovery_receipt_digest: &ContentDigest,
    ) -> Result<ContentDigest, M5RuntimeError> {
        validate_identifier("M5 final post-rollback cycle id", cycle_id)?;
        Ok(digest_json_content(&(
            M5_FINAL_POST_ROLLBACK_PROBE_DOMAIN,
            "causal-execution-context",
            proof_run_manifest_digest,
            m5_export_bundle_content_digest,
            m6_completion_bundle_content_digest,
            m2_restart_capture_digest,
            cycle_id,
            cycle_record_digest,
            recovery_receipt_digest,
        ))?)
    }

    fn expected_final_probe_digest(&self) -> Result<ContentDigest, M5RuntimeError> {
        Ok(digest_json_content(&(
            M5_FINAL_POST_ROLLBACK_PROBE_DOMAIN,
            &self.schema,
            &self.proof_run_manifest_digest,
            &self.m5_export_bundle_content_digest,
            &self.m6_completion_bundle_content_digest,
            &self.m2_restart_capture_digest,
            &self.causal_execution_context_digest,
            &self.probe,
        ))?)
    }
}

fn active_execution_audit_record(execution: &M5ActiveExecution) -> M5ActiveExecutionAuditRecord {
    M5ActiveExecutionAuditRecord {
        package_digest: execution.package_digest.clone(),
        package_bytes_digest: execution.package_bytes_digest.clone(),
        component_digest: execution.component_digest.clone(),
        input: execution.input,
        output: execution.output,
        m3_invocation_id: execution.m3_invocation_id.clone(),
        m3_receipt_digest: execution.m3_receipt_digest.clone(),
        m3_attestation_digest: execution.m3_attestation_digest.clone(),
        m3_proof_digest: execution.m3_proof_digest.clone(),
        causal_context_digest: execution.causal_context_digest.clone(),
        execution_digest: execution.execution_digest.clone(),
    }
}

/// Compact result for two consecutive governed cycles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M5TwoCycleOutcome {
    pub first: CycleOutcome,
    pub second: CycleOutcome,
    pub active_package_digest: ContentDigest,
    pub active_generation: u32,
}

/// Frozen, secret-free reconstruction of the exact provider HTTP JSON body.
///
/// Validation rebuilds the body through the same pure inference seam used by
/// the live adapter. Retaining the full generation policy prevents a digest
/// alone from hiding a wire-relevant token limit or retry policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ProviderWireRequestV1 {
    schema: String,
    provider_profile: M5ProviderProfileV1,
    api_base_url: String,
    endpoint_class: M5ProviderEndpointClassV1,
    model_id: String,
    generation_policy: InferenceGenerationPolicy,
    prompt_bytes: Vec<u8>,
    tool_catalog_bytes: Vec<u8>,
    response_schema_bytes: Vec<u8>,
    response_schema_id: String,
    required_function_name: String,
    canonical_request_body_bytes: Vec<u8>,
    request_body_digest: ContentDigest,
    wire_request_digest: ContentDigest,
}

impl M5ProviderWireRequestV1 {
    fn new(
        config: &GovernedLiveProviderConfig,
        request: &ProviderQualificationRequest,
    ) -> Result<Self, M5RuntimeError> {
        let mut wire = Self {
            schema: M5_PROVIDER_WIRE_REQUEST_SCHEMA.to_string(),
            provider_profile: request.configuration.provider_profile,
            api_base_url: request.configuration.api_base_url.clone(),
            endpoint_class: request.configuration.endpoint_class.clone(),
            model_id: request.configuration.model_id.clone(),
            generation_policy: config.generation_policy.clone(),
            prompt_bytes: request.prompt_bytes.clone(),
            tool_catalog_bytes: request.replay_capsule.filtered_tool_catalog_bytes.clone(),
            response_schema_bytes: request.replay_capsule.response_schema_bytes.clone(),
            response_schema_id: m5_provider_response_schema_id(&request.qualification_id),
            required_function_name: PROVIDER_CANDIDATE_OPERATION.to_string(),
            canonical_request_body_bytes: Vec::new(),
            request_body_digest: ContentDigest::from_bytes(&[]),
            wire_request_digest: ContentDigest::from_bytes(&[]),
        };
        wire.canonical_request_body_bytes = wire.rebuild_body_bytes()?;
        wire.request_body_digest = ContentDigest::from_bytes(&wire.canonical_request_body_bytes);
        wire.wire_request_digest = wire.expected_digest()?;
        wire.validate_for(request)?;
        Ok(wire)
    }

    fn challenged_from_base(
        base: &Self,
        request: &ProviderQualificationRequest,
    ) -> Result<Self, M5RuntimeError> {
        let mut wire = Self {
            schema: M5_PROVIDER_WIRE_REQUEST_SCHEMA.to_string(),
            provider_profile: base.provider_profile,
            api_base_url: base.api_base_url.clone(),
            endpoint_class: base.endpoint_class.clone(),
            model_id: base.model_id.clone(),
            generation_policy: base.generation_policy.clone(),
            prompt_bytes: request.prompt_bytes.clone(),
            tool_catalog_bytes: request.replay_capsule.filtered_tool_catalog_bytes.clone(),
            response_schema_bytes: request.replay_capsule.response_schema_bytes.clone(),
            response_schema_id: base.response_schema_id.clone(),
            required_function_name: base.required_function_name.clone(),
            canonical_request_body_bytes: Vec::new(),
            request_body_digest: ContentDigest::from_bytes(&[]),
            wire_request_digest: ContentDigest::from_bytes(&[]),
        };
        wire.canonical_request_body_bytes = wire.rebuild_body_bytes()?;
        wire.request_body_digest = ContentDigest::from_bytes(&wire.canonical_request_body_bytes);
        wire.wire_request_digest = wire.expected_digest()?;
        wire.validate_for(request)?;
        Ok(wire)
    }

    pub fn validate_for(
        &self,
        request: &ProviderQualificationRequest,
    ) -> Result<(), M5RuntimeError> {
        request.validate()?;
        self.generation_policy.validate()?;
        let generation_policy_digest = digest_json_content(&self.generation_policy)?;
        let maximum_retries = u32::try_from(self.generation_policy.max_retries).map_err(|_| {
            M5RuntimeError::Integrity(
                "provider wire retry bound is not representable as u32".to_string(),
            )
        })?;
        let maximum_output_tokens = u32::try_from(self.generation_policy.max_output_tokens)
            .map_err(|_| {
                M5RuntimeError::Integrity(
                    "provider wire output-token bound is not representable as u32".to_string(),
                )
            })?;
        if self.schema != M5_PROVIDER_WIRE_REQUEST_SCHEMA
            || self.provider_profile != request.configuration.provider_profile
            || self.api_base_url != request.configuration.api_base_url
            || self.endpoint_class != request.configuration.endpoint_class
            || self.model_id != request.configuration.model_id
            || self.generation_policy.generation_policy_id
                != request.configuration.generation_policy_id
            || generation_policy_digest != request.configuration.generation_policy_digest
            || maximum_retries != request.configuration.maximum_retries
            || maximum_output_tokens != request.configuration.maximum_output_tokens
            || self.prompt_bytes != request.prompt_bytes
            || self.tool_catalog_bytes != request.replay_capsule.filtered_tool_catalog_bytes
            || self.response_schema_bytes != request.replay_capsule.response_schema_bytes
            || self.response_schema_id != m5_provider_response_schema_id(&request.qualification_id)
            || self.required_function_name != PROVIDER_CANDIDATE_OPERATION
        {
            return Err(M5RuntimeError::Integrity(
                "provider wire request differs from its exact frozen configuration, capsule, or required function"
                    .to_string(),
            ));
        }
        let rebuilt = self.rebuild_body_bytes()?;
        if self.canonical_request_body_bytes != rebuilt
            || self.request_body_digest != ContentDigest::from_bytes(&rebuilt)
        {
            return Err(M5RuntimeError::Integrity(
                "provider wire request body differs from the pure frozen-input rebuild".to_string(),
            ));
        }
        require_digest(
            "M5 provider wire request",
            &self.wire_request_digest,
            &self.expected_digest()?,
        )
    }

    pub fn request_body_digest(&self) -> &ContentDigest {
        &self.request_body_digest
    }

    pub fn api_base_url(&self) -> &str {
        &self.api_base_url
    }

    pub fn endpoint_class(&self) -> M5ProviderEndpointClassV1 {
        self.endpoint_class.clone()
    }

    pub fn wire_request_digest(&self) -> &ContentDigest {
        &self.wire_request_digest
    }

    pub fn canonical_request_body_bytes(&self) -> &[u8] {
        &self.canonical_request_body_bytes
    }

    pub fn generation_policy(&self) -> &InferenceGenerationPolicy {
        &self.generation_policy
    }

    fn rebuild_body_bytes(&self) -> Result<Vec<u8>, M5RuntimeError> {
        let prompt = std::str::from_utf8(&self.prompt_bytes).map_err(|_| {
            M5RuntimeError::Integrity("provider wire prompt is not UTF-8".to_string())
        })?;
        let tool_catalog = std::str::from_utf8(&self.tool_catalog_bytes).map_err(|_| {
            M5RuntimeError::Integrity("provider wire tool catalog is not UTF-8".to_string())
        })?;
        let response_schema = std::str::from_utf8(&self.response_schema_bytes).map_err(|_| {
            M5RuntimeError::Integrity("provider wire response schema is not UTF-8".to_string())
        })?;
        Ok(
            build_required_function_request_body_json_from_frozen_inputs(
                inference_mode_for_provider_profile(self.provider_profile),
                &self.model_id,
                prompt,
                tool_catalog,
                response_schema,
                &self.response_schema_id,
                u32::try_from(self.generation_policy.max_output_tokens).map_err(|_| {
                    M5RuntimeError::Integrity(
                        "provider wire output-token bound is not representable as u32".to_string(),
                    )
                })?,
                &self.required_function_name,
            )?
            .into_bytes(),
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5RuntimeError> {
        Ok(digest_json_content(&(
            M5_PROVIDER_WIRE_REQUEST_DOMAIN,
            &self.schema,
            self.provider_profile,
            &self.api_base_url,
            &self.endpoint_class,
            &self.model_id,
            &self.generation_policy,
            &self.prompt_bytes,
            &self.tool_catalog_bytes,
            &self.response_schema_bytes,
            &self.response_schema_id,
            &self.required_function_name,
            &self.canonical_request_body_bytes,
            &self.request_body_digest,
        ))?)
    }
}

fn inference_mode_for_provider_profile(profile: M5ProviderProfileV1) -> InferenceProviderMode {
    match profile {
        M5ProviderProfileV1::OpenAiResponses => InferenceProviderMode::OpenAiResponses,
        M5ProviderProfileV1::OpenRouterChatCompletions => {
            InferenceProviderMode::OpenRouterChatCompletions
        }
    }
}

fn m5_provider_response_schema_id(qualification_id: &str) -> String {
    format!("m5-live-{}-schema", sanitize_id(qualification_id))
}

/// Fixed, explicit value used only by the generic non-M7 provider path.
pub fn m5_unbound_invocation_challenge_digest() -> ContentDigest {
    unbound_provider_invocation_challenge_digest()
}

/// Canonical pre-live-call handoff for one proof-run-specific provider cycle.
///
/// The precommit replaces the plan's operator context, while the target and
/// qualification request bind the exact incumbent, candidate, prompt,
/// provider/model configuration, schemas, and replay capsule. An operator can
/// persist this record before constructing any credential-bearing live port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5PreparedProviderSeedV1 {
    pub schema: String,
    pub precommit: M5ProviderPrecommitV1,
    pub plan: M5SeedCyclePlan,
    pub target: ProviderCandidateTarget,
    pub qualification_request: ProviderQualificationRequest,
    pub provider_wire_request: M5ProviderWireRequestV1,
    pub prepared_digest: ContentDigest,
}

impl M5PreparedProviderSeedV1 {
    fn new(
        precommit: M5ProviderPrecommitV1,
        plan: M5SeedCyclePlan,
        target: ProviderCandidateTarget,
        qualification_request: ProviderQualificationRequest,
        provider_wire_request: M5ProviderWireRequestV1,
    ) -> Result<Self, M5RuntimeError> {
        let mut prepared = Self {
            schema: M5_PREPARED_PROVIDER_SEED_SCHEMA.to_string(),
            precommit,
            plan,
            target,
            qualification_request,
            provider_wire_request,
            prepared_digest: ContentDigest::from_bytes(&[]),
        };
        prepared.prepared_digest = prepared.expected_digest()?;
        prepared.validate()?;
        Ok(prepared)
    }

    pub fn validate(&self) -> Result<(), M5RuntimeError> {
        if self.schema != M5_PREPARED_PROVIDER_SEED_SCHEMA {
            return Err(M5RuntimeError::Integrity(
                "unsupported prepared provider-seed schema".to_string(),
            ));
        }
        self.target.validate()?;
        self.qualification_request.validate()?;
        self.provider_wire_request
            .validate_for(&self.qualification_request)?;
        self.precommit.validate_for(
            &self.precommit.proof_run_id,
            &self.precommit.qualification_id,
            self.precommit.prepared_at_ms,
            &self.precommit.provider_configuration,
            &self.plan,
        )?;
        if self.precommit.qualification_id != self.qualification_request.qualification_id
            || self.precommit.provider_configuration != self.qualification_request.configuration
            || self.plan.operator_context_digest != self.precommit.precommit_digest
            || self.target.operator_context_digest != self.precommit.precommit_digest
            || self.target.cycle_id != self.plan.cycle_id
            || self.target.challenger_wat_bytes != self.plan.challenger_wat_bytes
            || self.target.challenger_policy != self.plan.challenger_policy
            || self.target.state_compatibility != self.plan.state_compatibility
            || self.target.migration_plan != self.plan.migration_plan
            || self.target.migration_artifacts != self.plan.migration_artifacts
            || self.qualification_request.package_digest != self.target.incumbent_package_digest
            || self.qualification_request.target_digest != self.target.target_digest
            || self
                .qualification_request
                .invocation_challenge_digest
                .is_some()
        {
            return Err(M5RuntimeError::Integrity(
                "prepared provider seed does not cross-link its exact precommit, plan, target, and qualification request"
                    .to_string(),
            ));
        }
        require_digest(
            "prepared provider seed",
            &self.prepared_digest,
            &self.expected_digest()?,
        )
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M5RuntimeError> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        if bytes.is_empty() || bytes.len() > MAX_RUNTIME_STATE_BYTES {
            return Err(M5RuntimeError::ResourceBound(
                "prepared provider seed exceeds its canonical byte bound".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M5RuntimeError> {
        if bytes.is_empty() || bytes.len() > MAX_RUNTIME_STATE_BYTES {
            return Err(M5RuntimeError::ResourceBound(
                "prepared provider seed is empty or outside its canonical byte bound".to_string(),
            ));
        }
        let prepared: Self = serde_json::from_slice(bytes)?;
        prepared.validate()?;
        if serde_json::to_vec_pretty(&prepared)? != bytes {
            return Err(M5RuntimeError::Integrity(
                "prepared provider seed is not in its exact canonical encoding".to_string(),
            ));
        }
        Ok(prepared)
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5RuntimeError> {
        Ok(digest_json_content(&(
            M5_PREPARED_PROVIDER_SEED_SCHEMA,
            &self.precommit.precommit_digest,
            &self.qualification_request.request_digest,
            &self.provider_wire_request.wire_request_digest,
            &self.target.target_digest,
        ))?)
    }
}

pub const M5_PROVIDER_RUN_NONCE_BYTES: usize = 32;

/// Pre-call nonce challenge bound to one manifest, frozen live scope, and base
/// prepared qualification request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ProviderInvocationChallengeV1 {
    schema: String,
    manifest_digest: ContentDigest,
    live_provider_scope_digest: ContentDigest,
    base_qualification_request_digest: ContentDigest,
    run_nonce: [u8; M5_PROVIDER_RUN_NONCE_BYTES],
    run_nonce_digest: ContentDigest,
    invocation_challenge_digest: ContentDigest,
}

impl M5ProviderInvocationChallengeV1 {
    pub fn derive(
        prepared: &M5PreparedProviderSeedV1,
        manifest_digest: ContentDigest,
        live_provider_scope_digest: ContentDigest,
        run_nonce: [u8; M5_PROVIDER_RUN_NONCE_BYTES],
    ) -> Result<Self, M5RuntimeError> {
        prepared.validate()?;
        if run_nonce.iter().all(|byte| *byte == 0) {
            return Err(M5RuntimeError::Integrity(
                "provider invocation challenge nonce must not be all zero".to_string(),
            ));
        }
        let run_nonce_digest = ContentDigest::from_bytes(&run_nonce);
        let invocation_challenge_digest = digest_json_content(&(
            M5_PROVIDER_INVOCATION_CHALLENGE_DOMAIN,
            &manifest_digest,
            &live_provider_scope_digest,
            &prepared.qualification_request.request_digest,
            run_nonce.as_slice(),
        ))?;
        let challenge = Self {
            schema: M5_PROVIDER_INVOCATION_CHALLENGE_SCHEMA.to_string(),
            manifest_digest,
            live_provider_scope_digest,
            base_qualification_request_digest: prepared
                .qualification_request
                .request_digest
                .clone(),
            run_nonce,
            run_nonce_digest,
            invocation_challenge_digest,
        };
        challenge.validate_for(prepared)?;
        Ok(challenge)
    }

    pub fn validate_for(&self, prepared: &M5PreparedProviderSeedV1) -> Result<(), M5RuntimeError> {
        prepared.validate()?;
        if self.schema != M5_PROVIDER_INVOCATION_CHALLENGE_SCHEMA
            || self.base_qualification_request_digest
                != prepared.qualification_request.request_digest
            || self.run_nonce.iter().all(|byte| *byte == 0)
            || self.run_nonce_digest != ContentDigest::from_bytes(&self.run_nonce)
        {
            return Err(M5RuntimeError::Integrity(
                "provider invocation challenge differs from its exact prepared request or nonce"
                    .to_string(),
            ));
        }
        require_digest(
            "M5 provider invocation challenge",
            &self.invocation_challenge_digest,
            &digest_json_content(&(
                M5_PROVIDER_INVOCATION_CHALLENGE_DOMAIN,
                &self.manifest_digest,
                &self.live_provider_scope_digest,
                &self.base_qualification_request_digest,
                self.run_nonce.as_slice(),
            ))?,
        )
    }

    pub fn manifest_digest(&self) -> &ContentDigest {
        &self.manifest_digest
    }

    pub fn live_provider_scope_digest(&self) -> &ContentDigest {
        &self.live_provider_scope_digest
    }

    pub fn base_qualification_request_digest(&self) -> &ContentDigest {
        &self.base_qualification_request_digest
    }

    pub fn run_nonce(&self) -> &[u8; M5_PROVIDER_RUN_NONCE_BYTES] {
        &self.run_nonce
    }

    pub fn run_nonce_digest(&self) -> &ContentDigest {
        &self.run_nonce_digest
    }

    pub fn invocation_challenge_digest(&self) -> &ContentDigest {
        &self.invocation_challenge_digest
    }
}

/// Exact post-manifest provider request and wire body derived from a prepared
/// base seed plus one current-call challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ChallengedProviderSeedV1 {
    schema: String,
    prepared_digest: ContentDigest,
    challenge: M5ProviderInvocationChallengeV1,
    qualification_request: ProviderQualificationRequest,
    provider_wire_request: M5ProviderWireRequestV1,
    challenged_digest: ContentDigest,
}

impl M5ChallengedProviderSeedV1 {
    pub fn derive(
        prepared: &M5PreparedProviderSeedV1,
        manifest_digest: ContentDigest,
        live_provider_scope_digest: ContentDigest,
        run_nonce: [u8; M5_PROVIDER_RUN_NONCE_BYTES],
    ) -> Result<Self, M5RuntimeError> {
        let challenge = M5ProviderInvocationChallengeV1::derive(
            prepared,
            manifest_digest,
            live_provider_scope_digest,
            run_nonce,
        )?;
        Self::from_challenge(prepared, challenge)
    }

    fn from_challenge(
        prepared: &M5PreparedProviderSeedV1,
        challenge: M5ProviderInvocationChallengeV1,
    ) -> Result<Self, M5RuntimeError> {
        challenge.validate_for(prepared)?;
        let prompt_bytes = challenged_provider_prompt_bytes(
            &prepared.qualification_request.prompt_bytes,
            challenge.invocation_challenge_digest(),
        )?;
        let base_capsule = &prepared.qualification_request.replay_capsule;
        let replay_capsule = ProviderReplayCapsule::new(
            &prepared.qualification_request.configuration,
            prompt_bytes.clone(),
            base_capsule.filtered_tool_catalog_bytes.clone(),
            base_capsule.selected_tool_definition_bytes.clone(),
            base_capsule.selected_argument_schema_bytes.clone(),
            base_capsule.response_schema_bytes.clone(),
        )?;
        let qualification_request = ProviderQualificationRequest::new_challenged(
            prepared.qualification_request.qualification_id.clone(),
            prepared.qualification_request.package_digest.clone(),
            prepared.qualification_request.target_digest.clone(),
            prepared.qualification_request.configuration.clone(),
            prompt_bytes,
            replay_capsule,
            challenge.invocation_challenge_digest().clone(),
        )?;
        let provider_wire_request = M5ProviderWireRequestV1::challenged_from_base(
            &prepared.provider_wire_request,
            &qualification_request,
        )?;
        let mut challenged = Self {
            schema: M5_CHALLENGED_PROVIDER_SEED_SCHEMA.to_string(),
            prepared_digest: prepared.prepared_digest.clone(),
            challenge,
            qualification_request,
            provider_wire_request,
            challenged_digest: ContentDigest::from_bytes(&[]),
        };
        challenged.challenged_digest = challenged.expected_digest()?;
        challenged.validate_for(prepared)?;
        Ok(challenged)
    }

    pub fn validate_for(&self, prepared: &M5PreparedProviderSeedV1) -> Result<(), M5RuntimeError> {
        prepared.validate()?;
        self.challenge.validate_for(prepared)?;
        self.qualification_request.validate()?;
        self.provider_wire_request
            .validate_for(&self.qualification_request)?;
        if self.schema != M5_CHALLENGED_PROVIDER_SEED_SCHEMA
            || self.prepared_digest != prepared.prepared_digest
            || self
                .qualification_request
                .invocation_challenge_digest
                .as_ref()
                != Some(self.challenge.invocation_challenge_digest())
        {
            return Err(M5RuntimeError::Integrity(
                "challenged provider seed differs from its prepared base or invocation challenge"
                    .to_string(),
            ));
        }
        let rebuilt = Self::from_challenge_unvalidated(prepared, self.challenge.clone())?;
        if self.qualification_request != rebuilt.qualification_request
            || self.provider_wire_request != rebuilt.provider_wire_request
        {
            return Err(M5RuntimeError::Integrity(
                "challenged provider request is not the exact derivation of its prepared base"
                    .to_string(),
            ));
        }
        require_digest(
            "M5 challenged provider seed",
            &self.challenged_digest,
            &self.expected_digest()?,
        )
    }

    fn from_challenge_unvalidated(
        prepared: &M5PreparedProviderSeedV1,
        challenge: M5ProviderInvocationChallengeV1,
    ) -> Result<Self, M5RuntimeError> {
        let prompt_bytes = challenged_provider_prompt_bytes(
            &prepared.qualification_request.prompt_bytes,
            challenge.invocation_challenge_digest(),
        )?;
        let base_capsule = &prepared.qualification_request.replay_capsule;
        let replay_capsule = ProviderReplayCapsule::new(
            &prepared.qualification_request.configuration,
            prompt_bytes.clone(),
            base_capsule.filtered_tool_catalog_bytes.clone(),
            base_capsule.selected_tool_definition_bytes.clone(),
            base_capsule.selected_argument_schema_bytes.clone(),
            base_capsule.response_schema_bytes.clone(),
        )?;
        let qualification_request = ProviderQualificationRequest::new_challenged(
            prepared.qualification_request.qualification_id.clone(),
            prepared.qualification_request.package_digest.clone(),
            prepared.qualification_request.target_digest.clone(),
            prepared.qualification_request.configuration.clone(),
            prompt_bytes,
            replay_capsule,
            challenge.invocation_challenge_digest().clone(),
        )?;
        let provider_wire_request = M5ProviderWireRequestV1::challenged_from_base(
            &prepared.provider_wire_request,
            &qualification_request,
        )?;
        let mut challenged = Self {
            schema: M5_CHALLENGED_PROVIDER_SEED_SCHEMA.to_string(),
            prepared_digest: prepared.prepared_digest.clone(),
            challenge,
            qualification_request,
            provider_wire_request,
            challenged_digest: ContentDigest::from_bytes(&[]),
        };
        challenged.challenged_digest = challenged.expected_digest()?;
        Ok(challenged)
    }

    pub fn challenge(&self) -> &M5ProviderInvocationChallengeV1 {
        &self.challenge
    }

    pub fn qualification_request(&self) -> &ProviderQualificationRequest {
        &self.qualification_request
    }

    pub fn provider_wire_request(&self) -> &M5ProviderWireRequestV1 {
        &self.provider_wire_request
    }

    pub fn challenged_digest(&self) -> &ContentDigest {
        &self.challenged_digest
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5RuntimeError> {
        Ok(digest_json_content(&(
            M5_CHALLENGED_PROVIDER_SEED_DOMAIN,
            &self.prepared_digest,
            self.challenge.invocation_challenge_digest(),
            &self.qualification_request.request_digest,
            self.provider_wire_request.wire_request_digest(),
        ))?)
    }
}

fn challenged_provider_prompt_bytes(
    base_prompt_bytes: &[u8],
    invocation_challenge_digest: &ContentDigest,
) -> Result<Vec<u8>, M5RuntimeError> {
    let mut prompt: serde_json::Value =
        serde_json::from_slice(base_prompt_bytes).map_err(|_| {
            M5RuntimeError::Integrity(
                "prepared provider prompt is not the canonical challenge template".to_string(),
            )
        })?;
    let expected_unbound = m5_unbound_invocation_challenge_digest();
    let top_level = prompt
        .get("invocation_challenge_digest")
        .and_then(serde_json::Value::as_str);
    let argument = prompt
        .get("required_response")
        .and_then(|value| value.get("arguments"))
        .and_then(|value| value.get("invocation_challenge_digest"))
        .and_then(serde_json::Value::as_str);
    if top_level != Some(expected_unbound.as_str()) || argument != Some(expected_unbound.as_str()) {
        return Err(M5RuntimeError::Integrity(
            "prepared provider prompt does not contain the exact unbound challenge placeholder"
                .to_string(),
        ));
    }
    prompt["invocation_challenge_digest"] =
        serde_json::Value::String(invocation_challenge_digest.as_str().to_string());
    prompt["required_response"]["arguments"]["invocation_challenge_digest"] =
        serde_json::Value::String(invocation_challenge_digest.as_str().to_string());
    Ok(serde_json::to_vec(&prompt)?)
}

/// Provider configuration plus the exact governed adapter inputs.
///
/// The provider entry stores only an environment-variable *name*.  The value is
/// resolved inside `perform_live_turn` and is never retained by this type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedLiveProviderConfig {
    pub provider: InferenceProviderRegistryEntry,
    pub generation_policy: InferenceGenerationPolicy,
}

/// Production adapter over the repository's HTTP inference driver and canonical
/// model-facing tool membrane.
pub struct GovernedLiveProviderPort {
    config: GovernedLiveProviderConfig,
    expected_configuration: ProviderConfiguration,
    tool_catalog_json: String,
    selected_tool_definition_bytes: Vec<u8>,
    selected_argument_schema_bytes: Vec<u8>,
    response_schema_json: String,
}

impl GovernedLiveProviderPort {
    pub fn new(config: GovernedLiveProviderConfig) -> Result<Self, M5RuntimeError> {
        if config.generation_policy.max_output_tokens == 0
            || config.generation_policy.max_output_tokens > M5_LIVE_PROVIDER_MAX_OUTPUT_TOKENS
        {
            return Err(M5RuntimeError::InvalidConfig(format!(
                "live qualification output-token bound must be within 1..={M5_LIVE_PROVIDER_MAX_OUTPUT_TOKENS}"
            )));
        }
        if config.provider.request_timeout_ms == 0
            || config.provider.request_timeout_ms > M5_LIVE_PROVIDER_MAX_REQUEST_TIMEOUT_MS
        {
            return Err(M5RuntimeError::InvalidConfig(format!(
                "live qualification request timeout must be within 1..={M5_LIVE_PROVIDER_MAX_REQUEST_TIMEOUT_MS} milliseconds per attempt"
            )));
        }
        config.provider.validate()?;
        config.generation_policy.validate()?;
        if config.generation_policy.max_retries > MAX_M5_PROVIDER_RETRIES as usize {
            return Err(M5RuntimeError::InvalidConfig(format!(
                "live qualification permits at most {MAX_M5_PROVIDER_RETRIES} provider retries"
            )));
        }
        if !config.provider.active {
            return Err(M5RuntimeError::InvalidConfig(
                "live qualification requires an active provider entry".to_string(),
            ));
        }
        if matches!(
            config.provider.provider_mode,
            crate::execution::inference::InferenceProviderMode::DeterministicFixture
                | crate::execution::inference::InferenceProviderMode::Disabled
        ) {
            return Err(M5RuntimeError::InvalidConfig(
                "live qualification requires an OpenAI or OpenRouter provider mode".to_string(),
            ));
        }
        if config.provider.models.len() != 1 {
            return Err(M5RuntimeError::InvalidConfig(
                "live qualification requires exactly one explicitly selected provider model"
                    .to_string(),
            ));
        }
        let selected_model = &config.provider.models[0];
        if !selected_model.supports_json_schema || !selected_model.supports_function_tools {
            return Err(M5RuntimeError::InvalidConfig(
                "the selected live-provider model must support both JSON schema output and function tools"
                    .to_string(),
            ));
        }
        let tool_catalog_json = provider_tool_catalog_json();
        let response_schema_json = provider_response_schema_json();
        let tool_catalog_value: serde_json::Value = serde_json::from_str(&tool_catalog_json)?;
        let selected_tool = tool_catalog_value
            .as_array()
            .and_then(|definitions| definitions.first())
            .ok_or_else(|| {
                M5RuntimeError::InvalidConfig(
                    "M5 provider catalog must contain one exact proposal tool".to_string(),
                )
            })?;
        let selected_arguments = selected_tool.get("parameters").ok_or_else(|| {
            M5RuntimeError::InvalidConfig(
                "M5 proposal tool has no exact argument schema".to_string(),
            )
        })?;
        let selected_tool_definition_bytes = serde_json::to_vec(selected_tool)?;
        let selected_argument_schema_bytes = serde_json::to_vec(selected_arguments)?;
        let provider_profile = match config.provider.provider_mode {
            InferenceProviderMode::OpenAiResponses => M5ProviderProfileV1::OpenAiResponses,
            InferenceProviderMode::OpenRouterChatCompletions => {
                M5ProviderProfileV1::OpenRouterChatCompletions
            }
            InferenceProviderMode::DeterministicFixture | InferenceProviderMode::Disabled => {
                return Err(M5RuntimeError::InvalidConfig(
                    "live qualification requires an OpenAI or OpenRouter provider mode".to_string(),
                ));
            }
        };
        let maximum_retries =
            u32::try_from(config.generation_policy.max_retries).map_err(|_| {
                M5RuntimeError::InvalidConfig(
                    "live qualification retry bound is not representable as u32".to_string(),
                )
            })?;
        let maximum_output_tokens = u32::try_from(config.generation_policy.max_output_tokens)
            .map_err(|_| {
                M5RuntimeError::InvalidConfig(
                    "live qualification output-token bound is not representable as u32".to_string(),
                )
            })?;
        let (api_base_url, loopback) =
            normalize_safe_provider_api_base_url(&config.provider.api_base_url)?;
        let endpoint_class = if loopback {
            M5ProviderEndpointClassV1::LoopbackTest
        } else {
            M5ProviderEndpointClassV1::ExternalHttps
        };
        let expected_configuration = ProviderConfiguration {
            provider_id: config.provider.provider_id.clone(),
            model_id: selected_model.model_ref.clone(),
            provider_profile,
            api_base_url,
            endpoint_class,
            driver_profile_digest: digest_json_content(&(
                &config.provider,
                &config.generation_policy,
                M5_REQUIRED_FUNCTION_DRIVER_PROFILE,
                PROVIDER_CANDIDATE_OPERATION,
                m5_provider_driver_transport_semantics(config.provider.provider_mode),
            ))?,
            generation_policy_id: config.generation_policy.generation_policy_id.clone(),
            generation_policy_digest: digest_json_content(&config.generation_policy)?,
            maximum_retries,
            maximum_output_tokens,
            input_cost_per_million_microunits: selected_model.input_cost_per_million_microunits,
            output_cost_per_million_microunits: selected_model.output_cost_per_million_microunits,
            cost_currency: "usd".to_string(),
            parser_digest: ContentDigest::from_bytes(M5_PROVIDER_PARSER_DOMAIN),
            response_schema_digest: ContentDigest::from_bytes(response_schema_json.as_bytes()),
            prompt_renderer_digest: ContentDigest::from_bytes(M5_PROMPT_RENDERER_DOMAIN),
            tool_catalog_digest: ContentDigest::from_bytes(tool_catalog_json.as_bytes()),
        };
        expected_configuration.fingerprint()?;
        Ok(Self {
            config,
            expected_configuration,
            tool_catalog_json,
            selected_tool_definition_bytes,
            selected_argument_schema_bytes,
            response_schema_json,
        })
    }

    pub fn provider_configuration(&self) -> &ProviderConfiguration {
        &self.expected_configuration
    }

    pub fn qualification_request(
        &self,
        qualification_id: impl Into<String>,
        incumbent_package_digest: ContentDigest,
        target_digest: ContentDigest,
        prompt_bytes: Vec<u8>,
    ) -> Result<ProviderQualificationRequest, M5RuntimeError> {
        let capsule = self.replay_capsule(prompt_bytes.clone())?;
        Ok(ProviderQualificationRequest::new(
            qualification_id,
            incumbent_package_digest,
            target_digest,
            self.expected_configuration.clone(),
            prompt_bytes,
            capsule,
        )?)
    }

    fn replay_capsule(
        &self,
        prompt_bytes: Vec<u8>,
    ) -> Result<ProviderReplayCapsule, M5RuntimeError> {
        Ok(ProviderReplayCapsule::new(
            &self.expected_configuration,
            prompt_bytes,
            self.tool_catalog_json.as_bytes().to_vec(),
            self.selected_tool_definition_bytes.clone(),
            self.selected_argument_schema_bytes.clone(),
            self.response_schema_json.as_bytes().to_vec(),
        )?)
    }

    fn parse_intent(
        &self,
        normalized_json: &str,
        expected: &LiveIntentWire,
    ) -> Result<ParsedProviderIntent, PortFailure> {
        let arguments: BTreeMap<String, String> =
            serde_json::from_str(normalized_json).map_err(|error| {
            PortFailure::failed(
                "provider_intent_parse_failed",
                format!(
                    "provider output was not the exact required-function argument object: {error}"
                ),
            )
        })?;
        let wire = LiveIntentWire {
            operation: expected.operation.clone(),
            target_genome_digest: expected.target_genome_digest.clone(),
            arguments,
        };
        if &wire != expected {
            return Err(PortFailure::failed(
                "provider_intent_target_mismatch",
                "provider intent differs from the exact predeclared operation, target genome, or arguments",
            ));
        }
        if wire.operation != crate::m5_provider_binding::PROVIDER_CANDIDATE_OPERATION {
            return Err(PortFailure::failed(
                "provider_tool_not_exposed",
                "provider selected an operation outside the single M5 proposal capability",
            ));
        }
        let expected_keys = [
            "challenger_wat_digest",
            "cycle_id",
            "invocation_challenge_digest",
            "policy_digest",
        ];
        if wire.arguments.len() != expected_keys.len()
            || !expected_keys
                .iter()
                .all(|key| wire.arguments.contains_key(*key))
            || wire.arguments.get("cycle_id").is_none_or(|value| {
                value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control)
            })
            || [
                "challenger_wat_digest",
                "invocation_challenge_digest",
                "policy_digest",
            ]
            .iter()
            .any(|key| {
                wire.arguments
                    .get(*key)
                    .and_then(|value| ContentDigest::new(value.clone()).ok())
                    .is_none()
            })
        {
            return Err(PortFailure::failed(
                "provider_arguments_invalid",
                "provider intent must contain exactly one bounded cycle id and three valid SHA-256 digests",
            ));
        }
        let intent = ParsedProviderIntent {
            intent_schema: M5_PROVIDER_INTENT_SCHEMA.to_string(),
            operation: wire.operation,
            target_genome_digest: wire.target_genome_digest,
            arguments: wire.arguments,
        };
        intent.intent_digest().map_err(port_failure)?;
        Ok(intent)
    }

    fn expected_intent_from_prompt(
        &self,
        prompt_bytes: &[u8],
    ) -> Result<LiveIntentWire, PortFailure> {
        let prompt: serde_json::Value = serde_json::from_slice(prompt_bytes).map_err(|error| {
            PortFailure::failed(
                "provider_prompt_contract_invalid",
                format!("frozen provider prompt is not valid JSON: {error}"),
            )
        })?;
        serde_json::from_value(prompt.get("required_response").cloned().ok_or_else(|| {
            PortFailure::failed(
                "provider_prompt_contract_invalid",
                "frozen provider prompt has no exact required_response",
            )
        })?)
        .map_err(|error| {
            PortFailure::failed(
                "provider_prompt_contract_invalid",
                format!("frozen required_response is outside the bounded intent schema: {error}"),
            )
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveIntentWire {
    operation: String,
    target_genome_digest: ContentDigest,
    arguments: BTreeMap<String, String>,
}

fn provider_accounting_from_bundle(
    config: &GovernedLiveProviderConfig,
    expected_configuration: &ProviderConfiguration,
    bundle: &InferenceTurnBundle,
    transcript: &RedactedTranscript,
) -> Result<M5ProviderAccountingSummaryV1, PortFailure> {
    bundle.validate().map_err(|error| {
        PortFailure::failed(
            "live_provider_evidence_invalid",
            format!("inference bundle failed internal validation: {error}"),
        )
    })?;
    let inconsistent = |message: &str| {
        PortFailure::failed("live_provider_accounting_inconsistent", message.to_string())
    };

    let selected_model =
        config.provider.models.first().ok_or_else(|| {
            inconsistent("validated provider configuration has no selected model")
        })?;
    if bundle.turn_request.provider_ref != config.provider.provider_id
        || bundle.turn_request.provider_ref != expected_configuration.provider_id
        || bundle.provider_outcome.provider_ref != bundle.turn_request.provider_ref
        || bundle.turn_request.model_ref != selected_model.model_ref
        || bundle.turn_request.model_ref != expected_configuration.model_id
        || bundle.provider_outcome.model_ref != bundle.turn_request.model_ref
    {
        return Err(inconsistent(
            "provider, model, request, and outcome identities do not agree",
        ));
    }
    if bundle.generation_policy != config.generation_policy
        || bundle.turn_request.generation_policy_ref
            != bundle.generation_policy.generation_policy_id
        || bundle.generation_policy.generation_policy_id
            != expected_configuration.generation_policy_id
        || bundle.generation_policy.max_retries != expected_configuration.maximum_retries as usize
        || bundle.generation_policy.max_output_tokens
            != expected_configuration.maximum_output_tokens as usize
    {
        return Err(inconsistent(
            "inference bundle used a different generation policy than the governed adapter",
        ));
    }
    let generation_policy_digest =
        digest_json_content(&bundle.generation_policy).map_err(port_failure)?;
    if generation_policy_digest != expected_configuration.generation_policy_digest {
        return Err(inconsistent(
            "inference bundle generation policy digest differs from the qualification request",
        ));
    }
    let driver_profile_digest = digest_json_content(&(
        &config.provider,
        &config.generation_policy,
        M5_REQUIRED_FUNCTION_DRIVER_PROFILE,
        PROVIDER_CANDIDATE_OPERATION,
        m5_provider_driver_transport_semantics(config.provider.provider_mode),
    ))
    .map_err(port_failure)?;
    let (normalized_api_base_url, loopback) =
        normalize_safe_provider_api_base_url(&config.provider.api_base_url)
            .map_err(port_failure)?;
    let endpoint_class = if loopback {
        M5ProviderEndpointClassV1::LoopbackTest
    } else {
        M5ProviderEndpointClassV1::ExternalHttps
    };
    if driver_profile_digest != expected_configuration.driver_profile_digest {
        return Err(inconsistent(
            "live provider driver profile differs from the frozen qualification configuration",
        ));
    }
    if normalized_api_base_url != expected_configuration.api_base_url
        || endpoint_class != expected_configuration.endpoint_class
    {
        return Err(inconsistent(
            "live provider API base URL or endpoint class differs from the frozen configuration",
        ));
    }
    if expected_configuration.parser_digest != ContentDigest::from_bytes(M5_PROVIDER_PARSER_DOMAIN)
        || expected_configuration.prompt_renderer_digest
            != ContentDigest::from_bytes(M5_PROMPT_RENDERER_DOMAIN)
    {
        return Err(inconsistent(
            "parser or prompt-renderer identity differs from the governed M5 implementation",
        ));
    }
    let tool_catalog_digest =
        ContentDigest::from_bytes(bundle.tool_catalog.tool_catalog_json.as_bytes());
    if tool_catalog_digest != expected_configuration.tool_catalog_digest {
        return Err(inconsistent(
            "inference bundle tool catalog differs from the qualification request",
        ));
    }
    let response_schema_digest =
        ContentDigest::from_bytes(bundle.response_schema.response_schema_json.as_bytes());
    if response_schema_digest != expected_configuration.response_schema_digest {
        return Err(inconsistent(
            "inference bundle response schema differs from the qualification request",
        ));
    }
    if ContentDigest::from_bytes(bundle.rendered_prompt.prompt_text.as_bytes())
        != transcript.raw_prompt_digest
    {
        return Err(inconsistent(
            "redacted transcript prompt digest differs from the exact rendered provider prompt",
        ));
    }
    if bundle.turn_result.finish_reason != bundle.provider_outcome.finish_reason
        || bundle.provider_outcome.finish_reason != InferenceFinishReason::Completed
    {
        return Err(inconsistent(
            "turn-result and provider-outcome finish reasons do not name one completed turn",
        ));
    }

    let usage = &bundle.usage_record;
    let outcome = &bundle.provider_outcome;
    if usage.input_tokens != outcome.input_tokens
        || usage.output_tokens != outcome.output_tokens
        || usage.total_tokens != outcome.total_tokens
        || usage.latency_ms != outcome.latency_ms
        || usage.estimated_cost_microunits != outcome.estimated_cost_microunits
        || usage.currency != outcome.currency
    {
        return Err(inconsistent(
            "usage and provider-outcome token, latency, cost, or currency accounting disagree",
        ));
    }

    let ordered_attempt_refs: Vec<String> = bundle
        .attempts
        .iter()
        .map(|attempt| attempt.attempt_id.clone())
        .collect();
    if outcome.attempt_refs.as_slice() != ordered_attempt_refs.as_slice()
        || bundle.turn_result.attempt_refs.as_slice() != ordered_attempt_refs.as_slice()
        || bundle.request_body_records.len() != bundle.attempts.len()
        || bundle.raw_output_records.len() != bundle.attempts.len()
    {
        return Err(inconsistent(
            "attempt order or one-request/one-response cardinality is inconsistent",
        ));
    }

    let mut attempt_summaries = Vec::with_capacity(bundle.attempts.len());
    let mut summed_latency_ms = 0_u64;
    for (index, attempt) in bundle.attempts.iter().enumerate() {
        let expected_attempt_number = index.checked_add(1).ok_or_else(|| {
            inconsistent("provider attempt index overflowed its bounded representation")
        })?;
        if attempt.attempt_number != expected_attempt_number {
            return Err(inconsistent(
                "provider attempts are not contiguous and ordered from one",
            ));
        }
        let mut request_bodies = bundle
            .request_body_records
            .iter()
            .filter(|record| record.request_body_id == attempt.request_body_ref);
        let request_body = request_bodies.next().ok_or_else(|| {
            inconsistent("provider attempt has no exact retained request-body record")
        })?;
        if request_bodies.next().is_some() || request_body.attempt_number != attempt.attempt_number
        {
            return Err(inconsistent(
                "provider attempt request-body linkage is ambiguous or inconsistent",
            ));
        }
        let mut raw_outputs = bundle
            .raw_output_records
            .iter()
            .filter(|record| record.raw_output_id == attempt.raw_response_body_ref);
        let raw_output = raw_outputs.next().ok_or_else(|| {
            inconsistent("provider attempt has no exact retained raw-response record")
        })?;
        if raw_outputs.next().is_some()
            || raw_output.attempt_number != attempt.attempt_number
            || raw_output.provider_ref != bundle.turn_request.provider_ref
            || raw_output.model_ref != bundle.turn_request.model_ref
        {
            return Err(inconsistent(
                "provider attempt raw-response linkage or identity is inconsistent",
            ));
        }
        summed_latency_ms = summed_latency_ms
            .checked_add(attempt.latency_ms)
            .ok_or_else(|| inconsistent("provider attempt latency total overflowed"))?;
        attempt_summaries.push(M5ProviderAttemptSummaryV1 {
            attempt_number: u32::try_from(attempt.attempt_number).map_err(|_| {
                inconsistent("provider attempt number is not representable as a bounded u32")
            })?,
            http_status: attempt.http_status,
            latency_ms: attempt.latency_ms,
            retry_classification: attempt.retry_classification,
            request_body_digest: ContentDigest::from_bytes(
                request_body.request_body_json.as_bytes(),
            ),
            raw_response_digest: ContentDigest::from_bytes(
                raw_output.raw_output_payload.as_bytes(),
            ),
        });
    }
    let terminal_attempt = bundle.attempts.last().ok_or_else(|| {
        inconsistent("completed provider accounting contains no terminal attempt")
    })?;
    if outcome.final_http_status != terminal_attempt.http_status
        || bundle.turn_result.raw_output_ref != terminal_attempt.raw_response_body_ref
        || summed_latency_ms != usage.latency_ms
    {
        return Err(inconsistent(
            "terminal status, terminal raw response, or total attempt latency disagrees",
        ));
    }

    let provider_profile = match config.provider.provider_mode {
        InferenceProviderMode::OpenAiResponses => M5ProviderProfileV1::OpenAiResponses,
        InferenceProviderMode::OpenRouterChatCompletions => {
            M5ProviderProfileV1::OpenRouterChatCompletions
        }
        InferenceProviderMode::DeterministicFixture | InferenceProviderMode::Disabled => {
            return Err(inconsistent(
                "provider accounting cannot represent a non-live provider profile",
            ));
        }
    };
    if provider_profile != expected_configuration.provider_profile {
        return Err(inconsistent(
            "provider profile differs from the frozen qualification configuration",
        ));
    }
    if selected_model.input_cost_per_million_microunits
        != expected_configuration.input_cost_per_million_microunits
        || selected_model.output_cost_per_million_microunits
            != expected_configuration.output_cost_per_million_microunits
        || usage.currency != expected_configuration.cost_currency
    {
        return Err(inconsistent(
            "provider pricing basis differs from the frozen qualification configuration",
        ));
    }
    let maximum_retries = u32::try_from(bundle.generation_policy.max_retries).map_err(|_| {
        inconsistent("provider maximum retries is not representable as a bounded u32")
    })?;
    let input_tokens = u64::try_from(usage.input_tokens)
        .map_err(|_| inconsistent("provider input-token count is not representable as u64"))?;
    let output_tokens = u64::try_from(usage.output_tokens)
        .map_err(|_| inconsistent("provider output-token count is not representable as u64"))?;
    let total_tokens = u64::try_from(usage.total_tokens)
        .map_err(|_| inconsistent("provider total-token count is not representable as u64"))?;

    M5ProviderAccountingSummaryV1::new(
        bundle.turn_request.provider_ref.clone(),
        bundle.turn_request.model_ref.clone(),
        provider_profile,
        response_schema_digest,
        bundle.generation_policy.generation_policy_id.clone(),
        generation_policy_digest,
        maximum_retries,
        expected_configuration.maximum_output_tokens,
        expected_configuration.input_cost_per_million_microunits,
        expected_configuration.output_cost_per_million_microunits,
        bundle.turn_result.finish_reason,
        input_tokens,
        output_tokens,
        total_tokens,
        usage.estimated_cost_microunits,
        usage.currency.clone(),
        usage.latency_ms,
        attempt_summaries,
        transcript,
    )
    .map_err(|error| {
        inconsistent(&format!(
            "mapped provider accounting is invalid after cross-checks: {error}"
        ))
    })
}

fn redacted_provider_turn_id(accounting: &M5ProviderAccountingSummaryV1) -> String {
    format!("provider-turn:{}", accounting.accounting_digest.file_stem())
}

impl LiveProviderQualificationPort for GovernedLiveProviderPort {
    fn perform_live_turn(
        &self,
        request: &ProviderQualificationRequest,
    ) -> Result<LiveProviderTurn, PortFailure> {
        request.validate().map_err(port_failure)?;
        if request.configuration != self.expected_configuration {
            return Err(PortFailure::failed(
                "provider_configuration_mismatch",
                "qualification request does not name the exact configured driver, schema, renderer, and tool catalog",
            ));
        }
        let expected_capsule = self
            .replay_capsule(request.prompt_bytes.clone())
            .map_err(port_failure)?;
        if request.replay_capsule != expected_capsule {
            return Err(PortFailure::failed(
                "provider_replay_capsule_mismatch",
                "qualification request does not retain the exact configured prompt, one-tool catalog, argument schema, and response schema",
            ));
        }
        let expected_wire =
            M5ProviderWireRequestV1::new(&self.config, request).map_err(port_failure)?;
        if std::env::var_os(&self.config.provider.api_key_env_var).is_none() {
            return Err(PortFailure::unavailable(
                "provider_credential_unavailable",
                format!(
                    "credential environment variable '{}' is not present at call time",
                    self.config.provider.api_key_env_var
                ),
            ));
        }
        let prompt_text = std::str::from_utf8(&request.prompt_bytes).map_err(|error| {
            PortFailure::failed(
                "provider_prompt_not_utf8",
                format!("bounded provider prompt is not UTF-8: {error}"),
            )
        })?;
        let turn_id = format!("m5-live-{}", sanitize_id(&request.qualification_id));
        let rendered_prompt_id = format!("{turn_id}-prompt");
        let tool_catalog_id = format!("{turn_id}-tools");
        let response_schema_id = m5_provider_response_schema_id(&request.qualification_id);
        let generation_policy_id = self.config.generation_policy.generation_policy_id.clone();
        let rendered_prompt = InferenceRenderedPromptRecord {
            rendered_prompt_id: rendered_prompt_id.clone(),
            turn_request_ref: turn_id.clone(),
            // The request digest binds the exact full prompt presented to the
            // provider; no hidden suffix is appended at the transport edge.
            prompt_text: prompt_text.to_string(),
            created_at: "call-time".to_string(),
        };
        let tool_catalog = InferenceToolCatalogPayloadRecord {
            tool_catalog_id: tool_catalog_id.clone(),
            turn_request_ref: turn_id.clone(),
            tool_catalog_json: self.tool_catalog_json.clone(),
            created_at: "call-time".to_string(),
        };
        let response_schema = InferenceResponseSchemaPayloadRecord {
            response_schema_id: response_schema_id.clone(),
            turn_request_ref: turn_id.clone(),
            response_schema_json: self.response_schema_json.clone(),
            created_at: "call-time".to_string(),
        };
        let inference_request = InferenceTurnRequest {
            turn_request_id: turn_id,
            provider_ref: self.config.provider.provider_id.clone(),
            model_ref: request.configuration.model_id.clone(),
            rendered_prompt_ref: rendered_prompt_id,
            tool_catalog_ref: tool_catalog_id,
            response_schema_ref: response_schema_id,
            generation_policy_ref: generation_policy_id,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                PortFailure::failed(
                    "provider_runtime_unavailable",
                    format!("could not create the bounded inference runtime: {error}"),
                )
            })?;
        let bundle = runtime
            .block_on(execute_inference_turn_requiring_function_tool(
                &self.config.provider,
                &self.config.generation_policy,
                &inference_request,
                &rendered_prompt,
                &tool_catalog,
                &response_schema,
                PROVIDER_CANDIDATE_OPERATION,
            ))
            .map_err(|error| {
                PortFailure::failed(
                    "live_provider_turn_failed",
                    format!("governed inference adapter rejected the live turn: {error}"),
                )
            })?;
        bundle.validate().map_err(|error| {
            PortFailure::failed(
                "live_provider_evidence_invalid",
                format!("inference bundle failed internal validation: {error}"),
            )
        })?;
        if bundle.request_body_records.is_empty()
            || bundle.request_body_records.iter().any(|record| {
                record.request_body_json.as_bytes() != expected_wire.canonical_request_body_bytes()
            })
        {
            return Err(PortFailure::failed(
                "live_provider_wire_request_mismatch",
                "provider adapter request bytes differ from the frozen pure wire-request rebuild",
            ));
        }
        if bundle.turn_result.finish_reason != InferenceFinishReason::Completed {
            return Err(PortFailure::failed(
                "live_provider_not_completed",
                format!(
                    "provider turn ended with {:?}",
                    bundle.turn_result.finish_reason
                ),
            ));
        }
        let parsed_output = bundle.parsed_output.as_ref().ok_or_else(|| {
            PortFailure::failed(
                "live_provider_missing_parsed_output",
                "completed provider turn has no parsed output",
            )
        })?;
        let expected_intent = self.expected_intent_from_prompt(&request.prompt_bytes)?;
        let normalized_parser_input_bytes =
            parsed_output.normalized_output_json.as_bytes().to_vec();
        if normalized_parser_input_bytes.is_empty()
            || normalized_parser_input_bytes.len() > MAX_PROVIDER_RESPONSE_BYTES
        {
            return Err(PortFailure::failed(
                "provider_response_too_large",
                "normalized provider tool arguments are empty or exceed their byte limit",
            ));
        }
        let intent = self.parse_intent(&parsed_output.normalized_output_json, &expected_intent)?;
        let redacted_response = parsed_output.normalized_output_json.clone();
        let raw_response = bundle
            .raw_output_records
            .last()
            .ok_or_else(|| {
                PortFailure::failed(
                    "live_provider_missing_raw_receipt",
                    "validated provider bundle has no raw response receipt",
                )
            })?
            .raw_output_payload
            .as_bytes();
        let transcript = RedactedTranscript {
            request_digest: request.request_digest.clone(),
            redacted_prompt: format!(
                "[redacted prompt sha256={}]",
                ContentDigest::from_bytes(&request.prompt_bytes)
            ),
            redacted_response: redacted_response.clone(),
            raw_prompt_digest: ContentDigest::from_bytes(&request.prompt_bytes),
            raw_response_digest: ContentDigest::from_bytes(raw_response),
            redaction_applied: true,
        };
        let provider_accounting = provider_accounting_from_bundle(
            &self.config,
            &self.expected_configuration,
            &bundle,
            &transcript,
        )?;
        if provider_accounting
            .attempts
            .iter()
            .any(|attempt| &attempt.request_body_digest != expected_wire.request_body_digest())
        {
            return Err(PortFailure::failed(
                "live_provider_wire_digest_mismatch",
                "one or more retained provider attempts differ from the frozen wire-request digest",
            ));
        }
        let provider_receipt_digest = provider_accounting.accounting_digest.clone();
        let external_turn_id = redacted_provider_turn_id(&provider_accounting);
        LiveProviderTurn {
            request_digest: request.request_digest.clone(),
            configuration_fingerprint: request.configuration.fingerprint().map_err(port_failure)?,
            replay_capsule_digest: request.replay_capsule.capsule_digest.clone(),
            transport: ProviderTransport::LiveProviderApi,
            // This is a local digest-derived correlation id. Raw provider
            // request/response ids never enter durable M5 state.
            external_turn_id,
            provider_receipt_digest,
            provider_accounting,
            transcript,
            normalized_parser_input_bytes,
            parsed_intent: intent,
            turn_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .map_err(port_failure)
    }

    fn replay_offline(
        &self,
        request: &ProviderReplayRequest,
    ) -> Result<ProviderReplayRecord, PortFailure> {
        if !request.network_forbidden {
            return Err(PortFailure::failed(
                "provider_replay_network_not_forbidden",
                "offline replay requires an explicit network prohibition",
            ));
        }
        let normalized_json =
            std::str::from_utf8(&request.normalized_parser_input_bytes).map_err(|error| {
                PortFailure::failed(
                    "provider_replay_input_not_utf8",
                    format!("frozen normalized parser input is not UTF-8: {error}"),
                )
            })?;
        if request.normalized_parser_input_bytes != request.transcript.redacted_response.as_bytes()
        {
            return Err(PortFailure::failed(
                "provider_replay_input_mismatch",
                "frozen normalized parser input differs from the retained redacted response",
            ));
        }
        let expected_intent =
            self.expected_intent_from_prompt(&request.replay_capsule.rendered_prompt_bytes)?;
        let parsed_intent = self.parse_intent(normalized_json, &expected_intent)?;
        ProviderReplayRecord {
            request_digest: request.request_digest.clone(),
            network_used: false,
            parsed_intent,
            parser_digest: request.expected_parser_digest.clone(),
            replay_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .map_err(port_failure)
    }
}

struct ActualM1CandidatePort {
    root: PathBuf,
    suite: ValidationSuite,
    mutation_gate: Mutex<()>,
}

impl ActualM1CandidatePort {
    fn open(root: impl AsRef<Path>, suite: ValidationSuite) -> Result<Self, M5RuntimeError> {
        suite
            .validate()
            .map_err(|error| M5RuntimeError::InvalidConfig(error.to_string()))?;
        Ok(Self {
            root: secure_create_root(root.as_ref())?,
            suite,
            mutation_gate: Mutex::new(()),
        })
    }

    fn persist_record(&self, record: &ProvingRecord) -> Result<(), M5RuntimeError> {
        let bytes = serde_json::to_vec_pretty(record)?;
        persist_immutable(
            &self.root,
            &self
                .root
                .join(format!("{}.json", record.record_digest.file_stem())),
            &bytes,
        )
    }

    fn load_record(
        &self,
        expected_digest: &ContentDigest,
    ) -> Result<ProvingRecord, M5RuntimeError> {
        let path = self
            .root
            .join(format!("{}.json", expected_digest.file_stem()));
        let record: ProvingRecord = read_json_bounded(&path, MAX_RUNTIME_STATE_BYTES)?;
        validate_proving_record(&self.suite, &record)
            .map_err(|error| M5RuntimeError::Integrity(error.to_string()))?;
        require_digest(
            "M5 proving record lookup",
            expected_digest,
            &record.record_digest,
        )?;
        Ok(record)
    }
}

impl M1CandidatePort for ActualM1CandidatePort {
    fn build_and_prove(&self, request: &M1BuildRequest) -> Result<M1BuildEvidence, PortFailure> {
        let _guard = self
            .mutation_gate
            .lock()
            .map_err(|_| PortFailure::failed("m1_lock_poisoned", "M1 proving lock is poisoned"))?;
        if ContentDigest::from_bytes(&request.component_bytes) != request.component_digest {
            return Err(PortFailure::failed(
                "m1_component_digest_mismatch",
                "candidate request digest does not match the exact component bytes",
            ));
        }
        if request.stable_interface_digest
            != StableInterfaceContract::reference()
                .contract_digest()
                .map_err(port_failure)?
        {
            return Err(PortFailure::failed(
                "m1_interface_mismatch",
                "candidate does not name the stable reference interface",
            ));
        }
        let record =
            prove_component_i32(&self.suite, &request.component_bytes).map_err(port_failure)?;
        self.persist_record(&record).map_err(port_failure)?;
        let runnable = record.results.iter().all(|result| result.trace().is_some());
        M1BuildEvidence {
            request_digest: request.request_digest.clone(),
            component_digest: record.component_digest,
            stable_interface_digest: request.stable_interface_digest.clone(),
            observed_export: self.suite.export_name.clone(),
            runnable,
            proving_record_digest: record.record_digest,
            evidence_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .map_err(port_failure)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageRecipeBinding {
    package_digest: ContentDigest,
    component_digest: ContentDigest,
    wat_digest: ContentDigest,
    binding_digest: ContentDigest,
}

impl PackageRecipeBinding {
    fn new(package: &FactoryPackage, wat_digest: ContentDigest) -> Result<Self, M5RuntimeError> {
        let mut binding = Self {
            package_digest: package.package_digest.clone(),
            component_digest: package.payload.genome.component_digest.clone(),
            wat_digest,
            binding_digest: ContentDigest::from_bytes(&[]),
        };
        binding.binding_digest = binding.expected_digest()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), M5RuntimeError> {
        require_digest(
            "M5 package recipe binding",
            &self.binding_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5RuntimeError> {
        Ok(digest_json_content(&(
            "wasm-biotic:m5-package-recipe-binding:v1",
            &self.package_digest,
            &self.component_digest,
            &self.wat_digest,
        ))?)
    }
}

struct ActualM4WorkerPort {
    component_recipes_root: PathBuf,
    package_bindings_root: PathBuf,
    workflow_runs_root: PathBuf,
    workflow_evidence_root: PathBuf,
    template_root: PathBuf,
    factory_id: String,
    scope_id: String,
    worker_max_concurrency: usize,
    suite: ValidationSuite,
    logical_clock: AtomicU64,
    mutation_gate: Mutex<()>,
}

#[derive(Clone)]
struct M5M2CaptureClock {
    now_ms: Arc<AtomicU64>,
}

impl M5M2CaptureClock {
    fn new(now_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            now_ms: Arc::new(AtomicU64::new(now_ms)),
        })
    }

    fn set(&self, now_ms: u64) {
        self.now_ms.store(now_ms, Ordering::Release);
    }
}

impl SupervisorClock for M5M2CaptureClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::Acquire)
    }
}

impl ActualM4WorkerPort {
    fn open(
        root: impl AsRef<Path>,
        template_root: impl AsRef<Path>,
        factory_id: impl Into<String>,
        scope_id: impl Into<String>,
        worker_max_concurrency: usize,
        suite: ValidationSuite,
    ) -> Result<Self, M5RuntimeError> {
        let root = secure_create_root(root.as_ref())?;
        let component_recipes_root = secure_child_directory(&root, "components")?;
        let package_bindings_root = secure_child_directory(&root, "packages")?;
        let workflow_runs_root = secure_child_directory(&root, "workflow-runs")?;
        let workflow_evidence_root = secure_child_directory(&root, "workflow-evidence")?;
        Ok(Self {
            component_recipes_root,
            package_bindings_root,
            workflow_runs_root,
            workflow_evidence_root,
            template_root: fs::canonicalize(template_root.as_ref())
                .map_err(|error| M5RuntimeError::io(template_root.as_ref(), error))?,
            factory_id: factory_id.into(),
            scope_id: scope_id.into(),
            worker_max_concurrency,
            suite,
            logical_clock: AtomicU64::new(1_000),
            mutation_gate: Mutex::new(()),
        })
    }

    fn register_component_recipe(
        &self,
        expected_component_bytes: &[u8],
        wat_bytes: &[u8],
    ) -> Result<ContentDigest, M5RuntimeError> {
        if wat_bytes.is_empty() || wat_bytes.len() > MAX_RECIPE_BYTES {
            return Err(M5RuntimeError::ResourceBound(
                "WAT recipe is outside the bounded source envelope".to_string(),
            ));
        }
        let compiled = wat::parse_bytes(wat_bytes)
            .map_err(|error| M5RuntimeError::InvalidRecipe(error.to_string()))?
            .into_owned();
        if compiled != expected_component_bytes {
            return Err(M5RuntimeError::Integrity(
                "registered WAT does not compile to the exact named component bytes".to_string(),
            ));
        }
        let component_digest = ContentDigest::from_bytes(expected_component_bytes);
        let path = self
            .component_recipes_root
            .join(format!("{}.wat", component_digest.file_stem()));
        persist_immutable(&self.component_recipes_root, &path, wat_bytes)?;
        Ok(component_digest)
    }

    fn register_package_recipe(
        &self,
        package: &FactoryPackage,
        wat_bytes: &[u8],
    ) -> Result<(), M5RuntimeError> {
        let _guard = self
            .mutation_gate
            .lock()
            .map_err(|_| M5RuntimeError::LockPoisoned)?;
        package.validate()?;
        let component_digest =
            self.register_component_recipe(&package.payload.genome.component_bytes, wat_bytes)?;
        if component_digest != package.payload.genome.component_digest {
            return Err(M5RuntimeError::Integrity(
                "package component identity differs from its registered recipe".to_string(),
            ));
        }
        let binding = PackageRecipeBinding::new(package, ContentDigest::from_bytes(wat_bytes))?;
        let path = self
            .package_bindings_root
            .join(format!("{}.json", package.package_digest.file_stem()));
        persist_immutable(
            &self.package_bindings_root,
            &path,
            &serde_json::to_vec_pretty(&binding)?,
        )
    }

    fn recipe_for_component(
        &self,
        component_digest: &ContentDigest,
    ) -> Result<Vec<u8>, M5RuntimeError> {
        let path = self
            .component_recipes_root
            .join(format!("{}.wat", component_digest.file_stem()));
        let wat_bytes = read_regular_bounded(&path, MAX_RECIPE_BYTES)?;
        let compiled = wat::parse_bytes(&wat_bytes)
            .map_err(|error| M5RuntimeError::InvalidRecipe(error.to_string()))?
            .into_owned();
        require_digest(
            "M5 compiled component recipe",
            component_digest,
            &ContentDigest::from_bytes(&compiled),
        )?;
        Ok(wat_bytes)
    }

    fn recipe_for_package(
        &self,
        package_digest: &ContentDigest,
    ) -> Result<Vec<u8>, M5RuntimeError> {
        let path = self
            .package_bindings_root
            .join(format!("{}.json", package_digest.file_stem()));
        let binding: PackageRecipeBinding = read_json_bounded(&path, MAX_RECIPE_BYTES)?;
        binding.validate()?;
        require_digest(
            "M5 package recipe identity",
            package_digest,
            &binding.package_digest,
        )?;
        let wat = self.recipe_for_component(&binding.component_digest)?;
        require_digest(
            "M5 package WAT recipe",
            &binding.wat_digest,
            &ContentDigest::from_bytes(&wat),
        )?;
        Ok(wat)
    }

    fn recipe_for_exported_package(
        &self,
        package: &FactoryPackage,
    ) -> Result<Vec<u8>, M5RuntimeError> {
        if package.payload.generation != 0 {
            return self.recipe_for_package(&package.package_digest);
        }
        let wat = read_regular_bounded(
            &self.template_root.join(TEMPLATE_WAT_FILE),
            MAX_RECIPE_BYTES,
        )?;
        let compiled = wat::parse_bytes(&wat)
            .map_err(|error| M5RuntimeError::InvalidRecipe(error.to_string()))?
            .into_owned();
        if compiled != package.payload.genome.component_bytes {
            return Err(M5RuntimeError::Integrity(
                "frozen generation-zero WAT does not compile to its exact package component"
                    .to_string(),
            ));
        }
        Ok(wat)
    }

    fn persist_workflow_evidence(
        &self,
        evidence: crate::m4_runtime::M4ReferenceWorkflowEvidence,
        service_receipts: Vec<crate::capability_services::InvocationReceipt>,
        service_attestations: Vec<crate::capability_services::ServiceInvocationAttestation>,
    ) -> Result<crate::m4_runtime::M4ReferenceWorkflowEvidence, M5RuntimeError> {
        let record = M5StoredM4WorkflowEvidenceV1::new(
            evidence,
            self.suite.clone(),
            service_receipts,
            service_attestations,
        )?;
        let path = self.workflow_evidence_root.join(format!(
            "{}.json",
            record.governance_context_digest().file_stem()
        ));
        persist_immutable(
            &self.workflow_evidence_root,
            &path,
            &serde_json::to_vec_pretty(&record)?,
        )?;
        let loaded = self.load_workflow_evidence(record.governance_context_digest())?;
        if loaded != record {
            return Err(M5RuntimeError::Integrity(
                "persisted M4 workflow evidence changed during immutable reopen".to_string(),
            ));
        }
        Ok(record.evidence().clone())
    }

    fn load_workflow_evidence(
        &self,
        governance_context_digest: &ContentDigest,
    ) -> Result<M5StoredM4WorkflowEvidenceV1, M5RuntimeError> {
        let path = self
            .workflow_evidence_root
            .join(format!("{}.json", governance_context_digest.file_stem()));
        let record: M5StoredM4WorkflowEvidenceV1 =
            read_json_bounded(&path, MAX_STORED_M4_WORKFLOW_BYTES)?;
        record.validate()?;
        require_digest(
            "M5 M4 workflow lookup",
            governance_context_digest,
            record.governance_context_digest(),
        )?;
        Ok(record)
    }

    fn locate_workflow_run_for_lifecycle_anchor(
        &self,
        m4_lifecycle_job_id: &str,
        m4_lifecycle_terminal_job_digest: &ContentDigest,
    ) -> Result<(PathBuf, SupervisorState, String), M5RuntimeError> {
        validate_identifier("M4 lifecycle job_id", m4_lifecycle_job_id)?;
        let mut run_roots = fs::read_dir(&self.workflow_runs_root)
            .map_err(|error| M5RuntimeError::io(&self.workflow_runs_root, error))?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|error| M5RuntimeError::io(&self.workflow_runs_root, error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if run_roots.len() > MAX_M5_M4_WORKFLOW_RUNS {
            return Err(M5RuntimeError::ResourceBound(format!(
                "M4 workflow-run count {} exceeds {}",
                run_roots.len(),
                MAX_M5_M4_WORKFLOW_RUNS
            )));
        }
        run_roots.sort();
        let mut matches = Vec::new();
        for run_root in run_roots {
            let metadata = fs::symlink_metadata(&run_root)
                .map_err(|error| M5RuntimeError::io(&run_root, error))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(M5RuntimeError::UnsafePath(run_root));
            }
            let canonical = fs::canonicalize(&run_root)
                .map_err(|error| M5RuntimeError::io(&run_root, error))?;
            if canonical.parent() != Some(self.workflow_runs_root.as_path()) {
                return Err(M5RuntimeError::UnsafePath(run_root));
            }
            let state_path = canonical.join("m2-supervisor/supervisor-state.json");
            if !state_path.exists() {
                continue;
            }
            let state: SupervisorState = read_json_bounded(&state_path, MAX_RUNTIME_STATE_BYTES)?;
            let Some(anchor_job) = state.jobs.get(m4_lifecycle_job_id) else {
                continue;
            };
            if anchor_job.phase != JobPhase::Succeeded
                || anchor_job.terminal_outcome.is_none()
                || digest_json_content(anchor_job)? != *m4_lifecycle_terminal_job_digest
            {
                return Err(M5RuntimeError::Integrity(format!(
                    "M4 lifecycle anchor '{m4_lifecycle_job_id}' differs in its live workflow supervisor"
                )));
            }
            let lifecycle: M1LifecycleJob = serde_json::from_str(&anchor_job.payload_json)?;
            let M1LifecycleJob::OpenWorkspace(payload) = lifecycle else {
                return Err(M5RuntimeError::Integrity(format!(
                    "M4 lifecycle anchor '{m4_lifecycle_job_id}' is not the closed OpenWorkspace stage"
                )));
            };
            matches.push((canonical, state, payload.workspace_id));
        }
        if matches.len() != 1 {
            return Err(M5RuntimeError::Integrity(format!(
                "expected exactly one isolated M4 supervisor with lifecycle anchor '{m4_lifecycle_job_id}', found {}",
                matches.len()
            )));
        }
        Ok(matches.pop().expect("one checked M4 workflow root"))
    }

    fn capture_post_export_restart(
        &self,
        binding: &M5M2PostExportJobBindingV2,
        m4_lifecycle_job_id: &str,
    ) -> Result<M5M2PostExportRestartCaptureV2, M5RuntimeError> {
        let _guard = self
            .mutation_gate
            .lock()
            .map_err(|_| M5RuntimeError::LockPoisoned)?;
        let (run_root, initial_state, workspace_id) = self
            .locate_workflow_run_for_lifecycle_anchor(
                m4_lifecycle_job_id,
                binding.m4_lifecycle_terminal_job_digest(),
            )?;
        let job_id = binding.job_id();
        let idempotency_key = binding.idempotency_key();
        if initial_state.jobs.contains_key(&job_id)
            || initial_state
                .idempotency_index
                .contains_key(&idempotency_key)
        {
            return Err(M5RuntimeError::Conflict(
                "this proof-run post-export restart job already exists".to_string(),
            ));
        }
        let base_ms = initial_state.updated_at_ms.checked_add(1).ok_or_else(|| {
            M5RuntimeError::ResourceBound("M2 supervisor clock is exhausted".to_string())
        })?;
        let due_ms = base_ms.checked_add(10).ok_or_else(|| {
            M5RuntimeError::ResourceBound("M2 supervisor clock is exhausted".to_string())
        })?;
        let deadline_at_ms = due_ms.checked_add(10_000).ok_or_else(|| {
            M5RuntimeError::ResourceBound("M2 supervisor deadline is exhausted".to_string())
        })?;
        let clock = M5M2CaptureClock::new(base_ms);
        let suffix = binding
            .challenge_digest(m4_lifecycle_job_id, &workspace_id)?
            .file_stem()
            .chars()
            .skip("sha256-".len())
            .take(24)
            .collect::<String>();
        let config = |owner_id: String| M2RuntimeConfig {
            supervisor_root: run_root.join("m2-supervisor"),
            lifecycle_root: run_root.join("m2-lifecycle"),
            template_root: self.template_root.clone(),
            owner_id,
            max_idle_wait_ms: 10,
        };
        let before_runtime =
            M2Runtime::with_clock(config(format!("m7-m2-before-{suffix}")), clock.clone())?;
        before_runtime.start()?;
        let submitted = before_runtime.submit(M2SubmitJobRequest {
            job_id: job_id.clone(),
            idempotency_key,
            not_before_ms: due_ms,
            deadline_at_ms,
            retry_policy: RetryPolicy::default(),
            lifecycle: M1LifecycleJob::OpenWorkspace(OpenWorkspacePayload {
                workspace_id: workspace_id.clone(),
            }),
        })?;
        if !submitted.created || submitted.job.job_kind != M1_OPEN_WORKSPACE_JOB_KIND {
            let _ = before_runtime.stop();
            return Err(M5RuntimeError::Conflict(
                "post-export restart job was not freshly submitted through the closed M1 catalog"
                    .to_string(),
            ));
        }
        before_runtime.stop()?;
        let state_path = run_root.join("m2-supervisor/supervisor-state.json");
        let pre_restart_supervisor_state_bytes =
            read_regular_bounded(&state_path, MAX_RUNTIME_STATE_BYTES)?;

        clock.set(due_ms);
        let after_runtime = M2Runtime::with_clock(config(format!("m7-m2-after-{suffix}")), clock)?;
        after_runtime.start()?;
        let mut completed = None;
        for _ in 0..500 {
            if let Some(job) = after_runtime.job(&job_id)?
                && job.phase.is_terminal()
            {
                completed = Some(job);
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        let completion_ok = completed
            .as_ref()
            .is_some_and(|job| job.phase == JobPhase::Succeeded && job.terminal_outcome.is_some());
        after_runtime.stop()?;
        if !completion_ok {
            return Err(M5RuntimeError::Execution(
                "post-export OpenWorkspace did not complete after distinct-owner restart"
                    .to_string(),
            ));
        }
        let post_restart_supervisor_state_bytes =
            read_regular_bounded(&state_path, MAX_RUNTIME_STATE_BYTES)?;
        M5M2PostExportRestartCaptureV2::from_canonical_state_bytes(
            binding.clone(),
            m4_lifecycle_job_id,
            pre_restart_supervisor_state_bytes,
            post_restart_supervisor_state_bytes,
        )
    }

    fn with_validated_live_post_export_capture<T>(
        &self,
        capture: &M5M2PostExportRestartCaptureV2,
        action: impl FnOnce() -> Result<T, M5RuntimeError>,
    ) -> Result<T, M5RuntimeError> {
        let _guard = self
            .mutation_gate
            .lock()
            .map_err(|_| M5RuntimeError::LockPoisoned)?;
        capture.validate()?;
        let (run_root, current_state, _) = self.locate_workflow_run_for_lifecycle_anchor(
            capture.m4_lifecycle_job_id(),
            capture.binding().m4_lifecycle_terminal_job_digest(),
        )?;
        let state_path = run_root.join("m2-supervisor/supervisor-state.json");
        let current_bytes = read_regular_bounded(&state_path, MAX_RUNTIME_STATE_BYTES)?;
        if current_bytes != capture.post_restart_supervisor_state_bytes
            || serde_json::to_vec_pretty(&current_state)? != current_bytes
        {
            return Err(M5RuntimeError::Conflict(
                "post-export M2 capture is not the exact current isolated supervisor state"
                    .to_string(),
            ));
        }
        // Keep the worker mutation gate held until the causally challenged M3
        // invocation has durably completed. This closes the live-C2 check/use
        // interval even for callers holding the separately exposed M4 handle.
        action()
    }

    fn run_actual_workflow(
        &self,
        workflow_id: String,
        wat_bytes: Vec<u8>,
        governance_context_digest: ContentDigest,
    ) -> Result<crate::m4_runtime::M4ReferenceWorkflowEvidence, M5RuntimeError> {
        let run_digest = digest_json_content(&(
            "wasm-biotic:m5-isolated-m4-workflow-run:v1",
            &workflow_id,
            &governance_context_digest,
            ContentDigest::from_bytes(&wat_bytes),
        ))?;
        let run_root = secure_child_directory(&self.workflow_runs_root, &run_digest.file_stem())?;
        let suffix = run_digest
            .file_stem()
            .chars()
            .skip("sha256-".len())
            .take(24)
            .collect::<String>();
        let m2 = Arc::new(M2Runtime::new(M2RuntimeConfig {
            supervisor_root: run_root.join("m2-supervisor"),
            lifecycle_root: run_root.join("m2-lifecycle"),
            template_root: self.template_root.clone(),
            owner_id: format!("m5-m4-{suffix}"),
            max_idle_wait_ms: 50,
        })?);
        m2.start()?;
        let m3 = Arc::new(M3CapabilityRuntime::open(
            M3RuntimeConfig::new(
                run_root.join("m3-runtime"),
                &self.template_root,
                self.scope_id.clone(),
                format!("m5-m4-{suffix}"),
            ),
            Arc::clone(&m2),
        )?);
        let runtime = M4Runtime::open(
            M4RuntimeConfig {
                root: run_root.join("m4-runtime"),
                factory_id: self.factory_id.clone(),
                worker_max_concurrency: self.worker_max_concurrency,
            },
            Arc::clone(&m3),
        )?;
        let start_tick = self.logical_clock.fetch_add(1_000, Ordering::Relaxed);
        runtime.ensure_reference_workers(start_tick)?;
        let request = M4ReferenceWorkflowRequest {
            workflow_id,
            governance_context_digest,
            objective: "build, prove, review, package, and preserve the exact bounded M5 component"
                .to_string(),
            replacement_wat_bytes: wat_bytes,
            validation_suite: self.suite.clone(),
            budget: WorkBudget {
                max_attempts: 3,
                max_capability_calls: 16,
                max_input_bytes: 2 * 1024 * 1024,
                max_output_bytes: 2 * 1024 * 1024,
                max_runtime_ticks: 500,
            },
            deadline: WorkDeadline {
                not_before_tick: start_tick,
                expires_at_tick: start_tick.saturating_add(900),
            },
        };
        let workflow_request_digest = digest_json_content(&(
            "wasm-biotic:m4-reference-request:v2",
            &request.workflow_id,
            &request.objective,
            &request.governance_context_digest,
            ContentDigest::from_bytes(&request.replacement_wat_bytes),
            &request.validation_suite,
            &request.budget,
            &request.deadline,
        ))?;
        let workflow_suffix = {
            let value = workflow_request_digest.as_str();
            value[value.len().saturating_sub(24)..].to_string()
        };
        let result = runtime
            .prepare_reference_workflow(&request)
            .and_then(|spec| runtime.run_reference_workflow(spec, start_tick));
        let evidence = match result {
            Ok(evidence) => evidence,
            Err(error) => {
                let m3_stop = m3.stop();
                let m2_stop = m2.stop();
                m3_stop?;
                m2_stop?;
                return Err(error.into());
            }
        };
        let operations_invocation_id = format!("m4-{workflow_suffix}-inspect-terminal-operations");
        let operations_invocation = CapabilityInvocation {
            identity: InvocationIdentity {
                invocation_id: operations_invocation_id.clone(),
                idempotency_key: format!("idempotency:{operations_invocation_id}"),
                service_id: OPERATIONS_INSPECT_SERVICE_ID.to_string(),
                scope_id: m3.config().scope_id.clone(),
                caller_id: format!("m5-m4:{}", self.factory_id),
                authority: AuthorityClass::Observe,
                approval: InvocationApproval::Automatic,
            },
            budget: InvocationBudget::bounded(30_000),
            request: CapabilityRequest::InspectOperations(InspectOperationsRequest {
                deployment: ScopedDeploymentRef {
                    scope_id: m3.config().scope_id.clone(),
                    deployment_id: m3.config().deployment_id.clone(),
                },
            }),
        };
        let operations_record =
            m3.inspect_operations(&operations_invocation, ServiceCancellationToken::new())?;
        if operations_record.inspection_invocation_id != operations_invocation_id {
            return Err(M5RuntimeError::Integrity(
                "terminal M4 operations inspection persisted under a different invocation identity"
                    .to_string(),
            ));
        }
        let mut service_invocation_ids = vec![
            operations_invocation_id,
            format!("m4-{workflow_suffix}-preflight-open-incumbent"),
            format!("m4-{workflow_suffix}-preflight-open-candidate"),
            format!("m4-{workflow_suffix}-preflight-build-incumbent"),
            format!("m4-{workflow_suffix}-preflight-package-incumbent"),
            format!("m4-{workflow_suffix}-preflight-prove-incumbent"),
            format!("m4-{workflow_suffix}-schedule-anchor"),
            format!("m4-{workflow_suffix}-publish-planner-context"),
        ];
        service_invocation_ids.extend(
            evidence
                .executions
                .iter()
                .flat_map(|execution| execution.service_attestations.iter())
                .map(|attestation| attestation.invocation_id.clone()),
        );
        service_invocation_ids.sort();
        let original_count = service_invocation_ids.len();
        service_invocation_ids.dedup();
        if service_invocation_ids.len() != original_count {
            return Err(M5RuntimeError::Integrity(
                "M4 workflow reused a native-service invocation identity".to_string(),
            ));
        }
        let service_receipts = service_invocation_ids
            .iter()
            .map(|invocation_id| m3.receipt(invocation_id))
            .collect::<Result<Vec<_>, _>>()?;
        let service_attestations = service_invocation_ids
            .iter()
            .map(|invocation_id| m3.attestation(invocation_id))
            .collect::<Result<Vec<_>, _>>()?;
        let m3_stop = m3.stop();
        let m2_stop = m2.stop();
        m3_stop?;
        m2_stop?;
        self.persist_workflow_evidence(evidence, service_receipts, service_attestations)
    }
}

impl M4WorkerPort for ActualM4WorkerPort {
    fn execute_workflow(
        &self,
        request: &WorkerWorkflowRequest,
    ) -> Result<WorkerWorkflowEvidence, PortFailure> {
        let wat = self
            .recipe_for_package(&request.challenger_package_digest)
            .map_err(port_failure)?;
        let evidence = self
            .run_actual_workflow(
                format!("m5-cycle-{}", sanitize_id(&request.cycle_id)),
                wat,
                request.request_digest.clone(),
            )
            .map_err(port_failure)?;
        if evidence.governance_context_digest != request.request_digest
            || evidence.executions.len() != request.required_roles.len()
            || evidence.worker.result_digests.len() != request.required_roles.len()
        {
            return Err(PortFailure::failed(
                "m4_worker_governance_mismatch",
                "real M4 workflow did not preserve its exact governance context and one durable result per required role",
            ));
        }
        let actual = evidence
            .executions
            .iter()
            .map(|execution| (worker_role(execution.role), execution))
            .collect::<BTreeMap<_, _>>();
        let receipts = request
            .required_roles
            .iter()
            .map(|role| {
                let execution = actual.get(role).ok_or_else(|| {
                    PortFailure::failed(
                        "m4_worker_role_missing",
                        format!("real M4 workflow omitted required role {role:?}"),
                    )
                })?;
                if execution.governance_context_digest != request.request_digest
                    || execution.service_attestations.is_empty()
                    || execution
                        .service_attestations
                        .iter()
                        .any(|attestation| !attestation.terminal_success)
                {
                    return Err(PortFailure::failed(
                        "m4_worker_attestation_invalid",
                        format!(
                            "M4 role {role:?} lacks exact-context successful native-service attestations"
                        ),
                    ));
                }
                Ok(WorkerReceipt {
                    role: *role,
                    execution_id: execution.execution_id.clone(),
                    terminal_status: WorkerTerminalStatus::Succeeded,
                    input_digest: request.request_digest.clone(),
                    output_digest: Some(execution.worker_result_digest.clone()),
                })
            })
            .collect::<Result<Vec<_>, PortFailure>>()?;
        WorkerWorkflowEvidence {
            request_digest: request.request_digest.clone(),
            challenger_package_digest: request.challenger_package_digest.clone(),
            receipts,
            evidence_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .map_err(port_failure)
    }

    fn materialize_generation(
        &self,
        request: &GenerationMaterializationRequest,
    ) -> Result<GenerationMaterializationEvidence, PortFailure> {
        let wat = render_reference_delta_v1(request.directive).map_err(port_failure)?;
        let component = wat::parse_bytes(&wat)
            .map_err(|error| {
                PortFailure::failed(
                    "m4_generation_compile_failed",
                    format!("canonical generated WAT did not compile: {error}"),
                )
            })?
            .into_owned();
        if component.len() as u64 > request.maximum_component_bytes {
            return Err(PortFailure::failed(
                "m4_generation_component_budget_exceeded",
                "canonical generated component exceeds the declared byte budget",
            ));
        }
        let evidence = self
            .run_actual_workflow(
                format!("m5-generation-step-{}", sanitize_id(&request.cycle_id)),
                wat.clone(),
                request.request_digest.clone(),
            )
            .map_err(port_failure)?;
        let required_roles = required_worker_roles();
        if evidence.governance_context_digest != request.request_digest
            || evidence.executions.len() != required_roles.len()
        {
            return Err(PortFailure::failed(
                "m4_generation_governance_mismatch",
                "generation workflow did not preserve its exact governance context and six-role execution",
            ));
        }
        let actual = evidence
            .executions
            .iter()
            .map(|execution| (worker_role(execution.role), execution))
            .collect::<BTreeMap<_, _>>();
        let worker_receipts = required_roles
            .iter()
            .map(|role| {
                let execution = actual.get(role).ok_or_else(|| {
                    PortFailure::failed(
                        "m4_generation_worker_role_missing",
                        format!("generation workflow omitted required role {role:?}"),
                    )
                })?;
                if execution.governance_context_digest != request.request_digest
                    || execution.service_attestations.is_empty()
                    || execution
                        .service_attestations
                        .iter()
                        .any(|attestation| !attestation.terminal_success)
                {
                    return Err(PortFailure::failed(
                        "m4_generation_worker_attestation_invalid",
                        format!(
                            "generation role {role:?} lacks exact-context successful service attestations"
                        ),
                    ));
                }
                Ok(WorkerReceipt {
                    role: *role,
                    execution_id: execution.execution_id.clone(),
                    terminal_status: WorkerTerminalStatus::Succeeded,
                    input_digest: request.request_digest.clone(),
                    output_digest: Some(execution.worker_result_digest.clone()),
                })
            })
            .collect::<Result<Vec<_>, PortFailure>>()?;
        self.register_component_recipe(&component, &wat)
            .map_err(port_failure)?;
        let workflow_evidence_digest = digest_json_content(&(
            "wasm-biotic:m5-generation-m4-workflow-evidence:v1",
            &evidence,
        ))
        .map_err(port_failure)?;
        GenerationMaterializationEvidence {
            request_digest: request.request_digest.clone(),
            driver_evidence_digest: request.driver_evidence_digest.clone(),
            rendered_wat_digest: ContentDigest::from_bytes(&wat),
            rendered_wat_bytes: wat,
            successor_component_digest: ContentDigest::from_bytes(&component),
            successor_component_bytes: component,
            workflow_id: evidence.worker.workflow_id,
            worker_receipts,
            workflow_evidence_digest,
            evidence_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .map_err(port_failure)
    }
}

fn worker_role(role: GovernedWorkerRole) -> WorkerRole {
    match role {
        GovernedWorkerRole::Planner => WorkerRole::Planner,
        GovernedWorkerRole::Builder => WorkerRole::Builder,
        GovernedWorkerRole::Validator => WorkerRole::Validator,
        GovernedWorkerRole::Reviewer => WorkerRole::Reviewer,
        GovernedWorkerRole::Packager => WorkerRole::Packager,
        GovernedWorkerRole::ContinuityWorker => WorkerRole::Continuity,
    }
}

fn required_worker_roles() -> [WorkerRole; 6] {
    [
        WorkerRole::Planner,
        WorkerRole::Builder,
        WorkerRole::Validator,
        WorkerRole::Reviewer,
        WorkerRole::Packager,
        WorkerRole::Continuity,
    ]
}

/// Bounded production facade over the durable reproduction engine and its real
/// M1--M4 adapters.
pub struct M5Runtime {
    manifest: M5RuntimeManifest,
    m2: Arc<M2Runtime>,
    m3: Arc<M3CapabilityRuntime>,
    m4: Arc<M4Runtime>,
    m1_candidate: Arc<ActualM1CandidatePort>,
    approval: Arc<M5SupervisorAdapter>,
    capability: Arc<M5EffectCapabilityPort>,
    provider_bindings: Arc<ProviderCandidateBindingStore>,
    workers: Arc<ActualM4WorkerPort>,
    governed_live_provider_configuration_fingerprint: Option<ContentDigest>,
    operation_gate: Mutex<()>,
    engine: Mutex<FactoryReproductionEngine>,
    // Declared last so every mutable child is dropped before root ownership.
    _owner_lock: File,
}

impl M5Runtime {
    /// Initialize a generation-zero factory from one frozen reference WAT.
    pub fn initialize(
        config: M5RuntimeConfig,
        incumbent_wat_bytes: Vec<u8>,
        validation_suite: ValidationSuite,
        release_gate: ReleaseGate,
        initial_state_schema: u32,
        initialization_authority: M5InitializationAuthority,
        live_provider: Option<Arc<dyn LiveProviderQualificationPort>>,
    ) -> Result<Self, M5RuntimeError> {
        config.validate()?;
        initialization_authority.validate()?;
        if initial_state_schema == 0 {
            return Err(M5RuntimeError::InvalidConfig(
                "initial state schema must be non-zero".to_string(),
            ));
        }
        validate_suite_matches_gate(&validation_suite, &release_gate)?;
        let root = secure_create_root(&config.root)?;
        let owner_lock = acquire_m5_owner_lock(&root)?;
        let manifest_path = root.join(MANIFEST_FILE);
        if manifest_path.exists() {
            return Err(M5RuntimeError::AlreadyInitialized);
        }
        let incumbent_component = compile_wat(&incumbent_wat_bytes)?;
        let state_compatibility = StateCompatibility {
            readable_schema_min: initial_state_schema,
            readable_schema_max: initial_state_schema.saturating_add(1),
            written_schema: initial_state_schema,
            incumbent_rollback_readable_through: initial_state_schema.saturating_add(1),
        };
        state_compatibility.validate()?;
        let max_canary_tasks = release_gate
            .thresholds
            .minimum_post_activation_successes
            .max(u32::try_from(release_gate.benchmarks.len()).unwrap_or(u32::MAX));
        let incumbent = FactoryPackage::build(
            config.factory_id.clone(),
            0,
            MutableGenome::new(
                None,
                incumbent_component,
                MutableFactoryPolicy::terminal(1, max_canary_tasks),
            )?,
            StableInterfaceContract::reference(),
            WorkerCatalog::reference()?,
            ServiceDependencyCatalog::reference()?,
            state_compatibility,
        )?;
        let manifest = M5RuntimeManifest::new(
            M5RuntimeConfig {
                root: root.clone(),
                ..config
            },
            validation_suite,
            release_gate,
            &incumbent_wat_bytes,
        )?;
        let journal_path = root.join(INITIALIZATION_JOURNAL_FILE);
        let mut journal = M5InitializationJournal::new(
            manifest.clone(),
            incumbent.clone(),
            initialization_authority,
        )?;
        if journal_path.exists() {
            let existing: M5InitializationJournal =
                read_json_bounded(&journal_path, MAX_RUNTIME_STATE_BYTES)?;
            existing.validate()?;
            if existing.manifest != journal.manifest
                || existing.incumbent != journal.incumbent
                || existing.initial_state_bytes != journal.initial_state_bytes
                || existing.initialization_authority != journal.initialization_authority
            {
                return Err(M5RuntimeError::Conflict(
                    "existing M5 initialization intent differs from the requested exact inputs"
                        .to_string(),
                ));
            }
            journal = existing;
        } else {
            write_json_atomic(&root, &journal_path, &journal)?;
        }
        // The exact initialization intent must exist before the first template
        // or mutable child-store byte is published.
        let template_root = secure_child_directory(&root, TEMPLATE_DIRECTORY)?;
        persist_immutable(
            &template_root,
            &template_root.join(TEMPLATE_WAT_FILE),
            &incumbent_wat_bytes,
        )?;
        persist_immutable(
            &template_root,
            &template_root.join(TEMPLATE_WIT_FILE),
            crate::factory_reproduction::REFERENCE_WIT.as_bytes(),
        )?;
        let runtime = Self::open_components(
            manifest.clone(),
            Some(&incumbent),
            live_provider,
            Some(&journal.initialization_authority),
            owner_lock,
        )?;
        journal.advance(M5InitializationPhase::ComponentsReconciled)?;
        write_json_atomic(&root, &journal_path, &journal)?;
        write_json_atomic(&root, &manifest_path, &manifest)?;
        journal.advance(M5InitializationPhase::Complete)?;
        write_json_atomic(&root, &journal_path, &journal)?;
        Ok(runtime)
    }

    pub fn initialize_with_governed_live_provider(
        config: M5RuntimeConfig,
        incumbent_wat_bytes: Vec<u8>,
        validation_suite: ValidationSuite,
        release_gate: ReleaseGate,
        initial_state_schema: u32,
        initialization_authority: M5InitializationAuthority,
        provider: Arc<GovernedLiveProviderPort>,
    ) -> Result<Self, M5RuntimeError> {
        let fingerprint = provider.provider_configuration().fingerprint()?;
        let live_provider: Arc<dyn LiveProviderQualificationPort> = provider;
        let mut runtime = Self::initialize(
            config,
            incumbent_wat_bytes,
            validation_suite,
            release_gate,
            initial_state_schema,
            initialization_authority,
            Some(live_provider),
        )?;
        runtime.governed_live_provider_configuration_fingerprint = Some(fingerprint);
        Ok(runtime)
    }

    /// Reopen durable M2--M5 state and recover any interrupted migration or
    /// activation through the reproduction engine's pending-effect record.
    pub fn open(
        config: M5RuntimeConfig,
        live_provider: Option<Arc<dyn LiveProviderQualificationPort>>,
    ) -> Result<Self, M5RuntimeError> {
        config.validate()?;
        let requested_root = fs::canonicalize(&config.root)
            .map_err(|error| M5RuntimeError::io(&config.root, error))?;
        let owner_lock = acquire_m5_owner_lock(&requested_root)?;
        let manifest_path = requested_root.join(MANIFEST_FILE);
        let journal_path = requested_root.join(INITIALIZATION_JOURNAL_FILE);
        let mut journal = if journal_path.exists() {
            let journal: M5InitializationJournal =
                read_json_bounded(&journal_path, MAX_RUNTIME_STATE_BYTES)?;
            journal.validate()?;
            Some(journal)
        } else {
            None
        };
        let (manifest, incumbent, resuming_initialization) = if manifest_path.exists() {
            let manifest: M5RuntimeManifest =
                read_json_bounded(&manifest_path, MAX_RUNTIME_STATE_BYTES)?;
            if let Some(journal) = &journal
                && journal.manifest != manifest
            {
                return Err(M5RuntimeError::Integrity(
                    "M5 manifest differs from its initialization journal".to_string(),
                ));
            }
            (manifest, None, false)
        } else if let Some(journal) = &journal {
            (
                journal.manifest.clone(),
                Some(journal.incumbent.clone()),
                true,
            )
        } else {
            return Err(M5RuntimeError::NotInitialized);
        };
        manifest.validate()?;
        if manifest.config.root != requested_root
            || manifest.config.factory_id != config.factory_id
            || manifest.config.scope_id != config.scope_id
            || manifest.config.deployment_id != config.deployment_id
            || manifest.config.worker_max_concurrency != config.worker_max_concurrency
        {
            return Err(M5RuntimeError::Conflict(
                "open configuration differs from the durable M5 manifest".to_string(),
            ));
        }
        let incumbent_wat = read_regular_bounded(
            &requested_root
                .join(TEMPLATE_DIRECTORY)
                .join(TEMPLATE_WAT_FILE),
            MAX_RECIPE_BYTES,
        )?;
        require_digest(
            "frozen incumbent WAT",
            &manifest.incumbent_wat_digest,
            &ContentDigest::from_bytes(&incumbent_wat),
        )?;
        let runtime = Self::open_components(
            manifest.clone(),
            incumbent.as_ref(),
            live_provider,
            journal
                .as_ref()
                .filter(|_| resuming_initialization)
                .map(|journal| &journal.initialization_authority),
            owner_lock,
        )?;
        if let Some(journal) = journal.as_mut() {
            if journal.phase != M5InitializationPhase::Complete {
                journal.advance(M5InitializationPhase::ComponentsReconciled)?;
                write_json_atomic(&requested_root, &journal_path, journal)?;
            }
            if resuming_initialization {
                write_json_atomic(&requested_root, &manifest_path, &manifest)?;
            }
            if journal.phase != M5InitializationPhase::Complete {
                journal.advance(M5InitializationPhase::Complete)?;
                write_json_atomic(&requested_root, &journal_path, journal)?;
            }
        } else if resuming_initialization {
            return Err(M5RuntimeError::Integrity(
                "resumed initialization lost its durable journal".to_string(),
            ));
        }
        Ok(runtime)
    }

    pub fn open_with_governed_live_provider(
        config: M5RuntimeConfig,
        provider: Arc<GovernedLiveProviderPort>,
    ) -> Result<Self, M5RuntimeError> {
        let fingerprint = provider.provider_configuration().fingerprint()?;
        let live_provider: Arc<dyn LiveProviderQualificationPort> = provider;
        let mut runtime = Self::open(config, Some(live_provider))?;
        runtime.governed_live_provider_configuration_fingerprint = Some(fingerprint);
        Ok(runtime)
    }

    fn open_components(
        manifest: M5RuntimeManifest,
        incumbent: Option<&FactoryPackage>,
        live_provider: Option<Arc<dyn LiveProviderQualificationPort>>,
        initialization_authority: Option<&M5InitializationAuthority>,
        owner_lock: File,
    ) -> Result<Self, M5RuntimeError> {
        let initializing = initialization_authority.is_some();
        let root = &manifest.config.root;
        let template_root = root.join(TEMPLATE_DIRECTORY);
        let m2 = Arc::new(M2Runtime::new(M2RuntimeConfig {
            supervisor_root: root.join("m2-supervisor"),
            lifecycle_root: root.join("m2-lifecycle"),
            template_root: template_root.clone(),
            owner_id: format!("m5-{}", sanitize_id(&manifest.config.factory_id)),
            max_idle_wait_ms: 50,
        })?);
        let effect_backend = Arc::new(FactoryEffectStore::open(root.join(CAPABILITY_DIRECTORY))?);
        let m3 = Arc::new(M3CapabilityRuntime::open_with_factory_evolution(
            M3RuntimeConfig::new(
                root.join("m3-runtime"),
                &template_root,
                manifest.config.scope_id.clone(),
                manifest.config.deployment_id.clone(),
            ),
            Arc::clone(&m2),
            effect_backend.clone(),
        )?);
        let m4 = Arc::new(M4Runtime::open(
            M4RuntimeConfig {
                root: root.join("m4-runtime"),
                factory_id: manifest.config.factory_id.clone(),
                worker_max_concurrency: manifest.config.worker_max_concurrency,
            },
            Arc::clone(&m3),
        )?);
        let m1_candidate = Arc::new(ActualM1CandidatePort::open(
            root.join(PROVING_DIRECTORY),
            manifest.validation_suite.clone(),
        )?);
        let approval = Arc::new(M5SupervisorAdapter::open(
            root.join(APPROVAL_DIRECTORY),
            format!(
                "m5_{}",
                sanitize_id(&manifest.config.factory_id).replace(':', "_")
            ),
        )?);
        let ledger = Arc::new(M5M3InvocationProofLedger::open(
            M5M3AdapterConfig {
                root: root.join(M3_PROOF_DIRECTORY),
                scope_id: manifest.config.scope_id.clone(),
                factory_id: manifest.config.factory_id.clone(),
                caller_id: format!("m5-runtime:{}", manifest.config.factory_id),
                invocation_timeout_ms: 120_000,
            },
            Arc::clone(&m3),
        )?);
        let capability = Arc::new(M5EffectCapabilityPort::open(
            root.join(CAPABILITY_PORT_DIRECTORY),
            ledger,
            Arc::clone(&approval),
            effect_backend,
        )?);
        let provider_bindings = Arc::new(ProviderCandidateBindingStore::open(
            root.join(PROVIDER_BINDINGS_DIRECTORY),
        )?);
        if initializing {
            let incumbent = incumbent.ok_or_else(|| {
                M5RuntimeError::InvalidConfig(
                    "initialization requires an incumbent package".to_string(),
                )
            })?;
            let initial_state_bytes = serde_json::to_vec(&json!({
                "schema": incumbent.payload.boot_manifest.state_compatibility.written_schema,
                "factory_id": incumbent.payload.factory_id,
                "generation": incumbent.payload.generation,
            }))?;
            let initialize_request = FactoryInitializeRequest::new(
                format!("m5-initialize-{}", manifest.manifest_digest.file_stem()),
                manifest.config.factory_id.clone(),
                incumbent.canonical_bytes()?,
                incumbent
                    .payload
                    .boot_manifest
                    .state_compatibility
                    .written_schema,
                initial_state_bytes,
            )?;
            let initialization_authority = initialization_authority.ok_or_else(|| {
                M5RuntimeError::Integrity(
                    "initialization has no exact journaled operator authority".to_string(),
                )
            })?;
            approval.authorize_initialization(M5InitializationAuthorizationRequest {
                factory_id: manifest.config.factory_id.clone(),
                incumbent_package_bytes: incumbent.canonical_bytes()?,
                incumbent_component_bytes: incumbent.payload.genome.component_bytes.clone(),
                initial_state_schema: initialize_request.initial_state_schema,
                initial_state_bytes_digest: ContentDigest::from_bytes(
                    &initialize_request.initial_state_bytes,
                ),
                manifest_digest: manifest.manifest_digest.clone(),
                operator_ref: initialization_authority.operator_ref.clone(),
                rationale: initialization_authority.rationale.clone(),
            })?;
            let initialization_approval_ref = approval
                .require_and_consume_initialization_authority(M5InitializationExecutionRequest {
                    initialize_request: initialize_request.clone(),
                    incumbent_component_bytes: incumbent.payload.genome.component_bytes.clone(),
                    manifest_digest: manifest.manifest_digest.clone(),
                })?;
            capability.initialize_factory(&initialize_request, &initialization_approval_ref)?;
        }
        let workers = Arc::new(ActualM4WorkerPort::open(
            root.join(RECIPES_DIRECTORY),
            &template_root,
            manifest.config.factory_id.clone(),
            manifest.config.scope_id.clone(),
            manifest.config.worker_max_concurrency,
            manifest.validation_suite.clone(),
        )?);
        if let Some(incumbent) = incumbent {
            let incumbent_wat =
                read_regular_bounded(&template_root.join(TEMPLATE_WAT_FILE), MAX_RECIPE_BYTES)?;
            workers.register_package_recipe(&incumbent, &incumbent_wat)?;
        }
        let ports = ReproductionPorts {
            m1_candidate: m1_candidate.clone(),
            m2_supervisor: approval.clone(),
            m3_capability: capability.clone(),
            m4_workers: workers.clone(),
            live_provider,
        };
        let engine_root = root.join(ENGINE_DIRECTORY);
        let engine_state_exists = engine_root.join("factory-reproduction-state.json").exists();
        let engine = if initializing && !engine_state_exists {
            FactoryReproductionEngine::initialize(
                &engine_root,
                manifest.config.factory_id.clone(),
                incumbent.cloned().ok_or(M5RuntimeError::NotInitialized)?,
                manifest.release_gate.clone(),
                ports,
            )?
        } else {
            FactoryReproductionEngine::open(&engine_root, ports)?
        };
        for binding in provider_bindings.validate_all()? {
            let qualification = engine
                .state()
                .provider_qualifications
                .iter()
                .find(|record| record.record_digest == binding.qualification_record_digest)
                .ok_or_else(|| {
                    M5RuntimeError::Integrity(format!(
                        "provider binding {} has no exact qualification in the reproduction store",
                        binding.binding_digest
                    ))
                })?;
            binding.validate_with_qualification(Some(qualification))?;
            capability.validate_provider_proposal_reference(
                &binding.proposal_evidence.request,
                &binding.proposal_evidence.result,
                &binding.proposal_evidence.m3_reference,
            )?;
        }
        capability.validate_all()?;
        capability.audit_reproduction_state(engine.state())?;
        let active_package = engine.active_package()?;
        let engine_state = engine.state();
        // Opening an existing runtime is reconciliation, not a factory effect.
        // The backend snapshot path reconciles and validates the physical route
        // without appending an M3 inspection proof. Keeping reopen read-only is
        // essential: an exact terminal result must re-derive byte-for-byte
        // before and after process restart.
        let active_effect = capability.backend_snapshot()?.ok_or_else(|| {
            M5RuntimeError::Integrity(
                "factory effect store has no active package after reconciliation".to_string(),
            )
        })?;
        if active_effect.package_digest != active_package.package_digest
            || active_effect.package_bytes_digest
                != ContentDigest::from_bytes(&active_package.canonical_bytes()?)
            || active_effect.component_digest != active_package.payload.genome.component_digest
            || active_effect.generation != engine_state.active_generation
            || active_effect.state_schema != engine_state.active_state_schema
        {
            return Err(M5RuntimeError::Integrity(
                "M5 engine projection differs from the authoritative receipted effect store"
                    .to_string(),
            ));
        }
        m2.start()?;
        Ok(Self {
            manifest,
            m2,
            m3,
            m4,
            m1_candidate,
            approval,
            capability,
            provider_bindings,
            workers,
            governed_live_provider_configuration_fingerprint: None,
            operation_gate: Mutex::new(()),
            engine: Mutex::new(engine),
            _owner_lock: owner_lock,
        })
    }

    pub fn config(&self) -> &M5RuntimeConfig {
        &self.manifest.config
    }

    pub fn validation_suite(&self) -> &ValidationSuite {
        &self.manifest.validation_suite
    }

    pub fn release_gate(&self) -> &ReleaseGate {
        &self.manifest.release_gate
    }

    pub fn m2(&self) -> &Arc<M2Runtime> {
        &self.m2
    }

    pub fn m3(&self) -> &Arc<M3CapabilityRuntime> {
        &self.m3
    }

    pub fn m4(&self) -> &Arc<M4Runtime> {
        &self.m4
    }

    pub fn state_snapshot(
        &self,
    ) -> Result<crate::factory_reproduction::ReproductionState, M5RuntimeError> {
        Ok(self.lock_engine()?.state().clone())
    }

    pub fn active_package(&self) -> Result<FactoryPackage, M5RuntimeError> {
        Ok(self.lock_engine()?.active_package()?)
    }

    /// Capture the exact active effect-store snapshot without requiring the
    /// active package to be exportable as a live adopted successor.
    ///
    /// This is the read-only evidence seam for containment after an operator
    /// rollback. It preserves the normal engine → effect-gate lock order and
    /// cross-checks the authoritative backend snapshot against both the
    /// reproduction projection and a full M3 audit.
    pub fn active_runtime_snapshot(&self) -> Result<FactoryRuntimeSnapshot, M5RuntimeError> {
        let engine = self.lock_engine()?;
        let _effect_guard = self.capability.lock_gate()?;
        let state = engine.state();
        let package = engine.active_package()?;
        let snapshot = self.capability.backend_snapshot()?.ok_or_else(|| {
            M5RuntimeError::Integrity(
                "factory effect store has no active package snapshot".to_string(),
            )
        })?;
        validate_factory_runtime_snapshot(&snapshot)?;
        let audit = self.capability.audit_reproduction_state(state)?;
        if snapshot.package_digest != state.active_package_digest
            || snapshot.package_digest != package.package_digest
            || snapshot.package_bytes_digest
                != ContentDigest::from_bytes(&package.canonical_bytes()?)
            || snapshot.component_digest != package.payload.genome.component_digest
            || snapshot.generation != state.active_generation
            || snapshot.state_schema != state.active_state_schema
            || audit.backend_snapshot_digest != snapshot.snapshot_digest
            || audit.reproduction_state_digest != state.state_digest
        {
            return Err(M5RuntimeError::Integrity(
                "active runtime snapshot differs from the reproduction or M3 effect projection"
                    .to_string(),
            ));
        }
        Ok(snapshot)
    }

    /// Capture the exact currently adopted N+1 state as a transport-neutral,
    /// standalone-verifiable handoff bundle.
    ///
    /// Lock ordering is always reproduction engine → M3 effect gate. The
    /// effect gate is also taken by every M3 invocation, so the audit ledger
    /// and backend CAS facts cannot move while package bytes and recipes are
    /// collected. A second full audit and final backend snapshot comparison
    /// make the race check explicit before returning.
    pub fn export_active_adopted_bundle(&self) -> Result<M5ExportBundleV1, M5RuntimeError> {
        let engine = self.lock_engine()?;
        let _effect_guard = self.capability.lock_gate()?;
        let state = engine.state().clone();
        let initial_snapshot = self.capability.backend_snapshot()?.ok_or_else(|| {
            M5RuntimeError::Integrity(
                "cannot export a factory without an authoritative backend snapshot".to_string(),
            )
        })?;
        let initial_audit = self.capability.audit_reproduction_state(&state)?;
        if initial_audit.backend_snapshot_digest != initial_snapshot.snapshot_digest {
            return Err(M5RuntimeError::Conflict(
                "M3 audit and backend snapshot moved before export capture".to_string(),
            ));
        }

        let mut packages = Vec::with_capacity(state.package_index.len());
        for index in state.package_index.values() {
            let package = engine.package(&index.package_digest)?;
            let recipe = self.workers.recipe_for_exported_package(&package)?;
            packages.push(M5ExportPackageV1::from_live_package(&package, recipe)?);
        }
        let evidence_references = active_evidence_references(&state)?;
        let m1_proving_record = self
            .m1_candidate
            .load_record(&evidence_references.m1_proving_record_digest)?;
        let m4_workflow_records = evidence_references
            .m4_workflows
            .iter()
            .map(|reference| {
                let stored = self
                    .workers
                    .load_workflow_evidence(&reference.governance_context_digest)?;
                if reference
                    .workflow_id
                    .as_ref()
                    .is_some_and(|workflow_id| workflow_id != stored.workflow_id())
                    || stored.execution_ids() != reference.execution_ids
                    || stored.result_digests() != reference.result_digests
                {
                    return Err(M5RuntimeError::Integrity(format!(
                        "stored M4 {:?} workflow is cross-linked to different workflow, execution, or result identities",
                        reference.kind
                    )));
                }
                Ok(stored)
            })
            .collect::<Result<Vec<_>, M5RuntimeError>>()?;
        let bundle = M5ExportBundleV1::from_live_runtime(
            self.manifest.clone(),
            state.clone(),
            packages,
            m1_proving_record,
            m4_workflow_records,
            initial_snapshot.clone(),
            initial_audit.clone(),
        )?;

        let final_audit = self.capability.audit_reproduction_state(&state)?;
        let final_snapshot = self.capability.backend_snapshot()?.ok_or_else(|| {
            M5RuntimeError::Conflict(
                "authoritative backend snapshot disappeared during export".to_string(),
            )
        })?;
        if engine.state().state_digest != state.state_digest
            || final_audit != initial_audit
            || final_snapshot != initial_snapshot
        {
            return Err(M5RuntimeError::Conflict(
                "M5 state, effect audit, or backend snapshot changed during export".to_string(),
            ));
        }
        bundle.validate_standalone()?;
        Ok(bundle)
    }

    /// Submit and execute one future, ordinary `OpenWorkspace` job on the
    /// exact isolated M4 supervisor that already contains the selected
    /// exported lifecycle anchor. The job is stopped before it is due, then
    /// completed only after reopening under a distinct owner.
    pub fn capture_post_export_m2_restart(
        &self,
        proof_run_manifest_digest: ContentDigest,
        m5_export_bundle_content_digest: ContentDigest,
        m6_completion_bundle: &M6CompletionBundleV1,
        m4_lifecycle_job_id: &str,
        m4_lifecycle_terminal_job_digest: ContentDigest,
    ) -> Result<M5M2PostExportRestartCaptureV2, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        let m6_completion_bundle_bytes = m6_completion_bundle
            .canonical_bytes()
            .map_err(|error| M5RuntimeError::Integrity(error.to_string()))?;
        let sender_export_digest = m6_completion_bundle
            .sender_m5_export_bundle_content_digest()
            .map_err(|error| M5RuntimeError::Integrity(error.to_string()))?;
        require_digest(
            "post-export M2 M6 sender M5 export",
            &m5_export_bundle_content_digest,
            &sender_export_digest,
        )?;
        self.capture_post_export_m2_restart_under_gate(
            proof_run_manifest_digest,
            m5_export_bundle_content_digest,
            ContentDigest::from_bytes(&m6_completion_bundle_bytes),
            m4_lifecycle_job_id,
            m4_lifecycle_terminal_job_digest,
        )
    }

    #[cfg(test)]
    pub(crate) fn capture_post_export_m2_restart_with_completion_digest_for_test(
        &self,
        proof_run_manifest_digest: ContentDigest,
        m5_export_bundle_content_digest: ContentDigest,
        m6_completion_bundle_content_digest: ContentDigest,
        m4_lifecycle_job_id: &str,
        m4_lifecycle_terminal_job_digest: ContentDigest,
    ) -> Result<M5M2PostExportRestartCaptureV2, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        self.capture_post_export_m2_restart_under_gate(
            proof_run_manifest_digest,
            m5_export_bundle_content_digest,
            m6_completion_bundle_content_digest,
            m4_lifecycle_job_id,
            m4_lifecycle_terminal_job_digest,
        )
    }

    fn capture_post_export_m2_restart_under_gate(
        &self,
        proof_run_manifest_digest: ContentDigest,
        m5_export_bundle_content_digest: ContentDigest,
        m6_completion_bundle_content_digest: ContentDigest,
        m4_lifecycle_job_id: &str,
        m4_lifecycle_terminal_job_digest: ContentDigest,
    ) -> Result<M5M2PostExportRestartCaptureV2, M5RuntimeError> {
        let current_export = self.export_active_adopted_bundle()?;
        let current_export_digest = ContentDigest::from_bytes(&current_export.canonical_bytes()?);
        require_digest(
            "post-export M2 current M5 export",
            &m5_export_bundle_content_digest,
            &current_export_digest,
        )?;
        let binding = M5M2PostExportJobBindingV2::new(
            proof_run_manifest_digest,
            m5_export_bundle_content_digest,
            m6_completion_bundle_content_digest,
            m4_lifecycle_job_id,
            m4_lifecycle_terminal_job_digest,
        )?;
        self.workers
            .capture_post_export_restart(&binding, m4_lifecycle_job_id)
    }

    pub fn execute_active(&self, input: i32) -> Result<M5ActiveExecution, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        let expected = self.lock_engine()?.state().active_package_digest.clone();
        self.execute_active_for_package(expected, input)
    }

    fn execute_active_for_package(
        &self,
        expected: ContentDigest,
        input: i32,
    ) -> Result<M5ActiveExecution, M5RuntimeError> {
        self.execute_active_for_package_with_context(expected, input, None)
    }

    fn execute_active_for_package_with_context(
        &self,
        expected: ContentDigest,
        input: i32,
        causal_context_digest: Option<ContentDigest>,
    ) -> Result<M5ActiveExecution, M5RuntimeError> {
        let (result, reference) = match &causal_context_digest {
            Some(context) => self.capability.execute_active_with_causal_context(
                expected,
                input,
                context.clone(),
            )?,
            None => self.capability.execute_active(expected, input)?,
        };
        let mut execution = M5ActiveExecution {
            package_digest: result.snapshot.package_digest,
            package_bytes_digest: result.snapshot.package_bytes_digest,
            component_digest: result.snapshot.component_digest,
            input: result.input,
            output: result.output,
            m3_invocation_id: reference.invocation_id,
            m3_receipt_digest: reference.receipt_digest,
            m3_attestation_digest: reference.attestation_digest,
            m3_proof_digest: reference.proof_digest,
            causal_context_digest: causal_context_digest.clone(),
            execution_digest: ContentDigest::from_bytes(&[]),
        };
        execution.execution_digest = match &causal_context_digest {
            None => digest_json_content(&(
                "wasm-biotic:m5-active-execution:v2",
                &execution.package_digest,
                &execution.package_bytes_digest,
                &execution.component_digest,
                execution.input,
                execution.output,
                &execution.m3_invocation_id,
                &execution.m3_receipt_digest,
                &execution.m3_attestation_digest,
                &execution.m3_proof_digest,
                &result.trace,
            ))?,
            Some(context) => digest_json_content(&(
                "wasm-biotic:m5-active-execution:v3",
                &execution.package_digest,
                &execution.package_bytes_digest,
                &execution.component_digest,
                execution.input,
                execution.output,
                &execution.m3_invocation_id,
                &execution.m3_receipt_digest,
                &execution.m3_attestation_digest,
                &execution.m3_proof_digest,
                context,
                &result.trace,
            ))?,
        };
        Ok(execution)
    }

    /// Re-resolve caller-retained active executions against the authoritative
    /// M3 proof ledger, backend facts, current reproduction state, and active
    /// snapshot.
    ///
    /// The returned audit is suitable for a detached rollback-behavior probe:
    /// merely constructing an [`M5ActiveExecution`] cannot satisfy it because
    /// every field, receipt, attestation, proof, response, and execution trace
    /// must resolve in the effect stores while the M5 state lock is held.
    pub fn audit_active_executions(
        &self,
        executions: &[M5ActiveExecution],
    ) -> Result<M5EffectAuditReport, M5RuntimeError> {
        let records = executions
            .iter()
            .map(active_execution_audit_record)
            .collect::<Vec<_>>();
        let engine = self.lock_engine()?;
        self.capability
            .audit_reproduction_state_with_executions(engine.state(), &records)
            .map_err(M5RuntimeError::from)
    }

    /// Execute and seal one exact behavior probe after a named recovery cycle.
    ///
    /// The engine lock remains held across the before-audit, execution, and
    /// after-audit. If the package/input request was already served, its
    /// invocation appears in the before-audit and the probe fails rather than
    /// reusing old evidence. A successful result therefore contains one new
    /// M3-backed execution and an otherwise unchanged audit closure.
    pub fn capture_post_rollback_probe(
        &self,
        cycle_id: &str,
        input: i32,
    ) -> Result<M5PostRollbackProbeV1, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        self.capture_post_rollback_probe_under_gate(cycle_id, input)
    }

    /// Execute the final fresh rollback probe only after revalidating the
    /// current export, exact M6 completion, and exact live terminal M2 state.
    /// The derived chronology challenge is sealed into the M3 Execute request
    /// before its durable invocation intent is written.
    pub fn capture_final_post_rollback_probe(
        &self,
        cycle_id: &str,
        input: i32,
        proof_run_manifest_digest: ContentDigest,
        m5_export_bundle_content_digest: ContentDigest,
        m6_completion_bundle: &M6CompletionBundleV1,
        m2_restart_capture: &M5M2PostExportRestartCaptureV2,
    ) -> Result<M5FinalPostRollbackProbeV1, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        let m6_bytes = m6_completion_bundle
            .canonical_bytes()
            .map_err(|error| M5RuntimeError::Integrity(error.to_string()))?;
        let sender_export_digest = m6_completion_bundle
            .sender_m5_export_bundle_content_digest()
            .map_err(|error| M5RuntimeError::Integrity(error.to_string()))?;
        require_digest(
            "final post-rollback M6 sender M5 export",
            &m5_export_bundle_content_digest,
            &sender_export_digest,
        )?;
        self.capture_final_post_rollback_probe_under_gate(
            cycle_id,
            input,
            proof_run_manifest_digest,
            m5_export_bundle_content_digest,
            ContentDigest::from_bytes(&m6_bytes),
            m2_restart_capture,
        )
    }

    #[cfg(test)]
    pub(crate) fn capture_final_post_rollback_probe_with_completion_digest_for_test(
        &self,
        cycle_id: &str,
        input: i32,
        proof_run_manifest_digest: ContentDigest,
        m5_export_bundle_content_digest: ContentDigest,
        m6_completion_bundle_content_digest: ContentDigest,
        m2_restart_capture: &M5M2PostExportRestartCaptureV2,
    ) -> Result<M5FinalPostRollbackProbeV1, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        self.capture_final_post_rollback_probe_under_gate(
            cycle_id,
            input,
            proof_run_manifest_digest,
            m5_export_bundle_content_digest,
            m6_completion_bundle_content_digest,
            m2_restart_capture,
        )
    }

    fn capture_final_post_rollback_probe_under_gate(
        &self,
        cycle_id: &str,
        input: i32,
        proof_run_manifest_digest: ContentDigest,
        m5_export_bundle_content_digest: ContentDigest,
        m6_completion_bundle_content_digest: ContentDigest,
        m2_restart_capture: &M5M2PostExportRestartCaptureV2,
    ) -> Result<M5FinalPostRollbackProbeV1, M5RuntimeError> {
        validate_identifier("M5 final post-rollback probe cycle id", cycle_id)?;
        m2_restart_capture.validate()?;
        let binding = m2_restart_capture.binding();
        require_digest(
            "final post-rollback manifest",
            &proof_run_manifest_digest,
            binding.manifest_digest(),
        )?;
        require_digest(
            "final post-rollback M5 export",
            &m5_export_bundle_content_digest,
            binding.m5_export_bundle_content_digest(),
        )?;
        require_digest(
            "final post-rollback M6 completion",
            &m6_completion_bundle_content_digest,
            binding.m6_completion_bundle_content_digest(),
        )?;
        let current_export = self.export_active_adopted_bundle()?;
        require_digest(
            "final post-rollback current M5 export",
            &m5_export_bundle_content_digest,
            &ContentDigest::from_bytes(&current_export.canonical_bytes()?),
        )?;
        self.workers
            .with_validated_live_post_export_capture(m2_restart_capture, || {
                let (cycle_record_digest, recovery_receipt_digest) = {
                    let engine = self.lock_engine()?;
                    engine.state().validate()?;
                    let cycle = engine
                        .state()
                        .cycles
                        .iter()
                        .find(|cycle| cycle.cycle_id == cycle_id)
                        .ok_or_else(|| {
                            M5RuntimeError::Integrity(format!(
                                "final post-rollback cycle '{cycle_id}' is absent"
                            ))
                        })?;
                    let recovery = cycle.recovery_receipt.as_ref().ok_or_else(|| {
                        M5RuntimeError::Integrity(
                            "final post-rollback cycle has no recovery receipt".to_string(),
                        )
                    })?;
                    (cycle.record_digest.clone(), recovery.receipt_digest.clone())
                };
                let causal_execution_context_digest =
                    M5FinalPostRollbackProbeV1::expected_causal_execution_context_digest(
                        &proof_run_manifest_digest,
                        &m5_export_bundle_content_digest,
                        &m6_completion_bundle_content_digest,
                        m2_restart_capture.capture_digest(),
                        cycle_id,
                        &cycle_record_digest,
                        &recovery_receipt_digest,
                    )?;
                let probe = self.capture_causally_bound_post_rollback_probe_under_gate(
                    cycle_id,
                    input,
                    causal_execution_context_digest.clone(),
                )?;
                let mut value = M5FinalPostRollbackProbeV1 {
                    schema: M5_FINAL_POST_ROLLBACK_PROBE_SCHEMA.to_string(),
                    proof_run_manifest_digest,
                    m5_export_bundle_content_digest,
                    m6_completion_bundle_content_digest,
                    m2_restart_capture_digest: m2_restart_capture.capture_digest().clone(),
                    causal_execution_context_digest,
                    probe,
                    final_probe_digest: ContentDigest::from_bytes(&[]),
                };
                value.final_probe_digest = value.expected_final_probe_digest()?;
                value.validate()?;
                Ok(value)
            })
    }

    fn capture_post_rollback_probe_under_gate(
        &self,
        cycle_id: &str,
        input: i32,
    ) -> Result<M5PostRollbackProbeV1, M5RuntimeError> {
        let parts = self.capture_post_rollback_probe_parts_under_gate(cycle_id, input, None)?;
        let mut probe = M5PostRollbackProbeV1 {
            schema: M5_POST_ROLLBACK_PROBE_SCHEMA.to_string(),
            cycle_id: parts.cycle_id,
            cycle_record_digest: parts.cycle_record_digest,
            recovery_receipt_digest: parts.recovery_receipt_digest,
            restored_package_digest: parts.restored_package_digest,
            execution: parts.execution,
            reproduction_state_digest: parts.reproduction_state_digest,
            active_snapshot_digest: parts.active_snapshot_digest,
            prior_effect_audit: parts.prior_effect_audit,
            effect_audit: parts.effect_audit,
            probe_digest: ContentDigest::from_bytes(&[]),
        };
        probe.probe_digest = probe.expected_digest()?;
        probe.validate()?;
        Ok(probe)
    }

    fn capture_causally_bound_post_rollback_probe_under_gate(
        &self,
        cycle_id: &str,
        input: i32,
        causal_execution_context_digest: ContentDigest,
    ) -> Result<M5CausallyBoundPostRollbackProbeV1, M5RuntimeError> {
        let parts = self.capture_post_rollback_probe_parts_under_gate(
            cycle_id,
            input,
            Some(causal_execution_context_digest.clone()),
        )?;
        let mut probe = M5CausallyBoundPostRollbackProbeV1 {
            schema: M5_CAUSALLY_BOUND_POST_ROLLBACK_PROBE_SCHEMA.to_string(),
            causal_execution_context_digest,
            cycle_id: parts.cycle_id,
            cycle_record_digest: parts.cycle_record_digest,
            recovery_receipt_digest: parts.recovery_receipt_digest,
            restored_package_digest: parts.restored_package_digest,
            execution: parts.execution,
            reproduction_state_digest: parts.reproduction_state_digest,
            active_snapshot_digest: parts.active_snapshot_digest,
            prior_effect_audit: parts.prior_effect_audit,
            effect_audit: parts.effect_audit,
            probe_digest: ContentDigest::from_bytes(&[]),
        };
        probe.probe_digest = probe.expected_digest()?;
        probe.validate()?;
        Ok(probe)
    }

    fn capture_post_rollback_probe_parts_under_gate(
        &self,
        cycle_id: &str,
        input: i32,
        causal_context_digest: Option<ContentDigest>,
    ) -> Result<CapturedPostRollbackProbeParts, M5RuntimeError> {
        validate_identifier("M5 post-rollback probe cycle id", cycle_id)?;
        let engine = self.lock_engine()?;
        engine.state().validate()?;
        let cycle = engine
            .state()
            .cycles
            .iter()
            .find(|cycle| cycle.cycle_id == cycle_id)
            .ok_or_else(|| {
                M5RuntimeError::Integrity(format!(
                    "post-rollback probe cycle '{cycle_id}' is absent"
                ))
            })?;
        if !matches!(
            cycle.status,
            crate::factory_reproduction::CycleStatus::QuarantinedAndRolledBack
                | crate::factory_reproduction::CycleStatus::RecoveredToIncumbent
        ) || engine.state().in_flight.is_some()
            || cycle.parent_package_digest != engine.state().active_package_digest
        {
            return Err(M5RuntimeError::Integrity(
                "post-rollback probe requires a terminal recovery restored to the active package"
                    .to_string(),
            ));
        }
        let recovery = cycle.recovery_receipt.as_ref().ok_or_else(|| {
            M5RuntimeError::Integrity(
                "post-rollback probe cycle has no recovery receipt".to_string(),
            )
        })?;
        if recovery.restored_package_digest != cycle.parent_package_digest
            || !recovery.state_readable
        {
            return Err(M5RuntimeError::Integrity(
                "post-rollback probe recovery does not restore readable incumbent state"
                    .to_string(),
            ));
        }
        let cycle_record_digest = cycle.record_digest.clone();
        let recovery_receipt_digest = recovery.receipt_digest.clone();
        let restored_package_digest = cycle.parent_package_digest.clone();

        let prior_effect_audit = self.capability.audit_reproduction_state(engine.state())?;
        let execution = self.execute_active_for_package_with_context(
            restored_package_digest.clone(),
            input,
            causal_context_digest,
        )?;
        if prior_effect_audit.entries.iter().any(|entry| {
            entry.invocation_id == execution.m3_invocation_id
                || entry.proof_digest == execution.m3_proof_digest
        }) {
            return Err(M5RuntimeError::Conflict(
                "post-rollback probe request reused a pre-existing execution; choose a fresh bounded input"
                    .to_string(),
            ));
        }
        let effect_audit = self.capability.audit_reproduction_state_with_executions(
            engine.state(),
            &[active_execution_audit_record(&execution)],
        )?;
        Ok(CapturedPostRollbackProbeParts {
            cycle_id: cycle_id.to_string(),
            cycle_record_digest,
            recovery_receipt_digest,
            restored_package_digest,
            execution,
            reproduction_state_digest: effect_audit.reproduction_state_digest.clone(),
            active_snapshot_digest: effect_audit.backend_snapshot_digest.clone(),
            prior_effect_audit,
            effect_audit,
        })
    }

    /// Run a fully governed seeded cycle.  Approval is bound to the package
    /// preview calculated from the same immutable inputs the engine will use.
    pub fn run_seeded_cycle(&self, plan: M5SeedCyclePlan) -> Result<CycleOutcome, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        self.run_seeded_cycle_under_gate(plan)
    }

    fn run_seeded_cycle_under_gate(
        &self,
        plan: M5SeedCyclePlan,
    ) -> Result<CycleOutcome, M5RuntimeError> {
        validate_identifier("M5 seed cycle id", &plan.cycle_id)?;
        validate_cycle_migration_inputs(
            plan.migration_plan.as_ref(),
            plan.migration_artifacts.as_ref(),
        )?;
        let challenger_component = compile_wat(&plan.challenger_wat_bytes)?;
        let mut engine = self.lock_engine()?;
        let (incumbent, seed_request) =
            self.seed_request_for_plan(&engine, &plan, challenger_component)?;
        let genome = seed_request.genome.clone();
        let challenger =
            preview_package(&incumbent, genome.clone(), plan.state_compatibility.clone())?;
        if let Some(outcome) = engine
            .terminal_seeded_cycle_replay(&seed_request)
            .map_err(map_cycle_replay_error)?
        {
            self.ensure_terminal_authorization_matches(
                &plan.cycle_id,
                &incumbent,
                &challenger,
                plan.approval_decision,
                &plan.approver_ref,
                &plan.approval_rationale,
                Some(&plan.challenger_wat_bytes),
                &outcome,
            )?;
            return Ok(outcome);
        }
        // This is the M5-wide write-ahead boundary: no recipe, migration,
        // supervisor, provider, worker, or capability side effect may precede
        // the exact immutable cycle intent.
        engine.record_seeded_cycle_intent(&seed_request)?;
        self.workers
            .register_package_recipe(&challenger, &plan.challenger_wat_bytes)?;
        self.register_cycle_migration(
            plan.migration_plan.as_ref(),
            plan.migration_artifacts.as_ref(),
        )?;
        self.approval
            .authorize_package(M5PackageAuthorizationRequest {
                cycle_id: plan.cycle_id.clone(),
                incumbent_package_digest: incumbent.package_digest.clone(),
                challenger_package_bytes: challenger.canonical_bytes()?,
                challenger_component_bytes: challenger.payload.genome.component_bytes.clone(),
                decision: plan.approval_decision,
                approver_ref: plan.approver_ref,
                rationale: plan.approval_rationale,
            })?;
        Ok(engine.run_seeded_cycle(seed_request)?)
    }

    /// Admit one already-canonical receiver-local package through the ordinary
    /// M5 seeded-cycle law.
    ///
    /// This is deliberately a package-input seam, not an activation seam. M5
    /// reconstructs the exact deterministic package preview, records the
    /// normal seeded intent, and then runs the existing M1 proving, M4 worker,
    /// M3 shadow/gate, M2 decision, activation, observation, and rollback
    /// sequence. No alternate active pointer or imported evidence shortcut is
    /// introduced.
    pub fn run_exact_candidate_cycle(
        &self,
        plan: M5ExactCandidateCyclePlan,
    ) -> Result<M5ExactCandidateCycleResult, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        self.run_exact_candidate_cycle_under_gate(plan)
    }

    fn run_exact_candidate_cycle_under_gate(
        &self,
        plan: M5ExactCandidateCyclePlan,
    ) -> Result<M5ExactCandidateCycleResult, M5RuntimeError> {
        let ExactCandidateMaterial {
            candidate,
            candidate_package_bytes_digest,
            candidate_wat_digest,
            bound_operator_context_digest,
        } = exact_candidate_material(&plan)?;

        let mut engine = self.lock_engine()?;
        let incumbent = self.cycle_incumbent_or_active(&engine, &plan.cycle_id)?;
        validate_exact_candidate_static_boundary(
            &self.manifest,
            engine.state(),
            &plan,
            &incumbent,
            &candidate,
            &candidate_package_bytes_digest,
        )?;
        let request = SeedCycleRequest {
            cycle_id: plan.cycle_id.clone(),
            expected_active_package_digest: plan.expected_active_package_digest.clone(),
            expected_gate_digest: plan.expected_release_gate_digest.clone(),
            genome: candidate.payload.genome.clone(),
            state_compatibility: candidate.payload.boot_manifest.state_compatibility.clone(),
            migration_plan: None,
            operator_context_digest: bound_operator_context_digest.clone(),
        };
        if let Some(outcome) = engine
            .terminal_seeded_cycle_replay(&request)
            .map_err(map_cycle_replay_error)?
        {
            self.ensure_terminal_authorization_matches(
                &plan.cycle_id,
                &incumbent,
                &candidate,
                plan.approval_decision,
                &plan.approver_ref,
                &plan.approval_rationale,
                Some(&plan.candidate_wat_bytes),
                &outcome,
            )?;
            return self.exact_candidate_result(
                &plan,
                candidate,
                candidate_package_bytes_digest,
                candidate_wat_digest,
                bound_operator_context_digest,
                outcome,
                &engine,
            );
        }

        validate_exact_candidate_cycle_budget(engine.state(), &plan.cycle_id)?;
        let active_snapshot = self.capability.backend_snapshot()?.ok_or_else(|| {
            M5RuntimeError::Integrity(
                "exact candidate preflight found no authoritative active snapshot".to_string(),
            )
        })?;
        validate_exact_candidate_active_snapshot(
            engine.state(),
            &plan,
            &incumbent,
            &candidate,
            &active_snapshot,
        )?;

        // The normal engine intent is the write-ahead boundary. The derived
        // operator context binds every exact plan input, including source WAT,
        // active snapshot, approval disposition, and the caller's context.
        // Thus even a byte-equivalent component with changed WAT cannot reuse
        // this cycle id after an interruption at this boundary.
        engine
            .record_seeded_cycle_intent(&request)
            .map_err(map_cycle_replay_error)?;
        self.workers
            .register_package_recipe(&candidate, &plan.candidate_wat_bytes)?;
        self.approval
            .authorize_package(M5PackageAuthorizationRequest {
                cycle_id: plan.cycle_id.clone(),
                incumbent_package_digest: incumbent.package_digest,
                challenger_package_bytes: plan.candidate_package_bytes.clone(),
                challenger_component_bytes: candidate.payload.genome.component_bytes.clone(),
                decision: plan.approval_decision,
                approver_ref: plan.approver_ref.clone(),
                rationale: plan.approval_rationale.clone(),
            })?;
        let outcome = engine.run_seeded_cycle(request)?;
        self.exact_candidate_result(
            &plan,
            candidate,
            candidate_package_bytes_digest,
            candidate_wat_digest,
            bound_operator_context_digest,
            outcome,
            &engine,
        )
    }

    /// Resolve and re-derive one already-terminal exact candidate cycle.
    ///
    /// Unlike [`Self::run_exact_candidate_cycle`], this inspection seam never
    /// records an intent, registers a recipe, authorizes a package, or invokes
    /// a reproduction/effect port. `None` means that the exact terminal result
    /// does not exist; callers performing recovery must fail closed rather
    /// than turn inspection into missing work.
    pub fn inspect_exact_candidate_cycle(
        &self,
        plan: &M5ExactCandidateCyclePlan,
    ) -> Result<Option<M5ExactCandidateCycleResult>, M5RuntimeError> {
        let ExactCandidateMaterial {
            candidate,
            candidate_package_bytes_digest,
            candidate_wat_digest,
            bound_operator_context_digest,
        } = exact_candidate_material(plan)?;

        let engine = self.lock_engine()?;
        let incumbent = self.cycle_incumbent_or_active(&engine, &plan.cycle_id)?;
        validate_exact_candidate_static_boundary(
            &self.manifest,
            engine.state(),
            plan,
            &incumbent,
            &candidate,
            &candidate_package_bytes_digest,
        )?;
        let request = SeedCycleRequest {
            cycle_id: plan.cycle_id.clone(),
            expected_active_package_digest: plan.expected_active_package_digest.clone(),
            expected_gate_digest: plan.expected_release_gate_digest.clone(),
            genome: candidate.payload.genome.clone(),
            state_compatibility: candidate.payload.boot_manifest.state_compatibility.clone(),
            migration_plan: None,
            operator_context_digest: bound_operator_context_digest.clone(),
        };
        let Some(outcome) = engine
            .terminal_seeded_cycle_replay(&request)
            .map_err(map_cycle_replay_error)?
        else {
            return Ok(None);
        };
        self.ensure_terminal_authorization_matches(
            &plan.cycle_id,
            &incumbent,
            &candidate,
            plan.approval_decision,
            &plan.approver_ref,
            &plan.approval_rationale,
            Some(&plan.candidate_wat_bytes),
            &outcome,
        )?;
        self.exact_candidate_result(
            plan,
            candidate,
            candidate_package_bytes_digest,
            candidate_wat_digest,
            bound_operator_context_digest,
            outcome,
            &engine,
        )
        .map(Some)
    }

    /// Run the N+1-driven cycle.  The exact successor bytes come only from the
    /// adopted package's digest-bound instruction and its previously registered
    /// recipe; no seed fixture is accepted here.
    pub fn run_adopted_successor_cycle(
        &self,
        plan: M5AdoptedCyclePlan,
    ) -> Result<CycleOutcome, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        self.run_adopted_successor_cycle_under_gate(plan)
    }

    fn run_adopted_successor_cycle_under_gate(
        &self,
        plan: M5AdoptedCyclePlan,
    ) -> Result<CycleOutcome, M5RuntimeError> {
        validate_identifier("M5 adopted cycle id", &plan.cycle_id)?;
        validate_cycle_migration_inputs(
            plan.migration_plan.as_ref(),
            plan.migration_artifacts.as_ref(),
        )?;
        let mut engine = self.lock_engine()?;
        let executor = self.cycle_incumbent_or_active(&engine, &plan.cycle_id)?;
        let request = AdoptedSuccessorRequest {
            cycle_id: plan.cycle_id.clone(),
            expected_active_package_digest: executor.package_digest.clone(),
            expected_gate_digest: self.cycle_gate_or_manifest(&engine, &plan.cycle_id),
            migration_plan: plan.migration_plan.clone(),
            operator_context_digest: plan.operator_context_digest.clone(),
        };
        if let Some(outcome) = engine
            .terminal_adopted_successor_cycle_replay(&request)
            .map_err(map_cycle_replay_error)?
        {
            if let Some(successor_digest) = terminal_outcome_package_digest(&outcome) {
                let successor = engine.package(successor_digest)?;
                self.ensure_terminal_authorization_matches(
                    &plan.cycle_id,
                    &executor,
                    &successor,
                    plan.approval_decision,
                    &plan.approver_ref,
                    &plan.approval_rationale,
                    None,
                    &outcome,
                )?;
            }
            return Ok(outcome);
        }
        let prepared = match engine.prepare_adopted_successor_cycle(request.clone())? {
            PrepareSuccessorOutcome::Stopped(record) => return Ok(CycleOutcome::Stopped(record)),
            PrepareSuccessorOutcome::Prepared(prepared) => prepared,
        };
        let successor = prepared.successor_package.clone();
        self.workers.register_package_recipe(
            &successor,
            &prepared
                .initiation
                .materialization_evidence
                .rendered_wat_bytes,
        )?;
        self.register_cycle_migration(
            plan.migration_plan.as_ref(),
            plan.migration_artifacts.as_ref(),
        )?;
        self.approval
            .authorize_package(M5PackageAuthorizationRequest {
                cycle_id: plan.cycle_id.clone(),
                incumbent_package_digest: executor.package_digest.clone(),
                challenger_package_bytes: successor.canonical_bytes()?,
                challenger_component_bytes: successor.payload.genome.component_bytes.clone(),
                decision: plan.approval_decision,
                approver_ref: plan.approver_ref,
                rationale: plan.approval_rationale,
            })?;
        Ok(engine.complete_prepared_successor_cycle(request, &prepared)?)
    }

    pub fn run_two_cycles(
        &self,
        seed: M5SeedCyclePlan,
        adopted: M5AdoptedCyclePlan,
    ) -> Result<M5TwoCycleOutcome, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        let first = self.run_seeded_cycle_under_gate(seed)?;
        if !matches!(first, CycleOutcome::Adopted { .. }) {
            return Err(M5RuntimeError::CycleNotAdopted(
                "first cycle did not adopt a successor".to_string(),
            ));
        }
        let second = self.run_adopted_successor_cycle_under_gate(adopted)?;
        if !matches!(second, CycleOutcome::Adopted { .. }) {
            return Err(M5RuntimeError::CycleNotAdopted(
                "second cycle did not adopt a successor".to_string(),
            ));
        }
        let state = self.state_snapshot()?;
        Ok(M5TwoCycleOutcome {
            first,
            second,
            active_package_digest: state.active_package_digest,
            active_generation: state.active_generation,
        })
    }

    pub fn operator_revert_active(
        &self,
        rollback_id: impl Into<String>,
        expected_active_package_digest: &ContentDigest,
        reason_ref: impl Into<String>,
    ) -> Result<crate::factory_reproduction::OperatorRollbackRecord, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        let rollback_id = rollback_id.into();
        let reason_ref = reason_ref.into();
        let mut engine = self.lock_engine()?;
        let state = engine.state().clone();
        let active = engine.active_package()?;
        if &active.package_digest != expected_active_package_digest {
            return Err(M5RuntimeError::Conflict(
                "operator rollback target differs from the active package".to_string(),
            ));
        }
        let retained = state.retained_incumbent.as_ref().ok_or_else(|| {
            M5RuntimeError::Conflict(
                "operator rollback requires an exact retained incumbent".to_string(),
            )
        })?;
        let restore = engine.package(&retained.package_digest)?;
        let source_cycle_id = state
            .cycles
            .iter()
            .rev()
            .find(|cycle| cycle.challenger_package_digest == active.package_digest)
            .map(|cycle| cycle.cycle_id.clone())
            .ok_or_else(|| {
                M5RuntimeError::Integrity(
                    "active successor has no exact source cycle for rollback authority".to_string(),
                )
            })?;
        let recovery_id = format!("recovery:{rollback_id}");
        let active_package_bytes = active.canonical_bytes()?;
        let active_component_bytes = active.payload.genome.component_bytes.clone();
        let restore_package_bytes = restore.canonical_bytes()?;
        let restore_component_bytes = restore.payload.genome.component_bytes.clone();
        self.approval
            .authorize_operator_rollback(M5OperatorRollbackAuthorizationRequest {
                rollback_id: recovery_id.clone(),
                source_cycle_id: source_cycle_id.clone(),
                active_package_bytes: active_package_bytes.clone(),
                active_component_bytes: active_component_bytes.clone(),
                restore_package_bytes: restore_package_bytes.clone(),
                restore_component_bytes: restore_component_bytes.clone(),
                operator_ref: reason_ref.clone(),
                reason_ref: reason_ref.clone(),
                rationale: "explicit operator request to restore the exact retained incumbent"
                    .to_string(),
            })?;
        self.approval
            .require_exact_operator_rollback(&M5OperatorRollbackExecutionRequest {
                rollback_id: recovery_id,
                source_cycle_id,
                active_package_bytes,
                active_component_bytes,
                restore_package_bytes,
                restore_component_bytes,
                reason_ref: reason_ref.clone(),
            })?;
        Ok(engine.operator_revert_active(
            rollback_id,
            expected_active_package_digest,
            reason_ref,
        )?)
    }

    pub fn qualify_live_provider(
        &self,
        request: ProviderQualificationRequest,
    ) -> Result<LiveProviderQualificationRecord, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        self.qualify_live_provider_under_gate(request)
    }

    fn qualify_live_provider_under_gate(
        &self,
        request: ProviderQualificationRequest,
    ) -> Result<LiveProviderQualificationRecord, M5RuntimeError> {
        Ok(self.lock_engine()?.qualify_live_provider(request)?)
    }

    /// Revalidate and return every durable live-provider/candidate binding in
    /// stable digest-name order. This is the read-only operator seam used to
    /// inspect and export the exact qualification admitted by M5.
    pub fn provider_candidate_bindings(
        &self,
    ) -> Result<Vec<ProviderCandidateBinding>, M5RuntimeError> {
        Ok(self.provider_bindings.validate_all()?)
    }

    /// Resolve one exact durable binding and cross-check it against the
    /// qualification retained by the reproduction engine.
    pub fn provider_candidate_binding(
        &self,
        binding_digest: &ContentDigest,
    ) -> Result<ProviderCandidateBinding, M5RuntimeError> {
        let engine = self.lock_engine()?;
        let binding = self.provider_bindings.load(binding_digest, None)?;
        let qualification = engine
            .state()
            .provider_qualifications
            .iter()
            .find(|record| record.record_digest == binding.qualification_record_digest)
            .ok_or_else(|| {
                M5RuntimeError::Integrity(format!(
                    "provider binding {} has no exact qualification in the reproduction store",
                    binding.binding_digest
                ))
            })?;
        binding.validate_with_qualification(Some(qualification))?;
        self.capability.validate_provider_proposal_reference(
            &binding.proposal_evidence.request,
            &binding.proposal_evidence.result,
            &binding.proposal_evidence.m3_reference,
        )?;
        Ok(binding)
    }

    /// Export one canonical, standalone-verifiable provider binding without
    /// exposing the credential used for its live turn.
    pub fn export_provider_candidate_binding(
        &self,
        binding_digest: &ContentDigest,
    ) -> Result<Vec<u8>, M5RuntimeError> {
        Ok(self
            .provider_candidate_binding(binding_digest)?
            .canonical_bytes()?)
    }

    /// Construct the only prompt accepted for a provider-backed seed plan.
    /// The exact incumbent, candidate package and component identities, genome,
    /// release gate, migration posture, and bounded proposal arguments are all
    /// present before any live call occurs.
    pub fn provider_qualification_request_for_seed(
        &self,
        qualification_id: impl Into<String>,
        provider: &GovernedLiveProviderPort,
        plan: &M5SeedCyclePlan,
    ) -> Result<ProviderQualificationRequest, M5RuntimeError> {
        let (incumbent, target, prompt_bytes) = self.provider_target_and_prompt(plan)?;
        provider.qualification_request(
            qualification_id,
            incumbent.package_digest,
            target.target_digest,
            prompt_bytes,
        )
    }

    /// Freeze the exact proof-run/provider/plan tuple before any live call.
    ///
    /// This method performs deterministic target and prompt construction only.
    /// The returned canonical record is intended to be persisted by the
    /// operator before [`Self::run_precommitted_provider_backed_seed_cycle`].
    pub fn prepare_provider_backed_seed_cycle(
        &self,
        proof_run_id: impl Into<String>,
        qualification_id: impl Into<String>,
        prepared_at_ms: u64,
        provider: &GovernedLiveProviderPort,
        plan: M5SeedCyclePlan,
    ) -> Result<M5PreparedProviderSeedV1, M5RuntimeError> {
        let qualification_id = qualification_id.into();
        let (precommit, bound_plan) = M5ProviderPrecommitV1::prepare(
            proof_run_id,
            qualification_id.clone(),
            prepared_at_ms,
            provider.provider_configuration().clone(),
            plan,
        )?;
        let (_, target, prompt_bytes) = self.provider_target_and_prompt(&bound_plan)?;
        let qualification_request = provider.qualification_request(
            qualification_id,
            target.incumbent_package_digest.clone(),
            target.target_digest.clone(),
            prompt_bytes,
        )?;
        let provider_wire_request =
            M5ProviderWireRequestV1::new(&provider.config, &qualification_request)?;
        M5PreparedProviderSeedV1::new(
            precommit,
            bound_plan,
            target,
            qualification_request,
            provider_wire_request,
        )
    }

    /// Perform the only public current-manifest provider invocation path.
    ///
    /// This runtime already owns the process-level M5 lock. The method rejects
    /// every matching durable intent, cycle, qualification, or binding before
    /// drawing randomness; it then derives one challenged request, performs
    /// the call, resolves one exact binding, and seals an opaque completion.
    pub fn run_current_manifest_provider_invocation(
        &self,
        manifest: &M7ProofRunManifest,
        prepared: M5PreparedProviderSeedV1,
    ) -> Result<M5CompletedProviderInvocationV1, M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        manifest.canonical_bytes().map_err(|error| {
            M5RuntimeError::Integrity(format!("M7 proof-run manifest is invalid: {error}"))
        })?;
        prepared.validate()?;
        let prepared_configuration_fingerprint =
            prepared.qualification_request.configuration.fingerprint()?;
        if self
            .governed_live_provider_configuration_fingerprint
            .as_ref()
            != Some(&prepared_configuration_fingerprint)
        {
            return Err(M5RuntimeError::Conflict(
                "public completed invocation requires the exact concrete governed live-provider runtime"
                    .to_string(),
            ));
        }
        let scope = LiveProviderQualificationScope::from_prepared(&prepared).map_err(|error| {
            M5RuntimeError::Integrity(format!("live-provider scope is invalid: {error}"))
        })?;
        if manifest.live_provider_scope() != Some(&scope)
            || manifest.proof_run_id() != prepared.precommit.proof_run_id
        {
            return Err(M5RuntimeError::Conflict(
                "prepared provider seed differs from the exact current M7 manifest scope"
                    .to_string(),
            ));
        }
        let manifest_validated_at_ms = observed_provider_unix_time_ms()?;
        if manifest_validated_at_ms < manifest.run_started_at_ms() {
            return Err(M5RuntimeError::Conflict(
                "provider manifest validation predates the manifest run start".to_string(),
            ));
        }

        // This is the second, owner-lock-held preflight. Nothing challenge- or
        // transport-related happens before it succeeds.
        self.reject_existing_provider_invocation_evidence(&prepared)?;

        #[cfg(test)]
        pause_after_provider_invocation_preflight_for_test(&prepared.plan.cycle_id);

        let run_nonce = fresh_provider_run_nonce().map_err(|error| {
            M5RuntimeError::Execution(format!("provider nonce generation failed: {error}"))
        })?;
        let challenged = M5ChallengedProviderSeedV1::derive(
            &prepared,
            manifest.manifest_digest().clone(),
            scope.scope_digest().clone(),
            run_nonce,
        )?;
        let call_started_at_ms = observe_provider_time_strictly_after(manifest_validated_at_ms)?;
        let (qualification, outcome) = self
            .run_challenged_precommitted_provider_backed_seed_cycle_under_gate(
                &prepared,
                &challenged,
            )?;
        let call_completed_at_ms = observed_provider_unix_time_ms()?;
        if call_completed_at_ms < call_started_at_ms {
            return Err(M5RuntimeError::Conflict(
                "provider call completion predates its observed start".to_string(),
            ));
        }
        let challenged_request = challenged.qualification_request();
        if qualification.qualification_id != challenged_request.qualification_id
            || qualification.request_digest != challenged_request.request_digest
            || qualification.package_digest != challenged_request.package_digest
            || qualification.target_digest != challenged_request.target_digest
            || qualification.replay_capsule_digest
                != challenged_request.replay_capsule.capsule_digest
            || qualification.configuration_fingerprint
                != challenged_request.configuration.fingerprint()?
            || qualification.status != ProviderQualificationStatus::Qualified
        {
            return Err(M5RuntimeError::Integrity(
                "M5 returned a qualification outside the exact challenged request".to_string(),
            ));
        }
        let mut matches = self
            .provider_bindings
            .validate_all()?
            .into_iter()
            .filter(|binding| {
                binding.target == prepared.target
                    && binding.qualification_record_digest == qualification.record_digest
                    && binding.qualification == qualification
                    && binding.proposal_evidence.request.qualification_request
                        == *challenged_request
            });
        let binding = matches.next().ok_or_else(|| {
            M5RuntimeError::Integrity(
                "current provider invocation has no exact durable binding".to_string(),
            )
        })?;
        if matches.next().is_some() {
            return Err(M5RuntimeError::Integrity(
                "current provider invocation has multiple exact durable bindings".to_string(),
            ));
        }
        let receipt = M5ProviderExecutionReceiptV1::new(
            manifest,
            &prepared,
            &challenged,
            &binding,
            &outcome,
            manifest_validated_at_ms,
            call_started_at_ms,
            call_completed_at_ms,
        )
        .map_err(|error| {
            M5RuntimeError::Integrity(format!("provider receipt sealing failed: {error}"))
        })?;
        M5CompletedProviderInvocationV1::seal(prepared, challenged, binding, outcome, receipt)
            .map_err(|error| {
                M5RuntimeError::Integrity(format!(
                    "completed provider invocation sealing failed: {error}"
                ))
            })
    }

    fn reject_existing_provider_invocation_evidence(
        &self,
        prepared: &M5PreparedProviderSeedV1,
    ) -> Result<(), M5RuntimeError> {
        let state_has_match = {
            let engine = self.lock_engine()?;
            let state = engine.state();
            state
                .cycle_intents
                .iter()
                .any(|intent| intent.cycle_id == prepared.plan.cycle_id)
                || state
                    .cycles
                    .iter()
                    .any(|cycle| cycle.cycle_id == prepared.plan.cycle_id)
                || state.provider_qualifications.iter().any(|qualification| {
                    qualification.qualification_id
                        == prepared.qualification_request.qualification_id
                        || qualification.target_digest == prepared.target.target_digest
                })
        };
        if state_has_match {
            return Err(M5RuntimeError::Conflict(
                "current provider invocation already has matching durable factory evidence"
                    .to_string(),
            ));
        }
        if self
            .provider_bindings
            .validate_all()?
            .iter()
            .any(|binding| {
                binding.target.cycle_id == prepared.plan.cycle_id
                    || binding.target.target_digest == prepared.target.target_digest
                    || binding.qualification.qualification_id
                        == prepared.qualification_request.qualification_id
            })
        {
            return Err(M5RuntimeError::Conflict(
                "current provider invocation already has a matching durable provider binding"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Execute only the exact provider cycle frozen by a persisted precommit.
    ///
    /// This unchallenged API is retained for explicitly non-M7 callers. M7
    /// workflows must use [`Self::run_current_manifest_provider_invocation`].
    pub fn run_precommitted_provider_backed_seed_cycle(
        &self,
        prepared: M5PreparedProviderSeedV1,
    ) -> Result<(LiveProviderQualificationRecord, CycleOutcome), M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        self.run_precommitted_provider_backed_seed_cycle_under_gate(prepared)
    }

    fn run_precommitted_provider_backed_seed_cycle_under_gate(
        &self,
        prepared: M5PreparedProviderSeedV1,
    ) -> Result<(LiveProviderQualificationRecord, CycleOutcome), M5RuntimeError> {
        prepared.validate()?;
        let (_, expected_target, expected_prompt) =
            self.provider_target_and_prompt(&prepared.plan)?;
        let expected_request = ProviderQualificationRequest::new(
            prepared.qualification_request.qualification_id.clone(),
            expected_target.incumbent_package_digest.clone(),
            expected_target.target_digest.clone(),
            prepared.qualification_request.configuration.clone(),
            expected_prompt,
            prepared.qualification_request.replay_capsule.clone(),
        )?;
        if expected_target != prepared.target || expected_request != prepared.qualification_request
        {
            return Err(M5RuntimeError::Conflict(
                "prepared provider seed differs from the current exact runtime target or prompt"
                    .to_string(),
            ));
        }
        self.run_provider_backed_seed_cycle_under_gate(
            prepared.qualification_request,
            prepared.plan,
        )
    }

    /// Internal proof-path execution for one exact post-manifest challenge.
    /// Public callers must use the completed-invocation API, which owns the
    /// locked preflight, nonce draw, binding resolution, and receipt sealing.
    fn run_challenged_precommitted_provider_backed_seed_cycle_under_gate(
        &self,
        prepared: &M5PreparedProviderSeedV1,
        challenged: &M5ChallengedProviderSeedV1,
    ) -> Result<(LiveProviderQualificationRecord, CycleOutcome), M5RuntimeError> {
        prepared.validate()?;
        challenged.validate_for(prepared)?;
        let expected =
            M5ChallengedProviderSeedV1::from_challenge(prepared, challenged.challenge.clone())?;
        if &expected != challenged {
            return Err(M5RuntimeError::Conflict(
                "challenged provider seed differs from the exact current-call derivation"
                    .to_string(),
            ));
        }
        self.run_provider_backed_seed_cycle_under_gate(
            challenged.qualification_request.clone(),
            prepared.plan.clone(),
        )
    }

    /// A provider-backed proposal may enter the deterministic cycle only after
    /// exact live-turn plus offline-replay qualification.  The subsequent
    /// candidate still traverses the same M1 proving, M4 workers, M3 shadowing,
    /// M2 approval, and exact activation law.
    pub fn run_provider_backed_seed_cycle(
        &self,
        qualification: ProviderQualificationRequest,
        plan: M5SeedCyclePlan,
    ) -> Result<(LiveProviderQualificationRecord, CycleOutcome), M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        self.run_provider_backed_seed_cycle_under_gate(qualification, plan)
    }

    fn run_provider_backed_seed_cycle_under_gate(
        &self,
        qualification: ProviderQualificationRequest,
        plan: M5SeedCyclePlan,
    ) -> Result<(LiveProviderQualificationRecord, CycleOutcome), M5RuntimeError> {
        validate_cycle_migration_inputs(
            plan.migration_plan.as_ref(),
            plan.migration_artifacts.as_ref(),
        )?;
        let (incumbent, target, base_prompt_bytes) = self.provider_target_and_prompt(&plan)?;
        let prompt_bytes = match qualification.invocation_challenge_digest.as_ref() {
            Some(challenge) => challenged_provider_prompt_bytes(&base_prompt_bytes, challenge)?,
            None => base_prompt_bytes,
        };
        let expected_qualification = match qualification.invocation_challenge_digest.clone() {
            Some(challenge) => ProviderQualificationRequest::new_challenged(
                qualification.qualification_id.clone(),
                incumbent.package_digest.clone(),
                target.target_digest.clone(),
                qualification.configuration.clone(),
                prompt_bytes,
                qualification.replay_capsule.clone(),
                challenge,
            ),
            None => ProviderQualificationRequest::new(
                qualification.qualification_id.clone(),
                incumbent.package_digest.clone(),
                target.target_digest.clone(),
                qualification.configuration.clone(),
                prompt_bytes,
                qualification.replay_capsule.clone(),
            ),
        }
        .map_err(|error| {
            M5RuntimeError::Conflict(format!(
                "provider qualification request cannot be reconstructed for the exact seed target: {error}"
            ))
        })?;
        if qualification != expected_qualification {
            return Err(M5RuntimeError::Conflict(
                "provider qualification request is not the canonical exact-candidate seed prompt"
                    .to_string(),
            ));
        }
        let provider_seed_request = SeedCycleRequest {
            cycle_id: plan.cycle_id.clone(),
            expected_active_package_digest: incumbent.package_digest.clone(),
            expected_gate_digest: target.release_gate_digest.clone(),
            genome: target.materialized_genome()?,
            state_compatibility: plan.state_compatibility.clone(),
            migration_plan: plan.migration_plan.clone(),
            operator_context_digest: plan.operator_context_digest.clone(),
        };
        {
            let engine = self.lock_engine()?;
            if let Some(outcome) = engine
                .terminal_seeded_cycle_replay(&provider_seed_request)
                .map_err(map_cycle_replay_error)?
            {
                let record = engine
                    .state()
                    .provider_qualifications
                    .iter()
                    .find(|record| record.qualification_id == qualification.qualification_id)
                    .cloned()
                    .ok_or_else(|| {
                        M5RuntimeError::Conflict(
                            "terminal seed cycle has no provider qualification for this exact request"
                                .to_string(),
                        )
                    })?;
                if record.request_digest != qualification.request_digest
                    || record.package_digest != qualification.package_digest
                    || record.target_digest != qualification.target_digest
                    || record.replay_capsule_digest != qualification.replay_capsule.capsule_digest
                    || record.configuration_fingerprint
                        != qualification.configuration.fingerprint()?
                    || record.status != ProviderQualificationStatus::Qualified
                {
                    return Err(M5RuntimeError::Conflict(
                        "terminal seed cycle provider qualification differs from the exact replay request"
                            .to_string(),
                    ));
                }
                self.require_exact_provider_binding(&target, &record)?;
                let challenger =
                    FactoryPackage::from_canonical_bytes(&target.candidate_package_bytes)?;
                self.ensure_terminal_authorization_matches(
                    &plan.cycle_id,
                    &incumbent,
                    &challenger,
                    plan.approval_decision,
                    &plan.approver_ref,
                    &plan.approval_rationale,
                    Some(&plan.challenger_wat_bytes),
                    &outcome,
                )?;
                return Ok((record, outcome));
            }
        }
        self.lock_engine()?
            .record_seeded_cycle_intent(&provider_seed_request)?;
        let proposal_qualification = qualification.clone();
        let record = self.qualify_live_provider_under_gate(qualification)?;
        if record.status != ProviderQualificationStatus::Qualified {
            return Err(M5RuntimeError::ProviderNotQualified(Box::new(record)));
        }
        let parsed_intent = record
            .live_turn
            .as_ref()
            .ok_or_else(|| {
                M5RuntimeError::Integrity(
                    "qualified provider record has no live-turn intent".to_string(),
                )
            })?
            .parsed_intent
            .clone();
        let normalized_parser_input_bytes = record
            .live_turn
            .as_ref()
            .expect("qualified live turn checked above")
            .normalized_parser_input_bytes
            .clone();
        let proposal_request = FactoryProviderProposalRequest::new(
            proposal_qualification,
            normalized_parser_input_bytes,
        )?;
        let (proposal_result, proposal_reference) = self
            .capability
            .record_provider_proposal(&proposal_request)?;
        let proposal_evidence =
            ProviderProposalEvidence::new(proposal_request, proposal_result, proposal_reference)?;
        self.capability.validate_provider_proposal_reference(
            &proposal_evidence.request,
            &proposal_evidence.result,
            &proposal_evidence.m3_reference,
        )?;
        self.provider_bindings.bind_and_publish(
            target,
            record.clone(),
            parsed_intent,
            proposal_evidence,
        )?;
        let outcome = self.run_seeded_cycle_under_gate(plan)?;
        Ok((record, outcome))
    }

    fn require_exact_provider_binding(
        &self,
        target: &ProviderCandidateTarget,
        qualification: &LiveProviderQualificationRecord,
    ) -> Result<ProviderCandidateBinding, M5RuntimeError> {
        let mut matches = self
            .provider_bindings
            .validate_all()?
            .into_iter()
            .filter(|binding| {
                binding.target.target_digest == target.target_digest
                    && binding.qualification_record_digest == qualification.record_digest
            });
        let binding = matches.next().ok_or_else(|| {
            M5RuntimeError::Integrity(format!(
                "qualified provider target '{}' has no durable M3-backed proposal binding",
                target.target_digest
            ))
        })?;
        if matches.next().is_some() {
            return Err(M5RuntimeError::Integrity(format!(
                "qualified provider target '{}' has multiple proposal bindings",
                target.target_digest
            )));
        }
        if &binding.target != target {
            return Err(M5RuntimeError::Integrity(
                "provider binding target differs from the exact replayed seed target".to_string(),
            ));
        }
        binding.validate_with_qualification(Some(qualification))?;
        self.capability.validate_provider_proposal_reference(
            &binding.proposal_evidence.request,
            &binding.proposal_evidence.result,
            &binding.proposal_evidence.m3_reference,
        )?;
        Ok(binding)
    }

    fn provider_target_and_prompt(
        &self,
        plan: &M5SeedCyclePlan,
    ) -> Result<(FactoryPackage, ProviderCandidateTarget, Vec<u8>), M5RuntimeError> {
        validate_identifier("M5 provider seed cycle id", &plan.cycle_id)?;
        let component_bytes = compile_wat(&plan.challenger_wat_bytes)?;
        let engine = self.lock_engine()?;
        let (incumbent, seed_request) =
            self.seed_request_for_plan(&engine, plan, component_bytes)?;
        drop(engine);
        let gate_digest = seed_request.expected_gate_digest.clone();
        let candidate = preview_package(
            &incumbent,
            seed_request.genome,
            plan.state_compatibility.clone(),
        )?;
        let candidate_bytes = candidate.canonical_bytes()?;
        let target = ProviderCandidateTarget::new(
            plan.cycle_id.clone(),
            &incumbent,
            &candidate,
            gate_digest.clone(),
            plan.challenger_wat_bytes.clone(),
            plan.challenger_policy.clone(),
            plan.state_compatibility.clone(),
            plan.migration_plan.clone(),
            plan.migration_artifacts.clone(),
            plan.operator_context_digest.clone(),
        )?;
        let invocation_challenge_digest = m5_unbound_invocation_challenge_digest();
        let prompt_bytes = serde_json::to_vec(&json!({
            "schema": M5_PROVIDER_PROMPT_SCHEMA,
            "non_authoritative_proposal": true,
            "operation": crate::m5_provider_binding::PROVIDER_CANDIDATE_OPERATION,
            "cycle_id": target.cycle_id,
            "incumbent_package_digest": incumbent.package_digest,
            "incumbent_package_bytes_digest": ContentDigest::from_bytes(
                &incumbent.canonical_bytes()?
            ),
            "candidate_package_digest": candidate.package_digest,
            "candidate_package_bytes_digest": ContentDigest::from_bytes(&candidate_bytes),
            "candidate_component_digest": candidate.payload.genome.component_digest,
            "target_genome_digest": target.target_genome_digest,
            "challenger_wat_digest": target.challenger_wat_digest,
            "policy_digest": target.challenger_policy_digest,
            "release_gate_digest": gate_digest,
            "state_compatibility": target.state_compatibility,
            "migration_plan_digest": target
                .migration_plan
                .as_ref()
                .map(|plan| plan.plan_digest.clone()),
            "migration_artifact_bundle_digest": target
                .migration_artifacts
                .as_ref()
                .map(|artifacts| artifacts.bundle_digest.clone()),
            "operator_context_digest": target.operator_context_digest,
            "invocation_challenge_digest": invocation_challenge_digest,
            "required_response": {
                "operation": crate::m5_provider_binding::PROVIDER_CANDIDATE_OPERATION,
                "target_genome_digest": target.target_genome_digest,
                "arguments": {
                    "cycle_id": target.cycle_id,
                    "challenger_wat_digest": target.challenger_wat_digest,
                    "policy_digest": target.challenger_policy_digest,
                    "invocation_challenge_digest": invocation_challenge_digest,
                }
            }
        }))?;
        Ok((incumbent, target, prompt_bytes))
    }

    /// Deterministic negative-control hook: the next real post-activation
    /// observation is marked unhealthy after its task executes.
    pub fn induce_next_health_regression(&self) -> Result<(), M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        self.capability.arm_next_observation_regression()?;
        Ok(())
    }

    /// Deterministic crash-boundary hook: interrupt the next activation after a
    /// successful durable migration, leaving engine recovery work for reopen.
    pub fn interrupt_next_activation(&self) -> Result<(), M5RuntimeError> {
        let _operation_guard = self.lock_operation()?;
        self.capability.arm_interrupt_before_next_activation()?;
        Ok(())
    }

    fn cycle_incumbent_or_active(
        &self,
        engine: &FactoryReproductionEngine,
        cycle_id: &str,
    ) -> Result<FactoryPackage, M5RuntimeError> {
        if let Some(intent) = engine
            .state()
            .cycle_intents
            .iter()
            .find(|intent| intent.cycle_id == cycle_id)
        {
            return Ok(engine.package(&intent.expected_active_package_digest)?);
        }
        Ok(engine.active_package()?)
    }

    fn cycle_gate_or_manifest(
        &self,
        engine: &FactoryReproductionEngine,
        cycle_id: &str,
    ) -> ContentDigest {
        engine
            .state()
            .cycle_intents
            .iter()
            .find(|intent| intent.cycle_id == cycle_id)
            .map(|intent| intent.expected_gate_digest.clone())
            .unwrap_or_else(|| self.manifest.release_gate.gate_digest.clone())
    }

    fn seed_request_for_plan(
        &self,
        engine: &FactoryReproductionEngine,
        plan: &M5SeedCyclePlan,
        challenger_component: Vec<u8>,
    ) -> Result<(FactoryPackage, SeedCycleRequest), M5RuntimeError> {
        let incumbent = self.cycle_incumbent_or_active(engine, &plan.cycle_id)?;
        let genome = MutableGenome::new(
            Some(incumbent.package_digest.clone()),
            challenger_component,
            plan.challenger_policy.clone(),
        )?;
        let request = SeedCycleRequest {
            cycle_id: plan.cycle_id.clone(),
            expected_active_package_digest: incumbent.package_digest.clone(),
            expected_gate_digest: self.cycle_gate_or_manifest(engine, &plan.cycle_id),
            genome,
            state_compatibility: plan.state_compatibility.clone(),
            migration_plan: plan.migration_plan.clone(),
            operator_context_digest: plan.operator_context_digest.clone(),
        };
        Ok((incumbent, request))
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_terminal_authorization_matches(
        &self,
        cycle_id: &str,
        incumbent: &FactoryPackage,
        challenger: &FactoryPackage,
        decision: ApprovalDecision,
        approver_ref: &str,
        rationale: &str,
        supplied_wat: Option<&[u8]>,
        outcome: &CycleOutcome,
    ) -> Result<(), M5RuntimeError> {
        if matches!(outcome, CycleOutcome::Stopped(_)) {
            return Ok(());
        }
        let authorization = self
            .approval
            .package_authorization(cycle_id)?
            .ok_or_else(|| {
                M5RuntimeError::Integrity(format!(
                    "terminal cycle '{cycle_id}' has no immutable package authorization"
                ))
            })?;
        if &authorization.incumbent_package_digest != &incumbent.package_digest
            || &authorization.challenger_package != challenger
            || authorization.decision != decision
            || authorization.approver_ref != approver_ref
            || authorization.rationale != rationale
        {
            return Err(M5RuntimeError::Conflict(format!(
                "terminal cycle '{cycle_id}' authorization differs from the replay input"
            )));
        }
        if let Some(supplied_wat) = supplied_wat {
            let retained_wat = self
                .workers
                .recipe_for_package(&challenger.package_digest)?;
            if retained_wat != supplied_wat {
                return Err(M5RuntimeError::Conflict(format!(
                    "terminal cycle '{cycle_id}' WAT recipe differs from the replay input"
                )));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn exact_candidate_result(
        &self,
        plan: &M5ExactCandidateCyclePlan,
        candidate_package: FactoryPackage,
        candidate_package_bytes_digest: ContentDigest,
        candidate_wat_digest: ContentDigest,
        bound_operator_context_digest: ContentDigest,
        outcome: CycleOutcome,
        engine: &FactoryReproductionEngine,
    ) -> Result<M5ExactCandidateCycleResult, M5RuntimeError> {
        let reproduction_state = engine.state().clone();
        let intent = reproduction_state
            .cycle_intents
            .iter()
            .find(|intent| intent.cycle_id == plan.cycle_id)
            .cloned()
            .ok_or_else(|| {
                M5RuntimeError::Integrity(format!(
                    "terminal exact candidate cycle '{}' has no durable intent",
                    plan.cycle_id
                ))
            })?;
        let cycle_record = reproduction_state
            .cycles
            .iter()
            .find(|cycle| cycle.cycle_id == plan.cycle_id)
            .cloned()
            .ok_or_else(|| {
                M5RuntimeError::Integrity(format!(
                    "terminal exact candidate cycle '{}' has no durable cycle record",
                    plan.cycle_id
                ))
            })?;
        let package_authorization = self
            .approval
            .package_authorization(&plan.cycle_id)?
            .ok_or_else(|| {
                M5RuntimeError::Integrity(format!(
                    "terminal exact candidate cycle '{}' has no package authorization",
                    plan.cycle_id
                ))
            })?;
        let incumbent_package = engine.package(&plan.expected_active_package_digest)?;
        let active_snapshot = self.capability.backend_snapshot()?.ok_or_else(|| {
            M5RuntimeError::Integrity(
                "terminal exact candidate cycle has no authoritative active snapshot".to_string(),
            )
        })?;
        let effect_audit = self
            .capability
            .audit_reproduction_state(&reproduction_state)?;
        let result = M5ExactCandidateCycleResult {
            cycle_id: plan.cycle_id.clone(),
            expected_active_package_digest: plan.expected_active_package_digest.clone(),
            expected_active_snapshot_digest: plan.expected_active_snapshot_digest.clone(),
            expected_release_gate_digest: plan.expected_release_gate_digest.clone(),
            incumbent_package,
            candidate_package,
            candidate_package_bytes_digest,
            candidate_wat_digest,
            supplied_operator_context_digest: plan.operator_context_digest.clone(),
            bound_operator_context_digest,
            approval_decision: plan.approval_decision,
            approver_ref: plan.approver_ref.clone(),
            approval_rationale: plan.approval_rationale.clone(),
            intent,
            package_authorization,
            cycle_record,
            outcome,
            reproduction_state,
            active_snapshot,
            effect_audit,
        };
        result.validate()?;
        Ok(result)
    }

    fn register_cycle_migration(
        &self,
        plan: Option<&StateMigrationPlan>,
        artifacts: Option<&StateMigrationArtifactBundle>,
    ) -> Result<(), M5RuntimeError> {
        validate_cycle_migration_inputs(plan, artifacts)?;
        match (plan, artifacts) {
            (None, None) => Ok(()),
            (Some(plan), Some(artifacts))
                if plan.migration_program_digest == artifacts.bundle_digest =>
            {
                self.capability.register_migration_artifacts(artifacts)?;
                Ok(())
            }
            (Some(_), Some(_)) => Err(M5RuntimeError::InvalidConfig(
                "migration plan does not bind the supplied executable artifact bundle".to_string(),
            )),
            (Some(_), None) => Err(M5RuntimeError::InvalidConfig(
                "migration plan requires exact executable forward and rollback artifacts"
                    .to_string(),
            )),
            (None, Some(_)) => Err(M5RuntimeError::InvalidConfig(
                "migration artifacts must not be supplied without a migration plan".to_string(),
            )),
        }
    }

    fn lock_engine(&self) -> Result<MutexGuard<'_, FactoryReproductionEngine>, M5RuntimeError> {
        self.engine.lock().map_err(|_| M5RuntimeError::LockPoisoned)
    }

    fn lock_operation(&self) -> Result<MutexGuard<'_, ()>, M5RuntimeError> {
        self.operation_gate
            .lock()
            .map_err(|_| M5RuntimeError::Integrity("M5 operation gate is poisoned".to_string()))
    }
}

impl Drop for M5Runtime {
    fn drop(&mut self) {
        let _ = self.m3.stop();
        let _ = self.m2.stop();
    }
}

#[derive(Serialize)]
struct M5ExactCandidateContextDigestMaterial<'a> {
    cycle_id: &'a str,
    expected_active_package_digest: &'a ContentDigest,
    expected_active_snapshot_digest: &'a ContentDigest,
    expected_release_gate_digest: &'a ContentDigest,
    candidate_package_digest: &'a ContentDigest,
    candidate_package_bytes_digest: &'a ContentDigest,
    candidate_component_digest: &'a ContentDigest,
    candidate_wat_digest: &'a ContentDigest,
    supplied_operator_context_digest: &'a ContentDigest,
    approval_decision: ApprovalDecision,
    approver_ref: &'a str,
    approval_rationale: &'a str,
    state_transition: &'static str,
}

struct ExactCandidateMaterial {
    candidate: FactoryPackage,
    candidate_package_bytes_digest: ContentDigest,
    candidate_wat_digest: ContentDigest,
    bound_operator_context_digest: ContentDigest,
}

fn exact_candidate_material(
    plan: &M5ExactCandidateCyclePlan,
) -> Result<ExactCandidateMaterial, M5RuntimeError> {
    validate_identifier("M5 exact candidate cycle id", &plan.cycle_id)?;
    validate_identifier("M5 exact candidate approver ref", &plan.approver_ref)?;
    validate_approval_rationale(&plan.approval_rationale)?;
    if plan.operator_context_digest == ContentDigest::from_bytes(&[]) {
        return Err(M5RuntimeError::InvalidConfig(
            "exact candidate operator context must bind nonempty receiver-local evidence"
                .to_string(),
        ));
    }

    let candidate =
        FactoryPackage::from_canonical_bytes(&plan.candidate_package_bytes).map_err(|error| {
            M5RuntimeError::Integrity(format!(
                "exact candidate bytes are not one canonical factory package: {error}"
            ))
        })?;
    let compiled = compile_wat(&plan.candidate_wat_bytes)?;
    if compiled != candidate.payload.genome.component_bytes {
        return Err(M5RuntimeError::Integrity(
            "exact candidate WAT does not compile to the component bytes in the package"
                .to_string(),
        ));
    }
    let candidate_package_bytes_digest = ContentDigest::from_bytes(&plan.candidate_package_bytes);
    let candidate_wat_digest = ContentDigest::from_bytes(&plan.candidate_wat_bytes);
    let bound_operator_context_digest = exact_candidate_context_digest(
        plan,
        &candidate,
        &candidate_package_bytes_digest,
        &candidate_wat_digest,
    )?;
    Ok(ExactCandidateMaterial {
        candidate,
        candidate_package_bytes_digest,
        candidate_wat_digest,
        bound_operator_context_digest,
    })
}

fn exact_candidate_context_digest(
    plan: &M5ExactCandidateCyclePlan,
    candidate: &FactoryPackage,
    candidate_package_bytes_digest: &ContentDigest,
    candidate_wat_digest: &ContentDigest,
) -> Result<ContentDigest, M5RuntimeError> {
    exact_candidate_context_digest_from_material(M5ExactCandidateContextDigestMaterial {
        cycle_id: &plan.cycle_id,
        expected_active_package_digest: &plan.expected_active_package_digest,
        expected_active_snapshot_digest: &plan.expected_active_snapshot_digest,
        expected_release_gate_digest: &plan.expected_release_gate_digest,
        candidate_package_digest: &candidate.package_digest,
        candidate_package_bytes_digest,
        candidate_component_digest: &candidate.payload.genome.component_digest,
        candidate_wat_digest,
        supplied_operator_context_digest: &plan.operator_context_digest,
        approval_decision: plan.approval_decision,
        approver_ref: &plan.approver_ref,
        approval_rationale: &plan.approval_rationale,
        state_transition: "no_migration_v1",
    })
}

fn exact_candidate_context_digest_from_result(
    result: &M5ExactCandidateCycleResult,
) -> Result<ContentDigest, M5RuntimeError> {
    exact_candidate_context_digest_from_material(M5ExactCandidateContextDigestMaterial {
        cycle_id: &result.cycle_id,
        expected_active_package_digest: &result.expected_active_package_digest,
        expected_active_snapshot_digest: &result.expected_active_snapshot_digest,
        expected_release_gate_digest: &result.expected_release_gate_digest,
        candidate_package_digest: &result.candidate_package.package_digest,
        candidate_package_bytes_digest: &result.candidate_package_bytes_digest,
        candidate_component_digest: &result.candidate_package.payload.genome.component_digest,
        candidate_wat_digest: &result.candidate_wat_digest,
        supplied_operator_context_digest: &result.supplied_operator_context_digest,
        approval_decision: result.approval_decision,
        approver_ref: &result.approver_ref,
        approval_rationale: &result.approval_rationale,
        state_transition: "no_migration_v1",
    })
}

fn exact_candidate_context_digest_from_material(
    material: M5ExactCandidateContextDigestMaterial<'_>,
) -> Result<ContentDigest, M5RuntimeError> {
    Ok(digest_json_content(&(
        M5_EXACT_CANDIDATE_CONTEXT_DOMAIN,
        material,
    ))?)
}

fn validate_exact_candidate_static_boundary(
    manifest: &M5RuntimeManifest,
    state: &ReproductionState,
    plan: &M5ExactCandidateCyclePlan,
    incumbent: &FactoryPackage,
    candidate: &FactoryPackage,
    candidate_package_bytes_digest: &ContentDigest,
) -> Result<(), M5RuntimeError> {
    manifest.validate()?;
    state.validate()?;
    incumbent.validate()?;
    candidate.validate()?;
    if state.factory_id != manifest.config.factory_id
        || state.release_gate != manifest.release_gate
        || plan.expected_release_gate_digest != manifest.release_gate.gate_digest
    {
        return Err(M5RuntimeError::Conflict(
            "exact candidate plan is not bound to the receiver's current release gate".to_string(),
        ));
    }
    if plan.expected_active_package_digest != incumbent.package_digest {
        return Err(M5RuntimeError::Conflict(
            "exact candidate plan names a different active parent package".to_string(),
        ));
    }
    if candidate_package_bytes_digest != &candidate.package_digest
        || candidate_package_bytes_digest
            != &ContentDigest::from_bytes(&plan.candidate_package_bytes)
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate canonical package-byte identity is inconsistent".to_string(),
        ));
    }
    let expected_generation = incumbent.payload.generation.checked_add(1).ok_or_else(|| {
        M5RuntimeError::ResourceBound("exact candidate generation overflowed".to_string())
    })?;
    if candidate.payload.factory_id != manifest.config.factory_id
        || candidate.payload.parent_package_digest != Some(incumbent.package_digest.clone())
        || candidate.payload.genome.parent_package_digest != Some(incumbent.package_digest.clone())
        || candidate.payload.generation != expected_generation
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate has the wrong receiver factory, parent, or N+1 generation".to_string(),
        ));
    }
    if candidate.payload.stable_interface != incumbent.payload.stable_interface
        || candidate.payload.worker_catalog != incumbent.payload.worker_catalog
        || candidate.payload.service_dependencies != incumbent.payload.service_dependencies
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate changes the stable interface, worker catalog, or service catalog"
                .to_string(),
        ));
    }
    let incumbent_state = &incumbent.payload.boot_manifest.state_compatibility;
    let candidate_state = &candidate.payload.boot_manifest.state_compatibility;
    let current_schema = incumbent_state.written_schema;
    if current_schema < candidate_state.readable_schema_min
        || current_schema > candidate_state.readable_schema_max
        || candidate_state.written_schema != current_schema
        || current_schema > incumbent_state.incumbent_rollback_readable_through
        || current_schema > candidate_state.incumbent_rollback_readable_through
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate is not a no-migration continuation of the active state schema"
                .to_string(),
        ));
    }
    let gate = &manifest.release_gate;
    if candidate.payload.generation > gate.budgets.max_generation_depth
        || candidate.payload.genome.component_bytes.len() as u64 > gate.budgets.max_component_bytes
        || candidate.payload.genome.policy.max_canary_tasks > gate.budgets.max_shadow_tasks
    {
        return Err(M5RuntimeError::ResourceBound(
            "exact candidate exceeds the receiver release-gate generation, component, or task budget"
                .to_string(),
        ));
    }
    let preview = preview_package(
        incumbent,
        candidate.payload.genome.clone(),
        candidate_state.clone(),
    )?;
    if &preview != candidate {
        return Err(M5RuntimeError::Integrity(
            "exact candidate differs from the receiver's deterministic N+1 package preview"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_exact_candidate_cycle_budget(
    state: &ReproductionState,
    cycle_id: &str,
) -> Result<(), M5RuntimeError> {
    if state.in_flight.is_some() {
        return Err(M5RuntimeError::Conflict(
            "exact candidate cannot start while M5 recovery is pending".to_string(),
        ));
    }
    if state.cycles.len() as u32 >= state.release_gate.budgets.max_total_cycles {
        return Err(M5RuntimeError::ResourceBound(
            "exact candidate exceeds the receiver's total cycle budget".to_string(),
        ));
    }
    if state.cycles.iter().any(|cycle| cycle.cycle_id == cycle_id) {
        return Err(M5RuntimeError::Conflict(format!(
            "exact candidate cycle '{cycle_id}' has a nonterminal durable cycle record"
        )));
    }
    Ok(())
}

fn validate_exact_candidate_active_snapshot(
    state: &ReproductionState,
    plan: &M5ExactCandidateCyclePlan,
    incumbent: &FactoryPackage,
    candidate: &FactoryPackage,
    snapshot: &FactoryRuntimeSnapshot,
) -> Result<(), M5RuntimeError> {
    validate_factory_runtime_snapshot(snapshot)?;
    let incumbent_bytes = incumbent.canonical_bytes()?;
    if state.active_package_digest != incumbent.package_digest
        || state.active_generation != incumbent.payload.generation
        || snapshot.snapshot_digest != plan.expected_active_snapshot_digest
        || snapshot.factory_id != state.factory_id
        || snapshot.package_digest != incumbent.package_digest
        || snapshot.package_bytes_digest != ContentDigest::from_bytes(&incumbent_bytes)
        || snapshot.component_digest != incumbent.payload.genome.component_digest
        || snapshot.generation != incumbent.payload.generation
        || snapshot.state_schema != state.active_state_schema
    {
        return Err(M5RuntimeError::Conflict(
            "exact candidate plan is stale relative to the authoritative active snapshot"
                .to_string(),
        ));
    }
    let compatibility = &candidate.payload.boot_manifest.state_compatibility;
    if snapshot.state_schema < compatibility.readable_schema_min
        || snapshot.state_schema > compatibility.readable_schema_max
        || compatibility.written_schema != snapshot.state_schema
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate cannot continue the authoritative active state without migration"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_factory_runtime_snapshot(
    snapshot: &FactoryRuntimeSnapshot,
) -> Result<(), M5RuntimeError> {
    if snapshot.schema != M5_FACTORY_SNAPSHOT_SCHEMA || snapshot.factory_id.trim().is_empty() {
        return Err(M5RuntimeError::Integrity(
            "authoritative M5 snapshot has an unsupported schema or empty factory".to_string(),
        ));
    }
    require_digest(
        "authoritative M5 snapshot",
        &snapshot.snapshot_digest,
        &digest_json_content(&(
            M5_FACTORY_SNAPSHOT_SCHEMA,
            &snapshot.factory_id,
            &snapshot.package_digest,
            &snapshot.package_bytes_digest,
            &snapshot.component_digest,
            snapshot.generation,
            snapshot.state_schema,
            &snapshot.state_blob_digest,
            &snapshot.activation_id,
        ))?,
    )
}

fn validate_exact_candidate_result(
    result: &M5ExactCandidateCycleResult,
) -> Result<(), M5RuntimeError> {
    validate_identifier("M5 exact candidate result cycle id", &result.cycle_id)?;
    validate_identifier(
        "M5 exact candidate result approver ref",
        &result.approver_ref,
    )?;
    validate_approval_rationale(&result.approval_rationale)?;
    result.incumbent_package.validate()?;
    result.candidate_package.validate()?;
    let candidate_bytes = result.candidate_package.canonical_bytes()?;
    require_digest(
        "exact candidate result package bytes",
        &result.candidate_package_bytes_digest,
        &ContentDigest::from_bytes(&candidate_bytes),
    )?;
    require_digest(
        "exact candidate bound operator context",
        &result.bound_operator_context_digest,
        &exact_candidate_context_digest_from_result(result)?,
    )?;
    if result.expected_active_package_digest != result.incumbent_package.package_digest
        || result.candidate_package.payload.parent_package_digest
            != Some(result.incumbent_package.package_digest.clone())
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate result is cross-linked to a different incumbent".to_string(),
        ));
    }

    result.reproduction_state.validate()?;
    result.effect_audit.validate()?;
    validate_factory_runtime_snapshot(&result.active_snapshot)?;
    require_digest(
        "exact candidate result reproduction state",
        &result.effect_audit.reproduction_state_digest,
        &result.reproduction_state.state_digest,
    )?;
    require_digest(
        "exact candidate result backend snapshot",
        &result.effect_audit.backend_snapshot_digest,
        &result.active_snapshot.snapshot_digest,
    )?;
    if result.reproduction_state.in_flight.is_some()
        || result.reproduction_state.factory_id != result.incumbent_package.payload.factory_id
        || result.reproduction_state.release_gate.gate_digest != result.expected_release_gate_digest
        || result.active_snapshot.factory_id != result.reproduction_state.factory_id
        || result.active_snapshot.package_digest != result.reproduction_state.active_package_digest
        || result.active_snapshot.generation != result.reproduction_state.active_generation
        || result.active_snapshot.state_schema != result.reproduction_state.active_state_schema
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate final snapshot, effect audit, and reproduction state disagree"
                .to_string(),
        ));
    }

    let durable_intent = result
        .reproduction_state
        .cycle_intents
        .iter()
        .find(|intent| intent.cycle_id == result.cycle_id)
        .ok_or_else(|| {
            M5RuntimeError::Integrity(
                "exact candidate result has no matching durable cycle intent".to_string(),
            )
        })?;
    let durable_cycle = result
        .reproduction_state
        .cycles
        .iter()
        .find(|cycle| cycle.cycle_id == result.cycle_id)
        .ok_or_else(|| {
            M5RuntimeError::Integrity(
                "exact candidate result has no matching durable cycle".to_string(),
            )
        })?;
    if durable_intent != &result.intent
        || durable_cycle != &result.cycle_record
        || result.intent.cycle_id != result.cycle_id
        || result.intent.kind != crate::factory_reproduction::CycleIntentKind::Seeded
        || result.intent.expected_active_package_digest != result.expected_active_package_digest
        || result.intent.expected_gate_digest != result.expected_release_gate_digest
        || result.intent.seed_genome.as_ref() != Some(&result.candidate_package.payload.genome)
        || result.intent.state_compatibility
            != result
                .candidate_package
                .payload
                .boot_manifest
                .state_compatibility
        || result.intent.migration_plan.is_some()
        || result.intent.operator_context_digest != result.bound_operator_context_digest
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate result differs from its seeded-cycle intent".to_string(),
        ));
    }

    result.package_authorization.validate()?;
    if result.package_authorization.cycle_id != result.cycle_id
        || result.package_authorization.incumbent_package_digest
            != result.expected_active_package_digest
        || result.package_authorization.challenger_package != result.candidate_package
        || result.package_authorization.decision != result.approval_decision
        || result.package_authorization.approver_ref != result.approver_ref
        || result.package_authorization.rationale != result.approval_rationale
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate result differs from its immutable package authorization".to_string(),
        ));
    }
    if result.cycle_record.cycle_id != result.cycle_id
        || result.cycle_record.parent_package_digest != result.expected_active_package_digest
        || result.cycle_record.challenger_package_digest != result.candidate_package.package_digest
        || result.cycle_record.challenger_package_bytes_digest
            != result.candidate_package_bytes_digest
        || result.cycle_record.genome_digest
            != result.candidate_package.payload.genome.genome_digest
        || result.cycle_record.gate_digest != result.expected_release_gate_digest
        || result.cycle_record.initiation.is_some()
        || result.cycle_record.migration_plan.is_some()
        || result.cycle_record.migration_receipt.is_some()
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate cycle record differs from the authorized package or no-migration plan"
                .to_string(),
        ));
    }
    if let Some(approval) = &result.cycle_record.approval
        && (approval.decision != result.approval_decision
            || approval.approver_ref != result.approver_ref
            || approval.rationale != result.approval_rationale)
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate supervisor decision differs from its authorization".to_string(),
        ));
    }

    let final_package = validate_exact_candidate_outcome(result)?;
    let final_bytes = final_package.canonical_bytes()?;
    if result.active_snapshot.package_digest != final_package.package_digest
        || result.active_snapshot.package_bytes_digest != ContentDigest::from_bytes(&final_bytes)
        || result.active_snapshot.component_digest != final_package.payload.genome.component_digest
        || result.active_snapshot.generation != final_package.payload.generation
    {
        return Err(M5RuntimeError::Integrity(
            "exact candidate terminal outcome differs from actual active component execution"
                .to_string(),
        ));
    }
    validate_exact_candidate_effect_entries(result)
}

fn validate_exact_candidate_outcome(
    result: &M5ExactCandidateCycleResult,
) -> Result<&FactoryPackage, M5RuntimeError> {
    use crate::factory_reproduction::CycleStatus;
    match (&result.outcome, result.cycle_record.status) {
        (
            CycleOutcome::Adopted {
                package_digest,
                cycle_record_digest,
            },
            CycleStatus::Adopted,
        ) if package_digest == &result.candidate_package.package_digest
            && cycle_record_digest == &result.cycle_record.record_digest
            && result
                .cycle_record
                .approval
                .as_ref()
                .is_some_and(|approval| approval.decision == ApprovalDecision::Approved)
            && result.cycle_record.activation_receipt.is_some()
            && result.cycle_record.observation_evidence.is_some()
            && result.cycle_record.recovery_receipt.is_none() =>
        {
            Ok(&result.candidate_package)
        }
        (
            CycleOutcome::GateRejected {
                package_digest,
                cycle_record_digest,
            },
            CycleStatus::GateRejected,
        ) if package_digest == &result.candidate_package.package_digest
            && cycle_record_digest == &result.cycle_record.record_digest
            && result.cycle_record.approval.is_none()
            && result.cycle_record.activation_receipt.is_none()
            && result.cycle_record.observation_evidence.is_none()
            && result.cycle_record.recovery_receipt.is_none() =>
        {
            Ok(&result.incumbent_package)
        }
        (
            CycleOutcome::ApprovalRejected {
                package_digest,
                cycle_record_digest,
            },
            CycleStatus::ApprovalRejected,
        ) if package_digest == &result.candidate_package.package_digest
            && cycle_record_digest == &result.cycle_record.record_digest
            && result
                .cycle_record
                .approval
                .as_ref()
                .is_some_and(|approval| approval.decision == ApprovalDecision::Rejected)
            && result.cycle_record.activation_receipt.is_none()
            && result.cycle_record.observation_evidence.is_none()
            && result.cycle_record.recovery_receipt.is_none() =>
        {
            Ok(&result.incumbent_package)
        }
        (
            CycleOutcome::QuarantinedAndRolledBack {
                package_digest,
                restored_package_digest,
                cycle_record_digest,
            },
            CycleStatus::QuarantinedAndRolledBack | CycleStatus::RecoveredToIncumbent,
        ) if package_digest == &result.candidate_package.package_digest
            && restored_package_digest == &result.incumbent_package.package_digest
            && cycle_record_digest == &result.cycle_record.record_digest
            && result
                .cycle_record
                .approval
                .as_ref()
                .is_some_and(|approval| approval.decision == ApprovalDecision::Approved)
            && result.cycle_record.activation_receipt.is_some()
            && result.cycle_record.observation_evidence.is_some()
            && result
                .cycle_record
                .recovery_receipt
                .as_ref()
                .is_some_and(|receipt| {
                    receipt.restored_package_digest == result.incumbent_package.package_digest
                }) =>
        {
            Ok(&result.incumbent_package)
        }
        _ => Err(M5RuntimeError::Integrity(
            "exact candidate outcome is nonterminal or differs from its cycle evidence".to_string(),
        )),
    }
}

fn validate_exact_candidate_effect_entries(
    result: &M5ExactCandidateCycleResult,
) -> Result<(), M5RuntimeError> {
    validate_exact_effect_entry(
        &result.effect_audit,
        M5EffectAuditKind::Shadow,
        &format!("cycle:{}:shadow", result.cycle_id),
        Some(&result.cycle_record.shadow_evidence.request_digest),
    )?;
    validate_exact_effect_entry(
        &result.effect_audit,
        M5EffectAuditKind::Migration,
        &format!("cycle:{}:migration", result.cycle_id),
        None,
    )?;
    validate_exact_effect_entry(
        &result.effect_audit,
        M5EffectAuditKind::Activation,
        &format!("cycle:{}:activation", result.cycle_id),
        result
            .cycle_record
            .activation_receipt
            .as_ref()
            .map(|receipt| &receipt.request_digest),
    )?;
    validate_exact_effect_entry(
        &result.effect_audit,
        M5EffectAuditKind::Observation,
        &format!("cycle:{}:observation", result.cycle_id),
        result
            .cycle_record
            .observation_evidence
            .as_ref()
            .map(|evidence| &evidence.request_digest),
    )?;
    validate_exact_effect_entry(
        &result.effect_audit,
        M5EffectAuditKind::Recovery,
        &format!("cycle:{}:recovery", result.cycle_id),
        result
            .cycle_record
            .recovery_receipt
            .as_ref()
            .map(|receipt| &receipt.request_digest),
    )
}

fn validate_exact_effect_entry(
    audit: &M5EffectAuditReport,
    kind: M5EffectAuditKind,
    evidence_id: &str,
    expected_request_digest: Option<&ContentDigest>,
) -> Result<(), M5RuntimeError> {
    let matching = audit
        .entries
        .iter()
        .filter(|entry| {
            entry
                .evidence_id
                .split('|')
                .any(|alias| alias == evidence_id)
        })
        .collect::<Vec<_>>();
    match expected_request_digest {
        Some(expected)
            if matching.len() == 1
                && matching[0].kind == kind
                && &matching[0].domain_request_digest == expected =>
        {
            Ok(())
        }
        None if matching.is_empty() => Ok(()),
        _ => Err(M5RuntimeError::Integrity(format!(
            "exact candidate effect audit differs at '{evidence_id}'"
        ))),
    }
}

fn validate_approval_rationale(rationale: &str) -> Result<(), M5RuntimeError> {
    if rationale.trim().is_empty() || rationale.len() > 4_096 {
        return Err(M5RuntimeError::InvalidConfig(
            "M5 approval rationale must contain 1..=4096 bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_cycle_migration_inputs(
    plan: Option<&StateMigrationPlan>,
    artifacts: Option<&StateMigrationArtifactBundle>,
) -> Result<(), M5RuntimeError> {
    match (plan, artifacts) {
        (None, None) => Ok(()),
        (Some(plan), Some(artifacts)) => {
            plan.validate()?;
            artifacts.validate()?;
            if plan.migration_program_digest != artifacts.bundle_digest {
                return Err(M5RuntimeError::InvalidConfig(
                    "migration plan does not bind the supplied executable artifact bundle"
                        .to_string(),
                ));
            }
            Ok(())
        }
        (Some(_), None) => Err(M5RuntimeError::InvalidConfig(
            "migration plan requires exact executable forward and rollback artifacts".to_string(),
        )),
        (None, Some(_)) => Err(M5RuntimeError::InvalidConfig(
            "migration artifacts must not be supplied without a migration plan".to_string(),
        )),
    }
}

fn terminal_outcome_package_digest(outcome: &CycleOutcome) -> Option<&ContentDigest> {
    match outcome {
        CycleOutcome::Adopted { package_digest, .. }
        | CycleOutcome::GateRejected { package_digest, .. }
        | CycleOutcome::ApprovalRejected { package_digest, .. }
        | CycleOutcome::QuarantinedAndRolledBack { package_digest, .. } => Some(package_digest),
        CycleOutcome::Stopped(_) => None,
    }
}

fn map_cycle_replay_error(error: ReproductionError) -> M5RuntimeError {
    match error {
        ReproductionError::DuplicateCycleId(cycle_id) => M5RuntimeError::Conflict(format!(
            "cycle id '{cycle_id}' is already bound to different immutable input"
        )),
        other => M5RuntimeError::Dependency(other.to_string()),
    }
}

fn preview_package(
    incumbent: &FactoryPackage,
    genome: MutableGenome,
    compatibility: StateCompatibility,
) -> Result<FactoryPackage, M5RuntimeError> {
    Ok(FactoryPackage::build(
        incumbent.payload.factory_id.clone(),
        incumbent.payload.generation.checked_add(1).ok_or_else(|| {
            M5RuntimeError::ResourceBound("factory generation counter overflowed".to_string())
        })?,
        genome,
        incumbent.payload.stable_interface.clone(),
        incumbent.payload.worker_catalog.clone(),
        incumbent.payload.service_dependencies.clone(),
        compatibility,
    )?)
}

fn validate_suite_matches_gate(
    suite: &ValidationSuite,
    gate: &ReleaseGate,
) -> Result<(), M5RuntimeError> {
    suite
        .validate()
        .map_err(|error| M5RuntimeError::InvalidConfig(error.to_string()))?;
    gate.validate()?;
    if suite.export_name != StableInterfaceContract::reference().exported_function
        || suite.cases.len() != gate.benchmarks.len()
    {
        return Err(M5RuntimeError::InvalidConfig(
            "M1 proving suite and M5 release gate do not describe the same reference task"
                .to_string(),
        ));
    }
    for (case, benchmark) in suite.cases.iter().zip(&gate.benchmarks) {
        if benchmark.request_bytes != case.input.to_le_bytes() {
            return Err(M5RuntimeError::InvalidConfig(format!(
                "benchmark '{}' does not use the proving input for case '{}'",
                benchmark.benchmark_id, case.case_id
            )));
        }
        let crate::m1_validation::ExpectedI32Outcome::Returned(expected) = case.expected else {
            return Err(M5RuntimeError::InvalidConfig(
                "bounded M5 release benchmarks require returned i32 proving outcomes".to_string(),
            ));
        };
        if benchmark.expected_output_digest != ContentDigest::from_bytes(&expected.to_le_bytes()) {
            return Err(M5RuntimeError::InvalidConfig(format!(
                "benchmark '{}' expected output differs from case '{}'",
                benchmark.benchmark_id, case.case_id
            )));
        }
    }
    Ok(())
}

fn compile_wat(wat_bytes: &[u8]) -> Result<Vec<u8>, M5RuntimeError> {
    if wat_bytes.is_empty() || wat_bytes.len() > MAX_RECIPE_BYTES {
        return Err(M5RuntimeError::ResourceBound(
            "component WAT is outside the bounded recipe envelope".to_string(),
        ));
    }
    Ok(wat::parse_bytes(wat_bytes)
        .map_err(|error| M5RuntimeError::InvalidRecipe(error.to_string()))?
        .into_owned())
}

fn provider_response_schema_json() -> String {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["operation", "target_genome_digest", "arguments"],
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["candidate.materialize_patchset"]
            },
            "target_genome_digest": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$"
            },
            "arguments": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "cycle_id",
                    "challenger_wat_digest",
                    "policy_digest",
                    "invocation_challenge_digest"
                ],
                "properties": {
                    "cycle_id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 512
                    },
                    "challenger_wat_digest": {
                        "type": "string",
                        "pattern": "^sha256:[0-9a-f]{64}$"
                    },
                    "policy_digest": {
                        "type": "string",
                        "pattern": "^sha256:[0-9a-f]{64}$"
                    },
                    "invocation_challenge_digest": {
                        "type": "string",
                        "pattern": "^sha256:[0-9a-f]{64}$"
                    }
                }
            }
        }
    })
    .to_string()
}

fn provider_tool_catalog_json() -> String {
    json!([{
        "type": "function",
        "name": crate::m5_provider_binding::PROVIDER_CANDIDATE_OPERATION,
        "description": "Propose materialization of one already bounded, digest-identified M5 candidate. This proposal cannot authorize promotion.",
        "parameters": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "cycle_id",
                "challenger_wat_digest",
                "policy_digest",
                "invocation_challenge_digest"
            ],
            "properties": {
                "cycle_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 512
                },
                "challenger_wat_digest": {
                    "type": "string",
                    "pattern": "^sha256:[0-9a-f]{64}$"
                },
                "policy_digest": {
                    "type": "string",
                    "pattern": "^sha256:[0-9a-f]{64}$"
                },
                "invocation_challenge_digest": {
                    "type": "string",
                    "pattern": "^sha256:[0-9a-f]{64}$"
                }
            }
        }
    }])
    .to_string()
}

fn observed_provider_unix_time_ms() -> Result<u64, M5RuntimeError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        M5RuntimeError::Integrity("system time predates the Unix epoch".to_string())
    })?;
    u64::try_from(elapsed.as_millis()).map_err(|_| {
        M5RuntimeError::Integrity(
            "system time exceeds the provider timestamp representation".to_string(),
        )
    })
}

fn observe_provider_time_strictly_after(lower_bound_ms: u64) -> Result<u64, M5RuntimeError> {
    let observed = observed_provider_unix_time_ms()?;
    if observed < lower_bound_ms {
        return Err(M5RuntimeError::Integrity(
            "system time regressed after manifest validation".to_string(),
        ));
    }
    if observed > lower_bound_ms {
        return Ok(observed);
    }
    thread::sleep(Duration::from_millis(1));
    let observed = observed_provider_unix_time_ms()?;
    if observed <= lower_bound_ms {
        return Err(M5RuntimeError::Integrity(
            "system time did not advance after manifest validation".to_string(),
        ));
    }
    Ok(observed)
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M5RuntimeError> {
    if path.as_os_str().is_empty() {
        return Err(M5RuntimeError::InvalidConfig(
            "owned root must not be empty".to_string(),
        ));
    }
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|error| M5RuntimeError::io(path, error))?;
    let canonical = fs::canonicalize(path).map_err(|error| M5RuntimeError::io(path, error))?;
    let metadata =
        fs::symlink_metadata(&canonical).map_err(|error| M5RuntimeError::io(&canonical, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(M5RuntimeError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn acquire_m5_owner_lock(root: &Path) -> Result<File, M5RuntimeError> {
    let path = root.join(M5_RUNTIME_OWNER_LOCK_FILE);
    reject_symlink_if_present(&path)?;
    if path.exists() {
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| M5RuntimeError::io(&path, error))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(M5RuntimeError::UnsafePath(path));
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| M5RuntimeError::io(&path, error))?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => M5RuntimeError::Conflict(format!(
            "M5 runtime root '{}' already has a live owner",
            root.display()
        )),
        std::fs::TryLockError::Error(error) => M5RuntimeError::io(&path, error),
    })?;
    Ok(file)
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M5RuntimeError> {
    validate_identifier("owned directory name", name)?;
    let path = root.join(name);
    reject_symlink_if_present(&path)?;
    fs::create_dir_all(&path).map_err(|error| M5RuntimeError::io(&path, error))?;
    let canonical = fs::canonicalize(&path).map_err(|error| M5RuntimeError::io(&path, error))?;
    if canonical.parent() != Some(root) {
        return Err(M5RuntimeError::UnsafePath(path));
    }
    Ok(canonical)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M5RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(M5RuntimeError::UnsafePath(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(M5RuntimeError::io(path, error)),
    }
}

fn read_regular_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, M5RuntimeError> {
    reject_symlink_if_present(path)?;
    let metadata = fs::metadata(path).map_err(|error| M5RuntimeError::io(path, error))?;
    if !metadata.is_file() || metadata.len() > max_bytes as u64 {
        return Err(M5RuntimeError::ResourceBound(format!(
            "file '{}' is not regular or exceeds {max_bytes} bytes",
            path.display()
        )));
    }
    let file = File::open(path).map_err(|error| M5RuntimeError::io(path, error))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| M5RuntimeError::io(path, error))?;
    if bytes.len() > max_bytes {
        return Err(M5RuntimeError::ResourceBound(format!(
            "file '{}' exceeds {max_bytes} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_json_bounded<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_bytes: usize,
) -> Result<T, M5RuntimeError> {
    Ok(serde_json::from_slice(&read_regular_bounded(
        path, max_bytes,
    )?)?)
}

fn persist_immutable(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), M5RuntimeError> {
    if path.parent() != Some(root) || bytes.is_empty() {
        return Err(M5RuntimeError::UnsafePath(path.to_path_buf()));
    }
    reject_symlink_if_present(path)?;
    if path.exists() {
        let existing = read_regular_bounded(path, bytes.len().max(1))?;
        if existing == bytes {
            return Ok(());
        }
        return Err(M5RuntimeError::Conflict(format!(
            "immutable record '{}' already contains different bytes",
            path.display()
        )));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| M5RuntimeError::io(path, error))?;
    file.write_all(bytes)
        .map_err(|error| M5RuntimeError::io(path, error))?;
    file.sync_all()
        .map_err(|error| M5RuntimeError::io(path, error))
}

fn write_json_atomic<T: Serialize>(
    root: &Path,
    path: &Path,
    value: &T,
) -> Result<(), M5RuntimeError> {
    write_atomic(root, path, &serde_json::to_vec_pretty(value)?)
}

fn write_atomic(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), M5RuntimeError> {
    if path.parent() != Some(root) || bytes.is_empty() {
        return Err(M5RuntimeError::UnsafePath(path.to_path_buf()));
    }
    reject_symlink_if_present(path)?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(
        ".{}.tmp-{}-{sequence}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("m5-state"),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| M5RuntimeError::io(&temporary, error))?;
    file.write_all(bytes)
        .map_err(|error| M5RuntimeError::io(&temporary, error))?;
    file.sync_all()
        .map_err(|error| M5RuntimeError::io(&temporary, error))?;
    fs::rename(&temporary, path).map_err(|error| M5RuntimeError::io(path, error))
}

fn require_digest(
    subject: &str,
    expected: &ContentDigest,
    actual: &ContentDigest,
) -> Result<(), M5RuntimeError> {
    if expected == actual {
        Ok(())
    } else {
        Err(M5RuntimeError::Integrity(format!(
            "{subject} digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<(), M5RuntimeError> {
    if value.trim().is_empty()
        || value.len() > 512
        || value.contains('\0')
        || value.contains('/')
        || value.contains('\\')
        || value == "."
        || value == ".."
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(M5RuntimeError::InvalidConfig(format!(
            "{field} is blank, unsafe, or outside its length bound"
        )));
    }
    Ok(())
}

fn validate_safe_component(field: &str, value: &str) -> Result<(), M5RuntimeError> {
    if value.is_empty()
        || value.len() > 128
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(M5RuntimeError::InvalidConfig(format!(
            "{field} must be one bounded ASCII path component"
        )));
    }
    Ok(())
}

fn sanitize_id(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | ':') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized.trim_matches('-').to_string()
}

fn port_failure(error: impl Display) -> PortFailure {
    PortFailure::failed("m5_adapter_failure", error.to_string())
}

#[derive(Debug)]
pub enum M5RuntimeError {
    InvalidConfig(String),
    InvalidRecipe(String),
    Integrity(String),
    Conflict(String),
    ResourceBound(String),
    Execution(String),
    UnsafePath(PathBuf),
    AlreadyInitialized,
    NotInitialized,
    LockPoisoned,
    CycleNotAdopted(String),
    ProviderNotQualified(Box<LiveProviderQualificationRecord>),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Serialization(String),
    Dependency(String),
}

impl M5RuntimeError {
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl Display for M5RuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid M5 config: {message}"),
            Self::InvalidRecipe(message) => write!(formatter, "invalid M5 WAT recipe: {message}"),
            Self::Integrity(message) => write!(formatter, "M5 integrity failure: {message}"),
            Self::Conflict(message) => write!(formatter, "M5 durable conflict: {message}"),
            Self::ResourceBound(message) => write!(formatter, "M5 resource bound: {message}"),
            Self::Execution(message) => write!(formatter, "M5 execution failed: {message}"),
            Self::UnsafePath(path) => write!(formatter, "unsafe M5 path '{}'", path.display()),
            Self::AlreadyInitialized => write!(formatter, "M5 runtime is already initialized"),
            Self::NotInitialized => write!(formatter, "M5 runtime is not initialized"),
            Self::LockPoisoned => write!(formatter, "M5 mutation lock is poisoned"),
            Self::CycleNotAdopted(message) => write!(formatter, "{message}"),
            Self::ProviderNotQualified(record) => write!(
                formatter,
                "live provider qualification '{}' ended as {:?}",
                record.qualification_id, record.status
            ),
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "M5 I/O failure at '{}': {source}",
                    path.display()
                )
            }
            Self::Serialization(message) => {
                write!(formatter, "M5 serialization failure: {message}")
            }
            Self::Dependency(message) => write!(formatter, "M5 dependency failure: {message}"),
        }
    }
}

impl Error for M5RuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for M5RuntimeError {
    fn from(error: std::io::Error) -> Self {
        Self::io("<unknown>", error)
    }
}

impl From<serde_json::Error> for M5RuntimeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

macro_rules! dependency_error {
    ($($type:path),+ $(,)?) => {
        $(
            impl From<$type> for M5RuntimeError {
                fn from(error: $type) -> Self {
                    Self::Dependency(error.to_string())
                }
            }
        )+
    };
}

dependency_error!(
    crate::execution::artifact::ArtifactError,
    crate::execution::component::ComponentBuildError,
    crate::execution::inference::InferenceAdapterError,
    crate::execution::tool_membrane::ToolMembraneError,
    crate::m1_validation::ValidationError,
    crate::m2_runtime::M2RuntimeError,
    crate::m3_runtime::M3RuntimeError,
    crate::m4_runtime::M4RuntimeError,
    crate::m5_effect_port::M5EffectPortError,
    crate::m5_effect_store::FactoryEffectStoreError,
    crate::m5_export::M5ExportError,
    crate::m5_m3_adapter::M5M3AdapterError,
    crate::m5_provider_binding::ProviderBindingError,
    crate::m5_provider_precommit::M5ProviderPrecommitError,
    crate::m5_supervisor_adapter::M5SupervisorAdapterError,
    crate::deployment::DeploymentError,
    crate::factory_reproduction::ReproductionError,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::component::ComponentExecutionLimits;
    use crate::execution::inference::{
        InferenceAttemptRecord, InferenceProviderMode, InferenceProviderModelEntry,
        InferenceProviderOutcomeRecord, InferenceRawOutputRecord, InferenceRequestBodyRecord,
        InferenceRetryClassification, InferenceTurnResult, InferenceUsageRecord,
    };
    use crate::factory_reproduction::{
        BenchmarkSpec, CycleStatus, GenerationLoopInstruction, InvariantKind, InvariantSpec,
        PendingStage, PortFailureKind, RecursionBudgets, ReleaseThresholds, StopReason,
    };
    use crate::m1_validation::{ValidationCase, ValidationSuite};
    use std::collections::BTreeSet;

    struct TestDirectory(PathBuf);

    struct ProviderInvocationPreflightHookReset {
        cycle_id: String,
    }

    impl Drop for ProviderInvocationPreflightHookReset {
        fn drop(&mut self) {
            if let Ok(mut slot) = PROVIDER_INVOCATION_PREFLIGHT_TEST_HOOK.lock()
                && slot
                    .as_ref()
                    .is_some_and(|hook| hook.cycle_id == self.cycle_id)
            {
                *slot = None;
            }
        }
    }

    fn install_provider_invocation_preflight_hook(
        cycle_id: &str,
        reached: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) -> ProviderInvocationPreflightHookReset {
        let mut slot = PROVIDER_INVOCATION_PREFLIGHT_TEST_HOOK
            .lock()
            .expect("install provider invocation preflight hook");
        assert!(slot.is_none(), "provider preflight hook already installed");
        *slot = Some(ProviderInvocationPreflightTestHook {
            cycle_id: cycle_id.to_string(),
            reached,
            release,
        });
        ProviderInvocationPreflightHookReset {
            cycle_id: cycle_id.to_string(),
        }
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m5-integration-{label}-{}-{}",
                std::process::id(),
                TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create isolated M5 test root");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if self.0.exists() && std::env::var_os("KEEP_M5_TEST_ROOT").is_none() {
                fs::remove_dir_all(&self.0).expect("remove isolated M5 test root");
            }
        }
    }

    fn config(directory: &TestDirectory) -> M5RuntimeConfig {
        M5RuntimeConfig {
            root: directory.0.clone(),
            factory_id: "factory:m5-test".to_string(),
            scope_id: "scope:m5-test".to_string(),
            deployment_id: "deployment-m5-test".to_string(),
            worker_max_concurrency: 1,
        }
    }

    fn component_wat(body: &str) -> Vec<u8> {
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

    fn incumbent_wat() -> Vec<u8> {
        component_wat("local.get 0")
    }

    fn n1_wat() -> Vec<u8> {
        component_wat(
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

    fn n1_distinct_wat() -> Vec<u8> {
        component_wat(
            r#"nop
               local.get 0
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

    fn suite() -> ValidationSuite {
        ValidationSuite::new(
            "m5-reference-suite",
            "transform",
            vec![
                ValidationCase::returns("case:one", 1, 2),
                ValidationCase::returns("case:seven", 7, 8),
            ],
            ComponentExecutionLimits::default(),
        )
        .expect("valid M5 proving suite")
    }

    fn gate() -> ReleaseGate {
        let benchmarks = [(1_i32, 2_i32), (7_i32, 8_i32)]
            .into_iter()
            .enumerate()
            .map(|(index, (input, output))| BenchmarkSpec {
                benchmark_id: format!("benchmark:{index}"),
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
            invariant_id: format!("invariant:{index}"),
            kind,
            required: true,
        })
        .collect();
        ReleaseGate::new(
            "m5-reference-gate",
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
        .expect("valid M5 release gate")
    }

    fn compatibility(schema: u32) -> StateCompatibility {
        StateCompatibility {
            readable_schema_min: 1,
            readable_schema_max: 2,
            written_schema: schema,
            incumbent_rollback_readable_through: 2,
        }
    }

    fn initialize(directory: &TestDirectory) -> M5Runtime {
        M5Runtime::initialize(
            config(directory),
            incumbent_wat(),
            suite(),
            gate(),
            1,
            M5InitializationAuthority {
                operator_ref: "operator:m5-test-bootstrap".to_string(),
                rationale: "authorize the exact generation-zero test factory".to_string(),
            },
            None,
        )
        .expect("initialize real M5 runtime")
    }

    fn initialize_with_live_provider(
        directory: &TestDirectory,
        provider: Arc<dyn LiveProviderQualificationPort>,
    ) -> M5Runtime {
        M5Runtime::initialize(
            config(directory),
            incumbent_wat(),
            suite(),
            gate(),
            1,
            M5InitializationAuthority {
                operator_ref: "operator:m5-test-bootstrap".to_string(),
                rationale: "authorize the exact generation-zero test factory".to_string(),
            },
            Some(provider),
        )
        .expect("initialize real M5 runtime with provider")
    }

    fn approved_seed(cycle_id: &str, policy: MutableFactoryPolicy) -> M5SeedCyclePlan {
        M5SeedCyclePlan {
            cycle_id: cycle_id.to_string(),
            challenger_wat_bytes: n1_wat(),
            challenger_policy: policy,
            state_compatibility: compatibility(1),
            migration_plan: None,
            migration_artifacts: None,
            operator_context_digest: ContentDigest::from_bytes(b"operator-context"),
            approval_decision: ApprovalDecision::Approved,
            approver_ref: "operator:m5-test".to_string(),
            approval_rationale: "exact proving, worker, and shadow evidence approved".to_string(),
        }
    }

    fn approved_adopted(cycle_id: &str) -> M5AdoptedCyclePlan {
        M5AdoptedCyclePlan {
            cycle_id: cycle_id.to_string(),
            migration_plan: None,
            migration_artifacts: None,
            operator_context_digest: ContentDigest::from_bytes(b"operator-adopted-context"),
            approval_decision: ApprovalDecision::Approved,
            approver_ref: "operator:m5-test".to_string(),
            approval_rationale: "successor-driven candidate passed the same law".to_string(),
        }
    }

    fn exact_candidate_plan(
        runtime: &M5Runtime,
        cycle_id: &str,
        decision: ApprovalDecision,
    ) -> M5ExactCandidateCyclePlan {
        let incumbent = runtime
            .active_package()
            .expect("active exact-package parent");
        let wat = n1_wat();
        let component = compile_wat(&wat).expect("compile exact candidate");
        let genome = MutableGenome::new(
            Some(incumbent.package_digest.clone()),
            component,
            MutableFactoryPolicy::terminal(2, 2),
        )
        .expect("exact candidate genome");
        let candidate = preview_package(
            &incumbent,
            genome,
            incumbent.payload.boot_manifest.state_compatibility.clone(),
        )
        .expect("deterministic exact candidate package");
        let active_snapshot = runtime
            .capability
            .backend_snapshot()
            .expect("read active snapshot")
            .expect("initialized active snapshot");
        M5ExactCandidateCyclePlan {
            cycle_id: cycle_id.to_string(),
            expected_active_package_digest: incumbent.package_digest,
            expected_active_snapshot_digest: active_snapshot.snapshot_digest,
            expected_release_gate_digest: runtime.release_gate().gate_digest.clone(),
            candidate_package_bytes: candidate.canonical_bytes().expect("candidate bytes"),
            candidate_wat_bytes: wat,
            operator_context_digest: ContentDigest::from_bytes(
                format!("receiver-plan:{cycle_id}").as_bytes(),
            ),
            approval_decision: decision,
            approver_ref: "operator:m5-exact-import".to_string(),
            approval_rationale: "approve the exact receiver-local package and current snapshot"
                .to_string(),
        }
    }

    fn replace_exact_candidate(plan: &mut M5ExactCandidateCyclePlan, package: &FactoryPackage) {
        plan.candidate_package_bytes = package.canonical_bytes().expect("replacement package");
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ExactPreflightFootprint {
        state: ReproductionState,
        snapshot: FactoryRuntimeSnapshot,
        audit: M5EffectAuditReport,
        proving_records: usize,
        recipe_bindings: usize,
        workflow_runs: usize,
        workflow_evidence: usize,
    }

    fn directory_entries(path: &Path) -> usize {
        fs::read_dir(path)
            .expect("read exact preflight footprint directory")
            .count()
    }

    fn exact_preflight_footprint(runtime: &M5Runtime) -> ExactPreflightFootprint {
        let state = runtime.state_snapshot().expect("preflight state");
        ExactPreflightFootprint {
            snapshot: runtime
                .capability
                .backend_snapshot()
                .expect("preflight backend snapshot")
                .expect("initialized backend snapshot"),
            audit: runtime
                .capability
                .audit_reproduction_state(&state)
                .expect("preflight audit"),
            proving_records: directory_entries(&runtime.m1_candidate.root),
            recipe_bindings: directory_entries(&runtime.workers.package_bindings_root),
            workflow_runs: directory_entries(&runtime.workers.workflow_runs_root),
            workflow_evidence: directory_entries(&runtime.workers.workflow_evidence_root),
            state,
        }
    }

    fn assert_exact_preflight_rejected_without_effect(
        runtime: &M5Runtime,
        plan: M5ExactCandidateCyclePlan,
    ) {
        let cycle_id = plan.cycle_id.clone();
        let before = exact_preflight_footprint(runtime);
        assert!(
            runtime.run_exact_candidate_cycle(plan).is_err(),
            "invalid exact candidate plan unexpectedly ran"
        );
        let after = exact_preflight_footprint(runtime);
        assert!(
            after == before,
            "invalid exact-candidate preflight changed the bounded runtime footprint"
        );
        assert!(
            runtime
                .approval
                .package_authorization(&cycle_id)
                .expect("query preflight authorization")
                .is_none()
        );
        assert!(
            runtime
                .state_snapshot()
                .expect("state after preflight rejection")
                .cycle_intents
                .iter()
                .all(|intent| intent.cycle_id != cycle_id)
        );
    }

    #[test]
    fn active_runtime_snapshot_validates_adopted_and_operator_restored_states() {
        let directory = TestDirectory::new("active-runtime-snapshot");
        let runtime = initialize(&directory);
        let incumbent = runtime
            .active_runtime_snapshot()
            .expect("capture incumbent snapshot");
        let outcome = runtime
            .run_seeded_cycle(approved_seed(
                "cycle:active-runtime-snapshot",
                MutableFactoryPolicy::terminal(2, 2),
            ))
            .expect("adopt snapshot fixture");
        assert!(matches!(outcome, CycleOutcome::Adopted { .. }));
        let adopted = runtime
            .active_runtime_snapshot()
            .expect("capture adopted snapshot");
        assert_ne!(adopted.package_digest, incumbent.package_digest);
        assert_eq!(
            adopted.package_digest,
            runtime
                .state_snapshot()
                .expect("adopted reproduction state")
                .active_package_digest
        );

        runtime
            .operator_revert_active(
                "rollback:active-runtime-snapshot",
                &adopted.package_digest,
                "operator:active-runtime-snapshot",
            )
            .expect("restore exact incumbent");
        let restored = runtime
            .active_runtime_snapshot()
            .expect("capture operator-restored snapshot");
        assert_eq!(restored.package_digest, incumbent.package_digest);
        assert_eq!(
            restored.package_digest,
            runtime
                .state_snapshot()
                .expect("restored reproduction state")
                .active_package_digest
        );
        assert!(
            runtime.export_active_adopted_bundle().is_err(),
            "read-only snapshots must not weaken adopted-export eligibility"
        );
    }

    struct CountingProvider {
        live_calls: AtomicU64,
        replay_calls: AtomicU64,
        last_intent: Mutex<Option<ParsedProviderIntent>>,
    }

    impl CountingProvider {
        fn new() -> Self {
            Self {
                live_calls: AtomicU64::new(0),
                replay_calls: AtomicU64::new(0),
                last_intent: Mutex::new(None),
            }
        }
    }

    impl LiveProviderQualificationPort for CountingProvider {
        fn perform_live_turn(
            &self,
            request: &ProviderQualificationRequest,
        ) -> Result<LiveProviderTurn, PortFailure> {
            self.live_calls.fetch_add(1, Ordering::Relaxed);
            let prompt: serde_json::Value = serde_json::from_slice(&request.prompt_bytes)
                .map_err(|error| PortFailure::failed("test_provider_prompt", error.to_string()))?;
            let string_field = |field: &str| {
                prompt
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        PortFailure::failed(
                            "test_provider_prompt",
                            format!("provider prompt has no string field '{field}'"),
                        )
                    })
            };
            let target_genome_digest = serde_json::from_value(
                prompt.get("target_genome_digest").cloned().ok_or_else(|| {
                    PortFailure::failed(
                        "test_provider_prompt",
                        "provider prompt has no target genome digest",
                    )
                })?,
            )
            .map_err(|error| PortFailure::failed("test_provider_prompt", error.to_string()))?;
            let intent = ParsedProviderIntent {
                intent_schema: M5_PROVIDER_INTENT_SCHEMA.to_string(),
                operation: crate::m5_provider_binding::PROVIDER_CANDIDATE_OPERATION.to_string(),
                target_genome_digest,
                arguments: BTreeMap::from([
                    ("cycle_id".to_string(), string_field("cycle_id")?),
                    (
                        "challenger_wat_digest".to_string(),
                        string_field("challenger_wat_digest")?,
                    ),
                    ("policy_digest".to_string(), string_field("policy_digest")?),
                    (
                        "invocation_challenge_digest".to_string(),
                        string_field("invocation_challenge_digest")?,
                    ),
                ]),
            };
            let normalized_parser_input_bytes = serde_json::to_vec(&intent.arguments)
                .map_err(|error| PortFailure::failed("test_provider_intent", error.to_string()))?;
            *self
                .last_intent
                .lock()
                .map_err(|_| PortFailure::failed("test_provider_lock", "lock poisoned"))? =
                Some(intent.clone());
            let transcript = RedactedTranscript {
                request_digest: request.request_digest.clone(),
                redacted_prompt: "[REDACTED PROMPT]".to_string(),
                redacted_response: String::from_utf8(normalized_parser_input_bytes.clone())
                    .map_err(|error| {
                        PortFailure::failed("test_provider_intent", error.to_string())
                    })?,
                raw_prompt_digest: ContentDigest::from_bytes(&request.prompt_bytes),
                raw_response_digest: ContentDigest::from_bytes(b"m5-runtime-provider-response"),
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
                1,
                1,
                2,
                0,
                request.configuration.cost_currency.clone(),
                1,
                vec![M5ProviderAttemptSummaryV1 {
                    attempt_number: 1,
                    http_status: Some(200),
                    latency_ms: 1,
                    retry_classification:
                        crate::execution::inference::InferenceRetryClassification::NoRetryNeeded,
                    request_body_digest: ContentDigest::from_bytes(b"m5-runtime-provider-request"),
                    raw_response_digest: transcript.raw_response_digest.clone(),
                }],
                &transcript,
            )
            .map_err(|error| PortFailure::failed("test_provider_accounting", error.to_string()))?;
            LiveProviderTurn {
                request_digest: request.request_digest.clone(),
                configuration_fingerprint: request.configuration.fingerprint().map_err(
                    |error| PortFailure::failed("test_provider_config", error.to_string()),
                )?,
                replay_capsule_digest: request.replay_capsule.capsule_digest.clone(),
                transport: ProviderTransport::LiveProviderApi,
                external_turn_id: "provider-turn:m5-runtime-replay".to_string(),
                provider_receipt_digest: provider_accounting.accounting_digest.clone(),
                provider_accounting,
                transcript,
                normalized_parser_input_bytes,
                parsed_intent: intent,
                turn_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("test_provider_turn", error.to_string()))
        }

        fn replay_offline(
            &self,
            request: &ProviderReplayRequest,
        ) -> Result<ProviderReplayRecord, PortFailure> {
            self.replay_calls.fetch_add(1, Ordering::Relaxed);
            let intent = self
                .last_intent
                .lock()
                .map_err(|_| PortFailure::failed("test_provider_lock", "lock poisoned"))?
                .clone()
                .ok_or_else(|| {
                    PortFailure::failed("test_provider_intent", "live intent was not retained")
                })?;
            ProviderReplayRecord {
                request_digest: request.request_digest.clone(),
                network_used: false,
                parsed_intent: intent,
                parser_digest: request.expected_parser_digest.clone(),
                replay_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("test_provider_replay", error.to_string()))
        }
    }

    fn governed_provider_config() -> GovernedLiveProviderConfig {
        GovernedLiveProviderConfig {
            provider: InferenceProviderRegistryEntry {
                provider_id: "provider:test-runtime-replay".to_string(),
                provider_mode: InferenceProviderMode::OpenAiResponses,
                models: vec![InferenceProviderModelEntry {
                    model_ref: "model:test-runtime-replay".to_string(),
                    input_cost_per_million_microunits: 0,
                    output_cost_per_million_microunits: 0,
                    supports_json_schema: true,
                    supports_function_tools: true,
                }],
                capability_summary: "test provider terminal runtime replay".to_string(),
                policy_summary: "the counting fixture performs no network call".to_string(),
                active: true,
                api_base_url: "https://api.openai.com".to_string(),
                api_key_env_var: "WASM_BIOTIC_M5_TEST_KEY_THAT_MUST_NOT_EXIST".to_string(),
                organization_env_var: None,
                project_env_var: None,
                request_timeout_ms: 100,
            },
            generation_policy: InferenceGenerationPolicy {
                generation_policy_id: "policy:m5-runtime-replay".to_string(),
                max_output_tokens: 128,
                max_retries: 0,
                summary: "one bounded provider replay fixture turn".to_string(),
            },
        }
    }

    fn governed_provider_request_builder() -> GovernedLiveProviderPort {
        GovernedLiveProviderPort::new(governed_provider_config())
            .expect("build provider request helper")
    }

    #[test]
    fn governed_provider_requires_one_capable_active_model() {
        let mut inactive = governed_provider_config();
        inactive.provider.active = false;
        assert!(matches!(
            GovernedLiveProviderPort::new(inactive),
            Err(M5RuntimeError::InvalidConfig(message))
                if message.contains("active provider")
        ));

        let mut ambiguous = governed_provider_config();
        ambiguous.provider.models.push(InferenceProviderModelEntry {
            model_ref: "model:unselected-second".to_string(),
            input_cost_per_million_microunits: 0,
            output_cost_per_million_microunits: 0,
            supports_json_schema: true,
            supports_function_tools: true,
        });
        assert!(matches!(
            GovernedLiveProviderPort::new(ambiguous),
            Err(M5RuntimeError::InvalidConfig(message))
                if message.contains("exactly one explicitly selected")
        ));

        let mut incapable = governed_provider_config();
        incapable.provider.models[0].supports_function_tools = false;
        assert!(matches!(
            GovernedLiveProviderPort::new(incapable),
            Err(M5RuntimeError::InvalidConfig(message))
                if message.contains("JSON schema output and function tools")
        ));

        let mut excessive_retries = governed_provider_config();
        excessive_retries.generation_policy.max_retries = MAX_M5_PROVIDER_RETRIES as usize + 1;
        assert!(matches!(
            GovernedLiveProviderPort::new(excessive_retries),
            Err(M5RuntimeError::InvalidConfig(message))
                if message.contains("provider retries")
        ));

        let mut zero_output_tokens = governed_provider_config();
        zero_output_tokens.generation_policy.max_output_tokens = 0;
        assert!(matches!(
            GovernedLiveProviderPort::new(zero_output_tokens),
            Err(M5RuntimeError::InvalidConfig(message))
                if message.contains("output-token bound")
        ));

        let mut excessive_output_tokens = governed_provider_config();
        excessive_output_tokens.generation_policy.max_output_tokens =
            M5_LIVE_PROVIDER_MAX_OUTPUT_TOKENS + 1;
        assert!(matches!(
            GovernedLiveProviderPort::new(excessive_output_tokens),
            Err(M5RuntimeError::InvalidConfig(message))
                if message.contains("output-token bound")
        ));

        let mut zero_timeout = governed_provider_config();
        zero_timeout.provider.request_timeout_ms = 0;
        assert!(matches!(
            GovernedLiveProviderPort::new(zero_timeout),
            Err(M5RuntimeError::InvalidConfig(message))
                if message.contains("request timeout")
        ));

        let mut excessive_timeout = governed_provider_config();
        excessive_timeout.provider.request_timeout_ms = M5_LIVE_PROVIDER_MAX_REQUEST_TIMEOUT_MS + 1;
        assert!(matches!(
            GovernedLiveProviderPort::new(excessive_timeout),
            Err(M5RuntimeError::InvalidConfig(message))
                if message.contains("request timeout")
        ));
    }

    #[test]
    fn challenged_provider_seed_binds_fresh_nonce_echo_and_exact_wire_request() {
        let directory = TestDirectory::new("challenged-provider-wire");
        let runtime = initialize(&directory);
        let provider = governed_provider_request_builder();
        let prepared = runtime
            .prepare_provider_backed_seed_cycle(
                "proof-run:challenged-provider-wire",
                "qualification:challenged-provider-wire",
                100,
                &provider,
                approved_seed(
                    "cycle:challenged-provider-wire",
                    MutableFactoryPolicy::terminal(2, 2),
                ),
            )
            .expect("prepare exact unbound provider seed");
        let manifest_digest = ContentDigest::from_bytes(b"manifest:challenged-provider-wire");
        let scope_digest = ContentDigest::from_bytes(b"scope:challenged-provider-wire");
        let challenged_a = M5ChallengedProviderSeedV1::derive(
            &prepared,
            manifest_digest.clone(),
            scope_digest.clone(),
            [0x11; M5_PROVIDER_RUN_NONCE_BYTES],
        )
        .expect("derive first current-call challenge");
        let challenged_b = M5ChallengedProviderSeedV1::derive(
            &prepared,
            manifest_digest,
            scope_digest,
            [0x22; M5_PROVIDER_RUN_NONCE_BYTES],
        )
        .expect("derive second current-call challenge");

        assert_ne!(
            challenged_a.challenge().invocation_challenge_digest(),
            challenged_b.challenge().invocation_challenge_digest()
        );
        assert_ne!(
            challenged_a.qualification_request().request_digest,
            challenged_b.qualification_request().request_digest
        );
        assert_ne!(
            challenged_a.provider_wire_request().request_body_digest(),
            challenged_b.provider_wire_request().request_body_digest()
        );
        assert_ne!(
            challenged_a.provider_wire_request().wire_request_digest(),
            challenged_b.provider_wire_request().wire_request_digest()
        );

        let prompt: serde_json::Value =
            serde_json::from_slice(&challenged_a.qualification_request().prompt_bytes)
                .expect("decode challenged provider prompt");
        let expected_challenge = challenged_a
            .challenge()
            .invocation_challenge_digest()
            .as_str();
        assert_eq!(
            prompt
                .get("invocation_challenge_digest")
                .and_then(serde_json::Value::as_str),
            Some(expected_challenge)
        );
        assert_eq!(
            prompt
                .get("required_response")
                .and_then(|value| value.get("arguments"))
                .and_then(|value| value.get("invocation_challenge_digest"))
                .and_then(serde_json::Value::as_str),
            Some(expected_challenge)
        );
        let request_body: serde_json::Value = serde_json::from_slice(
            challenged_a
                .provider_wire_request()
                .canonical_request_body_bytes(),
        )
        .expect("decode exact challenged request body");
        assert!(request_body.to_string().contains(expected_challenge));

        let mut wrong_echo = challenged_a.clone();
        let mut wrong_prompt: serde_json::Value =
            serde_json::from_slice(&wrong_echo.qualification_request.prompt_bytes)
                .expect("decode prompt for echo tamper");
        wrong_prompt["required_response"]["arguments"]["invocation_challenge_digest"] =
            serde_json::Value::String(ContentDigest::from_bytes(b"wrong-echo").to_string());
        wrong_echo.qualification_request.prompt_bytes =
            serde_json::to_vec(&wrong_prompt).expect("encode wrong echo");
        assert!(wrong_echo.validate_for(&prepared).is_err());

        let mut wrong_wire = challenged_a.clone();
        wrong_wire
            .provider_wire_request
            .canonical_request_body_bytes
            .push(b' ');
        assert!(wrong_wire.validate_for(&prepared).is_err());

        let mut wrong_endpoint = challenged_a.clone();
        wrong_endpoint.provider_wire_request.endpoint_class =
            M5ProviderEndpointClassV1::LoopbackTest;
        assert!(wrong_endpoint.validate_for(&prepared).is_err());
    }

    #[test]
    fn current_manifest_provider_invocation_holds_gate_against_same_plan_cycle() {
        assert!(
            std::env::var_os("WASM_BIOTIC_M5_TEST_KEY_THAT_MUST_NOT_EXIST").is_none(),
            "the no-credential provider fixture unexpectedly has a credential"
        );
        let directory = TestDirectory::new("provider-vs-ordinary-operation-gate");
        let provider = Arc::new(governed_provider_request_builder());
        let runtime = Arc::new(
            M5Runtime::initialize_with_governed_live_provider(
                config(&directory),
                incumbent_wat(),
                suite(),
                gate(),
                1,
                M5InitializationAuthority {
                    operator_ref: "operator:m5-test-bootstrap".to_string(),
                    rationale: "authorize the exact generation-zero test factory".to_string(),
                },
                provider.clone(),
            )
            .expect("initialize concrete governed-provider runtime"),
        );
        let proof_run_id = "proof-run:provider-vs-ordinary-operation-gate";
        let prepared = runtime
            .prepare_provider_backed_seed_cycle(
                proof_run_id,
                "qualification:provider-vs-ordinary-operation-gate",
                150,
                &provider,
                approved_seed(
                    "cycle:provider-vs-ordinary-operation-gate",
                    MutableFactoryPolicy::terminal(2, 2),
                ),
            )
            .expect("freeze same-plan provider seed");
        let scope = LiveProviderQualificationScope::from_prepared(&prepared)
            .expect("derive exact provider scope");
        let manifest = crate::m7_closure::tests::manifest_for_proof_run(proof_run_id, Some(scope));

        let provider_reached = Arc::new(std::sync::Barrier::new(2));
        let release_provider = Arc::new(std::sync::Barrier::new(2));
        let _hook_reset = install_provider_invocation_preflight_hook(
            &prepared.plan.cycle_id,
            Arc::clone(&provider_reached),
            Arc::clone(&release_provider),
        );
        let provider_runtime = Arc::clone(&runtime);
        let provider_prepared = prepared.clone();
        let provider_thread = thread::spawn(move || {
            provider_runtime.run_current_manifest_provider_invocation(&manifest, provider_prepared)
        });

        provider_reached.wait();
        assert!(matches!(
            runtime.operation_gate.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        let state_at_locked_preflight = runtime
            .state_snapshot()
            .expect("read state at locked provider preflight");
        assert!(state_at_locked_preflight.cycle_intents.is_empty());
        assert!(state_at_locked_preflight.cycles.is_empty());
        assert!(state_at_locked_preflight.provider_qualifications.is_empty());

        let ordinary_started = Arc::new(std::sync::Barrier::new(2));
        let ordinary_runtime = Arc::clone(&runtime);
        let ordinary_plan = prepared.plan.clone();
        let ordinary_started_in_thread = Arc::clone(&ordinary_started);
        let ordinary_thread = thread::spawn(move || {
            ordinary_started_in_thread.wait();
            ordinary_runtime.run_seeded_cycle(ordinary_plan)
        });
        ordinary_started.wait();
        assert!(matches!(
            runtime.operation_gate.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));

        // The high-level provider call still owns the gate when released from
        // the deterministic preflight barrier. It must record its challenged
        // qualification outcome before the ordinary same-plan cycle can enter.
        release_provider.wait();
        let provider_error = provider_thread
            .join()
            .expect("provider invocation thread")
            .expect_err("missing credential must fail the governed live turn");
        assert!(matches!(
            provider_error,
            M5RuntimeError::ProviderNotQualified(record)
                if record.status == ProviderQualificationStatus::Unavailable
        ));
        assert!(matches!(
            ordinary_thread.join().expect("ordinary cycle thread"),
            Ok(CycleOutcome::Adopted { .. })
        ));

        let terminal = runtime.state_snapshot().expect("terminal raced state");
        assert_eq!(terminal.provider_qualifications.len(), 1);
        assert_eq!(
            terminal.provider_qualifications[0].status,
            ProviderQualificationStatus::Unavailable
        );
        assert_eq!(terminal.cycle_intents.len(), 1);
        assert_eq!(terminal.cycles.len(), 1);
    }

    #[test]
    fn provider_accounting_cross_checks_multi_attempt_bundle_and_retains_only_digests() {
        let mut config = governed_provider_config();
        config.provider.provider_mode = InferenceProviderMode::OpenRouterChatCompletions;
        config.provider.api_base_url =
            "https://openrouter.invalid/DO_NOT_RETAIN_API_URL".to_string();
        config.provider.api_key_env_var = "DO_NOT_RETAIN_API_KEY_ENV".to_string();
        config.provider.organization_env_var = Some("DO_NOT_RETAIN_ORGANIZATION_ENV".to_string());
        config.provider.project_env_var = Some("DO_NOT_RETAIN_PROJECT_ENV".to_string());
        config.provider.capability_summary = "DO_NOT_RETAIN_CAPABILITY_SUMMARY".to_string();
        config.provider.policy_summary = "DO_NOT_RETAIN_PROVIDER_POLICY_SUMMARY".to_string();
        config.provider.models[0].input_cost_per_million_microunits = 1_000_000;
        config.provider.models[0].output_cost_per_million_microunits = 2_500_000;
        config.generation_policy.max_retries = 1;
        config.generation_policy.summary = "DO_NOT_RETAIN_GENERATION_SUMMARY".to_string();
        let port = GovernedLiveProviderPort::new(config.clone())
            .expect("build governed provider mapper fixture");
        let mut expected_configuration = port.provider_configuration().clone();
        let turn_request = InferenceTurnRequest {
            turn_request_id: "turn:m5-accounting".to_string(),
            provider_ref: config.provider.provider_id.clone(),
            model_ref: config.provider.models[0].model_ref.clone(),
            rendered_prompt_ref: "prompt:m5-accounting".to_string(),
            tool_catalog_ref: "tools:m5-accounting".to_string(),
            response_schema_ref: "schema:m5-accounting".to_string(),
            generation_policy_ref: config.generation_policy.generation_policy_id.clone(),
        };
        let rendered_prompt = InferenceRenderedPromptRecord {
            rendered_prompt_id: turn_request.rendered_prompt_ref.clone(),
            turn_request_ref: turn_request.turn_request_id.clone(),
            prompt_text: "DO_NOT_RETAIN_RENDERED_PROMPT".to_string(),
            created_at: "test-time".to_string(),
        };
        let tool_catalog = InferenceToolCatalogPayloadRecord {
            tool_catalog_id: turn_request.tool_catalog_ref.clone(),
            turn_request_ref: turn_request.turn_request_id.clone(),
            tool_catalog_json: r#"[{"type":"function","name":"DO_NOT_RETAIN_TOOL_CONTENT"}]"#
                .to_string(),
            created_at: "test-time".to_string(),
        };
        // Exercise the mapper with a sensitive catalog payload while still
        // binding it to the exact configuration supplied to the mapper.
        expected_configuration.tool_catalog_digest =
            ContentDigest::from_bytes(tool_catalog.tool_catalog_json.as_bytes());
        let response_schema = InferenceResponseSchemaPayloadRecord {
            response_schema_id: turn_request.response_schema_ref.clone(),
            turn_request_ref: turn_request.turn_request_id.clone(),
            response_schema_json: provider_response_schema_json(),
            created_at: "test-time".to_string(),
        };
        let request_body_records = vec![
            InferenceRequestBodyRecord {
                request_body_id: "request-body:DO_NOT_RETAIN_FIRST_REQUEST_ID".to_string(),
                turn_request_ref: turn_request.turn_request_id.clone(),
                attempt_number: 1,
                request_body_json: r#"{"secret":"DO_NOT_RETAIN_FIRST_REQUEST_CONTENT"}"#
                    .to_string(),
                created_at: "test-time".to_string(),
            },
            InferenceRequestBodyRecord {
                request_body_id: "request-body:DO_NOT_RETAIN_SECOND_REQUEST_ID".to_string(),
                turn_request_ref: turn_request.turn_request_id.clone(),
                attempt_number: 2,
                request_body_json: r#"{"secret":"DO_NOT_RETAIN_FIRST_REQUEST_CONTENT"}"#
                    .to_string(),
                created_at: "test-time".to_string(),
            },
        ];
        let raw_output_records = vec![
            InferenceRawOutputRecord {
                raw_output_id: "raw-output:DO_NOT_RETAIN_FIRST_RESPONSE_ID".to_string(),
                turn_request_ref: turn_request.turn_request_id.clone(),
                provider_ref: turn_request.provider_ref.clone(),
                model_ref: turn_request.model_ref.clone(),
                attempt_number: 1,
                raw_output_payload: "DO_NOT_RETAIN_FIRST_RESPONSE_CONTENT".to_string(),
                created_at: "test-time".to_string(),
            },
            InferenceRawOutputRecord {
                raw_output_id: "raw-output:DO_NOT_RETAIN_SECOND_RESPONSE_ID".to_string(),
                turn_request_ref: turn_request.turn_request_id.clone(),
                provider_ref: turn_request.provider_ref.clone(),
                model_ref: turn_request.model_ref.clone(),
                attempt_number: 2,
                raw_output_payload: "DO_NOT_RETAIN_SECOND_RESPONSE_CONTENT".to_string(),
                created_at: "test-time".to_string(),
            },
        ];
        let attempts = vec![
            InferenceAttemptRecord {
                attempt_id: "attempt:DO_NOT_RETAIN_FIRST_ATTEMPT_ID".to_string(),
                turn_request_ref: turn_request.turn_request_id.clone(),
                attempt_number: 1,
                request_body_ref: request_body_records[0].request_body_id.clone(),
                raw_response_body_ref: raw_output_records[0].raw_output_id.clone(),
                http_status: Some(500),
                latency_ms: 3,
                retry_classification: InferenceRetryClassification::RetriedServerError,
                provider_response_id: Some("DO_NOT_RETAIN_FIRST_PROVIDER_RESPONSE_ID".to_string()),
                provider_request_id: Some("DO_NOT_RETAIN_FIRST_PROVIDER_REQUEST_ID".to_string()),
                transport_error_summary: Some("DO_NOT_RETAIN_TRANSPORT_ERROR_SUMMARY".to_string()),
                created_at: "test-time".to_string(),
            },
            InferenceAttemptRecord {
                attempt_id: "attempt:DO_NOT_RETAIN_SECOND_ATTEMPT_ID".to_string(),
                turn_request_ref: turn_request.turn_request_id.clone(),
                attempt_number: 2,
                request_body_ref: request_body_records[1].request_body_id.clone(),
                raw_response_body_ref: raw_output_records[1].raw_output_id.clone(),
                http_status: Some(200),
                latency_ms: 5,
                retry_classification: InferenceRetryClassification::NoRetryNeeded,
                provider_response_id: Some("DO_NOT_RETAIN_SECOND_PROVIDER_RESPONSE_ID".to_string()),
                provider_request_id: Some("DO_NOT_RETAIN_SECOND_PROVIDER_REQUEST_ID".to_string()),
                transport_error_summary: None,
                created_at: "test-time".to_string(),
            },
        ];
        let usage_record = InferenceUsageRecord {
            usage_record_id: "usage:m5-accounting".to_string(),
            turn_request_ref: turn_request.turn_request_id.clone(),
            input_tokens: 2,
            output_tokens: 3,
            total_tokens: 5,
            latency_ms: 8,
            estimated_cost_microunits: 9,
            currency: "usd".to_string(),
            created_at: "test-time".to_string(),
        };
        let attempt_refs: Vec<String> = attempts
            .iter()
            .map(|attempt| attempt.attempt_id.clone())
            .collect();
        let provider_outcome = InferenceProviderOutcomeRecord {
            provider_outcome_id: "outcome:m5-accounting".to_string(),
            turn_request_ref: turn_request.turn_request_id.clone(),
            provider_ref: turn_request.provider_ref.clone(),
            model_ref: turn_request.model_ref.clone(),
            finish_reason: InferenceFinishReason::Completed,
            final_http_status: Some(200),
            attempt_refs: attempt_refs.clone(),
            refusal_summary: Some("DO_NOT_RETAIN_REFUSAL_SUMMARY".to_string()),
            provider_response_id: Some("DO_NOT_RETAIN_OUTCOME_RESPONSE_ID".to_string()),
            provider_request_id: Some("DO_NOT_RETAIN_OUTCOME_REQUEST_ID".to_string()),
            input_tokens: 2,
            output_tokens: 3,
            total_tokens: 5,
            latency_ms: 8,
            estimated_cost_microunits: 9,
            currency: "usd".to_string(),
            created_at: "test-time".to_string(),
        };
        let turn_result = InferenceTurnResult {
            turn_result_id: "result:m5-accounting".to_string(),
            turn_request_ref: turn_request.turn_request_id.clone(),
            raw_output_ref: raw_output_records[1].raw_output_id.clone(),
            parsed_output_ref: None,
            finish_reason: InferenceFinishReason::Completed,
            usage_record_ref: usage_record.usage_record_id.clone(),
            provider_outcome_ref: provider_outcome.provider_outcome_id.clone(),
            attempt_refs,
            provider_metadata_refs: vec!["DO_NOT_RETAIN_PROVIDER_METADATA_ID".to_string()],
            degradation_ref: None,
            created_at: "test-time".to_string(),
        };
        let bundle = InferenceTurnBundle {
            turn_request,
            generation_policy: config.generation_policy.clone(),
            rendered_prompt,
            tool_catalog,
            response_schema,
            request_body_records,
            raw_output_records,
            usage_record,
            attempts,
            provider_outcome,
            parsed_output: None,
            turn_result,
            degradation_record: None,
        };
        bundle
            .validate()
            .expect("valid multi-attempt inference bundle");
        let transcript = RedactedTranscript {
            request_digest: ContentDigest::from_bytes(b"accounting-request"),
            redacted_prompt: "[REDACTED PROMPT]".to_string(),
            redacted_response: "[REDACTED RESPONSE]".to_string(),
            raw_prompt_digest: ContentDigest::from_bytes(
                bundle.rendered_prompt.prompt_text.as_bytes(),
            ),
            raw_response_digest: ContentDigest::from_bytes(
                b"DO_NOT_RETAIN_SECOND_RESPONSE_CONTENT",
            ),
            redaction_applied: true,
        };

        let accounting =
            provider_accounting_from_bundle(&config, &expected_configuration, &bundle, &transcript)
                .expect("map cross-checked provider accounting");
        assert_eq!(
            accounting.provider_profile,
            M5ProviderProfileV1::OpenRouterChatCompletions
        );
        assert_eq!(accounting.maximum_retries, 1);
        assert_eq!(accounting.attempts.len(), 2);
        assert_eq!(
            accounting.attempts[0].request_body_digest, accounting.attempts[1].request_body_digest,
            "every retry must bind the same frozen request body"
        );
        assert_eq!(accounting.total_latency_ms, 8);
        assert_eq!(
            accounting.attempts[1].raw_response_digest,
            transcript.raw_response_digest
        );
        let retained_turn = LiveProviderTurn {
            request_digest: transcript.request_digest.clone(),
            configuration_fingerprint: expected_configuration
                .fingerprint()
                .expect("configuration fingerprint"),
            replay_capsule_digest: ContentDigest::from_bytes(b"test-replay-capsule"),
            transport: ProviderTransport::LiveProviderApi,
            external_turn_id: redacted_provider_turn_id(&accounting),
            provider_receipt_digest: accounting.accounting_digest.clone(),
            provider_accounting: accounting.clone(),
            transcript: transcript.clone(),
            normalized_parser_input_bytes: transcript.redacted_response.as_bytes().to_vec(),
            parsed_intent: ParsedProviderIntent {
                intent_schema: M5_PROVIDER_INTENT_SCHEMA.to_string(),
                operation: "candidate.materialize_patchset".to_string(),
                target_genome_digest: ContentDigest::from_bytes(b"accounting-target"),
                arguments: BTreeMap::new(),
            },
            turn_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .expect("seal retained redacted provider turn");
        let serialized = serde_json::to_string(&retained_turn).expect("serialize retained turn");
        for forbidden in [
            "DO_NOT_RETAIN_API_URL",
            "DO_NOT_RETAIN_API_KEY_ENV",
            "DO_NOT_RETAIN_ORGANIZATION_ENV",
            "DO_NOT_RETAIN_PROJECT_ENV",
            "DO_NOT_RETAIN_CAPABILITY_SUMMARY",
            "DO_NOT_RETAIN_PROVIDER_POLICY_SUMMARY",
            "DO_NOT_RETAIN_GENERATION_SUMMARY",
            "DO_NOT_RETAIN_RENDERED_PROMPT",
            "DO_NOT_RETAIN_TOOL_CONTENT",
            "DO_NOT_RETAIN_FIRST_REQUEST_CONTENT",
            "DO_NOT_RETAIN_SECOND_REQUEST_CONTENT",
            "DO_NOT_RETAIN_FIRST_RESPONSE_CONTENT",
            "DO_NOT_RETAIN_SECOND_RESPONSE_CONTENT",
            "DO_NOT_RETAIN_FIRST_PROVIDER_RESPONSE_ID",
            "DO_NOT_RETAIN_SECOND_PROVIDER_REQUEST_ID",
            "DO_NOT_RETAIN_TRANSPORT_ERROR_SUMMARY",
            "DO_NOT_RETAIN_REFUSAL_SUMMARY",
            "DO_NOT_RETAIN_PROVIDER_METADATA_ID",
        ] {
            assert!(!serialized.contains(forbidden), "retained {forbidden}");
        }
        assert!(
            !serialized.contains("DO_NOT_RETAIN_"),
            "accounting retained an unenumerated sensitive fixture marker: {serialized}"
        );

        let mut inconsistent_bundle = bundle.clone();
        inconsistent_bundle.usage_record.input_tokens += 1;
        inconsistent_bundle.usage_record.total_tokens += 1;
        inconsistent_bundle
            .validate()
            .expect("generic bundle validation does not cross-check usage against outcome");
        let failure = provider_accounting_from_bundle(
            &config,
            &expected_configuration,
            &inconsistent_bundle,
            &transcript,
        )
        .expect_err("M5 accounting must reject divergent usage and outcome totals");
        assert_eq!(failure.code, "live_provider_accounting_inconsistent");

        let mut substituted_catalog = bundle.clone();
        substituted_catalog.tool_catalog.tool_catalog_json =
            r#"[{"type":"function","name":"substituted"}]"#.to_string();
        substituted_catalog
            .validate()
            .expect("generic bundle validation accepts a different valid catalog payload");
        let failure = provider_accounting_from_bundle(
            &config,
            &expected_configuration,
            &substituted_catalog,
            &transcript,
        )
        .expect_err("M5 accounting must reject a substituted tool catalog");
        assert_eq!(failure.code, "live_provider_accounting_inconsistent");

        let mut wrong_prompt_transcript = transcript.clone();
        wrong_prompt_transcript.raw_prompt_digest = ContentDigest::from_bytes(b"wrong-prompt");
        let failure = provider_accounting_from_bundle(
            &config,
            &expected_configuration,
            &bundle,
            &wrong_prompt_transcript,
        )
        .expect_err("M5 accounting must bind the exact rendered prompt digest");
        assert_eq!(failure.code, "live_provider_accounting_inconsistent");

        let mut wrong_cost = bundle.clone();
        wrong_cost.usage_record.estimated_cost_microunits += 1;
        wrong_cost.provider_outcome.estimated_cost_microunits += 1;
        wrong_cost
            .validate()
            .expect("generic bundle validation accepts internally matching copied cost fields");
        let failure = provider_accounting_from_bundle(
            &config,
            &expected_configuration,
            &wrong_cost,
            &transcript,
        )
        .expect_err("M5 accounting must independently recompute estimated provider cost");
        assert_eq!(failure.code, "live_provider_accounting_inconsistent");
    }

    #[test]
    fn governed_provider_normalizes_exact_tool_arguments_without_loosening_target_binding() {
        let provider = governed_provider_request_builder();
        let expected = LiveIntentWire {
            operation: crate::m5_provider_binding::PROVIDER_CANDIDATE_OPERATION.to_string(),
            target_genome_digest: ContentDigest::from_bytes(b"exact-provider-target-genome"),
            arguments: BTreeMap::from([
                ("cycle_id".to_string(), "cycle:exact-tool-call".to_string()),
                (
                    "challenger_wat_digest".to_string(),
                    ContentDigest::from_bytes(b"exact-tool-call-wat")
                        .as_str()
                        .to_string(),
                ),
                (
                    "policy_digest".to_string(),
                    ContentDigest::from_bytes(b"exact-tool-call-policy")
                        .as_str()
                        .to_string(),
                ),
                (
                    "invocation_challenge_digest".to_string(),
                    ContentDigest::from_bytes(b"exact-tool-call-challenge")
                        .as_str()
                        .to_string(),
                ),
            ]),
        };
        let tool_arguments =
            serde_json::to_string(&expected.arguments).expect("exact tool arguments JSON");
        let parsed = provider
            .parse_intent(&tool_arguments, &expected)
            .expect("normalize exact function-tool arguments");
        assert_eq!(parsed.operation, expected.operation);
        assert_eq!(parsed.target_genome_digest, expected.target_genome_digest);
        assert_eq!(parsed.arguments, expected.arguments);

        let mut changed = expected.arguments.clone();
        changed.insert("cycle_id".to_string(), "cycle:changed".to_string());
        let changed = serde_json::to_string(&changed).expect("changed arguments JSON");
        let error = provider
            .parse_intent(&changed, &expected)
            .expect_err("changed tool arguments cannot borrow the frozen target");
        assert_eq!(error.code, "provider_intent_target_mismatch");

        let synthesized_full_wire =
            serde_json::to_string(&expected).expect("synthesized full intent wire JSON");
        let error = provider
            .parse_intent(&synthesized_full_wire, &expected)
            .expect_err("offline replay must not accept a different full-wire parser branch");
        assert_eq!(error.code, "provider_intent_parse_failed");
    }

    #[test]
    fn exact_candidate_cycle_adopts_restarts_replays_and_changes_active_execution() {
        let directory = TestDirectory::new("m5-exact-adopt-replay");
        let runtime = initialize(&directory);
        let before = runtime.execute_active(7).expect("execute exact incumbent");
        assert_eq!(before.output, 7);
        let plan = exact_candidate_plan(
            &runtime,
            "cycle:exact-adopt-replay",
            ApprovalDecision::Approved,
        );
        let expected_candidate =
            FactoryPackage::from_canonical_bytes(&plan.candidate_package_bytes)
                .expect("parse planned exact candidate");
        let before_inspection = runtime.state_snapshot().expect("state before inspection");
        assert!(
            runtime
                .inspect_exact_candidate_cycle(&plan)
                .expect("inspect absent exact cycle")
                .is_none(),
            "inspection must not manufacture missing exact-cycle work"
        );
        let after_inspection = runtime.state_snapshot().expect("state after inspection");
        assert!(
            after_inspection == before_inspection,
            "inspection of an absent cycle must not mutate M5"
        );
        let first = runtime
            .run_exact_candidate_cycle(plan.clone())
            .expect("adopt exact candidate");
        first.validate().expect("validate exact adoption result");
        let inspected = runtime
            .inspect_exact_candidate_cycle(&plan)
            .expect("inspect terminal exact cycle")
            .expect("terminal exact cycle exists");
        assert!(
            inspected == first,
            "inspection must re-derive the complete authoritative result"
        );
        assert!(matches!(first.outcome, CycleOutcome::Adopted { .. }));
        assert_eq!(
            first.active_snapshot.package_digest,
            expected_candidate.package_digest
        );
        assert_ne!(
            first.supplied_operator_context_digest,
            first.bound_operator_context_digest
        );
        let reopen_config = runtime.config().clone();
        drop(runtime);

        let reopened =
            M5Runtime::open(reopen_config, None).expect("reopen exact candidate runtime");
        let reopened_inspection = reopened
            .inspect_exact_candidate_cycle(&plan)
            .expect("inspect exact cycle after restart")
            .expect("terminal exact cycle survives restart");
        assert!(
            reopened_inspection == first,
            "reopened exact-cycle inspection differed from the authoritative result"
        );
        let replayed = reopened
            .run_exact_candidate_cycle(plan.clone())
            .expect("exact terminal replay");
        replayed.validate().expect("validate replayed result");
        assert_eq!(replayed.outcome, first.outcome);
        assert!(
            replayed.cycle_record == first.cycle_record,
            "exact terminal replay returned a different evidence-bearing cycle record"
        );
        assert_eq!(
            replayed.bound_operator_context_digest,
            first.bound_operator_context_digest
        );
        let after = reopened
            .execute_active(7)
            .expect("execute adopted exact component");
        assert_eq!(after.output, 8);
        assert_eq!(after.package_digest, expected_candidate.package_digest);
        assert_eq!(
            after.component_digest,
            expected_candidate.payload.genome.component_digest
        );

        let mut changed = plan;
        changed.candidate_wat_bytes.extend_from_slice(b"\n");
        assert!(matches!(
            reopened.run_exact_candidate_cycle(changed),
            Err(M5RuntimeError::Conflict(_))
        ));
    }

    #[test]
    fn exact_candidate_cycle_health_failure_rolls_back_actual_active_execution() {
        let directory = TestDirectory::new("m5-exact-health-rollback");
        let runtime = initialize(&directory);
        let cycle_id = "cycle:exact-health-rollback";
        let incumbent = runtime.active_package().expect("exact incumbent");
        let before = runtime
            .execute_active(7)
            .expect("execute before exact rollback");
        runtime
            .induce_next_health_regression()
            .expect("arm exact observation failure");
        let result = runtime
            .run_exact_candidate_cycle(exact_candidate_plan(
                &runtime,
                cycle_id,
                ApprovalDecision::Approved,
            ))
            .expect("run exact candidate with unhealthy observation");
        result.validate().expect("validate exact rollback result");
        assert!(matches!(
            result.outcome,
            CycleOutcome::QuarantinedAndRolledBack { .. }
        ));
        assert_eq!(
            result.active_snapshot.package_digest,
            incumbent.package_digest
        );
        assert!(result.cycle_record.activation_receipt.is_some());
        assert!(result.cycle_record.observation_evidence.is_some());
        assert!(result.cycle_record.recovery_receipt.is_some());
        assert!(result.effect_audit.entries.iter().any(|entry| {
            entry.kind == M5EffectAuditKind::Recovery
                && entry
                    .evidence_id
                    .split('|')
                    .any(|alias| alias == "cycle:cycle:exact-health-rollback:recovery")
        }));
        let after = runtime
            .execute_active(7)
            .expect("execute restored incumbent");
        assert_eq!(before.output, 7);
        assert_eq!(after.output, 7);
        assert_eq!(after.package_digest, incumbent.package_digest);
        assert_eq!(after.component_digest, before.component_digest);

        let probe = runtime
            .capture_post_rollback_probe(cycle_id, 23)
            .expect("execute and audit fresh post-rollback behavior");
        assert_eq!(probe.cycle_id(), cycle_id);
        assert_eq!(probe.restored_package_digest(), &incumbent.package_digest);
        assert_eq!(probe.execution().input, 23);
        assert_eq!(probe.execution().output, 23);
        assert_eq!(
            probe.effect_audit().entries.len(),
            probe.prior_effect_audit().entries.len() + 1
        );
        let bytes = probe.canonical_bytes().expect("canonical probe bytes");
        let reopened_probe = M5PostRollbackProbeV1::from_canonical_bytes(&bytes)
            .expect("reopen detached post-rollback probe");
        assert!(
            reopened_probe == probe,
            "detached post-rollback probe differed from its canonical source"
        );
        assert!(matches!(
            runtime.capture_post_rollback_probe(cycle_id, 23),
            Err(M5RuntimeError::Conflict(_))
        ));
    }

    #[test]
    fn final_post_rollback_probe_is_causally_after_m6_and_live_m2_restart() {
        let directory = TestDirectory::new("m5-final-chronology-probe");
        let runtime = initialize(&directory);
        runtime
            .run_seeded_cycle(approved_seed(
                "cycle:chronology-adopted",
                MutableFactoryPolicy::terminal(2, 2),
            ))
            .expect("adopt chronology export parent");
        let rollback_cycle_id = "cycle:chronology-rollback";
        runtime
            .induce_next_health_regression()
            .expect("arm chronology rollback");
        let mut rollback_seed =
            approved_seed(rollback_cycle_id, MutableFactoryPolicy::terminal(3, 2));
        rollback_seed.challenger_wat_bytes = n1_distinct_wat();
        let rollback = runtime
            .run_seeded_cycle(rollback_seed)
            .expect("run chronology rollback");
        assert!(matches!(
            rollback,
            CycleOutcome::QuarantinedAndRolledBack { .. }
        ));

        // Model the earlier M6-internal probe. The later final proof must add
        // its own fresh challenged M3 execution rather than reusing this one.
        runtime
            .capture_post_rollback_probe(rollback_cycle_id, 23)
            .expect("capture earlier internal rollback probe");
        let export = runtime
            .export_active_adopted_bundle()
            .expect("freeze exact post-rollback export");
        let export_bytes = export
            .canonical_bytes()
            .expect("canonical chronology export");
        let export_digest = ContentDigest::from_bytes(&export_bytes);
        let manifest_digest = ContentDigest::from_bytes(b"manifest:final-chronology");
        let m6_digest = ContentDigest::from_bytes(b"m6-completion:final-chronology");
        let anchor = &export.active_cycle().m4_workflows()[0]
            .workflow()
            .lifecycle_anchor;
        let capture = runtime
            .capture_post_export_m2_restart_with_completion_digest_for_test(
                manifest_digest.clone(),
                export_digest.clone(),
                m6_digest.clone(),
                &anchor.m2_job_id,
                anchor.terminal_job_digest.clone(),
            )
            .expect("capture chronology M2 restart");

        assert!(matches!(
            runtime.capture_final_post_rollback_probe_with_completion_digest_for_test(
                rollback_cycle_id,
                29,
                manifest_digest.clone(),
                export_digest.clone(),
                ContentDigest::from_bytes(b"m6-completion:changed"),
                &capture,
            ),
            Err(M5RuntimeError::Integrity(_))
        ));
        let mut changed_capture = capture.clone();
        changed_capture.capture_digest = ContentDigest::from_bytes(b"changed-m2-capture");
        assert!(matches!(
            runtime.capture_final_post_rollback_probe_with_completion_digest_for_test(
                rollback_cycle_id,
                29,
                manifest_digest.clone(),
                export_digest.clone(),
                m6_digest.clone(),
                &changed_capture,
            ),
            Err(M5RuntimeError::Integrity(_))
        ));

        let state_path = fs::read_dir(directory.0.join("m4-recipes/workflow-runs"))
            .expect("read chronology workflow roots")
            .map(|entry| {
                entry
                    .expect("chronology workflow root")
                    .path()
                    .join("m2-supervisor/supervisor-state.json")
            })
            .find(|path| {
                fs::read(path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<SupervisorState>(&bytes).ok())
                    .is_some_and(|state| state.jobs.contains_key(&anchor.m2_job_id))
            })
            .expect("locate chronology supervisor state");
        fs::write(&state_path, capture.pre_restart_supervisor_state_bytes())
            .expect("regress live chronology state");
        assert!(matches!(
            runtime.capture_final_post_rollback_probe_with_completion_digest_for_test(
                rollback_cycle_id,
                29,
                manifest_digest.clone(),
                export_digest.clone(),
                m6_digest.clone(),
                &capture,
            ),
            Err(M5RuntimeError::Conflict(_))
        ));
        fs::write(&state_path, capture.post_restart_supervisor_state_bytes())
            .expect("restore live chronology state");

        let final_probe = runtime
            .capture_final_post_rollback_probe_with_completion_digest_for_test(
                rollback_cycle_id,
                29,
                manifest_digest.clone(),
                export_digest,
                m6_digest.clone(),
                &capture,
            )
            .expect("capture final chronology-bound probe");
        assert_eq!(
            final_probe
                .probe()
                .execution()
                .causal_context_digest
                .as_ref(),
            Some(final_probe.causal_execution_context_digest())
        );
        assert_eq!(
            final_probe.m2_restart_capture_digest(),
            capture.capture_digest()
        );
        let causal_inner_bytes = final_probe
            .probe()
            .canonical_bytes()
            .expect("canonical causally bound inner probe");
        assert!(M5PostRollbackProbeV1::from_canonical_bytes(&causal_inner_bytes).is_err());
        let ordinary_probe_bytes = runtime
            .capture_post_rollback_probe(rollback_cycle_id, 31)
            .expect("capture later ordinary V1 probe")
            .canonical_bytes()
            .expect("canonical ordinary V1 probe");
        assert!(
            M5CausallyBoundPostRollbackProbeV1::from_canonical_bytes(&ordinary_probe_bytes)
                .is_err()
        );
        let final_bytes = final_probe
            .canonical_bytes()
            .expect("canonical final probe");
        assert_eq!(
            M5FinalPostRollbackProbeV1::from_canonical_bytes(&final_bytes)
                .expect("detached final probe"),
            final_probe
        );

        for (field, changed) in [
            (
                "m6_completion_bundle_content_digest",
                ContentDigest::from_bytes(b"m6-completion:spliced"),
            ),
            (
                "m2_restart_capture_digest",
                ContentDigest::from_bytes(b"m2-capture:spliced"),
            ),
        ] {
            let mut json: serde_json::Value =
                serde_json::from_slice(&final_bytes).expect("parse final probe JSON");
            json[field] = serde_json::to_value(changed).expect("changed digest JSON");
            let changed_bytes = serde_json::to_vec(&json).expect("canonical changed JSON");
            assert!(M5FinalPostRollbackProbeV1::from_canonical_bytes(&changed_bytes).is_err());
        }
    }

    #[test]
    fn exact_candidate_preflight_rejects_wrong_inputs_before_any_effect() {
        let directory = TestDirectory::new("m5-exact-preflight");
        let runtime = initialize(&directory);

        let mut wrong_recipe = exact_candidate_plan(
            &runtime,
            "cycle:exact-wrong-recipe",
            ApprovalDecision::Approved,
        );
        wrong_recipe.candidate_wat_bytes = incumbent_wat();
        assert_exact_preflight_rejected_without_effect(&runtime, wrong_recipe);

        let mut wrong_package = exact_candidate_plan(
            &runtime,
            "cycle:exact-wrong-package",
            ApprovalDecision::Approved,
        );
        wrong_package.candidate_package_bytes[0] ^= 1;
        assert_exact_preflight_rejected_without_effect(&runtime, wrong_package);

        let base = exact_candidate_plan(
            &runtime,
            "cycle:exact-wrong-factory",
            ApprovalDecision::Approved,
        );
        let base_package = FactoryPackage::from_canonical_bytes(&base.candidate_package_bytes)
            .expect("base exact candidate");
        let wrong_factory_package = FactoryPackage::build(
            "factory:other-receiver",
            base_package.payload.generation,
            base_package.payload.genome.clone(),
            base_package.payload.stable_interface.clone(),
            base_package.payload.worker_catalog.clone(),
            base_package.payload.service_dependencies.clone(),
            base_package
                .payload
                .boot_manifest
                .state_compatibility
                .clone(),
        )
        .expect("valid wrong-factory package");
        let mut wrong_factory = base;
        replace_exact_candidate(&mut wrong_factory, &wrong_factory_package);
        assert_exact_preflight_rejected_without_effect(&runtime, wrong_factory);

        let mut wrong_parent = exact_candidate_plan(
            &runtime,
            "cycle:exact-wrong-parent",
            ApprovalDecision::Approved,
        );
        let original = FactoryPackage::from_canonical_bytes(&wrong_parent.candidate_package_bytes)
            .expect("base parent candidate");
        let wrong_parent_genome = MutableGenome::new(
            Some(ContentDigest::from_bytes(b"wrong-parent")),
            original.payload.genome.component_bytes.clone(),
            original.payload.genome.policy.clone(),
        )
        .expect("wrong-parent genome");
        let wrong_parent_package = FactoryPackage::build(
            original.payload.factory_id.clone(),
            original.payload.generation,
            wrong_parent_genome,
            original.payload.stable_interface.clone(),
            original.payload.worker_catalog.clone(),
            original.payload.service_dependencies.clone(),
            original.payload.boot_manifest.state_compatibility.clone(),
        )
        .expect("valid wrong-parent package");
        replace_exact_candidate(&mut wrong_parent, &wrong_parent_package);
        assert_exact_preflight_rejected_without_effect(&runtime, wrong_parent);

        let mut wrong_generation = exact_candidate_plan(
            &runtime,
            "cycle:exact-wrong-generation",
            ApprovalDecision::Approved,
        );
        let original =
            FactoryPackage::from_canonical_bytes(&wrong_generation.candidate_package_bytes)
                .expect("base generation candidate");
        let wrong_generation_package = FactoryPackage::build(
            original.payload.factory_id.clone(),
            original.payload.generation + 1,
            original.payload.genome.clone(),
            original.payload.stable_interface.clone(),
            original.payload.worker_catalog.clone(),
            original.payload.service_dependencies.clone(),
            original.payload.boot_manifest.state_compatibility.clone(),
        )
        .expect("valid wrong-generation package");
        replace_exact_candidate(&mut wrong_generation, &wrong_generation_package);
        assert_exact_preflight_rejected_without_effect(&runtime, wrong_generation);

        let mut wrong_active = exact_candidate_plan(
            &runtime,
            "cycle:exact-wrong-active",
            ApprovalDecision::Approved,
        );
        wrong_active.expected_active_package_digest =
            ContentDigest::from_bytes(b"wrong-active-package");
        assert_exact_preflight_rejected_without_effect(&runtime, wrong_active);

        let mut wrong_snapshot = exact_candidate_plan(
            &runtime,
            "cycle:exact-wrong-snapshot",
            ApprovalDecision::Approved,
        );
        wrong_snapshot.expected_active_snapshot_digest =
            ContentDigest::from_bytes(b"wrong-active-snapshot");
        assert_exact_preflight_rejected_without_effect(&runtime, wrong_snapshot);

        let mut wrong_gate = exact_candidate_plan(
            &runtime,
            "cycle:exact-wrong-gate",
            ApprovalDecision::Approved,
        );
        wrong_gate.expected_release_gate_digest = ContentDigest::from_bytes(b"wrong-gate");
        assert_exact_preflight_rejected_without_effect(&runtime, wrong_gate);

        let mut wrong_state = exact_candidate_plan(
            &runtime,
            "cycle:exact-wrong-state",
            ApprovalDecision::Approved,
        );
        let original = FactoryPackage::from_canonical_bytes(&wrong_state.candidate_package_bytes)
            .expect("base state candidate");
        let wrong_state_package = FactoryPackage::build(
            original.payload.factory_id.clone(),
            original.payload.generation,
            original.payload.genome.clone(),
            original.payload.stable_interface.clone(),
            original.payload.worker_catalog.clone(),
            original.payload.service_dependencies.clone(),
            compatibility(2),
        )
        .expect("valid schema-changing package");
        replace_exact_candidate(&mut wrong_state, &wrong_state_package);
        assert_exact_preflight_rejected_without_effect(&runtime, wrong_state);

        let mut over_budget = exact_candidate_plan(
            &runtime,
            "cycle:exact-over-budget",
            ApprovalDecision::Approved,
        );
        let original = FactoryPackage::from_canonical_bytes(&over_budget.candidate_package_bytes)
            .expect("base budget candidate");
        let over_budget_genome = MutableGenome::new(
            original.payload.parent_package_digest.clone(),
            original.payload.genome.component_bytes.clone(),
            MutableFactoryPolicy::terminal(2, 5),
        )
        .expect("over-budget candidate genome");
        let over_budget_package = FactoryPackage::build(
            original.payload.factory_id.clone(),
            original.payload.generation,
            over_budget_genome,
            original.payload.stable_interface.clone(),
            original.payload.worker_catalog.clone(),
            original.payload.service_dependencies.clone(),
            original.payload.boot_manifest.state_compatibility.clone(),
        )
        .expect("valid over-budget package");
        replace_exact_candidate(&mut over_budget, &over_budget_package);
        assert_exact_preflight_rejected_without_effect(&runtime, over_budget);
    }

    #[test]
    fn exact_candidate_denied_approval_never_activates() {
        let directory = TestDirectory::new("m5-exact-denied");
        let runtime = initialize(&directory);
        let incumbent = runtime.active_package().expect("denied incumbent");
        let before = runtime
            .capability
            .backend_snapshot()
            .expect("read denied preflight snapshot")
            .expect("initialized denied snapshot");
        let result = runtime
            .run_exact_candidate_cycle(exact_candidate_plan(
                &runtime,
                "cycle:exact-denied",
                ApprovalDecision::Rejected,
            ))
            .expect("terminal exact denial");
        result.validate().expect("validate exact denial");
        assert!(matches!(
            result.outcome,
            CycleOutcome::ApprovalRejected { .. }
        ));
        assert_eq!(result.active_snapshot, before);
        assert_eq!(
            result.active_snapshot.package_digest,
            incumbent.package_digest
        );
        assert!(result.cycle_record.activation_receipt.is_none());
        assert!(result.cycle_record.observation_evidence.is_none());
        assert!(result.cycle_record.recovery_receipt.is_none());
        assert!(result.effect_audit.entries.iter().all(|entry| {
            entry.evidence_id != "cycle:cycle:exact-denied:activation"
                && entry.evidence_id != "cycle:cycle:exact-denied:observation"
                && entry.evidence_id != "cycle:cycle:exact-denied:recovery"
        }));
        let execution = runtime
            .execute_active(7)
            .expect("execute after exact denial");
        assert_eq!(execution.output, 7);
        assert_eq!(execution.package_digest, incumbent.package_digest);
    }

    #[test]
    fn export_captures_real_n_plus_one_and_reopens_standalone() {
        let directory = TestDirectory::new("m5-export-n1");
        let runtime = initialize(&directory);
        let outcome = runtime
            .run_seeded_cycle(approved_seed(
                "cycle:export-n1",
                MutableFactoryPolicy::terminal(2, 2),
            ))
            .expect("adopt real N+1");
        assert!(matches!(outcome, CycleOutcome::Adopted { .. }));

        let bundle = runtime
            .export_active_adopted_bundle()
            .expect("export exact adopted N+1");
        bundle.validate_standalone().expect("standalone validation");
        assert_eq!(bundle.reproduction_state().active_generation, 1);
        assert_eq!(
            bundle.active_package().package_digest(),
            &bundle.reproduction_state().active_package_digest
        );
        assert_eq!(
            bundle.active_cycle().m1_proving_record().record_digest,
            bundle.active_cycle().m1_evidence().proving_record_digest
        );
        assert_eq!(bundle.active_cycle().m4_workflows().len(), 1);
        assert_eq!(
            bundle.active_cycle().m4_workflows()[0]
                .workflow()
                .worker
                .execution_ids,
            bundle
                .active_cycle()
                .m4_worker_evidence()
                .receipts
                .iter()
                .map(|receipt| receipt.execution_id.clone())
                .collect::<Vec<_>>()
        );
        let exported_workflow = &bundle.active_cycle().m4_workflows()[0];
        let service_families = exported_workflow
            .service_receipts()
            .iter()
            .map(|receipt| receipt.family())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            service_families,
            std::collections::BTreeSet::from([
                crate::execution::NativeServiceFamily::Build,
                crate::execution::NativeServiceFamily::Validation,
                crate::execution::NativeServiceFamily::Review,
                crate::execution::NativeServiceFamily::Packaging,
                crate::execution::NativeServiceFamily::Continuity,
                crate::execution::NativeServiceFamily::Scheduling,
                crate::execution::NativeServiceFamily::Operations,
            ]),
            "the authoritative M4 workflow export must carry all seven M3 service families"
        );
        let operations_receipts = exported_workflow
            .service_receipts()
            .iter()
            .filter(|receipt| receipt.family() == crate::execution::NativeServiceFamily::Operations)
            .collect::<Vec<_>>();
        assert_eq!(
            operations_receipts.len(),
            1,
            "the workflow must persist exactly one terminal operations inspection"
        );
        let operations_receipt = operations_receipts[0];
        assert_eq!(
            operations_receipt.operation(),
            crate::capability_services::CapabilityOperation::OperationsInspect
        );
        let operations_attestation = exported_workflow
            .service_attestations()
            .iter()
            .find(|attestation| attestation.invocation_id == operations_receipt.invocation_id())
            .expect("terminal operations receipt has its exact attestation");
        assert_eq!(
            operations_attestation.family,
            crate::execution::NativeServiceFamily::Operations
        );
        assert_eq!(
            operations_attestation.operation,
            crate::capability_services::CapabilityOperation::OperationsInspect
        );
        assert_eq!(
            &operations_attestation.input_digest,
            operations_receipt.input_digest()
        );
        assert_eq!(
            &operations_attestation.output_digest,
            operations_receipt.output_digest()
        );
        assert_eq!(
            &operations_attestation.receipt_digest,
            operations_receipt.receipt_digest()
        );
        assert!(operations_attestation.terminal_success);

        let m4_successes = exported_workflow
            .service_receipts()
            .iter()
            .filter_map(|receipt| match receipt.outcome() {
                crate::capability_services::InvocationOutcome::Succeeded { result } => Some(result),
                crate::capability_services::InvocationOutcome::Terminal { .. } => None,
            })
            .collect::<Vec<_>>();
        assert!(m4_successes.iter().any(|result| {
            matches!(
                result,
                crate::capability_services::CapabilitySuccess::Build(_)
            )
        }));
        assert!(m4_successes.iter().any(|result| {
            matches!(
                result,
                crate::capability_services::CapabilitySuccess::Package(_)
            )
        }));
        assert!(m4_successes.iter().any(|result| {
            matches!(
                result,
                crate::capability_services::CapabilitySuccess::Proving(_)
            )
        }));
        assert!(m4_successes.iter().any(|result| {
            matches!(
                result,
                crate::capability_services::CapabilitySuccess::Comparison(_)
            )
        }));
        assert!(matches!(
            bundle.active_cycle().release_authority(),
            crate::m5_export::M5ExportReleaseAuthorityV1::M3ShadowGate { .. }
        ));
        let compiled_component = wat::parse_bytes(bundle.active_package().recipe_wat_bytes())
            .expect("exported retained WAT compiles")
            .into_owned();
        let retained_component =
            FactoryPackage::from_canonical_bytes(bundle.active_package().canonical_package_bytes())
                .expect("exported active package parses")
                .payload
                .genome
                .component_bytes;
        assert!(
            compiled_component == retained_component,
            "exported WAT compiled to different component bytes (compiled_bytes={}, retained_bytes={})",
            compiled_component.len(),
            retained_component.len()
        );
        let bytes = bundle.canonical_bytes().expect("canonical export bytes");
        let sender_root = directory.0.to_string_lossy().into_owned();
        assert!(
            !bytes
                .windows(sender_root.len())
                .any(|window| window == sender_root.as_bytes()),
            "portable export must not persist the sender store root"
        );
        assert!(
            !String::from_utf8_lossy(&bytes).contains("\"root\":"),
            "portable runtime identity must not serialize a root field"
        );
        drop(runtime);

        let detached =
            M5ExportBundleV1::from_canonical_bytes(&bytes).expect("detached receiver reopen");
        detached
            .validate_standalone()
            .expect("detached bundle remains complete after source shutdown");
        assert_eq!(
            detached.active_cycle().m1_proving_record().record_digest,
            bundle.active_cycle().m1_proving_record().record_digest
        );
        assert_eq!(
            detached.active_cycle().m4_workflows()[0].stored_record_digest(),
            bundle.active_cycle().m4_workflows()[0].stored_record_digest()
        );
        let reopened =
            M5Runtime::open(config(&directory), None).expect("reopen source factory after export");
        reopened
            .export_active_adopted_bundle()
            .expect("reopened live source remains exportable")
            .validate_standalone()
            .expect("reopened export validates");
    }

    #[test]
    fn post_export_restart_uses_exact_m4_root_closed_catalog_and_rejects_duplicate_root() {
        let directory = TestDirectory::new("m5-post-export-m2");
        let runtime = initialize(&directory);
        assert!(matches!(
            runtime
                .run_seeded_cycle(approved_seed(
                    "cycle:post-export-m2",
                    MutableFactoryPolicy::terminal(2, 2),
                ))
                .expect("adopt M2 capture target"),
            CycleOutcome::Adopted { .. }
        ));
        let export = runtime
            .export_active_adopted_bundle()
            .expect("export exact M2 capture target");
        let export_bytes = export.canonical_bytes().expect("canonical M5 export");
        let anchor = &export.active_cycle().m4_workflows()[0]
            .workflow()
            .lifecycle_anchor;

        let workflow_runs = directory.0.join("m4-recipes/workflow-runs");
        let source_state = fs::read_dir(&workflow_runs)
            .expect("read workflow-run roots")
            .map(|entry| entry.expect("workflow-run entry").path())
            .map(|root| root.join("m2-supervisor/supervisor-state.json"))
            .find(|path| {
                fs::read(path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<SupervisorState>(&bytes).ok())
                    .is_some_and(|state| state.jobs.contains_key(&anchor.m2_job_id))
            })
            .expect("locate exact anchor state");
        let duplicate_root = workflow_runs.join("duplicate-anchor-root");
        fs::create_dir_all(duplicate_root.join("m2-supervisor"))
            .expect("create duplicate anchor root");
        fs::copy(
            &source_state,
            duplicate_root.join("m2-supervisor/supervisor-state.json"),
        )
        .expect("copy duplicate anchor state");
        assert!(matches!(
            runtime.capture_post_export_m2_restart_with_completion_digest_for_test(
                ContentDigest::from_bytes(b"manifest:duplicate-root"),
                ContentDigest::from_bytes(&export_bytes),
                ContentDigest::from_bytes(b"m6-completion:duplicate-root"),
                &anchor.m2_job_id,
                anchor.terminal_job_digest.clone(),
            ),
            Err(M5RuntimeError::Integrity(message)) if message.contains("found 2")
        ));
        fs::remove_dir_all(&duplicate_root).expect("remove exact duplicate test root");

        let manifest_digest = ContentDigest::from_bytes(b"manifest:post-export-m2");
        let capture = runtime
            .capture_post_export_m2_restart_with_completion_digest_for_test(
                manifest_digest.clone(),
                ContentDigest::from_bytes(&export_bytes),
                ContentDigest::from_bytes(b"m6-completion:post-export-m2"),
                &anchor.m2_job_id,
                anchor.terminal_job_digest.clone(),
            )
            .expect("capture typed post-export restart");
        let before: SupervisorState =
            serde_json::from_slice(capture.pre_restart_supervisor_state_bytes())
                .expect("parse pre-restart state");
        let after: SupervisorState =
            serde_json::from_slice(capture.post_restart_supervisor_state_bytes())
                .expect("parse post-restart state");
        assert_eq!(
            serde_json::to_vec_pretty(&before).expect("canonical pretty pre-state"),
            capture.pre_restart_supervisor_state_bytes()
        );
        assert_eq!(
            serde_json::to_vec_pretty(&after).expect("canonical pretty post-state"),
            capture.post_restart_supervisor_state_bytes()
        );
        let capture_bytes = capture.canonical_bytes().expect("bounded capture bytes");
        assert!(capture_bytes.len() <= MAX_M5_M2_POST_EXPORT_CAPTURE_BYTES);
        assert_eq!(
            M5M2PostExportRestartCaptureV2::from_canonical_bytes(&capture_bytes)
                .expect("detached exact capture"),
            capture
        );
        let challenges = before
            .jobs
            .values()
            .filter_map(|job| {
                M5M2PostExportJobBindingV2::from_job_identity(&job.job_id, &job.idempotency_key)
                    .ok()
                    .map(|binding| (job, binding))
            })
            .collect::<Vec<_>>();
        assert_eq!(challenges.len(), 1);
        let (scheduled, binding) = &challenges[0];
        assert_eq!(binding.manifest_digest(), &manifest_digest);
        assert_eq!(
            binding.m5_export_bundle_content_digest(),
            &ContentDigest::from_bytes(&export_bytes)
        );
        assert_eq!(
            binding.m6_completion_bundle_content_digest(),
            &ContentDigest::from_bytes(b"m6-completion:post-export-m2")
        );
        assert_eq!(scheduled.job_kind, M1_OPEN_WORKSPACE_JOB_KIND);
        assert!(scheduled.not_before_ms > before.updated_at_ms);
        assert!(!scheduled.phase.is_terminal());
        assert_eq!(
            after
                .jobs
                .get(&scheduled.job_id)
                .map(|job| job.phase.clone()),
            Some(JobPhase::Succeeded)
        );
        assert_ne!(before.heartbeat.owner_id, after.heartbeat.owner_id);
        assert!(after.heartbeat.started_at_ms >= scheduled.not_before_ms);
        assert_eq!(
            digest_json_content(
                before
                    .jobs
                    .get(&anchor.m2_job_id)
                    .expect("pre-state exact anchor")
            )
            .expect("pre-state anchor digest"),
            anchor.terminal_job_digest
        );
    }

    #[test]
    fn post_export_job_identity_is_bounded_canonical_and_exactly_round_trips() {
        let binding = M5M2PostExportJobBindingV2::new(
            ContentDigest::from_bytes(b"manifest"),
            ContentDigest::from_bytes(b"export"),
            ContentDigest::from_bytes(b"m6-completion"),
            "m4-anchor-job",
            ContentDigest::from_bytes(b"anchor"),
        )
        .expect("post-export binding");
        let job_id = binding.job_id();
        let idempotency_key = binding.idempotency_key();
        assert!(job_id.len() <= 256);
        assert!(idempotency_key.len() <= 256);
        assert_eq!(
            M5M2PostExportJobBindingV2::from_job_identity(&job_id, &idempotency_key)
                .expect("canonical identity round trip"),
            binding
        );

        let mut uppercase = job_id.clone();
        uppercase.replace_range(
            M5_M2_POST_EXPORT_JOB_PREFIX.len()..M5_M2_POST_EXPORT_JOB_PREFIX.len() + 1,
            "A",
        );
        assert!(
            M5M2PostExportJobBindingV2::from_job_identity(&uppercase, &idempotency_key).is_err()
        );
        assert!(
            M5M2PostExportJobBindingV2::from_job_identity(
                &format!("{job_id}.extra"),
                &idempotency_key,
            )
            .is_err()
        );
        let mut uppercase_effect = idempotency_key.clone();
        uppercase_effect.replace_range(
            M5_M2_POST_EXPORT_EFFECT_PREFIX.len()..M5_M2_POST_EXPORT_EFFECT_PREFIX.len() + 1,
            "A",
        );
        assert!(M5M2PostExportJobBindingV2::from_job_identity(&job_id, &uppercase_effect).is_err());
        assert!(
            M5M2PostExportJobBindingV2::from_job_identity(
                &job_id,
                &format!("{idempotency_key}.extra"),
            )
            .is_err()
        );
        assert!(
            M5M2PostExportJobBindingV2::from_job_identity(
                &job_id,
                &idempotency_key.replacen("m7-m2-open-effect-v2", "m7-m2-open-effect-v1", 1),
            )
            .is_err()
        );
    }

    #[test]
    fn export_rejects_recipe_lineage_worker_and_effect_tampering() {
        let directory = TestDirectory::new("m5-export-tamper");
        let runtime = initialize(&directory);
        runtime
            .run_seeded_cycle(approved_seed(
                "cycle:export-tamper",
                MutableFactoryPolicy::terminal(2, 2),
            ))
            .expect("adopt tamper target");
        let bundle = runtime
            .export_active_adopted_bundle()
            .expect("capture valid export");

        let mut recipe = bundle.clone();
        recipe.tamper_active_recipe_for_test();
        assert!(recipe.validate_standalone().is_err());

        let mut lineage = bundle.clone();
        lineage.remove_active_lineage_for_test();
        assert!(lineage.validate_standalone().is_err());

        let mut workers = bundle.clone();
        workers.cross_link_worker_for_test();
        assert!(workers.validate_standalone().is_err());

        let mut effects = bundle;
        effects.remove_active_shadow_effect_for_test();
        assert!(effects.validate_standalone().is_err());

        let original = runtime
            .export_active_adopted_bundle()
            .expect("recapture valid full-evidence export");
        let mut m1 = original.clone();
        m1.tamper_full_m1_record_for_test();
        assert!(m1.validate_standalone().is_err());

        let mut missing_m4 = original.clone();
        missing_m4.remove_full_m4_workflow_for_test();
        assert!(missing_m4.validate_standalone().is_err());

        let mut cross_linked_m4 = original;
        cross_linked_m4.cross_link_full_m4_workflow_for_test();
        assert!(cross_linked_m4.validate_standalone().is_err());
    }

    #[test]
    fn export_rejects_missing_corrupt_and_cross_linked_full_m1_m4_store_records() {
        let directory = TestDirectory::new("m5-export-full-store-records");
        let runtime = initialize(&directory);
        runtime
            .run_seeded_cycle(approved_seed(
                "cycle:export-full-store-n1",
                MutableFactoryPolicy {
                    policy_revision: 2,
                    generation_enabled: true,
                    generation_instruction: Some(GenerationLoopInstruction {
                        instruction_id: "instruction:export-full-store-n1".to_string(),
                        driver_contract:
                            crate::factory_reproduction::GenerationDriverContract::reference(),
                        successor_policy_revision: 3,
                        max_executions: 1,
                    }),
                    max_canary_tasks: 2,
                },
            ))
            .expect("adopt recursive N1");
        runtime
            .run_adopted_successor_cycle(approved_adopted("cycle:export-full-store-n2"))
            .expect("adopt materialized N2");

        let state = runtime.state_snapshot().expect("active N2 state");
        let active = active_evidence_references(&state).expect("active evidence references");
        assert_eq!(
            active.m4_workflows.len(),
            2,
            "recursive adoption requires materialization and candidate workflows"
        );
        let prior_cycle = state
            .cycles
            .iter()
            .find(|cycle| cycle.cycle_id == "cycle:export-full-store-n1")
            .expect("prior N1 cycle remains retained");
        let prior_m1_path = directory.0.join(PROVING_DIRECTORY).join(format!(
            "{}.json",
            prior_cycle.m1_evidence.proving_record_digest.file_stem()
        ));
        let prior_m4_path = directory
            .0
            .join(RECIPES_DIRECTORY)
            .join("workflow-evidence")
            .join(format!(
                "{}.json",
                prior_cycle.worker_evidence.request_digest.file_stem()
            ));
        let prior_m1 = fs::read(&prior_m1_path).expect("read prior exact M1 record");
        let prior_m4 = fs::read(&prior_m4_path).expect("read prior exact M4 record");

        let active_m1_path = directory.0.join(PROVING_DIRECTORY).join(format!(
            "{}.json",
            active.m1_proving_record_digest.file_stem()
        ));
        let active_m1 = fs::read(&active_m1_path).expect("read active exact M1 record");

        fs::remove_file(&active_m1_path).expect("delete active M1 negative control");
        assert!(runtime.export_active_adopted_bundle().is_err());
        fs::write(&active_m1_path, &active_m1).expect("restore active M1");

        fs::write(&active_m1_path, b"{}").expect("corrupt active M1 negative control");
        assert!(runtime.export_active_adopted_bundle().is_err());
        fs::write(&active_m1_path, &active_m1).expect("restore active M1");

        fs::write(&active_m1_path, &prior_m1).expect("cross-link prior M1 under active identity");
        assert!(runtime.export_active_adopted_bundle().is_err());
        fs::write(&active_m1_path, &active_m1).expect("restore active M1");

        for reference in &active.m4_workflows {
            let active_m4_path = directory
                .0
                .join(RECIPES_DIRECTORY)
                .join("workflow-evidence")
                .join(format!(
                    "{}.json",
                    reference.governance_context_digest.file_stem()
                ));
            let active_m4 =
                fs::read(&active_m4_path).expect("read active exact M4 workflow record");

            fs::remove_file(&active_m4_path).expect("delete active M4 negative control");
            assert!(runtime.export_active_adopted_bundle().is_err());
            fs::write(&active_m4_path, &active_m4).expect("restore active M4");

            fs::write(&active_m4_path, b"{}").expect("corrupt active M4 negative control");
            assert!(runtime.export_active_adopted_bundle().is_err());
            fs::write(&active_m4_path, &active_m4).expect("restore active M4");

            fs::write(&active_m4_path, &prior_m4)
                .expect("cross-link prior M4 under active request identity");
            assert!(runtime.export_active_adopted_bundle().is_err());
            fs::write(&active_m4_path, &active_m4).expect("restore active M4");
        }

        let bundle = runtime
            .export_active_adopted_bundle()
            .expect("restored exact full evidence is exportable");
        assert_eq!(bundle.active_cycle().m4_workflows().len(), 2);
        let bytes = bundle
            .canonical_bytes()
            .expect("canonical full-evidence bytes");
        M5ExportBundleV1::from_canonical_bytes(&bytes)
            .expect("standalone canonical recursive full-evidence reopen");
    }

    #[test]
    fn export_rejects_generation_zero_operator_revert_and_unhealthy_quarantine() {
        let root_directory = TestDirectory::new("m5-export-root");
        let root = initialize(&root_directory);
        assert!(root.export_active_adopted_bundle().is_err());

        let reverted_directory = TestDirectory::new("m5-export-reverted");
        let reverted = initialize(&reverted_directory);
        let adopted = reverted
            .run_seeded_cycle(approved_seed(
                "cycle:export-before-revert",
                MutableFactoryPolicy::terminal(2, 2),
            ))
            .expect("adopt rollback target");
        let digest = match adopted {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            _ => panic!("unexpected non-adopted outcome"),
        };
        reverted
            .operator_revert_active(
                "rollback:export-negative-control",
                &digest,
                "operator:export-negative-control",
            )
            .expect("operator restore exact incumbent");
        assert!(reverted.export_active_adopted_bundle().is_err());

        let unhealthy_directory = TestDirectory::new("m5-export-unhealthy");
        let unhealthy = initialize(&unhealthy_directory);
        unhealthy
            .induce_next_health_regression()
            .expect("arm health regression");
        let outcome = unhealthy
            .run_seeded_cycle(approved_seed(
                "cycle:export-unhealthy",
                MutableFactoryPolicy::terminal(2, 2),
            ))
            .expect("quarantine unhealthy candidate");
        assert!(matches!(
            outcome,
            CycleOutcome::QuarantinedAndRolledBack { .. }
        ));
        assert!(
            !unhealthy
                .state_snapshot()
                .expect("state")
                .quarantines
                .is_empty()
        );
        assert!(unhealthy.export_active_adopted_bundle().is_err());
    }

    #[test]
    fn export_rejects_unresolved_in_flight_successor() {
        let directory = TestDirectory::new("m5-export-in-flight");
        let runtime = initialize(&directory);
        runtime
            .run_seeded_cycle(approved_seed(
                "cycle:export-live-n1",
                MutableFactoryPolicy {
                    policy_revision: 2,
                    generation_enabled: true,
                    generation_instruction: Some(GenerationLoopInstruction {
                        instruction_id: "instruction:export-live-n1".to_string(),
                        driver_contract:
                            crate::factory_reproduction::GenerationDriverContract::reference(),
                        successor_policy_revision: 3,
                        max_executions: 1,
                    }),
                    max_canary_tasks: 2,
                },
            ))
            .expect("adopt recursive N+1");
        runtime
            .interrupt_next_activation()
            .expect("arm deterministic activation interruption");
        assert!(
            runtime
                .run_adopted_successor_cycle(approved_adopted("cycle:export-interrupted-n2"))
                .is_err()
        );
        assert!(
            runtime
                .state_snapshot()
                .expect("pending state")
                .in_flight
                .is_some()
        );
        let error = runtime
            .export_active_adopted_bundle()
            .expect_err("in-flight state must never export");
        assert!(error.to_string().contains("in-flight"));
    }

    #[test]
    fn export_serializes_concurrent_effect_admission_into_a_complete_audit() {
        let directory = TestDirectory::new("m5-export-effect-race");
        let runtime = std::sync::Arc::new(initialize(&directory));
        runtime
            .run_seeded_cycle(approved_seed(
                "cycle:export-effect-race",
                MutableFactoryPolicy::terminal(2, 2),
            ))
            .expect("adopt race target");
        let executor = std::sync::Arc::clone(&runtime);
        let concurrent = std::thread::spawn(move || {
            (0..4)
                .map(|input| {
                    executor
                        .execute_active(input)
                        .expect("concurrent exact execution")
                })
                .collect::<Vec<_>>()
        });
        let bundle = runtime
            .export_active_adopted_bundle()
            .expect("operation gate yields a coherent export");
        let executions = concurrent.join().expect("concurrent execution thread");
        assert_eq!(executions.len(), 4);
        bundle
            .validate_standalone()
            .expect("effect race cannot produce a partial audit bundle");
        runtime
            .export_active_adopted_bundle()
            .expect("post-race audit includes every admitted effect")
            .validate_standalone()
            .expect("post-race export validates");
    }

    #[test]
    fn two_actual_cycles_route_exact_bytes_and_survive_restart() {
        let directory = TestDirectory::new("two-cycles");
        let runtime = initialize(&directory);
        let before = runtime.execute_active(7).expect("execute incumbent");
        assert_eq!(before.output, 7);
        assert!(before.m3_invocation_id.contains("m5-m3-"));
        assert_ne!(before.m3_receipt_digest, before.m3_attestation_digest);
        assert_ne!(before.m3_proof_digest, ContentDigest::from_bytes(&[]));
        let first = runtime
            .run_seeded_cycle(approved_seed(
                "cycle:n-to-n1",
                MutableFactoryPolicy {
                    policy_revision: 2,
                    generation_enabled: true,
                    generation_instruction: Some(GenerationLoopInstruction {
                        instruction_id: "instruction:n1-build-n2".to_string(),
                        driver_contract:
                            crate::factory_reproduction::GenerationDriverContract::reference(),
                        successor_policy_revision: 3,
                        max_executions: 1,
                    }),
                    max_canary_tasks: 2,
                },
            ))
            .expect("run real N to N+1 cycle");
        let n1_digest = match first {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            _ => panic!("first reproduction cycle returned a non-adopted outcome"),
        };
        let after_first = runtime.execute_active(7).expect("execute adopted N+1");
        assert_eq!(after_first.output, 8);
        assert_eq!(after_first.package_digest, n1_digest);
        assert_ne!(after_first.package_digest, before.package_digest);

        let second = runtime
            .run_adopted_successor_cycle(approved_adopted("cycle:n1-to-n2"))
            .expect("N+1 drives the governed N+2 cycle");
        let n2_digest = match second {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            _ => panic!("second reproduction cycle returned a non-adopted outcome"),
        };
        let after_second = runtime.execute_active(7).expect("execute adopted N+2");
        assert_eq!(after_second.output, 8);
        assert_eq!(after_second.package_digest, n2_digest);
        assert_ne!(after_second.component_digest, after_first.component_digest);

        let state = runtime.state_snapshot().expect("load reproduction state");
        assert_eq!(state.active_generation, 2);
        assert_eq!(state.cycles.len(), 2);
        assert_eq!(state.generation_initiations.len(), 1);
        assert_eq!(
            state.generation_initiations[0].executor_package_digest,
            n1_digest
        );
        assert_eq!(
            state.cycles[1]
                .initiation
                .as_ref()
                .expect("N+2 material initiation")
                .executor_package_digest,
            n1_digest
        );
        assert!(state.cycles.iter().all(|cycle| {
            cycle.status == CycleStatus::Adopted
                && cycle.worker_evidence.receipts.len() == 6
                && cycle.worker_evidence.receipts.iter().all(|receipt| {
                    receipt.terminal_status == WorkerTerminalStatus::Succeeded
                        && receipt.output_digest.is_some()
                })
        }));
        assert!(state.lineage.iter().any(|lineage| {
            lineage.package_digest == n2_digest
                && lineage.parent_package_digest.as_ref() == Some(&n1_digest)
                && lineage.generation_initiation_digest.is_some()
        }));
        let exact_package_bytes = runtime
            .active_package()
            .expect("active package")
            .canonical_bytes()
            .expect("canonical bytes");
        assert_eq!(
            ContentDigest::from_bytes(&exact_package_bytes),
            after_second.package_bytes_digest
        );
        drop(runtime);

        let reopened = M5Runtime::open(config(&directory), None).expect("reopen durable M5");
        let reopened_state = reopened.state_snapshot().expect("reopened state");
        assert_eq!(reopened_state.active_package_digest, n2_digest);
        assert_eq!(reopened_state.active_generation, 2);
        assert!(reopened_state.in_flight.is_none());
        assert_eq!(
            reopened
                .execute_active(7)
                .expect("execute after restart")
                .output,
            8
        );
        assert!(reopened.m2().status().expect("M2 status").worker_running);
        assert_eq!(
            reopened
                .m3()
                .services()
                .iter()
                .map(|service| format!("{:?}", service.family))
                .collect::<BTreeSet<_>>()
                .len(),
            7
        );
    }

    #[test]
    fn terminal_seeded_and_adopted_replays_use_historical_intents_without_new_state() {
        let directory = TestDirectory::new("terminal-runtime-replay");
        let runtime = initialize(&directory);
        let seed = approved_seed(
            "cycle:terminal-seed-replay",
            MutableFactoryPolicy {
                policy_revision: 2,
                generation_enabled: true,
                generation_instruction: Some(GenerationLoopInstruction {
                    instruction_id: "instruction:terminal-runtime-replay".to_string(),
                    driver_contract:
                        crate::factory_reproduction::GenerationDriverContract::reference(),
                    successor_policy_revision: 3,
                    max_executions: 1,
                }),
                max_canary_tasks: 2,
            },
        );
        let first = runtime
            .run_seeded_cycle(seed.clone())
            .expect("adopt seeded successor");
        let after_seed = runtime.state_snapshot().expect("state after seed");
        assert_eq!(after_seed.active_generation, 1);
        let replayed_seed = runtime
            .run_seeded_cycle(seed.clone())
            .expect("replay terminal seed");
        assert!(
            replayed_seed == first,
            "terminal seeded-cycle replay differed from the retained outcome"
        );
        let state_after_seed_replay = runtime.state_snapshot().expect("state after seed replay");
        assert!(
            state_after_seed_replay == after_seed,
            "terminal seed replay changed the exact reproduction state"
        );

        let mut changed_seed = seed.clone();
        changed_seed.operator_context_digest =
            ContentDigest::from_bytes(b"changed-seed-operator-context");
        assert!(matches!(
            runtime.run_seeded_cycle(changed_seed),
            Err(M5RuntimeError::Conflict(_))
        ));
        let mut changed_wat = seed;
        changed_wat.challenger_wat_bytes.push(b'\n');
        assert!(matches!(
            runtime.run_seeded_cycle(changed_wat),
            Err(M5RuntimeError::Conflict(_))
        ));
        let state_after_seed_conflicts = runtime
            .state_snapshot()
            .expect("state after seed conflicts");
        assert!(
            state_after_seed_conflicts == after_seed,
            "rejected seed replays changed the exact reproduction state"
        );

        let adopted = approved_adopted("cycle:terminal-adopted-replay");
        let second = runtime
            .run_adopted_successor_cycle(adopted.clone())
            .expect("adopt generated successor");
        let after_adopted = runtime.state_snapshot().expect("state after adopted cycle");
        assert_eq!(after_adopted.active_generation, 2);
        let replayed_adopted = runtime
            .run_adopted_successor_cycle(adopted.clone())
            .expect("replay terminal adopted cycle");
        assert!(
            replayed_adopted == second,
            "terminal adopted-cycle replay differed from the retained outcome"
        );
        let state_after_adopted_replay = runtime
            .state_snapshot()
            .expect("state after adopted replay");
        assert!(
            state_after_adopted_replay == after_adopted,
            "terminal adopted replay changed the exact reproduction state"
        );

        let mut changed_adopted = adopted;
        changed_adopted.operator_context_digest =
            ContentDigest::from_bytes(b"changed-adopted-operator-context");
        assert!(matches!(
            runtime.run_adopted_successor_cycle(changed_adopted),
            Err(M5RuntimeError::Conflict(_))
        ));
        let state_after_adopted_conflict = runtime
            .state_snapshot()
            .expect("state after adopted conflict");
        assert!(
            state_after_adopted_conflict == after_adopted,
            "rejected adopted replay changed the exact reproduction state"
        );
    }

    #[test]
    fn root_has_one_live_owner_and_initialization_journal_repairs_manifest_loss() {
        let directory = TestDirectory::new("owner-and-init-recovery");
        let runtime = initialize(&directory);
        let second = M5Runtime::open(config(&directory), None);
        assert!(matches!(second, Err(M5RuntimeError::Conflict(_))));
        let expected = runtime
            .state_snapshot()
            .expect("initialized state")
            .active_package_digest;
        drop(runtime);

        let manifest_path = directory.0.join(MANIFEST_FILE);
        fs::remove_file(&manifest_path).expect("simulate crash before manifest durability");
        let reopened = M5Runtime::open(config(&directory), None)
            .expect("resume exact initialization from its journal");
        assert!(manifest_path.exists());
        assert_eq!(
            reopened
                .state_snapshot()
                .expect("reconciled state")
                .active_package_digest,
            expected
        );
        let journal: M5InitializationJournal = read_json_bounded(
            &directory.0.join(INITIALIZATION_JOURNAL_FILE),
            MAX_RUNTIME_STATE_BYTES,
        )
        .expect("reload initialization journal");
        journal.validate().expect("valid journal");
        assert_eq!(journal.phase, M5InitializationPhase::Complete);
    }

    #[test]
    fn revert_or_disable_removes_n_plus_one_causality_and_rejection_does_not_route() {
        let directory = TestDirectory::new("causality");
        let runtime = initialize(&directory);
        let root_digest = runtime
            .state_snapshot()
            .expect("root state")
            .active_package_digest;
        let n1 = runtime
            .run_seeded_cycle(approved_seed(
                "cycle:causal-n1",
                MutableFactoryPolicy {
                    policy_revision: 2,
                    generation_enabled: true,
                    generation_instruction: Some(GenerationLoopInstruction {
                        instruction_id: "instruction:causal".to_string(),
                        driver_contract:
                            crate::factory_reproduction::GenerationDriverContract::reference(),
                        successor_policy_revision: 3,
                        max_executions: 1,
                    }),
                    max_canary_tasks: 2,
                },
            ))
            .expect("adopt causal N+1");
        let n1_digest = match n1 {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            _ => panic!("causal N+1 cycle returned a non-adopted outcome"),
        };
        runtime
            .operator_revert_active(
                "rollback:remove-n1",
                &n1_digest,
                "operator:causality-negative-control",
            )
            .expect("revert N+1");
        assert_eq!(
            runtime
                .state_snapshot()
                .expect("reverted state")
                .active_package_digest,
            root_digest
        );
        let stopped = runtime
            .run_adopted_successor_cycle(approved_adopted("cycle:after-revert"))
            .expect("root records explicit generation stop");
        assert!(matches!(
            stopped,
            CycleOutcome::Stopped(ref record)
                if record.reason == StopReason::GenerationDisabled
        ));
        assert!(
            runtime
                .state_snapshot()
                .expect("stopped state")
                .generation_initiations
                .is_empty()
        );
        drop(runtime);

        let rejected_directory = TestDirectory::new("approval-rejected");
        let rejected_runtime = initialize(&rejected_directory);
        let mut rejected = approved_seed(
            "cycle:approval-rejected",
            MutableFactoryPolicy::terminal(2, 2),
        );
        rejected.approval_decision = ApprovalDecision::Rejected;
        rejected.approval_rationale = "operator rejected promotion".to_string();
        let outcome = rejected_runtime
            .run_seeded_cycle(rejected)
            .expect("record approval rejection");
        assert!(matches!(outcome, CycleOutcome::ApprovalRejected { .. }));
        assert_eq!(
            rejected_runtime
                .state_snapshot()
                .expect("rejected state")
                .active_package_digest,
            rejected_runtime
                .execute_active(7)
                .expect("incumbent still routed")
                .package_digest
        );
        assert_eq!(
            rejected_runtime
                .execute_active(7)
                .expect("incumbent behavior")
                .output,
            7
        );
    }

    #[test]
    fn regression_rolls_back_and_partial_migration_recovers_atomically() {
        let regression_directory = TestDirectory::new("regression");
        let runtime = initialize(&regression_directory);
        let root_digest = runtime
            .state_snapshot()
            .expect("root state")
            .active_package_digest;
        runtime
            .induce_next_health_regression()
            .expect("arm actual health negative control");
        let outcome = runtime
            .run_seeded_cycle(approved_seed(
                "cycle:regression",
                MutableFactoryPolicy::terminal(2, 2),
            ))
            .expect("regression invokes governed rollback");
        assert!(matches!(
            outcome,
            CycleOutcome::QuarantinedAndRolledBack {
                ref restored_package_digest,
                ..
            } if restored_package_digest == &root_digest
        ));
        let state = runtime.state_snapshot().expect("rollback state");
        assert_eq!(state.active_package_digest, root_digest);
        assert_eq!(state.active_generation, 0);
        assert_eq!(state.quarantines.len(), 1);
        assert_eq!(runtime.execute_active(7).expect("restored route").output, 7);
        drop(runtime);
        let reopened =
            M5Runtime::open(config(&regression_directory), None).expect("reopen rolled back M5");
        assert_eq!(reopened.execute_active(7).expect("restart route").output, 7);
        drop(reopened);

        let migration_directory = TestDirectory::new("partial-migration");
        let migrating = initialize(&migration_directory);
        let migration_root = migrating
            .state_snapshot()
            .expect("migration root")
            .active_package_digest;
        migrating
            .interrupt_next_activation()
            .expect("arm post-migration interruption");
        let mut plan = approved_seed(
            "cycle:partial-migration",
            MutableFactoryPolicy::terminal(2, 2),
        );
        plan.state_compatibility = compatibility(2);
        let forward = crate::m5_effect_store::StateTransformArtifact::new(
            crate::m5_effect_store::StateTransformDirection::Forward,
            1,
            2,
            crate::m5_effect_store::StateTransformProgram::Prepend {
                prefix: b"schema-v2:".to_vec(),
            },
            ContentDigest::from_bytes(b"m5-forward-transform-proof"),
        )
        .expect("valid forward migration artifact");
        let rollback = crate::m5_effect_store::StateTransformArtifact::new(
            crate::m5_effect_store::StateTransformDirection::Rollback,
            2,
            1,
            crate::m5_effect_store::StateTransformProgram::RemovePrefix {
                prefix: b"schema-v2:".to_vec(),
            },
            ContentDigest::from_bytes(b"m5-rollback-transform-proof"),
        )
        .expect("valid rollback migration artifact");
        let artifacts = StateMigrationArtifactBundle::new(forward, rollback)
            .expect("valid migration artifact bundle");
        plan.migration_plan = Some(
            StateMigrationPlan::new(
                "migration:v1-to-v2",
                1,
                2,
                1,
                artifacts.bundle_digest.clone(),
                4_096,
            )
            .expect("valid migration plan"),
        );
        plan.migration_artifacts = Some(artifacts);
        assert!(migrating.run_seeded_cycle(plan).is_err());
        let interrupted = migrating.state_snapshot().expect("interrupted state");
        assert_eq!(
            interrupted
                .in_flight
                .as_ref()
                .expect("durable pending effect")
                .stage,
            PendingStage::ActivationRequested
        );
        assert!(
            interrupted
                .in_flight
                .as_ref()
                .expect("pending effect")
                .migration_receipt
                .is_some()
        );
        drop(migrating);

        let recovered =
            M5Runtime::open(config(&migration_directory), None).expect("recover partial migration");
        let recovered_state = recovered.state_snapshot().expect("recovered state");
        assert_eq!(recovered_state.active_package_digest, migration_root);
        assert_eq!(recovered_state.active_state_schema, 1);
        assert!(recovered_state.in_flight.is_none());
        assert_eq!(
            recovered_state.cycles[0].status,
            CycleStatus::RecoveredToIncumbent
        );
        assert_eq!(
            recovered.execute_active(7).expect("recovered route").output,
            7
        );
    }

    #[test]
    fn terminal_provider_seed_replay_returns_stored_record_without_new_provider_calls() {
        let directory = TestDirectory::new("terminal-provider-replay");
        let provider = Arc::new(CountingProvider::new());
        let runtime = initialize_with_live_provider(&directory, provider.clone());
        let request_builder = governed_provider_request_builder();
        let plan = approved_seed(
            "cycle:terminal-provider-replay",
            MutableFactoryPolicy::terminal(2, 2),
        );
        let qualification = runtime
            .provider_qualification_request_for_seed(
                "qualification:terminal-provider-replay",
                &request_builder,
                &plan,
            )
            .expect("construct exact provider request");
        let (record, outcome) = runtime
            .run_provider_backed_seed_cycle(qualification.clone(), plan.clone())
            .expect("run first provider-backed seed");
        assert_eq!(record.status, ProviderQualificationStatus::Qualified);
        assert!(matches!(outcome, CycleOutcome::Adopted { .. }));
        assert_eq!(provider.live_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.replay_calls.load(Ordering::Relaxed), 1);
        let bindings = runtime
            .provider_candidate_bindings()
            .expect("list provider bindings");
        assert_eq!(bindings.len(), 1);
        let exported = runtime
            .export_provider_candidate_binding(&bindings[0].binding_digest)
            .expect("export exact provider binding");
        let exported_binding = ProviderCandidateBinding::from_canonical_bytes(&exported)
            .expect("parse exported provider binding");
        assert!(
            exported_binding == bindings[0],
            "exported provider binding differed from the retained candidate binding"
        );
        let terminal_state = runtime
            .state_snapshot()
            .expect("state after provider-backed adoption");
        assert_eq!(terminal_state.active_generation, 1);
        let proof_ledger_path = directory
            .0
            .join(M3_PROOF_DIRECTORY)
            .join("m5-m3-proof-ledger.json");
        let proof_ledger_before_terminal_replay =
            fs::read(&proof_ledger_path).expect("read proposal proof ledger");

        let replay = runtime
            .run_provider_backed_seed_cycle(qualification.clone(), plan.clone())
            .expect("return exact terminal provider replay");
        let expected_replay = (record.clone(), outcome.clone());
        assert!(
            replay == expected_replay,
            "terminal provider replay differed from the retained record and outcome"
        );
        assert_eq!(provider.live_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.replay_calls.load(Ordering::Relaxed), 1);
        let proof_ledger_after_terminal_replay =
            fs::read(&proof_ledger_path).expect("reread proposal proof ledger");
        assert!(
            proof_ledger_after_terminal_replay == proof_ledger_before_terminal_replay,
            "terminal replay must not issue a second provider proposal effect"
        );
        let state_after_provider_replay = runtime
            .state_snapshot()
            .expect("state after provider replay");
        assert!(
            state_after_provider_replay == terminal_state,
            "terminal provider replay changed the exact reproduction state"
        );
        drop(runtime);

        let reopened_provider: Arc<dyn LiveProviderQualificationPort> = provider.clone();
        let reopened = M5Runtime::open(config(&directory), Some(reopened_provider))
            .expect("reopen M3-backed provider binding");
        let proof_ledger_after_reopen =
            fs::read(&proof_ledger_path).expect("read proposal proof ledger after reopen");
        let restarted_replay = reopened
            .run_provider_backed_seed_cycle(qualification.clone(), plan.clone())
            .expect("return terminal provider replay after restart");
        let expected_restarted_replay = (record, outcome);
        assert!(
            restarted_replay == expected_restarted_replay,
            "restarted provider replay differed from the retained record and outcome"
        );
        assert_eq!(provider.live_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.replay_calls.load(Ordering::Relaxed), 1);
        let proof_ledger_after_restarted_replay =
            fs::read(&proof_ledger_path).expect("proof ledger after restarted replay");
        assert!(
            proof_ledger_after_restarted_replay == proof_ledger_after_reopen,
            "restarted replay must reuse the retained provider proposal proof"
        );

        let mut changed = plan;
        changed.operator_context_digest =
            ContentDigest::from_bytes(b"changed-provider-operator-context");
        assert!(matches!(
            reopened.run_provider_backed_seed_cycle(qualification, changed),
            Err(M5RuntimeError::Conflict(_))
        ));
        assert_eq!(provider.live_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.replay_calls.load(Ordering::Relaxed), 1);
        let state_after_provider_conflict = reopened
            .state_snapshot()
            .expect("state after provider conflict");
        assert!(
            state_after_provider_conflict == terminal_state,
            "rejected provider replay changed the exact reproduction state"
        );
    }

    #[test]
    fn precommitted_provider_seed_is_canonical_proof_run_bound_and_executable() {
        let directory = TestDirectory::new("precommitted-provider-seed");
        let provider = Arc::new(CountingProvider::new());
        let runtime = initialize_with_live_provider(&directory, provider.clone());
        let request_builder = governed_provider_request_builder();
        let original_plan = approved_seed(
            "cycle:precommitted-provider-seed",
            MutableFactoryPolicy::terminal(2, 2),
        );

        let prepared = runtime
            .prepare_provider_backed_seed_cycle(
                "proof-run:precommit-a",
                "qualification:precommit-a",
                1_000,
                &request_builder,
                original_plan.clone(),
            )
            .expect("freeze exact provider seed before its live turn");
        assert_eq!(
            prepared.plan.operator_context_digest,
            prepared.precommit.precommit_digest
        );
        assert_eq!(
            prepared.target.operator_context_digest,
            prepared.precommit.precommit_digest
        );
        let bytes = prepared.canonical_bytes().expect("canonical prepared seed");
        let reopened_prepared = M5PreparedProviderSeedV1::from_canonical_bytes(&bytes)
            .expect("reopen canonical prepared seed");
        assert!(
            reopened_prepared == prepared,
            "reopened prepared provider seed differed from its canonical source"
        );

        let other_proof_run = runtime
            .prepare_provider_backed_seed_cycle(
                "proof-run:precommit-b",
                "qualification:precommit-b",
                1_001,
                &request_builder,
                original_plan,
            )
            .expect("freeze another exact proof run");
        assert_ne!(
            prepared.precommit.precommit_digest,
            other_proof_run.precommit.precommit_digest
        );
        assert_ne!(
            prepared.target.target_digest,
            other_proof_run.target.target_digest
        );
        assert_ne!(
            prepared.qualification_request.request_digest,
            other_proof_run.qualification_request.request_digest
        );

        let mut changed = prepared.clone();
        changed.plan.approval_rationale =
            "post-precommit approval rationale substitution".to_string();
        assert!(changed.validate().is_err());
        assert_eq!(provider.live_calls.load(Ordering::Relaxed), 0);
        assert_eq!(provider.replay_calls.load(Ordering::Relaxed), 0);

        let (record, outcome) = runtime
            .run_precommitted_provider_backed_seed_cycle(prepared.clone())
            .expect("execute only the exact precommitted provider seed");
        assert_eq!(record.status, ProviderQualificationStatus::Qualified);
        assert!(matches!(outcome, CycleOutcome::Adopted { .. }));
        assert_eq!(provider.live_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.replay_calls.load(Ordering::Relaxed), 1);
        let bindings = runtime
            .provider_candidate_bindings()
            .expect("list exact provider binding");
        assert_eq!(bindings.len(), 1);
        assert!(
            bindings[0].target == prepared.target,
            "retained provider target differed from the precommitted exact target"
        );
        let reopened_binding = ProviderCandidateBinding::from_canonical_bytes(
            &runtime
                .export_provider_candidate_binding(&bindings[0].binding_digest)
                .expect("export exact provider binding"),
        )
        .expect("reopen exported provider binding");
        assert!(
            reopened_binding == bindings[0],
            "reopened provider binding differed from the retained candidate binding"
        );
    }

    #[test]
    fn reopen_rejects_missing_provider_proposal_proof() {
        let directory = TestDirectory::new("missing-provider-proposal-proof");
        let provider = Arc::new(CountingProvider::new());
        let runtime = initialize_with_live_provider(&directory, provider.clone());
        let request_builder = governed_provider_request_builder();
        let plan = approved_seed(
            "cycle:missing-provider-proposal-proof",
            MutableFactoryPolicy::terminal(2, 2),
        );
        let qualification = runtime
            .provider_qualification_request_for_seed(
                "qualification:missing-provider-proposal-proof",
                &request_builder,
                &plan,
            )
            .expect("provider qualification request");
        runtime
            .run_provider_backed_seed_cycle(qualification, plan)
            .expect("create M3-backed provider binding");
        assert_eq!(
            runtime
                .provider_bindings
                .validate_all()
                .expect("validate provider binding")
                .len(),
            1
        );
        drop(runtime);

        fs::remove_file(
            directory
                .0
                .join(M3_PROOF_DIRECTORY)
                .join("m5-m3-proof-ledger.json"),
        )
        .expect("remove M3 proof ledger");
        let reopened_provider: Arc<dyn LiveProviderQualificationPort> = provider;
        assert!(matches!(
            M5Runtime::open(config(&directory), Some(reopened_provider)),
            Err(M5RuntimeError::Dependency(_)) | Err(M5RuntimeError::Integrity(_))
        ));
    }

    #[test]
    fn reopen_rejects_cross_linked_provider_proposal_proof() {
        let directory = TestDirectory::new("cross-linked-provider-proposal-proof");
        let provider = Arc::new(CountingProvider::new());
        let runtime = initialize_with_live_provider(&directory, provider.clone());
        let request_builder = governed_provider_request_builder();
        let plan = approved_seed(
            "cycle:cross-linked-provider-proposal-proof",
            MutableFactoryPolicy::terminal(2, 2),
        );
        let qualification = runtime
            .provider_qualification_request_for_seed(
                "qualification:cross-linked-provider-proposal-proof",
                &request_builder,
                &plan,
            )
            .expect("provider qualification request");
        runtime
            .run_provider_backed_seed_cycle(qualification, plan)
            .expect("create M3-backed provider binding");
        drop(runtime);

        let ledger_value: serde_json::Value = serde_json::from_slice(
            &fs::read(
                directory
                    .0
                    .join(M3_PROOF_DIRECTORY)
                    .join("m5-m3-proof-ledger.json"),
            )
            .expect("read M3 proof ledger"),
        )
        .expect("parse M3 proof ledger");
        let cross_linked_proof_digest: ContentDigest = serde_json::from_value(
            ledger_value["records"]
                .as_array()
                .expect("proof records")
                .iter()
                .find(|record| record["request"]["operation"] == "initialize")
                .expect("initialization proof")["proof_digest"]
                .clone(),
        )
        .expect("decode cross-linked proof digest");
        let bindings_root = directory
            .0
            .join(PROVIDER_BINDINGS_DIRECTORY)
            .join("bindings");
        let original_path = fs::read_dir(&bindings_root)
            .expect("read bindings")
            .next()
            .expect("one provider binding")
            .expect("binding entry")
            .path();
        let mut binding: ProviderCandidateBinding =
            serde_json::from_slice(&fs::read(&original_path).expect("read provider binding"))
                .expect("parse provider binding");
        binding.proposal_evidence.m3_reference.proof_digest = cross_linked_proof_digest;
        binding.proposal_evidence.evidence_digest = digest_json_content(&(
            crate::m5_provider_binding::PROVIDER_PROPOSAL_EVIDENCE_SCHEMA,
            &binding.proposal_evidence.request,
            &binding.proposal_evidence.result,
            &binding.proposal_evidence.m3_reference,
        ))
        .expect("reseal locally consistent proposal evidence");
        binding.binding_digest = digest_json_content(&(
            crate::m5_provider_binding::PROVIDER_CANDIDATE_BINDING_SCHEMA,
            &binding.target.target_digest,
            &binding.qualification_record_digest,
            &binding.intent_digest,
            &binding.proposal_evidence.evidence_digest,
        ))
        .expect("reseal locally consistent provider binding");
        let cross_linked_path =
            bindings_root.join(format!("{}.json", binding.binding_digest.file_stem()));
        fs::remove_file(&original_path).expect("remove original binding");
        fs::write(
            &cross_linked_path,
            serde_json::to_vec_pretty(&binding).expect("encode cross-linked binding"),
        )
        .expect("write cross-linked binding");

        let reopened_provider: Arc<dyn LiveProviderQualificationPort> = provider;
        assert!(matches!(
            M5Runtime::open(config(&directory), Some(reopened_provider)),
            Err(M5RuntimeError::Dependency(_)) | Err(M5RuntimeError::Integrity(_))
        ));
    }

    #[test]
    fn provider_proposal_effect_is_read_only_before_binding_and_candidate_work() {
        let directory = TestDirectory::new("read-only-provider-proposal");
        let provider = Arc::new(CountingProvider::new());
        let runtime = initialize_with_live_provider(&directory, provider);
        let request_builder = governed_provider_request_builder();
        let plan = approved_seed(
            "cycle:read-only-provider-proposal",
            MutableFactoryPolicy::terminal(2, 2),
        );
        let qualification = runtime
            .provider_qualification_request_for_seed(
                "qualification:read-only-provider-proposal",
                &request_builder,
                &plan,
            )
            .expect("provider qualification request");
        let qualified = runtime
            .qualify_live_provider(qualification.clone())
            .expect("qualify exact live and offline turn");
        assert_eq!(qualified.status, ProviderQualificationStatus::Qualified);
        let backend_before = runtime
            .capability
            .backend_snapshot()
            .expect("backend snapshot before proposal");
        let proposal = FactoryProviderProposalRequest::new(
            qualification,
            qualified
                .live_turn
                .as_ref()
                .expect("qualified live turn")
                .normalized_parser_input_bytes
                .clone(),
        )
        .expect("provider proposal request");
        let (result, reference) = runtime
            .capability
            .record_provider_proposal(&proposal)
            .expect("record provider proposal through M3");
        runtime
            .capability
            .validate_provider_proposal_reference(&proposal, &result, &reference)
            .expect("re-resolve proposal proof");
        let backend_after = runtime
            .capability
            .backend_snapshot()
            .expect("backend snapshot after proposal");
        assert!(
            backend_after == backend_before,
            "read-only provider proposal changed the exact capability backend snapshot"
        );
        let state = runtime.state_snapshot().expect("state after proposal");
        assert_eq!(state.active_generation, 0);
        assert!(state.cycle_intents.is_empty());
        assert!(state.cycles.is_empty());
        assert!(
            runtime
                .provider_bindings
                .validate_all()
                .expect("provider binding store")
                .is_empty()
        );
        drop(runtime);
        let reopened = M5Runtime::open(config(&directory), None)
            .expect("reopen with an unbound read-only proposal proof");
        let reopened_state = reopened.state_snapshot().expect("reopened proposal state");
        assert_eq!(reopened_state.active_generation, 0);
        assert!(reopened_state.cycle_intents.is_empty());
        assert!(reopened_state.cycles.is_empty());
    }

    #[test]
    fn absent_live_credentials_are_unavailable_never_qualified() {
        let directory = TestDirectory::new("provider-unavailable");
        let runtime = initialize(&directory);
        let active = runtime
            .state_snapshot()
            .expect("active state")
            .active_package_digest;
        let configuration = ProviderConfiguration {
            provider_id: "provider:unconfigured".to_string(),
            model_id: "model:unconfigured".to_string(),
            provider_profile: M5ProviderProfileV1::OpenAiResponses,
            api_base_url: "https://provider.example.test/v1/".to_string(),
            endpoint_class: M5ProviderEndpointClassV1::ExternalHttps,
            driver_profile_digest: ContentDigest::from_bytes(b"driver"),
            generation_policy_id: "policy:unconfigured".to_string(),
            generation_policy_digest: ContentDigest::from_bytes(b"generation-policy"),
            maximum_retries: 0,
            maximum_output_tokens: 512,
            input_cost_per_million_microunits: 0,
            output_cost_per_million_microunits: 0,
            cost_currency: "usd".to_string(),
            parser_digest: ContentDigest::from_bytes(M5_PROVIDER_PARSER_DOMAIN),
            response_schema_digest: ContentDigest::from_bytes(
                provider_response_schema_json().as_bytes(),
            ),
            prompt_renderer_digest: ContentDigest::from_bytes(b"renderer"),
            tool_catalog_digest: ContentDigest::from_bytes(provider_tool_catalog_json().as_bytes()),
        };
        let prompt = b"propose one bounded candidate operation".to_vec();
        let catalog: serde_json::Value =
            serde_json::from_str(&provider_tool_catalog_json()).expect("tool catalog JSON");
        let selected = catalog
            .as_array()
            .and_then(|items| items.first())
            .expect("one selected tool");
        let capsule = ProviderReplayCapsule::new(
            &configuration,
            prompt.clone(),
            provider_tool_catalog_json().into_bytes(),
            serde_json::to_vec(selected).expect("selected tool bytes"),
            serde_json::to_vec(selected.get("parameters").expect("argument schema"))
                .expect("argument schema bytes"),
            provider_response_schema_json().into_bytes(),
        )
        .expect("provider replay capsule");
        let record = runtime
            .qualify_live_provider(
                ProviderQualificationRequest::new(
                    "qualification:no-provider",
                    active,
                    ContentDigest::from_bytes(b"unconfigured-target"),
                    configuration.clone(),
                    prompt,
                    capsule,
                )
                .expect("valid qualification request"),
            )
            .expect("record unavailable qualification");
        assert_eq!(record.status, ProviderQualificationStatus::Unavailable);
        assert!(record.live_turn.is_none());
        assert!(record.replay.is_none());
        assert!(
            !record
                .is_qualified_for(&configuration)
                .expect("qualification comparison")
        );

        let port = GovernedLiveProviderPort::new(GovernedLiveProviderConfig {
            provider: InferenceProviderRegistryEntry {
                provider_id: "provider:test-live".to_string(),
                provider_mode: InferenceProviderMode::OpenAiResponses,
                models: vec![InferenceProviderModelEntry {
                    model_ref: "model:test-live".to_string(),
                    input_cost_per_million_microunits: 0,
                    output_cost_per_million_microunits: 0,
                    supports_json_schema: true,
                    supports_function_tools: true,
                }],
                capability_summary: "test live provider boundary".to_string(),
                policy_summary: "credentials are call-time only".to_string(),
                active: true,
                api_base_url: "https://api.openai.com".to_string(),
                api_key_env_var: "WASM_BIOTIC_M5_TEST_KEY_THAT_MUST_NOT_EXIST".to_string(),
                organization_env_var: None,
                project_env_var: None,
                request_timeout_ms: 100,
            },
            generation_policy: InferenceGenerationPolicy {
                generation_policy_id: "policy:m5-live-test".to_string(),
                max_output_tokens: 128,
                max_retries: 0,
                summary: "one bounded qualification turn".to_string(),
            },
        })
        .expect("build governed live adapter");
        let request = port
            .qualification_request(
                "qualification:missing-credential",
                ContentDigest::from_bytes(b"package"),
                ContentDigest::from_bytes(b"target"),
                b"propose candidate.materialize_patchset".to_vec(),
            )
            .expect("valid live request");
        let failure = port
            .perform_live_turn(&request)
            .expect_err("missing credential is unavailable");
        assert_eq!(failure.kind, PortFailureKind::Unavailable);
        assert_eq!(failure.code, "provider_credential_unavailable");
    }

    #[test]
    fn provider_qualification_for_one_exact_target_cannot_run_another_seed_plan() {
        let directory = TestDirectory::new("provider-target-mismatch");
        let runtime = initialize(&directory);
        let port = GovernedLiveProviderPort::new(GovernedLiveProviderConfig {
            provider: InferenceProviderRegistryEntry {
                provider_id: "provider:test-target-binding".to_string(),
                provider_mode: InferenceProviderMode::OpenAiResponses,
                models: vec![InferenceProviderModelEntry {
                    model_ref: "model:test-target-binding".to_string(),
                    input_cost_per_million_microunits: 0,
                    output_cost_per_million_microunits: 0,
                    supports_json_schema: true,
                    supports_function_tools: true,
                }],
                capability_summary: "test exact provider target binding".to_string(),
                policy_summary: "no live call is made in this negative control".to_string(),
                active: true,
                api_base_url: "https://api.openai.com".to_string(),
                api_key_env_var: "WASM_BIOTIC_M5_TEST_KEY_THAT_MUST_NOT_EXIST".to_string(),
                organization_env_var: None,
                project_env_var: None,
                request_timeout_ms: 100,
            },
            generation_policy: InferenceGenerationPolicy {
                generation_policy_id: "policy:m5-target-binding".to_string(),
                max_output_tokens: 128,
                max_retries: 0,
                summary: "one bounded exact-target qualification".to_string(),
            },
        })
        .expect("build exact-target provider adapter");
        let plan = approved_seed(
            "cycle:provider-target-binding",
            MutableFactoryPolicy::terminal(2, 2),
        );
        let request = runtime
            .provider_qualification_request_for_seed(
                "qualification:provider-target-binding",
                &port,
                &plan,
            )
            .expect("construct exact provider request");
        let mut unrelated = plan.clone();
        unrelated.challenger_wat_bytes.push(b'\n');
        assert!(matches!(
            runtime.run_provider_backed_seed_cycle(request, unrelated),
            Err(M5RuntimeError::Conflict(_))
        ));
        let state = runtime
            .state_snapshot()
            .expect("state after rejected binding");
        assert!(state.provider_qualifications.is_empty());
        assert!(state.cycle_intents.is_empty());
        assert!(state.cycles.is_empty());
    }
}
