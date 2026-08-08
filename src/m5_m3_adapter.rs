//! Durable, domain-neutral proof ledger for M5 factory effects executed by M3.
//!
//! The adapter keeps M5 domain payloads opaque. It binds those exact bytes to
//! one stable backend `logical_effect_id`, maps the requested factory operation
//! to the narrow opt-in M3 service, and persists the complete M3 proof chain
//! for every attempt:
//!
//! - the exact [`CapabilityInvocation`] submitted to M3;
//! - the independently reloaded durable invocation input;
//! - the terminal [`InvocationReceipt`];
//! - the independently derived [`ServiceInvocationAttestation`]; and
//! - the typed [`FactoryEffectResult`] when the attempt succeeded.
//!
//! A pending attempt is durable before M3 is called. Recovery never invents a
//! successful result or blindly replays an ambiguous effect: opening the ledger
//! first asks M3 for the deterministic attempt identity and seals any receipt
//! that M3 already owns. A later [`M5M3InvocationProofLedger::invoke`] may
//! safely resubmit that exact M3 invocation because both its invocation identity
//! and idempotency key are stable.

use crate::capability_services::{
    CAPABILITY_ATTESTATION_SCHEMA, CancellationToken, CapabilityHostError, CapabilityInvocation,
    CapabilityOperation, CapabilityRequest, CapabilitySuccess, FactoryEffectRequest,
    FactoryEffectResult, InvocationApproval, InvocationBudget, InvocationIdentity,
    InvocationOutcome, InvocationReceipt, MAX_FACTORY_EFFECT_REQUEST_BYTES,
    MAX_FACTORY_EFFECT_RESPONSE_BYTES, ServiceFailureKind, ServiceInvocationAttestation,
};
use crate::execution::{
    ApprovalClass, AuthorityClass, ContentDigest, NativeServiceFamily, digest_json_content,
};
use crate::m3_runtime::{
    FACTORY_EXECUTION_SERVICE_ID, FACTORY_INSPECT_SERVICE_ID, FACTORY_PROMOTION_SERVICE_ID,
    M3CapabilityRuntime, M3RuntimeError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

pub const M5_M3_LEDGER_SCHEMA: &str = "wasm-biotic.m5-m3-proof-ledger.v1";
pub const M5_M3_PROOF_SCHEMA: &str = "wasm-biotic.m5-m3-invocation-proof.v1";
pub const M5_M3_ATTEMPT_SCHEMA: &str = "wasm-biotic.m5-m3-attempt-proof.v1";
pub const M5_M3_MAX_ATTEMPTS: u8 = 3;

const LEDGER_STATE_FILE: &str = "m5-m3-proof-ledger.json";
const LEDGER_OWNER_LOCK_FILE: &str = ".m5-m3-proof-ledger.lock";
const REQUEST_FINGERPRINT_DOMAIN: &str = "wasm-biotic:m5-m3-request:v1";
const ATTEMPT_IDENTITY_DOMAIN: &str = "wasm-biotic:m5-m3-attempt:v1";
const MAX_LEDGER_BYTES: usize = 64 * 1_048_576;
const MAX_LEDGER_RECORDS: usize = 128;
const MAX_IDENTIFIER_BYTES: usize = 1_024;
const MAX_INVOCATION_TIMEOUT_MS: u64 = 300_000;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// The complete domain-neutral operation vocabulary exposed by the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactoryEffectOperation {
    Execute,
    ProviderProposal,
    Shadow,
    Initialize,
    StateMigrate,
    Activate,
    Observe,
    Rollback,
    Inspect,
}

impl FactoryEffectOperation {
    pub const fn service_id(self) -> &'static str {
        match self {
            Self::Execute | Self::ProviderProposal | Self::Shadow => FACTORY_EXECUTION_SERVICE_ID,
            Self::Initialize
            | Self::StateMigrate
            | Self::Activate
            | Self::Observe
            | Self::Rollback => FACTORY_PROMOTION_SERVICE_ID,
            Self::Inspect => FACTORY_INSPECT_SERVICE_ID,
        }
    }

    pub const fn capability_operation(self) -> CapabilityOperation {
        match self {
            Self::Execute => CapabilityOperation::FactoryExecute,
            Self::ProviderProposal => CapabilityOperation::FactoryProviderProposal,
            Self::Shadow => CapabilityOperation::FactoryShadow,
            Self::Initialize => CapabilityOperation::FactoryInitialize,
            Self::StateMigrate => CapabilityOperation::FactoryStateMigrate,
            Self::Activate => CapabilityOperation::FactoryActivate,
            Self::Observe => CapabilityOperation::FactoryObserve,
            Self::Rollback => CapabilityOperation::FactoryRollback,
            Self::Inspect => CapabilityOperation::FactoryInspect,
        }
    }

    pub const fn family(self) -> NativeServiceFamily {
        match self {
            Self::Execute | Self::ProviderProposal | Self::Shadow => {
                NativeServiceFamily::Validation
            }
            Self::Initialize
            | Self::StateMigrate
            | Self::Activate
            | Self::Observe
            | Self::Rollback
            | Self::Inspect => NativeServiceFamily::Operations,
        }
    }

    pub fn authority(self) -> AuthorityClass {
        match self {
            Self::Execute | Self::ProviderProposal | Self::Shadow | Self::Inspect => {
                AuthorityClass::Observe
            }
            Self::Initialize
            | Self::StateMigrate
            | Self::Activate
            | Self::Observe
            | Self::Rollback => AuthorityClass::PromotionControl,
        }
    }

    pub fn required_approval(self) -> ApprovalClass {
        match self {
            Self::Execute | Self::ProviderProposal | Self::Shadow | Self::Inspect => {
                ApprovalClass::AutoAllowed
            }
            Self::Initialize
            | Self::StateMigrate
            | Self::Activate
            | Self::Observe
            | Self::Rollback => ApprovalClass::HumanRequired,
        }
    }

    pub const fn requires_human_approval(self) -> bool {
        matches!(
            self,
            Self::Initialize | Self::StateMigrate | Self::Activate | Self::Observe | Self::Rollback
        )
    }

    fn wrap_request(self, request: FactoryEffectRequest) -> CapabilityRequest {
        match self {
            Self::Execute => CapabilityRequest::FactoryExecute(request),
            Self::ProviderProposal => CapabilityRequest::FactoryProviderProposal(request),
            Self::Shadow => CapabilityRequest::FactoryShadow(request),
            Self::Initialize => CapabilityRequest::FactoryInitialize(request),
            Self::StateMigrate => CapabilityRequest::FactoryStateMigrate(request),
            Self::Activate => CapabilityRequest::FactoryActivate(request),
            Self::Observe => CapabilityRequest::FactoryObserve(request),
            Self::Rollback => CapabilityRequest::FactoryRollback(request),
            Self::Inspect => CapabilityRequest::FactoryInspect(request),
        }
    }
}

/// Fixed namespace and resource bounds for one local proof ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5M3AdapterConfig {
    pub root: PathBuf,
    pub scope_id: String,
    pub factory_id: String,
    pub caller_id: String,
    pub invocation_timeout_ms: u64,
}

impl M5M3AdapterConfig {
    pub fn validate(&self) -> Result<(), M5M3AdapterError> {
        if self.root.as_os_str().is_empty() {
            return Err(M5M3AdapterError::InvalidConfig(
                "ledger root must not be empty".to_string(),
            ));
        }
        validate_safe_identifier("scope_id", &self.scope_id, 256)?;
        validate_safe_identifier("factory_id", &self.factory_id, 256)?;
        if self.caller_id.trim().is_empty() || self.caller_id.len() > MAX_IDENTIFIER_BYTES {
            return Err(M5M3AdapterError::InvalidConfig(format!(
                "caller_id must contain 1..={MAX_IDENTIFIER_BYTES} nonblank bytes"
            )));
        }
        if self.invocation_timeout_ms == 0 || self.invocation_timeout_ms > MAX_INVOCATION_TIMEOUT_MS
        {
            return Err(M5M3AdapterError::InvalidConfig(format!(
                "invocation_timeout_ms must be between 1 and {MAX_INVOCATION_TIMEOUT_MS}"
            )));
        }
        Ok(())
    }
}

/// Exact opaque request accepted by [`M5M3InvocationProofLedger::invoke`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryEffectInvokeRequest {
    pub operation: FactoryEffectOperation,
    pub logical_effect_id: String,
    pub exact_request_digest: ContentDigest,
    pub exact_request_bytes: Vec<u8>,
    /// Required exactly for promotion operations and forbidden for automatic
    /// execution, shadow, and inspection operations.
    pub approval_ref: Option<String>,
}

impl FactoryEffectInvokeRequest {
    pub fn new(
        operation: FactoryEffectOperation,
        logical_effect_id: impl Into<String>,
        exact_request_bytes: Vec<u8>,
        approval_ref: Option<String>,
    ) -> Self {
        Self {
            operation,
            logical_effect_id: logical_effect_id.into(),
            exact_request_digest: ContentDigest::from_bytes(&exact_request_bytes),
            exact_request_bytes,
            approval_ref,
        }
    }

    pub fn validate(&self) -> Result<(), M5M3AdapterError> {
        validate_bounded_nonblank(
            "logical_effect_id",
            &self.logical_effect_id,
            MAX_IDENTIFIER_BYTES,
        )?;
        if self.exact_request_bytes.len() > MAX_FACTORY_EFFECT_REQUEST_BYTES {
            return Err(M5M3AdapterError::InvalidRequest(format!(
                "exact_request_bytes contains {} bytes, limit is {MAX_FACTORY_EFFECT_REQUEST_BYTES}",
                self.exact_request_bytes.len()
            )));
        }
        let actual = ContentDigest::from_bytes(&self.exact_request_bytes);
        if actual != self.exact_request_digest {
            return Err(M5M3AdapterError::InvalidRequest(format!(
                "exact request bytes digest to {actual}, declared {}",
                self.exact_request_digest
            )));
        }
        match (
            self.operation.requires_human_approval(),
            self.approval_ref.as_deref(),
        ) {
            (true, Some(approval_ref)) => {
                validate_bounded_nonblank("approval_ref", approval_ref, MAX_IDENTIFIER_BYTES)?;
            }
            (true, None) => {
                return Err(M5M3AdapterError::InvalidRequest(format!(
                    "{:?} requires an exact human approval reference",
                    self.operation
                )));
            }
            (false, None) => {}
            (false, Some(_)) => {
                return Err(M5M3AdapterError::InvalidRequest(format!(
                    "{:?} is automatic and must not carry an approval reference",
                    self.operation
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactoryEffectProofStatus {
    Retryable,
    InFlight,
    Succeeded,
    TerminalFailure,
    Exhausted,
}

/// One complete M3 attempt proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryEffectAttemptProof {
    pub schema: String,
    pub attempt_number: u8,
    pub invocation: CapabilityInvocation,
    pub durable_input: CapabilityInvocation,
    pub receipt: InvocationReceipt,
    pub attestation: ServiceInvocationAttestation,
    pub result: Option<FactoryEffectResult>,
    pub proof_digest: ContentDigest,
}

/// A durable intent published before M3 crosses the effect boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingFactoryEffectAttempt {
    pub attempt_number: u8,
    pub invocation: CapabilityInvocation,
    pub intent_digest: ContentDigest,
}

/// Full proof history for one immutable logical factory-effect request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryEffectInvocationProof {
    pub schema: String,
    pub request_fingerprint: ContentDigest,
    pub request: FactoryEffectInvokeRequest,
    pub attempts: Vec<FactoryEffectAttemptProof>,
    pub pending_attempt: Option<PendingFactoryEffectAttempt>,
    pub status: FactoryEffectProofStatus,
    pub proof_digest: ContentDigest,
}

impl FactoryEffectInvocationProof {
    pub fn terminal_result(&self) -> Option<&FactoryEffectResult> {
        if self.status != FactoryEffectProofStatus::Succeeded {
            return None;
        }
        self.attempts
            .last()
            .and_then(|attempt| attempt.result.as_ref())
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            FactoryEffectProofStatus::Succeeded
                | FactoryEffectProofStatus::TerminalFailure
                | FactoryEffectProofStatus::Exhausted
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct M5M3LedgerState {
    schema: String,
    config: M5M3AdapterConfig,
    config_digest: ContentDigest,
    records: Vec<FactoryEffectInvocationProof>,
    ledger_digest: ContentDigest,
}

/// Sole-writer durable adapter over the opt-in M3 factory services.
pub struct M5M3InvocationProofLedger {
    root: PathBuf,
    config: M5M3AdapterConfig,
    _owner_lock: File,
    m3: Arc<M3CapabilityRuntime>,
    state: Mutex<M5M3LedgerState>,
}

#[derive(Debug)]
pub enum M5M3AdapterError {
    InvalidConfig(String),
    InvalidRequest(String),
    Conflict(String),
    CorruptLedger(String),
    M3(M3RuntimeError),
    Serialization(serde_json::Error),
    Digest(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    UnsafePath {
        path: PathBuf,
        reason: &'static str,
    },
    ResourceBoundExceeded {
        resource: &'static str,
        actual: usize,
        limit: usize,
    },
}

impl M5M3AdapterError {
    fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }
}

impl Display for M5M3AdapterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid M5-M3 config: {reason}"),
            Self::InvalidRequest(reason) => write!(formatter, "invalid factory effect: {reason}"),
            Self::Conflict(reason) => write!(formatter, "M5-M3 proof conflict: {reason}"),
            Self::CorruptLedger(reason) => write!(formatter, "M5-M3 ledger is corrupt: {reason}"),
            Self::M3(error) => write!(formatter, "M3 factory invocation failed: {error}"),
            Self::Serialization(error) => write!(formatter, "M5-M3 JSON failed: {error}"),
            Self::Digest(error) => write!(formatter, "M5-M3 digest failed: {error}"),
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "M5-M3 I/O at '{}' failed: {source}",
                    path.display()
                )
            }
            Self::UnsafePath { path, reason } => {
                write!(
                    formatter,
                    "unsafe M5-M3 path '{}': {reason}",
                    path.display()
                )
            }
            Self::ResourceBoundExceeded {
                resource,
                actual,
                limit,
            } => write!(
                formatter,
                "M5-M3 {resource} uses {actual} items or bytes; limit is {limit}"
            ),
        }
    }
}

impl Error for M5M3AdapterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::M3(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::InvalidConfig(_)
            | Self::InvalidRequest(_)
            | Self::Conflict(_)
            | Self::CorruptLedger(_)
            | Self::Digest(_)
            | Self::UnsafePath { .. }
            | Self::ResourceBoundExceeded { .. } => None,
        }
    }
}

impl From<M3RuntimeError> for M5M3AdapterError {
    fn from(value: M3RuntimeError) -> Self {
        Self::M3(value)
    }
}

impl From<serde_json::Error> for M5M3AdapterError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl M5M3InvocationProofLedger {
    pub fn open(
        mut config: M5M3AdapterConfig,
        m3: Arc<M3CapabilityRuntime>,
    ) -> Result<Self, M5M3AdapterError> {
        config.validate()?;
        let root = secure_create_root(&config.root)?;
        config.root = root.clone();
        config.validate()?;
        validate_m3_factory_catalog(&config, &m3)?;
        let owner_lock = acquire_owner_lock(&root)?;
        let state_path = root.join(LEDGER_STATE_FILE);
        reject_symlink_if_present(&state_path)?;

        let state_existed = state_path.exists();
        let state = if state_existed {
            read_state(&state_path)?
        } else {
            let config_digest = adapter_config_digest(&config)?;
            let mut state = M5M3LedgerState {
                schema: M5_M3_LEDGER_SCHEMA.to_string(),
                config: config.clone(),
                config_digest,
                records: Vec::new(),
                ledger_digest: ContentDigest::from_bytes(&[]),
            };
            state.ledger_digest = ledger_digest(&state)?;
            state
        };

        let ledger = Self {
            root,
            config,
            _owner_lock: owner_lock,
            m3,
            state: Mutex::new(state),
        };
        {
            let state = ledger.lock_state()?;
            ledger.validate_local_state(&state)?;
            if state.config != ledger.config {
                return Err(M5M3AdapterError::Conflict(
                    "the supplied adapter config differs from the durable ledger config"
                        .to_string(),
                ));
            }
            if !state_existed {
                ledger.persist_state(&state)?;
            }
        }
        ledger.validate_all()?;
        Ok(ledger)
    }

    pub fn config(&self) -> &M5M3AdapterConfig {
        &self.config
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Execute or resume one exact logical factory effect.
    ///
    /// Successfully receipted terminal failures are proof, not adapter errors.
    /// Failed, timed-out, cancelled, unavailable, and resource-exhausted
    /// receipts consume at most three distinct M3 attempts and are returned in
    /// an `Exhausted` proof record. Unsupported, scope-denied, and
    /// approval-blocked receipts stop immediately. Infrastructure errors return
    /// `Err` while leaving the exact pending invocation durable for recovery.
    pub fn invoke(
        &self,
        request: FactoryEffectInvokeRequest,
    ) -> Result<FactoryEffectInvocationProof, M5M3AdapterError> {
        request.validate()?;
        let request_fingerprint = factory_request_fingerprint(&self.config, &request)?;
        let mut state = self.lock_state()?;
        self.validate_local_state(&state)?;

        if state.records.iter().any(|record| {
            record.request.logical_effect_id == request.logical_effect_id
                && record.request_fingerprint != request_fingerprint
        }) {
            return Err(M5M3AdapterError::Conflict(format!(
                "logical effect '{}' is already bound to different immutable inputs",
                request.logical_effect_id
            )));
        }
        if let Some(existing) = state
            .records
            .iter()
            .find(|record| record.request_fingerprint == request_fingerprint)
        {
            if existing.request != request {
                return Err(M5M3AdapterError::Conflict(format!(
                    "request fingerprint {request_fingerprint} resolves to different exact inputs"
                )));
            }
        }

        if !state
            .records
            .iter()
            .any(|record| record.request_fingerprint == request_fingerprint)
        {
            if state.records.len() >= MAX_LEDGER_RECORDS {
                return Err(M5M3AdapterError::ResourceBoundExceeded {
                    resource: "proof record count",
                    actual: state.records.len() + 1,
                    limit: MAX_LEDGER_RECORDS,
                });
            }
            let mut record = FactoryEffectInvocationProof {
                schema: M5_M3_PROOF_SCHEMA.to_string(),
                request_fingerprint: request_fingerprint.clone(),
                request,
                attempts: Vec::new(),
                pending_attempt: None,
                status: FactoryEffectProofStatus::Retryable,
                proof_digest: ContentDigest::from_bytes(&[]),
            };
            record.proof_digest = invocation_proof_digest(&record)?;
            state.records.push(record);
            state
                .records
                .sort_by(|left, right| left.request_fingerprint.cmp(&right.request_fingerprint));
            state.ledger_digest = ledger_digest(&state)?;
        }

        loop {
            let record_index = record_index(&state, &request_fingerprint)?;
            if state.records[record_index].is_terminal() {
                return Ok(state.records[record_index].clone());
            }

            if state.records[record_index].pending_attempt.is_none() {
                let attempt_number = u8::try_from(state.records[record_index].attempts.len() + 1)
                    .map_err(|_| {
                    M5M3AdapterError::CorruptLedger(
                        "factory attempt count cannot fit its bounded identity".to_string(),
                    )
                })?;
                if attempt_number > M5_M3_MAX_ATTEMPTS {
                    return Err(M5M3AdapterError::CorruptLedger(format!(
                        "record {} exceeded the maximum attempt count",
                        request_fingerprint
                    )));
                }
                let invocation = self.expected_invocation(
                    &state.records[record_index].request,
                    &request_fingerprint,
                    attempt_number,
                )?;
                let mut pending = PendingFactoryEffectAttempt {
                    attempt_number,
                    invocation,
                    intent_digest: ContentDigest::from_bytes(&[]),
                };
                pending.intent_digest = pending_attempt_digest(&pending)?;
                let mut next_state = state.clone();
                next_state.records[record_index].pending_attempt = Some(pending);
                next_state.records[record_index].status = FactoryEffectProofStatus::InFlight;
                refresh_record_and_ledger_digests(&mut next_state, record_index)?;
                self.persist_state(&next_state)?;
                *state = next_state;
            }

            let pending = state.records[record_index]
                .pending_attempt
                .clone()
                .ok_or_else(|| {
                    M5M3AdapterError::CorruptLedger(
                        "in-flight factory proof lost its pending invocation".to_string(),
                    )
                })?;
            let receipt = self
                .m3
                .invoke(&pending.invocation, CancellationToken::new())?;
            let proof =
                self.build_attempt_proof(&state.records[record_index], &pending, receipt)?;
            let mut next_state = state.clone();
            next_state.records[record_index].attempts.push(proof);
            next_state.records[record_index].pending_attempt = None;
            next_state.records[record_index].status =
                derive_proof_status(&next_state.records[record_index])?;
            refresh_record_and_ledger_digests(&mut next_state, record_index)?;
            self.validate_record_against_m3(&next_state.records[record_index])?;
            self.persist_state(&next_state)?;
            *state = next_state;

            if state.records[record_index].is_terminal() {
                return Ok(state.records[record_index].clone());
            }
        }
    }

    /// Re-derive every local digest and compare every completed proof artifact
    /// with M3's durable input, receipt, and attestation.
    ///
    /// If a previously pending invocation now has an M3 receipt, validation
    /// seals that already-completed attempt before returning.
    pub fn validate_all(&self) -> Result<Vec<FactoryEffectInvocationProof>, M5M3AdapterError> {
        let mut state = self.lock_state()?;
        self.validate_local_state(&state)?;
        let mut next_state = state.clone();
        let changed = self.reconcile_pending_receipts(&mut next_state)?;
        self.validate_local_state(&next_state)?;
        for record in &next_state.records {
            self.validate_record_against_m3(record)?;
        }
        if changed {
            next_state.ledger_digest = ledger_digest(&next_state)?;
            self.persist_state(&next_state)?;
            *state = next_state;
        }
        Ok(state.records.clone())
    }

    fn reconcile_pending_receipts(
        &self,
        state: &mut M5M3LedgerState,
    ) -> Result<bool, M5M3AdapterError> {
        let mut changed = false;
        for record_index in 0..state.records.len() {
            let Some(pending) = state.records[record_index].pending_attempt.clone() else {
                continue;
            };
            let receipt = match self.m3.receipt(&pending.invocation.identity.invocation_id) {
                Ok(receipt) => receipt,
                Err(M3RuntimeError::Capability(CapabilityHostError::ReceiptNotFound {
                    ..
                })) => continue,
                Err(error) => return Err(error.into()),
            };
            let proof =
                self.build_attempt_proof(&state.records[record_index], &pending, receipt)?;
            state.records[record_index].attempts.push(proof);
            state.records[record_index].pending_attempt = None;
            state.records[record_index].status = derive_proof_status(&state.records[record_index])?;
            refresh_record_and_ledger_digests(state, record_index)?;
            changed = true;
        }
        Ok(changed)
    }

    fn build_attempt_proof(
        &self,
        record: &FactoryEffectInvocationProof,
        pending: &PendingFactoryEffectAttempt,
        receipt: InvocationReceipt,
    ) -> Result<FactoryEffectAttemptProof, M5M3AdapterError> {
        if receipt.invocation_id() != pending.invocation.identity.invocation_id {
            return Err(M5M3AdapterError::CorruptLedger(format!(
                "M3 returned receipt '{}' for pending invocation '{}'",
                receipt.invocation_id(),
                pending.invocation.identity.invocation_id
            )));
        }
        let durable_input = self
            .m3
            .invocation_input(&pending.invocation.identity.invocation_id)?;
        let attestation = self
            .m3
            .attestation(&pending.invocation.identity.invocation_id)?;
        let result = match receipt.outcome() {
            InvocationOutcome::Succeeded {
                result: CapabilitySuccess::FactoryEffect(result),
            } => Some(result.as_ref().clone()),
            InvocationOutcome::Succeeded { .. } => {
                return Err(M5M3AdapterError::CorruptLedger(format!(
                    "factory invocation '{}' returned a non-factory success",
                    receipt.invocation_id()
                )));
            }
            InvocationOutcome::Terminal { .. } => None,
        };
        let mut proof = FactoryEffectAttemptProof {
            schema: M5_M3_ATTEMPT_SCHEMA.to_string(),
            attempt_number: pending.attempt_number,
            invocation: pending.invocation.clone(),
            durable_input,
            receipt,
            attestation,
            result,
            proof_digest: ContentDigest::from_bytes(&[]),
        };
        proof.proof_digest = attempt_proof_digest(&proof)?;
        self.validate_attempt_local(record, &proof)?;
        Ok(proof)
    }

    fn validate_local_state(&self, state: &M5M3LedgerState) -> Result<(), M5M3AdapterError> {
        if state.schema != M5_M3_LEDGER_SCHEMA {
            return Err(M5M3AdapterError::CorruptLedger(
                "unsupported proof ledger schema".to_string(),
            ));
        }
        state.config.validate().map_err(|error| {
            M5M3AdapterError::CorruptLedger(format!("durable adapter config is invalid: {error}"))
        })?;
        if state.config != self.config {
            return Err(M5M3AdapterError::Conflict(
                "durable adapter config does not match the open request".to_string(),
            ));
        }
        let expected_config_digest = adapter_config_digest(&state.config)?;
        if state.config_digest != expected_config_digest {
            return Err(M5M3AdapterError::CorruptLedger(
                "adapter config digest does not match its fields".to_string(),
            ));
        }
        if state.records.len() > MAX_LEDGER_RECORDS {
            return Err(M5M3AdapterError::ResourceBoundExceeded {
                resource: "proof record count",
                actual: state.records.len(),
                limit: MAX_LEDGER_RECORDS,
            });
        }

        let mut previous_fingerprint: Option<&ContentDigest> = None;
        let mut logical_effect_ids = BTreeSet::new();
        for record in &state.records {
            if let Some(previous) = previous_fingerprint {
                if previous >= &record.request_fingerprint {
                    return Err(M5M3AdapterError::CorruptLedger(
                        "proof records are not strictly ordered by unique request fingerprint"
                            .to_string(),
                    ));
                }
            }
            previous_fingerprint = Some(&record.request_fingerprint);
            if !logical_effect_ids.insert(record.request.logical_effect_id.as_str()) {
                return Err(M5M3AdapterError::CorruptLedger(format!(
                    "logical effect '{}' appears in more than one proof record",
                    record.request.logical_effect_id
                )));
            }
            self.validate_record_local(record)?;
        }
        let expected_ledger_digest = ledger_digest(state)?;
        if state.ledger_digest != expected_ledger_digest {
            return Err(M5M3AdapterError::CorruptLedger(
                "ledger digest does not match its complete record set".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_record_local(
        &self,
        record: &FactoryEffectInvocationProof,
    ) -> Result<(), M5M3AdapterError> {
        if record.schema != M5_M3_PROOF_SCHEMA {
            return Err(M5M3AdapterError::CorruptLedger(
                "unsupported invocation proof schema".to_string(),
            ));
        }
        record.request.validate().map_err(|error| {
            M5M3AdapterError::CorruptLedger(format!("durable factory request is invalid: {error}"))
        })?;
        let expected_fingerprint = factory_request_fingerprint(&self.config, &record.request)?;
        if record.request_fingerprint != expected_fingerprint {
            return Err(M5M3AdapterError::CorruptLedger(format!(
                "factory proof request fingerprint is {}, expected {expected_fingerprint}",
                record.request_fingerprint
            )));
        }
        if record.attempts.len() > usize::from(M5_M3_MAX_ATTEMPTS) {
            return Err(M5M3AdapterError::CorruptLedger(format!(
                "factory proof {} contains more than {M5_M3_MAX_ATTEMPTS} attempts",
                record.request_fingerprint
            )));
        }
        for (index, attempt) in record.attempts.iter().enumerate() {
            let attempt_number = u8::try_from(index + 1).map_err(|_| {
                M5M3AdapterError::CorruptLedger(
                    "attempt index cannot fit its bounded identity".to_string(),
                )
            })?;
            if attempt.attempt_number != attempt_number {
                return Err(M5M3AdapterError::CorruptLedger(format!(
                    "factory proof {} has a non-sequential attempt number",
                    record.request_fingerprint
                )));
            }
            self.validate_attempt_local(record, attempt)?;
            if index + 1 < record.attempts.len() && !attempt_is_retryable_failure(attempt)? {
                return Err(M5M3AdapterError::CorruptLedger(format!(
                    "factory proof {} continued after a terminal attempt",
                    record.request_fingerprint
                )));
            }
        }
        if let Some(pending) = &record.pending_attempt {
            if let Some(last) = record.attempts.last() {
                if !attempt_is_retryable_failure(last)? {
                    return Err(M5M3AdapterError::CorruptLedger(format!(
                        "factory proof {} has a pending retry after a terminal attempt",
                        record.request_fingerprint
                    )));
                }
            }
            let expected_number = u8::try_from(record.attempts.len() + 1).map_err(|_| {
                M5M3AdapterError::CorruptLedger(
                    "pending attempt index cannot fit its bounded identity".to_string(),
                )
            })?;
            if pending.attempt_number != expected_number
                || pending.attempt_number > M5_M3_MAX_ATTEMPTS
            {
                return Err(M5M3AdapterError::CorruptLedger(format!(
                    "factory proof {} has an invalid pending attempt number",
                    record.request_fingerprint
                )));
            }
            let expected_invocation = self.expected_invocation(
                &record.request,
                &record.request_fingerprint,
                pending.attempt_number,
            )?;
            if pending.invocation != expected_invocation
                || pending.intent_digest != pending_attempt_digest(pending)?
            {
                return Err(M5M3AdapterError::CorruptLedger(format!(
                    "factory proof {} pending intent is not canonical",
                    record.request_fingerprint
                )));
            }
        }
        let expected_status = derive_proof_status(record)?;
        if record.status != expected_status {
            return Err(M5M3AdapterError::CorruptLedger(format!(
                "factory proof {} status is {:?}, expected {expected_status:?}",
                record.request_fingerprint, record.status
            )));
        }
        if record.proof_digest != invocation_proof_digest(record)? {
            return Err(M5M3AdapterError::CorruptLedger(format!(
                "factory proof {} digest does not match its fields",
                record.request_fingerprint
            )));
        }
        Ok(())
    }

    fn validate_attempt_local(
        &self,
        record: &FactoryEffectInvocationProof,
        attempt: &FactoryEffectAttemptProof,
    ) -> Result<(), M5M3AdapterError> {
        if attempt.schema != M5_M3_ATTEMPT_SCHEMA {
            return Err(M5M3AdapterError::CorruptLedger(
                "unsupported attempt proof schema".to_string(),
            ));
        }
        let expected_invocation = self.expected_invocation(
            &record.request,
            &record.request_fingerprint,
            attempt.attempt_number,
        )?;
        if attempt.invocation != expected_invocation || attempt.durable_input != expected_invocation
        {
            return Err(M5M3AdapterError::CorruptLedger(format!(
                "attempt {} for {} does not contain the exact canonical invocation and input",
                attempt.attempt_number, record.request_fingerprint
            )));
        }
        attempt.receipt.verify_integrity().map_err(|error| {
            M5M3AdapterError::CorruptLedger(format!(
                "attempt {} receipt failed integrity: {error}",
                attempt.attempt_number
            ))
        })?;
        let canonical_input_bytes = serde_json::to_vec(&attempt.invocation)?;
        if attempt.receipt.invocation_id() != attempt.invocation.identity.invocation_id
            || attempt.receipt.service_id() != record.request.operation.service_id()
            || attempt.receipt.family() != record.request.operation.family()
            || attempt.receipt.operation() != record.request.operation.capability_operation()
            || attempt.receipt.scope_id() != self.config.scope_id
            || attempt.receipt.input_digest() != &ContentDigest::from_bytes(&canonical_input_bytes)
        {
            return Err(M5M3AdapterError::CorruptLedger(format!(
                "attempt {} receipt identity differs from its exact invocation",
                attempt.attempt_number
            )));
        }
        let attestation = &attempt.attestation;
        let expected_attestation_id = format!(
            "attestation:{}",
            attempt.receipt.receipt_digest().file_stem()
        );
        if attestation.schema != CAPABILITY_ATTESTATION_SCHEMA
            || attestation.attestation_id != expected_attestation_id
            || attestation.invocation_id != attempt.receipt.invocation_id()
            || attestation.service_id != attempt.receipt.service_id()
            || attestation.family != attempt.receipt.family()
            || attestation.operation != attempt.receipt.operation()
            || attestation.scope_id != attempt.receipt.scope_id()
            || &attestation.input_digest != attempt.receipt.input_digest()
            || &attestation.output_digest != attempt.receipt.output_digest()
            || &attestation.receipt_digest != attempt.receipt.receipt_digest()
            || &attestation.provenance != attempt.receipt.provenance()
            || attestation.terminal_success != attempt.receipt.outcome().is_success()
            || attestation.failure_kind != attempt.receipt.outcome().failure_kind()
        {
            return Err(M5M3AdapterError::CorruptLedger(format!(
                "attempt {} attestation differs from its receipt",
                attempt.attempt_number
            )));
        }
        match attempt.receipt.outcome() {
            InvocationOutcome::Succeeded {
                result: CapabilitySuccess::FactoryEffect(receipt_result),
            } => {
                let stored_result = attempt.result.as_ref().ok_or_else(|| {
                    M5M3AdapterError::CorruptLedger(format!(
                        "successful attempt {} does not retain its factory result",
                        attempt.attempt_number
                    ))
                })?;
                if stored_result != receipt_result.as_ref() {
                    return Err(M5M3AdapterError::CorruptLedger(format!(
                        "attempt {} stored result differs from its receipt",
                        attempt.attempt_number
                    )));
                }
                validate_factory_result(&record.request, stored_result)?;
            }
            InvocationOutcome::Succeeded { .. } => {
                return Err(M5M3AdapterError::CorruptLedger(format!(
                    "attempt {} has a non-factory success",
                    attempt.attempt_number
                )));
            }
            InvocationOutcome::Terminal { .. } if attempt.result.is_some() => {
                return Err(M5M3AdapterError::CorruptLedger(format!(
                    "terminal attempt {} incorrectly retains a success result",
                    attempt.attempt_number
                )));
            }
            InvocationOutcome::Terminal { .. } => {}
        }
        if attempt.proof_digest != attempt_proof_digest(attempt)? {
            return Err(M5M3AdapterError::CorruptLedger(format!(
                "attempt {} proof digest does not match its fields",
                attempt.attempt_number
            )));
        }
        Ok(())
    }

    fn validate_record_against_m3(
        &self,
        record: &FactoryEffectInvocationProof,
    ) -> Result<(), M5M3AdapterError> {
        for attempt in &record.attempts {
            let invocation_id = &attempt.invocation.identity.invocation_id;
            if self.m3.receipt(invocation_id)? != attempt.receipt {
                return Err(M5M3AdapterError::CorruptLedger(format!(
                    "M3 receipt for '{invocation_id}' differs from the proof ledger"
                )));
            }
            if self.m3.invocation_input(invocation_id)? != attempt.durable_input {
                return Err(M5M3AdapterError::CorruptLedger(format!(
                    "M3 input for '{invocation_id}' differs from the proof ledger"
                )));
            }
            if self.m3.attestation(invocation_id)? != attempt.attestation {
                return Err(M5M3AdapterError::CorruptLedger(format!(
                    "M3 attestation for '{invocation_id}' differs from the proof ledger"
                )));
            }
        }
        if let Some(pending) = &record.pending_attempt {
            match self.m3.receipt(&pending.invocation.identity.invocation_id) {
                Ok(_) => {
                    return Err(M5M3AdapterError::CorruptLedger(format!(
                        "pending invocation '{}' has an unsealed M3 receipt",
                        pending.invocation.identity.invocation_id
                    )));
                }
                Err(M3RuntimeError::Capability(CapabilityHostError::ReceiptNotFound {
                    ..
                })) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn expected_invocation(
        &self,
        request: &FactoryEffectInvokeRequest,
        request_fingerprint: &ContentDigest,
        attempt_number: u8,
    ) -> Result<CapabilityInvocation, M5M3AdapterError> {
        if attempt_number == 0 || attempt_number > M5_M3_MAX_ATTEMPTS {
            return Err(M5M3AdapterError::CorruptLedger(format!(
                "attempt number must be between 1 and {M5_M3_MAX_ATTEMPTS}"
            )));
        }
        let identity_digest =
            digest_json(&(ATTEMPT_IDENTITY_DOMAIN, request_fingerprint, attempt_number))?;
        let identity_stem = identity_digest.file_stem();
        let approval = if request.operation.requires_human_approval() {
            InvocationApproval::Granted {
                approval_ref: request.approval_ref.clone().ok_or_else(|| {
                    M5M3AdapterError::InvalidRequest(
                        "promotion operation is missing its human approval reference".to_string(),
                    )
                })?,
                class: ApprovalClass::HumanRequired,
            }
        } else {
            InvocationApproval::Automatic
        };
        let effect_request = FactoryEffectRequest {
            scope_id: self.config.scope_id.clone(),
            factory_id: self.config.factory_id.clone(),
            logical_effect_id: request.logical_effect_id.clone(),
            exact_request_digest: request.exact_request_digest.clone(),
            exact_request_bytes: request.exact_request_bytes.clone(),
        };
        Ok(CapabilityInvocation {
            identity: InvocationIdentity {
                invocation_id: format!("m5-m3-invocation:{identity_stem}"),
                idempotency_key: format!("m5-m3-idempotency:{identity_stem}"),
                service_id: request.operation.service_id().to_string(),
                scope_id: self.config.scope_id.clone(),
                caller_id: self.config.caller_id.clone(),
                authority: request.operation.authority(),
                approval,
            },
            budget: InvocationBudget::bounded(self.config.invocation_timeout_ms),
            request: request.operation.wrap_request(effect_request),
        })
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, M5M3LedgerState>, M5M3AdapterError> {
        self.state.lock().map_err(|_| {
            M5M3AdapterError::Conflict("proof ledger state lock was poisoned".to_string())
        })
    }

    fn persist_state(&self, state: &M5M3LedgerState) -> Result<(), M5M3AdapterError> {
        let bytes = serde_json::to_vec_pretty(state)?;
        enforce_bound("ledger state bytes", bytes.len(), MAX_LEDGER_BYTES)?;
        atomic_replace(&self.root, &self.root.join(LEDGER_STATE_FILE), &bytes)
    }
}

fn validate_m3_factory_catalog(
    config: &M5M3AdapterConfig,
    m3: &M3CapabilityRuntime,
) -> Result<(), M5M3AdapterError> {
    if m3.config().scope_id != config.scope_id {
        return Err(M5M3AdapterError::InvalidConfig(format!(
            "adapter scope '{}' differs from M3 scope '{}'",
            config.scope_id,
            m3.config().scope_id
        )));
    }
    let expected = [
        (
            FACTORY_EXECUTION_SERVICE_ID,
            NativeServiceFamily::Validation,
            BTreeSet::from([
                CapabilityOperation::FactoryExecute,
                CapabilityOperation::FactoryProviderProposal,
                CapabilityOperation::FactoryShadow,
            ]),
        ),
        (
            FACTORY_PROMOTION_SERVICE_ID,
            NativeServiceFamily::Operations,
            BTreeSet::from([
                CapabilityOperation::FactoryInitialize,
                CapabilityOperation::FactoryStateMigrate,
                CapabilityOperation::FactoryActivate,
                CapabilityOperation::FactoryObserve,
                CapabilityOperation::FactoryRollback,
            ]),
        ),
        (
            FACTORY_INSPECT_SERVICE_ID,
            NativeServiceFamily::Operations,
            BTreeSet::from([CapabilityOperation::FactoryInspect]),
        ),
    ];
    for (service_id, family, operations) in expected {
        let registration = m3
            .services()
            .iter()
            .find(|registration| registration.service_id == service_id)
            .ok_or_else(|| {
                M5M3AdapterError::InvalidConfig(format!(
                    "M3 runtime does not register required factory service '{service_id}'"
                ))
            })?;
        if registration.family != family || registration.supported_operations != operations {
            return Err(M5M3AdapterError::InvalidConfig(format!(
                "M3 factory service '{service_id}' does not expose the exact expected family and operations"
            )));
        }
    }
    Ok(())
}

fn factory_request_fingerprint(
    config: &M5M3AdapterConfig,
    request: &FactoryEffectInvokeRequest,
) -> Result<ContentDigest, M5M3AdapterError> {
    digest_json(&(
        REQUEST_FINGERPRINT_DOMAIN,
        &config.scope_id,
        &config.factory_id,
        &config.caller_id,
        request,
    ))
}

fn adapter_config_digest(config: &M5M3AdapterConfig) -> Result<ContentDigest, M5M3AdapterError> {
    digest_json(&("wasm-biotic:m5-m3-config:v1", config))
}

fn pending_attempt_digest(
    pending: &PendingFactoryEffectAttempt,
) -> Result<ContentDigest, M5M3AdapterError> {
    digest_json(&(
        ATTEMPT_IDENTITY_DOMAIN,
        pending.attempt_number,
        &pending.invocation,
    ))
}

fn attempt_proof_digest(
    proof: &FactoryEffectAttemptProof,
) -> Result<ContentDigest, M5M3AdapterError> {
    digest_json(&(
        M5_M3_ATTEMPT_SCHEMA,
        proof.attempt_number,
        &proof.invocation,
        &proof.durable_input,
        &proof.receipt,
        &proof.attestation,
        &proof.result,
    ))
}

fn invocation_proof_digest(
    proof: &FactoryEffectInvocationProof,
) -> Result<ContentDigest, M5M3AdapterError> {
    digest_json(&(
        M5_M3_PROOF_SCHEMA,
        &proof.request_fingerprint,
        &proof.request,
        &proof.attempts,
        &proof.pending_attempt,
        proof.status,
    ))
}

fn ledger_digest(state: &M5M3LedgerState) -> Result<ContentDigest, M5M3AdapterError> {
    digest_json(&(
        M5_M3_LEDGER_SCHEMA,
        &state.config,
        &state.config_digest,
        &state.records,
    ))
}

fn digest_json<T: Serialize>(value: &T) -> Result<ContentDigest, M5M3AdapterError> {
    digest_json_content(value).map_err(|error| M5M3AdapterError::Digest(error.to_string()))
}

fn derive_proof_status(
    record: &FactoryEffectInvocationProof,
) -> Result<FactoryEffectProofStatus, M5M3AdapterError> {
    if record.pending_attempt.is_some() {
        return Ok(FactoryEffectProofStatus::InFlight);
    }
    let Some(last) = record.attempts.last() else {
        return Ok(FactoryEffectProofStatus::Retryable);
    };
    match last.receipt.outcome() {
        InvocationOutcome::Succeeded {
            result: CapabilitySuccess::FactoryEffect(_),
        } => Ok(FactoryEffectProofStatus::Succeeded),
        InvocationOutcome::Succeeded { .. } => Err(M5M3AdapterError::CorruptLedger(
            "factory proof contains a non-factory success".to_string(),
        )),
        InvocationOutcome::Terminal { failure } if retryable_failure(failure.kind) => {
            if record.attempts.len() >= usize::from(M5_M3_MAX_ATTEMPTS) {
                Ok(FactoryEffectProofStatus::Exhausted)
            } else {
                Ok(FactoryEffectProofStatus::Retryable)
            }
        }
        InvocationOutcome::Terminal { .. } => Ok(FactoryEffectProofStatus::TerminalFailure),
    }
}

fn attempt_is_retryable_failure(
    attempt: &FactoryEffectAttemptProof,
) -> Result<bool, M5M3AdapterError> {
    match attempt.receipt.outcome() {
        InvocationOutcome::Terminal { failure } => Ok(retryable_failure(failure.kind)),
        InvocationOutcome::Succeeded {
            result: CapabilitySuccess::FactoryEffect(_),
        } => Ok(false),
        InvocationOutcome::Succeeded { .. } => Err(M5M3AdapterError::CorruptLedger(
            "factory attempt contains a non-factory success".to_string(),
        )),
    }
}

fn retryable_failure(kind: ServiceFailureKind) -> bool {
    matches!(
        kind,
        ServiceFailureKind::Failed
            | ServiceFailureKind::TimedOut
            | ServiceFailureKind::Cancelled
            | ServiceFailureKind::Unavailable
            | ServiceFailureKind::ResourceExhausted
    )
}

fn validate_factory_result(
    request: &FactoryEffectInvokeRequest,
    result: &FactoryEffectResult,
) -> Result<(), M5M3AdapterError> {
    if result.logical_effect_id != request.logical_effect_id
        || result.exact_request_digest != request.exact_request_digest
    {
        return Err(M5M3AdapterError::CorruptLedger(
            "factory result does not bind the exact logical effect and request digest".to_string(),
        ));
    }
    if result.exact_response_bytes.len() > MAX_FACTORY_EFFECT_RESPONSE_BYTES {
        return Err(M5M3AdapterError::ResourceBoundExceeded {
            resource: "factory response bytes",
            actual: result.exact_response_bytes.len(),
            limit: MAX_FACTORY_EFFECT_RESPONSE_BYTES,
        });
    }
    let actual = ContentDigest::from_bytes(&result.exact_response_bytes);
    if result.exact_response_digest != actual {
        return Err(M5M3AdapterError::CorruptLedger(format!(
            "factory response bytes digest to {actual}, declared {}",
            result.exact_response_digest
        )));
    }
    Ok(())
}

fn record_index(
    state: &M5M3LedgerState,
    fingerprint: &ContentDigest,
) -> Result<usize, M5M3AdapterError> {
    state
        .records
        .binary_search_by(|record| record.request_fingerprint.cmp(fingerprint))
        .map_err(|_| {
            M5M3AdapterError::CorruptLedger(format!(
                "proof record {fingerprint} disappeared from the ledger"
            ))
        })
}

fn refresh_record_and_ledger_digests(
    state: &mut M5M3LedgerState,
    record_index: usize,
) -> Result<(), M5M3AdapterError> {
    let record_digest =
        invocation_proof_digest(state.records.get(record_index).ok_or_else(|| {
            M5M3AdapterError::CorruptLedger("proof record index is out of bounds".to_string())
        })?)?;
    state.records[record_index].proof_digest = record_digest;
    state.ledger_digest = ledger_digest(state)?;
    Ok(())
}

fn validate_safe_identifier(
    field: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), M5M3AdapterError> {
    let path = Path::new(value);
    let valid = !value.trim().is_empty()
        && value.len() <= max_bytes
        && !path.is_absolute()
        && !value.contains('/')
        && !value.contains('\\')
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if valid {
        Ok(())
    } else {
        Err(M5M3AdapterError::InvalidConfig(format!(
            "{field} is not a safe identifier bounded to {max_bytes} bytes: {value:?}"
        )))
    }
}

fn validate_bounded_nonblank(
    field: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), M5M3AdapterError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        Err(M5M3AdapterError::InvalidRequest(format!(
            "{field} must contain 1..={max_bytes} nonblank bytes"
        )))
    } else {
        Ok(())
    }
}

fn enforce_bound(
    resource: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), M5M3AdapterError> {
    if actual > limit {
        Err(M5M3AdapterError::ResourceBoundExceeded {
            resource,
            actual,
            limit,
        })
    } else {
        Ok(())
    }
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M5M3AdapterError> {
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| M5M3AdapterError::io(path, source))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M5M3AdapterError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(M5M3AdapterError::UnsafePath {
            path: path.to_path_buf(),
            reason: "ledger root must be a real directory",
        });
    }
    fs::canonicalize(path).map_err(|source| M5M3AdapterError::io(path, source))
}

fn acquire_owner_lock(root: &Path) -> Result<File, M5M3AdapterError> {
    let path = root.join(LEDGER_OWNER_LOCK_FILE);
    reject_symlink_if_present(&path)?;
    if path.exists() {
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| M5M3AdapterError::io(&path, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(M5M3AdapterError::UnsafePath {
                path,
                reason: "ledger owner lock must be a regular file",
            });
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| M5M3AdapterError::io(&path, source))?;
    file.try_lock().map_err(|source| match source {
        std::fs::TryLockError::WouldBlock => M5M3AdapterError::Conflict(format!(
            "proof ledger root '{}' already has a live owner",
            root.display()
        )),
        std::fs::TryLockError::Error(source) => M5M3AdapterError::io(&path, source),
    })?;
    Ok(file)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M5M3AdapterError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(M5M3AdapterError::UnsafePath {
            path: path.to_path_buf(),
            reason: "symbolic links are not accepted",
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M5M3AdapterError::io(path, source)),
    }
}

fn read_state(path: &Path) -> Result<M5M3LedgerState, M5M3AdapterError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M5M3AdapterError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(M5M3AdapterError::UnsafePath {
            path: path.to_path_buf(),
            reason: "ledger state must be a regular non-symlink file",
        });
    }
    let byte_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    enforce_bound("ledger state bytes", byte_len, MAX_LEDGER_BYTES)?;
    let mut bytes = Vec::with_capacity(byte_len);
    File::open(path)
        .map_err(|source| M5M3AdapterError::io(path, source))?
        .read_to_end(&mut bytes)
        .map_err(|source| M5M3AdapterError::io(path, source))?;
    let state = serde_json::from_slice::<M5M3LedgerState>(&bytes)?;
    if serde_json::to_vec_pretty(&state)? != bytes {
        return Err(M5M3AdapterError::CorruptLedger(
            "ledger state bytes are not the canonical persisted JSON encoding".to_string(),
        ));
    }
    Ok(state)
}

fn atomic_replace(root: &Path, destination: &Path, bytes: &[u8]) -> Result<(), M5M3AdapterError> {
    reject_symlink_if_present(destination)?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(
        ".m5-m3-ledger-write-{}-{sequence}",
        std::process::id()
    ));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| M5M3AdapterError::io(&temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| M5M3AdapterError::io(&temporary, source))?;
        file.sync_all()
            .map_err(|source| M5M3AdapterError::io(&temporary, source))?;
        fs::rename(&temporary, destination)
            .map_err(|source| M5M3AdapterError::io(destination, source))?;
        File::open(root)
            .map_err(|source| M5M3AdapterError::io(root, source))?
            .sync_all()
            .map_err(|source| M5M3AdapterError::io(root, source))
    })();
    if temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_services::{FactoryEvolutionPort, InvocationControl, ServiceFailure};
    use crate::m2_runtime::{M2Runtime, M2RuntimeConfig};
    use std::collections::BTreeSet;
    use std::sync::atomic::AtomicU64;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const SCOPE: &str = "scope-a";
    const FACTORY: &str = "factory-a";
    const DEPLOYMENT: &str = "reference-task";

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "wasm-biotic-m5-m3-{label}-{}-{sequence}",
                std::process::id()
            ));
            if root.exists() {
                fs::remove_dir_all(&root).expect("remove stale adapter test root");
            }
            fs::create_dir(&root).expect("create adapter test root");
            Self { root }
        }

        fn copy_template(&self) -> PathBuf {
            let destination = self.root.join("template");
            fs::create_dir(&destination).expect("create isolated template");
            let fixture = fixture_root().join("template");
            for file in ["component.wit", "component.wat"] {
                fs::copy(fixture.join(file), destination.join(file)).expect("copy frozen template");
            }
            destination
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Default)]
    struct RetryThenSucceedFactoryPort {
        calls: Mutex<Vec<(CapabilityOperation, FactoryEffectRequest)>>,
    }

    impl FactoryEvolutionPort for RetryThenSucceedFactoryPort {
        fn apply_factory_effect(
            &self,
            operation: CapabilityOperation,
            request: &FactoryEffectRequest,
            control: &InvocationControl,
        ) -> Result<FactoryEffectResult, ServiceFailure> {
            control.check()?;
            let call_number = {
                let mut calls = self.calls.lock().expect("lock fixture calls");
                calls.push((operation, request.clone()));
                calls.len()
            };
            if call_number <= 2 {
                return Err(ServiceFailure::unavailable(
                    "fixture_transient_unavailable",
                    "fixture fails its first two bounded attempts",
                ));
            }
            let mut response = format!("{operation:?}:").into_bytes();
            response.extend_from_slice(&request.exact_request_bytes);
            Ok(FactoryEffectResult::new(request, response))
        }
    }

    #[test]
    fn operation_mapping_is_complete_and_exact() {
        let automatic = [
            FactoryEffectOperation::Execute,
            FactoryEffectOperation::ProviderProposal,
            FactoryEffectOperation::Shadow,
            FactoryEffectOperation::Inspect,
        ];
        for operation in automatic {
            assert_eq!(operation.authority(), AuthorityClass::Observe);
            assert_eq!(operation.required_approval(), ApprovalClass::AutoAllowed);
            assert!(!operation.requires_human_approval());
        }
        assert_eq!(
            FactoryEffectOperation::Execute.service_id(),
            FACTORY_EXECUTION_SERVICE_ID
        );
        assert_eq!(
            FactoryEffectOperation::Shadow.service_id(),
            FACTORY_EXECUTION_SERVICE_ID
        );
        assert_eq!(
            FactoryEffectOperation::ProviderProposal.service_id(),
            FACTORY_EXECUTION_SERVICE_ID
        );
        assert_eq!(
            FactoryEffectOperation::Inspect.service_id(),
            FACTORY_INSPECT_SERVICE_ID
        );

        let promotion = [
            FactoryEffectOperation::Initialize,
            FactoryEffectOperation::StateMigrate,
            FactoryEffectOperation::Activate,
            FactoryEffectOperation::Observe,
            FactoryEffectOperation::Rollback,
        ];
        for operation in promotion {
            assert_eq!(operation.service_id(), FACTORY_PROMOTION_SERVICE_ID);
            assert_eq!(operation.family(), NativeServiceFamily::Operations);
            assert_eq!(operation.authority(), AuthorityClass::PromotionControl);
            assert_eq!(operation.required_approval(), ApprovalClass::HumanRequired);
            assert!(operation.requires_human_approval());
        }
        assert_eq!(
            FactoryEffectOperation::Shadow.family(),
            NativeServiceFamily::Validation
        );
        assert_eq!(
            FactoryEffectOperation::ProviderProposal.family(),
            NativeServiceFamily::Validation
        );
        assert_eq!(
            FactoryEffectOperation::Inspect.family(),
            NativeServiceFamily::Operations
        );
        assert_eq!(
            [
                FactoryEffectOperation::Execute,
                FactoryEffectOperation::ProviderProposal,
                FactoryEffectOperation::Shadow,
                FactoryEffectOperation::Initialize,
                FactoryEffectOperation::StateMigrate,
                FactoryEffectOperation::Activate,
                FactoryEffectOperation::Observe,
                FactoryEffectOperation::Rollback,
                FactoryEffectOperation::Inspect,
            ]
            .into_iter()
            .map(FactoryEffectOperation::capability_operation)
            .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                CapabilityOperation::FactoryExecute,
                CapabilityOperation::FactoryProviderProposal,
                CapabilityOperation::FactoryShadow,
                CapabilityOperation::FactoryInitialize,
                CapabilityOperation::FactoryStateMigrate,
                CapabilityOperation::FactoryActivate,
                CapabilityOperation::FactoryObserve,
                CapabilityOperation::FactoryRollback,
                CapabilityOperation::FactoryInspect,
            ])
        );
    }

    #[test]
    fn provider_proposal_retries_with_stable_identity_and_reopens_complete_m3_proofs() {
        let test = TestDirectory::new("retry-reload");
        let template = test.copy_template();
        let m2 = Arc::new(
            M2Runtime::new(M2RuntimeConfig {
                supervisor_root: test.root.join("m2-supervisor"),
                lifecycle_root: test.root.join("m2-lifecycle"),
                template_root: template.clone(),
                owner_id: "m5-m3-adapter-test".to_string(),
                max_idle_wait_ms: 10,
            })
            .expect("construct M2"),
        );
        let backend = Arc::new(RetryThenSucceedFactoryPort::default());
        let factory_port: Arc<dyn FactoryEvolutionPort> = backend.clone();
        let m3 = Arc::new(
            M3CapabilityRuntime::open_with_factory_evolution(
                crate::m3_runtime::M3RuntimeConfig::new(
                    test.root.join("m3"),
                    template,
                    SCOPE,
                    DEPLOYMENT,
                ),
                Arc::clone(&m2),
                factory_port,
            )
            .expect("open M3 factory extension"),
        );
        let config = M5M3AdapterConfig {
            root: test.root.join("ledger"),
            scope_id: SCOPE.to_string(),
            factory_id: FACTORY.to_string(),
            caller_id: "m5-fixture".to_string(),
            invocation_timeout_ms: 30_000,
        };
        let ledger = M5M3InvocationProofLedger::open(config.clone(), Arc::clone(&m3))
            .expect("open proof ledger");
        let exact_request_bytes = b"\0opaque-provider-proposal\xff".to_vec();
        let request = FactoryEffectInvokeRequest::new(
            FactoryEffectOperation::ProviderProposal,
            "logical:provider-proposal:1",
            exact_request_bytes.clone(),
            None,
        );
        let proof = ledger.invoke(request.clone()).expect("invoke with retries");
        assert_eq!(proof.status, FactoryEffectProofStatus::Succeeded);
        assert_eq!(proof.attempts.len(), 3);
        assert!(proof.pending_attempt.is_none());
        assert!(proof.terminal_result().is_some());
        assert_eq!(
            proof
                .attempts
                .iter()
                .map(|attempt| attempt.invocation.identity.invocation_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        assert_eq!(
            proof.attempts[0].receipt.outcome().failure_kind(),
            Some(ServiceFailureKind::Unavailable)
        );
        assert_eq!(
            proof.attempts[1].receipt.outcome().failure_kind(),
            Some(ServiceFailureKind::Unavailable)
        );
        assert!(proof.attempts[2].receipt.outcome().is_success());
        for attempt in &proof.attempts {
            assert!(
                attempt.invocation == attempt.durable_input,
                "M3 attempt invocation differed from its durable input (attempt={})",
                attempt.attempt_number
            );
            assert_eq!(
                attempt.attestation.receipt_digest,
                *attempt.receipt.receipt_digest()
            );
        }
        let calls = backend.calls.lock().expect("read backend calls");
        assert_eq!(calls.len(), 3);
        assert!(calls.iter().all(|(operation, effect)| {
            *operation == CapabilityOperation::FactoryProviderProposal
                && effect.logical_effect_id == "logical:provider-proposal:1"
                && effect.exact_request_bytes.as_slice() == exact_request_bytes.as_slice()
        }));
        drop(calls);

        let validated = ledger.validate_all().expect("validate complete ledger");
        assert!(
            validated == vec![proof.clone()],
            "validated M5/M3 proof ledger differed from the exact singleton (actual_count={})",
            validated.len()
        );
        let replayed = ledger
            .invoke(request.clone())
            .expect("idempotent adapter replay");
        assert!(
            replayed == proof,
            "idempotent M5/M3 adapter replay differed from the retained proof"
        );
        assert_eq!(backend.calls.lock().unwrap().len(), 3);
        assert!(matches!(
            ledger.invoke(FactoryEffectInvokeRequest::new(
                FactoryEffectOperation::ProviderProposal,
                "logical:provider-proposal:1",
                b"different".to_vec(),
                None,
            )),
            Err(M5M3AdapterError::Conflict(_))
        ));
        drop(ledger);

        let reopened = M5M3InvocationProofLedger::open(config, Arc::clone(&m3))
            .expect("reopen and rederive proof ledger");
        let reopened_proofs = reopened.validate_all().expect("validate reopened ledger");
        assert!(
            reopened_proofs == vec![proof],
            "reopened M5/M3 proof ledger differed from the exact singleton (actual_count={})",
            reopened_proofs.len()
        );
        assert!(matches!(
            FactoryEffectInvokeRequest::new(
                FactoryEffectOperation::Activate,
                "logical:activate:missing-approval",
                b"activate".to_vec(),
                None,
            )
            .validate(),
            Err(M5M3AdapterError::InvalidRequest(_))
        ));
        drop(reopened);
        drop(m3);
        m2.stop().expect("stop M2");
    }

    fn fixture_root() -> PathBuf {
        let source = PathBuf::from(file!());
        let absolute = if source.is_absolute() {
            source
        } else {
            std::env::current_dir()
                .expect("current directory")
                .join(source)
        };
        absolute
            .parent()
            .and_then(Path::parent)
            .expect("source file beneath repository root")
            .join("artifacts/fixtures/m1-reference-component")
    }
}
