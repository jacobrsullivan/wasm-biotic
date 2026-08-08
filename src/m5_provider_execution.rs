//! Canonical proof that one M5 provider call happened after an M7 v4 manifest.
//!
//! The durable provider binding proves what qualification was accepted, but it
//! cannot by itself prove that the qualification was produced by the current
//! operator invocation.  This receipt adds the missing causal boundary.  It
//! contains only identifiers, digests, timestamps, and a fresh OS-random
//! nonce; provider prompts, responses, transcripts, and credentials are never
//! copied into it.

use crate::execution::ContentDigest;
use crate::factory_reproduction::{
    CycleOutcome, M5ProviderEndpointClassV1, ProviderQualificationStatus, StopReason,
};
use crate::m5_provider_binding::ProviderCandidateBinding;
use crate::m5_runtime::{
    M5_PROVIDER_RUN_NONCE_BYTES, M5ChallengedProviderSeedV1, M5PreparedProviderSeedV1,
};
use crate::m7_closure::{LiveProviderQualificationScope, M7ProofRunManifest};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

pub const M5_PROVIDER_EXECUTION_RECEIPT_SCHEMA: &str =
    "wasm-biotic.m5-provider-execution-receipt.v2";
pub const M5_COMPLETED_PROVIDER_INVOCATION_SCHEMA: &str =
    "wasm-biotic.m5-completed-provider-invocation.v1";
const RECEIPT_DIGEST_DOMAIN: &str = "wasm-biotic:m5-provider-execution-receipt:v2";
const COMPLETED_INVOCATION_DIGEST_DOMAIN: &str = "wasm-biotic:m5-completed-provider-invocation:v1";
const TERMINAL_OUTCOME_DIGEST_DOMAIN: &str = "wasm-biotic:m5-provider-terminal-outcome:v1";
const MAX_RECEIPT_BYTES: usize = 64 * 1024;

/// Redacted terminal disposition bound by the execution receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum M5ProviderTerminalOutcomeV1 {
    Adopted {
        package_digest: ContentDigest,
        cycle_record_digest: ContentDigest,
    },
    GateRejected {
        package_digest: ContentDigest,
        cycle_record_digest: ContentDigest,
    },
    ApprovalRejected {
        package_digest: ContentDigest,
        cycle_record_digest: ContentDigest,
    },
    QuarantinedAndRolledBack {
        package_digest: ContentDigest,
        restored_package_digest: ContentDigest,
        cycle_record_digest: ContentDigest,
    },
    Stopped {
        active_package_digest: ContentDigest,
        stop_record_digest: ContentDigest,
        reason: StopReason,
    },
}

impl From<&CycleOutcome> for M5ProviderTerminalOutcomeV1 {
    fn from(outcome: &CycleOutcome) -> Self {
        match outcome {
            CycleOutcome::Adopted {
                package_digest,
                cycle_record_digest,
            } => Self::Adopted {
                package_digest: package_digest.clone(),
                cycle_record_digest: cycle_record_digest.clone(),
            },
            CycleOutcome::GateRejected {
                package_digest,
                cycle_record_digest,
            } => Self::GateRejected {
                package_digest: package_digest.clone(),
                cycle_record_digest: cycle_record_digest.clone(),
            },
            CycleOutcome::ApprovalRejected {
                package_digest,
                cycle_record_digest,
            } => Self::ApprovalRejected {
                package_digest: package_digest.clone(),
                cycle_record_digest: cycle_record_digest.clone(),
            },
            CycleOutcome::QuarantinedAndRolledBack {
                package_digest,
                restored_package_digest,
                cycle_record_digest,
            } => Self::QuarantinedAndRolledBack {
                package_digest: package_digest.clone(),
                restored_package_digest: restored_package_digest.clone(),
                cycle_record_digest: cycle_record_digest.clone(),
            },
            CycleOutcome::Stopped(stop) => Self::Stopped {
                active_package_digest: stop.active_package_digest.clone(),
                stop_record_digest: stop.record_digest.clone(),
                reason: stop.reason,
            },
        }
    }
}

impl M5ProviderTerminalOutcomeV1 {
    pub fn digest(&self) -> Result<ContentDigest, M5ProviderExecutionError> {
        let bytes = serde_json::to_vec(&(TERMINAL_OUTCOME_DIGEST_DOMAIN, self))
            .map_err(|error| M5ProviderExecutionError::Serialization(error.to_string()))?;
        Ok(ContentDigest::from_bytes(&bytes))
    }

    pub fn non_adopted_status(&self) -> Option<&'static str> {
        match self {
            Self::Adopted { .. } => None,
            Self::GateRejected { .. } => Some("gate_rejected"),
            Self::ApprovalRejected { .. } => Some("approval_rejected"),
            Self::QuarantinedAndRolledBack { .. } => Some("quarantined_and_rolled_back"),
            Self::Stopped { .. } => Some("stopped"),
        }
    }

    fn cycle_record_digest(&self) -> Option<&ContentDigest> {
        match self {
            Self::Adopted {
                cycle_record_digest,
                ..
            }
            | Self::GateRejected {
                cycle_record_digest,
                ..
            }
            | Self::ApprovalRejected {
                cycle_record_digest,
                ..
            }
            | Self::QuarantinedAndRolledBack {
                cycle_record_digest,
                ..
            } => Some(cycle_record_digest),
            Self::Stopped { .. } => None,
        }
    }
}

fn terminal_cycle_record_digest(
    outcome: &CycleOutcome,
) -> Result<ContentDigest, M5ProviderExecutionError> {
    match outcome {
        CycleOutcome::Adopted {
            cycle_record_digest,
            ..
        }
        | CycleOutcome::GateRejected {
            cycle_record_digest,
            ..
        }
        | CycleOutcome::ApprovalRejected {
            cycle_record_digest,
            ..
        }
        | CycleOutcome::QuarantinedAndRolledBack {
            cycle_record_digest,
            ..
        } => Ok(cycle_record_digest.clone()),
        CycleOutcome::Stopped(_) => Err(M5ProviderExecutionError::Invalid(
            "completed provider invocation requires an exact terminal cycle record".to_string(),
        )),
    }
}

/// Operator-observed post-call attestation for one exact provider execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ProviderExecutionReceiptV1 {
    pub schema: String,
    pub proof_run_id: String,
    pub manifest_digest: ContentDigest,
    pub manifest_run_started_at_ms: u64,
    pub prepared_digest: ContentDigest,
    pub precommit_digest: ContentDigest,
    pub base_qualification_request_digest: ContentDigest,
    pub qualification_request_digest: ContentDigest,
    pub challenged_seed_digest: ContentDigest,
    pub live_provider_scope_digest: ContentDigest,
    pub invocation_challenge_digest: ContentDigest,
    pub wire_request_digest: ContentDigest,
    pub request_body_digest: ContentDigest,
    pub target_digest: ContentDigest,
    pub binding_digest: ContentDigest,
    pub qualification_record_digest: ContentDigest,
    pub provider_configuration_fingerprint: ContentDigest,
    pub provider_id: String,
    pub model_id: String,
    pub api_base_url: String,
    pub endpoint_class: M5ProviderEndpointClassV1,
    pub qualification_id: String,
    pub qualification_status: ProviderQualificationStatus,
    pub transcript_redacted: bool,
    /// Narrow statement about these canonical receipt bytes only.
    pub credential_material_in_receipt: bool,
    pub terminal_outcome: M5ProviderTerminalOutcomeV1,
    pub terminal_outcome_digest: ContentDigest,
    pub terminal_cycle_record_digest: ContentDigest,
    pub manifest_validated_at_ms: u64,
    pub call_started_at_ms: u64,
    pub call_completed_at_ms: u64,
    pub run_nonce_hex: String,
    pub run_nonce_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
}

#[derive(Serialize)]
struct ReceiptDigestMaterial<'a> {
    domain: &'static str,
    proof_run_id: &'a str,
    manifest_digest: &'a ContentDigest,
    manifest_run_started_at_ms: u64,
    prepared_digest: &'a ContentDigest,
    precommit_digest: &'a ContentDigest,
    base_qualification_request_digest: &'a ContentDigest,
    qualification_request_digest: &'a ContentDigest,
    challenged_seed_digest: &'a ContentDigest,
    live_provider_scope_digest: &'a ContentDigest,
    invocation_challenge_digest: &'a ContentDigest,
    wire_request_digest: &'a ContentDigest,
    request_body_digest: &'a ContentDigest,
    target_digest: &'a ContentDigest,
    binding_digest: &'a ContentDigest,
    qualification_record_digest: &'a ContentDigest,
    provider_configuration_fingerprint: &'a ContentDigest,
    provider_id: &'a str,
    model_id: &'a str,
    api_base_url: &'a str,
    endpoint_class: M5ProviderEndpointClassV1,
    qualification_id: &'a str,
    qualification_status: ProviderQualificationStatus,
    transcript_redacted: bool,
    credential_material_in_receipt: bool,
    terminal_outcome_digest: &'a ContentDigest,
    terminal_cycle_record_digest: &'a ContentDigest,
    manifest_validated_at_ms: u64,
    call_started_at_ms: u64,
    call_completed_at_ms: u64,
    run_nonce_hex: &'a str,
    run_nonce_digest: &'a ContentDigest,
}

impl M5ProviderExecutionReceiptV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        manifest: &M7ProofRunManifest,
        prepared: &M5PreparedProviderSeedV1,
        challenged: &M5ChallengedProviderSeedV1,
        binding: &ProviderCandidateBinding,
        outcome: &CycleOutcome,
        manifest_validated_at_ms: u64,
        call_started_at_ms: u64,
        call_completed_at_ms: u64,
    ) -> Result<Self, M5ProviderExecutionError> {
        // Calling canonical_bytes revalidates the exact public v4 manifest
        // before any of its identities are copied into the receipt.
        manifest.canonical_bytes().map_err(|error| {
            M5ProviderExecutionError::Invalid(format!("M7 manifest is invalid: {error}"))
        })?;
        prepared.validate().map_err(|error| {
            M5ProviderExecutionError::Invalid(format!("prepared seed is invalid: {error}"))
        })?;
        challenged.validate_for(prepared).map_err(|error| {
            M5ProviderExecutionError::Invalid(format!("challenged seed is invalid: {error}"))
        })?;
        binding.validate().map_err(|error| {
            M5ProviderExecutionError::Invalid(format!("provider binding is invalid: {error}"))
        })?;
        let request = challenged.qualification_request();
        let configuration = &request.configuration;
        let turn = binding.qualification.live_turn.as_ref().ok_or_else(|| {
            M5ProviderExecutionError::Invalid(
                "qualified binding has no redacted live-turn evidence".to_string(),
            )
        })?;
        let challenge = challenged.challenge();
        let run_nonce_hex = encode_lower_hex(challenge.run_nonce());
        let terminal_cycle_record_digest = terminal_cycle_record_digest(outcome)?;
        let mut receipt = Self {
            schema: M5_PROVIDER_EXECUTION_RECEIPT_SCHEMA.to_string(),
            proof_run_id: prepared.precommit.proof_run_id.clone(),
            manifest_digest: manifest.manifest_digest().clone(),
            manifest_run_started_at_ms: manifest.run_started_at_ms(),
            prepared_digest: prepared.prepared_digest.clone(),
            precommit_digest: prepared.precommit.precommit_digest.clone(),
            base_qualification_request_digest: prepared
                .qualification_request
                .request_digest
                .clone(),
            qualification_request_digest: request.request_digest.clone(),
            challenged_seed_digest: challenged.challenged_digest().clone(),
            live_provider_scope_digest: challenge.live_provider_scope_digest().clone(),
            invocation_challenge_digest: challenge.invocation_challenge_digest().clone(),
            wire_request_digest: challenged
                .provider_wire_request()
                .wire_request_digest()
                .clone(),
            request_body_digest: challenged
                .provider_wire_request()
                .request_body_digest()
                .clone(),
            target_digest: prepared.target.target_digest.clone(),
            binding_digest: binding.binding_digest.clone(),
            qualification_record_digest: binding.qualification_record_digest.clone(),
            provider_configuration_fingerprint: configuration.fingerprint().map_err(|error| {
                M5ProviderExecutionError::Invalid(format!(
                    "provider configuration cannot be fingerprinted: {error}"
                ))
            })?,
            provider_id: configuration.provider_id.clone(),
            model_id: configuration.model_id.clone(),
            api_base_url: configuration.api_base_url.clone(),
            endpoint_class: configuration.endpoint_class,
            qualification_id: request.qualification_id.clone(),
            qualification_status: binding.qualification.status,
            transcript_redacted: turn.transcript.redaction_applied,
            credential_material_in_receipt: false,
            terminal_outcome: M5ProviderTerminalOutcomeV1::from(outcome),
            terminal_outcome_digest: ContentDigest::from_bytes(&[]),
            terminal_cycle_record_digest,
            manifest_validated_at_ms,
            call_started_at_ms,
            call_completed_at_ms,
            run_nonce_digest: challenge.run_nonce_digest().clone(),
            run_nonce_hex,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.terminal_outcome_digest = receipt.terminal_outcome.digest()?;
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate_for_manifest(manifest, prepared, challenged, binding)?;
        Ok(receipt)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M5ProviderExecutionError> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| M5ProviderExecutionError::Serialization(error.to_string()))?;
        enforce_receipt_bound(bytes.len())?;
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M5ProviderExecutionError> {
        enforce_receipt_bound(bytes.len())?;
        if bytes.is_empty() {
            return Err(M5ProviderExecutionError::Invalid(
                "provider execution receipt is empty".to_string(),
            ));
        }
        let receipt: Self = serde_json::from_slice(bytes)
            .map_err(|error| M5ProviderExecutionError::Serialization(error.to_string()))?;
        receipt.validate()?;
        if serde_json::to_vec_pretty(&receipt)
            .map_err(|error| M5ProviderExecutionError::Serialization(error.to_string()))?
            != bytes
        {
            return Err(M5ProviderExecutionError::Invalid(
                "provider execution receipt is not canonical JSON".to_string(),
            ));
        }
        Ok(receipt)
    }

    pub fn validate_for_records(
        &self,
        prepared: &M5PreparedProviderSeedV1,
        challenged: &M5ChallengedProviderSeedV1,
        binding: &ProviderCandidateBinding,
    ) -> Result<(), M5ProviderExecutionError> {
        self.validate()?;
        prepared.validate().map_err(|error| {
            M5ProviderExecutionError::Invalid(format!("prepared seed is invalid: {error}"))
        })?;
        challenged.validate_for(prepared).map_err(|error| {
            M5ProviderExecutionError::Invalid(format!("challenged seed is invalid: {error}"))
        })?;
        binding.validate().map_err(|error| {
            M5ProviderExecutionError::Invalid(format!("provider binding is invalid: {error}"))
        })?;
        let request = challenged.qualification_request();
        let binding_request = &binding.proposal_evidence.request.qualification_request;
        let configuration_fingerprint = request.configuration.fingerprint().map_err(|error| {
            M5ProviderExecutionError::Invalid(format!(
                "provider configuration cannot be fingerprinted: {error}"
            ))
        })?;
        let turn = binding.qualification.live_turn.as_ref().ok_or_else(|| {
            M5ProviderExecutionError::Invalid(
                "qualified binding has no redacted live-turn evidence".to_string(),
            )
        })?;
        let observed_call_duration_ms = self
            .call_completed_at_ms
            .checked_sub(self.call_started_at_ms)
            .ok_or_else(|| {
                M5ProviderExecutionError::Invalid(
                    "provider execution call interval regressed".to_string(),
                )
            })?;
        if turn.provider_accounting.total_latency_ms > observed_call_duration_ms {
            return Err(M5ProviderExecutionError::Invalid(
                "provider accounting latency exceeds the observed provider-call interval"
                    .to_string(),
            ));
        }
        if turn.provider_accounting.attempts.iter().any(|attempt| {
            &attempt.request_body_digest != challenged.provider_wire_request().request_body_digest()
        }) {
            return Err(M5ProviderExecutionError::Invalid(
                "provider accounting contains an attempt outside the exact challenged wire request"
                    .to_string(),
            ));
        }
        let terminal_matches_target = match &self.terminal_outcome {
            M5ProviderTerminalOutcomeV1::Adopted { package_digest, .. }
            | M5ProviderTerminalOutcomeV1::GateRejected { package_digest, .. }
            | M5ProviderTerminalOutcomeV1::ApprovalRejected { package_digest, .. } => {
                package_digest == &prepared.target.candidate_package_digest
            }
            M5ProviderTerminalOutcomeV1::QuarantinedAndRolledBack {
                package_digest,
                restored_package_digest,
                ..
            } => {
                package_digest == &prepared.target.candidate_package_digest
                    && restored_package_digest == &prepared.target.incumbent_package_digest
            }
            M5ProviderTerminalOutcomeV1::Stopped {
                active_package_digest,
                ..
            } => {
                active_package_digest == &prepared.target.incumbent_package_digest
                    || active_package_digest == &prepared.target.candidate_package_digest
            }
        };
        if binding.target != prepared.target
            || binding_request != request
            || self.proof_run_id != prepared.precommit.proof_run_id
            || self.prepared_digest != prepared.prepared_digest
            || self.precommit_digest != prepared.precommit.precommit_digest
            || self.base_qualification_request_digest
                != prepared.qualification_request.request_digest
            || self.qualification_request_digest != request.request_digest
            || self.challenged_seed_digest != *challenged.challenged_digest()
            || self.live_provider_scope_digest
                != *challenged.challenge().live_provider_scope_digest()
            || self.invocation_challenge_digest
                != *challenged.challenge().invocation_challenge_digest()
            || self.wire_request_digest != *challenged.provider_wire_request().wire_request_digest()
            || self.request_body_digest != *challenged.provider_wire_request().request_body_digest()
            || self.target_digest != prepared.target.target_digest
            || self.binding_digest != binding.binding_digest
            || self.qualification_record_digest != binding.qualification_record_digest
            || self.provider_configuration_fingerprint != configuration_fingerprint
            || self.provider_id != request.configuration.provider_id
            || self.model_id != request.configuration.model_id
            || self.api_base_url != request.configuration.api_base_url
            || self.endpoint_class != request.configuration.endpoint_class
            || self.qualification_id != request.qualification_id
            || self.qualification_status != ProviderQualificationStatus::Qualified
            || self.qualification_status != binding.qualification.status
            || !self.transcript_redacted
            || self.transcript_redacted != turn.transcript.redaction_applied
            || self.credential_material_in_receipt
            || self.run_nonce_digest != *challenged.challenge().run_nonce_digest()
            || self.run_nonce_hex != encode_lower_hex(challenged.challenge().run_nonce())
            || !terminal_matches_target
        {
            return Err(M5ProviderExecutionError::Invalid(
                "execution receipt differs from its exact prepared request, target, qualification, or binding"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_manifest(
        &self,
        manifest: &M7ProofRunManifest,
        prepared: &M5PreparedProviderSeedV1,
        challenged: &M5ChallengedProviderSeedV1,
        binding: &ProviderCandidateBinding,
    ) -> Result<(), M5ProviderExecutionError> {
        manifest.canonical_bytes().map_err(|error| {
            M5ProviderExecutionError::Invalid(format!("M7 manifest is invalid: {error}"))
        })?;
        self.validate_for_records(prepared, challenged, binding)?;
        let scope = LiveProviderQualificationScope::from_prepared(prepared).map_err(|error| {
            M5ProviderExecutionError::Invalid(format!(
                "prepared live-provider scope is invalid: {error}"
            ))
        })?;
        if manifest.live_provider_scope() != Some(&scope)
            || manifest.proof_run_id() != self.proof_run_id
            || manifest.manifest_digest() != &self.manifest_digest
            || manifest.run_started_at_ms() != self.manifest_run_started_at_ms
            || manifest.manifest_digest() != challenged.challenge().manifest_digest()
            || scope.scope_digest() != challenged.challenge().live_provider_scope_digest()
        {
            return Err(M5ProviderExecutionError::Invalid(
                "execution receipt is not bound to the exact frozen M7 v4 manifest".to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), M5ProviderExecutionError> {
        if self.schema != M5_PROVIDER_EXECUTION_RECEIPT_SCHEMA {
            return Err(M5ProviderExecutionError::Invalid(
                "unsupported provider execution receipt schema".to_string(),
            ));
        }
        if self.proof_run_id.trim().is_empty()
            || self.provider_id.trim().is_empty()
            || self.model_id.trim().is_empty()
            || self.qualification_id.trim().is_empty()
        {
            return Err(M5ProviderExecutionError::Invalid(
                "provider execution receipt identifiers must be nonempty".to_string(),
            ));
        }
        if self.manifest_run_started_at_ms == 0
            || self.manifest_validated_at_ms < self.manifest_run_started_at_ms
            || self.manifest_validated_at_ms >= self.call_started_at_ms
            || self.call_started_at_ms > self.call_completed_at_ms
        {
            return Err(M5ProviderExecutionError::Invalid(
                "provider execution timestamps do not prove manifest-start <= validation < call-start <= call-completion"
                    .to_string(),
            ));
        }
        let nonce = decode_lower_hex_nonce(&self.run_nonce_hex)?;
        if nonce.iter().all(|byte| *byte == 0)
            || self.run_nonce_digest != ContentDigest::from_bytes(&nonce)
        {
            return Err(M5ProviderExecutionError::Invalid(
                "provider execution nonce is invalid".to_string(),
            ));
        }
        if self.terminal_outcome_digest != self.terminal_outcome.digest()? {
            return Err(M5ProviderExecutionError::Invalid(
                "provider execution terminal outcome digest is invalid".to_string(),
            ));
        }
        if self.terminal_outcome.cycle_record_digest() != Some(&self.terminal_cycle_record_digest) {
            return Err(M5ProviderExecutionError::Invalid(
                "provider execution receipt does not retain its exact terminal cycle-record digest"
                    .to_string(),
            ));
        }
        if self.receipt_digest != self.expected_digest()? {
            return Err(M5ProviderExecutionError::Invalid(
                "provider execution receipt digest is invalid".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5ProviderExecutionError> {
        let bytes = serde_json::to_vec(&ReceiptDigestMaterial {
            domain: RECEIPT_DIGEST_DOMAIN,
            proof_run_id: &self.proof_run_id,
            manifest_digest: &self.manifest_digest,
            manifest_run_started_at_ms: self.manifest_run_started_at_ms,
            prepared_digest: &self.prepared_digest,
            precommit_digest: &self.precommit_digest,
            base_qualification_request_digest: &self.base_qualification_request_digest,
            qualification_request_digest: &self.qualification_request_digest,
            challenged_seed_digest: &self.challenged_seed_digest,
            live_provider_scope_digest: &self.live_provider_scope_digest,
            invocation_challenge_digest: &self.invocation_challenge_digest,
            wire_request_digest: &self.wire_request_digest,
            request_body_digest: &self.request_body_digest,
            target_digest: &self.target_digest,
            binding_digest: &self.binding_digest,
            qualification_record_digest: &self.qualification_record_digest,
            provider_configuration_fingerprint: &self.provider_configuration_fingerprint,
            provider_id: &self.provider_id,
            model_id: &self.model_id,
            api_base_url: &self.api_base_url,
            endpoint_class: self.endpoint_class,
            qualification_id: &self.qualification_id,
            qualification_status: self.qualification_status,
            transcript_redacted: self.transcript_redacted,
            credential_material_in_receipt: self.credential_material_in_receipt,
            terminal_outcome_digest: &self.terminal_outcome_digest,
            terminal_cycle_record_digest: &self.terminal_cycle_record_digest,
            manifest_validated_at_ms: self.manifest_validated_at_ms,
            call_started_at_ms: self.call_started_at_ms,
            call_completed_at_ms: self.call_completed_at_ms,
            run_nonce_hex: &self.run_nonce_hex,
            run_nonce_digest: &self.run_nonce_digest,
        })
        .map_err(|error| M5ProviderExecutionError::Serialization(error.to_string()))?;
        Ok(ContentDigest::from_bytes(&bytes))
    }
}

/// Opaque, canonical result of the one high-level owner-locked provider proof
/// path. Public callers can validate/decode and inspect it, but cannot assemble
/// one from arbitrary prepared, binding, and receipt values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct M5CompletedProviderInvocationV1 {
    schema: String,
    prepared_seed: M5PreparedProviderSeedV1,
    challenged_seed: M5ChallengedProviderSeedV1,
    provider_binding: ProviderCandidateBinding,
    terminal_outcome: M5ProviderTerminalOutcomeV1,
    execution_receipt: M5ProviderExecutionReceiptV1,
    terminal_cycle_record_digest: ContentDigest,
    completed_invocation_digest: ContentDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct M5CompletedProviderInvocationWireV1 {
    schema: String,
    prepared_seed: M5PreparedProviderSeedV1,
    challenged_seed: M5ChallengedProviderSeedV1,
    provider_binding: ProviderCandidateBinding,
    terminal_outcome: M5ProviderTerminalOutcomeV1,
    execution_receipt: M5ProviderExecutionReceiptV1,
    terminal_cycle_record_digest: ContentDigest,
    completed_invocation_digest: ContentDigest,
}

impl M5CompletedProviderInvocationV1 {
    pub(crate) fn seal(
        prepared_seed: M5PreparedProviderSeedV1,
        challenged_seed: M5ChallengedProviderSeedV1,
        provider_binding: ProviderCandidateBinding,
        terminal_outcome: CycleOutcome,
        execution_receipt: M5ProviderExecutionReceiptV1,
    ) -> Result<Self, M5ProviderExecutionError> {
        let terminal_cycle_record_digest = terminal_cycle_record_digest(&terminal_outcome)?;
        let mut completed = Self {
            schema: M5_COMPLETED_PROVIDER_INVOCATION_SCHEMA.to_string(),
            prepared_seed,
            challenged_seed,
            provider_binding,
            terminal_outcome: M5ProviderTerminalOutcomeV1::from(&terminal_outcome),
            execution_receipt,
            terminal_cycle_record_digest,
            completed_invocation_digest: ContentDigest::from_bytes(&[]),
        };
        completed.completed_invocation_digest = completed.expected_digest()?;
        completed.validate()?;
        Ok(completed)
    }

    pub fn validate(&self) -> Result<(), M5ProviderExecutionError> {
        if self.schema != M5_COMPLETED_PROVIDER_INVOCATION_SCHEMA {
            return Err(M5ProviderExecutionError::Invalid(
                "unsupported completed provider invocation schema".to_string(),
            ));
        }
        self.prepared_seed.validate().map_err(|error| {
            M5ProviderExecutionError::Invalid(format!("prepared seed is invalid: {error}"))
        })?;
        self.challenged_seed
            .validate_for(&self.prepared_seed)
            .map_err(|error| {
                M5ProviderExecutionError::Invalid(format!("challenged seed is invalid: {error}"))
            })?;
        self.provider_binding.validate().map_err(|error| {
            M5ProviderExecutionError::Invalid(format!("provider binding is invalid: {error}"))
        })?;
        self.execution_receipt.validate_for_records(
            &self.prepared_seed,
            &self.challenged_seed,
            &self.provider_binding,
        )?;
        let terminal_cycle_record_digest = self
            .terminal_outcome
            .cycle_record_digest()
            .cloned()
            .ok_or_else(|| {
                M5ProviderExecutionError::Invalid(
                    "completed provider invocation has no terminal cycle record".to_string(),
                )
            })?;
        if self.terminal_cycle_record_digest != terminal_cycle_record_digest
            || self.execution_receipt.terminal_cycle_record_digest != terminal_cycle_record_digest
            || self.execution_receipt.terminal_outcome != self.terminal_outcome
        {
            return Err(M5ProviderExecutionError::Invalid(
                "completed provider invocation differs from its exact terminal outcome or cycle record"
                    .to_string(),
            ));
        }
        if self.completed_invocation_digest != self.expected_digest()? {
            return Err(M5ProviderExecutionError::Invalid(
                "completed provider invocation digest is invalid".to_string(),
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M5ProviderExecutionError> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| M5ProviderExecutionError::Serialization(error.to_string()))?;
        if bytes.is_empty() || bytes.len() > 8 * 1_048_576 {
            return Err(M5ProviderExecutionError::Invalid(
                "completed provider invocation is outside its canonical byte bound".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M5ProviderExecutionError> {
        if bytes.is_empty() || bytes.len() > 8 * 1_048_576 {
            return Err(M5ProviderExecutionError::Invalid(
                "completed provider invocation bytes are outside their bound".to_string(),
            ));
        }
        let wire: M5CompletedProviderInvocationWireV1 = serde_json::from_slice(bytes)
            .map_err(|error| M5ProviderExecutionError::Serialization(error.to_string()))?;
        let completed = Self {
            schema: wire.schema,
            prepared_seed: wire.prepared_seed,
            challenged_seed: wire.challenged_seed,
            provider_binding: wire.provider_binding,
            terminal_outcome: wire.terminal_outcome,
            execution_receipt: wire.execution_receipt,
            terminal_cycle_record_digest: wire.terminal_cycle_record_digest,
            completed_invocation_digest: wire.completed_invocation_digest,
        };
        completed.validate()?;
        if serde_json::to_vec_pretty(&completed)
            .map_err(|error| M5ProviderExecutionError::Serialization(error.to_string()))?
            != bytes
        {
            return Err(M5ProviderExecutionError::Invalid(
                "completed provider invocation is not canonical JSON".to_string(),
            ));
        }
        Ok(completed)
    }

    pub fn prepared_seed(&self) -> &M5PreparedProviderSeedV1 {
        &self.prepared_seed
    }

    pub fn challenged_seed(&self) -> &M5ChallengedProviderSeedV1 {
        &self.challenged_seed
    }

    pub fn provider_binding(&self) -> &ProviderCandidateBinding {
        &self.provider_binding
    }

    pub fn terminal_outcome(&self) -> &M5ProviderTerminalOutcomeV1 {
        &self.terminal_outcome
    }

    pub fn execution_receipt(&self) -> &M5ProviderExecutionReceiptV1 {
        &self.execution_receipt
    }

    pub fn terminal_cycle_record_digest(&self) -> &ContentDigest {
        &self.terminal_cycle_record_digest
    }

    pub fn completed_invocation_digest(&self) -> &ContentDigest {
        &self.completed_invocation_digest
    }

    pub fn api_base_url(&self) -> &str {
        self.challenged_seed.provider_wire_request().api_base_url()
    }

    pub fn endpoint_class(&self) -> M5ProviderEndpointClassV1 {
        self.challenged_seed
            .provider_wire_request()
            .endpoint_class()
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5ProviderExecutionError> {
        let bytes = serde_json::to_vec(&(
            COMPLETED_INVOCATION_DIGEST_DOMAIN,
            &self.prepared_seed.prepared_digest,
            self.challenged_seed.challenged_digest(),
            &self.provider_binding.binding_digest,
            &self.execution_receipt.receipt_digest,
            &self.terminal_cycle_record_digest,
        ))
        .map_err(|error| M5ProviderExecutionError::Serialization(error.to_string()))?;
        Ok(ContentDigest::from_bytes(&bytes))
    }
}

/// Draw a fresh invocation nonce from the operating system CSPRNG.
pub(crate) fn fresh_provider_run_nonce()
-> Result<[u8; M5_PROVIDER_RUN_NONCE_BYTES], M5ProviderExecutionError> {
    let mut nonce = [0_u8; M5_PROVIDER_RUN_NONCE_BYTES];
    SystemRandom::new().fill(&mut nonce).map_err(|_| {
        M5ProviderExecutionError::Randomness("operating-system randomness is unavailable")
    })?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(M5ProviderExecutionError::Randomness(
            "operating-system randomness returned a forbidden zero nonce",
        ));
    }
    Ok(nonce)
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_lower_hex_nonce(
    value: &str,
) -> Result<[u8; M5_PROVIDER_RUN_NONCE_BYTES], M5ProviderExecutionError> {
    if value.len() != M5_PROVIDER_RUN_NONCE_BYTES * 2
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(M5ProviderExecutionError::Invalid(
            "provider execution nonce must be 64 lowercase hexadecimal characters".to_string(),
        ));
    }
    let mut nonce = [0_u8; M5_PROVIDER_RUN_NONCE_BYTES];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        nonce[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(nonce)
}

fn hex_nibble(byte: u8) -> Result<u8, M5ProviderExecutionError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(M5ProviderExecutionError::Invalid(
            "provider execution nonce contains invalid hexadecimal".to_string(),
        )),
    }
}

fn enforce_receipt_bound(length: usize) -> Result<(), M5ProviderExecutionError> {
    if length > MAX_RECEIPT_BYTES {
        return Err(M5ProviderExecutionError::Invalid(format!(
            "provider execution receipt exceeds {MAX_RECEIPT_BYTES} bytes"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum M5ProviderExecutionError {
    Invalid(String),
    Serialization(String),
    Randomness(&'static str),
}

impl Display for M5ProviderExecutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "provider execution serialization failed: {message}"
                )
            }
            Self::Randomness(message) => formatter.write_str(message),
        }
    }
}

impl Error for M5ProviderExecutionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m7_closure::tests::live_provider_source_fixture;

    #[test]
    fn rejects_provider_accounting_latency_outside_observed_call_interval() {
        let source = live_provider_source_fixture("proof-run:latency-bound", 150);
        let completed = source
            .completed_invocation()
            .expect("decode opaque completed provider fixture");
        let prepared = completed.prepared_seed();
        let challenged = completed.challenged_seed();
        let binding = completed.provider_binding();
        let accounting_latency_ms = binding
            .qualification
            .live_turn
            .as_ref()
            .expect("fixture qualified live turn")
            .provider_accounting
            .total_latency_ms;
        assert!(accounting_latency_ms > 0, "fixture must exercise the bound");

        let mut receipt = completed.execution_receipt().clone();
        receipt.call_completed_at_ms = receipt
            .call_started_at_ms
            .checked_add(accounting_latency_ms - 1)
            .expect("bounded fixture call interval");
        receipt.receipt_digest = receipt
            .expected_digest()
            .expect("reseal impossible-latency receipt");

        assert!(matches!(
            receipt.validate_for_records(prepared, challenged, binding),
            Err(M5ProviderExecutionError::Invalid(message))
                if message == "provider accounting latency exceeds the observed provider-call interval"
        ));
    }
}
