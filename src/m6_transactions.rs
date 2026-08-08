//! Durable, append-only M6 coordinator transactions.
//!
//! This module is intentionally effect-free. It records exact coordinator
//! intent and verified stage facts, reconstructs them after restart, and
//! classifies recovery from externally supplied authoritative observations. It
//! never invokes M5, M3, a provider, a spool, or an authority implementation.

use crate::execution::artifact::ContentDigest;
use crate::m6_identity::{Clock, RouteResourceProfile};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

pub const JOURNAL_CONFIG_SCHEMA: &str = "wasm-biotic.m6-coordinator-config.v1";
pub const TRANSACTION_INTENT_SCHEMA: &str = "wasm-biotic.m6-transaction-intent.v1";
pub const TRANSACTION_STAGE_SCHEMA: &str = "wasm-biotic.m6-transaction-stage.v1";
pub const STAGE_EVIDENCE_SCHEMA: &str = "wasm-biotic.m6-stage-evidence.v1";
pub const EFFECT_FACT_SCHEMA: &str = "wasm-biotic.m6-authoritative-effect-fact.v1";

const CONFIG_DOMAIN: &[u8] = b"wasm-biotic:m6:coordinator-config:v1\0";
const REQUEST_DOMAIN: &[u8] = b"wasm-biotic:m6:transaction-request:v1\0";
const INTENT_DOMAIN: &[u8] = b"wasm-biotic:m6:transaction-intent:v1\0";
const STAGE_EVIDENCE_DOMAIN: &[u8] = b"wasm-biotic:m6:stage-evidence:v1\0";
const STAGE_RECORD_DOMAIN: &[u8] = b"wasm-biotic:m6:stage-record:v1\0";
const EFFECT_FACT_DOMAIN: &[u8] = b"wasm-biotic:m6:effect-fact:v1\0";
const CONFIG_FILE: &str = "journal-config.json";
const OWNER_LOCK_FILE: &str = ".m6-coordinator.lock";
const INTENTS_DIRECTORY: &str = "intents";
const TRANSACTIONS_DIRECTORY: &str = "transactions";
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_REFERENCE_COUNT: usize = 256;
const MAX_RECORD_BYTES: usize = 512 * 1_024;
const MAX_DEADLINE_WINDOW_MS: u64 = 30 * 86_400_000;
const MAX_RETRY_ATTEMPTS: u32 = 32;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionKind {
    SenderExport,
    ReceiverIntake,
    SenderRevocationPublication,
    ReceiverRevocationApplication,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStage {
    ExportIntentRecorded,
    OutboundBundleCommitted,
    RouteStageCommitted,
    RouteReadyCommitted,
    ExportReceiptCommitted,

    IntakeIntentRecorded,
    RawAdmissionRejected,
    RawQuarantined,
    SenderAuthenticated,
    ReplayAndSequenceCommitted,
    SenderEvidenceVerified,
    ReceiverProvingCommitted,
    ValidationRejected,
    AwaitingApproval,
    Denied,
    Expired,
    Escalated,
    ActivationIntentRecorded,
    ActivationEffectCommitted,
    ObservationIntentRecorded,
    Healthy,
    RollbackIntentRecorded,
    RolledBack,
    ContainmentRequired,

    RevocationIntentRecorded,
    RevocationOutboundCommitted,
    RevocationRouteStageCommitted,
    RevocationRouteReadyCommitted,
    RevocationReceiptCommitted,

    RevocationIntakeIntentRecorded,
    RevocationRawQuarantined,
    RevocationAuthenticated,
    RevocationReplayAndSequenceCommitted,
    RevocationTombstoneCommitted,
    RevocationAffectedExchangesResolved,
    RevocationContainmentIntentRecorded,
    RevocationContained,
    RevocationContainmentRequired,
}

impl TransactionStage {
    pub const ALL: [Self; 38] = [
        Self::ExportIntentRecorded,
        Self::OutboundBundleCommitted,
        Self::RouteStageCommitted,
        Self::RouteReadyCommitted,
        Self::ExportReceiptCommitted,
        Self::IntakeIntentRecorded,
        Self::RawAdmissionRejected,
        Self::RawQuarantined,
        Self::SenderAuthenticated,
        Self::ReplayAndSequenceCommitted,
        Self::SenderEvidenceVerified,
        Self::ReceiverProvingCommitted,
        Self::ValidationRejected,
        Self::AwaitingApproval,
        Self::Denied,
        Self::Expired,
        Self::Escalated,
        Self::ActivationIntentRecorded,
        Self::ActivationEffectCommitted,
        Self::ObservationIntentRecorded,
        Self::Healthy,
        Self::RollbackIntentRecorded,
        Self::RolledBack,
        Self::ContainmentRequired,
        Self::RevocationIntentRecorded,
        Self::RevocationOutboundCommitted,
        Self::RevocationRouteStageCommitted,
        Self::RevocationRouteReadyCommitted,
        Self::RevocationReceiptCommitted,
        Self::RevocationIntakeIntentRecorded,
        Self::RevocationRawQuarantined,
        Self::RevocationAuthenticated,
        Self::RevocationReplayAndSequenceCommitted,
        Self::RevocationTombstoneCommitted,
        Self::RevocationAffectedExchangesResolved,
        Self::RevocationContainmentIntentRecorded,
        Self::RevocationContained,
        Self::RevocationContainmentRequired,
    ];

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ExportReceiptCommitted
                | Self::RawAdmissionRejected
                | Self::ValidationRejected
                | Self::Denied
                | Self::Expired
                | Self::Escalated
                | Self::Healthy
                | Self::RolledBack
                | Self::ContainmentRequired
                | Self::RevocationReceiptCommitted
                | Self::RevocationContained
                | Self::RevocationContainmentRequired
        )
    }

    fn file_label(self) -> &'static str {
        match self {
            Self::ExportIntentRecorded => "export-intent-recorded",
            Self::OutboundBundleCommitted => "outbound-bundle-committed",
            Self::RouteStageCommitted => "route-stage-committed",
            Self::RouteReadyCommitted => "route-ready-committed",
            Self::ExportReceiptCommitted => "export-receipt-committed",
            Self::IntakeIntentRecorded => "intake-intent-recorded",
            Self::RawAdmissionRejected => "raw-admission-rejected",
            Self::RawQuarantined => "raw-quarantined",
            Self::SenderAuthenticated => "sender-authenticated",
            Self::ReplayAndSequenceCommitted => "replay-and-sequence-committed",
            Self::SenderEvidenceVerified => "sender-evidence-verified",
            Self::ReceiverProvingCommitted => "receiver-proving-committed",
            Self::ValidationRejected => "validation-rejected",
            Self::AwaitingApproval => "awaiting-approval",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Escalated => "escalated",
            Self::ActivationIntentRecorded => "activation-intent-recorded",
            Self::ActivationEffectCommitted => "activation-effect-committed",
            Self::ObservationIntentRecorded => "observation-intent-recorded",
            Self::Healthy => "healthy",
            Self::RollbackIntentRecorded => "rollback-intent-recorded",
            Self::RolledBack => "rolled-back",
            Self::ContainmentRequired => "containment-required",
            Self::RevocationIntentRecorded => "revocation-intent-recorded",
            Self::RevocationOutboundCommitted => "revocation-outbound-committed",
            Self::RevocationRouteStageCommitted => "revocation-route-stage-committed",
            Self::RevocationRouteReadyCommitted => "revocation-route-ready-committed",
            Self::RevocationReceiptCommitted => "revocation-receipt-committed",
            Self::RevocationIntakeIntentRecorded => "revocation-intake-intent-recorded",
            Self::RevocationRawQuarantined => "revocation-raw-quarantined",
            Self::RevocationAuthenticated => "revocation-authenticated",
            Self::RevocationReplayAndSequenceCommitted => {
                "revocation-replay-and-sequence-committed"
            }
            Self::RevocationTombstoneCommitted => "revocation-tombstone-committed",
            Self::RevocationAffectedExchangesResolved => "revocation-affected-exchanges-resolved",
            Self::RevocationContainmentIntentRecorded => "revocation-containment-intent-recorded",
            Self::RevocationContained => "revocation-contained",
            Self::RevocationContainmentRequired => "revocation-containment-required",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageCause {
    Normal,
    Recovery,
    ValidationRejection,
    PolicyRejection,
    ApprovalDecision,
    Expiry,
    HealthRegression,
    Revocation,
    EffectConflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    pub attempt_timeout_ms: u64,
    pub max_attempts: u32,
    pub max_recovery_attempts: u32,
}

impl RetryPolicy {
    pub fn bounded(
        max_attempts: u32,
        max_recovery_attempts: u32,
        attempt_timeout_ms: u64,
    ) -> Result<Self, M6TransactionError> {
        let policy = Self {
            attempt_timeout_ms,
            max_attempts,
            max_recovery_attempts,
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), M6TransactionError> {
        if self.max_attempts == 0
            || self.max_attempts > MAX_RETRY_ATTEMPTS
            || self.max_recovery_attempts > self.max_attempts
            || self.attempt_timeout_ms == 0
            || self.attempt_timeout_ms > MAX_DEADLINE_WINDOW_MS
        {
            return Err(M6TransactionError::InvalidRequest(
                "retry policy is outside its bounded envelope".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate this immutable retry envelope against one route generation.
    pub fn validate_for_resource_profile(
        &self,
        profile: &RouteResourceProfile,
    ) -> Result<(), M6TransactionError> {
        profile
            .validate()
            .map_err(|error| M6TransactionError::InvalidRequest(error.to_string()))?;
        self.validate()?;
        if self.max_attempts > profile.max_retry_attempts
            || self.max_recovery_attempts > profile.max_recovery_attempts
            || self.attempt_timeout_ms > profile.max_message_lifetime_ms
        {
            return Err(M6TransactionError::InvalidRequest(
                "retry policy exceeds the immutable route resource profile".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionRequestDraft {
    pub kind: TransactionKind,
    pub logical_operation_id: String,
    pub idempotency_key: String,
    pub route_id: String,
    pub route_generation: u64,
    pub route_definition_digest: ContentDigest,
    pub message_digest: ContentDigest,
    pub exchange_digest: ContentDigest,
    pub package_digest: ContentDigest,
    pub before_snapshot_digest: ContentDigest,
    pub expected_after_snapshot_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub authority_refs: Vec<ContentDigest>,
    pub evidence_refs: Vec<ContentDigest>,
    pub retry_policy: RetryPolicy,
    pub deadline_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionIntent {
    pub authority_refs: Vec<ContentDigest>,
    pub before_snapshot_digest: ContentDigest,
    pub created_at_ms: u64,
    pub deadline_ms: u64,
    pub evidence_refs: Vec<ContentDigest>,
    pub exchange_digest: ContentDigest,
    pub expected_after_snapshot_digest: ContentDigest,
    pub idempotency_key: String,
    pub intent_digest: ContentDigest,
    pub kind: TransactionKind,
    pub logical_operation_id: String,
    pub message_digest: ContentDigest,
    pub package_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub retry_policy: RetryPolicy,
    pub route_definition_digest: ContentDigest,
    pub route_generation: u64,
    pub route_id: String,
    pub schema: String,
}

impl TransactionIntent {
    fn new(
        mut draft: TransactionRequestDraft,
        created_at_ms: u64,
    ) -> Result<Self, M6TransactionError> {
        draft.authority_refs.sort();
        draft.authority_refs.dedup();
        draft.evidence_refs.sort();
        draft.evidence_refs.dedup();
        validate_identifier("logical operation id", &draft.logical_operation_id)?;
        validate_identifier("idempotency key", &draft.idempotency_key)?;
        validate_identifier("route id", &draft.route_id)?;
        draft.retry_policy.validate()?;
        if draft.route_generation == 0
            || draft.authority_refs.is_empty()
            || draft.authority_refs.len() > MAX_REFERENCE_COUNT
            || draft.evidence_refs.is_empty()
            || draft.evidence_refs.len() > MAX_REFERENCE_COUNT
            || draft.deadline_ms <= created_at_ms
            || draft.deadline_ms.saturating_sub(created_at_ms) > MAX_DEADLINE_WINDOW_MS
        {
            return Err(M6TransactionError::InvalidRequest(
                "transaction route, references, or deadline are outside bounds".to_string(),
            ));
        }
        let request_digest = request_digest(&draft, created_at_ms)?;
        let mut intent = Self {
            authority_refs: draft.authority_refs,
            before_snapshot_digest: draft.before_snapshot_digest,
            created_at_ms,
            deadline_ms: draft.deadline_ms,
            evidence_refs: draft.evidence_refs,
            exchange_digest: draft.exchange_digest,
            expected_after_snapshot_digest: draft.expected_after_snapshot_digest,
            idempotency_key: draft.idempotency_key,
            intent_digest: ContentDigest::from_bytes(&[]),
            kind: draft.kind,
            logical_operation_id: draft.logical_operation_id,
            message_digest: draft.message_digest,
            package_digest: draft.package_digest,
            policy_digest: draft.policy_digest,
            request_digest,
            retry_policy: draft.retry_policy,
            route_definition_digest: draft.route_definition_digest,
            route_generation: draft.route_generation,
            route_id: draft.route_id,
            schema: TRANSACTION_INTENT_SCHEMA.to_string(),
        };
        intent.intent_digest = intent.expected_digest()?;
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), M6TransactionError> {
        if self.schema != TRANSACTION_INTENT_SCHEMA {
            return Err(M6TransactionError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("logical operation id", &self.logical_operation_id)?;
        validate_identifier("idempotency key", &self.idempotency_key)?;
        validate_identifier("route id", &self.route_id)?;
        self.retry_policy.validate()?;
        if self.route_generation == 0
            || self.authority_refs.is_empty()
            || self.authority_refs.len() > MAX_REFERENCE_COUNT
            || !is_strictly_sorted_unique(&self.authority_refs)
            || self.evidence_refs.is_empty()
            || self.evidence_refs.len() > MAX_REFERENCE_COUNT
            || !is_strictly_sorted_unique(&self.evidence_refs)
            || self.deadline_ms <= self.created_at_ms
            || self.deadline_ms.saturating_sub(self.created_at_ms) > MAX_DEADLINE_WINDOW_MS
        {
            return Err(M6TransactionError::InvalidRequest(
                "durable transaction intent is outside bounds".to_string(),
            ));
        }
        let draft = TransactionRequestDraft {
            kind: self.kind,
            logical_operation_id: self.logical_operation_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            route_id: self.route_id.clone(),
            route_generation: self.route_generation,
            route_definition_digest: self.route_definition_digest.clone(),
            message_digest: self.message_digest.clone(),
            exchange_digest: self.exchange_digest.clone(),
            package_digest: self.package_digest.clone(),
            before_snapshot_digest: self.before_snapshot_digest.clone(),
            expected_after_snapshot_digest: self.expected_after_snapshot_digest.clone(),
            policy_digest: self.policy_digest.clone(),
            authority_refs: self.authority_refs.clone(),
            evidence_refs: self.evidence_refs.clone(),
            retry_policy: self.retry_policy.clone(),
            deadline_ms: self.deadline_ms,
        };
        require_digest(
            "transaction request",
            &self.request_digest,
            &request_digest(&draft, self.created_at_ms)?,
        )?;
        require_digest(
            "transaction intent",
            &self.intent_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6TransactionError> {
        digest_domain(
            INTENT_DOMAIN,
            &TransactionIntentDigestBinding {
                authority_refs: &self.authority_refs,
                before_snapshot_digest: &self.before_snapshot_digest,
                created_at_ms: self.created_at_ms,
                deadline_ms: self.deadline_ms,
                evidence_refs: &self.evidence_refs,
                exchange_digest: &self.exchange_digest,
                expected_after_snapshot_digest: &self.expected_after_snapshot_digest,
                idempotency_key: &self.idempotency_key,
                kind: self.kind,
                logical_operation_id: &self.logical_operation_id,
                message_digest: &self.message_digest,
                package_digest: &self.package_digest,
                policy_digest: &self.policy_digest,
                request_digest: &self.request_digest,
                retry_policy: &self.retry_policy,
                route_definition_digest: &self.route_definition_digest,
                route_generation: self.route_generation,
                route_id: &self.route_id,
                schema: &self.schema,
            },
        )
    }
}

#[derive(Serialize)]
struct TransactionRequestDigestBinding<'a> {
    authority_refs: &'a [ContentDigest],
    before_snapshot_digest: &'a ContentDigest,
    created_at_ms: u64,
    deadline_ms: u64,
    evidence_refs: &'a [ContentDigest],
    exchange_digest: &'a ContentDigest,
    expected_after_snapshot_digest: &'a ContentDigest,
    idempotency_key: &'a str,
    kind: TransactionKind,
    logical_operation_id: &'a str,
    message_digest: &'a ContentDigest,
    package_digest: &'a ContentDigest,
    policy_digest: &'a ContentDigest,
    retry_policy: &'a RetryPolicy,
    route_definition_digest: &'a ContentDigest,
    route_generation: u64,
    route_id: &'a str,
}

#[derive(Serialize)]
struct TransactionIntentDigestBinding<'a> {
    authority_refs: &'a [ContentDigest],
    before_snapshot_digest: &'a ContentDigest,
    created_at_ms: u64,
    deadline_ms: u64,
    evidence_refs: &'a [ContentDigest],
    exchange_digest: &'a ContentDigest,
    expected_after_snapshot_digest: &'a ContentDigest,
    idempotency_key: &'a str,
    kind: TransactionKind,
    logical_operation_id: &'a str,
    message_digest: &'a ContentDigest,
    package_digest: &'a ContentDigest,
    policy_digest: &'a ContentDigest,
    request_digest: &'a ContentDigest,
    retry_policy: &'a RetryPolicy,
    route_definition_digest: &'a ContentDigest,
    route_generation: u64,
    route_id: &'a str,
    schema: &'a str,
}

fn request_digest(
    draft: &TransactionRequestDraft,
    created_at_ms: u64,
) -> Result<ContentDigest, M6TransactionError> {
    digest_domain(
        REQUEST_DOMAIN,
        &TransactionRequestDigestBinding {
            authority_refs: &draft.authority_refs,
            before_snapshot_digest: &draft.before_snapshot_digest,
            created_at_ms,
            deadline_ms: draft.deadline_ms,
            evidence_refs: &draft.evidence_refs,
            exchange_digest: &draft.exchange_digest,
            expected_after_snapshot_digest: &draft.expected_after_snapshot_digest,
            idempotency_key: &draft.idempotency_key,
            kind: draft.kind,
            logical_operation_id: &draft.logical_operation_id,
            message_digest: &draft.message_digest,
            package_digest: &draft.package_digest,
            policy_digest: &draft.policy_digest,
            retry_policy: &draft.retry_policy,
            route_definition_digest: &draft.route_definition_digest,
            route_generation: draft.route_generation,
            route_id: &draft.route_id,
        },
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageEvidence {
    pub attempt: u32,
    pub authority_ref: Option<ContentDigest>,
    pub cause: StageCause,
    pub effect_request_digest: Option<ContentDigest>,
    pub evidence_digest: ContentDigest,
    pub evidence_refs: Vec<ContentDigest>,
    pub receipt_ref: Option<ContentDigest>,
    pub attestation_ref: Option<ContentDigest>,
    pub schema: String,
}

impl StageEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cause: StageCause,
        attempt: u32,
        authority_ref: Option<ContentDigest>,
        effect_request_digest: Option<ContentDigest>,
        receipt_ref: Option<ContentDigest>,
        attestation_ref: Option<ContentDigest>,
        mut evidence_refs: Vec<ContentDigest>,
    ) -> Result<Self, M6TransactionError> {
        evidence_refs.sort();
        evidence_refs.dedup();
        let mut evidence = Self {
            attempt,
            authority_ref,
            cause,
            effect_request_digest,
            evidence_digest: ContentDigest::from_bytes(&[]),
            evidence_refs,
            receipt_ref,
            attestation_ref,
            schema: STAGE_EVIDENCE_SCHEMA.to_string(),
        };
        evidence.validate_fields()?;
        evidence.evidence_digest = evidence.expected_digest()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), M6TransactionError> {
        self.validate_fields()?;
        require_digest(
            "transaction stage evidence",
            &self.evidence_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6TransactionError> {
        if self.schema != STAGE_EVIDENCE_SCHEMA {
            return Err(M6TransactionError::UnsupportedSchema(self.schema.clone()));
        }
        if self.attempt > MAX_RETRY_ATTEMPTS
            || self.evidence_refs.len() > MAX_REFERENCE_COUNT
            || !is_strictly_sorted_unique(&self.evidence_refs)
        {
            return Err(M6TransactionError::InvalidStageEvidence(
                "stage evidence is outside its retry or reference bounds".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6TransactionError> {
        digest_domain(
            STAGE_EVIDENCE_DOMAIN,
            &(
                self.attempt,
                &self.authority_ref,
                self.cause,
                &self.effect_request_digest,
                &self.evidence_refs,
                &self.receipt_ref,
                &self.attestation_ref,
                &self.schema,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionStageRecord {
    pub before_snapshot_digest: ContentDigest,
    pub evidence: StageEvidence,
    pub expected_after_snapshot_digest: ContentDigest,
    pub logical_operation_id: String,
    pub ordinal: u32,
    pub previous_stage_digest: Option<ContentDigest>,
    pub recorded_at_ms: u64,
    pub request_digest: ContentDigest,
    pub schema: String,
    pub stage: TransactionStage,
    pub stage_digest: ContentDigest,
}

impl TransactionStageRecord {
    fn new(
        intent: &TransactionIntent,
        ordinal: u32,
        previous_stage_digest: Option<ContentDigest>,
        stage: TransactionStage,
        evidence: StageEvidence,
        recorded_at_ms: u64,
    ) -> Result<Self, M6TransactionError> {
        evidence.validate()?;
        let mut record = Self {
            before_snapshot_digest: intent.before_snapshot_digest.clone(),
            evidence,
            expected_after_snapshot_digest: intent.expected_after_snapshot_digest.clone(),
            logical_operation_id: intent.logical_operation_id.clone(),
            ordinal,
            previous_stage_digest,
            recorded_at_ms,
            request_digest: intent.request_digest.clone(),
            schema: TRANSACTION_STAGE_SCHEMA.to_string(),
            stage,
            stage_digest: ContentDigest::from_bytes(&[]),
        };
        record.stage_digest = record.expected_digest()?;
        Ok(record)
    }

    fn validate(
        &self,
        intent: &TransactionIntent,
        expected_ordinal: u32,
        expected_previous: Option<&ContentDigest>,
    ) -> Result<(), M6TransactionError> {
        if self.schema != TRANSACTION_STAGE_SCHEMA {
            return Err(M6TransactionError::UnsupportedSchema(self.schema.clone()));
        }
        self.evidence.validate()?;
        if self.logical_operation_id != intent.logical_operation_id
            || self.request_digest != intent.request_digest
            || self.before_snapshot_digest != intent.before_snapshot_digest
            || self.expected_after_snapshot_digest != intent.expected_after_snapshot_digest
            || self.ordinal != expected_ordinal
            || self.previous_stage_digest.as_ref() != expected_previous
            || self.recorded_at_ms < intent.created_at_ms
        {
            return Err(M6TransactionError::StateIntegrity(
                "stage record differs from its immutable intent or chain position".to_string(),
            ));
        }
        require_digest(
            "transaction stage",
            &self.stage_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6TransactionError> {
        digest_domain(
            STAGE_RECORD_DOMAIN,
            &(
                &self.before_snapshot_digest,
                &self.evidence.evidence_digest,
                &self.expected_after_snapshot_digest,
                &self.logical_operation_id,
                self.ordinal,
                &self.previous_stage_digest,
                self.recorded_at_ms,
                &self.request_digest,
                &self.schema,
                self.stage,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionProjection {
    pub intent: TransactionIntent,
    pub stages: Vec<TransactionStageRecord>,
}

impl TransactionProjection {
    pub fn current_stage(&self) -> Option<TransactionStage> {
        self.stages.last().map(|record| record.stage)
    }

    pub fn current_record(&self) -> Option<&TransactionStageRecord> {
        self.stages.last()
    }

    /// Encode the complete immutable intent and append-only stage chain for
    /// detached verification outside the coordinator journal.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M6TransactionError> {
        self.validate()?;
        canonical_json(self)
    }

    /// Decode an exact canonical projection and independently validate every
    /// digest, authority/effect binding, ordinal, timestamp, and transition.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M6TransactionError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(M6TransactionError::ResourceExhausted(format!(
                "transaction projection is {} bytes; limit is {MAX_RECORD_BYTES}",
                bytes.len()
            )));
        }
        let projection: Self = parse_canonical(bytes)?;
        projection.validate()?;
        Ok(projection)
    }

    pub fn validate(&self) -> Result<(), M6TransactionError> {
        self.intent.validate()?;
        if self.stages.is_empty() || self.stages.len() > MAX_REFERENCE_COUNT {
            return Err(M6TransactionError::StateIntegrity(format!(
                "transaction projection must contain 1..={MAX_REFERENCE_COUNT} stages"
            )));
        }

        let mut previous_digest: Option<ContentDigest> = None;
        let mut previous_stage: Option<TransactionStage> = None;
        let mut previous_time = self.intent.created_at_ms;
        let mut seen = BTreeSet::new();
        for (index, record) in self.stages.iter().enumerate() {
            let ordinal = u32::try_from(index + 1).map_err(|_| {
                M6TransactionError::ResourceExhausted(
                    "transaction projection ordinal does not fit u32".to_string(),
                )
            })?;
            record.validate(&self.intent, ordinal, previous_digest.as_ref())?;
            validate_stage_evidence(&self.intent, record.stage, &record.evidence)?;
            if !seen.insert(record.stage) {
                return Err(M6TransactionError::StateIntegrity(format!(
                    "stage '{:?}' appears more than once",
                    record.stage
                )));
            }
            match previous_stage {
                None if record.stage == initial_stage(self.intent.kind)
                    && record.evidence.cause == StageCause::Normal => {}
                Some(previous)
                    if is_legal_transition(
                        self.intent.kind,
                        previous,
                        record.stage,
                        record.evidence.cause,
                    ) => {}
                previous => {
                    return Err(M6TransactionError::InvalidTransition {
                        kind: self.intent.kind,
                        from: previous,
                        to: record.stage,
                        cause: record.evidence.cause,
                    });
                }
            }
            if record.recorded_at_ms < previous_time {
                return Err(M6TransactionError::StateIntegrity(
                    "stage timestamps regress within the detached chain".to_string(),
                ));
            }
            previous_time = record.recorded_at_ms;
            previous_stage = Some(record.stage);
            previous_digest = Some(record.stage_digest.clone());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalConfig {
    pub config_digest: ContentDigest,
    pub max_stages_per_transaction: u32,
    pub max_transactions: u32,
    pub schema: String,
}

impl JournalConfig {
    pub fn bounded(
        max_transactions: u32,
        max_stages_per_transaction: u32,
    ) -> Result<Self, M6TransactionError> {
        let mut config = Self {
            config_digest: ContentDigest::from_bytes(&[]),
            max_stages_per_transaction,
            max_transactions,
            schema: JOURNAL_CONFIG_SCHEMA.to_string(),
        };
        config.validate_fields()?;
        config.config_digest = config.expected_digest()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), M6TransactionError> {
        self.validate_fields()?;
        require_digest(
            "coordinator journal config",
            &self.config_digest,
            &self.expected_digest()?,
        )
    }

    /// Validate this durable journal's transaction count against one route.
    pub fn validate_for_resource_profile(
        &self,
        profile: &RouteResourceProfile,
    ) -> Result<(), M6TransactionError> {
        profile
            .validate()
            .map_err(|error| M6TransactionError::InvalidRequest(error.to_string()))?;
        self.validate()?;
        if self.max_transactions > profile.max_transaction_records {
            return Err(M6TransactionError::InvalidRequest(
                "journal transaction count exceeds the immutable route resource profile"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), M6TransactionError> {
        if self.schema != JOURNAL_CONFIG_SCHEMA {
            return Err(M6TransactionError::UnsupportedSchema(self.schema.clone()));
        }
        if self.max_transactions == 0
            || self.max_transactions > 1_000_000
            || self.max_stages_per_transaction == 0
            || self.max_stages_per_transaction > 256
        {
            return Err(M6TransactionError::InvalidRequest(
                "journal limits are outside their bounded envelope".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6TransactionError> {
        digest_domain(
            CONFIG_DOMAIN,
            &(
                self.max_stages_per_transaction,
                self.max_transactions,
                &self.schema,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityAvailability {
    Available(ContentDigest),
    Missing,
    Expired(ContentDigest),
    Conflicting(Vec<ContentDigest>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeEffectFact {
    pub after_snapshot_digest: ContentDigest,
    pub attestation_ref: ContentDigest,
    pub before_snapshot_digest: ContentDigest,
    pub effect_stage: TransactionStage,
    pub fact_digest: ContentDigest,
    pub idempotency_key: String,
    pub receipt_ref: ContentDigest,
    pub request_digest: ContentDigest,
    pub schema: String,
}

impl AuthoritativeEffectFact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_digest: ContentDigest,
        idempotency_key: String,
        effect_stage: TransactionStage,
        before_snapshot_digest: ContentDigest,
        after_snapshot_digest: ContentDigest,
        receipt_ref: ContentDigest,
        attestation_ref: ContentDigest,
    ) -> Result<Self, M6TransactionError> {
        validate_identifier("effect idempotency key", &idempotency_key)?;
        let mut fact = Self {
            after_snapshot_digest,
            attestation_ref,
            before_snapshot_digest,
            effect_stage,
            fact_digest: ContentDigest::from_bytes(&[]),
            idempotency_key,
            receipt_ref,
            request_digest,
            schema: EFFECT_FACT_SCHEMA.to_string(),
        };
        fact.fact_digest = fact.expected_digest()?;
        Ok(fact)
    }

    pub fn validate(&self) -> Result<(), M6TransactionError> {
        if self.schema != EFFECT_FACT_SCHEMA {
            return Err(M6TransactionError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("effect idempotency key", &self.idempotency_key)?;
        require_digest(
            "authoritative effect fact",
            &self.fact_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6TransactionError> {
        digest_domain(
            EFFECT_FACT_DOMAIN,
            &(
                &self.after_snapshot_digest,
                &self.attestation_ref,
                &self.before_snapshot_digest,
                self.effect_stage,
                &self.idempotency_key,
                &self.receipt_ref,
                &self.request_digest,
                &self.schema,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectFactState {
    NotApplicable,
    Missing,
    Committed(AuthoritativeEffectFact),
    Conflicting(Vec<ContentDigest>),
    Ambiguous(Vec<ContentDigest>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryContext {
    pub authority: AuthorityAvailability,
    pub effect: EffectFactState,
    pub attempts_used: u32,
    pub observed_at_ms: u64,
    pub revocation_pending: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryTerminalReason {
    AlreadyTerminal,
    DeadlineReached,
    RetryBudgetExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainmentReason {
    AmbiguousEffectFact,
    ConflictingAuthority,
    ConflictingEffectFact,
    InvalidAuthorityBinding,
    MismatchedEffectBinding,
    MissingCommittedEffectFact,
    RevocationDuringActivation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryPlan {
    VerifyCommittedEffect {
        fact_digest: ContentDigest,
        effect_stage: TransactionStage,
    },
    ResubmitExactEffect {
        attempt: u32,
        deadline_ms: u64,
        idempotency_key: String,
        request_digest: ContentDigest,
    },
    AwaitAuthority {
        deadline_ms: u64,
        stage: Option<TransactionStage>,
    },
    Terminal {
        reason: RecoveryTerminalReason,
        stage: Option<TransactionStage>,
    },
    ContainmentRequired {
        reason: ContainmentReason,
    },
}

/// Returns whether `to` is a legal durable successor of `from` for `kind`.
///
/// This function has no side effects and deliberately includes the recorded
/// cause: rollback and containment branches cannot be reached by relabelling a
/// normal forward transition.
pub fn is_legal_transition(
    kind: TransactionKind,
    from: TransactionStage,
    to: TransactionStage,
    cause: StageCause,
) -> bool {
    use StageCause as C;
    use TransactionKind as K;
    use TransactionStage as S;

    let forward = matches!(cause, C::Normal | C::Recovery);
    match (kind, from, to) {
        (K::SenderExport, S::ExportIntentRecorded, S::OutboundBundleCommitted)
        | (K::SenderExport, S::OutboundBundleCommitted, S::RouteStageCommitted)
        | (K::SenderExport, S::RouteStageCommitted, S::RouteReadyCommitted)
        | (K::SenderExport, S::RouteReadyCommitted, S::ExportReceiptCommitted)
        | (
            K::SenderRevocationPublication,
            S::RevocationIntentRecorded,
            S::RevocationOutboundCommitted,
        )
        | (
            K::SenderRevocationPublication,
            S::RevocationOutboundCommitted,
            S::RevocationRouteStageCommitted,
        )
        | (
            K::SenderRevocationPublication,
            S::RevocationRouteStageCommitted,
            S::RevocationRouteReadyCommitted,
        )
        | (
            K::SenderRevocationPublication,
            S::RevocationRouteReadyCommitted,
            S::RevocationReceiptCommitted,
        )
        | (K::ReceiverIntake, S::IntakeIntentRecorded, S::RawQuarantined)
        | (K::ReceiverIntake, S::RawQuarantined, S::SenderAuthenticated)
        | (K::ReceiverIntake, S::SenderAuthenticated, S::ReplayAndSequenceCommitted)
        | (K::ReceiverIntake, S::ReplayAndSequenceCommitted, S::SenderEvidenceVerified)
        | (K::ReceiverIntake, S::SenderEvidenceVerified, S::ReceiverProvingCommitted)
        | (K::ReceiverIntake, S::ReceiverProvingCommitted, S::AwaitingApproval)
        | (K::ReceiverIntake, S::ActivationIntentRecorded, S::ActivationEffectCommitted)
        | (K::ReceiverIntake, S::ActivationEffectCommitted, S::ObservationIntentRecorded)
        | (K::ReceiverIntake, S::ObservationIntentRecorded, S::Healthy)
        | (
            K::ReceiverRevocationApplication,
            S::RevocationIntakeIntentRecorded,
            S::RevocationRawQuarantined,
        )
        | (
            K::ReceiverRevocationApplication,
            S::RevocationRawQuarantined,
            S::RevocationAuthenticated,
        )
        | (
            K::ReceiverRevocationApplication,
            S::RevocationAuthenticated,
            S::RevocationReplayAndSequenceCommitted,
        )
        | (
            K::ReceiverRevocationApplication,
            S::RevocationReplayAndSequenceCommitted,
            S::RevocationTombstoneCommitted,
        )
        | (
            K::ReceiverRevocationApplication,
            S::RevocationTombstoneCommitted,
            S::RevocationAffectedExchangesResolved,
        )
        | (
            K::ReceiverRevocationApplication,
            S::RevocationContainmentIntentRecorded,
            S::RevocationContained,
        ) => forward,

        (K::ReceiverIntake, S::IntakeIntentRecorded, S::RawAdmissionRejected)
        | (
            K::ReceiverRevocationApplication,
            S::RevocationIntakeIntentRecorded,
            S::RawAdmissionRejected,
        ) => cause == C::ValidationRejection,
        (K::ReceiverIntake, S::IntakeIntentRecorded, S::ValidationRejected)
        | (
            K::ReceiverRevocationApplication,
            S::RevocationIntakeIntentRecorded,
            S::ValidationRejected,
        ) => cause == C::ValidationRejection,
        (
            K::ReceiverIntake,
            S::RawQuarantined
            | S::SenderAuthenticated
            | S::ReplayAndSequenceCommitted
            | S::SenderEvidenceVerified
            | S::ReceiverProvingCommitted,
            S::ValidationRejected,
        )
        | (
            K::ReceiverRevocationApplication,
            S::RevocationRawQuarantined
            | S::RevocationAuthenticated
            | S::RevocationReplayAndSequenceCommitted,
            S::ValidationRejected,
        ) => matches!(
            cause,
            C::ValidationRejection | C::PolicyRejection | C::Expiry
        ),
        (K::ReceiverIntake, S::ActivationIntentRecorded, S::ValidationRejected) => {
            matches!(cause, C::ValidationRejection | C::PolicyRejection)
        }
        (K::ReceiverIntake, S::AwaitingApproval, S::ActivationIntentRecorded) => {
            cause == C::ApprovalDecision
        }
        (K::ReceiverIntake, S::AwaitingApproval, S::Denied) => {
            matches!(cause, C::ApprovalDecision | C::PolicyRejection)
        }
        (K::ReceiverIntake, S::AwaitingApproval, S::Expired) => cause == C::Expiry,
        (K::ReceiverIntake, S::AwaitingApproval, S::Escalated) => cause == C::ApprovalDecision,
        (
            K::ReceiverIntake,
            S::ActivationIntentRecorded
            | S::ActivationEffectCommitted
            | S::ObservationIntentRecorded,
            S::RollbackIntentRecorded,
        ) => matches!(
            cause,
            C::Revocation | C::HealthRegression | C::EffectConflict
        ),
        (
            K::ReceiverIntake,
            S::ActivationIntentRecorded
            | S::ActivationEffectCommitted
            | S::ObservationIntentRecorded,
            S::ContainmentRequired,
        ) => cause == C::EffectConflict,
        (K::ReceiverIntake, S::RollbackIntentRecorded, S::RolledBack) => matches!(
            cause,
            C::Normal | C::Recovery | C::Revocation | C::HealthRegression
        ),
        (K::ReceiverIntake, S::RollbackIntentRecorded, S::ContainmentRequired) => {
            matches!(cause, C::Recovery | C::EffectConflict)
        }
        (
            K::ReceiverRevocationApplication,
            S::RevocationAffectedExchangesResolved,
            S::RevocationContainmentIntentRecorded,
        ) => matches!(cause, C::Normal | C::Recovery | C::Revocation),
        (
            K::ReceiverRevocationApplication,
            S::RevocationAffectedExchangesResolved,
            S::RevocationContained,
        ) => forward,
        (
            K::ReceiverRevocationApplication,
            S::RevocationAffectedExchangesResolved | S::RevocationContainmentIntentRecorded,
            S::RevocationContainmentRequired,
        ) => matches!(cause, C::Recovery | C::EffectConflict),
        _ => false,
    }
}

fn initial_stage(kind: TransactionKind) -> TransactionStage {
    match kind {
        TransactionKind::SenderExport => TransactionStage::ExportIntentRecorded,
        TransactionKind::ReceiverIntake => TransactionStage::IntakeIntentRecorded,
        TransactionKind::SenderRevocationPublication => TransactionStage::RevocationIntentRecorded,
        TransactionKind::ReceiverRevocationApplication => {
            TransactionStage::RevocationIntakeIntentRecorded
        }
    }
}

/// Sole-writer, append-only coordinator journal.
///
/// `_owner_lock` is intentionally the final field so the operating-system lock
/// outlives all mutable in-memory state during drop.
pub struct CoordinatorJournal {
    root: PathBuf,
    intents_root: PathBuf,
    transactions_root: PathBuf,
    staging_root: PathBuf,
    config: JournalConfig,
    clock: Arc<dyn Clock>,
    state: Mutex<BTreeMap<String, TransactionProjection>>,
    _owner_lock: File,
}

impl CoordinatorJournal {
    pub fn open_or_initialize(
        root: impl AsRef<Path>,
        config: JournalConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, M6TransactionError> {
        config.validate()?;
        let root = secure_create_root(root.as_ref())?;
        let owner_lock = acquire_owner_lock(&root)?;
        let staging_root = secure_child_directory(&root, "staging")?;
        recover_staging(&staging_root)?;

        let config_path = root.join(CONFIG_FILE);
        let config_bytes = canonical_json(&config)?;
        persist_immutable(&staging_root, &config_path, &config_bytes)?;
        let durable_config: JournalConfig = load_canonical_record(&config_path)?;
        durable_config.validate()?;
        if durable_config != config {
            return Err(M6TransactionError::ConfigConflict {
                requested: config.config_digest,
                durable: durable_config.config_digest,
            });
        }

        let intents_root = secure_child_directory(&root, INTENTS_DIRECTORY)?;
        let transactions_root = secure_child_directory(&root, TRANSACTIONS_DIRECTORY)?;
        let state = reconstruct_all(&intents_root, &transactions_root, &durable_config)?;

        Ok(Self {
            root,
            intents_root,
            transactions_root,
            staging_root,
            config: durable_config,
            clock,
            state: Mutex::new(state),
            _owner_lock: owner_lock,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config(&self) -> &JournalConfig {
        &self.config
    }

    pub fn transaction(
        &self,
        logical_operation_id: &str,
    ) -> Result<Option<TransactionProjection>, M6TransactionError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        Ok(self.state_guard()?.get(logical_operation_id).cloned())
    }

    pub fn transactions(&self) -> Result<Vec<TransactionProjection>, M6TransactionError> {
        Ok(self.state_guard()?.values().cloned().collect())
    }

    /// Record the immutable request and its typed initial stage.
    ///
    /// Replaying the same request and evidence returns the original record,
    /// including its original timestamp and digest. Reusing either the logical
    /// ID or idempotency key for different request bytes is a conflict.
    pub fn begin(
        &self,
        draft: TransactionRequestDraft,
        initial_evidence: StageEvidence,
    ) -> Result<TransactionStageRecord, M6TransactionError> {
        let mut state = self.state_guard()?;

        if let Some(existing) = state.get(&draft.logical_operation_id) {
            let candidate = TransactionIntent::new(draft, existing.intent.created_at_ms);
            let candidate = match candidate {
                Ok(candidate) if candidate == existing.intent => candidate,
                Ok(candidate) => {
                    return Err(M6TransactionError::CrossRequestConflict {
                        identity: existing.intent.logical_operation_id.clone(),
                        existing: existing.intent.request_digest.clone(),
                        requested: candidate.request_digest,
                    });
                }
                Err(_) => {
                    return Err(M6TransactionError::CrossRequestConflict {
                        identity: existing.intent.logical_operation_id.clone(),
                        existing: existing.intent.request_digest.clone(),
                        requested: ContentDigest::from_bytes(b"invalid-request"),
                    });
                }
            };
            debug_assert_eq!(candidate, existing.intent);
            if let Some(first) = existing.stages.first() {
                return if first.evidence == initial_evidence {
                    Ok(first.clone())
                } else {
                    Err(M6TransactionError::StageConflict {
                        logical_operation_id: existing.intent.logical_operation_id.clone(),
                        stage: first.stage,
                    })
                };
            }
            let request_digest = existing.intent.request_digest.clone();
            let operation_id = existing.intent.logical_operation_id.clone();
            let kind = existing.intent.kind;
            return self.append_locked(
                &mut state,
                &operation_id,
                &request_digest,
                initial_stage(kind),
                initial_evidence,
                true,
            );
        }

        let created_at_ms = self.trusted_now_ms()?;
        let intent = TransactionIntent::new(draft, created_at_ms)?;
        initial_evidence.validate()?;
        validate_stage_evidence(&intent, initial_stage(intent.kind), &initial_evidence)?;
        if initial_evidence.cause != StageCause::Normal {
            return Err(M6TransactionError::InvalidTransition {
                kind: intent.kind,
                from: None,
                to: initial_stage(intent.kind),
                cause: initial_evidence.cause,
            });
        }
        for existing in state.values() {
            if existing.intent.idempotency_key == intent.idempotency_key {
                return Err(M6TransactionError::CrossRequestConflict {
                    identity: intent.idempotency_key.clone(),
                    existing: existing.intent.request_digest.clone(),
                    requested: intent.request_digest.clone(),
                });
            }
        }
        if state.len() >= self.config.max_transactions as usize {
            return Err(M6TransactionError::ResourceExhausted(
                "coordinator transaction count is at its configured limit".to_string(),
            ));
        }

        let intent_path = intent_path(&self.intents_root, &intent.logical_operation_id);
        persist_immutable(&self.staging_root, &intent_path, &canonical_json(&intent)?)?;
        let operation_id = intent.logical_operation_id.clone();
        let request_digest = intent.request_digest.clone();
        let kind = intent.kind;
        state.insert(
            operation_id.clone(),
            TransactionProjection {
                intent,
                stages: Vec::new(),
            },
        );
        self.append_locked(
            &mut state,
            &operation_id,
            &request_digest,
            initial_stage(kind),
            initial_evidence,
            true,
        )
    }

    pub fn append(
        &self,
        logical_operation_id: &str,
        request_digest: &ContentDigest,
        stage: TransactionStage,
        evidence: StageEvidence,
    ) -> Result<TransactionStageRecord, M6TransactionError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        let mut state = self.state_guard()?;
        self.append_locked(
            &mut state,
            logical_operation_id,
            request_digest,
            stage,
            evidence,
            false,
        )
    }

    /// Classify restart work from authoritative observations without invoking
    /// or mutating any external effect.
    pub fn plan_recovery(
        &self,
        logical_operation_id: &str,
        request_digest: &ContentDigest,
        context: &RecoveryContext,
    ) -> Result<RecoveryPlan, M6TransactionError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        let state = self.state_guard()?;
        let projection = state.get(logical_operation_id).ok_or_else(|| {
            M6TransactionError::TransactionNotFound(logical_operation_id.to_string())
        })?;
        if &projection.intent.request_digest != request_digest {
            return Err(M6TransactionError::WrongRequestDigest {
                logical_operation_id: logical_operation_id.to_string(),
                expected: projection.intent.request_digest.clone(),
                supplied: request_digest.clone(),
            });
        }
        classify_recovery(projection, context)
    }

    fn append_locked(
        &self,
        state: &mut BTreeMap<String, TransactionProjection>,
        logical_operation_id: &str,
        request_digest: &ContentDigest,
        stage: TransactionStage,
        evidence: StageEvidence,
        allow_initial: bool,
    ) -> Result<TransactionStageRecord, M6TransactionError> {
        let projection = state.get_mut(logical_operation_id).ok_or_else(|| {
            M6TransactionError::TransactionNotFound(logical_operation_id.to_string())
        })?;
        if &projection.intent.request_digest != request_digest {
            return Err(M6TransactionError::WrongRequestDigest {
                logical_operation_id: logical_operation_id.to_string(),
                expected: projection.intent.request_digest.clone(),
                supplied: request_digest.clone(),
            });
        }

        if let Some(existing) = projection
            .stages
            .iter()
            .find(|record| record.stage == stage)
        {
            return if existing.evidence == evidence {
                Ok(existing.clone())
            } else {
                Err(M6TransactionError::StageConflict {
                    logical_operation_id: logical_operation_id.to_string(),
                    stage,
                })
            };
        }

        evidence.validate()?;
        validate_stage_evidence(&projection.intent, stage, &evidence)?;
        if projection.stages.len() >= self.config.max_stages_per_transaction as usize {
            return Err(M6TransactionError::ResourceExhausted(format!(
                "transaction '{logical_operation_id}' reached its stage limit"
            )));
        }

        match projection.current_stage() {
            None if allow_initial
                && stage == initial_stage(projection.intent.kind)
                && evidence.cause == StageCause::Normal => {}
            None => {
                return Err(M6TransactionError::InvalidTransition {
                    kind: projection.intent.kind,
                    from: None,
                    to: stage,
                    cause: evidence.cause,
                });
            }
            Some(current)
                if is_legal_transition(projection.intent.kind, current, stage, evidence.cause) => {}
            Some(current) => {
                return Err(M6TransactionError::InvalidTransition {
                    kind: projection.intent.kind,
                    from: Some(current),
                    to: stage,
                    cause: evidence.cause,
                });
            }
        }

        let recorded_at_ms = self.trusted_now_ms()?;
        if let Some(previous) = projection.current_record()
            && recorded_at_ms < previous.recorded_at_ms
        {
            return Err(M6TransactionError::Clock(
                "trusted clock moved behind the durable stage chain".to_string(),
            ));
        }
        if recorded_at_ms >= projection.intent.deadline_ms && !stage_allowed_after_deadline(stage) {
            return Err(M6TransactionError::DeadlineReached {
                deadline_ms: projection.intent.deadline_ms,
                trusted_now_ms: recorded_at_ms,
            });
        }

        let ordinal = u32::try_from(projection.stages.len() + 1).map_err(|_| {
            M6TransactionError::ResourceExhausted("stage ordinal does not fit u32".to_string())
        })?;
        let previous_stage_digest = projection
            .current_record()
            .map(|record| record.stage_digest.clone());
        let record = TransactionStageRecord::new(
            &projection.intent,
            ordinal,
            previous_stage_digest,
            stage,
            evidence,
            recorded_at_ms,
        )?;
        let directory = transaction_directory(
            &self.transactions_root,
            &projection.intent.logical_operation_id,
        )?;
        let path = directory.join(stage_file_name(record.ordinal, record.stage));
        persist_immutable(&self.staging_root, &path, &canonical_json(&record)?)?;
        projection.stages.push(record.clone());
        Ok(record)
    }

    fn trusted_now_ms(&self) -> Result<u64, M6TransactionError> {
        self.clock
            .now_ms()
            .map_err(|error| M6TransactionError::Clock(error.to_string()))
    }

    fn state_guard(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<String, TransactionProjection>>, M6TransactionError> {
        self.state.lock().map_err(|_| {
            M6TransactionError::LockPoisoned("coordinator transaction state".to_string())
        })
    }
}

fn classify_recovery(
    projection: &TransactionProjection,
    context: &RecoveryContext,
) -> Result<RecoveryPlan, M6TransactionError> {
    if context.attempts_used > projection.intent.retry_policy.max_attempts {
        return Err(M6TransactionError::InvalidRecoveryContext(
            "attempt count exceeds the immutable retry policy".to_string(),
        ));
    }
    let current = projection.current_stage();

    match &context.authority {
        AuthorityAvailability::Conflicting(_) => {
            return Ok(RecoveryPlan::ContainmentRequired {
                reason: ContainmentReason::ConflictingAuthority,
            });
        }
        AuthorityAvailability::Available(reference) | AuthorityAvailability::Expired(reference)
            if !projection.intent.authority_refs.contains(reference) =>
        {
            return Ok(RecoveryPlan::ContainmentRequired {
                reason: ContainmentReason::InvalidAuthorityBinding,
            });
        }
        _ => {}
    }

    match &context.effect {
        EffectFactState::Conflicting(_) => {
            return Ok(RecoveryPlan::ContainmentRequired {
                reason: ContainmentReason::ConflictingEffectFact,
            });
        }
        EffectFactState::Ambiguous(_) => {
            return Ok(RecoveryPlan::ContainmentRequired {
                reason: ContainmentReason::AmbiguousEffectFact,
            });
        }
        EffectFactState::Committed(fact) => {
            if fact.validate().is_err() || !effect_fact_matches(&projection.intent, current, fact) {
                return Ok(RecoveryPlan::ContainmentRequired {
                    reason: ContainmentReason::MismatchedEffectBinding,
                });
            }
            return Ok(RecoveryPlan::VerifyCommittedEffect {
                fact_digest: fact.fact_digest.clone(),
                effect_stage: fact.effect_stage,
            });
        }
        EffectFactState::Missing | EffectFactState::NotApplicable
            if current.is_some_and(stage_claims_authoritative_effect) =>
        {
            return Ok(RecoveryPlan::ContainmentRequired {
                reason: ContainmentReason::MissingCommittedEffectFact,
            });
        }
        EffectFactState::Missing | EffectFactState::NotApplicable => {}
    }

    if context.revocation_pending && current.is_some_and(stage_is_activated_or_activating) {
        return Ok(RecoveryPlan::ContainmentRequired {
            reason: ContainmentReason::RevocationDuringActivation,
        });
    }

    if current.is_some_and(TransactionStage::is_terminal) {
        return Ok(RecoveryPlan::Terminal {
            reason: RecoveryTerminalReason::AlreadyTerminal,
            stage: current,
        });
    }
    if context.observed_at_ms >= projection.intent.deadline_ms {
        return Ok(RecoveryPlan::Terminal {
            reason: RecoveryTerminalReason::DeadlineReached,
            stage: current,
        });
    }
    if context.attempts_used >= projection.intent.retry_policy.max_attempts {
        return Ok(RecoveryPlan::Terminal {
            reason: RecoveryTerminalReason::RetryBudgetExhausted,
            stage: current,
        });
    }

    if matches!(
        &context.authority,
        AuthorityAvailability::Missing | AuthorityAvailability::Expired(_)
    ) || current == Some(TransactionStage::AwaitingApproval)
    {
        return Ok(RecoveryPlan::AwaitAuthority {
            deadline_ms: projection.intent.deadline_ms,
            stage: current,
        });
    }

    Ok(RecoveryPlan::ResubmitExactEffect {
        attempt: context.attempts_used + 1,
        deadline_ms: projection.intent.deadline_ms,
        idempotency_key: projection.intent.idempotency_key.clone(),
        request_digest: projection.intent.request_digest.clone(),
    })
}

fn effect_fact_matches(
    intent: &TransactionIntent,
    current: Option<TransactionStage>,
    fact: &AuthoritativeEffectFact,
) -> bool {
    if fact.request_digest != intent.request_digest
        || fact.idempotency_key != intent.idempotency_key
        || fact.before_snapshot_digest != intent.before_snapshot_digest
    {
        return false;
    }
    let expected_after = if matches!(
        fact.effect_stage,
        TransactionStage::RolledBack | TransactionStage::RevocationContained
    ) {
        &intent.before_snapshot_digest
    } else {
        &intent.expected_after_snapshot_digest
    };
    if &fact.after_snapshot_digest != expected_after {
        return false;
    }
    match current {
        None => fact.effect_stage == initial_stage(intent.kind),
        Some(TransactionStage::ActivationIntentRecorded) => {
            fact.effect_stage == TransactionStage::ActivationEffectCommitted
        }
        Some(TransactionStage::RollbackIntentRecorded) => {
            fact.effect_stage == TransactionStage::RolledBack
        }
        Some(TransactionStage::RevocationContainmentIntentRecorded) => {
            fact.effect_stage == TransactionStage::RevocationContained
        }
        Some(stage) => fact.effect_stage == stage,
    }
}

fn stage_claims_authoritative_effect(stage: TransactionStage) -> bool {
    matches!(
        stage,
        TransactionStage::ActivationEffectCommitted
            | TransactionStage::ObservationIntentRecorded
            | TransactionStage::Healthy
            | TransactionStage::RolledBack
            | TransactionStage::RevocationContained
    )
}

fn stage_is_activated_or_activating(stage: TransactionStage) -> bool {
    matches!(
        stage,
        TransactionStage::ActivationIntentRecorded
            | TransactionStage::ActivationEffectCommitted
            | TransactionStage::ObservationIntentRecorded
    )
}

fn stage_allowed_after_deadline(stage: TransactionStage) -> bool {
    matches!(
        stage,
        TransactionStage::RawAdmissionRejected
            | TransactionStage::ValidationRejected
            | TransactionStage::Expired
            | TransactionStage::RollbackIntentRecorded
            | TransactionStage::RolledBack
            | TransactionStage::ContainmentRequired
            | TransactionStage::RevocationContainmentIntentRecorded
            | TransactionStage::RevocationContained
            | TransactionStage::RevocationContainmentRequired
    )
}

fn validate_stage_evidence(
    intent: &TransactionIntent,
    stage: TransactionStage,
    evidence: &StageEvidence,
) -> Result<(), M6TransactionError> {
    if evidence.evidence_refs.is_empty() {
        return Err(M6TransactionError::InvalidStageEvidence(
            "every stage must cite at least one immutable evidence record".to_string(),
        ));
    }
    if evidence.attempt > intent.retry_policy.max_attempts
        || (evidence.cause == StageCause::Recovery
            && evidence.attempt > intent.retry_policy.max_recovery_attempts)
    {
        return Err(M6TransactionError::InvalidStageEvidence(
            "stage attempt exceeds the immutable retry policy".to_string(),
        ));
    }
    if let Some(authority_ref) = &evidence.authority_ref
        && !intent.authority_refs.contains(authority_ref)
    {
        return Err(M6TransactionError::InvalidStageEvidence(
            "stage authority is not bound by the immutable request".to_string(),
        ));
    }
    if let Some(effect_request_digest) = &evidence.effect_request_digest
        && effect_request_digest != &intent.request_digest
    {
        return Err(M6TransactionError::InvalidStageEvidence(
            "stage effect request differs from the immutable request".to_string(),
        ));
    }
    if stage_requires_authority(stage) && evidence.authority_ref.is_none() {
        return Err(M6TransactionError::InvalidStageEvidence(format!(
            "stage '{stage:?}' requires an authority reference"
        )));
    }
    if stage_is_effect_intent(stage) && evidence.effect_request_digest.is_none() {
        return Err(M6TransactionError::InvalidStageEvidence(format!(
            "stage '{stage:?}' requires the exact effect request digest"
        )));
    }
    if stage_is_effect_commit(stage)
        && (evidence.effect_request_digest.is_none()
            || evidence.receipt_ref.is_none()
            || evidence.attestation_ref.is_none())
    {
        return Err(M6TransactionError::InvalidStageEvidence(format!(
            "stage '{stage:?}' requires request, receipt, and attestation evidence"
        )));
    }
    if (stage_is_effect_intent(stage) || stage_is_effect_commit(stage)) && evidence.attempt == 0 {
        return Err(M6TransactionError::InvalidStageEvidence(format!(
            "stage '{stage:?}' requires a positive bounded attempt"
        )));
    }
    Ok(())
}

fn stage_requires_authority(stage: TransactionStage) -> bool {
    matches!(
        stage,
        TransactionStage::SenderAuthenticated
            | TransactionStage::SenderEvidenceVerified
            | TransactionStage::AwaitingApproval
            | TransactionStage::Denied
            | TransactionStage::Expired
            | TransactionStage::Escalated
            | TransactionStage::ActivationIntentRecorded
            | TransactionStage::RollbackIntentRecorded
            | TransactionStage::RevocationAuthenticated
            | TransactionStage::RevocationTombstoneCommitted
            | TransactionStage::RevocationContainmentIntentRecorded
    )
}

fn stage_is_effect_intent(stage: TransactionStage) -> bool {
    matches!(
        stage,
        TransactionStage::ActivationIntentRecorded
            | TransactionStage::RollbackIntentRecorded
            | TransactionStage::RevocationContainmentIntentRecorded
    )
}

fn stage_is_effect_commit(stage: TransactionStage) -> bool {
    matches!(
        stage,
        TransactionStage::ActivationEffectCommitted
            | TransactionStage::RolledBack
            | TransactionStage::RevocationContained
    )
}

fn reconstruct_all(
    intents_root: &Path,
    transactions_root: &Path,
    config: &JournalConfig,
) -> Result<BTreeMap<String, TransactionProjection>, M6TransactionError> {
    let intent_files = bounded_regular_files(intents_root, config.max_transactions as usize)?;
    let mut state = BTreeMap::new();
    let mut idempotency_keys = BTreeMap::<String, ContentDigest>::new();
    for path in intent_files {
        let intent: TransactionIntent = load_canonical_record(&path)?;
        intent.validate()?;
        if path != intent_path(intents_root, &intent.logical_operation_id) {
            return Err(M6TransactionError::StateIntegrity(format!(
                "intent '{}' is stored under an unexpected path",
                intent.logical_operation_id
            )));
        }
        if let Some(existing) = idempotency_keys.insert(
            intent.idempotency_key.clone(),
            intent.request_digest.clone(),
        ) {
            return Err(M6TransactionError::CrossRequestConflict {
                identity: intent.idempotency_key.clone(),
                existing,
                requested: intent.request_digest.clone(),
            });
        }
        let key = intent.logical_operation_id.clone();
        if state
            .insert(
                key.clone(),
                TransactionProjection {
                    intent,
                    stages: Vec::new(),
                },
            )
            .is_some()
        {
            return Err(M6TransactionError::StateIntegrity(format!(
                "duplicate transaction intent '{key}'"
            )));
        }
    }

    for entry in bounded_directory_entries(transactions_root, config.max_transactions as usize)? {
        let metadata = fs::symlink_metadata(&entry)
            .map_err(|source| M6TransactionError::io(&entry, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(M6TransactionError::UnsafePath(entry));
        }
        let name = entry
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| M6TransactionError::UnsafePath(entry.clone()))?;
        let projection = state
            .values_mut()
            .find(|projection| operation_stem(&projection.intent.logical_operation_id) == name)
            .ok_or_else(|| {
                M6TransactionError::StateIntegrity(format!("orphan transaction directory '{name}'"))
            })?;
        reconstruct_stages(&entry, projection, config)?;
    }
    Ok(state)
}

fn reconstruct_stages(
    directory: &Path,
    projection: &mut TransactionProjection,
    config: &JournalConfig,
) -> Result<(), M6TransactionError> {
    let files = bounded_regular_files(directory, config.max_stages_per_transaction as usize)?;
    let mut previous_digest: Option<ContentDigest> = None;
    let mut previous_stage: Option<TransactionStage> = None;
    let mut previous_time = projection.intent.created_at_ms;
    let mut seen = BTreeSet::new();
    for (index, path) in files.into_iter().enumerate() {
        let record: TransactionStageRecord = load_canonical_record(&path)?;
        let ordinal = u32::try_from(index + 1).map_err(|_| {
            M6TransactionError::ResourceExhausted("stage ordinal does not fit u32".to_string())
        })?;
        record.validate(&projection.intent, ordinal, previous_digest.as_ref())?;
        validate_stage_evidence(&projection.intent, record.stage, &record.evidence)?;
        if path.file_name().and_then(|name| name.to_str())
            != Some(stage_file_name(ordinal, record.stage).as_str())
        {
            return Err(M6TransactionError::StateIntegrity(format!(
                "stage ordinal {ordinal} has an unexpected filename"
            )));
        }
        if !seen.insert(record.stage) {
            return Err(M6TransactionError::StateIntegrity(format!(
                "stage '{:?}' appears more than once",
                record.stage
            )));
        }
        match previous_stage {
            None if record.stage == initial_stage(projection.intent.kind)
                && record.evidence.cause == StageCause::Normal => {}
            Some(previous)
                if is_legal_transition(
                    projection.intent.kind,
                    previous,
                    record.stage,
                    record.evidence.cause,
                ) => {}
            previous => {
                return Err(M6TransactionError::InvalidTransition {
                    kind: projection.intent.kind,
                    from: previous,
                    to: record.stage,
                    cause: record.evidence.cause,
                });
            }
        }
        if record.recorded_at_ms < previous_time {
            return Err(M6TransactionError::StateIntegrity(
                "stage timestamps regress within the durable chain".to_string(),
            ));
        }
        previous_time = record.recorded_at_ms;
        previous_stage = Some(record.stage);
        previous_digest = Some(record.stage_digest.clone());
        projection.stages.push(record);
    }
    Ok(())
}

fn intent_path(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!("{}.json", operation_stem(logical_operation_id)))
}

fn operation_stem(logical_operation_id: &str) -> String {
    let mut bytes = Vec::from(b"wasm-biotic:m6:logical-operation:v1\0".as_slice());
    bytes.extend_from_slice(logical_operation_id.as_bytes());
    ContentDigest::from_bytes(&bytes).file_stem()
}

fn transaction_directory(
    root: &Path,
    logical_operation_id: &str,
) -> Result<PathBuf, M6TransactionError> {
    secure_child_directory(root, &operation_stem(logical_operation_id))
}

fn stage_file_name(ordinal: u32, stage: TransactionStage) -> String {
    format!("{ordinal:06}-{}.json", stage.file_label())
}

#[derive(Debug)]
pub enum M6TransactionError {
    InvalidRequest(String),
    InvalidStageEvidence(String),
    InvalidRecoveryContext(String),
    InvalidTransition {
        kind: TransactionKind,
        from: Option<TransactionStage>,
        to: TransactionStage,
        cause: StageCause,
    },
    TransactionNotFound(String),
    CrossRequestConflict {
        identity: String,
        existing: ContentDigest,
        requested: ContentDigest,
    },
    StageConflict {
        logical_operation_id: String,
        stage: TransactionStage,
    },
    WrongRequestDigest {
        logical_operation_id: String,
        expected: ContentDigest,
        supplied: ContentDigest,
    },
    DeadlineReached {
        deadline_ms: u64,
        trusted_now_ms: u64,
    },
    DuplicateOwner(PathBuf),
    ConfigConflict {
        requested: ContentDigest,
        durable: ContentDigest,
    },
    ImmutableConflict(PathBuf),
    StateIntegrity(String),
    UnsafePath(PathBuf),
    UnsupportedSchema(String),
    Canonical(String),
    Clock(String),
    LockPoisoned(String),
    ResourceExhausted(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl M6TransactionError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl Display for M6TransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid transaction request: {message}")
            }
            Self::InvalidStageEvidence(message) => {
                write!(formatter, "invalid stage evidence: {message}")
            }
            Self::InvalidRecoveryContext(message) => {
                write!(formatter, "invalid recovery context: {message}")
            }
            Self::InvalidTransition {
                kind,
                from,
                to,
                cause,
            } => write!(
                formatter,
                "illegal {kind:?} transaction transition from {from:?} to {to:?} with cause {cause:?}"
            ),
            Self::TransactionNotFound(identity) => {
                write!(formatter, "transaction '{identity}' was not found")
            }
            Self::CrossRequestConflict {
                identity,
                existing,
                requested,
            } => write!(
                formatter,
                "transaction identity '{identity}' is already bound to {existing}, not {requested}"
            ),
            Self::StageConflict {
                logical_operation_id,
                stage,
            } => write!(
                formatter,
                "transaction '{logical_operation_id}' already records different evidence for {stage:?}"
            ),
            Self::WrongRequestDigest {
                logical_operation_id,
                expected,
                supplied,
            } => write!(
                formatter,
                "transaction '{logical_operation_id}' expects request {expected}, not {supplied}"
            ),
            Self::DeadlineReached {
                deadline_ms,
                trusted_now_ms,
            } => write!(
                formatter,
                "transaction deadline {deadline_ms} was reached at {trusted_now_ms}"
            ),
            Self::DuplicateOwner(path) => {
                write!(
                    formatter,
                    "coordinator journal '{}' already has an owner",
                    path.display()
                )
            }
            Self::ConfigConflict { requested, durable } => write!(
                formatter,
                "coordinator config {requested} conflicts with durable config {durable}"
            ),
            Self::ImmutableConflict(path) => write!(
                formatter,
                "immutable coordinator record '{}' already contains different bytes",
                path.display()
            ),
            Self::StateIntegrity(message) => {
                write!(formatter, "coordinator state integrity failure: {message}")
            }
            Self::UnsafePath(path) => {
                write!(formatter, "unsafe coordinator path '{}'", path.display())
            }
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported coordinator schema '{schema}'")
            }
            Self::Canonical(message) => {
                write!(formatter, "non-canonical coordinator encoding: {message}")
            }
            Self::Clock(message) => {
                write!(formatter, "trusted coordinator clock failed: {message}")
            }
            Self::LockPoisoned(name) => write!(formatter, "coordinator lock '{name}' was poisoned"),
            Self::ResourceExhausted(message) => {
                write!(formatter, "coordinator resource exhausted: {message}")
            }
            Self::Io { path, source } => write!(
                formatter,
                "coordinator I/O failed for '{}': {source}",
                path.display()
            ),
        }
    }
}

impl Error for M6TransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), M6TransactionError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(M6TransactionError::InvalidRequest(format!(
            "{field} must contain 1..={MAX_IDENTIFIER_BYTES} non-control bytes"
        )));
    }
    Ok(())
}

fn is_strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn require_digest(
    subject: &str,
    actual: &ContentDigest,
    expected: &ContentDigest,
) -> Result<(), M6TransactionError> {
    if actual == expected {
        Ok(())
    } else {
        Err(M6TransactionError::StateIntegrity(format!(
            "{subject} digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

fn digest_domain<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ContentDigest, M6TransactionError> {
    let mut bytes = Vec::from(domain);
    bytes.extend_from_slice(&canonical_json(value)?);
    Ok(ContentDigest::from_bytes(&bytes))
}

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, M6TransactionError> {
    let value = serde_json::to_value(value)
        .map_err(|error| M6TransactionError::Canonical(error.to_string()))?;
    let mut bytes = Vec::new();
    write_canonical_value(&value, &mut bytes)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(M6TransactionError::ResourceExhausted(format!(
            "canonical record is {} bytes; limit is {MAX_RECORD_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn write_canonical_value(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), M6TransactionError> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" })
        }
        serde_json::Value::Number(number) => {
            if !number.is_i64() && !number.is_u64() {
                return Err(M6TransactionError::Canonical(
                    "floating-point numbers are forbidden".to_string(),
                ));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        serde_json::Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|error| M6TransactionError::Canonical(error.to_string()))?
                .as_bytes(),
        ),
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_value(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|error| M6TransactionError::Canonical(error.to_string()))?
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical_value(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn parse_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, M6TransactionError> {
    let value = serde_json::from_slice::<T>(bytes)
        .map_err(|error| M6TransactionError::Canonical(error.to_string()))?;
    if canonical_json(&value)? != bytes {
        return Err(M6TransactionError::Canonical(
            "input has whitespace, key-order, duplicate-field, or representation drift".to_string(),
        ));
    }
    Ok(value)
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M6TransactionError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(M6TransactionError::UnsafePath(path.to_path_buf()));
    }
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| M6TransactionError::io(path, source))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6TransactionError::io(path, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(M6TransactionError::UnsafePath(path.to_path_buf()));
    }
    fs::canonicalize(path).map_err(|source| M6TransactionError::io(path, source))
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M6TransactionError> {
    if name.is_empty() || Path::new(name).components().count() != 1 || name == "." || name == ".." {
        return Err(M6TransactionError::UnsafePath(root.join(name)));
    }
    let path = root.join(name);
    reject_symlink_if_present(&path)?;
    fs::create_dir_all(&path).map_err(|source| M6TransactionError::io(&path, source))?;
    let canonical =
        fs::canonicalize(&path).map_err(|source| M6TransactionError::io(&path, source))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|source| M6TransactionError::io(&canonical, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || canonical.parent() != Some(root) {
        return Err(M6TransactionError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M6TransactionError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(M6TransactionError::UnsafePath(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M6TransactionError::io(path, source)),
    }
}

fn acquire_owner_lock(root: &Path) -> Result<File, M6TransactionError> {
    let path = root.join(OWNER_LOCK_FILE);
    reject_symlink_if_present(&path)?;
    if path.exists() {
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| M6TransactionError::io(&path, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(M6TransactionError::UnsafePath(path));
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| M6TransactionError::io(&path, source))?;
    file.try_lock().map_err(|source| match source {
        std::fs::TryLockError::WouldBlock => M6TransactionError::DuplicateOwner(root.to_path_buf()),
        std::fs::TryLockError::Error(source) => M6TransactionError::io(&path, source),
    })?;
    Ok(file)
}

fn recover_staging(staging_root: &Path) -> Result<(), M6TransactionError> {
    for path in bounded_regular_files(staging_root, 512)? {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !name.starts_with(".m6-transaction-") || !name.ends_with(".tmp") {
            return Err(M6TransactionError::StateIntegrity(format!(
                "unexpected coordinator staging entry '{}'",
                path.display()
            )));
        }
        fs::remove_file(&path).map_err(|source| M6TransactionError::io(&path, source))?;
    }
    sync_directory(staging_root)
}

fn persist_immutable(
    staging_root: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), M6TransactionError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(M6TransactionError::ResourceExhausted(format!(
            "durable record is {} bytes; limit is {MAX_RECORD_BYTES}",
            bytes.len()
        )));
    }
    reject_symlink_if_present(destination)?;
    if destination.exists() {
        let existing = read_regular_file_bounded(destination)?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(M6TransactionError::ImmutableConflict(
                destination.to_path_buf(),
            ))
        };
    }
    let destination_parent = destination
        .parent()
        .ok_or_else(|| M6TransactionError::UnsafePath(destination.to_path_buf()))?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = staging_root.join(format!(
        ".m6-transaction-{}-{sequence}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| M6TransactionError::io(&temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| M6TransactionError::io(&temporary, source))?;
        file.sync_all()
            .map_err(|source| M6TransactionError::io(&temporary, source))?;
        match fs::hard_link(&temporary, destination) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_regular_file_bounded(destination)?;
                if existing != bytes {
                    return Err(M6TransactionError::ImmutableConflict(
                        destination.to_path_buf(),
                    ));
                }
            }
            Err(source) => {
                return Err(M6TransactionError::io(destination, source));
            }
        }
        sync_directory(destination_parent)
    })();
    let _ = fs::remove_file(&temporary);
    let _ = sync_directory(staging_root);
    result
}

fn load_canonical_record<T: DeserializeOwned + Serialize>(
    path: &Path,
) -> Result<T, M6TransactionError> {
    parse_canonical(&read_regular_file_bounded(path)?)
}

fn read_regular_file_bounded(path: &Path) -> Result<Vec<u8>, M6TransactionError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6TransactionError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(M6TransactionError::UnsafePath(path.to_path_buf()));
    }
    let length = usize::try_from(metadata.len()).map_err(|_| {
        M6TransactionError::ResourceExhausted(format!(
            "record '{}' length does not fit usize",
            path.display()
        ))
    })?;
    if length > MAX_RECORD_BYTES {
        return Err(M6TransactionError::ResourceExhausted(format!(
            "record '{}' is {length} bytes; limit is {MAX_RECORD_BYTES}",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(length);
    File::open(path)
        .and_then(|file| {
            file.take((MAX_RECORD_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
        })
        .map_err(|source| M6TransactionError::io(path, source))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(M6TransactionError::ResourceExhausted(format!(
            "record '{}' exceeds {MAX_RECORD_BYTES} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn bounded_regular_files(
    directory: &Path,
    limit: usize,
) -> Result<Vec<PathBuf>, M6TransactionError> {
    let mut files = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|source| M6TransactionError::io(directory, source))?
    {
        let path = entry
            .map_err(|source| M6TransactionError::io(directory, source))?
            .path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| M6TransactionError::io(&path, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(M6TransactionError::UnsafePath(path));
        }
        files.push(path);
        if files.len() > limit {
            return Err(M6TransactionError::ResourceExhausted(format!(
                "directory '{}' exceeds its {limit}-entry limit",
                directory.display()
            )));
        }
    }
    files.sort();
    Ok(files)
}

fn bounded_directory_entries(
    directory: &Path,
    limit: usize,
) -> Result<Vec<PathBuf>, M6TransactionError> {
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|source| M6TransactionError::io(directory, source))?
    {
        entries.push(
            entry
                .map_err(|source| M6TransactionError::io(directory, source))?
                .path(),
        );
        if entries.len() > limit {
            return Err(M6TransactionError::ResourceExhausted(format!(
                "directory '{}' exceeds its {limit}-entry limit",
                directory.display()
            )));
        }
    }
    entries.sort();
    Ok(entries)
}

fn sync_directory(path: &Path) -> Result<(), M6TransactionError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| M6TransactionError::io(path, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m6_identity::DeterministicClock;
    use std::thread;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m6-transactions-{label}-{}-{}",
                std::process::id(),
                TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create M6 transaction test root");
            Self(path)
        }

        fn child(&self, label: &str) -> PathBuf {
            self.0.join(label)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if self.0.exists() && std::env::var_os("KEEP_M6_TRANSACTION_TEST_ROOT").is_none() {
                fs::remove_dir_all(&self.0).expect("remove M6 transaction test root");
            }
        }
    }

    fn digest(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(label.as_bytes())
    }

    fn config() -> JournalConfig {
        JournalConfig::bounded(256, 64).expect("bounded journal config")
    }

    fn draft(
        kind: TransactionKind,
        logical_operation_id: &str,
        idempotency_key: &str,
    ) -> TransactionRequestDraft {
        TransactionRequestDraft {
            kind,
            logical_operation_id: logical_operation_id.to_string(),
            idempotency_key: idempotency_key.to_string(),
            route_id: "route-a".to_string(),
            route_generation: 1,
            route_definition_digest: digest("route-definition"),
            message_digest: digest("message"),
            exchange_digest: digest("exchange"),
            package_digest: digest("package"),
            before_snapshot_digest: digest("before"),
            expected_after_snapshot_digest: digest("after"),
            policy_digest: digest("policy"),
            authority_refs: vec![digest("authority")],
            evidence_refs: vec![digest("request-evidence")],
            retry_policy: RetryPolicy::bounded(8, 4, 1_000).expect("bounded retry policy"),
            deadline_ms: 10_000,
        }
    }

    fn initial_evidence() -> StageEvidence {
        StageEvidence::new(
            StageCause::Normal,
            0,
            Some(digest("authority")),
            None,
            None,
            None,
            vec![digest("initial-stage-evidence")],
        )
        .expect("initial evidence")
    }

    fn evidence(request_digest: &ContentDigest, cause: StageCause) -> StageEvidence {
        StageEvidence::new(
            cause,
            1,
            Some(digest("authority")),
            Some(request_digest.clone()),
            Some(digest("receipt")),
            Some(digest("attestation")),
            vec![digest("stage-evidence")],
        )
        .expect("stage evidence")
    }

    fn open(root: &Path, clock: Arc<DeterministicClock>) -> CoordinatorJournal {
        CoordinatorJournal::open_or_initialize(root, config(), clock)
            .expect("open coordinator journal")
    }

    type StagePath = Vec<(TransactionStage, StageCause)>;

    fn receiver_prefix() -> StagePath {
        use TransactionStage as S;
        vec![
            (S::IntakeIntentRecorded, StageCause::Normal),
            (S::RawQuarantined, StageCause::Normal),
            (S::SenderAuthenticated, StageCause::Normal),
            (S::ReplayAndSequenceCommitted, StageCause::Normal),
            (S::SenderEvidenceVerified, StageCause::Normal),
            (S::ReceiverProvingCommitted, StageCause::Normal),
            (S::AwaitingApproval, StageCause::Normal),
        ]
    }

    fn revocation_application_prefix() -> StagePath {
        use TransactionStage as S;
        vec![
            (S::RevocationIntakeIntentRecorded, StageCause::Normal),
            (S::RevocationRawQuarantined, StageCause::Normal),
            (S::RevocationAuthenticated, StageCause::Normal),
            (S::RevocationReplayAndSequenceCommitted, StageCause::Normal),
            (S::RevocationTombstoneCommitted, StageCause::Normal),
            (S::RevocationAffectedExchangesResolved, StageCause::Normal),
        ]
    }

    fn all_valid_paths() -> Vec<(TransactionKind, StagePath)> {
        use TransactionKind as K;
        use TransactionStage as S;

        let sender = vec![
            (S::ExportIntentRecorded, StageCause::Normal),
            (S::OutboundBundleCommitted, StageCause::Normal),
            (S::RouteStageCommitted, StageCause::Normal),
            (S::RouteReadyCommitted, StageCause::Normal),
            (S::ExportReceiptCommitted, StageCause::Normal),
        ];
        let revocation_sender = vec![
            (S::RevocationIntentRecorded, StageCause::Normal),
            (S::RevocationOutboundCommitted, StageCause::Normal),
            (S::RevocationRouteStageCommitted, StageCause::Normal),
            (S::RevocationRouteReadyCommitted, StageCause::Normal),
            (S::RevocationReceiptCommitted, StageCause::Normal),
        ];

        let mut healthy = receiver_prefix();
        healthy.extend([
            (S::ActivationIntentRecorded, StageCause::ApprovalDecision),
            (S::ActivationEffectCommitted, StageCause::Normal),
            (S::ObservationIntentRecorded, StageCause::Normal),
            (S::Healthy, StageCause::Normal),
        ]);
        let mut denied = receiver_prefix();
        denied.push((S::Denied, StageCause::ApprovalDecision));
        let mut promotion_rejected = receiver_prefix();
        promotion_rejected.extend([
            (S::ActivationIntentRecorded, StageCause::ApprovalDecision),
            (S::ValidationRejected, StageCause::ValidationRejection),
        ]);
        let raw_admission_rejected = vec![
            (S::IntakeIntentRecorded, StageCause::Normal),
            (S::RawAdmissionRejected, StageCause::ValidationRejection),
        ];
        let validation_rejected = vec![
            (S::IntakeIntentRecorded, StageCause::Normal),
            (S::RawQuarantined, StageCause::Normal),
            (S::ValidationRejected, StageCause::ValidationRejection),
        ];
        let mut expired = receiver_prefix();
        expired.push((S::Expired, StageCause::Expiry));
        let mut escalated = receiver_prefix();
        escalated.push((S::Escalated, StageCause::ApprovalDecision));
        let mut rolled_back = receiver_prefix();
        rolled_back.extend([
            (S::ActivationIntentRecorded, StageCause::ApprovalDecision),
            (S::ActivationEffectCommitted, StageCause::Normal),
            (S::RollbackIntentRecorded, StageCause::Revocation),
            (S::RolledBack, StageCause::Revocation),
        ]);
        let mut contained = receiver_prefix();
        contained.extend([
            (S::ActivationIntentRecorded, StageCause::ApprovalDecision),
            (S::ActivationEffectCommitted, StageCause::Normal),
            (S::ContainmentRequired, StageCause::EffectConflict),
        ]);

        let mut revocation_contained = revocation_application_prefix();
        revocation_contained.extend([
            (
                S::RevocationContainmentIntentRecorded,
                StageCause::Revocation,
            ),
            (S::RevocationContained, StageCause::Normal),
        ]);
        let mut revocation_required = revocation_application_prefix();
        revocation_required.extend([
            (
                S::RevocationContainmentIntentRecorded,
                StageCause::Revocation,
            ),
            (S::RevocationContainmentRequired, StageCause::EffectConflict),
        ]);

        vec![
            (K::SenderExport, sender),
            (K::ReceiverIntake, healthy),
            (K::ReceiverIntake, raw_admission_rejected),
            (K::ReceiverIntake, validation_rejected),
            (K::ReceiverIntake, denied),
            (K::ReceiverIntake, promotion_rejected),
            (K::ReceiverIntake, expired),
            (K::ReceiverIntake, escalated),
            (K::ReceiverIntake, rolled_back),
            (K::ReceiverIntake, contained),
            (K::SenderRevocationPublication, revocation_sender),
            (K::ReceiverRevocationApplication, revocation_contained),
            (K::ReceiverRevocationApplication, revocation_required),
        ]
    }

    fn expected_transitions() -> Vec<(
        TransactionKind,
        TransactionStage,
        TransactionStage,
        Vec<StageCause>,
    )> {
        use StageCause as C;
        use TransactionKind as K;
        use TransactionStage as S;

        let forward = vec![C::Normal, C::Recovery];
        vec![
            (
                K::SenderExport,
                S::ExportIntentRecorded,
                S::OutboundBundleCommitted,
                forward.clone(),
            ),
            (
                K::SenderExport,
                S::OutboundBundleCommitted,
                S::RouteStageCommitted,
                forward.clone(),
            ),
            (
                K::SenderExport,
                S::RouteStageCommitted,
                S::RouteReadyCommitted,
                forward.clone(),
            ),
            (
                K::SenderExport,
                S::RouteReadyCommitted,
                S::ExportReceiptCommitted,
                forward.clone(),
            ),
            (
                K::ReceiverIntake,
                S::IntakeIntentRecorded,
                S::RawQuarantined,
                forward.clone(),
            ),
            (
                K::ReceiverIntake,
                S::IntakeIntentRecorded,
                S::RawAdmissionRejected,
                vec![C::ValidationRejection],
            ),
            (
                K::ReceiverIntake,
                S::IntakeIntentRecorded,
                S::ValidationRejected,
                vec![C::ValidationRejection],
            ),
            (
                K::ReceiverIntake,
                S::RawQuarantined,
                S::SenderAuthenticated,
                forward.clone(),
            ),
            (
                K::ReceiverIntake,
                S::SenderAuthenticated,
                S::ReplayAndSequenceCommitted,
                forward.clone(),
            ),
            (
                K::ReceiverIntake,
                S::ReplayAndSequenceCommitted,
                S::SenderEvidenceVerified,
                forward.clone(),
            ),
            (
                K::ReceiverIntake,
                S::SenderEvidenceVerified,
                S::ReceiverProvingCommitted,
                forward.clone(),
            ),
            (
                K::ReceiverIntake,
                S::ReceiverProvingCommitted,
                S::AwaitingApproval,
                forward.clone(),
            ),
            (
                K::ReceiverIntake,
                S::RawQuarantined,
                S::ValidationRejected,
                vec![C::ValidationRejection, C::PolicyRejection, C::Expiry],
            ),
            (
                K::ReceiverIntake,
                S::SenderAuthenticated,
                S::ValidationRejected,
                vec![C::ValidationRejection, C::PolicyRejection, C::Expiry],
            ),
            (
                K::ReceiverIntake,
                S::ReplayAndSequenceCommitted,
                S::ValidationRejected,
                vec![C::ValidationRejection, C::PolicyRejection, C::Expiry],
            ),
            (
                K::ReceiverIntake,
                S::SenderEvidenceVerified,
                S::ValidationRejected,
                vec![C::ValidationRejection, C::PolicyRejection, C::Expiry],
            ),
            (
                K::ReceiverIntake,
                S::ReceiverProvingCommitted,
                S::ValidationRejected,
                vec![C::ValidationRejection, C::PolicyRejection, C::Expiry],
            ),
            (
                K::ReceiverIntake,
                S::AwaitingApproval,
                S::ActivationIntentRecorded,
                vec![C::ApprovalDecision],
            ),
            (
                K::ReceiverIntake,
                S::AwaitingApproval,
                S::Denied,
                vec![C::ApprovalDecision, C::PolicyRejection],
            ),
            (
                K::ReceiverIntake,
                S::AwaitingApproval,
                S::Expired,
                vec![C::Expiry],
            ),
            (
                K::ReceiverIntake,
                S::AwaitingApproval,
                S::Escalated,
                vec![C::ApprovalDecision],
            ),
            (
                K::ReceiverIntake,
                S::ActivationIntentRecorded,
                S::ValidationRejected,
                vec![C::ValidationRejection, C::PolicyRejection],
            ),
            (
                K::ReceiverIntake,
                S::ActivationIntentRecorded,
                S::ActivationEffectCommitted,
                forward.clone(),
            ),
            (
                K::ReceiverIntake,
                S::ActivationEffectCommitted,
                S::ObservationIntentRecorded,
                forward.clone(),
            ),
            (
                K::ReceiverIntake,
                S::ObservationIntentRecorded,
                S::Healthy,
                forward.clone(),
            ),
            (
                K::ReceiverIntake,
                S::ActivationIntentRecorded,
                S::RollbackIntentRecorded,
                vec![C::Revocation, C::HealthRegression, C::EffectConflict],
            ),
            (
                K::ReceiverIntake,
                S::ActivationEffectCommitted,
                S::RollbackIntentRecorded,
                vec![C::Revocation, C::HealthRegression, C::EffectConflict],
            ),
            (
                K::ReceiverIntake,
                S::ObservationIntentRecorded,
                S::RollbackIntentRecorded,
                vec![C::Revocation, C::HealthRegression, C::EffectConflict],
            ),
            (
                K::ReceiverIntake,
                S::ActivationIntentRecorded,
                S::ContainmentRequired,
                vec![C::EffectConflict],
            ),
            (
                K::ReceiverIntake,
                S::ActivationEffectCommitted,
                S::ContainmentRequired,
                vec![C::EffectConflict],
            ),
            (
                K::ReceiverIntake,
                S::ObservationIntentRecorded,
                S::ContainmentRequired,
                vec![C::EffectConflict],
            ),
            (
                K::ReceiverIntake,
                S::RollbackIntentRecorded,
                S::RolledBack,
                vec![C::Normal, C::Recovery, C::Revocation, C::HealthRegression],
            ),
            (
                K::ReceiverIntake,
                S::RollbackIntentRecorded,
                S::ContainmentRequired,
                vec![C::Recovery, C::EffectConflict],
            ),
            (
                K::SenderRevocationPublication,
                S::RevocationIntentRecorded,
                S::RevocationOutboundCommitted,
                forward.clone(),
            ),
            (
                K::SenderRevocationPublication,
                S::RevocationOutboundCommitted,
                S::RevocationRouteStageCommitted,
                forward.clone(),
            ),
            (
                K::SenderRevocationPublication,
                S::RevocationRouteStageCommitted,
                S::RevocationRouteReadyCommitted,
                forward.clone(),
            ),
            (
                K::SenderRevocationPublication,
                S::RevocationRouteReadyCommitted,
                S::RevocationReceiptCommitted,
                forward.clone(),
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationIntakeIntentRecorded,
                S::RevocationRawQuarantined,
                forward.clone(),
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationIntakeIntentRecorded,
                S::RawAdmissionRejected,
                vec![C::ValidationRejection],
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationIntakeIntentRecorded,
                S::ValidationRejected,
                vec![C::ValidationRejection],
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationRawQuarantined,
                S::RevocationAuthenticated,
                forward.clone(),
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationAuthenticated,
                S::RevocationReplayAndSequenceCommitted,
                forward.clone(),
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationReplayAndSequenceCommitted,
                S::RevocationTombstoneCommitted,
                forward.clone(),
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationRawQuarantined,
                S::ValidationRejected,
                vec![C::ValidationRejection, C::PolicyRejection, C::Expiry],
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationAuthenticated,
                S::ValidationRejected,
                vec![C::ValidationRejection, C::PolicyRejection, C::Expiry],
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationReplayAndSequenceCommitted,
                S::ValidationRejected,
                vec![C::ValidationRejection, C::PolicyRejection, C::Expiry],
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationTombstoneCommitted,
                S::RevocationAffectedExchangesResolved,
                forward.clone(),
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationAffectedExchangesResolved,
                S::RevocationContainmentIntentRecorded,
                vec![C::Normal, C::Recovery, C::Revocation],
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationAffectedExchangesResolved,
                S::RevocationContained,
                forward.clone(),
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationContainmentIntentRecorded,
                S::RevocationContained,
                forward,
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationAffectedExchangesResolved,
                S::RevocationContainmentRequired,
                vec![C::Recovery, C::EffectConflict],
            ),
            (
                K::ReceiverRevocationApplication,
                S::RevocationContainmentIntentRecorded,
                S::RevocationContainmentRequired,
                vec![C::Recovery, C::EffectConflict],
            ),
        ]
    }

    #[test]
    fn route_profile_caps_transaction_retry_and_timeout_boundaries() {
        let profile = RouteResourceProfile::bounded_default().expect("route profile");

        JournalConfig::bounded(profile.max_transaction_records, 8)
            .expect("journal at route boundary")
            .validate_for_resource_profile(&profile)
            .expect("journal boundary is accepted");
        assert!(matches!(
            JournalConfig::bounded(profile.max_transaction_records + 1, 8)
                .expect("journal within hard bound")
                .validate_for_resource_profile(&profile),
            Err(M6TransactionError::InvalidRequest(_))
        ));

        RetryPolicy::bounded(
            profile.max_retry_attempts,
            profile.max_recovery_attempts,
            profile.max_message_lifetime_ms,
        )
        .expect("retry at route boundaries")
        .validate_for_resource_profile(&profile)
        .expect("retry boundaries are accepted");
        assert!(matches!(
            RetryPolicy::bounded(
                profile.max_retry_attempts + 1,
                profile.max_recovery_attempts,
                profile.max_message_lifetime_ms,
            )
            .expect("retry within hard bound")
            .validate_for_resource_profile(&profile),
            Err(M6TransactionError::InvalidRequest(_))
        ));
        assert!(matches!(
            RetryPolicy::bounded(
                profile.max_retry_attempts,
                profile.max_recovery_attempts,
                profile.max_message_lifetime_ms + 1,
            )
            .expect("timeout within hard bound")
            .validate_for_resource_profile(&profile),
            Err(M6TransactionError::InvalidRequest(_))
        ));
    }

    #[test]
    fn transition_graph_is_exhaustive_and_healthy_is_terminal() {
        let expected = expected_transitions();
        let kinds = [
            TransactionKind::SenderExport,
            TransactionKind::ReceiverIntake,
            TransactionKind::SenderRevocationPublication,
            TransactionKind::ReceiverRevocationApplication,
        ];
        let causes = [
            StageCause::Normal,
            StageCause::Recovery,
            StageCause::ValidationRejection,
            StageCause::PolicyRejection,
            StageCause::ApprovalDecision,
            StageCause::Expiry,
            StageCause::HealthRegression,
            StageCause::Revocation,
            StageCause::EffectConflict,
        ];

        for kind in kinds {
            for from in TransactionStage::ALL {
                for to in TransactionStage::ALL {
                    for cause in causes {
                        let listed = expected.iter().any(
                            |(expected_kind, expected_from, expected_to, allowed)| {
                                *expected_kind == kind
                                    && *expected_from == from
                                    && *expected_to == to
                                    && allowed.contains(&cause)
                            },
                        );
                        assert_eq!(
                            is_legal_transition(kind, from, to, cause),
                            listed,
                            "unexpected graph result for {kind:?}: {from:?} -> {to:?} ({cause:?})"
                        );
                    }
                }
            }
        }
        assert!(TransactionStage::Healthy.is_terminal());
        assert!(!is_legal_transition(
            TransactionKind::ReceiverIntake,
            TransactionStage::Healthy,
            TransactionStage::RollbackIntentRecorded,
            StageCause::Revocation,
        ));

        let covered = all_valid_paths()
            .into_iter()
            .flat_map(|(_, path)| path)
            .map(|(stage, _)| stage)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            covered,
            TransactionStage::ALL.into_iter().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn raw_admission_and_post_quarantine_rejections_are_distinct_terminal_facts() {
        use StageCause as C;
        use TransactionKind as K;
        use TransactionStage as S;

        assert!(is_legal_transition(
            K::ReceiverIntake,
            S::IntakeIntentRecorded,
            S::RawAdmissionRejected,
            C::ValidationRejection,
        ));
        assert!(is_legal_transition(
            K::ReceiverRevocationApplication,
            S::RevocationIntakeIntentRecorded,
            S::RawAdmissionRejected,
            C::ValidationRejection,
        ));
        for (kind, initial) in [
            (K::ReceiverIntake, S::IntakeIntentRecorded),
            (
                K::ReceiverRevocationApplication,
                S::RevocationIntakeIntentRecorded,
            ),
        ] {
            assert!(is_legal_transition(
                kind,
                initial,
                S::ValidationRejected,
                C::ValidationRejection,
            ));
            for forbidden_cause in [
                C::Normal,
                C::Recovery,
                C::PolicyRejection,
                C::ApprovalDecision,
                C::Expiry,
                C::HealthRegression,
                C::Revocation,
                C::EffectConflict,
            ] {
                assert!(!is_legal_transition(
                    kind,
                    initial,
                    S::ValidationRejected,
                    forbidden_cause,
                ));
            }
        }
        assert!(!is_legal_transition(
            K::ReceiverIntake,
            S::RawQuarantined,
            S::RawAdmissionRejected,
            C::ValidationRejection,
        ));
        assert!(is_legal_transition(
            K::ReceiverIntake,
            S::RawQuarantined,
            S::ValidationRejected,
            C::ValidationRejection,
        ));
        assert!(is_legal_transition(
            K::ReceiverIntake,
            S::ReceiverProvingCommitted,
            S::ValidationRejected,
            C::PolicyRejection,
        ));
        assert!(S::RawAdmissionRejected.is_terminal());
        assert!(S::ValidationRejected.is_terminal());

        for terminal in [S::RawAdmissionRejected, S::ValidationRejected] {
            for kind in [
                K::SenderExport,
                K::ReceiverIntake,
                K::SenderRevocationPublication,
                K::ReceiverRevocationApplication,
            ] {
                for next in S::ALL {
                    for cause in [
                        C::Normal,
                        C::Recovery,
                        C::ValidationRejection,
                        C::PolicyRejection,
                        C::ApprovalDecision,
                        C::Expiry,
                        C::HealthRegression,
                        C::Revocation,
                        C::EffectConflict,
                    ] {
                        assert!(
                            !is_legal_transition(kind, terminal, next, cause),
                            "terminal rejection unexpectedly advanced: {kind:?} {terminal:?} -> {next:?} ({cause:?})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn post_replay_validation_rejection_requires_terminal_negative_record_digest() {
        let directory = TestDirectory::new("terminal-negative-evidence");
        let root = directory.child("journal");
        let journal = open(&root, Arc::new(DeterministicClock::new(1_000)));
        let logical_id = "terminal-negative";
        let request_digest = journal
            .begin(
                draft(
                    TransactionKind::ReceiverIntake,
                    logical_id,
                    "terminal-negative-key",
                ),
                initial_evidence(),
            )
            .expect("begin receiver intake")
            .request_digest;
        for stage in [
            TransactionStage::RawQuarantined,
            TransactionStage::SenderAuthenticated,
            TransactionStage::ReplayAndSequenceCommitted,
        ] {
            journal
                .append(
                    logical_id,
                    &request_digest,
                    stage,
                    evidence(&request_digest, StageCause::Normal),
                )
                .expect("advance through authenticated replay commit");
        }

        let missing_negative_record = StageEvidence::new(
            StageCause::ValidationRejection,
            1,
            None,
            None,
            None,
            None,
            vec![],
        )
        .expect("construct structurally valid empty evidence");
        assert!(matches!(
            journal.append(
                logical_id,
                &request_digest,
                TransactionStage::ValidationRejected,
                missing_negative_record,
            ),
            Err(M6TransactionError::InvalidStageEvidence(_))
        ));

        let terminal_negative_record_digest = digest("terminal-negative-record");
        let committed = journal
            .append(
                logical_id,
                &request_digest,
                TransactionStage::ValidationRejected,
                StageEvidence::new(
                    StageCause::ValidationRejection,
                    1,
                    None,
                    None,
                    None,
                    None,
                    vec![terminal_negative_record_digest.clone()],
                )
                .expect("terminal-negative evidence"),
            )
            .expect("terminalize after negative replay evidence");
        assert_eq!(
            committed.evidence.evidence_refs,
            vec![terminal_negative_record_digest]
        );
        assert!(committed.stage.is_terminal());
    }

    #[test]
    fn every_stage_prefix_reconstructs_and_can_finish() {
        let directory = TestDirectory::new("crash-every-stage");
        for (path_index, (kind, path)) in all_valid_paths().into_iter().enumerate() {
            for prefix_len in 1..=path.len() {
                let root = directory.child(&format!("path-{path_index}-{prefix_len}"));
                let clock = Arc::new(DeterministicClock::new(1_000));
                let logical_id = format!("logical-{path_index}");
                let idempotency_key = format!("idempotency-{path_index}");
                let request = draft(kind, &logical_id, &idempotency_key);
                let request_digest;
                {
                    let journal = open(&root, clock.clone());
                    let first = journal
                        .begin(request.clone(), initial_evidence())
                        .expect("record initial stage");
                    assert_eq!(first.stage, path[0].0);
                    request_digest = first.request_digest.clone();
                    for (stage, cause) in path.iter().copied().skip(1).take(prefix_len - 1) {
                        journal
                            .append(
                                &logical_id,
                                &request_digest,
                                stage,
                                evidence(&request_digest, cause),
                            )
                            .expect("append stage before simulated crash");
                    }
                }

                let journal = open(&root, clock);
                let recovered = journal
                    .transaction(&logical_id)
                    .expect("load projection")
                    .expect("projection exists");
                assert_eq!(recovered.stages.len(), prefix_len);
                assert_eq!(recovered.current_stage(), Some(path[prefix_len - 1].0));

                for (stage, cause) in path.iter().copied().skip(prefix_len) {
                    journal
                        .append(
                            &logical_id,
                            &request_digest,
                            stage,
                            evidence(&request_digest, cause),
                        )
                        .expect("finish recovered path");
                }
                let finished = journal
                    .transaction(&logical_id)
                    .expect("load finished projection")
                    .expect("finished projection exists");
                assert_eq!(finished.stages.len(), path.len());
                assert_eq!(finished.current_stage(), path.last().map(|item| item.0));
            }
        }
    }

    #[test]
    fn intent_only_crash_resumes_the_exact_initial_record() {
        let directory = TestDirectory::new("intent-only");
        let root = directory.child("journal");
        let clock = Arc::new(DeterministicClock::new(1_000));
        drop(open(&root, clock.clone()));

        let request = draft(
            TransactionKind::ReceiverIntake,
            "intent-only",
            "intent-only-key",
        );
        let intent = TransactionIntent::new(request.clone(), 1_000).expect("build intent");
        persist_immutable(
            &root.join("staging"),
            &intent_path(&root.join(INTENTS_DIRECTORY), "intent-only"),
            &canonical_json(&intent).expect("canonical intent"),
        )
        .expect("simulate committed intent before crash");

        let journal = open(&root, clock);
        assert!(
            journal
                .transaction("intent-only")
                .expect("read intent-only projection")
                .expect("intent-only projection exists")
                .stages
                .is_empty()
        );
        let initial = journal
            .begin(request, initial_evidence())
            .expect("resume exact initial stage");
        assert_eq!(initial.request_digest, intent.request_digest);
        assert_eq!(initial.stage, TransactionStage::IntakeIntentRecorded);
    }

    #[test]
    fn tampered_stage_prevents_reopen() {
        let directory = TestDirectory::new("tamper");
        let root = directory.child("journal");
        let clock = Arc::new(DeterministicClock::new(1_000));
        let request = draft(TransactionKind::ReceiverIntake, "tampered", "tampered-key");
        let request_digest;
        {
            let journal = open(&root, clock.clone());
            request_digest = journal
                .begin(request, initial_evidence())
                .expect("begin tamper transaction")
                .request_digest;
            journal
                .append(
                    "tampered",
                    &request_digest,
                    TransactionStage::RawQuarantined,
                    evidence(&request_digest, StageCause::Normal),
                )
                .expect("append raw quarantine");
        }

        let stage_path = root
            .join(TRANSACTIONS_DIRECTORY)
            .join(operation_stem("tampered"))
            .join(stage_file_name(2, TransactionStage::RawQuarantined));
        let mut bytes = fs::read(&stage_path).expect("read stage to tamper");
        let needle = b"raw_quarantined";
        let offset = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("stage label in durable record");
        bytes[offset] = b'x';
        fs::write(&stage_path, bytes).expect("tamper durable stage");

        let result = CoordinatorJournal::open_or_initialize(&root, config(), clock);
        assert!(matches!(
            result,
            Err(M6TransactionError::Canonical(_)) | Err(M6TransactionError::StateIntegrity(_))
        ));
    }

    fn snapshot_files(root: &Path, current: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(current)
            .expect("read snapshot directory")
            .map(|entry| entry.expect("read snapshot entry").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            let metadata = fs::symlink_metadata(&path).expect("snapshot metadata");
            if metadata.is_dir() {
                snapshot_files(root, &path, snapshot);
            } else if metadata.is_file() {
                snapshot.insert(
                    path.strip_prefix(root)
                        .expect("snapshot path beneath root")
                        .to_path_buf(),
                    fs::read(&path).expect("read snapshot file"),
                );
            }
        }
    }

    fn durable_snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut snapshot = BTreeMap::new();
        snapshot_files(root, root, &mut snapshot);
        snapshot
    }

    #[test]
    fn duplicate_owner_is_rejected_without_mutating_durable_state() {
        let directory = TestDirectory::new("duplicate-owner");
        let root = directory.child("journal");
        let clock = Arc::new(DeterministicClock::new(1_000));
        let owner = open(&root, clock.clone());
        owner
            .begin(
                draft(TransactionKind::SenderExport, "owned", "owned-key"),
                initial_evidence(),
            )
            .expect("begin owned transaction");
        let before = durable_snapshot(&root);

        let duplicate = CoordinatorJournal::open_or_initialize(&root, config(), clock);
        assert!(matches!(
            duplicate,
            Err(M6TransactionError::DuplicateOwner(_))
        ));
        assert_eq!(durable_snapshot(&root), before);
    }

    #[test]
    fn concurrent_exact_replay_appends_one_immutable_stage() {
        let directory = TestDirectory::new("concurrent");
        let root = directory.child("journal");
        let clock = Arc::new(DeterministicClock::new(1_000));
        let journal = Arc::new(open(&root, clock));
        let request_digest = journal
            .begin(
                draft(
                    TransactionKind::ReceiverIntake,
                    "concurrent",
                    "concurrent-key",
                ),
                initial_evidence(),
            )
            .expect("begin concurrent transaction")
            .request_digest;
        let shared_evidence = evidence(&request_digest, StageCause::Normal);

        let mut handles = Vec::new();
        for _ in 0..16 {
            let journal = journal.clone();
            let request_digest = request_digest.clone();
            let shared_evidence = shared_evidence.clone();
            handles.push(thread::spawn(move || {
                journal
                    .append(
                        "concurrent",
                        &request_digest,
                        TransactionStage::RawQuarantined,
                        shared_evidence,
                    )
                    .expect("concurrent exact replay")
            }));
        }
        let records = handles
            .into_iter()
            .map(|handle| handle.join().expect("join exact replay"))
            .collect::<Vec<_>>();
        assert!(
            records
                .iter()
                .all(|record| record.stage_digest == records[0].stage_digest)
        );
        assert_eq!(
            journal
                .transaction("concurrent")
                .expect("load concurrent transaction")
                .expect("concurrent transaction exists")
                .stages
                .len(),
            2
        );
    }

    #[test]
    fn exact_replay_is_idempotent_and_cross_request_reuse_conflicts() {
        let directory = TestDirectory::new("cross-request");
        let root = directory.child("journal");
        let clock = Arc::new(DeterministicClock::new(1_000));
        let journal = open(&root, clock);
        let request = draft(TransactionKind::SenderExport, "logical", "stable-key");
        let first = journal
            .begin(request.clone(), initial_evidence())
            .expect("first begin");
        let replay = journal
            .begin(request.clone(), initial_evidence())
            .expect("exact begin replay");
        assert_eq!(replay.stage_digest, first.stage_digest);

        let mut conflicting = request;
        conflicting.package_digest = digest("different-package");
        assert!(matches!(
            journal.begin(conflicting, initial_evidence()),
            Err(M6TransactionError::CrossRequestConflict { .. })
        ));
        assert!(matches!(
            journal.begin(
                draft(TransactionKind::SenderExport, "other-logical", "stable-key",),
                initial_evidence(),
            ),
            Err(M6TransactionError::CrossRequestConflict { .. })
        ));
    }

    fn advance_receiver_to_activation(
        journal: &CoordinatorJournal,
        logical_id: &str,
        request_digest: &ContentDigest,
    ) {
        for (stage, cause) in receiver_prefix().into_iter().skip(1).chain([(
            TransactionStage::ActivationIntentRecorded,
            StageCause::ApprovalDecision,
        )]) {
            journal
                .append(
                    logical_id,
                    request_digest,
                    stage,
                    evidence(request_digest, cause),
                )
                .expect("advance receiver to activation");
        }
    }

    #[test]
    fn revocation_during_activation_requires_a_durable_rollback_branch() {
        let directory = TestDirectory::new("revocation-activation");
        let root = directory.child("journal");
        let journal = open(&root, Arc::new(DeterministicClock::new(1_000)));
        let request_digest = journal
            .begin(
                draft(
                    TransactionKind::ReceiverIntake,
                    "activation",
                    "activation-key",
                ),
                initial_evidence(),
            )
            .expect("begin activation transaction")
            .request_digest;
        advance_receiver_to_activation(&journal, "activation", &request_digest);

        let recovery = journal
            .plan_recovery(
                "activation",
                &request_digest,
                &RecoveryContext {
                    authority: AuthorityAvailability::Available(digest("authority")),
                    effect: EffectFactState::Missing,
                    attempts_used: 1,
                    observed_at_ms: 1_100,
                    revocation_pending: true,
                },
            )
            .expect("classify revocation during activation");
        assert_eq!(
            recovery,
            RecoveryPlan::ContainmentRequired {
                reason: ContainmentReason::RevocationDuringActivation
            }
        );

        journal
            .append(
                "activation",
                &request_digest,
                TransactionStage::RollbackIntentRecorded,
                evidence(&request_digest, StageCause::Revocation),
            )
            .expect("record rollback before any further activation");
        assert!(matches!(
            journal.append(
                "activation",
                &request_digest,
                TransactionStage::ActivationEffectCommitted,
                evidence(&request_digest, StageCause::Normal),
            ),
            Err(M6TransactionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn recovery_fails_closed_for_ambiguous_missing_or_conflicting_effects() {
        let directory = TestDirectory::new("effect-classification");
        let root = directory.child("journal");
        let journal = open(&root, Arc::new(DeterministicClock::new(1_000)));
        let request = draft(TransactionKind::ReceiverIntake, "effect", "effect-key");
        let before = request.before_snapshot_digest.clone();
        let after = request.expected_after_snapshot_digest.clone();
        let request_digest = journal
            .begin(request, initial_evidence())
            .expect("begin effect transaction")
            .request_digest;
        advance_receiver_to_activation(&journal, "effect", &request_digest);

        let base_context = RecoveryContext {
            authority: AuthorityAvailability::Available(digest("authority")),
            effect: EffectFactState::Conflicting(vec![digest("fact-a"), digest("fact-b")]),
            attempts_used: 1,
            observed_at_ms: 1_100,
            revocation_pending: false,
        };
        assert_eq!(
            journal
                .plan_recovery("effect", &request_digest, &base_context)
                .expect("classify conflicting effect"),
            RecoveryPlan::ContainmentRequired {
                reason: ContainmentReason::ConflictingEffectFact
            }
        );

        let mut ambiguous = base_context.clone();
        ambiguous.effect = EffectFactState::Ambiguous(vec![digest("uncertain-fact")]);
        assert_eq!(
            journal
                .plan_recovery("effect", &request_digest, &ambiguous)
                .expect("classify ambiguous effect"),
            RecoveryPlan::ContainmentRequired {
                reason: ContainmentReason::AmbiguousEffectFact
            }
        );

        journal
            .append(
                "effect",
                &request_digest,
                TransactionStage::ActivationEffectCommitted,
                evidence(&request_digest, StageCause::Normal),
            )
            .expect("record committed activation");
        let mut missing = base_context.clone();
        missing.effect = EffectFactState::Missing;
        assert_eq!(
            journal
                .plan_recovery("effect", &request_digest, &missing)
                .expect("classify missing committed fact"),
            RecoveryPlan::ContainmentRequired {
                reason: ContainmentReason::MissingCommittedEffectFact
            }
        );

        let fact = AuthoritativeEffectFact::new(
            request_digest.clone(),
            "effect-key".to_string(),
            TransactionStage::ActivationEffectCommitted,
            before.clone(),
            after,
            digest("effect-receipt"),
            digest("effect-attestation"),
        )
        .expect("authoritative effect fact");
        let expected_fact_digest = fact.fact_digest.clone();
        let mut committed = base_context.clone();
        committed.effect = EffectFactState::Committed(fact);
        assert_eq!(
            journal
                .plan_recovery("effect", &request_digest, &committed)
                .expect("classify exact committed effect"),
            RecoveryPlan::VerifyCommittedEffect {
                fact_digest: expected_fact_digest,
                effect_stage: TransactionStage::ActivationEffectCommitted,
            }
        );

        let mismatched = AuthoritativeEffectFact::new(
            request_digest.clone(),
            "effect-key".to_string(),
            TransactionStage::ActivationEffectCommitted,
            before,
            digest("wrong-after"),
            digest("effect-receipt"),
            digest("effect-attestation"),
        )
        .expect("well-formed but mismatched fact");
        let mut mismatch_context = base_context;
        mismatch_context.effect = EffectFactState::Committed(mismatched);
        assert_eq!(
            journal
                .plan_recovery("effect", &request_digest, &mismatch_context,)
                .expect("classify mismatched effect"),
            RecoveryPlan::ContainmentRequired {
                reason: ContainmentReason::MismatchedEffectBinding
            }
        );
    }
}
