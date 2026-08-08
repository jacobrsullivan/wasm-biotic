//! Bounded receiver-side M6 orchestration over the ordinary M5 cycle law.
//!
//! This module owns coordination only. Raw admission and replay remain in
//! [`crate::m6_identity`], authorization and approval remain in
//! [`crate::m6_authority`], package verification/proving/planning remain in
//! [`crate::m6_import`], revocation remains in [`crate::m6_revocation`], and
//! M5 remains the sole owner of the active-package pointer.

use crate::execution::artifact::{ContentDigest, digest_json_content};
use crate::execution::component::execute_component_i32_export;
use crate::factory_reproduction::{
    ApprovalDecision, CycleOutcome, FactoryPackage, LiveProviderQualificationPort,
    OperatorRollbackRecord,
};
use crate::m1_validation::ValidationSuite;
use crate::m5_effect_port::{M5EffectAuditKind, M5EffectAuditReport};
use crate::m5_effect_store::FactoryRuntimeSnapshot;
use crate::m5_runtime::{
    M5ActiveExecution, M5ExactCandidateCyclePlan, M5ExactCandidateCycleResult,
    M5PostRollbackProbeV1, M5Runtime, M5RuntimeConfig,
};
use crate::m6_authority::{
    ActionAuthorization, ApprovalDecisionIntent, ApprovalDecisionKind, ApprovalDecisionRecord,
    ApprovalRequest, ApprovalRequestDraft, AuthorityAction, AuthorizationConsumption,
    AuthorizationStore, EndpointActionProfile, EndpointAuthorityKind, ExactActionBinding,
    M6AuthorityError, OpaqueAuthorizationVerifier,
};
use crate::m6_identity::{
    Clock, FactorySigner, GovernedFilesystemSpool, IDENTITY_MUTABLE_TOP_LEVEL_DIRECTORIES,
    IssuedManifest, M6IdentityError, ManifestIssuer, ManifestKind, ManifestPayload, NonceSource,
    PreparedIssuanceResolution, RawAdmissionOutcome, RawAdmissionRejected, RawQuarantineRecord,
    ReceiverAcknowledgementPayload, ReceiverRawQuarantine, ReplayCommitFact,
    ReplayCommitResolution, ReplayControlStateV1, ReplayJournal, RouteDefinition,
    RouteEndpointRole, SignedManifest, TerminalNegativeDisposition, TerminalNegativeReason,
    TerminalNegativeRecord, TerminalNegativeResolution,
    verify_receiver_control_rejection_signature, verify_receiver_intake_completion_signature,
    verify_receiver_quarantine_inventory_signature, verify_receiver_reopen_audit_signature,
    verify_receiver_replay_control_signature, verify_receiver_revocation_completion_signature,
};
use crate::m6_import::{
    M6ImportError, ReceiverActiveStateV1, ReceiverCompatibilityDecisionV1,
    ReceiverCompatibilityIssue, ReceiverImportPlanV1, ReceiverImportPolicyV1,
    ReceiverProvingReportV1, VerifiedQuarantinedExportV1, assess_receiver_compatibility,
    derive_receiver_import_plan, prove_quarantined_import, verify_quarantined_export,
};
use crate::m6_revocation::{
    ExchangeRevocationBindingV1, M6RevocationError, ReceiverImportDispositionV1,
    ReceiverRevocationLedger, RequiredContainmentActionV1, RevocationAffectedImportV1,
    RevocationContainmentOutcomeV1, RevocationContainmentResolutionV1, RevocationTombstoneV1,
};
use crate::m6_revocation_sender_runtime::SenderRevocationPublicationEvidenceV1;
use crate::m6_transactions::{
    CoordinatorJournal, JournalConfig, M6TransactionError, RetryPolicy, StageCause, StageEvidence,
    TransactionKind, TransactionProjection, TransactionRequestDraft, TransactionStage,
    TransactionStageRecord,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub const RECEIVER_INTAKE_REQUEST_SCHEMA: &str = "wasm-biotic.m6-receiver-intake-request.v1";
pub const RECEIVER_INTAKE_REQUEST_COMMIT_SCHEMA: &str =
    "wasm-biotic.m6-receiver-intake-request-commit.v1";
pub const RECEIVER_VALIDATION_REJECTION_SCHEMA: &str =
    "wasm-biotic.m6-receiver-validation-rejection.v1";
pub const RECEIVER_M5_CYCLE_EVIDENCE_SCHEMA: &str = "wasm-biotic.m6-receiver-m5-cycle-evidence.v1";
pub const RECEIVER_M5_PRE_ACTIVATION_PROBE_SCHEMA: &str =
    "wasm-biotic.m6-receiver-m5-pre-activation-probe.v1";
pub const RECEIVER_M5_BEHAVIOR_CHANGE_EVIDENCE_SCHEMA: &str =
    "wasm-biotic.m6-receiver-m5-behavior-change-evidence.v1";
pub const RECEIVER_ADOPTION_RECEIPT_SCHEMA: &str = "wasm-biotic.m6-receiver-adoption-receipt.v1";
pub const RECEIVER_TERMINAL_DECISION_SCHEMA: &str = "wasm-biotic.m6-receiver-terminal-decision.v1";
pub const RECEIVER_ACK_REQUEST_SCHEMA: &str = "wasm-biotic.m6-receiver-ack-request.v1";
pub const RECEIVER_ACK_RECEIPT_SCHEMA: &str = "wasm-biotic.m6-receiver-ack-receipt.v1";
pub const RECEIVER_REVOCATION_REQUEST_SCHEMA: &str =
    "wasm-biotic.m6-receiver-revocation-request.v1";
pub const RECEIVER_REVOCATION_MATCH_SET_SCHEMA: &str =
    "wasm-biotic.m6-receiver-revocation-match-set.v1";
pub const RECEIVER_REVOCATION_REJECTION_SCHEMA: &str =
    "wasm-biotic.m6-receiver-revocation-rejection.v1";
pub const RECEIVER_REVOCATION_RECEIPT_SCHEMA: &str =
    "wasm-biotic.m6-receiver-revocation-receipt.v1";
pub const RECEIVER_EXCHANGE_COMPLETION_EVIDENCE_SCHEMA: &str =
    "wasm-biotic.m6-receiver-exchange-completion-evidence.v1";
pub const RECEIVER_REPLAY_CONTROL_PROOF_SCHEMA: &str =
    "wasm-biotic.m6-receiver-replay-control-proof.v1";
pub const RECEIVER_UNRESOLVED_QUARANTINE_INVENTORY_SCHEMA: &str =
    "wasm-biotic.m6-receiver-unresolved-quarantine-inventory.v1";
pub const RECEIVER_REOPEN_AUDIT_SCHEMA: &str = "wasm-biotic.m6-receiver-reopen-audit.v1";
pub const RECEIVER_REOPEN_PROOF_SCHEMA: &str = "wasm-biotic.m6-receiver-reopen-proof.v1";
pub const RECEIVER_AUTHENTICATED_MESSAGE_CLAIM_SCHEMA: &str =
    "wasm-biotic.m6-receiver-authenticated-message-claim.v1";
pub const RECEIVER_SIGNED_CONTROL_REJECTION_SCHEMA: &str =
    "wasm-biotic.m6-receiver-signed-control-rejection.v1";
pub const RECEIVER_COMPATIBILITY_CONTROL_REJECTION_SCHEMA: &str =
    "wasm-biotic.m6-receiver-compatibility-control-rejection.v1";
pub const RECEIVER_NEGATIVE_CONTROL_SUITE_SCHEMA: &str =
    "wasm-biotic.m6-receiver-negative-control-suite.v1";
pub const RECEIVER_REVOCATION_COMPLETION_EVIDENCE_SCHEMA: &str =
    "wasm-biotic.m6-receiver-revocation-completion-evidence.v1";

const REQUEST_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-intake-request:v1\0";
const REQUEST_COMMIT_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-intake-request-commit:v1\0";
const EXCHANGE_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-exchange:v1\0";
const PROSPECTIVE_AFTER_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-prospective-after:v1\0";
const UNKNOWN_SOURCE_PACKAGE_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-source-package-pending:v1\0";
const PROVING_REQUEST_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-proving-request:v1\0";
const PROMOTION_REQUEST_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-promotion-request:v1\0";
const OBSERVATION_REQUEST_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-observation-request:v1\0";
const ROLLBACK_REQUEST_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-rollback-request:v1\0";
const VALIDATION_REJECTION_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-validation-rejection:v1\0";
const REPLAY_FACT_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-replay-fact:v1\0";
const M5_CYCLE_EVIDENCE_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-m5-cycle-evidence:v1\0";
const M5_BEHAVIOR_CHANGE_EVIDENCE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-m5-behavior-change-evidence:v1\0";
const ADOPTION_RECEIPT_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-adoption-receipt:v1\0";
const TERMINAL_DECISION_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-terminal-decision:v1\0";
const ACK_REQUEST_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-ack-request:v1\0";
const ACK_RECEIPT_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-ack-receipt:v1\0";
const ACK_DELIVERY_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-ack-delivery:v1\0";
const REVOCATION_REQUEST_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-revocation-request:v1\0";
const REVOCATION_MATCH_SET_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-revocation-match-set:v1\0";
const REVOCATION_REJECTION_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-revocation-rejection:v1\0";
const REVOCATION_RECEIPT_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-revocation-receipt:v1\0";
const REVOCATION_EXCHANGE_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-revocation-exchange:v1\0";
const UNRESOLVED_RISKS_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-unresolved-risks:v1\0";
const COMPLETION_EVIDENCE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-exchange-completion-evidence:v1\0";
const COMPLETION_AUTHORITY_SOURCE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-completion-authority-source:v1\0";
const REPLAY_CONTROL_PROOF_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-replay-control-proof:v1\0";
const QUARANTINE_INVENTORY_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-unresolved-quarantine-inventory:v1\0";
const REOPEN_AUDIT_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-reopen-audit:v1\0";
const REOPEN_PROOF_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-reopen-proof:v1\0";
const DURABLE_STATE_ROOT_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-durable-state-root:v1\0";
const PROCESS_INSTANCE_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-process-instance:v1\0";
const MESSAGE_CLAIM_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-authenticated-message-claim:v1\0";
const CONTROL_REJECTION_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-signed-control-rejection:v1\0";
const COMPATIBILITY_CONTROL_REJECTION_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-compatibility-control-rejection:v1\0";
const NEGATIVE_CONTROL_SUITE_DOMAIN: &[u8] = b"wasm-biotic:m6:receiver-negative-control-suite:v1\0";
const REVOCATION_COMPLETION_EVIDENCE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-revocation-completion-evidence:v1\0";
const REVOCATION_AFFECTED_COMPLETION_SOURCE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-revocation-affected-completion-source:v1\0";
const NO_IMPORT_PLAN: &[u8] = b"wasm-biotic:m6:receiver:no-import-plan:v1";
const NO_PROVING: &[u8] = b"wasm-biotic:m6:receiver:no-proving:v1";
const NO_APPROVAL: &[u8] = b"wasm-biotic:m6:receiver:no-approval:v1";
const NO_MIGRATION: &[u8] = b"wasm-biotic:m6:receiver:no-migration:v1";

const OWNER_LOCK_FILE: &str = ".m6-receiver-endpoint.lock";
const INTAKE_AUTHORITY_DIRECTORY: &str = "m6-receiver-intake-authority";
const PROVING_AUTHORITY_DIRECTORY: &str = "m6-receiver-proving-authority";
const APPROVAL_AUTHORITY_DIRECTORY: &str = "m6-receiver-approval-authority";
const PROMOTION_AUTHORITY_DIRECTORY: &str = "m6-receiver-promotion-authority";
const OBSERVATION_AUTHORITY_DIRECTORY: &str = "m6-receiver-observation-authority";
const ROLLBACK_AUTHORITY_DIRECTORY: &str = "m6-receiver-rollback-authority";
const JOURNAL_DIRECTORY: &str = "m6-receiver-coordinator";
const REVOCATION_DIRECTORY: &str = "m6-receiver-revocations";
const OPERATIONS_DIRECTORY: &str = "m6-receiver-intakes";
const REVOCATION_OPERATIONS_DIRECTORY: &str = "m6-receiver-revocation-applications";
const REOPEN_AUDITS_DIRECTORY: &str = "m6-receiver-reopen-audits";
const MESSAGE_CLAIMS_DIRECTORY: &str = "m6-receiver-message-claims";
const CONTROL_REJECTIONS_DIRECTORY: &str = "m6-receiver-control-rejections";
const REQUEST_FILE: &str = "request.json";
const ACTIVE_STATE_FILE: &str = "active-state.json";
const REQUEST_COMMIT_FILE: &str = "commit.json";
const RAW_RECORD_FILE: &str = "raw-quarantine.json";
const VERIFIED_EXPORT_FILE: &str = "verified-export.json";
const COMPATIBILITY_FILE: &str = "compatibility.json";
const PROVING_FILE: &str = "proving.json";
const IMPORT_PLAN_FILE: &str = "import-plan.json";
const VALIDATION_REJECTION_FILE: &str = "validation-rejection.json";
const M5_CYCLE_FILE: &str = "m5-cycle-evidence.json";
const PRE_ACTIVATION_EXECUTION_FILE: &str = "pre-activation-execution.json";
const BEHAVIOR_CHANGE_FILE: &str = "m5-behavior-change-evidence.json";
const POST_ROLLBACK_PROBE_FILE: &str = "post-rollback-probe.json";
const ADOPTION_RECEIPT_FILE: &str = "adoption-receipt.json";
const TERMINAL_DECISION_FILE: &str = "terminal-decision.json";
const ACK_REQUEST_FILE: &str = "ack-request.json";
const ACK_RECEIPT_FILE: &str = "ack-receipt.json";
const REVOCATION_MATCH_SET_FILE: &str = "matched-imports.json";
const REVOCATION_REJECTION_FILE: &str = "revocation-rejection.json";
const REVOCATION_RECEIPT_FILE: &str = "revocation-receipt.json";

const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_REQUEST_BYTES: usize = 2 * 1_048_576;
const MAX_RECORD_BYTES: usize = 32 * 1_048_576;
const MAX_COMPLETION_EVIDENCE_BYTES: usize = 512 * 1_048_576;
const MAX_REOPEN_AUDIT_BYTES: usize = 32 * 1_048_576;
const MAX_DURABLE_STATE_ENTRIES: usize = 100_000;
const MAX_DURABLE_STATE_FILE_BYTES: usize = 256 * 1_048_576;
const MAX_DURABLE_STATE_AGGREGATE_BYTES: u64 = 4 * 1_073_741_824;
const BEHAVIOR_CHANGE_PROBE_INPUT: i32 = i32::MIN;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct M6ReceiverRuntimeConfig {
    pub endpoint_root: PathBuf,
    pub m5: M5RuntimeConfig,
    pub route_root: PathBuf,
    pub expected_route_definition_digest: ContentDigest,
    pub import_policy: ReceiverImportPolicyV1,
    pub intake_authorization_profile: EndpointActionProfile,
    pub proving_authorization_profile: EndpointActionProfile,
    pub approval_authorization_profile: EndpointActionProfile,
    pub promotion_authorization_profile: EndpointActionProfile,
    pub observation_authorization_profile: EndpointActionProfile,
    pub rollback_authorization_profile: EndpointActionProfile,
    pub journal_config: JournalConfig,
    pub retry_policy: RetryPolicy,
    pub max_intake_operations: u32,
}

impl M6ReceiverRuntimeConfig {
    fn validate_non_path_fields(&self) -> Result<(), M6ReceiverError> {
        self.m5
            .validate()
            .map_err(|error| M6ReceiverError::M5(error.to_string()))?;
        self.import_policy
            .validate()
            .map_err(|error| M6ReceiverError::Import(error.to_string()))?;
        self.journal_config
            .validate()
            .map_err(|error| M6ReceiverError::Transaction(error.to_string()))?;
        let profiles = [
            (
                &self.intake_authorization_profile,
                EndpointAuthorityKind::Intake,
                AuthorityAction::IntakePackage,
            ),
            (
                &self.proving_authorization_profile,
                EndpointAuthorityKind::Proving,
                AuthorityAction::ProveImport,
            ),
            (
                &self.approval_authorization_profile,
                EndpointAuthorityKind::Approval,
                AuthorityAction::GrantImportApproval,
            ),
            (
                &self.promotion_authorization_profile,
                EndpointAuthorityKind::Promotion,
                AuthorityAction::AdoptImport,
            ),
            (
                &self.observation_authorization_profile,
                EndpointAuthorityKind::Observation,
                AuthorityAction::ObserveImport,
            ),
            (
                &self.rollback_authorization_profile,
                EndpointAuthorityKind::Rollback,
                AuthorityAction::RollbackImport,
            ),
        ];
        if self.endpoint_root.as_os_str().is_empty()
            || self.route_root.as_os_str().is_empty()
            || self.max_intake_operations == 0
            || self.max_intake_operations > self.journal_config.max_transactions
            || self.journal_config.max_stages_per_transaction < 12
            || self.retry_policy.max_attempts == 0
            || self.retry_policy.max_attempts > 32
            || self.retry_policy.max_recovery_attempts > self.retry_policy.max_attempts
            || self.retry_policy.attempt_timeout_ms == 0
            || self.import_policy.receiver_factory_id() != self.m5.factory_id
            || profiles.iter().any(|(profile, kind, action)| {
                profile.authority_kind() != *kind
                    || !profile.supports(*action)
                    || profile.factory_id() != self.m5.factory_id
            })
        {
            return Err(M6ReceiverError::InvalidConfiguration(
                "receiver roots, bounds, policy, M5 identity, or authority profiles are invalid"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

pub struct ReceiverAuthorityVerifiers<V> {
    pub intake: V,
    pub proving: V,
    pub approval: V,
    pub promotion: V,
    pub observation: V,
    pub rollback: V,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverIntakeRequest {
    schema: String,
    logical_operation_id: String,
    principal_id: String,
    captured_at_ms: u64,
    deadline_ms: u64,
    route_id: String,
    route_generation: u64,
    route_definition_digest: ContentDigest,
    message_digest: ContentDigest,
    exchange_digest: ContentDigest,
    source_package_anchor_digest: ContentDigest,
    expected_active_package_digest: ContentDigest,
    expected_active_snapshot_digest: ContentDigest,
    active_state_digest: ContentDigest,
    policy_digest: ContentDigest,
    prospective_after_digest: ContentDigest,
    request_digest: ContentDigest,
}

impl ReceiverIntakeRequest {
    #[allow(clippy::too_many_arguments)]
    fn new(
        logical_operation_id: String,
        principal_id: String,
        captured_at_ms: u64,
        deadline_ms: u64,
        message_digest: ContentDigest,
        route: &RouteDefinition,
        active: &ReceiverActiveStateV1,
        policy: &ReceiverImportPolicyV1,
    ) -> Result<Self, M6ReceiverError> {
        validate_identifier("receiver intake operation id", &logical_operation_id)?;
        validate_identifier("receiver intake principal", &principal_id)?;
        let exchange_digest = digest_domain(
            EXCHANGE_DOMAIN,
            &(
                &logical_operation_id,
                &message_digest,
                &route.definition_digest,
                active.active_state_digest(),
                policy.policy_digest(),
            ),
        )?;
        let source_package_anchor_digest =
            digest_domain(UNKNOWN_SOURCE_PACKAGE_DOMAIN, &message_digest)?;
        let prospective_after_digest = digest_domain(
            PROSPECTIVE_AFTER_DOMAIN,
            &(
                &message_digest,
                active.active_state_digest(),
                policy.policy_digest(),
            ),
        )?;
        let mut request = Self {
            schema: RECEIVER_INTAKE_REQUEST_SCHEMA.to_string(),
            logical_operation_id,
            principal_id,
            captured_at_ms,
            deadline_ms,
            route_id: route.route_id.clone(),
            route_generation: route.generation,
            route_definition_digest: route.definition_digest.clone(),
            message_digest,
            exchange_digest,
            source_package_anchor_digest,
            expected_active_package_digest: active.snapshot().package_digest.clone(),
            expected_active_snapshot_digest: active.snapshot().snapshot_digest.clone(),
            active_state_digest: active.active_state_digest().clone(),
            policy_digest: policy.policy_digest().clone(),
            prospective_after_digest,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = request.expected_digest()?;
        request.validate(route, active, policy)?;
        Ok(request)
    }

    fn validate(
        &self,
        route: &RouteDefinition,
        active: &ReceiverActiveStateV1,
        policy: &ReceiverImportPolicyV1,
    ) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_INTAKE_REQUEST_SCHEMA
            || self.deadline_ms <= self.captured_at_ms
            || self.deadline_ms.saturating_sub(self.captured_at_ms) > 30 * 86_400_000
            || self.route_id != route.route_id
            || self.route_generation != route.generation
            || self.route_definition_digest != route.definition_digest
            || self.expected_active_package_digest != active.snapshot().package_digest
            || self.expected_active_snapshot_digest != active.snapshot().snapshot_digest
            || self.active_state_digest != *active.active_state_digest()
            || self.policy_digest != *policy.policy_digest()
        {
            return Err(M6ReceiverError::Integrity(
                "receiver intake request differs from its exact route, state, or policy"
                    .to_string(),
            ));
        }
        validate_identifier("receiver intake operation id", &self.logical_operation_id)?;
        validate_identifier("receiver intake principal", &self.principal_id)?;
        require_digest(
            "receiver exchange",
            &self.exchange_digest,
            &digest_domain(
                EXCHANGE_DOMAIN,
                &(
                    &self.logical_operation_id,
                    &self.message_digest,
                    &self.route_definition_digest,
                    &self.active_state_digest,
                    &self.policy_digest,
                ),
            )?,
        )?;
        require_digest(
            "pending source package",
            &self.source_package_anchor_digest,
            &digest_domain(UNKNOWN_SOURCE_PACKAGE_DOMAIN, &self.message_digest)?,
        )?;
        require_digest(
            "prospective after",
            &self.prospective_after_digest,
            &digest_domain(
                PROSPECTIVE_AFTER_DOMAIN,
                &(
                    &self.message_digest,
                    &self.active_state_digest,
                    &self.policy_digest,
                ),
            )?,
        )?;
        require_digest(
            "receiver intake request",
            &self.request_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REQUEST_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.principal_id,
                self.captured_at_ms,
                self.deadline_ms,
                &self.route_id,
                self.route_generation,
                &self.route_definition_digest,
                &self.message_digest,
                &self.exchange_digest,
                &self.source_package_anchor_digest,
                &self.expected_active_package_digest,
                &self.expected_active_snapshot_digest,
                &self.active_state_digest,
                &self.policy_digest,
                &self.prospective_after_digest,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverIntakeRequestCommit {
    schema: String,
    request_digest: ContentDigest,
    request_bytes_digest: ContentDigest,
    active_state_bytes_digest: ContentDigest,
    commit_digest: ContentDigest,
}

impl ReceiverIntakeRequestCommit {
    fn new(
        request: &ReceiverIntakeRequest,
        request_bytes: &[u8],
        active_state_bytes: &[u8],
    ) -> Result<Self, M6ReceiverError> {
        let mut commit = Self {
            schema: RECEIVER_INTAKE_REQUEST_COMMIT_SCHEMA.to_string(),
            request_digest: request.request_digest.clone(),
            request_bytes_digest: ContentDigest::from_bytes(request_bytes),
            active_state_bytes_digest: ContentDigest::from_bytes(active_state_bytes),
            commit_digest: ContentDigest::from_bytes(&[]),
        };
        commit.commit_digest = commit.expected_digest()?;
        Ok(commit)
    }

    fn validate(
        &self,
        request: &ReceiverIntakeRequest,
        request_bytes: &[u8],
        active_state_bytes: &[u8],
    ) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_INTAKE_REQUEST_COMMIT_SCHEMA
            || self.request_digest != request.request_digest
            || self.request_bytes_digest != ContentDigest::from_bytes(request_bytes)
            || self.active_state_bytes_digest != ContentDigest::from_bytes(active_state_bytes)
        {
            return Err(M6ReceiverError::Integrity(
                "receiver intake request commit is incomplete or cross-linked".to_string(),
            ));
        }
        require_digest(
            "receiver intake request commit",
            &self.commit_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REQUEST_COMMIT_DOMAIN,
            &(
                &self.schema,
                &self.request_digest,
                &self.request_bytes_digest,
                &self.active_state_bytes_digest,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedReceiverIntake {
    pub logical_operation_id: String,
    pub outer_request_digest: ContentDigest,
    pub coordinator_request_digest: ContentDigest,
    pub message_digest: ContentDigest,
    pub expected_active_snapshot_digest: ContentDigest,
    pub authorization_binding: ExactActionBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedReceiverProving {
    pub logical_operation_id: String,
    pub message_digest: ContentDigest,
    pub verified_export_digest: ContentDigest,
    pub compatibility_decision_digest: ContentDigest,
    pub source_package_digest: ContentDigest,
    pub authorization_binding: ExactActionBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedReceiverApproval {
    pub logical_operation_id: String,
    pub approval_request: ApprovalRequest,
    pub import_plan_digest: ContentDigest,
    pub receiver_local_package_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedReceiverDecision {
    pub logical_operation_id: String,
    pub approval_request_digest: ContentDigest,
    pub decision_intent: ApprovalDecisionIntent,
    pub authorization_binding: ExactActionBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedReceiverPromotion {
    pub logical_operation_id: String,
    pub approval_decision_digest: ContentDigest,
    pub import_plan_digest: ContentDigest,
    pub receiver_local_package_digest: ContentDigest,
    pub authorization_binding: ExactActionBinding,
    pub observation_authorization_binding: ExactActionBinding,
    pub rollback_authorization_binding: ExactActionBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiverAdmissionResult {
    AwaitingProving(PreparedReceiverProving),
    RawAdmissionRejected(RawAdmissionRejected),
    ValidationRejected(ReceiverValidationRejection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiverProvingResult {
    AwaitingApproval(PreparedReceiverApproval),
    ValidationRejected(ReceiverValidationRejection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiverApprovalResult {
    ReadyForPromotion(PreparedReceiverPromotion),
    Terminal(ReceiverTerminalDecision),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiverAdoptionResult {
    Adopted(ReceiverAdoptionReceipt),
    ValidationRejected(ReceiverValidationRejection),
    Terminal(ReceiverTerminalDecision),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverTerminalKind {
    ValidationRejected,
    Denied,
    Expired,
    Escalated,
    RevokedBeforePromotion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverValidationRejection {
    pub schema: String,
    pub logical_operation_id: String,
    pub outer_request_digest: ContentDigest,
    pub message_digest: ContentDigest,
    pub raw_quarantine_digest: ContentDigest,
    pub authenticated: bool,
    pub policy_rule: String,
    pub detail: String,
    pub evidence_refs: Vec<ContentDigest>,
    pub rejected_at_ms: u64,
    pub record_digest: ContentDigest,
}

impl ReceiverValidationRejection {
    fn new(
        request: &ReceiverIntakeRequest,
        raw: &RawQuarantineRecord,
        authenticated: bool,
        policy_rule: impl Into<String>,
        detail: impl Into<String>,
        mut evidence_refs: Vec<ContentDigest>,
        rejected_at_ms: u64,
    ) -> Result<Self, M6ReceiverError> {
        evidence_refs.sort();
        evidence_refs.dedup();
        let mut record = Self {
            schema: RECEIVER_VALIDATION_REJECTION_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            outer_request_digest: request.request_digest.clone(),
            message_digest: request.message_digest.clone(),
            raw_quarantine_digest: raw.raw_unit_digest.clone(),
            authenticated,
            policy_rule: policy_rule.into(),
            detail: detail.into().chars().take(4_096).collect(),
            evidence_refs,
            rejected_at_ms,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        record.validate_fields()?;
        record.record_digest = record.expected_digest()?;
        Ok(record)
    }

    fn validate_fields(&self) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_VALIDATION_REJECTION_SCHEMA
            || self.detail.is_empty()
            || self.detail.len() > 4_096
            || self.evidence_refs.is_empty()
            || self.evidence_refs.len() > 256
            || !is_strictly_sorted_unique(&self.evidence_refs)
        {
            return Err(M6ReceiverError::Integrity(
                "receiver validation rejection is outside its bounded schema".to_string(),
            ));
        }
        validate_identifier("receiver validation policy rule", &self.policy_rule)
    }

    fn validate(
        &self,
        request: &ReceiverIntakeRequest,
        raw: &RawQuarantineRecord,
    ) -> Result<(), M6ReceiverError> {
        self.validate_fields()?;
        if self.logical_operation_id != request.logical_operation_id
            || self.outer_request_digest != request.request_digest
            || self.message_digest != request.message_digest
            || self.raw_quarantine_digest != raw.raw_unit_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver validation rejection is cross-linked".to_string(),
            ));
        }
        require_digest(
            "receiver validation rejection",
            &self.record_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            VALIDATION_REJECTION_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.outer_request_digest,
                &self.message_digest,
                &self.raw_quarantine_digest,
                self.authenticated,
                &self.policy_rule,
                &self.detail,
                &self.evidence_refs,
                self.rejected_at_ms,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverTerminalDecision {
    pub schema: String,
    pub logical_operation_id: String,
    pub outer_request_digest: ContentDigest,
    pub message_digest: ContentDigest,
    pub kind: ReceiverTerminalKind,
    pub approval_request_digest: Option<ContentDigest>,
    pub approval_decision_digest: Option<ContentDigest>,
    pub evidence_digest: ContentDigest,
    pub recorded_at_ms: u64,
    pub record_digest: ContentDigest,
}

impl ReceiverTerminalDecision {
    fn new(
        request: &ReceiverIntakeRequest,
        kind: ReceiverTerminalKind,
        approval_request_digest: Option<ContentDigest>,
        approval_decision_digest: Option<ContentDigest>,
        evidence_digest: ContentDigest,
        recorded_at_ms: u64,
    ) -> Result<Self, M6ReceiverError> {
        let mut record = Self {
            schema: RECEIVER_TERMINAL_DECISION_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            outer_request_digest: request.request_digest.clone(),
            message_digest: request.message_digest.clone(),
            kind,
            approval_request_digest,
            approval_decision_digest,
            evidence_digest,
            recorded_at_ms,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        record.record_digest = record.expected_digest()?;
        Ok(record)
    }

    fn validate(&self, request: &ReceiverIntakeRequest) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_TERMINAL_DECISION_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.outer_request_digest != request.request_digest
            || self.message_digest != request.message_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver terminal decision is cross-linked".to_string(),
            ));
        }
        require_digest(
            "receiver terminal decision",
            &self.record_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            TERMINAL_DECISION_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.outer_request_digest,
                &self.message_digest,
                self.kind,
                &self.approval_request_digest,
                &self.approval_decision_digest,
                &self.evidence_digest,
                self.recorded_at_ms,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverAcknowledgementRequest {
    schema: String,
    logical_operation_id: String,
    disposition: String,
    intake_record_digest: ContentDigest,
    raw_quarantine_digest: ContentDigest,
    receiver_transaction_digest: ContentDigest,
    sender_message_digest: ContentDigest,
    message_lifetime_ms: u64,
    issuance_idempotency_key: String,
    request_digest: ContentDigest,
}

impl ReceiverAcknowledgementRequest {
    #[allow(clippy::too_many_arguments)]
    fn new_for_context(
        logical_operation_id: &str,
        intake_record_digest: ContentDigest,
        sender_message_digest: ContentDigest,
        disposition: impl Into<String>,
        raw_quarantine_digest: ContentDigest,
        receiver_transaction_digest: ContentDigest,
        message_lifetime_ms: u64,
    ) -> Result<Self, M6ReceiverError> {
        let mut record = Self {
            schema: RECEIVER_ACK_REQUEST_SCHEMA.to_string(),
            logical_operation_id: logical_operation_id.to_string(),
            disposition: disposition.into(),
            intake_record_digest,
            raw_quarantine_digest,
            receiver_transaction_digest,
            sender_message_digest,
            message_lifetime_ms,
            issuance_idempotency_key: format!("receiver-ack:{logical_operation_id}"),
            request_digest: ContentDigest::from_bytes(&[]),
        };
        record.validate_fields()?;
        record.request_digest = record.expected_digest()?;
        Ok(record)
    }

    fn validate_fields(&self) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_ACK_REQUEST_SCHEMA || self.message_lifetime_ms == 0 {
            return Err(M6ReceiverError::Integrity(
                "receiver acknowledgement request is outside its bounded schema".to_string(),
            ));
        }
        validate_identifier(
            "receiver acknowledgement operation id",
            &self.logical_operation_id,
        )?;
        validate_identifier("receiver acknowledgement disposition", &self.disposition)?;
        validate_identifier(
            "receiver acknowledgement idempotency key",
            &self.issuance_idempotency_key,
        )
    }

    fn validate(
        &self,
        request: &ReceiverIntakeRequest,
        route: &RouteDefinition,
    ) -> Result<(), M6ReceiverError> {
        self.validate_for_context(
            &request.logical_operation_id,
            &request.request_digest,
            &request.message_digest,
            route,
        )
    }

    fn validate_for_context(
        &self,
        logical_operation_id: &str,
        intake_record_digest: &ContentDigest,
        sender_message_digest: &ContentDigest,
        route: &RouteDefinition,
    ) -> Result<(), M6ReceiverError> {
        self.validate_fields()?;
        if self.logical_operation_id != logical_operation_id
            || &self.intake_record_digest != intake_record_digest
            || &self.sender_message_digest != sender_message_digest
            || self.message_lifetime_ms > route.resource_profile.max_message_lifetime_ms
        {
            return Err(M6ReceiverError::Integrity(
                "receiver acknowledgement request is cross-linked".to_string(),
            ));
        }
        require_digest(
            "receiver acknowledgement request",
            &self.request_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            ACK_REQUEST_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.disposition,
                &self.intake_record_digest,
                &self.raw_quarantine_digest,
                &self.receiver_transaction_digest,
                &self.sender_message_digest,
                self.message_lifetime_ms,
                &self.issuance_idempotency_key,
            ),
        )
    }

    fn payload(&self) -> ManifestPayload {
        ManifestPayload::ReceiverAcknowledgement(ReceiverAcknowledgementPayload {
            disposition: self.disposition.clone(),
            intake_record_digest: self.intake_record_digest.clone(),
            raw_quarantine_digest: self.raw_quarantine_digest.clone(),
            receiver_transaction_digest: self.receiver_transaction_digest.clone(),
            sender_message_digest: self.sender_message_digest.clone(),
        })
    }
}

/// Receiver-signed route receipt for one disposition. This acknowledges only
/// intake disposition; it is not proof that adoption occurred.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverAcknowledgementReceipt {
    pub schema: String,
    pub logical_operation_id: String,
    pub acknowledgement_request_digest: ContentDigest,
    pub receiver_transaction_digest: ContentDigest,
    pub sender_message_digest: ContentDigest,
    pub acknowledgement_message_digest: ContentDigest,
    pub acknowledgement_sequence: u64,
    pub issuance_request_digest: ContentDigest,
    pub ready_delivery_digest: ContentDigest,
    pub disposition: String,
    pub recorded_at_ms: u64,
    pub receipt_digest: ContentDigest,
}

impl ReceiverAcknowledgementReceipt {
    fn new(
        request: &ReceiverAcknowledgementRequest,
        issued: &IssuedManifest,
        issuance_request_digest: ContentDigest,
        ready_delivery_digest: ContentDigest,
        recorded_at_ms: u64,
    ) -> Result<Self, M6ReceiverError> {
        let mut receipt = Self {
            schema: RECEIVER_ACK_RECEIPT_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            acknowledgement_request_digest: request.request_digest.clone(),
            receiver_transaction_digest: request.receiver_transaction_digest.clone(),
            sender_message_digest: request.sender_message_digest.clone(),
            acknowledgement_message_digest: issued.manifest.message_digest.clone(),
            acknowledgement_sequence: issued.manifest.unsigned.sequence,
            issuance_request_digest,
            ready_delivery_digest,
            disposition: request.disposition.clone(),
            recorded_at_ms,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        Ok(receipt)
    }

    fn validate(
        &self,
        request: &ReceiverAcknowledgementRequest,
        issued: &IssuedManifest,
        route: &RouteDefinition,
        issuance_request_digest: &ContentDigest,
        ready_delivery_digest: &ContentDigest,
    ) -> Result<(), M6ReceiverError> {
        validate_ack_issued(request, issued, route)?;
        if self.schema != RECEIVER_ACK_RECEIPT_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.acknowledgement_request_digest != request.request_digest
            || self.receiver_transaction_digest != request.receiver_transaction_digest
            || self.sender_message_digest != request.sender_message_digest
            || self.acknowledgement_message_digest != issued.manifest.message_digest
            || self.acknowledgement_sequence != issued.manifest.unsigned.sequence
            || &self.issuance_request_digest != issuance_request_digest
            || &self.ready_delivery_digest != ready_delivery_digest
            || self.disposition != request.disposition
        {
            return Err(M6ReceiverError::Integrity(
                "receiver acknowledgement receipt is cross-linked".to_string(),
            ));
        }
        require_digest(
            "receiver acknowledgement receipt",
            &self.receipt_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            ACK_RECEIPT_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.acknowledgement_request_digest,
                &self.receiver_transaction_digest,
                &self.sender_message_digest,
                &self.acknowledgement_message_digest,
                self.acknowledgement_sequence,
                &self.issuance_request_digest,
                &self.ready_delivery_digest,
                &self.disposition,
                self.recorded_at_ms,
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverInboundTransactionKindV1 {
    Import,
    Revocation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverAuthenticatedMessageClaimV1 {
    schema: String,
    transaction_kind: ReceiverInboundTransactionKindV1,
    logical_operation_id: String,
    outer_request_digest: ContentDigest,
    message_digest: ContentDigest,
    raw_quarantine_digest: ContentDigest,
    route_definition_digest: ContentDigest,
    claimed_at_ms: u64,
    claim_digest: ContentDigest,
}

impl ReceiverAuthenticatedMessageClaimV1 {
    pub fn transaction_kind(&self) -> ReceiverInboundTransactionKindV1 {
        self.transaction_kind
    }

    pub fn logical_operation_id(&self) -> &str {
        &self.logical_operation_id
    }

    pub fn outer_request_digest(&self) -> &ContentDigest {
        &self.outer_request_digest
    }

    pub fn message_digest(&self) -> &ContentDigest {
        &self.message_digest
    }

    pub fn claim_digest(&self) -> &ContentDigest {
        &self.claim_digest
    }

    pub fn canonical_bytes(&self, route: &RouteDefinition) -> Result<Vec<u8>, M6ReceiverError> {
        self.validate(route)?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6ReceiverError> {
        let claim: Self = parse_canonical(bytes, MAX_RECORD_BYTES)?;
        claim.validate(route)?;
        Ok(claim)
    }

    fn new(
        transaction_kind: ReceiverInboundTransactionKindV1,
        logical_operation_id: String,
        outer_request_digest: ContentDigest,
        message_digest: ContentDigest,
        raw_quarantine_digest: ContentDigest,
        route: &RouteDefinition,
        claimed_at_ms: u64,
    ) -> Result<Self, M6ReceiverError> {
        let mut claim = Self {
            schema: RECEIVER_AUTHENTICATED_MESSAGE_CLAIM_SCHEMA.to_string(),
            transaction_kind,
            logical_operation_id,
            outer_request_digest,
            message_digest,
            raw_quarantine_digest,
            route_definition_digest: route.definition_digest.clone(),
            claimed_at_ms,
            claim_digest: ContentDigest::from_bytes(&[]),
        };
        claim.claim_digest = claim.expected_digest()?;
        claim.validate(route)?;
        Ok(claim)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_AUTHENTICATED_MESSAGE_CLAIM_SCHEMA
            || self.route_definition_digest != route.definition_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver authenticated-message claim belongs to another route".to_string(),
            ));
        }
        validate_identifier(
            "receiver authenticated-message claim operation id",
            &self.logical_operation_id,
        )?;
        require_digest(
            "receiver authenticated-message claim",
            &self.claim_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            MESSAGE_CLAIM_DOMAIN,
            &(
                &self.schema,
                self.transaction_kind,
                &self.logical_operation_id,
                &self.outer_request_digest,
                &self.message_digest,
                &self.raw_quarantine_digest,
                &self.route_definition_digest,
                self.claimed_at_ms,
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverControlPlaneV1 {
    Authentication,
    Replay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverControlRejectionClassV1 {
    RawAdmission,
    CanonicalManifest,
    MessageIdentity,
    RouteAuthentication,
    SequenceReplay,
    SequenceGap,
    ChainConflict,
    NonceReplay,
    MessageReplay,
}

impl ReceiverControlRejectionClassV1 {
    pub fn control_plane(self) -> ReceiverControlPlaneV1 {
        match self {
            Self::RawAdmission
            | Self::CanonicalManifest
            | Self::MessageIdentity
            | Self::RouteAuthentication => ReceiverControlPlaneV1::Authentication,
            Self::SequenceReplay
            | Self::SequenceGap
            | Self::ChainConflict
            | Self::NonceReplay
            | Self::MessageReplay => ReceiverControlPlaneV1::Replay,
        }
    }
}

/// Receiver-signed durable evidence that one hostile or replaying input was
/// rejected. Authentication and replay variants share storage but remain
/// semantically disjoint through the mandatory typed class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverSignedControlRejectionV1 {
    schema: String,
    control_plane: ReceiverControlPlaneV1,
    class: ReceiverControlRejectionClassV1,
    logical_operation_id: String,
    outer_request_digest: ContentDigest,
    message_digest: ContentDigest,
    raw_evidence_digest: ContentDigest,
    route_definition_digest: ContentDigest,
    signing_key_id: String,
    attempted_manifest_bytes: Option<Vec<u8>>,
    raw_admission_rejection_bytes: Option<Vec<u8>>,
    raw_quarantine_record_bytes: Option<Vec<u8>>,
    raw_unit_files: Option<BTreeMap<String, Vec<u8>>>,
    existing_message_claim_bytes: Option<Vec<u8>>,
    prior_replay_state: ReplayControlStateV1,
    post_replay_state: ReplayControlStateV1,
    detail: String,
    recorded_at_ms: u64,
    record_digest: ContentDigest,
    signature_hex: String,
}

impl ReceiverSignedControlRejectionV1 {
    pub fn control_plane(&self) -> ReceiverControlPlaneV1 {
        self.control_plane
    }

    pub fn class(&self) -> ReceiverControlRejectionClassV1 {
        self.class
    }

    pub fn logical_operation_id(&self) -> &str {
        &self.logical_operation_id
    }

    pub fn message_digest(&self) -> &ContentDigest {
        &self.message_digest
    }

    pub fn record_digest(&self) -> &ContentDigest {
        &self.record_digest
    }

    pub fn canonical_bytes(&self, route: &RouteDefinition) -> Result<Vec<u8>, M6ReceiverError> {
        self.validate(route)?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6ReceiverError> {
        let rejection: Self = parse_canonical(bytes, MAX_RECORD_BYTES)?;
        rejection.validate(route)?;
        Ok(rejection)
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        class: ReceiverControlRejectionClassV1,
        logical_operation_id: String,
        outer_request_digest: ContentDigest,
        message_digest: ContentDigest,
        raw_evidence_digest: ContentDigest,
        route: &RouteDefinition,
        signer: &FactorySigner,
        attempted_manifest_bytes: Option<Vec<u8>>,
        raw_admission_rejection_bytes: Option<Vec<u8>>,
        raw_quarantine_record_bytes: Option<Vec<u8>>,
        raw_unit_files: Option<BTreeMap<String, Vec<u8>>>,
        existing_message_claim_bytes: Option<Vec<u8>>,
        prior_replay_state: ReplayControlStateV1,
        post_replay_state: ReplayControlStateV1,
        detail: String,
        recorded_at_ms: u64,
    ) -> Result<Self, M6ReceiverError> {
        let mut rejection = Self {
            schema: RECEIVER_SIGNED_CONTROL_REJECTION_SCHEMA.to_string(),
            control_plane: class.control_plane(),
            class,
            logical_operation_id,
            outer_request_digest,
            message_digest,
            raw_evidence_digest,
            route_definition_digest: route.definition_digest.clone(),
            signing_key_id: signer.signing_key_id().to_string(),
            attempted_manifest_bytes,
            raw_admission_rejection_bytes,
            raw_quarantine_record_bytes,
            raw_unit_files,
            existing_message_claim_bytes,
            prior_replay_state,
            post_replay_state,
            detail: detail.chars().take(4_096).collect(),
            recorded_at_ms,
            record_digest: ContentDigest::from_bytes(&[]),
            signature_hex: String::new(),
        };
        rejection.record_digest = rejection.expected_digest()?;
        rejection.signature_hex = signer
            .sign_receiver_control_rejection(route, &rejection.record_digest)
            .map_err(|error| M6ReceiverError::Identity(error.to_string()))?;
        rejection.validate(route)?;
        Ok(rejection)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_SIGNED_CONTROL_REJECTION_SCHEMA
            || self.control_plane != self.class.control_plane()
            || self.route_definition_digest != route.definition_digest
            || self.signing_key_id != route.receiver.signing_key_id
            || self.detail.is_empty()
            || self.detail.len() > 4_096
            || self.prior_replay_state.route_definition_digest != route.definition_digest
            || self.post_replay_state.route_definition_digest != route.definition_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver control rejection is outside its exact route schema".to_string(),
            ));
        }
        validate_identifier(
            "receiver control-rejection operation id",
            &self.logical_operation_id,
        )?;
        if self.class == ReceiverControlRejectionClassV1::RawAdmission {
            if self.raw_quarantine_record_bytes.is_some() || self.raw_unit_files.is_some() {
                return Err(M6ReceiverError::Integrity(
                    "raw-admission rejection cannot claim committed quarantine bytes".to_string(),
                ));
            }
        } else {
            let raw_bytes = self.raw_quarantine_record_bytes.as_deref().ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "post-admission control rejection lacks its raw quarantine record".to_string(),
                )
            })?;
            let files = self.raw_unit_files.as_ref().ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "post-admission control rejection lacks exact raw-unit bytes".to_string(),
                )
            })?;
            let raw = RawQuarantineRecord::from_canonical_bytes(raw_bytes, route)?;
            validate_portable_raw_unit_files(&raw, files)?;
            let source_is_current_operation = raw.intake_operation_id == self.logical_operation_id;
            let source_is_existing_claim =
                if self.class == ReceiverControlRejectionClassV1::MessageReplay {
                    self.existing_message_claim_bytes
                        .as_deref()
                        .map(|bytes| {
                            ReceiverAuthenticatedMessageClaimV1::from_canonical_bytes(bytes, route)
                        })
                        .transpose()?
                        .is_some_and(|claim| {
                            claim.logical_operation_id == raw.intake_operation_id
                                && claim.raw_quarantine_digest == raw.raw_unit_digest
                                && claim.message_digest == self.message_digest
                        })
                } else {
                    false
                };
            if (!source_is_current_operation && !source_is_existing_claim)
                || raw.raw_unit_digest != self.raw_evidence_digest
                || self.attempted_manifest_bytes.as_ref() != files.get("manifest.json")
            {
                return Err(M6ReceiverError::Integrity(
                    "post-admission control rejection differs from immutable quarantine bytes"
                        .to_string(),
                ));
            }
        }
        match self.control_plane {
            ReceiverControlPlaneV1::Replay => {
                if self.prior_replay_state != self.post_replay_state
                    || self.attempted_manifest_bytes.is_none()
                    || self.raw_admission_rejection_bytes.is_some()
                {
                    return Err(M6ReceiverError::Integrity(
                        "replay rejection must prove an unchanged replay state and exact manifest"
                            .to_string(),
                    ));
                }
                let manifest = SignedManifest::from_canonical_bytes(
                    self.attempted_manifest_bytes.as_deref().unwrap_or_default(),
                )?;
                manifest.verify_route(route)?;
                if manifest.message_digest != self.message_digest {
                    return Err(M6ReceiverError::Integrity(
                        "replay rejection differs from its attempted message".to_string(),
                    ));
                }
            }
            ReceiverControlPlaneV1::Authentication => {
                if self.class == ReceiverControlRejectionClassV1::RawAdmission {
                    let bytes = self
                        .raw_admission_rejection_bytes
                        .as_deref()
                        .ok_or_else(|| {
                            M6ReceiverError::Integrity(
                                "raw-admission control rejection lacks its exact capsule"
                                    .to_string(),
                            )
                        })?;
                    let rejected: RawAdmissionRejected = parse_canonical(bytes, MAX_RECORD_BYTES)?;
                    rejected.validate(route)?;
                    if rejected.intake_operation_id != self.logical_operation_id
                        || rejected.record_digest != self.raw_evidence_digest
                    {
                        return Err(M6ReceiverError::Integrity(
                            "raw-admission control rejection is cross-linked".to_string(),
                        ));
                    }
                } else {
                    let attempted = self.attempted_manifest_bytes.as_deref().ok_or_else(|| {
                        M6ReceiverError::Integrity(
                            "manifest authentication rejection lacks attempted bytes".to_string(),
                        )
                    })?;
                    match self.class {
                        ReceiverControlRejectionClassV1::CanonicalManifest => {
                            if SignedManifest::from_canonical_bytes(attempted).is_ok() {
                                return Err(M6ReceiverError::Integrity(
                                    "canonical-manifest rejection bytes decode successfully"
                                        .to_string(),
                                ));
                            }
                        }
                        ReceiverControlRejectionClassV1::MessageIdentity => {
                            let manifest = SignedManifest::from_canonical_bytes(attempted)?;
                            if manifest.message_digest == self.message_digest {
                                return Err(M6ReceiverError::Integrity(
                                    "message-identity rejection does not reproduce a digest mismatch"
                                        .to_string(),
                                ));
                            }
                        }
                        ReceiverControlRejectionClassV1::RouteAuthentication => {
                            let manifest = SignedManifest::from_canonical_bytes(attempted)?;
                            if manifest.message_digest != self.message_digest
                                || manifest.verify_route(route).is_ok()
                            {
                                return Err(M6ReceiverError::Integrity(
                                    "route-authentication rejection does not reproduce an identity/signature failure"
                                        .to_string(),
                                ));
                            }
                        }
                        _ => {
                            return Err(M6ReceiverError::Integrity(
                                "authentication control uses a replay-only rejection class"
                                    .to_string(),
                            ));
                        }
                    }
                }
            }
        }
        if let Some(bytes) = &self.existing_message_claim_bytes {
            let claim = ReceiverAuthenticatedMessageClaimV1::from_canonical_bytes(bytes, route)?;
            if claim.message_digest != self.message_digest
                || (self.class == ReceiverControlRejectionClassV1::MessageReplay
                    && claim.logical_operation_id == self.logical_operation_id
                    && claim.outer_request_digest == self.outer_request_digest)
            {
                return Err(M6ReceiverError::Integrity(
                    "control rejection existing message claim is cross-linked".to_string(),
                ));
            }
        }
        require_digest(
            "receiver signed control rejection",
            &self.record_digest,
            &self.expected_digest()?,
        )?;
        verify_receiver_control_rejection_signature(
            route,
            &self.signing_key_id,
            &self.record_digest,
            &self.signature_hex,
        )
        .map_err(|error| M6ReceiverError::Identity(error.to_string()))
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            CONTROL_REJECTION_DOMAIN,
            &(
                &self.schema,
                self.control_plane,
                self.class,
                &self.logical_operation_id,
                &self.outer_request_digest,
                &self.message_digest,
                &self.raw_evidence_digest,
                &self.route_definition_digest,
                &self.signing_key_id,
                (
                    self.attempted_manifest_bytes
                        .as_deref()
                        .map(ContentDigest::from_bytes),
                    self.raw_admission_rejection_bytes
                        .as_deref()
                        .map(ContentDigest::from_bytes),
                    self.raw_quarantine_record_bytes
                        .as_deref()
                        .map(ContentDigest::from_bytes),
                    self.raw_unit_files
                        .as_ref()
                        .map(|files| digest_domain(CONTROL_REJECTION_DOMAIN, files))
                        .transpose()?,
                    self.existing_message_claim_bytes
                        .as_deref()
                        .map(ContentDigest::from_bytes),
                ),
                &self.prior_replay_state,
                &self.post_replay_state,
                &self.detail,
                self.recorded_at_ms,
            ),
        )
    }
}

/// Receiver-signed evidence that a fully authenticated M5 export was rejected
/// by the receiver's real compatibility policy before any M5 effect.
///
/// Unlike an authentication control, this source intentionally contains the
/// exact verified export and compatibility decision. It therefore cannot turn
/// a malformed or unauthenticated message into an interface-policy result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverCompatibilityControlRejectionV1 {
    schema: String,
    logical_operation_id: String,
    route_definition_digest: ContentDigest,
    signing_key_id: String,
    message_digest: ContentDigest,
    raw_quarantine_digest: ContentDigest,
    verified_export_digest: ContentDigest,
    compatibility_decision_digest: ContentDigest,
    validation_rejection_digest: ContentDigest,
    terminal_negative_record_digest: ContentDigest,
    terminal_stage_digest: ContentDigest,
    active_snapshot_digest: ContentDigest,
    request_record_bytes: Vec<u8>,
    active_state_bytes: Vec<u8>,
    import_policy_bytes: Vec<u8>,
    raw_quarantine_record_bytes: Vec<u8>,
    raw_unit_files: BTreeMap<String, Vec<u8>>,
    signed_manifest_bytes: Vec<u8>,
    verified_export_bytes: Vec<u8>,
    compatibility_decision_bytes: Vec<u8>,
    validation_rejection_bytes: Vec<u8>,
    terminal_negative_record_bytes: Vec<u8>,
    coordinator_projection_bytes: Vec<u8>,
    post_rejection_active_state_bytes: Vec<u8>,
    evidence_digest: ContentDigest,
    signature_hex: String,
}

impl ReceiverCompatibilityControlRejectionV1 {
    pub fn logical_operation_id(&self) -> &str {
        &self.logical_operation_id
    }

    pub fn message_digest(&self) -> &ContentDigest {
        &self.message_digest
    }

    pub fn compatibility_decision_digest(&self) -> &ContentDigest {
        &self.compatibility_decision_digest
    }

    pub fn evidence_digest(&self) -> &ContentDigest {
        &self.evidence_digest
    }

    pub fn canonical_bytes_detached(
        &self,
        route: &RouteDefinition,
    ) -> Result<Vec<u8>, M6ReceiverError> {
        self.validate(route)?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes_detached(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6ReceiverError> {
        let evidence: Self = parse_canonical(bytes, MAX_RECORD_BYTES)?;
        evidence.validate(route)?;
        Ok(evidence)
    }

    fn seal(
        mut self,
        route: &RouteDefinition,
        signer: &FactorySigner,
    ) -> Result<Self, M6ReceiverError> {
        self.evidence_digest = self.expected_digest()?;
        self.signature_hex = signer
            .sign_receiver_control_rejection(route, &self.evidence_digest)
            .map_err(|error| M6ReceiverError::Identity(error.to_string()))?;
        self.validate(route)?;
        Ok(self)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_COMPATIBILITY_CONTROL_REJECTION_SCHEMA
            || self.route_definition_digest != route.definition_digest
            || self.signing_key_id != route.receiver.signing_key_id
        {
            return Err(M6ReceiverError::Integrity(
                "compatibility control rejection belongs to another route or schema".to_string(),
            ));
        }
        validate_identifier(
            "compatibility control operation id",
            &self.logical_operation_id,
        )?;

        let policy = ReceiverImportPolicyV1::from_canonical_bytes(&self.import_policy_bytes)?;
        let active = ReceiverActiveStateV1::from_canonical_bytes(&self.active_state_bytes)?;
        let post_active =
            ReceiverActiveStateV1::from_canonical_bytes(&self.post_rejection_active_state_bytes)?;
        let request: ReceiverIntakeRequest =
            parse_canonical(&self.request_record_bytes, MAX_REQUEST_BYTES)?;
        request.validate(route, &active, &policy)?;
        let raw =
            RawQuarantineRecord::from_canonical_bytes(&self.raw_quarantine_record_bytes, route)?;
        validate_portable_raw_unit_files(&raw, &self.raw_unit_files)?;
        let manifest = SignedManifest::from_canonical_bytes(&self.signed_manifest_bytes)?;
        manifest.verify_route(route)?;
        if self.raw_unit_files.get("manifest.json") != Some(&self.signed_manifest_bytes)
            || request.logical_operation_id != self.logical_operation_id
            || request.message_digest != self.message_digest
            || raw.intake_operation_id != self.logical_operation_id
            || raw.raw_unit_digest != self.raw_quarantine_digest
            || manifest.message_digest != self.message_digest
        {
            return Err(M6ReceiverError::Integrity(
                "compatibility control request, raw unit, and signed message are cross-linked"
                    .to_string(),
            ));
        }

        let verified = VerifiedQuarantinedExportV1::from_canonical_bytes(
            &self.verified_export_bytes,
            route,
            &policy,
        )?;
        if verified.manifest() != &manifest
            || verified.raw_quarantine_record() != &raw
            || verified.verification_digest() != &self.verified_export_digest
        {
            return Err(M6ReceiverError::Integrity(
                "compatibility control verified export differs from exact quarantine sources"
                    .to_string(),
            ));
        }
        let compatibility = ReceiverCompatibilityDecisionV1::from_canonical_bytes(
            &self.compatibility_decision_bytes,
            &verified,
            &active,
            &policy,
        )?;
        if compatibility.compatible()
            || !compatibility
                .issues()
                .contains(&ReceiverCompatibilityIssue::InterfaceMismatch)
            || compatibility.decision_digest() != &self.compatibility_decision_digest
        {
            return Err(M6ReceiverError::Integrity(
                "compatibility control does not reproduce an actual interface-policy rejection"
                    .to_string(),
            ));
        }

        let rejection: ReceiverValidationRejection =
            parse_canonical(&self.validation_rejection_bytes, MAX_RECORD_BYTES)?;
        rejection.validate(&request, &raw)?;
        if !rejection.authenticated
            || rejection.policy_rule != "receiver-compatibility"
            || rejection.record_digest != self.validation_rejection_digest
            || !rejection
                .evidence_refs
                .contains(verified.verification_digest())
            || !rejection
                .evidence_refs
                .contains(compatibility.decision_digest())
        {
            return Err(M6ReceiverError::Integrity(
                "compatibility control lacks its exact authenticated validation rejection"
                    .to_string(),
            ));
        }
        let negative = TerminalNegativeRecord::from_canonical_bytes(
            &self.terminal_negative_record_bytes,
            route,
            RouteEndpointRole::Sender,
        )?;
        if negative.message_digest != self.message_digest
            || negative.disposition != TerminalNegativeDisposition::PolicyRejected
            || negative.reason
                != (TerminalNegativeReason::PolicyRejected {
                    policy_rule: "receiver-compatibility".to_string(),
                })
            || negative.negative_evidence_digest != rejection.record_digest
            || negative.record_digest != self.terminal_negative_record_digest
        {
            return Err(M6ReceiverError::Integrity(
                "compatibility control terminal-negative evidence is cross-linked".to_string(),
            ));
        }

        let projection =
            TransactionProjection::from_canonical_bytes(&self.coordinator_projection_bytes)?;
        let terminal = projection.current_record().ok_or_else(|| {
            M6ReceiverError::Integrity(
                "compatibility control coordinator projection has no terminal stage".to_string(),
            )
        })?;
        if projection.intent.kind != TransactionKind::ReceiverIntake
            || projection.intent.logical_operation_id != self.logical_operation_id
            || projection.intent.route_definition_digest != route.definition_digest
            || projection.intent.message_digest != self.message_digest
            || projection.intent.before_snapshot_digest != active.snapshot().snapshot_digest
            || projection.intent.policy_digest != *policy.policy_digest()
            || terminal.stage != TransactionStage::ValidationRejected
            || terminal.stage_digest != self.terminal_stage_digest
            || !terminal
                .evidence
                .evidence_refs
                .contains(&rejection.record_digest)
            || !terminal
                .evidence
                .evidence_refs
                .contains(&negative.record_digest)
        {
            return Err(M6ReceiverError::Integrity(
                "compatibility control coordinator terminal stage is cross-linked".to_string(),
            ));
        }
        if active != post_active || active.snapshot().snapshot_digest != self.active_snapshot_digest
        {
            return Err(M6ReceiverError::Integrity(
                "compatibility rejection changed the receiver's active M5 state".to_string(),
            ));
        }

        require_digest(
            "receiver compatibility control rejection",
            &self.evidence_digest,
            &self.expected_digest()?,
        )?;
        verify_receiver_control_rejection_signature(
            route,
            &self.signing_key_id,
            &self.evidence_digest,
            &self.signature_hex,
        )
        .map_err(|error| M6ReceiverError::Identity(error.to_string()))
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            COMPATIBILITY_CONTROL_REJECTION_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.route_definition_digest,
                &self.signing_key_id,
                &self.message_digest,
                &self.raw_quarantine_digest,
                &self.verified_export_digest,
                &self.compatibility_decision_digest,
                &self.validation_rejection_digest,
                &self.terminal_negative_record_digest,
                &self.terminal_stage_digest,
                &self.active_snapshot_digest,
                (
                    ContentDigest::from_bytes(&self.request_record_bytes),
                    ContentDigest::from_bytes(&self.active_state_bytes),
                    ContentDigest::from_bytes(&self.import_policy_bytes),
                    ContentDigest::from_bytes(&self.raw_quarantine_record_bytes),
                    digest_domain(COMPATIBILITY_CONTROL_REJECTION_DOMAIN, &self.raw_unit_files)?,
                    ContentDigest::from_bytes(&self.signed_manifest_bytes),
                    ContentDigest::from_bytes(&self.verified_export_bytes),
                    ContentDigest::from_bytes(&self.compatibility_decision_bytes),
                    ContentDigest::from_bytes(&self.validation_rejection_bytes),
                    ContentDigest::from_bytes(&self.terminal_negative_record_bytes),
                    ContentDigest::from_bytes(&self.coordinator_projection_bytes),
                    ContentDigest::from_bytes(&self.post_rejection_active_state_bytes),
                ),
            ),
        )
    }
}

/// Receiver-signed aggregate of three distinct, real negative controls.
///
/// Replay rejection is deliberately excluded: replay remains a separate
/// signed source with its own unchanged-state semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverNegativeControlSuiteV1 {
    schema: String,
    route_definition_digest: ContentDigest,
    signing_key_id: String,
    content_tamper_rejection_bytes: Vec<u8>,
    false_route_identity_rejection_bytes: Vec<u8>,
    incompatible_interface_rejection_bytes: Vec<u8>,
    content_tamper_rejection_digest: ContentDigest,
    false_route_identity_rejection_digest: ContentDigest,
    incompatible_interface_rejection_digest: ContentDigest,
    suite_digest: ContentDigest,
    signature_hex: String,
}

impl ReceiverNegativeControlSuiteV1 {
    pub fn suite_digest(&self) -> &ContentDigest {
        &self.suite_digest
    }

    pub fn content_tamper_rejection_digest(&self) -> &ContentDigest {
        &self.content_tamper_rejection_digest
    }

    pub fn false_route_identity_rejection_digest(&self) -> &ContentDigest {
        &self.false_route_identity_rejection_digest
    }

    pub fn incompatible_interface_rejection_digest(&self) -> &ContentDigest {
        &self.incompatible_interface_rejection_digest
    }

    pub fn canonical_bytes_detached(
        &self,
        route: &RouteDefinition,
    ) -> Result<Vec<u8>, M6ReceiverError> {
        self.validate(route)?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes_detached(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6ReceiverError> {
        let suite: Self = parse_canonical(bytes, MAX_RECORD_BYTES)?;
        suite.validate(route)?;
        Ok(suite)
    }

    fn new(
        route: &RouteDefinition,
        signer: &FactorySigner,
        content_tamper: ReceiverSignedControlRejectionV1,
        false_route_identity: ReceiverSignedControlRejectionV1,
        incompatible_interface: ReceiverCompatibilityControlRejectionV1,
    ) -> Result<Self, M6ReceiverError> {
        let mut suite = Self {
            schema: RECEIVER_NEGATIVE_CONTROL_SUITE_SCHEMA.to_string(),
            route_definition_digest: route.definition_digest.clone(),
            signing_key_id: signer.signing_key_id().to_string(),
            content_tamper_rejection_bytes: content_tamper.canonical_bytes(route)?,
            false_route_identity_rejection_bytes: false_route_identity.canonical_bytes(route)?,
            incompatible_interface_rejection_bytes: incompatible_interface
                .canonical_bytes_detached(route)?,
            content_tamper_rejection_digest: content_tamper.record_digest().clone(),
            false_route_identity_rejection_digest: false_route_identity.record_digest().clone(),
            incompatible_interface_rejection_digest: incompatible_interface
                .evidence_digest()
                .clone(),
            suite_digest: ContentDigest::from_bytes(&[]),
            signature_hex: String::new(),
        };
        suite.suite_digest = suite.expected_digest()?;
        suite.signature_hex = signer
            .sign_receiver_control_rejection(route, &suite.suite_digest)
            .map_err(|error| M6ReceiverError::Identity(error.to_string()))?;
        suite.validate(route)?;
        Ok(suite)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_NEGATIVE_CONTROL_SUITE_SCHEMA
            || self.route_definition_digest != route.definition_digest
            || self.signing_key_id != route.receiver.signing_key_id
        {
            return Err(M6ReceiverError::Integrity(
                "receiver negative-control suite belongs to another route or schema".to_string(),
            ));
        }
        let content = ReceiverSignedControlRejectionV1::from_canonical_bytes(
            &self.content_tamper_rejection_bytes,
            route,
        )?;
        let identity = ReceiverSignedControlRejectionV1::from_canonical_bytes(
            &self.false_route_identity_rejection_bytes,
            route,
        )?;
        let compatibility = ReceiverCompatibilityControlRejectionV1::from_canonical_bytes_detached(
            &self.incompatible_interface_rejection_bytes,
            route,
        )?;
        if content.control_plane() != ReceiverControlPlaneV1::Authentication
            || content.class() != ReceiverControlRejectionClassV1::CanonicalManifest
            || content.record_digest() != &self.content_tamper_rejection_digest
            || identity.control_plane() != ReceiverControlPlaneV1::Authentication
            || identity.class() != ReceiverControlRejectionClassV1::RouteAuthentication
            || identity.record_digest() != &self.false_route_identity_rejection_digest
            || compatibility.evidence_digest() != &self.incompatible_interface_rejection_digest
        {
            return Err(M6ReceiverError::Integrity(
                "negative-control suite does not contain its three exact typed controls"
                    .to_string(),
            ));
        }
        let operations = BTreeSet::from([
            content.logical_operation_id().to_string(),
            identity.logical_operation_id().to_string(),
            compatibility.logical_operation_id().to_string(),
        ]);
        let messages = BTreeSet::from([
            content.message_digest().clone(),
            identity.message_digest().clone(),
            compatibility.message_digest().clone(),
        ]);
        if operations.len() != 3 || messages.len() != 3 {
            return Err(M6ReceiverError::Integrity(
                "negative-control suite reuses an operation or message across controls".to_string(),
            ));
        }
        require_digest(
            "receiver negative-control suite",
            &self.suite_digest,
            &self.expected_digest()?,
        )?;
        verify_receiver_control_rejection_signature(
            route,
            &self.signing_key_id,
            &self.suite_digest,
            &self.signature_hex,
        )
        .map_err(|error| M6ReceiverError::Identity(error.to_string()))
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            NEGATIVE_CONTROL_SUITE_DOMAIN,
            &(
                &self.schema,
                &self.route_definition_digest,
                &self.signing_key_id,
                &self.content_tamper_rejection_digest,
                &self.false_route_identity_rejection_digest,
                &self.incompatible_interface_rejection_digest,
                ContentDigest::from_bytes(&self.content_tamper_rejection_bytes),
                ContentDigest::from_bytes(&self.false_route_identity_rejection_bytes),
                ContentDigest::from_bytes(&self.incompatible_interface_rejection_bytes),
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverReplayControlDispositionV1 {
    Accepted,
    TerminalNegative,
}

/// Receiver-signed, portable proof of the exact replay-control fact for one
/// sender message. This is deliberately separate from exchange completion:
/// consuming replay identity does not itself prove that an import succeeded or
/// reached a terminal rejection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverReplayControlProofV1 {
    schema: String,
    route_definition_digest: ContentDigest,
    signing_key_id: String,
    receiver_factory_id: String,
    sender_factory_id: String,
    logical_operation_id: String,
    outer_request_digest: ContentDigest,
    message_digest: ContentDigest,
    raw_quarantine_digest: ContentDigest,
    sequence: u64,
    nonce: String,
    retained_until_ms: u64,
    disposition: ReceiverReplayControlDispositionV1,
    signed_manifest_bytes: Vec<u8>,
    message_claim_bytes: Vec<u8>,
    terminal_negative_record_bytes: Option<Vec<u8>>,
    replay_fact_digest: ContentDigest,
    proof_digest: ContentDigest,
    signature_hex: String,
}

impl ReceiverReplayControlProofV1 {
    pub fn message_digest(&self) -> &ContentDigest {
        &self.message_digest
    }

    pub fn logical_operation_id(&self) -> &str {
        &self.logical_operation_id
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn disposition(&self) -> ReceiverReplayControlDispositionV1 {
        self.disposition
    }

    pub fn replay_fact_digest(&self) -> &ContentDigest {
        &self.replay_fact_digest
    }

    pub fn proof_digest(&self) -> &ContentDigest {
        &self.proof_digest
    }

    pub fn canonical_bytes(&self, route: &RouteDefinition) -> Result<Vec<u8>, M6ReceiverError> {
        self.validate(route)?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6ReceiverError> {
        let proof: Self = parse_canonical(bytes, MAX_RECORD_BYTES)?;
        proof.validate(route)?;
        Ok(proof)
    }

    fn from_resolution(
        route: &RouteDefinition,
        signer: &FactorySigner,
        raw_quarantine_digest: ContentDigest,
        manifest: &SignedManifest,
        claim: &ReceiverAuthenticatedMessageClaimV1,
        disposition: ReceiverReplayControlDispositionV1,
        commit: ReplayCommitFact,
        terminal_negative: Option<TerminalNegativeRecord>,
    ) -> Result<Self, M6ReceiverError> {
        let signed_manifest_bytes = manifest.canonical_bytes()?;
        let message_claim_bytes = claim.canonical_bytes(route)?;
        let terminal_negative_record_bytes = terminal_negative
            .as_ref()
            .map(|record| record.canonical_bytes(route, RouteEndpointRole::Sender))
            .transpose()?;
        let replay_fact_digest = replay_fact_digest(&commit)?;
        let mut proof = Self {
            schema: RECEIVER_REPLAY_CONTROL_PROOF_SCHEMA.to_string(),
            route_definition_digest: route.definition_digest.clone(),
            signing_key_id: signer.signing_key_id().to_string(),
            receiver_factory_id: route.receiver.factory_id.clone(),
            sender_factory_id: route.sender.factory_id.clone(),
            logical_operation_id: claim.logical_operation_id.clone(),
            outer_request_digest: claim.outer_request_digest.clone(),
            message_digest: commit.message_digest,
            raw_quarantine_digest,
            sequence: commit.sequence,
            nonce: commit.nonce,
            retained_until_ms: commit.retained_until_ms,
            disposition,
            signed_manifest_bytes,
            message_claim_bytes,
            terminal_negative_record_bytes,
            replay_fact_digest,
            proof_digest: ContentDigest::from_bytes(&[]),
            signature_hex: String::new(),
        };
        proof.proof_digest = proof.expected_digest()?;
        proof.signature_hex = signer
            .sign_receiver_replay_control(route, &proof.proof_digest)
            .map_err(|error| M6ReceiverError::Identity(error.to_string()))?;
        proof.validate(route)?;
        Ok(proof)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_REPLAY_CONTROL_PROOF_SCHEMA
            || self.route_definition_digest != route.definition_digest
            || self.signing_key_id != route.receiver.signing_key_id
            || self.receiver_factory_id != route.receiver.factory_id
            || self.sender_factory_id != route.sender.factory_id
            || self.logical_operation_id.is_empty()
            || self.retained_until_ms == 0
            || self.signed_manifest_bytes.is_empty()
            || self.signed_manifest_bytes.len() > route.resource_profile.max_manifest_bytes as usize
        {
            return Err(M6ReceiverError::Integrity(
                "receiver replay-control proof is outside its exact route schema".to_string(),
            ));
        }
        validate_identifier("receiver replay-control nonce", &self.nonce)?;
        validate_identifier(
            "receiver replay-control operation id",
            &self.logical_operation_id,
        )?;
        let claim = ReceiverAuthenticatedMessageClaimV1::from_canonical_bytes(
            &self.message_claim_bytes,
            route,
        )?;
        if claim.logical_operation_id != self.logical_operation_id
            || claim.outer_request_digest != self.outer_request_digest
            || claim.message_digest != self.message_digest
            || claim.raw_quarantine_digest != self.raw_quarantine_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver replay-control proof differs from its durable message claim".to_string(),
            ));
        }
        let manifest = SignedManifest::from_canonical_bytes(&self.signed_manifest_bytes)?;
        manifest.verify_route(route)?;
        if manifest.unsigned.origin_role != RouteEndpointRole::Sender
            || manifest.message_digest != self.message_digest
            || manifest.unsigned.sequence != self.sequence
            || manifest.unsigned.nonce != self.nonce
        {
            return Err(M6ReceiverError::Integrity(
                "receiver replay-control proof differs from its signed sender manifest".to_string(),
            ));
        }
        let fact = ReplayCommitFact {
            message_digest: self.message_digest.clone(),
            nonce: self.nonce.clone(),
            retained_until_ms: self.retained_until_ms,
            route_definition_digest: self.route_definition_digest.clone(),
            sequence: self.sequence,
        };
        require_digest(
            "receiver replay-control fact",
            &self.replay_fact_digest,
            &replay_fact_digest(&fact)?,
        )?;
        match (
            self.disposition,
            self.terminal_negative_record_bytes.as_deref(),
        ) {
            (ReceiverReplayControlDispositionV1::Accepted, None) => {}
            (ReceiverReplayControlDispositionV1::TerminalNegative, Some(negative_bytes)) => {
                let negative = TerminalNegativeRecord::from_canonical_bytes(
                    negative_bytes,
                    route,
                    RouteEndpointRole::Sender,
                )?;
                if negative.message_digest != self.message_digest
                    || negative.sequence != self.sequence
                    || negative.nonce != self.nonce
                {
                    return Err(M6ReceiverError::Integrity(
                        "terminal-negative replay proof is cross-linked".to_string(),
                    ));
                }
            }
            _ => {
                return Err(M6ReceiverError::Integrity(
                    "replay-control disposition has the wrong terminal-negative source".to_string(),
                ));
            }
        }
        require_digest(
            "receiver replay-control proof",
            &self.proof_digest,
            &self.expected_digest()?,
        )?;
        verify_receiver_replay_control_signature(
            route,
            &self.signing_key_id,
            &self.proof_digest,
            &self.signature_hex,
        )
        .map_err(|error| M6ReceiverError::Identity(error.to_string()))
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REPLAY_CONTROL_PROOF_DOMAIN,
            &(
                (
                    &self.schema,
                    &self.route_definition_digest,
                    &self.signing_key_id,
                    &self.receiver_factory_id,
                    &self.sender_factory_id,
                    &self.logical_operation_id,
                    &self.outer_request_digest,
                    &self.message_digest,
                    &self.raw_quarantine_digest,
                ),
                (
                    self.sequence,
                    &self.nonce,
                    self.retained_until_ms,
                    self.disposition,
                    ContentDigest::from_bytes(&self.signed_manifest_bytes),
                    ContentDigest::from_bytes(&self.message_claim_bytes),
                    self.terminal_negative_record_bytes
                        .as_deref()
                        .map(ContentDigest::from_bytes),
                ),
                &self.replay_fact_digest,
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverM5Disposition {
    Healthy,
    RolledBack,
    ValidationRejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverM5CycleEvidence {
    schema: String,
    logical_operation_id: String,
    outer_request_digest: ContentDigest,
    approval_decision_digest: ContentDigest,
    promotion_authorization_digest: ContentDigest,
    promotion_consumption_digest: ContentDigest,
    observation_authorization_digest: ContentDigest,
    observation_consumption_digest: ContentDigest,
    rollback_authorization_digest: ContentDigest,
    rollback_consumption_digest: ContentDigest,
    import_plan_digest: ContentDigest,
    cycle_id: String,
    disposition: ReceiverM5Disposition,
    cycle_record: crate::factory_reproduction::CycleRecord,
    active_snapshot: FactoryRuntimeSnapshot,
    reproduction_state_digest: ContentDigest,
    effect_audit: M5EffectAuditReport,
    evidence_digest: ContentDigest,
}

impl ReceiverM5CycleEvidence {
    fn from_result(
        request: &ReceiverIntakeRequest,
        decision: &ApprovalDecisionRecord,
        promotion_consumption: &AuthorizationConsumption,
        observation_consumption: &AuthorizationConsumption,
        rollback_consumption: &AuthorizationConsumption,
        plan: &ReceiverImportPlanV1,
        result: &M5ExactCandidateCycleResult,
    ) -> Result<Self, M6ReceiverError> {
        result
            .validate()
            .map_err(|error| M6ReceiverError::M5(error.to_string()))?;
        let disposition = match &result.outcome {
            CycleOutcome::Adopted { .. } => ReceiverM5Disposition::Healthy,
            CycleOutcome::QuarantinedAndRolledBack { .. } => ReceiverM5Disposition::RolledBack,
            CycleOutcome::GateRejected { .. }
            | CycleOutcome::ApprovalRejected { .. }
            | CycleOutcome::Stopped(_) => ReceiverM5Disposition::ValidationRejected,
        };
        let mut evidence = Self {
            schema: RECEIVER_M5_CYCLE_EVIDENCE_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            outer_request_digest: request.request_digest.clone(),
            approval_decision_digest: decision.decision_digest().clone(),
            promotion_authorization_digest: promotion_consumption.authorization_digest().clone(),
            promotion_consumption_digest: promotion_consumption.receipt_digest().clone(),
            observation_authorization_digest: observation_consumption
                .authorization_digest()
                .clone(),
            observation_consumption_digest: observation_consumption.receipt_digest().clone(),
            rollback_authorization_digest: rollback_consumption.authorization_digest().clone(),
            rollback_consumption_digest: rollback_consumption.receipt_digest().clone(),
            import_plan_digest: plan.import_plan_digest().clone(),
            cycle_id: result.cycle_id.clone(),
            disposition,
            cycle_record: result.cycle_record.clone(),
            active_snapshot: result.active_snapshot.clone(),
            reproduction_state_digest: result.reproduction_state.state_digest.clone(),
            effect_audit: result.effect_audit.clone(),
            evidence_digest: ContentDigest::from_bytes(&[]),
        };
        evidence.evidence_digest = evidence.expected_digest()?;
        Ok(evidence)
    }

    fn validate(
        &self,
        request: &ReceiverIntakeRequest,
        decision: &ApprovalDecisionRecord,
        promotion_consumption: &AuthorizationConsumption,
        observation_consumption: &AuthorizationConsumption,
        rollback_consumption: &AuthorizationConsumption,
        plan: &ReceiverImportPlanV1,
    ) -> Result<(), M6ReceiverError> {
        self.effect_audit
            .validate()
            .map_err(|error| M6ReceiverError::M5(error.to_string()))?;
        if self.schema != RECEIVER_M5_CYCLE_EVIDENCE_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.outer_request_digest != request.request_digest
            || self.approval_decision_digest != *decision.decision_digest()
            || self.promotion_authorization_digest != *promotion_consumption.authorization_digest()
            || self.promotion_consumption_digest != *promotion_consumption.receipt_digest()
            || self.observation_authorization_digest
                != *observation_consumption.authorization_digest()
            || self.observation_consumption_digest != *observation_consumption.receipt_digest()
            || self.rollback_authorization_digest != *rollback_consumption.authorization_digest()
            || self.rollback_consumption_digest != *rollback_consumption.receipt_digest()
            || self.import_plan_digest != *plan.import_plan_digest()
            || self.cycle_id != activation_cycle_id(&request.logical_operation_id)
            || self.cycle_record.cycle_id != self.cycle_id
            || self.effect_audit.reproduction_state_digest != self.reproduction_state_digest
            || self.effect_audit.backend_snapshot_digest != self.active_snapshot.snapshot_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver M5 cycle projection is missing or cross-linked".to_string(),
            ));
        }
        match self.disposition {
            ReceiverM5Disposition::Healthy
                if self.cycle_record.activation_receipt.is_none()
                    || self.cycle_record.observation_evidence.is_none()
                    || self.cycle_record.recovery_receipt.is_some()
                    || self.active_snapshot.package_digest
                        != *plan.receiver_local_package_digest() =>
            {
                return Err(M6ReceiverError::Integrity(
                    "healthy receiver M5 projection lacks activation/observation evidence"
                        .to_string(),
                ));
            }
            ReceiverM5Disposition::RolledBack
                if self.cycle_record.activation_receipt.is_none()
                    || self.cycle_record.observation_evidence.is_none()
                    || self.cycle_record.recovery_receipt.is_none()
                    || self.active_snapshot.snapshot_digest
                        != request.expected_active_snapshot_digest
                    || self.active_snapshot.package_digest
                        != request.expected_active_package_digest =>
            {
                return Err(M6ReceiverError::Integrity(
                    "rolled-back receiver M5 projection lacks recovery evidence or the exact prior active state"
                        .to_string(),
                ));
            }
            ReceiverM5Disposition::ValidationRejected
                if self.cycle_record.activation_receipt.is_some()
                    || self.cycle_record.observation_evidence.is_some()
                    || self.cycle_record.recovery_receipt.is_some()
                    || self.active_snapshot.snapshot_digest
                        != request.expected_active_snapshot_digest
                    || self.active_snapshot.package_digest
                        != request.expected_active_package_digest =>
            {
                return Err(M6ReceiverError::Integrity(
                    "M5 validation rejection claims an activation or changed active snapshot"
                        .to_string(),
                ));
            }
            _ => {}
        }
        require_digest(
            "receiver M5 cycle evidence",
            &self.evidence_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_against_authoritative_recovery(
        &self,
        request: &ReceiverIntakeRequest,
        decision: &ApprovalDecisionRecord,
        promotion_consumption: &AuthorizationConsumption,
        observation_consumption: &AuthorizationConsumption,
        rollback_consumption: &AuthorizationConsumption,
        plan: &ReceiverImportPlanV1,
        authoritative: &M5ExactCandidateCycleResult,
    ) -> Result<(), M6ReceiverError> {
        self.validate(
            request,
            decision,
            promotion_consumption,
            observation_consumption,
            rollback_consumption,
            plan,
        )?;
        let current_by_proof = authoritative
            .effect_audit
            .entries
            .iter()
            .map(|entry| (entry.proof_digest.as_str(), entry))
            .collect::<BTreeMap<_, _>>();
        if self.effect_audit.entries.iter().any(|retained| {
            current_by_proof
                .get(retained.proof_digest.as_str())
                .copied()
                != Some(retained)
        }) || authoritative
            .effect_audit
            .entries
            .iter()
            .filter(|entry| {
                !self
                    .effect_audit
                    .entries
                    .iter()
                    .any(|retained| retained.proof_digest == entry.proof_digest)
            })
            .any(|entry| {
                !matches!(
                    entry.kind,
                    M5EffectAuditKind::ActiveExecution
                        | M5EffectAuditKind::ServedExecution
                        | M5EffectAuditKind::InspectionDiagnostic
                )
            })
        {
            return Err(M6ReceiverError::Integrity(
                "retained receiver M5 audit is not an exact append-only runtime-audit subset"
                    .to_string(),
            ));
        }

        // Read-only recovery may occur after a signed same-input behavior
        // probe. That probe appends execution evidence to M5's audit ledger,
        // but cannot change the already terminal cycle. Normalize only that
        // independently validated append-only audit field, then compare every
        // immutable cycle/source fact to the authoritative reconstruction.
        let mut projected = Self::from_result(
            request,
            decision,
            promotion_consumption,
            observation_consumption,
            rollback_consumption,
            plan,
            authoritative,
        )?;
        projected.effect_audit = self.effect_audit.clone();
        projected.evidence_digest = projected.expected_digest()?;
        if projected != *self {
            return Err(M6ReceiverError::Integrity(
                "retained receiver M5 evidence differs from authoritative terminal cycle facts"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            M5_CYCLE_EVIDENCE_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.outer_request_digest,
                &self.approval_decision_digest,
                &self.promotion_authorization_digest,
                &self.promotion_consumption_digest,
                &self.observation_authorization_digest,
                &self.observation_consumption_digest,
                &self.rollback_authorization_digest,
                &self.rollback_consumption_digest,
                &self.import_plan_digest,
                &self.cycle_id,
                self.disposition,
                &self.cycle_record,
                &self.active_snapshot,
                (&self.reproduction_state_digest, &self.effect_audit),
            ),
        )
    }
}

/// Exact incumbent package and M3-backed execution captured durably before
/// receiver activation authority is consumed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverM5PreActivationProbeV1 {
    schema: String,
    logical_operation_id: String,
    active_snapshot: FactoryRuntimeSnapshot,
    active_package_bytes: Vec<u8>,
    execution: M5ActiveExecution,
    probe_digest: ContentDigest,
}

impl ReceiverM5PreActivationProbeV1 {
    fn capture(
        logical_operation_id: &str,
        active: &ReceiverActiveStateV1,
        active_package: &FactoryPackage,
        execution: M5ActiveExecution,
        suite: &ValidationSuite,
    ) -> Result<Self, M6ReceiverError> {
        let mut probe = Self {
            schema: RECEIVER_M5_PRE_ACTIVATION_PROBE_SCHEMA.to_string(),
            logical_operation_id: logical_operation_id.to_string(),
            active_snapshot: active.snapshot().clone(),
            active_package_bytes: active_package
                .canonical_bytes()
                .map_err(|error| M6ReceiverError::M5(error.to_string()))?,
            execution,
            probe_digest: ContentDigest::from_bytes(&[]),
        };
        probe.probe_digest = probe.expected_digest()?;
        probe.validate(logical_operation_id, active, suite)?;
        Ok(probe)
    }

    fn validate(
        &self,
        logical_operation_id: &str,
        active: &ReceiverActiveStateV1,
        suite: &ValidationSuite,
    ) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_M5_PRE_ACTIVATION_PROBE_SCHEMA
            || self.logical_operation_id != logical_operation_id
            || self.active_snapshot != *active.snapshot()
            || self.execution.input != BEHAVIOR_CHANGE_PROBE_INPUT
        {
            return Err(M6ReceiverError::Integrity(
                "pre-activation behavior probe is stale or outside its exact operation".to_string(),
            ));
        }
        validate_execution_against_package(&self.execution, &self.active_package_bytes, suite)?;
        if self.execution.package_digest != self.active_snapshot.package_digest
            || self.execution.package_bytes_digest != self.active_snapshot.package_bytes_digest
            || self.execution.component_digest != self.active_snapshot.component_digest
        {
            return Err(M6ReceiverError::Integrity(
                "pre-activation execution differs from the expected incumbent snapshot".to_string(),
            ));
        }
        require_digest(
            "pre-activation behavior probe",
            &self.probe_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            M5_BEHAVIOR_CHANGE_EVIDENCE_DOMAIN,
            &(
                "pre_activation",
                &self.schema,
                &self.logical_operation_id,
                &self.active_snapshot,
                ContentDigest::from_bytes(&self.active_package_bytes),
                &self.execution,
            ),
        )
    }
}

/// Exact before/after M5 executions proving that one healthy receiver import
/// changed behavior through the active route. Both executions are resolved
/// against the M3 ledger in `effect_audit`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverM5BehaviorChangeEvidenceV1 {
    schema: String,
    logical_operation_id: String,
    cycle_id: String,
    import_plan_digest: ContentDigest,
    pre_activation_probe: ReceiverM5PreActivationProbeV1,
    post_activation_execution: M5ActiveExecution,
    effect_audit: M5EffectAuditReport,
    evidence_digest: ContentDigest,
}

impl ReceiverM5BehaviorChangeEvidenceV1 {
    fn validate(
        &self,
        request: &ReceiverIntakeRequest,
        active: &ReceiverActiveStateV1,
        plan: &ReceiverImportPlanV1,
        cycle: &ReceiverM5CycleEvidence,
        suite: &ValidationSuite,
    ) -> Result<(), M6ReceiverError> {
        self.effect_audit
            .validate()
            .map_err(|error| M6ReceiverError::M5(error.to_string()))?;
        self.pre_activation_probe
            .validate(&request.logical_operation_id, active, suite)?;
        validate_execution_against_package(
            &self.post_activation_execution,
            plan.receiver_local_package_bytes(),
            suite,
        )?;
        if self.schema != RECEIVER_M5_BEHAVIOR_CHANGE_EVIDENCE_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.cycle_id != cycle.cycle_id
            || self.import_plan_digest != *plan.import_plan_digest()
            || cycle.disposition != ReceiverM5Disposition::Healthy
            || self.pre_activation_probe.execution.input != self.post_activation_execution.input
            || self.pre_activation_probe.execution.output == self.post_activation_execution.output
            || self.pre_activation_probe.execution.package_digest
                != request.expected_active_package_digest
            || self.post_activation_execution.package_digest
                != *plan.receiver_local_package_digest()
            || self.post_activation_execution.package_digest != cycle.active_snapshot.package_digest
            || self.effect_audit.reproduction_state_digest != cycle.reproduction_state_digest
            || self.effect_audit.backend_snapshot_digest != cycle.active_snapshot.snapshot_digest
        {
            return Err(M6ReceiverError::Integrity(
                "healthy behavior evidence lacks an exact different-output incumbent/import pair"
                    .to_string(),
            ));
        }
        for execution in [
            &self.pre_activation_probe.execution,
            &self.post_activation_execution,
        ] {
            let matching = self
                .effect_audit
                .entries
                .iter()
                .filter(|entry| {
                    entry.kind == M5EffectAuditKind::ActiveExecution
                        && entry.evidence_id
                            == format!("active-execution:{}", execution.execution_digest)
                        && entry.invocation_id == execution.m3_invocation_id
                        && entry.receipt_digest == execution.m3_receipt_digest
                        && entry.attestation_digest == execution.m3_attestation_digest
                        && entry.proof_digest == execution.m3_proof_digest
                })
                .count();
            if matching != 1 {
                return Err(M6ReceiverError::Integrity(
                    "behavior execution does not resolve exactly once in the M3 effect audit"
                        .to_string(),
                ));
            }
        }
        require_digest(
            "receiver M5 behavior-change evidence",
            &self.evidence_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            M5_BEHAVIOR_CHANGE_EVIDENCE_DOMAIN,
            &(
                "before_after",
                &self.schema,
                &self.logical_operation_id,
                &self.cycle_id,
                &self.import_plan_digest,
                &self.pre_activation_probe,
                &self.post_activation_execution,
                &self.effect_audit,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverAdoptionReceipt {
    pub schema: String,
    pub logical_operation_id: String,
    pub outer_request_digest: ContentDigest,
    pub coordinator_request_digest: ContentDigest,
    pub message_digest: ContentDigest,
    pub import_plan_digest: ContentDigest,
    pub receiver_local_package_digest: ContentDigest,
    pub approval_decision_digest: ContentDigest,
    pub promotion_authorization_digest: ContentDigest,
    pub promotion_consumption_digest: ContentDigest,
    pub observation_authorization_digest: ContentDigest,
    pub observation_consumption_digest: ContentDigest,
    pub rollback_authorization_digest: ContentDigest,
    pub rollback_consumption_digest: ContentDigest,
    pub m5_cycle_evidence_digest: ContentDigest,
    pub disposition: ReceiverM5Disposition,
    pub final_active_snapshot_digest: ContentDigest,
    pub recorded_at_ms: u64,
    pub receipt_digest: ContentDigest,
}

impl ReceiverAdoptionReceipt {
    #[allow(clippy::too_many_arguments)]
    fn new(
        request: &ReceiverIntakeRequest,
        coordinator_request_digest: ContentDigest,
        decision: &ApprovalDecisionRecord,
        promotion_consumption: &AuthorizationConsumption,
        observation_consumption: &AuthorizationConsumption,
        rollback_consumption: &AuthorizationConsumption,
        plan: &ReceiverImportPlanV1,
        evidence: &ReceiverM5CycleEvidence,
        recorded_at_ms: u64,
    ) -> Result<Self, M6ReceiverError> {
        let mut receipt = Self {
            schema: RECEIVER_ADOPTION_RECEIPT_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            outer_request_digest: request.request_digest.clone(),
            coordinator_request_digest,
            message_digest: request.message_digest.clone(),
            import_plan_digest: plan.import_plan_digest().clone(),
            receiver_local_package_digest: plan.receiver_local_package_digest().clone(),
            approval_decision_digest: decision.decision_digest().clone(),
            promotion_authorization_digest: promotion_consumption.authorization_digest().clone(),
            promotion_consumption_digest: promotion_consumption.receipt_digest().clone(),
            observation_authorization_digest: observation_consumption
                .authorization_digest()
                .clone(),
            observation_consumption_digest: observation_consumption.receipt_digest().clone(),
            rollback_authorization_digest: rollback_consumption.authorization_digest().clone(),
            rollback_consumption_digest: rollback_consumption.receipt_digest().clone(),
            m5_cycle_evidence_digest: evidence.evidence_digest.clone(),
            disposition: evidence.disposition,
            final_active_snapshot_digest: evidence.active_snapshot.snapshot_digest.clone(),
            recorded_at_ms,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        Ok(receipt)
    }

    fn validate(
        &self,
        request: &ReceiverIntakeRequest,
        coordinator_request_digest: &ContentDigest,
        decision: &ApprovalDecisionRecord,
        promotion_consumption: &AuthorizationConsumption,
        observation_consumption: &AuthorizationConsumption,
        rollback_consumption: &AuthorizationConsumption,
        plan: &ReceiverImportPlanV1,
        evidence: &ReceiverM5CycleEvidence,
    ) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_ADOPTION_RECEIPT_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.outer_request_digest != request.request_digest
            || &self.coordinator_request_digest != coordinator_request_digest
            || self.message_digest != request.message_digest
            || self.import_plan_digest != *plan.import_plan_digest()
            || self.receiver_local_package_digest != *plan.receiver_local_package_digest()
            || self.approval_decision_digest != *decision.decision_digest()
            || self.promotion_authorization_digest != *promotion_consumption.authorization_digest()
            || self.promotion_consumption_digest != *promotion_consumption.receipt_digest()
            || self.observation_authorization_digest
                != *observation_consumption.authorization_digest()
            || self.observation_consumption_digest != *observation_consumption.receipt_digest()
            || self.rollback_authorization_digest != *rollback_consumption.authorization_digest()
            || self.rollback_consumption_digest != *rollback_consumption.receipt_digest()
            || self.m5_cycle_evidence_digest != evidence.evidence_digest
            || self.disposition != evidence.disposition
            || self.final_active_snapshot_digest != evidence.active_snapshot.snapshot_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver adoption receipt is missing or cross-linked".to_string(),
            ));
        }
        require_digest(
            "receiver adoption receipt",
            &self.receipt_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            ADOPTION_RECEIPT_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.outer_request_digest,
                &self.coordinator_request_digest,
                &self.message_digest,
                &self.import_plan_digest,
                &self.receiver_local_package_digest,
                &self.approval_decision_digest,
                &self.promotion_authorization_digest,
                &self.promotion_consumption_digest,
                &self.observation_authorization_digest,
                &self.observation_consumption_digest,
                &self.rollback_authorization_digest,
                &self.rollback_consumption_digest,
                &self.m5_cycle_evidence_digest,
                (
                    self.disposition,
                    &self.final_active_snapshot_digest,
                    self.recorded_at_ms,
                ),
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverCompletionAuthoritySourceV1 {
    action: AuthorityAction,
    profile_bytes: Vec<u8>,
    authorization_bytes: Vec<u8>,
    consumption_bytes: Vec<u8>,
    profile_digest: ContentDigest,
    authorization_digest: ContentDigest,
    consumption_digest: ContentDigest,
    source_digest: ContentDigest,
}

impl ReceiverCompletionAuthoritySourceV1 {
    fn from_store<V: OpaqueAuthorizationVerifier>(
        store: &AuthorizationStore<V>,
        binding: &ExactActionBinding,
    ) -> Result<Self, M6ReceiverError> {
        let (authorization, consumption) = store.load_consumption_for_binding(binding)?;
        Self::from_records(store, &authorization, &consumption)
    }

    fn from_records<V: OpaqueAuthorizationVerifier>(
        store: &AuthorizationStore<V>,
        authorization: &ActionAuthorization,
        consumption: &AuthorizationConsumption,
    ) -> Result<Self, M6ReceiverError> {
        let profile_bytes = store.profile().canonical_bytes()?;
        let authorization_bytes =
            authorization.canonical_bytes(store.profile(), store.verifier())?;
        let consumption_bytes = consumption.canonical_bytes(&authorization)?;
        let mut source = Self {
            action: authorization.binding().action,
            profile_bytes,
            authorization_bytes,
            consumption_bytes,
            profile_digest: store.profile().profile_digest().clone(),
            authorization_digest: authorization.authorization_digest().clone(),
            consumption_digest: consumption.receipt_digest().clone(),
            source_digest: ContentDigest::from_bytes(&[]),
        };
        source.source_digest = source.expected_digest()?;
        Ok(source)
    }

    fn validate_detached(
        &self,
        receiver_factory_id: &str,
    ) -> Result<
        (
            EndpointActionProfile,
            ActionAuthorization,
            AuthorizationConsumption,
        ),
        M6ReceiverError,
    > {
        let profile = EndpointActionProfile::from_canonical_bytes(&self.profile_bytes)?;
        let authorization = ActionAuthorization::from_endpoint_attested_canonical_bytes(
            &self.authorization_bytes,
            &profile,
        )?;
        let consumption = AuthorizationConsumption::from_canonical_bytes(
            &self.consumption_bytes,
            &authorization,
        )?;
        if profile.factory_id() != receiver_factory_id
            || authorization.binding().action != self.action
            || authorization.use_limit() != 1
            || consumption.use_ordinal() != 1
            || self.profile_digest != *profile.profile_digest()
            || self.authorization_digest != *authorization.authorization_digest()
            || self.consumption_digest != *consumption.receipt_digest()
        {
            return Err(M6ReceiverError::Integrity(
                "receiver completion authority source is not exact and single-use".to_string(),
            ));
        }
        require_digest(
            "receiver completion authority source",
            &self.source_digest,
            &self.expected_digest()?,
        )?;
        Ok((profile, authorization, consumption))
    }

    fn validate_live<V: OpaqueAuthorizationVerifier>(
        &self,
        store: &AuthorizationStore<V>,
    ) -> Result<(), M6ReceiverError> {
        let embedded = EndpointActionProfile::from_canonical_bytes(&self.profile_bytes)?;
        if &embedded != store.profile() {
            return Err(M6ReceiverError::Integrity(
                "completion authority source differs from the live endpoint profile".to_string(),
            ));
        }
        let authorization = ActionAuthorization::from_canonical_bytes(
            &self.authorization_bytes,
            store.profile(),
            store.verifier(),
        )?;
        AuthorizationConsumption::from_canonical_bytes(&self.consumption_bytes, &authorization)?;
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            COMPLETION_AUTHORITY_SOURCE_DOMAIN,
            &(
                self.action,
                ContentDigest::from_bytes(&self.profile_bytes),
                ContentDigest::from_bytes(&self.authorization_bytes),
                ContentDigest::from_bytes(&self.consumption_bytes),
                &self.profile_digest,
                &self.authorization_digest,
                &self.consumption_digest,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverExchangeCompletionSourceDigestsV1 {
    pub request_record: ContentDigest,
    pub request_commit: ContentDigest,
    pub active_state: ContentDigest,
    pub import_policy: ContentDigest,
    pub proving_suite: ContentDigest,
    pub raw_quarantine: ContentDigest,
    pub raw_unit_files: ContentDigest,
    pub signed_manifest: ContentDigest,
    pub verified_export: ContentDigest,
    pub compatibility: ContentDigest,
    pub proving: ContentDigest,
    pub import_plan: ContentDigest,
    pub coordinator_projection: ContentDigest,
    pub replay_control: ContentDigest,
    pub approval_request: ContentDigest,
    pub approval_decision: ContentDigest,
    pub authority_sources: ContentDigest,
    pub m5_cycle: ContentDigest,
    pub pre_activation_probe: ContentDigest,
    pub behavior_change: Option<ContentDigest>,
    pub post_rollback_probe: Option<ContentDigest>,
    pub adoption_receipt: ContentDigest,
    pub acknowledgement_request: ContentDigest,
    pub acknowledgement_manifest: ContentDigest,
    pub acknowledgement_receipt: ContentDigest,
}

/// Receiver-signed, source-complete evidence for one terminal ordinary M5
/// import cycle. `Healthy` is the accepted branch; `RolledBack` is the typed
/// negative branch and must carry a fresh M3-backed post-rollback probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverExchangeCompletionEvidenceV1 {
    schema: String,
    logical_operation_id: String,
    route_definition_digest: ContentDigest,
    signing_key_id: String,
    sender_factory_id: String,
    receiver_factory_id: String,
    message_digest: ContentDigest,
    export_bundle_digest: ContentDigest,
    source_package_digest: ContentDigest,
    receiver_local_package_digest: ContentDigest,
    proving_digest: ContentDigest,
    import_plan_digest: ContentDigest,
    prior_active_snapshot_digest: ContentDigest,
    final_active_snapshot_digest: ContentDigest,
    disposition: ReceiverM5Disposition,
    terminal_stage: TransactionStage,
    terminal_stage_digest: ContentDigest,
    adoption_receipt_digest: ContentDigest,
    source_digests: ReceiverExchangeCompletionSourceDigestsV1,
    request_record_bytes: Vec<u8>,
    request_commit_bytes: Vec<u8>,
    active_state_bytes: Vec<u8>,
    import_policy_bytes: Vec<u8>,
    proving_suite_bytes: Vec<u8>,
    raw_quarantine_bytes: Vec<u8>,
    raw_unit_files: BTreeMap<String, Vec<u8>>,
    signed_manifest_bytes: Vec<u8>,
    verified_export_bytes: Vec<u8>,
    compatibility_bytes: Vec<u8>,
    proving_bytes: Vec<u8>,
    import_plan_bytes: Vec<u8>,
    coordinator_projection_bytes: Vec<u8>,
    replay_control_bytes: Vec<u8>,
    approval_request_bytes: Vec<u8>,
    approval_decision_bytes: Vec<u8>,
    authority_sources: Vec<ReceiverCompletionAuthoritySourceV1>,
    m5_cycle_bytes: Vec<u8>,
    pre_activation_probe_bytes: Vec<u8>,
    behavior_change_bytes: Option<Vec<u8>>,
    post_rollback_probe_bytes: Option<Vec<u8>>,
    adoption_receipt_bytes: Vec<u8>,
    acknowledgement_request_bytes: Vec<u8>,
    acknowledgement_manifest_bytes: Vec<u8>,
    acknowledgement_receipt_bytes: Vec<u8>,
    evidence_digest: ContentDigest,
    source_set_signature_hex: String,
}

impl ReceiverExchangeCompletionEvidenceV1 {
    pub fn logical_operation_id(&self) -> &str {
        &self.logical_operation_id
    }

    pub fn route_definition_digest(&self) -> &ContentDigest {
        &self.route_definition_digest
    }

    pub fn sender_factory_id(&self) -> &str {
        &self.sender_factory_id
    }

    pub fn receiver_factory_id(&self) -> &str {
        &self.receiver_factory_id
    }

    pub fn message_digest(&self) -> &ContentDigest {
        &self.message_digest
    }

    pub fn export_bundle_digest(&self) -> &ContentDigest {
        &self.export_bundle_digest
    }

    pub fn source_package_digest(&self) -> &ContentDigest {
        &self.source_package_digest
    }

    pub fn receiver_local_package_digest(&self) -> &ContentDigest {
        &self.receiver_local_package_digest
    }

    pub fn proving_digest(&self) -> &ContentDigest {
        &self.proving_digest
    }

    pub fn import_plan_digest(&self) -> &ContentDigest {
        &self.import_plan_digest
    }

    pub fn prior_active_snapshot_digest(&self) -> &ContentDigest {
        &self.prior_active_snapshot_digest
    }

    pub fn final_active_snapshot_digest(&self) -> &ContentDigest {
        &self.final_active_snapshot_digest
    }

    pub fn disposition(&self) -> ReceiverM5Disposition {
        self.disposition
    }

    pub fn before_behavior_output(&self) -> Result<i32, M6ReceiverError> {
        let probe: ReceiverM5PreActivationProbeV1 =
            parse_canonical(&self.pre_activation_probe_bytes, MAX_RECORD_BYTES)?;
        Ok(probe.execution.output)
    }

    pub fn behavior_probe_input(&self) -> Result<i32, M6ReceiverError> {
        let probe: ReceiverM5PreActivationProbeV1 =
            parse_canonical(&self.pre_activation_probe_bytes, MAX_RECORD_BYTES)?;
        Ok(probe.execution.input)
    }

    pub fn pre_activation_probe_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let probe: ReceiverM5PreActivationProbeV1 =
            parse_canonical(&self.pre_activation_probe_bytes, MAX_RECORD_BYTES)?;
        Ok(probe.probe_digest)
    }

    pub fn after_behavior_output(&self) -> Result<Option<i32>, M6ReceiverError> {
        self.behavior_change_bytes
            .as_deref()
            .map(|bytes| {
                parse_canonical::<ReceiverM5BehaviorChangeEvidenceV1>(bytes, MAX_RECORD_BYTES)
                    .map(|evidence| evidence.post_activation_execution.output)
            })
            .transpose()
    }

    pub fn behavior_change_evidence_digest(
        &self,
    ) -> Result<Option<ContentDigest>, M6ReceiverError> {
        self.behavior_change_bytes
            .as_deref()
            .map(|bytes| {
                parse_canonical::<ReceiverM5BehaviorChangeEvidenceV1>(bytes, MAX_RECORD_BYTES)
                    .map(|evidence| evidence.evidence_digest)
            })
            .transpose()
    }

    pub fn post_adoption_failure_observed(&self) -> Result<bool, M6ReceiverError> {
        let cycle: ReceiverM5CycleEvidence =
            parse_canonical(&self.m5_cycle_bytes, MAX_RECORD_BYTES)?;
        Ok(cycle
            .cycle_record
            .observation_evidence
            .as_ref()
            .is_some_and(observation_has_failure))
    }

    pub fn restored_behavior_output(&self) -> Result<Option<i32>, M6ReceiverError> {
        self.post_rollback_probe_bytes
            .as_deref()
            .map(|bytes| {
                M5PostRollbackProbeV1::from_canonical_bytes(bytes)
                    .map(|probe| probe.execution().output)
                    .map_err(M6ReceiverError::from)
            })
            .transpose()
    }

    pub fn restored_behavior_input(&self) -> Result<Option<i32>, M6ReceiverError> {
        self.post_rollback_probe_bytes
            .as_deref()
            .map(|bytes| {
                M5PostRollbackProbeV1::from_canonical_bytes(bytes)
                    .map(|probe| probe.execution().input)
                    .map_err(M6ReceiverError::from)
            })
            .transpose()
    }

    pub fn post_rollback_probe_digest(&self) -> Result<Option<ContentDigest>, M6ReceiverError> {
        self.post_rollback_probe_bytes
            .as_deref()
            .map(|bytes| {
                M5PostRollbackProbeV1::from_canonical_bytes(bytes)
                    .map(|probe| probe.probe_digest().clone())
                    .map_err(M6ReceiverError::from)
            })
            .transpose()
    }

    pub fn proves_observable_behavior_change(&self) -> bool {
        self.disposition == ReceiverM5Disposition::Healthy && self.behavior_change_bytes.is_some()
    }

    pub fn proves_restored_incumbent_behavior(&self) -> bool {
        if self.disposition != ReceiverM5Disposition::RolledBack
            || self.behavior_change_bytes.is_some()
        {
            return false;
        }
        let Ok(pre_activation) = parse_canonical::<ReceiverM5PreActivationProbeV1>(
            &self.pre_activation_probe_bytes,
            MAX_RECORD_BYTES,
        ) else {
            return false;
        };
        let Some(post_rollback_bytes) = self.post_rollback_probe_bytes.as_deref() else {
            return false;
        };
        let Ok(post_rollback) = M5PostRollbackProbeV1::from_canonical_bytes(post_rollback_bytes)
        else {
            return false;
        };
        let Ok(suite) =
            parse_canonical::<ValidationSuite>(&self.proving_suite_bytes, MAX_RECORD_BYTES)
        else {
            return false;
        };
        post_rollback.execution().input != pre_activation.execution.input
            && post_rollback.restored_package_digest()
                == &pre_activation.active_snapshot.package_digest
            && post_rollback.active_snapshot_digest()
                == &pre_activation.active_snapshot.snapshot_digest
            && post_rollback.execution().package_bytes_digest
                == pre_activation.execution.package_bytes_digest
            && post_rollback.execution().component_digest
                == pre_activation.execution.component_digest
            && validate_execution_against_package(
                post_rollback.execution(),
                &pre_activation.active_package_bytes,
                &suite,
            )
            .is_ok()
    }

    pub fn terminal_stage(&self) -> TransactionStage {
        self.terminal_stage
    }

    pub fn terminal_stage_digest(&self) -> &ContentDigest {
        &self.terminal_stage_digest
    }

    pub fn adoption_receipt_digest(&self) -> &ContentDigest {
        &self.adoption_receipt_digest
    }

    pub fn intake_record_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let request: ReceiverIntakeRequest =
            parse_canonical(&self.request_record_bytes, MAX_REQUEST_BYTES)?;
        Ok(request.request_digest)
    }

    pub fn coordinator_request_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let projection =
            TransactionProjection::from_canonical_bytes(&self.coordinator_projection_bytes)?;
        Ok(projection.intent.request_digest)
    }

    pub fn raw_quarantine_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let raw: RawQuarantineRecord =
            parse_canonical(&self.raw_quarantine_bytes, MAX_RECORD_BYTES)?;
        Ok(raw.raw_unit_digest)
    }

    pub fn replay_control_proof_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let replay: ReceiverReplayControlProofV1 =
            parse_canonical(&self.replay_control_bytes, MAX_RECORD_BYTES)?;
        Ok(replay.proof_digest)
    }

    pub fn replay_fact_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let replay: ReceiverReplayControlProofV1 =
            parse_canonical(&self.replay_control_bytes, MAX_RECORD_BYTES)?;
        Ok(replay.replay_fact_digest)
    }

    pub fn replay_sequence(&self) -> Result<u64, M6ReceiverError> {
        let replay: ReceiverReplayControlProofV1 =
            parse_canonical(&self.replay_control_bytes, MAX_RECORD_BYTES)?;
        Ok(replay.sequence)
    }

    pub fn acknowledgement_request_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let request: ReceiverAcknowledgementRequest =
            parse_canonical(&self.acknowledgement_request_bytes, MAX_RECORD_BYTES)?;
        Ok(request.request_digest)
    }

    pub fn ack_intake_record_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let request: ReceiverAcknowledgementRequest =
            parse_canonical(&self.acknowledgement_request_bytes, MAX_RECORD_BYTES)?;
        Ok(request.intake_record_digest)
    }

    pub fn ack_raw_quarantine_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let request: ReceiverAcknowledgementRequest =
            parse_canonical(&self.acknowledgement_request_bytes, MAX_RECORD_BYTES)?;
        Ok(request.raw_quarantine_digest)
    }

    pub fn ack_receiver_transaction_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let request: ReceiverAcknowledgementRequest =
            parse_canonical(&self.acknowledgement_request_bytes, MAX_RECORD_BYTES)?;
        Ok(request.receiver_transaction_digest)
    }

    pub fn ack_sender_message_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let request: ReceiverAcknowledgementRequest =
            parse_canonical(&self.acknowledgement_request_bytes, MAX_RECORD_BYTES)?;
        Ok(request.sender_message_digest)
    }

    pub fn acknowledgement_message_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let receipt: ReceiverAcknowledgementReceipt =
            parse_canonical(&self.acknowledgement_receipt_bytes, MAX_RECORD_BYTES)?;
        Ok(receipt.acknowledgement_message_digest)
    }

    pub fn acknowledgement_sequence(&self) -> Result<u64, M6ReceiverError> {
        let receipt: ReceiverAcknowledgementReceipt =
            parse_canonical(&self.acknowledgement_receipt_bytes, MAX_RECORD_BYTES)?;
        Ok(receipt.acknowledgement_sequence)
    }

    pub fn acknowledgement_receipt_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        let receipt: ReceiverAcknowledgementReceipt =
            parse_canonical(&self.acknowledgement_receipt_bytes, MAX_RECORD_BYTES)?;
        Ok(receipt.receipt_digest)
    }

    pub fn source_digests(&self) -> &ReceiverExchangeCompletionSourceDigestsV1 {
        &self.source_digests
    }

    pub fn evidence_digest(&self) -> &ContentDigest {
        &self.evidence_digest
    }

    pub fn canonical_bytes_detached(
        &self,
        route: &RouteDefinition,
    ) -> Result<Vec<u8>, M6ReceiverError> {
        self.validate_detached(route)?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_COMPLETION_EVIDENCE_BYTES {
            return Err(M6ReceiverError::ResourceExhausted(
                "receiver exchange completion evidence exceeds its byte budget".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes_detached(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6ReceiverError> {
        let evidence: Self = parse_canonical(bytes, MAX_COMPLETION_EVIDENCE_BYTES)?;
        evidence.validate_detached(route)?;
        Ok(evidence)
    }

    fn expected_source_digests(
        &self,
    ) -> Result<ReceiverExchangeCompletionSourceDigestsV1, M6ReceiverError> {
        Ok(ReceiverExchangeCompletionSourceDigestsV1 {
            request_record: ContentDigest::from_bytes(&self.request_record_bytes),
            request_commit: ContentDigest::from_bytes(&self.request_commit_bytes),
            active_state: ContentDigest::from_bytes(&self.active_state_bytes),
            import_policy: ContentDigest::from_bytes(&self.import_policy_bytes),
            proving_suite: ContentDigest::from_bytes(&self.proving_suite_bytes),
            raw_quarantine: ContentDigest::from_bytes(&self.raw_quarantine_bytes),
            raw_unit_files: ContentDigest::from_bytes(&canonical_json(&self.raw_unit_files)?),
            signed_manifest: ContentDigest::from_bytes(&self.signed_manifest_bytes),
            verified_export: ContentDigest::from_bytes(&self.verified_export_bytes),
            compatibility: ContentDigest::from_bytes(&self.compatibility_bytes),
            proving: ContentDigest::from_bytes(&self.proving_bytes),
            import_plan: ContentDigest::from_bytes(&self.import_plan_bytes),
            coordinator_projection: ContentDigest::from_bytes(&self.coordinator_projection_bytes),
            replay_control: ContentDigest::from_bytes(&self.replay_control_bytes),
            approval_request: ContentDigest::from_bytes(&self.approval_request_bytes),
            approval_decision: ContentDigest::from_bytes(&self.approval_decision_bytes),
            authority_sources: ContentDigest::from_bytes(&canonical_json(&self.authority_sources)?),
            m5_cycle: ContentDigest::from_bytes(&self.m5_cycle_bytes),
            pre_activation_probe: ContentDigest::from_bytes(&self.pre_activation_probe_bytes),
            behavior_change: self
                .behavior_change_bytes
                .as_deref()
                .map(ContentDigest::from_bytes),
            post_rollback_probe: self
                .post_rollback_probe_bytes
                .as_deref()
                .map(ContentDigest::from_bytes),
            adoption_receipt: ContentDigest::from_bytes(&self.adoption_receipt_bytes),
            acknowledgement_request: ContentDigest::from_bytes(&self.acknowledgement_request_bytes),
            acknowledgement_manifest: ContentDigest::from_bytes(
                &self.acknowledgement_manifest_bytes,
            ),
            acknowledgement_receipt: ContentDigest::from_bytes(&self.acknowledgement_receipt_bytes),
        })
    }

    fn validate_detached(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        route.validate()?;
        validate_identifier(
            "receiver completion logical operation id",
            &self.logical_operation_id,
        )?;
        if self.schema != RECEIVER_EXCHANGE_COMPLETION_EVIDENCE_SCHEMA
            || self.route_definition_digest != route.definition_digest
            || self.signing_key_id != route.receiver.signing_key_id
            || self.sender_factory_id != route.sender.factory_id
            || self.receiver_factory_id != route.receiver.factory_id
            || !matches!(
                self.disposition,
                ReceiverM5Disposition::Healthy | ReceiverM5Disposition::RolledBack
            )
            || self.source_digests != self.expected_source_digests()?
        {
            return Err(M6ReceiverError::Integrity(
                "receiver exchange completion evidence is outside its exact route or source set"
                    .to_string(),
            ));
        }
        require_digest(
            "receiver exchange completion evidence",
            &self.evidence_digest,
            &self.expected_digest()?,
        )?;
        // The endpoint signature is checked before any opaque authorization is
        // accepted through the endpoint-attested detached parser below.
        verify_receiver_intake_completion_signature(
            route,
            &self.signing_key_id,
            &self.evidence_digest,
            &self.source_set_signature_hex,
        )?;

        let policy = ReceiverImportPolicyV1::from_canonical_bytes(&self.import_policy_bytes)?;
        if policy.receiver_factory_id() != self.receiver_factory_id
            || policy.source_factory_id() != self.sender_factory_id
        {
            return Err(M6ReceiverError::Integrity(
                "completion import policy differs from the route endpoints".to_string(),
            ));
        }
        let suite: ValidationSuite = parse_canonical(&self.proving_suite_bytes, MAX_RECORD_BYTES)?;
        suite
            .validate()
            .map_err(|error| M6ReceiverError::Import(error.to_string()))?;
        if suite
            .suite_digest()
            .map_err(|error| M6ReceiverError::Import(error.to_string()))?
            != *policy.proving_suite_digest()
        {
            return Err(M6ReceiverError::Integrity(
                "completion proving suite differs from the import policy".to_string(),
            ));
        }
        let active = ReceiverActiveStateV1::from_canonical_bytes(&self.active_state_bytes)?;
        let request: ReceiverIntakeRequest =
            parse_canonical(&self.request_record_bytes, MAX_REQUEST_BYTES)?;
        let commit: ReceiverIntakeRequestCommit =
            parse_canonical(&self.request_commit_bytes, MAX_REQUEST_BYTES)?;
        request.validate(route, &active, &policy)?;
        commit.validate(
            &request,
            &self.request_record_bytes,
            &self.active_state_bytes,
        )?;
        let raw = RawQuarantineRecord::from_canonical_bytes(&self.raw_quarantine_bytes, route)?;
        validate_portable_raw_unit_files(&raw, &self.raw_unit_files)?;
        let retained_manifest_bytes =
            self.raw_unit_files.get("manifest.json").ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "completion raw unit lacks its exact signed manifest".to_string(),
                )
            })?;
        if retained_manifest_bytes != &self.signed_manifest_bytes {
            return Err(M6ReceiverError::Integrity(
                "completion signed manifest differs from raw quarantine bytes".to_string(),
            ));
        }
        let manifest = SignedManifest::from_canonical_bytes(&self.signed_manifest_bytes)?;
        manifest.verify_route(route)?;
        if manifest.message_digest != request.message_digest
            || raw.intake_operation_id != request.logical_operation_id
        {
            return Err(M6ReceiverError::Integrity(
                "completion raw/message sources are cross-linked".to_string(),
            ));
        }
        let verified = VerifiedQuarantinedExportV1::from_canonical_bytes(
            &self.verified_export_bytes,
            route,
            &policy,
        )?;
        if verified.raw_quarantine_record() != &raw || verified.manifest() != &manifest {
            return Err(M6ReceiverError::Integrity(
                "verified export differs from exact raw quarantine sources".to_string(),
            ));
        }
        let compatibility = ReceiverCompatibilityDecisionV1::from_canonical_bytes(
            &self.compatibility_bytes,
            &verified,
            &active,
            &policy,
        )?;
        let proving = ReceiverProvingReportV1::from_canonical_bytes(
            &self.proving_bytes,
            &verified,
            &active,
            &policy,
            &compatibility,
            &suite,
        )?;
        let plan = ReceiverImportPlanV1::from_canonical_bytes(
            &self.import_plan_bytes,
            &verified,
            &active,
            &policy,
            &compatibility,
            &proving,
            &suite,
        )?;
        let projection =
            TransactionProjection::from_canonical_bytes(&self.coordinator_projection_bytes)?;
        let terminal = projection.current_record().ok_or_else(|| {
            M6ReceiverError::Integrity(
                "receiver completion coordinator projection has no terminal stage".to_string(),
            )
        })?;
        let expected_terminal = match self.disposition {
            ReceiverM5Disposition::Healthy => TransactionStage::Healthy,
            ReceiverM5Disposition::RolledBack => TransactionStage::RolledBack,
            ReceiverM5Disposition::ValidationRejected => unreachable!(),
        };
        if projection.intent.kind != TransactionKind::ReceiverIntake
            || projection.intent.logical_operation_id != request.logical_operation_id
            || projection.intent.request_digest
                != self.coordinator_request_digest_from_sources(&request)?
            || terminal.stage != expected_terminal
            || terminal.stage_digest != self.terminal_stage_digest
            || self.terminal_stage != expected_terminal
        {
            return Err(M6ReceiverError::Integrity(
                "completion coordinator chain differs from its terminal disposition".to_string(),
            ));
        }
        let replay =
            ReceiverReplayControlProofV1::from_canonical_bytes(&self.replay_control_bytes, route)?;
        if replay.disposition != ReceiverReplayControlDispositionV1::Accepted
            || replay.logical_operation_id != request.logical_operation_id
            || replay.outer_request_digest != request.request_digest
            || replay.message_digest != request.message_digest
            || replay.raw_quarantine_digest != raw.raw_unit_digest
        {
            return Err(M6ReceiverError::Integrity(
                "completion replay commitment differs from the accepted intake".to_string(),
            ));
        }

        let expected_actions = [
            AuthorityAction::IntakePackage,
            AuthorityAction::ProveImport,
            AuthorityAction::GrantImportApproval,
            AuthorityAction::AdoptImport,
            AuthorityAction::ObserveImport,
            AuthorityAction::RollbackImport,
        ];
        if self.authority_sources.len() != expected_actions.len()
            || self
                .authority_sources
                .iter()
                .map(|source| source.action)
                .ne(expected_actions)
        {
            return Err(M6ReceiverError::Integrity(
                "completion authority set is not the exact ordered six-action set".to_string(),
            ));
        }
        let mut parsed_authority = BTreeMap::new();
        for source in &self.authority_sources {
            let (_, authorization, consumption) =
                source.validate_detached(&self.receiver_factory_id)?;
            parsed_authority.insert(source.action, (authorization, consumption));
        }
        require_completion_binding(
            &parsed_authority,
            AuthorityAction::IntakePackage,
            &intake_binding(&request),
        )?;
        require_completion_binding(
            &parsed_authority,
            AuthorityAction::ProveImport,
            &proving_binding(&request, &verified, &compatibility, &suite)?,
        )?;
        let approval_request = ApprovalRequest::from_canonical_bytes(&self.approval_request_bytes)?;
        let (approval_authorization, approval_consumption) =
            completion_authority(&parsed_authority, AuthorityAction::GrantImportApproval)?;
        let decision = ApprovalDecisionRecord::from_canonical_bytes(
            &self.approval_decision_bytes,
            &approval_request,
            approval_authorization,
            approval_consumption,
        )?;
        if decision.kind() != ApprovalDecisionKind::Granted {
            return Err(M6ReceiverError::Integrity(
                "terminal M5 completion lacks a Granted approval decision".to_string(),
            ));
        }
        require_completion_binding(
            &parsed_authority,
            AuthorityAction::AdoptImport,
            &promotion_binding(&request, &decision, &proving, &plan)?,
        )?;
        require_completion_binding(
            &parsed_authority,
            AuthorityAction::ObserveImport,
            &observation_binding(&request, &decision, &proving, &plan)?,
        )?;
        require_completion_binding(
            &parsed_authority,
            AuthorityAction::RollbackImport,
            &rollback_binding(&request, &decision, &proving, &plan)?,
        )?;
        let (_, promotion_consumption) =
            completion_authority(&parsed_authority, AuthorityAction::AdoptImport)?;
        let (_, observation_consumption) =
            completion_authority(&parsed_authority, AuthorityAction::ObserveImport)?;
        let (_, rollback_consumption) =
            completion_authority(&parsed_authority, AuthorityAction::RollbackImport)?;
        let cycle: ReceiverM5CycleEvidence =
            parse_canonical(&self.m5_cycle_bytes, MAX_RECORD_BYTES)?;
        cycle.validate(
            &request,
            &decision,
            promotion_consumption,
            observation_consumption,
            rollback_consumption,
            &plan,
        )?;
        let receipt: ReceiverAdoptionReceipt =
            parse_canonical(&self.adoption_receipt_bytes, MAX_RECORD_BYTES)?;
        receipt.validate(
            &request,
            &projection.intent.request_digest,
            &decision,
            promotion_consumption,
            observation_consumption,
            rollback_consumption,
            &plan,
            &cycle,
        )?;
        let pre_activation: ReceiverM5PreActivationProbeV1 =
            parse_canonical(&self.pre_activation_probe_bytes, MAX_RECORD_BYTES)?;
        pre_activation.validate(&request.logical_operation_id, &active, &suite)?;
        validate_completion_activation_observation(&cycle, &plan)?;
        match (
            self.disposition,
            self.behavior_change_bytes.as_deref(),
            self.post_rollback_probe_bytes.as_deref(),
        ) {
            (ReceiverM5Disposition::Healthy, Some(behavior_bytes), None) => {
                let behavior: ReceiverM5BehaviorChangeEvidenceV1 =
                    parse_canonical(behavior_bytes, MAX_RECORD_BYTES)?;
                behavior.validate(&request, &active, &plan, &cycle, &suite)?;
                if behavior.pre_activation_probe != pre_activation {
                    return Err(M6ReceiverError::Integrity(
                        "healthy behavior evidence changed its durable pre-activation probe"
                            .to_string(),
                    ));
                }
            }
            (ReceiverM5Disposition::RolledBack, None, Some(bytes)) => {
                let probe = M5PostRollbackProbeV1::from_canonical_bytes(bytes)?;
                let recovery = cycle
                    .cycle_record
                    .recovery_receipt
                    .as_ref()
                    .ok_or_else(|| {
                        M6ReceiverError::Integrity(
                            "rolled-back completion lacks recovery receipt".to_string(),
                        )
                    })?;
                if probe.cycle_id() != cycle.cycle_id
                    || probe.cycle_record_digest() != &cycle.cycle_record.record_digest
                    || probe.recovery_receipt_digest() != &recovery.receipt_digest
                    || probe.restored_package_digest() != &request.expected_active_package_digest
                    || probe.active_snapshot_digest() != &request.expected_active_snapshot_digest
                {
                    return Err(M6ReceiverError::Integrity(
                        "post-rollback behavior probe differs from the exact recovery".to_string(),
                    ));
                }
                validate_execution_against_package(
                    probe.execution(),
                    &pre_activation.active_package_bytes,
                    &suite,
                )?;
            }
            _ => {
                return Err(M6ReceiverError::Integrity(
                    "completion disposition has the wrong before/after or rollback behavior sources"
                        .to_string(),
                ));
            }
        }
        let ack_request: ReceiverAcknowledgementRequest =
            parse_canonical(&self.acknowledgement_request_bytes, MAX_RECORD_BYTES)?;
        ack_request.validate(&request, route)?;
        if ack_request.receiver_transaction_digest != terminal.stage_digest
            || ack_request.disposition
                != match self.disposition {
                    ReceiverM5Disposition::Healthy => "healthy",
                    ReceiverM5Disposition::RolledBack => "rolled_back",
                    ReceiverM5Disposition::ValidationRejected => unreachable!(),
                }
        {
            return Err(M6ReceiverError::Integrity(
                "completion acknowledgement differs from terminal disposition".to_string(),
            ));
        }
        let ack_manifest =
            SignedManifest::from_canonical_bytes(&self.acknowledgement_manifest_bytes)?;
        let issued_ack = IssuedManifest {
            attachments: BTreeMap::new(),
            manifest: ack_manifest,
        };
        let ack_receipt: ReceiverAcknowledgementReceipt =
            parse_canonical(&self.acknowledgement_receipt_bytes, MAX_RECORD_BYTES)?;
        let ack_delivery = ack_delivery_digest(&issued_ack)?;
        ack_receipt.validate(
            &ack_request,
            &issued_ack,
            route,
            &ack_receipt.issuance_request_digest,
            &ack_delivery,
        )?;
        if self.logical_operation_id != request.logical_operation_id
            || self.message_digest != request.message_digest
            || self.export_bundle_digest != *verified.export_bundle_digest()
            || self.source_package_digest != *verified.source_package_digest()
            || self.receiver_local_package_digest != *plan.receiver_local_package_digest()
            || self.proving_digest != *proving.report_digest()
            || self.import_plan_digest != *plan.import_plan_digest()
            || self.prior_active_snapshot_digest != active.snapshot().snapshot_digest
            || self.final_active_snapshot_digest != cycle.active_snapshot.snapshot_digest
            || self.disposition != cycle.disposition
            || self.adoption_receipt_digest != receipt.receipt_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver completion projection is stale or cross-linked".to_string(),
            ));
        }
        Ok(())
    }

    fn coordinator_request_digest_from_sources(
        &self,
        request: &ReceiverIntakeRequest,
    ) -> Result<ContentDigest, M6ReceiverError> {
        let projection =
            TransactionProjection::from_canonical_bytes(&self.coordinator_projection_bytes)?;
        if projection.intent.logical_operation_id != request.logical_operation_id {
            return Err(M6ReceiverError::Integrity(
                "completion transaction belongs to another intake".to_string(),
            ));
        }
        Ok(projection.intent.request_digest)
    }

    fn validate_live<V: OpaqueAuthorizationVerifier>(
        &self,
        runtime: &M6ReceiverRuntime<V>,
    ) -> Result<(), M6ReceiverError> {
        self.validate_detached(runtime.route())?;
        for source in &self.authority_sources {
            let store = match source.action {
                AuthorityAction::IntakePackage => &runtime.intake_authority,
                AuthorityAction::ProveImport => &runtime.proving_authority,
                AuthorityAction::GrantImportApproval => &runtime.approval_authority,
                AuthorityAction::AdoptImport => &runtime.promotion_authority,
                AuthorityAction::ObserveImport => &runtime.observation_authority,
                AuthorityAction::RollbackImport => &runtime.rollback_authority,
                action => {
                    return Err(M6ReceiverError::Integrity(format!(
                        "unsupported live completion authority action {action:?}"
                    )));
                }
            };
            source.validate_live(store)?;
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            COMPLETION_EVIDENCE_DOMAIN,
            &(
                (
                    &self.schema,
                    &self.logical_operation_id,
                    &self.route_definition_digest,
                    &self.signing_key_id,
                    &self.sender_factory_id,
                    &self.receiver_factory_id,
                    &self.message_digest,
                    &self.export_bundle_digest,
                    &self.source_package_digest,
                    &self.receiver_local_package_digest,
                ),
                (
                    &self.proving_digest,
                    &self.import_plan_digest,
                    &self.prior_active_snapshot_digest,
                    &self.final_active_snapshot_digest,
                    self.disposition,
                    self.terminal_stage,
                    &self.terminal_stage_digest,
                    &self.adoption_receipt_digest,
                ),
                &self.source_digests,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverQuarantineOperationAuditV1 {
    transaction_kind: ReceiverInboundTransactionKindV1,
    logical_operation_id: String,
    message_digest: ContentDigest,
    outer_request_digest: ContentDigest,
    coordinator_request_digest: ContentDigest,
    current_stage: TransactionStage,
    request_bytes: Vec<u8>,
    coordinator_projection_bytes: Vec<u8>,
    raw_quarantine_bytes: Option<Vec<u8>>,
    unresolved_raw_unit_files: Option<BTreeMap<String, Vec<u8>>>,
    operation_digest: ContentDigest,
}

impl ReceiverQuarantineOperationAuditV1 {
    pub fn transaction_kind(&self) -> ReceiverInboundTransactionKindV1 {
        self.transaction_kind
    }

    pub fn logical_operation_id(&self) -> &str {
        &self.logical_operation_id
    }

    pub fn message_digest(&self) -> &ContentDigest {
        &self.message_digest
    }

    pub fn current_stage(&self) -> TransactionStage {
        self.current_stage
    }

    pub fn unresolved(&self) -> bool {
        self.raw_quarantine_bytes.is_some() && !self.current_stage.is_terminal()
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        validate_identifier(
            "receiver quarantine-inventory operation id",
            &self.logical_operation_id,
        )?;
        let projection =
            TransactionProjection::from_canonical_bytes(&self.coordinator_projection_bytes)?;
        let expected_kind = match self.transaction_kind {
            ReceiverInboundTransactionKindV1::Import => TransactionKind::ReceiverIntake,
            ReceiverInboundTransactionKindV1::Revocation => {
                TransactionKind::ReceiverRevocationApplication
            }
        };
        if projection.intent.kind != expected_kind
            || projection.intent.logical_operation_id != self.logical_operation_id
            || projection.intent.request_digest != self.coordinator_request_digest
            || projection.current_stage() != Some(self.current_stage)
        {
            return Err(M6ReceiverError::Integrity(
                "quarantine inventory operation differs from its coordinator projection"
                    .to_string(),
            ));
        }
        match self.transaction_kind {
            ReceiverInboundTransactionKindV1::Import => {
                let request: ReceiverIntakeRequest =
                    parse_canonical(&self.request_bytes, MAX_REQUEST_BYTES)?;
                if request.schema != RECEIVER_INTAKE_REQUEST_SCHEMA
                    || request.logical_operation_id != self.logical_operation_id
                    || request.message_digest != self.message_digest
                    || request.request_digest != self.outer_request_digest
                    || request.route_id != route.route_id
                    || request.route_generation != route.generation
                    || request.route_definition_digest != route.definition_digest
                {
                    return Err(M6ReceiverError::Integrity(
                        "quarantine inventory import request is cross-linked".to_string(),
                    ));
                }
                require_digest(
                    "quarantine inventory import request",
                    &request.request_digest,
                    &request.expected_digest()?,
                )?;
            }
            ReceiverInboundTransactionKindV1::Revocation => {
                let request: ReceiverRevocationRequest =
                    parse_canonical(&self.request_bytes, MAX_REQUEST_BYTES)?;
                request.validate(route, &request.revocation_policy_digest)?;
                if request.logical_operation_id != self.logical_operation_id
                    || request.message_digest != self.message_digest
                    || request.request_digest != self.outer_request_digest
                {
                    return Err(M6ReceiverError::Integrity(
                        "quarantine inventory revocation request is cross-linked".to_string(),
                    ));
                }
            }
        }
        match (
            self.raw_quarantine_bytes.as_deref(),
            self.unresolved_raw_unit_files.as_ref(),
            self.current_stage.is_terminal(),
        ) {
            (None, None, _)
                if matches!(
                    self.current_stage,
                    TransactionStage::IntakeIntentRecorded
                        | TransactionStage::RevocationIntakeIntentRecorded
                        | TransactionStage::RawAdmissionRejected
                        | TransactionStage::ValidationRejected
                ) => {}
            (Some(raw_bytes), None, true) => {
                let raw = RawQuarantineRecord::from_canonical_bytes(raw_bytes, route)?;
                if raw.intake_operation_id != self.logical_operation_id {
                    return Err(M6ReceiverError::Integrity(
                        "terminal quarantine record belongs to another operation".to_string(),
                    ));
                }
            }
            (Some(raw_bytes), Some(files), false) => {
                let raw = RawQuarantineRecord::from_canonical_bytes(raw_bytes, route)?;
                if raw.intake_operation_id != self.logical_operation_id {
                    return Err(M6ReceiverError::Integrity(
                        "unresolved quarantine record belongs to another operation".to_string(),
                    ));
                }
                validate_portable_raw_unit_files(&raw, files)?;
            }
            _ => {
                return Err(M6ReceiverError::Integrity(
                    "quarantine inventory has the wrong raw-unit evidence for its terminal state"
                        .to_string(),
                ));
            }
        }
        require_digest(
            "receiver quarantine operation audit",
            &self.operation_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            QUARANTINE_INVENTORY_DOMAIN,
            &(
                "operation",
                self.transaction_kind,
                &self.logical_operation_id,
                &self.message_digest,
                &self.outer_request_digest,
                &self.coordinator_request_digest,
                self.current_stage,
                ContentDigest::from_bytes(&self.request_bytes),
                ContentDigest::from_bytes(&self.coordinator_projection_bytes),
                self.raw_quarantine_bytes
                    .as_deref()
                    .map(ContentDigest::from_bytes),
                self.unresolved_raw_unit_files
                    .as_ref()
                    .map(canonical_json)
                    .transpose()?
                    .as_deref()
                    .map(ContentDigest::from_bytes),
            ),
        )
    }
}

/// Receiver-signed scan of every durable receiver import/revocation
/// transaction. Unresolved quarantine is derived only from an exact
/// nonterminal projection that owns committed raw bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverUnresolvedQuarantineInventoryV1 {
    schema: String,
    receiver_factory_id: String,
    route_definition_digest: ContentDigest,
    signing_key_id: String,
    durable_state_digest: ContentDigest,
    operations: Vec<ReceiverQuarantineOperationAuditV1>,
    unresolved_operation_digests: Vec<ContentDigest>,
    scanned_at_ms: u64,
    inventory_digest: ContentDigest,
    signature_hex: String,
}

impl ReceiverUnresolvedQuarantineInventoryV1 {
    pub fn durable_state_digest(&self) -> &ContentDigest {
        &self.durable_state_digest
    }

    pub fn operations(&self) -> &[ReceiverQuarantineOperationAuditV1] {
        &self.operations
    }

    pub fn unresolved_operation_digests(&self) -> &[ContentDigest] {
        &self.unresolved_operation_digests
    }

    pub fn unresolved_count(&self) -> usize {
        self.unresolved_operation_digests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.unresolved_operation_digests.is_empty()
    }

    pub fn inventory_digest(&self) -> &ContentDigest {
        &self.inventory_digest
    }

    pub fn canonical_bytes_detached(
        &self,
        route: &RouteDefinition,
    ) -> Result<Vec<u8>, M6ReceiverError> {
        self.validate(route)?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_COMPLETION_EVIDENCE_BYTES {
            return Err(M6ReceiverError::ResourceExhausted(
                "receiver quarantine inventory exceeds its byte budget".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes_detached(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6ReceiverError> {
        let inventory: Self = parse_canonical(bytes, MAX_COMPLETION_EVIDENCE_BYTES)?;
        inventory.validate(route)?;
        Ok(inventory)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_UNRESOLVED_QUARANTINE_INVENTORY_SCHEMA
            || self.receiver_factory_id != route.receiver.factory_id
            || self.route_definition_digest != route.definition_digest
            || self.signing_key_id != route.receiver.signing_key_id
            || self.operations.len() > MAX_DURABLE_STATE_ENTRIES
            || !self.operations.windows(2).all(|pair| {
                (
                    pair[0].transaction_kind,
                    pair[0].logical_operation_id.as_str(),
                ) < (
                    pair[1].transaction_kind,
                    pair[1].logical_operation_id.as_str(),
                )
            })
        {
            return Err(M6ReceiverError::Integrity(
                "receiver quarantine inventory is outside its exact bounded route schema"
                    .to_string(),
            ));
        }
        for operation in &self.operations {
            operation.validate(route)?;
        }
        let expected_unresolved = self
            .operations
            .iter()
            .filter(|operation| operation.unresolved())
            .map(|operation| operation.operation_digest.clone())
            .collect::<Vec<_>>();
        if self.unresolved_operation_digests != expected_unresolved {
            return Err(M6ReceiverError::Integrity(
                "receiver quarantine inventory unresolved set is not source-derived".to_string(),
            ));
        }
        require_digest(
            "receiver quarantine inventory",
            &self.inventory_digest,
            &self.expected_digest()?,
        )?;
        verify_receiver_quarantine_inventory_signature(
            route,
            &self.signing_key_id,
            &self.inventory_digest,
            &self.signature_hex,
        )
        .map_err(M6ReceiverError::from)
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            QUARANTINE_INVENTORY_DOMAIN,
            &(
                "inventory",
                &self.schema,
                &self.receiver_factory_id,
                &self.route_definition_digest,
                &self.signing_key_id,
                &self.durable_state_digest,
                &self.operations,
                &self.unresolved_operation_digests,
                self.scanned_at_ms,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverReopenRecoveredExchangeV1 {
    logical_operation_id: String,
    message_digest: ContentDigest,
    disposition: ReceiverM5Disposition,
    terminal_stage_digest: ContentDigest,
    adoption_receipt_digest: ContentDigest,
    request_bytes: Vec<u8>,
    coordinator_projection_bytes: Vec<u8>,
    adoption_receipt_bytes: Vec<u8>,
    recovered_digest: ContentDigest,
}

impl ReceiverReopenRecoveredExchangeV1 {
    pub fn logical_operation_id(&self) -> &str {
        &self.logical_operation_id
    }

    pub fn message_digest(&self) -> &ContentDigest {
        &self.message_digest
    }

    pub fn disposition(&self) -> ReceiverM5Disposition {
        self.disposition
    }

    pub fn adoption_receipt_digest(&self) -> &ContentDigest {
        &self.adoption_receipt_digest
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        validate_identifier(
            "receiver reopen recovered operation id",
            &self.logical_operation_id,
        )?;
        let request: ReceiverIntakeRequest =
            parse_canonical(&self.request_bytes, MAX_REQUEST_BYTES)?;
        let projection =
            TransactionProjection::from_canonical_bytes(&self.coordinator_projection_bytes)?;
        let receipt: ReceiverAdoptionReceipt =
            parse_canonical(&self.adoption_receipt_bytes, MAX_RECORD_BYTES)?;
        require_digest(
            "reopened receiver adoption receipt",
            &receipt.receipt_digest,
            &receipt.expected_digest()?,
        )?;
        let expected_stage = match self.disposition {
            ReceiverM5Disposition::Healthy => TransactionStage::Healthy,
            ReceiverM5Disposition::RolledBack => TransactionStage::RolledBack,
            ReceiverM5Disposition::ValidationRejected => {
                return Err(M6ReceiverError::Integrity(
                    "validation rejection is not a recovered adoption".to_string(),
                ));
            }
        };
        let terminal = projection.current_record().ok_or_else(|| {
            M6ReceiverError::Integrity(
                "reopened receiver exchange lacks terminal coordinator state".to_string(),
            )
        })?;
        if request.schema != RECEIVER_INTAKE_REQUEST_SCHEMA
            || request.route_id != route.route_id
            || request.route_generation != route.generation
            || request.route_definition_digest != route.definition_digest
            || projection.intent.kind != TransactionKind::ReceiverIntake
            || projection.intent.logical_operation_id != self.logical_operation_id
            || receipt.logical_operation_id != self.logical_operation_id
            || receipt.coordinator_request_digest != projection.intent.request_digest
            || receipt.message_digest != request.message_digest
            || receipt.disposition != self.disposition
            || terminal.stage != expected_stage
            || self.logical_operation_id != request.logical_operation_id
            || self.message_digest != request.message_digest
            || self.terminal_stage_digest != terminal.stage_digest
            || self.adoption_receipt_digest != receipt.receipt_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver reopen recovered exchange is stale or cross-linked".to_string(),
            ));
        }
        require_digest(
            "recovered receiver exchange",
            &self.recovered_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REOPEN_AUDIT_DOMAIN,
            &(
                "exchange",
                &self.logical_operation_id,
                &self.message_digest,
                self.disposition,
                &self.terminal_stage_digest,
                &self.adoption_receipt_digest,
                ContentDigest::from_bytes(&self.request_bytes),
                ContentDigest::from_bytes(&self.coordinator_projection_bytes),
                ContentDigest::from_bytes(&self.adoption_receipt_bytes),
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverReopenAuditV1 {
    schema: String,
    receiver_factory_id: String,
    route_definition_digest: ContentDigest,
    signing_key_id: String,
    open_ordinal: u64,
    previous_audit_digest: Option<ContentDigest>,
    previous_process_instance_id: Option<String>,
    current_process_instance_id: String,
    pre_open_state_digest: ContentDigest,
    post_reconciliation_state_digest: ContentDigest,
    recovered_exchanges: Vec<ReceiverReopenRecoveredExchangeV1>,
    quarantine_inventory_bytes: Vec<u8>,
    quarantine_inventory_digest: ContentDigest,
    opened_at_ms: u64,
    audit_digest: ContentDigest,
    signature_hex: String,
}

impl ReceiverReopenAuditV1 {
    pub fn open_ordinal(&self) -> u64 {
        self.open_ordinal
    }

    pub fn current_process_instance_id(&self) -> &str {
        &self.current_process_instance_id
    }

    pub fn recovered_exchanges(&self) -> &[ReceiverReopenRecoveredExchangeV1] {
        &self.recovered_exchanges
    }

    pub fn quarantine_inventory_digest(&self) -> &ContentDigest {
        &self.quarantine_inventory_digest
    }

    pub fn audit_digest(&self) -> &ContentDigest {
        &self.audit_digest
    }

    pub fn canonical_bytes(&self, route: &RouteDefinition) -> Result<Vec<u8>, M6ReceiverError> {
        self.validate(route)?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_REOPEN_AUDIT_BYTES {
            return Err(M6ReceiverError::ResourceExhausted(
                "receiver reopen audit exceeds its byte budget".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6ReceiverError> {
        let audit: Self = parse_canonical(bytes, MAX_REOPEN_AUDIT_BYTES)?;
        audit.validate(route)?;
        Ok(audit)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_REOPEN_AUDIT_SCHEMA
            || self.receiver_factory_id != route.receiver.factory_id
            || self.route_definition_digest != route.definition_digest
            || self.signing_key_id != route.receiver.signing_key_id
            || self.open_ordinal == 0
        {
            return Err(M6ReceiverError::Integrity(
                "receiver reopen audit is outside its exact route schema".to_string(),
            ));
        }
        validate_identifier(
            "current receiver process instance id",
            &self.current_process_instance_id,
        )?;
        match (
            self.open_ordinal,
            &self.previous_audit_digest,
            &self.previous_process_instance_id,
        ) {
            (1, None, None) => {}
            (ordinal, Some(_), Some(previous))
                if ordinal > 1 && previous != &self.current_process_instance_id =>
            {
                validate_identifier("previous receiver process instance id", previous)?;
            }
            _ => {
                return Err(M6ReceiverError::Integrity(
                    "receiver reopen audit lacks a distinct prior process instance".to_string(),
                ));
            }
        }
        if self.recovered_exchanges.len() > MAX_DURABLE_STATE_ENTRIES
            || !self
                .recovered_exchanges
                .windows(2)
                .all(|pair| pair[0].logical_operation_id < pair[1].logical_operation_id)
        {
            return Err(M6ReceiverError::Integrity(
                "receiver reopen recovered exchange set is not bounded, sorted, and unique"
                    .to_string(),
            ));
        }
        for recovered in &self.recovered_exchanges {
            recovered.validate(route)?;
        }
        let inventory = ReceiverUnresolvedQuarantineInventoryV1::from_canonical_bytes_detached(
            &self.quarantine_inventory_bytes,
            route,
        )?;
        if inventory.inventory_digest != self.quarantine_inventory_digest
            || inventory.durable_state_digest != self.post_reconciliation_state_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver reopen inventory differs from reconciled durable state".to_string(),
            ));
        }
        require_digest(
            "receiver reopen audit",
            &self.audit_digest,
            &self.expected_digest()?,
        )?;
        verify_receiver_reopen_audit_signature(
            route,
            &self.signing_key_id,
            &self.audit_digest,
            &self.signature_hex,
        )
        .map_err(M6ReceiverError::from)
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REOPEN_AUDIT_DOMAIN,
            &(
                (
                    &self.schema,
                    &self.receiver_factory_id,
                    &self.route_definition_digest,
                    &self.signing_key_id,
                    self.open_ordinal,
                    &self.previous_audit_digest,
                    &self.previous_process_instance_id,
                    &self.current_process_instance_id,
                ),
                (
                    &self.pre_open_state_digest,
                    &self.post_reconciliation_state_digest,
                    &self.recovered_exchanges,
                    ContentDigest::from_bytes(&self.quarantine_inventory_bytes),
                    &self.quarantine_inventory_digest,
                    self.opened_at_ms,
                ),
            ),
        )
    }
}

/// Exact adjacent signed receiver-open audits. The current audit embeds the
/// full signed quarantine scan and all recovered terminal adoption receipts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverReopenProofV1 {
    schema: String,
    receiver_factory_id: String,
    route_definition_digest: ContentDigest,
    previous_audit_digest: ContentDigest,
    current_audit_digest: ContentDigest,
    previous_audit_bytes: Vec<u8>,
    current_audit_bytes: Vec<u8>,
    proof_digest: ContentDigest,
}

impl ReceiverReopenProofV1 {
    pub fn previous_audit_digest(&self) -> &ContentDigest {
        &self.previous_audit_digest
    }

    pub fn current_audit_digest(&self) -> &ContentDigest {
        &self.current_audit_digest
    }

    pub fn proof_digest(&self) -> &ContentDigest {
        &self.proof_digest
    }

    pub fn canonical_bytes_detached(
        &self,
        route: &RouteDefinition,
    ) -> Result<Vec<u8>, M6ReceiverError> {
        self.validate(route)?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes_detached(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6ReceiverError> {
        let proof: Self = parse_canonical(bytes, 2 * MAX_REOPEN_AUDIT_BYTES)?;
        proof.validate(route)?;
        Ok(proof)
    }

    pub fn proves_restart_of(
        &self,
        route: &RouteDefinition,
        logical_operation_id: &str,
        adoption_receipt_digest: &ContentDigest,
    ) -> Result<bool, M6ReceiverError> {
        self.validate(route)?;
        let current =
            ReceiverReopenAuditV1::from_canonical_bytes(&self.current_audit_bytes, route)?;
        Ok(current.recovered_exchanges.iter().any(|recovered| {
            recovered.logical_operation_id == logical_operation_id
                && &recovered.adoption_receipt_digest == adoption_receipt_digest
        }))
    }

    pub fn current_quarantine_inventory(
        &self,
        route: &RouteDefinition,
    ) -> Result<ReceiverUnresolvedQuarantineInventoryV1, M6ReceiverError> {
        self.validate(route)?;
        let current =
            ReceiverReopenAuditV1::from_canonical_bytes(&self.current_audit_bytes, route)?;
        ReceiverUnresolvedQuarantineInventoryV1::from_canonical_bytes_detached(
            &current.quarantine_inventory_bytes,
            route,
        )
    }

    pub fn proves_zero_unresolved_quarantine(
        &self,
        route: &RouteDefinition,
    ) -> Result<bool, M6ReceiverError> {
        Ok(self.current_quarantine_inventory(route)?.is_empty())
    }

    fn from_adjacent(
        route: &RouteDefinition,
        previous: &ReceiverReopenAuditV1,
        current: &ReceiverReopenAuditV1,
    ) -> Result<Self, M6ReceiverError> {
        let previous_audit_bytes = previous.canonical_bytes(route)?;
        let current_audit_bytes = current.canonical_bytes(route)?;
        let mut proof = Self {
            schema: RECEIVER_REOPEN_PROOF_SCHEMA.to_string(),
            receiver_factory_id: route.receiver.factory_id.clone(),
            route_definition_digest: route.definition_digest.clone(),
            previous_audit_digest: previous.audit_digest.clone(),
            current_audit_digest: current.audit_digest.clone(),
            previous_audit_bytes,
            current_audit_bytes,
            proof_digest: ContentDigest::from_bytes(&[]),
        };
        proof.proof_digest = proof.expected_digest()?;
        proof.validate(route)?;
        Ok(proof)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_REOPEN_PROOF_SCHEMA
            || self.receiver_factory_id != route.receiver.factory_id
            || self.route_definition_digest != route.definition_digest
            || self.previous_audit_bytes.is_empty()
            || self.current_audit_bytes.is_empty()
            || self.previous_audit_bytes.len() > MAX_REOPEN_AUDIT_BYTES
            || self.current_audit_bytes.len() > MAX_REOPEN_AUDIT_BYTES
        {
            return Err(M6ReceiverError::Integrity(
                "receiver reopen proof is outside its exact bounded route schema".to_string(),
            ));
        }
        let previous =
            ReceiverReopenAuditV1::from_canonical_bytes(&self.previous_audit_bytes, route)?;
        let current =
            ReceiverReopenAuditV1::from_canonical_bytes(&self.current_audit_bytes, route)?;
        if self.previous_audit_digest != previous.audit_digest
            || self.current_audit_digest != current.audit_digest
            || current.open_ordinal != previous.open_ordinal.saturating_add(1)
            || current.previous_audit_digest.as_ref() != Some(&previous.audit_digest)
            || current.previous_process_instance_id.as_deref()
                != Some(previous.current_process_instance_id.as_str())
            || current.current_process_instance_id == previous.current_process_instance_id
        {
            return Err(M6ReceiverError::Integrity(
                "receiver reopen proof lacks an exact adjacent distinct-instance audit chain"
                    .to_string(),
            ));
        }
        require_digest(
            "receiver reopen proof",
            &self.proof_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REOPEN_PROOF_DOMAIN,
            &(
                &self.schema,
                &self.receiver_factory_id,
                &self.route_definition_digest,
                &self.previous_audit_digest,
                &self.current_audit_digest,
                ContentDigest::from_bytes(&self.previous_audit_bytes),
                ContentDigest::from_bytes(&self.current_audit_bytes),
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiverCrashPoint {
    OuterRequestPersisted,
    IntakeIntentRecorded,
    IntakeAuthorizationConsumed,
    RawAdmissionCommitted,
    RawQuarantinedStage,
    SenderAuthenticated,
    ReplayCommitted,
    ReplayStageCommitted,
    SenderEvidenceRecordsCommitted,
    SenderEvidenceVerified,
    ProvingAuthorizationConsumed,
    ProvingRecordCommitted,
    ReceiverProvingCommitted,
    ImportPlanCommitted,
    ApprovalRequestCommitted,
    AwaitingApproval,
    ApprovalDecisionCommitted,
    ApprovalTerminalCommitted,
    PromotionAuthorizationConsumed,
    ObservationAuthorizationConsumed,
    RollbackAuthorizationConsumed,
    ActivationIntentRecorded,
    M5CycleCommitted,
    ActivationEffectCommitted,
    ObservationIntentRecorded,
    HealthyCommitted,
    RollbackIntentRecorded,
    RolledBackCommitted,
    AdoptionReceiptCommitted,
    AcknowledgementRequestCommitted,
    AcknowledgementPrepared,
    AcknowledgementChainCommitted,
    AcknowledgementRouteStaged,
    AcknowledgementRouteReady,
    AcknowledgementReceiptCommitted,
    RevocationRequestPersisted,
    RevocationIntakeIntentRecorded,
    RevocationRawAdmissionCommitted,
    RevocationRawQuarantined,
    RevocationAuthenticated,
    RevocationReplayCommitted,
    RevocationTombstoneCommitted,
    RevocationAffectedImportsCommitted,
    RevocationContainmentIntentRecorded,
    RevocationContainmentEffectsCommitted,
    RevocationTerminalCommitted,
}

pub struct M6ReceiverRuntime<V: OpaqueAuthorizationVerifier> {
    endpoint_root: PathBuf,
    operations_root: PathBuf,
    revocation_operations_root: PathBuf,
    message_claims_root: PathBuf,
    control_rejections_root: PathBuf,
    reopen_audits_root: PathBuf,
    max_intake_operations: u32,
    retry_policy: RetryPolicy,
    clock: Arc<dyn Clock>,
    signer: FactorySigner,
    import_policy: ReceiverImportPolicyV1,
    intake_authority: AuthorizationStore<V>,
    proving_authority: AuthorizationStore<V>,
    approval_authority: AuthorizationStore<V>,
    promotion_authority: AuthorizationStore<V>,
    observation_authority: AuthorizationStore<V>,
    rollback_authority: AuthorizationStore<V>,
    m5: M5Runtime,
    spool: GovernedFilesystemSpool,
    quarantine: ReceiverRawQuarantine,
    replay: ReplayJournal,
    acknowledgement_issuer: ManifestIssuer,
    journal: CoordinatorJournal,
    revocations: ReceiverRevocationLedger,
    latest_reopen_audit: ReceiverReopenAuditV1,
    _owner_lock: File,
}

impl<V: OpaqueAuthorizationVerifier> M6ReceiverRuntime<V> {
    pub fn open(
        config: M6ReceiverRuntimeConfig,
        verifiers: ReceiverAuthorityVerifiers<V>,
        signer: FactorySigner,
        clock: Arc<dyn Clock>,
        nonce_source: Arc<dyn NonceSource>,
        live_provider: Option<Arc<dyn LiveProviderQualificationPort>>,
    ) -> Result<Self, M6ReceiverError> {
        config.validate_non_path_fields()?;
        let endpoint_root = secure_create_root(&config.endpoint_root)?;
        let owner_lock = acquire_endpoint_owner(&endpoint_root)?;

        let m5_root = fs::canonicalize(&config.m5.root)
            .map_err(|source| M6ReceiverError::io(&config.m5.root, source))?;
        if m5_root == endpoint_root || !m5_root.starts_with(&endpoint_root) {
            return Err(M6ReceiverError::InvalidConfiguration(
                "the receiver M5 root must be a strict endpoint child".to_string(),
            ));
        }
        ensure_m5_root_isolated(&endpoint_root, &m5_root)?;

        // Endpoint ownership precedes every mutable child.
        let intake_authority = AuthorizationStore::open(
            endpoint_root.join(INTAKE_AUTHORITY_DIRECTORY),
            config.intake_authorization_profile,
            verifiers.intake,
        )?;
        let proving_authority = AuthorizationStore::open(
            endpoint_root.join(PROVING_AUTHORITY_DIRECTORY),
            config.proving_authorization_profile,
            verifiers.proving,
        )?;
        let approval_authority = AuthorizationStore::open(
            endpoint_root.join(APPROVAL_AUTHORITY_DIRECTORY),
            config.approval_authorization_profile,
            verifiers.approval,
        )?;
        let promotion_authority = AuthorizationStore::open(
            endpoint_root.join(PROMOTION_AUTHORITY_DIRECTORY),
            config.promotion_authorization_profile,
            verifiers.promotion,
        )?;
        let observation_authority = AuthorizationStore::open(
            endpoint_root.join(OBSERVATION_AUTHORITY_DIRECTORY),
            config.observation_authorization_profile,
            verifiers.observation,
        )?;
        let rollback_authority = AuthorizationStore::open(
            endpoint_root.join(ROLLBACK_AUTHORITY_DIRECTORY),
            config.rollback_authorization_profile,
            verifiers.rollback,
        )?;
        let m5 = M5Runtime::open(
            M5RuntimeConfig {
                root: m5_root,
                ..config.m5
            },
            live_provider,
        )?;
        let spool = GovernedFilesystemSpool::open(
            &config.route_root,
            &endpoint_root,
            RouteEndpointRole::Receiver,
            &config.expected_route_definition_digest,
        )?;
        let route = spool.route().clone();
        if route.receiver.factory_id != m5.config().factory_id
            || route.receiver.factory_id != config.import_policy.receiver_factory_id()
            || route.receiver.factory_id != intake_authority.profile().factory_id()
            || route.receiver.factory_id != proving_authority.profile().factory_id()
            || route.receiver.factory_id != approval_authority.profile().factory_id()
            || route.receiver.factory_id != promotion_authority.profile().factory_id()
            || route.receiver.factory_id != observation_authority.profile().factory_id()
            || route.receiver.factory_id != rollback_authority.profile().factory_id()
            || config.import_policy.source_factory_id() != route.sender.factory_id
            || config.max_intake_operations > route.resource_profile.max_replay_records
            || signer.signing_key_id() != route.receiver.signing_key_id
            || signer.public_key_hex() != route.receiver.public_key_hex
        {
            return Err(M6ReceiverError::InvalidConfiguration(
                "receiver M5, policy, route, authority identities, or bounds differ".to_string(),
            ));
        }
        config
            .journal_config
            .validate_for_resource_profile(&route.resource_profile)
            .map_err(M6ReceiverError::from)?;
        config
            .retry_policy
            .validate_for_resource_profile(&route.resource_profile)
            .map_err(M6ReceiverError::from)?;
        let operations_root = secure_child_directory(&endpoint_root, OPERATIONS_DIRECTORY)?;
        recover_building_directories(&operations_root)?;
        let revocation_operations_root =
            secure_child_directory(&endpoint_root, REVOCATION_OPERATIONS_DIRECTORY)?;
        recover_building_directories(&revocation_operations_root)?;
        let message_claims_root = secure_child_directory(&endpoint_root, MESSAGE_CLAIMS_DIRECTORY)?;
        let control_rejections_root =
            secure_child_directory(&endpoint_root, CONTROL_REJECTIONS_DIRECTORY)?;
        let reopen_audits_root = secure_child_directory(&endpoint_root, REOPEN_AUDITS_DIRECTORY)?;
        let pre_open_state_digest = receiver_durable_state_root(&endpoint_root, &m5.config().root)?;
        let quarantine = ReceiverRawQuarantine::open_or_initialize(
            &endpoint_root,
            route.clone(),
            Arc::clone(&clock),
        )?;
        let replay = ReplayJournal::open_or_initialize(
            &endpoint_root,
            route.clone(),
            RouteEndpointRole::Sender,
            Arc::clone(&clock),
        )?;
        let acknowledgement_issuer = ManifestIssuer::open_or_initialize(
            &endpoint_root,
            route.clone(),
            RouteEndpointRole::Receiver,
            Arc::clone(&clock),
            Arc::clone(&nonce_source),
        )?;
        let journal = CoordinatorJournal::open_or_initialize(
            endpoint_root.join(JOURNAL_DIRECTORY),
            config.journal_config,
            Arc::clone(&clock),
        )?;
        let revocations = ReceiverRevocationLedger::open_or_initialize(
            endpoint_root.join(REVOCATION_DIRECTORY),
            route.clone(),
            Arc::clone(&clock),
        )?;
        let post_reconciliation_state_digest =
            receiver_durable_state_root(&endpoint_root, &m5.config().root)?;
        let previous_audits = load_receiver_reopen_audit_chain(&reopen_audits_root, &route)?;
        let previous = previous_audits.last();
        let current_process_instance_id = generate_receiver_process_instance_id(
            nonce_source.as_ref(),
            previous.map(|audit| audit.current_process_instance_id.as_str()),
        )?;
        let recovered_exchanges = load_reopen_recovered_exchanges(
            &operations_root,
            &journal,
            &route,
            config.max_intake_operations,
        )?;
        let opened_at_ms = clock.now_ms().map_err(M6ReceiverError::from)?;
        let inventory = build_quarantine_inventory(
            &operations_root,
            &revocation_operations_root,
            &control_rejections_root,
            &journal,
            &quarantine,
            &route,
            &signer,
            post_reconciliation_state_digest.clone(),
            opened_at_ms,
        )?;
        let quarantine_inventory_bytes = inventory.canonical_bytes_detached(&route)?;
        let mut latest_reopen_audit = ReceiverReopenAuditV1 {
            schema: RECEIVER_REOPEN_AUDIT_SCHEMA.to_string(),
            receiver_factory_id: route.receiver.factory_id.clone(),
            route_definition_digest: route.definition_digest.clone(),
            signing_key_id: signer.signing_key_id().to_string(),
            open_ordinal: previous
                .map(|audit| audit.open_ordinal.saturating_add(1))
                .unwrap_or(1),
            previous_audit_digest: previous.map(|audit| audit.audit_digest.clone()),
            previous_process_instance_id: previous
                .map(|audit| audit.current_process_instance_id.clone()),
            current_process_instance_id,
            pre_open_state_digest,
            post_reconciliation_state_digest,
            recovered_exchanges,
            quarantine_inventory_bytes,
            quarantine_inventory_digest: inventory.inventory_digest.clone(),
            opened_at_ms,
            audit_digest: ContentDigest::from_bytes(&[]),
            signature_hex: String::new(),
        };
        latest_reopen_audit.audit_digest = latest_reopen_audit.expected_digest()?;
        latest_reopen_audit.signature_hex =
            signer.sign_receiver_reopen_audit(&route, &latest_reopen_audit.audit_digest)?;
        latest_reopen_audit.validate(&route)?;
        persist_receiver_reopen_audit(&reopen_audits_root, &latest_reopen_audit)?;

        Ok(Self {
            endpoint_root,
            operations_root,
            revocation_operations_root,
            message_claims_root,
            control_rejections_root,
            reopen_audits_root,
            max_intake_operations: config.max_intake_operations,
            retry_policy: config.retry_policy,
            clock,
            signer,
            import_policy: config.import_policy,
            intake_authority,
            proving_authority,
            approval_authority,
            promotion_authority,
            observation_authority,
            rollback_authority,
            m5,
            spool,
            quarantine,
            replay,
            acknowledgement_issuer,
            journal,
            revocations,
            latest_reopen_audit,
            _owner_lock: owner_lock,
        })
    }

    pub fn endpoint_root(&self) -> &Path {
        &self.endpoint_root
    }

    pub fn route(&self) -> &RouteDefinition {
        self.spool.route()
    }

    pub fn latest_reopen_audit(&self) -> &ReceiverReopenAuditV1 {
        &self.latest_reopen_audit
    }

    pub fn reopen_audit_chain(&self) -> Result<Vec<ReceiverReopenAuditV1>, M6ReceiverError> {
        load_receiver_reopen_audit_chain(&self.reopen_audits_root, self.route())
    }

    pub fn latest_reopen_proof(&self) -> Result<Option<ReceiverReopenProofV1>, M6ReceiverError> {
        let audits = self.reopen_audit_chain()?;
        if audits.len() < 2 {
            return Ok(None);
        }
        Ok(Some(ReceiverReopenProofV1::from_adjacent(
            self.route(),
            &audits[audits.len() - 2],
            &audits[audits.len() - 1],
        )?))
    }

    pub fn unresolved_quarantine_inventory(
        &self,
    ) -> Result<ReceiverUnresolvedQuarantineInventoryV1, M6ReceiverError> {
        build_quarantine_inventory(
            &self.operations_root,
            &self.revocation_operations_root,
            &self.control_rejections_root,
            &self.journal,
            &self.quarantine,
            self.route(),
            &self.signer,
            receiver_durable_state_root(&self.endpoint_root, &self.m5.config().root)?,
            self.now_ms()?,
        )
    }

    pub fn prepare_intake(
        &self,
        logical_operation_id: impl Into<String>,
        principal_id: impl Into<String>,
        message_digest: ContentDigest,
        deadline_ms: u64,
    ) -> Result<PreparedReceiverIntake, M6ReceiverError> {
        self.prepare_intake_with_fault(
            logical_operation_id,
            principal_id,
            message_digest,
            deadline_ms,
            None,
        )
    }

    pub fn prepare_intake_with_fault(
        &self,
        logical_operation_id: impl Into<String>,
        principal_id: impl Into<String>,
        message_digest: ContentDigest,
        deadline_ms: u64,
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<PreparedReceiverIntake, M6ReceiverError> {
        let logical_operation_id = logical_operation_id.into();
        let principal_id = principal_id.into();
        validate_identifier("receiver intake operation id", &logical_operation_id)?;
        validate_identifier("receiver intake principal", &principal_id)?;
        self.require_no_other_pending_operation(&logical_operation_id)?;
        let operation_root = operation_root(&self.operations_root, &logical_operation_id);
        let (request, active) = if operation_root.exists() {
            let (request, active) =
                load_request_unit(&operation_root, self.route(), &self.import_policy)?;
            if request.logical_operation_id != logical_operation_id
                || request.principal_id != principal_id
                || request.message_digest != message_digest
                || request.deadline_ms != deadline_ms
            {
                return Err(M6ReceiverError::Conflict {
                    identity: logical_operation_id,
                    existing: request.request_digest,
                    requested: ContentDigest::from_bytes(&canonical_json(&(
                        principal_id,
                        message_digest,
                        deadline_ms,
                    ))?),
                });
            }
            (request, active)
        } else {
            enforce_operation_bound(&self.operations_root, self.max_intake_operations)?;
            let active = self.capture_active_state()?;
            let captured_at_ms = self.now_ms()?;
            let request = ReceiverIntakeRequest::new(
                logical_operation_id.clone(),
                principal_id,
                captured_at_ms,
                deadline_ms,
                message_digest,
                self.route(),
                &active,
                &self.import_policy,
            )?;
            persist_request_unit(&operation_root, &request, &active)?;
            maybe_crash(crash_at, ReceiverCrashPoint::OuterRequestPersisted)?;
            (request, active)
        };

        let initial = self.journal.begin(
            self.transaction_draft(&request),
            stage_evidence(
                StageCause::Normal,
                0,
                None,
                None,
                vec![
                    request.request_digest.clone(),
                    request.active_state_digest.clone(),
                    request.route_definition_digest.clone(),
                ],
                None,
                None,
            )?,
        )?;
        maybe_crash(crash_at, ReceiverCrashPoint::IntakeIntentRecorded)?;
        request.validate(self.route(), &active, &self.import_policy)?;
        Ok(PreparedReceiverIntake {
            logical_operation_id: request.logical_operation_id.clone(),
            outer_request_digest: request.request_digest.clone(),
            coordinator_request_digest: initial.request_digest,
            message_digest: request.message_digest.clone(),
            expected_active_snapshot_digest: request.expected_active_snapshot_digest.clone(),
            authorization_binding: intake_binding(&request),
        })
    }

    pub fn publish_authorization(
        &self,
        authorization: ActionAuthorization,
    ) -> Result<ContentDigest, M6ReceiverError> {
        let store = match authorization.binding().action {
            AuthorityAction::IntakePackage => &self.intake_authority,
            AuthorityAction::ProveImport => &self.proving_authority,
            AuthorityAction::GrantImportApproval
            | AuthorityAction::DenyImportApproval
            | AuthorityAction::ExpireImportApproval
            | AuthorityAction::EscalateImportApproval => &self.approval_authority,
            AuthorityAction::AdoptImport => &self.promotion_authority,
            AuthorityAction::ObserveImport => &self.observation_authority,
            AuthorityAction::RollbackImport => &self.rollback_authority,
            action => {
                return Err(M6ReceiverError::Authority(format!(
                    "receiver runtime does not accept {action:?} authorization"
                )));
            }
        };
        let published = store.publish_authorization(authorization)?;
        Ok(published.authorization_digest().clone())
    }

    fn capture_active_state(&self) -> Result<ReceiverActiveStateV1, M6ReceiverError> {
        let snapshot = self.m5.active_runtime_snapshot()?;
        let package = self.m5.active_package()?;
        let package_bytes = package
            .canonical_bytes()
            .map_err(|error| M6ReceiverError::M5(error.to_string()))?;
        ReceiverActiveStateV1::new(snapshot, package_bytes).map_err(M6ReceiverError::from)
    }

    fn now_ms(&self) -> Result<u64, M6ReceiverError> {
        self.clock
            .now_ms()
            .map_err(|error| M6ReceiverError::Identity(error.to_string()))
    }

    fn transaction_draft(&self, request: &ReceiverIntakeRequest) -> TransactionRequestDraft {
        TransactionRequestDraft {
            kind: TransactionKind::ReceiverIntake,
            logical_operation_id: request.logical_operation_id.clone(),
            idempotency_key: format!("receiver-intake:{}", request.logical_operation_id),
            route_id: request.route_id.clone(),
            route_generation: request.route_generation,
            route_definition_digest: request.route_definition_digest.clone(),
            message_digest: request.message_digest.clone(),
            exchange_digest: request.exchange_digest.clone(),
            package_digest: request.source_package_anchor_digest.clone(),
            before_snapshot_digest: request.expected_active_snapshot_digest.clone(),
            expected_after_snapshot_digest: request.prospective_after_digest.clone(),
            policy_digest: request.policy_digest.clone(),
            authority_refs: self.authority_profile_refs(),
            evidence_refs: vec![
                request.request_digest.clone(),
                request.active_state_digest.clone(),
                request.message_digest.clone(),
            ],
            retry_policy: self.retry_policy.clone(),
            deadline_ms: request.deadline_ms,
        }
    }

    fn authority_profile_refs(&self) -> Vec<ContentDigest> {
        vec![
            self.intake_authority.profile().profile_digest().clone(),
            self.proving_authority.profile().profile_digest().clone(),
            self.approval_authority.profile().profile_digest().clone(),
            self.promotion_authority.profile().profile_digest().clone(),
            self.observation_authority
                .profile()
                .profile_digest()
                .clone(),
            self.rollback_authority.profile().profile_digest().clone(),
        ]
    }

    pub fn load_acknowledgement(
        &self,
        logical_operation_id: &str,
    ) -> Result<Option<ReceiverAcknowledgementReceipt>, M6ReceiverError> {
        validate_identifier("receiver intake operation id", logical_operation_id)?;
        let operation_root = operation_root(&self.operations_root, logical_operation_id);
        let path = operation_root.join(ACK_RECEIPT_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let (request, _) = load_request_unit(&operation_root, self.route(), &self.import_policy)?;
        let ack_request: ReceiverAcknowledgementRequest =
            load_canonical_file(&operation_root.join(ACK_REQUEST_FILE), MAX_RECORD_BYTES)?;
        ack_request.validate(&request, self.route())?;
        let terminal_stage = self
            .journal
            .transaction(logical_operation_id)?
            .and_then(|projection| projection.current_record().cloned())
            .filter(|record| record.stage.is_terminal())
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "receiver ACK receipt has no terminal coordinator record".to_string(),
                )
            })?;
        if ack_request.receiver_transaction_digest != terminal_stage.stage_digest
            || receiver_terminal_stage_label(terminal_stage.stage)
                != Some(ack_request.disposition.as_str())
        {
            return Err(M6ReceiverError::Integrity(
                "receiver ACK request differs from the current terminal disposition".to_string(),
            ));
        }
        let receipt: ReceiverAcknowledgementReceipt = load_canonical_file(&path, MAX_RECORD_BYTES)?;
        let ready = self
            .spool
            .read_outbound_ready(&receipt.acknowledgement_message_digest)?;
        let delivery_digest = ack_delivery_digest(&ready)?;
        receipt.validate(
            &ack_request,
            &ready,
            self.route(),
            &receipt.issuance_request_digest,
            &delivery_digest,
        )?;
        Ok(Some(receipt))
    }

    pub fn load_replay_control_proof(
        &self,
        logical_operation_id: &str,
    ) -> Result<Option<ReceiverReplayControlProofV1>, M6ReceiverError> {
        validate_identifier("receiver replay-control operation id", logical_operation_id)?;
        let operation_root = operation_root(&self.operations_root, logical_operation_id);
        if !operation_root.exists() {
            return Ok(None);
        }
        let (request, _) = load_request_unit(&operation_root, self.route(), &self.import_policy)?;
        let claim_path = self
            .message_claims_root
            .join(format!("{}.json", request.message_digest.file_stem()));
        if !claim_path.exists() {
            return Ok(None);
        }
        let claim: ReceiverAuthenticatedMessageClaimV1 =
            load_canonical_file(&claim_path, MAX_RECORD_BYTES)?;
        claim.validate(self.route())?;
        if claim.logical_operation_id != logical_operation_id
            || claim.transaction_kind != ReceiverInboundTransactionKindV1::Import
            || claim.outer_request_digest != request.request_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver replay-control claim differs from its intake operation".to_string(),
            ));
        }
        let raw: RawQuarantineRecord =
            load_canonical_file(&operation_root.join(RAW_RECORD_FILE), MAX_RECORD_BYTES)?;
        let manifest = self.quarantine.parse_quarantined_manifest(&raw)?;
        let (disposition, commit, negative) =
            match self.replay.resolve_terminal_negative(&manifest)? {
                TerminalNegativeResolution::ChainCommitted { commit, record } => (
                    ReceiverReplayControlDispositionV1::TerminalNegative,
                    commit,
                    Some(record),
                ),
                TerminalNegativeResolution::Missing => {
                    let commit = match self.replay.resolve_exact_commit(&manifest)? {
                        ReplayCommitResolution::ExactCommitted(commit) => commit,
                        _ => return Ok(None),
                    };
                    (ReceiverReplayControlDispositionV1::Accepted, commit, None)
                }
                TerminalNegativeResolution::Recorded(_) => {
                    return Err(M6ReceiverError::InvalidState(
                        "terminal-negative replay source is recorded but not chain committed"
                            .to_string(),
                    ));
                }
            };
        Ok(Some(ReceiverReplayControlProofV1::from_resolution(
            self.route(),
            &self.signer,
            raw.raw_unit_digest,
            &manifest,
            &claim,
            disposition,
            commit,
            negative,
        )?))
    }

    /// Reopen every exact durable source for one Healthy or RolledBack import,
    /// re-run all live opaque authority verifiers, and receiver-sign the
    /// resulting portable source-digest set.
    pub fn load_exchange_completion_evidence(
        &self,
        logical_operation_id: &str,
    ) -> Result<Option<ReceiverExchangeCompletionEvidenceV1>, M6ReceiverError> {
        validate_identifier(
            "receiver exchange completion operation id",
            logical_operation_id,
        )?;
        let operation_root = operation_root(&self.operations_root, logical_operation_id);
        if !operation_root.join(ADOPTION_RECEIPT_FILE).exists() {
            return Ok(None);
        }
        let request_record_bytes =
            read_regular_bounded(&operation_root.join(REQUEST_FILE), MAX_REQUEST_BYTES)?;
        let request_commit_bytes =
            read_regular_bounded(&operation_root.join(REQUEST_COMMIT_FILE), MAX_REQUEST_BYTES)?;
        let active_state_bytes =
            read_regular_bounded(&operation_root.join(ACTIVE_STATE_FILE), MAX_RECORD_BYTES)?;
        let request: ReceiverIntakeRequest =
            parse_canonical(&request_record_bytes, MAX_REQUEST_BYTES)?;
        let active = ReceiverActiveStateV1::from_canonical_bytes(&active_state_bytes)?;
        request.validate(self.route(), &active, &self.import_policy)?;
        let raw_quarantine_bytes =
            read_regular_bounded(&operation_root.join(RAW_RECORD_FILE), MAX_RECORD_BYTES)?;
        let raw = RawQuarantineRecord::from_canonical_bytes(&raw_quarantine_bytes, self.route())?;
        let raw_unit = self.quarantine.read_committed_unit(&raw)?;
        let manifest = self.quarantine.parse_quarantined_manifest(&raw)?;
        let signed_manifest_bytes = manifest.canonical_bytes()?;
        let verified_export_bytes =
            read_regular_bounded(&operation_root.join(VERIFIED_EXPORT_FILE), MAX_RECORD_BYTES)?;
        let compatibility_bytes =
            read_regular_bounded(&operation_root.join(COMPATIBILITY_FILE), MAX_RECORD_BYTES)?;
        let proving_bytes =
            read_regular_bounded(&operation_root.join(PROVING_FILE), MAX_RECORD_BYTES)?;
        let import_plan_bytes =
            read_regular_bounded(&operation_root.join(IMPORT_PLAN_FILE), MAX_RECORD_BYTES)?;
        let verified = VerifiedQuarantinedExportV1::from_canonical_bytes(
            &verified_export_bytes,
            self.route(),
            &self.import_policy,
        )?;
        let compatibility = ReceiverCompatibilityDecisionV1::from_canonical_bytes(
            &compatibility_bytes,
            &verified,
            &active,
            &self.import_policy,
        )?;
        let proving = ReceiverProvingReportV1::from_canonical_bytes(
            &proving_bytes,
            &verified,
            &active,
            &self.import_policy,
            &compatibility,
            self.m5.validation_suite(),
        )?;
        let plan = ReceiverImportPlanV1::from_canonical_bytes(
            &import_plan_bytes,
            &verified,
            &active,
            &self.import_policy,
            &compatibility,
            &proving,
            self.m5.validation_suite(),
        )?;
        let projection = self
            .journal
            .transaction(logical_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "completed receiver import has no coordinator projection".to_string(),
                )
            })?;
        let terminal = projection.current_record().ok_or_else(|| {
            M6ReceiverError::Integrity(
                "completed receiver import has no terminal coordinator record".to_string(),
            )
        })?;
        if !matches!(
            terminal.stage,
            TransactionStage::Healthy | TransactionStage::RolledBack
        ) {
            return Err(M6ReceiverError::Integrity(
                "adoption receipt exists without a Healthy or RolledBack terminal stage"
                    .to_string(),
            ));
        }
        let coordinator_projection_bytes = projection.canonical_bytes()?;
        let replay = self
            .load_replay_control_proof(logical_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "completed receiver import lacks replay-control commitment".to_string(),
                )
            })?;
        let replay_control_bytes = replay.canonical_bytes(self.route())?;
        let approval_request = self.approval_request(
            &request,
            &active,
            &verified,
            &compatibility,
            &proving,
            &plan,
        )?;
        if self
            .approval_authority
            .load_approval_request(approval_request.request_digest())?
            != approval_request
        {
            return Err(M6ReceiverError::Integrity(
                "completed receiver import approval request differs from durable authority state"
                    .to_string(),
            ));
        }
        let decision = self
            .approval_authority
            .load_approval_decision(approval_request.request_digest())?;
        if decision.kind() != ApprovalDecisionKind::Granted {
            return Err(M6ReceiverError::Integrity(
                "completed receiver M5 cycle lacks a Granted decision".to_string(),
            ));
        }
        let approval_authorization = self
            .approval_authority
            .load_authorization(decision.authorization_digest())?;
        let approval_consumption = self
            .approval_authority
            .load_consumption(decision.authorization_digest(), 1)?;

        let mut authority_sources = vec![
            ReceiverCompletionAuthoritySourceV1::from_store(
                &self.intake_authority,
                &intake_binding(&request),
            )?,
            ReceiverCompletionAuthoritySourceV1::from_store(
                &self.proving_authority,
                &proving_binding(
                    &request,
                    &verified,
                    &compatibility,
                    self.m5.validation_suite(),
                )?,
            )?,
            ReceiverCompletionAuthoritySourceV1::from_records(
                &self.approval_authority,
                &approval_authorization,
                &approval_consumption,
            )?,
            ReceiverCompletionAuthoritySourceV1::from_store(
                &self.promotion_authority,
                &promotion_binding(&request, &decision, &proving, &plan)?,
            )?,
            ReceiverCompletionAuthoritySourceV1::from_store(
                &self.observation_authority,
                &observation_binding(&request, &decision, &proving, &plan)?,
            )?,
            ReceiverCompletionAuthoritySourceV1::from_store(
                &self.rollback_authority,
                &rollback_binding(&request, &decision, &proving, &plan)?,
            )?,
        ];
        authority_sources.sort_by_key(|source| source.action);

        let m5_cycle_bytes =
            read_regular_bounded(&operation_root.join(M5_CYCLE_FILE), MAX_RECORD_BYTES)?;
        let cycle: ReceiverM5CycleEvidence = parse_canonical(&m5_cycle_bytes, MAX_RECORD_BYTES)?;
        let pre_activation_probe_bytes = read_regular_bounded(
            &operation_root.join(PRE_ACTIVATION_EXECUTION_FILE),
            MAX_RECORD_BYTES,
        )?;
        let behavior_change_bytes = if cycle.disposition == ReceiverM5Disposition::Healthy {
            Some(self.load_or_capture_behavior_change(
                &operation_root,
                &request,
                &active,
                &plan,
                &cycle,
            )?)
        } else {
            None
        };
        let adoption_receipt_bytes = read_regular_bounded(
            &operation_root.join(ADOPTION_RECEIPT_FILE),
            MAX_RECORD_BYTES,
        )?;
        let receipt: ReceiverAdoptionReceipt =
            parse_canonical(&adoption_receipt_bytes, MAX_RECORD_BYTES)?;
        let post_rollback_probe_bytes = if cycle.disposition == ReceiverM5Disposition::RolledBack {
            Some(self.load_or_capture_post_rollback_probe(&operation_root, &cycle)?)
        } else {
            None
        };
        let ack = self
            .load_acknowledgement(logical_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::InvalidState(
                    "completed receiver import lacks its published disposition ACK".to_string(),
                )
            })?;
        let acknowledgement_request_bytes =
            read_regular_bounded(&operation_root.join(ACK_REQUEST_FILE), MAX_RECORD_BYTES)?;
        let acknowledgement_receipt_bytes =
            read_regular_bounded(&operation_root.join(ACK_RECEIPT_FILE), MAX_RECORD_BYTES)?;
        let ready_ack = self
            .spool
            .read_outbound_ready(&ack.acknowledgement_message_digest)?;
        if !ready_ack.attachments.is_empty() {
            return Err(M6ReceiverError::Integrity(
                "receiver completion ACK unexpectedly carries attachments".to_string(),
            ));
        }
        let acknowledgement_manifest_bytes = ready_ack.manifest.canonical_bytes()?;
        let import_policy_bytes = self.import_policy.canonical_bytes()?;
        let proving_suite_bytes = canonical_json(self.m5.validation_suite())?;
        let approval_request_bytes = approval_request.canonical_bytes()?;
        let approval_decision_bytes = decision.canonical_bytes(
            &approval_request,
            &approval_authorization,
            &approval_consumption,
        )?;

        let empty = ContentDigest::from_bytes(&[]);
        let mut evidence = ReceiverExchangeCompletionEvidenceV1 {
            schema: RECEIVER_EXCHANGE_COMPLETION_EVIDENCE_SCHEMA.to_string(),
            logical_operation_id: logical_operation_id.to_string(),
            route_definition_digest: self.route().definition_digest.clone(),
            signing_key_id: self.signer.signing_key_id().to_string(),
            sender_factory_id: self.route().sender.factory_id.clone(),
            receiver_factory_id: self.route().receiver.factory_id.clone(),
            message_digest: request.message_digest.clone(),
            export_bundle_digest: verified.export_bundle_digest().clone(),
            source_package_digest: verified.source_package_digest().clone(),
            receiver_local_package_digest: plan.receiver_local_package_digest().clone(),
            proving_digest: proving.report_digest().clone(),
            import_plan_digest: plan.import_plan_digest().clone(),
            prior_active_snapshot_digest: active.snapshot().snapshot_digest.clone(),
            final_active_snapshot_digest: cycle.active_snapshot.snapshot_digest.clone(),
            disposition: cycle.disposition,
            terminal_stage: terminal.stage,
            terminal_stage_digest: terminal.stage_digest.clone(),
            adoption_receipt_digest: receipt.receipt_digest.clone(),
            source_digests: ReceiverExchangeCompletionSourceDigestsV1 {
                request_record: empty.clone(),
                request_commit: empty.clone(),
                active_state: empty.clone(),
                import_policy: empty.clone(),
                proving_suite: empty.clone(),
                raw_quarantine: empty.clone(),
                raw_unit_files: empty.clone(),
                signed_manifest: empty.clone(),
                verified_export: empty.clone(),
                compatibility: empty.clone(),
                proving: empty.clone(),
                import_plan: empty.clone(),
                coordinator_projection: empty.clone(),
                replay_control: empty.clone(),
                approval_request: empty.clone(),
                approval_decision: empty.clone(),
                authority_sources: empty.clone(),
                m5_cycle: empty.clone(),
                pre_activation_probe: empty.clone(),
                behavior_change: None,
                post_rollback_probe: None,
                adoption_receipt: empty.clone(),
                acknowledgement_request: empty.clone(),
                acknowledgement_manifest: empty.clone(),
                acknowledgement_receipt: empty,
            },
            request_record_bytes,
            request_commit_bytes,
            active_state_bytes,
            import_policy_bytes,
            proving_suite_bytes,
            raw_quarantine_bytes,
            raw_unit_files: raw_unit.files().clone(),
            signed_manifest_bytes,
            verified_export_bytes,
            compatibility_bytes,
            proving_bytes,
            import_plan_bytes,
            coordinator_projection_bytes,
            replay_control_bytes,
            approval_request_bytes,
            approval_decision_bytes,
            authority_sources,
            m5_cycle_bytes,
            pre_activation_probe_bytes,
            behavior_change_bytes,
            post_rollback_probe_bytes,
            adoption_receipt_bytes,
            acknowledgement_request_bytes,
            acknowledgement_manifest_bytes,
            acknowledgement_receipt_bytes,
            evidence_digest: ContentDigest::from_bytes(&[]),
            source_set_signature_hex: String::new(),
        };
        evidence.source_digests = evidence.expected_source_digests()?;
        evidence.evidence_digest = evidence.expected_digest()?;
        evidence.source_set_signature_hex = self
            .signer
            .sign_receiver_intake_completion(self.route(), &evidence.evidence_digest)?;
        evidence.validate_live(self)?;
        Ok(Some(evidence))
    }

    fn load_or_capture_pre_activation_probe(
        &self,
        operation_root: &Path,
        request: &ReceiverIntakeRequest,
        active: &ReceiverActiveStateV1,
    ) -> Result<ReceiverM5PreActivationProbeV1, M6ReceiverError> {
        let path = operation_root.join(PRE_ACTIVATION_EXECUTION_FILE);
        if path.exists() {
            let probe: ReceiverM5PreActivationProbeV1 =
                load_canonical_file(&path, MAX_RECORD_BYTES)?;
            probe.validate(
                &request.logical_operation_id,
                active,
                self.m5.validation_suite(),
            )?;
            return Ok(probe);
        }
        let live = self.capture_active_state()?;
        if live != *active {
            return Err(M6ReceiverError::ActiveStateChanged {
                expected: active.snapshot().snapshot_digest.clone(),
                observed: live.snapshot().snapshot_digest.clone(),
            });
        }
        let package = self.m5.active_package()?;
        let package_bytes = package
            .canonical_bytes()
            .map_err(|error| M6ReceiverError::M5(error.to_string()))?;
        if package.package_digest != request.expected_active_package_digest
            || ContentDigest::from_bytes(&package_bytes) != active.snapshot().package_bytes_digest
            || package.payload.genome.component_digest != active.snapshot().component_digest
        {
            return Err(M6ReceiverError::Integrity(
                "pre-activation package differs from the intake's exact incumbent snapshot"
                    .to_string(),
            ));
        }
        let execution = self.m5.execute_active(BEHAVIOR_CHANGE_PROBE_INPUT)?;
        let probe = ReceiverM5PreActivationProbeV1::capture(
            &request.logical_operation_id,
            active,
            &package,
            execution,
            self.m5.validation_suite(),
        )?;
        persist_operation_record(
            operation_root,
            PRE_ACTIVATION_EXECUTION_FILE,
            &canonical_json(&probe)?,
            MAX_RECORD_BYTES,
        )?;
        Ok(probe)
    }

    fn load_or_capture_behavior_change(
        &self,
        operation_root: &Path,
        request: &ReceiverIntakeRequest,
        active: &ReceiverActiveStateV1,
        plan: &ReceiverImportPlanV1,
        cycle: &ReceiverM5CycleEvidence,
    ) -> Result<Vec<u8>, M6ReceiverError> {
        let path = operation_root.join(BEHAVIOR_CHANGE_FILE);
        if path.exists() {
            let bytes = read_regular_bounded(&path, MAX_RECORD_BYTES)?;
            let evidence: ReceiverM5BehaviorChangeEvidenceV1 =
                parse_canonical(&bytes, MAX_RECORD_BYTES)?;
            evidence.validate(request, active, plan, cycle, self.m5.validation_suite())?;
            return Ok(bytes);
        }
        if cycle.disposition != ReceiverM5Disposition::Healthy {
            return Err(M6ReceiverError::InvalidState(
                "before/after behavior evidence requires a Healthy M5 cycle".to_string(),
            ));
        }
        let pre_activation: ReceiverM5PreActivationProbeV1 = load_canonical_file(
            &operation_root.join(PRE_ACTIVATION_EXECUTION_FILE),
            MAX_RECORD_BYTES,
        )?;
        pre_activation.validate(
            &request.logical_operation_id,
            active,
            self.m5.validation_suite(),
        )?;
        let post_activation_execution = self.m5.execute_active(pre_activation.execution.input)?;
        let effect_audit = self.m5.audit_active_executions(&[
            pre_activation.execution.clone(),
            post_activation_execution.clone(),
        ])?;
        let mut evidence = ReceiverM5BehaviorChangeEvidenceV1 {
            schema: RECEIVER_M5_BEHAVIOR_CHANGE_EVIDENCE_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            cycle_id: cycle.cycle_id.clone(),
            import_plan_digest: plan.import_plan_digest().clone(),
            pre_activation_probe: pre_activation,
            post_activation_execution,
            effect_audit,
            evidence_digest: ContentDigest::from_bytes(&[]),
        };
        evidence.evidence_digest = evidence.expected_digest()?;
        evidence.validate(request, active, plan, cycle, self.m5.validation_suite())?;
        let bytes = canonical_json(&evidence)?;
        persist_operation_record(
            operation_root,
            BEHAVIOR_CHANGE_FILE,
            &bytes,
            MAX_RECORD_BYTES,
        )?;
        Ok(bytes)
    }

    fn load_or_capture_post_rollback_probe(
        &self,
        operation_root: &Path,
        cycle: &ReceiverM5CycleEvidence,
    ) -> Result<Vec<u8>, M6ReceiverError> {
        let path = operation_root.join(POST_ROLLBACK_PROBE_FILE);
        if path.exists() {
            let bytes = read_regular_bounded(&path, MAX_RECORD_BYTES)?;
            M5PostRollbackProbeV1::from_canonical_bytes(&bytes)?;
            return Ok(bytes);
        }
        let mut last_error = None;
        for input in 23..31 {
            match self.m5.capture_post_rollback_probe(&cycle.cycle_id, input) {
                Ok(probe) => {
                    let bytes = probe.canonical_bytes()?;
                    persist_operation_record(
                        operation_root,
                        POST_ROLLBACK_PROBE_FILE,
                        &bytes,
                        MAX_RECORD_BYTES,
                    )?;
                    return Ok(bytes);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(M6ReceiverError::M5(format!(
            "could not capture a fresh post-rollback behavior probe: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "no probe inputs attempted".to_string())
        )))
    }

    /// Resume publication of the exact receiver acknowledgement for a
    /// terminal intake. This is also the bounded recovery seam for a
    /// `ContainmentRequired` stage written by effect-conflict handling.
    pub fn recover_acknowledgement(
        &mut self,
        logical_operation_id: &str,
    ) -> Result<ReceiverAcknowledgementReceipt, M6ReceiverError> {
        validate_identifier("receiver intake operation id", logical_operation_id)?;
        let operation_root = operation_root(&self.operations_root, logical_operation_id);
        let (request, _) = load_request_unit(&operation_root, self.route(), &self.import_policy)?;
        let terminal_stage = self
            .journal
            .transaction(logical_operation_id)?
            .and_then(|projection| projection.current_record().cloned())
            .filter(|record| record.stage.is_terminal())
            .ok_or_else(|| {
                M6ReceiverError::InvalidState(
                    "receiver acknowledgement recovery requires a terminal intake".to_string(),
                )
            })?;
        let disposition = receiver_terminal_stage_label(terminal_stage.stage).ok_or_else(|| {
            M6ReceiverError::InvalidState(format!(
                "receiver intake stage {:?} has no acknowledgement disposition",
                terminal_stage.stage
            ))
        })?;
        let raw_or_rejection_digest =
            if terminal_stage.stage == TransactionStage::RawAdmissionRejected {
                self.quarantine
                    .admission_rejection(logical_operation_id)?
                    .ok_or_else(|| {
                        M6ReceiverError::Integrity(
                            "raw-admission rejection stage has no durable rejection".to_string(),
                        )
                    })?
                    .record_digest
            } else {
                let raw: RawQuarantineRecord =
                    load_canonical_file(&operation_root.join(RAW_RECORD_FILE), MAX_RECORD_BYTES)?;
                self.quarantine.read_committed_unit(&raw)?;
                raw.raw_unit_digest
            };
        self.publish_acknowledgement(
            &request,
            disposition,
            raw_or_rejection_digest,
            &terminal_stage,
            None,
        )
    }

    fn publish_acknowledgement(
        &mut self,
        request: &ReceiverIntakeRequest,
        disposition: &str,
        raw_or_rejection_digest: ContentDigest,
        terminal_stage: &TransactionStageRecord,
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<ReceiverAcknowledgementReceipt, M6ReceiverError> {
        self.publish_acknowledgement_for_context(
            operation_root(&self.operations_root, &request.logical_operation_id),
            &request.logical_operation_id,
            &request.request_digest,
            &request.message_digest,
            disposition,
            raw_or_rejection_digest,
            terminal_stage,
            crash_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_acknowledgement_for_context(
        &mut self,
        operation_root: PathBuf,
        logical_operation_id: &str,
        intake_record_digest: &ContentDigest,
        sender_message_digest: &ContentDigest,
        disposition: &str,
        raw_or_rejection_digest: ContentDigest,
        terminal_stage: &TransactionStageRecord,
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<ReceiverAcknowledgementReceipt, M6ReceiverError> {
        if !terminal_stage.stage.is_terminal()
            || terminal_stage.logical_operation_id != logical_operation_id
            || receiver_terminal_stage_label(terminal_stage.stage) != Some(disposition)
        {
            return Err(M6ReceiverError::InvalidState(
                "receiver acknowledgement requires the exact terminal coordinator disposition"
                    .to_string(),
            ));
        }
        let requested = ReceiverAcknowledgementRequest::new_for_context(
            logical_operation_id,
            intake_record_digest.clone(),
            sender_message_digest.clone(),
            disposition,
            raw_or_rejection_digest,
            terminal_stage.stage_digest.clone(),
            self.route().resource_profile.max_message_lifetime_ms,
        )?;
        requested.validate_for_context(
            logical_operation_id,
            intake_record_digest,
            sender_message_digest,
            self.route(),
        )?;
        let ack_request_path = operation_root.join(ACK_REQUEST_FILE);
        let ack_request = if ack_request_path.exists() {
            let existing: ReceiverAcknowledgementRequest =
                load_canonical_file(&ack_request_path, MAX_RECORD_BYTES)?;
            existing.validate_for_context(
                logical_operation_id,
                intake_record_digest,
                sender_message_digest,
                self.route(),
            )?;
            if existing != requested {
                return Err(M6ReceiverError::Conflict {
                    identity: format!("receiver-ack:{logical_operation_id}"),
                    existing: existing.request_digest,
                    requested: requested.request_digest,
                });
            }
            existing
        } else {
            persist_immutable_file(&ack_request_path, &canonical_json(&requested)?)?;
            requested
        };
        maybe_crash(
            crash_at,
            ReceiverCrashPoint::AcknowledgementRequestCommitted,
        )?;

        let mut resolution = self
            .acknowledgement_issuer
            .prepared_resolution(&ack_request.issuance_idempotency_key)?;
        if matches!(resolution, PreparedIssuanceResolution::Missing) {
            self.acknowledgement_issuer.prepare_idempotent(
                ack_request.issuance_idempotency_key.clone(),
                &self.signer,
                ack_request.payload(),
                Vec::new(),
                ack_request.message_lifetime_ms,
            )?;
            resolution = self
                .acknowledgement_issuer
                .prepared_resolution(&ack_request.issuance_idempotency_key)?;
        }
        let (prepared, issuance_request_digest, chain_committed) = match resolution {
            PreparedIssuanceResolution::Prepared(issuance) => {
                (issuance.issued, issuance.request_digest, false)
            }
            PreparedIssuanceResolution::ChainCommitted { commit, issuance } => {
                if commit.message_digest != issuance.issued.manifest.message_digest {
                    return Err(M6ReceiverError::Integrity(
                        "receiver ACK origin-chain fact differs from retained bytes".to_string(),
                    ));
                }
                (issuance.issued, issuance.request_digest, true)
            }
            PreparedIssuanceResolution::Abandoned { abandonment, .. } => {
                return Err(M6ReceiverError::Integrity(format!(
                    "receiver acknowledgement was abandoned as {}",
                    abandonment.record_digest
                )));
            }
            PreparedIssuanceResolution::Missing => {
                return Err(M6ReceiverError::Integrity(
                    "receiver acknowledgement prepare disappeared".to_string(),
                ));
            }
        };
        validate_ack_issued(&ack_request, &prepared, self.route())?;
        maybe_crash(crash_at, ReceiverCrashPoint::AcknowledgementPrepared)?;
        let committed = if chain_committed {
            prepared
        } else {
            self.acknowledgement_issuer.commit_prepared_exact(
                &ack_request.issuance_idempotency_key,
                &issuance_request_digest,
            )?
        };
        validate_ack_issued(&ack_request, &committed, self.route())?;
        maybe_crash(crash_at, ReceiverCrashPoint::AcknowledgementChainCommitted)?;

        {
            let owner = self.spool.acquire_role()?;
            self.spool.stage_delivery(&owner, &committed)?;
        }
        maybe_crash(crash_at, ReceiverCrashPoint::AcknowledgementRouteStaged)?;
        {
            let owner = self.spool.acquire_role()?;
            self.spool
                .commit_staged(&owner, &committed.manifest.message_digest)?;
        }
        let ready = self
            .spool
            .read_outbound_ready(&committed.manifest.message_digest)?;
        validate_ack_issued(&ack_request, &ready, self.route())?;
        if ready != committed {
            return Err(M6ReceiverError::Integrity(
                "ready receiver acknowledgement differs from retained issuance".to_string(),
            ));
        }
        maybe_crash(crash_at, ReceiverCrashPoint::AcknowledgementRouteReady)?;
        let delivery_digest = ack_delivery_digest(&ready)?;
        let receipt_path = operation_root.join(ACK_RECEIPT_FILE);
        let receipt = if receipt_path.exists() {
            let existing: ReceiverAcknowledgementReceipt =
                load_canonical_file(&receipt_path, MAX_RECORD_BYTES)?;
            existing.validate(
                &ack_request,
                &ready,
                self.route(),
                &issuance_request_digest,
                &delivery_digest,
            )?;
            existing
        } else {
            let receipt = ReceiverAcknowledgementReceipt::new(
                &ack_request,
                &ready,
                issuance_request_digest.clone(),
                delivery_digest.clone(),
                self.now_ms()?,
            )?;
            persist_immutable_file(&receipt_path, &canonical_json(&receipt)?)?;
            receipt
        };
        receipt.validate(
            &ack_request,
            &ready,
            self.route(),
            &issuance_request_digest,
            &delivery_digest,
        )?;
        maybe_crash(
            crash_at,
            ReceiverCrashPoint::AcknowledgementReceiptCommitted,
        )?;
        Ok(receipt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverRevocationRequest {
    schema: String,
    logical_operation_id: String,
    captured_at_ms: u64,
    deadline_ms: u64,
    route_id: String,
    route_generation: u64,
    route_definition_digest: ContentDigest,
    message_digest: ContentDigest,
    exchange_digest: ContentDigest,
    captured_active_snapshot_digest: ContentDigest,
    revocation_policy_digest: ContentDigest,
    request_digest: ContentDigest,
}

impl ReceiverRevocationRequest {
    fn new(
        logical_operation_id: String,
        captured_at_ms: u64,
        deadline_ms: u64,
        message_digest: ContentDigest,
        captured_active_snapshot_digest: ContentDigest,
        route: &RouteDefinition,
        revocation_policy_digest: ContentDigest,
    ) -> Result<Self, M6ReceiverError> {
        validate_identifier("receiver revocation operation id", &logical_operation_id)?;
        let exchange_digest = digest_domain(
            REVOCATION_EXCHANGE_DOMAIN,
            &(
                &logical_operation_id,
                &message_digest,
                &route.definition_digest,
                &captured_active_snapshot_digest,
                &revocation_policy_digest,
            ),
        )?;
        let mut request = Self {
            schema: RECEIVER_REVOCATION_REQUEST_SCHEMA.to_string(),
            logical_operation_id,
            captured_at_ms,
            deadline_ms,
            route_id: route.route_id.clone(),
            route_generation: route.generation,
            route_definition_digest: route.definition_digest.clone(),
            message_digest,
            exchange_digest,
            captured_active_snapshot_digest,
            revocation_policy_digest,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = request.expected_digest()?;
        request.validate(route, &request.revocation_policy_digest)?;
        Ok(request)
    }

    fn validate(
        &self,
        route: &RouteDefinition,
        revocation_policy_digest: &ContentDigest,
    ) -> Result<(), M6ReceiverError> {
        validate_identifier(
            "receiver revocation operation id",
            &self.logical_operation_id,
        )?;
        if self.schema != RECEIVER_REVOCATION_REQUEST_SCHEMA
            || self.deadline_ms <= self.captured_at_ms
            || self.deadline_ms.saturating_sub(self.captured_at_ms) > 30 * 86_400_000
            || self.route_id != route.route_id
            || self.route_generation != route.generation
            || self.route_definition_digest != route.definition_digest
            || &self.revocation_policy_digest != revocation_policy_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver revocation request differs from its route, deadline, or policy"
                    .to_string(),
            ));
        }
        require_digest(
            "receiver revocation exchange",
            &self.exchange_digest,
            &digest_domain(
                REVOCATION_EXCHANGE_DOMAIN,
                &(
                    &self.logical_operation_id,
                    &self.message_digest,
                    &self.route_definition_digest,
                    &self.captured_active_snapshot_digest,
                    &self.revocation_policy_digest,
                ),
            )?,
        )?;
        require_digest(
            "receiver revocation request",
            &self.request_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REVOCATION_REQUEST_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                self.captured_at_ms,
                self.deadline_ms,
                &self.route_id,
                self.route_generation,
                &self.route_definition_digest,
                &self.message_digest,
                &self.exchange_digest,
                &self.captured_active_snapshot_digest,
                &self.revocation_policy_digest,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedReceiverRevocationIntake {
    pub logical_operation_id: String,
    pub request_digest: ContentDigest,
    pub coordinator_request_digest: ContentDigest,
    pub message_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverRevocationAffectedOperation {
    pub import_logical_operation_id: String,
    pub import_request_digest: ContentDigest,
    pub affected: RevocationAffectedImportV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverRevocationMatchSet {
    schema: String,
    logical_operation_id: String,
    request_digest: ContentDigest,
    tombstone_digest: ContentDigest,
    affected_operations: Vec<ReceiverRevocationAffectedOperation>,
    record_digest: ContentDigest,
}

impl ReceiverRevocationMatchSet {
    fn new(
        request: &ReceiverRevocationRequest,
        tombstone: &RevocationTombstoneV1,
        mut affected_operations: Vec<ReceiverRevocationAffectedOperation>,
    ) -> Result<Self, M6ReceiverError> {
        affected_operations.sort_by(|left, right| {
            left.import_logical_operation_id
                .cmp(&right.import_logical_operation_id)
        });
        let mut record = Self {
            schema: RECEIVER_REVOCATION_MATCH_SET_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            request_digest: request.request_digest.clone(),
            tombstone_digest: tombstone.tombstone_digest.clone(),
            affected_operations,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        record.validate_fields(request, tombstone)?;
        record.record_digest = record.expected_digest()?;
        Ok(record)
    }

    fn validate(
        &self,
        request: &ReceiverRevocationRequest,
        tombstone: &RevocationTombstoneV1,
    ) -> Result<(), M6ReceiverError> {
        self.validate_fields(request, tombstone)?;
        require_digest(
            "receiver revocation match set",
            &self.record_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(
        &self,
        request: &ReceiverRevocationRequest,
        tombstone: &RevocationTombstoneV1,
    ) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_REVOCATION_MATCH_SET_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.request_digest != request.request_digest
            || self.tombstone_digest != tombstone.tombstone_digest
            || self.affected_operations.len() > 256
            || !self.affected_operations.windows(2).all(|pair| {
                pair[0].import_logical_operation_id < pair[1].import_logical_operation_id
            })
            || self.affected_operations.iter().any(|entry| {
                entry.affected.tombstone_digest != tombstone.tombstone_digest
                    || entry.import_request_digest == ContentDigest::from_bytes(&[])
                    || !tombstone.matches(&entry.affected.binding)
            })
        {
            return Err(M6ReceiverError::Integrity(
                "receiver revocation match set is incomplete or cross-linked".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REVOCATION_MATCH_SET_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.request_digest,
                &self.tombstone_digest,
                &self.affected_operations,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedReceiverRevocationContainment {
    pub logical_operation_id: String,
    pub request_digest: ContentDigest,
    pub tombstone: RevocationTombstoneV1,
    pub affected_operations: Vec<ReceiverRevocationAffectedOperation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverRevocationValidationRejection {
    pub schema: String,
    pub logical_operation_id: String,
    pub request_digest: ContentDigest,
    pub message_digest: ContentDigest,
    pub raw_quarantine_digest: ContentDigest,
    pub authenticated: bool,
    pub detail: String,
    pub evidence_refs: Vec<ContentDigest>,
    pub rejected_at_ms: u64,
    pub record_digest: ContentDigest,
}

impl ReceiverRevocationValidationRejection {
    fn new(
        request: &ReceiverRevocationRequest,
        raw: &RawQuarantineRecord,
        authenticated: bool,
        detail: impl Into<String>,
        mut evidence_refs: Vec<ContentDigest>,
        rejected_at_ms: u64,
    ) -> Result<Self, M6ReceiverError> {
        evidence_refs.sort();
        evidence_refs.dedup();
        let mut record = Self {
            schema: RECEIVER_REVOCATION_REJECTION_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            request_digest: request.request_digest.clone(),
            message_digest: request.message_digest.clone(),
            raw_quarantine_digest: raw.raw_unit_digest.clone(),
            authenticated,
            detail: detail.into().chars().take(4_096).collect(),
            evidence_refs,
            rejected_at_ms,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        record.validate_fields(request, raw)?;
        record.record_digest = record.expected_digest()?;
        Ok(record)
    }

    fn validate(
        &self,
        request: &ReceiverRevocationRequest,
        raw: &RawQuarantineRecord,
    ) -> Result<(), M6ReceiverError> {
        self.validate_fields(request, raw)?;
        require_digest(
            "receiver revocation rejection",
            &self.record_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(
        &self,
        request: &ReceiverRevocationRequest,
        raw: &RawQuarantineRecord,
    ) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_REVOCATION_REJECTION_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.request_digest != request.request_digest
            || self.message_digest != request.message_digest
            || self.raw_quarantine_digest != raw.raw_unit_digest
            || self.detail.is_empty()
            || self.detail.len() > 4_096
            || self.evidence_refs.is_empty()
            || !is_strictly_sorted_unique(&self.evidence_refs)
        {
            return Err(M6ReceiverError::Integrity(
                "receiver revocation rejection is incomplete or cross-linked".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REVOCATION_REJECTION_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.request_digest,
                &self.message_digest,
                &self.raw_quarantine_digest,
                self.authenticated,
                &self.detail,
                &self.evidence_refs,
                self.rejected_at_ms,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiverRevocationAdmissionResult {
    AwaitingContainment(PreparedReceiverRevocationContainment),
    RawAdmissionRejected(RawAdmissionRejected),
    ValidationRejected(ReceiverRevocationValidationRejection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverRevocationRollbackAuthority {
    pub import_logical_operation_id: String,
    pub rollback_authorization_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverRevocationResolvedOperation {
    pub import_logical_operation_id: String,
    pub resolution: RevocationContainmentResolutionV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverRevocationApplicationReceipt {
    pub schema: String,
    pub logical_operation_id: String,
    pub request_digest: ContentDigest,
    pub tombstone_digest: ContentDigest,
    pub match_set_digest: ContentDigest,
    pub resolved_operations: Vec<ReceiverRevocationResolvedOperation>,
    pub containment_required: bool,
    pub final_active_snapshot_digest: ContentDigest,
    pub recorded_at_ms: u64,
    pub receipt_digest: ContentDigest,
}

impl ReceiverRevocationApplicationReceipt {
    fn new(
        request: &ReceiverRevocationRequest,
        matches: &ReceiverRevocationMatchSet,
        mut resolved_operations: Vec<ReceiverRevocationResolvedOperation>,
        final_active_snapshot_digest: ContentDigest,
        recorded_at_ms: u64,
    ) -> Result<Self, M6ReceiverError> {
        resolved_operations.sort_by(|left, right| {
            left.import_logical_operation_id
                .cmp(&right.import_logical_operation_id)
        });
        let containment_required = resolved_operations.iter().any(|entry| {
            entry.resolution.outcome == RevocationContainmentOutcomeV1::ContainmentRequired
        });
        let mut receipt = Self {
            schema: RECEIVER_REVOCATION_RECEIPT_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            request_digest: request.request_digest.clone(),
            tombstone_digest: matches.tombstone_digest.clone(),
            match_set_digest: matches.record_digest.clone(),
            resolved_operations,
            containment_required,
            final_active_snapshot_digest,
            recorded_at_ms,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.validate_fields(request, matches)?;
        receipt.receipt_digest = receipt.expected_digest()?;
        Ok(receipt)
    }

    fn validate(
        &self,
        request: &ReceiverRevocationRequest,
        matches: &ReceiverRevocationMatchSet,
    ) -> Result<(), M6ReceiverError> {
        self.validate_fields(request, matches)?;
        require_digest(
            "receiver revocation application receipt",
            &self.receipt_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(
        &self,
        request: &ReceiverRevocationRequest,
        matches: &ReceiverRevocationMatchSet,
    ) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_REVOCATION_RECEIPT_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.request_digest != request.request_digest
            || self.tombstone_digest != matches.tombstone_digest
            || self.match_set_digest != matches.record_digest
            || self.resolved_operations.len() != matches.affected_operations.len()
            || !self.resolved_operations.windows(2).all(|pair| {
                pair[0].import_logical_operation_id < pair[1].import_logical_operation_id
            })
            || self
                .resolved_operations
                .iter()
                .zip(matches.affected_operations.iter())
                .any(|(resolution, affected)| {
                    resolution.import_logical_operation_id != affected.import_logical_operation_id
                        || resolution.resolution.affected_digest
                            != affected.affected.affected_digest
                })
            || self.containment_required
                != self.resolved_operations.iter().any(|entry| {
                    entry.resolution.outcome == RevocationContainmentOutcomeV1::ContainmentRequired
                })
        {
            return Err(M6ReceiverError::Integrity(
                "receiver revocation receipt is incomplete or cross-linked".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REVOCATION_RECEIPT_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.request_digest,
                &self.tombstone_digest,
                &self.match_set_digest,
                &self.resolved_operations,
                self.containment_required,
                &self.final_active_snapshot_digest,
                self.recorded_at_ms,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiverRevocationApplicationResult {
    Contained {
        receipt: ReceiverRevocationApplicationReceipt,
        acknowledgement: ReceiverAcknowledgementReceipt,
    },
    ContainmentRequired {
        receipt: ReceiverRevocationApplicationReceipt,
        acknowledgement: ReceiverAcknowledgementReceipt,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverRevocationAffectedCompletionSourceV1 {
    import_logical_operation_id: String,
    affected: RevocationAffectedImportV1,
    resolution: RevocationContainmentResolutionV1,
    import_completion_bytes: Vec<u8>,
    rollback_authority_profile_bytes: Vec<u8>,
    rollback_authorization_bytes: Vec<u8>,
    rollback_consumption_bytes: Vec<u8>,
    operator_rollback_record_bytes: Vec<u8>,
    post_rollback_effect_audit_bytes: Vec<u8>,
    source_digest: ContentDigest,
}

impl ReceiverRevocationAffectedCompletionSourceV1 {
    fn validate(
        &self,
        route: &RouteDefinition,
        tombstone: &RevocationTombstoneV1,
        final_active_snapshot_digest: &ContentDigest,
    ) -> Result<(), M6ReceiverError> {
        validate_identifier(
            "revocation affected completion import operation id",
            &self.import_logical_operation_id,
        )?;
        self.affected.validate(tombstone)?;
        self.resolution.validate(&self.affected)?;
        if self.affected.disposition_at_resolution != ReceiverImportDispositionV1::ActiveHealthy
            || self.affected.required_action
                != RequiredContainmentActionV1::StopAdmissionAndRollback
            || self.resolution.outcome != RevocationContainmentOutcomeV1::RolledBack
        {
            return Err(M6ReceiverError::Integrity(
                "portable revocation completion requires a real active-import rollback".to_string(),
            ));
        }

        let completion = ReceiverExchangeCompletionEvidenceV1::from_canonical_bytes_detached(
            &self.import_completion_bytes,
            route,
        )?;
        if completion.logical_operation_id != self.import_logical_operation_id
            || completion.disposition != ReceiverM5Disposition::Healthy
            || self.affected.binding.exchange_message_digest != completion.message_digest
            || self.affected.binding.receiver_import_plan_digest != completion.import_plan_digest
            || self.affected.binding.receiver_local_package_digest
                != completion.receiver_local_package_digest
            || self.affected.binding.source_identity_document_digest
                != route.sender.identity_document_digest
            || self.affected.binding.source_package_digest != completion.source_package_digest
            || self.affected.binding.source_signing_key_digest
                != ContentDigest::from_bytes(route.sender.public_key_hex.as_bytes())
        {
            return Err(M6ReceiverError::Integrity(
                "revocation affected import differs from its exact healthy exchange completion"
                    .to_string(),
            ));
        }
        let rollback_source = completion
            .authority_sources
            .iter()
            .find(|source| source.action == AuthorityAction::RollbackImport)
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "affected healthy exchange lacks its exact rollback authority source"
                        .to_string(),
                )
            })?;
        let (_, authorization, consumption) =
            rollback_source.validate_detached(&route.receiver.factory_id)?;
        if rollback_source.profile_bytes != self.rollback_authority_profile_bytes
            || rollback_source.authorization_bytes != self.rollback_authorization_bytes
            || rollback_source.consumption_bytes != self.rollback_consumption_bytes
            || !self
                .resolution
                .authoritative_effect_refs
                .contains(authorization.authorization_digest())
            || !self
                .resolution
                .authoritative_effect_refs
                .contains(authorization.binding_digest())
            || !self
                .resolution
                .authoritative_effect_refs
                .contains(consumption.receipt_digest())
        {
            return Err(M6ReceiverError::Integrity(
                "revocation rollback resolution lacks its exact pre-authorized rollback source"
                    .to_string(),
            ));
        }

        let operator: OperatorRollbackRecord =
            parse_canonical(&self.operator_rollback_record_bytes, MAX_RECORD_BYTES)?;
        validate_operator_rollback_record(&operator)?;
        let active = ReceiverActiveStateV1::from_canonical_bytes(&completion.active_state_bytes)?;
        if operator.from_package_digest != completion.receiver_local_package_digest
            || operator.restored_package_digest != active.snapshot().package_digest
            || !self
                .resolution
                .authoritative_effect_refs
                .contains(&operator.record_digest)
            || !self
                .resolution
                .authoritative_effect_refs
                .contains(&operator.recovery_receipt.receipt_digest)
        {
            return Err(M6ReceiverError::Integrity(
                "revocation operator rollback differs from the exact imported and incumbent packages"
                    .to_string(),
            ));
        }
        let audit: M5EffectAuditReport =
            parse_canonical(&self.post_rollback_effect_audit_bytes, MAX_RECORD_BYTES)?;
        audit
            .validate()
            .map_err(|error| M6ReceiverError::M5(error.to_string()))?;
        let expected_evidence_id = format!("operator-rollback:{}", operator.rollback_id);
        if &audit.backend_snapshot_digest != final_active_snapshot_digest
            || !audit.entries.iter().any(|entry| {
                entry.kind == M5EffectAuditKind::Recovery
                    && entry
                        .evidence_id
                        .split('|')
                        .any(|alias| alias == expected_evidence_id)
                    && entry.domain_request_digest == operator.recovery_receipt.request_digest
            })
        {
            return Err(M6ReceiverError::Integrity(
                "revocation rollback does not resolve in the post-rollback M5 effect audit"
                    .to_string(),
            ));
        }
        require_digest(
            "receiver revocation affected completion source",
            &self.source_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REVOCATION_AFFECTED_COMPLETION_SOURCE_DOMAIN,
            &(
                &self.import_logical_operation_id,
                &self.affected,
                &self.resolution,
                (
                    ContentDigest::from_bytes(&self.import_completion_bytes),
                    ContentDigest::from_bytes(&self.rollback_authority_profile_bytes),
                    ContentDigest::from_bytes(&self.rollback_authorization_bytes),
                    ContentDigest::from_bytes(&self.rollback_consumption_bytes),
                    ContentDigest::from_bytes(&self.operator_rollback_record_bytes),
                    ContentDigest::from_bytes(&self.post_rollback_effect_audit_bytes),
                ),
            ),
        )
    }
}

/// Receiver-signed, source-complete evidence that one sender-signed
/// revocation rolled back at least one previously healthy imported exchange
/// and published the exact receiver revocation acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverRevocationCompletionEvidenceV1 {
    schema: String,
    route_definition_digest: ContentDigest,
    signing_key_id: String,
    logical_operation_id: String,
    sender_message_digest: ContentDigest,
    sender_publication_evidence_digest: ContentDigest,
    sender_sequence: u64,
    sender_previous_message_digest: Option<ContentDigest>,
    sender_issued_at_ms: u64,
    sender_committed_at_ms: u64,
    prior_source_authorization_evidence_digest: ContentDigest,
    tombstone_digest: ContentDigest,
    receiver_containment_receipt_digest: ContentDigest,
    final_active_snapshot_digest: ContentDigest,
    terminal_stage_digest: ContentDigest,
    acknowledgement_message_digest: ContentDigest,
    sender_publication_evidence_bytes: Vec<u8>,
    receiver_request_bytes: Vec<u8>,
    raw_quarantine_record_bytes: Vec<u8>,
    raw_unit_files: BTreeMap<String, Vec<u8>>,
    signed_revocation_manifest_bytes: Vec<u8>,
    tombstone_bytes: Vec<u8>,
    match_set_bytes: Vec<u8>,
    affected_sources: Vec<ReceiverRevocationAffectedCompletionSourceV1>,
    receiver_coordinator_projection_bytes: Vec<u8>,
    receiver_containment_receipt_bytes: Vec<u8>,
    acknowledgement_request_bytes: Vec<u8>,
    acknowledgement_manifest_bytes: Vec<u8>,
    acknowledgement_receipt_bytes: Vec<u8>,
    evidence_digest: ContentDigest,
    source_set_signature_hex: String,
}

impl ReceiverRevocationCompletionEvidenceV1 {
    pub fn logical_operation_id(&self) -> &str {
        &self.logical_operation_id
    }

    pub fn sender_message_digest(&self) -> &ContentDigest {
        &self.sender_message_digest
    }

    pub fn sender_publication_evidence_digest(&self) -> &ContentDigest {
        &self.sender_publication_evidence_digest
    }

    pub fn sender_sequence(&self) -> u64 {
        self.sender_sequence
    }

    pub fn sender_previous_message_digest(&self) -> Option<&ContentDigest> {
        self.sender_previous_message_digest.as_ref()
    }

    pub fn sender_issued_at_ms(&self) -> u64 {
        self.sender_issued_at_ms
    }

    pub fn sender_committed_at_ms(&self) -> u64 {
        self.sender_committed_at_ms
    }

    pub fn prior_source_authorization_evidence_digest(&self) -> &ContentDigest {
        &self.prior_source_authorization_evidence_digest
    }

    pub fn tombstone_digest(&self) -> &ContentDigest {
        &self.tombstone_digest
    }

    pub fn receiver_containment_receipt_digest(&self) -> &ContentDigest {
        &self.receiver_containment_receipt_digest
    }

    pub fn final_active_snapshot_digest(&self) -> &ContentDigest {
        &self.final_active_snapshot_digest
    }

    pub fn terminal_stage_digest(&self) -> &ContentDigest {
        &self.terminal_stage_digest
    }

    pub fn acknowledgement_message_digest(&self) -> &ContentDigest {
        &self.acknowledgement_message_digest
    }

    pub fn affected_operation_count(&self) -> usize {
        self.affected_sources.len()
    }

    pub fn proves_rollback_of(&self, completion: &ReceiverExchangeCompletionEvidenceV1) -> bool {
        let Ok(completion_bytes) = canonical_json(completion) else {
            return false;
        };
        self.affected_sources.iter().any(|source| {
            source.import_logical_operation_id == completion.logical_operation_id
                && source.affected.binding.exchange_message_digest == completion.message_digest
                && source.resolution.outcome == RevocationContainmentOutcomeV1::RolledBack
                && source.import_completion_bytes == completion_bytes
        })
    }

    pub fn evidence_digest(&self) -> &ContentDigest {
        &self.evidence_digest
    }

    pub fn canonical_bytes_detached(
        &self,
        route: &RouteDefinition,
    ) -> Result<Vec<u8>, M6ReceiverError> {
        self.validate_detached(route)?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes_detached(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6ReceiverError> {
        let evidence: Self = parse_canonical(bytes, MAX_RECORD_BYTES)?;
        evidence.validate_detached(route)?;
        Ok(evidence)
    }

    fn validate_detached(&self, route: &RouteDefinition) -> Result<(), M6ReceiverError> {
        if self.schema != RECEIVER_REVOCATION_COMPLETION_EVIDENCE_SCHEMA
            || self.route_definition_digest != route.definition_digest
            || self.signing_key_id != route.receiver.signing_key_id
            || self.affected_sources.is_empty()
            || self.affected_sources.len() > route.resource_profile.max_revocation_records as usize
        {
            return Err(M6ReceiverError::Integrity(
                "receiver revocation completion is outside its route-bound schema".to_string(),
            ));
        }
        validate_identifier(
            "receiver revocation completion operation id",
            &self.logical_operation_id,
        )?;
        verify_receiver_revocation_completion_signature(
            route,
            &self.signing_key_id,
            &self.evidence_digest,
            &self.source_set_signature_hex,
        )?;

        let sender = SenderRevocationPublicationEvidenceV1::from_canonical_bytes_detached(
            &self.sender_publication_evidence_bytes,
            route,
        )
        .map_err(|error| M6ReceiverError::Integrity(error.to_string()))?;
        if sender.message_digest() != &self.sender_message_digest
            || sender.evidence_digest() != &self.sender_publication_evidence_digest
            || sender.sequence() != self.sender_sequence
            || sender.previous_message_digest() != self.sender_previous_message_digest.as_ref()
            || sender.issued_at_ms() != self.sender_issued_at_ms
            || sender.committed_at_ms() != self.sender_committed_at_ms
            || sender.prior_source_authorization_evidence_digest()
                != &self.prior_source_authorization_evidence_digest
            || sender.signed_manifest_bytes() != self.signed_revocation_manifest_bytes
        {
            return Err(M6ReceiverError::Integrity(
                "receiver revocation completion differs from sender-signed publication evidence"
                    .to_string(),
            ));
        }
        let config = crate::m6_revocation::RevocationLedgerConfigV1::for_route(route)?;
        let request: ReceiverRevocationRequest =
            parse_canonical(&self.receiver_request_bytes, MAX_REQUEST_BYTES)?;
        request.validate(route, &config.config_digest)?;
        let raw =
            RawQuarantineRecord::from_canonical_bytes(&self.raw_quarantine_record_bytes, route)?;
        validate_portable_raw_unit_files(&raw, &self.raw_unit_files)?;
        if self.raw_unit_files.get("manifest.json") != Some(&self.signed_revocation_manifest_bytes)
        {
            return Err(M6ReceiverError::Integrity(
                "receiver revocation signed manifest differs from immutable quarantine bytes"
                    .to_string(),
            ));
        }
        let manifest =
            SignedManifest::from_canonical_bytes(&self.signed_revocation_manifest_bytes)?;
        manifest.verify_route(route)?;
        let tombstone: RevocationTombstoneV1 =
            parse_canonical(&self.tombstone_bytes, MAX_RECORD_BYTES)?;
        tombstone.validate(&config)?;
        let matches: ReceiverRevocationMatchSet =
            parse_canonical(&self.match_set_bytes, MAX_RECORD_BYTES)?;
        matches.validate(&request, &tombstone)?;
        let receipt: ReceiverRevocationApplicationReceipt =
            parse_canonical(&self.receiver_containment_receipt_bytes, MAX_RECORD_BYTES)?;
        receipt.validate(&request, &matches)?;
        if request.logical_operation_id != self.logical_operation_id
            || request.message_digest != self.sender_message_digest
            || raw.intake_operation_id != self.logical_operation_id
            || raw.raw_unit_digest != tombstone.raw_quarantine_digest
            || raw.record_digest != tombstone.raw_quarantine_record_digest
            || manifest.message_digest != self.sender_message_digest
            || tombstone.sender_message_digest != self.sender_message_digest
            || tombstone.tombstone_digest != self.tombstone_digest
            || tombstone.target_kind != sender.target_kind()
            || &tombstone.target_identity != sender.target_identity()
            || tombstone.authorization_digest
                != *sender.prior_source_authorization_evidence_digest()
            || receipt.receipt_digest != self.receiver_containment_receipt_digest
            || receipt.final_active_snapshot_digest != self.final_active_snapshot_digest
            || receipt.containment_required
            || receipt.resolved_operations.len() != self.affected_sources.len()
            || matches.affected_operations.len() != self.affected_sources.len()
        {
            return Err(M6ReceiverError::Integrity(
                "receiver revocation request, tombstone, match set, and receipt are cross-linked"
                    .to_string(),
            ));
        }
        for ((source, affected), resolved) in self
            .affected_sources
            .iter()
            .zip(matches.affected_operations.iter())
            .zip(receipt.resolved_operations.iter())
        {
            if source.import_logical_operation_id != affected.import_logical_operation_id
                || source.affected != affected.affected
                || source.import_logical_operation_id != resolved.import_logical_operation_id
                || source.resolution != resolved.resolution
            {
                return Err(M6ReceiverError::Integrity(
                    "receiver revocation affected source differs from match or receipt".to_string(),
                ));
            }
            source.validate(route, &tombstone, &self.final_active_snapshot_digest)?;
        }

        let projection = TransactionProjection::from_canonical_bytes(
            &self.receiver_coordinator_projection_bytes,
        )?;
        let terminal = projection.current_record().ok_or_else(|| {
            M6ReceiverError::Integrity(
                "receiver revocation completion has no terminal coordinator stage".to_string(),
            )
        })?;
        if projection.intent.kind != TransactionKind::ReceiverRevocationApplication
            || projection.intent.logical_operation_id != self.logical_operation_id
            || projection.intent.message_digest != self.sender_message_digest
            || terminal.stage != TransactionStage::RevocationContained
            || terminal.stage_digest != self.terminal_stage_digest
            || !terminal
                .evidence
                .evidence_refs
                .contains(&receipt.receipt_digest)
            || !terminal
                .evidence
                .evidence_refs
                .contains(&tombstone.tombstone_digest)
            || !terminal
                .evidence
                .evidence_refs
                .contains(&matches.record_digest)
        {
            return Err(M6ReceiverError::Integrity(
                "receiver revocation terminal coordinator projection is cross-linked".to_string(),
            ));
        }

        let ack_request: ReceiverAcknowledgementRequest =
            parse_canonical(&self.acknowledgement_request_bytes, MAX_RECORD_BYTES)?;
        ack_request.validate_for_context(
            &self.logical_operation_id,
            &request.request_digest,
            &self.sender_message_digest,
            route,
        )?;
        let ack_manifest =
            SignedManifest::from_canonical_bytes(&self.acknowledgement_manifest_bytes)?;
        let ack_issued = IssuedManifest {
            attachments: BTreeMap::new(),
            manifest: ack_manifest,
        };
        validate_ack_issued(&ack_request, &ack_issued, route)?;
        let ack_receipt: ReceiverAcknowledgementReceipt =
            parse_canonical(&self.acknowledgement_receipt_bytes, MAX_RECORD_BYTES)?;
        let ack_delivery = ack_delivery_digest(&ack_issued)?;
        ack_receipt.validate(
            &ack_request,
            &ack_issued,
            route,
            &ack_receipt.issuance_request_digest,
            &ack_delivery,
        )?;
        if ack_request.disposition != "revocation_contained"
            || ack_request.receiver_transaction_digest != terminal.stage_digest
            || ack_request.raw_quarantine_digest != raw.raw_unit_digest
            || ack_receipt.acknowledgement_message_digest != self.acknowledgement_message_digest
        {
            return Err(M6ReceiverError::Integrity(
                "receiver revocation acknowledgement is not the exact contained disposition"
                    .to_string(),
            ));
        }
        require_digest(
            "receiver revocation completion evidence",
            &self.evidence_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ReceiverError> {
        digest_domain(
            REVOCATION_COMPLETION_EVIDENCE_DOMAIN,
            &(
                (
                    &self.schema,
                    &self.route_definition_digest,
                    &self.signing_key_id,
                    &self.logical_operation_id,
                    &self.sender_message_digest,
                    &self.sender_publication_evidence_digest,
                    self.sender_sequence,
                    &self.sender_previous_message_digest,
                    self.sender_issued_at_ms,
                    self.sender_committed_at_ms,
                    &self.prior_source_authorization_evidence_digest,
                    &self.tombstone_digest,
                    &self.receiver_containment_receipt_digest,
                    &self.final_active_snapshot_digest,
                    &self.terminal_stage_digest,
                    &self.acknowledgement_message_digest,
                ),
                (
                    ContentDigest::from_bytes(&self.sender_publication_evidence_bytes),
                    ContentDigest::from_bytes(&self.receiver_request_bytes),
                    ContentDigest::from_bytes(&self.raw_quarantine_record_bytes),
                    digest_domain(REVOCATION_COMPLETION_EVIDENCE_DOMAIN, &self.raw_unit_files)?,
                    ContentDigest::from_bytes(&self.signed_revocation_manifest_bytes),
                    ContentDigest::from_bytes(&self.tombstone_bytes),
                    ContentDigest::from_bytes(&self.match_set_bytes),
                    digest_domain(
                        REVOCATION_COMPLETION_EVIDENCE_DOMAIN,
                        &self.affected_sources,
                    )?,
                    ContentDigest::from_bytes(&self.receiver_coordinator_projection_bytes),
                    ContentDigest::from_bytes(&self.receiver_containment_receipt_bytes),
                    ContentDigest::from_bytes(&self.acknowledgement_request_bytes),
                    ContentDigest::from_bytes(&self.acknowledgement_manifest_bytes),
                    ContentDigest::from_bytes(&self.acknowledgement_receipt_bytes),
                ),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::component::ComponentExecutionLimits;
    use crate::factory_reproduction::{
        BenchmarkSpec, FACTORY_PACKAGE_SCHEMA, InvariantKind, InvariantSpec, MutableFactoryPolicy,
        RecursionBudgets, ReleaseGate, ReleaseThresholds, StableInterfaceContract,
        StateCompatibility,
    };
    use crate::m1_validation::{ValidationCase, ValidationSuite};
    use crate::m5_runtime::{M5InitializationAuthority, M5SeedCyclePlan};
    use crate::m6_authority::{
        ActionAuthorizationRequest, AuthorizationIssuer, OpaqueAuthorizationSigner,
    };
    use crate::m6_identity::{
        DeterministicClock, DeterministicNonceSource, FactoryIdentityDocument, RouteResourceProfile,
    };
    use crate::m6_revocation::RevocationTargetKindV1;
    use crate::m6_revocation_sender_runtime::{
        M6RevocationSenderRuntime, M6RevocationSenderRuntimeConfig, SenderRevocationReceipt,
    };
    use crate::m6_sender_runtime::{
        M6SenderRuntime, M6SenderRuntimeConfig, PreparedSenderExport, SenderExportReceipt,
    };
    use sha2::{Digest, Sha256};
    use std::sync::{Condvar, Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Each receiver fixture owns multiple M2-M6 runtimes and their lock files.
    // Libtest otherwise starts enough heavyweight fixtures concurrently to
    // exceed macOS's common 256-descriptor soft limit before a behavioral
    // assertion runs. Four still exercises concurrent roots while keeping the
    // harness inside that host-resource boundary.
    const MAX_CONCURRENT_RECEIVER_TEST_RIGS: usize = 4;
    static RECEIVER_TEST_RIG_CONCURRENCY: OnceLock<(Mutex<usize>, Condvar)> = OnceLock::new();

    struct ReceiverTestRigPermit;

    impl ReceiverTestRigPermit {
        fn acquire() -> Self {
            let (active, available) =
                RECEIVER_TEST_RIG_CONCURRENCY.get_or_init(|| (Mutex::new(0), Condvar::new()));
            let mut active = active
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            while *active >= MAX_CONCURRENT_RECEIVER_TEST_RIGS {
                active = available
                    .wait(active)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            *active += 1;
            Self
        }
    }

    impl Drop for ReceiverTestRigPermit {
        fn drop(&mut self) {
            let (active, available) = RECEIVER_TEST_RIG_CONCURRENCY
                .get()
                .expect("receiver test concurrency gate is initialized");
            let mut active = active
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(
                *active > 0,
                "receiver test concurrency permit count underflow"
            );
            *active -= 1;
            available.notify_one();
        }
    }

    #[derive(Clone)]
    struct TestCredential {
        issuer_id: String,
        secret: Vec<u8>,
    }

    impl TestCredential {
        fn new(issuer_id: impl Into<String>) -> Self {
            let issuer_id = issuer_id.into();
            Self {
                secret: format!("receiver-test-secret:{issuer_id}").into_bytes(),
                issuer_id,
            }
        }

        fn proof(&self, payload_digest: &ContentDigest) -> String {
            let mut hasher = Sha256::new();
            hasher.update(b"wasm-biotic:m6:receiver-test-authority:v1");
            hasher.update((self.secret.len() as u64).to_be_bytes());
            hasher.update(&self.secret);
            hasher.update(payload_digest.as_str().as_bytes());
            format!("{:x}", hasher.finalize())
        }
    }

    impl OpaqueAuthorizationSigner for TestCredential {
        fn issuer_id(&self) -> &str {
            &self.issuer_id
        }

        fn sign_authorization(&self, payload_digest: &ContentDigest) -> Result<String, String> {
            Ok(self.proof(payload_digest))
        }
    }

    impl OpaqueAuthorizationVerifier for TestCredential {
        fn issuer_id(&self) -> &str {
            &self.issuer_id
        }

        fn verify_authorization(
            &self,
            payload_digest: &ContentDigest,
            attestation: &str,
        ) -> Result<bool, String> {
            Ok(self.proof(payload_digest) == attestation)
        }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m6-receiver-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create receiver test root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.exists() && std::env::var_os("KEEP_M6_RECEIVER_TEST_ROOT").is_none() {
                fs::remove_dir_all(&self.0).expect("remove receiver test root");
            }
        }
    }

    #[derive(Clone)]
    struct ReceiverTestProfiles {
        intake: EndpointActionProfile,
        proving: EndpointActionProfile,
        approval: EndpointActionProfile,
        promotion: EndpointActionProfile,
        observation: EndpointActionProfile,
        rollback: EndpointActionProfile,
    }

    #[derive(Clone)]
    struct ReceiverTestCredentials {
        intake: TestCredential,
        proving: TestCredential,
        approval: TestCredential,
        promotion: TestCredential,
        observation: TestCredential,
        rollback: TestCredential,
    }

    struct TestRig {
        _root: TestRoot,
        sender_root: PathBuf,
        receiver_root: PathBuf,
        route_root: PathBuf,
        route: RouteDefinition,
        sender_profile: EndpointActionProfile,
        sender_credential: TestCredential,
        revocation_profile: EndpointActionProfile,
        revocation_credential: TestCredential,
        profiles: ReceiverTestProfiles,
        credentials: ReceiverTestCredentials,
        policy: ReceiverImportPolicyV1,
        clock: Arc<DeterministicClock>,
        sender_nonce: Arc<DeterministicNonceSource>,
        receiver_nonce: Arc<DeterministicNonceSource>,
        _permit: ReceiverTestRigPermit,
    }

    impl TestRig {
        fn new(label: &str) -> Self {
            let permit = ReceiverTestRigPermit::acquire();
            let root = TestRoot::new(label);
            let sender_root = root.0.join("sender");
            let receiver_root = root.0.join("receiver");
            let route_root = root.0.join("route");
            fs::create_dir(&sender_root).expect("sender root");
            fs::create_dir(&receiver_root).expect("receiver root");
            fs::create_dir(&route_root).expect("route root");

            initialize_adopted_m5(source_m5_config(&sender_root), "source");
            initialize_adopted_m5(receiver_m5_config(&receiver_root), "receiver");
            let receiver_m5 = M5Runtime::open(receiver_m5_config(&receiver_root), None)
                .expect("open receiver M5 for policy");
            let receiver_bundle = receiver_m5
                .export_active_adopted_bundle()
                .expect("export receiver active package");
            let receiver_package = FactoryPackage::from_canonical_bytes(
                receiver_bundle.active_package().canonical_package_bytes(),
            )
            .expect("receiver active package");
            drop(receiver_m5);

            let sender_profile = EndpointActionProfile::new(
                "profile:sender-export",
                "factory:sender",
                "issuer:sender-export",
                content("sender-export-authority"),
                EndpointAuthorityKind::Export,
            )
            .expect("sender export profile");
            let revocation_profile = EndpointActionProfile::new(
                "profile:sender-revocation",
                "factory:sender",
                "issuer:sender-revocation",
                content("sender-revocation-authority"),
                EndpointAuthorityKind::Revocation,
            )
            .expect("sender revocation profile");
            let profiles = ReceiverTestProfiles {
                intake: receiver_profile("intake", EndpointAuthorityKind::Intake),
                proving: receiver_profile("proving", EndpointAuthorityKind::Proving),
                approval: receiver_profile("approval", EndpointAuthorityKind::Approval),
                promotion: receiver_profile("promotion", EndpointAuthorityKind::Promotion),
                observation: receiver_profile("observation", EndpointAuthorityKind::Observation),
                rollback: receiver_profile("rollback", EndpointAuthorityKind::Rollback),
            };
            let credentials = ReceiverTestCredentials {
                intake: TestCredential::new("issuer:receiver-intake"),
                proving: TestCredential::new("issuer:receiver-proving"),
                approval: TestCredential::new("issuer:receiver-approval"),
                promotion: TestCredential::new("issuer:receiver-promotion"),
                observation: TestCredential::new("issuer:receiver-observation"),
                rollback: TestCredential::new("issuer:receiver-rollback"),
            };
            let exchange_policy = content("receiver-test-exchange-policy");
            let package_schema = ContentDigest::from_bytes(FACTORY_PACKAGE_SCHEMA.as_bytes());
            let interface_schema = StableInterfaceContract::reference()
                .contract_digest()
                .expect("stable interface digest");
            let sender = sender_signer();
            let receiver = receiver_signer();
            let sender_identity = FactoryIdentityDocument::new(
                "factory:sender",
                &sender,
                1,
                1_000_000,
                vec![package_schema.clone()],
                vec![interface_schema.clone()],
                sender_profile.profile_digest().clone(),
                exchange_policy.clone(),
            )
            .expect("sender identity");
            let receiver_identity = FactoryIdentityDocument::new(
                "factory:receiver",
                &receiver,
                1,
                1_000_000,
                vec![package_schema],
                vec![interface_schema],
                content("receiver-authority-profile-set"),
                exchange_policy.clone(),
            )
            .expect("receiver identity");
            let route = RouteDefinition::new(
                format!("route:receiver-runtime-{label}"),
                1,
                &sender_identity,
                &receiver_identity,
                exchange_policy,
                RouteResourceProfile::bounded_default().expect("route resources"),
            )
            .expect("route");
            GovernedFilesystemSpool::initialize(
                &route_root,
                &sender_root,
                &receiver_root,
                route.clone(),
            )
            .expect("initialize route spool");
            let policy = ReceiverImportPolicyV1::for_route(
                format!("policy:receiver-runtime-{label}"),
                &route,
                &receiver_package,
                &validation_suite(),
                crate::m6_import::ReceiverImportLimitsV1::bounded_default(),
                false,
            )
            .expect("receiver import policy");
            Self {
                _root: root,
                sender_root,
                receiver_root,
                route_root,
                route,
                sender_profile,
                sender_credential: TestCredential::new("issuer:sender-export"),
                revocation_profile,
                revocation_credential: TestCredential::new("issuer:sender-revocation"),
                profiles,
                credentials,
                policy,
                clock: Arc::new(DeterministicClock::new(1_000)),
                sender_nonce: Arc::new(DeterministicNonceSource::new([0x31; 32])),
                receiver_nonce: Arc::new(DeterministicNonceSource::new([0x42; 32])),
                _permit: permit,
            }
        }

        fn sender_config(&self) -> M6SenderRuntimeConfig {
            M6SenderRuntimeConfig {
                endpoint_root: self.sender_root.clone(),
                m5: source_m5_config(&self.sender_root),
                route_root: self.route_root.clone(),
                expected_route_definition_digest: self.route.definition_digest.clone(),
                authorization_profile: self.sender_profile.clone(),
                journal_config: JournalConfig::bounded(64, 8).expect("sender journal"),
                retry_policy: RetryPolicy::bounded(8, 8, 1_000).expect("sender retry"),
                max_export_requests: 64,
                max_export_receipts: 64,
            }
        }

        fn receiver_config(&self) -> M6ReceiverRuntimeConfig {
            M6ReceiverRuntimeConfig {
                endpoint_root: self.receiver_root.clone(),
                m5: receiver_m5_config(&self.receiver_root),
                route_root: self.route_root.clone(),
                expected_route_definition_digest: self.route.definition_digest.clone(),
                import_policy: self.policy.clone(),
                intake_authorization_profile: self.profiles.intake.clone(),
                proving_authorization_profile: self.profiles.proving.clone(),
                approval_authorization_profile: self.profiles.approval.clone(),
                promotion_authorization_profile: self.profiles.promotion.clone(),
                observation_authorization_profile: self.profiles.observation.clone(),
                rollback_authorization_profile: self.profiles.rollback.clone(),
                journal_config: JournalConfig::bounded(64, 24).expect("receiver journal"),
                retry_policy: RetryPolicy::bounded(8, 8, 1_000).expect("receiver retry"),
                max_intake_operations: 64,
            }
        }

        fn open_sender(&self) -> M6SenderRuntime<TestCredential> {
            let clock: Arc<dyn Clock> = self.clock.clone();
            let nonce: Arc<dyn NonceSource> = self.sender_nonce.clone();
            M6SenderRuntime::open(
                self.sender_config(),
                self.sender_credential.clone(),
                sender_signer(),
                clock,
                nonce,
                None,
            )
            .expect("open sender")
        }

        fn open_revocation_sender(&self) -> M6RevocationSenderRuntime<TestCredential> {
            let clock: Arc<dyn Clock> = self.clock.clone();
            let nonce: Arc<dyn NonceSource> = self.sender_nonce.clone();
            M6RevocationSenderRuntime::open(
                M6RevocationSenderRuntimeConfig {
                    endpoint_root: self.sender_root.clone(),
                    route_root: self.route_root.clone(),
                    expected_route_definition_digest: self.route.definition_digest.clone(),
                    authorization_profile: self.revocation_profile.clone(),
                    journal_config: JournalConfig::bounded(64, 8)
                        .expect("sender revocation journal"),
                    retry_policy: RetryPolicy::bounded(8, 8, 1_000)
                        .expect("sender revocation retry"),
                    max_revocation_requests: 64,
                    max_revocation_receipts: 64,
                },
                self.revocation_credential.clone(),
                sender_signer(),
                clock,
                nonce,
            )
            .expect("open sender revocation runtime")
        }

        fn publish_revocation(
            &self,
            operation: &str,
            target_kind: RevocationTargetKindV1,
            target_identity: ContentDigest,
            prior_source_evidence: ContentDigest,
        ) -> SenderRevocationReceipt {
            let mut sender = self.open_revocation_sender();
            let prepared = sender
                .prepare_revocation(
                    operation,
                    "principal:revocation-operator",
                    target_kind,
                    target_identity,
                    format!("revoke exact fixture {operation}"),
                    prior_source_evidence,
                    60_000,
                )
                .expect("prepare sender revocation");
            let authorization = sender
                .publish_authorization(self.issue(
                    &self.revocation_profile,
                    &self.revocation_credential,
                    prepared.authorization_binding,
                ))
                .expect("publish revocation authority");
            sender
                .commit_revocation(operation, &authorization)
                .expect("commit sender revocation")
        }

        fn open_receiver(&self) -> M6ReceiverRuntime<TestCredential> {
            self.open_receiver_with_config(self.receiver_config())
                .expect("open receiver")
        }

        fn open_receiver_with_config(
            &self,
            config: M6ReceiverRuntimeConfig,
        ) -> Result<M6ReceiverRuntime<TestCredential>, M6ReceiverError> {
            let clock: Arc<dyn Clock> = self.clock.clone();
            let nonce: Arc<dyn NonceSource> = self.receiver_nonce.clone();
            M6ReceiverRuntime::open(
                config,
                ReceiverAuthorityVerifiers {
                    intake: self.credentials.intake.clone(),
                    proving: self.credentials.proving.clone(),
                    approval: self.credentials.approval.clone(),
                    promotion: self.credentials.promotion.clone(),
                    observation: self.credentials.observation.clone(),
                    rollback: self.credentials.rollback.clone(),
                },
                receiver_signer(),
                clock,
                nonce,
                None,
            )
        }

        fn issue(
            &self,
            profile: &EndpointActionProfile,
            credential: &TestCredential,
            binding: ExactActionBinding,
        ) -> ActionAuthorization {
            AuthorizationIssuer::new(profile.clone(), credential.clone())
                .expect("authorization issuer")
                .issue(
                    ActionAuthorizationRequest::new(binding, 1).expect("single-use request"),
                    self.clock.now_ms().expect("clock"),
                    900_000,
                )
                .expect("issue authorization")
        }

        fn authorize_sender(
            &self,
            runtime: &M6SenderRuntime<TestCredential>,
            prepared: &PreparedSenderExport,
        ) -> ContentDigest {
            runtime
                .publish_authorization(self.issue(
                    &self.sender_profile,
                    &self.sender_credential,
                    prepared.authorization_binding.clone(),
                ))
                .expect("publish sender authority")
        }

        fn authorize_receiver(
            &self,
            runtime: &M6ReceiverRuntime<TestCredential>,
            profile: &EndpointActionProfile,
            credential: &TestCredential,
            binding: ExactActionBinding,
        ) -> ContentDigest {
            runtime
                .publish_authorization(self.issue(profile, credential, binding))
                .expect("publish receiver authority")
        }

        fn publish_export(&self, intake_operation: &str) -> SenderExportReceipt {
            let export_operation = format!("export:{intake_operation}");
            let mut sender = self.open_sender();
            let prepared = sender
                .prepare_export(&export_operation, "principal:sender", 60_000)
                .expect("prepare export");
            let authorization = self.authorize_sender(&sender, &prepared);
            sender
                .commit_export(&export_operation, &authorization)
                .expect("commit export")
        }

        fn ready_for_approval(
            &self,
            operation: &str,
        ) -> (M6ReceiverRuntime<TestCredential>, PreparedReceiverApproval) {
            let export_receipt = self.publish_export(operation);
            let mut receiver = self.open_receiver();
            let intake = receiver
                .prepare_intake(
                    operation,
                    "principal:receiver",
                    export_receipt.message_digest,
                    100_000,
                )
                .expect("prepare intake");
            let intake_authorization = self.authorize_receiver(
                &receiver,
                &self.profiles.intake,
                &self.credentials.intake,
                intake.authorization_binding,
            );
            let proving = match receiver
                .admit_and_authenticate(operation, &intake_authorization)
                .expect("admit intake")
            {
                ReceiverAdmissionResult::AwaitingProving(prepared) => prepared,
                _ => panic!("receiver admission returned an unexpected bounded outcome"),
            };
            let proving_authorization = self.authorize_receiver(
                &receiver,
                &self.profiles.proving,
                &self.credentials.proving,
                proving.authorization_binding,
            );
            let approval = match receiver
                .prove_and_plan(operation, &proving_authorization)
                .expect("prove and plan")
            {
                ReceiverProvingResult::AwaitingApproval(prepared) => prepared,
                _ => panic!("receiver proving returned an unexpected bounded outcome"),
            };
            (receiver, approval)
        }

        fn ready_for_promotion(
            &self,
            operation: &str,
        ) -> (
            M6ReceiverRuntime<TestCredential>,
            PreparedReceiverPromotion,
            ContentDigest,
            ContentDigest,
            ContentDigest,
        ) {
            let mut sender = self.open_sender();
            let export = sender
                .prepare_export(format!("export:{operation}"), "principal:sender", 60_000)
                .expect("prepare export");
            let export_authorization = self.authorize_sender(&sender, &export);
            let export_receipt = sender
                .commit_export(&format!("export:{operation}"), &export_authorization)
                .expect("commit export");
            drop(sender);

            let mut receiver = self.open_receiver();
            let intake = receiver
                .prepare_intake(
                    operation,
                    "principal:receiver",
                    export_receipt.message_digest,
                    100_000,
                )
                .expect("prepare intake");
            let intake_authorization = self.authorize_receiver(
                &receiver,
                &self.profiles.intake,
                &self.credentials.intake,
                intake.authorization_binding,
            );
            let proving = match receiver
                .admit_and_authenticate(operation, &intake_authorization)
                .expect("admit intake")
            {
                ReceiverAdmissionResult::AwaitingProving(prepared) => prepared,
                _ => panic!("receiver admission returned an unexpected bounded outcome"),
            };
            let proving_authorization = self.authorize_receiver(
                &receiver,
                &self.profiles.proving,
                &self.credentials.proving,
                proving.authorization_binding,
            );
            match receiver
                .prove_and_plan(operation, &proving_authorization)
                .expect("prove and plan")
            {
                ReceiverProvingResult::AwaitingApproval(_) => {}
                _ => panic!("receiver proving returned an unexpected bounded outcome"),
            }
            let prepared_decision = receiver
                .prepare_approval_decision(
                    operation,
                    ApprovalDecisionKind::Granted,
                    "principal:receiver-operator",
                    "approve exact receiver import",
                )
                .expect("prepare granted decision");
            let approval_authorization = self.authorize_receiver(
                &receiver,
                &self.profiles.approval,
                &self.credentials.approval,
                prepared_decision.authorization_binding,
            );
            let promotion = match receiver
                .decide_approval(
                    operation,
                    &approval_authorization,
                    prepared_decision.decision_intent,
                )
                .expect("record granted decision")
            {
                ReceiverApprovalResult::ReadyForPromotion(prepared) => prepared,
                _ => panic!("receiver approval returned an unexpected bounded outcome"),
            };
            let promotion_authorization = self.authorize_receiver(
                &receiver,
                &self.profiles.promotion,
                &self.credentials.promotion,
                promotion.authorization_binding.clone(),
            );
            let observation_authorization = self.authorize_receiver(
                &receiver,
                &self.profiles.observation,
                &self.credentials.observation,
                promotion.observation_authorization_binding.clone(),
            );
            let rollback_authorization = self.authorize_receiver(
                &receiver,
                &self.profiles.rollback,
                &self.credentials.rollback,
                promotion.rollback_authorization_binding.clone(),
            );
            (
                receiver,
                promotion,
                promotion_authorization,
                observation_authorization,
                rollback_authorization,
            )
        }
    }

    fn receiver_profile(label: &str, kind: EndpointAuthorityKind) -> EndpointActionProfile {
        EndpointActionProfile::new(
            format!("profile:receiver-{label}"),
            "factory:receiver",
            format!("issuer:receiver-{label}"),
            content(&format!("receiver-{label}-authority")),
            kind,
        )
        .expect("receiver profile")
    }

    fn source_m5_config(root: &Path) -> M5RuntimeConfig {
        M5RuntimeConfig {
            root: root.join("m5"),
            factory_id: "factory:sender".to_string(),
            scope_id: "scope:m6-receiver-source".to_string(),
            deployment_id: "deployment-m6-receiver-source".to_string(),
            worker_max_concurrency: 1,
        }
    }

    fn receiver_m5_config(root: &Path) -> M5RuntimeConfig {
        M5RuntimeConfig {
            root: root.join("m5"),
            factory_id: "factory:receiver".to_string(),
            scope_id: "scope:m6-receiver-target".to_string(),
            deployment_id: "deployment-m6-receiver-target".to_string(),
            worker_max_concurrency: 1,
        }
    }

    fn initialize_adopted_m5(config: M5RuntimeConfig, label: &str) {
        let runtime = M5Runtime::initialize(
            config,
            incumbent_wat(),
            validation_suite(),
            release_gate(label),
            1,
            M5InitializationAuthority {
                operator_ref: format!("operator:{label}-bootstrap"),
                rationale: "initialize exact receiver runtime fixture".to_string(),
            },
            None,
        )
        .expect("initialize M5");
        let outcome = runtime
            .run_seeded_cycle(approved_seed(
                &format!("cycle:{label}-n1"),
                if label == "receiver" {
                    equivalent_successor_wat()
                } else {
                    successor_wat()
                },
            ))
            .expect("adopt M5 fixture package");
        assert!(matches!(outcome, CycleOutcome::Adopted { .. }));
    }

    fn content(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(label.as_bytes())
    }

    fn sender_signer() -> FactorySigner {
        FactorySigner::from_seed("key:sender", [0x51; 32]).expect("sender signer")
    }

    fn receiver_signer() -> FactorySigner {
        FactorySigner::from_seed("key:receiver", [0x72; 32]).expect("receiver signer")
    }

    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct TestDeliveryCommitMarker {
        manifest_bytes_digest: ContentDigest,
        message_digest: ContentDigest,
        schema: String,
    }

    fn copy_control_fixture_tree(source: &Path, destination: &Path) {
        fs::create_dir(destination).expect("create hostile ready unit");
        for entry in fs::read_dir(source).expect("read source ready unit") {
            let entry = entry.expect("read source ready entry");
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            if entry.file_type().expect("source ready entry type").is_dir() {
                copy_control_fixture_tree(&source_path, &destination_path);
            } else {
                fs::copy(&source_path, &destination_path).expect("copy hostile ready file");
            }
        }
    }

    fn clone_ready_unit_with_manifest(
        spool: &GovernedFilesystemSpool,
        source_message_digest: &ContentDigest,
        target_message_digest: &ContentDigest,
        manifest_bytes: &[u8],
    ) {
        let source = spool.outbound_ready_unit_directory(source_message_digest);
        let destination = spool.outbound_ready_unit_directory(target_message_digest);
        copy_control_fixture_tree(&source, &destination);
        fs::write(destination.join("manifest.json"), manifest_bytes)
            .expect("write hostile manifest bytes");
        fs::write(
            destination.join("commit.json"),
            canonical_json(&TestDeliveryCommitMarker {
                manifest_bytes_digest: ContentDigest::from_bytes(manifest_bytes),
                message_digest: target_message_digest.clone(),
                schema: crate::m6_identity::DELIVERY_COMMIT_SCHEMA.to_string(),
            })
            .expect("encode hostile delivery commit"),
        )
        .expect("write hostile delivery commit");
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

    fn successor_wat() -> Vec<u8> {
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

    fn equivalent_successor_wat() -> Vec<u8> {
        component_wat(
            r#"local.get 0
               i32.const -2147483648
               i32.eq
               if (result i32)
                   i32.const 2
               else
                   local.get 0
                   i32.const 0
                   i32.add
                   i32.const 1
                   i32.add
               end"#,
        )
    }

    fn validation_suite() -> ValidationSuite {
        ValidationSuite::new(
            "m6-receiver-suite",
            "transform",
            vec![
                ValidationCase::returns("case:one", 1, 2),
                ValidationCase::returns("case:seven", 7, 8),
            ],
            ComponentExecutionLimits::default(),
        )
        .expect("validation suite")
    }

    fn release_gate(label: &str) -> ReleaseGate {
        let benchmarks = [(1_i32, 2_i32), (7_i32, 8_i32)]
            .into_iter()
            .enumerate()
            .map(|(index, (input, output))| BenchmarkSpec {
                benchmark_id: format!("benchmark:{label}:{index}"),
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
            invariant_id: format!("invariant:{label}:{index}"),
            kind,
            required: true,
        })
        .collect();
        ReleaseGate::new(
            format!("m6-receiver-gate-{label}"),
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
        .expect("release gate")
    }

    fn approved_seed(cycle_id: &str, challenger_wat_bytes: Vec<u8>) -> M5SeedCyclePlan {
        M5SeedCyclePlan {
            cycle_id: cycle_id.to_string(),
            challenger_wat_bytes,
            challenger_policy: MutableFactoryPolicy::terminal(2, 2),
            state_compatibility: StateCompatibility {
                readable_schema_min: 1,
                readable_schema_max: 2,
                written_schema: 1,
                incumbent_rollback_readable_through: 2,
            },
            migration_plan: None,
            migration_artifacts: None,
            operator_context_digest: content("receiver-test-operator-context"),
            approval_decision: ApprovalDecision::Approved,
            approver_ref: "operator:receiver-test".to_string(),
            approval_rationale: "approve exact fixture".to_string(),
        }
    }

    fn assert_injected_crash<T>(result: Result<T, M6ReceiverError>, expected: ReceiverCrashPoint) {
        match result {
            Err(M6ReceiverError::InjectedCrash(actual)) if actual == expected => {}
            Err(error) => panic!("expected crash at {expected:?}, got {error}"),
            Ok(_) => panic!("expected crash at {expected:?}, operation completed"),
        }
    }

    fn assert_unique_transaction_stages(
        runtime: &M6ReceiverRuntime<TestCredential>,
        operation: &str,
        expected_terminal: TransactionStage,
    ) {
        let projection = runtime
            .journal
            .transaction(operation)
            .expect("load receiver transaction")
            .expect("receiver transaction exists");
        assert_eq!(projection.current_stage(), Some(expected_terminal));
        let unique = projection
            .stages
            .iter()
            .map(|record| record.stage)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            unique.len(),
            projection.stages.len(),
            "recovery must not duplicate a coordinator stage"
        );
    }

    fn assert_terminal_import_recovery(
        runtime: &M6ReceiverRuntime<TestCredential>,
        operation: &str,
        expected_terminal: TransactionStage,
        expected_ack: &str,
    ) {
        assert_unique_transaction_stages(runtime, operation, expected_terminal);
        let acknowledgement = runtime
            .load_acknowledgement(operation)
            .expect("load terminal acknowledgement")
            .expect("terminal acknowledgement exists");
        assert_eq!(acknowledgement.disposition, expected_ack);
        assert_eq!(
            runtime
                .unresolved_quarantine_inventory()
                .expect("load terminal quarantine inventory")
                .unresolved_count(),
            0,
            "terminal recovery must leave no unresolved quarantined operation"
        );
    }

    fn assert_terminal_revocation_recovery(
        runtime: &M6ReceiverRuntime<TestCredential>,
        operation: &str,
        expected_terminal: TransactionStage,
        expected_ack: &str,
        expected_evidence: &ContentDigest,
    ) {
        assert_unique_transaction_stages(runtime, operation, expected_terminal);
        let root = revocation_operation_root(&runtime.revocation_operations_root, operation);
        let request = load_revocation_request_unit(
            &root,
            runtime.route(),
            &runtime.revocations.config().config_digest,
        )
        .expect("load revocation request");
        let ack_request: ReceiverAcknowledgementRequest =
            load_canonical_file(&root.join(ACK_REQUEST_FILE), MAX_RECORD_BYTES)
                .expect("load revocation acknowledgement request");
        ack_request
            .validate_for_context(
                operation,
                &request.request_digest,
                &request.message_digest,
                runtime.route(),
            )
            .expect("validate revocation acknowledgement request");
        assert_eq!(ack_request.disposition, expected_ack);
        assert_eq!(&ack_request.raw_quarantine_digest, expected_evidence);
        let receipt: ReceiverAcknowledgementReceipt =
            load_canonical_file(&root.join(ACK_RECEIPT_FILE), MAX_RECORD_BYTES)
                .expect("load revocation acknowledgement receipt");
        let ready = runtime
            .spool
            .read_outbound_ready(&receipt.acknowledgement_message_digest)
            .expect("load ready revocation acknowledgement");
        let delivery = ack_delivery_digest(&ready).expect("derive acknowledgement delivery");
        receipt
            .validate(
                &ack_request,
                &ready,
                runtime.route(),
                &receipt.issuance_request_digest,
                &delivery,
            )
            .expect("validate revocation acknowledgement");
    }

    fn assert_exactly_one_m5_cycle(runtime: &M6ReceiverRuntime<TestCredential>, operation: &str) {
        let cycle_id = activation_cycle_id(operation);
        let state = runtime.m5.state_snapshot().expect("load receiver M5 state");
        assert_eq!(
            state
                .cycles
                .iter()
                .filter(|cycle| cycle.cycle_id == cycle_id)
                .count(),
            1,
            "crash recovery must execute the exact M5 cycle once"
        );
    }

    #[test]
    fn m5_root_rejects_every_exact_identity_directory_collision() {
        let endpoint = PathBuf::from("/receiver");
        for directory in IDENTITY_MUTABLE_TOP_LEVEL_DIRECTORIES {
            let error = ensure_m5_root_isolated(&endpoint, &endpoint.join(directory))
                .expect_err("exact identity-layer collision must fail closed");
            assert!(matches!(
                error,
                M6ReceiverError::InvalidConfiguration(message)
                    if message.contains(directory)
            ));
        }
    }

    #[test]
    fn m5_root_rejects_nested_receiver_and_identity_directory_collisions() {
        let endpoint = PathBuf::from("/receiver");
        for directory in [
            OPERATIONS_DIRECTORY,
            PROMOTION_AUTHORITY_DIRECTORY,
            "m6-issued-manifests",
            "m6-raw-quarantine",
        ] {
            let nested = endpoint.join(directory).join("nested-m5");
            assert!(
                ensure_m5_root_isolated(&endpoint, &nested).is_err(),
                "nested M5 root under {directory} must fail closed"
            );
        }
        assert!(ensure_m5_root_isolated(&endpoint, &endpoint.join("m5")).is_ok());
    }

    #[test]
    fn receiver_open_rejects_exact_and_nested_identity_root_collisions() {
        let rig = TestRig::new("m5-root-open-collision");
        for (index, root) in [
            rig.receiver_root.join("m6-issued-manifests"),
            rig.receiver_root
                .join("m6-raw-quarantine")
                .join("nested-m5"),
        ]
        .into_iter()
        .enumerate()
        {
            fs::create_dir_all(&root).expect("create colliding M5 root");
            let mut config = rig.receiver_config();
            config.m5.root = root;
            assert!(
                matches!(
                    rig.open_receiver_with_config(config),
                    Err(M6ReceiverError::InvalidConfiguration(message))
                        if message.contains("overlaps reserved directory")
                ),
                "collision fixture {index} must fail before any child store opens"
            );
        }
    }

    #[test]
    fn receiver_open_enforces_route_bound_journal_and_retry_profiles_at_boundary_and_plus_one() {
        let rig = TestRig::new("route-resource-open-bounds");
        let profile = rig.route.resource_profile.clone();

        let mut transaction_overflow = rig.receiver_config();
        transaction_overflow.journal_config =
            JournalConfig::bounded(profile.max_transaction_records + 1, 24)
                .expect("locally valid transaction overflow");
        assert!(matches!(
            rig.open_receiver_with_config(transaction_overflow),
            Err(M6ReceiverError::Transaction(message))
                if message.contains("transaction count exceeds")
        ));

        let mut retry_overflow = rig.receiver_config();
        retry_overflow.retry_policy = RetryPolicy::bounded(
            profile.max_retry_attempts + 1,
            profile.max_recovery_attempts,
            profile.max_message_lifetime_ms,
        )
        .expect("locally valid retry overflow");
        assert!(matches!(
            rig.open_receiver_with_config(retry_overflow),
            Err(M6ReceiverError::Transaction(message))
                if message.contains("retry policy exceeds")
        ));

        let mut recovery_overflow = rig.receiver_config();
        recovery_overflow.retry_policy = RetryPolicy::bounded(
            profile.max_retry_attempts + 1,
            profile.max_recovery_attempts + 1,
            profile.max_message_lifetime_ms,
        )
        .expect("locally valid recovery overflow");
        assert!(matches!(
            rig.open_receiver_with_config(recovery_overflow),
            Err(M6ReceiverError::Transaction(message))
                if message.contains("retry policy exceeds")
        ));

        let mut timeout_overflow = rig.receiver_config();
        timeout_overflow.retry_policy = RetryPolicy::bounded(
            profile.max_retry_attempts,
            profile.max_recovery_attempts,
            profile.max_message_lifetime_ms + 1,
        )
        .expect("locally valid timeout overflow");
        assert!(matches!(
            rig.open_receiver_with_config(timeout_overflow),
            Err(M6ReceiverError::Transaction(message))
                if message.contains("retry policy exceeds")
        ));

        let mut exact_boundary = rig.receiver_config();
        exact_boundary.journal_config = JournalConfig::bounded(profile.max_transaction_records, 24)
            .expect("route-bound transaction budget");
        exact_boundary.retry_policy = RetryPolicy::bounded(
            profile.max_retry_attempts,
            profile.max_recovery_attempts,
            profile.max_message_lifetime_ms,
        )
        .expect("route-bound retry budget");
        drop(
            rig.open_receiver_with_config(exact_boundary)
                .expect("exact route resource boundary must open"),
        );
    }

    #[test]
    fn import_crash_matrix_reopens_each_uncovered_success_seam_exactly_once() {
        let operation = "intake:systematic-success-crash-matrix";
        let rig = TestRig::new("systematic-success-crash-matrix");
        let export_receipt = rig.publish_export(operation);
        let mut runtime = rig.open_receiver();

        for point in [
            ReceiverCrashPoint::OuterRequestPersisted,
            ReceiverCrashPoint::IntakeIntentRecorded,
        ] {
            assert_injected_crash(
                runtime.prepare_intake_with_fault(
                    operation,
                    "principal:receiver",
                    export_receipt.message_digest.clone(),
                    100_000,
                    Some(point),
                ),
                point,
            );
            drop(runtime);
            runtime = rig.open_receiver();
        }
        let intake = runtime
            .prepare_intake(
                operation,
                "principal:receiver",
                export_receipt.message_digest,
                100_000,
            )
            .expect("resume exact intake preparation");
        let intake_authorization = rig.authorize_receiver(
            &runtime,
            &rig.profiles.intake,
            &rig.credentials.intake,
            intake.authorization_binding,
        );

        for point in [
            ReceiverCrashPoint::IntakeAuthorizationConsumed,
            ReceiverCrashPoint::RawAdmissionCommitted,
            ReceiverCrashPoint::RawQuarantinedStage,
            ReceiverCrashPoint::SenderAuthenticated,
            ReceiverCrashPoint::SenderEvidenceRecordsCommitted,
            ReceiverCrashPoint::ReplayCommitted,
            ReceiverCrashPoint::ReplayStageCommitted,
            ReceiverCrashPoint::SenderEvidenceVerified,
        ] {
            assert_injected_crash(
                runtime.admit_and_authenticate_with_fault(
                    operation,
                    &intake_authorization,
                    Some(point),
                ),
                point,
            );
            drop(runtime);
            runtime = rig.open_receiver();
        }
        let proving = match runtime
            .admit_and_authenticate(operation, &intake_authorization)
            .expect("resume exact admission")
        {
            ReceiverAdmissionResult::AwaitingProving(prepared) => prepared,
            _ => panic!("recovered admission returned an unexpected bounded outcome"),
        };
        let intake_consumption = runtime
            .intake_authority
            .load_consumption(&intake_authorization, 1)
            .expect("load exact intake authority consumption");
        let proving_authorization = rig.authorize_receiver(
            &runtime,
            &rig.profiles.proving,
            &rig.credentials.proving,
            proving.authorization_binding,
        );

        for point in [
            ReceiverCrashPoint::ProvingAuthorizationConsumed,
            ReceiverCrashPoint::ProvingRecordCommitted,
            ReceiverCrashPoint::ReceiverProvingCommitted,
            ReceiverCrashPoint::ImportPlanCommitted,
            ReceiverCrashPoint::ApprovalRequestCommitted,
            ReceiverCrashPoint::AwaitingApproval,
        ] {
            assert_injected_crash(
                runtime.prove_and_plan_with_fault(operation, &proving_authorization, Some(point)),
                point,
            );
            drop(runtime);
            runtime = rig.open_receiver();
        }
        let approval = match runtime
            .prove_and_plan(operation, &proving_authorization)
            .expect("resume exact proving and planning")
        {
            ReceiverProvingResult::AwaitingApproval(prepared) => prepared,
            _ => panic!("recovered proving returned an unexpected bounded outcome"),
        };
        assert_eq!(
            runtime
                .intake_authority
                .load_consumption(&intake_authorization, 1)
                .expect("reopen intake authority consumption"),
            intake_consumption,
            "recovery must resolve the same intake use"
        );
        let proving_consumption = runtime
            .proving_authority
            .load_consumption(&proving_authorization, 1)
            .expect("load exact proving authority consumption");

        let decision = runtime
            .prepare_approval_decision(
                operation,
                ApprovalDecisionKind::Granted,
                "principal:receiver-operator",
                "approve systematic crash recovery",
            )
            .expect("prepare granted approval");
        assert_eq!(
            approval.approval_request.request_digest(),
            &decision.approval_request_digest
        );
        let decision_intent = decision.decision_intent;
        let approval_authorization = rig.authorize_receiver(
            &runtime,
            &rig.profiles.approval,
            &rig.credentials.approval,
            decision.authorization_binding,
        );
        assert_injected_crash(
            runtime.decide_approval_with_fault(
                operation,
                &approval_authorization,
                decision_intent.clone(),
                Some(ReceiverCrashPoint::ApprovalDecisionCommitted),
            ),
            ReceiverCrashPoint::ApprovalDecisionCommitted,
        );
        drop(runtime);
        runtime = rig.open_receiver();
        let promotion = match runtime
            .decide_approval(operation, &approval_authorization, decision_intent)
            .expect("resume exact granted approval")
        {
            ReceiverApprovalResult::ReadyForPromotion(prepared) => prepared,
            _ => panic!("recovered approval returned an unexpected bounded outcome"),
        };
        assert_eq!(
            runtime
                .proving_authority
                .load_consumption(&proving_authorization, 1)
                .expect("reopen proving authority consumption"),
            proving_consumption,
            "recovery must resolve the same proving use"
        );

        let promotion_authorization = rig.authorize_receiver(
            &runtime,
            &rig.profiles.promotion,
            &rig.credentials.promotion,
            promotion.authorization_binding,
        );
        let observation_authorization = rig.authorize_receiver(
            &runtime,
            &rig.profiles.observation,
            &rig.credentials.observation,
            promotion.observation_authorization_binding,
        );
        let rollback_authorization = rig.authorize_receiver(
            &runtime,
            &rig.profiles.rollback,
            &rig.credentials.rollback,
            promotion.rollback_authorization_binding,
        );

        for point in [
            ReceiverCrashPoint::M5CycleCommitted,
            ReceiverCrashPoint::ActivationEffectCommitted,
            ReceiverCrashPoint::ObservationIntentRecorded,
            ReceiverCrashPoint::HealthyCommitted,
            ReceiverCrashPoint::AdoptionReceiptCommitted,
            ReceiverCrashPoint::AcknowledgementRequestCommitted,
            ReceiverCrashPoint::AcknowledgementPrepared,
            ReceiverCrashPoint::AcknowledgementChainCommitted,
            ReceiverCrashPoint::AcknowledgementRouteStaged,
            ReceiverCrashPoint::AcknowledgementRouteReady,
            ReceiverCrashPoint::AcknowledgementReceiptCommitted,
        ] {
            assert_injected_crash(
                runtime.commit_adoption_with_fault(
                    operation,
                    &promotion_authorization,
                    &observation_authorization,
                    &rollback_authorization,
                    Some(point),
                ),
                point,
            );
            drop(runtime);
            runtime = rig.open_receiver();
        }
        let result = runtime
            .recover_adoption(
                operation,
                &promotion_authorization,
                &observation_authorization,
                &rollback_authorization,
            )
            .expect("resume exact healthy adoption");
        let ReceiverAdoptionResult::Adopted(receipt) = result else {
            panic!("recovered import did not produce an adoption receipt");
        };
        assert_eq!(receipt.disposition, ReceiverM5Disposition::Healthy);
        assert_exactly_one_m5_cycle(&runtime, operation);
        assert_terminal_import_recovery(&runtime, operation, TransactionStage::Healthy, "healthy");
        runtime
            .load_exchange_completion_evidence(operation)
            .expect("reopen all recovered exchange sources")
            .expect("recovered exchange completion exists");
    }

    #[test]
    fn denial_crash_reopens_terminal_decision_without_effect_or_duplicate_ack() {
        let operation = "intake:systematic-denial-crash";
        let rig = TestRig::new("systematic-denial-crash");
        let (mut runtime, approval) = rig.ready_for_approval(operation);
        let prepared = runtime
            .prepare_approval_decision(
                operation,
                ApprovalDecisionKind::Denied,
                "principal:receiver-operator",
                "deny systematic terminal recovery fixture",
            )
            .expect("prepare denial");
        assert_eq!(
            approval.approval_request.request_digest(),
            &prepared.approval_request_digest
        );
        let intent = prepared.decision_intent;
        let authorization = rig.authorize_receiver(
            &runtime,
            &rig.profiles.approval,
            &rig.credentials.approval,
            prepared.authorization_binding,
        );
        assert_injected_crash(
            runtime.decide_approval_with_fault(
                operation,
                &authorization,
                intent.clone(),
                Some(ReceiverCrashPoint::ApprovalTerminalCommitted),
            ),
            ReceiverCrashPoint::ApprovalTerminalCommitted,
        );
        drop(runtime);

        let mut recovered = rig.open_receiver();
        let result = recovered
            .decide_approval(operation, &authorization, intent)
            .expect("resume exact denial");
        assert!(matches!(
            result,
            ReceiverApprovalResult::Terminal(ReceiverTerminalDecision {
                kind: ReceiverTerminalKind::Denied,
                ..
            })
        ));
        assert_terminal_import_recovery(&recovered, operation, TransactionStage::Denied, "denied");
        assert_eq!(
            recovered
                .m5
                .state_snapshot()
                .expect("load receiver M5 state")
                .cycles
                .iter()
                .filter(|cycle| cycle.cycle_id == activation_cycle_id(operation))
                .count(),
            0,
            "terminal approval recovery must not execute M5"
        );
    }

    #[test]
    fn rollback_crash_matrix_reopens_both_branch_only_seams_exactly_once() {
        let operation = "intake:systematic-rollback-crash-matrix";
        let rig = TestRig::new("systematic-rollback-crash-matrix");
        let (
            mut runtime,
            _promotion,
            promotion_authorization,
            observation_authorization,
            rollback_authorization,
        ) = rig.ready_for_promotion(operation);
        let prior_snapshot = runtime
            .m5
            .active_runtime_snapshot()
            .expect("capture prior receiver snapshot");
        runtime
            .induce_next_health_regression()
            .expect("arm exact health regression");

        for point in [
            ReceiverCrashPoint::RollbackIntentRecorded,
            ReceiverCrashPoint::RolledBackCommitted,
        ] {
            assert_injected_crash(
                runtime.commit_adoption_with_fault(
                    operation,
                    &promotion_authorization,
                    &observation_authorization,
                    &rollback_authorization,
                    Some(point),
                ),
                point,
            );
            drop(runtime);
            runtime = rig.open_receiver();
        }
        let result = runtime
            .recover_adoption(
                operation,
                &promotion_authorization,
                &observation_authorization,
                &rollback_authorization,
            )
            .expect("resume exact rolled-back adoption");
        let ReceiverAdoptionResult::Adopted(receipt) = result else {
            panic!("rollback recovery did not return adoption receipt");
        };
        assert_eq!(receipt.disposition, ReceiverM5Disposition::RolledBack);
        assert_eq!(
            runtime
                .m5
                .active_runtime_snapshot()
                .expect("load restored receiver snapshot")
                .snapshot_digest,
            prior_snapshot.snapshot_digest
        );
        assert_exactly_one_m5_cycle(&runtime, operation);
        assert_terminal_import_recovery(
            &runtime,
            operation,
            TransactionStage::RolledBack,
            "rolled_back",
        );
    }

    #[test]
    fn revocation_crash_matrix_reopens_prepare_admission_and_terminal_seams_exactly_once() {
        let operation = "receiver-revocation:systematic-unmatched";
        let rig = TestRig::new("systematic-unmatched-revocation-crash-matrix");
        let publication = rig.publish_revocation(
            "sender-revocation:systematic-unmatched",
            RevocationTargetKindV1::ExchangeMessage,
            content("unmatched-revocation-target"),
            content("unmatched-revocation-prior-source"),
        );
        let mut runtime = rig.open_receiver();

        for point in [
            ReceiverCrashPoint::RevocationRequestPersisted,
            ReceiverCrashPoint::RevocationIntakeIntentRecorded,
        ] {
            assert_injected_crash(
                runtime.prepare_revocation_intake_with_fault(
                    operation,
                    publication.message_digest.clone(),
                    100_000,
                    Some(point),
                ),
                point,
            );
            drop(runtime);
            runtime = rig.open_receiver();
        }
        runtime
            .prepare_revocation_intake(operation, publication.message_digest.clone(), 100_000)
            .expect("resume exact revocation preparation");

        for point in [
            ReceiverCrashPoint::RevocationRawAdmissionCommitted,
            ReceiverCrashPoint::RevocationRawQuarantined,
            ReceiverCrashPoint::RevocationAuthenticated,
            ReceiverCrashPoint::RevocationReplayCommitted,
            ReceiverCrashPoint::RevocationTombstoneCommitted,
            ReceiverCrashPoint::RevocationAffectedImportsCommitted,
        ] {
            assert_injected_crash(
                runtime.admit_revocation_with_fault(operation, Some(point)),
                point,
            );
            drop(runtime);
            runtime = rig.open_receiver();
        }
        let prepared = match runtime
            .admit_revocation(operation)
            .expect("resume exact revocation admission")
        {
            ReceiverRevocationAdmissionResult::AwaitingContainment(prepared) => prepared,
            _ => panic!("recovered revocation admission returned an unexpected bounded outcome"),
        };
        assert!(prepared.affected_operations.is_empty());
        let tombstone = prepared.tombstone;
        assert_injected_crash(
            runtime.contain_revocation_with_fault(
                operation,
                &[],
                Some(ReceiverCrashPoint::RevocationTerminalCommitted),
            ),
            ReceiverCrashPoint::RevocationTerminalCommitted,
        );
        drop(runtime);

        let mut recovered = rig.open_receiver();
        let result = recovered
            .recover_revocation_containment(operation, &[])
            .expect("resume unmatched revocation containment");
        let ReceiverRevocationApplicationResult::Contained {
            receipt,
            acknowledgement,
        } = result
        else {
            panic!("unmatched revocation recovery unexpectedly requires containment");
        };
        assert!(receipt.resolved_operations.is_empty());
        assert_eq!(acknowledgement.disposition, "revocation_contained");
        assert_eq!(
            recovered
                .revocations
                .tombstone(&publication.message_digest)
                .expect("load exact tombstone")
                .expect("tombstone exists"),
            tombstone,
            "recovery must reuse the one authenticated tombstone"
        );
        assert_unique_transaction_stages(
            &recovered,
            operation,
            TransactionStage::RevocationContained,
        );
        assert_eq!(
            recovered
                .unresolved_quarantine_inventory()
                .expect("load recovered revocation inventory")
                .unresolved_count(),
            0
        );
    }

    #[test]
    fn revocation_containment_intent_crash_reopens_before_one_exact_rollback() {
        let import_operation = "intake:systematic-revocation-intent";
        let revocation_operation = "receiver-revocation:systematic-intent";
        let rig = TestRig::new("systematic-revocation-intent-crash");
        let (
            mut runtime,
            _promotion,
            promotion_authorization,
            observation_authorization,
            rollback_authorization,
        ) = rig.ready_for_promotion(import_operation);
        runtime
            .commit_adoption(
                import_operation,
                &promotion_authorization,
                &observation_authorization,
                &rollback_authorization,
            )
            .expect("adopt before revocation intent crash");
        let (request, _) = load_request_unit(
            &operation_root(&runtime.operations_root, import_operation),
            runtime.route(),
            &runtime.import_policy,
        )
        .expect("load adopted intake request");
        let publication = rig.publish_revocation(
            "sender-revocation:systematic-intent",
            RevocationTargetKindV1::ExchangeMessage,
            request.message_digest,
            content("systematic-intent-prior-source"),
        );
        runtime
            .prepare_revocation_intake(revocation_operation, publication.message_digest, 100_000)
            .expect("prepare effectful revocation");
        let prepared = match runtime
            .admit_revocation(revocation_operation)
            .expect("admit effectful revocation")
        {
            ReceiverRevocationAdmissionResult::AwaitingContainment(prepared) => prepared,
            _ => panic!("effectful revocation admission returned an unexpected bounded outcome"),
        };
        assert_eq!(prepared.affected_operations.len(), 1);
        let authority = ReceiverRevocationRollbackAuthority {
            import_logical_operation_id: import_operation.to_string(),
            rollback_authorization_digest: rollback_authorization,
        };
        assert_injected_crash(
            runtime.contain_revocation_with_fault(
                revocation_operation,
                std::slice::from_ref(&authority),
                Some(ReceiverCrashPoint::RevocationContainmentIntentRecorded),
            ),
            ReceiverCrashPoint::RevocationContainmentIntentRecorded,
        );
        assert_eq!(
            runtime
                .m5
                .state_snapshot()
                .expect("load pre-effect M5 state")
                .operator_rollbacks
                .len(),
            0,
            "write-ahead containment intent must precede the rollback effect"
        );
        drop(runtime);

        let mut recovered = rig.open_receiver();
        let result = recovered
            .recover_revocation_containment(revocation_operation, std::slice::from_ref(&authority))
            .expect("resume effectful revocation containment");
        let ReceiverRevocationApplicationResult::Contained {
            receipt,
            acknowledgement,
        } = result
        else {
            panic!("effectful revocation recovery unexpectedly requires containment");
        };
        assert_eq!(receipt.resolved_operations.len(), 1);
        assert_eq!(
            receipt.resolved_operations[0].resolution.outcome,
            RevocationContainmentOutcomeV1::RolledBack
        );
        assert_eq!(acknowledgement.disposition, "revocation_contained");
        assert_eq!(
            recovered
                .m5
                .state_snapshot()
                .expect("load post-recovery M5 state")
                .operator_rollbacks
                .len(),
            1,
            "recovery must execute exactly one operator rollback"
        );
        assert_unique_transaction_stages(
            &recovered,
            revocation_operation,
            TransactionStage::RevocationContained,
        );
        assert_eq!(
            recovered
                .unresolved_quarantine_inventory()
                .expect("load terminal containment inventory")
                .unresolved_count(),
            0
        );
    }

    #[test]
    fn operator_restored_receiver_baseline_allows_later_import() {
        let first_operation = "intake:operator-restored-first";
        let second_operation = "intake:operator-restored-later";
        let revocation_operation = "receiver-revocation:operator-restored-first";
        let rig = TestRig::new("operator-restored-baseline");
        let (
            mut runtime,
            _promotion,
            promotion_authorization,
            observation_authorization,
            rollback_authorization,
        ) = rig.ready_for_promotion(first_operation);
        let prior_snapshot = runtime
            .m5
            .active_runtime_snapshot()
            .expect("capture exact pre-adoption baseline");
        let first = runtime
            .commit_adoption(
                first_operation,
                &promotion_authorization,
                &observation_authorization,
                &rollback_authorization,
            )
            .expect("adopt first import");
        let ReceiverAdoptionResult::Adopted(first_receipt) = first else {
            panic!("first import did not adopt");
        };
        assert_eq!(first_receipt.disposition, ReceiverM5Disposition::Healthy);

        let revocation = rig.publish_revocation(
            "sender-revocation:operator-restored-first",
            RevocationTargetKindV1::ExchangeMessage,
            first_receipt.message_digest.clone(),
            content("operator-restored-prior-source"),
        );
        runtime
            .prepare_revocation_intake(revocation_operation, revocation.message_digest, 100_000)
            .expect("prepare exact revocation");
        let prepared = match runtime
            .admit_revocation(revocation_operation)
            .expect("admit exact revocation")
        {
            ReceiverRevocationAdmissionResult::AwaitingContainment(prepared) => prepared,
            _ => panic!("revocation did not reach containment"),
        };
        assert_eq!(prepared.affected_operations.len(), 1);
        let contained = runtime
            .contain_revocation(
                revocation_operation,
                &[ReceiverRevocationRollbackAuthority {
                    import_logical_operation_id: first_operation.to_string(),
                    rollback_authorization_digest: rollback_authorization,
                }],
            )
            .expect("contain exact revocation");
        let ReceiverRevocationApplicationResult::Contained { receipt, .. } = contained else {
            panic!("exact revocation unexpectedly required manual containment");
        };
        assert_eq!(
            receipt.final_active_snapshot_digest,
            prior_snapshot.snapshot_digest
        );
        drop(runtime);

        let (
            mut later,
            _promotion,
            later_promotion_authorization,
            later_observation_authorization,
            later_rollback_authorization,
        ) = rig.ready_for_promotion(second_operation);
        later
            .m5
            .induce_next_health_regression()
            .expect("arm later import rollback");
        let later_result = later
            .commit_adoption(
                second_operation,
                &later_promotion_authorization,
                &later_observation_authorization,
                &later_rollback_authorization,
            )
            .expect("complete later import from operator-restored baseline");
        let ReceiverAdoptionResult::Adopted(later_receipt) = later_result else {
            panic!("later import did not complete");
        };
        assert_eq!(later_receipt.disposition, ReceiverM5Disposition::RolledBack);
        assert_terminal_import_recovery(
            &later,
            second_operation,
            TransactionStage::RolledBack,
            "rolled_back",
        );
    }

    #[test]
    fn partial_effect_authority_consumptions_recover_without_duplicate_use() {
        for (index, point) in [
            ReceiverCrashPoint::PromotionAuthorizationConsumed,
            ReceiverCrashPoint::ObservationAuthorizationConsumed,
            ReceiverCrashPoint::RollbackAuthorizationConsumed,
        ]
        .into_iter()
        .enumerate()
        {
            let operation = format!("intake:authority-crash-{index}");
            let rig = TestRig::new(&format!("authority-crash-{index}"));
            let (
                mut runtime,
                _promotion,
                promotion_authorization,
                observation_authorization,
                rollback_authorization,
            ) = rig.ready_for_promotion(&operation);
            assert!(matches!(
                runtime.commit_adoption_with_fault(
                    &operation,
                    &promotion_authorization,
                    &observation_authorization,
                    &rollback_authorization,
                    Some(point),
                ),
                Err(M6ReceiverError::InjectedCrash(actual)) if actual == point
            ));
            assert_eq!(
                runtime
                    .journal
                    .transaction(&operation)
                    .expect("load transaction")
                    .expect("transaction")
                    .current_stage(),
                Some(TransactionStage::AwaitingApproval),
                "effect intent must not precede all three consumptions"
            );
            let durable_promotion = runtime
                .promotion_authority
                .load_consumption(&promotion_authorization, 1)
                .expect("promotion consumption is durable");
            let durable_observation = runtime
                .observation_authority
                .load_consumption(&observation_authorization, 1);
            let durable_rollback = runtime
                .rollback_authority
                .load_consumption(&rollback_authorization, 1);
            if index == 0 {
                assert!(durable_observation.is_err());
                assert!(durable_rollback.is_err());
            } else if index == 1 {
                assert!(durable_observation.is_ok());
                assert!(durable_rollback.is_err());
            } else {
                assert!(durable_observation.is_ok());
                assert!(durable_rollback.is_ok());
            }
            drop(runtime);

            let mut recovered = rig.open_receiver();
            let result = recovered
                .recover_adoption(
                    &operation,
                    &promotion_authorization,
                    &observation_authorization,
                    &rollback_authorization,
                )
                .expect("recover exact partial authority sequence");
            let ReceiverAdoptionResult::Adopted(receipt) = result else {
                panic!("partial authority recovery did not adopt");
            };
            assert_eq!(receipt.disposition, ReceiverM5Disposition::Healthy);
            assert_eq!(
                recovered
                    .promotion_authority
                    .load_consumption(&promotion_authorization, 1)
                    .expect("reopen promotion consumption"),
                durable_promotion,
                "recovery must resolve the same use rather than consume again"
            );
            let ack = recovered
                .load_acknowledgement(&operation)
                .expect("load ACK")
                .expect("healthy ACK");
            assert_eq!(ack.disposition, "healthy");
            assert_eq!(ack.sender_message_digest, receipt.message_digest);
            assert_eq!(
                recovered
                    .journal
                    .transaction(&operation)
                    .expect("load recovered transaction")
                    .expect("recovered transaction")
                    .current_stage(),
                Some(TransactionStage::Healthy)
            );
        }
    }

    #[test]
    fn rollback_branch_restores_prior_snapshot_and_cites_conditional_authority() {
        let operation = "intake:health-regression";
        let rig = TestRig::new("health-regression");
        let (
            mut runtime,
            promotion,
            promotion_authorization,
            observation_authorization,
            rollback_authorization,
        ) = rig.ready_for_promotion(operation);
        runtime
            .induce_next_health_regression()
            .expect("arm one-shot health regression");
        let result = runtime
            .commit_adoption(
                operation,
                &promotion_authorization,
                &observation_authorization,
                &rollback_authorization,
            )
            .expect("complete rollback outcome");
        let ReceiverAdoptionResult::Adopted(receipt) = result else {
            panic!("health regression did not produce an adoption receipt");
        };
        assert_eq!(receipt.disposition, ReceiverM5Disposition::RolledBack);
        let operation_root = operation_root(&runtime.operations_root, operation);
        let (request, _) =
            load_request_unit(&operation_root, runtime.route(), &runtime.import_policy)
                .expect("load intake request");
        assert_eq!(
            receipt.final_active_snapshot_digest,
            request.expected_active_snapshot_digest
        );

        let observation_consumption = runtime
            .observation_authority
            .load_consumption(&observation_authorization, 1)
            .expect("observation consumption");
        let rollback_consumption = runtime
            .rollback_authority
            .load_consumption(&rollback_authorization, 1)
            .expect("rollback consumption");
        let projection = runtime
            .journal
            .transaction(operation)
            .expect("load transaction")
            .expect("transaction");
        let observation_stage = projection
            .stages
            .iter()
            .find(|record| record.stage == TransactionStage::ObservationIntentRecorded)
            .expect("observation stage");
        assert_eq!(
            observation_stage.evidence.authority_ref.as_ref(),
            Some(runtime.observation_authority.profile().profile_digest())
        );
        assert!(
            observation_stage
                .evidence
                .evidence_refs
                .contains(observation_consumption.receipt_digest())
        );
        assert!(
            !observation_stage
                .evidence
                .evidence_refs
                .contains(rollback_consumption.receipt_digest()),
            "observation branch must not claim rollback execution"
        );
        let rollback_stage = projection
            .stages
            .iter()
            .find(|record| record.stage == TransactionStage::RollbackIntentRecorded)
            .expect("rollback intent");
        assert_eq!(
            rollback_stage.evidence.authority_ref.as_ref(),
            Some(runtime.rollback_authority.profile().profile_digest())
        );
        assert!(
            rollback_stage
                .evidence
                .evidence_refs
                .contains(rollback_consumption.receipt_digest())
        );
        assert_eq!(
            projection.current_stage(),
            Some(TransactionStage::RolledBack)
        );
        assert_eq!(
            promotion.rollback_authorization_binding.action,
            AuthorityAction::RollbackImport
        );
        let ack = runtime
            .load_acknowledgement(operation)
            .expect("load ACK")
            .expect("rolled-back ACK");
        assert_eq!(ack.disposition, "rolled_back");
    }

    #[test]
    fn signed_exchange_completion_reopens_healthy_and_rolled_back_sources_detached() {
        for (label, rolled_back) in [
            ("completion-healthy", false),
            ("completion-rolled-back", true),
        ] {
            let operation = format!("intake:{label}");
            let rig = TestRig::new(label);
            let (
                mut runtime,
                _promotion,
                promotion_authorization,
                observation_authorization,
                rollback_authorization,
            ) = rig.ready_for_promotion(&operation);
            if rolled_back {
                runtime
                    .induce_next_health_regression()
                    .expect("arm one-shot health regression");
            }
            let result = runtime
                .commit_adoption(
                    &operation,
                    &promotion_authorization,
                    &observation_authorization,
                    &rollback_authorization,
                )
                .expect("complete receiver import");
            let ReceiverAdoptionResult::Adopted(receipt) = result else {
                panic!("completion fixture did not reach adoption");
            };
            let expected_disposition = if rolled_back {
                ReceiverM5Disposition::RolledBack
            } else {
                ReceiverM5Disposition::Healthy
            };
            assert_eq!(receipt.disposition, expected_disposition);

            let evidence = runtime
                .load_exchange_completion_evidence(&operation)
                .expect("reopen exact completion sources")
                .expect("completion evidence");
            assert_eq!(evidence.disposition(), expected_disposition);
            assert_eq!(evidence.message_digest(), &receipt.message_digest);
            assert_eq!(evidence.adoption_receipt_digest(), &receipt.receipt_digest);
            assert_eq!(
                evidence.behavior_probe_input().expect("behavior input"),
                BEHAVIOR_CHANGE_PROBE_INPUT
            );
            assert_eq!(evidence.before_behavior_output().expect("before output"), 2);
            evidence
                .pre_activation_probe_digest()
                .expect("pre-activation probe digest");
            if rolled_back {
                assert!(!evidence.proves_observable_behavior_change());
                assert!(evidence.proves_restored_incumbent_behavior());
                assert!(
                    evidence
                        .post_adoption_failure_observed()
                        .expect("observed regression")
                );
                assert_eq!(
                    evidence
                        .after_behavior_output()
                        .expect("no healthy after output"),
                    None
                );
                assert!(
                    evidence
                        .post_rollback_probe_digest()
                        .expect("post-rollback digest")
                        .is_some()
                );
                let restored_input = evidence
                    .restored_behavior_input()
                    .expect("restored behavior input")
                    .expect("rolled-back evidence has a restored input");
                let restored_output = evidence
                    .restored_behavior_output()
                    .expect("restored behavior output")
                    .expect("rolled-back evidence has a restored output");
                assert_ne!(restored_input, BEHAVIOR_CHANGE_PROBE_INPUT);
                assert_eq!(
                    restored_output,
                    restored_input
                        .checked_add(1)
                        .expect("bounded restored test input")
                );
            } else {
                assert!(evidence.proves_observable_behavior_change());
                assert!(!evidence.proves_restored_incumbent_behavior());
                assert!(
                    !evidence
                        .post_adoption_failure_observed()
                        .expect("healthy observation")
                );
                assert_eq!(
                    evidence.after_behavior_output().expect("after output"),
                    Some(1)
                );
                assert_ne!(
                    evidence.before_behavior_output().expect("before output"),
                    evidence
                        .after_behavior_output()
                        .expect("after output")
                        .expect("healthy after output")
                );
                assert!(
                    evidence
                        .behavior_change_evidence_digest()
                        .expect("behavior digest")
                        .is_some()
                );
                assert_eq!(
                    evidence
                        .post_rollback_probe_digest()
                        .expect("no rollback digest"),
                    None
                );
            }
            let bytes = evidence
                .canonical_bytes_detached(&rig.route)
                .expect("canonical signed completion evidence");
            let detached = ReceiverExchangeCompletionEvidenceV1::from_canonical_bytes_detached(
                &bytes, &rig.route,
            )
            .expect("detached receiver completion validation");
            assert!(
                detached == evidence,
                "detached receiver completion evidence differed from its canonical source"
            );

            if rolled_back {
                let restored_input = evidence
                    .restored_behavior_input()
                    .expect("restored input")
                    .expect("rolled-back restored input");
                for target in ["restored-input", "restored-package"] {
                    let mut tampered = evidence.clone();
                    let probe_bytes = tampered
                        .post_rollback_probe_bytes
                        .as_mut()
                        .expect("rolled-back probe bytes");
                    match target {
                        "restored-input" => {
                            let original = format!("\"input\":{restored_input}");
                            let replacement =
                                format!("\"input\":{}", restored_input.saturating_add(1));
                            assert_eq!(original.len(), replacement.len());
                            let offset = probe_bytes
                                .windows(original.len())
                                .position(|window| window == original.as_bytes())
                                .expect("locate restored execution input");
                            probe_bytes[offset..offset + original.len()]
                                .copy_from_slice(replacement.as_bytes());
                        }
                        "restored-package" => {
                            let marker = b"\"restored_package_digest\":\"";
                            let start = probe_bytes
                                .windows(marker.len())
                                .position(|window| window == marker)
                                .expect("locate restored package digest")
                                + marker.len();
                            let end = probe_bytes[start..]
                                .iter()
                                .position(|byte| *byte == b'"')
                                .expect("terminate restored package digest")
                                + start;
                            let index = (start..end)
                                .rev()
                                .find(|index| probe_bytes[*index].is_ascii_hexdigit())
                                .expect("locate restored package digest hex");
                            probe_bytes[index] = if probe_bytes[index] == b'a' {
                                b'b'
                            } else {
                                b'a'
                            };
                        }
                        _ => unreachable!(),
                    }
                    tampered.source_digests = tampered
                        .expected_source_digests()
                        .expect("tampered sources");
                    tampered.evidence_digest = tampered
                        .expected_digest()
                        .expect("tampered evidence digest");
                    tampered.source_set_signature_hex = runtime
                        .signer
                        .sign_receiver_intake_completion(&rig.route, &tampered.evidence_digest)
                        .expect("sign adversarial outer source set");
                    let tampered_bytes =
                        canonical_json(&tampered).expect("canonical adversarial completion");
                    assert!(
                        ReceiverExchangeCompletionEvidenceV1::from_canonical_bytes_detached(
                            &tampered_bytes,
                            &rig.route,
                        )
                        .is_err(),
                        "outer-resealed {target} tamper must fail detached source validation"
                    );
                }
            }

            let mut forged = evidence.clone();
            forged.message_digest = content("forged-receiver-completion-message");
            forged.evidence_digest = forged.expected_digest().expect("forged digest");
            let forged_bytes = canonical_json(&forged).expect("forged completion bytes");
            assert!(
                ReceiverExchangeCompletionEvidenceV1::from_canonical_bytes_detached(
                    &forged_bytes,
                    &rig.route,
                )
                .is_err(),
                "recomputed public digests cannot replace the receiver signature"
            );
        }
    }

    #[test]
    fn receiver_inventory_root_excludes_live_m5_state_churn() {
        let rig = TestRig::new("receiver-inventory-m5-churn");
        let runtime = rig.open_receiver();
        let before = runtime
            .unresolved_quarantine_inventory()
            .expect("capture M6-owned receiver inventory before M5 churn");
        let execution = runtime
            .m5
            .execute_active(37)
            .expect("execute through live M5 without changing M6 exchange state");
        assert_eq!(execution.input, 37);
        let after = runtime
            .unresolved_quarantine_inventory()
            .expect("capture M6-owned receiver inventory after M5 churn");
        assert_eq!(
            before.durable_state_digest(),
            after.durable_state_digest(),
            "M5/M2 state churn must be outside the M6 receiver durable-state cut"
        );
        assert!(
            before == after,
            "unchanged M6 operation and quarantine evidence must reproduce exactly"
        );
    }

    #[test]
    fn signed_receiver_reopen_proof_recovers_exchange_and_zero_quarantine_inventory() {
        let operation = "intake:receiver-reopen-proof";
        let rig = TestRig::new("receiver-reopen-proof");
        let receipt = {
            let (
                mut runtime,
                _promotion,
                promotion_authorization,
                observation_authorization,
                rollback_authorization,
            ) = rig.ready_for_promotion(operation);
            assert!(
                runtime
                    .latest_reopen_proof()
                    .expect("first-open receiver proof lookup")
                    .is_none(),
                "initial receiver initialization is not a restart"
            );
            let unresolved = runtime
                .unresolved_quarantine_inventory()
                .expect("scan awaiting-approval quarantine");
            assert_eq!(unresolved.unresolved_count(), 1);
            assert!(unresolved.operations()[0].unresolved());
            let unresolved_bytes = unresolved
                .canonical_bytes_detached(&rig.route)
                .expect("canonical unresolved inventory");
            let detached_unresolved =
                ReceiverUnresolvedQuarantineInventoryV1::from_canonical_bytes_detached(
                    &unresolved_bytes,
                    &rig.route,
                )
                .expect("detached unresolved inventory");
            assert!(
                detached_unresolved == unresolved,
                "detached unresolved quarantine inventory differed from its canonical source"
            );
            let result = runtime
                .commit_adoption(
                    operation,
                    &promotion_authorization,
                    &observation_authorization,
                    &rollback_authorization,
                )
                .expect("complete receiver exchange before restart");
            let ReceiverAdoptionResult::Adopted(receipt) = result else {
                panic!("receiver reopen fixture did not adopt");
            };
            let inventory = runtime
                .unresolved_quarantine_inventory()
                .expect("scan terminal quarantine");
            assert!(inventory.is_empty());
            assert_eq!(inventory.unresolved_count(), 0);
            let inventory_bytes = inventory
                .canonical_bytes_detached(&rig.route)
                .expect("canonical inventory");
            let detached_inventory =
                ReceiverUnresolvedQuarantineInventoryV1::from_canonical_bytes_detached(
                    &inventory_bytes,
                    &rig.route,
                )
                .expect("detached zero inventory");
            assert!(
                detached_inventory == inventory,
                "detached terminal quarantine inventory differed from its canonical source"
            );
            receipt
        };

        let runtime = rig.open_receiver();
        let proof = runtime
            .latest_reopen_proof()
            .expect("load receiver reopen proof")
            .expect("second receiver open has adjacent proof");
        assert!(
            proof
                .proves_restart_of(&rig.route, operation, &receipt.receipt_digest)
                .expect("validate recovered adoption")
        );
        assert!(
            proof
                .proves_zero_unresolved_quarantine(&rig.route)
                .expect("validate zero quarantine after restart")
        );
        let inventory = proof
            .current_quarantine_inventory(&rig.route)
            .expect("inventory embedded in current audit");
        assert_eq!(inventory.operations().len(), 1);
        assert!(inventory.operations()[0].current_stage().is_terminal());
        let proof_bytes = proof
            .canonical_bytes_detached(&rig.route)
            .expect("canonical receiver reopen proof");
        let detached_proof =
            ReceiverReopenProofV1::from_canonical_bytes_detached(&proof_bytes, &rig.route)
                .expect("detached receiver reopen proof");
        assert!(
            detached_proof == proof,
            "detached receiver reopen proof differed from its canonical source"
        );

        let mut forged = proof.clone();
        let mut current: ReceiverReopenAuditV1 =
            parse_canonical(&forged.current_audit_bytes, MAX_REOPEN_AUDIT_BYTES)
                .expect("current receiver audit");
        current.post_reconciliation_state_digest = content("forged-reconciled-state");
        current.audit_digest = current.expected_digest().expect("forged audit digest");
        forged.current_audit_bytes = canonical_json(&current).expect("forged audit bytes");
        forged.current_audit_digest = current.audit_digest;
        forged.proof_digest = forged.expected_digest().expect("forged proof digest");
        let forged_bytes = canonical_json(&forged).expect("forged proof bytes");
        assert!(
            ReceiverReopenProofV1::from_canonical_bytes_detached(&forged_bytes, &rig.route)
                .is_err(),
            "recomputed public digests cannot replace the receiver reopen signature"
        );
    }

    #[test]
    fn signed_negative_control_suite_replays_three_real_receiver_rejections_detached() {
        let content_operation = "intake:negative-content-tamper";
        let identity_operation = "intake:negative-false-route";
        let compatibility_operation = "intake:negative-interface-policy";
        let mut rig = TestRig::new("negative-control-suite");
        rig.policy = rig
            .policy
            .clone()
            .requiring_interface_digest_for_test(content("incompatible-interface-policy"))
            .expect("configure an explicit incompatible receiver interface policy");

        let export_receipt = {
            let mut sender = rig.open_sender();
            let prepared = sender
                .prepare_export("export:negative-control-source", "principal:sender", 60_000)
                .expect("prepare negative-control source export");
            let authorization = rig.authorize_sender(&sender, &prepared);
            sender
                .commit_export("export:negative-control-source", &authorization)
                .expect("commit negative-control source export")
        };
        let sender_spool = GovernedFilesystemSpool::open(
            &rig.route_root,
            &rig.sender_root,
            RouteEndpointRole::Sender,
            &rig.route.definition_digest,
        )
        .expect("open sender spool for negative-control fixtures");
        let issued = sender_spool
            .read_outbound_ready(&export_receipt.message_digest)
            .expect("read exact valid source export");

        let content_message_digest = content("negative-control-canonical-message");
        clone_ready_unit_with_manifest(
            &sender_spool,
            &export_receipt.message_digest,
            &content_message_digest,
            b"{}",
        );

        let mut false_route_unsigned = issued.manifest.unsigned.clone();
        false_route_unsigned.route_id = "route:negative-control-false-route".to_string();
        let false_route_manifest = SignedManifest::sign(false_route_unsigned, &sender_signer())
            .expect("sign structurally valid false-route manifest");
        let false_route_manifest_bytes = false_route_manifest
            .canonical_bytes()
            .expect("encode false-route manifest");
        clone_ready_unit_with_manifest(
            &sender_spool,
            &export_receipt.message_digest,
            &false_route_manifest.message_digest,
            &false_route_manifest_bytes,
        );
        drop(sender_spool);

        let mut receiver = rig.open_receiver();
        let mut reject =
            |operation: &str, message_digest: ContentDigest| -> ReceiverValidationRejection {
                let intake = receiver
                    .prepare_intake(
                        operation,
                        "principal:negative-control",
                        message_digest,
                        100_000,
                    )
                    .expect("prepare negative-control intake");
                let authorization = rig.authorize_receiver(
                    &receiver,
                    &rig.profiles.intake,
                    &rig.credentials.intake,
                    intake.authorization_binding,
                );
                match receiver
                    .admit_and_authenticate(operation, &authorization)
                    .expect("execute negative-control intake")
                {
                    ReceiverAdmissionResult::ValidationRejected(rejection) => rejection,
                    _ => panic!("negative control did not reject"),
                }
            };
        let content_rejection = reject(content_operation, content_message_digest);
        assert!(!content_rejection.authenticated);
        assert_eq!(content_rejection.policy_rule, "canonical-manifest");
        let identity_rejection = reject(
            identity_operation,
            false_route_manifest.message_digest.clone(),
        );
        assert!(!identity_rejection.authenticated);
        assert_eq!(identity_rejection.policy_rule, "route-authentication");
        let compatibility_rejection = reject(
            compatibility_operation,
            export_receipt.message_digest.clone(),
        );
        assert!(compatibility_rejection.authenticated);
        assert_eq!(
            compatibility_rejection.policy_rule,
            "receiver-compatibility"
        );
        drop(reject);

        let suite = receiver
            .negative_control_suite(
                content_operation,
                identity_operation,
                compatibility_operation,
            )
            .expect("build signed receiver negative-control suite");
        let bytes = suite
            .canonical_bytes_detached(&rig.route)
            .expect("encode detached negative-control suite");
        let detached =
            ReceiverNegativeControlSuiteV1::from_canonical_bytes_detached(&bytes, &rig.route)
                .expect("replay all three controls detached");
        assert!(
            detached == suite,
            "detached receiver negative-control suite differed from its canonical source"
        );

        let mut tampered = suite.clone();
        tampered.content_tamper_rejection_bytes[0] ^= 1;
        let tampered_bytes = canonical_json(&tampered).expect("encode one-byte-tampered suite");
        assert!(
            ReceiverNegativeControlSuiteV1::from_canonical_bytes_detached(
                &tampered_bytes,
                &rig.route,
            )
            .is_err(),
            "one changed source byte must invalidate the signed detached suite"
        );
    }

    #[test]
    fn terminal_message_reuse_by_new_operation_is_signed_replay_rejection() {
        let first_operation = "intake:message-claim-first";
        let second_operation = "intake:message-claim-replay";
        let rig = TestRig::new("message-claim-replay");
        let (mut runtime, approval) = rig.ready_for_approval(first_operation);
        let prepared_denial = runtime
            .prepare_approval_decision(
                first_operation,
                ApprovalDecisionKind::Denied,
                "principal:receiver-operator",
                "terminalize the first authenticated replay-claim fixture",
            )
            .expect("prepare first terminal denial");
        assert_eq!(
            approval.approval_request.request_digest(),
            &prepared_denial.approval_request_digest
        );
        let denial_authorization = rig.authorize_receiver(
            &runtime,
            &rig.profiles.approval,
            &rig.credentials.approval,
            prepared_denial.authorization_binding,
        );
        let first = runtime
            .decide_approval(
                first_operation,
                &denial_authorization,
                prepared_denial.decision_intent,
            )
            .expect("terminalize first authenticated message");
        let ReceiverApprovalResult::Terminal(first_terminal) = first else {
            panic!("first authenticated message did not terminalize");
        };
        assert_eq!(first_terminal.kind, ReceiverTerminalKind::Denied);
        assert_terminal_import_recovery(
            &runtime,
            first_operation,
            TransactionStage::Denied,
            "denied",
        );

        let second = runtime
            .prepare_intake(
                second_operation,
                "principal:receiver",
                first_terminal.message_digest.clone(),
                100_000,
            )
            .expect("prepare second operation over identical signed message");
        let second_outer_request_digest = second.outer_request_digest.clone();
        let second_authorization = rig.authorize_receiver(
            &runtime,
            &rig.profiles.intake,
            &rig.credentials.intake,
            second.authorization_binding,
        );
        let prior_state = runtime.replay.control_state();
        let error = runtime
            .admit_and_authenticate(second_operation, &second_authorization)
            .expect_err("cross-operation signed-message reuse must fail");
        let record_digest = match error {
            M6ReceiverError::ControlRejected {
                class: ReceiverControlRejectionClassV1::MessageReplay,
                record_digest,
            } => record_digest,
            other => panic!("unexpected replay rejection: {other}"),
        };
        assert_eq!(
            runtime.replay.control_state(),
            prior_state,
            "replay rejection must not mutate the authenticated replay state"
        );
        let rejection = runtime
            .load_control_rejection(
                second_operation,
                ReceiverControlRejectionClassV1::MessageReplay,
                &first_terminal.message_digest,
                &second_outer_request_digest,
            )
            .expect("load signed replay rejection")
            .expect("signed replay rejection exists");
        assert_eq!(rejection.record_digest(), &record_digest);
        assert_eq!(rejection.control_plane(), ReceiverControlPlaneV1::Replay);
        let bytes = rejection
            .canonical_bytes(runtime.route())
            .expect("portable replay rejection");
        let detached =
            ReceiverSignedControlRejectionV1::from_canonical_bytes(&bytes, runtime.route())
                .expect("detached replay rejection");
        assert!(
            detached == rejection,
            "detached receiver replay rejection differed from its canonical source"
        );
        assert_terminal_import_recovery(
            &runtime,
            second_operation,
            TransactionStage::ValidationRejected,
            "validation_rejected",
        );
        let second_root = operation_root(&runtime.operations_root, second_operation);
        let terminal: ReceiverTerminalDecision =
            load_canonical_file(&second_root.join(TERMINAL_DECISION_FILE), MAX_RECORD_BYTES)
                .expect("load replay terminal decision");
        assert_eq!(terminal.kind, ReceiverTerminalKind::ValidationRejected);
        assert_eq!(terminal.evidence_digest, record_digest);
        let ack_request: ReceiverAcknowledgementRequest =
            load_canonical_file(&second_root.join(ACK_REQUEST_FILE), MAX_RECORD_BYTES)
                .expect("load replay acknowledgement request");
        assert_eq!(ack_request.raw_quarantine_digest, record_digest);

        drop(runtime);
        let mut recovered = rig.open_receiver();
        let reopened_error = recovered
            .admit_and_authenticate(second_operation, &second_authorization)
            .expect_err("reopened replay operation must resolve the same rejection");
        assert!(matches!(
            reopened_error,
            M6ReceiverError::ControlRejected {
                class: ReceiverControlRejectionClassV1::MessageReplay,
                record_digest: ref reopened_digest,
            } if reopened_digest == &record_digest
        ));
        assert_terminal_import_recovery(
            &recovered,
            second_operation,
            TransactionStage::ValidationRejected,
            "validation_rejected",
        );

        let revocation_replay_operation = "receiver-revocation:message-claim-replay";
        let prepared_revocation_replay = recovered
            .prepare_revocation_intake(
                revocation_replay_operation,
                first_terminal.message_digest.clone(),
                100_000,
            )
            .expect("prepare revocation caller over claimed export message");
        let revocation_replay_error = recovered
            .admit_revocation(revocation_replay_operation)
            .expect_err("revocation caller must reject the cross-operation message claim");
        let revocation_replay_digest = match revocation_replay_error {
            M6ReceiverError::ControlRejected {
                class: ReceiverControlRejectionClassV1::MessageReplay,
                record_digest,
            } => record_digest,
            other => panic!("unexpected revocation replay rejection: {other}"),
        };
        let revocation_rejection = recovered
            .load_control_rejection(
                revocation_replay_operation,
                ReceiverControlRejectionClassV1::MessageReplay,
                &first_terminal.message_digest,
                &prepared_revocation_replay.request_digest,
            )
            .expect("load revocation caller replay rejection")
            .expect("revocation caller replay rejection exists");
        assert_eq!(
            revocation_rejection.record_digest(),
            &revocation_replay_digest
        );
        assert_terminal_revocation_recovery(
            &recovered,
            revocation_replay_operation,
            TransactionStage::ValidationRejected,
            "validation_rejected",
            &revocation_replay_digest,
        );

        drop(recovered);
        let mut recovered = rig.open_receiver();
        let reopened_revocation_error = recovered
            .admit_revocation(revocation_replay_operation)
            .expect_err("reopened revocation replay must resolve the same rejection");
        assert!(matches!(
            reopened_revocation_error,
            M6ReceiverError::ControlRejected {
                class: ReceiverControlRejectionClassV1::MessageReplay,
                record_digest: ref reopened_digest,
            } if reopened_digest == &revocation_replay_digest
        ));
        assert_terminal_revocation_recovery(
            &recovered,
            revocation_replay_operation,
            TransactionStage::ValidationRejected,
            "validation_rejected",
            &revocation_replay_digest,
        );
        let reopened_inventory = recovered
            .unresolved_quarantine_inventory()
            .expect("reopen both import and revocation operation roots");
        for (kind, operation) in [
            (ReceiverInboundTransactionKindV1::Import, second_operation),
            (
                ReceiverInboundTransactionKindV1::Revocation,
                revocation_replay_operation,
            ),
        ] {
            assert!(
                reopened_inventory.operations().iter().any(|entry| {
                    entry.transaction_kind() == kind
                        && entry.logical_operation_id() == operation
                        && entry.current_stage() == TransactionStage::ValidationRejected
                }),
                "reopen inventory must retain the terminal {kind:?} root for {operation}"
            );
        }

        drop(recovered);
        let later_operation = "intake:valid-after-message-replays";
        let (
            mut later,
            _promotion,
            later_promotion_authorization,
            later_observation_authorization,
            later_rollback_authorization,
        ) = rig.ready_for_promotion(later_operation);
        let later_result = later
            .commit_adoption(
                later_operation,
                &later_promotion_authorization,
                &later_observation_authorization,
                &later_rollback_authorization,
            )
            .expect("later valid import is not blocked");
        let ReceiverAdoptionResult::Adopted(later_receipt) = later_result else {
            panic!("later valid import did not adopt");
        };
        assert_eq!(later_receipt.disposition, ReceiverM5Disposition::Healthy);
        assert_terminal_import_recovery(
            &later,
            later_operation,
            TransactionStage::Healthy,
            "healthy",
        );

        let genuine_publication = rig.publish_revocation(
            "sender-revocation:after-message-replays",
            RevocationTargetKindV1::ExchangeMessage,
            later_receipt.message_digest,
            content("prior-source-evidence:after-message-replays"),
        );
        let genuine_revocation_operation = "receiver-revocation:after-message-replays";
        later
            .prepare_revocation_intake(
                genuine_revocation_operation,
                genuine_publication.message_digest,
                100_000,
            )
            .expect("later genuine revocation is not blocked");
        let genuine_prepared = match later
            .admit_revocation(genuine_revocation_operation)
            .expect("admit later genuine revocation")
        {
            ReceiverRevocationAdmissionResult::AwaitingContainment(prepared) => prepared,
            _ => panic!("genuine revocation admission returned an unexpected bounded outcome"),
        };
        assert_eq!(genuine_prepared.affected_operations.len(), 1);
        let containment = later
            .contain_revocation(
                genuine_revocation_operation,
                &[ReceiverRevocationRollbackAuthority {
                    import_logical_operation_id: later_operation.to_string(),
                    rollback_authorization_digest: later_rollback_authorization,
                }],
            )
            .expect("contain later genuine revocation");
        assert!(matches!(
            containment,
            ReceiverRevocationApplicationResult::Contained {
                receipt: ReceiverRevocationApplicationReceipt {
                    containment_required: false,
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            later
                .unresolved_quarantine_inventory()
                .expect("load post-replay containment inventory")
                .unresolved_count(),
            0
        );
    }

    #[test]
    fn tombstone_ingested_before_export_rejects_at_first_real_plan_before_approval() {
        let rig = TestRig::new("revocation-before-plan");
        let source =
            M5Runtime::open(source_m5_config(&rig.sender_root), None).expect("open source M5");
        let source_package_digest = source
            .active_package()
            .expect("source package")
            .package_digest;
        drop(source);

        let revocation = rig.publish_revocation(
            "sender-revocation:before-plan",
            RevocationTargetKindV1::SourcePackage,
            source_package_digest,
            content("prior-source-evidence:before-plan"),
        );
        let mut receiver = rig.open_receiver();
        receiver
            .prepare_revocation_intake(
                "receiver-revocation:before-plan",
                revocation.message_digest.clone(),
                100_000,
            )
            .expect("prepare receiver revocation");
        let admission = receiver
            .admit_revocation("receiver-revocation:before-plan")
            .expect("admit receiver revocation");
        let prepared = match admission {
            ReceiverRevocationAdmissionResult::AwaitingContainment(prepared) => prepared,
            _ => panic!("revocation did not reach containment"),
        };
        assert!(prepared.affected_operations.is_empty());
        let applied = receiver
            .contain_revocation("receiver-revocation:before-plan", &[])
            .expect("commit tombstone-only revocation");
        let ReceiverRevocationApplicationResult::Contained {
            receipt,
            acknowledgement,
        } = applied
        else {
            panic!("tombstone-only revocation was not contained");
        };
        assert!(receipt.resolved_operations.is_empty());
        assert_eq!(acknowledgement.disposition, "revocation_contained");
        drop(receiver);

        let export_receipt = {
            let mut sender = rig.open_sender();
            let prepared = sender
                .prepare_export("export:after-tombstone", "principal:sender", 60_000)
                .expect("prepare export after tombstone");
            let authorization = rig.authorize_sender(&sender, &prepared);
            sender
                .commit_export("export:after-tombstone", &authorization)
                .expect("commit export after tombstone")
        };
        let mut receiver = rig.open_receiver();
        let intake = receiver
            .prepare_intake(
                "intake:after-tombstone",
                "principal:receiver",
                export_receipt.message_digest,
                100_000,
            )
            .expect("prepare import after tombstone");
        let intake_authorization = rig.authorize_receiver(
            &receiver,
            &rig.profiles.intake,
            &rig.credentials.intake,
            intake.authorization_binding,
        );
        let proving = match receiver
            .admit_and_authenticate("intake:after-tombstone", &intake_authorization)
            .expect("admit import after tombstone")
        {
            ReceiverAdmissionResult::AwaitingProving(prepared) => prepared,
            _ => panic!("import admission returned an unexpected bounded outcome"),
        };
        let proving_authorization = rig.authorize_receiver(
            &receiver,
            &rig.profiles.proving,
            &rig.credentials.proving,
            proving.authorization_binding,
        );
        let result = receiver
            .prove_and_plan("intake:after-tombstone", &proving_authorization)
            .expect("plan-time revocation preflight");
        assert!(matches!(
            result,
            ReceiverProvingResult::ValidationRejected(ref rejection)
                if rejection.policy_rule == "revocation-before-approval"
        ));
        assert_eq!(
            receiver
                .journal
                .transaction("intake:after-tombstone")
                .expect("read import transaction")
                .expect("import transaction")
                .current_stage(),
            Some(TransactionStage::ValidationRejected)
        );
        assert!(
            !operation_root(&receiver.operations_root, "intake:after-tombstone")
                .join("approval-request.json")
                .exists(),
            "revoked import must stop before approval publication"
        );
    }

    #[test]
    fn revocation_during_activation_cancels_at_safe_boundary_with_exact_rollback_authority() {
        let operation = "intake:revoked-during-activation";
        let rig = TestRig::new("revocation-during-activation");
        let (
            mut receiver,
            _promotion,
            promotion_authorization,
            observation_authorization,
            rollback_authorization,
        ) = rig.ready_for_promotion(operation);
        assert!(matches!(
            receiver.commit_adoption_with_fault(
                operation,
                &promotion_authorization,
                &observation_authorization,
                &rollback_authorization,
                Some(ReceiverCrashPoint::ActivationIntentRecorded),
            ),
            Err(M6ReceiverError::InjectedCrash(
                ReceiverCrashPoint::ActivationIntentRecorded
            ))
        ));
        let (intake_request, _) = load_request_unit(
            &operation_root(&receiver.operations_root, operation),
            receiver.route(),
            &receiver.import_policy,
        )
        .expect("load activation-pending import");
        let revocation = rig.publish_revocation(
            "sender-revocation:during-activation",
            RevocationTargetKindV1::ExchangeMessage,
            intake_request.message_digest,
            content("prior-source-evidence:during-activation"),
        );
        receiver
            .prepare_revocation_intake(
                "receiver-revocation:during-activation",
                revocation.message_digest,
                100_000,
            )
            .expect("prepare activation revocation");
        let admission = receiver
            .admit_revocation("receiver-revocation:during-activation")
            .expect("admit activation revocation");
        let ReceiverRevocationAdmissionResult::AwaitingContainment(prepared) = admission else {
            panic!("activation revocation did not reach containment");
        };
        assert_eq!(prepared.affected_operations.len(), 1);
        assert_eq!(
            prepared.affected_operations[0]
                .affected
                .disposition_at_resolution,
            ReceiverImportDispositionV1::ActivationPending
        );
        let result = receiver
            .contain_revocation(
                "receiver-revocation:during-activation",
                &[ReceiverRevocationRollbackAuthority {
                    import_logical_operation_id: operation.to_string(),
                    rollback_authorization_digest: rollback_authorization,
                }],
            )
            .expect("cancel at activation safe boundary");
        let ReceiverRevocationApplicationResult::Contained {
            receipt,
            acknowledgement,
        } = result
        else {
            panic!("activation revocation unexpectedly required containment");
        };
        assert_eq!(
            receipt.resolved_operations[0].resolution.outcome,
            RevocationContainmentOutcomeV1::CancelledBeforeActivation
        );
        assert_eq!(acknowledgement.disposition, "revocation_contained");
        assert_eq!(
            receiver
                .journal
                .transaction(operation)
                .expect("read import transaction")
                .expect("import transaction")
                .current_stage(),
            Some(TransactionStage::RolledBack)
        );
    }

    #[test]
    fn revocation_after_adoption_rolls_back_through_receiver_m5_and_exact_authority() {
        let operation = "intake:revoked-after-adoption";
        let rig = TestRig::new("revocation-after-adoption");
        let (
            mut receiver,
            _promotion,
            promotion_authorization,
            observation_authorization,
            rollback_authorization,
        ) = rig.ready_for_promotion(operation);
        let adopted = receiver
            .commit_adoption(
                operation,
                &promotion_authorization,
                &observation_authorization,
                &rollback_authorization,
            )
            .expect("adopt before revocation");
        assert!(matches!(
            adopted,
            ReceiverAdoptionResult::Adopted(ReceiverAdoptionReceipt {
                disposition: ReceiverM5Disposition::Healthy,
                ..
            })
        ));
        let accepted_receiver = receiver
            .load_exchange_completion_evidence(operation)
            .expect("load accepted receiver completion")
            .expect("accepted receiver completion exists");
        let accepted_sender = {
            let sender = rig.open_sender();
            sender
                .load_export_completion_evidence(&format!("export:{operation}"))
                .expect("load accepted sender completion")
                .expect("accepted sender completion exists")
        };
        let prior_source_authorization_evidence_digest = accepted_sender
            .source_digests()
            .authorization_consumption
            .clone();
        let operation_root = operation_root(&receiver.operations_root, operation);
        let (intake_request, _) =
            load_request_unit(&operation_root, receiver.route(), &receiver.import_policy)
                .expect("load adopted import request");
        let (revocation, sender_publication) = {
            let mut sender = rig.open_revocation_sender();
            let prepared = sender
                .prepare_revocation(
                    "sender-revocation:after-adoption",
                    "principal:revocation-operator",
                    RevocationTargetKindV1::ExchangeMessage,
                    intake_request.message_digest.clone(),
                    "revoke exact adopted exchange",
                    prior_source_authorization_evidence_digest.clone(),
                    60_000,
                )
                .expect("prepare sender post-adoption revocation");
            let authorization = sender
                .publish_authorization(rig.issue(
                    &rig.revocation_profile,
                    &rig.revocation_credential,
                    prepared.authorization_binding,
                ))
                .expect("publish exact sender revocation authority");
            let receipt = sender
                .commit_revocation("sender-revocation:after-adoption", &authorization)
                .expect("commit sender post-adoption revocation");
            let publication = sender
                .load_publication_completion_evidence("sender-revocation:after-adoption")
                .expect("load sender revocation publication evidence")
                .expect("sender publication evidence exists");
            (receipt, publication)
        };
        receiver
            .prepare_revocation_intake(
                "receiver-revocation:after-adoption",
                revocation.message_digest,
                100_000,
            )
            .expect("prepare post-adoption revocation");
        let admission = receiver
            .admit_revocation("receiver-revocation:after-adoption")
            .expect("admit post-adoption revocation");
        let ReceiverRevocationAdmissionResult::AwaitingContainment(prepared) = admission else {
            panic!("post-adoption revocation did not reach containment");
        };
        assert_eq!(
            prepared.affected_operations[0]
                .affected
                .disposition_at_resolution,
            ReceiverImportDispositionV1::ActiveHealthy
        );
        let result = receiver
            .contain_revocation(
                "receiver-revocation:after-adoption",
                &[ReceiverRevocationRollbackAuthority {
                    import_logical_operation_id: operation.to_string(),
                    rollback_authorization_digest: rollback_authorization,
                }],
            )
            .expect("rollback adopted import");
        let ReceiverRevocationApplicationResult::Contained { receipt, .. } = result else {
            panic!("post-adoption rollback unexpectedly required containment");
        };
        assert_eq!(
            receipt.resolved_operations[0].resolution.outcome,
            RevocationContainmentOutcomeV1::RolledBack
        );
        assert_eq!(
            receiver
                .m5
                .state_snapshot()
                .expect("M5 state after revocation")
                .active_package_digest,
            intake_request.expected_active_package_digest
        );
        let evidence = receiver
            .load_revocation_completion_evidence(
                "receiver-revocation:after-adoption",
                &sender_publication,
            )
            .expect("load receiver revocation completion evidence")
            .expect("receiver revocation completion exists");
        assert_eq!(evidence.affected_operation_count(), 1);
        assert_eq!(
            evidence.sender_publication_evidence_digest(),
            sender_publication.evidence_digest()
        );
        assert_eq!(
            evidence.prior_source_authorization_evidence_digest(),
            &accepted_sender.source_digests().authorization_consumption
        );
        assert_eq!(evidence.sender_sequence(), accepted_sender.sequence() + 1);
        assert_eq!(
            evidence.sender_previous_message_digest(),
            Some(accepted_sender.message_digest())
        );
        assert!(evidence.sender_issued_at_ms() >= accepted_sender.committed_at_ms());
        assert!(evidence.sender_committed_at_ms() >= evidence.sender_issued_at_ms());
        assert!(evidence.proves_rollback_of(&accepted_receiver));
        assert_eq!(
            evidence.final_active_snapshot_digest(),
            accepted_receiver.prior_active_snapshot_digest()
        );
        assert_eq!(
            evidence.receiver_containment_receipt_digest(),
            &receipt.receipt_digest
        );
        let bytes = evidence
            .canonical_bytes_detached(&rig.route)
            .expect("encode portable receiver revocation completion");
        let detached = ReceiverRevocationCompletionEvidenceV1::from_canonical_bytes_detached(
            &bytes, &rig.route,
        )
        .expect("validate portable receiver revocation completion");
        assert!(
            detached == evidence,
            "detached receiver revocation completion differed from its canonical source"
        );
        let mut tampered = evidence.clone();
        tampered.affected_sources[0].operator_rollback_record_bytes[0] ^= 1;
        let tampered_bytes =
            canonical_json(&tampered).expect("encode tampered revocation completion");
        assert!(
            ReceiverRevocationCompletionEvidenceV1::from_canonical_bytes_detached(
                &tampered_bytes,
                &rig.route,
            )
            .is_err(),
            "one changed rollback source byte must invalidate revocation completion"
        );
    }

    #[test]
    fn revocation_restart_after_m5_effect_reuses_one_operator_rollback_and_publishes_ack() {
        let operation = "intake:revocation-crash-seam";
        let rig = TestRig::new("revocation-crash-seam");
        let (
            mut receiver,
            _promotion,
            promotion_authorization,
            observation_authorization,
            rollback_authorization,
        ) = rig.ready_for_promotion(operation);
        receiver
            .commit_adoption(
                operation,
                &promotion_authorization,
                &observation_authorization,
                &rollback_authorization,
            )
            .expect("adopt before crash seam");
        let (intake_request, _) = load_request_unit(
            &operation_root(&receiver.operations_root, operation),
            receiver.route(),
            &receiver.import_policy,
        )
        .expect("load adopted crash-seam import");
        let revocation = rig.publish_revocation(
            "sender-revocation:crash-seam",
            RevocationTargetKindV1::ExchangeMessage,
            intake_request.message_digest,
            content("prior-source-evidence:crash-seam"),
        );
        receiver
            .prepare_revocation_intake(
                "receiver-revocation:crash-seam",
                revocation.message_digest,
                100_000,
            )
            .expect("prepare crash-seam revocation");
        receiver
            .admit_revocation("receiver-revocation:crash-seam")
            .expect("admit crash-seam revocation");
        let authority = ReceiverRevocationRollbackAuthority {
            import_logical_operation_id: operation.to_string(),
            rollback_authorization_digest: rollback_authorization,
        };
        assert!(matches!(
            receiver.contain_revocation_with_fault(
                "receiver-revocation:crash-seam",
                std::slice::from_ref(&authority),
                Some(ReceiverCrashPoint::RevocationContainmentEffectsCommitted),
            ),
            Err(M6ReceiverError::InjectedCrash(
                ReceiverCrashPoint::RevocationContainmentEffectsCommitted
            ))
        ));
        assert_eq!(
            receiver
                .m5
                .state_snapshot()
                .expect("M5 state at crash seam")
                .operator_rollbacks
                .len(),
            1
        );
        drop(receiver);

        let mut recovered = rig.open_receiver();
        let result = recovered
            .recover_revocation_containment("receiver-revocation:crash-seam", &[authority])
            .expect("recover exact revocation containment");
        let ReceiverRevocationApplicationResult::Contained {
            receipt,
            acknowledgement,
        } = result
        else {
            panic!("recovered revocation unexpectedly required containment");
        };
        assert_eq!(
            receipt.resolved_operations[0].resolution.outcome,
            RevocationContainmentOutcomeV1::RolledBack
        );
        assert_eq!(acknowledgement.disposition, "revocation_contained");
        assert_eq!(
            recovered
                .m5
                .state_snapshot()
                .expect("M5 state after recovery")
                .operator_rollbacks
                .len(),
            1,
            "restart must not issue a second operator rollback"
        );
        assert_eq!(
            recovered
                .journal
                .transaction("receiver-revocation:crash-seam")
                .expect("load revocation transaction")
                .expect("revocation transaction")
                .current_stage(),
            Some(TransactionStage::RevocationContained)
        );
    }
}

impl<V: OpaqueAuthorizationVerifier> M6ReceiverRuntime<V> {
    #[allow(clippy::too_many_arguments)]
    fn append_stage(
        &self,
        request: &ReceiverIntakeRequest,
        coordinator_request_digest: &ContentDigest,
        stage: TransactionStage,
        cause: StageCause,
        attempt: u32,
        authority_ref: Option<ContentDigest>,
        effect_request_digest: Option<ContentDigest>,
        evidence_refs: Vec<ContentDigest>,
        receipt_ref: Option<ContentDigest>,
        attestation_ref: Option<ContentDigest>,
    ) -> Result<TransactionStageRecord, M6ReceiverError> {
        self.journal
            .append(
                &request.logical_operation_id,
                coordinator_request_digest,
                stage,
                stage_evidence(
                    cause,
                    attempt,
                    authority_ref,
                    effect_request_digest,
                    evidence_refs,
                    receipt_ref,
                    attestation_ref,
                )?,
            )
            .map_err(M6ReceiverError::from)
    }

    fn coordinator_request_digest(
        &self,
        logical_operation_id: &str,
    ) -> Result<ContentDigest, M6ReceiverError> {
        self.journal
            .transaction(logical_operation_id)?
            .map(|projection| projection.intent.request_digest)
            .ok_or_else(|| {
                M6ReceiverError::InvalidState(format!(
                    "receiver coordinator has no transaction '{logical_operation_id}'"
                ))
            })
    }

    fn require_no_other_pending_operation(
        &self,
        logical_operation_id: &str,
    ) -> Result<(), M6ReceiverError> {
        for transaction in self.journal.transactions()? {
            if matches!(
                transaction.intent.kind,
                TransactionKind::ReceiverIntake | TransactionKind::ReceiverRevocationApplication
            ) && transaction.intent.logical_operation_id != logical_operation_id
                && !transaction
                    .current_stage()
                    .is_some_and(TransactionStage::is_terminal)
            {
                return Err(M6ReceiverError::RecoveryBlocked {
                    blocking_operation_id: transaction.intent.logical_operation_id,
                });
            }
        }
        Ok(())
    }

    fn require_no_other_pending_revocation(
        &self,
        logical_operation_id: &str,
    ) -> Result<(), M6ReceiverError> {
        for transaction in self.journal.transactions()? {
            if transaction.intent.kind == TransactionKind::ReceiverRevocationApplication
                && transaction.intent.logical_operation_id != logical_operation_id
                && !transaction
                    .current_stage()
                    .is_some_and(TransactionStage::is_terminal)
            {
                return Err(M6ReceiverError::RecoveryBlocked {
                    blocking_operation_id: transaction.intent.logical_operation_id,
                });
            }
        }
        Ok(())
    }
}

fn intake_binding(request: &ReceiverIntakeRequest) -> ExactActionBinding {
    ExactActionBinding {
        action: AuthorityAction::IntakePackage,
        principal_id: request.principal_id.clone(),
        route_id: request.route_id.clone(),
        route_generation: request.route_generation,
        message_digest: request.message_digest.clone(),
        exchange_digest: request.exchange_digest.clone(),
        package_digest: request.source_package_anchor_digest.clone(),
        request_digest: request.request_digest.clone(),
        expected_active_snapshot_digest: request.expected_active_snapshot_digest.clone(),
        import_plan_digest: ContentDigest::from_bytes(NO_IMPORT_PLAN),
        policy_digest: request.policy_digest.clone(),
        proving_digest: ContentDigest::from_bytes(NO_PROVING),
        approval_context_digest: ContentDigest::from_bytes(NO_APPROVAL),
        idempotency_key: format!("receiver-intake:{}", request.logical_operation_id),
    }
}

fn proving_binding(
    request: &ReceiverIntakeRequest,
    verified: &VerifiedQuarantinedExportV1,
    compatibility: &ReceiverCompatibilityDecisionV1,
    suite: &crate::m1_validation::ValidationSuite,
) -> Result<ExactActionBinding, M6ReceiverError> {
    let proving_digest = digest_domain(
        PROVING_REQUEST_DOMAIN,
        &(
            &request.request_digest,
            verified.verification_digest(),
            compatibility.decision_digest(),
            suite
                .suite_digest()
                .map_err(|error| M6ReceiverError::Import(error.to_string()))?,
        ),
    )?;
    Ok(ExactActionBinding {
        action: AuthorityAction::ProveImport,
        principal_id: request.principal_id.clone(),
        route_id: request.route_id.clone(),
        route_generation: request.route_generation,
        message_digest: request.message_digest.clone(),
        exchange_digest: request.exchange_digest.clone(),
        package_digest: verified.source_package_digest().clone(),
        request_digest: proving_digest.clone(),
        expected_active_snapshot_digest: request.expected_active_snapshot_digest.clone(),
        import_plan_digest: ContentDigest::from_bytes(NO_IMPORT_PLAN),
        policy_digest: request.policy_digest.clone(),
        proving_digest,
        approval_context_digest: ContentDigest::from_bytes(NO_APPROVAL),
        idempotency_key: format!("receiver-prove:{}", request.logical_operation_id),
    })
}

fn promotion_binding(
    request: &ReceiverIntakeRequest,
    decision: &ApprovalDecisionRecord,
    proving: &ReceiverProvingReportV1,
    plan: &ReceiverImportPlanV1,
) -> Result<ExactActionBinding, M6ReceiverError> {
    let request_digest = digest_domain(
        PROMOTION_REQUEST_DOMAIN,
        &(
            &request.request_digest,
            decision.decision_digest(),
            proving.report_digest(),
            plan.import_plan_digest(),
            plan.receiver_local_package_digest(),
        ),
    )?;
    Ok(ExactActionBinding {
        action: AuthorityAction::AdoptImport,
        principal_id: decision.principal_id().to_string(),
        route_id: request.route_id.clone(),
        route_generation: request.route_generation,
        message_digest: request.message_digest.clone(),
        exchange_digest: request.exchange_digest.clone(),
        package_digest: plan.receiver_local_package_digest().clone(),
        request_digest,
        expected_active_snapshot_digest: request.expected_active_snapshot_digest.clone(),
        import_plan_digest: plan.import_plan_digest().clone(),
        policy_digest: request.policy_digest.clone(),
        proving_digest: proving.report_digest().clone(),
        approval_context_digest: decision.approval_context_digest().clone(),
        idempotency_key: format!("receiver-adopt:{}", request.logical_operation_id),
    })
}

fn observation_binding(
    request: &ReceiverIntakeRequest,
    decision: &ApprovalDecisionRecord,
    proving: &ReceiverProvingReportV1,
    plan: &ReceiverImportPlanV1,
) -> Result<ExactActionBinding, M6ReceiverError> {
    conditional_effect_binding(
        AuthorityAction::ObserveImport,
        OBSERVATION_REQUEST_DOMAIN,
        "receiver-observe",
        request,
        decision,
        proving,
        plan,
    )
}

fn rollback_binding(
    request: &ReceiverIntakeRequest,
    decision: &ApprovalDecisionRecord,
    proving: &ReceiverProvingReportV1,
    plan: &ReceiverImportPlanV1,
) -> Result<ExactActionBinding, M6ReceiverError> {
    conditional_effect_binding(
        AuthorityAction::RollbackImport,
        ROLLBACK_REQUEST_DOMAIN,
        "receiver-rollback",
        request,
        decision,
        proving,
        plan,
    )
}

#[allow(clippy::too_many_arguments)]
fn conditional_effect_binding(
    action: AuthorityAction,
    domain: &[u8],
    idempotency_prefix: &str,
    request: &ReceiverIntakeRequest,
    decision: &ApprovalDecisionRecord,
    proving: &ReceiverProvingReportV1,
    plan: &ReceiverImportPlanV1,
) -> Result<ExactActionBinding, M6ReceiverError> {
    let request_digest = digest_domain(
        domain,
        &(
            &request.request_digest,
            decision.decision_digest(),
            proving.report_digest(),
            plan.import_plan_digest(),
            plan.receiver_local_package_digest(),
            &request.expected_active_snapshot_digest,
            &request.policy_digest,
        ),
    )?;
    Ok(ExactActionBinding {
        action,
        principal_id: decision.principal_id().to_string(),
        route_id: request.route_id.clone(),
        route_generation: request.route_generation,
        message_digest: request.message_digest.clone(),
        exchange_digest: request.exchange_digest.clone(),
        package_digest: plan.receiver_local_package_digest().clone(),
        request_digest,
        expected_active_snapshot_digest: request.expected_active_snapshot_digest.clone(),
        import_plan_digest: plan.import_plan_digest().clone(),
        policy_digest: request.policy_digest.clone(),
        proving_digest: proving.report_digest().clone(),
        approval_context_digest: decision.approval_context_digest().clone(),
        idempotency_key: format!("{idempotency_prefix}:{}", request.logical_operation_id),
    })
}

fn promotion_request_digest(
    request: &ReceiverIntakeRequest,
    decision: &ApprovalDecisionRecord,
    proving: &ReceiverProvingReportV1,
    plan: &ReceiverImportPlanV1,
    promotion_consumption: &AuthorizationConsumption,
    observation_consumption: &AuthorizationConsumption,
    rollback_consumption: &AuthorizationConsumption,
) -> Result<ContentDigest, M6ReceiverError> {
    digest_domain(
        PROMOTION_REQUEST_DOMAIN,
        &(
            &request.request_digest,
            decision.decision_digest(),
            proving.report_digest(),
            plan.import_plan_digest(),
            plan.receiver_local_package_digest(),
            promotion_consumption.authorization_digest(),
            promotion_consumption.receipt_digest(),
            observation_consumption.authorization_digest(),
            observation_consumption.receipt_digest(),
            rollback_consumption.authorization_digest(),
            rollback_consumption.receipt_digest(),
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn exact_m5_cycle_plan(
    request: &ReceiverIntakeRequest,
    decision: &ApprovalDecisionRecord,
    proving: &ReceiverProvingReportV1,
    plan: &ReceiverImportPlanV1,
    promotion_consumption: &AuthorizationConsumption,
    observation_consumption: &AuthorizationConsumption,
    rollback_consumption: &AuthorizationConsumption,
    expected_release_gate_digest: ContentDigest,
) -> Result<M5ExactCandidateCyclePlan, M6ReceiverError> {
    Ok(M5ExactCandidateCyclePlan {
        cycle_id: activation_cycle_id(&request.logical_operation_id),
        expected_active_package_digest: request.expected_active_package_digest.clone(),
        expected_active_snapshot_digest: request.expected_active_snapshot_digest.clone(),
        expected_release_gate_digest,
        candidate_package_bytes: plan.receiver_local_package_bytes().to_vec(),
        candidate_wat_bytes: plan.source_recipe_wat_bytes().to_vec(),
        operator_context_digest: promotion_request_digest(
            request,
            decision,
            proving,
            plan,
            promotion_consumption,
            observation_consumption,
            rollback_consumption,
        )?,
        approval_decision: ApprovalDecision::Approved,
        approver_ref: decision.principal_id().to_string(),
        approval_rationale: decision.rationale().to_string(),
    })
}

fn exchange_revocation_binding(
    route: &RouteDefinition,
    request: &ReceiverIntakeRequest,
    verified: &VerifiedQuarantinedExportV1,
    plan: &ReceiverImportPlanV1,
) -> ExchangeRevocationBindingV1 {
    ExchangeRevocationBindingV1 {
        exchange_message_digest: request.message_digest.clone(),
        receiver_import_plan_digest: plan.import_plan_digest().clone(),
        receiver_local_package_digest: plan.receiver_local_package_digest().clone(),
        source_identity_document_digest: verified.source_identity_document_digest().clone(),
        source_package_digest: verified.source_package_digest().clone(),
        source_signing_key_digest: ContentDigest::from_bytes(
            route.sender.public_key_hex.as_bytes(),
        ),
    }
}

fn require_exact_authorization(
    authorization: &ActionAuthorization,
    action: AuthorityAction,
    expected_binding: &ExactActionBinding,
) -> Result<(), M6ReceiverError> {
    if authorization.binding().action != action
        || authorization.binding() != expected_binding
        || authorization.use_limit() != 1
    {
        return Err(M6ReceiverError::Authority(format!(
            "{action:?} authorization does not bind the exact receiver request"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn stage_evidence(
    cause: StageCause,
    attempt: u32,
    authority_ref: Option<ContentDigest>,
    effect_request_digest: Option<ContentDigest>,
    evidence_refs: Vec<ContentDigest>,
    receipt_ref: Option<ContentDigest>,
    attestation_ref: Option<ContentDigest>,
) -> Result<StageEvidence, M6ReceiverError> {
    StageEvidence::new(
        cause,
        attempt,
        authority_ref,
        effect_request_digest,
        receipt_ref,
        attestation_ref,
        evidence_refs,
    )
    .map_err(M6ReceiverError::from)
}

fn replay_fact_digest(fact: &ReplayCommitFact) -> Result<ContentDigest, M6ReceiverError> {
    digest_domain(
        REPLAY_FACT_DOMAIN,
        &(
            &fact.message_digest,
            &fact.nonce,
            fact.retained_until_ms,
            &fact.route_definition_digest,
            fact.sequence,
        ),
    )
}

fn validate_portable_raw_unit_files(
    record: &RawQuarantineRecord,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), M6ReceiverError> {
    if files.len() != record.files.len()
        || record.files.iter().any(|observation| {
            files.get(&observation.relative_path).is_none_or(|bytes| {
                bytes.len() as u64 != observation.byte_length
                    || ContentDigest::from_bytes(bytes) != observation.content_digest
            })
        })
    {
        return Err(M6ReceiverError::Integrity(
            "portable raw-unit bytes differ from immutable quarantine observations".to_string(),
        ));
    }
    Ok(())
}

fn validate_operator_rollback_record(
    record: &OperatorRollbackRecord,
) -> Result<(), M6ReceiverError> {
    validate_identifier("operator rollback id", &record.rollback_id)?;
    validate_identifier("operator rollback reason", &record.reason_ref)?;
    if !record.recovery_receipt.state_readable
        || record.recovery_receipt.restored_package_digest != record.restored_package_digest
    {
        return Err(M6ReceiverError::Integrity(
            "operator rollback recovery did not restore a readable exact package".to_string(),
        ));
    }
    let recovery_digest = digest_json_content(&(
        "wasm-biotic:recovery-receipt:v1",
        &record.recovery_receipt.recovery_id,
        &record.recovery_receipt.request_digest,
        &record.recovery_receipt.restored_package_digest,
        &record.recovery_receipt.restored_package_bytes_digest,
        record.recovery_receipt.restored_state_schema,
        record.recovery_receipt.state_readable,
    ))
    .map_err(|error| M6ReceiverError::Serialization(error.to_string()))?;
    require_digest(
        "operator rollback recovery receipt",
        &record.recovery_receipt.receipt_digest,
        &recovery_digest,
    )?;
    let rollback_digest = digest_json_content(&(
        "wasm-biotic:operator-factory-rollback:v1",
        &record.rollback_id,
        &record.from_package_digest,
        &record.restored_package_digest,
        &record.reason_ref,
        &record.recovery_receipt,
    ))
    .map_err(|error| M6ReceiverError::Serialization(error.to_string()))?;
    require_digest(
        "operator rollback record",
        &record.record_digest,
        &rollback_digest,
    )
}

fn validate_execution_against_package(
    execution: &M5ActiveExecution,
    package_bytes: &[u8],
    suite: &ValidationSuite,
) -> Result<(), M6ReceiverError> {
    let package = FactoryPackage::from_canonical_bytes(package_bytes)
        .map_err(|error| M6ReceiverError::M5(error.to_string()))?;
    if package
        .canonical_bytes()
        .map_err(|error| M6ReceiverError::M5(error.to_string()))?
        != package_bytes
        || execution.package_digest != package.package_digest
        || execution.package_bytes_digest != ContentDigest::from_bytes(package_bytes)
        || execution.component_digest != package.payload.genome.component_digest
    {
        return Err(M6ReceiverError::Integrity(
            "M5 active execution differs from its exact package bytes".to_string(),
        ));
    }
    let trace = execute_component_i32_export(
        &package.payload.genome.component_bytes,
        &suite.export_name,
        execution.input,
        &suite.limits,
    )
    .map_err(|error| M6ReceiverError::M5(error.to_string()))?;
    if trace.output != Some(execution.output) {
        return Err(M6ReceiverError::Integrity(
            "M5 active execution output cannot be replayed from its component bytes".to_string(),
        ));
    }
    let expected_digest = digest_json_content(&(
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
        &trace,
    ))
    .map_err(|error| M6ReceiverError::Serialization(error.to_string()))?;
    require_digest(
        "M5 active execution",
        &execution.execution_digest,
        &expected_digest,
    )
}

fn completion_authority<'a>(
    authorities: &'a BTreeMap<AuthorityAction, (ActionAuthorization, AuthorizationConsumption)>,
    action: AuthorityAction,
) -> Result<&'a (ActionAuthorization, AuthorizationConsumption), M6ReceiverError> {
    authorities.get(&action).ok_or_else(|| {
        M6ReceiverError::Integrity(format!(
            "receiver completion lacks exact {action:?} authority source"
        ))
    })
}

fn require_completion_binding(
    authorities: &BTreeMap<AuthorityAction, (ActionAuthorization, AuthorizationConsumption)>,
    action: AuthorityAction,
    expected: &ExactActionBinding,
) -> Result<(), M6ReceiverError> {
    let (authorization, _) = completion_authority(authorities, action)?;
    require_exact_authorization(authorization, action, expected)
}

fn observation_has_failure(
    observation: &crate::factory_reproduction::PostActivationEvidence,
) -> bool {
    observation.task_observations.iter().any(|task| {
        task.terminal != crate::factory_reproduction::ExecutionTerminal::Succeeded
            || task.health != crate::factory_reproduction::HealthStatus::Healthy
    }) || observation
        .health_observations
        .iter()
        .any(|health| health.status != crate::factory_reproduction::HealthStatus::Healthy)
}

fn validate_completion_activation_observation(
    cycle: &ReceiverM5CycleEvidence,
    plan: &ReceiverImportPlanV1,
) -> Result<(), M6ReceiverError> {
    if cycle.cycle_record.challenger_package_digest != *plan.receiver_local_package_digest() {
        return Err(M6ReceiverError::Integrity(
            "M5 completion challenger differs from the receiver-proved local package".to_string(),
        ));
    }
    let observation = cycle
        .cycle_record
        .observation_evidence
        .as_ref()
        .ok_or_else(|| {
            M6ReceiverError::Integrity(
                "terminal M5 completion lacks post-activation observations".to_string(),
            )
        })?;
    match cycle.disposition {
        ReceiverM5Disposition::Healthy => {
            // This proves that the receiver-proved package was exercised in
            // shadow and then observed through the active route. It is only an
            // activation observation; the separate same-input before/after
            // M3 executions establish the actual behavior-change claim.
            let activated_package_observed = cycle.cycle_record.parent_package_digest
                != cycle.cycle_record.challenger_package_digest
                && cycle
                    .cycle_record
                    .shadow_evidence
                    .incumbent_observations
                    .iter()
                    .any(|incumbent| {
                        cycle
                            .cycle_record
                            .shadow_evidence
                            .challenger_observations
                            .iter()
                            .find(|candidate| candidate.benchmark_id == incumbent.benchmark_id)
                            .is_some_and(|challenger| {
                                incumbent.package_digest == cycle.cycle_record.parent_package_digest
                                    && challenger.package_digest
                                        == cycle.cycle_record.challenger_package_digest
                                    && observation.task_observations.iter().any(|active| {
                                        // Shadow and live probes intentionally use
                                        // different execution/benchmark labels.
                                        // The canonical request digest is their
                                        // exact cross-domain input identity.
                                        active.request_digest == challenger.request_digest
                                            && active.package_digest
                                                == *plan.receiver_local_package_digest()
                                            && active.output_digest == challenger.output_digest
                                            && active.terminal == challenger.terminal
                                            && active.health == challenger.health
                                    })
                            })
                    });
            if !activated_package_observed {
                return Err(M6ReceiverError::Integrity(
                    "healthy import completion does not derive an exact activated-package observation"
                        .to_string(),
                ));
            }
        }
        ReceiverM5Disposition::RolledBack => {
            let observed_failure = observation_has_failure(observation);
            if !observed_failure || cycle.cycle_record.recovery_receipt.is_none() {
                return Err(M6ReceiverError::Integrity(
                    "rolled-back completion lacks an observed post-adoption failure and recovery"
                        .to_string(),
                ));
            }
        }
        ReceiverM5Disposition::ValidationRejected => {
            return Err(M6ReceiverError::Integrity(
                "pre-activation validation rejection is not an exchange completion".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_ack_issued(
    request: &ReceiverAcknowledgementRequest,
    issued: &IssuedManifest,
    route: &RouteDefinition,
) -> Result<(), M6ReceiverError> {
    issued.manifest.verify_route(route)?;
    if !issued.attachments.is_empty()
        || issued.manifest.unsigned.origin_role != RouteEndpointRole::Receiver
        || issued.manifest.unsigned.payload != request.payload()
    {
        return Err(M6ReceiverError::Integrity(
            "receiver acknowledgement issuance differs from its exact attachment-free payload"
                .to_string(),
        ));
    }
    Ok(())
}

fn ack_delivery_digest(issued: &IssuedManifest) -> Result<ContentDigest, M6ReceiverError> {
    digest_domain(
        ACK_DELIVERY_DOMAIN,
        &(issued.manifest.canonical_bytes()?, &issued.attachments),
    )
}

fn approval_kind_label(kind: ApprovalDecisionKind) -> &'static str {
    match kind {
        ApprovalDecisionKind::Granted => "granted",
        ApprovalDecisionKind::Denied => "denied",
        ApprovalDecisionKind::Expired => "expired",
        ApprovalDecisionKind::Escalated => "escalated",
    }
}

fn terminal_kind_label(kind: ReceiverTerminalKind) -> &'static str {
    match kind {
        ReceiverTerminalKind::ValidationRejected => "validation_rejected",
        ReceiverTerminalKind::Denied => "denied",
        ReceiverTerminalKind::Expired => "expired",
        ReceiverTerminalKind::Escalated => "escalated",
        ReceiverTerminalKind::RevokedBeforePromotion => "denied",
    }
}

fn receiver_terminal_stage_label(stage: TransactionStage) -> Option<&'static str> {
    match stage {
        TransactionStage::RawAdmissionRejected => Some("raw_admission_rejected"),
        TransactionStage::ValidationRejected => Some("validation_rejected"),
        TransactionStage::Denied => Some("denied"),
        TransactionStage::Expired => Some("expired"),
        TransactionStage::Escalated => Some("escalated"),
        TransactionStage::Healthy => Some("healthy"),
        TransactionStage::RolledBack => Some("rolled_back"),
        TransactionStage::ContainmentRequired => Some("containment_required"),
        TransactionStage::RevocationContained => Some("revocation_contained"),
        TransactionStage::RevocationContainmentRequired => Some("revocation_containment_required"),
        _ => None,
    }
}

fn activation_cycle_id(logical_operation_id: &str) -> String {
    format!(
        "m6-import:{}",
        ContentDigest::from_bytes(logical_operation_id.as_bytes()).file_stem()
    )
}

fn operation_root(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!(
        "{}.intake",
        ContentDigest::from_bytes(logical_operation_id.as_bytes()).file_stem()
    ))
}

fn persist_request_unit(
    operation_root: &Path,
    request: &ReceiverIntakeRequest,
    active: &ReceiverActiveStateV1,
) -> Result<(), M6ReceiverError> {
    let parent = operation_root
        .parent()
        .ok_or_else(|| M6ReceiverError::UnsafePath(operation_root.to_path_buf()))?;
    if operation_root.exists() {
        return Err(M6ReceiverError::Integrity(
            "receiver request unit appeared after its absence was checked".to_string(),
        ));
    }
    let request_bytes = canonical_json(request)?;
    let active_bytes = active.canonical_bytes()?;
    let commit = ReceiverIntakeRequestCommit::new(request, &request_bytes, &active_bytes)?;
    let temporary = parent.join(format!(
        ".building-{}-{}-{}",
        request.request_digest.file_stem(),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        fs::create_dir(&temporary).map_err(|source| M6ReceiverError::io(&temporary, source))?;
        write_new_sync(&temporary.join(REQUEST_FILE), &request_bytes)?;
        write_new_sync(&temporary.join(ACTIVE_STATE_FILE), &active_bytes)?;
        write_new_sync(
            &temporary.join(REQUEST_COMMIT_FILE),
            &canonical_json(&commit)?,
        )?;
        sync_directory(&temporary)?;
        fs::rename(&temporary, operation_root)
            .map_err(|source| M6ReceiverError::io(operation_root, source))?;
        sync_directory(parent)
    })();
    if result.is_err() && temporary.exists() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn load_request_unit(
    operation_root: &Path,
    route: &RouteDefinition,
    policy: &ReceiverImportPolicyV1,
) -> Result<(ReceiverIntakeRequest, ReceiverActiveStateV1), M6ReceiverError> {
    reject_symlink(operation_root)?;
    let request_bytes =
        read_regular_bounded(&operation_root.join(REQUEST_FILE), MAX_REQUEST_BYTES)?;
    let active_bytes =
        read_regular_bounded(&operation_root.join(ACTIVE_STATE_FILE), MAX_REQUEST_BYTES)?;
    let commit: ReceiverIntakeRequestCommit =
        load_canonical_file(&operation_root.join(REQUEST_COMMIT_FILE), MAX_REQUEST_BYTES)?;
    let request: ReceiverIntakeRequest = parse_canonical(&request_bytes, MAX_REQUEST_BYTES)?;
    let active = ReceiverActiveStateV1::from_canonical_bytes(&active_bytes)?;
    request.validate(route, &active, policy)?;
    commit.validate(&request, &request_bytes, &active_bytes)?;
    Ok((request, active))
}

fn persist_operation_record(
    operation_root: &Path,
    name: &str,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<(), M6ReceiverError> {
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(M6ReceiverError::ResourceExhausted(format!(
            "receiver record '{name}' exceeds its byte budget"
        )));
    }
    persist_immutable_file(&operation_root.join(name), bytes)
}

fn enforce_operation_bound(
    operations_root: &Path,
    max_operations: u32,
) -> Result<(), M6ReceiverError> {
    let mut count = 0_u32;
    for entry in fs::read_dir(operations_root)
        .map_err(|source| M6ReceiverError::io(operations_root, source))?
    {
        let entry = entry.map_err(|source| M6ReceiverError::io(operations_root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if entry
            .file_type()
            .map_err(|source| M6ReceiverError::io(&path, source))?
            .is_dir()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".intake"))
        {
            count = count.saturating_add(1);
        } else if !entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".building-"))
        {
            return Err(M6ReceiverError::Integrity(format!(
                "unexpected receiver operation entry '{}'",
                path.display()
            )));
        }
    }
    if count >= max_operations {
        return Err(M6ReceiverError::ResourceExhausted(
            "receiver intake operation budget is exhausted".to_string(),
        ));
    }
    Ok(())
}

fn recover_building_directories(root: &Path) -> Result<(), M6ReceiverError> {
    for entry in fs::read_dir(root).map_err(|source| M6ReceiverError::io(root, source))? {
        let entry = entry.map_err(|source| M6ReceiverError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".building-"))
            && entry
                .file_type()
                .map_err(|source| M6ReceiverError::io(&path, source))?
                .is_dir()
        {
            fs::remove_dir_all(&path).map_err(|source| M6ReceiverError::io(&path, source))?;
        }
    }
    sync_directory(root)
}

fn build_quarantine_inventory(
    operations_root: &Path,
    revocation_operations_root: &Path,
    control_rejections_root: &Path,
    journal: &CoordinatorJournal,
    quarantine: &ReceiverRawQuarantine,
    route: &RouteDefinition,
    signer: &FactorySigner,
    durable_state_digest: ContentDigest,
    scanned_at_ms: u64,
) -> Result<ReceiverUnresolvedQuarantineInventoryV1, M6ReceiverError> {
    let mut operations = Vec::new();
    for projection in journal.transactions()? {
        let (transaction_kind, root) = match projection.intent.kind {
            TransactionKind::ReceiverIntake => {
                (ReceiverInboundTransactionKindV1::Import, operations_root)
            }
            TransactionKind::ReceiverRevocationApplication => (
                ReceiverInboundTransactionKindV1::Revocation,
                revocation_operations_root,
            ),
            _ => continue,
        };
        let current_stage = projection.current_stage().ok_or_else(|| {
            M6ReceiverError::Integrity(
                "receiver quarantine scan found a transaction without a current stage".to_string(),
            )
        })?;
        let operation_root = match transaction_kind {
            ReceiverInboundTransactionKindV1::Import => {
                operation_root(root, &projection.intent.logical_operation_id)
            }
            ReceiverInboundTransactionKindV1::Revocation => {
                revocation_operation_root(root, &projection.intent.logical_operation_id)
            }
        };
        let request_bytes =
            read_regular_bounded(&operation_root.join(REQUEST_FILE), MAX_REQUEST_BYTES)?;
        let (message_digest, outer_request_digest) = match transaction_kind {
            ReceiverInboundTransactionKindV1::Import => {
                let request: ReceiverIntakeRequest =
                    parse_canonical(&request_bytes, MAX_REQUEST_BYTES)?;
                (request.message_digest, request.request_digest)
            }
            ReceiverInboundTransactionKindV1::Revocation => {
                let request: ReceiverRevocationRequest =
                    parse_canonical(&request_bytes, MAX_REQUEST_BYTES)?;
                (request.message_digest, request.request_digest)
            }
        };
        let coordinator_projection_bytes = projection.canonical_bytes()?;
        let raw_path = operation_root.join(RAW_RECORD_FILE);
        let raw_quarantine_bytes = raw_path
            .exists()
            .then(|| read_regular_bounded(&raw_path, MAX_RECORD_BYTES))
            .transpose()?;
        let early_control_rejection = if raw_quarantine_bytes.is_none()
            && current_stage == TransactionStage::ValidationRejected
        {
            let identity = digest_domain(
                CONTROL_REJECTION_DOMAIN,
                &(
                    ReceiverControlRejectionClassV1::MessageReplay,
                    &projection.intent.logical_operation_id,
                    &outer_request_digest,
                    &message_digest,
                ),
            )?;
            let path = control_rejections_root.join(format!("{}.json", identity.file_stem()));
            if !path.exists() {
                return Err(M6ReceiverError::Integrity(
                    "raw-free terminal validation lacks its signed control rejection".to_string(),
                ));
            }
            let rejection: ReceiverSignedControlRejectionV1 =
                load_canonical_file(&path, MAX_RECORD_BYTES)?;
            rejection.validate(route)?;
            let terminal = projection.current_record().ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "early control rejection lacks its terminal coordinator record".to_string(),
                )
            })?;
            if rejection.class != ReceiverControlRejectionClassV1::MessageReplay
                || rejection.logical_operation_id != projection.intent.logical_operation_id
                || rejection.outer_request_digest != outer_request_digest
                || rejection.message_digest != message_digest
                || !terminal
                    .evidence
                    .evidence_refs
                    .contains(&rejection.record_digest)
            {
                return Err(M6ReceiverError::Integrity(
                    "early terminal replay projection differs from its signed control rejection"
                        .to_string(),
                ));
            }
            true
        } else {
            false
        };
        let unresolved_raw_unit_files =
            if raw_quarantine_bytes.is_some() && !current_stage.is_terminal() {
                let raw = RawQuarantineRecord::from_canonical_bytes(
                    raw_quarantine_bytes.as_deref().expect("checked"),
                    route,
                )?;
                Some(quarantine.read_committed_unit(&raw)?.files().clone())
            } else {
                None
            };
        if raw_quarantine_bytes.is_none()
            && !matches!(
                current_stage,
                TransactionStage::IntakeIntentRecorded
                    | TransactionStage::RevocationIntakeIntentRecorded
                    | TransactionStage::RawAdmissionRejected
            )
            && !early_control_rejection
        {
            return Err(M6ReceiverError::Integrity(
                "receiver transaction advanced beyond raw admission without quarantine evidence"
                    .to_string(),
            ));
        }
        let mut operation = ReceiverQuarantineOperationAuditV1 {
            transaction_kind,
            logical_operation_id: projection.intent.logical_operation_id.clone(),
            message_digest,
            outer_request_digest,
            coordinator_request_digest: projection.intent.request_digest.clone(),
            current_stage,
            request_bytes,
            coordinator_projection_bytes,
            raw_quarantine_bytes,
            unresolved_raw_unit_files,
            operation_digest: ContentDigest::from_bytes(&[]),
        };
        operation.operation_digest = operation.expected_digest()?;
        operation.validate(route)?;
        operations.push(operation);
    }
    operations.sort_by(|left, right| {
        (left.transaction_kind, left.logical_operation_id.as_str())
            .cmp(&(right.transaction_kind, right.logical_operation_id.as_str()))
    });
    if operations.len() > MAX_DURABLE_STATE_ENTRIES {
        return Err(M6ReceiverError::ResourceExhausted(
            "receiver quarantine inventory exceeds its operation bound".to_string(),
        ));
    }
    let unresolved_operation_digests = operations
        .iter()
        .filter(|operation| operation.unresolved())
        .map(|operation| operation.operation_digest.clone())
        .collect();
    let mut inventory = ReceiverUnresolvedQuarantineInventoryV1 {
        schema: RECEIVER_UNRESOLVED_QUARANTINE_INVENTORY_SCHEMA.to_string(),
        receiver_factory_id: route.receiver.factory_id.clone(),
        route_definition_digest: route.definition_digest.clone(),
        signing_key_id: signer.signing_key_id().to_string(),
        durable_state_digest,
        operations,
        unresolved_operation_digests,
        scanned_at_ms,
        inventory_digest: ContentDigest::from_bytes(&[]),
        signature_hex: String::new(),
    };
    inventory.inventory_digest = inventory.expected_digest()?;
    inventory.signature_hex =
        signer.sign_receiver_quarantine_inventory(route, &inventory.inventory_digest)?;
    inventory.validate(route)?;
    Ok(inventory)
}

#[derive(Serialize)]
struct ReceiverDurableStateEntry {
    relative_path: String,
    entry_kind: &'static str,
    byte_length: u64,
    content_digest: Option<ContentDigest>,
}

fn receiver_durable_state_root(
    endpoint_root: &Path,
    m5_root: &Path,
) -> Result<ContentDigest, M6ReceiverError> {
    let endpoint_root = fs::canonicalize(endpoint_root)
        .map_err(|source| M6ReceiverError::io(endpoint_root, source))?;
    let m5_root =
        fs::canonicalize(m5_root).map_err(|source| M6ReceiverError::io(m5_root, source))?;
    if m5_root == endpoint_root || !m5_root.starts_with(&endpoint_root) {
        return Err(M6ReceiverError::InvalidConfiguration(
            "receiver durable-state scope requires the exact configured M5 subtree".to_string(),
        ));
    }
    let mut pending = vec![endpoint_root.to_path_buf()];
    let mut entries = Vec::new();
    let mut aggregate_bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        let mut children = fs::read_dir(&directory)
            .map_err(|source| M6ReceiverError::io(&directory, source))?
            .map(|entry| {
                entry
                    .map(|value| value.path())
                    .map_err(|source| M6ReceiverError::io(&directory, source))
            })
            .collect::<Result<Vec<_>, _>>()?;
        children.sort();
        for child in children.into_iter().rev() {
            reject_symlink(&child)?;
            let relative = child
                .strip_prefix(&endpoint_root)
                .map_err(|_| M6ReceiverError::UnsafePath(child.clone()))?;
            let relative_string = relative
                .to_str()
                .ok_or_else(|| M6ReceiverError::UnsafePath(child.clone()))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            let first_component = relative
                .components()
                .next()
                .and_then(|component| component.as_os_str().to_str())
                .ok_or_else(|| M6ReceiverError::UnsafePath(child.clone()))?;
            if child == m5_root
                || first_component == REOPEN_AUDITS_DIRECTORY
                || (relative.components().count() == 1 && first_component == OWNER_LOCK_FILE)
            {
                continue;
            }
            let metadata =
                fs::metadata(&child).map_err(|source| M6ReceiverError::io(&child, source))?;
            if metadata.is_dir() {
                entries.push(ReceiverDurableStateEntry {
                    relative_path: relative_string,
                    entry_kind: "directory",
                    byte_length: 0,
                    content_digest: None,
                });
                pending.push(child);
            } else if metadata.is_file() {
                let length = metadata.len();
                if length > MAX_DURABLE_STATE_FILE_BYTES as u64 {
                    return Err(M6ReceiverError::ResourceExhausted(format!(
                        "receiver durable state file '{}' exceeds its snapshot bound",
                        child.display()
                    )));
                }
                aggregate_bytes = aggregate_bytes.checked_add(length).ok_or_else(|| {
                    M6ReceiverError::ResourceExhausted(
                        "receiver durable state byte total overflowed".to_string(),
                    )
                })?;
                if aggregate_bytes > MAX_DURABLE_STATE_AGGREGATE_BYTES {
                    return Err(M6ReceiverError::ResourceExhausted(
                        "receiver durable state exceeds its aggregate snapshot bound".to_string(),
                    ));
                }
                let bytes = read_regular_bounded(&child, MAX_DURABLE_STATE_FILE_BYTES)?;
                entries.push(ReceiverDurableStateEntry {
                    relative_path: relative_string,
                    entry_kind: "file",
                    byte_length: length,
                    content_digest: Some(ContentDigest::from_bytes(&bytes)),
                });
            } else {
                return Err(M6ReceiverError::Integrity(format!(
                    "receiver durable state contains unsupported entry '{}'",
                    child.display()
                )));
            }
            if entries.len() > MAX_DURABLE_STATE_ENTRIES {
                return Err(M6ReceiverError::ResourceExhausted(
                    "receiver durable state exceeds its entry bound".to_string(),
                ));
            }
        }
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    digest_domain(DURABLE_STATE_ROOT_DOMAIN, &entries)
}

fn generate_receiver_process_instance_id(
    nonce_source: &dyn NonceSource,
    previous: Option<&str>,
) -> Result<String, M6ReceiverError> {
    for _ in 0..8 {
        let mut entropy = [0_u8; 32];
        nonce_source.fill(&mut entropy)?;
        let digest = {
            let mut bytes = Vec::from(PROCESS_INSTANCE_DOMAIN);
            bytes.extend_from_slice(&entropy);
            ContentDigest::from_bytes(&bytes)
        };
        let instance_id = format!("receiver-instance:{}", digest.file_stem());
        if previous != Some(instance_id.as_str()) {
            return Ok(instance_id);
        }
    }
    Err(M6ReceiverError::Integrity(
        "nonce source repeated the prior receiver process instance identity".to_string(),
    ))
}

fn load_reopen_recovered_exchanges(
    operations_root: &Path,
    journal: &CoordinatorJournal,
    route: &RouteDefinition,
    maximum: u32,
) -> Result<Vec<ReceiverReopenRecoveredExchangeV1>, M6ReceiverError> {
    let mut recovered = Vec::new();
    for entry in fs::read_dir(operations_root)
        .map_err(|source| M6ReceiverError::io(operations_root, source))?
    {
        let entry = entry.map_err(|source| M6ReceiverError::io(operations_root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if !entry
            .file_type()
            .map_err(|source| M6ReceiverError::io(&path, source))?
            .is_dir()
        {
            return Err(M6ReceiverError::Integrity(format!(
                "unexpected receiver intake entry '{}'",
                path.display()
            )));
        }
        let receipt_path = path.join(ADOPTION_RECEIPT_FILE);
        if !receipt_path.exists() {
            continue;
        }
        let request_bytes = read_regular_bounded(&path.join(REQUEST_FILE), MAX_REQUEST_BYTES)?;
        let request: ReceiverIntakeRequest = parse_canonical(&request_bytes, MAX_REQUEST_BYTES)?;
        let adoption_receipt_bytes = read_regular_bounded(&receipt_path, MAX_RECORD_BYTES)?;
        let receipt: ReceiverAdoptionReceipt =
            parse_canonical(&adoption_receipt_bytes, MAX_RECORD_BYTES)?;
        let projection = journal
            .transaction(&request.logical_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "reopened receiver adoption has no coordinator transaction".to_string(),
                )
            })?;
        let terminal = projection.current_record().ok_or_else(|| {
            M6ReceiverError::Integrity(
                "reopened receiver adoption has no terminal coordinator stage".to_string(),
            )
        })?;
        let coordinator_projection_bytes = projection.canonical_bytes()?;
        let mut exchange = ReceiverReopenRecoveredExchangeV1 {
            logical_operation_id: request.logical_operation_id.clone(),
            message_digest: request.message_digest.clone(),
            disposition: receipt.disposition,
            terminal_stage_digest: terminal.stage_digest.clone(),
            adoption_receipt_digest: receipt.receipt_digest.clone(),
            request_bytes,
            coordinator_projection_bytes,
            adoption_receipt_bytes,
            recovered_digest: ContentDigest::from_bytes(&[]),
        };
        exchange.recovered_digest = exchange.expected_digest()?;
        exchange.validate(route)?;
        recovered.push(exchange);
        if recovered.len() > maximum as usize {
            return Err(M6ReceiverError::ResourceExhausted(
                "receiver reopen exchange count exceeds its configured bound".to_string(),
            ));
        }
    }
    recovered.sort_by(|left, right| left.logical_operation_id.cmp(&right.logical_operation_id));
    if !recovered
        .windows(2)
        .all(|pair| pair[0].logical_operation_id < pair[1].logical_operation_id)
    {
        return Err(M6ReceiverError::Integrity(
            "receiver reopen exchanges reuse a logical operation id".to_string(),
        ));
    }
    Ok(recovered)
}

fn load_receiver_reopen_audit_chain(
    root: &Path,
    route: &RouteDefinition,
) -> Result<Vec<ReceiverReopenAuditV1>, M6ReceiverError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).map_err(|source| M6ReceiverError::io(root, source))? {
        let entry = entry.map_err(|source| M6ReceiverError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| M6ReceiverError::UnsafePath(path.clone()))?;
        if !entry
            .file_type()
            .map_err(|source| M6ReceiverError::io(&path, source))?
            .is_file()
            || !name.starts_with("open-")
            || !name.ends_with(".json")
        {
            return Err(M6ReceiverError::Integrity(format!(
                "unexpected receiver reopen-audit entry '{}'",
                path.display()
            )));
        }
        paths.push(path);
        if paths.len() > MAX_DURABLE_STATE_ENTRIES {
            return Err(M6ReceiverError::ResourceExhausted(
                "receiver reopen-audit chain exceeds its entry bound".to_string(),
            ));
        }
    }
    paths.sort();
    let mut audits = Vec::with_capacity(paths.len());
    for (index, path) in paths.iter().enumerate() {
        let audit: ReceiverReopenAuditV1 = load_canonical_file(path, MAX_REOPEN_AUDIT_BYTES)?;
        audit.validate(route)?;
        if audit.open_ordinal != index as u64 + 1
            || audit.previous_audit_digest
                != audits
                    .last()
                    .map(|previous: &ReceiverReopenAuditV1| previous.audit_digest.clone())
            || audit.previous_process_instance_id
                != audits
                    .last()
                    .map(|previous| previous.current_process_instance_id.clone())
        {
            return Err(M6ReceiverError::Integrity(
                "receiver reopen-audit chain is missing, reordered, or cross-linked".to_string(),
            ));
        }
        audits.push(audit);
    }
    Ok(audits)
}

fn persist_receiver_reopen_audit(
    root: &Path,
    audit: &ReceiverReopenAuditV1,
) -> Result<(), M6ReceiverError> {
    persist_immutable_file(
        &root.join(format!("open-{:020}.json", audit.open_ordinal)),
        &canonical_json(audit)?,
    )
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M6ReceiverError> {
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| M6ReceiverError::io(path, source))?;
    let canonical = fs::canonicalize(path).map_err(|source| M6ReceiverError::io(path, source))?;
    reject_symlink(&canonical)?;
    Ok(canonical)
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M6ReceiverError> {
    validate_identifier("receiver child directory", name)?;
    let path = root.join(name);
    reject_symlink_if_present(&path)?;
    fs::create_dir_all(&path).map_err(|source| M6ReceiverError::io(&path, source))?;
    let canonical = fs::canonicalize(&path).map_err(|source| M6ReceiverError::io(&path, source))?;
    if canonical.parent() != Some(root) {
        return Err(M6ReceiverError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn acquire_endpoint_owner(root: &Path) -> Result<File, M6ReceiverError> {
    let path = root.join(OWNER_LOCK_FILE);
    reject_symlink_if_present(&path)?;
    let existed = path.exists();
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| M6ReceiverError::io(&path, source))?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => {
            M6ReceiverError::EndpointAlreadyOwned(root.to_path_buf())
        }
        std::fs::TryLockError::Error(source) => M6ReceiverError::io(&path, source),
    })?;
    if !existed {
        sync_directory(root)?;
    }
    Ok(file)
}

fn persist_immutable_file(path: &Path, bytes: &[u8]) -> Result<(), M6ReceiverError> {
    if path.exists() {
        let existing = read_regular_bounded(path, bytes.len().max(1))?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(M6ReceiverError::Integrity(format!(
                "immutable receiver file '{}' contains conflicting bytes",
                path.display()
            )))
        };
    }
    write_new_sync(path, bytes)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| M6ReceiverError::UnsafePath(path.to_path_buf()))?,
    )
}

fn write_new_sync(path: &Path, bytes: &[u8]) -> Result<(), M6ReceiverError> {
    reject_symlink_if_present(path)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|source| M6ReceiverError::io(path, source))?;
    file.write_all(bytes)
        .map_err(|source| M6ReceiverError::io(path, source))?;
    file.sync_all()
        .map_err(|source| M6ReceiverError::io(path, source))
}

fn read_regular_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, M6ReceiverError> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|source| M6ReceiverError::io(path, source))?;
    if !metadata.is_file() || metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(M6ReceiverError::ResourceExhausted(format!(
            "receiver file '{}' is not regular or exceeds its byte budget",
            path.display()
        )));
    }
    let mut file = File::open(path).map_err(|source| M6ReceiverError::io(path, source))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(u64::try_from(max_bytes).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| M6ReceiverError::io(path, source))?;
    if bytes.len() > max_bytes {
        return Err(M6ReceiverError::ResourceExhausted(format!(
            "receiver file '{}' exceeds its byte budget",
            path.display()
        )));
    }
    Ok(bytes)
}

fn load_canonical_file<T: DeserializeOwned + Serialize>(
    path: &Path,
    max_bytes: usize,
) -> Result<T, M6ReceiverError> {
    parse_canonical(&read_regular_bounded(path, max_bytes)?, max_bytes)
}

fn parse_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, M6ReceiverError> {
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(M6ReceiverError::ResourceExhausted(
            "canonical receiver record is outside its byte budget".to_string(),
        ));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| M6ReceiverError::Serialization(error.to_string()))?;
    if canonical_json(&value)? != bytes {
        return Err(M6ReceiverError::Integrity(
            "receiver record is not canonical JSON".to_string(),
        ));
    }
    Ok(value)
}

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, M6ReceiverError> {
    serde_json::to_vec(value).map_err(|error| M6ReceiverError::Serialization(error.to_string()))
}

fn digest_domain<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ContentDigest, M6ReceiverError> {
    let mut bytes = Vec::from(domain);
    bytes.extend_from_slice(&canonical_json(value)?);
    Ok(ContentDigest::from_bytes(&bytes))
}

fn require_digest(
    subject: &str,
    actual: &ContentDigest,
    expected: &ContentDigest,
) -> Result<(), M6ReceiverError> {
    if actual == expected {
        Ok(())
    } else {
        Err(M6ReceiverError::DigestMismatch {
            subject: subject.to_string(),
            expected: expected.clone(),
            actual: actual.clone(),
        })
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<(), M6ReceiverError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(M6ReceiverError::InvalidConfiguration(format!(
            "{field} must contain 1..={MAX_IDENTIFIER_BYTES} non-control bytes"
        )));
    }
    Ok(())
}

fn ensure_m5_root_isolated(endpoint_root: &Path, m5_root: &Path) -> Result<(), M6ReceiverError> {
    for reserved in [
        INTAKE_AUTHORITY_DIRECTORY,
        PROVING_AUTHORITY_DIRECTORY,
        APPROVAL_AUTHORITY_DIRECTORY,
        PROMOTION_AUTHORITY_DIRECTORY,
        OBSERVATION_AUTHORITY_DIRECTORY,
        ROLLBACK_AUTHORITY_DIRECTORY,
        JOURNAL_DIRECTORY,
        REVOCATION_DIRECTORY,
        OPERATIONS_DIRECTORY,
        REVOCATION_OPERATIONS_DIRECTORY,
        MESSAGE_CLAIMS_DIRECTORY,
        CONTROL_REJECTIONS_DIRECTORY,
        REOPEN_AUDITS_DIRECTORY,
    ]
    .into_iter()
    .chain(IDENTITY_MUTABLE_TOP_LEVEL_DIRECTORIES.iter().copied())
    {
        let reserved_path = endpoint_root.join(reserved);
        if m5_root.starts_with(&reserved_path) || reserved_path.starts_with(m5_root) {
            return Err(M6ReceiverError::InvalidConfiguration(format!(
                "the receiver M5 root overlaps reserved directory '{reserved}'"
            )));
        }
    }
    Ok(())
}

fn is_strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M6ReceiverError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(M6ReceiverError::UnsafePath(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M6ReceiverError::io(path, source)),
    }
}

fn reject_symlink(path: &Path) -> Result<(), M6ReceiverError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6ReceiverError::io(path, source))?;
    if metadata.file_type().is_symlink() {
        Err(M6ReceiverError::UnsafePath(path.to_path_buf()))
    } else {
        Ok(())
    }
}

fn sync_directory(path: &Path) -> Result<(), M6ReceiverError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| M6ReceiverError::io(path, source))
}

fn maybe_crash(
    configured: Option<ReceiverCrashPoint>,
    boundary: ReceiverCrashPoint,
) -> Result<(), M6ReceiverError> {
    if configured == Some(boundary) {
        Err(M6ReceiverError::InjectedCrash(boundary))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum M6ReceiverError {
    InvalidConfiguration(String),
    InvalidState(String),
    Conflict {
        identity: String,
        existing: ContentDigest,
        requested: ContentDigest,
    },
    ActiveStateChanged {
        expected: ContentDigest,
        observed: ContentDigest,
    },
    RecoveryBlocked {
        blocking_operation_id: String,
    },
    ControlRejected {
        class: ReceiverControlRejectionClassV1,
        record_digest: ContentDigest,
    },
    EndpointAlreadyOwned(PathBuf),
    ResourceExhausted(String),
    Integrity(String),
    DigestMismatch {
        subject: String,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    UnsafePath(PathBuf),
    InjectedCrash(ReceiverCrashPoint),
    M5(String),
    Identity(String),
    Authority(String),
    Import(String),
    Revocation(String),
    Transaction(String),
    Serialization(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl M6ReceiverError {
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl Display for M6ReceiverError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid M6 receiver configuration: {message}")
            }
            Self::InvalidState(message) => {
                write!(formatter, "invalid M6 receiver state: {message}")
            }
            Self::Conflict {
                identity,
                existing,
                requested,
            } => write!(
                formatter,
                "receiver identity '{identity}' conflicts: existing {existing}, requested {requested}"
            ),
            Self::ActiveStateChanged { expected, observed } => write!(
                formatter,
                "receiver M5 active state changed: expected {expected}, observed {observed}"
            ),
            Self::RecoveryBlocked {
                blocking_operation_id,
            } => write!(
                formatter,
                "receiver operation is blocked by incomplete intake '{blocking_operation_id}'"
            ),
            Self::ControlRejected {
                class,
                record_digest,
            } => write!(
                formatter,
                "receiver {class:?} control rejected the input with signed record {record_digest}"
            ),
            Self::EndpointAlreadyOwned(path) => write!(
                formatter,
                "M6 receiver endpoint '{}' already has a live owner",
                path.display()
            ),
            Self::ResourceExhausted(message) => {
                write!(formatter, "M6 receiver resource bound: {message}")
            }
            Self::Integrity(message) => {
                write!(formatter, "M6 receiver integrity failure: {message}")
            }
            Self::DigestMismatch {
                subject,
                expected,
                actual,
            } => write!(
                formatter,
                "{subject} digest mismatch: expected {expected}, observed {actual}"
            ),
            Self::UnsafePath(path) => {
                write!(formatter, "unsafe M6 receiver path '{}'", path.display())
            }
            Self::InjectedCrash(point) => {
                write!(formatter, "injected receiver crash after {point:?}")
            }
            Self::M5(message) => write!(formatter, "M5 receiver dependency failed: {message}"),
            Self::Identity(message) => {
                write!(
                    formatter,
                    "M6 receiver identity dependency failed: {message}"
                )
            }
            Self::Authority(message) => {
                write!(
                    formatter,
                    "M6 receiver authority dependency failed: {message}"
                )
            }
            Self::Import(message) => {
                write!(formatter, "M6 receiver import dependency failed: {message}")
            }
            Self::Revocation(message) => {
                write!(
                    formatter,
                    "M6 receiver revocation dependency failed: {message}"
                )
            }
            Self::Transaction(message) => {
                write!(
                    formatter,
                    "M6 receiver coordinator dependency failed: {message}"
                )
            }
            Self::Serialization(message) => {
                write!(formatter, "M6 receiver serialization failed: {message}")
            }
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "M6 receiver I/O at '{}': {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for M6ReceiverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<crate::m5_runtime::M5RuntimeError> for M6ReceiverError {
    fn from(error: crate::m5_runtime::M5RuntimeError) -> Self {
        Self::M5(error.to_string())
    }
}

impl From<M6IdentityError> for M6ReceiverError {
    fn from(error: M6IdentityError) -> Self {
        Self::Identity(error.to_string())
    }
}

impl From<M6AuthorityError> for M6ReceiverError {
    fn from(error: M6AuthorityError) -> Self {
        Self::Authority(error.to_string())
    }
}

impl From<M6ImportError> for M6ReceiverError {
    fn from(error: M6ImportError) -> Self {
        Self::Import(error.to_string())
    }
}

impl From<M6RevocationError> for M6ReceiverError {
    fn from(error: M6RevocationError) -> Self {
        Self::Revocation(error.to_string())
    }
}

impl From<M6TransactionError> for M6ReceiverError {
    fn from(error: M6TransactionError) -> Self {
        Self::Transaction(error.to_string())
    }
}

impl<V: OpaqueAuthorizationVerifier> M6ReceiverRuntime<V> {
    pub fn commit_adoption(
        &mut self,
        logical_operation_id: &str,
        promotion_authorization_digest: &ContentDigest,
        observation_authorization_digest: &ContentDigest,
        rollback_authorization_digest: &ContentDigest,
    ) -> Result<ReceiverAdoptionResult, M6ReceiverError> {
        self.commit_adoption_with_fault(
            logical_operation_id,
            promotion_authorization_digest,
            observation_authorization_digest,
            rollback_authorization_digest,
            None,
        )
    }

    pub fn recover_adoption(
        &mut self,
        logical_operation_id: &str,
        promotion_authorization_digest: &ContentDigest,
        observation_authorization_digest: &ContentDigest,
        rollback_authorization_digest: &ContentDigest,
    ) -> Result<ReceiverAdoptionResult, M6ReceiverError> {
        self.commit_adoption(
            logical_operation_id,
            promotion_authorization_digest,
            observation_authorization_digest,
            rollback_authorization_digest,
        )
    }

    pub fn commit_adoption_with_fault(
        &mut self,
        logical_operation_id: &str,
        promotion_authorization_digest: &ContentDigest,
        observation_authorization_digest: &ContentDigest,
        rollback_authorization_digest: &ContentDigest,
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<ReceiverAdoptionResult, M6ReceiverError> {
        validate_identifier("receiver intake operation id", logical_operation_id)?;
        self.require_no_other_pending_operation(logical_operation_id)?;
        let operation_root = operation_root(&self.operations_root, logical_operation_id);
        let (request, active) =
            load_request_unit(&operation_root, self.route(), &self.import_policy)?;
        let (raw, verified, compatibility, proving, plan) =
            self.load_planned_context(&operation_root, &active)?;
        let approval_request = self.approval_request(
            &request,
            &active,
            &verified,
            &compatibility,
            &proving,
            &plan,
        )?;
        let decision = self
            .approval_authority
            .load_approval_decision(approval_request.request_digest())?;
        if decision.kind() != ApprovalDecisionKind::Granted {
            return Err(M6ReceiverError::InvalidState(
                "receiver adoption requires an immutable Granted decision".to_string(),
            ));
        }
        let expected_binding = promotion_binding(&request, &decision, &proving, &plan)?;
        let authorization = self
            .promotion_authority
            .load_authorization(promotion_authorization_digest)?;
        require_exact_authorization(
            &authorization,
            AuthorityAction::AdoptImport,
            &expected_binding,
        )?;
        let expected_observation_binding =
            observation_binding(&request, &decision, &proving, &plan)?;
        let observation_authorization = self
            .observation_authority
            .load_authorization(observation_authorization_digest)?;
        require_exact_authorization(
            &observation_authorization,
            AuthorityAction::ObserveImport,
            &expected_observation_binding,
        )?;
        let expected_rollback_binding = rollback_binding(&request, &decision, &proving, &plan)?;
        let rollback_authorization = self
            .rollback_authority
            .load_authorization(rollback_authorization_digest)?;
        require_exact_authorization(
            &rollback_authorization,
            AuthorityAction::RollbackImport,
            &expected_rollback_binding,
        )?;

        let coordinator_request_digest = self.coordinator_request_digest(logical_operation_id)?;
        let current_stage = self
            .journal
            .transaction(logical_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::InvalidState(
                    "receiver transaction disappeared before promotion".to_string(),
                )
            })?
            .current_stage();
        if operation_root.join(ADOPTION_RECEIPT_FILE).exists() {
            // A completed operation must already have all three exact
            // consumptions. Recovery reads those immutable facts rather than
            // attempting any additional use.
            let consumption = self
                .promotion_authority
                .load_consumption(promotion_authorization_digest, 1)?;
            let observation_consumption = self
                .observation_authority
                .load_consumption(observation_authorization_digest, 1)?;
            let rollback_consumption = self
                .rollback_authority
                .load_consumption(rollback_authorization_digest, 1)?;
            let evidence: ReceiverM5CycleEvidence =
                load_canonical_file(&operation_root.join(M5_CYCLE_FILE), MAX_RECORD_BYTES)?;
            evidence.validate(
                &request,
                &decision,
                &consumption,
                &observation_consumption,
                &rollback_consumption,
                &plan,
            )?;
            let receipt: ReceiverAdoptionReceipt = load_canonical_file(
                &operation_root.join(ADOPTION_RECEIPT_FILE),
                MAX_RECORD_BYTES,
            )?;
            receipt.validate(
                &request,
                &coordinator_request_digest,
                &decision,
                &consumption,
                &observation_consumption,
                &rollback_consumption,
                &plan,
                &evidence,
            )?;
            let terminal_stage = self
                .journal
                .transaction(logical_operation_id)?
                .and_then(|projection| projection.current_record().cloned())
                .ok_or_else(|| {
                    M6ReceiverError::InvalidState(
                        "receiver adoption receipt has no terminal coordinator stage".to_string(),
                    )
                })?;
            self.publish_acknowledgement(
                &request,
                match receipt.disposition {
                    ReceiverM5Disposition::Healthy => "healthy",
                    ReceiverM5Disposition::RolledBack => "rolled_back",
                    ReceiverM5Disposition::ValidationRejected => "validation_rejected",
                },
                raw.raw_unit_digest.clone(),
                &terminal_stage,
                crash_at,
            )?;
            return Ok(ReceiverAdoptionResult::Adopted(receipt));
        }
        if operation_root.join(TERMINAL_DECISION_FILE).exists() {
            let terminal: ReceiverTerminalDecision = load_canonical_file(
                &operation_root.join(TERMINAL_DECISION_FILE),
                MAX_RECORD_BYTES,
            )?;
            terminal.validate(&request)?;
            let terminal_stage = self
                .journal
                .transaction(logical_operation_id)?
                .and_then(|projection| projection.current_record().cloned())
                .filter(|record| record.stage.is_terminal())
                .ok_or_else(|| {
                    M6ReceiverError::Integrity(
                        "receiver terminal decision has no terminal coordinator record".to_string(),
                    )
                })?;
            self.publish_acknowledgement(
                &request,
                terminal_kind_label(terminal.kind),
                raw.raw_unit_digest.clone(),
                &terminal_stage,
                crash_at,
            )?;
            if terminal.kind == ReceiverTerminalKind::ValidationRejected {
                let rejection: ReceiverValidationRejection = load_canonical_file(
                    &operation_root.join(VALIDATION_REJECTION_FILE),
                    MAX_RECORD_BYTES,
                )?;
                rejection.validate(&request, &raw)?;
                return Ok(ReceiverAdoptionResult::ValidationRejected(rejection));
            }
            return Ok(ReceiverAdoptionResult::Terminal(terminal));
        }

        let (consumption, observation_consumption, rollback_consumption) = if current_stage
            == Some(TransactionStage::AwaitingApproval)
        {
            // Every fallible safety preflight precedes the first irreversible
            // promotion-authority write. If recovery finds one or two exact
            // consumptions already durable, `consume` resolves those same
            // ordinal-one facts and creates only the still-missing facts.
            let local_package =
                FactoryPackage::from_canonical_bytes(plan.receiver_local_package_bytes())
                    .map_err(|error| M6ReceiverError::Import(error.to_string()))?;
            if local_package.package_digest != *plan.receiver_local_package_digest() {
                return Err(M6ReceiverError::Integrity(
                    "receiver-local package bytes differ from the sealed import plan".to_string(),
                ));
            }
            let revocation_binding =
                exchange_revocation_binding(self.route(), &request, &verified, &plan);
            if self.revocations.is_revoked(&revocation_binding)? {
                let terminal_stage = self.append_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::Denied,
                    StageCause::PolicyRejection,
                    0,
                    Some(self.approval_authority.profile().profile_digest().clone()),
                    None,
                    vec![
                        plan.import_plan_digest().clone(),
                        decision.decision_digest().clone(),
                        authorization.authorization_digest().clone(),
                    ],
                    None,
                    None,
                )?;
                let terminal = self.persist_terminal_decision(
                    &request,
                    ReceiverTerminalKind::RevokedBeforePromotion,
                    Some(approval_request.request_digest().clone()),
                    Some(decision.decision_digest().clone()),
                    plan.import_plan_digest().clone(),
                )?;
                self.publish_acknowledgement(
                    &request,
                    "denied",
                    raw.raw_unit_digest.clone(),
                    &terminal_stage,
                    crash_at,
                )?;
                return Ok(ReceiverAdoptionResult::Terminal(terminal));
            }

            // The active state is re-read only before the first activation
            // intent. Once that write-ahead fact exists, M5's exact cycle
            // replay is authoritative even if the effect already changed the
            // live active snapshot.
            let live = self.capture_active_state()?;
            if live != active {
                return Err(M6ReceiverError::ActiveStateChanged {
                    expected: active.snapshot().snapshot_digest.clone(),
                    observed: live.snapshot().snapshot_digest.clone(),
                });
            }
            // The exact incumbent execution is durable before any activation
            // authority consumption or write-ahead activation intent.
            self.load_or_capture_pre_activation_probe(&operation_root, &request, &active)?;
            let consumption = self
                .promotion_authority
                .consume(&authorization.invocation(1), self.now_ms()?)?;
            maybe_crash(crash_at, ReceiverCrashPoint::PromotionAuthorizationConsumed)?;
            let observation_consumption = self
                .observation_authority
                .consume(&observation_authorization.invocation(1), self.now_ms()?)?;
            maybe_crash(
                crash_at,
                ReceiverCrashPoint::ObservationAuthorizationConsumed,
            )?;
            let rollback_consumption = self
                .rollback_authority
                .consume(&rollback_authorization.invocation(1), self.now_ms()?)?;
            maybe_crash(crash_at, ReceiverCrashPoint::RollbackAuthorizationConsumed)?;
            self.append_stage(
                &request,
                &coordinator_request_digest,
                TransactionStage::ActivationIntentRecorded,
                StageCause::ApprovalDecision,
                1,
                Some(self.promotion_authority.profile().profile_digest().clone()),
                Some(coordinator_request_digest.clone()),
                vec![
                    approval_request.request_digest().clone(),
                    decision.decision_digest().clone(),
                    plan.import_plan_digest().clone(),
                    consumption.receipt_digest().clone(),
                    authorization.binding_digest().clone(),
                    observation_consumption.receipt_digest().clone(),
                    observation_authorization.binding_digest().clone(),
                    rollback_consumption.receipt_digest().clone(),
                    rollback_authorization.binding_digest().clone(),
                ],
                None,
                None,
            )?;
            maybe_crash(crash_at, ReceiverCrashPoint::ActivationIntentRecorded)?;
            (consumption, observation_consumption, rollback_consumption)
        } else {
            // Once the effect intent exists, recovery may only resolve the
            // exact already-consumed authority facts. A missing fact is an
            // integrity failure; it must never be synthesized after intent.
            let pre_activation: ReceiverM5PreActivationProbeV1 = load_canonical_file(
                &operation_root.join(PRE_ACTIVATION_EXECUTION_FILE),
                MAX_RECORD_BYTES,
            )?;
            pre_activation.validate(
                &request.logical_operation_id,
                &active,
                self.m5.validation_suite(),
            )?;
            (
                self.promotion_authority
                    .load_consumption(promotion_authorization_digest, 1)?,
                self.observation_authority
                    .load_consumption(observation_authorization_digest, 1)?,
                self.rollback_authority
                    .load_consumption(rollback_authorization_digest, 1)?,
            )
        };

        let exact_cycle_plan = exact_m5_cycle_plan(
            &request,
            &decision,
            &proving,
            &plan,
            &consumption,
            &observation_consumption,
            &rollback_consumption,
            self.m5.release_gate().gate_digest.clone(),
        )?;
        let cycle_evidence = if operation_root.join(M5_CYCLE_FILE).exists() {
            let evidence: ReceiverM5CycleEvidence =
                load_canonical_file(&operation_root.join(M5_CYCLE_FILE), MAX_RECORD_BYTES)?;
            evidence.validate(
                &request,
                &decision,
                &consumption,
                &observation_consumption,
                &rollback_consumption,
                &plan,
            )?;
            let authoritative = self
                .m5
                .inspect_exact_candidate_cycle(&exact_cycle_plan)?
                .ok_or_else(|| {
                    M6ReceiverError::Integrity(
                        "retained receiver M5 evidence has no authoritative terminal cycle"
                            .to_string(),
                    )
                })?;
            evidence.validate_against_authoritative_recovery(
                &request,
                &decision,
                &consumption,
                &observation_consumption,
                &rollback_consumption,
                &plan,
                &authoritative,
            )?;
            evidence
        } else {
            let durable_stage = self
                .journal
                .transaction(logical_operation_id)?
                .and_then(|projection| projection.current_stage())
                .ok_or_else(|| {
                    M6ReceiverError::InvalidState(
                        "receiver transaction has no activation stage before M5".to_string(),
                    )
                })?;
            if durable_stage != TransactionStage::ActivationIntentRecorded {
                return Err(M6ReceiverError::Integrity(format!(
                    "missing M5 evidence at receiver stage {durable_stage:?}"
                )));
            }
            let result = self.m5.run_exact_candidate_cycle(exact_cycle_plan)?;
            let evidence = ReceiverM5CycleEvidence::from_result(
                &request,
                &decision,
                &consumption,
                &observation_consumption,
                &rollback_consumption,
                &plan,
                &result,
            )?;
            evidence.validate(
                &request,
                &decision,
                &consumption,
                &observation_consumption,
                &rollback_consumption,
                &plan,
            )?;
            persist_operation_record(
                &operation_root,
                M5_CYCLE_FILE,
                &canonical_json(&evidence)?,
                MAX_RECORD_BYTES,
            )?;
            evidence
        };
        maybe_crash(crash_at, ReceiverCrashPoint::M5CycleCommitted)?;

        if cycle_evidence.disposition == ReceiverM5Disposition::Healthy {
            self.load_or_capture_behavior_change(
                &operation_root,
                &request,
                &active,
                &plan,
                &cycle_evidence,
            )?;
        }

        if cycle_evidence.disposition == ReceiverM5Disposition::ValidationRejected {
            let rejection = self.record_validation_rejection(
                &request,
                &raw,
                true,
                "m5-terminal-validation",
                "ordinary M5 exact candidate cycle rejected before activation",
                vec![
                    cycle_evidence.cycle_record.record_digest.clone(),
                    cycle_evidence.effect_audit.report_digest.clone(),
                    cycle_evidence.active_snapshot.snapshot_digest.clone(),
                    cycle_evidence.evidence_digest.clone(),
                ],
            )?;
            self.append_validation_rejected(
                &request,
                &coordinator_request_digest,
                &rejection,
                None,
                crash_at,
            )?;
            self.persist_terminal_decision(
                &request,
                ReceiverTerminalKind::ValidationRejected,
                Some(approval_request.request_digest().clone()),
                Some(decision.decision_digest().clone()),
                cycle_evidence.evidence_digest.clone(),
            )?;
            return Ok(ReceiverAdoptionResult::ValidationRejected(rejection));
        }

        if let Some(activation) = &cycle_evidence.cycle_record.activation_receipt {
            self.append_stage(
                &request,
                &coordinator_request_digest,
                TransactionStage::ActivationEffectCommitted,
                StageCause::Normal,
                1,
                None,
                Some(coordinator_request_digest.clone()),
                vec![
                    activation.request_digest.clone(),
                    activation.receipt_digest.clone(),
                    cycle_evidence.effect_audit.report_digest.clone(),
                    cycle_evidence.evidence_digest.clone(),
                ],
                Some(activation.receipt_digest.clone()),
                Some(cycle_evidence.effect_audit.report_digest.clone()),
            )?;
            maybe_crash(crash_at, ReceiverCrashPoint::ActivationEffectCommitted)?;
        }
        if let Some(observation) = &cycle_evidence.cycle_record.observation_evidence {
            self.append_stage(
                &request,
                &coordinator_request_digest,
                TransactionStage::ObservationIntentRecorded,
                StageCause::Normal,
                1,
                Some(
                    self.observation_authority
                        .profile()
                        .profile_digest()
                        .clone(),
                ),
                None,
                vec![
                    observation.request_digest.clone(),
                    observation.evidence_digest.clone(),
                    cycle_evidence.effect_audit.report_digest.clone(),
                    observation_consumption.receipt_digest().clone(),
                    observation_authorization.binding_digest().clone(),
                ],
                None,
                None,
            )?;
            maybe_crash(crash_at, ReceiverCrashPoint::ObservationIntentRecorded)?;
        }

        let (terminal_stage, acknowledgement_disposition) = match cycle_evidence.disposition {
            ReceiverM5Disposition::Healthy => {
                let terminal_stage = self.append_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::Healthy,
                    StageCause::Normal,
                    1,
                    None,
                    None,
                    vec![
                        cycle_evidence.cycle_record.record_digest.clone(),
                        cycle_evidence.active_snapshot.snapshot_digest.clone(),
                        cycle_evidence.effect_audit.report_digest.clone(),
                        cycle_evidence.evidence_digest.clone(),
                    ],
                    None,
                    None,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::HealthyCommitted)?;
                (terminal_stage, "healthy")
            }
            ReceiverM5Disposition::RolledBack => {
                self.append_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::RollbackIntentRecorded,
                    StageCause::HealthRegression,
                    1,
                    Some(self.rollback_authority.profile().profile_digest().clone()),
                    Some(coordinator_request_digest.clone()),
                    vec![
                        cycle_evidence.cycle_record.record_digest.clone(),
                        cycle_evidence.effect_audit.report_digest.clone(),
                        cycle_evidence.evidence_digest.clone(),
                        rollback_consumption.receipt_digest().clone(),
                        rollback_authorization.binding_digest().clone(),
                    ],
                    None,
                    None,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::RollbackIntentRecorded)?;
                let rollback_receipt = cycle_evidence
                    .cycle_record
                    .recovery_receipt
                    .as_ref()
                    .map(|receipt| receipt.receipt_digest.clone())
                    .ok_or_else(|| {
                        M6ReceiverError::Integrity(
                            "rolled-back M5 result has no recovery receipt".to_string(),
                        )
                    })?;
                let terminal_stage = self.append_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::RolledBack,
                    StageCause::HealthRegression,
                    1,
                    None,
                    Some(coordinator_request_digest.clone()),
                    vec![
                        rollback_receipt.clone(),
                        cycle_evidence.active_snapshot.snapshot_digest.clone(),
                        cycle_evidence.effect_audit.report_digest.clone(),
                        cycle_evidence.evidence_digest.clone(),
                        rollback_consumption.receipt_digest().clone(),
                    ],
                    Some(rollback_receipt),
                    Some(cycle_evidence.effect_audit.report_digest.clone()),
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::RolledBackCommitted)?;
                (terminal_stage, "rolled_back")
            }
            ReceiverM5Disposition::ValidationRejected => unreachable!(),
        };

        let receipt = ReceiverAdoptionReceipt::new(
            &request,
            coordinator_request_digest.clone(),
            &decision,
            &consumption,
            &observation_consumption,
            &rollback_consumption,
            &plan,
            &cycle_evidence,
            self.now_ms()?,
        )?;
        persist_operation_record(
            &operation_root,
            ADOPTION_RECEIPT_FILE,
            &canonical_json(&receipt)?,
            MAX_RECORD_BYTES,
        )?;
        maybe_crash(crash_at, ReceiverCrashPoint::AdoptionReceiptCommitted)?;
        let durable: ReceiverAdoptionReceipt = load_canonical_file(
            &operation_root.join(ADOPTION_RECEIPT_FILE),
            MAX_RECORD_BYTES,
        )?;
        durable.validate(
            &request,
            &coordinator_request_digest,
            &decision,
            &consumption,
            &observation_consumption,
            &rollback_consumption,
            &plan,
            &cycle_evidence,
        )?;
        self.publish_acknowledgement(
            &request,
            acknowledgement_disposition,
            raw.raw_unit_digest.clone(),
            &terminal_stage,
            crash_at,
        )?;
        Ok(ReceiverAdoptionResult::Adopted(durable))
    }

    pub fn execute_active(
        &self,
        input: i32,
    ) -> Result<crate::m5_runtime::M5ActiveExecution, M6ReceiverError> {
        self.m5.execute_active(input).map_err(M6ReceiverError::from)
    }

    pub fn induce_next_health_regression(&self) -> Result<(), M6ReceiverError> {
        self.m5
            .induce_next_health_regression()
            .map_err(M6ReceiverError::from)
    }
}

impl<V: OpaqueAuthorizationVerifier> M6ReceiverRuntime<V> {
    pub fn prove_and_plan(
        &mut self,
        logical_operation_id: &str,
        proving_authorization_digest: &ContentDigest,
    ) -> Result<ReceiverProvingResult, M6ReceiverError> {
        self.prove_and_plan_with_fault(logical_operation_id, proving_authorization_digest, None)
    }

    pub fn prove_and_plan_with_fault(
        &mut self,
        logical_operation_id: &str,
        proving_authorization_digest: &ContentDigest,
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<ReceiverProvingResult, M6ReceiverError> {
        validate_identifier("receiver intake operation id", logical_operation_id)?;
        self.require_no_other_pending_operation(logical_operation_id)?;
        let operation_root = operation_root(&self.operations_root, logical_operation_id);
        let (request, active) =
            load_request_unit(&operation_root, self.route(), &self.import_policy)?;
        let (raw, verified, compatibility) =
            self.load_verified_context(&operation_root, &active)?;
        let coordinator_request_digest = self.coordinator_request_digest(logical_operation_id)?;

        let expected_binding = proving_binding(
            &request,
            &verified,
            &compatibility,
            self.m5.validation_suite(),
        )?;
        let authorization = self
            .proving_authority
            .load_authorization(proving_authorization_digest)?;
        require_exact_authorization(
            &authorization,
            AuthorityAction::ProveImport,
            &expected_binding,
        )?;
        let consumption = self
            .proving_authority
            .consume(&authorization.invocation(1), self.now_ms()?)?;
        maybe_crash(crash_at, ReceiverCrashPoint::ProvingAuthorizationConsumed)?;

        // This is the only call below the ProveImport boundary that may
        // instantiate quarantined Wasm.
        let proving = prove_quarantined_import(
            &verified,
            &active,
            &self.import_policy,
            &compatibility,
            self.m5.validation_suite(),
        )?;
        persist_operation_record(
            &operation_root,
            PROVING_FILE,
            &proving.canonical_bytes(
                &verified,
                &active,
                &self.import_policy,
                &compatibility,
                self.m5.validation_suite(),
            )?,
            MAX_RECORD_BYTES,
        )?;
        maybe_crash(crash_at, ReceiverCrashPoint::ProvingRecordCommitted)?;
        self.append_stage(
            &request,
            &coordinator_request_digest,
            TransactionStage::ReceiverProvingCommitted,
            StageCause::Normal,
            0,
            None,
            None,
            vec![
                proving.report_digest().clone(),
                proving.proving_record().record_digest.clone(),
                consumption.receipt_digest().clone(),
                authorization.binding_digest().clone(),
            ],
            None,
            None,
        )?;
        maybe_crash(crash_at, ReceiverCrashPoint::ReceiverProvingCommitted)?;

        if !proving.accepted() {
            let rejection = self.record_validation_rejection(
                &request,
                &raw,
                true,
                "receiver-proving",
                "receiver-local proving suite rejected the quarantined component",
                vec![
                    verified.verification_digest().clone(),
                    compatibility.decision_digest().clone(),
                    proving.report_digest().clone(),
                    consumption.receipt_digest().clone(),
                ],
            )?;
            self.append_validation_rejected(
                &request,
                &coordinator_request_digest,
                &rejection,
                None,
                crash_at,
            )?;
            return Ok(ReceiverProvingResult::ValidationRejected(rejection));
        }

        let plan = derive_receiver_import_plan(
            &verified,
            &active,
            &self.import_policy,
            &compatibility,
            &proving,
            self.m5.validation_suite(),
        )?;
        persist_operation_record(
            &operation_root,
            IMPORT_PLAN_FILE,
            &plan.canonical_bytes(
                &verified,
                &active,
                &self.import_policy,
                &compatibility,
                &proving,
                self.m5.validation_suite(),
            )?,
            MAX_RECORD_BYTES,
        )?;
        maybe_crash(crash_at, ReceiverCrashPoint::ImportPlanCommitted)?;
        let revocation_binding =
            exchange_revocation_binding(self.route(), &request, &verified, &plan);
        let matching_tombstones = self.revocations.matching_tombstones(&revocation_binding)?;
        if !matching_tombstones.is_empty() {
            // A tombstone may legitimately predate this import. Do not invent
            // receiver-local plan identities while the package is still raw:
            // the first exact check runs immediately after the real plan is
            // durable and before approval publication or effect authority.
            let mut resolution_digests = Vec::with_capacity(matching_tombstones.len());
            for tombstone in &matching_tombstones {
                let affected = self.revocations.record_affected_import(
                    &tombstone.tombstone_digest,
                    revocation_binding.clone(),
                    ReceiverImportDispositionV1::Quarantined,
                )?;
                let resolution = self.revocations.resolve_containment(
                    &affected.affected_digest,
                    RevocationContainmentOutcomeV1::RejectedBeforeApproval,
                    vec![
                        tombstone.tombstone_digest.clone(),
                        plan.import_plan_digest().clone(),
                        proving.report_digest().clone(),
                    ],
                )?;
                resolution_digests.push(resolution.resolution_digest);
            }
            resolution_digests.sort();
            resolution_digests.dedup();
            let revocation_evidence_digest =
                ContentDigest::from_bytes(&canonical_json(&resolution_digests)?);
            let rejection = self.record_validation_rejection(
                &request,
                &raw,
                true,
                "revocation-before-approval",
                "an authenticated sender tombstone matched the exact newly persisted import plan",
                vec![
                    plan.import_plan_digest().clone(),
                    proving.report_digest().clone(),
                    revocation_evidence_digest.clone(),
                ],
            )?;
            let coordinator_request_digest =
                self.coordinator_request_digest(logical_operation_id)?;
            let terminal = self.append_stage(
                &request,
                &coordinator_request_digest,
                TransactionStage::ValidationRejected,
                StageCause::PolicyRejection,
                0,
                None,
                None,
                vec![
                    rejection.record_digest.clone(),
                    plan.import_plan_digest().clone(),
                    revocation_evidence_digest.clone(),
                ],
                None,
                None,
            )?;
            self.persist_terminal_decision(
                &request,
                ReceiverTerminalKind::ValidationRejected,
                None,
                None,
                revocation_evidence_digest,
            )?;
            self.publish_acknowledgement(
                &request,
                "validation_rejected",
                raw.raw_unit_digest.clone(),
                &terminal,
                crash_at,
            )?;
            return Ok(ReceiverProvingResult::ValidationRejected(rejection));
        }
        let approval_request = self.approval_request(
            &request,
            &active,
            &verified,
            &compatibility,
            &proving,
            &plan,
        )?;
        let approval_request = self
            .approval_authority
            .publish_approval_request(approval_request)?;
        maybe_crash(crash_at, ReceiverCrashPoint::ApprovalRequestCommitted)?;
        self.append_stage(
            &request,
            &coordinator_request_digest,
            TransactionStage::AwaitingApproval,
            StageCause::Normal,
            0,
            Some(self.approval_authority.profile().profile_digest().clone()),
            None,
            vec![
                approval_request.request_digest().clone(),
                plan.import_plan_digest().clone(),
                proving.report_digest().clone(),
                consumption.receipt_digest().clone(),
            ],
            None,
            None,
        )?;
        maybe_crash(crash_at, ReceiverCrashPoint::AwaitingApproval)?;
        Ok(ReceiverProvingResult::AwaitingApproval(
            PreparedReceiverApproval {
                logical_operation_id: request.logical_operation_id,
                import_plan_digest: plan.import_plan_digest().clone(),
                receiver_local_package_digest: plan.receiver_local_package_digest().clone(),
                approval_request,
            },
        ))
    }

    pub fn prepare_approval_decision(
        &self,
        logical_operation_id: &str,
        kind: ApprovalDecisionKind,
        principal_id: impl Into<String>,
        rationale: impl Into<String>,
    ) -> Result<PreparedReceiverDecision, M6ReceiverError> {
        validate_identifier("receiver intake operation id", logical_operation_id)?;
        let operation_root = operation_root(&self.operations_root, logical_operation_id);
        let (request, active) =
            load_request_unit(&operation_root, self.route(), &self.import_policy)?;
        let (_, verified, compatibility, proving, plan) =
            self.load_planned_context(&operation_root, &active)?;
        let approval_request = self.approval_request(
            &request,
            &active,
            &verified,
            &compatibility,
            &proving,
            &plan,
        )?;
        let durable = self
            .approval_authority
            .load_approval_request(approval_request.request_digest())?;
        if durable != approval_request {
            return Err(M6ReceiverError::Integrity(
                "durable approval request differs from the exact import plan".to_string(),
            ));
        }
        let intent = ApprovalDecisionIntent::new(
            kind,
            principal_id,
            rationale,
            format!(
                "receiver-decision:{}:{}",
                logical_operation_id,
                approval_kind_label(kind)
            ),
        )?;
        let authorization_binding = durable.decision_authorization_binding(&intent)?;
        Ok(PreparedReceiverDecision {
            logical_operation_id: logical_operation_id.to_string(),
            approval_request_digest: durable.request_digest().clone(),
            decision_intent: intent,
            authorization_binding,
        })
    }

    pub fn decide_approval(
        &mut self,
        logical_operation_id: &str,
        approval_authorization_digest: &ContentDigest,
        intent: ApprovalDecisionIntent,
    ) -> Result<ReceiverApprovalResult, M6ReceiverError> {
        self.decide_approval_with_fault(
            logical_operation_id,
            approval_authorization_digest,
            intent,
            None,
        )
    }

    pub fn decide_approval_with_fault(
        &mut self,
        logical_operation_id: &str,
        approval_authorization_digest: &ContentDigest,
        intent: ApprovalDecisionIntent,
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<ReceiverApprovalResult, M6ReceiverError> {
        validate_identifier("receiver intake operation id", logical_operation_id)?;
        self.require_no_other_pending_operation(logical_operation_id)?;
        let operation_root = operation_root(&self.operations_root, logical_operation_id);
        let (request, active) =
            load_request_unit(&operation_root, self.route(), &self.import_policy)?;
        let (raw, verified, compatibility, proving, plan) =
            self.load_planned_context(&operation_root, &active)?;
        let approval_request = self.approval_request(
            &request,
            &active,
            &verified,
            &compatibility,
            &proving,
            &plan,
        )?;
        let decision = self.approval_authority.record_approval_decision(
            approval_request.request_digest(),
            approval_authorization_digest,
            intent,
            self.now_ms()?,
        )?;
        maybe_crash(crash_at, ReceiverCrashPoint::ApprovalDecisionCommitted)?;

        if decision.kind() == ApprovalDecisionKind::Granted {
            return Ok(ReceiverApprovalResult::ReadyForPromotion(
                PreparedReceiverPromotion {
                    logical_operation_id: request.logical_operation_id.clone(),
                    approval_decision_digest: decision.decision_digest().clone(),
                    import_plan_digest: plan.import_plan_digest().clone(),
                    receiver_local_package_digest: plan.receiver_local_package_digest().clone(),
                    authorization_binding: promotion_binding(&request, &decision, &proving, &plan)?,
                    observation_authorization_binding: observation_binding(
                        &request, &decision, &proving, &plan,
                    )?,
                    rollback_authorization_binding: rollback_binding(
                        &request, &decision, &proving, &plan,
                    )?,
                },
            ));
        }

        let (stage, cause, kind) = match decision.kind() {
            ApprovalDecisionKind::Denied => (
                TransactionStage::Denied,
                StageCause::ApprovalDecision,
                ReceiverTerminalKind::Denied,
            ),
            ApprovalDecisionKind::Expired => (
                TransactionStage::Expired,
                StageCause::Expiry,
                ReceiverTerminalKind::Expired,
            ),
            ApprovalDecisionKind::Escalated => (
                TransactionStage::Escalated,
                StageCause::ApprovalDecision,
                ReceiverTerminalKind::Escalated,
            ),
            ApprovalDecisionKind::Granted => unreachable!(),
        };
        let coordinator_request_digest = self.coordinator_request_digest(logical_operation_id)?;
        let terminal_stage = self.append_stage(
            &request,
            &coordinator_request_digest,
            stage,
            cause,
            0,
            Some(self.approval_authority.profile().profile_digest().clone()),
            None,
            vec![
                approval_request.request_digest().clone(),
                decision.decision_digest().clone(),
                decision.authorization_digest().clone(),
                plan.import_plan_digest().clone(),
            ],
            None,
            None,
        )?;
        let terminal = self.persist_terminal_decision(
            &request,
            kind,
            Some(approval_request.request_digest().clone()),
            Some(decision.decision_digest().clone()),
            decision.decision_digest().clone(),
        )?;
        maybe_crash(crash_at, ReceiverCrashPoint::ApprovalTerminalCommitted)?;
        self.publish_acknowledgement(
            &request,
            approval_kind_label(decision.kind()),
            raw.raw_unit_digest,
            &terminal_stage,
            crash_at,
        )?;
        Ok(ReceiverApprovalResult::Terminal(terminal))
    }

    fn load_verified_context(
        &self,
        operation_root: &Path,
        active: &ReceiverActiveStateV1,
    ) -> Result<
        (
            RawQuarantineRecord,
            VerifiedQuarantinedExportV1,
            ReceiverCompatibilityDecisionV1,
        ),
        M6ReceiverError,
    > {
        let raw: RawQuarantineRecord =
            load_canonical_file(&operation_root.join(RAW_RECORD_FILE), MAX_RECORD_BYTES)?;
        self.quarantine.read_committed_unit(&raw)?;
        let verified = VerifiedQuarantinedExportV1::from_canonical_bytes(
            &read_regular_bounded(&operation_root.join(VERIFIED_EXPORT_FILE), MAX_RECORD_BYTES)?,
            self.route(),
            &self.import_policy,
        )?;
        let compatibility = ReceiverCompatibilityDecisionV1::from_canonical_bytes(
            &read_regular_bounded(&operation_root.join(COMPATIBILITY_FILE), MAX_RECORD_BYTES)?,
            &verified,
            active,
            &self.import_policy,
        )?;
        Ok((raw, verified, compatibility))
    }

    #[allow(clippy::type_complexity)]
    fn load_planned_context(
        &self,
        operation_root: &Path,
        active: &ReceiverActiveStateV1,
    ) -> Result<
        (
            RawQuarantineRecord,
            VerifiedQuarantinedExportV1,
            ReceiverCompatibilityDecisionV1,
            ReceiverProvingReportV1,
            ReceiverImportPlanV1,
        ),
        M6ReceiverError,
    > {
        let (raw, verified, compatibility) = self.load_verified_context(operation_root, active)?;
        let proving = ReceiverProvingReportV1::from_canonical_bytes(
            &read_regular_bounded(&operation_root.join(PROVING_FILE), MAX_RECORD_BYTES)?,
            &verified,
            active,
            &self.import_policy,
            &compatibility,
            self.m5.validation_suite(),
        )?;
        let plan = ReceiverImportPlanV1::from_canonical_bytes(
            &read_regular_bounded(&operation_root.join(IMPORT_PLAN_FILE), MAX_RECORD_BYTES)?,
            &verified,
            active,
            &self.import_policy,
            &compatibility,
            &proving,
            self.m5.validation_suite(),
        )?;
        Ok((raw, verified, compatibility, proving, plan))
    }

    fn approval_request(
        &self,
        request: &ReceiverIntakeRequest,
        active: &ReceiverActiveStateV1,
        verified: &VerifiedQuarantinedExportV1,
        compatibility: &ReceiverCompatibilityDecisionV1,
        proving: &ReceiverProvingReportV1,
        plan: &ReceiverImportPlanV1,
    ) -> Result<ApprovalRequest, M6ReceiverError> {
        let local = FactoryPackage::from_canonical_bytes(plan.receiver_local_package_bytes())
            .map_err(|error| M6ReceiverError::Import(error.to_string()))?;
        let unresolved_risks_digest = digest_domain(
            UNRESOLVED_RISKS_DOMAIN,
            &(
                compatibility.issues(),
                compatibility.migration_required(),
                proving.accepted(),
                proving.report_digest(),
            ),
        )?;
        ApprovalRequest::new(ApprovalRequestDraft {
            request_id: format!("receiver-approval:{}", request.logical_operation_id),
            factory_id: self.route().receiver.factory_id.clone(),
            requester_principal_id: request.principal_id.clone(),
            route_id: request.route_id.clone(),
            route_generation: request.route_generation,
            message_digest: request.message_digest.clone(),
            exchange_digest: request.exchange_digest.clone(),
            raw_quarantine_digest: verified.raw_quarantine_digest().clone(),
            authenticated_source_identity_digest: verified
                .source_identity_document_digest()
                .clone(),
            source_package_digest: verified.source_package_digest().clone(),
            receiver_package_digest: plan.receiver_local_package_digest().clone(),
            source_component_digest: verified.source_component_digest().clone(),
            receiver_component_digest: local.payload.genome.component_digest,
            m5_export_bundle_digest: verified.export_bundle_digest().clone(),
            compatibility_decision_digest: compatibility.decision_digest().clone(),
            expected_active_snapshot_digest: active.snapshot().snapshot_digest.clone(),
            rollback_target_digest: plan.rollback_target_digest().clone(),
            import_plan_digest: plan.import_plan_digest().clone(),
            migration_plan_digest: ContentDigest::from_bytes(NO_MIGRATION),
            policy_digest: self.import_policy.policy_digest().clone(),
            proving_digest: proving.report_digest().clone(),
            unresolved_risks_digest,
            requested_at_ms: request.captured_at_ms,
            deadline_ms: request.deadline_ms,
            idempotency_key: format!("receiver-approval:{}", request.logical_operation_id),
        })
        .map_err(M6ReceiverError::from)
    }

    fn persist_terminal_decision(
        &self,
        request: &ReceiverIntakeRequest,
        kind: ReceiverTerminalKind,
        approval_request_digest: Option<ContentDigest>,
        approval_decision_digest: Option<ContentDigest>,
        evidence_digest: ContentDigest,
    ) -> Result<ReceiverTerminalDecision, M6ReceiverError> {
        let path = operation_root(&self.operations_root, &request.logical_operation_id)
            .join(TERMINAL_DECISION_FILE);
        if path.exists() {
            let record: ReceiverTerminalDecision = load_canonical_file(&path, MAX_RECORD_BYTES)?;
            record.validate(request)?;
            if record.kind != kind
                || record.approval_request_digest != approval_request_digest
                || record.approval_decision_digest != approval_decision_digest
                || record.evidence_digest != evidence_digest
            {
                return Err(M6ReceiverError::Conflict {
                    identity: request.logical_operation_id.clone(),
                    existing: record.record_digest,
                    requested: evidence_digest,
                });
            }
            return Ok(record);
        }
        let record = ReceiverTerminalDecision::new(
            request,
            kind,
            approval_request_digest,
            approval_decision_digest,
            evidence_digest,
            self.now_ms()?,
        )?;
        persist_immutable_file(&path, &canonical_json(&record)?)?;
        Ok(record)
    }
}

impl<V: OpaqueAuthorizationVerifier> M6ReceiverRuntime<V> {
    pub fn admit_and_authenticate(
        &mut self,
        logical_operation_id: &str,
        intake_authorization_digest: &ContentDigest,
    ) -> Result<ReceiverAdmissionResult, M6ReceiverError> {
        self.admit_and_authenticate_with_fault(
            logical_operation_id,
            intake_authorization_digest,
            None,
        )
    }

    pub fn admit_and_authenticate_with_fault(
        &mut self,
        logical_operation_id: &str,
        intake_authorization_digest: &ContentDigest,
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<ReceiverAdmissionResult, M6ReceiverError> {
        validate_identifier("receiver intake operation id", logical_operation_id)?;
        self.require_no_other_pending_operation(logical_operation_id)?;
        let operation_root = operation_root(&self.operations_root, logical_operation_id);
        let (request, active) =
            load_request_unit(&operation_root, self.route(), &self.import_policy)?;
        let coordinator_request_digest = self.coordinator_request_digest(logical_operation_id)?;

        let expected_binding = intake_binding(&request);
        let authorization = self
            .intake_authority
            .load_authorization(intake_authorization_digest)?;
        require_exact_authorization(
            &authorization,
            AuthorityAction::IntakePackage,
            &expected_binding,
        )?;
        let consumption = self
            .intake_authority
            .consume(&authorization.invocation(1), self.now_ms()?)?;
        maybe_crash(crash_at, ReceiverCrashPoint::IntakeAuthorizationConsumed)?;
        if let Some(rejection) = self.reject_cross_operation_message_claim(
            ReceiverInboundTransactionKindV1::Import,
            &request.logical_operation_id,
            &request.request_digest,
            &request.message_digest,
        )? {
            let terminal = self.append_stage(
                &request,
                &coordinator_request_digest,
                TransactionStage::ValidationRejected,
                StageCause::ValidationRejection,
                0,
                None,
                None,
                vec![
                    rejection.record_digest.clone(),
                    rejection.raw_evidence_digest.clone(),
                    consumption.receipt_digest().clone(),
                    authorization.authorization_digest().clone(),
                ],
                None,
                None,
            )?;
            self.persist_terminal_decision(
                &request,
                ReceiverTerminalKind::ValidationRejected,
                None,
                None,
                rejection.record_digest.clone(),
            )?;
            self.publish_acknowledgement(
                &request,
                "validation_rejected",
                rejection.record_digest.clone(),
                &terminal,
                crash_at,
            )?;
            return Err(M6ReceiverError::ControlRejected {
                class: rejection.class,
                record_digest: rejection.record_digest,
            });
        }

        // The exact Intake authorization is durably consumed before the
        // receiver role is acquired or a byte in the inbound ready unit is
        // observed.
        let admission = if let Some(record) =
            self.quarantine.committed_for_intake(logical_operation_id)?
        {
            RawAdmissionOutcome::Quarantined(record)
        } else if let Some(rejected) = self.quarantine.admission_rejection(logical_operation_id)? {
            RawAdmissionOutcome::Rejected(rejected)
        } else {
            let owner = self.spool.acquire_role()?;
            self.quarantine.admit_ready(
                &self.spool,
                &owner,
                &request.message_digest,
                logical_operation_id,
            )?
        };

        match admission {
            RawAdmissionOutcome::Rejected(rejected) => {
                let replay_state = self.replay.control_state();
                self.persist_control_rejection(
                    ReceiverControlRejectionClassV1::RawAdmission,
                    &request.logical_operation_id,
                    &request.request_digest,
                    &request.message_digest,
                    &rejected.record_digest,
                    None,
                    Some(canonical_json(&rejected)?),
                    None,
                    replay_state.clone(),
                    replay_state,
                    "raw route unit failed the hard pre-interpretation admission boundary",
                )?;
                let terminal_stage = self.append_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::RawAdmissionRejected,
                    StageCause::ValidationRejection,
                    0,
                    None,
                    None,
                    vec![
                        rejected.record_digest.clone(),
                        consumption.receipt_digest().clone(),
                        authorization.authorization_digest().clone(),
                    ],
                    None,
                    None,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::RawAdmissionCommitted)?;
                self.publish_acknowledgement(
                    &request,
                    "raw_admission_rejected",
                    rejected.record_digest.clone(),
                    &terminal_stage,
                    crash_at,
                )?;
                return Ok(ReceiverAdmissionResult::RawAdmissionRejected(rejected));
            }
            RawAdmissionOutcome::Quarantined(raw) => {
                persist_operation_record(
                    &operation_root,
                    RAW_RECORD_FILE,
                    &canonical_json(&raw)?,
                    MAX_RECORD_BYTES,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::RawAdmissionCommitted)?;
                self.append_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::RawQuarantined,
                    StageCause::Normal,
                    0,
                    None,
                    None,
                    vec![
                        raw.raw_unit_digest.clone(),
                        raw.record_digest.clone(),
                        consumption.receipt_digest().clone(),
                    ],
                    None,
                    None,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::RawQuarantinedStage)?;

                let raw_unit = self.quarantine.read_committed_unit(&raw)?;
                let attempted_manifest_bytes = raw_unit
                    .files()
                    .get("manifest.json")
                    .cloned()
                    .ok_or_else(|| {
                        M6ReceiverError::Integrity(
                            "committed raw intake lacks exact manifest bytes".to_string(),
                        )
                    })?;
                let manifest = match self.quarantine.parse_quarantined_manifest(&raw) {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        let replay_state = self.replay.control_state();
                        self.persist_control_rejection(
                            ReceiverControlRejectionClassV1::CanonicalManifest,
                            &request.logical_operation_id,
                            &request.request_digest,
                            &request.message_digest,
                            &raw.raw_unit_digest,
                            Some(attempted_manifest_bytes.clone()),
                            None,
                            None,
                            replay_state.clone(),
                            replay_state,
                            &error.to_string(),
                        )?;
                        let rejection = self.record_validation_rejection(
                            &request,
                            &raw,
                            false,
                            "canonical-manifest",
                            error.to_string(),
                            vec![
                                raw.record_digest.clone(),
                                consumption.receipt_digest().clone(),
                            ],
                        )?;
                        self.append_validation_rejected(
                            &request,
                            &coordinator_request_digest,
                            &rejection,
                            None,
                            crash_at,
                        )?;
                        return Ok(ReceiverAdmissionResult::ValidationRejected(rejection));
                    }
                };
                if manifest.message_digest != request.message_digest {
                    let replay_state = self.replay.control_state();
                    self.persist_control_rejection(
                        ReceiverControlRejectionClassV1::MessageIdentity,
                        &request.logical_operation_id,
                        &request.request_digest,
                        &request.message_digest,
                        &raw.raw_unit_digest,
                        Some(attempted_manifest_bytes.clone()),
                        None,
                        None,
                        replay_state.clone(),
                        replay_state,
                        "canonical manifest differs from the exact intake message identity",
                    )?;
                    let rejection = self.record_validation_rejection(
                        &request,
                        &raw,
                        false,
                        "message-identity",
                        "canonical manifest differs from the exact intake message digest",
                        vec![
                            raw.record_digest.clone(),
                            manifest.message_digest.clone(),
                            consumption.receipt_digest().clone(),
                        ],
                    )?;
                    self.append_validation_rejected(
                        &request,
                        &coordinator_request_digest,
                        &rejection,
                        None,
                        crash_at,
                    )?;
                    return Ok(ReceiverAdmissionResult::ValidationRejected(rejection));
                }
                if let Err(error) = manifest.verify_route(self.route()) {
                    let replay_state = self.replay.control_state();
                    self.persist_control_rejection(
                        ReceiverControlRejectionClassV1::RouteAuthentication,
                        &request.logical_operation_id,
                        &request.request_digest,
                        &request.message_digest,
                        &raw.raw_unit_digest,
                        Some(attempted_manifest_bytes.clone()),
                        None,
                        None,
                        replay_state.clone(),
                        replay_state,
                        &error.to_string(),
                    )?;
                    let rejection = self.record_validation_rejection(
                        &request,
                        &raw,
                        false,
                        "route-authentication",
                        error.to_string(),
                        vec![
                            raw.record_digest.clone(),
                            manifest.message_digest.clone(),
                            consumption.receipt_digest().clone(),
                        ],
                    )?;
                    self.append_validation_rejected(
                        &request,
                        &coordinator_request_digest,
                        &rejection,
                        None,
                        crash_at,
                    )?;
                    return Ok(ReceiverAdmissionResult::ValidationRejected(rejection));
                }
                self.append_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::SenderAuthenticated,
                    StageCause::Normal,
                    0,
                    Some(self.intake_authority.profile().profile_digest().clone()),
                    None,
                    vec![
                        manifest.message_digest.clone(),
                        raw.record_digest.clone(),
                        consumption.receipt_digest().clone(),
                        authorization.binding_digest().clone(),
                    ],
                    None,
                    None,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::SenderAuthenticated)?;

                let now_ms = self.now_ms()?;
                if now_ms > manifest.unsigned.expires_at_ms {
                    let rejection = self.record_validation_rejection(
                        &request,
                        &raw,
                        true,
                        "message-expired",
                        "authenticated sender message expired before replay admission",
                        vec![
                            raw.record_digest.clone(),
                            manifest.message_digest.clone(),
                            consumption.receipt_digest().clone(),
                        ],
                    )?;
                    let negative = self.record_terminal_negative_claimed(
                        ReceiverInboundTransactionKindV1::Import,
                        &request.logical_operation_id,
                        &request.request_digest,
                        &raw.raw_unit_digest,
                        &manifest,
                        TerminalNegativeDisposition::Expired,
                        TerminalNegativeReason::Expired,
                        rejection.record_digest.clone(),
                    )?;
                    self.append_validation_rejected(
                        &request,
                        &coordinator_request_digest,
                        &rejection,
                        Some(&negative),
                        crash_at,
                    )?;
                    return Ok(ReceiverAdmissionResult::ValidationRejected(rejection));
                }

                let verified =
                    match verify_quarantined_export(self.route(), &self.import_policy, &raw_unit) {
                        Ok(verified) => verified,
                        Err(error) => {
                            let rejection = self.record_validation_rejection(
                                &request,
                                &raw,
                                true,
                                "export-closure",
                                error.to_string(),
                                vec![
                                    raw.record_digest.clone(),
                                    manifest.message_digest.clone(),
                                    consumption.receipt_digest().clone(),
                                ],
                            )?;
                            let negative = self.record_terminal_negative_claimed(
                                ReceiverInboundTransactionKindV1::Import,
                                &request.logical_operation_id,
                                &request.request_digest,
                                &raw.raw_unit_digest,
                                &manifest,
                                TerminalNegativeDisposition::PolicyRejected,
                                TerminalNegativeReason::PolicyRejected {
                                    policy_rule: "receiver-export-closure".to_string(),
                                },
                                rejection.record_digest.clone(),
                            )?;
                            self.append_validation_rejected(
                                &request,
                                &coordinator_request_digest,
                                &rejection,
                                Some(&negative),
                                crash_at,
                            )?;
                            return Ok(ReceiverAdmissionResult::ValidationRejected(rejection));
                        }
                    };
                let compatibility =
                    assess_receiver_compatibility(&verified, &active, &self.import_policy)?;
                let verified_bytes = verified.canonical_bytes(self.route(), &self.import_policy)?;
                persist_operation_record(
                    &operation_root,
                    VERIFIED_EXPORT_FILE,
                    &verified_bytes,
                    MAX_RECORD_BYTES,
                )?;
                persist_operation_record(
                    &operation_root,
                    COMPATIBILITY_FILE,
                    &compatibility.canonical_bytes(&verified, &active, &self.import_policy)?,
                    MAX_RECORD_BYTES,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::SenderEvidenceRecordsCommitted)?;

                if !compatibility.compatible() {
                    let rejection = self.record_validation_rejection(
                        &request,
                        &raw,
                        true,
                        "receiver-compatibility",
                        format!(
                            "receiver compatibility rejected issues {:?}",
                            compatibility.issues()
                        ),
                        vec![
                            raw.record_digest.clone(),
                            verified.verification_digest().clone(),
                            compatibility.decision_digest().clone(),
                        ],
                    )?;
                    let negative = self.record_terminal_negative_claimed(
                        ReceiverInboundTransactionKindV1::Import,
                        &request.logical_operation_id,
                        &request.request_digest,
                        &raw.raw_unit_digest,
                        &manifest,
                        TerminalNegativeDisposition::PolicyRejected,
                        TerminalNegativeReason::PolicyRejected {
                            policy_rule: "receiver-compatibility".to_string(),
                        },
                        rejection.record_digest.clone(),
                    )?;
                    self.append_validation_rejected(
                        &request,
                        &coordinator_request_digest,
                        &rejection,
                        Some(&negative),
                        crash_at,
                    )?;
                    return Ok(ReceiverAdmissionResult::ValidationRejected(rejection));
                }

                let replay_fact = self.commit_or_resolve_replay(
                    ReceiverInboundTransactionKindV1::Import,
                    &request.logical_operation_id,
                    &request.request_digest,
                    &raw.raw_unit_digest,
                    &manifest,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::ReplayCommitted)?;
                let replay_digest = replay_fact_digest(&replay_fact)?;
                self.append_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::ReplayAndSequenceCommitted,
                    StageCause::Normal,
                    0,
                    None,
                    None,
                    vec![
                        replay_digest,
                        replay_fact.message_digest.clone(),
                        raw.record_digest.clone(),
                    ],
                    None,
                    None,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::ReplayStageCommitted)?;
                self.append_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::SenderEvidenceVerified,
                    StageCause::Normal,
                    0,
                    Some(self.intake_authority.profile().profile_digest().clone()),
                    None,
                    vec![
                        verified.verification_digest().clone(),
                        compatibility.decision_digest().clone(),
                        raw.record_digest.clone(),
                        consumption.receipt_digest().clone(),
                    ],
                    None,
                    None,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::SenderEvidenceVerified)?;
                Ok(ReceiverAdmissionResult::AwaitingProving(
                    PreparedReceiverProving {
                        logical_operation_id: request.logical_operation_id.clone(),
                        message_digest: request.message_digest.clone(),
                        verified_export_digest: verified.verification_digest().clone(),
                        compatibility_decision_digest: compatibility.decision_digest().clone(),
                        source_package_digest: verified.source_package_digest().clone(),
                        authorization_binding: proving_binding(
                            &request,
                            &verified,
                            &compatibility,
                            self.m5.validation_suite(),
                        )?,
                    },
                ))
            }
        }
    }

    fn authenticated_message_claim(
        &self,
        transaction_kind: ReceiverInboundTransactionKindV1,
        logical_operation_id: &str,
        outer_request_digest: &ContentDigest,
        raw_quarantine_digest: &ContentDigest,
        manifest: &SignedManifest,
    ) -> Result<ReceiverAuthenticatedMessageClaimV1, M6ReceiverError> {
        let path = self
            .message_claims_root
            .join(format!("{}.json", manifest.message_digest.file_stem()));
        if path.exists() {
            let existing: ReceiverAuthenticatedMessageClaimV1 =
                load_canonical_file(&path, MAX_RECORD_BYTES)?;
            existing.validate(self.route())?;
            if existing.transaction_kind == transaction_kind
                && existing.logical_operation_id == logical_operation_id
                && &existing.outer_request_digest == outer_request_digest
                && existing.message_digest == manifest.message_digest
                && &existing.raw_quarantine_digest == raw_quarantine_digest
            {
                return Ok(existing);
            }
            let state = self.replay.control_state();
            let rejection = self.persist_control_rejection(
                ReceiverControlRejectionClassV1::MessageReplay,
                logical_operation_id,
                outer_request_digest,
                &manifest.message_digest,
                raw_quarantine_digest,
                Some(manifest.canonical_bytes()?),
                None,
                Some(existing.canonical_bytes(self.route())?),
                state.clone(),
                state,
                "authenticated signed message is already claimed by another receiver operation",
            )?;
            return Err(M6ReceiverError::ControlRejected {
                class: rejection.class,
                record_digest: rejection.record_digest,
            });
        }
        let claim = ReceiverAuthenticatedMessageClaimV1::new(
            transaction_kind,
            logical_operation_id.to_string(),
            outer_request_digest.clone(),
            manifest.message_digest.clone(),
            raw_quarantine_digest.clone(),
            self.route(),
            self.now_ms()?,
        )?;
        persist_immutable_file(&path, &canonical_json(&claim)?)?;
        Ok(claim)
    }

    fn reject_cross_operation_message_claim(
        &self,
        transaction_kind: ReceiverInboundTransactionKindV1,
        logical_operation_id: &str,
        outer_request_digest: &ContentDigest,
        message_digest: &ContentDigest,
    ) -> Result<Option<ReceiverSignedControlRejectionV1>, M6ReceiverError> {
        let path = self
            .message_claims_root
            .join(format!("{}.json", message_digest.file_stem()));
        if !path.exists() {
            return Ok(None);
        }
        let existing: ReceiverAuthenticatedMessageClaimV1 =
            load_canonical_file(&path, MAX_RECORD_BYTES)?;
        existing.validate(self.route())?;
        if existing.transaction_kind == transaction_kind
            && existing.logical_operation_id == logical_operation_id
            && &existing.outer_request_digest == outer_request_digest
        {
            return Ok(None);
        }
        let raw = self
            .quarantine
            .committed_for_intake(&existing.logical_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "authenticated message claim has no exact raw quarantine unit".to_string(),
                )
            })?;
        let unit = self.quarantine.read_committed_unit(&raw)?;
        let attempted_manifest_bytes =
            unit.files().get("manifest.json").cloned().ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "claimed replay message lacks retained manifest bytes".to_string(),
                )
            })?;
        let manifest = SignedManifest::from_canonical_bytes(&attempted_manifest_bytes)?;
        manifest.verify_route(self.route())?;
        if &manifest.message_digest != message_digest {
            return Err(M6ReceiverError::Integrity(
                "claimed replay manifest differs from the requested message".to_string(),
            ));
        }
        let replay_state = self.replay.control_state();
        let rejection = self.persist_control_rejection(
            ReceiverControlRejectionClassV1::MessageReplay,
            logical_operation_id,
            outer_request_digest,
            message_digest,
            &raw.raw_unit_digest,
            Some(attempted_manifest_bytes),
            None,
            Some(existing.canonical_bytes(self.route())?),
            replay_state.clone(),
            replay_state,
            "signed message was already consumed by a different receiver operation",
        )?;
        Ok(Some(rejection))
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_control_rejection(
        &self,
        class: ReceiverControlRejectionClassV1,
        logical_operation_id: &str,
        outer_request_digest: &ContentDigest,
        message_digest: &ContentDigest,
        raw_evidence_digest: &ContentDigest,
        attempted_manifest_bytes: Option<Vec<u8>>,
        raw_admission_rejection_bytes: Option<Vec<u8>>,
        existing_message_claim_bytes: Option<Vec<u8>>,
        prior_replay_state: ReplayControlStateV1,
        post_replay_state: ReplayControlStateV1,
        detail: &str,
    ) -> Result<ReceiverSignedControlRejectionV1, M6ReceiverError> {
        let identity = digest_domain(
            CONTROL_REJECTION_DOMAIN,
            &(
                class,
                logical_operation_id,
                outer_request_digest,
                message_digest,
            ),
        )?;
        let path = self
            .control_rejections_root
            .join(format!("{}.json", identity.file_stem()));
        if path.exists() {
            let existing: ReceiverSignedControlRejectionV1 =
                load_canonical_file(&path, MAX_RECORD_BYTES)?;
            existing.validate(self.route())?;
            return Ok(existing);
        }
        let (raw_quarantine_record_bytes, raw_unit_files) = if class
            == ReceiverControlRejectionClassV1::RawAdmission
        {
            (None, None)
        } else {
            let raw = match self.quarantine.committed_for_intake(logical_operation_id)? {
                Some(raw) => raw,
                None if class == ReceiverControlRejectionClassV1::MessageReplay => {
                    let claim_bytes = existing_message_claim_bytes.as_deref().ok_or_else(|| {
                        M6ReceiverError::Integrity(
                            "early message-replay rejection lacks the existing claim".to_string(),
                        )
                    })?;
                    let claim = ReceiverAuthenticatedMessageClaimV1::from_canonical_bytes(
                        claim_bytes,
                        self.route(),
                    )?;
                    self.quarantine
                        .committed_for_intake(&claim.logical_operation_id)?
                        .ok_or_else(|| {
                            M6ReceiverError::Integrity(
                                "message-replay claim has no exact source quarantine unit"
                                    .to_string(),
                            )
                        })?
                }
                None => {
                    return Err(M6ReceiverError::Integrity(
                        "post-admission control rejection has no committed raw quarantine unit"
                            .to_string(),
                    ));
                }
            };
            if &raw.raw_unit_digest != raw_evidence_digest {
                return Err(M6ReceiverError::Integrity(
                    "post-admission control rejection raw evidence digest differs from quarantine"
                        .to_string(),
                ));
            }
            let unit = self.quarantine.read_committed_unit(&raw)?;
            (Some(canonical_json(&raw)?), Some(unit.files().clone()))
        };
        let rejection = ReceiverSignedControlRejectionV1::new(
            class,
            logical_operation_id.to_string(),
            outer_request_digest.clone(),
            message_digest.clone(),
            raw_evidence_digest.clone(),
            self.route(),
            &self.signer,
            attempted_manifest_bytes,
            raw_admission_rejection_bytes,
            raw_quarantine_record_bytes,
            raw_unit_files,
            existing_message_claim_bytes,
            prior_replay_state,
            post_replay_state,
            detail.to_string(),
            self.now_ms()?,
        )?;
        persist_immutable_file(&path, &canonical_json(&rejection)?)?;
        Ok(rejection)
    }

    pub fn load_control_rejection(
        &self,
        logical_operation_id: &str,
        class: ReceiverControlRejectionClassV1,
        message_digest: &ContentDigest,
        outer_request_digest: &ContentDigest,
    ) -> Result<Option<ReceiverSignedControlRejectionV1>, M6ReceiverError> {
        validate_identifier(
            "receiver control-rejection operation id",
            logical_operation_id,
        )?;
        let identity = digest_domain(
            CONTROL_REJECTION_DOMAIN,
            &(
                class,
                logical_operation_id,
                outer_request_digest,
                message_digest,
            ),
        )?;
        let path = self
            .control_rejections_root
            .join(format!("{}.json", identity.file_stem()));
        if !path.exists() {
            return Ok(None);
        }
        let rejection: ReceiverSignedControlRejectionV1 =
            load_canonical_file(&path, MAX_RECORD_BYTES)?;
        rejection.validate(self.route())?;
        Ok(Some(rejection))
    }

    /// Reconstruct receiver-signed evidence for a real, authenticated
    /// compatibility rejection from the runtime's durable operation sources.
    pub fn compatibility_control_rejection(
        &self,
        logical_operation_id: &str,
    ) -> Result<Option<ReceiverCompatibilityControlRejectionV1>, M6ReceiverError> {
        validate_identifier(
            "receiver compatibility-control operation id",
            logical_operation_id,
        )?;
        let operation_root = operation_root(&self.operations_root, logical_operation_id);
        let required_paths = [
            operation_root.join(REQUEST_FILE),
            operation_root.join(ACTIVE_STATE_FILE),
            operation_root.join(RAW_RECORD_FILE),
            operation_root.join(VERIFIED_EXPORT_FILE),
            operation_root.join(COMPATIBILITY_FILE),
            operation_root.join(VALIDATION_REJECTION_FILE),
        ];
        if required_paths.iter().any(|path| !path.exists()) {
            return Ok(None);
        }

        let (request, active) =
            load_request_unit(&operation_root, self.route(), &self.import_policy)?;
        let request_record_bytes =
            read_regular_bounded(&operation_root.join(REQUEST_FILE), MAX_REQUEST_BYTES)?;
        let active_state_bytes =
            read_regular_bounded(&operation_root.join(ACTIVE_STATE_FILE), MAX_REQUEST_BYTES)?;
        let raw: RawQuarantineRecord =
            load_canonical_file(&operation_root.join(RAW_RECORD_FILE), MAX_RECORD_BYTES)?;
        let raw_quarantine_record_bytes = canonical_json(&raw)?;
        let raw_unit = self.quarantine.read_committed_unit(&raw)?;
        let raw_unit_files = raw_unit.files().clone();
        let signed_manifest_bytes =
            raw_unit_files
                .get("manifest.json")
                .cloned()
                .ok_or_else(|| {
                    M6ReceiverError::Integrity(
                        "compatibility-control raw unit lacks its signed manifest".to_string(),
                    )
                })?;
        let manifest = SignedManifest::from_canonical_bytes(&signed_manifest_bytes)?;
        manifest.verify_route(self.route())?;

        let verified_export_bytes =
            read_regular_bounded(&operation_root.join(VERIFIED_EXPORT_FILE), MAX_RECORD_BYTES)?;
        let verified = VerifiedQuarantinedExportV1::from_canonical_bytes(
            &verified_export_bytes,
            self.route(),
            &self.import_policy,
        )?;
        let compatibility_decision_bytes =
            read_regular_bounded(&operation_root.join(COMPATIBILITY_FILE), MAX_RECORD_BYTES)?;
        let compatibility = ReceiverCompatibilityDecisionV1::from_canonical_bytes(
            &compatibility_decision_bytes,
            &verified,
            &active,
            &self.import_policy,
        )?;
        let validation_rejection_bytes = read_regular_bounded(
            &operation_root.join(VALIDATION_REJECTION_FILE),
            MAX_RECORD_BYTES,
        )?;
        let rejection: ReceiverValidationRejection =
            parse_canonical(&validation_rejection_bytes, MAX_RECORD_BYTES)?;
        rejection.validate(&request, &raw)?;
        let negative = self
            .replay
            .load_terminal_negative(&manifest)?
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "compatibility-control operation lacks terminal-negative evidence".to_string(),
                )
            })?;
        let terminal_negative_record_bytes =
            negative.canonical_bytes(self.route(), RouteEndpointRole::Sender)?;
        let projection = self
            .journal
            .transaction(logical_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "compatibility-control operation lacks a coordinator projection".to_string(),
                )
            })?;
        let terminal_stage_digest = projection
            .current_record()
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "compatibility-control projection lacks a terminal stage".to_string(),
                )
            })?
            .stage_digest
            .clone();
        let coordinator_projection_bytes = projection.canonical_bytes()?;
        let post_active = self.capture_active_state()?;
        let post_rejection_active_state_bytes = post_active.canonical_bytes()?;

        let evidence = ReceiverCompatibilityControlRejectionV1 {
            schema: RECEIVER_COMPATIBILITY_CONTROL_REJECTION_SCHEMA.to_string(),
            logical_operation_id: logical_operation_id.to_string(),
            route_definition_digest: self.route().definition_digest.clone(),
            signing_key_id: self.signer.signing_key_id().to_string(),
            message_digest: request.message_digest,
            raw_quarantine_digest: raw.raw_unit_digest,
            verified_export_digest: verified.verification_digest().clone(),
            compatibility_decision_digest: compatibility.decision_digest().clone(),
            validation_rejection_digest: rejection.record_digest,
            terminal_negative_record_digest: negative.record_digest,
            terminal_stage_digest,
            active_snapshot_digest: active.snapshot().snapshot_digest.clone(),
            request_record_bytes,
            active_state_bytes,
            import_policy_bytes: self.import_policy.canonical_bytes()?,
            raw_quarantine_record_bytes,
            raw_unit_files,
            signed_manifest_bytes,
            verified_export_bytes,
            compatibility_decision_bytes,
            validation_rejection_bytes,
            terminal_negative_record_bytes,
            coordinator_projection_bytes,
            post_rejection_active_state_bytes,
            evidence_digest: ContentDigest::from_bytes(&[]),
            signature_hex: String::new(),
        }
        .seal(self.route(), &self.signer)?;
        Ok(Some(evidence))
    }

    /// Build the signed three-control suite from three already executed
    /// receiver operations. Replay evidence is intentionally not accepted by
    /// this API.
    pub fn negative_control_suite(
        &self,
        content_tamper_operation_id: &str,
        false_route_identity_operation_id: &str,
        incompatible_interface_operation_id: &str,
    ) -> Result<ReceiverNegativeControlSuiteV1, M6ReceiverError> {
        let required_rejection =
            |logical_operation_id: &str,
             class: ReceiverControlRejectionClassV1|
             -> Result<ReceiverSignedControlRejectionV1, M6ReceiverError> {
                let operation_root = operation_root(&self.operations_root, logical_operation_id);
                let (request, _) =
                    load_request_unit(&operation_root, self.route(), &self.import_policy)?;
                self.load_control_rejection(
                logical_operation_id,
                class,
                &request.message_digest,
                &request.request_digest,
            )?
            .ok_or_else(|| {
                M6ReceiverError::Integrity(format!(
                    "negative-control operation '{logical_operation_id}' lacks its {class:?} rejection"
                ))
            })
            };
        let content_tamper = required_rejection(
            content_tamper_operation_id,
            ReceiverControlRejectionClassV1::CanonicalManifest,
        )?;
        let false_route_identity = required_rejection(
            false_route_identity_operation_id,
            ReceiverControlRejectionClassV1::RouteAuthentication,
        )?;
        let incompatible_interface = self
            .compatibility_control_rejection(incompatible_interface_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::Integrity(format!(
                    "negative-control operation '{incompatible_interface_operation_id}' lacks an authenticated compatibility rejection"
                ))
            })?;
        ReceiverNegativeControlSuiteV1::new(
            self.route(),
            &self.signer,
            content_tamper,
            false_route_identity,
            incompatible_interface,
        )
    }

    fn commit_or_resolve_replay(
        &mut self,
        transaction_kind: ReceiverInboundTransactionKindV1,
        logical_operation_id: &str,
        outer_request_digest: &ContentDigest,
        raw_quarantine_digest: &ContentDigest,
        manifest: &SignedManifest,
    ) -> Result<ReplayCommitFact, M6ReceiverError> {
        self.authenticated_message_claim(
            transaction_kind,
            logical_operation_id,
            outer_request_digest,
            raw_quarantine_digest,
            manifest,
        )?;
        let prior_state = self.replay.control_state();
        match self.replay.resolve_exact_commit(manifest)? {
            ReplayCommitResolution::ExactCommitted(fact) => Ok(fact),
            ReplayCommitResolution::NotCommitted { .. } => {
                if let Err(error) = self.replay.verify_and_commit(manifest) {
                    let class = match &error {
                        M6IdentityError::Replay { .. } => {
                            Some(ReceiverControlRejectionClassV1::SequenceReplay)
                        }
                        M6IdentityError::SequenceGap { .. } => {
                            Some(ReceiverControlRejectionClassV1::SequenceGap)
                        }
                        M6IdentityError::ChainConflict { .. } => {
                            Some(ReceiverControlRejectionClassV1::ChainConflict)
                        }
                        M6IdentityError::NonceReplay(_) => {
                            Some(ReceiverControlRejectionClassV1::NonceReplay)
                        }
                        M6IdentityError::MessageReplay(_) => {
                            Some(ReceiverControlRejectionClassV1::MessageReplay)
                        }
                        _ => None,
                    };
                    if let Some(class) = class {
                        let post_state = self.replay.control_state();
                        let rejection = self.persist_control_rejection(
                            class,
                            logical_operation_id,
                            outer_request_digest,
                            &manifest.message_digest,
                            raw_quarantine_digest,
                            Some(manifest.canonical_bytes()?),
                            None,
                            None,
                            prior_state,
                            post_state,
                            &error.to_string(),
                        )?;
                        return Err(M6ReceiverError::ControlRejected {
                            class,
                            record_digest: rejection.record_digest,
                        });
                    }
                    return Err(M6ReceiverError::from(error));
                }
                match self.replay.resolve_exact_commit(manifest)? {
                    ReplayCommitResolution::ExactCommitted(fact) => Ok(fact),
                    resolution => Err(M6ReceiverError::Integrity(format!(
                        "replay commit did not resolve to its exact fact: {resolution:?}"
                    ))),
                }
            }
            ReplayCommitResolution::Conflicting {
                last_committed_sequence,
                observed_message_digest,
                observed_sequence,
            } => {
                let post_state = self.replay.control_state();
                let rejection = self.persist_control_rejection(
                    ReceiverControlRejectionClassV1::SequenceReplay,
                    logical_operation_id,
                    outer_request_digest,
                    &manifest.message_digest,
                    raw_quarantine_digest,
                    Some(manifest.canonical_bytes()?),
                    None,
                    None,
                    prior_state,
                    post_state,
                    &format!(
                        "sequence {observed_sequence} conflicts with committed cursor {last_committed_sequence} and message {observed_message_digest}"
                    ),
                )?;
                Err(M6ReceiverError::ControlRejected {
                    class: rejection.class,
                    record_digest: rejection.record_digest,
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_terminal_negative_claimed(
        &mut self,
        transaction_kind: ReceiverInboundTransactionKindV1,
        logical_operation_id: &str,
        outer_request_digest: &ContentDigest,
        raw_quarantine_digest: &ContentDigest,
        manifest: &SignedManifest,
        disposition: TerminalNegativeDisposition,
        reason: TerminalNegativeReason,
        negative_evidence_digest: ContentDigest,
    ) -> Result<TerminalNegativeRecord, M6ReceiverError> {
        self.authenticated_message_claim(
            transaction_kind,
            logical_operation_id,
            outer_request_digest,
            raw_quarantine_digest,
            manifest,
        )?;
        self.replay
            .record_terminal_negative(manifest, disposition, reason, negative_evidence_digest)
            .map_err(M6ReceiverError::from)
    }

    fn record_validation_rejection(
        &self,
        request: &ReceiverIntakeRequest,
        raw: &RawQuarantineRecord,
        authenticated: bool,
        policy_rule: impl Into<String>,
        detail: impl Into<String>,
        evidence_refs: Vec<ContentDigest>,
    ) -> Result<ReceiverValidationRejection, M6ReceiverError> {
        let path = operation_root(&self.operations_root, &request.logical_operation_id)
            .join(VALIDATION_REJECTION_FILE);
        if path.exists() {
            let record: ReceiverValidationRejection = load_canonical_file(&path, MAX_RECORD_BYTES)?;
            record.validate(request, raw)?;
            return Ok(record);
        }
        let record = ReceiverValidationRejection::new(
            request,
            raw,
            authenticated,
            policy_rule,
            detail,
            evidence_refs,
            self.now_ms()?,
        )?;
        persist_immutable_file(&path, &canonical_json(&record)?)?;
        Ok(record)
    }

    fn append_validation_rejected(
        &mut self,
        request: &ReceiverIntakeRequest,
        coordinator_request_digest: &ContentDigest,
        rejection: &ReceiverValidationRejection,
        terminal_negative: Option<&TerminalNegativeRecord>,
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<ReceiverAcknowledgementReceipt, M6ReceiverError> {
        let mut refs = rejection.evidence_refs.clone();
        refs.push(rejection.record_digest.clone());
        if let Some(record) = terminal_negative {
            refs.push(record.record_digest.clone());
            refs.push(record.negative_evidence_digest.clone());
        }
        let stage = self.append_stage(
            request,
            coordinator_request_digest,
            TransactionStage::ValidationRejected,
            StageCause::ValidationRejection,
            0,
            None,
            None,
            refs,
            None,
            None,
        )?;
        self.publish_acknowledgement(
            request,
            "validation_rejected",
            rejection.raw_quarantine_digest.clone(),
            &stage,
            crash_at,
        )
    }
}

fn revocation_operation_root(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!(
        "{}.revocation",
        ContentDigest::from_bytes(logical_operation_id.as_bytes()).file_stem()
    ))
}

fn persist_revocation_request_unit(
    operation_root: &Path,
    request: &ReceiverRevocationRequest,
) -> Result<(), M6ReceiverError> {
    let parent = operation_root
        .parent()
        .ok_or_else(|| M6ReceiverError::UnsafePath(operation_root.to_path_buf()))?;
    if operation_root.exists() {
        return Err(M6ReceiverError::Integrity(
            "receiver revocation request unit appeared after its absence was checked".to_string(),
        ));
    }
    let request_bytes = canonical_json(request)?;
    let commit = (
        "wasm-biotic.m6-receiver-revocation-request-commit.v1".to_string(),
        request.request_digest.clone(),
        ContentDigest::from_bytes(&request_bytes),
    );
    let temporary = parent.join(format!(
        ".building-revocation-{}-{}-{}",
        request.request_digest.file_stem(),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        fs::create_dir(&temporary).map_err(|source| M6ReceiverError::io(&temporary, source))?;
        write_new_sync(&temporary.join(REQUEST_FILE), &request_bytes)?;
        write_new_sync(
            &temporary.join(REQUEST_COMMIT_FILE),
            &canonical_json(&commit)?,
        )?;
        sync_directory(&temporary)?;
        fs::rename(&temporary, operation_root)
            .map_err(|source| M6ReceiverError::io(operation_root, source))?;
        sync_directory(parent)
    })();
    if result.is_err() && temporary.exists() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn load_revocation_request_unit(
    operation_root: &Path,
    route: &RouteDefinition,
    revocation_policy_digest: &ContentDigest,
) -> Result<ReceiverRevocationRequest, M6ReceiverError> {
    reject_symlink(operation_root)?;
    let request_bytes =
        read_regular_bounded(&operation_root.join(REQUEST_FILE), MAX_REQUEST_BYTES)?;
    let request: ReceiverRevocationRequest = parse_canonical(&request_bytes, MAX_REQUEST_BYTES)?;
    request.validate(route, revocation_policy_digest)?;
    let commit: (String, ContentDigest, ContentDigest) =
        load_canonical_file(&operation_root.join(REQUEST_COMMIT_FILE), MAX_REQUEST_BYTES)?;
    if commit
        != (
            "wasm-biotic.m6-receiver-revocation-request-commit.v1".to_string(),
            request.request_digest.clone(),
            ContentDigest::from_bytes(&request_bytes),
        )
    {
        return Err(M6ReceiverError::Integrity(
            "receiver revocation request commit is incomplete or cross-linked".to_string(),
        ));
    }
    Ok(request)
}

fn enforce_revocation_operation_bound(
    operations_root: &Path,
    max_operations: u32,
) -> Result<(), M6ReceiverError> {
    let mut count = 0_u32;
    for entry in fs::read_dir(operations_root)
        .map_err(|source| M6ReceiverError::io(operations_root, source))?
    {
        let entry = entry.map_err(|source| M6ReceiverError::io(operations_root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| M6ReceiverError::UnsafePath(path.clone()))?
            .to_string();
        let file_type = entry
            .file_type()
            .map_err(|source| M6ReceiverError::io(&path, source))?;
        if file_type.is_dir() && name.ends_with(".revocation") {
            count = count.saturating_add(1);
        } else if !name.starts_with(".building-") {
            return Err(M6ReceiverError::Integrity(format!(
                "unexpected receiver revocation operation entry '{}'",
                path.display()
            )));
        }
    }
    if count >= max_operations {
        return Err(M6ReceiverError::ResourceExhausted(
            "receiver revocation operation budget is exhausted".to_string(),
        ));
    }
    Ok(())
}

impl<V: OpaqueAuthorizationVerifier> M6ReceiverRuntime<V> {
    pub fn prepare_revocation_intake(
        &self,
        logical_operation_id: impl Into<String>,
        message_digest: ContentDigest,
        deadline_ms: u64,
    ) -> Result<PreparedReceiverRevocationIntake, M6ReceiverError> {
        self.prepare_revocation_intake_with_fault(
            logical_operation_id,
            message_digest,
            deadline_ms,
            None,
        )
    }

    pub fn prepare_revocation_intake_with_fault(
        &self,
        logical_operation_id: impl Into<String>,
        message_digest: ContentDigest,
        deadline_ms: u64,
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<PreparedReceiverRevocationIntake, M6ReceiverError> {
        let logical_operation_id = logical_operation_id.into();
        validate_identifier("receiver revocation operation id", &logical_operation_id)?;
        self.require_no_other_pending_revocation(&logical_operation_id)?;
        if let Some(existing) = self.journal.transaction(&logical_operation_id)?
            && existing.intent.kind != TransactionKind::ReceiverRevocationApplication
        {
            return Err(M6ReceiverError::Conflict {
                identity: logical_operation_id,
                existing: existing.intent.request_digest,
                requested: ContentDigest::from_bytes(b"receiver-revocation-application"),
            });
        }
        let operation_root =
            revocation_operation_root(&self.revocation_operations_root, &logical_operation_id);
        let policy_digest = self.revocations.config().config_digest.clone();
        let request = if operation_root.exists() {
            let existing =
                load_revocation_request_unit(&operation_root, self.route(), &policy_digest)?;
            if existing.logical_operation_id != logical_operation_id
                || existing.message_digest != message_digest
                || existing.deadline_ms != deadline_ms
            {
                return Err(M6ReceiverError::Conflict {
                    identity: logical_operation_id,
                    existing: existing.request_digest,
                    requested: ContentDigest::from_bytes(&canonical_json(&(
                        message_digest,
                        deadline_ms,
                    ))?),
                });
            }
            existing
        } else {
            enforce_revocation_operation_bound(
                &self.revocation_operations_root,
                self.max_intake_operations,
            )?;
            let active = self.capture_active_state()?;
            let request = ReceiverRevocationRequest::new(
                logical_operation_id.clone(),
                self.now_ms()?,
                deadline_ms,
                message_digest,
                active.snapshot().snapshot_digest.clone(),
                self.route(),
                policy_digest,
            )?;
            persist_revocation_request_unit(&operation_root, &request)?;
            maybe_crash(crash_at, ReceiverCrashPoint::RevocationRequestPersisted)?;
            request
        };
        let initial = self.journal.begin(
            TransactionRequestDraft {
                kind: TransactionKind::ReceiverRevocationApplication,
                logical_operation_id: request.logical_operation_id.clone(),
                idempotency_key: format!(
                    "receiver-revocation-application:{}",
                    request.logical_operation_id
                ),
                route_id: request.route_id.clone(),
                route_generation: request.route_generation,
                route_definition_digest: request.route_definition_digest.clone(),
                message_digest: request.message_digest.clone(),
                exchange_digest: request.exchange_digest.clone(),
                package_digest: request.message_digest.clone(),
                before_snapshot_digest: request.captured_active_snapshot_digest.clone(),
                expected_after_snapshot_digest: request.captured_active_snapshot_digest.clone(),
                policy_digest: request.revocation_policy_digest.clone(),
                authority_refs: vec![
                    self.route().sender.identity_document_digest.clone(),
                    self.rollback_authority.profile().profile_digest().clone(),
                ],
                evidence_refs: vec![
                    request.request_digest.clone(),
                    request.message_digest.clone(),
                    request.route_definition_digest.clone(),
                ],
                retry_policy: self.retry_policy.clone(),
                deadline_ms: request.deadline_ms,
            },
            stage_evidence(
                StageCause::Normal,
                0,
                None,
                None,
                vec![
                    request.request_digest.clone(),
                    request.message_digest.clone(),
                    request.route_definition_digest.clone(),
                ],
                None,
                None,
            )?,
        )?;
        maybe_crash(crash_at, ReceiverCrashPoint::RevocationIntakeIntentRecorded)?;
        Ok(PreparedReceiverRevocationIntake {
            logical_operation_id: request.logical_operation_id,
            request_digest: request.request_digest,
            coordinator_request_digest: initial.request_digest,
            message_digest: request.message_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_revocation_stage(
        &self,
        request: &ReceiverRevocationRequest,
        coordinator_request_digest: &ContentDigest,
        stage: TransactionStage,
        cause: StageCause,
        attempt: u32,
        authority_ref: Option<ContentDigest>,
        effect_request_digest: Option<ContentDigest>,
        evidence_refs: Vec<ContentDigest>,
        receipt_ref: Option<ContentDigest>,
        attestation_ref: Option<ContentDigest>,
    ) -> Result<TransactionStageRecord, M6ReceiverError> {
        let projection = self
            .journal
            .transaction(&request.logical_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::InvalidState(format!(
                    "receiver revocation coordinator has no transaction '{}'",
                    request.logical_operation_id
                ))
            })?;
        if let Some(existing) = projection
            .stages
            .iter()
            .find(|record| record.stage == stage)
        {
            return Ok(existing.clone());
        }
        if projection
            .current_stage()
            .is_some_and(TransactionStage::is_terminal)
        {
            return Err(M6ReceiverError::InvalidState(format!(
                "receiver revocation transaction '{}' is already terminal at {:?}",
                request.logical_operation_id,
                projection.current_stage()
            )));
        }
        self.journal
            .append(
                &request.logical_operation_id,
                coordinator_request_digest,
                stage,
                stage_evidence(
                    cause,
                    attempt,
                    authority_ref,
                    effect_request_digest,
                    evidence_refs,
                    receipt_ref,
                    attestation_ref,
                )?,
            )
            .map_err(M6ReceiverError::from)
    }

    fn record_revocation_rejection(
        &self,
        request: &ReceiverRevocationRequest,
        raw: &RawQuarantineRecord,
        authenticated: bool,
        detail: impl Into<String>,
        evidence_refs: Vec<ContentDigest>,
    ) -> Result<ReceiverRevocationValidationRejection, M6ReceiverError> {
        let operation_root = revocation_operation_root(
            &self.revocation_operations_root,
            &request.logical_operation_id,
        );
        let path = operation_root.join(REVOCATION_REJECTION_FILE);
        if path.exists() {
            let record: ReceiverRevocationValidationRejection =
                load_canonical_file(&path, MAX_RECORD_BYTES)?;
            record.validate(request, raw)?;
            return Ok(record);
        }
        let record = ReceiverRevocationValidationRejection::new(
            request,
            raw,
            authenticated,
            detail,
            evidence_refs,
            self.now_ms()?,
        )?;
        persist_immutable_file(&path, &canonical_json(&record)?)?;
        Ok(record)
    }

    fn reject_revocation_after_quarantine(
        &mut self,
        request: &ReceiverRevocationRequest,
        raw: &RawQuarantineRecord,
        authenticated: bool,
        detail: impl Into<String>,
        evidence_refs: Vec<ContentDigest>,
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<ReceiverRevocationAdmissionResult, M6ReceiverError> {
        let rejection =
            self.record_revocation_rejection(request, raw, authenticated, detail, evidence_refs)?;
        let coordinator_request_digest =
            self.coordinator_request_digest(&request.logical_operation_id)?;
        let terminal = self.ensure_revocation_stage(
            request,
            &coordinator_request_digest,
            TransactionStage::ValidationRejected,
            StageCause::ValidationRejection,
            0,
            None,
            None,
            vec![
                rejection.record_digest.clone(),
                rejection.raw_quarantine_digest.clone(),
            ],
            None,
            None,
        )?;
        self.publish_acknowledgement_for_context(
            revocation_operation_root(
                &self.revocation_operations_root,
                &request.logical_operation_id,
            ),
            &request.logical_operation_id,
            &request.request_digest,
            &request.message_digest,
            "validation_rejected",
            raw.raw_unit_digest.clone(),
            &terminal,
            crash_at,
        )?;
        Ok(ReceiverRevocationAdmissionResult::ValidationRejected(
            rejection,
        ))
    }

    fn scan_matching_imports(
        &self,
        tombstone: &RevocationTombstoneV1,
    ) -> Result<Vec<ReceiverRevocationAffectedOperation>, M6ReceiverError> {
        let mut affected = Vec::new();
        let mut observed = 0_u32;
        for entry in fs::read_dir(&self.operations_root)
            .map_err(|source| M6ReceiverError::io(&self.operations_root, source))?
        {
            let entry =
                entry.map_err(|source| M6ReceiverError::io(&self.operations_root, source))?;
            let path = entry.path();
            reject_symlink(&path)?;
            let name = entry
                .file_name()
                .to_str()
                .ok_or_else(|| M6ReceiverError::UnsafePath(path.clone()))?
                .to_string();
            let file_type = entry
                .file_type()
                .map_err(|source| M6ReceiverError::io(&path, source))?;
            if name.starts_with(".building-") {
                continue;
            }
            if !file_type.is_dir() || !name.ends_with(".intake") {
                return Err(M6ReceiverError::Integrity(format!(
                    "unexpected receiver intake operation entry '{}'",
                    path.display()
                )));
            }
            observed = observed.saturating_add(1);
            if observed > self.max_intake_operations {
                return Err(M6ReceiverError::ResourceExhausted(
                    "receiver intake operation budget is exceeded during revocation scan"
                        .to_string(),
                ));
            }
            if !path.join(IMPORT_PLAN_FILE).exists() {
                continue;
            }
            let (import_request, active) =
                load_request_unit(&path, self.route(), &self.import_policy)?;
            let (_, verified, _, _, plan) = self.load_planned_context(&path, &active)?;
            let binding =
                exchange_revocation_binding(self.route(), &import_request, &verified, &plan);
            if !tombstone.matches(&binding) {
                continue;
            }
            let projection = self
                .journal
                .transaction(&import_request.logical_operation_id)?
                .ok_or_else(|| {
                    M6ReceiverError::Integrity(format!(
                        "planned import '{}' has no coordinator transaction",
                        import_request.logical_operation_id
                    ))
                })?;
            let disposition =
                receiver_import_disposition(projection.current_stage().ok_or_else(|| {
                    M6ReceiverError::Integrity(format!(
                        "planned import '{}' has no durable lifecycle stage",
                        import_request.logical_operation_id
                    ))
                })?);
            let record = self.revocations.record_affected_import(
                &tombstone.tombstone_digest,
                binding,
                disposition,
            )?;
            affected.push(ReceiverRevocationAffectedOperation {
                import_logical_operation_id: import_request.logical_operation_id,
                import_request_digest: import_request.request_digest,
                affected: record,
            });
        }
        affected.sort_by(|left, right| {
            left.import_logical_operation_id
                .cmp(&right.import_logical_operation_id)
        });
        Ok(affected)
    }

    pub fn admit_revocation(
        &mut self,
        logical_operation_id: &str,
    ) -> Result<ReceiverRevocationAdmissionResult, M6ReceiverError> {
        self.admit_revocation_with_fault(logical_operation_id, None)
    }

    pub fn admit_revocation_with_fault(
        &mut self,
        logical_operation_id: &str,
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<ReceiverRevocationAdmissionResult, M6ReceiverError> {
        validate_identifier("receiver revocation operation id", logical_operation_id)?;
        self.require_no_other_pending_revocation(logical_operation_id)?;
        let operation_root =
            revocation_operation_root(&self.revocation_operations_root, logical_operation_id);
        let request = load_revocation_request_unit(
            &operation_root,
            self.route(),
            &self.revocations.config().config_digest,
        )?;
        let coordinator_request_digest = self.coordinator_request_digest(logical_operation_id)?;
        if let Some(rejection) = self.reject_cross_operation_message_claim(
            ReceiverInboundTransactionKindV1::Revocation,
            &request.logical_operation_id,
            &request.request_digest,
            &request.message_digest,
        )? {
            let terminal = self.ensure_revocation_stage(
                &request,
                &coordinator_request_digest,
                TransactionStage::ValidationRejected,
                StageCause::ValidationRejection,
                0,
                None,
                None,
                vec![
                    rejection.record_digest.clone(),
                    rejection.raw_evidence_digest.clone(),
                ],
                None,
                None,
            )?;
            self.publish_acknowledgement_for_context(
                operation_root,
                &request.logical_operation_id,
                &request.request_digest,
                &request.message_digest,
                "validation_rejected",
                rejection.record_digest.clone(),
                &terminal,
                crash_at,
            )?;
            return Err(M6ReceiverError::ControlRejected {
                class: rejection.class,
                record_digest: rejection.record_digest,
            });
        }

        let admission = if let Some(record) =
            self.quarantine.committed_for_intake(logical_operation_id)?
        {
            RawAdmissionOutcome::Quarantined(record)
        } else if let Some(rejected) = self.quarantine.admission_rejection(logical_operation_id)? {
            RawAdmissionOutcome::Rejected(rejected)
        } else {
            let owner = self.spool.acquire_role()?;
            self.quarantine.admit_ready(
                &self.spool,
                &owner,
                &request.message_digest,
                logical_operation_id,
            )?
        };
        match admission {
            RawAdmissionOutcome::Rejected(rejected) => {
                let replay_state = self.replay.control_state();
                self.persist_control_rejection(
                    ReceiverControlRejectionClassV1::RawAdmission,
                    &request.logical_operation_id,
                    &request.request_digest,
                    &request.message_digest,
                    &rejected.record_digest,
                    None,
                    Some(canonical_json(&rejected)?),
                    None,
                    replay_state.clone(),
                    replay_state,
                    "raw revocation unit failed the hard pre-interpretation admission boundary",
                )?;
                let terminal = self.ensure_revocation_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::RawAdmissionRejected,
                    StageCause::ValidationRejection,
                    0,
                    None,
                    None,
                    vec![rejected.record_digest.clone()],
                    None,
                    None,
                )?;
                maybe_crash(
                    crash_at,
                    ReceiverCrashPoint::RevocationRawAdmissionCommitted,
                )?;
                self.publish_acknowledgement_for_context(
                    operation_root,
                    &request.logical_operation_id,
                    &request.request_digest,
                    &request.message_digest,
                    "raw_admission_rejected",
                    rejected.record_digest.clone(),
                    &terminal,
                    crash_at,
                )?;
                Ok(ReceiverRevocationAdmissionResult::RawAdmissionRejected(
                    rejected,
                ))
            }
            RawAdmissionOutcome::Quarantined(raw) => {
                persist_operation_record(
                    &operation_root,
                    RAW_RECORD_FILE,
                    &canonical_json(&raw)?,
                    MAX_RECORD_BYTES,
                )?;
                maybe_crash(
                    crash_at,
                    ReceiverCrashPoint::RevocationRawAdmissionCommitted,
                )?;
                self.ensure_revocation_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::RevocationRawQuarantined,
                    StageCause::Normal,
                    0,
                    None,
                    None,
                    vec![raw.raw_unit_digest.clone(), raw.record_digest.clone()],
                    None,
                    None,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::RevocationRawQuarantined)?;

                let manifest = match self.quarantine.parse_quarantined_manifest(&raw) {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        return self.reject_revocation_after_quarantine(
                            &request,
                            &raw,
                            false,
                            error.to_string(),
                            vec![raw.record_digest.clone()],
                            crash_at,
                        );
                    }
                };
                if manifest.message_digest != request.message_digest {
                    return self.reject_revocation_after_quarantine(
                        &request,
                        &raw,
                        false,
                        "revocation manifest differs from the requested message identity",
                        vec![raw.record_digest.clone(), manifest.message_digest.clone()],
                        crash_at,
                    );
                }
                if let Err(error) = manifest.verify_route(self.route()) {
                    return self.reject_revocation_after_quarantine(
                        &request,
                        &raw,
                        false,
                        error.to_string(),
                        vec![raw.record_digest.clone(), manifest.message_digest.clone()],
                        crash_at,
                    );
                }
                let committed = self.quarantine.read_committed_unit(&raw)?;
                let retained_paths = committed.files().keys().cloned().collect::<Vec<_>>();
                if manifest.unsigned.kind != ManifestKind::Revocation
                    || manifest.unsigned.origin_role != RouteEndpointRole::Sender
                    || !manifest.unsigned.attachments.is_empty()
                    || retained_paths
                        != vec!["commit.json".to_string(), "manifest.json".to_string()]
                    || !matches!(manifest.unsigned.payload, ManifestPayload::Revocation(_))
                {
                    return self.reject_revocation_after_quarantine(
                        &request,
                        &raw,
                        true,
                        "authenticated revocation must be sender-originated and attachment-free",
                        vec![raw.record_digest.clone(), manifest.message_digest.clone()],
                        crash_at,
                    );
                }
                self.ensure_revocation_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::RevocationAuthenticated,
                    StageCause::Normal,
                    0,
                    Some(self.route().sender.identity_document_digest.clone()),
                    None,
                    vec![
                        raw.record_digest.clone(),
                        manifest.message_digest.clone(),
                        self.route().sender.identity_document_digest.clone(),
                    ],
                    None,
                    None,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::RevocationAuthenticated)?;
                if self.now_ms()? > manifest.unsigned.expires_at_ms {
                    let rejection = self.record_revocation_rejection(
                        &request,
                        &raw,
                        true,
                        "authenticated revocation expired before replay admission",
                        vec![raw.record_digest.clone(), manifest.message_digest.clone()],
                    )?;
                    let negative = self.record_terminal_negative_claimed(
                        ReceiverInboundTransactionKindV1::Revocation,
                        &request.logical_operation_id,
                        &request.request_digest,
                        &raw.raw_unit_digest,
                        &manifest,
                        TerminalNegativeDisposition::Expired,
                        TerminalNegativeReason::Expired,
                        rejection.record_digest.clone(),
                    )?;
                    let terminal = self.ensure_revocation_stage(
                        &request,
                        &coordinator_request_digest,
                        TransactionStage::ValidationRejected,
                        StageCause::Expiry,
                        0,
                        None,
                        None,
                        vec![
                            rejection.record_digest.clone(),
                            negative.record_digest.clone(),
                        ],
                        None,
                        None,
                    )?;
                    self.publish_acknowledgement_for_context(
                        operation_root,
                        &request.logical_operation_id,
                        &request.request_digest,
                        &request.message_digest,
                        "validation_rejected",
                        raw.raw_unit_digest.clone(),
                        &terminal,
                        crash_at,
                    )?;
                    return Ok(ReceiverRevocationAdmissionResult::ValidationRejected(
                        rejection,
                    ));
                }
                let replay = self.commit_or_resolve_replay(
                    ReceiverInboundTransactionKindV1::Revocation,
                    &request.logical_operation_id,
                    &request.request_digest,
                    &raw.raw_unit_digest,
                    &manifest,
                )?;
                let replay_digest = replay_fact_digest(&replay)?;
                self.ensure_revocation_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::RevocationReplayAndSequenceCommitted,
                    StageCause::Normal,
                    0,
                    None,
                    None,
                    vec![
                        replay_digest,
                        replay.message_digest.clone(),
                        raw.record_digest.clone(),
                    ],
                    None,
                    None,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::RevocationReplayCommitted)?;
                let tombstone = self.revocations.apply_authenticated(
                    &manifest,
                    &replay,
                    raw.raw_unit_digest.clone(),
                    raw.record_digest.clone(),
                )?;
                self.ensure_revocation_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::RevocationTombstoneCommitted,
                    StageCause::Normal,
                    0,
                    Some(self.route().sender.identity_document_digest.clone()),
                    None,
                    vec![
                        tombstone.tombstone_digest.clone(),
                        replay.message_digest.clone(),
                        raw.record_digest.clone(),
                    ],
                    None,
                    None,
                )?;
                maybe_crash(crash_at, ReceiverCrashPoint::RevocationTombstoneCommitted)?;

                let match_path = operation_root.join(REVOCATION_MATCH_SET_FILE);
                let matches = if match_path.exists() {
                    let existing: ReceiverRevocationMatchSet =
                        load_canonical_file(&match_path, MAX_RECORD_BYTES)?;
                    existing.validate(&request, &tombstone)?;
                    existing
                } else {
                    let matches = ReceiverRevocationMatchSet::new(
                        &request,
                        &tombstone,
                        self.scan_matching_imports(&tombstone)?,
                    )?;
                    persist_immutable_file(&match_path, &canonical_json(&matches)?)?;
                    matches
                };
                self.ensure_revocation_stage(
                    &request,
                    &coordinator_request_digest,
                    TransactionStage::RevocationAffectedExchangesResolved,
                    StageCause::Normal,
                    0,
                    None,
                    None,
                    vec![
                        tombstone.tombstone_digest.clone(),
                        matches.record_digest.clone(),
                    ],
                    None,
                    None,
                )?;
                maybe_crash(
                    crash_at,
                    ReceiverCrashPoint::RevocationAffectedImportsCommitted,
                )?;
                Ok(ReceiverRevocationAdmissionResult::AwaitingContainment(
                    PreparedReceiverRevocationContainment {
                        logical_operation_id: request.logical_operation_id,
                        request_digest: request.request_digest,
                        tombstone,
                        affected_operations: matches.affected_operations,
                    },
                ))
            }
        }
    }
}

fn receiver_import_disposition(stage: TransactionStage) -> ReceiverImportDispositionV1 {
    match stage {
        TransactionStage::AwaitingApproval => ReceiverImportDispositionV1::AwaitingApproval,
        TransactionStage::ActivationIntentRecorded
        | TransactionStage::ActivationEffectCommitted
        | TransactionStage::ObservationIntentRecorded
        | TransactionStage::RollbackIntentRecorded => {
            ReceiverImportDispositionV1::ActivationPending
        }
        TransactionStage::Healthy => ReceiverImportDispositionV1::ActiveHealthy,
        TransactionStage::Expired => ReceiverImportDispositionV1::Expired,
        TransactionStage::Escalated => ReceiverImportDispositionV1::Escalated,
        TransactionStage::RolledBack => ReceiverImportDispositionV1::RolledBack,
        TransactionStage::ContainmentRequired => ReceiverImportDispositionV1::ContainmentRequired,
        TransactionStage::Denied
        | TransactionStage::ValidationRejected
        | TransactionStage::RawAdmissionRejected => ReceiverImportDispositionV1::Denied,
        _ => ReceiverImportDispositionV1::Quarantined,
    }
}

impl<V: OpaqueAuthorizationVerifier> M6ReceiverRuntime<V> {
    fn ensure_import_stage(
        &self,
        request: &ReceiverIntakeRequest,
        stage: TransactionStage,
        cause: StageCause,
        attempt: u32,
        authority_ref: Option<ContentDigest>,
        effect_request_digest: Option<ContentDigest>,
        evidence_refs: Vec<ContentDigest>,
        receipt_ref: Option<ContentDigest>,
        attestation_ref: Option<ContentDigest>,
    ) -> Result<TransactionStageRecord, M6ReceiverError> {
        let projection = self
            .journal
            .transaction(&request.logical_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::InvalidState(format!(
                    "receiver coordinator has no import transaction '{}'",
                    request.logical_operation_id
                ))
            })?;
        if let Some(existing) = projection
            .stages
            .iter()
            .find(|record| record.stage == stage)
        {
            return Ok(existing.clone());
        }
        self.append_stage(
            request,
            &projection.intent.request_digest,
            stage,
            cause,
            attempt,
            authority_ref,
            effect_request_digest,
            evidence_refs,
            receipt_ref,
            attestation_ref,
        )
    }

    fn resolve_pre_effect_import(
        &mut self,
        entry: &ReceiverRevocationAffectedOperation,
        tombstone: &RevocationTombstoneV1,
    ) -> Result<RevocationContainmentResolutionV1, M6ReceiverError> {
        if let Some(existing) = self
            .revocations
            .containment_resolution(&entry.affected.affected_digest)?
        {
            return Ok(existing);
        }
        let operation_root =
            operation_root(&self.operations_root, &entry.import_logical_operation_id);
        let (request, _) = load_request_unit(&operation_root, self.route(), &self.import_policy)?;
        if request.request_digest != entry.import_request_digest {
            return Err(M6ReceiverError::Integrity(
                "revocation affected work differs from the durable import request".to_string(),
            ));
        }
        let current = self
            .journal
            .transaction(&request.logical_operation_id)?
            .and_then(|projection| projection.current_record().cloned())
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "revocation affected import has no durable lifecycle stage".to_string(),
                )
            })?;
        if current.stage.is_terminal() {
            return self
                .revocations
                .resolve_containment(
                    &entry.affected.affected_digest,
                    RevocationContainmentOutcomeV1::AlreadyTerminal,
                    vec![
                        tombstone.tombstone_digest.clone(),
                        current.stage_digest.clone(),
                    ],
                )
                .map_err(M6ReceiverError::from);
        }

        let resolution = self.revocations.resolve_containment(
            &entry.affected.affected_digest,
            RevocationContainmentOutcomeV1::RejectedBeforeApproval,
            vec![
                tombstone.tombstone_digest.clone(),
                current.stage_digest.clone(),
            ],
        )?;
        match current.stage {
            TransactionStage::AwaitingApproval => {
                let terminal = self.ensure_import_stage(
                    &request,
                    TransactionStage::Denied,
                    StageCause::PolicyRejection,
                    0,
                    Some(self.approval_authority.profile().profile_digest().clone()),
                    None,
                    vec![
                        tombstone.tombstone_digest.clone(),
                        entry.affected.affected_digest.clone(),
                        resolution.resolution_digest.clone(),
                    ],
                    None,
                    None,
                )?;
                self.persist_terminal_decision(
                    &request,
                    ReceiverTerminalKind::RevokedBeforePromotion,
                    None,
                    None,
                    resolution.resolution_digest.clone(),
                )?;
                let raw: RawQuarantineRecord =
                    load_canonical_file(&operation_root.join(RAW_RECORD_FILE), MAX_RECORD_BYTES)?;
                self.publish_acknowledgement(
                    &request,
                    "denied",
                    raw.raw_unit_digest,
                    &terminal,
                    None,
                )?;
            }
            TransactionStage::ReceiverProvingCommitted => {
                let raw: RawQuarantineRecord =
                    load_canonical_file(&operation_root.join(RAW_RECORD_FILE), MAX_RECORD_BYTES)?;
                let rejection = self.record_validation_rejection(
                    &request,
                    &raw,
                    true,
                    "revocation-before-approval",
                    "an authenticated sender revocation matched the exact persisted import plan",
                    vec![
                        tombstone.tombstone_digest.clone(),
                        entry.affected.affected_digest.clone(),
                        resolution.resolution_digest.clone(),
                    ],
                )?;
                let terminal = self.ensure_import_stage(
                    &request,
                    TransactionStage::ValidationRejected,
                    StageCause::PolicyRejection,
                    0,
                    None,
                    None,
                    vec![
                        rejection.record_digest.clone(),
                        tombstone.tombstone_digest.clone(),
                        resolution.resolution_digest.clone(),
                    ],
                    None,
                    None,
                )?;
                self.persist_terminal_decision(
                    &request,
                    ReceiverTerminalKind::ValidationRejected,
                    None,
                    None,
                    resolution.resolution_digest.clone(),
                )?;
                self.publish_acknowledgement(
                    &request,
                    "validation_rejected",
                    raw.raw_unit_digest,
                    &terminal,
                    None,
                )?;
            }
            stage => {
                return Err(M6ReceiverError::InvalidState(format!(
                    "pre-effect revocation work cannot reject import stage {stage:?}"
                )));
            }
        }
        Ok(resolution)
    }

    fn resolve_effectful_import(
        &mut self,
        entry: &ReceiverRevocationAffectedOperation,
        tombstone: &RevocationTombstoneV1,
        rollback_authorization_digest: &ContentDigest,
    ) -> Result<RevocationContainmentResolutionV1, M6ReceiverError> {
        let operation_root =
            operation_root(&self.operations_root, &entry.import_logical_operation_id);
        let (request, active) =
            load_request_unit(&operation_root, self.route(), &self.import_policy)?;
        if request.request_digest != entry.import_request_digest {
            return Err(M6ReceiverError::Integrity(
                "effectful revocation work differs from the durable import request".to_string(),
            ));
        }
        let (_, verified, compatibility, proving, plan) =
            self.load_planned_context(&operation_root, &active)?;
        if exchange_revocation_binding(self.route(), &request, &verified, &plan)
            != entry.affected.binding
        {
            return Err(M6ReceiverError::Integrity(
                "effectful revocation work differs from the exact import binding".to_string(),
            ));
        }
        let approval_request = self.approval_request(
            &request,
            &active,
            &verified,
            &compatibility,
            &proving,
            &plan,
        )?;
        let decision = self
            .approval_authority
            .load_approval_decision(approval_request.request_digest())?;
        if decision.kind() != ApprovalDecisionKind::Granted {
            return Err(M6ReceiverError::Integrity(
                "effectful revocation import lacks its immutable Granted decision".to_string(),
            ));
        }
        let expected_binding = rollback_binding(&request, &decision, &proving, &plan)?;
        let authorization = self
            .rollback_authority
            .load_authorization(rollback_authorization_digest)?;
        require_exact_authorization(
            &authorization,
            AuthorityAction::RollbackImport,
            &expected_binding,
        )?;
        let consumption = self
            .rollback_authority
            .load_consumption(rollback_authorization_digest, 1)?;

        let import_projection = self
            .journal
            .transaction(&request.logical_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "effectful revocation import has no coordinator transaction".to_string(),
                )
            })?;
        let current = import_projection.current_stage().ok_or_else(|| {
            M6ReceiverError::Integrity(
                "effectful revocation import has no lifecycle stage".to_string(),
            )
        })?;
        let import_coordinator_request_digest = import_projection.intent.request_digest.clone();
        if matches!(
            current,
            TransactionStage::ActivationIntentRecorded
                | TransactionStage::ActivationEffectCommitted
                | TransactionStage::ObservationIntentRecorded
        ) {
            self.ensure_import_stage(
                &request,
                TransactionStage::RollbackIntentRecorded,
                StageCause::Revocation,
                1,
                Some(self.rollback_authority.profile().profile_digest().clone()),
                Some(import_coordinator_request_digest.clone()),
                vec![
                    tombstone.tombstone_digest.clone(),
                    entry.affected.affected_digest.clone(),
                    authorization.authorization_digest().clone(),
                    consumption.receipt_digest().clone(),
                ],
                None,
                None,
            )?;
        }

        if let Some(existing) = self
            .revocations
            .containment_resolution(&entry.affected.affected_digest)?
        {
            self.finish_effectful_import_projection(
                &request,
                &import_coordinator_request_digest,
                &existing,
            )?;
            return Ok(existing);
        }

        let rollback_id = format!(
            "m6-revocation:{}:{}",
            tombstone.tombstone_digest.file_stem(),
            ContentDigest::from_bytes(request.logical_operation_id.as_bytes()).file_stem()
        );
        let state = self.m5.state_snapshot()?;
        let existing_operator_rollback = state
            .operator_rollbacks
            .iter()
            .find(|record| record.rollback_id == rollback_id)
            .cloned();
        let source_cycle = state
            .cycles
            .iter()
            .find(|cycle| cycle.cycle_id == activation_cycle_id(&request.logical_operation_id))
            .cloned();
        let mut effect_refs = vec![
            tombstone.tombstone_digest.clone(),
            entry.affected.affected_digest.clone(),
            authorization.authorization_digest().clone(),
            authorization.binding_digest().clone(),
            consumption.receipt_digest().clone(),
        ];
        let outcome = if let Some(record) = existing_operator_rollback {
            effect_refs.push(record.record_digest.clone());
            effect_refs.push(record.recovery_receipt.receipt_digest.clone());
            RevocationContainmentOutcomeV1::RolledBack
        } else if let Some(pending) = &state.in_flight {
            effect_refs.push(ContentDigest::from_bytes(&canonical_json(&(
                pending.cycle_id.clone(),
                pending.stage,
            ))?));
            RevocationContainmentOutcomeV1::ContainmentRequired
        } else if state.active_package_digest == *plan.receiver_local_package_digest() {
            match self.m5.operator_revert_active(
                rollback_id,
                plan.receiver_local_package_digest(),
                format!("revocation:{}", tombstone.tombstone_digest.file_stem()),
            ) {
                Ok(record) => {
                    effect_refs.push(record.record_digest.clone());
                    effect_refs.push(record.recovery_receipt.receipt_digest.clone());
                    RevocationContainmentOutcomeV1::RolledBack
                }
                Err(error) => {
                    effect_refs.push(ContentDigest::from_bytes(error.to_string().as_bytes()));
                    RevocationContainmentOutcomeV1::ContainmentRequired
                }
            }
        } else if state.active_package_digest == request.expected_active_package_digest {
            if let Some(cycle) = source_cycle {
                effect_refs.push(cycle.record_digest.clone());
                if let Some(recovery) = cycle.recovery_receipt {
                    effect_refs.push(recovery.receipt_digest);
                    RevocationContainmentOutcomeV1::RolledBack
                } else if current == TransactionStage::ActivationIntentRecorded {
                    RevocationContainmentOutcomeV1::CancelledBeforeActivation
                } else {
                    RevocationContainmentOutcomeV1::ContainmentRequired
                }
            } else if current == TransactionStage::ActivationIntentRecorded
                || current == TransactionStage::RollbackIntentRecorded
            {
                RevocationContainmentOutcomeV1::CancelledBeforeActivation
            } else {
                RevocationContainmentOutcomeV1::ContainmentRequired
            }
        } else {
            effect_refs.push(state.state_digest);
            RevocationContainmentOutcomeV1::ContainmentRequired
        };
        let resolution = self.revocations.resolve_containment(
            &entry.affected.affected_digest,
            outcome,
            effect_refs,
        )?;
        self.finish_effectful_import_projection(
            &request,
            &import_coordinator_request_digest,
            &resolution,
        )?;
        Ok(resolution)
    }

    fn finish_effectful_import_projection(
        &self,
        request: &ReceiverIntakeRequest,
        import_coordinator_request_digest: &ContentDigest,
        resolution: &RevocationContainmentResolutionV1,
    ) -> Result<(), M6ReceiverError> {
        let current = self
            .journal
            .transaction(&request.logical_operation_id)?
            .and_then(|projection| projection.current_stage())
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "revocation containment lost the import lifecycle stage".to_string(),
                )
            })?;
        if current.is_terminal() {
            return Ok(());
        }
        match resolution.outcome {
            RevocationContainmentOutcomeV1::CancelledBeforeActivation
            | RevocationContainmentOutcomeV1::RolledBack => {
                self.ensure_import_stage(
                    request,
                    TransactionStage::RolledBack,
                    StageCause::Revocation,
                    1,
                    None,
                    Some(import_coordinator_request_digest.clone()),
                    vec![
                        resolution.affected_digest.clone(),
                        resolution.resolution_digest.clone(),
                    ],
                    Some(resolution.resolution_digest.clone()),
                    Some(resolution.resolution_digest.clone()),
                )?;
            }
            RevocationContainmentOutcomeV1::ContainmentRequired => {
                self.ensure_import_stage(
                    request,
                    TransactionStage::ContainmentRequired,
                    StageCause::EffectConflict,
                    1,
                    None,
                    None,
                    vec![
                        resolution.affected_digest.clone(),
                        resolution.resolution_digest.clone(),
                    ],
                    None,
                    None,
                )?;
            }
            outcome => {
                return Err(M6ReceiverError::Integrity(format!(
                    "effectful import resolved to non-effectful outcome {outcome:?}"
                )));
            }
        }
        Ok(())
    }

    pub fn contain_revocation(
        &mut self,
        logical_operation_id: &str,
        rollback_authorities: &[ReceiverRevocationRollbackAuthority],
    ) -> Result<ReceiverRevocationApplicationResult, M6ReceiverError> {
        self.contain_revocation_with_fault(logical_operation_id, rollback_authorities, None)
    }

    pub fn recover_revocation_containment(
        &mut self,
        logical_operation_id: &str,
        rollback_authorities: &[ReceiverRevocationRollbackAuthority],
    ) -> Result<ReceiverRevocationApplicationResult, M6ReceiverError> {
        self.contain_revocation(logical_operation_id, rollback_authorities)
    }

    pub fn contain_revocation_with_fault(
        &mut self,
        logical_operation_id: &str,
        rollback_authorities: &[ReceiverRevocationRollbackAuthority],
        crash_at: Option<ReceiverCrashPoint>,
    ) -> Result<ReceiverRevocationApplicationResult, M6ReceiverError> {
        validate_identifier("receiver revocation operation id", logical_operation_id)?;
        self.require_no_other_pending_revocation(logical_operation_id)?;
        let operation_root =
            revocation_operation_root(&self.revocation_operations_root, logical_operation_id);
        let request = load_revocation_request_unit(
            &operation_root,
            self.route(),
            &self.revocations.config().config_digest,
        )?;
        let raw: RawQuarantineRecord =
            load_canonical_file(&operation_root.join(RAW_RECORD_FILE), MAX_RECORD_BYTES)?;
        self.quarantine.read_committed_unit(&raw)?;
        let tombstone = self
            .revocations
            .tombstone(&request.message_digest)?
            .ok_or_else(|| {
                M6ReceiverError::InvalidState(
                    "receiver revocation containment requires a durable tombstone".to_string(),
                )
            })?;
        let matches: ReceiverRevocationMatchSet = load_canonical_file(
            &operation_root.join(REVOCATION_MATCH_SET_FILE),
            MAX_RECORD_BYTES,
        )?;
        matches.validate(&request, &tombstone)?;
        let coordinator_request_digest = self.coordinator_request_digest(logical_operation_id)?;

        let mut authority_by_import = BTreeMap::new();
        for authority in rollback_authorities {
            validate_identifier(
                "revocation rollback import operation id",
                &authority.import_logical_operation_id,
            )?;
            if authority_by_import
                .insert(
                    authority.import_logical_operation_id.clone(),
                    authority.rollback_authorization_digest.clone(),
                )
                .is_some()
            {
                return Err(M6ReceiverError::InvalidConfiguration(format!(
                    "duplicate rollback authority for import '{}'",
                    authority.import_logical_operation_id
                )));
            }
        }

        let requires_effect_boundary = matches.affected_operations.iter().any(|entry| {
            matches!(
                entry.affected.required_action,
                RequiredContainmentActionV1::CancelAtEffectSafeBoundary
                    | RequiredContainmentActionV1::StopAdmissionAndRollback
                    | RequiredContainmentActionV1::KeepServingDisabled
            )
        });
        if requires_effect_boundary {
            self.ensure_revocation_stage(
                &request,
                &coordinator_request_digest,
                TransactionStage::RevocationContainmentIntentRecorded,
                StageCause::Revocation,
                1,
                Some(self.rollback_authority.profile().profile_digest().clone()),
                Some(coordinator_request_digest.clone()),
                vec![
                    tombstone.tombstone_digest.clone(),
                    matches.record_digest.clone(),
                ],
                None,
                None,
            )?;
            maybe_crash(
                crash_at,
                ReceiverCrashPoint::RevocationContainmentIntentRecorded,
            )?;
        }

        let mut resolved_operations = Vec::with_capacity(matches.affected_operations.len());
        for entry in &matches.affected_operations {
            let resolution = match entry.affected.required_action {
                RequiredContainmentActionV1::RejectBeforeApproval
                | RequiredContainmentActionV1::RetainHistoricalTombstone => {
                    self.resolve_pre_effect_import(entry, &tombstone)?
                }
                RequiredContainmentActionV1::CancelAtEffectSafeBoundary
                | RequiredContainmentActionV1::StopAdmissionAndRollback => {
                    let rollback_authorization_digest = authority_by_import
                        .get(&entry.import_logical_operation_id)
                        .ok_or_else(|| {
                            M6ReceiverError::InvalidState(format!(
                                "revocation containment requires the exact prior Rollback authorization for import '{}'",
                                entry.import_logical_operation_id
                            ))
                        })?;
                    self.resolve_effectful_import(entry, &tombstone, rollback_authorization_digest)?
                }
                RequiredContainmentActionV1::KeepServingDisabled => {
                    self.revocations.resolve_containment(
                        &entry.affected.affected_digest,
                        RevocationContainmentOutcomeV1::ContainmentRequired,
                        vec![
                            tombstone.tombstone_digest.clone(),
                            entry.affected.affected_digest.clone(),
                        ],
                    )?
                }
            };
            resolved_operations.push(ReceiverRevocationResolvedOperation {
                import_logical_operation_id: entry.import_logical_operation_id.clone(),
                resolution,
            });
        }
        maybe_crash(
            crash_at,
            ReceiverCrashPoint::RevocationContainmentEffectsCommitted,
        )?;
        let final_active = self.m5.active_runtime_snapshot()?;
        let requested_receipt = ReceiverRevocationApplicationReceipt::new(
            &request,
            &matches,
            resolved_operations,
            final_active.snapshot_digest,
            self.now_ms()?,
        )?;
        let receipt_path = operation_root.join(REVOCATION_RECEIPT_FILE);
        let receipt = if receipt_path.exists() {
            let existing: ReceiverRevocationApplicationReceipt =
                load_canonical_file(&receipt_path, MAX_RECORD_BYTES)?;
            existing.validate(&request, &matches)?;
            if existing.resolved_operations != requested_receipt.resolved_operations
                || existing.containment_required != requested_receipt.containment_required
                || existing.final_active_snapshot_digest
                    != requested_receipt.final_active_snapshot_digest
            {
                return Err(M6ReceiverError::Conflict {
                    identity: request.logical_operation_id.clone(),
                    existing: existing.receipt_digest,
                    requested: requested_receipt.receipt_digest,
                });
            }
            existing
        } else {
            persist_immutable_file(&receipt_path, &canonical_json(&requested_receipt)?)?;
            requested_receipt
        };
        let terminal = if receipt.containment_required {
            self.ensure_revocation_stage(
                &request,
                &coordinator_request_digest,
                TransactionStage::RevocationContainmentRequired,
                StageCause::EffectConflict,
                1,
                None,
                None,
                vec![
                    receipt.receipt_digest.clone(),
                    tombstone.tombstone_digest.clone(),
                    matches.record_digest.clone(),
                ],
                None,
                None,
            )?
        } else {
            self.ensure_revocation_stage(
                &request,
                &coordinator_request_digest,
                TransactionStage::RevocationContained,
                StageCause::Normal,
                1,
                None,
                Some(coordinator_request_digest.clone()),
                vec![
                    receipt.receipt_digest.clone(),
                    tombstone.tombstone_digest.clone(),
                    matches.record_digest.clone(),
                ],
                Some(receipt.receipt_digest.clone()),
                Some(receipt.final_active_snapshot_digest.clone()),
            )?
        };
        maybe_crash(crash_at, ReceiverCrashPoint::RevocationTerminalCommitted)?;
        let disposition = if receipt.containment_required {
            "revocation_containment_required"
        } else {
            "revocation_contained"
        };
        let acknowledgement = self.publish_acknowledgement_for_context(
            operation_root,
            &request.logical_operation_id,
            &request.request_digest,
            &request.message_digest,
            disposition,
            raw.raw_unit_digest,
            &terminal,
            crash_at,
        )?;
        if receipt.containment_required {
            Ok(ReceiverRevocationApplicationResult::ContainmentRequired {
                receipt,
                acknowledgement,
            })
        } else {
            Ok(ReceiverRevocationApplicationResult::Contained {
                receipt,
                acknowledgement,
            })
        }
    }

    pub fn load_revocation_completion_evidence(
        &self,
        logical_operation_id: &str,
        sender_publication: &SenderRevocationPublicationEvidenceV1,
    ) -> Result<Option<ReceiverRevocationCompletionEvidenceV1>, M6ReceiverError> {
        validate_identifier(
            "receiver revocation completion operation id",
            logical_operation_id,
        )?;
        let operation_root =
            revocation_operation_root(&self.revocation_operations_root, logical_operation_id);
        let receipt_path = operation_root.join(REVOCATION_RECEIPT_FILE);
        if !receipt_path.exists() {
            return Ok(None);
        }
        let sender_publication_evidence_bytes = sender_publication
            .canonical_bytes_detached(self.route())
            .map_err(|error| M6ReceiverError::Integrity(error.to_string()))?;
        let receiver_request_bytes =
            read_regular_bounded(&operation_root.join(REQUEST_FILE), MAX_REQUEST_BYTES)?;
        let request: ReceiverRevocationRequest =
            parse_canonical(&receiver_request_bytes, MAX_REQUEST_BYTES)?;
        request.validate(self.route(), &self.revocations.config().config_digest)?;
        if sender_publication.message_digest() != &request.message_digest {
            return Err(M6ReceiverError::Integrity(
                "sender revocation publication differs from receiver intake request".to_string(),
            ));
        }
        let raw: RawQuarantineRecord =
            load_canonical_file(&operation_root.join(RAW_RECORD_FILE), MAX_RECORD_BYTES)?;
        let raw_unit = self.quarantine.read_committed_unit(&raw)?;
        let raw_unit_files = raw_unit.files().clone();
        let signed_revocation_manifest_bytes = raw_unit_files
            .get("manifest.json")
            .cloned()
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "receiver revocation completion lacks signed manifest bytes".to_string(),
                )
            })?;
        let tombstone = self
            .revocations
            .tombstone(&request.message_digest)?
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "receiver revocation completion lacks durable tombstone".to_string(),
                )
            })?;
        let matches: ReceiverRevocationMatchSet = load_canonical_file(
            &operation_root.join(REVOCATION_MATCH_SET_FILE),
            MAX_RECORD_BYTES,
        )?;
        matches.validate(&request, &tombstone)?;
        let receipt: ReceiverRevocationApplicationReceipt =
            load_canonical_file(&receipt_path, MAX_RECORD_BYTES)?;
        receipt.validate(&request, &matches)?;
        if receipt.containment_required || matches.affected_operations.is_empty() {
            return Err(M6ReceiverError::InvalidState(
                "portable revocation completion requires contained affected work".to_string(),
            ));
        }
        let projection = self
            .journal
            .transaction(logical_operation_id)?
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "receiver revocation completion lacks coordinator projection".to_string(),
                )
            })?;
        let terminal_stage_digest = projection
            .current_record()
            .ok_or_else(|| {
                M6ReceiverError::Integrity(
                    "receiver revocation completion lacks terminal stage".to_string(),
                )
            })?
            .stage_digest
            .clone();
        let state = self.m5.state_snapshot()?;
        let effect_audit = self.m5.audit_active_executions(&[])?;
        let effect_audit_bytes = canonical_json(&effect_audit)?;
        let mut affected_sources = Vec::with_capacity(matches.affected_operations.len());
        for affected in &matches.affected_operations {
            let resolved = receipt
                .resolved_operations
                .iter()
                .find(|entry| {
                    entry.import_logical_operation_id == affected.import_logical_operation_id
                })
                .ok_or_else(|| {
                    M6ReceiverError::Integrity(
                        "receiver revocation receipt lost an affected operation".to_string(),
                    )
                })?;
            if resolved.resolution.outcome != RevocationContainmentOutcomeV1::RolledBack {
                return Err(M6ReceiverError::InvalidState(format!(
                    "affected import '{}' did not complete a real rollback",
                    affected.import_logical_operation_id
                )));
            }
            let import_completion = self
                .load_exchange_completion_evidence(&affected.import_logical_operation_id)?
                .ok_or_else(|| {
                    M6ReceiverError::Integrity(format!(
                        "affected import '{}' lacks exact exchange completion evidence",
                        affected.import_logical_operation_id
                    ))
                })?;
            let rollback_source = import_completion
                .authority_sources
                .iter()
                .find(|source| source.action == AuthorityAction::RollbackImport)
                .ok_or_else(|| {
                    M6ReceiverError::Integrity(
                        "affected import completion lacks rollback authority".to_string(),
                    )
                })?;
            let operator = state
                .operator_rollbacks
                .iter()
                .find(|record| {
                    resolved
                        .resolution
                        .authoritative_effect_refs
                        .contains(&record.record_digest)
                })
                .cloned()
                .ok_or_else(|| {
                    M6ReceiverError::Integrity(
                        "rolled-back revocation resolution lacks its M5 operator rollback record"
                            .to_string(),
                    )
                })?;
            let mut source = ReceiverRevocationAffectedCompletionSourceV1 {
                import_logical_operation_id: affected.import_logical_operation_id.clone(),
                affected: affected.affected.clone(),
                resolution: resolved.resolution.clone(),
                import_completion_bytes: import_completion
                    .canonical_bytes_detached(self.route())?,
                rollback_authority_profile_bytes: rollback_source.profile_bytes.clone(),
                rollback_authorization_bytes: rollback_source.authorization_bytes.clone(),
                rollback_consumption_bytes: rollback_source.consumption_bytes.clone(),
                operator_rollback_record_bytes: canonical_json(&operator)?,
                post_rollback_effect_audit_bytes: effect_audit_bytes.clone(),
                source_digest: ContentDigest::from_bytes(&[]),
            };
            source.source_digest = source.expected_digest()?;
            source.validate(
                self.route(),
                &tombstone,
                &receipt.final_active_snapshot_digest,
            )?;
            affected_sources.push(source);
        }
        let acknowledgement_request_bytes =
            read_regular_bounded(&operation_root.join(ACK_REQUEST_FILE), MAX_RECORD_BYTES)?;
        let acknowledgement_receipt_bytes =
            read_regular_bounded(&operation_root.join(ACK_RECEIPT_FILE), MAX_RECORD_BYTES)?;
        let acknowledgement: ReceiverAcknowledgementReceipt =
            parse_canonical(&acknowledgement_receipt_bytes, MAX_RECORD_BYTES)?;
        let acknowledgement_ready = self
            .spool
            .read_outbound_ready(&acknowledgement.acknowledgement_message_digest)?;
        let acknowledgement_manifest_bytes = acknowledgement_ready.manifest.canonical_bytes()?;
        let mut evidence = ReceiverRevocationCompletionEvidenceV1 {
            schema: RECEIVER_REVOCATION_COMPLETION_EVIDENCE_SCHEMA.to_string(),
            route_definition_digest: self.route().definition_digest.clone(),
            signing_key_id: self.signer.signing_key_id().to_string(),
            logical_operation_id: logical_operation_id.to_string(),
            sender_message_digest: request.message_digest,
            sender_publication_evidence_digest: sender_publication.evidence_digest().clone(),
            sender_sequence: sender_publication.sequence(),
            sender_previous_message_digest: sender_publication.previous_message_digest().cloned(),
            sender_issued_at_ms: sender_publication.issued_at_ms(),
            sender_committed_at_ms: sender_publication.committed_at_ms(),
            prior_source_authorization_evidence_digest: sender_publication
                .prior_source_authorization_evidence_digest()
                .clone(),
            tombstone_digest: tombstone.tombstone_digest.clone(),
            receiver_containment_receipt_digest: receipt.receipt_digest.clone(),
            final_active_snapshot_digest: receipt.final_active_snapshot_digest.clone(),
            terminal_stage_digest,
            acknowledgement_message_digest: acknowledgement.acknowledgement_message_digest,
            sender_publication_evidence_bytes,
            receiver_request_bytes,
            raw_quarantine_record_bytes: canonical_json(&raw)?,
            raw_unit_files,
            signed_revocation_manifest_bytes,
            tombstone_bytes: canonical_json(&tombstone)?,
            match_set_bytes: canonical_json(&matches)?,
            affected_sources,
            receiver_coordinator_projection_bytes: projection.canonical_bytes()?,
            receiver_containment_receipt_bytes: canonical_json(&receipt)?,
            acknowledgement_request_bytes,
            acknowledgement_manifest_bytes,
            acknowledgement_receipt_bytes,
            evidence_digest: ContentDigest::from_bytes(&[]),
            source_set_signature_hex: String::new(),
        };
        evidence.evidence_digest = evidence.expected_digest()?;
        evidence.source_set_signature_hex = self
            .signer
            .sign_receiver_revocation_completion(self.route(), &evidence.evidence_digest)?;
        evidence.validate_detached(self.route())?;
        Ok(Some(evidence))
    }
}
