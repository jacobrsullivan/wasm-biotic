//! Sequential sender-side publication of authenticated M6 revocations.
//!
//! A revocation prepare is deliberately separate from its current
//! [`AuthorityAction::IssueRevocation`] credential. The signed
//! [`RevocationManifestPayload::authorization_digest`] is the immutable
//! evidence identity for the prior source publication or target authority
//! being revoked. The current credential is issued only after the exact
//! signed message exists, and binds that message through
//! [`ExactActionBinding`]. This avoids a circular message/authorization
//! digest while retaining both identities in the journal and receipt.
//!
//! This runtime owns no M5 handle and accepts no peer endpoint root. It shares
//! the sender endpoint owner lock, sender-role [`ManifestIssuer`], and neutral
//! route spool with export publication. Export and revocation therefore run
//! sequentially on one origin sequence.

use crate::execution::artifact::ContentDigest;
use crate::m6_authority::{
    ActionAuthorization, AuthorityAction, AuthorizationConsumption, AuthorizationStore,
    EndpointActionProfile, EndpointAuthorityKind, ExactActionBinding, M6AuthorityError,
    OpaqueAuthorizationVerifier,
};
use crate::m6_identity::{
    Clock, FactorySigner, GovernedFilesystemSpool, IssuedManifest, M6IdentityError, ManifestIssuer,
    ManifestKind, ManifestPayload, NonceSource, PreparedIssuanceAbandonment,
    PreparedIssuanceDisposition, PreparedIssuanceResolution, RevocationManifestPayload,
    RouteDefinition, RouteEndpointRole, verify_sender_revocation_completion_signature,
};
use crate::m6_revocation::RevocationTargetKindV1;
use crate::m6_sender_runtime::acquire_sender_endpoint_owner;
use crate::m6_transactions::{
    CoordinatorJournal, JournalConfig, M6TransactionError, RetryPolicy, StageCause, StageEvidence,
    TransactionKind, TransactionProjection, TransactionRequestDraft, TransactionStage,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub const SENDER_REVOCATION_REQUEST_SCHEMA: &str = "wasm-biotic.m6-sender-revocation-request.v1";
pub const SENDER_REVOCATION_RECEIPT_SCHEMA: &str = "wasm-biotic.m6-sender-revocation-receipt.v1";
pub const SENDER_REVOCATION_ABANDONMENT_SCHEMA: &str =
    "wasm-biotic.m6-sender-revocation-abandonment.v1";
pub const SENDER_REVOCATION_PUBLICATION_EVIDENCE_SCHEMA: &str =
    "wasm-biotic.m6-sender-revocation-publication-evidence.v1";

const REQUEST_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-revocation-request:v1\0";
const REQUEST_CONFLICT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-revocation-request-conflict:v1\0";
const RECEIPT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-revocation-receipt:v1\0";
const ABANDONMENT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-revocation-abandonment:v1\0";
const DELIVERY_FACT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-revocation-delivery-fact:v1\0";
const PUBLICATION_EVIDENCE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:sender-revocation-publication-evidence:v1\0";
const NOT_APPLICABLE_ACTIVE_SNAPSHOT: &[u8] =
    b"wasm-biotic:m6:sender-revocation:no-active-snapshot:v1";
const NOT_APPLICABLE_IMPORT_PLAN: &[u8] = b"wasm-biotic:m6:sender-revocation:no-import-plan:v1";
const NOT_APPLICABLE_PROVING: &[u8] = b"wasm-biotic:m6:sender-revocation:no-receiver-proving:v1";

const AUTHORITY_DIRECTORY: &str = "m6-sender-revocation-authority";
const JOURNAL_DIRECTORY: &str = "m6-sender-revocation-coordinator";
const REQUESTS_DIRECTORY: &str = "m6-sender-revocation-requests";
const RECEIPTS_DIRECTORY: &str = "m6-sender-revocation-receipts";
const ABANDONMENTS_DIRECTORY: &str = "m6-sender-revocation-abandonments";
const STAGING_DIRECTORY: &str = "m6-sender-revocation-staging";
const RECORD_SUFFIX: &str = ".json";
const STAGING_PREFIX: &str = ".revocation-publication-";
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 4_096;
const MAX_RECORD_BYTES: usize = 512 * 1_024;
const MAX_PUBLICATION_EVIDENCE_BYTES: usize = 4 * 1_048_576;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Live-only sender revocation configuration. No path in this value is
/// serialized into durable revocation evidence.
#[derive(Clone, Debug)]
pub struct M6RevocationSenderRuntimeConfig {
    pub endpoint_root: PathBuf,
    pub route_root: PathBuf,
    pub expected_route_definition_digest: ContentDigest,
    pub authorization_profile: EndpointActionProfile,
    pub journal_config: JournalConfig,
    pub retry_policy: RetryPolicy,
    pub max_revocation_requests: u32,
    pub max_revocation_receipts: u32,
}

impl M6RevocationSenderRuntimeConfig {
    fn validate_non_path_fields(&self) -> Result<(), M6RevocationSenderError> {
        self.journal_config
            .validate()
            .map_err(M6RevocationSenderError::from)?;
        if self.endpoint_root.as_os_str().is_empty()
            || self.route_root.as_os_str().is_empty()
            || self.max_revocation_requests == 0
            || self.max_revocation_receipts == 0
            || self.max_revocation_receipts > self.max_revocation_requests
            || self.max_revocation_requests > self.journal_config.max_transactions
            || self.journal_config.max_stages_per_transaction < 5
            || self.retry_policy.max_attempts == 0
            || self.retry_policy.max_attempts > 32
            || self.retry_policy.max_recovery_attempts > self.retry_policy.max_attempts
            || self.retry_policy.attempt_timeout_ms == 0
            || self.authorization_profile.authority_kind() != EndpointAuthorityKind::Revocation
            || !self
                .authorization_profile
                .supports(AuthorityAction::IssueRevocation)
        {
            return Err(M6RevocationSenderError::InvalidConfiguration(
                "revocation sender roots, bounds, retry policy, or authority profile are invalid"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderRevocationRequest {
    schema: String,
    logical_operation_id: String,
    principal_id: String,
    issuance_idempotency_key: String,
    captured_at_ms: u64,
    message_lifetime_ms: u64,
    route_id: String,
    route_generation: u64,
    route_definition_digest: ContentDigest,
    sender_identity_document_digest: ContentDigest,
    receiver_identity_document_digest: ContentDigest,
    exchange_policy_digest: ContentDigest,
    resource_profile_digest: ContentDigest,
    target_kind: RevocationTargetKindV1,
    target_identity: ContentDigest,
    reason: String,
    prior_source_authorization_evidence_digest: ContentDigest,
    request_digest: ContentDigest,
}

#[derive(Serialize)]
struct SenderRevocationRequestDigestMaterial<'a> {
    schema: &'a str,
    logical_operation_id: &'a str,
    principal_id: &'a str,
    issuance_idempotency_key: &'a str,
    captured_at_ms: u64,
    message_lifetime_ms: u64,
    route_id: &'a str,
    route_generation: u64,
    route_definition_digest: &'a ContentDigest,
    sender_identity_document_digest: &'a ContentDigest,
    receiver_identity_document_digest: &'a ContentDigest,
    exchange_policy_digest: &'a ContentDigest,
    resource_profile_digest: &'a ContentDigest,
    target_kind: RevocationTargetKindV1,
    target_identity: &'a ContentDigest,
    reason: &'a str,
    prior_source_authorization_evidence_digest: &'a ContentDigest,
}

impl SenderRevocationRequest {
    #[allow(clippy::too_many_arguments)]
    fn new(
        logical_operation_id: String,
        principal_id: String,
        captured_at_ms: u64,
        message_lifetime_ms: u64,
        target_kind: RevocationTargetKindV1,
        target_identity: ContentDigest,
        reason: String,
        prior_source_authorization_evidence_digest: ContentDigest,
        route: &RouteDefinition,
    ) -> Result<Self, M6RevocationSenderError> {
        validate_identifier("logical operation id", &logical_operation_id)?;
        validate_identifier("revocation principal id", &principal_id)?;
        validate_reason(&reason)?;
        require_meaningful_digest("revocation target", &target_identity)?;
        require_meaningful_digest(
            "prior source authorization evidence",
            &prior_source_authorization_evidence_digest,
        )?;
        let issuance_idempotency_key = format!("sender-revocation:{logical_operation_id}");
        validate_identifier("issuance idempotency key", &issuance_idempotency_key)?;
        let mut request = Self {
            schema: SENDER_REVOCATION_REQUEST_SCHEMA.to_string(),
            logical_operation_id,
            principal_id,
            issuance_idempotency_key,
            captured_at_ms,
            message_lifetime_ms,
            route_id: route.route_id.clone(),
            route_generation: route.generation,
            route_definition_digest: route.definition_digest.clone(),
            sender_identity_document_digest: route.sender.identity_document_digest.clone(),
            receiver_identity_document_digest: route.receiver.identity_document_digest.clone(),
            exchange_policy_digest: route.exchange_policy_digest.clone(),
            resource_profile_digest: route.resource_profile.profile_digest.clone(),
            target_kind,
            target_identity,
            reason,
            prior_source_authorization_evidence_digest,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = request.expected_digest()?;
        request.validate(route)?;
        Ok(request)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6RevocationSenderError> {
        route.validate().map_err(M6RevocationSenderError::from)?;
        validate_identifier("logical operation id", &self.logical_operation_id)?;
        validate_identifier("revocation principal id", &self.principal_id)?;
        validate_identifier("issuance idempotency key", &self.issuance_idempotency_key)?;
        validate_reason(&self.reason)?;
        require_meaningful_digest("revocation target", &self.target_identity)?;
        require_meaningful_digest(
            "prior source authorization evidence",
            &self.prior_source_authorization_evidence_digest,
        )?;
        if self.schema != SENDER_REVOCATION_REQUEST_SCHEMA
            || self.issuance_idempotency_key
                != format!("sender-revocation:{}", self.logical_operation_id)
            || self.message_lifetime_ms == 0
            || self.message_lifetime_ms > route.resource_profile.max_revocation_lifetime_ms
            || self.route_id != route.route_id
            || self.route_generation != route.generation
            || self.route_definition_digest != route.definition_digest
            || self.sender_identity_document_digest != route.sender.identity_document_digest
            || self.receiver_identity_document_digest != route.receiver.identity_document_digest
            || self.exchange_policy_digest != route.exchange_policy_digest
            || self.resource_profile_digest != route.resource_profile.profile_digest
        {
            return Err(M6RevocationSenderError::Integrity(
                "sender revocation request differs from its exact route or bounded schema"
                    .to_string(),
            ));
        }
        require_digest(
            "sender revocation request",
            &self.request_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6RevocationSenderError> {
        digest_domain(
            REQUEST_DOMAIN,
            &SenderRevocationRequestDigestMaterial {
                schema: &self.schema,
                logical_operation_id: &self.logical_operation_id,
                principal_id: &self.principal_id,
                issuance_idempotency_key: &self.issuance_idempotency_key,
                captured_at_ms: self.captured_at_ms,
                message_lifetime_ms: self.message_lifetime_ms,
                route_id: &self.route_id,
                route_generation: self.route_generation,
                route_definition_digest: &self.route_definition_digest,
                sender_identity_document_digest: &self.sender_identity_document_digest,
                receiver_identity_document_digest: &self.receiver_identity_document_digest,
                exchange_policy_digest: &self.exchange_policy_digest,
                resource_profile_digest: &self.resource_profile_digest,
                target_kind: self.target_kind,
                target_identity: &self.target_identity,
                reason: &self.reason,
                prior_source_authorization_evidence_digest: &self
                    .prior_source_authorization_evidence_digest,
            },
        )
    }
}

/// Exact signed prepare returned before current revocation authority exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSenderRevocation {
    pub logical_operation_id: String,
    pub request_digest: ContentDigest,
    pub issuance_request_digest: ContentDigest,
    pub target_kind: RevocationTargetKindV1,
    pub target_identity: ContentDigest,
    pub reason: String,
    /// Evidence identity for the prior publication or source authority being
    /// revoked. This is the digest carried in the signed manifest payload.
    pub prior_source_authorization_evidence_digest: ContentDigest,
    pub message_digest: ContentDigest,
    pub sequence: u64,
    pub nonce: String,
    pub previous_message_digest: Option<ContentDigest>,
    /// Current `IssueRevocation` authority must match this exact binding.
    pub authorization_binding: ExactActionBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderRevocationReceipt {
    pub schema: String,
    pub logical_operation_id: String,
    pub request_digest: ContentDigest,
    pub coordinator_request_digest: ContentDigest,
    pub route_definition_digest: ContentDigest,
    pub route_generation: u64,
    pub sender_identity_document_digest: ContentDigest,
    pub receiver_identity_document_digest: ContentDigest,
    pub target_kind: RevocationTargetKindV1,
    pub target_identity: ContentDigest,
    pub reason: String,
    /// The prior source publication/authority evidence carried by the signed
    /// revocation. It is not the current IssueRevocation credential.
    pub prior_source_authorization_evidence_digest: ContentDigest,
    pub message_digest: ContentDigest,
    pub sequence: u64,
    pub nonce: String,
    pub previous_message_digest: Option<ContentDigest>,
    pub current_revocation_authorization_digest: ContentDigest,
    pub current_revocation_binding_digest: ContentDigest,
    pub authorization_consumption_digest: ContentDigest,
    pub route_delivery_digest: ContentDigest,
    pub committed_at_ms: u64,
    pub receipt_digest: ContentDigest,
}

#[derive(Serialize)]
struct SenderRevocationReceiptDigestMaterial<'a> {
    schema: &'a str,
    logical_operation_id: &'a str,
    request_digest: &'a ContentDigest,
    coordinator_request_digest: &'a ContentDigest,
    route_definition_digest: &'a ContentDigest,
    route_generation: u64,
    sender_identity_document_digest: &'a ContentDigest,
    receiver_identity_document_digest: &'a ContentDigest,
    target_kind: RevocationTargetKindV1,
    target_identity: &'a ContentDigest,
    reason: &'a str,
    prior_source_authorization_evidence_digest: &'a ContentDigest,
    message_digest: &'a ContentDigest,
    sequence: u64,
    nonce: &'a str,
    previous_message_digest: &'a Option<ContentDigest>,
    current_revocation_authorization_digest: &'a ContentDigest,
    current_revocation_binding_digest: &'a ContentDigest,
    authorization_consumption_digest: &'a ContentDigest,
    route_delivery_digest: &'a ContentDigest,
    committed_at_ms: u64,
}

impl SenderRevocationReceipt {
    fn new(
        request: &SenderRevocationRequest,
        coordinator_request_digest: ContentDigest,
        issued: &IssuedManifest,
        authorization: &ActionAuthorization,
        consumption: &AuthorizationConsumption,
        route_delivery_digest: ContentDigest,
        committed_at_ms: u64,
    ) -> Result<Self, M6RevocationSenderError> {
        let mut receipt = Self {
            schema: SENDER_REVOCATION_RECEIPT_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            request_digest: request.request_digest.clone(),
            coordinator_request_digest,
            route_definition_digest: request.route_definition_digest.clone(),
            route_generation: request.route_generation,
            sender_identity_document_digest: request.sender_identity_document_digest.clone(),
            receiver_identity_document_digest: request.receiver_identity_document_digest.clone(),
            target_kind: request.target_kind,
            target_identity: request.target_identity.clone(),
            reason: request.reason.clone(),
            prior_source_authorization_evidence_digest: request
                .prior_source_authorization_evidence_digest
                .clone(),
            message_digest: issued.manifest.message_digest.clone(),
            sequence: issued.manifest.unsigned.sequence,
            nonce: issued.manifest.unsigned.nonce.clone(),
            previous_message_digest: issued.manifest.unsigned.previous_message_digest.clone(),
            current_revocation_authorization_digest: authorization.authorization_digest().clone(),
            current_revocation_binding_digest: authorization.binding_digest().clone(),
            authorization_consumption_digest: consumption.receipt_digest().clone(),
            route_delivery_digest,
            committed_at_ms,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate(
            request,
            &receipt.coordinator_request_digest,
            issued,
            authorization,
            consumption,
            &receipt.route_delivery_digest,
        )?;
        Ok(receipt)
    }

    fn validate(
        &self,
        request: &SenderRevocationRequest,
        coordinator_request_digest: &ContentDigest,
        issued: &IssuedManifest,
        authorization: &ActionAuthorization,
        consumption: &AuthorizationConsumption,
        route_delivery_digest: &ContentDigest,
    ) -> Result<(), M6RevocationSenderError> {
        let expected_binding = revocation_authorization_binding(request, issued)?;
        if self.schema != SENDER_REVOCATION_RECEIPT_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.request_digest != request.request_digest
            || &self.coordinator_request_digest != coordinator_request_digest
            || self.route_definition_digest != request.route_definition_digest
            || self.route_generation != request.route_generation
            || self.sender_identity_document_digest != request.sender_identity_document_digest
            || self.receiver_identity_document_digest != request.receiver_identity_document_digest
            || self.target_kind != request.target_kind
            || self.target_identity != request.target_identity
            || self.reason != request.reason
            || self.prior_source_authorization_evidence_digest
                != request.prior_source_authorization_evidence_digest
            || self.message_digest != issued.manifest.message_digest
            || self.sequence != issued.manifest.unsigned.sequence
            || self.nonce != issued.manifest.unsigned.nonce
            || self.previous_message_digest != issued.manifest.unsigned.previous_message_digest
            || self.current_revocation_authorization_digest != *authorization.authorization_digest()
            || self.current_revocation_binding_digest != *authorization.binding_digest()
            || self.authorization_consumption_digest != *consumption.receipt_digest()
            || self.route_delivery_digest != *route_delivery_digest
            || authorization.binding() != &expected_binding
            || authorization.binding().action != AuthorityAction::IssueRevocation
            || authorization.use_limit() != 1
            || consumption.authorization_digest() != authorization.authorization_digest()
            || consumption.binding_digest() != authorization.binding_digest()
            || consumption.idempotency_key() != request.issuance_idempotency_key
            || consumption.use_ordinal() != 1
            || self.committed_at_ms < consumption.consumed_at_ms()
        {
            return Err(M6RevocationSenderError::Integrity(
                "sender revocation receipt is missing or cross-linked".to_string(),
            ));
        }
        require_digest(
            "sender revocation receipt",
            &self.receipt_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6RevocationSenderError> {
        digest_domain(
            RECEIPT_DOMAIN,
            &SenderRevocationReceiptDigestMaterial {
                schema: &self.schema,
                logical_operation_id: &self.logical_operation_id,
                request_digest: &self.request_digest,
                coordinator_request_digest: &self.coordinator_request_digest,
                route_definition_digest: &self.route_definition_digest,
                route_generation: self.route_generation,
                sender_identity_document_digest: &self.sender_identity_document_digest,
                receiver_identity_document_digest: &self.receiver_identity_document_digest,
                target_kind: self.target_kind,
                target_identity: &self.target_identity,
                reason: &self.reason,
                prior_source_authorization_evidence_digest: &self
                    .prior_source_authorization_evidence_digest,
                message_digest: &self.message_digest,
                sequence: self.sequence,
                nonce: &self.nonce,
                previous_message_digest: &self.previous_message_digest,
                current_revocation_authorization_digest: &self
                    .current_revocation_authorization_digest,
                current_revocation_binding_digest: &self.current_revocation_binding_digest,
                authorization_consumption_digest: &self.authorization_consumption_digest,
                route_delivery_digest: &self.route_delivery_digest,
                committed_at_ms: self.committed_at_ms,
            },
        )
    }
}

/// Sender-signed, source-complete proof that an exact revocation statement
/// crossed the sender publication boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderRevocationPublicationEvidenceV1 {
    schema: String,
    route_definition_digest: ContentDigest,
    route_generation: u64,
    signing_key_id: String,
    logical_operation_id: String,
    message_digest: ContentDigest,
    sequence: u64,
    previous_message_digest: Option<ContentDigest>,
    issued_at_ms: u64,
    committed_at_ms: u64,
    target_kind: RevocationTargetKindV1,
    target_identity: ContentDigest,
    prior_source_authorization_evidence_digest: ContentDigest,
    sender_receipt_digest: ContentDigest,
    terminal_stage_digest: ContentDigest,
    request_bytes: Vec<u8>,
    authority_profile_bytes: Vec<u8>,
    authorization_bytes: Vec<u8>,
    authorization_consumption_bytes: Vec<u8>,
    signed_manifest_bytes: Vec<u8>,
    coordinator_projection_bytes: Vec<u8>,
    sender_receipt_bytes: Vec<u8>,
    evidence_digest: ContentDigest,
    source_set_signature_hex: String,
}

#[derive(Serialize)]
struct SenderRevocationPublicationDigestMaterial<'a> {
    schema: &'a str,
    route_definition_digest: &'a ContentDigest,
    route_generation: u64,
    signing_key_id: &'a str,
    logical_operation_id: &'a str,
    message_digest: &'a ContentDigest,
    sequence: u64,
    previous_message_digest: &'a Option<ContentDigest>,
    issued_at_ms: u64,
    committed_at_ms: u64,
    target_kind: RevocationTargetKindV1,
    target_identity: &'a ContentDigest,
    prior_source_authorization_evidence_digest: &'a ContentDigest,
    sender_receipt_digest: &'a ContentDigest,
    terminal_stage_digest: &'a ContentDigest,
    request_bytes_digest: ContentDigest,
    authority_profile_bytes_digest: ContentDigest,
    authorization_bytes_digest: ContentDigest,
    authorization_consumption_bytes_digest: ContentDigest,
    signed_manifest_bytes_digest: ContentDigest,
    coordinator_projection_bytes_digest: ContentDigest,
    sender_receipt_bytes_digest: ContentDigest,
}

impl SenderRevocationPublicationEvidenceV1 {
    pub fn logical_operation_id(&self) -> &str {
        &self.logical_operation_id
    }

    pub fn message_digest(&self) -> &ContentDigest {
        &self.message_digest
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn previous_message_digest(&self) -> Option<&ContentDigest> {
        self.previous_message_digest.as_ref()
    }

    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    pub fn committed_at_ms(&self) -> u64 {
        self.committed_at_ms
    }

    pub fn target_kind(&self) -> RevocationTargetKindV1 {
        self.target_kind
    }

    pub fn target_identity(&self) -> &ContentDigest {
        &self.target_identity
    }

    pub fn prior_source_authorization_evidence_digest(&self) -> &ContentDigest {
        &self.prior_source_authorization_evidence_digest
    }

    pub fn sender_receipt_digest(&self) -> &ContentDigest {
        &self.sender_receipt_digest
    }

    pub fn evidence_digest(&self) -> &ContentDigest {
        &self.evidence_digest
    }

    pub fn signed_manifest_bytes(&self) -> &[u8] {
        &self.signed_manifest_bytes
    }

    pub fn canonical_bytes_detached(
        &self,
        route: &RouteDefinition,
    ) -> Result<Vec<u8>, M6RevocationSenderError> {
        self.validate_detached(route)?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_PUBLICATION_EVIDENCE_BYTES {
            return Err(M6RevocationSenderError::ResourceExhausted(
                "sender revocation publication evidence exceeds its byte budget".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes_detached(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6RevocationSenderError> {
        if bytes.is_empty() || bytes.len() > MAX_PUBLICATION_EVIDENCE_BYTES {
            return Err(M6RevocationSenderError::ResourceExhausted(
                "sender revocation publication evidence exceeds its byte budget".to_string(),
            ));
        }
        let evidence: Self = parse_canonical(bytes)?;
        evidence.validate_detached(route)?;
        Ok(evidence)
    }

    fn validate_detached(&self, route: &RouteDefinition) -> Result<(), M6RevocationSenderError> {
        if self.schema != SENDER_REVOCATION_PUBLICATION_EVIDENCE_SCHEMA
            || self.route_definition_digest != route.definition_digest
            || self.route_generation != route.generation
            || self.signing_key_id != route.sender.signing_key_id
        {
            return Err(M6RevocationSenderError::Integrity(
                "sender revocation publication evidence belongs to another route or schema"
                    .to_string(),
            ));
        }
        validate_identifier(
            "sender revocation publication operation id",
            &self.logical_operation_id,
        )?;
        let request: SenderRevocationRequest = parse_canonical(&self.request_bytes)?;
        request.validate(route)?;
        let profile = EndpointActionProfile::from_canonical_bytes(&self.authority_profile_bytes)?;
        if profile.authority_kind() != EndpointAuthorityKind::Revocation
            || !profile.supports(AuthorityAction::IssueRevocation)
            || profile.factory_id() != route.sender.factory_id
        {
            return Err(M6RevocationSenderError::Integrity(
                "sender revocation publication authority profile is not the route sender"
                    .to_string(),
            ));
        }
        let authorization = ActionAuthorization::from_endpoint_attested_canonical_bytes(
            &self.authorization_bytes,
            &profile,
        )?;
        let consumption = AuthorizationConsumption::from_canonical_bytes(
            &self.authorization_consumption_bytes,
            &authorization,
        )?;
        let manifest =
            crate::m6_identity::SignedManifest::from_canonical_bytes(&self.signed_manifest_bytes)?;
        let issued = IssuedManifest {
            attachments: Default::default(),
            manifest,
        };
        validate_issued(&request, &issued, route)?;
        let projection =
            TransactionProjection::from_canonical_bytes(&self.coordinator_projection_bytes)?;
        let terminal = projection.current_record().ok_or_else(|| {
            M6RevocationSenderError::Integrity(
                "sender revocation publication projection has no terminal stage".to_string(),
            )
        })?;
        let receipt: SenderRevocationReceipt = parse_canonical(&self.sender_receipt_bytes)?;
        let delivery_digest = delivery_fact_digest(&issued)?;
        receipt.validate(
            &request,
            &projection.intent.request_digest,
            &issued,
            &authorization,
            &consumption,
            &delivery_digest,
        )?;
        if request.logical_operation_id != self.logical_operation_id
            || request.target_kind != self.target_kind
            || request.target_identity != self.target_identity
            || request.prior_source_authorization_evidence_digest
                != self.prior_source_authorization_evidence_digest
            || issued.manifest.message_digest != self.message_digest
            || issued.manifest.unsigned.sequence != self.sequence
            || issued.manifest.unsigned.previous_message_digest != self.previous_message_digest
            || issued.manifest.unsigned.issued_at_ms != self.issued_at_ms
            || receipt.receipt_digest != self.sender_receipt_digest
            || receipt.sequence != self.sequence
            || receipt.previous_message_digest != self.previous_message_digest
            || receipt.committed_at_ms != self.committed_at_ms
            || self.committed_at_ms < self.issued_at_ms
            || projection.intent.kind != TransactionKind::SenderRevocationPublication
            || projection.intent.logical_operation_id != self.logical_operation_id
            || projection.intent.message_digest != self.message_digest
            || terminal.stage != TransactionStage::RevocationReceiptCommitted
            || terminal.stage_digest != self.terminal_stage_digest
            || !terminal
                .evidence
                .evidence_refs
                .contains(&receipt.receipt_digest)
        {
            return Err(M6RevocationSenderError::Integrity(
                "sender revocation publication sources are cross-linked".to_string(),
            ));
        }
        require_digest(
            "sender revocation publication evidence",
            &self.evidence_digest,
            &self.expected_digest()?,
        )?;
        verify_sender_revocation_completion_signature(
            route,
            &self.signing_key_id,
            &self.evidence_digest,
            &self.source_set_signature_hex,
        )
        .map_err(M6RevocationSenderError::from)
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6RevocationSenderError> {
        digest_domain(
            PUBLICATION_EVIDENCE_DOMAIN,
            &SenderRevocationPublicationDigestMaterial {
                schema: &self.schema,
                route_definition_digest: &self.route_definition_digest,
                route_generation: self.route_generation,
                signing_key_id: &self.signing_key_id,
                logical_operation_id: &self.logical_operation_id,
                message_digest: &self.message_digest,
                sequence: self.sequence,
                previous_message_digest: &self.previous_message_digest,
                issued_at_ms: self.issued_at_ms,
                committed_at_ms: self.committed_at_ms,
                target_kind: self.target_kind,
                target_identity: &self.target_identity,
                prior_source_authorization_evidence_digest: &self
                    .prior_source_authorization_evidence_digest,
                sender_receipt_digest: &self.sender_receipt_digest,
                terminal_stage_digest: &self.terminal_stage_digest,
                request_bytes_digest: ContentDigest::from_bytes(&self.request_bytes),
                authority_profile_bytes_digest: ContentDigest::from_bytes(
                    &self.authority_profile_bytes,
                ),
                authorization_bytes_digest: ContentDigest::from_bytes(&self.authorization_bytes),
                authorization_consumption_bytes_digest: ContentDigest::from_bytes(
                    &self.authorization_consumption_bytes,
                ),
                signed_manifest_bytes_digest: ContentDigest::from_bytes(
                    &self.signed_manifest_bytes,
                ),
                coordinator_projection_bytes_digest: ContentDigest::from_bytes(
                    &self.coordinator_projection_bytes,
                ),
                sender_receipt_bytes_digest: ContentDigest::from_bytes(&self.sender_receipt_bytes),
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderRevocationAbandonment {
    pub schema: String,
    pub logical_operation_id: String,
    pub request_digest: ContentDigest,
    pub issuance_request_digest: ContentDigest,
    pub route_definition_digest: ContentDigest,
    pub target_kind: RevocationTargetKindV1,
    pub target_identity: ContentDigest,
    pub message_digest: ContentDigest,
    pub sequence: u64,
    pub disposition: PreparedIssuanceDisposition,
    pub reason: String,
    pub decision_evidence_digest: ContentDigest,
    pub identity_abandonment_digest: ContentDigest,
    pub abandoned_at_ms: u64,
    pub abandonment_digest: ContentDigest,
}

impl SenderRevocationAbandonment {
    fn new(
        request: &SenderRevocationRequest,
        issuance_request_digest: ContentDigest,
        abandonment: &PreparedIssuanceAbandonment,
    ) -> Result<Self, M6RevocationSenderError> {
        let mut record = Self {
            schema: SENDER_REVOCATION_ABANDONMENT_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            request_digest: request.request_digest.clone(),
            issuance_request_digest,
            route_definition_digest: request.route_definition_digest.clone(),
            target_kind: request.target_kind,
            target_identity: request.target_identity.clone(),
            message_digest: abandonment.message_digest.clone(),
            sequence: abandonment.sequence,
            disposition: abandonment.disposition,
            reason: abandonment.reason.clone(),
            decision_evidence_digest: abandonment.decision_evidence_digest.clone(),
            identity_abandonment_digest: abandonment.record_digest.clone(),
            abandoned_at_ms: abandonment.abandoned_at_ms,
            abandonment_digest: ContentDigest::from_bytes(&[]),
        };
        record.abandonment_digest = record.expected_digest()?;
        record.validate(request, abandonment)?;
        Ok(record)
    }

    fn validate(
        &self,
        request: &SenderRevocationRequest,
        abandonment: &PreparedIssuanceAbandonment,
    ) -> Result<(), M6RevocationSenderError> {
        if self.schema != SENDER_REVOCATION_ABANDONMENT_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.request_digest != request.request_digest
            || self.route_definition_digest != request.route_definition_digest
            || self.target_kind != request.target_kind
            || self.target_identity != request.target_identity
            || self.message_digest != abandonment.message_digest
            || self.sequence != abandonment.sequence
            || self.disposition != abandonment.disposition
            || self.reason != abandonment.reason
            || self.decision_evidence_digest != abandonment.decision_evidence_digest
            || self.identity_abandonment_digest != abandonment.record_digest
            || self.abandoned_at_ms != abandonment.abandoned_at_ms
        {
            return Err(M6RevocationSenderError::Integrity(
                "sender revocation abandonment is missing or cross-linked".to_string(),
            ));
        }
        require_digest(
            "sender revocation abandonment",
            &self.abandonment_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6RevocationSenderError> {
        digest_domain(
            ABANDONMENT_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.request_digest,
                &self.issuance_request_digest,
                &self.route_definition_digest,
                self.target_kind,
                &self.target_identity,
                &self.message_digest,
                self.sequence,
                self.disposition,
                &self.reason,
                &self.decision_evidence_digest,
                &self.identity_abandonment_digest,
                self.abandoned_at_ms,
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationSenderCrashPoint {
    RequestPersisted,
    PreparedIssuancePersisted,
    RevocationIntentRecorded,
    RevocationOutboundCommitted,
    AuthorizationConsumed,
    OriginChainCommitted,
    RouteStageEffectCommitted,
    RevocationRouteStageCommitted,
    RouteReadyEffectCommitted,
    RevocationRouteReadyCommitted,
    ReceiptEffectCommitted,
    RevocationReceiptCommitted,
    AbandonmentEffectCommitted,
    AbandonmentReceiptCommitted,
}

/// Sequential revocation publisher. `_owner_lock` is deliberately last so the
/// shared endpoint ownership outlives every mutable child during drop.
pub struct M6RevocationSenderRuntime<V: OpaqueAuthorizationVerifier> {
    endpoint_root: PathBuf,
    requests_root: PathBuf,
    receipts_root: PathBuf,
    abandonments_root: PathBuf,
    staging_root: PathBuf,
    max_revocation_requests: u32,
    max_revocation_receipts: u32,
    retry_policy: RetryPolicy,
    clock: Arc<dyn Clock>,
    signer: FactorySigner,
    issuer: ManifestIssuer,
    authorization: AuthorizationStore<V>,
    spool: GovernedFilesystemSpool,
    journal: CoordinatorJournal,
    _owner_lock: File,
}

impl<V: OpaqueAuthorizationVerifier> M6RevocationSenderRuntime<V> {
    pub fn open(
        config: M6RevocationSenderRuntimeConfig,
        verifier: V,
        signer: FactorySigner,
        clock: Arc<dyn Clock>,
        nonce_source: Arc<dyn NonceSource>,
    ) -> Result<Self, M6RevocationSenderError> {
        config.validate_non_path_fields()?;
        let endpoint_root = secure_create_root(&config.endpoint_root)?;
        let owner_lock = acquire_sender_endpoint_owner(&endpoint_root)
            .map_err(|error| M6RevocationSenderError::Endpoint(error.to_string()))?;

        // No mutable child opens before the shared sender endpoint lock.
        let spool = GovernedFilesystemSpool::open(
            &config.route_root,
            &endpoint_root,
            RouteEndpointRole::Sender,
            &config.expected_route_definition_digest,
        )
        .map_err(M6RevocationSenderError::from)?;
        let route = spool.route().clone();
        if signer.signing_key_id() != route.sender.signing_key_id
            || signer.public_key_hex() != route.sender.public_key_hex
            || config.authorization_profile.factory_id() != route.sender.factory_id
            || config.max_revocation_requests > route.resource_profile.max_revocation_records
            || config.max_revocation_receipts > route.resource_profile.max_revocation_records
        {
            return Err(M6RevocationSenderError::InvalidConfiguration(
                "revocation signer, authority factory, request bound, or sender route identity differ"
                    .to_string(),
            ));
        }
        config
            .journal_config
            .validate_for_resource_profile(&route.resource_profile)
            .map_err(M6RevocationSenderError::from)?;
        config
            .retry_policy
            .validate_for_resource_profile(&route.resource_profile)
            .map_err(M6RevocationSenderError::from)?;

        let authorization = AuthorizationStore::open(
            endpoint_root.join(AUTHORITY_DIRECTORY),
            config.authorization_profile,
            verifier,
        )
        .map_err(M6RevocationSenderError::from)?;
        // ADR lock order is endpoint -> local authority -> identity/effects.
        // This is the same sender-role origin store used by export.
        let issuer = ManifestIssuer::open_or_initialize(
            &endpoint_root,
            route,
            RouteEndpointRole::Sender,
            Arc::clone(&clock),
            nonce_source,
        )
        .map_err(M6RevocationSenderError::from)?;
        let journal = CoordinatorJournal::open_or_initialize(
            endpoint_root.join(JOURNAL_DIRECTORY),
            config.journal_config,
            Arc::clone(&clock),
        )
        .map_err(M6RevocationSenderError::from)?;
        let requests_root = secure_child_directory(&endpoint_root, REQUESTS_DIRECTORY)?;
        let receipts_root = secure_child_directory(&endpoint_root, RECEIPTS_DIRECTORY)?;
        let abandonments_root = secure_child_directory(&endpoint_root, ABANDONMENTS_DIRECTORY)?;
        let staging_root = secure_child_directory(&endpoint_root, STAGING_DIRECTORY)?;
        recover_staging(&staging_root)?;

        let runtime = Self {
            endpoint_root,
            requests_root,
            receipts_root,
            abandonments_root,
            staging_root,
            max_revocation_requests: config.max_revocation_requests,
            max_revocation_receipts: config.max_revocation_receipts,
            retry_policy: config.retry_policy,
            clock,
            signer,
            issuer,
            authorization,
            spool,
            journal,
            _owner_lock: owner_lock,
        };
        runtime.validate_record_stores()?;
        Ok(runtime)
    }

    pub fn endpoint_root(&self) -> &Path {
        &self.endpoint_root
    }

    pub fn route(&self) -> &RouteDefinition {
        self.spool.route()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_revocation(
        &mut self,
        logical_operation_id: impl Into<String>,
        principal_id: impl Into<String>,
        target_kind: RevocationTargetKindV1,
        target_identity: ContentDigest,
        reason: impl Into<String>,
        prior_source_authorization_evidence_digest: ContentDigest,
        message_lifetime_ms: u64,
    ) -> Result<PreparedSenderRevocation, M6RevocationSenderError> {
        self.prepare_revocation_with_fault(
            logical_operation_id,
            principal_id,
            target_kind,
            target_identity,
            reason,
            prior_source_authorization_evidence_digest,
            message_lifetime_ms,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_revocation_with_fault(
        &mut self,
        logical_operation_id: impl Into<String>,
        principal_id: impl Into<String>,
        target_kind: RevocationTargetKindV1,
        target_identity: ContentDigest,
        reason: impl Into<String>,
        prior_source_authorization_evidence_digest: ContentDigest,
        message_lifetime_ms: u64,
        crash_at: Option<RevocationSenderCrashPoint>,
    ) -> Result<PreparedSenderRevocation, M6RevocationSenderError> {
        let logical_operation_id = logical_operation_id.into();
        let principal_id = principal_id.into();
        let reason = reason.into();
        validate_identifier("logical operation id", &logical_operation_id)?;
        validate_identifier("revocation principal id", &principal_id)?;
        validate_reason(&reason)?;
        require_meaningful_digest("revocation target", &target_identity)?;
        require_meaningful_digest(
            "prior source authorization evidence",
            &prior_source_authorization_evidence_digest,
        )?;
        self.require_no_other_pending_operation(&logical_operation_id)?;

        let path = request_path(&self.requests_root, &logical_operation_id);
        let request = if path.exists() {
            let request = load_request(&path, self.route())?;
            if request.logical_operation_id != logical_operation_id
                || request.principal_id != principal_id
                || request.target_kind != target_kind
                || request.target_identity != target_identity
                || request.reason != reason
                || request.prior_source_authorization_evidence_digest
                    != prior_source_authorization_evidence_digest
                || request.message_lifetime_ms != message_lifetime_ms
            {
                return Err(M6RevocationSenderError::Conflict {
                    identity: logical_operation_id,
                    existing: request.request_digest,
                    requested: request_conflict_digest(
                        &principal_id,
                        target_kind,
                        &target_identity,
                        &reason,
                        &prior_source_authorization_evidence_digest,
                        message_lifetime_ms,
                    )?,
                });
            }
            request
        } else {
            enforce_file_bound(
                &self.requests_root,
                self.max_revocation_requests,
                "sender revocation requests",
            )?;
            let captured_at_ms = self.clock.now_ms().map_err(M6RevocationSenderError::from)?;
            let request = SenderRevocationRequest::new(
                logical_operation_id,
                principal_id,
                captured_at_ms,
                message_lifetime_ms,
                target_kind,
                target_identity,
                reason,
                prior_source_authorization_evidence_digest,
                self.route(),
            )?;
            persist_immutable(&self.staging_root, &path, &canonical_json(&request)?)?;
            maybe_crash(crash_at, RevocationSenderCrashPoint::RequestPersisted)?;
            request
        };

        let (issued, issuance_request_digest, _) = self.resolve_or_prepare_issuance(&request)?;
        maybe_crash(
            crash_at,
            RevocationSenderCrashPoint::PreparedIssuancePersisted,
        )?;
        prepared_projection(&request, issuance_request_digest, &issued)
    }

    pub fn publish_authorization(
        &self,
        authorization: ActionAuthorization,
    ) -> Result<ContentDigest, M6RevocationSenderError> {
        let authorization = self
            .authorization
            .publish_authorization(authorization)
            .map_err(M6RevocationSenderError::from)?;
        Ok(authorization.authorization_digest().clone())
    }

    pub fn commit_revocation(
        &mut self,
        logical_operation_id: &str,
        authorization_digest: &ContentDigest,
    ) -> Result<SenderRevocationReceipt, M6RevocationSenderError> {
        self.commit_revocation_with_fault(logical_operation_id, authorization_digest, None)
    }

    pub fn recover_revocation(
        &mut self,
        logical_operation_id: &str,
        authorization_digest: &ContentDigest,
    ) -> Result<SenderRevocationReceipt, M6RevocationSenderError> {
        self.commit_revocation(logical_operation_id, authorization_digest)
    }

    pub fn commit_revocation_with_fault(
        &mut self,
        logical_operation_id: &str,
        authorization_digest: &ContentDigest,
        crash_at: Option<RevocationSenderCrashPoint>,
    ) -> Result<SenderRevocationReceipt, M6RevocationSenderError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        self.require_no_other_pending_operation(logical_operation_id)?;
        let request_path = request_path(&self.requests_root, logical_operation_id);
        if !request_path.exists() {
            return Err(M6RevocationSenderError::NotPrepared(
                logical_operation_id.to_string(),
            ));
        }
        let request = load_request(&request_path, self.route())?;
        if request.logical_operation_id != logical_operation_id {
            return Err(M6RevocationSenderError::Integrity(
                "revocation request is stored under another operation identity".to_string(),
            ));
        }
        let (prepared, issuance_request_digest, chain_already_committed) =
            self.resolve_or_prepare_issuance(&request)?;
        validate_issued(&request, &prepared, self.route())?;

        let expected_binding = revocation_authorization_binding(&request, &prepared)?;
        let authorization = self
            .authorization
            .load_authorization(authorization_digest)
            .map_err(M6RevocationSenderError::from)?;
        if authorization.binding() != &expected_binding
            || authorization.binding().action != AuthorityAction::IssueRevocation
            || authorization.use_limit() != 1
        {
            return Err(M6RevocationSenderError::Authority(
                "authorization does not bind the exact prepared revocation".to_string(),
            ));
        }

        let initial = self
            .journal
            .begin(
                transaction_draft(
                    &request,
                    &prepared,
                    authorization.authorization_digest().clone(),
                    self.retry_policy.clone(),
                ),
                stage_evidence(
                    Some(authorization.authorization_digest().clone()),
                    vec![
                        request.request_digest.clone(),
                        issuance_request_digest.clone(),
                        request.target_identity.clone(),
                        request.prior_source_authorization_evidence_digest.clone(),
                        prepared.manifest.message_digest.clone(),
                    ],
                    None,
                    None,
                )?,
            )
            .map_err(M6RevocationSenderError::from)?;
        maybe_crash(
            crash_at,
            RevocationSenderCrashPoint::RevocationIntentRecorded,
        )?;
        let coordinator_request_digest = initial.request_digest.clone();

        self.append_stage(
            &request,
            &coordinator_request_digest,
            TransactionStage::RevocationOutboundCommitted,
            Some(authorization.authorization_digest().clone()),
            vec![
                request.request_digest.clone(),
                issuance_request_digest.clone(),
                prepared.manifest.message_digest.clone(),
                delivery_fact_digest(&prepared)?,
            ],
            None,
            None,
        )?;
        maybe_crash(
            crash_at,
            RevocationSenderCrashPoint::RevocationOutboundCommitted,
        )?;

        let trusted_now_ms = self.clock.now_ms().map_err(M6RevocationSenderError::from)?;
        let consumption = self
            .authorization
            .consume(&authorization.invocation(1), trusted_now_ms)
            .map_err(M6RevocationSenderError::from)?;
        maybe_crash(crash_at, RevocationSenderCrashPoint::AuthorizationConsumed)?;

        let chain_committed = if chain_already_committed {
            prepared.clone()
        } else {
            self.issuer
                .commit_prepared_exact(&request.issuance_idempotency_key, &issuance_request_digest)
                .map_err(M6RevocationSenderError::from)?
        };
        validate_issued(&request, &chain_committed, self.route())?;
        maybe_crash(crash_at, RevocationSenderCrashPoint::OriginChainCommitted)?;

        {
            let route_owner = self
                .spool
                .acquire_role()
                .map_err(M6RevocationSenderError::from)?;
            let staged_digest = self
                .spool
                .stage_delivery(&route_owner, &chain_committed)
                .map_err(M6RevocationSenderError::from)?;
            require_digest(
                "staged revocation message",
                &chain_committed.manifest.message_digest,
                &staged_digest,
            )?;
            self.spool
                .stage_delivery(&route_owner, &chain_committed)
                .map_err(M6RevocationSenderError::from)?;
            maybe_crash(
                crash_at,
                RevocationSenderCrashPoint::RouteStageEffectCommitted,
            )?;
        }
        self.append_stage(
            &request,
            &coordinator_request_digest,
            TransactionStage::RevocationRouteStageCommitted,
            Some(authorization.authorization_digest().clone()),
            vec![
                request.request_digest.clone(),
                chain_committed.manifest.message_digest.clone(),
                delivery_fact_digest(&chain_committed)?,
                consumption.receipt_digest().clone(),
            ],
            Some(consumption.receipt_digest().clone()),
            Some(authorization.binding_digest().clone()),
        )?;
        maybe_crash(
            crash_at,
            RevocationSenderCrashPoint::RevocationRouteStageCommitted,
        )?;

        let ready = {
            let route_owner = self
                .spool
                .acquire_role()
                .map_err(M6RevocationSenderError::from)?;
            self.spool
                .commit_staged(&route_owner, &chain_committed.manifest.message_digest)
                .map_err(M6RevocationSenderError::from)?;
            self.spool
                .read_outbound_ready(&chain_committed.manifest.message_digest)
                .map_err(M6RevocationSenderError::from)?
        };
        validate_issued(&request, &ready, self.route())?;
        if ready != chain_committed {
            return Err(M6RevocationSenderError::Integrity(
                "ready revocation bytes differ from the retained issuance".to_string(),
            ));
        }
        maybe_crash(
            crash_at,
            RevocationSenderCrashPoint::RouteReadyEffectCommitted,
        )?;
        let ready_delivery_digest = delivery_fact_digest(&ready)?;
        self.append_stage(
            &request,
            &coordinator_request_digest,
            TransactionStage::RevocationRouteReadyCommitted,
            Some(authorization.authorization_digest().clone()),
            vec![
                ready.manifest.message_digest.clone(),
                ready_delivery_digest.clone(),
                consumption.receipt_digest().clone(),
            ],
            Some(consumption.receipt_digest().clone()),
            Some(authorization.binding_digest().clone()),
        )?;
        maybe_crash(
            crash_at,
            RevocationSenderCrashPoint::RevocationRouteReadyCommitted,
        )?;

        let receipt_path = receipt_path(&self.receipts_root, logical_operation_id);
        let receipt = if receipt_path.exists() {
            let receipt: SenderRevocationReceipt =
                load_canonical_file(&receipt_path, MAX_RECORD_BYTES)?;
            receipt.validate(
                &request,
                &coordinator_request_digest,
                &ready,
                &authorization,
                &consumption,
                &ready_delivery_digest,
            )?;
            receipt
        } else {
            enforce_file_bound(
                &self.receipts_root,
                self.max_revocation_receipts,
                "sender revocation receipts",
            )?;
            let committed_at_ms = self.clock.now_ms().map_err(M6RevocationSenderError::from)?;
            let receipt = SenderRevocationReceipt::new(
                &request,
                coordinator_request_digest.clone(),
                &ready,
                &authorization,
                &consumption,
                ready_delivery_digest.clone(),
                committed_at_ms,
            )?;
            persist_immutable(
                &self.staging_root,
                &receipt_path,
                &canonical_json(&receipt)?,
            )?;
            receipt
        };
        maybe_crash(crash_at, RevocationSenderCrashPoint::ReceiptEffectCommitted)?;
        self.append_stage(
            &request,
            &coordinator_request_digest,
            TransactionStage::RevocationReceiptCommitted,
            Some(authorization.authorization_digest().clone()),
            vec![
                receipt.receipt_digest.clone(),
                ready_delivery_digest,
                consumption.receipt_digest().clone(),
            ],
            Some(receipt.receipt_digest.clone()),
            Some(authorization.binding_digest().clone()),
        )?;
        maybe_crash(
            crash_at,
            RevocationSenderCrashPoint::RevocationReceiptCommitted,
        )?;
        Ok(receipt)
    }

    pub fn abandon_revocation(
        &mut self,
        logical_operation_id: &str,
        disposition: PreparedIssuanceDisposition,
        reason: impl Into<String>,
        decision_evidence_digest: ContentDigest,
    ) -> Result<SenderRevocationAbandonment, M6RevocationSenderError> {
        self.abandon_revocation_with_fault(
            logical_operation_id,
            disposition,
            reason,
            decision_evidence_digest,
            None,
        )
    }

    pub fn abandon_revocation_with_fault(
        &mut self,
        logical_operation_id: &str,
        disposition: PreparedIssuanceDisposition,
        reason: impl Into<String>,
        decision_evidence_digest: ContentDigest,
        crash_at: Option<RevocationSenderCrashPoint>,
    ) -> Result<SenderRevocationAbandonment, M6RevocationSenderError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        require_meaningful_digest("revocation abandonment evidence", &decision_evidence_digest)?;
        self.require_no_other_pending_operation(logical_operation_id)?;
        let path = request_path(&self.requests_root, logical_operation_id);
        if !path.exists() {
            return Err(M6RevocationSenderError::NotPrepared(
                logical_operation_id.to_string(),
            ));
        }
        let request = load_request(&path, self.route())?;
        let (issued, issuance_request_digest) = self.resolve_issuance_for_abandonment(&request)?;
        validate_issued(&request, &issued, self.route())?;
        let identity_abandonment = self
            .issuer
            .abandon_prepared(
                &request.issuance_idempotency_key,
                &issuance_request_digest,
                disposition,
                reason.into(),
                decision_evidence_digest,
            )
            .map_err(M6RevocationSenderError::from)?;
        maybe_crash(
            crash_at,
            RevocationSenderCrashPoint::AbandonmentEffectCommitted,
        )?;
        let record = SenderRevocationAbandonment::new(
            &request,
            issuance_request_digest,
            &identity_abandonment,
        )?;
        let path = abandonment_path(&self.abandonments_root, logical_operation_id);
        if path.exists() {
            let existing: SenderRevocationAbandonment =
                load_canonical_file(&path, MAX_RECORD_BYTES)?;
            existing.validate(&request, &identity_abandonment)?;
            if existing != record {
                return Err(M6RevocationSenderError::Conflict {
                    identity: logical_operation_id.to_string(),
                    existing: existing.abandonment_digest,
                    requested: record.abandonment_digest,
                });
            }
        } else {
            enforce_file_bound(
                &self.abandonments_root,
                self.max_revocation_requests,
                "sender revocation abandonments",
            )?;
            persist_immutable(&self.staging_root, &path, &canonical_json(&record)?)?;
        }
        maybe_crash(
            crash_at,
            RevocationSenderCrashPoint::AbandonmentReceiptCommitted,
        )?;
        Ok(record)
    }

    pub fn load_receipt(
        &self,
        logical_operation_id: &str,
    ) -> Result<Option<SenderRevocationReceipt>, M6RevocationSenderError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        let path = receipt_path(&self.receipts_root, logical_operation_id);
        if !path.exists() {
            return Ok(None);
        }
        let receipt: SenderRevocationReceipt = load_canonical_file(&path, MAX_RECORD_BYTES)?;
        require_digest(
            "sender revocation receipt",
            &receipt.receipt_digest,
            &receipt.expected_digest()?,
        )?;
        if receipt.logical_operation_id != logical_operation_id {
            return Err(M6RevocationSenderError::Integrity(
                "sender revocation receipt is stored under another operation".to_string(),
            ));
        }
        Ok(Some(receipt))
    }

    pub fn load_publication_completion_evidence(
        &self,
        logical_operation_id: &str,
    ) -> Result<Option<SenderRevocationPublicationEvidenceV1>, M6RevocationSenderError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        let Some(receipt) = self.load_receipt(logical_operation_id)? else {
            return Ok(None);
        };
        let request_bytes = read_regular_bounded(
            &request_path(&self.requests_root, logical_operation_id),
            MAX_RECORD_BYTES,
        )?;
        let request: SenderRevocationRequest = parse_canonical(&request_bytes)?;
        request.validate(self.route())?;
        let issued = match self
            .issuer
            .prepared_resolution(&request.issuance_idempotency_key)
            .map_err(M6RevocationSenderError::from)?
        {
            PreparedIssuanceResolution::ChainCommitted { issuance, .. } => issuance.issued,
            _ => {
                return Err(M6RevocationSenderError::Integrity(
                    "sender revocation receipt has no committed origin-chain issuance".to_string(),
                ));
            }
        };
        validate_issued(&request, &issued, self.route())?;
        let authorization = self
            .authorization
            .load_authorization(&receipt.current_revocation_authorization_digest)
            .map_err(M6RevocationSenderError::from)?;
        let consumption = self
            .authorization
            .load_consumption(&receipt.current_revocation_authorization_digest, 1)
            .map_err(M6RevocationSenderError::from)?;
        let projection = self
            .journal
            .transaction(logical_operation_id)?
            .ok_or_else(|| {
                M6RevocationSenderError::Integrity(
                    "sender revocation receipt has no coordinator projection".to_string(),
                )
            })?;
        let terminal_stage_digest = projection
            .current_record()
            .ok_or_else(|| {
                M6RevocationSenderError::Integrity(
                    "sender revocation projection has no terminal stage".to_string(),
                )
            })?
            .stage_digest
            .clone();
        let mut evidence = SenderRevocationPublicationEvidenceV1 {
            schema: SENDER_REVOCATION_PUBLICATION_EVIDENCE_SCHEMA.to_string(),
            route_definition_digest: self.route().definition_digest.clone(),
            route_generation: self.route().generation,
            signing_key_id: self.signer.signing_key_id().to_string(),
            logical_operation_id: logical_operation_id.to_string(),
            message_digest: receipt.message_digest.clone(),
            sequence: issued.manifest.unsigned.sequence,
            previous_message_digest: issued.manifest.unsigned.previous_message_digest.clone(),
            issued_at_ms: issued.manifest.unsigned.issued_at_ms,
            committed_at_ms: receipt.committed_at_ms,
            target_kind: receipt.target_kind,
            target_identity: receipt.target_identity.clone(),
            prior_source_authorization_evidence_digest: receipt
                .prior_source_authorization_evidence_digest
                .clone(),
            sender_receipt_digest: receipt.receipt_digest.clone(),
            terminal_stage_digest,
            request_bytes,
            authority_profile_bytes: self
                .authorization
                .profile()
                .canonical_bytes()
                .map_err(M6RevocationSenderError::from)?,
            authorization_bytes: authorization
                .canonical_bytes(self.authorization.profile(), self.authorization.verifier())
                .map_err(M6RevocationSenderError::from)?,
            authorization_consumption_bytes: consumption
                .canonical_bytes(&authorization)
                .map_err(M6RevocationSenderError::from)?,
            signed_manifest_bytes: issued
                .manifest
                .canonical_bytes()
                .map_err(M6RevocationSenderError::from)?,
            coordinator_projection_bytes: projection.canonical_bytes()?,
            sender_receipt_bytes: canonical_json(&receipt)?,
            evidence_digest: ContentDigest::from_bytes(&[]),
            source_set_signature_hex: String::new(),
        };
        evidence.evidence_digest = evidence.expected_digest()?;
        evidence.source_set_signature_hex = self
            .signer
            .sign_sender_revocation_completion(self.route(), &evidence.evidence_digest)
            .map_err(M6RevocationSenderError::from)?;
        evidence.validate_detached(self.route())?;
        Ok(Some(evidence))
    }

    pub fn load_abandonment(
        &self,
        logical_operation_id: &str,
    ) -> Result<Option<SenderRevocationAbandonment>, M6RevocationSenderError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        let path = abandonment_path(&self.abandonments_root, logical_operation_id);
        if !path.exists() {
            return Ok(None);
        }
        let request = load_request(
            &request_path(&self.requests_root, logical_operation_id),
            self.route(),
        )?;
        let resolution = self
            .issuer
            .prepared_resolution(&request.issuance_idempotency_key)
            .map_err(M6RevocationSenderError::from)?;
        let identity_abandonment = match resolution {
            PreparedIssuanceResolution::Abandoned { abandonment, .. } => abandonment,
            _ => {
                return Err(M6RevocationSenderError::Integrity(
                    "revocation abandonment projection has no identity-layer fact".to_string(),
                ));
            }
        };
        let record: SenderRevocationAbandonment = load_canonical_file(&path, MAX_RECORD_BYTES)?;
        record.validate(&request, &identity_abandonment)?;
        Ok(Some(record))
    }

    /// Canonically reopens an attachment-free ready revocation from the
    /// neutral spool and revalidates its route signature and four-value target
    /// kind.
    pub fn read_ready_revocation(
        &self,
        message_digest: &ContentDigest,
    ) -> Result<IssuedManifest, M6RevocationSenderError> {
        let issued = self
            .spool
            .read_outbound_ready(message_digest)
            .map_err(M6RevocationSenderError::from)?;
        issued
            .manifest
            .verify_route(self.route())
            .map_err(M6RevocationSenderError::from)?;
        if !issued.attachments.is_empty()
            || !issued.manifest.unsigned.attachments.is_empty()
            || issued.manifest.unsigned.kind != ManifestKind::Revocation
        {
            return Err(M6RevocationSenderError::Integrity(
                "ready revocation is not an attachment-free revocation manifest".to_string(),
            ));
        }
        let ManifestPayload::Revocation(payload) = &issued.manifest.unsigned.payload else {
            return Err(M6RevocationSenderError::Integrity(
                "ready revocation has the wrong payload kind".to_string(),
            ));
        };
        RevocationTargetKindV1::parse(&payload.target_kind)
            .map_err(|error| M6RevocationSenderError::Integrity(error.to_string()))?;
        validate_reason(&payload.reason)?;
        require_meaningful_digest("ready revocation target", &payload.target_identity)?;
        require_meaningful_digest(
            "ready prior source authorization evidence",
            &payload.authorization_digest,
        )?;
        Ok(issued)
    }

    pub fn last_committed_sequence(&self) -> u64 {
        self.issuer.last_sequence()
    }

    fn resolve_or_prepare_issuance(
        &mut self,
        request: &SenderRevocationRequest,
    ) -> Result<(IssuedManifest, ContentDigest, bool), M6RevocationSenderError> {
        let mut resolution = self
            .issuer
            .prepared_resolution(&request.issuance_idempotency_key)
            .map_err(M6RevocationSenderError::from)?;
        if matches!(resolution, PreparedIssuanceResolution::Missing) {
            self.issuer
                .prepare_idempotent(
                    request.issuance_idempotency_key.clone(),
                    &self.signer,
                    revocation_payload(request),
                    Vec::new(),
                    request.message_lifetime_ms,
                )
                .map_err(M6RevocationSenderError::from)?;
            resolution = self
                .issuer
                .prepared_resolution(&request.issuance_idempotency_key)
                .map_err(M6RevocationSenderError::from)?;
        }
        let (issuance, chain_committed) = match resolution {
            PreparedIssuanceResolution::Prepared(issuance) => (issuance, false),
            PreparedIssuanceResolution::ChainCommitted { commit, issuance } => {
                if commit.message_digest != issuance.issued.manifest.message_digest
                    || commit.sequence != issuance.issued.manifest.unsigned.sequence
                {
                    return Err(M6RevocationSenderError::Integrity(
                        "origin-chain fact differs from retained revocation issuance".to_string(),
                    ));
                }
                (issuance, true)
            }
            PreparedIssuanceResolution::Abandoned { abandonment, .. } => {
                return Err(M6RevocationSenderError::RevocationAbandoned {
                    logical_operation_id: request.logical_operation_id.clone(),
                    abandonment_digest: abandonment.record_digest,
                });
            }
            PreparedIssuanceResolution::Missing => {
                return Err(M6RevocationSenderError::Integrity(
                    "manifest issuer lost the just-persisted revocation prepare".to_string(),
                ));
            }
        };
        if issuance.idempotency_key != request.issuance_idempotency_key {
            return Err(M6RevocationSenderError::Integrity(
                "revocation issuance idempotency identity differs from its request".to_string(),
            ));
        }
        validate_issued(request, &issuance.issued, self.route())?;
        Ok((issuance.issued, issuance.request_digest, chain_committed))
    }

    fn resolve_issuance_for_abandonment(
        &mut self,
        request: &SenderRevocationRequest,
    ) -> Result<(IssuedManifest, ContentDigest), M6RevocationSenderError> {
        let mut resolution = self
            .issuer
            .prepared_resolution(&request.issuance_idempotency_key)
            .map_err(M6RevocationSenderError::from)?;
        if matches!(resolution, PreparedIssuanceResolution::Missing) {
            self.issuer
                .prepare_idempotent(
                    request.issuance_idempotency_key.clone(),
                    &self.signer,
                    revocation_payload(request),
                    Vec::new(),
                    request.message_lifetime_ms,
                )
                .map_err(M6RevocationSenderError::from)?;
            resolution = self
                .issuer
                .prepared_resolution(&request.issuance_idempotency_key)
                .map_err(M6RevocationSenderError::from)?;
        }
        let issuance = match resolution {
            PreparedIssuanceResolution::Prepared(issuance)
            | PreparedIssuanceResolution::Abandoned { issuance, .. } => issuance,
            PreparedIssuanceResolution::ChainCommitted { .. } => {
                return Err(M6RevocationSenderError::CannotAbandonCommitted(
                    request.logical_operation_id.clone(),
                ));
            }
            PreparedIssuanceResolution::Missing => {
                return Err(M6RevocationSenderError::Integrity(
                    "manifest issuer lost the just-persisted abandonment prepare".to_string(),
                ));
            }
        };
        validate_issued(request, &issuance.issued, self.route())?;
        Ok((issuance.issued, issuance.request_digest))
    }

    fn append_stage(
        &self,
        request: &SenderRevocationRequest,
        coordinator_request_digest: &ContentDigest,
        stage: TransactionStage,
        authority_ref: Option<ContentDigest>,
        evidence_refs: Vec<ContentDigest>,
        receipt_ref: Option<ContentDigest>,
        attestation_ref: Option<ContentDigest>,
    ) -> Result<(), M6RevocationSenderError> {
        self.journal
            .append(
                &request.logical_operation_id,
                coordinator_request_digest,
                stage,
                stage_evidence(authority_ref, evidence_refs, receipt_ref, attestation_ref)?,
            )
            .map_err(M6RevocationSenderError::from)?;
        Ok(())
    }

    fn require_no_other_pending_operation(
        &self,
        requested_operation_id: &str,
    ) -> Result<(), M6RevocationSenderError> {
        for projection in self
            .journal
            .transactions()
            .map_err(M6RevocationSenderError::from)?
        {
            if projection.intent.logical_operation_id != requested_operation_id
                && !projection
                    .current_stage()
                    .is_some_and(TransactionStage::is_terminal)
                && self
                    .load_abandonment(&projection.intent.logical_operation_id)?
                    .is_none()
            {
                return Err(M6RevocationSenderError::RecoveryBlocked {
                    blocking_operation_id: projection.intent.logical_operation_id,
                });
            }
        }
        for path in
            bounded_record_files(&self.requests_root, self.max_revocation_requests as usize)?
        {
            let request = load_request(&path, self.route())?;
            if request.logical_operation_id != requested_operation_id
                && self.load_receipt(&request.logical_operation_id)?.is_none()
                && self
                    .load_abandonment(&request.logical_operation_id)?
                    .is_none()
            {
                return Err(M6RevocationSenderError::RecoveryBlocked {
                    blocking_operation_id: request.logical_operation_id,
                });
            }
        }
        Ok(())
    }

    fn validate_record_stores(&self) -> Result<(), M6RevocationSenderError> {
        for path in
            bounded_record_files(&self.requests_root, self.max_revocation_requests as usize)?
        {
            let request = load_request(&path, self.route())?;
            if path != request_path(&self.requests_root, &request.logical_operation_id) {
                return Err(M6RevocationSenderError::Integrity(
                    "sender revocation request is stored under a non-canonical path".to_string(),
                ));
            }
        }
        for path in
            bounded_record_files(&self.receipts_root, self.max_revocation_receipts as usize)?
        {
            let receipt: SenderRevocationReceipt = load_canonical_file(&path, MAX_RECORD_BYTES)?;
            require_digest(
                "sender revocation receipt",
                &receipt.receipt_digest,
                &receipt.expected_digest()?,
            )?;
            if path != receipt_path(&self.receipts_root, &receipt.logical_operation_id) {
                return Err(M6RevocationSenderError::Integrity(
                    "sender revocation receipt is stored under a non-canonical path".to_string(),
                ));
            }
        }
        for path in bounded_record_files(
            &self.abandonments_root,
            self.max_revocation_requests as usize,
        )? {
            let abandonment: SenderRevocationAbandonment =
                load_canonical_file(&path, MAX_RECORD_BYTES)?;
            require_digest(
                "sender revocation abandonment",
                &abandonment.abandonment_digest,
                &abandonment.expected_digest()?,
            )?;
            if path != abandonment_path(&self.abandonments_root, &abandonment.logical_operation_id)
            {
                return Err(M6RevocationSenderError::Integrity(
                    "sender revocation abandonment is stored under a non-canonical path"
                        .to_string(),
                ));
            }
        }
        for projection in self
            .journal
            .transactions()
            .map_err(M6RevocationSenderError::from)?
        {
            let path = request_path(&self.requests_root, &projection.intent.logical_operation_id);
            if !path.exists() {
                return Err(M6RevocationSenderError::Integrity(
                    "revocation coordinator transaction has no immutable outer request".to_string(),
                ));
            }
        }
        Ok(())
    }
}

fn prepared_projection(
    request: &SenderRevocationRequest,
    issuance_request_digest: ContentDigest,
    issued: &IssuedManifest,
) -> Result<PreparedSenderRevocation, M6RevocationSenderError> {
    Ok(PreparedSenderRevocation {
        logical_operation_id: request.logical_operation_id.clone(),
        request_digest: request.request_digest.clone(),
        issuance_request_digest,
        target_kind: request.target_kind,
        target_identity: request.target_identity.clone(),
        reason: request.reason.clone(),
        prior_source_authorization_evidence_digest: request
            .prior_source_authorization_evidence_digest
            .clone(),
        message_digest: issued.manifest.message_digest.clone(),
        sequence: issued.manifest.unsigned.sequence,
        nonce: issued.manifest.unsigned.nonce.clone(),
        previous_message_digest: issued.manifest.unsigned.previous_message_digest.clone(),
        authorization_binding: revocation_authorization_binding(request, issued)?,
    })
}

fn revocation_payload(request: &SenderRevocationRequest) -> ManifestPayload {
    ManifestPayload::Revocation(RevocationManifestPayload {
        authorization_digest: request.prior_source_authorization_evidence_digest.clone(),
        reason: request.reason.clone(),
        target_identity: request.target_identity.clone(),
        target_kind: request.target_kind.label().to_string(),
    })
}

fn revocation_authorization_binding(
    request: &SenderRevocationRequest,
    issued: &IssuedManifest,
) -> Result<ExactActionBinding, M6RevocationSenderError> {
    let binding = ExactActionBinding {
        action: AuthorityAction::IssueRevocation,
        principal_id: request.principal_id.clone(),
        route_id: request.route_id.clone(),
        route_generation: request.route_generation,
        message_digest: issued.manifest.message_digest.clone(),
        exchange_digest: request.prior_source_authorization_evidence_digest.clone(),
        package_digest: request.target_identity.clone(),
        request_digest: request.request_digest.clone(),
        expected_active_snapshot_digest: ContentDigest::from_bytes(NOT_APPLICABLE_ACTIVE_SNAPSHOT),
        import_plan_digest: ContentDigest::from_bytes(NOT_APPLICABLE_IMPORT_PLAN),
        policy_digest: request.exchange_policy_digest.clone(),
        proving_digest: ContentDigest::from_bytes(NOT_APPLICABLE_PROVING),
        approval_context_digest: request.request_digest.clone(),
        idempotency_key: request.issuance_idempotency_key.clone(),
    };
    binding.validate().map_err(M6RevocationSenderError::from)?;
    Ok(binding)
}

fn validate_issued(
    request: &SenderRevocationRequest,
    issued: &IssuedManifest,
    route: &RouteDefinition,
) -> Result<(), M6RevocationSenderError> {
    issued
        .manifest
        .verify_route(route)
        .map_err(M6RevocationSenderError::from)?;
    if issued.manifest.unsigned.kind != ManifestKind::Revocation
        || issued.manifest.unsigned.payload != revocation_payload(request)
        || !issued.manifest.unsigned.attachments.is_empty()
        || !issued.attachments.is_empty()
        || issued.manifest.unsigned.origin_role != RouteEndpointRole::Sender
        || issued.manifest.unsigned.route_id != request.route_id
        || issued.manifest.unsigned.route_generation != request.route_generation
        || issued.manifest.unsigned.sender_identity_document_digest
            != request.sender_identity_document_digest
        || issued.manifest.unsigned.receiver_identity_document_digest
            != request.receiver_identity_document_digest
        || issued.manifest.unsigned.policy_digest != request.exchange_policy_digest
        || issued.manifest.unsigned.resource_profile_digest != request.resource_profile_digest
    {
        return Err(M6RevocationSenderError::Integrity(
            "retained signed revocation differs from its exact immutable request".to_string(),
        ));
    }
    Ok(())
}

fn transaction_draft(
    request: &SenderRevocationRequest,
    issued: &IssuedManifest,
    authorization_digest: ContentDigest,
    retry_policy: RetryPolicy,
) -> TransactionRequestDraft {
    TransactionRequestDraft {
        kind: TransactionKind::SenderRevocationPublication,
        logical_operation_id: request.logical_operation_id.clone(),
        idempotency_key: request.issuance_idempotency_key.clone(),
        route_id: request.route_id.clone(),
        route_generation: request.route_generation,
        route_definition_digest: request.route_definition_digest.clone(),
        message_digest: issued.manifest.message_digest.clone(),
        exchange_digest: request.prior_source_authorization_evidence_digest.clone(),
        package_digest: request.target_identity.clone(),
        before_snapshot_digest: request.prior_source_authorization_evidence_digest.clone(),
        expected_after_snapshot_digest: issued.manifest.message_digest.clone(),
        policy_digest: request.exchange_policy_digest.clone(),
        authority_refs: vec![authorization_digest],
        evidence_refs: vec![
            request.request_digest.clone(),
            request.target_identity.clone(),
            request.prior_source_authorization_evidence_digest.clone(),
            issued.manifest.message_digest.clone(),
        ],
        retry_policy,
        deadline_ms: issued.manifest.unsigned.expires_at_ms,
    }
}

fn stage_evidence(
    authority_ref: Option<ContentDigest>,
    evidence_refs: Vec<ContentDigest>,
    receipt_ref: Option<ContentDigest>,
    attestation_ref: Option<ContentDigest>,
) -> Result<StageEvidence, M6RevocationSenderError> {
    StageEvidence::new(
        StageCause::Normal,
        1,
        authority_ref,
        None,
        receipt_ref,
        attestation_ref,
        evidence_refs,
    )
    .map_err(M6RevocationSenderError::from)
}

fn delivery_fact_digest(issued: &IssuedManifest) -> Result<ContentDigest, M6RevocationSenderError> {
    digest_domain(
        DELIVERY_FACT_DOMAIN,
        &(
            &issued.manifest.message_digest,
            ContentDigest::from_bytes(
                &issued
                    .manifest
                    .canonical_bytes()
                    .map_err(M6RevocationSenderError::from)?,
            ),
            &issued.attachments,
        ),
    )
}

fn request_conflict_digest(
    principal_id: &str,
    target_kind: RevocationTargetKindV1,
    target_identity: &ContentDigest,
    reason: &str,
    prior_source_authorization_evidence_digest: &ContentDigest,
    message_lifetime_ms: u64,
) -> Result<ContentDigest, M6RevocationSenderError> {
    digest_domain(
        REQUEST_CONFLICT_DOMAIN,
        &(
            principal_id,
            target_kind,
            target_identity,
            reason,
            prior_source_authorization_evidence_digest,
            message_lifetime_ms,
        ),
    )
}

fn request_path(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!(
        "{}{RECORD_SUFFIX}",
        revocation_operation_stem(logical_operation_id)
    ))
}

fn receipt_path(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!(
        "{}{RECORD_SUFFIX}",
        revocation_operation_stem(logical_operation_id)
    ))
}

fn abandonment_path(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!(
        "{}{RECORD_SUFFIX}",
        revocation_operation_stem(logical_operation_id)
    ))
}

pub(crate) fn revocation_operation_stem(logical_operation_id: &str) -> String {
    let mut bytes = Vec::from(b"wasm-biotic:m6:sender-revocation-operation:v1\0".as_slice());
    bytes.extend_from_slice(logical_operation_id.as_bytes());
    ContentDigest::from_bytes(&bytes).file_stem()
}

fn load_request(
    path: &Path,
    route: &RouteDefinition,
) -> Result<SenderRevocationRequest, M6RevocationSenderError> {
    let request: SenderRevocationRequest = load_canonical_file(path, MAX_RECORD_BYTES)?;
    request.validate(route)?;
    Ok(request)
}

fn maybe_crash(
    requested: Option<RevocationSenderCrashPoint>,
    point: RevocationSenderCrashPoint,
) -> Result<(), M6RevocationSenderError> {
    if requested == Some(point) {
        Err(M6RevocationSenderError::InjectedCrash(point))
    } else {
        Ok(())
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), M6RevocationSenderError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(M6RevocationSenderError::InvalidConfiguration(format!(
            "{field} must contain 1..={MAX_IDENTIFIER_BYTES} non-control bytes"
        )));
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<(), M6RevocationSenderError> {
    if reason.trim().is_empty() || reason.len() > MAX_REASON_BYTES {
        return Err(M6RevocationSenderError::InvalidConfiguration(format!(
            "revocation reason must contain 1..={MAX_REASON_BYTES} bytes"
        )));
    }
    Ok(())
}

fn require_meaningful_digest(
    subject: &str,
    digest: &ContentDigest,
) -> Result<(), M6RevocationSenderError> {
    let all_zero = digest
        .as_str()
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.bytes().all(|byte| byte == b'0'));
    if all_zero || digest == &ContentDigest::from_bytes(&[]) {
        return Err(M6RevocationSenderError::InvalidConfiguration(format!(
            "{subject} digest must cite external immutable evidence"
        )));
    }
    Ok(())
}

fn require_digest(
    subject: &str,
    actual: &ContentDigest,
    expected: &ContentDigest,
) -> Result<(), M6RevocationSenderError> {
    if actual == expected {
        Ok(())
    } else {
        Err(M6RevocationSenderError::Integrity(format!(
            "{subject} digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

fn digest_domain<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ContentDigest, M6RevocationSenderError> {
    let mut bytes = Vec::from(domain);
    bytes.extend_from_slice(&canonical_json(value)?);
    Ok(ContentDigest::from_bytes(&bytes))
}

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, M6RevocationSenderError> {
    let value = serde_json::to_value(value)
        .map_err(|error| M6RevocationSenderError::Serialization(error.to_string()))?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    if output.len() > MAX_RECORD_BYTES {
        return Err(M6RevocationSenderError::ResourceExhausted(format!(
            "canonical record is {} bytes; limit is {MAX_RECORD_BYTES}",
            output.len()
        )));
    }
    Ok(output)
}

fn write_canonical_value(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), M6RevocationSenderError> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" })
        }
        serde_json::Value::Number(number) => {
            if !number.is_i64() && !number.is_u64() {
                return Err(M6RevocationSenderError::Serialization(
                    "floating-point values are forbidden".to_string(),
                ));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        serde_json::Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|error| M6RevocationSenderError::Serialization(error.to_string()))?
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
                        .map_err(|error| M6RevocationSenderError::Serialization(error.to_string()))?
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

fn parse_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, M6RevocationSenderError> {
    let value = serde_json::from_slice::<T>(bytes)
        .map_err(|error| M6RevocationSenderError::Serialization(error.to_string()))?;
    if canonical_json(&value)? != bytes {
        return Err(M6RevocationSenderError::Serialization(
            "record is not canonical JSON".to_string(),
        ));
    }
    Ok(value)
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M6RevocationSenderError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(M6RevocationSenderError::UnsafePath(path.to_path_buf()));
    }
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| M6RevocationSenderError::io(path, source))?;
    let canonical =
        fs::canonicalize(path).map_err(|source| M6RevocationSenderError::io(path, source))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|source| M6RevocationSenderError::io(&canonical, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(M6RevocationSenderError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M6RevocationSenderError> {
    if name.is_empty() || Path::new(name).components().count() != 1 || name == "." || name == ".." {
        return Err(M6RevocationSenderError::UnsafePath(root.join(name)));
    }
    let path = root.join(name);
    reject_symlink_if_present(&path)?;
    fs::create_dir_all(&path).map_err(|source| M6RevocationSenderError::io(&path, source))?;
    let canonical =
        fs::canonicalize(&path).map_err(|source| M6RevocationSenderError::io(&path, source))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|source| M6RevocationSenderError::io(&canonical, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || canonical.parent() != Some(root) {
        return Err(M6RevocationSenderError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M6RevocationSenderError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(M6RevocationSenderError::UnsafePath(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M6RevocationSenderError::io(path, source)),
    }
}

fn reject_symlink(path: &Path) -> Result<(), M6RevocationSenderError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6RevocationSenderError::io(path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(M6RevocationSenderError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn recover_staging(root: &Path) -> Result<(), M6RevocationSenderError> {
    for entry in fs::read_dir(root).map_err(|source| M6RevocationSenderError::io(root, source))? {
        let entry = entry.map_err(|source| M6RevocationSenderError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| M6RevocationSenderError::UnsafePath(path.clone()))?
            .to_string();
        if !entry
            .file_type()
            .map_err(|source| M6RevocationSenderError::io(&path, source))?
            .is_file()
            || !name.starts_with(STAGING_PREFIX)
            || !name.ends_with(".tmp")
        {
            return Err(M6RevocationSenderError::UnsafePath(path));
        }
        fs::remove_file(&path).map_err(|source| M6RevocationSenderError::io(&path, source))?;
    }
    sync_directory(root)
}

fn persist_immutable(
    staging_root: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), M6RevocationSenderError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(M6RevocationSenderError::ResourceExhausted(format!(
            "durable record is {} bytes; limit is {MAX_RECORD_BYTES}",
            bytes.len()
        )));
    }
    reject_symlink_if_present(destination)?;
    if destination.exists() {
        let existing = read_regular_bounded(destination, MAX_RECORD_BYTES)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(M6RevocationSenderError::ImmutableConflict(
            destination.to_path_buf(),
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| M6RevocationSenderError::UnsafePath(destination.to_path_buf()))?;
    let temporary = staging_root.join(format!(
        "{STAGING_PREFIX}{}-{}-{}.tmp",
        ContentDigest::from_bytes(bytes).file_stem(),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| M6RevocationSenderError::io(&temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| M6RevocationSenderError::io(&temporary, source))?;
        file.sync_all()
            .map_err(|source| M6RevocationSenderError::io(&temporary, source))?;
        sync_directory(staging_root)?;
        match fs::hard_link(&temporary, destination) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_regular_bounded(destination, MAX_RECORD_BYTES)?;
                if existing != bytes {
                    return Err(M6RevocationSenderError::ImmutableConflict(
                        destination.to_path_buf(),
                    ));
                }
            }
            Err(source) => return Err(M6RevocationSenderError::io(destination, source)),
        }
        sync_directory(parent)?;
        fs::remove_file(&temporary)
            .map_err(|source| M6RevocationSenderError::io(&temporary, source))?;
        sync_directory(staging_root)
    })();
    result
}

fn enforce_file_bound(
    root: &Path,
    maximum: u32,
    label: &str,
) -> Result<(), M6RevocationSenderError> {
    let count = bounded_record_files(root, maximum as usize)?.len();
    if count >= maximum as usize {
        return Err(M6RevocationSenderError::ResourceExhausted(format!(
            "{label} reached its {maximum}-record budget"
        )));
    }
    Ok(())
}

fn bounded_record_files(
    root: &Path,
    maximum: usize,
) -> Result<Vec<PathBuf>, M6RevocationSenderError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).map_err(|source| M6RevocationSenderError::io(root, source))? {
        let entry = entry.map_err(|source| M6RevocationSenderError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if !entry
            .file_type()
            .map_err(|source| M6RevocationSenderError::io(&path, source))?
            .is_file()
            || !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(RECORD_SUFFIX))
        {
            return Err(M6RevocationSenderError::UnsafePath(path));
        }
        paths.push(path);
        if paths.len() > maximum {
            return Err(M6RevocationSenderError::ResourceExhausted(format!(
                "record directory '{}' exceeds its {maximum}-entry budget",
                root.display()
            )));
        }
    }
    paths.sort();
    Ok(paths)
}

fn load_canonical_file<T: DeserializeOwned + Serialize>(
    path: &Path,
    maximum: usize,
) -> Result<T, M6RevocationSenderError> {
    parse_canonical(&read_regular_bounded(path, maximum)?)
}

fn read_regular_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, M6RevocationSenderError> {
    reject_symlink(path)?;
    let before =
        fs::symlink_metadata(path).map_err(|source| M6RevocationSenderError::io(path, source))?;
    if !before.is_file() || before.len() > maximum as u64 {
        return Err(M6RevocationSenderError::ResourceExhausted(format!(
            "'{}' is not a bounded regular record",
            path.display()
        )));
    }
    let file = File::open(path).map_err(|source| M6RevocationSenderError::io(path, source))?;
    let opened = file
        .metadata()
        .map_err(|source| M6RevocationSenderError::io(path, source))?;
    if !same_regular_file(&before, &opened) {
        return Err(M6RevocationSenderError::Integrity(format!(
            "record '{}' changed before bounded read",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| M6RevocationSenderError::io(path, source))?;
    let after =
        fs::symlink_metadata(path).map_err(|source| M6RevocationSenderError::io(path, source))?;
    if bytes.len() > maximum
        || !same_regular_file(&before, &after)
        || !same_regular_file(&opened, &after)
    {
        return Err(M6RevocationSenderError::Integrity(format!(
            "record '{}' changed during bounded read",
            path.display()
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_regular_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn same_regular_file(left: &Metadata, right: &Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

fn sync_directory(path: &Path) -> Result<(), M6RevocationSenderError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| M6RevocationSenderError::io(path, source))
}

#[derive(Debug)]
pub enum M6RevocationSenderError {
    InvalidConfiguration(String),
    NotPrepared(String),
    Conflict {
        identity: String,
        existing: ContentDigest,
        requested: ContentDigest,
    },
    RevocationAbandoned {
        logical_operation_id: String,
        abandonment_digest: ContentDigest,
    },
    CannotAbandonCommitted(String),
    RecoveryBlocked {
        blocking_operation_id: String,
    },
    InjectedCrash(RevocationSenderCrashPoint),
    Endpoint(String),
    Authority(String),
    Identity(String),
    Transaction(String),
    Integrity(String),
    ResourceExhausted(String),
    UnsafePath(PathBuf),
    ImmutableConflict(PathBuf),
    Serialization(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl M6RevocationSenderError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl Display for M6RevocationSenderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(
                    formatter,
                    "invalid M6 revocation sender configuration: {message}"
                )
            }
            Self::NotPrepared(operation) => {
                write!(
                    formatter,
                    "revocation operation '{operation}' is not prepared"
                )
            }
            Self::Conflict {
                identity,
                existing,
                requested,
            } => write!(
                formatter,
                "revocation identity '{identity}' is bound to {existing}, not {requested}"
            ),
            Self::RevocationAbandoned {
                logical_operation_id,
                abandonment_digest,
            } => write!(
                formatter,
                "revocation '{logical_operation_id}' was abandoned as {abandonment_digest}"
            ),
            Self::CannotAbandonCommitted(operation) => write!(
                formatter,
                "chain-committed revocation '{operation}' cannot be abandoned"
            ),
            Self::RecoveryBlocked {
                blocking_operation_id,
            } => write!(
                formatter,
                "revocation recovery must finish '{blocking_operation_id}' first"
            ),
            Self::InjectedCrash(point) => {
                write!(formatter, "injected revocation sender crash at {point:?}")
            }
            Self::Endpoint(message) => {
                write!(formatter, "sender endpoint ownership failed: {message}")
            }
            Self::Authority(message) => write!(formatter, "revocation authority failed: {message}"),
            Self::Identity(message) => write!(formatter, "revocation identity failed: {message}"),
            Self::Transaction(message) => {
                write!(formatter, "revocation coordinator failed: {message}")
            }
            Self::Integrity(message) => {
                write!(formatter, "revocation sender integrity failure: {message}")
            }
            Self::ResourceExhausted(message) => {
                write!(formatter, "revocation sender resource exhausted: {message}")
            }
            Self::UnsafePath(path) => {
                write!(
                    formatter,
                    "unsafe revocation sender path '{}'",
                    path.display()
                )
            }
            Self::ImmutableConflict(path) => write!(
                formatter,
                "immutable revocation sender record '{}' conflicts",
                path.display()
            ),
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "revocation sender serialization failed: {message}"
                )
            }
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "revocation sender I/O at '{}': {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for M6RevocationSenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<M6IdentityError> for M6RevocationSenderError {
    fn from(error: M6IdentityError) -> Self {
        Self::Identity(error.to_string())
    }
}

impl From<M6AuthorityError> for M6RevocationSenderError {
    fn from(error: M6AuthorityError) -> Self {
        Self::Authority(error.to_string())
    }
}

impl From<M6TransactionError> for M6RevocationSenderError {
    fn from(error: M6TransactionError) -> Self {
        Self::Transaction(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m6_authority::{
        ActionAuthorizationRequest, AuthorizationIssuer, OpaqueAuthorizationSigner,
    };
    use crate::m6_identity::{
        AttachmentInput, DeterministicClock, DeterministicNonceSource, ExportManifestPayload,
        FactoryIdentityDocument, RouteResourceProfile, SignedManifest,
    };
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct TestCredential {
        issuer_id: String,
        secret: Vec<u8>,
    }

    impl TestCredential {
        fn new() -> Self {
            Self {
                issuer_id: "issuer:sender-revocation".to_string(),
                secret: b"sender-revocation-test-credential".to_vec(),
            }
        }

        fn proof(&self, payload_digest: &ContentDigest) -> String {
            let mut hasher = Sha256::new();
            hasher.update(b"wasm-biotic:m6:sender-revocation-test-authority:v1");
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
                "wasm-biotic-m6-revocation-sender-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create revocation sender test root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.exists() && std::env::var_os("KEEP_M6_REVOCATION_SENDER_TEST_ROOT").is_none()
            {
                fs::remove_dir_all(&self.0).expect("remove revocation sender test root");
            }
        }
    }

    struct TestRig {
        _root: TestRoot,
        sender_root: PathBuf,
        route_root: PathBuf,
        route: RouteDefinition,
        profile: EndpointActionProfile,
        credential: TestCredential,
        clock: Arc<DeterministicClock>,
        nonce: Arc<DeterministicNonceSource>,
    }

    impl TestRig {
        fn new(label: &str) -> Self {
            let root = TestRoot::new(label);
            let sender_root = root.0.join("sender");
            let receiver_root = root.0.join("receiver");
            let route_root = root.0.join("route");
            fs::create_dir(&sender_root).expect("sender root");
            fs::create_dir(&receiver_root).expect("receiver root");
            fs::create_dir(&route_root).expect("route root");

            let profile = EndpointActionProfile::new(
                "profile:sender-revocation",
                "factory:sender",
                "issuer:sender-revocation",
                content("revocation-authority-implementation"),
                EndpointAuthorityKind::Revocation,
            )
            .expect("revocation authority profile");
            let sender_signer = sender_signer();
            let receiver_signer =
                FactorySigner::from_seed("key:receiver-v1", [0x72; 32]).expect("receiver signer");
            let package_schemas = vec![content("factory-package-schema")];
            let interface_schemas = vec![content("factory-interface-schema")];
            let exchange_policy_digest = content("exchange-policy");
            let sender_identity = FactoryIdentityDocument::new(
                "factory:sender",
                &sender_signer,
                1,
                10_000_000,
                package_schemas.clone(),
                interface_schemas.clone(),
                profile.profile_digest().clone(),
                exchange_policy_digest.clone(),
            )
            .expect("sender identity");
            let receiver_identity = FactoryIdentityDocument::new(
                "factory:receiver",
                &receiver_signer,
                1,
                10_000_000,
                package_schemas,
                interface_schemas,
                content("receiver-authority-profile"),
                exchange_policy_digest.clone(),
            )
            .expect("receiver identity");
            let route = RouteDefinition::new(
                "route:sender-to-receiver",
                1,
                &sender_identity,
                &receiver_identity,
                exchange_policy_digest,
                RouteResourceProfile::bounded_default().expect("route resources"),
            )
            .expect("route definition");
            GovernedFilesystemSpool::initialize(
                &route_root,
                &sender_root,
                &receiver_root,
                route.clone(),
            )
            .expect("initialize governed route");
            Self {
                _root: root,
                sender_root,
                route_root,
                route,
                profile,
                credential: TestCredential::new(),
                clock: Arc::new(DeterministicClock::new(1_000_000)),
                nonce: Arc::new(DeterministicNonceSource::new([0x63; 32])),
            }
        }

        fn config(&self) -> M6RevocationSenderRuntimeConfig {
            M6RevocationSenderRuntimeConfig {
                endpoint_root: self.sender_root.clone(),
                route_root: self.route_root.clone(),
                expected_route_definition_digest: self.route.definition_digest.clone(),
                authorization_profile: self.profile.clone(),
                journal_config: JournalConfig::bounded(128, 8).expect("journal bounds"),
                retry_policy: RetryPolicy::bounded(8, 8, 1_000).expect("retry bounds"),
                max_revocation_requests: 128,
                max_revocation_receipts: 128,
            }
        }

        fn open(&self) -> M6RevocationSenderRuntime<TestCredential> {
            let clock: Arc<dyn Clock> = self.clock.clone();
            let nonce: Arc<dyn NonceSource> = self.nonce.clone();
            M6RevocationSenderRuntime::open(
                self.config(),
                self.credential.clone(),
                sender_signer(),
                clock,
                nonce,
            )
            .expect("open sender revocation runtime")
        }

        fn authorization(
            &self,
            binding: ExactActionBinding,
            issued_at_ms: u64,
            expires_at_ms: u64,
        ) -> ActionAuthorization {
            AuthorizationIssuer::new(self.profile.clone(), self.credential.clone())
                .expect("authorization issuer")
                .issue(
                    ActionAuthorizationRequest::new(binding, 1).expect("exact revocation action"),
                    issued_at_ms,
                    expires_at_ms,
                )
                .expect("issue revocation authorization")
        }

        fn authorize(
            &self,
            runtime: &M6RevocationSenderRuntime<TestCredential>,
            prepared: &PreparedSenderRevocation,
        ) -> ContentDigest {
            let now = self.clock.now_ms().expect("trusted clock");
            runtime
                .publish_authorization(self.authorization(
                    prepared.authorization_binding.clone(),
                    now,
                    now + 50_000,
                ))
                .expect("publish exact revocation authorization")
        }
    }

    fn content(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(label.as_bytes())
    }

    fn sender_signer() -> FactorySigner {
        FactorySigner::from_seed("key:sender-v1", [0x51; 32]).expect("sender signer")
    }

    fn export_payload(label: &str) -> ManifestPayload {
        ManifestPayload::Export(ExportManifestPayload {
            component_digest: content(&format!("component:{label}")),
            export_bundle_digest: content(&format!("bundle:{label}")),
            package_bytes_digest: content(&format!("package-bytes:{label}")),
            package_digest: content(&format!("package:{label}")),
        })
    }

    fn issue_export(
        rig: &TestRig,
        logical_operation_id: &str,
        commit: bool,
    ) -> (IssuedManifest, ContentDigest) {
        let endpoint_owner =
            acquire_sender_endpoint_owner(&rig.sender_root).expect("sender endpoint owner");
        let clock: Arc<dyn Clock> = rig.clock.clone();
        let nonce: Arc<dyn NonceSource> = rig.nonce.clone();
        let mut issuer = ManifestIssuer::open_or_initialize(
            &rig.sender_root,
            rig.route.clone(),
            RouteEndpointRole::Sender,
            clock,
            nonce,
        )
        .expect("open shared sender issuer");
        let idempotency_key = format!("sender-export:{logical_operation_id}");
        let prepared = issuer
            .prepare_idempotent(
                idempotency_key.clone(),
                &sender_signer(),
                export_payload(logical_operation_id),
                vec![AttachmentInput::new(
                    "m5-export-bundle",
                    "application/json",
                    format!("export:{logical_operation_id}").into_bytes(),
                )],
                60_000,
            )
            .expect("prepare export on shared chain");
        let recovered = issuer
            .recover_issuance(&idempotency_key)
            .expect("recover export prepare")
            .expect("export prepare exists");
        if commit {
            let committed = issuer
                .commit_prepared_exact(&idempotency_key, &recovered.request_digest)
                .expect("commit export on shared chain");
            assert_eq!(committed, prepared);
        }
        drop(issuer);
        drop(endpoint_owner);
        (prepared, recovered.request_digest)
    }

    fn prepare(
        runtime: &mut M6RevocationSenderRuntime<TestCredential>,
        operation: &str,
        kind: RevocationTargetKindV1,
    ) -> PreparedSenderRevocation {
        runtime
            .prepare_revocation(
                operation,
                "principal:revocation-operator",
                kind,
                content(&format!("target:{operation}")),
                format!("revoke {operation}"),
                content(&format!("prior-source-authorization:{operation}")),
                60_000,
            )
            .expect("prepare revocation")
    }

    #[test]
    fn export_revocation_export_interleave_shares_exact_origin_chain() {
        let rig = TestRig::new("shared-origin-interleave");
        let (first_export, _) = issue_export(&rig, "export-n1", true);
        assert_eq!(first_export.manifest.unsigned.sequence, 1);

        let revocation_receipt = {
            let mut runtime = rig.open();
            let prepared = prepare(
                &mut runtime,
                "revocation-n2",
                RevocationTargetKindV1::SourcePackage,
            );
            assert_eq!(prepared.sequence, 2);
            assert_eq!(
                prepared.previous_message_digest,
                Some(first_export.manifest.message_digest.clone())
            );
            let authorization = rig.authorize(&runtime, &prepared);
            runtime
                .commit_revocation("revocation-n2", &authorization)
                .expect("commit interleaved revocation")
        };
        assert_eq!(revocation_receipt.sequence, 2);

        let (third_export, _) = issue_export(&rig, "export-n3", true);
        assert_eq!(third_export.manifest.unsigned.sequence, 3);
        assert_eq!(
            third_export.manifest.unsigned.previous_message_digest,
            Some(revocation_receipt.message_digest)
        );
    }

    #[test]
    fn pending_export_blocks_revocation_until_exact_abandon_or_commit() {
        for commit_pending in [false, true] {
            let label = if commit_pending {
                "pending-export-commit"
            } else {
                "pending-export-abandon"
            };
            let rig = TestRig::new(label);
            let (pending, request_digest) = issue_export(&rig, "pending-export", false);
            assert_eq!(pending.manifest.unsigned.sequence, 1);

            {
                let mut runtime = rig.open();
                assert!(matches!(
                    runtime.prepare_revocation(
                        "revocation-after-pending-export",
                        "principal:operator",
                        RevocationTargetKindV1::ExchangeMessage,
                        content("target:pending-export"),
                        "revoke after pending export",
                        content("source-evidence:pending-export"),
                        60_000,
                    ),
                    Err(M6RevocationSenderError::Identity(ref message))
                        if message.contains("durably pending exact chain commit")
                ));
                assert_eq!(runtime.last_committed_sequence(), 0);
            }

            let endpoint_owner =
                acquire_sender_endpoint_owner(&rig.sender_root).expect("sender endpoint owner");
            let clock: Arc<dyn Clock> = rig.clock.clone();
            let nonce: Arc<dyn NonceSource> = rig.nonce.clone();
            let mut issuer = ManifestIssuer::open_or_initialize(
                &rig.sender_root,
                rig.route.clone(),
                RouteEndpointRole::Sender,
                clock,
                nonce,
            )
            .expect("reopen shared issuer");
            if commit_pending {
                issuer
                    .commit_prepared_exact("sender-export:pending-export", &request_digest)
                    .expect("exactly commit pending export");
            } else {
                issuer
                    .abandon_prepared(
                        "sender-export:pending-export",
                        &request_digest,
                        PreparedIssuanceDisposition::OperatorCancelled,
                        "cancel pending export",
                        content("evidence:cancel-pending-export"),
                    )
                    .expect("exactly abandon pending export");
            }
            drop(issuer);
            drop(endpoint_owner);

            let mut runtime = rig.open();
            let prepared = runtime
                .prepare_revocation(
                    "revocation-after-pending-export",
                    "principal:operator",
                    RevocationTargetKindV1::ExchangeMessage,
                    content("target:pending-export"),
                    "revoke after pending export",
                    content("source-evidence:pending-export"),
                    60_000,
                )
                .expect("retry exact revocation after resolving export");
            assert_eq!(prepared.sequence, if commit_pending { 2 } else { 1 });
        }
    }

    #[test]
    fn all_four_target_kinds_publish_attachment_free_canonical_ready_units() {
        let rig = TestRig::new("four-target-kinds");
        let mut runtime = rig.open();
        for (index, kind) in [
            RevocationTargetKindV1::ExchangeMessage,
            RevocationTargetKindV1::SourcePackage,
            RevocationTargetKindV1::SourceSigningKey,
            RevocationTargetKindV1::SenderIdentity,
        ]
        .into_iter()
        .enumerate()
        {
            let operation = format!("revocation-kind-{index}");
            let prepared = prepare(&mut runtime, &operation, kind);
            assert_eq!(prepared.sequence, index as u64 + 1);
            let authorization = rig.authorize(&runtime, &prepared);
            let receipt = runtime
                .commit_revocation(&operation, &authorization)
                .expect("commit typed revocation");
            assert_eq!(receipt.target_kind, kind);
            assert_eq!(
                receipt.prior_source_authorization_evidence_digest,
                prepared.prior_source_authorization_evidence_digest
            );
            assert_ne!(
                receipt.current_revocation_authorization_digest,
                receipt.prior_source_authorization_evidence_digest,
                "current IssueRevocation credential must remain distinct from prior source evidence"
            );

            let ready = runtime
                .read_ready_revocation(&receipt.message_digest)
                .expect("canonical ready readback");
            assert!(ready.attachments.is_empty());
            assert!(ready.manifest.unsigned.attachments.is_empty());
            let canonical = ready
                .manifest
                .canonical_bytes()
                .expect("canonical ready manifest");
            assert_eq!(
                SignedManifest::from_canonical_bytes(&canonical)
                    .expect("reparse canonical ready manifest"),
                ready.manifest
            );
            let ManifestPayload::Revocation(payload) = &ready.manifest.unsigned.payload else {
                panic!("ready payload is not revocation")
            };
            assert_eq!(payload.target_kind, kind.label());
            assert_eq!(
                payload.authorization_digest,
                prepared.prior_source_authorization_evidence_digest
            );
            assert_eq!(
                runtime
                    .recover_revocation(&operation, &authorization)
                    .expect("exact terminal retry"),
                receipt
            );
            let projection = runtime
                .journal
                .transaction(&operation)
                .expect("read revocation transaction")
                .expect("revocation transaction exists");
            assert_eq!(
                projection
                    .stages
                    .iter()
                    .map(|stage| stage.stage)
                    .collect::<Vec<_>>(),
                vec![
                    TransactionStage::RevocationIntentRecorded,
                    TransactionStage::RevocationOutboundCommitted,
                    TransactionStage::RevocationRouteStageCommitted,
                    TransactionStage::RevocationRouteReadyCommitted,
                    TransactionStage::RevocationReceiptCommitted,
                ]
            );
        }
    }

    #[test]
    fn denial_and_expiry_abandon_exact_prepares_without_sequence_gap() {
        let rig = TestRig::new("denial-expiry-no-gap");
        let mut runtime = rig.open();

        let denied = prepare(
            &mut runtime,
            "revocation-denied",
            RevocationTargetKindV1::SourcePackage,
        );
        assert_eq!(denied.sequence, 1);
        let denied_abandonment = runtime
            .abandon_revocation(
                "revocation-denied",
                PreparedIssuanceDisposition::AuthorizationDenied,
                "revocation authority denied",
                content("decision:denied"),
            )
            .expect("abandon denied revocation");
        assert_eq!(
            runtime
                .abandon_revocation(
                    "revocation-denied",
                    PreparedIssuanceDisposition::AuthorizationDenied,
                    "revocation authority denied",
                    content("decision:denied"),
                )
                .expect("exact abandonment retry"),
            denied_abandonment
        );
        assert_eq!(runtime.last_committed_sequence(), 0);

        let expired = prepare(
            &mut runtime,
            "revocation-expired",
            RevocationTargetKindV1::SourceSigningKey,
        );
        assert_eq!(expired.sequence, 1);
        let now = rig.clock.now_ms().expect("trusted clock");
        let expiring_authorization = runtime
            .publish_authorization(rig.authorization(
                expired.authorization_binding.clone(),
                now,
                now + 10,
            ))
            .expect("publish expiring authorization");
        rig.clock.advance(10);
        assert!(matches!(
            runtime.commit_revocation("revocation-expired", &expiring_authorization),
            Err(M6RevocationSenderError::Authority(ref message))
                if message.contains("expired")
        ));
        runtime
            .abandon_revocation(
                "revocation-expired",
                PreparedIssuanceDisposition::AuthorizationExpired,
                "revocation authority expired",
                content("decision:expired"),
            )
            .expect("abandon expired revocation");
        assert_eq!(runtime.last_committed_sequence(), 0);

        let accepted = prepare(
            &mut runtime,
            "revocation-accepted",
            RevocationTargetKindV1::SenderIdentity,
        );
        assert_eq!(accepted.sequence, 1);
        let authorization = rig.authorize(&runtime, &accepted);
        let receipt = runtime
            .commit_revocation("revocation-accepted", &authorization)
            .expect("commit accepted revocation after abandonments");
        assert_eq!(receipt.sequence, 1);
        assert_eq!(runtime.last_committed_sequence(), 1);
    }

    #[test]
    fn every_prepare_and_publication_crash_boundary_recovers_exactly() {
        for point in [
            RevocationSenderCrashPoint::RequestPersisted,
            RevocationSenderCrashPoint::PreparedIssuancePersisted,
        ] {
            let rig = TestRig::new(&format!("prepare-crash-{point:?}"));
            {
                let mut runtime = rig.open();
                assert!(matches!(
                    runtime.prepare_revocation_with_fault(
                        "revocation-prepare-crash",
                        "principal:operator",
                        RevocationTargetKindV1::ExchangeMessage,
                        content("target:prepare-crash"),
                        "prepare crash recovery",
                        content("source-evidence:prepare-crash"),
                        60_000,
                        Some(point),
                    ),
                    Err(M6RevocationSenderError::InjectedCrash(actual)) if actual == point
                ));
            }
            let mut reopened = rig.open();
            let recovered = reopened
                .prepare_revocation(
                    "revocation-prepare-crash",
                    "principal:operator",
                    RevocationTargetKindV1::ExchangeMessage,
                    content("target:prepare-crash"),
                    "prepare crash recovery",
                    content("source-evidence:prepare-crash"),
                    60_000,
                )
                .expect("recover exact prepare");
            assert_eq!(recovered.sequence, 1);
        }

        for point in [
            RevocationSenderCrashPoint::AbandonmentEffectCommitted,
            RevocationSenderCrashPoint::AbandonmentReceiptCommitted,
        ] {
            let rig = TestRig::new(&format!("abandonment-crash-{point:?}"));
            {
                let mut runtime = rig.open();
                prepare(
                    &mut runtime,
                    "revocation-abandonment-crash",
                    RevocationTargetKindV1::SourceSigningKey,
                );
                assert!(matches!(
                    runtime.abandon_revocation_with_fault(
                        "revocation-abandonment-crash",
                        PreparedIssuanceDisposition::AuthorizationDenied,
                        "deny crash control",
                        content("decision:abandonment-crash"),
                        Some(point),
                    ),
                    Err(M6RevocationSenderError::InjectedCrash(actual)) if actual == point
                ));
            }
            let mut reopened = rig.open();
            let recovered = reopened
                .abandon_revocation(
                    "revocation-abandonment-crash",
                    PreparedIssuanceDisposition::AuthorizationDenied,
                    "deny crash control",
                    content("decision:abandonment-crash"),
                )
                .expect("recover exact abandonment");
            assert_eq!(recovered.sequence, 1);
            assert_eq!(reopened.last_committed_sequence(), 0);
        }

        for point in [
            RevocationSenderCrashPoint::RevocationIntentRecorded,
            RevocationSenderCrashPoint::RevocationOutboundCommitted,
            RevocationSenderCrashPoint::AuthorizationConsumed,
            RevocationSenderCrashPoint::OriginChainCommitted,
            RevocationSenderCrashPoint::RouteStageEffectCommitted,
            RevocationSenderCrashPoint::RevocationRouteStageCommitted,
            RevocationSenderCrashPoint::RouteReadyEffectCommitted,
            RevocationSenderCrashPoint::RevocationRouteReadyCommitted,
            RevocationSenderCrashPoint::ReceiptEffectCommitted,
            RevocationSenderCrashPoint::RevocationReceiptCommitted,
        ] {
            let rig = TestRig::new(&format!("publication-crash-{point:?}"));
            let authorization;
            {
                let mut runtime = rig.open();
                let prepared = prepare(
                    &mut runtime,
                    "revocation-publication-crash",
                    RevocationTargetKindV1::SourcePackage,
                );
                authorization = rig.authorize(&runtime, &prepared);
                assert!(matches!(
                    runtime.commit_revocation_with_fault(
                        "revocation-publication-crash",
                        &authorization,
                        Some(point),
                    ),
                    Err(M6RevocationSenderError::InjectedCrash(actual)) if actual == point
                ));
            }
            let mut reopened = rig.open();
            let receipt = reopened
                .recover_revocation("revocation-publication-crash", &authorization)
                .expect("recover exact publication");
            assert_eq!(receipt.sequence, 1);
            assert_eq!(
                reopened
                    .recover_revocation("revocation-publication-crash", &authorization)
                    .expect("idempotent terminal retry"),
                receipt
            );
            assert_eq!(reopened.last_committed_sequence(), 1);
        }
    }

    #[test]
    fn wrong_authorization_changed_request_tamper_and_duplicate_owner_fail_closed() {
        let rig = TestRig::new("negative-controls");
        let mut runtime = rig.open();
        let second_open = M6RevocationSenderRuntime::open(
            rig.config(),
            rig.credential.clone(),
            sender_signer(),
            rig.clock.clone(),
            rig.nonce.clone(),
        );
        assert!(matches!(
            second_open,
            Err(M6RevocationSenderError::Endpoint(ref message))
                if message.contains("already")
        ));

        let first = prepare(
            &mut runtime,
            "revocation-auth-first",
            RevocationTargetKindV1::ExchangeMessage,
        );
        let first_authorization = rig.authorize(&runtime, &first);
        runtime
            .commit_revocation("revocation-auth-first", &first_authorization)
            .expect("commit first authorization");

        let second = prepare(
            &mut runtime,
            "revocation-auth-second",
            RevocationTargetKindV1::SourcePackage,
        );
        assert!(matches!(
            runtime.prepare_revocation(
                "revocation-auth-second",
                "principal:revocation-operator",
                RevocationTargetKindV1::SourcePackage,
                content("target:revocation-auth-second"),
                "changed reason",
                content("prior-source-authorization:revocation-auth-second"),
                60_000,
            ),
            Err(M6RevocationSenderError::Conflict { .. })
        ));
        assert!(matches!(
            runtime.commit_revocation("revocation-auth-second", &first_authorization),
            Err(M6RevocationSenderError::Authority(ref message))
                if message.contains("exact prepared revocation")
        ));
        assert_eq!(runtime.last_committed_sequence(), 1);
        let second_authorization = rig.authorize(&runtime, &second);
        runtime
            .commit_revocation("revocation-auth-second", &second_authorization)
            .expect("commit second exact authorization");
        drop(runtime);

        let tamper_rig = TestRig::new("request-tamper");
        {
            let mut runtime = tamper_rig.open();
            prepare(
                &mut runtime,
                "revocation-tampered",
                RevocationTargetKindV1::SenderIdentity,
            );
        }
        let path = request_path(
            &tamper_rig.sender_root.join(REQUESTS_DIRECTORY),
            "revocation-tampered",
        );
        let bytes = fs::read(&path).expect("read retained request");
        let mut value: serde_json::Value =
            serde_json::from_slice(&bytes).expect("parse retained request");
        value.as_object_mut().expect("request object").insert(
            "reason".to_string(),
            serde_json::Value::String("tampered reason".to_string()),
        );
        fs::write(
            &path,
            canonical_json(&value).expect("canonical tampered request"),
        )
        .expect("tamper request");
        assert!(matches!(
            M6RevocationSenderRuntime::open(
                tamper_rig.config(),
                tamper_rig.credential.clone(),
                sender_signer(),
                tamper_rig.clock.clone(),
                tamper_rig.nonce.clone(),
            ),
            Err(M6RevocationSenderError::Integrity(ref message))
                if message.contains("request digest mismatch")
        ));
    }
}
