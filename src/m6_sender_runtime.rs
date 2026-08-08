//! Governed M6 sender publication over one healthy, adopted M5 factory.
//!
//! The sender is deliberately two phase. [`M6SenderRuntime::prepare_export`]
//! first persists an immutable outer request and an exact signed issuance
//! without consuming the route sequence. It returns the exact
//! [`ExactActionBinding`] that an export authority must authorize. Only
//! [`M6SenderRuntime::commit_export`] may consume that authorization, commit
//! the prepared origin-chain entry, stage the route unit, and make it ready.
//!
//! This split is a safety property, not an ergonomic choice: a signed message
//! digest contains runtime-owned sequence, nonce, and clock values, while the
//! authorization must bind that exact digest. Consuming a sequence during
//! preparation would leave a permanent receiver-visible gap when authority is
//! denied or expires.

use crate::execution::artifact::ContentDigest;
use crate::factory_reproduction::{FactoryPackage, LiveProviderQualificationPort};
use crate::m5_export::{M5ExportBundleV1, M5ExportPackageV1};
use crate::m5_runtime::{M5Runtime, M5RuntimeConfig};
use crate::m6_authority::{
    ActionAuthorization, AuthorityAction, AuthorizationConsumption, AuthorizationStore,
    EndpointActionProfile, EndpointAuthorityKind, ExactActionBinding, M6AuthorityError,
    OpaqueAuthorizationVerifier,
};
use crate::m6_identity::{
    AttachmentDescriptor, AttachmentInput, Clock, ExportManifestPayload, FactorySigner,
    GovernedFilesystemSpool, IDENTITY_MUTABLE_TOP_LEVEL_DIRECTORIES, IssuedManifest,
    M6IdentityError, ManifestIssuer, ManifestPayload, NonceSource, PreparedIssuanceAbandonment,
    PreparedIssuanceDisposition, PreparedIssuanceResolution, RouteDefinition, RouteEndpointRole,
    SignedManifest, verify_sender_export_completion_signature,
    verify_sender_isolation_audit_signature, verify_sender_reopen_audit_signature,
};
use crate::m6_import::{
    M5_EXPORT_ATTACHMENT_MEDIA_TYPE, M5_EXPORT_ATTACHMENT_NAME, M5_PACKAGE_ATTACHMENT_MEDIA_TYPE,
    M5_RECIPE_ATTACHMENT_MEDIA_TYPE, m5_package_attachment_name, m5_recipe_attachment_name,
};
use crate::m6_transactions::{
    CoordinatorJournal, JournalConfig, M6TransactionError, RetryPolicy, StageCause, StageEvidence,
    TransactionKind, TransactionRequestDraft, TransactionStage,
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

pub const SENDER_EXPORT_REQUEST_SCHEMA: &str = "wasm-biotic.m6-sender-export-request.v1";
pub const SENDER_EXPORT_REQUEST_COMMIT_SCHEMA: &str =
    "wasm-biotic.m6-sender-export-request-commit.v1";
pub const SENDER_EXPORT_RECEIPT_SCHEMA: &str = "wasm-biotic.m6-sender-export-receipt.v1";
pub const SENDER_EXPORT_CLEARANCE_SCHEMA: &str = "wasm-biotic.m6-sender-export-clearance.v1";
pub const SENDER_EXPORT_ABANDONMENT_SCHEMA: &str = "wasm-biotic.m6-sender-export-abandonment.v1";
pub const SENDER_EXPORT_COMPLETION_EVIDENCE_SCHEMA: &str =
    "wasm-biotic.m6-sender-export-completion-evidence.v1";
pub const SENDER_POST_ROLLBACK_ISOLATION_AUDIT_SCHEMA: &str =
    "wasm-biotic.m6-sender-post-rollback-isolation-audit.v1";
pub const SENDER_REOPEN_AUDIT_SCHEMA: &str = "wasm-biotic.m6-sender-reopen-audit.v1";
pub const SENDER_REOPEN_PROOF_SCHEMA: &str = "wasm-biotic.m6-sender-reopen-proof.v1";

const REQUEST_DIGEST_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-export-request:v1\0";
const REQUEST_COMMIT_DIGEST_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-export-request-commit:v1\0";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-export-receipt:v1\0";
const CLEARANCE_DIGEST_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-export-clearance:v1\0";
const ABANDONMENT_DIGEST_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-export-abandonment:v1\0";
const DELIVERY_FACT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-delivery-fact:v1\0";
const COMPLETION_EVIDENCE_DIGEST_DOMAIN: &[u8] =
    b"wasm-biotic:m6:sender-export-completion-evidence:v1\0";
const POST_ROLLBACK_ISOLATION_AUDIT_DIGEST_DOMAIN: &[u8] =
    b"wasm-biotic:m6:sender-post-rollback-isolation-audit:v1\0";
const REOPEN_AUDIT_DIGEST_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-reopen-audit:v1\0";
const REOPEN_PROOF_DIGEST_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-reopen-proof:v1\0";
const DURABLE_STATE_ROOT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-durable-state-root:v1\0";
const PROCESS_INSTANCE_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-process-instance:v1\0";
const NOT_APPLICABLE_IMPORT_PLAN: &[u8] = b"wasm-biotic:m6:sender-export:no-import-plan:v1";
const NOT_APPLICABLE_PROVING: &[u8] = b"wasm-biotic:m6:sender-export:no-receiver-proving:v1";
const NOT_APPLICABLE_APPROVAL: &[u8] = b"wasm-biotic:m6:sender-export:no-import-approval:v1";

const OWNER_LOCK_FILE: &str = ".m6-sender-endpoint.lock";
const AUTHORITY_DIRECTORY: &str = "m6-sender-authority";
const JOURNAL_DIRECTORY: &str = "m6-sender-coordinator";
const REQUESTS_DIRECTORY: &str = "m6-sender-export-requests";
const RECEIPTS_DIRECTORY: &str = "m6-sender-export-receipts";
const CLEARANCES_DIRECTORY: &str = "m6-sender-export-clearances";
const ABANDONMENTS_DIRECTORY: &str = "m6-sender-export-abandonments";
const REOPEN_AUDITS_DIRECTORY: &str = "m6-sender-reopen-audits";
const REQUEST_RECORD_FILE: &str = "request.json";
const REQUEST_BUNDLE_FILE: &str = "m5-export-bundle.json";
const REQUEST_COMMIT_FILE: &str = "commit.json";
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_REQUEST_RECORD_BYTES: usize = 2 * 1_048_576;
const MAX_RECEIPT_BYTES: usize = 2 * 1_048_576;
const MAX_CLEARANCE_BYTES: usize = 512 * 1_024;
const MAX_ABANDONMENT_BYTES: usize = 512 * 1_024;
const MAX_COMPLETION_EVIDENCE_BYTES: usize = 256 * 1_048_576;
const MAX_ISOLATION_AUDIT_BYTES: usize = 256 * 1_048_576;
const MAX_REOPEN_AUDIT_BYTES: usize = 8 * 1_048_576;
const MAX_DURABLE_STATE_ENTRIES: usize = 100_000;
const MAX_DURABLE_STATE_FILE_BYTES: usize = 256 * 1_048_576;
const MAX_DURABLE_STATE_AGGREGATE_BYTES: u64 = 2 * 1_073_741_824;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Paths are live configuration only. This type is never persisted by the
/// sender runtime, which prevents the neutral route path from leaking into
/// endpoint evidence and leaves no place to accept a peer endpoint root.
#[derive(Clone, Debug)]
pub struct M6SenderRuntimeConfig {
    pub endpoint_root: PathBuf,
    pub m5: M5RuntimeConfig,
    pub route_root: PathBuf,
    pub expected_route_definition_digest: ContentDigest,
    pub authorization_profile: EndpointActionProfile,
    pub journal_config: JournalConfig,
    pub retry_policy: RetryPolicy,
    pub max_export_requests: u32,
    pub max_export_receipts: u32,
}

impl M6SenderRuntimeConfig {
    fn validate_non_path_fields(&self) -> Result<(), M6SenderError> {
        self.m5
            .validate()
            .map_err(|error| M6SenderError::M5(error.to_string()))?;
        self.journal_config
            .validate()
            .map_err(|error| M6SenderError::Transaction(error.to_string()))?;
        if self.endpoint_root.as_os_str().is_empty()
            || self.route_root.as_os_str().is_empty()
            || self.max_export_requests == 0
            || self.max_export_receipts == 0
            || self.max_export_requests > self.journal_config.max_transactions
            || self.max_export_receipts > self.max_export_requests
            || self.journal_config.max_stages_per_transaction < 5
            || self.retry_policy.max_attempts == 0
            || self.retry_policy.max_attempts > 32
            || self.retry_policy.max_recovery_attempts > self.retry_policy.max_attempts
            || self.retry_policy.attempt_timeout_ms == 0
            || self.authorization_profile.authority_kind() != EndpointAuthorityKind::Export
            || !self
                .authorization_profile
                .supports(AuthorityAction::ExportPackage)
            || self.authorization_profile.factory_id() != self.m5.factory_id
        {
            return Err(M6SenderError::InvalidConfiguration(
                "sender roots, bounds, factory identity, or Export authority profile are invalid"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// One package's redundant route-attachment closure.
///
/// Multiple bindings may deliberately cite the same recipe digest. The
/// manifest carries one descriptor per unique content digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderPackageAttachmentBinding {
    pub active: bool,
    pub package_attachment_digest: ContentDigest,
    pub package_digest: ContentDigest,
    pub recipe_attachment_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderExportRequest {
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
    bundle_bytes_digest: ContentDigest,
    bundle_digest: ContentDigest,
    package_digest: ContentDigest,
    package_bytes_digest: ContentDigest,
    component_digest: ContentDigest,
    active_snapshot_digest: ContentDigest,
    attachments: Vec<AttachmentDescriptor>,
    package_attachment_bindings: Vec<SenderPackageAttachmentBinding>,
    request_digest: ContentDigest,
}

#[derive(Serialize)]
struct SenderExportRequestDigestMaterial<'a> {
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
    bundle_bytes_digest: &'a ContentDigest,
    bundle_digest: &'a ContentDigest,
    package_digest: &'a ContentDigest,
    package_bytes_digest: &'a ContentDigest,
    component_digest: &'a ContentDigest,
    active_snapshot_digest: &'a ContentDigest,
    attachments: &'a [AttachmentDescriptor],
    package_attachment_bindings: &'a [SenderPackageAttachmentBinding],
}

impl SenderExportRequest {
    #[allow(clippy::too_many_arguments)]
    fn new(
        logical_operation_id: String,
        principal_id: String,
        captured_at_ms: u64,
        message_lifetime_ms: u64,
        route: &RouteDefinition,
        bundle: &M5ExportBundleV1,
        material: &ExportMaterial,
    ) -> Result<Self, M6SenderError> {
        validate_identifier("logical operation id", &logical_operation_id)?;
        validate_identifier("export principal id", &principal_id)?;
        let issuance_idempotency_key = format!("sender-export:{logical_operation_id}");
        validate_identifier("issuance idempotency key", &issuance_idempotency_key)?;
        let mut request = Self {
            schema: SENDER_EXPORT_REQUEST_SCHEMA.to_string(),
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
            bundle_bytes_digest: ContentDigest::from_bytes(&material.bundle_bytes),
            bundle_digest: bundle.bundle_digest().clone(),
            package_digest: material.active_package.package_digest.clone(),
            package_bytes_digest: bundle
                .active_package()
                .canonical_package_bytes_digest()
                .clone(),
            component_digest: material
                .active_package
                .payload
                .genome
                .component_digest
                .clone(),
            active_snapshot_digest: bundle.active_runtime_snapshot().snapshot_digest.clone(),
            attachments: material.descriptors.clone(),
            package_attachment_bindings: material.package_bindings.clone(),
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = request.expected_digest()?;
        request.validate(route, &material.bundle_bytes)?;
        Ok(request)
    }

    fn validate(&self, route: &RouteDefinition, bundle_bytes: &[u8]) -> Result<(), M6SenderError> {
        if self.schema != SENDER_EXPORT_REQUEST_SCHEMA {
            return Err(M6SenderError::Integrity(
                "unsupported sender export request schema".to_string(),
            ));
        }
        validate_identifier("logical operation id", &self.logical_operation_id)?;
        validate_identifier("export principal id", &self.principal_id)?;
        validate_identifier("issuance idempotency key", &self.issuance_idempotency_key)?;
        route
            .validate()
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        if self.message_lifetime_ms == 0
            || self.message_lifetime_ms > route.resource_profile.max_message_lifetime_ms
            || self.route_id != route.route_id
            || self.route_generation != route.generation
            || self.route_definition_digest != route.definition_digest
            || self.sender_identity_document_digest != route.sender.identity_document_digest
            || self.receiver_identity_document_digest != route.receiver.identity_document_digest
            || self.exchange_policy_digest != route.exchange_policy_digest
            || self.resource_profile_digest != route.resource_profile.profile_digest
            || self.bundle_bytes_digest != ContentDigest::from_bytes(bundle_bytes)
        {
            return Err(M6SenderError::Integrity(
                "sender export request differs from its route or retained bundle".to_string(),
            ));
        }
        let bundle = M5ExportBundleV1::from_canonical_bytes(bundle_bytes)
            .map_err(|error| M6SenderError::M5(error.to_string()))?;
        let material = build_export_material(&bundle, route)?;
        if material.bundle_bytes != bundle_bytes
            || self.bundle_digest != *bundle.bundle_digest()
            || self.package_digest != material.active_package.package_digest
            || self.package_bytes_digest
                != *bundle.active_package().canonical_package_bytes_digest()
            || self.component_digest != material.active_package.payload.genome.component_digest
            || self.active_snapshot_digest != bundle.active_runtime_snapshot().snapshot_digest
            || self.attachments != material.descriptors
            || self.package_attachment_bindings != material.package_bindings
        {
            return Err(M6SenderError::Integrity(
                "sender export request closure is missing, stale, or cross-linked".to_string(),
            ));
        }
        require_digest(
            "sender export request",
            &self.request_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderError> {
        digest_domain(
            REQUEST_DIGEST_DOMAIN,
            &SenderExportRequestDigestMaterial {
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
                bundle_bytes_digest: &self.bundle_bytes_digest,
                bundle_digest: &self.bundle_digest,
                package_digest: &self.package_digest,
                package_bytes_digest: &self.package_bytes_digest,
                component_digest: &self.component_digest,
                active_snapshot_digest: &self.active_snapshot_digest,
                attachments: &self.attachments,
                package_attachment_bindings: &self.package_attachment_bindings,
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderExportRequestCommit {
    schema: String,
    bundle_bytes_digest: ContentDigest,
    request_digest: ContentDigest,
    request_record_bytes_digest: ContentDigest,
    commit_digest: ContentDigest,
}

impl SenderExportRequestCommit {
    fn new(
        request: &SenderExportRequest,
        request_record_bytes: &[u8],
        bundle_bytes: &[u8],
    ) -> Result<Self, M6SenderError> {
        let mut commit = Self {
            schema: SENDER_EXPORT_REQUEST_COMMIT_SCHEMA.to_string(),
            bundle_bytes_digest: ContentDigest::from_bytes(bundle_bytes),
            request_digest: request.request_digest.clone(),
            request_record_bytes_digest: ContentDigest::from_bytes(request_record_bytes),
            commit_digest: ContentDigest::from_bytes(&[]),
        };
        commit.commit_digest = commit.expected_digest()?;
        Ok(commit)
    }

    fn validate(
        &self,
        request: &SenderExportRequest,
        request_record_bytes: &[u8],
        bundle_bytes: &[u8],
    ) -> Result<(), M6SenderError> {
        if self.schema != SENDER_EXPORT_REQUEST_COMMIT_SCHEMA
            || self.bundle_bytes_digest != ContentDigest::from_bytes(bundle_bytes)
            || self.request_digest != request.request_digest
            || self.request_record_bytes_digest != ContentDigest::from_bytes(request_record_bytes)
        {
            return Err(M6SenderError::Integrity(
                "sender export request commit is incomplete or cross-linked".to_string(),
            ));
        }
        require_digest(
            "sender export request commit",
            &self.commit_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderError> {
        digest_domain(
            REQUEST_COMMIT_DIGEST_DOMAIN,
            &(
                &self.schema,
                &self.bundle_bytes_digest,
                &self.request_digest,
                &self.request_record_bytes_digest,
            ),
        )
    }
}

#[derive(Clone, Debug)]
struct ExportMaterial {
    active_package: FactoryPackage,
    bundle_bytes: Vec<u8>,
    descriptors: Vec<AttachmentDescriptor>,
    inputs: Vec<AttachmentInput>,
    package_bindings: Vec<SenderPackageAttachmentBinding>,
}

/// The exact result of preparation. `authorization_binding` is suitable for
/// an Export-profile [`crate::m6_authority::AuthorizationIssuer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedSenderExport {
    pub logical_operation_id: String,
    pub request_digest: ContentDigest,
    pub bundle_digest: ContentDigest,
    pub package_digest: ContentDigest,
    pub active_snapshot_digest: ContentDigest,
    pub message_digest: ContentDigest,
    pub sequence: u64,
    pub authorization_binding: ExactActionBinding,
}

/// Durable sender-local evidence that the exact signed delivery is ready.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderExportReceipt {
    pub schema: String,
    pub logical_operation_id: String,
    pub outer_request_digest: ContentDigest,
    pub coordinator_request_digest: ContentDigest,
    pub route_definition_digest: ContentDigest,
    pub route_id: String,
    pub route_generation: u64,
    pub message_digest: ContentDigest,
    pub sequence: u64,
    pub bundle_digest: ContentDigest,
    pub package_digest: ContentDigest,
    pub active_snapshot_digest: ContentDigest,
    pub authorization_digest: ContentDigest,
    pub authorization_consumption_digest: ContentDigest,
    pub ready_delivery_digest: ContentDigest,
    pub committed_at_ms: u64,
    pub receipt_digest: ContentDigest,
}

impl SenderExportReceipt {
    #[allow(clippy::too_many_arguments)]
    fn new(
        request: &SenderExportRequest,
        coordinator_request_digest: ContentDigest,
        issued: &IssuedManifest,
        consumption: &AuthorizationConsumption,
        ready_delivery_digest: ContentDigest,
        committed_at_ms: u64,
    ) -> Result<Self, M6SenderError> {
        let mut receipt = Self {
            schema: SENDER_EXPORT_RECEIPT_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            outer_request_digest: request.request_digest.clone(),
            coordinator_request_digest,
            route_definition_digest: request.route_definition_digest.clone(),
            route_id: request.route_id.clone(),
            route_generation: request.route_generation,
            message_digest: issued.manifest.message_digest.clone(),
            sequence: issued.manifest.unsigned.sequence,
            bundle_digest: request.bundle_digest.clone(),
            package_digest: request.package_digest.clone(),
            active_snapshot_digest: request.active_snapshot_digest.clone(),
            authorization_digest: consumption.authorization_digest().clone(),
            authorization_consumption_digest: consumption.receipt_digest().clone(),
            ready_delivery_digest,
            committed_at_ms,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        Ok(receipt)
    }

    fn validate(
        &self,
        request: &SenderExportRequest,
        coordinator_request_digest: &ContentDigest,
        issued: &IssuedManifest,
        consumption: &AuthorizationConsumption,
        ready_delivery_digest: &ContentDigest,
    ) -> Result<(), M6SenderError> {
        if self.schema != SENDER_EXPORT_RECEIPT_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.outer_request_digest != request.request_digest
            || &self.coordinator_request_digest != coordinator_request_digest
            || self.route_definition_digest != request.route_definition_digest
            || self.route_id != request.route_id
            || self.route_generation != request.route_generation
            || self.message_digest != issued.manifest.message_digest
            || self.sequence != issued.manifest.unsigned.sequence
            || self.bundle_digest != request.bundle_digest
            || self.package_digest != request.package_digest
            || self.active_snapshot_digest != request.active_snapshot_digest
            || self.authorization_digest != *consumption.authorization_digest()
            || self.authorization_consumption_digest != *consumption.receipt_digest()
            || &self.ready_delivery_digest != ready_delivery_digest
        {
            return Err(M6SenderError::Integrity(
                "sender export receipt is missing or cross-linked".to_string(),
            ));
        }
        require_digest(
            "sender export receipt",
            &self.receipt_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderError> {
        digest_domain(
            RECEIPT_DIGEST_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.outer_request_digest,
                &self.coordinator_request_digest,
                &self.route_definition_digest,
                &self.route_id,
                self.route_generation,
                &self.message_digest,
                self.sequence,
                &self.bundle_digest,
                &self.package_digest,
                &self.active_snapshot_digest,
                &self.authorization_digest,
                &self.authorization_consumption_digest,
                &self.ready_delivery_digest,
                self.committed_at_ms,
            ),
        )
    }
}

/// Append-only evidence that live M5 still resolved to the immutable outer
/// request immediately before the first origin-chain commit attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderExportClearance {
    pub schema: String,
    pub logical_operation_id: String,
    pub outer_request_digest: ContentDigest,
    pub message_digest: ContentDigest,
    pub bundle_bytes_digest: ContentDigest,
    pub bundle_digest: ContentDigest,
    pub package_digest: ContentDigest,
    pub active_snapshot_digest: ContentDigest,
    pub checked_at_ms: u64,
    pub attempt: u32,
    pub previous_clearance_digest: Option<ContentDigest>,
    pub clearance_digest: ContentDigest,
}

impl SenderExportClearance {
    fn new(
        request: &SenderExportRequest,
        issued: &IssuedManifest,
        checked_at_ms: u64,
        attempt: u32,
        previous_clearance_digest: Option<ContentDigest>,
    ) -> Result<Self, M6SenderError> {
        if attempt == 0 {
            return Err(M6SenderError::Integrity(
                "sender export clearance attempt must be positive".to_string(),
            ));
        }
        let mut clearance = Self {
            schema: SENDER_EXPORT_CLEARANCE_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            outer_request_digest: request.request_digest.clone(),
            message_digest: issued.manifest.message_digest.clone(),
            bundle_bytes_digest: request.bundle_bytes_digest.clone(),
            bundle_digest: request.bundle_digest.clone(),
            package_digest: request.package_digest.clone(),
            active_snapshot_digest: request.active_snapshot_digest.clone(),
            checked_at_ms,
            attempt,
            previous_clearance_digest,
            clearance_digest: ContentDigest::from_bytes(&[]),
        };
        clearance.clearance_digest = clearance.expected_digest()?;
        clearance.validate(request, issued)?;
        Ok(clearance)
    }

    fn validate(
        &self,
        request: &SenderExportRequest,
        issued: &IssuedManifest,
    ) -> Result<(), M6SenderError> {
        if self.schema != SENDER_EXPORT_CLEARANCE_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.outer_request_digest != request.request_digest
            || self.message_digest != issued.manifest.message_digest
            || self.bundle_bytes_digest != request.bundle_bytes_digest
            || self.bundle_digest != request.bundle_digest
            || self.package_digest != request.package_digest
            || self.active_snapshot_digest != request.active_snapshot_digest
            || self.attempt == 0
            || (self.attempt == 1 && self.previous_clearance_digest.is_some())
            || (self.attempt > 1 && self.previous_clearance_digest.is_none())
        {
            return Err(M6SenderError::Integrity(
                "sender M5 publication clearance is missing or cross-linked".to_string(),
            ));
        }
        require_digest(
            "sender export clearance",
            &self.clearance_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderError> {
        digest_domain(
            CLEARANCE_DIGEST_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.outer_request_digest,
                &self.message_digest,
                &self.bundle_bytes_digest,
                &self.bundle_digest,
                &self.package_digest,
                &self.active_snapshot_digest,
                self.checked_at_ms,
                self.attempt,
                &self.previous_clearance_digest,
            ),
        )
    }
}

/// Sender-local terminal projection of an immutable identity-layer
/// abandonment. It frees the operation fence without deleting the signed
/// prepare or advancing the origin chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderExportAbandonment {
    pub schema: String,
    pub logical_operation_id: String,
    pub outer_request_digest: ContentDigest,
    pub issuance_request_digest: ContentDigest,
    pub route_definition_digest: ContentDigest,
    pub message_digest: ContentDigest,
    pub sequence: u64,
    pub disposition: PreparedIssuanceDisposition,
    pub reason: String,
    pub decision_evidence_digest: ContentDigest,
    pub identity_abandonment_digest: ContentDigest,
    pub abandoned_at_ms: u64,
    pub abandonment_digest: ContentDigest,
}

impl SenderExportAbandonment {
    fn new(
        request: &SenderExportRequest,
        issuance_request_digest: ContentDigest,
        abandonment: &PreparedIssuanceAbandonment,
    ) -> Result<Self, M6SenderError> {
        let mut record = Self {
            schema: SENDER_EXPORT_ABANDONMENT_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            outer_request_digest: request.request_digest.clone(),
            issuance_request_digest,
            route_definition_digest: request.route_definition_digest.clone(),
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
        request: &SenderExportRequest,
        abandonment: &PreparedIssuanceAbandonment,
    ) -> Result<(), M6SenderError> {
        if self.schema != SENDER_EXPORT_ABANDONMENT_SCHEMA
            || self.logical_operation_id != request.logical_operation_id
            || self.outer_request_digest != request.request_digest
            || self.route_definition_digest != request.route_definition_digest
            || self.message_digest != abandonment.message_digest
            || self.sequence != abandonment.sequence
            || self.disposition != abandonment.disposition
            || self.reason != abandonment.reason
            || self.decision_evidence_digest != abandonment.decision_evidence_digest
            || self.identity_abandonment_digest != abandonment.record_digest
            || self.abandoned_at_ms != abandonment.abandoned_at_ms
        {
            return Err(M6SenderError::Integrity(
                "sender abandonment projection is missing or cross-linked".to_string(),
            ));
        }
        require_digest(
            "sender export abandonment",
            &self.abandonment_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderError> {
        digest_domain(
            ABANDONMENT_DIGEST_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.outer_request_digest,
                &self.issuance_request_digest,
                &self.route_definition_digest,
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

/// Content identities for every exact durable source carried by one sender
/// export completion proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderExportCompletionSourceDigestsV1 {
    pub authorization: ContentDigest,
    pub authorization_consumption: ContentDigest,
    pub authorization_profile: ContentDigest,
    pub clearance: ContentDigest,
    pub m5_export_bundle: ContentDigest,
    pub ready_attachments: ContentDigest,
    pub ready_manifest: ContentDigest,
    pub receipt: ContentDigest,
    pub request_commit: ContentDigest,
    pub request_record: ContentDigest,
    pub retained_attachments: ContentDigest,
    pub retained_manifest: ContentDigest,
}

/// Portable, source-bound proof of one completed sender publication.
///
/// This record carries the exact canonical bytes reopened from every durable
/// sender boundary. It never accepts a caller-provided "completed" boolean.
/// Detached validation replays route signature verification, M5 export
/// validation, authority attestation verification, authorization-consumption
/// validation, delivery equality, clearance validation, and receipt
/// cross-linking.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderExportCompletionEvidenceV1 {
    schema: String,
    logical_operation_id: String,
    route_definition_digest: ContentDigest,
    signing_key_id: String,
    sender_factory_id: String,
    receiver_factory_id: String,
    message_digest: ContentDigest,
    previous_message_digest: Option<ContentDigest>,
    sequence: u64,
    bundle_digest: ContentDigest,
    package_digest: ContentDigest,
    active_snapshot_digest: ContentDigest,
    committed_at_ms: u64,
    receipt_digest: ContentDigest,
    source_digests: SenderExportCompletionSourceDigestsV1,
    request_record_bytes: Vec<u8>,
    request_commit_bytes: Vec<u8>,
    m5_export_bundle_bytes: Vec<u8>,
    retained_manifest_bytes: Vec<u8>,
    retained_attachments: BTreeMap<ContentDigest, Vec<u8>>,
    ready_manifest_bytes: Vec<u8>,
    ready_attachments: BTreeMap<ContentDigest, Vec<u8>>,
    authorization_profile_bytes: Vec<u8>,
    authorization_bytes: Vec<u8>,
    authorization_consumption_bytes: Vec<u8>,
    clearance_bytes: Vec<u8>,
    receipt_bytes: Vec<u8>,
    evidence_digest: ContentDigest,
    source_set_signature_hex: String,
}

impl SenderExportCompletionEvidenceV1 {
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

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn previous_message_digest(&self) -> Option<&ContentDigest> {
        self.previous_message_digest.as_ref()
    }

    pub fn bundle_digest(&self) -> &ContentDigest {
        &self.bundle_digest
    }

    pub fn package_digest(&self) -> &ContentDigest {
        &self.package_digest
    }

    pub fn active_snapshot_digest(&self) -> &ContentDigest {
        &self.active_snapshot_digest
    }

    pub fn committed_at_ms(&self) -> u64 {
        self.committed_at_ms
    }

    pub fn receipt_digest(&self) -> &ContentDigest {
        &self.receipt_digest
    }

    pub fn source_digests(&self) -> &SenderExportCompletionSourceDigestsV1 {
        &self.source_digests
    }

    pub fn m5_export_bundle_bytes(&self) -> &[u8] {
        &self.m5_export_bundle_bytes
    }

    pub fn retained_manifest_bytes(&self) -> &[u8] {
        &self.retained_manifest_bytes
    }

    pub fn evidence_digest(&self) -> &ContentDigest {
        &self.evidence_digest
    }

    pub fn source_set_signature_hex(&self) -> &str {
        &self.source_set_signature_hex
    }

    /// Serialize only after re-running the opaque authority verifier.
    pub fn canonical_bytes<V: OpaqueAuthorizationVerifier>(
        &self,
        route: &RouteDefinition,
        profile: &EndpointActionProfile,
        verifier: &V,
    ) -> Result<Vec<u8>, M6SenderError> {
        self.validate(route, profile, verifier)?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_COMPLETION_EVIDENCE_BYTES {
            return Err(M6SenderError::ResourceExhausted(
                "sender completion evidence exceeds its byte budget".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn canonical_bytes_detached(
        &self,
        route: &RouteDefinition,
    ) -> Result<Vec<u8>, M6SenderError> {
        self.validate_detached(route)?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_COMPLETION_EVIDENCE_BYTES {
            return Err(M6SenderError::ResourceExhausted(
                "sender completion evidence exceeds its byte budget".to_string(),
            ));
        }
        Ok(bytes)
    }

    /// Parse exact canonical bytes and independently replay every sender
    /// validation boundary, including opaque authority attestation.
    pub fn from_canonical_bytes<V: OpaqueAuthorizationVerifier>(
        bytes: &[u8],
        route: &RouteDefinition,
        profile: &EndpointActionProfile,
        verifier: &V,
    ) -> Result<Self, M6SenderError> {
        let evidence: Self = parse_canonical(bytes, MAX_COMPLETION_EVIDENCE_BYTES)?;
        evidence.validate(route, profile, verifier)?;
        Ok(evidence)
    }

    /// Parse for pure M7 use. Opaque authority credentials were verified by
    /// the live sender at capture; this detached path instead verifies the
    /// sender's pinned Ed25519 attestation over the exact source-digest set,
    /// then replays every portable structural and canonical cross-link.
    pub fn from_canonical_bytes_detached(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6SenderError> {
        let evidence: Self = parse_canonical(bytes, MAX_COMPLETION_EVIDENCE_BYTES)?;
        evidence.validate_detached(route)?;
        Ok(evidence)
    }

    fn from_sources(
        route: &RouteDefinition,
        signer: &FactorySigner,
        request_record_bytes: Vec<u8>,
        request_commit_bytes: Vec<u8>,
        m5_export_bundle_bytes: Vec<u8>,
        retained: IssuedManifest,
        ready: IssuedManifest,
        authorization_profile_bytes: Vec<u8>,
        authorization_bytes: Vec<u8>,
        authorization_consumption_bytes: Vec<u8>,
        clearance_bytes: Vec<u8>,
        receipt_bytes: Vec<u8>,
    ) -> Result<Self, M6SenderError> {
        let request: SenderExportRequest =
            parse_canonical(&request_record_bytes, MAX_REQUEST_RECORD_BYTES)?;
        let receipt: SenderExportReceipt = parse_canonical(&receipt_bytes, MAX_RECEIPT_BYTES)?;
        let retained_manifest_bytes = retained
            .manifest
            .canonical_bytes()
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        let ready_manifest_bytes = ready
            .manifest
            .canonical_bytes()
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        let mut evidence = Self {
            schema: SENDER_EXPORT_COMPLETION_EVIDENCE_SCHEMA.to_string(),
            logical_operation_id: request.logical_operation_id.clone(),
            route_definition_digest: route.definition_digest.clone(),
            signing_key_id: signer.signing_key_id().to_string(),
            sender_factory_id: route.sender.factory_id.clone(),
            receiver_factory_id: route.receiver.factory_id.clone(),
            message_digest: retained.manifest.message_digest.clone(),
            previous_message_digest: retained.manifest.unsigned.previous_message_digest.clone(),
            sequence: retained.manifest.unsigned.sequence,
            bundle_digest: request.bundle_digest.clone(),
            package_digest: request.package_digest.clone(),
            active_snapshot_digest: request.active_snapshot_digest.clone(),
            committed_at_ms: receipt.committed_at_ms,
            receipt_digest: receipt.receipt_digest.clone(),
            source_digests: SenderExportCompletionSourceDigestsV1 {
                authorization: ContentDigest::from_bytes(&authorization_bytes),
                authorization_consumption: ContentDigest::from_bytes(
                    &authorization_consumption_bytes,
                ),
                authorization_profile: ContentDigest::from_bytes(&authorization_profile_bytes),
                clearance: ContentDigest::from_bytes(&clearance_bytes),
                m5_export_bundle: ContentDigest::from_bytes(&m5_export_bundle_bytes),
                ready_attachments: canonical_map_digest(&ready.attachments)?,
                ready_manifest: ContentDigest::from_bytes(&ready_manifest_bytes),
                receipt: ContentDigest::from_bytes(&receipt_bytes),
                request_commit: ContentDigest::from_bytes(&request_commit_bytes),
                request_record: ContentDigest::from_bytes(&request_record_bytes),
                retained_attachments: canonical_map_digest(&retained.attachments)?,
                retained_manifest: ContentDigest::from_bytes(&retained_manifest_bytes),
            },
            request_record_bytes,
            request_commit_bytes,
            m5_export_bundle_bytes,
            retained_manifest_bytes,
            retained_attachments: retained.attachments,
            ready_manifest_bytes,
            ready_attachments: ready.attachments,
            authorization_profile_bytes,
            authorization_bytes,
            authorization_consumption_bytes,
            clearance_bytes,
            receipt_bytes,
            evidence_digest: ContentDigest::from_bytes(&[]),
            source_set_signature_hex: String::new(),
        };
        evidence.evidence_digest = evidence.expected_digest()?;
        evidence.source_set_signature_hex = signer
            .sign_sender_export_completion(route, &evidence.evidence_digest)
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        Ok(evidence)
    }

    fn validate_detached(&self, route: &RouteDefinition) -> Result<(), M6SenderError> {
        if self.schema != SENDER_EXPORT_COMPLETION_EVIDENCE_SCHEMA {
            return Err(M6SenderError::Integrity(
                "unsupported sender completion evidence schema".to_string(),
            ));
        }
        validate_identifier(
            "completion logical operation id",
            &self.logical_operation_id,
        )?;
        validate_identifier("completion sender factory id", &self.sender_factory_id)?;
        validate_identifier("completion receiver factory id", &self.receiver_factory_id)?;
        route
            .validate()
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        if self.route_definition_digest != route.definition_digest
            || self.signing_key_id != route.sender.signing_key_id
            || self.sender_factory_id != route.sender.factory_id
            || self.receiver_factory_id != route.receiver.factory_id
            || route.sender.factory_id == route.receiver.factory_id
        {
            return Err(M6SenderError::Integrity(
                "sender completion evidence is bound to another route or endpoint root".to_string(),
            ));
        }
        validate_completion_source_bounds(self)?;
        let expected_sources = SenderExportCompletionSourceDigestsV1 {
            authorization: ContentDigest::from_bytes(&self.authorization_bytes),
            authorization_consumption: ContentDigest::from_bytes(
                &self.authorization_consumption_bytes,
            ),
            authorization_profile: ContentDigest::from_bytes(&self.authorization_profile_bytes),
            clearance: ContentDigest::from_bytes(&self.clearance_bytes),
            m5_export_bundle: ContentDigest::from_bytes(&self.m5_export_bundle_bytes),
            ready_attachments: canonical_map_digest(&self.ready_attachments)?,
            ready_manifest: ContentDigest::from_bytes(&self.ready_manifest_bytes),
            receipt: ContentDigest::from_bytes(&self.receipt_bytes),
            request_commit: ContentDigest::from_bytes(&self.request_commit_bytes),
            request_record: ContentDigest::from_bytes(&self.request_record_bytes),
            retained_attachments: canonical_map_digest(&self.retained_attachments)?,
            retained_manifest: ContentDigest::from_bytes(&self.retained_manifest_bytes),
        };
        if self.source_digests != expected_sources {
            return Err(M6SenderError::Integrity(
                "sender completion source digest set differs from its exact bytes".to_string(),
            ));
        }

        let request: SenderExportRequest =
            parse_canonical(&self.request_record_bytes, MAX_REQUEST_RECORD_BYTES)?;
        let commit: SenderExportRequestCommit =
            parse_canonical(&self.request_commit_bytes, MAX_REQUEST_RECORD_BYTES)?;
        request.validate(route, &self.m5_export_bundle_bytes)?;
        commit.validate(
            &request,
            &self.request_record_bytes,
            &self.m5_export_bundle_bytes,
        )?;
        let bundle = M5ExportBundleV1::from_canonical_bytes(&self.m5_export_bundle_bytes)
            .map_err(|error| M6SenderError::M5(error.to_string()))?;
        let material = build_export_material(&bundle, route)?;

        let retained = IssuedManifest {
            attachments: self.retained_attachments.clone(),
            manifest: SignedManifest::from_canonical_bytes(&self.retained_manifest_bytes)
                .map_err(|error| M6SenderError::Identity(error.to_string()))?,
        };
        let ready = IssuedManifest {
            attachments: self.ready_attachments.clone(),
            manifest: SignedManifest::from_canonical_bytes(&self.ready_manifest_bytes)
                .map_err(|error| M6SenderError::Identity(error.to_string()))?,
        };
        validate_issued(&request, &material, &retained, route)?;
        validate_issued(&request, &material, &ready, route)?;
        if retained != ready {
            return Err(M6SenderError::Integrity(
                "retained issuance and exact ready delivery differ".to_string(),
            ));
        }

        let embedded_profile =
            EndpointActionProfile::from_canonical_bytes(&self.authorization_profile_bytes)
                .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        if embedded_profile.factory_id() != self.sender_factory_id
            || embedded_profile.authority_kind() != EndpointAuthorityKind::Export
        {
            return Err(M6SenderError::Integrity(
                "sender completion authority profile differs from the pinned export profile"
                    .to_string(),
            ));
        }
        let authorization: ActionAuthorization =
            parse_authority_canonical(&self.authorization_bytes)?;
        let expected_binding = export_authorization_binding(&request, &retained)?;
        if authorization.binding() != &expected_binding
            || authorization.use_limit() != 1
            || authorization.authorization_digest()
                != &parse_canonical::<SenderExportReceipt>(&self.receipt_bytes, MAX_RECEIPT_BYTES)?
                    .authorization_digest
        {
            return Err(M6SenderError::Integrity(
                "sender completion authorization is not the exact export authorization".to_string(),
            ));
        }
        let consumption: AuthorizationConsumption =
            parse_authority_canonical(&self.authorization_consumption_bytes)?;
        if consumption.use_ordinal() != 1
            || consumption.authorization_digest() != authorization.authorization_digest()
            || consumption.binding_digest() != authorization.binding_digest()
            || consumption.idempotency_key() != authorization.binding().idempotency_key
        {
            return Err(M6SenderError::Integrity(
                "sender completion requires the sole export authorization consumption".to_string(),
            ));
        }
        let clearance: SenderExportClearance =
            parse_canonical(&self.clearance_bytes, MAX_CLEARANCE_BYTES)?;
        clearance.validate(&request, &retained)?;
        let receipt: SenderExportReceipt = parse_canonical(&self.receipt_bytes, MAX_RECEIPT_BYTES)?;
        let ready_delivery_digest = delivery_fact_digest(&ready)?;
        receipt.validate(
            &request,
            &receipt.coordinator_request_digest,
            &ready,
            &consumption,
            &ready_delivery_digest,
        )?;
        if self.logical_operation_id != request.logical_operation_id
            || self.message_digest != retained.manifest.message_digest
            || self.previous_message_digest != retained.manifest.unsigned.previous_message_digest
            || self.sequence != retained.manifest.unsigned.sequence
            || self.bundle_digest != request.bundle_digest
            || self.package_digest != request.package_digest
            || self.active_snapshot_digest != request.active_snapshot_digest
            || self.committed_at_ms != receipt.committed_at_ms
            || self.receipt_digest != receipt.receipt_digest
        {
            return Err(M6SenderError::Integrity(
                "sender completion projection is stale or cross-linked".to_string(),
            ));
        }
        require_digest(
            "sender export completion evidence",
            &self.evidence_digest,
            &self.expected_digest()?,
        )?;
        verify_sender_export_completion_signature(
            route,
            &self.signing_key_id,
            &self.evidence_digest,
            &self.source_set_signature_hex,
        )
        .map_err(|error| M6SenderError::Identity(error.to_string()))
    }

    fn validate<V: OpaqueAuthorizationVerifier>(
        &self,
        route: &RouteDefinition,
        profile: &EndpointActionProfile,
        verifier: &V,
    ) -> Result<(), M6SenderError> {
        self.validate_detached(route)?;
        let embedded_profile =
            EndpointActionProfile::from_canonical_bytes(&self.authorization_profile_bytes)
                .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        if &embedded_profile != profile {
            return Err(M6SenderError::Integrity(
                "sender completion authority profile differs from the live pinned profile"
                    .to_string(),
            ));
        }
        let authorization = ActionAuthorization::from_canonical_bytes(
            &self.authorization_bytes,
            &embedded_profile,
            verifier,
        )
        .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        AuthorizationConsumption::from_canonical_bytes(
            &self.authorization_consumption_bytes,
            &authorization,
        )
        .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderError> {
        digest_domain(
            COMPLETION_EVIDENCE_DIGEST_DOMAIN,
            &(
                &self.schema,
                &self.logical_operation_id,
                &self.route_definition_digest,
                &self.signing_key_id,
                &self.sender_factory_id,
                &self.receiver_factory_id,
                &self.message_digest,
                &self.previous_message_digest,
                self.sequence,
                &self.bundle_digest,
                &self.package_digest,
                &self.active_snapshot_digest,
                self.committed_at_ms,
                &self.receipt_digest,
                &self.source_digests,
            ),
        )
    }
}

/// Sender-signed proof that the live sender M5 state still equals the exact
/// state exported for both sides of an M6 two-outcome control.
///
/// Receiver adoption and rollback are remote effects. Sender-local transport
/// records are expected to move as exports and acknowledgements are retained,
/// so this proof deliberately attests the authoritative M5 projection rather
/// than pretending the whole sender endpoint is byte-for-byte static.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderPostRollbackIsolationAuditV1 {
    schema: String,
    route_definition_digest: ContentDigest,
    signing_key_id: String,
    sender_factory_id: String,
    receiver_factory_id: String,
    accepted_export_operation_id: String,
    accepted_export_evidence_digest: ContentDigest,
    rolled_back_export_operation_id: String,
    rolled_back_export_evidence_digest: ContentDigest,
    m5_export_bundle_digest: ContentDigest,
    m5_export_bundle_content_digest: ContentDigest,
    active_package_digest: ContentDigest,
    active_snapshot_digest: ContentDigest,
    captured_at_ms: u64,
    m5_export_bundle_bytes: Vec<u8>,
    audit_digest: ContentDigest,
    signature_hex: String,
}

impl SenderPostRollbackIsolationAuditV1 {
    pub fn accepted_export_operation_id(&self) -> &str {
        &self.accepted_export_operation_id
    }

    pub fn accepted_export_evidence_digest(&self) -> &ContentDigest {
        &self.accepted_export_evidence_digest
    }

    pub fn rolled_back_export_operation_id(&self) -> &str {
        &self.rolled_back_export_operation_id
    }

    pub fn rolled_back_export_evidence_digest(&self) -> &ContentDigest {
        &self.rolled_back_export_evidence_digest
    }

    pub fn m5_export_bundle_digest(&self) -> &ContentDigest {
        &self.m5_export_bundle_digest
    }

    pub fn m5_export_bundle_bytes(&self) -> &[u8] {
        &self.m5_export_bundle_bytes
    }

    pub fn active_package_digest(&self) -> &ContentDigest {
        &self.active_package_digest
    }

    pub fn active_snapshot_digest(&self) -> &ContentDigest {
        &self.active_snapshot_digest
    }

    pub fn captured_at_ms(&self) -> u64 {
        self.captured_at_ms
    }

    pub fn audit_digest(&self) -> &ContentDigest {
        &self.audit_digest
    }

    pub fn canonical_bytes(&self, route: &RouteDefinition) -> Result<Vec<u8>, M6SenderError> {
        self.validate_detached(route)?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_ISOLATION_AUDIT_BYTES {
            return Err(M6SenderError::ResourceExhausted(
                "sender post-rollback isolation audit exceeds its byte budget".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes_detached(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6SenderError> {
        let audit: Self = parse_canonical(bytes, MAX_ISOLATION_AUDIT_BYTES)?;
        audit.validate_detached(route)?;
        Ok(audit)
    }

    fn from_live(
        route: &RouteDefinition,
        signer: &FactorySigner,
        accepted: &SenderExportCompletionEvidenceV1,
        rolled_back: &SenderExportCompletionEvidenceV1,
        m5_export_bundle: M5ExportBundleV1,
        captured_at_ms: u64,
    ) -> Result<Self, M6SenderError> {
        let m5_export_bundle_bytes = m5_export_bundle
            .canonical_bytes()
            .map_err(|error| M6SenderError::M5(error.to_string()))?;
        if accepted.logical_operation_id == rolled_back.logical_operation_id
            || accepted.message_digest == rolled_back.message_digest
            || accepted.receipt_digest == rolled_back.receipt_digest
            || accepted.m5_export_bundle_bytes != rolled_back.m5_export_bundle_bytes
            || accepted.m5_export_bundle_bytes != m5_export_bundle_bytes
        {
            return Err(M6SenderError::Integrity(
                "sender isolation audit requires two distinct exports of the exact current M5 state"
                    .to_string(),
            ));
        }
        let mut audit = Self {
            schema: SENDER_POST_ROLLBACK_ISOLATION_AUDIT_SCHEMA.to_string(),
            route_definition_digest: route.definition_digest.clone(),
            signing_key_id: signer.signing_key_id().to_string(),
            sender_factory_id: route.sender.factory_id.clone(),
            receiver_factory_id: route.receiver.factory_id.clone(),
            accepted_export_operation_id: accepted.logical_operation_id.clone(),
            accepted_export_evidence_digest: accepted.evidence_digest.clone(),
            rolled_back_export_operation_id: rolled_back.logical_operation_id.clone(),
            rolled_back_export_evidence_digest: rolled_back.evidence_digest.clone(),
            m5_export_bundle_digest: m5_export_bundle.bundle_digest().clone(),
            m5_export_bundle_content_digest: ContentDigest::from_bytes(&m5_export_bundle_bytes),
            active_package_digest: m5_export_bundle.active_package().package_digest().clone(),
            active_snapshot_digest: m5_export_bundle
                .active_runtime_snapshot()
                .snapshot_digest
                .clone(),
            captured_at_ms,
            m5_export_bundle_bytes,
            audit_digest: ContentDigest::from_bytes(&[]),
            signature_hex: String::new(),
        };
        audit.audit_digest = audit.expected_digest()?;
        audit.signature_hex = signer
            .sign_sender_isolation_audit(route, &audit.audit_digest)
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        audit.validate_detached(route)?;
        Ok(audit)
    }

    fn validate_detached(&self, route: &RouteDefinition) -> Result<(), M6SenderError> {
        route
            .validate()
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        validate_identifier(
            "accepted sender isolation export operation id",
            &self.accepted_export_operation_id,
        )?;
        validate_identifier(
            "rolled-back sender isolation export operation id",
            &self.rolled_back_export_operation_id,
        )?;
        if self.schema != SENDER_POST_ROLLBACK_ISOLATION_AUDIT_SCHEMA
            || self.route_definition_digest != route.definition_digest
            || self.signing_key_id != route.sender.signing_key_id
            || self.sender_factory_id != route.sender.factory_id
            || self.receiver_factory_id != route.receiver.factory_id
            || self.accepted_export_operation_id == self.rolled_back_export_operation_id
            || self.accepted_export_evidence_digest == self.rolled_back_export_evidence_digest
            || self.captured_at_ms == 0
            || self.m5_export_bundle_bytes.is_empty()
            || self.m5_export_bundle_bytes.len() > MAX_ISOLATION_AUDIT_BYTES
            || self.m5_export_bundle_content_digest
                != ContentDigest::from_bytes(&self.m5_export_bundle_bytes)
        {
            return Err(M6SenderError::Integrity(
                "sender post-rollback isolation audit is outside its exact route or source schema"
                    .to_string(),
            ));
        }
        let bundle = M5ExportBundleV1::from_canonical_bytes(&self.m5_export_bundle_bytes)
            .map_err(|error| M6SenderError::M5(error.to_string()))?;
        if self.m5_export_bundle_digest != *bundle.bundle_digest()
            || self.active_package_digest != *bundle.active_package().package_digest()
            || self.active_snapshot_digest != bundle.active_runtime_snapshot().snapshot_digest
        {
            return Err(M6SenderError::Integrity(
                "sender isolation audit projection differs from its exact M5 export bundle"
                    .to_string(),
            ));
        }
        require_digest(
            "sender post-rollback isolation audit",
            &self.audit_digest,
            &self.expected_digest()?,
        )?;
        verify_sender_isolation_audit_signature(
            route,
            &self.signing_key_id,
            &self.audit_digest,
            &self.signature_hex,
        )
        .map_err(|error| M6SenderError::Identity(error.to_string()))
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderError> {
        digest_domain(
            POST_ROLLBACK_ISOLATION_AUDIT_DIGEST_DOMAIN,
            &(
                &self.schema,
                &self.route_definition_digest,
                &self.signing_key_id,
                &self.sender_factory_id,
                &self.receiver_factory_id,
                &self.accepted_export_operation_id,
                &self.accepted_export_evidence_digest,
                &self.rolled_back_export_operation_id,
                &self.rolled_back_export_evidence_digest,
                &self.m5_export_bundle_digest,
                &self.m5_export_bundle_content_digest,
                &self.active_package_digest,
                &self.active_snapshot_digest,
                self.captured_at_ms,
            ),
        )
    }
}

/// One exact sender receipt reopened and checked during endpoint start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderReopenRecoveredExportV1 {
    logical_operation_id: String,
    message_digest: ContentDigest,
    receipt_digest: ContentDigest,
    receipt_bytes: Vec<u8>,
}

impl SenderReopenRecoveredExportV1 {
    pub fn logical_operation_id(&self) -> &str {
        &self.logical_operation_id
    }

    pub fn message_digest(&self) -> &ContentDigest {
        &self.message_digest
    }

    pub fn receipt_digest(&self) -> &ContentDigest {
        &self.receipt_digest
    }

    fn from_receipt(receipt: SenderExportReceipt) -> Result<Self, M6SenderError> {
        Ok(Self {
            logical_operation_id: receipt.logical_operation_id.clone(),
            message_digest: receipt.message_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receipt_bytes: canonical_json(&receipt)?,
        })
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6SenderError> {
        validate_identifier(
            "reopened export logical operation id",
            &self.logical_operation_id,
        )?;
        let receipt: SenderExportReceipt = parse_canonical(&self.receipt_bytes, MAX_RECEIPT_BYTES)?;
        require_digest(
            "reopened sender export receipt",
            &receipt.receipt_digest,
            &receipt.expected_digest()?,
        )?;
        if receipt.logical_operation_id != self.logical_operation_id
            || receipt.message_digest != self.message_digest
            || receipt.receipt_digest != self.receipt_digest
            || receipt.route_definition_digest != route.definition_digest
            || receipt.route_id != route.route_id
            || receipt.route_generation != route.generation
        {
            return Err(M6SenderError::Integrity(
                "reopen audit receipt is stale or belongs to another route".to_string(),
            ));
        }
        Ok(())
    }
}

/// Immutable fact emitted only after one sender endpoint has been exclusively
/// reopened and its durable stores have completed startup reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderReopenAuditV1 {
    schema: String,
    sender_factory_id: String,
    route_definition_digest: ContentDigest,
    signing_key_id: String,
    open_ordinal: u64,
    previous_audit_digest: Option<ContentDigest>,
    previous_process_instance_id: Option<String>,
    current_process_instance_id: String,
    pre_open_state_digest: ContentDigest,
    post_reconciliation_state_digest: ContentDigest,
    recovered_exports: Vec<SenderReopenRecoveredExportV1>,
    opened_at_ms: u64,
    audit_digest: ContentDigest,
    signature_hex: String,
}

impl SenderReopenAuditV1 {
    pub fn open_ordinal(&self) -> u64 {
        self.open_ordinal
    }

    pub fn previous_process_instance_id(&self) -> Option<&str> {
        self.previous_process_instance_id.as_deref()
    }

    pub fn current_process_instance_id(&self) -> &str {
        &self.current_process_instance_id
    }

    pub fn pre_open_state_digest(&self) -> &ContentDigest {
        &self.pre_open_state_digest
    }

    pub fn post_reconciliation_state_digest(&self) -> &ContentDigest {
        &self.post_reconciliation_state_digest
    }

    pub fn recovered_exports(&self) -> &[SenderReopenRecoveredExportV1] {
        &self.recovered_exports
    }

    pub fn audit_digest(&self) -> &ContentDigest {
        &self.audit_digest
    }

    pub fn canonical_bytes(&self, route: &RouteDefinition) -> Result<Vec<u8>, M6SenderError> {
        self.validate(route)?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_REOPEN_AUDIT_BYTES {
            return Err(M6SenderError::ResourceExhausted(
                "sender reopen audit exceeds its byte budget".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6SenderError> {
        let audit: Self = parse_canonical(bytes, MAX_REOPEN_AUDIT_BYTES)?;
        audit.validate(route)?;
        Ok(audit)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6SenderError> {
        if self.schema != SENDER_REOPEN_AUDIT_SCHEMA
            || self.route_definition_digest != route.definition_digest
            || self.sender_factory_id != route.sender.factory_id
            || self.signing_key_id != route.sender.signing_key_id
            || self.open_ordinal == 0
        {
            return Err(M6SenderError::Integrity(
                "sender reopen audit is outside its exact route schema".to_string(),
            ));
        }
        validate_identifier(
            "current sender process instance id",
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
                validate_identifier("previous sender process instance id", previous)?;
            }
            _ => {
                return Err(M6SenderError::Integrity(
                    "sender reopen audit does not prove a distinct prior process instance"
                        .to_string(),
                ));
            }
        }
        if self.recovered_exports.len() > MAX_DURABLE_STATE_ENTRIES
            || !self
                .recovered_exports
                .windows(2)
                .all(|pair| pair[0].logical_operation_id < pair[1].logical_operation_id)
        {
            return Err(M6SenderError::Integrity(
                "sender reopen receipt set is not bounded, sorted, and unique".to_string(),
            ));
        }
        for recovered in &self.recovered_exports {
            recovered.validate(route)?;
        }
        require_digest(
            "sender reopen audit",
            &self.audit_digest,
            &self.expected_digest()?,
        )?;
        verify_sender_reopen_audit_signature(
            route,
            &self.signing_key_id,
            &self.audit_digest,
            &self.signature_hex,
        )
        .map_err(|error| M6SenderError::Identity(error.to_string()))
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderError> {
        digest_domain(
            REOPEN_AUDIT_DIGEST_DOMAIN,
            &(
                &self.schema,
                &self.sender_factory_id,
                &self.route_definition_digest,
                &self.signing_key_id,
                self.open_ordinal,
                &self.previous_audit_digest,
                &self.previous_process_instance_id,
                &self.current_process_instance_id,
                &self.pre_open_state_digest,
                &self.post_reconciliation_state_digest,
                &self.recovered_exports,
                self.opened_at_ms,
            ),
        )
    }
}

/// Exact adjacent signed open audits proving that a completed sender receipt
/// was recovered by a distinct later process instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderReopenProofV1 {
    schema: String,
    sender_factory_id: String,
    route_definition_digest: ContentDigest,
    previous_audit_digest: ContentDigest,
    current_audit_digest: ContentDigest,
    previous_audit_bytes_digest: ContentDigest,
    current_audit_bytes_digest: ContentDigest,
    previous_audit_bytes: Vec<u8>,
    current_audit_bytes: Vec<u8>,
    proof_digest: ContentDigest,
}

impl SenderReopenProofV1 {
    pub fn previous_audit_digest(&self) -> &ContentDigest {
        &self.previous_audit_digest
    }

    pub fn current_audit_digest(&self) -> &ContentDigest {
        &self.current_audit_digest
    }

    pub fn proof_digest(&self) -> &ContentDigest {
        &self.proof_digest
    }

    pub fn canonical_bytes(&self, route: &RouteDefinition) -> Result<Vec<u8>, M6SenderError> {
        self.validate(route)?;
        let bytes = canonical_json(self)?;
        if bytes.len() > 2 * MAX_REOPEN_AUDIT_BYTES {
            return Err(M6SenderError::ResourceExhausted(
                "sender reopen proof exceeds its byte budget".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6SenderError> {
        let proof: Self = parse_canonical(bytes, 2 * MAX_REOPEN_AUDIT_BYTES)?;
        proof.validate(route)?;
        Ok(proof)
    }

    pub fn proves_restart_of(
        &self,
        route: &RouteDefinition,
        logical_operation_id: &str,
        receipt_digest: &ContentDigest,
    ) -> Result<bool, M6SenderError> {
        self.validate(route)?;
        let current = SenderReopenAuditV1::from_canonical_bytes(&self.current_audit_bytes, route)?;
        Ok(current.recovered_exports.iter().any(|recovered| {
            recovered.logical_operation_id == logical_operation_id
                && &recovered.receipt_digest == receipt_digest
        }))
    }

    fn from_adjacent(
        route: &RouteDefinition,
        previous: &SenderReopenAuditV1,
        current: &SenderReopenAuditV1,
    ) -> Result<Self, M6SenderError> {
        let previous_audit_bytes = previous.canonical_bytes(route)?;
        let current_audit_bytes = current.canonical_bytes(route)?;
        let mut proof = Self {
            schema: SENDER_REOPEN_PROOF_SCHEMA.to_string(),
            sender_factory_id: route.sender.factory_id.clone(),
            route_definition_digest: route.definition_digest.clone(),
            previous_audit_digest: previous.audit_digest.clone(),
            current_audit_digest: current.audit_digest.clone(),
            previous_audit_bytes_digest: ContentDigest::from_bytes(&previous_audit_bytes),
            current_audit_bytes_digest: ContentDigest::from_bytes(&current_audit_bytes),
            previous_audit_bytes,
            current_audit_bytes,
            proof_digest: ContentDigest::from_bytes(&[]),
        };
        proof.proof_digest = proof.expected_digest()?;
        proof.validate(route)?;
        Ok(proof)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6SenderError> {
        if self.schema != SENDER_REOPEN_PROOF_SCHEMA
            || self.sender_factory_id != route.sender.factory_id
            || self.route_definition_digest != route.definition_digest
            || self.previous_audit_bytes.is_empty()
            || self.current_audit_bytes.is_empty()
            || self.previous_audit_bytes.len() > MAX_REOPEN_AUDIT_BYTES
            || self.current_audit_bytes.len() > MAX_REOPEN_AUDIT_BYTES
        {
            return Err(M6SenderError::Integrity(
                "sender reopen proof is outside its exact bounded route schema".to_string(),
            ));
        }
        require_digest(
            "previous sender reopen audit bytes",
            &self.previous_audit_bytes_digest,
            &ContentDigest::from_bytes(&self.previous_audit_bytes),
        )?;
        require_digest(
            "current sender reopen audit bytes",
            &self.current_audit_bytes_digest,
            &ContentDigest::from_bytes(&self.current_audit_bytes),
        )?;
        let previous =
            SenderReopenAuditV1::from_canonical_bytes(&self.previous_audit_bytes, route)?;
        let current = SenderReopenAuditV1::from_canonical_bytes(&self.current_audit_bytes, route)?;
        if self.previous_audit_digest != previous.audit_digest
            || self.current_audit_digest != current.audit_digest
            || current.open_ordinal != previous.open_ordinal.saturating_add(1)
            || current.previous_audit_digest.as_ref() != Some(&previous.audit_digest)
            || current.previous_process_instance_id.as_deref()
                != Some(previous.current_process_instance_id.as_str())
            || current.current_process_instance_id == previous.current_process_instance_id
        {
            return Err(M6SenderError::Integrity(
                "sender reopen proof lacks an exact adjacent distinct-instance audit chain"
                    .to_string(),
            ));
        }
        require_digest(
            "sender reopen proof",
            &self.proof_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderError> {
        digest_domain(
            REOPEN_PROOF_DIGEST_DOMAIN,
            &(
                &self.schema,
                &self.sender_factory_id,
                &self.route_definition_digest,
                &self.previous_audit_digest,
                &self.current_audit_digest,
                &self.previous_audit_bytes_digest,
                &self.current_audit_bytes_digest,
            ),
        )
    }
}

/// Deterministic process-death seam used by the focused crash matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderCrashPoint {
    OuterRequestPersisted,
    PreparedIssuancePersisted,
    ExportIntentRecorded,
    OutboundBundleCommitted,
    AuthorizationConsumed,
    OriginChainCommitted,
    RouteStageEffectCommitted,
    RouteStageCommitted,
    PreChainM5Revalidated,
    RouteReadyEffectCommitted,
    RouteReadyCommitted,
    ExportReceiptEffectCommitted,
    ExportReceiptCommitted,
    AbandonmentEffectCommitted,
    AbandonmentReceiptCommitted,
}

/// One sender endpoint. The endpoint owner lock is the final field so every
/// M5, authority, issuer, coordinator, and spool child drops first.
pub struct M6SenderRuntime<V: OpaqueAuthorizationVerifier> {
    endpoint_root: PathBuf,
    requests_root: PathBuf,
    receipts_root: PathBuf,
    clearances_root: PathBuf,
    abandonments_root: PathBuf,
    reopen_audits_root: PathBuf,
    max_export_requests: u32,
    max_export_receipts: u32,
    retry_policy: RetryPolicy,
    clock: Arc<dyn Clock>,
    signer: FactorySigner,
    authorization: AuthorizationStore<V>,
    m5: M5Runtime,
    spool: GovernedFilesystemSpool,
    issuer: ManifestIssuer,
    journal: CoordinatorJournal,
    latest_reopen_audit: SenderReopenAuditV1,
    _owner_lock: File,
}

impl<V: OpaqueAuthorizationVerifier> M6SenderRuntime<V> {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        config: M6SenderRuntimeConfig,
        verifier: V,
        signer: FactorySigner,
        clock: Arc<dyn Clock>,
        nonce_source: Arc<dyn NonceSource>,
        live_provider: Option<Arc<dyn LiveProviderQualificationPort>>,
    ) -> Result<Self, M6SenderError> {
        config.validate_non_path_fields()?;
        let endpoint_root = secure_create_root(&config.endpoint_root)?;
        let owner_lock = acquire_endpoint_owner(&endpoint_root)?;

        // Every mutable child is opened only after endpoint ownership.
        let m5_root = fs::canonicalize(&config.m5.root)
            .map_err(|source| M6SenderError::io(&config.m5.root, source))?;
        if m5_root == endpoint_root || !m5_root.starts_with(&endpoint_root) {
            return Err(M6SenderError::InvalidConfiguration(
                "the sender M5 root must be a strict child of its endpoint root".to_string(),
            ));
        }
        ensure_m5_root_isolated(&endpoint_root, &m5_root)?;

        let authorization = AuthorizationStore::open(
            endpoint_root.join(AUTHORITY_DIRECTORY),
            config.authorization_profile,
            verifier,
        )
        .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        let m5 = M5Runtime::open(
            M5RuntimeConfig {
                root: m5_root,
                ..config.m5
            },
            live_provider,
        )
        .map_err(|error| M6SenderError::M5(error.to_string()))?;
        let spool = GovernedFilesystemSpool::open(
            &config.route_root,
            &endpoint_root,
            RouteEndpointRole::Sender,
            &config.expected_route_definition_digest,
        )
        .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        let route = spool.route();
        if route.sender.factory_id != authorization.profile().factory_id()
            || route.sender.factory_id != m5.config().factory_id
            || signer.signing_key_id() != route.sender.signing_key_id
            || signer.public_key_hex() != route.sender.public_key_hex
        {
            return Err(M6SenderError::InvalidConfiguration(
                "sender M5, authority profile, route identity, or Ed25519 signer differ"
                    .to_string(),
            ));
        }
        if config.max_export_requests > route.resource_profile.max_replay_records {
            return Err(M6SenderError::InvalidConfiguration(
                "sender request bound exceeds the immutable route record budget".to_string(),
            ));
        }
        config
            .journal_config
            .validate_for_resource_profile(&route.resource_profile)
            .map_err(|error| M6SenderError::Transaction(error.to_string()))?;
        config
            .retry_policy
            .validate_for_resource_profile(&route.resource_profile)
            .map_err(|error| M6SenderError::Transaction(error.to_string()))?;

        let requests_root = secure_child_directory(&endpoint_root, REQUESTS_DIRECTORY)?;
        let receipts_root = secure_child_directory(&endpoint_root, RECEIPTS_DIRECTORY)?;
        let clearances_root = secure_child_directory(&endpoint_root, CLEARANCES_DIRECTORY)?;
        let abandonments_root = secure_child_directory(&endpoint_root, ABANDONMENTS_DIRECTORY)?;
        let reopen_audits_root = secure_child_directory(&endpoint_root, REOPEN_AUDITS_DIRECTORY)?;
        let canonical_m5_root = m5.config().root.clone();
        let pre_open_state_digest = sender_durable_state_root(&endpoint_root, &canonical_m5_root)?;
        recover_building_directories(&requests_root)?;
        let issuer = ManifestIssuer::open_or_initialize(
            &endpoint_root,
            route.clone(),
            RouteEndpointRole::Sender,
            Arc::clone(&clock),
            Arc::clone(&nonce_source),
        )
        .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        let journal = CoordinatorJournal::open_or_initialize(
            endpoint_root.join(JOURNAL_DIRECTORY),
            config.journal_config,
            Arc::clone(&clock),
        )
        .map_err(|error| M6SenderError::Transaction(error.to_string()))?;
        let post_reconciliation_state_digest =
            sender_durable_state_root(&endpoint_root, &canonical_m5_root)?;
        let previous_audits = load_sender_reopen_audit_chain(&reopen_audits_root, route)?;
        let previous = previous_audits.last();
        let current_process_instance_id = generate_process_instance_id(
            nonce_source.as_ref(),
            previous.map(|audit| audit.current_process_instance_id.as_str()),
        )?;
        let recovered_exports =
            load_reopen_recovered_exports(&receipts_root, route, config.max_export_receipts)?;
        let opened_at_ms = clock
            .now_ms()
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        let mut latest_reopen_audit = SenderReopenAuditV1 {
            schema: SENDER_REOPEN_AUDIT_SCHEMA.to_string(),
            sender_factory_id: route.sender.factory_id.clone(),
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
            recovered_exports,
            opened_at_ms,
            audit_digest: ContentDigest::from_bytes(&[]),
            signature_hex: String::new(),
        };
        latest_reopen_audit.audit_digest = latest_reopen_audit.expected_digest()?;
        latest_reopen_audit.signature_hex = signer
            .sign_sender_reopen_audit(route, &latest_reopen_audit.audit_digest)
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        latest_reopen_audit.validate(route)?;
        persist_sender_reopen_audit(&reopen_audits_root, &latest_reopen_audit)?;

        Ok(Self {
            endpoint_root,
            requests_root,
            receipts_root,
            clearances_root,
            abandonments_root,
            reopen_audits_root,
            max_export_requests: config.max_export_requests,
            max_export_receipts: config.max_export_receipts,
            retry_policy: config.retry_policy,
            clock,
            signer,
            authorization,
            m5,
            spool,
            issuer,
            journal,
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

    pub fn latest_reopen_audit(&self) -> &SenderReopenAuditV1 {
        &self.latest_reopen_audit
    }

    pub fn reopen_audit_chain(&self) -> Result<Vec<SenderReopenAuditV1>, M6SenderError> {
        load_sender_reopen_audit_chain(&self.reopen_audits_root, self.route())
    }

    pub fn latest_reopen_proof(&self) -> Result<Option<SenderReopenProofV1>, M6SenderError> {
        let audits = self.reopen_audit_chain()?;
        if audits.len() < 2 {
            return Ok(None);
        }
        let previous = &audits[audits.len() - 2];
        let current = &audits[audits.len() - 1];
        Ok(Some(SenderReopenProofV1::from_adjacent(
            self.route(),
            previous,
            current,
        )?))
    }

    pub fn prepare_export(
        &mut self,
        logical_operation_id: impl Into<String>,
        principal_id: impl Into<String>,
        message_lifetime_ms: u64,
    ) -> Result<PreparedSenderExport, M6SenderError> {
        self.prepare_export_with_fault(
            logical_operation_id,
            principal_id,
            message_lifetime_ms,
            None,
        )
    }

    pub fn prepare_export_with_fault(
        &mut self,
        logical_operation_id: impl Into<String>,
        principal_id: impl Into<String>,
        message_lifetime_ms: u64,
        crash_at: Option<SenderCrashPoint>,
    ) -> Result<PreparedSenderExport, M6SenderError> {
        let logical_operation_id = logical_operation_id.into();
        let principal_id = principal_id.into();
        validate_identifier("logical operation id", &logical_operation_id)?;
        validate_identifier("export principal id", &principal_id)?;
        self.require_no_other_pending_operation(&logical_operation_id)?;

        let request_path = request_unit_path(&self.requests_root, &logical_operation_id);
        let (request, material) = if request_path.exists() {
            let (request, bundle_bytes) = load_request_unit(&request_path, self.route())?;
            if request.logical_operation_id != logical_operation_id
                || request.principal_id != principal_id
                || request.message_lifetime_ms != message_lifetime_ms
            {
                return Err(M6SenderError::Conflict {
                    identity: logical_operation_id,
                    existing: request.request_digest,
                    requested: ContentDigest::from_bytes(&canonical_json(&(
                        principal_id,
                        message_lifetime_ms,
                    ))?),
                });
            }
            let bundle = M5ExportBundleV1::from_canonical_bytes(&bundle_bytes)
                .map_err(|error| M6SenderError::M5(error.to_string()))?;
            let material = build_export_material(&bundle, self.route())?;
            (request, material)
        } else {
            enforce_record_bound(
                &self.requests_root,
                self.max_export_requests,
                "sender export requests",
            )?;
            let bundle = self
                .m5
                .export_active_adopted_bundle()
                .map_err(|error| M6SenderError::M5(error.to_string()))?;
            let material = build_export_material(&bundle, self.route())?;
            let captured_at_ms = self
                .clock
                .now_ms()
                .map_err(|error| M6SenderError::Identity(error.to_string()))?;
            let request = SenderExportRequest::new(
                logical_operation_id.clone(),
                principal_id,
                captured_at_ms,
                message_lifetime_ms,
                self.route(),
                &bundle,
                &material,
            )?;
            persist_request_unit(
                &self.requests_root,
                &request_path,
                &request,
                &material.bundle_bytes,
            )?;
            maybe_crash(crash_at, SenderCrashPoint::OuterRequestPersisted)?;
            (request, material)
        };

        let (issued, _, _) = self.resolve_or_prepare_issuance(&request, &material)?;
        validate_issued(&request, &material, &issued, self.route())?;
        maybe_crash(crash_at, SenderCrashPoint::PreparedIssuancePersisted)?;
        Ok(prepared_projection(&request, &issued)?)
    }

    /// Publish an opaque, exact authorization after the caller has compared
    /// it with `PreparedSenderExport::authorization_binding`.
    pub fn publish_authorization(
        &self,
        authorization: ActionAuthorization,
    ) -> Result<ContentDigest, M6SenderError> {
        let published = self
            .authorization
            .publish_authorization(authorization)
            .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        Ok(published.authorization_digest().clone())
    }

    pub fn commit_export(
        &mut self,
        logical_operation_id: &str,
        authorization_digest: &ContentDigest,
    ) -> Result<SenderExportReceipt, M6SenderError> {
        self.commit_export_with_fault(logical_operation_id, authorization_digest, None)
    }

    /// Exact restart entrypoint. Repeating it after any committed boundary
    /// verifies the authoritative fact and returns the original receipt.
    pub fn recover_export(
        &mut self,
        logical_operation_id: &str,
        authorization_digest: &ContentDigest,
    ) -> Result<SenderExportReceipt, M6SenderError> {
        self.commit_export(logical_operation_id, authorization_digest)
    }

    pub fn abandon_export(
        &mut self,
        logical_operation_id: &str,
        disposition: PreparedIssuanceDisposition,
        reason: impl Into<String>,
        decision_evidence_digest: ContentDigest,
    ) -> Result<SenderExportAbandonment, M6SenderError> {
        self.abandon_export_with_fault(
            logical_operation_id,
            disposition,
            reason,
            decision_evidence_digest,
            None,
        )
    }

    /// Terminalize an uncommitted prepare without deleting its exact signed
    /// bytes or advancing the route sequence.
    pub fn abandon_export_with_fault(
        &mut self,
        logical_operation_id: &str,
        disposition: PreparedIssuanceDisposition,
        reason: impl Into<String>,
        decision_evidence_digest: ContentDigest,
        crash_at: Option<SenderCrashPoint>,
    ) -> Result<SenderExportAbandonment, M6SenderError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        self.require_no_other_pending_operation(logical_operation_id)?;
        let request_path = request_unit_path(&self.requests_root, logical_operation_id);
        if !request_path.exists() {
            return Err(M6SenderError::NotPrepared(logical_operation_id.to_string()));
        }
        let (request, bundle_bytes) = load_request_unit(&request_path, self.route())?;
        let bundle = M5ExportBundleV1::from_canonical_bytes(&bundle_bytes)
            .map_err(|error| M6SenderError::M5(error.to_string()))?;
        let material = build_export_material(&bundle, self.route())?;
        let resolution = self
            .issuer
            .prepared_resolution(&request.issuance_idempotency_key)
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        let recovered = match resolution {
            PreparedIssuanceResolution::Missing => {
                self.issuer
                    .prepare_idempotent(
                        request.issuance_idempotency_key.clone(),
                        &self.signer,
                        export_payload(&request),
                        clone_attachment_inputs(&material.inputs),
                        request.message_lifetime_ms,
                    )
                    .map_err(|error| M6SenderError::Identity(error.to_string()))?;
                match self
                    .issuer
                    .prepared_resolution(&request.issuance_idempotency_key)
                    .map_err(|error| M6SenderError::Identity(error.to_string()))?
                {
                    PreparedIssuanceResolution::Prepared(issuance) => issuance,
                    _ => {
                        return Err(M6SenderError::Integrity(
                            "newly prepared abandonment target did not remain uncommitted"
                                .to_string(),
                        ));
                    }
                }
            }
            PreparedIssuanceResolution::Prepared(issuance)
            | PreparedIssuanceResolution::Abandoned { issuance, .. } => issuance,
            PreparedIssuanceResolution::ChainCommitted { commit, .. } => {
                return Err(M6SenderError::CannotAbandonCommitted {
                    logical_operation_id: logical_operation_id.to_string(),
                    message_digest: commit.message_digest,
                });
            }
        };
        validate_issued(&request, &material, &recovered.issued, self.route())?;
        let identity_abandonment = self
            .issuer
            .abandon_prepared(
                &request.issuance_idempotency_key,
                &recovered.request_digest,
                disposition,
                reason.into(),
                decision_evidence_digest,
            )
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        maybe_crash(crash_at, SenderCrashPoint::AbandonmentEffectCommitted)?;
        let record = SenderExportAbandonment::new(
            &request,
            recovered.request_digest,
            &identity_abandonment,
        )?;
        let path = abandonment_path(&self.abandonments_root, logical_operation_id);
        if path.exists() {
            let existing: SenderExportAbandonment =
                load_canonical_file(&path, MAX_ABANDONMENT_BYTES)?;
            existing.validate(&request, &identity_abandonment)?;
            if existing != record {
                return Err(M6SenderError::Conflict {
                    identity: logical_operation_id.to_string(),
                    existing: existing.abandonment_digest,
                    requested: record.abandonment_digest,
                });
            }
        } else {
            enforce_file_bound(
                &self.abandonments_root,
                self.max_export_requests,
                "sender export abandonments",
            )?;
            persist_immutable_file(&path, &canonical_json(&record)?)?;
        }
        maybe_crash(crash_at, SenderCrashPoint::AbandonmentReceiptCommitted)?;
        Ok(record)
    }

    pub fn commit_export_with_fault(
        &mut self,
        logical_operation_id: &str,
        authorization_digest: &ContentDigest,
        crash_at: Option<SenderCrashPoint>,
    ) -> Result<SenderExportReceipt, M6SenderError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        self.require_no_other_pending_operation(logical_operation_id)?;
        let request_path = request_unit_path(&self.requests_root, logical_operation_id);
        if !request_path.exists() {
            return Err(M6SenderError::NotPrepared(logical_operation_id.to_string()));
        }
        let (request, bundle_bytes) = load_request_unit(&request_path, self.route())?;
        if request.logical_operation_id != logical_operation_id {
            return Err(M6SenderError::Integrity(
                "request unit is stored under a different operation identity".to_string(),
            ));
        }
        let bundle = M5ExportBundleV1::from_canonical_bytes(&bundle_bytes)
            .map_err(|error| M6SenderError::M5(error.to_string()))?;
        let material = build_export_material(&bundle, self.route())?;
        let (prepared, issuance_request_digest, chain_already_committed) =
            self.resolve_or_prepare_issuance(&request, &material)?;
        validate_issued(&request, &material, &prepared, self.route())?;

        let expected_binding = export_authorization_binding(&request, &prepared)?;
        let authorization = self
            .authorization
            .load_authorization(authorization_digest)
            .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        if authorization.binding() != &expected_binding
            || authorization.binding().action != AuthorityAction::ExportPackage
            || authorization.use_limit() != 1
        {
            return Err(M6SenderError::Authority(
                "authorization does not bind the exact prepared export".to_string(),
            ));
        }

        let initial_evidence = stage_evidence(
            Some(authorization.authorization_digest().clone()),
            vec![
                request.request_digest.clone(),
                request.bundle_digest.clone(),
                prepared.manifest.message_digest.clone(),
            ],
            None,
            None,
        )?;
        let initial = self
            .journal
            .begin(
                transaction_draft(
                    &request,
                    &prepared,
                    authorization.authorization_digest().clone(),
                    self.retry_policy.clone(),
                ),
                initial_evidence,
            )
            .map_err(|error| M6SenderError::Transaction(error.to_string()))?;
        maybe_crash(crash_at, SenderCrashPoint::ExportIntentRecorded)?;
        let coordinator_request_digest = initial.request_digest.clone();

        // The issuer store is the authoritative sender-local outbound fact.
        validate_issued(&request, &material, &prepared, self.route())?;
        self.append_stage(
            &request,
            &coordinator_request_digest,
            TransactionStage::OutboundBundleCommitted,
            Some(authorization.authorization_digest().clone()),
            vec![
                request.request_digest.clone(),
                prepared.manifest.message_digest.clone(),
                delivery_fact_digest(&prepared)?,
            ],
            None,
            None,
        )?;
        maybe_crash(crash_at, SenderCrashPoint::OutboundBundleCommitted)?;

        let invocation = authorization.invocation(1);
        let trusted_now_ms = self
            .clock
            .now_ms()
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        let consumption = self
            .authorization
            .consume(&invocation, trusted_now_ms)
            .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        maybe_crash(crash_at, SenderCrashPoint::AuthorizationConsumed)?;

        // Only an uncommitted prepare re-enters M5. Once the exact origin
        // chain fact exists, recovery must finish publishing these retained
        // bytes even if live M5 later changes; otherwise the receiver can
        // never advance past the authenticated missing sequence.
        let clearance = if chain_already_committed {
            self.latest_clearance(&request, &prepared)?.ok_or_else(|| {
                M6SenderError::Integrity(
                    "chain-committed export has no durable pre-commit M5 clearance".to_string(),
                )
            })?
        } else {
            self.require_live_bundle_unchanged(&request)?;
            let clearance = self.record_clearance(&request, &prepared)?;
            maybe_crash(crash_at, SenderCrashPoint::PreChainM5Revalidated)?;
            clearance
        };
        let chain_committed = if chain_already_committed {
            prepared.clone()
        } else {
            self.issuer
                .commit_prepared_exact(&request.issuance_idempotency_key, &issuance_request_digest)
                .map_err(|error| M6SenderError::Identity(error.to_string()))?
        };
        validate_issued(&request, &material, &chain_committed, self.route())?;
        maybe_crash(crash_at, SenderCrashPoint::OriginChainCommitted)?;

        // Route-role ownership is acquired only after the exact authorization
        // consumption and M5 revalidation.
        {
            let route_owner = self
                .spool
                .acquire_role()
                .map_err(|error| M6SenderError::Identity(error.to_string()))?;
            let staged_digest = self
                .spool
                .stage_delivery(&route_owner, &chain_committed)
                .map_err(|error| M6SenderError::Identity(error.to_string()))?;
            require_digest(
                "route staged message",
                &chain_committed.manifest.message_digest,
                &staged_digest,
            )?;
            // A second call reads and byte-compares the authoritative staged
            // (or already-ready) unit instead of trusting the preceding return
            // value.
            self.spool
                .stage_delivery(&route_owner, &chain_committed)
                .map_err(|error| M6SenderError::Identity(error.to_string()))?;
            maybe_crash(crash_at, SenderCrashPoint::RouteStageEffectCommitted)?;
        }
        self.append_stage(
            &request,
            &coordinator_request_digest,
            TransactionStage::RouteStageCommitted,
            Some(authorization.authorization_digest().clone()),
            vec![
                chain_committed.manifest.message_digest.clone(),
                delivery_fact_digest(&chain_committed)?,
                consumption.receipt_digest().clone(),
                clearance.clearance_digest.clone(),
            ],
            Some(consumption.receipt_digest().clone()),
            Some(authorization.binding_digest().clone()),
        )?;
        maybe_crash(crash_at, SenderCrashPoint::RouteStageCommitted)?;

        let ready_already_exists = self
            .spool
            .outbound_ready_unit_directory(&chain_committed.manifest.message_digest)
            .exists();
        let ready = {
            let route_owner = self
                .spool
                .acquire_role()
                .map_err(|error| M6SenderError::Identity(error.to_string()))?;
            if !ready_already_exists {
                self.spool
                    .commit_staged(&route_owner, &chain_committed.manifest.message_digest)
                    .map_err(|error| M6SenderError::Identity(error.to_string()))?;
            }
            self.spool
                .read_outbound_ready(&chain_committed.manifest.message_digest)
                .map_err(|error| M6SenderError::Identity(error.to_string()))?
        };
        validate_issued(&request, &material, &ready, self.route())?;
        if ready != chain_committed {
            return Err(M6SenderError::Integrity(
                "ready route bytes differ from the retained issuance".to_string(),
            ));
        }
        maybe_crash(crash_at, SenderCrashPoint::RouteReadyEffectCommitted)?;
        let ready_delivery_digest = delivery_fact_digest(&ready)?;
        self.append_stage(
            &request,
            &coordinator_request_digest,
            TransactionStage::RouteReadyCommitted,
            Some(authorization.authorization_digest().clone()),
            vec![
                ready.manifest.message_digest.clone(),
                ready_delivery_digest.clone(),
                consumption.receipt_digest().clone(),
                clearance.clearance_digest.clone(),
            ],
            Some(consumption.receipt_digest().clone()),
            Some(authorization.binding_digest().clone()),
        )?;
        maybe_crash(crash_at, SenderCrashPoint::RouteReadyCommitted)?;

        let receipt_path = receipt_path(&self.receipts_root, logical_operation_id);
        let receipt = if receipt_path.exists() {
            let receipt: SenderExportReceipt =
                load_canonical_file(&receipt_path, MAX_RECEIPT_BYTES)?;
            receipt.validate(
                &request,
                &coordinator_request_digest,
                &ready,
                &consumption,
                &ready_delivery_digest,
            )?;
            receipt
        } else {
            enforce_file_bound(
                &self.receipts_root,
                self.max_export_receipts,
                "sender export receipts",
            )?;
            let committed_at_ms = self
                .clock
                .now_ms()
                .map_err(|error| M6SenderError::Identity(error.to_string()))?;
            let receipt = SenderExportReceipt::new(
                &request,
                coordinator_request_digest.clone(),
                &ready,
                &consumption,
                ready_delivery_digest.clone(),
                committed_at_ms,
            )?;
            persist_immutable_file(&receipt_path, &canonical_json(&receipt)?)?;
            receipt
        };
        maybe_crash(crash_at, SenderCrashPoint::ExportReceiptEffectCommitted)?;
        self.append_stage(
            &request,
            &coordinator_request_digest,
            TransactionStage::ExportReceiptCommitted,
            Some(authorization.authorization_digest().clone()),
            vec![
                receipt.receipt_digest.clone(),
                ready_delivery_digest,
                consumption.receipt_digest().clone(),
                clearance.clearance_digest,
            ],
            Some(receipt.receipt_digest.clone()),
            Some(authorization.binding_digest().clone()),
        )?;
        maybe_crash(crash_at, SenderCrashPoint::ExportReceiptCommitted)?;
        Ok(receipt)
    }

    pub fn load_receipt(
        &self,
        logical_operation_id: &str,
    ) -> Result<Option<SenderExportReceipt>, M6SenderError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        let path = receipt_path(&self.receipts_root, logical_operation_id);
        if !path.exists() {
            return Ok(None);
        }
        let receipt: SenderExportReceipt = load_canonical_file(&path, MAX_RECEIPT_BYTES)?;
        require_digest(
            "sender export receipt",
            &receipt.receipt_digest,
            &receipt.expected_digest()?,
        )?;
        Ok(Some(receipt))
    }

    /// Reopen every exact durable source for one completed export and return a
    /// portable proof whose detached validator replays the same boundaries.
    pub fn load_export_completion_evidence(
        &self,
        logical_operation_id: &str,
    ) -> Result<Option<SenderExportCompletionEvidenceV1>, M6SenderError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        let receipt = match self.load_receipt(logical_operation_id)? {
            Some(receipt) => receipt,
            None => return Ok(None),
        };
        let request_root = request_unit_path(&self.requests_root, logical_operation_id);
        let (request, _) = load_request_unit(&request_root, self.route())?;
        let request_record_bytes = read_regular_bounded(
            &request_root.join(REQUEST_RECORD_FILE),
            MAX_REQUEST_RECORD_BYTES,
        )?;
        let request_commit_bytes = read_regular_bounded(
            &request_root.join(REQUEST_COMMIT_FILE),
            MAX_REQUEST_RECORD_BYTES,
        )?;
        let bundle_limit = usize::try_from(
            self.route()
                .resource_profile
                .max_attachment_bytes
                .min(self.route().resource_profile.max_evidence_bytes),
        )
        .unwrap_or(usize::MAX);
        let m5_export_bundle_bytes =
            read_regular_bounded(&request_root.join(REQUEST_BUNDLE_FILE), bundle_limit)?;

        let retained = match self
            .issuer
            .prepared_resolution(&request.issuance_idempotency_key)
            .map_err(|error| M6SenderError::Identity(error.to_string()))?
        {
            PreparedIssuanceResolution::ChainCommitted { issuance, .. } => issuance.issued,
            PreparedIssuanceResolution::Missing
            | PreparedIssuanceResolution::Prepared(_)
            | PreparedIssuanceResolution::Abandoned { .. } => {
                return Err(M6SenderError::Integrity(
                    "completed sender export lacks an exact committed issuance".to_string(),
                ));
            }
        };
        let ready = self
            .spool
            .read_outbound_ready(&receipt.message_digest)
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        let authorization = self
            .authorization
            .load_authorization(&receipt.authorization_digest)
            .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        let consumption = self
            .authorization
            .load_consumption(&receipt.authorization_digest, 1)
            .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        let clearance = self.latest_clearance(&request, &retained)?.ok_or_else(|| {
            M6SenderError::Integrity(
                "completed sender export lacks its exact pre-chain M5 clearance".to_string(),
            )
        })?;
        let profile = self.authorization.profile();
        let authorization_profile_bytes = profile
            .canonical_bytes()
            .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        let authorization_bytes = authorization
            .canonical_bytes(profile, self.authorization.verifier())
            .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        let authorization_consumption_bytes = consumption
            .canonical_bytes(&authorization)
            .map_err(|error| M6SenderError::Authority(error.to_string()))?;
        let evidence = SenderExportCompletionEvidenceV1::from_sources(
            self.route(),
            &self.signer,
            request_record_bytes,
            request_commit_bytes,
            m5_export_bundle_bytes,
            retained,
            ready,
            authorization_profile_bytes,
            authorization_bytes,
            authorization_consumption_bytes,
            canonical_json(&clearance)?,
            canonical_json(&receipt)?,
        )?;
        evidence.validate(self.route(), profile, self.authorization.verifier())?;
        Ok(Some(evidence))
    }

    /// Capture a fresh sender-owned M5 projection after the receiver-side
    /// accepted/rollback controls have run.
    ///
    /// The two prior completion records may have been captured before route
    /// collection removed their ready units. Their pinned sender signatures and
    /// opaque authority sources are revalidated here, then the current live M5
    /// bundle must equal both byte-for-byte before a new sender signature is
    /// emitted.
    pub fn capture_post_rollback_isolation_audit(
        &self,
        accepted: &SenderExportCompletionEvidenceV1,
        rolled_back: &SenderExportCompletionEvidenceV1,
    ) -> Result<SenderPostRollbackIsolationAuditV1, M6SenderError> {
        let profile = self.authorization.profile();
        let verifier = self.authorization.verifier();
        accepted.validate(self.route(), profile, verifier)?;
        rolled_back.validate(self.route(), profile, verifier)?;
        let current = self
            .m5
            .export_active_adopted_bundle()
            .map_err(|error| M6SenderError::M5(error.to_string()))?;
        let captured_at_ms = self
            .clock
            .now_ms()
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        SenderPostRollbackIsolationAuditV1::from_live(
            self.route(),
            &self.signer,
            accepted,
            rolled_back,
            current,
            captured_at_ms,
        )
    }

    pub fn load_abandonment(
        &self,
        logical_operation_id: &str,
    ) -> Result<Option<SenderExportAbandonment>, M6SenderError> {
        validate_identifier("logical operation id", logical_operation_id)?;
        let path = abandonment_path(&self.abandonments_root, logical_operation_id);
        if !path.exists() {
            return Ok(None);
        }
        let request_path = request_unit_path(&self.requests_root, logical_operation_id);
        let (request, _) = load_request_unit(&request_path, self.route())?;
        let resolution = self
            .issuer
            .prepared_resolution(&request.issuance_idempotency_key)
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        let identity_abandonment = match resolution {
            PreparedIssuanceResolution::Abandoned { abandonment, .. } => abandonment,
            _ => {
                return Err(M6SenderError::Integrity(
                    "sender abandonment projection has no exact identity-layer fact".to_string(),
                ));
            }
        };
        let record: SenderExportAbandonment = load_canonical_file(&path, MAX_ABANDONMENT_BYTES)?;
        record.validate(&request, &identity_abandonment)?;
        Ok(Some(record))
    }

    pub fn last_committed_sequence(&self) -> u64 {
        self.issuer.last_sequence()
    }

    fn resolve_or_prepare_issuance(
        &mut self,
        request: &SenderExportRequest,
        material: &ExportMaterial,
    ) -> Result<(IssuedManifest, ContentDigest, bool), M6SenderError> {
        let mut resolution = self
            .issuer
            .prepared_resolution(&request.issuance_idempotency_key)
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        if matches!(resolution, PreparedIssuanceResolution::Missing) {
            self.issuer
                .prepare_idempotent(
                    request.issuance_idempotency_key.clone(),
                    &self.signer,
                    export_payload(request),
                    clone_attachment_inputs(&material.inputs),
                    request.message_lifetime_ms,
                )
                .map_err(|error| M6SenderError::Identity(error.to_string()))?;
            resolution = self
                .issuer
                .prepared_resolution(&request.issuance_idempotency_key)
                .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        }
        let (issuance, chain_committed) = match resolution {
            PreparedIssuanceResolution::Prepared(issuance) => (issuance, false),
            PreparedIssuanceResolution::ChainCommitted { commit, issuance } => {
                if commit.message_digest != issuance.issued.manifest.message_digest
                    || commit.sequence != issuance.issued.manifest.unsigned.sequence
                {
                    return Err(M6SenderError::Integrity(
                        "origin-chain fact differs from retained prepared issuance".to_string(),
                    ));
                }
                (issuance, true)
            }
            PreparedIssuanceResolution::Abandoned { abandonment, .. } => {
                return Err(M6SenderError::ExportAbandoned {
                    logical_operation_id: request.logical_operation_id.clone(),
                    abandonment_digest: abandonment.record_digest,
                });
            }
            PreparedIssuanceResolution::Missing => {
                return Err(M6SenderError::Integrity(
                    "manifest issuer lost the just-persisted prepare".to_string(),
                ));
            }
        };
        if issuance.idempotency_key != request.issuance_idempotency_key {
            return Err(M6SenderError::Integrity(
                "prepared issuance idempotency identity differs from the outer request".to_string(),
            ));
        }
        validate_issued(request, material, &issuance.issued, self.route())?;
        Ok((issuance.issued, issuance.request_digest, chain_committed))
    }

    fn record_clearance(
        &self,
        request: &SenderExportRequest,
        issued: &IssuedManifest,
    ) -> Result<SenderExportClearance, M6SenderError> {
        let existing = self.clearances(request, issued)?;
        let attempt = u32::try_from(existing.len() + 1).map_err(|_| {
            M6SenderError::ResourceExhausted("sender clearance attempt overflowed".to_string())
        })?;
        if attempt > self.retry_policy.max_attempts {
            return Err(M6SenderError::ResourceExhausted(
                "sender M5 clearance retry budget is exhausted".to_string(),
            ));
        }
        let checked_at_ms = self
            .clock
            .now_ms()
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        let previous = existing
            .last()
            .map(|clearance| clearance.clearance_digest.clone());
        let clearance =
            SenderExportClearance::new(request, issued, checked_at_ms, attempt, previous)?;
        let operation_root =
            clearance_operation_root(&self.clearances_root, &request.logical_operation_id);
        if !operation_root.exists() {
            fs::create_dir(&operation_root)
                .map_err(|source| M6SenderError::io(&operation_root, source))?;
            sync_directory(&self.clearances_root)?;
        }
        let path = operation_root.join(format!("{attempt:04}.json"));
        persist_immutable_file(&path, &canonical_json(&clearance)?)?;
        Ok(clearance)
    }

    fn latest_clearance(
        &self,
        request: &SenderExportRequest,
        issued: &IssuedManifest,
    ) -> Result<Option<SenderExportClearance>, M6SenderError> {
        Ok(self.clearances(request, issued)?.pop())
    }

    fn clearances(
        &self,
        request: &SenderExportRequest,
        issued: &IssuedManifest,
    ) -> Result<Vec<SenderExportClearance>, M6SenderError> {
        let root = clearance_operation_root(&self.clearances_root, &request.logical_operation_id);
        if !root.exists() {
            return Ok(Vec::new());
        }
        reject_symlink(&root)?;
        if !root.is_dir() {
            return Err(M6SenderError::Integrity(
                "sender clearance operation root is not a directory".to_string(),
            ));
        }
        let mut paths = Vec::new();
        for entry in fs::read_dir(&root).map_err(|source| M6SenderError::io(&root, source))? {
            let entry = entry.map_err(|source| M6SenderError::io(&root, source))?;
            let path = entry.path();
            reject_symlink(&path)?;
            if !entry
                .file_type()
                .map_err(|source| M6SenderError::io(&path, source))?
                .is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                return Err(M6SenderError::Integrity(format!(
                    "unexpected sender clearance entry '{}'",
                    path.display()
                )));
            }
            paths.push(path);
            if paths.len() > self.retry_policy.max_attempts as usize {
                return Err(M6SenderError::ResourceExhausted(
                    "sender clearance records exceed the retry budget".to_string(),
                ));
            }
        }
        paths.sort();
        let mut records = Vec::with_capacity(paths.len());
        let mut previous = None;
        for (index, path) in paths.into_iter().enumerate() {
            let record: SenderExportClearance = load_canonical_file(&path, MAX_CLEARANCE_BYTES)?;
            record.validate(request, issued)?;
            let expected_attempt = u32::try_from(index + 1).map_err(|_| {
                M6SenderError::ResourceExhausted("sender clearance ordinal overflowed".to_string())
            })?;
            let expected_file_name = format!("{expected_attempt:04}.json");
            if record.attempt != expected_attempt
                || record.previous_clearance_digest != previous
                || path.file_name().and_then(|name| name.to_str())
                    != Some(expected_file_name.as_str())
            {
                return Err(M6SenderError::Integrity(
                    "sender clearance chain has a gap or false prior link".to_string(),
                ));
            }
            previous = Some(record.clearance_digest.clone());
            records.push(record);
        }
        Ok(records)
    }

    fn operation_is_terminally_abandoned(
        &self,
        logical_operation_id: &str,
    ) -> Result<bool, M6SenderError> {
        self.load_abandonment(logical_operation_id)
            .map(|record| record.is_some())
    }

    fn append_stage(
        &self,
        request: &SenderExportRequest,
        coordinator_request_digest: &ContentDigest,
        stage: TransactionStage,
        authority_ref: Option<ContentDigest>,
        evidence_refs: Vec<ContentDigest>,
        receipt_ref: Option<ContentDigest>,
        attestation_ref: Option<ContentDigest>,
    ) -> Result<(), M6SenderError> {
        self.journal
            .append(
                &request.logical_operation_id,
                coordinator_request_digest,
                stage,
                stage_evidence(authority_ref, evidence_refs, receipt_ref, attestation_ref)?,
            )
            .map_err(|error| M6SenderError::Transaction(error.to_string()))?;
        Ok(())
    }

    fn require_live_bundle_unchanged(
        &self,
        request: &SenderExportRequest,
    ) -> Result<(), M6SenderError> {
        let current = self
            .m5
            .export_active_adopted_bundle()
            .map_err(|error| M6SenderError::M5(error.to_string()))?;
        let current_bytes = current
            .canonical_bytes()
            .map_err(|error| M6SenderError::M5(error.to_string()))?;
        if current.bundle_digest() != &request.bundle_digest
            || ContentDigest::from_bytes(&current_bytes) != request.bundle_bytes_digest
            || current.active_runtime_snapshot().snapshot_digest != request.active_snapshot_digest
            || current.active_package().package_digest() != &request.package_digest
        {
            return Err(M6SenderError::M5Changed {
                expected_bundle: request.bundle_digest.clone(),
                actual_bundle: current.bundle_digest().clone(),
            });
        }
        Ok(())
    }

    fn require_no_other_pending_operation(
        &self,
        requested_operation_id: &str,
    ) -> Result<(), M6SenderError> {
        for projection in self
            .journal
            .transactions()
            .map_err(|error| M6SenderError::Transaction(error.to_string()))?
        {
            if projection.intent.logical_operation_id != requested_operation_id
                && !projection
                    .current_stage()
                    .is_some_and(TransactionStage::is_terminal)
                && !self
                    .operation_is_terminally_abandoned(&projection.intent.logical_operation_id)?
            {
                return Err(M6SenderError::RecoveryBlocked {
                    blocking_operation_id: projection.intent.logical_operation_id,
                });
            }
        }
        for unit in bounded_request_units(&self.requests_root, self.max_export_requests as usize)? {
            let (request, _) = load_request_unit(&unit, self.route())?;
            if request.logical_operation_id != requested_operation_id {
                let has_transaction = self
                    .journal
                    .transaction(&request.logical_operation_id)
                    .map_err(|error| M6SenderError::Transaction(error.to_string()))?;
                if has_transaction
                    .as_ref()
                    .and_then(|projection| projection.current_stage())
                    .is_none_or(|stage| !stage.is_terminal())
                    && !self.operation_is_terminally_abandoned(&request.logical_operation_id)?
                {
                    return Err(M6SenderError::RecoveryBlocked {
                        blocking_operation_id: request.logical_operation_id,
                    });
                }
            }
        }
        Ok(())
    }
}

fn prepared_projection(
    request: &SenderExportRequest,
    issued: &IssuedManifest,
) -> Result<PreparedSenderExport, M6SenderError> {
    Ok(PreparedSenderExport {
        logical_operation_id: request.logical_operation_id.clone(),
        request_digest: request.request_digest.clone(),
        bundle_digest: request.bundle_digest.clone(),
        package_digest: request.package_digest.clone(),
        active_snapshot_digest: request.active_snapshot_digest.clone(),
        message_digest: issued.manifest.message_digest.clone(),
        sequence: issued.manifest.unsigned.sequence,
        authorization_binding: export_authorization_binding(request, issued)?,
    })
}

fn export_authorization_binding(
    request: &SenderExportRequest,
    issued: &IssuedManifest,
) -> Result<ExactActionBinding, M6SenderError> {
    let binding = ExactActionBinding {
        action: AuthorityAction::ExportPackage,
        principal_id: request.principal_id.clone(),
        route_id: request.route_id.clone(),
        route_generation: request.route_generation,
        message_digest: issued.manifest.message_digest.clone(),
        exchange_digest: request.request_digest.clone(),
        package_digest: request.package_digest.clone(),
        request_digest: request.request_digest.clone(),
        expected_active_snapshot_digest: request.active_snapshot_digest.clone(),
        import_plan_digest: ContentDigest::from_bytes(NOT_APPLICABLE_IMPORT_PLAN),
        policy_digest: request.exchange_policy_digest.clone(),
        proving_digest: ContentDigest::from_bytes(NOT_APPLICABLE_PROVING),
        approval_context_digest: ContentDigest::from_bytes(NOT_APPLICABLE_APPROVAL),
        idempotency_key: request.issuance_idempotency_key.clone(),
    };
    binding
        .validate()
        .map_err(|error| M6SenderError::Authority(error.to_string()))?;
    Ok(binding)
}

fn export_payload(request: &SenderExportRequest) -> ManifestPayload {
    ManifestPayload::Export(ExportManifestPayload {
        component_digest: request.component_digest.clone(),
        export_bundle_digest: request.bundle_digest.clone(),
        package_bytes_digest: request.package_bytes_digest.clone(),
        package_digest: request.package_digest.clone(),
    })
}

fn transaction_draft(
    request: &SenderExportRequest,
    issued: &IssuedManifest,
    authorization_digest: ContentDigest,
    retry_policy: RetryPolicy,
) -> TransactionRequestDraft {
    TransactionRequestDraft {
        kind: TransactionKind::SenderExport,
        logical_operation_id: request.logical_operation_id.clone(),
        idempotency_key: request.issuance_idempotency_key.clone(),
        route_id: request.route_id.clone(),
        route_generation: request.route_generation,
        route_definition_digest: request.route_definition_digest.clone(),
        message_digest: issued.manifest.message_digest.clone(),
        exchange_digest: request.request_digest.clone(),
        package_digest: request.package_digest.clone(),
        before_snapshot_digest: request.active_snapshot_digest.clone(),
        expected_after_snapshot_digest: request.active_snapshot_digest.clone(),
        policy_digest: request.exchange_policy_digest.clone(),
        authority_refs: vec![authorization_digest],
        evidence_refs: vec![
            request.request_digest.clone(),
            request.bundle_digest.clone(),
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
) -> Result<StageEvidence, M6SenderError> {
    StageEvidence::new(
        StageCause::Normal,
        1,
        authority_ref,
        None,
        receipt_ref,
        attestation_ref,
        evidence_refs,
    )
    .map_err(|error| M6SenderError::Transaction(error.to_string()))
}

fn build_export_material(
    bundle: &M5ExportBundleV1,
    route: &RouteDefinition,
) -> Result<ExportMaterial, M6SenderError> {
    bundle
        .validate_standalone()
        .map_err(|error| M6SenderError::M5(error.to_string()))?;
    route
        .validate()
        .map_err(|error| M6SenderError::Identity(error.to_string()))?;
    let bundle_bytes = bundle
        .canonical_bytes()
        .map_err(|error| M6SenderError::M5(error.to_string()))?;
    if u64::try_from(bundle_bytes.len()).unwrap_or(u64::MAX)
        > route.resource_profile.max_evidence_bytes
    {
        return Err(M6SenderError::ResourceExhausted(
            "M5 export bundle exceeds the immutable route evidence budget".to_string(),
        ));
    }
    let active_package =
        FactoryPackage::from_canonical_bytes(bundle.active_package().canonical_package_bytes())
            .map_err(|error| M6SenderError::M5(error.to_string()))?;

    let mut unique = BTreeMap::<ContentDigest, AttachmentInput>::new();
    insert_unique_attachment(
        &mut unique,
        AttachmentInput::new(
            M5_EXPORT_ATTACHMENT_NAME,
            M5_EXPORT_ATTACHMENT_MEDIA_TYPE,
            bundle_bytes.clone(),
        ),
    )?;

    let mut exported_packages: Vec<(bool, &M5ExportPackageV1)> =
        Vec::with_capacity(bundle.referenced_packages().len() + 1);
    exported_packages.push((true, bundle.active_package()));
    exported_packages.extend(
        bundle
            .referenced_packages()
            .iter()
            .map(|package| (false, package)),
    );
    exported_packages.sort_by(|left, right| left.1.package_digest().cmp(right.1.package_digest()));

    let mut package_bindings = Vec::with_capacity(exported_packages.len());
    for (active, package) in exported_packages {
        if u64::try_from(package.canonical_package_bytes().len()).unwrap_or(u64::MAX)
            > route.resource_profile.max_package_bytes
        {
            return Err(M6SenderError::ResourceExhausted(
                "M5 export package exceeds the immutable route package budget".to_string(),
            ));
        }
        let package_digest = package.package_digest().clone();
        let package_attachment_digest =
            ContentDigest::from_bytes(package.canonical_package_bytes());
        let recipe_attachment_digest = ContentDigest::from_bytes(package.recipe_wat_bytes());
        if package_attachment_digest != *package.canonical_package_bytes_digest()
            || recipe_attachment_digest != *package.recipe_wat_digest()
        {
            return Err(M6SenderError::Integrity(
                "M5 export package attachment identities diverge".to_string(),
            ));
        }
        insert_unique_attachment(
            &mut unique,
            AttachmentInput::new(
                m5_package_attachment_name(&package_attachment_digest),
                M5_PACKAGE_ATTACHMENT_MEDIA_TYPE,
                package.canonical_package_bytes().to_vec(),
            ),
        )?;
        insert_unique_attachment(
            &mut unique,
            AttachmentInput::new(
                m5_recipe_attachment_name(&recipe_attachment_digest),
                M5_RECIPE_ATTACHMENT_MEDIA_TYPE,
                package.recipe_wat_bytes().to_vec(),
            ),
        )?;
        package_bindings.push(SenderPackageAttachmentBinding {
            active,
            package_attachment_digest,
            package_digest,
            recipe_attachment_digest,
        });
    }
    package_bindings.sort_by(|left, right| left.package_digest.cmp(&right.package_digest));

    if unique.len() > route.resource_profile.max_attachment_count as usize {
        return Err(M6SenderError::ResourceExhausted(
            "M5 bundle attachment closure exceeds the route count budget".to_string(),
        ));
    }
    let mut aggregate = 0_u64;
    let mut inputs: Vec<AttachmentInput> = unique.into_values().collect();
    inputs.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
    let mut descriptors = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let byte_length = u64::try_from(input.bytes.len()).map_err(|_| {
            M6SenderError::ResourceExhausted("attachment byte length overflowed".to_string())
        })?;
        if byte_length == 0 || byte_length > route.resource_profile.max_attachment_bytes {
            return Err(M6SenderError::ResourceExhausted(format!(
                "attachment '{}' exceeds its route byte budget",
                input.logical_name
            )));
        }
        aggregate = aggregate.saturating_add(byte_length);
        descriptors.push(AttachmentDescriptor {
            byte_length,
            content_digest: ContentDigest::from_bytes(&input.bytes),
            logical_name: input.logical_name.clone(),
            media_type: input.media_type.clone(),
        });
    }
    if aggregate > route.resource_profile.max_delivery_bytes {
        return Err(M6SenderError::ResourceExhausted(
            "M5 bundle attachment closure exceeds the aggregate route budget".to_string(),
        ));
    }
    if !descriptors
        .windows(2)
        .all(|window| window[0].logical_name < window[1].logical_name)
    {
        return Err(M6SenderError::Integrity(
            "attachment closure is not strictly ordered".to_string(),
        ));
    }
    let descriptor_digests: BTreeSet<_> = descriptors
        .iter()
        .map(|descriptor| descriptor.content_digest.clone())
        .collect();
    for binding in &package_bindings {
        if !descriptor_digests.contains(&binding.package_attachment_digest)
            || !descriptor_digests.contains(&binding.recipe_attachment_digest)
        {
            return Err(M6SenderError::Integrity(
                "package-to-attachment closure is incomplete".to_string(),
            ));
        }
    }
    Ok(ExportMaterial {
        active_package,
        bundle_bytes,
        descriptors,
        inputs,
        package_bindings,
    })
}

fn insert_unique_attachment(
    unique: &mut BTreeMap<ContentDigest, AttachmentInput>,
    candidate: AttachmentInput,
) -> Result<(), M6SenderError> {
    let digest = ContentDigest::from_bytes(&candidate.bytes);
    if let Some(existing) = unique.get(&digest) {
        if existing.bytes != candidate.bytes {
            return Err(M6SenderError::Integrity(
                "content digest collision across export attachments".to_string(),
            ));
        }
        // Shared recipe bytes deliberately resolve to the one deterministic
        // digest-derived logical name already present.
        return Ok(());
    }
    unique.insert(digest, candidate);
    Ok(())
}

fn clone_attachment_inputs(inputs: &[AttachmentInput]) -> Vec<AttachmentInput> {
    inputs
        .iter()
        .map(|input| {
            AttachmentInput::new(
                input.logical_name.clone(),
                input.media_type.clone(),
                input.bytes.clone(),
            )
        })
        .collect()
}

fn validate_issued(
    request: &SenderExportRequest,
    material: &ExportMaterial,
    issued: &IssuedManifest,
    route: &RouteDefinition,
) -> Result<(), M6SenderError> {
    issued
        .manifest
        .verify_route(route)
        .map_err(|error| M6SenderError::Identity(error.to_string()))?;
    if issued.manifest.unsigned.payload != export_payload(request)
        || issued.manifest.unsigned.attachments != material.descriptors
        || issued.manifest.unsigned.route_id != request.route_id
        || issued.manifest.unsigned.route_generation != request.route_generation
    {
        return Err(M6SenderError::Integrity(
            "retained signed issuance differs from the immutable export request".to_string(),
        ));
    }
    let expected: BTreeMap<_, _> = material
        .inputs
        .iter()
        .map(|input| (ContentDigest::from_bytes(&input.bytes), input.bytes.clone()))
        .collect();
    if issued.attachments != expected {
        return Err(M6SenderError::Integrity(
            "retained issuance attachment bytes differ from the immutable closure".to_string(),
        ));
    }
    Ok(())
}

fn delivery_fact_digest(issued: &IssuedManifest) -> Result<ContentDigest, M6SenderError> {
    digest_domain(
        DELIVERY_FACT_DOMAIN,
        &(
            &issued.manifest.message_digest,
            ContentDigest::from_bytes(
                &issued
                    .manifest
                    .canonical_bytes()
                    .map_err(|error| M6SenderError::Identity(error.to_string()))?,
            ),
            &issued.attachments,
        ),
    )
}

fn persist_request_unit(
    requests_root: &Path,
    destination: &Path,
    request: &SenderExportRequest,
    bundle_bytes: &[u8],
) -> Result<(), M6SenderError> {
    if destination.parent() != Some(requests_root) {
        return Err(M6SenderError::UnsafePath(destination.to_path_buf()));
    }
    let request_bytes = canonical_json(request)?;
    if request_bytes.len() > MAX_REQUEST_RECORD_BYTES {
        return Err(M6SenderError::ResourceExhausted(
            "sender outer request record exceeds its byte budget".to_string(),
        ));
    }
    let commit = SenderExportRequestCommit::new(request, &request_bytes, bundle_bytes)?;
    let temporary = requests_root.join(format!(
        ".building-{}-{}-{}",
        request.request_digest.file_stem(),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&temporary).map_err(|source| M6SenderError::io(&temporary, source))?;
    let result = (|| {
        write_new_sync(&temporary.join(REQUEST_RECORD_FILE), &request_bytes)?;
        write_new_sync(&temporary.join(REQUEST_BUNDLE_FILE), bundle_bytes)?;
        write_new_sync(
            &temporary.join(REQUEST_COMMIT_FILE),
            &canonical_json(&commit)?,
        )?;
        sync_directory(&temporary)?;
        fs::rename(&temporary, destination)
            .map_err(|source| M6SenderError::io(destination, source))?;
        sync_directory(requests_root)
    })();
    if result.is_err() && temporary.exists() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn load_request_unit(
    unit: &Path,
    route: &RouteDefinition,
) -> Result<(SenderExportRequest, Vec<u8>), M6SenderError> {
    reject_symlink(unit)?;
    if !unit.is_dir() {
        return Err(M6SenderError::Integrity(format!(
            "sender request unit '{}' is not a directory",
            unit.display()
        )));
    }
    let entries = bounded_directory_entries(unit, 3)?;
    let expected = BTreeSet::from([
        REQUEST_RECORD_FILE.to_string(),
        REQUEST_BUNDLE_FILE.to_string(),
        REQUEST_COMMIT_FILE.to_string(),
    ]);
    if entries != expected {
        return Err(M6SenderError::Integrity(format!(
            "sender request unit '{}' has missing or unexpected files",
            unit.display()
        )));
    }
    let request_path = unit.join(REQUEST_RECORD_FILE);
    let request_bytes = read_regular_bounded(&request_path, MAX_REQUEST_RECORD_BYTES)?;
    let request: SenderExportRequest = parse_canonical(&request_bytes, MAX_REQUEST_RECORD_BYTES)?;
    let bundle_limit = usize::try_from(
        route
            .resource_profile
            .max_attachment_bytes
            .min(route.resource_profile.max_evidence_bytes),
    )
    .unwrap_or(usize::MAX);
    let bundle_bytes = read_regular_bounded(&unit.join(REQUEST_BUNDLE_FILE), bundle_limit)?;
    let commit_bytes =
        read_regular_bounded(&unit.join(REQUEST_COMMIT_FILE), MAX_REQUEST_RECORD_BYTES)?;
    let commit: SenderExportRequestCommit =
        parse_canonical(&commit_bytes, MAX_REQUEST_RECORD_BYTES)?;
    request.validate(route, &bundle_bytes)?;
    commit.validate(&request, &request_bytes, &bundle_bytes)?;
    if unit
        != request_unit_path(
            unit.parent()
                .ok_or_else(|| M6SenderError::UnsafePath(unit.to_path_buf()))?,
            &request.logical_operation_id,
        )
    {
        return Err(M6SenderError::Integrity(
            "sender request unit is stored under the wrong operation path".to_string(),
        ));
    }
    Ok((request, bundle_bytes))
}

fn request_unit_path(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!(
        "{}.request",
        ContentDigest::from_bytes(logical_operation_id.as_bytes()).file_stem()
    ))
}

fn receipt_path(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!(
        "{}.json",
        ContentDigest::from_bytes(logical_operation_id.as_bytes()).file_stem()
    ))
}

fn abandonment_path(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!(
        "{}.json",
        ContentDigest::from_bytes(logical_operation_id.as_bytes()).file_stem()
    ))
}

fn clearance_operation_root(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!(
        "{}.clearances",
        ContentDigest::from_bytes(logical_operation_id.as_bytes()).file_stem()
    ))
}

fn bounded_request_units(root: &Path, max: usize) -> Result<Vec<PathBuf>, M6SenderError> {
    let mut units = Vec::new();
    for entry in fs::read_dir(root).map_err(|source| M6SenderError::io(root, source))? {
        let entry = entry.map_err(|source| M6SenderError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let file_type = entry
            .file_type()
            .map_err(|source| M6SenderError::io(&path, source))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if file_type.is_dir() && name.ends_with(".request") {
            units.push(path);
        } else if !name.starts_with(".building-") {
            return Err(M6SenderError::Integrity(format!(
                "unexpected entry '{}' in sender request store",
                path.display()
            )));
        }
        if units.len() > max {
            return Err(M6SenderError::ResourceExhausted(
                "sender request store exceeds its record budget".to_string(),
            ));
        }
    }
    units.sort();
    Ok(units)
}

fn enforce_record_bound(root: &Path, max: u32, label: &str) -> Result<(), M6SenderError> {
    if bounded_request_units(root, max as usize)?.len() >= max as usize {
        return Err(M6SenderError::ResourceExhausted(format!(
            "{label} reached the immutable record budget"
        )));
    }
    Ok(())
}

fn enforce_file_bound(root: &Path, max: u32, label: &str) -> Result<(), M6SenderError> {
    let mut count = 0_usize;
    for entry in fs::read_dir(root).map_err(|source| M6SenderError::io(root, source))? {
        let entry = entry.map_err(|source| M6SenderError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if !entry
            .file_type()
            .map_err(|source| M6SenderError::io(&path, source))?
            .is_file()
            || path.extension().and_then(|value| value.to_str()) != Some("json")
        {
            return Err(M6SenderError::Integrity(format!(
                "unexpected sender receipt entry '{}'",
                path.display()
            )));
        }
        count += 1;
        if count >= max as usize {
            return Err(M6SenderError::ResourceExhausted(format!(
                "{label} reached the immutable record budget"
            )));
        }
    }
    Ok(())
}

fn recover_building_directories(root: &Path) -> Result<(), M6SenderError> {
    for entry in fs::read_dir(root).map_err(|source| M6SenderError::io(root, source))? {
        let entry = entry.map_err(|source| M6SenderError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(".building-")
            && entry
                .file_type()
                .map_err(|source| M6SenderError::io(&path, source))?
                .is_dir()
        {
            fs::remove_dir_all(&path).map_err(|source| M6SenderError::io(&path, source))?;
        }
    }
    sync_directory(root)
}

#[derive(Serialize)]
struct SenderDurableStateEntry {
    relative_path: String,
    entry_kind: &'static str,
    byte_length: u64,
    content_digest: Option<ContentDigest>,
}

/// Digest the state owned by the M6 sender endpoint itself.
///
/// The configured canonical M5 subtree is deliberately outside this snapshot:
/// M5 exports and completion evidence prove that boundary separately, while
/// its live M2 worker continuously replaces supervisor state through transient
/// files. Reopen audits and the endpoint owner lock are likewise excluded by
/// their existing rules below.
fn sender_durable_state_root(
    endpoint_root: &Path,
    canonical_m5_root: &Path,
) -> Result<ContentDigest, M6SenderError> {
    if canonical_m5_root == endpoint_root || !canonical_m5_root.starts_with(endpoint_root) {
        return Err(M6SenderError::InvalidConfiguration(
            "the canonical M5 root must be a strict sender endpoint child".to_string(),
        ));
    }
    let mut pending = vec![endpoint_root.to_path_buf()];
    let mut entries = Vec::new();
    let mut aggregate_bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        let mut children = fs::read_dir(&directory)
            .map_err(|source| M6SenderError::io(&directory, source))?
            .map(|entry| {
                entry
                    .map(|value| value.path())
                    .map_err(|source| M6SenderError::io(&directory, source))
            })
            .collect::<Result<Vec<_>, _>>()?;
        children.sort();
        for child in children.into_iter().rev() {
            if child == canonical_m5_root {
                continue;
            }
            reject_symlink(&child)?;
            let relative = child
                .strip_prefix(endpoint_root)
                .map_err(|_| M6SenderError::UnsafePath(child.clone()))?;
            let relative_string = relative
                .to_str()
                .ok_or_else(|| M6SenderError::UnsafePath(child.clone()))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            let first_component = relative
                .components()
                .next()
                .and_then(|component| component.as_os_str().to_str())
                .ok_or_else(|| M6SenderError::UnsafePath(child.clone()))?;
            if first_component == REOPEN_AUDITS_DIRECTORY
                || (relative.components().count() == 1 && first_component == OWNER_LOCK_FILE)
            {
                continue;
            }
            let metadata =
                fs::metadata(&child).map_err(|source| M6SenderError::io(&child, source))?;
            if metadata.is_dir() {
                entries.push(SenderDurableStateEntry {
                    relative_path: relative_string,
                    entry_kind: "directory",
                    byte_length: 0,
                    content_digest: None,
                });
                pending.push(child);
            } else if metadata.is_file() {
                let length = metadata.len();
                if length > MAX_DURABLE_STATE_FILE_BYTES as u64 {
                    return Err(M6SenderError::ResourceExhausted(format!(
                        "sender durable state file '{}' exceeds its snapshot bound",
                        child.display()
                    )));
                }
                aggregate_bytes = aggregate_bytes.checked_add(length).ok_or_else(|| {
                    M6SenderError::ResourceExhausted(
                        "sender durable state byte total overflowed".to_string(),
                    )
                })?;
                if aggregate_bytes > MAX_DURABLE_STATE_AGGREGATE_BYTES {
                    return Err(M6SenderError::ResourceExhausted(
                        "sender durable state exceeds its aggregate snapshot bound".to_string(),
                    ));
                }
                let bytes = read_regular_bounded(&child, MAX_DURABLE_STATE_FILE_BYTES)?;
                entries.push(SenderDurableStateEntry {
                    relative_path: relative_string,
                    entry_kind: "file",
                    byte_length: length,
                    content_digest: Some(ContentDigest::from_bytes(&bytes)),
                });
            } else {
                return Err(M6SenderError::Integrity(format!(
                    "sender durable state contains unsupported entry '{}'",
                    child.display()
                )));
            }
            if entries.len() > MAX_DURABLE_STATE_ENTRIES {
                return Err(M6SenderError::ResourceExhausted(
                    "sender durable state exceeds its entry bound".to_string(),
                ));
            }
        }
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    digest_domain(DURABLE_STATE_ROOT_DOMAIN, &entries)
}

fn generate_process_instance_id(
    nonce_source: &dyn NonceSource,
    previous: Option<&str>,
) -> Result<String, M6SenderError> {
    for _ in 0..8 {
        let mut entropy = [0_u8; 32];
        nonce_source
            .fill(&mut entropy)
            .map_err(|error| M6SenderError::Identity(error.to_string()))?;
        let digest = {
            let mut bytes = Vec::from(PROCESS_INSTANCE_DOMAIN);
            bytes.extend_from_slice(&entropy);
            ContentDigest::from_bytes(&bytes)
        };
        let instance_id = format!("sender-instance:{}", digest.file_stem());
        if previous != Some(instance_id.as_str()) {
            return Ok(instance_id);
        }
    }
    Err(M6SenderError::Integrity(
        "nonce source repeated the prior sender process instance identity".to_string(),
    ))
}

fn load_reopen_recovered_exports(
    receipts_root: &Path,
    route: &RouteDefinition,
    maximum: u32,
) -> Result<Vec<SenderReopenRecoveredExportV1>, M6SenderError> {
    let mut recovered = Vec::new();
    for entry in
        fs::read_dir(receipts_root).map_err(|source| M6SenderError::io(receipts_root, source))?
    {
        let entry = entry.map_err(|source| M6SenderError::io(receipts_root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if !entry
            .file_type()
            .map_err(|source| M6SenderError::io(&path, source))?
            .is_file()
            || path.extension().and_then(|value| value.to_str()) != Some("json")
        {
            return Err(M6SenderError::Integrity(format!(
                "unexpected sender receipt entry '{}'",
                path.display()
            )));
        }
        let receipt: SenderExportReceipt = load_canonical_file(&path, MAX_RECEIPT_BYTES)?;
        require_digest(
            "reopened sender receipt",
            &receipt.receipt_digest,
            &receipt.expected_digest()?,
        )?;
        if receipt.route_definition_digest != route.definition_digest
            || receipt.route_id != route.route_id
            || receipt.route_generation != route.generation
        {
            return Err(M6SenderError::Integrity(
                "reopened sender receipt belongs to another route".to_string(),
            ));
        }
        recovered.push(SenderReopenRecoveredExportV1::from_receipt(receipt)?);
        if recovered.len() > maximum as usize {
            return Err(M6SenderError::ResourceExhausted(
                "reopened sender receipt count exceeds its configured bound".to_string(),
            ));
        }
    }
    recovered.sort_by(|left, right| left.logical_operation_id.cmp(&right.logical_operation_id));
    if !recovered
        .windows(2)
        .all(|pair| pair[0].logical_operation_id < pair[1].logical_operation_id)
    {
        return Err(M6SenderError::Integrity(
            "reopened sender receipts reuse a logical operation id".to_string(),
        ));
    }
    Ok(recovered)
}

fn load_sender_reopen_audit_chain(
    root: &Path,
    route: &RouteDefinition,
) -> Result<Vec<SenderReopenAuditV1>, M6SenderError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).map_err(|source| M6SenderError::io(root, source))? {
        let entry = entry.map_err(|source| M6SenderError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| M6SenderError::UnsafePath(path.clone()))?;
        if !entry
            .file_type()
            .map_err(|source| M6SenderError::io(&path, source))?
            .is_file()
            || !name.starts_with("open-")
            || !name.ends_with(".json")
        {
            return Err(M6SenderError::Integrity(format!(
                "unexpected sender reopen-audit entry '{}'",
                path.display()
            )));
        }
        paths.push(path);
        if paths.len() > MAX_DURABLE_STATE_ENTRIES {
            return Err(M6SenderError::ResourceExhausted(
                "sender reopen-audit chain exceeds its entry bound".to_string(),
            ));
        }
    }
    paths.sort();
    let mut audits = Vec::with_capacity(paths.len());
    for (index, path) in paths.iter().enumerate() {
        let audit: SenderReopenAuditV1 = load_canonical_file(path, MAX_REOPEN_AUDIT_BYTES)?;
        audit.validate(route)?;
        let expected_ordinal = index as u64 + 1;
        if audit.open_ordinal != expected_ordinal
            || audit.previous_audit_digest
                != audits
                    .last()
                    .map(|previous: &SenderReopenAuditV1| previous.audit_digest.clone())
            || audit.previous_process_instance_id
                != audits
                    .last()
                    .map(|previous| previous.current_process_instance_id.clone())
        {
            return Err(M6SenderError::Integrity(
                "sender reopen-audit chain is missing, reordered, or cross-linked".to_string(),
            ));
        }
        audits.push(audit);
    }
    Ok(audits)
}

fn persist_sender_reopen_audit(
    root: &Path,
    audit: &SenderReopenAuditV1,
) -> Result<(), M6SenderError> {
    let path = root.join(format!("open-{:020}.json", audit.open_ordinal));
    persist_immutable_file(&path, &canonical_json(audit)?)
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M6SenderError> {
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| M6SenderError::io(path, source))?;
    let canonical = fs::canonicalize(path).map_err(|source| M6SenderError::io(path, source))?;
    reject_symlink(&canonical)?;
    Ok(canonical)
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M6SenderError> {
    validate_identifier("sender child directory", name)?;
    let path = root.join(name);
    reject_symlink_if_present(&path)?;
    fs::create_dir_all(&path).map_err(|source| M6SenderError::io(&path, source))?;
    let canonical = fs::canonicalize(&path).map_err(|source| M6SenderError::io(&path, source))?;
    if canonical.parent() != Some(root) {
        return Err(M6SenderError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn acquire_endpoint_owner(root: &Path) -> Result<File, M6SenderError> {
    let path = root.join(OWNER_LOCK_FILE);
    reject_symlink_if_present(&path)?;
    let existed = path.exists();
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| M6SenderError::io(&path, source))?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => {
            M6SenderError::EndpointAlreadyOwned(root.to_path_buf())
        }
        std::fs::TryLockError::Error(source) => M6SenderError::io(&path, source),
    })?;
    if !existed {
        sync_directory(root)?;
    }
    Ok(file)
}

pub(crate) fn acquire_sender_endpoint_owner(root: &Path) -> Result<File, M6SenderError> {
    acquire_endpoint_owner(root)
}

fn persist_immutable_file(path: &Path, bytes: &[u8]) -> Result<(), M6SenderError> {
    if path.exists() {
        let existing = read_regular_bounded(path, bytes.len().max(1))?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(M6SenderError::Integrity(format!(
                "immutable file '{}' contains conflicting bytes",
                path.display()
            )))
        };
    }
    write_new_sync(path, bytes)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| M6SenderError::UnsafePath(path.to_path_buf()))?,
    )
}

fn write_new_sync(path: &Path, bytes: &[u8]) -> Result<(), M6SenderError> {
    reject_symlink_if_present(path)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|source| M6SenderError::io(path, source))?;
    file.write_all(bytes)
        .map_err(|source| M6SenderError::io(path, source))?;
    file.sync_all()
        .map_err(|source| M6SenderError::io(path, source))
}

fn read_regular_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, M6SenderError> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|source| M6SenderError::io(path, source))?;
    if !metadata.is_file() || metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(M6SenderError::ResourceExhausted(format!(
            "file '{}' is not regular or exceeds its byte budget",
            path.display()
        )));
    }
    let mut file = File::open(path).map_err(|source| M6SenderError::io(path, source))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(u64::try_from(max_bytes).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| M6SenderError::io(path, source))?;
    if bytes.len() > max_bytes {
        return Err(M6SenderError::ResourceExhausted(format!(
            "file '{}' exceeds its byte budget",
            path.display()
        )));
    }
    Ok(bytes)
}

fn load_canonical_file<T: DeserializeOwned + Serialize>(
    path: &Path,
    max_bytes: usize,
) -> Result<T, M6SenderError> {
    let bytes = read_regular_bounded(path, max_bytes)?;
    parse_canonical(&bytes, max_bytes)
}

fn parse_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, M6SenderError> {
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(M6SenderError::ResourceExhausted(
            "canonical record is outside its byte budget".to_string(),
        ));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| M6SenderError::Serialization(error.to_string()))?;
    if canonical_json(&value)? != bytes {
        return Err(M6SenderError::Integrity(
            "record is not in its canonical JSON representation".to_string(),
        ));
    }
    Ok(value)
}

fn parse_authority_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, M6SenderError> {
    if bytes.is_empty() || bytes.len() > MAX_CLEARANCE_BYTES {
        return Err(M6SenderError::ResourceExhausted(
            "portable authority source is outside its byte budget".to_string(),
        ));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| M6SenderError::Serialization(error.to_string()))?;
    let canonical = serde_json::to_vec_pretty(&value)
        .map_err(|error| M6SenderError::Serialization(error.to_string()))?;
    if canonical != bytes {
        return Err(M6SenderError::Integrity(
            "portable authority source is not in its exact canonical representation".to_string(),
        ));
    }
    Ok(value)
}

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, M6SenderError> {
    serde_json::to_vec(value).map_err(|error| M6SenderError::Serialization(error.to_string()))
}

fn canonical_map_digest(
    values: &BTreeMap<ContentDigest, Vec<u8>>,
) -> Result<ContentDigest, M6SenderError> {
    Ok(ContentDigest::from_bytes(&canonical_json(values)?))
}

fn validate_completion_source_bounds(
    evidence: &SenderExportCompletionEvidenceV1,
) -> Result<(), M6SenderError> {
    let scalar_sources = [
        evidence.request_record_bytes.as_slice(),
        evidence.request_commit_bytes.as_slice(),
        evidence.m5_export_bundle_bytes.as_slice(),
        evidence.retained_manifest_bytes.as_slice(),
        evidence.ready_manifest_bytes.as_slice(),
        evidence.authorization_profile_bytes.as_slice(),
        evidence.authorization_bytes.as_slice(),
        evidence.authorization_consumption_bytes.as_slice(),
        evidence.clearance_bytes.as_slice(),
        evidence.receipt_bytes.as_slice(),
    ];
    if scalar_sources.iter().any(|bytes| bytes.is_empty()) {
        return Err(M6SenderError::Integrity(
            "sender completion evidence contains an empty exact source".to_string(),
        ));
    }
    let mut aggregate = scalar_sources
        .iter()
        .try_fold(0_u64, |total, bytes| total.checked_add(bytes.len() as u64))
        .ok_or_else(|| {
            M6SenderError::ResourceExhausted(
                "sender completion source byte total overflowed".to_string(),
            )
        })?;
    for attachments in [&evidence.retained_attachments, &evidence.ready_attachments] {
        if attachments.is_empty() || attachments.len() > 1_024 {
            return Err(M6SenderError::ResourceExhausted(
                "sender completion attachment set is empty or outside bounds".to_string(),
            ));
        }
        for (digest, bytes) in attachments {
            if bytes.is_empty() || digest != &ContentDigest::from_bytes(bytes) {
                return Err(M6SenderError::Integrity(
                    "sender completion attachment key differs from its exact bytes".to_string(),
                ));
            }
            aggregate = aggregate.checked_add(bytes.len() as u64).ok_or_else(|| {
                M6SenderError::ResourceExhausted(
                    "sender completion attachment byte total overflowed".to_string(),
                )
            })?;
        }
    }
    if aggregate > MAX_COMPLETION_EVIDENCE_BYTES as u64 {
        return Err(M6SenderError::ResourceExhausted(
            "sender completion exact sources exceed their aggregate byte budget".to_string(),
        ));
    }
    Ok(())
}

fn digest_domain<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ContentDigest, M6SenderError> {
    let mut bytes = Vec::from(domain);
    bytes.extend_from_slice(&canonical_json(value)?);
    Ok(ContentDigest::from_bytes(&bytes))
}

fn require_digest(
    subject: &str,
    expected: &ContentDigest,
    actual: &ContentDigest,
) -> Result<(), M6SenderError> {
    if expected == actual {
        Ok(())
    } else {
        Err(M6SenderError::DigestMismatch {
            subject: subject.to_string(),
            expected: expected.clone(),
            actual: actual.clone(),
        })
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<(), M6SenderError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(M6SenderError::InvalidConfiguration(format!(
            "{field} must contain 1..={MAX_IDENTIFIER_BYTES} non-control bytes"
        )));
    }
    Ok(())
}

fn ensure_m5_root_isolated(endpoint_root: &Path, m5_root: &Path) -> Result<(), M6SenderError> {
    for reserved in [
        AUTHORITY_DIRECTORY,
        JOURNAL_DIRECTORY,
        REQUESTS_DIRECTORY,
        RECEIPTS_DIRECTORY,
        CLEARANCES_DIRECTORY,
        ABANDONMENTS_DIRECTORY,
        REOPEN_AUDITS_DIRECTORY,
    ]
    .into_iter()
    .chain(IDENTITY_MUTABLE_TOP_LEVEL_DIRECTORIES.iter().copied())
    {
        let reserved_path = endpoint_root.join(reserved);
        if m5_root.starts_with(&reserved_path) || reserved_path.starts_with(m5_root) {
            return Err(M6SenderError::InvalidConfiguration(format!(
                "the M5 root overlaps reserved sender directory '{reserved}'"
            )));
        }
    }
    Ok(())
}

fn bounded_directory_entries(path: &Path, max: usize) -> Result<BTreeSet<String>, M6SenderError> {
    let mut entries = BTreeSet::new();
    for entry in fs::read_dir(path).map_err(|source| M6SenderError::io(path, source))? {
        let entry = entry.map_err(|source| M6SenderError::io(path, source))?;
        let child = entry.path();
        reject_symlink(&child)?;
        let name = entry.file_name().into_string().map_err(|_| {
            M6SenderError::Integrity(format!(
                "directory '{}' contains a non-UTF-8 entry",
                path.display()
            ))
        })?;
        if !entry
            .file_type()
            .map_err(|source| M6SenderError::io(&child, source))?
            .is_file()
            || !entries.insert(name)
            || entries.len() > max
        {
            return Err(M6SenderError::Integrity(format!(
                "directory '{}' has invalid or excessive entries",
                path.display()
            )));
        }
    }
    Ok(entries)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M6SenderError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(M6SenderError::UnsafePath(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M6SenderError::io(path, source)),
    }
}

fn reject_symlink(path: &Path) -> Result<(), M6SenderError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| M6SenderError::io(path, source))?;
    if metadata.file_type().is_symlink() {
        Err(M6SenderError::UnsafePath(path.to_path_buf()))
    } else {
        Ok(())
    }
}

fn sync_directory(path: &Path) -> Result<(), M6SenderError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| M6SenderError::io(path, source))
}

fn maybe_crash(
    configured: Option<SenderCrashPoint>,
    boundary: SenderCrashPoint,
) -> Result<(), M6SenderError> {
    if configured == Some(boundary) {
        Err(M6SenderError::InjectedCrash(boundary))
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum M6SenderError {
    InvalidConfiguration(String),
    NotPrepared(String),
    Conflict {
        identity: String,
        existing: ContentDigest,
        requested: ContentDigest,
    },
    M5Changed {
        expected_bundle: ContentDigest,
        actual_bundle: ContentDigest,
    },
    RecoveryBlocked {
        blocking_operation_id: String,
    },
    ExportAbandoned {
        logical_operation_id: String,
        abandonment_digest: ContentDigest,
    },
    CannotAbandonCommitted {
        logical_operation_id: String,
        message_digest: ContentDigest,
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
    InjectedCrash(SenderCrashPoint),
    M5(String),
    Identity(String),
    Authority(String),
    Transaction(String),
    Serialization(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl M6SenderError {
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl Display for M6SenderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid M6 sender configuration: {message}")
            }
            Self::NotPrepared(operation) => {
                write!(formatter, "sender export '{operation}' was not prepared")
            }
            Self::Conflict {
                identity,
                existing,
                requested,
            } => write!(
                formatter,
                "sender export identity '{identity}' conflicts: existing {existing}, requested {requested}"
            ),
            Self::M5Changed {
                expected_bundle,
                actual_bundle,
            } => write!(
                formatter,
                "M5 changed before publication: expected {expected_bundle}, observed {actual_bundle}"
            ),
            Self::RecoveryBlocked {
                blocking_operation_id,
            } => write!(
                formatter,
                "sender publication is blocked by incomplete operation '{blocking_operation_id}'"
            ),
            Self::ExportAbandoned {
                logical_operation_id,
                abandonment_digest,
            } => write!(
                formatter,
                "sender export '{logical_operation_id}' was immutably abandoned as {abandonment_digest}"
            ),
            Self::CannotAbandonCommitted {
                logical_operation_id,
                message_digest,
            } => write!(
                formatter,
                "sender export '{logical_operation_id}' cannot be abandoned after origin-chain commit {message_digest}"
            ),
            Self::EndpointAlreadyOwned(path) => write!(
                formatter,
                "M6 sender endpoint '{}' already has a live owner",
                path.display()
            ),
            Self::ResourceExhausted(message) => {
                write!(formatter, "M6 sender resource bound: {message}")
            }
            Self::Integrity(message) => {
                write!(formatter, "M6 sender integrity failure: {message}")
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
                write!(formatter, "unsafe M6 sender path '{}'", path.display())
            }
            Self::InjectedCrash(point) => {
                write!(formatter, "injected sender crash after {point:?}")
            }
            Self::M5(message) => write!(formatter, "M5 sender dependency failed: {message}"),
            Self::Identity(message) => {
                write!(
                    formatter,
                    "M6 sender identity/spool dependency failed: {message}"
                )
            }
            Self::Authority(message) => {
                write!(
                    formatter,
                    "M6 sender authority dependency failed: {message}"
                )
            }
            Self::Transaction(message) => {
                write!(
                    formatter,
                    "M6 sender coordinator dependency failed: {message}"
                )
            }
            Self::Serialization(message) => {
                write!(formatter, "M6 sender serialization failed: {message}")
            }
            Self::Io { path, source } => {
                write!(formatter, "M6 sender I/O at '{}': {source}", path.display())
            }
        }
    }
}

impl Error for M6SenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<M6IdentityError> for M6SenderError {
    fn from(error: M6IdentityError) -> Self {
        Self::Identity(error.to_string())
    }
}

impl From<M6AuthorityError> for M6SenderError {
    fn from(error: M6AuthorityError) -> Self {
        Self::Authority(error.to_string())
    }
}

impl From<M6TransactionError> for M6SenderError {
    fn from(error: M6TransactionError) -> Self {
        Self::Transaction(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::component::ComponentExecutionLimits;
    use crate::factory_reproduction::{
        ApprovalDecision, BenchmarkSpec, CycleOutcome, InvariantKind, InvariantSpec,
        MutableFactoryPolicy, RecursionBudgets, ReleaseGate, ReleaseThresholds, StateCompatibility,
    };
    use crate::m1_validation::{ValidationCase, ValidationSuite};
    use crate::m5_runtime::{M5InitializationAuthority, M5SeedCyclePlan};
    use crate::m6_authority::{
        ActionAuthorizationRequest, AuthorizationIssuer, OpaqueAuthorizationSigner,
    };
    use crate::m6_identity::{
        DeterministicClock, DeterministicNonceSource, FactoryIdentityDocument, RouteResourceProfile,
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
                issuer_id: "issuer:sender-export".to_string(),
                secret: b"sender-test-authority-secret".to_vec(),
            }
        }

        fn proof(&self, payload_digest: &ContentDigest) -> String {
            let mut hasher = Sha256::new();
            hasher.update(b"wasm-biotic:m6:sender-test-authority:v1");
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
                "wasm-biotic-m6-sender-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create sender test root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.exists() && std::env::var_os("KEEP_M6_SENDER_TEST_ROOT").is_none() {
                fs::remove_dir_all(&self.0).expect("remove sender test root");
            }
        }
    }

    struct TestRig {
        _root: TestRoot,
        sender_root: PathBuf,
        receiver_root: PathBuf,
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

            let m5_config = test_m5_config(&sender_root);
            let m5 = M5Runtime::initialize(
                m5_config,
                incumbent_wat(),
                validation_suite(),
                release_gate(),
                1,
                M5InitializationAuthority {
                    operator_ref: "operator:m6-sender-bootstrap".to_string(),
                    rationale: "initialize exact sender M5 fixture".to_string(),
                },
                None,
            )
            .expect("initialize sender M5");
            let outcome = m5
                .run_seeded_cycle(approved_seed("cycle:m6-sender-n1"))
                .expect("adopt sender N+1");
            assert!(matches!(outcome, CycleOutcome::Adopted { .. }));
            drop(m5);

            let exchange_policy_digest = content("sender-exchange-policy");
            let profile = EndpointActionProfile::new(
                "profile:sender-export",
                "factory:sender",
                "issuer:sender-export",
                content("sender-authority-implementation"),
                EndpointAuthorityKind::Export,
            )
            .expect("sender Export profile");
            let sender_signer = sender_signer();
            let receiver_signer =
                FactorySigner::from_seed("key:receiver-v1", [0x72; 32]).expect("receiver signer");
            let package_schemas = vec![content("factory-package-schema")];
            let interface_schemas = vec![content("factory-interface-schema")];
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
            let resources = RouteResourceProfile::bounded_default().expect("route bounds");
            let route = RouteDefinition::new(
                "route:sender-to-receiver",
                1,
                &sender_identity,
                &receiver_identity,
                exchange_policy_digest,
                resources,
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
                receiver_root,
                route_root,
                route,
                profile,
                credential: TestCredential::new(),
                clock: Arc::new(DeterministicClock::new(1_000_000)),
                nonce: Arc::new(DeterministicNonceSource::new([0x53; 32])),
            }
        }

        fn m5_config(&self) -> M5RuntimeConfig {
            test_m5_config(&self.sender_root)
        }

        fn sender_config(&self) -> M6SenderRuntimeConfig {
            M6SenderRuntimeConfig {
                endpoint_root: self.sender_root.clone(),
                m5: self.m5_config(),
                route_root: self.route_root.clone(),
                expected_route_definition_digest: self.route.definition_digest.clone(),
                authorization_profile: self.profile.clone(),
                journal_config: JournalConfig::bounded(64, 8).expect("journal bounds"),
                retry_policy: RetryPolicy::bounded(8, 8, 1_000).expect("retry bounds"),
                max_export_requests: 64,
                max_export_receipts: 64,
            }
        }

        fn open(&self) -> M6SenderRuntime<TestCredential> {
            let clock: Arc<dyn Clock> = self.clock.clone();
            let nonce: Arc<dyn NonceSource> = self.nonce.clone();
            M6SenderRuntime::open(
                self.sender_config(),
                self.credential.clone(),
                sender_signer(),
                clock,
                nonce,
                None,
            )
            .expect("open M6 sender")
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
                    ActionAuthorizationRequest::new(binding, 1).expect("exact action request"),
                    issued_at_ms,
                    expires_at_ms,
                )
                .expect("issue exact authorization")
        }

        fn authorize(
            &self,
            runtime: &M6SenderRuntime<TestCredential>,
            prepared: &PreparedSenderExport,
        ) -> ContentDigest {
            let now = self.clock.now_ms().expect("trusted clock");
            runtime
                .publish_authorization(self.authorization(
                    prepared.authorization_binding.clone(),
                    now,
                    now + 50_000,
                ))
                .expect("publish exact export authorization")
        }
    }

    fn content(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(label.as_bytes())
    }

    fn sender_signer() -> FactorySigner {
        FactorySigner::from_seed("key:sender-v1", [0x51; 32]).expect("sender signer")
    }

    fn test_m5_config(sender_root: &Path) -> M5RuntimeConfig {
        M5RuntimeConfig {
            root: sender_root.join("m5"),
            factory_id: "factory:sender".to_string(),
            scope_id: "scope:m6-sender".to_string(),
            deployment_id: "deployment-m6-sender".to_string(),
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

    fn validation_suite() -> ValidationSuite {
        ValidationSuite::new(
            "m6-sender-suite",
            "transform",
            vec![
                ValidationCase::returns("case:one", 1, 2),
                ValidationCase::returns("case:seven", 7, 8),
            ],
            ComponentExecutionLimits::default(),
        )
        .expect("validation suite")
    }

    fn release_gate() -> ReleaseGate {
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
            "m6-sender-gate",
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

    fn approved_seed(cycle_id: &str) -> M5SeedCyclePlan {
        M5SeedCyclePlan {
            cycle_id: cycle_id.to_string(),
            challenger_wat_bytes: successor_wat(),
            challenger_policy: MutableFactoryPolicy::terminal(2, 2),
            state_compatibility: StateCompatibility {
                readable_schema_min: 1,
                readable_schema_max: 2,
                written_schema: 1,
                incumbent_rollback_readable_through: 2,
            },
            migration_plan: None,
            migration_artifacts: None,
            operator_context_digest: content("m6-sender-operator-context"),
            approval_decision: ApprovalDecision::Approved,
            approver_ref: "operator:m6-sender".to_string(),
            approval_rationale: "approve exact sender fixture".to_string(),
        }
    }

    #[test]
    fn m5_root_rejects_exact_and_nested_sender_or_identity_directory_overlap() {
        let endpoint = PathBuf::from("/sender");
        for directory in [
            AUTHORITY_DIRECTORY,
            REQUESTS_DIRECTORY,
            "m6-route-chains",
            "m6-issued-manifests",
            "m6-raw-quarantine",
        ] {
            assert!(
                ensure_m5_root_isolated(&endpoint, &endpoint.join(directory)).is_err(),
                "exact M5 overlap with {directory} must fail closed"
            );
            assert!(
                ensure_m5_root_isolated(&endpoint, &endpoint.join(directory).join("nested-m5"),)
                    .is_err(),
                "nested M5 overlap with {directory} must fail closed"
            );
        }
        assert!(ensure_m5_root_isolated(&endpoint, &endpoint.join("m5")).is_ok());
    }

    #[test]
    fn happy_export_has_exact_closed_attachments_readback_and_idempotent_receipt() {
        let rig = TestRig::new("happy");
        let mut runtime = rig.open();
        let prepared = runtime
            .prepare_export("export:happy", "principal:exporter", 60_000)
            .expect("prepare exact export");
        assert_eq!(prepared.sequence, 1);
        assert_eq!(runtime.last_committed_sequence(), 0);
        let authorization = rig.authorize(&runtime, &prepared);
        let receipt = runtime
            .commit_export("export:happy", &authorization)
            .expect("commit exact export");
        assert_eq!(receipt.sequence, 1);
        assert_eq!(runtime.last_committed_sequence(), 1);
        assert_eq!(
            runtime
                .commit_export("export:happy", &authorization)
                .expect("exact replay"),
            receipt
        );

        let spool = GovernedFilesystemSpool::open(
            &rig.route_root,
            &rig.sender_root,
            RouteEndpointRole::Sender,
            &rig.route.definition_digest,
        )
        .expect("open readback spool");
        let ready = spool
            .read_outbound_ready(&receipt.message_digest)
            .expect("read exact ready bytes");
        let bundle_descriptor = ready
            .manifest
            .unsigned
            .attachments
            .iter()
            .find(|descriptor| descriptor.logical_name == M5_EXPORT_ATTACHMENT_NAME)
            .expect("bundle descriptor");
        let bundle = M5ExportBundleV1::from_canonical_bytes(
            ready
                .attachments
                .get(&bundle_descriptor.content_digest)
                .expect("bundle bytes"),
        )
        .expect("standalone route bundle");
        let descriptors: BTreeMap<_, _> = ready
            .manifest
            .unsigned
            .attachments
            .iter()
            .map(|descriptor| (descriptor.content_digest.clone(), descriptor))
            .collect();
        for package in
            std::iter::once(bundle.active_package()).chain(bundle.referenced_packages().iter())
        {
            let package_digest = ContentDigest::from_bytes(package.canonical_package_bytes());
            let recipe_digest = ContentDigest::from_bytes(package.recipe_wat_bytes());
            assert_eq!(
                descriptors
                    .get(&package_digest)
                    .expect("package descriptor")
                    .logical_name,
                m5_package_attachment_name(&package_digest)
            );
            assert_eq!(
                descriptors
                    .get(&recipe_digest)
                    .expect("recipe descriptor")
                    .logical_name,
                m5_recipe_attachment_name(&recipe_digest)
            );
            let expected_package_bytes = package.canonical_package_bytes().to_vec();
            let ready_package_bytes = ready.attachments.get(&package_digest);
            assert!(
                ready_package_bytes.is_some_and(|bytes| bytes == &expected_package_bytes),
                "ready export package attachment differed from the exact M5 package (expected_bytes={}, actual_bytes={})",
                expected_package_bytes.len(),
                ready_package_bytes.map_or(0, |bytes| bytes.len())
            );
            assert_eq!(
                ready.attachments.get(&recipe_digest),
                Some(&package.recipe_wat_bytes().to_vec())
            );
        }
    }

    #[test]
    fn completion_evidence_is_source_bound_signed_and_rechecks_opaque_authority_at_capture() {
        let rig = TestRig::new("completion-evidence");
        let mut runtime = rig.open();
        let prepared = runtime
            .prepare_export("export:completion", "principal:exporter", 60_000)
            .expect("prepare completion export");
        let authorization = rig.authorize(&runtime, &prepared);
        let receipt = runtime
            .commit_export("export:completion", &authorization)
            .expect("commit completion export");
        let evidence = runtime
            .load_export_completion_evidence("export:completion")
            .expect("load completion evidence")
            .expect("completed export evidence");
        assert_eq!(evidence.receipt_digest(), &receipt.receipt_digest);
        assert_eq!(evidence.message_digest(), &receipt.message_digest);

        let bytes = evidence
            .canonical_bytes(&rig.route, &rig.profile, &rig.credential)
            .expect("canonical completion evidence");
        let detached = SenderExportCompletionEvidenceV1::from_canonical_bytes(
            &bytes,
            &rig.route,
            &rig.profile,
            &rig.credential,
        )
        .expect("full detached validation");
        assert!(
            detached == evidence,
            "detached sender completion evidence differed from its canonical source"
        );
        let endpoint_detached =
            SenderExportCompletionEvidenceV1::from_canonical_bytes_detached(&bytes, &rig.route)
                .expect("endpoint-signed detached validation");
        assert!(
            endpoint_detached == evidence,
            "endpoint-signed sender completion evidence differed from its canonical source"
        );

        let wrong_verifier = TestCredential {
            issuer_id: rig.credential.issuer_id.clone(),
            secret: b"wrong-sender-authority-secret".to_vec(),
        };
        assert!(
            SenderExportCompletionEvidenceV1::from_canonical_bytes(
                &bytes,
                &rig.route,
                &rig.profile,
                &wrong_verifier,
            )
            .is_err(),
            "live capture validation must reject the wrong opaque verifier"
        );
        let wrong_profile = EndpointActionProfile::new(
            "profile:wrong-sender-export",
            "factory:sender",
            "issuer:sender-export",
            content("wrong-sender-authority-implementation"),
            EndpointAuthorityKind::Export,
        )
        .expect("wrong but internally valid profile");
        assert!(
            SenderExportCompletionEvidenceV1::from_canonical_bytes(
                &bytes,
                &rig.route,
                &wrong_profile,
                &rig.credential,
            )
            .is_err(),
            "live capture validation must reject the wrong pinned profile"
        );

        let mut tampered: serde_json::Value =
            serde_json::from_slice(&bytes).expect("completion JSON");
        let bundle_bytes = tampered
            .get_mut("m5_export_bundle_bytes")
            .and_then(serde_json::Value::as_array_mut)
            .expect("bundle byte array");
        let first = bundle_bytes[0].as_u64().expect("first bundle byte");
        bundle_bytes[0] = serde_json::Value::from(first ^ 1);
        let tampered_bytes = serde_json::to_vec(&tampered).expect("canonical tampered JSON");
        assert!(
            SenderExportCompletionEvidenceV1::from_canonical_bytes_detached(
                &tampered_bytes,
                &rig.route,
            )
            .is_err(),
            "one changed exact source byte must fail closed"
        );

        let mut forged = evidence.clone();
        forged.message_digest = content("forged-completion-message");
        forged.evidence_digest = forged.expected_digest().expect("forged digest");
        let forged_bytes = canonical_json(&forged).expect("forged canonical bytes");
        assert!(
            SenderExportCompletionEvidenceV1::from_canonical_bytes_detached(
                &forged_bytes,
                &rig.route,
            )
            .is_err(),
            "recomputed public digests cannot replace the sender Ed25519 attestation"
        );
    }

    #[test]
    fn post_rollback_isolation_audit_reopens_the_exact_live_m5_state() {
        let rig = TestRig::new("post-rollback-isolation");
        let mut runtime = rig.open();
        for operation in ["export:isolation-accepted", "export:isolation-rolled-back"] {
            let prepared = runtime
                .prepare_export(operation, "principal:exporter", 60_000)
                .expect("prepare isolation export");
            let authorization = rig.authorize(&runtime, &prepared);
            runtime
                .commit_export(operation, &authorization)
                .expect("commit isolation export");
        }
        let accepted = runtime
            .load_export_completion_evidence("export:isolation-accepted")
            .expect("load accepted sender evidence")
            .expect("accepted sender evidence");
        let rolled_back = runtime
            .load_export_completion_evidence("export:isolation-rolled-back")
            .expect("load rolled-back sender evidence")
            .expect("rolled-back sender evidence");
        let audit = runtime
            .capture_post_rollback_isolation_audit(&accepted, &rolled_back)
            .expect("capture sender M5 isolation");
        assert_eq!(
            audit.accepted_export_evidence_digest(),
            accepted.evidence_digest()
        );
        assert_eq!(
            audit.rolled_back_export_evidence_digest(),
            rolled_back.evidence_digest()
        );
        assert!(
            audit.m5_export_bundle_bytes() == accepted.m5_export_bundle_bytes(),
            "sender isolation audit differed from the accepted M5 export bundle (audit_bytes={}, accepted_bytes={})",
            audit.m5_export_bundle_bytes().len(),
            accepted.m5_export_bundle_bytes().len()
        );
        assert!(
            audit.m5_export_bundle_bytes() == rolled_back.m5_export_bundle_bytes(),
            "sender isolation audit differed from the rolled-back M5 export bundle (audit_bytes={}, rolled_back_bytes={})",
            audit.m5_export_bundle_bytes().len(),
            rolled_back.m5_export_bundle_bytes().len()
        );
        assert_eq!(audit.active_package_digest(), accepted.package_digest());
        assert_eq!(
            audit.active_snapshot_digest(),
            accepted.active_snapshot_digest()
        );

        let bytes = audit
            .canonical_bytes(&rig.route)
            .expect("canonical sender isolation audit");
        let detached =
            SenderPostRollbackIsolationAuditV1::from_canonical_bytes_detached(&bytes, &rig.route)
                .expect("detached sender isolation audit");
        assert!(
            detached == audit,
            "detached sender isolation audit differed from its canonical source"
        );
        assert!(
            runtime
                .capture_post_rollback_isolation_audit(&accepted, &accepted)
                .is_err(),
            "one export cannot be relabeled as both completion outcomes"
        );

        let mut forged = audit.clone();
        forged.captured_at_ms = forged.captured_at_ms.saturating_add(1);
        forged.audit_digest = forged.expected_digest().expect("recomputed public digest");
        let forged_bytes = canonical_json(&forged).expect("canonical forged isolation audit");
        assert!(
            SenderPostRollbackIsolationAuditV1::from_canonical_bytes_detached(
                &forged_bytes,
                &rig.route,
            )
            .is_err(),
            "public digest recomputation cannot replace the pinned sender signature"
        );
    }

    #[test]
    fn signed_adjacent_reopen_proof_requires_distinct_instance_and_recovered_receipt() {
        let rig = TestRig::new("signed-reopen-proof");
        let receipt = {
            let mut runtime = rig.open();
            assert!(
                runtime
                    .latest_reopen_proof()
                    .expect("first-open proof lookup")
                    .is_none(),
                "initialization is not a restart"
            );
            let prepared = runtime
                .prepare_export("export:restart-proof", "principal:exporter", 60_000)
                .expect("prepare restart export");
            let authorization = rig.authorize(&runtime, &prepared);
            runtime
                .commit_export("export:restart-proof", &authorization)
                .expect("commit restart export")
        };

        let runtime = rig.open();
        let proof = runtime
            .latest_reopen_proof()
            .expect("load latest reopen proof")
            .expect("second open has adjacent proof");
        assert!(
            proof
                .proves_restart_of(&rig.route, "export:restart-proof", &receipt.receipt_digest,)
                .expect("validate restart proof")
        );
        assert!(
            !proof
                .proves_restart_of(
                    &rig.route,
                    "export:restart-proof",
                    &content("wrong-receipt"),
                )
                .expect("validate wrong-receipt query")
        );
        let proof_bytes = proof
            .canonical_bytes(&rig.route)
            .expect("canonical reopen proof");
        let detached = SenderReopenProofV1::from_canonical_bytes(&proof_bytes, &rig.route)
            .expect("detached signed reopen proof");
        assert!(
            detached == proof,
            "detached sender reopen proof differed from its canonical source"
        );

        let mut forged = proof.clone();
        let mut forged_current: SenderReopenAuditV1 =
            parse_canonical(&forged.current_audit_bytes, MAX_REOPEN_AUDIT_BYTES)
                .expect("current audit source");
        forged_current.pre_open_state_digest = content("forged-pre-open-state");
        forged_current.audit_digest = forged_current
            .expected_digest()
            .expect("forged audit digest");
        forged.current_audit_bytes =
            canonical_json(&forged_current).expect("forged current audit bytes");
        forged.current_audit_bytes_digest = ContentDigest::from_bytes(&forged.current_audit_bytes);
        forged.current_audit_digest = forged_current.audit_digest;
        forged.proof_digest = forged.expected_digest().expect("forged proof digest");
        let forged_bytes = canonical_json(&forged).expect("forged proof bytes");
        assert!(
            SenderReopenProofV1::from_canonical_bytes(&forged_bytes, &rig.route).is_err(),
            "recomputed audit and proof digests cannot forge the pinned sender signature"
        );
    }

    #[test]
    fn reopen_digest_excludes_live_m5_heartbeat_state_and_stays_stable_across_reopens() {
        let rig = TestRig::new("reopen-digest-m6-owned-state");
        let runtime = rig.open();
        let endpoint_root = fs::canonicalize(&rig.sender_root).expect("canonical sender root");
        let m5_root = fs::canonicalize(rig.m5_config().root).expect("canonical M5 root");
        let supervisor_state = m5_root.join("m2-supervisor/supervisor-state.json");

        let stable_m6_digest =
            sender_durable_state_root(&endpoint_root, &m5_root).expect("first M6-owned scan");
        let heartbeat_before = fs::read(&supervisor_state).expect("initial live M2 state");
        let heartbeat_after = (0..100)
            .find_map(|_| {
                std::thread::sleep(std::time::Duration::from_millis(10));
                let current = fs::read(&supervisor_state).expect("live M2 heartbeat state");
                (current != heartbeat_before).then_some(current)
            })
            .expect("live M2 heartbeat must replace supervisor state");
        assert_ne!(heartbeat_after, heartbeat_before);

        for _ in 0..32 {
            assert_eq!(
                sender_durable_state_root(&endpoint_root, &m5_root)
                    .expect("repeat scan while M2 heartbeat is live"),
                stable_m6_digest,
                "M2 state and its atomic temporary files are outside the M6 reopen digest"
            );
            std::thread::yield_now();
        }
        drop(runtime);

        for _ in 0..3 {
            let reopened = rig.open();
            let audit = reopened.latest_reopen_audit();
            assert_eq!(
                audit.pre_open_state_digest(),
                audit.post_reconciliation_state_digest(),
                "a clean reopen must not mutate the M6-owned sender state"
            );
            assert_eq!(
                audit.post_reconciliation_state_digest(),
                &stable_m6_digest,
                "reopen audit must retain the stable M6-owned state boundary"
            );
            assert_eq!(
                sender_durable_state_root(&endpoint_root, &m5_root)
                    .expect("scan after clean reopen"),
                stable_m6_digest
            );
            drop(reopened);
        }
    }

    #[test]
    fn every_publication_boundary_recovers_exact_bytes_after_reopen() {
        let rig = TestRig::new("crash-matrix");
        let mut runtime = rig.open();
        for (index, point) in [
            SenderCrashPoint::OuterRequestPersisted,
            SenderCrashPoint::PreparedIssuancePersisted,
        ]
        .into_iter()
        .enumerate()
        {
            let operation = format!("export:prepare-crash-{index}");
            assert!(matches!(
                runtime.prepare_export_with_fault(
                    operation.clone(),
                    "principal:exporter",
                    60_000,
                    Some(point),
                ),
                Err(M6SenderError::InjectedCrash(actual)) if actual == point
            ));
            drop(runtime);
            runtime = rig.open();
            let prepared = runtime
                .prepare_export(operation.clone(), "principal:exporter", 60_000)
                .expect("recover exact prepare");
            let authorization = rig.authorize(&runtime, &prepared);
            runtime
                .commit_export(&operation, &authorization)
                .expect("finish prepare-crash export");
        }

        for (index, point) in [
            SenderCrashPoint::ExportIntentRecorded,
            SenderCrashPoint::OutboundBundleCommitted,
            SenderCrashPoint::AuthorizationConsumed,
            SenderCrashPoint::PreChainM5Revalidated,
            SenderCrashPoint::OriginChainCommitted,
            SenderCrashPoint::RouteStageEffectCommitted,
            SenderCrashPoint::RouteStageCommitted,
            SenderCrashPoint::RouteReadyEffectCommitted,
            SenderCrashPoint::RouteReadyCommitted,
            SenderCrashPoint::ExportReceiptEffectCommitted,
            SenderCrashPoint::ExportReceiptCommitted,
        ]
        .into_iter()
        .enumerate()
        {
            let operation = format!("export:commit-crash-{index}");
            let prepared = runtime
                .prepare_export(operation.clone(), "principal:exporter", 60_000)
                .expect("prepare crash-matrix export");
            let authorization = rig.authorize(&runtime, &prepared);
            assert!(matches!(
                runtime.commit_export_with_fault(
                    &operation,
                    &authorization,
                    Some(point),
                ),
                Err(M6SenderError::InjectedCrash(actual)) if actual == point
            ));
            drop(runtime);
            runtime = rig.open();
            let receipt = runtime
                .recover_export(&operation, &authorization)
                .expect("recover exact publication");
            assert_eq!(receipt.message_digest, prepared.message_digest);
            assert_eq!(receipt.sequence, prepared.sequence);
        }
    }

    #[test]
    fn exact_chain_commit_recovery_finishes_after_source_m5_changes() {
        let rig = TestRig::new("chain-then-m5-change");
        let mut runtime = rig.open();
        let prepared = runtime
            .prepare_export("export:chain-then-change", "principal:exporter", 60_000)
            .expect("prepare export");
        let authorization = rig.authorize(&runtime, &prepared);
        assert!(matches!(
            runtime.commit_export_with_fault(
                "export:chain-then-change",
                &authorization,
                Some(SenderCrashPoint::OriginChainCommitted),
            ),
            Err(M6SenderError::InjectedCrash(
                SenderCrashPoint::OriginChainCommitted
            ))
        ));
        drop(runtime);

        let m5 = M5Runtime::open(rig.m5_config(), None).expect("open source M5");
        m5.operator_revert_active(
            "rollback:after-chain-commit",
            &prepared.package_digest,
            "operator:chain-crash-test",
        )
        .expect("change live M5 after exact chain commit");
        assert!(m5.export_active_adopted_bundle().is_err());
        drop(m5);

        let mut runtime = rig.open();
        let receipt = runtime
            .recover_export("export:chain-then-change", &authorization)
            .expect("finish exact chain-committed bytes without re-export");
        assert_eq!(receipt.message_digest, prepared.message_digest);
        assert_eq!(receipt.sequence, prepared.sequence);
    }

    #[test]
    fn denied_and_expired_abandonment_reuse_coordinate_without_gap() {
        let rig = TestRig::new("abandonment");
        let mut runtime = rig.open();
        let denied = runtime
            .prepare_export("export:denied", "principal:exporter", 60_000)
            .expect("prepare denied export");
        assert_eq!(denied.sequence, 1);
        assert!(matches!(
            runtime.abandon_export_with_fault(
                "export:denied",
                PreparedIssuanceDisposition::AuthorizationDenied,
                "operator denied release",
                content("denial-decision"),
                Some(SenderCrashPoint::AbandonmentEffectCommitted),
            ),
            Err(M6SenderError::InjectedCrash(
                SenderCrashPoint::AbandonmentEffectCommitted
            ))
        ));
        drop(runtime);
        runtime = rig.open();
        let denial = runtime
            .abandon_export(
                "export:denied",
                PreparedIssuanceDisposition::AuthorizationDenied,
                "operator denied release",
                content("denial-decision"),
            )
            .expect("recover exact denial");
        assert_eq!(runtime.last_committed_sequence(), 0);
        assert_eq!(
            runtime
                .load_abandonment("export:denied")
                .expect("load denial"),
            Some(denial.clone())
        );
        assert!(
            runtime
                .abandon_export(
                    "export:denied",
                    PreparedIssuanceDisposition::AuthorizationDenied,
                    "changed denial",
                    content("denial-decision"),
                )
                .is_err(),
            "changed abandonment must conflict"
        );

        let accepted = runtime
            .prepare_export("export:accepted-after-denial", "principal:exporter", 60_000)
            .expect("prepare after denial");
        assert_eq!(accepted.sequence, 1);
        let accepted_authorization = rig.authorize(&runtime, &accepted);
        runtime
            .commit_export("export:accepted-after-denial", &accepted_authorization)
            .expect("commit after denial");

        let expired = runtime
            .prepare_export("export:expired", "principal:exporter", 60_000)
            .expect("prepare expiring export");
        assert_eq!(expired.sequence, 2);
        let now = rig.clock.now_ms().expect("clock");
        let expired_authorization = runtime
            .publish_authorization(rig.authorization(
                expired.authorization_binding.clone(),
                now,
                now + 10,
            ))
            .expect("publish expiring authorization");
        rig.clock.advance(10);
        assert!(
            runtime
                .commit_export("export:expired", &expired_authorization)
                .is_err(),
            "expired authority cannot commit the origin chain"
        );
        runtime
            .abandon_export(
                "export:expired",
                PreparedIssuanceDisposition::AuthorizationExpired,
                "exact export authority expired",
                content("expiry-evidence"),
            )
            .expect("abandon expired prepare");
        assert_eq!(runtime.last_committed_sequence(), 1);

        let accepted_two = runtime
            .prepare_export("export:accepted-after-expiry", "principal:exporter", 60_000)
            .expect("prepare after expiry");
        assert_eq!(accepted_two.sequence, 2);
        let authorization_two = rig.authorize(&runtime, &accepted_two);
        runtime
            .commit_export("export:accepted-after-expiry", &authorization_two)
            .expect("commit same coordinate after expiry");
    }

    #[test]
    fn authorization_target_and_cross_operation_reuse_fail_before_publication() {
        let rig = TestRig::new("authority-target");
        let mut runtime = rig.open();
        let first = runtime
            .prepare_export("export:authority-a", "principal:exporter", 60_000)
            .expect("prepare first");
        let mut wrong_binding = first.authorization_binding.clone();
        wrong_binding.message_digest = content("wrong-message");
        wrong_binding.idempotency_key = "sender-export:wrong-target".to_string();
        let now = rig.clock.now_ms().expect("clock");
        let wrong = runtime
            .publish_authorization(rig.authorization(wrong_binding, now, now + 50_000))
            .expect("publish internally valid wrong target");
        assert!(runtime.commit_export("export:authority-a", &wrong).is_err());
        assert_eq!(runtime.last_committed_sequence(), 0);
        let exact = rig.authorize(&runtime, &first);
        runtime
            .commit_export("export:authority-a", &exact)
            .expect("commit exact first");

        let second = runtime
            .prepare_export("export:authority-b", "principal:exporter", 60_000)
            .expect("prepare second");
        assert!(
            runtime.commit_export("export:authority-b", &exact).is_err(),
            "authorization for operation A cannot publish B"
        );
        assert_eq!(runtime.last_committed_sequence(), 1);
        let second_exact = rig.authorize(&runtime, &second);
        runtime
            .commit_export("export:authority-b", &second_exact)
            .expect("commit exact second");
    }

    #[test]
    fn duplicate_owner_changes_no_bytes_and_peer_root_is_never_persisted() {
        let rig = TestRig::new("owner-peer-root");
        let runtime = rig.open();
        let before = regular_file_snapshot(&rig.sender_root);
        let clock: Arc<dyn Clock> = rig.clock.clone();
        let nonce: Arc<dyn NonceSource> = rig.nonce.clone();
        assert!(matches!(
            M6SenderRuntime::open(
                rig.sender_config(),
                rig.credential.clone(),
                sender_signer(),
                clock,
                nonce,
                None,
            ),
            Err(M6SenderError::EndpointAlreadyOwned(_))
        ));
        assert_eq!(regular_file_snapshot(&rig.sender_root), before);
        let peer_root = rig.receiver_root.to_string_lossy();
        assert!(
            regular_file_snapshot(&rig.sender_root)
                .values()
                .all(|bytes| !contains_subslice(bytes, peer_root.as_bytes())),
            "sender durable bytes must not contain the receiver root"
        );
        drop(runtime);
    }

    #[test]
    fn retained_request_signature_and_route_tamper_fail_closed() {
        let request_rig = TestRig::new("request-tamper");
        let mut runtime = request_rig.open();
        runtime
            .prepare_export("export:request-tamper", "principal:exporter", 60_000)
            .expect("prepare request tamper fixture");
        drop(runtime);
        let request_bundle = find_file(
            &request_rig.sender_root.join(REQUESTS_DIRECTORY),
            REQUEST_BUNDLE_FILE,
        );
        fs::write(&request_bundle, b"{}").expect("tamper retained bundle");
        let mut runtime = request_rig.open();
        assert!(
            runtime
                .prepare_export("export:request-tamper", "principal:exporter", 60_000,)
                .is_err()
        );
        drop(runtime);

        let signature_rig = TestRig::new("signature-tamper");
        let mut runtime = signature_rig.open();
        runtime
            .prepare_export("export:signature-tamper", "principal:exporter", 60_000)
            .expect("prepare signature tamper fixture");
        drop(runtime);
        let manifest = find_file(
            &signature_rig.sender_root.join("m6-issued-manifests"),
            "manifest.json",
        );
        let mut bytes = fs::read(&manifest).expect("read manifest");
        let index = bytes.len() / 2;
        bytes[index] ^= 1;
        fs::write(&manifest, bytes).expect("tamper signature manifest");
        assert!(
            M6SenderRuntime::open(
                signature_rig.sender_config(),
                signature_rig.credential.clone(),
                sender_signer(),
                signature_rig.clock.clone(),
                signature_rig.nonce.clone(),
                None,
            )
            .is_err()
        );

        let route_rig = TestRig::new("route-tamper");
        let runtime = route_rig.open();
        drop(runtime);
        fs::write(route_rig.route_root.join("route-definition.json"), b"{}")
            .expect("tamper route definition");
        assert!(
            M6SenderRuntime::open(
                route_rig.sender_config(),
                route_rig.credential.clone(),
                sender_signer(),
                route_rig.clock.clone(),
                route_rig.nonce.clone(),
                None,
            )
            .is_err()
        );
    }

    fn regular_file_snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, current: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let mut entries: Vec<_> = fs::read_dir(current)
                .expect("read snapshot directory")
                .map(|entry| entry.expect("snapshot entry"))
                .collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let kind = entry.file_type().expect("snapshot type");
                if kind.is_dir() {
                    visit(root, &path, files);
                } else if kind.is_file() {
                    files.insert(
                        path.strip_prefix(root)
                            .expect("relative snapshot")
                            .to_path_buf(),
                        fs::read(&path).expect("snapshot bytes"),
                    );
                }
            }
        }
        let mut files = BTreeMap::new();
        visit(root, root, &mut files);
        files
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn find_file(root: &Path, file_name: &str) -> PathBuf {
        let mut matches = Vec::new();
        fn visit(current: &Path, file_name: &str, matches: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(current).expect("read find directory") {
                let entry = entry.expect("find entry");
                let path = entry.path();
                let kind = entry.file_type().expect("find type");
                if kind.is_dir() {
                    visit(&path, file_name, matches);
                } else if kind.is_file() && entry.file_name().to_string_lossy() == file_name {
                    matches.push(path);
                }
            }
        }
        visit(root, file_name, &mut matches);
        assert_eq!(matches.len(), 1, "expected one matching file");
        matches.remove(0)
    }
}
