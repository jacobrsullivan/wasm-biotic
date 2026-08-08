//! Sender-side intake of receiver acknowledgements and retention-safe route collection.
//!
//! Receiver acknowledgements are transport evidence, not adoption evidence. This
//! runtime first copies the complete receiver-ready route unit into a bounded,
//! sender-local raw quarantine without decoding it. Only retained bytes are then
//! canonically decoded, verified against the route's pinned receiver Ed25519
//! identity, correlated to an exact retained sender export or revocation receipt,
//! and committed to a receiver-origin [`ReplayJournal`].
//!
//! Collection is a separate, retention-gated operation. It preserves sender
//! publication receipts, acknowledgement quarantine, replay state, correlation
//! evidence, and route collection facts. Only the exact acknowledged ready unit
//! is detached and removed.

use crate::execution::artifact::ContentDigest;
use crate::m6_identity::{
    Clock, DELIVERY_COMMIT_SCHEMA, GovernedFilesystemSpool, IssuedManifest, M6IdentityError,
    ManifestKind, ManifestPayload, ReceiverAcknowledgementPayload, ReplayCommitFact,
    ReplayCommitResolution, ReplayJournal, RouteDefinition, RouteEndpointRole, SignedManifest,
};
use crate::m6_revocation::RevocationTargetKindV1;
use crate::m6_revocation_sender_runtime::{
    SENDER_REVOCATION_RECEIPT_SCHEMA, SenderRevocationReceipt, revocation_operation_stem,
};
use crate::m6_sender_runtime::{
    SENDER_EXPORT_RECEIPT_SCHEMA, SenderExportReceipt, acquire_sender_endpoint_owner,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub const SENDER_ACK_RAW_QUARANTINE_SCHEMA: &str = "wasm-biotic.m6-sender-ack-raw-quarantine.v1";
pub const SENDER_ACK_INTENT_SCHEMA: &str = "wasm-biotic.m6-sender-ack-intent.v1";
pub const SENDER_ACK_CORRELATION_SCHEMA: &str = "wasm-biotic.m6-sender-ack-correlation.v1";
pub const SENDER_CONTROL_ACK_INTENT_SCHEMA: &str = "wasm-biotic.m6-sender-control-ack-intent.v1";
pub const SENDER_CONTROL_ACK_RECEIPT_SCHEMA: &str = "wasm-biotic.m6-sender-control-ack-receipt.v1";
pub const SENDER_ACK_COMPLETION_EVIDENCE_SCHEMA: &str =
    "wasm-biotic.m6-sender-ack-completion-evidence.v1";
pub const SENDER_COLLECTION_INTENT_SCHEMA: &str = "wasm-biotic.m6-sender-collection-intent.v1";
pub const ROUTE_COLLECTION_FACT_SCHEMA: &str = "wasm-biotic.m6-route-collection-fact.v1";
pub const SENDER_COLLECTION_STAGE_SCHEMA: &str = "wasm-biotic.m6-sender-collection-stage.v1";
pub const SENDER_COLLECTION_RECEIPT_SCHEMA: &str = "wasm-biotic.m6-sender-collection-receipt.v1";

const ACK_RAW_UNIT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-ack-raw-unit:v1\0";
const ACK_RAW_RECORD_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-ack-raw-record:v1\0";
const ACK_INTENT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-ack-intent:v1\0";
const ACK_CORRELATION_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-ack-correlation:v1\0";
const CONTROL_ACK_INTENT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-control-ack-intent:v1\0";
const CONTROL_ACK_RECEIPT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-control-ack-receipt:v1\0";
const ACK_COMPLETION_EVIDENCE_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-ack-completion-evidence:v1\0";
const ACK_REPLAY_FACT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-ack-replay-fact:v1\0";
const COLLECTION_INTENT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-collection-intent:v1\0";
const ROUTE_COLLECTION_FACT_DOMAIN: &[u8] = b"wasm-biotic:m6:route-collection-fact:v1\0";
const COLLECTION_STAGE_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-collection-stage:v1\0";
const COLLECTION_RECEIPT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-collection-receipt:v1\0";
const COLLECTION_SNAPSHOT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-collection-snapshot:v1\0";
const EXPORT_RECEIPT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-export-receipt:v1\0";
const REVOCATION_RECEIPT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-revocation-receipt:v1\0";
const EXPORT_DELIVERY_FACT_DOMAIN: &[u8] = b"wasm-biotic:m6:sender-delivery-fact:v1\0";
const REVOCATION_DELIVERY_FACT_DOMAIN: &[u8] =
    b"wasm-biotic:m6:sender-revocation-delivery-fact:v1\0";

const RAW_DIRECTORY: &str = "m6-sender-ack-raw-quarantine";
const ACK_INTENTS_DIRECTORY: &str = "m6-sender-ack-intents";
const CORRELATIONS_DIRECTORY: &str = "m6-sender-ack-correlations";
const CONTROL_ACK_INTENTS_DIRECTORY: &str = "m6-sender-control-ack-intents";
const CONTROL_ACK_RECEIPTS_DIRECTORY: &str = "m6-sender-control-ack-receipts";
const COLLECTION_INTENTS_DIRECTORY: &str = "m6-sender-collection-intents";
const COLLECTION_JOURNALS_DIRECTORY: &str = "m6-sender-collection-journals";
const COLLECTION_RECEIPTS_DIRECTORY: &str = "m6-sender-collection-receipts";
const STAGING_DIRECTORY: &str = "m6-sender-ack-staging";
const EXPORT_RECEIPTS_DIRECTORY: &str = "m6-sender-export-receipts";
const REVOCATION_RECEIPTS_DIRECTORY: &str = "m6-sender-revocation-receipts";
const ROUTE_LOCKS_DIRECTORY: &str = "role-locks";
const ROUTE_MAINTENANCE_LOCK_FILE: &str = "maintenance.lock";
const ROUTE_COLLECTION_ARCHIVE_DIRECTORY: &str = "maintenance-collected";
const ROUTE_COLLECTION_FACTS_DIRECTORY: &str = "maintenance-records";
const MANIFEST_FILE: &str = "manifest.json";
const DELIVERY_COMMIT_FILE: &str = "commit.json";
const RAW_RECORD_FILE: &str = "raw-record.json";
const RAW_COMMIT_FILE: &str = "raw-commit.json";
const RAW_UNIT_DIRECTORY: &str = "unit";
const RECORD_SUFFIX: &str = ".json";
const RAW_SUFFIX: &str = ".raw";
const STAGING_PREFIX: &str = ".sender-ack-";
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_RECORD_BYTES: usize = 2 * 1_048_576;
const MAX_RAW_ENTRIES_ABSOLUTE: usize = 4_096;
const MAX_RAW_BYTES_ABSOLUTE: u64 = 64 * 1_048_576;
// Portable ACK evidence uses the same canonical encoder as the durable ACK
// records. The immutable route evidence ceiling may tighten this hard limit.
const MAX_ACK_COMPLETION_EVIDENCE_BYTES: usize = MAX_RECORD_BYTES;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct M6SenderAckRuntimeConfig {
    pub endpoint_root: PathBuf,
    pub route_root: PathBuf,
    pub expected_route_definition_digest: ContentDigest,
    pub max_acknowledgements: u32,
    pub max_collection_records: u32,
    pub max_source_receipts_per_kind: u32,
}

impl M6SenderAckRuntimeConfig {
    fn validate_non_path_fields(&self) -> Result<(), M6SenderAckError> {
        if self.endpoint_root.as_os_str().is_empty()
            || self.route_root.as_os_str().is_empty()
            || self.max_acknowledgements == 0
            || self.max_collection_records == 0
            || self.max_source_receipts_per_kind == 0
            || self.max_collection_records > self.max_acknowledgements
        {
            return Err(M6SenderAckError::InvalidConfiguration(
                "ACK roots and record bounds must be nonempty and internally consistent"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_for_resource_profile(
        &self,
        profile: &crate::m6_identity::RouteResourceProfile,
    ) -> Result<(), M6SenderAckError> {
        self.validate_non_path_fields()?;
        profile.validate().map_err(M6SenderAckError::from)?;
        if self.max_acknowledgements > profile.max_replay_records
            || self.max_collection_records > profile.max_transaction_records
            || self.max_source_receipts_per_kind > profile.max_replay_records
            || self.max_source_receipts_per_kind > profile.max_revocation_records
        {
            return Err(M6SenderAckError::InvalidConfiguration(
                "sender ACK count bounds exceed the immutable route replay, transaction, or revocation budget"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderPublicationKind {
    Export,
    Revocation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderAckRawFileObservation {
    pub byte_length: u64,
    pub content_digest: ContentDigest,
    pub relative_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderAckRawQuarantineRecord {
    pub schema: String,
    pub acknowledgement_message_digest: ContentDigest,
    pub route_definition_digest: ContentDigest,
    pub route_generation: u64,
    pub route_entry_name: String,
    pub observed_at_ms: u64,
    pub files: Vec<SenderAckRawFileObservation>,
    pub total_bytes: u64,
    pub raw_unit_digest: ContentDigest,
    pub record_digest: ContentDigest,
}

impl SenderAckRawQuarantineRecord {
    fn new(
        acknowledgement_message_digest: ContentDigest,
        route: &RouteDefinition,
        route_entry_name: String,
        observed_at_ms: u64,
        files: Vec<SenderAckRawFileObservation>,
    ) -> Result<Self, M6SenderAckError> {
        let total_bytes = files.iter().try_fold(0_u64, |total, file| {
            total.checked_add(file.byte_length).ok_or_else(|| {
                M6SenderAckError::ResourceExhausted(
                    "raw acknowledgement byte count overflowed".to_string(),
                )
            })
        })?;
        let raw_unit_digest = digest_domain(ACK_RAW_UNIT_DOMAIN, &files)?;
        let mut record = Self {
            schema: SENDER_ACK_RAW_QUARANTINE_SCHEMA.to_string(),
            acknowledgement_message_digest,
            route_definition_digest: route.definition_digest.clone(),
            route_generation: route.generation,
            route_entry_name,
            observed_at_ms,
            files,
            total_bytes,
            raw_unit_digest,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        record.record_digest = record.expected_digest()?;
        record.validate(route)?;
        Ok(record)
    }

    fn validate(&self, route: &RouteDefinition) -> Result<(), M6SenderAckError> {
        let expected_entry = delivery_unit_name(&self.acknowledgement_message_digest);
        if self.schema != SENDER_ACK_RAW_QUARANTINE_SCHEMA
            || self.route_definition_digest != route.definition_digest
            || self.route_generation != route.generation
            || self.route_entry_name != expected_entry
            || self.files.is_empty()
            || self.files.len() > raw_entry_limit(route)
            || !strictly_sorted_unique_by(&self.files, |file| file.relative_path.clone())
            || self.total_bytes
                != self
                    .files
                    .iter()
                    .try_fold(0_u64, |total, file| total.checked_add(file.byte_length))
                    .ok_or_else(|| {
                        M6SenderAckError::ResourceExhausted(
                            "raw acknowledgement byte count overflowed".to_string(),
                        )
                    })?
            || self.total_bytes > raw_byte_limit(route)
        {
            return Err(M6SenderAckError::Integrity(
                "sender ACK raw quarantine record is outside its exact route and bounds"
                    .to_string(),
            ));
        }
        for file in &self.files {
            validate_relative_string(&file.relative_path)?;
            if file.byte_length == 0 {
                return Err(M6SenderAckError::Integrity(
                    "sender ACK raw quarantine contains an empty route file".to_string(),
                ));
            }
        }
        require_digest(
            "sender ACK raw unit",
            &self.raw_unit_digest,
            &digest_domain(ACK_RAW_UNIT_DOMAIN, &self.files)?,
        )?;
        require_digest(
            "sender ACK raw quarantine record",
            &self.record_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderAckError> {
        digest_domain(
            ACK_RAW_RECORD_DOMAIN,
            &(
                &self.schema,
                &self.acknowledgement_message_digest,
                &self.route_definition_digest,
                self.route_generation,
                &self.route_entry_name,
                self.observed_at_ms,
                &self.files,
                self.total_bytes,
                &self.raw_unit_digest,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCommitMarker {
    schema: String,
    acknowledgement_message_digest: ContentDigest,
    raw_unit_digest: ContentDigest,
    raw_record_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryCommitMarker {
    manifest_bytes_digest: ContentDigest,
    message_digest: ContentDigest,
    schema: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderSourceReceiptEvidence {
    pub publication_kind: SenderPublicationKind,
    pub logical_operation_id: String,
    pub sender_message_digest: ContentDigest,
    pub sender_sequence: u64,
    pub sender_receipt_digest: ContentDigest,
    pub route_delivery_digest: ContentDigest,
    pub source_committed_at_ms: u64,
}

impl SenderSourceReceiptEvidence {
    fn validate(&self) -> Result<(), M6SenderAckError> {
        validate_identifier(
            "source publication logical operation",
            &self.logical_operation_id,
        )?;
        if self.sender_sequence == 0 {
            return Err(M6SenderAckError::Integrity(
                "source publication receipt has sequence zero".to_string(),
            ));
        }
        require_meaningful_digest("source sender message", &self.sender_message_digest)?;
        require_meaningful_digest("source sender receipt", &self.sender_receipt_digest)?;
        require_meaningful_digest("source route delivery", &self.route_delivery_digest)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderAckIntent {
    schema: String,
    acknowledgement_message_digest: ContentDigest,
    acknowledgement_sequence: u64,
    acknowledgement_nonce: String,
    acknowledgement_previous_message_digest: Option<ContentDigest>,
    signed_manifest_bytes_digest: ContentDigest,
    raw_unit_digest: ContentDigest,
    raw_record_digest: ContentDigest,
    route_definition_digest: ContentDigest,
    route_generation: u64,
    source: SenderSourceReceiptEvidence,
    disposition: String,
    intake_record_digest: ContentDigest,
    raw_quarantine_digest: ContentDigest,
    receiver_transaction_digest: ContentDigest,
    accepted_at_ms: u64,
    intent_digest: ContentDigest,
}

impl SenderAckIntent {
    fn new(
        manifest: &SignedManifest,
        manifest_bytes: &[u8],
        raw: &SenderAckRawQuarantineRecord,
        payload: &ReceiverAcknowledgementPayload,
        source: SenderSourceReceiptEvidence,
        route: &RouteDefinition,
        accepted_at_ms: u64,
    ) -> Result<Self, M6SenderAckError> {
        let mut intent = Self {
            schema: SENDER_ACK_INTENT_SCHEMA.to_string(),
            acknowledgement_message_digest: manifest.message_digest.clone(),
            acknowledgement_sequence: manifest.unsigned.sequence,
            acknowledgement_nonce: manifest.unsigned.nonce.clone(),
            acknowledgement_previous_message_digest: manifest
                .unsigned
                .previous_message_digest
                .clone(),
            signed_manifest_bytes_digest: ContentDigest::from_bytes(manifest_bytes),
            raw_unit_digest: raw.raw_unit_digest.clone(),
            raw_record_digest: raw.record_digest.clone(),
            route_definition_digest: route.definition_digest.clone(),
            route_generation: route.generation,
            source,
            disposition: payload.disposition.clone(),
            intake_record_digest: payload.intake_record_digest.clone(),
            raw_quarantine_digest: payload.raw_quarantine_digest.clone(),
            receiver_transaction_digest: payload.receiver_transaction_digest.clone(),
            accepted_at_ms,
            intent_digest: ContentDigest::from_bytes(&[]),
        };
        intent.intent_digest = intent.expected_digest()?;
        intent.validate(manifest, manifest_bytes, raw, payload, route)?;
        Ok(intent)
    }

    fn validate(
        &self,
        manifest: &SignedManifest,
        manifest_bytes: &[u8],
        raw: &SenderAckRawQuarantineRecord,
        payload: &ReceiverAcknowledgementPayload,
        route: &RouteDefinition,
    ) -> Result<(), M6SenderAckError> {
        if self.schema != SENDER_ACK_INTENT_SCHEMA
            || self.acknowledgement_message_digest != manifest.message_digest
            || self.acknowledgement_sequence != manifest.unsigned.sequence
            || self.acknowledgement_nonce != manifest.unsigned.nonce
            || self.acknowledgement_previous_message_digest
                != manifest.unsigned.previous_message_digest
            || self.signed_manifest_bytes_digest != ContentDigest::from_bytes(manifest_bytes)
            || self.raw_unit_digest != raw.raw_unit_digest
            || self.raw_record_digest != raw.record_digest
            || self.route_definition_digest != route.definition_digest
            || self.route_generation != route.generation
            || self.source.sender_message_digest != payload.sender_message_digest
            || self.disposition != payload.disposition
            || self.intake_record_digest != payload.intake_record_digest
            || self.raw_quarantine_digest != payload.raw_quarantine_digest
            || self.receiver_transaction_digest != payload.receiver_transaction_digest
        {
            return Err(M6SenderAckError::Integrity(
                "sender ACK intent is missing or cross-linked".to_string(),
            ));
        }
        self.source.validate()?;
        require_digest(
            "sender ACK intent",
            &self.intent_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderAckError> {
        digest_domain(
            ACK_INTENT_DOMAIN,
            &(
                &self.schema,
                &self.acknowledgement_message_digest,
                self.acknowledgement_sequence,
                &self.acknowledgement_nonce,
                &self.acknowledgement_previous_message_digest,
                &self.signed_manifest_bytes_digest,
                &self.raw_unit_digest,
                &self.raw_record_digest,
                &self.route_definition_digest,
                self.route_generation,
                &self.source,
                &self.disposition,
                &self.intake_record_digest,
                &self.raw_quarantine_digest,
                &self.receiver_transaction_digest,
                self.accepted_at_ms,
            ),
        )
    }
}

/// Durable sender intent for an authenticated receiver rejection ACK that is
/// deliberately not correlated as a source-publication receipt.
///
/// This path exists because authentication/replay controls can reject a
/// tampered or false-route message digest for which the sender has no retained
/// publication receipt. Such a receiver-signed terminal ACK must still advance
/// the receiver-origin replay chain or it would permanently block every later
/// valid ACK on the route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderControlAcknowledgementIntentV1 {
    schema: String,
    acknowledgement_message_digest: ContentDigest,
    acknowledgement_sequence: u64,
    acknowledgement_nonce: String,
    acknowledgement_previous_message_digest: Option<ContentDigest>,
    signed_manifest_bytes_digest: ContentDigest,
    raw_unit_digest: ContentDigest,
    raw_record_digest: ContentDigest,
    route_definition_digest: ContentDigest,
    route_generation: u64,
    acknowledged_sender_message_digest: ContentDigest,
    disposition: String,
    intake_record_digest: ContentDigest,
    raw_quarantine_digest: ContentDigest,
    receiver_transaction_digest: ContentDigest,
    accepted_at_ms: u64,
    intent_digest: ContentDigest,
}

impl SenderControlAcknowledgementIntentV1 {
    fn new(
        manifest: &SignedManifest,
        manifest_bytes: &[u8],
        raw: &SenderAckRawQuarantineRecord,
        payload: &ReceiverAcknowledgementPayload,
        route: &RouteDefinition,
        accepted_at_ms: u64,
    ) -> Result<Self, M6SenderAckError> {
        let mut intent = Self {
            schema: SENDER_CONTROL_ACK_INTENT_SCHEMA.to_string(),
            acknowledgement_message_digest: manifest.message_digest.clone(),
            acknowledgement_sequence: manifest.unsigned.sequence,
            acknowledgement_nonce: manifest.unsigned.nonce.clone(),
            acknowledgement_previous_message_digest: manifest
                .unsigned
                .previous_message_digest
                .clone(),
            signed_manifest_bytes_digest: ContentDigest::from_bytes(manifest_bytes),
            raw_unit_digest: raw.raw_unit_digest.clone(),
            raw_record_digest: raw.record_digest.clone(),
            route_definition_digest: route.definition_digest.clone(),
            route_generation: route.generation,
            acknowledged_sender_message_digest: payload.sender_message_digest.clone(),
            disposition: payload.disposition.clone(),
            intake_record_digest: payload.intake_record_digest.clone(),
            raw_quarantine_digest: payload.raw_quarantine_digest.clone(),
            receiver_transaction_digest: payload.receiver_transaction_digest.clone(),
            accepted_at_ms,
            intent_digest: ContentDigest::from_bytes(&[]),
        };
        intent.intent_digest = intent.expected_digest()?;
        intent.validate(manifest, manifest_bytes, raw, payload, route)?;
        Ok(intent)
    }

    fn validate(
        &self,
        manifest: &SignedManifest,
        manifest_bytes: &[u8],
        raw: &SenderAckRawQuarantineRecord,
        payload: &ReceiverAcknowledgementPayload,
        route: &RouteDefinition,
    ) -> Result<(), M6SenderAckError> {
        if self.schema != SENDER_CONTROL_ACK_INTENT_SCHEMA
            || self.acknowledgement_message_digest != manifest.message_digest
            || self.acknowledgement_sequence != manifest.unsigned.sequence
            || self.acknowledgement_nonce != manifest.unsigned.nonce
            || self.acknowledgement_previous_message_digest
                != manifest.unsigned.previous_message_digest
            || self.signed_manifest_bytes_digest != ContentDigest::from_bytes(manifest_bytes)
            || self.raw_unit_digest != raw.raw_unit_digest
            || self.raw_record_digest != raw.record_digest
            || self.route_definition_digest != route.definition_digest
            || self.route_generation != route.generation
            || self.acknowledged_sender_message_digest != payload.sender_message_digest
            || self.disposition != payload.disposition
            || self.intake_record_digest != payload.intake_record_digest
            || self.raw_quarantine_digest != payload.raw_quarantine_digest
            || self.receiver_transaction_digest != payload.receiver_transaction_digest
        {
            return Err(M6SenderAckError::Integrity(
                "sender control ACK intent is missing or cross-linked".to_string(),
            ));
        }
        validate_control_ack_payload(payload)?;
        require_digest(
            "sender control ACK intent",
            &self.intent_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderAckError> {
        digest_domain(
            CONTROL_ACK_INTENT_DOMAIN,
            &(
                &self.schema,
                &self.acknowledgement_message_digest,
                self.acknowledgement_sequence,
                &self.acknowledgement_nonce,
                &self.acknowledgement_previous_message_digest,
                &self.signed_manifest_bytes_digest,
                &self.raw_unit_digest,
                &self.raw_record_digest,
                &self.route_definition_digest,
                self.route_generation,
                &self.acknowledged_sender_message_digest,
                &self.disposition,
                &self.intake_record_digest,
                &self.raw_quarantine_digest,
                &self.receiver_transaction_digest,
                self.accepted_at_ms,
            ),
        )
    }
}

/// Sender-side terminal evidence that a receiver-signed negative ACK advanced
/// the route replay chain without being treated as adoption or as a successful
/// source-publication correlation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderControlAcknowledgementReceiptV1 {
    pub schema: String,
    pub acknowledgement_message_digest: ContentDigest,
    pub acknowledgement_sequence: u64,
    pub acknowledgement_nonce: String,
    pub acknowledgement_previous_message_digest: Option<ContentDigest>,
    pub acknowledged_sender_message_digest: ContentDigest,
    pub acknowledgement_intent_digest: ContentDigest,
    pub signed_manifest_bytes_digest: ContentDigest,
    pub raw_unit_digest: ContentDigest,
    pub raw_record_digest: ContentDigest,
    pub disposition: String,
    pub intake_record_digest: ContentDigest,
    pub raw_quarantine_digest: ContentDigest,
    pub receiver_transaction_digest: ContentDigest,
    pub replay_commit_digest: ContentDigest,
    pub replay_retained_until_ms: u64,
    pub accepted_at_ms: u64,
    /// Always false: this receipt does not claim a retained sender publication.
    pub source_correlated: bool,
    /// Always true: the ACK records only a receiver terminal intake decision.
    pub intake_only: bool,
    /// Always false: a rejection ACK can never establish sender adoption.
    pub adoption_inferred: bool,
    pub receipt_digest: ContentDigest,
}

#[derive(Serialize)]
struct ControlAckReceiptDigestMaterial<'a> {
    schema: &'a str,
    acknowledgement_message_digest: &'a ContentDigest,
    acknowledgement_sequence: u64,
    acknowledgement_nonce: &'a str,
    acknowledgement_previous_message_digest: &'a Option<ContentDigest>,
    acknowledged_sender_message_digest: &'a ContentDigest,
    acknowledgement_intent_digest: &'a ContentDigest,
    signed_manifest_bytes_digest: &'a ContentDigest,
    raw_unit_digest: &'a ContentDigest,
    raw_record_digest: &'a ContentDigest,
    disposition: &'a str,
    intake_record_digest: &'a ContentDigest,
    raw_quarantine_digest: &'a ContentDigest,
    receiver_transaction_digest: &'a ContentDigest,
    replay_commit_digest: &'a ContentDigest,
    replay_retained_until_ms: u64,
    accepted_at_ms: u64,
    source_correlated: bool,
    intake_only: bool,
    adoption_inferred: bool,
}

impl SenderControlAcknowledgementReceiptV1 {
    fn new(
        intent: &SenderControlAcknowledgementIntentV1,
        replay: &ReplayCommitFact,
    ) -> Result<Self, M6SenderAckError> {
        let mut receipt = Self {
            schema: SENDER_CONTROL_ACK_RECEIPT_SCHEMA.to_string(),
            acknowledgement_message_digest: intent.acknowledgement_message_digest.clone(),
            acknowledgement_sequence: intent.acknowledgement_sequence,
            acknowledgement_nonce: intent.acknowledgement_nonce.clone(),
            acknowledgement_previous_message_digest: intent
                .acknowledgement_previous_message_digest
                .clone(),
            acknowledged_sender_message_digest: intent.acknowledged_sender_message_digest.clone(),
            acknowledgement_intent_digest: intent.intent_digest.clone(),
            signed_manifest_bytes_digest: intent.signed_manifest_bytes_digest.clone(),
            raw_unit_digest: intent.raw_unit_digest.clone(),
            raw_record_digest: intent.raw_record_digest.clone(),
            disposition: intent.disposition.clone(),
            intake_record_digest: intent.intake_record_digest.clone(),
            raw_quarantine_digest: intent.raw_quarantine_digest.clone(),
            receiver_transaction_digest: intent.receiver_transaction_digest.clone(),
            replay_commit_digest: replay_commit_digest(replay)?,
            replay_retained_until_ms: replay.retained_until_ms,
            accepted_at_ms: intent.accepted_at_ms,
            source_correlated: false,
            intake_only: true,
            adoption_inferred: false,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate(intent, replay)?;
        Ok(receipt)
    }

    fn validate(
        &self,
        intent: &SenderControlAcknowledgementIntentV1,
        replay: &ReplayCommitFact,
    ) -> Result<(), M6SenderAckError> {
        if self.schema != SENDER_CONTROL_ACK_RECEIPT_SCHEMA
            || self.acknowledgement_message_digest != intent.acknowledgement_message_digest
            || self.acknowledgement_sequence != intent.acknowledgement_sequence
            || self.acknowledgement_nonce != intent.acknowledgement_nonce
            || self.acknowledgement_previous_message_digest
                != intent.acknowledgement_previous_message_digest
            || self.acknowledged_sender_message_digest != intent.acknowledged_sender_message_digest
            || self.acknowledgement_intent_digest != intent.intent_digest
            || self.signed_manifest_bytes_digest != intent.signed_manifest_bytes_digest
            || self.raw_unit_digest != intent.raw_unit_digest
            || self.raw_record_digest != intent.raw_record_digest
            || self.disposition != intent.disposition
            || self.intake_record_digest != intent.intake_record_digest
            || self.raw_quarantine_digest != intent.raw_quarantine_digest
            || self.receiver_transaction_digest != intent.receiver_transaction_digest
            || self.replay_commit_digest != replay_commit_digest(replay)?
            || self.replay_retained_until_ms != replay.retained_until_ms
            || self.source_correlated
            || !self.intake_only
            || self.adoption_inferred
        {
            return Err(M6SenderAckError::Integrity(
                "sender control ACK receipt is missing or cross-linked".to_string(),
            ));
        }
        require_digest(
            "sender control ACK receipt",
            &self.receipt_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderAckError> {
        digest_domain(
            CONTROL_ACK_RECEIPT_DOMAIN,
            &ControlAckReceiptDigestMaterial {
                schema: &self.schema,
                acknowledgement_message_digest: &self.acknowledgement_message_digest,
                acknowledgement_sequence: self.acknowledgement_sequence,
                acknowledgement_nonce: &self.acknowledgement_nonce,
                acknowledgement_previous_message_digest: &self
                    .acknowledgement_previous_message_digest,
                acknowledged_sender_message_digest: &self.acknowledged_sender_message_digest,
                acknowledgement_intent_digest: &self.acknowledgement_intent_digest,
                signed_manifest_bytes_digest: &self.signed_manifest_bytes_digest,
                raw_unit_digest: &self.raw_unit_digest,
                raw_record_digest: &self.raw_record_digest,
                disposition: &self.disposition,
                intake_record_digest: &self.intake_record_digest,
                raw_quarantine_digest: &self.raw_quarantine_digest,
                receiver_transaction_digest: &self.receiver_transaction_digest,
                replay_commit_digest: &self.replay_commit_digest,
                replay_retained_until_ms: self.replay_retained_until_ms,
                accepted_at_ms: self.accepted_at_ms,
                source_correlated: self.source_correlated,
                intake_only: self.intake_only,
                adoption_inferred: self.adoption_inferred,
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderAcknowledgementCorrelationReceipt {
    pub schema: String,
    pub source: SenderSourceReceiptEvidence,
    pub acknowledgement_message_digest: ContentDigest,
    pub acknowledgement_sequence: u64,
    pub acknowledgement_nonce: String,
    pub acknowledgement_previous_message_digest: Option<ContentDigest>,
    pub acknowledgement_intent_digest: ContentDigest,
    pub signed_manifest_bytes_digest: ContentDigest,
    pub raw_unit_digest: ContentDigest,
    pub raw_record_digest: ContentDigest,
    pub disposition: String,
    pub intake_record_digest: ContentDigest,
    pub raw_quarantine_digest: ContentDigest,
    pub receiver_transaction_digest: ContentDigest,
    pub replay_commit_digest: ContentDigest,
    pub replay_retained_until_ms: u64,
    pub accepted_at_ms: u64,
    /// Always true: the ACK records receiver intake disposition only.
    pub intake_only: bool,
    /// Always false: sender adoption is never inferred from an ACK.
    pub adoption_inferred: bool,
    pub receipt_digest: ContentDigest,
}

#[derive(Serialize)]
struct AckCorrelationDigestMaterial<'a> {
    schema: &'a str,
    source: &'a SenderSourceReceiptEvidence,
    acknowledgement_message_digest: &'a ContentDigest,
    acknowledgement_sequence: u64,
    acknowledgement_nonce: &'a str,
    acknowledgement_previous_message_digest: &'a Option<ContentDigest>,
    acknowledgement_intent_digest: &'a ContentDigest,
    signed_manifest_bytes_digest: &'a ContentDigest,
    raw_unit_digest: &'a ContentDigest,
    raw_record_digest: &'a ContentDigest,
    disposition: &'a str,
    intake_record_digest: &'a ContentDigest,
    raw_quarantine_digest: &'a ContentDigest,
    receiver_transaction_digest: &'a ContentDigest,
    replay_commit_digest: &'a ContentDigest,
    replay_retained_until_ms: u64,
    accepted_at_ms: u64,
    intake_only: bool,
    adoption_inferred: bool,
}

impl SenderAcknowledgementCorrelationReceipt {
    fn new(intent: &SenderAckIntent, replay: &ReplayCommitFact) -> Result<Self, M6SenderAckError> {
        let mut receipt = Self {
            schema: SENDER_ACK_CORRELATION_SCHEMA.to_string(),
            source: intent.source.clone(),
            acknowledgement_message_digest: intent.acknowledgement_message_digest.clone(),
            acknowledgement_sequence: intent.acknowledgement_sequence,
            acknowledgement_nonce: intent.acknowledgement_nonce.clone(),
            acknowledgement_previous_message_digest: intent
                .acknowledgement_previous_message_digest
                .clone(),
            acknowledgement_intent_digest: intent.intent_digest.clone(),
            signed_manifest_bytes_digest: intent.signed_manifest_bytes_digest.clone(),
            raw_unit_digest: intent.raw_unit_digest.clone(),
            raw_record_digest: intent.raw_record_digest.clone(),
            disposition: intent.disposition.clone(),
            intake_record_digest: intent.intake_record_digest.clone(),
            raw_quarantine_digest: intent.raw_quarantine_digest.clone(),
            receiver_transaction_digest: intent.receiver_transaction_digest.clone(),
            replay_commit_digest: replay_commit_digest(replay)?,
            replay_retained_until_ms: replay.retained_until_ms,
            accepted_at_ms: intent.accepted_at_ms,
            intake_only: true,
            adoption_inferred: false,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate(intent, replay)?;
        Ok(receipt)
    }

    fn validate(
        &self,
        intent: &SenderAckIntent,
        replay: &ReplayCommitFact,
    ) -> Result<(), M6SenderAckError> {
        if self.schema != SENDER_ACK_CORRELATION_SCHEMA
            || self.source != intent.source
            || self.acknowledgement_message_digest != intent.acknowledgement_message_digest
            || self.acknowledgement_sequence != intent.acknowledgement_sequence
            || self.acknowledgement_nonce != intent.acknowledgement_nonce
            || self.acknowledgement_previous_message_digest
                != intent.acknowledgement_previous_message_digest
            || self.acknowledgement_intent_digest != intent.intent_digest
            || self.signed_manifest_bytes_digest != intent.signed_manifest_bytes_digest
            || self.raw_unit_digest != intent.raw_unit_digest
            || self.raw_record_digest != intent.raw_record_digest
            || self.disposition != intent.disposition
            || self.intake_record_digest != intent.intake_record_digest
            || self.raw_quarantine_digest != intent.raw_quarantine_digest
            || self.receiver_transaction_digest != intent.receiver_transaction_digest
            || self.replay_commit_digest != replay_commit_digest(replay)?
            || self.replay_retained_until_ms != replay.retained_until_ms
            || !self.intake_only
            || self.adoption_inferred
        {
            return Err(M6SenderAckError::Integrity(
                "sender ACK correlation receipt is missing or cross-linked".to_string(),
            ));
        }
        self.source.validate()?;
        require_digest(
            "sender ACK correlation receipt",
            &self.receipt_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderAckError> {
        digest_domain(
            ACK_CORRELATION_DOMAIN,
            &AckCorrelationDigestMaterial {
                schema: &self.schema,
                source: &self.source,
                acknowledgement_message_digest: &self.acknowledgement_message_digest,
                acknowledgement_sequence: self.acknowledgement_sequence,
                acknowledgement_nonce: &self.acknowledgement_nonce,
                acknowledgement_previous_message_digest: &self
                    .acknowledgement_previous_message_digest,
                acknowledgement_intent_digest: &self.acknowledgement_intent_digest,
                signed_manifest_bytes_digest: &self.signed_manifest_bytes_digest,
                raw_unit_digest: &self.raw_unit_digest,
                raw_record_digest: &self.raw_record_digest,
                disposition: &self.disposition,
                intake_record_digest: &self.intake_record_digest,
                raw_quarantine_digest: &self.raw_quarantine_digest,
                receiver_transaction_digest: &self.receiver_transaction_digest,
                replay_commit_digest: &self.replay_commit_digest,
                replay_retained_until_ms: self.replay_retained_until_ms,
                accepted_at_ms: self.accepted_at_ms,
                intake_only: self.intake_only,
                adoption_inferred: self.adoption_inferred,
            },
        )
    }
}

/// Content identities for every exact source carried by one portable sender
/// acknowledgement completion proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderAcknowledgementCompletionSourceDigestsV1 {
    pub sender_publication_receipt: ContentDigest,
    pub raw_acknowledgement_record: ContentDigest,
    pub raw_acknowledgement_commit: ContentDigest,
    pub raw_acknowledgement_files: ContentDigest,
    pub receiver_signed_manifest: ContentDigest,
    pub receiver_delivery_commit: ContentDigest,
    pub correlation_receipt: ContentDigest,
    pub replay_fact: ContentDigest,
    pub collection_intent: Option<ContentDigest>,
    pub route_collection_fact: Option<ContentDigest>,
    pub collection_journal: Option<ContentDigest>,
    pub collection_receipt: Option<ContentDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderAcknowledgementReplayFactSourceV1 {
    message_digest: ContentDigest,
    nonce: String,
    retained_until_ms: u64,
    route_definition_digest: ContentDigest,
    sequence: u64,
}

impl SenderAcknowledgementReplayFactSourceV1 {
    fn from_fact(fact: &ReplayCommitFact) -> Self {
        Self {
            message_digest: fact.message_digest.clone(),
            nonce: fact.nonce.clone(),
            retained_until_ms: fact.retained_until_ms,
            route_definition_digest: fact.route_definition_digest.clone(),
            sequence: fact.sequence,
        }
    }

    fn to_fact(&self) -> ReplayCommitFact {
        ReplayCommitFact {
            message_digest: self.message_digest.clone(),
            nonce: self.nonce.clone(),
            retained_until_ms: self.retained_until_ms,
            route_definition_digest: self.route_definition_digest.clone(),
            sequence: self.sequence,
        }
    }
}

/// Portable, source-bound proof of one authenticated sender-side ACK intake.
///
/// The ACK proves receiver intake disposition only. It never proves sender
/// adoption. Detached validation replays the receiver signature, route and
/// role binding, attachment-free raw-unit validation, exact source receipt
/// correlation, receiver-origin replay fact, and any completed dual-unit
/// collection. A pinned sender Ed25519 signature attests only this exact
/// content-digest set; no private signer material is serializable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderAcknowledgementCompletionEvidenceV1 {
    schema: String,
    route_definition_digest: ContentDigest,
    route_generation: u64,
    signing_key_id: String,
    sender_factory_id: String,
    receiver_factory_id: String,
    source_publication_kind: SenderPublicationKind,
    logical_operation_id: String,
    sender_message_digest: ContentDigest,
    sender_sequence: u64,
    source_receipt_digest: ContentDigest,
    acknowledgement_message_digest: ContentDigest,
    acknowledgement_sequence: u64,
    disposition: String,
    intake_record_digest: ContentDigest,
    raw_quarantine_digest: ContentDigest,
    receiver_transaction_digest: ContentDigest,
    replay_fact_digest: ContentDigest,
    replay_retained_until_ms: u64,
    correlation_receipt_digest: ContentDigest,
    intake_only: bool,
    adoption_inferred: bool,
    collection_receipt_digest: Option<ContentDigest>,
    source_digests: SenderAcknowledgementCompletionSourceDigestsV1,
    sender_publication_receipt_bytes: Vec<u8>,
    raw_acknowledgement_record_bytes: Vec<u8>,
    raw_acknowledgement_commit_bytes: Vec<u8>,
    raw_acknowledgement_files: BTreeMap<String, Vec<u8>>,
    correlation_receipt_bytes: Vec<u8>,
    replay_fact_bytes: Vec<u8>,
    collection_intent_bytes: Option<Vec<u8>>,
    route_collection_fact_bytes: Option<Vec<u8>>,
    collection_journal_files: Option<BTreeMap<String, Vec<u8>>>,
    collection_receipt_bytes: Option<Vec<u8>>,
    evidence_digest: ContentDigest,
    source_set_signature_hex: String,
}

#[derive(Serialize)]
struct SenderAcknowledgementCompletionDigestMaterial<'a> {
    schema: &'a str,
    route_definition_digest: &'a ContentDigest,
    route_generation: u64,
    signing_key_id: &'a str,
    sender_factory_id: &'a str,
    receiver_factory_id: &'a str,
    source_publication_kind: SenderPublicationKind,
    logical_operation_id: &'a str,
    sender_message_digest: &'a ContentDigest,
    sender_sequence: u64,
    source_receipt_digest: &'a ContentDigest,
    acknowledgement_message_digest: &'a ContentDigest,
    acknowledgement_sequence: u64,
    disposition: &'a str,
    intake_record_digest: &'a ContentDigest,
    raw_quarantine_digest: &'a ContentDigest,
    receiver_transaction_digest: &'a ContentDigest,
    replay_fact_digest: &'a ContentDigest,
    replay_retained_until_ms: u64,
    correlation_receipt_digest: &'a ContentDigest,
    intake_only: bool,
    adoption_inferred: bool,
    collection_receipt_digest: &'a Option<ContentDigest>,
    source_digests: &'a SenderAcknowledgementCompletionSourceDigestsV1,
}

struct SenderAcknowledgementCompletionSources {
    sender_publication_receipt_bytes: Vec<u8>,
    raw_acknowledgement_record_bytes: Vec<u8>,
    raw_acknowledgement_commit_bytes: Vec<u8>,
    raw_acknowledgement_files: BTreeMap<String, Vec<u8>>,
    correlation_receipt_bytes: Vec<u8>,
    replay_fact_bytes: Vec<u8>,
    collection_intent_bytes: Option<Vec<u8>>,
    route_collection_fact_bytes: Option<Vec<u8>>,
    collection_journal_files: Option<BTreeMap<String, Vec<u8>>>,
    collection_receipt_bytes: Option<Vec<u8>>,
}

impl SenderAcknowledgementCompletionEvidenceV1 {
    pub fn sender_publication_kind(&self) -> SenderPublicationKind {
        self.source_publication_kind
    }

    pub fn sender_message_digest(&self) -> &ContentDigest {
        &self.sender_message_digest
    }

    pub fn sender_sequence(&self) -> u64 {
        self.sender_sequence
    }

    pub fn source_receipt_digest(&self) -> &ContentDigest {
        &self.source_receipt_digest
    }

    pub fn acknowledgement_message_digest(&self) -> &ContentDigest {
        &self.acknowledgement_message_digest
    }

    pub fn acknowledgement_sequence(&self) -> u64 {
        self.acknowledgement_sequence
    }

    pub fn disposition(&self) -> &str {
        &self.disposition
    }

    pub fn intake_record_digest(&self) -> &ContentDigest {
        &self.intake_record_digest
    }

    pub fn raw_quarantine_digest(&self) -> &ContentDigest {
        &self.raw_quarantine_digest
    }

    pub fn receiver_transaction_digest(&self) -> &ContentDigest {
        &self.receiver_transaction_digest
    }

    pub fn replay_fact_digest(&self) -> &ContentDigest {
        &self.replay_fact_digest
    }

    pub fn replay_retained_until_ms(&self) -> u64 {
        self.replay_retained_until_ms
    }

    pub fn correlation_digest(&self) -> &ContentDigest {
        &self.correlation_receipt_digest
    }

    pub fn intake_only(&self) -> bool {
        self.intake_only
    }

    pub fn adoption_inferred(&self) -> bool {
        self.adoption_inferred
    }

    pub fn collection_digest(&self) -> Option<&ContentDigest> {
        self.collection_receipt_digest.as_ref()
    }

    pub fn evidence_digest(&self) -> &ContentDigest {
        &self.evidence_digest
    }

    pub fn source_digests(&self) -> &SenderAcknowledgementCompletionSourceDigestsV1 {
        &self.source_digests
    }

    pub fn canonical_bytes(
        &self,
        runtime: &M6SenderAckRuntime,
    ) -> Result<Vec<u8>, M6SenderAckError> {
        let current = runtime
            .load_acknowledgement_completion_evidence(&self.sender_message_digest)?
            .ok_or_else(|| {
                M6SenderAckError::Integrity(
                    "live sender no longer resolves this ACK completion".to_string(),
                )
            })?;
        if current != *self {
            return Err(M6SenderAckError::Integrity(
                "ACK completion differs from the live exact source set".to_string(),
            ));
        }
        self.canonical_bytes_detached(runtime.route())
    }

    pub fn canonical_bytes_detached(
        &self,
        route: &RouteDefinition,
    ) -> Result<Vec<u8>, M6SenderAckError> {
        self.validate_detached(route)?;
        let bytes = canonical_json(self)?;
        enforce_route_byte_limit(
            &bytes,
            acknowledgement_completion_byte_limit(route),
            "sender ACK completion evidence",
        )?;
        Ok(bytes)
    }

    pub fn from_canonical_bytes_detached(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6SenderAckError> {
        enforce_route_byte_limit(
            bytes,
            acknowledgement_completion_byte_limit(route),
            "sender ACK completion evidence",
        )?;
        let evidence: Self = parse_canonical(bytes)?;
        evidence.validate_detached(route)?;
        Ok(evidence)
    }

    fn from_sources(
        route: &RouteDefinition,
        signer: &crate::m6_identity::FactorySigner,
        correlation: &SenderAcknowledgementCorrelationReceipt,
        sources: SenderAcknowledgementCompletionSources,
    ) -> Result<Self, M6SenderAckError> {
        let source_digests = acknowledgement_completion_source_digests(&sources)?;
        let collection_receipt_digest = sources
            .collection_receipt_bytes
            .as_deref()
            .map(parse_canonical::<SenderCollectionReceipt>)
            .transpose()?
            .map(|receipt| receipt.receipt_digest);
        let mut evidence = Self {
            schema: SENDER_ACK_COMPLETION_EVIDENCE_SCHEMA.to_string(),
            route_definition_digest: route.definition_digest.clone(),
            route_generation: route.generation,
            signing_key_id: signer.signing_key_id().to_string(),
            sender_factory_id: route.sender.factory_id.clone(),
            receiver_factory_id: route.receiver.factory_id.clone(),
            source_publication_kind: correlation.source.publication_kind,
            logical_operation_id: correlation.source.logical_operation_id.clone(),
            sender_message_digest: correlation.source.sender_message_digest.clone(),
            sender_sequence: correlation.source.sender_sequence,
            source_receipt_digest: correlation.source.sender_receipt_digest.clone(),
            acknowledgement_message_digest: correlation.acknowledgement_message_digest.clone(),
            acknowledgement_sequence: correlation.acknowledgement_sequence,
            disposition: correlation.disposition.clone(),
            intake_record_digest: correlation.intake_record_digest.clone(),
            raw_quarantine_digest: correlation.raw_quarantine_digest.clone(),
            receiver_transaction_digest: correlation.receiver_transaction_digest.clone(),
            replay_fact_digest: correlation.replay_commit_digest.clone(),
            replay_retained_until_ms: correlation.replay_retained_until_ms,
            correlation_receipt_digest: correlation.receipt_digest.clone(),
            intake_only: correlation.intake_only,
            adoption_inferred: correlation.adoption_inferred,
            collection_receipt_digest,
            source_digests,
            sender_publication_receipt_bytes: sources.sender_publication_receipt_bytes,
            raw_acknowledgement_record_bytes: sources.raw_acknowledgement_record_bytes,
            raw_acknowledgement_commit_bytes: sources.raw_acknowledgement_commit_bytes,
            raw_acknowledgement_files: sources.raw_acknowledgement_files,
            correlation_receipt_bytes: sources.correlation_receipt_bytes,
            replay_fact_bytes: sources.replay_fact_bytes,
            collection_intent_bytes: sources.collection_intent_bytes,
            route_collection_fact_bytes: sources.route_collection_fact_bytes,
            collection_journal_files: sources.collection_journal_files,
            collection_receipt_bytes: sources.collection_receipt_bytes,
            evidence_digest: ContentDigest::from_bytes(&[]),
            source_set_signature_hex: String::new(),
        };
        evidence.evidence_digest = evidence.expected_digest()?;
        evidence.source_set_signature_hex = signer
            .sign_sender_ack_completion(route, &evidence.evidence_digest)
            .map_err(M6SenderAckError::from)?;
        evidence.validate_detached(route)?;
        Ok(evidence)
    }

    fn validate_detached(&self, route: &RouteDefinition) -> Result<(), M6SenderAckError> {
        validate_acknowledgement_completion_evidence(self, route)
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6SenderAckError> {
        digest_domain(
            ACK_COMPLETION_EVIDENCE_DOMAIN,
            &SenderAcknowledgementCompletionDigestMaterial {
                schema: &self.schema,
                route_definition_digest: &self.route_definition_digest,
                route_generation: self.route_generation,
                signing_key_id: &self.signing_key_id,
                sender_factory_id: &self.sender_factory_id,
                receiver_factory_id: &self.receiver_factory_id,
                source_publication_kind: self.source_publication_kind,
                logical_operation_id: &self.logical_operation_id,
                sender_message_digest: &self.sender_message_digest,
                sender_sequence: self.sender_sequence,
                source_receipt_digest: &self.source_receipt_digest,
                acknowledgement_message_digest: &self.acknowledgement_message_digest,
                acknowledgement_sequence: self.acknowledgement_sequence,
                disposition: &self.disposition,
                intake_record_digest: &self.intake_record_digest,
                raw_quarantine_digest: &self.raw_quarantine_digest,
                receiver_transaction_digest: &self.receiver_transaction_digest,
                replay_fact_digest: &self.replay_fact_digest,
                replay_retained_until_ms: self.replay_retained_until_ms,
                correlation_receipt_digest: &self.correlation_receipt_digest,
                intake_only: self.intake_only,
                adoption_inferred: self.adoption_inferred,
                collection_receipt_digest: &self.collection_receipt_digest,
                source_digests: &self.source_digests,
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderCollectionIntent {
    schema: String,
    sender_message_digest: ContentDigest,
    source_publication_kind: SenderPublicationKind,
    source_receipt_digest: ContentDigest,
    source_route_delivery_digest: ContentDigest,
    acknowledgement_message_digest: ContentDigest,
    acknowledgement_receipt_digest: ContentDigest,
    route_definition_digest: ContentDigest,
    route_generation: u64,
    requested_at_ms: u64,
    minimum_collect_at_ms: u64,
    source_ready_files: Vec<SenderAckRawFileObservation>,
    source_ready_snapshot_digest: ContentDigest,
    acknowledgement_ready_files: Vec<SenderAckRawFileObservation>,
    acknowledgement_ready_snapshot_digest: ContentDigest,
    intent_digest: ContentDigest,
}

impl SenderCollectionIntent {
    fn expected_digest(&self) -> Result<ContentDigest, M6SenderAckError> {
        digest_domain(
            COLLECTION_INTENT_DOMAIN,
            &(
                &self.schema,
                &self.sender_message_digest,
                self.source_publication_kind,
                &self.source_receipt_digest,
                &self.source_route_delivery_digest,
                &self.acknowledgement_message_digest,
                &self.acknowledgement_receipt_digest,
                &self.route_definition_digest,
                self.route_generation,
                self.requested_at_ms,
                self.minimum_collect_at_ms,
                &self.source_ready_files,
                &self.source_ready_snapshot_digest,
                &self.acknowledgement_ready_files,
                &self.acknowledgement_ready_snapshot_digest,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCollectionFact {
    pub schema: String,
    pub sender_message_digest: ContentDigest,
    pub source_publication_kind: SenderPublicationKind,
    pub source_receipt_digest: ContentDigest,
    pub acknowledgement_receipt_digest: ContentDigest,
    pub collection_intent_digest: ContentDigest,
    pub source_ready_files: Vec<SenderAckRawFileObservation>,
    pub source_ready_snapshot_digest: ContentDigest,
    pub acknowledgement_ready_files: Vec<SenderAckRawFileObservation>,
    pub acknowledgement_ready_snapshot_digest: ContentDigest,
    pub route_definition_digest: ContentDigest,
    pub route_generation: u64,
    pub detached_at_ms: u64,
    pub fact_digest: ContentDigest,
}

impl RouteCollectionFact {
    fn expected_digest(&self) -> Result<ContentDigest, M6SenderAckError> {
        digest_domain(
            ROUTE_COLLECTION_FACT_DOMAIN,
            &(
                &self.schema,
                &self.sender_message_digest,
                self.source_publication_kind,
                &self.source_receipt_digest,
                &self.acknowledgement_receipt_digest,
                &self.collection_intent_digest,
                &self.source_ready_files,
                &self.source_ready_snapshot_digest,
                &self.acknowledgement_ready_files,
                &self.acknowledgement_ready_snapshot_digest,
                &self.route_definition_digest,
                self.route_generation,
                self.detached_at_ms,
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderCollectionStage {
    IntentRecorded,
    RouteUnitsDetached,
    RouteCollectionFactCommitted,
    RouteBytesRemoved,
    CollectionReceiptCommitted,
}

impl SenderCollectionStage {
    const ALL: [Self; 5] = [
        Self::IntentRecorded,
        Self::RouteUnitsDetached,
        Self::RouteCollectionFactCommitted,
        Self::RouteBytesRemoved,
        Self::CollectionReceiptCommitted,
    ];

    fn ordinal(self) -> u32 {
        match self {
            Self::IntentRecorded => 1,
            Self::RouteUnitsDetached => 2,
            Self::RouteCollectionFactCommitted => 3,
            Self::RouteBytesRemoved => 4,
            Self::CollectionReceiptCommitted => 5,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::IntentRecorded => "intent-recorded",
            Self::RouteUnitsDetached => "route-units-detached",
            Self::RouteCollectionFactCommitted => "route-collection-fact-committed",
            Self::RouteBytesRemoved => "route-bytes-removed",
            Self::CollectionReceiptCommitted => "collection-receipt-committed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SenderCollectionStageRecord {
    schema: String,
    sender_message_digest: ContentDigest,
    collection_intent_digest: ContentDigest,
    stage: SenderCollectionStage,
    ordinal: u32,
    previous_stage_digest: Option<ContentDigest>,
    evidence_digests: Vec<ContentDigest>,
    recorded_at_ms: u64,
    stage_digest: ContentDigest,
}

impl SenderCollectionStageRecord {
    fn expected_digest(&self) -> Result<ContentDigest, M6SenderAckError> {
        digest_domain(
            COLLECTION_STAGE_DOMAIN,
            &(
                &self.schema,
                &self.sender_message_digest,
                &self.collection_intent_digest,
                self.stage,
                self.ordinal,
                &self.previous_stage_digest,
                &self.evidence_digests,
                self.recorded_at_ms,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SenderCollectionReceipt {
    pub schema: String,
    pub sender_message_digest: ContentDigest,
    pub source_publication_kind: SenderPublicationKind,
    pub source_receipt_digest: ContentDigest,
    pub acknowledgement_message_digest: ContentDigest,
    pub acknowledgement_receipt_digest: ContentDigest,
    pub collection_intent_digest: ContentDigest,
    pub route_collection_fact_digest: ContentDigest,
    pub source_ready_snapshot_digest: ContentDigest,
    pub acknowledgement_ready_snapshot_digest: ContentDigest,
    pub route_definition_digest: ContentDigest,
    pub route_generation: u64,
    pub minimum_collect_at_ms: u64,
    pub collected_at_ms: u64,
    pub source_receipt_retained: bool,
    pub acknowledgement_evidence_retained: bool,
    pub receipt_digest: ContentDigest,
}

impl SenderCollectionReceipt {
    fn expected_digest(&self) -> Result<ContentDigest, M6SenderAckError> {
        digest_domain(
            COLLECTION_RECEIPT_DOMAIN,
            &(
                &self.schema,
                &self.sender_message_digest,
                self.source_publication_kind,
                &self.source_receipt_digest,
                &self.acknowledgement_message_digest,
                &self.acknowledgement_receipt_digest,
                &self.collection_intent_digest,
                &self.route_collection_fact_digest,
                &self.source_ready_snapshot_digest,
                &self.acknowledgement_ready_snapshot_digest,
                &self.route_definition_digest,
                self.route_generation,
                self.minimum_collect_at_ms,
                self.collected_at_ms,
                self.source_receipt_retained,
                self.acknowledgement_evidence_retained,
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderAckCrashPoint {
    RawQuarantineCommitted,
    AckIntentCommitted,
    ControlAckIntentCommitted,
    ReplayCommitted,
    CorrelationReceiptCommitted,
    ControlAckReceiptCommitted,
    CollectionIntentCommitted,
    SourceRouteUnitDetached,
    AcknowledgementRouteUnitDetached,
    RouteUnitDetached,
    RouteCollectionFactCommitted,
    SourceRouteFileRemoved,
    SourceRouteBytesRemoved,
    AcknowledgementRouteFileRemoved,
    AcknowledgementRouteBytesRemoved,
    RouteBytesRemoved,
    CollectionReceiptCommitted,
}

pub struct M6SenderAckRuntime {
    endpoint_root: PathBuf,
    raw_root: PathBuf,
    ack_intents_root: PathBuf,
    correlations_root: PathBuf,
    control_ack_intents_root: PathBuf,
    control_ack_receipts_root: PathBuf,
    collection_intents_root: PathBuf,
    collection_journals_root: PathBuf,
    collection_receipts_root: PathBuf,
    staging_root: PathBuf,
    export_receipts_root: PathBuf,
    revocation_receipts_root: PathBuf,
    route_root: PathBuf,
    max_acknowledgements: u32,
    max_collection_records: u32,
    max_source_receipts_per_kind: u32,
    signer: crate::m6_identity::FactorySigner,
    clock: Arc<dyn Clock>,
    replay: ReplayJournal,
    spool: GovernedFilesystemSpool,
    _route_owner: crate::m6_identity::RouteRoleOwner,
    _endpoint_owner: File,
}

impl M6SenderAckRuntime {
    pub fn open(
        config: M6SenderAckRuntimeConfig,
        signer: crate::m6_identity::FactorySigner,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, M6SenderAckError> {
        config.validate_non_path_fields()?;
        let endpoint_root = secure_create_root(&config.endpoint_root)?;
        let endpoint_owner = acquire_sender_endpoint_owner(&endpoint_root)
            .map_err(|error| M6SenderAckError::Endpoint(error.to_string()))?;
        let route_root = secure_existing_root(&config.route_root)?;
        ensure_disjoint(&endpoint_root, &route_root)?;

        let spool = GovernedFilesystemSpool::open(
            &route_root,
            &endpoint_root,
            RouteEndpointRole::Sender,
            &config.expected_route_definition_digest,
        )
        .map_err(M6SenderAckError::from)?;
        config.validate_for_resource_profile(&spool.route().resource_profile)?;
        if signer.signing_key_id() != spool.route().sender.signing_key_id
            || signer.public_key_hex() != spool.route().sender.public_key_hex
        {
            return Err(M6SenderAckError::Identity(
                "sender ACK runtime signer differs from the route-pinned sender Ed25519 identity"
                    .to_string(),
            ));
        }

        let raw_root = secure_child_directory(&endpoint_root, RAW_DIRECTORY)?;
        let ack_intents_root = secure_child_directory(&endpoint_root, ACK_INTENTS_DIRECTORY)?;
        let correlations_root = secure_child_directory(&endpoint_root, CORRELATIONS_DIRECTORY)?;
        let control_ack_intents_root =
            secure_child_directory(&endpoint_root, CONTROL_ACK_INTENTS_DIRECTORY)?;
        let control_ack_receipts_root =
            secure_child_directory(&endpoint_root, CONTROL_ACK_RECEIPTS_DIRECTORY)?;
        let collection_intents_root =
            secure_child_directory(&endpoint_root, COLLECTION_INTENTS_DIRECTORY)?;
        let collection_journals_root =
            secure_child_directory(&endpoint_root, COLLECTION_JOURNALS_DIRECTORY)?;
        let collection_receipts_root =
            secure_child_directory(&endpoint_root, COLLECTION_RECEIPTS_DIRECTORY)?;
        let staging_root = secure_child_directory(&endpoint_root, STAGING_DIRECTORY)?;
        recover_staging(&staging_root)?;

        let replay = ReplayJournal::open_or_initialize(
            &endpoint_root,
            spool.route().clone(),
            RouteEndpointRole::Receiver,
            clock.clone(),
        )
        .map_err(M6SenderAckError::from)?;

        // The route-role fence is deliberately acquired after endpoint-local
        // mutable stores. The endpoint owner remains the final field released.
        let route_owner = spool.acquire_role().map_err(M6SenderAckError::from)?;

        let runtime = Self {
            raw_root,
            ack_intents_root,
            correlations_root,
            control_ack_intents_root,
            control_ack_receipts_root,
            collection_intents_root,
            collection_journals_root,
            collection_receipts_root,
            staging_root,
            export_receipts_root: endpoint_root.join(EXPORT_RECEIPTS_DIRECTORY),
            revocation_receipts_root: endpoint_root.join(REVOCATION_RECEIPTS_DIRECTORY),
            endpoint_root,
            route_root,
            max_acknowledgements: config.max_acknowledgements,
            max_collection_records: config.max_collection_records,
            max_source_receipts_per_kind: config.max_source_receipts_per_kind,
            signer,
            clock,
            replay,
            spool,
            _route_owner: route_owner,
            _endpoint_owner: endpoint_owner,
        };
        runtime.validate_stores()?;
        Ok(runtime)
    }

    pub fn endpoint_root(&self) -> &Path {
        &self.endpoint_root
    }

    pub fn route(&self) -> &RouteDefinition {
        self.spool.route()
    }

    pub fn last_acknowledgement_sequence(&self) -> u64 {
        self.replay.last_sequence()
    }

    pub fn consume_acknowledgement(
        &mut self,
        acknowledgement_message_digest: &ContentDigest,
    ) -> Result<SenderAcknowledgementCorrelationReceipt, M6SenderAckError> {
        self.consume_acknowledgement_with_fault(acknowledgement_message_digest, None)
    }

    pub fn recover_acknowledgement(
        &mut self,
        acknowledgement_message_digest: &ContentDigest,
    ) -> Result<SenderAcknowledgementCorrelationReceipt, M6SenderAckError> {
        self.consume_acknowledgement(acknowledgement_message_digest)
    }

    pub fn consume_acknowledgement_with_fault(
        &mut self,
        acknowledgement_message_digest: &ContentDigest,
        crash_at: Option<SenderAckCrashPoint>,
    ) -> Result<SenderAcknowledgementCorrelationReceipt, M6SenderAckError> {
        require_meaningful_digest(
            "receiver acknowledgement message",
            acknowledgement_message_digest,
        )?;
        let raw = self.quarantine_acknowledgement(acknowledgement_message_digest)?;
        maybe_crash(crash_at, SenderAckCrashPoint::RawQuarantineCommitted)?;

        let (manifest_bytes, manifest, payload) =
            self.parse_and_authenticate_acknowledgement(&raw)?;
        if control_ack_intent_path(&self.control_ack_intents_root, &manifest.message_digest)
            .exists()
        {
            return Err(M6SenderAckError::AcknowledgementClassificationConflict(
                manifest.message_digest,
            ));
        }
        let source = self.resolve_source_receipt(&payload.sender_message_digest)?;
        validate_ack_payload(&payload)?;
        if let Some(existing) = self.load_correlation(&payload.sender_message_digest)? {
            if existing.acknowledgement_message_digest == manifest.message_digest {
                return Ok(existing);
            }
            return Err(M6SenderAckError::Conflict {
                identity: payload.sender_message_digest.to_string(),
                existing: existing.acknowledgement_message_digest,
                requested: manifest.message_digest,
            });
        }
        let intent_path = ack_intent_path(&self.ack_intents_root, &manifest.message_digest);
        let intent = if intent_path.exists() {
            let existing: SenderAckIntent =
                load_canonical_file(&intent_path, route_record_byte_limit(self.route()))?;
            existing.validate(&manifest, &manifest_bytes, &raw, &payload, self.route())?;
            if existing.source != source {
                return Err(M6SenderAckError::Integrity(
                    "persisted sender ACK intent differs from its retained source receipt"
                        .to_string(),
                ));
            }
            validate_message_time(&manifest, self.route(), existing.accepted_at_ms)?;
            existing
        } else {
            let accepted_at_ms = self.clock.now_ms().map_err(M6SenderAckError::from)?;
            validate_message_time(&manifest, self.route(), accepted_at_ms)?;
            let requested_intent = SenderAckIntent::new(
                &manifest,
                &manifest_bytes,
                &raw,
                &payload,
                source,
                self.route(),
                accepted_at_ms,
            )?;
            enforce_combined_file_bound(
                &[&self.ack_intents_root, &self.control_ack_intents_root],
                self.max_acknowledgements,
                "combined sender ACK intents",
            )?;
            persist_immutable(
                &self.staging_root,
                &intent_path,
                &canonical_route_record(self.route(), &requested_intent)?,
            )?;
            requested_intent
        };
        maybe_crash(crash_at, SenderAckCrashPoint::AckIntentCommitted)?;

        let replay = match self
            .replay
            .resolve_exact_commit(&manifest)
            .map_err(M6SenderAckError::from)?
        {
            ReplayCommitResolution::ExactCommitted(fact) => fact,
            ReplayCommitResolution::NotCommitted { .. } => {
                self.replay
                    .verify_and_commit(&manifest)
                    .map_err(M6SenderAckError::from)?;
                exact_replay_fact(&self.replay, &manifest)?
            }
            ReplayCommitResolution::Conflicting {
                last_committed_sequence,
                observed_message_digest,
                observed_sequence,
            } => {
                return Err(M6SenderAckError::Integrity(format!(
                    "receiver ACK sequence {observed_sequence} for {observed_message_digest} conflicts with committed sequence {last_committed_sequence}"
                )));
            }
        };
        maybe_crash(crash_at, SenderAckCrashPoint::ReplayCommitted)?;

        let receipt_path = correlation_path(
            &self.correlations_root,
            &intent.source.sender_message_digest,
        );
        let requested_receipt = SenderAcknowledgementCorrelationReceipt::new(&intent, &replay)?;
        let receipt = if receipt_path.exists() {
            let existing: SenderAcknowledgementCorrelationReceipt =
                load_canonical_file(&receipt_path, route_record_byte_limit(self.route()))?;
            existing.validate(&intent, &replay)?;
            if existing != requested_receipt {
                return Err(M6SenderAckError::Conflict {
                    identity: intent.source.sender_message_digest.to_string(),
                    existing: existing.receipt_digest,
                    requested: requested_receipt.receipt_digest,
                });
            }
            existing
        } else {
            enforce_combined_file_bound(
                &[&self.correlations_root, &self.control_ack_receipts_root],
                self.max_acknowledgements,
                "combined sender ACK terminal receipts",
            )?;
            persist_immutable(
                &self.staging_root,
                &receipt_path,
                &canonical_route_record(self.route(), &requested_receipt)?,
            )?;
            requested_receipt
        };
        maybe_crash(crash_at, SenderAckCrashPoint::CorrelationReceiptCommitted)?;
        Ok(receipt)
    }

    /// Consume a receiver-signed negative terminal ACK without claiming that it
    /// correlates to a retained sender publication.
    ///
    /// Callers must select this explicit path for authentication/replay
    /// controls. Only `raw_admission_rejected` and `validation_rejected` are
    /// accepted. The ACK advances the receiver-origin replay chain and produces
    /// durable intake-only evidence, but can never be used as adoption evidence
    /// or as a source-publication correlation.
    pub fn consume_control_acknowledgement(
        &mut self,
        acknowledgement_message_digest: &ContentDigest,
    ) -> Result<SenderControlAcknowledgementReceiptV1, M6SenderAckError> {
        self.consume_control_acknowledgement_with_fault(acknowledgement_message_digest, None)
    }

    pub fn recover_control_acknowledgement(
        &mut self,
        acknowledgement_message_digest: &ContentDigest,
    ) -> Result<SenderControlAcknowledgementReceiptV1, M6SenderAckError> {
        self.consume_control_acknowledgement(acknowledgement_message_digest)
    }

    pub fn consume_control_acknowledgement_with_fault(
        &mut self,
        acknowledgement_message_digest: &ContentDigest,
        crash_at: Option<SenderAckCrashPoint>,
    ) -> Result<SenderControlAcknowledgementReceiptV1, M6SenderAckError> {
        require_meaningful_digest(
            "receiver control acknowledgement message",
            acknowledgement_message_digest,
        )?;
        let raw = self.quarantine_acknowledgement(acknowledgement_message_digest)?;
        maybe_crash(crash_at, SenderAckCrashPoint::RawQuarantineCommitted)?;

        let (manifest_bytes, manifest, payload) =
            self.parse_and_authenticate_acknowledgement(&raw)?;
        validate_control_ack_payload(&payload)?;
        if ack_intent_path(&self.ack_intents_root, &manifest.message_digest).exists() {
            return Err(M6SenderAckError::AcknowledgementClassificationConflict(
                manifest.message_digest,
            ));
        }
        if let Some(existing) = self.load_control_acknowledgement(&manifest.message_digest)? {
            return Ok(existing);
        }

        let intent_path =
            control_ack_intent_path(&self.control_ack_intents_root, &manifest.message_digest);
        let intent = if intent_path.exists() {
            let existing: SenderControlAcknowledgementIntentV1 =
                load_canonical_file(&intent_path, route_record_byte_limit(self.route()))?;
            existing.validate(&manifest, &manifest_bytes, &raw, &payload, self.route())?;
            validate_message_time(&manifest, self.route(), existing.accepted_at_ms)?;
            existing
        } else {
            let accepted_at_ms = self.clock.now_ms().map_err(M6SenderAckError::from)?;
            validate_message_time(&manifest, self.route(), accepted_at_ms)?;
            let requested = SenderControlAcknowledgementIntentV1::new(
                &manifest,
                &manifest_bytes,
                &raw,
                &payload,
                self.route(),
                accepted_at_ms,
            )?;
            enforce_combined_file_bound(
                &[&self.ack_intents_root, &self.control_ack_intents_root],
                self.max_acknowledgements,
                "combined sender ACK intents",
            )?;
            persist_immutable(
                &self.staging_root,
                &intent_path,
                &canonical_route_record(self.route(), &requested)?,
            )?;
            requested
        };
        maybe_crash(crash_at, SenderAckCrashPoint::ControlAckIntentCommitted)?;

        let replay = match self
            .replay
            .resolve_exact_commit(&manifest)
            .map_err(M6SenderAckError::from)?
        {
            ReplayCommitResolution::ExactCommitted(fact) => fact,
            ReplayCommitResolution::NotCommitted { .. } => {
                self.replay
                    .verify_and_commit(&manifest)
                    .map_err(M6SenderAckError::from)?;
                exact_replay_fact(&self.replay, &manifest)?
            }
            ReplayCommitResolution::Conflicting {
                last_committed_sequence,
                observed_message_digest,
                observed_sequence,
            } => {
                return Err(M6SenderAckError::Integrity(format!(
                    "receiver control ACK sequence {observed_sequence} for {observed_message_digest} conflicts with committed sequence {last_committed_sequence}"
                )));
            }
        };
        maybe_crash(crash_at, SenderAckCrashPoint::ReplayCommitted)?;

        let receipt_path =
            control_ack_receipt_path(&self.control_ack_receipts_root, &manifest.message_digest);
        let requested = SenderControlAcknowledgementReceiptV1::new(&intent, &replay)?;
        let receipt = if receipt_path.exists() {
            let existing: SenderControlAcknowledgementReceiptV1 =
                load_canonical_file(&receipt_path, route_record_byte_limit(self.route()))?;
            existing.validate(&intent, &replay)?;
            if existing != requested {
                return Err(M6SenderAckError::Conflict {
                    identity: manifest.message_digest.to_string(),
                    existing: existing.receipt_digest,
                    requested: requested.receipt_digest,
                });
            }
            existing
        } else {
            enforce_combined_file_bound(
                &[&self.correlations_root, &self.control_ack_receipts_root],
                self.max_acknowledgements,
                "combined sender ACK terminal receipts",
            )?;
            persist_immutable(
                &self.staging_root,
                &receipt_path,
                &canonical_route_record(self.route(), &requested)?,
            )?;
            requested
        };
        maybe_crash(crash_at, SenderAckCrashPoint::ControlAckReceiptCommitted)?;
        Ok(receipt)
    }

    pub fn load_control_acknowledgement(
        &self,
        acknowledgement_message_digest: &ContentDigest,
    ) -> Result<Option<SenderControlAcknowledgementReceiptV1>, M6SenderAckError> {
        let receipt_path = control_ack_receipt_path(
            &self.control_ack_receipts_root,
            acknowledgement_message_digest,
        );
        if !receipt_path.exists() {
            return Ok(None);
        }
        let raw = self
            .load_raw_quarantine(acknowledgement_message_digest)?
            .ok_or_else(|| {
                M6SenderAckError::Integrity(
                    "sender control ACK receipt has no retained raw quarantine".to_string(),
                )
            })?;
        let (manifest_bytes, manifest, payload) =
            self.parse_and_authenticate_acknowledgement(&raw)?;
        validate_control_ack_payload(&payload)?;
        let intent_path = control_ack_intent_path(
            &self.control_ack_intents_root,
            acknowledgement_message_digest,
        );
        let intent: SenderControlAcknowledgementIntentV1 =
            load_canonical_file(&intent_path, route_record_byte_limit(self.route()))?;
        intent.validate(&manifest, &manifest_bytes, &raw, &payload, self.route())?;
        let replay = exact_replay_fact(&self.replay, &manifest)?;
        let receipt: SenderControlAcknowledgementReceiptV1 =
            load_canonical_file(&receipt_path, route_record_byte_limit(self.route()))?;
        receipt.validate(&intent, &replay)?;
        if receipt.acknowledgement_message_digest != *acknowledgement_message_digest {
            return Err(M6SenderAckError::Integrity(
                "sender control ACK receipt is stored under another acknowledgement identity"
                    .to_string(),
            ));
        }
        Ok(Some(receipt))
    }

    pub fn load_raw_quarantine(
        &self,
        acknowledgement_message_digest: &ContentDigest,
    ) -> Result<Option<SenderAckRawQuarantineRecord>, M6SenderAckError> {
        let path = raw_unit_path(&self.raw_root, acknowledgement_message_digest);
        if !path.exists() {
            return Ok(None);
        }
        let (record, _) = load_raw_unit(&path, self.route())?;
        if record.acknowledgement_message_digest != *acknowledgement_message_digest {
            return Err(M6SenderAckError::Integrity(
                "sender ACK raw unit is stored under another acknowledgement identity".to_string(),
            ));
        }
        Ok(Some(record))
    }

    pub fn load_correlation(
        &self,
        sender_message_digest: &ContentDigest,
    ) -> Result<Option<SenderAcknowledgementCorrelationReceipt>, M6SenderAckError> {
        let path = correlation_path(&self.correlations_root, sender_message_digest);
        if !path.exists() {
            return Ok(None);
        }
        let receipt: SenderAcknowledgementCorrelationReceipt =
            load_canonical_file(&path, route_record_byte_limit(self.route()))?;
        if receipt.source.sender_message_digest != *sender_message_digest {
            return Err(M6SenderAckError::Integrity(
                "sender ACK correlation is stored under another source message".to_string(),
            ));
        }
        let intent_path = ack_intent_path(
            &self.ack_intents_root,
            &receipt.acknowledgement_message_digest,
        );
        let intent: SenderAckIntent =
            load_canonical_file(&intent_path, route_record_byte_limit(self.route()))?;
        let raw = self
            .load_raw_quarantine(&receipt.acknowledgement_message_digest)?
            .ok_or_else(|| {
                M6SenderAckError::Integrity(
                    "sender ACK correlation has no retained raw quarantine".to_string(),
                )
            })?;
        let (manifest_bytes, manifest, payload) =
            self.parse_and_authenticate_acknowledgement(&raw)?;
        intent.validate(&manifest, &manifest_bytes, &raw, &payload, self.route())?;
        let replay = exact_replay_fact(&self.replay, &manifest)?;
        receipt.validate(&intent, &replay)?;
        let source = self.resolve_source_receipt(sender_message_digest)?;
        if source != receipt.source {
            return Err(M6SenderAckError::Integrity(
                "sender ACK correlation differs from its retained source receipt".to_string(),
            ));
        }
        Ok(Some(receipt))
    }

    /// Reopen every exact durable source for one authenticated ACK and return
    /// a sender-signed proof suitable for detached M7 validation.
    pub fn load_acknowledgement_completion_evidence(
        &self,
        sender_message_digest: &ContentDigest,
    ) -> Result<Option<SenderAcknowledgementCompletionEvidenceV1>, M6SenderAckError> {
        let correlation = match self.load_correlation(sender_message_digest)? {
            Some(correlation) => correlation,
            None => return Ok(None),
        };
        let raw_root = raw_unit_path(&self.raw_root, &correlation.acknowledgement_message_digest);
        let (raw_record, raw_snapshot) = load_raw_unit(&raw_root, self.route())?;
        let raw_acknowledgement_files = raw_snapshot
            .into_iter()
            .map(|(path, bytes)| Ok((relative_path_string(&path)?, bytes)))
            .collect::<Result<BTreeMap<_, _>, M6SenderAckError>>()?;
        let (_, manifest, _) = self.parse_and_authenticate_acknowledgement(&raw_record)?;
        let replay = exact_replay_fact(&self.replay, &manifest)?;
        let replay_fact_bytes = canonical_route_record(
            self.route(),
            &SenderAcknowledgementReplayFactSourceV1::from_fact(&replay),
        )?;

        let receipt_path =
            collection_receipt_path(&self.collection_receipts_root, sender_message_digest);
        let (
            collection_intent_bytes,
            route_collection_fact_bytes,
            collection_journal_files,
            collection_receipt_bytes,
        ) = if receipt_path.exists() {
            self.load_collection_receipt(sender_message_digest)?
                .ok_or_else(|| {
                    M6SenderAckError::Integrity(
                        "collection receipt path disappeared during ACK evidence capture"
                            .to_string(),
                    )
                })?;
            let intent_path =
                collection_intent_path(&self.collection_intents_root, sender_message_digest);
            let (_, facts_root) = self.route_maintenance_roots_existing()?;
            let fact_path = route_collection_fact_path(&facts_root, sender_message_digest);
            let journal_root =
                collection_journal_root(&self.collection_journals_root, sender_message_digest);
            let mut journal = BTreeMap::new();
            for path in bounded_regular_files(&journal_root, SenderCollectionStage::ALL.len())? {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| M6SenderAckError::UnsafePath(path.clone()))?
                    .to_string();
                journal.insert(
                    name,
                    read_regular_bounded(&path, route_record_byte_limit(self.route()))?,
                );
            }
            (
                Some(read_regular_bounded(
                    &intent_path,
                    route_record_byte_limit(self.route()),
                )?),
                Some(read_regular_bounded(
                    &fact_path,
                    route_record_byte_limit(self.route()),
                )?),
                Some(journal),
                Some(read_regular_bounded(
                    &receipt_path,
                    route_record_byte_limit(self.route()),
                )?),
            )
        } else {
            (None, None, None, None)
        };

        let sources = SenderAcknowledgementCompletionSources {
            sender_publication_receipt_bytes: self
                .source_publication_receipt_bytes(&correlation.source)?,
            raw_acknowledgement_record_bytes: read_regular_bounded(
                &raw_root.join(RAW_RECORD_FILE),
                route_record_byte_limit(self.route()),
            )?,
            raw_acknowledgement_commit_bytes: read_regular_bounded(
                &raw_root.join(RAW_COMMIT_FILE),
                route_record_byte_limit(self.route()),
            )?,
            raw_acknowledgement_files,
            correlation_receipt_bytes: read_regular_bounded(
                &correlation_path(&self.correlations_root, sender_message_digest),
                route_record_byte_limit(self.route()),
            )?,
            replay_fact_bytes,
            collection_intent_bytes,
            route_collection_fact_bytes,
            collection_journal_files,
            collection_receipt_bytes,
        };
        Ok(Some(
            SenderAcknowledgementCompletionEvidenceV1::from_sources(
                self.route(),
                &self.signer,
                &correlation,
                sources,
            )?,
        ))
    }

    fn source_publication_receipt_bytes(
        &self,
        source: &SenderSourceReceiptEvidence,
    ) -> Result<Vec<u8>, M6SenderAckError> {
        let path = match source.publication_kind {
            SenderPublicationKind::Export => {
                source_receipt_path(&self.export_receipts_root, &source.logical_operation_id)
            }
            SenderPublicationKind::Revocation => revocation_source_receipt_path(
                &self.revocation_receipts_root,
                &source.logical_operation_id,
            ),
        };
        let bytes = read_regular_bounded(&path, route_record_byte_limit(self.route()))?;
        let resolved =
            source_evidence_from_receipt_bytes(source.publication_kind, &bytes, self.route())?;
        if resolved != *source {
            return Err(M6SenderAckError::Integrity(
                "source receipt bytes differ from their ACK correlation".to_string(),
            ));
        }
        Ok(bytes)
    }

    fn quarantine_acknowledgement(
        &self,
        acknowledgement_message_digest: &ContentDigest,
    ) -> Result<SenderAckRawQuarantineRecord, M6SenderAckError> {
        if let Some(existing) = self.load_raw_quarantine(acknowledgement_message_digest)? {
            return Ok(existing);
        }
        enforce_directory_bound(
            &self.raw_root,
            self.max_acknowledgements,
            RAW_SUFFIX,
            "sender ACK raw quarantine",
        )?;
        let source = self
            .spool
            .inbound_ready_unit_directory(acknowledgement_message_digest);
        let snapshot = scan_raw_route_unit(&source, self.route())?;
        let files = raw_observations(&snapshot)?;
        let observed_at_ms = self.clock.now_ms().map_err(M6SenderAckError::from)?;
        let record = SenderAckRawQuarantineRecord::new(
            acknowledgement_message_digest.clone(),
            self.route(),
            delivery_unit_name(acknowledgement_message_digest),
            observed_at_ms,
            files,
        )?;
        let destination = raw_unit_path(&self.raw_root, acknowledgement_message_digest);
        persist_raw_unit(
            &self.raw_root,
            &self.staging_root,
            &destination,
            &record,
            &snapshot,
            self.route(),
        )?;
        Ok(record)
    }

    fn parse_and_authenticate_acknowledgement(
        &self,
        raw: &SenderAckRawQuarantineRecord,
    ) -> Result<(Vec<u8>, SignedManifest, ReceiverAcknowledgementPayload), M6SenderAckError> {
        let (_, snapshot) = load_raw_unit(
            &raw_unit_path(&self.raw_root, &raw.acknowledgement_message_digest),
            self.route(),
        )?;
        let expected_paths = BTreeSet::from([
            PathBuf::from(MANIFEST_FILE),
            PathBuf::from(DELIVERY_COMMIT_FILE),
        ]);
        if snapshot.keys().cloned().collect::<BTreeSet<_>>() != expected_paths {
            return Err(M6SenderAckError::Integrity(
                "receiver acknowledgement route unit is not attachment-free".to_string(),
            ));
        }
        let manifest_bytes = snapshot
            .get(Path::new(MANIFEST_FILE))
            .cloned()
            .ok_or_else(|| {
                M6SenderAckError::Integrity(
                    "receiver acknowledgement lacks canonical manifest bytes".to_string(),
                )
            })?;
        let commit: DeliveryCommitMarker = parse_canonical(
            snapshot
                .get(Path::new(DELIVERY_COMMIT_FILE))
                .ok_or_else(|| {
                    M6SenderAckError::Integrity(
                        "receiver acknowledgement lacks its delivery commit marker".to_string(),
                    )
                })?,
        )?;
        let manifest = SignedManifest::from_canonical_bytes(&manifest_bytes)
            .map_err(M6SenderAckError::from)?;
        if commit.schema != DELIVERY_COMMIT_SCHEMA
            || commit.message_digest != manifest.message_digest
            || commit.manifest_bytes_digest != ContentDigest::from_bytes(&manifest_bytes)
            || manifest.message_digest != raw.acknowledgement_message_digest
        {
            return Err(M6SenderAckError::Integrity(
                "receiver acknowledgement commit marker or route identity is cross-linked"
                    .to_string(),
            ));
        }
        manifest
            .verify_route(self.route())
            .map_err(M6SenderAckError::from)?;
        if manifest.unsigned.kind != ManifestKind::ReceiverAcknowledgement
            || manifest.unsigned.origin_role != RouteEndpointRole::Receiver
            || !manifest.unsigned.attachments.is_empty()
        {
            return Err(M6SenderAckError::Integrity(
                "route unit is not a pinned, attachment-free receiver acknowledgement".to_string(),
            ));
        }
        let ManifestPayload::ReceiverAcknowledgement(payload) = manifest.unsigned.payload.clone()
        else {
            return Err(M6SenderAckError::Integrity(
                "receiver acknowledgement manifest carries another payload kind".to_string(),
            ));
        };
        Ok((manifest_bytes, manifest, payload))
    }

    fn resolve_source_receipt(
        &self,
        sender_message_digest: &ContentDigest,
    ) -> Result<SenderSourceReceiptEvidence, M6SenderAckError> {
        let export = find_export_receipt(
            &self.export_receipts_root,
            sender_message_digest,
            self.max_source_receipts_per_kind,
            self.route(),
        )?;
        let revocation = find_revocation_receipt(
            &self.revocation_receipts_root,
            sender_message_digest,
            self.max_source_receipts_per_kind,
            self.route(),
        )?;
        match (export, revocation) {
            (Some(_), Some(_)) => Err(M6SenderAckError::Integrity(
                "one sender message is claimed by both export and revocation receipts".to_string(),
            )),
            (Some(receipt), None) => Ok(SenderSourceReceiptEvidence {
                publication_kind: SenderPublicationKind::Export,
                logical_operation_id: receipt.logical_operation_id,
                sender_message_digest: receipt.message_digest,
                sender_sequence: receipt.sequence,
                sender_receipt_digest: receipt.receipt_digest,
                route_delivery_digest: receipt.ready_delivery_digest,
                source_committed_at_ms: receipt.committed_at_ms,
            }),
            (None, Some(receipt)) => Ok(SenderSourceReceiptEvidence {
                publication_kind: SenderPublicationKind::Revocation,
                logical_operation_id: receipt.logical_operation_id,
                sender_message_digest: receipt.message_digest,
                sender_sequence: receipt.sequence,
                sender_receipt_digest: receipt.receipt_digest,
                route_delivery_digest: receipt.route_delivery_digest,
                source_committed_at_ms: receipt.committed_at_ms,
            }),
            (None, None) => Err(M6SenderAckError::SourceReceiptNotFound(
                sender_message_digest.clone(),
            )),
        }
    }

    pub fn collect_acknowledged(
        &mut self,
        sender_message_digest: &ContentDigest,
    ) -> Result<SenderCollectionReceipt, M6SenderAckError> {
        self.collect_acknowledged_with_fault(sender_message_digest, None)
    }

    pub fn recover_collection(
        &mut self,
        sender_message_digest: &ContentDigest,
    ) -> Result<SenderCollectionReceipt, M6SenderAckError> {
        self.collect_acknowledged(sender_message_digest)
    }

    pub fn collect_acknowledged_with_fault(
        &mut self,
        sender_message_digest: &ContentDigest,
        crash_at: Option<SenderAckCrashPoint>,
    ) -> Result<SenderCollectionReceipt, M6SenderAckError> {
        require_meaningful_digest("collection sender message", sender_message_digest)?;
        let correlation = self
            .load_correlation(sender_message_digest)?
            .ok_or_else(|| {
                M6SenderAckError::AcknowledgementNotFound(sender_message_digest.clone())
            })?;

        let source_ready_path = self
            .spool
            .outbound_ready_unit_directory(sender_message_digest);
        let acknowledgement_ready_path = self
            .spool
            .inbound_ready_unit_directory(&correlation.acknowledgement_message_digest);
        if source_ready_path == acknowledgement_ready_path {
            return Err(M6SenderAckError::Integrity(
                "source and acknowledgement resolve to the same route unit".to_string(),
            ));
        }
        let raw_acknowledgement = self
            .load_raw_quarantine(&correlation.acknowledgement_message_digest)?
            .ok_or_else(|| {
                M6SenderAckError::Integrity(
                    "collection has no retained raw acknowledgement".to_string(),
                )
            })?;
        let intent_path =
            collection_intent_path(&self.collection_intents_root, sender_message_digest);
        let intent = if intent_path.exists() {
            let existing: SenderCollectionIntent =
                load_canonical_file(&intent_path, route_record_byte_limit(self.route()))?;
            validate_collection_intent(
                &existing,
                &correlation,
                &raw_acknowledgement,
                self.route(),
            )?;
            existing
        } else {
            let requested_at_ms = self.clock.now_ms().map_err(M6SenderAckError::from)?;
            let minimum_collect_at_ms = collection_minimum_time(&correlation, self.route());
            if requested_at_ms < minimum_collect_at_ms {
                return Err(M6SenderAckError::RetentionActive {
                    minimum_collect_at_ms,
                    observed_at_ms: requested_at_ms,
                });
            }

            let source_ready = self
                .spool
                .read_outbound_ready(sender_message_digest)
                .map_err(M6SenderAckError::from)?;
            validate_ready_source(&source_ready, &correlation.source, self.route())?;
            let delivery_digest =
                source_delivery_digest(&source_ready, correlation.source.publication_kind)?;
            require_digest(
                "collection source route delivery",
                &correlation.source.route_delivery_digest,
                &delivery_digest,
            )?;
            let source_ready_snapshot = scan_raw_route_unit(&source_ready_path, self.route())?;
            let source_ready_files = raw_observations(&source_ready_snapshot)?;
            let source_ready_snapshot_digest = route_snapshot_digest(&source_ready_snapshot)?;

            let acknowledgement_ready_snapshot =
                scan_raw_route_unit(&acknowledgement_ready_path, self.route())?;
            let acknowledgement_ready_files = raw_observations(&acknowledgement_ready_snapshot)?;
            if acknowledgement_ready_files != raw_acknowledgement.files {
                return Err(M6SenderAckError::Integrity(
                    "receiver ACK ready bytes differ from the retained raw quarantine".to_string(),
                ));
            }
            let acknowledgement_ready_snapshot_digest =
                route_snapshot_digest(&acknowledgement_ready_snapshot)?;

            let mut requested_intent = SenderCollectionIntent {
                schema: SENDER_COLLECTION_INTENT_SCHEMA.to_string(),
                sender_message_digest: sender_message_digest.clone(),
                source_publication_kind: correlation.source.publication_kind,
                source_receipt_digest: correlation.source.sender_receipt_digest.clone(),
                source_route_delivery_digest: correlation.source.route_delivery_digest.clone(),
                acknowledgement_message_digest: correlation.acknowledgement_message_digest.clone(),
                acknowledgement_receipt_digest: correlation.receipt_digest.clone(),
                route_definition_digest: self.route().definition_digest.clone(),
                route_generation: self.route().generation,
                requested_at_ms,
                minimum_collect_at_ms,
                source_ready_files,
                source_ready_snapshot_digest,
                acknowledgement_ready_files,
                acknowledgement_ready_snapshot_digest,
                intent_digest: ContentDigest::from_bytes(&[]),
            };
            requested_intent.intent_digest = requested_intent.expected_digest()?;
            validate_collection_intent(
                &requested_intent,
                &correlation,
                &raw_acknowledgement,
                self.route(),
            )?;
            enforce_file_bound(
                &self.collection_intents_root,
                self.max_collection_records,
                "sender collection intents",
            )?;
            persist_immutable(
                &self.staging_root,
                &intent_path,
                &canonical_route_record(self.route(), &requested_intent)?,
            )?;
            requested_intent
        };
        self.append_collection_stage(
            &intent,
            SenderCollectionStage::IntentRecorded,
            vec![
                intent.intent_digest.clone(),
                correlation.receipt_digest.clone(),
                correlation.source.sender_receipt_digest.clone(),
                intent.source_ready_snapshot_digest.clone(),
                intent.acknowledgement_ready_snapshot_digest.clone(),
            ],
        )?;
        maybe_crash(crash_at, SenderAckCrashPoint::CollectionIntentCommitted)?;

        let maintenance_lock = self.acquire_maintenance_lock()?;
        let (archive_root, facts_root) = self.route_maintenance_roots()?;
        let source_archive_path =
            archive_root.join(source_archive_unit_name(sender_message_digest));
        let acknowledgement_archive_path = archive_root.join(acknowledgement_archive_unit_name(
            &correlation.acknowledgement_message_digest,
        ));
        let fact_path = route_collection_fact_path(&facts_root, sender_message_digest);

        if fact_path.exists() {
            if source_ready_path.exists() || acknowledgement_ready_path.exists() {
                return Err(M6SenderAckError::Integrity(
                    "durable route collection fact exists while a ready unit is visible"
                        .to_string(),
                ));
            }
            validate_archive_if_present(
                &source_archive_path,
                &intent.source_ready_files,
                "detached source collection snapshot",
            )?;
            validate_archive_if_present(
                &acknowledgement_archive_path,
                &intent.acknowledgement_ready_files,
                "detached acknowledgement collection snapshot",
            )?;
        } else {
            detach_or_validate_collection_unit(
                &source_ready_path,
                &source_archive_path,
                &archive_root,
                &intent.source_ready_files,
                &intent.source_ready_snapshot_digest,
                "source",
                self.route(),
            )?;
            maybe_crash(crash_at, SenderAckCrashPoint::SourceRouteUnitDetached)?;
            detach_or_validate_collection_unit(
                &acknowledgement_ready_path,
                &acknowledgement_archive_path,
                &archive_root,
                &intent.acknowledgement_ready_files,
                &intent.acknowledgement_ready_snapshot_digest,
                "acknowledgement",
                self.route(),
            )?;
            maybe_crash(
                crash_at,
                SenderAckCrashPoint::AcknowledgementRouteUnitDetached,
            )?;
        }
        maybe_crash(crash_at, SenderAckCrashPoint::RouteUnitDetached)?;
        self.append_collection_stage(
            &intent,
            SenderCollectionStage::RouteUnitsDetached,
            vec![
                intent.intent_digest.clone(),
                intent.source_ready_snapshot_digest.clone(),
                intent.acknowledgement_ready_snapshot_digest.clone(),
                correlation.receipt_digest.clone(),
            ],
        )?;

        let fact = if fact_path.exists() {
            let existing: RouteCollectionFact =
                load_canonical_file(&fact_path, route_record_byte_limit(self.route()))?;
            validate_route_collection_fact(&existing, &intent, self.route())?;
            existing
        } else {
            if !source_archive_path.exists() || !acknowledgement_archive_path.exists() {
                return Err(M6SenderAckError::Integrity(
                    "route collection fact requires both exact detached units".to_string(),
                ));
            }
            let mut fact = RouteCollectionFact {
                schema: ROUTE_COLLECTION_FACT_SCHEMA.to_string(),
                sender_message_digest: sender_message_digest.clone(),
                source_publication_kind: intent.source_publication_kind,
                source_receipt_digest: intent.source_receipt_digest.clone(),
                acknowledgement_receipt_digest: intent.acknowledgement_receipt_digest.clone(),
                collection_intent_digest: intent.intent_digest.clone(),
                source_ready_files: intent.source_ready_files.clone(),
                source_ready_snapshot_digest: intent.source_ready_snapshot_digest.clone(),
                acknowledgement_ready_files: intent.acknowledgement_ready_files.clone(),
                acknowledgement_ready_snapshot_digest: intent
                    .acknowledgement_ready_snapshot_digest
                    .clone(),
                route_definition_digest: self.route().definition_digest.clone(),
                route_generation: self.route().generation,
                detached_at_ms: self.clock.now_ms().map_err(M6SenderAckError::from)?,
                fact_digest: ContentDigest::from_bytes(&[]),
            };
            fact.fact_digest = fact.expected_digest()?;
            validate_route_collection_fact(&fact, &intent, self.route())?;
            persist_route_immutable(&fact_path, &canonical_route_record(self.route(), &fact)?)?;
            fact
        };
        maybe_crash(crash_at, SenderAckCrashPoint::RouteCollectionFactCommitted)?;
        self.append_collection_stage(
            &intent,
            SenderCollectionStage::RouteCollectionFactCommitted,
            vec![
                intent.intent_digest.clone(),
                fact.fact_digest.clone(),
                fact.source_ready_snapshot_digest.clone(),
                fact.acknowledgement_ready_snapshot_digest.clone(),
            ],
        )?;

        remove_collection_archive_if_present(
            &archive_root,
            &source_archive_path,
            &fact.source_ready_files,
            "source",
            crash_at,
            SenderAckCrashPoint::SourceRouteFileRemoved,
        )?;
        maybe_crash(crash_at, SenderAckCrashPoint::SourceRouteBytesRemoved)?;
        remove_collection_archive_if_present(
            &archive_root,
            &acknowledgement_archive_path,
            &fact.acknowledgement_ready_files,
            "acknowledgement",
            crash_at,
            SenderAckCrashPoint::AcknowledgementRouteFileRemoved,
        )?;
        maybe_crash(
            crash_at,
            SenderAckCrashPoint::AcknowledgementRouteBytesRemoved,
        )?;
        if source_ready_path.exists()
            || source_archive_path.exists()
            || acknowledgement_ready_path.exists()
            || acknowledgement_archive_path.exists()
        {
            return Err(M6SenderAckError::Integrity(
                "source or acknowledgement route bytes remain visible after exact collection"
                    .to_string(),
            ));
        }
        maybe_crash(crash_at, SenderAckCrashPoint::RouteBytesRemoved)?;
        self.append_collection_stage(
            &intent,
            SenderCollectionStage::RouteBytesRemoved,
            vec![
                fact.fact_digest.clone(),
                fact.source_ready_snapshot_digest.clone(),
                fact.acknowledgement_ready_snapshot_digest.clone(),
                correlation.receipt_digest.clone(),
            ],
        )?;

        // Resolve both local evidence families again after the route mutation.
        // Their continued presence is part of the collection receipt.
        let retained_correlation =
            self.load_correlation(sender_message_digest)?
                .ok_or_else(|| {
                    M6SenderAckError::Integrity(
                        "collection removed acknowledgement correlation evidence".to_string(),
                    )
                })?;
        let retained_source = self.resolve_source_receipt(sender_message_digest)?;
        if retained_correlation != correlation || retained_source != correlation.source {
            return Err(M6SenderAckError::Integrity(
                "collection changed retained source or acknowledgement evidence".to_string(),
            ));
        }

        let mut receipt = SenderCollectionReceipt {
            schema: SENDER_COLLECTION_RECEIPT_SCHEMA.to_string(),
            sender_message_digest: sender_message_digest.clone(),
            source_publication_kind: intent.source_publication_kind,
            source_receipt_digest: intent.source_receipt_digest.clone(),
            acknowledgement_message_digest: intent.acknowledgement_message_digest.clone(),
            acknowledgement_receipt_digest: intent.acknowledgement_receipt_digest.clone(),
            collection_intent_digest: intent.intent_digest.clone(),
            route_collection_fact_digest: fact.fact_digest.clone(),
            source_ready_snapshot_digest: intent.source_ready_snapshot_digest.clone(),
            acknowledgement_ready_snapshot_digest: intent
                .acknowledgement_ready_snapshot_digest
                .clone(),
            route_definition_digest: intent.route_definition_digest.clone(),
            route_generation: intent.route_generation,
            minimum_collect_at_ms: intent.minimum_collect_at_ms,
            collected_at_ms: fact.detached_at_ms,
            source_receipt_retained: true,
            acknowledgement_evidence_retained: true,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        validate_collection_receipt(&receipt, &intent, &fact, &correlation)?;
        let receipt_path =
            collection_receipt_path(&self.collection_receipts_root, sender_message_digest);
        if !receipt_path.exists() {
            enforce_file_bound(
                &self.collection_receipts_root,
                self.max_collection_records,
                "sender collection receipts",
            )?;
        }
        persist_immutable(
            &self.staging_root,
            &receipt_path,
            &canonical_route_record(self.route(), &receipt)?,
        )?;
        maybe_crash(crash_at, SenderAckCrashPoint::CollectionReceiptCommitted)?;
        self.append_collection_stage(
            &intent,
            SenderCollectionStage::CollectionReceiptCommitted,
            vec![
                receipt.receipt_digest.clone(),
                fact.fact_digest.clone(),
                correlation.receipt_digest.clone(),
                correlation.source.sender_receipt_digest.clone(),
            ],
        )?;
        drop(maintenance_lock);
        Ok(receipt)
    }

    pub fn load_collection_receipt(
        &self,
        sender_message_digest: &ContentDigest,
    ) -> Result<Option<SenderCollectionReceipt>, M6SenderAckError> {
        let path = collection_receipt_path(&self.collection_receipts_root, sender_message_digest);
        if !path.exists() {
            return Ok(None);
        }
        let receipt: SenderCollectionReceipt =
            load_canonical_file(&path, route_record_byte_limit(self.route()))?;
        if receipt.sender_message_digest != *sender_message_digest {
            return Err(M6SenderAckError::Integrity(
                "collection receipt is stored under another sender message".to_string(),
            ));
        }
        let intent: SenderCollectionIntent = load_canonical_file(
            &collection_intent_path(&self.collection_intents_root, sender_message_digest),
            route_record_byte_limit(self.route()),
        )?;
        let correlation = self
            .load_correlation(sender_message_digest)?
            .ok_or_else(|| {
                M6SenderAckError::Integrity(
                    "collection receipt has no retained ACK correlation".to_string(),
                )
            })?;
        let raw_acknowledgement = self
            .load_raw_quarantine(&correlation.acknowledgement_message_digest)?
            .ok_or_else(|| {
                M6SenderAckError::Integrity(
                    "collection receipt has no retained raw ACK".to_string(),
                )
            })?;
        validate_collection_intent(&intent, &correlation, &raw_acknowledgement, self.route())?;
        let (archive_root, facts_root) = self.route_maintenance_roots_existing()?;
        let fact: RouteCollectionFact = load_canonical_file(
            &route_collection_fact_path(&facts_root, sender_message_digest),
            route_record_byte_limit(self.route()),
        )?;
        validate_route_collection_fact(&fact, &intent, self.route())?;
        validate_collection_receipt(&receipt, &intent, &fact, &correlation)?;
        let source_ready_path = self
            .spool
            .outbound_ready_unit_directory(sender_message_digest);
        let acknowledgement_ready_path = self
            .spool
            .inbound_ready_unit_directory(&correlation.acknowledgement_message_digest);
        let source_archive_path =
            archive_root.join(source_archive_unit_name(sender_message_digest));
        let acknowledgement_archive_path = archive_root.join(acknowledgement_archive_unit_name(
            &correlation.acknowledgement_message_digest,
        ));
        if source_ready_path.exists()
            || source_archive_path.exists()
            || acknowledgement_ready_path.exists()
            || acknowledgement_archive_path.exists()
        {
            return Err(M6SenderAckError::Integrity(
                "collection receipt exists while collected route bytes remain".to_string(),
            ));
        }
        let stages = self.collection_stages(&intent)?;
        if stages.last().map(|stage| stage.stage)
            != Some(SenderCollectionStage::CollectionReceiptCommitted)
        {
            return Err(M6SenderAckError::Integrity(
                "collection receipt has no complete append-only journal".to_string(),
            ));
        }
        Ok(Some(receipt))
    }

    fn append_collection_stage(
        &self,
        intent: &SenderCollectionIntent,
        stage: SenderCollectionStage,
        mut evidence_digests: Vec<ContentDigest>,
    ) -> Result<SenderCollectionStageRecord, M6SenderAckError> {
        evidence_digests.sort();
        evidence_digests.dedup();
        if evidence_digests.is_empty() {
            return Err(M6SenderAckError::Integrity(
                "collection stage has no immutable evidence".to_string(),
            ));
        }
        let existing = self.collection_stages(intent)?;
        if let Some(found) = existing.iter().find(|record| record.stage == stage) {
            if found.ordinal != stage.ordinal()
                || found.collection_intent_digest != intent.intent_digest
                || found.evidence_digests != evidence_digests
            {
                return Err(M6SenderAckError::Integrity(
                    "existing collection stage differs from exact retry".to_string(),
                ));
            }
            return Ok(found.clone());
        }
        if existing.len() + 1 != stage.ordinal() as usize {
            return Err(M6SenderAckError::Integrity(format!(
                "collection stage {:?} would skip a durable predecessor",
                stage
            )));
        }
        let previous = existing.last();
        let recorded_at_ms = self.clock.now_ms().map_err(M6SenderAckError::from)?;
        if previous.is_some_and(|record| recorded_at_ms < record.recorded_at_ms) {
            return Err(M6SenderAckError::Integrity(
                "collection journal clock moved backwards".to_string(),
            ));
        }
        let mut record = SenderCollectionStageRecord {
            schema: SENDER_COLLECTION_STAGE_SCHEMA.to_string(),
            sender_message_digest: intent.sender_message_digest.clone(),
            collection_intent_digest: intent.intent_digest.clone(),
            stage,
            ordinal: stage.ordinal(),
            previous_stage_digest: previous.map(|record| record.stage_digest.clone()),
            evidence_digests,
            recorded_at_ms,
            stage_digest: ContentDigest::from_bytes(&[]),
        };
        record.stage_digest = record.expected_digest()?;
        validate_collection_stage_record(&record, intent, previous)?;
        let root = collection_journal_root(
            &self.collection_journals_root,
            &intent.sender_message_digest,
        );
        if !root.exists() {
            enforce_directory_bound(
                &self.collection_journals_root,
                self.max_collection_records,
                ".journal",
                "sender collection journals",
            )?;
            create_direct_child(&self.collection_journals_root, &root)?;
        }
        let path = root.join(format!("{:04}-{}.json", record.ordinal, stage.label()));
        persist_immutable(
            &self.staging_root,
            &path,
            &canonical_route_record(self.route(), &record)?,
        )?;
        Ok(record)
    }

    fn collection_stages(
        &self,
        intent: &SenderCollectionIntent,
    ) -> Result<Vec<SenderCollectionStageRecord>, M6SenderAckError> {
        let root = collection_journal_root(
            &self.collection_journals_root,
            &intent.sender_message_digest,
        );
        if !root.exists() {
            return Ok(Vec::new());
        }
        ensure_real_directory(&root)?;
        let paths = bounded_regular_files(&root, SenderCollectionStage::ALL.len())?;
        let mut records = Vec::with_capacity(paths.len());
        for path in paths {
            let record: SenderCollectionStageRecord =
                load_canonical_file(&path, route_record_byte_limit(self.route()))?;
            let previous = records.last();
            validate_collection_stage_record(&record, intent, previous)?;
            let expected_name = format!("{:04}-{}.json", record.ordinal, record.stage.label());
            if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
                return Err(M6SenderAckError::Integrity(
                    "collection stage is stored under a non-canonical name".to_string(),
                ));
            }
            records.push(record);
        }
        Ok(records)
    }

    fn acquire_maintenance_lock(&self) -> Result<File, M6SenderAckError> {
        let locks = self
            .route_root
            .join(format!("generation-{}", self.route().generation))
            .join(ROUTE_LOCKS_DIRECTORY);
        ensure_real_directory(&locks)?;
        let path = locks.join(ROUTE_MAINTENANCE_LOCK_FILE);
        reject_symlink_if_present(&path)?;
        let existed = path.exists();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|source| M6SenderAckError::io(&path, source))?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => M6SenderAckError::MaintenanceAlreadyOwned,
            std::fs::TryLockError::Error(source) => M6SenderAckError::io(&path, source),
        })?;
        if !existed {
            sync_directory(&locks)?;
        }
        Ok(file)
    }

    fn route_maintenance_roots(&self) -> Result<(PathBuf, PathBuf), M6SenderAckError> {
        let generation = self
            .route_root
            .join(format!("generation-{}", self.route().generation));
        ensure_real_directory(&generation)?;
        let archive = secure_child_directory(&generation, ROUTE_COLLECTION_ARCHIVE_DIRECTORY)?;
        let facts = secure_child_directory(&generation, ROUTE_COLLECTION_FACTS_DIRECTORY)?;
        Ok((archive, facts))
    }

    fn route_maintenance_roots_existing(&self) -> Result<(PathBuf, PathBuf), M6SenderAckError> {
        let generation = self
            .route_root
            .join(format!("generation-{}", self.route().generation));
        let archive = generation.join(ROUTE_COLLECTION_ARCHIVE_DIRECTORY);
        let facts = generation.join(ROUTE_COLLECTION_FACTS_DIRECTORY);
        ensure_real_directory(&archive)?;
        ensure_real_directory(&facts)?;
        Ok((archive, facts))
    }

    fn validate_stores(&self) -> Result<(), M6SenderAckError> {
        let raw_paths = bounded_directories(
            &self.raw_root,
            self.max_acknowledgements as usize,
            RAW_SUFFIX,
        )?;
        for path in raw_paths {
            let (record, _) = load_raw_unit(&path, self.route())?;
            if path != raw_unit_path(&self.raw_root, &record.acknowledgement_message_digest) {
                return Err(M6SenderAckError::Integrity(
                    "raw ACK unit is stored under a non-canonical path".to_string(),
                ));
            }
        }
        let ack_intent_paths =
            bounded_regular_files(&self.ack_intents_root, self.max_acknowledgements as usize)?;
        let control_ack_intent_paths = bounded_regular_files(
            &self.control_ack_intents_root,
            self.max_acknowledgements as usize,
        )?;
        if ack_intent_paths.len() + control_ack_intent_paths.len()
            > self.max_acknowledgements as usize
        {
            return Err(M6SenderAckError::ResourceExhausted(
                "combined sender ACK intents exceed the immutable route bound".to_string(),
            ));
        }
        let correlated_intent_names = ack_intent_paths
            .iter()
            .filter_map(|path| path.file_name())
            .map(|name| name.to_os_string())
            .collect::<BTreeSet<_>>();
        if control_ack_intent_paths
            .iter()
            .filter_map(|path| path.file_name())
            .any(|name| correlated_intent_names.contains(name))
        {
            return Err(M6SenderAckError::Integrity(
                "one receiver ACK has both correlated and control-only intake intents".to_string(),
            ));
        }
        for path in ack_intent_paths {
            let intent: SenderAckIntent =
                load_canonical_file(&path, route_record_byte_limit(self.route()))?;
            require_digest(
                "stored sender ACK intent",
                &intent.intent_digest,
                &intent.expected_digest()?,
            )?;
            if path
                != ack_intent_path(
                    &self.ack_intents_root,
                    &intent.acknowledgement_message_digest,
                )
            {
                return Err(M6SenderAckError::Integrity(
                    "sender ACK intent is stored under a non-canonical path".to_string(),
                ));
            }
        }
        for path in control_ack_intent_paths {
            let intent: SenderControlAcknowledgementIntentV1 =
                load_canonical_file(&path, route_record_byte_limit(self.route()))?;
            require_digest(
                "stored sender control ACK intent",
                &intent.intent_digest,
                &intent.expected_digest()?,
            )?;
            if path
                != control_ack_intent_path(
                    &self.control_ack_intents_root,
                    &intent.acknowledgement_message_digest,
                )
            {
                return Err(M6SenderAckError::Integrity(
                    "sender control ACK intent is stored under a non-canonical path".to_string(),
                ));
            }
        }
        let correlation_paths =
            bounded_regular_files(&self.correlations_root, self.max_acknowledgements as usize)?;
        let control_ack_receipt_paths = bounded_regular_files(
            &self.control_ack_receipts_root,
            self.max_acknowledgements as usize,
        )?;
        if correlation_paths.len() + control_ack_receipt_paths.len()
            > self.max_acknowledgements as usize
        {
            return Err(M6SenderAckError::ResourceExhausted(
                "combined sender ACK terminal receipts exceed the immutable route bound"
                    .to_string(),
            ));
        }
        for path in correlation_paths {
            let receipt: SenderAcknowledgementCorrelationReceipt =
                load_canonical_file(&path, route_record_byte_limit(self.route()))?;
            require_digest(
                "stored sender ACK correlation",
                &receipt.receipt_digest,
                &receipt.expected_digest()?,
            )?;
            if path
                != correlation_path(
                    &self.correlations_root,
                    &receipt.source.sender_message_digest,
                )
            {
                return Err(M6SenderAckError::Integrity(
                    "sender ACK correlation is stored under a non-canonical path".to_string(),
                ));
            }
        }
        for path in control_ack_receipt_paths {
            let receipt: SenderControlAcknowledgementReceiptV1 =
                load_canonical_file(&path, route_record_byte_limit(self.route()))?;
            require_digest(
                "stored sender control ACK receipt",
                &receipt.receipt_digest,
                &receipt.expected_digest()?,
            )?;
            if path
                != control_ack_receipt_path(
                    &self.control_ack_receipts_root,
                    &receipt.acknowledgement_message_digest,
                )
            {
                return Err(M6SenderAckError::Integrity(
                    "sender control ACK receipt is stored under a non-canonical path".to_string(),
                ));
            }
        }
        for path in bounded_regular_files(
            &self.collection_intents_root,
            self.max_collection_records as usize,
        )? {
            let intent: SenderCollectionIntent =
                load_canonical_file(&path, route_record_byte_limit(self.route()))?;
            require_digest(
                "stored sender collection intent",
                &intent.intent_digest,
                &intent.expected_digest()?,
            )?;
            if path
                != collection_intent_path(
                    &self.collection_intents_root,
                    &intent.sender_message_digest,
                )
            {
                return Err(M6SenderAckError::Integrity(
                    "sender collection intent is stored under a non-canonical path".to_string(),
                ));
            }
            self.collection_stages(&intent)?;
        }
        for path in bounded_regular_files(
            &self.collection_receipts_root,
            self.max_collection_records as usize,
        )? {
            let receipt: SenderCollectionReceipt =
                load_canonical_file(&path, route_record_byte_limit(self.route()))?;
            require_digest(
                "stored sender collection receipt",
                &receipt.receipt_digest,
                &receipt.expected_digest()?,
            )?;
            if path
                != collection_receipt_path(
                    &self.collection_receipts_root,
                    &receipt.sender_message_digest,
                )
            {
                return Err(M6SenderAckError::Integrity(
                    "sender collection receipt is stored under a non-canonical path".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum M6SenderAckError {
    InvalidConfiguration(String),
    SourceReceiptNotFound(ContentDigest),
    AcknowledgementNotFound(ContentDigest),
    AcknowledgementClassificationConflict(ContentDigest),
    RetentionActive {
        minimum_collect_at_ms: u64,
        observed_at_ms: u64,
    },
    Conflict {
        identity: String,
        existing: ContentDigest,
        requested: ContentDigest,
    },
    MaintenanceAlreadyOwned,
    InjectedCrash(SenderAckCrashPoint),
    Endpoint(String),
    Identity(String),
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

impl M6SenderAckError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl Display for M6SenderAckError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid sender ACK configuration: {message}")
            }
            Self::SourceReceiptNotFound(digest) => {
                write!(formatter, "no retained sender receipt exists for {digest}")
            }
            Self::AcknowledgementNotFound(digest) => {
                write!(
                    formatter,
                    "no authenticated receiver ACK exists for {digest}"
                )
            }
            Self::AcknowledgementClassificationConflict(digest) => write!(
                formatter,
                "receiver ACK {digest} already has the opposite sender intake classification"
            ),
            Self::RetentionActive {
                minimum_collect_at_ms,
                observed_at_ms,
            } => write!(
                formatter,
                "route retention remains active until {minimum_collect_at_ms}; observed {observed_at_ms}"
            ),
            Self::Conflict {
                identity,
                existing,
                requested,
            } => write!(
                formatter,
                "sender ACK identity '{identity}' is bound to {existing}, not {requested}"
            ),
            Self::MaintenanceAlreadyOwned => {
                formatter.write_str("route maintenance already has a live owner")
            }
            Self::InjectedCrash(point) => {
                write!(formatter, "injected sender ACK crash at {point:?}")
            }
            Self::Endpoint(message) => {
                write!(formatter, "sender endpoint ownership failed: {message}")
            }
            Self::Identity(message) => write!(formatter, "sender ACK identity failed: {message}"),
            Self::Integrity(message) => {
                write!(formatter, "sender ACK integrity failure: {message}")
            }
            Self::ResourceExhausted(message) => {
                write!(formatter, "sender ACK resource exhausted: {message}")
            }
            Self::UnsafePath(path) => {
                write!(formatter, "unsafe sender ACK path '{}'", path.display())
            }
            Self::ImmutableConflict(path) => write!(
                formatter,
                "immutable sender ACK record '{}' conflicts",
                path.display()
            ),
            Self::Serialization(message) => {
                write!(formatter, "sender ACK serialization failed: {message}")
            }
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "sender ACK I/O at '{}': {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for M6SenderAckError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<M6IdentityError> for M6SenderAckError {
    fn from(error: M6IdentityError) -> Self {
        Self::Identity(error.to_string())
    }
}

fn maybe_crash(
    configured: Option<SenderAckCrashPoint>,
    current: SenderAckCrashPoint,
) -> Result<(), M6SenderAckError> {
    if configured == Some(current) {
        Err(M6SenderAckError::InjectedCrash(current))
    } else {
        Ok(())
    }
}

fn exact_replay_fact(
    replay: &ReplayJournal,
    manifest: &SignedManifest,
) -> Result<ReplayCommitFact, M6SenderAckError> {
    match replay
        .resolve_exact_commit(manifest)
        .map_err(M6SenderAckError::from)?
    {
        ReplayCommitResolution::ExactCommitted(fact) => Ok(fact),
        ReplayCommitResolution::NotCommitted { .. }
        | ReplayCommitResolution::Conflicting { .. } => Err(M6SenderAckError::Integrity(
            "receiver ACK has no exact durable replay-chain fact".to_string(),
        )),
    }
}

fn replay_commit_digest(fact: &ReplayCommitFact) -> Result<ContentDigest, M6SenderAckError> {
    digest_domain(
        ACK_REPLAY_FACT_DOMAIN,
        &(
            &fact.message_digest,
            &fact.nonce,
            fact.retained_until_ms,
            &fact.route_definition_digest,
            fact.sequence,
        ),
    )
}

fn validate_message_time(
    manifest: &SignedManifest,
    route: &RouteDefinition,
    observed_at_ms: u64,
) -> Result<(), M6SenderAckError> {
    if manifest.unsigned.issued_at_ms
        > observed_at_ms.saturating_add(route.resource_profile.accepted_clock_skew_ms)
    {
        return Err(M6SenderAckError::Identity(
            M6IdentityError::FutureMessage {
                now_ms: observed_at_ms,
                issued_at_ms: manifest.unsigned.issued_at_ms,
            }
            .to_string(),
        ));
    }
    if observed_at_ms > manifest.unsigned.expires_at_ms {
        return Err(M6SenderAckError::Identity(
            M6IdentityError::Expired {
                now_ms: observed_at_ms,
                expires_at_ms: manifest.unsigned.expires_at_ms,
            }
            .to_string(),
        ));
    }
    Ok(())
}

fn validate_ack_payload(payload: &ReceiverAcknowledgementPayload) -> Result<(), M6SenderAckError> {
    const TERMINAL_DISPOSITIONS: &[&str] = &[
        "raw_admission_rejected",
        "validation_rejected",
        "denied",
        "expired",
        "escalated",
        "healthy",
        "rolled_back",
        "containment_required",
        "revocation_contained",
        "revocation_containment_required",
    ];
    if !TERMINAL_DISPOSITIONS.contains(&payload.disposition.as_str()) {
        return Err(M6SenderAckError::Integrity(format!(
            "receiver ACK disposition '{}' is not a bounded terminal intake disposition",
            payload.disposition
        )));
    }
    require_meaningful_digest("ACK sender message", &payload.sender_message_digest)?;
    require_meaningful_digest("ACK intake record", &payload.intake_record_digest)?;
    require_meaningful_digest("ACK raw quarantine", &payload.raw_quarantine_digest)?;
    require_meaningful_digest(
        "ACK receiver transaction",
        &payload.receiver_transaction_digest,
    )
}

fn validate_control_ack_payload(
    payload: &ReceiverAcknowledgementPayload,
) -> Result<(), M6SenderAckError> {
    validate_ack_payload(payload)?;
    if !matches!(
        payload.disposition.as_str(),
        "raw_admission_rejected" | "validation_rejected"
    ) {
        return Err(M6SenderAckError::Integrity(format!(
            "receiver control ACK disposition '{}' is not a bounded rejection disposition",
            payload.disposition
        )));
    }
    Ok(())
}

fn find_export_receipt(
    root: &Path,
    sender_message_digest: &ContentDigest,
    maximum: u32,
    route: &RouteDefinition,
) -> Result<Option<SenderExportReceipt>, M6SenderAckError> {
    if !root.exists() {
        return Ok(None);
    }
    ensure_real_directory(root)?;
    let mut found = None;
    for path in bounded_regular_files(root, maximum as usize)? {
        let bytes = read_regular_bounded(&path, route_record_byte_limit(route))?;
        let receipt: SenderExportReceipt = parse_struct_canonical(&bytes)?;
        validate_export_receipt(&receipt, route)?;
        if path != source_receipt_path(root, &receipt.logical_operation_id) {
            return Err(M6SenderAckError::Integrity(
                "sender export receipt is stored under a non-canonical path".to_string(),
            ));
        }
        if receipt.message_digest == *sender_message_digest && found.replace(receipt).is_some() {
            return Err(M6SenderAckError::Integrity(
                "multiple sender export receipts claim one message".to_string(),
            ));
        }
    }
    Ok(found)
}

fn find_revocation_receipt(
    root: &Path,
    sender_message_digest: &ContentDigest,
    maximum: u32,
    route: &RouteDefinition,
) -> Result<Option<SenderRevocationReceipt>, M6SenderAckError> {
    if !root.exists() {
        return Ok(None);
    }
    ensure_real_directory(root)?;
    let mut found = None;
    for path in bounded_regular_files(root, maximum as usize)? {
        let receipt: SenderRevocationReceipt =
            load_canonical_file(&path, route_record_byte_limit(route))?;
        validate_revocation_receipt(&receipt, route)?;
        if path != revocation_source_receipt_path(root, &receipt.logical_operation_id) {
            return Err(M6SenderAckError::Integrity(
                "sender revocation receipt is stored under a non-canonical path".to_string(),
            ));
        }
        if receipt.message_digest == *sender_message_digest && found.replace(receipt).is_some() {
            return Err(M6SenderAckError::Integrity(
                "multiple sender revocation receipts claim one message".to_string(),
            ));
        }
    }
    Ok(found)
}

fn validate_export_receipt(
    receipt: &SenderExportReceipt,
    route: &RouteDefinition,
) -> Result<(), M6SenderAckError> {
    validate_identifier(
        "sender export receipt logical operation",
        &receipt.logical_operation_id,
    )?;
    if receipt.schema != SENDER_EXPORT_RECEIPT_SCHEMA
        || receipt.route_definition_digest != route.definition_digest
        || receipt.route_id != route.route_id
        || receipt.route_generation != route.generation
        || receipt.sequence == 0
    {
        return Err(M6SenderAckError::Integrity(
            "sender export receipt is outside the ACK route".to_string(),
        ));
    }
    require_digest(
        "sender export receipt",
        &receipt.receipt_digest,
        &digest_domain(
            EXPORT_RECEIPT_DOMAIN,
            &(
                &receipt.schema,
                &receipt.logical_operation_id,
                &receipt.outer_request_digest,
                &receipt.coordinator_request_digest,
                &receipt.route_definition_digest,
                &receipt.route_id,
                receipt.route_generation,
                &receipt.message_digest,
                receipt.sequence,
                &receipt.bundle_digest,
                &receipt.package_digest,
                &receipt.active_snapshot_digest,
                &receipt.authorization_digest,
                &receipt.authorization_consumption_digest,
                &receipt.ready_delivery_digest,
                receipt.committed_at_ms,
            ),
        )?,
    )
}

#[derive(Serialize)]
struct RevocationReceiptDigestMaterial<'a> {
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

fn validate_revocation_receipt(
    receipt: &SenderRevocationReceipt,
    route: &RouteDefinition,
) -> Result<(), M6SenderAckError> {
    validate_identifier(
        "sender revocation receipt logical operation",
        &receipt.logical_operation_id,
    )?;
    if receipt.schema != SENDER_REVOCATION_RECEIPT_SCHEMA
        || receipt.route_definition_digest != route.definition_digest
        || receipt.route_generation != route.generation
        || receipt.sender_identity_document_digest != route.sender.identity_document_digest
        || receipt.receiver_identity_document_digest != route.receiver.identity_document_digest
        || receipt.sequence == 0
        || receipt.reason.is_empty()
        || receipt.reason.len() > 4_096
    {
        return Err(M6SenderAckError::Integrity(
            "sender revocation receipt is outside the ACK route".to_string(),
        ));
    }
    require_digest(
        "sender revocation receipt",
        &receipt.receipt_digest,
        &digest_domain(
            REVOCATION_RECEIPT_DOMAIN,
            &RevocationReceiptDigestMaterial {
                schema: &receipt.schema,
                logical_operation_id: &receipt.logical_operation_id,
                request_digest: &receipt.request_digest,
                coordinator_request_digest: &receipt.coordinator_request_digest,
                route_definition_digest: &receipt.route_definition_digest,
                route_generation: receipt.route_generation,
                sender_identity_document_digest: &receipt.sender_identity_document_digest,
                receiver_identity_document_digest: &receipt.receiver_identity_document_digest,
                target_kind: receipt.target_kind,
                target_identity: &receipt.target_identity,
                reason: &receipt.reason,
                prior_source_authorization_evidence_digest: &receipt
                    .prior_source_authorization_evidence_digest,
                message_digest: &receipt.message_digest,
                sequence: receipt.sequence,
                nonce: &receipt.nonce,
                previous_message_digest: &receipt.previous_message_digest,
                current_revocation_authorization_digest: &receipt
                    .current_revocation_authorization_digest,
                current_revocation_binding_digest: &receipt.current_revocation_binding_digest,
                authorization_consumption_digest: &receipt.authorization_consumption_digest,
                route_delivery_digest: &receipt.route_delivery_digest,
                committed_at_ms: receipt.committed_at_ms,
            },
        )?,
    )
}

fn source_evidence_from_receipt_bytes(
    kind: SenderPublicationKind,
    bytes: &[u8],
    route: &RouteDefinition,
) -> Result<SenderSourceReceiptEvidence, M6SenderAckError> {
    match kind {
        SenderPublicationKind::Export => {
            let receipt: SenderExportReceipt = parse_struct_canonical(bytes)?;
            validate_export_receipt(&receipt, route)?;
            Ok(SenderSourceReceiptEvidence {
                publication_kind: SenderPublicationKind::Export,
                logical_operation_id: receipt.logical_operation_id,
                sender_message_digest: receipt.message_digest,
                sender_sequence: receipt.sequence,
                sender_receipt_digest: receipt.receipt_digest,
                route_delivery_digest: receipt.ready_delivery_digest,
                source_committed_at_ms: receipt.committed_at_ms,
            })
        }
        SenderPublicationKind::Revocation => {
            let receipt: SenderRevocationReceipt = parse_canonical(bytes)?;
            validate_revocation_receipt(&receipt, route)?;
            Ok(SenderSourceReceiptEvidence {
                publication_kind: SenderPublicationKind::Revocation,
                logical_operation_id: receipt.logical_operation_id,
                sender_message_digest: receipt.message_digest,
                sender_sequence: receipt.sequence,
                sender_receipt_digest: receipt.receipt_digest,
                route_delivery_digest: receipt.route_delivery_digest,
                source_committed_at_ms: receipt.committed_at_ms,
            })
        }
    }
}

fn validate_ready_source(
    ready: &IssuedManifest,
    source: &SenderSourceReceiptEvidence,
    route: &RouteDefinition,
) -> Result<(), M6SenderAckError> {
    ready
        .manifest
        .verify_route(route)
        .map_err(M6SenderAckError::from)?;
    if ready.manifest.message_digest != source.sender_message_digest
        || ready.manifest.unsigned.sequence != source.sender_sequence
        || ready.manifest.unsigned.origin_role != RouteEndpointRole::Sender
    {
        return Err(M6SenderAckError::Integrity(
            "ready source unit differs from its retained sender receipt".to_string(),
        ));
    }
    match (source.publication_kind, &ready.manifest.unsigned.payload) {
        (SenderPublicationKind::Export, ManifestPayload::Export(payload)) => {
            require_meaningful_digest("ready export bundle", &payload.export_bundle_digest)?;
            require_meaningful_digest("ready export package", &payload.package_digest)?;
        }
        (SenderPublicationKind::Revocation, ManifestPayload::Revocation(payload)) => {
            RevocationTargetKindV1::parse(&payload.target_kind)
                .map_err(|error| M6SenderAckError::Integrity(error.to_string()))?;
            require_meaningful_digest("ready revocation target", &payload.target_identity)?;
            require_meaningful_digest(
                "ready revocation source authority",
                &payload.authorization_digest,
            )?;
        }
        _ => {
            return Err(M6SenderAckError::Integrity(
                "ready source manifest kind differs from its receipt family".to_string(),
            ));
        }
    }
    Ok(())
}

fn source_delivery_digest(
    issued: &IssuedManifest,
    kind: SenderPublicationKind,
) -> Result<ContentDigest, M6SenderAckError> {
    let domain = match kind {
        SenderPublicationKind::Export => EXPORT_DELIVERY_FACT_DOMAIN,
        SenderPublicationKind::Revocation => REVOCATION_DELIVERY_FACT_DOMAIN,
    };
    digest_domain(
        domain,
        &(
            &issued.manifest.message_digest,
            ContentDigest::from_bytes(
                &issued
                    .manifest
                    .canonical_bytes()
                    .map_err(M6SenderAckError::from)?,
            ),
            &issued.attachments,
        ),
    )
}

fn acknowledgement_completion_source_digests(
    sources: &SenderAcknowledgementCompletionSources,
) -> Result<SenderAcknowledgementCompletionSourceDigestsV1, M6SenderAckError> {
    let manifest = sources
        .raw_acknowledgement_files
        .get(MANIFEST_FILE)
        .ok_or_else(|| {
            M6SenderAckError::Integrity(
                "ACK completion raw source set lacks manifest bytes".to_string(),
            )
        })?;
    let delivery_commit = sources
        .raw_acknowledgement_files
        .get(DELIVERY_COMMIT_FILE)
        .ok_or_else(|| {
            M6SenderAckError::Integrity(
                "ACK completion raw source set lacks delivery commit bytes".to_string(),
            )
        })?;
    Ok(SenderAcknowledgementCompletionSourceDigestsV1 {
        sender_publication_receipt: ContentDigest::from_bytes(
            &sources.sender_publication_receipt_bytes,
        ),
        raw_acknowledgement_record: ContentDigest::from_bytes(
            &sources.raw_acknowledgement_record_bytes,
        ),
        raw_acknowledgement_commit: ContentDigest::from_bytes(
            &sources.raw_acknowledgement_commit_bytes,
        ),
        raw_acknowledgement_files: ContentDigest::from_bytes(&canonical_json(
            &sources.raw_acknowledgement_files,
        )?),
        receiver_signed_manifest: ContentDigest::from_bytes(manifest),
        receiver_delivery_commit: ContentDigest::from_bytes(delivery_commit),
        correlation_receipt: ContentDigest::from_bytes(&sources.correlation_receipt_bytes),
        replay_fact: ContentDigest::from_bytes(&sources.replay_fact_bytes),
        collection_intent: optional_bytes_digest(&sources.collection_intent_bytes),
        route_collection_fact: optional_bytes_digest(&sources.route_collection_fact_bytes),
        collection_journal: sources
            .collection_journal_files
            .as_ref()
            .map(canonical_json)
            .transpose()?
            .map(|bytes| ContentDigest::from_bytes(&bytes)),
        collection_receipt: optional_bytes_digest(&sources.collection_receipt_bytes),
    })
}

fn optional_bytes_digest(bytes: &Option<Vec<u8>>) -> Option<ContentDigest> {
    bytes.as_ref().map(|bytes| ContentDigest::from_bytes(bytes))
}

fn completion_sources_from_evidence(
    evidence: &SenderAcknowledgementCompletionEvidenceV1,
) -> SenderAcknowledgementCompletionSources {
    SenderAcknowledgementCompletionSources {
        sender_publication_receipt_bytes: evidence.sender_publication_receipt_bytes.clone(),
        raw_acknowledgement_record_bytes: evidence.raw_acknowledgement_record_bytes.clone(),
        raw_acknowledgement_commit_bytes: evidence.raw_acknowledgement_commit_bytes.clone(),
        raw_acknowledgement_files: evidence.raw_acknowledgement_files.clone(),
        correlation_receipt_bytes: evidence.correlation_receipt_bytes.clone(),
        replay_fact_bytes: evidence.replay_fact_bytes.clone(),
        collection_intent_bytes: evidence.collection_intent_bytes.clone(),
        route_collection_fact_bytes: evidence.route_collection_fact_bytes.clone(),
        collection_journal_files: evidence.collection_journal_files.clone(),
        collection_receipt_bytes: evidence.collection_receipt_bytes.clone(),
    }
}

fn validate_acknowledgement_completion_source_bounds(
    evidence: &SenderAcknowledgementCompletionEvidenceV1,
    route: &RouteDefinition,
) -> Result<(), M6SenderAckError> {
    let scalars = [
        evidence.sender_publication_receipt_bytes.as_slice(),
        evidence.raw_acknowledgement_record_bytes.as_slice(),
        evidence.raw_acknowledgement_commit_bytes.as_slice(),
        evidence.correlation_receipt_bytes.as_slice(),
        evidence.replay_fact_bytes.as_slice(),
    ];
    if scalars.iter().any(|bytes| bytes.is_empty())
        || evidence.raw_acknowledgement_files.is_empty()
        || evidence.raw_acknowledgement_files.len() > raw_entry_limit(route)
    {
        return Err(M6SenderAckError::Integrity(
            "sender ACK completion contains an empty or out-of-bounds exact source".to_string(),
        ));
    }
    let mut total = scalars
        .iter()
        .try_fold(0_u64, |total, bytes| total.checked_add(bytes.len() as u64))
        .ok_or_else(|| {
            M6SenderAckError::ResourceExhausted(
                "sender ACK completion source byte count overflowed".to_string(),
            )
        })?;
    for (path, bytes) in &evidence.raw_acknowledgement_files {
        validate_relative_string(path)?;
        if bytes.is_empty() {
            return Err(M6SenderAckError::Integrity(
                "sender ACK completion contains an empty raw route file".to_string(),
            ));
        }
        total = total.checked_add(bytes.len() as u64).ok_or_else(|| {
            M6SenderAckError::ResourceExhausted(
                "sender ACK completion source byte count overflowed".to_string(),
            )
        })?;
    }
    for optional in [
        &evidence.collection_intent_bytes,
        &evidence.route_collection_fact_bytes,
        &evidence.collection_receipt_bytes,
    ] {
        if let Some(bytes) = optional {
            if bytes.is_empty() {
                return Err(M6SenderAckError::Integrity(
                    "sender ACK completion contains an empty collection source".to_string(),
                ));
            }
            total = total.checked_add(bytes.len() as u64).ok_or_else(|| {
                M6SenderAckError::ResourceExhausted(
                    "sender ACK completion source byte count overflowed".to_string(),
                )
            })?;
        }
    }
    if let Some(journal) = &evidence.collection_journal_files {
        if journal.is_empty() || journal.len() > SenderCollectionStage::ALL.len() {
            return Err(M6SenderAckError::Integrity(
                "sender ACK completion collection journal is empty or out of bounds".to_string(),
            ));
        }
        for (name, bytes) in journal {
            validate_identifier("ACK completion collection journal name", name)?;
            if bytes.is_empty() {
                return Err(M6SenderAckError::Integrity(
                    "sender ACK completion contains an empty journal source".to_string(),
                ));
            }
            total = total.checked_add(bytes.len() as u64).ok_or_else(|| {
                M6SenderAckError::ResourceExhausted(
                    "sender ACK completion source byte count overflowed".to_string(),
                )
            })?;
        }
    }
    if total > u64::try_from(acknowledgement_completion_byte_limit(route)).unwrap_or(u64::MAX) {
        return Err(M6SenderAckError::ResourceExhausted(
            "sender ACK completion exact sources exceed the immutable route evidence budget"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_acknowledgement_completion_evidence(
    evidence: &SenderAcknowledgementCompletionEvidenceV1,
    route: &RouteDefinition,
) -> Result<(), M6SenderAckError> {
    route.validate().map_err(M6SenderAckError::from)?;
    validate_identifier(
        "ACK completion logical operation",
        &evidence.logical_operation_id,
    )?;
    validate_identifier("ACK completion signing key", &evidence.signing_key_id)?;
    validate_identifier("ACK completion sender factory", &evidence.sender_factory_id)?;
    validate_identifier(
        "ACK completion receiver factory",
        &evidence.receiver_factory_id,
    )?;
    if evidence.schema != SENDER_ACK_COMPLETION_EVIDENCE_SCHEMA
        || evidence.route_definition_digest != route.definition_digest
        || evidence.route_generation != route.generation
        || evidence.signing_key_id != route.sender.signing_key_id
        || evidence.sender_factory_id != route.sender.factory_id
        || evidence.receiver_factory_id != route.receiver.factory_id
        || evidence.sender_factory_id == evidence.receiver_factory_id
        || !evidence.intake_only
        || evidence.adoption_inferred
    {
        return Err(M6SenderAckError::Integrity(
            "sender ACK completion is outside its pinned route or adoption boundary".to_string(),
        ));
    }
    validate_ack_payload(&ReceiverAcknowledgementPayload {
        disposition: evidence.disposition.clone(),
        intake_record_digest: evidence.intake_record_digest.clone(),
        raw_quarantine_digest: evidence.raw_quarantine_digest.clone(),
        receiver_transaction_digest: evidence.receiver_transaction_digest.clone(),
        sender_message_digest: evidence.sender_message_digest.clone(),
    })?;
    validate_acknowledgement_completion_source_bounds(evidence, route)?;
    let sources = completion_sources_from_evidence(evidence);
    if evidence.source_digests != acknowledgement_completion_source_digests(&sources)? {
        return Err(M6SenderAckError::Integrity(
            "sender ACK completion source digests differ from their exact bytes".to_string(),
        ));
    }

    let source = source_evidence_from_receipt_bytes(
        evidence.source_publication_kind,
        &evidence.sender_publication_receipt_bytes,
        route,
    )?;
    if source.logical_operation_id != evidence.logical_operation_id
        || source.sender_message_digest != evidence.sender_message_digest
        || source.sender_sequence != evidence.sender_sequence
        || source.sender_receipt_digest != evidence.source_receipt_digest
    {
        return Err(M6SenderAckError::Integrity(
            "sender ACK completion projection differs from its publication receipt".to_string(),
        ));
    }

    let raw: SenderAckRawQuarantineRecord =
        parse_canonical(&evidence.raw_acknowledgement_record_bytes)?;
    raw.validate(route)?;
    let raw_commit: RawCommitMarker = parse_canonical(&evidence.raw_acknowledgement_commit_bytes)?;
    if raw_commit.schema != SENDER_ACK_RAW_QUARANTINE_SCHEMA
        || raw_commit.acknowledgement_message_digest != raw.acknowledgement_message_digest
        || raw_commit.raw_unit_digest != raw.raw_unit_digest
        || raw_commit.raw_record_digest != raw.record_digest
    {
        return Err(M6SenderAckError::Integrity(
            "sender ACK completion raw commit is cross-linked".to_string(),
        ));
    }
    let raw_snapshot = evidence
        .raw_acknowledgement_files
        .iter()
        .map(|(path, bytes)| {
            let relative = PathBuf::from(path);
            validate_relative_path(&relative)?;
            Ok((relative, bytes.clone()))
        })
        .collect::<Result<BTreeMap<_, _>, M6SenderAckError>>()?;
    if raw_observations(&raw_snapshot)? != raw.files {
        return Err(M6SenderAckError::Integrity(
            "sender ACK completion raw files differ from their quarantine record".to_string(),
        ));
    }
    let expected_raw_paths = BTreeSet::from([
        PathBuf::from(MANIFEST_FILE),
        PathBuf::from(DELIVERY_COMMIT_FILE),
    ]);
    if raw_snapshot.keys().cloned().collect::<BTreeSet<_>>() != expected_raw_paths {
        return Err(M6SenderAckError::Integrity(
            "sender ACK completion raw unit is not attachment-free".to_string(),
        ));
    }
    let manifest_bytes = raw_snapshot
        .get(Path::new(MANIFEST_FILE))
        .ok_or_else(|| M6SenderAckError::Integrity("ACK manifest is absent".to_string()))?;
    let manifest =
        SignedManifest::from_canonical_bytes(manifest_bytes).map_err(M6SenderAckError::from)?;
    manifest
        .verify_route(route)
        .map_err(M6SenderAckError::from)?;
    let delivery: DeliveryCommitMarker = parse_canonical(
        raw_snapshot
            .get(Path::new(DELIVERY_COMMIT_FILE))
            .ok_or_else(|| M6SenderAckError::Integrity("ACK commit is absent".to_string()))?,
    )?;
    if delivery.schema != DELIVERY_COMMIT_SCHEMA
        || delivery.message_digest != manifest.message_digest
        || delivery.manifest_bytes_digest != ContentDigest::from_bytes(manifest_bytes)
        || manifest.message_digest != raw.acknowledgement_message_digest
        || manifest.unsigned.origin_role != RouteEndpointRole::Receiver
        || manifest.unsigned.kind != ManifestKind::ReceiverAcknowledgement
        || !manifest.unsigned.attachments.is_empty()
    {
        return Err(M6SenderAckError::Integrity(
            "sender ACK completion manifest, commit, route, or role is cross-linked".to_string(),
        ));
    }
    let ManifestPayload::ReceiverAcknowledgement(payload) = manifest.unsigned.payload.clone()
    else {
        return Err(M6SenderAckError::Integrity(
            "sender ACK completion manifest carries another payload".to_string(),
        ));
    };
    validate_ack_payload(&payload)?;

    let replay_source: SenderAcknowledgementReplayFactSourceV1 =
        parse_canonical(&evidence.replay_fact_bytes)?;
    let replay = replay_source.to_fact();
    if replay.message_digest != manifest.message_digest
        || replay.nonce != manifest.unsigned.nonce
        || replay.sequence != manifest.unsigned.sequence
        || replay.route_definition_digest != route.definition_digest
    {
        return Err(M6SenderAckError::Integrity(
            "sender ACK completion replay fact is cross-linked".to_string(),
        ));
    }
    let correlation: SenderAcknowledgementCorrelationReceipt =
        parse_canonical(&evidence.correlation_receipt_bytes)?;
    let intent = SenderAckIntent {
        schema: SENDER_ACK_INTENT_SCHEMA.to_string(),
        acknowledgement_message_digest: correlation.acknowledgement_message_digest.clone(),
        acknowledgement_sequence: correlation.acknowledgement_sequence,
        acknowledgement_nonce: correlation.acknowledgement_nonce.clone(),
        acknowledgement_previous_message_digest: correlation
            .acknowledgement_previous_message_digest
            .clone(),
        signed_manifest_bytes_digest: correlation.signed_manifest_bytes_digest.clone(),
        raw_unit_digest: correlation.raw_unit_digest.clone(),
        raw_record_digest: correlation.raw_record_digest.clone(),
        route_definition_digest: route.definition_digest.clone(),
        route_generation: route.generation,
        source: correlation.source.clone(),
        disposition: correlation.disposition.clone(),
        intake_record_digest: correlation.intake_record_digest.clone(),
        raw_quarantine_digest: correlation.raw_quarantine_digest.clone(),
        receiver_transaction_digest: correlation.receiver_transaction_digest.clone(),
        accepted_at_ms: correlation.accepted_at_ms,
        intent_digest: correlation.acknowledgement_intent_digest.clone(),
    };
    intent.validate(&manifest, manifest_bytes, &raw, &payload, route)?;
    validate_message_time(&manifest, route, intent.accepted_at_ms)?;
    if intent.accepted_at_ms < raw.observed_at_ms {
        return Err(M6SenderAckError::Integrity(
            "ACK completion acceptance predates raw quarantine".to_string(),
        ));
    }
    correlation.validate(&intent, &replay)?;
    if correlation.source != source
        || correlation.acknowledgement_message_digest != evidence.acknowledgement_message_digest
        || correlation.acknowledgement_sequence != evidence.acknowledgement_sequence
        || correlation.disposition != evidence.disposition
        || correlation.intake_record_digest != evidence.intake_record_digest
        || correlation.raw_quarantine_digest != evidence.raw_quarantine_digest
        || correlation.receiver_transaction_digest != evidence.receiver_transaction_digest
        || correlation.replay_commit_digest != evidence.replay_fact_digest
        || correlation.replay_retained_until_ms != evidence.replay_retained_until_ms
        || correlation.receipt_digest != evidence.correlation_receipt_digest
        || correlation.intake_only != evidence.intake_only
        || correlation.adoption_inferred != evidence.adoption_inferred
    {
        return Err(M6SenderAckError::Integrity(
            "sender ACK completion projection differs from its correlation receipt".to_string(),
        ));
    }

    validate_acknowledgement_completion_collection(evidence, &correlation, &raw, route)?;
    require_digest(
        "sender ACK completion evidence",
        &evidence.evidence_digest,
        &evidence.expected_digest()?,
    )?;
    crate::m6_identity::verify_sender_ack_completion_signature(
        route,
        &evidence.signing_key_id,
        &evidence.evidence_digest,
        &evidence.source_set_signature_hex,
    )
    .map_err(M6SenderAckError::from)
}

fn validate_acknowledgement_completion_collection(
    evidence: &SenderAcknowledgementCompletionEvidenceV1,
    correlation: &SenderAcknowledgementCorrelationReceipt,
    raw: &SenderAckRawQuarantineRecord,
    route: &RouteDefinition,
) -> Result<(), M6SenderAckError> {
    let presence = [
        evidence.collection_intent_bytes.is_some(),
        evidence.route_collection_fact_bytes.is_some(),
        evidence.collection_journal_files.is_some(),
        evidence.collection_receipt_bytes.is_some(),
        evidence.collection_receipt_digest.is_some(),
    ];
    let present = presence.iter().filter(|present| **present).count();
    if present == 0 {
        if evidence.source_digests.collection_intent.is_some()
            || evidence.source_digests.route_collection_fact.is_some()
            || evidence.source_digests.collection_journal.is_some()
            || evidence.source_digests.collection_receipt.is_some()
        {
            return Err(M6SenderAckError::Integrity(
                "ACK completion has collection digests without collection sources".to_string(),
            ));
        }
        return Ok(());
    }
    if present != presence.len() {
        return Err(M6SenderAckError::Integrity(
            "ACK completion carries a partial collection source set".to_string(),
        ));
    }
    let intent: SenderCollectionIntent = parse_canonical(
        evidence
            .collection_intent_bytes
            .as_deref()
            .ok_or_else(|| M6SenderAckError::Integrity("collection intent absent".to_string()))?,
    )?;
    validate_collection_intent(&intent, correlation, raw, route)?;
    let fact: RouteCollectionFact = parse_canonical(
        evidence
            .route_collection_fact_bytes
            .as_deref()
            .ok_or_else(|| M6SenderAckError::Integrity("collection fact absent".to_string()))?,
    )?;
    validate_route_collection_fact(&fact, &intent, route)?;
    let receipt: SenderCollectionReceipt = parse_canonical(
        evidence
            .collection_receipt_bytes
            .as_deref()
            .ok_or_else(|| M6SenderAckError::Integrity("collection receipt absent".to_string()))?,
    )?;
    validate_collection_receipt(&receipt, &intent, &fact, correlation)?;
    if evidence.collection_receipt_digest.as_ref() != Some(&receipt.receipt_digest) {
        return Err(M6SenderAckError::Integrity(
            "ACK completion collection digest differs from its receipt".to_string(),
        ));
    }
    let journal = evidence
        .collection_journal_files
        .as_ref()
        .ok_or_else(|| M6SenderAckError::Integrity("collection journal absent".to_string()))?;
    if journal.len() != SenderCollectionStage::ALL.len() {
        return Err(M6SenderAckError::Integrity(
            "ACK completion collection journal is incomplete".to_string(),
        ));
    }
    let mut previous = None;
    for (ordinal, stage) in SenderCollectionStage::ALL.iter().copied().enumerate() {
        let name = format!("{:04}-{}.json", ordinal + 1, stage.label());
        let bytes = journal.get(&name).ok_or_else(|| {
            M6SenderAckError::Integrity(format!("ACK completion collection journal lacks '{name}'"))
        })?;
        let record: SenderCollectionStageRecord = parse_canonical(bytes)?;
        validate_collection_stage_record(&record, &intent, previous.as_ref())?;
        previous = Some(record);
    }
    if previous.as_ref().map(|record| record.stage)
        != Some(SenderCollectionStage::CollectionReceiptCommitted)
    {
        return Err(M6SenderAckError::Integrity(
            "ACK completion collection journal is not terminal".to_string(),
        ));
    }
    Ok(())
}

fn collection_minimum_time(
    correlation: &SenderAcknowledgementCorrelationReceipt,
    route: &RouteDefinition,
) -> u64 {
    let retention_ms = route.resource_profile.route_delivery_retention_ms;
    correlation
        .source
        .source_committed_at_ms
        .saturating_add(retention_ms)
        .max(correlation.accepted_at_ms.saturating_add(retention_ms))
        .max(
            correlation
                .accepted_at_ms
                .saturating_add(route.resource_profile.crash_recovery_interval_ms),
        )
}

fn validate_collection_intent(
    intent: &SenderCollectionIntent,
    correlation: &SenderAcknowledgementCorrelationReceipt,
    raw_acknowledgement: &SenderAckRawQuarantineRecord,
    route: &RouteDefinition,
) -> Result<(), M6SenderAckError> {
    let expected_minimum = collection_minimum_time(correlation, route);
    if intent.schema != SENDER_COLLECTION_INTENT_SCHEMA
        || intent.sender_message_digest != correlation.source.sender_message_digest
        || intent.source_publication_kind != correlation.source.publication_kind
        || intent.source_receipt_digest != correlation.source.sender_receipt_digest
        || intent.source_route_delivery_digest != correlation.source.route_delivery_digest
        || intent.acknowledgement_message_digest != correlation.acknowledgement_message_digest
        || intent.acknowledgement_receipt_digest != correlation.receipt_digest
        || intent.route_definition_digest != route.definition_digest
        || intent.route_generation != route.generation
        || intent.minimum_collect_at_ms != expected_minimum
        || intent.requested_at_ms < intent.minimum_collect_at_ms
        || intent.acknowledgement_ready_files != raw_acknowledgement.files
    {
        return Err(M6SenderAckError::Integrity(
            "sender collection intent is missing, premature, or cross-linked".to_string(),
        ));
    }
    validate_collection_observations(
        "collection source ready files",
        &intent.source_ready_files,
        &intent.source_ready_snapshot_digest,
        route,
    )?;
    validate_collection_observations(
        "collection acknowledgement ready files",
        &intent.acknowledgement_ready_files,
        &intent.acknowledgement_ready_snapshot_digest,
        route,
    )?;
    require_digest(
        "collection acknowledgement raw snapshot",
        &intent.acknowledgement_ready_snapshot_digest,
        &raw_record_route_snapshot_digest(raw_acknowledgement)?,
    )?;
    require_digest(
        "sender collection intent",
        &intent.intent_digest,
        &intent.expected_digest()?,
    )
}

fn validate_route_collection_fact(
    fact: &RouteCollectionFact,
    intent: &SenderCollectionIntent,
    route: &RouteDefinition,
) -> Result<(), M6SenderAckError> {
    if fact.schema != ROUTE_COLLECTION_FACT_SCHEMA
        || fact.sender_message_digest != intent.sender_message_digest
        || fact.source_publication_kind != intent.source_publication_kind
        || fact.source_receipt_digest != intent.source_receipt_digest
        || fact.acknowledgement_receipt_digest != intent.acknowledgement_receipt_digest
        || fact.collection_intent_digest != intent.intent_digest
        || fact.source_ready_files != intent.source_ready_files
        || fact.source_ready_snapshot_digest != intent.source_ready_snapshot_digest
        || fact.acknowledgement_ready_files != intent.acknowledgement_ready_files
        || fact.acknowledgement_ready_snapshot_digest
            != intent.acknowledgement_ready_snapshot_digest
        || fact.route_definition_digest != route.definition_digest
        || fact.route_generation != route.generation
        || fact.detached_at_ms < intent.minimum_collect_at_ms
    {
        return Err(M6SenderAckError::Integrity(
            "route collection fact is missing or cross-linked".to_string(),
        ));
    }
    require_digest(
        "route collection fact",
        &fact.fact_digest,
        &fact.expected_digest()?,
    )
}

fn validate_collection_receipt(
    receipt: &SenderCollectionReceipt,
    intent: &SenderCollectionIntent,
    fact: &RouteCollectionFact,
    correlation: &SenderAcknowledgementCorrelationReceipt,
) -> Result<(), M6SenderAckError> {
    if receipt.schema != SENDER_COLLECTION_RECEIPT_SCHEMA
        || receipt.sender_message_digest != intent.sender_message_digest
        || receipt.source_publication_kind != intent.source_publication_kind
        || receipt.source_receipt_digest != intent.source_receipt_digest
        || receipt.acknowledgement_message_digest != intent.acknowledgement_message_digest
        || receipt.acknowledgement_receipt_digest != intent.acknowledgement_receipt_digest
        || receipt.acknowledgement_receipt_digest != correlation.receipt_digest
        || receipt.collection_intent_digest != intent.intent_digest
        || receipt.route_collection_fact_digest != fact.fact_digest
        || receipt.source_ready_snapshot_digest != intent.source_ready_snapshot_digest
        || receipt.acknowledgement_ready_snapshot_digest
            != intent.acknowledgement_ready_snapshot_digest
        || receipt.route_definition_digest != intent.route_definition_digest
        || receipt.route_generation != intent.route_generation
        || receipt.minimum_collect_at_ms != intent.minimum_collect_at_ms
        || receipt.collected_at_ms != fact.detached_at_ms
        || !receipt.source_receipt_retained
        || !receipt.acknowledgement_evidence_retained
    {
        return Err(M6SenderAckError::Integrity(
            "sender collection receipt is missing or cross-linked".to_string(),
        ));
    }
    require_digest(
        "sender collection receipt",
        &receipt.receipt_digest,
        &receipt.expected_digest()?,
    )
}

fn validate_collection_stage_record(
    record: &SenderCollectionStageRecord,
    intent: &SenderCollectionIntent,
    previous: Option<&SenderCollectionStageRecord>,
) -> Result<(), M6SenderAckError> {
    let expected_stage = SenderCollectionStage::ALL
        .get(record.ordinal.saturating_sub(1) as usize)
        .copied();
    if record.schema != SENDER_COLLECTION_STAGE_SCHEMA
        || record.sender_message_digest != intent.sender_message_digest
        || record.collection_intent_digest != intent.intent_digest
        || record.ordinal == 0
        || expected_stage != Some(record.stage)
        || record.previous_stage_digest != previous.map(|previous| previous.stage_digest.clone())
        || record
            .evidence_digests
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || record.evidence_digests.is_empty()
        || previous.is_some_and(|previous| record.recorded_at_ms < previous.recorded_at_ms)
    {
        return Err(M6SenderAckError::Integrity(
            "sender collection stage chain is malformed or cross-linked".to_string(),
        ));
    }
    require_digest(
        "sender collection stage",
        &record.stage_digest,
        &record.expected_digest()?,
    )
}

fn route_snapshot_digest(
    snapshot: &BTreeMap<PathBuf, Vec<u8>>,
) -> Result<ContentDigest, M6SenderAckError> {
    let observations = raw_observations(snapshot)?;
    digest_domain(COLLECTION_SNAPSHOT_DOMAIN, &observations)
}

fn raw_record_route_snapshot_digest(
    record: &SenderAckRawQuarantineRecord,
) -> Result<ContentDigest, M6SenderAckError> {
    digest_domain(COLLECTION_SNAPSHOT_DOMAIN, &record.files)
}

fn validate_collection_observations(
    subject: &str,
    observations: &[SenderAckRawFileObservation],
    expected_snapshot_digest: &ContentDigest,
    route: &RouteDefinition,
) -> Result<(), M6SenderAckError> {
    if observations.is_empty()
        || observations.len() > raw_entry_limit(route)
        || !strictly_sorted_unique_by(observations, |file| file.relative_path.clone())
    {
        return Err(M6SenderAckError::Integrity(format!(
            "{subject} are empty, unordered, duplicated, or out of bounds"
        )));
    }
    let mut total = 0_u64;
    for observation in observations {
        validate_relative_string(&observation.relative_path)?;
        if observation.byte_length == 0 {
            return Err(M6SenderAckError::Integrity(format!(
                "{subject} contain an empty route file"
            )));
        }
        total = total.checked_add(observation.byte_length).ok_or_else(|| {
            M6SenderAckError::ResourceExhausted(format!("{subject} byte count overflowed"))
        })?;
        require_meaningful_digest(subject, &observation.content_digest)?;
    }
    if total > raw_byte_limit(route) {
        return Err(M6SenderAckError::ResourceExhausted(format!(
            "{subject} exceed the route byte bound"
        )));
    }
    require_digest(
        subject,
        expected_snapshot_digest,
        &digest_domain(COLLECTION_SNAPSHOT_DOMAIN, &observations)?,
    )
}

fn detach_or_validate_collection_unit(
    ready_path: &Path,
    archive_path: &Path,
    archive_root: &Path,
    expected_files: &[SenderAckRawFileObservation],
    expected_snapshot_digest: &ContentDigest,
    label: &str,
    route: &RouteDefinition,
) -> Result<(), M6SenderAckError> {
    let ready_exists = ready_path.exists();
    let archive_exists = archive_path.exists();
    if ready_exists && archive_exists {
        return Err(M6SenderAckError::Integrity(format!(
            "collection has both ready and detached {label} units"
        )));
    }
    if ready_exists {
        let observed = scan_raw_route_unit(ready_path, route)?;
        require_digest(
            &format!("{label} ready collection snapshot"),
            expected_snapshot_digest,
            &route_snapshot_digest(&observed)?,
        )?;
        fs::rename(ready_path, archive_path)
            .map_err(|source| M6SenderAckError::io(archive_path, source))?;
        sync_directory(
            ready_path
                .parent()
                .ok_or_else(|| M6SenderAckError::UnsafePath(ready_path.to_path_buf()))?,
        )?;
        sync_directory(archive_root)?;
        return Ok(());
    }
    if archive_exists {
        let observed = scan_collection_archive_remainder(archive_path, expected_files)?;
        if observed.len() != expected_files.len() {
            return Err(M6SenderAckError::Integrity(format!(
                "detached {label} unit is incomplete before its durable route fact"
            )));
        }
        return require_digest(
            &format!("detached {label} collection snapshot"),
            expected_snapshot_digest,
            &route_snapshot_digest(&observed)?,
        );
    }
    Err(M6SenderAckError::Integrity(format!(
        "collection intent has neither the exact {label} ready unit nor its detached copy"
    )))
}

fn validate_archive_if_present(
    archive_path: &Path,
    expected_files: &[SenderAckRawFileObservation],
    subject: &str,
) -> Result<(), M6SenderAckError> {
    if !archive_path.exists() {
        return Ok(());
    }
    scan_collection_archive_remainder(archive_path, expected_files)
        .map(|_| ())
        .map_err(|error| match error {
            M6SenderAckError::Integrity(message) => {
                M6SenderAckError::Integrity(format!("{subject}: {message}"))
            }
            other => other,
        })
}

fn remove_collection_archive_if_present(
    archive_root: &Path,
    archive_path: &Path,
    expected_files: &[SenderAckRawFileObservation],
    label: &str,
    crash_at: Option<SenderAckCrashPoint>,
    file_removed_point: SenderAckCrashPoint,
) -> Result<(), M6SenderAckError> {
    if !archive_path.exists() {
        return Ok(());
    }
    remove_collection_archive_remainder(
        archive_root,
        archive_path,
        expected_files,
        crash_at,
        file_removed_point,
    )
    .map_err(|error| match error {
        M6SenderAckError::Integrity(message) => {
            M6SenderAckError::Integrity(format!("{label} route archive: {message}"))
        }
        other => other,
    })
}

fn raw_entry_limit(route: &RouteDefinition) -> usize {
    usize::try_from(route.resource_profile.max_attachment_count)
        .unwrap_or(usize::MAX)
        .saturating_add(2)
        .min(MAX_RAW_ENTRIES_ABSOLUTE)
}

fn raw_byte_limit(route: &RouteDefinition) -> u64 {
    route
        .resource_profile
        .max_delivery_bytes
        .saturating_add(route.resource_profile.max_manifest_bytes)
        .saturating_add(route.resource_profile.max_manifest_bytes)
        .min(MAX_RAW_BYTES_ABSOLUTE)
}

fn route_record_byte_limit(route: &RouteDefinition) -> usize {
    usize::try_from(route.resource_profile.max_evidence_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_RECORD_BYTES)
}

fn acknowledgement_completion_byte_limit(route: &RouteDefinition) -> usize {
    usize::try_from(route.resource_profile.max_evidence_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_ACK_COMPLETION_EVIDENCE_BYTES)
}

fn enforce_route_byte_limit(
    bytes: &[u8],
    maximum: usize,
    subject: &str,
) -> Result<(), M6SenderAckError> {
    if bytes.len() > maximum {
        return Err(M6SenderAckError::ResourceExhausted(format!(
            "{subject} is {} bytes; immutable route limit is {maximum}",
            bytes.len()
        )));
    }
    Ok(())
}

fn canonical_route_record<T: Serialize + ?Sized>(
    route: &RouteDefinition,
    value: &T,
) -> Result<Vec<u8>, M6SenderAckError> {
    let bytes = canonical_json(value)?;
    enforce_route_byte_limit(
        &bytes,
        route_record_byte_limit(route),
        "canonical sender ACK record",
    )?;
    Ok(bytes)
}

fn scan_raw_route_unit(
    root: &Path,
    route: &RouteDefinition,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, M6SenderAckError> {
    ensure_real_directory(root)?;
    let mut snapshot = BTreeMap::new();
    read_raw_tree(root, root, route, &mut snapshot, 0)?;
    let total_bytes = snapshot
        .values()
        .try_fold(0_u64, |total, bytes| total.checked_add(bytes.len() as u64))
        .ok_or_else(|| {
            M6SenderAckError::ResourceExhausted(
                "raw receiver ACK byte count overflowed".to_string(),
            )
        })?;
    if snapshot.is_empty()
        || snapshot.len() > raw_entry_limit(route)
        || total_bytes > raw_byte_limit(route)
    {
        return Err(M6SenderAckError::ResourceExhausted(
            "raw receiver ACK route unit exceeds its immutable entry or byte bound".to_string(),
        ));
    }
    Ok(snapshot)
}

fn read_raw_tree(
    root: &Path,
    current: &Path,
    route: &RouteDefinition,
    snapshot: &mut BTreeMap<PathBuf, Vec<u8>>,
    depth: usize,
) -> Result<(), M6SenderAckError> {
    if depth > 3 {
        return Err(M6SenderAckError::UnsafePath(current.to_path_buf()));
    }
    let mut entries = fs::read_dir(current)
        .map_err(|source| M6SenderAckError::io(current, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| M6SenderAckError::io(current, source))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        reject_symlink(&path)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| M6SenderAckError::UnsafePath(path.clone()))?
            .to_path_buf();
        validate_relative_path(&relative)?;
        let file_type = entry
            .file_type()
            .map_err(|source| M6SenderAckError::io(&path, source))?;
        if file_type.is_dir() {
            read_raw_tree(root, &path, route, snapshot, depth + 1)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(M6SenderAckError::UnsafePath(path));
        }
        if snapshot.len() >= raw_entry_limit(route) {
            return Err(M6SenderAckError::ResourceExhausted(
                "raw receiver ACK entry budget is full".to_string(),
            ));
        }
        let remaining = raw_byte_limit(route).saturating_sub(
            snapshot
                .values()
                .map(|bytes| bytes.len() as u64)
                .sum::<u64>(),
        );
        let maximum = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(MAX_RAW_BYTES_ABSOLUTE as usize);
        let bytes = read_regular_bounded(&path, maximum)?;
        if bytes.is_empty() {
            return Err(M6SenderAckError::Integrity(format!(
                "raw receiver ACK file '{}' is empty",
                relative.display()
            )));
        }
        snapshot.insert(relative, bytes);
    }
    Ok(())
}

fn raw_observations(
    snapshot: &BTreeMap<PathBuf, Vec<u8>>,
) -> Result<Vec<SenderAckRawFileObservation>, M6SenderAckError> {
    snapshot
        .iter()
        .map(|(relative, bytes)| {
            validate_relative_path(relative)?;
            Ok(SenderAckRawFileObservation {
                byte_length: bytes.len() as u64,
                content_digest: ContentDigest::from_bytes(bytes),
                relative_path: relative_path_string(relative)?,
            })
        })
        .collect()
}

fn persist_raw_unit(
    raw_root: &Path,
    staging_root: &Path,
    destination: &Path,
    record: &SenderAckRawQuarantineRecord,
    snapshot: &BTreeMap<PathBuf, Vec<u8>>,
    route: &RouteDefinition,
) -> Result<(), M6SenderAckError> {
    if destination.parent() != Some(raw_root) {
        return Err(M6SenderAckError::UnsafePath(destination.to_path_buf()));
    }
    record.validate(route)?;
    if raw_observations(snapshot)? != record.files {
        return Err(M6SenderAckError::Integrity(
            "raw ACK snapshot differs from its quarantine record".to_string(),
        ));
    }
    if destination.exists() {
        let (existing_record, existing_snapshot) = load_raw_unit(destination, route)?;
        return if existing_record == *record && existing_snapshot == *snapshot {
            Ok(())
        } else {
            Err(M6SenderAckError::ImmutableConflict(
                destination.to_path_buf(),
            ))
        };
    }
    let staging = staging_root.join(format!(
        "{STAGING_PREFIX}raw-{}-{}-{}",
        record.acknowledgement_message_digest.file_stem(),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        create_direct_child(staging_root, &staging)?;
        let unit = staging.join(RAW_UNIT_DIRECTORY);
        create_direct_child(&staging, &unit)?;
        write_snapshot(&unit, snapshot)?;
        write_new_sync(
            &staging.join(RAW_RECORD_FILE),
            &canonical_route_record(route, record)?,
        )?;
        let commit = RawCommitMarker {
            schema: SENDER_ACK_RAW_QUARANTINE_SCHEMA.to_string(),
            acknowledgement_message_digest: record.acknowledgement_message_digest.clone(),
            raw_unit_digest: record.raw_unit_digest.clone(),
            raw_record_digest: record.record_digest.clone(),
        };
        write_new_sync(
            &staging.join(RAW_COMMIT_FILE),
            &canonical_route_record(route, &commit)?,
        )?;
        sync_all_directories(&staging)?;
        fs::rename(&staging, destination)
            .map_err(|source| M6SenderAckError::io(destination, source))?;
        sync_directory(raw_root)
    })();
    if result.is_err() && staging.exists() {
        let _ = remove_confined_directory(staging_root, &staging);
    }
    result
}

fn load_raw_unit(
    root: &Path,
    route: &RouteDefinition,
) -> Result<(SenderAckRawQuarantineRecord, BTreeMap<PathBuf, Vec<u8>>), M6SenderAckError> {
    ensure_real_directory(root)?;
    let allowed = BTreeSet::from([
        RAW_UNIT_DIRECTORY.to_string(),
        RAW_RECORD_FILE.to_string(),
        RAW_COMMIT_FILE.to_string(),
    ]);
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(|source| M6SenderAckError::io(root, source))? {
        let entry = entry.map_err(|source| M6SenderAckError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| M6SenderAckError::UnsafePath(path.clone()))?
            .to_string();
        if !allowed.contains(&name) || !names.insert(name) {
            return Err(M6SenderAckError::UnsafePath(path));
        }
    }
    if names != allowed {
        return Err(M6SenderAckError::Integrity(
            "raw ACK quarantine unit is incomplete".to_string(),
        ));
    }
    let record: SenderAckRawQuarantineRecord =
        load_canonical_file(&root.join(RAW_RECORD_FILE), route_record_byte_limit(route))?;
    record.validate(route)?;
    let commit: RawCommitMarker =
        load_canonical_file(&root.join(RAW_COMMIT_FILE), route_record_byte_limit(route))?;
    if commit.schema != SENDER_ACK_RAW_QUARANTINE_SCHEMA
        || commit.acknowledgement_message_digest != record.acknowledgement_message_digest
        || commit.raw_unit_digest != record.raw_unit_digest
        || commit.raw_record_digest != record.record_digest
    {
        return Err(M6SenderAckError::Integrity(
            "raw ACK quarantine commit marker is cross-linked".to_string(),
        ));
    }
    let snapshot = scan_raw_route_unit(&root.join(RAW_UNIT_DIRECTORY), route)?;
    if raw_observations(&snapshot)? != record.files {
        return Err(M6SenderAckError::Integrity(
            "retained raw ACK bytes differ from their immutable observations".to_string(),
        ));
    }
    Ok((record, snapshot))
}

fn write_snapshot(
    root: &Path,
    snapshot: &BTreeMap<PathBuf, Vec<u8>>,
) -> Result<(), M6SenderAckError> {
    for (relative, bytes) in snapshot {
        validate_relative_path(relative)?;
        let path = root.join(relative);
        if !path.starts_with(root) {
            return Err(M6SenderAckError::UnsafePath(path));
        }
        if let Some(parent) = path.parent() {
            create_descendant_directories(root, parent)?;
        }
        write_new_sync(&path, bytes)?;
    }
    sync_all_directories(root)
}

fn create_descendant_directories(root: &Path, target: &Path) -> Result<(), M6SenderAckError> {
    if !target.starts_with(root) {
        return Err(M6SenderAckError::UnsafePath(target.to_path_buf()));
    }
    let relative = target
        .strip_prefix(root)
        .map_err(|_| M6SenderAckError::UnsafePath(target.to_path_buf()))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(M6SenderAckError::UnsafePath(target.to_path_buf()));
        };
        current.push(name);
        reject_symlink_if_present(&current)?;
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                ensure_real_directory(&current)?;
            }
            Err(source) => return Err(M6SenderAckError::io(&current, source)),
        }
    }
    Ok(())
}

fn persist_immutable(
    staging_root: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), M6SenderAckError> {
    reject_symlink_if_present(destination)?;
    if destination.exists() {
        return if read_regular_bounded(destination, bytes.len().max(1))? == bytes {
            Ok(())
        } else {
            Err(M6SenderAckError::ImmutableConflict(
                destination.to_path_buf(),
            ))
        };
    }
    let temporary = staging_root.join(format!(
        "{STAGING_PREFIX}record-{}-{}-{}.tmp",
        ContentDigest::from_bytes(destination.as_os_str().as_encoded_bytes()).file_stem(),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    write_new_sync(&temporary, bytes)?;
    match fs::hard_link(&temporary, destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if read_regular_bounded(destination, bytes.len().max(1))? != bytes {
                let _ = fs::remove_file(&temporary);
                return Err(M6SenderAckError::ImmutableConflict(
                    destination.to_path_buf(),
                ));
            }
        }
        Err(source) => {
            let _ = fs::remove_file(&temporary);
            return Err(M6SenderAckError::io(destination, source));
        }
    }
    fs::remove_file(&temporary).map_err(|source| M6SenderAckError::io(&temporary, source))?;
    sync_directory(
        destination
            .parent()
            .ok_or_else(|| M6SenderAckError::UnsafePath(destination.to_path_buf()))?,
    )?;
    sync_directory(staging_root)
}

fn persist_route_immutable(path: &Path, bytes: &[u8]) -> Result<(), M6SenderAckError> {
    reject_symlink_if_present(path)?;
    if path.exists() {
        return if read_regular_bounded(path, bytes.len().max(1))? == bytes {
            Ok(())
        } else {
            Err(M6SenderAckError::ImmutableConflict(path.to_path_buf()))
        };
    }
    let parent = path
        .parent()
        .ok_or_else(|| M6SenderAckError::UnsafePath(path.to_path_buf()))?;
    ensure_real_directory(parent)?;
    let temporary = parent.join(format!(
        "{STAGING_PREFIX}route-fact-{}-{}-{}.tmp",
        ContentDigest::from_bytes(path.as_os_str().as_encoded_bytes()).file_stem(),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    write_new_sync(&temporary, bytes)?;
    fs::rename(&temporary, path).map_err(|source| M6SenderAckError::io(path, source))?;
    sync_directory(parent)
}

fn write_new_sync(path: &Path, bytes: &[u8]) -> Result<(), M6SenderAckError> {
    reject_symlink_if_present(path)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|source| M6SenderAckError::io(path, source))?;
    file.write_all(bytes)
        .map_err(|source| M6SenderAckError::io(path, source))?;
    file.sync_all()
        .map_err(|source| M6SenderAckError::io(path, source))
}

fn read_regular_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, M6SenderAckError> {
    reject_symlink(path)?;
    let before = fs::symlink_metadata(path).map_err(|source| M6SenderAckError::io(path, source))?;
    if !before.is_file() || before.len() > maximum as u64 {
        return Err(M6SenderAckError::ResourceExhausted(format!(
            "'{}' is not a bounded regular file",
            path.display()
        )));
    }
    let file = File::open(path).map_err(|source| M6SenderAckError::io(path, source))?;
    let opened = file
        .metadata()
        .map_err(|source| M6SenderAckError::io(path, source))?;
    if !same_regular_file(&before, &opened) {
        return Err(M6SenderAckError::Integrity(format!(
            "file '{}' changed before bounded read",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| M6SenderAckError::io(path, source))?;
    let after = fs::symlink_metadata(path).map_err(|source| M6SenderAckError::io(path, source))?;
    if bytes.len() > maximum
        || !same_regular_file(&before, &after)
        || !same_regular_file(&opened, &after)
    {
        return Err(M6SenderAckError::Integrity(format!(
            "file '{}' changed during bounded read",
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

fn remove_collection_archive_remainder(
    parent: &Path,
    root: &Path,
    expected_files: &[SenderAckRawFileObservation],
    crash_at: Option<SenderAckCrashPoint>,
    file_removed_point: SenderAckCrashPoint,
) -> Result<(), M6SenderAckError> {
    if root.parent() != Some(parent) {
        return Err(M6SenderAckError::UnsafePath(root.to_path_buf()));
    }
    let expected = collection_observation_map(expected_files)?;
    let observed = scan_collection_archive_remainder(root, expected_files)?;
    let mut files = observed.keys().cloned().collect::<Vec<_>>();
    files.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for relative in files {
        let path = root.join(&relative);
        let observation = expected
            .get(&relative)
            .ok_or_else(|| M6SenderAckError::UnsafePath(path.clone()))?;
        let maximum = usize::try_from(observation.byte_length).map_err(|_| {
            M6SenderAckError::ResourceExhausted(
                "collection observation length does not fit this host".to_string(),
            )
        })?;
        let bytes = read_regular_bounded(&path, maximum)?;
        if bytes.len() as u64 != observation.byte_length
            || ContentDigest::from_bytes(&bytes) != observation.content_digest
        {
            return Err(M6SenderAckError::Integrity(
                "route file changed during exact collection removal".to_string(),
            ));
        }
        fs::remove_file(&path).map_err(|source| M6SenderAckError::io(&path, source))?;
        sync_directory(
            path.parent()
                .ok_or_else(|| M6SenderAckError::UnsafePath(path.clone()))?,
        )?;
        maybe_crash(crash_at, file_removed_point)?;
    }
    let mut directories = Vec::new();
    collect_directories(root, root, &mut directories, 0)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        fs::remove_dir(&directory).map_err(|source| M6SenderAckError::io(&directory, source))?;
        sync_directory(
            directory
                .parent()
                .ok_or_else(|| M6SenderAckError::UnsafePath(directory.clone()))?,
        )?;
    }
    fs::remove_dir(root).map_err(|source| M6SenderAckError::io(root, source))?;
    sync_directory(parent)
}

fn collection_observation_map(
    expected_files: &[SenderAckRawFileObservation],
) -> Result<BTreeMap<PathBuf, SenderAckRawFileObservation>, M6SenderAckError> {
    let mut expected = BTreeMap::new();
    for observation in expected_files {
        validate_relative_string(&observation.relative_path)?;
        let relative = PathBuf::from(&observation.relative_path);
        validate_relative_path(&relative)?;
        if expected.insert(relative, observation.clone()).is_some() {
            return Err(M6SenderAckError::Integrity(
                "collection observations contain a duplicate route path".to_string(),
            ));
        }
    }
    Ok(expected)
}

fn collection_expected_directories(
    expected: &BTreeMap<PathBuf, SenderAckRawFileObservation>,
) -> BTreeSet<PathBuf> {
    let mut directories = BTreeSet::new();
    for relative in expected.keys() {
        let mut parent = relative.parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            directories.insert(path.to_path_buf());
            parent = path.parent();
        }
    }
    directories
}

fn scan_collection_archive_remainder(
    root: &Path,
    expected_files: &[SenderAckRawFileObservation],
) -> Result<BTreeMap<PathBuf, Vec<u8>>, M6SenderAckError> {
    ensure_real_directory(root)?;
    let expected = collection_observation_map(expected_files)?;
    let expected_directories = collection_expected_directories(&expected);
    let mut snapshot = BTreeMap::new();
    read_collection_archive_remainder(
        root,
        root,
        &expected,
        &expected_directories,
        &mut snapshot,
        0,
    )?;
    Ok(snapshot)
}

fn read_collection_archive_remainder(
    root: &Path,
    current: &Path,
    expected: &BTreeMap<PathBuf, SenderAckRawFileObservation>,
    expected_directories: &BTreeSet<PathBuf>,
    snapshot: &mut BTreeMap<PathBuf, Vec<u8>>,
    depth: usize,
) -> Result<(), M6SenderAckError> {
    if depth > 3 {
        return Err(M6SenderAckError::UnsafePath(current.to_path_buf()));
    }
    for entry in fs::read_dir(current).map_err(|source| M6SenderAckError::io(current, source))? {
        let entry = entry.map_err(|source| M6SenderAckError::io(current, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| M6SenderAckError::UnsafePath(path.clone()))?
            .to_path_buf();
        validate_relative_path(&relative)?;
        let file_type = entry
            .file_type()
            .map_err(|source| M6SenderAckError::io(&path, source))?;
        if file_type.is_dir() {
            if !expected_directories.contains(&relative) {
                return Err(M6SenderAckError::UnsafePath(path));
            }
            read_collection_archive_remainder(
                root,
                &path,
                expected,
                expected_directories,
                snapshot,
                depth + 1,
            )?;
        } else if file_type.is_file() {
            let observation = expected
                .get(&relative)
                .ok_or_else(|| M6SenderAckError::UnsafePath(path.clone()))?;
            let maximum = usize::try_from(observation.byte_length).map_err(|_| {
                M6SenderAckError::ResourceExhausted(
                    "collection observation length does not fit this host".to_string(),
                )
            })?;
            let bytes = read_regular_bounded(&path, maximum)?;
            if bytes.len() as u64 != observation.byte_length
                || ContentDigest::from_bytes(&bytes) != observation.content_digest
            {
                return Err(M6SenderAckError::Integrity(format!(
                    "retained route file '{}' differs from its collection observation",
                    relative.display()
                )));
            }
            snapshot.insert(relative, bytes);
        } else {
            return Err(M6SenderAckError::UnsafePath(path));
        }
    }
    Ok(())
}

fn remove_confined_directory(parent: &Path, root: &Path) -> Result<(), M6SenderAckError> {
    if root.parent() != Some(parent) {
        return Err(M6SenderAckError::UnsafePath(root.to_path_buf()));
    }
    let mut directories = Vec::new();
    collect_directories(root, root, &mut directories, 0)?;
    let mut files = Vec::new();
    collect_files(root, root, &mut files, 0)?;
    for path in files {
        reject_symlink(&path)?;
        fs::remove_file(&path).map_err(|source| M6SenderAckError::io(&path, source))?;
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in directories {
        fs::remove_dir(&path).map_err(|source| M6SenderAckError::io(&path, source))?;
    }
    fs::remove_dir(root).map_err(|source| M6SenderAckError::io(root, source))
}

fn collect_directories(
    root: &Path,
    current: &Path,
    output: &mut Vec<PathBuf>,
    depth: usize,
) -> Result<(), M6SenderAckError> {
    if depth > 4 {
        return Err(M6SenderAckError::UnsafePath(current.to_path_buf()));
    }
    for entry in fs::read_dir(current).map_err(|source| M6SenderAckError::io(current, source))? {
        let entry = entry.map_err(|source| M6SenderAckError::io(current, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if entry
            .file_type()
            .map_err(|source| M6SenderAckError::io(&path, source))?
            .is_dir()
        {
            if !path.starts_with(root) {
                return Err(M6SenderAckError::UnsafePath(path));
            }
            output.push(path.clone());
            collect_directories(root, &path, output, depth + 1)?;
        }
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    current: &Path,
    output: &mut Vec<PathBuf>,
    depth: usize,
) -> Result<(), M6SenderAckError> {
    if depth > 4 {
        return Err(M6SenderAckError::UnsafePath(current.to_path_buf()));
    }
    for entry in fs::read_dir(current).map_err(|source| M6SenderAckError::io(current, source))? {
        let entry = entry.map_err(|source| M6SenderAckError::io(current, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let file_type = entry
            .file_type()
            .map_err(|source| M6SenderAckError::io(&path, source))?;
        if file_type.is_dir() {
            collect_files(root, &path, output, depth + 1)?;
        } else if file_type.is_file() {
            output.push(path);
        } else {
            return Err(M6SenderAckError::UnsafePath(path));
        }
    }
    Ok(())
}

fn recover_staging(root: &Path) -> Result<(), M6SenderAckError> {
    for entry in fs::read_dir(root).map_err(|source| M6SenderAckError::io(root, source))? {
        let entry = entry.map_err(|source| M6SenderAckError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| M6SenderAckError::UnsafePath(path.clone()))?
            .to_string();
        if !name.starts_with(STAGING_PREFIX) {
            return Err(M6SenderAckError::UnsafePath(path));
        }
        let file_type = entry
            .file_type()
            .map_err(|source| M6SenderAckError::io(&path, source))?;
        if file_type.is_file() {
            fs::remove_file(&path).map_err(|source| M6SenderAckError::io(&path, source))?;
        } else if file_type.is_dir() {
            remove_confined_directory(root, &path)?;
        } else {
            return Err(M6SenderAckError::UnsafePath(path));
        }
    }
    sync_directory(root)
}

fn enforce_file_bound(root: &Path, maximum: u32, label: &str) -> Result<(), M6SenderAckError> {
    let count = bounded_regular_files(root, maximum as usize)?.len();
    if count >= maximum as usize {
        return Err(M6SenderAckError::ResourceExhausted(format!(
            "{label} reached its {maximum}-record bound"
        )));
    }
    Ok(())
}

fn enforce_combined_file_bound(
    roots: &[&Path],
    maximum: u32,
    label: &str,
) -> Result<(), M6SenderAckError> {
    let mut count = 0_usize;
    for root in roots {
        count = count
            .checked_add(bounded_regular_files(root, maximum as usize)?.len())
            .ok_or_else(|| {
                M6SenderAckError::ResourceExhausted(format!("{label} count overflowed"))
            })?;
    }
    if count >= maximum as usize {
        return Err(M6SenderAckError::ResourceExhausted(format!(
            "{label} reached its {maximum}-record bound"
        )));
    }
    Ok(())
}

fn enforce_directory_bound(
    root: &Path,
    maximum: u32,
    suffix: &str,
    label: &str,
) -> Result<(), M6SenderAckError> {
    let count = bounded_directories(root, maximum as usize, suffix)?.len();
    if count >= maximum as usize {
        return Err(M6SenderAckError::ResourceExhausted(format!(
            "{label} reached its {maximum}-unit bound"
        )));
    }
    Ok(())
}

fn bounded_regular_files(root: &Path, maximum: usize) -> Result<Vec<PathBuf>, M6SenderAckError> {
    ensure_real_directory(root)?;
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).map_err(|source| M6SenderAckError::io(root, source))? {
        let entry = entry.map_err(|source| M6SenderAckError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if !entry
            .file_type()
            .map_err(|source| M6SenderAckError::io(&path, source))?
            .is_file()
            || !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(RECORD_SUFFIX))
        {
            return Err(M6SenderAckError::UnsafePath(path));
        }
        paths.push(path);
        if paths.len() > maximum {
            return Err(M6SenderAckError::ResourceExhausted(format!(
                "record directory '{}' exceeds its {maximum}-entry bound",
                root.display()
            )));
        }
    }
    paths.sort();
    Ok(paths)
}

fn bounded_directories(
    root: &Path,
    maximum: usize,
    suffix: &str,
) -> Result<Vec<PathBuf>, M6SenderAckError> {
    ensure_real_directory(root)?;
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).map_err(|source| M6SenderAckError::io(root, source))? {
        let entry = entry.map_err(|source| M6SenderAckError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if !entry
            .file_type()
            .map_err(|source| M6SenderAckError::io(&path, source))?
            .is_dir()
            || !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(suffix))
        {
            return Err(M6SenderAckError::UnsafePath(path));
        }
        paths.push(path);
        if paths.len() > maximum {
            return Err(M6SenderAckError::ResourceExhausted(format!(
                "directory '{}' exceeds its {maximum}-entry bound",
                root.display()
            )));
        }
    }
    paths.sort();
    Ok(paths)
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M6SenderAckError> {
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| M6SenderAckError::io(path, source))?;
    let canonical = fs::canonicalize(path).map_err(|source| M6SenderAckError::io(path, source))?;
    ensure_real_directory(&canonical)?;
    Ok(canonical)
}

fn secure_existing_root(path: &Path) -> Result<PathBuf, M6SenderAckError> {
    reject_symlink(path)?;
    let canonical = fs::canonicalize(path).map_err(|source| M6SenderAckError::io(path, source))?;
    ensure_real_directory(&canonical)?;
    Ok(canonical)
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M6SenderAckError> {
    validate_identifier("sender ACK directory", name)?;
    let path = root.join(name);
    reject_symlink_if_present(&path)?;
    match fs::create_dir(&path) {
        Ok(()) => sync_directory(root)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(M6SenderAckError::io(&path, source)),
    }
    ensure_real_directory(&path)?;
    let canonical =
        fs::canonicalize(&path).map_err(|source| M6SenderAckError::io(&path, source))?;
    if canonical.parent() != Some(root) {
        return Err(M6SenderAckError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn create_direct_child(parent: &Path, path: &Path) -> Result<(), M6SenderAckError> {
    if path.parent() != Some(parent) {
        return Err(M6SenderAckError::UnsafePath(path.to_path_buf()));
    }
    reject_symlink_if_present(path)?;
    fs::create_dir(path).map_err(|source| M6SenderAckError::io(path, source))?;
    sync_directory(parent)
}

fn ensure_real_directory(path: &Path) -> Result<(), M6SenderAckError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6SenderAckError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(M6SenderAckError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn ensure_disjoint(left: &Path, right: &Path) -> Result<(), M6SenderAckError> {
    if left == right || left.starts_with(right) || right.starts_with(left) {
        return Err(M6SenderAckError::InvalidConfiguration(
            "sender endpoint and neutral route roots must be disjoint".to_string(),
        ));
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M6SenderAckError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(M6SenderAckError::UnsafePath(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M6SenderAckError::io(path, source)),
    }
}

fn reject_symlink(path: &Path) -> Result<(), M6SenderAckError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6SenderAckError::io(path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(M6SenderAckError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), M6SenderAckError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| M6SenderAckError::io(path, source))
}

fn sync_all_directories(root: &Path) -> Result<(), M6SenderAckError> {
    let mut directories = vec![root.to_path_buf()];
    collect_directories(root, root, &mut directories, 0)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    directories.dedup();
    for directory in directories {
        sync_directory(&directory)?;
    }
    Ok(())
}

fn ack_intent_path(root: &Path, digest: &ContentDigest) -> PathBuf {
    root.join(format!("{}.json", digest.file_stem()))
}

fn correlation_path(root: &Path, sender_message_digest: &ContentDigest) -> PathBuf {
    root.join(format!("{}.json", sender_message_digest.file_stem()))
}

fn control_ack_intent_path(root: &Path, acknowledgement_message_digest: &ContentDigest) -> PathBuf {
    root.join(format!(
        "{}.json",
        acknowledgement_message_digest.file_stem()
    ))
}

fn control_ack_receipt_path(
    root: &Path,
    acknowledgement_message_digest: &ContentDigest,
) -> PathBuf {
    root.join(format!(
        "{}.json",
        acknowledgement_message_digest.file_stem()
    ))
}

fn collection_intent_path(root: &Path, sender_message_digest: &ContentDigest) -> PathBuf {
    root.join(format!("{}.json", sender_message_digest.file_stem()))
}

fn collection_receipt_path(root: &Path, sender_message_digest: &ContentDigest) -> PathBuf {
    root.join(format!("{}.json", sender_message_digest.file_stem()))
}

fn collection_journal_root(root: &Path, sender_message_digest: &ContentDigest) -> PathBuf {
    root.join(format!("{}.journal", sender_message_digest.file_stem()))
}

fn route_collection_fact_path(root: &Path, sender_message_digest: &ContentDigest) -> PathBuf {
    root.join(format!("{}.json", sender_message_digest.file_stem()))
}

fn source_archive_unit_name(sender_message_digest: &ContentDigest) -> String {
    format!("source-{}", delivery_unit_name(sender_message_digest))
}

fn acknowledgement_archive_unit_name(acknowledgement_message_digest: &ContentDigest) -> String {
    format!(
        "acknowledgement-{}",
        delivery_unit_name(acknowledgement_message_digest)
    )
}

fn raw_unit_path(root: &Path, acknowledgement_message_digest: &ContentDigest) -> PathBuf {
    root.join(format!(
        "{}{RAW_SUFFIX}",
        acknowledgement_message_digest.file_stem()
    ))
}

fn source_receipt_path(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!(
        "{}.json",
        ContentDigest::from_bytes(logical_operation_id.as_bytes()).file_stem()
    ))
}

fn revocation_source_receipt_path(root: &Path, logical_operation_id: &str) -> PathBuf {
    root.join(format!(
        "{}{RECORD_SUFFIX}",
        revocation_operation_stem(logical_operation_id)
    ))
}

fn delivery_unit_name(message_digest: &ContentDigest) -> String {
    format!("{}.unit", message_digest.file_stem())
}

fn validate_identifier(subject: &str, value: &str) -> Result<(), M6SenderAckError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value
            .chars()
            .any(|character| character.is_control() || character == '\0')
    {
        return Err(M6SenderAckError::InvalidConfiguration(format!(
            "{subject} is blank, unsafe, or exceeds {MAX_IDENTIFIER_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_relative_string(value: &str) -> Result<(), M6SenderAckError> {
    validate_relative_path(Path::new(value))
}

fn validate_relative_path(path: &Path) -> Result<(), M6SenderAckError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().count() > 4
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(M6SenderAckError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn relative_path_string(path: &Path) -> Result<String, M6SenderAckError> {
    validate_relative_path(path)?;
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(M6SenderAckError::UnsafePath(path.to_path_buf()));
        };
        parts.push(
            part.to_str()
                .ok_or_else(|| M6SenderAckError::UnsafePath(path.to_path_buf()))?,
        );
    }
    Ok(parts.join("/"))
}

fn strictly_sorted_unique_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn require_meaningful_digest(
    subject: &str,
    digest: &ContentDigest,
) -> Result<(), M6SenderAckError> {
    if digest == &ContentDigest::from_bytes(&[]) {
        return Err(M6SenderAckError::Integrity(format!(
            "{subject} uses the empty-content sentinel"
        )));
    }
    Ok(())
}

fn require_digest(
    subject: &str,
    expected: &ContentDigest,
    actual: &ContentDigest,
) -> Result<(), M6SenderAckError> {
    if expected == actual {
        Ok(())
    } else {
        Err(M6SenderAckError::Integrity(format!(
            "{subject} digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

fn digest_domain<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ContentDigest, M6SenderAckError> {
    let mut bytes = Vec::from(domain);
    bytes.extend_from_slice(&canonical_json(value)?);
    Ok(ContentDigest::from_bytes(&bytes))
}

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, M6SenderAckError> {
    let value = serde_json::to_value(value)
        .map_err(|error| M6SenderAckError::Serialization(error.to_string()))?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    if output.len() > MAX_RECORD_BYTES {
        return Err(M6SenderAckError::ResourceExhausted(format!(
            "canonical ACK record is {} bytes; limit is {MAX_RECORD_BYTES}",
            output.len()
        )));
    }
    Ok(output)
}

fn write_canonical_value(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), M6SenderAckError> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" })
        }
        serde_json::Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        serde_json::Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|error| M6SenderAckError::Serialization(error.to_string()))?
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
                        .map_err(|error| M6SenderAckError::Serialization(error.to_string()))?
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

fn parse_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, M6SenderAckError> {
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| M6SenderAckError::Serialization(error.to_string()))?;
    if canonical_json(&value)? != bytes {
        return Err(M6SenderAckError::Integrity(
            "record is not in canonical JSON form".to_string(),
        ));
    }
    Ok(value)
}

fn parse_struct_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, M6SenderAckError> {
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| M6SenderAckError::Serialization(error.to_string()))?;
    let expected = serde_json::to_vec(&value)
        .map_err(|error| M6SenderAckError::Serialization(error.to_string()))?;
    if expected != bytes {
        return Err(M6SenderAckError::Integrity(
            "upstream sender receipt is not in its canonical struct encoding".to_string(),
        ));
    }
    Ok(value)
}

fn load_canonical_file<T: DeserializeOwned + Serialize>(
    path: &Path,
    maximum: usize,
) -> Result<T, M6SenderAckError> {
    parse_canonical(&read_regular_bounded(path, maximum)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m6_identity::{
        AttachmentInput, DeterministicClock, DeterministicNonceSource, ExportManifestPayload,
        FactoryIdentityDocument, FactorySigner, ManifestIssuer, NonceSource,
        RevocationManifestPayload, RouteResourceProfile,
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m6-sender-ack-{label}-{}-{}",
                std::process::id(),
                TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create sender ACK test root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.exists() && std::env::var_os("KEEP_M6_SENDER_ACK_TEST_ROOT").is_none() {
                fs::remove_dir_all(&self.0).expect("remove sender ACK test root");
            }
        }
    }

    struct TestRig {
        _root: TestRoot,
        sender_root: PathBuf,
        receiver_root: PathBuf,
        route_root: PathBuf,
        route: RouteDefinition,
        clock: Arc<DeterministicClock>,
        sender_nonce: Arc<DeterministicNonceSource>,
        receiver_nonce: Arc<DeterministicNonceSource>,
    }

    impl TestRig {
        fn new(label: &str) -> Self {
            Self::with_resource_profile(
                label,
                RouteResourceProfile::bounded_default().expect("route resource profile"),
            )
        }

        fn with_resource_profile(label: &str, resource_profile: RouteResourceProfile) -> Self {
            let root = TestRoot::new(label);
            let sender_root = root.0.join("sender");
            let receiver_root = root.0.join("receiver");
            let route_root = root.0.join("route");
            let sender = sender_signer();
            let receiver = receiver_signer();
            let schemas = vec![content("package-schema")];
            let interfaces = vec![content("interface-schema")];
            let exchange_policy = content("exchange-policy");
            let sender_identity = FactoryIdentityDocument::new(
                "factory:sender",
                &sender,
                1,
                1_000_000_000_000,
                schemas.clone(),
                interfaces.clone(),
                content("sender-authority"),
                exchange_policy.clone(),
            )
            .expect("sender identity");
            let receiver_identity = FactoryIdentityDocument::new(
                "factory:receiver",
                &receiver,
                1,
                1_000_000_000_000,
                schemas,
                interfaces,
                content("receiver-authority"),
                exchange_policy.clone(),
            )
            .expect("receiver identity");
            let route = RouteDefinition::new(
                format!("route:sender-ack-{label}"),
                1,
                &sender_identity,
                &receiver_identity,
                exchange_policy,
                resource_profile,
            )
            .expect("route definition");
            GovernedFilesystemSpool::initialize(
                &route_root,
                &sender_root,
                &receiver_root,
                route.clone(),
            )
            .expect("initialize route");
            Self {
                _root: root,
                sender_root,
                receiver_root,
                route_root,
                route,
                clock: Arc::new(DeterministicClock::new(1_000_000)),
                sender_nonce: Arc::new(DeterministicNonceSource::new([0x51; 32])),
                receiver_nonce: Arc::new(DeterministicNonceSource::new([0x72; 32])),
            }
        }

        fn config(&self) -> M6SenderAckRuntimeConfig {
            M6SenderAckRuntimeConfig {
                endpoint_root: self.sender_root.clone(),
                route_root: self.route_root.clone(),
                expected_route_definition_digest: self.route.definition_digest.clone(),
                max_acknowledgements: 128,
                max_collection_records: 128,
                max_source_receipts_per_kind: 128,
            }
        }

        fn open(&self) -> Result<M6SenderAckRuntime, M6SenderAckError> {
            let clock: Arc<dyn Clock> = self.clock.clone();
            M6SenderAckRuntime::open(self.config(), sender_signer(), clock)
        }

        fn sender_issuer(&self) -> ManifestIssuer {
            let clock: Arc<dyn Clock> = self.clock.clone();
            let nonce: Arc<dyn NonceSource> = self.sender_nonce.clone();
            ManifestIssuer::open_or_initialize(
                &self.sender_root,
                self.route.clone(),
                RouteEndpointRole::Sender,
                clock,
                nonce,
            )
            .expect("open sender issuer")
        }

        fn receiver_issuer(&self) -> ManifestIssuer {
            let clock: Arc<dyn Clock> = self.clock.clone();
            let nonce: Arc<dyn NonceSource> = self.receiver_nonce.clone();
            ManifestIssuer::open_or_initialize(
                &self.receiver_root,
                self.route.clone(),
                RouteEndpointRole::Receiver,
                clock,
                nonce,
            )
            .expect("open receiver issuer")
        }

        fn sender_spool(&self) -> GovernedFilesystemSpool {
            GovernedFilesystemSpool::open(
                &self.route_root,
                &self.sender_root,
                RouteEndpointRole::Sender,
                &self.route.definition_digest,
            )
            .expect("open sender spool")
        }

        fn receiver_spool(&self) -> GovernedFilesystemSpool {
            GovernedFilesystemSpool::open(
                &self.route_root,
                &self.receiver_root,
                RouteEndpointRole::Receiver,
                &self.route.definition_digest,
            )
            .expect("open receiver spool")
        }

        fn publish_export(&self, operation: &str) -> IssuedManifest {
            let endpoint_owner =
                acquire_sender_endpoint_owner(&self.sender_root).expect("sender endpoint owner");
            let mut issuer = self.sender_issuer();
            let payload = ExportManifestPayload {
                component_digest: content(&format!("component:{operation}")),
                export_bundle_digest: content(&format!("bundle:{operation}")),
                package_bytes_digest: content(&format!("package-bytes:{operation}")),
                package_digest: content(&format!("package:{operation}")),
            };
            let issued = issuer
                .issue(
                    &sender_signer(),
                    ManifestPayload::Export(payload.clone()),
                    vec![AttachmentInput::new(
                        "m5-export-bundle",
                        "application/json",
                        format!("export:{operation}").into_bytes(),
                    )],
                    60_000,
                )
                .expect("issue source export");
            let spool = self.sender_spool();
            let owner = spool.acquire_role().expect("sender route role");
            spool
                .publish(&owner, &issued)
                .expect("publish source export");
            let mut receipt = SenderExportReceipt {
                schema: SENDER_EXPORT_RECEIPT_SCHEMA.to_string(),
                logical_operation_id: operation.to_string(),
                outer_request_digest: content(&format!("outer:{operation}")),
                coordinator_request_digest: content(&format!("coordinator:{operation}")),
                route_definition_digest: self.route.definition_digest.clone(),
                route_id: self.route.route_id.clone(),
                route_generation: self.route.generation,
                message_digest: issued.manifest.message_digest.clone(),
                sequence: issued.manifest.unsigned.sequence,
                bundle_digest: payload.export_bundle_digest,
                package_digest: payload.package_digest,
                active_snapshot_digest: content(&format!("active:{operation}")),
                authorization_digest: content(&format!("authorization:{operation}")),
                authorization_consumption_digest: content(&format!("consumption:{operation}")),
                ready_delivery_digest: source_delivery_digest(
                    &issued,
                    SenderPublicationKind::Export,
                )
                .expect("source delivery digest"),
                committed_at_ms: self.clock.now_ms().expect("clock"),
                receipt_digest: ContentDigest::from_bytes(&[]),
            };
            receipt.receipt_digest = digest_domain(
                EXPORT_RECEIPT_DOMAIN,
                &(
                    &receipt.schema,
                    &receipt.logical_operation_id,
                    &receipt.outer_request_digest,
                    &receipt.coordinator_request_digest,
                    &receipt.route_definition_digest,
                    &receipt.route_id,
                    receipt.route_generation,
                    &receipt.message_digest,
                    receipt.sequence,
                    &receipt.bundle_digest,
                    &receipt.package_digest,
                    &receipt.active_snapshot_digest,
                    &receipt.authorization_digest,
                    &receipt.authorization_consumption_digest,
                    &receipt.ready_delivery_digest,
                    receipt.committed_at_ms,
                ),
            )
            .expect("export receipt digest");
            validate_export_receipt(&receipt, &self.route).expect("valid export receipt");
            let receipts = self.sender_root.join(EXPORT_RECEIPTS_DIRECTORY);
            fs::create_dir_all(&receipts).expect("create export receipts");
            fs::write(
                source_receipt_path(&receipts, operation),
                serde_json::to_vec(&receipt).expect("encode export receipt"),
            )
            .expect("persist export receipt");
            drop(owner);
            drop(spool);
            drop(issuer);
            drop(endpoint_owner);
            issued
        }

        fn publish_revocation(&self, operation: &str) -> IssuedManifest {
            let endpoint_owner =
                acquire_sender_endpoint_owner(&self.sender_root).expect("sender endpoint owner");
            let mut issuer = self.sender_issuer();
            let target_kind = RevocationTargetKindV1::SourcePackage;
            let payload = RevocationManifestPayload {
                authorization_digest: content(&format!("prior-authorization:{operation}")),
                reason: format!("revoke {operation}"),
                target_identity: content(&format!("target:{operation}")),
                target_kind: target_kind.label().to_string(),
            };
            let issued = issuer
                .issue(
                    &sender_signer(),
                    ManifestPayload::Revocation(payload.clone()),
                    vec![],
                    60_000,
                )
                .expect("issue source revocation");
            let spool = self.sender_spool();
            let owner = spool.acquire_role().expect("sender route role");
            spool
                .publish(&owner, &issued)
                .expect("publish source revocation");
            let mut receipt = SenderRevocationReceipt {
                schema: SENDER_REVOCATION_RECEIPT_SCHEMA.to_string(),
                logical_operation_id: operation.to_string(),
                request_digest: content(&format!("request:{operation}")),
                coordinator_request_digest: content(&format!("coordinator:{operation}")),
                route_definition_digest: self.route.definition_digest.clone(),
                route_generation: self.route.generation,
                sender_identity_document_digest: self.route.sender.identity_document_digest.clone(),
                receiver_identity_document_digest: self
                    .route
                    .receiver
                    .identity_document_digest
                    .clone(),
                target_kind,
                target_identity: payload.target_identity,
                reason: payload.reason,
                prior_source_authorization_evidence_digest: payload.authorization_digest,
                message_digest: issued.manifest.message_digest.clone(),
                sequence: issued.manifest.unsigned.sequence,
                nonce: issued.manifest.unsigned.nonce.clone(),
                previous_message_digest: issued.manifest.unsigned.previous_message_digest.clone(),
                current_revocation_authorization_digest: content(&format!(
                    "current-authorization:{operation}"
                )),
                current_revocation_binding_digest: content(&format!("current-binding:{operation}")),
                authorization_consumption_digest: content(&format!("consumption:{operation}")),
                route_delivery_digest: source_delivery_digest(
                    &issued,
                    SenderPublicationKind::Revocation,
                )
                .expect("revocation delivery digest"),
                committed_at_ms: self.clock.now_ms().expect("clock"),
                receipt_digest: ContentDigest::from_bytes(&[]),
            };
            receipt.receipt_digest = digest_domain(
                REVOCATION_RECEIPT_DOMAIN,
                &RevocationReceiptDigestMaterial {
                    schema: &receipt.schema,
                    logical_operation_id: &receipt.logical_operation_id,
                    request_digest: &receipt.request_digest,
                    coordinator_request_digest: &receipt.coordinator_request_digest,
                    route_definition_digest: &receipt.route_definition_digest,
                    route_generation: receipt.route_generation,
                    sender_identity_document_digest: &receipt.sender_identity_document_digest,
                    receiver_identity_document_digest: &receipt.receiver_identity_document_digest,
                    target_kind: receipt.target_kind,
                    target_identity: &receipt.target_identity,
                    reason: &receipt.reason,
                    prior_source_authorization_evidence_digest: &receipt
                        .prior_source_authorization_evidence_digest,
                    message_digest: &receipt.message_digest,
                    sequence: receipt.sequence,
                    nonce: &receipt.nonce,
                    previous_message_digest: &receipt.previous_message_digest,
                    current_revocation_authorization_digest: &receipt
                        .current_revocation_authorization_digest,
                    current_revocation_binding_digest: &receipt.current_revocation_binding_digest,
                    authorization_consumption_digest: &receipt.authorization_consumption_digest,
                    route_delivery_digest: &receipt.route_delivery_digest,
                    committed_at_ms: receipt.committed_at_ms,
                },
            )
            .expect("revocation receipt digest");
            validate_revocation_receipt(&receipt, &self.route).expect("valid revocation receipt");
            let receipts = self.sender_root.join(REVOCATION_RECEIPTS_DIRECTORY);
            fs::create_dir_all(&receipts).expect("create revocation receipts");
            fs::write(
                revocation_source_receipt_path(&receipts, operation),
                canonical_json(&receipt).expect("encode revocation receipt"),
            )
            .expect("persist revocation receipt");
            drop(owner);
            drop(spool);
            drop(issuer);
            drop(endpoint_owner);
            issued
        }

        fn issue_acknowledgement(
            &self,
            sender_message_digest: &ContentDigest,
            disposition: &str,
            with_attachment: bool,
        ) -> IssuedManifest {
            let mut issuer = self.receiver_issuer();
            let attachments = if with_attachment {
                vec![AttachmentInput::new(
                    "forbidden-ack-attachment",
                    "application/octet-stream",
                    b"forbidden".to_vec(),
                )]
            } else {
                vec![]
            };
            issuer
                .issue(
                    &receiver_signer(),
                    ManifestPayload::ReceiverAcknowledgement(ReceiverAcknowledgementPayload {
                        disposition: disposition.to_string(),
                        intake_record_digest: content(&format!("intake:{sender_message_digest}")),
                        raw_quarantine_digest: content(&format!("raw:{sender_message_digest}")),
                        receiver_transaction_digest: content(&format!(
                            "transaction:{sender_message_digest}:{disposition}"
                        )),
                        sender_message_digest: sender_message_digest.clone(),
                    }),
                    attachments,
                    60_000,
                )
                .expect("issue receiver acknowledgement")
        }

        fn publish_acknowledgement(
            &self,
            sender_message_digest: &ContentDigest,
            disposition: &str,
        ) -> IssuedManifest {
            let issued = self.issue_acknowledgement(sender_message_digest, disposition, false);
            let spool = self.receiver_spool();
            let owner = spool.acquire_role().expect("receiver route role");
            spool
                .publish(&owner, &issued)
                .expect("publish receiver acknowledgement");
            issued
        }

        fn publish_acknowledgement_with_attachment(
            &self,
            sender_message_digest: &ContentDigest,
        ) -> IssuedManifest {
            let issued = self.issue_acknowledgement(sender_message_digest, "healthy", true);
            let spool = self.receiver_spool();
            let owner = spool.acquire_role().expect("receiver route role");
            spool
                .publish(&owner, &issued)
                .expect("publish attached receiver acknowledgement");
            issued
        }

        fn place_manual_receiver_unit(&self, issued: &IssuedManifest) {
            let spool = self.receiver_spool();
            let path = spool.outbound_ready_unit_directory(&issued.manifest.message_digest);
            fs::create_dir(&path).expect("create adversarial ready unit");
            let manifest_bytes = issued
                .manifest
                .canonical_bytes()
                .expect("canonical adversarial manifest");
            fs::write(path.join(MANIFEST_FILE), &manifest_bytes)
                .expect("write adversarial manifest");
            fs::write(
                path.join(DELIVERY_COMMIT_FILE),
                canonical_json(&DeliveryCommitMarker {
                    manifest_bytes_digest: ContentDigest::from_bytes(&manifest_bytes),
                    message_digest: issued.manifest.message_digest.clone(),
                    schema: DELIVERY_COMMIT_SCHEMA.to_string(),
                })
                .expect("encode adversarial commit"),
            )
            .expect("write adversarial commit");
        }
    }

    fn content(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(label.as_bytes())
    }

    fn rebind_resource_profile(mut profile: RouteResourceProfile) -> RouteResourceProfile {
        profile.profile_digest = digest_domain(
            b"wasm-biotic:m6:resource-profile:v2\0",
            &(
                (
                    profile.accepted_clock_skew_ms,
                    profile.allowed_clock_regression_ms,
                    profile.crash_recovery_interval_ms,
                    profile.max_attachment_bytes,
                    profile.max_attachment_count,
                    profile.max_delivery_bytes,
                    profile.max_evidence_bytes,
                    profile.max_manifest_bytes,
                    profile.max_message_lifetime_ms,
                    profile.max_package_bytes,
                ),
                (
                    profile.max_proving_cases,
                    profile.max_proving_fuel,
                    profile.max_proving_instances,
                    profile.max_proving_memory_bytes,
                    profile.max_quarantine_units,
                    profile.max_ready_units,
                    profile.max_recovery_attempts,
                    profile.max_replay_records,
                    profile.max_retry_attempts,
                    profile.max_revocation_lifetime_ms,
                    profile.max_revocation_records,
                    profile.max_staged_units,
                    profile.max_transaction_records,
                    profile.route_delivery_retention_ms,
                    &profile.schema,
                ),
            ),
        )
        .expect("route resource profile digest");
        profile.validate().expect("valid route resource profile");
        profile
    }

    fn sender_signer() -> FactorySigner {
        FactorySigner::from_seed("key:sender-v1", [0x51; 32]).expect("sender signer")
    }

    fn receiver_signer() -> FactorySigner {
        FactorySigner::from_seed("key:receiver-v1", [0x72; 32]).expect("receiver signer")
    }

    fn expect_crash<T>(result: Result<T, M6SenderAckError>, point: SenderAckCrashPoint) {
        assert!(matches!(
            result,
            Err(M6SenderAckError::InjectedCrash(observed)) if observed == point
        ));
    }

    #[test]
    fn route_profile_caps_ack_counts_journals_sources_and_bytes_at_plus_one() {
        let mut profile = RouteResourceProfile::bounded_default().expect("route resource profile");
        profile.max_replay_records = 8;
        profile.max_revocation_records = 6;
        profile.max_transaction_records = 4;
        profile.max_evidence_bytes = 512;
        let profile = rebind_resource_profile(profile);
        let rig = TestRig::with_resource_profile("route-resource-boundaries", profile);

        let mut exact = rig.config();
        exact.max_acknowledgements = rig.route.resource_profile.max_replay_records;
        exact.max_collection_records = rig.route.resource_profile.max_transaction_records;
        exact.max_source_receipts_per_kind = rig.route.resource_profile.max_revocation_records;
        exact
            .validate_for_resource_profile(&rig.route.resource_profile)
            .expect("exact ACK route boundaries");
        drop(
            M6SenderAckRuntime::open(exact.clone(), sender_signer(), rig.clock.clone())
                .expect("open at exact ACK route boundaries"),
        );

        let mut acknowledgement_plus_one = exact.clone();
        acknowledgement_plus_one.max_acknowledgements += 1;
        assert!(matches!(
            acknowledgement_plus_one.validate_for_resource_profile(&rig.route.resource_profile),
            Err(M6SenderAckError::InvalidConfiguration(_))
        ));
        assert!(matches!(
            M6SenderAckRuntime::open(acknowledgement_plus_one, sender_signer(), rig.clock.clone(),),
            Err(M6SenderAckError::InvalidConfiguration(_))
        ));

        let mut collection_plus_one = exact.clone();
        collection_plus_one.max_collection_records += 1;
        assert!(matches!(
            collection_plus_one.validate_for_resource_profile(&rig.route.resource_profile),
            Err(M6SenderAckError::InvalidConfiguration(_))
        ));
        assert!(matches!(
            M6SenderAckRuntime::open(collection_plus_one, sender_signer(), rig.clock.clone()),
            Err(M6SenderAckError::InvalidConfiguration(_))
        ));

        let mut source_plus_one = exact;
        source_plus_one.max_source_receipts_per_kind += 1;
        assert!(matches!(
            source_plus_one.validate_for_resource_profile(&rig.route.resource_profile),
            Err(M6SenderAckError::InvalidConfiguration(_))
        ));
        assert!(matches!(
            M6SenderAckRuntime::open(source_plus_one, sender_signer(), rig.clock.clone()),
            Err(M6SenderAckError::InvalidConfiguration(_))
        ));

        let record_limit = route_record_byte_limit(&rig.route);
        assert_eq!(record_limit, 512);
        enforce_route_byte_limit(&vec![0_u8; record_limit], record_limit, "test ACK record")
            .expect("exact ACK record byte boundary");
        assert!(matches!(
            enforce_route_byte_limit(
                &vec![0_u8; record_limit + 1],
                record_limit,
                "test ACK record",
            ),
            Err(M6SenderAckError::ResourceExhausted(_))
        ));
        assert_eq!(acknowledgement_completion_byte_limit(&rig.route), 512);
    }

    #[test]
    fn reopen_rejects_one_ack_named_in_both_normal_and_control_intent_stores() {
        let rig = TestRig::new("duplicate-normal-control-intent");
        let export = rig.publish_export("dual-classification-source");
        let acknowledgement =
            rig.publish_acknowledgement(&export.manifest.message_digest, "healthy");
        {
            let mut runtime = rig.open().expect("open sender ACK runtime");
            runtime
                .consume_acknowledgement(&acknowledgement.manifest.message_digest)
                .expect("commit genuine correlated ACK intent");
        }

        let correlated_intent = ack_intent_path(
            &rig.sender_root.join(ACK_INTENTS_DIRECTORY),
            &acknowledgement.manifest.message_digest,
        );
        let control_intent = control_ack_intent_path(
            &rig.sender_root.join(CONTROL_ACK_INTENTS_DIRECTORY),
            &acknowledgement.manifest.message_digest,
        );
        assert!(correlated_intent.is_file());
        assert!(!control_intent.exists());
        fs::copy(&correlated_intent, &control_intent)
            .expect("duplicate exact ACK intent filename across classification stores");

        match rig.open() {
            Err(M6SenderAckError::Integrity(message)) => assert_eq!(
                message,
                "one receiver ACK has both correlated and control-only intake intents"
            ),
            Err(other) => panic!("unexpected duplicate intent classification error: {other}"),
            Ok(_) => panic!("reopen accepted one ACK under two terminal classifications"),
        }
    }

    #[test]
    fn bobs_correlates_export_and_revocation_acknowledgements_without_adoption() {
        let rig = TestRig::new("positive-export-revocation");
        let export = rig.publish_export("export-one");
        let revocation = rig.publish_revocation("revocation-two");
        let revocation_receipts = rig.sender_root.join(REVOCATION_RECEIPTS_DIRECTORY);
        let canonical_revocation_receipt =
            revocation_source_receipt_path(&revocation_receipts, "revocation-two");
        assert!(canonical_revocation_receipt.exists());
        assert_ne!(
            canonical_revocation_receipt,
            source_receipt_path(&revocation_receipts, "revocation-two")
        );
        let export_ack = rig.publish_acknowledgement(&export.manifest.message_digest, "healthy");
        let revocation_ack = rig
            .publish_acknowledgement(&revocation.manifest.message_digest, "revocation_contained");
        let mut runtime = rig.open().expect("open sender ACK runtime");

        let export_receipt = runtime
            .consume_acknowledgement(&export_ack.manifest.message_digest)
            .expect("correlate export ACK");
        assert_eq!(
            export_receipt.source.publication_kind,
            SenderPublicationKind::Export
        );
        assert_eq!(
            export_receipt.source.sender_message_digest,
            export.manifest.message_digest
        );
        assert_eq!(export_receipt.disposition, "healthy");
        assert!(export_receipt.intake_only);
        assert!(!export_receipt.adoption_inferred);

        let revocation_receipt = runtime
            .consume_acknowledgement(&revocation_ack.manifest.message_digest)
            .expect("correlate revocation ACK");
        assert_eq!(
            revocation_receipt.source.publication_kind,
            SenderPublicationKind::Revocation
        );
        assert_eq!(revocation_receipt.disposition, "revocation_contained");
        assert!(revocation_receipt.intake_only);
        assert!(!revocation_receipt.adoption_inferred);
        assert_eq!(runtime.last_acknowledgement_sequence(), 2);
    }

    #[test]
    fn bobs_control_ack_path_terminally_advances_unknown_and_duplicate_source_rejections() {
        let rig = TestRig::new("control-ack-chain");
        let accepted_source = rig.publish_export("accepted-source");
        let later_source = rig.publish_export("later-source");
        let unknown_sender_message = content("tampered-or-false-route-message");
        let unknown_rejection =
            rig.publish_acknowledgement(&unknown_sender_message, "validation_rejected");
        let accepted_ack =
            rig.publish_acknowledgement(&accepted_source.manifest.message_digest, "healthy");
        let replay_rejection = rig.publish_acknowledgement(
            &accepted_source.manifest.message_digest,
            "validation_rejected",
        );
        let later_ack =
            rig.publish_acknowledgement(&later_source.manifest.message_digest, "rolled_back");
        let mut runtime = rig.open().expect("open control ACK chain");

        assert!(matches!(
            runtime.consume_acknowledgement(&unknown_rejection.manifest.message_digest),
            Err(M6SenderAckError::SourceReceiptNotFound(ref digest))
                if digest == &unknown_sender_message
        ));
        assert_eq!(runtime.last_acknowledgement_sequence(), 0);
        let unknown_receipt = runtime
            .consume_control_acknowledgement(&unknown_rejection.manifest.message_digest)
            .expect("terminally consume unknown-source rejection ACK");
        assert_eq!(unknown_receipt.acknowledgement_sequence, 1);
        assert_eq!(
            unknown_receipt.acknowledged_sender_message_digest,
            unknown_sender_message
        );
        assert_eq!(unknown_receipt.disposition, "validation_rejected");
        assert!(!unknown_receipt.source_correlated);
        assert!(unknown_receipt.intake_only);
        assert!(!unknown_receipt.adoption_inferred);

        let accepted = runtime
            .consume_acknowledgement(&accepted_ack.manifest.message_digest)
            .expect("consume accepted source ACK after terminal control ACK");
        assert_eq!(accepted.acknowledgement_sequence, 2);
        assert_eq!(runtime.last_acknowledgement_sequence(), 2);

        assert!(matches!(
            runtime.consume_acknowledgement(&replay_rejection.manifest.message_digest),
            Err(M6SenderAckError::Conflict { .. })
        ));
        let replay_receipt = runtime
            .consume_control_acknowledgement(&replay_rejection.manifest.message_digest)
            .expect("terminally consume duplicate-source replay rejection ACK");
        assert_eq!(replay_receipt.acknowledgement_sequence, 3);
        assert_eq!(
            replay_receipt.acknowledged_sender_message_digest,
            accepted_source.manifest.message_digest
        );
        assert!(!replay_receipt.source_correlated);

        let later = runtime
            .consume_acknowledgement(&later_ack.manifest.message_digest)
            .expect("later ordinary ACK remains live after control ACKs");
        assert_eq!(later.acknowledgement_sequence, 4);
        assert_eq!(runtime.last_acknowledgement_sequence(), 4);

        assert_eq!(
            runtime
                .consume_control_acknowledgement(&replay_rejection.manifest.message_digest)
                .expect("control ACK retry is exact"),
            replay_receipt
        );
        drop(runtime);
        let reopened = rig.open().expect("reopen terminal control ACK chain");
        assert_eq!(reopened.last_acknowledgement_sequence(), 4);
        assert_eq!(
            reopened
                .load_control_acknowledgement(&unknown_rejection.manifest.message_digest)
                .expect("load unknown control ACK"),
            Some(unknown_receipt)
        );
        assert_eq!(
            reopened
                .load_control_acknowledgement(&replay_rejection.manifest.message_digest)
                .expect("load replay control ACK"),
            Some(replay_receipt)
        );
    }

    #[test]
    fn bobs_control_ack_rejects_positive_dispositions_and_recovers_every_commit_seam() {
        {
            let rig = TestRig::new("control-ack-positive-disposition");
            let unknown = content("unknown-positive-source");
            let healthy = rig.publish_acknowledgement(&unknown, "healthy");
            let mut runtime = rig.open().expect("open positive control ACK rig");
            assert!(matches!(
                runtime.consume_control_acknowledgement(&healthy.manifest.message_digest),
                Err(M6SenderAckError::Integrity(_))
            ));
            assert_eq!(runtime.last_acknowledgement_sequence(), 0);
        }

        for point in [
            SenderAckCrashPoint::RawQuarantineCommitted,
            SenderAckCrashPoint::ControlAckIntentCommitted,
            SenderAckCrashPoint::ReplayCommitted,
            SenderAckCrashPoint::ControlAckReceiptCommitted,
        ] {
            let rig = TestRig::new(&format!("control-ack-crash-{point:?}"));
            let unknown = content(&format!("unknown-control-source-{point:?}"));
            let acknowledgement = rig.publish_acknowledgement(&unknown, "raw_admission_rejected");
            let mut runtime = rig.open().expect("open control ACK crash rig");
            expect_crash(
                runtime.consume_control_acknowledgement_with_fault(
                    &acknowledgement.manifest.message_digest,
                    Some(point),
                ),
                point,
            );
            drop(runtime);

            let mut reopened = rig.open().expect("reopen control ACK crash rig");
            let receipt = reopened
                .recover_control_acknowledgement(&acknowledgement.manifest.message_digest)
                .expect("recover exact control ACK");
            assert_eq!(receipt.acknowledgement_sequence, 1);
            assert_eq!(receipt.acknowledged_sender_message_digest, unknown);
            assert_eq!(receipt.disposition, "raw_admission_rejected");
            assert!(!receipt.source_correlated);
            assert!(receipt.intake_only);
            assert!(!receipt.adoption_inferred);
            assert_eq!(reopened.last_acknowledgement_sequence(), 1);
            assert_eq!(
                reopened
                    .recover_control_acknowledgement(&acknowledgement.manifest.message_digest)
                    .expect("retry recovered control ACK"),
                receipt
            );
        }
    }

    #[test]
    fn bobs_ack_intake_rejects_forgery_tamper_wrong_target_and_attachments() {
        {
            let rig = TestRig::new("forged-receiver");
            let source = rig.publish_export("source");
            let valid =
                rig.issue_acknowledgement(&source.manifest.message_digest, "healthy", false);
            let impostor =
                FactorySigner::from_seed("key:receiver-v1", [0x99; 32]).expect("impostor receiver");
            let forged_manifest = SignedManifest::sign(valid.manifest.unsigned.clone(), &impostor)
                .expect("sign forged ACK");
            let forged = IssuedManifest {
                attachments: BTreeMap::new(),
                manifest: forged_manifest,
            };
            rig.place_manual_receiver_unit(&forged);
            let mut runtime = rig.open().expect("open forged receiver rig");
            assert!(
                runtime
                    .consume_acknowledgement(&forged.manifest.message_digest)
                    .is_err()
            );
            assert!(
                runtime
                    .load_raw_quarantine(&forged.manifest.message_digest)
                    .expect("load forged raw evidence")
                    .is_some()
            );
            assert_eq!(runtime.last_acknowledgement_sequence(), 0);
        }

        {
            let rig = TestRig::new("tampered-route-bytes");
            let source = rig.publish_export("source");
            let acknowledgement =
                rig.publish_acknowledgement(&source.manifest.message_digest, "healthy");
            let path = rig
                .receiver_spool()
                .outbound_ready_unit_directory(&acknowledgement.manifest.message_digest)
                .join(MANIFEST_FILE);
            OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open manifest for tamper")
                .write_all(b" ")
                .expect("tamper manifest bytes");
            let mut runtime = rig.open().expect("open tamper rig");
            assert!(
                runtime
                    .consume_acknowledgement(&acknowledgement.manifest.message_digest)
                    .is_err()
            );
            assert!(
                runtime
                    .load_raw_quarantine(&acknowledgement.manifest.message_digest)
                    .expect("load tampered raw evidence")
                    .is_some()
            );
            assert_eq!(runtime.last_acknowledgement_sequence(), 0);
        }

        {
            let rig = TestRig::new("wrong-target");
            let source = rig.publish_export("source");
            let unknown = content("unknown-sender-message");
            let acknowledgement = rig.publish_acknowledgement(&unknown, "healthy");
            let mut runtime = rig.open().expect("open wrong target rig");
            assert!(matches!(
                runtime.consume_acknowledgement(&acknowledgement.manifest.message_digest),
                Err(M6SenderAckError::SourceReceiptNotFound(ref digest)) if digest == &unknown
            ));
            assert!(
                runtime
                    .load_raw_quarantine(&acknowledgement.manifest.message_digest)
                    .expect("load wrong-target raw evidence")
                    .is_some()
            );
            assert!(
                runtime
                    .load_correlation(&source.manifest.message_digest)
                    .expect("load absent correlation")
                    .is_none()
            );
        }

        {
            let rig = TestRig::new("attached-ack");
            let source = rig.publish_export("source");
            let acknowledgement =
                rig.publish_acknowledgement_with_attachment(&source.manifest.message_digest);
            let mut runtime = rig.open().expect("open attached ACK rig");
            assert!(
                runtime
                    .consume_acknowledgement(&acknowledgement.manifest.message_digest)
                    .is_err()
            );
            assert_eq!(runtime.last_acknowledgement_sequence(), 0);
        }
    }

    #[test]
    fn bobs_replay_gap_retry_and_duplicate_source_ack_are_fail_closed() {
        let rig = TestRig::new("replay-gap");
        let first_source = rig.publish_export("source-one");
        let second_source = rig.publish_export("source-two");
        let first_ack =
            rig.publish_acknowledgement(&first_source.manifest.message_digest, "healthy");
        let second_ack =
            rig.publish_acknowledgement(&second_source.manifest.message_digest, "denied");
        let duplicate_source_ack =
            rig.publish_acknowledgement(&first_source.manifest.message_digest, "rolled_back");
        let mut runtime = rig.open().expect("open replay rig");

        assert!(
            runtime
                .consume_acknowledgement(&second_ack.manifest.message_digest)
                .is_err()
        );
        assert_eq!(runtime.last_acknowledgement_sequence(), 0);
        let first = runtime
            .consume_acknowledgement(&first_ack.manifest.message_digest)
            .expect("consume first ACK");
        rig.clock.advance(17);
        let second = runtime
            .consume_acknowledgement(&second_ack.manifest.message_digest)
            .expect("close ACK sequence gap");
        assert_eq!(runtime.last_acknowledgement_sequence(), 2);
        assert_eq!(
            runtime
                .consume_acknowledgement(&first_ack.manifest.message_digest)
                .expect("exact ACK retry"),
            first
        );
        assert!(matches!(
            runtime.consume_acknowledgement(&duplicate_source_ack.manifest.message_digest),
            Err(M6SenderAckError::Conflict { .. })
        ));
        assert_eq!(
            runtime.last_acknowledgement_sequence(),
            2,
            "a second ACK for one source must not consume the receiver replay chain"
        );
        assert_eq!(second.disposition, "denied");
    }

    #[test]
    fn bobs_ack_crash_recovery_is_idempotent_with_an_advanced_clock() {
        for point in [
            SenderAckCrashPoint::RawQuarantineCommitted,
            SenderAckCrashPoint::AckIntentCommitted,
            SenderAckCrashPoint::ReplayCommitted,
            SenderAckCrashPoint::CorrelationReceiptCommitted,
        ] {
            let rig = TestRig::new(&format!("ack-crash-{point:?}"));
            let source = rig.publish_export("source");
            let acknowledgement =
                rig.publish_acknowledgement(&source.manifest.message_digest, "healthy");
            {
                let mut runtime = rig.open().expect("open ACK crash rig");
                expect_crash(
                    runtime.consume_acknowledgement_with_fault(
                        &acknowledgement.manifest.message_digest,
                        Some(point),
                    ),
                    point,
                );
            }
            rig.clock.advance(37);
            let mut reopened = rig.open().expect("reopen ACK crash rig");
            let recovered = reopened
                .recover_acknowledgement(&acknowledgement.manifest.message_digest)
                .expect("recover exact ACK");
            assert_eq!(
                reopened
                    .recover_acknowledgement(&acknowledgement.manifest.message_digest)
                    .expect("retry recovered ACK"),
                recovered
            );
            assert_eq!(reopened.last_acknowledgement_sequence(), 1);
            assert!(recovered.intake_only);
            assert!(!recovered.adoption_inferred);
        }
    }

    #[test]
    fn bobs_collection_is_dual_unit_retention_gated_and_crash_recoverable() {
        for point in [
            SenderAckCrashPoint::CollectionIntentCommitted,
            SenderAckCrashPoint::SourceRouteUnitDetached,
            SenderAckCrashPoint::AcknowledgementRouteUnitDetached,
            SenderAckCrashPoint::RouteUnitDetached,
            SenderAckCrashPoint::RouteCollectionFactCommitted,
            SenderAckCrashPoint::SourceRouteFileRemoved,
            SenderAckCrashPoint::SourceRouteBytesRemoved,
            SenderAckCrashPoint::AcknowledgementRouteFileRemoved,
            SenderAckCrashPoint::AcknowledgementRouteBytesRemoved,
            SenderAckCrashPoint::RouteBytesRemoved,
            SenderAckCrashPoint::CollectionReceiptCommitted,
        ] {
            let rig = TestRig::new(&format!("collection-crash-{point:?}"));
            let source = rig.publish_export("collect-source");
            let unrelated = rig.publish_export("unrelated-source");
            let acknowledgement =
                rig.publish_acknowledgement(&source.manifest.message_digest, "healthy");
            {
                let mut runtime = rig.open().expect("open collection rig");
                runtime
                    .consume_acknowledgement(&acknowledgement.manifest.message_digest)
                    .expect("correlate collection ACK");
                assert!(matches!(
                    runtime.collect_acknowledged(&source.manifest.message_digest),
                    Err(M6SenderAckError::RetentionActive { .. })
                ));
                assert!(
                    runtime
                        .spool
                        .outbound_ready_unit_directory(&source.manifest.message_digest)
                        .exists()
                );
                assert!(
                    runtime
                        .spool
                        .inbound_ready_unit_directory(&acknowledgement.manifest.message_digest)
                        .exists()
                );
            }
            rig.clock
                .advance(rig.route.resource_profile.route_delivery_retention_ms);
            {
                let mut runtime = rig.open().expect("reopen eligible collection rig");
                expect_crash(
                    runtime.collect_acknowledged_with_fault(
                        &source.manifest.message_digest,
                        Some(point),
                    ),
                    point,
                );
            }
            rig.clock.advance(53);
            let mut reopened = rig.open().expect("reopen crashed collection");
            let recovered = reopened
                .recover_collection(&source.manifest.message_digest)
                .expect("recover dual-unit collection");
            assert_eq!(
                reopened
                    .recover_collection(&source.manifest.message_digest)
                    .expect("exact collection retry"),
                recovered
            );
            assert!(
                !reopened
                    .spool
                    .outbound_ready_unit_directory(&source.manifest.message_digest)
                    .exists()
            );
            assert!(
                !reopened
                    .spool
                    .inbound_ready_unit_directory(&acknowledgement.manifest.message_digest)
                    .exists()
            );
            assert!(
                reopened
                    .spool
                    .outbound_ready_unit_directory(&unrelated.manifest.message_digest)
                    .exists()
            );
            assert!(
                reopened
                    .load_raw_quarantine(&acknowledgement.manifest.message_digest)
                    .expect("retained raw ACK")
                    .is_some()
            );
            assert!(
                reopened
                    .load_correlation(&source.manifest.message_digest)
                    .expect("retained correlation")
                    .is_some()
            );
            assert!(
                source_receipt_path(
                    &rig.sender_root.join(EXPORT_RECEIPTS_DIRECTORY),
                    "collect-source"
                )
                .exists()
            );
            assert!(recovered.source_receipt_retained);
            assert!(recovered.acknowledgement_evidence_retained);
            assert_ne!(
                recovered.source_ready_snapshot_digest,
                recovered.acknowledgement_ready_snapshot_digest
            );
            assert_eq!(
                reopened
                    .load_collection_receipt(&source.manifest.message_digest)
                    .expect("load completed collection"),
                Some(recovered)
            );
        }
    }

    #[test]
    fn bobs_collection_rejects_unsafe_locking_and_source_tamper_without_deletion() {
        {
            let rig = TestRig::new("maintenance-lock");
            let source = rig.publish_export("source");
            let acknowledgement =
                rig.publish_acknowledgement(&source.manifest.message_digest, "healthy");
            let mut runtime = rig.open().expect("open maintenance-lock rig");
            runtime
                .consume_acknowledgement(&acknowledgement.manifest.message_digest)
                .expect("correlate ACK");
            rig.clock
                .advance(rig.route.resource_profile.route_delivery_retention_ms);
            let lock_path = rig
                .route_root
                .join(format!("generation-{}", rig.route.generation))
                .join(ROUTE_LOCKS_DIRECTORY)
                .join(ROUTE_MAINTENANCE_LOCK_FILE);
            let lock = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&lock_path)
                .expect("open maintenance lock");
            lock.try_lock().expect("own maintenance lock");
            assert!(matches!(
                runtime.collect_acknowledged(&source.manifest.message_digest),
                Err(M6SenderAckError::MaintenanceAlreadyOwned)
            ));
            assert!(
                runtime
                    .spool
                    .outbound_ready_unit_directory(&source.manifest.message_digest)
                    .exists()
            );
            assert!(
                runtime
                    .spool
                    .inbound_ready_unit_directory(&acknowledgement.manifest.message_digest)
                    .exists()
            );
        }

        {
            let rig = TestRig::new("source-tamper");
            let source = rig.publish_export("source");
            let acknowledgement =
                rig.publish_acknowledgement(&source.manifest.message_digest, "healthy");
            let mut runtime = rig.open().expect("open source-tamper rig");
            runtime
                .consume_acknowledgement(&acknowledgement.manifest.message_digest)
                .expect("correlate ACK");
            rig.clock
                .advance(rig.route.resource_profile.route_delivery_retention_ms);
            let source_manifest = runtime
                .spool
                .outbound_ready_unit_directory(&source.manifest.message_digest)
                .join(MANIFEST_FILE);
            OpenOptions::new()
                .append(true)
                .open(&source_manifest)
                .expect("open source manifest")
                .write_all(b" ")
                .expect("tamper source manifest");
            assert!(
                runtime
                    .collect_acknowledged(&source.manifest.message_digest)
                    .is_err()
            );
            assert!(
                runtime
                    .spool
                    .outbound_ready_unit_directory(&source.manifest.message_digest)
                    .exists()
            );
            assert!(
                runtime
                    .spool
                    .inbound_ready_unit_directory(&acknowledgement.manifest.message_digest)
                    .exists()
            );
        }
    }

    #[test]
    fn bobs_ack_completion_evidence_is_portable_source_bound_and_sender_attested() {
        let rig = TestRig::new("portable-ack-completion");
        let source = rig.publish_export("portable-source");
        let acknowledgement =
            rig.publish_acknowledgement(&source.manifest.message_digest, "healthy");
        let mut runtime = rig.open().expect("open portable ACK rig");
        let correlation = runtime
            .consume_acknowledgement(&acknowledgement.manifest.message_digest)
            .expect("consume portable ACK");
        let evidence = runtime
            .load_acknowledgement_completion_evidence(&source.manifest.message_digest)
            .expect("capture ACK completion")
            .expect("ACK completion exists");

        assert_eq!(evidence.schema, SENDER_ACK_COMPLETION_EVIDENCE_SCHEMA);
        assert_eq!(
            evidence.sender_publication_kind(),
            SenderPublicationKind::Export
        );
        assert_eq!(
            evidence.sender_message_digest(),
            &source.manifest.message_digest
        );
        assert_eq!(
            evidence.sender_sequence(),
            source.manifest.unsigned.sequence
        );
        assert_eq!(
            evidence.acknowledgement_message_digest(),
            &acknowledgement.manifest.message_digest
        );
        assert_eq!(
            evidence.acknowledgement_sequence(),
            acknowledgement.manifest.unsigned.sequence
        );
        assert_eq!(evidence.disposition(), "healthy");
        assert_eq!(evidence.correlation_digest(), &correlation.receipt_digest);
        assert_eq!(
            evidence.source_receipt_digest(),
            &correlation.source.sender_receipt_digest
        );
        assert!(evidence.intake_only());
        assert!(!evidence.adoption_inferred());
        assert!(evidence.collection_digest().is_none());

        let bytes = evidence
            .canonical_bytes(&runtime)
            .expect("validate live ACK completion");
        let detached = SenderAcknowledgementCompletionEvidenceV1::from_canonical_bytes_detached(
            &bytes, &rig.route,
        )
        .expect("validate detached ACK completion");
        assert!(
            detached == evidence,
            "detached ACK completion evidence differed from its canonical source"
        );

        let mut noncanonical = bytes.clone();
        noncanonical.push(b' ');
        assert!(
            SenderAcknowledgementCompletionEvidenceV1::from_canonical_bytes_detached(
                &noncanonical,
                &rig.route
            )
            .is_err()
        );

        let mut raw_tamper = evidence.clone();
        raw_tamper
            .raw_acknowledgement_files
            .get_mut(MANIFEST_FILE)
            .expect("manifest source")
            .push(b' ');
        assert!(raw_tamper.canonical_bytes_detached(&rig.route).is_err());

        let mut signature_tamper = evidence.clone();
        let replacement = if signature_tamper.source_set_signature_hex.starts_with('0') {
            "1"
        } else {
            "0"
        };
        signature_tamper
            .source_set_signature_hex
            .replace_range(0..1, replacement);
        assert!(
            signature_tamper
                .canonical_bytes_detached(&rig.route)
                .is_err()
        );

        let other_route = TestRig::new("portable-ack-wrong-route");
        assert!(
            SenderAcknowledgementCompletionEvidenceV1::from_canonical_bytes_detached(
                &bytes,
                &other_route.route
            )
            .is_err()
        );

        drop(runtime);
        let reopened = rig.open().expect("reopen portable ACK rig");
        assert_eq!(
            reopened
                .load_acknowledgement_completion_evidence(&source.manifest.message_digest)
                .expect("reopen ACK completion")
                .expect("reopened ACK completion exists"),
            evidence
        );

        drop(reopened);
        let clock: Arc<dyn Clock> = rig.clock.clone();
        let impostor =
            FactorySigner::from_seed("key:sender-v1", [0x99; 32]).expect("impostor sender");
        assert!(matches!(
            M6SenderAckRuntime::open(rig.config(), impostor, clock),
            Err(M6SenderAckError::Identity(_))
        ));
    }

    #[test]
    fn bobs_ack_completion_evidence_carries_terminal_collection_sources() {
        let rig = TestRig::new("portable-collected-ack");
        let source = rig.publish_revocation("portable-revocation");
        let acknowledgement =
            rig.publish_acknowledgement(&source.manifest.message_digest, "revocation_contained");
        let mut runtime = rig.open().expect("open collected ACK rig");
        runtime
            .consume_acknowledgement(&acknowledgement.manifest.message_digest)
            .expect("consume revocation ACK");
        rig.clock
            .advance(rig.route.resource_profile.route_delivery_retention_ms);
        let collection = runtime
            .collect_acknowledged(&source.manifest.message_digest)
            .expect("collect acknowledged route units");
        let evidence = runtime
            .load_acknowledgement_completion_evidence(&source.manifest.message_digest)
            .expect("capture collected ACK completion")
            .expect("collected ACK completion exists");

        assert_eq!(
            evidence.sender_publication_kind(),
            SenderPublicationKind::Revocation
        );
        assert_eq!(evidence.disposition(), "revocation_contained");
        assert_eq!(
            evidence.collection_digest(),
            Some(&collection.receipt_digest)
        );
        assert!(evidence.intake_only());
        assert!(!evidence.adoption_inferred());
        assert_eq!(
            evidence.source_digests().collection_receipt.as_ref(),
            Some(&ContentDigest::from_bytes(
                evidence
                    .collection_receipt_bytes
                    .as_deref()
                    .expect("collection receipt source")
            ))
        );

        let bytes = evidence
            .canonical_bytes(&runtime)
            .expect("validate live collected ACK completion");
        let detached = SenderAcknowledgementCompletionEvidenceV1::from_canonical_bytes_detached(
            &bytes, &rig.route,
        )
        .expect("validate detached collected ACK completion");
        assert!(
            detached == evidence,
            "detached collected ACK completion evidence differed from its canonical source"
        );

        let mut partial_collection = evidence.clone();
        partial_collection.collection_journal_files = None;
        assert!(
            partial_collection
                .canonical_bytes_detached(&rig.route)
                .is_err()
        );
    }
}
