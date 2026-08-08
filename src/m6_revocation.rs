//! Receiver-owned, append-only M6 revocation tombstones.
//!
//! This module deliberately performs no transport intake, replay mutation, or
//! deployment effect.  It accepts only a sender-authenticated revocation whose
//! exact sequence is already committed by [`crate::m6_identity::ReplayJournal`],
//! records an irreversible local tombstone, and derives the containment work
//! required for matching receiver imports.

use crate::execution::artifact::ContentDigest;
use crate::m6_identity::{
    Clock, ManifestKind, ManifestPayload, ReplayCommitFact, RouteDefinition, SignedManifest,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

pub const REVOCATION_LEDGER_CONFIG_SCHEMA: &str = "wasm-biotic.m6-revocation-ledger-config.v1";
pub const REVOCATION_TOMBSTONE_SCHEMA: &str = "wasm-biotic.m6-revocation-tombstone.v1";
pub const REVOCATION_AFFECTED_IMPORT_SCHEMA: &str = "wasm-biotic.m6-revocation-affected-import.v1";
pub const REVOCATION_CONTAINMENT_RESOLUTION_SCHEMA: &str =
    "wasm-biotic.m6-revocation-containment-resolution.v1";

const CONFIG_DOMAIN: &[u8] = b"wasm-biotic:m6:revocation-ledger-config:v1\0";
const TOMBSTONE_DOMAIN: &[u8] = b"wasm-biotic:m6:revocation-tombstone:v1\0";
const AFFECTED_DOMAIN: &[u8] = b"wasm-biotic:m6:revocation-affected-import:v1\0";
const RESOLUTION_DOMAIN: &[u8] = b"wasm-biotic:m6:revocation-containment-resolution:v1\0";
const CONFIG_FILE: &str = "ledger-config.json";
const OWNER_LOCK_FILE: &str = ".revocation-ledger.lock";
const TOMBSTONES_DIRECTORY: &str = "tombstones";
const AFFECTED_DIRECTORY: &str = "affected-imports";
const RESOLUTIONS_DIRECTORY: &str = "containment-resolutions";
const STAGING_DIRECTORY: &str = "staging";
const MAX_RECORD_BYTES: usize = 512 * 1_024;
const MAX_REASON_BYTES: usize = 4_096;
const MAX_IDENTIFIER_BYTES: usize = 512;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// The four revocation targets accepted by ADR 0006.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTargetKindV1 {
    ExchangeMessage,
    SourcePackage,
    SourceSigningKey,
    SenderIdentity,
}

impl RevocationTargetKindV1 {
    pub fn label(self) -> &'static str {
        match self {
            Self::ExchangeMessage => "exchange_message",
            Self::SourcePackage => "source_package",
            Self::SourceSigningKey => "source_signing_key",
            Self::SenderIdentity => "sender_identity",
        }
    }

    pub fn parse(value: &str) -> Result<Self, M6RevocationError> {
        match value {
            "exchange_message" => Ok(Self::ExchangeMessage),
            "source_package" => Ok(Self::SourcePackage),
            "source_signing_key" => Ok(Self::SourceSigningKey),
            "sender_identity" => Ok(Self::SenderIdentity),
            other => Err(M6RevocationError::UnsupportedTargetKind(other.to_string())),
        }
    }
}

/// Exact source identities retained by one receiver-local import.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRevocationBindingV1 {
    pub exchange_message_digest: ContentDigest,
    pub receiver_import_plan_digest: ContentDigest,
    pub receiver_local_package_digest: ContentDigest,
    pub source_identity_document_digest: ContentDigest,
    pub source_package_digest: ContentDigest,
    pub source_signing_key_digest: ContentDigest,
}

impl ExchangeRevocationBindingV1 {
    pub fn target_identity(&self, kind: RevocationTargetKindV1) -> &ContentDigest {
        match kind {
            RevocationTargetKindV1::ExchangeMessage => &self.exchange_message_digest,
            RevocationTargetKindV1::SourcePackage => &self.source_package_digest,
            RevocationTargetKindV1::SourceSigningKey => &self.source_signing_key_digest,
            RevocationTargetKindV1::SenderIdentity => &self.source_identity_document_digest,
        }
    }
}

/// Receiver import posture at the instant a matching tombstone is resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverImportDispositionV1 {
    Quarantined,
    AwaitingApproval,
    ActivationPending,
    ActiveHealthy,
    Denied,
    Expired,
    Escalated,
    RolledBack,
    ContainmentRequired,
}

/// Receiver-owned action implied by a revocation.  A sender never executes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredContainmentActionV1 {
    RejectBeforeApproval,
    CancelAtEffectSafeBoundary,
    StopAdmissionAndRollback,
    RetainHistoricalTombstone,
    KeepServingDisabled,
}

impl RequiredContainmentActionV1 {
    fn for_disposition(disposition: ReceiverImportDispositionV1) -> Self {
        match disposition {
            ReceiverImportDispositionV1::Quarantined
            | ReceiverImportDispositionV1::AwaitingApproval => Self::RejectBeforeApproval,
            ReceiverImportDispositionV1::ActivationPending => Self::CancelAtEffectSafeBoundary,
            ReceiverImportDispositionV1::ActiveHealthy => Self::StopAdmissionAndRollback,
            ReceiverImportDispositionV1::Denied
            | ReceiverImportDispositionV1::Expired
            | ReceiverImportDispositionV1::Escalated
            | ReceiverImportDispositionV1::RolledBack => Self::RetainHistoricalTombstone,
            ReceiverImportDispositionV1::ContainmentRequired => Self::KeepServingDisabled,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationLedgerConfigV1 {
    pub config_digest: ContentDigest,
    pub max_affected_imports: u32,
    pub max_tombstones: u32,
    pub receiver_identity_document_digest: ContentDigest,
    pub route_definition_digest: ContentDigest,
    pub route_generation: u64,
    pub route_id: String,
    pub schema: String,
    pub sender_identity_document_digest: ContentDigest,
}

impl RevocationLedgerConfigV1 {
    pub fn for_route(route: &RouteDefinition) -> Result<Self, M6RevocationError> {
        route.validate().map_err(identity_error)?;
        let mut config = Self {
            config_digest: ContentDigest::from_bytes(&[]),
            max_affected_imports: route.resource_profile.max_revocation_records,
            max_tombstones: route.resource_profile.max_revocation_records,
            receiver_identity_document_digest: route.receiver.identity_document_digest.clone(),
            route_definition_digest: route.definition_digest.clone(),
            route_generation: route.generation,
            route_id: route.route_id.clone(),
            schema: REVOCATION_LEDGER_CONFIG_SCHEMA.to_string(),
            sender_identity_document_digest: route.sender.identity_document_digest.clone(),
        };
        config.validate_fields()?;
        config.config_digest = config.expected_digest()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), M6RevocationError> {
        self.validate_fields()?;
        require_digest(
            "revocation ledger config",
            &self.config_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6RevocationError> {
        if self.schema != REVOCATION_LEDGER_CONFIG_SCHEMA {
            return Err(M6RevocationError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("route id", &self.route_id)?;
        if self.route_generation == 0 || self.max_tombstones == 0 || self.max_affected_imports == 0
        {
            return Err(M6RevocationError::InvalidRecord(
                "revocation ledger bounds and route generation must be nonzero".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6RevocationError> {
        digest_domain(
            CONFIG_DOMAIN,
            &(
                self.max_affected_imports,
                self.max_tombstones,
                &self.receiver_identity_document_digest,
                &self.route_definition_digest,
                self.route_generation,
                &self.route_id,
                &self.schema,
                &self.sender_identity_document_digest,
            ),
        )
    }
}

/// Irreversible receiver-local record of one authenticated sender statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationTombstoneV1 {
    pub applied_at_ms: u64,
    pub authorization_digest: ContentDigest,
    pub raw_quarantine_digest: ContentDigest,
    pub raw_quarantine_record_digest: ContentDigest,
    pub reason: String,
    pub replay_retained_until_ms: u64,
    pub route_definition_digest: ContentDigest,
    pub route_generation: u64,
    pub route_id: String,
    pub schema: String,
    pub sender_identity_document_digest: ContentDigest,
    pub sender_message_digest: ContentDigest,
    pub sender_nonce: String,
    pub sender_sequence: u64,
    pub target_identity: ContentDigest,
    pub target_kind: RevocationTargetKindV1,
    pub tombstone_digest: ContentDigest,
}

impl RevocationTombstoneV1 {
    pub fn matches(&self, binding: &ExchangeRevocationBindingV1) -> bool {
        &self.target_identity == binding.target_identity(self.target_kind)
    }

    pub fn validate(&self, config: &RevocationLedgerConfigV1) -> Result<(), M6RevocationError> {
        config.validate()?;
        if self.schema != REVOCATION_TOMBSTONE_SCHEMA {
            return Err(M6RevocationError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("revocation route id", &self.route_id)?;
        validate_identifier("revocation nonce", &self.sender_nonce)?;
        if self.route_definition_digest != config.route_definition_digest
            || self.route_generation != config.route_generation
            || self.route_id != config.route_id
            || self.sender_identity_document_digest != config.sender_identity_document_digest
            || self.sender_sequence == 0
            || self.replay_retained_until_ms < self.applied_at_ms
            || self.reason.trim().is_empty()
            || self.reason.len() > MAX_REASON_BYTES
        {
            return Err(M6RevocationError::InvalidRecord(
                "revocation tombstone differs from its route, retention, or reason bounds"
                    .to_string(),
            ));
        }
        require_digest(
            "revocation tombstone",
            &self.tombstone_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6RevocationError> {
        digest_domain(
            TOMBSTONE_DOMAIN,
            &(
                self.applied_at_ms,
                &self.authorization_digest,
                &self.raw_quarantine_digest,
                &self.raw_quarantine_record_digest,
                &self.reason,
                self.replay_retained_until_ms,
                &self.route_definition_digest,
                self.route_generation,
                &self.route_id,
                &self.schema,
                &self.sender_identity_document_digest,
                &self.sender_message_digest,
                &self.sender_nonce,
                self.sender_sequence,
                &self.target_identity,
                self.target_kind,
            ),
        )
    }
}

/// Durable work item written before receiver containment begins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationAffectedImportV1 {
    pub affected_digest: ContentDigest,
    pub binding: ExchangeRevocationBindingV1,
    pub disposition_at_resolution: ReceiverImportDispositionV1,
    pub recorded_at_ms: u64,
    pub required_action: RequiredContainmentActionV1,
    pub schema: String,
    pub tombstone_digest: ContentDigest,
}

impl RevocationAffectedImportV1 {
    pub fn validate(&self, tombstone: &RevocationTombstoneV1) -> Result<(), M6RevocationError> {
        if self.schema != REVOCATION_AFFECTED_IMPORT_SCHEMA {
            return Err(M6RevocationError::UnsupportedSchema(self.schema.clone()));
        }
        if self.tombstone_digest != tombstone.tombstone_digest
            || !tombstone.matches(&self.binding)
            || self.required_action
                != RequiredContainmentActionV1::for_disposition(self.disposition_at_resolution)
            || self.recorded_at_ms < tombstone.applied_at_ms
        {
            return Err(M6RevocationError::FalseLink(
                "affected import differs from its tombstone or lifecycle posture".to_string(),
            ));
        }
        require_digest(
            "revocation affected import",
            &self.affected_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6RevocationError> {
        digest_domain(
            AFFECTED_DOMAIN,
            &(
                &self.binding,
                self.disposition_at_resolution,
                self.recorded_at_ms,
                self.required_action,
                &self.schema,
                &self.tombstone_digest,
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationContainmentOutcomeV1 {
    RejectedBeforeApproval,
    CancelledBeforeActivation,
    RolledBack,
    AlreadyTerminal,
    ContainmentRequired,
}

/// Immutable terminal result for one affected-import work item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationContainmentResolutionV1 {
    pub affected_digest: ContentDigest,
    pub authoritative_effect_refs: Vec<ContentDigest>,
    pub outcome: RevocationContainmentOutcomeV1,
    pub resolved_at_ms: u64,
    pub resolution_digest: ContentDigest,
    pub schema: String,
}

impl RevocationContainmentResolutionV1 {
    pub fn validate(&self, affected: &RevocationAffectedImportV1) -> Result<(), M6RevocationError> {
        if self.schema != REVOCATION_CONTAINMENT_RESOLUTION_SCHEMA {
            return Err(M6RevocationError::UnsupportedSchema(self.schema.clone()));
        }
        if self.affected_digest != affected.affected_digest
            || self.resolved_at_ms < affected.recorded_at_ms
            || !is_strictly_sorted_unique(&self.authoritative_effect_refs)
            || !outcome_matches_action(self.outcome, affected.required_action)
        {
            return Err(M6RevocationError::FalseLink(
                "containment resolution differs from its exact required action".to_string(),
            ));
        }
        if matches!(
            self.outcome,
            RevocationContainmentOutcomeV1::RolledBack
                | RevocationContainmentOutcomeV1::ContainmentRequired
        ) && self.authoritative_effect_refs.is_empty()
        {
            return Err(M6RevocationError::InvalidRecord(
                "rollback or containment-required resolution needs authoritative effect evidence"
                    .to_string(),
            ));
        }
        require_digest(
            "revocation containment resolution",
            &self.resolution_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6RevocationError> {
        digest_domain(
            RESOLUTION_DOMAIN,
            &(
                &self.affected_digest,
                &self.authoritative_effect_refs,
                self.outcome,
                self.resolved_at_ms,
                &self.schema,
            ),
        )
    }
}

fn outcome_matches_action(
    outcome: RevocationContainmentOutcomeV1,
    action: RequiredContainmentActionV1,
) -> bool {
    match action {
        RequiredContainmentActionV1::RejectBeforeApproval => matches!(
            outcome,
            RevocationContainmentOutcomeV1::RejectedBeforeApproval
                | RevocationContainmentOutcomeV1::AlreadyTerminal
        ),
        RequiredContainmentActionV1::CancelAtEffectSafeBoundary => matches!(
            outcome,
            RevocationContainmentOutcomeV1::CancelledBeforeActivation
                | RevocationContainmentOutcomeV1::RolledBack
                | RevocationContainmentOutcomeV1::ContainmentRequired
        ),
        RequiredContainmentActionV1::StopAdmissionAndRollback => matches!(
            outcome,
            RevocationContainmentOutcomeV1::RolledBack
                | RevocationContainmentOutcomeV1::ContainmentRequired
        ),
        RequiredContainmentActionV1::RetainHistoricalTombstone => {
            outcome == RevocationContainmentOutcomeV1::AlreadyTerminal
        }
        RequiredContainmentActionV1::KeepServingDisabled => {
            outcome == RevocationContainmentOutcomeV1::ContainmentRequired
        }
    }
}

#[derive(Default)]
struct LedgerState {
    tombstones: BTreeMap<String, RevocationTombstoneV1>,
    affected: BTreeMap<String, RevocationAffectedImportV1>,
    resolutions: BTreeMap<String, RevocationContainmentResolutionV1>,
}

/// Receiver-local revocation ledger.
///
/// `_owner_lock` is last so all in-memory state and child paths are dropped
/// before ownership transfers to another process.
pub struct ReceiverRevocationLedger {
    root: PathBuf,
    tombstones_root: PathBuf,
    affected_root: PathBuf,
    resolutions_root: PathBuf,
    staging_root: PathBuf,
    route: RouteDefinition,
    config: RevocationLedgerConfigV1,
    clock: Arc<dyn Clock>,
    state: Mutex<LedgerState>,
    _owner_lock: File,
}

impl ReceiverRevocationLedger {
    pub fn open_or_initialize(
        root: impl AsRef<Path>,
        route: RouteDefinition,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, M6RevocationError> {
        route.validate().map_err(identity_error)?;
        let root = secure_create_root(root.as_ref())?;
        let owner_lock = acquire_owner_lock(&root)?;
        let staging_root = secure_child_directory(&root, STAGING_DIRECTORY)?;
        recover_staging(&staging_root)?;
        let tombstones_root = secure_child_directory(&root, TOMBSTONES_DIRECTORY)?;
        let affected_root = secure_child_directory(&root, AFFECTED_DIRECTORY)?;
        let resolutions_root = secure_child_directory(&root, RESOLUTIONS_DIRECTORY)?;

        let config = RevocationLedgerConfigV1::for_route(&route)?;
        let config_path = root.join(CONFIG_FILE);
        persist_immutable(&staging_root, &config_path, &canonical_json(&config)?)?;
        let durable: RevocationLedgerConfigV1 = read_canonical_record(&config_path)?;
        durable.validate()?;
        if durable != config {
            return Err(M6RevocationError::ConfigConflict {
                expected: config.config_digest,
                actual: durable.config_digest,
            });
        }
        let state = reconstruct(
            &tombstones_root,
            &affected_root,
            &resolutions_root,
            &durable,
        )?;
        if state.tombstones.len() > durable.max_tombstones as usize
            || state.affected.len() > durable.max_affected_imports as usize
        {
            return Err(M6RevocationError::ResourceExhausted(
                "durable revocation ledger exceeds its route-bound record budget".to_string(),
            ));
        }
        Ok(Self {
            root,
            tombstones_root,
            affected_root,
            resolutions_root,
            staging_root,
            route,
            config: durable,
            clock,
            state: Mutex::new(state),
            _owner_lock: owner_lock,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config(&self) -> &RevocationLedgerConfigV1 {
        &self.config
    }

    /// Persist one irreversible tombstone after authentication and replay
    /// commit.  Exact repetition is idempotent; changed bytes under the same
    /// sender message identity fail closed.
    pub fn apply_authenticated(
        &self,
        manifest: &SignedManifest,
        replay: &ReplayCommitFact,
        raw_quarantine_digest: ContentDigest,
        raw_quarantine_record_digest: ContentDigest,
    ) -> Result<RevocationTombstoneV1, M6RevocationError> {
        manifest.verify_route(&self.route).map_err(identity_error)?;
        if manifest.unsigned.kind != ManifestKind::Revocation
            || manifest.unsigned.origin_role != crate::m6_identity::RouteEndpointRole::Sender
            || !manifest.unsigned.attachments.is_empty()
        {
            return Err(M6RevocationError::InvalidRecord(
                "revocation must be a sender-originated, attachment-free signed message"
                    .to_string(),
            ));
        }
        if replay.message_digest != manifest.message_digest
            || replay.nonce != manifest.unsigned.nonce
            || replay.route_definition_digest != self.route.definition_digest
            || replay.sequence != manifest.unsigned.sequence
        {
            return Err(M6RevocationError::ReplayNotCommitted(
                manifest.message_digest.clone(),
            ));
        }
        let ManifestPayload::Revocation(payload) = &manifest.unsigned.payload else {
            return Err(M6RevocationError::InvalidRecord(
                "revocation kind carries a non-revocation payload".to_string(),
            ));
        };
        let target_kind = RevocationTargetKindV1::parse(&payload.target_kind)?;
        let mut state = self.state_guard()?;
        let key = manifest.message_digest.as_str().to_string();
        if let Some(existing) = state.tombstones.get(&key) {
            if existing.authorization_digest == payload.authorization_digest
                && existing.raw_quarantine_digest == raw_quarantine_digest
                && existing.raw_quarantine_record_digest == raw_quarantine_record_digest
                && existing.reason == payload.reason
                && existing.replay_retained_until_ms == replay.retained_until_ms
                && existing.route_definition_digest == self.route.definition_digest
                && existing.route_generation == self.route.generation
                && existing.route_id == self.route.route_id
                && existing.sender_identity_document_digest
                    == self.route.sender.identity_document_digest
                && existing.sender_message_digest == manifest.message_digest
                && existing.sender_nonce == manifest.unsigned.nonce
                && existing.sender_sequence == manifest.unsigned.sequence
                && existing.target_identity == payload.target_identity
                && existing.target_kind == target_kind
            {
                existing.validate(&self.config)?;
                return Ok(existing.clone());
            }
            return Err(M6RevocationError::Conflict(
                "sender message identity is already bound to a different tombstone".to_string(),
            ));
        }
        let now_ms = self.clock.now_ms().map_err(identity_error)?;
        let mut record = RevocationTombstoneV1 {
            applied_at_ms: now_ms,
            authorization_digest: payload.authorization_digest.clone(),
            raw_quarantine_digest,
            raw_quarantine_record_digest,
            reason: payload.reason.clone(),
            replay_retained_until_ms: replay.retained_until_ms,
            route_definition_digest: self.route.definition_digest.clone(),
            route_generation: self.route.generation,
            route_id: self.route.route_id.clone(),
            schema: REVOCATION_TOMBSTONE_SCHEMA.to_string(),
            sender_identity_document_digest: self.route.sender.identity_document_digest.clone(),
            sender_message_digest: manifest.message_digest.clone(),
            sender_nonce: manifest.unsigned.nonce.clone(),
            sender_sequence: manifest.unsigned.sequence,
            target_identity: payload.target_identity.clone(),
            target_kind,
            tombstone_digest: ContentDigest::from_bytes(&[]),
        };
        record.tombstone_digest = record.expected_digest()?;
        record.validate(&self.config)?;
        if state.tombstones.len() >= self.config.max_tombstones as usize {
            return Err(M6RevocationError::ResourceExhausted(
                "revocation tombstone budget is exhausted".to_string(),
            ));
        }
        let path = self
            .tombstones_root
            .join(record_name(&record.sender_message_digest));
        persist_immutable(&self.staging_root, &path, &canonical_json(&record)?)?;
        state.tombstones.insert(key, record.clone());
        Ok(record)
    }

    pub fn tombstone(
        &self,
        sender_message_digest: &ContentDigest,
    ) -> Result<Option<RevocationTombstoneV1>, M6RevocationError> {
        Ok(self
            .state_guard()?
            .tombstones
            .get(sender_message_digest.as_str())
            .cloned())
    }

    pub fn matching_tombstones(
        &self,
        binding: &ExchangeRevocationBindingV1,
    ) -> Result<Vec<RevocationTombstoneV1>, M6RevocationError> {
        let mut records = self
            .state_guard()?
            .tombstones
            .values()
            .filter(|record| record.matches(binding))
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.sender_sequence
                .cmp(&right.sender_sequence)
                .then(left.tombstone_digest.cmp(&right.tombstone_digest))
        });
        Ok(records)
    }

    pub fn is_revoked(
        &self,
        binding: &ExchangeRevocationBindingV1,
    ) -> Result<bool, M6RevocationError> {
        Ok(!self.matching_tombstones(binding)?.is_empty())
    }

    /// Write the receiver-owned containment intent before any cancellation,
    /// route stop, or rollback effect starts.
    pub fn record_affected_import(
        &self,
        tombstone_digest: &ContentDigest,
        binding: ExchangeRevocationBindingV1,
        disposition: ReceiverImportDispositionV1,
    ) -> Result<RevocationAffectedImportV1, M6RevocationError> {
        let mut state = self.state_guard()?;
        let tombstone = state
            .tombstones
            .values()
            .find(|record| &record.tombstone_digest == tombstone_digest)
            .cloned()
            .ok_or_else(|| M6RevocationError::NotFound(format!("tombstone {tombstone_digest}")))?;
        if !tombstone.matches(&binding) {
            return Err(M6RevocationError::FalseLink(
                "revocation target does not match the supplied import".to_string(),
            ));
        }
        if let Some(existing) = state.affected.values().find(|record| {
            record.tombstone_digest == *tombstone_digest && record.binding == binding
        }) {
            return if existing.disposition_at_resolution == disposition {
                existing.validate(&tombstone)?;
                Ok(existing.clone())
            } else {
                Err(M6RevocationError::Conflict(
                    "matching tombstone and import already have a different durable lifecycle posture"
                        .to_string(),
                ))
            };
        }
        let now_ms = self.clock.now_ms().map_err(identity_error)?;
        let mut record = RevocationAffectedImportV1 {
            affected_digest: ContentDigest::from_bytes(&[]),
            binding,
            disposition_at_resolution: disposition,
            recorded_at_ms: now_ms,
            required_action: RequiredContainmentActionV1::for_disposition(disposition),
            schema: REVOCATION_AFFECTED_IMPORT_SCHEMA.to_string(),
            tombstone_digest: tombstone.tombstone_digest.clone(),
        };
        record.affected_digest = record.expected_digest()?;
        record.validate(&tombstone)?;
        let key = record.affected_digest.as_str().to_string();
        if let Some(existing) = state.affected.get(&key) {
            return if existing == &record {
                Ok(existing.clone())
            } else {
                Err(M6RevocationError::Conflict(
                    "affected-import identity is already bound to different work".to_string(),
                ))
            };
        }
        if state.affected.len() >= self.config.max_affected_imports as usize {
            return Err(M6RevocationError::ResourceExhausted(
                "affected-import budget is exhausted".to_string(),
            ));
        }
        let path = self
            .affected_root
            .join(record_name(&record.affected_digest));
        persist_immutable(&self.staging_root, &path, &canonical_json(&record)?)?;
        state.affected.insert(key, record.clone());
        Ok(record)
    }

    pub fn resolve_containment(
        &self,
        affected_digest: &ContentDigest,
        outcome: RevocationContainmentOutcomeV1,
        mut authoritative_effect_refs: Vec<ContentDigest>,
    ) -> Result<RevocationContainmentResolutionV1, M6RevocationError> {
        authoritative_effect_refs.sort();
        authoritative_effect_refs.dedup();
        let mut state = self.state_guard()?;
        let affected = state
            .affected
            .get(affected_digest.as_str())
            .cloned()
            .ok_or_else(|| {
                M6RevocationError::NotFound(format!("affected import {affected_digest}"))
            })?;
        let key = affected.affected_digest.as_str().to_string();
        if let Some(existing) = state.resolutions.get(&key) {
            return if existing.outcome == outcome
                && existing.authoritative_effect_refs == authoritative_effect_refs
            {
                existing.validate(&affected)?;
                Ok(existing.clone())
            } else {
                Err(M6RevocationError::Conflict(
                    "affected import already has a different terminal containment result"
                        .to_string(),
                ))
            };
        }
        let now_ms = self.clock.now_ms().map_err(identity_error)?;
        let mut record = RevocationContainmentResolutionV1 {
            affected_digest: affected.affected_digest.clone(),
            authoritative_effect_refs,
            outcome,
            resolved_at_ms: now_ms,
            resolution_digest: ContentDigest::from_bytes(&[]),
            schema: REVOCATION_CONTAINMENT_RESOLUTION_SCHEMA.to_string(),
        };
        record.resolution_digest = record.expected_digest()?;
        record.validate(&affected)?;
        let path = self
            .resolutions_root
            .join(record_name(&record.affected_digest));
        persist_immutable(&self.staging_root, &path, &canonical_json(&record)?)?;
        state.resolutions.insert(key, record.clone());
        Ok(record)
    }

    pub fn unresolved_affected_imports(
        &self,
    ) -> Result<Vec<RevocationAffectedImportV1>, M6RevocationError> {
        let state = self.state_guard()?;
        let mut records = state
            .affected
            .iter()
            .filter(|(key, _)| !state.resolutions.contains_key(*key))
            .map(|(_, record)| record.clone())
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.recorded_at_ms
                .cmp(&right.recorded_at_ms)
                .then(left.affected_digest.cmp(&right.affected_digest))
        });
        Ok(records)
    }

    /// Read one exact terminal containment resolution without mutating the
    /// ledger. Receiver orchestration uses this seam to resume after a crash
    /// without reissuing an already-completed deployment effect.
    pub fn containment_resolution(
        &self,
        affected_digest: &ContentDigest,
    ) -> Result<Option<RevocationContainmentResolutionV1>, M6RevocationError> {
        let state = self.state_guard()?;
        let Some(record) = state.resolutions.get(affected_digest.as_str()).cloned() else {
            return Ok(None);
        };
        let affected = state
            .affected
            .get(affected_digest.as_str())
            .ok_or_else(|| {
                M6RevocationError::Integrity(format!(
                    "containment resolution {affected_digest} has no affected-import record"
                ))
            })?;
        record.validate(affected)?;
        Ok(Some(record))
    }

    pub fn validate_all(&self) -> Result<(), M6RevocationError> {
        let reconstructed = reconstruct(
            &self.tombstones_root,
            &self.affected_root,
            &self.resolutions_root,
            &self.config,
        )?;
        let state = self.state_guard()?;
        if reconstructed.tombstones != state.tombstones
            || reconstructed.affected != state.affected
            || reconstructed.resolutions != state.resolutions
        {
            return Err(M6RevocationError::Integrity(
                "in-memory revocation projection differs from durable records".to_string(),
            ));
        }
        Ok(())
    }

    fn state_guard(&self) -> Result<MutexGuard<'_, LedgerState>, M6RevocationError> {
        self.state.lock().map_err(|_| {
            M6RevocationError::Integrity("revocation ledger mutex is poisoned".to_string())
        })
    }
}

fn reconstruct(
    tombstones_root: &Path,
    affected_root: &Path,
    resolutions_root: &Path,
    config: &RevocationLedgerConfigV1,
) -> Result<LedgerState, M6RevocationError> {
    let mut state = LedgerState::default();
    for path in regular_json_records(tombstones_root, config.max_tombstones)? {
        let record: RevocationTombstoneV1 = read_canonical_record(&path)?;
        record.validate(config)?;
        require_record_name(&path, &record.sender_message_digest)?;
        let key = record.sender_message_digest.as_str().to_string();
        if state.tombstones.insert(key, record).is_some() {
            return Err(M6RevocationError::Integrity(
                "duplicate revocation sender-message identity".to_string(),
            ));
        }
    }
    for path in regular_json_records(affected_root, config.max_affected_imports)? {
        let record: RevocationAffectedImportV1 = read_canonical_record(&path)?;
        require_record_name(&path, &record.affected_digest)?;
        let tombstone = state
            .tombstones
            .values()
            .find(|candidate| candidate.tombstone_digest == record.tombstone_digest)
            .ok_or_else(|| {
                M6RevocationError::FalseLink(
                    "affected import cites an absent tombstone".to_string(),
                )
            })?;
        record.validate(tombstone)?;
        let key = record.affected_digest.as_str().to_string();
        if state.affected.insert(key, record).is_some() {
            return Err(M6RevocationError::Integrity(
                "duplicate affected-import identity".to_string(),
            ));
        }
    }
    for path in regular_json_records(resolutions_root, config.max_affected_imports)? {
        let record: RevocationContainmentResolutionV1 = read_canonical_record(&path)?;
        require_record_name(&path, &record.affected_digest)?;
        let affected = state
            .affected
            .get(record.affected_digest.as_str())
            .ok_or_else(|| {
                M6RevocationError::FalseLink(
                    "containment resolution cites an absent affected import".to_string(),
                )
            })?;
        record.validate(affected)?;
        let key = record.affected_digest.as_str().to_string();
        if state.resolutions.insert(key, record).is_some() {
            return Err(M6RevocationError::Integrity(
                "duplicate containment resolution".to_string(),
            ));
        }
    }
    Ok(state)
}

fn regular_json_records(root: &Path, limit: u32) -> Result<Vec<PathBuf>, M6RevocationError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).map_err(|source| io_error(root, source))? {
        let entry = entry.map_err(|source| io_error(root, source))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || path.extension().and_then(|value| value.to_str()) != Some("json")
        {
            return Err(M6RevocationError::UnsafePath(path));
        }
        paths.push(path);
        if paths.len() > limit as usize {
            return Err(M6RevocationError::ResourceExhausted(format!(
                "record count beneath '{}' exceeds {limit}",
                root.display()
            )));
        }
    }
    paths.sort();
    Ok(paths)
}

fn record_name(digest: &ContentDigest) -> String {
    format!("{}.json", digest.file_stem())
}

fn require_record_name(path: &Path, digest: &ContentDigest) -> Result<(), M6RevocationError> {
    if path.file_name().and_then(|value| value.to_str()) != Some(record_name(digest).as_str()) {
        return Err(M6RevocationError::Integrity(format!(
            "record '{}' is stored beneath a noncanonical name",
            path.display()
        )));
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, M6RevocationError> {
    serde_json::to_vec(value).map_err(|error| M6RevocationError::Serialization(error.to_string()))
}

fn read_canonical_record<T: DeserializeOwned + Serialize>(
    path: &Path,
) -> Result<T, M6RevocationError> {
    let bytes = read_bounded(path, MAX_RECORD_BYTES)?;
    let value: T = serde_json::from_slice(&bytes)
        .map_err(|error| M6RevocationError::Serialization(error.to_string()))?;
    if canonical_json(&value)? != bytes {
        return Err(M6RevocationError::Integrity(format!(
            "record '{}' is not canonical JSON",
            path.display()
        )));
    }
    Ok(value)
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, M6RevocationError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > maximum as u64
    {
        return Err(M6RevocationError::UnsafePath(path.to_path_buf()));
    }
    let mut file = File::open(path).map_err(|source| io_error(path, source))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() > maximum {
        return Err(M6RevocationError::ResourceExhausted(format!(
            "record '{}' exceeds {maximum} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn persist_immutable(
    staging_root: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), M6RevocationError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(M6RevocationError::ResourceExhausted(
            "revocation record exceeds its byte budget".to_string(),
        ));
    }
    if destination.exists() {
        let existing = read_bounded(destination, MAX_RECORD_BYTES)?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(M6RevocationError::Conflict(format!(
                "immutable record '{}' already contains different bytes",
                destination.display()
            )))
        };
    }
    let parent = destination
        .parent()
        .ok_or_else(|| M6RevocationError::UnsafePath(destination.to_path_buf()))?;
    let temporary = staging_root.join(format!(
        ".building-{}-{}-{}",
        destination
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("record"),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|source| io_error(&temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| io_error(&temporary, source))?;
        file.sync_all()
            .map_err(|source| io_error(&temporary, source))?;
        fs::rename(&temporary, destination).map_err(|source| io_error(destination, source))?;
        sync_directory(parent)?;
        sync_directory(staging_root)
    })();
    if result.is_err() && temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M6RevocationError> {
    reject_unsafe_components(path)?;
    fs::create_dir_all(path).map_err(|source| io_error(path, source))?;
    let canonical = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    let metadata =
        fs::symlink_metadata(&canonical).map_err(|source| io_error(&canonical, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(M6RevocationError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M6RevocationError> {
    validate_identifier("revocation child directory", name)?;
    let path = root.join(name);
    fs::create_dir_all(&path).map_err(|source| io_error(&path, source))?;
    let canonical = fs::canonicalize(&path).map_err(|source| io_error(&path, source))?;
    if !canonical.starts_with(root) {
        return Err(M6RevocationError::UnsafePath(canonical));
    }
    let metadata =
        fs::symlink_metadata(&canonical).map_err(|source| io_error(&canonical, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(M6RevocationError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn reject_unsafe_components(path: &Path) -> Result<(), M6RevocationError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(M6RevocationError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn acquire_owner_lock(root: &Path) -> Result<File, M6RevocationError> {
    let path = root.join(OWNER_LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| io_error(&path, source))?;
    file.try_lock()
        .map_err(|_| M6RevocationError::AlreadyOwned(root.to_path_buf()))?;
    Ok(file)
}

fn recover_staging(root: &Path) -> Result<(), M6RevocationError> {
    let mut removed = false;
    for entry in fs::read_dir(root).map_err(|source| io_error(root, source))? {
        let entry = entry.map_err(|source| io_error(root, source))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".building-"))
        {
            return Err(M6RevocationError::UnsafePath(path));
        }
        fs::remove_file(&path).map_err(|source| io_error(&path, source))?;
        removed = true;
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), M6RevocationError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|source| io_error(path, source))
}

fn validate_identifier(label: &str, value: &str) -> Result<(), M6RevocationError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('\\')
        || value == "."
        || value == ".."
    {
        return Err(M6RevocationError::InvalidRecord(format!(
            "{label} is not a safe bounded identifier"
        )));
    }
    Ok(())
}

fn is_strictly_sorted_unique(values: &[ContentDigest]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn digest_domain<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<ContentDigest, M6RevocationError> {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&canonical_json(value)?);
    Ok(ContentDigest::from_bytes(&bytes))
}

fn require_digest(
    subject: &str,
    expected: &ContentDigest,
    actual: &ContentDigest,
) -> Result<(), M6RevocationError> {
    if expected != actual {
        return Err(M6RevocationError::DigestMismatch {
            subject: subject.to_string(),
            expected: expected.clone(),
            actual: actual.clone(),
        });
    }
    Ok(())
}

fn identity_error(error: crate::m6_identity::M6IdentityError) -> M6RevocationError {
    M6RevocationError::Identity(error.to_string())
}

fn io_error(path: &Path, source: std::io::Error) -> M6RevocationError {
    M6RevocationError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug)]
pub enum M6RevocationError {
    InvalidRecord(String),
    UnsupportedSchema(String),
    UnsupportedTargetKind(String),
    Serialization(String),
    Identity(String),
    ReplayNotCommitted(ContentDigest),
    FalseLink(String),
    Conflict(String),
    ConfigConflict {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    DigestMismatch {
        subject: String,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    ResourceExhausted(String),
    NotFound(String),
    AlreadyOwned(PathBuf),
    UnsafePath(PathBuf),
    Integrity(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl Display for M6RevocationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRecord(message) => {
                write!(formatter, "invalid M6 revocation record: {message}")
            }
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported M6 revocation schema '{schema}'")
            }
            Self::UnsupportedTargetKind(kind) => {
                write!(formatter, "unsupported M6 revocation target kind '{kind}'")
            }
            Self::Serialization(message) => {
                write!(formatter, "M6 revocation serialization failed: {message}")
            }
            Self::Identity(message) => {
                write!(formatter, "M6 revocation identity check failed: {message}")
            }
            Self::ReplayNotCommitted(digest) => write!(
                formatter,
                "revocation message {digest} has no exact durable replay commit"
            ),
            Self::FalseLink(message) => {
                write!(formatter, "M6 revocation false link: {message}")
            }
            Self::Conflict(message) => {
                write!(formatter, "M6 revocation conflict: {message}")
            }
            Self::ConfigConflict { expected, actual } => write!(
                formatter,
                "revocation ledger config differs: expected {expected}, got {actual}"
            ),
            Self::DigestMismatch {
                subject,
                expected,
                actual,
            } => write!(
                formatter,
                "{subject} digest mismatch: expected {expected}, got {actual}"
            ),
            Self::ResourceExhausted(message) => {
                write!(formatter, "M6 revocation resource exhausted: {message}")
            }
            Self::NotFound(subject) => {
                write!(formatter, "M6 revocation record not found: {subject}")
            }
            Self::AlreadyOwned(path) => write!(
                formatter,
                "revocation ledger '{}' already has a live owner",
                path.display()
            ),
            Self::UnsafePath(path) => {
                write!(formatter, "unsafe M6 revocation path '{}'", path.display())
            }
            Self::Integrity(message) => {
                write!(formatter, "M6 revocation integrity failure: {message}")
            }
            Self::Io { path, source } => write!(
                formatter,
                "M6 revocation I/O failure at '{}': {source}",
                path.display()
            ),
        }
    }
}

impl Error for M6RevocationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m6_identity::{
        DeterministicClock, FactoryIdentityDocument, FactorySigner, ManifestPayload,
        RevocationManifestPayload, RouteEndpointRole, RouteResourceProfile, UnsignedManifest,
    };
    static TEST_TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestTemp {
        path: PathBuf,
    }

    impl TestTemp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m6-revocation-{}-{}",
                std::process::id(),
                TEST_TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            if path.exists() {
                fs::remove_dir_all(&path).expect("remove stale temporary root");
            }
            fs::create_dir_all(&path).expect("create temporary root");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestTemp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct Fixture {
        _temp: TestTemp,
        root: PathBuf,
        route: RouteDefinition,
        sender: FactorySigner,
        clock: Arc<DeterministicClock>,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = TestTemp::new();
            let sender = FactorySigner::from_seed("sender-key", [1; 32]).expect("sender key");
            let receiver = FactorySigner::from_seed("receiver-key", [2; 32]).expect("receiver key");
            let package_schema = ContentDigest::from_bytes(b"package-schema");
            let interface_schema = ContentDigest::from_bytes(b"interface-schema");
            let authority = ContentDigest::from_bytes(b"authority");
            let policy = ContentDigest::from_bytes(b"policy");
            let sender_identity = FactoryIdentityDocument::new(
                "factory-a",
                &sender,
                1,
                1_000_000,
                vec![package_schema.clone()],
                vec![interface_schema.clone()],
                authority.clone(),
                policy.clone(),
            )
            .expect("sender identity");
            let receiver_identity = FactoryIdentityDocument::new(
                "factory-b",
                &receiver,
                1,
                1_000_000,
                vec![package_schema],
                vec![interface_schema],
                authority,
                policy.clone(),
            )
            .expect("receiver identity");
            let route = RouteDefinition::new(
                "a-to-b",
                1,
                &sender_identity,
                &receiver_identity,
                policy,
                RouteResourceProfile::bounded_default().expect("profile"),
            )
            .expect("route");
            Self {
                root: temp.path().join("revocations"),
                _temp: temp,
                route,
                sender,
                clock: Arc::new(DeterministicClock::new(10_000)),
            }
        }

        fn manifest(
            &self,
            sequence: u64,
            prior: Option<ContentDigest>,
            target_kind: RevocationTargetKindV1,
            target_identity: ContentDigest,
        ) -> SignedManifest {
            SignedManifest::sign(
                UnsignedManifest {
                    attachments: Vec::new(),
                    canonical_encoding_version: self.route.canonical_encoding_version,
                    expires_at_ms: 20_000,
                    issued_at_ms: 9_000,
                    kind: ManifestKind::Revocation,
                    nonce: format!("{:032x}", sequence),
                    origin_role: RouteEndpointRole::Sender,
                    origin_signing_key_id: self.route.sender.signing_key_id.clone(),
                    payload: ManifestPayload::Revocation(RevocationManifestPayload {
                        authorization_digest: ContentDigest::from_bytes(b"revocation-authority"),
                        reason: "receiver must contain this source".to_string(),
                        target_identity,
                        target_kind: target_kind.label().to_string(),
                    }),
                    policy_digest: self.route.exchange_policy_digest.clone(),
                    previous_message_digest: prior,
                    receiver_identity_document_digest: self
                        .route
                        .receiver
                        .identity_document_digest
                        .clone(),
                    resource_profile_digest: self.route.resource_profile.profile_digest.clone(),
                    route_generation: self.route.generation,
                    route_id: self.route.route_id.clone(),
                    schema: crate::m6_identity::SIGNED_MANIFEST_SCHEMA.to_string(),
                    sender_identity_document_digest: self
                        .route
                        .sender
                        .identity_document_digest
                        .clone(),
                    sequence,
                },
                &self.sender,
            )
            .expect("signed revocation")
        }

        fn replay(&self, manifest: &SignedManifest) -> ReplayCommitFact {
            ReplayCommitFact {
                message_digest: manifest.message_digest.clone(),
                nonce: manifest.unsigned.nonce.clone(),
                retained_until_ms: 500_000,
                route_definition_digest: self.route.definition_digest.clone(),
                sequence: manifest.unsigned.sequence,
            }
        }
    }

    fn binding() -> ExchangeRevocationBindingV1 {
        ExchangeRevocationBindingV1 {
            exchange_message_digest: ContentDigest::from_bytes(b"message"),
            receiver_import_plan_digest: ContentDigest::from_bytes(b"plan"),
            receiver_local_package_digest: ContentDigest::from_bytes(b"local"),
            source_identity_document_digest: ContentDigest::from_bytes(b"source-identity"),
            source_package_digest: ContentDigest::from_bytes(b"source-package"),
            source_signing_key_digest: ContentDigest::from_bytes(b"source-key"),
        }
    }

    #[test]
    fn tombstone_is_irreversible_idempotent_and_reconstructs_after_restart() {
        let fixture = Fixture::new();
        let binding = binding();
        let manifest = fixture.manifest(
            1,
            None,
            RevocationTargetKindV1::SourcePackage,
            binding.source_package_digest.clone(),
        );
        let ledger = ReceiverRevocationLedger::open_or_initialize(
            &fixture.root,
            fixture.route.clone(),
            fixture.clock.clone(),
        )
        .expect("ledger");
        let record = ledger
            .apply_authenticated(
                &manifest,
                &fixture.replay(&manifest),
                ContentDigest::from_bytes(b"raw"),
                ContentDigest::from_bytes(b"raw-record"),
            )
            .expect("apply");
        fixture.clock.advance(1_000);
        assert_eq!(
            ledger
                .apply_authenticated(
                    &manifest,
                    &fixture.replay(&manifest),
                    ContentDigest::from_bytes(b"raw"),
                    ContentDigest::from_bytes(b"raw-record"),
                )
                .expect("idempotent"),
            record
        );
        assert!(ledger.is_revoked(&binding).expect("query"));
        ledger.validate_all().expect("validate");
        drop(ledger);

        let reopened = ReceiverRevocationLedger::open_or_initialize(
            &fixture.root,
            fixture.route.clone(),
            fixture.clock.clone(),
        )
        .expect("reopen");
        assert_eq!(
            reopened.tombstone(&manifest.message_digest).expect("load"),
            Some(record)
        );
        assert!(reopened.is_revoked(&binding).expect("query after restart"));
    }

    #[test]
    fn all_four_target_kinds_match_only_the_exact_source_identity() {
        let fixture = Fixture::new();
        let binding = binding();
        let ledger = ReceiverRevocationLedger::open_or_initialize(
            &fixture.root,
            fixture.route.clone(),
            fixture.clock.clone(),
        )
        .expect("ledger");
        let kinds = [
            RevocationTargetKindV1::ExchangeMessage,
            RevocationTargetKindV1::SourcePackage,
            RevocationTargetKindV1::SourceSigningKey,
            RevocationTargetKindV1::SenderIdentity,
        ];
        let mut prior = None;
        for (index, kind) in kinds.into_iter().enumerate() {
            let manifest = fixture.manifest(
                index as u64 + 1,
                prior.clone(),
                kind,
                binding.target_identity(kind).clone(),
            );
            ledger
                .apply_authenticated(
                    &manifest,
                    &fixture.replay(&manifest),
                    ContentDigest::from_bytes(format!("raw-{index}").as_bytes()),
                    ContentDigest::from_bytes(format!("raw-record-{index}").as_bytes()),
                )
                .expect("apply");
            prior = Some(manifest.message_digest);
        }
        assert_eq!(
            ledger
                .matching_tombstones(&binding)
                .expect("matching")
                .len(),
            4
        );
        let mut changed = binding.clone();
        changed.source_package_digest = ContentDigest::from_bytes(b"other");
        assert_eq!(
            ledger
                .matching_tombstones(&changed)
                .expect("partial matching")
                .len(),
            3
        );
    }

    #[test]
    fn containment_intent_precedes_and_constrains_terminal_resolution() {
        let fixture = Fixture::new();
        let binding = binding();
        let manifest = fixture.manifest(
            1,
            None,
            RevocationTargetKindV1::SourcePackage,
            binding.source_package_digest.clone(),
        );
        let ledger = ReceiverRevocationLedger::open_or_initialize(
            &fixture.root,
            fixture.route.clone(),
            fixture.clock.clone(),
        )
        .expect("ledger");
        let tombstone = ledger
            .apply_authenticated(
                &manifest,
                &fixture.replay(&manifest),
                ContentDigest::from_bytes(b"raw"),
                ContentDigest::from_bytes(b"raw-record"),
            )
            .expect("apply");
        let affected = ledger
            .record_affected_import(
                &tombstone.tombstone_digest,
                binding,
                ReceiverImportDispositionV1::ActiveHealthy,
            )
            .expect("affected");
        fixture.clock.advance(1_000);
        assert_eq!(
            ledger
                .record_affected_import(
                    &tombstone.tombstone_digest,
                    affected.binding.clone(),
                    ReceiverImportDispositionV1::ActiveHealthy,
                )
                .expect("idempotent affected import"),
            affected
        );
        assert_eq!(
            affected.required_action,
            RequiredContainmentActionV1::StopAdmissionAndRollback
        );
        assert!(matches!(
            ledger.resolve_containment(
                &affected.affected_digest,
                RevocationContainmentOutcomeV1::AlreadyTerminal,
                Vec::new(),
            ),
            Err(M6RevocationError::FalseLink(_))
        ));
        assert_eq!(
            ledger
                .unresolved_affected_imports()
                .expect("unresolved")
                .len(),
            1
        );
        let resolution = ledger
            .resolve_containment(
                &affected.affected_digest,
                RevocationContainmentOutcomeV1::RolledBack,
                vec![ContentDigest::from_bytes(b"m5-rollback-receipt")],
            )
            .expect("resolution");
        fixture.clock.advance(1_000);
        assert_eq!(
            ledger
                .resolve_containment(
                    &affected.affected_digest,
                    RevocationContainmentOutcomeV1::RolledBack,
                    vec![ContentDigest::from_bytes(b"m5-rollback-receipt")],
                )
                .expect("idempotent resolution"),
            resolution
        );
        assert_eq!(
            resolution.outcome,
            RevocationContainmentOutcomeV1::RolledBack
        );
        assert!(
            ledger
                .unresolved_affected_imports()
                .expect("resolved")
                .is_empty()
        );
    }

    #[test]
    fn forged_replay_fact_and_tampered_durable_record_fail_closed() {
        let fixture = Fixture::new();
        let binding = binding();
        let manifest = fixture.manifest(
            1,
            None,
            RevocationTargetKindV1::ExchangeMessage,
            binding.exchange_message_digest,
        );
        let ledger = ReceiverRevocationLedger::open_or_initialize(
            &fixture.root,
            fixture.route.clone(),
            fixture.clock.clone(),
        )
        .expect("ledger");
        let mut replay = fixture.replay(&manifest);
        replay.message_digest = ContentDigest::from_bytes(b"forged");
        assert!(matches!(
            ledger.apply_authenticated(
                &manifest,
                &replay,
                ContentDigest::from_bytes(b"raw"),
                ContentDigest::from_bytes(b"raw-record"),
            ),
            Err(M6RevocationError::ReplayNotCommitted(_))
        ));
        let record = ledger
            .apply_authenticated(
                &manifest,
                &fixture.replay(&manifest),
                ContentDigest::from_bytes(b"raw"),
                ContentDigest::from_bytes(b"raw-record"),
            )
            .expect("apply");
        drop(ledger);
        let path = fixture
            .root
            .join(TOMBSTONES_DIRECTORY)
            .join(record_name(&record.sender_message_digest));
        let mut bytes = fs::read(&path).expect("read");
        let offset = bytes
            .windows(b"receiver must contain this source".len())
            .position(|window| window == b"receiver must contain this source")
            .expect("reason");
        bytes[offset] = b'R';
        fs::write(&path, bytes).expect("tamper");
        assert!(matches!(
            ReceiverRevocationLedger::open_or_initialize(
                &fixture.root,
                fixture.route,
                fixture.clock,
            ),
            Err(M6RevocationError::DigestMismatch { .. }) | Err(M6RevocationError::Integrity(_))
        ));
    }

    #[test]
    fn duplicate_owner_fails_without_mutating_ledger_bytes() {
        let fixture = Fixture::new();
        let ledger = ReceiverRevocationLedger::open_or_initialize(
            &fixture.root,
            fixture.route.clone(),
            fixture.clock.clone(),
        )
        .expect("ledger");
        let before = directory_snapshot(&fixture.root);
        assert!(matches!(
            ReceiverRevocationLedger::open_or_initialize(
                &fixture.root,
                fixture.route,
                fixture.clock,
            ),
            Err(M6RevocationError::AlreadyOwned(_))
        ));
        assert_eq!(directory_snapshot(&fixture.root), before);
        drop(ledger);
    }

    fn directory_snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, current: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let mut entries = fs::read_dir(current)
                .expect("read directory")
                .map(|entry| entry.expect("entry"))
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let relative = path.strip_prefix(root).expect("relative").to_path_buf();
                let kind = entry.file_type().expect("type");
                if kind.is_dir() {
                    visit(root, &path, result);
                } else if entry.file_name() != OWNER_LOCK_FILE {
                    result.insert(relative, fs::read(path).expect("read file"));
                }
            }
        }
        let mut result = BTreeMap::new();
        visit(root, root, &mut result);
        result
    }
}
