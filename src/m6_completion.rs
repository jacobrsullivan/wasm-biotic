//! Typed, exact-source M6 completion evidence for M7 closure review.
//!
//! This module is intentionally stricter than an exchange summary. A complete
//! bundle must carry canonical bytes from both independently rooted endpoints,
//! both signed restart chains, two distinct exchange outcomes that embed the
//! same exact M5 state, and separate tamper, replay, ACK, revocation, and
//! quarantine-inventory controls. Every M7 value is derived from those
//! sources; callers cannot supply success booleans.

use crate::execution::artifact::ContentDigest;
use crate::m5_export::M5ExportBundleV1;
use crate::m6_identity::{ROUTE_DEFINITION_SCHEMA, RouteDefinition};
use crate::m6_receiver_runtime::{
    RECEIVER_EXCHANGE_COMPLETION_EVIDENCE_SCHEMA, RECEIVER_REOPEN_PROOF_SCHEMA,
    RECEIVER_REVOCATION_COMPLETION_EVIDENCE_SCHEMA,
    RECEIVER_UNRESOLVED_QUARANTINE_INVENTORY_SCHEMA, ReceiverControlPlaneV1,
    ReceiverExchangeCompletionEvidenceV1, ReceiverM5Disposition, ReceiverNegativeControlSuiteV1,
    ReceiverReopenProofV1, ReceiverRevocationCompletionEvidenceV1,
    ReceiverSignedControlRejectionV1, ReceiverUnresolvedQuarantineInventoryV1,
};
use crate::m6_sender_ack_runtime::{
    SENDER_ACK_COMPLETION_EVIDENCE_SCHEMA, SenderAcknowledgementCompletionEvidenceV1,
    SenderPublicationKind,
};
use crate::m6_sender_runtime::{
    SENDER_EXPORT_COMPLETION_EVIDENCE_SCHEMA, SENDER_POST_ROLLBACK_ISOLATION_AUDIT_SCHEMA,
    SENDER_REOPEN_PROOF_SCHEMA, SenderExportCompletionEvidenceV1,
    SenderPostRollbackIsolationAuditV1, SenderReopenProofV1,
};
use crate::m6_transactions::TransactionStage;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};

pub const M6_COMPLETION_BUNDLE_SCHEMA: &str = "wasm-biotic.m6-completion-bundle.v1";
pub const M6_COMPLETION_SOURCE_SCHEMA: &str = "wasm-biotic.m6-completion-source.v1";

pub const RECEIVER_NEGATIVE_CONTROL_SUITE_REQUIRED_SCHEMA: &str =
    crate::m6_receiver_runtime::RECEIVER_NEGATIVE_CONTROL_SUITE_SCHEMA;
pub const RECEIVER_REPLAY_REJECTION_EVIDENCE_REQUIRED_SCHEMA: &str =
    crate::m6_receiver_runtime::RECEIVER_SIGNED_CONTROL_REJECTION_SCHEMA;
pub const REVOCATION_CONTROL_REQUIRED_SCHEMA: &str = RECEIVER_REVOCATION_COMPLETION_EVIDENCE_SCHEMA;

const BUNDLE_DIGEST_DOMAIN: &[u8] = b"wasm-biotic:m6:completion-bundle:v1\0";
const MAX_SOURCE_BYTES: usize = 256 * 1_048_576;
const MAX_BUNDLE_BYTES: usize = 256 * 1_048_576;
const MAX_SOURCE_COUNT: usize = 32;
const ROUTE_EVIDENCE_FIXED_ALLOWANCE_BYTES: u64 = 16 * 1_048_576;
const ROUTE_DELIVERY_COPY_ALLOWANCE: u64 = 12;
const ROUTE_MANIFEST_COPY_ALLOWANCE: u64 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M6CompletionSourceRoleV1 {
    RouteDefinition,
    AcceptedSenderCompletion,
    RolledBackSenderCompletion,
    SenderReopenProof,
    PostRollbackSenderIsolationAudit,
    AcceptedReceiverCompletion,
    RolledBackReceiverCompletion,
    ReceiverReopenProof,
    NegativeControlSuite,
    ReplayRejectionEvidence,
    QuarantineInventory,
    AcceptedAcknowledgement,
    RolledBackAcknowledgement,
    RevocationControl,
}

impl M6CompletionSourceRoleV1 {
    pub fn source_schema(self) -> &'static str {
        match self {
            Self::RouteDefinition => ROUTE_DEFINITION_SCHEMA,
            Self::AcceptedSenderCompletion | Self::RolledBackSenderCompletion => {
                SENDER_EXPORT_COMPLETION_EVIDENCE_SCHEMA
            }
            Self::SenderReopenProof => SENDER_REOPEN_PROOF_SCHEMA,
            Self::PostRollbackSenderIsolationAudit => SENDER_POST_ROLLBACK_ISOLATION_AUDIT_SCHEMA,
            Self::AcceptedReceiverCompletion | Self::RolledBackReceiverCompletion => {
                RECEIVER_EXCHANGE_COMPLETION_EVIDENCE_SCHEMA
            }
            Self::ReceiverReopenProof => RECEIVER_REOPEN_PROOF_SCHEMA,
            Self::NegativeControlSuite => RECEIVER_NEGATIVE_CONTROL_SUITE_REQUIRED_SCHEMA,
            Self::ReplayRejectionEvidence => RECEIVER_REPLAY_REJECTION_EVIDENCE_REQUIRED_SCHEMA,
            Self::QuarantineInventory => RECEIVER_UNRESOLVED_QUARANTINE_INVENTORY_SCHEMA,
            Self::AcceptedAcknowledgement | Self::RolledBackAcknowledgement => {
                SENDER_ACK_COMPLETION_EVIDENCE_SCHEMA
            }
            Self::RevocationControl => REVOCATION_CONTROL_REQUIRED_SCHEMA,
        }
    }
}

pub fn required_completion_source_roles() -> BTreeSet<M6CompletionSourceRoleV1> {
    BTreeSet::from([
        M6CompletionSourceRoleV1::RouteDefinition,
        M6CompletionSourceRoleV1::AcceptedSenderCompletion,
        M6CompletionSourceRoleV1::RolledBackSenderCompletion,
        M6CompletionSourceRoleV1::SenderReopenProof,
        M6CompletionSourceRoleV1::PostRollbackSenderIsolationAudit,
        M6CompletionSourceRoleV1::AcceptedReceiverCompletion,
        M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
        M6CompletionSourceRoleV1::ReceiverReopenProof,
        M6CompletionSourceRoleV1::NegativeControlSuite,
        M6CompletionSourceRoleV1::ReplayRejectionEvidence,
        M6CompletionSourceRoleV1::QuarantineInventory,
        M6CompletionSourceRoleV1::AcceptedAcknowledgement,
        M6CompletionSourceRoleV1::RolledBackAcknowledgement,
        M6CompletionSourceRoleV1::RevocationControl,
    ])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M6CompletionSourceV1 {
    schema: String,
    role: M6CompletionSourceRoleV1,
    source_schema: String,
    byte_length: u64,
    digest: ContentDigest,
    canonical_bytes: Vec<u8>,
}

impl M6CompletionSourceV1 {
    pub fn role(&self) -> M6CompletionSourceRoleV1 {
        self.role
    }

    pub fn source_schema(&self) -> &str {
        &self.source_schema
    }

    pub fn digest(&self) -> &ContentDigest {
        &self.digest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    fn new(
        role: M6CompletionSourceRoleV1,
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, M6CompletionError> {
        if canonical_bytes.is_empty() || canonical_bytes.len() > MAX_SOURCE_BYTES {
            return Err(M6CompletionError::ResourceBound(format!(
                "{role:?} source length must be in 1..={MAX_SOURCE_BYTES}"
            )));
        }
        Ok(Self {
            schema: M6_COMPLETION_SOURCE_SCHEMA.to_string(),
            role,
            source_schema: role.source_schema().to_string(),
            byte_length: canonical_bytes.len() as u64,
            digest: ContentDigest::from_bytes(&canonical_bytes),
            canonical_bytes,
        })
    }

    fn validate_envelope(&self) -> Result<(), M6CompletionError> {
        if self.schema != M6_COMPLETION_SOURCE_SCHEMA
            || self.source_schema != self.role.source_schema()
            || self.canonical_bytes.is_empty()
            || self.canonical_bytes.len() > MAX_SOURCE_BYTES
            || self.byte_length != self.canonical_bytes.len() as u64
            || self.digest != ContentDigest::from_bytes(&self.canonical_bytes)
        {
            return Err(M6CompletionError::InvalidSource {
                role: self.role,
                detail: "source envelope differs from its exact schema, length, or digest"
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// Mutable assembly form. Insertion records bytes but does not bless them;
/// finalization validates the exact required set and every detached source.
#[derive(Clone, Debug, Default)]
pub struct M6CompletionDraftV1 {
    sources: BTreeMap<M6CompletionSourceRoleV1, M6CompletionSourceV1>,
}

impl M6CompletionDraftV1 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_exact_source(
        &mut self,
        role: M6CompletionSourceRoleV1,
        canonical_bytes: Vec<u8>,
    ) -> Result<(), M6CompletionError> {
        if self.sources.contains_key(&role) {
            return Err(M6CompletionError::DuplicateSource(role));
        }
        let source = M6CompletionSourceV1::new(role, canonical_bytes)?;
        self.sources.insert(role, source);
        Ok(())
    }

    pub fn source_roles(&self) -> BTreeSet<M6CompletionSourceRoleV1> {
        self.sources.keys().copied().collect()
    }

    pub fn try_finalize(self) -> Result<M6CompletionBundleV1, M6CompletionError> {
        M6CompletionBundleV1::derive_from_source_map(self.sources)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M6CompletionDerivedFactsV1 {
    accepted_exchange_digest: ContentDigest,
    rejected_or_rolled_back_exchange_digest: ContentDigest,
    accepted_exchange_count: u32,
    rejected_or_rolled_back_count: u32,
    exact_bytes_verified: bool,
    sender_lineage_resolved: bool,
    receiver_proving_resolved: bool,
    negative_control_suite_passed: bool,
    replay_rejection_control_passed: bool,
    revocation_control_passed: bool,
    unresolved_quarantine_count: u32,
    receiver_rejection_or_rollback_complete: bool,
    sender_unchanged: bool,
    both_factories_restarted: bool,
    acknowledgement_used_as_adoption_evidence: bool,
}

impl M6CompletionDerivedFactsV1 {
    pub fn accepted_exchange_digest(&self) -> &ContentDigest {
        &self.accepted_exchange_digest
    }

    pub fn rejected_or_rolled_back_exchange_digest(&self) -> &ContentDigest {
        &self.rejected_or_rolled_back_exchange_digest
    }

    pub fn accepted_exchange_count(&self) -> u32 {
        self.accepted_exchange_count
    }

    pub fn rejected_or_rolled_back_count(&self) -> u32 {
        self.rejected_or_rolled_back_count
    }

    pub fn exact_bytes_verified(&self) -> bool {
        self.exact_bytes_verified
    }

    pub fn sender_lineage_resolved(&self) -> bool {
        self.sender_lineage_resolved
    }

    pub fn receiver_proving_resolved(&self) -> bool {
        self.receiver_proving_resolved
    }

    pub fn negative_control_suite_passed(&self) -> bool {
        self.negative_control_suite_passed
    }

    pub fn replay_rejection_control_passed(&self) -> bool {
        self.replay_rejection_control_passed
    }

    pub fn revocation_control_passed(&self) -> bool {
        self.revocation_control_passed
    }

    pub fn unresolved_quarantine_count(&self) -> u32 {
        self.unresolved_quarantine_count
    }

    pub fn receiver_rejection_or_rollback_complete(&self) -> bool {
        self.receiver_rejection_or_rollback_complete
    }

    pub fn sender_unchanged(&self) -> bool {
        self.sender_unchanged
    }

    pub fn both_factories_restarted(&self) -> bool {
        self.both_factories_restarted
    }

    pub fn acknowledgement_used_as_adoption_evidence(&self) -> bool {
        self.acknowledgement_used_as_adoption_evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M6CompletionBundleV1 {
    schema: String,
    route_definition_digest: ContentDigest,
    sender_factory_id: String,
    receiver_factory_id: String,
    sources: Vec<M6CompletionSourceV1>,
    derived: M6CompletionDerivedFactsV1,
    bundle_digest: ContentDigest,
}

impl M6CompletionBundleV1 {
    pub fn route_definition_digest(&self) -> &ContentDigest {
        &self.route_definition_digest
    }

    pub fn sender_factory_id(&self) -> &str {
        &self.sender_factory_id
    }

    pub fn receiver_factory_id(&self) -> &str {
        &self.receiver_factory_id
    }

    pub fn sources(&self) -> &[M6CompletionSourceV1] {
        &self.sources
    }

    pub fn derived(&self) -> &M6CompletionDerivedFactsV1 {
        &self.derived
    }

    pub fn bundle_digest(&self) -> &ContentDigest {
        &self.bundle_digest
    }

    /// Return the content identity of the exact canonical M5 export embedded
    /// by both sender outcomes in this completion bundle.
    ///
    /// The completion validator already requires the accepted and rolled-back
    /// sender records (and the post-rollback isolation audit) to carry the
    /// same M5 bytes. Revalidating here keeps this public projection
    /// fail-closed even when the value was obtained through deserialization
    /// rather than [`Self::from_canonical_bytes`].
    pub fn sender_m5_export_bundle_content_digest(
        &self,
    ) -> Result<ContentDigest, M6CompletionError> {
        self.validate()?;
        let accepted_source = self
            .sources
            .iter()
            .find(|source| source.role == M6CompletionSourceRoleV1::AcceptedSenderCompletion)
            .ok_or_else(|| {
                M6CompletionError::MissingSources(BTreeSet::from([
                    M6CompletionSourceRoleV1::AcceptedSenderCompletion,
                ]))
            })?;
        let route_source = self
            .sources
            .iter()
            .find(|source| source.role == M6CompletionSourceRoleV1::RouteDefinition)
            .ok_or_else(|| {
                M6CompletionError::MissingSources(BTreeSet::from([
                    M6CompletionSourceRoleV1::RouteDefinition,
                ]))
            })?;
        let route = parse_route(route_source.canonical_bytes())?;
        let accepted = SenderExportCompletionEvidenceV1::from_canonical_bytes_detached(
            accepted_source.canonical_bytes(),
            &route,
        )
        .map_err(|error| invalid(M6CompletionSourceRoleV1::AcceptedSenderCompletion, error))?;
        Ok(ContentDigest::from_bytes(accepted.m5_export_bundle_bytes()))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M6CompletionError> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(M6CompletionError::ResourceBound(
                "M6 completion bundle exceeds its byte budget".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M6CompletionError> {
        if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
            return Err(M6CompletionError::ResourceBound(
                "M6 completion bundle bytes are outside bounds".to_string(),
            ));
        }
        let bundle: Self = serde_json::from_slice(bytes)
            .map_err(|error| M6CompletionError::Serialization(error.to_string()))?;
        if canonical_json(&bundle)? != bytes {
            return Err(M6CompletionError::NonCanonical(
                "M6 completion bundle is not canonical JSON".to_string(),
            ));
        }
        bundle.validate()?;
        Ok(bundle)
    }

    fn derive_from_source_map(
        sources: BTreeMap<M6CompletionSourceRoleV1, M6CompletionSourceV1>,
    ) -> Result<Self, M6CompletionError> {
        let actual: BTreeSet<_> = sources.keys().copied().collect();
        let required = required_completion_source_roles();
        if !required.is_subset(&actual) {
            return Err(M6CompletionError::MissingSources(
                required.difference(&actual).copied().collect(),
            ));
        }
        if sources.len() > MAX_SOURCE_COUNT {
            return Err(M6CompletionError::ResourceBound(
                "M6 completion source count exceeds its bound".to_string(),
            ));
        }
        validate_aggregate_source_bytes(&sources, MAX_BUNDLE_BYTES as u64)?;
        for source in sources.values() {
            source.validate_envelope()?;
        }
        let route = parse_route(source_bytes(
            &sources,
            M6CompletionSourceRoleV1::RouteDefinition,
        )?)?;
        validate_route_aggregate_source_bytes(&sources, &route)?;

        // Validate and cross-link the independently signed sender projection
        // before reporting any receiver-owned API gap.
        let accepted_sender = SenderExportCompletionEvidenceV1::from_canonical_bytes_detached(
            source_bytes(&sources, M6CompletionSourceRoleV1::AcceptedSenderCompletion)?,
            &route,
        )
        .map_err(|error| invalid(M6CompletionSourceRoleV1::AcceptedSenderCompletion, error))?;
        let rolled_back_sender = SenderExportCompletionEvidenceV1::from_canonical_bytes_detached(
            source_bytes(
                &sources,
                M6CompletionSourceRoleV1::RolledBackSenderCompletion,
            )?,
            &route,
        )
        .map_err(|error| invalid(M6CompletionSourceRoleV1::RolledBackSenderCompletion, error))?;
        if accepted_sender.logical_operation_id() == rolled_back_sender.logical_operation_id()
            || accepted_sender.message_digest() == rolled_back_sender.message_digest()
            || accepted_sender.receipt_digest() == rolled_back_sender.receipt_digest()
        {
            return Err(M6CompletionError::CrossLink(
                "accepted and rolled-back exchanges must be distinct sender operations".to_string(),
            ));
        }
        let accepted_sender_m5 =
            M5ExportBundleV1::from_canonical_bytes(accepted_sender.m5_export_bundle_bytes())
                .map_err(|error| {
                    invalid(M6CompletionSourceRoleV1::AcceptedSenderCompletion, error)
                })?;
        let rolled_back_sender_m5 =
            M5ExportBundleV1::from_canonical_bytes(rolled_back_sender.m5_export_bundle_bytes())
                .map_err(|error| {
                    invalid(M6CompletionSourceRoleV1::RolledBackSenderCompletion, error)
                })?;
        if accepted_sender.m5_export_bundle_bytes() != rolled_back_sender.m5_export_bundle_bytes()
            || accepted_sender_m5 != rolled_back_sender_m5
        {
            return Err(M6CompletionError::CrossLink(
                "signed accepted/rolled-back sender sources embed different M5 state".to_string(),
            ));
        }
        let reopen = SenderReopenProofV1::from_canonical_bytes(
            source_bytes(&sources, M6CompletionSourceRoleV1::SenderReopenProof)?,
            &route,
        )
        .map_err(|error| invalid(M6CompletionSourceRoleV1::SenderReopenProof, error))?;
        for sender in [&accepted_sender, &rolled_back_sender] {
            if !reopen
                .proves_restart_of(
                    &route,
                    sender.logical_operation_id(),
                    sender.receipt_digest(),
                )
                .map_err(|error| invalid(M6CompletionSourceRoleV1::SenderReopenProof, error))?
            {
                return Err(M6CompletionError::CrossLink(format!(
                    "sender reopen proof does not recover '{}'",
                    sender.logical_operation_id()
                )));
            }
        }
        let sender_isolation = SenderPostRollbackIsolationAuditV1::from_canonical_bytes_detached(
            source_bytes(
                &sources,
                M6CompletionSourceRoleV1::PostRollbackSenderIsolationAudit,
            )?,
            &route,
        )
        .map_err(|error| {
            invalid(
                M6CompletionSourceRoleV1::PostRollbackSenderIsolationAudit,
                error,
            )
        })?;
        validate_sender_isolation_cross_links(
            &sender_isolation,
            &accepted_sender,
            &rolled_back_sender,
        )?;

        let accepted_ack =
            SenderAcknowledgementCompletionEvidenceV1::from_canonical_bytes_detached(
                source_bytes(&sources, M6CompletionSourceRoleV1::AcceptedAcknowledgement)?,
                &route,
            )
            .map_err(|error| invalid(M6CompletionSourceRoleV1::AcceptedAcknowledgement, error))?;
        let rolled_back_ack =
            SenderAcknowledgementCompletionEvidenceV1::from_canonical_bytes_detached(
                source_bytes(
                    &sources,
                    M6CompletionSourceRoleV1::RolledBackAcknowledgement,
                )?,
                &route,
            )
            .map_err(|error| invalid(M6CompletionSourceRoleV1::RolledBackAcknowledgement, error))?;
        validate_acknowledgement_cross_links(
            &accepted_ack,
            &accepted_sender,
            M6CompletionSourceRoleV1::AcceptedAcknowledgement,
            "healthy",
        )?;
        validate_acknowledgement_cross_links(
            &rolled_back_ack,
            &rolled_back_sender,
            M6CompletionSourceRoleV1::RolledBackAcknowledgement,
            "rolled_back",
        )?;
        if accepted_ack.acknowledgement_sequence() >= rolled_back_ack.acknowledgement_sequence()
            || accepted_ack.acknowledgement_message_digest()
                == rolled_back_ack.acknowledgement_message_digest()
            || accepted_ack.correlation_digest() == rolled_back_ack.correlation_digest()
            || accepted_ack.intake_record_digest() == rolled_back_ack.intake_record_digest()
            || accepted_ack.raw_quarantine_digest() == rolled_back_ack.raw_quarantine_digest()
            || accepted_ack.receiver_transaction_digest()
                == rolled_back_ack.receiver_transaction_digest()
            || accepted_ack.replay_fact_digest() == rolled_back_ack.replay_fact_digest()
        {
            return Err(M6CompletionError::CrossLink(
                "accepted and rolled-back ACKs must be distinct, ordered receiver publications"
                    .to_string(),
            ));
        }
        let accepted_receiver =
            ReceiverExchangeCompletionEvidenceV1::from_canonical_bytes_detached(
                source_bytes(
                    &sources,
                    M6CompletionSourceRoleV1::AcceptedReceiverCompletion,
                )?,
                &route,
            )
            .map_err(|error| {
                invalid(M6CompletionSourceRoleV1::AcceptedReceiverCompletion, error)
            })?;
        let rolled_back_receiver =
            ReceiverExchangeCompletionEvidenceV1::from_canonical_bytes_detached(
                source_bytes(
                    &sources,
                    M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
                )?,
                &route,
            )
            .map_err(|error| {
                invalid(
                    M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
                    error,
                )
            })?;
        validate_receiver_completion_cross_links(
            &accepted_receiver,
            &accepted_sender,
            &accepted_ack,
            &route,
            M6CompletionSourceRoleV1::AcceptedReceiverCompletion,
            ReceiverM5Disposition::Healthy,
            TransactionStage::Healthy,
        )?;
        validate_receiver_completion_cross_links(
            &rolled_back_receiver,
            &rolled_back_sender,
            &rolled_back_ack,
            &route,
            M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
            ReceiverM5Disposition::RolledBack,
            TransactionStage::RolledBack,
        )?;
        validate_receiver_outcome_pair(&accepted_receiver, &rolled_back_receiver)?;

        let receiver_reopen = ReceiverReopenProofV1::from_canonical_bytes_detached(
            source_bytes(&sources, M6CompletionSourceRoleV1::ReceiverReopenProof)?,
            &route,
        )
        .map_err(|error| invalid(M6CompletionSourceRoleV1::ReceiverReopenProof, error))?;
        let quarantine_inventory =
            ReceiverUnresolvedQuarantineInventoryV1::from_canonical_bytes_detached(
                source_bytes(&sources, M6CompletionSourceRoleV1::QuarantineInventory)?,
                &route,
            )
            .map_err(|error| invalid(M6CompletionSourceRoleV1::QuarantineInventory, error))?;
        validate_receiver_reopen_and_inventory_cross_links(
            &receiver_reopen,
            &quarantine_inventory,
            &accepted_receiver,
            &rolled_back_receiver,
            &route,
        )?;

        // Every control is validated through its owning runtime's detached
        // parser. No caller-supplied success fact can bridge this list.
        for role in [
            M6CompletionSourceRoleV1::NegativeControlSuite,
            M6CompletionSourceRoleV1::ReplayRejectionEvidence,
            M6CompletionSourceRoleV1::RevocationControl,
        ] {
            validate_detached_source(
                sources
                    .get(&role)
                    .ok_or_else(|| M6CompletionError::MissingSources(BTreeSet::from([role])))?,
                &route,
            )?;
        }
        let derived = derive_completion_facts_from_validated_sources(&sources, &route)?;
        let mut bundle = Self {
            schema: M6_COMPLETION_BUNDLE_SCHEMA.to_string(),
            route_definition_digest: route.definition_digest.clone(),
            sender_factory_id: route.sender.factory_id.clone(),
            receiver_factory_id: route.receiver.factory_id.clone(),
            sources: sources.into_values().collect(),
            derived,
            bundle_digest: ContentDigest::from_bytes(&[]),
        };
        bundle.bundle_digest = bundle.expected_digest()?;
        if canonical_json(&bundle)?.len() > MAX_BUNDLE_BYTES {
            return Err(M6CompletionError::ResourceBound(
                "M6 completion bundle exceeds its canonical byte budget".to_string(),
            ));
        }
        Ok(bundle)
    }

    fn validate(&self) -> Result<(), M6CompletionError> {
        if self.schema != M6_COMPLETION_BUNDLE_SCHEMA
            || self.sources.is_empty()
            || self.sources.len() > MAX_SOURCE_COUNT
            || !self
                .sources
                .windows(2)
                .all(|pair| pair[0].role < pair[1].role)
        {
            return Err(M6CompletionError::InvalidBundle(
                "M6 completion bundle has invalid schema or source ordering".to_string(),
            ));
        }
        let sources: BTreeMap<_, _> = self
            .sources
            .iter()
            .cloned()
            .map(|source| (source.role, source))
            .collect();
        if sources.len() != self.sources.len() {
            return Err(M6CompletionError::InvalidBundle(
                "M6 completion bundle repeats a semantic source role".to_string(),
            ));
        }
        let rebuilt = Self::derive_from_source_map(sources)?;
        if rebuilt.route_definition_digest != self.route_definition_digest
            || rebuilt.sender_factory_id != self.sender_factory_id
            || rebuilt.receiver_factory_id != self.receiver_factory_id
            || rebuilt.derived != self.derived
        {
            return Err(M6CompletionError::InvalidBundle(
                "M6 completion derived projection differs from exact sources".to_string(),
            ));
        }
        require_digest(
            "M6 completion bundle",
            &self.bundle_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6CompletionError> {
        digest_domain(
            BUNDLE_DIGEST_DOMAIN,
            &(
                &self.schema,
                &self.route_definition_digest,
                &self.sender_factory_id,
                &self.receiver_factory_id,
                &self.sources,
                &self.derived,
            ),
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_sender_revocation_chronology(
    accepted_sequence: u64,
    accepted_committed_at_ms: u64,
    accepted_message_digest: &ContentDigest,
    revocation_sequence: u64,
    revocation_previous_message_digest: Option<&ContentDigest>,
    revocation_issued_at_ms: u64,
    revocation_committed_at_ms: u64,
    revocation_message_digest: &ContentDigest,
    rolled_back_sequence: u64,
    rolled_back_previous_message_digest: Option<&ContentDigest>,
    rolled_back_committed_at_ms: u64,
    rolled_back_message_digest: &ContentDigest,
) -> Result<(), M6CompletionError> {
    if accepted_sequence.checked_add(1) != Some(revocation_sequence)
        || revocation_sequence.checked_add(1) != Some(rolled_back_sequence)
        || revocation_previous_message_digest != Some(accepted_message_digest)
        || rolled_back_previous_message_digest != Some(revocation_message_digest)
        || accepted_committed_at_ms >= revocation_issued_at_ms
        || revocation_issued_at_ms > revocation_committed_at_ms
        || revocation_committed_at_ms >= rolled_back_committed_at_ms
        || accepted_message_digest == revocation_message_digest
        || accepted_message_digest == rolled_back_message_digest
        || revocation_message_digest == rolled_back_message_digest
    {
        return Err(M6CompletionError::CrossLink(
            "accepted export, revocation, and rolled-back export are not one exact adjacent sender route chain"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_revocation_cross_links(
    revocation: &ReceiverRevocationCompletionEvidenceV1,
    accepted_sender: &SenderExportCompletionEvidenceV1,
    rolled_back_sender: &SenderExportCompletionEvidenceV1,
    accepted_receiver: &ReceiverExchangeCompletionEvidenceV1,
    rolled_back_receiver: &ReceiverExchangeCompletionEvidenceV1,
) -> Result<(), M6CompletionError> {
    validate_sender_revocation_chronology(
        accepted_sender.sequence(),
        accepted_sender.committed_at_ms(),
        accepted_sender.message_digest(),
        revocation.sender_sequence(),
        revocation.sender_previous_message_digest(),
        revocation.sender_issued_at_ms(),
        revocation.sender_committed_at_ms(),
        revocation.sender_message_digest(),
        rolled_back_sender.sequence(),
        rolled_back_sender.previous_message_digest(),
        rolled_back_sender.committed_at_ms(),
        rolled_back_sender.message_digest(),
    )?;
    if revocation.affected_operation_count() != 1
        || !revocation.proves_rollback_of(accepted_receiver)
        || revocation.proves_rollback_of(rolled_back_receiver)
        || revocation.prior_source_authorization_evidence_digest()
            != &accepted_sender.source_digests().authorization_consumption
        || revocation.final_active_snapshot_digest()
            != accepted_receiver.prior_active_snapshot_digest()
        || revocation.final_active_snapshot_digest()
            != rolled_back_receiver.prior_active_snapshot_digest()
        || revocation.final_active_snapshot_digest()
            != rolled_back_receiver.final_active_snapshot_digest()
    {
        return Err(M6CompletionError::CrossLink(
            "revocation control is not the exact accepted-export rollback separating the two receiver outcomes"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_acknowledgement_cross_links(
    acknowledgement: &SenderAcknowledgementCompletionEvidenceV1,
    sender: &SenderExportCompletionEvidenceV1,
    role: M6CompletionSourceRoleV1,
    required_disposition: &str,
) -> Result<(), M6CompletionError> {
    if acknowledgement.sender_publication_kind() != SenderPublicationKind::Export
        || acknowledgement.sender_message_digest() != sender.message_digest()
        || acknowledgement.sender_sequence() != sender.sequence()
        || acknowledgement.source_receipt_digest() != sender.receipt_digest()
        || acknowledgement.disposition() != required_disposition
        || !acknowledgement.intake_only()
        || acknowledgement.adoption_inferred()
    {
        return Err(M6CompletionError::InvalidSource {
            role,
            detail: format!(
                "ACK must be intake-only and correlate the exact sender export with disposition '{required_disposition}'"
            ),
        });
    }
    Ok(())
}

fn validate_sender_isolation_cross_links(
    isolation: &SenderPostRollbackIsolationAuditV1,
    accepted: &SenderExportCompletionEvidenceV1,
    rolled_back: &SenderExportCompletionEvidenceV1,
) -> Result<(), M6CompletionError> {
    if isolation.accepted_export_operation_id() != accepted.logical_operation_id()
        || isolation.accepted_export_evidence_digest() != accepted.evidence_digest()
        || isolation.rolled_back_export_operation_id() != rolled_back.logical_operation_id()
        || isolation.rolled_back_export_evidence_digest() != rolled_back.evidence_digest()
        || isolation.m5_export_bundle_bytes() != accepted.m5_export_bundle_bytes()
        || isolation.m5_export_bundle_bytes() != rolled_back.m5_export_bundle_bytes()
    {
        return Err(M6CompletionError::CrossLink(
            "sender isolation audit must identify both exact signed exports and preserve their exact M5 state after receiver rollback"
                .to_string(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_receiver_completion_cross_links(
    receiver: &ReceiverExchangeCompletionEvidenceV1,
    sender: &SenderExportCompletionEvidenceV1,
    acknowledgement: &SenderAcknowledgementCompletionEvidenceV1,
    route: &RouteDefinition,
    role: M6CompletionSourceRoleV1,
    required_disposition: ReceiverM5Disposition,
    required_terminal_stage: TransactionStage,
) -> Result<(), M6CompletionError> {
    let intake_record = receiver
        .intake_record_digest()
        .map_err(|error| invalid(role, error))?;
    let coordinator_request = receiver
        .coordinator_request_digest()
        .map_err(|error| invalid(role, error))?;
    let raw_quarantine = receiver
        .raw_quarantine_digest()
        .map_err(|error| invalid(role, error))?;
    let replay_control = receiver
        .replay_control_proof_digest()
        .map_err(|error| invalid(role, error))?;
    let replay_fact = receiver
        .replay_fact_digest()
        .map_err(|error| invalid(role, error))?;
    let replay_sequence = receiver
        .replay_sequence()
        .map_err(|error| invalid(role, error))?;
    let acknowledgement_request = receiver
        .acknowledgement_request_digest()
        .map_err(|error| invalid(role, error))?;
    let ack_intake = receiver
        .ack_intake_record_digest()
        .map_err(|error| invalid(role, error))?;
    let ack_raw = receiver
        .ack_raw_quarantine_digest()
        .map_err(|error| invalid(role, error))?;
    let ack_transaction = receiver
        .ack_receiver_transaction_digest()
        .map_err(|error| invalid(role, error))?;
    let ack_sender_message = receiver
        .ack_sender_message_digest()
        .map_err(|error| invalid(role, error))?;
    let ack_message = receiver
        .acknowledgement_message_digest()
        .map_err(|error| invalid(role, error))?;
    let ack_sequence = receiver
        .acknowledgement_sequence()
        .map_err(|error| invalid(role, error))?;
    let acknowledgement_receipt = receiver
        .acknowledgement_receipt_digest()
        .map_err(|error| invalid(role, error))?;
    validate_directional_replay_fact_separation(
        &replay_fact,
        acknowledgement.replay_fact_digest(),
        role,
    )?;
    if receiver.route_definition_digest() != &route.definition_digest
        || receiver.sender_factory_id() != route.sender.factory_id
        || receiver.receiver_factory_id() != route.receiver.factory_id
        || receiver.message_digest() != sender.message_digest()
        || receiver.export_bundle_digest() != sender.bundle_digest()
        || receiver.source_package_digest() != sender.package_digest()
        || receiver.disposition() != required_disposition
        || receiver.terminal_stage() != required_terminal_stage
        || acknowledgement.receiver_transaction_digest() != receiver.terminal_stage_digest()
        || intake_record == coordinator_request
        || intake_record != ack_intake
        || acknowledgement.intake_record_digest() != &intake_record
        || raw_quarantine != ack_raw
        || acknowledgement.raw_quarantine_digest() != &raw_quarantine
        || ack_transaction != *receiver.terminal_stage_digest()
        || acknowledgement.receiver_transaction_digest() != &ack_transaction
        || ack_sender_message != *sender.message_digest()
        || acknowledgement.sender_message_digest() != &ack_sender_message
        || ack_message != *acknowledgement.acknowledgement_message_digest()
        || ack_sequence != acknowledgement.acknowledgement_sequence()
        || replay_sequence != sender.sequence()
        || replay_control == replay_fact
        || acknowledgement_request == acknowledgement_receipt
    {
        return Err(M6CompletionError::InvalidSource {
            role,
            detail:
                "receiver completion must identify the exact route, signed sender publication, terminal outcome, and sender-observed ACK transaction"
                    .to_string(),
        });
    }

    let before_input = receiver
        .behavior_probe_input()
        .map_err(|error| invalid(role, error))?;
    let before = receiver
        .before_behavior_output()
        .map_err(|error| invalid(role, error))?;
    let after = receiver
        .after_behavior_output()
        .map_err(|error| invalid(role, error))?;
    let behavior_change = receiver
        .behavior_change_evidence_digest()
        .map_err(|error| invalid(role, error))?;
    let failure_observed = receiver
        .post_adoption_failure_observed()
        .map_err(|error| invalid(role, error))?;
    let restored = receiver
        .restored_behavior_output()
        .map_err(|error| invalid(role, error))?;
    let restored_input = receiver
        .restored_behavior_input()
        .map_err(|error| invalid(role, error))?;
    let post_rollback_probe = receiver
        .post_rollback_probe_digest()
        .map_err(|error| invalid(role, error))?;
    let valid_behavior = match required_disposition {
        ReceiverM5Disposition::Healthy => {
            receiver.proves_observable_behavior_change()
                && !failure_observed
                && after.is_some_and(|output| output != before)
                && behavior_change.is_some()
                && restored.is_none()
                && restored_input.is_none()
                && post_rollback_probe.is_none()
        }
        ReceiverM5Disposition::RolledBack => {
            receiver.proves_restored_incumbent_behavior()
                && failure_observed
                && after.is_none()
                && behavior_change.is_none()
                && restored.is_some()
                && restored_input.is_some_and(|input| input != before_input)
                && post_rollback_probe.is_some()
        }
        ReceiverM5Disposition::ValidationRejected => false,
    };
    if !valid_behavior {
        return Err(M6CompletionError::InvalidSource {
            role,
            detail:
                "receiver completion lacks the required pre-activation, behavior-change, post-adoption-failure, or restored-behavior proof"
                    .to_string(),
        });
    }
    Ok(())
}

fn validate_directional_replay_fact_separation(
    receiver_export_replay_fact: &ContentDigest,
    sender_ack_replay_fact: &ContentDigest,
    role: M6CompletionSourceRoleV1,
) -> Result<(), M6CompletionError> {
    if receiver_export_replay_fact == sender_ack_replay_fact {
        return Err(M6CompletionError::InvalidSource {
            role,
            detail:
                "receiver export replay fact and sender acknowledgement replay fact collapse two directional message domains"
                    .to_string(),
        });
    }
    Ok(())
}

fn validate_receiver_outcome_pair(
    accepted: &ReceiverExchangeCompletionEvidenceV1,
    rolled_back: &ReceiverExchangeCompletionEvidenceV1,
) -> Result<(), M6CompletionError> {
    let accepted_input = accepted
        .behavior_probe_input()
        .map_err(|error| invalid(M6CompletionSourceRoleV1::AcceptedReceiverCompletion, error))?;
    let accepted_after = accepted
        .after_behavior_output()
        .map_err(|error| invalid(M6CompletionSourceRoleV1::AcceptedReceiverCompletion, error))?
        .ok_or_else(|| {
            M6CompletionError::CrossLink(
                "accepted receiver completion has no post-activation behavior output".to_string(),
            )
        })?;
    let accepted_before = accepted
        .before_behavior_output()
        .map_err(|error| invalid(M6CompletionSourceRoleV1::AcceptedReceiverCompletion, error))?;
    let rolled_back_input = rolled_back.behavior_probe_input().map_err(|error| {
        invalid(
            M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
            error,
        )
    })?;
    let rolled_back_before = rolled_back.before_behavior_output().map_err(|error| {
        invalid(
            M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
            error,
        )
    })?;
    let rolled_back_restored = rolled_back.restored_behavior_output().map_err(|error| {
        invalid(
            M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
            error,
        )
    })?;
    let rolled_back_restored_input = rolled_back.restored_behavior_input().map_err(|error| {
        invalid(
            M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
            error,
        )
    })?;
    let accepted_pre_activation = accepted
        .pre_activation_probe_digest()
        .map_err(|error| invalid(M6CompletionSourceRoleV1::AcceptedReceiverCompletion, error))?;
    let rolled_back_pre_activation =
        rolled_back.pre_activation_probe_digest().map_err(|error| {
            invalid(
                M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
                error,
            )
        })?;
    let accepted_behavior = accepted
        .behavior_change_evidence_digest()
        .map_err(|error| invalid(M6CompletionSourceRoleV1::AcceptedReceiverCompletion, error))?
        .ok_or_else(|| {
            M6CompletionError::CrossLink(
                "accepted receiver completion has no behavior-change digest".to_string(),
            )
        })?;
    let rolled_back_probe = rolled_back
        .post_rollback_probe_digest()
        .map_err(|error| {
            invalid(
                M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
                error,
            )
        })?
        .ok_or_else(|| {
            M6CompletionError::CrossLink(
                "rolled-back receiver completion has no post-rollback probe digest".to_string(),
            )
        })?;
    if accepted.logical_operation_id() == rolled_back.logical_operation_id()
        || accepted.evidence_digest() == rolled_back.evidence_digest()
        || accepted.terminal_stage_digest() == rolled_back.terminal_stage_digest()
        || accepted.adoption_receipt_digest() == rolled_back.adoption_receipt_digest()
        || accepted.proving_digest() == rolled_back.proving_digest()
        || accepted.import_plan_digest() == rolled_back.import_plan_digest()
        || accepted_pre_activation == rolled_back_pre_activation
        || accepted_behavior == rolled_back_probe
    {
        return Err(M6CompletionError::CrossLink(
            "accepted and rolled-back receiver evidence must identify distinct operations, proving runs, plans, probes, receipts, and terminal records"
                .to_string(),
        ));
    }
    validate_receiver_outcome_chronology(
        accepted.prior_active_snapshot_digest(),
        accepted.final_active_snapshot_digest(),
        rolled_back.prior_active_snapshot_digest(),
        rolled_back.final_active_snapshot_digest(),
        accepted_input,
        rolled_back_input,
        accepted_before,
        accepted_after,
        rolled_back_before,
        rolled_back_restored_input,
        rolled_back_restored,
    )
}

fn validate_receiver_reopen_and_inventory_cross_links(
    reopen: &ReceiverReopenProofV1,
    inventory: &ReceiverUnresolvedQuarantineInventoryV1,
    accepted: &ReceiverExchangeCompletionEvidenceV1,
    rolled_back: &ReceiverExchangeCompletionEvidenceV1,
    route: &RouteDefinition,
) -> Result<(), M6CompletionError> {
    for receiver in [accepted, rolled_back] {
        if !reopen
            .proves_restart_of(
                route,
                receiver.logical_operation_id(),
                receiver.adoption_receipt_digest(),
            )
            .map_err(|error| invalid(M6CompletionSourceRoleV1::ReceiverReopenProof, error))?
        {
            return Err(M6CompletionError::CrossLink(format!(
                "receiver reopen proof does not recover operation '{}' with its exact adoption receipt",
                receiver.logical_operation_id()
            )));
        }
    }

    let embedded_inventory = reopen
        .current_quarantine_inventory(route)
        .map_err(|error| invalid(M6CompletionSourceRoleV1::ReceiverReopenProof, error))?;
    let proves_zero = reopen
        .proves_zero_unresolved_quarantine(route)
        .map_err(|error| invalid(M6CompletionSourceRoleV1::ReceiverReopenProof, error))?;
    if embedded_inventory != *inventory
        || embedded_inventory.inventory_digest() != inventory.inventory_digest()
        || !proves_zero
        || !inventory.is_empty()
        || inventory.unresolved_count() != 0
    {
        return Err(M6CompletionError::CrossLink(
            "receiver reopen proof must embed the exact separately supplied signed inventory and prove zero unresolved quarantine after restart"
                .to_string(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_receiver_outcome_chronology(
    accepted_prior_snapshot: &ContentDigest,
    accepted_final_snapshot: &ContentDigest,
    rolled_back_prior_snapshot: &ContentDigest,
    rolled_back_final_snapshot: &ContentDigest,
    accepted_probe_input: i32,
    rolled_back_probe_input: i32,
    accepted_before_output: i32,
    accepted_after_output: i32,
    rolled_back_before_output: i32,
    rolled_back_restored_input: Option<i32>,
    rolled_back_restored_output: Option<i32>,
) -> Result<(), M6CompletionError> {
    if accepted_prior_snapshot == accepted_final_snapshot
        || accepted_prior_snapshot != rolled_back_prior_snapshot
        || rolled_back_prior_snapshot != rolled_back_final_snapshot
        || accepted_probe_input != rolled_back_probe_input
        || accepted_before_output != rolled_back_before_output
        || accepted_after_output == rolled_back_before_output
        || rolled_back_restored_input.is_none()
        || rolled_back_restored_input == Some(rolled_back_probe_input)
        || rolled_back_restored_output.is_none()
    {
        return Err(M6CompletionError::CrossLink(
            "receiver outcomes must start from the same incumbent, prove an accepted behavior change, and prove rollback restoration after the intervening revocation"
                .to_string(),
        ));
    }
    Ok(())
}

fn derive_completion_facts_from_validated_sources(
    sources: &BTreeMap<M6CompletionSourceRoleV1, M6CompletionSourceV1>,
    route: &RouteDefinition,
) -> Result<M6CompletionDerivedFactsV1, M6CompletionError> {
    let _negative_control_suite = ReceiverNegativeControlSuiteV1::from_canonical_bytes_detached(
        source_bytes(sources, M6CompletionSourceRoleV1::NegativeControlSuite)?,
        route,
    )
    .map_err(|error| invalid(M6CompletionSourceRoleV1::NegativeControlSuite, error))?;
    let replay = ReceiverSignedControlRejectionV1::from_canonical_bytes(
        source_bytes(sources, M6CompletionSourceRoleV1::ReplayRejectionEvidence)?,
        route,
    )
    .map_err(|error| invalid(M6CompletionSourceRoleV1::ReplayRejectionEvidence, error))?;
    if replay.control_plane() != ReceiverControlPlaneV1::Replay {
        return Err(M6CompletionError::InvalidSource {
            role: M6CompletionSourceRoleV1::ReplayRejectionEvidence,
            detail: "completion replay source is not a receiver-signed replay-plane rejection"
                .to_string(),
        });
    }

    let accepted_sender = SenderExportCompletionEvidenceV1::from_canonical_bytes_detached(
        source_bytes(sources, M6CompletionSourceRoleV1::AcceptedSenderCompletion)?,
        route,
    )
    .map_err(|error| invalid(M6CompletionSourceRoleV1::AcceptedSenderCompletion, error))?;
    let rolled_back_sender = SenderExportCompletionEvidenceV1::from_canonical_bytes_detached(
        source_bytes(
            sources,
            M6CompletionSourceRoleV1::RolledBackSenderCompletion,
        )?,
        route,
    )
    .map_err(|error| invalid(M6CompletionSourceRoleV1::RolledBackSenderCompletion, error))?;
    if replay.message_digest() != accepted_sender.message_digest()
        && replay.message_digest() != rolled_back_sender.message_digest()
    {
        return Err(M6CompletionError::CrossLink(
            "replay rejection does not target either exact completion export".to_string(),
        ));
    }

    let accepted_receiver = ReceiverExchangeCompletionEvidenceV1::from_canonical_bytes_detached(
        source_bytes(
            sources,
            M6CompletionSourceRoleV1::AcceptedReceiverCompletion,
        )?,
        route,
    )
    .map_err(|error| invalid(M6CompletionSourceRoleV1::AcceptedReceiverCompletion, error))?;
    let rolled_back_receiver = ReceiverExchangeCompletionEvidenceV1::from_canonical_bytes_detached(
        source_bytes(
            sources,
            M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
        )?,
        route,
    )
    .map_err(|error| {
        invalid(
            M6CompletionSourceRoleV1::RolledBackReceiverCompletion,
            error,
        )
    })?;
    let revocation = ReceiverRevocationCompletionEvidenceV1::from_canonical_bytes_detached(
        source_bytes(sources, M6CompletionSourceRoleV1::RevocationControl)?,
        route,
    )
    .map_err(|error| invalid(M6CompletionSourceRoleV1::RevocationControl, error))?;
    validate_revocation_cross_links(
        &revocation,
        &accepted_sender,
        &rolled_back_sender,
        &accepted_receiver,
        &rolled_back_receiver,
    )?;

    Ok(M6CompletionDerivedFactsV1 {
        accepted_exchange_digest: accepted_receiver.evidence_digest().clone(),
        rejected_or_rolled_back_exchange_digest: rolled_back_receiver.evidence_digest().clone(),
        accepted_exchange_count: 1,
        rejected_or_rolled_back_count: 1,
        exact_bytes_verified: true,
        sender_lineage_resolved: true,
        receiver_proving_resolved: true,
        negative_control_suite_passed: true,
        replay_rejection_control_passed: true,
        revocation_control_passed: true,
        unresolved_quarantine_count: 0,
        receiver_rejection_or_rollback_complete: true,
        sender_unchanged: true,
        both_factories_restarted: true,
        acknowledgement_used_as_adoption_evidence: false,
    })
}

fn validate_detached_source(
    source: &M6CompletionSourceV1,
    route: &RouteDefinition,
) -> Result<(), M6CompletionError> {
    match source.role {
        M6CompletionSourceRoleV1::RouteDefinition => {
            let parsed = parse_route(&source.canonical_bytes)?;
            if parsed != *route {
                return Err(M6CompletionError::CrossLink(
                    "route source changed during validation".to_string(),
                ));
            }
            Ok(())
        }
        M6CompletionSourceRoleV1::AcceptedSenderCompletion
        | M6CompletionSourceRoleV1::RolledBackSenderCompletion => {
            SenderExportCompletionEvidenceV1::from_canonical_bytes_detached(
                &source.canonical_bytes,
                route,
            )
            .map(|_| ())
            .map_err(|error| invalid(source.role, error))
        }
        M6CompletionSourceRoleV1::SenderReopenProof => {
            SenderReopenProofV1::from_canonical_bytes(&source.canonical_bytes, route)
                .map(|_| ())
                .map_err(|error| invalid(source.role, error))
        }
        M6CompletionSourceRoleV1::PostRollbackSenderIsolationAudit => {
            SenderPostRollbackIsolationAuditV1::from_canonical_bytes_detached(
                &source.canonical_bytes,
                route,
            )
            .map(|_| ())
            .map_err(|error| invalid(source.role, error))
        }
        M6CompletionSourceRoleV1::NegativeControlSuite => {
            ReceiverNegativeControlSuiteV1::from_canonical_bytes_detached(
                &source.canonical_bytes,
                route,
            )
            .map(|_| ())
            .map_err(|error| invalid(source.role, error))
        }
        M6CompletionSourceRoleV1::AcceptedReceiverCompletion
        | M6CompletionSourceRoleV1::RolledBackReceiverCompletion => {
            ReceiverExchangeCompletionEvidenceV1::from_canonical_bytes_detached(
                &source.canonical_bytes,
                route,
            )
            .map(|_| ())
            .map_err(|error| invalid(source.role, error))
        }
        M6CompletionSourceRoleV1::ReceiverReopenProof => {
            ReceiverReopenProofV1::from_canonical_bytes_detached(&source.canonical_bytes, route)
                .map(|_| ())
                .map_err(|error| invalid(source.role, error))
        }
        M6CompletionSourceRoleV1::ReplayRejectionEvidence => {
            let rejection = ReceiverSignedControlRejectionV1::from_canonical_bytes(
                &source.canonical_bytes,
                route,
            )
            .map_err(|error| invalid(source.role, error))?;
            if rejection.control_plane() != ReceiverControlPlaneV1::Replay {
                return Err(M6CompletionError::InvalidSource {
                    role: source.role,
                    detail:
                        "completion replay source is not a receiver-signed replay-plane rejection"
                            .to_string(),
                });
            }
            Ok(())
        }
        M6CompletionSourceRoleV1::QuarantineInventory => {
            ReceiverUnresolvedQuarantineInventoryV1::from_canonical_bytes_detached(
                &source.canonical_bytes,
                route,
            )
            .map(|_| ())
            .map_err(|error| invalid(source.role, error))
        }
        M6CompletionSourceRoleV1::AcceptedAcknowledgement
        | M6CompletionSourceRoleV1::RolledBackAcknowledgement => {
            SenderAcknowledgementCompletionEvidenceV1::from_canonical_bytes_detached(
                &source.canonical_bytes,
                route,
            )
            .map(|_| ())
            .map_err(|error| invalid(source.role, error))
        }
        M6CompletionSourceRoleV1::RevocationControl => {
            ReceiverRevocationCompletionEvidenceV1::from_canonical_bytes_detached(
                &source.canonical_bytes,
                route,
            )
            .map(|_| ())
            .map_err(|error| invalid(source.role, error))
        }
    }
}

fn validate_aggregate_source_bytes(
    sources: &BTreeMap<M6CompletionSourceRoleV1, M6CompletionSourceV1>,
    limit: u64,
) -> Result<(), M6CompletionError> {
    let aggregate = sources.values().try_fold(0_u64, |total, source| {
        let exact_length = u64::try_from(source.canonical_bytes.len()).map_err(|_| {
            M6CompletionError::ResourceBound(
                "M6 completion source length cannot be represented".to_string(),
            )
        })?;
        total.checked_add(exact_length).ok_or_else(|| {
            M6CompletionError::ResourceBound(
                "M6 completion exact-source aggregate overflowed".to_string(),
            )
        })
    })?;
    if aggregate > limit {
        return Err(M6CompletionError::ResourceBound(format!(
            "M6 completion exact-source aggregate {aggregate} exceeds {limit} bytes"
        )));
    }
    Ok(())
}

fn validate_route_aggregate_source_bytes(
    sources: &BTreeMap<M6CompletionSourceRoleV1, M6CompletionSourceV1>,
    route: &RouteDefinition,
) -> Result<(), M6CompletionError> {
    let delivery_allowance = route
        .resource_profile
        .max_delivery_bytes
        .checked_mul(ROUTE_DELIVERY_COPY_ALLOWANCE)
        .ok_or_else(|| {
            M6CompletionError::ResourceBound(
                "route-derived M6 delivery allowance overflowed".to_string(),
            )
        })?;
    let manifest_allowance = route
        .resource_profile
        .max_manifest_bytes
        .checked_mul(ROUTE_MANIFEST_COPY_ALLOWANCE)
        .ok_or_else(|| {
            M6CompletionError::ResourceBound(
                "route-derived M6 manifest allowance overflowed".to_string(),
            )
        })?;
    let route_limit = ROUTE_EVIDENCE_FIXED_ALLOWANCE_BYTES
        .checked_add(delivery_allowance)
        .and_then(|total| total.checked_add(manifest_allowance))
        .ok_or_else(|| {
            M6CompletionError::ResourceBound(
                "route-derived M6 completion allowance overflowed".to_string(),
            )
        })?
        .min(MAX_BUNDLE_BYTES as u64);
    validate_aggregate_source_bytes(sources, route_limit)
}

fn source_bytes<'a>(
    sources: &'a BTreeMap<M6CompletionSourceRoleV1, M6CompletionSourceV1>,
    role: M6CompletionSourceRoleV1,
) -> Result<&'a [u8], M6CompletionError> {
    sources
        .get(&role)
        .map(|source| source.canonical_bytes.as_slice())
        .ok_or_else(|| M6CompletionError::MissingSources(BTreeSet::from([role])))
}

fn parse_route(bytes: &[u8]) -> Result<RouteDefinition, M6CompletionError> {
    let route: RouteDefinition =
        parse_sorted_canonical(bytes, M6CompletionSourceRoleV1::RouteDefinition)?;
    route
        .validate()
        .map_err(|error| invalid(M6CompletionSourceRoleV1::RouteDefinition, error))?;
    Ok(route)
}

fn parse_sorted_canonical<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
    role: M6CompletionSourceRoleV1,
) -> Result<T, M6CompletionError> {
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
        return Err(M6CompletionError::InvalidSource {
            role,
            detail: "source bytes are empty or outside bounds".to_string(),
        });
    }
    let value: T =
        serde_json::from_slice(bytes).map_err(|error| M6CompletionError::InvalidSource {
            role,
            detail: error.to_string(),
        })?;
    if canonical_sorted_json(&value)? != bytes {
        return Err(M6CompletionError::InvalidSource {
            role,
            detail: "source is not in the M6 identity canonical representation".to_string(),
        });
    }
    Ok(value)
}

fn canonical_sorted_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, M6CompletionError> {
    let value = serde_json::to_value(value)
        .map_err(|error| M6CompletionError::Serialization(error.to_string()))?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    Ok(output)
}

fn write_canonical_value(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), M6CompletionError> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" })
        }
        serde_json::Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        serde_json::Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|error| M6CompletionError::Serialization(error.to_string()))?
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
                        .map_err(|error| M6CompletionError::Serialization(error.to_string()))?
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

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, M6CompletionError> {
    serde_json::to_vec(value).map_err(|error| M6CompletionError::Serialization(error.to_string()))
}

fn digest_domain<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ContentDigest, M6CompletionError> {
    let mut bytes = Vec::from(domain);
    bytes.extend_from_slice(&canonical_json(value)?);
    Ok(ContentDigest::from_bytes(&bytes))
}

fn require_digest(
    subject: &str,
    expected: &ContentDigest,
    actual: &ContentDigest,
) -> Result<(), M6CompletionError> {
    if expected == actual {
        Ok(())
    } else {
        Err(M6CompletionError::InvalidBundle(format!(
            "{subject} digest mismatch: expected {expected}, observed {actual}"
        )))
    }
}

fn invalid(role: M6CompletionSourceRoleV1, error: impl Display) -> M6CompletionError {
    M6CompletionError::InvalidSource {
        role,
        detail: error.to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum M6CompletionError {
    MissingSources(BTreeSet<M6CompletionSourceRoleV1>),
    DuplicateSource(M6CompletionSourceRoleV1),
    InvalidSource {
        role: M6CompletionSourceRoleV1,
        detail: String,
    },
    CrossLink(String),
    InvalidBundle(String),
    NonCanonical(String),
    ResourceBound(String),
    Serialization(String),
}

impl Display for M6CompletionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSources(roles) => {
                write!(
                    formatter,
                    "M6 completion is missing exact source roles {roles:?}"
                )
            }
            Self::DuplicateSource(role) => {
                write!(
                    formatter,
                    "M6 completion repeats exact source role {role:?}"
                )
            }
            Self::InvalidSource { role, detail } => {
                write!(formatter, "invalid M6 completion source {role:?}: {detail}")
            }
            Self::CrossLink(message) => {
                write!(formatter, "M6 completion cross-link failure: {message}")
            }
            Self::InvalidBundle(message) => {
                write!(formatter, "invalid M6 completion bundle: {message}")
            }
            Self::NonCanonical(message) => formatter.write_str(message),
            Self::ResourceBound(message) => {
                write!(formatter, "M6 completion resource bound: {message}")
            }
            Self::Serialization(message) => {
                write!(formatter, "M6 completion serialization failed: {message}")
            }
        }
    }
}

impl Error for M6CompletionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m6_identity::{FactoryIdentityDocument, FactorySigner, RouteResourceProfile};

    fn content(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(label.as_bytes())
    }

    fn route() -> RouteDefinition {
        let sender =
            FactorySigner::from_seed("key:completion-sender", [0x31; 32]).expect("sender signer");
        let receiver = FactorySigner::from_seed("key:completion-receiver", [0x32; 32])
            .expect("receiver signer");
        let package_schemas = vec![content("package-schema")];
        let interface_schemas = vec![content("interface-schema")];
        let policy = content("exchange-policy");
        let sender_identity = FactoryIdentityDocument::new(
            "factory:completion-sender",
            &sender,
            1,
            1_000_000,
            package_schemas.clone(),
            interface_schemas.clone(),
            content("sender-authority"),
            policy.clone(),
        )
        .expect("sender identity");
        let receiver_identity = FactoryIdentityDocument::new(
            "factory:completion-receiver",
            &receiver,
            1,
            1_000_000,
            package_schemas,
            interface_schemas,
            content("receiver-authority"),
            policy.clone(),
        )
        .expect("receiver identity");
        RouteDefinition::new(
            "route:completion",
            1,
            &sender_identity,
            &receiver_identity,
            policy,
            RouteResourceProfile::bounded_default().expect("resource profile"),
        )
        .expect("route")
    }

    #[test]
    fn draft_requires_the_complete_exact_role_set_before_validation() {
        let route = route();
        let route_bytes = canonical_sorted_json(&route).expect("canonical route");
        let mut draft = M6CompletionDraftV1::new();
        draft
            .insert_exact_source(M6CompletionSourceRoleV1::RouteDefinition, route_bytes)
            .expect("insert route");
        let error = draft.try_finalize().expect_err("incomplete draft");
        let M6CompletionError::MissingSources(missing) = error else {
            panic!("unexpected incomplete error");
        };
        assert!(missing.contains(&M6CompletionSourceRoleV1::AcceptedSenderCompletion));
        assert!(missing.contains(&M6CompletionSourceRoleV1::ReceiverReopenProof));
        assert!(missing.contains(&M6CompletionSourceRoleV1::QuarantineInventory));
    }

    #[test]
    fn source_envelope_rejects_length_digest_and_schema_tamper() {
        let route = route();
        let bytes = canonical_sorted_json(&route).expect("canonical route");
        let source = M6CompletionSourceV1::new(M6CompletionSourceRoleV1::RouteDefinition, bytes)
            .expect("route source");
        source.validate_envelope().expect("valid envelope");

        let mut tampered = source.clone();
        tampered.byte_length = tampered.byte_length.saturating_add(1);
        assert!(tampered.validate_envelope().is_err());
        let mut tampered = source.clone();
        tampered.digest = content("wrong-source");
        assert!(tampered.validate_envelope().is_err());
        let mut tampered = source;
        tampered.source_schema = SENDER_REOPEN_PROOF_SCHEMA.to_string();
        assert!(tampered.validate_envelope().is_err());
    }

    #[test]
    fn sender_revocation_chronology_requires_exact_adjacent_chain() {
        let accepted_message = content("accepted-message");
        let revocation_message = content("revocation-message");
        let rolled_back_message = content("rolled-back-message");
        let unrelated_message = content("unrelated-message");
        assert!(
            validate_sender_revocation_chronology(
                7,
                1_000,
                &accepted_message,
                8,
                Some(&accepted_message),
                1_001,
                1_002,
                &revocation_message,
                9,
                Some(&revocation_message),
                1_003,
                &rolled_back_message,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_sender_revocation_chronology(
                7,
                1_000,
                &accepted_message,
                8,
                Some(&accepted_message),
                1_000,
                1_002,
                &revocation_message,
                9,
                Some(&revocation_message),
                1_003,
                &rolled_back_message,
            ),
            Err(M6CompletionError::CrossLink(_))
        ));
        assert!(matches!(
            validate_sender_revocation_chronology(
                7,
                1_000,
                &accepted_message,
                8,
                Some(&unrelated_message),
                1_001,
                1_002,
                &revocation_message,
                9,
                Some(&revocation_message),
                1_003,
                &rolled_back_message,
            ),
            Err(M6CompletionError::CrossLink(_))
        ));
    }

    #[test]
    fn receiver_completion_source_tamper_reaches_the_detached_validator() {
        let route = route();
        let source = M6CompletionSourceV1::new(
            M6CompletionSourceRoleV1::AcceptedReceiverCompletion,
            b"{}".to_vec(),
        )
        .expect("bounded tampered source");
        assert!(matches!(
            validate_detached_source(&source, &route),
            Err(M6CompletionError::InvalidSource {
                role: M6CompletionSourceRoleV1::AcceptedReceiverCompletion,
                ..
            })
        ));
    }

    #[test]
    fn receiver_export_and_sender_ack_replay_facts_cannot_be_collapsed() {
        let receiver_export_fact = content("receiver-export-replay-fact");
        let sender_ack_fact = content("sender-ack-replay-fact");
        assert!(
            validate_directional_replay_fact_separation(
                &receiver_export_fact,
                &sender_ack_fact,
                M6CompletionSourceRoleV1::AcceptedReceiverCompletion,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_directional_replay_fact_separation(
                &receiver_export_fact,
                &receiver_export_fact,
                M6CompletionSourceRoleV1::AcceptedReceiverCompletion,
            ),
            Err(M6CompletionError::InvalidSource {
                role: M6CompletionSourceRoleV1::AcceptedReceiverCompletion,
                ..
            })
        ));
    }

    #[test]
    fn receiver_restart_and_inventory_tamper_reach_their_detached_validators() {
        let route = route();
        for role in [
            M6CompletionSourceRoleV1::ReceiverReopenProof,
            M6CompletionSourceRoleV1::QuarantineInventory,
        ] {
            let source =
                M6CompletionSourceV1::new(role, b"{}".to_vec()).expect("bounded tampered source");
            assert!(matches!(
                validate_detached_source(&source, &route),
                Err(M6CompletionError::InvalidSource {
                    role: invalid_role,
                    ..
                }) if invalid_role == role
            ));
        }
    }

    #[test]
    fn receiver_owned_control_tamper_reaches_every_detached_validator() {
        let route = route();
        for role in [
            M6CompletionSourceRoleV1::NegativeControlSuite,
            M6CompletionSourceRoleV1::ReplayRejectionEvidence,
            M6CompletionSourceRoleV1::RevocationControl,
        ] {
            let source =
                M6CompletionSourceV1::new(role, b"{}".to_vec()).expect("bounded tampered source");
            assert!(matches!(
                validate_detached_source(&source, &route),
                Err(M6CompletionError::InvalidSource {
                    role: invalid_role,
                    ..
                }) if invalid_role == role
            ));
        }
    }

    #[test]
    fn receiver_pair_requires_revocation_separated_incumbent_and_behavior_chronology() {
        let incumbent = content("receiver-incumbent-snapshot");
        let imported = content("receiver-imported-snapshot");
        assert!(
            validate_receiver_outcome_chronology(
                &incumbent,
                &imported,
                &incumbent,
                &incumbent,
                7,
                7,
                8,
                9,
                8,
                Some(23),
                Some(24),
            )
            .is_ok()
        );

        // Direct accepted-final -> rollback-prior adjacency omits the required
        // revocation restoration between the two exchange controls.
        assert!(matches!(
            validate_receiver_outcome_chronology(
                &incumbent,
                &imported,
                &imported,
                &imported,
                7,
                7,
                8,
                9,
                9,
                Some(23),
                Some(24),
            ),
            Err(M6CompletionError::CrossLink(_))
        ));
        assert!(matches!(
            validate_receiver_outcome_chronology(
                &incumbent,
                &imported,
                &incumbent,
                &incumbent,
                7,
                7,
                8,
                8,
                8,
                Some(23),
                Some(24),
            ),
            Err(M6CompletionError::CrossLink(_))
        ));
        assert!(matches!(
            validate_receiver_outcome_chronology(
                &incumbent,
                &imported,
                &incumbent,
                &incumbent,
                7,
                7,
                8,
                9,
                8,
                Some(7),
                Some(8),
            ),
            Err(M6CompletionError::CrossLink(_))
        ));
    }
}
