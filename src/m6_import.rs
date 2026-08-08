//! Receiver-local verification, compatibility, proving, and import planning for M6.
//!
//! This module begins only after an admissible route unit is durably present in
//! receiver-owned raw quarantine. It authenticates the exact retained manifest,
//! resolves the complete M5 export attachment, independently checks receiver
//! compatibility, and runs the receiver's own M1 proving suite.
//!
//! There is deliberately no activation API here. [`prove_quarantined_import`]
//! is the sole function in this module that executes quarantined component
//! bytes. A successful [`ReceiverImportPlanV1`] is immutable planning evidence,
//! not an approval, authority grant, deployment handle, or active-package
//! pointer.

use crate::execution::artifact::{ContentDigest, digest_json_content};
use crate::factory_reproduction::{
    FACTORY_PACKAGE_SCHEMA, FactoryPackage, MutableGenome, REFERENCE_EXPORT,
};
use crate::m1_validation::{
    ProvingRecord, ValidationSuite, prove_component_i32, validate_proving_record,
};
use crate::m5_effect_store::FactoryRuntimeSnapshot;
use crate::m5_export::{M5ExportBundleV1, M5ExportError};
use crate::m6_identity::{
    CommittedRawQuarantineUnit, DELIVERY_COMMIT_SCHEMA, ManifestKind, ManifestPayload,
    RAW_QUARANTINE_SCHEMA, RawFileObservation, RawQuarantineRecord, RouteDefinition,
    SignedManifest,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

pub const RECEIVER_IMPORT_POLICY_SCHEMA: &str = "wasm-biotic.m6-receiver-import-policy.v2";
pub const RECEIVER_ACTIVE_STATE_SCHEMA: &str = "wasm-biotic.m6-receiver-active-state.v1";
pub const VERIFIED_QUARANTINED_EXPORT_SCHEMA: &str =
    "wasm-biotic.m6-verified-quarantined-export.v2";
pub const RECEIVER_COMPATIBILITY_SCHEMA: &str = "wasm-biotic.m6-receiver-compatibility.v1";
pub const RECEIVER_PROVING_REPORT_SCHEMA: &str = "wasm-biotic.m6-receiver-proving-report.v1";
pub const RECEIVER_IMPORT_PLAN_SCHEMA: &str = "wasm-biotic.m6-receiver-import-plan.v1";
pub const IMPORTED_LINEAGE_BINDING_SCHEMA: &str = "wasm-biotic.m6-imported-lineage-binding.v1";

pub const M5_EXPORT_ATTACHMENT_NAME: &str = "m5-export-bundle";
pub const M5_EXPORT_ATTACHMENT_MEDIA_TYPE: &str =
    "application/vnd.wasm-biotic.m5-export-bundle.v2+json";
pub const M5_PACKAGE_ATTACHMENT_MEDIA_TYPE: &str =
    "application/vnd.wasm-biotic.factory-package.v1+json";
pub const M5_RECIPE_ATTACHMENT_MEDIA_TYPE: &str =
    "application/vnd.wasm-biotic.factory-recipe.wat.v1";

const FACTORY_SNAPSHOT_SCHEMA: &str = "wasm-biotic.m5-factory-snapshot.v1";
const DELIVERY_MANIFEST_FILE: &str = "manifest.json";
const DELIVERY_COMMIT_FILE: &str = "commit.json";
const DELIVERY_ATTACHMENTS_DIRECTORY: &str = "attachments";
const RAW_UNIT_DOMAIN: &[u8] = b"wasm-biotic:m6:raw-unit:v1\0";
const RAW_RECORD_DOMAIN: &[u8] = b"wasm-biotic:m6:raw-quarantine-record:v1\0";

const POLICY_DOMAIN: &str = "wasm-biotic:m6:receiver-import-policy:v2";
const ACTIVE_STATE_DOMAIN: &str = "wasm-biotic:m6:receiver-active-state:v1";
const ROLLBACK_TARGET_DOMAIN: &str = "wasm-biotic:m6:receiver-rollback-target:v1";
const VERIFIED_EXPORT_DOMAIN: &str = "wasm-biotic:m6:verified-quarantined-export:v2";
const COMPATIBILITY_DOMAIN: &str = "wasm-biotic:m6:receiver-compatibility:v1";
const PROVING_REPORT_DOMAIN: &str = "wasm-biotic:m6:receiver-proving-report:v1";
const IMPORT_LINEAGE_DOMAIN: &str = "wasm-biotic:m6:imported-lineage-binding:v1";
const IMPORT_PLAN_DOMAIN: &str = "wasm-biotic:m6:receiver-import-plan:v1";
const NO_MIGRATION_DOMAIN: &str = "wasm-biotic:m6:no-state-migration:v1";

const HARD_MAX_BUNDLE_BYTES: u64 = 256 * 1_048_576;
const HARD_MAX_PACKAGE_BYTES: u64 = 16 * 1_048_576;
const HARD_MAX_RECIPE_BYTES: u64 = 256 * 1_024;
const HARD_MAX_COMPONENT_BYTES: u64 = 1_048_576;
const HARD_MAX_EVIDENCE_BYTES: u64 = 512 * 1_048_576;
const HARD_MAX_QUARANTINE_BYTES: u64 = 320 * 1_048_576;
const HARD_MAX_QUARANTINE_FILES: u32 = 515;
const HARD_MAX_PROVING_CASES: u32 = 1_024;
const HARD_MAX_PROVING_FUEL: u64 = 1_000_000_000;
const HARD_MAX_PROVING_INSTANCES: u32 = 1_024;
const HARD_MAX_PROVING_MEMORY_BYTES: u64 = 1_073_741_824;
const HARD_MAX_SOURCE_GENERATION: u32 = 64;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_RECORD_OVERHEAD_BYTES: usize = 4 * 1_048_576;

/// Finite receiver-side bounds. Values cannot widen the M5 hard limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverImportLimitsV1 {
    pub max_bundle_bytes: u64,
    pub max_component_bytes: u64,
    pub max_evidence_bytes: u64,
    pub max_package_bytes: u64,
    pub max_proving_cases: u32,
    pub max_proving_fuel: u64,
    pub max_proving_instances: u32,
    pub max_proving_memory_bytes: u64,
    pub max_quarantine_bytes: u64,
    pub max_quarantine_files: u32,
    pub max_recipe_bytes: u64,
    pub max_source_generation: u32,
}

impl ReceiverImportLimitsV1 {
    pub fn bounded_default() -> Self {
        Self {
            max_bundle_bytes: 64 * 1_048_576,
            max_component_bytes: HARD_MAX_COMPONENT_BYTES,
            max_evidence_bytes: 320 * 1_048_576,
            max_package_bytes: 4 * 1_048_576,
            max_proving_cases: 64,
            max_proving_fuel: 100_000,
            max_proving_instances: 16,
            max_proving_memory_bytes: 16 * 1_048_576,
            max_quarantine_bytes: 80 * 1_048_576,
            max_quarantine_files: 16,
            max_recipe_bytes: HARD_MAX_RECIPE_BYTES,
            max_source_generation: 16,
        }
    }

    pub fn validate(&self) -> Result<(), M6ImportError> {
        let valid = self.max_bundle_bytes > 0
            && self.max_bundle_bytes <= HARD_MAX_BUNDLE_BYTES
            && self.max_component_bytes > 0
            && self.max_component_bytes <= HARD_MAX_COMPONENT_BYTES
            && self.max_evidence_bytes > 0
            && self.max_evidence_bytes <= HARD_MAX_EVIDENCE_BYTES
            && self.max_package_bytes > 0
            && self.max_package_bytes <= HARD_MAX_PACKAGE_BYTES
            && self.max_proving_cases > 0
            && self.max_proving_cases <= HARD_MAX_PROVING_CASES
            && self.max_proving_fuel > 0
            && self.max_proving_fuel <= HARD_MAX_PROVING_FUEL
            && self.max_proving_instances > 0
            && self.max_proving_instances <= HARD_MAX_PROVING_INSTANCES
            && self.max_proving_memory_bytes > 0
            && self.max_proving_memory_bytes <= HARD_MAX_PROVING_MEMORY_BYTES
            && self.max_quarantine_bytes > 0
            && self.max_quarantine_bytes <= HARD_MAX_QUARANTINE_BYTES
            && self.max_quarantine_bytes <= self.max_evidence_bytes
            && self.max_bundle_bytes <= self.max_evidence_bytes
            && self.max_quarantine_files >= 3
            && self.max_quarantine_files <= HARD_MAX_QUARANTINE_FILES
            && self.max_recipe_bytes > 0
            && self.max_recipe_bytes <= HARD_MAX_RECIPE_BYTES
            && self.max_source_generation > 0
            && self.max_source_generation <= HARD_MAX_SOURCE_GENERATION;
        if !valid {
            return Err(M6ImportError::InvalidPolicy(
                "receiver import limits are zero or exceed hard bounds".to_string(),
            ));
        }
        Ok(())
    }
}

/// The only state transition admitted by the first bounded M6 import path.
///
/// Schema-changing imports need a receiver-local executable migration artifact
/// and M5 effect integration. That path is intentionally not invented here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverStateTransitionPolicy {
    ExactCurrentSchemaOnly,
}

/// Immutable receiver policy derived from one pinned route and the receiver's
/// admitted package/interface/capability profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverImportPolicyV1 {
    allow_imported_generation_capability: bool,
    limits: ReceiverImportLimitsV1,
    policy_digest: ContentDigest,
    policy_id: String,
    proving_suite_digest: ContentDigest,
    receiver_factory_id: String,
    receiver_identity_document_digest: ContentDigest,
    required_interface_digest: ContentDigest,
    required_package_format_version: u32,
    required_package_schema: String,
    required_service_catalog_digest: ContentDigest,
    required_worker_catalog_digest: ContentDigest,
    resource_profile_digest: ContentDigest,
    schema: String,
    source_factory_id: String,
    source_identity_document_digest: ContentDigest,
    state_transition_policy: ReceiverStateTransitionPolicy,
}

impl ReceiverImportPolicyV1 {
    /// Freeze a policy from the route, a receiver-admitted package profile, and
    /// the receiver's independent proving suite.
    pub fn for_route(
        policy_id: impl Into<String>,
        route: &RouteDefinition,
        admitted_receiver_package: &FactoryPackage,
        proving_suite: &ValidationSuite,
        limits: ReceiverImportLimitsV1,
        allow_imported_generation_capability: bool,
    ) -> Result<Self, M6ImportError> {
        route
            .validate()
            .map_err(|error| M6ImportError::Authentication(error.to_string()))?;
        admitted_receiver_package
            .validate()
            .map_err(|error| M6ImportError::InvalidPolicy(error.to_string()))?;
        proving_suite
            .validate()
            .map_err(|error| M6ImportError::InvalidPolicy(error.to_string()))?;
        limits.validate()?;
        validate_import_limits_for_route(route, &limits)?;
        validate_suite_limits(&limits, proving_suite)?;
        if admitted_receiver_package.payload.factory_id != route.receiver.factory_id {
            return Err(M6ImportError::InvalidPolicy(
                "admitted receiver package belongs to a different factory".to_string(),
            ));
        }
        let mut policy = Self {
            allow_imported_generation_capability,
            limits,
            policy_digest: ContentDigest::from_bytes(&[]),
            policy_id: policy_id.into(),
            proving_suite_digest: proving_suite
                .suite_digest()
                .map_err(|error| M6ImportError::InvalidPolicy(error.to_string()))?,
            receiver_factory_id: route.receiver.factory_id.clone(),
            receiver_identity_document_digest: route.receiver.identity_document_digest.clone(),
            required_interface_digest: admitted_receiver_package
                .payload
                .boot_manifest
                .interface_digest
                .clone(),
            required_package_format_version: admitted_receiver_package
                .payload
                .boot_manifest
                .package_format_version,
            required_package_schema: admitted_receiver_package.payload.schema.clone(),
            required_service_catalog_digest: admitted_receiver_package
                .payload
                .boot_manifest
                .service_catalog_digest
                .clone(),
            required_worker_catalog_digest: admitted_receiver_package
                .payload
                .boot_manifest
                .worker_catalog_digest
                .clone(),
            resource_profile_digest: route.resource_profile.profile_digest.clone(),
            schema: RECEIVER_IMPORT_POLICY_SCHEMA.to_string(),
            source_factory_id: route.sender.factory_id.clone(),
            source_identity_document_digest: route.sender.identity_document_digest.clone(),
            state_transition_policy: ReceiverStateTransitionPolicy::ExactCurrentSchemaOnly,
        };
        policy.validate_fields()?;
        policy.policy_digest = policy.expected_digest()?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn policy_digest(&self) -> &ContentDigest {
        &self.policy_digest
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn limits(&self) -> &ReceiverImportLimitsV1 {
        &self.limits
    }

    pub fn receiver_factory_id(&self) -> &str {
        &self.receiver_factory_id
    }

    pub fn source_factory_id(&self) -> &str {
        &self.source_factory_id
    }

    pub fn proving_suite_digest(&self) -> &ContentDigest {
        &self.proving_suite_digest
    }

    /// Return a new immutable policy pinned to an operator-selected required
    /// interface identity. This can deliberately express a negative-control
    /// policy that a valid source package does not satisfy.
    pub fn with_required_interface_digest(
        mut self,
        digest: ContentDigest,
    ) -> Result<Self, M6ImportError> {
        self.validate()?;
        if digest == ContentDigest::from_bytes(&[]) {
            return Err(M6ImportError::InvalidPolicy(
                "required interface digest uses the empty-content sentinel".to_string(),
            ));
        }
        self.required_interface_digest = digest;
        self.policy_digest = ContentDigest::from_bytes(&[]);
        self.validate_fields()?;
        self.policy_digest = self.expected_digest()?;
        self.validate()?;
        Ok(self)
    }

    #[cfg(test)]
    pub(crate) fn requiring_interface_digest_for_test(
        self,
        digest: ContentDigest,
    ) -> Result<Self, M6ImportError> {
        self.with_required_interface_digest(digest)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M6ImportError> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M6ImportError> {
        let policy: Self = parse_canonical(bytes, MAX_RECORD_OVERHEAD_BYTES)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), M6ImportError> {
        self.validate_fields()?;
        require_digest(
            "receiver import policy",
            &self.policy_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6ImportError> {
        if self.schema != RECEIVER_IMPORT_POLICY_SCHEMA {
            return Err(M6ImportError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("receiver import policy id", &self.policy_id)?;
        validate_identifier("receiver factory id", &self.receiver_factory_id)?;
        validate_identifier("source factory id", &self.source_factory_id)?;
        if self.receiver_factory_id == self.source_factory_id
            || self.receiver_identity_document_digest == self.source_identity_document_digest
            || self.required_package_schema != FACTORY_PACKAGE_SCHEMA
            || self.required_package_format_version != 1
        {
            return Err(M6ImportError::InvalidPolicy(
                "receiver policy has false peer identity or unsupported package schema".to_string(),
            ));
        }
        self.limits.validate()
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ImportError> {
        digest(&(
            POLICY_DOMAIN,
            (
                self.allow_imported_generation_capability,
                &self.limits,
                &self.policy_id,
                &self.proving_suite_digest,
            ),
            (
                &self.receiver_factory_id,
                &self.receiver_identity_document_digest,
                &self.required_interface_digest,
                self.required_package_format_version,
                &self.required_package_schema,
                &self.required_service_catalog_digest,
                &self.required_worker_catalog_digest,
            ),
            (
                &self.resource_profile_digest,
                &self.schema,
                &self.source_factory_id,
                &self.source_identity_document_digest,
                self.state_transition_policy,
            ),
        ))
    }
}

/// Exact receiver active state and rollback material observed before planning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverActiveStateV1 {
    active_package_bytes: Vec<u8>,
    active_state_digest: ContentDigest,
    rollback_target_digest: ContentDigest,
    schema: String,
    snapshot: FactoryRuntimeSnapshot,
}

impl ReceiverActiveStateV1 {
    pub fn new(
        snapshot: FactoryRuntimeSnapshot,
        active_package_bytes: Vec<u8>,
    ) -> Result<Self, M6ImportError> {
        let mut state = Self {
            active_package_bytes,
            active_state_digest: ContentDigest::from_bytes(&[]),
            rollback_target_digest: ContentDigest::from_bytes(&[]),
            schema: RECEIVER_ACTIVE_STATE_SCHEMA.to_string(),
            snapshot,
        };
        state.rollback_target_digest = state.expected_rollback_target_digest()?;
        state.active_state_digest = state.expected_digest()?;
        state.validate()?;
        Ok(state)
    }

    pub fn snapshot(&self) -> &FactoryRuntimeSnapshot {
        &self.snapshot
    }

    pub fn active_state_digest(&self) -> &ContentDigest {
        &self.active_state_digest
    }

    pub fn rollback_target_digest(&self) -> &ContentDigest {
        &self.rollback_target_digest
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M6ImportError> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M6ImportError> {
        let state: Self = parse_canonical(
            bytes,
            HARD_MAX_PACKAGE_BYTES as usize + MAX_RECORD_OVERHEAD_BYTES,
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), M6ImportError> {
        if self.schema != RECEIVER_ACTIVE_STATE_SCHEMA {
            return Err(M6ImportError::UnsupportedSchema(self.schema.clone()));
        }
        let package = self.active_package()?;
        validate_snapshot(&self.snapshot, &package, &self.active_package_bytes)?;
        require_digest(
            "receiver rollback target",
            &self.rollback_target_digest,
            &self.expected_rollback_target_digest()?,
        )?;
        require_digest(
            "receiver active state",
            &self.active_state_digest,
            &self.expected_digest()?,
        )
    }

    fn active_package(&self) -> Result<FactoryPackage, M6ImportError> {
        FactoryPackage::from_canonical_bytes(&self.active_package_bytes)
            .map_err(|error| M6ImportError::Integrity(error.to_string()))
    }

    fn expected_rollback_target_digest(&self) -> Result<ContentDigest, M6ImportError> {
        digest(&(
            ROLLBACK_TARGET_DOMAIN,
            &self.snapshot.snapshot_digest,
            &self.snapshot.package_digest,
            &self.snapshot.package_bytes_digest,
            &self.snapshot.state_blob_digest,
            self.snapshot.state_schema,
        ))
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ImportError> {
        digest(&(
            ACTIVE_STATE_DOMAIN,
            &self.active_package_bytes,
            &self.rollback_target_digest,
            &self.schema,
            &self.snapshot,
        ))
    }
}

pub fn m5_package_attachment_name(digest: &ContentDigest) -> String {
    format!("m5-package-{}", digest.file_stem())
}

pub fn m5_recipe_attachment_name(digest: &ContentDigest) -> String {
    format!("m5-recipe-{}", digest.file_stem())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryCommitMarkerV1 {
    manifest_bytes_digest: ContentDigest,
    message_digest: ContentDigest,
    schema: String,
}

/// Receiver-verified, exact export material retained after raw quarantine.
///
/// Fields are private so downstream code cannot obtain a component execution
/// handle from this record. Its canonical bytes exist for durable restart and
/// forensic reconstruction; possession of those bytes is not activation
/// authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedQuarantinedExportV1 {
    closure_attachment_bytes: BTreeMap<ContentDigest, Vec<u8>>,
    export_bundle_bytes: Vec<u8>,
    export_bundle_bytes_digest: ContentDigest,
    export_bundle_digest: ContentDigest,
    manifest: SignedManifest,
    raw_quarantine: RawQuarantineRecord,
    receiver_factory_id: String,
    route_definition_digest: ContentDigest,
    schema: String,
    source_component_digest: ContentDigest,
    source_factory_id: String,
    source_identity_document_digest: ContentDigest,
    source_package_bytes_digest: ContentDigest,
    source_package_digest: ContentDigest,
    source_recipe_digest: ContentDigest,
    verification_digest: ContentDigest,
}

impl VerifiedQuarantinedExportV1 {
    pub fn manifest(&self) -> &SignedManifest {
        &self.manifest
    }

    pub fn raw_quarantine_record(&self) -> &RawQuarantineRecord {
        &self.raw_quarantine
    }

    pub fn message_digest(&self) -> &ContentDigest {
        &self.manifest.message_digest
    }

    pub fn raw_quarantine_digest(&self) -> &ContentDigest {
        &self.raw_quarantine.raw_unit_digest
    }

    pub fn raw_quarantine_record_digest(&self) -> &ContentDigest {
        &self.raw_quarantine.record_digest
    }

    pub fn route_definition_digest(&self) -> &ContentDigest {
        &self.route_definition_digest
    }

    pub fn source_factory_id(&self) -> &str {
        &self.source_factory_id
    }

    pub fn source_identity_document_digest(&self) -> &ContentDigest {
        &self.source_identity_document_digest
    }

    pub fn source_package_digest(&self) -> &ContentDigest {
        &self.source_package_digest
    }

    pub fn source_package_bytes_digest(&self) -> &ContentDigest {
        &self.source_package_bytes_digest
    }

    pub fn source_component_digest(&self) -> &ContentDigest {
        &self.source_component_digest
    }

    pub fn source_recipe_digest(&self) -> &ContentDigest {
        &self.source_recipe_digest
    }

    pub fn export_bundle_digest(&self) -> &ContentDigest {
        &self.export_bundle_digest
    }

    pub fn verification_digest(&self) -> &ContentDigest {
        &self.verification_digest
    }

    pub fn canonical_bytes(
        &self,
        route: &RouteDefinition,
        policy: &ReceiverImportPolicyV1,
    ) -> Result<Vec<u8>, M6ImportError> {
        self.validate(route, policy)?;
        let bytes = canonical_json(self)?;
        if bytes.len() > checked_verified_record_bound(policy)? {
            return Err(M6ImportError::ResourceBound(
                "verified export record exceeds the immutable evidence-byte budget".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        route: &RouteDefinition,
        policy: &ReceiverImportPolicyV1,
    ) -> Result<Self, M6ImportError> {
        let max = checked_verified_record_bound(policy)?;
        let verified: Self = parse_canonical(bytes, max)?;
        verified.validate(route, policy)?;
        Ok(verified)
    }

    pub fn validate(
        &self,
        route: &RouteDefinition,
        policy: &ReceiverImportPolicyV1,
    ) -> Result<(), M6ImportError> {
        if self.schema != VERIFIED_QUARANTINED_EXPORT_SCHEMA {
            return Err(M6ImportError::UnsupportedSchema(self.schema.clone()));
        }
        validate_route_policy(route, policy)?;
        self.manifest
            .verify_route(route)
            .map_err(|error| M6ImportError::Authentication(error.to_string()))?;
        let expected_files = expected_raw_export_files(
            &self.manifest,
            &self.export_bundle_bytes,
            &self.closure_attachment_bytes,
        )?;
        validate_raw_quarantine(&self.raw_quarantine, &expected_files, route, &policy.limits)?;
        let bundle =
            validate_export_bundle(&self.export_bundle_bytes, &self.manifest, route, policy)?;
        validate_attachment_closure(
            &bundle,
            &self.manifest,
            &self.export_bundle_bytes,
            &self.closure_attachment_bytes,
        )?;
        let source_package = active_source_package(&bundle)?;
        let exported_package = bundle.active_package();
        if self.receiver_factory_id != policy.receiver_factory_id
            || self.route_definition_digest != route.definition_digest
            || self.source_factory_id != route.sender.factory_id
            || self.source_factory_id != policy.source_factory_id
            || self.source_identity_document_digest != route.sender.identity_document_digest
            || self.source_identity_document_digest != policy.source_identity_document_digest
            || self.export_bundle_bytes_digest
                != ContentDigest::from_bytes(&self.export_bundle_bytes)
            || self.export_bundle_digest != *bundle.bundle_digest()
            || self.source_package_digest != source_package.package_digest
            || self.source_package_bytes_digest
                != *exported_package.canonical_package_bytes_digest()
            || self.source_component_digest != source_package.payload.genome.component_digest
            || self.source_recipe_digest != *exported_package.recipe_wat_digest()
        {
            return Err(M6ImportError::Integrity(
                "verified export projections are missing or cross-linked".to_string(),
            ));
        }
        require_digest(
            "verified quarantined export",
            &self.verification_digest,
            &self.expected_digest()?,
        )
    }

    fn bundle(&self) -> Result<M5ExportBundleV1, M6ImportError> {
        M5ExportBundleV1::from_canonical_bytes(&self.export_bundle_bytes).map_err(m5_export_error)
    }

    fn source_package(&self) -> Result<FactoryPackage, M6ImportError> {
        active_source_package(&self.bundle()?)
    }

    fn source_recipe_bytes(&self) -> Result<Vec<u8>, M6ImportError> {
        Ok(self.bundle()?.active_package().recipe_wat_bytes().to_vec())
    }

    fn source_package_bytes(&self) -> Result<Vec<u8>, M6ImportError> {
        Ok(self
            .bundle()?
            .active_package()
            .canonical_package_bytes()
            .to_vec())
    }

    fn source_component_bytes(&self) -> Result<Vec<u8>, M6ImportError> {
        Ok(self.source_package()?.payload.genome.component_bytes)
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ImportError> {
        digest(&(
            VERIFIED_EXPORT_DOMAIN,
            &self.closure_attachment_bytes,
            &self.export_bundle_bytes,
            &self.export_bundle_bytes_digest,
            &self.export_bundle_digest,
            &self.manifest,
            &self.raw_quarantine,
            &self.receiver_factory_id,
            &self.route_definition_digest,
            &self.schema,
            &self.source_component_digest,
            &self.source_factory_id,
            &self.source_identity_document_digest,
            &self.source_package_bytes_digest,
            &self.source_package_digest,
            &self.source_recipe_digest,
        ))
    }
}

/// Verify an authenticated export only from bytes copied out of receiver-owned
/// quarantine. This function parses and compiles WAT to check byte identity,
/// but it does not instantiate or execute the component.
pub fn verify_quarantined_export(
    route: &RouteDefinition,
    policy: &ReceiverImportPolicyV1,
    quarantined: &CommittedRawQuarantineUnit,
) -> Result<VerifiedQuarantinedExportV1, M6ImportError> {
    validate_route_policy(route, policy)?;
    let raw_quarantine = quarantined.record();
    let files = quarantined.files();
    enforce_raw_bounds(files, &policy.limits)?;
    let manifest_bytes = quarantined
        .files()
        .get(DELIVERY_MANIFEST_FILE)
        .ok_or_else(|| {
            M6ImportError::MissingEvidence(
                "raw quarantine has no canonical signed manifest".to_string(),
            )
        })?;
    let manifest = SignedManifest::from_canonical_bytes(manifest_bytes)
        .map_err(|error| M6ImportError::Authentication(error.to_string()))?;
    manifest
        .verify_route(route)
        .map_err(|error| M6ImportError::Authentication(error.to_string()))?;
    let descriptor = exact_export_attachment(&manifest)?;
    let bundle_attachment_path = attachment_path(&descriptor.content_digest);
    let export_bundle_bytes = quarantined
        .files()
        .get(&bundle_attachment_path)
        .cloned()
        .ok_or_else(|| {
            M6ImportError::MissingEvidence(format!(
                "raw quarantine lacks export attachment '{bundle_attachment_path}'"
            ))
        })?;
    validate_raw_quarantine(raw_quarantine, files, route, &policy.limits)?;
    let bundle = validate_export_bundle(&export_bundle_bytes, &manifest, route, policy)?;
    let mut all_attachments = BTreeMap::new();
    for attachment in &manifest.unsigned.attachments {
        let path = attachment_path(&attachment.content_digest);
        let bytes = files.get(&path).cloned().ok_or_else(|| {
            M6ImportError::MissingEvidence(format!(
                "raw quarantine lacks signed attachment '{path}'"
            ))
        })?;
        if all_attachments
            .insert(attachment.content_digest.clone(), bytes)
            .is_some()
        {
            return Err(M6ImportError::Integrity(
                "signed manifest repeats an attachment content identity".to_string(),
            ));
        }
    }
    validate_attachment_closure(
        &bundle,
        &manifest,
        &export_bundle_bytes,
        &all_attachments
            .iter()
            .filter(|(digest, _)| *digest != &descriptor.content_digest)
            .map(|(digest, bytes)| (digest.clone(), bytes.clone()))
            .collect(),
    )?;
    let closure_attachment_bytes = all_attachments
        .into_iter()
        .filter(|(digest, _)| digest != &descriptor.content_digest)
        .collect();
    let source_package = active_source_package(&bundle)?;
    let exported_package = bundle.active_package();
    let mut verified = VerifiedQuarantinedExportV1 {
        closure_attachment_bytes,
        export_bundle_bytes_digest: ContentDigest::from_bytes(&export_bundle_bytes),
        export_bundle_digest: bundle.bundle_digest().clone(),
        export_bundle_bytes,
        manifest,
        raw_quarantine: raw_quarantine.clone(),
        receiver_factory_id: route.receiver.factory_id.clone(),
        route_definition_digest: route.definition_digest.clone(),
        schema: VERIFIED_QUARANTINED_EXPORT_SCHEMA.to_string(),
        source_component_digest: source_package.payload.genome.component_digest.clone(),
        source_factory_id: route.sender.factory_id.clone(),
        source_identity_document_digest: route.sender.identity_document_digest.clone(),
        source_package_bytes_digest: exported_package.canonical_package_bytes_digest().clone(),
        source_package_digest: source_package.package_digest,
        source_recipe_digest: exported_package.recipe_wat_digest().clone(),
        verification_digest: ContentDigest::from_bytes(&[]),
    };
    verified.verification_digest = verified.expected_digest()?;
    verified.validate(route, policy)?;
    let _ = verified.canonical_bytes(route, policy)?;
    Ok(verified)
}

fn validate_export_bundle(
    bytes: &[u8],
    manifest: &SignedManifest,
    route: &RouteDefinition,
    policy: &ReceiverImportPolicyV1,
) -> Result<M5ExportBundleV1, M6ImportError> {
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            > policy
                .limits
                .max_bundle_bytes
                .min(policy.limits.max_evidence_bytes)
    {
        return Err(M6ImportError::ResourceBound(
            "M5 export bundle exceeds receiver policy".to_string(),
        ));
    }
    let bundle = M5ExportBundleV1::from_canonical_bytes(bytes).map_err(m5_export_error)?;
    bundle.validate_standalone().map_err(m5_export_error)?;
    bundle
        .runtime_identity()
        .validate()
        .map_err(m5_export_error)?;
    let source_package = active_source_package(&bundle)?;
    let exported = bundle.active_package();
    let package_len = u64::try_from(exported.canonical_package_bytes().len()).unwrap_or(u64::MAX);
    let recipe_len = u64::try_from(exported.recipe_wat_bytes().len()).unwrap_or(u64::MAX);
    let component_len =
        u64::try_from(source_package.payload.genome.component_bytes.len()).unwrap_or(u64::MAX);
    if package_len > policy.limits.max_package_bytes
        || recipe_len > policy.limits.max_recipe_bytes
        || component_len > policy.limits.max_component_bytes
    {
        return Err(M6ImportError::ResourceBound(
            "active package, recipe, or component exceeds receiver policy".to_string(),
        ));
    }
    if bundle.runtime_identity().factory_id() != route.sender.factory_id
        || bundle.runtime_identity().factory_id() != policy.source_factory_id
        || source_package.payload.factory_id != route.sender.factory_id
    {
        return Err(M6ImportError::FalseLink(
            "signed source identity and M5 factory identity differ".to_string(),
        ));
    }
    let payload = match &manifest.unsigned.payload {
        ManifestPayload::Export(payload) => payload,
        _ => {
            return Err(M6ImportError::FalseLink(
                "receiver import requires an export manifest".to_string(),
            ));
        }
    };
    if manifest.unsigned.kind != ManifestKind::Export
        || payload.export_bundle_digest != *bundle.bundle_digest()
        || payload.package_digest != source_package.package_digest
        || payload.package_bytes_digest != *exported.canonical_package_bytes_digest()
        || payload.component_digest != source_package.payload.genome.component_digest
    {
        return Err(M6ImportError::FalseLink(
            "export manifest payload differs from exact M5 bundle material".to_string(),
        ));
    }
    let compiled = wat::parse_bytes(exported.recipe_wat_bytes())
        .map_err(|error| {
            M6ImportError::Integrity(format!("exported recipe is not valid WAT: {error}"))
        })?
        .into_owned();
    if compiled != source_package.payload.genome.component_bytes
        || exported.recipe_wat_digest() != &ContentDigest::from_bytes(exported.recipe_wat_bytes())
        || exported.canonical_package_bytes_digest()
            != &ContentDigest::from_bytes(exported.canonical_package_bytes())
    {
        return Err(M6ImportError::Integrity(
            "source package, component, or recipe bytes diverge".to_string(),
        ));
    }
    Ok(bundle)
}

fn active_source_package(bundle: &M5ExportBundleV1) -> Result<FactoryPackage, M6ImportError> {
    FactoryPackage::from_canonical_bytes(bundle.active_package().canonical_package_bytes())
        .map_err(|error| M6ImportError::Integrity(error.to_string()))
}

fn validate_route_policy(
    route: &RouteDefinition,
    policy: &ReceiverImportPolicyV1,
) -> Result<(), M6ImportError> {
    route
        .validate()
        .map_err(|error| M6ImportError::Authentication(error.to_string()))?;
    policy.validate()?;
    if route.sender.factory_id != policy.source_factory_id
        || route.sender.identity_document_digest != policy.source_identity_document_digest
        || route.receiver.factory_id != policy.receiver_factory_id
        || route.receiver.identity_document_digest != policy.receiver_identity_document_digest
        || route.resource_profile.profile_digest != policy.resource_profile_digest
    {
        return Err(M6ImportError::FalseLink(
            "route peer or resource-profile bindings differ from receiver import policy"
                .to_string(),
        ));
    }
    validate_import_limits_for_route(route, &policy.limits)
}

fn exact_export_attachment(
    manifest: &SignedManifest,
) -> Result<&crate::m6_identity::AttachmentDescriptor, M6ImportError> {
    if manifest.unsigned.kind != ManifestKind::Export
        || !matches!(manifest.unsigned.payload, ManifestPayload::Export(_))
    {
        return Err(M6ImportError::MissingEvidence(
            "receiver import requires an export manifest".to_string(),
        ));
    }
    let mut matching = manifest.unsigned.attachments.iter().filter(|descriptor| {
        descriptor.logical_name == M5_EXPORT_ATTACHMENT_NAME
            && descriptor.media_type == M5_EXPORT_ATTACHMENT_MEDIA_TYPE
    });
    let descriptor = matching.next().ok_or_else(|| {
        M6ImportError::MissingEvidence(
            "manifest has no exact M5 export bundle attachment".to_string(),
        )
    })?;
    if matching.next().is_some() {
        return Err(M6ImportError::MissingEvidence(
            "manifest repeats the M5 export bundle attachment".to_string(),
        ));
    }
    Ok(descriptor)
}

fn expected_raw_export_files(
    manifest: &SignedManifest,
    export_bundle_bytes: &[u8],
    closure_attachment_bytes: &BTreeMap<ContentDigest, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>, M6ImportError> {
    let descriptor = exact_export_attachment(manifest)?;
    if descriptor.byte_length != u64::try_from(export_bundle_bytes.len()).unwrap_or(u64::MAX)
        || descriptor.content_digest != ContentDigest::from_bytes(export_bundle_bytes)
    {
        return Err(M6ImportError::Integrity(
            "retained export attachment differs from signed descriptor".to_string(),
        ));
    }
    let manifest_bytes = manifest
        .canonical_bytes()
        .map_err(|error| M6ImportError::Authentication(error.to_string()))?;
    let commit = DeliveryCommitMarkerV1 {
        manifest_bytes_digest: ContentDigest::from_bytes(&manifest_bytes),
        message_digest: manifest.message_digest.clone(),
        schema: DELIVERY_COMMIT_SCHEMA.to_string(),
    };
    let mut files = BTreeMap::new();
    files.insert(
        attachment_path(&descriptor.content_digest),
        export_bundle_bytes.to_vec(),
    );
    for (digest, bytes) in closure_attachment_bytes {
        if files
            .insert(attachment_path(digest), bytes.clone())
            .is_some()
        {
            return Err(M6ImportError::Integrity(
                "quarantined attachment closure repeats a content identity".to_string(),
            ));
        }
    }
    files.insert(DELIVERY_COMMIT_FILE.to_string(), canonical_json(&commit)?);
    files.insert(DELIVERY_MANIFEST_FILE.to_string(), manifest_bytes);
    Ok(files)
}

fn validate_attachment_closure(
    bundle: &M5ExportBundleV1,
    manifest: &SignedManifest,
    export_bundle_bytes: &[u8],
    closure_attachment_bytes: &BTreeMap<ContentDigest, Vec<u8>>,
) -> Result<(), M6ImportError> {
    let bundle_descriptor = exact_export_attachment(manifest)?;
    let mut expected = BTreeMap::<ContentDigest, (String, String, Vec<u8>)>::new();
    expected.insert(
        ContentDigest::from_bytes(export_bundle_bytes),
        (
            M5_EXPORT_ATTACHMENT_NAME.to_string(),
            M5_EXPORT_ATTACHMENT_MEDIA_TYPE.to_string(),
            export_bundle_bytes.to_vec(),
        ),
    );
    for exported in
        std::iter::once(bundle.active_package()).chain(bundle.referenced_packages().iter())
    {
        let package_digest = ContentDigest::from_bytes(exported.canonical_package_bytes());
        let recipe_digest = ContentDigest::from_bytes(exported.recipe_wat_bytes());
        if expected
            .insert(
                package_digest.clone(),
                (
                    m5_package_attachment_name(&package_digest),
                    M5_PACKAGE_ATTACHMENT_MEDIA_TYPE.to_string(),
                    exported.canonical_package_bytes().to_vec(),
                ),
            )
            .is_some()
        {
            return Err(M6ImportError::Integrity(
                "package attachment content collides with another closure artifact".to_string(),
            ));
        }
        match expected.get(&recipe_digest) {
            Some((name, media_type, bytes))
                if name == &m5_recipe_attachment_name(&recipe_digest)
                    && media_type == M5_RECIPE_ATTACHMENT_MEDIA_TYPE
                    && bytes.as_slice() == exported.recipe_wat_bytes() => {}
            Some(_) => {
                return Err(M6ImportError::Integrity(
                    "recipe attachment content collides with a different artifact".to_string(),
                ));
            }
            None => {
                expected.insert(
                    recipe_digest.clone(),
                    (
                        m5_recipe_attachment_name(&recipe_digest),
                        M5_RECIPE_ATTACHMENT_MEDIA_TYPE.to_string(),
                        exported.recipe_wat_bytes().to_vec(),
                    ),
                );
            }
        }
    }
    if bundle_descriptor.content_digest != ContentDigest::from_bytes(export_bundle_bytes)
        || manifest.unsigned.attachments.len() != expected.len()
    {
        return Err(M6ImportError::MissingEvidence(
            "signed attachments do not exactly close the M5 export".to_string(),
        ));
    }
    for descriptor in &manifest.unsigned.attachments {
        let (logical_name, media_type, bytes) =
            expected.get(&descriptor.content_digest).ok_or_else(|| {
                M6ImportError::FalseLink(format!(
                    "unrecognized attachment '{}'",
                    descriptor.logical_name
                ))
            })?;
        if &descriptor.logical_name != logical_name
            || &descriptor.media_type != media_type
            || descriptor.byte_length != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        {
            return Err(M6ImportError::FalseLink(format!(
                "attachment '{}' metadata differs from its M5 artifact",
                descriptor.logical_name
            )));
        }
        if descriptor.content_digest == bundle_descriptor.content_digest {
            if bytes.as_slice() != export_bundle_bytes {
                return Err(M6ImportError::Integrity(
                    "bundle attachment bytes diverge".to_string(),
                ));
            }
        } else if closure_attachment_bytes
            .get(&descriptor.content_digest)
            .map(Vec::as_slice)
            != Some(bytes.as_slice())
        {
            return Err(M6ImportError::Integrity(format!(
                "attachment '{}' bytes are missing or divergent",
                descriptor.logical_name
            )));
        }
    }
    if closure_attachment_bytes.len() + 1 != expected.len()
        || closure_attachment_bytes
            .keys()
            .any(|digest| !expected.contains_key(digest))
    {
        return Err(M6ImportError::MissingEvidence(
            "quarantined package/recipe attachment set is not closed".to_string(),
        ));
    }
    Ok(())
}

fn validate_raw_quarantine(
    record: &RawQuarantineRecord,
    files: &BTreeMap<String, Vec<u8>>,
    route: &RouteDefinition,
    limits: &ReceiverImportLimitsV1,
) -> Result<(), M6ImportError> {
    if record.schema != RAW_QUARANTINE_SCHEMA
        || record.route_definition_digest != route.definition_digest
        || record.files.is_empty()
        || record.files.len() != files.len()
        || record.files.len() > limits.max_quarantine_files as usize
        || record.route_entry_name.is_empty()
        || record.intake_operation_id.is_empty()
    {
        return Err(M6ImportError::RawQuarantine(
            "raw quarantine record has missing or cross-linked fields".to_string(),
        ));
    }
    validate_identifier(
        "raw quarantine intake operation",
        &record.intake_operation_id,
    )?;
    let expected_entry = format!(
        "{}.unit",
        files
            .get(DELIVERY_MANIFEST_FILE)
            .and_then(|bytes| SignedManifest::from_canonical_bytes(bytes).ok())
            .map(|manifest| manifest.message_digest.file_stem())
            .ok_or_else(|| {
                M6ImportError::RawQuarantine(
                    "raw quarantine manifest cannot resolve its route entry".to_string(),
                )
            })?
    );
    if record.route_entry_name != expected_entry {
        return Err(M6ImportError::FalseLink(
            "raw quarantine route entry names a different message".to_string(),
        ));
    }
    let observations = files
        .iter()
        .map(|(relative_path, bytes)| {
            Ok(RawFileObservation {
                byte_length: u64::try_from(bytes.len()).map_err(|_| {
                    M6ImportError::ResourceBound(
                        "raw quarantine file length overflowed".to_string(),
                    )
                })?,
                content_digest: ContentDigest::from_bytes(bytes),
                relative_path: relative_path.clone(),
            })
        })
        .collect::<Result<Vec<_>, M6ImportError>>()?;
    if observations != record.files {
        return Err(M6ImportError::RawQuarantine(
            "raw quarantine observations differ from retained bytes".to_string(),
        ));
    }
    let total_bytes = observations.iter().try_fold(0_u64, |total, file| {
        total.checked_add(file.byte_length).ok_or_else(|| {
            M6ImportError::ResourceBound("raw quarantine byte total overflowed".to_string())
        })
    })?;
    if total_bytes != record.total_bytes || total_bytes > limits.max_quarantine_bytes {
        return Err(M6ImportError::ResourceBound(
            "raw quarantine byte total differs or exceeds policy".to_string(),
        ));
    }
    let raw_unit_digest = domain_digest_bytes(RAW_UNIT_DOMAIN, &record.files)?;
    if record.raw_unit_digest != raw_unit_digest {
        return Err(M6ImportError::RawQuarantine(
            "raw quarantine unit digest does not resolve exact files".to_string(),
        ));
    }
    let expected_record_digest = domain_digest_bytes(
        RAW_RECORD_DOMAIN,
        &(
            &record.files,
            &record.intake_operation_id,
            record.observed_at_ms,
            &record.raw_unit_digest,
            &record.route_definition_digest,
            &record.route_entry_name,
            &record.schema,
            record.total_bytes,
        ),
    )?;
    require_digest(
        "raw quarantine record",
        &record.record_digest,
        &expected_record_digest,
    )
}

fn enforce_raw_bounds(
    files: &BTreeMap<String, Vec<u8>>,
    limits: &ReceiverImportLimitsV1,
) -> Result<(), M6ImportError> {
    if files.is_empty()
        || files.len() > limits.max_quarantine_files as usize
        || files
            .keys()
            .any(|path| path.is_empty() || !is_safe_portable_path(path))
    {
        return Err(M6ImportError::ResourceBound(
            "quarantined unit exceeds receiver import policy".to_string(),
        ));
    }
    let total = files.values().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                M6ImportError::ResourceBound("quarantined file length overflowed".to_string())
            })?)
            .ok_or_else(|| {
                M6ImportError::ResourceBound("quarantined aggregate length overflowed".to_string())
            })
    })?;
    if total > limits.max_quarantine_bytes {
        return Err(M6ImportError::ResourceBound(
            "quarantined unit exceeds receiver import byte policy".to_string(),
        ));
    }
    Ok(())
}

fn attachment_path(digest: &ContentDigest) -> String {
    format!(
        "{DELIVERY_ATTACHMENTS_DIRECTORY}/{}.blob",
        digest.file_stem()
    )
}

/// Typed reasons why a verified source package cannot enter receiver proving.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverCompatibilityIssue {
    ImportedGenerationCapabilityForbidden,
    InterfaceMismatch,
    PackageFormatMismatch,
    PackageSchemaMismatch,
    ReceiverCapabilityProfileDrift,
    ReceiverInterfaceProfileDrift,
    ReceiverPackageProfileDrift,
    ReceiverRollbackUnreadable,
    ServiceCapabilityMismatch,
    SourceGenerationOutOfBounds,
    StateSchemaMismatch,
    StateSchemaUnreadable,
    WorkerCapabilityMismatch,
}

/// Reproducible receiver-local compatibility decision. Negative decisions are
/// retained as evidence but cannot be used for proving or plan construction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverCompatibilityDecisionV1 {
    compatible: bool,
    decision_digest: ContentDigest,
    issues: Vec<ReceiverCompatibilityIssue>,
    migration_required: bool,
    policy_digest: ContentDigest,
    receiver_active_state_digest: ContentDigest,
    receiver_state_schema: u32,
    schema: String,
    source_package_digest: ContentDigest,
    source_state_schema: u32,
    verified_export_digest: ContentDigest,
}

impl ReceiverCompatibilityDecisionV1 {
    pub fn compatible(&self) -> bool {
        self.compatible
    }

    pub fn issues(&self) -> &[ReceiverCompatibilityIssue] {
        &self.issues
    }

    pub fn migration_required(&self) -> bool {
        self.migration_required
    }

    pub fn decision_digest(&self) -> &ContentDigest {
        &self.decision_digest
    }

    pub fn canonical_bytes(
        &self,
        verified: &VerifiedQuarantinedExportV1,
        active: &ReceiverActiveStateV1,
        policy: &ReceiverImportPolicyV1,
    ) -> Result<Vec<u8>, M6ImportError> {
        self.validate(verified, active, policy)?;
        let bytes = canonical_json(self)?;
        enforce_evidence_bytes(
            policy,
            &bytes,
            MAX_RECORD_OVERHEAD_BYTES,
            "receiver compatibility decision",
        )?;
        Ok(bytes)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        verified: &VerifiedQuarantinedExportV1,
        active: &ReceiverActiveStateV1,
        policy: &ReceiverImportPolicyV1,
    ) -> Result<Self, M6ImportError> {
        let decision: Self = parse_canonical(
            bytes,
            MAX_RECORD_OVERHEAD_BYTES.min(checked_evidence_bound(policy)?),
        )?;
        decision.validate(verified, active, policy)?;
        Ok(decision)
    }

    pub fn validate(
        &self,
        verified: &VerifiedQuarantinedExportV1,
        active: &ReceiverActiveStateV1,
        policy: &ReceiverImportPolicyV1,
    ) -> Result<(), M6ImportError> {
        if self.schema != RECEIVER_COMPATIBILITY_SCHEMA {
            return Err(M6ImportError::UnsupportedSchema(self.schema.clone()));
        }
        let expected = derive_compatibility(verified, active, policy)?;
        if self.compatible != expected.compatible
            || self.issues != expected.issues
            || self.migration_required != expected.migration_required
            || self.policy_digest != expected.policy_digest
            || self.receiver_active_state_digest != expected.receiver_active_state_digest
            || self.receiver_state_schema != expected.receiver_state_schema
            || self.source_package_digest != expected.source_package_digest
            || self.source_state_schema != expected.source_state_schema
            || self.verified_export_digest != expected.verified_export_digest
        {
            return Err(M6ImportError::FalseLink(
                "compatibility decision differs from exact receiver inputs".to_string(),
            ));
        }
        require_digest(
            "receiver compatibility decision",
            &self.decision_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ImportError> {
        digest(&(
            COMPATIBILITY_DOMAIN,
            self.compatible,
            &self.issues,
            self.migration_required,
            &self.policy_digest,
            &self.receiver_active_state_digest,
            self.receiver_state_schema,
            &self.schema,
            &self.source_package_digest,
            self.source_state_schema,
            &self.verified_export_digest,
        ))
    }
}

/// Derive and retain both positive and negative compatibility decisions.
pub fn assess_receiver_compatibility(
    verified: &VerifiedQuarantinedExportV1,
    active: &ReceiverActiveStateV1,
    policy: &ReceiverImportPolicyV1,
) -> Result<ReceiverCompatibilityDecisionV1, M6ImportError> {
    let mut decision = derive_compatibility(verified, active, policy)?;
    decision.decision_digest = decision.expected_digest()?;
    decision.validate(verified, active, policy)?;
    let _ = decision.canonical_bytes(verified, active, policy)?;
    Ok(decision)
}

fn derive_compatibility(
    verified: &VerifiedQuarantinedExportV1,
    active: &ReceiverActiveStateV1,
    policy: &ReceiverImportPolicyV1,
) -> Result<ReceiverCompatibilityDecisionV1, M6ImportError> {
    policy.validate()?;
    active.validate()?;
    let source = verified.source_package()?;
    let receiver = active.active_package()?;
    if active.snapshot.factory_id != policy.receiver_factory_id {
        return Err(M6ImportError::FalseLink(
            "receiver active snapshot belongs to another factory".to_string(),
        ));
    }

    let mut issues = Vec::new();
    if receiver.payload.schema != policy.required_package_schema
        || receiver.payload.boot_manifest.package_format_version
            != policy.required_package_format_version
    {
        issues.push(ReceiverCompatibilityIssue::ReceiverPackageProfileDrift);
    }
    if receiver.payload.boot_manifest.interface_digest != policy.required_interface_digest {
        issues.push(ReceiverCompatibilityIssue::ReceiverInterfaceProfileDrift);
    }
    if receiver.payload.boot_manifest.worker_catalog_digest != policy.required_worker_catalog_digest
        || receiver.payload.boot_manifest.service_catalog_digest
            != policy.required_service_catalog_digest
    {
        issues.push(ReceiverCompatibilityIssue::ReceiverCapabilityProfileDrift);
    }
    if source.payload.schema != policy.required_package_schema {
        issues.push(ReceiverCompatibilityIssue::PackageSchemaMismatch);
    }
    if source.payload.boot_manifest.package_format_version != policy.required_package_format_version
    {
        issues.push(ReceiverCompatibilityIssue::PackageFormatMismatch);
    }
    if source.payload.boot_manifest.interface_digest != policy.required_interface_digest
        || source.payload.stable_interface.exported_function != REFERENCE_EXPORT
    {
        issues.push(ReceiverCompatibilityIssue::InterfaceMismatch);
    }
    if source.payload.boot_manifest.worker_catalog_digest != policy.required_worker_catalog_digest {
        issues.push(ReceiverCompatibilityIssue::WorkerCapabilityMismatch);
    }
    if source.payload.boot_manifest.service_catalog_digest != policy.required_service_catalog_digest
    {
        issues.push(ReceiverCompatibilityIssue::ServiceCapabilityMismatch);
    }
    if source.payload.generation == 0
        || source.payload.generation > policy.limits.max_source_generation
    {
        issues.push(ReceiverCompatibilityIssue::SourceGenerationOutOfBounds);
    }
    if source.payload.genome.policy.generation_enabled
        && !policy.allow_imported_generation_capability
    {
        issues.push(ReceiverCompatibilityIssue::ImportedGenerationCapabilityForbidden);
    }
    let source_state = &source.payload.boot_manifest.state_compatibility;
    let receiver_schema = active.snapshot.state_schema;
    if receiver_schema < source_state.readable_schema_min
        || receiver_schema > source_state.readable_schema_max
    {
        issues.push(ReceiverCompatibilityIssue::StateSchemaUnreadable);
    }
    let migration_required = source_state.written_schema != receiver_schema;
    if migration_required {
        issues.push(ReceiverCompatibilityIssue::StateSchemaMismatch);
    }
    if receiver_schema
        > receiver
            .payload
            .boot_manifest
            .state_compatibility
            .incumbent_rollback_readable_through
    {
        issues.push(ReceiverCompatibilityIssue::ReceiverRollbackUnreadable);
    }
    issues.sort();
    issues.dedup();
    let source_package_digest = source.package_digest.clone();
    let source_state_schema = source_state.written_schema;
    Ok(ReceiverCompatibilityDecisionV1 {
        compatible: issues.is_empty(),
        decision_digest: ContentDigest::from_bytes(&[]),
        issues,
        migration_required,
        policy_digest: policy.policy_digest.clone(),
        receiver_active_state_digest: active.active_state_digest.clone(),
        receiver_state_schema: receiver_schema,
        schema: RECEIVER_COMPATIBILITY_SCHEMA.to_string(),
        source_package_digest,
        source_state_schema,
        verified_export_digest: verified.verification_digest.clone(),
    })
}

/// Exact receiver-owned M1 proving evidence over the quarantined component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverProvingReportV1 {
    accepted: bool,
    compatibility_decision_digest: ContentDigest,
    component_digest: ContentDigest,
    policy_digest: ContentDigest,
    proving_record: ProvingRecord,
    receiver_active_state_digest: ContentDigest,
    report_digest: ContentDigest,
    schema: String,
    suite_digest: ContentDigest,
    verified_export_digest: ContentDigest,
}

impl ReceiverProvingReportV1 {
    pub fn accepted(&self) -> bool {
        self.accepted
    }

    pub fn proving_record(&self) -> &ProvingRecord {
        &self.proving_record
    }

    pub fn report_digest(&self) -> &ContentDigest {
        &self.report_digest
    }

    pub fn canonical_bytes(
        &self,
        verified: &VerifiedQuarantinedExportV1,
        active: &ReceiverActiveStateV1,
        policy: &ReceiverImportPolicyV1,
        compatibility: &ReceiverCompatibilityDecisionV1,
        suite: &ValidationSuite,
    ) -> Result<Vec<u8>, M6ImportError> {
        self.validate(verified, active, policy, compatibility, suite)?;
        let bytes = canonical_json(self)?;
        enforce_evidence_bytes(
            policy,
            &bytes,
            MAX_RECORD_OVERHEAD_BYTES,
            "receiver proving report",
        )?;
        Ok(bytes)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        verified: &VerifiedQuarantinedExportV1,
        active: &ReceiverActiveStateV1,
        policy: &ReceiverImportPolicyV1,
        compatibility: &ReceiverCompatibilityDecisionV1,
        suite: &ValidationSuite,
    ) -> Result<Self, M6ImportError> {
        let report: Self = parse_canonical(
            bytes,
            MAX_RECORD_OVERHEAD_BYTES.min(checked_evidence_bound(policy)?),
        )?;
        report.validate(verified, active, policy, compatibility, suite)?;
        Ok(report)
    }

    pub fn validate(
        &self,
        verified: &VerifiedQuarantinedExportV1,
        active: &ReceiverActiveStateV1,
        policy: &ReceiverImportPolicyV1,
        compatibility: &ReceiverCompatibilityDecisionV1,
        suite: &ValidationSuite,
    ) -> Result<(), M6ImportError> {
        if self.schema != RECEIVER_PROVING_REPORT_SCHEMA {
            return Err(M6ImportError::UnsupportedSchema(self.schema.clone()));
        }
        policy.validate()?;
        active.validate()?;
        compatibility.validate(verified, active, policy)?;
        validate_receiver_suite(policy, suite)?;
        validate_proving_record(suite, &self.proving_record)
            .map_err(|error| M6ImportError::Integrity(error.to_string()))?;
        let expected_accepted = self.proving_record.summary.all_satisfied;
        if self.accepted != expected_accepted
            || self.compatibility_decision_digest != compatibility.decision_digest
            || self.component_digest != verified.source_component_digest
            || self.component_digest != self.proving_record.component_digest
            || self.policy_digest != policy.policy_digest
            || self.receiver_active_state_digest != active.active_state_digest
            || self.suite_digest != policy.proving_suite_digest
            || self.verified_export_digest != verified.verification_digest
        {
            return Err(M6ImportError::FalseLink(
                "receiver proving report is missing or cross-linked".to_string(),
            ));
        }
        require_digest(
            "receiver proving report",
            &self.report_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ImportError> {
        digest(&(
            PROVING_REPORT_DOMAIN,
            self.accepted,
            &self.compatibility_decision_digest,
            &self.component_digest,
            &self.policy_digest,
            &self.proving_record,
            &self.receiver_active_state_digest,
            &self.schema,
            &self.suite_digest,
            &self.verified_export_digest,
        ))
    }
}

/// The only receiver-import function in this module that instantiates or
/// executes quarantined component bytes.
pub fn prove_quarantined_import(
    verified: &VerifiedQuarantinedExportV1,
    active: &ReceiverActiveStateV1,
    policy: &ReceiverImportPolicyV1,
    compatibility: &ReceiverCompatibilityDecisionV1,
    suite: &ValidationSuite,
) -> Result<ReceiverProvingReportV1, M6ImportError> {
    active.validate()?;
    compatibility.validate(verified, active, policy)?;
    if !compatibility.compatible {
        return Err(M6ImportError::Incompatible(compatibility.issues.clone()));
    }
    validate_receiver_suite(policy, suite)?;
    let component_bytes = verified.source_component_bytes()?;
    let proving_record = prove_component_i32(suite, &component_bytes)
        .map_err(|error| M6ImportError::Proving(error.to_string()))?;
    let mut report = ReceiverProvingReportV1 {
        accepted: proving_record.summary.all_satisfied,
        compatibility_decision_digest: compatibility.decision_digest.clone(),
        component_digest: ContentDigest::from_bytes(&component_bytes),
        policy_digest: policy.policy_digest.clone(),
        proving_record,
        receiver_active_state_digest: active.active_state_digest.clone(),
        report_digest: ContentDigest::from_bytes(&[]),
        schema: RECEIVER_PROVING_REPORT_SCHEMA.to_string(),
        suite_digest: policy.proving_suite_digest.clone(),
        verified_export_digest: verified.verification_digest.clone(),
    };
    report.report_digest = report.expected_digest()?;
    report.validate(verified, active, policy, compatibility, suite)?;
    let _ = report.canonical_bytes(verified, active, policy, compatibility, suite)?;
    Ok(report)
}

fn validate_receiver_suite(
    policy: &ReceiverImportPolicyV1,
    suite: &ValidationSuite,
) -> Result<(), M6ImportError> {
    suite
        .validate()
        .map_err(|error| M6ImportError::InvalidPolicy(error.to_string()))?;
    validate_suite_limits(&policy.limits, suite)?;
    if suite
        .suite_digest()
        .map_err(|error| M6ImportError::InvalidPolicy(error.to_string()))?
        != policy.proving_suite_digest
    {
        return Err(M6ImportError::FalseLink(
            "receiver proving suite differs from immutable policy".to_string(),
        ));
    }
    Ok(())
}

fn validate_import_limits_for_route(
    route: &RouteDefinition,
    limits: &ReceiverImportLimitsV1,
) -> Result<(), M6ImportError> {
    limits.validate()?;
    let profile = &route.resource_profile;
    if limits.max_evidence_bytes > profile.max_evidence_bytes
        || limits.max_package_bytes > profile.max_package_bytes
        || limits.max_proving_cases > profile.max_proving_cases
        || limits.max_proving_fuel > profile.max_proving_fuel
        || limits.max_proving_instances > profile.max_proving_instances
        || limits.max_proving_memory_bytes > profile.max_proving_memory_bytes
    {
        return Err(M6ImportError::InvalidPolicy(
            "receiver import limits exceed the immutable route resource profile".to_string(),
        ));
    }
    Ok(())
}

fn validate_suite_limits(
    limits: &ReceiverImportLimitsV1,
    suite: &ValidationSuite,
) -> Result<(), M6ImportError> {
    if suite.cases.len() > limits.max_proving_cases as usize
        || suite.limits.fuel > limits.max_proving_fuel
        || suite.limits.max_instances > limits.max_proving_instances
        || suite.limits.max_memory_bytes > limits.max_proving_memory_bytes
    {
        return Err(M6ImportError::InvalidPolicy(
            "receiver proving suite exceeds the immutable import policy limits".to_string(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverStateTransitionV1 {
    NoMigration,
}

/// Explicit source-to-receiver lineage retained beside the derived local
/// package. It never rewrites the sender package to claim local origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedLineageBindingV1 {
    export_bundle_digest: ContentDigest,
    lineage_digest: ContentDigest,
    message_digest: ContentDigest,
    raw_quarantine_digest: ContentDigest,
    receiver_local_package_digest: ContentDigest,
    receiver_parent_package_digest: ContentDigest,
    receiver_proving_report_digest: ContentDigest,
    schema: String,
    source_component_digest: ContentDigest,
    source_factory_id: String,
    source_identity_document_digest: ContentDigest,
    source_package_digest: ContentDigest,
    source_recipe_digest: ContentDigest,
}

impl ImportedLineageBindingV1 {
    pub fn lineage_digest(&self) -> &ContentDigest {
        &self.lineage_digest
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ImportError> {
        digest(&(
            IMPORT_LINEAGE_DOMAIN,
            &self.export_bundle_digest,
            &self.message_digest,
            &self.raw_quarantine_digest,
            &self.receiver_local_package_digest,
            &self.receiver_parent_package_digest,
            &self.receiver_proving_report_digest,
            &self.schema,
            &self.source_component_digest,
            &self.source_factory_id,
            &self.source_identity_document_digest,
            &self.source_package_digest,
            &self.source_recipe_digest,
        ))
    }

    fn validate(&self) -> Result<(), M6ImportError> {
        if self.schema != IMPORTED_LINEAGE_BINDING_SCHEMA {
            return Err(M6ImportError::UnsupportedSchema(self.schema.clone()));
        }
        require_digest(
            "imported lineage binding",
            &self.lineage_digest,
            &self.expected_digest()?,
        )
    }
}

/// Effect-free, exact receiver-local import plan.
///
/// The local package is a separately content-addressed wrapper whose component
/// bytes equal the independently proved source component. This record does not
/// authorize M3 or M5 and exposes no activation operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverImportPlanV1 {
    compatibility_decision_digest: ContentDigest,
    export_bundle_digest: ContentDigest,
    import_plan_digest: ContentDigest,
    imported_lineage: ImportedLineageBindingV1,
    message_digest: ContentDigest,
    migration_plan_digest: ContentDigest,
    policy_digest: ContentDigest,
    raw_quarantine_digest: ContentDigest,
    receiver_active_snapshot_digest: ContentDigest,
    receiver_factory_id: String,
    receiver_local_package_bytes: Vec<u8>,
    receiver_local_package_bytes_digest: ContentDigest,
    receiver_local_package_digest: ContentDigest,
    receiver_proving_report_digest: ContentDigest,
    rollback_target_digest: ContentDigest,
    route_definition_digest: ContentDigest,
    schema: String,
    source_factory_id: String,
    source_identity_document_digest: ContentDigest,
    source_package_bytes: Vec<u8>,
    source_package_bytes_digest: ContentDigest,
    source_package_digest: ContentDigest,
    source_recipe_digest: ContentDigest,
    source_recipe_wat_bytes: Vec<u8>,
    state_transition: ReceiverStateTransitionV1,
    verified_export_digest: ContentDigest,
}

#[derive(Serialize)]
struct ReceiverImportPlanDigestMaterial<'a> {
    compatibility_decision_digest: &'a ContentDigest,
    export_bundle_digest: &'a ContentDigest,
    imported_lineage: &'a ImportedLineageBindingV1,
    message_digest: &'a ContentDigest,
    migration_plan_digest: &'a ContentDigest,
    policy_digest: &'a ContentDigest,
    raw_quarantine_digest: &'a ContentDigest,
    receiver_active_snapshot_digest: &'a ContentDigest,
    receiver_factory_id: &'a str,
    receiver_local_package_bytes: &'a [u8],
    receiver_local_package_bytes_digest: &'a ContentDigest,
    receiver_local_package_digest: &'a ContentDigest,
    receiver_proving_report_digest: &'a ContentDigest,
    rollback_target_digest: &'a ContentDigest,
    route_definition_digest: &'a ContentDigest,
    schema: &'a str,
    source_factory_id: &'a str,
    source_identity_document_digest: &'a ContentDigest,
    source_package_bytes: &'a [u8],
    source_package_bytes_digest: &'a ContentDigest,
    source_package_digest: &'a ContentDigest,
    source_recipe_digest: &'a ContentDigest,
    source_recipe_wat_bytes: &'a [u8],
    state_transition: ReceiverStateTransitionV1,
    verified_export_digest: &'a ContentDigest,
}

impl ReceiverImportPlanV1 {
    pub fn import_plan_digest(&self) -> &ContentDigest {
        &self.import_plan_digest
    }

    pub fn receiver_local_package_digest(&self) -> &ContentDigest {
        &self.receiver_local_package_digest
    }

    pub fn receiver_local_package_bytes_digest(&self) -> &ContentDigest {
        &self.receiver_local_package_bytes_digest
    }

    pub fn receiver_local_package_bytes(&self) -> &[u8] {
        &self.receiver_local_package_bytes
    }

    pub fn source_recipe_wat_bytes(&self) -> &[u8] {
        &self.source_recipe_wat_bytes
    }

    pub fn rollback_target_digest(&self) -> &ContentDigest {
        &self.rollback_target_digest
    }

    pub fn imported_lineage(&self) -> &ImportedLineageBindingV1 {
        &self.imported_lineage
    }

    pub fn receiver_proving_report_digest(&self) -> &ContentDigest {
        &self.receiver_proving_report_digest
    }

    pub fn canonical_bytes(
        &self,
        verified: &VerifiedQuarantinedExportV1,
        active: &ReceiverActiveStateV1,
        policy: &ReceiverImportPolicyV1,
        compatibility: &ReceiverCompatibilityDecisionV1,
        proving: &ReceiverProvingReportV1,
        suite: &ValidationSuite,
    ) -> Result<Vec<u8>, M6ImportError> {
        self.validate(verified, active, policy, compatibility, proving, suite)?;
        let bytes = canonical_json(self)?;
        let max = checked_plan_bound(policy)?;
        if bytes.len() > max {
            return Err(M6ImportError::ResourceBound(
                "receiver import plan exceeds its record bound".to_string(),
            ));
        }
        Ok(bytes)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_canonical_bytes(
        bytes: &[u8],
        verified: &VerifiedQuarantinedExportV1,
        active: &ReceiverActiveStateV1,
        policy: &ReceiverImportPolicyV1,
        compatibility: &ReceiverCompatibilityDecisionV1,
        proving: &ReceiverProvingReportV1,
        suite: &ValidationSuite,
    ) -> Result<Self, M6ImportError> {
        let plan: Self = parse_canonical(bytes, checked_plan_bound(policy)?)?;
        plan.validate(verified, active, policy, compatibility, proving, suite)?;
        Ok(plan)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate(
        &self,
        verified: &VerifiedQuarantinedExportV1,
        active: &ReceiverActiveStateV1,
        policy: &ReceiverImportPolicyV1,
        compatibility: &ReceiverCompatibilityDecisionV1,
        proving: &ReceiverProvingReportV1,
        suite: &ValidationSuite,
    ) -> Result<(), M6ImportError> {
        if self.schema != RECEIVER_IMPORT_PLAN_SCHEMA {
            return Err(M6ImportError::UnsupportedSchema(self.schema.clone()));
        }
        active.validate()?;
        compatibility.validate(verified, active, policy)?;
        proving.validate(verified, active, policy, compatibility, suite)?;
        if !compatibility.compatible {
            return Err(M6ImportError::Incompatible(compatibility.issues.clone()));
        }
        if !proving.accepted {
            return Err(M6ImportError::ProvingRejected);
        }
        let source = FactoryPackage::from_canonical_bytes(&self.source_package_bytes)
            .map_err(|error| M6ImportError::Integrity(error.to_string()))?;
        let local = FactoryPackage::from_canonical_bytes(&self.receiver_local_package_bytes)
            .map_err(|error| M6ImportError::Integrity(error.to_string()))?;
        let active_package = active.active_package()?;
        let compiled = wat::parse_bytes(&self.source_recipe_wat_bytes)
            .map_err(|error| {
                M6ImportError::Integrity(format!("planned source recipe is not valid WAT: {error}"))
            })?
            .into_owned();
        if self.compatibility_decision_digest != compatibility.decision_digest
            || self.export_bundle_digest != verified.export_bundle_digest
            || self.message_digest != *verified.message_digest()
            || self.policy_digest != policy.policy_digest
            || self.raw_quarantine_digest != *verified.raw_quarantine_digest()
            || self.receiver_active_snapshot_digest != active.snapshot.snapshot_digest
            || self.receiver_factory_id != policy.receiver_factory_id
            || self.receiver_local_package_bytes_digest
                != ContentDigest::from_bytes(&self.receiver_local_package_bytes)
            || self.receiver_local_package_digest != local.package_digest
            || self.receiver_proving_report_digest != proving.report_digest
            || self.rollback_target_digest != active.rollback_target_digest
            || self.route_definition_digest != verified.route_definition_digest
            || self.source_factory_id != verified.source_factory_id
            || self.source_identity_document_digest != verified.source_identity_document_digest
            || self.source_package_bytes_digest
                != ContentDigest::from_bytes(&self.source_package_bytes)
            || self.source_package_bytes_digest != verified.source_package_bytes_digest
            || self.source_package_digest != source.package_digest
            || self.source_package_digest != verified.source_package_digest
            || self.source_recipe_digest != ContentDigest::from_bytes(&self.source_recipe_wat_bytes)
            || self.source_recipe_digest != verified.source_recipe_digest
            || self.state_transition != ReceiverStateTransitionV1::NoMigration
            || self.verified_export_digest != verified.verification_digest
            || compiled != source.payload.genome.component_bytes
            || compiled != local.payload.genome.component_bytes
            || local.payload.factory_id != policy.receiver_factory_id
            || local.payload.parent_package_digest != Some(active_package.package_digest.clone())
            || local.payload.generation != active_package.payload.generation.saturating_add(1)
        {
            return Err(M6ImportError::FalseLink(
                "receiver import plan differs from exact source, proving, or rollback material"
                    .to_string(),
            ));
        }
        let expected_local =
            derive_local_package(&source, &active_package, &policy.receiver_factory_id)?;
        if expected_local != local {
            return Err(M6ImportError::Integrity(
                "receiver-local package is not the deterministic import wrapper".to_string(),
            ));
        }
        let expected_no_migration = no_migration_digest(
            active.snapshot.state_schema,
            &active.snapshot.snapshot_digest,
            &source.package_digest,
        )?;
        if self.migration_plan_digest != expected_no_migration {
            return Err(M6ImportError::FalseLink(
                "no-migration identity differs from exact active state".to_string(),
            ));
        }
        self.imported_lineage.validate()?;
        if self.imported_lineage != expected_lineage(verified, &active_package, &local, proving)? {
            return Err(M6ImportError::FalseLink(
                "imported lineage is stale or cross-linked".to_string(),
            ));
        }
        require_digest(
            "receiver import plan",
            &self.import_plan_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ImportError> {
        digest(&(
            IMPORT_PLAN_DOMAIN,
            ReceiverImportPlanDigestMaterial {
                compatibility_decision_digest: &self.compatibility_decision_digest,
                export_bundle_digest: &self.export_bundle_digest,
                imported_lineage: &self.imported_lineage,
                message_digest: &self.message_digest,
                migration_plan_digest: &self.migration_plan_digest,
                policy_digest: &self.policy_digest,
                raw_quarantine_digest: &self.raw_quarantine_digest,
                receiver_active_snapshot_digest: &self.receiver_active_snapshot_digest,
                receiver_factory_id: &self.receiver_factory_id,
                receiver_local_package_bytes: &self.receiver_local_package_bytes,
                receiver_local_package_bytes_digest: &self.receiver_local_package_bytes_digest,
                receiver_local_package_digest: &self.receiver_local_package_digest,
                receiver_proving_report_digest: &self.receiver_proving_report_digest,
                rollback_target_digest: &self.rollback_target_digest,
                route_definition_digest: &self.route_definition_digest,
                schema: &self.schema,
                source_factory_id: &self.source_factory_id,
                source_identity_document_digest: &self.source_identity_document_digest,
                source_package_bytes: &self.source_package_bytes,
                source_package_bytes_digest: &self.source_package_bytes_digest,
                source_package_digest: &self.source_package_digest,
                source_recipe_digest: &self.source_recipe_digest,
                source_recipe_wat_bytes: &self.source_recipe_wat_bytes,
                state_transition: self.state_transition,
                verified_export_digest: &self.verified_export_digest,
            },
        ))
    }
}

/// Derive an exact local wrapper and lineage after a positive receiver proving
/// report. This remains effect-free and performs no activation.
pub fn derive_receiver_import_plan(
    verified: &VerifiedQuarantinedExportV1,
    active: &ReceiverActiveStateV1,
    policy: &ReceiverImportPolicyV1,
    compatibility: &ReceiverCompatibilityDecisionV1,
    proving: &ReceiverProvingReportV1,
    suite: &ValidationSuite,
) -> Result<ReceiverImportPlanV1, M6ImportError> {
    active.validate()?;
    compatibility.validate(verified, active, policy)?;
    proving.validate(verified, active, policy, compatibility, suite)?;
    if !compatibility.compatible {
        return Err(M6ImportError::Incompatible(compatibility.issues.clone()));
    }
    if !proving.accepted {
        return Err(M6ImportError::ProvingRejected);
    }
    let source = verified.source_package()?;
    let active_package = active.active_package()?;
    let local = derive_local_package(&source, &active_package, &policy.receiver_factory_id)?;
    let source_package_bytes = verified.source_package_bytes()?;
    let source_recipe_wat_bytes = verified.source_recipe_bytes()?;
    let receiver_local_package_bytes = local
        .canonical_bytes()
        .map_err(|error| M6ImportError::Integrity(error.to_string()))?;
    let imported_lineage = expected_lineage(verified, &active_package, &local, proving)?;
    let mut plan = ReceiverImportPlanV1 {
        compatibility_decision_digest: compatibility.decision_digest.clone(),
        export_bundle_digest: verified.export_bundle_digest.clone(),
        import_plan_digest: ContentDigest::from_bytes(&[]),
        imported_lineage,
        message_digest: verified.manifest.message_digest.clone(),
        migration_plan_digest: no_migration_digest(
            active.snapshot.state_schema,
            &active.snapshot.snapshot_digest,
            &source.package_digest,
        )?,
        policy_digest: policy.policy_digest.clone(),
        raw_quarantine_digest: verified.raw_quarantine.raw_unit_digest.clone(),
        receiver_active_snapshot_digest: active.snapshot.snapshot_digest.clone(),
        receiver_factory_id: policy.receiver_factory_id.clone(),
        receiver_local_package_bytes_digest: ContentDigest::from_bytes(
            &receiver_local_package_bytes,
        ),
        receiver_local_package_digest: local.package_digest,
        receiver_local_package_bytes,
        receiver_proving_report_digest: proving.report_digest.clone(),
        rollback_target_digest: active.rollback_target_digest.clone(),
        route_definition_digest: verified.route_definition_digest.clone(),
        schema: RECEIVER_IMPORT_PLAN_SCHEMA.to_string(),
        source_factory_id: verified.source_factory_id.clone(),
        source_identity_document_digest: verified.source_identity_document_digest.clone(),
        source_package_bytes_digest: ContentDigest::from_bytes(&source_package_bytes),
        source_package_digest: source.package_digest,
        source_package_bytes,
        source_recipe_digest: ContentDigest::from_bytes(&source_recipe_wat_bytes),
        source_recipe_wat_bytes,
        state_transition: ReceiverStateTransitionV1::NoMigration,
        verified_export_digest: verified.verification_digest.clone(),
    };
    plan.import_plan_digest = plan.expected_digest()?;
    plan.validate(verified, active, policy, compatibility, proving, suite)?;
    let _ = plan.canonical_bytes(verified, active, policy, compatibility, proving, suite)?;
    Ok(plan)
}

fn derive_local_package(
    source: &FactoryPackage,
    receiver_parent: &FactoryPackage,
    receiver_factory_id: &str,
) -> Result<FactoryPackage, M6ImportError> {
    let local_genome = MutableGenome::new(
        Some(receiver_parent.package_digest.clone()),
        source.payload.genome.component_bytes.clone(),
        source.payload.genome.policy.clone(),
    )
    .map_err(|error| M6ImportError::Integrity(error.to_string()))?;
    FactoryPackage::build(
        receiver_factory_id,
        receiver_parent
            .payload
            .generation
            .checked_add(1)
            .ok_or_else(|| {
                M6ImportError::ResourceBound("receiver local generation overflowed".to_string())
            })?,
        local_genome,
        source.payload.stable_interface.clone(),
        source.payload.worker_catalog.clone(),
        source.payload.service_dependencies.clone(),
        source.payload.boot_manifest.state_compatibility.clone(),
    )
    .map_err(|error| M6ImportError::Integrity(error.to_string()))
}

fn expected_lineage(
    verified: &VerifiedQuarantinedExportV1,
    receiver_parent: &FactoryPackage,
    local: &FactoryPackage,
    proving: &ReceiverProvingReportV1,
) -> Result<ImportedLineageBindingV1, M6ImportError> {
    let mut lineage = ImportedLineageBindingV1 {
        export_bundle_digest: verified.export_bundle_digest.clone(),
        lineage_digest: ContentDigest::from_bytes(&[]),
        message_digest: verified.manifest.message_digest.clone(),
        raw_quarantine_digest: verified.raw_quarantine.raw_unit_digest.clone(),
        receiver_local_package_digest: local.package_digest.clone(),
        receiver_parent_package_digest: receiver_parent.package_digest.clone(),
        receiver_proving_report_digest: proving.report_digest.clone(),
        schema: IMPORTED_LINEAGE_BINDING_SCHEMA.to_string(),
        source_component_digest: verified.source_component_digest.clone(),
        source_factory_id: verified.source_factory_id.clone(),
        source_identity_document_digest: verified.source_identity_document_digest.clone(),
        source_package_digest: verified.source_package_digest.clone(),
        source_recipe_digest: verified.source_recipe_digest.clone(),
    };
    lineage.lineage_digest = lineage.expected_digest()?;
    lineage.validate()?;
    Ok(lineage)
}

fn no_migration_digest(
    state_schema: u32,
    active_snapshot_digest: &ContentDigest,
    source_package_digest: &ContentDigest,
) -> Result<ContentDigest, M6ImportError> {
    digest(&(
        NO_MIGRATION_DOMAIN,
        state_schema,
        active_snapshot_digest,
        source_package_digest,
    ))
}

fn validate_snapshot(
    snapshot: &FactoryRuntimeSnapshot,
    package: &FactoryPackage,
    package_bytes: &[u8],
) -> Result<(), M6ImportError> {
    let expected_digest = digest(&(
        FACTORY_SNAPSHOT_SCHEMA,
        &snapshot.factory_id,
        &snapshot.package_digest,
        &snapshot.package_bytes_digest,
        &snapshot.component_digest,
        snapshot.generation,
        snapshot.state_schema,
        &snapshot.state_blob_digest,
        &snapshot.activation_id,
    ))?;
    if snapshot.schema != FACTORY_SNAPSHOT_SCHEMA
        || snapshot.factory_id != package.payload.factory_id
        || snapshot.package_digest != package.package_digest
        || snapshot.package_bytes_digest != ContentDigest::from_bytes(package_bytes)
        || snapshot.component_digest != package.payload.genome.component_digest
        || snapshot.generation != package.payload.generation
        || snapshot.state_schema == 0
        || snapshot.snapshot_digest != expected_digest
    {
        return Err(M6ImportError::Integrity(
            "receiver M5 active snapshot differs from exact active package bytes".to_string(),
        ));
    }
    Ok(())
}

fn checked_evidence_bound(policy: &ReceiverImportPolicyV1) -> Result<usize, M6ImportError> {
    usize::try_from(policy.limits.max_evidence_bytes).map_err(|_| {
        M6ImportError::ResourceBound(
            "receiver evidence-byte budget does not fit this platform".to_string(),
        )
    })
}

fn checked_verified_record_bound(policy: &ReceiverImportPolicyV1) -> Result<usize, M6ImportError> {
    let structural = usize::try_from(policy.limits.max_quarantine_bytes)
        .ok()
        .and_then(|value| value.checked_add(MAX_RECORD_OVERHEAD_BYTES))
        .ok_or_else(|| {
            M6ImportError::ResourceBound("verified export record bound overflowed".to_string())
        })?;
    Ok(structural.min(checked_evidence_bound(policy)?))
}

fn enforce_evidence_bytes(
    policy: &ReceiverImportPolicyV1,
    bytes: &[u8],
    structural_bound: usize,
    kind: &'static str,
) -> Result<(), M6ImportError> {
    if bytes.len() > structural_bound.min(checked_evidence_bound(policy)?) {
        return Err(M6ImportError::ResourceBound(format!(
            "{kind} exceeds the immutable evidence-byte budget"
        )));
    }
    Ok(())
}

fn checked_plan_bound(policy: &ReceiverImportPolicyV1) -> Result<usize, M6ImportError> {
    let package = usize::try_from(policy.limits.max_package_bytes).map_err(|_| {
        M6ImportError::ResourceBound(
            "receiver package bound does not fit this platform".to_string(),
        )
    })?;
    let recipe = usize::try_from(policy.limits.max_recipe_bytes).map_err(|_| {
        M6ImportError::ResourceBound("receiver recipe bound does not fit this platform".to_string())
    })?;
    let structural = package
        .checked_mul(2)
        .and_then(|value| value.checked_add(recipe))
        .and_then(|value| value.checked_add(MAX_RECORD_OVERHEAD_BYTES))
        .ok_or_else(|| {
            M6ImportError::ResourceBound("receiver import plan record bound overflowed".to_string())
        })?;
    Ok(structural.min(checked_evidence_bound(policy)?))
}

fn is_safe_portable_path(path: &str) -> bool {
    !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.contains('\\')
        && !path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), M6ImportError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(M6ImportError::Integrity(format!(
            "{field} must contain 1..={MAX_IDENTIFIER_BYTES} non-control bytes"
        )));
    }
    Ok(())
}

fn require_digest(
    subject: &str,
    actual: &ContentDigest,
    expected: &ContentDigest,
) -> Result<(), M6ImportError> {
    if actual == expected {
        Ok(())
    } else {
        Err(M6ImportError::Integrity(format!(
            "{subject} digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

fn digest<T: Serialize>(value: &T) -> Result<ContentDigest, M6ImportError> {
    digest_json_content(value).map_err(|error| M6ImportError::Serialization(error.to_string()))
}

fn domain_digest_bytes<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ContentDigest, M6ImportError> {
    let mut bytes = Vec::from(domain);
    bytes.extend_from_slice(&canonical_json(value)?);
    Ok(ContentDigest::from_bytes(&bytes))
}

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, M6ImportError> {
    serde_json::to_vec(value).map_err(|error| M6ImportError::Serialization(error.to_string()))
}

fn parse_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, M6ImportError> {
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(M6ImportError::ResourceBound(
            "canonical record byte length is outside bounds".to_string(),
        ));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| M6ImportError::Serialization(error.to_string()))?;
    if canonical_json(&value)? != bytes {
        return Err(M6ImportError::Integrity(
            "record is not in its sole canonical representation".to_string(),
        ));
    }
    Ok(value)
}

fn m5_export_error(error: M5ExportError) -> M6ImportError {
    match error {
        M5ExportError::UnsupportedSchema(schema) => M6ImportError::UnsupportedSchema(schema),
        M5ExportError::ResourceBound(message) => M6ImportError::ResourceBound(message),
        M5ExportError::Serialization(message) => M6ImportError::Serialization(message),
        M5ExportError::NotExportable(message) | M5ExportError::Integrity(message) => {
            M6ImportError::Integrity(message)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum M6ImportError {
    Authentication(String),
    FalseLink(String),
    Incompatible(Vec<ReceiverCompatibilityIssue>),
    Integrity(String),
    InvalidPolicy(String),
    MissingEvidence(String),
    Proving(String),
    ProvingRejected,
    RawQuarantine(String),
    ResourceBound(String),
    Serialization(String),
    UnsupportedSchema(String),
}

impl Display for M6ImportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authentication(message) => {
                write!(formatter, "M6 import authentication failed: {message}")
            }
            Self::FalseLink(message) => {
                write!(formatter, "M6 import evidence is cross-linked: {message}")
            }
            Self::Incompatible(issues) => {
                write!(formatter, "M6 import is incompatible: {issues:?}")
            }
            Self::Integrity(message) => {
                write!(formatter, "M6 import integrity failure: {message}")
            }
            Self::InvalidPolicy(message) => {
                write!(formatter, "invalid M6 receiver import policy: {message}")
            }
            Self::MissingEvidence(message) => {
                write!(formatter, "M6 import evidence is incomplete: {message}")
            }
            Self::Proving(message) => {
                write!(formatter, "M6 receiver proving failed: {message}")
            }
            Self::ProvingRejected => {
                write!(formatter, "M6 receiver proving did not satisfy every case")
            }
            Self::RawQuarantine(message) => {
                write!(formatter, "M6 raw quarantine mismatch: {message}")
            }
            Self::ResourceBound(message) => {
                write!(formatter, "M6 import resource bound: {message}")
            }
            Self::Serialization(message) => {
                write!(formatter, "M6 import serialization failure: {message}")
            }
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported M6 import schema '{schema}'")
            }
        }
    }
}

impl Error for M6ImportError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::component::ComponentExecutionLimits;
    use crate::factory_reproduction::{
        ApprovalDecision, BenchmarkSpec, InvariantKind, InvariantSpec, MutableFactoryPolicy,
        RecursionBudgets, ReleaseGate, ReleaseThresholds, ServiceDependencyCatalog,
        StableInterfaceContract, StateCompatibility, WorkerCatalog,
    };
    use crate::m1_validation::ValidationCase;
    use crate::m5_runtime::{
        M5InitializationAuthority, M5Runtime, M5RuntimeConfig, M5SeedCyclePlan,
    };
    use crate::m6_identity::{
        AttachmentDescriptor, CANONICAL_ENCODING_VERSION, DeterministicClock,
        ExportManifestPayload, FactoryIdentityDocument, FactorySigner, GovernedFilesystemSpool,
        IssuedManifest, ManifestPayload, ReceiverRawQuarantine, RouteEndpointRole,
        RouteResourceProfile, SIGNED_MANIFEST_SCHEMA, UnsignedManifest,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, OnceLock};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    static SOURCE_EXPORT: OnceLock<Vec<u8>> = OnceLock::new();

    struct TestTree(PathBuf);

    impl TestTree {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aiaf-v1-m6-import-{label}-{}-{}",
                std::process::id(),
                TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("create test tree");
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            if self.0.starts_with(std::env::temp_dir()) {
                let _ = fs::remove_dir_all(&self.0);
            }
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

    fn identity_wat() -> Vec<u8> {
        component_wat("local.get 0")
    }

    fn increment_wat() -> Vec<u8> {
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

    fn receiver_suite() -> ValidationSuite {
        ValidationSuite::new(
            "m6-receiver-suite",
            REFERENCE_EXPORT,
            vec![
                ValidationCase::returns("case:one", 1, 2),
                ValidationCase::returns("case:seven", 7, 8),
            ],
            ComponentExecutionLimits::default(),
        )
        .expect("valid receiver proving suite")
    }

    fn rejecting_suite() -> ValidationSuite {
        ValidationSuite::new(
            "m6-receiver-rejecting-suite",
            REFERENCE_EXPORT,
            vec![
                ValidationCase::returns("case:one", 1, 99),
                ValidationCase::returns("case:seven", 7, 99),
            ],
            ComponentExecutionLimits::default(),
        )
        .expect("valid negative proving suite")
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
            "m6-source-gate",
            benchmarks,
            invariants,
            RecursionBudgets {
                max_generation_depth: 4,
                max_total_cycles: 8,
                max_shadow_tasks: 4,
                max_component_bytes: HARD_MAX_COMPONENT_BYTES,
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
        .expect("valid release gate")
    }

    fn source_export_bytes() -> Vec<u8> {
        SOURCE_EXPORT
            .get_or_init(|| {
                let tree = TestTree::new("source-export");
                let runtime = M5Runtime::initialize(
                    M5RuntimeConfig {
                        root: tree.join("source-runtime"),
                        factory_id: "factory:m6-source".to_string(),
                        scope_id: "scope:m6-source".to_string(),
                        deployment_id: "deployment-m6-source".to_string(),
                        worker_max_concurrency: 1,
                    },
                    identity_wat(),
                    receiver_suite(),
                    release_gate(),
                    1,
                    M5InitializationAuthority {
                        operator_ref: "operator:m6-source-bootstrap".to_string(),
                        rationale: "initialize exact source fixture".to_string(),
                    },
                    None,
                )
                .expect("initialize source M5");
                runtime
                    .run_seeded_cycle(M5SeedCyclePlan {
                        cycle_id: "cycle:m6-source-n1".to_string(),
                        challenger_wat_bytes: increment_wat(),
                        challenger_policy: MutableFactoryPolicy::terminal(2, 2),
                        state_compatibility: StateCompatibility {
                            readable_schema_min: 1,
                            readable_schema_max: 2,
                            written_schema: 1,
                            incumbent_rollback_readable_through: 2,
                        },
                        migration_plan: None,
                        migration_artifacts: None,
                        operator_context_digest: ContentDigest::from_bytes(
                            b"m6-source-operator-context",
                        ),
                        approval_decision: ApprovalDecision::Approved,
                        approver_ref: "operator:m6-source".to_string(),
                        approval_rationale: "approve exact M6 source fixture".to_string(),
                    })
                    .expect("adopt source N+1");
                let bytes = runtime
                    .export_active_adopted_bundle()
                    .expect("export source N+1")
                    .canonical_bytes()
                    .expect("canonical source export");
                drop(runtime);
                bytes
            })
            .clone()
    }

    fn receiver_package() -> FactoryPackage {
        FactoryPackage::build(
            "factory:m6-receiver",
            0,
            MutableGenome::new(
                None,
                wat::parse_bytes(&identity_wat())
                    .expect("compile receiver WAT")
                    .into_owned(),
                MutableFactoryPolicy::terminal(1, 2),
            )
            .expect("receiver genome"),
            StableInterfaceContract::reference(),
            WorkerCatalog::reference().expect("worker catalog"),
            ServiceDependencyCatalog::reference().expect("service catalog"),
            StateCompatibility {
                readable_schema_min: 1,
                readable_schema_max: 2,
                written_schema: 1,
                incumbent_rollback_readable_through: 2,
            },
        )
        .expect("receiver package")
    }

    fn active_state(package: &FactoryPackage) -> ReceiverActiveStateV1 {
        let package_bytes = package.canonical_bytes().expect("receiver bytes");
        let state_bytes = br#"{"factory_id":"factory:m6-receiver","generation":0,"schema":1}"#;
        let mut snapshot = FactoryRuntimeSnapshot {
            schema: FACTORY_SNAPSHOT_SCHEMA.to_string(),
            factory_id: package.payload.factory_id.clone(),
            package_digest: package.package_digest.clone(),
            package_bytes_digest: ContentDigest::from_bytes(&package_bytes),
            component_digest: package.payload.genome.component_digest.clone(),
            generation: package.payload.generation,
            state_schema: 1,
            state_blob_digest: ContentDigest::from_bytes(state_bytes),
            activation_id: None,
            snapshot_digest: ContentDigest::from_bytes(&[]),
        };
        snapshot.snapshot_digest = digest(&(
            FACTORY_SNAPSHOT_SCHEMA,
            &snapshot.factory_id,
            &snapshot.package_digest,
            &snapshot.package_bytes_digest,
            &snapshot.component_digest,
            snapshot.generation,
            snapshot.state_schema,
            &snapshot.state_blob_digest,
            &snapshot.activation_id,
        ))
        .expect("snapshot digest");
        ReceiverActiveStateV1::new(snapshot, package_bytes).expect("receiver active state")
    }

    struct ImportRig {
        _tree: TestTree,
        active: ReceiverActiveStateV1,
        policy: ReceiverImportPolicyV1,
        receiver_quarantine: ReceiverRawQuarantine,
        receiver_spool: GovernedFilesystemSpool,
        route: RouteDefinition,
        sender_signer: FactorySigner,
        sender_spool: GovernedFilesystemSpool,
        suite: ValidationSuite,
    }

    impl ImportRig {
        fn new(label: &str, suite: ValidationSuite) -> Self {
            let tree = TestTree::new(label);
            let sender_signer =
                FactorySigner::from_seed("key:m6-source", [0x31; 32]).expect("source signer");
            let receiver_signer =
                FactorySigner::from_seed("key:m6-receiver", [0x42; 32]).expect("receiver signer");
            let package_schema = ContentDigest::from_bytes(FACTORY_PACKAGE_SCHEMA.as_bytes());
            let interface_schema = StableInterfaceContract::reference()
                .contract_digest()
                .expect("interface digest");
            let exchange_policy = ContentDigest::from_bytes(b"m6-route-exchange-policy");
            let sender_identity = FactoryIdentityDocument::new(
                "factory:m6-source",
                &sender_signer,
                1,
                1_000_000,
                vec![package_schema.clone()],
                vec![interface_schema.clone()],
                ContentDigest::from_bytes(b"source-authority-profile"),
                exchange_policy.clone(),
            )
            .expect("sender identity");
            let receiver_identity = FactoryIdentityDocument::new(
                "factory:m6-receiver",
                &receiver_signer,
                1,
                1_000_000,
                vec![package_schema],
                vec![interface_schema],
                ContentDigest::from_bytes(b"receiver-authority-profile"),
                exchange_policy.clone(),
            )
            .expect("receiver identity");
            let route = RouteDefinition::new(
                format!("route:m6-import-{label}"),
                1,
                &sender_identity,
                &receiver_identity,
                exchange_policy,
                RouteResourceProfile::bounded_default().expect("route profile"),
            )
            .expect("route");
            let sender_root = tree.join("sender");
            let receiver_root = tree.join("receiver");
            let route_root = tree.join("route");
            GovernedFilesystemSpool::initialize(
                &route_root,
                &sender_root,
                &receiver_root,
                route.clone(),
            )
            .expect("initialize spool");
            let sender_spool = GovernedFilesystemSpool::open(
                &route_root,
                &sender_root,
                RouteEndpointRole::Sender,
                &route.definition_digest,
            )
            .expect("open sender spool");
            let receiver_spool = GovernedFilesystemSpool::open(
                &route_root,
                &receiver_root,
                RouteEndpointRole::Receiver,
                &route.definition_digest,
            )
            .expect("open receiver spool");
            let receiver_quarantine = ReceiverRawQuarantine::open_or_initialize(
                &receiver_root,
                route.clone(),
                Arc::new(DeterministicClock::new(100)),
            )
            .expect("open receiver quarantine");
            let package = receiver_package();
            let active = active_state(&package);
            let policy = ReceiverImportPolicyV1::for_route(
                format!("policy:m6-import-{label}"),
                &route,
                &package,
                &suite,
                ReceiverImportLimitsV1::bounded_default(),
                false,
            )
            .expect("receiver policy");
            Self {
                _tree: tree,
                active,
                policy,
                receiver_quarantine,
                receiver_spool,
                route,
                sender_signer,
                sender_spool,
                suite,
            }
        }

        fn issue(&self, bundle_bytes: Vec<u8>, mode: FixtureMode) -> IssuedManifest {
            let bundle =
                M5ExportBundleV1::from_canonical_bytes(&bundle_bytes).expect("fixture bundle");
            let source = active_source_package(&bundle).expect("source package");
            let mut attachments = exact_fixture_attachments(&bundle, bundle_bytes);
            let mut payload = ExportManifestPayload {
                component_digest: source.payload.genome.component_digest.clone(),
                export_bundle_digest: bundle.bundle_digest().clone(),
                package_bytes_digest: bundle
                    .active_package()
                    .canonical_package_bytes_digest()
                    .clone(),
                package_digest: source.package_digest.clone(),
            };
            match mode {
                FixtureMode::Exact => {}
                FixtureMode::BundleOnly => {
                    attachments.retain(|_, (name, _, _)| name == M5_EXPORT_ATTACHMENT_NAME);
                }
                FixtureMode::FalsePayload => {
                    payload.package_digest = ContentDigest::from_bytes(b"false-package-link");
                }
                FixtureMode::RecipeDivergence => {
                    let recipe = attachments
                        .iter()
                        .find(|(_, (_, media, _))| media == M5_RECIPE_ATTACHMENT_MEDIA_TYPE)
                        .map(|(digest, _)| digest.clone())
                        .expect("recipe attachment");
                    let (_, _, mut bytes) = attachments.remove(&recipe).expect("recipe");
                    bytes.extend_from_slice(b"\n;; divergent");
                    let digest = ContentDigest::from_bytes(&bytes);
                    attachments.insert(
                        digest.clone(),
                        (
                            m5_recipe_attachment_name(&digest),
                            M5_RECIPE_ATTACHMENT_MEDIA_TYPE.to_string(),
                            bytes,
                        ),
                    );
                }
            }
            let descriptors = attachments
                .iter()
                .map(
                    |(digest, (logical_name, media_type, bytes))| AttachmentDescriptor {
                        byte_length: bytes.len() as u64,
                        content_digest: digest.clone(),
                        logical_name: logical_name.clone(),
                        media_type: media_type.clone(),
                    },
                )
                .collect::<Vec<_>>();
            let mut descriptors = descriptors;
            descriptors.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
            let unsigned = UnsignedManifest {
                attachments: descriptors,
                canonical_encoding_version: CANONICAL_ENCODING_VERSION,
                expires_at_ms: 60_000,
                issued_at_ms: 100,
                kind: ManifestKind::Export,
                nonce: format!("{:032x}", TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)),
                origin_role: RouteEndpointRole::Sender,
                origin_signing_key_id: self.sender_signer.signing_key_id().to_string(),
                payload: ManifestPayload::Export(payload),
                policy_digest: self.route.exchange_policy_digest.clone(),
                previous_message_digest: None,
                receiver_identity_document_digest: self
                    .route
                    .receiver
                    .identity_document_digest
                    .clone(),
                resource_profile_digest: self.route.resource_profile.profile_digest.clone(),
                route_generation: self.route.generation,
                route_id: self.route.route_id.clone(),
                schema: SIGNED_MANIFEST_SCHEMA.to_string(),
                sender_identity_document_digest: self.route.sender.identity_document_digest.clone(),
                sequence: 1,
            };
            IssuedManifest {
                attachments: attachments
                    .into_iter()
                    .map(|(digest, (_, _, bytes))| (digest, bytes))
                    .collect(),
                manifest: SignedManifest::sign(unsigned, &self.sender_signer)
                    .expect("sign fixture manifest"),
            }
        }

        fn commit(&self, mode: FixtureMode) -> CommittedRawQuarantineUnit {
            let issued = self.issue(source_export_bytes(), mode);
            let sender_owner = self.sender_spool.acquire_role().expect("sender role");
            let message = self
                .sender_spool
                .publish(&sender_owner, &issued)
                .expect("publish fixture");
            drop(sender_owner);
            let receiver_owner = self.receiver_spool.acquire_role().expect("receiver role");
            let record = self
                .receiver_quarantine
                .quarantine_ready(
                    &self.receiver_spool,
                    &receiver_owner,
                    &message,
                    &format!("intake:{}", TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)),
                )
                .expect("raw quarantine fixture");
            drop(receiver_owner);
            self.receiver_quarantine
                .read_committed_unit(&record)
                .expect("reopen committed raw unit")
        }

        fn verified(
            &self,
            mode: FixtureMode,
        ) -> Result<VerifiedQuarantinedExportV1, M6ImportError> {
            let committed = self.commit(mode);
            verify_quarantined_export(&self.route, &self.policy, &committed)
        }
    }

    #[derive(Clone, Copy)]
    enum FixtureMode {
        Exact,
        BundleOnly,
        FalsePayload,
        RecipeDivergence,
    }

    fn exact_fixture_attachments(
        bundle: &M5ExportBundleV1,
        bundle_bytes: Vec<u8>,
    ) -> BTreeMap<ContentDigest, (String, String, Vec<u8>)> {
        let bundle_digest = ContentDigest::from_bytes(&bundle_bytes);
        let mut attachments = BTreeMap::from([(
            bundle_digest,
            (
                M5_EXPORT_ATTACHMENT_NAME.to_string(),
                M5_EXPORT_ATTACHMENT_MEDIA_TYPE.to_string(),
                bundle_bytes,
            ),
        )]);
        for exported in
            std::iter::once(bundle.active_package()).chain(bundle.referenced_packages().iter())
        {
            let package_bytes = exported.canonical_package_bytes().to_vec();
            let package_digest = ContentDigest::from_bytes(&package_bytes);
            attachments.insert(
                package_digest.clone(),
                (
                    m5_package_attachment_name(&package_digest),
                    M5_PACKAGE_ATTACHMENT_MEDIA_TYPE.to_string(),
                    package_bytes,
                ),
            );
            let recipe_bytes = exported.recipe_wat_bytes().to_vec();
            let recipe_digest = ContentDigest::from_bytes(&recipe_bytes);
            attachments.entry(recipe_digest.clone()).or_insert_with(|| {
                (
                    m5_recipe_attachment_name(&recipe_digest),
                    M5_RECIPE_ATTACHMENT_MEDIA_TYPE.to_string(),
                    recipe_bytes,
                )
            });
        }
        attachments
    }

    #[test]
    fn route_profile_caps_receiver_policy_and_proving_suite_at_boundary_plus_one() {
        let rig = ImportRig::new("route-policy-bounds", receiver_suite());
        let receiver = receiver_package();
        assert_eq!(
            rig.policy.resource_profile_digest,
            rig.route.resource_profile.profile_digest
        );

        let boundary_cases = (0..rig.route.resource_profile.max_proving_cases)
            .map(|index| {
                ValidationCase::returns(
                    format!("case:{index}"),
                    i32::try_from(index).expect("case input"),
                    i32::try_from(index).expect("case output"),
                )
            })
            .collect();
        let boundary_suite = ValidationSuite::new(
            "m6-route-proving-boundary",
            REFERENCE_EXPORT,
            boundary_cases,
            crate::execution::component::ComponentExecutionLimits {
                fuel: rig.route.resource_profile.max_proving_fuel,
                max_memory_bytes: rig.route.resource_profile.max_proving_memory_bytes,
                max_instances: rig.route.resource_profile.max_proving_instances,
                ..crate::execution::component::ComponentExecutionLimits::default()
            },
        )
        .expect("suite at route boundaries");
        ReceiverImportPolicyV1::for_route(
            "policy:proving-boundary",
            &rig.route,
            &receiver,
            &boundary_suite,
            ReceiverImportLimitsV1::bounded_default(),
            false,
        )
        .expect("all exact route boundaries");

        let mut evidence_plus_one = ReceiverImportLimitsV1::bounded_default();
        evidence_plus_one.max_evidence_bytes = rig.route.resource_profile.max_evidence_bytes + 1;
        assert!(matches!(
            ReceiverImportPolicyV1::for_route(
                "policy:evidence-plus-one",
                &rig.route,
                &receiver,
                &rig.suite,
                evidence_plus_one,
                false,
            ),
            Err(M6ImportError::InvalidPolicy(_))
        ));

        let over_fuel_suite = ValidationSuite::new(
            "m6-over-route-fuel",
            REFERENCE_EXPORT,
            vec![ValidationCase::returns("case:one", 1, 2)],
            crate::execution::component::ComponentExecutionLimits {
                fuel: rig.route.resource_profile.max_proving_fuel + 1,
                ..crate::execution::component::ComponentExecutionLimits::default()
            },
        )
        .expect("suite within M1 hard structure");
        let mut over_fuel_limits = ReceiverImportLimitsV1::bounded_default();
        over_fuel_limits.max_proving_fuel = rig.route.resource_profile.max_proving_fuel + 1;
        assert!(matches!(
            ReceiverImportPolicyV1::for_route(
                "policy:fuel-plus-one",
                &rig.route,
                &receiver,
                &over_fuel_suite,
                over_fuel_limits,
                false,
            ),
            Err(M6ImportError::InvalidPolicy(_))
        ));

        let over_memory_suite = ValidationSuite::new(
            "m6-over-route-memory",
            REFERENCE_EXPORT,
            vec![ValidationCase::returns("case:one", 1, 2)],
            crate::execution::component::ComponentExecutionLimits {
                max_memory_bytes: rig.route.resource_profile.max_proving_memory_bytes + 1,
                ..crate::execution::component::ComponentExecutionLimits::default()
            },
        )
        .expect("suite within M1 hard structure");
        let mut over_memory_limits = ReceiverImportLimitsV1::bounded_default();
        over_memory_limits.max_proving_memory_bytes =
            rig.route.resource_profile.max_proving_memory_bytes + 1;
        assert!(matches!(
            ReceiverImportPolicyV1::for_route(
                "policy:memory-plus-one",
                &rig.route,
                &receiver,
                &over_memory_suite,
                over_memory_limits,
                false,
            ),
            Err(M6ImportError::InvalidPolicy(_))
        ));

        let over_instances_suite = ValidationSuite::new(
            "m6-over-route-instances",
            REFERENCE_EXPORT,
            vec![ValidationCase::returns("case:one", 1, 2)],
            crate::execution::component::ComponentExecutionLimits {
                max_instances: rig.route.resource_profile.max_proving_instances + 1,
                ..crate::execution::component::ComponentExecutionLimits::default()
            },
        )
        .expect("suite within M1 hard structure");
        let mut over_instances_limits = ReceiverImportLimitsV1::bounded_default();
        over_instances_limits.max_proving_instances =
            rig.route.resource_profile.max_proving_instances + 1;
        assert!(matches!(
            ReceiverImportPolicyV1::for_route(
                "policy:instances-plus-one",
                &rig.route,
                &receiver,
                &over_instances_suite,
                over_instances_limits,
                false,
            ),
            Err(M6ImportError::InvalidPolicy(_))
        ));

        let over_case_count = rig.route.resource_profile.max_proving_cases + 1;
        let over_case_suite = ValidationSuite::new(
            "m6-over-route-cases",
            REFERENCE_EXPORT,
            (0..over_case_count)
                .map(|index| {
                    ValidationCase::returns(
                        format!("case:{index}"),
                        i32::try_from(index).expect("case input"),
                        i32::try_from(index).expect("case output"),
                    )
                })
                .collect(),
            crate::execution::component::ComponentExecutionLimits::default(),
        )
        .expect("suite within M1 hard case count");
        let mut over_case_limits = ReceiverImportLimitsV1::bounded_default();
        over_case_limits.max_proving_cases = over_case_count;
        assert!(matches!(
            ReceiverImportPolicyV1::for_route(
                "policy:cases-plus-one",
                &rig.route,
                &receiver,
                &over_case_suite,
                over_case_limits,
                false,
            ),
            Err(M6ImportError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn package_bytes_accept_exact_policy_boundary_and_reject_boundary_plus_one() {
        let rig = ImportRig::new("package-byte-boundary", receiver_suite());
        let committed = rig.commit(FixtureMode::Exact);
        let bundle =
            M5ExportBundleV1::from_canonical_bytes(&source_export_bytes()).expect("source export");
        let package_bytes = u64::try_from(bundle.active_package().canonical_package_bytes().len())
            .expect("package length");
        assert!(package_bytes > 1);

        let mut exact_limits = ReceiverImportLimitsV1::bounded_default();
        exact_limits.max_package_bytes = package_bytes;
        let exact_policy = ReceiverImportPolicyV1::for_route(
            "policy:package-exact",
            &rig.route,
            &receiver_package(),
            &rig.suite,
            exact_limits,
            false,
        )
        .expect("exact package-byte policy");
        verify_quarantined_export(&rig.route, &exact_policy, &committed)
            .expect("package at exact byte boundary");

        let mut one_too_small = ReceiverImportLimitsV1::bounded_default();
        one_too_small.max_package_bytes = package_bytes - 1;
        let one_too_small_policy = ReceiverImportPolicyV1::for_route(
            "policy:package-plus-one",
            &rig.route,
            &receiver_package(),
            &rig.suite,
            one_too_small,
            false,
        )
        .expect("one-byte-smaller package policy");
        assert!(matches!(
            verify_quarantined_export(&rig.route, &one_too_small_policy, &committed),
            Err(M6ImportError::ResourceBound(_))
        ));
    }

    #[test]
    fn exact_quarantine_proving_plan_and_all_restart_records_validate() {
        let rig = ImportRig::new("positive-restart", receiver_suite());
        let verified = rig.verified(FixtureMode::Exact).expect("verify import");
        let compatibility = assess_receiver_compatibility(&verified, &rig.active, &rig.policy)
            .expect("compatibility");
        assert!(compatibility.compatible());
        let proving = prove_quarantined_import(
            &verified,
            &rig.active,
            &rig.policy,
            &compatibility,
            &rig.suite,
        )
        .expect("receiver proving");
        assert!(proving.accepted());
        let plan = derive_receiver_import_plan(
            &verified,
            &rig.active,
            &rig.policy,
            &compatibility,
            &proving,
            &rig.suite,
        )
        .expect("derive import plan");
        let source = FactoryPackage::from_canonical_bytes(&plan.source_package_bytes)
            .expect("source package in plan");
        let local = FactoryPackage::from_canonical_bytes(&plan.receiver_local_package_bytes)
            .expect("local package in plan");
        assert!(
            plan.receiver_local_package_bytes() == plan.receiver_local_package_bytes.as_slice(),
            "receiver-local package accessor changed exact bytes (package_bytes={})",
            plan.receiver_local_package_bytes.len()
        );
        assert_eq!(
            plan.source_recipe_wat_bytes(),
            plan.source_recipe_wat_bytes.as_slice()
        );
        assert_eq!(
            source.payload.genome.component_bytes,
            local.payload.genome.component_bytes
        );
        assert_ne!(source.package_digest, local.package_digest);

        let policy_bytes = rig.policy.canonical_bytes().expect("policy bytes");
        let reopened_policy =
            ReceiverImportPolicyV1::from_canonical_bytes(&policy_bytes).expect("reopen policy");
        let active_bytes = rig.active.canonical_bytes().expect("active bytes");
        let reopened_active =
            ReceiverActiveStateV1::from_canonical_bytes(&active_bytes).expect("reopen active");
        let verified_bytes = verified
            .canonical_bytes(&rig.route, &reopened_policy)
            .expect("verified bytes");
        let reopened_verified = VerifiedQuarantinedExportV1::from_canonical_bytes(
            &verified_bytes,
            &rig.route,
            &reopened_policy,
        )
        .expect("reopen verified export");
        let decision_bytes = compatibility
            .canonical_bytes(&reopened_verified, &reopened_active, &reopened_policy)
            .expect("decision bytes");
        let reopened_decision = ReceiverCompatibilityDecisionV1::from_canonical_bytes(
            &decision_bytes,
            &reopened_verified,
            &reopened_active,
            &reopened_policy,
        )
        .expect("reopen compatibility");
        let proving_bytes = proving
            .canonical_bytes(
                &reopened_verified,
                &reopened_active,
                &reopened_policy,
                &reopened_decision,
                &rig.suite,
            )
            .expect("proving bytes");
        let reopened_proving = ReceiverProvingReportV1::from_canonical_bytes(
            &proving_bytes,
            &reopened_verified,
            &reopened_active,
            &reopened_policy,
            &reopened_decision,
            &rig.suite,
        )
        .expect("reopen proving");
        let plan_bytes = plan
            .canonical_bytes(
                &reopened_verified,
                &reopened_active,
                &reopened_policy,
                &reopened_decision,
                &reopened_proving,
                &rig.suite,
            )
            .expect("plan bytes");
        ReceiverImportPlanV1::from_canonical_bytes(
            &plan_bytes,
            &reopened_verified,
            &reopened_active,
            &reopened_policy,
            &reopened_decision,
            &reopened_proving,
            &rig.suite,
        )
        .expect("reopen plan");
    }

    #[test]
    fn missing_package_recipe_closure_fails_before_compatibility() {
        let rig = ImportRig::new("missing-closure", receiver_suite());
        assert!(matches!(
            rig.verified(FixtureMode::BundleOnly),
            Err(M6ImportError::MissingEvidence(_))
        ));
    }

    #[test]
    fn signed_false_package_link_is_rejected() {
        let rig = ImportRig::new("false-package-link", receiver_suite());
        assert!(matches!(
            rig.verified(FixtureMode::FalsePayload),
            Err(M6ImportError::FalseLink(_))
        ));
    }

    #[test]
    fn divergent_recipe_attachment_is_rejected() {
        let rig = ImportRig::new("recipe-divergence", receiver_suite());
        assert!(matches!(
            rig.verified(FixtureMode::RecipeDivergence),
            Err(M6ImportError::MissingEvidence(_))
                | Err(M6ImportError::FalseLink(_))
                | Err(M6ImportError::Integrity(_))
        ));
    }

    #[test]
    fn public_interface_policy_builder_reseals_and_drives_a_real_negative_control() {
        let rig = ImportRig::new("public-interface-policy-builder", receiver_suite());
        let original_policy_digest = rig.policy.policy_digest().clone();
        let required_interface = ContentDigest::from_bytes(b"operator-pinned-interface");
        let policy = rig
            .policy
            .clone()
            .with_required_interface_digest(required_interface.clone())
            .expect("operator-pinned interface policy");
        assert_eq!(policy.required_interface_digest, required_interface);
        assert_ne!(policy.policy_digest(), &original_policy_digest);
        policy.validate().expect("resealed policy validates");

        let policy_bytes = policy.canonical_bytes().expect("policy bytes");
        assert_eq!(
            ReceiverImportPolicyV1::from_canonical_bytes(&policy_bytes)
                .expect("reopen operator policy"),
            policy
        );

        let verified = rig.verified(FixtureMode::Exact).expect("verified source");
        let decision = assess_receiver_compatibility(&verified, &rig.active, &policy)
            .expect("negative-control compatibility");
        assert!(!decision.compatible());
        assert!(
            decision
                .issues()
                .contains(&ReceiverCompatibilityIssue::InterfaceMismatch)
        );

        assert!(matches!(
            rig.policy
                .clone()
                .with_required_interface_digest(ContentDigest::from_bytes(&[])),
            Err(M6ImportError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn capability_and_interface_policy_mismatches_are_typed_incompatible() {
        let rig = ImportRig::new("compatibility-mismatch", receiver_suite());
        let verified = rig.verified(FixtureMode::Exact).expect("verified");
        let mut policy = rig.policy.clone();
        policy.required_interface_digest = ContentDigest::from_bytes(b"different-interface");
        policy.required_worker_catalog_digest = ContentDigest::from_bytes(b"different-workers");
        policy.required_service_catalog_digest = ContentDigest::from_bytes(b"different-services");
        policy.policy_digest = policy.expected_digest().expect("reseal policy");
        let decision = assess_receiver_compatibility(&verified, &rig.active, &policy)
            .expect("negative compatibility evidence");
        assert!(!decision.compatible());
        assert!(
            decision
                .issues()
                .contains(&ReceiverCompatibilityIssue::InterfaceMismatch)
        );
        assert!(
            decision
                .issues()
                .contains(&ReceiverCompatibilityIssue::WorkerCapabilityMismatch)
        );
        assert!(
            decision
                .issues()
                .contains(&ReceiverCompatibilityIssue::ServiceCapabilityMismatch)
        );
        assert!(matches!(
            prove_quarantined_import(&verified, &rig.active, &policy, &decision, &rig.suite,),
            Err(M6ImportError::Incompatible(_))
        ));
    }

    #[test]
    fn real_receiver_proving_failure_cannot_derive_a_plan() {
        let rig = ImportRig::new("proving-rejection", rejecting_suite());
        let verified = rig.verified(FixtureMode::Exact).expect("verified");
        let compatibility =
            assess_receiver_compatibility(&verified, &rig.active, &rig.policy).expect("compatible");
        let proving = prove_quarantined_import(
            &verified,
            &rig.active,
            &rig.policy,
            &compatibility,
            &rig.suite,
        )
        .expect("negative proving record");
        assert!(!proving.accepted());
        assert!(matches!(
            derive_receiver_import_plan(
                &verified,
                &rig.active,
                &rig.policy,
                &compatibility,
                &proving,
                &rig.suite,
            ),
            Err(M6ImportError::ProvingRejected)
        ));
    }

    #[test]
    fn cross_message_proving_report_cannot_bind_a_second_import() {
        let rig = ImportRig::new("cross-message", receiver_suite());
        let first = rig.verified(FixtureMode::Exact).expect("first");
        let first_compatibility = assess_receiver_compatibility(&first, &rig.active, &rig.policy)
            .expect("first compatibility");
        let first_proving = prove_quarantined_import(
            &first,
            &rig.active,
            &rig.policy,
            &first_compatibility,
            &rig.suite,
        )
        .expect("first proving");
        let second = rig.verified(FixtureMode::Exact).expect("second");
        let second_compatibility = assess_receiver_compatibility(&second, &rig.active, &rig.policy)
            .expect("second compatibility");
        assert_ne!(first.message_digest(), second.message_digest());
        assert!(matches!(
            derive_receiver_import_plan(
                &second,
                &rig.active,
                &rig.policy,
                &second_compatibility,
                &first_proving,
                &rig.suite,
            ),
            Err(M6ImportError::FalseLink(_))
        ));
    }

    #[test]
    fn tampered_canonical_plan_and_verified_export_fail_closed() {
        let rig = ImportRig::new("canonical-tamper", receiver_suite());
        let verified = rig.verified(FixtureMode::Exact).expect("verified");
        let compatibility = assess_receiver_compatibility(&verified, &rig.active, &rig.policy)
            .expect("compatibility");
        let proving = prove_quarantined_import(
            &verified,
            &rig.active,
            &rig.policy,
            &compatibility,
            &rig.suite,
        )
        .expect("proving");
        let plan = derive_receiver_import_plan(
            &verified,
            &rig.active,
            &rig.policy,
            &compatibility,
            &proving,
            &rig.suite,
        )
        .expect("plan");

        let mut verified_bytes = verified
            .canonical_bytes(&rig.route, &rig.policy)
            .expect("verified bytes");
        let index = verified_bytes.len() / 2;
        verified_bytes[index] ^= 1;
        assert!(
            VerifiedQuarantinedExportV1::from_canonical_bytes(
                &verified_bytes,
                &rig.route,
                &rig.policy,
            )
            .is_err()
        );

        let mut plan_bytes = plan
            .canonical_bytes(
                &verified,
                &rig.active,
                &rig.policy,
                &compatibility,
                &proving,
                &rig.suite,
            )
            .expect("plan bytes");
        let index = plan_bytes.len() / 2;
        plan_bytes[index] ^= 1;
        assert!(
            ReceiverImportPlanV1::from_canonical_bytes(
                &plan_bytes,
                &verified,
                &rig.active,
                &rig.policy,
                &compatibility,
                &proving,
                &rig.suite,
            )
            .is_err()
        );
    }
}
