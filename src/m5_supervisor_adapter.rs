//! Durable, exact M2 authorization and decision records for the local M5 loop.
//!
//! The reproduction engine's [`M2SupervisorPort`] request contains content
//! digests rather than the challenger bytes themselves. This adapter therefore
//! accepts and validates the complete canonical [`FactoryPackage`] and component
//! bytes before a cycle runs. An approval request can match that authorization
//! only by the cycle id and the SHA-256 identities of those exact bytes.
//!
//! Generation-zero initialization has its own authority boundary. The operator
//! record binds the exact incumbent, initial-state digest/schema, and runtime
//! manifest before an actual `FactoryInitialize` request can consume it. The
//! consumption is immutable and yields the content-bound approval reference
//! carried by M3.
//!
//! Authorizations and decisions are separate immutable records. Replaying an
//! exact decided request returns the persisted decision without reopening the
//! supervisor. An undecided request is submitted to [`LocalDurableSupervisor`]
//! under deterministic job and idempotency identities, resolved once, and then
//! sealed as an immutable decision. The supervisor's own durable idempotency
//! makes a retry safe if the process stops between supervisor resolution and
//! decision publication.

use crate::execution::artifact::ContentDigest;
use crate::factory_reproduction::{
    ApprovalDecision, FactoryPackage, M2SupervisorPort, PortFailure, SupervisorApprovalRecord,
    SupervisorApprovalRequest,
};
use crate::m5_effect_store::FactoryInitializeRequest;
use crate::supervisor::{
    ApprovalResolutionKind, ApprovalResolutionRecord, LocalDurableSupervisor, RetryPolicy,
    SubmitJobRequest, SupervisorError, SystemSupervisorClock,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

const PACKAGE_AUTHORIZATION_SCHEMA: &str = "wasm-biotic.m5-package-authorization.v1";
const SUPERVISOR_DECISION_SCHEMA: &str = "wasm-biotic.m5-supervisor-decision.v1";
const INITIALIZATION_AUTHORIZATION_SCHEMA: &str = "wasm-biotic.m5-initialization-authorization.v1";
const INITIALIZATION_CONSUMPTION_SCHEMA: &str = "wasm-biotic.m5-initialization-consumption.v1";
const OPERATOR_ROLLBACK_AUTHORIZATION_SCHEMA: &str =
    "wasm-biotic.m5-operator-rollback-authorization.v1";
const PACKAGE_AUTHORIZATIONS_DIRECTORY: &str = "package-authorizations";
const DECISIONS_DIRECTORY: &str = "decisions";
const INITIALIZATION_AUTHORIZATIONS_DIRECTORY: &str = "initialization-authorizations";
const INITIALIZATION_CONSUMPTIONS_DIRECTORY: &str = "initialization-consumptions";
const ROLLBACK_AUTHORIZATIONS_DIRECTORY: &str = "rollback-authorizations";
const SUPERVISOR_DIRECTORY: &str = "supervisor-runtime";
const OWNER_LOCK_FILE: &str = "m5-supervisor-adapter.lock";
const TEMPORARY_FILE_PREFIX: &str = ".m5-supervisor-write-";
const M5_APPROVAL_JOB_KIND: &str = "m5.factory.approval";
const MAX_RECORDS_PER_KIND: usize = 4_096;
const MAX_PACKAGE_AUTHORIZATION_BYTES: usize = 20 * 1_048_576;
const MAX_DECISION_BYTES: usize = 1_048_576;
const MAX_INITIALIZATION_AUTHORIZATION_BYTES: usize = 20 * 1_048_576;
const MAX_INITIALIZATION_CONSUMPTION_BYTES: usize = 32 * 1_048_576;
const MAX_ROLLBACK_AUTHORIZATION_BYTES: usize = 40 * 1_048_576;
const MAX_RATIONALE_BYTES: usize = 4_096;

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Exact operator authority for the one generation-zero initialization of a
/// local factory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M5InitializationAuthorizationRequest {
    pub factory_id: String,
    pub incumbent_package_bytes: Vec<u8>,
    pub incumbent_component_bytes: Vec<u8>,
    pub initial_state_schema: u32,
    pub initial_state_bytes_digest: ContentDigest,
    pub manifest_digest: ContentDigest,
    pub operator_ref: String,
    pub rationale: String,
}

/// Immutable initialization authority. The canonical package retains the
/// exact component bytes and makes every recorded identity re-derivable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5InitializationAuthorizationRecord {
    pub schema: String,
    pub factory_id: String,
    pub incumbent_package: FactoryPackage,
    pub incumbent_package_digest: ContentDigest,
    pub incumbent_package_bytes_digest: ContentDigest,
    pub incumbent_component_digest: ContentDigest,
    pub incumbent_component_bytes_digest: ContentDigest,
    pub initial_state_schema: u32,
    pub initial_state_bytes_digest: ContentDigest,
    pub manifest_digest: ContentDigest,
    pub operator_ref: String,
    pub rationale: String,
    pub authorization_digest: ContentDigest,
}

impl M5InitializationAuthorizationRecord {
    fn from_request(
        request: M5InitializationAuthorizationRequest,
    ) -> Result<Self, M5SupervisorAdapterError> {
        validate_identifier("initialization factory id", &request.factory_id)?;
        validate_identifier("initialization operator ref", &request.operator_ref)?;
        validate_rationale(&request.rationale)?;
        validate_nonempty_content_digest(
            "initial state bytes",
            &request.initial_state_bytes_digest,
        )?;
        validate_nonempty_content_digest("M5 manifest", &request.manifest_digest)?;
        let incumbent_package = parse_exact_package(
            "initialization incumbent package",
            &request.incumbent_package_bytes,
            &request.incumbent_component_bytes,
        )?;
        if let Some(issue) = initialization_package_issue(
            &incumbent_package,
            &request.factory_id,
            request.initial_state_schema,
        ) {
            return Err(M5SupervisorAdapterError::InvalidRequest(issue));
        }
        let incumbent_package_bytes = incumbent_package
            .canonical_bytes()
            .map_err(|error| M5SupervisorAdapterError::InvalidRequest(error.to_string()))?;
        let mut record = Self {
            schema: INITIALIZATION_AUTHORIZATION_SCHEMA.to_string(),
            factory_id: request.factory_id,
            incumbent_package_digest: incumbent_package.package_digest.clone(),
            incumbent_package_bytes_digest: ContentDigest::from_bytes(&incumbent_package_bytes),
            incumbent_component_digest: incumbent_package.payload.genome.component_digest.clone(),
            incumbent_component_bytes_digest: ContentDigest::from_bytes(
                &incumbent_package.payload.genome.component_bytes,
            ),
            incumbent_package,
            initial_state_schema: request.initial_state_schema,
            initial_state_bytes_digest: request.initial_state_bytes_digest,
            manifest_digest: request.manifest_digest,
            operator_ref: request.operator_ref,
            rationale: request.rationale,
            authorization_digest: empty_digest(),
        };
        record.authorization_digest = record.expected_digest()?;
        record.validate()?;
        Ok(record)
    }

    /// Re-derive the exact generation-zero package, component, state binding,
    /// manifest binding, and immutable operator authority.
    pub fn validate(&self) -> Result<(), M5SupervisorAdapterError> {
        if self.schema != INITIALIZATION_AUTHORIZATION_SCHEMA {
            return Err(M5SupervisorAdapterError::Integrity(format!(
                "unsupported initialization authorization schema {:?}",
                self.schema
            )));
        }
        validate_identifier("initialization factory id", &self.factory_id)?;
        validate_identifier("initialization operator ref", &self.operator_ref)?;
        validate_rationale(&self.rationale)?;
        self.incumbent_package.validate().map_err(|error| {
            M5SupervisorAdapterError::Integrity(format!(
                "initialization incumbent package is invalid: {error}"
            ))
        })?;
        if let Some(issue) = initialization_package_issue(
            &self.incumbent_package,
            &self.factory_id,
            self.initial_state_schema,
        ) {
            return Err(M5SupervisorAdapterError::Integrity(issue));
        }
        validate_package_identity(
            "initialization incumbent",
            &self.incumbent_package,
            &self.incumbent_package_digest,
            &self.incumbent_package_bytes_digest,
            &self.incumbent_component_digest,
            &self.incumbent_component_bytes_digest,
        )?;
        validate_nonempty_content_digest("initial state bytes", &self.initial_state_bytes_digest)
            .map_err(|error| M5SupervisorAdapterError::Integrity(error.to_string()))?;
        validate_nonempty_content_digest("M5 manifest", &self.manifest_digest)
            .map_err(|error| M5SupervisorAdapterError::Integrity(error.to_string()))?;
        require_digest(
            "initialization authorization",
            &self.expected_digest()?,
            &self.authorization_digest,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5SupervisorAdapterError> {
        digest_serializable(&(
            "wasm-biotic:m5-initialization-authorization:v1",
            &self.factory_id,
            &self.incumbent_package_digest,
            &self.incumbent_package_bytes_digest,
            &self.incumbent_component_digest,
            &self.incumbent_component_bytes_digest,
            self.initial_state_schema,
            &self.initial_state_bytes_digest,
            &self.manifest_digest,
            &self.operator_ref,
            &self.rationale,
        ))
    }

    pub fn authorization_ref(&self) -> String {
        self.authorization_digest.to_string()
    }
}

/// The exact initialization effect presented when consuming operator authority.
///
/// `initialize_request` carries the operation id, canonical package bytes, and
/// actual state bytes. The component is repeated so a caller cannot authorize
/// a package while presenting different executable bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M5InitializationExecutionRequest {
    pub initialize_request: FactoryInitializeRequest,
    pub incumbent_component_bytes: Vec<u8>,
    pub manifest_digest: ContentDigest,
}

/// Immutable evidence that one exact initialization authority was consumed for
/// one exact [`FactoryInitializeRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5InitializationConsumptionRecord {
    pub schema: String,
    pub factory_id: String,
    pub initialize_request: FactoryInitializeRequest,
    pub incumbent_package_digest: ContentDigest,
    pub incumbent_package_bytes_digest: ContentDigest,
    pub incumbent_component_digest: ContentDigest,
    pub incumbent_component_bytes_digest: ContentDigest,
    pub initial_state_schema: u32,
    pub initial_state_bytes_digest: ContentDigest,
    pub manifest_digest: ContentDigest,
    pub authorization_digest: ContentDigest,
    pub consumption_digest: ContentDigest,
}

impl M5InitializationConsumptionRecord {
    fn from_request(
        request: M5InitializationExecutionRequest,
        authorization: &M5InitializationAuthorizationRecord,
    ) -> Result<Self, M5SupervisorAdapterError> {
        validate_initialize_request(&request.initialize_request)?;
        let incumbent_package = parse_exact_package(
            "consumed initialization package",
            &request.initialize_request.package_bytes,
            &request.incumbent_component_bytes,
        )?;
        let initial_state_bytes_digest =
            ContentDigest::from_bytes(&request.initialize_request.initial_state_bytes);
        if request.initialize_request.factory_id != authorization.factory_id
            || incumbent_package != authorization.incumbent_package
            || request.initialize_request.initial_state_schema != authorization.initial_state_schema
            || initial_state_bytes_digest != authorization.initial_state_bytes_digest
            || request.manifest_digest != authorization.manifest_digest
        {
            return Err(M5SupervisorAdapterError::Conflict(format!(
                "factory {:?} initialization effect differs from its exact operator authority",
                request.initialize_request.factory_id
            )));
        }
        let incumbent_package_bytes = incumbent_package
            .canonical_bytes()
            .map_err(|error| M5SupervisorAdapterError::InvalidRequest(error.to_string()))?;
        let mut record = Self {
            schema: INITIALIZATION_CONSUMPTION_SCHEMA.to_string(),
            factory_id: authorization.factory_id.clone(),
            initialize_request: request.initialize_request,
            incumbent_package_digest: incumbent_package.package_digest.clone(),
            incumbent_package_bytes_digest: ContentDigest::from_bytes(&incumbent_package_bytes),
            incumbent_component_digest: incumbent_package.payload.genome.component_digest.clone(),
            incumbent_component_bytes_digest: ContentDigest::from_bytes(
                &incumbent_package.payload.genome.component_bytes,
            ),
            initial_state_schema: authorization.initial_state_schema,
            initial_state_bytes_digest,
            manifest_digest: request.manifest_digest,
            authorization_digest: authorization.authorization_digest.clone(),
            consumption_digest: empty_digest(),
        };
        record.consumption_digest = record.expected_digest()?;
        record.validate(authorization)?;
        Ok(record)
    }

    fn validate(
        &self,
        authorization: &M5InitializationAuthorizationRecord,
    ) -> Result<(), M5SupervisorAdapterError> {
        if self.schema != INITIALIZATION_CONSUMPTION_SCHEMA {
            return Err(M5SupervisorAdapterError::Integrity(format!(
                "unsupported initialization consumption schema {:?}",
                self.schema
            )));
        }
        validate_identifier("initialization factory id", &self.factory_id)?;
        validate_initialize_request(&self.initialize_request)
            .map_err(|error| M5SupervisorAdapterError::Integrity(error.to_string()))?;
        let incumbent_package = FactoryPackage::from_canonical_bytes(
            &self.initialize_request.package_bytes,
        )
        .map_err(|error| {
            M5SupervisorAdapterError::Integrity(format!(
                "consumed initialization package is invalid: {error}"
            ))
        })?;
        validate_package_identity(
            "consumed initialization",
            &incumbent_package,
            &self.incumbent_package_digest,
            &self.incumbent_package_bytes_digest,
            &self.incumbent_component_digest,
            &self.incumbent_component_bytes_digest,
        )?;
        if self.factory_id != authorization.factory_id
            || self.initialize_request.factory_id != authorization.factory_id
            || incumbent_package != authorization.incumbent_package
            || self.incumbent_package_digest != authorization.incumbent_package_digest
            || self.incumbent_package_bytes_digest != authorization.incumbent_package_bytes_digest
            || self.incumbent_component_digest != authorization.incumbent_component_digest
            || self.incumbent_component_bytes_digest
                != authorization.incumbent_component_bytes_digest
            || self.initial_state_schema != authorization.initial_state_schema
            || self.initialize_request.initial_state_schema != self.initial_state_schema
            || self.initial_state_bytes_digest
                != ContentDigest::from_bytes(&self.initialize_request.initial_state_bytes)
            || self.initial_state_bytes_digest != authorization.initial_state_bytes_digest
            || self.manifest_digest != authorization.manifest_digest
            || self.authorization_digest != authorization.authorization_digest
        {
            return Err(M5SupervisorAdapterError::Integrity(
                "initialization consumption differs from its exact durable authority".to_string(),
            ));
        }
        require_digest(
            "initialization consumption",
            &self.expected_digest()?,
            &self.consumption_digest,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5SupervisorAdapterError> {
        digest_serializable(&(
            "wasm-biotic:m5-initialization-consumption:v1",
            &self.factory_id,
            &self.initialize_request,
            &self.incumbent_package_digest,
            &self.incumbent_package_bytes_digest,
            &self.incumbent_component_digest,
            &self.incumbent_component_bytes_digest,
            self.initial_state_schema,
            &self.initial_state_bytes_digest,
            &self.manifest_digest,
            &self.authorization_digest,
        ))
    }

    /// Opaque, content-bound reference accepted by the M3 FactoryInitialize
    /// capability invocation.
    pub fn approval_ref(&self) -> String {
        self.consumption_digest.to_string()
    }
}

/// Exact bytes and operator disposition authorized before one M5 cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M5PackageAuthorizationRequest {
    pub cycle_id: String,
    pub incumbent_package_digest: ContentDigest,
    pub challenger_package_bytes: Vec<u8>,
    pub challenger_component_bytes: Vec<u8>,
    pub decision: ApprovalDecision,
    pub approver_ref: String,
    pub rationale: String,
}

/// Immutable, fully re-derivable package authorization.
///
/// The package retains the exact component bytes. Its canonical representation
/// is the only accepted representation of `challenger_package_bytes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5PackageAuthorizationRecord {
    pub schema: String,
    pub cycle_id: String,
    pub incumbent_package_digest: ContentDigest,
    pub challenger_package: FactoryPackage,
    pub challenger_package_digest: ContentDigest,
    pub challenger_package_bytes_digest: ContentDigest,
    pub challenger_component_digest: ContentDigest,
    pub challenger_component_bytes_digest: ContentDigest,
    pub decision: ApprovalDecision,
    pub approver_ref: String,
    pub rationale: String,
    pub authorization_digest: ContentDigest,
}

impl M5PackageAuthorizationRecord {
    fn from_request(
        request: M5PackageAuthorizationRequest,
    ) -> Result<Self, M5SupervisorAdapterError> {
        validate_identifier("cycle id", &request.cycle_id)?;
        validate_identifier("approver ref", &request.approver_ref)?;
        validate_rationale(&request.rationale)?;
        let challenger_package = FactoryPackage::from_canonical_bytes(
            &request.challenger_package_bytes,
        )
        .map_err(|error| {
            M5SupervisorAdapterError::InvalidRequest(format!(
                "challenger package bytes are not one valid canonical package: {error}"
            ))
        })?;
        if challenger_package.payload.genome.component_bytes != request.challenger_component_bytes {
            return Err(M5SupervisorAdapterError::InvalidRequest(
                "challenger component bytes differ from the bytes embedded in the package"
                    .to_string(),
            ));
        }
        let package_bytes = challenger_package
            .canonical_bytes()
            .map_err(|error| M5SupervisorAdapterError::InvalidRequest(error.to_string()))?;
        let component_bytes = &challenger_package.payload.genome.component_bytes;
        let mut record = Self {
            schema: PACKAGE_AUTHORIZATION_SCHEMA.to_string(),
            cycle_id: request.cycle_id,
            incumbent_package_digest: request.incumbent_package_digest,
            challenger_package_digest: challenger_package.package_digest.clone(),
            challenger_package_bytes_digest: ContentDigest::from_bytes(&package_bytes),
            challenger_component_digest: challenger_package.payload.genome.component_digest.clone(),
            challenger_component_bytes_digest: ContentDigest::from_bytes(component_bytes),
            challenger_package,
            decision: request.decision,
            approver_ref: request.approver_ref,
            rationale: request.rationale,
            authorization_digest: empty_digest(),
        };
        record.authorization_digest = record.expected_digest()?;
        record.validate()?;
        Ok(record)
    }

    /// Re-derive the package, component, and record identities.
    pub fn validate(&self) -> Result<(), M5SupervisorAdapterError> {
        if self.schema != PACKAGE_AUTHORIZATION_SCHEMA {
            return Err(M5SupervisorAdapterError::Integrity(format!(
                "unsupported package authorization schema {:?}",
                self.schema
            )));
        }
        validate_identifier("cycle id", &self.cycle_id)?;
        validate_identifier("approver ref", &self.approver_ref)?;
        validate_rationale(&self.rationale)?;
        self.challenger_package.validate().map_err(|error| {
            M5SupervisorAdapterError::Integrity(format!(
                "authorized challenger package is invalid: {error}"
            ))
        })?;
        let package_bytes = self.challenger_package.canonical_bytes().map_err(|error| {
            M5SupervisorAdapterError::Integrity(format!(
                "authorized challenger package cannot be canonicalized: {error}"
            ))
        })?;
        require_digest(
            "authorized package record",
            &self.challenger_package.package_digest,
            &self.challenger_package_digest,
        )?;
        require_digest(
            "authorized package bytes",
            &ContentDigest::from_bytes(&package_bytes),
            &self.challenger_package_bytes_digest,
        )?;
        require_digest(
            "authorized component record",
            &self.challenger_package.payload.genome.component_digest,
            &self.challenger_component_digest,
        )?;
        require_digest(
            "authorized component bytes",
            &ContentDigest::from_bytes(&self.challenger_package.payload.genome.component_bytes),
            &self.challenger_component_bytes_digest,
        )?;
        require_digest(
            "package authorization",
            &self.expected_digest()?,
            &self.authorization_digest,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5SupervisorAdapterError> {
        digest_serializable(&(
            "wasm-biotic:m5-package-authorization:v1",
            &self.cycle_id,
            &self.incumbent_package_digest,
            &self.challenger_package_digest,
            &self.challenger_package_bytes_digest,
            &self.challenger_component_digest,
            &self.challenger_component_bytes_digest,
            self.decision,
            &self.approver_ref,
            &self.rationale,
        ))
    }

    /// Stable reference suitable for audit logs.
    pub fn authorization_ref(&self) -> String {
        self.authorization_digest.to_string()
    }
}

/// Immutable result of resolving one exact package authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5SupervisorDecisionRecord {
    pub schema: String,
    pub cycle_id: String,
    pub request: SupervisorApprovalRequest,
    pub authorization_digest: ContentDigest,
    pub approval: SupervisorApprovalRecord,
    pub decision_record_digest: ContentDigest,
}

impl M5SupervisorDecisionRecord {
    fn new(
        request: SupervisorApprovalRequest,
        authorization: &M5PackageAuthorizationRecord,
        approval: SupervisorApprovalRecord,
    ) -> Result<Self, M5SupervisorAdapterError> {
        let mut record = Self {
            schema: SUPERVISOR_DECISION_SCHEMA.to_string(),
            cycle_id: request.cycle_id.clone(),
            request,
            authorization_digest: authorization.authorization_digest.clone(),
            approval,
            decision_record_digest: empty_digest(),
        };
        record.decision_record_digest = record.expected_digest()?;
        record.validate(authorization)?;
        Ok(record)
    }

    fn validate(
        &self,
        authorization: &M5PackageAuthorizationRecord,
    ) -> Result<(), M5SupervisorAdapterError> {
        if self.schema != SUPERVISOR_DECISION_SCHEMA {
            return Err(M5SupervisorAdapterError::Integrity(format!(
                "unsupported supervisor decision schema {:?}",
                self.schema
            )));
        }
        validate_supervisor_request(&self.request)?;
        if self.cycle_id != self.request.cycle_id
            || self.cycle_id != authorization.cycle_id
            || self.authorization_digest != authorization.authorization_digest
        {
            return Err(M5SupervisorAdapterError::Integrity(
                "supervisor decision is not bound to its exact cycle authorization".to_string(),
            ));
        }
        match_request_to_authorization(&self.request, authorization)?;
        validate_approval(&self.approval, &self.request, authorization)?;
        require_digest(
            "supervisor decision record",
            &self.expected_digest()?,
            &self.decision_record_digest,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5SupervisorAdapterError> {
        digest_serializable(&(
            "wasm-biotic:m5-supervisor-decision:v1",
            &self.cycle_id,
            &self.request,
            &self.authorization_digest,
            &self.approval,
        ))
    }
}

/// Exact approved identity consumed by an M3 promotion effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5PromotionApprovalReference {
    pub cycle_id: String,
    pub supervisor_approval_id: String,
    pub approval_digest: ContentDigest,
    /// Matches the approval reference format currently used by M5 deployment.
    pub approval_ref: String,
    pub request_digest: ContentDigest,
    pub package_digest: ContentDigest,
    pub package_bytes_digest: ContentDigest,
    pub component_digest: ContentDigest,
    pub component_bytes_digest: ContentDigest,
    pub decision_record_digest: ContentDigest,
}

/// Exact packages and explicit operator authority for one rollback operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M5OperatorRollbackAuthorizationRequest {
    pub rollback_id: String,
    /// The cycle whose promoted package is being reverted.
    pub source_cycle_id: String,
    pub active_package_bytes: Vec<u8>,
    pub active_component_bytes: Vec<u8>,
    pub restore_package_bytes: Vec<u8>,
    pub restore_component_bytes: Vec<u8>,
    pub operator_ref: String,
    pub reason_ref: String,
    pub rationale: String,
}

/// Immutable rollback authority, kept separately from promotion decisions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5OperatorRollbackAuthorizationRecord {
    pub schema: String,
    pub rollback_id: String,
    pub source_cycle_id: String,
    pub active_package: FactoryPackage,
    pub active_package_digest: ContentDigest,
    pub active_package_bytes_digest: ContentDigest,
    pub active_component_digest: ContentDigest,
    pub active_component_bytes_digest: ContentDigest,
    pub restore_package: FactoryPackage,
    pub restore_package_digest: ContentDigest,
    pub restore_package_bytes_digest: ContentDigest,
    pub restore_component_digest: ContentDigest,
    pub restore_component_bytes_digest: ContentDigest,
    pub operator_ref: String,
    pub reason_ref: String,
    pub rationale: String,
    pub authorization_digest: ContentDigest,
}

impl M5OperatorRollbackAuthorizationRecord {
    fn from_request(
        request: M5OperatorRollbackAuthorizationRequest,
    ) -> Result<Self, M5SupervisorAdapterError> {
        validate_identifier("rollback id", &request.rollback_id)?;
        validate_identifier("rollback source cycle id", &request.source_cycle_id)?;
        validate_identifier("rollback operator ref", &request.operator_ref)?;
        validate_identifier("rollback reason ref", &request.reason_ref)?;
        validate_rationale(&request.rationale)?;
        let active_package = parse_exact_package(
            "active rollback package",
            &request.active_package_bytes,
            &request.active_component_bytes,
        )?;
        let restore_package = parse_exact_package(
            "restore rollback package",
            &request.restore_package_bytes,
            &request.restore_component_bytes,
        )?;
        validate_rollback_edge(&active_package, &restore_package)?;
        let active_package_bytes = active_package
            .canonical_bytes()
            .map_err(|error| M5SupervisorAdapterError::InvalidRequest(error.to_string()))?;
        let restore_package_bytes = restore_package
            .canonical_bytes()
            .map_err(|error| M5SupervisorAdapterError::InvalidRequest(error.to_string()))?;
        let mut record = Self {
            schema: OPERATOR_ROLLBACK_AUTHORIZATION_SCHEMA.to_string(),
            rollback_id: request.rollback_id,
            source_cycle_id: request.source_cycle_id,
            active_package_digest: active_package.package_digest.clone(),
            active_package_bytes_digest: ContentDigest::from_bytes(&active_package_bytes),
            active_component_digest: active_package.payload.genome.component_digest.clone(),
            active_component_bytes_digest: ContentDigest::from_bytes(
                &active_package.payload.genome.component_bytes,
            ),
            active_package,
            restore_package_digest: restore_package.package_digest.clone(),
            restore_package_bytes_digest: ContentDigest::from_bytes(&restore_package_bytes),
            restore_component_digest: restore_package.payload.genome.component_digest.clone(),
            restore_component_bytes_digest: ContentDigest::from_bytes(
                &restore_package.payload.genome.component_bytes,
            ),
            restore_package,
            operator_ref: request.operator_ref,
            reason_ref: request.reason_ref,
            rationale: request.rationale,
            authorization_digest: empty_digest(),
        };
        record.authorization_digest = record.expected_digest()?;
        record.validate()?;
        Ok(record)
    }

    /// Re-derive both packages, both components, their rollback edge, and the
    /// record digest.
    pub fn validate(&self) -> Result<(), M5SupervisorAdapterError> {
        if self.schema != OPERATOR_ROLLBACK_AUTHORIZATION_SCHEMA {
            return Err(M5SupervisorAdapterError::Integrity(format!(
                "unsupported rollback authorization schema {:?}",
                self.schema
            )));
        }
        validate_identifier("rollback id", &self.rollback_id)?;
        validate_identifier("rollback source cycle id", &self.source_cycle_id)?;
        validate_identifier("rollback operator ref", &self.operator_ref)?;
        validate_identifier("rollback reason ref", &self.reason_ref)?;
        validate_rationale(&self.rationale)?;
        self.active_package.validate().map_err(|error| {
            M5SupervisorAdapterError::Integrity(format!(
                "active rollback package is invalid: {error}"
            ))
        })?;
        self.restore_package.validate().map_err(|error| {
            M5SupervisorAdapterError::Integrity(format!(
                "restore rollback package is invalid: {error}"
            ))
        })?;
        validate_rollback_edge(&self.active_package, &self.restore_package)?;
        validate_package_identity(
            "active rollback",
            &self.active_package,
            &self.active_package_digest,
            &self.active_package_bytes_digest,
            &self.active_component_digest,
            &self.active_component_bytes_digest,
        )?;
        validate_package_identity(
            "restore rollback",
            &self.restore_package,
            &self.restore_package_digest,
            &self.restore_package_bytes_digest,
            &self.restore_component_digest,
            &self.restore_component_bytes_digest,
        )?;
        require_digest(
            "operator rollback authorization",
            &self.expected_digest()?,
            &self.authorization_digest,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5SupervisorAdapterError> {
        digest_serializable(&(
            "wasm-biotic:m5-operator-rollback-authorization:v1",
            &self.rollback_id,
            &self.source_cycle_id,
            &self.active_package_digest,
            &self.active_package_bytes_digest,
            &self.active_component_digest,
            &self.active_component_bytes_digest,
            &self.restore_package_digest,
            &self.restore_package_bytes_digest,
            &self.restore_component_digest,
            &self.restore_component_bytes_digest,
            &self.operator_ref,
            &self.reason_ref,
            &self.rationale,
        ))
    }

    pub fn authorization_ref(&self) -> String {
        self.authorization_digest.to_string()
    }
}

/// Exact bytes presented immediately before applying a governed rollback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M5OperatorRollbackExecutionRequest {
    pub rollback_id: String,
    pub source_cycle_id: String,
    pub active_package_bytes: Vec<u8>,
    pub active_component_bytes: Vec<u8>,
    pub restore_package_bytes: Vec<u8>,
    pub restore_component_bytes: Vec<u8>,
    pub reason_ref: String,
}

#[derive(Default)]
struct AdapterState {
    initialization_authorizations: BTreeMap<String, M5InitializationAuthorizationRecord>,
    initialization_consumptions: BTreeMap<String, M5InitializationConsumptionRecord>,
    authorizations: BTreeMap<String, M5PackageAuthorizationRecord>,
    decisions: BTreeMap<String, M5SupervisorDecisionRecord>,
    rollback_authorizations: BTreeMap<String, M5OperatorRollbackAuthorizationRecord>,
}

/// Sole-writer durable adapter between the M5 reproduction law and M2.
pub struct M5SupervisorAdapter {
    root: PathBuf,
    owner_id: String,
    initialization_authorizations_root: PathBuf,
    initialization_consumptions_root: PathBuf,
    package_authorizations_root: PathBuf,
    decisions_root: PathBuf,
    rollback_authorizations_root: PathBuf,
    supervisor_root: PathBuf,
    _owner_lock: File,
    state: Mutex<AdapterState>,
}

impl M5SupervisorAdapter {
    /// Open one local authorization namespace and validate every immutable
    /// record before making it available.
    pub fn open(
        root: impl AsRef<Path>,
        owner_id: impl Into<String>,
    ) -> Result<Self, M5SupervisorAdapterError> {
        let owner_id = owner_id.into();
        validate_owner_id(&owner_id)?;
        let root = secure_create_root(root.as_ref())?;
        let owner_lock = acquire_owner_lock(&root, &owner_id)?;
        let initialization_authorizations_root =
            secure_child_directory(&root, INITIALIZATION_AUTHORIZATIONS_DIRECTORY)?;
        let initialization_consumptions_root =
            secure_child_directory(&root, INITIALIZATION_CONSUMPTIONS_DIRECTORY)?;
        let package_authorizations_root =
            secure_child_directory(&root, PACKAGE_AUTHORIZATIONS_DIRECTORY)?;
        let decisions_root = secure_child_directory(&root, DECISIONS_DIRECTORY)?;
        let rollback_authorizations_root =
            secure_child_directory(&root, ROLLBACK_AUTHORIZATIONS_DIRECTORY)?;
        let supervisor_root = secure_child_directory(&root, SUPERVISOR_DIRECTORY)?;
        for directory in [
            &initialization_authorizations_root,
            &initialization_consumptions_root,
            &package_authorizations_root,
            &decisions_root,
            &rollback_authorizations_root,
        ] {
            cleanup_temporary_files(directory)?;
        }
        let state = load_state(
            &initialization_authorizations_root,
            &initialization_consumptions_root,
            &package_authorizations_root,
            &decisions_root,
            &rollback_authorizations_root,
        )?;
        Ok(Self {
            root,
            owner_id,
            initialization_authorizations_root,
            initialization_consumptions_root,
            package_authorizations_root,
            decisions_root,
            rollback_authorizations_root,
            supervisor_root,
            _owner_lock: owner_lock,
            state: Mutex::new(state),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Append exact generation-zero operator authority. An exact replay is
    /// idempotent; a factory id can never be rebound to different bytes,
    /// state, manifest, operator, or rationale.
    pub fn authorize_initialization(
        &self,
        request: M5InitializationAuthorizationRequest,
    ) -> Result<M5InitializationAuthorizationRecord, M5SupervisorAdapterError> {
        let record = M5InitializationAuthorizationRecord::from_request(request)?;
        let mut state = self.lock_state()?;
        if let Some(existing) = state.initialization_authorizations.get(&record.factory_id) {
            return if existing == &record {
                Ok(existing.clone())
            } else {
                Err(M5SupervisorAdapterError::Conflict(format!(
                    "factory {:?} already has different immutable initialization authority",
                    record.factory_id
                )))
            };
        }
        if state
            .initialization_consumptions
            .contains_key(&record.factory_id)
        {
            return Err(M5SupervisorAdapterError::Integrity(format!(
                "factory {:?} has an initialization consumption without its authority",
                record.factory_id
            )));
        }
        let path = self
            .initialization_authorizations_root
            .join(record_file_name(&record.factory_id));
        persist_json_immutable(
            &self.initialization_authorizations_root,
            &path,
            &record,
            MAX_INITIALIZATION_AUTHORIZATION_BYTES,
        )?;
        state
            .initialization_authorizations
            .insert(record.factory_id.clone(), record.clone());
        Ok(record)
    }

    pub fn initialization_authorization(
        &self,
        factory_id: &str,
    ) -> Result<Option<M5InitializationAuthorizationRecord>, M5SupervisorAdapterError> {
        validate_identifier("initialization factory id", factory_id)?;
        Ok(self
            .lock_state()?
            .initialization_authorizations
            .get(factory_id)
            .cloned())
    }

    pub fn initialization_consumption(
        &self,
        factory_id: &str,
    ) -> Result<Option<M5InitializationConsumptionRecord>, M5SupervisorAdapterError> {
        validate_identifier("initialization factory id", factory_id)?;
        Ok(self
            .lock_state()?
            .initialization_consumptions
            .get(factory_id)
            .cloned())
    }

    /// Require exact operator authority for an actual FactoryInitialize
    /// request, consume it durably, and return the opaque approval reference
    /// carried by the M3 invocation. Exact retries return the same reference;
    /// every changed execution conflicts.
    pub fn require_and_consume_initialization_authority(
        &self,
        request: M5InitializationExecutionRequest,
    ) -> Result<String, M5SupervisorAdapterError> {
        validate_initialize_request(&request.initialize_request)?;
        let factory_id = request.initialize_request.factory_id.clone();
        let mut state = self.lock_state()?;
        let authorization = state
            .initialization_authorizations
            .get(&factory_id)
            .cloned()
            .ok_or_else(
                || M5SupervisorAdapterError::InitializationAuthorizationMissing {
                    factory_id: factory_id.clone(),
                },
            )?;
        let record = M5InitializationConsumptionRecord::from_request(request, &authorization)?;
        if let Some(existing) = state.initialization_consumptions.get(&factory_id) {
            return if existing == &record {
                Ok(existing.approval_ref())
            } else {
                Err(M5SupervisorAdapterError::Conflict(format!(
                    "factory {factory_id:?} already consumed initialization authority for a different exact effect"
                )))
            };
        }
        let path = self
            .initialization_consumptions_root
            .join(record_file_name(&factory_id));
        persist_json_immutable(
            &self.initialization_consumptions_root,
            &path,
            &record,
            MAX_INITIALIZATION_CONSUMPTION_BYTES,
        )?;
        let approval_ref = record.approval_ref();
        state.initialization_consumptions.insert(factory_id, record);
        Ok(approval_ref)
    }

    /// Persist an exact authorization. Exact replays are idempotent; the cycle
    /// id can never be rebound to different input or a different disposition.
    pub fn authorize_package(
        &self,
        request: M5PackageAuthorizationRequest,
    ) -> Result<M5PackageAuthorizationRecord, M5SupervisorAdapterError> {
        let record = M5PackageAuthorizationRecord::from_request(request)?;
        let mut state = self.lock_state()?;
        if let Some(existing) = state.authorizations.get(&record.cycle_id) {
            return if existing == &record {
                Ok(existing.clone())
            } else {
                Err(M5SupervisorAdapterError::Conflict(format!(
                    "cycle {:?} already has a different immutable package authorization",
                    record.cycle_id
                )))
            };
        }
        if state.decisions.contains_key(&record.cycle_id) {
            return Err(M5SupervisorAdapterError::Integrity(format!(
                "cycle {:?} has a decision without its authorization",
                record.cycle_id
            )));
        }
        let path = self
            .package_authorizations_root
            .join(record_file_name(&record.cycle_id));
        persist_json_immutable(
            &self.package_authorizations_root,
            &path,
            &record,
            MAX_PACKAGE_AUTHORIZATION_BYTES,
        )?;
        state
            .authorizations
            .insert(record.cycle_id.clone(), record.clone());
        Ok(record)
    }

    pub fn package_authorization(
        &self,
        cycle_id: &str,
    ) -> Result<Option<M5PackageAuthorizationRecord>, M5SupervisorAdapterError> {
        validate_identifier("cycle id", cycle_id)?;
        Ok(self.lock_state()?.authorizations.get(cycle_id).cloned())
    }

    pub fn decision_for_cycle(
        &self,
        cycle_id: &str,
    ) -> Result<Option<M5SupervisorDecisionRecord>, M5SupervisorAdapterError> {
        validate_identifier("cycle id", cycle_id)?;
        Ok(self.lock_state()?.decisions.get(cycle_id).cloned())
    }

    /// Resolve an exact approval request or return its already-persisted exact
    /// decision without invoking the supervisor again.
    pub fn decide_authorized(
        &self,
        request: &SupervisorApprovalRequest,
    ) -> Result<SupervisorApprovalRecord, M5SupervisorAdapterError> {
        validate_supervisor_request(request)?;
        let mut state = self.lock_state()?;
        if let Some(existing) = state.decisions.get(&request.cycle_id) {
            if &existing.request == request {
                return Ok(existing.approval.clone());
            }
            return Err(M5SupervisorAdapterError::Conflict(format!(
                "cycle {:?} already has a decision for a different exact request",
                request.cycle_id
            )));
        }
        let authorization = state
            .authorizations
            .get(&request.cycle_id)
            .cloned()
            .ok_or_else(|| M5SupervisorAdapterError::AuthorizationMissing {
                cycle_id: request.cycle_id.clone(),
            })?;
        match_request_to_authorization(request, &authorization)?;
        let approval = self.invoke_supervisor(request, &authorization)?;
        let decision =
            M5SupervisorDecisionRecord::new(request.clone(), &authorization, approval.clone())?;
        let path = self
            .decisions_root
            .join(record_file_name(&request.cycle_id));
        persist_json_immutable(&self.decisions_root, &path, &decision, MAX_DECISION_BYTES)?;
        state.decisions.insert(request.cycle_id.clone(), decision);
        Ok(approval)
    }

    /// Return only a granted, exact approval. Rejected or undecided cycles have
    /// no promotion authority.
    pub fn approval_for_cycle(
        &self,
        cycle_id: &str,
    ) -> Result<Option<M5PromotionApprovalReference>, M5SupervisorAdapterError> {
        validate_identifier("cycle id", cycle_id)?;
        let state = self.lock_state()?;
        let Some(decision) = state.decisions.get(cycle_id) else {
            return Ok(None);
        };
        if decision.approval.decision != ApprovalDecision::Approved {
            return Ok(None);
        }
        let authorization = state.authorizations.get(cycle_id).ok_or_else(|| {
            M5SupervisorAdapterError::Integrity(format!(
                "approved cycle {cycle_id:?} has no package authorization"
            ))
        })?;
        Ok(Some(M5PromotionApprovalReference {
            cycle_id: cycle_id.to_string(),
            supervisor_approval_id: decision.approval.approval_id.clone(),
            approval_digest: decision.approval.approval_digest.clone(),
            approval_ref: decision.approval.approval_digest.to_string(),
            request_digest: decision.request.request_digest.clone(),
            package_digest: authorization.challenger_package_digest.clone(),
            package_bytes_digest: authorization.challenger_package_bytes_digest.clone(),
            component_digest: authorization.challenger_component_digest.clone(),
            component_bytes_digest: authorization.challenger_component_bytes_digest.clone(),
            decision_record_digest: decision.decision_record_digest.clone(),
        }))
    }

    /// Persist separate exact authority for an operator-initiated rollback.
    pub fn authorize_operator_rollback(
        &self,
        request: M5OperatorRollbackAuthorizationRequest,
    ) -> Result<M5OperatorRollbackAuthorizationRecord, M5SupervisorAdapterError> {
        let record = M5OperatorRollbackAuthorizationRecord::from_request(request)?;
        let mut state = self.lock_state()?;
        if let Some(existing) = state.rollback_authorizations.get(&record.rollback_id) {
            return if existing == &record {
                Ok(existing.clone())
            } else {
                Err(M5SupervisorAdapterError::Conflict(format!(
                    "rollback {:?} already has different immutable operator authority",
                    record.rollback_id
                )))
            };
        }
        let path = self
            .rollback_authorizations_root
            .join(record_file_name(&record.rollback_id));
        persist_json_immutable(
            &self.rollback_authorizations_root,
            &path,
            &record,
            MAX_ROLLBACK_AUTHORIZATION_BYTES,
        )?;
        state
            .rollback_authorizations
            .insert(record.rollback_id.clone(), record.clone());
        Ok(record)
    }

    pub fn operator_rollback_authorization(
        &self,
        rollback_id: &str,
    ) -> Result<Option<M5OperatorRollbackAuthorizationRecord>, M5SupervisorAdapterError> {
        validate_identifier("rollback id", rollback_id)?;
        Ok(self
            .lock_state()?
            .rollback_authorizations
            .get(rollback_id)
            .cloned())
    }

    /// Verify the exact active and restore bytes immediately before rollback.
    pub fn require_exact_operator_rollback(
        &self,
        request: &M5OperatorRollbackExecutionRequest,
    ) -> Result<M5OperatorRollbackAuthorizationRecord, M5SupervisorAdapterError> {
        validate_identifier("rollback id", &request.rollback_id)?;
        validate_identifier("rollback source cycle id", &request.source_cycle_id)?;
        validate_identifier("rollback reason ref", &request.reason_ref)?;
        let active_package = parse_exact_package(
            "active rollback package",
            &request.active_package_bytes,
            &request.active_component_bytes,
        )?;
        let restore_package = parse_exact_package(
            "restore rollback package",
            &request.restore_package_bytes,
            &request.restore_component_bytes,
        )?;
        let state = self.lock_state()?;
        let authorization = state
            .rollback_authorizations
            .get(&request.rollback_id)
            .cloned()
            .ok_or_else(|| M5SupervisorAdapterError::RollbackAuthorizationMissing {
                rollback_id: request.rollback_id.clone(),
            })?;
        if authorization.source_cycle_id != request.source_cycle_id
            || authorization.reason_ref != request.reason_ref
            || authorization.active_package != active_package
            || authorization.restore_package != restore_package
        {
            return Err(M5SupervisorAdapterError::Conflict(format!(
                "rollback {:?} does not match its exact operator authorization",
                request.rollback_id
            )));
        }
        Ok(authorization)
    }

    fn invoke_supervisor(
        &self,
        request: &SupervisorApprovalRequest,
        authorization: &M5PackageAuthorizationRecord,
    ) -> Result<SupervisorApprovalRecord, M5SupervisorAdapterError> {
        let cycle_key = record_key(&request.cycle_id);
        let approval_request_id = format!("m5-approval-{cycle_key}");
        let job_id = format!("m5-approval-job-{cycle_key}");
        let mut supervisor = LocalDurableSupervisor::open(
            &self.supervisor_root,
            format!("{}-{cycle_key}", self.owner_id),
            Arc::new(SystemSupervisorClock),
        )?;
        supervisor.submit_job(SubmitJobRequest {
            job_id: job_id.clone(),
            job_kind: M5_APPROVAL_JOB_KIND.to_string(),
            payload_json: serde_json::to_string(request)?,
            idempotency_key: format!("m5-approval-effect-{}", request.request_digest.file_stem()),
            // Stable values are required for the supervisor's exact request
            // fingerprint to remain idempotent across crash recovery.
            not_before_ms: 0,
            deadline_at_ms: u64::MAX,
            retry_policy: RetryPolicy::default(),
            approval_request_id: Some(approval_request_id.clone()),
        })?;
        supervisor.resolve_approval(ApprovalResolutionRecord {
            approval_request_id: approval_request_id.clone(),
            resolution: match authorization.decision {
                ApprovalDecision::Approved => ApprovalResolutionKind::Granted,
                ApprovalDecision::Rejected => ApprovalResolutionKind::Denied,
            },
            evidence_ref: format!(
                "m5-authorization-{}",
                authorization.authorization_digest.file_stem()
            ),
            resolved_at_ms: 0,
        })?;
        let should_cancel = authorization.decision == ApprovalDecision::Approved
            && supervisor
                .job(&job_id)
                .is_some_and(|job| !job.phase.is_terminal());
        if should_cancel {
            supervisor.cancel_job(&job_id, "approval consumed by exact M5 promotion decision")?;
        }
        supervisor.graceful_shutdown()?;
        let approved = authorization.decision == ApprovalDecision::Approved;
        SupervisorApprovalRecord {
            approval_id: approval_request_id,
            request_digest: request.request_digest.clone(),
            decision: authorization.decision,
            approved_package_digest: approved.then_some(request.challenger_package_digest.clone()),
            approved_package_bytes_digest: approved
                .then_some(request.challenger_package_bytes_digest.clone()),
            gate_decision_digest: request.gate_decision_digest.clone(),
            evidence_digests: vec![
                request.m1_evidence_digest.clone(),
                request.worker_evidence_digest.clone(),
                request.shadow_evidence_digest.clone(),
            ],
            approver_ref: authorization.approver_ref.clone(),
            rationale: authorization.rationale.clone(),
            approval_digest: empty_digest(),
        }
        .seal()
        .map_err(|error| M5SupervisorAdapterError::Integrity(error.to_string()))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, AdapterState>, M5SupervisorAdapterError> {
        self.state
            .lock()
            .map_err(|_| M5SupervisorAdapterError::LockPoisoned)
    }
}

impl M2SupervisorPort for M5SupervisorAdapter {
    fn decide(
        &self,
        request: &SupervisorApprovalRequest,
    ) -> Result<SupervisorApprovalRecord, PortFailure> {
        self.decide_authorized(request)
            .map_err(M5SupervisorAdapterError::into_port_failure)
    }
}

fn load_state(
    initialization_authorizations_root: &Path,
    initialization_consumptions_root: &Path,
    package_authorizations_root: &Path,
    decisions_root: &Path,
    rollback_authorizations_root: &Path,
) -> Result<AdapterState, M5SupervisorAdapterError> {
    let mut state = AdapterState::default();
    for path in record_files(initialization_authorizations_root)? {
        let record: M5InitializationAuthorizationRecord =
            read_json_bounded(&path, MAX_INITIALIZATION_AUTHORIZATION_BYTES)?;
        record.validate()?;
        require_expected_record_name(&path, &record.factory_id)?;
        if state
            .initialization_authorizations
            .insert(record.factory_id.clone(), record)
            .is_some()
        {
            return Err(M5SupervisorAdapterError::Integrity(
                "duplicate initialization authorization factory id".to_string(),
            ));
        }
    }
    for path in record_files(initialization_consumptions_root)? {
        let record: M5InitializationConsumptionRecord =
            read_json_bounded(&path, MAX_INITIALIZATION_CONSUMPTION_BYTES)?;
        require_expected_record_name(&path, &record.factory_id)?;
        let authorization = state
            .initialization_authorizations
            .get(&record.factory_id)
            .ok_or_else(|| {
                M5SupervisorAdapterError::Integrity(format!(
                    "initialization consumption for factory {:?} has no immutable authority",
                    record.factory_id
                ))
            })?;
        record.validate(authorization)?;
        if state
            .initialization_consumptions
            .insert(record.factory_id.clone(), record)
            .is_some()
        {
            return Err(M5SupervisorAdapterError::Integrity(
                "duplicate initialization consumption factory id".to_string(),
            ));
        }
    }
    for path in record_files(package_authorizations_root)? {
        let record: M5PackageAuthorizationRecord =
            read_json_bounded(&path, MAX_PACKAGE_AUTHORIZATION_BYTES)?;
        record.validate()?;
        require_expected_record_name(&path, &record.cycle_id)?;
        if state
            .authorizations
            .insert(record.cycle_id.clone(), record)
            .is_some()
        {
            return Err(M5SupervisorAdapterError::Integrity(
                "duplicate package authorization cycle id".to_string(),
            ));
        }
    }
    for path in record_files(decisions_root)? {
        let record: M5SupervisorDecisionRecord = read_json_bounded(&path, MAX_DECISION_BYTES)?;
        require_expected_record_name(&path, &record.cycle_id)?;
        let authorization = state.authorizations.get(&record.cycle_id).ok_or_else(|| {
            M5SupervisorAdapterError::Integrity(format!(
                "decision for cycle {:?} has no immutable package authorization",
                record.cycle_id
            ))
        })?;
        record.validate(authorization)?;
        if state
            .decisions
            .insert(record.cycle_id.clone(), record)
            .is_some()
        {
            return Err(M5SupervisorAdapterError::Integrity(
                "duplicate supervisor decision cycle id".to_string(),
            ));
        }
    }
    for path in record_files(rollback_authorizations_root)? {
        let record: M5OperatorRollbackAuthorizationRecord =
            read_json_bounded(&path, MAX_ROLLBACK_AUTHORIZATION_BYTES)?;
        record.validate()?;
        require_expected_record_name(&path, &record.rollback_id)?;
        if state
            .rollback_authorizations
            .insert(record.rollback_id.clone(), record)
            .is_some()
        {
            return Err(M5SupervisorAdapterError::Integrity(
                "duplicate operator rollback authorization id".to_string(),
            ));
        }
    }
    Ok(state)
}

fn validate_supervisor_request(
    request: &SupervisorApprovalRequest,
) -> Result<(), M5SupervisorAdapterError> {
    validate_identifier("supervisor request cycle id", &request.cycle_id)?;
    require_digest(
        "supervisor approval request",
        &expected_supervisor_request_digest(request)?,
        &request.request_digest,
    )
}

fn expected_supervisor_request_digest(
    request: &SupervisorApprovalRequest,
) -> Result<ContentDigest, M5SupervisorAdapterError> {
    digest_serializable(&(
        "wasm-biotic:supervisor-approval-request:v1",
        &request.cycle_id,
        &request.incumbent_package_digest,
        &request.challenger_package_digest,
        &request.challenger_package_bytes_digest,
        &request.gate_digest,
        &request.gate_decision_digest,
        &request.m1_evidence_digest,
        &request.worker_evidence_digest,
        &request.shadow_evidence_digest,
        &request.migration_plan_digest,
        &request.operator_context_digest,
    ))
}

fn match_request_to_authorization(
    request: &SupervisorApprovalRequest,
    authorization: &M5PackageAuthorizationRecord,
) -> Result<(), M5SupervisorAdapterError> {
    if request.cycle_id != authorization.cycle_id
        || request.incumbent_package_digest != authorization.incumbent_package_digest
        || request.challenger_package_digest != authorization.challenger_package_digest
        || request.challenger_package_bytes_digest != authorization.challenger_package_bytes_digest
    {
        return Err(M5SupervisorAdapterError::Conflict(format!(
            "approval request for cycle {:?} does not match its exact package authorization",
            request.cycle_id
        )));
    }
    // The package was reconstructed from canonical bytes and contains the
    // validated component bytes. A SHA-256 match on those canonical package
    // bytes therefore also binds the component identities in the authorization.
    authorization.validate()
}

fn validate_approval(
    approval: &SupervisorApprovalRecord,
    request: &SupervisorApprovalRequest,
    authorization: &M5PackageAuthorizationRecord,
) -> Result<(), M5SupervisorAdapterError> {
    let resealed = approval
        .clone()
        .seal()
        .map_err(|error| M5SupervisorAdapterError::Integrity(error.to_string()))?;
    let expected_approval_id = format!("m5-approval-{}", record_key(&request.cycle_id));
    if approval.approval_id != expected_approval_id
        || resealed.approval_digest != approval.approval_digest
        || approval.request_digest != request.request_digest
        || approval.decision != authorization.decision
        || approval.gate_decision_digest != request.gate_decision_digest
        || approval.evidence_digests
            != [
                request.m1_evidence_digest.clone(),
                request.worker_evidence_digest.clone(),
                request.shadow_evidence_digest.clone(),
            ]
        || approval.approver_ref != authorization.approver_ref
        || approval.rationale != authorization.rationale
    {
        return Err(M5SupervisorAdapterError::Integrity(
            "persisted supervisor approval fields do not match their exact request and authorization"
                .to_string(),
        ));
    }
    let approved = authorization.decision == ApprovalDecision::Approved;
    if approval.approved_package_digest
        != approved.then_some(request.challenger_package_digest.clone())
        || approval.approved_package_bytes_digest
            != approved.then_some(request.challenger_package_bytes_digest.clone())
    {
        return Err(M5SupervisorAdapterError::Integrity(
            "persisted supervisor approval names the wrong package bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_initialize_request(
    request: &FactoryInitializeRequest,
) -> Result<(), M5SupervisorAdapterError> {
    let rederived = FactoryInitializeRequest::new(
        request.operation_id.clone(),
        request.factory_id.clone(),
        request.package_bytes.clone(),
        request.initial_state_schema,
        request.initial_state_bytes.clone(),
    )
    .map_err(|error| {
        M5SupervisorAdapterError::InvalidRequest(format!(
            "factory initialization request is invalid: {error}"
        ))
    })?;
    if &rederived != request {
        return Err(M5SupervisorAdapterError::InvalidRequest(
            "factory initialization request digest or schema is not exact".to_string(),
        ));
    }
    Ok(())
}

fn initialization_package_issue(
    package: &FactoryPackage,
    factory_id: &str,
    initial_state_schema: u32,
) -> Option<String> {
    if package.payload.factory_id != factory_id {
        return Some(
            "initialization incumbent package factory id differs from its authority".to_string(),
        );
    }
    if package.payload.generation != 0 || package.payload.parent_package_digest.is_some() {
        return Some(
            "initialization authority requires one generation-zero package with no parent"
                .to_string(),
        );
    }
    if initial_state_schema == 0
        || package
            .payload
            .boot_manifest
            .state_compatibility
            .written_schema
            != initial_state_schema
    {
        return Some(
            "initial state schema differs from the incumbent package written schema".to_string(),
        );
    }
    None
}

fn validate_nonempty_content_digest(
    label: &str,
    digest: &ContentDigest,
) -> Result<(), M5SupervisorAdapterError> {
    if digest == &empty_digest() {
        return Err(M5SupervisorAdapterError::InvalidRequest(format!(
            "{label} digest must not identify empty bytes"
        )));
    }
    Ok(())
}

fn parse_exact_package(
    label: &str,
    package_bytes: &[u8],
    component_bytes: &[u8],
) -> Result<FactoryPackage, M5SupervisorAdapterError> {
    let package = FactoryPackage::from_canonical_bytes(package_bytes).map_err(|error| {
        M5SupervisorAdapterError::InvalidRequest(format!("{label} is invalid: {error}"))
    })?;
    if package.payload.genome.component_bytes != component_bytes {
        return Err(M5SupervisorAdapterError::InvalidRequest(format!(
            "{label} component bytes differ from the bytes embedded in its package"
        )));
    }
    Ok(package)
}

fn validate_package_identity(
    label: &str,
    package: &FactoryPackage,
    package_digest: &ContentDigest,
    package_bytes_digest: &ContentDigest,
    component_digest: &ContentDigest,
    component_bytes_digest: &ContentDigest,
) -> Result<(), M5SupervisorAdapterError> {
    let package_bytes = package.canonical_bytes().map_err(|error| {
        M5SupervisorAdapterError::Integrity(format!("{label} package is invalid: {error}"))
    })?;
    require_digest(
        &format!("{label} package record"),
        &package.package_digest,
        package_digest,
    )?;
    require_digest(
        &format!("{label} package bytes"),
        &ContentDigest::from_bytes(&package_bytes),
        package_bytes_digest,
    )?;
    require_digest(
        &format!("{label} component record"),
        &package.payload.genome.component_digest,
        component_digest,
    )?;
    require_digest(
        &format!("{label} component bytes"),
        &ContentDigest::from_bytes(&package.payload.genome.component_bytes),
        component_bytes_digest,
    )
}

fn validate_rollback_edge(
    active: &FactoryPackage,
    restore: &FactoryPackage,
) -> Result<(), M5SupervisorAdapterError> {
    if active.payload.factory_id != restore.payload.factory_id
        || active.payload.parent_package_digest.as_ref() != Some(&restore.package_digest)
        || active.payload.generation != restore.payload.generation.saturating_add(1)
    {
        return Err(M5SupervisorAdapterError::InvalidRequest(
            "operator rollback must restore the exact immediate parent package of the active package"
                .to_string(),
        ));
    }
    Ok(())
}

fn digest_serializable<T: Serialize + ?Sized>(
    value: &T,
) -> Result<ContentDigest, M5SupervisorAdapterError> {
    Ok(ContentDigest::from_bytes(&serde_json::to_vec(value)?))
}

fn empty_digest() -> ContentDigest {
    ContentDigest::from_bytes(&[])
}

fn require_digest(
    subject: &str,
    actual: &ContentDigest,
    expected: &ContentDigest,
) -> Result<(), M5SupervisorAdapterError> {
    if actual == expected {
        Ok(())
    } else {
        Err(M5SupervisorAdapterError::Integrity(format!(
            "{subject} digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), M5SupervisorAdapterError> {
    if value.trim().is_empty()
        || value.len() > 512
        || value.contains('\0')
        || value.contains('/')
        || value.contains('\\')
        || matches!(value, "." | "..")
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(M5SupervisorAdapterError::InvalidRequest(format!(
            "{field} is blank, unsafe, or outside its length bound"
        )));
    }
    Ok(())
}

fn validate_owner_id(value: &str) -> Result<(), M5SupervisorAdapterError> {
    if value.trim().is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(M5SupervisorAdapterError::InvalidRequest(
            "owner id must be 1..=128 ASCII letters, digits, '-' or '_'".to_string(),
        ));
    }
    Ok(())
}

fn validate_rationale(value: &str) -> Result<(), M5SupervisorAdapterError> {
    if value.trim().is_empty() || value.len() > MAX_RATIONALE_BYTES || value.contains('\0') {
        return Err(M5SupervisorAdapterError::InvalidRequest(format!(
            "rationale must contain 1..={MAX_RATIONALE_BYTES} non-NUL bytes"
        )));
    }
    Ok(())
}

fn record_key(identifier: &str) -> String {
    ContentDigest::from_bytes(identifier.as_bytes()).file_stem()
}

fn record_file_name(identifier: &str) -> String {
    format!("{}.json", record_key(identifier))
}

fn require_expected_record_name(
    path: &Path,
    identifier: &str,
) -> Result<(), M5SupervisorAdapterError> {
    if path.file_name().and_then(|name| name.to_str())
        != Some(record_file_name(identifier).as_str())
    {
        return Err(M5SupervisorAdapterError::Integrity(format!(
            "immutable record '{}' is stored under the wrong identity",
            path.display()
        )));
    }
    Ok(())
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M5SupervisorAdapterError> {
    if path.as_os_str().is_empty() {
        return Err(M5SupervisorAdapterError::InvalidRequest(
            "adapter root must not be empty".to_string(),
        ));
    }
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| M5SupervisorAdapterError::io(path, source))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M5SupervisorAdapterError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(M5SupervisorAdapterError::UnsafePath {
            path: path.to_path_buf(),
            reason: "adapter root must be a real directory",
        });
    }
    fs::canonicalize(path).map_err(|source| M5SupervisorAdapterError::io(path, source))
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M5SupervisorAdapterError> {
    let path = root.join(name);
    reject_symlink_if_present(&path)?;
    fs::create_dir_all(&path).map_err(|source| M5SupervisorAdapterError::io(&path, source))?;
    let canonical =
        fs::canonicalize(&path).map_err(|source| M5SupervisorAdapterError::io(&path, source))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|source| M5SupervisorAdapterError::io(&canonical, source))?;
    if canonical.parent() != Some(root) || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(M5SupervisorAdapterError::UnsafePath {
            path,
            reason: "adapter child must be a direct real directory",
        });
    }
    Ok(canonical)
}

fn acquire_owner_lock(root: &Path, owner_id: &str) -> Result<File, M5SupervisorAdapterError> {
    let path = root.join(OWNER_LOCK_FILE);
    reject_symlink_if_present(&path)?;
    if path.exists() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| M5SupervisorAdapterError::io(&path, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(M5SupervisorAdapterError::UnsafePath {
                path,
                reason: "adapter owner lock must be a regular file",
            });
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| M5SupervisorAdapterError::io(&path, source))?;
    file.try_lock().map_err(|source| match source {
        std::fs::TryLockError::WouldBlock => {
            M5SupervisorAdapterError::WriterAlreadyActive(path.clone())
        }
        std::fs::TryLockError::Error(source) => M5SupervisorAdapterError::io(&path, source),
    })?;
    file.set_len(0)
        .and_then(|_| file.seek(SeekFrom::Start(0)))
        .and_then(|_| file.write_all(owner_id.as_bytes()))
        .and_then(|_| file.sync_all())
        .map_err(|source| M5SupervisorAdapterError::io(&path, source))?;
    Ok(file)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M5SupervisorAdapterError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(M5SupervisorAdapterError::UnsafePath {
                path: path.to_path_buf(),
                reason: "symbolic links are not accepted",
            })
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M5SupervisorAdapterError::io(path, source)),
    }
}

fn cleanup_temporary_files(directory: &Path) -> Result<(), M5SupervisorAdapterError> {
    for entry in
        fs::read_dir(directory).map_err(|source| M5SupervisorAdapterError::io(directory, source))?
    {
        let entry = entry.map_err(|source| M5SupervisorAdapterError::io(directory, source))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(M5SupervisorAdapterError::UnsafePath {
                path: entry.path(),
                reason: "record filename is not UTF-8",
            });
        };
        if !name.starts_with(TEMPORARY_FILE_PREFIX) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| M5SupervisorAdapterError::io(&path, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(M5SupervisorAdapterError::UnsafePath {
                path,
                reason: "staged record is not a regular file",
            });
        }
        fs::remove_file(&path).map_err(|source| M5SupervisorAdapterError::io(&path, source))?;
    }
    Ok(())
}

fn record_files(directory: &Path) -> Result<Vec<PathBuf>, M5SupervisorAdapterError> {
    let mut paths = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|source| M5SupervisorAdapterError::io(directory, source))?
    {
        let entry = entry.map_err(|source| M5SupervisorAdapterError::io(directory, source))?;
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(M5SupervisorAdapterError::UnsafePath {
                path,
                reason: "record filename is not UTF-8",
            });
        };
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| M5SupervisorAdapterError::io(&path, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || !name.ends_with(".json") {
            return Err(M5SupervisorAdapterError::UnsafePath {
                path,
                reason: "record directory may contain only regular .json files",
            });
        }
        paths.push(path);
        if paths.len() > MAX_RECORDS_PER_KIND {
            return Err(M5SupervisorAdapterError::ResourceBound(format!(
                "record directory '{}' exceeds its {}-record bound",
                directory.display(),
                MAX_RECORDS_PER_KIND
            )));
        }
    }
    paths.sort();
    Ok(paths)
}

fn read_json_bounded<T: for<'de> Deserialize<'de>>(
    path: &Path,
    maximum: usize,
) -> Result<T, M5SupervisorAdapterError> {
    reject_symlink_if_present(path)?;
    let metadata =
        fs::metadata(path).map_err(|source| M5SupervisorAdapterError::io(path, source))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(M5SupervisorAdapterError::ResourceBound(format!(
            "record '{}' is not regular or exceeds {maximum} bytes",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|source| M5SupervisorAdapterError::io(path, source))?
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| M5SupervisorAdapterError::io(path, source))?;
    if bytes.len() > maximum {
        return Err(M5SupervisorAdapterError::ResourceBound(format!(
            "record '{}' exceeded {maximum} bytes while being read",
            path.display()
        )));
    }
    serde_json::from_slice(&bytes).map_err(M5SupervisorAdapterError::from)
}

fn persist_json_immutable<T: Serialize>(
    directory: &Path,
    destination: &Path,
    value: &T,
    maximum: usize,
) -> Result<(), M5SupervisorAdapterError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > maximum || destination.parent() != Some(directory) {
        return Err(M5SupervisorAdapterError::ResourceBound(format!(
            "immutable record '{}' is empty, oversized, or outside its record directory",
            destination.display()
        )));
    }
    reject_symlink_if_present(destination)?;
    if destination.exists() {
        let existing = read_regular_bounded(destination, maximum)?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(M5SupervisorAdapterError::Conflict(format!(
                "immutable record '{}' already contains different bytes",
                destination.display()
            )))
        };
    }
    let temporary = directory.join(format!(
        "{TEMPORARY_FILE_PREFIX}{}-{}",
        std::process::id(),
        TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| M5SupervisorAdapterError::io(&temporary, source))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|source| M5SupervisorAdapterError::io(&temporary, source))?;
        match fs::hard_link(&temporary, destination) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_regular_bounded(destination, maximum)?;
                if existing == bytes {
                    Ok(())
                } else {
                    Err(M5SupervisorAdapterError::Conflict(format!(
                        "immutable record '{}' was concurrently published with different bytes",
                        destination.display()
                    )))
                }
            }
            Err(source) => Err(M5SupervisorAdapterError::io(destination, source)),
        }?;
        fs::remove_file(&temporary)
            .map_err(|source| M5SupervisorAdapterError::io(&temporary, source))?;
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| M5SupervisorAdapterError::io(directory, source))
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn read_regular_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, M5SupervisorAdapterError> {
    reject_symlink_if_present(path)?;
    let metadata =
        fs::metadata(path).map_err(|source| M5SupervisorAdapterError::io(path, source))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(M5SupervisorAdapterError::ResourceBound(format!(
            "record '{}' is not regular or exceeds {maximum} bytes",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|source| M5SupervisorAdapterError::io(path, source))?
        .take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| M5SupervisorAdapterError::io(path, source))?;
    if bytes.len() > maximum {
        return Err(M5SupervisorAdapterError::ResourceBound(format!(
            "record '{}' exceeded {maximum} bytes while being read",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Fail-closed errors from the immutable authorization boundary.
#[derive(Debug)]
pub enum M5SupervisorAdapterError {
    InvalidRequest(String),
    InitializationAuthorizationMissing {
        factory_id: String,
    },
    AuthorizationMissing {
        cycle_id: String,
    },
    RollbackAuthorizationMissing {
        rollback_id: String,
    },
    Integrity(String),
    Conflict(String),
    ResourceBound(String),
    WriterAlreadyActive(PathBuf),
    LockPoisoned,
    UnsafePath {
        path: PathBuf,
        reason: &'static str,
    },
    Supervisor(SupervisorError),
    Serialization(serde_json::Error),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl M5SupervisorAdapterError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }

    fn into_port_failure(self) -> PortFailure {
        match self {
            Self::InitializationAuthorizationMissing { factory_id } => PortFailure::unavailable(
                "m2_explicit_initialization_approval_missing",
                format!("factory {factory_id:?} has no durable exact initialization authorization"),
            ),
            Self::AuthorizationMissing { cycle_id } => PortFailure::unavailable(
                "m2_explicit_approval_missing",
                format!("cycle {cycle_id:?} has no durable exact-package operator authorization"),
            ),
            other => PortFailure::failed("m2_durable_authorization_failed", other.to_string()),
        }
    }
}

impl From<SupervisorError> for M5SupervisorAdapterError {
    fn from(value: SupervisorError) -> Self {
        Self::Supervisor(value)
    }
}

impl From<serde_json::Error> for M5SupervisorAdapterError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl Display for M5SupervisorAdapterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(message) => write!(formatter, "invalid request: {message}"),
            Self::InitializationAuthorizationMissing { factory_id } => write!(
                formatter,
                "initialization authorization is missing for factory {factory_id:?}"
            ),
            Self::AuthorizationMissing { cycle_id } => {
                write!(
                    formatter,
                    "package authorization is missing for cycle {cycle_id:?}"
                )
            }
            Self::RollbackAuthorizationMissing { rollback_id } => write!(
                formatter,
                "operator rollback authorization is missing for {rollback_id:?}"
            ),
            Self::Integrity(message) => write!(formatter, "record integrity failure: {message}"),
            Self::Conflict(message) => write!(formatter, "immutable record conflict: {message}"),
            Self::ResourceBound(message) => write!(formatter, "resource bound exceeded: {message}"),
            Self::WriterAlreadyActive(path) => write!(
                formatter,
                "another M5 supervisor adapter owns '{}'",
                path.display()
            ),
            Self::LockPoisoned => write!(formatter, "adapter state lock is poisoned"),
            Self::UnsafePath { path, reason } => {
                write!(
                    formatter,
                    "unsafe adapter path '{}': {reason}",
                    path.display()
                )
            }
            Self::Supervisor(error) => write!(formatter, "durable supervisor failed: {error}"),
            Self::Serialization(error) => write!(formatter, "serialization failed: {error}"),
            Self::Io { path, source } => {
                write!(formatter, "I/O failed at '{}': {source}", path.display())
            }
        }
    }
}

impl Error for M5SupervisorAdapterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Supervisor(source) => Some(source),
            Self::Serialization(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_reproduction::{
        MutableFactoryPolicy, MutableGenome, ServiceDependencyCatalog, StableInterfaceContract,
        StateCompatibility, WorkerCatalog,
    };
    use serde_json::Value;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m5-supervisor-{label}-{}-{}",
                std::process::id(),
                TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create isolated adapter test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if self.0.exists() {
                fs::remove_dir_all(&self.0).expect("remove isolated adapter test directory");
            }
        }
    }

    fn digest(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(label.as_bytes())
    }

    fn package(
        generation: u32,
        parent_package_digest: Option<ContentDigest>,
        component_seed: u8,
    ) -> FactoryPackage {
        let component_bytes = vec![0, 97, 115, 109, 1, 0, 0, component_seed];
        FactoryPackage::build(
            "factory:test",
            generation,
            MutableGenome::new(
                parent_package_digest,
                component_bytes,
                MutableFactoryPolicy::terminal(generation.saturating_add(1), 1),
            )
            .expect("build genome"),
            StableInterfaceContract::reference(),
            WorkerCatalog::reference().expect("reference worker catalog"),
            ServiceDependencyCatalog::reference().expect("reference service catalog"),
            StateCompatibility {
                readable_schema_min: 1,
                readable_schema_max: 2,
                written_schema: 1,
                incumbent_rollback_readable_through: 2,
            },
        )
        .expect("build package")
    }

    fn package_authorization(
        cycle_id: &str,
        incumbent: &FactoryPackage,
        challenger: &FactoryPackage,
        decision: ApprovalDecision,
    ) -> M5PackageAuthorizationRequest {
        M5PackageAuthorizationRequest {
            cycle_id: cycle_id.to_string(),
            incumbent_package_digest: incumbent.package_digest.clone(),
            challenger_package_bytes: challenger.canonical_bytes().expect("canonical package"),
            challenger_component_bytes: challenger.payload.genome.component_bytes.clone(),
            decision,
            approver_ref: "operator:test".to_string(),
            rationale: "exact bounded package reviewed".to_string(),
        }
    }

    fn initialization_authorization(
        incumbent: &FactoryPackage,
        initial_state_bytes: &[u8],
        manifest_digest: ContentDigest,
    ) -> M5InitializationAuthorizationRequest {
        M5InitializationAuthorizationRequest {
            factory_id: incumbent.payload.factory_id.clone(),
            incumbent_package_bytes: incumbent
                .canonical_bytes()
                .expect("incumbent package bytes"),
            incumbent_component_bytes: incumbent.payload.genome.component_bytes.clone(),
            initial_state_schema: incumbent
                .payload
                .boot_manifest
                .state_compatibility
                .written_schema,
            initial_state_bytes_digest: ContentDigest::from_bytes(initial_state_bytes),
            manifest_digest,
            operator_ref: "operator:initialization".to_string(),
            rationale: "exact local generation-zero initialization reviewed".to_string(),
        }
    }

    fn initialization_execution(
        operation_id: &str,
        incumbent: &FactoryPackage,
        initial_state_bytes: Vec<u8>,
        manifest_digest: ContentDigest,
    ) -> M5InitializationExecutionRequest {
        M5InitializationExecutionRequest {
            initialize_request: FactoryInitializeRequest::new(
                operation_id,
                incumbent.payload.factory_id.clone(),
                incumbent
                    .canonical_bytes()
                    .expect("incumbent package bytes"),
                incumbent
                    .payload
                    .boot_manifest
                    .state_compatibility
                    .written_schema,
                initial_state_bytes,
            )
            .expect("construct exact factory initialize request"),
            incumbent_component_bytes: incumbent.payload.genome.component_bytes.clone(),
            manifest_digest,
        }
    }

    fn approval_request(
        cycle_id: &str,
        incumbent: &FactoryPackage,
        challenger: &FactoryPackage,
    ) -> SupervisorApprovalRequest {
        let package_bytes = challenger.canonical_bytes().expect("canonical package");
        let mut request = SupervisorApprovalRequest {
            cycle_id: cycle_id.to_string(),
            incumbent_package_digest: incumbent.package_digest.clone(),
            challenger_package_digest: challenger.package_digest.clone(),
            challenger_package_bytes_digest: ContentDigest::from_bytes(&package_bytes),
            gate_digest: digest("gate"),
            gate_decision_digest: digest("gate-decision"),
            m1_evidence_digest: digest("m1"),
            worker_evidence_digest: digest("workers"),
            shadow_evidence_digest: digest("shadow"),
            migration_plan_digest: Some(digest("migration")),
            operator_context_digest: digest("operator-context"),
            request_digest: empty_digest(),
        };
        request.request_digest =
            expected_supervisor_request_digest(&request).expect("seal approval request");
        request
    }

    fn rollback_authorization(
        rollback_id: &str,
        source_cycle_id: &str,
        active: &FactoryPackage,
        restore: &FactoryPackage,
    ) -> M5OperatorRollbackAuthorizationRequest {
        M5OperatorRollbackAuthorizationRequest {
            rollback_id: rollback_id.to_string(),
            source_cycle_id: source_cycle_id.to_string(),
            active_package_bytes: active.canonical_bytes().expect("active package bytes"),
            active_component_bytes: active.payload.genome.component_bytes.clone(),
            restore_package_bytes: restore.canonical_bytes().expect("restore package bytes"),
            restore_component_bytes: restore.payload.genome.component_bytes.clone(),
            operator_ref: "operator:rollback".to_string(),
            reason_ref: "incident:test".to_string(),
            rationale: "explicit rollback after bounded observation".to_string(),
        }
    }

    #[test]
    fn initialization_authority_is_exact_durable_and_idempotently_consumed() {
        let directory = TestDirectory::new("initialization");
        let incumbent = package(0, None, 12);
        let initial_state_bytes = br#"{"factory":"test","generation":0,"schema":1}"#.to_vec();
        let manifest_digest = digest("m5-manifest");
        let authorization_request =
            initialization_authorization(&incumbent, &initial_state_bytes, manifest_digest.clone());
        let execution_request = initialization_execution(
            "initialize:factory-test",
            &incumbent,
            initial_state_bytes,
            manifest_digest,
        );
        let adapter = M5SupervisorAdapter::open(&directory.0, "owner_test").expect("open adapter");

        let authorization = adapter
            .authorize_initialization(authorization_request.clone())
            .expect("append exact initialization authority");
        let replayed_authorization = adapter
            .authorize_initialization(authorization_request)
            .expect("replay exact initialization authority");
        assert!(
            replayed_authorization == authorization,
            "initialization authority replay differed from the retained authority"
        );
        let loaded_authorization = adapter
            .initialization_authorization("factory:test")
            .expect("lookup initialization authority");
        assert!(
            loaded_authorization.as_ref() == Some(&authorization),
            "loaded initialization authority differed from the retained authority"
        );

        let approval_ref = adapter
            .require_and_consume_initialization_authority(execution_request.clone())
            .expect("consume exact initialization authority");
        let consumption = adapter
            .initialization_consumption("factory:test")
            .expect("lookup initialization consumption")
            .expect("initialization authority was consumed");
        assert_eq!(approval_ref, consumption.approval_ref());
        assert_eq!(
            consumption.authorization_digest,
            authorization.authorization_digest
        );
        assert!(
            consumption.initialize_request == execution_request.initialize_request,
            "initialization consumption retained different exact request bytes"
        );
        assert_eq!(
            adapter
                .require_and_consume_initialization_authority(execution_request.clone())
                .expect("idempotently consume the exact same initialization"),
            approval_ref
        );

        drop(adapter);
        let reopened =
            M5SupervisorAdapter::open(&directory.0, "owner_test").expect("reopen adapter");
        let reopened_authorization = reopened
            .initialization_authorization("factory:test")
            .expect("reload initialization authority");
        assert!(
            reopened_authorization.as_ref() == Some(&authorization),
            "reopened initialization authority differed from the retained authority"
        );
        let reopened_consumption = reopened
            .initialization_consumption("factory:test")
            .expect("reload initialization consumption");
        assert!(
            reopened_consumption.as_ref() == Some(&consumption),
            "reopened initialization consumption differed from the retained consumption"
        );
        assert_eq!(
            reopened
                .require_and_consume_initialization_authority(execution_request)
                .expect("replay exact consumption after reopen"),
            approval_ref
        );
    }

    #[test]
    fn initialization_authority_rejects_missing_changed_or_reused_material() {
        let directory = TestDirectory::new("initialization-conflict");
        let incumbent = package(0, None, 13);
        let initial_state_bytes = br#"{"schema":1,"value":"authorized"}"#.to_vec();
        let manifest_digest = digest("m5-manifest-authorized");
        let authorization_request =
            initialization_authorization(&incumbent, &initial_state_bytes, manifest_digest.clone());
        let execution_request = initialization_execution(
            "initialize:authorized",
            &incumbent,
            initial_state_bytes.clone(),
            manifest_digest.clone(),
        );
        let adapter = M5SupervisorAdapter::open(&directory.0, "owner_test").expect("open adapter");

        assert!(matches!(
            adapter.require_and_consume_initialization_authority(execution_request.clone()),
            Err(M5SupervisorAdapterError::InitializationAuthorizationMissing { .. })
        ));

        let mut wrong_component = authorization_request.clone();
        wrong_component.incumbent_component_bytes.push(99);
        assert!(matches!(
            adapter.authorize_initialization(wrong_component),
            Err(M5SupervisorAdapterError::InvalidRequest(_))
        ));
        adapter
            .authorize_initialization(authorization_request.clone())
            .expect("append exact initialization authority");

        let mut changed_authority = authorization_request;
        changed_authority.manifest_digest = digest("different-manifest");
        assert!(matches!(
            adapter.authorize_initialization(changed_authority),
            Err(M5SupervisorAdapterError::Conflict(_))
        ));

        let mut changed_component = execution_request.clone();
        changed_component.incumbent_component_bytes.push(7);
        assert!(matches!(
            adapter.require_and_consume_initialization_authority(changed_component),
            Err(M5SupervisorAdapterError::InvalidRequest(_))
        ));
        let different_incumbent = package(0, None, 15);
        let changed_package = initialization_execution(
            "initialize:authorized",
            &different_incumbent,
            initial_state_bytes.clone(),
            manifest_digest.clone(),
        );
        assert!(matches!(
            adapter.require_and_consume_initialization_authority(changed_package),
            Err(M5SupervisorAdapterError::Conflict(_))
        ));
        let changed_state = initialization_execution(
            "initialize:authorized",
            &incumbent,
            br#"{"schema":1,"value":"different"}"#.to_vec(),
            manifest_digest.clone(),
        );
        assert!(matches!(
            adapter.require_and_consume_initialization_authority(changed_state),
            Err(M5SupervisorAdapterError::Conflict(_))
        ));
        let changed_manifest = initialization_execution(
            "initialize:authorized",
            &incumbent,
            initial_state_bytes,
            digest("different-manifest"),
        );
        assert!(matches!(
            adapter.require_and_consume_initialization_authority(changed_manifest),
            Err(M5SupervisorAdapterError::Conflict(_))
        ));

        let approval_ref = adapter
            .require_and_consume_initialization_authority(execution_request)
            .expect("consume the exact authorized initialization");
        let changed_operation = initialization_execution(
            "initialize:different-operation",
            &incumbent,
            br#"{"schema":1,"value":"authorized"}"#.to_vec(),
            manifest_digest,
        );
        assert!(matches!(
            adapter.require_and_consume_initialization_authority(changed_operation),
            Err(M5SupervisorAdapterError::Conflict(_))
        ));
        assert_eq!(
            adapter
                .initialization_consumption("factory:test")
                .expect("lookup sole consumption")
                .expect("consumption exists")
                .approval_ref(),
            approval_ref
        );
    }

    #[test]
    fn tampered_initialization_consumption_is_rejected_on_reload() {
        let directory = TestDirectory::new("initialization-tamper");
        let incumbent = package(0, None, 14);
        let initial_state_bytes = br#"{"schema":1,"value":"exact"}"#.to_vec();
        let manifest_digest = digest("m5-manifest-tamper");
        let adapter = M5SupervisorAdapter::open(&directory.0, "owner_test").expect("open adapter");
        adapter
            .authorize_initialization(initialization_authorization(
                &incumbent,
                &initial_state_bytes,
                manifest_digest.clone(),
            ))
            .expect("authorize initialization");
        adapter
            .require_and_consume_initialization_authority(initialization_execution(
                "initialize:tamper-test",
                &incumbent,
                initial_state_bytes,
                manifest_digest,
            ))
            .expect("consume initialization authority");
        drop(adapter);

        let consumption_path = directory
            .0
            .join(INITIALIZATION_CONSUMPTIONS_DIRECTORY)
            .join(record_file_name("factory:test"));
        let mut value: Value =
            serde_json::from_slice(&fs::read(&consumption_path).expect("read consumption"))
                .expect("parse consumption");
        value["initialize_request"]["initial_state_bytes"] =
            serde_json::to_value(b"tampered".to_vec()).expect("encode tampered state bytes");
        fs::write(
            &consumption_path,
            serde_json::to_vec(&value).expect("encode tampered consumption"),
        )
        .expect("tamper consumption fixture");

        assert!(matches!(
            M5SupervisorAdapter::open(&directory.0, "owner_test"),
            Err(M5SupervisorAdapterError::Integrity(_))
        ));
    }

    #[test]
    fn exact_decision_is_durable_and_replay_does_not_reopen_supervisor() {
        let directory = TestDirectory::new("decision-replay");
        let incumbent = package(0, None, 1);
        let challenger = package(1, Some(incumbent.package_digest.clone()), 2);
        let request = approval_request("cycle:n1", &incumbent, &challenger);
        let adapter = M5SupervisorAdapter::open(&directory.0, "owner_test").expect("open adapter");
        adapter
            .authorize_package(package_authorization(
                "cycle:n1",
                &incumbent,
                &challenger,
                ApprovalDecision::Approved,
            ))
            .expect("authorize exact package");

        let first = adapter
            .decide_authorized(&request)
            .expect("resolve exact decision");
        let supervisor_state_path = directory
            .0
            .join(SUPERVISOR_DIRECTORY)
            .join("supervisor-state.json");
        let supervisor_bytes =
            fs::read(&supervisor_state_path).expect("read supervisor state after resolution");
        let replay = adapter
            .decide_authorized(&request)
            .expect("replay exact decision");
        assert_eq!(replay, first);
        assert_eq!(
            fs::read(&supervisor_state_path).expect("reread supervisor state"),
            supervisor_bytes,
            "an existing immutable decision must bypass the supervisor"
        );
        let approval = adapter
            .approval_for_cycle("cycle:n1")
            .expect("lookup approval")
            .expect("approved cycle has promotion authority");
        assert_eq!(approval.approval_digest, first.approval_digest);
        assert_eq!(approval.approval_ref, first.approval_digest.to_string());
        assert_eq!(
            approval.component_bytes_digest,
            ContentDigest::from_bytes(&challenger.payload.genome.component_bytes)
        );

        drop(adapter);
        let reopened =
            M5SupervisorAdapter::open(&directory.0, "owner_test").expect("reopen adapter");
        assert_eq!(
            reopened
                .decide_authorized(&request)
                .expect("replay after reopen"),
            first
        );
        assert_eq!(
            fs::read(&supervisor_state_path).expect("read untouched supervisor state"),
            supervisor_bytes
        );
    }

    #[test]
    fn package_and_component_conflicts_fail_closed() {
        let directory = TestDirectory::new("package-conflict");
        let incumbent = package(0, None, 3);
        let challenger = package(1, Some(incumbent.package_digest.clone()), 4);
        let adapter = M5SupervisorAdapter::open(&directory.0, "owner_test").expect("open adapter");

        let mut wrong_component = package_authorization(
            "cycle:n1",
            &incumbent,
            &challenger,
            ApprovalDecision::Approved,
        );
        wrong_component.challenger_component_bytes.push(99);
        assert!(matches!(
            adapter.authorize_package(wrong_component),
            Err(M5SupervisorAdapterError::InvalidRequest(_))
        ));
        adapter
            .authorize_package(package_authorization(
                "cycle:n1",
                &incumbent,
                &challenger,
                ApprovalDecision::Approved,
            ))
            .expect("persist exact authorization");
        assert!(matches!(
            adapter.authorize_package(package_authorization(
                "cycle:n1",
                &incumbent,
                &challenger,
                ApprovalDecision::Rejected,
            )),
            Err(M5SupervisorAdapterError::Conflict(_))
        ));

        let different = package(1, Some(incumbent.package_digest.clone()), 5);
        let request = approval_request("cycle:n1", &incumbent, &different);
        assert!(matches!(
            adapter.decide_authorized(&request),
            Err(M5SupervisorAdapterError::Conflict(_))
        ));
        assert!(
            adapter
                .decision_for_cycle("cycle:n1")
                .expect("lookup decision")
                .is_none()
        );
    }

    #[test]
    fn tampered_decision_is_rejected_on_open() {
        let directory = TestDirectory::new("decision-tamper");
        let incumbent = package(0, None, 6);
        let challenger = package(1, Some(incumbent.package_digest.clone()), 7);
        let request = approval_request("cycle:n1", &incumbent, &challenger);
        let adapter = M5SupervisorAdapter::open(&directory.0, "owner_test").expect("open adapter");
        adapter
            .authorize_package(package_authorization(
                "cycle:n1",
                &incumbent,
                &challenger,
                ApprovalDecision::Approved,
            ))
            .expect("authorize");
        adapter.decide_authorized(&request).expect("decide");
        drop(adapter);

        let decision_path = directory
            .0
            .join(DECISIONS_DIRECTORY)
            .join(record_file_name("cycle:n1"));
        let mut value: Value =
            serde_json::from_slice(&fs::read(&decision_path).expect("read decision"))
                .expect("parse decision");
        value["approval"]["rationale"] = Value::String("tampered rationale".to_string());
        fs::write(
            &decision_path,
            serde_json::to_vec(&value).expect("encode tampered decision"),
        )
        .expect("tamper decision fixture");

        assert!(matches!(
            M5SupervisorAdapter::open(&directory.0, "owner_test"),
            Err(M5SupervisorAdapterError::Integrity(_))
        ));
    }

    #[test]
    fn rejected_decision_has_no_m3_promotion_authority() {
        let directory = TestDirectory::new("rejected");
        let incumbent = package(0, None, 8);
        let challenger = package(1, Some(incumbent.package_digest.clone()), 9);
        let request = approval_request("cycle:n1", &incumbent, &challenger);
        let adapter = M5SupervisorAdapter::open(&directory.0, "owner_test").expect("open adapter");
        adapter
            .authorize_package(package_authorization(
                "cycle:n1",
                &incumbent,
                &challenger,
                ApprovalDecision::Rejected,
            ))
            .expect("authorize rejection");
        let decision = M2SupervisorPort::decide(&adapter, &request).expect("record rejection");
        assert_eq!(decision.decision, ApprovalDecision::Rejected);
        assert!(decision.approved_package_digest.is_none());
        assert!(
            adapter
                .approval_for_cycle("cycle:n1")
                .expect("lookup rejected cycle")
                .is_none()
        );
    }

    #[test]
    fn operator_rollback_authority_is_separate_durable_and_exact() {
        let directory = TestDirectory::new("rollback");
        let restore = package(0, None, 10);
        let active = package(1, Some(restore.package_digest.clone()), 11);
        let authorization_request =
            rollback_authorization("rollback:n1", "cycle:n1", &active, &restore);
        let execution_request = M5OperatorRollbackExecutionRequest {
            rollback_id: "rollback:n1".to_string(),
            source_cycle_id: "cycle:n1".to_string(),
            active_package_bytes: active.canonical_bytes().expect("active bytes"),
            active_component_bytes: active.payload.genome.component_bytes.clone(),
            restore_package_bytes: restore.canonical_bytes().expect("restore bytes"),
            restore_component_bytes: restore.payload.genome.component_bytes.clone(),
            reason_ref: "incident:test".to_string(),
        };
        let adapter = M5SupervisorAdapter::open(&directory.0, "owner_test").expect("open adapter");
        let first = adapter
            .authorize_operator_rollback(authorization_request.clone())
            .expect("authorize rollback");
        let replayed = adapter
            .authorize_operator_rollback(authorization_request)
            .expect("idempotent rollback authorization");
        assert!(
            replayed == first,
            "rollback authorization replay differed from the retained authority"
        );
        let matched = adapter
            .require_exact_operator_rollback(&execution_request)
            .expect("match exact rollback");
        assert!(
            matched == first,
            "matched rollback authority differed from the retained authority"
        );
        assert!(
            adapter
                .package_authorization("cycle:n1")
                .expect("lookup package authorization")
                .is_none(),
            "rollback authority must not appear in package authorization records"
        );

        let mut wrong_execution = execution_request.clone();
        wrong_execution.active_component_bytes.push(1);
        assert!(matches!(
            adapter.require_exact_operator_rollback(&wrong_execution),
            Err(M5SupervisorAdapterError::InvalidRequest(_))
        ));
        drop(adapter);

        let reopened =
            M5SupervisorAdapter::open(&directory.0, "owner_test").expect("reopen adapter");
        let reopened_authorization = reopened
            .operator_rollback_authorization("rollback:n1")
            .expect("lookup rollback authorization");
        assert!(
            reopened_authorization.as_ref() == Some(&first),
            "reopened rollback authority differed from the retained authority"
        );
    }
}
