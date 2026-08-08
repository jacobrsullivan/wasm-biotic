//! Bounded, local-first exchange between two independently rooted factories.
//!
//! The transport is a governed filesystem queue rooted outside both factory
//! stores. A sender copies canonical [`FactoryPackage`] bytes, lineage, and
//! actual proving evidence into a signed route envelope. A receiver reads only
//! that neutral queue, copies every artifact into its own quarantine, and then
//! applies its own interface, proving, policy, approval, deployment,
//! observation, and rollback decisions.
//!
//! Authentication is HMAC-SHA256 with a route key supplied at call time. Only a
//! domain-separated SHA-256 key fingerprint is persisted. This is appropriate
//! to the deliberately local threat model: operating-system permissions protect
//! factory roots and key delivery, while HMAC, nonces, expiry, revocation, and
//! durable replay journals detect queue alteration or spoofing. It is not a
//! claim of public federation, Byzantine trust, distributed consensus, or
//! safety after an endpoint or its route key is compromised.

use crate::deployment::{
    ActivationRequest, LocalDeploymentService, ObservationOutcome, ObservationRequest,
    RollbackRequest,
};
use crate::execution::artifact::ContentDigest;
use crate::execution::component::{
    ComponentExecutionLimits, ComponentI32ExecutionTrace, execute_component_i32_export,
};
use crate::factory_reproduction::{
    FactoryPackage, FactoryPackagePayload, REFERENCE_EXPORT, ReproductionError,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const M6_FACTORY_STATE_SCHEMA_VERSION: u32 = 1;
pub const M6_ROUTE_SCHEMA: &str = "wasm-biotic.m6-filesystem-route.v1";
pub const M6_EXCHANGE_SCHEMA: &str = "wasm-biotic.m6-exchange-envelope.v1";
pub const M6_REVOCATION_SCHEMA: &str = "wasm-biotic.m6-revocation-envelope.v1";

const FACTORY_STATE_FILE: &str = "m6-factory-state.json";
const ROUTE_DEFINITION_FILE: &str = "route-definition.json";
const ROUTE_INBOX_DIRECTORY: &str = "inbox";
const ROUTE_PENDING_DIRECTORY: &str = ".pending";
const ROUTE_REVOCATION_DIRECTORY: &str = "revocations";
const ROUTE_PENDING_REVOCATION_DIRECTORY: &str = ".pending-revocations";
const QUARANTINE_DIRECTORY: &str = "quarantine";
const OUTBOUND_DIRECTORY: &str = "outbound";
const DEPLOYMENT_DIRECTORY: &str = "deployment";
const MAX_ROUTE_FILE_BYTES: usize = 20 * 1_048_576;
const MIN_ROUTE_KEY_BYTES: usize = 32;
const MAX_RECORDS: usize = 10_000;
const CLOCK_SKEW_MS: u64 = 30_000;
const HMAC_BLOCK_BYTES: usize = 64;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteEndpointRole {
    Sender,
    Receiver,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityAction {
    ExportPackage,
    ManageLocalPackage,
    IssueRevocation,
    DisposeQuarantine,
    ActivateImport,
    ObserveImport,
    RollbackImport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEnvelope {
    pub envelope_id: String,
    pub factory_id: String,
    pub principal_id: String,
    pub resource_scope: String,
    pub permitted_actions: BTreeSet<AuthorityAction>,
    pub envelope_digest: ContentDigest,
}

impl AuthorityEnvelope {
    pub fn new(
        envelope_id: impl Into<String>,
        factory_id: impl Into<String>,
        principal_id: impl Into<String>,
        resource_scope: impl Into<String>,
        permitted_actions: BTreeSet<AuthorityAction>,
    ) -> Result<Self, M6ExchangeError> {
        let mut envelope = Self {
            envelope_id: envelope_id.into(),
            factory_id: factory_id.into(),
            principal_id: principal_id.into(),
            resource_scope: resource_scope.into(),
            permitted_actions,
            envelope_digest: ContentDigest::from_bytes(&[]),
        };
        envelope.validate_fields()?;
        envelope.envelope_digest = envelope.expected_digest()?;
        Ok(envelope)
    }

    pub fn invocation(&self, action: AuthorityAction) -> AuthorityInvocation {
        AuthorityInvocation {
            envelope_id: self.envelope_id.clone(),
            principal_id: self.principal_id.clone(),
            resource_scope: self.resource_scope.clone(),
            action,
        }
    }

    fn validate(&self) -> Result<(), M6ExchangeError> {
        self.validate_fields()?;
        require_digest(
            "authority envelope",
            &self.envelope_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6ExchangeError> {
        validate_identifier("authority envelope id", &self.envelope_id)?;
        validate_identifier("authority factory id", &self.factory_id)?;
        validate_identifier("authority principal id", &self.principal_id)?;
        validate_identifier("authority resource scope", &self.resource_scope)?;
        if self.permitted_actions.is_empty() {
            return Err(M6ExchangeError::InvalidConfiguration(
                "authority envelope must permit at least one bounded action".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ExchangeError> {
        digest_serializable(&(
            "wasm-biotic:m6-authority-envelope:v1",
            &self.envelope_id,
            &self.factory_id,
            &self.principal_id,
            &self.resource_scope,
            &self.permitted_actions,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityInvocation {
    pub envelope_id: String,
    pub principal_id: String,
    pub resource_scope: String,
    pub action: AuthorityAction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvingCase {
    pub case_id: String,
    pub input: i32,
    pub expected_output: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryExchangePolicy {
    pub policy_id: String,
    pub accepted_interface_ref: String,
    pub accepted_interface_digest: ContentDigest,
    pub proving_cases: Vec<ProvingCase>,
    pub post_adoption_cases: Vec<ProvingCase>,
    pub max_package_bytes: u64,
    pub max_envelope_ttl_ms: u64,
    pub execution_limits: ComponentExecutionLimits,
    pub policy_digest: ContentDigest,
}

impl FactoryExchangePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: impl Into<String>,
        accepted_interface_ref: impl Into<String>,
        accepted_interface_digest: ContentDigest,
        proving_cases: Vec<ProvingCase>,
        post_adoption_cases: Vec<ProvingCase>,
        max_package_bytes: u64,
        max_envelope_ttl_ms: u64,
        execution_limits: ComponentExecutionLimits,
    ) -> Result<Self, M6ExchangeError> {
        let mut policy = Self {
            policy_id: policy_id.into(),
            accepted_interface_ref: accepted_interface_ref.into(),
            accepted_interface_digest,
            proving_cases,
            post_adoption_cases,
            max_package_bytes,
            max_envelope_ttl_ms,
            execution_limits,
            policy_digest: ContentDigest::from_bytes(&[]),
        };
        policy.validate_fields()?;
        policy.policy_digest = policy.expected_digest()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), M6ExchangeError> {
        self.validate_fields()?;
        require_digest(
            "factory exchange policy",
            &self.policy_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6ExchangeError> {
        validate_identifier("exchange policy id", &self.policy_id)?;
        validate_identifier("accepted interface ref", &self.accepted_interface_ref)?;
        validate_cases("receiver proving", &self.proving_cases)?;
        validate_cases("post-adoption observation", &self.post_adoption_cases)?;
        if self.max_package_bytes == 0
            || self.max_package_bytes > MAX_ROUTE_FILE_BYTES as u64
            || self.max_envelope_ttl_ms == 0
        {
            return Err(M6ExchangeError::InvalidConfiguration(
                "package and envelope TTL bounds must be nonzero and locally bounded".to_string(),
            ));
        }
        if self.execution_limits.fuel == 0
            || self.execution_limits.max_memory_bytes == 0
            || self.execution_limits.max_instances == 0
        {
            return Err(M6ExchangeError::InvalidConfiguration(
                "component execution limits must be nonzero".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ExchangeError> {
        digest_serializable(&(
            "wasm-biotic:m6-factory-policy:v1",
            &self.policy_id,
            &self.accepted_interface_ref,
            &self.accepted_interface_digest,
            &self.proving_cases,
            &self.post_adoption_cases,
            self.max_package_bytes,
            self.max_envelope_ttl_ms,
            &self.execution_limits,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryEndpointProfile {
    pub factory_id: String,
    pub endpoint_role: RouteEndpointRole,
    pub route_id: String,
    pub peer_factory_id: String,
    pub policy: FactoryExchangePolicy,
    pub authority: AuthorityEnvelope,
    pub profile_digest: ContentDigest,
}

impl FactoryEndpointProfile {
    pub fn new(
        factory_id: impl Into<String>,
        endpoint_role: RouteEndpointRole,
        route_id: impl Into<String>,
        peer_factory_id: impl Into<String>,
        policy: FactoryExchangePolicy,
        authority: AuthorityEnvelope,
    ) -> Result<Self, M6ExchangeError> {
        let mut profile = Self {
            factory_id: factory_id.into(),
            endpoint_role,
            route_id: route_id.into(),
            peer_factory_id: peer_factory_id.into(),
            policy,
            authority,
            profile_digest: ContentDigest::from_bytes(&[]),
        };
        profile.validate_fields()?;
        profile.profile_digest = profile.expected_digest()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<(), M6ExchangeError> {
        self.validate_fields()?;
        require_digest(
            "factory endpoint profile",
            &self.profile_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6ExchangeError> {
        validate_identifier("factory id", &self.factory_id)?;
        validate_identifier("route id", &self.route_id)?;
        validate_identifier("peer factory id", &self.peer_factory_id)?;
        if self.factory_id == self.peer_factory_id {
            return Err(M6ExchangeError::InvalidConfiguration(
                "factory and peer identities must be distinct".to_string(),
            ));
        }
        self.policy.validate()?;
        self.authority.validate()?;
        if self.authority.factory_id != self.factory_id {
            return Err(M6ExchangeError::InvalidConfiguration(
                "authority envelope belongs to a different factory".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ExchangeError> {
        digest_serializable(&(
            "wasm-biotic:m6-endpoint-profile:v1",
            &self.factory_id,
            self.endpoint_role,
            &self.route_id,
            &self.peer_factory_id,
            &self.policy.policy_digest,
            &self.authority.envelope_digest,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDefinition {
    pub schema: String,
    pub route_id: String,
    pub sender_factory_id: String,
    pub receiver_factory_id: String,
    pub key_fingerprint: ContentDigest,
    pub definition_digest: ContentDigest,
}

impl RouteDefinition {
    fn build(
        route_id: impl Into<String>,
        sender_factory_id: impl Into<String>,
        receiver_factory_id: impl Into<String>,
        route_key: &[u8],
    ) -> Result<Self, M6ExchangeError> {
        validate_route_key(route_key)?;
        let mut definition = Self {
            schema: M6_ROUTE_SCHEMA.to_string(),
            route_id: route_id.into(),
            sender_factory_id: sender_factory_id.into(),
            receiver_factory_id: receiver_factory_id.into(),
            key_fingerprint: route_key_fingerprint(route_key),
            definition_digest: ContentDigest::from_bytes(&[]),
        };
        definition.validate_fields()?;
        definition.definition_digest = definition.expected_digest()?;
        Ok(definition)
    }

    fn validate(&self) -> Result<(), M6ExchangeError> {
        self.validate_fields()?;
        require_digest(
            "route definition",
            &self.definition_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6ExchangeError> {
        if self.schema != M6_ROUTE_SCHEMA {
            return Err(M6ExchangeError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("route id", &self.route_id)?;
        validate_identifier("route sender", &self.sender_factory_id)?;
        validate_identifier("route receiver", &self.receiver_factory_id)?;
        if self.sender_factory_id == self.receiver_factory_id {
            return Err(M6ExchangeError::InvalidConfiguration(
                "route endpoints must have distinct identities".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ExchangeError> {
        digest_serializable(&(
            M6_ROUTE_SCHEMA,
            &self.route_id,
            &self.sender_factory_id,
            &self.receiver_factory_id,
            &self.key_fingerprint,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernedFilesystemRoute {
    canonical_root: PathBuf,
    definition: RouteDefinition,
}

impl GovernedFilesystemRoute {
    pub fn initialize(
        root: impl AsRef<Path>,
        route_id: impl Into<String>,
        sender_factory_id: impl Into<String>,
        receiver_factory_id: impl Into<String>,
        route_key: &[u8],
    ) -> Result<Self, M6ExchangeError> {
        let root = prepare_new_or_existing_directory(root.as_ref(), "route root")?;
        let definition =
            RouteDefinition::build(route_id, sender_factory_id, receiver_factory_id, route_key)?;
        let definition_path = root.join(ROUTE_DEFINITION_FILE);
        if definition_path.exists() {
            return Err(M6ExchangeError::AlreadyInitialized(
                "route definition already exists".to_string(),
            ));
        }
        ensure_directory(&root.join(ROUTE_INBOX_DIRECTORY))?;
        ensure_directory(&root.join(ROUTE_PENDING_DIRECTORY))?;
        ensure_directory(&root.join(ROUTE_REVOCATION_DIRECTORY))?;
        ensure_directory(&root.join(ROUTE_PENDING_REVOCATION_DIRECTORY))?;
        atomic_write_new(
            &definition_path,
            &serde_json::to_vec_pretty(&definition)
                .map_err(|error| M6ExchangeError::Serialization(error.to_string()))?,
        )?;
        let route = Self {
            canonical_root: root,
            definition,
        };
        route.verify_layout()?;
        Ok(route)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self, M6ExchangeError> {
        let root = prepare_existing_directory(root.as_ref(), "route root")?;
        let definition: RouteDefinition =
            read_json_bounded(&root.join(ROUTE_DEFINITION_FILE), MAX_ROUTE_FILE_BYTES)?;
        definition.validate()?;
        let route = Self {
            canonical_root: root,
            definition,
        };
        route.verify_layout()?;
        route.recover()?;
        Ok(route)
    }

    pub fn definition(&self) -> &RouteDefinition {
        &self.definition
    }

    pub fn root(&self) -> &Path {
        &self.canonical_root
    }

    /// Completes atomic route deliveries left in a pending directory.
    pub fn recover(&self) -> Result<RouteRecoveryReport, M6ExchangeError> {
        self.verify_layout()?;
        let recovered_envelopes = recover_pending_directory(
            &self.pending_directory(),
            &self.inbox_directory(),
            "exchange",
        )?;
        let recovered_revocations = recover_pending_directory(
            &self.pending_revocation_directory(),
            &self.revocation_directory(),
            "revocation",
        )?;
        Ok(RouteRecoveryReport {
            recovered_envelopes,
            recovered_revocations,
        })
    }

    fn verify_layout(&self) -> Result<(), M6ExchangeError> {
        reject_symlink(&self.canonical_root)?;
        for path in [
            self.inbox_directory(),
            self.pending_directory(),
            self.revocation_directory(),
            self.pending_revocation_directory(),
        ] {
            ensure_existing_real_directory(&path)?;
            if !path.starts_with(&self.canonical_root) {
                return Err(M6ExchangeError::UnsafePath(
                    "route subdirectory escaped its root".to_string(),
                ));
            }
        }
        reject_symlink(&self.canonical_root.join(ROUTE_DEFINITION_FILE))
    }

    fn enqueue_exchange(&self, envelope: &SignedExchangeEnvelope) -> Result<(), M6ExchangeError> {
        let file_name = digest_file_name(&envelope.envelope_id, "exchange")?;
        enqueue_atomic(
            &self.pending_directory().join(&file_name),
            &self.inbox_directory().join(file_name),
            &canonical_json(envelope)?,
        )
    }

    fn enqueue_revocation(
        &self,
        envelope: &SignedRevocationEnvelope,
    ) -> Result<(), M6ExchangeError> {
        let file_name = digest_file_name(&envelope.revocation_id, "revocation")?;
        enqueue_atomic(
            &self.pending_revocation_directory().join(&file_name),
            &self.revocation_directory().join(file_name),
            &canonical_json(envelope)?,
        )
    }

    fn read_exchange_bytes(&self, envelope_id: &ContentDigest) -> Result<Vec<u8>, M6ExchangeError> {
        read_bounded(
            &self
                .inbox_directory()
                .join(digest_file_name(envelope_id, "exchange")?),
            MAX_ROUTE_FILE_BYTES,
        )
    }

    fn read_revocation_bytes(
        &self,
        revocation_id: &ContentDigest,
    ) -> Result<Vec<u8>, M6ExchangeError> {
        read_bounded(
            &self
                .revocation_directory()
                .join(digest_file_name(revocation_id, "revocation")?),
            MAX_ROUTE_FILE_BYTES,
        )
    }

    fn inbox_directory(&self) -> PathBuf {
        self.canonical_root.join(ROUTE_INBOX_DIRECTORY)
    }

    fn pending_directory(&self) -> PathBuf {
        self.canonical_root.join(ROUTE_PENDING_DIRECTORY)
    }

    fn revocation_directory(&self) -> PathBuf {
        self.canonical_root.join(ROUTE_REVOCATION_DIRECTORY)
    }

    fn pending_revocation_directory(&self) -> PathBuf {
        self.canonical_root.join(ROUTE_PENDING_REVOCATION_DIRECTORY)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRecoveryReport {
    pub recovered_envelopes: usize,
    pub recovered_revocations: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionObservation {
    pub case_id: String,
    pub input: i32,
    pub expected_output: i32,
    pub actual_output: Option<i32>,
    pub passed: bool,
    pub trace_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvingEvidence {
    pub suite_id: String,
    pub package_digest: ContentDigest,
    pub component_digest: ContentDigest,
    pub interface_digest: ContentDigest,
    pub observations: Vec<ExecutionObservation>,
    pub overall_pass: bool,
    pub report_digest: ContentDigest,
}

impl ProvingEvidence {
    fn validate_digest(&self) -> Result<(), M6ExchangeError> {
        require_digest(
            "proving evidence",
            &self.report_digest,
            &proving_report_digest(self)?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportLineageEvidence {
    pub source_factory_id: String,
    pub source_active_package_digest: ContentDigest,
    pub package_digest: ContentDigest,
    pub component_digest: ContentDigest,
    pub generation: u32,
    pub parent_package_digest: Option<ContentDigest>,
    pub lineage_digest: ContentDigest,
}

impl ExportLineageEvidence {
    fn validate_digest(&self) -> Result<(), M6ExchangeError> {
        require_digest(
            "export lineage",
            &self.lineage_digest,
            &lineage_digest(self)?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangePayload {
    pub route_id: String,
    pub sender_factory_id: String,
    pub receiver_factory_id: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub package_digest: ContentDigest,
    pub package_bytes: Vec<u8>,
    pub lineage: ExportLineageEvidence,
    pub sender_proving: ProvingEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteAuthentication {
    pub algorithm: String,
    pub key_fingerprint: ContentDigest,
    pub tag: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedExchangeEnvelope {
    pub schema: String,
    pub envelope_id: ContentDigest,
    pub payload: ExchangePayload,
    pub authentication: RouteAuthentication,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RevocationTarget {
    SenderIdentity(String),
    PackageDigest(ContentDigest),
    EnvelopeId(ContentDigest),
    Nonce(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationPayload {
    pub route_id: String,
    pub sender_factory_id: String,
    pub receiver_factory_id: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub target: RevocationTarget,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRevocationEnvelope {
    pub schema: String,
    pub revocation_id: ContentDigest,
    pub payload: RevocationPayload,
    pub authentication: RouteAuthentication,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportRequest {
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportReceipt {
    pub envelope_id: ContentDigest,
    pub package_digest: ContentDigest,
    pub lineage_digest: ContentDigest,
    pub proving_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationRequest {
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub target: RevocationTarget,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationReceipt {
    pub revocation_id: ContentDigest,
    pub target: RevocationTarget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionCode {
    AuthenticationFailed,
    FalseIdentity,
    Expired,
    Revoked,
    PackageDigestMismatch,
    InvalidPackage,
    InterfaceMismatch,
    SenderEvidenceMismatch,
    ReceiverProvingFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExchangeDisposition {
    Quarantined,
    Rejected {
        code: RejectionCode,
        reason: String,
    },
    AwaitingApproval,
    ApprovalDenied {
        approval_id: String,
        reason: String,
    },
    Adopted {
        approval_id: String,
        activation_id: String,
    },
    Healthy {
        approval_id: String,
        activation_id: String,
        observation_id: String,
    },
    RolledBack {
        approval_id: String,
        activation_id: String,
        observation_id: String,
        rollback_id: String,
        restored_package_digest: ContentDigest,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub exchange_id: ContentDigest,
    pub package_digest: ContentDigest,
    pub principal_id: String,
    pub policy_digest: ContentDigest,
    pub approved: bool,
    pub reason: String,
    pub record_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostAdoptionReport {
    pub exchange_id: ContentDigest,
    pub package_digest: ContentDigest,
    pub observations: Vec<ExecutionObservation>,
    pub healthy: bool,
    pub report_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRecord {
    pub envelope_id: ContentDigest,
    pub route_id: String,
    pub sender_factory_id: String,
    pub receiver_factory_id: String,
    pub nonce: String,
    pub package_digest: ContentDigest,
    pub quarantined_envelope_digest: ContentDigest,
    pub quarantined_package_digest: ContentDigest,
    pub sender_lineage_digest: ContentDigest,
    pub sender_proving_digest: ContentDigest,
    pub receiver_proving: Option<ProvingEvidence>,
    pub approval: Option<ApprovalRecord>,
    pub post_adoption: Option<PostAdoptionReport>,
    pub disposition: ExchangeDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentExchangeRecord {
    pub nonce: String,
    pub envelope_id: ContentDigest,
    pub package_digest: ContentDigest,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedRevocation {
    pub revocation_id: ContentDigest,
    pub nonce: String,
    pub target: RevocationTarget,
    pub reason: String,
    pub applied_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PendingFactoryEffect {
    Activation {
        envelope_id: ContentDigest,
        approval: ApprovalRecord,
    },
    Rollback {
        envelope_id: ContentDigest,
        report: PostAdoptionReport,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M6FactoryState {
    pub schema_version: u32,
    pub profile: FactoryEndpointProfile,
    pub route_definition_digest: ContentDigest,
    pub active_package_digest: ContentDigest,
    pub active_exchange_id: Option<ContentDigest>,
    pub sent_exchanges: Vec<SentExchangeRecord>,
    pub exchanges: BTreeMap<String, ExchangeRecord>,
    pub sent_nonces: BTreeMap<String, ContentDigest>,
    pub received_nonces: BTreeMap<String, ContentDigest>,
    pub sent_revocation_nonces: BTreeMap<String, ContentDigest>,
    pub received_revocation_nonces: BTreeMap<String, ContentDigest>,
    pub revocations: Vec<AppliedRevocation>,
    pending_effect: Option<PendingFactoryEffect>,
    pub state_digest: ContentDigest,
}

impl M6FactoryState {
    fn seal(&mut self) -> Result<(), M6ExchangeError> {
        self.state_digest = self.expected_digest()?;
        Ok(())
    }

    fn validate(&self) -> Result<(), M6ExchangeError> {
        if self.schema_version != M6_FACTORY_STATE_SCHEMA_VERSION {
            return Err(M6ExchangeError::UnsupportedStateSchema(self.schema_version));
        }
        self.profile.validate()?;
        if self.sent_exchanges.len() > MAX_RECORDS
            || self.exchanges.len() > MAX_RECORDS
            || self.sent_nonces.len() > MAX_RECORDS
            || self.received_nonces.len() > MAX_RECORDS
            || self.sent_revocation_nonces.len() > MAX_RECORDS
            || self.received_revocation_nonces.len() > MAX_RECORDS
            || self.revocations.len() > MAX_RECORDS
        {
            return Err(M6ExchangeError::StateIntegrity(
                "durable M6 record budget exceeded".to_string(),
            ));
        }
        for (nonce, envelope_id) in &self.received_nonces {
            let record = self.exchanges.get(envelope_id.as_str()).ok_or_else(|| {
                M6ExchangeError::StateIntegrity(format!(
                    "received nonce '{nonce}' names a missing exchange"
                ))
            })?;
            if record.nonce != *nonce {
                return Err(M6ExchangeError::StateIntegrity(
                    "received nonce index differs from exchange lineage".to_string(),
                ));
            }
        }
        require_digest(
            "M6 factory state",
            &self.state_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6ExchangeError> {
        digest_serializable(&(
            "wasm-biotic:m6-factory-state:v1",
            self.schema_version,
            &self.profile,
            &self.route_definition_digest,
            &self.active_package_digest,
            &self.active_exchange_id,
            &self.sent_exchanges,
            &self.exchanges,
            &self.sent_nonces,
            &self.received_nonces,
            &self.sent_revocation_nonces,
            &self.received_revocation_nonces,
            &self.revocations,
            &self.pending_effect,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve { reason: String },
    Deny { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub approval_id: String,
    pub exchange_id: ContentDigest,
    pub decision: ApprovalDecision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdoptionReceipt {
    pub exchange_id: ContentDigest,
    pub package_digest: ContentDigest,
    pub previous_package_digest: ContentDigest,
    pub activation_id: String,
    pub approval_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationDisposition {
    Healthy(PostAdoptionReport),
    RolledBack {
        report: PostAdoptionReport,
        restored_package_digest: ContentDigest,
    },
}

/// One endpoint of the bounded M6 route.
///
/// The struct contains no peer-root path and exposes no operation that accepts
/// one. Its only shared filesystem dependency is [`GovernedFilesystemRoute`].
pub struct M6Factory {
    canonical_root: PathBuf,
    quarantine_root: PathBuf,
    outbound_root: PathBuf,
    route: GovernedFilesystemRoute,
    deployment: LocalDeploymentService,
    state: M6FactoryState,
}

impl M6Factory {
    pub fn initialize(
        root: impl AsRef<Path>,
        route: GovernedFilesystemRoute,
        profile: FactoryEndpointProfile,
        incumbent: FactoryPackage,
    ) -> Result<Self, M6ExchangeError> {
        profile.validate()?;
        incumbent
            .validate()
            .map_err(M6ExchangeError::reproduction)?;
        validate_profile_route(&profile, route.definition())?;
        let canonical_root = prepare_new_or_existing_directory(root.as_ref(), "factory root")?;
        ensure_disjoint_roots(&canonical_root, route.root())?;
        let state_path = canonical_root.join(FACTORY_STATE_FILE);
        if state_path.exists() {
            return Err(M6ExchangeError::AlreadyInitialized(
                "factory endpoint state already exists".to_string(),
            ));
        }
        if incumbent.payload.factory_id != profile.factory_id {
            return Err(M6ExchangeError::InvalidConfiguration(
                "incumbent package belongs to a different factory identity".to_string(),
            ));
        }
        let quarantine_root = canonical_root.join(QUARANTINE_DIRECTORY);
        let outbound_root = canonical_root.join(OUTBOUND_DIRECTORY);
        ensure_directory(&quarantine_root)?;
        ensure_directory(&outbound_root)?;
        let deployment_root = canonical_root.join(DEPLOYMENT_DIRECTORY);
        let deployment = LocalDeploymentService::open(&deployment_root, &canonical_root)
            .map_err(M6ExchangeError::deployment)?;
        let incumbent_bytes = incumbent
            .canonical_bytes()
            .map_err(M6ExchangeError::reproduction)?;
        let initialization = deployment
            .initialize_active("m6-initialize-incumbent", &incumbent_bytes)
            .map_err(M6ExchangeError::deployment)?;
        if initialization.installed_artifact.digest != incumbent.package_digest {
            return Err(M6ExchangeError::StateIntegrity(
                "deployment initialized bytes other than the incumbent package".to_string(),
            ));
        }
        let mut state = M6FactoryState {
            schema_version: M6_FACTORY_STATE_SCHEMA_VERSION,
            profile,
            route_definition_digest: route.definition.definition_digest.clone(),
            active_package_digest: incumbent.package_digest,
            active_exchange_id: None,
            sent_exchanges: Vec::new(),
            exchanges: BTreeMap::new(),
            sent_nonces: BTreeMap::new(),
            received_nonces: BTreeMap::new(),
            sent_revocation_nonces: BTreeMap::new(),
            received_revocation_nonces: BTreeMap::new(),
            revocations: Vec::new(),
            pending_effect: None,
            state_digest: ContentDigest::from_bytes(&[]),
        };
        state.seal()?;
        atomic_replace_json(&state_path, &state)?;
        Ok(Self {
            canonical_root,
            quarantine_root,
            outbound_root,
            route,
            deployment,
            state,
        })
    }

    pub fn open(
        root: impl AsRef<Path>,
        route: GovernedFilesystemRoute,
    ) -> Result<Self, M6ExchangeError> {
        let canonical_root = prepare_existing_directory(root.as_ref(), "factory root")?;
        ensure_disjoint_roots(&canonical_root, route.root())?;
        let state: M6FactoryState = read_json_bounded(
            &canonical_root.join(FACTORY_STATE_FILE),
            MAX_ROUTE_FILE_BYTES,
        )?;
        state.validate()?;
        validate_profile_route(&state.profile, route.definition())?;
        require_digest(
            "factory route binding",
            &state.route_definition_digest,
            &route.definition.definition_digest,
        )?;
        let quarantine_root = canonical_root.join(QUARANTINE_DIRECTORY);
        let outbound_root = canonical_root.join(OUTBOUND_DIRECTORY);
        ensure_existing_real_directory(&quarantine_root)?;
        ensure_existing_real_directory(&outbound_root)?;
        let deployment = LocalDeploymentService::open(
            canonical_root.join(DEPLOYMENT_DIRECTORY),
            &canonical_root,
        )
        .map_err(M6ExchangeError::deployment)?;
        let mut factory = Self {
            canonical_root,
            quarantine_root,
            outbound_root,
            route,
            deployment,
            state,
        };
        factory.recover_pending_effect()?;
        factory.verify_active_package()?;
        Ok(factory)
    }

    pub fn root(&self) -> &Path {
        &self.canonical_root
    }

    pub fn route_root(&self) -> &Path {
        self.route.root()
    }

    pub fn state(&self) -> &M6FactoryState {
        &self.state
    }

    pub fn active_package(&self) -> Result<FactoryPackage, M6ExchangeError> {
        let bytes = self
            .deployment
            .read_active_bytes()
            .map_err(M6ExchangeError::deployment)?;
        let package =
            FactoryPackage::from_canonical_bytes(&bytes).map_err(M6ExchangeError::reproduction)?;
        require_digest(
            "active package",
            &self.state.active_package_digest,
            &package.package_digest,
        )?;
        Ok(package)
    }

    pub fn execute_active(
        &self,
        input: i32,
    ) -> Result<ComponentI32ExecutionTrace, M6ExchangeError> {
        let package = self.active_package()?;
        execute_component_i32_export(
            &package.payload.genome.component_bytes,
            REFERENCE_EXPORT,
            input,
            &self.state.profile.policy.execution_limits,
        )
        .map_err(|error| M6ExchangeError::Component(error.to_string()))
    }

    /// Stages and activates an M5-produced package within the sender's own root.
    ///
    /// This does not generate a package; it makes an already validated package
    /// the exact local source artifact that a subsequent export may name.
    pub fn activate_local_package(
        &mut self,
        package: &FactoryPackage,
        authority: &AuthorityInvocation,
    ) -> Result<(), M6ExchangeError> {
        self.require_role(RouteEndpointRole::Sender)?;
        self.authorize(authority, AuthorityAction::ManageLocalPackage)?;
        package.validate().map_err(M6ExchangeError::reproduction)?;
        if package.payload.factory_id != self.state.profile.factory_id {
            return Err(M6ExchangeError::FalseIdentity {
                expected: self.state.profile.factory_id.clone(),
                actual: package.payload.factory_id.clone(),
            });
        }
        let bytes = package
            .canonical_bytes()
            .map_err(M6ExchangeError::reproduction)?;
        let directory = self.outbound_root.join(package.package_digest.file_stem());
        ensure_directory(&directory)?;
        let package_path = directory.join("package.bin");
        atomic_write_idempotent(&package_path, &bytes)?;
        let previous = self.state.active_package_digest.clone();
        if previous == package.package_digest {
            return Ok(());
        }
        let relative = package_path
            .strip_prefix(&self.canonical_root)
            .map_err(|_| M6ExchangeError::UnsafePath("outbound path escaped root".to_string()))?
            .to_path_buf();
        let operation_id = format!(
            "m6-local-activate-{}",
            short_digest(&package.package_digest)
        );
        self.deployment
            .activate(&ActivationRequest {
                operation_id,
                candidate_path: relative,
                expected_candidate_digest: package.package_digest.clone(),
                expected_active_digest: previous,
                approval_ref: self.state.profile.authority.envelope_digest.to_string(),
                comparison_ref: package.payload.boot_manifest.interface_digest.to_string(),
                observation_window_ref: self.state.profile.policy.policy_digest.to_string(),
            })
            .map_err(M6ExchangeError::deployment)?;
        self.state.active_package_digest = package.package_digest.clone();
        self.state.active_exchange_id = None;
        self.persist_state()
    }

    pub fn export_active(
        &mut self,
        request: ExportRequest,
        route_key: &[u8],
        authority: &AuthorityInvocation,
    ) -> Result<ExportReceipt, M6ExchangeError> {
        self.require_role(RouteEndpointRole::Sender)?;
        self.authorize(authority, AuthorityAction::ExportPackage)?;
        self.verify_route_key(route_key)?;
        validate_nonce(&request.nonce)?;
        validate_time_window(
            request.issued_at_ms,
            request.expires_at_ms,
            request.issued_at_ms,
            self.state.profile.policy.max_envelope_ttl_ms,
        )?;
        if self.state.sent_nonces.contains_key(&request.nonce) {
            return Err(M6ExchangeError::Replay {
                nonce: request.nonce,
            });
        }
        self.ensure_record_capacity()?;
        let package = self.active_package()?;
        if package.byte_len > self.state.profile.policy.max_package_bytes {
            return Err(M6ExchangeError::PolicyRejected(
                "active package exceeds sender export policy".to_string(),
            ));
        }
        let package_bytes = package
            .canonical_bytes()
            .map_err(M6ExchangeError::reproduction)?;
        let sender_proving = run_proving(
            &format!("sender:{}", self.state.profile.policy.policy_id),
            &package,
            &self.state.profile.policy.proving_cases,
            &self.state.profile.policy.execution_limits,
        )?;
        if !sender_proving.overall_pass {
            return Err(M6ExchangeError::SenderEvidenceMismatch(
                "sender proving did not pass its declared cases".to_string(),
            ));
        }
        let mut lineage = ExportLineageEvidence {
            source_factory_id: self.state.profile.factory_id.clone(),
            source_active_package_digest: self.state.active_package_digest.clone(),
            package_digest: package.package_digest.clone(),
            component_digest: package.payload.genome.component_digest.clone(),
            generation: package.payload.generation,
            parent_package_digest: package.payload.parent_package_digest.clone(),
            lineage_digest: ContentDigest::from_bytes(&[]),
        };
        lineage.lineage_digest = lineage_digest(&lineage)?;
        let payload = ExchangePayload {
            route_id: self.state.profile.route_id.clone(),
            sender_factory_id: self.state.profile.factory_id.clone(),
            receiver_factory_id: self.state.profile.peer_factory_id.clone(),
            nonce: request.nonce.clone(),
            issued_at_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
            package_digest: package.package_digest.clone(),
            package_bytes,
            lineage: lineage.clone(),
            sender_proving: sender_proving.clone(),
        };
        let envelope = sign_exchange(payload, route_key)?;
        self.route.enqueue_exchange(&envelope)?;
        self.state
            .sent_nonces
            .insert(request.nonce.clone(), envelope.envelope_id.clone());
        self.state.sent_exchanges.push(SentExchangeRecord {
            nonce: request.nonce,
            envelope_id: envelope.envelope_id.clone(),
            package_digest: package.package_digest.clone(),
            expires_at_ms: request.expires_at_ms,
        });
        self.persist_state()?;
        Ok(ExportReceipt {
            envelope_id: envelope.envelope_id,
            package_digest: package.package_digest,
            lineage_digest: lineage.lineage_digest,
            proving_digest: sender_proving.report_digest,
        })
    }

    pub fn issue_revocation(
        &mut self,
        request: RevocationRequest,
        route_key: &[u8],
        authority: &AuthorityInvocation,
    ) -> Result<RevocationReceipt, M6ExchangeError> {
        self.require_role(RouteEndpointRole::Sender)?;
        self.authorize(authority, AuthorityAction::IssueRevocation)?;
        self.verify_route_key(route_key)?;
        validate_nonce(&request.nonce)?;
        validate_identifier("revocation reason", &request.reason)?;
        validate_time_window(
            request.issued_at_ms,
            request.expires_at_ms,
            request.issued_at_ms,
            self.state.profile.policy.max_envelope_ttl_ms,
        )?;
        if self
            .state
            .sent_revocation_nonces
            .contains_key(&request.nonce)
        {
            return Err(M6ExchangeError::Replay {
                nonce: request.nonce,
            });
        }
        self.ensure_record_capacity()?;
        let payload = RevocationPayload {
            route_id: self.state.profile.route_id.clone(),
            sender_factory_id: self.state.profile.factory_id.clone(),
            receiver_factory_id: self.state.profile.peer_factory_id.clone(),
            nonce: request.nonce.clone(),
            issued_at_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
            target: request.target.clone(),
            reason: request.reason,
        };
        let envelope = sign_revocation(payload, route_key)?;
        self.route.enqueue_revocation(&envelope)?;
        self.state
            .sent_revocation_nonces
            .insert(request.nonce, envelope.revocation_id.clone());
        self.persist_state()?;
        Ok(RevocationReceipt {
            revocation_id: envelope.revocation_id,
            target: request.target,
        })
    }

    pub fn apply_revocation(
        &mut self,
        revocation_id: &ContentDigest,
        route_key: &[u8],
        now_ms: u64,
    ) -> Result<AppliedRevocation, M6ExchangeError> {
        self.require_role(RouteEndpointRole::Receiver)?;
        self.verify_route_key(route_key)?;
        let raw = self.route.read_revocation_bytes(revocation_id)?;
        let envelope: SignedRevocationEnvelope = parse_canonical(&raw)?;
        verify_revocation_envelope(
            &envelope,
            self.route.definition(),
            route_key,
            now_ms,
            self.state.profile.policy.max_envelope_ttl_ms,
        )?;
        if &envelope.revocation_id != revocation_id {
            return Err(M6ExchangeError::DigestMismatch {
                subject: "requested revocation".to_string(),
                expected: revocation_id.clone(),
                actual: envelope.revocation_id,
            });
        }
        if self
            .state
            .received_revocation_nonces
            .contains_key(&envelope.payload.nonce)
        {
            return Err(M6ExchangeError::Replay {
                nonce: envelope.payload.nonce,
            });
        }
        self.ensure_record_capacity()?;
        let applied = AppliedRevocation {
            revocation_id: revocation_id.clone(),
            nonce: envelope.payload.nonce.clone(),
            target: envelope.payload.target,
            reason: envelope.payload.reason,
            applied_at_ms: now_ms,
        };
        self.state
            .received_revocation_nonces
            .insert(applied.nonce.clone(), applied.revocation_id.clone());
        self.state.revocations.push(applied.clone());
        self.persist_state()?;
        Ok(applied)
    }

    /// Copies a route artifact into receiver-owned quarantine before any
    /// authentication, package validation, interface evaluation, or execution.
    pub fn receive(
        &mut self,
        envelope_id: &ContentDigest,
        route_key: &[u8],
        now_ms: u64,
    ) -> Result<ExchangeRecord, M6ExchangeError> {
        self.require_role(RouteEndpointRole::Receiver)?;
        self.verify_route_key(route_key)?;
        if self.state.exchanges.contains_key(envelope_id.as_str()) {
            let nonce = self
                .state
                .exchanges
                .get(envelope_id.as_str())
                .map(|record| record.nonce.clone())
                .unwrap_or_default();
            return Err(M6ExchangeError::Replay { nonce });
        }
        self.ensure_record_capacity()?;
        let raw = self.route.read_exchange_bytes(envelope_id)?;
        let envelope: SignedExchangeEnvelope = serde_json::from_slice(&raw)
            .map_err(|error| M6ExchangeError::Serialization(error.to_string()))?;
        let quarantine_directory = self.quarantine_root.join(envelope_id.file_stem());
        ensure_directory(&quarantine_directory)?;
        let quarantined_envelope_path = quarantine_directory.join("envelope.json");
        let quarantined_package_path = quarantine_directory.join("package.bin");
        atomic_write_idempotent(&quarantined_envelope_path, &raw)?;
        atomic_write_idempotent(&quarantined_package_path, &envelope.payload.package_bytes)?;
        let initial = ExchangeRecord {
            envelope_id: envelope_id.clone(),
            route_id: envelope.payload.route_id.clone(),
            sender_factory_id: envelope.payload.sender_factory_id.clone(),
            receiver_factory_id: envelope.payload.receiver_factory_id.clone(),
            nonce: envelope.payload.nonce.clone(),
            package_digest: envelope.payload.package_digest.clone(),
            quarantined_envelope_digest: ContentDigest::from_bytes(&raw),
            quarantined_package_digest: ContentDigest::from_bytes(&envelope.payload.package_bytes),
            sender_lineage_digest: envelope.payload.lineage.lineage_digest.clone(),
            sender_proving_digest: envelope.payload.sender_proving.report_digest.clone(),
            receiver_proving: None,
            approval: None,
            post_adoption: None,
            disposition: ExchangeDisposition::Quarantined,
        };
        self.state
            .exchanges
            .insert(envelope_id.as_str().to_string(), initial);
        self.persist_state()?;

        if canonical_json(&envelope)? != raw {
            return self.reject_exchange(
                envelope_id,
                RejectionCode::AuthenticationFailed,
                "route envelope is not in canonical representation",
                M6ExchangeError::AuthenticationFailed,
            );
        }
        if let Err(error) = verify_exchange_envelope(
            &envelope,
            self.route.definition(),
            route_key,
            now_ms,
            self.state.profile.policy.max_envelope_ttl_ms,
        ) {
            let (code, public_error) = rejection_for_verification_error(error);
            return self.reject_exchange(
                envelope_id,
                code,
                &public_error.to_string(),
                public_error,
            );
        }
        if &envelope.envelope_id != envelope_id {
            return self.reject_exchange(
                envelope_id,
                RejectionCode::AuthenticationFailed,
                "requested envelope identity differs from authenticated content",
                M6ExchangeError::AuthenticationFailed,
            );
        }
        if let Some(previous) = self.state.received_nonces.get(&envelope.payload.nonce) {
            return self.reject_exchange(
                envelope_id,
                RejectionCode::AuthenticationFailed,
                "authenticated nonce was already received",
                M6ExchangeError::Replay {
                    nonce: format!("{} ({previous})", envelope.payload.nonce),
                },
            );
        }
        self.state
            .received_nonces
            .insert(envelope.payload.nonce.clone(), envelope.envelope_id.clone());
        self.persist_state()?;

        if let Some(target) = self.matching_revocation(&envelope.payload) {
            return self.reject_exchange(
                envelope_id,
                RejectionCode::Revoked,
                "authenticated envelope matches a durable revocation",
                M6ExchangeError::Revoked(target),
            );
        }
        if envelope.payload.package_bytes.len() as u64 > self.state.profile.policy.max_package_bytes
        {
            return self.reject_exchange(
                envelope_id,
                RejectionCode::InvalidPackage,
                "package exceeds receiver policy byte bound",
                M6ExchangeError::PolicyRejected(
                    "package exceeds receiver policy byte bound".to_string(),
                ),
            );
        }
        let actual_package_digest = ContentDigest::from_bytes(&envelope.payload.package_bytes);
        if actual_package_digest != envelope.payload.package_digest {
            return self.reject_exchange(
                envelope_id,
                RejectionCode::PackageDigestMismatch,
                "exact package bytes differ from the declared SHA-256 identity",
                M6ExchangeError::DigestMismatch {
                    subject: "received package bytes".to_string(),
                    expected: envelope.payload.package_digest.clone(),
                    actual: actual_package_digest,
                },
            );
        }
        let raw_payload = match serde_json::from_slice::<FactoryPackagePayload>(
            &envelope.payload.package_bytes,
        ) {
            Ok(payload) => payload,
            Err(error) => {
                return self.reject_exchange(
                    envelope_id,
                    RejectionCode::InvalidPackage,
                    "package payload is not decodable",
                    M6ExchangeError::InvalidPackage(error.to_string()),
                );
            }
        };
        if raw_payload.stable_interface.interface_ref
            != self.state.profile.policy.accepted_interface_ref
            || raw_payload.boot_manifest.interface_digest
                != self.state.profile.policy.accepted_interface_digest
        {
            return self.reject_exchange(
                envelope_id,
                RejectionCode::InterfaceMismatch,
                "package interface is incompatible with receiver policy",
                M6ExchangeError::InterfaceMismatch {
                    expected: self.state.profile.policy.accepted_interface_ref.clone(),
                    actual: raw_payload.stable_interface.interface_ref,
                },
            );
        }
        let package = match FactoryPackage::from_canonical_bytes(&envelope.payload.package_bytes) {
            Ok(package) => package,
            Err(error) => {
                return self.reject_exchange(
                    envelope_id,
                    RejectionCode::InvalidPackage,
                    "FactoryPackage validation rejected the exact bytes",
                    M6ExchangeError::InvalidPackage(error.to_string()),
                );
            }
        };
        if package.payload.factory_id != envelope.payload.sender_factory_id {
            return self.reject_exchange(
                envelope_id,
                RejectionCode::FalseIdentity,
                "package factory identity differs from authenticated sender",
                M6ExchangeError::FalseIdentity {
                    expected: envelope.payload.sender_factory_id.clone(),
                    actual: package.payload.factory_id,
                },
            );
        }
        if let Err(error) = validate_sender_evidence(&envelope.payload, &package) {
            return self.reject_exchange(
                envelope_id,
                RejectionCode::SenderEvidenceMismatch,
                "sender lineage or proving evidence is not bound to the package",
                error,
            );
        }
        let receiver_proving = run_proving(
            &format!("receiver:{}", self.state.profile.policy.policy_id),
            &package,
            &self.state.profile.policy.proving_cases,
            &self.state.profile.policy.execution_limits,
        )?;
        if !receiver_proving.overall_pass {
            return self.reject_exchange(
                envelope_id,
                RejectionCode::ReceiverProvingFailed,
                "receiver-owned proving rejected the quarantined component",
                M6ExchangeError::ReceiverProvingFailed,
            );
        }
        let record = self
            .state
            .exchanges
            .get_mut(envelope_id.as_str())
            .ok_or_else(|| {
                M6ExchangeError::StateIntegrity(
                    "quarantine record disappeared during evaluation".to_string(),
                )
            })?;
        record.receiver_proving = Some(receiver_proving);
        record.disposition = ExchangeDisposition::AwaitingApproval;
        let result = record.clone();
        self.persist_state()?;
        Ok(result)
    }

    pub fn approve_and_adopt(
        &mut self,
        request: ApprovalRequest,
        authority: &AuthorityInvocation,
    ) -> Result<AdoptionReceipt, M6ExchangeError> {
        self.require_role(RouteEndpointRole::Receiver)?;
        self.authorize(authority, AuthorityAction::DisposeQuarantine)?;
        validate_identifier("approval id", &request.approval_id)?;
        let existing = self
            .state
            .exchanges
            .get(request.exchange_id.as_str())
            .cloned()
            .ok_or_else(|| M6ExchangeError::UnknownExchange(request.exchange_id.clone()))?;
        if !matches!(existing.disposition, ExchangeDisposition::AwaitingApproval) {
            return Err(M6ExchangeError::InvalidDisposition {
                envelope_id: request.exchange_id,
                expected: "awaiting_approval",
                actual: disposition_name(&existing.disposition),
            });
        }
        let (approved, reason) = match request.decision {
            ApprovalDecision::Approve { reason } => {
                self.authorize(authority, AuthorityAction::ActivateImport)?;
                (true, reason)
            }
            ApprovalDecision::Deny { reason } => (false, reason),
        };
        validate_identifier("approval reason", &reason)?;
        let mut approval = ApprovalRecord {
            approval_id: request.approval_id.clone(),
            exchange_id: existing.envelope_id.clone(),
            package_digest: existing.package_digest.clone(),
            principal_id: authority.principal_id.clone(),
            policy_digest: self.state.profile.policy.policy_digest.clone(),
            approved,
            reason: reason.clone(),
            record_digest: ContentDigest::from_bytes(&[]),
        };
        approval.record_digest = approval_record_digest(&approval)?;
        if !approved {
            let record = self
                .state
                .exchanges
                .get_mut(existing.envelope_id.as_str())
                .ok_or_else(|| M6ExchangeError::UnknownExchange(existing.envelope_id.clone()))?;
            record.approval = Some(approval);
            record.disposition = ExchangeDisposition::ApprovalDenied {
                approval_id: request.approval_id,
                reason,
            };
            self.persist_state()?;
            return Err(M6ExchangeError::ApprovalDenied(existing.envelope_id));
        }
        self.state.pending_effect = Some(PendingFactoryEffect::Activation {
            envelope_id: existing.envelope_id.clone(),
            approval: approval.clone(),
        });
        self.persist_state()?;
        self.complete_pending_activation(&existing.envelope_id, &approval)
    }

    /// An exchange can be executed only after its exact bytes are the active
    /// receiver deployment. Quarantine and approval status alone are
    /// insufficient.
    pub fn execute_exchange(
        &self,
        envelope_id: &ContentDigest,
        input: i32,
    ) -> Result<ComponentI32ExecutionTrace, M6ExchangeError> {
        let record = self
            .state
            .exchanges
            .get(envelope_id.as_str())
            .ok_or_else(|| M6ExchangeError::UnknownExchange(envelope_id.clone()))?;
        if !matches!(
            record.disposition,
            ExchangeDisposition::Adopted { .. } | ExchangeDisposition::Healthy { .. }
        ) || self.state.active_exchange_id.as_ref() != Some(envelope_id)
            || self.state.active_package_digest != record.package_digest
        {
            return Err(M6ExchangeError::PreDispositionExecutionDenied(
                envelope_id.clone(),
            ));
        }
        self.execute_active(input)
    }

    pub fn observe_adoption(
        &mut self,
        envelope_id: &ContentDigest,
        authority: &AuthorityInvocation,
    ) -> Result<ObservationDisposition, M6ExchangeError> {
        self.require_role(RouteEndpointRole::Receiver)?;
        self.authorize(authority, AuthorityAction::ObserveImport)?;
        let record = self
            .state
            .exchanges
            .get(envelope_id.as_str())
            .cloned()
            .ok_or_else(|| M6ExchangeError::UnknownExchange(envelope_id.clone()))?;
        let (approval_id, activation_id) = match &record.disposition {
            ExchangeDisposition::Adopted {
                approval_id,
                activation_id,
            } => (approval_id.clone(), activation_id.clone()),
            _ => {
                return Err(M6ExchangeError::InvalidDisposition {
                    envelope_id: envelope_id.clone(),
                    expected: "adopted",
                    actual: disposition_name(&record.disposition),
                });
            }
        };
        if self.state.active_exchange_id.as_ref() != Some(envelope_id) {
            return Err(M6ExchangeError::PreDispositionExecutionDenied(
                envelope_id.clone(),
            ));
        }
        let package = self.active_package()?;
        let proving = run_proving(
            &format!(
                "post-adoption:{}:{}",
                self.state.profile.policy.policy_id,
                short_digest(envelope_id)
            ),
            &package,
            &self.state.profile.policy.post_adoption_cases,
            &self.state.profile.policy.execution_limits,
        )?;
        let mut report = PostAdoptionReport {
            exchange_id: envelope_id.clone(),
            package_digest: package.package_digest.clone(),
            observations: proving.observations,
            healthy: proving.overall_pass,
            report_digest: ContentDigest::from_bytes(&[]),
        };
        report.report_digest = post_adoption_report_digest(&report)?;
        let observation_id = format!("m6-observe-{}", short_digest(envelope_id));
        let evidence = canonical_json(&report)?;
        self.deployment
            .record_observation(
                &ObservationRequest {
                    observation_id: observation_id.clone(),
                    activation_id: activation_id.clone(),
                    expected_active_digest: package.package_digest.clone(),
                    outcome: if report.healthy {
                        ObservationOutcome::Healthy
                    } else {
                        ObservationOutcome::Regressed
                    },
                    summary: if report.healthy {
                        "receiver-owned post-adoption proving passed".to_string()
                    } else {
                        "receiver-owned post-adoption proving failed".to_string()
                    },
                },
                &evidence,
            )
            .map_err(M6ExchangeError::deployment)?;
        if report.healthy {
            let mutable = self
                .state
                .exchanges
                .get_mut(envelope_id.as_str())
                .ok_or_else(|| M6ExchangeError::UnknownExchange(envelope_id.clone()))?;
            mutable.post_adoption = Some(report.clone());
            mutable.disposition = ExchangeDisposition::Healthy {
                approval_id,
                activation_id,
                observation_id,
            };
            self.persist_state()?;
            return Ok(ObservationDisposition::Healthy(report));
        }
        self.authorize(authority, AuthorityAction::RollbackImport)?;
        self.state.pending_effect = Some(PendingFactoryEffect::Rollback {
            envelope_id: envelope_id.clone(),
            report: report.clone(),
        });
        self.persist_state()?;
        self.complete_pending_rollback(envelope_id, &report)
    }

    fn complete_pending_activation(
        &mut self,
        envelope_id: &ContentDigest,
        approval: &ApprovalRecord,
    ) -> Result<AdoptionReceipt, M6ExchangeError> {
        let record = self
            .state
            .exchanges
            .get(envelope_id.as_str())
            .cloned()
            .ok_or_else(|| M6ExchangeError::UnknownExchange(envelope_id.clone()))?;
        let proving = record.receiver_proving.as_ref().ok_or_else(|| {
            M6ExchangeError::StateIntegrity(
                "activation pending without receiver proving evidence".to_string(),
            )
        })?;
        if !proving.overall_pass
            || proving.package_digest != record.package_digest
            || approval.exchange_id != *envelope_id
            || approval.package_digest != record.package_digest
            || !approval.approved
        {
            return Err(M6ExchangeError::StateIntegrity(
                "pending activation is not bound to proving and approval".to_string(),
            ));
        }
        require_digest(
            "activation approval",
            &approval.record_digest,
            &approval_record_digest(approval)?,
        )?;
        let candidate_path = self
            .quarantine_root
            .join(envelope_id.file_stem())
            .join("package.bin");
        let candidate_bytes = read_bounded(&candidate_path, MAX_ROUTE_FILE_BYTES)?;
        require_digest(
            "quarantined activation bytes",
            &record.package_digest,
            &ContentDigest::from_bytes(&candidate_bytes),
        )?;
        let previous_package_digest = self.state.active_package_digest.clone();
        let relative_path = candidate_path
            .strip_prefix(&self.canonical_root)
            .map_err(|_| M6ExchangeError::UnsafePath("quarantine path escaped root".to_string()))?
            .to_path_buf();
        let activation_id = format!("m6-adopt-{}", short_digest(envelope_id));
        let activation = self
            .deployment
            .activate(&ActivationRequest {
                operation_id: activation_id.clone(),
                candidate_path: relative_path,
                expected_candidate_digest: record.package_digest.clone(),
                expected_active_digest: previous_package_digest.clone(),
                approval_ref: approval.record_digest.to_string(),
                comparison_ref: proving.report_digest.to_string(),
                observation_window_ref: self.state.profile.policy.policy_digest.to_string(),
            })
            .map_err(M6ExchangeError::deployment)?;
        if activation.activated_artifact.digest != record.package_digest
            || activation.previous_artifact.digest != previous_package_digest
        {
            return Err(M6ExchangeError::StateIntegrity(
                "deployment activation differs from exact approved byte lineage".to_string(),
            ));
        }
        let mutable = self
            .state
            .exchanges
            .get_mut(envelope_id.as_str())
            .ok_or_else(|| M6ExchangeError::UnknownExchange(envelope_id.clone()))?;
        mutable.approval = Some(approval.clone());
        mutable.disposition = ExchangeDisposition::Adopted {
            approval_id: approval.approval_id.clone(),
            activation_id: activation_id.clone(),
        };
        self.state.active_package_digest = record.package_digest.clone();
        self.state.active_exchange_id = Some(envelope_id.clone());
        self.state.pending_effect = None;
        self.persist_state()?;
        Ok(AdoptionReceipt {
            exchange_id: envelope_id.clone(),
            package_digest: record.package_digest,
            previous_package_digest,
            activation_id,
            approval_digest: approval.record_digest.clone(),
        })
    }

    fn complete_pending_rollback(
        &mut self,
        envelope_id: &ContentDigest,
        report: &PostAdoptionReport,
    ) -> Result<ObservationDisposition, M6ExchangeError> {
        let record = self
            .state
            .exchanges
            .get(envelope_id.as_str())
            .cloned()
            .ok_or_else(|| M6ExchangeError::UnknownExchange(envelope_id.clone()))?;
        let (approval_id, activation_id) = match &record.disposition {
            ExchangeDisposition::Adopted {
                approval_id,
                activation_id,
            } => (approval_id.clone(), activation_id.clone()),
            _ => {
                return Err(M6ExchangeError::InvalidDisposition {
                    envelope_id: envelope_id.clone(),
                    expected: "adopted",
                    actual: disposition_name(&record.disposition),
                });
            }
        };
        require_digest(
            "post-adoption report",
            &report.report_digest,
            &post_adoption_report_digest(report)?,
        )?;
        if report.healthy || report.exchange_id != *envelope_id {
            return Err(M6ExchangeError::StateIntegrity(
                "rollback pending without a failing bound observation".to_string(),
            ));
        }
        let rollback_id = format!("m6-rollback-{}", short_digest(envelope_id));
        let rollback = self
            .deployment
            .rollback(&RollbackRequest {
                operation_id: rollback_id.clone(),
                activation_id: activation_id.clone(),
                reason_ref: report.report_digest.to_string(),
            })
            .map_err(M6ExchangeError::deployment)?;
        if rollback.from_artifact.digest != record.package_digest {
            return Err(M6ExchangeError::StateIntegrity(
                "rollback did not start from the adopted package".to_string(),
            ));
        }
        let observation_id = format!("m6-observe-{}", short_digest(envelope_id));
        let restored = rollback.restored_artifact.digest;
        let mutable = self
            .state
            .exchanges
            .get_mut(envelope_id.as_str())
            .ok_or_else(|| M6ExchangeError::UnknownExchange(envelope_id.clone()))?;
        mutable.post_adoption = Some(report.clone());
        mutable.disposition = ExchangeDisposition::RolledBack {
            approval_id,
            activation_id,
            observation_id,
            rollback_id,
            restored_package_digest: restored.clone(),
        };
        self.state.active_package_digest = restored.clone();
        self.state.active_exchange_id = self
            .state
            .exchanges
            .values()
            .find(|candidate| {
                candidate.package_digest == restored
                    && matches!(
                        candidate.disposition,
                        ExchangeDisposition::Adopted { .. } | ExchangeDisposition::Healthy { .. }
                    )
            })
            .map(|candidate| candidate.envelope_id.clone());
        self.state.pending_effect = None;
        self.persist_state()?;
        Ok(ObservationDisposition::RolledBack {
            report: report.clone(),
            restored_package_digest: restored,
        })
    }

    fn recover_pending_effect(&mut self) -> Result<(), M6ExchangeError> {
        let Some(pending) = self.state.pending_effect.clone() else {
            return Ok(());
        };
        match pending {
            PendingFactoryEffect::Activation {
                envelope_id,
                approval,
            } => {
                self.complete_pending_activation(&envelope_id, &approval)?;
            }
            PendingFactoryEffect::Rollback {
                envelope_id,
                report,
            } => {
                self.complete_pending_rollback(&envelope_id, &report)?;
            }
        }
        Ok(())
    }

    fn reject_exchange(
        &mut self,
        envelope_id: &ContentDigest,
        code: RejectionCode,
        reason: &str,
        error: M6ExchangeError,
    ) -> Result<ExchangeRecord, M6ExchangeError> {
        let record = self
            .state
            .exchanges
            .get_mut(envelope_id.as_str())
            .ok_or_else(|| M6ExchangeError::UnknownExchange(envelope_id.clone()))?;
        record.disposition = ExchangeDisposition::Rejected {
            code,
            reason: reason.to_string(),
        };
        self.persist_state()?;
        Err(error)
    }

    fn matching_revocation(&self, payload: &ExchangePayload) -> Option<RevocationTarget> {
        self.state.revocations.iter().find_map(|revocation| {
            let matches = match &revocation.target {
                RevocationTarget::SenderIdentity(sender) => sender == &payload.sender_factory_id,
                RevocationTarget::PackageDigest(digest) => digest == &payload.package_digest,
                RevocationTarget::EnvelopeId(digest) => {
                    exchange_payload_digest(payload).as_ref().ok() == Some(digest)
                }
                RevocationTarget::Nonce(nonce) => nonce == &payload.nonce,
            };
            matches.then(|| revocation.target.clone())
        })
    }

    fn require_role(&self, expected: RouteEndpointRole) -> Result<(), M6ExchangeError> {
        if self.state.profile.endpoint_role != expected {
            return Err(M6ExchangeError::WrongEndpointRole {
                expected,
                actual: self.state.profile.endpoint_role,
            });
        }
        Ok(())
    }

    fn authorize(
        &self,
        invocation: &AuthorityInvocation,
        expected_action: AuthorityAction,
    ) -> Result<(), M6ExchangeError> {
        let authority = &self.state.profile.authority;
        if invocation.envelope_id != authority.envelope_id
            || invocation.principal_id != authority.principal_id
            || invocation.resource_scope != authority.resource_scope
            || !authority.permitted_actions.contains(&expected_action)
        {
            return Err(M6ExchangeError::AuthorityDenied {
                action: expected_action,
            });
        }
        Ok(())
    }

    fn verify_route_key(&self, route_key: &[u8]) -> Result<(), M6ExchangeError> {
        validate_route_key(route_key)?;
        let actual = route_key_fingerprint(route_key);
        if actual != self.route.definition.key_fingerprint {
            return Err(M6ExchangeError::RouteKeyMismatch);
        }
        Ok(())
    }

    fn verify_active_package(&self) -> Result<(), M6ExchangeError> {
        let deployment = self
            .deployment
            .active_artifact()
            .map_err(M6ExchangeError::deployment)?
            .ok_or_else(|| {
                M6ExchangeError::StateIntegrity("deployment is not initialized".to_string())
            })?;
        require_digest(
            "active deployment state",
            &self.state.active_package_digest,
            &deployment.digest,
        )?;
        self.active_package().map(|_| ())
    }

    fn ensure_record_capacity(&self) -> Result<(), M6ExchangeError> {
        if self.state.sent_exchanges.len() >= MAX_RECORDS
            || self.state.exchanges.len() >= MAX_RECORDS
            || self.state.revocations.len() >= MAX_RECORDS
        {
            return Err(M6ExchangeError::StateIntegrity(
                "M6 durable record budget is full".to_string(),
            ));
        }
        Ok(())
    }

    fn persist_state(&mut self) -> Result<(), M6ExchangeError> {
        self.state.seal()?;
        self.state.validate()?;
        atomic_replace_json(&self.canonical_root.join(FACTORY_STATE_FILE), &self.state)
    }
}

fn validate_profile_route(
    profile: &FactoryEndpointProfile,
    route: &RouteDefinition,
) -> Result<(), M6ExchangeError> {
    route.validate()?;
    if profile.route_id != route.route_id {
        return Err(M6ExchangeError::InvalidConfiguration(
            "factory profile names a different route".to_string(),
        ));
    }
    let (expected_self, expected_peer) = match profile.endpoint_role {
        RouteEndpointRole::Sender => (&route.sender_factory_id, &route.receiver_factory_id),
        RouteEndpointRole::Receiver => (&route.receiver_factory_id, &route.sender_factory_id),
    };
    if &profile.factory_id != expected_self || &profile.peer_factory_id != expected_peer {
        return Err(M6ExchangeError::InvalidConfiguration(
            "factory identity, peer, and endpoint role differ from route definition".to_string(),
        ));
    }
    Ok(())
}

fn run_proving(
    suite_id: &str,
    package: &FactoryPackage,
    cases: &[ProvingCase],
    limits: &ComponentExecutionLimits,
) -> Result<ProvingEvidence, M6ExchangeError> {
    validate_identifier("proving suite id", suite_id)?;
    validate_cases("proving", cases)?;
    package.validate().map_err(M6ExchangeError::reproduction)?;
    let mut observations = Vec::with_capacity(cases.len());
    for case in cases {
        let trace = execute_component_i32_export(
            &package.payload.genome.component_bytes,
            REFERENCE_EXPORT,
            case.input,
            limits,
        )
        .map_err(|error| M6ExchangeError::Component(error.to_string()))?;
        let actual_output = trace.output;
        let passed = !trace.trapped && actual_output == Some(case.expected_output);
        observations.push(ExecutionObservation {
            case_id: case.case_id.clone(),
            input: case.input,
            expected_output: case.expected_output,
            actual_output,
            passed,
            trace_digest: digest_serializable(&("wasm-biotic:m6-component-trace:v1", &trace))?,
        });
    }
    let mut evidence = ProvingEvidence {
        suite_id: suite_id.to_string(),
        package_digest: package.package_digest.clone(),
        component_digest: package.payload.genome.component_digest.clone(),
        interface_digest: package.payload.boot_manifest.interface_digest.clone(),
        overall_pass: observations.iter().all(|observation| observation.passed),
        observations,
        report_digest: ContentDigest::from_bytes(&[]),
    };
    evidence.report_digest = proving_report_digest(&evidence)?;
    Ok(evidence)
}

fn validate_sender_evidence(
    payload: &ExchangePayload,
    package: &FactoryPackage,
) -> Result<(), M6ExchangeError> {
    payload.lineage.validate_digest()?;
    payload.sender_proving.validate_digest()?;
    let lineage = &payload.lineage;
    if lineage.source_factory_id != payload.sender_factory_id
        || lineage.source_active_package_digest != payload.package_digest
        || lineage.package_digest != payload.package_digest
        || lineage.component_digest != package.payload.genome.component_digest
        || lineage.generation != package.payload.generation
        || lineage.parent_package_digest != package.payload.parent_package_digest
    {
        return Err(M6ExchangeError::SenderEvidenceMismatch(
            "export lineage differs from the exact package".to_string(),
        ));
    }
    let proving = &payload.sender_proving;
    if proving.package_digest != payload.package_digest
        || proving.component_digest != package.payload.genome.component_digest
        || proving.interface_digest != package.payload.boot_manifest.interface_digest
        || !proving.overall_pass
        || proving.observations.is_empty()
        || proving.observations.iter().any(|item| !item.passed)
    {
        return Err(M6ExchangeError::SenderEvidenceMismatch(
            "sender proving is incomplete, failing, or bound to different bytes".to_string(),
        ));
    }
    Ok(())
}

fn sign_exchange(
    payload: ExchangePayload,
    route_key: &[u8],
) -> Result<SignedExchangeEnvelope, M6ExchangeError> {
    validate_route_key(route_key)?;
    let envelope_id = exchange_payload_digest(&payload)?;
    let core = (M6_EXCHANGE_SCHEMA, &envelope_id, &payload);
    let tag = hmac_tag(route_key, &canonical_json(&core)?);
    Ok(SignedExchangeEnvelope {
        schema: M6_EXCHANGE_SCHEMA.to_string(),
        envelope_id,
        payload,
        authentication: RouteAuthentication {
            algorithm: "hmac-sha256".to_string(),
            key_fingerprint: route_key_fingerprint(route_key),
            tag,
        },
    })
}

fn verify_exchange_envelope(
    envelope: &SignedExchangeEnvelope,
    route: &RouteDefinition,
    route_key: &[u8],
    now_ms: u64,
    max_ttl_ms: u64,
) -> Result<(), M6ExchangeError> {
    if envelope.schema != M6_EXCHANGE_SCHEMA {
        return Err(M6ExchangeError::UnsupportedSchema(envelope.schema.clone()));
    }
    verify_route_authentication(
        &envelope.authentication,
        route_key,
        &canonical_json(&(M6_EXCHANGE_SCHEMA, &envelope.envelope_id, &envelope.payload))?,
        &route.key_fingerprint,
    )?;
    let expected_id = exchange_payload_digest(&envelope.payload)?;
    require_digest("exchange envelope", &envelope.envelope_id, &expected_id)?;
    verify_payload_route(
        &envelope.payload.route_id,
        &envelope.payload.sender_factory_id,
        &envelope.payload.receiver_factory_id,
        route,
    )?;
    validate_nonce(&envelope.payload.nonce)?;
    validate_time_window(
        envelope.payload.issued_at_ms,
        envelope.payload.expires_at_ms,
        now_ms,
        max_ttl_ms,
    )
}

fn sign_revocation(
    payload: RevocationPayload,
    route_key: &[u8],
) -> Result<SignedRevocationEnvelope, M6ExchangeError> {
    validate_route_key(route_key)?;
    let revocation_id = revocation_payload_digest(&payload)?;
    let tag = hmac_tag(
        route_key,
        &canonical_json(&(M6_REVOCATION_SCHEMA, &revocation_id, &payload))?,
    );
    Ok(SignedRevocationEnvelope {
        schema: M6_REVOCATION_SCHEMA.to_string(),
        revocation_id,
        payload,
        authentication: RouteAuthentication {
            algorithm: "hmac-sha256".to_string(),
            key_fingerprint: route_key_fingerprint(route_key),
            tag,
        },
    })
}

fn verify_revocation_envelope(
    envelope: &SignedRevocationEnvelope,
    route: &RouteDefinition,
    route_key: &[u8],
    now_ms: u64,
    max_ttl_ms: u64,
) -> Result<(), M6ExchangeError> {
    if envelope.schema != M6_REVOCATION_SCHEMA {
        return Err(M6ExchangeError::UnsupportedSchema(envelope.schema.clone()));
    }
    verify_route_authentication(
        &envelope.authentication,
        route_key,
        &canonical_json(&(
            M6_REVOCATION_SCHEMA,
            &envelope.revocation_id,
            &envelope.payload,
        ))?,
        &route.key_fingerprint,
    )?;
    require_digest(
        "revocation envelope",
        &envelope.revocation_id,
        &revocation_payload_digest(&envelope.payload)?,
    )?;
    verify_payload_route(
        &envelope.payload.route_id,
        &envelope.payload.sender_factory_id,
        &envelope.payload.receiver_factory_id,
        route,
    )?;
    validate_nonce(&envelope.payload.nonce)?;
    validate_identifier("revocation reason", &envelope.payload.reason)?;
    validate_time_window(
        envelope.payload.issued_at_ms,
        envelope.payload.expires_at_ms,
        now_ms,
        max_ttl_ms,
    )
}

fn verify_payload_route(
    route_id: &str,
    sender_factory_id: &str,
    receiver_factory_id: &str,
    route: &RouteDefinition,
) -> Result<(), M6ExchangeError> {
    if route_id != route.route_id {
        return Err(M6ExchangeError::FalseIdentity {
            expected: route.route_id.clone(),
            actual: route_id.to_string(),
        });
    }
    if sender_factory_id != route.sender_factory_id {
        return Err(M6ExchangeError::FalseIdentity {
            expected: route.sender_factory_id.clone(),
            actual: sender_factory_id.to_string(),
        });
    }
    if receiver_factory_id != route.receiver_factory_id {
        return Err(M6ExchangeError::FalseIdentity {
            expected: route.receiver_factory_id.clone(),
            actual: receiver_factory_id.to_string(),
        });
    }
    Ok(())
}

fn verify_route_authentication(
    authentication: &RouteAuthentication,
    route_key: &[u8],
    authenticated_bytes: &[u8],
    expected_fingerprint: &ContentDigest,
) -> Result<(), M6ExchangeError> {
    validate_route_key(route_key)?;
    if authentication.algorithm != "hmac-sha256"
        || &authentication.key_fingerprint != expected_fingerprint
        || route_key_fingerprint(route_key) != *expected_fingerprint
    {
        return Err(M6ExchangeError::AuthenticationFailed);
    }
    let expected = hmac_tag(route_key, authenticated_bytes);
    if !constant_time_equal(expected.as_bytes(), authentication.tag.as_bytes()) {
        return Err(M6ExchangeError::AuthenticationFailed);
    }
    Ok(())
}

fn rejection_for_verification_error(error: M6ExchangeError) -> (RejectionCode, M6ExchangeError) {
    let code = match error {
        M6ExchangeError::FalseIdentity { .. } => RejectionCode::FalseIdentity,
        M6ExchangeError::Expired { .. } => RejectionCode::Expired,
        _ => RejectionCode::AuthenticationFailed,
    };
    (code, error)
}

fn exchange_payload_digest(payload: &ExchangePayload) -> Result<ContentDigest, M6ExchangeError> {
    digest_serializable(&("wasm-biotic:m6-exchange-payload:v1", payload))
}

fn revocation_payload_digest(
    payload: &RevocationPayload,
) -> Result<ContentDigest, M6ExchangeError> {
    digest_serializable(&("wasm-biotic:m6-revocation-payload:v1", payload))
}

fn lineage_digest(lineage: &ExportLineageEvidence) -> Result<ContentDigest, M6ExchangeError> {
    digest_serializable(&(
        "wasm-biotic:m6-export-lineage:v1",
        &lineage.source_factory_id,
        &lineage.source_active_package_digest,
        &lineage.package_digest,
        &lineage.component_digest,
        lineage.generation,
        &lineage.parent_package_digest,
    ))
}

fn proving_report_digest(evidence: &ProvingEvidence) -> Result<ContentDigest, M6ExchangeError> {
    digest_serializable(&(
        "wasm-biotic:m6-proving-evidence:v1",
        &evidence.suite_id,
        &evidence.package_digest,
        &evidence.component_digest,
        &evidence.interface_digest,
        &evidence.observations,
        evidence.overall_pass,
    ))
}

fn approval_record_digest(record: &ApprovalRecord) -> Result<ContentDigest, M6ExchangeError> {
    digest_serializable(&(
        "wasm-biotic:m6-approval:v1",
        &record.approval_id,
        &record.exchange_id,
        &record.package_digest,
        &record.principal_id,
        &record.policy_digest,
        record.approved,
        &record.reason,
    ))
}

fn post_adoption_report_digest(
    report: &PostAdoptionReport,
) -> Result<ContentDigest, M6ExchangeError> {
    digest_serializable(&(
        "wasm-biotic:m6-post-adoption:v1",
        &report.exchange_id,
        &report.package_digest,
        &report.observations,
        report.healthy,
    ))
}

fn route_key_fingerprint(route_key: &[u8]) -> ContentDigest {
    let mut bytes = b"wasm-biotic:m6-route-key-fingerprint:v1\0".to_vec();
    bytes.extend_from_slice(route_key);
    ContentDigest::from_bytes(&bytes)
}

fn hmac_tag(key: &[u8], message: &[u8]) -> String {
    let mut normalized = [0_u8; HMAC_BLOCK_BYTES];
    if key.len() > HMAC_BLOCK_BYTES {
        let digest = Sha256::digest(key);
        normalized[..digest.len()].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for index in 0..HMAC_BLOCK_BYTES {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    format!("hmac-sha256:{:x}", outer.finalize())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn validate_route_key(route_key: &[u8]) -> Result<(), M6ExchangeError> {
    if route_key.len() < MIN_ROUTE_KEY_BYTES {
        return Err(M6ExchangeError::InvalidConfiguration(format!(
            "route key must contain at least {MIN_ROUTE_KEY_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_cases(label: &str, cases: &[ProvingCase]) -> Result<(), M6ExchangeError> {
    if cases.is_empty() || cases.len() > 256 {
        return Err(M6ExchangeError::InvalidConfiguration(format!(
            "{label} must contain between 1 and 256 cases"
        )));
    }
    let mut ids = BTreeSet::new();
    for case in cases {
        validate_identifier("proving case id", &case.case_id)?;
        if !ids.insert(case.case_id.as_str()) {
            return Err(M6ExchangeError::InvalidConfiguration(format!(
                "{label} contains duplicate case id '{}'",
                case.case_id
            )));
        }
    }
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<(), M6ExchangeError> {
    validate_identifier("route nonce", nonce)?;
    if nonce.len() > 256 {
        return Err(M6ExchangeError::InvalidConfiguration(
            "route nonce exceeds 256 bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_time_window(
    issued_at_ms: u64,
    expires_at_ms: u64,
    now_ms: u64,
    max_ttl_ms: u64,
) -> Result<(), M6ExchangeError> {
    if expires_at_ms <= issued_at_ms || expires_at_ms.saturating_sub(issued_at_ms) > max_ttl_ms {
        return Err(M6ExchangeError::InvalidConfiguration(
            "route envelope expiry is outside the configured TTL bound".to_string(),
        ));
    }
    if issued_at_ms > now_ms.saturating_add(CLOCK_SKEW_MS) || now_ms > expires_at_ms {
        return Err(M6ExchangeError::Expired {
            issued_at_ms,
            expires_at_ms,
            now_ms,
        });
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), M6ExchangeError> {
    if value.trim().is_empty()
        || value.len() > 512
        || value
            .chars()
            .any(|character| character.is_control() || character == '\0')
    {
        return Err(M6ExchangeError::InvalidConfiguration(format!(
            "{field} is blank, too long, or contains control characters"
        )));
    }
    Ok(())
}

fn require_digest(
    subject: &str,
    expected: &ContentDigest,
    actual: &ContentDigest,
) -> Result<(), M6ExchangeError> {
    if expected != actual {
        return Err(M6ExchangeError::DigestMismatch {
            subject: subject.to_string(),
            expected: expected.clone(),
            actual: actual.clone(),
        });
    }
    Ok(())
}

fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Result<ContentDigest, M6ExchangeError> {
    Ok(ContentDigest::from_bytes(&canonical_json(value)?))
}

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, M6ExchangeError> {
    serde_json::to_vec(value).map_err(|error| M6ExchangeError::Serialization(error.to_string()))
}

fn parse_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, M6ExchangeError> {
    let value = serde_json::from_slice::<T>(bytes)
        .map_err(|error| M6ExchangeError::Serialization(error.to_string()))?;
    if canonical_json(&value)? != bytes {
        return Err(M6ExchangeError::Serialization(
            "route record is not in canonical representation".to_string(),
        ));
    }
    Ok(value)
}

fn disposition_name(disposition: &ExchangeDisposition) -> &'static str {
    match disposition {
        ExchangeDisposition::Quarantined => "quarantined",
        ExchangeDisposition::Rejected { .. } => "rejected",
        ExchangeDisposition::AwaitingApproval => "awaiting_approval",
        ExchangeDisposition::ApprovalDenied { .. } => "approval_denied",
        ExchangeDisposition::Adopted { .. } => "adopted",
        ExchangeDisposition::Healthy { .. } => "healthy",
        ExchangeDisposition::RolledBack { .. } => "rolled_back",
    }
}

fn short_digest(digest: &ContentDigest) -> &str {
    digest
        .as_str()
        .strip_prefix("sha256:")
        .and_then(|value| value.get(..16))
        .unwrap_or("invalid-digest")
}

fn digest_file_name(digest: &ContentDigest, suffix: &str) -> Result<String, M6ExchangeError> {
    validate_identifier("route file suffix", suffix)?;
    Ok(format!("{}.{}.json", digest.file_stem(), suffix))
}

fn prepare_new_or_existing_directory(path: &Path, role: &str) -> Result<PathBuf, M6ExchangeError> {
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| M6ExchangeError::io(path, source))?;
    prepare_existing_directory(path, role)
}

fn prepare_existing_directory(path: &Path, role: &str) -> Result<PathBuf, M6ExchangeError> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|source| M6ExchangeError::io(path, source))?;
    if !metadata.is_dir() {
        return Err(M6ExchangeError::UnsafePath(format!(
            "{role} '{}' is not a directory",
            path.display()
        )));
    }
    fs::canonicalize(path).map_err(|source| M6ExchangeError::io(path, source))
}

fn ensure_directory(path: &Path) -> Result<(), M6ExchangeError> {
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| M6ExchangeError::io(path, source))?;
    ensure_existing_real_directory(path)
}

fn ensure_existing_real_directory(path: &Path) -> Result<(), M6ExchangeError> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|source| M6ExchangeError::io(path, source))?;
    if !metadata.is_dir() {
        return Err(M6ExchangeError::UnsafePath(format!(
            "'{}' is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M6ExchangeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(M6ExchangeError::UnsafePath(
            format!("symbolic link '{}' is not allowed", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M6ExchangeError::io(path, source)),
    }
}

fn reject_symlink(path: &Path) -> Result<(), M6ExchangeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6ExchangeError::io(path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(M6ExchangeError::UnsafePath(format!(
            "symbolic link '{}' is not allowed",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_disjoint_roots(factory_root: &Path, route_root: &Path) -> Result<(), M6ExchangeError> {
    if factory_root == route_root
        || factory_root.starts_with(route_root)
        || route_root.starts_with(factory_root)
    {
        return Err(M6ExchangeError::InvalidConfiguration(
            "factory state root and neutral route root must be disjoint".to_string(),
        ));
    }
    Ok(())
}

fn enqueue_atomic(pending: &Path, final_path: &Path, bytes: &[u8]) -> Result<(), M6ExchangeError> {
    if final_path.exists() {
        let existing = read_bounded(final_path, MAX_ROUTE_FILE_BYTES)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(M6ExchangeError::RouteConflict(final_path.to_path_buf()));
    }
    atomic_write_idempotent(pending, bytes)?;
    fs::rename(pending, final_path).map_err(|source| M6ExchangeError::io(final_path, source))?;
    sync_parent(final_path)?;
    Ok(())
}

fn recover_pending_directory(
    pending_directory: &Path,
    final_directory: &Path,
    label: &str,
) -> Result<usize, M6ExchangeError> {
    ensure_existing_real_directory(pending_directory)?;
    ensure_existing_real_directory(final_directory)?;
    let mut recovered = 0;
    for entry in fs::read_dir(pending_directory)
        .map_err(|source| M6ExchangeError::io(pending_directory, source))?
    {
        let entry = entry.map_err(|source| M6ExchangeError::io(pending_directory, source))?;
        let source_path = entry.path();
        reject_symlink(&source_path)?;
        if !entry
            .file_type()
            .map_err(|source| M6ExchangeError::io(&source_path, source))?
            .is_file()
        {
            return Err(M6ExchangeError::UnsafePath(format!(
                "pending {label} entry '{}' is not a regular file",
                source_path.display()
            )));
        }
        let name = entry.file_name();
        let destination = final_directory.join(&name);
        if destination.exists() {
            let pending_bytes = read_bounded(&source_path, MAX_ROUTE_FILE_BYTES)?;
            let final_bytes = read_bounded(&destination, MAX_ROUTE_FILE_BYTES)?;
            if pending_bytes != final_bytes {
                return Err(M6ExchangeError::RouteConflict(destination));
            }
            fs::remove_file(&source_path)
                .map_err(|source| M6ExchangeError::io(&source_path, source))?;
        } else {
            fs::rename(&source_path, &destination)
                .map_err(|source| M6ExchangeError::io(&destination, source))?;
        }
        recovered += 1;
    }
    if recovered > 0 {
        sync_directory(final_directory)?;
        sync_directory(pending_directory)?;
    }
    Ok(recovered)
}

fn atomic_write_new(path: &Path, bytes: &[u8]) -> Result<(), M6ExchangeError> {
    reject_symlink_if_present(path)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|source| M6ExchangeError::io(path, source))?;
    file.write_all(bytes)
        .map_err(|source| M6ExchangeError::io(path, source))?;
    file.sync_all()
        .map_err(|source| M6ExchangeError::io(path, source))?;
    sync_parent(path)
}

fn atomic_write_idempotent(path: &Path, bytes: &[u8]) -> Result<(), M6ExchangeError> {
    if path.exists() {
        reject_symlink(path)?;
        let existing = read_bounded(path, MAX_ROUTE_FILE_BYTES)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(M6ExchangeError::RouteConflict(path.to_path_buf()));
    }
    atomic_write_new(path, bytes)
}

fn atomic_replace_json<T: Serialize>(path: &Path, value: &T) -> Result<(), M6ExchangeError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| M6ExchangeError::Serialization(error.to_string()))?;
    atomic_replace(path, &bytes)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), M6ExchangeError> {
    reject_symlink_if_present(path)?;
    let parent = path.parent().ok_or_else(|| {
        M6ExchangeError::UnsafePath(format!("'{}' has no parent", path.display()))
    })?;
    ensure_existing_real_directory(parent)?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| M6ExchangeError::UnsafePath("non-UTF-8 state filename".to_string()))?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{sequence}",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|source| M6ExchangeError::io(&temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| M6ExchangeError::io(&temporary, source))?;
        file.sync_all()
            .map_err(|source| M6ExchangeError::io(&temporary, source))?;
        fs::rename(&temporary, path).map_err(|source| M6ExchangeError::io(path, source))?;
        sync_parent(path)
    })();
    if result.is_err() && temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, M6ExchangeError> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|source| M6ExchangeError::io(path, source))?;
    if !metadata.is_file() {
        return Err(M6ExchangeError::UnsafePath(format!(
            "'{}' is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > limit as u64 {
        return Err(M6ExchangeError::PolicyRejected(format!(
            "'{}' exceeds the {limit}-byte route bound",
            path.display()
        )));
    }
    let file = File::open(path).map_err(|source| M6ExchangeError::io(path, source))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| M6ExchangeError::io(path, source))?;
    if bytes.len() > limit {
        return Err(M6ExchangeError::PolicyRejected(format!(
            "'{}' grew beyond its byte bound while reading",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_json_bounded<T: DeserializeOwned>(path: &Path, limit: usize) -> Result<T, M6ExchangeError> {
    serde_json::from_slice(&read_bounded(path, limit)?)
        .map_err(|error| M6ExchangeError::Serialization(error.to_string()))
}

fn sync_parent(path: &Path) -> Result<(), M6ExchangeError> {
    let parent = path.parent().ok_or_else(|| {
        M6ExchangeError::UnsafePath(format!("'{}' has no parent", path.display()))
    })?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<(), M6ExchangeError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| M6ExchangeError::io(path, source))
}

#[derive(Debug)]
pub enum M6ExchangeError {
    AlreadyInitialized(String),
    UnsupportedSchema(String),
    UnsupportedStateSchema(u32),
    InvalidConfiguration(String),
    WrongEndpointRole {
        expected: RouteEndpointRole,
        actual: RouteEndpointRole,
    },
    AuthorityDenied {
        action: AuthorityAction,
    },
    RouteKeyMismatch,
    AuthenticationFailed,
    FalseIdentity {
        expected: String,
        actual: String,
    },
    Expired {
        issued_at_ms: u64,
        expires_at_ms: u64,
        now_ms: u64,
    },
    Replay {
        nonce: String,
    },
    Revoked(RevocationTarget),
    DigestMismatch {
        subject: String,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    InterfaceMismatch {
        expected: String,
        actual: String,
    },
    InvalidPackage(String),
    SenderEvidenceMismatch(String),
    ReceiverProvingFailed,
    PolicyRejected(String),
    ApprovalDenied(ContentDigest),
    UnknownExchange(ContentDigest),
    InvalidDisposition {
        envelope_id: ContentDigest,
        expected: &'static str,
        actual: &'static str,
    },
    PreDispositionExecutionDenied(ContentDigest),
    RouteConflict(PathBuf),
    StateIntegrity(String),
    UnsafePath(String),
    Serialization(String),
    Component(String),
    Deployment(String),
    Reproduction(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl M6ExchangeError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }

    fn deployment(error: impl Display) -> Self {
        Self::Deployment(error.to_string())
    }

    fn reproduction(error: ReproductionError) -> Self {
        Self::Reproduction(error.to_string())
    }
}

impl Display for M6ExchangeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInitialized(message) => {
                write!(formatter, "already initialized: {message}")
            }
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported M6 schema '{schema}'")
            }
            Self::UnsupportedStateSchema(version) => {
                write!(formatter, "unsupported M6 state schema version {version}")
            }
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid M6 configuration: {message}")
            }
            Self::WrongEndpointRole { expected, actual } => {
                write!(
                    formatter,
                    "endpoint role is {actual:?}; expected {expected:?}"
                )
            }
            Self::AuthorityDenied { action } => {
                write!(formatter, "authority denied M6 action {action:?}")
            }
            Self::RouteKeyMismatch => formatter.write_str("route key fingerprint mismatch"),
            Self::AuthenticationFailed => {
                formatter.write_str("route envelope authentication failed")
            }
            Self::FalseIdentity { expected, actual } => {
                write!(
                    formatter,
                    "false identity: expected '{expected}', got '{actual}'"
                )
            }
            Self::Expired {
                issued_at_ms,
                expires_at_ms,
                now_ms,
            } => write!(
                formatter,
                "route envelope outside validity window {issued_at_ms}..={expires_at_ms} at {now_ms}"
            ),
            Self::Replay { nonce } => write!(formatter, "route nonce replay '{nonce}'"),
            Self::Revoked(target) => write!(formatter, "route artifact is revoked by {target:?}"),
            Self::DigestMismatch {
                subject,
                expected,
                actual,
            } => write!(
                formatter,
                "{subject} digest mismatch: expected {expected}, got {actual}"
            ),
            Self::InterfaceMismatch { expected, actual } => write!(
                formatter,
                "receiver interface mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::InvalidPackage(message) => write!(formatter, "invalid package: {message}"),
            Self::SenderEvidenceMismatch(message) => {
                write!(formatter, "sender evidence mismatch: {message}")
            }
            Self::ReceiverProvingFailed => {
                formatter.write_str("receiver-owned proving rejected the package")
            }
            Self::PolicyRejected(message) => {
                write!(formatter, "receiver policy rejected: {message}")
            }
            Self::ApprovalDenied(exchange) => {
                write!(formatter, "receiver approval denied exchange {exchange}")
            }
            Self::UnknownExchange(exchange) => write!(formatter, "unknown exchange {exchange}"),
            Self::InvalidDisposition {
                envelope_id,
                expected,
                actual,
            } => write!(
                formatter,
                "exchange {envelope_id} is {actual}; expected {expected}"
            ),
            Self::PreDispositionExecutionDenied(exchange) => write!(
                formatter,
                "exchange {exchange} cannot execute before approved active disposition"
            ),
            Self::RouteConflict(path) => {
                write!(formatter, "route file conflict at '{}'", path.display())
            }
            Self::StateIntegrity(message) => write!(formatter, "M6 state integrity: {message}"),
            Self::UnsafePath(message) => write!(formatter, "unsafe M6 path: {message}"),
            Self::Serialization(message) => write!(formatter, "M6 serialization: {message}"),
            Self::Component(message) => write!(formatter, "component execution: {message}"),
            Self::Deployment(message) => write!(formatter, "deployment: {message}"),
            Self::Reproduction(message) => write!(formatter, "factory package: {message}"),
            Self::Io { path, source } => {
                write!(formatter, "M6 I/O at '{}': {source}", path.display())
            }
        }
    }
}

impl Error for M6ExchangeError {
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
    use crate::factory_reproduction::{
        MutableFactoryPolicy, MutableGenome, ServiceDependencyCatalog, StableInterfaceContract,
        StateCompatibility, WorkerCatalog,
    };

    const NOW: u64 = 1_000_000;
    const EXPIRES: u64 = NOW + 60_000;
    const ROUTE_KEY: &[u8] = b"m6-test-route-key-32-bytes-long!!";

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m6-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create M6 test directory");
            Self(path)
        }

        fn child(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Pair {
        directory: TestDirectory,
        sender: M6Factory,
        receiver: M6Factory,
    }

    impl Pair {
        fn new(label: &str) -> Self {
            let directory = TestDirectory::new(label);
            let route = GovernedFilesystemRoute::initialize(
                directory.child("neutral-route"),
                "route:a-to-b",
                "factory:a",
                "factory:b",
                ROUTE_KEY,
            )
            .expect("initialize governed route");
            let sender = M6Factory::initialize(
                directory.child("factory-a"),
                route.clone(),
                profile("factory:a", "factory:b", RouteEndpointRole::Sender),
                package("factory:a", increment_component(1)),
            )
            .expect("initialize sender");
            let receiver = M6Factory::initialize(
                directory.child("factory-b"),
                route,
                profile("factory:b", "factory:a", RouteEndpointRole::Receiver),
                package("factory:b", increment_component(0)),
            )
            .expect("initialize receiver");
            Self {
                directory,
                sender,
                receiver,
            }
        }

        fn export(&mut self, nonce: &str) -> ExportReceipt {
            let authority = self
                .sender
                .state
                .profile
                .authority
                .invocation(AuthorityAction::ExportPackage);
            self.sender
                .export_active(
                    ExportRequest {
                        nonce: nonce.to_string(),
                        issued_at_ms: NOW,
                        expires_at_ms: EXPIRES,
                    },
                    ROUTE_KEY,
                    &authority,
                )
                .expect("export active package")
        }

        fn receive(&mut self, receipt: &ExportReceipt) -> ExchangeRecord {
            self.receiver
                .receive(&receipt.envelope_id, ROUTE_KEY, NOW + 1)
                .expect("receive exchange")
        }

        fn adopt(&mut self, receipt: &ExportReceipt, approval_id: &str) -> AdoptionReceipt {
            let authority = self
                .receiver
                .state
                .profile
                .authority
                .invocation(AuthorityAction::ActivateImport);
            self.receiver
                .approve_and_adopt(
                    ApprovalRequest {
                        approval_id: approval_id.to_string(),
                        exchange_id: receipt.envelope_id.clone(),
                        decision: ApprovalDecision::Approve {
                            reason: "receiver operator approved independently".to_string(),
                        },
                    },
                    &authority,
                )
                .expect("adopt approved exchange")
        }
    }

    fn profile(
        factory_id: &str,
        peer_factory_id: &str,
        role: RouteEndpointRole,
    ) -> FactoryEndpointProfile {
        let interface = StableInterfaceContract::reference();
        let proving_cases = vec![
            ProvingCase {
                case_id: "prove:one".to_string(),
                input: 1,
                expected_output: 2,
            },
            ProvingCase {
                case_id: "prove:seven".to_string(),
                input: 7,
                expected_output: 8,
            },
        ];
        let observation_cases = vec![ProvingCase {
            case_id: "observe:ninety-nine".to_string(),
            input: 99,
            expected_output: 100,
        }];
        let policy = FactoryExchangePolicy::new(
            match role {
                RouteEndpointRole::Sender => "policy:factory-a-export",
                RouteEndpointRole::Receiver => "policy:factory-b-import",
            },
            interface.interface_ref.clone(),
            interface.contract_digest().expect("interface digest"),
            proving_cases,
            observation_cases,
            4 * 1_048_576,
            120_000,
            ComponentExecutionLimits::default(),
        )
        .expect("valid exchange policy");
        let actions = match role {
            RouteEndpointRole::Sender => [
                AuthorityAction::ExportPackage,
                AuthorityAction::ManageLocalPackage,
                AuthorityAction::IssueRevocation,
            ]
            .into_iter()
            .collect(),
            RouteEndpointRole::Receiver => [
                AuthorityAction::DisposeQuarantine,
                AuthorityAction::ActivateImport,
                AuthorityAction::ObserveImport,
                AuthorityAction::RollbackImport,
            ]
            .into_iter()
            .collect(),
        };
        let authority = AuthorityEnvelope::new(
            format!("authority:{factory_id}"),
            factory_id,
            format!("operator:{factory_id}"),
            format!("factory-root:{factory_id}"),
            actions,
        )
        .expect("valid authority");
        FactoryEndpointProfile::new(
            factory_id,
            role,
            "route:a-to-b",
            peer_factory_id,
            policy,
            authority,
        )
        .expect("valid profile")
    }

    fn package(factory_id: &str, component_bytes: Vec<u8>) -> FactoryPackage {
        FactoryPackage::build(
            factory_id,
            0,
            MutableGenome::new(None, component_bytes, MutableFactoryPolicy::terminal(1, 4))
                .expect("valid mutable genome"),
            StableInterfaceContract::reference(),
            WorkerCatalog::reference().expect("worker catalog"),
            ServiceDependencyCatalog::reference().expect("service catalog"),
            StateCompatibility {
                readable_schema_min: 1,
                readable_schema_max: 1,
                written_schema: 1,
                incumbent_rollback_readable_through: 1,
            },
        )
        .expect("valid factory package")
    }

    fn increment_component(increment: i32) -> Vec<u8> {
        wat::parse_str(format!(
            r#"(component
                (core module $implementation
                    (func (export "transform") (param i32) (result i32)
                        local.get 0
                        i32.const {increment}
                        i32.add))
                (core instance $instance (instantiate $implementation))
                (func (export "transform") (param "input" s32) (result s32)
                    (canon lift (core func $instance "transform"))))"#
        ))
        .expect("compile increment component")
    }

    fn late_failure_component() -> Vec<u8> {
        wat::parse_str(
            r#"(component
                (core module $implementation
                    (func (export "transform") (param i32) (result i32)
                        local.get 0
                        i32.const 99
                        i32.eq
                        if (result i32)
                            i32.const 0
                        else
                            local.get 0
                            i32.const 1
                            i32.add
                        end))
                (core instance $instance (instantiate $implementation))
                (func (export "transform") (param "input" s32) (result s32)
                    (canon lift (core func $instance "transform"))))"#,
        )
        .expect("compile late-failure component")
    }

    fn route_exchange_path(route: &GovernedFilesystemRoute, id: &ContentDigest) -> PathBuf {
        route
            .inbox_directory()
            .join(digest_file_name(id, "exchange").expect("route filename"))
    }

    fn read_envelope(
        route: &GovernedFilesystemRoute,
        id: &ContentDigest,
    ) -> SignedExchangeEnvelope {
        serde_json::from_slice(
            &read_bounded(&route_exchange_path(route, id), MAX_ROUTE_FILE_BYTES)
                .expect("read envelope"),
        )
        .expect("decode envelope")
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_vector() {
        let key = [0x0b_u8; 20];
        assert_eq!(
            hmac_tag(&key, b"Hi There"),
            "hmac-sha256:b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn tampered_package_bytes_are_quarantined_then_rejected_without_execution() {
        let mut pair = Pair::new("tampered");
        let receipt = pair.export("nonce:tampered");
        let path = route_exchange_path(&pair.sender.route, &receipt.envelope_id);
        let mut envelope = read_envelope(&pair.sender.route, &receipt.envelope_id);
        envelope.payload.package_bytes[0] ^= 0x01;
        atomic_replace(&path, &canonical_json(&envelope).expect("encode tamper"))
            .expect("replace route envelope");

        let error = pair
            .receiver
            .receive(&receipt.envelope_id, ROUTE_KEY, NOW + 1)
            .expect_err("tampered bytes must fail");
        assert!(matches!(error, M6ExchangeError::AuthenticationFailed));
        let record = pair
            .receiver
            .state
            .exchanges
            .get(receipt.envelope_id.as_str())
            .expect("durable rejected quarantine");
        assert!(matches!(
            record.disposition,
            ExchangeDisposition::Rejected {
                code: RejectionCode::AuthenticationFailed,
                ..
            }
        ));
        assert!(
            pair.receiver
                .quarantine_root
                .join(receipt.envelope_id.file_stem())
                .join("package.bin")
                .is_file()
        );
        assert_eq!(
            pair.receiver
                .execute_active(7)
                .expect("incumbent executes")
                .output,
            Some(7)
        );
    }

    #[test]
    fn false_sender_identity_and_false_mac_are_rejected() {
        let mut false_identity = Pair::new("false-identity");
        let receipt = false_identity.export("nonce:false-identity-base");
        let mut envelope = read_envelope(&false_identity.sender.route, &receipt.envelope_id);
        envelope.payload.sender_factory_id = "factory:impostor".to_string();
        let forged =
            sign_exchange(envelope.payload, ROUTE_KEY).expect("sign deliberately false identity");
        false_identity
            .sender
            .route
            .enqueue_exchange(&forged)
            .expect("enqueue forged identity");
        let error = false_identity
            .receiver
            .receive(&forged.envelope_id, ROUTE_KEY, NOW + 1)
            .expect_err("false identity must fail");
        assert!(matches!(error, M6ExchangeError::FalseIdentity { .. }));

        let mut false_mac = Pair::new("false-mac");
        let receipt = false_mac.export("nonce:false-mac");
        let path = route_exchange_path(&false_mac.sender.route, &receipt.envelope_id);
        let mut envelope = read_envelope(&false_mac.sender.route, &receipt.envelope_id);
        envelope.authentication.tag.replace_range(12..13, "0");
        atomic_replace(&path, &canonical_json(&envelope).expect("encode false MAC"))
            .expect("replace route envelope");
        assert!(matches!(
            false_mac
                .receiver
                .receive(&receipt.envelope_id, ROUTE_KEY, NOW + 1),
            Err(M6ExchangeError::AuthenticationFailed)
        ));
    }

    #[test]
    fn authenticated_incompatible_interface_is_rejected_in_quarantine() {
        let mut pair = Pair::new("interface");
        let receipt = pair.export("nonce:interface-base");
        let envelope = read_envelope(&pair.sender.route, &receipt.envelope_id);
        let mut payload = envelope.payload;
        let mut package_payload: FactoryPackagePayload =
            serde_json::from_slice(&payload.package_bytes).expect("decode package payload");
        package_payload.stable_interface.interface_ref =
            "wit:wasm-biotic:reference-task/reference-task@v2".to_string();
        payload.package_bytes =
            canonical_json(&package_payload).expect("encode incompatible bytes");
        payload.package_digest = ContentDigest::from_bytes(&payload.package_bytes);
        payload.lineage.source_active_package_digest = payload.package_digest.clone();
        payload.lineage.package_digest = payload.package_digest.clone();
        payload.lineage.lineage_digest =
            lineage_digest(&payload.lineage).expect("reseal forged lineage");
        payload.sender_proving.package_digest = payload.package_digest.clone();
        payload.sender_proving.report_digest =
            proving_report_digest(&payload.sender_proving).expect("reseal sender proof");
        payload.nonce = "nonce:interface-v2".to_string();
        let incompatible = sign_exchange(payload, ROUTE_KEY).expect("authenticate incompatibility");
        pair.sender
            .route
            .enqueue_exchange(&incompatible)
            .expect("enqueue incompatible package");

        let error = pair
            .receiver
            .receive(&incompatible.envelope_id, ROUTE_KEY, NOW + 1)
            .expect_err("incompatible interface must fail");
        assert!(matches!(error, M6ExchangeError::InterfaceMismatch { .. }));
        assert!(matches!(
            pair.receiver
                .state
                .exchanges
                .get(incompatible.envelope_id.as_str())
                .expect("rejection record")
                .disposition,
            ExchangeDisposition::Rejected {
                code: RejectionCode::InterfaceMismatch,
                ..
            }
        ));
    }

    #[test]
    fn replayed_envelope_is_rejected_after_first_receiver_proving() {
        let mut pair = Pair::new("replay");
        let receipt = pair.export("nonce:replay");
        let first = pair.receive(&receipt);
        assert!(matches!(
            first.disposition,
            ExchangeDisposition::AwaitingApproval
        ));
        assert!(matches!(
            pair.receiver
                .receive(&receipt.envelope_id, ROUTE_KEY, NOW + 2),
            Err(M6ExchangeError::Replay { .. })
        ));
        assert_eq!(pair.receiver.state.received_nonces.len(), 1);
    }

    #[test]
    fn quarantine_cannot_execute_or_activate_before_receiver_approval() {
        let mut pair = Pair::new("pre-disposition");
        let receipt = pair.export("nonce:pre-disposition");
        pair.receive(&receipt);
        assert!(matches!(
            pair.receiver.execute_exchange(&receipt.envelope_id, 7),
            Err(M6ExchangeError::PreDispositionExecutionDenied(_))
        ));
        assert_eq!(
            pair.receiver
                .execute_active(7)
                .expect("incumbent remains active")
                .output,
            Some(7)
        );
        assert_ne!(
            pair.receiver.state.active_package_digest,
            receipt.package_digest
        );
    }

    #[test]
    fn successful_exchange_independently_proves_approves_and_changes_behavior() {
        let mut pair = Pair::new("success");
        let receipt = pair.export("nonce:success");
        let record = pair.receive(&receipt);
        let receiver_proving = record.receiver_proving.expect("receiver proving evidence");
        assert!(receiver_proving.overall_pass);
        assert_ne!(
            receiver_proving.report_digest, receipt.proving_digest,
            "sender and receiver use independently named proving suites"
        );
        let adoption = pair.adopt(&receipt, "approval:success");
        assert_eq!(adoption.package_digest, receipt.package_digest);
        assert_eq!(
            pair.receiver
                .execute_exchange(&receipt.envelope_id, 7)
                .expect("approved import executes")
                .output,
            Some(8)
        );
        let active_bytes = pair
            .receiver
            .deployment
            .read_active_bytes()
            .expect("read exact active package");
        assert_eq!(
            ContentDigest::from_bytes(&active_bytes),
            receipt.package_digest
        );
        let route_bytes = read_envelope(&pair.sender.route, &receipt.envelope_id)
            .payload
            .package_bytes;
        assert!(
            active_bytes == route_bytes,
            "activated receiver package differed from routed package bytes (active_bytes={}, route_bytes={})",
            active_bytes.len(),
            route_bytes.len()
        );
    }

    #[test]
    fn post_adoption_failure_rolls_back_receiver_without_mutating_sender() {
        let mut pair = Pair::new("rollback-symmetry");
        let first = pair.export("nonce:first-good");
        pair.receive(&first);
        pair.adopt(&first, "approval:first-good");
        let observe_authority = pair
            .receiver
            .state
            .profile
            .authority
            .invocation(AuthorityAction::ObserveImport);
        assert!(matches!(
            pair.receiver
                .observe_adoption(&first.envelope_id, &observe_authority)
                .expect("healthy first import"),
            ObservationDisposition::Healthy(_)
        ));

        let late_failure = package("factory:a", late_failure_component());
        let sender_authority = pair
            .sender
            .state
            .profile
            .authority
            .invocation(AuthorityAction::ManageLocalPackage);
        pair.sender
            .activate_local_package(&late_failure, &sender_authority)
            .expect("activate new sender package");
        let second = pair.export("nonce:late-failure");
        pair.receive(&second);
        pair.adopt(&second, "approval:late-failure");
        assert_eq!(
            pair.receiver
                .execute_exchange(&second.envelope_id, 1)
                .expect("canary input passes")
                .output,
            Some(2)
        );
        let sender_digest_before = pair.sender.state.active_package_digest.clone();
        let disposition = pair
            .receiver
            .observe_adoption(&second.envelope_id, &observe_authority)
            .expect("failed observation triggers rollback");
        assert!(matches!(
            disposition,
            ObservationDisposition::RolledBack {
                restored_package_digest,
                ..
            } if restored_package_digest == first.package_digest
        ));
        assert_eq!(
            pair.receiver
                .execute_active(99)
                .expect("restored receiver executes")
                .output,
            Some(100)
        );
        assert_eq!(
            pair.sender
                .execute_active(99)
                .expect("sender remains on its failing-at-99 package")
                .output,
            Some(0)
        );
        assert_eq!(
            pair.sender.state.active_package_digest,
            sender_digest_before
        );
        assert!(matches!(
            pair.receiver
                .state
                .exchanges
                .get(second.envelope_id.as_str())
                .expect("rollback lineage")
                .disposition,
            ExchangeDisposition::RolledBack { .. }
        ));
    }

    #[test]
    fn revocation_expiry_and_route_recovery_are_enforced() {
        let mut revoked = Pair::new("revoked");
        let receipt = revoked.export("nonce:revoked-package");
        let authority = revoked
            .sender
            .state
            .profile
            .authority
            .invocation(AuthorityAction::IssueRevocation);
        let revocation = revoked
            .sender
            .issue_revocation(
                RevocationRequest {
                    nonce: "nonce:revocation".to_string(),
                    issued_at_ms: NOW,
                    expires_at_ms: EXPIRES,
                    target: RevocationTarget::EnvelopeId(receipt.envelope_id.clone()),
                    reason: "sender withdrew the route artifact".to_string(),
                },
                ROUTE_KEY,
                &authority,
            )
            .expect("issue revocation");
        revoked
            .receiver
            .apply_revocation(&revocation.revocation_id, ROUTE_KEY, NOW + 1)
            .expect("apply authenticated revocation");
        assert!(matches!(
            revoked
                .receiver
                .receive(&receipt.envelope_id, ROUTE_KEY, NOW + 2),
            Err(M6ExchangeError::Revoked(RevocationTarget::EnvelopeId(_)))
        ));

        let mut expired = Pair::new("expired");
        let receipt = expired.export("nonce:expired");
        assert!(matches!(
            expired
                .receiver
                .receive(&receipt.envelope_id, ROUTE_KEY, EXPIRES + 1),
            Err(M6ExchangeError::Expired { .. })
        ));

        let mut recovery = Pair::new("route-recovery");
        let receipt = recovery.export("nonce:route-recovery");
        let final_path = route_exchange_path(&recovery.sender.route, &receipt.envelope_id);
        let pending_path =
            recovery.sender.route.pending_directory().join(
                digest_file_name(&receipt.envelope_id, "exchange").expect("pending filename"),
            );
        fs::rename(&final_path, &pending_path).expect("simulate interrupted route delivery");
        let report = recovery.sender.route.recover().expect("recover route");
        assert_eq!(report.recovered_envelopes, 1);
        assert!(final_path.is_file());
        recovery.receive(&receipt);
    }

    #[test]
    fn two_disjoint_roots_restart_with_exchange_and_adoption_lineage() {
        let mut pair = Pair::new("restart");
        let receipt = pair.export("nonce:restart");
        pair.receive(&receipt);
        pair.adopt(&receipt, "approval:restart");
        let sender_root = pair.sender.root().to_path_buf();
        let receiver_root = pair.receiver.root().to_path_buf();
        let route_root = pair.sender.route_root().to_path_buf();
        assert_ne!(sender_root, receiver_root);
        assert!(!sender_root.starts_with(&receiver_root));
        assert!(!receiver_root.starts_with(&sender_root));
        assert!(!route_root.starts_with(&sender_root));
        assert!(!route_root.starts_with(&receiver_root));
        drop(pair.sender);
        drop(pair.receiver);

        let route = GovernedFilesystemRoute::open(&route_root).expect("reopen neutral route");
        let sender =
            M6Factory::open(&sender_root, route.clone()).expect("reopen independent sender root");
        let receiver =
            M6Factory::open(&receiver_root, route).expect("reopen independent receiver root");
        assert_eq!(sender.state.sent_exchanges.len(), 1);
        assert_eq!(
            receiver
                .state
                .exchanges
                .get(receipt.envelope_id.as_str())
                .expect("durable exchange")
                .package_digest,
            receipt.package_digest
        );
        assert_eq!(
            receiver
                .execute_exchange(&receipt.envelope_id, 7)
                .expect("restarted receiver executes adopted bytes")
                .output,
            Some(8)
        );

        let secret = String::from_utf8_lossy(ROUTE_KEY);
        for root in [&sender_root, &receiver_root, &route_root] {
            assert!(
                !tree_contains(root, secret.as_bytes()),
                "route secret must never be persisted beneath {}",
                root.display()
            );
        }
        drop(sender);
        drop(receiver);
        drop(pair.directory);
    }

    fn tree_contains(root: &Path, needle: &[u8]) -> bool {
        let entries = fs::read_dir(root).expect("read persisted tree");
        for entry in entries {
            let entry = entry.expect("read tree entry");
            let path = entry.path();
            if path.is_dir() {
                if tree_contains(&path, needle) {
                    return true;
                }
            } else {
                let bytes = fs::read(&path).expect("read persisted file");
                if bytes.windows(needle.len()).any(|window| window == needle) {
                    return true;
                }
            }
        }
        false
    }
}
