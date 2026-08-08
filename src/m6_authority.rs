//! Exact, durable local authority and approval records for M6.
//!
//! This module deliberately does not own credentials. An
//! [`AuthorizationIssuer`] can ask an opaque signer to attest one exact
//! [`ActionAuthorization`], while an [`AuthorizationStore`] receives a
//! separately provisioned opaque verifier. Only public issuer identity and
//! attestation bytes are durable; secret keys, handles, and provider paths are
//! never serialized.
//!
//! The store is a sole-writer, append-only boundary. Every authorization,
//! consumption receipt, approval request, and terminal approval decision is
//! digest sealed and published with no-clobber semantics. The numeric time
//! arguments accepted here are trusted inputs from the endpoint clock layer;
//! this lower layer never calls the ambient system clock to make an authority
//! decision.

use crate::execution::{ContentDigest, digest_json_content};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

pub const ENDPOINT_ACTION_PROFILE_SCHEMA: &str = "wasm-biotic.m6-endpoint-action-profile.v1";
pub const ACTION_AUTHORIZATION_SCHEMA: &str = "wasm-biotic.m6-action-authorization.v1";
pub const AUTHORIZATION_CONSUMPTION_SCHEMA: &str = "wasm-biotic.m6-authorization-consumption.v1";
pub const APPROVAL_REQUEST_SCHEMA: &str = "wasm-biotic.m6-approval-request.v1";
pub const APPROVAL_DECISION_SCHEMA: &str = "wasm-biotic.m6-approval-decision.v1";

const PROFILE_DOMAIN: &str = "wasm-biotic:m6-endpoint-action-profile:v1";
const ACTION_BINDING_DOMAIN: &str = "wasm-biotic:m6-exact-action-binding:v1";
const AUTHORIZATION_PAYLOAD_DOMAIN: &str = "wasm-biotic:m6-action-authorization-payload:v1";
const AUTHORIZATION_RECORD_DOMAIN: &str = "wasm-biotic:m6-action-authorization-record:v1";
const CONSUMPTION_DOMAIN: &str = "wasm-biotic:m6-authorization-consumption:v1";
const APPROVAL_REQUEST_DOMAIN: &str = "wasm-biotic:m6-approval-request:v1";
const APPROVAL_CONTEXT_DOMAIN: &str = "wasm-biotic:m6-approval-decision-context:v1";
const APPROVAL_DECISION_DOMAIN: &str = "wasm-biotic:m6-approval-decision:v1";

const OWNER_LOCK_FILE: &str = ".m6-authority.lock";
const PROFILE_FILE: &str = "endpoint-action-profile.json";
const AUTHORIZATION_DIRECTORY: &str = "authorizations";
const CONSUMPTION_DIRECTORY: &str = "consumptions";
const APPROVAL_REQUEST_DIRECTORY: &str = "approval-requests";
const APPROVAL_DECISION_DIRECTORY: &str = "approval-decisions";
const STAGING_DIRECTORY: &str = ".staging";

const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_RATIONALE_BYTES: usize = 16 * 1_024;
const MAX_ATTESTATION_BYTES: usize = 16 * 1_024;
const MAX_RECORD_BYTES: usize = 256 * 1_024;
const MAX_RECORDS_PER_DIRECTORY: usize = 10_000;
const MAX_AUTHORIZATION_USES: u32 = 64;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// The one action authorized by a record.
///
/// There is intentionally no "allowed actions" field on
/// [`ActionAuthorization`]. A record binds exactly one enum value and the
/// endpoint profile must independently permit that same value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityAction {
    ExportPackage,
    IssueRevocation,
    IntakePackage,
    ProveImport,
    GrantImportApproval,
    DenyImportApproval,
    ExpireImportApproval,
    EscalateImportApproval,
    AdoptImport,
    ObserveImport,
    RollbackImport,
    DisposeQuarantine,
}

/// A credential boundary with a fixed, non-configurable action profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointAuthorityKind {
    Export,
    Revocation,
    Intake,
    Proving,
    Approval,
    Promotion,
    Observation,
    Rollback,
    QuarantineDisposition,
}

impl EndpointAuthorityKind {
    fn mandatory_actions(self) -> BTreeSet<AuthorityAction> {
        match self {
            Self::Export => BTreeSet::from([AuthorityAction::ExportPackage]),
            Self::Revocation => BTreeSet::from([AuthorityAction::IssueRevocation]),
            Self::Intake => BTreeSet::from([AuthorityAction::IntakePackage]),
            Self::Proving => BTreeSet::from([AuthorityAction::ProveImport]),
            Self::Approval => BTreeSet::from([
                AuthorityAction::GrantImportApproval,
                AuthorityAction::DenyImportApproval,
                AuthorityAction::ExpireImportApproval,
                AuthorityAction::EscalateImportApproval,
            ]),
            Self::Promotion => BTreeSet::from([AuthorityAction::AdoptImport]),
            Self::Observation => BTreeSet::from([AuthorityAction::ObserveImport]),
            Self::Rollback => BTreeSet::from([AuthorityAction::RollbackImport]),
            Self::QuarantineDisposition => BTreeSet::from([AuthorityAction::DisposeQuarantine]),
        }
    }
}

/// Immutable, self-describing profile for one local credential boundary.
///
/// `actions` is derived from `authority_kind` and revalidated on every open.
/// A caller cannot persist a wider or narrower ad-hoc allowlist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointActionProfile {
    schema: String,
    profile_id: String,
    factory_id: String,
    issuer_id: String,
    authority_implementation_digest: ContentDigest,
    authority_kind: EndpointAuthorityKind,
    actions: BTreeSet<AuthorityAction>,
    profile_digest: ContentDigest,
}

impl EndpointActionProfile {
    pub fn new(
        profile_id: impl Into<String>,
        factory_id: impl Into<String>,
        issuer_id: impl Into<String>,
        authority_implementation_digest: ContentDigest,
        authority_kind: EndpointAuthorityKind,
    ) -> Result<Self, M6AuthorityError> {
        let mut profile = Self {
            schema: ENDPOINT_ACTION_PROFILE_SCHEMA.to_string(),
            profile_id: profile_id.into(),
            factory_id: factory_id.into(),
            issuer_id: issuer_id.into(),
            authority_implementation_digest,
            authority_kind,
            actions: authority_kind.mandatory_actions(),
            profile_digest: ContentDigest::from_bytes(&[]),
        };
        profile.validate_fields()?;
        profile.profile_digest = profile.expected_digest()?;
        Ok(profile)
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn factory_id(&self) -> &str {
        &self.factory_id
    }

    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    pub fn authority_implementation_digest(&self) -> &ContentDigest {
        &self.authority_implementation_digest
    }

    pub fn authority_kind(&self) -> EndpointAuthorityKind {
        self.authority_kind
    }

    pub fn actions(&self) -> &BTreeSet<AuthorityAction> {
        &self.actions
    }

    pub fn profile_digest(&self) -> &ContentDigest {
        &self.profile_digest
    }

    pub fn supports(&self, action: AuthorityAction) -> bool {
        self.actions.contains(&action)
    }

    /// Return the exact portable encoding used by the durable authority
    /// store. The profile is fully revalidated before any bytes are exposed.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M6AuthorityError> {
        self.validate()?;
        canonical_bytes(self)
    }

    /// Parse and independently validate one exact durable profile.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M6AuthorityError> {
        let profile: Self = parse_canonical_bytes(bytes)?;
        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<(), M6AuthorityError> {
        self.validate_fields()?;
        require_digest(
            "endpoint action profile",
            &self.profile_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6AuthorityError> {
        if self.schema != ENDPOINT_ACTION_PROFILE_SCHEMA {
            return Err(M6AuthorityError::InvalidProfile(
                "unsupported endpoint action profile schema".to_string(),
            ));
        }
        validate_identifier("profile_id", &self.profile_id)?;
        validate_identifier("factory_id", &self.factory_id)?;
        validate_identifier("issuer_id", &self.issuer_id)?;
        if self.actions != self.authority_kind.mandatory_actions() {
            return Err(M6AuthorityError::InvalidProfile(
                "endpoint actions differ from the mandatory authority-kind profile".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6AuthorityError> {
        digest(&(
            PROFILE_DOMAIN,
            &self.profile_id,
            &self.factory_id,
            &self.issuer_id,
            &self.authority_implementation_digest,
            self.authority_kind,
            &self.actions,
        ))
    }
}

/// Exact effect identity carried both by an authorization and its invocation.
///
/// All digest fields are mandatory. An action for which one field is not
/// semantically applicable must bind an explicit, domain-specific
/// "not-applicable" digest rather than omit the field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactActionBinding {
    pub action: AuthorityAction,
    pub principal_id: String,
    pub route_id: String,
    pub route_generation: u64,
    pub message_digest: ContentDigest,
    pub exchange_digest: ContentDigest,
    pub package_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub expected_active_snapshot_digest: ContentDigest,
    pub import_plan_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub proving_digest: ContentDigest,
    pub approval_context_digest: ContentDigest,
    pub idempotency_key: String,
}

impl ExactActionBinding {
    pub fn validate(&self) -> Result<(), M6AuthorityError> {
        validate_identifier("principal_id", &self.principal_id)?;
        validate_identifier("route_id", &self.route_id)?;
        validate_identifier("idempotency_key", &self.idempotency_key)?;
        if self.route_generation == 0 {
            return Err(M6AuthorityError::InvalidAuthorization(
                "route generation must be nonzero".to_string(),
            ));
        }
        Ok(())
    }

    pub fn binding_digest(&self) -> Result<ContentDigest, M6AuthorityError> {
        self.validate()?;
        digest(&(
            ACTION_BINDING_DOMAIN,
            self.action,
            &self.principal_id,
            &self.route_id,
            self.route_generation,
            &self.message_digest,
            &self.exchange_digest,
            &self.package_digest,
            &self.request_digest,
            &self.expected_active_snapshot_digest,
            &self.import_plan_digest,
            &self.policy_digest,
            &self.proving_digest,
            &self.approval_context_digest,
            &self.idempotency_key,
        ))
    }
}

/// Non-durable issue command passed through the private issuer boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionAuthorizationRequest {
    binding: ExactActionBinding,
    use_limit: u32,
}

impl ActionAuthorizationRequest {
    pub fn new(binding: ExactActionBinding, use_limit: u32) -> Result<Self, M6AuthorityError> {
        binding.validate()?;
        validate_use_limit(use_limit)?;
        Ok(Self { binding, use_limit })
    }

    pub fn binding(&self) -> &ExactActionBinding {
        &self.binding
    }

    pub fn use_limit(&self) -> u32 {
        self.use_limit
    }
}

/// Opaque signing facility. Implementations retain credential material.
///
/// Returned errors must already be redacted; the store never persists them.
pub trait OpaqueAuthorizationSigner {
    fn issuer_id(&self) -> &str;

    fn sign_authorization(&self, payload_digest: &ContentDigest) -> Result<String, String>;
}

/// Opaque verification facility provisioned independently at store open.
pub trait OpaqueAuthorizationVerifier {
    fn issuer_id(&self) -> &str;

    fn verify_authorization(
        &self,
        payload_digest: &ContentDigest,
        attestation: &str,
    ) -> Result<bool, String>;
}

/// Private minting boundary for one exact endpoint profile.
///
/// The type is intentionally not serializable. Its signer remains opaque.
pub struct AuthorizationIssuer<S: OpaqueAuthorizationSigner> {
    profile: EndpointActionProfile,
    signer: S,
}

impl<S: OpaqueAuthorizationSigner> AuthorizationIssuer<S> {
    pub fn new(profile: EndpointActionProfile, signer: S) -> Result<Self, M6AuthorityError> {
        profile.validate()?;
        if signer.issuer_id() != profile.issuer_id {
            return Err(M6AuthorityError::CredentialMismatch {
                expected: profile.issuer_id.clone(),
                supplied: signer.issuer_id().to_string(),
            });
        }
        Ok(Self { profile, signer })
    }

    pub fn profile(&self) -> &EndpointActionProfile {
        &self.profile
    }

    /// Mint an exact record using times supplied by the trusted clock layer.
    pub fn issue(
        &self,
        request: ActionAuthorizationRequest,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<ActionAuthorization, M6AuthorityError> {
        if !self.profile.supports(request.binding.action) {
            return Err(M6AuthorityError::ActionOutsideProfile {
                action: request.binding.action,
                profile: self.profile.authority_kind,
            });
        }
        if expires_at_ms <= issued_at_ms {
            return Err(M6AuthorityError::InvalidAuthorization(
                "authorization expiry must be later than issuance".to_string(),
            ));
        }

        let binding_digest = request.binding.binding_digest()?;
        let mut authorization = ActionAuthorization {
            schema: ACTION_AUTHORIZATION_SCHEMA.to_string(),
            factory_id: self.profile.factory_id.clone(),
            issuer_id: self.profile.issuer_id.clone(),
            endpoint_profile_digest: self.profile.profile_digest.clone(),
            binding: request.binding,
            binding_digest,
            issued_at_ms,
            expires_at_ms,
            use_limit: request.use_limit,
            payload_digest: ContentDigest::from_bytes(&[]),
            issuer_attestation: String::new(),
            authorization_digest: ContentDigest::from_bytes(&[]),
        };
        authorization.payload_digest = authorization.expected_payload_digest()?;
        authorization.issuer_attestation = self
            .signer
            .sign_authorization(&authorization.payload_digest)
            .map_err(M6AuthorityError::CredentialFailure)?;
        validate_attestation(&authorization.issuer_attestation)?;
        authorization.authorization_digest = authorization.expected_record_digest()?;
        authorization.validate_structure()?;
        Ok(authorization)
    }
}

/// Immutable, digest-sealed authorization for one exact action and target.
///
/// Fields are private so normal construction must cross
/// [`AuthorizationIssuer`]. Deserialization is required for durable loading,
/// but a deserialized or manually forged value is not trusted: store
/// publication and use always rederive every digest and invoke the pinned
/// opaque verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionAuthorization {
    schema: String,
    factory_id: String,
    issuer_id: String,
    endpoint_profile_digest: ContentDigest,
    binding: ExactActionBinding,
    binding_digest: ContentDigest,
    issued_at_ms: u64,
    expires_at_ms: u64,
    use_limit: u32,
    payload_digest: ContentDigest,
    issuer_attestation: String,
    authorization_digest: ContentDigest,
}

impl ActionAuthorization {
    pub fn factory_id(&self) -> &str {
        &self.factory_id
    }

    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    pub fn endpoint_profile_digest(&self) -> &ContentDigest {
        &self.endpoint_profile_digest
    }

    pub fn binding(&self) -> &ExactActionBinding {
        &self.binding
    }

    pub fn binding_digest(&self) -> &ContentDigest {
        &self.binding_digest
    }

    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub fn use_limit(&self) -> u32 {
        self.use_limit
    }

    pub fn payload_digest(&self) -> &ContentDigest {
        &self.payload_digest
    }

    pub fn issuer_attestation(&self) -> &str {
        &self.issuer_attestation
    }

    pub fn authorization_digest(&self) -> &ContentDigest {
        &self.authorization_digest
    }

    pub fn invocation(&self, use_ordinal: u32) -> ActionInvocation {
        ActionInvocation {
            authorization_digest: self.authorization_digest.clone(),
            binding: self.binding.clone(),
            use_ordinal,
        }
    }

    /// Return the exact durable encoding only after the pinned endpoint
    /// profile and opaque issuer verifier accept the authorization.
    pub fn canonical_bytes<V: OpaqueAuthorizationVerifier>(
        &self,
        profile: &EndpointActionProfile,
        verifier: &V,
    ) -> Result<Vec<u8>, M6AuthorityError> {
        self.validate_for(profile, verifier)?;
        canonical_bytes(self)
    }

    /// Parse one exact durable authorization and re-run both structural
    /// validation and opaque issuer-attestation verification.
    ///
    /// There is intentionally no verifier-free detached parser: a digest
    /// sealed record is not proof that its opaque issuer credential accepted
    /// the attestation.
    pub fn from_canonical_bytes<V: OpaqueAuthorizationVerifier>(
        bytes: &[u8],
        profile: &EndpointActionProfile,
        verifier: &V,
    ) -> Result<Self, M6AuthorityError> {
        let authorization: Self = parse_canonical_bytes(bytes)?;
        authorization.validate_for(profile, verifier)?;
        Ok(authorization)
    }

    /// Parse an authorization whose opaque issuer attestation has already
    /// been checked by an endpoint-signed completion proof.
    ///
    /// This still revalidates every public field, digest, exact binding, and
    /// pinned endpoint profile. It deliberately does not claim to re-run the
    /// opaque credential verifier; callers must first verify the enclosing
    /// endpoint Ed25519 completion signature.
    pub fn from_endpoint_attested_canonical_bytes(
        bytes: &[u8],
        profile: &EndpointActionProfile,
    ) -> Result<Self, M6AuthorityError> {
        let authorization: Self = parse_canonical_bytes(bytes)?;
        authorization.validate_structure()?;
        profile.validate()?;
        if authorization.factory_id != profile.factory_id {
            return Err(M6AuthorityError::TargetMismatch("factory_id"));
        }
        if authorization.issuer_id != profile.issuer_id {
            return Err(M6AuthorityError::TargetMismatch("issuer_id"));
        }
        if authorization.endpoint_profile_digest != profile.profile_digest {
            return Err(M6AuthorityError::TargetMismatch("endpoint_profile_digest"));
        }
        if !profile.supports(authorization.binding.action) {
            return Err(M6AuthorityError::ActionOutsideProfile {
                action: authorization.binding.action,
                profile: profile.authority_kind,
            });
        }
        Ok(authorization)
    }

    fn validate_structure(&self) -> Result<(), M6AuthorityError> {
        if self.schema != ACTION_AUTHORIZATION_SCHEMA {
            return Err(M6AuthorityError::InvalidAuthorization(
                "unsupported action authorization schema".to_string(),
            ));
        }
        validate_identifier("factory_id", &self.factory_id)?;
        validate_identifier("issuer_id", &self.issuer_id)?;
        self.binding.validate()?;
        validate_use_limit(self.use_limit)?;
        validate_attestation(&self.issuer_attestation)?;
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(M6AuthorityError::InvalidAuthorization(
                "authorization expiry must be later than issuance".to_string(),
            ));
        }
        require_digest(
            "exact action binding",
            &self.binding_digest,
            &self.binding.binding_digest()?,
        )?;
        require_digest(
            "authorization payload",
            &self.payload_digest,
            &self.expected_payload_digest()?,
        )?;
        require_digest(
            "action authorization",
            &self.authorization_digest,
            &self.expected_record_digest()?,
        )
    }

    fn validate_for<V: OpaqueAuthorizationVerifier>(
        &self,
        profile: &EndpointActionProfile,
        verifier: &V,
    ) -> Result<(), M6AuthorityError> {
        self.validate_structure()?;
        profile.validate()?;
        if self.factory_id != profile.factory_id {
            return Err(M6AuthorityError::TargetMismatch("factory_id"));
        }
        if self.issuer_id != profile.issuer_id {
            return Err(M6AuthorityError::TargetMismatch("issuer_id"));
        }
        if self.endpoint_profile_digest != profile.profile_digest {
            return Err(M6AuthorityError::TargetMismatch("endpoint_profile_digest"));
        }
        if !profile.supports(self.binding.action) {
            return Err(M6AuthorityError::ActionOutsideProfile {
                action: self.binding.action,
                profile: profile.authority_kind,
            });
        }
        if verifier.issuer_id() != profile.issuer_id {
            return Err(M6AuthorityError::CredentialMismatch {
                expected: profile.issuer_id.clone(),
                supplied: verifier.issuer_id().to_string(),
            });
        }
        match verifier.verify_authorization(&self.payload_digest, &self.issuer_attestation) {
            Ok(true) => Ok(()),
            Ok(false) => Err(M6AuthorityError::CredentialRejected),
            Err(message) => Err(M6AuthorityError::CredentialFailure(message)),
        }
    }

    fn expected_payload_digest(&self) -> Result<ContentDigest, M6AuthorityError> {
        digest(&(
            AUTHORIZATION_PAYLOAD_DOMAIN,
            &self.factory_id,
            &self.issuer_id,
            &self.endpoint_profile_digest,
            &self.binding_digest,
            self.issued_at_ms,
            self.expires_at_ms,
            self.use_limit,
        ))
    }

    fn expected_record_digest(&self) -> Result<ContentDigest, M6AuthorityError> {
        digest(&(
            AUTHORIZATION_RECORD_DOMAIN,
            &self.payload_digest,
            &self.issuer_attestation,
        ))
    }
}

/// One requested use of an exact authorization.
///
/// `use_ordinal` counts durable consumptions of the same idempotent effect.
/// Every ordinal carries the identical binding and idempotency key; it cannot
/// authorize a second target. Repeating a committed ordinal returns the exact
/// original receipt and does not spend another use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionInvocation {
    pub authorization_digest: ContentDigest,
    pub binding: ExactActionBinding,
    pub use_ordinal: u32,
}

impl ActionInvocation {
    pub fn new(
        authorization_digest: ContentDigest,
        binding: ExactActionBinding,
        use_ordinal: u32,
    ) -> Result<Self, M6AuthorityError> {
        binding.validate()?;
        if use_ordinal == 0 {
            return Err(M6AuthorityError::InvalidInvocation(
                "use ordinal must be nonzero".to_string(),
            ));
        }
        Ok(Self {
            authorization_digest,
            binding,
            use_ordinal,
        })
    }
}

/// Durable evidence that one bounded use was consumed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationConsumption {
    schema: String,
    authorization_digest: ContentDigest,
    binding_digest: ContentDigest,
    idempotency_key: String,
    use_ordinal: u32,
    consumed_at_ms: u64,
    receipt_digest: ContentDigest,
}

impl AuthorizationConsumption {
    pub fn authorization_digest(&self) -> &ContentDigest {
        &self.authorization_digest
    }

    pub fn binding_digest(&self) -> &ContentDigest {
        &self.binding_digest
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn use_ordinal(&self) -> u32 {
        self.use_ordinal
    }

    pub fn consumed_at_ms(&self) -> u64 {
        self.consumed_at_ms
    }

    pub fn receipt_digest(&self) -> &ContentDigest {
        &self.receipt_digest
    }

    /// Return the exact durable encoding after revalidating the receipt
    /// against the exact authorization it consumed.
    pub fn canonical_bytes(
        &self,
        authorization: &ActionAuthorization,
    ) -> Result<Vec<u8>, M6AuthorityError> {
        self.validate_against(authorization)?;
        canonical_bytes(self)
    }

    /// Parse and independently validate a consumption receipt against the
    /// exact authorization named by the enclosing portable proof.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        authorization: &ActionAuthorization,
    ) -> Result<Self, M6AuthorityError> {
        let consumption: Self = parse_canonical_bytes(bytes)?;
        consumption.validate_against(authorization)?;
        Ok(consumption)
    }

    fn new(
        authorization: &ActionAuthorization,
        use_ordinal: u32,
        consumed_at_ms: u64,
    ) -> Result<Self, M6AuthorityError> {
        let mut receipt = Self {
            schema: AUTHORIZATION_CONSUMPTION_SCHEMA.to_string(),
            authorization_digest: authorization.authorization_digest.clone(),
            binding_digest: authorization.binding_digest.clone(),
            idempotency_key: authorization.binding.idempotency_key.clone(),
            use_ordinal,
            consumed_at_ms,
            receipt_digest: ContentDigest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate_against(authorization)?;
        Ok(receipt)
    }

    fn validate_against(
        &self,
        authorization: &ActionAuthorization,
    ) -> Result<(), M6AuthorityError> {
        if self.schema != AUTHORIZATION_CONSUMPTION_SCHEMA {
            return Err(M6AuthorityError::Integrity(
                "unsupported authorization consumption schema".to_string(),
            ));
        }
        if self.authorization_digest != authorization.authorization_digest
            || self.binding_digest != authorization.binding_digest
            || self.idempotency_key != authorization.binding.idempotency_key
        {
            return Err(M6AuthorityError::Integrity(
                "authorization consumption does not bind its exact authorization".to_string(),
            ));
        }
        if self.use_ordinal == 0 || self.use_ordinal > authorization.use_limit {
            return Err(M6AuthorityError::Integrity(
                "authorization consumption exceeds its sealed use limit".to_string(),
            ));
        }
        if self.consumed_at_ms < authorization.issued_at_ms
            || self.consumed_at_ms >= authorization.expires_at_ms
        {
            return Err(M6AuthorityError::Integrity(
                "authorization consumption time is outside the sealed validity interval"
                    .to_string(),
            ));
        }
        require_digest(
            "authorization consumption",
            &self.receipt_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6AuthorityError> {
        digest(&(
            CONSUMPTION_DOMAIN,
            &self.authorization_digest,
            &self.binding_digest,
            &self.idempotency_key,
            self.use_ordinal,
            self.consumed_at_ms,
        ))
    }
}

/// Input for one immutable receiver approval request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequestDraft {
    pub request_id: String,
    pub factory_id: String,
    pub requester_principal_id: String,
    pub route_id: String,
    pub route_generation: u64,
    pub message_digest: ContentDigest,
    pub exchange_digest: ContentDigest,
    pub raw_quarantine_digest: ContentDigest,
    pub authenticated_source_identity_digest: ContentDigest,
    pub source_package_digest: ContentDigest,
    pub receiver_package_digest: ContentDigest,
    pub source_component_digest: ContentDigest,
    pub receiver_component_digest: ContentDigest,
    pub m5_export_bundle_digest: ContentDigest,
    pub compatibility_decision_digest: ContentDigest,
    pub expected_active_snapshot_digest: ContentDigest,
    pub rollback_target_digest: ContentDigest,
    pub import_plan_digest: ContentDigest,
    pub migration_plan_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub proving_digest: ContentDigest,
    pub unresolved_risks_digest: ContentDigest,
    pub requested_at_ms: u64,
    pub deadline_ms: u64,
    pub idempotency_key: String,
}

/// Immutable request shown to the receiver approval authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    schema: String,
    request_id: String,
    factory_id: String,
    requester_principal_id: String,
    route_id: String,
    route_generation: u64,
    message_digest: ContentDigest,
    exchange_digest: ContentDigest,
    raw_quarantine_digest: ContentDigest,
    authenticated_source_identity_digest: ContentDigest,
    source_package_digest: ContentDigest,
    receiver_package_digest: ContentDigest,
    source_component_digest: ContentDigest,
    receiver_component_digest: ContentDigest,
    m5_export_bundle_digest: ContentDigest,
    compatibility_decision_digest: ContentDigest,
    expected_active_snapshot_digest: ContentDigest,
    rollback_target_digest: ContentDigest,
    import_plan_digest: ContentDigest,
    migration_plan_digest: ContentDigest,
    policy_digest: ContentDigest,
    proving_digest: ContentDigest,
    unresolved_risks_digest: ContentDigest,
    requested_action: AuthorityAction,
    requested_at_ms: u64,
    deadline_ms: u64,
    idempotency_key: String,
    request_digest: ContentDigest,
}

#[derive(Serialize)]
struct ApprovalRequestDigestMaterial<'a> {
    domain: &'static str,
    request_id: &'a str,
    factory_id: &'a str,
    requester_principal_id: &'a str,
    route_id: &'a str,
    route_generation: u64,
    message_digest: &'a ContentDigest,
    exchange_digest: &'a ContentDigest,
    raw_quarantine_digest: &'a ContentDigest,
    authenticated_source_identity_digest: &'a ContentDigest,
    source_package_digest: &'a ContentDigest,
    receiver_package_digest: &'a ContentDigest,
    source_component_digest: &'a ContentDigest,
    receiver_component_digest: &'a ContentDigest,
    m5_export_bundle_digest: &'a ContentDigest,
    compatibility_decision_digest: &'a ContentDigest,
    expected_active_snapshot_digest: &'a ContentDigest,
    rollback_target_digest: &'a ContentDigest,
    import_plan_digest: &'a ContentDigest,
    migration_plan_digest: &'a ContentDigest,
    policy_digest: &'a ContentDigest,
    proving_digest: &'a ContentDigest,
    unresolved_risks_digest: &'a ContentDigest,
    requested_action: AuthorityAction,
    requested_at_ms: u64,
    deadline_ms: u64,
    idempotency_key: &'a str,
}

impl ApprovalRequest {
    pub fn new(draft: ApprovalRequestDraft) -> Result<Self, M6AuthorityError> {
        let mut request = Self {
            schema: APPROVAL_REQUEST_SCHEMA.to_string(),
            request_id: draft.request_id,
            factory_id: draft.factory_id,
            requester_principal_id: draft.requester_principal_id,
            route_id: draft.route_id,
            route_generation: draft.route_generation,
            message_digest: draft.message_digest,
            exchange_digest: draft.exchange_digest,
            raw_quarantine_digest: draft.raw_quarantine_digest,
            authenticated_source_identity_digest: draft.authenticated_source_identity_digest,
            source_package_digest: draft.source_package_digest,
            receiver_package_digest: draft.receiver_package_digest,
            source_component_digest: draft.source_component_digest,
            receiver_component_digest: draft.receiver_component_digest,
            m5_export_bundle_digest: draft.m5_export_bundle_digest,
            compatibility_decision_digest: draft.compatibility_decision_digest,
            expected_active_snapshot_digest: draft.expected_active_snapshot_digest,
            rollback_target_digest: draft.rollback_target_digest,
            import_plan_digest: draft.import_plan_digest,
            migration_plan_digest: draft.migration_plan_digest,
            policy_digest: draft.policy_digest,
            proving_digest: draft.proving_digest,
            unresolved_risks_digest: draft.unresolved_risks_digest,
            requested_action: AuthorityAction::AdoptImport,
            requested_at_ms: draft.requested_at_ms,
            deadline_ms: draft.deadline_ms,
            idempotency_key: draft.idempotency_key,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.validate_fields()?;
        request.request_digest = request.expected_digest()?;
        Ok(request)
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn factory_id(&self) -> &str {
        &self.factory_id
    }

    pub fn route_id(&self) -> &str {
        &self.route_id
    }

    pub fn route_generation(&self) -> u64 {
        self.route_generation
    }

    pub fn message_digest(&self) -> &ContentDigest {
        &self.message_digest
    }

    pub fn exchange_digest(&self) -> &ContentDigest {
        &self.exchange_digest
    }

    pub fn raw_quarantine_digest(&self) -> &ContentDigest {
        &self.raw_quarantine_digest
    }

    pub fn authenticated_source_identity_digest(&self) -> &ContentDigest {
        &self.authenticated_source_identity_digest
    }

    pub fn source_package_digest(&self) -> &ContentDigest {
        &self.source_package_digest
    }

    pub fn receiver_package_digest(&self) -> &ContentDigest {
        &self.receiver_package_digest
    }

    pub fn source_component_digest(&self) -> &ContentDigest {
        &self.source_component_digest
    }

    pub fn receiver_component_digest(&self) -> &ContentDigest {
        &self.receiver_component_digest
    }

    pub fn m5_export_bundle_digest(&self) -> &ContentDigest {
        &self.m5_export_bundle_digest
    }

    pub fn compatibility_decision_digest(&self) -> &ContentDigest {
        &self.compatibility_decision_digest
    }

    pub fn expected_active_snapshot_digest(&self) -> &ContentDigest {
        &self.expected_active_snapshot_digest
    }

    pub fn rollback_target_digest(&self) -> &ContentDigest {
        &self.rollback_target_digest
    }

    pub fn import_plan_digest(&self) -> &ContentDigest {
        &self.import_plan_digest
    }

    pub fn migration_plan_digest(&self) -> &ContentDigest {
        &self.migration_plan_digest
    }

    pub fn policy_digest(&self) -> &ContentDigest {
        &self.policy_digest
    }

    pub fn proving_digest(&self) -> &ContentDigest {
        &self.proving_digest
    }

    pub fn unresolved_risks_digest(&self) -> &ContentDigest {
        &self.unresolved_risks_digest
    }

    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    pub fn request_digest(&self) -> &ContentDigest {
        &self.request_digest
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M6AuthorityError> {
        self.validate()?;
        canonical_bytes(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M6AuthorityError> {
        let request: Self = parse_canonical_bytes(bytes)?;
        request.validate()?;
        Ok(request)
    }

    /// Derive the sole exact authorization binding accepted for this immutable
    /// request and terminal decision intent.
    pub fn decision_authorization_binding(
        &self,
        intent: &ApprovalDecisionIntent,
    ) -> Result<ExactActionBinding, M6AuthorityError> {
        self.validate()?;
        intent.validate()?;
        let context_digest = approval_context_digest(self, intent)?;
        Ok(approval_decision_binding(self, intent, context_digest))
    }

    fn validate(&self) -> Result<(), M6AuthorityError> {
        self.validate_fields()?;
        require_digest(
            "approval request",
            &self.request_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6AuthorityError> {
        if self.schema != APPROVAL_REQUEST_SCHEMA
            || self.requested_action != AuthorityAction::AdoptImport
        {
            return Err(M6AuthorityError::InvalidApproval(
                "approval request has an unsupported schema or action".to_string(),
            ));
        }
        validate_identifier("approval request_id", &self.request_id)?;
        validate_identifier("approval factory_id", &self.factory_id)?;
        validate_identifier(
            "approval requester_principal_id",
            &self.requester_principal_id,
        )?;
        validate_identifier("approval route_id", &self.route_id)?;
        validate_identifier("approval idempotency_key", &self.idempotency_key)?;
        if self.route_generation == 0 {
            return Err(M6AuthorityError::InvalidApproval(
                "approval route generation must be nonzero".to_string(),
            ));
        }
        if self.deadline_ms <= self.requested_at_ms {
            return Err(M6AuthorityError::InvalidApproval(
                "approval deadline must be later than request time".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6AuthorityError> {
        digest(&ApprovalRequestDigestMaterial {
            domain: APPROVAL_REQUEST_DOMAIN,
            request_id: &self.request_id,
            factory_id: &self.factory_id,
            requester_principal_id: &self.requester_principal_id,
            route_id: &self.route_id,
            route_generation: self.route_generation,
            message_digest: &self.message_digest,
            exchange_digest: &self.exchange_digest,
            raw_quarantine_digest: &self.raw_quarantine_digest,
            authenticated_source_identity_digest: &self.authenticated_source_identity_digest,
            source_package_digest: &self.source_package_digest,
            receiver_package_digest: &self.receiver_package_digest,
            source_component_digest: &self.source_component_digest,
            receiver_component_digest: &self.receiver_component_digest,
            m5_export_bundle_digest: &self.m5_export_bundle_digest,
            compatibility_decision_digest: &self.compatibility_decision_digest,
            expected_active_snapshot_digest: &self.expected_active_snapshot_digest,
            rollback_target_digest: &self.rollback_target_digest,
            import_plan_digest: &self.import_plan_digest,
            migration_plan_digest: &self.migration_plan_digest,
            policy_digest: &self.policy_digest,
            proving_digest: &self.proving_digest,
            unresolved_risks_digest: &self.unresolved_risks_digest,
            requested_action: self.requested_action,
            requested_at_ms: self.requested_at_ms,
            deadline_ms: self.deadline_ms,
            idempotency_key: &self.idempotency_key,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionKind {
    Granted,
    Denied,
    Expired,
    Escalated,
}

impl ApprovalDecisionKind {
    fn authority_action(self) -> AuthorityAction {
        match self {
            Self::Granted => AuthorityAction::GrantImportApproval,
            Self::Denied => AuthorityAction::DenyImportApproval,
            Self::Expired => AuthorityAction::ExpireImportApproval,
            Self::Escalated => AuthorityAction::EscalateImportApproval,
        }
    }
}

/// Non-durable exact decision command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalDecisionIntent {
    pub kind: ApprovalDecisionKind,
    pub principal_id: String,
    pub rationale: String,
    pub idempotency_key: String,
}

impl ApprovalDecisionIntent {
    pub fn new(
        kind: ApprovalDecisionKind,
        principal_id: impl Into<String>,
        rationale: impl Into<String>,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, M6AuthorityError> {
        let intent = Self {
            kind,
            principal_id: principal_id.into(),
            rationale: rationale.into(),
            idempotency_key: idempotency_key.into(),
        };
        intent.validate()?;
        Ok(intent)
    }

    fn validate(&self) -> Result<(), M6AuthorityError> {
        validate_identifier("approval principal_id", &self.principal_id)?;
        validate_identifier("approval decision idempotency_key", &self.idempotency_key)?;
        if self.rationale.trim().is_empty()
            || self.rationale.len() > MAX_RATIONALE_BYTES
            || self.rationale.chars().any(char::is_control)
        {
            return Err(M6AuthorityError::InvalidApproval(format!(
                "approval rationale must contain 1..={MAX_RATIONALE_BYTES} non-control bytes"
            )));
        }
        Ok(())
    }
}

/// Immutable terminal decision kept separately from its approval request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionRecord {
    schema: String,
    request_digest: ContentDigest,
    factory_id: String,
    kind: ApprovalDecisionKind,
    principal_id: String,
    rationale: String,
    expected_active_snapshot_digest: ContentDigest,
    import_plan_digest: ContentDigest,
    approval_context_digest: ContentDigest,
    authorization_digest: ContentDigest,
    authorization_consumption_digest: ContentDigest,
    idempotency_key: String,
    decided_at_ms: u64,
    decision_digest: ContentDigest,
}

impl ApprovalDecisionRecord {
    pub fn request_digest(&self) -> &ContentDigest {
        &self.request_digest
    }

    pub fn kind(&self) -> ApprovalDecisionKind {
        self.kind
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    pub fn expected_active_snapshot_digest(&self) -> &ContentDigest {
        &self.expected_active_snapshot_digest
    }

    pub fn import_plan_digest(&self) -> &ContentDigest {
        &self.import_plan_digest
    }

    pub fn approval_context_digest(&self) -> &ContentDigest {
        &self.approval_context_digest
    }

    pub fn authorization_digest(&self) -> &ContentDigest {
        &self.authorization_digest
    }

    pub fn authorization_consumption_digest(&self) -> &ContentDigest {
        &self.authorization_consumption_digest
    }

    pub fn decided_at_ms(&self) -> u64 {
        self.decided_at_ms
    }

    pub fn decision_digest(&self) -> &ContentDigest {
        &self.decision_digest
    }

    pub fn canonical_bytes(
        &self,
        request: &ApprovalRequest,
        authorization: &ActionAuthorization,
        consumption: &AuthorizationConsumption,
    ) -> Result<Vec<u8>, M6AuthorityError> {
        self.validate_against(request, authorization, consumption)?;
        canonical_bytes(self)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        request: &ApprovalRequest,
        authorization: &ActionAuthorization,
        consumption: &AuthorizationConsumption,
    ) -> Result<Self, M6AuthorityError> {
        let decision: Self = parse_canonical_bytes(bytes)?;
        decision.validate_against(request, authorization, consumption)?;
        Ok(decision)
    }

    fn new(
        request: &ApprovalRequest,
        intent: &ApprovalDecisionIntent,
        context_digest: ContentDigest,
        authorization: &ActionAuthorization,
        consumption: &AuthorizationConsumption,
        decided_at_ms: u64,
    ) -> Result<Self, M6AuthorityError> {
        let mut record = Self {
            schema: APPROVAL_DECISION_SCHEMA.to_string(),
            request_digest: request.request_digest.clone(),
            factory_id: request.factory_id.clone(),
            kind: intent.kind,
            principal_id: intent.principal_id.clone(),
            rationale: intent.rationale.clone(),
            expected_active_snapshot_digest: request.expected_active_snapshot_digest.clone(),
            import_plan_digest: request.import_plan_digest.clone(),
            approval_context_digest: context_digest,
            authorization_digest: authorization.authorization_digest.clone(),
            authorization_consumption_digest: consumption.receipt_digest.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            decided_at_ms,
            decision_digest: ContentDigest::from_bytes(&[]),
        };
        record.decision_digest = record.expected_digest()?;
        record.validate_against(request, authorization, consumption)?;
        Ok(record)
    }

    fn validate_against(
        &self,
        request: &ApprovalRequest,
        authorization: &ActionAuthorization,
        consumption: &AuthorizationConsumption,
    ) -> Result<(), M6AuthorityError> {
        if self.schema != APPROVAL_DECISION_SCHEMA {
            return Err(M6AuthorityError::Integrity(
                "unsupported approval decision schema".to_string(),
            ));
        }
        validate_identifier("approval decision principal_id", &self.principal_id)?;
        validate_identifier("approval decision idempotency_key", &self.idempotency_key)?;
        if self.rationale.trim().is_empty()
            || self.rationale.len() > MAX_RATIONALE_BYTES
            || self.rationale.chars().any(char::is_control)
        {
            return Err(M6AuthorityError::Integrity(
                "approval decision has an invalid rationale".to_string(),
            ));
        }
        if self.request_digest != request.request_digest
            || self.factory_id != request.factory_id
            || self.expected_active_snapshot_digest != request.expected_active_snapshot_digest
            || self.import_plan_digest != request.import_plan_digest
        {
            return Err(M6AuthorityError::Integrity(
                "approval decision does not bind its exact request, state, and import plan"
                    .to_string(),
            ));
        }
        validate_decision_time(self.kind, request, self.decided_at_ms)?;
        let intent = ApprovalDecisionIntent {
            kind: self.kind,
            principal_id: self.principal_id.clone(),
            rationale: self.rationale.clone(),
            idempotency_key: self.idempotency_key.clone(),
        };
        intent.validate()?;
        let expected_context = approval_context_digest(request, &intent)?;
        require_digest(
            "approval decision context",
            &self.approval_context_digest,
            &expected_context,
        )?;
        if self.authorization_digest != authorization.authorization_digest
            || self.authorization_consumption_digest != consumption.receipt_digest
        {
            return Err(M6AuthorityError::Integrity(
                "approval decision does not bind its authorization consumption".to_string(),
            ));
        }
        let expected_binding = approval_decision_binding(request, &intent, expected_context);
        compare_exact_binding(&authorization.binding, &expected_binding).map_err(|error| {
            M6AuthorityError::Integrity(format!(
                "approval decision authorization is not exact: {error}"
            ))
        })?;
        if authorization.use_limit != 1 || consumption.use_ordinal != 1 {
            return Err(M6AuthorityError::Integrity(
                "approval decision authorization must be single use".to_string(),
            ));
        }
        consumption.validate_against(authorization)?;
        require_digest(
            "approval decision",
            &self.decision_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6AuthorityError> {
        digest(&(
            APPROVAL_DECISION_DOMAIN,
            &self.request_digest,
            &self.factory_id,
            self.kind,
            &self.principal_id,
            &self.rationale,
            &self.expected_active_snapshot_digest,
            &self.import_plan_digest,
            &self.approval_context_digest,
            &self.authorization_digest,
            &self.authorization_consumption_digest,
            &self.idempotency_key,
            self.decided_at_ms,
        ))
    }
}

/// Durable sole-writer store for one endpoint action profile.
///
/// `_owner_lock` is deliberately the final field, so it is released after all
/// credential-independent state held by the store.
pub struct AuthorizationStore<V: OpaqueAuthorizationVerifier> {
    root: PathBuf,
    profile: EndpointActionProfile,
    verifier: V,
    authorizations_root: PathBuf,
    consumptions_root: PathBuf,
    approval_requests_root: PathBuf,
    approval_decisions_root: PathBuf,
    staging_root: PathBuf,
    transaction_lock: Mutex<()>,
    _owner_lock: File,
}

impl<V: OpaqueAuthorizationVerifier> AuthorizationStore<V> {
    pub fn open(
        root: impl AsRef<Path>,
        profile: EndpointActionProfile,
        verifier: V,
    ) -> Result<Self, M6AuthorityError> {
        profile.validate()?;
        if verifier.issuer_id() != profile.issuer_id {
            return Err(M6AuthorityError::CredentialMismatch {
                expected: profile.issuer_id.clone(),
                supplied: verifier.issuer_id().to_string(),
            });
        }

        let root = secure_create_root(root.as_ref())?;
        let owner_lock = acquire_owner_lock(&root)?;
        let staging_root = secure_child_directory(&root, STAGING_DIRECTORY)?;
        recover_staging(&staging_root)?;
        let authorizations_root = secure_child_directory(&root, AUTHORIZATION_DIRECTORY)?;
        let consumptions_root = secure_child_directory(&root, CONSUMPTION_DIRECTORY)?;
        let approval_requests_root = secure_child_directory(&root, APPROVAL_REQUEST_DIRECTORY)?;
        let approval_decisions_root = secure_child_directory(&root, APPROVAL_DECISION_DIRECTORY)?;

        let profile_bytes = canonical_bytes(&profile)?;
        persist_immutable_named(&staging_root, &root.join(PROFILE_FILE), &profile_bytes)?;

        let store = Self {
            root,
            profile,
            verifier,
            authorizations_root,
            consumptions_root,
            approval_requests_root,
            approval_decisions_root,
            staging_root,
            transaction_lock: Mutex::new(()),
            _owner_lock: owner_lock,
        };
        store.validate_all()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn profile(&self) -> &EndpointActionProfile {
        &self.profile
    }

    /// Crate-internal access for portable endpoint evidence builders. The
    /// verifier remains opaque and is never serialized or exposed outside the
    /// crate.
    pub(crate) fn verifier(&self) -> &V {
        &self.verifier
    }

    /// Verify and durably publish an authorization without consuming it.
    pub fn publish_authorization(
        &self,
        authorization: ActionAuthorization,
    ) -> Result<ActionAuthorization, M6AuthorityError> {
        let _guard = self.mutation_guard()?;
        authorization.validate_for(&self.profile, &self.verifier)?;
        self.ensure_authorization_idempotency_available(&authorization)?;
        let destination = self.authorization_path(&authorization.authorization_digest);
        enforce_new_record_bound(&self.authorizations_root, &destination)?;
        let bytes = canonical_bytes(&authorization)?;
        persist_immutable_named(&self.staging_root, &destination, &bytes)?;
        Ok(authorization)
    }

    pub fn load_authorization(
        &self,
        authorization_digest: &ContentDigest,
    ) -> Result<ActionAuthorization, M6AuthorityError> {
        let path = self.authorization_path(authorization_digest);
        if !path.exists() {
            return Err(M6AuthorityError::AuthorizationNotFound(
                authorization_digest.clone(),
            ));
        }
        let authorization: ActionAuthorization = load_canonical_record(&path)?;
        authorization.validate_for(&self.profile, &self.verifier)?;
        if &authorization.authorization_digest != authorization_digest
            || path != self.authorization_path(&authorization.authorization_digest)
        {
            return Err(M6AuthorityError::Integrity(format!(
                "authorization file '{}' does not match its digest identity",
                path.display()
            )));
        }
        Ok(authorization)
    }

    /// Consume one exact use using trusted time from the endpoint clock layer.
    pub fn consume(
        &self,
        invocation: &ActionInvocation,
        trusted_now_ms: u64,
    ) -> Result<AuthorizationConsumption, M6AuthorityError> {
        let _guard = self.mutation_guard()?;
        let authorization = self.load_authorization(&invocation.authorization_digest)?;
        self.consume_loaded(&authorization, invocation, trusted_now_ms)
    }

    pub fn load_consumption(
        &self,
        authorization_digest: &ContentDigest,
        use_ordinal: u32,
    ) -> Result<AuthorizationConsumption, M6AuthorityError> {
        let authorization = self.load_authorization(authorization_digest)?;
        let path = self.consumption_path(authorization_digest, use_ordinal);
        if !path.exists() {
            return Err(M6AuthorityError::ConsumptionNotFound {
                authorization: authorization_digest.clone(),
                use_ordinal,
            });
        }
        self.load_consumption_path(&path, &authorization)
    }

    /// Resolve one already-validated consumption by its immutable receipt
    /// identity. This read-only seam supports endpoint completion evidence
    /// reconstruction when a coordinator stage retained the consumption
    /// digest but not the authorization file name.
    pub fn load_consumption_by_receipt_digest(
        &self,
        receipt_digest: &ContentDigest,
    ) -> Result<(ActionAuthorization, AuthorizationConsumption), M6AuthorityError> {
        let mut found = None;
        for path in bounded_regular_files(&self.consumptions_root)? {
            let candidate: AuthorizationConsumption = load_canonical_record(&path)?;
            if &candidate.receipt_digest != receipt_digest {
                continue;
            }
            let authorization = self.load_authorization(&candidate.authorization_digest)?;
            candidate.validate_against(&authorization)?;
            if found.replace((authorization, candidate)).is_some() {
                return Err(M6AuthorityError::Integrity(format!(
                    "multiple authorization consumptions claim receipt {receipt_digest}"
                )));
            }
        }
        found.ok_or_else(|| M6AuthorityError::ConsumptionNotFound {
            authorization: receipt_digest.clone(),
            use_ordinal: 0,
        })
    }

    /// Resolve the sole authorization and ordinal-one consumption for an
    /// exact action binding. Completion evidence uses this read-only lookup so
    /// it never guesses an authorization identity from coordinator metadata.
    pub fn load_consumption_for_binding(
        &self,
        binding: &ExactActionBinding,
    ) -> Result<(ActionAuthorization, AuthorizationConsumption), M6AuthorityError> {
        binding.validate()?;
        let mut found = None;
        for path in bounded_regular_files(&self.authorizations_root)? {
            let candidate: ActionAuthorization = load_canonical_record(&path)?;
            candidate.validate_for(&self.profile, &self.verifier)?;
            if candidate.binding() != binding {
                continue;
            }
            if found.replace(candidate).is_some() {
                return Err(M6AuthorityError::Integrity(format!(
                    "multiple authorizations claim exact binding {}",
                    binding.binding_digest()?
                )));
            }
        }
        let authorization = found.ok_or_else(|| {
            M6AuthorityError::AuthorizationNotFound(
                binding
                    .binding_digest()
                    .unwrap_or_else(|_| ContentDigest::from_bytes(b"invalid-exact-action-binding")),
            )
        })?;
        if authorization.use_limit() != 1 {
            return Err(M6AuthorityError::Integrity(
                "portable completion evidence requires a single-use authorization".to_string(),
            ));
        }
        let consumption = self.load_consumption(authorization.authorization_digest(), 1)?;
        Ok((authorization, consumption))
    }

    pub fn publish_approval_request(
        &self,
        request: ApprovalRequest,
    ) -> Result<ApprovalRequest, M6AuthorityError> {
        let _guard = self.mutation_guard()?;
        self.require_approval_profile()?;
        request.validate()?;
        if request.factory_id != self.profile.factory_id {
            return Err(M6AuthorityError::TargetMismatch("factory_id"));
        }
        self.ensure_approval_request_identity_available(&request)?;
        let destination = self.approval_request_path(&request.request_digest);
        enforce_new_record_bound(&self.approval_requests_root, &destination)?;
        let bytes = canonical_bytes(&request)?;
        persist_immutable_named(&self.staging_root, &destination, &bytes)?;
        Ok(request)
    }

    pub fn load_approval_request(
        &self,
        request_digest: &ContentDigest,
    ) -> Result<ApprovalRequest, M6AuthorityError> {
        self.require_approval_profile()?;
        let path = self.approval_request_path(request_digest);
        if !path.exists() {
            return Err(M6AuthorityError::ApprovalRequestNotFound(
                request_digest.clone(),
            ));
        }
        let request: ApprovalRequest = load_canonical_record(&path)?;
        request.validate()?;
        if request.factory_id != self.profile.factory_id
            || &request.request_digest != request_digest
            || path != self.approval_request_path(&request.request_digest)
        {
            return Err(M6AuthorityError::Integrity(format!(
                "approval request file '{}' does not match its exact identity",
                path.display()
            )));
        }
        Ok(request)
    }

    /// Consume exact approval authority and publish one terminal decision.
    ///
    /// Exact retries return the already durable decision. A different
    /// authorization, outcome, rationale, principal, or idempotency key cannot
    /// replace it.
    pub fn record_approval_decision(
        &self,
        request_digest: &ContentDigest,
        authorization_digest: &ContentDigest,
        intent: ApprovalDecisionIntent,
        trusted_now_ms: u64,
    ) -> Result<ApprovalDecisionRecord, M6AuthorityError> {
        let _guard = self.mutation_guard()?;
        self.require_approval_profile()?;
        intent.validate()?;
        let request = self.load_approval_request(request_digest)?;
        let destination = self.approval_decision_path(request_digest);

        if destination.exists() {
            let existing = self.load_approval_decision(request_digest)?;
            if existing.kind == intent.kind
                && existing.principal_id == intent.principal_id
                && existing.rationale == intent.rationale
                && existing.idempotency_key == intent.idempotency_key
                && existing.authorization_digest == *authorization_digest
            {
                return Ok(existing);
            }
            return Err(M6AuthorityError::ApprovalAlreadyDecided {
                request: request_digest.clone(),
                existing: existing.decision_digest,
            });
        }

        let context_digest = approval_context_digest(&request, &intent)?;
        let expected_binding = approval_decision_binding(&request, &intent, context_digest.clone());
        let authorization = self.load_authorization(authorization_digest)?;
        if authorization.use_limit != 1 {
            return Err(M6AuthorityError::InvalidApproval(
                "approval decision authorization must have use_limit=1".to_string(),
            ));
        }
        compare_exact_binding(&authorization.binding, &expected_binding)?;
        let consumption_already_committed = self.consumption_path(authorization_digest, 1).exists();
        if !consumption_already_committed {
            validate_decision_time(intent.kind, &request, trusted_now_ms)?;
        }
        let invocation = ActionInvocation::new(authorization_digest.clone(), expected_binding, 1)?;
        let consumption = self.consume_loaded(&authorization, &invocation, trusted_now_ms)?;
        validate_decision_time(intent.kind, &request, consumption.consumed_at_ms)?;
        let decision = ApprovalDecisionRecord::new(
            &request,
            &intent,
            context_digest,
            &authorization,
            &consumption,
            consumption.consumed_at_ms,
        )?;
        enforce_new_record_bound(&self.approval_decisions_root, &destination)?;
        let bytes = canonical_bytes(&decision)?;
        persist_immutable_named(&self.staging_root, &destination, &bytes)?;
        Ok(decision)
    }

    pub fn load_approval_decision(
        &self,
        request_digest: &ContentDigest,
    ) -> Result<ApprovalDecisionRecord, M6AuthorityError> {
        self.require_approval_profile()?;
        let request = self.load_approval_request(request_digest)?;
        let path = self.approval_decision_path(request_digest);
        if !path.exists() {
            return Err(M6AuthorityError::ApprovalDecisionNotFound(
                request_digest.clone(),
            ));
        }
        let decision: ApprovalDecisionRecord = load_canonical_record(&path)?;
        let authorization = self.load_authorization(&decision.authorization_digest)?;
        let consumption = self.load_consumption(&decision.authorization_digest, 1)?;
        decision.validate_against(&request, &authorization, &consumption)?;
        if &decision.request_digest != request_digest
            || path != self.approval_decision_path(&decision.request_digest)
        {
            return Err(M6AuthorityError::Integrity(format!(
                "approval decision file '{}' does not match its request identity",
                path.display()
            )));
        }
        Ok(decision)
    }

    /// Revalidate every durable byte reachable from this store.
    pub fn validate_all(&self) -> Result<(), M6AuthorityError> {
        let _guard = self.mutation_guard()?;
        self.validate_all_unlocked()
    }

    fn validate_all_unlocked(&self) -> Result<(), M6AuthorityError> {
        let durable_profile: EndpointActionProfile =
            load_canonical_record(&self.root.join(PROFILE_FILE))?;
        durable_profile.validate()?;
        if durable_profile != self.profile {
            return Err(M6AuthorityError::ProfileConflict {
                expected: self.profile.profile_digest.clone(),
                durable: durable_profile.profile_digest,
            });
        }

        let mut authorization_idempotency = BTreeMap::new();
        for path in bounded_regular_files(&self.authorizations_root)? {
            let authorization: ActionAuthorization = load_canonical_record(&path)?;
            authorization.validate_for(&self.profile, &self.verifier)?;
            if path != self.authorization_path(&authorization.authorization_digest) {
                return Err(M6AuthorityError::Integrity(format!(
                    "authorization file '{}' has a non-canonical name",
                    path.display()
                )));
            }
            if let Some(existing) = authorization_idempotency.insert(
                authorization.binding.idempotency_key.clone(),
                authorization.authorization_digest.clone(),
            ) {
                return Err(M6AuthorityError::ConflictingReuse {
                    idempotency_key: authorization.binding.idempotency_key.clone(),
                    existing,
                    requested: authorization.authorization_digest,
                });
            }
        }

        for path in bounded_regular_files(&self.consumptions_root)? {
            let consumption: AuthorizationConsumption = load_canonical_record(&path)?;
            let authorization = self.load_authorization(&consumption.authorization_digest)?;
            consumption.validate_against(&authorization)?;
            if path
                != self.consumption_path(&consumption.authorization_digest, consumption.use_ordinal)
            {
                return Err(M6AuthorityError::Integrity(format!(
                    "consumption file '{}' has a non-canonical name",
                    path.display()
                )));
            }
            if consumption.use_ordinal > 1 {
                let prior = self.consumption_path(
                    &consumption.authorization_digest,
                    consumption.use_ordinal - 1,
                );
                if !prior.exists() {
                    return Err(M6AuthorityError::Integrity(format!(
                        "consumption file '{}' has a missing prior ordinal",
                        path.display()
                    )));
                }
            }
        }

        let mut approval_request_ids = BTreeMap::new();
        let mut approval_idempotency = BTreeMap::new();
        for path in bounded_regular_files(&self.approval_requests_root)? {
            self.require_approval_profile()?;
            let request: ApprovalRequest = load_canonical_record(&path)?;
            request.validate()?;
            if request.factory_id != self.profile.factory_id
                || path != self.approval_request_path(&request.request_digest)
            {
                return Err(M6AuthorityError::Integrity(format!(
                    "approval request file '{}' has a non-canonical identity",
                    path.display()
                )));
            }
            if let Some(existing) = approval_request_ids
                .insert(request.request_id.clone(), request.request_digest.clone())
            {
                return Err(M6AuthorityError::ApprovalRequestRebound {
                    identity: request.request_id,
                    existing,
                    requested: request.request_digest,
                });
            }
            if let Some(existing) = approval_idempotency.insert(
                request.idempotency_key.clone(),
                request.request_digest.clone(),
            ) {
                return Err(M6AuthorityError::ApprovalRequestRebound {
                    identity: request.idempotency_key,
                    existing,
                    requested: request.request_digest,
                });
            }
        }

        for path in bounded_regular_files(&self.approval_decisions_root)? {
            self.require_approval_profile()?;
            let decision: ApprovalDecisionRecord = load_canonical_record(&path)?;
            let request = self.load_approval_request(&decision.request_digest)?;
            let authorization = self.load_authorization(&decision.authorization_digest)?;
            let consumption = self.load_consumption(&decision.authorization_digest, 1)?;
            decision.validate_against(&request, &authorization, &consumption)?;
            if path != self.approval_decision_path(&decision.request_digest) {
                return Err(M6AuthorityError::Integrity(format!(
                    "approval decision file '{}' has a non-canonical identity",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    fn mutation_guard(&self) -> Result<MutexGuard<'_, ()>, M6AuthorityError> {
        self.transaction_lock.lock().map_err(|_| {
            M6AuthorityError::Integrity("authority-store transaction mutex is poisoned".to_string())
        })
    }

    fn consume_loaded(
        &self,
        authorization: &ActionAuthorization,
        invocation: &ActionInvocation,
        trusted_now_ms: u64,
    ) -> Result<AuthorizationConsumption, M6AuthorityError> {
        authorization.validate_for(&self.profile, &self.verifier)?;
        invocation.binding.validate()?;
        if invocation.authorization_digest != authorization.authorization_digest {
            return Err(M6AuthorityError::TargetMismatch("authorization_digest"));
        }
        compare_exact_binding(&authorization.binding, &invocation.binding)?;
        if invocation.use_ordinal == 0 || invocation.use_ordinal > authorization.use_limit {
            return Err(M6AuthorityError::UseLimitExceeded {
                limit: authorization.use_limit,
                requested: invocation.use_ordinal,
            });
        }

        let path =
            self.consumption_path(&authorization.authorization_digest, invocation.use_ordinal);
        if path.exists() {
            return self.load_consumption_path(&path, authorization);
        }
        if trusted_now_ms < authorization.issued_at_ms {
            return Err(M6AuthorityError::NotYetValid {
                issued_at_ms: authorization.issued_at_ms,
                trusted_now_ms,
            });
        }
        if trusted_now_ms >= authorization.expires_at_ms {
            return Err(M6AuthorityError::Expired {
                expires_at_ms: authorization.expires_at_ms,
                trusted_now_ms,
            });
        }
        if invocation.use_ordinal > 1 {
            let prior = self.consumption_path(
                &authorization.authorization_digest,
                invocation.use_ordinal - 1,
            );
            if !prior.exists() {
                return Err(M6AuthorityError::UseSequenceGap {
                    requested: invocation.use_ordinal,
                    missing: invocation.use_ordinal - 1,
                });
            }
        }

        let receipt =
            AuthorizationConsumption::new(authorization, invocation.use_ordinal, trusted_now_ms)?;
        enforce_new_record_bound(&self.consumptions_root, &path)?;
        let bytes = canonical_bytes(&receipt)?;
        persist_immutable_named(&self.staging_root, &path, &bytes)?;
        Ok(receipt)
    }

    fn load_consumption_path(
        &self,
        path: &Path,
        authorization: &ActionAuthorization,
    ) -> Result<AuthorizationConsumption, M6AuthorityError> {
        if path.parent() != Some(self.consumptions_root.as_path()) {
            return Err(M6AuthorityError::UnsafePath(path.to_path_buf()));
        }
        let receipt: AuthorizationConsumption = load_canonical_record(path)?;
        receipt.validate_against(authorization)?;
        if path != self.consumption_path(&receipt.authorization_digest, receipt.use_ordinal) {
            return Err(M6AuthorityError::Integrity(format!(
                "consumption file '{}' does not match its exact identity",
                path.display()
            )));
        }
        Ok(receipt)
    }

    fn require_approval_profile(&self) -> Result<(), M6AuthorityError> {
        if self.profile.authority_kind == EndpointAuthorityKind::Approval {
            Ok(())
        } else {
            Err(M6AuthorityError::ActionOutsideProfile {
                action: AuthorityAction::GrantImportApproval,
                profile: self.profile.authority_kind,
            })
        }
    }

    fn ensure_authorization_idempotency_available(
        &self,
        requested: &ActionAuthorization,
    ) -> Result<(), M6AuthorityError> {
        for path in bounded_regular_files(&self.authorizations_root)? {
            let existing: ActionAuthorization = load_canonical_record(&path)?;
            existing.validate_for(&self.profile, &self.verifier)?;
            if existing.binding.idempotency_key == requested.binding.idempotency_key
                && existing.authorization_digest != requested.authorization_digest
            {
                return Err(M6AuthorityError::ConflictingReuse {
                    idempotency_key: requested.binding.idempotency_key.clone(),
                    existing: existing.authorization_digest,
                    requested: requested.authorization_digest.clone(),
                });
            }
        }
        Ok(())
    }

    fn ensure_approval_request_identity_available(
        &self,
        requested: &ApprovalRequest,
    ) -> Result<(), M6AuthorityError> {
        for path in bounded_regular_files(&self.approval_requests_root)? {
            let existing: ApprovalRequest = load_canonical_record(&path)?;
            existing.validate()?;
            let identity_reused = existing.request_id == requested.request_id;
            let idempotency_reused = existing.idempotency_key == requested.idempotency_key;
            if (identity_reused || idempotency_reused)
                && existing.request_digest != requested.request_digest
            {
                return Err(M6AuthorityError::ApprovalRequestRebound {
                    identity: if identity_reused {
                        requested.request_id.clone()
                    } else {
                        requested.idempotency_key.clone()
                    },
                    existing: existing.request_digest,
                    requested: requested.request_digest.clone(),
                });
            }
        }
        Ok(())
    }

    fn authorization_path(&self, digest: &ContentDigest) -> PathBuf {
        self.authorizations_root
            .join(format!("{}.json", digest.file_stem()))
    }

    fn consumption_path(&self, digest: &ContentDigest, use_ordinal: u32) -> PathBuf {
        self.consumptions_root
            .join(format!("{}-{use_ordinal:08}.json", digest.file_stem()))
    }

    fn approval_request_path(&self, digest: &ContentDigest) -> PathBuf {
        self.approval_requests_root
            .join(format!("{}.json", digest.file_stem()))
    }

    fn approval_decision_path(&self, request_digest: &ContentDigest) -> PathBuf {
        self.approval_decisions_root
            .join(format!("{}.json", request_digest.file_stem()))
    }
}

fn approval_context_digest(
    request: &ApprovalRequest,
    intent: &ApprovalDecisionIntent,
) -> Result<ContentDigest, M6AuthorityError> {
    intent.validate()?;
    digest(&(
        APPROVAL_CONTEXT_DOMAIN,
        &request.request_digest,
        intent.kind,
        &intent.principal_id,
        &intent.rationale,
        &intent.idempotency_key,
    ))
}

fn approval_decision_binding(
    request: &ApprovalRequest,
    intent: &ApprovalDecisionIntent,
    context_digest: ContentDigest,
) -> ExactActionBinding {
    ExactActionBinding {
        action: intent.kind.authority_action(),
        principal_id: intent.principal_id.clone(),
        route_id: request.route_id.clone(),
        route_generation: request.route_generation,
        message_digest: request.message_digest.clone(),
        exchange_digest: request.exchange_digest.clone(),
        package_digest: request.receiver_package_digest.clone(),
        request_digest: request.request_digest.clone(),
        expected_active_snapshot_digest: request.expected_active_snapshot_digest.clone(),
        import_plan_digest: request.import_plan_digest.clone(),
        policy_digest: request.policy_digest.clone(),
        proving_digest: request.proving_digest.clone(),
        approval_context_digest: context_digest,
        idempotency_key: intent.idempotency_key.clone(),
    }
}

fn validate_decision_time(
    kind: ApprovalDecisionKind,
    request: &ApprovalRequest,
    trusted_now_ms: u64,
) -> Result<(), M6AuthorityError> {
    match kind {
        ApprovalDecisionKind::Expired if trusted_now_ms < request.deadline_ms => {
            Err(M6AuthorityError::ApprovalDeadlineNotReached {
                deadline_ms: request.deadline_ms,
                trusted_now_ms,
            })
        }
        ApprovalDecisionKind::Granted
        | ApprovalDecisionKind::Denied
        | ApprovalDecisionKind::Escalated
            if trusted_now_ms >= request.deadline_ms =>
        {
            Err(M6AuthorityError::ApprovalDeadlinePassed {
                deadline_ms: request.deadline_ms,
                trusted_now_ms,
            })
        }
        _ => Ok(()),
    }
}

fn compare_exact_binding(
    authorized: &ExactActionBinding,
    requested: &ExactActionBinding,
) -> Result<(), M6AuthorityError> {
    if authorized.action != requested.action {
        return Err(M6AuthorityError::ActionMismatch {
            authorized: authorized.action,
            requested: requested.action,
        });
    }
    if authorized.principal_id != requested.principal_id {
        return Err(M6AuthorityError::TargetMismatch("principal_id"));
    }
    if authorized.route_id != requested.route_id {
        return Err(M6AuthorityError::TargetMismatch("route_id"));
    }
    if authorized.route_generation != requested.route_generation {
        return Err(M6AuthorityError::TargetMismatch("route_generation"));
    }
    if authorized.message_digest != requested.message_digest {
        return Err(M6AuthorityError::TargetMismatch("message_digest"));
    }
    if authorized.exchange_digest != requested.exchange_digest {
        return Err(M6AuthorityError::TargetMismatch("exchange_digest"));
    }
    if authorized.package_digest != requested.package_digest {
        return Err(M6AuthorityError::TargetMismatch("package_digest"));
    }
    if authorized.request_digest != requested.request_digest {
        return Err(M6AuthorityError::TargetMismatch("request_digest"));
    }
    if authorized.expected_active_snapshot_digest != requested.expected_active_snapshot_digest {
        return Err(M6AuthorityError::TargetMismatch(
            "expected_active_snapshot_digest",
        ));
    }
    if authorized.import_plan_digest != requested.import_plan_digest {
        return Err(M6AuthorityError::TargetMismatch("import_plan_digest"));
    }
    if authorized.policy_digest != requested.policy_digest {
        return Err(M6AuthorityError::TargetMismatch("policy_digest"));
    }
    if authorized.proving_digest != requested.proving_digest {
        return Err(M6AuthorityError::TargetMismatch("proving_digest"));
    }
    if authorized.approval_context_digest != requested.approval_context_digest {
        return Err(M6AuthorityError::TargetMismatch("approval_context_digest"));
    }
    if authorized.idempotency_key != requested.idempotency_key {
        return Err(M6AuthorityError::TargetMismatch("idempotency_key"));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), M6AuthorityError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(M6AuthorityError::InvalidIdentifier {
            field,
            limit: MAX_IDENTIFIER_BYTES,
        });
    }
    Ok(())
}

fn validate_attestation(value: &str) -> Result<(), M6AuthorityError> {
    if value.trim().is_empty()
        || value.len() > MAX_ATTESTATION_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(M6AuthorityError::InvalidAuthorization(format!(
            "issuer attestation must contain 1..={MAX_ATTESTATION_BYTES} non-control bytes"
        )));
    }
    Ok(())
}

fn validate_use_limit(use_limit: u32) -> Result<(), M6AuthorityError> {
    if use_limit == 0 || use_limit > MAX_AUTHORIZATION_USES {
        return Err(M6AuthorityError::InvalidAuthorization(format!(
            "authorization use limit must be in 1..={MAX_AUTHORIZATION_USES}"
        )));
    }
    Ok(())
}

fn digest<T: Serialize>(value: &T) -> Result<ContentDigest, M6AuthorityError> {
    digest_json_content(value).map_err(|error| M6AuthorityError::Serialization(error.to_string()))
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, M6AuthorityError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| M6AuthorityError::Serialization(error.to_string()))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(M6AuthorityError::ResourceBoundExceeded {
            resource: "durable authority record",
            actual: bytes.len(),
            limit: MAX_RECORD_BYTES,
        });
    }
    Ok(bytes)
}

fn parse_canonical_bytes<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, M6AuthorityError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(M6AuthorityError::ResourceBoundExceeded {
            resource: "portable authority record",
            actual: bytes.len(),
            limit: MAX_RECORD_BYTES,
        });
    }
    let record: T = serde_json::from_slice(bytes)
        .map_err(|error| M6AuthorityError::Serialization(error.to_string()))?;
    if canonical_bytes(&record)? != bytes {
        return Err(M6AuthorityError::Integrity(
            "portable authority record is not the exact canonical encoding".to_string(),
        ));
    }
    Ok(record)
}

fn require_digest(
    subject: &str,
    actual: &ContentDigest,
    expected: &ContentDigest,
) -> Result<(), M6AuthorityError> {
    if actual == expected {
        Ok(())
    } else {
        Err(M6AuthorityError::Integrity(format!(
            "{subject} digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M6AuthorityError> {
    if path.as_os_str().is_empty() {
        return Err(M6AuthorityError::InvalidStore(
            "authority-store root must not be empty".to_string(),
        ));
    }
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| M6AuthorityError::io(path, source))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6AuthorityError::io(path, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(M6AuthorityError::UnsafePath(path.to_path_buf()));
    }
    fs::canonicalize(path).map_err(|source| M6AuthorityError::io(path, source))
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M6AuthorityError> {
    let path = root.join(name);
    reject_symlink_if_present(&path)?;
    fs::create_dir_all(&path).map_err(|source| M6AuthorityError::io(&path, source))?;
    let canonical =
        fs::canonicalize(&path).map_err(|source| M6AuthorityError::io(&path, source))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|source| M6AuthorityError::io(&canonical, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || canonical.parent() != Some(root) {
        return Err(M6AuthorityError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn acquire_owner_lock(root: &Path) -> Result<File, M6AuthorityError> {
    let path = root.join(OWNER_LOCK_FILE);
    reject_symlink_if_present(&path)?;
    if path.exists() {
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| M6AuthorityError::io(&path, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(M6AuthorityError::UnsafePath(path));
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| M6AuthorityError::io(&path, source))?;
    file.try_lock().map_err(|source| match source {
        std::fs::TryLockError::WouldBlock => M6AuthorityError::DuplicateOwner(root.to_path_buf()),
        std::fs::TryLockError::Error(source) => M6AuthorityError::io(&path, source),
    })?;
    Ok(file)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M6AuthorityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(M6AuthorityError::UnsafePath(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M6AuthorityError::io(path, source)),
    }
}

fn recover_staging(staging_root: &Path) -> Result<(), M6AuthorityError> {
    for path in bounded_regular_files(staging_root)? {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !name.starts_with(".m6-authority-") || !name.ends_with(".tmp") {
            return Err(M6AuthorityError::Integrity(format!(
                "unexpected authority staging entry '{}'",
                path.display()
            )));
        }
        fs::remove_file(&path).map_err(|source| M6AuthorityError::io(&path, source))?;
    }
    File::open(staging_root)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| M6AuthorityError::io(staging_root, source))
}

fn read_regular_file_bounded(path: &Path) -> Result<Vec<u8>, M6AuthorityError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6AuthorityError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(M6AuthorityError::UnsafePath(path.to_path_buf()));
    }
    let byte_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if byte_len > MAX_RECORD_BYTES {
        return Err(M6AuthorityError::ResourceBoundExceeded {
            resource: "durable authority record",
            actual: byte_len,
            limit: MAX_RECORD_BYTES,
        });
    }
    let mut bytes = Vec::with_capacity(byte_len);
    File::open(path)
        .map_err(|source| M6AuthorityError::io(path, source))?
        .take((MAX_RECORD_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| M6AuthorityError::io(path, source))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(M6AuthorityError::ResourceBoundExceeded {
            resource: "durable authority record",
            actual: bytes.len(),
            limit: MAX_RECORD_BYTES,
        });
    }
    Ok(bytes)
}

fn load_canonical_record<T: DeserializeOwned + Serialize>(
    path: &Path,
) -> Result<T, M6AuthorityError> {
    let bytes = read_regular_file_bounded(path)?;
    let record: T = serde_json::from_slice(&bytes)
        .map_err(|error| M6AuthorityError::Serialization(error.to_string()))?;
    let canonical = canonical_bytes(&record)?;
    if canonical != bytes {
        return Err(M6AuthorityError::Integrity(format!(
            "durable file '{}' is not the exact canonical encoding",
            path.display()
        )));
    }
    Ok(record)
}

fn bounded_regular_files(directory: &Path) -> Result<Vec<PathBuf>, M6AuthorityError> {
    let mut paths = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|source| M6AuthorityError::io(directory, source))?
    {
        let entry = entry.map_err(|source| M6AuthorityError::io(directory, source))?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| M6AuthorityError::io(&path, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(M6AuthorityError::UnsafePath(path));
        }
        paths.push(path);
        if paths.len() > MAX_RECORDS_PER_DIRECTORY {
            return Err(M6AuthorityError::ResourceBoundExceeded {
                resource: "durable authority records",
                actual: paths.len(),
                limit: MAX_RECORDS_PER_DIRECTORY,
            });
        }
    }
    paths.sort();
    Ok(paths)
}

fn enforce_new_record_bound(directory: &Path, destination: &Path) -> Result<(), M6AuthorityError> {
    if destination.exists() {
        return Ok(());
    }
    let actual = bounded_regular_files(directory)?.len().saturating_add(1);
    if actual > MAX_RECORDS_PER_DIRECTORY {
        Err(M6AuthorityError::ResourceBoundExceeded {
            resource: "durable authority records",
            actual,
            limit: MAX_RECORDS_PER_DIRECTORY,
        })
    } else {
        Ok(())
    }
}

/// Atomically publish immutable bytes by linking a synchronized staging inode.
fn persist_immutable_named(
    staging_root: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), M6AuthorityError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(M6AuthorityError::ResourceBoundExceeded {
            resource: "durable authority record",
            actual: bytes.len(),
            limit: MAX_RECORD_BYTES,
        });
    }
    reject_symlink_if_present(destination)?;
    if destination.exists() {
        let existing = read_regular_file_bounded(destination)?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(M6AuthorityError::ImmutableConflict(
                destination.to_path_buf(),
            ))
        };
    }
    let destination_parent = destination
        .parent()
        .ok_or_else(|| M6AuthorityError::UnsafePath(destination.to_path_buf()))?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = staging_root.join(format!(
        ".m6-authority-{}-{sequence}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| M6AuthorityError::io(&temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| M6AuthorityError::io(&temporary, source))?;
        file.sync_all()
            .map_err(|source| M6AuthorityError::io(&temporary, source))?;
        match fs::hard_link(&temporary, destination) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_regular_file_bounded(destination)?;
                if existing != bytes {
                    return Err(M6AuthorityError::ImmutableConflict(
                        destination.to_path_buf(),
                    ));
                }
            }
            Err(source) => {
                return Err(M6AuthorityError::io(destination, source));
            }
        }
        File::open(destination_parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| M6AuthorityError::io(destination_parent, source))
    })();
    let _ = fs::remove_file(&temporary);
    let _ = File::open(staging_root).and_then(|directory| directory.sync_all());
    result
}

#[derive(Debug)]
pub enum M6AuthorityError {
    InvalidStore(String),
    InvalidProfile(String),
    InvalidIdentifier {
        field: &'static str,
        limit: usize,
    },
    InvalidAuthorization(String),
    InvalidInvocation(String),
    InvalidApproval(String),
    ActionOutsideProfile {
        action: AuthorityAction,
        profile: EndpointAuthorityKind,
    },
    ActionMismatch {
        authorized: AuthorityAction,
        requested: AuthorityAction,
    },
    TargetMismatch(&'static str),
    CredentialMismatch {
        expected: String,
        supplied: String,
    },
    CredentialRejected,
    CredentialFailure(String),
    NotYetValid {
        issued_at_ms: u64,
        trusted_now_ms: u64,
    },
    Expired {
        expires_at_ms: u64,
        trusted_now_ms: u64,
    },
    UseLimitExceeded {
        limit: u32,
        requested: u32,
    },
    UseSequenceGap {
        requested: u32,
        missing: u32,
    },
    ConflictingReuse {
        idempotency_key: String,
        existing: ContentDigest,
        requested: ContentDigest,
    },
    AuthorizationNotFound(ContentDigest),
    ConsumptionNotFound {
        authorization: ContentDigest,
        use_ordinal: u32,
    },
    ApprovalRequestNotFound(ContentDigest),
    ApprovalDecisionNotFound(ContentDigest),
    ApprovalAlreadyDecided {
        request: ContentDigest,
        existing: ContentDigest,
    },
    ApprovalRequestRebound {
        identity: String,
        existing: ContentDigest,
        requested: ContentDigest,
    },
    ApprovalDeadlineNotReached {
        deadline_ms: u64,
        trusted_now_ms: u64,
    },
    ApprovalDeadlinePassed {
        deadline_ms: u64,
        trusted_now_ms: u64,
    },
    DuplicateOwner(PathBuf),
    ProfileConflict {
        expected: ContentDigest,
        durable: ContentDigest,
    },
    ImmutableConflict(PathBuf),
    Integrity(String),
    UnsafePath(PathBuf),
    ResourceBoundExceeded {
        resource: &'static str,
        actual: usize,
        limit: usize,
    },
    Serialization(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl M6AuthorityError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl Display for M6AuthorityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStore(message) => {
                write!(formatter, "invalid M6 authority store: {message}")
            }
            Self::InvalidProfile(message) => {
                write!(formatter, "invalid endpoint action profile: {message}")
            }
            Self::InvalidIdentifier { field, limit } => write!(
                formatter,
                "{field} must contain 1..={limit} non-control bytes"
            ),
            Self::InvalidAuthorization(message) => {
                write!(formatter, "invalid action authorization: {message}")
            }
            Self::InvalidInvocation(message) => {
                write!(formatter, "invalid authority invocation: {message}")
            }
            Self::InvalidApproval(message) => {
                write!(formatter, "invalid approval record: {message}")
            }
            Self::ActionOutsideProfile { action, profile } => write!(
                formatter,
                "action {action:?} is outside mandatory profile {profile:?}"
            ),
            Self::ActionMismatch {
                authorized,
                requested,
            } => write!(
                formatter,
                "authorization action mismatch: authorized {authorized:?}, requested {requested:?}"
            ),
            Self::TargetMismatch(field) => {
                write!(formatter, "authorization target mismatch at {field}")
            }
            Self::CredentialMismatch { expected, supplied } => write!(
                formatter,
                "credential issuer mismatch: expected {expected}, supplied {supplied}"
            ),
            Self::CredentialRejected => {
                formatter.write_str("opaque issuer verification rejected authorization")
            }
            Self::CredentialFailure(message) => {
                write!(formatter, "opaque credential operation failed: {message}")
            }
            Self::NotYetValid {
                issued_at_ms,
                trusted_now_ms,
            } => write!(
                formatter,
                "authorization is not yet valid: issued {issued_at_ms}, trusted now {trusted_now_ms}"
            ),
            Self::Expired {
                expires_at_ms,
                trusted_now_ms,
            } => write!(
                formatter,
                "authorization expired at {expires_at_ms}; trusted now is {trusted_now_ms}"
            ),
            Self::UseLimitExceeded { limit, requested } => write!(
                formatter,
                "authorization use ordinal {requested} exceeds sealed limit {limit}"
            ),
            Self::UseSequenceGap { requested, missing } => write!(
                formatter,
                "authorization use ordinal {requested} has missing prior ordinal {missing}"
            ),
            Self::ConflictingReuse {
                idempotency_key,
                existing,
                requested,
            } => write!(
                formatter,
                "idempotency key {idempotency_key} is already bound to authorization {existing}, not {requested}"
            ),
            Self::AuthorizationNotFound(digest) => {
                write!(formatter, "authorization {digest} was not found")
            }
            Self::ConsumptionNotFound {
                authorization,
                use_ordinal,
            } => write!(
                formatter,
                "authorization {authorization} has no consumption ordinal {use_ordinal}"
            ),
            Self::ApprovalRequestNotFound(digest) => {
                write!(formatter, "approval request {digest} was not found")
            }
            Self::ApprovalDecisionNotFound(digest) => {
                write!(
                    formatter,
                    "approval decision for request {digest} was not found"
                )
            }
            Self::ApprovalAlreadyDecided { request, existing } => write!(
                formatter,
                "approval request {request} already has immutable decision {existing}"
            ),
            Self::ApprovalRequestRebound {
                identity,
                existing,
                requested,
            } => write!(
                formatter,
                "approval identity {identity} is already bound to request {existing}, not {requested}"
            ),
            Self::ApprovalDeadlineNotReached {
                deadline_ms,
                trusted_now_ms,
            } => write!(
                formatter,
                "approval expiry requested at {trusted_now_ms} before deadline {deadline_ms}"
            ),
            Self::ApprovalDeadlinePassed {
                deadline_ms,
                trusted_now_ms,
            } => write!(
                formatter,
                "approval decision requested at {trusted_now_ms} after deadline {deadline_ms}"
            ),
            Self::DuplicateOwner(path) => write!(
                formatter,
                "M6 authority store '{}' already has a live owner",
                path.display()
            ),
            Self::ProfileConflict { expected, durable } => write!(
                formatter,
                "durable endpoint profile {durable} differs from requested profile {expected}"
            ),
            Self::ImmutableConflict(path) => write!(
                formatter,
                "immutable authority record conflicts with '{}'",
                path.display()
            ),
            Self::Integrity(message) => {
                write!(formatter, "M6 authority integrity failure: {message}")
            }
            Self::UnsafePath(path) => {
                write!(formatter, "unsafe M6 authority path '{}'", path.display())
            }
            Self::ResourceBoundExceeded {
                resource,
                actual,
                limit,
            } => write!(
                formatter,
                "{resource} exceeds its bound: {actual} > {limit}"
            ),
            Self::Serialization(message) => {
                write!(formatter, "M6 authority serialization failed: {message}")
            }
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "M6 authority I/O at '{}': {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for M6AuthorityError {
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
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, Barrier};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct TestCredential {
        issuer_id: String,
        secret: Vec<u8>,
    }

    impl TestCredential {
        fn new(issuer_id: &str, secret: &[u8]) -> Self {
            Self {
                issuer_id: issuer_id.to_string(),
                secret: secret.to_vec(),
            }
        }

        fn proof(&self, payload_digest: &ContentDigest) -> String {
            let mut hasher = Sha256::new();
            hasher.update(b"wasm-biotic:test-opaque-credential:v1");
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
                .expect("system clock")
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "wasm-biotic-m6-authority-{label}-{}-{nonce}",
                std::process::id()
            )))
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn content(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(label.as_bytes())
    }

    fn profile(kind: EndpointAuthorityKind) -> EndpointActionProfile {
        EndpointActionProfile::new(
            format!("profile-{kind:?}"),
            "factory:receiver",
            "issuer:receiver",
            content(&format!("authority-implementation:{kind:?}")),
            kind,
        )
        .expect("endpoint profile")
    }

    fn credential(secret: &[u8]) -> TestCredential {
        TestCredential::new("issuer:receiver", secret)
    }

    fn binding(action: AuthorityAction) -> ExactActionBinding {
        ExactActionBinding {
            action,
            principal_id: "principal:operator".to_string(),
            route_id: "route:a-to-b".to_string(),
            route_generation: 1,
            message_digest: content("message"),
            exchange_digest: content("exchange"),
            package_digest: content("package"),
            request_digest: content("request"),
            expected_active_snapshot_digest: content("active"),
            import_plan_digest: content("import-plan"),
            policy_digest: content("policy"),
            proving_digest: content("proving"),
            approval_context_digest: content("approval-context"),
            idempotency_key: "idempotency:1".to_string(),
        }
    }

    fn issued_authorization(
        profile: EndpointActionProfile,
        credential: TestCredential,
        binding: ExactActionBinding,
        use_limit: u32,
    ) -> ActionAuthorization {
        AuthorizationIssuer::new(profile, credential)
            .expect("issuer")
            .issue(
                ActionAuthorizationRequest::new(binding, use_limit).expect("authorization request"),
                100,
                500,
            )
            .expect("issue authorization")
    }

    fn approval_request(label: &str) -> ApprovalRequest {
        ApprovalRequest::new(ApprovalRequestDraft {
            request_id: format!("approval-request:{label}"),
            factory_id: "factory:receiver".to_string(),
            requester_principal_id: "principal:intake".to_string(),
            route_id: "route:a-to-b".to_string(),
            route_generation: 1,
            message_digest: content(&format!("message:{label}")),
            exchange_digest: content(&format!("exchange:{label}")),
            raw_quarantine_digest: content(&format!("raw-quarantine:{label}")),
            authenticated_source_identity_digest: content("sender-identity"),
            source_package_digest: content(&format!("source-package:{label}")),
            receiver_package_digest: content(&format!("receiver-package:{label}")),
            source_component_digest: content(&format!("source-component:{label}")),
            receiver_component_digest: content(&format!("receiver-component:{label}")),
            m5_export_bundle_digest: content(&format!("m5-export:{label}")),
            compatibility_decision_digest: content(&format!("compatibility:{label}")),
            expected_active_snapshot_digest: content("active"),
            rollback_target_digest: content("rollback-target"),
            import_plan_digest: content(&format!("import-plan:{label}")),
            migration_plan_digest: content(&format!("migration-plan:{label}")),
            policy_digest: content("policy"),
            proving_digest: content(&format!("proving:{label}")),
            unresolved_risks_digest: content(&format!("risks:{label}")),
            requested_at_ms: 100,
            deadline_ms: 400,
            idempotency_key: format!("adopt:{label}"),
        })
        .expect("approval request")
    }

    fn decision_authorization(
        profile: EndpointActionProfile,
        credential: TestCredential,
        request: &ApprovalRequest,
        intent: &ApprovalDecisionIntent,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> ActionAuthorization {
        AuthorizationIssuer::new(profile, credential)
            .expect("approval issuer")
            .issue(
                ActionAuthorizationRequest::new(
                    request
                        .decision_authorization_binding(intent)
                        .expect("decision authorization binding"),
                    1,
                )
                .expect("decision authorization request"),
                issued_at_ms,
                expires_at_ms,
            )
            .expect("decision authorization")
    }

    #[test]
    fn private_issuer_boundary_rejects_self_mint_and_resealed_forgery() {
        let root = TestRoot::new("forgery");
        let endpoint_profile = profile(EndpointAuthorityKind::Promotion);
        let trusted = credential(b"trusted-private-material");
        let store = AuthorizationStore::open(&root.0, endpoint_profile.clone(), trusted.clone())
            .expect("store");

        let self_minted = issued_authorization(
            endpoint_profile.clone(),
            credential(b"attacker-private-material"),
            binding(AuthorityAction::AdoptImport),
            1,
        );
        assert!(matches!(
            store.publish_authorization(self_minted),
            Err(M6AuthorityError::CredentialRejected)
        ));

        let valid = issued_authorization(
            endpoint_profile,
            trusted,
            binding(AuthorityAction::AdoptImport),
            1,
        );
        let mut forged = valid.clone();
        forged.binding.principal_id = "principal:attacker".to_string();
        forged.binding_digest = forged
            .binding
            .binding_digest()
            .expect("forged binding digest");
        forged.payload_digest = forged
            .expected_payload_digest()
            .expect("forged payload digest");
        forged.authorization_digest = forged
            .expected_record_digest()
            .expect("forged record digest");
        assert!(matches!(
            store.publish_authorization(forged),
            Err(M6AuthorityError::CredentialRejected)
        ));
        store
            .publish_authorization(valid)
            .expect("valid private-issuer record");
    }

    #[test]
    fn mandatory_profile_and_exact_action_equality_reject_action_mismatch() {
        let root = TestRoot::new("action-mismatch");
        let endpoint_profile = profile(EndpointAuthorityKind::Promotion);
        let secret = credential(b"promotion-secret");
        let store = AuthorizationStore::open(&root.0, endpoint_profile.clone(), secret.clone())
            .expect("store");

        let outside = AuthorizationIssuer::new(endpoint_profile.clone(), secret.clone())
            .expect("issuer")
            .issue(
                ActionAuthorizationRequest::new(binding(AuthorityAction::RollbackImport), 1)
                    .expect("request"),
                100,
                500,
            );
        assert!(matches!(
            outside,
            Err(M6AuthorityError::ActionOutsideProfile {
                action: AuthorityAction::RollbackImport,
                profile: EndpointAuthorityKind::Promotion
            })
        ));

        let authorization = store
            .publish_authorization(issued_authorization(
                endpoint_profile.clone(),
                secret.clone(),
                binding(AuthorityAction::AdoptImport),
                1,
            ))
            .expect("publish");
        let mut invocation = authorization.invocation(1);
        invocation.binding.action = AuthorityAction::RollbackImport;
        assert!(matches!(
            store.consume(&invocation, 200),
            Err(M6AuthorityError::ActionMismatch {
                authorized: AuthorityAction::AdoptImport,
                requested: AuthorityAction::RollbackImport
            })
        ));
    }

    #[test]
    fn target_state_and_policy_rebinding_are_denied() {
        let root = TestRoot::new("binding-mismatch");
        let endpoint_profile = profile(EndpointAuthorityKind::Promotion);
        let secret = credential(b"promotion-secret");
        let store = AuthorizationStore::open(&root.0, endpoint_profile.clone(), secret.clone())
            .expect("store");
        let authorization = store
            .publish_authorization(issued_authorization(
                endpoint_profile.clone(),
                secret.clone(),
                binding(AuthorityAction::AdoptImport),
                1,
            ))
            .expect("publish");

        let mut target = authorization.invocation(1);
        target.binding.package_digest = content("different-package");
        assert!(matches!(
            store.consume(&target, 200),
            Err(M6AuthorityError::TargetMismatch("package_digest"))
        ));

        let mut state = authorization.invocation(1);
        state.binding.expected_active_snapshot_digest = content("different-active-state");
        assert!(matches!(
            store.consume(&state, 200),
            Err(M6AuthorityError::TargetMismatch(
                "expected_active_snapshot_digest"
            ))
        ));

        let mut plan = authorization.invocation(1);
        plan.binding.import_plan_digest = content("different-import-plan");
        assert!(matches!(
            store.consume(&plan, 200),
            Err(M6AuthorityError::TargetMismatch("import_plan_digest"))
        ));

        let mut policy = authorization.invocation(1);
        policy.binding.policy_digest = content("different-policy");
        assert!(matches!(
            store.consume(&policy, 200),
            Err(M6AuthorityError::TargetMismatch("policy_digest"))
        ));

        let mut conflicting = binding(AuthorityAction::AdoptImport);
        conflicting.package_digest = content("rebound-package");
        assert!(matches!(
            store.publish_authorization(issued_authorization(
                endpoint_profile,
                secret,
                conflicting,
                1,
            )),
            Err(M6AuthorityError::ConflictingReuse {
                idempotency_key,
                ..
            }) if idempotency_key == "idempotency:1"
        ));
    }

    #[test]
    fn expiry_blocks_new_use_but_exact_committed_replay_is_stable() {
        let root = TestRoot::new("expiry-replay");
        let endpoint_profile = profile(EndpointAuthorityKind::Promotion);
        let secret = credential(b"promotion-secret");
        let store = AuthorizationStore::open(&root.0, endpoint_profile.clone(), secret.clone())
            .expect("store");

        let expired = store
            .publish_authorization(issued_authorization(
                endpoint_profile.clone(),
                secret.clone(),
                binding(AuthorityAction::AdoptImport),
                1,
            ))
            .expect("publish expired candidate");
        assert!(matches!(
            store.consume(&expired.invocation(1), 500),
            Err(M6AuthorityError::Expired {
                expires_at_ms: 500,
                trusted_now_ms: 500
            })
        ));

        let mut second_binding = binding(AuthorityAction::AdoptImport);
        second_binding.idempotency_key = "idempotency:second".to_string();
        let committed = store
            .publish_authorization(issued_authorization(
                endpoint_profile,
                secret,
                second_binding,
                1,
            ))
            .expect("publish committed authorization");
        let first = store
            .consume(&committed.invocation(1), 200)
            .expect("first consumption");
        let replay = store
            .consume(&committed.invocation(1), 900)
            .expect("exact replay after expiry");
        assert_eq!(replay, first);
        assert_eq!(replay.consumed_at_ms(), 200);
    }

    #[test]
    fn use_limit_is_ordered_bounded_and_exact_replays_do_not_spend() {
        let root = TestRoot::new("use-limit");
        let endpoint_profile = profile(EndpointAuthorityKind::Observation);
        let secret = credential(b"observation-secret");
        let store = AuthorizationStore::open(&root.0, endpoint_profile.clone(), secret.clone())
            .expect("store");
        let authorization = store
            .publish_authorization(issued_authorization(
                endpoint_profile,
                secret,
                binding(AuthorityAction::ObserveImport),
                2,
            ))
            .expect("publish");

        assert!(matches!(
            store.consume(&authorization.invocation(2), 200),
            Err(M6AuthorityError::UseSequenceGap {
                requested: 2,
                missing: 1
            })
        ));
        let first = store
            .consume(&authorization.invocation(1), 200)
            .expect("first use");
        assert_eq!(
            store
                .consume(&authorization.invocation(1), 201)
                .expect("first exact replay"),
            first
        );
        let second = store
            .consume(&authorization.invocation(2), 202)
            .expect("second use");
        assert_eq!(second.use_ordinal(), 2);
        assert!(matches!(
            store.consume(&authorization.invocation(3), 203),
            Err(M6AuthorityError::UseLimitExceeded {
                limit: 2,
                requested: 3
            })
        ));
    }

    #[test]
    fn concurrent_exact_consumption_is_serialized_to_one_receipt() {
        let root = TestRoot::new("concurrent-consumption");
        let endpoint_profile = profile(EndpointAuthorityKind::Promotion);
        let secret = credential(b"promotion-secret");
        let store = Arc::new(
            AuthorizationStore::open(&root.0, endpoint_profile.clone(), secret.clone())
                .expect("store"),
        );
        let authorization = store
            .publish_authorization(issued_authorization(
                endpoint_profile,
                secret,
                binding(AuthorityAction::AdoptImport),
                1,
            ))
            .expect("publish");
        let invocation = authorization.invocation(1);
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for trusted_now_ms in [200, 201] {
            let store = Arc::clone(&store);
            let invocation = invocation.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .consume(&invocation, trusted_now_ms)
                    .expect("serialized exact consumption")
            }));
        }
        barrier.wait();
        let first = workers.remove(0).join().expect("first worker");
        let second = workers.remove(0).join().expect("second worker");
        assert_eq!(first, second);
        assert!(first.consumed_at_ms() == 200 || first.consumed_at_ms() == 201);
    }

    #[test]
    fn duplicate_owner_fails_before_mutable_use() {
        let root = TestRoot::new("duplicate-owner");
        let endpoint_profile = profile(EndpointAuthorityKind::Promotion);
        let secret = credential(b"promotion-secret");
        let first = AuthorizationStore::open(&root.0, endpoint_profile.clone(), secret.clone())
            .expect("first owner");
        assert!(matches!(
            AuthorizationStore::open(&root.0, endpoint_profile, secret),
            Err(M6AuthorityError::DuplicateOwner(_))
        ));
        drop(first);
    }

    #[test]
    fn restart_revalidates_profile_authorization_and_consumption() {
        let root = TestRoot::new("restart");
        let endpoint_profile = profile(EndpointAuthorityKind::Promotion);
        let secret = credential(b"promotion-secret");
        let (authorization_digest, first_receipt) = {
            let store = AuthorizationStore::open(&root.0, endpoint_profile.clone(), secret.clone())
                .expect("store");
            let authorization = store
                .publish_authorization(issued_authorization(
                    endpoint_profile.clone(),
                    secret.clone(),
                    binding(AuthorityAction::AdoptImport),
                    1,
                ))
                .expect("publish");
            let receipt = store
                .consume(&authorization.invocation(1), 200)
                .expect("consume");
            (authorization.authorization_digest().clone(), receipt)
        };

        let reopened = AuthorizationStore::open(&root.0, endpoint_profile, secret).expect("reopen");
        reopened.validate_all().expect("restart validation");
        let loaded = reopened
            .load_authorization(&authorization_digest)
            .expect("load authorization");
        assert_eq!(loaded.authorization_digest(), &authorization_digest);
        assert_eq!(
            reopened
                .load_consumption(&authorization_digest, 1)
                .expect("load consumption"),
            first_receipt
        );
    }

    #[test]
    fn immutable_authorization_file_tamper_blocks_reopen() {
        let root = TestRoot::new("tamper");
        let endpoint_profile = profile(EndpointAuthorityKind::Promotion);
        let secret = credential(b"promotion-secret");
        let authorization_path = {
            let store = AuthorizationStore::open(&root.0, endpoint_profile.clone(), secret.clone())
                .expect("store");
            let authorization = store
                .publish_authorization(issued_authorization(
                    endpoint_profile.clone(),
                    secret.clone(),
                    binding(AuthorityAction::AdoptImport),
                    1,
                ))
                .expect("publish");
            store.authorization_path(authorization.authorization_digest())
        };

        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&authorization_path).expect("read authorization"))
                .expect("parse authorization");
        value["binding"]["policy_digest"] =
            serde_json::Value::String(content("tampered-policy").as_str().to_string());
        fs::write(
            &authorization_path,
            serde_json::to_vec_pretty(&value).expect("render tamper"),
        )
        .expect("tamper immutable file");

        assert!(matches!(
            AuthorizationStore::open(&root.0, endpoint_profile, secret),
            Err(M6AuthorityError::Integrity(_)) | Err(M6AuthorityError::CredentialRejected)
        ));
    }

    #[test]
    fn approval_decision_is_exact_terminal_and_cannot_be_reused_or_overwritten() {
        let root = TestRoot::new("approval-terminal");
        let endpoint_profile = profile(EndpointAuthorityKind::Approval);
        let secret = credential(b"approval-secret");
        let store = AuthorizationStore::open(&root.0, endpoint_profile.clone(), secret.clone())
            .expect("store");
        let first_request = store
            .publish_approval_request(approval_request("first"))
            .expect("publish first request");
        let mut rebound_request = approval_request("rebound");
        rebound_request.request_id = first_request.request_id.clone();
        rebound_request.request_digest = rebound_request
            .expected_digest()
            .expect("rebound request digest");
        assert!(matches!(
            store.publish_approval_request(rebound_request),
            Err(M6AuthorityError::ApprovalRequestRebound { .. })
        ));
        let grant_intent = ApprovalDecisionIntent::new(
            ApprovalDecisionKind::Granted,
            "principal:approver",
            "receiver proving and exact active state satisfy policy",
            "decision:first:grant",
        )
        .expect("grant intent");
        let public_binding = first_request
            .decision_authorization_binding(&grant_intent)
            .expect("public exact decision binding");
        let private_context =
            approval_context_digest(&first_request, &grant_intent).expect("private context");
        assert_eq!(
            public_binding,
            approval_decision_binding(&first_request, &grant_intent, private_context)
        );
        let grant_authorization = store
            .publish_authorization(decision_authorization(
                endpoint_profile.clone(),
                secret.clone(),
                &first_request,
                &grant_intent,
                100,
                350,
            ))
            .expect("publish grant authorization");
        let granted = store
            .record_approval_decision(
                first_request.request_digest(),
                grant_authorization.authorization_digest(),
                grant_intent.clone(),
                200,
            )
            .expect("grant decision");
        assert_eq!(granted.kind(), ApprovalDecisionKind::Granted);
        assert_eq!(
            granted.expected_active_snapshot_digest(),
            first_request.expected_active_snapshot_digest()
        );
        assert_eq!(
            granted.import_plan_digest(),
            first_request.import_plan_digest()
        );
        assert_eq!(
            store
                .record_approval_decision(
                    first_request.request_digest(),
                    grant_authorization.authorization_digest(),
                    grant_intent,
                    300,
                )
                .expect("exact decision replay"),
            granted
        );

        let deny_intent = ApprovalDecisionIntent::new(
            ApprovalDecisionKind::Denied,
            "principal:approver",
            "attempted overwrite",
            "decision:first:deny",
        )
        .expect("deny intent");
        let deny_authorization = store
            .publish_authorization(decision_authorization(
                endpoint_profile.clone(),
                secret.clone(),
                &first_request,
                &deny_intent,
                100,
                350,
            ))
            .expect("publish deny authorization");
        assert!(matches!(
            store.record_approval_decision(
                first_request.request_digest(),
                deny_authorization.authorization_digest(),
                deny_intent,
                250,
            ),
            Err(M6AuthorityError::ApprovalAlreadyDecided { .. })
        ));

        let second_request = store
            .publish_approval_request(approval_request("second"))
            .expect("publish second request");
        assert!(matches!(
            store.record_approval_decision(
                second_request.request_digest(),
                grant_authorization.authorization_digest(),
                ApprovalDecisionIntent::new(
                    ApprovalDecisionKind::Granted,
                    "principal:approver",
                    "receiver proving and exact active state satisfy policy",
                    "decision:first:grant",
                )
                .expect("reused intent"),
                220,
            ),
            Err(M6AuthorityError::TargetMismatch("message_digest"))
                | Err(M6AuthorityError::TargetMismatch("exchange_digest"))
                | Err(M6AuthorityError::TargetMismatch("package_digest"))
                | Err(M6AuthorityError::TargetMismatch("request_digest"))
                | Err(M6AuthorityError::TargetMismatch("import_plan_digest"))
                | Err(M6AuthorityError::TargetMismatch("proving_digest"))
                | Err(M6AuthorityError::TargetMismatch("approval_context_digest"))
        ));
    }

    #[test]
    fn denial_expiry_and_escalation_are_separate_terminal_records() {
        for (label, kind, decision_time) in [
            ("denied", ApprovalDecisionKind::Denied, 200),
            ("expired", ApprovalDecisionKind::Expired, 400),
            ("escalated", ApprovalDecisionKind::Escalated, 200),
        ] {
            let root = TestRoot::new(label);
            let endpoint_profile = profile(EndpointAuthorityKind::Approval);
            let secret = credential(format!("approval-secret:{label}").as_bytes());
            let store = AuthorizationStore::open(&root.0, endpoint_profile.clone(), secret.clone())
                .expect("store");
            let request = store
                .publish_approval_request(approval_request(label))
                .expect("publish request");
            let intent = ApprovalDecisionIntent::new(
                kind,
                "principal:approver",
                format!("terminal {label} rationale"),
                format!("decision:{label}"),
            )
            .expect("decision intent");
            let authorization = store
                .publish_authorization(decision_authorization(
                    endpoint_profile,
                    secret,
                    &request,
                    &intent,
                    100,
                    500,
                ))
                .expect("publish decision authorization");
            let decision = store
                .record_approval_decision(
                    request.request_digest(),
                    authorization.authorization_digest(),
                    intent,
                    decision_time,
                )
                .expect("record decision");
            assert_eq!(decision.kind(), kind);
            assert_ne!(decision.decision_digest(), request.request_digest());
        }
    }

    #[test]
    fn opaque_credential_bytes_are_never_persisted() {
        let root = TestRoot::new("credential-redaction");
        let endpoint_profile = profile(EndpointAuthorityKind::Promotion);
        let secret_bytes = b"DO-NOT-PERSIST-THIS-OPAQUE-CREDENTIAL";
        let secret = credential(secret_bytes);
        let store = AuthorizationStore::open(&root.0, endpoint_profile.clone(), secret.clone())
            .expect("store");
        store
            .publish_authorization(issued_authorization(
                endpoint_profile,
                secret,
                binding(AuthorityAction::AdoptImport),
                1,
            ))
            .expect("publish");

        fn inspect(path: &Path, secret: &[u8]) {
            for entry in fs::read_dir(path).expect("read durable directory") {
                let entry = entry.expect("directory entry");
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).expect("metadata");
                if metadata.is_dir() {
                    inspect(&path, secret);
                } else {
                    let bytes = fs::read(&path).expect("read durable file");
                    assert!(
                        !bytes.windows(secret.len()).any(|window| window == secret),
                        "credential leaked into {}",
                        path.display()
                    );
                }
            }
        }
        inspect(store.root(), secret_bytes);
    }
}
