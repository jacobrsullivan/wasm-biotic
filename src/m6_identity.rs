//! Cryptographic identity and governed filesystem transport foundations for M6.
//!
//! This module deliberately stops below M5 export-bundle construction and
//! receiver adoption. It provides the bounded primitives required by ADR 0006:
//! distinct Ed25519 factory identities, role- and route-bound signed manifests,
//! runtime-owned clocks and nonces, durable authenticated chains, an immutable
//! staged-to-ready spool, and receiver-owned raw quarantine before parsing.

use crate::execution::artifact::ContentDigest;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const FACTORY_IDENTITY_SCHEMA: &str = "wasm-biotic.m6-factory-identity.v1";
pub const ROUTE_DEFINITION_SCHEMA: &str = "wasm-biotic.m6-route-definition.v1";
pub const RESOURCE_PROFILE_SCHEMA: &str = "wasm-biotic.m6-route-resources.v2";
pub const SIGNED_MANIFEST_SCHEMA: &str = "wasm-biotic.m6-signed-manifest.v1";
pub const CHAIN_STATE_SCHEMA: &str = "wasm-biotic.m6-route-chain-state.v2";
pub const ISSUANCE_RECORD_SCHEMA: &str = "wasm-biotic.m6-issuance-record.v1";
pub const ISSUANCE_ABANDONMENT_SCHEMA: &str = "wasm-biotic.m6-issuance-abandonment.v1";
pub const TERMINAL_NEGATIVE_SCHEMA: &str = "wasm-biotic.m6-terminal-negative.v1";
pub const DELIVERY_COMMIT_SCHEMA: &str = "wasm-biotic.m6-delivery-commit.v1";
pub const RAW_QUARANTINE_SCHEMA: &str = "wasm-biotic.m6-raw-quarantine.v1";
pub const RAW_REJECTION_SCHEMA: &str = "wasm-biotic.m6-raw-rejection.v1";
pub const RAW_ADMISSION_REJECTION_SCHEMA: &str = "wasm-biotic.m6-raw-admission-rejected.v1";
pub const CANONICAL_ENCODING_VERSION: u32 = 1;
pub const FACTORY_IDENTITY_VERSION: u32 = 1;

const IDENTITY_DIGEST_DOMAIN: &[u8] = b"wasm-biotic:m6:factory-identity:v1\0";
const ROUTE_DIGEST_DOMAIN: &[u8] = b"wasm-biotic:m6:route-definition:v1\0";
const RESOURCE_DIGEST_DOMAIN: &[u8] = b"wasm-biotic:m6:resource-profile:v2\0";
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"wasm-biotic:m6:manifest-signature:v1\0";
const SENDER_REOPEN_AUDIT_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:sender-reopen-audit-signature:v1\0";
const SENDER_EXPORT_COMPLETION_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:sender-export-completion-signature:v1\0";
const SENDER_REVOCATION_COMPLETION_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:sender-revocation-completion-signature:v1\0";
const SENDER_ACK_COMPLETION_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:sender-ack-completion-signature:v1\0";
const SENDER_ISOLATION_AUDIT_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:sender-isolation-audit-signature:v1\0";
const RECEIVER_REOPEN_AUDIT_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-reopen-audit-signature:v1\0";
const RECEIVER_INTAKE_COMPLETION_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-intake-completion-signature:v1\0";
const RECEIVER_REVOCATION_COMPLETION_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-revocation-completion-signature:v1\0";
const RECEIVER_REPLAY_CONTROL_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-replay-control-signature:v1\0";
const RECEIVER_QUARANTINE_INVENTORY_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-quarantine-inventory-signature:v1\0";
const RECEIVER_CONTROL_REJECTION_SIGNATURE_DOMAIN: &[u8] =
    b"wasm-biotic:m6:receiver-control-rejection-signature:v1\0";
const MANIFEST_IDENTITY_DOMAIN: &[u8] = b"wasm-biotic:m6:manifest-identity:v1\0";
const CHAIN_STATE_DOMAIN: &[u8] = b"wasm-biotic:m6:chain-state:v1\0";
const ISSUANCE_FINGERPRINT_DOMAIN: &[u8] = b"wasm-biotic:m6:issuance-fingerprint:v1\0";
const ISSUANCE_REQUEST_DOMAIN: &[u8] = b"wasm-biotic:m6:issuance-request:v1\0";
const ISSUANCE_RECORD_DOMAIN: &[u8] = b"wasm-biotic:m6:issuance-record:v1\0";
const ISSUANCE_ABANDONMENT_DOMAIN: &[u8] = b"wasm-biotic:m6:issuance-abandonment:v1\0";
const TERMINAL_NEGATIVE_DOMAIN: &[u8] = b"wasm-biotic:m6:terminal-negative:v1\0";
const ISSUANCE_PATH_DOMAIN: &[u8] = b"wasm-biotic:m6:issuance-path:v1\0";
const RAW_UNIT_DOMAIN: &[u8] = b"wasm-biotic:m6:raw-unit:v1\0";
const MAX_IDENTIFIER_BYTES: usize = 512;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const NONCE_BYTES: usize = 16;
const ROUTE_DEFINITION_FILE: &str = "route-definition.json";
const SENDER_STAGED_DIRECTORY: &str = "sender-staged";
const SENDER_READY_DIRECTORY: &str = "sender-ready";
const RECEIVER_STAGED_DIRECTORY: &str = "receiver-ack-staged";
const RECEIVER_READY_DIRECTORY: &str = "receiver-ack-ready";
const LOCKS_DIRECTORY: &str = "role-locks";
const QUARANTINE_DIRECTORY: &str = "m6-raw-quarantine";
const RAW_ADMISSION_REJECTIONS_DIRECTORY: &str = "admission-rejections";
const MANIFEST_FILE: &str = "manifest.json";
const ATTACHMENTS_DIRECTORY: &str = "attachments";
const DELIVERY_COMMIT_FILE: &str = "commit.json";
const RAW_RECORD_FILE: &str = "raw-record.json";
const RAW_COMMIT_FILE: &str = "raw-commit.json";
const RAW_UNIT_DIRECTORY: &str = "unit";
const RAW_REJECTION_FILE: &str = "rejection.json";
const RAW_ADMISSION_REJECTION_SUFFIX: &str = ".raw-admission-rejected.json";
const RAW_QUARANTINE_STAGING_PREFIX: &str = ".raw-stage-";
const RAW_ADMISSION_ABSOLUTE_ENTRY_CAP: u32 = 4_096;
const RAW_ADMISSION_ABSOLUTE_BYTE_CAP: u64 = 64 * 1_048_576;
const RAW_ADMISSION_REJECTION_MAX_BYTES: usize = 8 * 1_048_576;
const ISSUANCE_DIRECTORY: &str = "m6-issued-manifests";
const ISSUER_LOCKS_DIRECTORY: &str = "m6-issuer-locks";
const ISSUANCE_RECORD_FILE: &str = "issuance-record.json";
const ISSUANCE_ABANDONMENT_FILE: &str = "issuance-abandonment.json";
const TERMINAL_NEGATIVE_DIRECTORY: &str = "m6-terminal-negatives";
const TERMINAL_NEGATIVE_SUFFIX: &str = ".terminal-negative.json";
const TERMINAL_NEGATIVE_STAGING_PREFIX: &str = ".building-terminal-negative-";

/// Endpoint-local top-level directories whose contents are owned by the M6
/// identity layer. Higher-level endpoint runtimes use this list to keep an M5
/// runtime root disjoint from identity journals, issuance state, and raw
/// quarantine.
pub(crate) const IDENTITY_MUTABLE_TOP_LEVEL_DIRECTORIES: &[&str] = &[
    "m6-route-chains",
    ISSUANCE_DIRECTORY,
    ISSUER_LOCKS_DIRECTORY,
    TERMINAL_NEGATIVE_DIRECTORY,
    QUARANTINE_DIRECTORY,
];

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteEndpointRole {
    Sender,
    Receiver,
}

impl RouteEndpointRole {
    fn label(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Receiver => "receiver",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestKind {
    Export,
    Revocation,
    ReceiverAcknowledgement,
}

impl ManifestKind {
    pub fn origin_role(self) -> RouteEndpointRole {
        match self {
            Self::Export | Self::Revocation => RouteEndpointRole::Sender,
            Self::ReceiverAcknowledgement => RouteEndpointRole::Receiver,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Export => "export",
            Self::Revocation => "revocation",
            Self::ReceiverAcknowledgement => "receiver-acknowledgement",
        }
    }
}

#[derive(Debug)]
pub enum M6IdentityError {
    InvalidConfiguration(String),
    UnsupportedSchema(String),
    Serialization(String),
    CanonicalEncoding(String),
    Signature(String),
    SignatureInvalid,
    FalseIdentity {
        subject: &'static str,
        expected: String,
        actual: String,
    },
    WrongRole {
        expected: RouteEndpointRole,
        actual: RouteEndpointRole,
    },
    DigestMismatch {
        subject: String,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    Replay {
        sequence: u64,
    },
    NonceReplay(String),
    MessageReplay(ContentDigest),
    SequenceGap {
        expected: u64,
        actual: u64,
    },
    ChainConflict {
        expected: Option<ContentDigest>,
        actual: Option<ContentDigest>,
    },
    Expired {
        now_ms: u64,
        expires_at_ms: u64,
    },
    FutureMessage {
        now_ms: u64,
        issued_at_ms: u64,
    },
    ClockUntrusted {
        watermark_ms: u64,
        observed_ms: u64,
    },
    ResourceExhausted(String),
    UnsafePath(PathBuf),
    RouteConflict(PathBuf),
    RoleAlreadyOwned(RouteEndpointRole),
    IssuanceConflict {
        idempotency_key: String,
        existing: ContentDigest,
        requested: ContentDigest,
    },
    PendingIssuance {
        idempotency_key: String,
        request_digest: ContentDigest,
    },
    IssuanceAbandoned {
        idempotency_key: String,
        abandonment_digest: ContentDigest,
    },
    IssuanceAbandonmentConflict {
        idempotency_key: String,
        existing: ContentDigest,
        requested: ContentDigest,
    },
    MissingNegativeEvidence,
    TerminalNegativeConflict {
        message_digest: ContentDigest,
        existing: ContentDigest,
        requested: ContentDigest,
    },
    ContradictoryNegativeTiming {
        disposition: TerminalNegativeDisposition,
        now_ms: u64,
        expires_at_ms: u64,
    },
    StateIntegrity(String),
    MalformedQuarantined {
        raw_unit_digest: ContentDigest,
        reason: String,
    },
    AdmissionRejected {
        rejection_digest: ContentDigest,
        violation: RawAdmissionViolation,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl M6IdentityError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl Display for M6IdentityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid M6 identity configuration: {message}")
            }
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported M6 identity schema '{schema}'")
            }
            Self::Serialization(message) => write!(formatter, "serialization failed: {message}"),
            Self::CanonicalEncoding(message) => {
                write!(formatter, "non-canonical M6 encoding: {message}")
            }
            Self::Signature(message) => write!(formatter, "signature operation failed: {message}"),
            Self::SignatureInvalid => formatter.write_str("Ed25519 signature verification failed"),
            Self::FalseIdentity {
                subject,
                expected,
                actual,
            } => write!(
                formatter,
                "false {subject} identity: expected '{expected}', got '{actual}'"
            ),
            Self::WrongRole { expected, actual } => {
                write!(formatter, "route role is {actual:?}; expected {expected:?}")
            }
            Self::DigestMismatch {
                subject,
                expected,
                actual,
            } => write!(
                formatter,
                "{subject} digest mismatch: expected {expected}, got {actual}"
            ),
            Self::Replay { sequence } => write!(formatter, "sequence {sequence} is a replay"),
            Self::NonceReplay(nonce) => write!(formatter, "nonce '{nonce}' is a replay"),
            Self::MessageReplay(digest) => write!(formatter, "message '{digest}' is a replay"),
            Self::SequenceGap { expected, actual } => {
                write!(formatter, "sequence gap: expected {expected}, got {actual}")
            }
            Self::ChainConflict { expected, actual } => write!(
                formatter,
                "prior-message chain conflict: expected {expected:?}, got {actual:?}"
            ),
            Self::Expired {
                now_ms,
                expires_at_ms,
            } => write!(
                formatter,
                "message expired at {expires_at_ms}; current time is {now_ms}"
            ),
            Self::FutureMessage {
                now_ms,
                issued_at_ms,
            } => write!(
                formatter,
                "message issue time {issued_at_ms} is beyond accepted skew at {now_ms}"
            ),
            Self::ClockUntrusted {
                watermark_ms,
                observed_ms,
            } => write!(
                formatter,
                "clock moved behind durable watermark {watermark_ms} to {observed_ms}"
            ),
            Self::ResourceExhausted(message) => {
                write!(formatter, "M6 resource budget exhausted: {message}")
            }
            Self::UnsafePath(path) => write!(formatter, "unsafe M6 path '{}'", path.display()),
            Self::RouteConflict(path) => {
                write!(
                    formatter,
                    "immutable route conflict at '{}'",
                    path.display()
                )
            }
            Self::RoleAlreadyOwned(role) => {
                write!(formatter, "M6 {role:?} route role already has a live owner")
            }
            Self::IssuanceConflict {
                idempotency_key,
                existing,
                requested,
            } => write!(
                formatter,
                "issuance idempotency key '{idempotency_key}' is bound to {existing}, not {requested}"
            ),
            Self::PendingIssuance {
                idempotency_key,
                request_digest,
            } => write!(
                formatter,
                "issuance '{idempotency_key}' ({request_digest}) is durably pending exact chain commit"
            ),
            Self::IssuanceAbandoned {
                idempotency_key,
                abandonment_digest,
            } => write!(
                formatter,
                "issuance '{idempotency_key}' was immutably abandoned ({abandonment_digest})"
            ),
            Self::IssuanceAbandonmentConflict {
                idempotency_key,
                existing,
                requested,
            } => write!(
                formatter,
                "issuance abandonment '{idempotency_key}' is bound to {existing}, not {requested}"
            ),
            Self::MissingNegativeEvidence => {
                formatter.write_str("terminal-negative outcome has no durable evidence digest")
            }
            Self::TerminalNegativeConflict {
                message_digest,
                existing,
                requested,
            } => write!(
                formatter,
                "terminal-negative record for '{message_digest}' is bound to {existing}, not {requested}"
            ),
            Self::ContradictoryNegativeTiming {
                disposition,
                now_ms,
                expires_at_ms,
            } => write!(
                formatter,
                "terminal-negative disposition {disposition:?} contradicts message expiry {expires_at_ms} at {now_ms}"
            ),
            Self::StateIntegrity(message) => {
                write!(formatter, "M6 state integrity failure: {message}")
            }
            Self::MalformedQuarantined {
                raw_unit_digest,
                reason,
            } => write!(
                formatter,
                "raw unit {raw_unit_digest} was quarantined before malformed input was rejected: {reason}"
            ),
            Self::AdmissionRejected {
                rejection_digest,
                violation,
            } => write!(
                formatter,
                "raw route unit admission was rejected by {violation:?} ({rejection_digest})"
            ),
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "M6 I/O failure at '{}': {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for M6IdentityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Runtime-owned wall clock. Callers never supply authoritative message time.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> Result<u64, M6IdentityError>;
}

#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> Result<u64, M6IdentityError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                M6IdentityError::InvalidConfiguration(format!(
                    "system clock predates Unix epoch: {error}"
                ))
            })?;
        u64::try_from(duration.as_millis()).map_err(|_| {
            M6IdentityError::ResourceExhausted(
                "system time does not fit u64 milliseconds".to_string(),
            )
        })
    }
}

/// Deterministic clock for restart and boundary tests.
pub struct DeterministicClock {
    now_ms: AtomicU64,
}

impl DeterministicClock {
    pub fn new(now_ms: u64) -> Self {
        Self {
            now_ms: AtomicU64::new(now_ms),
        }
    }

    pub fn set(&self, now_ms: u64) {
        self.now_ms.store(now_ms, Ordering::SeqCst);
    }

    pub fn advance(&self, delta_ms: u64) {
        self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl Clock for DeterministicClock {
    fn now_ms(&self) -> Result<u64, M6IdentityError> {
        Ok(self.now_ms.load(Ordering::SeqCst))
    }
}

/// Runtime-owned nonce generator. Implementations must fill every requested
/// byte and production implementations must be cryptographically secure.
pub trait NonceSource: Send + Sync {
    fn fill(&self, destination: &mut [u8]) -> Result<(), M6IdentityError>;
}

#[derive(Default)]
pub struct SystemNonceSource;

impl NonceSource for SystemNonceSource {
    fn fill(&self, destination: &mut [u8]) -> Result<(), M6IdentityError> {
        SystemRandom::new()
            .fill(destination)
            .map_err(|_| M6IdentityError::Signature("secure nonce generation failed".to_string()))
    }
}

/// Deterministic, non-cryptographic nonce source intended only for tests.
pub struct DeterministicNonceSource {
    seed: [u8; 32],
    counter: AtomicU64,
}

impl DeterministicNonceSource {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: AtomicU64::new(0),
        }
    }
}

impl NonceSource for DeterministicNonceSource {
    fn fill(&self, destination: &mut [u8]) -> Result<(), M6IdentityError> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut offset = 0;
        let mut block = 0_u64;
        while offset < destination.len() {
            let digest = Sha256::digest(
                [
                    self.seed.as_slice(),
                    counter.to_be_bytes().as_slice(),
                    block.to_be_bytes().as_slice(),
                ]
                .concat(),
            );
            let remaining = destination.len() - offset;
            let count = remaining.min(digest.len());
            destination[offset..offset + count].copy_from_slice(&digest[..count]);
            offset += count;
            block = block.saturating_add(1);
        }
        Ok(())
    }
}

/// Opaque in-memory Ed25519 signer. It intentionally has no serialization
/// implementation and exposes only its public key and signature operation.
pub struct FactorySigner {
    signing_key_id: String,
    key_pair: Ed25519KeyPair,
}

impl Debug for FactorySigner {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FactorySigner")
            .field("signing_key_id", &self.signing_key_id)
            .field("public_key_hex", &self.public_key_hex())
            .finish_non_exhaustive()
    }
}

impl FactorySigner {
    pub fn generate(signing_key_id: impl Into<String>) -> Result<Self, M6IdentityError> {
        let signing_key_id = signing_key_id.into();
        validate_identifier("signing key id", &signing_key_id)?;
        let random = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&random)
            .map_err(|_| M6IdentityError::Signature("Ed25519 key generation failed".to_string()))?;
        let key_pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).map_err(|_| {
            M6IdentityError::Signature("generated Ed25519 key could not be reopened".to_string())
        })?;
        Ok(Self {
            signing_key_id,
            key_pair,
        })
    }

    pub fn from_seed(
        signing_key_id: impl Into<String>,
        seed: [u8; 32],
    ) -> Result<Self, M6IdentityError> {
        let signing_key_id = signing_key_id.into();
        validate_identifier("signing key id", &signing_key_id)?;
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| {
            M6IdentityError::Signature("deterministic Ed25519 seed was rejected".to_string())
        })?;
        Ok(Self {
            signing_key_id,
            key_pair,
        })
    }

    pub fn signing_key_id(&self) -> &str {
        &self.signing_key_id
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    pub fn public_key_hex(&self) -> String {
        hex_encode(self.public_key_bytes())
    }

    fn sign(&self, preimage: &[u8]) -> Vec<u8> {
        self.key_pair.sign(preimage).as_ref().to_vec()
    }

    /// Sign only the domain-separated sender-reopen audit identity. This
    /// helper cannot sign arbitrary bytes and does not interact with the route
    /// message sequence.
    pub(crate) fn sign_sender_reopen_audit(
        &self,
        route: &RouteDefinition,
        audit_digest: &ContentDigest,
    ) -> Result<String, M6IdentityError> {
        route.validate()?;
        if self.signing_key_id != route.sender.signing_key_id
            || self.public_key_hex() != route.sender.public_key_hex
        {
            return Err(M6IdentityError::FalseIdentity {
                subject: "sender reopen signer",
                expected: format!(
                    "{}:{}",
                    route.sender.signing_key_id, route.sender.public_key_hex
                ),
                actual: format!("{}:{}", self.signing_key_id, self.public_key_hex()),
            });
        }
        Ok(hex_encode(&self.sign(
            &sender_reopen_audit_signature_preimage(route, audit_digest),
        )))
    }

    /// Sign only one domain-separated sender export completion identity after
    /// the live runtime has verified its opaque authority sources.
    pub(crate) fn sign_sender_export_completion(
        &self,
        route: &RouteDefinition,
        evidence_digest: &ContentDigest,
    ) -> Result<String, M6IdentityError> {
        route.validate()?;
        if self.signing_key_id != route.sender.signing_key_id
            || self.public_key_hex() != route.sender.public_key_hex
        {
            return Err(M6IdentityError::FalseIdentity {
                subject: "sender completion signer",
                expected: format!(
                    "{}:{}",
                    route.sender.signing_key_id, route.sender.public_key_hex
                ),
                actual: format!("{}:{}", self.signing_key_id, self.public_key_hex()),
            });
        }
        Ok(hex_encode(&self.sign(
            &sender_export_completion_signature_preimage(route, evidence_digest),
        )))
    }

    pub(crate) fn sign_sender_revocation_completion(
        &self,
        route: &RouteDefinition,
        evidence_digest: &ContentDigest,
    ) -> Result<String, M6IdentityError> {
        route.validate()?;
        if self.signing_key_id != route.sender.signing_key_id
            || self.public_key_hex() != route.sender.public_key_hex
        {
            return Err(M6IdentityError::FalseIdentity {
                subject: "sender revocation completion signer",
                expected: format!(
                    "{}:{}",
                    route.sender.signing_key_id, route.sender.public_key_hex
                ),
                actual: format!("{}:{}", self.signing_key_id, self.public_key_hex()),
            });
        }
        Ok(hex_encode(&self.sign(
            &sender_revocation_completion_signature_preimage(route, evidence_digest),
        )))
    }

    /// Sign only one domain-separated sender acknowledgement completion after
    /// the live runtime has revalidated its exact retained source set.
    pub(crate) fn sign_sender_ack_completion(
        &self,
        route: &RouteDefinition,
        evidence_digest: &ContentDigest,
    ) -> Result<String, M6IdentityError> {
        route.validate()?;
        if self.signing_key_id != route.sender.signing_key_id
            || self.public_key_hex() != route.sender.public_key_hex
        {
            return Err(M6IdentityError::FalseIdentity {
                subject: "sender ACK completion signer",
                expected: format!(
                    "{}:{}",
                    route.sender.signing_key_id, route.sender.public_key_hex
                ),
                actual: format!("{}:{}", self.signing_key_id, self.public_key_hex()),
            });
        }
        Ok(hex_encode(&self.sign(
            &sender_ack_completion_signature_preimage(route, evidence_digest),
        )))
    }

    /// Sign only one domain-separated sender isolation audit over the exact
    /// post-control M5 projection cross-linked to two sender export completions.
    pub(crate) fn sign_sender_isolation_audit(
        &self,
        route: &RouteDefinition,
        audit_digest: &ContentDigest,
    ) -> Result<String, M6IdentityError> {
        route.validate()?;
        if self.signing_key_id != route.sender.signing_key_id
            || self.public_key_hex() != route.sender.public_key_hex
        {
            return Err(M6IdentityError::FalseIdentity {
                subject: "sender isolation audit signer",
                expected: format!(
                    "{}:{}",
                    route.sender.signing_key_id, route.sender.public_key_hex
                ),
                actual: format!("{}:{}", self.signing_key_id, self.public_key_hex()),
            });
        }
        Ok(hex_encode(&self.sign(
            &sender_isolation_audit_signature_preimage(route, audit_digest),
        )))
    }

    /// Sign only the domain-separated receiver-reopen audit identity. This
    /// helper cannot sign arbitrary bytes and does not interact with either
    /// direction of the route message sequence.
    pub(crate) fn sign_receiver_reopen_audit(
        &self,
        route: &RouteDefinition,
        audit_digest: &ContentDigest,
    ) -> Result<String, M6IdentityError> {
        route.validate()?;
        if self.signing_key_id != route.receiver.signing_key_id
            || self.public_key_hex() != route.receiver.public_key_hex
        {
            return Err(M6IdentityError::FalseIdentity {
                subject: "receiver reopen signer",
                expected: format!(
                    "{}:{}",
                    route.receiver.signing_key_id, route.receiver.public_key_hex
                ),
                actual: format!("{}:{}", self.signing_key_id, self.public_key_hex()),
            });
        }
        Ok(hex_encode(&self.sign(
            &receiver_reopen_audit_signature_preimage(route, audit_digest),
        )))
    }

    /// Sign one exact receiver intake completion identity after the live
    /// runtime has revalidated its opaque authority sources.
    pub(crate) fn sign_receiver_intake_completion(
        &self,
        route: &RouteDefinition,
        evidence_digest: &ContentDigest,
    ) -> Result<String, M6IdentityError> {
        route.validate()?;
        if self.signing_key_id != route.receiver.signing_key_id
            || self.public_key_hex() != route.receiver.public_key_hex
        {
            return Err(M6IdentityError::FalseIdentity {
                subject: "receiver completion signer",
                expected: format!(
                    "{}:{}",
                    route.receiver.signing_key_id, route.receiver.public_key_hex
                ),
                actual: format!("{}:{}", self.signing_key_id, self.public_key_hex()),
            });
        }
        Ok(hex_encode(&self.sign(
            &receiver_intake_completion_signature_preimage(route, evidence_digest),
        )))
    }

    pub(crate) fn sign_receiver_revocation_completion(
        &self,
        route: &RouteDefinition,
        evidence_digest: &ContentDigest,
    ) -> Result<String, M6IdentityError> {
        self.require_receiver_identity(route, "receiver revocation completion signer")?;
        Ok(hex_encode(&self.sign(
            &receiver_revocation_completion_signature_preimage(route, evidence_digest),
        )))
    }

    pub(crate) fn sign_receiver_replay_control(
        &self,
        route: &RouteDefinition,
        proof_digest: &ContentDigest,
    ) -> Result<String, M6IdentityError> {
        self.require_receiver_identity(route, "receiver replay-control signer")?;
        Ok(hex_encode(&self.sign(
            &receiver_replay_control_signature_preimage(route, proof_digest),
        )))
    }

    pub(crate) fn sign_receiver_quarantine_inventory(
        &self,
        route: &RouteDefinition,
        inventory_digest: &ContentDigest,
    ) -> Result<String, M6IdentityError> {
        self.require_receiver_identity(route, "receiver quarantine-inventory signer")?;
        Ok(hex_encode(&self.sign(
            &receiver_quarantine_inventory_signature_preimage(route, inventory_digest),
        )))
    }

    pub(crate) fn sign_receiver_control_rejection(
        &self,
        route: &RouteDefinition,
        record_digest: &ContentDigest,
    ) -> Result<String, M6IdentityError> {
        self.require_receiver_identity(route, "receiver control-rejection signer")?;
        Ok(hex_encode(&self.sign(
            &receiver_control_rejection_signature_preimage(route, record_digest),
        )))
    }

    fn require_receiver_identity(
        &self,
        route: &RouteDefinition,
        subject: &'static str,
    ) -> Result<(), M6IdentityError> {
        route.validate()?;
        if self.signing_key_id != route.receiver.signing_key_id
            || self.public_key_hex() != route.receiver.public_key_hex
        {
            return Err(M6IdentityError::FalseIdentity {
                subject,
                expected: format!(
                    "{}:{}",
                    route.receiver.signing_key_id, route.receiver.public_key_hex
                ),
                actual: format!("{}:{}", self.signing_key_id, self.public_key_hex()),
            });
        }
        Ok(())
    }
}

pub(crate) fn verify_sender_reopen_audit_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    audit_digest: &ContentDigest,
    signature_hex: &str,
) -> Result<(), M6IdentityError> {
    route.validate()?;
    if signing_key_id != route.sender.signing_key_id {
        return Err(M6IdentityError::FalseIdentity {
            subject: "sender reopen signing key",
            expected: route.sender.signing_key_id.clone(),
            actual: signing_key_id.to_string(),
        });
    }
    let public_key = hex_decode(&route.sender.public_key_hex)?;
    let signature = hex_decode(signature_hex)?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(M6IdentityError::SignatureInvalid);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(
            &sender_reopen_audit_signature_preimage(route, audit_digest),
            &signature,
        )
        .map_err(|_| M6IdentityError::SignatureInvalid)
}

fn sender_reopen_audit_signature_preimage(
    route: &RouteDefinition,
    audit_digest: &ContentDigest,
) -> Vec<u8> {
    let mut preimage = Vec::from(SENDER_REOPEN_AUDIT_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(route.definition_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(route.sender.identity_document_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(audit_digest.as_str().as_bytes());
    preimage
}

pub(crate) fn verify_sender_export_completion_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    evidence_digest: &ContentDigest,
    signature_hex: &str,
) -> Result<(), M6IdentityError> {
    route.validate()?;
    if signing_key_id != route.sender.signing_key_id {
        return Err(M6IdentityError::FalseIdentity {
            subject: "sender completion signing key",
            expected: route.sender.signing_key_id.clone(),
            actual: signing_key_id.to_string(),
        });
    }
    let public_key = hex_decode(&route.sender.public_key_hex)?;
    let signature = hex_decode(signature_hex)?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(M6IdentityError::SignatureInvalid);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(
            &sender_export_completion_signature_preimage(route, evidence_digest),
            &signature,
        )
        .map_err(|_| M6IdentityError::SignatureInvalid)
}

fn sender_export_completion_signature_preimage(
    route: &RouteDefinition,
    evidence_digest: &ContentDigest,
) -> Vec<u8> {
    let mut preimage = Vec::from(SENDER_EXPORT_COMPLETION_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(route.definition_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(route.sender.identity_document_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(evidence_digest.as_str().as_bytes());
    preimage
}

pub(crate) fn verify_sender_revocation_completion_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    evidence_digest: &ContentDigest,
    signature_hex: &str,
) -> Result<(), M6IdentityError> {
    route.validate()?;
    if signing_key_id != route.sender.signing_key_id {
        return Err(M6IdentityError::FalseIdentity {
            subject: "sender revocation completion signing key",
            expected: route.sender.signing_key_id.clone(),
            actual: signing_key_id.to_string(),
        });
    }
    let public_key = hex_decode(&route.sender.public_key_hex)?;
    let signature = hex_decode(signature_hex)?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(M6IdentityError::SignatureInvalid);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(
            &sender_revocation_completion_signature_preimage(route, evidence_digest),
            &signature,
        )
        .map_err(|_| M6IdentityError::SignatureInvalid)
}

fn sender_revocation_completion_signature_preimage(
    route: &RouteDefinition,
    evidence_digest: &ContentDigest,
) -> Vec<u8> {
    let mut preimage = Vec::from(SENDER_REVOCATION_COMPLETION_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(route.definition_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(route.sender.identity_document_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(evidence_digest.as_str().as_bytes());
    preimage
}

pub(crate) fn verify_sender_ack_completion_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    evidence_digest: &ContentDigest,
    signature_hex: &str,
) -> Result<(), M6IdentityError> {
    route.validate()?;
    if signing_key_id != route.sender.signing_key_id {
        return Err(M6IdentityError::FalseIdentity {
            subject: "sender ACK completion signing key",
            expected: route.sender.signing_key_id.clone(),
            actual: signing_key_id.to_string(),
        });
    }
    let public_key = hex_decode(&route.sender.public_key_hex)?;
    let signature = hex_decode(signature_hex)?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(M6IdentityError::SignatureInvalid);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(
            &sender_ack_completion_signature_preimage(route, evidence_digest),
            &signature,
        )
        .map_err(|_| M6IdentityError::SignatureInvalid)
}

fn sender_ack_completion_signature_preimage(
    route: &RouteDefinition,
    evidence_digest: &ContentDigest,
) -> Vec<u8> {
    let mut preimage = Vec::from(SENDER_ACK_COMPLETION_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(route.definition_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(route.sender.identity_document_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(evidence_digest.as_str().as_bytes());
    preimage
}

pub(crate) fn verify_sender_isolation_audit_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    audit_digest: &ContentDigest,
    signature_hex: &str,
) -> Result<(), M6IdentityError> {
    route.validate()?;
    if signing_key_id != route.sender.signing_key_id {
        return Err(M6IdentityError::FalseIdentity {
            subject: "sender isolation audit signing key",
            expected: route.sender.signing_key_id.clone(),
            actual: signing_key_id.to_string(),
        });
    }
    let public_key = hex_decode(&route.sender.public_key_hex)?;
    let signature = hex_decode(signature_hex)?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(M6IdentityError::SignatureInvalid);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(
            &sender_isolation_audit_signature_preimage(route, audit_digest),
            &signature,
        )
        .map_err(|_| M6IdentityError::SignatureInvalid)
}

fn sender_isolation_audit_signature_preimage(
    route: &RouteDefinition,
    audit_digest: &ContentDigest,
) -> Vec<u8> {
    let mut preimage = Vec::from(SENDER_ISOLATION_AUDIT_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(route.definition_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(route.sender.identity_document_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(audit_digest.as_str().as_bytes());
    preimage
}

pub(crate) fn verify_receiver_reopen_audit_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    audit_digest: &ContentDigest,
    signature_hex: &str,
) -> Result<(), M6IdentityError> {
    route.validate()?;
    if signing_key_id != route.receiver.signing_key_id {
        return Err(M6IdentityError::FalseIdentity {
            subject: "receiver reopen signing key",
            expected: route.receiver.signing_key_id.clone(),
            actual: signing_key_id.to_string(),
        });
    }
    let public_key = hex_decode(&route.receiver.public_key_hex)?;
    let signature = hex_decode(signature_hex)?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(M6IdentityError::SignatureInvalid);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(
            &receiver_reopen_audit_signature_preimage(route, audit_digest),
            &signature,
        )
        .map_err(|_| M6IdentityError::SignatureInvalid)
}

fn receiver_reopen_audit_signature_preimage(
    route: &RouteDefinition,
    audit_digest: &ContentDigest,
) -> Vec<u8> {
    let mut preimage = Vec::from(RECEIVER_REOPEN_AUDIT_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(route.definition_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(route.receiver.identity_document_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(audit_digest.as_str().as_bytes());
    preimage
}

pub(crate) fn verify_receiver_intake_completion_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    evidence_digest: &ContentDigest,
    signature_hex: &str,
) -> Result<(), M6IdentityError> {
    route.validate()?;
    if signing_key_id != route.receiver.signing_key_id {
        return Err(M6IdentityError::FalseIdentity {
            subject: "receiver completion signing key",
            expected: route.receiver.signing_key_id.clone(),
            actual: signing_key_id.to_string(),
        });
    }
    let public_key = hex_decode(&route.receiver.public_key_hex)?;
    let signature = hex_decode(signature_hex)?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(M6IdentityError::SignatureInvalid);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(
            &receiver_intake_completion_signature_preimage(route, evidence_digest),
            &signature,
        )
        .map_err(|_| M6IdentityError::SignatureInvalid)
}

fn receiver_intake_completion_signature_preimage(
    route: &RouteDefinition,
    evidence_digest: &ContentDigest,
) -> Vec<u8> {
    let mut preimage = Vec::from(RECEIVER_INTAKE_COMPLETION_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(route.definition_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(route.receiver.identity_document_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(evidence_digest.as_str().as_bytes());
    preimage
}

pub(crate) fn verify_receiver_revocation_completion_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    evidence_digest: &ContentDigest,
    signature_hex: &str,
) -> Result<(), M6IdentityError> {
    verify_receiver_domain_signature(
        route,
        signing_key_id,
        &receiver_revocation_completion_signature_preimage(route, evidence_digest),
        signature_hex,
        "receiver revocation completion signing key",
    )
}

fn receiver_revocation_completion_signature_preimage(
    route: &RouteDefinition,
    evidence_digest: &ContentDigest,
) -> Vec<u8> {
    receiver_signature_preimage(
        RECEIVER_REVOCATION_COMPLETION_SIGNATURE_DOMAIN,
        route,
        evidence_digest,
    )
}

pub(crate) fn verify_receiver_replay_control_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    proof_digest: &ContentDigest,
    signature_hex: &str,
) -> Result<(), M6IdentityError> {
    verify_receiver_domain_signature(
        route,
        signing_key_id,
        &receiver_replay_control_signature_preimage(route, proof_digest),
        signature_hex,
        "receiver replay-control signing key",
    )
}

fn receiver_replay_control_signature_preimage(
    route: &RouteDefinition,
    proof_digest: &ContentDigest,
) -> Vec<u8> {
    receiver_signature_preimage(
        RECEIVER_REPLAY_CONTROL_SIGNATURE_DOMAIN,
        route,
        proof_digest,
    )
}

pub(crate) fn verify_receiver_quarantine_inventory_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    inventory_digest: &ContentDigest,
    signature_hex: &str,
) -> Result<(), M6IdentityError> {
    verify_receiver_domain_signature(
        route,
        signing_key_id,
        &receiver_quarantine_inventory_signature_preimage(route, inventory_digest),
        signature_hex,
        "receiver quarantine-inventory signing key",
    )
}

fn receiver_quarantine_inventory_signature_preimage(
    route: &RouteDefinition,
    inventory_digest: &ContentDigest,
) -> Vec<u8> {
    receiver_signature_preimage(
        RECEIVER_QUARANTINE_INVENTORY_SIGNATURE_DOMAIN,
        route,
        inventory_digest,
    )
}

pub(crate) fn verify_receiver_control_rejection_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    record_digest: &ContentDigest,
    signature_hex: &str,
) -> Result<(), M6IdentityError> {
    verify_receiver_domain_signature(
        route,
        signing_key_id,
        &receiver_control_rejection_signature_preimage(route, record_digest),
        signature_hex,
        "receiver control-rejection signing key",
    )
}

fn receiver_control_rejection_signature_preimage(
    route: &RouteDefinition,
    record_digest: &ContentDigest,
) -> Vec<u8> {
    receiver_signature_preimage(
        RECEIVER_CONTROL_REJECTION_SIGNATURE_DOMAIN,
        route,
        record_digest,
    )
}

fn receiver_signature_preimage(
    domain: &[u8],
    route: &RouteDefinition,
    digest: &ContentDigest,
) -> Vec<u8> {
    let mut preimage = Vec::from(domain);
    preimage.extend_from_slice(route.definition_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(route.receiver.identity_document_digest.as_str().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(digest.as_str().as_bytes());
    preimage
}

fn verify_receiver_domain_signature(
    route: &RouteDefinition,
    signing_key_id: &str,
    preimage: &[u8],
    signature_hex: &str,
    subject: &'static str,
) -> Result<(), M6IdentityError> {
    route.validate()?;
    if signing_key_id != route.receiver.signing_key_id {
        return Err(M6IdentityError::FalseIdentity {
            subject,
            expected: route.receiver.signing_key_id.clone(),
            actual: signing_key_id.to_string(),
        });
    }
    let public_key = hex_decode(&route.receiver.public_key_hex)?;
    let signature = hex_decode(signature_hex)?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(M6IdentityError::SignatureInvalid);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(preimage, &signature)
        .map_err(|_| M6IdentityError::SignatureInvalid)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryIdentityDocument {
    pub authority_profile_digest: ContentDigest,
    pub exchange_policy_digest: ContentDigest,
    pub factory_id: String,
    pub identity_document_digest: ContentDigest,
    pub identity_document_version: u32,
    pub public_key_hex: String,
    pub schema: String,
    pub signing_key_id: String,
    pub supported_interface_schema_digests: Vec<ContentDigest>,
    pub supported_package_schema_digests: Vec<ContentDigest>,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
}

impl FactoryIdentityDocument {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        factory_id: impl Into<String>,
        signer: &FactorySigner,
        valid_from_ms: u64,
        valid_until_ms: u64,
        supported_package_schema_digests: Vec<ContentDigest>,
        supported_interface_schema_digests: Vec<ContentDigest>,
        authority_profile_digest: ContentDigest,
        exchange_policy_digest: ContentDigest,
    ) -> Result<Self, M6IdentityError> {
        let mut document = Self {
            authority_profile_digest,
            exchange_policy_digest,
            factory_id: factory_id.into(),
            identity_document_digest: ContentDigest::from_bytes(&[]),
            identity_document_version: FACTORY_IDENTITY_VERSION,
            public_key_hex: signer.public_key_hex(),
            schema: FACTORY_IDENTITY_SCHEMA.to_string(),
            signing_key_id: signer.signing_key_id().to_string(),
            supported_interface_schema_digests,
            supported_package_schema_digests,
            valid_from_ms,
            valid_until_ms,
        };
        document.validate_fields()?;
        document.identity_document_digest = document.expected_digest()?;
        Ok(document)
    }

    pub fn validate(&self) -> Result<(), M6IdentityError> {
        self.validate_fields()?;
        require_digest(
            "factory identity document",
            &self.identity_document_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6IdentityError> {
        if self.schema != FACTORY_IDENTITY_SCHEMA
            || self.identity_document_version != FACTORY_IDENTITY_VERSION
        {
            return Err(M6IdentityError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("factory id", &self.factory_id)?;
        validate_identifier("signing key id", &self.signing_key_id)?;
        let public_key = hex_decode(&self.public_key_hex)?;
        if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(M6IdentityError::InvalidConfiguration(
                "Ed25519 public key must contain exactly 32 bytes".to_string(),
            ));
        }
        if self.valid_from_ms >= self.valid_until_ms {
            return Err(M6IdentityError::InvalidConfiguration(
                "factory identity validity interval is empty".to_string(),
            ));
        }
        if self.supported_package_schema_digests.is_empty()
            || self.supported_interface_schema_digests.is_empty()
            || !is_strictly_sorted_unique(&self.supported_package_schema_digests)
            || !is_strictly_sorted_unique(&self.supported_interface_schema_digests)
        {
            return Err(M6IdentityError::InvalidConfiguration(
                "supported schema digests must be nonempty, sorted, and unique".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6IdentityError> {
        digest_domain_serializable(
            IDENTITY_DIGEST_DOMAIN,
            &(
                &self.authority_profile_digest,
                &self.exchange_policy_digest,
                &self.factory_id,
                self.identity_document_version,
                &self.public_key_hex,
                &self.schema,
                &self.signing_key_id,
                &self.supported_interface_schema_digests,
                &self.supported_package_schema_digests,
                self.valid_from_ms,
                self.valid_until_ms,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteResourceProfile {
    pub accepted_clock_skew_ms: u64,
    pub allowed_clock_regression_ms: u64,
    pub crash_recovery_interval_ms: u64,
    pub max_attachment_bytes: u64,
    pub max_attachment_count: u32,
    pub max_delivery_bytes: u64,
    pub max_evidence_bytes: u64,
    pub max_manifest_bytes: u64,
    pub max_message_lifetime_ms: u64,
    pub max_package_bytes: u64,
    pub max_proving_cases: u32,
    pub max_proving_fuel: u64,
    pub max_proving_instances: u32,
    pub max_proving_memory_bytes: u64,
    pub max_quarantine_units: u32,
    pub max_ready_units: u32,
    pub max_recovery_attempts: u32,
    pub max_replay_records: u32,
    pub max_retry_attempts: u32,
    pub max_revocation_lifetime_ms: u64,
    pub max_revocation_records: u32,
    pub max_staged_units: u32,
    pub max_transaction_records: u32,
    pub profile_digest: ContentDigest,
    pub route_delivery_retention_ms: u64,
    pub schema: String,
}

impl RouteResourceProfile {
    pub fn bounded_default() -> Result<Self, M6IdentityError> {
        let mut profile = Self {
            accepted_clock_skew_ms: 30_000,
            allowed_clock_regression_ms: 1_000,
            crash_recovery_interval_ms: 86_400_000,
            max_attachment_bytes: 4 * 1_048_576,
            max_attachment_count: 64,
            max_delivery_bytes: 20 * 1_048_576,
            max_evidence_bytes: 320 * 1_048_576,
            max_manifest_bytes: 1_048_576,
            max_message_lifetime_ms: 86_400_000,
            max_package_bytes: 4 * 1_048_576,
            max_proving_cases: 64,
            max_proving_fuel: 100_000,
            max_proving_instances: 16,
            max_proving_memory_bytes: 16 * 1_048_576,
            max_quarantine_units: 1_024,
            max_ready_units: 1_024,
            max_recovery_attempts: 8,
            max_replay_records: 10_000,
            max_retry_attempts: 8,
            max_revocation_lifetime_ms: 86_400_000,
            max_revocation_records: 10_000,
            max_staged_units: 128,
            max_transaction_records: 10_000,
            profile_digest: ContentDigest::from_bytes(&[]),
            route_delivery_retention_ms: 7 * 86_400_000,
            schema: RESOURCE_PROFILE_SCHEMA.to_string(),
        };
        profile.validate_fields()?;
        profile.profile_digest = profile.expected_digest()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), M6IdentityError> {
        self.validate_fields()?;
        require_digest(
            "route resource profile",
            &self.profile_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6IdentityError> {
        if self.schema != RESOURCE_PROFILE_SCHEMA {
            return Err(M6IdentityError::UnsupportedSchema(self.schema.clone()));
        }
        if self.max_manifest_bytes == 0
            || self.max_attachment_count == 0
            || self.max_attachment_bytes == 0
            || self.max_delivery_bytes < self.max_manifest_bytes
            || self.max_evidence_bytes == 0
            || self.max_package_bytes == 0
            || self.max_package_bytes > self.max_attachment_bytes
            || self.max_proving_cases == 0
            || self.max_proving_cases > 1_024
            || self.max_proving_fuel == 0
            || self.max_proving_instances == 0
            || self.max_proving_memory_bytes == 0
            || self.max_ready_units == 0
            || self.max_staged_units == 0
            || self.max_quarantine_units == 0
            || self.max_replay_records == 0
            || self.max_revocation_records == 0
            || self.max_revocation_records > self.max_replay_records
            || self.max_transaction_records == 0
            || self.max_retry_attempts == 0
            || self.max_retry_attempts > 32
            || self.max_recovery_attempts > self.max_retry_attempts
            || self.max_message_lifetime_ms == 0
            || self.max_revocation_lifetime_ms == 0
            || self.max_revocation_lifetime_ms > self.max_message_lifetime_ms
            || self.route_delivery_retention_ms == 0
            || self.crash_recovery_interval_ms == 0
        {
            return Err(M6IdentityError::InvalidConfiguration(
                "route resource limits must be finite and nonzero".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6IdentityError> {
        digest_domain_serializable(
            RESOURCE_DIGEST_DOMAIN,
            &(
                (
                    self.accepted_clock_skew_ms,
                    self.allowed_clock_regression_ms,
                    self.crash_recovery_interval_ms,
                    self.max_attachment_bytes,
                    self.max_attachment_count,
                    self.max_delivery_bytes,
                    self.max_evidence_bytes,
                    self.max_manifest_bytes,
                    self.max_message_lifetime_ms,
                    self.max_package_bytes,
                ),
                (
                    self.max_proving_cases,
                    self.max_proving_fuel,
                    self.max_proving_instances,
                    self.max_proving_memory_bytes,
                    self.max_quarantine_units,
                    self.max_ready_units,
                    self.max_recovery_attempts,
                    self.max_replay_records,
                    self.max_retry_attempts,
                    self.max_revocation_lifetime_ms,
                    self.max_revocation_records,
                    self.max_staged_units,
                    self.max_transaction_records,
                    self.route_delivery_retention_ms,
                    &self.schema,
                ),
            ),
        )
    }

    fn tombstone_retention_ms(&self) -> u64 {
        self.max_message_lifetime_ms
            .saturating_add(self.accepted_clock_skew_ms)
            .saturating_add(self.route_delivery_retention_ms)
            .saturating_add(self.crash_recovery_interval_ms)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePeerBinding {
    pub factory_id: String,
    pub identity_document_digest: ContentDigest,
    pub public_key_hex: String,
    pub role: RouteEndpointRole,
    pub signing_key_id: String,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
}

impl RoutePeerBinding {
    fn from_identity(
        role: RouteEndpointRole,
        identity: &FactoryIdentityDocument,
    ) -> Result<Self, M6IdentityError> {
        identity.validate()?;
        Ok(Self {
            factory_id: identity.factory_id.clone(),
            identity_document_digest: identity.identity_document_digest.clone(),
            public_key_hex: identity.public_key_hex.clone(),
            role,
            signing_key_id: identity.signing_key_id.clone(),
            valid_from_ms: identity.valid_from_ms,
            valid_until_ms: identity.valid_until_ms,
        })
    }

    fn validate(&self, expected_role: RouteEndpointRole) -> Result<(), M6IdentityError> {
        if self.role != expected_role {
            return Err(M6IdentityError::WrongRole {
                expected: expected_role,
                actual: self.role,
            });
        }
        validate_identifier("route peer factory id", &self.factory_id)?;
        validate_identifier("route peer signing key id", &self.signing_key_id)?;
        if hex_decode(&self.public_key_hex)?.len() != ED25519_PUBLIC_KEY_BYTES
            || self.valid_from_ms >= self.valid_until_ms
        {
            return Err(M6IdentityError::InvalidConfiguration(
                "route peer public key or validity interval is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDefinition {
    pub canonical_encoding_version: u32,
    pub definition_digest: ContentDigest,
    pub exchange_policy_digest: ContentDigest,
    pub generation: u64,
    pub receiver: RoutePeerBinding,
    pub resource_profile: RouteResourceProfile,
    pub route_id: String,
    pub schema: String,
    pub sender: RoutePeerBinding,
}

impl RouteDefinition {
    pub fn new(
        route_id: impl Into<String>,
        generation: u64,
        sender: &FactoryIdentityDocument,
        receiver: &FactoryIdentityDocument,
        exchange_policy_digest: ContentDigest,
        resource_profile: RouteResourceProfile,
    ) -> Result<Self, M6IdentityError> {
        let mut definition = Self {
            canonical_encoding_version: CANONICAL_ENCODING_VERSION,
            definition_digest: ContentDigest::from_bytes(&[]),
            exchange_policy_digest,
            generation,
            receiver: RoutePeerBinding::from_identity(RouteEndpointRole::Receiver, receiver)?,
            resource_profile,
            route_id: route_id.into(),
            schema: ROUTE_DEFINITION_SCHEMA.to_string(),
            sender: RoutePeerBinding::from_identity(RouteEndpointRole::Sender, sender)?,
        };
        definition.validate_fields()?;
        definition.definition_digest = definition.expected_digest()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), M6IdentityError> {
        self.validate_fields()?;
        require_digest(
            "route definition",
            &self.definition_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), M6IdentityError> {
        if self.schema != ROUTE_DEFINITION_SCHEMA
            || self.canonical_encoding_version != CANONICAL_ENCODING_VERSION
        {
            return Err(M6IdentityError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("route id", &self.route_id)?;
        if self.generation == 0 {
            return Err(M6IdentityError::InvalidConfiguration(
                "route generation must be nonzero".to_string(),
            ));
        }
        self.sender.validate(RouteEndpointRole::Sender)?;
        self.receiver.validate(RouteEndpointRole::Receiver)?;
        self.resource_profile.validate()?;
        if self.sender.factory_id == self.receiver.factory_id
            || self.sender.identity_document_digest == self.receiver.identity_document_digest
            || self.sender.public_key_hex == self.receiver.public_key_hex
        {
            return Err(M6IdentityError::InvalidConfiguration(
                "sender and receiver identities and Ed25519 public keys must be distinct"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6IdentityError> {
        digest_domain_serializable(
            ROUTE_DIGEST_DOMAIN,
            &(
                self.canonical_encoding_version,
                &self.exchange_policy_digest,
                self.generation,
                &self.receiver,
                &self.resource_profile.profile_digest,
                &self.route_id,
                &self.schema,
                &self.sender,
            ),
        )
    }

    fn peer(&self, role: RouteEndpointRole) -> &RoutePeerBinding {
        match role {
            RouteEndpointRole::Sender => &self.sender,
            RouteEndpointRole::Receiver => &self.receiver,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentDescriptor {
    pub byte_length: u64,
    pub content_digest: ContentDigest,
    pub logical_name: String,
    pub media_type: String,
}

impl AttachmentDescriptor {
    fn validate(&self, profile: &RouteResourceProfile) -> Result<(), M6IdentityError> {
        validate_identifier("attachment logical name", &self.logical_name)?;
        validate_media_type(&self.media_type)?;
        if self.byte_length == 0 || self.byte_length > profile.max_attachment_bytes {
            return Err(M6IdentityError::ResourceExhausted(format!(
                "attachment '{}' exceeds its byte budget",
                self.logical_name
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentInput {
    pub bytes: Vec<u8>,
    pub logical_name: String,
    pub media_type: String,
}

impl AttachmentInput {
    pub fn new(
        logical_name: impl Into<String>,
        media_type: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            bytes,
            logical_name: logical_name.into(),
            media_type: media_type.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportManifestPayload {
    pub component_digest: ContentDigest,
    pub export_bundle_digest: ContentDigest,
    pub package_bytes_digest: ContentDigest,
    pub package_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationManifestPayload {
    pub authorization_digest: ContentDigest,
    pub reason: String,
    pub target_identity: ContentDigest,
    pub target_kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverAcknowledgementPayload {
    pub disposition: String,
    pub intake_record_digest: ContentDigest,
    pub raw_quarantine_digest: ContentDigest,
    pub receiver_transaction_digest: ContentDigest,
    pub sender_message_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ManifestPayload {
    Export(ExportManifestPayload),
    Revocation(RevocationManifestPayload),
    ReceiverAcknowledgement(ReceiverAcknowledgementPayload),
}

impl ManifestPayload {
    pub fn kind(&self) -> ManifestKind {
        match self {
            Self::Export(_) => ManifestKind::Export,
            Self::Revocation(_) => ManifestKind::Revocation,
            Self::ReceiverAcknowledgement(_) => ManifestKind::ReceiverAcknowledgement,
        }
    }

    fn validate(&self) -> Result<(), M6IdentityError> {
        match self {
            Self::Export(_) => Ok(()),
            Self::Revocation(payload) => {
                validate_identifier("revocation target kind", &payload.target_kind)?;
                if payload.reason.trim().is_empty() || payload.reason.len() > 4_096 {
                    return Err(M6IdentityError::InvalidConfiguration(
                        "revocation reason must contain 1..=4096 bytes".to_string(),
                    ));
                }
                Ok(())
            }
            Self::ReceiverAcknowledgement(payload) => {
                validate_identifier("receiver disposition", &payload.disposition)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedManifest {
    pub attachments: Vec<AttachmentDescriptor>,
    pub canonical_encoding_version: u32,
    pub expires_at_ms: u64,
    pub issued_at_ms: u64,
    pub kind: ManifestKind,
    pub nonce: String,
    pub origin_role: RouteEndpointRole,
    pub origin_signing_key_id: String,
    pub payload: ManifestPayload,
    pub policy_digest: ContentDigest,
    pub previous_message_digest: Option<ContentDigest>,
    pub receiver_identity_document_digest: ContentDigest,
    pub resource_profile_digest: ContentDigest,
    pub route_generation: u64,
    pub route_id: String,
    pub schema: String,
    pub sender_identity_document_digest: ContentDigest,
    pub sequence: u64,
}

impl UnsignedManifest {
    fn validate_fields(&self) -> Result<(), M6IdentityError> {
        if self.schema != SIGNED_MANIFEST_SCHEMA
            || self.canonical_encoding_version != CANONICAL_ENCODING_VERSION
        {
            return Err(M6IdentityError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("manifest route id", &self.route_id)?;
        validate_identifier("manifest signing key id", &self.origin_signing_key_id)?;
        validate_nonce(&self.nonce)?;
        self.payload.validate()?;
        if self.route_generation == 0
            || self.sequence == 0
            || self.issued_at_ms >= self.expires_at_ms
            || self.payload.kind() != self.kind
            || self.kind.origin_role() != self.origin_role
        {
            return Err(M6IdentityError::InvalidConfiguration(
                "manifest route, sequence, time, kind, or origin role is invalid".to_string(),
            ));
        }
        if self.sequence == 1 && self.previous_message_digest.is_some()
            || self.sequence > 1 && self.previous_message_digest.is_none()
        {
            return Err(M6IdentityError::InvalidConfiguration(
                "manifest prior-message chain does not match its sequence".to_string(),
            ));
        }
        if !is_strictly_sorted_unique_by(&self.attachments, |attachment| {
            attachment.logical_name.clone()
        }) {
            return Err(M6IdentityError::InvalidConfiguration(
                "manifest attachments must be sorted by unique logical name".to_string(),
            ));
        }
        let mut digests = BTreeSet::new();
        for attachment in &self.attachments {
            if !digests.insert(attachment.content_digest.clone()) {
                return Err(M6IdentityError::InvalidConfiguration(
                    "manifest attachment content digests must be unique".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    pub algorithm: String,
    pub signature_hex: String,
    pub signing_key_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedManifestBody {
    signature: ManifestSignature,
    unsigned: UnsignedManifest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    pub message_digest: ContentDigest,
    pub signature: ManifestSignature,
    pub unsigned: UnsignedManifest,
}

impl SignedManifest {
    pub fn sign(
        unsigned: UnsignedManifest,
        signer: &FactorySigner,
    ) -> Result<Self, M6IdentityError> {
        unsigned.validate_fields()?;
        if signer.signing_key_id() != unsigned.origin_signing_key_id {
            return Err(M6IdentityError::FalseIdentity {
                subject: "origin signing key",
                expected: unsigned.origin_signing_key_id.clone(),
                actual: signer.signing_key_id().to_string(),
            });
        }
        let preimage = signature_preimage(&unsigned)?;
        let signature = ManifestSignature {
            algorithm: "Ed25519".to_string(),
            signature_hex: hex_encode(&signer.sign(&preimage)),
            signing_key_id: signer.signing_key_id().to_string(),
        };
        let mut manifest = Self {
            message_digest: ContentDigest::from_bytes(&[]),
            signature,
            unsigned,
        };
        manifest.message_digest = manifest.expected_digest()?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M6IdentityError> {
        self.validate()?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M6IdentityError> {
        let manifest: Self = parse_canonical(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), M6IdentityError> {
        self.unsigned.validate_fields()?;
        if self.signature.algorithm != "Ed25519"
            || self.signature.signing_key_id != self.unsigned.origin_signing_key_id
            || hex_decode(&self.signature.signature_hex)?.len() != ED25519_SIGNATURE_BYTES
        {
            return Err(M6IdentityError::InvalidConfiguration(
                "manifest signature metadata is invalid".to_string(),
            ));
        }
        require_digest(
            "signed manifest",
            &self.message_digest,
            &self.expected_digest()?,
        )
    }

    pub fn verify_route(&self, route: &RouteDefinition) -> Result<(), M6IdentityError> {
        self.validate()?;
        route.validate()?;
        let unsigned = &self.unsigned;
        if unsigned.route_id != route.route_id || unsigned.route_generation != route.generation {
            return Err(M6IdentityError::FalseIdentity {
                subject: "route",
                expected: format!("{}:{}", route.route_id, route.generation),
                actual: format!("{}:{}", unsigned.route_id, unsigned.route_generation),
            });
        }
        if unsigned.sender_identity_document_digest != route.sender.identity_document_digest {
            return Err(M6IdentityError::FalseIdentity {
                subject: "sender",
                expected: route.sender.identity_document_digest.to_string(),
                actual: unsigned.sender_identity_document_digest.to_string(),
            });
        }
        if unsigned.receiver_identity_document_digest != route.receiver.identity_document_digest {
            return Err(M6IdentityError::FalseIdentity {
                subject: "receiver",
                expected: route.receiver.identity_document_digest.to_string(),
                actual: unsigned.receiver_identity_document_digest.to_string(),
            });
        }
        if unsigned.policy_digest != route.exchange_policy_digest
            || unsigned.resource_profile_digest != route.resource_profile.profile_digest
        {
            return Err(M6IdentityError::FalseIdentity {
                subject: "route policy",
                expected: format!(
                    "{}:{}",
                    route.exchange_policy_digest, route.resource_profile.profile_digest
                ),
                actual: format!(
                    "{}:{}",
                    unsigned.policy_digest, unsigned.resource_profile_digest
                ),
            });
        }
        if unsigned.attachments.len() > route.resource_profile.max_attachment_count as usize
            || unsigned.expires_at_ms.saturating_sub(unsigned.issued_at_ms)
                > route.resource_profile.max_message_lifetime_ms
            || (unsigned.kind == ManifestKind::Revocation
                && unsigned.expires_at_ms.saturating_sub(unsigned.issued_at_ms)
                    > route.resource_profile.max_revocation_lifetime_ms)
        {
            return Err(M6IdentityError::ResourceExhausted(
                "signed manifest exceeds route attachment or lifetime bounds".to_string(),
            ));
        }
        let mut aggregate = 0_u64;
        for attachment in &unsigned.attachments {
            attachment.validate(&route.resource_profile)?;
            aggregate = aggregate.saturating_add(attachment.byte_length);
        }
        if aggregate > route.resource_profile.max_delivery_bytes {
            return Err(M6IdentityError::ResourceExhausted(
                "signed manifest attachment bytes exceed route profile".to_string(),
            ));
        }
        let expected_role = unsigned.kind.origin_role();
        if unsigned.origin_role != expected_role {
            return Err(M6IdentityError::WrongRole {
                expected: expected_role,
                actual: unsigned.origin_role,
            });
        }
        let peer = route.peer(expected_role);
        if unsigned.origin_signing_key_id != peer.signing_key_id {
            return Err(M6IdentityError::FalseIdentity {
                subject: "signing key",
                expected: peer.signing_key_id.clone(),
                actual: unsigned.origin_signing_key_id.clone(),
            });
        }
        if unsigned.issued_at_ms < peer.valid_from_ms || unsigned.issued_at_ms > peer.valid_until_ms
        {
            return Err(M6IdentityError::FalseIdentity {
                subject: "key validity",
                expected: format!("{}..={}", peer.valid_from_ms, peer.valid_until_ms),
                actual: unsigned.issued_at_ms.to_string(),
            });
        }
        let public_key = hex_decode(&peer.public_key_hex)?;
        let signature = hex_decode(&self.signature.signature_hex)?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&signature_preimage(unsigned)?, &signature)
            .map_err(|_| M6IdentityError::SignatureInvalid)
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6IdentityError> {
        digest_domain_serializable(
            MANIFEST_IDENTITY_DOMAIN,
            &SignedManifestBody {
                signature: self.signature.clone(),
                unsigned: self.unsigned.clone(),
            },
        )
    }
}

fn signature_preimage(unsigned: &UnsignedManifest) -> Result<Vec<u8>, M6IdentityError> {
    let mut preimage = Vec::from(MANIFEST_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(unsigned.kind.label().as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(&canonical_json(unsigned)?);
    Ok(preimage)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedManifest {
    pub attachments: BTreeMap<ContentDigest, Vec<u8>>,
    pub manifest: SignedManifest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredIssuance {
    pub abandonment: Option<PreparedIssuanceAbandonment>,
    pub idempotency_key: String,
    pub issued: IssuedManifest,
    pub request_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreparedIssuanceResolution {
    Missing,
    Prepared(RecoveredIssuance),
    ChainCommitted {
        commit: ReplayCommitFact,
        issuance: RecoveredIssuance,
    },
    Abandoned {
        abandonment: PreparedIssuanceAbandonment,
        issuance: RecoveredIssuance,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedIssuanceDisposition {
    AuthorizationDenied,
    AuthorizationExpired,
    Superseded,
    OperatorCancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedIssuanceAbandonment {
    pub abandoned_at_ms: u64,
    pub decision_evidence_digest: ContentDigest,
    pub disposition: PreparedIssuanceDisposition,
    pub idempotency_key: String,
    pub message_digest: ContentDigest,
    pub reason: String,
    pub record_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub role: RouteEndpointRole,
    pub route_definition_digest: ContentDigest,
    pub schema: String,
    pub sequence: u64,
}

impl PreparedIssuanceAbandonment {
    fn new(
        record: &DurableIssuanceRecord,
        issued: &IssuedManifest,
        route: &RouteDefinition,
        role: RouteEndpointRole,
        abandoned_at_ms: u64,
        disposition: PreparedIssuanceDisposition,
        reason: String,
        decision_evidence_digest: ContentDigest,
    ) -> Result<Self, M6IdentityError> {
        let mut abandonment = Self {
            abandoned_at_ms,
            decision_evidence_digest,
            disposition,
            idempotency_key: record.idempotency_key.clone(),
            message_digest: issued.manifest.message_digest.clone(),
            reason,
            record_digest: ContentDigest::from_bytes(&[]),
            request_digest: record.request_digest.clone(),
            role,
            route_definition_digest: route.definition_digest.clone(),
            schema: ISSUANCE_ABANDONMENT_SCHEMA.to_string(),
            sequence: issued.manifest.unsigned.sequence,
        };
        abandonment.record_digest = abandonment.expected_digest()?;
        abandonment.validate(record, issued, route, role)?;
        Ok(abandonment)
    }

    fn validate(
        &self,
        record: &DurableIssuanceRecord,
        issued: &IssuedManifest,
        route: &RouteDefinition,
        role: RouteEndpointRole,
    ) -> Result<(), M6IdentityError> {
        if self.schema != ISSUANCE_ABANDONMENT_SCHEMA {
            return Err(M6IdentityError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("issuance idempotency key", &self.idempotency_key)?;
        validate_bounded_reason(&self.reason)?;
        if self.idempotency_key != record.idempotency_key
            || self.request_digest != record.request_digest
            || self.message_digest != record.message_digest
            || self.message_digest != issued.manifest.message_digest
            || self.sequence != record.sequence
            || self.sequence != issued.manifest.unsigned.sequence
            || self.role != role
            || self.route_definition_digest != route.definition_digest
        {
            return Err(M6IdentityError::StateIntegrity(
                "issuance abandonment is cross-linked to another exact prepare".to_string(),
            ));
        }
        require_digest(
            "issuance abandonment",
            &self.record_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6IdentityError> {
        digest_domain_serializable(
            ISSUANCE_ABANDONMENT_DOMAIN,
            &(
                self.abandoned_at_ms,
                &self.decision_evidence_digest,
                self.disposition,
                &self.idempotency_key,
                &self.message_digest,
                &self.reason,
                &self.request_digest,
                self.role,
                &self.route_definition_digest,
                &self.schema,
                self.sequence,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableIssuanceRecord {
    idempotency_key: String,
    message_digest: ContentDigest,
    record_digest: ContentDigest,
    request_digest: ContentDigest,
    role: RouteEndpointRole,
    route_definition_digest: ContentDigest,
    schema: String,
    sequence: u64,
}

impl DurableIssuanceRecord {
    fn new(
        idempotency_key: String,
        request_digest: ContentDigest,
        issued: &IssuedManifest,
        route: &RouteDefinition,
        role: RouteEndpointRole,
    ) -> Result<Self, M6IdentityError> {
        validate_identifier("issuance idempotency key", &idempotency_key)?;
        let mut record = Self {
            idempotency_key,
            message_digest: issued.manifest.message_digest.clone(),
            record_digest: ContentDigest::from_bytes(&[]),
            request_digest,
            role,
            route_definition_digest: route.definition_digest.clone(),
            schema: ISSUANCE_RECORD_SCHEMA.to_string(),
            sequence: issued.manifest.unsigned.sequence,
        };
        record.record_digest = record.expected_digest()?;
        record.validate(issued, route, role)?;
        Ok(record)
    }

    fn validate(
        &self,
        issued: &IssuedManifest,
        route: &RouteDefinition,
        role: RouteEndpointRole,
    ) -> Result<(), M6IdentityError> {
        if self.schema != ISSUANCE_RECORD_SCHEMA {
            return Err(M6IdentityError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("issuance idempotency key", &self.idempotency_key)?;
        if self.route_definition_digest != route.definition_digest
            || self.role != role
            || self.message_digest != issued.manifest.message_digest
            || self.sequence != issued.manifest.unsigned.sequence
            || issued.manifest.unsigned.origin_role != role
        {
            return Err(M6IdentityError::StateIntegrity(
                "durable issuance record differs from its route or exact signed manifest"
                    .to_string(),
            ));
        }
        require_digest(
            "durable issuance record",
            &self.record_digest,
            &self.expected_digest()?,
        )?;
        let lifetime_ms = issued
            .manifest
            .unsigned
            .expires_at_ms
            .checked_sub(issued.manifest.unsigned.issued_at_ms)
            .ok_or_else(|| {
                M6IdentityError::StateIntegrity("issued manifest lifetime underflowed".to_string())
            })?;
        require_digest(
            "durable issuance request",
            &self.request_digest,
            &issuance_request_digest(
                &self.idempotency_key,
                route,
                role,
                &issued.manifest.unsigned.origin_signing_key_id,
                &issued.manifest.unsigned.payload,
                &issued.manifest.unsigned.attachments,
                lifetime_ms,
            )?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6IdentityError> {
        digest_domain_serializable(
            ISSUANCE_RECORD_DOMAIN,
            &(
                &self.idempotency_key,
                &self.message_digest,
                &self.request_digest,
                self.role,
                &self.route_definition_digest,
                &self.schema,
                self.sequence,
            ),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayCommitFact {
    pub message_digest: ContentDigest,
    pub nonce: String,
    pub retained_until_ms: u64,
    pub route_definition_digest: ContentDigest,
    pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayCommitResolution {
    NotCommitted {
        expected_sequence: u64,
        observed_sequence: u64,
    },
    ExactCommitted(ReplayCommitFact),
    Conflicting {
        last_committed_sequence: u64,
        observed_message_digest: ContentDigest,
        observed_sequence: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayControlStateV1 {
    pub clock_watermark_ms: u64,
    pub last_message_digest: Option<ContentDigest>,
    pub last_sequence: u64,
    pub route_definition_digest: ContentDigest,
    pub state_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalNegativeDisposition {
    Expired,
    Revoked,
    PolicyRejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalNegativeReason {
    Expired,
    Revoked { reason_code: String },
    PolicyRejected { policy_rule: String },
}

impl TerminalNegativeReason {
    fn disposition(&self) -> TerminalNegativeDisposition {
        match self {
            Self::Expired => TerminalNegativeDisposition::Expired,
            Self::Revoked { .. } => TerminalNegativeDisposition::Revoked,
            Self::PolicyRejected { .. } => TerminalNegativeDisposition::PolicyRejected,
        }
    }

    fn validate(&self) -> Result<(), M6IdentityError> {
        match self {
            Self::Expired => Ok(()),
            Self::Revoked { reason_code } => {
                validate_identifier("terminal revocation reason code", reason_code)
            }
            Self::PolicyRejected { policy_rule } => {
                validate_identifier("terminal policy rule", policy_rule)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalNegativeRecord {
    pub canonical_manifest_bytes: Vec<u8>,
    pub clock_watermark_ms: u64,
    pub disposition: TerminalNegativeDisposition,
    pub message_digest: ContentDigest,
    pub negative_evidence_digest: ContentDigest,
    pub nonce: String,
    pub origin_role: RouteEndpointRole,
    pub previous_message_digest: Option<ContentDigest>,
    pub reason: TerminalNegativeReason,
    pub record_digest: ContentDigest,
    pub recorded_at_ms: u64,
    pub route_definition_digest: ContentDigest,
    pub route_generation: u64,
    pub schema: String,
    pub sequence: u64,
    pub signed_manifest_bytes_digest: ContentDigest,
}

#[derive(Serialize)]
struct TerminalNegativeDigestBody<'a> {
    canonical_manifest_bytes: &'a [u8],
    clock_watermark_ms: u64,
    disposition: TerminalNegativeDisposition,
    message_digest: &'a ContentDigest,
    negative_evidence_digest: &'a ContentDigest,
    nonce: &'a str,
    origin_role: RouteEndpointRole,
    previous_message_digest: &'a Option<ContentDigest>,
    reason: &'a TerminalNegativeReason,
    recorded_at_ms: u64,
    route_definition_digest: &'a ContentDigest,
    route_generation: u64,
    schema: &'a str,
    sequence: u64,
    signed_manifest_bytes_digest: &'a ContentDigest,
}

impl TerminalNegativeRecord {
    pub fn canonical_bytes(
        &self,
        route: &RouteDefinition,
        origin_role: RouteEndpointRole,
    ) -> Result<Vec<u8>, M6IdentityError> {
        self.validate(route, origin_role)?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        route: &RouteDefinition,
        origin_role: RouteEndpointRole,
    ) -> Result<Self, M6IdentityError> {
        let record: Self = parse_canonical(bytes)?;
        record.validate(route, origin_role)?;
        Ok(record)
    }

    fn new(
        canonical_manifest_bytes: Vec<u8>,
        manifest: &SignedManifest,
        route: &RouteDefinition,
        origin_role: RouteEndpointRole,
        disposition: TerminalNegativeDisposition,
        reason: TerminalNegativeReason,
        negative_evidence_digest: ContentDigest,
        recorded_at_ms: u64,
        prior_clock_watermark_ms: u64,
    ) -> Result<Self, M6IdentityError> {
        let mut record = Self {
            signed_manifest_bytes_digest: ContentDigest::from_bytes(&canonical_manifest_bytes),
            canonical_manifest_bytes,
            clock_watermark_ms: prior_clock_watermark_ms.max(recorded_at_ms),
            disposition,
            message_digest: manifest.message_digest.clone(),
            negative_evidence_digest,
            nonce: manifest.unsigned.nonce.clone(),
            origin_role,
            previous_message_digest: manifest.unsigned.previous_message_digest.clone(),
            reason,
            record_digest: ContentDigest::from_bytes(&[]),
            recorded_at_ms,
            route_definition_digest: route.definition_digest.clone(),
            route_generation: route.generation,
            schema: TERMINAL_NEGATIVE_SCHEMA.to_string(),
            sequence: manifest.unsigned.sequence,
        };
        record.record_digest = record.expected_digest()?;
        record.validate(route, origin_role)?;
        Ok(record)
    }

    fn validate(
        &self,
        route: &RouteDefinition,
        origin_role: RouteEndpointRole,
    ) -> Result<SignedManifest, M6IdentityError> {
        if self.schema != TERMINAL_NEGATIVE_SCHEMA {
            return Err(M6IdentityError::UnsupportedSchema(self.schema.clone()));
        }
        self.reason.validate()?;
        require_terminal_negative_evidence(&self.negative_evidence_digest)?;
        if self.reason.disposition() != self.disposition
            || self.route_definition_digest != route.definition_digest
            || self.route_generation != route.generation
            || self.origin_role != origin_role
            || self.clock_watermark_ms < self.recorded_at_ms
            || self.canonical_manifest_bytes.is_empty()
            || self.canonical_manifest_bytes.len()
                > route.resource_profile.max_manifest_bytes as usize
        {
            return Err(M6IdentityError::StateIntegrity(
                "terminal-negative record is outside its exact bounded schema".to_string(),
            ));
        }
        require_digest(
            "terminal-negative signed manifest bytes",
            &self.signed_manifest_bytes_digest,
            &ContentDigest::from_bytes(&self.canonical_manifest_bytes),
        )?;
        let manifest = SignedManifest::from_canonical_bytes(&self.canonical_manifest_bytes)?;
        manifest.verify_route(route)?;
        if manifest.unsigned.origin_role != origin_role
            || manifest.message_digest != self.message_digest
            || manifest.unsigned.sequence != self.sequence
            || manifest.unsigned.nonce != self.nonce
            || manifest.unsigned.previous_message_digest != self.previous_message_digest
        {
            return Err(M6IdentityError::StateIntegrity(
                "terminal-negative record differs from its exact signed message".to_string(),
            ));
        }
        if manifest.unsigned.issued_at_ms
            > self
                .recorded_at_ms
                .saturating_add(route.resource_profile.accepted_clock_skew_ms)
            || (self.disposition == TerminalNegativeDisposition::Expired)
                != (self.recorded_at_ms > manifest.unsigned.expires_at_ms)
        {
            return Err(M6IdentityError::StateIntegrity(
                "terminal-negative record contradicts its retained message time".to_string(),
            ));
        }
        require_digest(
            "terminal-negative record",
            &self.record_digest,
            &self.expected_digest()?,
        )?;
        Ok(manifest)
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6IdentityError> {
        digest_domain_serializable(
            TERMINAL_NEGATIVE_DOMAIN,
            &TerminalNegativeDigestBody {
                canonical_manifest_bytes: &self.canonical_manifest_bytes,
                clock_watermark_ms: self.clock_watermark_ms,
                disposition: self.disposition,
                message_digest: &self.message_digest,
                negative_evidence_digest: &self.negative_evidence_digest,
                nonce: &self.nonce,
                origin_role: self.origin_role,
                previous_message_digest: &self.previous_message_digest,
                reason: &self.reason,
                recorded_at_ms: self.recorded_at_ms,
                route_definition_digest: &self.route_definition_digest,
                route_generation: self.route_generation,
                schema: &self.schema,
                sequence: self.sequence,
                signed_manifest_bytes_digest: &self.signed_manifest_bytes_digest,
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalNegativeResolution {
    Missing,
    Recorded(TerminalNegativeRecord),
    ChainCommitted {
        commit: ReplayCommitFact,
        record: TerminalNegativeRecord,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalNegativeChainFact {
    disposition: TerminalNegativeDisposition,
    message_digest: ContentDigest,
    negative_evidence_digest: ContentDigest,
    record_digest: ContentDigest,
    sequence: u64,
}

impl TerminalNegativeChainFact {
    fn from_record(record: &TerminalNegativeRecord) -> Self {
        Self {
            disposition: record.disposition,
            message_digest: record.message_digest.clone(),
            negative_evidence_digest: record.negative_evidence_digest.clone(),
            record_digest: record.record_digest.clone(),
            sequence: record.sequence,
        }
    }

    fn matches_record(&self, record: &TerminalNegativeRecord) -> bool {
        self == &Self::from_record(record)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChainMode {
    Origin,
    Intake,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayTombstone {
    message_digest: ContentDigest,
    retained_until_ms: u64,
    sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableChainState {
    clock_watermark_ms: u64,
    last_message_digest: Option<ContentDigest>,
    last_sequence: u64,
    message_tombstones: BTreeMap<String, ReplayTombstone>,
    mode: ChainMode,
    nonce_tombstones: BTreeMap<String, ReplayTombstone>,
    role: RouteEndpointRole,
    route_definition_digest: ContentDigest,
    route_generation: u64,
    schema: String,
    state_digest: ContentDigest,
    terminal_negative_facts: BTreeMap<String, TerminalNegativeChainFact>,
}

impl DurableChainState {
    fn new(
        route: &RouteDefinition,
        role: RouteEndpointRole,
        mode: ChainMode,
    ) -> Result<Self, M6IdentityError> {
        let mut state = Self {
            clock_watermark_ms: 0,
            last_message_digest: None,
            last_sequence: 0,
            message_tombstones: BTreeMap::new(),
            mode,
            nonce_tombstones: BTreeMap::new(),
            role,
            route_definition_digest: route.definition_digest.clone(),
            route_generation: route.generation,
            schema: CHAIN_STATE_SCHEMA.to_string(),
            state_digest: ContentDigest::from_bytes(&[]),
            terminal_negative_facts: BTreeMap::new(),
        };
        state.state_digest = state.expected_digest()?;
        Ok(state)
    }

    fn validate(
        &self,
        route: &RouteDefinition,
        role: RouteEndpointRole,
        mode: ChainMode,
    ) -> Result<(), M6IdentityError> {
        if self.schema != CHAIN_STATE_SCHEMA {
            return Err(M6IdentityError::UnsupportedSchema(self.schema.clone()));
        }
        if self.route_definition_digest != route.definition_digest
            || self.route_generation != route.generation
            || self.role != role
            || self.mode != mode
        {
            return Err(M6IdentityError::StateIntegrity(
                "durable chain state is bound to a different route, role, or mode".to_string(),
            ));
        }
        if self.last_sequence == 0 && self.last_message_digest.is_some()
            || self.last_sequence > 0 && self.last_message_digest.is_none()
            || self.terminal_negative_facts.len()
                > route.resource_profile.max_replay_records as usize
            || self.mode == ChainMode::Origin && !self.terminal_negative_facts.is_empty()
        {
            return Err(M6IdentityError::StateIntegrity(
                "durable chain cursor is internally inconsistent".to_string(),
            ));
        }
        for (message_key, fact) in &self.terminal_negative_facts {
            let message_tombstone = self.message_tombstones.get(message_key);
            let nonce_matches = self.nonce_tombstones.values().any(|tombstone| {
                tombstone.message_digest == fact.message_digest
                    && tombstone.sequence == fact.sequence
            });
            if message_key != fact.message_digest.as_str()
                || fact.sequence == 0
                || fact.sequence > self.last_sequence
                || message_tombstone.is_none_or(|tombstone| {
                    tombstone.message_digest != fact.message_digest
                        || tombstone.sequence != fact.sequence
                })
                || !nonce_matches
            {
                return Err(M6IdentityError::StateIntegrity(
                    "terminal-negative chain fact lacks its exact replay tombstones".to_string(),
                ));
            }
            require_terminal_negative_evidence(&fact.negative_evidence_digest)?;
        }
        require_digest(
            "durable route chain state",
            &self.state_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M6IdentityError> {
        digest_domain_serializable(
            CHAIN_STATE_DOMAIN,
            &(
                self.clock_watermark_ms,
                &self.last_message_digest,
                self.last_sequence,
                &self.message_tombstones,
                self.mode,
                &self.nonce_tombstones,
                self.role,
                &self.route_definition_digest,
                self.route_generation,
                &self.schema,
                &self.terminal_negative_facts,
            ),
        )
    }
}

struct DurableChainStore {
    profile: RouteResourceProfile,
    route: RouteDefinition,
    state: DurableChainState,
    state_path: PathBuf,
}

impl DurableChainStore {
    fn open_or_initialize(
        local_root: &Path,
        route: &RouteDefinition,
        role: RouteEndpointRole,
        mode: ChainMode,
    ) -> Result<Self, M6IdentityError> {
        route.validate()?;
        let local_root = prepare_root(local_root, true)?;
        let chains_root = secure_child_directory(&local_root, "m6-route-chains")?;
        let state_path = chains_root.join(format!(
            "{}-{}-{}.json",
            route.definition_digest.file_stem(),
            role.label(),
            match mode {
                ChainMode::Origin => "origin",
                ChainMode::Intake => "intake",
            }
        ));
        let state = if state_path.exists() {
            let state: DurableChainState = parse_canonical(&read_bounded(
                &state_path,
                usize::try_from(route.resource_profile.max_manifest_bytes).unwrap_or(usize::MAX),
            )?)?;
            state.validate(route, role, mode)?;
            state
        } else {
            let state = DurableChainState::new(route, role, mode)?;
            persist_immutable(&state_path, &canonical_json(&state)?)?;
            state
        };
        Ok(Self {
            profile: route.resource_profile.clone(),
            route: route.clone(),
            state,
            state_path,
        })
    }

    fn observe_clock(&mut self, observed_ms: u64) -> Result<(), M6IdentityError> {
        self.validate_clock(observed_ms)?;
        if observed_ms > self.state.clock_watermark_ms {
            let mut next = self.state.clone();
            next.clock_watermark_ms = observed_ms;
            self.persist_next(next)?;
        }
        Ok(())
    }

    fn validate_clock(&self, observed_ms: u64) -> Result<(), M6IdentityError> {
        if observed_ms.saturating_add(self.profile.allowed_clock_regression_ms)
            < self.state.clock_watermark_ms
        {
            return Err(M6IdentityError::ClockUntrusted {
                watermark_ms: self.state.clock_watermark_ms,
                observed_ms,
            });
        }
        Ok(())
    }

    fn next_coordinates(&self) -> Result<(u64, Option<ContentDigest>), M6IdentityError> {
        if self.state.mode != ChainMode::Origin {
            return Err(M6IdentityError::StateIntegrity(
                "intake chain cannot allocate sender coordinates".to_string(),
            ));
        }
        let sequence = self.state.last_sequence.checked_add(1).ok_or_else(|| {
            M6IdentityError::ResourceExhausted("route sequence overflowed".to_string())
        })?;
        Ok((sequence, self.state.last_message_digest.clone()))
    }

    fn commit(&mut self, manifest: &SignedManifest, now_ms: u64) -> Result<(), M6IdentityError> {
        self.validate_next_candidate(manifest)?;
        self.persist_commit(manifest, now_ms, None)
    }

    fn commit_terminal_negative(
        &mut self,
        manifest: &SignedManifest,
        record: &TerminalNegativeRecord,
    ) -> Result<(), M6IdentityError> {
        if self.state.mode != ChainMode::Intake {
            return Err(M6IdentityError::StateIntegrity(
                "terminal-negative facts may only advance an intake chain".to_string(),
            ));
        }
        let retained = record.validate(&self.route, self.state.role)?;
        if &retained != manifest {
            return Err(M6IdentityError::StateIntegrity(
                "terminal-negative commit differs from its retained exact manifest".to_string(),
            ));
        }
        self.validate_next_candidate(manifest)?;
        if self.state.terminal_negative_facts.len() >= self.profile.max_replay_records as usize {
            return Err(M6IdentityError::ResourceExhausted(
                "durable terminal-negative fact budget is full".to_string(),
            ));
        }
        self.persist_commit(
            manifest,
            record.clock_watermark_ms,
            Some(TerminalNegativeChainFact::from_record(record)),
        )
    }

    fn validate_next_candidate(&self, manifest: &SignedManifest) -> Result<(), M6IdentityError> {
        manifest.verify_route(&self.route)?;
        if manifest.unsigned.origin_role != self.state.role {
            return Err(M6IdentityError::WrongRole {
                expected: self.state.role,
                actual: manifest.unsigned.origin_role,
            });
        }
        let expected = self.state.last_sequence.checked_add(1).ok_or_else(|| {
            M6IdentityError::ResourceExhausted("route sequence overflowed".to_string())
        })?;
        if manifest.unsigned.sequence <= self.state.last_sequence {
            return Err(M6IdentityError::Replay {
                sequence: manifest.unsigned.sequence,
            });
        }
        if manifest.unsigned.sequence > expected {
            return Err(M6IdentityError::SequenceGap {
                expected,
                actual: manifest.unsigned.sequence,
            });
        }
        if manifest.unsigned.previous_message_digest != self.state.last_message_digest {
            return Err(M6IdentityError::ChainConflict {
                expected: self.state.last_message_digest.clone(),
                actual: manifest.unsigned.previous_message_digest.clone(),
            });
        }
        if self
            .state
            .nonce_tombstones
            .contains_key(&manifest.unsigned.nonce)
        {
            return Err(M6IdentityError::NonceReplay(
                manifest.unsigned.nonce.clone(),
            ));
        }
        if self
            .state
            .message_tombstones
            .contains_key(manifest.message_digest.as_str())
        {
            return Err(M6IdentityError::MessageReplay(
                manifest.message_digest.clone(),
            ));
        }
        if self.state.nonce_tombstones.len() >= self.profile.max_replay_records as usize
            || self.state.message_tombstones.len() >= self.profile.max_replay_records as usize
        {
            return Err(M6IdentityError::ResourceExhausted(
                "durable replay tombstone budget is full".to_string(),
            ));
        }
        Ok(())
    }

    fn persist_commit(
        &mut self,
        manifest: &SignedManifest,
        now_ms: u64,
        terminal_negative: Option<TerminalNegativeChainFact>,
    ) -> Result<(), M6IdentityError> {
        let tombstone = ReplayTombstone {
            message_digest: manifest.message_digest.clone(),
            retained_until_ms: now_ms.saturating_add(self.profile.tombstone_retention_ms()),
            sequence: manifest.unsigned.sequence,
        };
        let mut next = self.state.clone();
        next.nonce_tombstones
            .insert(manifest.unsigned.nonce.clone(), tombstone.clone());
        next.message_tombstones
            .insert(manifest.message_digest.as_str().to_string(), tombstone);
        next.last_sequence = manifest.unsigned.sequence;
        next.last_message_digest = Some(manifest.message_digest.clone());
        next.clock_watermark_ms = next.clock_watermark_ms.max(now_ms);
        if let Some(fact) = terminal_negative {
            if next
                .terminal_negative_facts
                .insert(manifest.message_digest.as_str().to_string(), fact)
                .is_some()
            {
                return Err(M6IdentityError::StateIntegrity(
                    "terminal-negative fact already occupies this message identity".to_string(),
                ));
            }
        }
        self.persist_next(next)
    }

    fn persist_next(&mut self, mut next: DurableChainState) -> Result<(), M6IdentityError> {
        next.state_digest = next.expected_digest()?;
        next.validate(&self.route, self.state.role, self.state.mode)?;
        atomic_replace(&self.state_path, &canonical_json(&next)?)?;
        self.state = next;
        Ok(())
    }

    fn last_sequence(&self) -> u64 {
        self.state.last_sequence
    }

    fn resolve_exact_commit(
        &self,
        manifest: &SignedManifest,
    ) -> Result<ReplayCommitResolution, M6IdentityError> {
        let observed_sequence = manifest.unsigned.sequence;
        if observed_sequence > self.state.last_sequence {
            let expected_sequence = self.state.last_sequence.checked_add(1).ok_or_else(|| {
                M6IdentityError::ResourceExhausted("route sequence overflowed".to_string())
            })?;
            return Ok(ReplayCommitResolution::NotCommitted {
                expected_sequence,
                observed_sequence,
            });
        }

        let message_tombstone = self
            .state
            .message_tombstones
            .get(manifest.message_digest.as_str());
        let nonce_tombstone = self.state.nonce_tombstones.get(&manifest.unsigned.nonce);
        if let (Some(message), Some(nonce)) = (message_tombstone, nonce_tombstone)
            && message == nonce
            && message.sequence == observed_sequence
            && message.message_digest == manifest.message_digest
        {
            return Ok(ReplayCommitResolution::ExactCommitted(ReplayCommitFact {
                message_digest: manifest.message_digest.clone(),
                nonce: manifest.unsigned.nonce.clone(),
                retained_until_ms: message.retained_until_ms,
                route_definition_digest: self.route.definition_digest.clone(),
                sequence: observed_sequence,
            }));
        }
        Ok(ReplayCommitResolution::Conflicting {
            last_committed_sequence: self.state.last_sequence,
            observed_message_digest: manifest.message_digest.clone(),
            observed_sequence,
        })
    }

    fn terminal_negative_fact(
        &self,
        message_digest: &ContentDigest,
    ) -> Option<&TerminalNegativeChainFact> {
        self.state
            .terminal_negative_facts
            .get(message_digest.as_str())
    }
}

/// Role-bound manifest issuer. Sequence, prior digest, clock, and nonce are all
/// obtained from runtime-owned services and durable state.
pub struct ManifestIssuer {
    chain: DurableChainStore,
    clock: Arc<dyn Clock>,
    issued_root: PathBuf,
    nonce_source: Arc<dyn NonceSource>,
    role: RouteEndpointRole,
    route: RouteDefinition,
    _owner_lock: File,
}

impl ManifestIssuer {
    pub fn open_or_initialize(
        local_root: impl AsRef<Path>,
        route: RouteDefinition,
        role: RouteEndpointRole,
        clock: Arc<dyn Clock>,
        nonce_source: Arc<dyn NonceSource>,
    ) -> Result<Self, M6IdentityError> {
        route.validate()?;
        let local_root = prepare_root(local_root.as_ref(), true)?;
        let locks_root = secure_child_directory(&local_root, ISSUER_LOCKS_DIRECTORY)?;
        let owner_lock = acquire_issuer_lock(&locks_root, &route, role)?;
        let issuance_root = secure_child_directory(&local_root, ISSUANCE_DIRECTORY)?;
        let issued_root = secure_child_directory(
            &issuance_root,
            &format!("{}-{}", route.definition_digest.file_stem(), role.label()),
        )?;
        recover_issuance_staging(&issued_root)?;
        let chain =
            DurableChainStore::open_or_initialize(&local_root, &route, role, ChainMode::Origin)?;
        validate_issuance_store(&issued_root, &route, role, &chain)?;
        Ok(Self {
            chain,
            clock,
            issued_root,
            nonce_source,
            role,
            route,
            _owner_lock: owner_lock,
        })
    }

    /// Issue using an idempotency key derived from the exact logical request.
    ///
    /// Repeating identical inputs returns the exact previously signed manifest.
    /// Call `issue_idempotent` with a distinct stable key when two deliberately
    /// separate operations have otherwise identical content.
    pub fn issue(
        &mut self,
        signer: &FactorySigner,
        payload: ManifestPayload,
        attachments: Vec<AttachmentInput>,
        lifetime_ms: u64,
    ) -> Result<IssuedManifest, M6IdentityError> {
        let (descriptors, attachment_bytes) =
            bind_attachments(attachments, &self.route.resource_profile)?;
        let fingerprint = issuance_fingerprint(
            &self.route,
            self.role,
            signer.signing_key_id(),
            &payload,
            &descriptors,
            lifetime_ms,
        )?;
        let idempotency_key = format!("request:{}", fingerprint.file_stem());
        let prepared = self.prepare_bound(
            idempotency_key.clone(),
            signer,
            payload,
            descriptors,
            attachment_bytes,
            lifetime_ms,
        )?;
        let committed = self.commit_prepared(&idempotency_key)?;
        if committed != prepared {
            return Err(M6IdentityError::StateIntegrity(
                "committed issuance differs from its exact prepared bytes".to_string(),
            ));
        }
        Ok(committed)
    }

    pub fn issue_idempotent(
        &mut self,
        idempotency_key: impl Into<String>,
        signer: &FactorySigner,
        payload: ManifestPayload,
        attachments: Vec<AttachmentInput>,
        lifetime_ms: u64,
    ) -> Result<IssuedManifest, M6IdentityError> {
        let idempotency_key = idempotency_key.into();
        validate_identifier("issuance idempotency key", &idempotency_key)?;
        let (descriptors, attachment_bytes) =
            bind_attachments(attachments, &self.route.resource_profile)?;
        let prepared = self.prepare_bound(
            idempotency_key.clone(),
            signer,
            payload,
            descriptors,
            attachment_bytes,
            lifetime_ms,
        )?;
        let committed = self.commit_prepared(&idempotency_key)?;
        if committed != prepared {
            return Err(M6IdentityError::StateIntegrity(
                "committed issuance differs from its exact prepared bytes".to_string(),
            ));
        }
        Ok(committed)
    }

    /// Persist exact signed bytes without advancing the origin chain.
    ///
    /// At most one next-coordinate issuance may remain prepared for a route
    /// role. Exact retries return the retained nonce, sequence, signature, and
    /// attachments. Call [`Self::commit_prepared`] only after the coordinator
    /// has durably recorded every prerequisite authorization and final export
    /// check.
    pub fn prepare_idempotent(
        &mut self,
        idempotency_key: impl Into<String>,
        signer: &FactorySigner,
        payload: ManifestPayload,
        attachments: Vec<AttachmentInput>,
        lifetime_ms: u64,
    ) -> Result<IssuedManifest, M6IdentityError> {
        let idempotency_key = idempotency_key.into();
        validate_identifier("issuance idempotency key", &idempotency_key)?;
        let (descriptors, attachment_bytes) =
            bind_attachments(attachments, &self.route.resource_profile)?;
        self.prepare_bound(
            idempotency_key,
            signer,
            payload,
            descriptors,
            attachment_bytes,
            lifetime_ms,
        )
    }

    /// Read exact already-persisted issuance bytes without mutating the origin
    /// chain, clock watermark, nonce source, or issuance store.
    pub fn recover_issuance(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<RecoveredIssuance>, M6IdentityError> {
        validate_identifier("issuance idempotency key", idempotency_key)?;
        let path = issuance_unit_path(&self.issued_root, idempotency_key);
        if !path.exists() {
            return Ok(None);
        }
        let (record, issued, abandonment) = load_issuance_unit(&path, &self.route, self.role)?;
        Ok(Some(RecoveredIssuance {
            abandonment,
            idempotency_key: record.idempotency_key,
            issued,
            request_digest: record.request_digest,
        }))
    }

    /// The stricter recovery form also checks a caller-persisted exact request
    /// digest. It remains read-only; committing is a separate explicit action.
    pub fn recover_exact_issuance(
        &self,
        idempotency_key: &str,
        request_digest: &ContentDigest,
    ) -> Result<Option<IssuedManifest>, M6IdentityError> {
        validate_identifier("issuance idempotency key", idempotency_key)?;
        let path = issuance_unit_path(&self.issued_root, idempotency_key);
        if !path.exists() {
            return Ok(None);
        }
        let (record, issued, _) = load_issuance_unit(&path, &self.route, self.role)?;
        if &record.request_digest != request_digest {
            return Err(M6IdentityError::IssuanceConflict {
                idempotency_key: idempotency_key.to_string(),
                existing: record.request_digest,
                requested: request_digest.clone(),
            });
        }
        Ok(Some(issued))
    }

    /// Resolve a retained prepare and its origin-chain state without mutation.
    pub fn prepared_resolution(
        &self,
        idempotency_key: &str,
    ) -> Result<PreparedIssuanceResolution, M6IdentityError> {
        validate_identifier("issuance idempotency key", idempotency_key)?;
        let path = issuance_unit_path(&self.issued_root, idempotency_key);
        if !path.exists() {
            return Ok(PreparedIssuanceResolution::Missing);
        }
        let (record, issued, abandonment) = load_issuance_unit(&path, &self.route, self.role)?;
        let issuance = RecoveredIssuance {
            abandonment: abandonment.clone(),
            idempotency_key: record.idempotency_key.clone(),
            issued: issued.clone(),
            request_digest: record.request_digest,
        };
        let resolution = self.chain.resolve_exact_commit(&issued.manifest)?;
        if let Some(abandonment) = abandonment {
            if matches!(resolution, ReplayCommitResolution::ExactCommitted(_)) {
                return Err(M6IdentityError::StateIntegrity(format!(
                    "abandoned issuance '{idempotency_key}' is also chain committed"
                )));
            }
            return Ok(PreparedIssuanceResolution::Abandoned {
                abandonment,
                issuance,
            });
        }
        match resolution {
            ReplayCommitResolution::ExactCommitted(commit) => {
                Ok(PreparedIssuanceResolution::ChainCommitted { commit, issuance })
            }
            ReplayCommitResolution::NotCommitted {
                expected_sequence,
                observed_sequence,
            } if expected_sequence == observed_sequence
                && issued.manifest.unsigned.previous_message_digest
                    == self.chain.state.last_message_digest =>
            {
                Ok(PreparedIssuanceResolution::Prepared(issuance))
            }
            ReplayCommitResolution::NotCommitted { .. }
            | ReplayCommitResolution::Conflicting { .. } => Err(M6IdentityError::StateIntegrity(
                format!("retained issuance '{idempotency_key}' conflicts with the origin chain"),
            )),
        }
    }

    /// Resolve only the exact chain status of a retained, non-abandoned
    /// prepare. This is a compact recovery seam for coordinators that already
    /// retain the request digest and exact issued bytes.
    pub fn resolve_prepared_commit(
        &self,
        idempotency_key: &str,
    ) -> Result<ReplayCommitResolution, M6IdentityError> {
        validate_identifier("issuance idempotency key", idempotency_key)?;
        let path = issuance_unit_path(&self.issued_root, idempotency_key);
        if !path.exists() {
            return Err(M6IdentityError::StateIntegrity(format!(
                "prepared issuance '{idempotency_key}' does not exist"
            )));
        }
        let (_, issued, abandonment) = load_issuance_unit(&path, &self.route, self.role)?;
        if let Some(abandonment) = abandonment {
            return Err(M6IdentityError::IssuanceAbandoned {
                idempotency_key: idempotency_key.to_string(),
                abandonment_digest: abandonment.record_digest,
            });
        }
        self.chain.resolve_exact_commit(&issued.manifest)
    }

    /// Commit one retained exact issuance to the origin chain, exactly once.
    ///
    /// Repeating this call after a successful commit returns the retained
    /// signed bytes without advancing the sequence again.
    pub fn commit_prepared(
        &mut self,
        idempotency_key: &str,
    ) -> Result<IssuedManifest, M6IdentityError> {
        validate_identifier("issuance idempotency key", idempotency_key)?;
        let path = issuance_unit_path(&self.issued_root, idempotency_key);
        if !path.exists() {
            return Err(M6IdentityError::StateIntegrity(format!(
                "prepared issuance '{idempotency_key}' does not exist"
            )));
        }
        let (record, issued, abandonment) = load_issuance_unit(&path, &self.route, self.role)?;
        if let Some(abandonment) = abandonment {
            return Err(M6IdentityError::IssuanceAbandoned {
                idempotency_key: idempotency_key.to_string(),
                abandonment_digest: abandonment.record_digest,
            });
        }
        self.resume_exact_issuance(&record, &issued)?;
        Ok(issued)
    }

    /// Commit one retained issuance only if it matches a coordinator-retained
    /// exact request digest.
    pub fn commit_prepared_exact(
        &mut self,
        idempotency_key: &str,
        request_digest: &ContentDigest,
    ) -> Result<IssuedManifest, M6IdentityError> {
        validate_identifier("issuance idempotency key", idempotency_key)?;
        let path = issuance_unit_path(&self.issued_root, idempotency_key);
        if !path.exists() {
            return Err(M6IdentityError::StateIntegrity(format!(
                "prepared issuance '{idempotency_key}' does not exist"
            )));
        }
        let (record, issued, abandonment) = load_issuance_unit(&path, &self.route, self.role)?;
        if &record.request_digest != request_digest {
            return Err(M6IdentityError::IssuanceConflict {
                idempotency_key: idempotency_key.to_string(),
                existing: record.request_digest,
                requested: request_digest.clone(),
            });
        }
        if let Some(abandonment) = abandonment {
            return Err(M6IdentityError::IssuanceAbandoned {
                idempotency_key: idempotency_key.to_string(),
                abandonment_digest: abandonment.record_digest,
            });
        }
        self.resume_exact_issuance(&record, &issued)?;
        Ok(issued)
    }

    /// Terminalize an uncommitted prepare without deleting its exact bytes or
    /// advancing the origin chain.
    ///
    /// Exact retries are idempotent. A changed disposition, reason, decision
    /// evidence, or request binding conflicts with the immutable first fact.
    #[allow(clippy::too_many_arguments)]
    pub fn abandon_prepared(
        &mut self,
        idempotency_key: &str,
        request_digest: &ContentDigest,
        disposition: PreparedIssuanceDisposition,
        reason: impl Into<String>,
        decision_evidence_digest: ContentDigest,
    ) -> Result<PreparedIssuanceAbandonment, M6IdentityError> {
        validate_identifier("issuance idempotency key", idempotency_key)?;
        let reason = reason.into();
        validate_bounded_reason(&reason)?;
        let path = issuance_unit_path(&self.issued_root, idempotency_key);
        if !path.exists() {
            return Err(M6IdentityError::StateIntegrity(format!(
                "prepared issuance '{idempotency_key}' does not exist"
            )));
        }
        let (record, issued, existing) = load_issuance_unit(&path, &self.route, self.role)?;
        if &record.request_digest != request_digest {
            return Err(M6IdentityError::IssuanceConflict {
                idempotency_key: idempotency_key.to_string(),
                existing: record.request_digest,
                requested: request_digest.clone(),
            });
        }
        let requested_abandonment_digest = abandonment_request_digest(
            idempotency_key,
            request_digest,
            &record.message_digest,
            record.sequence,
            disposition,
            &reason,
            &decision_evidence_digest,
        )?;
        if let Some(existing) = existing {
            let existing_request_digest = abandonment_request_digest(
                &existing.idempotency_key,
                &existing.request_digest,
                &existing.message_digest,
                existing.sequence,
                existing.disposition,
                &existing.reason,
                &existing.decision_evidence_digest,
            )?;
            if existing_request_digest == requested_abandonment_digest {
                return Ok(existing);
            }
            return Err(M6IdentityError::IssuanceAbandonmentConflict {
                idempotency_key: idempotency_key.to_string(),
                existing: existing.record_digest,
                requested: requested_abandonment_digest,
            });
        }
        match self.chain.resolve_exact_commit(&issued.manifest)? {
            ReplayCommitResolution::NotCommitted {
                expected_sequence,
                observed_sequence,
            } if expected_sequence == observed_sequence
                && issued.manifest.unsigned.previous_message_digest
                    == self.chain.state.last_message_digest => {}
            ReplayCommitResolution::ExactCommitted(_) => {
                return Err(M6IdentityError::StateIntegrity(format!(
                    "committed issuance '{idempotency_key}' cannot be abandoned"
                )));
            }
            ReplayCommitResolution::NotCommitted { .. }
            | ReplayCommitResolution::Conflicting { .. } => {
                return Err(M6IdentityError::StateIntegrity(format!(
                    "issuance '{idempotency_key}' no longer occupies the next origin coordinate"
                )));
            }
        }
        let abandoned_at_ms = self.clock.now_ms()?;
        self.chain.validate_clock(abandoned_at_ms)?;
        let abandonment = PreparedIssuanceAbandonment::new(
            &record,
            &issued,
            &self.route,
            self.role,
            abandoned_at_ms,
            disposition,
            reason,
            decision_evidence_digest,
        )?;
        persist_immutable(
            &path.join(ISSUANCE_ABANDONMENT_FILE),
            &canonical_json(&abandonment)?,
        )?;
        Ok(abandonment)
    }

    pub fn prepared_abandonment(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<PreparedIssuanceAbandonment>, M6IdentityError> {
        validate_identifier("issuance idempotency key", idempotency_key)?;
        let path = issuance_unit_path(&self.issued_root, idempotency_key);
        if !path.exists() {
            return Ok(None);
        }
        let (_, _, abandonment) = load_issuance_unit(&path, &self.route, self.role)?;
        Ok(abandonment)
    }

    pub fn last_sequence(&self) -> u64 {
        self.chain.last_sequence()
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_bound(
        &mut self,
        idempotency_key: String,
        signer: &FactorySigner,
        payload: ManifestPayload,
        descriptors: Vec<AttachmentDescriptor>,
        attachment_bytes: BTreeMap<ContentDigest, Vec<u8>>,
        lifetime_ms: u64,
    ) -> Result<IssuedManifest, M6IdentityError> {
        self.validate_issuance_inputs(signer, &payload, lifetime_ms)?;
        let request_digest = issuance_request_digest(
            &idempotency_key,
            &self.route,
            self.role,
            signer.signing_key_id(),
            &payload,
            &descriptors,
            lifetime_ms,
        )?;
        let path = issuance_unit_path(&self.issued_root, &idempotency_key);
        if path.exists() {
            let (record, issued, abandonment) = load_issuance_unit(&path, &self.route, self.role)?;
            if record.request_digest != request_digest {
                return Err(M6IdentityError::IssuanceConflict {
                    idempotency_key,
                    existing: record.request_digest,
                    requested: request_digest,
                });
            }
            if let Some(abandonment) = abandonment {
                return Err(M6IdentityError::IssuanceAbandoned {
                    idempotency_key,
                    abandonment_digest: abandonment.record_digest,
                });
            }
            return Ok(issued);
        }

        if let Some(pending) =
            pending_issuance(&self.issued_root, &self.route, self.role, &self.chain)?
        {
            return Err(M6IdentityError::PendingIssuance {
                idempotency_key: pending.idempotency_key,
                request_digest: pending.request_digest,
            });
        }
        enforce_unit_count(
            &self.issued_root,
            self.route.resource_profile.max_replay_records,
            "durable issuance units",
        )?;

        let (record, issued) = self.create_persisted_issuance(
            idempotency_key,
            request_digest,
            signer,
            payload,
            descriptors,
            attachment_bytes,
            lifetime_ms,
        )?;
        record.validate(&issued, &self.route, self.role)?;
        Ok(issued)
    }

    fn validate_issuance_inputs(
        &self,
        signer: &FactorySigner,
        payload: &ManifestPayload,
        lifetime_ms: u64,
    ) -> Result<(), M6IdentityError> {
        let kind = payload.kind();
        if kind.origin_role() != self.role {
            return Err(M6IdentityError::WrongRole {
                expected: kind.origin_role(),
                actual: self.role,
            });
        }
        let peer = self.route.peer(self.role);
        if signer.signing_key_id() != peer.signing_key_id
            || signer.public_key_hex() != peer.public_key_hex
        {
            return Err(M6IdentityError::FalseIdentity {
                subject: "manifest signer",
                expected: format!("{}:{}", peer.signing_key_id, peer.public_key_hex),
                actual: format!("{}:{}", signer.signing_key_id(), signer.public_key_hex()),
            });
        }
        payload.validate()?;
        if lifetime_ms == 0
            || lifetime_ms > self.route.resource_profile.max_message_lifetime_ms
            || (kind == ManifestKind::Revocation
                && lifetime_ms > self.route.resource_profile.max_revocation_lifetime_ms)
        {
            return Err(M6IdentityError::ResourceExhausted(
                "message lifetime is outside the route profile".to_string(),
            ));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn create_persisted_issuance(
        &mut self,
        idempotency_key: String,
        request_digest: ContentDigest,
        signer: &FactorySigner,
        payload: ManifestPayload,
        descriptors: Vec<AttachmentDescriptor>,
        attachment_bytes: BTreeMap<ContentDigest, Vec<u8>>,
        lifetime_ms: u64,
    ) -> Result<(DurableIssuanceRecord, IssuedManifest), M6IdentityError> {
        let kind = payload.kind();
        let now_ms = self.clock.now_ms()?;
        self.chain.validate_clock(now_ms)?;
        let mut nonce = None;
        for _ in 0..32 {
            let mut nonce_bytes = [0_u8; NONCE_BYTES];
            self.nonce_source.fill(&mut nonce_bytes)?;
            let candidate = hex_encode(&nonce_bytes);
            if !issuance_nonce_exists(&self.issued_root, &self.route, self.role, &candidate)? {
                nonce = Some(candidate);
                break;
            }
        }
        let nonce = nonce.ok_or_else(|| {
            M6IdentityError::ResourceExhausted(
                "nonce source repeated 32 retained issuance nonces".to_string(),
            )
        })?;
        let (sequence, previous_message_digest) = self.chain.next_coordinates()?;
        let unsigned = UnsignedManifest {
            attachments: descriptors,
            canonical_encoding_version: CANONICAL_ENCODING_VERSION,
            expires_at_ms: now_ms.saturating_add(lifetime_ms),
            issued_at_ms: now_ms,
            kind,
            nonce,
            origin_role: self.role,
            origin_signing_key_id: signer.signing_key_id().to_string(),
            payload,
            policy_digest: self.route.exchange_policy_digest.clone(),
            previous_message_digest,
            receiver_identity_document_digest: self.route.receiver.identity_document_digest.clone(),
            resource_profile_digest: self.route.resource_profile.profile_digest.clone(),
            route_generation: self.route.generation,
            route_id: self.route.route_id.clone(),
            schema: SIGNED_MANIFEST_SCHEMA.to_string(),
            sender_identity_document_digest: self.route.sender.identity_document_digest.clone(),
            sequence,
        };
        let manifest = SignedManifest::sign(unsigned, signer)?;
        manifest.verify_route(&self.route)?;
        if manifest.canonical_bytes()?.len()
            > self.route.resource_profile.max_manifest_bytes as usize
        {
            return Err(M6IdentityError::ResourceExhausted(
                "signed manifest exceeds its byte budget".to_string(),
            ));
        }
        let issued = IssuedManifest {
            attachments: attachment_bytes,
            manifest,
        };
        let record = DurableIssuanceRecord::new(
            idempotency_key,
            request_digest,
            &issued,
            &self.route,
            self.role,
        )?;
        persist_issuance_unit(&self.issued_root, &record, &issued, &self.route)?;
        Ok((record, issued))
    }

    fn resume_exact_issuance(
        &mut self,
        record: &DurableIssuanceRecord,
        issued: &IssuedManifest,
    ) -> Result<(), M6IdentityError> {
        record.validate(issued, &self.route, self.role)?;
        match self.chain.resolve_exact_commit(&issued.manifest)? {
            ReplayCommitResolution::ExactCommitted(_) => Ok(()),
            ReplayCommitResolution::NotCommitted {
                expected_sequence,
                observed_sequence,
            } if expected_sequence == observed_sequence
                && issued.manifest.unsigned.previous_message_digest
                    == self.chain.state.last_message_digest =>
            {
                let now_ms = self.clock.now_ms()?;
                self.chain.observe_clock(now_ms)?;
                self.chain.commit(&issued.manifest, now_ms)
            }
            ReplayCommitResolution::NotCommitted { .. }
            | ReplayCommitResolution::Conflicting { .. } => {
                Err(M6IdentityError::StateIntegrity(format!(
                    "durable issuance '{}' conflicts with the origin chain",
                    record.idempotency_key
                )))
            }
        }
    }
}

/// Receiver-side (or acknowledgement-consumer-side) authenticated replay
/// journal. Verification precedes every durable cursor or tombstone mutation.
pub struct ReplayJournal {
    chain: DurableChainStore,
    clock: Arc<dyn Clock>,
    negative_root: PathBuf,
    route: RouteDefinition,
    #[cfg(test)]
    fail_after_terminal_negative_record: bool,
}

impl ReplayJournal {
    pub fn open_or_initialize(
        local_root: impl AsRef<Path>,
        route: RouteDefinition,
        origin_role: RouteEndpointRole,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, M6IdentityError> {
        route.validate()?;
        let local_root = prepare_root(local_root.as_ref(), true)?;
        let chain = DurableChainStore::open_or_initialize(
            &local_root,
            &route,
            origin_role,
            ChainMode::Intake,
        )?;
        let base = secure_child_directory(&local_root, TERMINAL_NEGATIVE_DIRECTORY)?;
        let negative_root = secure_child_directory(
            &base,
            &format!(
                "{}-{}",
                route.definition_digest.file_stem(),
                origin_role.label()
            ),
        )?;
        recover_terminal_negative_staging(&negative_root, &route, origin_role)?;
        validate_terminal_negative_store(&negative_root, &route, origin_role, &chain)?;
        Ok(Self {
            chain,
            clock,
            negative_root,
            route,
            #[cfg(test)]
            fail_after_terminal_negative_record: false,
        })
    }

    pub fn verify_and_commit(&mut self, manifest: &SignedManifest) -> Result<(), M6IdentityError> {
        manifest.verify_route(&self.route)?;
        let now_ms = self.clock.now_ms()?;
        self.chain.validate_clock(now_ms)?;
        if manifest.unsigned.issued_at_ms
            > now_ms.saturating_add(self.route.resource_profile.accepted_clock_skew_ms)
        {
            return Err(M6IdentityError::FutureMessage {
                now_ms,
                issued_at_ms: manifest.unsigned.issued_at_ms,
            });
        }
        if now_ms > manifest.unsigned.expires_at_ms {
            return Err(M6IdentityError::Expired {
                now_ms,
                expires_at_ms: manifest.unsigned.expires_at_ms,
            });
        }
        // All replay/sequence/nonce/message checks precede the clock-watermark
        // write. A rejected attempt therefore has an exactly unchanged
        // replay-state digest, which can be attested by the receiver control
        // ledger without conflating rejection with an accepted commit.
        self.chain.validate_next_candidate(manifest)?;
        self.chain.observe_clock(now_ms)?;
        self.chain.commit(manifest, now_ms)
    }

    pub fn last_sequence(&self) -> u64 {
        self.chain.last_sequence()
    }

    pub fn control_state(&self) -> ReplayControlStateV1 {
        ReplayControlStateV1 {
            clock_watermark_ms: self.chain.state.clock_watermark_ms,
            last_message_digest: self.chain.state.last_message_digest.clone(),
            last_sequence: self.chain.state.last_sequence,
            route_definition_digest: self.chain.state.route_definition_digest.clone(),
            state_digest: self.chain.state.state_digest.clone(),
        }
    }

    /// Resolve whether these exact signed bytes are already durably committed.
    ///
    /// This is intentionally read-only: it does not advance the cursor, update
    /// the trusted clock watermark, or weaken `verify_and_commit`'s ordinary
    /// duplicate-delivery `Replay` result.
    pub fn resolve_exact_commit(
        &self,
        manifest: &SignedManifest,
    ) -> Result<ReplayCommitResolution, M6IdentityError> {
        manifest.verify_route(&self.route)?;
        self.chain.resolve_exact_commit(manifest)
    }

    /// Authenticate and terminally consume an exact canonical message without
    /// treating it as an accepted package input.
    ///
    /// The negative record is durable before replay cursor mutation. Only
    /// `Expired`, `Revoked`, and `PolicyRejected` are representable.
    pub fn record_terminal_negative_bytes(
        &mut self,
        canonical_manifest_bytes: &[u8],
        disposition: TerminalNegativeDisposition,
        reason: TerminalNegativeReason,
        negative_evidence_digest: ContentDigest,
    ) -> Result<TerminalNegativeRecord, M6IdentityError> {
        if canonical_manifest_bytes.is_empty()
            || canonical_manifest_bytes.len()
                > self.route.resource_profile.max_manifest_bytes as usize
        {
            return Err(M6IdentityError::ResourceExhausted(
                "terminal-negative manifest bytes exceed their hard bound".to_string(),
            ));
        }
        let manifest = SignedManifest::from_canonical_bytes(canonical_manifest_bytes)?;
        self.record_terminal_negative_canonical(
            canonical_manifest_bytes.to_vec(),
            &manifest,
            disposition,
            reason,
            negative_evidence_digest,
        )
    }

    pub fn record_terminal_negative(
        &mut self,
        manifest: &SignedManifest,
        disposition: TerminalNegativeDisposition,
        reason: TerminalNegativeReason,
        negative_evidence_digest: ContentDigest,
    ) -> Result<TerminalNegativeRecord, M6IdentityError> {
        self.record_terminal_negative_canonical(
            manifest.canonical_bytes()?,
            manifest,
            disposition,
            reason,
            negative_evidence_digest,
        )
    }

    pub fn load_terminal_negative(
        &self,
        manifest: &SignedManifest,
    ) -> Result<Option<TerminalNegativeRecord>, M6IdentityError> {
        manifest.verify_route(&self.route)?;
        let path = terminal_negative_path(&self.negative_root, &manifest.message_digest);
        if !path.exists() {
            return Ok(None);
        }
        let record = load_terminal_negative_path(&path, &self.route, self.chain.state.role)?;
        if record.canonical_manifest_bytes != manifest.canonical_bytes()? {
            return Err(M6IdentityError::StateIntegrity(
                "terminal-negative record is cross-linked to different signed bytes".to_string(),
            ));
        }
        Ok(Some(record))
    }

    pub fn resolve_terminal_negative(
        &self,
        manifest: &SignedManifest,
    ) -> Result<TerminalNegativeResolution, M6IdentityError> {
        let Some(record) = self.load_terminal_negative(manifest)? else {
            return Ok(TerminalNegativeResolution::Missing);
        };
        match self.chain.resolve_exact_commit(manifest)? {
            ReplayCommitResolution::ExactCommitted(commit) => {
                let fact = self
                    .chain
                    .terminal_negative_fact(&record.message_digest)
                    .ok_or_else(|| {
                        M6IdentityError::StateIntegrity(
                            "committed terminal-negative message has no chain fact".to_string(),
                        )
                    })?;
                if !fact.matches_record(&record) {
                    return Err(M6IdentityError::StateIntegrity(
                        "terminal-negative chain fact differs from its record".to_string(),
                    ));
                }
                Ok(TerminalNegativeResolution::ChainCommitted { commit, record })
            }
            ReplayCommitResolution::NotCommitted {
                expected_sequence,
                observed_sequence,
            } if expected_sequence == observed_sequence
                && manifest.unsigned.previous_message_digest
                    == self.chain.state.last_message_digest =>
            {
                if self
                    .chain
                    .terminal_negative_fact(&record.message_digest)
                    .is_some()
                {
                    return Err(M6IdentityError::StateIntegrity(
                        "uncommitted terminal-negative record already has a chain fact".to_string(),
                    ));
                }
                Ok(TerminalNegativeResolution::Recorded(record))
            }
            ReplayCommitResolution::NotCommitted { .. }
            | ReplayCommitResolution::Conflicting { .. } => Err(M6IdentityError::StateIntegrity(
                "terminal-negative record conflicts with the replay cursor".to_string(),
            )),
        }
    }

    fn record_terminal_negative_canonical(
        &mut self,
        canonical_manifest_bytes: Vec<u8>,
        manifest: &SignedManifest,
        disposition: TerminalNegativeDisposition,
        reason: TerminalNegativeReason,
        negative_evidence_digest: ContentDigest,
    ) -> Result<TerminalNegativeRecord, M6IdentityError> {
        manifest.verify_route(&self.route)?;
        if manifest.canonical_bytes()? != canonical_manifest_bytes {
            return Err(M6IdentityError::CanonicalEncoding(
                "terminal-negative signed bytes are not the canonical manifest bytes".to_string(),
            ));
        }
        reason.validate()?;
        if reason.disposition() != disposition {
            return Err(M6IdentityError::InvalidConfiguration(
                "terminal-negative reason and disposition differ".to_string(),
            ));
        }
        require_terminal_negative_evidence(&negative_evidence_digest)?;
        let path = terminal_negative_path(&self.negative_root, &manifest.message_digest);
        if path.exists() {
            let record = load_terminal_negative_path(&path, &self.route, self.chain.state.role)?;
            let requested = terminal_negative_request_digest(
                &canonical_manifest_bytes,
                disposition,
                &reason,
                &negative_evidence_digest,
            )?;
            let existing = terminal_negative_request_digest(
                &record.canonical_manifest_bytes,
                record.disposition,
                &record.reason,
                &record.negative_evidence_digest,
            )?;
            if requested != existing {
                return Err(M6IdentityError::TerminalNegativeConflict {
                    message_digest: manifest.message_digest.clone(),
                    existing: record.record_digest,
                    requested,
                });
            }
            if record.canonical_manifest_bytes != canonical_manifest_bytes {
                return Err(M6IdentityError::StateIntegrity(
                    "terminal-negative path is cross-linked to different signed bytes".to_string(),
                ));
            }
            match self.resolve_terminal_negative(manifest)? {
                TerminalNegativeResolution::ChainCommitted { .. } => return Ok(record),
                TerminalNegativeResolution::Recorded(_) => {
                    self.chain.commit_terminal_negative(manifest, &record)?;
                    return Ok(record);
                }
                TerminalNegativeResolution::Missing => {
                    return Err(M6IdentityError::StateIntegrity(
                        "retained terminal-negative record disappeared during recovery".to_string(),
                    ));
                }
            }
        }

        let now_ms = self.clock.now_ms()?;
        self.chain.validate_clock(now_ms)?;
        if manifest.unsigned.issued_at_ms
            > now_ms.saturating_add(self.route.resource_profile.accepted_clock_skew_ms)
        {
            return Err(M6IdentityError::FutureMessage {
                now_ms,
                issued_at_ms: manifest.unsigned.issued_at_ms,
            });
        }
        let expired = now_ms > manifest.unsigned.expires_at_ms;
        if (disposition == TerminalNegativeDisposition::Expired) != expired {
            return Err(M6IdentityError::ContradictoryNegativeTiming {
                disposition,
                now_ms,
                expires_at_ms: manifest.unsigned.expires_at_ms,
            });
        }
        self.chain.validate_next_candidate(manifest)?;
        enforce_file_count(
            &self.negative_root,
            self.route.resource_profile.max_replay_records,
            TERMINAL_NEGATIVE_SUFFIX,
            "terminal-negative records",
        )?;
        let record = TerminalNegativeRecord::new(
            canonical_manifest_bytes,
            manifest,
            &self.route,
            self.chain.state.role,
            disposition,
            reason,
            negative_evidence_digest,
            now_ms,
            self.chain.state.clock_watermark_ms,
        )?;
        let record_bytes = canonical_json(&record)?;
        if record_bytes.len() > terminal_negative_record_limit(&self.route.resource_profile) {
            return Err(M6IdentityError::ResourceExhausted(
                "terminal-negative record exceeds its absolute storage bound".to_string(),
            ));
        }
        persist_terminal_negative_immutable(&self.negative_root, &path, &record_bytes)?;
        #[cfg(test)]
        if self.fail_after_terminal_negative_record {
            return Err(M6IdentityError::StateIntegrity(
                "injected crash after terminal-negative record commit".to_string(),
            ));
        }
        self.chain.commit_terminal_negative(manifest, &record)?;
        Ok(record)
    }
}

fn terminal_negative_path(root: &Path, message_digest: &ContentDigest) -> PathBuf {
    root.join(format!(
        "{}{}",
        message_digest.file_stem(),
        TERMINAL_NEGATIVE_SUFFIX
    ))
}

fn terminal_negative_record_limit(profile: &RouteResourceProfile) -> usize {
    usize::try_from(profile.max_manifest_bytes)
        .unwrap_or(usize::MAX)
        .saturating_mul(5)
        .saturating_add(64 * 1_024)
        .min(64 * 1_048_576)
}

fn load_terminal_negative_path(
    path: &Path,
    route: &RouteDefinition,
    origin_role: RouteEndpointRole,
) -> Result<TerminalNegativeRecord, M6IdentityError> {
    let record: TerminalNegativeRecord = parse_canonical(&read_bounded(
        path,
        terminal_negative_record_limit(&route.resource_profile),
    )?)?;
    record.validate(route, origin_role)?;
    let expected_name = format!(
        "{}{}",
        record.message_digest.file_stem(),
        TERMINAL_NEGATIVE_SUFFIX
    );
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
        return Err(M6IdentityError::StateIntegrity(
            "terminal-negative record is stored under the wrong message path".to_string(),
        ));
    }
    Ok(record)
}

fn terminal_negative_request_digest(
    canonical_manifest_bytes: &[u8],
    disposition: TerminalNegativeDisposition,
    reason: &TerminalNegativeReason,
    negative_evidence_digest: &ContentDigest,
) -> Result<ContentDigest, M6IdentityError> {
    digest_domain_serializable(
        b"wasm-biotic:m6:terminal-negative-request:v1\0",
        &(
            canonical_manifest_bytes,
            disposition,
            reason,
            negative_evidence_digest,
        ),
    )
}

fn require_terminal_negative_evidence(digest: &ContentDigest) -> Result<(), M6IdentityError> {
    let is_zero = digest
        .as_str()
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.bytes().all(|byte| byte == b'0'));
    if is_zero || digest == &ContentDigest::from_bytes(&[]) {
        return Err(M6IdentityError::MissingNegativeEvidence);
    }
    Ok(())
}

fn persist_terminal_negative_immutable(
    root: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), M6IdentityError> {
    require_direct_child(root, destination)?;
    if destination.exists() {
        let existing = read_bounded(destination, bytes.len().saturating_add(1))?;
        if existing == bytes {
            return Ok(());
        }
        return Err(M6IdentityError::RouteConflict(destination.to_path_buf()));
    }
    let staging = root.join(format!(
        "{TERMINAL_NEGATIVE_STAGING_PREFIX}{}-{}-{}",
        ContentDigest::from_bytes(bytes).file_stem(),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    (|| {
        write_new_sync(&staging, bytes)?;
        match fs::hard_link(&staging, destination) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_bounded(destination, bytes.len().saturating_add(1))?;
                if existing != bytes {
                    return Err(M6IdentityError::RouteConflict(destination.to_path_buf()));
                }
            }
            Err(source) => {
                return Err(M6IdentityError::io(destination, source));
            }
        }
        sync_directory(root)?;
        fs::remove_file(&staging).map_err(|source| M6IdentityError::io(&staging, source))?;
        sync_directory(root)
    })()
}

fn recover_terminal_negative_staging(
    root: &Path,
    route: &RouteDefinition,
    origin_role: RouteEndpointRole,
) -> Result<(), M6IdentityError> {
    let mut staging_paths = Vec::new();
    for entry in fs::read_dir(root).map_err(|source| M6IdentityError::io(root, source))? {
        let entry = entry.map_err(|source| M6IdentityError::io(root, source))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| M6IdentityError::UnsafePath(path.clone()))?
            .to_string();
        if name.starts_with(TERMINAL_NEGATIVE_STAGING_PREFIX) {
            reject_symlink(&path)?;
            let metadata =
                fs::symlink_metadata(&path).map_err(|source| M6IdentityError::io(&path, source))?;
            if !metadata.is_file() {
                return Err(M6IdentityError::UnsafePath(path));
            }
            staging_paths.push(path);
        }
    }
    staging_paths.sort();
    for staging in staging_paths {
        let bytes = read_bounded(
            &staging,
            terminal_negative_record_limit(&route.resource_profile),
        )?;
        let record: TerminalNegativeRecord = parse_canonical(&bytes)?;
        record.validate(route, origin_role)?;
        let destination = terminal_negative_path(root, &record.message_digest);
        if destination.exists() {
            let existing = read_bounded(
                &destination,
                terminal_negative_record_limit(&route.resource_profile),
            )?;
            if existing != bytes {
                return Err(M6IdentityError::RouteConflict(destination));
            }
        } else {
            fs::hard_link(&staging, &destination)
                .map_err(|source| M6IdentityError::io(&destination, source))?;
            sync_directory(root)?;
        }
        fs::remove_file(&staging).map_err(|source| M6IdentityError::io(&staging, source))?;
        sync_directory(root)?;
    }
    Ok(())
}

fn validate_terminal_negative_store(
    root: &Path,
    route: &RouteDefinition,
    origin_role: RouteEndpointRole,
    chain: &DurableChainStore,
) -> Result<(), M6IdentityError> {
    let mut records = BTreeMap::new();
    let mut pending = 0_usize;
    for entry in fs::read_dir(root).map_err(|source| M6IdentityError::io(root, source))? {
        let entry = entry.map_err(|source| M6IdentityError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| M6IdentityError::io(&path, source))?;
        if !metadata.is_file()
            || !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(TERMINAL_NEGATIVE_SUFFIX))
        {
            return Err(M6IdentityError::UnsafePath(path));
        }
        if records.len() >= route.resource_profile.max_replay_records as usize {
            return Err(M6IdentityError::ResourceExhausted(
                "terminal-negative record store exceeds its route budget".to_string(),
            ));
        }
        let record = load_terminal_negative_path(&path, route, origin_role)?;
        if records
            .insert(record.message_digest.clone(), record.clone())
            .is_some()
        {
            return Err(M6IdentityError::StateIntegrity(
                "terminal-negative store contains duplicate message identities".to_string(),
            ));
        }
        match chain.resolve_exact_commit(&SignedManifest::from_canonical_bytes(
            &record.canonical_manifest_bytes,
        )?)? {
            ReplayCommitResolution::ExactCommitted(_) => {
                let fact = chain
                    .terminal_negative_fact(&record.message_digest)
                    .ok_or_else(|| {
                        M6IdentityError::StateIntegrity(
                            "committed terminal-negative record has no chain fact".to_string(),
                        )
                    })?;
                if !fact.matches_record(&record)
                    || chain.state.clock_watermark_ms < record.clock_watermark_ms
                {
                    return Err(M6IdentityError::StateIntegrity(
                        "terminal-negative record differs from committed chain state".to_string(),
                    ));
                }
            }
            ReplayCommitResolution::NotCommitted {
                expected_sequence,
                observed_sequence,
            } if expected_sequence == observed_sequence
                && record.previous_message_digest == chain.state.last_message_digest =>
            {
                pending += 1;
                if pending > 1
                    || chain
                        .terminal_negative_fact(&record.message_digest)
                        .is_some()
                {
                    return Err(M6IdentityError::StateIntegrity(
                        "terminal-negative store has ambiguous pending records".to_string(),
                    ));
                }
            }
            ReplayCommitResolution::NotCommitted { .. }
            | ReplayCommitResolution::Conflicting { .. } => {
                return Err(M6IdentityError::StateIntegrity(
                    "terminal-negative record conflicts with replay state".to_string(),
                ));
            }
        }
    }
    for (message_digest, fact) in &chain.state.terminal_negative_facts {
        let record = records.get(&fact.message_digest).ok_or_else(|| {
            M6IdentityError::StateIntegrity(
                "terminal-negative chain fact has no immutable record".to_string(),
            )
        })?;
        if message_digest != fact.message_digest.as_str() || !fact.matches_record(record) {
            return Err(M6IdentityError::StateIntegrity(
                "terminal-negative chain fact is cross-linked".to_string(),
            ));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct IssuanceRequestBinding<'a> {
    attachments: &'a [AttachmentDescriptor],
    idempotency_key: &'a str,
    lifetime_ms: u64,
    origin_signing_key_id: &'a str,
    payload: &'a ManifestPayload,
    role: RouteEndpointRole,
    route_definition_digest: &'a ContentDigest,
}

fn issuance_fingerprint(
    route: &RouteDefinition,
    role: RouteEndpointRole,
    origin_signing_key_id: &str,
    payload: &ManifestPayload,
    attachments: &[AttachmentDescriptor],
    lifetime_ms: u64,
) -> Result<ContentDigest, M6IdentityError> {
    digest_domain_serializable(
        ISSUANCE_FINGERPRINT_DOMAIN,
        &(
            attachments,
            lifetime_ms,
            origin_signing_key_id,
            payload,
            role,
            &route.definition_digest,
        ),
    )
}

fn issuance_request_digest(
    idempotency_key: &str,
    route: &RouteDefinition,
    role: RouteEndpointRole,
    origin_signing_key_id: &str,
    payload: &ManifestPayload,
    attachments: &[AttachmentDescriptor],
    lifetime_ms: u64,
) -> Result<ContentDigest, M6IdentityError> {
    digest_domain_serializable(
        ISSUANCE_REQUEST_DOMAIN,
        &IssuanceRequestBinding {
            attachments,
            idempotency_key,
            lifetime_ms,
            origin_signing_key_id,
            payload,
            role,
            route_definition_digest: &route.definition_digest,
        },
    )
}

fn abandonment_request_digest(
    idempotency_key: &str,
    request_digest: &ContentDigest,
    message_digest: &ContentDigest,
    sequence: u64,
    disposition: PreparedIssuanceDisposition,
    reason: &str,
    decision_evidence_digest: &ContentDigest,
) -> Result<ContentDigest, M6IdentityError> {
    digest_domain_serializable(
        b"wasm-biotic:m6:issuance-abandonment-request:v1\0",
        &(
            decision_evidence_digest,
            disposition,
            idempotency_key,
            message_digest,
            reason,
            request_digest,
            sequence,
        ),
    )
}

fn validate_bounded_reason(reason: &str) -> Result<(), M6IdentityError> {
    if reason.is_empty()
        || reason.len() > 4_096
        || reason
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(M6IdentityError::InvalidConfiguration(
            "issuance abandonment reason is blank, contains unsafe control characters, or exceeds 4096 bytes"
                .to_string(),
        ));
    }
    Ok(())
}

fn issuance_unit_name(idempotency_key: &str) -> String {
    let mut bytes = Vec::from(ISSUANCE_PATH_DOMAIN);
    bytes.extend_from_slice(idempotency_key.as_bytes());
    format!("{}.unit", ContentDigest::from_bytes(&bytes).file_stem())
}

fn issuance_unit_path(root: &Path, idempotency_key: &str) -> PathBuf {
    root.join(issuance_unit_name(idempotency_key))
}

fn acquire_issuer_lock(
    locks_root: &Path,
    route: &RouteDefinition,
    role: RouteEndpointRole,
) -> Result<File, M6IdentityError> {
    let path = locks_root.join(format!(
        "{}-{}.lock",
        route.definition_digest.file_stem(),
        role.label()
    ));
    reject_symlink_if_present(&path)?;
    let existed = path.exists();
    if existed {
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| M6IdentityError::io(&path, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(M6IdentityError::UnsafePath(path));
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| M6IdentityError::io(&path, source))?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => M6IdentityError::RoleAlreadyOwned(role),
        std::fs::TryLockError::Error(source) => M6IdentityError::io(&path, source),
    })?;
    if !existed {
        sync_directory(locks_root)?;
    }
    Ok(file)
}

fn recover_issuance_staging(root: &Path) -> Result<(), M6IdentityError> {
    let mut removed = false;
    for entry in fs::read_dir(root).map_err(|source| M6IdentityError::io(root, source))? {
        let entry = entry.map_err(|source| M6IdentityError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| M6IdentityError::UnsafePath(path.clone()))?
            .to_string();
        let file_type = entry
            .file_type()
            .map_err(|source| M6IdentityError::io(&path, source))?;
        if file_type.is_dir() && name.starts_with(".building-issuance-") {
            remove_confined_directory(root, &path)?;
            removed = true;
        } else if !(file_type.is_dir() && name.ends_with(".unit")) {
            return Err(M6IdentityError::UnsafePath(path));
        }
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(())
}

fn issuance_unit_paths(
    root: &Path,
    profile: &RouteResourceProfile,
) -> Result<Vec<PathBuf>, M6IdentityError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).map_err(|source| M6IdentityError::io(root, source))? {
        let entry = entry.map_err(|source| M6IdentityError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if !entry
            .file_type()
            .map_err(|source| M6IdentityError::io(&path, source))?
            .is_dir()
            || !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".unit"))
        {
            return Err(M6IdentityError::UnsafePath(path));
        }
        paths.push(path);
        if paths.len() > profile.max_replay_records as usize {
            return Err(M6IdentityError::ResourceExhausted(
                "durable issuance unit budget is exceeded".to_string(),
            ));
        }
    }
    paths.sort();
    Ok(paths)
}

fn issuance_nonce_exists(
    root: &Path,
    route: &RouteDefinition,
    role: RouteEndpointRole,
    nonce: &str,
) -> Result<bool, M6IdentityError> {
    for path in issuance_unit_paths(root, &route.resource_profile)? {
        let (_, issued, _) = load_issuance_unit(&path, route, role)?;
        if issued.manifest.unsigned.nonce == nonce {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_issuance_store(
    root: &Path,
    route: &RouteDefinition,
    role: RouteEndpointRole,
    chain: &DurableChainStore,
) -> Result<(), M6IdentityError> {
    inspect_issuance_store(root, route, role, chain).map(|_| ())
}

fn pending_issuance(
    root: &Path,
    route: &RouteDefinition,
    role: RouteEndpointRole,
    chain: &DurableChainStore,
) -> Result<Option<DurableIssuanceRecord>, M6IdentityError> {
    inspect_issuance_store(root, route, role, chain)
}

fn inspect_issuance_store(
    root: &Path,
    route: &RouteDefinition,
    role: RouteEndpointRole,
    chain: &DurableChainStore,
) -> Result<Option<DurableIssuanceRecord>, M6IdentityError> {
    let mut seen_keys = BTreeSet::new();
    let mut live_sequences = BTreeSet::new();
    let mut pending = None;
    for path in issuance_unit_paths(root, &route.resource_profile)? {
        let (record, issued, abandonment) = load_issuance_unit(&path, route, role)?;
        if !seen_keys.insert(record.idempotency_key.clone()) {
            return Err(M6IdentityError::StateIntegrity(
                "durable issuance store has duplicate idempotency keys".to_string(),
            ));
        }
        let resolution = chain.resolve_exact_commit(&issued.manifest)?;
        if abandonment.is_some() {
            match resolution {
                ReplayCommitResolution::ExactCommitted(_) => {
                    return Err(M6IdentityError::StateIntegrity(format!(
                        "abandoned issuance '{}' is also committed",
                        record.idempotency_key
                    )));
                }
                ReplayCommitResolution::NotCommitted {
                    expected_sequence,
                    observed_sequence,
                } if expected_sequence == observed_sequence
                    && issued.manifest.unsigned.previous_message_digest
                        == chain.state.last_message_digest => {}
                ReplayCommitResolution::Conflicting { .. }
                    if record.sequence <= chain.state.last_sequence => {}
                ReplayCommitResolution::NotCommitted { .. }
                | ReplayCommitResolution::Conflicting { .. } => {
                    return Err(M6IdentityError::StateIntegrity(format!(
                        "abandoned issuance '{}' has impossible origin coordinates",
                        record.idempotency_key
                    )));
                }
            }
            continue;
        }
        if !live_sequences.insert(record.sequence) {
            return Err(M6IdentityError::StateIntegrity(
                "duplicate issuance sequence is not fully covered by immutable abandonment"
                    .to_string(),
            ));
        }
        match resolution {
            ReplayCommitResolution::ExactCommitted(_) => {}
            ReplayCommitResolution::NotCommitted {
                expected_sequence,
                observed_sequence,
            } if expected_sequence == observed_sequence
                && issued.manifest.unsigned.previous_message_digest
                    == chain.state.last_message_digest =>
            {
                if pending.replace(record).is_some() {
                    return Err(M6IdentityError::StateIntegrity(
                        "durable issuance store has more than one pending chain commit".to_string(),
                    ));
                }
            }
            ReplayCommitResolution::NotCommitted { .. }
            | ReplayCommitResolution::Conflicting { .. } => {
                return Err(M6IdentityError::StateIntegrity(format!(
                    "durable issuance unit '{}' conflicts with the origin chain",
                    path.display()
                )));
            }
        }
    }
    Ok(pending)
}

fn issuance_snapshot(
    record: &DurableIssuanceRecord,
    issued: &IssuedManifest,
    route: &RouteDefinition,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, M6IdentityError> {
    let mut snapshot = expected_delivery_snapshot(issued, route)?;
    snapshot.insert(PathBuf::from(ISSUANCE_RECORD_FILE), canonical_json(record)?);
    enforce_snapshot_bounds(&snapshot, &route.resource_profile)?;
    Ok(snapshot)
}

fn persist_issuance_unit(
    root: &Path,
    record: &DurableIssuanceRecord,
    issued: &IssuedManifest,
    route: &RouteDefinition,
) -> Result<(), M6IdentityError> {
    record.validate(issued, route, issued.manifest.unsigned.origin_role)?;
    let desired = issuance_snapshot(record, issued, route)?;
    let destination = issuance_unit_path(root, &record.idempotency_key);
    if destination.exists() {
        return require_snapshot_matches(&destination, &desired, &route.resource_profile);
    }
    let temporary = root.join(format!(
        ".building-issuance-{}-{}-{}",
        issued.manifest.message_digest.file_stem(),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        write_snapshot_directory(&temporary, &desired)?;
        fs::rename(&temporary, &destination)
            .map_err(|source| M6IdentityError::io(&destination, source))?;
        sync_directory(root)
    })();
    if result.is_err() && temporary.exists() {
        let _ = remove_confined_directory(root, &temporary);
    }
    result
}

fn load_issuance_unit(
    path: &Path,
    route: &RouteDefinition,
    role: RouteEndpointRole,
) -> Result<
    (
        DurableIssuanceRecord,
        IssuedManifest,
        Option<PreparedIssuanceAbandonment>,
    ),
    M6IdentityError,
> {
    let mut delivery_snapshot = read_tree_snapshot(path, &route.resource_profile)?;
    let abandonment_bytes = delivery_snapshot.remove(Path::new(ISSUANCE_ABANDONMENT_FILE));
    let record_bytes = delivery_snapshot
        .remove(Path::new(ISSUANCE_RECORD_FILE))
        .ok_or_else(|| {
            M6IdentityError::StateIntegrity(
                "durable issuance unit lacks its request record".to_string(),
            )
        })?;
    let record: DurableIssuanceRecord = parse_canonical(&record_bytes)?;
    let manifest = validate_delivery_snapshot(&delivery_snapshot, route)?;
    let mut attachments = BTreeMap::new();
    for descriptor in &manifest.unsigned.attachments {
        let relative = attachment_relative_path(&descriptor.content_digest);
        attachments.insert(
            descriptor.content_digest.clone(),
            delivery_snapshot.get(&relative).cloned().ok_or_else(|| {
                M6IdentityError::StateIntegrity(format!(
                    "durable issuance lacks attachment '{}'",
                    descriptor.content_digest
                ))
            })?,
        );
    }
    let issued = IssuedManifest {
        attachments,
        manifest,
    };
    record.validate(&issued, route, role)?;
    let abandonment = abandonment_bytes
        .map(|bytes| {
            let abandonment: PreparedIssuanceAbandonment = parse_canonical(&bytes)?;
            abandonment.validate(&record, &issued, route, role)?;
            Ok(abandonment)
        })
        .transpose()?;
    if path.file_name().and_then(|name| name.to_str())
        != Some(issuance_unit_name(&record.idempotency_key).as_str())
    {
        return Err(M6IdentityError::StateIntegrity(
            "durable issuance unit is stored under the wrong idempotency path".to_string(),
        ));
    }
    Ok((record, issued, abandonment))
}

fn bind_attachments(
    attachments: Vec<AttachmentInput>,
    profile: &RouteResourceProfile,
) -> Result<(Vec<AttachmentDescriptor>, BTreeMap<ContentDigest, Vec<u8>>), M6IdentityError> {
    if attachments.len() > profile.max_attachment_count as usize {
        return Err(M6IdentityError::ResourceExhausted(
            "attachment count exceeds route profile".to_string(),
        ));
    }
    let mut descriptors = Vec::with_capacity(attachments.len());
    let mut bytes_by_digest = BTreeMap::new();
    let mut logical_names = BTreeSet::new();
    let mut aggregate = 0_u64;
    for attachment in attachments {
        validate_identifier("attachment logical name", &attachment.logical_name)?;
        validate_media_type(&attachment.media_type)?;
        let byte_length = u64::try_from(attachment.bytes.len()).map_err(|_| {
            M6IdentityError::ResourceExhausted("attachment length overflowed".to_string())
        })?;
        if byte_length == 0 || byte_length > profile.max_attachment_bytes {
            return Err(M6IdentityError::ResourceExhausted(format!(
                "attachment '{}' exceeds its byte budget",
                attachment.logical_name
            )));
        }
        aggregate = aggregate.saturating_add(byte_length);
        if aggregate > profile.max_delivery_bytes {
            return Err(M6IdentityError::ResourceExhausted(
                "aggregate attachment bytes exceed route profile".to_string(),
            ));
        }
        let digest = ContentDigest::from_bytes(&attachment.bytes);
        if !logical_names.insert(attachment.logical_name.clone())
            || bytes_by_digest
                .insert(digest.clone(), attachment.bytes)
                .is_some()
        {
            return Err(M6IdentityError::InvalidConfiguration(
                "attachment logical names and content digests must be unique".to_string(),
            ));
        }
        descriptors.push(AttachmentDescriptor {
            byte_length,
            content_digest: digest,
            logical_name: attachment.logical_name,
            media_type: attachment.media_type,
        });
    }
    descriptors.sort_by(|left, right| left.logical_name.cmp(&right.logical_name));
    Ok((descriptors, bytes_by_digest))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryCommitMarker {
    manifest_bytes_digest: ContentDigest,
    message_digest: ContentDigest,
    schema: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpoolRecoveryReport {
    pub recovered_units: usize,
}

#[derive(Clone, Debug)]
pub struct GovernedFilesystemSpool {
    local_root: PathBuf,
    role: RouteEndpointRole,
    route: RouteDefinition,
    route_root: PathBuf,
}

impl GovernedFilesystemSpool {
    /// Initialize the neutral route capability and both directional spool
    /// directories. Endpoint handles are opened separately and never receive
    /// the peer endpoint's private filesystem root.
    pub fn initialize(
        route_root: impl AsRef<Path>,
        sender_root: impl AsRef<Path>,
        receiver_root: impl AsRef<Path>,
        route: RouteDefinition,
    ) -> Result<ContentDigest, M6IdentityError> {
        route.validate()?;
        let sender_root = prepare_root(sender_root.as_ref(), true)?;
        let receiver_root = prepare_root(receiver_root.as_ref(), true)?;
        let route_root = prepare_root(route_root.as_ref(), true)?;
        ensure_pairwise_disjoint(&sender_root, &receiver_root, &route_root)?;
        let definition_path = route_root.join(ROUTE_DEFINITION_FILE);
        persist_immutable(&definition_path, &canonical_json(&route)?)?;
        initialize_spool_layout(&route_root, &route)?;
        Ok(route.definition_digest)
    }

    /// Open one endpoint-local spool capability.
    ///
    /// `local_root` is the only endpoint-private path accepted or retained.
    pub fn open(
        route_root: impl AsRef<Path>,
        local_root: impl AsRef<Path>,
        role: RouteEndpointRole,
        expected_definition_digest: &ContentDigest,
    ) -> Result<Self, M6IdentityError> {
        let local_root = prepare_root(local_root.as_ref(), false)?;
        let route_root = prepare_root(route_root.as_ref(), false)?;
        if local_root == route_root
            || local_root.starts_with(&route_root)
            || route_root.starts_with(&local_root)
        {
            return Err(M6IdentityError::InvalidConfiguration(
                "endpoint-local root and neutral route root must be disjoint".to_string(),
            ));
        }
        let route: RouteDefinition = parse_canonical(&read_bounded(
            &route_root.join(ROUTE_DEFINITION_FILE),
            2 * 1_048_576,
        )?)?;
        route.validate()?;
        require_digest(
            "opened route definition",
            expected_definition_digest,
            &route.definition_digest,
        )?;
        let spool = Self {
            local_root,
            role,
            route,
            route_root,
        };
        spool.verify_endpoint_layout()?;
        Ok(spool)
    }

    pub fn route(&self) -> &RouteDefinition {
        &self.route
    }

    pub fn role(&self) -> RouteEndpointRole {
        self.role
    }

    pub fn local_root(&self) -> &Path {
        &self.local_root
    }

    pub fn acquire_role(&self) -> Result<RouteRoleOwner, M6IdentityError> {
        self.verify_endpoint_layout()?;
        let locks = self.generation_root().join(LOCKS_DIRECTORY);
        let lock_path = locks.join(format!("{}.lock", self.role.label()));
        reject_symlink_if_present(&lock_path)?;
        let existed = lock_path.exists();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|source| M6IdentityError::io(&lock_path, source))?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => M6IdentityError::RoleAlreadyOwned(self.role),
            std::fs::TryLockError::Error(source) => M6IdentityError::io(&lock_path, source),
        })?;
        if !existed {
            sync_directory(&locks)?;
        }
        Ok(RouteRoleOwner {
            local_root: self.local_root.clone(),
            role: self.role,
            route_definition_digest: self.route.definition_digest.clone(),
            route_root: self.route_root.clone(),
            _lock: file,
        })
    }

    pub fn stage_delivery(
        &self,
        owner: &RouteRoleOwner,
        issued: &IssuedManifest,
    ) -> Result<ContentDigest, M6IdentityError> {
        self.require_owner(owner)?;
        if issued.manifest.unsigned.origin_role != self.role {
            return Err(M6IdentityError::WrongRole {
                expected: self.role,
                actual: issued.manifest.unsigned.origin_role,
            });
        }
        issued.manifest.verify_route(&self.route)?;
        let desired = expected_delivery_snapshot(issued, &self.route)?;
        let (staged_root, ready_root) = self.outbound_delivery_directories();
        let unit_name = delivery_unit_name(&issued.manifest.message_digest);
        let staged = staged_root.join(&unit_name);
        let ready = ready_root.join(&unit_name);
        if ready.exists() {
            require_snapshot_matches(&ready, &desired, &self.route.resource_profile)?;
            return Ok(issued.manifest.message_digest.clone());
        }
        if staged.exists() {
            require_snapshot_matches(&staged, &desired, &self.route.resource_profile)?;
            return Ok(issued.manifest.message_digest.clone());
        }
        enforce_unit_count(
            &staged_root,
            self.route.resource_profile.max_staged_units,
            "staged delivery units",
        )?;
        enforce_unit_count(
            &ready_root,
            self.route.resource_profile.max_ready_units,
            "ready delivery units",
        )?;
        let temporary = staged_root.join(format!(
            ".building-{}-{}-{}",
            issued.manifest.message_digest.file_stem(),
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            write_snapshot_directory(&temporary, &desired)?;
            fs::rename(&temporary, &staged)
                .map_err(|source| M6IdentityError::io(&staged, source))?;
            sync_directory(&staged_root)
        })();
        if result.is_err() && temporary.exists() {
            let _ = remove_confined_directory(&staged_root, &temporary);
        }
        result?;
        Ok(issued.manifest.message_digest.clone())
    }

    pub fn commit_staged(
        &self,
        owner: &RouteRoleOwner,
        message_digest: &ContentDigest,
    ) -> Result<(), M6IdentityError> {
        self.require_owner(owner)?;
        let (staged_root, ready_root) = self.outbound_delivery_directories();
        let unit_name = delivery_unit_name(message_digest);
        let staged = staged_root.join(&unit_name);
        let ready = ready_root.join(&unit_name);
        if ready.exists() {
            if staged.exists() {
                let staged_snapshot = read_tree_snapshot(&staged, &self.route.resource_profile)?;
                let ready_snapshot = read_tree_snapshot(&ready, &self.route.resource_profile)?;
                if staged_snapshot != ready_snapshot {
                    return Err(M6IdentityError::RouteConflict(ready));
                }
                remove_confined_directory(&staged_root, &staged)?;
                sync_directory(&staged_root)?;
            }
            return Ok(());
        }
        let snapshot = read_tree_snapshot(&staged, &self.route.resource_profile)?;
        let manifest = validate_delivery_snapshot(&snapshot, &self.route)?;
        require_digest(
            "staged delivery identity",
            message_digest,
            &manifest.message_digest,
        )?;
        fs::rename(&staged, &ready).map_err(|source| M6IdentityError::io(&ready, source))?;
        sync_directory(&ready_root)?;
        sync_directory(&staged_root)
    }

    pub fn publish(
        &self,
        owner: &RouteRoleOwner,
        issued: &IssuedManifest,
    ) -> Result<ContentDigest, M6IdentityError> {
        let message_digest = self.stage_delivery(owner, issued)?;
        self.commit_staged(owner, &message_digest)?;
        Ok(message_digest)
    }

    pub fn recover_staged(
        &self,
        owner: &RouteRoleOwner,
    ) -> Result<SpoolRecoveryReport, M6IdentityError> {
        self.require_owner(owner)?;
        let (staged_root, _) = self.outbound_delivery_directories();
        let mut units = Vec::new();
        for entry in fs::read_dir(&staged_root)
            .map_err(|source| M6IdentityError::io(&staged_root, source))?
        {
            let entry = entry.map_err(|source| M6IdentityError::io(&staged_root, source))?;
            let path = entry.path();
            reject_symlink(&path)?;
            if entry
                .file_type()
                .map_err(|source| M6IdentityError::io(&path, source))?
                .is_dir()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(".unit"))
            {
                units.push(path);
            }
        }
        if units.len() > self.route.resource_profile.max_staged_units as usize {
            return Err(M6IdentityError::ResourceExhausted(
                "staged delivery count exceeds route profile".to_string(),
            ));
        }
        units.sort();
        let mut recovered = 0;
        for path in units {
            let snapshot = read_tree_snapshot(&path, &self.route.resource_profile)?;
            let manifest = validate_delivery_snapshot(&snapshot, &self.route)?;
            if manifest.unsigned.origin_role != self.role {
                return Err(M6IdentityError::WrongRole {
                    expected: self.role,
                    actual: manifest.unsigned.origin_role,
                });
            }
            self.commit_staged(owner, &manifest.message_digest)?;
            recovered += 1;
        }
        Ok(SpoolRecoveryReport {
            recovered_units: recovered,
        })
    }

    pub fn outbound_ready_unit_directory(&self, message_digest: &ContentDigest) -> PathBuf {
        self.outbound_delivery_directories()
            .1
            .join(delivery_unit_name(message_digest))
    }

    pub fn inbound_ready_unit_directory(&self, message_digest: &ContentDigest) -> PathBuf {
        self.inbound_ready_directory()
            .join(delivery_unit_name(message_digest))
    }

    pub fn read_outbound_ready(
        &self,
        message_digest: &ContentDigest,
    ) -> Result<IssuedManifest, M6IdentityError> {
        let snapshot = read_tree_snapshot(
            &self.outbound_ready_unit_directory(message_digest),
            &self.route.resource_profile,
        )?;
        let manifest = validate_delivery_snapshot(&snapshot, &self.route)?;
        let mut attachments = BTreeMap::new();
        for descriptor in &manifest.unsigned.attachments {
            let relative = attachment_relative_path(&descriptor.content_digest);
            attachments.insert(
                descriptor.content_digest.clone(),
                snapshot.get(&relative).cloned().ok_or_else(|| {
                    M6IdentityError::StateIntegrity(format!(
                        "ready unit lacks attachment '{}'",
                        descriptor.content_digest
                    ))
                })?,
            );
        }
        Ok(IssuedManifest {
            attachments,
            manifest,
        })
    }

    fn verify_endpoint_layout(&self) -> Result<(), M6IdentityError> {
        if self.local_root == self.route_root
            || self.local_root.starts_with(&self.route_root)
            || self.route_root.starts_with(&self.local_root)
        {
            return Err(M6IdentityError::InvalidConfiguration(
                "endpoint-local root and neutral route root must remain disjoint".to_string(),
            ));
        }
        ensure_real_directory(&self.local_root)?;
        reject_symlink(&self.route_root)?;
        reject_symlink(&self.route_root.join(ROUTE_DEFINITION_FILE))?;
        let generation_root = self.generation_root();
        ensure_real_directory(&generation_root)?;
        require_direct_child(&self.route_root, &generation_root)?;
        let (outbound_staged, outbound_ready) = self.outbound_delivery_directories();
        for path in [
            outbound_staged,
            outbound_ready,
            self.inbound_ready_directory(),
            generation_root.join(LOCKS_DIRECTORY),
        ] {
            ensure_real_directory(&path)?;
            require_direct_child(&generation_root, &path)?;
        }
        Ok(())
    }

    fn generation_root(&self) -> PathBuf {
        self.route_root
            .join(format!("generation-{}", self.route.generation))
    }

    fn outbound_delivery_directories(&self) -> (PathBuf, PathBuf) {
        let generation = self.generation_root();
        match self.role {
            RouteEndpointRole::Sender => (
                generation.join(SENDER_STAGED_DIRECTORY),
                generation.join(SENDER_READY_DIRECTORY),
            ),
            RouteEndpointRole::Receiver => (
                generation.join(RECEIVER_STAGED_DIRECTORY),
                generation.join(RECEIVER_READY_DIRECTORY),
            ),
        }
    }

    fn inbound_ready_directory(&self) -> PathBuf {
        let generation = self.generation_root();
        match self.role {
            RouteEndpointRole::Sender => generation.join(RECEIVER_READY_DIRECTORY),
            RouteEndpointRole::Receiver => generation.join(SENDER_READY_DIRECTORY),
        }
    }

    fn require_owner(&self, owner: &RouteRoleOwner) -> Result<(), M6IdentityError> {
        if owner.role != self.role {
            return Err(M6IdentityError::WrongRole {
                expected: self.role,
                actual: owner.role,
            });
        }
        if owner.route_definition_digest != self.route.definition_digest
            || owner.route_root != self.route_root
            || owner.local_root != self.local_root
        {
            return Err(M6IdentityError::StateIntegrity(
                "route role owner belongs to another endpoint or route definition".to_string(),
            ));
        }
        Ok(())
    }
}

fn initialize_spool_layout(
    route_root: &Path,
    route: &RouteDefinition,
) -> Result<(), M6IdentityError> {
    let generation_root =
        secure_child_directory(route_root, &format!("generation-{}", route.generation))?;
    for name in [
        SENDER_STAGED_DIRECTORY,
        SENDER_READY_DIRECTORY,
        RECEIVER_STAGED_DIRECTORY,
        RECEIVER_READY_DIRECTORY,
        LOCKS_DIRECTORY,
    ] {
        secure_child_directory(&generation_root, name)?;
    }
    Ok(())
}

/// A non-cloneable live role fence. The lock is declared last so every other
/// field is released before ownership transfers.
pub struct RouteRoleOwner {
    local_root: PathBuf,
    role: RouteEndpointRole,
    route_definition_digest: ContentDigest,
    route_root: PathBuf,
    _lock: File,
}

impl RouteRoleOwner {
    pub fn role(&self) -> RouteEndpointRole {
        self.role
    }
}

fn expected_delivery_snapshot(
    issued: &IssuedManifest,
    route: &RouteDefinition,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, M6IdentityError> {
    issued.manifest.verify_route(route)?;
    let manifest_bytes = issued.manifest.canonical_bytes()?;
    if manifest_bytes.len() > route.resource_profile.max_manifest_bytes as usize {
        return Err(M6IdentityError::ResourceExhausted(
            "manifest exceeds route byte budget".to_string(),
        ));
    }
    let mut expected_digests = BTreeSet::new();
    let mut snapshot = BTreeMap::new();
    snapshot.insert(PathBuf::from(MANIFEST_FILE), manifest_bytes.clone());
    for descriptor in &issued.manifest.unsigned.attachments {
        descriptor.validate(&route.resource_profile)?;
        let bytes = issued
            .attachments
            .get(&descriptor.content_digest)
            .ok_or_else(|| {
                M6IdentityError::InvalidConfiguration(format!(
                    "manifest attachment '{}' has no supplied bytes",
                    descriptor.logical_name
                ))
            })?;
        if bytes.len() as u64 != descriptor.byte_length {
            return Err(M6IdentityError::DigestMismatch {
                subject: format!("attachment '{}' length", descriptor.logical_name),
                expected: ContentDigest::from_bytes(&descriptor.byte_length.to_be_bytes()),
                actual: ContentDigest::from_bytes(&(bytes.len() as u64).to_be_bytes()),
            });
        }
        require_digest(
            &format!("attachment '{}'", descriptor.logical_name),
            &descriptor.content_digest,
            &ContentDigest::from_bytes(bytes),
        )?;
        expected_digests.insert(descriptor.content_digest.clone());
        snapshot.insert(
            attachment_relative_path(&descriptor.content_digest),
            bytes.clone(),
        );
    }
    if expected_digests.len() != issued.attachments.len()
        || issued
            .attachments
            .keys()
            .any(|digest| !expected_digests.contains(digest))
    {
        return Err(M6IdentityError::InvalidConfiguration(
            "supplied attachment set differs from the signed manifest".to_string(),
        ));
    }
    let commit = DeliveryCommitMarker {
        manifest_bytes_digest: ContentDigest::from_bytes(&manifest_bytes),
        message_digest: issued.manifest.message_digest.clone(),
        schema: DELIVERY_COMMIT_SCHEMA.to_string(),
    };
    snapshot.insert(
        PathBuf::from(DELIVERY_COMMIT_FILE),
        canonical_json(&commit)?,
    );
    enforce_snapshot_bounds(&snapshot, &route.resource_profile)?;
    Ok(snapshot)
}

fn validate_delivery_snapshot(
    snapshot: &BTreeMap<PathBuf, Vec<u8>>,
    route: &RouteDefinition,
) -> Result<SignedManifest, M6IdentityError> {
    enforce_snapshot_bounds(snapshot, &route.resource_profile)?;
    let manifest_bytes = snapshot.get(Path::new(MANIFEST_FILE)).ok_or_else(|| {
        M6IdentityError::StateIntegrity("delivery unit has no manifest".to_string())
    })?;
    let manifest = SignedManifest::from_canonical_bytes(manifest_bytes)?;
    manifest.verify_route(route)?;
    let commit: DeliveryCommitMarker = parse_canonical(
        snapshot
            .get(Path::new(DELIVERY_COMMIT_FILE))
            .ok_or_else(|| {
                M6IdentityError::StateIntegrity(
                    "delivery unit has no durable commit marker".to_string(),
                )
            })?,
    )?;
    if commit.schema != DELIVERY_COMMIT_SCHEMA
        || commit.message_digest != manifest.message_digest
        || commit.manifest_bytes_digest != ContentDigest::from_bytes(manifest_bytes)
    {
        return Err(M6IdentityError::StateIntegrity(
            "delivery commit marker differs from its exact manifest".to_string(),
        ));
    }
    let expected = manifest
        .unsigned
        .attachments
        .iter()
        .map(|descriptor| {
            (
                attachment_relative_path(&descriptor.content_digest),
                descriptor,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let actual_attachment_paths = snapshot
        .keys()
        .filter(|path| path.starts_with(ATTACHMENTS_DIRECTORY))
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_attachment_paths = expected.keys().cloned().collect::<BTreeSet<_>>();
    if actual_attachment_paths != expected_attachment_paths {
        return Err(M6IdentityError::StateIntegrity(
            "delivery attachment filenames differ from the manifest".to_string(),
        ));
    }
    if snapshot.len() != expected.len() + 2 {
        return Err(M6IdentityError::StateIntegrity(
            "delivery unit contains undeclared files".to_string(),
        ));
    }
    for (path, descriptor) in expected {
        descriptor.validate(&route.resource_profile)?;
        let bytes = snapshot.get(&path).ok_or_else(|| {
            M6IdentityError::StateIntegrity(format!(
                "delivery unit lacks attachment '{}'",
                descriptor.logical_name
            ))
        })?;
        if bytes.len() as u64 != descriptor.byte_length {
            return Err(M6IdentityError::StateIntegrity(format!(
                "delivery attachment '{}' length changed",
                descriptor.logical_name
            )));
        }
        require_digest(
            &format!("delivery attachment '{}'", descriptor.logical_name),
            &descriptor.content_digest,
            &ContentDigest::from_bytes(bytes),
        )?;
    }
    Ok(manifest)
}

fn attachment_relative_path(digest: &ContentDigest) -> PathBuf {
    PathBuf::from(ATTACHMENTS_DIRECTORY).join(format!("{}.blob", digest.file_stem()))
}

fn delivery_unit_name(message_digest: &ContentDigest) -> String {
    format!("{}.unit", message_digest.file_stem())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawFileObservation {
    pub byte_length: u64,
    pub content_digest: ContentDigest,
    pub relative_path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawAdmissionEntryKind {
    Directory,
    RegularFile,
    Symlink,
    Other,
}

/// Bounded metadata observed while deciding whether a physical route unit may
/// enter raw quarantine.
///
/// A content digest is present only when the complete regular file was read
/// under the route hard caps and its pre-open, opened, post-read, and final
/// path metadata remained stable. These observations are explicitly not a
/// complete-input identity and cannot be converted into a quarantined unit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAdmissionObservation {
    pub content_digest: Option<ContentDigest>,
    pub entry_kind: RawAdmissionEntryKind,
    pub lstat_byte_length: u64,
    pub opened_byte_length: Option<u64>,
    pub post_read_byte_length: Option<u64>,
    pub relative_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawAdmissionViolation {
    Symlink {
        relative_path: String,
    },
    NonRegular {
        entry_kind: RawAdmissionEntryKind,
        relative_path: String,
    },
    EntryCountExceeded {
        maximum_entries: u32,
        minimum_observed_entries: u32,
    },
    PerFileBytesExceeded {
        maximum_bytes: u64,
        observed_bytes: u64,
        relative_path: String,
    },
    AggregateBytesExceeded {
        maximum_bytes: u64,
        observed_bytes: u64,
    },
    ChangedDuringRead {
        relative_path: String,
    },
    UnsafePath {
        path_hint: String,
    },
}

/// Immutable receiver-local evidence that a physical route unit failed the
/// hard, pre-interpretation admission boundary.
///
/// This capsule intentionally has no raw-unit digest: no partial prefix is
/// represented as the complete attacker-controlled input. `observations` is a
/// bounded forensic set, and `observations_complete` says whether enumeration
/// completed before the hard violation was found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAdmissionRejected {
    pub intake_operation_id: String,
    pub observations: Vec<RawAdmissionObservation>,
    pub observations_complete: bool,
    pub observations_digest: ContentDigest,
    pub record_digest: ContentDigest,
    pub rejected_at_ms: u64,
    pub route_definition_digest: ContentDigest,
    pub route_entry_name: String,
    pub schema: String,
    pub violation: RawAdmissionViolation,
}

impl RawAdmissionRejected {
    pub fn validate(&self, route: &RouteDefinition) -> Result<(), M6IdentityError> {
        if self.schema != RAW_ADMISSION_REJECTION_SCHEMA {
            return Err(M6IdentityError::UnsupportedSchema(self.schema.clone()));
        }
        route.validate()?;
        require_digest(
            "raw admission rejection route",
            &route.definition_digest,
            &self.route_definition_digest,
        )?;
        validate_identifier("raw intake operation id", &self.intake_operation_id)?;
        validate_unit_entry_name(&self.route_entry_name)?;
        let maximum_observations = raw_admission_entry_limit(&route.resource_profile)
            .checked_add(1)
            .ok_or_else(|| {
                M6IdentityError::ResourceExhausted(
                    "raw admission observation bound overflowed".to_string(),
                )
            })? as usize;
        if self.observations.len() > maximum_observations
            || !is_strictly_sorted_unique_by(&self.observations, |entry| {
                entry.relative_path.clone()
            })
        {
            return Err(M6IdentityError::StateIntegrity(
                "raw admission observations exceed their bound or are not sorted and unique"
                    .to_string(),
            ));
        }
        for observation in &self.observations {
            validate_portable_relative_string(&observation.relative_path)?;
            match observation.entry_kind {
                RawAdmissionEntryKind::RegularFile => {}
                _ if observation.content_digest.is_some()
                    || observation.opened_byte_length.is_some()
                    || observation.post_read_byte_length.is_some() =>
                {
                    return Err(M6IdentityError::StateIntegrity(
                        "non-file raw admission observation claims opened file evidence"
                            .to_string(),
                    ));
                }
                _ => {}
            }
            if observation.content_digest.is_some()
                && (observation.opened_byte_length != Some(observation.lstat_byte_length)
                    || observation.post_read_byte_length != Some(observation.lstat_byte_length))
            {
                return Err(M6IdentityError::StateIntegrity(
                    "raw admission digest is not backed by stable lengths".to_string(),
                ));
            }
        }
        validate_raw_admission_violation(
            &self.violation,
            &route.resource_profile,
            self.observations_complete,
        )?;
        require_digest(
            "raw admission observations",
            &self.observations_digest,
            &raw_admission_observations_digest(&self.observations, self.observations_complete)?,
        )?;
        require_digest(
            "raw admission rejection",
            &self.record_digest,
            &raw_admission_rejection_digest(self)?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawAdmissionOutcome {
    Quarantined(RawQuarantineRecord),
    Rejected(RawAdmissionRejected),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawQuarantineRecord {
    pub files: Vec<RawFileObservation>,
    pub intake_operation_id: String,
    pub observed_at_ms: u64,
    pub raw_unit_digest: ContentDigest,
    pub record_digest: ContentDigest,
    pub route_definition_digest: ContentDigest,
    pub route_entry_name: String,
    pub schema: String,
    pub total_bytes: u64,
}

impl RawQuarantineRecord {
    pub fn canonical_bytes(&self, route: &RouteDefinition) -> Result<Vec<u8>, M6IdentityError> {
        self.validate(route)?;
        canonical_json(self)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        route: &RouteDefinition,
    ) -> Result<Self, M6IdentityError> {
        let record: Self = parse_canonical(bytes)?;
        record.validate(route)?;
        Ok(record)
    }

    pub fn validate(&self, route: &RouteDefinition) -> Result<(), M6IdentityError> {
        if self.schema != RAW_QUARANTINE_SCHEMA
            || self.route_definition_digest != route.definition_digest
            || self.files.is_empty()
            || !is_strictly_sorted_unique_by(&self.files, |file| file.relative_path.clone())
            || self.total_bytes != self.files.iter().map(|file| file.byte_length).sum::<u64>()
        {
            return Err(M6IdentityError::StateIntegrity(
                "raw quarantine record is outside its exact schema".to_string(),
            ));
        }
        validate_identifier("raw intake operation id", &self.intake_operation_id)?;
        validate_unit_entry_name(&self.route_entry_name)?;
        require_digest(
            "raw quarantine unit",
            &self.raw_unit_digest,
            &raw_unit_digest(&self.files)?,
        )?;
        require_digest(
            "raw quarantine record",
            &self.record_digest,
            &raw_record_digest(self)?,
        )
    }
}

/// Opaque, revalidated view of one complete receiver-owned raw quarantine unit.
///
/// Callers cannot construct this value. The only constructor reopens the
/// committed quarantine directory, re-derives every file observation and the
/// aggregate raw-unit identity, and matches them to the immutable record.
/// This prevents downstream verification from accepting a caller-assembled
/// map that merely looks like quarantined input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedRawQuarantineUnit {
    files: BTreeMap<String, Vec<u8>>,
    record: RawQuarantineRecord,
}

impl CommittedRawQuarantineUnit {
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    pub fn record(&self) -> &RawQuarantineRecord {
        &self.record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRejectionRecord {
    pub raw_unit_digest: ContentDigest,
    pub reason: String,
    pub record_digest: ContentDigest,
    pub rejected_at_ms: u64,
    pub schema: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RawAdmissionMetadataFingerprint {
    byte_length: u64,
    entry_kind: RawAdmissionEntryKind,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
}

#[derive(Clone, Debug)]
struct RawAdmissionCandidate {
    absolute_path: PathBuf,
    before: RawAdmissionMetadataFingerprint,
    observation_index: usize,
    relative_path: String,
}

#[derive(Clone, Debug)]
struct RawAdmissionDirectoryCandidate {
    absolute_path: PathBuf,
    before: RawAdmissionMetadataFingerprint,
    relative_path: String,
}

enum RawAdmissionScanOutcome {
    Admitted {
        files: BTreeMap<PathBuf, Vec<u8>>,
        observations: Vec<RawAdmissionObservation>,
    },
    Rejected {
        observations: Vec<RawAdmissionObservation>,
        observations_complete: bool,
        violation: RawAdmissionViolation,
    },
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawAdmissionTestPoint {
    AfterOpen,
    AfterRead,
}

pub struct ReceiverRawQuarantine {
    clock: Arc<dyn Clock>,
    quarantine_root: PathBuf,
    rejection_root: PathBuf,
    receiver_root: PathBuf,
    route: RouteDefinition,
    #[cfg(test)]
    admission_read_hook: Option<Arc<dyn Fn(&Path, RawAdmissionTestPoint) + Send + Sync>>,
}

impl ReceiverRawQuarantine {
    pub fn open_or_initialize(
        receiver_root: impl AsRef<Path>,
        route: RouteDefinition,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, M6IdentityError> {
        route.validate()?;
        let receiver_root = prepare_root(receiver_root.as_ref(), false)?;
        let base = secure_child_directory(&receiver_root, QUARANTINE_DIRECTORY)?;
        let quarantine_root = secure_child_directory(&base, &route.definition_digest.file_stem())?;
        let rejection_root =
            secure_child_directory(&quarantine_root, RAW_ADMISSION_REJECTIONS_DIRECTORY)?;
        Ok(Self {
            clock,
            quarantine_root,
            rejection_root,
            receiver_root,
            route,
            #[cfg(test)]
            admission_read_hook: None,
        })
    }

    /// Apply the hard pre-interpretation admission boundary to one immutable
    /// route entry.
    ///
    /// No manifest, signature, attachment descriptor, or payload is decoded by
    /// this operation. A fully admitted byte set is atomically committed to
    /// receiver-local raw quarantine; a hard violation atomically commits a
    /// bounded [`RawAdmissionRejected`] capsule instead.
    pub fn admit_ready(
        &self,
        spool: &GovernedFilesystemSpool,
        owner: &RouteRoleOwner,
        message_digest: &ContentDigest,
        intake_operation_id: &str,
    ) -> Result<RawAdmissionOutcome, M6IdentityError> {
        validate_identifier("intake operation id", intake_operation_id)?;
        spool.require_owner(owner)?;
        if spool.role != RouteEndpointRole::Receiver {
            return Err(M6IdentityError::WrongRole {
                expected: RouteEndpointRole::Receiver,
                actual: spool.role,
            });
        }
        if self.receiver_root != spool.local_root
            || self.route.definition_digest != spool.route.definition_digest
        {
            return Err(M6IdentityError::StateIntegrity(
                "raw quarantine and spool belong to different receiver or route".to_string(),
            ));
        }
        if let Some(rejected) = self.admission_rejection(intake_operation_id)? {
            return Ok(RawAdmissionOutcome::Rejected(rejected));
        }

        let source = spool.inbound_ready_unit_directory(message_digest);
        let route_entry_name = source
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| M6IdentityError::UnsafePath(source.clone()))?
            .to_string();
        validate_unit_entry_name(&route_entry_name)?;
        match self.scan_raw_route_unit(&source, &route_entry_name)? {
            RawAdmissionScanOutcome::Admitted {
                files,
                observations,
            } => {
                let record = self.commit_raw_quarantine(
                    files,
                    observations,
                    intake_operation_id,
                    route_entry_name,
                )?;
                Ok(RawAdmissionOutcome::Quarantined(record))
            }
            RawAdmissionScanOutcome::Rejected {
                observations,
                observations_complete,
                violation,
            } => {
                let rejected = self.persist_admission_rejection(
                    intake_operation_id,
                    route_entry_name,
                    observations,
                    observations_complete,
                    violation,
                )?;
                Ok(RawAdmissionOutcome::Rejected(rejected))
            }
        }
    }

    pub fn quarantine_ready(
        &self,
        spool: &GovernedFilesystemSpool,
        owner: &RouteRoleOwner,
        message_digest: &ContentDigest,
        intake_operation_id: &str,
    ) -> Result<RawQuarantineRecord, M6IdentityError> {
        match self.admit_ready(spool, owner, message_digest, intake_operation_id)? {
            RawAdmissionOutcome::Quarantined(record) => Ok(record),
            RawAdmissionOutcome::Rejected(rejected) => Err(M6IdentityError::AdmissionRejected {
                rejection_digest: rejected.record_digest,
                violation: rejected.violation,
            }),
        }
    }

    /// Resolve an already committed raw quarantine unit by the coordinator's
    /// stable intake operation identity.
    ///
    /// This recovery lookup is read-only: it does not inspect the route entry,
    /// observe the clock, or create new quarantine evidence.
    pub fn committed_for_intake(
        &self,
        intake_operation_id: &str,
    ) -> Result<Option<RawQuarantineRecord>, M6IdentityError> {
        validate_identifier("intake operation id", intake_operation_id)?;
        let mut committed_count = 0_usize;
        let mut staging_count = 0_usize;
        let mut found = None;
        for entry in fs::read_dir(&self.quarantine_root)
            .map_err(|source| M6IdentityError::io(&self.quarantine_root, source))?
        {
            let entry =
                entry.map_err(|source| M6IdentityError::io(&self.quarantine_root, source))?;
            let path = entry.path();
            reject_symlink(&path)?;
            let name = entry
                .file_name()
                .to_str()
                .ok_or_else(|| M6IdentityError::UnsafePath(path.clone()))?
                .to_string();
            let file_type = entry
                .file_type()
                .map_err(|source| M6IdentityError::io(&path, source))?;
            if path == self.rejection_root {
                if !file_type.is_dir() {
                    return Err(M6IdentityError::UnsafePath(path));
                }
                continue;
            }
            if name.starts_with(RAW_QUARANTINE_STAGING_PREFIX) {
                if !file_type.is_dir() {
                    return Err(M6IdentityError::UnsafePath(path));
                }
                staging_count += 1;
                if staging_count > 1 {
                    return Err(M6IdentityError::StateIntegrity(
                        "raw quarantine contains ambiguous incomplete staging".to_string(),
                    ));
                }
                continue;
            }
            if !file_type.is_dir() || !name.ends_with(".raw") {
                return Err(M6IdentityError::UnsafePath(path));
            }
            committed_count += 1;
            if committed_count > self.route.resource_profile.max_quarantine_units as usize {
                return Err(M6IdentityError::ResourceExhausted(
                    "raw quarantine exceeds its route unit budget".to_string(),
                ));
            }
            let record: RawQuarantineRecord = parse_canonical(&read_bounded(
                &path.join(RAW_RECORD_FILE),
                self.route.resource_profile.max_manifest_bytes as usize,
            )?)?;
            record.validate(&self.route)?;
            if path != self.raw_unit_path(&record.raw_unit_digest) {
                return Err(M6IdentityError::StateIntegrity(
                    "committed raw quarantine record is stored under the wrong unit identity"
                        .to_string(),
                ));
            }
            if record.intake_operation_id == intake_operation_id {
                let retained = self.read_committed_unit(&record)?.record;
                if found.replace(retained).is_some() {
                    return Err(M6IdentityError::StateIntegrity(format!(
                        "multiple committed raw quarantine units claim intake operation '{intake_operation_id}'"
                    )));
                }
            }
        }
        if found.is_some() && self.admission_rejection(intake_operation_id)?.is_some() {
            return Err(M6IdentityError::StateIntegrity(format!(
                "intake operation '{intake_operation_id}' has both admitted and rejected terminal evidence"
            )));
        }
        Ok(found)
    }

    fn commit_raw_quarantine(
        &self,
        snapshot: BTreeMap<PathBuf, Vec<u8>>,
        observations: Vec<RawAdmissionObservation>,
        intake_operation_id: &str,
        route_entry_name: String,
    ) -> Result<RawQuarantineRecord, M6IdentityError> {
        enforce_unit_count(
            &self.quarantine_root,
            self.route.resource_profile.max_quarantine_units,
            "raw quarantine units",
        )?;
        let files = observations
            .into_iter()
            .filter(|observation| observation.entry_kind == RawAdmissionEntryKind::RegularFile)
            .map(|observation| {
                Ok(RawFileObservation {
                    byte_length: observation.lstat_byte_length,
                    content_digest: observation.content_digest.ok_or_else(|| {
                        M6IdentityError::StateIntegrity(
                            "admitted file has no complete content digest".to_string(),
                        )
                    })?,
                    relative_path: observation.relative_path,
                })
            })
            .collect::<Result<Vec<_>, M6IdentityError>>()?;
        let total_bytes = files.iter().map(|file| file.byte_length).sum();
        let raw_digest = raw_unit_digest(&files)?;
        let observed_at_ms = self.clock.now_ms()?;
        let mut record = RawQuarantineRecord {
            files,
            intake_operation_id: intake_operation_id.to_string(),
            observed_at_ms,
            raw_unit_digest: raw_digest.clone(),
            record_digest: ContentDigest::from_bytes(&[]),
            route_definition_digest: self.route.definition_digest.clone(),
            route_entry_name,
            schema: RAW_QUARANTINE_SCHEMA.to_string(),
            total_bytes,
        };
        record.record_digest = raw_record_digest(&record)?;
        record.validate(&self.route)?;
        let final_path = self.raw_unit_path(&raw_digest);
        let desired = raw_quarantine_snapshot(&snapshot, &record)?;
        if final_path.exists() {
            require_snapshot_matches(&final_path, &desired, &self.route.resource_profile)?;
            return Ok(record);
        }
        let staging = self.quarantine_root.join(format!(
            "{RAW_QUARANTINE_STAGING_PREFIX}{}-{}-{}",
            ContentDigest::from_bytes(intake_operation_id.as_bytes()).file_stem(),
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            write_snapshot_directory(&staging, &desired)?;
            fs::rename(&staging, &final_path)
                .map_err(|source| M6IdentityError::io(&final_path, source))?;
            sync_directory(&self.quarantine_root)
        })();
        if result.is_err() && staging.exists() {
            let _ = remove_confined_directory(&self.quarantine_root, &staging);
        }
        result?;
        Ok(record)
    }

    pub fn admission_rejection(
        &self,
        intake_operation_id: &str,
    ) -> Result<Option<RawAdmissionRejected>, M6IdentityError> {
        validate_identifier("intake operation id", intake_operation_id)?;
        let path = self.raw_admission_rejection_path(intake_operation_id);
        if !path.exists() {
            return Ok(None);
        }
        let record: RawAdmissionRejected = parse_canonical(&read_bounded(
            &path,
            self.route.resource_profile.max_manifest_bytes as usize,
        )?)?;
        record.validate(&self.route)?;
        if record.intake_operation_id != intake_operation_id {
            return Err(M6IdentityError::StateIntegrity(
                "raw admission rejection is cross-linked to another intake operation".to_string(),
            ));
        }
        Ok(Some(record))
    }

    fn scan_raw_route_unit(
        &self,
        source: &Path,
        route_entry_name: &str,
    ) -> Result<RawAdmissionScanOutcome, M6IdentityError> {
        let root_metadata = match fs::symlink_metadata(source) {
            Ok(metadata) => metadata,
            Err(source_error) => {
                return Err(M6IdentityError::io(source, source_error));
            }
        };
        let root_fingerprint = raw_admission_metadata_fingerprint(&root_metadata);
        if root_fingerprint.entry_kind == RawAdmissionEntryKind::Symlink {
            return Ok(RawAdmissionScanOutcome::Rejected {
                observations: Vec::new(),
                observations_complete: false,
                violation: RawAdmissionViolation::Symlink {
                    relative_path: route_entry_name.to_string(),
                },
            });
        }
        if root_fingerprint.entry_kind != RawAdmissionEntryKind::Directory {
            return Ok(RawAdmissionScanOutcome::Rejected {
                observations: Vec::new(),
                observations_complete: false,
                violation: RawAdmissionViolation::NonRegular {
                    entry_kind: root_fingerprint.entry_kind,
                    relative_path: route_entry_name.to_string(),
                },
            });
        }

        let mut candidates = Vec::new();
        let mut directories = Vec::new();
        let mut observations = Vec::new();
        if let Some(violation) = enumerate_raw_admission_entries(
            source,
            source,
            &self.route.resource_profile,
            &mut candidates,
            &mut directories,
            &mut observations,
            0,
        )? {
            observations.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
            return Ok(RawAdmissionScanOutcome::Rejected {
                observations,
                observations_complete: false,
                violation,
            });
        }
        observations.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        candidates.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        if candidates.is_empty() {
            return Ok(RawAdmissionScanOutcome::Rejected {
                observations,
                observations_complete: true,
                violation: RawAdmissionViolation::UnsafePath {
                    path_hint: "route-unit-has-no-regular-files".to_string(),
                },
            });
        }
        for candidate in &mut candidates {
            candidate.observation_index = observations
                .binary_search_by(|observation| {
                    observation.relative_path.cmp(&candidate.relative_path)
                })
                .map_err(|_| {
                    M6IdentityError::StateIntegrity(
                        "raw admission candidate has no metadata observation".to_string(),
                    )
                })?;
            if observations[candidate.observation_index].entry_kind
                != RawAdmissionEntryKind::RegularFile
            {
                return Err(M6IdentityError::StateIntegrity(
                    "raw admission file candidate is cross-linked".to_string(),
                ));
            }
        }

        for candidate in &candidates {
            let maximum_bytes =
                raw_admission_file_limit(&candidate.relative_path, &self.route.resource_profile)?;
            if candidate.before.byte_length > maximum_bytes {
                return Ok(RawAdmissionScanOutcome::Rejected {
                    observations,
                    observations_complete: true,
                    violation: RawAdmissionViolation::PerFileBytesExceeded {
                        maximum_bytes,
                        observed_bytes: candidate.before.byte_length,
                        relative_path: candidate.relative_path.clone(),
                    },
                });
            }
        }
        let observed_bytes = candidates.iter().try_fold(0_u64, |total, candidate| {
            total
                .checked_add(candidate.before.byte_length)
                .ok_or_else(|| {
                    M6IdentityError::ResourceExhausted(
                        "raw admission aggregate metadata length overflowed".to_string(),
                    )
                })
        })?;
        let maximum_bytes = raw_admission_aggregate_limit(&self.route.resource_profile);
        if observed_bytes > maximum_bytes {
            return Ok(RawAdmissionScanOutcome::Rejected {
                observations,
                observations_complete: true,
                violation: RawAdmissionViolation::AggregateBytesExceeded {
                    maximum_bytes,
                    observed_bytes,
                },
            });
        }

        let mut snapshot = BTreeMap::new();
        for candidate in &candidates {
            let current = match fs::symlink_metadata(&candidate.absolute_path) {
                Ok(metadata) => raw_admission_metadata_fingerprint(&metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(raw_admission_changed(
                        observations,
                        &candidate.relative_path,
                    ));
                }
                Err(source_error) => {
                    return Err(M6IdentityError::io(&candidate.absolute_path, source_error));
                }
            };
            if current != candidate.before
                || current.entry_kind != RawAdmissionEntryKind::RegularFile
            {
                return Ok(raw_admission_changed(
                    observations,
                    &candidate.relative_path,
                ));
            }
            let mut file = match File::open(&candidate.absolute_path) {
                Ok(file) => file,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::IsADirectory
                    ) =>
                {
                    return Ok(raw_admission_changed(
                        observations,
                        &candidate.relative_path,
                    ));
                }
                Err(source_error) => {
                    return Err(M6IdentityError::io(&candidate.absolute_path, source_error));
                }
            };
            let opened =
                raw_admission_metadata_fingerprint(&file.metadata().map_err(|source_error| {
                    M6IdentityError::io(&candidate.absolute_path, source_error)
                })?);
            observations[candidate.observation_index].opened_byte_length = Some(opened.byte_length);
            if opened != candidate.before || opened.entry_kind != RawAdmissionEntryKind::RegularFile
            {
                return Ok(raw_admission_changed(
                    observations,
                    &candidate.relative_path,
                ));
            }
            #[cfg(test)]
            if let Some(hook) = &self.admission_read_hook {
                hook(&candidate.absolute_path, RawAdmissionTestPoint::AfterOpen);
            }
            let maximum_file_bytes =
                raw_admission_file_limit(&candidate.relative_path, &self.route.resource_profile)?;
            let mut bytes = Vec::with_capacity(opened.byte_length as usize);
            (&mut file)
                .take(maximum_file_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|source_error| {
                    M6IdentityError::io(&candidate.absolute_path, source_error)
                })?;
            #[cfg(test)]
            if let Some(hook) = &self.admission_read_hook {
                hook(&candidate.absolute_path, RawAdmissionTestPoint::AfterRead);
            }
            let post_open =
                raw_admission_metadata_fingerprint(&file.metadata().map_err(|source_error| {
                    M6IdentityError::io(&candidate.absolute_path, source_error)
                })?);
            observations[candidate.observation_index].post_read_byte_length =
                Some(post_open.byte_length);
            let post_path = match fs::symlink_metadata(&candidate.absolute_path) {
                Ok(metadata) => raw_admission_metadata_fingerprint(&metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(raw_admission_changed(
                        observations,
                        &candidate.relative_path,
                    ));
                }
                Err(source_error) => {
                    return Err(M6IdentityError::io(&candidate.absolute_path, source_error));
                }
            };
            if post_open != candidate.before
                || post_path != candidate.before
                || u64::try_from(bytes.len()).ok() != Some(candidate.before.byte_length)
            {
                return Ok(raw_admission_changed(
                    observations,
                    &candidate.relative_path,
                ));
            }
            observations[candidate.observation_index].content_digest =
                Some(ContentDigest::from_bytes(&bytes));
            let relative = PathBuf::from(&candidate.relative_path);
            if snapshot.insert(relative, bytes).is_some() {
                return Err(M6IdentityError::StateIntegrity(
                    "raw admission produced a duplicate file snapshot".to_string(),
                ));
            }
        }

        let final_root = match fs::symlink_metadata(source) {
            Ok(metadata) => raw_admission_metadata_fingerprint(&metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(raw_admission_changed(observations, route_entry_name));
            }
            Err(source_error) => {
                return Err(M6IdentityError::io(source, source_error));
            }
        };
        if final_root != root_fingerprint {
            return Ok(raw_admission_changed(observations, route_entry_name));
        }
        for directory in directories {
            let final_metadata = match fs::symlink_metadata(&directory.absolute_path) {
                Ok(metadata) => raw_admission_metadata_fingerprint(&metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(raw_admission_changed(
                        observations,
                        &directory.relative_path,
                    ));
                }
                Err(source_error) => {
                    return Err(M6IdentityError::io(&directory.absolute_path, source_error));
                }
            };
            if final_metadata != directory.before {
                return Ok(raw_admission_changed(
                    observations,
                    &directory.relative_path,
                ));
            }
        }
        Ok(RawAdmissionScanOutcome::Admitted {
            files: snapshot,
            observations,
        })
    }

    fn persist_admission_rejection(
        &self,
        intake_operation_id: &str,
        route_entry_name: String,
        mut observations: Vec<RawAdmissionObservation>,
        observations_complete: bool,
        violation: RawAdmissionViolation,
    ) -> Result<RawAdmissionRejected, M6IdentityError> {
        if let Some(existing) = self.admission_rejection(intake_operation_id)? {
            return Ok(existing);
        }
        enforce_file_count(
            &self.rejection_root,
            self.route.resource_profile.max_quarantine_units,
            RAW_ADMISSION_REJECTION_SUFFIX,
            "raw admission rejections",
        )?;
        observations.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        let observations_digest =
            raw_admission_observations_digest(&observations, observations_complete)?;
        let mut rejected = RawAdmissionRejected {
            intake_operation_id: intake_operation_id.to_string(),
            observations,
            observations_complete,
            observations_digest,
            record_digest: ContentDigest::from_bytes(&[]),
            rejected_at_ms: self.clock.now_ms()?,
            route_definition_digest: self.route.definition_digest.clone(),
            route_entry_name,
            schema: RAW_ADMISSION_REJECTION_SCHEMA.to_string(),
            violation,
        };
        rejected.record_digest = raw_admission_rejection_digest(&rejected)?;
        rejected.validate(&self.route)?;
        let bytes = canonical_json(&rejected)?;
        if bytes.len() > RAW_ADMISSION_REJECTION_MAX_BYTES {
            return Err(M6IdentityError::ResourceExhausted(
                "raw admission rejection exceeds its absolute evidence bound".to_string(),
            ));
        }
        persist_immutable(
            &self.raw_admission_rejection_path(intake_operation_id),
            &bytes,
        )?;
        Ok(rejected)
    }

    /// Quarantine and durably commit every admitted raw byte before attempting
    /// canonical manifest decoding. Malformed input receives a durable
    /// rejection record referencing the exact raw unit.
    pub fn quarantine_then_parse(
        &self,
        spool: &GovernedFilesystemSpool,
        owner: &RouteRoleOwner,
        message_digest: &ContentDigest,
        intake_operation_id: &str,
    ) -> Result<(RawQuarantineRecord, SignedManifest), M6IdentityError> {
        let record = self.quarantine_ready(spool, owner, message_digest, intake_operation_id)?;
        match self.parse_quarantined_manifest(&record) {
            Ok(manifest) => Ok((record, manifest)),
            Err(error) => {
                let reason = error.to_string();
                self.persist_rejection(&record, &reason)?;
                Err(M6IdentityError::MalformedQuarantined {
                    raw_unit_digest: record.raw_unit_digest,
                    reason,
                })
            }
        }
    }

    pub fn parse_quarantined_manifest(
        &self,
        record: &RawQuarantineRecord,
    ) -> Result<SignedManifest, M6IdentityError> {
        record.validate(&self.route)?;
        let root = self.raw_unit_path(&record.raw_unit_digest);
        let retained: RawQuarantineRecord = parse_canonical(&read_bounded(
            &root.join(RAW_RECORD_FILE),
            self.route.resource_profile.max_manifest_bytes as usize,
        )?)?;
        if &retained != record {
            return Err(M6IdentityError::StateIntegrity(
                "supplied raw quarantine record differs from retained evidence".to_string(),
            ));
        }
        let bytes = read_bounded(
            &root.join(RAW_UNIT_DIRECTORY).join(MANIFEST_FILE),
            self.route.resource_profile.max_manifest_bytes as usize,
        )?;
        SignedManifest::from_canonical_bytes(&bytes)
    }

    pub fn raw_manifest_bytes(
        &self,
        raw_unit_digest: &ContentDigest,
    ) -> Result<Vec<u8>, M6IdentityError> {
        read_bounded(
            &self
                .raw_unit_path(raw_unit_digest)
                .join(RAW_UNIT_DIRECTORY)
                .join(MANIFEST_FILE),
            self.route.resource_profile.max_manifest_bytes as usize,
        )
    }

    /// Reopen a complete committed unit from receiver-owned quarantine.
    ///
    /// This is the only public path to [`CommittedRawQuarantineUnit`]. The
    /// returned bytes are read from the receiver store, never accepted from a
    /// caller, and remain non-executable until a separate proving boundary
    /// explicitly consumes them.
    pub fn read_committed_unit(
        &self,
        record: &RawQuarantineRecord,
    ) -> Result<CommittedRawQuarantineUnit, M6IdentityError> {
        record.validate(&self.route)?;
        let root = self.raw_unit_path(&record.raw_unit_digest);
        let retained: RawQuarantineRecord = parse_canonical(&read_bounded(
            &root.join(RAW_RECORD_FILE),
            self.route.resource_profile.max_manifest_bytes as usize,
        )?)?;
        retained.validate(&self.route)?;
        if &retained != record {
            return Err(M6IdentityError::StateIntegrity(
                "supplied raw quarantine record differs from retained evidence".to_string(),
            ));
        }
        let commit: (String, ContentDigest, ContentDigest) = parse_canonical(&read_bounded(
            &root.join(RAW_COMMIT_FILE),
            self.route.resource_profile.max_manifest_bytes as usize,
        )?)?;
        if commit
            != (
                "wasm-biotic.m6-raw-quarantine-commit.v1".to_string(),
                retained.raw_unit_digest.clone(),
                retained.record_digest.clone(),
            )
        {
            return Err(M6IdentityError::StateIntegrity(
                "committed raw quarantine marker is cross-linked".to_string(),
            ));
        }

        let snapshot =
            read_tree_snapshot(&root.join(RAW_UNIT_DIRECTORY), &self.route.resource_profile)?;
        let mut observations = Vec::with_capacity(snapshot.len());
        let mut files = BTreeMap::new();
        let mut total_bytes = 0_u64;
        for (path, bytes) in snapshot {
            let relative_path = portable_relative_path(&path)?;
            let byte_length = u64::try_from(bytes.len()).map_err(|_| {
                M6IdentityError::ResourceExhausted(
                    "committed raw quarantine file length overflowed".to_string(),
                )
            })?;
            total_bytes = total_bytes.checked_add(byte_length).ok_or_else(|| {
                M6IdentityError::ResourceExhausted(
                    "committed raw quarantine aggregate length overflowed".to_string(),
                )
            })?;
            observations.push(RawFileObservation {
                byte_length,
                content_digest: ContentDigest::from_bytes(&bytes),
                relative_path: relative_path.clone(),
            });
            if files.insert(relative_path, bytes).is_some() {
                return Err(M6IdentityError::StateIntegrity(
                    "committed raw quarantine contains a duplicate relative path".to_string(),
                ));
            }
        }
        observations.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        if observations != retained.files
            || total_bytes != retained.total_bytes
            || raw_unit_digest(&observations)? != retained.raw_unit_digest
        {
            return Err(M6IdentityError::StateIntegrity(
                "committed raw quarantine bytes differ from their immutable observations"
                    .to_string(),
            ));
        }
        Ok(CommittedRawQuarantineUnit {
            files,
            record: retained,
        })
    }

    pub fn rejection(
        &self,
        raw_unit_digest: &ContentDigest,
    ) -> Result<Option<RawRejectionRecord>, M6IdentityError> {
        let path = self.raw_unit_path(raw_unit_digest).join(RAW_REJECTION_FILE);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(parse_canonical(&read_bounded(
            &path,
            self.route.resource_profile.max_manifest_bytes as usize,
        )?)?))
    }

    fn persist_rejection(
        &self,
        record: &RawQuarantineRecord,
        reason: &str,
    ) -> Result<(), M6IdentityError> {
        let mut rejection = RawRejectionRecord {
            raw_unit_digest: record.raw_unit_digest.clone(),
            reason: reason.chars().take(4_096).collect(),
            record_digest: ContentDigest::from_bytes(&[]),
            rejected_at_ms: self.clock.now_ms()?,
            schema: RAW_REJECTION_SCHEMA.to_string(),
        };
        rejection.record_digest = digest_domain_serializable(
            b"wasm-biotic:m6:raw-rejection:v1\0",
            &(
                &rejection.raw_unit_digest,
                &rejection.reason,
                rejection.rejected_at_ms,
                &rejection.schema,
            ),
        )?;
        persist_immutable(
            &self
                .raw_unit_path(&record.raw_unit_digest)
                .join(RAW_REJECTION_FILE),
            &canonical_json(&rejection)?,
        )
    }

    fn raw_unit_path(&self, digest: &ContentDigest) -> PathBuf {
        self.quarantine_root
            .join(format!("{}.raw", digest.file_stem()))
    }

    fn raw_admission_rejection_path(&self, intake_operation_id: &str) -> PathBuf {
        let mut binding = Vec::from(b"wasm-biotic:m6:raw-admission-path:v1\0");
        binding.extend_from_slice(intake_operation_id.as_bytes());
        self.rejection_root.join(format!(
            "{}{}",
            ContentDigest::from_bytes(&binding).file_stem(),
            RAW_ADMISSION_REJECTION_SUFFIX
        ))
    }
}

fn raw_admission_metadata_fingerprint(metadata: &Metadata) -> RawAdmissionMetadataFingerprint {
    let file_type = metadata.file_type();
    let entry_kind = if file_type.is_symlink() {
        RawAdmissionEntryKind::Symlink
    } else if file_type.is_dir() {
        RawAdmissionEntryKind::Directory
    } else if file_type.is_file() {
        RawAdmissionEntryKind::RegularFile
    } else {
        RawAdmissionEntryKind::Other
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        RawAdmissionMetadataFingerprint {
            byte_length: metadata.len(),
            entry_kind,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        }
    }
    #[cfg(not(unix))]
    {
        RawAdmissionMetadataFingerprint {
            byte_length: metadata.len(),
            entry_kind,
        }
    }
}

fn enumerate_raw_admission_entries(
    root: &Path,
    current: &Path,
    profile: &RouteResourceProfile,
    candidates: &mut Vec<RawAdmissionCandidate>,
    directories: &mut Vec<RawAdmissionDirectoryCandidate>,
    observations: &mut Vec<RawAdmissionObservation>,
    depth: usize,
) -> Result<Option<RawAdmissionViolation>, M6IdentityError> {
    if depth > 1 {
        return Ok(Some(RawAdmissionViolation::UnsafePath {
            path_hint: raw_admission_unsafe_path_hint(current),
        }));
    }
    let mut entries = fs::read_dir(current)
        .map_err(|source| M6IdentityError::io(current, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| M6IdentityError::io(current, source))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let absolute_path = entry.path();
        let relative = match absolute_path.strip_prefix(root) {
            Ok(relative) => relative,
            Err(_) => {
                return Ok(Some(RawAdmissionViolation::UnsafePath {
                    path_hint: raw_admission_unsafe_path_hint(&absolute_path),
                }));
            }
        };
        let relative_path = match portable_relative_path(relative) {
            Ok(path) => path,
            Err(_) => {
                return Ok(Some(RawAdmissionViolation::UnsafePath {
                    path_hint: raw_admission_unsafe_path_hint(relative),
                }));
            }
        };
        let metadata = fs::symlink_metadata(&absolute_path)
            .map_err(|source| M6IdentityError::io(&absolute_path, source))?;
        let before = raw_admission_metadata_fingerprint(&metadata);
        observations.push(RawAdmissionObservation {
            content_digest: None,
            entry_kind: before.entry_kind,
            lstat_byte_length: before.byte_length,
            opened_byte_length: None,
            post_read_byte_length: None,
            relative_path: relative_path.clone(),
        });
        let maximum_entries = raw_admission_entry_limit(profile);
        if observations.len() > maximum_entries as usize {
            return Ok(Some(RawAdmissionViolation::EntryCountExceeded {
                maximum_entries,
                minimum_observed_entries: u32::try_from(observations.len()).unwrap_or(u32::MAX),
            }));
        }
        match before.entry_kind {
            RawAdmissionEntryKind::Symlink => {
                return Ok(Some(RawAdmissionViolation::Symlink { relative_path }));
            }
            RawAdmissionEntryKind::Other => {
                return Ok(Some(RawAdmissionViolation::NonRegular {
                    entry_kind: RawAdmissionEntryKind::Other,
                    relative_path,
                }));
            }
            RawAdmissionEntryKind::Directory => {
                if relative != Path::new(ATTACHMENTS_DIRECTORY) {
                    return Ok(Some(RawAdmissionViolation::NonRegular {
                        entry_kind: RawAdmissionEntryKind::Directory,
                        relative_path,
                    }));
                }
                directories.push(RawAdmissionDirectoryCandidate {
                    absolute_path: absolute_path.clone(),
                    before,
                    relative_path: relative_path.clone(),
                });
                if let Some(violation) = enumerate_raw_admission_entries(
                    root,
                    &absolute_path,
                    profile,
                    candidates,
                    directories,
                    observations,
                    depth + 1,
                )? {
                    return Ok(Some(violation));
                }
            }
            RawAdmissionEntryKind::RegularFile => {
                if !raw_admission_file_path_is_allowed(relative) {
                    return Ok(Some(RawAdmissionViolation::UnsafePath {
                        path_hint: relative_path,
                    }));
                }
                candidates.push(RawAdmissionCandidate {
                    absolute_path,
                    before,
                    observation_index: observations.len() - 1,
                    relative_path,
                });
            }
        }
    }
    Ok(None)
}

fn raw_admission_file_path_is_allowed(relative: &Path) -> bool {
    if relative == Path::new(MANIFEST_FILE) || relative == Path::new(DELIVERY_COMMIT_FILE) {
        return true;
    }
    let components = relative.components().collect::<Vec<_>>();
    components.len() == 2
        && components[0].as_os_str() == ATTACHMENTS_DIRECTORY
        && matches!(components[1], Component::Normal(_))
}

fn raw_admission_changed(
    observations: Vec<RawAdmissionObservation>,
    relative_path: &str,
) -> RawAdmissionScanOutcome {
    RawAdmissionScanOutcome::Rejected {
        observations,
        observations_complete: true,
        violation: RawAdmissionViolation::ChangedDuringRead {
            relative_path: relative_path.to_string(),
        },
    }
}

fn raw_admission_entry_limit(profile: &RouteResourceProfile) -> u32 {
    profile
        .max_attachment_count
        .saturating_add(3)
        .min(RAW_ADMISSION_ABSOLUTE_ENTRY_CAP)
}

fn raw_admission_file_limit(
    relative_path: &str,
    profile: &RouteResourceProfile,
) -> Result<u64, M6IdentityError> {
    validate_portable_relative_string(relative_path)?;
    let relative = Path::new(relative_path);
    let configured =
        if relative == Path::new(MANIFEST_FILE) || relative == Path::new(DELIVERY_COMMIT_FILE) {
            profile.max_manifest_bytes
        } else if raw_admission_file_path_is_allowed(relative) {
            profile.max_attachment_bytes
        } else {
            return Err(M6IdentityError::StateIntegrity(
                "raw admission file is outside the fixed route-unit shape".to_string(),
            ));
        };
    Ok(configured.min(RAW_ADMISSION_ABSOLUTE_BYTE_CAP))
}

fn raw_admission_aggregate_limit(profile: &RouteResourceProfile) -> u64 {
    profile
        .max_delivery_bytes
        .saturating_add(profile.max_manifest_bytes.saturating_mul(2))
        .min(RAW_ADMISSION_ABSOLUTE_BYTE_CAP)
}

fn raw_admission_unsafe_path_hint(path: &Path) -> String {
    let digest = ContentDigest::from_bytes(path.as_os_str().as_encoded_bytes());
    format!("opaque-path:{}", digest.file_stem())
}

fn validate_portable_relative_string(value: &str) -> Result<(), M6IdentityError> {
    let path = Path::new(value);
    validate_relative_path(path)?;
    if portable_relative_path(path)? != value {
        return Err(M6IdentityError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_raw_admission_violation(
    violation: &RawAdmissionViolation,
    profile: &RouteResourceProfile,
    observations_complete: bool,
) -> Result<(), M6IdentityError> {
    match violation {
        RawAdmissionViolation::Symlink { relative_path } => {
            validate_portable_relative_string(relative_path)?;
            if observations_complete {
                return Err(M6IdentityError::StateIntegrity(
                    "symlink rejection falsely claims complete enumeration".to_string(),
                ));
            }
        }
        RawAdmissionViolation::NonRegular {
            entry_kind,
            relative_path,
        } => {
            validate_portable_relative_string(relative_path)?;
            if *entry_kind == RawAdmissionEntryKind::RegularFile
                || *entry_kind == RawAdmissionEntryKind::Symlink
                || observations_complete
            {
                return Err(M6IdentityError::StateIntegrity(
                    "non-regular rejection has an incoherent type or completion claim".to_string(),
                ));
            }
        }
        RawAdmissionViolation::EntryCountExceeded {
            maximum_entries,
            minimum_observed_entries,
        } => {
            if *maximum_entries != raw_admission_entry_limit(profile)
                || minimum_observed_entries <= maximum_entries
                || observations_complete
            {
                return Err(M6IdentityError::StateIntegrity(
                    "raw admission entry-count rejection is incoherent".to_string(),
                ));
            }
        }
        RawAdmissionViolation::PerFileBytesExceeded {
            maximum_bytes,
            observed_bytes,
            relative_path,
        } => {
            if *maximum_bytes != raw_admission_file_limit(relative_path, profile)?
                || observed_bytes <= maximum_bytes
                || !observations_complete
            {
                return Err(M6IdentityError::StateIntegrity(
                    "raw admission per-file rejection is incoherent".to_string(),
                ));
            }
        }
        RawAdmissionViolation::AggregateBytesExceeded {
            maximum_bytes,
            observed_bytes,
        } => {
            if *maximum_bytes != raw_admission_aggregate_limit(profile)
                || observed_bytes <= maximum_bytes
                || !observations_complete
            {
                return Err(M6IdentityError::StateIntegrity(
                    "raw admission aggregate rejection is incoherent".to_string(),
                ));
            }
        }
        RawAdmissionViolation::ChangedDuringRead { relative_path } => {
            validate_portable_relative_string(relative_path)?;
            if !observations_complete {
                return Err(M6IdentityError::StateIntegrity(
                    "change-during-read rejection requires complete enumeration".to_string(),
                ));
            }
        }
        RawAdmissionViolation::UnsafePath { path_hint } => {
            if path_hint.is_empty() || path_hint.len() > MAX_IDENTIFIER_BYTES.saturating_mul(3) {
                return Err(M6IdentityError::StateIntegrity(
                    "unsafe-path admission rejection is outside its evidence bound".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn raw_admission_observations_digest(
    observations: &[RawAdmissionObservation],
    observations_complete: bool,
) -> Result<ContentDigest, M6IdentityError> {
    digest_domain_serializable(
        b"wasm-biotic:m6:raw-admission-observations:v1\0",
        &(observations, observations_complete),
    )
}

fn raw_admission_rejection_digest(
    record: &RawAdmissionRejected,
) -> Result<ContentDigest, M6IdentityError> {
    digest_domain_serializable(
        b"wasm-biotic:m6:raw-admission-rejected:v1\0",
        &(
            &record.intake_operation_id,
            &record.observations,
            record.observations_complete,
            &record.observations_digest,
            record.rejected_at_ms,
            &record.route_definition_digest,
            &record.route_entry_name,
            &record.schema,
            &record.violation,
        ),
    )
}

fn raw_unit_digest(files: &[RawFileObservation]) -> Result<ContentDigest, M6IdentityError> {
    digest_domain_serializable(RAW_UNIT_DOMAIN, &files)
}

fn raw_record_digest(record: &RawQuarantineRecord) -> Result<ContentDigest, M6IdentityError> {
    digest_domain_serializable(
        b"wasm-biotic:m6:raw-quarantine-record:v1\0",
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
    )
}

fn raw_quarantine_snapshot(
    source: &BTreeMap<PathBuf, Vec<u8>>,
    record: &RawQuarantineRecord,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, M6IdentityError> {
    let mut snapshot = BTreeMap::new();
    for (path, bytes) in source {
        snapshot.insert(PathBuf::from(RAW_UNIT_DIRECTORY).join(path), bytes.clone());
    }
    snapshot.insert(PathBuf::from(RAW_RECORD_FILE), canonical_json(record)?);
    snapshot.insert(
        PathBuf::from(RAW_COMMIT_FILE),
        canonical_json(&(
            "wasm-biotic.m6-raw-quarantine-commit.v1",
            &record.raw_unit_digest,
            &record.record_digest,
        ))?,
    );
    Ok(snapshot)
}

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, M6IdentityError> {
    let value = serde_json::to_value(value)
        .map_err(|error| M6IdentityError::Serialization(error.to_string()))?;
    let mut bytes = Vec::new();
    write_canonical_value(&value, &mut bytes)?;
    Ok(bytes)
}

fn write_canonical_value(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), M6IdentityError> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" })
        }
        serde_json::Value::Number(number) => {
            if !number.is_i64() && !number.is_u64() {
                return Err(M6IdentityError::CanonicalEncoding(
                    "floating-point numbers are forbidden".to_string(),
                ));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        serde_json::Value::String(value) => {
            output.extend_from_slice(
                serde_json::to_string(value)
                    .map_err(|error| M6IdentityError::Serialization(error.to_string()))?
                    .as_bytes(),
            );
        }
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
                        .map_err(|error| M6IdentityError::Serialization(error.to_string()))?
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

fn parse_canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, M6IdentityError> {
    let value = serde_json::from_slice::<T>(bytes)
        .map_err(|error| M6IdentityError::Serialization(error.to_string()))?;
    if canonical_json(&value)? != bytes {
        return Err(M6IdentityError::CanonicalEncoding(
            "input has whitespace, key-order, duplicate-field, or representation drift".to_string(),
        ));
    }
    Ok(value)
}

fn digest_domain_serializable<T: Serialize + ?Sized>(
    domain: &[u8],
    value: &T,
) -> Result<ContentDigest, M6IdentityError> {
    let mut bytes = Vec::from(domain);
    bytes.extend_from_slice(&canonical_json(value)?);
    Ok(ContentDigest::from_bytes(&bytes))
}

fn require_digest(
    subject: &str,
    expected: &ContentDigest,
    actual: &ContentDigest,
) -> Result<(), M6IdentityError> {
    if expected == actual {
        Ok(())
    } else {
        Err(M6IdentityError::DigestMismatch {
            subject: subject.to_string(),
            expected: expected.clone(),
            actual: actual.clone(),
        })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode(value: &str) -> Result<Vec<u8>, M6IdentityError> {
    if value.len() % 2 != 0 || value.is_empty() {
        return Err(M6IdentityError::InvalidConfiguration(
            "hex value must contain a nonempty even number of digits".to_string(),
        ));
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        decoded.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8, M6IdentityError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(M6IdentityError::InvalidConfiguration(
            "hex value must use lowercase ASCII digits".to_string(),
        )),
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<(), M6IdentityError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.contains('\0')
        || value.contains('/')
        || value.contains('\\')
        || matches!(value, "." | "..")
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(M6IdentityError::InvalidConfiguration(format!(
            "{field} is blank, unsafe, or outside its byte bound"
        )));
    }
    Ok(())
}

fn validate_media_type(value: &str) -> Result<(), M6IdentityError> {
    if value.is_empty()
        || value.len() > 256
        || !value.contains('/')
        || value.bytes().any(|byte| {
            !byte.is_ascii_alphanumeric()
                && !matches!(byte, b'/' | b'-' | b'+' | b'.' | b';' | b'=')
        })
    {
        return Err(M6IdentityError::InvalidConfiguration(
            "attachment media type is invalid or outside its byte bound".to_string(),
        ));
    }
    Ok(())
}

fn validate_nonce(value: &str) -> Result<(), M6IdentityError> {
    let bytes = hex_decode(value)?;
    if bytes.len() < NONCE_BYTES || bytes.len() > 64 {
        return Err(M6IdentityError::InvalidConfiguration(
            "route nonce must contain 128..=512 bits".to_string(),
        ));
    }
    Ok(())
}

fn is_strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_strictly_sorted_unique_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn prepare_root(path: &Path, create: bool) -> Result<PathBuf, M6IdentityError> {
    if path.as_os_str().is_empty() {
        return Err(M6IdentityError::UnsafePath(path.to_path_buf()));
    }
    reject_symlink_if_present(path)?;
    if create {
        fs::create_dir_all(path).map_err(|source| M6IdentityError::io(path, source))?;
    }
    reject_symlink(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6IdentityError::io(path, source))?;
    if !metadata.is_dir() {
        return Err(M6IdentityError::UnsafePath(path.to_path_buf()));
    }
    fs::canonicalize(path).map_err(|source| M6IdentityError::io(path, source))
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M6IdentityError> {
    validate_identifier("M6 child directory", name)?;
    let path = root.join(name);
    reject_symlink_if_present(&path)?;
    fs::create_dir_all(&path).map_err(|source| M6IdentityError::io(&path, source))?;
    ensure_real_directory(&path)?;
    let canonical = fs::canonicalize(&path).map_err(|source| M6IdentityError::io(&path, source))?;
    if canonical.parent() != Some(root) {
        return Err(M6IdentityError::UnsafePath(path));
    }
    Ok(canonical)
}

fn ensure_real_directory(path: &Path) -> Result<(), M6IdentityError> {
    reject_symlink(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6IdentityError::io(path, source))?;
    if !metadata.is_dir() {
        return Err(M6IdentityError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M6IdentityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(M6IdentityError::UnsafePath(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M6IdentityError::io(path, source)),
    }
}

fn reject_symlink(path: &Path) -> Result<(), M6IdentityError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| M6IdentityError::io(path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(M6IdentityError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn ensure_pairwise_disjoint(
    sender_root: &Path,
    receiver_root: &Path,
    route_root: &Path,
) -> Result<(), M6IdentityError> {
    for (left, right) in [
        (sender_root, receiver_root),
        (sender_root, route_root),
        (receiver_root, route_root),
    ] {
        if left == right || left.starts_with(right) || right.starts_with(left) {
            return Err(M6IdentityError::InvalidConfiguration(
                "sender, receiver, and neutral route roots must be pairwise disjoint".to_string(),
            ));
        }
    }
    Ok(())
}

fn require_direct_child(root: &Path, path: &Path) -> Result<(), M6IdentityError> {
    if path.parent() != Some(root) || !path.starts_with(root) {
        return Err(M6IdentityError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn persist_immutable(path: &Path, bytes: &[u8]) -> Result<(), M6IdentityError> {
    if path.exists() {
        let existing = read_bounded(path, bytes.len().saturating_add(1).max(2 * 1_048_576))?;
        if existing == bytes {
            return Ok(());
        }
        return Err(M6IdentityError::RouteConflict(path.to_path_buf()));
    }
    write_new_sync(path, bytes)
}

fn write_new_sync(path: &Path, bytes: &[u8]) -> Result<(), M6IdentityError> {
    reject_symlink_if_present(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| M6IdentityError::UnsafePath(path.to_path_buf()))?;
    ensure_real_directory(parent)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|source| M6IdentityError::io(path, source))?;
    file.write_all(bytes)
        .map_err(|source| M6IdentityError::io(path, source))?;
    file.sync_all()
        .map_err(|source| M6IdentityError::io(path, source))?;
    sync_directory(parent)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), M6IdentityError> {
    reject_symlink_if_present(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| M6IdentityError::UnsafePath(path.to_path_buf()))?;
    ensure_real_directory(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| M6IdentityError::UnsafePath(path.to_path_buf()))?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        write_new_sync(&temporary, bytes)?;
        fs::rename(&temporary, path).map_err(|source| M6IdentityError::io(path, source))?;
        sync_directory(parent)
    })();
    if result.is_err() && temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, M6IdentityError> {
    reject_symlink(path)?;
    let before = fs::symlink_metadata(path).map_err(|source| M6IdentityError::io(path, source))?;
    if !before.is_file() || before.len() > limit as u64 {
        return Err(M6IdentityError::ResourceExhausted(format!(
            "'{}' is not a bounded regular file",
            path.display()
        )));
    }
    let file = File::open(path).map_err(|source| M6IdentityError::io(path, source))?;
    let opened = file
        .metadata()
        .map_err(|source| M6IdentityError::io(path, source))?;
    if !opened.is_file() || opened.len() != before.len() {
        return Err(M6IdentityError::UnsafePath(path.to_path_buf()));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| M6IdentityError::io(path, source))?;
    let after = fs::symlink_metadata(path).map_err(|source| M6IdentityError::io(path, source))?;
    if bytes.len() > limit || after.len() != before.len() || !after.is_file() {
        return Err(M6IdentityError::ResourceExhausted(format!(
            "'{}' changed or exceeded its bound during read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), M6IdentityError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| M6IdentityError::io(path, source))
}

fn write_snapshot_directory(
    root: &Path,
    snapshot: &BTreeMap<PathBuf, Vec<u8>>,
) -> Result<(), M6IdentityError> {
    reject_symlink_if_present(root)?;
    fs::create_dir(root).map_err(|source| M6IdentityError::io(root, source))?;
    let mut commit_paths = Vec::new();
    for (relative, bytes) in snapshot {
        validate_relative_path(relative)?;
        if relative
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| matches!(name, DELIVERY_COMMIT_FILE | RAW_COMMIT_FILE))
        {
            commit_paths.push((relative, bytes));
            continue;
        }
        write_snapshot_file(root, relative, bytes)?;
    }
    for (relative, bytes) in commit_paths {
        write_snapshot_file(root, relative, bytes)?;
    }
    sync_all_directories(root)?;
    Ok(())
}

fn write_snapshot_file(root: &Path, relative: &Path, bytes: &[u8]) -> Result<(), M6IdentityError> {
    let path = root.join(relative);
    if !path.starts_with(root) {
        return Err(M6IdentityError::UnsafePath(path));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| M6IdentityError::io(parent, source))?;
    }
    write_new_sync(&path, bytes)
}

fn sync_all_directories(root: &Path) -> Result<(), M6IdentityError> {
    let mut directories = vec![root.to_path_buf()];
    collect_directories(root, root, &mut directories, 0)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    directories.dedup();
    for directory in directories {
        sync_directory(&directory)?;
    }
    Ok(())
}

fn collect_directories(
    root: &Path,
    current: &Path,
    output: &mut Vec<PathBuf>,
    depth: usize,
) -> Result<(), M6IdentityError> {
    if depth > 4 {
        return Err(M6IdentityError::UnsafePath(current.to_path_buf()));
    }
    for entry in fs::read_dir(current).map_err(|source| M6IdentityError::io(current, source))? {
        let entry = entry.map_err(|source| M6IdentityError::io(current, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if entry
            .file_type()
            .map_err(|source| M6IdentityError::io(&path, source))?
            .is_dir()
        {
            if !path.starts_with(root) {
                return Err(M6IdentityError::UnsafePath(path));
            }
            output.push(path.clone());
            collect_directories(root, &path, output, depth + 1)?;
        }
    }
    Ok(())
}

fn read_tree_snapshot(
    root: &Path,
    profile: &RouteResourceProfile,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, M6IdentityError> {
    ensure_real_directory(root)?;
    let mut snapshot = BTreeMap::new();
    read_tree_recursive(root, root, profile, &mut snapshot, 0)?;
    enforce_snapshot_bounds(&snapshot, profile)?;
    Ok(snapshot)
}

fn read_tree_recursive(
    root: &Path,
    current: &Path,
    profile: &RouteResourceProfile,
    snapshot: &mut BTreeMap<PathBuf, Vec<u8>>,
    depth: usize,
) -> Result<(), M6IdentityError> {
    if depth > 4 {
        return Err(M6IdentityError::UnsafePath(current.to_path_buf()));
    }
    let mut entries = fs::read_dir(current)
        .map_err(|source| M6IdentityError::io(current, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| M6IdentityError::io(current, source))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        reject_symlink(&path)?;
        let file_type = entry
            .file_type()
            .map_err(|source| M6IdentityError::io(&path, source))?;
        if file_type.is_dir() {
            read_tree_recursive(root, &path, profile, snapshot, depth + 1)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| M6IdentityError::UnsafePath(path.clone()))?
                .to_path_buf();
            validate_relative_path(&relative)?;
            let per_file_limit =
                profile.max_attachment_bytes.max(profile.max_manifest_bytes) as usize;
            let bytes = read_bounded(&path, per_file_limit)?;
            if snapshot.insert(relative, bytes).is_some() {
                return Err(M6IdentityError::StateIntegrity(
                    "raw unit contains duplicate relative paths".to_string(),
                ));
            }
            if snapshot.len() > profile.max_attachment_count as usize + 8 {
                return Err(M6IdentityError::ResourceExhausted(
                    "delivery entry count exceeds route profile".to_string(),
                ));
            }
        } else {
            return Err(M6IdentityError::UnsafePath(path));
        }
    }
    Ok(())
}

fn enforce_snapshot_bounds(
    snapshot: &BTreeMap<PathBuf, Vec<u8>>,
    profile: &RouteResourceProfile,
) -> Result<(), M6IdentityError> {
    if snapshot.is_empty() || snapshot.len() > profile.max_attachment_count as usize + 8 {
        return Err(M6IdentityError::ResourceExhausted(
            "delivery file count exceeds route profile".to_string(),
        ));
    }
    let total = snapshot.values().try_fold(0_u64, |total, bytes| {
        u64::try_from(bytes.len())
            .map(|length| total.saturating_add(length))
            .map_err(|_| {
                M6IdentityError::ResourceExhausted(
                    "delivery aggregate length overflowed".to_string(),
                )
            })
    })?;
    let hard_limit = profile
        .max_delivery_bytes
        .saturating_add(profile.max_manifest_bytes.saturating_mul(2));
    if total > hard_limit {
        return Err(M6IdentityError::ResourceExhausted(
            "delivery aggregate bytes exceed route profile".to_string(),
        ));
    }
    Ok(())
}

fn require_snapshot_matches(
    root: &Path,
    expected: &BTreeMap<PathBuf, Vec<u8>>,
    profile: &RouteResourceProfile,
) -> Result<(), M6IdentityError> {
    let actual = read_tree_snapshot(root, profile)?;
    if &actual == expected {
        Ok(())
    } else {
        Err(M6IdentityError::RouteConflict(root.to_path_buf()))
    }
}

fn enforce_unit_count(root: &Path, maximum: u32, label: &str) -> Result<(), M6IdentityError> {
    let mut count = 0_usize;
    for entry in fs::read_dir(root).map_err(|source| M6IdentityError::io(root, source))? {
        let entry = entry.map_err(|source| M6IdentityError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        if entry
            .file_type()
            .map_err(|source| M6IdentityError::io(&path, source))?
            .is_dir()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".unit") || name.ends_with(".raw"))
        {
            count += 1;
        }
    }
    if count >= maximum as usize {
        return Err(M6IdentityError::ResourceExhausted(format!(
            "{label} reached its {maximum}-record budget"
        )));
    }
    Ok(())
}

fn enforce_file_count(
    root: &Path,
    maximum: u32,
    suffix: &str,
    label: &str,
) -> Result<(), M6IdentityError> {
    let mut count = 0_usize;
    for entry in fs::read_dir(root).map_err(|source| M6IdentityError::io(root, source))? {
        let entry = entry.map_err(|source| M6IdentityError::io(root, source))?;
        let path = entry.path();
        reject_symlink(&path)?;
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| M6IdentityError::io(&path, source))?;
        if !metadata.is_file() {
            return Err(M6IdentityError::UnsafePath(path));
        }
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.ends_with(suffix))
        {
            count += 1;
        } else {
            return Err(M6IdentityError::UnsafePath(path));
        }
    }
    if count >= maximum as usize {
        return Err(M6IdentityError::ResourceExhausted(format!(
            "{label} reached its {maximum}-record budget"
        )));
    }
    Ok(())
}

fn remove_confined_directory(root: &Path, target: &Path) -> Result<(), M6IdentityError> {
    if target.parent() != Some(root) || !target.starts_with(root) {
        return Err(M6IdentityError::UnsafePath(target.to_path_buf()));
    }
    reject_symlink(target)?;
    fs::remove_dir_all(target).map_err(|source| M6IdentityError::io(target, source))
}

fn validate_relative_path(path: &Path) -> Result<(), M6IdentityError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component
                    .as_os_str()
                    .to_str()
                    .is_none_or(|value| value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES)
        })
    {
        return Err(M6IdentityError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn portable_relative_path(path: &Path) -> Result<String, M6IdentityError> {
    validate_relative_path(path)?;
    path.components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| M6IdentityError::UnsafePath(path.to_path_buf()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join("/"))
}

fn validate_unit_entry_name(value: &str) -> Result<(), M6IdentityError> {
    validate_identifier("route unit entry name", value)?;
    if !value.ends_with(".unit") {
        return Err(M6IdentityError::InvalidConfiguration(
            "route unit entry must use the immutable .unit suffix".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m6-identity-{label}-{}-{}",
                std::process::id(),
                TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create M6 identity test root");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if self.0.exists() && std::env::var_os("KEEP_M6_IDENTITY_TEST_ROOT").is_none() {
                fs::remove_dir_all(&self.0).expect("remove M6 identity test root");
            }
        }
    }

    struct TestRig {
        _directory: TestDirectory,
        clock: Arc<DeterministicClock>,
        receiver_root: PathBuf,
        receiver_signer: FactorySigner,
        receiver_spool: GovernedFilesystemSpool,
        route: RouteDefinition,
        route_root: PathBuf,
        sender_root: PathBuf,
        sender_signer: FactorySigner,
        sender_spool: GovernedFilesystemSpool,
    }

    impl TestRig {
        fn new(label: &str) -> Self {
            Self::with_resource_profile(
                label,
                RouteResourceProfile::bounded_default().expect("resource profile"),
            )
        }

        fn with_resource_profile(label: &str, resource_profile: RouteResourceProfile) -> Self {
            let directory = TestDirectory::new(label);
            let sender_root = directory.0.join("factory-sender");
            let receiver_root = directory.0.join("factory-receiver");
            let route_root = directory.0.join("neutral-route");
            let sender_signer =
                FactorySigner::from_seed("key:sender-v1", [0x11; 32]).expect("sender signer");
            let receiver_signer =
                FactorySigner::from_seed("key:receiver-v1", [0x22; 32]).expect("receiver signer");
            let package_schemas = vec![ContentDigest::from_bytes(b"factory-package-schema-v1")];
            let interface_schemas = vec![ContentDigest::from_bytes(b"factory-interface-schema-v1")];
            let sender_identity = FactoryIdentityDocument::new(
                "factory:sender",
                &sender_signer,
                1,
                10_000_000,
                package_schemas.clone(),
                interface_schemas.clone(),
                ContentDigest::from_bytes(b"sender-authority"),
                ContentDigest::from_bytes(b"exchange-policy"),
            )
            .expect("sender identity");
            let receiver_identity = FactoryIdentityDocument::new(
                "factory:receiver",
                &receiver_signer,
                1,
                10_000_000,
                package_schemas,
                interface_schemas,
                ContentDigest::from_bytes(b"receiver-authority"),
                ContentDigest::from_bytes(b"exchange-policy"),
            )
            .expect("receiver identity");
            let route = RouteDefinition::new(
                "route:sender-to-receiver",
                1,
                &sender_identity,
                &receiver_identity,
                ContentDigest::from_bytes(b"exchange-policy"),
                resource_profile,
            )
            .expect("route definition");
            GovernedFilesystemSpool::initialize(
                &route_root,
                &sender_root,
                &receiver_root,
                route.clone(),
            )
            .expect("initialize governed spool");
            let sender_spool = GovernedFilesystemSpool::open(
                &route_root,
                &sender_root,
                RouteEndpointRole::Sender,
                &route.definition_digest,
            )
            .expect("open sender-local spool");
            let receiver_spool = GovernedFilesystemSpool::open(
                &route_root,
                &receiver_root,
                RouteEndpointRole::Receiver,
                &route.definition_digest,
            )
            .expect("open receiver-local spool");
            Self {
                _directory: directory,
                clock: Arc::new(DeterministicClock::new(1_000_000)),
                receiver_root,
                receiver_signer,
                receiver_spool,
                route,
                route_root,
                sender_root,
                sender_signer,
                sender_spool,
            }
        }

        fn sender_issuer(&self, nonce_byte: u8) -> ManifestIssuer {
            ManifestIssuer::open_or_initialize(
                &self.sender_root,
                self.route.clone(),
                RouteEndpointRole::Sender,
                self.clock.clone(),
                Arc::new(DeterministicNonceSource::new([nonce_byte; 32])),
            )
            .expect("open sender issuer")
        }

        fn receiver_issuer(&self, nonce_byte: u8) -> ManifestIssuer {
            ManifestIssuer::open_or_initialize(
                &self.receiver_root,
                self.route.clone(),
                RouteEndpointRole::Receiver,
                self.clock.clone(),
                Arc::new(DeterministicNonceSource::new([nonce_byte; 32])),
            )
            .expect("open receiver issuer")
        }
    }

    fn export_payload(label: &[u8]) -> ManifestPayload {
        let package_bytes = [b"package:".as_slice(), label].concat();
        ManifestPayload::Export(ExportManifestPayload {
            component_digest: ContentDigest::from_bytes(
                [b"component:".as_slice(), label].concat().as_slice(),
            ),
            export_bundle_digest: ContentDigest::from_bytes(
                [b"bundle:".as_slice(), label].concat().as_slice(),
            ),
            package_bytes_digest: ContentDigest::from_bytes(&package_bytes),
            package_digest: ContentDigest::from_bytes(
                [b"package-identity:".as_slice(), label].concat().as_slice(),
            ),
        })
    }

    fn issue_export(
        issuer: &mut ManifestIssuer,
        signer: &FactorySigner,
        label: &[u8],
    ) -> IssuedManifest {
        issuer
            .issue(
                signer,
                export_payload(label),
                export_attachments(label),
                60_000,
            )
            .expect("issue export manifest")
    }

    fn export_attachments(label: &[u8]) -> Vec<AttachmentInput> {
        vec![AttachmentInput::new(
            "m5-export-bundle",
            "application/json",
            [b"attachment:".as_slice(), label].concat(),
        )]
    }

    fn publish_export(rig: &TestRig, nonce: u8, label: &[u8]) -> IssuedManifest {
        let mut issuer = rig.sender_issuer(nonce);
        let issued = issue_export(&mut issuer, &rig.sender_signer, label);
        let owner = rig.sender_spool.acquire_role().expect("sender route owner");
        rig.sender_spool
            .publish(&owner, &issued)
            .expect("publish route unit");
        issued
    }

    fn sign_manifest_without_field_validation(
        unsigned: UnsignedManifest,
        signer: &FactorySigner,
    ) -> SignedManifest {
        let signature = ManifestSignature {
            algorithm: "Ed25519".to_string(),
            signature_hex: hex_encode(
                &signer.sign(&signature_preimage(&unsigned).expect("unchecked signature preimage")),
            ),
            signing_key_id: signer.signing_key_id().to_string(),
        };
        let mut manifest = SignedManifest {
            message_digest: ContentDigest::from_bytes(&[]),
            signature,
            unsigned,
        };
        manifest.message_digest = manifest
            .expected_digest()
            .expect("unchecked manifest identity");
        manifest
    }

    fn place_untrusted_ready_unit(rig: &TestRig, issued: &IssuedManifest) -> Vec<u8> {
        let ready = rig
            .sender_spool
            .outbound_ready_unit_directory(&issued.manifest.message_digest);
        fs::create_dir(&ready).expect("create untrusted ready unit");
        let manifest_bytes = canonical_json(&issued.manifest).expect("encode untrusted manifest");
        fs::write(ready.join(MANIFEST_FILE), &manifest_bytes).expect("write untrusted manifest");
        for descriptor in &issued.manifest.unsigned.attachments {
            let bytes = issued
                .attachments
                .get(&descriptor.content_digest)
                .expect("untrusted attachment bytes");
            let path = ready.join(attachment_relative_path(&descriptor.content_digest));
            fs::create_dir_all(path.parent().expect("attachment parent"))
                .expect("create attachment parent");
            fs::write(path, bytes).expect("write untrusted attachment");
        }
        fs::write(
            ready.join(DELIVERY_COMMIT_FILE),
            canonical_json(&DeliveryCommitMarker {
                manifest_bytes_digest: ContentDigest::from_bytes(&manifest_bytes),
                message_digest: issued.manifest.message_digest.clone(),
                schema: DELIVERY_COMMIT_SCHEMA.to_string(),
            })
            .expect("encode untrusted delivery commit"),
        )
        .expect("write untrusted delivery commit");
        manifest_bytes
    }

    fn assert_route_identity_control_rejected(
        rig: &TestRig,
        issued: &IssuedManifest,
        intake_operation_id: &str,
        expected_subject: &'static str,
    ) {
        let manifest_bytes = place_untrusted_ready_unit(rig, issued);
        let receiver_owner = rig
            .receiver_spool
            .acquire_role()
            .expect("receiver route owner");
        let quarantine = open_raw_quarantine(rig);
        let record = quarantine
            .quarantine_ready(
                &rig.receiver_spool,
                &receiver_owner,
                &issued.manifest.message_digest,
                intake_operation_id,
            )
            .expect("raw quarantine route-identity control");
        drop(receiver_owner);
        assert_eq!(
            quarantine
                .raw_manifest_bytes(&record.raw_unit_digest)
                .expect("retained route-identity manifest"),
            manifest_bytes
        );
        assert_eq!(
            quarantine
                .read_committed_unit(&record)
                .expect("reopen exact route-identity raw unit")
                .record(),
            &record
        );
        let manifest = quarantine
            .parse_quarantined_manifest(&record)
            .expect("decode route-identity control after quarantine");
        let mut replay = open_sender_intake(rig);
        let before = replay.control_state();
        let error = replay
            .verify_and_commit(&manifest)
            .expect_err("route-identity control must fail");
        match &error {
            M6IdentityError::FalseIdentity { subject, .. } => {
                assert_eq!(*subject, expected_subject)
            }
            other => panic!("unexpected route-identity rejection: {other}"),
        }
        quarantine
            .persist_rejection(&record, &error.to_string())
            .expect("persist exact route-identity rejection");
        let rejection = quarantine
            .rejection(&record.raw_unit_digest)
            .expect("read route-identity rejection")
            .expect("route-identity rejection exists");
        assert_eq!(rejection.raw_unit_digest, record.raw_unit_digest);
        assert_eq!(replay.control_state(), before);
        drop(replay);
        assert_eq!(
            open_sender_intake(rig).control_state(),
            before,
            "route-identity rejection must not mutate durable replay or clock state"
        );
    }

    fn open_raw_quarantine(rig: &TestRig) -> ReceiverRawQuarantine {
        ReceiverRawQuarantine::open_or_initialize(
            &rig.receiver_root,
            rig.route.clone(),
            rig.clock.clone(),
        )
        .expect("open receiver raw quarantine")
    }

    fn expect_admission_rejected(outcome: RawAdmissionOutcome) -> RawAdmissionRejected {
        match outcome {
            RawAdmissionOutcome::Rejected(rejected) => rejected,
            RawAdmissionOutcome::Quarantined(_) => {
                panic!("hard-cap violation was misrepresented as quarantined input")
            }
        }
    }

    fn terminal_reason(disposition: TerminalNegativeDisposition) -> TerminalNegativeReason {
        match disposition {
            TerminalNegativeDisposition::Expired => TerminalNegativeReason::Expired,
            TerminalNegativeDisposition::Revoked => TerminalNegativeReason::Revoked {
                reason_code: "sender-revocation-confirmed".to_string(),
            },
            TerminalNegativeDisposition::PolicyRejected => TerminalNegativeReason::PolicyRejected {
                policy_rule: "receiver-policy-deny".to_string(),
            },
        }
    }

    fn terminal_evidence(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(format!("terminal-evidence:{label}").as_bytes())
    }

    fn open_sender_intake(rig: &TestRig) -> ReplayJournal {
        ReplayJournal::open_or_initialize(
            &rig.receiver_root,
            rig.route.clone(),
            RouteEndpointRole::Sender,
            rig.clock.clone(),
        )
        .expect("open sender intake replay journal")
    }

    fn terminal_negative_file_count(journal: &ReplayJournal) -> usize {
        fs::read_dir(&journal.negative_root)
            .expect("read terminal-negative store")
            .collect::<Result<Vec<_>, _>>()
            .expect("read terminal-negative entries")
            .len()
    }

    #[test]
    fn ed25519_signature_false_identity_tamper_and_directional_roles_fail_closed() {
        let rig = TestRig::new("signature");
        let mut sender_issuer = rig.sender_issuer(0x31);
        let issued = issue_export(&mut sender_issuer, &rig.sender_signer, b"one");
        issued
            .manifest
            .verify_route(&rig.route)
            .expect("pinned sender signature verifies");

        let mut false_unsigned = issued.manifest.unsigned.clone();
        false_unsigned.sender_identity_document_digest =
            ContentDigest::from_bytes(b"false-sender-identity");
        let false_identity =
            SignedManifest::sign(false_unsigned, &rig.sender_signer).expect("sign false claim");
        assert!(matches!(
            false_identity.verify_route(&rig.route),
            Err(M6IdentityError::FalseIdentity {
                subject: "sender",
                ..
            })
        ));

        let impostor =
            FactorySigner::from_seed("key:sender-v1", [0x44; 32]).expect("impostor signer");
        let false_key = SignedManifest::sign(issued.manifest.unsigned.clone(), &impostor)
            .expect("sign with false key id");
        assert!(matches!(
            false_key.verify_route(&rig.route),
            Err(M6IdentityError::SignatureInvalid)
        ));

        let mut tampered = issued.manifest.clone();
        tampered.unsigned.payload = export_payload(b"tampered");
        tampered.message_digest = tampered
            .expected_digest()
            .expect("reseal public digest only");
        assert!(matches!(
            tampered.verify_route(&rig.route),
            Err(M6IdentityError::SignatureInvalid)
        ));

        let mut attachment_tamper = issued.clone();
        attachment_tamper
            .attachments
            .values_mut()
            .next()
            .expect("one attachment")
            .push(0);
        let sender_owner = rig.sender_spool.acquire_role().expect("sender owner");
        assert!(matches!(
            rig.sender_spool
                .stage_delivery(&sender_owner, &attachment_tamper),
            Err(M6IdentityError::DigestMismatch { .. })
        ));

        let mut receiver_issuer = rig.receiver_issuer(0x32);
        let acknowledgement = receiver_issuer
            .issue(
                &rig.receiver_signer,
                ManifestPayload::ReceiverAcknowledgement(ReceiverAcknowledgementPayload {
                    disposition: "raw_quarantined".to_string(),
                    intake_record_digest: ContentDigest::from_bytes(b"intake"),
                    raw_quarantine_digest: ContentDigest::from_bytes(b"raw"),
                    receiver_transaction_digest: ContentDigest::from_bytes(b"transaction"),
                    sender_message_digest: issued.manifest.message_digest.clone(),
                }),
                vec![],
                60_000,
            )
            .expect("receiver-signed acknowledgement");
        acknowledgement
            .manifest
            .verify_route(&rig.route)
            .expect("pinned receiver acknowledgement verifies");
        assert_eq!(
            acknowledgement.manifest.unsigned.origin_role,
            RouteEndpointRole::Receiver
        );

        let bytes = issued
            .manifest
            .canonical_bytes()
            .expect("canonical manifest");
        let mut noncanonical = Vec::from(b" ");
        noncanonical.extend_from_slice(&bytes);
        assert!(matches!(
            SignedManifest::from_canonical_bytes(&noncanonical),
            Err(M6IdentityError::Serialization(_) | M6IdentityError::CanonicalEncoding(_))
        ));
    }

    #[test]
    fn sender_isolation_audit_signature_is_route_and_digest_bound() {
        let rig = TestRig::new("sender-isolation-audit-signature");
        let audit_digest = ContentDigest::from_bytes(b"post-control-m5-projection");
        let signature = rig
            .sender_signer
            .sign_sender_isolation_audit(&rig.route, &audit_digest)
            .expect("sign exact sender isolation audit");
        verify_sender_isolation_audit_signature(
            &rig.route,
            rig.sender_signer.signing_key_id(),
            &audit_digest,
            &signature,
        )
        .expect("verify exact sender isolation audit");

        assert!(matches!(
            verify_sender_isolation_audit_signature(
                &rig.route,
                rig.sender_signer.signing_key_id(),
                &ContentDigest::from_bytes(b"different-post-control-m5-projection"),
                &signature,
            ),
            Err(M6IdentityError::SignatureInvalid)
        ));

        let mut other_route = rig.route.clone();
        other_route.generation += 1;
        other_route.definition_digest = other_route
            .expected_digest()
            .expect("rebind distinct route definition");
        other_route
            .validate()
            .expect("distinct route remains valid");
        assert!(matches!(
            verify_sender_isolation_audit_signature(
                &other_route,
                rig.sender_signer.signing_key_id(),
                &audit_digest,
                &signature,
            ),
            Err(M6IdentityError::SignatureInvalid)
        ));
        assert!(matches!(
            rig.receiver_signer
                .sign_sender_isolation_audit(&rig.route, &audit_digest),
            Err(M6IdentityError::FalseIdentity {
                subject: "sender isolation audit signer",
                ..
            })
        ));
        assert!(
            verify_sender_reopen_audit_signature(
                &rig.route,
                rig.sender_signer.signing_key_id(),
                &audit_digest,
                &signature,
            )
            .is_err(),
            "isolation signatures must not verify in the sender-reopen domain"
        );
    }

    #[test]
    fn revocation_completion_signatures_are_directional_and_domain_separated() {
        let rig = TestRig::new("revocation-completion-signatures");
        let digest = ContentDigest::from_bytes(b"revocation-completion");

        let sender_signature = rig
            .sender_signer
            .sign_sender_revocation_completion(&rig.route, &digest)
            .expect("sender revocation signature");
        verify_sender_revocation_completion_signature(
            &rig.route,
            rig.sender_signer.signing_key_id(),
            &digest,
            &sender_signature,
        )
        .expect("verify sender revocation signature");
        assert!(
            verify_sender_export_completion_signature(
                &rig.route,
                rig.sender_signer.signing_key_id(),
                &digest,
                &sender_signature,
            )
            .is_err()
        );
        assert!(matches!(
            rig.receiver_signer
                .sign_sender_revocation_completion(&rig.route, &digest),
            Err(M6IdentityError::FalseIdentity { .. })
        ));

        let receiver_signature = rig
            .receiver_signer
            .sign_receiver_revocation_completion(&rig.route, &digest)
            .expect("receiver revocation signature");
        verify_receiver_revocation_completion_signature(
            &rig.route,
            rig.receiver_signer.signing_key_id(),
            &digest,
            &receiver_signature,
        )
        .expect("verify receiver revocation signature");
        assert!(
            verify_receiver_intake_completion_signature(
                &rig.route,
                rig.receiver_signer.signing_key_id(),
                &digest,
                &receiver_signature,
            )
            .is_err()
        );
        assert!(matches!(
            rig.sender_signer
                .sign_receiver_revocation_completion(&rig.route, &digest),
            Err(M6IdentityError::FalseIdentity { .. })
        ));
    }

    #[test]
    fn route_resource_profile_new_limits_are_validated_and_digest_bound() {
        let profile = RouteResourceProfile::bounded_default().expect("bounded profile");
        profile.validate().expect("default profile validates");

        let mut digest_tampered = profile.clone();
        digest_tampered.max_package_bytes += 1;
        assert!(digest_tampered.validate().is_err());

        let mut invalid_recovery = profile.clone();
        invalid_recovery.max_recovery_attempts = invalid_recovery.max_retry_attempts + 1;
        invalid_recovery.profile_digest =
            invalid_recovery.expected_digest().expect("profile digest");
        assert!(matches!(
            invalid_recovery.validate(),
            Err(M6IdentityError::InvalidConfiguration(_))
        ));

        let mut invalid_cases = profile;
        invalid_cases.max_proving_cases = 1_025;
        invalid_cases.profile_digest = invalid_cases.expected_digest().expect("profile digest");
        assert!(matches!(
            invalid_cases.validate(),
            Err(M6IdentityError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn revocation_lifetime_accepts_exact_route_boundary_and_rejects_plus_one() {
        let mut profile = RouteResourceProfile::bounded_default().expect("bounded profile");
        profile.max_message_lifetime_ms = 1_001;
        profile.max_revocation_lifetime_ms = 1_000;
        profile.profile_digest = profile.expected_digest().expect("profile digest");

        let exact = TestRig::with_resource_profile("revocation-lifetime-exact", profile.clone());
        let mut exact_issuer = exact.sender_issuer(0x39);
        exact_issuer
            .issue(
                &exact.sender_signer,
                ManifestPayload::Revocation(RevocationManifestPayload {
                    authorization_digest: ContentDigest::from_bytes(b"revocation-authority"),
                    reason: "exact route lifetime".to_string(),
                    target_identity: ContentDigest::from_bytes(b"target"),
                    target_kind: "exchange_message".to_string(),
                }),
                vec![],
                profile.max_revocation_lifetime_ms,
            )
            .expect("exact revocation lifetime");

        let plus_one = TestRig::with_resource_profile("revocation-lifetime-plus-one", profile);
        let mut plus_one_issuer = plus_one.sender_issuer(0x3a);
        assert!(matches!(
            plus_one_issuer.issue(
                &plus_one.sender_signer,
                ManifestPayload::Revocation(RevocationManifestPayload {
                    authorization_digest: ContentDigest::from_bytes(b"revocation-authority"),
                    reason: "over route lifetime".to_string(),
                    target_identity: ContentDigest::from_bytes(b"target"),
                    target_kind: "exchange_message".to_string(),
                }),
                vec![],
                1_001,
            ),
            Err(M6IdentityError::ResourceExhausted(_))
        ));
    }

    #[test]
    fn durable_chain_rejects_replay_nonce_reuse_and_gap_without_consuming_sequence() {
        let rig = TestRig::new("chain");
        let mut issuer = rig.sender_issuer(0x41);
        let first = issue_export(&mut issuer, &rig.sender_signer, b"first");
        let second = issuer
            .issue(
                &rig.sender_signer,
                ManifestPayload::Revocation(RevocationManifestPayload {
                    authorization_digest: ContentDigest::from_bytes(b"revocation-authority"),
                    reason: "withdraw the exact first exchange".to_string(),
                    target_identity: first.manifest.message_digest.clone(),
                    target_kind: "exchange_message".to_string(),
                }),
                vec![],
                60_000,
            )
            .expect("issue revocation on shared sender chain");
        assert_eq!(first.manifest.unsigned.sequence, 1);
        assert_eq!(second.manifest.unsigned.sequence, 2);
        assert_eq!(
            second.manifest.unsigned.previous_message_digest,
            Some(first.manifest.message_digest.clone())
        );

        let mut intake = ReplayJournal::open_or_initialize(
            &rig.receiver_root,
            rig.route.clone(),
            RouteEndpointRole::Sender,
            rig.clock.clone(),
        )
        .expect("open receiver replay journal");
        assert_eq!(
            intake
                .resolve_exact_commit(&second.manifest)
                .expect("read-only uncommitted fact"),
            ReplayCommitResolution::NotCommitted {
                expected_sequence: 1,
                observed_sequence: 2,
            }
        );
        assert!(matches!(
            intake.verify_and_commit(&second.manifest),
            Err(M6IdentityError::SequenceGap {
                expected: 1,
                actual: 2
            })
        ));
        assert_eq!(intake.last_sequence(), 0);
        intake
            .verify_and_commit(&first.manifest)
            .expect("accept exact first message");
        assert!(matches!(
            intake
                .resolve_exact_commit(&first.manifest)
                .expect("resolve exact first commit"),
            ReplayCommitResolution::ExactCommitted(ReplayCommitFact { sequence: 1, .. })
        ));
        assert!(matches!(
            intake.verify_and_commit(&first.manifest),
            Err(M6IdentityError::Replay { sequence: 1 })
        ));
        let mut conflicting_unsigned = first.manifest.unsigned.clone();
        conflicting_unsigned.payload = export_payload(b"same-sequence-conflict");
        let conflicting = SignedManifest::sign(conflicting_unsigned, &rig.sender_signer)
            .expect("sign same-sequence conflict");
        assert!(matches!(
            intake
                .resolve_exact_commit(&conflicting)
                .expect("resolve conflicting committed sequence"),
            ReplayCommitResolution::Conflicting {
                last_committed_sequence: 1,
                observed_sequence: 1,
                ..
            }
        ));
        intake
            .verify_and_commit(&second.manifest)
            .expect("gap closes and revocation advances");

        let third = issue_export(&mut issuer, &rig.sender_signer, b"third");
        let mut reused_nonce_unsigned = third.manifest.unsigned.clone();
        reused_nonce_unsigned.nonce = first.manifest.unsigned.nonce.clone();
        let reused_nonce = SignedManifest::sign(reused_nonce_unsigned, &rig.sender_signer)
            .expect("sign nonce-reuse control");
        assert!(matches!(
            intake.verify_and_commit(&reused_nonce),
            Err(M6IdentityError::NonceReplay(_))
        ));
        assert_eq!(intake.last_sequence(), 2);

        drop(intake);
        let reopened = ReplayJournal::open_or_initialize(
            &rig.receiver_root,
            rig.route.clone(),
            RouteEndpointRole::Sender,
            rig.clock.clone(),
        )
        .expect("reopen durable replay journal");
        assert_eq!(reopened.last_sequence(), 2);
        assert!(matches!(
            reopened
                .resolve_exact_commit(&second.manifest)
                .expect("resolve exact commit after reopen"),
            ReplayCommitResolution::ExactCommitted(ReplayCommitFact { sequence: 2, .. })
        ));
    }

    #[test]
    fn authenticated_terminal_negative_records_cover_all_three_dispositions() {
        for (index, disposition) in [
            TerminalNegativeDisposition::Expired,
            TerminalNegativeDisposition::Revoked,
            TerminalNegativeDisposition::PolicyRejected,
        ]
        .into_iter()
        .enumerate()
        {
            let label = format!("terminal-negative-kind-{index}");
            let rig = TestRig::new(&label);
            let mut issuer = rig.sender_issuer(0x70 + index as u8);
            let issued = issue_export(&mut issuer, &rig.sender_signer, label.as_bytes());
            if disposition == TerminalNegativeDisposition::Expired {
                rig.clock.set(issued.manifest.unsigned.expires_at_ms + 1);
            }
            let evidence = terminal_evidence(&label);
            let reason = terminal_reason(disposition);
            let mut intake = open_sender_intake(&rig);
            let record = intake
                .record_terminal_negative(
                    &issued.manifest,
                    disposition,
                    reason.clone(),
                    evidence.clone(),
                )
                .expect("commit authenticated terminal-negative outcome");
            assert_eq!(record.disposition, disposition);
            assert_eq!(record.reason, reason);
            assert_eq!(record.negative_evidence_digest, evidence);
            assert_eq!(record.sequence, 1);
            assert_eq!(intake.last_sequence(), 1);
            assert_eq!(
                intake
                    .load_terminal_negative(&issued.manifest)
                    .expect("load terminal-negative record"),
                Some(record.clone())
            );
            assert!(matches!(
                intake
                    .resolve_terminal_negative(&issued.manifest)
                    .expect("resolve terminal-negative chain fact"),
                TerminalNegativeResolution::ChainCommitted {
                    commit: ReplayCommitFact { sequence: 1, .. },
                    record: ref retained,
                } if retained == &record
            ));
            let fact = intake
                .chain
                .terminal_negative_fact(&issued.manifest.message_digest)
                .expect("chain cites terminal-negative record");
            assert_eq!(fact.record_digest, record.record_digest);
            assert_eq!(fact.negative_evidence_digest, evidence);
        }
    }

    #[test]
    fn terminal_negative_record_before_cursor_recovers_and_later_sequence_is_accepted() {
        let rig = TestRig::new("terminal-negative-crash");
        let mut issuer = rig.sender_issuer(0x74);
        let first = issue_export(&mut issuer, &rig.sender_signer, b"negative-first");
        let second = issue_export(&mut issuer, &rig.sender_signer, b"accepted-second");
        let evidence = terminal_evidence("record-before-cursor");
        let reason = TerminalNegativeReason::PolicyRejected {
            policy_rule: "receiver-incompatible".to_string(),
        };
        let chain_before;
        let negative_path;
        let negative_staging_path;
        let retained_record;
        {
            let mut intake = open_sender_intake(&rig);
            chain_before =
                fs::read(&intake.chain.state_path).expect("read intake chain before crash");
            intake.fail_after_terminal_negative_record = true;
            assert!(matches!(
                intake.record_terminal_negative(
                    &first.manifest,
                    TerminalNegativeDisposition::PolicyRejected,
                    reason.clone(),
                    evidence.clone(),
                ),
                Err(M6IdentityError::StateIntegrity(ref message))
                    if message.contains("injected crash")
            ));
            assert_eq!(intake.last_sequence(), 0);
            assert_eq!(
                fs::read(&intake.chain.state_path).expect("read chain after record-only crash"),
                chain_before
            );
            retained_record = intake
                .load_terminal_negative(&first.manifest)
                .expect("load record committed before crash")
                .expect("record exists before cursor");
            assert_eq!(terminal_negative_file_count(&intake), 1);
            negative_path =
                terminal_negative_path(&intake.negative_root, &first.manifest.message_digest);
            negative_staging_path = intake
                .negative_root
                .join(format!("{TERMINAL_NEGATIVE_STAGING_PREFIX}simulated-crash"));
        }

        fs::rename(&negative_path, &negative_staging_path)
            .expect("simulate crash after staging fsync but before final link");
        let mut reopened = open_sender_intake(&rig);
        assert!(
            negative_path.exists(),
            "startup recovery must atomically promote a complete staged record"
        );
        assert!(
            !negative_staging_path.exists(),
            "startup recovery removes staging only after promotion"
        );
        assert!(matches!(
            reopened
                .resolve_terminal_negative(&first.manifest)
                .expect("resolve record-before-cursor state"),
            TerminalNegativeResolution::Recorded(ref record)
                if record == &retained_record
        ));
        let recovered = reopened
            .record_terminal_negative(
                &first.manifest,
                TerminalNegativeDisposition::PolicyRejected,
                reason.clone(),
                evidence.clone(),
            )
            .expect("finish cursor commit from retained exact record");
        assert_eq!(recovered, retained_record);
        assert_eq!(reopened.last_sequence(), 1);

        rig.clock.advance(10);
        let state_after_commit =
            fs::read(&reopened.chain.state_path).expect("read committed negative state");
        assert_eq!(
            reopened
                .record_terminal_negative(
                    &first.manifest,
                    TerminalNegativeDisposition::PolicyRejected,
                    reason,
                    evidence.clone(),
                )
                .expect("cursor-before-coordinator exact replay"),
            retained_record
        );
        assert_eq!(
            fs::read(&reopened.chain.state_path).expect("read exact replay state"),
            state_after_commit,
            "exact retry must not advance or rewrite replay state"
        );
        assert!(matches!(
            reopened.record_terminal_negative(
                &first.manifest,
                TerminalNegativeDisposition::PolicyRejected,
                TerminalNegativeReason::PolicyRejected {
                    policy_rule: "changed-policy-rule".to_string(),
                },
                evidence,
            ),
            Err(M6IdentityError::TerminalNegativeConflict { .. })
        ));
        assert_eq!(
            fs::read(&reopened.chain.state_path).expect("read conflict state"),
            state_after_commit
        );

        reopened
            .verify_and_commit(&second.manifest)
            .expect("later exact sequence remains normally acceptable");
        assert_eq!(reopened.last_sequence(), 2);
        drop(reopened);

        let reopened_again = open_sender_intake(&rig);
        assert!(matches!(
            reopened_again
                .resolve_terminal_negative(&first.manifest)
                .expect("resolve negative after later accepted sequence"),
            TerminalNegativeResolution::ChainCommitted {
                commit: ReplayCommitFact { sequence: 1, .. },
                ..
            }
        ));
    }

    #[test]
    fn terminal_negative_timing_future_and_missing_evidence_never_mutate() {
        let expiry_rig = TestRig::new("terminal-negative-expiry-boundary");
        let mut expiry_issuer = expiry_rig.sender_issuer(0x75);
        let expiring = issue_export(&mut expiry_issuer, &expiry_rig.sender_signer, b"expiring");
        expiry_rig
            .clock
            .set(expiring.manifest.unsigned.expires_at_ms);
        let mut expiry_intake = open_sender_intake(&expiry_rig);
        let expiry_state_before =
            fs::read(&expiry_intake.chain.state_path).expect("expiry state before");
        assert!(matches!(
            expiry_intake.record_terminal_negative(
                &expiring.manifest,
                TerminalNegativeDisposition::Expired,
                TerminalNegativeReason::Expired,
                terminal_evidence("expiry-boundary"),
            ),
            Err(M6IdentityError::ContradictoryNegativeTiming {
                now_ms,
                expires_at_ms,
                ..
            }) if now_ms == expires_at_ms
        ));
        assert_eq!(terminal_negative_file_count(&expiry_intake), 0);
        assert_eq!(
            fs::read(&expiry_intake.chain.state_path).expect("expiry boundary state"),
            expiry_state_before
        );
        expiry_rig.clock.advance(1);
        expiry_intake
            .record_terminal_negative(
                &expiring.manifest,
                TerminalNegativeDisposition::Expired,
                TerminalNegativeReason::Expired,
                terminal_evidence("expiry-boundary"),
            )
            .expect("strictly post-expiry outcome is valid");

        let future_rig = TestRig::new("terminal-negative-future");
        future_rig.clock.set(2_000_000);
        let mut future_issuer = future_rig.sender_issuer(0x76);
        let future = issue_export(&mut future_issuer, &future_rig.sender_signer, b"future");
        future_rig.clock.set(1_000_000);
        let mut future_intake = open_sender_intake(&future_rig);
        let future_state_before =
            fs::read(&future_intake.chain.state_path).expect("future state before");
        assert!(matches!(
            future_intake.record_terminal_negative(
                &future.manifest,
                TerminalNegativeDisposition::PolicyRejected,
                terminal_reason(TerminalNegativeDisposition::PolicyRejected),
                terminal_evidence("future"),
            ),
            Err(M6IdentityError::FutureMessage { .. })
        ));
        assert_eq!(terminal_negative_file_count(&future_intake), 0);
        assert_eq!(future_intake.last_sequence(), 0);
        assert_eq!(
            fs::read(&future_intake.chain.state_path).expect("future state after"),
            future_state_before,
            "future-skew hold must not even advance the clock watermark"
        );

        let evidence_rig = TestRig::new("terminal-negative-missing-evidence");
        let mut evidence_issuer = evidence_rig.sender_issuer(0x77);
        let message = issue_export(
            &mut evidence_issuer,
            &evidence_rig.sender_signer,
            b"evidence",
        );
        let mut evidence_intake = open_sender_intake(&evidence_rig);
        let evidence_state_before =
            fs::read(&evidence_intake.chain.state_path).expect("evidence state before");
        let zero = ContentDigest::new(format!("sha256:{}", "0".repeat(64)))
            .expect("all-zero digest syntax");
        for missing in [ContentDigest::from_bytes(&[]), zero] {
            assert!(matches!(
                evidence_intake.record_terminal_negative(
                    &message.manifest,
                    TerminalNegativeDisposition::Revoked,
                    terminal_reason(TerminalNegativeDisposition::Revoked),
                    missing,
                ),
                Err(M6IdentityError::MissingNegativeEvidence)
            ));
        }
        assert_eq!(terminal_negative_file_count(&evidence_intake), 0);
        assert_eq!(evidence_intake.last_sequence(), 0);
        assert_eq!(
            fs::read(&evidence_intake.chain.state_path).expect("evidence state after"),
            evidence_state_before
        );
    }

    #[test]
    fn future_skew_boundary_is_accepted_and_plus_one_never_mutates_replay() {
        let rig = TestRig::new("future-skew-exact-boundary");
        let receiver_now_ms = 1_000_000;
        let accepted_skew_ms = rig.route.resource_profile.accepted_clock_skew_ms;
        assert!(accepted_skew_ms > 0);

        rig.clock.set(receiver_now_ms + accepted_skew_ms);
        let mut issuer = rig.sender_issuer(0x84);
        let boundary = issue_export(&mut issuer, &rig.sender_signer, b"future-skew-boundary");
        rig.clock.set(receiver_now_ms + accepted_skew_ms + 1);
        let beyond = issue_export(
            &mut issuer,
            &rig.sender_signer,
            b"future-skew-beyond-boundary",
        );
        assert_eq!(
            boundary.manifest.unsigned.issued_at_ms,
            receiver_now_ms + accepted_skew_ms
        );
        assert_eq!(
            beyond.manifest.unsigned.issued_at_ms,
            receiver_now_ms + accepted_skew_ms + 1
        );

        rig.clock.set(receiver_now_ms);
        let mut intake = open_sender_intake(&rig);
        intake
            .verify_and_commit(&boundary.manifest)
            .expect("future time exactly at accepted skew is valid");
        let accepted_state = intake.control_state();
        let accepted_state_bytes =
            fs::read(&intake.chain.state_path).expect("read accepted skew-boundary state");
        assert_eq!(accepted_state.last_sequence, 1);
        assert_eq!(accepted_state.clock_watermark_ms, receiver_now_ms);

        assert!(matches!(
            intake.verify_and_commit(&beyond.manifest),
            Err(M6IdentityError::FutureMessage {
                now_ms,
                issued_at_ms,
            }) if now_ms == receiver_now_ms
                && issued_at_ms == receiver_now_ms + accepted_skew_ms + 1
        ));
        assert_eq!(intake.control_state(), accepted_state);
        assert_eq!(
            fs::read(&intake.chain.state_path).expect("read state after future-skew rejection"),
            accepted_state_bytes,
            "one millisecond beyond accepted skew must not move watermark or replay cursor"
        );
        drop(intake);

        let reopened = open_sender_intake(&rig);
        assert_eq!(reopened.control_state(), accepted_state);
        assert_eq!(
            fs::read(&reopened.chain.state_path).expect("read reopened skew-boundary state"),
            accepted_state_bytes
        );
    }

    #[test]
    fn expiry_boundary_is_accepted_and_plus_one_is_a_durable_terminal_rejection() {
        let rig = TestRig::new("expiry-exact-boundary");
        let lifetime_ms = 5;
        let mut issuer = rig.sender_issuer(0x85);
        let boundary = issuer
            .issue(
                &rig.sender_signer,
                export_payload(b"expiry-boundary-accepted"),
                export_attachments(b"expiry-boundary-accepted"),
                lifetime_ms,
            )
            .expect("issue expiry-boundary message");
        let post_expiry = issuer
            .issue(
                &rig.sender_signer,
                export_payload(b"post-expiry-rejected"),
                export_attachments(b"post-expiry-rejected"),
                lifetime_ms,
            )
            .expect("issue post-expiry message");
        let expires_at_ms = boundary.manifest.unsigned.expires_at_ms;
        assert_eq!(post_expiry.manifest.unsigned.expires_at_ms, expires_at_ms);

        rig.clock.set(expires_at_ms);
        let mut intake = open_sender_intake(&rig);
        intake
            .verify_and_commit(&boundary.manifest)
            .expect("message remains valid at its exact expiry timestamp");
        let boundary_state = intake.control_state();
        let boundary_state_bytes =
            fs::read(&intake.chain.state_path).expect("read exact-expiry accepted state");
        assert_eq!(boundary_state.last_sequence, 1);
        assert_eq!(boundary_state.clock_watermark_ms, expires_at_ms);

        let evidence = terminal_evidence("post-expiry-exact-boundary");
        assert!(matches!(
            intake.record_terminal_negative(
                &post_expiry.manifest,
                TerminalNegativeDisposition::Expired,
                TerminalNegativeReason::Expired,
                evidence.clone(),
            ),
            Err(M6IdentityError::ContradictoryNegativeTiming {
                disposition: TerminalNegativeDisposition::Expired,
                now_ms,
                expires_at_ms: observed_expiry,
            }) if now_ms == expires_at_ms && observed_expiry == expires_at_ms
        ));
        assert_eq!(terminal_negative_file_count(&intake), 0);
        assert_eq!(intake.control_state(), boundary_state);
        assert_eq!(
            fs::read(&intake.chain.state_path).expect("read rejected expiry-boundary state"),
            boundary_state_bytes,
            "expiry is strict and the exact boundary must not record a negative disposition"
        );

        rig.clock.set(expires_at_ms + 1);
        let record = intake
            .record_terminal_negative(
                &post_expiry.manifest,
                TerminalNegativeDisposition::Expired,
                TerminalNegativeReason::Expired,
                evidence,
            )
            .expect("one millisecond post-expiry is durably terminal");
        assert_eq!(record.disposition, TerminalNegativeDisposition::Expired);
        assert_eq!(record.recorded_at_ms, expires_at_ms + 1);
        assert_eq!(record.clock_watermark_ms, expires_at_ms + 1);
        assert_eq!(record.sequence, 2);
        let record_path =
            terminal_negative_path(&intake.negative_root, &post_expiry.manifest.message_digest);
        let record_bytes =
            fs::read(&record_path).expect("read durable post-expiry rejection record");
        let expected_record_bytes = record
            .canonical_bytes(&rig.route, RouteEndpointRole::Sender)
            .expect("canonical post-expiry rejection");
        assert!(
            record_bytes == expected_record_bytes,
            "durable post-expiry rejection differed from its canonical bytes (actual_bytes={}, expected_bytes={})",
            record_bytes.len(),
            expected_record_bytes.len()
        );
        let committed_state = intake.control_state();
        let committed_state_bytes =
            fs::read(&intake.chain.state_path).expect("read post-expiry committed state");
        assert_eq!(committed_state.last_sequence, 2);
        assert_eq!(committed_state.clock_watermark_ms, expires_at_ms + 1);
        drop(intake);

        let reopened = open_sender_intake(&rig);
        assert_eq!(reopened.control_state(), committed_state);
        assert_eq!(
            fs::read(&reopened.chain.state_path).expect("read reopened post-expiry state"),
            committed_state_bytes
        );
        assert_eq!(
            fs::read(&record_path).expect("read reopened post-expiry rejection"),
            record_bytes
        );
        assert_eq!(
            reopened
                .load_terminal_negative(&post_expiry.manifest)
                .expect("load post-expiry rejection after reopen"),
            Some(record.clone())
        );
        assert!(matches!(
            reopened
                .resolve_terminal_negative(&post_expiry.manifest)
                .expect("resolve post-expiry rejection after reopen"),
            TerminalNegativeResolution::ChainCommitted {
                commit: ReplayCommitFact { sequence: 2, .. },
                record: ref retained,
            } if retained == &record
        ));
    }

    #[test]
    fn clock_watermark_reopens_and_regression_tolerance_has_an_exact_boundary() {
        let rig = TestRig::new("clock-regression-exact-boundary");
        let issuance_time_ms = 1_000_000;
        let watermark_ms = issuance_time_ms + 10_000;
        let allowed_regression_ms = rig.route.resource_profile.allowed_clock_regression_ms;
        assert!(allowed_regression_ms > 0 && allowed_regression_ms < watermark_ms);

        rig.clock.set(issuance_time_ms);
        let mut issuer = rig.sender_issuer(0x86);
        let first = issue_export(&mut issuer, &rig.sender_signer, b"clock-watermark-first");
        let within = issue_export(
            &mut issuer,
            &rig.sender_signer,
            b"clock-regression-boundary",
        );
        let beyond = issue_export(
            &mut issuer,
            &rig.sender_signer,
            b"clock-regression-beyond-boundary",
        );

        rig.clock.set(watermark_ms);
        let mut intake = open_sender_intake(&rig);
        intake
            .verify_and_commit(&first.manifest)
            .expect("establish durable receiver clock watermark");
        let watermarked_state = intake.control_state();
        let watermarked_state_bytes =
            fs::read(&intake.chain.state_path).expect("read durable watermarked state");
        assert_eq!(watermarked_state.last_sequence, 1);
        assert_eq!(watermarked_state.clock_watermark_ms, watermark_ms);
        drop(intake);

        let mut reopened = open_sender_intake(&rig);
        assert_eq!(reopened.control_state(), watermarked_state);
        assert_eq!(
            fs::read(&reopened.chain.state_path).expect("read unchanged reopened watermark"),
            watermarked_state_bytes,
            "reopen must preserve the exact durable watermark bytes"
        );

        let accepted_regression_ms = watermark_ms - allowed_regression_ms;
        rig.clock.set(accepted_regression_ms);
        reopened
            .verify_and_commit(&within.manifest)
            .expect("regression exactly at the configured tolerance remains valid");
        let tolerated_state = reopened.control_state();
        let tolerated_state_bytes =
            fs::read(&reopened.chain.state_path).expect("read tolerated-regression state");
        assert_eq!(tolerated_state.last_sequence, 2);
        assert_eq!(
            tolerated_state.clock_watermark_ms, watermark_ms,
            "an allowed regression must never lower the durable watermark"
        );

        let rejected_regression_ms = accepted_regression_ms - 1;
        rig.clock.set(rejected_regression_ms);
        assert!(matches!(
            reopened.verify_and_commit(&beyond.manifest),
            Err(M6IdentityError::ClockUntrusted {
                watermark_ms: observed_watermark,
                observed_ms,
            }) if observed_watermark == watermark_ms
                && observed_ms == rejected_regression_ms
        ));
        assert_eq!(reopened.control_state(), tolerated_state);
        assert_eq!(
            fs::read(&reopened.chain.state_path).expect("read clock-untrusted state"),
            tolerated_state_bytes,
            "one millisecond beyond regression tolerance must leave exact state bytes unchanged"
        );
        drop(reopened);

        let reopened_after_rejection = open_sender_intake(&rig);
        assert_eq!(reopened_after_rejection.control_state(), tolerated_state);
        assert_eq!(
            fs::read(&reopened_after_rejection.chain.state_path)
                .expect("read durable state after clock-untrusted reopen"),
            tolerated_state_bytes
        );
    }

    #[test]
    fn terminal_negative_parser_forgery_gap_and_nonce_controls_fail_before_record() {
        let rig = TestRig::new("terminal-negative-controls");
        let mut issuer = rig.sender_issuer(0x78);
        let first = issue_export(&mut issuer, &rig.sender_signer, b"control-first");
        let second = issue_export(&mut issuer, &rig.sender_signer, b"control-second");
        let mut intake = open_sender_intake(&rig);
        let evidence = terminal_evidence("negative-controls");
        let reason = terminal_reason(TerminalNegativeDisposition::PolicyRejected);
        let state_before = fs::read(&intake.chain.state_path).expect("control state before");

        let mut noncanonical = b" ".to_vec();
        noncanonical.extend_from_slice(
            &first
                .manifest
                .canonical_bytes()
                .expect("canonical first manifest"),
        );
        assert!(matches!(
            intake.record_terminal_negative_bytes(
                &noncanonical,
                TerminalNegativeDisposition::PolicyRejected,
                reason.clone(),
                evidence.clone(),
            ),
            Err(M6IdentityError::CanonicalEncoding(_))
        ));
        assert!(matches!(
            intake.record_terminal_negative(
                &second.manifest,
                TerminalNegativeDisposition::PolicyRejected,
                reason.clone(),
                evidence.clone(),
            ),
            Err(M6IdentityError::SequenceGap {
                expected: 1,
                actual: 2,
            })
        ));

        let mut forged = first.manifest.clone();
        let replacement = if forged.signature.signature_hex.starts_with("00") {
            "ff"
        } else {
            "00"
        };
        forged
            .signature
            .signature_hex
            .replace_range(0..2, replacement);
        forged.message_digest = forged
            .expected_digest()
            .expect("rebind forged envelope digest");
        assert!(matches!(
            intake.record_terminal_negative(
                &forged,
                TerminalNegativeDisposition::PolicyRejected,
                reason.clone(),
                evidence.clone(),
            ),
            Err(M6IdentityError::SignatureInvalid)
        ));
        let mut wrong_route_unsigned = first.manifest.unsigned.clone();
        wrong_route_unsigned.route_id = "route:wrong".to_string();
        let wrong_route = SignedManifest::sign(wrong_route_unsigned, &rig.sender_signer)
            .expect("sign wrong-route control");
        assert!(matches!(
            intake.record_terminal_negative(
                &wrong_route,
                TerminalNegativeDisposition::PolicyRejected,
                reason.clone(),
                evidence.clone(),
            ),
            Err(M6IdentityError::FalseIdentity {
                subject: "route",
                ..
            })
        ));
        let wrong_key = FactorySigner::from_seed("key:sender-v1", [0x99; 32]).expect("wrong key");
        let wrong_key_manifest = SignedManifest::sign(first.manifest.unsigned.clone(), &wrong_key)
            .expect("sign wrong-key control");
        assert!(matches!(
            intake.record_terminal_negative(
                &wrong_key_manifest,
                TerminalNegativeDisposition::PolicyRejected,
                reason.clone(),
                evidence.clone(),
            ),
            Err(M6IdentityError::SignatureInvalid)
        ));
        assert_eq!(terminal_negative_file_count(&intake), 0);
        assert_eq!(intake.last_sequence(), 0);
        assert_eq!(
            fs::read(&intake.chain.state_path).expect("state after rejected controls"),
            state_before
        );

        intake
            .record_terminal_negative(
                &first.manifest,
                TerminalNegativeDisposition::PolicyRejected,
                reason.clone(),
                evidence.clone(),
            )
            .expect("commit exact first negative");
        let mut reused_nonce_unsigned = second.manifest.unsigned.clone();
        reused_nonce_unsigned.nonce = first.manifest.unsigned.nonce.clone();
        let reused_nonce = SignedManifest::sign(reused_nonce_unsigned, &rig.sender_signer)
            .expect("sign nonce-reuse control");
        assert!(matches!(
            intake.record_terminal_negative(
                &reused_nonce,
                TerminalNegativeDisposition::PolicyRejected,
                reason,
                evidence,
            ),
            Err(M6IdentityError::NonceReplay(_))
        ));
        assert_eq!(terminal_negative_file_count(&intake), 1);
        assert_eq!(intake.last_sequence(), 1);
    }

    #[test]
    fn legacy_v1_chain_state_fails_closed_without_silent_migration() {
        let rig = TestRig::new("terminal-negative-schema-migration");
        let intake = open_sender_intake(&rig);
        let state_path = intake.chain.state_path.clone();
        drop(intake);

        let bytes = fs::read(&state_path).expect("read v2 chain state");
        let mut value: serde_json::Value =
            serde_json::from_slice(&bytes).expect("parse chain JSON");
        let object = value.as_object_mut().expect("chain object");
        object.insert(
            "schema".to_string(),
            serde_json::Value::String("wasm-biotic.m6-route-chain-state.v1".to_string()),
        );
        object.remove("terminal_negative_facts");
        fs::write(
            &state_path,
            canonical_json(&value).expect("canonical legacy-shaped state"),
        )
        .expect("write simulated legacy state");

        assert!(matches!(
            ReplayJournal::open_or_initialize(
                &rig.receiver_root,
                rig.route.clone(),
                RouteEndpointRole::Sender,
                rig.clock.clone(),
            ),
            Err(M6IdentityError::Serialization(_)) | Err(M6IdentityError::UnsupportedSchema(_))
        ));
    }

    #[test]
    fn issuer_reopens_exact_signed_bytes_without_nonce_or_sequence_regeneration() {
        let rig = TestRig::new("issuance-after-chain-commit");
        let first;
        let request_digest;
        {
            let mut issuer = rig.sender_issuer(0x81);
            first = issuer
                .issue_idempotent(
                    "export-operation-1",
                    &rig.sender_signer,
                    export_payload(b"idempotent"),
                    export_attachments(b"idempotent"),
                    60_000,
                )
                .expect("issue exact durable manifest");
            let recovered = issuer
                .recover_issuance("export-operation-1")
                .expect("resolve issuance while owner is live")
                .expect("issuance exists");
            request_digest = recovered.request_digest;
            assert_eq!(recovered.issued, first);
            assert_eq!(issuer.last_sequence(), 1);
        }

        rig.clock.advance(5_000);
        let mut reopened = rig.sender_issuer(0x92);
        let exact = reopened
            .issue_idempotent(
                "export-operation-1",
                &rig.sender_signer,
                export_payload(b"idempotent"),
                export_attachments(b"idempotent"),
                60_000,
            )
            .expect("retry returns exact durable issuance");
        assert_eq!(exact, first);
        assert_eq!(exact.manifest.unsigned.sequence, 1);
        assert_eq!(reopened.last_sequence(), 1);
        assert_eq!(
            reopened
                .recover_exact_issuance("export-operation-1", &request_digest,)
                .expect("strict exact recovery")
                .expect("strict issuance exists"),
            first
        );

        assert!(matches!(
            reopened.issue_idempotent(
                "export-operation-1",
                &rig.sender_signer,
                export_payload(b"conflicting-reuse"),
                export_attachments(b"conflicting-reuse"),
                60_000,
            ),
            Err(M6IdentityError::IssuanceConflict { .. })
        ));

        let deliberate_second = reopened
            .issue_idempotent(
                "export-operation-2",
                &rig.sender_signer,
                export_payload(b"idempotent"),
                export_attachments(b"idempotent"),
                60_000,
            )
            .expect("distinct operation may deliberately reuse content");
        assert_eq!(deliberate_second.manifest.unsigned.sequence, 2);
        assert_ne!(
            deliberate_second.manifest.unsigned.nonce,
            first.manifest.unsigned.nonce
        );
    }

    #[test]
    fn issuer_reopens_bundle_persisted_before_origin_chain_commit() {
        let rig = TestRig::new("issuance-before-chain-commit");
        let key = "persisted-before-chain";
        let payload = export_payload(b"pending");
        let lifetime_ms = 60_000;
        let persisted;
        let request_digest;
        {
            let mut issuer = rig.sender_issuer(0xa1);
            let chain_before_prepare =
                fs::read(&issuer.chain.state_path).expect("read origin chain before prepare");
            let (descriptors, _) =
                bind_attachments(export_attachments(b"pending"), &rig.route.resource_profile)
                    .expect("bind pending attachments");
            request_digest = issuance_request_digest(
                key,
                &rig.route,
                RouteEndpointRole::Sender,
                rig.sender_signer.signing_key_id(),
                &payload,
                &descriptors,
                lifetime_ms,
            )
            .expect("pending issuance request digest");
            persisted = issuer
                .prepare_idempotent(
                    key,
                    &rig.sender_signer,
                    payload.clone(),
                    export_attachments(b"pending"),
                    lifetime_ms,
                )
                .expect("prepare exact bundle before simulated crash");
            assert_eq!(issuer.last_sequence(), 0);
            assert_eq!(
                fs::read(&issuer.chain.state_path).expect("read origin chain after prepare"),
                chain_before_prepare,
                "prepare must not mutate the sequence, tombstones, or clock watermark"
            );
        }

        rig.clock.advance(5_000);
        let mut reopened = rig.sender_issuer(0xb2);
        let chain_before_recovery =
            fs::read(&reopened.chain.state_path).expect("read chain before recovery");
        let recovered = reopened
            .recover_exact_issuance(key, &request_digest)
            .expect("load pending exact issuance")
            .expect("pending issuance exists");
        assert_eq!(recovered, persisted);
        assert_eq!(
            reopened
                .recover_issuance(key)
                .expect("load prepared issuance")
                .expect("prepared issuance exists")
                .issued,
            persisted
        );
        assert_eq!(
            reopened
                .recover_exact_issuance(key, &request_digest)
                .expect("repeat read-only recovery")
                .expect("prepared issuance remains"),
            persisted
        );
        assert_eq!(reopened.last_sequence(), 0);
        assert_eq!(
            fs::read(&reopened.chain.state_path).expect("read chain after read-only recovery"),
            chain_before_recovery
        );
        assert!(matches!(
            reopened
                .prepared_resolution(key)
                .expect("resolve prepared state"),
            PreparedIssuanceResolution::Prepared(RecoveredIssuance {
                ref issued,
                ..
            }) if issued == &persisted
        ));
        assert!(matches!(
            reopened
                .resolve_prepared_commit(key)
                .expect("resolve uncommitted chain state"),
            ReplayCommitResolution::NotCommitted {
                expected_sequence: 1,
                observed_sequence: 1,
            }
        ));

        let committed = reopened
            .commit_prepared_exact(key, &request_digest)
            .expect("commit retained exact issuance");
        assert_eq!(committed, persisted);
        assert_eq!(reopened.last_sequence(), 1);
        assert_eq!(
            reopened
                .commit_prepared(key)
                .expect("exact commit replay is idempotent"),
            persisted
        );
        assert_eq!(reopened.last_sequence(), 1);
        assert!(matches!(
            reopened
                .prepared_resolution(key)
                .expect("resolve committed state"),
            PreparedIssuanceResolution::ChainCommitted {
                commit: ReplayCommitFact { sequence: 1, .. },
                ..
            }
        ));

        let retry = reopened
            .issue_idempotent(
                key,
                &rig.sender_signer,
                payload,
                export_attachments(b"pending"),
                lifetime_ms,
            )
            .expect("subsequent exact retry is stable");
        assert_eq!(retry, persisted);
        assert_eq!(reopened.last_sequence(), 1);
    }

    #[test]
    fn denied_and_expired_prepares_are_retained_without_sequence_gaps() {
        let rig = TestRig::new("issuance-abandonment");
        let denied_key = "prepare:denied";
        let expired_key = "prepare:expired";
        let accepted_key = "prepare:accepted";
        let denied_evidence = ContentDigest::from_bytes(b"denial-decision");
        let expired_evidence = ContentDigest::from_bytes(b"expiry-decision");

        {
            let mut issuer = rig.sender_issuer(0xc1);
            let denied = issuer
                .prepare_idempotent(
                    denied_key,
                    &rig.sender_signer,
                    export_payload(b"denied"),
                    export_attachments(b"denied"),
                    60_000,
                )
                .expect("prepare denied issuance");
            assert_eq!(denied.manifest.unsigned.sequence, 1);
            assert_eq!(issuer.last_sequence(), 0);
            let denied_request = issuer
                .recover_issuance(denied_key)
                .expect("load denied prepare")
                .expect("denied prepare exists")
                .request_digest;
            let chain_before_abandonment =
                fs::read(&issuer.chain.state_path).expect("chain before abandonment");
            let abandonment = issuer
                .abandon_prepared(
                    denied_key,
                    &denied_request,
                    PreparedIssuanceDisposition::AuthorizationDenied,
                    "sender authorization was denied",
                    denied_evidence.clone(),
                )
                .expect("immutably abandon denied prepare");
            assert_eq!(abandonment.sequence, 1);
            assert_eq!(issuer.last_sequence(), 0);
            assert_eq!(
                fs::read(&issuer.chain.state_path).expect("chain after abandonment"),
                chain_before_abandonment,
                "abandonment must not mutate origin-chain state"
            );
            assert_eq!(
                issuer
                    .abandon_prepared(
                        denied_key,
                        &denied_request,
                        PreparedIssuanceDisposition::AuthorizationDenied,
                        "sender authorization was denied",
                        denied_evidence.clone(),
                    )
                    .expect("exact abandonment replay"),
                abandonment
            );
            assert!(matches!(
                issuer.abandon_prepared(
                    denied_key,
                    &denied_request,
                    PreparedIssuanceDisposition::AuthorizationDenied,
                    "changed denial reason",
                    denied_evidence,
                ),
                Err(M6IdentityError::IssuanceAbandonmentConflict { .. })
            ));
            assert!(matches!(
                issuer.commit_prepared(denied_key),
                Err(M6IdentityError::IssuanceAbandoned { .. })
            ));
            assert!(matches!(
                issuer
                    .prepared_resolution(denied_key)
                    .expect("resolve abandoned state"),
                PreparedIssuanceResolution::Abandoned { .. }
            ));

            let expired = issuer
                .prepare_idempotent(
                    expired_key,
                    &rig.sender_signer,
                    export_payload(b"expired"),
                    export_attachments(b"expired"),
                    60_000,
                )
                .expect("reuse coordinate after denial");
            assert_eq!(expired.manifest.unsigned.sequence, 1);
            let expired_request = issuer
                .recover_issuance(expired_key)
                .expect("load expired prepare")
                .expect("expired prepare exists")
                .request_digest;
            issuer
                .abandon_prepared(
                    expired_key,
                    &expired_request,
                    PreparedIssuanceDisposition::AuthorizationExpired,
                    "authorization deadline expired",
                    expired_evidence,
                )
                .expect("immutably abandon expired prepare");
            assert_eq!(issuer.last_sequence(), 0);
        }

        let mut reopened = rig.sender_issuer(0xc1);
        assert_eq!(reopened.last_sequence(), 0);
        for key in [denied_key, expired_key] {
            let retained = reopened
                .recover_issuance(key)
                .expect("reopen abandoned prepare")
                .expect("abandoned prepare retained");
            assert!(retained.abandonment.is_some());
            assert!(matches!(
                reopened.commit_prepared(key),
                Err(M6IdentityError::IssuanceAbandoned { .. })
            ));
        }

        let accepted = reopened
            .prepare_idempotent(
                accepted_key,
                &rig.sender_signer,
                export_payload(b"accepted"),
                export_attachments(b"accepted"),
                60_000,
            )
            .expect("prepare after two abandoned candidates");
        assert_eq!(
            accepted.manifest.unsigned.sequence, 1,
            "abandoned prepares must not create an origin-chain gap"
        );
        assert_eq!(
            reopened
                .commit_prepared(accepted_key)
                .expect("commit accepted prepare"),
            accepted
        );
        assert_eq!(reopened.last_sequence(), 1);
        drop(reopened);

        let reopened_after_commit = rig.sender_issuer(0xe3);
        assert_eq!(reopened_after_commit.last_sequence(), 1);
        assert!(
            reopened_after_commit
                .prepared_abandonment(denied_key)
                .expect("resolve retained denial")
                .is_some()
        );
    }

    #[test]
    fn malformed_ready_manifest_is_raw_quarantined_before_parse_rejection() {
        let rig = TestRig::new("raw-quarantine");
        let mut issuer = rig.sender_issuer(0x51);
        let issued = issue_export(&mut issuer, &rig.sender_signer, b"malformed");
        let sender_owner = rig.sender_spool.acquire_role().expect("sender owner");
        rig.sender_spool
            .publish(&sender_owner, &issued)
            .expect("publish valid unit");
        drop(sender_owner);

        let ready_manifest = rig
            .sender_spool
            .outbound_ready_unit_directory(&issued.manifest.message_digest)
            .join(MANIFEST_FILE);
        let malformed = b"{this-is-not-json".to_vec();
        fs::write(&ready_manifest, &malformed).expect("simulate untrusted route tamper");

        let receiver_owner = rig
            .receiver_spool
            .acquire_role()
            .expect("receiver intake owner");
        let quarantine = ReceiverRawQuarantine::open_or_initialize(
            &rig.receiver_root,
            rig.route.clone(),
            rig.clock.clone(),
        )
        .expect("open receiver raw quarantine");
        let raw_digest = match quarantine.quarantine_then_parse(
            &rig.receiver_spool,
            &receiver_owner,
            &issued.manifest.message_digest,
            "intake:malformed-manifest",
        ) {
            Err(M6IdentityError::MalformedQuarantined {
                raw_unit_digest, ..
            }) => raw_unit_digest,
            _ => panic!("malformed intake returned an unexpected bounded outcome"),
        };
        assert_eq!(
            quarantine
                .raw_manifest_bytes(&raw_digest)
                .expect("retained raw manifest"),
            malformed
        );
        assert!(
            quarantine
                .rejection(&raw_digest)
                .expect("read raw rejection")
                .is_some(),
            "parse rejection must cite the already-committed raw unit"
        );
    }

    #[test]
    fn wrong_route_generation_and_wrong_intended_peer_are_raw_retained_without_replay_mutation() {
        let generation_rig = TestRig::new("wrong-route-generation");
        let mut generation_issuer = generation_rig.sender_issuer(0x54);
        let generation_base = issue_export(
            &mut generation_issuer,
            &generation_rig.sender_signer,
            b"wrong-generation",
        );
        let mut generation_unsigned = generation_base.manifest.unsigned.clone();
        generation_unsigned.route_generation += 1;
        let generation_manifest =
            SignedManifest::sign(generation_unsigned, &generation_rig.sender_signer)
                .expect("sign wrong-generation control");
        assert_route_identity_control_rejected(
            &generation_rig,
            &IssuedManifest {
                attachments: generation_base.attachments,
                manifest: generation_manifest,
            },
            "intake:wrong-route-generation",
            "route",
        );

        let peer_rig = TestRig::new("wrong-intended-peer");
        let mut peer_issuer = peer_rig.sender_issuer(0x55);
        let peer_base = issue_export(
            &mut peer_issuer,
            &peer_rig.sender_signer,
            b"wrong-intended-peer",
        );
        let mut peer_unsigned = peer_base.manifest.unsigned.clone();
        peer_unsigned.receiver_identity_document_digest =
            ContentDigest::from_bytes(b"wrong-intended-peer");
        let peer_manifest = SignedManifest::sign(peer_unsigned, &peer_rig.sender_signer)
            .expect("sign wrong-peer control");
        assert_route_identity_control_rejected(
            &peer_rig,
            &IssuedManifest {
                attachments: peer_base.attachments,
                manifest: peer_manifest,
            },
            "intake:wrong-intended-peer",
            "receiver",
        );
    }

    #[test]
    fn duplicate_attachment_names_are_raw_retained_and_rejected_before_replay() {
        let rig = TestRig::new("duplicate-attachment-names");
        let mut issuer = rig.sender_issuer(0x56);
        let base = issue_export(
            &mut issuer,
            &rig.sender_signer,
            b"duplicate-attachment-names",
        );
        let mut unsigned = base.manifest.unsigned.clone();
        let first = unsigned
            .attachments
            .first()
            .expect("one original attachment")
            .clone();
        let duplicate_bytes = b"distinct-bytes-under-a-duplicate-logical-name".to_vec();
        let duplicate_digest = ContentDigest::from_bytes(&duplicate_bytes);
        unsigned.attachments.push(AttachmentDescriptor {
            byte_length: u64::try_from(duplicate_bytes.len()).expect("duplicate attachment length"),
            content_digest: duplicate_digest.clone(),
            logical_name: first.logical_name,
            media_type: first.media_type,
        });
        let mut attachments = base.attachments;
        assert!(
            attachments
                .insert(duplicate_digest, duplicate_bytes)
                .is_none()
        );
        let issued = IssuedManifest {
            attachments,
            manifest: sign_manifest_without_field_validation(unsigned, &rig.sender_signer),
        };
        let manifest_bytes = place_untrusted_ready_unit(&rig, &issued);
        let receiver_owner = rig
            .receiver_spool
            .acquire_role()
            .expect("receiver route owner");
        let replay = open_sender_intake(&rig);
        let before = replay.control_state();
        let (raw_unit_digest, reason) = match open_raw_quarantine(&rig).quarantine_then_parse(
            &rig.receiver_spool,
            &receiver_owner,
            &issued.manifest.message_digest,
            "intake:duplicate-attachment-names",
        ) {
            Err(M6IdentityError::MalformedQuarantined {
                raw_unit_digest,
                reason,
            }) => (raw_unit_digest, reason),
            _ => panic!("duplicate-name intake returned an unexpected bounded outcome"),
        };
        drop(receiver_owner);

        assert!(
            reason.contains("manifest attachments must be sorted by unique logical name"),
            "rejection must identify the duplicate logical-name control: {reason}"
        );
        let quarantine = open_raw_quarantine(&rig);
        assert_eq!(
            quarantine
                .raw_manifest_bytes(&raw_unit_digest)
                .expect("retained duplicate-name manifest"),
            manifest_bytes
        );
        let record = quarantine
            .committed_for_intake("intake:duplicate-attachment-names")
            .expect("resolve duplicate-name intake")
            .expect("duplicate-name raw unit is committed");
        assert_eq!(record.raw_unit_digest, raw_unit_digest);
        assert_eq!(
            quarantine
                .read_committed_unit(&record)
                .expect("reopen exact duplicate-name raw unit")
                .record(),
            &record
        );
        let rejection = quarantine
            .rejection(&raw_unit_digest)
            .expect("read duplicate-name rejection")
            .expect("duplicate-name rejection exists");
        assert_eq!(rejection.raw_unit_digest, raw_unit_digest);
        assert_eq!(replay.control_state(), before);
        drop(replay);
        assert_eq!(
            open_sender_intake(&rig).control_state(),
            before,
            "duplicate-name rejection must not mutate durable replay or clock state"
        );
    }

    #[test]
    fn post_quarantine_truncation_is_durably_rejected_without_replay_mutation() {
        let rig = TestRig::new("post-quarantine-truncation");
        let issued = publish_export(&rig, 0x57, b"post-quarantine-truncation");
        let receiver_owner = rig
            .receiver_spool
            .acquire_role()
            .expect("receiver route owner");
        let quarantine = open_raw_quarantine(&rig);
        let record = quarantine
            .quarantine_ready(
                &rig.receiver_spool,
                &receiver_owner,
                &issued.manifest.message_digest,
                "intake:post-quarantine-truncation",
            )
            .expect("commit complete raw unit before truncation");
        drop(receiver_owner);

        let raw_root = quarantine.raw_unit_path(&record.raw_unit_digest);
        let raw_record_path = raw_root.join(RAW_RECORD_FILE);
        let immutable_record_bytes =
            fs::read(&raw_record_path).expect("read immutable raw record before truncation");
        let raw_manifest_path = raw_root.join(RAW_UNIT_DIRECTORY).join(MANIFEST_FILE);
        let original_manifest_bytes =
            fs::read(&raw_manifest_path).expect("read complete quarantined manifest");
        let truncated_manifest_bytes =
            original_manifest_bytes[..original_manifest_bytes.len() / 2].to_vec();
        assert!(!truncated_manifest_bytes.is_empty());

        let replay = open_sender_intake(&rig);
        let before = replay.control_state();
        fs::write(&raw_manifest_path, &truncated_manifest_bytes)
            .expect("truncate manifest only after raw quarantine commit");
        let parse_error = quarantine
            .parse_quarantined_manifest(&record)
            .expect_err("truncated quarantined manifest must not parse");
        let reason = parse_error.to_string();
        quarantine
            .persist_rejection(&record, &reason)
            .expect("persist truncation rejection against original raw identity");

        assert_eq!(
            fs::read(&raw_record_path).expect("read immutable raw record after rejection"),
            immutable_record_bytes,
            "post-quarantine rejection must not rewrite the committed raw observation"
        );
        assert_eq!(
            quarantine
                .raw_manifest_bytes(&record.raw_unit_digest)
                .expect("read retained truncated manifest"),
            truncated_manifest_bytes
        );
        assert!(matches!(
            quarantine.read_committed_unit(&record),
            Err(M6IdentityError::StateIntegrity(ref message))
                if message.contains("bytes differ from their immutable observations")
        ));
        let rejection = quarantine
            .rejection(&record.raw_unit_digest)
            .expect("read truncation rejection")
            .expect("truncation rejection exists");
        assert_eq!(rejection.raw_unit_digest, record.raw_unit_digest);
        assert_eq!(rejection.reason, reason);
        assert_eq!(replay.control_state(), before);
        drop(replay);
        assert_eq!(
            open_sender_intake(&rig).control_state(),
            before,
            "post-quarantine truncation must not mutate durable replay or clock state"
        );
    }

    #[test]
    fn committed_raw_quarantine_reopens_by_intake_without_clock_or_readmission() {
        struct UnavailableClock;

        impl Clock for UnavailableClock {
            fn now_ms(&self) -> Result<u64, M6IdentityError> {
                Err(M6IdentityError::StateIntegrity(
                    "recovery lookup observed the clock".to_string(),
                ))
            }
        }

        let rig = TestRig::new("raw-quarantine-intake-recovery");
        let issued = publish_export(&rig, 0x58, b"intake-recovery");
        let owner = rig
            .receiver_spool
            .acquire_role()
            .expect("receiver route owner");
        let quarantine = open_raw_quarantine(&rig);
        let committed = quarantine
            .quarantine_ready(
                &rig.receiver_spool,
                &owner,
                &issued.manifest.message_digest,
                "intake:restart-recovery",
            )
            .expect("commit raw quarantine before coordinator crash");
        drop(quarantine);

        let reopened = ReceiverRawQuarantine::open_or_initialize(
            &rig.receiver_root,
            rig.route.clone(),
            Arc::new(UnavailableClock),
        )
        .expect("reopen quarantine with unavailable wall clock");
        assert_eq!(
            reopened
                .committed_for_intake("intake:restart-recovery")
                .expect("resolve exact committed intake"),
            Some(committed)
        );
        assert_eq!(
            reopened
                .committed_for_intake("intake:never-admitted")
                .expect("resolve absent intake"),
            None
        );
    }

    #[test]
    fn committed_raw_quarantine_rejects_duplicate_intake_identity() {
        let rig = TestRig::new("raw-quarantine-duplicate-intake");
        let first = publish_export(&rig, 0x59, b"duplicate-intake-first");
        let second = publish_export(&rig, 0x5a, b"duplicate-intake-second");
        let owner = rig
            .receiver_spool
            .acquire_role()
            .expect("receiver route owner");
        let quarantine = open_raw_quarantine(&rig);
        let first_record = quarantine
            .quarantine_ready(
                &rig.receiver_spool,
                &owner,
                &first.manifest.message_digest,
                "intake:duplicate",
            )
            .expect("commit first intake claimant");
        let second_record = quarantine
            .quarantine_ready(
                &rig.receiver_spool,
                &owner,
                &second.manifest.message_digest,
                "intake:duplicate",
            )
            .expect("commit second intake claimant");
        assert_ne!(first_record.raw_unit_digest, second_record.raw_unit_digest);
        assert!(matches!(
            quarantine.committed_for_intake("intake:duplicate"),
            Err(M6IdentityError::StateIntegrity(ref message))
                if message.contains("multiple committed raw quarantine units")
        ));
    }

    #[test]
    fn committed_raw_quarantine_rejects_cross_link_and_byte_tamper() {
        let cross_link_rig = TestRig::new("raw-quarantine-cross-link");
        let cross_linked = publish_export(&cross_link_rig, 0x5b, b"cross-link");
        let cross_link_owner = cross_link_rig
            .receiver_spool
            .acquire_role()
            .expect("cross-link receiver route owner");
        let cross_link_quarantine = open_raw_quarantine(&cross_link_rig);
        let cross_link_record = cross_link_quarantine
            .quarantine_ready(
                &cross_link_rig.receiver_spool,
                &cross_link_owner,
                &cross_linked.manifest.message_digest,
                "intake:cross-link",
            )
            .expect("commit cross-link control");
        let correct_path = cross_link_quarantine.raw_unit_path(&cross_link_record.raw_unit_digest);
        let wrong_path = cross_link_quarantine.quarantine_root.join(format!(
            "{}.raw",
            ContentDigest::from_bytes(b"wrong-raw-unit-identity").file_stem()
        ));
        fs::rename(&correct_path, &wrong_path).expect("cross-link raw unit path");
        assert!(matches!(
            cross_link_quarantine.committed_for_intake("intake:cross-link"),
            Err(M6IdentityError::StateIntegrity(ref message))
                if message.contains("wrong unit identity")
        ));

        let tamper_rig = TestRig::new("raw-quarantine-byte-tamper");
        let tampered = publish_export(&tamper_rig, 0x5c, b"byte-tamper");
        let tamper_owner = tamper_rig
            .receiver_spool
            .acquire_role()
            .expect("tamper receiver route owner");
        let tamper_quarantine = open_raw_quarantine(&tamper_rig);
        let tamper_record = tamper_quarantine
            .quarantine_ready(
                &tamper_rig.receiver_spool,
                &tamper_owner,
                &tampered.manifest.message_digest,
                "intake:byte-tamper",
            )
            .expect("commit tamper control");
        fs::write(
            tamper_quarantine
                .raw_unit_path(&tamper_record.raw_unit_digest)
                .join(RAW_UNIT_DIRECTORY)
                .join(MANIFEST_FILE),
            b"tampered-after-commit",
        )
        .expect("tamper committed raw bytes");
        assert!(matches!(
            tamper_quarantine.committed_for_intake("intake:byte-tamper"),
            Err(M6IdentityError::StateIntegrity(ref message))
                if message.contains("bytes differ")
        ));
    }

    #[test]
    fn oversized_manifest_and_attachment_leave_typed_admission_evidence() {
        for (label, tamper_manifest) in [
            ("oversized-manifest", true),
            ("oversized-attachment", false),
        ] {
            let rig = TestRig::new(label);
            let issued = publish_export(&rig, 0x52, label.as_bytes());
            let ready = rig
                .sender_spool
                .outbound_ready_unit_directory(&issued.manifest.message_digest);
            let (path, maximum_bytes) = if tamper_manifest {
                (
                    ready.join(MANIFEST_FILE),
                    rig.route.resource_profile.max_manifest_bytes,
                )
            } else {
                (
                    ready.join(attachment_relative_path(
                        &issued.manifest.unsigned.attachments[0].content_digest,
                    )),
                    rig.route.resource_profile.max_attachment_bytes,
                )
            };
            fs::write(
                &path,
                vec![0xa5; usize::try_from(maximum_bytes + 1).expect("test bound")],
            )
            .expect("write oversized untrusted route file");

            let owner = rig
                .receiver_spool
                .acquire_role()
                .expect("receiver route owner");
            let quarantine = open_raw_quarantine(&rig);
            let rejected = expect_admission_rejected(
                quarantine
                    .admit_ready(
                        &rig.receiver_spool,
                        &owner,
                        &issued.manifest.message_digest,
                        &format!("intake:{label}"),
                    )
                    .expect("persist admission rejection"),
            );
            match rejected.violation {
                RawAdmissionViolation::PerFileBytesExceeded {
                    maximum_bytes: actual_maximum,
                    observed_bytes,
                    ..
                } => {
                    assert_eq!(actual_maximum, maximum_bytes);
                    assert_eq!(observed_bytes, maximum_bytes + 1);
                }
                _ => panic!("hard-cap intake returned an unexpected bounded outcome"),
            }
            assert!(rejected.observations_complete);
            assert!(
                fs::read_dir(&quarantine.quarantine_root)
                    .expect("list quarantine root")
                    .filter_map(Result::ok)
                    .all(|entry| !entry.file_name().to_string_lossy().ends_with(".raw")),
                "a rejected prefix must not be represented as a raw unit"
            );
        }
    }

    #[test]
    fn entry_count_and_aggregate_caps_are_typed_before_decode() {
        let rig = TestRig::new("entry-count");
        let issued = publish_export(&rig, 0x53, b"entry-count");
        let ready = rig
            .sender_spool
            .outbound_ready_unit_directory(&issued.manifest.message_digest);
        let attachments = ready.join(ATTACHMENTS_DIRECTORY);
        for index in 0..=rig.route.resource_profile.max_attachment_count {
            fs::write(attachments.join(format!("extra-{index:04}.blob")), b"x")
                .expect("add hostile route entry");
        }
        let owner = rig
            .receiver_spool
            .acquire_role()
            .expect("receiver route owner");
        let quarantine = open_raw_quarantine(&rig);
        let rejected = expect_admission_rejected(
            quarantine
                .admit_ready(
                    &rig.receiver_spool,
                    &owner,
                    &issued.manifest.message_digest,
                    "intake:entry-count",
                )
                .expect("entry-count rejection"),
        );
        assert!(matches!(
            rejected.violation,
            RawAdmissionViolation::EntryCountExceeded { .. }
        ));
        assert!(!rejected.observations_complete);
        assert_eq!(
            rejected.observations.len(),
            raw_admission_entry_limit(&rig.route.resource_profile) as usize + 1
        );

        let mut profile = RouteResourceProfile::bounded_default().expect("bounded profile");
        profile.max_delivery_bytes = profile.max_manifest_bytes;
        profile.profile_digest = profile.expected_digest().expect("profile digest");
        let aggregate_rig = TestRig::with_resource_profile("aggregate-cap", profile);
        let aggregate_issued = publish_export(&aggregate_rig, 0x54, b"aggregate-cap");
        let aggregate_ready = aggregate_rig
            .sender_spool
            .outbound_ready_unit_directory(&aggregate_issued.manifest.message_digest);
        let attachment = aggregate_ready.join(attachment_relative_path(
            &aggregate_issued.manifest.unsigned.attachments[0].content_digest,
        ));
        fs::write(&attachment, vec![0x5a; 3 * 1_048_576])
            .expect("write aggregate-sized attachment");
        let aggregate_owner = aggregate_rig
            .receiver_spool
            .acquire_role()
            .expect("aggregate receiver owner");
        let aggregate_quarantine = open_raw_quarantine(&aggregate_rig);
        let aggregate_rejected = expect_admission_rejected(
            aggregate_quarantine
                .admit_ready(
                    &aggregate_rig.receiver_spool,
                    &aggregate_owner,
                    &aggregate_issued.manifest.message_digest,
                    "intake:aggregate-cap",
                )
                .expect("aggregate rejection"),
        );
        assert!(matches!(
            aggregate_rejected.violation,
            RawAdmissionViolation::AggregateBytesExceeded { .. }
        ));
        assert!(aggregate_rejected.observations_complete);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_route_entry_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let rig = TestRig::new("raw-symlink");
        let issued = publish_export(&rig, 0x55, b"raw-symlink");
        let ready = rig
            .sender_spool
            .outbound_ready_unit_directory(&issued.manifest.message_digest);
        let manifest = ready.join(MANIFEST_FILE);
        fs::remove_file(&manifest).expect("remove route manifest");
        symlink(ready.join(DELIVERY_COMMIT_FILE), &manifest).expect("plant hostile symlink");

        let owner = rig
            .receiver_spool
            .acquire_role()
            .expect("receiver route owner");
        let quarantine = open_raw_quarantine(&rig);
        let rejected = expect_admission_rejected(
            quarantine
                .admit_ready(
                    &rig.receiver_spool,
                    &owner,
                    &issued.manifest.message_digest,
                    "intake:raw-symlink",
                )
                .expect("symlink rejection"),
        );
        assert!(matches!(
            rejected.violation,
            RawAdmissionViolation::Symlink { ref relative_path }
                if relative_path == MANIFEST_FILE
        ));
        assert!(
            rejected
                .observations
                .iter()
                .any(
                    |observation| observation.entry_kind == RawAdmissionEntryKind::Symlink
                        && observation.content_digest.is_none()
                )
        );
    }

    #[test]
    fn truncation_after_open_is_a_stable_change_rejection() {
        use std::sync::atomic::AtomicBool;

        let rig = TestRig::new("raw-change");
        let issued = publish_export(&rig, 0x56, b"raw-change");
        let owner = rig
            .receiver_spool
            .acquire_role()
            .expect("receiver route owner");
        let mut quarantine = open_raw_quarantine(&rig);
        let mutated = Arc::new(AtomicBool::new(false));
        let hook_mutated = mutated.clone();
        quarantine.admission_read_hook = Some(Arc::new(move |path, point| {
            if point == RawAdmissionTestPoint::AfterOpen
                && path.file_name().and_then(|name| name.to_str()) == Some(MANIFEST_FILE)
                && !hook_mutated.swap(true, Ordering::SeqCst)
            {
                OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(path)
                    .expect("truncate route file after open");
            }
        }));
        let rejected = expect_admission_rejected(
            quarantine
                .admit_ready(
                    &rig.receiver_spool,
                    &owner,
                    &issued.manifest.message_digest,
                    "intake:raw-change",
                )
                .expect("change-during-read rejection"),
        );
        assert!(mutated.load(Ordering::SeqCst));
        assert!(matches!(
            rejected.violation,
            RawAdmissionViolation::ChangedDuringRead { ref relative_path }
                if relative_path == MANIFEST_FILE
        ));
        assert!(rejected.observations_complete);
    }

    #[test]
    fn admission_rejection_reopens_exactly_and_tamper_fails_closed() {
        let rig = TestRig::new("raw-rejection-reopen");
        let issued = publish_export(&rig, 0x57, b"raw-rejection-reopen");
        let ready = rig
            .sender_spool
            .outbound_ready_unit_directory(&issued.manifest.message_digest);
        fs::write(
            ready.join(MANIFEST_FILE),
            vec![
                0x7b;
                usize::try_from(rig.route.resource_profile.max_manifest_bytes + 1)
                    .expect("test manifest bound")
            ],
        )
        .expect("write oversized manifest");
        let owner = rig
            .receiver_spool
            .acquire_role()
            .expect("receiver route owner");
        let quarantine = open_raw_quarantine(&rig);
        let first = expect_admission_rejected(
            quarantine
                .admit_ready(
                    &rig.receiver_spool,
                    &owner,
                    &issued.manifest.message_digest,
                    "intake:raw-rejection-reopen",
                )
                .expect("initial admission rejection"),
        );
        drop(quarantine);
        let reopened = open_raw_quarantine(&rig);
        let retained = reopened
            .admission_rejection("intake:raw-rejection-reopen")
            .expect("read retained rejection")
            .expect("retained rejection exists");
        assert_eq!(retained, first);

        fs::write(ready.join(MANIFEST_FILE), b"{}")
            .expect("route changes after terminal rejection");
        let replay = expect_admission_rejected(
            reopened
                .admit_ready(
                    &rig.receiver_spool,
                    &owner,
                    &issued.manifest.message_digest,
                    "intake:raw-rejection-reopen",
                )
                .expect("terminal rejection replay"),
        );
        assert_eq!(replay, first);

        let mut tampered = first.clone();
        tampered.rejected_at_ms += 1;
        fs::write(
            reopened.raw_admission_rejection_path("intake:raw-rejection-reopen"),
            canonical_json(&tampered).expect("canonical tampered rejection"),
        )
        .expect("tamper retained rejection");
        assert!(matches!(
            reopened.admission_rejection("intake:raw-rejection-reopen"),
            Err(M6IdentityError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn fully_staged_unit_recovers_to_ready_after_restart() {
        let rig = TestRig::new("stage-recovery");
        let mut issuer = rig.sender_issuer(0x61);
        let issued = issue_export(&mut issuer, &rig.sender_signer, b"recover");
        let owner = rig.sender_spool.acquire_role().expect("sender owner");
        rig.sender_spool
            .stage_delivery(&owner, &issued)
            .expect("durably stage exact unit");
        assert!(
            !rig.sender_spool
                .outbound_ready_unit_directory(&issued.manifest.message_digest)
                .exists()
        );
        drop(owner);

        let reopened = GovernedFilesystemSpool::open(
            &rig.route_root,
            &rig.sender_root,
            RouteEndpointRole::Sender,
            &rig.route.definition_digest,
        )
        .expect("reopen spool after staged crash");
        let owner = reopened.acquire_role().expect("reacquire sender owner");
        assert_eq!(
            reopened
                .recover_staged(&owner)
                .expect("recover exact staged unit")
                .recovered_units,
            1
        );
        assert_eq!(
            reopened
                .read_outbound_ready(&issued.manifest.message_digest)
                .expect("read recovered unit"),
            issued
        );
    }

    #[test]
    fn duplicate_role_owner_fails_without_durable_change() {
        let rig = TestRig::new("role-owner");
        let sender_owner = rig.sender_spool.acquire_role().expect("first sender owner");
        let before = snapshot_regular_files(&rig.route_root);
        assert!(matches!(
            rig.sender_spool.acquire_role(),
            Err(M6IdentityError::RoleAlreadyOwned(RouteEndpointRole::Sender))
        ));
        assert_eq!(snapshot_regular_files(&rig.route_root), before);
        let receiver_owner = rig
            .receiver_spool
            .acquire_role()
            .expect("sender and receiver roles may coexist");
        assert_eq!(sender_owner.role(), RouteEndpointRole::Sender);
        assert_eq!(receiver_owner.role(), RouteEndpointRole::Receiver);
    }

    #[test]
    fn endpoint_spool_state_and_persisted_bytes_never_contain_peer_root() {
        let rig = TestRig::new("endpoint-root-isolation");
        let canonical_sender_root =
            fs::canonicalize(&rig.sender_root).expect("canonical sender root");
        let canonical_receiver_root =
            fs::canonicalize(&rig.receiver_root).expect("canonical receiver root");
        assert_eq!(rig.sender_spool.role(), RouteEndpointRole::Sender);
        assert_eq!(rig.sender_spool.local_root(), canonical_sender_root);
        assert_eq!(rig.receiver_spool.role(), RouteEndpointRole::Receiver);
        assert_eq!(rig.receiver_spool.local_root(), canonical_receiver_root);

        let sender_state = format!("{:?}", rig.sender_spool);
        let receiver_state = format!("{:?}", rig.receiver_spool);
        assert!(
            !sender_state.contains(&canonical_receiver_root.to_string_lossy().to_string()),
            "sender endpoint state must not retain the receiver-private path"
        );
        assert!(
            !receiver_state.contains(&canonical_sender_root.to_string_lossy().to_string()),
            "receiver endpoint state must not retain the sender-private path"
        );

        let receiver_path_bytes = canonical_receiver_root
            .to_string_lossy()
            .as_bytes()
            .to_vec();
        for bytes in snapshot_regular_files(&rig.sender_root)
            .into_values()
            .chain(snapshot_regular_files(&rig.route_root).into_values())
        {
            assert!(
                !contains_subslice(&bytes, &receiver_path_bytes),
                "sender-visible durable bytes must not disclose the receiver-private path"
            );
        }
        let sender_path_bytes = canonical_sender_root.to_string_lossy().as_bytes().to_vec();
        for bytes in snapshot_regular_files(&rig.receiver_root)
            .into_values()
            .chain(snapshot_regular_files(&rig.route_root).into_values())
        {
            assert!(
                !contains_subslice(&bytes, &sender_path_bytes),
                "receiver-visible durable bytes must not disclose the sender-private path"
            );
        }
    }

    #[test]
    fn private_signing_seed_never_enters_identity_chain_or_spool_bytes() {
        let directory = TestDirectory::new("no-private-key");
        let sender_root = directory.0.join("sender");
        let receiver_root = directory.0.join("receiver");
        let route_root = directory.0.join("route");
        let private_seed = [0xa5; 32];
        let receiver_seed = [0x5a; 32];
        let sender =
            FactorySigner::from_seed("key:no-persist-sender", private_seed).expect("sender key");
        let receiver =
            FactorySigner::from_seed("key:no-persist-receiver", receiver_seed).expect("receiver");
        let schema = vec![ContentDigest::from_bytes(b"schema")];
        let sender_identity = FactoryIdentityDocument::new(
            "factory:no-persist-sender",
            &sender,
            1,
            10_000_000,
            schema.clone(),
            schema.clone(),
            ContentDigest::from_bytes(b"authority-a"),
            ContentDigest::from_bytes(b"policy"),
        )
        .expect("sender identity");
        let receiver_identity = FactoryIdentityDocument::new(
            "factory:no-persist-receiver",
            &receiver,
            1,
            10_000_000,
            schema.clone(),
            schema,
            ContentDigest::from_bytes(b"authority-b"),
            ContentDigest::from_bytes(b"policy"),
        )
        .expect("receiver identity");
        let route = RouteDefinition::new(
            "route:no-private-persistence",
            1,
            &sender_identity,
            &receiver_identity,
            ContentDigest::from_bytes(b"policy"),
            RouteResourceProfile::bounded_default().expect("profile"),
        )
        .expect("route");
        GovernedFilesystemSpool::initialize(
            &route_root,
            &sender_root,
            &receiver_root,
            route.clone(),
        )
        .expect("spool");
        let spool = GovernedFilesystemSpool::open(
            &route_root,
            &sender_root,
            RouteEndpointRole::Sender,
            &route.definition_digest,
        )
        .expect("sender-local spool");
        let clock = Arc::new(DeterministicClock::new(1_000_000));
        let mut issuer = ManifestIssuer::open_or_initialize(
            &sender_root,
            route,
            RouteEndpointRole::Sender,
            clock,
            Arc::new(DeterministicNonceSource::new([0x77; 32])),
        )
        .expect("issuer");
        let issued = issue_export(&mut issuer, &sender, b"private-key-control");
        let owner = spool.acquire_role().expect("sender owner");
        spool.publish(&owner, &issued).expect("publish");

        let private_hex = hex_encode(&private_seed).into_bytes();
        for bytes in [
            snapshot_regular_files(&sender_root),
            snapshot_regular_files(&receiver_root),
            snapshot_regular_files(&route_root),
        ]
        .into_iter()
        .flat_map(|files| files.into_values())
        {
            assert!(!contains_subslice(&bytes, &private_seed));
            assert!(!contains_subslice(&bytes, &private_hex));
        }
    }

    fn snapshot_regular_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(root: &Path, current: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let mut entries = fs::read_dir(current)
                .expect("read snapshot directory")
                .collect::<Result<Vec<_>, _>>()
                .expect("read snapshot entries");
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let file_type = entry.file_type().expect("snapshot file type");
                if file_type.is_dir() {
                    walk(root, &path, output);
                } else if file_type.is_file() {
                    output.insert(
                        path.strip_prefix(root)
                            .expect("snapshot path beneath root")
                            .to_path_buf(),
                        fs::read(&path).expect("read snapshot file"),
                    );
                }
            }
        }
        let mut output = BTreeMap::new();
        walk(root, root, &mut output);
        output
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }
}
